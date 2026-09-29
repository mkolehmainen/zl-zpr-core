//! Queues (i.e., frontend interface) for each stage of the system.

use crate::config;
use crate::packet::{self, Packet, PacketBuffer};
use crate::packet_queue;
use crate::test_packet::*;
use crate::two_way_queue;
use std::collections::VecDeque;
use std::result::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::oneshot::error::RecvError;
use zpr::packet_info::{LinkId, SubstrateAddr};
use zpr_utils::net_defs;

pub enum TryEnqueueError<T = ()> {
    Full(T),
}

pub enum MgmtProcessorMessage {
    Packet(Packet),
    TestPacket(TestPacket),
}

/// MgmtProcessor processes all inbound management requests.
/// Unlike other queues, this doesn't live directly in the assembly,
/// but rather in the peer table, as there is one of these per peer.
pub struct MgmtProcessor {
    sender: mpsc::Sender<MgmtProcessorMessage>,
}

impl MgmtProcessor {
    pub fn new(sender: mpsc::Sender<MgmtProcessorMessage>) -> Self {
        Self { sender }
    }

    pub fn try_enqueue_packet(&self, packet: Packet) -> Result<(), TryEnqueueError<Packet>> {
        match self.sender.try_send(MgmtProcessorMessage::Packet(packet)) {
            Ok(()) => Ok(()),

            Err(TrySendError::Closed(_)) => panic!("mgmt processor channel closed"),

            Err(TrySendError::Full(msg)) => {
                let MgmtProcessorMessage::Packet(pkt) = msg else {
                    unreachable!()
                };
                Err(TryEnqueueError::Full(pkt))
            }
        }
    }

    /// Sends TestPacket through system using MgmtProcessor sender, awaits response from
    /// the corresponding receiver via TestPacket::acknowledge, returns metrics or an error
    // TODO perhaps enqueue_test_packet is not the best name, because it does more than
    // just enqueue, it also waits for the response, unlike the other enqueue methods of other
    // queues
    #[allow(dead_code)]
    pub async fn enqueue_test_packet(&self) -> Result<TestPacketMetrics, RecvError> {
        let test_tuple = TestPacket::create();

        self.sender
            .send(MgmtProcessorMessage::TestPacket(test_tuple.0))
            .await
            .unwrap();

        Ok(test_tuple.1.await?)
    }
}

/// MgmtSubstrateEgress allows mgmt to inject ZDP packets into the substrate egress fastpath.
pub struct MgmtSubstrateEgress {
    queue: packet_queue::Sender<{ config::PACKET_BUFFER_SIZE }>,
}

impl MgmtSubstrateEgress {
    /// Sockets must be marked non-blocking by caller.
    pub fn new(queue: packet_queue::Sender<{ config::PACKET_BUFFER_SIZE }>) -> Self {
        Self { queue }
    }

    /// Enqueue the given packet to be egressed on the substrate.
    /// Blocks until the packet is in the hands of the fastpath.
    /// The packet is marked PRIORITY, which instructs the fastpath to
    /// ensure it eventually gets queued with the OS.
    #[allow(dead_code)]
    pub async fn enqueue_packet(&self, link_id: LinkId, packet: &mut Packet) {
        packet.metadata_mut().egress_link_id = link_id;
        packet.metadata_mut().flags |= packet::flags::PRIORITY;
        self.queue
            .send(packet)
            .await
            .expect("unrecoverable I/O error");
    }

    /// Try to enqueue the given packet to be egressed on the substrate.
    /// Returns `false` if there is no room in the queue.
    /// Unlike `enqueue_packet()`, the packet is not marked for any special processing.
    pub fn try_enqueue_packet(&self, link_id: LinkId, packet: &mut Packet) -> bool {
        packet.metadata_mut().egress_link_id = link_id;
        match self.queue.try_send(packet) {
            Ok(()) => true,
            Err(packet_queue::TrySendError::Full) => false,
            Err(err) => panic!("unrecoverable I/O error: {err:?}"),
        }
    }
}

/// Used for requeueing actor output packets from mgmt.
pub struct ActorOutputRequeue {
    queues: Box<[packet_queue::Sender<{ config::PACKET_BUFFER_SIZE }>]>,
}

impl ActorOutputRequeue {
    pub fn new(
        queues: impl IntoIterator<Item = packet_queue::Sender<{ config::PACKET_BUFFER_SIZE }>>,
    ) -> Self {
        Self {
            queues: queues.into_iter().collect(),
        }
    }

    pub fn try_enqueue_packet(&self, packet: Packet) -> Result<(), TryEnqueueError<Packet>> {
        let queue = self.select_queue(&packet);

        match queue.try_send(&packet) {
            Ok(()) => {
                drop(packet);
                Ok(())
            }

            Err(packet_queue::TrySendError::Full) => Err(TryEnqueueError::Full(packet)),
            Err(err) => panic!("unrecoverable I/O error: {err:?}"),
        }
    }

    fn select_queue(
        &self,
        packet: &Packet,
    ) -> &packet_queue::Sender<{ config::PACKET_BUFFER_SIZE }> {
        &self.queues[packet.metadata().ingress_lane_id as usize]
    }
}

/// One capture buffer: a pcap record header followed by (a prefix of) a
/// packet.  Sized to hold the largest packet the datapath carries.
type CaptureBuffer = Box<[u8; config::PACKET_BUFFER_SIZE]>;

/// Largest packet prefix that fits in a `CaptureBuffer` after its header.
const MAX_CAPTURE_LEN: usize =
    config::PACKET_BUFFER_SIZE - std::mem::size_of::<crate::pcap_writer::PcaprecHdr>();

/// State shared by the datapath (`Capture`) and the capture worker
/// (`CaptureReceiver`).  Both collections are allocated at full capacity up
/// front and there are exactly as many buffers as each can hold, so pushing
/// never grows either one: nothing here allocates after `capture_queue`.
struct CaptureShared {
    /// Buffers ready for the datapath to fill.
    free: Vec<CaptureBuffer>,
    /// Filled buffers waiting for the worker, oldest first.
    filled: VecDeque<CapturedPacket>,
}

/// A captured packet on its way to the capture worker: a pool buffer and
/// the number of bytes of it in use.
pub struct CapturedPacket {
    buf: CaptureBuffer,
    len: usize,
}

impl CapturedPacket {
    /// The pcap record: `PcaprecHdr` followed by the captured bytes.
    pub fn data(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Create the capture queue: the datapath-side `Capture` and the
/// worker-side `CaptureReceiver`, sharing a pool of `depth` buffers.
///
/// Why a pool (zipline#129): the datapath does no heap allocation per
/// packet, and capture must not be the exception.  (The AF_UNIX socketpair
/// this replaces didn't allocate in `ph` either; the kernel did the copy.)
/// Every buffer, and the storage of both queues that hold them, is
/// allocated here, once; buffers then cycle datapath -> worker -> pool ->
/// datapath.  A tokio mpsc is deliberately NOT used for the filled side:
/// its bounded channel limits the message count but allocates storage
/// blocks lazily on the sending thread, i.e. on the datapath (PR #47
/// review).  The cost is `depth * PACKET_BUFFER_SIZE` bytes held for the
/// life of the process (3 MB with the default topology), whether or not
/// capture is in use.
pub fn capture_queue(depth: usize) -> (Capture, CaptureReceiver) {
    let free: Vec<CaptureBuffer> = (0..depth)
        .map(|_| {
            // Built via Vec so the 12 KB buffer is never on the stack.
            vec![0u8; config::PACKET_BUFFER_SIZE]
                .into_boxed_slice()
                .try_into()
                .expect("vec has exactly PACKET_BUFFER_SIZE bytes")
        })
        .collect();
    let shared = Arc::new(Mutex::new(CaptureShared {
        free,
        filled: VecDeque::with_capacity(depth),
    }));
    let notify = Arc::new(tokio::sync::Notify::new());
    let worker_gone = Arc::new(AtomicBool::new(false));
    (
        Capture {
            shared: shared.clone(),
            notify: notify.clone(),
            worker_gone: worker_gone.clone(),
        },
        CaptureReceiver {
            shared,
            notify,
            worker_gone,
        },
    )
}

/// Capture will intercept packets in the PH and dump them into a file for debugging purposes
pub struct Capture {
    shared: Arc<Mutex<CaptureShared>>,
    /// Wakes the capture worker when a buffer is queued.
    notify: Arc<tokio::sync::Notify>,
    /// Set when the `CaptureReceiver` is dropped.
    worker_gone: Arc<AtomicBool>,
}

impl Capture {
    /// Try to send a packet to the capture system.
    /// Only `incl_len` bytes will be captured.  (If this is larger than the
    /// actual packet length, or than a capture buffer holds, it is reduced
    /// accordingly.)
    /// Never blocks and never allocates: if no pool buffer is free right now
    /// (all in flight, or another thread holds the queue lock) the packet is
    /// not captured and `Full` is returned.
    ///
    /// NOTE: the packet is not modified; `&mut` is kept so callers need not
    /// change.
    pub fn try_enqueue_packet(
        &self,
        packet: &mut Packet,
        timestamp: SystemTime,
        incl_len: usize,
    ) -> Result<(), TryEnqueueError> {
        if self.worker_gone.load(Ordering::Relaxed) {
            panic!("capture channel closed");
        }

        let body = packet.body();
        let incl_len = incl_len.min(body.len()).min(MAX_CAPTURE_LEN);

        // `try_lock` rather than `lock`: the datapath must not wait on
        // another thread.  Contention is treated like an empty pool.  The
        // copy is done under the lock so the buffer moves free -> filled in
        // one critical section; it is at most one packet's worth of bytes.
        let Ok(mut shared) = self.shared.try_lock() else {
            return Err(TryEnqueueError::Full(()));
        };
        let Some(mut buf) = shared.free.pop() else {
            return Err(TryEnqueueError::Full(()));
        };

        let hdr = crate::pcap_writer::PcaprecHdr::new(timestamp, incl_len, body.len());
        let hdr_len = std::mem::size_of_val(&hdr);
        buf[..hdr_len].copy_from_slice(zerocopy::IntoBytes::as_bytes(&hdr));
        buf[hdr_len..hdr_len + incl_len].copy_from_slice(&body[..incl_len]);

        // Cannot grow: `filled` has room for every buffer in the pool.
        shared.filled.push_back(CapturedPacket {
            buf,
            len: hdr_len + incl_len,
        });
        drop(shared);
        // Stores a permit if the worker is not waiting yet, so the wakeup
        // is not lost; does not allocate.
        self.notify.notify_one();
        Ok(())
    }
}

/// Worker side of the capture queue (see `capture_queue`).
pub struct CaptureReceiver {
    shared: Arc<Mutex<CaptureShared>>,
    notify: Arc<tokio::sync::Notify>,
    worker_gone: Arc<AtomicBool>,
}

impl CaptureReceiver {
    /// Wait for the next captured packet.
    pub async fn recv(&mut self) -> CapturedPacket {
        loop {
            if let Some(packet) = self.shared.lock().unwrap().filled.pop_front() {
                return packet;
            }
            self.notify.notified().await;
        }
    }

    /// Return a packet's buffer to the pool so the datapath can reuse it.
    /// Every packet from `recv` must come back here, or capture capacity
    /// shrinks.
    pub fn recycle(&self, packet: CapturedPacket) {
        // Cannot grow: `free` was allocated with room for every buffer.
        self.shared.lock().unwrap().free.push(packet.buf);
    }
}

impl Drop for CaptureReceiver {
    /// Tell the datapath the worker is gone, so capturing fails loudly
    /// (as the socketpair's closed peer did) instead of silently draining
    /// the pool.
    fn drop(&mut self) {
        self.worker_gone.store(true, Ordering::Relaxed);
    }
}

pub enum MgmtDispatchMessage {
    WithLink(Packet), // Link ID stored in packet metadata
    WithAddr {
        peer_sa: SubstrateAddr,
        interface_addr: net_defs::ScopedIpAddr,
        packet: Packet,
    },
}

impl two_way_queue::TwoWayReturnable<MgmtDispatchMessage> for PacketBuffer {
    fn convert(value: MgmtDispatchMessage) -> Self {
        match value {
            MgmtDispatchMessage::WithLink(pkt) => pkt.destroy(),
            MgmtDispatchMessage::WithAddr { packet, .. } => packet.destroy(),
        }
    }
}

pub struct MgmtDispatch {
    sender: two_way_queue::Sender<MgmtDispatchMessage, PacketBuffer>,
}

impl MgmtDispatch {
    pub fn try_dispatch_mgmt_packet_with_link(
        &mut self,
        packet: Packet,
    ) -> Result<(), TryEnqueueError<Packet>> {
        debug_assert_ne!(packet.metadata().ingress_link_id, 0);
        match self.sender.try_send(MgmtDispatchMessage::WithLink(packet)) {
            Ok(()) => Ok(()),

            Err(two_way_queue::TrySendError::Closed(_)) => panic!("mgmt dispatch channel closed"),

            Err(two_way_queue::TrySendError::Full(msg)) => {
                let MgmtDispatchMessage::WithLink(pkt) = msg else {
                    unreachable!()
                };
                Err(TryEnqueueError::Full(pkt))
            }
        }
    }

    pub fn try_dispatch_mgmt_packet_with_addr(
        &mut self,
        peer_sa: &SubstrateAddr,
        interface_addr: &net_defs::ScopedIpAddr,
        packet: Packet,
    ) -> Result<(), TryEnqueueError<Packet>> {
        debug_assert_eq!(packet.metadata().ingress_link_id, 0);
        match self.sender.try_send(MgmtDispatchMessage::WithAddr {
            peer_sa: *peer_sa,
            interface_addr: *interface_addr,
            packet,
        }) {
            Ok(()) => Ok(()),

            Err(two_way_queue::TrySendError::Closed(_)) => panic!("mgmt dispatch channel closed"),

            Err(two_way_queue::TrySendError::Full(msg)) => {
                let MgmtDispatchMessage::WithAddr { packet, .. } = msg else {
                    unreachable!()
                };
                Err(TryEnqueueError::Full(packet))
            }
        }
    }
}

/// Factory to build `MgmtDispatch` ingresses for specified two-way-queue return queues.
pub struct MgmtDispatchFactory(two_way_queue::SenderFactory<MgmtDispatchMessage, PacketBuffer>);

impl MgmtDispatchFactory {
    pub fn new(fact: two_way_queue::SenderFactory<MgmtDispatchMessage, PacketBuffer>) -> Self {
        Self(fact)
    }

    pub fn make(&self, ret_q: &two_way_queue::ReturnQueue<PacketBuffer>) -> MgmtDispatch {
        MgmtDispatch {
            sender: self.0.make(ret_q),
        }
    }
}

pub struct MgmtHairpinDispatch {
    sender: mpsc::Sender<Packet>,
}

impl MgmtHairpinDispatch {
    pub fn new(sender: mpsc::Sender<Packet>) -> Self {
        Self { sender }
    }

    pub fn try_dispatch_mgmt_packet_with_link(
        &self,
        packet: Packet,
    ) -> Result<(), TryEnqueueError<Packet>> {
        debug_assert_ne!(packet.metadata().ingress_link_id, 0);
        match self.sender.try_send(packet) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                panic!("mgmt hairpin dispatch channel closed")
            }
            Err(mpsc::error::TrySendError::Full(pkt)) => Err(TryEnqueueError::Full(pkt)),
        }
    }
}

pub enum AdapterManagerMessage {
    RequestTetherId(Packet),
}

impl two_way_queue::TwoWayReturnable<AdapterManagerMessage> for PacketBuffer {
    fn convert(value: AdapterManagerMessage) -> Self {
        match value {
            AdapterManagerMessage::RequestTetherId(pkt) => pkt.destroy(),
        }
    }
}

pub struct AdapterManager {
    sender: two_way_queue::Sender<AdapterManagerMessage, PacketBuffer>,
}

impl AdapterManager {
    /// Request a tether ID to use for sending packets starting with the
    /// specified packet.
    ///
    /// While awaiting a tether ID, the five-tuple will be marked pending in
    /// the ELT.  (Note that this occurs asynchronously!  Ensure that this
    /// race is benign for your use case before relying on the pending mark.)
    ///
    /// After a tether ID is received, a PEP will be added to
    /// the ELT, and an attempt will be made to send the specified packet.
    ///
    /// The specified packet must have already been classified.
    pub fn try_request_tether_id(&mut self, packet: Packet) -> Result<(), TryEnqueueError<Packet>> {
        match self
            .sender
            .try_send(AdapterManagerMessage::RequestTetherId(packet))
        {
            Ok(()) => Ok(()),

            Err(two_way_queue::TrySendError::Closed(_)) => panic!("adapter manager channel closed"),

            Err(two_way_queue::TrySendError::Full(msg)) => match msg {
                AdapterManagerMessage::RequestTetherId(packet) => {
                    Err(TryEnqueueError::Full(packet))
                }
            },
        }
    }
}

/// Factory to build `AdapterManager` ingresses for specified two-way-queue return queues.
pub struct AdapterManagerFactory(two_way_queue::SenderFactory<AdapterManagerMessage, PacketBuffer>);

impl AdapterManagerFactory {
    pub fn new(fact: two_way_queue::SenderFactory<AdapterManagerMessage, PacketBuffer>) -> Self {
        Self(fact)
    }

    pub fn make(&self, ret_q: &two_way_queue::ReturnQueue<PacketBuffer>) -> AdapterManager {
        AdapterManager {
            sender: self.0.make(ret_q),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap_writer::PcaprecHdr;
    use bytes::BufMut;
    use std::time::{Duration, UNIX_EPOCH};
    use zerocopy::FromBytes;

    const HDR_LEN: usize = std::mem::size_of::<PcaprecHdr>();

    /// A packet whose body is `body`, with no headroom.
    fn packet_with_body(body: &[u8]) -> Packet {
        let mut pkt = Packet::new(vec![0u8; config::PACKET_BUFFER_SIZE].into(), 0);
        pkt.put(body);
        pkt
    }

    /// The (incl_len, orig_len, ts_sec, ts_usec) fields of a record's header.
    fn header_fields(record: &[u8]) -> (u32, u32, u32, u32) {
        // PcaprecHdr is four native-endian u32s: ts_sec, ts_usec, incl_len, orig_len.
        let ([ts_sec, ts_usec, incl_len, orig_len], _) =
            <[u32; 4]>::read_from_prefix(record).unwrap();
        (incl_len, orig_len, ts_sec, ts_usec)
    }

    #[tokio::test]
    async fn enqueued_packet_arrives_as_pcap_record() {
        let (capture, mut receiver) = capture_queue(4);
        let mut pkt = packet_with_body(b"hello, capture");
        let ts = UNIX_EPOCH + Duration::new(1_000, 2_000);

        assert!(capture.try_enqueue_packet(&mut pkt, ts, 5).is_ok());

        let captured = receiver.recv().await;
        let record = captured.data();
        assert_eq!(record.len(), HDR_LEN + 5);
        assert_eq!(header_fields(record), (5, 14, 1_000, 2));
        assert_eq!(&record[HDR_LEN..], b"hello");
        // The packet itself is untouched.
        assert_eq!(pkt.body(), b"hello, capture");
    }

    #[tokio::test]
    async fn incl_len_is_clamped_to_packet_length() {
        let (capture, mut receiver) = capture_queue(1);
        let mut pkt = packet_with_body(b"short");

        assert!(
            capture
                .try_enqueue_packet(&mut pkt, SystemTime::now(), 1_000)
                .is_ok()
        );

        let captured = receiver.recv().await;
        assert_eq!(header_fields(captured.data()).0, 5);
        assert_eq!(&captured.data()[HDR_LEN..], b"short");
    }

    #[tokio::test]
    async fn exhausted_pool_reports_full_until_a_buffer_is_recycled() {
        let (capture, mut receiver) = capture_queue(2);
        let mut pkt = packet_with_body(b"x");
        let now = SystemTime::now();

        assert!(capture.try_enqueue_packet(&mut pkt, now, 1).is_ok());
        assert!(capture.try_enqueue_packet(&mut pkt, now, 1).is_ok());
        assert!(matches!(
            capture.try_enqueue_packet(&mut pkt, now, 1),
            Err(TryEnqueueError::Full(()))
        ));

        // Giving one buffer back makes room for exactly one more.
        let captured = receiver.recv().await;
        receiver.recycle(captured);
        assert!(capture.try_enqueue_packet(&mut pkt, now, 1).is_ok());
        assert!(matches!(
            capture.try_enqueue_packet(&mut pkt, now, 1),
            Err(TryEnqueueError::Full(()))
        ));
    }

    /// A worker already waiting in `recv` is woken by an enqueue from
    /// another (fastpath) thread.
    #[tokio::test]
    async fn waiting_worker_is_woken_by_enqueue_from_another_thread() {
        let (capture, mut receiver) = capture_queue(1);
        let producer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            let mut pkt = packet_with_body(b"wake");
            assert!(
                capture
                    .try_enqueue_packet(&mut pkt, SystemTime::now(), 4)
                    .is_ok()
            );
            capture // keep the sender alive until the packet is queued
        });

        let captured = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("the waiting worker must be woken");
        assert_eq!(&captured.data()[HDR_LEN..], b"wake");
        producer.join().unwrap();
    }

    /// The no-allocation invariant: cycling many more packets than the pool
    /// holds never grows either queue's storage (PR #47 review).
    #[tokio::test]
    async fn cycling_packets_never_grows_queue_storage() {
        let depth = 4;
        let (capture, mut receiver) = capture_queue(depth);
        let capacities = |r: &CaptureReceiver| {
            let shared = r.shared.lock().unwrap();
            (shared.free.capacity(), shared.filled.capacity())
        };
        let before = capacities(&receiver);
        let mut pkt = packet_with_body(b"cycle");

        for _ in 0..10 {
            for _ in 0..depth {
                assert!(
                    capture
                        .try_enqueue_packet(&mut pkt, SystemTime::now(), 5)
                        .is_ok()
                );
            }
            for _ in 0..depth {
                let captured = receiver.recv().await;
                receiver.recycle(captured);
            }
        }
        assert_eq!(capacities(&receiver), before);
    }

    #[test]
    #[should_panic(expected = "capture channel closed")]
    fn enqueue_after_worker_gone_panics() {
        let (capture, receiver) = capture_queue(1);
        drop(receiver);
        let mut pkt = packet_with_body(b"x");
        let _ = capture.try_enqueue_packet(&mut pkt, SystemTime::now(), 1);
    }
}
