use crate::batch_io::{self, BatchIo};
use crate::config;
use crate::counters::*;
use crate::fastpath::{FastpathWorker, FastpathWorkerConfig};
use crate::packet_queue;
#[cfg(windows)]
use crate::sys::wait::SocketWaitable;
use crate::sys::wait::{AsWaitSource, WaitHandle, Waitable};
use crate::sys::{TunPi, ZprTun};
use crate::zprtun;
use std::io::{ErrorKind, Result};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use zpr_utils::net_defs;

#[allow(unused_imports)]
use crate::packet::{self, Packet, flags};

pub struct FastpathIo {
    batch_io: BatchIo,
    actor_tun: Arc<ZprTun>,
    substrate_socket: UdpSocket,
    /// The substrate socket's waitable Event (`WSAEventSelect(FD_READ)`,
    /// plan D3): the socket itself is not waitable on Windows. Owned here
    /// beside the socket it is bound to.
    #[cfg(windows)]
    substrate_waitable: SocketWaitable,
    pub requeue_outq: packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
    pub mgmt_substrate_outq: packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,

    /// temporary packet storage during I/O batch operations
    packets: Vec<Packet>,
    /// temporary read result storage during I/O batch operations
    io_results: Vec<Result<usize>>,
    /// temporary recv result storage during I/O batch operations
    recv_results: Vec<Result<batch_io::ReceivedPacket>>,
}

impl FastpathIo {
    pub fn new(
        config: FastpathWorkerConfig,
        substrate_socket: UdpSocket,
        actor_tun: Arc<ZprTun>,
        requeue_outq: packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
        maybe_mgmt_substrate_outq: Option<packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>>,
    ) -> Self {
        // HACK: nix does not support disabling an FD, so instead, make a dummy mgmt_substrate_outq socket
        // if we weren't given one
        let mgmt_substrate_outq;
        match maybe_mgmt_substrate_outq {
            Some(outq) => mgmt_substrate_outq = outq,
            None => {
                let (_, outq) = packet_queue::packet_queue(1);
                mgmt_substrate_outq = outq;
            }
        }

        Self {
            batch_io: config
                .batch_io_engine
                .instantiate(config.batch_size)
                .unwrap(),
            actor_tun,
            #[cfg(windows)]
            substrate_waitable: SocketWaitable::new(&substrate_socket)
                .expect("unable to bind a wait event to the substrate socket"),
            substrate_socket,
            requeue_outq,
            mgmt_substrate_outq,
            packets: Vec::with_capacity(config.batch_size),
            io_results: Vec::with_capacity(config.batch_size),
            recv_results: Vec::with_capacity(config.batch_size),
        }
    }

    /// Substrate socket wait handle for the fastpath wait set.
    ///
    /// Unix: the socket's own fd. Windows: the socket is not waitable, so
    /// this is its [`SocketWaitable`]'s Event (plan D3) — distinct from the
    /// I/O-target handle `process_substrate_socket_in` passes to batch_io.
    pub fn substrate_socket_handle(&self) -> WaitHandle<'_> {
        #[cfg(unix)]
        {
            self.substrate_socket.as_wait_handle()
        }
        #[cfg(windows)]
        {
            self.substrate_waitable.handle()
        }
    }

    /// Actor TUN wait handle for the fastpath wait set.
    pub fn actor_tun_handle(&self) -> WaitHandle<'_> {
        self.actor_tun.as_wait_handle()
    }

    /// Requeue queue wait handle for the fastpath wait set.
    pub fn requeue_handle(&self) -> WaitHandle<'_> {
        self.requeue_outq.handle()
    }

    /// Mgmt substrate queue wait handle for the fastpath wait set.
    pub fn mgmt_substrate_handle(&self) -> WaitHandle<'_> {
        self.mgmt_substrate_outq.handle()
    }

    /// Process an input-ready notification on the substrate socket (substrate ingress).
    pub fn process_substrate_socket_in(&mut self, worker: &mut FastpathWorker) {
        // Acknowledge the wake BEFORE draining (Windows, plan D3):
        // `WSAEnumNetworkEvents` clears the Event and the FD_READ record.
        // Cleared first, a datagram that arrives mid-drain is either
        // consumed by this drain or re-posts FD_READ after the final
        // WouldBlock recv re-enables it. Cleared after, a datagram arriving
        // between the last recv and the clear would leave data buffered
        // with FD_READ posting disabled — a lost wakeup.
        #[cfg(windows)]
        self.substrate_waitable
            .reset()
            .expect("WSAEnumNetworkEvents failed on the substrate socket");

        let _nbufs = worker.get_fresh_packets(worker.config.batch_size, &mut self.packets);

        self.io_results.clear();
        let n = wouldblock_as_empty_batch(self.batch_io.try_recv_buf_from_to_batch(
            &self.substrate_socket,
            self.packets.iter_mut(),
            &mut self.recv_results,
        ))
        .expect("unrecoverable substrate socket error");

        // return empty buffers to pool
        worker
            .buffers
            .extend(self.packets.drain(n..).rev().map(|pkt| pkt.destroy()));

        // process packets
        for (pkt, result) in self.packets.drain(..).zip(self.recv_results.drain(..)) {
            let (mut sender, dest) = match result {
                Ok(res) if res.truncated => {
                    worker.drop_and_count(pkt, FastpathCounterType::DroppedOversize);
                    continue;
                }

                Ok(res) => (
                    res.source
                        .expect("received from non-IP address, should not happen!"),
                    res.destination
                        .expect("unknown recipient, should not happen!"),
                ),

                Err(err) => {
                    match err.kind() {
                        ErrorKind::WouldBlock | ErrorKind::ResourceBusy => {
                            worker.buffers.push(pkt.destroy());
                            continue;
                        }

                        // FIXME: do something with this later...
                        ErrorKind::ConnectionRefused => {
                            worker.buffers.push(pkt.destroy());
                            continue;
                        }

                        _ => panic!("got socket error {err}"),
                    }
                }
            };

            // SocketAddrV6 distinguishes addresses also by `flowinfo` which
            // we do not want -- only the 5-tuple.  So clear it.
            clear_flowinfo(&mut sender);

            worker.batch_counters[FastpathCounterType::InPacksRec].increment();
            worker.substrate_ingress(&sender, &dest, pkt);
        }
    }

    /// Process an output-ready notification on the substrate socket
    /// (substrate egress of PRIORITY packets).
    pub fn process_substrate_socket_out(&mut self, worker: &mut FastpathWorker) {
        self.process_substrate_egress_queue(worker);
    }

    /// Process an input-ready notification on the actor TUN (actor output).
    pub fn process_actor_tun_in(&mut self, worker: &mut FastpathWorker) {
        let _nbufs = worker.get_fresh_packets(worker.config.batch_size, &mut self.packets);

        self.io_results.clear();
        let n = wouldblock_as_empty_batch(self.batch_io.try_read_buf_batch(
            &self.actor_tun,
            self.packets.iter_mut(),
            &mut self.io_results,
        ))
        .expect("unrecoverable TUN error");

        // return empty buffers to pool
        worker
            .buffers
            .extend(self.packets.drain(n..).rev().map(|pkt| pkt.destroy()));

        // process packets
        for (mut pkt, result) in self.packets.drain(..).zip(self.io_results.drain(..)) {
            if let Err(err) = result {
                match err.kind() {
                    ErrorKind::WouldBlock | ErrorKind::ResourceBusy => {
                        worker.buffers.push(pkt.destroy());
                        continue;
                    }

                    _ => panic!("unrecoverable I/O error {err}"),
                }
            }

            if zprtun::TUN_HAS_PI {
                let pi = TunPi::read_pi(&mut pkt);
                if pi.strip || !is_ip(pi) {
                    // packet was too large or non-IP; drop
                    worker.drop_and_count(pkt, FastpathCounterType::OutPacksDrop);
                    continue;
                }
            } else {
                // No packet info, permit IP and IPv6 only (for now?)
                if pkt.body()[0] >> 4 != 4 && pkt.body()[0] >> 4 != 6 {
                    worker.drop_and_count(pkt, FastpathCounterType::OutPacksDrop);
                    continue;
                }
            }

            worker.batch_counters[FastpathCounterType::OutPacksRec].increment();
            worker.actor_output(pkt);
        }
    }

    /// Process an input-ready notification on the requeue socket.
    pub fn process_requeue_in(&mut self, worker: &mut FastpathWorker) {
        batch_process_packet_queue(
            worker,
            &mut self.requeue_outq,
            worker.config.batch_size,
            |worker, pkt| {
                worker.batch_counters[FastpathCounterType::RequeuedPacketsReceived].increment();
                worker.actor_output_post_classify(pkt, /* allow_bind_request */ false);
            },
        );
    }

    /// Process an input-ready notification on the mgmt substrate socket.
    pub fn process_mgmt_substrate_in(&mut self, worker: &mut FastpathWorker) {
        batch_process_packet_queue(
            worker,
            &mut self.mgmt_substrate_outq,
            worker.config.batch_size,
            |worker, pkt| {
                worker.batch_counters[FastpathCounterType::MgmtPacketsSent].increment();
                worker.substrate_egress(pkt);
            },
        );
    }

    /// Egress any queued packets, or drop if there is no space in the system queues.
    ///
    /// After this call, the actor input queue will be empty, and the substrate egress queue
    /// will contain only PRIORITY packets.
    pub fn process_out_queues(&mut self, worker: &mut FastpathWorker) {
        self.process_actor_input_queue(worker);
        self.process_substrate_egress_queue(worker);
    }

    /// Egress queued actor input packets only.
    fn process_actor_input_queue(&mut self, worker: &mut FastpathWorker) {
        // Add TUN PI header.
        match TunPi::PI_SIZE {
            0 => (),
            sz => {
                for pkt in &mut worker.actor_input_q {
                    let proto = net_defs::ip_ethertype(net_defs::ip_version(pkt.body()));
                    let mut hdr = pkt.alloc_zeroed_headroom(sz);
                    TunPi::write_pi(
                        &mut hdr,
                        TunPi {
                            strip: false,
                            proto,
                        },
                    );
                }
            }
        }

        // (Try to) send packets.
        self.io_results.clear();
        let n = wouldblock_as_empty_batch(self.batch_io.try_write_batch(
            &self.actor_tun,
            worker.actor_input_q.iter().map(|pkt| pkt.body()),
            &mut self.io_results,
        ))
        .expect("unrecoverable TUN error");

        // Tally results.
        let mut dropped = worker.actor_input_q.len() - n;
        for res in self.io_results.drain(..) {
            match res {
                Ok(_) => (),
                Err(err) if err.kind() == ErrorKind::WouldBlock => dropped += 1,
                Err(err) => panic!("unrecoverable TUN error: {}", err),
            }
        }
        worker.batch_counters[FastpathCounterType::InPacksSent]
            .increase_by((worker.actor_input_q.len() - dropped) as u64);
        worker.batch_counters[FastpathCounterType::InPacksDrop].increase_by(dropped as u64);

        // Return buffers to buffer stack.
        worker
            .buffers
            .extend(worker.actor_input_q.drain(..).map(|pkt| pkt.destroy()));
    }

    /// Egress queued substrate egress packets only.
    fn process_substrate_egress_queue(&mut self, worker: &mut FastpathWorker) {
        // (Try to) send packets.
        self.io_results.clear();

        let n = wouldblock_as_empty_batch(self.batch_io.try_send_to_from_batch(
            &self.substrate_socket,
            worker.substrate_egress_q.iter().map(|pkt| {
                (
                    pkt.pkt.body(),
                    pkt.dst,
                    Some(pkt.src),
                    Self::get_confirm_flag(&pkt.pkt),
                )
            }),
            &mut self.io_results,
        ))
        .unwrap_or_else(|err| panic!("unrecoverable I/O error: {err}"));

        // Tally results.
        let mut dropped = 0;
        let mut retained = 0;

        for i in 0..worker.substrate_egress_q.len() {
            // Determine whether the packet was in fact sent.
            // If it was, leave it in place and skip to the next packet.
            if i < n {
                match &self.io_results[i] {
                    Ok(_) => continue,
                    Err(err) if err.kind() == ErrorKind::WouldBlock => (),
                    // TODO: pending <https://github.com/rust-lang/rust/issues/86442>, provide more info to user
                    // (or potentially recover from certain errors)
                    Err(err) => panic!("unrecoverable I/O error: {err}"),
                }
            }

            // Packet was not sent.

            if worker.substrate_egress_q[i].pkt.metadata().flags & packet::flags::PRIORITY != 0 {
                // This was a priority packet.  Move it to the front of the queue.
                worker.substrate_egress_q.swap(i, retained);
                retained += 1;
            } else {
                // This was a normal packet.  Leave it to get dropped.
                dropped += 1;
            }
        }
        self.io_results.clear();

        // Now all un-sent priority packets are at the head of the queue.

        worker.batch_counters[FastpathCounterType::OutPacksSent]
            .increase_by((worker.substrate_egress_q.len() - dropped - retained) as u64);
        worker.batch_counters[FastpathCounterType::OutPacksDrop].increase_by(dropped as u64);

        // Return buffers to buffer stack, except for un-sent priority packets, which are retained for next time.
        worker.buffers.extend(
            worker
                .substrate_egress_q
                .drain(retained..)
                .map(|pkt| pkt.pkt.destroy()),
        );
    }

    /// Send flags for a substrate egress packet: `MSG_CONFIRM` when the
    /// packet's metadata asks for link-layer confirmation (a no-op off
    /// Linux, where the flag does not exist).
    fn get_confirm_flag(pkt: &Packet) -> batch_io::SendFlags {
        match pkt.metadata().flags & flags::CONFIRM != 0 {
            true => batch_io::SendFlags::confirm(),
            false => batch_io::SendFlags::none(),
        }
    }
}

fn is_ip(pi: TunPi) -> bool {
    pi.proto == net_defs::ethertype::IP || pi.proto == net_defs::ethertype::IPV6
}

/// Classify a batch I/O call's batch-level result: a first-item
/// `WouldBlock` means "nothing to do right now", so it comes back as an
/// empty batch (`Ok(0)`). Every engine returns a first-item error as the
/// batch error (the sendmmsg(2) emulation they share), and on Windows that
/// case is routine, not exceptional:
///
/// * TUN write: `ZprTun::send` maps a full Wintun send ring
///   (`ERROR_BUFFER_OVERFLOW`) to `WouldBlock` (zipline#131 PR #52 review
///   round 1, thread 2).
/// * Substrate receive and TUN read: the wait Event is reset before the
///   drain (see `process_substrate_socket_in`), so a wake can find nothing
///   to read (zipline#133 Windows smoke test).
/// * Substrate send: a full socket send buffer.
///
/// Everything else stays an error for the caller to treat as fatal.
fn wouldblock_as_empty_batch(res: Result<usize>) -> Result<usize> {
    match res {
        Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(0),
        res => res,
    }
}

fn clear_flowinfo(addr: &mut SocketAddr) {
    match addr {
        SocketAddr::V4(_) => (),
        SocketAddr::V6(addr) => addr.set_flowinfo(0),
    }
}

fn batch_process_packet_queue(
    worker: &mut FastpathWorker,
    queue: &mut packet_queue::Receiver<{ config::PACKET_BUFFER_SIZE }>,
    limit: usize,
    mut process_fn: impl FnMut(&mut FastpathWorker, Packet),
) {
    for _i in 0..limit {
        let Some(buf) = worker.buffers.pop() else {
            break;
        };

        match queue.try_recv(buf) {
            Ok(pkt) => {
                process_fn(worker, pkt);
            }

            Err(packet_queue::TryRecvError::Empty(buf)) => {
                worker.buffers.push(buf);
                break;
            }

            Err(err) => {
                panic!("unrecoverable I/O error {err:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::wouldblock_as_empty_batch;
    use crate::batch_io;
    use std::io::{Error, ErrorKind};
    use std::net::UdpSocket;

    /// zipline#131 PR #52 review round 1 (thread 2): a batch-level
    /// `WouldBlock` from the TUN write — the Wintun send ring full on the
    /// FIRST packet of a batch — is ordinary backpressure and must come
    /// back as "zero sent" (the whole batch then reaches the drop tally),
    /// not as an error the caller's `expect` turns into a fastpath panic.
    #[test]
    fn tun_write_first_item_wouldblock_is_zero_sent() {
        let res = wouldblock_as_empty_batch(Err(Error::new(
            ErrorKind::WouldBlock,
            "Wintun send ring full",
        )));
        assert_eq!(
            res.unwrap(),
            0,
            "a first-item WouldBlock must be nonfatal backpressure"
        );
    }

    /// A successful batch result passes through unchanged.
    #[test]
    fn tun_write_success_passes_through() {
        assert_eq!(wouldblock_as_empty_batch(Ok(7)).unwrap(), 7);
    }

    /// Anything that is not `WouldBlock` stays a batch-level error, so the
    /// caller's `expect("unrecoverable TUN error")` still fires on a real
    /// TUN failure.
    #[test]
    fn tun_write_real_error_stays_fatal() {
        let err = wouldblock_as_empty_batch(Err(Error::new(ErrorKind::BrokenPipe, "TUN gone")))
            .unwrap_err();
        assert_eq!(err.kind(), ErrorKind::BrokenPipe);
    }

    /// zipline#133 Windows smoke test: a substrate-socket wake that finds
    /// no datagram (on Windows the wait Event is reset before the drain, so
    /// such wakes are expected) makes every engine's batch receive fail
    /// its FIRST item with `WouldBlock`, which the batch loop returns as
    /// the batch error. That must classify as an empty batch — the smoke
    /// test's `ph.exe adapter` panicked here (`fastpath_io.rs`
    /// `.unwrap()`, os error 10035) right after docking.
    #[test]
    fn substrate_recv_on_empty_socket_is_empty_batch() {
        for name in batch_io::engine_names() {
            let mut bio = batch_io::select_engine_by_name(name)
                .unwrap()
                .instantiate(4)
                .unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket.set_nonblocking(true).unwrap();

            let mut bufs: Vec<Vec<u8>> = (0..4).map(|_| Vec::with_capacity(64)).collect();
            let mut results = Vec::new();
            let n = wouldblock_as_empty_batch(bio.try_recv_buf_from_to_batch(
                &socket,
                bufs.iter_mut(),
                &mut results,
            ))
            .unwrap_or_else(|err| {
                panic!("engine {name}: empty socket must be an empty batch, got {err}")
            });
            // Engines differ in shape (io_uring completes every item with
            // a per-item `WouldBlock`; the unbatched engines fail the first
            // item), but none may yield a packet.
            assert!(
                results[..n]
                    .iter()
                    .all(|r| matches!(r, Err(e) if e.kind() == ErrorKind::WouldBlock)),
                "engine {name}: nothing to receive"
            );
        }
    }
}
