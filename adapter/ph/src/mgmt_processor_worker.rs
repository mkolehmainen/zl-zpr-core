use crate::assembly::Assembly;
use crate::fastpath;
use crate::mgmt::{self, HandleMgmtError, HandleMgmtResult};
use crate::packet::Packet;
use crate::queues::MgmtProcessorMessage;
use crate::zdp::*;
use crate::zpr;
use std::future::Future;
use tokio::sync::mpsc;
use zpr_ext::zerocopy::*;

#[derive(Clone, Copy)]
pub struct Config {
    pub link_id: zpr::LinkId,
}

async fn worker<'pktbuf>(
    config: &Config,
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<MgmtProcessorMessage<'pktbuf>>,
) {
    while let Some(msg) = queue.recv().await {
        match msg {
            MgmtProcessorMessage::Packet(pkt) => {
                eprintln!(
                    "{}: dequeued mgmt message from {}",
                    asm.system_name, config.link_id
                );
                match handle_packet(asm, config.link_id, pkt).await {
                    Ok(()) => (),
                    Err((err, pkt)) => fastpath::drop_and_count(asm, pkt, err),
                }
            }

            MgmtProcessorMessage::TestPacket(pkt) => pkt.acknowledge(queue.len(), 1),
        }
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    config: &Config,
    asm: AsmRef,
    mut queue: mpsc::Receiver<MgmtProcessorMessage<'pktbuf>>,
) -> impl Future<Output = ()> + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &mut queue).await }
}

async fn handle_packet<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    ingress_link_id: zpr::LinkId,
    mut pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let Some(base_hdr) = ZdpBaseHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    eprintln!(
        "{}: handling mgmt message from {} type {:?} seq_num {}",
        asm.system_name, ingress_link_id, base_hdr.packet_type, base_hdr.sequence_number
    );

    let packet_type = base_hdr.packet_type;
    let seq_num = base_hdr.sequence_number.get() as u64; // TODO: reconstitute full seq num given expected seq num state

    if packet_type.is_response() {
        eprintln!("{}: got response from {}", asm.system_name, ingress_link_id);

        // Gets the designated sender, attempts to send the response, if not drops
        // the packet and increments corresponding counter
        let Some(peer_state) = asm.peer_table.get(ingress_link_id) else {
            return Err((HandleMgmtError::UnexpectedMgmtResponse, pkt));
        };

        peer_state
            .sync_req_state
            .forward_response(seq_num, (packet_type, pkt))
            .map_err(|pkt| (HandleMgmtError::UnexpectedMgmtResponse, pkt))
    } else if base_hdr.packet_type.is_per_flow() {
        let Some(per_flow_hdr) = ZdpPerFlowHeader::read_from_buf(&mut pkt) else {
            return Err((HandleMgmtError::BadStructure, pkt));
        };

        let stream_id: zpr::StreamId = per_flow_hdr.stream_id.into();

        match base_hdr.packet_type {
            ZdpPacketType::TransitPacket => panic!("unexpected Transit Packet in management path"),

            ZdpPacketType::BindAgentAddressRequest => {
                mgmt::handle_bind_agent_address_request(
                    asm,
                    ingress_link_id,
                    stream_id,
                    seq_num,
                    pkt,
                )
                .await
            }

            packet_type => Err((HandleMgmtError::UnknownType(packet_type.0), pkt)),
        }
    } else {
        match base_hdr.packet_type {
            ZdpPacketType::Report => mgmt::handle_report(asm, ingress_link_id, pkt).await,

            ZdpPacketType::Discard => mgmt::handle_discard(asm, ingress_link_id, pkt).await,

            ZdpPacketType::KeyManagement => {
                mgmt::handle_key_management(asm, ingress_link_id, pkt).await
            }

            ZdpPacketType::HelloRequest => {
                mgmt::handle_hello_request(asm, ingress_link_id, seq_num, pkt).await
            }

            packet_type => Err((HandleMgmtError::UnknownType(packet_type.0), pkt)),
        }
    }
}
