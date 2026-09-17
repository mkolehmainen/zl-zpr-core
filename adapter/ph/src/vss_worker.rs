use crate::address_pool::AddressPool;
use crate::prelude::*;
use crate::{visa_mgmt, visa_table};

use libnode::vss::{ConfigureResponse, ListProcessingResponse, SetTopologyResponse, VSSMessage};
use tokio::sync::mpsc;
use zpr::vsapi_types::{ApiResponseError, ErrorCode, Link, Param, ParamValue, VisaOp, pname};

pub async fn launch(asm: Arc<Assembly>, mut queue: mpsc::Receiver<VSSMessage>) {
    while let Some(msg) = queue.recv().await {
        match msg {
            VSSMessage::PushVisaOp(ops, resp_tx) => {
                let mut processed = 0u32;
                let mut failed = false;
                for op in ops {
                    match process_visaop(&asm, op) {
                        Ok(()) => processed += 1,
                        Err(e) => {
                            error!(target: VISA_MGMT, "error processing pushed visa op: {e}");
                            failed = true;
                            break;
                        }
                    }
                }
                let resp = if failed {
                    ListProcessingResponse::Failed {
                        processed,
                        e: ErrorCode::Internal,
                    }
                } else {
                    ListProcessingResponse::Ack { processed }
                };
                let _ = resp_tx.send(resp);
            }

            VSSMessage::RevokeAuth(addrs, resp_tx) => {
                // zipline#45 C5: for each revoked ZPR address docked on this
                // node, terminate the actor's link via the existing close
                // path (which deregisters the actor's addresses and removes
                // its visas — see deregister_actor_addresses /
                // clean_up_link_state). Unknown addresses are a no-op: the
                // VS may broadcast revocations for actors docked elsewhere.
                let processed = process_revoke_auth(&asm, &addrs);
                let _ = resp_tx.send(ListProcessingResponse::Ack { processed });
            }

            VSSMessage::SetServices(services, resp_tx) => {
                debug!(target: VSS_RPC, "received services update with {} entries", services.len());
                let mut svcs = asm.vs_auth_services.write().unwrap();
                svcs.update(None, services);
                let _ = resp_tx.send(Ok(()));
            }

            VSSMessage::Configure(params, resp_tx) => {
                debug!(target: VSS_RPC, "received VSS configuration update with {} entries", params.len());
                let resp = process_configuration(&asm, params);
                let _ = resp_tx.send(resp);
            }

            VSSMessage::SetTopology(links, resp_tx) => {
                debug!(target: VSS_RPC, "received topology update with {} links", links.len());
                let resp = process_topology(&asm, links);
                let _ = resp_tx.send(resp);
            }
        }
    }
}

pub fn process_visaop(asm: &Arc<Assembly>, op: VisaOp) -> Result<(), visa_table::VisaTableError> {
    match op {
        VisaOp::Grant(visa) => {
            let visa_id = visa.issuer_id;
            debug!(target: VISA_MGMT, "received pushed visa, id={visa_id}");
            let _vid = visa_mgmt::insert_visa(asm, visa)?;
        }
        VisaOp::RevokeVisaId(id) => {
            debug!(target: VISA_MGMT, "received pushed revocation, id={id}");
            visa_mgmt::handle_revocation(asm, id as VisaId)?;
        }
    }
    Ok(())
}

/// Terminate the link of every actor in `addrs` that is docked on this node
/// (zipline#45 C5). Termination runs the normal close path, which notifies
/// the VS of the disconnect and clears the actor's visas; addresses not
/// docked here are counted but otherwise ignored (no-op ack). Returns the
/// number of addresses processed (all of them: a revocation for an unknown
/// address is *successfully* processed as a no-op).
pub fn process_revoke_auth(asm: &Arc<Assembly>, addrs: &[std::net::IpAddr]) -> u32 {
    use crate::link_state::LinkEvent;
    use crate::zdp::TerminateReason;

    for addr in addrs {
        let addr = zpr_utils::net_defs::IpAddress::new_from_std(addr);
        // Only peer links dock actors; a match against a local/self address
        // is not a docked actor, so search the peer table directly.
        let docked_link = asm.peer_table.find(|(_id, peer)| {
            peer.link_state_machine
                .get_actor_addresses()
                .iter()
                .any(|a| *a == addr)
        });
        match docked_link {
            Some((link_id, _peer)) => {
                let link_id = link_id.get();
                warn!(target: VSS_RPC,
                    "revoke_auth: terminating {} (actor {addr} revoked by the visa service)",
                    asm.formatted_link_id(link_id));
                // Shutdown quells restart behavior; the close path
                // deregisters the actor's addresses (removing visas).
                if let Err(e) = asm
                    .process_link_state_event(link_id, LinkEvent::Close(TerminateReason::Shutdown))
                {
                    error!(target: VSS_RPC,
                        "revoke_auth: failed to terminate {}: {e}",
                        asm.formatted_link_id(link_id));
                }
            }
            None => {
                debug!(target: VSS_RPC,
                    "revoke_auth: {addr} is not docked on this node (no-op)");
            }
        }
    }
    addrs.len() as u32
}

/// Visa service sends configuration info here. Currently includes:
/// - AAA network to use (will be updated on the assembly).
fn process_configuration(asm: &Arc<Assembly>, params: Vec<Param>) -> ConfigureResponse {
    let mut aaa_ipnet_str = None;

    for param in params {
        match param.name.as_str() {
            pname::AAA_PREFIX => match param.value {
                ParamValue::StrParam(s) => {
                    if aaa_ipnet_str.is_some() {
                        error!(target: VSS_RPC, "multiple AAA_PREFIX parameters received");
                        return Err(ApiResponseError {
                            code: ErrorCode::ParamError,
                            message: "multiple AAA_PREFIX parameters".into(),
                            retry_in: 0,
                        });
                    }
                    aaa_ipnet_str = Some(s);
                }
                _ => {
                    error!(target: VSS_RPC, "invalid value type for AAA_PREFIX param");
                    return Err(ApiResponseError {
                        code: ErrorCode::ParamError,
                        message: "invalid type for AAA_PREFIX".into(),
                        retry_in: 0,
                    });
                }
            },
            _ => {
                info!(target: VSS_RPC, "unrecognized configuration parameter: {}", param.name);
            }
        }
    }

    if let Some(net) = aaa_ipnet_str {
        match net.parse() {
            Ok(ipnet) => {
                let pool = AddressPool::new(ipnet).map_err(|e| {
                    error!(target: VSS_RPC, "rejected AAA_PREFIX value: {e}");
                    ApiResponseError {
                        code: ErrorCode::ParamError,
                        message: format!("AAA_PREFIX rejected"),
                        retry_in: 0,
                    }
                })?;

                debug!(target: VSS_RPC, "updating local AAA address pool with network {}", ipnet);
                asm.address_pool.lock().unwrap().replace(pool);
            }
            Err(e) => {
                error!(target: VSS_RPC, "invalid AAA_PREFIX value: {e}");
                return Err(ApiResponseError {
                    code: ErrorCode::ParamError,
                    message: format!("invalid AAA_PREFIX"),
                    retry_in: 0,
                });
            }
        }
    }

    Ok(())
}

/// Placeholder. Links not yet acted on.
fn process_topology(_asm: &Arc<Assembly>, links: Vec<Link>) -> SetTopologyResponse {
    info!(target: VSS_RPC, "received topology update with {} links (not yet implemented)", links.len());
    for (i, link) in links.iter().enumerate() {
        info!(target: VSS_RPC, "[link {i}]-> peer {:?}, zpr addr {}", link.peer, link.zpr_addr);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::link_state::{LinkState, LinkType};
    use crate::peer_table;
    use std::net::IpAddr;
    use tokio::task::LocalSet;
    use zpr_utils::net_defs::{self, IpAddress};

    fn add_active_peer_with_actor(asm: &Arc<Assembly>, actor: IpAddr) -> zpr::packet_info::LinkId {
        let entry = asm.peer_table.vacant_entry().unwrap();
        let link_id = entry.key();
        let ps = peer_table::test::create_dummy_peer_state(
            link_id,
            LinkType::AdapterToNode,
            SubstrateAddr::from(([127, 0, 0, 1], 9000 + link_id.get() as u16)),
            net_defs::ScopedIpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 2).into()),
        );
        entry.insert(ps);
        let peer = asm.peer_table.get(link_id.get()).unwrap();
        peer.link_state_machine.test_set_state(LinkState::Active);
        peer.link_state_machine
            .test_add_actor_address(IpAddress::new_from_std(&actor));
        link_id.get()
    }

    /// C5 (zipline#45): revoke_auth for an actor docked here terminates the
    /// actor's link via the existing close path; an unknown address is a
    /// no-op — both count as processed in the ack.
    #[tokio::test]
    async fn test_revoke_auth_terminates_docked_actor_and_ignores_unknown() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let docked: IpAddr = "10.9.8.7".parse().unwrap();
                let unknown: IpAddr = "10.0.0.99".parse().unwrap();
                let link_id = add_active_peer_with_actor(&asm, docked);

                let processed = process_revoke_auth(&asm, &[docked, unknown]);
                assert_eq!(processed, 2, "both addresses count as processed");

                let state = asm
                    .peer_table
                    .get(link_id)
                    .unwrap()
                    .link_state_machine
                    .get_state();
                assert!(
                    !matches!(state, LinkState::Active),
                    "docked actor's link must leave Active after revoke_auth, got {state:?}"
                );
            })
            .await
    }

    /// C5 (zipline#45): revoke_auth with only unknown addresses changes no
    /// link state and still acks every address.
    #[tokio::test]
    async fn test_revoke_auth_unknown_address_is_noop() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let docked: IpAddr = "10.9.8.7".parse().unwrap();
                let unknown: IpAddr = "10.0.0.99".parse().unwrap();
                let link_id = add_active_peer_with_actor(&asm, docked);

                let processed = process_revoke_auth(&asm, &[unknown]);
                assert_eq!(processed, 1);
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::Active,
                    "an unrelated link must not be disturbed"
                );
            })
            .await
    }
}
