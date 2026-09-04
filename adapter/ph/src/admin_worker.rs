//! Receives commands, either from the cli or from someone directly interfacing
//! with the socket, performs action based on received command
//! To avoid excess parsing, the command must not have spaces

#![allow(unused_imports)]
#![allow(dead_code)]

use crate::link_state::{
    AuthAgentHandle, AuthFailureReason, LinkEvent, LinkState, OidcCredentialRequest,
};
use crate::logging;
use crate::logging::{levels, targets};
use crate::prelude::*;
use crate::test_packet::TestPacketMetrics;
use crate::zdp::TerminateReason;
use admin_api::rpc_commands::RpcCommands;
use admin_api::v1 as cli;
use cbpf_rs;
use cli::cmd_line_inter as svc;
use core::future::Future;
use hdrhistogram::Histogram;
use std::f64::consts::SQRT_2;
use std::fmt::Write;
use std::io::Error;
use std::io::IoSliceMut;
use std::net::IpAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot::error::RecvError;
use tokio::task::JoinSet;
use tokio::time::interval;
use tokio_util::compat::*;
use zpr_ext::std::os::unix::net::{AncillaryData, SocketAncillary};
use zpr_ext::tokio::net::*;

pub async fn launch_capnp(
    asm: Arc<Assembly>,
    listener: UnixListener,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let (sock, _addr) = listener.accept().await?;

        let (reader, writer) = sock.into_split();

        #[cfg(not(feature = "capnp-ancillary"))]
        let network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(reader).compat(),
            tokio::io::BufWriter::new(writer).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Server,
            capnp::message::ReaderOptions::new(),
        );

        //use an FD-passing transport instead of a plain byte stream.
        #[cfg(feature = "capnp-ancillary")]
        let network = capnp_rpc::twoparty::io::VatNetwork::new_with_fds(
            capnp_futures::io::tokio::UnixFdStream::new(reader),
            capnp_futures::io::tokio::UnixFdStream::new(writer),
            1,
            capnp_rpc::rpc_twoparty_capnp::Side::Server,
            capnp::message::ReaderOptions::new(),
        );

        let service: svc::Client = capnp_rpc::new_client(AdminServiceImpl { asm: asm.clone() });

        let rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), Some(service.clone().client));
        tokio::task::spawn_local(async move {
            let err = rpc_system.await;
            err
        });
    }
}

pub async fn launch(asm: Arc<Assembly>, listener: UnixListener) {
    match launch_capnp(asm.clone(), listener).await {
        Ok(()) => (),
        Err(e) => error!(target: RPC, "RPC System error: {}", e),
    };
}

struct AdminServiceImpl {
    asm: Arc<Assembly>,
}

impl svc::Server for AdminServiceImpl {
    async fn echo(
        self: Rc<Self>,
        _: svc::EchoParams,
        _: svc::EchoResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: RPC, "Echo procedure initiated");

        Ok(())
    }

    async fn reset_counters(
        self: Rc<Self>,
        _: svc::ResetCountersParams,
        _: svc::ResetCountersResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Reset counters procedure initiated");
        for value in self.asm.counters.management.values() {
            value.reset();
        }

        for fastpath in self.asm.counters.fastpaths.lock().unwrap().iter() {
            for value in fastpath.values() {
                value.reset();
            }
        }

        Ok(())
    }

    async fn counters(
        self: Rc<Self>,
        _: svc::CountersParams,
        mut results: svc::CountersResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: RPC, "Counters procedure initiated");
        let mut results_builder = results.get().init_counts();

        let mut counters_builder = results_builder
            .reborrow()
            .init_management()
            .init_counters(self.asm.counters.management.len() as u32);

        for (i, (key, &ref value)) in self.asm.counters.management.iter().enumerate() {
            let mut counter = counters_builder.reborrow().get(i as u32);
            counter.set_name(key.name());
            counter.set_val(value.get_count());
        }

        {
            let fastpaths = self.asm.counters.fastpaths.lock().unwrap();

            // Initialize builder for list of fastpaths
            let mut fastpaths_builder = results_builder
                .reborrow()
                .init_fastpaths(fastpaths.len() as u32);
            for (i, fastpath) in fastpaths.iter().enumerate() {
                // Initialize builder for individual fastpath and set its ID
                let mut fastpath_builder = fastpaths_builder.reborrow().get(i as u32);
                fastpath_builder.set_id(i as u32);

                // Set counters
                let mut counters_builder = fastpath_builder.init_counters(fastpath.len() as u32);
                for (i, (key, &ref value)) in fastpath.iter().enumerate() {
                    let mut counter = counters_builder.reborrow().get(i as u32);
                    counter.set_name(key.name());
                    counter.set_val(value.get_count());
                }
            }
        }

        results_builder.set_uptime_sec(self.asm.get_uptime().as_secs());
        results_builder.set_uptime_subsec_ms(self.asm.get_uptime().subsec_millis());

        Ok(())
    }

    #[cfg(not(feature = "capnp-ancillary"))]
    async fn set_capture_file(
        self: Rc<Self>,
        _: svc::SetCaptureFileParams,
        _: svc::SetCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        Err(capnp::Error::unimplemented(
            "method cmd_line_inter::Server::set_capture_file not implemented".to_string(),
        ))
    }

    /// Opens the capture file from an FD received as ancillary data.
    #[cfg(feature = "capnp-ancillary")]
    async fn set_capture_file(
        self: Rc<Self>,
        params: svc::SetCaptureFileParams,
        mut results: svc::SetCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Set capture file procedure initiated");
        let capture_file = params.get()?.get_capture_file()?;
        let fd = capture_file.client.get_fd().await?;
        let results_builder = results.get().init_result();

        match fd {
            Some(fd) => {
                let owned_fd = fd.try_clone_to_owned().map_err(|e| {
                    capnp::Error::failed(format!("failed to clone capture file fd: {e}"))
                })?;
                let file = File::from(std::fs::File::from(owned_fd));
                match self.asm.capture_worker.open_capture_file(file).await {
                    Ok(()) => {
                        debug!(target: RPC, "Capture file opened");
                        results_builder.init_success().set_none(());
                    }
                    Err(err) => {
                        debug!(target: RPC, "Error opening capture file: {err}");
                        results_builder
                            .init_error()
                            .set_txt(format!("Error opening capture file: {err}").as_str());
                    }
                }
            }
            None => {
                debug!(target: RPC, "Error opening capture file: no file descriptor received");
                results_builder
                    .init_error()
                    .set_txt("Error opening capture file: no file descriptor received");
            }
        }

        Ok(())
    }

    async fn close_capture_file(
        self: Rc<Self>,
        _: svc::CloseCaptureFileParams,
        _: svc::CloseCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        let _ = self.asm.capture_worker.close_capture_file().await;
        self.asm.flow_control.delete_program();

        Ok(())
    }

    async fn flush_capture_file(
        self: Rc<Self>,
        _: svc::FlushCaptureFileParams,
        _: svc::FlushCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Flush capture file procedure initiated");
        let _ = self.asm.capture_worker.flush_capture_file().await;

        Ok(())
    }

    async fn set_capture_program(
        self: Rc<Self>,
        params: svc::SetCaptureProgramParams,
        mut results: svc::SetCaptureProgramResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Set capture program procedure initiated");
        let programs = params.get()?.get_program()?.get_bpf_prog()?;

        let mut insn_vec = Vec::new();

        for program in programs.iter() {
            debug!(
                target: RPC,
                "Capture program values: code: {}, jt: {}, jf: {}, k: {}",
                program.get_code(),
                program.get_jt(),
                program.get_jf(),
                program.get_k()
            );
            let bpf_insn = cbpf_rs::BpfInsn {
                code: program.get_code(),
                jt: program.get_jt(),
                jf: program.get_jf(),
                k: program.get_k(),
            };
            insn_vec.push(bpf_insn);
        }

        let results_builder = results.get().init_result();

        match cbpf_rs::BpfProgram::validate(&insn_vec) {
            Ok(final_program) => {
                self.asm.flow_control.set_program(final_program);
                let mut success_builder = results_builder.init_success();
                success_builder.set_none(());
            }
            _ => {
                let mut error_builder = results_builder.init_error();
                error_builder.set_txt("Invalid program")
            }
        }

        Ok(())
    }

    async fn delete_capture_program(
        self: Rc<Self>,
        _: svc::DeleteCaptureProgramParams,
        _: svc::DeleteCaptureProgramResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Delete capture program procedure initiated");
        self.asm.flow_control.delete_program();
        Ok(())
    }

    async fn perf_sample(
        self: Rc<Self>,
        _: svc::PerfSampleParams,
        mut results: svc::PerfSampleResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Perf sample procedure initiated");
        let mut results_builder = results.get();
        results_builder.set_result("Not currently supported");
        Ok(())
    }

    async fn show_link_summary(
        self: Rc<Self>,
        _: svc::ShowLinkSummaryParams,
        mut results: svc::ShowLinkSummaryResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Show link summary procedure initiated");
        {
            let mut peer_ids = Vec::new();
            self.asm.peer_table.for_each(|(id, peer)| {
                if !peer.is_internal() {
                    peer_ids.push(id.get())
                }
            });

            let mut results_builder = results.get().init_summary(peer_ids.len() as u32);

            for (i, id) in peer_ids.iter().enumerate() {
                results_builder.set(
                    i as u32,
                    format!("  {id}: {}", get_link_summary(&self.asm, *id)),
                );
            }
        }

        Ok(())
    }

    async fn show_link(
        self: Rc<Self>,
        params: svc::ShowLinkParams,
        mut results: svc::ShowLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Show link procedure initiated");
        let id = params.get()?.get_id();
        debug!(target: RPC, "Show {} requested", self.asm.formatted_link_id(id));

        let mut results_builder = results.get();
        let response = match self.asm.peer_table.get(id) {
            Some(peer) => {
                let lsm = &peer.link_state_machine;

                format!(
                    "Link {id} info:\nSubstrate Address: {}\n{}",
                    peer.substrate_addr, lsm,
                )
            }
            None => format!("No such link {id}\n"),
        };

        results_builder.set_result(response);

        Ok(())
    }

    async fn configure_link(
        self: Rc<Self>,
        _: svc::ConfigureLinkParams,
        _: svc::ConfigureLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Configure link procedure initiated");
        Ok(())
    }

    async fn start_link(
        self: Rc<Self>,
        params: svc::StartLinkParams,
        mut results: svc::StartLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Start link procedure initiated");
        let id = params.get()?.get_id();
        debug!(target: RPC, "Start {} requested", self.asm.formatted_link_id(id));

        // An AuthAgent capability is optional: a null (absent) agent means a
        // device-only link, which behaves exactly as before OIDC. When one is
        // supplied, hold it on the link for the link's lifetime so the FSM
        // can request user credentials out of band.
        if params.get()?.has_auth_agent() {
            let agent_client = params.get()?.get_auth_agent()?;
            if let Some(peer) = self.asm.peer_table.get(id) {
                peer.link_state_machine
                    .set_auth_agent(spawn_auth_agent_bridge(agent_client));
                debug!(target: RPC, "AuthAgent registered for {}", self.asm.formatted_link_id(id));
            } else {
                warn!(target: RPC, "startLink: no such link {id}, cannot register AuthAgent");
            }
        }

        let results_builder = results.get().init_result();

        match self.asm.process_link_state_event(id, LinkEvent::Start) {
            Ok(_) => {
                let mut success_builder = results_builder.init_success();
                success_builder.set_none(());
            }
            Err(e) => {
                let resp = format!("Failed to start link {}: {:?}\n", id, e);
                let mut error_builder = results_builder.init_error();
                error_builder.set_txt(resp);
            }
        }
        Ok(())
    }

    async fn stop_link(
        self: Rc<Self>,
        params: svc::StopLinkParams,
        mut results: svc::StopLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Stop link procedure initiated");
        let task_asm = self.asm.clone();
        let id = params.get()?.get_id();
        debug!(target: RPC, "Stop {} requested", self.asm.formatted_link_id(id));

        let results_builder = results.get().init_result();

        match task_asm.process_link_state_event(id, LinkEvent::Close(TerminateReason::Other)) {
            Ok(_) => {
                let mut success_builder = results_builder.init_success();
                success_builder.set_none(());
            }
            Err(e) => {
                let resp = format!("Failed to stop link {}: {:?}\n", id, e);
                let mut error_builder = results_builder.init_error();
                error_builder.set_txt(resp);
            }
        }
        Ok(())
    }

    async fn reset_link(
        self: Rc<Self>,
        params: svc::ResetLinkParams,
        _: svc::ResetLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Reset link procedure initiated");
        let id = params.get()?.get_id();
        debug!(target: RPC, "Reset {} requested", self.asm.formatted_link_id(id));

        self.asm.reset_peer(id).await;
        Ok(())
    }

    async fn change_logging(
        self: Rc<Self>,
        params: svc::ChangeLoggingParams,
        mut results: svc::ChangeLoggingResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Change logging procedure initiated");
        let task_asm = self.asm.clone();
        let log_state = params.get()?.get_logs()?;
        // let log_vec: Vec<&str> = log_state.split_whitespace().collect();
        let mut applied: Vec<String> = Vec::new();
        let mut ignored: Vec<String> = Vec::new();
        for log in log_state.iter() {
            let target = log.get_level()?.to_str()?;
            let level = log.get_target()?.to_str()?;
            if targets::ALL_TARGETS.contains(&target)
                && levels::ALL_LEVELS.contains(&level.to_uppercase().as_str())
            {
                task_asm
                    .logging
                    .lock()
                    .unwrap()
                    .insert(target.to_string(), level.to_uppercase());
                applied.push(format!("{}={}", target, level));
                debug!(target: RPC, "Logging pair: {target}={level} applied");
            } else {
                ignored.push(format!("{}={}", target, level));
                debug!(target: RPC, "Logging pair: {target}={level} ignored");
            }
        }

        logging::reload_filter(&task_asm.reload_handle, &task_asm.logging.lock().unwrap());

        let mut results_builder = results.get().init_result();
        if applied.len() > 0 {
            let _ = results_builder.set_applied(applied.as_slice());
        }
        if ignored.len() > 0 {
            let _ = results_builder.set_ignored(ignored.as_slice());
        }

        Ok(())
    }

    async fn get_node_info(
        self: Rc<Self>,
        _: svc::GetNodeInfoParams,
        mut results: svc::GetNodeInfoResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Get node info from adapter");
        let task_asm = self.asm.clone();

        let mut results_builder = results.get().init_result();

        if let PhMode::Node = task_asm.ph_mode {
            let resp = format!("Not in adapter mode");
            let mut error_builder = results_builder.reborrow().init_error();
            error_builder.set_txt(resp);
            return Ok(());
        }

        match task_asm.peer_table.get(DOCK_LINK_ID) {
            Some(pt) => {
                let substrate_addr = pt.substrate_addr;
                let success_builder = results_builder.init_success();
                let mut sock_addr_builder = success_builder.init_sock_addr();

                sock_addr_builder.set_port(substrate_addr.port());
                let mut addr_builder = sock_addr_builder.init_addr();

                match substrate_addr.ip() {
                    IpAddr::V4(addr) => {
                        addr_builder.set_v4(&addr.octets());
                    }
                    IpAddr::V6(addr) => {
                        addr_builder.set_v6(&addr.octets());
                    }
                }
            }
            None => {
                let resp = format!("No node found");
                let mut error_builder = results_builder.init_error();
                error_builder.set_txt(resp);
            }
        }

        Ok(())
    }
}

// This code will eventually be removed and the logic moved into perf_sample above
/// Performs a performance sample on the PH by measuring the queue depths and the
/// packet latencies throughout the system. Requires the duration of the
/// sample as well as the number of samples per second.
async fn perf_sample(_asm: &Assembly, _duration: &str, _rate: &str) -> String {
    // FIXME: There are now a dynamically allocated number of mgmt_processors...
    // this needs to be restructured to account for that fact.
    Default::default()

    /*let send_duration = Duration::new(duration.parse().unwrap(), 0);
    let begin_time = Instant::now();
    let mut send_interval = interval(Duration::new(0, 1000000000 / rate.parse::<u32>().unwrap()));

    let mut mgmt_processor_duration = Histogram::<u64>::new(1).unwrap();
    let mut mgmt_processor_depth = Histogram::<u64>::new(1).unwrap();
    let mut mgmt_processor_batch = Histogram::<u64>::new(1).unwrap();

    send_interval.tick().await;

    // Enqueue test packets at the frequency desired by the user for the
    // desired amount of time
    while begin_time.elapsed().as_secs() < send_duration.as_secs() {
        let in_processor = asm.mgmt_processor.enqueue_test_packet().await;
        record_metrics(
            in_processor,
            &mut mgmt_processor_duration,
            &mut mgmt_processor_depth,
            &mut mgmt_processor_batch,
        );

        // TODO: record metrics from TUN interface and UDP socket

        send_interval.tick().await;
    }

    // Get values at 10, 25, 50, 75, 90 quantiles for each hist as well as the mean
    let mgmt_processor = three_hists_values(
        "Management Processor",
        &mgmt_processor_duration,
        &mgmt_processor_depth,
        &mgmt_processor_batch,
    );

    format!("{mgmt_processor}")*/
}

/// Helper for perf_sample
/// Records the metrics from a single test packet to the trio of histograms
/// tracking the data from the queue that particular test packet was enqueued on
fn record_metrics(
    metrics: Result<TestPacketMetrics, RecvError>,
    hist_dur: &mut Histogram<u64>,
    hist_dep: &mut Histogram<u64>,
    hist_batch: &mut Histogram<u64>,
) {
    let _ = hist_dur.record(
        metrics
            .as_ref()
            .unwrap()
            .in_queue
            .as_nanos()
            .try_into()
            .unwrap(),
    );
    let _ = hist_dep.record(metrics.as_ref().unwrap().queue_depth.try_into().unwrap());
    let _ = hist_batch.record(metrics.as_ref().unwrap().batch_size.try_into().unwrap());
}

/// Helper for perf_sample
/// Gets the values from the trio of histograms for each queue. Returns a string with the
/// data from all three histograms
fn three_hists_values(
    hist_name: &str,
    hist_dur: &Histogram<u64>,
    hist_dep: &Histogram<u64>,
    hist_batch: &Histogram<u64>,
) -> String {
    let mut info = String::new();

    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(
            &format!("{hist_name} Duration"), // TODO could use en enum and a display to get the name
            "ns",
            hist_dur
        )
        .as_str()
    );
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(&format!("{hist_name} Depth"), " packets", hist_dep).as_str()
    );
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(&format!("{hist_name} Batch"), " packets", hist_batch).as_str()
    );
    let mean: u64 = (hist_dur.mean() / (1.0 + hist_dep.mean())) as u64;
    let _ = write!(&mut info, "{hist_name} approx packet time: {mean}ns\n\n\n");

    info
}

/// Helper for three_hists_values
/// Gets the data from a single histogram. Requires the histogram and units of
/// measurement to format the data, as well as the histogram itself.
/// Returns string with the data from one historgram.
fn values_from_hist(hist_name: &str, units: &str, hist: &Histogram<u64>) -> String {
    let ten: u64 = hist.value_at_quantile(0.10);
    let twenty_five: u64 = hist.value_at_quantile(0.25);
    let fifty: u64 = hist.value_at_quantile(0.50);
    let seventy_five: u64 = hist.value_at_quantile(0.75);
    let ninety: u64 = hist.value_at_quantile(0.90);
    let mean: f64 = hist.mean();

    let mut values = format!(
        "{} values at - 10th Quantile: {}{}, 25th Quantile: {}{},\n50th Quantile: {}{}, 75th Quantile: {}{}, 90th Quantile: {}{}, Mean: {}{}\n\n",
        hist_name,
        ten,
        units,
        twenty_five,
        units,
        fifty,
        units,
        seventy_five,
        units,
        ninety,
        units,
        mean,
        units
    );

    let mut iter = hist.iter_log(1, SQRT_2);

    let mut iter_value = iter.next();
    let mut prev_bucket = 0;

    while iter_value != None {
        let curr_bucket = iter_value.as_ref().unwrap().value_iterated_to();
        let _ = write!(
            &mut values,
            "Bucket: {}-{} | {}\n",
            prev_bucket,
            curr_bucket,
            iter_value.unwrap().count_since_last_iteration()
        );

        prev_bucket = curr_bucket;
        iter_value = iter.next();
    }

    let _ = write!(&mut values, "\n");

    values
}

// Takes in ancillary data, extracts the file descriptor, and creates a file using the
// fd
async fn set_capture_file(asm: &Assembly, ancillary: SocketAncillary<'_>) -> String {
    info!(target: RPC, "Setting capture file");
    // Get the ancillary data
    let anc_message = ancillary.into_messages().nth(0).unwrap();
    // Get the SCM rights from the ancillary data
    if let AncillaryData::ScmRights(mut scm_rights) = anc_message.unwrap() {
        debug!(target: RPC, "SCM Rights exist");
        // See if there's actually data in the scm_rights, if yes try to open a
        // capture file, otherwise report failure to open file
        match scm_rights.nth(0) {
            Some(fd) => {
                let std_file = std::fs::File::from(fd.try_into_owned().unwrap()); // tokio::fs::File doesn't implement From<OwnedFd>
                let tokio_file = File::from(std_file);
                match asm.capture_worker.open_capture_file(tokio_file).await {
                    Ok(()) => {
                        debug!(target: RPC, "Capture file opened");
                        format!("Capture file opened\n")
                    }
                    Err(err) => {
                        debug!(target: RPC, "Error opening Capture file: {}\n", err);
                        format!("Error opening Capture file: {}\n", err)
                    }
                }
            }
            None => {
                debug!(target: RPC, "Error opening Capture file: no ancillary data received\n");
                format!("Error opening Capture file: no ancillary data received\n")
            }
        }
    } else {
        debug!(target: RPC, "Error opening Capture file: no ancillary data received\n");
        format!("Error opening Capture file: no ancillary data received\n")
    }
}

/// Bridge a Cap'n Proto [cli::auth_agent::Client] onto the channel-based
/// [AuthAgentHandle] the link state machine consumes.
///
/// Cap'n Proto clients are !Send and bound to this RPC task's LocalSet, so
/// the FSM cannot hold one directly; instead it sends
/// [OidcCredentialRequest]s down an unbounded channel and this task performs
/// the actual getOidcCredential calls, mapping errors onto
/// [AuthFailureReason]. The task ends when the last sender is dropped (link
/// gone) or the RPC connection dies.
///
/// Each call's lifetime is bounded (see the Codex review on zipline#13's
/// PR): the RPC is raced against the requester abandoning the request
/// (reply receiver dropped, e.g. the link timed out and was torn down) and
/// against [config::OIDC_USER_INTERACTION_TIMEOUT] itself. Either way the
/// in-flight call is dropped — which cancels it on the wire — so a later
/// request on the same link cannot queue forever behind an abandoned one.
fn spawn_auth_agent_bridge(agent: cli::auth_agent::Client) -> AuthAgentHandle {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<OidcCredentialRequest>();

    tokio::task::spawn_local(async move {
        while let Some(mut req) = rx.recv().await {
            let mut request = agent.get_oidc_credential_request();
            {
                let mut rb = request.get();
                rb.set_issuer(&req.idp.issuer[..]);
                rb.set_client_id(&req.idp.client_id[..]);
                rb.set_client_secret(req.idp.client_secret.as_deref().unwrap_or(""));
                let mut scopes = rb.reborrow().init_scopes(req.idp.scopes.len() as u32);
                for (i, scope) in req.idp.scopes.iter().enumerate() {
                    scopes.set(i as u32, &scope[..]);
                }
                rb.set_allow_offline_access(req.idp.allow_offline_access);
                rb.set_nonce(&req.nonce[..]);
                rb.set_interactive(req.interactive);
            }

            let outcome = tokio::select! {
                // The requester stopped waiting (the link timed out or was
                // torn down). Drop the RPC — cancelling it — and move on to
                // the next queued request instead of blocking on a call
                // nobody will consume.
                _ = req.reply.closed() => {
                    debug!(target: RPC, "AuthAgent request abandoned by requester, cancelling RPC");
                    continue;
                }
                // Nobody should still be waiting past the interaction
                // timeout; cut the call loose so the bridge cannot wedge
                // even if the requester's own timer misfires.
                _ = tokio::time::sleep(config::OIDC_USER_INTERACTION_TIMEOUT) => {
                    warn!(target: RPC, "AuthAgent call exceeded the user interaction timeout, cancelling RPC");
                    Err(AuthFailureReason::InteractionTimeout)
                }
                result = request.send().promise => match result {
                    Ok(response) => match parse_agent_response(response) {
                        Ok(id_token) => Ok(id_token),
                        Err(reason) => Err(reason),
                    },
                    Err(e) => {
                        warn!(target: RPC, "AuthAgent call failed: {e}");
                        Err(AuthFailureReason::AgentError(e.to_string()))
                    }
                },
            };
            // The receiver may be gone (e.g. the link timed out); that is fine.
            let _ = req.reply.send(outcome);
        }
        debug!(target: RPC, "AuthAgent bridge shutting down");
    });

    tx
}

/// Decode a getOidcCredential response into the ID token or a failure reason.
/// The agent reports "access_denied" for a user refusal per the spec's error
/// taxonomy; anything else in the error text is an agent-side failure.
fn parse_agent_response(
    response: capnp::capability::Response<cli::auth_agent::get_oidc_credential_results::Owned>,
) -> Result<String, AuthFailureReason> {
    let results = response
        .get()
        .map_err(|e| AuthFailureReason::AgentError(e.to_string()))?;
    let result = results
        .get_result()
        .map_err(|e| AuthFailureReason::AgentError(e.to_string()))?;
    match result
        .which()
        .map_err(|e| AuthFailureReason::AgentError(e.to_string()))?
    {
        cli::success_or_error::Which::Success(_) => {
            let id_token = results
                .get_id_token()
                .and_then(|t| t.to_str().map_err(|e| capnp::Error::failed(e.to_string())))
                .map_err(|e| AuthFailureReason::AgentError(e.to_string()))?
                .to_string();
            if id_token.is_empty() {
                return Err(AuthFailureReason::AgentError(
                    "agent returned an empty id_token".to_string(),
                ));
            }
            Ok(id_token)
        }
        cli::success_or_error::Which::Error(e) => {
            let txt = e
                .and_then(|ev| ev.get_txt())
                .and_then(|t| t.to_str().map_err(|e| capnp::Error::failed(e.to_string())))
                .unwrap_or("unknown agent error")
                .to_string();
            if txt.contains("access_denied") {
                Err(AuthFailureReason::UserDeclined)
            } else {
                Err(AuthFailureReason::AgentError(txt))
            }
        }
    }
}

// Helper for show_link_summary
fn get_link_summary(asm: &Arc<Assembly>, link_id: LinkId) -> String {
    match asm.peer_table.get(link_id) {
        Some(peer) => format!(
            "{} ({:?})",
            peer.substrate_addr,
            peer.link_state_machine.get_state()
        ),
        None => format!("Unconfigured"),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::auth::{self, AuthBlob};
    use crate::config::PACKET_BUFFER_SIZE;
    use crate::link_state::LinkType;
    use crate::packet_queue;
    use crate::peer_table;
    use crate::queues::MgmtSubstrateEgress;
    use crate::zdp;
    use base64::prelude::*;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;
    use tokio::task::LocalSet;
    use zpr_ext::zerocopy::FromBytesExt;
    use zpr_utils::net_defs;

    /// In-process fake AuthAgent whose calls complete only when the test
    /// releases them: each getOidcCredential call appends `(nonce,
    /// Some(release_sender))` to `pending` and then waits for the test to
    /// fire that sender. Leaving the sender in place models a user who
    /// never completes the login; firing it models a (possibly very late)
    /// completion.
    struct GatedAuthAgent {
        id_token: String,
        pending: Rc<RefCell<Vec<(String, Option<tokio::sync::oneshot::Sender<()>>)>>>,
    }

    impl cli::auth_agent::Server for GatedAuthAgent {
        async fn get_oidc_credential(
            self: Rc<Self>,
            params: cli::auth_agent::GetOidcCredentialParams,
            mut results: cli::auth_agent::GetOidcCredentialResults,
        ) -> Result<(), capnp::Error> {
            let nonce = params.get()?.get_nonce()?.to_str()?.to_string();
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.pending.borrow_mut().push((nonce, Some(tx)));
            // Held until the test releases this call (or the caller cancels
            // the RPC, which drops this task).
            let _ = rx.await;
            let mut rb = results.get();
            rb.set_id_token(&self.id_token[..]);
            rb.init_result().init_success().set_none(());
            Ok(())
        }
    }

    /// A minimal advertised OIDC identity provider for bridge/FSM tests.
    fn test_idp() -> auth::OidcIdpInfo {
        auth::OidcIdpInfo {
            issuer: "https://idp.test".to_string(),
            client_id: "test-client".to_string(),
            client_secret: None,
            scopes: vec!["openid".to_string()],
            allow_offline_access: false,
        }
    }

    /// Assembly with a readable management egress queue and one
    /// AdapterToNode peer; no bootstrap key, so OIDC is the only
    /// authentication path.
    fn oidc_test_assembly() -> (
        Arc<Assembly>,
        packet_queue::Receiver<PACKET_BUFFER_SIZE>,
        LinkId,
    ) {
        let (eg_tx, eg_rx) = packet_queue::packet_queue::<PACKET_BUFFER_SIZE>(32);
        let mut builder = TestAssemblyBuilder::new();
        builder.mgmt_substrate_egress = Some(MgmtSubstrateEgress::new(eg_tx));
        let asm = Arc::new(create_assembly(builder));

        let entry = asm.peer_table.vacant_entry().unwrap();
        let link_id = entry.key();
        let ps = peer_table::test::create_dummy_peer_state(
            link_id,
            LinkType::AdapterToNode,
            SubstrateAddr::from(([127, 0, 0, 1], 9000)),
            net_defs::ScopedIpAddr::V4(Ipv4Addr::new(127, 0, 0, 2).into()),
        );
        let link_id = entry.insert(ps).get();
        (asm, eg_rx, link_id)
    }

    /// A 48-byte InitAuth challenge whose nonce bytes are `tag`, so two
    /// attempts can be told apart by their challenge.
    fn challenge_payload(tag: u8) -> auth::ZdpInitAuthenticationPayload {
        auth::ZdpInitAuthenticationPayload {
            nonce: [tag; 8],
            ctime: 424242u64.into(),
            hmac: [6u8; 32],
        }
    }

    /// The raw challenge bytes the OIDC blob must round-trip.
    fn challenge_bytes(payload: &auth::ZdpInitAuthenticationPayload) -> [u8; 48] {
        let mut challenge = [0u8; 48];
        challenge[0..8].copy_from_slice(&payload.nonce);
        challenge[8..16].copy_from_slice(&payload.ctime.to_bytes());
        challenge[16..48].copy_from_slice(&payload.hmac);
        challenge
    }

    /// Drain every packet currently in the egress queue and return the blob
    /// string of each AcquireZprAddress packet (other packet types, e.g.
    /// TerminateLink from a close, are ignored).
    fn drain_acquire_blob_strs(rx: &mut packet_queue::Receiver<PACKET_BUFFER_SIZE>) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(mut pkt) = rx.try_recv(Box::new([0u8; PACKET_BUFFER_SIZE])) {
            let base = zdp::ZdpBaseHeader::read_from_buf(&mut pkt).unwrap();
            if base.packet_type != zdp::ZdpPacketType::AcquireZprAddress {
                continue;
            }
            let _mgmt = zdp::ZdpMgmtHeader::read_from_buf(&mut pkt).unwrap();
            let acq = zdp::ZdpAcquireZprAddressHeader::read_from_buf(&mut pkt).unwrap();
            let blob_len = acq.blob_len.get() as usize;
            let blob_bytes = pkt.copy_to_bytes(blob_len);
            out.push(String::from_utf8(blob_bytes.into()).unwrap());
        }
        out
    }

    /// Sleep in small steps until `cond` holds or `max_ms` elapses.
    async fn wait_for(max_ms: u64, mut cond: impl FnMut() -> bool) -> bool {
        for _ in 0..(max_ms / 10) {
            if cond() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        cond()
    }

    /// The bridge must not stay blocked on a getOidcCredential call whose
    /// requester has gone away (link timed out): the abandoned call is
    /// cancelled and the next queued request still reaches the agent.
    #[tokio::test(start_paused = true)]
    async fn test_bridge_abandons_call_when_requester_goes_away() {
        LocalSet::new()
            .run_until(async {
                let pending = Rc::new(RefCell::new(Vec::new()));
                let client: cli::auth_agent::Client = capnp_rpc::new_client(GatedAuthAgent {
                    id_token: "SECOND.JWT.TOKEN".to_string(),
                    pending: pending.clone(),
                });
                let handle = spawn_auth_agent_bridge(client);

                // Request 1: the requester stops waiting (link timeout).
                let (tx1, rx1) = tokio::sync::oneshot::channel();
                handle
                    .send(OidcCredentialRequest {
                        idp: test_idp(),
                        nonce: "nonce-1".to_string(),
                        interactive: true,
                        reply: tx1,
                    })
                    .unwrap();
                assert!(
                    wait_for(2_000, || pending.borrow().len() == 1).await,
                    "agent never saw request 1"
                );
                drop(rx1); // the requester gave up; the bridge must notice

                // Request 2 must still be serviced.
                let (tx2, rx2) = tokio::sync::oneshot::channel();
                handle
                    .send(OidcCredentialRequest {
                        idp: test_idp(),
                        nonce: "nonce-2".to_string(),
                        interactive: true,
                        reply: tx2,
                    })
                    .unwrap();
                assert!(
                    wait_for(5_000, || pending.borrow().len() == 2).await,
                    "request 2 is stuck behind the abandoned request 1"
                );
                let release = pending.borrow_mut()[1].1.take().unwrap();
                let _ = release.send(());

                let outcome = tokio::time::timeout(Duration::from_secs(5), rx2)
                    .await
                    .expect("bridge never answered request 2")
                    .expect("bridge dropped request 2's reply");
                assert_eq!(outcome, Ok("SECOND.JWT.TOKEN".to_string()));
            })
            .await
    }

    /// After WaitForUserAuth times out with the agent call still pending,
    /// a fresh authentication attempt on the same link (same registered
    /// AuthAgent, as after the auto-close/restart path) must reach the
    /// agent and succeed — it must not queue forever behind the abandoned
    /// first call.
    #[tokio::test(start_paused = true)]
    async fn test_timed_out_agent_call_is_abandoned_and_retry_proceeds() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut eg_rx, link_id) = oidc_test_assembly();

                let pending = Rc::new(RefCell::new(Vec::new()));
                let client: cli::auth_agent::Client = capnp_rpc::new_client(GatedAuthAgent {
                    id_token: "RETRY.JWT.TOKEN".to_string(),
                    pending: pending.clone(),
                });
                let handle = spawn_auth_agent_bridge(client);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::WaitForInitAuth);
                    peer.link_state_machine.test_set_oidc_idps(vec![test_idp()]);
                    peer.link_state_machine.set_auth_agent(handle);
                }

                // Attempt 1: the user never completes the login.
                let payload_a = challenge_payload(1);
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedInitAuth((false, Some(payload_a))),
                )
                .unwrap();
                assert!(
                    wait_for(2_000, || pending.borrow().len() == 1).await,
                    "agent never saw attempt 1's call"
                );

                // Let the interaction timeout fire and the link close.
                tokio::time::sleep(config::OIDC_USER_INTERACTION_TIMEOUT).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    assert_eq!(
                        peer.link_state_machine.get_last_auth_failure(),
                        Some(AuthFailureReason::InteractionTimeout)
                    );
                    // The restart path preserves LinkData (and thus the
                    // AuthAgent handle); model it by rewinding the FSM.
                    peer.link_state_machine
                        .test_set_state(LinkState::WaitForInitAuth);
                }
                // Ignore attempt 1's close traffic.
                let _ = drain_acquire_blob_strs(&mut eg_rx);

                // Attempt 2: a new challenge, and this time the user logs in.
                let payload_b = challenge_payload(2);
                let challenge_b = challenge_bytes(&payload_b);
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedInitAuth((false, Some(payload_b))),
                )
                .unwrap();
                assert!(
                    wait_for(5_000, || pending.borrow().len() == 2).await,
                    "attempt 2's call is stuck behind the abandoned attempt-1 call"
                );
                let release = pending.borrow_mut()[1].1.take().unwrap();
                let _ = release.send(());

                // The retry proceeded: the second agent call was bound to
                // attempt 2's challenge (nonce derived from challenge B),
                // and its token moved the link to RegisterAA (the acquire
                // request was initiated). Note the raw packet cannot be
                // read back here: the fake peer never acks attempt 1's
                // TerminateLink, so the serial ZDPR window holds it — a
                // harness artifact, not the bug under test.
                assert_eq!(
                    pending.borrow()[1].0,
                    auth::oidc_nonce_for_challenge(&challenge_b),
                    "attempt 2's agent call is not bound to attempt 2's challenge"
                );
                assert!(
                    wait_for(2_000, || {
                        asm.peer_table
                            .get(link_id)
                            .map(|p| p.link_state_machine.get_state() == LinkState::RegisterAA)
                            .unwrap_or(false)
                    })
                    .await,
                    "retry never reached RegisterAA; state={:?}",
                    asm.peer_table
                        .get(link_id)
                        .map(|p| p.link_state_machine.get_state())
                );
            })
            .await
    }

    /// A very late completion of attempt 1's agent call (after its
    /// WaitForUserAuth timed out and a NEW attempt with a new challenge is
    /// underway) must be discarded, not consumed by the new attempt: the
    /// old token is bound to the old challenge/nonce.
    #[tokio::test(start_paused = true)]
    async fn test_stale_completion_from_prior_attempt_is_discarded() {
        LocalSet::new()
            .run_until(async {
                let (asm, mut eg_rx, link_id) = oidc_test_assembly();

                let pending = Rc::new(RefCell::new(Vec::new()));
                let client: cli::auth_agent::Client = capnp_rpc::new_client(GatedAuthAgent {
                    id_token: "STALE.JWT.TOKEN".to_string(),
                    pending: pending.clone(),
                });
                let handle = spawn_auth_agent_bridge(client);
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(LinkState::WaitForInitAuth);
                    peer.link_state_machine.test_set_oidc_idps(vec![test_idp()]);
                    peer.link_state_machine.set_auth_agent(handle);
                }

                // Attempt 1 (challenge A): times out.
                let payload_a = challenge_payload(1);
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedInitAuth((false, Some(payload_a))),
                )
                .unwrap();
                assert!(
                    wait_for(2_000, || pending.borrow().len() == 1).await,
                    "agent never saw attempt 1's call"
                );
                tokio::time::sleep(config::OIDC_USER_INTERACTION_TIMEOUT).await;
                tokio::time::sleep(Duration::from_millis(500)).await;
                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    assert_eq!(
                        peer.link_state_machine.get_last_auth_failure(),
                        Some(AuthFailureReason::InteractionTimeout)
                    );
                    peer.link_state_machine
                        .test_set_state(LinkState::WaitForInitAuth);
                }
                let _ = drain_acquire_blob_strs(&mut eg_rx);

                // Attempt 2 (challenge B) is now waiting for the user.
                let payload_b = challenge_payload(2);
                asm.process_link_state_event(
                    link_id,
                    LinkEvent::ReceivedInitAuth((false, Some(payload_b))),
                )
                .unwrap();
                tokio::time::sleep(Duration::from_millis(200)).await;
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::WaitForUserAuth
                );

                // Attempt 1's call completes very late. If it was cancelled,
                // this release is a no-op; either way its token must not be
                // consumed by attempt 2.
                let release = pending.borrow_mut()[0].1.take().unwrap();
                let _ = release.send(());
                tokio::time::sleep(Duration::from_millis(500)).await;

                let blob_strs = drain_acquire_blob_strs(&mut eg_rx);
                assert!(
                    blob_strs.is_empty(),
                    "stale attempt-1 completion produced an acquire: {blob_strs:?}"
                );
                assert_eq!(
                    asm.peer_table
                        .get(link_id)
                        .unwrap()
                        .link_state_machine
                        .get_state(),
                    LinkState::WaitForUserAuth,
                    "stale attempt-1 completion moved the FSM off attempt 2"
                );
            })
            .await
    }

    /// In-process fake AuthAgent: returns a fixed ID token and records the
    /// nonce it was asked to bind into it.
    struct FakeAuthAgent {
        id_token: String,
        seen_nonce: Rc<RefCell<Option<String>>>,
    }

    impl cli::auth_agent::Server for FakeAuthAgent {
        async fn get_oidc_credential(
            self: Rc<Self>,
            params: cli::auth_agent::GetOidcCredentialParams,
            mut results: cli::auth_agent::GetOidcCredentialResults,
        ) -> Result<(), capnp::Error> {
            let nonce = params.get()?.get_nonce()?.to_str()?.to_string();
            *self.seen_nonce.borrow_mut() = Some(nonce);
            let mut rb = results.get();
            rb.set_id_token(&self.id_token[..]);
            rb.init_result().init_success().set_none(());
            Ok(())
        }
    }

    /// Full OIDC callback flow against a fake in-process `AuthAgent`:
    /// InitAuth with a known challenge must produce an AcquireZprAddress
    /// packet whose blob array carries both the SS (bootstrap) and OIDC
    /// blobs, with the OIDC blob's challenge equal to the InitAuth payload
    /// and the agent called with `oidc_nonce_for_challenge(&challenge)`.
    #[tokio::test(start_paused = true)]
    async fn test_agent_token_becomes_oidc_blob_with_challenge_nonce() {
        LocalSet::new()
            .run_until(async {
                // Egress queue we can read the AcquireZprAddress packet back from.
                let (eg_tx, mut eg_rx) = packet_queue::packet_queue::<PACKET_BUFFER_SIZE>(8);
                let mut builder = TestAssemblyBuilder::new();
                builder.mgmt_substrate_egress = Some(MgmtSubstrateEgress::new(eg_tx));

                // Bootstrap key configured, so an SS blob is produced alongside OIDC.
                let mut cfg = <config::Config as std::default::Default>::default();
                let mut keypath = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
                keypath.push("tests");
                keypath.push("data");
                keypath.push("rsa-key.pem");
                cfg.bootstrap = Some(auth::RsaBootstrapAuth::new("test.cn.zpr", &keypath).unwrap());
                builder.config = Some(rcu::RcuBox::new(cfg));

                let asm = Arc::new(create_assembly(builder));

                // Insert an adapter-side peer.
                let entry = asm.peer_table.vacant_entry().unwrap();
                let link_id = entry.key();
                let ps = peer_table::test::create_dummy_peer_state(
                    link_id,
                    LinkType::AdapterToNode,
                    SubstrateAddr::from(([127, 0, 0, 1], 9000)),
                    net_defs::ScopedIpAddr::V4(Ipv4Addr::new(127, 0, 0, 2).into()),
                );
                let link_id = entry.insert(ps).get();

                // Fake agent, bridged the same way start_link registers a real one.
                let seen_nonce = Rc::new(RefCell::new(None));
                let client: cli::auth_agent::Client = capnp_rpc::new_client(FakeAuthAgent {
                    id_token: "FAKE.JWT.TOKEN".to_string(),
                    seen_nonce: seen_nonce.clone(),
                });
                let agent_handle = spawn_auth_agent_bridge(client);

                let idp = auth::OidcIdpInfo {
                    issuer: "https://idp.test".to_string(),
                    client_id: "test-client".to_string(),
                    client_secret: None,
                    scopes: vec!["openid".to_string()],
                    allow_offline_access: false,
                };

                {
                    let peer = asm.peer_table.get(link_id).unwrap();
                    peer.link_state_machine
                        .test_set_state(crate::link_state::LinkState::WaitForInitAuth);
                    peer.link_state_machine.test_set_oidc_idps(vec![idp]);
                    peer.link_state_machine.set_auth_agent(agent_handle);
                }

                // Known 48-byte challenge: nonce || ctime || hmac.
                let payload = auth::ZdpInitAuthenticationPayload {
                    nonce: [5u8; 8],
                    ctime: 777777u64.into(),
                    hmac: [6u8; 32],
                };
                let mut challenge = [0u8; 48];
                challenge[0..8].copy_from_slice(&payload.nonce);
                challenge[8..16].copy_from_slice(&payload.ctime.to_bytes());
                challenge[16..48].copy_from_slice(&payload.hmac);

                asm.process_link_state_event(
                    link_id,
                    crate::link_state::LinkEvent::ReceivedInitAuth((true, Some(payload))),
                )
                .unwrap();

                // Wait for the agent round trip and the acquire to egress.
                let mut pkt = None;
                for _ in 0..200 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    match eg_rx.try_recv(Box::new([0u8; PACKET_BUFFER_SIZE])) {
                        Ok(p) => {
                            pkt = Some(p);
                            break;
                        }
                        Err(_) => continue,
                    }
                }
                let mut pkt = pkt.expect("no packet egressed after agent replied");

                // Parse: base header, mgmt header, acquire header, blob.
                let base = zdp::ZdpBaseHeader::read_from_buf(&mut pkt).unwrap();
                assert_eq!(base.packet_type, zdp::ZdpPacketType::AcquireZprAddress);
                let _mgmt = zdp::ZdpMgmtHeader::read_from_buf(&mut pkt).unwrap();
                let acq = zdp::ZdpAcquireZprAddressHeader::read_from_buf(&mut pkt).unwrap();
                let blob_len = acq.blob_len.get() as usize;
                assert!(blob_len > 0);
                let blob_bytes = pkt.copy_to_bytes(blob_len);
                let blob_str = String::from_utf8(blob_bytes.into()).unwrap();

                let blobs = auth::decode_blobs(&blob_str).unwrap();
                assert_eq!(blobs.len(), 2, "expected SS + OIDC blobs, got {blobs:?}");
                assert!(matches!(blobs[0], AuthBlob::SelfSigned(_)));
                let AuthBlob::Oidc(ref oidc) = blobs[1] else {
                    panic!("expected OIDC blob second, got {:?}", blobs[1]);
                };
                assert_eq!(oidc.id_token, "FAKE.JWT.TOKEN");
                assert_eq!(oidc.issuer, "https://idp.test");

                // The OIDC blob's challenge round-trips against the InitAuth payload.
                let decoded = BASE64_STANDARD.decode(&oidc.challenge).unwrap();
                assert_eq!(decoded, challenge);

                // The agent was called with the nonce derived from that challenge.
                assert_eq!(
                    seen_nonce.borrow().as_deref(),
                    Some(auth::oidc_nonce_for_challenge(&challenge).as_str())
                );
            })
            .await
    }
}
