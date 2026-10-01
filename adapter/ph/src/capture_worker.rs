use crate::logging::targets::CAPTURE;
use crate::pcap_writer::*;
use crate::prelude::*;
use crate::queues::CaptureReceiver;
use std::io;
use tokio::fs::File;
use tokio::sync::Mutex;

pub struct CaptureWorker {
    inner: Mutex<Inner>,
}

struct Inner {
    savefile: Option<PcapWriter<File>>,
}

impl CaptureWorker {
    pub fn new() -> Self {
        Self {
            inner: Inner { savefile: None }.into(),
        }
    }

    /// Unix-only: the sole caller is the admin RPC's `setCaptureFile`
    /// handler, which receives the file's fd over the capnp-ancillary
    /// FD-passing transport (zipline#142); capture is Unsupported
    /// elsewhere (plan D7).
    #[cfg(all(unix, feature = "capnp-ancillary"))]
    pub async fn open_capture_file(&self, file: File) -> Result<(), io::Error> {
        let mut inner = self.inner.lock().await;
        let mut savefile = PcapWriter::open(file, linktype::USER0).await?;
        savefile.flush().await?;
        inner.savefile = Some(savefile);
        Ok(())
    }

    pub async fn flush_capture_file(&self) -> Result<(), io::Error> {
        let savefile = &mut self.inner.lock().await.savefile;
        match savefile.as_mut() {
            Some(savefile) => savefile.flush().await,
            None => Ok(()),
        }
    }

    pub async fn close_capture_file(&self) -> Result<(), io::Error> {
        match self.inner.lock().await.savefile.take() {
            Some(savefile) => {
                savefile.close().await?;
            }
            None => (),
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn query_savefile(&self) -> bool {
        self.inner.lock().await.savefile.is_some()
    }
}

#[derive(Copy, Clone)]
pub struct Config {
    #[allow(dead_code)]
    pub batch_size: usize,
}

/// Drain the capture queue into the open capture file (if any), returning
/// every buffer to the pool once it has been written or discarded.
pub async fn launch(_config: Config, asm: Arc<Assembly>, mut queue: CaptureReceiver) {
    // TODO: batch processing (only take lock once per batch)
    loop {
        let captured = queue.recv().await;
        let mut state = asm.capture_worker.inner.lock().await;

        if let Some(savefile) = state.savefile.as_mut() {
            // Write the packets out.  If the queue is empty, force a flush
            // to make sure these packets get written out in timely fashion.
            // TODO: use poll to determine queue emptiness
            match savefile_write_batch(savefile, &[captured.data()], true).await {
                Ok(()) => (),

                Err(err) => {
                    error!(target: CAPTURE, "Error writing to capture file, ending capture: {}", err);
                    match state.savefile.take().unwrap().close().await {
                        Ok(_file) => (),
                        Err(err) => {
                            error!(target: CAPTURE, "Error closing capture file: {}", err)
                        }
                    }
                }
            }
        }
        drop(state);
        queue.recycle(captured);
    }
}

async fn savefile_write_batch<'a>(
    savefile: &'a mut PcapWriter<File>,
    packets: &[&[u8]],
    force_flush: bool,
) -> io::Result<()> {
    for packet in packets {
        savefile.write_raw(packet).await?;
    }

    // Note, we don't actually care _when_ the flush completes, just that
    // we've kicked it off...  (akin to sync_file_range(SYNC_FILE_RANGE_WRITE))
    // but tokio provides no way to express this without launching a separate task.
    if force_flush {
        savefile.flush().await?;
    }

    Ok(())
}
