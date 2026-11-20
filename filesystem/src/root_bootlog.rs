//! Persist boot messages from the first successful writable root mount.

use crate::{FileOps, FsError, FsInstance};
use alloc::{format, sync::Arc};
use core::fmt::Write;
use narf_console::{klog, Writer};
use narf_lib::mutex::Mutex;

const FILE_LIMIT: usize = 4 * 1024 * 1024;
const CHUNK: usize = 32 * 1024;

struct Log {
    file: Arc<dyn FileOps>,
    offset: usize,
    seq: u64,
}

static BOOT_LOG: Mutex<Option<Log>> = Mutex::new(None);

impl Log {
    async fn append(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        let len = bytes.len().min(FILE_LIMIT - self.offset);
        let mut rest = &bytes[..len];
        while !rest.is_empty() {
            let n = self.file.write(self.offset as u64, rest).await?;
            if n == 0 || n > rest.len() {
                return Err(FsError::InvalidData);
            }
            self.offset += n;
            rest = &rest[n..];
        }
        Ok(())
    }

    async fn drain(&mut self) -> Result<(), FsError> {
        // Filesystem I/O may itself generate kernel messages. Drain a finite
        // batch so boot can proceed even on a busy or noisy controller.
        let end = klog::next_seq();
        let before = self.offset;
        while self.seq < end && self.offset < FILE_LIMIT {
            let Some(chunk) = klog::export_since(self.seq, CHUNK, true) else {
                break;
            };
            if chunk.next_seq <= self.seq {
                break;
            }
            if chunk.lost != 0 {
                self.append(format!("[lost {} kernel records]\n", chunk.lost).as_bytes())
                    .await?;
            }
            self.append(&chunk.text).await?;
            self.seq = chunk.next_seq;
        }
        if self.offset != before {
            self.file.fsync(false).await?;
        }
        Ok(())
    }
}

async fn open(fs: &dyn FsInstance) -> Result<Log, FsError> {
    // Walk the mounted instance directly. A symlink, a later mount of /var,
    // or another filesystem cannot redirect writes to a different volume.
    let var = fs.root().lookup_dir_async("var").await?;
    let dir = var.lookup_dir_async("log").await?;
    for number in 1..=9999 {
        let name = format!("narf-boot-{number:04}.log");
        match dir.lookup_async(&name).await {
            Ok(_) => continue,
            Err(FsError::NotFound) => {}
            Err(e) => return Err(e),
        }
        let file = dir.create(&name).await?;
        file.set_perms(0o600).await?;
        let mut log = Log {
            file,
            offset: 0,
            seq: 0,
        };
        log.append(b"NARF writable root mounted\n").await?;
        log.drain().await?;
        // Commit the new name and its contents before running the next
        // initcall, even if no kernel records were available to export.
        dir.syncfs().await?;
        let _ = writeln!(Writer, "  rootlog: saved /var/log/{name}");
        return Ok(log);
    }
    Err(FsError::NoSpace)
}

pub(super) fn start(fs: &dyn FsInstance) {
    let log = match crate::sync_wait::wait_sync(open(fs)) {
        Ok(log) => log,
        Err(e) => {
            let _ = writeln!(Writer, "  rootlog: could not save boot log: {e:?}");
            return;
        }
    };
    *crate::sync_wait::wait_sync(BOOT_LOG.lock()) = Some(log);
    // Any CPU, not the boot CPU's default pin: the log must keep reaching
    // the disk when the boot CPU itself stops scheduling, the failure the
    // stall watchdog's buddy-CPU reports describe. The task touches only the
    // async log lock, the kernel log store and filesystem writes, which user
    // tasks reach from every CPU.
    narf_scheduler::spawn_stackful_with_spec(
        async {
            loop {
                {
                    let mut session = BOOT_LOG.lock().await;
                    if !flush(&mut session).await {
                        return;
                    }
                }
                narf_time::sleep_ms(1000).await;
            }
        },
        narf_scheduler::TaskSpec::kernel_any(),
        narf_scheduler::StackfulOptions::default(),
    );
}

async fn flush(session: &mut Option<Log>) -> bool {
    let Some(log) = session.as_mut() else {
        return false;
    };
    if let Err(e) = log.drain().await {
        let _ = writeln!(Writer, "  rootlog: stopped after disk write error: {e:?}");
    } else if log.offset < FILE_LIMIT {
        return true;
    }
    *session = None;
    false
}

/// Commit boot progress before entering the next initcall or launching PID 1.
/// Boot invokes this outside driver locks. The periodic writer owns any
/// checkpoint already in progress.
pub fn checkpoint() {
    if let Some(mut session) = BOOT_LOG.try_lock() {
        if session.is_some() {
            crate::sync_wait::wait_sync(flush(&mut session));
        }
    }
}
