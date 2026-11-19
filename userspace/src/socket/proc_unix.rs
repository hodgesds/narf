//! Linux `net/unix/af_unix.c::unix_seq_show`.

use super::{SocketFile, SocketState, UnixAddr};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use narf_filesystem::procfs::ProcFile;
use narf_lib::sync::IrqSafeSpinLock;

static SOCKETS: IrqSafeSpinLock<BTreeMap<u64, Weak<SocketFile>>> =
    IrqSafeSpinLock::new(BTreeMap::new());

pub(super) fn track(socket: &Arc<SocketFile>) {
    SOCKETS
        .lock()
        .insert(socket.inode.ino, Arc::downgrade(socket));
}

pub(super) fn forget(inode: u64) {
    SOCKETS.lock().remove(&inode);
}

pub(super) fn current_net_ns_id() -> u64 {
    task_net_ns_id(crate::handlers::current_task_id())
}

fn task_net_ns_id(_task: u64) -> u64 {
    #[cfg(feature = "container")]
    if let Some(ns) = crate::namespaces::current_net_ns(_task) {
        return ns.id();
    }
    0
}

#[derive(Debug)]
pub(crate) struct UnixSockets;

impl ProcFile for UnixSockets {
    fn net_view(&self, outer_id: Option<u64>) -> Option<Arc<dyn ProcFile>> {
        let task = match outer_id {
            None => crate::handlers::current_task_id(),
            Some(id) => crate::handlers::pid_to_task_raw(id)
                .or_else(|| crate::handlers::linux_tid_to_task_raw(id))?,
        };
        Some(Arc::new(UnixTable {
            namespace: task_net_ns_id(task),
            contents: IrqSafeSpinLock::new(None),
        }))
    }

    fn read(&self) -> Vec<u8> {
        render(current_net_ns_id())
    }
}

#[derive(Debug)]
struct UnixTable {
    namespace: u64,
    contents: IrqSafeSpinLock<Option<Vec<u8>>>,
}

impl ProcFile for UnixTable {
    fn read(&self) -> Vec<u8> {
        render(self.namespace)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, narf_filesystem::FsError> {
        let fresh = if offset == 0 || self.contents.lock().is_none() {
            Some(self.read())
        } else {
            None
        };
        let mut cached = self.contents.lock();
        if let Some(bytes) = fresh {
            *cached = Some(bytes);
        }
        let tail = cached
            .as_deref()
            .unwrap_or_default()
            .get(offset as usize..)
            .unwrap_or_default();
        let len = buf.len().min(tail.len());
        buf[..len].copy_from_slice(&tail[..len]);
        Ok(len)
    }
}

fn render(namespace: u64) -> Vec<u8> {
    let mut out = b"Num       RefCount Protocol Flags    Type St Inode Path\n".to_vec();
    // A last reference can run SocketFile::drop. Release the index lock before
    // upgrading any entry or inspecting socket state.
    let sockets: Vec<_> = SOCKETS.lock().values().cloned().collect();
    for weak in sockets {
        let Some(socket) = weak.upgrade() else {
            continue;
        };
        if socket.net_ns_id() != namespace {
            continue;
        }
        let (flags, state, addr, inode) = {
            let state = socket.state.lock();
            let inode = socket.inode.ino;
            match &*state {
                SocketState::UnixListener { addr, .. } => (0x10000, 1, Some(addr.clone()), inode),
                SocketState::UnixBound { addr } => (0, 1, Some(addr.clone()), inode),
                SocketState::UnixConnected { local_addr, .. } => {
                    if socket.unix_pending_accept.load(Ordering::Acquire) {
                        (0, 2, local_addr.clone(), 0)
                    } else {
                        (0, 3, local_addr.clone(), inode)
                    }
                }
                SocketState::UnixDgram { addr, .. } => {
                    let connected = socket.unix_dgram_established.load(Ordering::Acquire);
                    (0, if connected { 3 } else { 1 }, addr.clone(), inode)
                }
                SocketState::UnixListenerClosed => continue,
                _ => (0, 1, None, inode),
            }
        };
        // Mask the kernel address (%pK); exclude our temporary snapshot reference.
        let refs = Arc::strong_count(&socket) - 1;
        let prefix = alloc::format!(
            "0000000000000000: {refs:08X} 00000000 {flags:08X} {:04X} {state:02X} {inode:5}",
            socket.kind
        );
        out.extend_from_slice(prefix.as_bytes());
        match addr {
            Some(UnixAddr::Path(path)) => {
                out.push(b' ');
                out.extend_from_slice(path.as_bytes());
            }
            Some(UnixAddr::Abstract(bytes)) => {
                out.extend_from_slice(b" @");
                out.extend(bytes.into_iter().map(|b| if b == 0 { b'@' } else { b }));
            }
            _ => {}
        }
        out.push(b'\n');
    }
    out
}
