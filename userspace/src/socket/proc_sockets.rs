//! Live Unix and raw IP sockets for the Linux procfs sequence files.

use super::{SocketFile, SocketState, UnixAddr, AF_INET, AF_INET6, AF_UNIX, SOCK_RAW};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use narf_lib::sync::IrqSafeSpinLock;

static SOCKETS: IrqSafeSpinLock<BTreeMap<(u16, u64), Weak<SocketFile>>> =
    IrqSafeSpinLock::new(BTreeMap::new());

pub(super) fn tracked(domain: u16, kind: u32) -> bool {
    domain == AF_UNIX || (matches!(domain, AF_INET | AF_INET6) && kind == SOCK_RAW)
}

pub(super) fn track(socket: &Arc<SocketFile>) {
    SOCKETS
        .lock()
        .insert((socket.domain, socket.inode.ino), Arc::downgrade(socket));
}

pub(super) fn forget(domain: u16, inode: u64) {
    SOCKETS.lock().remove(&(domain, inode));
}

pub(super) fn current_net_ns_id() -> u64 {
    #[cfg(feature = "container")]
    if let Some(ns) = crate::namespaces::current_net_ns(crate::handlers::current_task_id()) {
        return ns.id();
    }
    0
}

fn sockets_in(domain: u16, namespace: u64) -> impl Iterator<Item = Arc<SocketFile>> {
    // The last reference can run SocketFile::drop. Release the index lock
    // before upgrading weak references, inspecting socket state or dropping them.
    let sockets: Vec<_> = SOCKETS
        .lock()
        .range((domain, 0)..=(domain, u64::MAX))
        .map(|(_, socket)| socket.clone())
        .collect();
    sockets
        .into_iter()
        .filter_map(|socket| socket.upgrade())
        .filter(move |socket| socket.net_ns_id() == namespace)
}

pub fn raw4_snapshot_in(namespace: u64) -> Vec<narf_filesystem::procfs::net::RawSocketSnapshot> {
    sockets_in(AF_INET, namespace)
        .filter_map(|socket| {
            let state = socket.state.lock();
            let SocketState::InetRaw {
                protocol,
                local_addr,
                peer,
                ..
            } = &*state
            else {
                return None;
            };
            Some(narf_filesystem::procfs::net::RawSocketSnapshot {
                local_addr: local_addr.to_be_bytes(),
                protocol: *protocol as u8,
                remote_addr: peer.map_or([0; 4], |(addr, _)| addr.to_be_bytes()),
                state_code: if peer.is_some() { 1 } else { 7 },
                uid: socket.sk_uid,
                inode: socket.inode.ino,
            })
        })
        .collect()
}

pub fn raw6_snapshot_in(namespace: u64) -> Vec<narf_filesystem::procfs::net::Raw6SocketSnapshot> {
    sockets_in(AF_INET6, namespace)
        .filter_map(|socket| {
            let state = socket.state.lock();
            let SocketState::Inet6Raw {
                protocol,
                local_addr,
                peer,
                ..
            } = &*state
            else {
                return None;
            };
            Some(narf_filesystem::procfs::net::Raw6SocketSnapshot {
                local_addr: *local_addr,
                protocol: *protocol as u8,
                remote_addr: peer.map_or([0; 16], |(addr, _)| addr),
                state_code: if peer.is_some() { 1 } else { 7 },
                uid: socket.sk_uid,
                inode: socket.inode.ino,
            })
        })
        .collect()
}

pub(crate) fn render_unix(namespace: u64) -> Vec<u8> {
    let mut out = b"Num       RefCount Protocol Flags    Type St Inode Path\n".to_vec();
    for socket in sockets_in(AF_UNIX, namespace) {
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
