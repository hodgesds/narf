//! Live Unix, loopback TCP and raw IP sockets for Linux procfs sequence files.

use super::{SocketFile, SocketState, UnixAddr, AF_INET, AF_INET6, AF_UNIX, SOCK_RAW, SOCK_STREAM};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use narf_lib::sync::IrqSafeSpinLock;

static SOCKETS: IrqSafeSpinLock<BTreeMap<(u16, u64), Weak<SocketFile>>> =
    IrqSafeSpinLock::new(BTreeMap::new());

pub(super) fn tracked(domain: u16, kind: u32) -> bool {
    domain == AF_UNIX
        || (matches!(domain, AF_INET | AF_INET6) && matches!(kind, SOCK_RAW | SOCK_STREAM))
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

/// TCP endpoints implemented by local rings rather than the network stack.
/// Wired listeners/connections already appear in the stack's snapshot; a
/// bound-only socket has not entered the TCP hash tables and is omitted too.
pub fn tcp4_loopback_snapshot_in(namespace: u64) -> Vec<narf_filesystem::procfs::net::TcbSnapshot> {
    sockets_in(AF_INET, namespace)
        .filter_map(|socket| {
            let state = socket.state.lock();
            let (local_addr, local_port, remote_addr, remote_port, state_code, rx_queue) =
                match &*state {
                    SocketState::InetListener {
                        addr,
                        port,
                        listening: true,
                        listen_id: None,
                        pending,
                        ..
                    } => (*addr, *port, 0, 0, 0x0a, pending.len() as u32),
                    SocketState::InetConnected {
                        local_addr,
                        local_port,
                        peer_addr,
                        peer_port,
                        rx,
                        ..
                    } => (
                        *local_addr,
                        *local_port,
                        *peer_addr,
                        *peer_port,
                        1, // ESTABLISHED, as in the ring path's TCP_INFO.
                        rx.len() as u32,
                    ),
                    _ => return None,
                };
            Some(narf_filesystem::procfs::net::TcbSnapshot {
                local_addr: local_addr.to_be_bytes(),
                local_port,
                remote_addr: remote_addr.to_be_bytes(),
                remote_port,
                state_code,
                // Ring writes are delivered directly to the peer's receive
                // queue: there are no unacknowledged packets or TCP timers.
                tx_queue: 0,
                rx_queue,
                retrnsmt: 0,
                timer_active: 0,
                timer_expires: 0,
                probes_out: 0,
                rto: 0,
                ack_timeout: 0,
                snd_cwnd: 0,
                snd_ssthresh: 0,
                uid: socket.sk_uid,
                timeout: 0,
                inode: socket.inode.ino,
            })
        })
        .collect()
}

/// IPv6 counterpart of [`tcp4_loopback_snapshot_in`].
pub fn tcp6_loopback_snapshot_in(
    namespace: u64,
) -> Vec<narf_filesystem::procfs::net::Tcb6Snapshot> {
    sockets_in(AF_INET6, namespace)
        .filter_map(|socket| {
            let state = socket.state.lock();
            let (local_addr, local_port, remote_addr, remote_port, state_code, rx_queue) =
                match &*state {
                    SocketState::Inet6Listener {
                        addr,
                        port,
                        listening: true,
                        listen_id: None,
                        pending,
                        ..
                    } => (*addr, *port, [0; 16], 0, 0x0a, pending.len() as u32),
                    SocketState::Inet6Connected {
                        local_addr,
                        local_port,
                        peer_addr,
                        peer_port,
                        rx,
                        ..
                    } => (
                        *local_addr,
                        *local_port,
                        *peer_addr,
                        *peer_port,
                        1,
                        rx.len() as u32,
                    ),
                    _ => return None,
                };
            Some(narf_filesystem::procfs::net::Tcb6Snapshot {
                local_addr,
                local_port,
                remote_addr,
                remote_port,
                state_code,
                tx_queue: 0,
                rx_queue,
                retrnsmt: 0,
                uid: socket.sk_uid,
                timeout: 0,
                inode: socket.inode.ino,
            })
        })
        .collect()
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
