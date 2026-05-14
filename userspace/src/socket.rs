//! Socket dispatcher + AF_UNIX SOCK_STREAM backend.
//!
//! Two entry shapes call into this module:
//! - POSIX-shaped syscalls (`sys_socket`/`sys_bind`/...) in
//!   `handlers.rs`, which copy buffers across the syscall ABI.
//! - Ring opcodes from the io-submission ring (`SockRegisterBuf`,
//!   `SockSendZc`) for the zerocopy fast path.
//!
//! Both paths land in `dispatch_op`. The dispatcher routes based
//! on `SocketDomain`; per-family backends own connection state.
//! `SocketFile` implements `narf_filesystem::FileOps` so socket
//! fds live in the same per-task fd table as regular files; the
//! existing `read`/`write`/`close` syscalls work on a socket fd
//! transparently.
//!
//! Stage-1 family: AF_UNIX SOCK_STREAM. A bound listener
//! registers its path in a global `LISTENERS` map; `connect()`
//! finds it, builds two SPSC ring buffers (one per direction),
//! and pushes a fresh accepted endpoint into the listener's
//! pending-accept queue. AF_INET TCP slots into the same shape
//! when the IP stack lands — `dispatch_op` switches on family,
//! everything below shares the SocketFile/FdEntry plumbing.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use narf_filesystem::{FileOps, FsError, FsFuture, Mode, Stat};
use narf_lib::sync::IrqSafeSpinLock;

// ── POSIX-numbered constants ────────────────────────────────────

pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;

pub const SHUT_RD: u32 = 0;
pub const SHUT_WR: u32 = 1;
pub const SHUT_RDWR: u32 = 2;

// ── Address shape ───────────────────────────────────────────────

/// Wire-stable address. POSIX sockaddr_* unions translate to/from
/// this shape libc-side; the kernel only deals with `(family, body)`.
/// Body length is up to 108 bytes (matches Unix sun_path max).
#[derive(Clone, Debug)]
pub struct SockAddr {
    pub family: u16,
    pub body: Vec<u8>,
}

// ── Socket op dispatcher ────────────────────────────────────────

#[derive(Debug)]
pub enum SocketOp<'a> {
    Bind { addr: SockAddr },
    Listen { backlog: u32 },
    Accept,
    Connect { addr: SockAddr },
    Send { buf: &'a [u8], flags: u32, addr: Option<SockAddr> },
    Recv { buf: &'a mut [u8], flags: u32 },
    Shutdown { how: u32 },
}

#[derive(Debug)]
pub enum SocketOpResult {
    Ok(u64),
    Accepted { socket: Arc<SocketFile>, peer: Option<SockAddr> },
    Received { n: usize, peer: Option<SockAddr> },
    Err(SockError),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SockError {
    BadFd,
    InvalidArg,
    NotSupported,
    NotConnected,
    AlreadyConnected,
    WouldBlock,
    AddrInUse,
    AddrNotAvail,
    ConnectionRefused,
    Pipe,
}

impl SockError {
    /// Map onto the libc-style errno value the user sees on -1.
    pub fn errno(self) -> i32 {
        match self {
            Self::BadFd => 9,             // EBADF
            Self::InvalidArg => 22,       // EINVAL
            Self::NotSupported => 95,     // ENOTSUP
            Self::NotConnected => 107,    // ENOTCONN
            Self::AlreadyConnected => 56, // EISCONN
            Self::WouldBlock => 11,       // EAGAIN
            Self::AddrInUse => 98,        // EADDRINUSE
            Self::AddrNotAvail => 99,     // EADDRNOTAVAIL
            Self::ConnectionRefused => 111, // ECONNREFUSED
            Self::Pipe => 32,             // EPIPE
        }
    }
}

// ── SocketFile (FileOps impl, lives in fd table) ────────────────

pub struct SocketFile {
    pub domain: u16,
    pub kind: u32,
    state: IrqSafeSpinLock<SocketState>,
}

enum SocketState {
    /// Freshly-created, no bind/connect yet.
    Fresh,
    /// AF_UNIX bound listener at the named path.
    UnixListener {
        path: String,
        backlog: u32,
        /// Connections that have been initiated by `connect()` but
        /// haven't yet been picked up by `accept()`. The other
        /// half of each pair is given to the connecter.
        pending: VecDeque<Arc<SocketFile>>,
    },
    /// AF_UNIX connected endpoint. Two ring buffers — one for
    /// each direction — shared between this end and the peer.
    UnixConnected {
        /// Bytes the local end SENDS (peer reads).
        tx: Arc<RingBuf>,
        /// Bytes the local end RECEIVES (peer writes).
        rx: Arc<RingBuf>,
    },
    /// AF_INET SOCK_STREAM bound listener at (addr, port). Stage-1
    /// loopback only — connect to 127.0.0.1 finds the listener
    /// in the INET_LISTENERS map; non-loopback addresses fail
    /// with ConnectionRefused until the NIC TX path lands.
    InetListener {
        addr: u32,
        port: u16,
        backlog: u32,
        pending: VecDeque<Arc<SocketFile>>,
    },
    /// AF_INET connected endpoint — same ring shape as UnixConnected.
    InetConnected {
        tx: Arc<RingBuf>,
        rx: Arc<RingBuf>,
        peer_addr: u32,
        peer_port: u16,
    },
    /// AF_INET SOCK_STREAM connection routed through the
    /// kernel-side TCP-over-NIC stack. `tcb_id` indexes
    /// `narf_net::tcp_stack::TCB_TABLE`. send/recv forward to the
    /// stack's helpers.
    InetWired {
        tcb_id: u32,
        peer_addr: u32,
        peer_port: u16,
    },
    /// AF_INET SOCK_DGRAM endpoint. UDP is connectionless: a single
    /// per-socket inbox holds (peer_addr, peer_port, payload)
    /// records pushed by other UDP sockets that sendto'd here.
    InetDgram {
        local_addr: u32,
        local_port: u16,
        inbox: VecDeque<DgramPacket>,
        /// Optional connect()'d peer — when set, send() goes there
        /// without an explicit destination addr.
        peer: Option<(u32, u16)>,
    },
    /// AF_UNIX SOCK_DGRAM endpoint. Same shape as InetDgram but
    /// keyed by path string.
    UnixDgram {
        path: Option<String>,
        inbox: VecDeque<DgramPacket>,
        peer: Option<String>,
    },
    /// AF_INET6 SOCK_STREAM — same ring shape as InetConnected,
    /// addressed by 16-byte IPv6 addr instead of u32 IPv4.
    Inet6Listener {
        addr: [u8; 16],
        port: u16,
        backlog: u32,
        pending: VecDeque<Arc<SocketFile>>,
    },
    Inet6Connected {
        tx: Arc<RingBuf>,
        rx: Arc<RingBuf>,
        peer_addr: [u8; 16],
        peer_port: u16,
    },
}

/// One enqueued UDP-style datagram. Owns the payload bytes (UDP
/// has no concept of partial reads — each recv yields one whole
/// packet, padded or truncated to the user buffer size).
#[derive(Debug)]
pub struct DgramPacket {
    pub peer_unix: Option<String>,
    pub peer_addr: u32,
    pub peer_port: u16,
    pub payload: Vec<u8>,
}

impl SocketFile {
    pub fn new(domain: u16, kind: u32) -> Arc<Self> {
        Arc::new(Self {
            domain,
            kind,
            state: IrqSafeSpinLock::new(SocketState::Fresh),
        })
    }

    /// Tear down listener / dgram-bound registry entries owned by
    /// this socket. Called from sys_close so the path / port is
    /// reusable on the next bind. Idempotent — Fresh / Connected
    /// sockets are no-ops.
    pub fn unregister(&self) {
        enum Reg {
            Unix(String),
            Inet(u32, u16),
            Inet6([u8; 16], u16),
            UnixDgram(String),
            InetDgram(u32, u16),
            Tcb(u32),
            None,
        }
        let reg = {
            let state = self.state.lock();
            match &*state {
                SocketState::UnixListener { path, .. } => Reg::Unix(path.clone()),
                SocketState::InetListener { addr, port, .. } => Reg::Inet(*addr, *port),
                SocketState::Inet6Listener { addr, port, .. } => Reg::Inet6(*addr, *port),
                SocketState::UnixDgram { path: Some(p), .. } => Reg::UnixDgram(p.clone()),
                SocketState::InetDgram { local_addr, local_port, .. } => {
                    Reg::InetDgram(*local_addr, *local_port)
                }
                SocketState::InetWired { tcb_id, .. } => Reg::Tcb(*tcb_id),
                _ => Reg::None,
            }
        };
        match reg {
            Reg::Unix(p) => {
                if let Some(map) = LISTENERS.lock().as_mut() { map.remove(&p); }
            }
            Reg::Inet(a, p) => {
                if let Some(map) = INET_LISTENERS.lock().as_mut() { map.remove(&(a, p)); }
            }
            Reg::Inet6(a, p) => {
                if let Some(map) = INET6_LISTENERS.lock().as_mut() { map.remove(&(a, p)); }
            }
            Reg::UnixDgram(p) => {
                if let Some(map) = UNIX_DGRAM_BOUND.lock().as_mut() { map.remove(&p); }
            }
            Reg::InetDgram(a, p) => {
                if let Some(map) = INET_DGRAM_BOUND.lock().as_mut() { map.remove(&(a, p)); }
            }
            Reg::Tcb(id) => {
                let _ = narf_net::tcp_stack::close(id);
            }
            Reg::None => {}
        }
    }
}

impl core::fmt::Debug for SocketFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SocketFile")
            .field("domain", &self.domain)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl FileOps for SocketFile {
    fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // POSIX `read` on a socket == `recv` with flags=0.
            let r = self.do_recv(buf, 0);
            match r {
                Ok((n, _)) => Ok(n),
                Err(SockError::WouldBlock) => Ok(0),
                Err(_) => Err(FsError::Unsupported),
            }
        })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            // POSIX `write` on a socket == `send` with flags=0.
            let r = self.do_send(buf, 0, None);
            match r {
                Ok(n) => Ok(n),
                Err(_) => Err(FsError::Unsupported),
            }
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: narf_filesystem::FileType::Special,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    fn poll_readiness(&self) -> u32 {
        let state = self.state.lock();
        match &*state {
            SocketState::Fresh => 0,
            SocketState::UnixListener { pending, .. }
            | SocketState::InetListener { pending, .. }
            | SocketState::Inet6Listener { pending, .. } => {
                if pending.is_empty() {
                    0
                } else {
                    narf_filesystem::POLL_IN
                }
            }
            SocketState::UnixConnected { rx, tx }
            | SocketState::InetConnected { rx, tx, .. }
            | SocketState::Inet6Connected { rx, tx, .. } => {
                let mut bits = 0;
                if rx.has_data() {
                    bits |= narf_filesystem::POLL_IN;
                }
                if tx.has_space() {
                    bits |= narf_filesystem::POLL_OUT;
                }
                if rx.is_closed() {
                    bits |= narf_filesystem::POLL_HUP;
                }
                bits
            }
            SocketState::InetDgram { inbox, .. }
            | SocketState::UnixDgram { inbox, .. } => {
                let mut bits = narf_filesystem::POLL_OUT; // always sendable
                if !inbox.is_empty() {
                    bits |= narf_filesystem::POLL_IN;
                }
                bits
            }
            SocketState::InetWired { .. } => {
                // Always-writable; readability is tracked
                // implicitly inside the TCP stack — Stage-1 just
                // reports POLL_OUT. POLL_IN gating lands once the
                // stack exposes a per-TCB readability accessor.
                narf_filesystem::POLL_OUT
            }
        }
    }
}

impl SocketFile {
    /// Per-op dispatcher. The SocketOp enum carries the operation
    /// shape; the per-family branch executes it. POSIX syscall
    /// shims and ring opcodes both call this.
    pub fn dispatch_op(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match (self.domain, self.kind) {
            (AF_UNIX, SOCK_STREAM) => self.dispatch_unix_stream(op),
            (AF_INET, SOCK_STREAM) => self.dispatch_inet_stream(op),
            (AF_INET, SOCK_DGRAM) => self.dispatch_inet_dgram(op),
            (AF_UNIX, SOCK_DGRAM) => self.dispatch_unix_dgram(op),
            (AF_INET6, SOCK_STREAM) => self.dispatch_inet6_stream(op),
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    fn dispatch_unix_stream(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => {
                if addr.family != AF_UNIX {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let path = match core::str::from_utf8(&addr.body) {
                    Ok(s) => alloc::string::String::from(s.trim_end_matches('\0')),
                    Err(_) => return SocketOpResult::Err(SockError::InvalidArg),
                };
                if path.is_empty() {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let mut state = self.state.lock();
                match &*state {
                    SocketState::Fresh => {
                        let mut listeners = LISTENERS.lock();
                        let map = listeners.get_or_insert_with(BTreeMap::new);
                        if map.contains_key(&path) {
                            return SocketOpResult::Err(SockError::AddrInUse);
                        }
                        // We can't put the listener in the map yet
                        // (we only have &Arc here) — record the
                        // path in our state, and have Listen() do
                        // the actual map insert. POSIX bind+listen
                        // are always called in sequence on stream
                        // sockets so this is fine.
                        *state = SocketState::UnixListener {
                            path,
                            backlog: 0,
                            pending: VecDeque::new(),
                        };
                        SocketOpResult::Ok(0)
                    }
                    _ => SocketOpResult::Err(SockError::InvalidArg),
                }
            }
            SocketOp::Listen { backlog } => {
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::UnixListener { path, backlog: b, .. } => {
                        *b = backlog;
                        let path = path.clone();
                        drop(state);
                        let mut listeners = LISTENERS.lock();
                        let map = listeners.get_or_insert_with(BTreeMap::new);
                        map.insert(path, self.clone());
                        SocketOpResult::Ok(0)
                    }
                    _ => SocketOpResult::Err(SockError::InvalidArg),
                }
            }
            SocketOp::Accept => {
                // Pop from the pending queue. Caller (sys_accept)
                // wraps this in a yield-loop until something arrives.
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::UnixListener { pending, .. } => {
                        if let Some(s) = pending.pop_front() {
                            SocketOpResult::Accepted { socket: s, peer: None }
                        } else {
                            SocketOpResult::Err(SockError::WouldBlock)
                        }
                    }
                    _ => SocketOpResult::Err(SockError::InvalidArg),
                }
            }
            SocketOp::Connect { addr } => {
                if addr.family != AF_UNIX {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let path = match core::str::from_utf8(&addr.body) {
                    Ok(s) => alloc::string::String::from(s.trim_end_matches('\0')),
                    Err(_) => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let listener = {
                    let listeners = LISTENERS.lock();
                    listeners
                        .as_ref()
                        .and_then(|m| m.get(&path).cloned())
                };
                let listener = match listener {
                    Some(l) => l,
                    None => return SocketOpResult::Err(SockError::ConnectionRefused),
                };
                // Mint two ring buffers; one direction each.
                let a_to_b = Arc::new(RingBuf::new());
                let b_to_a = Arc::new(RingBuf::new());
                // Give the new accepted endpoint to the listener's
                // pending queue; configure our local state with
                // the matching pair.
                let server_end = SocketFile::new(AF_UNIX, SOCK_STREAM);
                {
                    let mut srv_state = server_end.state.lock();
                    *srv_state = SocketState::UnixConnected {
                        tx: b_to_a.clone(),
                        rx: a_to_b.clone(),
                    };
                }
                {
                    let mut lst = listener.state.lock();
                    if let SocketState::UnixListener { pending, .. } = &mut *lst {
                        pending.push_back(server_end);
                    } else {
                        return SocketOpResult::Err(SockError::ConnectionRefused);
                    }
                }
                // Configure our (client) end.
                let mut state = self.state.lock();
                match &*state {
                    SocketState::Fresh => {
                        *state = SocketState::UnixConnected {
                            tx: a_to_b,
                            rx: b_to_a,
                        };
                        SocketOpResult::Ok(0)
                    }
                    _ => SocketOpResult::Err(SockError::AlreadyConnected),
                }
            }
            SocketOp::Send { buf, flags, addr: _ } => {
                match self.do_send(buf, flags, None) {
                    Ok(n) => SocketOpResult::Ok(n as u64),
                    Err(e) => SocketOpResult::Err(e),
                }
            }
            SocketOp::Recv { buf, flags } => {
                match self.do_recv(buf, flags) {
                    Ok((n, peer)) => SocketOpResult::Received { n, peer },
                    Err(e) => SocketOpResult::Err(e),
                }
            }
            SocketOp::Shutdown { how } => {
                let state = self.state.lock();
                match &*state {
                    SocketState::UnixConnected { tx, rx } => {
                        if how == SHUT_WR || how == SHUT_RDWR {
                            tx.close();
                        }
                        if how == SHUT_RD || how == SHUT_RDWR {
                            rx.close();
                        }
                        SocketOpResult::Ok(0)
                    }
                    _ => SocketOpResult::Err(SockError::NotConnected),
                }
            }
        }
    }

    /// AF_INET SOCK_STREAM dispatcher. Loopback only — connect to
    /// 127.0.0.1 finds the listener in INET_LISTENERS and pairs
    /// up two ring buffers. Non-loopback addresses fail with
    /// ConnectionRefused; that path lights up when the NIC TX
    /// path + TCP state machine land.
    fn dispatch_inet_stream(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => {
                if addr.family != AF_INET || addr.body.len() < 6 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                // sockaddr_in body: port (u16 BE) + ip (u32 BE).
                let port = u16::from_be_bytes([addr.body[0], addr.body[1]]);
                let ip = u32::from_be_bytes([
                    addr.body[2],
                    addr.body[3],
                    addr.body[4],
                    addr.body[5],
                ]);
                let mut state = self.state.lock();
                match &*state {
                    SocketState::Fresh => {
                        let key = (ip, port);
                        let mut listeners = INET_LISTENERS.lock();
                        let map = listeners.get_or_insert_with(BTreeMap::new);
                        if map.contains_key(&key) {
                            return SocketOpResult::Err(SockError::AddrInUse);
                        }
                        *state = SocketState::InetListener {
                            addr: ip,
                            port,
                            backlog: 0,
                            pending: VecDeque::new(),
                        };
                        SocketOpResult::Ok(0)
                    }
                    _ => SocketOpResult::Err(SockError::InvalidArg),
                }
            }
            SocketOp::Listen { backlog } => {
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::InetListener { addr, port, backlog: b, .. } => {
                        *b = backlog;
                        let key = (*addr, *port);
                        drop(state);
                        let mut listeners = INET_LISTENERS.lock();
                        let map = listeners.get_or_insert_with(BTreeMap::new);
                        map.insert(key, self.clone());
                        SocketOpResult::Ok(0)
                    }
                    _ => SocketOpResult::Err(SockError::InvalidArg),
                }
            }
            SocketOp::Accept => {
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::InetListener { pending, .. } => {
                        if let Some(s) = pending.pop_front() {
                            SocketOpResult::Accepted { socket: s, peer: None }
                        } else {
                            SocketOpResult::Err(SockError::WouldBlock)
                        }
                    }
                    _ => SocketOpResult::Err(SockError::InvalidArg),
                }
            }
            SocketOp::Connect { addr } => {
                if addr.family != AF_INET || addr.body.len() < 6 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let port = u16::from_be_bytes([addr.body[0], addr.body[1]]);
                let ip = u32::from_be_bytes([
                    addr.body[2],
                    addr.body[3],
                    addr.body[4],
                    addr.body[5],
                ]);
                // Look up the listener. Loopback (127.x.x.x) and
                // 0.0.0.0 (INADDR_ANY) listeners both match.
                let listener = {
                    let listeners = INET_LISTENERS.lock();
                    let m = listeners.as_ref();
                    m.and_then(|m| {
                        m.get(&(ip, port))
                            .or_else(|| m.get(&(0, port)))
                            .cloned()
                    })
                };
                let listener = match listener {
                    Some(l) => l,
                    None => {
                        // No in-process listener — try the kernel
                        // TCP-over-NIC path. Loopback addresses
                        // (127.x.x.x) skip this and return ECONNREFUSED.
                        let is_loopback = (ip >> 24) == 127;
                        if !is_loopback {
                            let ip_bytes = ip.to_be_bytes();
                            match narf_net::tcp_stack::connect(ip_bytes, port) {
                                Ok(tcb_id) => {
                                    let mut state = self.state.lock();
                                    if matches!(&*state, SocketState::Fresh) {
                                        *state = SocketState::InetWired {
                                            tcb_id,
                                            peer_addr: ip,
                                            peer_port: port,
                                        };
                                        return SocketOpResult::Ok(0);
                                    }
                                    return SocketOpResult::Err(SockError::AlreadyConnected);
                                }
                                Err(_) => {
                                    return SocketOpResult::Err(SockError::ConnectionRefused);
                                }
                            }
                        }
                        return SocketOpResult::Err(SockError::ConnectionRefused);
                    }
                };
                let a_to_b = Arc::new(RingBuf::new());
                let b_to_a = Arc::new(RingBuf::new());
                let server_end = SocketFile::new(AF_INET, SOCK_STREAM);
                {
                    let mut srv_state = server_end.state.lock();
                    *srv_state = SocketState::InetConnected {
                        tx: b_to_a.clone(),
                        rx: a_to_b.clone(),
                        peer_addr: ip,
                        peer_port: port,
                    };
                }
                {
                    let mut lst = listener.state.lock();
                    if let SocketState::InetListener { pending, .. } = &mut *lst {
                        pending.push_back(server_end);
                    } else {
                        return SocketOpResult::Err(SockError::ConnectionRefused);
                    }
                }
                let mut state = self.state.lock();
                match &*state {
                    SocketState::Fresh => {
                        *state = SocketState::InetConnected {
                            tx: a_to_b,
                            rx: b_to_a,
                            peer_addr: ip,
                            peer_port: port,
                        };
                        SocketOpResult::Ok(0)
                    }
                    _ => SocketOpResult::Err(SockError::AlreadyConnected),
                }
            }
            SocketOp::Send { buf, flags, addr: _ } => {
                match self.do_send(buf, flags, None) {
                    Ok(n) => SocketOpResult::Ok(n as u64),
                    Err(e) => SocketOpResult::Err(e),
                }
            }
            SocketOp::Recv { buf, flags } => {
                match self.do_recv(buf, flags) {
                    Ok((n, peer)) => SocketOpResult::Received { n, peer },
                    Err(e) => SocketOpResult::Err(e),
                }
            }
            SocketOp::Shutdown { how } => {
                let state = self.state.lock();
                match &*state {
                    SocketState::InetConnected { tx, rx, .. } => {
                        if how == SHUT_WR || how == SHUT_RDWR { tx.close(); }
                        if how == SHUT_RD || how == SHUT_RDWR { rx.close(); }
                        SocketOpResult::Ok(0)
                    }
                    _ => SocketOpResult::Err(SockError::NotConnected),
                }
            }
        }
    }

    /// AF_INET SOCK_DGRAM (UDP). Connectionless: bind sets the
    /// local addr/port + registers in INET_DGRAM_BOUND;
    /// sendto/send pushes a DgramPacket into the destination's
    /// inbox; recvfrom/recv pops from our own inbox.
    fn dispatch_inet_dgram(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => {
                if addr.family != AF_INET || addr.body.len() < 6 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let port = u16::from_be_bytes([addr.body[0], addr.body[1]]);
                let ip = u32::from_be_bytes([
                    addr.body[2], addr.body[3], addr.body[4], addr.body[5],
                ]);
                let mut state = self.state.lock();
                match &*state {
                    SocketState::Fresh => {
                        let mut bound = INET_DGRAM_BOUND.lock();
                        let map = bound.get_or_insert_with(BTreeMap::new);
                        if map.contains_key(&(ip, port)) {
                            return SocketOpResult::Err(SockError::AddrInUse);
                        }
                        *state = SocketState::InetDgram {
                            local_addr: ip,
                            local_port: port,
                            inbox: VecDeque::new(),
                            peer: None,
                        };
                        map.insert((ip, port), self.clone());
                        SocketOpResult::Ok(0)
                    }
                    _ => SocketOpResult::Err(SockError::InvalidArg),
                }
            }
            SocketOp::Connect { addr } => {
                if addr.family != AF_INET || addr.body.len() < 6 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let port = u16::from_be_bytes([addr.body[0], addr.body[1]]);
                let ip = u32::from_be_bytes([
                    addr.body[2], addr.body[3], addr.body[4], addr.body[5],
                ]);
                let mut state = self.state.lock();
                // If unbound, auto-bind to (0, ephemeral). For
                // simplicity we use port 0 (kernel-pick is a TODO).
                if matches!(&*state, SocketState::Fresh) {
                    *state = SocketState::InetDgram {
                        local_addr: 0,
                        local_port: 0,
                        inbox: VecDeque::new(),
                        peer: Some((ip, port)),
                    };
                    return SocketOpResult::Ok(0);
                }
                if let SocketState::InetDgram { peer, .. } = &mut *state {
                    *peer = Some((ip, port));
                    SocketOpResult::Ok(0)
                } else {
                    SocketOpResult::Err(SockError::InvalidArg)
                }
            }
            SocketOp::Send { buf, flags: _, addr } => {
                let state = self.state.lock();
                let (local_addr, local_port, dest) = match &*state {
                    SocketState::InetDgram { local_addr, local_port, peer, .. } => {
                        let dest = if let Some(a) = addr {
                            if a.body.len() < 6 {
                                return SocketOpResult::Err(SockError::InvalidArg);
                            }
                            let p = u16::from_be_bytes([a.body[0], a.body[1]]);
                            let i = u32::from_be_bytes([
                                a.body[2], a.body[3], a.body[4], a.body[5],
                            ]);
                            (i, p)
                        } else if let Some(d) = peer {
                            *d
                        } else {
                            return SocketOpResult::Err(SockError::InvalidArg);
                        };
                        (*local_addr, *local_port, dest)
                    }
                    _ => return SocketOpResult::Err(SockError::NotConnected),
                };
                drop(state);
                // Find the destination socket. Loopback + INADDR_ANY both match.
                let dest_sock = {
                    let bound = INET_DGRAM_BOUND.lock();
                    bound.as_ref().and_then(|m| {
                        m.get(&dest)
                            .or_else(|| m.get(&(0, dest.1)))
                            .cloned()
                    })
                };
                let dest_sock = match dest_sock {
                    Some(s) => s,
                    None => {
                        // No listener. UDP convention: silently
                        // drop (POSIX permits this — no error).
                        return SocketOpResult::Ok(buf.len() as u64);
                    }
                };
                let pkt = DgramPacket {
                    peer_unix: None,
                    peer_addr: local_addr,
                    peer_port: local_port,
                    payload: buf.to_vec(),
                };
                let mut ds = dest_sock.state.lock();
                if let SocketState::InetDgram { inbox, .. } = &mut *ds {
                    inbox.push_back(pkt);
                    SocketOpResult::Ok(buf.len() as u64)
                } else {
                    SocketOpResult::Ok(buf.len() as u64) // dropped
                }
            }
            SocketOp::Recv { buf, flags: _ } => {
                let mut state = self.state.lock();
                if let SocketState::InetDgram { inbox, .. } = &mut *state {
                    if let Some(pkt) = inbox.pop_front() {
                        let n = core::cmp::min(buf.len(), pkt.payload.len());
                        buf[..n].copy_from_slice(&pkt.payload[..n]);
                        let mut peer_body = alloc::vec::Vec::with_capacity(6);
                        peer_body.extend_from_slice(&pkt.peer_port.to_be_bytes());
                        peer_body.extend_from_slice(&pkt.peer_addr.to_be_bytes());
                        return SocketOpResult::Received {
                            n,
                            peer: Some(SockAddr {
                                family: AF_INET,
                                body: peer_body,
                            }),
                        };
                    }
                    return SocketOpResult::Err(SockError::WouldBlock);
                }
                SocketOpResult::Err(SockError::NotConnected)
            }
            SocketOp::Listen { .. } | SocketOp::Accept => {
                SocketOpResult::Err(SockError::NotSupported)
            }
            SocketOp::Shutdown { .. } => SocketOpResult::Ok(0),
        }
    }

    /// AF_UNIX SOCK_DGRAM. Same shape as InetDgram but path-keyed.
    fn dispatch_unix_dgram(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => {
                if addr.family != AF_UNIX {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let path = match core::str::from_utf8(&addr.body) {
                    Ok(s) => alloc::string::String::from(s.trim_end_matches('\0')),
                    Err(_) => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let mut state = self.state.lock();
                if matches!(&*state, SocketState::Fresh) {
                    let mut bound = UNIX_DGRAM_BOUND.lock();
                    let map = bound.get_or_insert_with(BTreeMap::new);
                    if map.contains_key(&path) {
                        return SocketOpResult::Err(SockError::AddrInUse);
                    }
                    *state = SocketState::UnixDgram {
                        path: Some(path.clone()),
                        inbox: VecDeque::new(),
                        peer: None,
                    };
                    map.insert(path, self.clone());
                    return SocketOpResult::Ok(0);
                }
                SocketOpResult::Err(SockError::InvalidArg)
            }
            SocketOp::Connect { addr } => {
                if addr.family != AF_UNIX {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let path = match core::str::from_utf8(&addr.body) {
                    Ok(s) => alloc::string::String::from(s.trim_end_matches('\0')),
                    Err(_) => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let mut state = self.state.lock();
                if matches!(&*state, SocketState::Fresh) {
                    *state = SocketState::UnixDgram {
                        path: None,
                        inbox: VecDeque::new(),
                        peer: Some(path),
                    };
                    return SocketOpResult::Ok(0);
                }
                if let SocketState::UnixDgram { peer, .. } = &mut *state {
                    *peer = Some(path);
                    SocketOpResult::Ok(0)
                } else {
                    SocketOpResult::Err(SockError::InvalidArg)
                }
            }
            SocketOp::Send { buf, flags: _, addr } => {
                let state = self.state.lock();
                let (local_path, dest_path) = match &*state {
                    SocketState::UnixDgram { path, peer, .. } => {
                        let dest = if let Some(a) = addr {
                            match core::str::from_utf8(&a.body) {
                                Ok(s) => alloc::string::String::from(s.trim_end_matches('\0')),
                                Err(_) => return SocketOpResult::Err(SockError::InvalidArg),
                            }
                        } else if let Some(p) = peer {
                            p.clone()
                        } else {
                            return SocketOpResult::Err(SockError::InvalidArg);
                        };
                        (path.clone(), dest)
                    }
                    _ => return SocketOpResult::Err(SockError::NotConnected),
                };
                drop(state);
                let dest_sock = {
                    let bound = UNIX_DGRAM_BOUND.lock();
                    bound.as_ref().and_then(|m| m.get(&dest_path).cloned())
                };
                let dest_sock = match dest_sock {
                    Some(s) => s,
                    None => return SocketOpResult::Ok(buf.len() as u64),
                };
                let pkt = DgramPacket {
                    peer_unix: local_path,
                    peer_addr: 0,
                    peer_port: 0,
                    payload: buf.to_vec(),
                };
                let mut ds = dest_sock.state.lock();
                if let SocketState::UnixDgram { inbox, .. } = &mut *ds {
                    inbox.push_back(pkt);
                }
                SocketOpResult::Ok(buf.len() as u64)
            }
            SocketOp::Recv { buf, flags: _ } => {
                let mut state = self.state.lock();
                if let SocketState::UnixDgram { inbox, .. } = &mut *state {
                    if let Some(pkt) = inbox.pop_front() {
                        let n = core::cmp::min(buf.len(), pkt.payload.len());
                        buf[..n].copy_from_slice(&pkt.payload[..n]);
                        let body = pkt.peer_unix.unwrap_or_default().into_bytes();
                        return SocketOpResult::Received {
                            n,
                            peer: Some(SockAddr { family: AF_UNIX, body }),
                        };
                    }
                    return SocketOpResult::Err(SockError::WouldBlock);
                }
                SocketOpResult::Err(SockError::NotConnected)
            }
            SocketOp::Listen { .. } | SocketOp::Accept => {
                SocketOpResult::Err(SockError::NotSupported)
            }
            SocketOp::Shutdown { .. } => SocketOpResult::Ok(0),
        }
    }

    /// AF_INET6 SOCK_STREAM. Same shape as AF_INET, addressed by
    /// 16-byte IPv6 instead of 4-byte IPv4.
    fn dispatch_inet6_stream(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => {
                if addr.family != AF_INET6 || addr.body.len() < 18 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                // sockaddr_in6: port (u16 BE) + flowinfo (u32) + addr ([u8; 16])
                let port = u16::from_be_bytes([addr.body[0], addr.body[1]]);
                let mut ip = [0u8; 16];
                // flowinfo = body[2..6]; addr = body[6..22]
                let off = if addr.body.len() >= 22 { 6 } else { 2 };
                let span = core::cmp::min(16, addr.body.len() - off);
                ip[..span].copy_from_slice(&addr.body[off..off + span]);
                let mut state = self.state.lock();
                if matches!(&*state, SocketState::Fresh) {
                    let mut listeners = INET6_LISTENERS.lock();
                    let map = listeners.get_or_insert_with(BTreeMap::new);
                    if map.contains_key(&(ip, port)) {
                        return SocketOpResult::Err(SockError::AddrInUse);
                    }
                    *state = SocketState::Inet6Listener {
                        addr: ip,
                        port,
                        backlog: 0,
                        pending: VecDeque::new(),
                    };
                    return SocketOpResult::Ok(0);
                }
                SocketOpResult::Err(SockError::InvalidArg)
            }
            SocketOp::Listen { backlog } => {
                let mut state = self.state.lock();
                if let SocketState::Inet6Listener { addr, port, backlog: b, .. } = &mut *state {
                    *b = backlog;
                    let key = (*addr, *port);
                    drop(state);
                    let mut listeners = INET6_LISTENERS.lock();
                    let map = listeners.get_or_insert_with(BTreeMap::new);
                    map.insert(key, self.clone());
                    SocketOpResult::Ok(0)
                } else {
                    SocketOpResult::Err(SockError::InvalidArg)
                }
            }
            SocketOp::Accept => {
                let mut state = self.state.lock();
                if let SocketState::Inet6Listener { pending, .. } = &mut *state {
                    if let Some(s) = pending.pop_front() {
                        SocketOpResult::Accepted { socket: s, peer: None }
                    } else {
                        SocketOpResult::Err(SockError::WouldBlock)
                    }
                } else {
                    SocketOpResult::Err(SockError::InvalidArg)
                }
            }
            SocketOp::Connect { addr } => {
                if addr.family != AF_INET6 || addr.body.len() < 18 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let port = u16::from_be_bytes([addr.body[0], addr.body[1]]);
                let mut ip = [0u8; 16];
                let off = if addr.body.len() >= 22 { 6 } else { 2 };
                let span = core::cmp::min(16, addr.body.len() - off);
                ip[..span].copy_from_slice(&addr.body[off..off + span]);
                let listener = {
                    let listeners = INET6_LISTENERS.lock();
                    let m = listeners.as_ref();
                    let unspecified = [0u8; 16];
                    m.and_then(|m| {
                        m.get(&(ip, port))
                            .or_else(|| m.get(&(unspecified, port)))
                            .cloned()
                    })
                };
                let listener = match listener {
                    Some(l) => l,
                    None => return SocketOpResult::Err(SockError::ConnectionRefused),
                };
                let a_to_b = Arc::new(RingBuf::new());
                let b_to_a = Arc::new(RingBuf::new());
                let server_end = SocketFile::new(AF_INET6, SOCK_STREAM);
                {
                    let mut srv_state = server_end.state.lock();
                    *srv_state = SocketState::Inet6Connected {
                        tx: b_to_a.clone(),
                        rx: a_to_b.clone(),
                        peer_addr: ip,
                        peer_port: port,
                    };
                }
                {
                    let mut lst = listener.state.lock();
                    if let SocketState::Inet6Listener { pending, .. } = &mut *lst {
                        pending.push_back(server_end);
                    } else {
                        return SocketOpResult::Err(SockError::ConnectionRefused);
                    }
                }
                let mut state = self.state.lock();
                if matches!(&*state, SocketState::Fresh) {
                    *state = SocketState::Inet6Connected {
                        tx: a_to_b,
                        rx: b_to_a,
                        peer_addr: ip,
                        peer_port: port,
                    };
                    SocketOpResult::Ok(0)
                } else {
                    SocketOpResult::Err(SockError::AlreadyConnected)
                }
            }
            SocketOp::Send { buf, flags, addr: _ } => {
                match self.do_send(buf, flags, None) {
                    Ok(n) => SocketOpResult::Ok(n as u64),
                    Err(e) => SocketOpResult::Err(e),
                }
            }
            SocketOp::Recv { buf, flags } => {
                match self.do_recv(buf, flags) {
                    Ok((n, peer)) => SocketOpResult::Received { n, peer },
                    Err(e) => SocketOpResult::Err(e),
                }
            }
            SocketOp::Shutdown { how } => {
                let state = self.state.lock();
                if let SocketState::Inet6Connected { tx, rx, .. } = &*state {
                    if how == SHUT_WR || how == SHUT_RDWR { tx.close(); }
                    if how == SHUT_RD || how == SHUT_RDWR { rx.close(); }
                    SocketOpResult::Ok(0)
                } else {
                    SocketOpResult::Err(SockError::NotConnected)
                }
            }
        }
    }

    fn do_send(
        &self,
        buf: &[u8],
        _flags: u32,
        _addr: Option<SockAddr>,
    ) -> Result<usize, SockError> {
        let state = self.state.lock();
        // InetWired sockets route through the kernel TCP-over-NIC stack.
        if let SocketState::InetWired { tcb_id, .. } = &*state {
            let id = *tcb_id;
            drop(state);
            return narf_net::tcp_stack::send(id, buf).map_err(|_| SockError::Pipe);
        }
        let tx = match &*state {
            SocketState::UnixConnected { tx, .. }
            | SocketState::InetConnected { tx, .. }
            | SocketState::Inet6Connected { tx, .. } => tx,
            _ => return Err(SockError::NotConnected),
        };
        if tx.is_closed() {
            return Err(SockError::Pipe);
        }
        let n = tx.write(buf);
        if n == 0 && !buf.is_empty() {
            Err(SockError::WouldBlock)
        } else {
            Ok(n)
        }
    }

    fn do_recv(
        &self,
        buf: &mut [u8],
        _flags: u32,
    ) -> Result<(usize, Option<SockAddr>), SockError> {
        let state = self.state.lock();
        if let SocketState::InetWired { tcb_id, .. } = &*state {
            let id = *tcb_id;
            drop(state);
            let n = narf_net::tcp_stack::recv(id, buf).map_err(|_| SockError::NotConnected)?;
            if n == 0 && !buf.is_empty() {
                return Err(SockError::WouldBlock);
            }
            return Ok((n, None));
        }
        let rx = match &*state {
            SocketState::UnixConnected { rx, .. }
            | SocketState::InetConnected { rx, .. }
            | SocketState::Inet6Connected { rx, .. } => rx,
            _ => return Err(SockError::NotConnected),
        };
        let n = rx.read(buf);
        if n == 0 && !buf.is_empty() && !rx.is_closed() {
            Err(SockError::WouldBlock)
        } else {
            Ok((n, None))
        }
    }
}

// ── In-kernel SPSC byte ring ────────────────────────────────────

const RING_CAP: usize = 64 * 1024;

#[derive(Debug)]
pub struct RingBuf {
    inner: IrqSafeSpinLock<RingInner>,
    closed: AtomicBool,
}

#[derive(Debug)]
struct RingInner {
    buf: Vec<u8>,
    head: usize,
    len: usize,
}

impl RingBuf {
    fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(RingInner {
                buf: alloc::vec![0u8; RING_CAP],
                head: 0,
                len: 0,
            }),
            closed: AtomicBool::new(false),
        }
    }

    fn write(&self, src: &[u8]) -> usize {
        let mut g = self.inner.lock();
        let avail = RING_CAP - g.len;
        let n = core::cmp::min(src.len(), avail);
        for i in 0..n {
            let pos = (g.head + g.len + i) % RING_CAP;
            g.buf[pos] = src[i];
        }
        g.len += n;
        n
    }

    fn read(&self, dst: &mut [u8]) -> usize {
        let mut g = self.inner.lock();
        let n = core::cmp::min(dst.len(), g.len);
        for i in 0..n {
            let pos = (g.head + i) % RING_CAP;
            dst[i] = g.buf[pos];
        }
        g.head = (g.head + n) % RING_CAP;
        g.len -= n;
        n
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    fn has_data(&self) -> bool {
        self.inner.lock().len > 0
    }

    fn has_space(&self) -> bool {
        self.inner.lock().len < RING_CAP
    }
}

// ── Bound-listener registry ─────────────────────────────────────

static LISTENERS: IrqSafeSpinLock<Option<BTreeMap<String, Arc<SocketFile>>>> =
    IrqSafeSpinLock::new(None);

/// AF_INET listener registry keyed by (ip, port). Loopback only
/// today; non-loopback addrs are accepted at bind() but no
/// connect path serves them until the NIC TX side wires in.
static INET_LISTENERS: IrqSafeSpinLock<Option<BTreeMap<(u32, u16), Arc<SocketFile>>>> =
    IrqSafeSpinLock::new(None);

/// AF_INET6 listener registry keyed by (ipv6, port). Same loopback-
/// only constraint as INET_LISTENERS.
static INET6_LISTENERS: IrqSafeSpinLock<Option<BTreeMap<([u8; 16], u16), Arc<SocketFile>>>> =
    IrqSafeSpinLock::new(None);

/// AF_INET datagram-bound registry: (ip, port) → socket. Lookup
/// from sendto's destination + delivery into the dest's inbox.
static INET_DGRAM_BOUND: IrqSafeSpinLock<Option<BTreeMap<(u32, u16), Arc<SocketFile>>>> =
    IrqSafeSpinLock::new(None);

/// AF_UNIX datagram-bound registry: path → socket.
static UNIX_DGRAM_BOUND: IrqSafeSpinLock<Option<BTreeMap<String, Arc<SocketFile>>>> =
    IrqSafeSpinLock::new(None);

// ── ZC fast-path: registered buffer pool ────────────────────────

static REGISTERED_BUFS: IrqSafeSpinLock<Option<BTreeMap<u32, RegBuf>>> =
    IrqSafeSpinLock::new(None);
static NEXT_BUF_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Debug)]
struct RegBuf {
    /// User vaddr of the registered region.
    base: u64,
    len: u64,
    /// Owning task id; only this task can reference it via the id.
    owner: u64,
}

pub fn register_user_buffer(owner: u64, ptr: u64, len: u64) -> Option<u32> {
    if ptr == 0 || len == 0 {
        return None;
    }
    let id = NEXT_BUF_ID.fetch_add(1, Ordering::Relaxed);
    let mut g = REGISTERED_BUFS.lock();
    let map = g.get_or_insert_with(BTreeMap::new);
    map.insert(id, RegBuf {
        base: ptr,
        len,
        owner,
    });
    Some(id)
}

pub fn registered_buffer_slice(
    owner: u64,
    buf_id: u32,
    off: u64,
    len: u64,
) -> Option<(u64, u64)> {
    let g = REGISTERED_BUFS.lock();
    let m = g.as_ref()?;
    let r = m.get(&buf_id)?;
    if r.owner != owner {
        return None;
    }
    if off.checked_add(len)? > r.len {
        return None;
    }
    Some((r.base + off, len))
}

// ── Ensure FileOps is `'static`-safe across move. SocketFile uses
//    Arc-shared rings; cloning the Arc into another fd table is the
//    intended dup() shape. ──────────────────────────────────────

#[allow(dead_code)]
fn _assert_send_sync() {
    fn assert<T: Send + Sync>() {}
    assert::<SocketFile>();
    assert::<RingBuf>();
}

// ── Stub for the future pin shape used by the dispatcher. The
//    `dispatch_op` calls today are synchronous; once we add an
//    async accept queue we'll surface a Pin<Box<...>>. Kept here
//    so the symbol is referenced from handlers.rs without an
//    "unused import" warning. ──────────────────────────────────

#[allow(dead_code)]
fn _force_pin() -> Pin<Box<dyn core::future::Future<Output = ()> + Send>> {
    Box::pin(async {})
}
