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
/// NARF kernel-bypass family — equivalent of Linux's AF_XDP (44).
/// Picks 45 because Linux's number is taken; carries our four-ring
/// model rather than mmap'd shared pages.
pub const AF_BYPASS: u16 = 45;
/// Linux `AF_NETLINK`. We implement exactly one protocol below.
pub const AF_NETLINK: u16 = 16;
/// `NETLINK_KOBJECT_UEVENT` — the udev hotplug-monitor netlink protocol.
/// libudev opens `socket(AF_NETLINK, SOCK_DGRAM|SOCK_RAW, 15)` and reads
/// device-uevent messages off it; we bridge it to the kernel uevent ring.
pub const NETLINK_KOBJECT_UEVENT: u32 = 15;

/// `sockaddr_nl` body (the bytes after the 2-byte `nl_family`) identifying
/// the KERNEL as a uevent's sender: `nl_pad=0`, `nl_pid=0` (kernel),
/// `nl_groups=1` (the KERNEL uevent group). libudev/udevd reject monitor
/// messages whose source pid is non-zero, so a uevent recv must report this.
fn kernel_nl_sockaddr_body() -> Vec<u8> {
    // nl_pad(2)=0, nl_pid(4)=0, nl_groups(4)=1 — little-endian.
    alloc::vec![0u8, 0, 0, 0, 0, 0, 1, 0, 0, 0]
}

/// Post-uevent-emit wake: bump the readiness generation + wake io waiters
/// so a parked `NETLINK_KOBJECT_UEVENT` monitor's poll/epoll resumes and
/// reads the new event. Installed into `narf_filesystem::uevent` when a
/// netlink socket is created.
fn uevent_wake_hook() {
    narf_net::readiness::notify(0);
}

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_RAW: u32 = 3;
/// `SOCK_SEQPACKET` — reliable, connection-oriented, message-boundary-
/// preserving. systemd-udev's control socket (`udev_ctrl`) uses this over
/// AF_UNIX. We back it with the AF_UNIX stream machinery; udev_ctrl frames
/// its own fixed-size messages, so byte-stream delivery is sufficient.
pub const SOCK_SEQPACKET: u32 = 5;

pub const SHUT_RD: u32 = 0;
pub const SHUT_WR: u32 = 1;
pub const SHUT_RDWR: u32 = 2;

// ── Socket-option levels and names ──────────────────────────────
// Numbers match Linux `<linux/socket.h>` / `<netinet/tcp.h>` /
// `<linux/in.h>`. Used by both handlers.rs and the dispatcher.

pub const SOL_SOCKET: u32 = 1;
pub const IPPROTO_IP: u32 = 0;
pub const IPPROTO_ICMP: u32 = 1;
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;
pub const IPPROTO_RAW: u32 = 255;

pub const SO_REUSEADDR: u32 = 2;
pub const SO_TYPE: u32 = 3;
pub const SO_ERROR: u32 = 4;
pub const SO_BROADCAST: u32 = 6;
pub const SO_SNDBUF: u32 = 7;
pub const SO_RCVBUF: u32 = 8;
pub const SO_KEEPALIVE: u32 = 9;
pub const SO_LINGER: u32 = 13;
pub const SO_REUSEPORT: u32 = 15;
pub const SO_PEERCRED: u32 = 17;
pub const SO_BINDTODEVICE: u32 = 25;
pub const SO_ACCEPTCONN: u32 = 30;
pub const SO_PROTOCOL: u32 = 38;
pub const SO_DOMAIN: u32 = 39;

pub const TCP_NODELAY: u32 = 1;
pub const TCP_MAXSEG: u32 = 2;
pub const TCP_CORK: u32 = 3;
pub const TCP_KEEPIDLE: u32 = 4;
pub const TCP_KEEPINTVL: u32 = 5;
pub const TCP_KEEPCNT: u32 = 6;
pub const TCP_QUICKACK: u32 = 12;
pub const TCP_CONGESTION: u32 = 13;
pub const TCP_USER_TIMEOUT: u32 = 18;

pub const IP_TOS: u32 = 1;
pub const IP_TTL: u32 = 2;
pub const IP_PKTINFO: u32 = 8;
pub const IP_RECVTTL: u32 = 12;
pub const IP_MTU: u32 = 14;
pub const IP_MULTICAST_TTL: u32 = 33;

/// `fcntl(F_SETFL, O_NONBLOCK)` bit. Used by the sys_fcntl path
/// to flip per-fd nonblock state on a SocketFile.
pub const O_NONBLOCK: u32 = 0o4000;

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
    Bind {
        addr: SockAddr,
    },
    Listen {
        backlog: u32,
    },
    Accept,
    Connect {
        addr: SockAddr,
    },
    Send {
        buf: &'a [u8],
        flags: u32,
        addr: Option<SockAddr>,
    },
    Recv {
        buf: &'a mut [u8],
        flags: u32,
    },
    Shutdown {
        how: u32,
    },
    /// `getsockname` — return the locally-bound address.
    GetSockName,
    /// `getpeername` — return the connected peer's address.
    GetPeerName,
    /// `setsockopt(fd, level, optname, value)`.
    SetSockOpt {
        level: u32,
        name: u32,
        value: &'a [u8],
    },
    /// `getsockopt(fd, level, optname, &out_buf)`. The dispatcher
    /// writes into `buf` and returns the byte count via `OptValue`.
    GetSockOpt {
        level: u32,
        name: u32,
        buf: &'a mut [u8],
    },
}

#[derive(Debug)]
pub enum SocketOpResult {
    Ok(u64),
    Accepted {
        socket: Arc<SocketFile>,
        peer: Option<SockAddr>,
    },
    Received {
        n: usize,
        peer: Option<SockAddr>,
    },
    /// Result of GetSockName / GetPeerName.
    Addr(SockAddr),
    /// Result of GetSockOpt — bytes written into the user-supplied
    /// buffer (the dispatcher wrote them directly through the
    /// `&mut [u8]` borrow on the op).
    OptValue {
        n: usize,
    },
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
    InProgress,
}

impl SockError {
    /// Map onto the libc-style errno value the user sees on -1.
    pub fn errno(self) -> i32 {
        match self {
            Self::BadFd => 9,               // EBADF
            Self::InvalidArg => 22,         // EINVAL
            Self::NotSupported => 95,       // ENOTSUP
            Self::NotConnected => 107,      // ENOTCONN
            Self::AlreadyConnected => 56,   // EISCONN
            Self::WouldBlock => 11,         // EAGAIN
            Self::AddrInUse => 98,          // EADDRINUSE
            Self::AddrNotAvail => 99,       // EADDRNOTAVAIL
            Self::ConnectionRefused => 111, // ECONNREFUSED
            Self::Pipe => 32,               // EPIPE
            Self::InProgress => 115,        // EINPROGRESS
        }
    }
}

// ── SocketFile (FileOps impl, lives in fd table) ────────────────

pub struct SocketFile {
    pub domain: u16,
    pub kind: u32,
    /// IPPROTO_* recorded at socket() time; surfaced via SO_PROTOCOL.
    pub protocol: u32,
    state: IrqSafeSpinLock<SocketState>,
    /// Per-socket option storage. Setsockopt writes here; getsockopt
    /// reads. Values that affect packet shape (TCP_NODELAY,
    /// SO_BROADCAST) push down into the kernel TCP/UDP stack when
    /// the socket actually wires up; the rest are passive storage.
    options: IrqSafeSpinLock<SockOptions>,
    /// O_NONBLOCK — flipped by sys_fcntl(F_SETFL). recv/send/accept/
    /// connect short-circuit to WouldBlock instead of yielding.
    nonblock: AtomicBool,
    /// Pending async error. connect/send/recv set on failure;
    /// getsockopt(SO_ERROR) consumes (returns + clears) it.
    pending_error: IrqSafeSpinLock<Option<SockError>>,
    /// Network-namespace id this socket belongs to (0 = host/default
    /// netns). Stamped by `sys_socket` from the creator's net-ns at
    /// socket() time. Used ONLY to key the AF_INET bind/port tables so
    /// two processes in different net-ns can both bind the same
    /// (addr, port); the per-packet NIC path is untouched.
    net_ns_id: core::sync::atomic::AtomicU64,
}

/// Faithful per-socket storage for set/getsockopt values. Defaults
/// match Linux's documented defaults. Fields that affect packet
/// shape get pushed down to the kernel stack when wired; the rest
/// are passive storage faithful to setsockopt round-trips.
#[derive(Debug)]
pub struct SockOptions {
    pub reuseaddr: bool,
    pub reuseport: bool,
    pub keepalive: bool,
    pub broadcast: bool,
    pub linger_on: bool,
    pub linger_sec: u32,
    pub rcvbuf: u32,
    pub sndbuf: u32,
    pub bindtodevice: Option<String>,
    // TCP
    pub tcp_nodelay: bool,
    pub tcp_keepidle: u32,
    pub tcp_keepintvl: u32,
    pub tcp_keepcnt: u32,
    pub tcp_user_timeout: u32,
    pub tcp_maxseg: u32,
    pub tcp_cork: bool,
    pub tcp_quickack: bool,
    pub tcp_congestion: String,
    // IP
    pub ip_ttl: u32,
    pub ip_tos: u32,
    pub ip_pktinfo: bool,
    pub ip_recvttl: bool,
    pub ip_mtu: u32,
    pub ip_multicast_ttl: u32,
}

impl Default for SockOptions {
    fn default() -> Self {
        Self {
            reuseaddr: false,
            reuseport: false,
            keepalive: false,
            broadcast: false,
            linger_on: false,
            linger_sec: 0,
            rcvbuf: 212_992,
            sndbuf: 212_992,
            bindtodevice: None,
            tcp_nodelay: false,
            tcp_keepidle: 7200,
            tcp_keepintvl: 75,
            tcp_keepcnt: 9,
            tcp_user_timeout: 0,
            tcp_maxseg: 1460,
            tcp_cork: false,
            tcp_quickack: false,
            tcp_congestion: String::from("cubic"),
            ip_ttl: 64,
            ip_tos: 0,
            ip_pktinfo: false,
            ip_recvttl: false,
            ip_mtu: 1500,
            ip_multicast_ttl: 1,
        }
    }
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
    /// AF_INET SOCK_STREAM bound listener at (addr, port). The
    /// `pending` queue + `INET_LISTENERS` map serve loopback
    /// (127.0.0.1) connects in-process. When the bind address is NOT
    /// loopback (0.0.0.0 / a wired iface IP), `listen()` ALSO opens a
    /// listener in the kernel TCP-over-NIC stack and records its
    /// `listen_id` here, so `accept()` pulls off-box connections (whose
    /// SYNs arrive via `tcp_stack::rx_handler`) from the kernel
    /// accept-queue and wraps each as an `InetWired` endpoint.
    InetListener {
        addr: u32,
        port: u16,
        backlog: u32,
        pending: VecDeque<Arc<SocketFile>>,
        /// `Some(id)` once a kernel-stack listener is open (non-loopback
        /// binds); `None` for loopback-only listeners.
        listen_id: Option<u32>,
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
    /// AF_INET SOCK_RAW. `protocol` is the IP protocol number
    /// (IPPROTO_ICMP, IPPROTO_RAW, etc.). ICMP echo flows route
    /// through the local inbox; the kernel raw IP path lands when
    /// `narf_net::raw_sock` wires through `iface::install_rx_handler`.
    InetRaw {
        protocol: u32,
        local_addr: u32,
        peer: Option<(u32, u16)>,
        inbox: VecDeque<DgramPacket>,
    },
    /// AF_BYPASS / AF_XDP-equivalent socket. Carries an Arc to a
    /// kernel-bypass state struct so `dispatch_op` can route into
    /// `crate::xdp_socket` for the four-ring setup, bind, and
    /// frame-level send/recv.
    Bypass {
        state: Arc<crate::xdp_socket::XdpSocketState>,
    },
    /// `AF_NETLINK` / `NETLINK_KOBJECT_UEVENT` monitor. Each socket carries
    /// its own cursor into the kernel uevent ring; `recv` drains one
    /// device-uevent message at a time (Linux netlink wire text), `poll`
    /// reports readable when the ring has events past the cursor.
    NetlinkUevent {
        reader: narf_filesystem::uevent::UeventReader,
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
        Self::with_protocol(domain, kind, 0)
    }

    /// Create a SocketFile with an explicit IP protocol. Used by
    /// `socket(domain, type, protocol)` so SOCK_RAW carries its
    /// IPPROTO_*, and so SO_PROTOCOL round-trips. Also seeds the
    /// state with InetRaw for AF_INET/SOCK_RAW.
    pub fn with_protocol(domain: u16, kind: u32, protocol: u32) -> Arc<Self> {
        let state = if domain == AF_INET && kind == SOCK_RAW {
            SocketState::InetRaw {
                protocol,
                local_addr: 0,
                peer: None,
                inbox: VecDeque::new(),
            }
        } else if domain == AF_BYPASS && kind == SOCK_RAW {
            // AF_BYPASS / AF_XDP-equivalent. Kernel-bypass state is
            // built lazily on setsockopt(XDP_UMEM_REG); here we just
            // stamp a fresh per-socket state record.
            SocketState::Bypass {
                state: Arc::new(crate::xdp_socket::XdpSocketState::new()),
            }
        } else if domain == AF_NETLINK {
            // Wire the post-emit wake so a uevent emitted while this monitor
            // is parked in poll/epoll wakes it (the ring lives in the fs
            // crate, which can't reach the net readiness layer directly).
            // Idempotent — a plain atomic store.
            narf_filesystem::uevent::set_wake_hook(uevent_wake_hook);
            // Start at the ring TAIL — a netlink uevent monitor only receives
            // events broadcast *after* it binds (Linux `NETLINK_KOBJECT_UEVENT`
            // is not replayed on connect). Replaying the buffered boot-time
            // "add" events to a late-connecting monitor is actively harmful:
            // libudev/libinput does NOT de-dup them against its sysfs
            // enumerate — it re-runs `evdev_device_create` for each replayed
            // "add", and that second add tears the already-created input device
            // back down (weston loses all keyboards/pointers ~5s after start).
            // Existing devices are discovered via `udev_enumerate` (sysfs
            // scan), not the monitor, so tail-start loses nothing.
            SocketState::NetlinkUevent {
                reader: narf_filesystem::uevent::UeventReader::new(),
            }
        } else {
            SocketState::Fresh
        };
        Arc::new(Self {
            domain,
            kind,
            protocol,
            state: IrqSafeSpinLock::new(state),
            options: IrqSafeSpinLock::new(SockOptions::default()),
            nonblock: AtomicBool::new(false),
            pending_error: IrqSafeSpinLock::new(None),
            net_ns_id: core::sync::atomic::AtomicU64::new(0),
        })
    }

    /// Stamp this socket's network-namespace id (see field docs).
    pub fn set_net_ns_id(&self, id: u64) {
        self.net_ns_id
            .store(id, core::sync::atomic::Ordering::Relaxed);
    }

    /// This socket's network-namespace id (0 = host/default).
    pub fn net_ns_id(&self) -> u64 {
        self.net_ns_id.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Create a pre-connected AF_UNIX SOCK_STREAM pair for
    /// `socketpair(2)`. Mints two ring buffers and crosses tx/rx so
    /// each end's `tx` is the other end's `rx` — the same wiring the
    /// `connect()`/`accept()` handshake produces, minus the named
    /// listener lookup. Both ends come back already `UnixConnected`.
    pub fn unix_stream_pair() -> (Arc<Self>, Arc<Self>) {
        let a = Self::new(AF_UNIX, SOCK_STREAM);
        let b = Self::new(AF_UNIX, SOCK_STREAM);
        let a_to_b = Arc::new(RingBuf::new());
        let b_to_a = Arc::new(RingBuf::new());
        *a.state.lock() = SocketState::UnixConnected {
            tx: a_to_b.clone(),
            rx: b_to_a.clone(),
        };
        *b.state.lock() = SocketState::UnixConnected {
            tx: b_to_a,
            rx: a_to_b,
        };
        (a, b)
    }

    /// Toggle the O_NONBLOCK flag (fcntl F_SETFL path).
    pub fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Release);
    }

    pub fn is_nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Acquire)
    }

    /// Drain the pending async error. SO_ERROR consumes-and-clears.
    pub fn take_pending_error(&self) -> Option<SockError> {
        self.pending_error.lock().take()
    }

    /// Record an async error so a subsequent getsockopt(SO_ERROR)
    /// can report it. Used by connect/send failure paths.
    pub fn set_pending_error(&self, e: SockError) {
        *self.pending_error.lock() = Some(e);
    }

    /// Encode the socket's locally-bound address (if any). Honors
    /// the same shape as `copy_user_addr`'s input.
    pub fn local_addr(&self) -> Option<SockAddr> {
        let state = self.state.lock();
        match &*state {
            SocketState::InetListener { addr, port, .. } => Some(make_sockaddr_in(*addr, *port)),
            SocketState::InetConnected {
                peer_addr,
                peer_port,
                ..
            } => {
                let _ = (peer_addr, peer_port);
                Some(make_sockaddr_in(0, 0))
            }
            SocketState::InetWired {
                peer_addr,
                peer_port,
                ..
            } => {
                let _ = (peer_addr, peer_port);
                Some(make_sockaddr_in(0, 0))
            }
            SocketState::InetDgram {
                local_addr,
                local_port,
                ..
            } => Some(make_sockaddr_in(*local_addr, *local_port)),
            SocketState::InetRaw { local_addr, .. } => Some(make_sockaddr_in(*local_addr, 0)),
            SocketState::UnixListener { path, .. } => Some(SockAddr {
                family: AF_UNIX,
                body: path.as_bytes().to_vec(),
            }),
            SocketState::UnixDgram { path: Some(p), .. } => Some(SockAddr {
                family: AF_UNIX,
                body: p.as_bytes().to_vec(),
            }),
            SocketState::Inet6Listener { addr, port, .. } => Some(make_sockaddr_in6(*addr, *port)),
            SocketState::Inet6Connected {
                peer_addr,
                peer_port,
                ..
            } => {
                let _ = (peer_addr, peer_port);
                Some(make_sockaddr_in6([0u8; 16], 0))
            }
            _ => None,
        }
    }

    /// Encode the socket's connected peer address (if any).
    pub fn peer_addr(&self) -> Option<SockAddr> {
        let state = self.state.lock();
        match &*state {
            SocketState::InetConnected {
                peer_addr,
                peer_port,
                ..
            } => Some(make_sockaddr_in(*peer_addr, *peer_port)),
            SocketState::InetWired {
                peer_addr,
                peer_port,
                ..
            } => Some(make_sockaddr_in(*peer_addr, *peer_port)),
            SocketState::InetDgram {
                peer: Some((a, p)), ..
            } => Some(make_sockaddr_in(*a, *p)),
            SocketState::InetRaw {
                peer: Some((a, p)), ..
            } => Some(make_sockaddr_in(*a, *p)),
            SocketState::UnixDgram { peer: Some(p), .. } => Some(SockAddr {
                family: AF_UNIX,
                body: p.as_bytes().to_vec(),
            }),
            SocketState::Inet6Connected {
                peer_addr,
                peer_port,
                ..
            } => Some(make_sockaddr_in6(*peer_addr, *peer_port)),
            _ => None,
        }
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
                SocketState::InetListener {
                    addr,
                    port,
                    listen_id,
                    ..
                } => {
                    // Tear down the kernel-stack listener TCB (if any);
                    // accepted child TCBs are owned by their own InetWired
                    // sockets and torn down separately.
                    if let Some(id) = listen_id {
                        narf_net::tcp_stack::remove_tcb(*id);
                        crate::handlers::clear_tcb_owner(*id);
                    }
                    Reg::Inet(*addr, *port)
                }
                SocketState::Inet6Listener { addr, port, .. } => Reg::Inet6(*addr, *port),
                SocketState::UnixDgram { path: Some(p), .. } => Reg::UnixDgram(p.clone()),
                SocketState::InetDgram {
                    local_addr,
                    local_port,
                    ..
                } => Reg::InetDgram(*local_addr, *local_port),
                SocketState::InetWired { tcb_id, .. } => Reg::Tcb(*tcb_id),
                _ => Reg::None,
            }
        };
        match reg {
            Reg::Unix(p) => {
                if let Some(map) = LISTENERS.lock().as_mut() {
                    map.remove(&p);
                }
            }
            Reg::Inet(a, p) => {
                if let Some(map) = INET_LISTENERS.lock().as_mut() {
                    map.remove(&(self.net_ns_id(), a, p));
                }
            }
            Reg::Inet6(a, p) => {
                if let Some(map) = INET6_LISTENERS.lock().as_mut() {
                    map.remove(&(a, p));
                }
            }
            Reg::UnixDgram(p) => {
                if let Some(map) = UNIX_DGRAM_BOUND.lock().as_mut() {
                    map.remove(&p);
                }
            }
            Reg::InetDgram(a, p) => {
                if let Some(map) = INET_DGRAM_BOUND.lock().as_mut() {
                    map.remove(&(self.net_ns_id(), a, p));
                }
                // Release any ephemeral reservation. clear() on an
                // unset bit is a no-op, so an explicit bind() to a
                // port in this range is harmless.
                if p >= crate::ephemeral_port::EPHEMERAL_MIN {
                    crate::ephemeral_port::free(
                        AF_INET,
                        0,
                        crate::ephemeral_port::SocketProto::Udp,
                        p,
                    );
                    if a != 0 {
                        crate::ephemeral_port::free(
                            AF_INET,
                            a,
                            crate::ephemeral_port::SocketProto::Udp,
                            p,
                        );
                    }
                }
            }
            Reg::Tcb(id) => {
                let _ = narf_net::tcp_stack::close(id);
                crate::handlers::clear_tcb_owner(id);
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

/// Build a `SockAddr` matching the wire body shape (`copy_user_addr`
/// in handlers.rs): family u16 + body[port_be, ip_be...]. `addr`
/// and `port` are taken in host byte order; the body is encoded BE.
pub fn make_sockaddr_in(addr: u32, port: u16) -> SockAddr {
    let mut body = Vec::with_capacity(6);
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&addr.to_be_bytes());
    SockAddr {
        family: AF_INET,
        body,
    }
}

/// Build an IPv6 sockaddr body.
pub fn make_sockaddr_in6(addr: [u8; 16], port: u16) -> SockAddr {
    let mut body = Vec::with_capacity(2 + 4 + 16);
    body.extend_from_slice(&port.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // flowinfo
    body.extend_from_slice(&addr);
    SockAddr {
        family: AF_INET6,
        body,
    }
}

/// Parse a `sockaddr_in`-shaped body into (ip, port) in host byte
/// order. Returns `None` if the family isn't AF_INET or the body
/// is too short.
pub fn parse_sockaddr_in(addr: &SockAddr) -> Option<(u32, u16)> {
    if addr.family != AF_INET || addr.body.len() < 6 {
        return None;
    }
    let port = u16::from_be_bytes([addr.body[0], addr.body[1]]);
    let ip = u32::from_be_bytes([addr.body[2], addr.body[3], addr.body[4], addr.body[5]]);
    Some((ip, port))
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

    fn read_should_block(&self) -> bool {
        // `read`/`recv` maps an empty ring to `Ok(0)`, which is indistinguishable
        // from a real EOF by byte count alone. `sys_read` only blocks a 0-byte
        // read when this returns true; the default is `false`, so WITHOUT this a
        // blocking recv on an empty-but-open socket returns a spurious EOF the
        // instant it finds no data — a blocking server (e.g. one that accept()s
        // then read()s a request, rather than poll()ing first like libwayland)
        // sees "peer closed" and gives up. Block while the rx side is still OPEN;
        // a genuine peer-close (rx closed) correctly falls through to EOF. Use
        // `!is_closed()` (not `!has_data()`) so data arriving between the read and
        // this check still re-executes the read instead of returning EOF.
        let state = self.state.lock();
        match &*state {
            SocketState::UnixConnected { rx, .. }
            | SocketState::InetConnected { rx, .. }
            | SocketState::Inet6Connected { rx, .. } => !rx.is_closed(),
            // Kernel-TCP-over-NIC (off-box) sockets: the rx lives in the TCB,
            // not a RingBuf here, so `readable()` is the authority — it's true
            // when RX data is buffered OR the peer closed / the connection is
            // dead (read returns EOF). Block a 0-byte read only while the
            // connection is OPEN-but-empty (`!readable`). WITHOUT this arm an
            // `InetWired` socket fell to `_ => false`, so a blocking server
            // that accept()s then read()s (netserve) saw a spurious EOF the
            // instant it read before the peer's first segment arrived — the
            // off-box net-smoke `netserve-fail: read` under slow (TCG) timing;
            // masked under KVM only because the data always beat the read.
            SocketState::InetWired { tcb_id, .. } => !narf_net::tcp_stack::readable(*tcb_id),
            SocketState::UnixDgram { inbox, .. } | SocketState::InetDgram { inbox, .. } => {
                inbox.is_empty()
            }
            _ => false,
        }
    }

    /// A readiness transition on a socket fires `readiness::notify` (the
    /// AF_UNIX send/connect paths and the TCP receive path both call it), so a
    /// `poll`/`epoll` waiter parked on a socket is woken promptly. This lets
    /// the blocking-poll fast path PARK an all-socket wait instead of
    /// busy-spinning — without it a Wayland client blocked in `poll(-1)` on its
    /// display fd pins a CPU and starves the cooperative own-stack executor.
    fn readiness_notifies(&self) -> bool {
        true
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode {
                file_type: narf_filesystem::FileType::Socket,
                perms: 0o600,
            },
            mtime_cycles: 0,
        }
    }

    fn poll_readiness(&self) -> u32 {
        let state = self.state.lock();
        match &*state {
            SocketState::Fresh => 0,
            // An AF_INET listener is accept-ready (POLL_IN) when its
            // loopback `pending` queue OR — for a wired (off-box) listen
            // — the kernel-stack accept-queue has a completed connection.
            // Without the kernel-queue check, an epoll-driven server like
            // redis never sees an incoming off-box connection.
            SocketState::InetListener {
                pending, listen_id, ..
            } => {
                let ready = !pending.is_empty()
                    || listen_id
                        .map(narf_net::tcp_stack::listen_has_pending)
                        .unwrap_or(false);
                if ready {
                    narf_filesystem::POLL_IN
                } else {
                    0
                }
            }
            SocketState::UnixListener { pending, .. }
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
                // Linux reports POLLIN on a peer-closed stream socket too, so
                // the reader's normal readable path runs, read() returns 0
                // (EOF), and it tears the connection down. Reporting only
                // POLLHUP (no POLLIN) here made dbus-daemon busy-spin on a
                // hung-up client fd — epoll kept returning it ready, but with
                // no POLLIN dbus never entered its read/disconnect path and
                // looped forever, wedging the whole session bus (Plasma stall).
                if rx.has_data() || rx.is_closed() {
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
            SocketState::InetDgram { inbox, .. } | SocketState::UnixDgram { inbox, .. } => {
                let mut bits = narf_filesystem::POLL_OUT; // always sendable
                if !inbox.is_empty() {
                    bits |= narf_filesystem::POLL_IN;
                }
                bits
            }
            SocketState::InetWired { tcb_id, .. } => {
                // Kernel-TCP-over-NIC: always writable (the stack
                // queues + flow-controls send), and POLL_IN when the
                // TCB has buffered RX data or the peer has closed
                // (read returns EOF). This is what makes epoll/poll/
                // select on a kernel-TCP socket wake on inbound data.
                let mut bits = narf_filesystem::POLL_OUT;
                if narf_net::tcp_stack::readable(*tcb_id) {
                    bits |= narf_filesystem::POLL_IN;
                }
                bits
            }
            SocketState::InetRaw { inbox, .. } => {
                let mut bits = narf_filesystem::POLL_OUT;
                if !inbox.is_empty() {
                    bits |= narf_filesystem::POLL_IN;
                }
                bits
            }
            SocketState::Bypass { .. } => {
                // Kernel-bypass path: readiness is managed by the XDP
                // layer directly; report both directions so callers can
                // always proceed and let the XDP ring buffer throttle.
                narf_filesystem::POLL_IN | narf_filesystem::POLL_OUT
            }
            SocketState::NetlinkUevent { reader } => {
                // Readable when an unread uevent is waiting; always writable
                // (the udev monitor is read-only but POLL_OUT is harmless).
                let mut bits = narf_filesystem::POLL_OUT;
                if reader.has_pending() {
                    bits |= narf_filesystem::POLL_IN;
                }
                bits
            }
        }
    }
}

impl SocketFile {
    /// Per-op dispatcher. The SocketOp enum carries the operation
    /// shape; the per-family branch executes it. POSIX syscall
    /// shims and ring opcodes both call this.
    pub fn dispatch_op(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        // Cross-family ops handled here directly: getsockname /
        // getpeername / set/getsockopt operate on storage that's
        // common across all family backends.
        match op {
            SocketOp::GetSockName => {
                // AF_NETLINK has no bound local_addr, but systemd/elogind's
                // sd_device_monitor getsockname()s the netlink socket right
                // after bind to learn the kernel-assigned nl_pid — a failure
                // there aborts "create udev watchers" → "Failed to fully start
                // up daemon". Synthesize sockaddr_nl body = nl_pad(2) +
                // nl_pid(4, unique non-zero) + nl_groups(4).
                if self.domain == AF_NETLINK {
                    static NL_PID: AtomicU32 = AtomicU32::new(0);
                    let pid = NL_PID.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                    let mut body = alloc::vec![0u8; 10];
                    body[2..6].copy_from_slice(&pid.to_le_bytes());
                    return SocketOpResult::Addr(SockAddr {
                        family: AF_NETLINK,
                        body,
                    });
                }
                return match self.local_addr() {
                    Some(a) => SocketOpResult::Addr(a),
                    // An *accepted* AF_UNIX socket has no bound local path, but
                    // libdbus's `_dbus_socket_can_pass_unix_fd()` getsockname()s
                    // the connection and enables SCM_RIGHTS fd-passing only if
                    // `sa_family == AF_UNIX`. Returning an error made dbus-daemon
                    // reply ERROR to NEGOTIATE_UNIX_FD, so a peer (elogind) could
                    // not pass an fd back — e.g. the session-controller fd in the
                    // CreateSession reply → "Not supported" → no logind session.
                    // Report a minimal AF_UNIX sockaddr (family only, empty path).
                    None if self.domain == AF_UNIX => SocketOpResult::Addr(SockAddr {
                        family: AF_UNIX,
                        body: alloc::vec::Vec::new(),
                    }),
                    None => SocketOpResult::Err(SockError::NotConnected),
                };
            }
            SocketOp::GetPeerName => {
                return match self.peer_addr() {
                    Some(a) => SocketOpResult::Addr(a),
                    None => SocketOpResult::Err(SockError::NotConnected),
                };
            }
            SocketOp::SetSockOpt { level, name, value } => {
                return self.handle_setsockopt(level, name, value);
            }
            SocketOp::GetSockOpt { level, name, buf } => {
                return self.handle_getsockopt(level, name, buf);
            }
            _ => {}
        }
        match (self.domain, self.kind) {
            (AF_UNIX, SOCK_STREAM) | (AF_UNIX, SOCK_SEQPACKET) => self.dispatch_unix_stream(op),
            (AF_INET, SOCK_STREAM) => self.dispatch_inet_stream(op),
            (AF_INET, SOCK_DGRAM) => self.dispatch_inet_dgram(op),
            (AF_INET, SOCK_RAW) => self.dispatch_inet_raw(op),
            (AF_UNIX, SOCK_DGRAM) => self.dispatch_unix_dgram(op),
            (AF_INET6, SOCK_STREAM) => self.dispatch_inet6_stream(op),
            (AF_BYPASS, SOCK_RAW) => self.dispatch_bypass(op),
            (AF_NETLINK, _) => self.dispatch_netlink(op),
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    /// `AF_NETLINK` / `NETLINK_KOBJECT_UEVENT` dispatcher. The monitor only
    /// ever binds (to a group mask we ignore) and receives; `recv` drains one
    /// uevent message from the ring per call (libudev reads one message per
    /// recv/recvmsg). Empty ring → WouldBlock so the caller blocks or gets
    /// EAGAIN, exactly like a quiet hardware monitor.
    fn dispatch_netlink(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            // bind(sockaddr_nl{family=16, pid, groups}) — accept any.
            SocketOp::Bind { .. } => SocketOpResult::Ok(0),
            // udev clients never send on the monitor; accept + discard.
            SocketOp::Send { buf, .. } => SocketOpResult::Ok(buf.len() as u64),
            SocketOp::Recv { buf, flags: _ } => {
                let ev = {
                    let mut g = self.state.lock();
                    match &mut *g {
                        SocketState::NetlinkUevent { reader } => reader.drain(1).into_iter().next(),
                        _ => return SocketOpResult::Err(SockError::InvalidArg),
                    }
                };
                match ev {
                    Some(env) => {
                        // Kernel netlink uevent wire format (NUL-separated,
                        // `action@devpath` header) so libudev/udevd parse it.
                        let bytes = env.to_netlink_bytes();
                        let n = core::cmp::min(buf.len(), bytes.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                        // Sender is the kernel: sockaddr_nl{family=AF_NETLINK,
                        // pid=0, groups=1}. libudev rejects monitor messages
                        // whose source pid != 0, so we must report it.
                        let peer = SockAddr {
                            family: AF_NETLINK,
                            body: kernel_nl_sockaddr_body(),
                        };
                        SocketOpResult::Received {
                            n,
                            peer: Some(peer),
                        }
                    }
                    None => SocketOpResult::Err(SockError::WouldBlock),
                }
            }
            SocketOp::Shutdown { how: _ } => SocketOpResult::Ok(0),
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    /// AF_BYPASS / AF_XDP-equivalent dispatcher. Routes the small
    /// BSD-shaped surface (bind / recv / shutdown) into
    /// `crate::xdp_socket`; the bulk of the API is exposed via
    /// `setsockopt(SOL_XDP, …)` which `handle_setsockopt` routes.
    fn dispatch_bypass(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        let state_arc = {
            let g = self.state.lock();
            match &*g {
                SocketState::Bypass { state } => state.clone(),
                _ => return SocketOpResult::Err(SockError::InvalidArg),
            }
        };
        match op {
            SocketOp::Bind { addr } => {
                if addr.family != AF_BYPASS {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let parsed = match crate::xdp_socket::parse_sockaddr_xdp(&addr.body) {
                    Some(p) => p,
                    None => return SocketOpResult::Err(SockError::InvalidArg),
                };
                match crate::xdp_socket::handle_bind(&state_arc, &parsed) {
                    Ok(()) => SocketOpResult::Ok(0),
                    Err(_) => SocketOpResult::Err(SockError::InvalidArg),
                }
            }
            SocketOp::Recv { buf, flags: _ } => match crate::xdp_socket::try_recv(&state_arc) {
                Ok(Some((_slot, bytes))) => {
                    let n = core::cmp::min(buf.len(), bytes.len());
                    buf[..n].copy_from_slice(&bytes[..n]);
                    SocketOpResult::Received { n, peer: None }
                }
                Ok(None) => SocketOpResult::Err(SockError::WouldBlock),
                Err(_) => SocketOpResult::Err(SockError::InvalidArg),
            },
            SocketOp::Shutdown { how: _ } => {
                crate::xdp_socket::close(&state_arc);
                SocketOpResult::Ok(0)
            }
            // Listen/accept/connect/send via BSD shape intentionally
            // don't apply to AF_BYPASS.
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    /// `setsockopt` dispatcher. `value` is the in-kernel
    /// representation: 4-byte native-endian int for integer
    /// options, raw bytes for string options.
    fn handle_setsockopt(&self, level: u32, name: u32, value: &[u8]) -> SocketOpResult {
        let read_u32 = |slot: &[u8]| -> Result<u32, SockError> {
            if slot.len() < 4 {
                return Err(SockError::InvalidArg);
            }
            Ok(u32::from_ne_bytes([slot[0], slot[1], slot[2], slot[3]]))
        };
        // Kernel TCB pushdown: when the socket is bound to a real
        // narf_net::tcp_stack TCB, forward TCP-layer options through
        // the kernel API so the negotiation actually takes effect on
        // the wire. Options we don't recognise here fall through and
        // are stored in `self.options` for round-trip purposes.
        if level == IPPROTO_TCP {
            let tcb_id = {
                let state = self.state.lock();
                if let SocketState::InetWired { tcb_id, .. } = &*state {
                    Some(*tcb_id)
                } else {
                    None
                }
            };
            if let Some(id) = tcb_id {
                if name == TCP_CONGESTION {
                    if let Ok(s) = core::str::from_utf8(value) {
                        let name = s.trim_end_matches('\0');
                        let _ = narf_net::tcp_stack::setsockopt_str(
                            id,
                            narf_net::tcp_stack::TCP_CONGESTION,
                            name,
                        );
                    }
                } else {
                    let raw = match read_u32(value) {
                        Ok(v) => v as i32,
                        Err(_) => 0,
                    };
                    let kid: Option<i32> = match name {
                        TCP_NODELAY => Some(narf_net::tcp_stack::TCP_NODELAY),
                        TCP_KEEPIDLE => Some(narf_net::tcp_stack::TCP_KEEPIDLE),
                        TCP_KEEPINTVL => Some(narf_net::tcp_stack::TCP_KEEPINTVL),
                        TCP_KEEPCNT => Some(narf_net::tcp_stack::TCP_KEEPCNT),
                        TCP_USER_TIMEOUT => Some(narf_net::tcp_stack::TCP_USER_TIMEOUT),
                        TCP_MAXSEG => Some(narf_net::tcp_stack::TCP_MAXSEG),
                        TCP_CORK => Some(narf_net::tcp_stack::TCP_CORK),
                        TCP_QUICKACK => Some(narf_net::tcp_stack::TCP_QUICKACK),
                        _ => None,
                    };
                    if let Some(opt) = kid {
                        let _ = narf_net::tcp_stack::setsockopt_int(id, opt, raw);
                    }
                }
            }
        }
        if level == SOL_SOCKET && name == SO_KEEPALIVE {
            let tcb_id = {
                let state = self.state.lock();
                if let SocketState::InetWired { tcb_id, .. } = &*state {
                    Some(*tcb_id)
                } else {
                    None
                }
            };
            if let Some(id) = tcb_id {
                let raw = match read_u32(value) {
                    Ok(v) => v as i32,
                    Err(_) => 0,
                };
                let _ = narf_net::tcp_stack::setsockopt_int(
                    id,
                    narf_net::tcp_stack::TCP_KEEPALIVE,
                    raw,
                );
            }
        }
        let mut opts = self.options.lock();
        match (level, name) {
            (SOL_SOCKET, SO_REUSEADDR) => match read_u32(value) {
                Ok(v) => {
                    opts.reuseaddr = v != 0;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (SOL_SOCKET, SO_REUSEPORT) => match read_u32(value) {
                Ok(v) => {
                    opts.reuseport = v != 0;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (SOL_SOCKET, SO_KEEPALIVE) => match read_u32(value) {
                Ok(v) => {
                    opts.keepalive = v != 0;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (SOL_SOCKET, SO_BROADCAST) => match read_u32(value) {
                Ok(v) => {
                    opts.broadcast = v != 0;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (SOL_SOCKET, SO_LINGER) => {
                if value.len() < 8 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let onoff = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
                let linger = u32::from_ne_bytes([value[4], value[5], value[6], value[7]]);
                opts.linger_on = onoff != 0;
                opts.linger_sec = linger;
                SocketOpResult::Ok(0)
            }
            (SOL_SOCKET, SO_RCVBUF) => match read_u32(value) {
                Ok(v) => {
                    opts.rcvbuf = v.max(2_048);
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (SOL_SOCKET, SO_SNDBUF) => match read_u32(value) {
                Ok(v) => {
                    opts.sndbuf = v.max(2_048);
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (SOL_SOCKET, SO_BINDTODEVICE) => match core::str::from_utf8(value) {
                Ok(s) => {
                    let n = String::from(s.trim_end_matches('\0'));
                    opts.bindtodevice = if n.is_empty() { None } else { Some(n) };
                    SocketOpResult::Ok(0)
                }
                Err(_) => SocketOpResult::Err(SockError::InvalidArg),
            },
            (SOL_SOCKET, SO_TYPE)
            | (SOL_SOCKET, SO_DOMAIN)
            | (SOL_SOCKET, SO_PROTOCOL)
            | (SOL_SOCKET, SO_ERROR) => SocketOpResult::Err(SockError::InvalidArg),
            (IPPROTO_TCP, TCP_NODELAY) => match read_u32(value) {
                Ok(v) => {
                    opts.tcp_nodelay = v != 0;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_TCP, TCP_KEEPIDLE) => match read_u32(value) {
                Ok(v) => {
                    opts.tcp_keepidle = v;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_TCP, TCP_KEEPINTVL) => match read_u32(value) {
                Ok(v) => {
                    opts.tcp_keepintvl = v;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_TCP, TCP_KEEPCNT) => match read_u32(value) {
                Ok(v) => {
                    opts.tcp_keepcnt = v;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_TCP, TCP_USER_TIMEOUT) => match read_u32(value) {
                Ok(v) => {
                    opts.tcp_user_timeout = v;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_TCP, TCP_MAXSEG) => match read_u32(value) {
                Ok(v) => {
                    if !(88..=65_535).contains(&v) {
                        return SocketOpResult::Err(SockError::InvalidArg);
                    }
                    opts.tcp_maxseg = v;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_TCP, TCP_CORK) => match read_u32(value) {
                Ok(v) => {
                    opts.tcp_cork = v != 0;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_TCP, TCP_QUICKACK) => match read_u32(value) {
                Ok(v) => {
                    opts.tcp_quickack = v != 0;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_TCP, TCP_CONGESTION) => match core::str::from_utf8(value) {
                Ok(s) => {
                    let n = s.trim_end_matches('\0');
                    match n {
                        "reno" | "cubic" | "bbr" | "vegas" | "westwood" => {
                            opts.tcp_congestion = String::from(n);
                            SocketOpResult::Ok(0)
                        }
                        _ => SocketOpResult::Err(SockError::InvalidArg),
                    }
                }
                Err(_) => SocketOpResult::Err(SockError::InvalidArg),
            },
            (IPPROTO_IP, IP_TTL) => match read_u32(value) {
                Ok(v) => {
                    if v == 0 || v > 255 {
                        return SocketOpResult::Err(SockError::InvalidArg);
                    }
                    opts.ip_ttl = v;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_IP, IP_TOS) => match read_u32(value) {
                Ok(v) => {
                    if v > 255 {
                        return SocketOpResult::Err(SockError::InvalidArg);
                    }
                    opts.ip_tos = v;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_IP, IP_PKTINFO) => match read_u32(value) {
                Ok(v) => {
                    opts.ip_pktinfo = v != 0;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_IP, IP_RECVTTL) => match read_u32(value) {
                Ok(v) => {
                    opts.ip_recvttl = v != 0;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            (IPPROTO_IP, IP_MULTICAST_TTL) => match read_u32(value) {
                Ok(v) => {
                    if v > 255 {
                        return SocketOpResult::Err(SockError::InvalidArg);
                    }
                    opts.ip_multicast_ttl = v;
                    SocketOpResult::Ok(0)
                }
                Err(e) => SocketOpResult::Err(e),
            },
            // Accept-and-ignore any option NARF doesn't model, rather
            // than failing it. Linux returns success (or ENOPROTOOPT) for
            // benign unknown options; returning an error makes real
            // daemons abort — redis treats a failed setsockopt(IPV6_V6ONLY)
            // on its listener as fatal. The value is simply not applied.
            _ => SocketOpResult::Ok(0),
        }
    }

    /// `getsockopt` dispatcher. Writes the value into `buf` and
    /// returns the byte count via `OptValue`. Integers are
    /// native-endian 4 bytes per Linux ABI.
    fn handle_getsockopt(&self, level: u32, name: u32, buf: &mut [u8]) -> SocketOpResult {
        let write_u32 = |buf: &mut [u8], v: u32| -> SocketOpResult {
            if buf.len() < 4 {
                return SocketOpResult::Err(SockError::InvalidArg);
            }
            buf[..4].copy_from_slice(&v.to_ne_bytes());
            SocketOpResult::OptValue { n: 4 }
        };
        let write_bool = |buf: &mut [u8], v: bool| write_u32(buf, v as u32);
        if level == SOL_SOCKET && name == SO_ERROR {
            let e = self.take_pending_error();
            let val = e.map(|e| e.errno() as u32).unwrap_or(0);
            return write_u32(buf, val);
        }
        // SO_ACCEPTCONN: 1 if the socket is `listen()`ing, else 0. Handled
        // before the `options` lock so we never nest state under options.
        // systemd's is_socket_internal() (behind sd_is_socket, which gates
        // sd-bus SCM_RIGHTS fd-passing) getsockopt()s this whenever the
        // `listening` arg is >= 0 — including sd_bus's
        // sd_is_socket(fd, AF_UNIX, 0, 0). An error here made accept_fd false
        // → no NEGOTIATE_UNIX_FD → elogind CreateSession "Not supported".
        if level == SOL_SOCKET && name == SO_ACCEPTCONN {
            let listening = matches!(
                &*self.state.lock(),
                SocketState::UnixListener { .. }
                    | SocketState::InetListener { .. }
                    | SocketState::Inet6Listener { .. }
            );
            return write_bool(buf, listening);
        }
        let opts = self.options.lock();
        match (level, name) {
            (SOL_SOCKET, SO_REUSEADDR) => write_bool(buf, opts.reuseaddr),
            (SOL_SOCKET, SO_REUSEPORT) => write_bool(buf, opts.reuseport),
            (SOL_SOCKET, SO_KEEPALIVE) => write_bool(buf, opts.keepalive),
            (SOL_SOCKET, SO_BROADCAST) => write_bool(buf, opts.broadcast),
            (SOL_SOCKET, SO_LINGER) => {
                if buf.len() < 8 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                buf[..4].copy_from_slice(&(opts.linger_on as u32).to_ne_bytes());
                buf[4..8].copy_from_slice(&opts.linger_sec.to_ne_bytes());
                SocketOpResult::OptValue { n: 8 }
            }
            (SOL_SOCKET, SO_RCVBUF) => write_u32(buf, opts.rcvbuf),
            (SOL_SOCKET, SO_SNDBUF) => write_u32(buf, opts.sndbuf),
            (SOL_SOCKET, SO_BINDTODEVICE) => {
                let s = opts.bindtodevice.as_deref().unwrap_or("");
                let bytes = s.as_bytes();
                let n = core::cmp::min(buf.len(), bytes.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                SocketOpResult::OptValue { n }
            }
            (SOL_SOCKET, SO_TYPE) => write_u32(buf, self.kind),
            // SO_PEERCRED → struct ucred { pid_t pid; uid_t uid; gid_t gid; }
            // (12 bytes). NARF has no real user model and doesn't track per-
            // socket peer credentials yet, so report a synthetic root ucred.
            // libwayland's wl_client_create queries this for client identity
            // and only stores it (no validation) — enough for the handshake.
            (SOL_SOCKET, SO_PEERCRED) => {
                if buf.len() < 12 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                buf[0..4].copy_from_slice(&1u32.to_ne_bytes()); // pid
                buf[4..8].copy_from_slice(&0u32.to_ne_bytes()); // uid (root)
                buf[8..12].copy_from_slice(&0u32.to_ne_bytes()); // gid (root)
                SocketOpResult::OptValue { n: 12 }
            }
            (SOL_SOCKET, SO_DOMAIN) => write_u32(buf, self.domain as u32),
            (SOL_SOCKET, SO_PROTOCOL) => write_u32(buf, self.protocol),
            (IPPROTO_TCP, TCP_NODELAY) => write_bool(buf, opts.tcp_nodelay),
            (IPPROTO_TCP, TCP_KEEPIDLE) => write_u32(buf, opts.tcp_keepidle),
            (IPPROTO_TCP, TCP_KEEPINTVL) => write_u32(buf, opts.tcp_keepintvl),
            (IPPROTO_TCP, TCP_KEEPCNT) => write_u32(buf, opts.tcp_keepcnt),
            (IPPROTO_TCP, TCP_USER_TIMEOUT) => write_u32(buf, opts.tcp_user_timeout),
            (IPPROTO_TCP, TCP_MAXSEG) => write_u32(buf, opts.tcp_maxseg),
            (IPPROTO_TCP, TCP_CORK) => write_bool(buf, opts.tcp_cork),
            (IPPROTO_TCP, TCP_QUICKACK) => write_bool(buf, opts.tcp_quickack),
            (IPPROTO_TCP, TCP_CONGESTION) => {
                let bytes = opts.tcp_congestion.as_bytes();
                let n = core::cmp::min(buf.len(), bytes.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                SocketOpResult::OptValue { n }
            }
            (IPPROTO_IP, IP_TTL) => write_u32(buf, opts.ip_ttl),
            (IPPROTO_IP, IP_TOS) => write_u32(buf, opts.ip_tos),
            (IPPROTO_IP, IP_PKTINFO) => write_bool(buf, opts.ip_pktinfo),
            (IPPROTO_IP, IP_RECVTTL) => write_bool(buf, opts.ip_recvttl),
            (IPPROTO_IP, IP_MTU) => write_u32(buf, opts.ip_mtu),
            (IPPROTO_IP, IP_MULTICAST_TTL) => write_u32(buf, opts.ip_multicast_ttl),
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    /// AF_INET SOCK_RAW dispatcher. Stage-1: bind/connect records
    /// the local/remote; send for IPPROTO_ICMP loops bytes back
    /// into the local inbox so a paired `recvfrom` returns them.
    /// The kernel raw IP path lands when `narf_net::raw_sock`
    /// wires into the iface RX dispatcher.
    fn dispatch_inet_raw(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => {
                let (ip, _port) = match parse_sockaddr_in(&addr) {
                    Some(v) => v,
                    None => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let mut state = self.state.lock();
                if let SocketState::InetRaw { local_addr, .. } = &mut *state {
                    *local_addr = ip;
                    SocketOpResult::Ok(0)
                } else {
                    SocketOpResult::Err(SockError::InvalidArg)
                }
            }
            SocketOp::Connect { addr } => {
                let (ip, port) = match parse_sockaddr_in(&addr) {
                    Some(v) => v,
                    None => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let mut state = self.state.lock();
                if let SocketState::InetRaw { peer, .. } = &mut *state {
                    *peer = Some((ip, port));
                    SocketOpResult::Ok(0)
                } else {
                    SocketOpResult::Err(SockError::InvalidArg)
                }
            }
            SocketOp::Send {
                buf,
                flags: _,
                addr,
            } => {
                let state = self.state.lock();
                let (protocol, dest) = match &*state {
                    SocketState::InetRaw { protocol, peer, .. } => {
                        let dest = if let Some(a) = addr {
                            match parse_sockaddr_in(&a) {
                                Some(v) => v,
                                None => return SocketOpResult::Err(SockError::InvalidArg),
                            }
                        } else if let Some(d) = peer {
                            *d
                        } else {
                            return SocketOpResult::Err(SockError::InvalidArg);
                        };
                        (*protocol, dest)
                    }
                    _ => return SocketOpResult::Err(SockError::InvalidArg),
                };
                drop(state);
                if protocol == IPPROTO_ICMP {
                    return self.deliver_icmp_loopback(buf, dest);
                }
                SocketOpResult::Ok(buf.len() as u64)
            }
            SocketOp::Recv { buf, flags: _ } => {
                let mut state = self.state.lock();
                if let SocketState::InetRaw { inbox, .. } = &mut *state {
                    if let Some(pkt) = inbox.pop_front() {
                        let n = core::cmp::min(buf.len(), pkt.payload.len());
                        buf[..n].copy_from_slice(&pkt.payload[..n]);
                        let peer = make_sockaddr_in(pkt.peer_addr, pkt.peer_port);
                        return SocketOpResult::Received {
                            n,
                            peer: Some(peer),
                        };
                    }
                    return SocketOpResult::Err(SockError::WouldBlock);
                }
                SocketOpResult::Err(SockError::NotConnected)
            }
            SocketOp::Shutdown { .. } => SocketOpResult::Ok(0),
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    /// Loopback ICMP echo: pushes the payload to our own inbox so
    /// a paired `recvfrom` returns the same bytes. Minimal moral
    /// equivalent of the in-kernel ICMP path.
    fn deliver_icmp_loopback(&self, buf: &[u8], dest: (u32, u16)) -> SocketOpResult {
        let mut state = self.state.lock();
        if let SocketState::InetRaw { inbox, .. } = &mut *state {
            inbox.push_back(DgramPacket {
                peer_unix: None,
                peer_addr: dest.0,
                peer_port: dest.1,
                payload: buf.to_vec(),
            });
            return SocketOpResult::Ok(buf.len() as u64);
        }
        SocketOpResult::Err(SockError::InvalidArg)
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
                    SocketState::UnixListener {
                        path, backlog: b, ..
                    } => {
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
                            SocketOpResult::Accepted {
                                socket: s,
                                peer: None,
                            }
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
                    listeners.as_ref().and_then(|m| m.get(&path).cloned())
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
                // Wake a server parked in poll/accept on the listener so it
                // accepts the new connection immediately (not on a fallback
                // timer). notify(0) wakes AND bumps the readiness generation, so
                // a server blocked in accept/epoll_wait with an INFINITE timeout
                // (deadline never passes) actually breaks out of its re-park to
                // re-run the accept check — a bare wake would just re-park it
                // forever (the connection sits unaccepted; observed as weston
                // never serving an external client). See the send path above.
                narf_net::readiness::notify(0);
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
            SocketOp::Send {
                buf,
                flags,
                addr: _,
            } => match self.do_send(buf, flags, None) {
                Ok(n) => SocketOpResult::Ok(n as u64),
                Err(e) => SocketOpResult::Err(e),
            },
            SocketOp::Recv { buf, flags } => match self.do_recv(buf, flags) {
                Ok((n, peer)) => SocketOpResult::Received { n, peer },
                Err(e) => SocketOpResult::Err(e),
            },
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
            _ => SocketOpResult::Err(SockError::NotSupported),
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
                let ip =
                    u32::from_be_bytes([addr.body[2], addr.body[3], addr.body[4], addr.body[5]]);
                let mut state = self.state.lock();
                match &*state {
                    SocketState::Fresh => {
                        let key = (self.net_ns_id(), ip, port);
                        let reuseaddr = self.options.lock().reuseaddr;
                        let mut listeners = INET_LISTENERS.lock();
                        let map = listeners.get_or_insert_with(BTreeMap::new);
                        // SO_REUSEADDR (Linux): permit double-bind to
                        // the same (addr, port) when the option is
                        // set. Linux ref: net/ipv4/inet_connection_sock.c
                        // inet_csk_bind_conflict() — `reuse` short-
                        // circuits the conflict check.
                        if map.contains_key(&key) && !reuseaddr {
                            return SocketOpResult::Err(SockError::AddrInUse);
                        }
                        *state = SocketState::InetListener {
                            addr: ip,
                            port,
                            backlog: 0,
                            pending: VecDeque::new(),
                            listen_id: None,
                        };
                        SocketOpResult::Ok(0)
                    }
                    _ => SocketOpResult::Err(SockError::InvalidArg),
                }
            }
            SocketOp::Listen { backlog } => {
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::InetListener {
                        addr,
                        port,
                        backlog: b,
                        listen_id,
                        ..
                    } => {
                        *b = backlog;
                        let addr = *addr;
                        let port = *port;
                        // Non-loopback (0.0.0.0 / wired IP) binds also open a
                        // kernel-stack listener so off-box clients reach us.
                        // 127.x stays loopback-only (the INET_LISTENERS map).
                        if (addr >> 24) != 127 && listen_id.is_none() {
                            let a = addr.to_be_bytes();
                            if let Ok(id) =
                                narf_net::tcp_stack::listen(a, port, backlog.max(1) as usize)
                            {
                                *listen_id = Some(id);
                                // This task owns the listener — targeted
                                // accept-ready wakes go only to it.
                                crate::handlers::set_tcb_owner(
                                    id,
                                    crate::handlers::current_task_id(),
                                );
                            }
                        }
                        let key = (self.net_ns_id(), addr, port);
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
                // Kernel-stack listener first: pop a completed off-box
                // connection from the accept-queue (its SYN/handshake was
                // driven by tcp_stack::rx_handler) and wrap the child TCB
                // as an InetWired endpoint whose send/recv forward to the
                // stack.
                let kernel_listen_id = {
                    let state = self.state.lock();
                    match &*state {
                        SocketState::InetListener { listen_id, .. } => *listen_id,
                        _ => None,
                    }
                };
                if let Some(lid) = kernel_listen_id {
                    if let Ok(Some(child_id)) = narf_net::tcp_stack::accept(lid) {
                        let child = SocketFile::new(AF_INET, SOCK_STREAM);
                        {
                            let mut cs = child.state.lock();
                            *cs = SocketState::InetWired {
                                tcb_id: child_id,
                                peer_addr: 0,
                                peer_port: 0,
                            };
                        }
                        // The accepting task owns this connection — targeted
                        // data-ready wakes go only to it.
                        crate::handlers::set_tcb_owner(
                            child_id,
                            crate::handlers::current_task_id(),
                        );
                        return SocketOpResult::Accepted {
                            socket: child,
                            peer: None,
                        };
                    }
                }
                // Loopback pending queue.
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::InetListener { pending, .. } => {
                        if let Some(s) = pending.pop_front() {
                            SocketOpResult::Accepted {
                                socket: s,
                                peer: None,
                            }
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
                let ip =
                    u32::from_be_bytes([addr.body[2], addr.body[3], addr.body[4], addr.body[5]]);
                // Look up the listener. Loopback (127.x.x.x) and
                // 0.0.0.0 (INADDR_ANY) listeners both match.
                let listener = {
                    let ns = self.net_ns_id();
                    let listeners = INET_LISTENERS.lock();
                    let m = listeners.as_ref();
                    m.and_then(|m| {
                        m.get(&(ns, ip, port))
                            .or_else(|| m.get(&(ns, 0, port)))
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
            SocketOp::Send {
                buf,
                flags,
                addr: _,
            } => match self.do_send(buf, flags, None) {
                Ok(n) => SocketOpResult::Ok(n as u64),
                Err(e) => SocketOpResult::Err(e),
            },
            SocketOp::Recv { buf, flags } => match self.do_recv(buf, flags) {
                Ok((n, peer)) => SocketOpResult::Received { n, peer },
                Err(e) => SocketOpResult::Err(e),
            },
            SocketOp::Shutdown { how } => {
                let state = self.state.lock();
                match &*state {
                    SocketState::InetConnected { tx, rx, .. } => {
                        if how == SHUT_WR || how == SHUT_RDWR {
                            tx.close();
                        }
                        if how == SHUT_RD || how == SHUT_RDWR {
                            rx.close();
                        }
                        SocketOpResult::Ok(0)
                    }
                    SocketState::InetWired { tcb_id, .. } => {
                        // The kernel TCP stack doesn't expose a
                        // half-close path yet. SHUT_RDWR sends a
                        // FIN via tcp_stack::close.
                        if how == SHUT_RDWR {
                            let _ = narf_net::tcp_stack::close(*tcb_id);
                        }
                        SocketOpResult::Ok(0)
                    }
                    _ => SocketOpResult::Err(SockError::NotConnected),
                }
            }
            _ => SocketOpResult::Err(SockError::NotSupported),
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
                let ip =
                    u32::from_be_bytes([addr.body[2], addr.body[3], addr.body[4], addr.body[5]]);
                let mut state = self.state.lock();
                match &*state {
                    SocketState::Fresh => {
                        let ns = self.net_ns_id();
                        let reuseaddr = self.options.lock().reuseaddr;
                        let mut bound = INET_DGRAM_BOUND.lock();
                        let map = bound.get_or_insert_with(BTreeMap::new);
                        if map.contains_key(&(ns, ip, port)) && !reuseaddr {
                            return SocketOpResult::Err(SockError::AddrInUse);
                        }
                        *state = SocketState::InetDgram {
                            local_addr: ip,
                            local_port: port,
                            inbox: VecDeque::new(),
                            peer: None,
                        };
                        map.insert((ns, ip, port), self.clone());
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
                let ip =
                    u32::from_be_bytes([addr.body[2], addr.body[3], addr.body[4], addr.body[5]]);
                let mut state = self.state.lock();
                // If unbound, auto-bind to (0, ephemeral-port).
                // RFC 6056 §3.2 Algorithm 1, IANA dynamic range.
                if matches!(&*state, SocketState::Fresh) {
                    let local_port = match crate::ephemeral_port::alloc(
                        AF_INET,
                        0,
                        crate::ephemeral_port::SocketProto::Udp,
                    ) {
                        Some(p) => p,
                        None => return SocketOpResult::Err(SockError::AddrNotAvail),
                    };
                    *state = SocketState::InetDgram {
                        local_addr: 0,
                        local_port,
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
            SocketOp::Send {
                buf,
                flags: _,
                addr,
            } => {
                let state = self.state.lock();
                let (local_addr, local_port, dest) = match &*state {
                    SocketState::InetDgram {
                        local_addr,
                        local_port,
                        peer,
                        ..
                    } => {
                        let dest = if let Some(a) = addr {
                            if a.body.len() < 6 {
                                return SocketOpResult::Err(SockError::InvalidArg);
                            }
                            let p = u16::from_be_bytes([a.body[0], a.body[1]]);
                            let i =
                                u32::from_be_bytes([a.body[2], a.body[3], a.body[4], a.body[5]]);
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
                // Linux net/ipv4/udp.c udp_sendmsg(): broadcast sends
                // require SO_BROADCAST. Without it, sendto to
                // 255.255.255.255 returns EACCES. We model the same.
                if dest.0 == 0xFFFF_FFFF && !self.options.lock().broadcast {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                // Find the destination socket. Loopback + INADDR_ANY both
                // match, scoped to THIS socket's net-ns (in-process
                // loopback never crosses a netns boundary).
                let dest_sock = {
                    let ns = self.net_ns_id();
                    let bound = INET_DGRAM_BOUND.lock();
                    bound.as_ref().and_then(|m| {
                        m.get(&(ns, dest.0, dest.1))
                            .or_else(|| m.get(&(ns, 0, dest.1)))
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
                if let SocketState::InetDgram { inbox, peer, .. } = &mut *state {
                    let connected_peer = *peer;
                    // Connected-mode filter: when connect() was
                    // called, drop any packets from a different
                    // peer (Linux returns ECONNREFUSED on these in
                    // a separate code path; we silently skip).
                    while let Some(pkt) = inbox.pop_front() {
                        if let Some((paddr, pport)) = connected_peer {
                            if (paddr, pport) != (pkt.peer_addr, pkt.peer_port) {
                                continue;
                            }
                        }
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
            _ => SocketOpResult::Err(SockError::NotSupported),
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
            SocketOp::Send {
                buf,
                flags: _,
                addr,
            } => {
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
                            peer: Some(SockAddr {
                                family: AF_UNIX,
                                body,
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
            _ => SocketOpResult::Err(SockError::NotSupported),
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
                if let SocketState::Inet6Listener {
                    addr,
                    port,
                    backlog: b,
                    ..
                } = &mut *state
                {
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
                        SocketOpResult::Accepted {
                            socket: s,
                            peer: None,
                        }
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
            SocketOp::Send {
                buf,
                flags,
                addr: _,
            } => match self.do_send(buf, flags, None) {
                Ok(n) => SocketOpResult::Ok(n as u64),
                Err(e) => SocketOpResult::Err(e),
            },
            SocketOp::Recv { buf, flags } => match self.do_recv(buf, flags) {
                Ok((n, peer)) => SocketOpResult::Received { n, peer },
                Err(e) => SocketOpResult::Err(e),
            },
            SocketOp::Shutdown { how } => {
                let state = self.state.lock();
                if let SocketState::Inet6Connected { tx, rx, .. } = &*state {
                    if how == SHUT_WR || how == SHUT_RDWR {
                        tx.close();
                    }
                    if how == SHUT_RD || how == SHUT_RDWR {
                        rx.close();
                    }
                    SocketOpResult::Ok(0)
                } else {
                    SocketOpResult::Err(SockError::NotConnected)
                }
            }
            _ => SocketOpResult::Err(SockError::NotSupported),
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
        drop(state);
        // Wake any peer parked in poll/epoll/recv on the other end of this
        // ring. AF_UNIX (and loopback INET) sockets carry no kernel TCB, so
        // they use the untracked (key=0) wake-all fallback — without this a
        // blocked reader only re-checked on a coarse timer (~2 s/frame for a
        // Wayland client), instead of waking the instant data lands.
        //
        // Go through `readiness::notify` (not a bare `wake_io_waiters`) so the
        // notify GENERATION is bumped too: a task parked in epoll_wait(-1) /
        // poll with an INFINITE timeout (deadline = u64::MAX never passes — e.g.
        // weston's main loop) only breaks out of its re-park when the lost-wake
        // guard sees `readiness::generation()` advance. A bare wake just re-polls
        // the task, which re-parks without re-running collect_ready, so the data
        // is never collected and the peer is never served (a finite-timeout
        // dispatcher like wl_2proc's `dispatch(50)` masked this via its deadline
        // re-execute). notify(0) calls the same wake hook AND bumps the gen.
        if n > 0 {
            narf_net::readiness::notify(0);
        }
        if n == 0 && !buf.is_empty() {
            Err(SockError::WouldBlock)
        } else {
            Ok(n)
        }
    }

    fn do_recv(&self, buf: &mut [u8], _flags: u32) -> Result<(usize, Option<SockAddr>), SockError> {
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

    /// AF_UNIX `sendmsg` with an SCM_RIGHTS fd batch: writes `buf` to the
    /// stream and queues `fds` for the peer's next `recvmsg`. Only valid on
    /// a connected AF_UNIX stream socket.
    pub fn unix_sendmsg(&self, buf: &[u8], fds: Vec<Arc<dyn FileOps>>) -> Result<usize, SockError> {
        let state = self.state.lock();
        let tx = match &*state {
            SocketState::UnixConnected { tx, .. } => tx,
            _ => return Err(SockError::NotConnected),
        };
        if tx.is_closed() {
            return Err(SockError::Pipe);
        }
        let n = tx.write(buf);
        tx.write_fds(fds);
        drop(state);
        // Wake a peer parked in poll/epoll/recv on the other end — same as
        // `do_send`. An fd-passing `sendmsg` (SCM_RIGHTS) is how libseat hands a
        // compositor its DRM/input fds; without this, a client blocked in
        // `poll(-1)` on the libseat socket never learns the reply arrived and
        // stalls device setup until a coarse fallback tick. `notify` (not a bare
        // `wake_io_waiters`) also bumps the readiness generation so an
        // infinite-timeout waiter breaks its re-park via the lost-wake guard.
        narf_net::readiness::notify(0);
        Ok(n)
    }

    /// Pop the next received SCM_RIGHTS fd batch from an AF_UNIX stream
    /// socket's receive ring (empty for non-unix sockets or when none were
    /// passed).
    pub fn unix_take_recv_fds(&self) -> Vec<Arc<dyn FileOps>> {
        let state = self.state.lock();
        match &*state {
            SocketState::UnixConnected { rx, .. } => rx.take_fds().unwrap_or_default(),
            _ => Vec::new(),
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

struct RingInner {
    buf: Vec<u8>,
    head: usize,
    len: usize,
    /// AF_UNIX SCM_RIGHTS fd-passing: a FIFO of fd batches sent alongside
    /// the byte stream. Each `sendmsg` carrying SCM_RIGHTS pushes one
    /// batch; each `recvmsg` that returns data pops the front batch and
    /// installs the file objects into the receiver's fd table. Wayland's
    /// shm/dma-buf buffer sharing rides on this.
    fds: VecDeque<Vec<Arc<dyn FileOps>>>,
}

impl core::fmt::Debug for RingInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RingInner")
            .field("head", &self.head)
            .field("len", &self.len)
            .field("fd_batches", &self.fds.len())
            .finish()
    }
}

impl RingBuf {
    fn new() -> Self {
        Self {
            inner: IrqSafeSpinLock::new(RingInner {
                buf: alloc::vec![0u8; RING_CAP],
                head: 0,
                len: 0,
                fds: VecDeque::new(),
            }),
            closed: AtomicBool::new(false),
        }
    }

    /// Queue an SCM_RIGHTS fd batch alongside the byte stream.
    fn write_fds(&self, fds: Vec<Arc<dyn FileOps>>) {
        if !fds.is_empty() {
            self.inner.lock().fds.push_back(fds);
        }
    }

    /// Pop the next queued fd batch (FIFO), if any.
    fn take_fds(&self) -> Option<Vec<Arc<dyn FileOps>>> {
        self.inner.lock().fds.pop_front()
    }

    fn write(&self, src: &[u8]) -> usize {
        let mut g = self.inner.lock();
        let avail = RING_CAP - g.len;
        let n = core::cmp::min(src.len(), avail);
        for (i, &byte) in src.iter().enumerate().take(n) {
            let pos = (g.head + g.len + i) % RING_CAP;
            g.buf[pos] = byte;
        }
        g.len += n;
        n
    }

    fn read(&self, dst: &mut [u8]) -> usize {
        let mut g = self.inner.lock();
        let n = core::cmp::min(dst.len(), g.len);
        for (i, slot) in dst.iter_mut().enumerate().take(n) {
            let pos = (g.head + i) % RING_CAP;
            *slot = g.buf[pos];
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

/// Registry map keyed by AF_INET (net_ns_id, ipv4, port). The leading
/// net-ns id scopes bind/port allocation so two processes in different
/// network namespaces can both bind the same (addr, port); the host
/// default netns is id 0. Loopback delivery looks up with the sender's
/// own ns id, so in-process datagrams never cross a netns boundary.
type Inet4Map = BTreeMap<(u64, u32, u16), Arc<SocketFile>>;
/// Registry map keyed by AF_INET6 (ipv6, port).
type Inet6Map = BTreeMap<([u8; 16], u16), Arc<SocketFile>>;

static LISTENERS: IrqSafeSpinLock<Option<BTreeMap<String, Arc<SocketFile>>>> =
    IrqSafeSpinLock::new(None);

/// Release a bound AF_UNIX pathname from the stream + dgram registries so
/// the address can be re-bound. Called by `unlink(2)` on a socket path —
/// dbus/wayland `unlink()` a stale socket before re-`bind()`-ing it, and
/// in Linux removing the socket inode frees the address. Returns true if
/// an entry was actually removed (the path was a live bound socket).
pub fn unbind_path(path: &str) -> bool {
    let mut removed = false;
    if let Some(map) = LISTENERS.lock().as_mut() {
        removed |= map.remove(path).is_some();
    }
    if let Some(map) = UNIX_DGRAM_BOUND.lock().as_mut() {
        removed |= map.remove(path).is_some();
    }
    removed
}

/// AF_INET listener registry keyed by (ip, port). Loopback only
/// today; non-loopback addrs are accepted at bind() but no
/// connect path serves them until the NIC TX side wires in.
static INET_LISTENERS: IrqSafeSpinLock<Option<Inet4Map>> = IrqSafeSpinLock::new(None);

/// AF_INET6 listener registry keyed by (ipv6, port). Same loopback-
/// only constraint as INET_LISTENERS.
static INET6_LISTENERS: IrqSafeSpinLock<Option<Inet6Map>> = IrqSafeSpinLock::new(None);

/// AF_INET datagram-bound registry: (ip, port) → socket. Lookup
/// from sendto's destination + delivery into the dest's inbox.
static INET_DGRAM_BOUND: IrqSafeSpinLock<Option<Inet4Map>> = IrqSafeSpinLock::new(None);

/// AF_UNIX datagram-bound registry: path → socket.
static UNIX_DGRAM_BOUND: IrqSafeSpinLock<Option<BTreeMap<String, Arc<SocketFile>>>> =
    IrqSafeSpinLock::new(None);

// ── ZC fast-path: registered buffer pool ────────────────────────

static REGISTERED_BUFS: IrqSafeSpinLock<Option<BTreeMap<u32, RegBuf>>> = IrqSafeSpinLock::new(None);
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
    map.insert(
        id,
        RegBuf {
            base: ptr,
            len,
            owner,
        },
    );
    Some(id)
}

pub fn registered_buffer_slice(owner: u64, buf_id: u32, off: u64, len: u64) -> Option<(u64, u64)> {
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
