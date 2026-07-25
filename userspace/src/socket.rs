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
use alloc::sync::{Arc, Weak};
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
/// Linux `AF_NETLINK`. We implement route + uevent as first-class protocols
/// and back every other family (audit / generic / netfilter / …) with a
/// coherent no-op sink so a `socket(AF_NETLINK, …)` never fails.
pub const AF_NETLINK: u16 = 16;
/// `SOL_NETLINK` — the get/setsockopt level for netlink-specific options
/// (NETLINK_ADD_MEMBERSHIP, NETLINK_EXT_ACK, NETLINK_GET_STRICT_CHK, …).
/// sd-netlink sets a handful of these best-effort right after `socket()`.
pub const SOL_NETLINK: u32 = 270;
pub const NETLINK_ADD_MEMBERSHIP: u32 = 1;
pub const NETLINK_DROP_MEMBERSHIP: u32 = 2;
pub const NETLINK_PKTINFO: u32 = 3;
pub const NETLINK_BROADCAST_ERROR: u32 = 4;
pub const NETLINK_NO_ENOBUFS: u32 = 5;
pub const NETLINK_CAP_ACK: u32 = 10;
pub const NETLINK_EXT_ACK: u32 = 11;
pub const NETLINK_GET_STRICT_CHK: u32 = 12;
/// `NETLINK_ROUTE` (rtnetlink) — the interface/address/route dump protocol.
/// systemd-udevd, systemd-networkd, and `ip link`/`ip addr` open
/// `socket(AF_NETLINK, SOCK_RAW, 0)` and send RTM_GETLINK/RTM_GETADDR dump
/// requests; we answer them from `narf_net::netlink_route::build_dump`.
pub const NETLINK_ROUTE: u32 = 0;
/// `NETLINK_SOCK_DIAG` — Linux socket-table diagnostics used by `ss`.
/// IPv4 TCP and UDP dumps are sourced from the kernel stack snapshots.
pub const NETLINK_SOCK_DIAG: u32 = 4;
/// `NETLINK_AUDIT` — the kernel audit protocol. systemd PID 1's audit setup
/// opens `socket(AF_NETLINK, SOCK_RAW, 9)`; we back it with the no-op sink
/// (audit is disabled — messages are accepted and silently dropped).
pub const NETLINK_AUDIT: u32 = 9;
/// `NETLINK_NETFILTER` — read-only nfnetlink conntrack dumps.
pub const NETLINK_NETFILTER: u32 = 12;
/// `NETLINK_KOBJECT_UEVENT` — the udev hotplug-monitor netlink protocol.
/// libudev opens `socket(AF_NETLINK, SOCK_DGRAM|SOCK_RAW, 15)` and reads
/// device-uevent messages off it; we bridge it to the kernel uevent ring.
pub const NETLINK_KOBJECT_UEVENT: u32 = 15;
/// `NETLINK_GENERIC` (genetlink) — the family-multiplexing protocol used by
/// nl80211, taskstats, thermal, etc. Backed by the sink. Note the numeric
/// value coincides with `AF_NETLINK` (16); they occupy different arg slots.
pub const NETLINK_GENERIC: u32 = 16;

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

/// `ioctl(fd, SIOCINQ, &int)` — bytes immediately readable. On Linux the
/// value is shared with `FIONREAD`/`TIOCINQ` (0x541B). For a datagram
/// socket it reports the size of the *next* pending datagram (0 when the
/// queue is empty); for a stream socket, the total buffered bytes. systemd
/// PID 1 issues this on its `$NOTIFY_SOCKET` AF_UNIX/SOCK_DGRAM socket to
/// size the read of a pending notification.
pub const SIOCINQ: u32 = 0x541B;

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
/// `SO_PASSCRED` — when set, `recvmsg` attaches an `SCM_CREDENTIALS`
/// ancillary message naming the sending peer's (pid, uid, gid).
pub const SO_PASSCRED: u32 = 16;
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
pub const MSG_PEEK: u32 = 0x02;
pub const MSG_TRUNC: u32 = 0x20;

// ── Address shape ───────────────────────────────────────────────

/// Wire-stable address. POSIX sockaddr_* unions translate to/from
/// this shape libc-side; the kernel only deals with `(family, body)`.
/// Body length is up to 108 bytes (matches Unix sun_path max).
#[derive(Clone, Debug)]
pub struct SockAddr {
    pub family: u16,
    pub body: Vec<u8>,
}

/// Peer/local credentials attached to a socket end. Mirrors Linux
/// `struct ucred { pid_t pid; uid_t uid; gid_t gid; }`. Stamped at
/// socket() creation from the creating task and copied to the peer
/// end on connect/accept so `SO_PEERCRED` and `SCM_CREDENTIALS`
/// report the real identity of the process on the other side.
// The all-zero default (pid 0 / root) is the identity an unstamped socket
// reads back — matching the synthetic ucred NARF reported before per-socket
// credential tracking.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Ucred {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// A parsed AF_UNIX destination. Linux keys three distinct address
/// shapes off the `sockaddr_un` layout:
/// - `Path` — a NUL-terminated pathname in `sun_path`; a filesystem
///   node backs it.
/// - `Abstract` — `sun_path[0] == '\0'`; the key is the bytes after
///   the leading NUL up to `addrlen`, living ONLY in the in-kernel
///   abstract-namespace registry (no filesystem node).
/// - `Unnamed` — `addrlen == sizeof(sa_family_t)` (2); an autobind
///   request that mints a fresh abstract name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnixAddr {
    Path(String),
    Abstract(Vec<u8>),
    Unnamed,
}

impl UnixAddr {
    /// Parse the `body` bytes of an AF_UNIX `SockAddr` (everything after
    /// the 2-byte family). `body.len()` equals `addrlen - 2`, so an empty
    /// body is the autobind (`Unnamed`) case. A leading NUL selects the
    /// abstract namespace; otherwise the pathname is NUL-trimmed.
    pub fn parse(body: &[u8]) -> Option<Self> {
        if body.is_empty() {
            return Some(UnixAddr::Unnamed);
        }
        if body[0] == 0 {
            // Abstract: the name is the raw bytes after the leading NUL,
            // NOT NUL-trimmed (abstract names may embed NULs).
            return Some(UnixAddr::Abstract(body[1..].to_vec()));
        }
        let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
        let s = core::str::from_utf8(&body[..end]).ok()?;
        if s.is_empty() {
            return None;
        }
        Some(UnixAddr::Path(String::from(s)))
    }

    /// Encode back into `SockAddr` body bytes (abstract keeps the leading
    /// NUL; pathname is the raw bytes; unnamed is empty).
    fn to_body(&self) -> Vec<u8> {
        match self {
            UnixAddr::Path(p) => p.as_bytes().to_vec(),
            UnixAddr::Abstract(name) => {
                let mut b = Vec::with_capacity(name.len() + 1);
                b.push(0u8);
                b.extend_from_slice(name);
                b
            }
            UnixAddr::Unnamed => Vec::new(),
        }
    }
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
    /// Datagram exceeded the caller's buffer. `copied` bytes were written;
    /// `full_len` is returned only when the call requested `MSG_TRUNC`.
    ReceivedTruncated {
        copied: usize,
        full_len: usize,
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
    /// Credentials of the process that owns this socket end. Stamped by
    /// `sys_socket`/`sys_socketpair` at creation; surfaced to the peer via
    /// `SO_PEERCRED` and to a `SO_PASSCRED` recvmsg via `SCM_CREDENTIALS`.
    local_cred: IrqSafeSpinLock<Ucred>,
    /// Credentials of the connected peer. Filled in at connect()/accept()
    /// time (each end copies the other's `local_cred`). Read by
    /// `getsockopt(SO_PEERCRED)`.
    peer_cred: IrqSafeSpinLock<Ucred>,
    /// `SO_PASSCRED` — recvmsg attaches an `SCM_CREDENTIALS` cmsg when set.
    passcred: AtomicBool,
    /// Credentials of the sender of the most recently received datagram.
    /// A `SO_PASSCRED` recvmsg on a DGRAM socket reports THESE (per-message
    /// identity), whereas a stream recvmsg reports the fixed `peer_cred`.
    last_recv_cred: IrqSafeSpinLock<Ucred>,
    /// AF_NETLINK local and connected peer addresses. Port ID zero means
    /// unbound; an explicit bind with nl_pid=0 allocates a unique ID.
    netlink_portid: AtomicU32,
    netlink_groups: AtomicU32,
    netlink_peer_portid: AtomicU32,
    netlink_peer_groups: AtomicU32,
    netlink_pktinfo: AtomicBool,
    netlink_broadcast_error: AtomicBool,
    netlink_no_enobufs: AtomicBool,
    netlink_cap_ack: AtomicBool,
    netlink_ext_ack: AtomicBool,
    netlink_strict_check: AtomicBool,
    /// Explicitly delegated NARF network-control authority. Never inferred
    /// from uid or Linux ambient capability bits.
    netlink_admin: IrqSafeSpinLock<Option<narf_net::AdminHandle>>,
    /// Userspace-to-userspace unicast datagrams, independent of each
    /// protocol's kernel reply queue so sender port IDs remain attributable.
    netlink_user_inbox: IrqSafeSpinLock<VecDeque<NetlinkUserPacket>>,
}

static NEXT_NETLINK_PORTID: AtomicU32 = AtomicU32::new(1);
static NETLINK_SOCKETS: IrqSafeSpinLock<Vec<Weak<SocketFile>>> = IrqSafeSpinLock::new(Vec::new());

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
    /// AF_UNIX bound listener at the named address (pathname or abstract).
    UnixListener {
        addr: UnixAddr,
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
    /// AF_UNIX SOCK_DGRAM endpoint. Same shape as InetDgram but keyed by
    /// a unix address (pathname or abstract name).
    UnixDgram {
        addr: Option<UnixAddr>,
        inbox: VecDeque<DgramPacket>,
        peer: Option<UnixAddr>,
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
    /// `AF_NETLINK` / `NETLINK_ROUTE` (rtnetlink) dump socket. A `send` of an
    /// RTM_GET* dump request builds the reply message stream via
    /// `narf_net::netlink_route::build_dump` and queues each message here;
    /// `recv` dequeues one message per call (the kernel dumps stream over
    /// netlink as one datagram per message, terminated by NLMSG_DONE).
    NetlinkRoute { replies: VecDeque<Vec<u8>> },
    /// `AF_NETLINK` for a protocol NARF does not model (NETLINK_AUDIT,
    /// NETLINK_GENERIC, NETLINK_NETFILTER, …). A coherent no-op sink: `bind`,
    /// `connect`, and `send` succeed (messages are dropped — audit/netfilter
    /// are disabled), `recv` reports empty (WouldBlock). This lets
    /// best-effort openers (systemd PID 1's audit setup) get a usable fd and
    /// proceed instead of failing the socket open with EPERM.
    NetlinkSink,
    /// `NETLINK_GENERIC` control-family socket. Requests to `nlctrl` queue
    /// generic-netlink family discovery replies here.
    NetlinkGeneric { replies: VecDeque<Vec<u8>> },
    /// `NETLINK_SOCK_DIAG` response queue for `inet_diag_req_v2` dumps.
    NetlinkSockDiag { replies: VecDeque<Vec<u8>> },
    /// `NETLINK_NETFILTER` response queue for nfnetlink conntrack dumps.
    NetlinkNetfilter { replies: VecDeque<Vec<u8>> },
}

/// One enqueued UDP-style datagram. Owns the payload bytes (UDP
/// has no concept of partial reads — each recv yields one whole
/// packet, padded or truncated to the user buffer size).
#[derive(Debug)]
pub struct DgramPacket {
    /// Source AF_UNIX address (pathname or abstract), if the sender was
    /// bound. `None` for an unbound sender or an AF_INET datagram.
    pub peer_unix: Option<UnixAddr>,
    /// Sender credentials, attached to recvmsg as SCM_CREDENTIALS when the
    /// receiver set SO_PASSCRED. Enables sd_notify's per-message identity.
    pub sender_cred: Ucred,
    pub peer_addr: u32,
    pub peer_port: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
struct NetlinkUserPacket {
    payload: Vec<u8>,
    sender_portid: u32,
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
        } else if domain == AF_NETLINK && protocol == NETLINK_ROUTE {
            // rtnetlink dump socket: replies are built on-demand from a
            // send(RTM_GET*) request, so start with an empty reply queue.
            SocketState::NetlinkRoute {
                replies: VecDeque::new(),
            }
        } else if domain == AF_NETLINK && protocol == NETLINK_GENERIC {
            SocketState::NetlinkGeneric {
                replies: VecDeque::new(),
            }
        } else if domain == AF_NETLINK && protocol == NETLINK_SOCK_DIAG {
            SocketState::NetlinkSockDiag {
                replies: VecDeque::new(),
            }
        } else if domain == AF_NETLINK && protocol == NETLINK_NETFILTER {
            SocketState::NetlinkNetfilter {
                replies: VecDeque::new(),
            }
        } else if domain == AF_NETLINK && protocol != NETLINK_KOBJECT_UEVENT {
            // Any AF_NETLINK protocol NARF does not model as route/generic/uevent
            // (NETLINK_AUDIT=9, NETLINK_NETFILTER=12, …) →
            // a coherent no-op sink. systemd PID 1 opens NETLINK_AUDIT during
            // manager setup; a hard failure here surfaced to userspace as the
            // -1 sentinel (glibc errno=EPERM) → "Failed to open netlink,
            // ignoring: Operation not permitted". The sink returns a usable fd.
            SocketState::NetlinkSink
        } else if domain == AF_NETLINK {
            // NETLINK_KOBJECT_UEVENT → the udev hotplug monitor. Wire the
            // post-emit wake so a uevent emitted
            // while this monitor is parked in poll/epoll wakes it (the ring
            // lives in the fs crate, which can't reach the net readiness layer
            // directly). Idempotent — a plain atomic store.
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
        let socket = Arc::new(Self {
            domain,
            kind,
            protocol,
            state: IrqSafeSpinLock::new(state),
            options: IrqSafeSpinLock::new(SockOptions::default()),
            nonblock: AtomicBool::new(false),
            pending_error: IrqSafeSpinLock::new(None),
            net_ns_id: core::sync::atomic::AtomicU64::new(0),
            local_cred: IrqSafeSpinLock::new(Ucred::default()),
            peer_cred: IrqSafeSpinLock::new(Ucred::default()),
            passcred: AtomicBool::new(false),
            last_recv_cred: IrqSafeSpinLock::new(Ucred::default()),
            netlink_portid: AtomicU32::new(0),
            netlink_groups: AtomicU32::new(0),
            netlink_peer_portid: AtomicU32::new(0),
            netlink_peer_groups: AtomicU32::new(0),
            netlink_pktinfo: AtomicBool::new(false),
            netlink_broadcast_error: AtomicBool::new(false),
            netlink_no_enobufs: AtomicBool::new(false),
            netlink_cap_ack: AtomicBool::new(false),
            netlink_ext_ack: AtomicBool::new(false),
            netlink_strict_check: AtomicBool::new(false),
            netlink_admin: IrqSafeSpinLock::new(None),
            netlink_user_inbox: IrqSafeSpinLock::new(VecDeque::new()),
        });
        if domain == AF_NETLINK {
            NETLINK_SOCKETS.lock().push(Arc::downgrade(&socket));
        }
        socket
    }

    pub fn delegate_netlink_admin(&self, admin: narf_net::AdminHandle) -> Result<(), SockError> {
        if self.domain != AF_NETLINK || self.protocol != NETLINK_ROUTE {
            return Err(SockError::InvalidArg);
        }
        admin.check_live().map_err(|_| SockError::InvalidArg)?;
        *self.netlink_admin.lock() = Some(admin);
        Ok(())
    }

    #[doc(hidden)]
    pub fn __test_has_netlink_admin(&self) -> bool {
        self.netlink_admin.lock().is_some()
    }

    fn broadcast_netlink_route(group: u32, message: &[u8]) {
        let mut sockets = NETLINK_SOCKETS.lock();
        sockets.retain(|weak| {
            let Some(socket) = weak.upgrade() else {
                return false;
            };
            if socket.protocol != NETLINK_ROUTE
                || socket.netlink_groups.load(Ordering::Acquire) & group == 0
            {
                return true;
            }
            if let SocketState::NetlinkRoute { replies } = &mut *socket.state.lock() {
                replies.push_back(message.to_vec());
            }
            true
        });
        drop(sockets);
        narf_net::readiness::notify(0);
    }

    fn netlink_addr(addr: &SockAddr) -> Option<(u32, u32)> {
        if addr.family != AF_NETLINK || addr.body.len() < 10 {
            return None;
        }
        let pid = u32::from_ne_bytes(addr.body[2..6].try_into().ok()?);
        let groups = u32::from_ne_bytes(addr.body[6..10].try_into().ok()?);
        Some((pid, groups))
    }

    fn netlink_sockaddr(portid: u32, groups: u32) -> SockAddr {
        let mut body = alloc::vec![0u8; 10];
        body[2..6].copy_from_slice(&portid.to_ne_bytes());
        body[6..10].copy_from_slice(&groups.to_ne_bytes());
        SockAddr {
            family: AF_NETLINK,
            body,
        }
    }

    fn ensure_netlink_portid(&self) -> u32 {
        let current = self.netlink_portid.load(Ordering::Acquire);
        if current != 0 {
            return current;
        }
        let allocated = loop {
            let candidate = NEXT_NETLINK_PORTID.fetch_add(1, Ordering::Relaxed).max(1);
            if !self.netlink_port_in_use(candidate) {
                break candidate;
            }
        };
        match self.netlink_portid.compare_exchange(
            0,
            allocated,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => allocated,
            Err(existing) => existing,
        }
    }

    fn netlink_port_in_use(&self, portid: u32) -> bool {
        let mut sockets = NETLINK_SOCKETS.lock();
        sockets.retain(|weak| weak.strong_count() != 0);
        sockets.iter().filter_map(Weak::upgrade).any(|socket| {
            !core::ptr::eq(Arc::as_ptr(&socket), self)
                && socket.protocol == self.protocol
                && socket.netlink_portid.load(Ordering::Acquire) == portid
        })
    }

    fn bind_netlink(&self, addr: &SockAddr) -> SocketOpResult {
        let (requested, groups) = match Self::netlink_addr(addr) {
            Some(v) => v,
            None => return SocketOpResult::Err(SockError::InvalidArg),
        };
        if self.netlink_portid.load(Ordering::Acquire) != 0 {
            return SocketOpResult::Err(SockError::InvalidArg);
        }
        let portid = if requested == 0 {
            loop {
                let candidate = NEXT_NETLINK_PORTID.fetch_add(1, Ordering::Relaxed).max(1);
                if !self.netlink_port_in_use(candidate) {
                    break candidate;
                }
            }
        } else {
            if self.netlink_port_in_use(requested) {
                return SocketOpResult::Err(SockError::AddrInUse);
            }
            requested
        };
        self.netlink_portid.store(portid, Ordering::Release);
        self.netlink_groups.store(groups, Ordering::Release);
        SocketOpResult::Ok(0)
    }

    /// Deliver a send addressed to a userspace netlink port. `None` means the
    /// destination is the kernel endpoint and protocol dispatch should proceed.
    fn send_netlink_user(&self, buf: &[u8], explicit: Option<&SockAddr>) -> Option<SocketOpResult> {
        let destination = explicit.and_then(Self::netlink_addr).unwrap_or_else(|| {
            (
                self.netlink_peer_portid.load(Ordering::Acquire),
                self.netlink_peer_groups.load(Ordering::Acquire),
            )
        });
        if destination == (0, 0) {
            return None;
        }
        // Userspace multicast requires authority NARF does not grant through
        // uid/capability emulation. Kernel-originated protocol notifications
        // continue to use their dedicated broadcast paths.
        if destination.1 != 0 {
            return Some(SocketOpResult::Err(SockError::NotSupported));
        }
        let sender = self.ensure_netlink_portid();
        let mut sockets = NETLINK_SOCKETS.lock();
        sockets.retain(|weak| weak.strong_count() != 0);
        let target = sockets.iter().filter_map(Weak::upgrade).find(|socket| {
            socket.protocol == self.protocol
                && socket.netlink_portid.load(Ordering::Acquire) == destination.0
        });
        let Some(target) = target else {
            return Some(SocketOpResult::Err(SockError::ConnectionRefused));
        };
        target
            .netlink_user_inbox
            .lock()
            .push_back(NetlinkUserPacket {
                payload: buf.to_vec(),
                sender_portid: sender,
            });
        drop(sockets);
        narf_net::readiness::notify(0);
        Some(SocketOpResult::Ok(buf.len() as u64))
    }

    fn recv_netlink_user(&self, buf: &mut [u8], flags: u32) -> Option<SocketOpResult> {
        let packet = {
            let mut inbox = self.netlink_user_inbox.lock();
            if flags & MSG_PEEK != 0 {
                inbox.front().map(|packet| NetlinkUserPacket {
                    payload: packet.payload.clone(),
                    sender_portid: packet.sender_portid,
                })
            } else {
                inbox.pop_front()
            }
        }?;
        let n = buf.len().min(packet.payload.len());
        buf[..n].copy_from_slice(&packet.payload[..n]);
        let peer = Some(Self::netlink_sockaddr(packet.sender_portid, 0));
        Some(if n < packet.payload.len() {
            SocketOpResult::ReceivedTruncated {
                copied: n,
                full_len: packet.payload.len(),
                peer,
            }
        } else {
            SocketOpResult::Received { n, peer }
        })
    }

    fn connect_netlink(&self, addr: &SockAddr) -> SocketOpResult {
        let (portid, groups) = match Self::netlink_addr(addr) {
            Some(v) => v,
            None => return SocketOpResult::Err(SockError::InvalidArg),
        };
        self.ensure_netlink_portid();
        self.netlink_peer_portid.store(portid, Ordering::Release);
        self.netlink_peer_groups.store(groups, Ordering::Release);
        SocketOpResult::Ok(0)
    }

    /// Stamp this socket end's owning credentials (see `local_cred`).
    /// Called by `sys_socket`/`sys_socketpair` right after creation.
    pub fn set_local_cred(&self, cred: Ucred) {
        *self.local_cred.lock() = cred;
    }

    /// This socket end's owning credentials.
    pub fn local_cred(&self) -> Ucred {
        *self.local_cred.lock()
    }

    /// The connected peer's credentials (SO_PEERCRED source).
    pub fn peer_cred(&self) -> Ucred {
        *self.peer_cred.lock()
    }

    fn set_peer_cred(&self, cred: Ucred) {
        *self.peer_cred.lock() = cred;
    }

    /// Whether `SO_PASSCRED` is enabled — recvmsg attaches SCM_CREDENTIALS.
    pub fn passcred(&self) -> bool {
        self.passcred.load(Ordering::Acquire)
    }

    /// Credentials to attach to the current recvmsg's `SCM_CREDENTIALS`
    /// ancillary message. DGRAM sockets report the sender of the most
    /// recently received datagram; connected (stream) sockets report the
    /// fixed peer credentials.
    pub fn recvmsg_cred(&self) -> Ucred {
        if self.kind == SOCK_DGRAM {
            *self.last_recv_cred.lock()
        } else {
            *self.peer_cred.lock()
        }
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

    /// Cross-wire two connected ends' peer credentials. Both ends of a
    /// `socketpair` (and the two halves of a `connect`/`accept`) belong to
    /// the same or cooperating processes; each end's `SO_PEERCRED` should
    /// report the OTHER end's owning identity.
    pub fn cross_peer_creds(a: &Arc<Self>, b: &Arc<Self>) {
        let ca = a.local_cred();
        let cb = b.local_cred();
        a.set_peer_cred(cb);
        b.set_peer_cred(ca);
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
            SocketState::UnixListener { addr, .. } => Some(SockAddr {
                family: AF_UNIX,
                body: addr.to_body(),
            }),
            SocketState::UnixDgram { addr: Some(a), .. } => Some(SockAddr {
                family: AF_UNIX,
                body: a.to_body(),
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
                body: p.to_body(),
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
            AbstractStream(Vec<u8>),
            Inet(u32, u16),
            Inet6([u8; 16], u16),
            UnixDgram(String),
            AbstractDgram(Vec<u8>),
            InetDgram(u32, u16),
            Tcb(u32),
            None,
        }
        let reg = {
            let state = self.state.lock();
            match &*state {
                SocketState::UnixListener { addr, .. } => match addr {
                    UnixAddr::Path(p) => Reg::Unix(p.clone()),
                    UnixAddr::Abstract(n) => Reg::AbstractStream(n.clone()),
                    UnixAddr::Unnamed => Reg::None,
                },
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
                SocketState::UnixDgram { addr: Some(a), .. } => match a {
                    UnixAddr::Path(p) => Reg::UnixDgram(p.clone()),
                    UnixAddr::Abstract(n) => Reg::AbstractDgram(n.clone()),
                    UnixAddr::Unnamed => Reg::None,
                },
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
            Reg::AbstractStream(n) => {
                if let Some(map) = ABSTRACT_STREAM.lock().as_mut() {
                    map.remove(&n);
                }
            }
            Reg::AbstractDgram(n) => {
                if let Some(map) = ABSTRACT_DGRAM.lock().as_mut() {
                    map.remove(&n);
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
    fn as_any(&self) -> Option<&dyn core::any::Any> {
        Some(self)
    }

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

    /// `ioctl(fd, SIOCINQ, &int)` — number of bytes immediately readable
    /// (see `inq_bytes` for the per-state count). Only `SIOCINQ` (==
    /// `FIONREAD`, 0x541B) is recognised; anything else is an unknown request
    /// → `ENOTTY` (Linux `sock_ioctl` default). An empty queue reports 0 with
    /// success (never ENOENT), which is what systemd PID 1 expects when it
    /// sizes a read of its `$NOTIFY_SOCKET` AF_UNIX/SOCK_DGRAM socket.
    fn ioctl(&self, cmd: u32, arg: usize) -> Result<u64, FsError> {
        if cmd != SIOCINQ {
            return Err(FsError::Unsupported);
        }
        let bytes = (self.inq_bytes() as i32).to_le_bytes();
        // SAFETY: `copy_to_user` validates `arg` as a user address through
        // the SMAP window; the length is the fixed 4-byte little-endian
        // `int` the SIOCINQ contract writes back.
        if unsafe { crate::handlers::copy_to_user(arg as u64, &bytes) }.is_err() {
            return Err(FsError::InvalidData);
        }
        Ok(0)
    }

    fn poll_readiness(&self) -> u32 {
        if self.domain == AF_NETLINK && !self.netlink_user_inbox.lock().is_empty() {
            return narf_filesystem::POLL_IN | narf_filesystem::POLL_OUT;
        }
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
            SocketState::NetlinkRoute { replies } => {
                // Always writable (a dump request is sendable); readable when
                // a built dump has queued reply messages waiting.
                let mut bits = narf_filesystem::POLL_OUT;
                if !replies.is_empty() {
                    bits |= narf_filesystem::POLL_IN;
                }
                bits
            }
            SocketState::NetlinkGeneric { replies } => {
                let mut bits = narf_filesystem::POLL_OUT;
                if !replies.is_empty() {
                    bits |= narf_filesystem::POLL_IN;
                }
                bits
            }
            SocketState::NetlinkSockDiag { replies } => {
                let mut bits = narf_filesystem::POLL_OUT;
                if !replies.is_empty() {
                    bits |= narf_filesystem::POLL_IN;
                }
                bits
            }
            SocketState::NetlinkNetfilter { replies } => {
                let mut bits = narf_filesystem::POLL_OUT;
                if !replies.is_empty() {
                    bits |= narf_filesystem::POLL_IN;
                }
                bits
            }
            // No-op sink (audit/netfilter/etc.): always writable (sends are
            // accepted + dropped), never readable (nothing is ever queued).
            SocketState::NetlinkSink => narf_filesystem::POLL_OUT,
        }
    }
}

impl SocketFile {
    /// Bytes immediately readable — the value the `SIOCINQ`/`FIONREAD` ioctl
    /// reports. For a datagram socket this is the size of the *next* queued
    /// datagram (0 when the queue is empty); for a connected stream socket
    /// it is the total buffered rx bytes. Every other state (fresh, listener,
    /// off-box kernel-TCP, bypass, uevent) yields 0 — no local byte count is
    /// tracked and a consumer reads 0 as "fall back to recv/MSG_PEEK".
    pub(crate) fn inq_bytes(&self) -> usize {
        if self.domain == AF_NETLINK {
            if let Some(packet) = self.netlink_user_inbox.lock().front() {
                return packet.payload.len();
            }
        }
        let state = self.state.lock();
        match &*state {
            SocketState::UnixDgram { inbox, .. }
            | SocketState::InetDgram { inbox, .. }
            | SocketState::InetRaw { inbox, .. } => {
                inbox.front().map(|p| p.payload.len()).unwrap_or(0)
            }
            SocketState::UnixConnected { rx, .. }
            | SocketState::InetConnected { rx, .. }
            | SocketState::Inet6Connected { rx, .. } => rx.len(),
            SocketState::NetlinkRoute { replies }
            | SocketState::NetlinkGeneric { replies }
            | SocketState::NetlinkSockDiag { replies }
            | SocketState::NetlinkNetfilter { replies } => {
                replies.front().map(Vec::len).unwrap_or(0)
            }
            SocketState::NetlinkUevent { reader } => reader
                .peek(1)
                .into_iter()
                .next()
                .map(|event| event.to_netlink_bytes().len())
                .unwrap_or(0),
            _ => 0,
        }
    }

    /// Per-op dispatcher. The SocketOp enum carries the operation
    /// shape; the per-family branch executes it. POSIX syscall
    /// shims and ring opcodes both call this.
    pub fn dispatch_op(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        let op = match op {
            SocketOp::Recv { buf, flags }
                if self.domain == AF_NETLINK && !self.netlink_user_inbox.lock().is_empty() =>
            {
                return self
                    .recv_netlink_user(buf, flags)
                    .unwrap_or(SocketOpResult::Err(SockError::WouldBlock));
            }
            other => other,
        };
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
                    return SocketOpResult::Addr(Self::netlink_sockaddr(
                        self.netlink_portid.load(Ordering::Acquire),
                        self.netlink_groups.load(Ordering::Acquire),
                    ));
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
                if self.domain == AF_NETLINK {
                    return SocketOpResult::Addr(Self::netlink_sockaddr(
                        self.netlink_peer_portid.load(Ordering::Acquire),
                        self.netlink_peer_groups.load(Ordering::Acquire),
                    ));
                }
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
            (AF_NETLINK, _) if self.protocol == NETLINK_ROUTE => self.dispatch_netlink_route(op),
            (AF_NETLINK, _) if self.protocol == NETLINK_GENERIC => {
                self.dispatch_netlink_generic(op)
            }
            (AF_NETLINK, _) if self.protocol == NETLINK_SOCK_DIAG => {
                self.dispatch_netlink_sock_diag(op)
            }
            (AF_NETLINK, _) if self.protocol == NETLINK_NETFILTER => {
                self.dispatch_netlink_netfilter(op)
            }
            (AF_NETLINK, _) if self.protocol != NETLINK_KOBJECT_UEVENT => {
                self.dispatch_netlink_sink(op)
            }
            (AF_NETLINK, _) => self.dispatch_netlink(op),
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    /// `AF_NETLINK` / `NETLINK_ROUTE` (rtnetlink) dispatcher. A `send` of an
    /// RTM_GET* dump request builds the reply stream via
    /// `narf_net::netlink_route::build_dump`, queues each message, and notifies
    /// readiness so a caller parked in poll/epoll wakes to read the replies.
    /// `recv` dequeues one queued message per call with a kernel `sockaddr_nl`
    /// peer (pid 0); an empty queue → WouldBlock (EAGAIN). Callers that
    /// send-then-recv on the same fd (sd-netlink, libnl) get their dump back.
    fn dispatch_netlink_route(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            // bind(sockaddr_nl{family=16, pid, groups}) — accept any.
            SocketOp::Bind { addr } => self.bind_netlink(&addr),
            SocketOp::Connect { addr } => self.connect_netlink(&addr),
            SocketOp::Send { buf, addr, .. } => {
                if let Some(result) = self.send_netlink_user(buf, addr.as_ref()) {
                    return result;
                }
                self.ensure_netlink_portid();
                let sent = buf.len() as u64;
                let admin = self.netlink_admin.lock().clone();
                let msgs = match narf_net::netlink_route::build_replies_with_options(
                    buf,
                    admin.as_ref(),
                    narf_net::netlink_route::ReplyOptions {
                        ext_ack: self.netlink_ext_ack.load(Ordering::Acquire),
                        cap_ack: self.netlink_cap_ack.load(Ordering::Acquire),
                        strict_check: self.netlink_strict_check.load(Ordering::Acquire),
                    },
                ) {
                    Ok(msgs) => msgs,
                    Err(()) => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let notifications =
                    narf_net::netlink_route::successful_mutation_notifications(buf, &msgs);
                {
                    let mut g = self.state.lock();
                    match &mut *g {
                        SocketState::NetlinkRoute { replies } => {
                            replies.extend(msgs);
                        }
                        _ => return SocketOpResult::Err(SockError::InvalidArg),
                    }
                }
                for (group, message) in notifications {
                    Self::broadcast_netlink_route(group, &message);
                }
                // Wake a reader parked in poll/epoll on the reply queue.
                narf_net::readiness::notify(0);
                SocketOpResult::Ok(sent)
            }
            SocketOp::Recv { buf, flags } => {
                let msg = {
                    let mut g = self.state.lock();
                    match &mut *g {
                        SocketState::NetlinkRoute { replies } => {
                            if flags & MSG_PEEK != 0 {
                                replies.front().cloned()
                            } else {
                                replies.pop_front()
                            }
                        }
                        _ => return SocketOpResult::Err(SockError::InvalidArg),
                    }
                };
                match msg {
                    Some(bytes) => {
                        let n = core::cmp::min(buf.len(), bytes.len());
                        buf[..n].copy_from_slice(&bytes[..n]);
                        // Sender is the kernel: sockaddr_nl{family, pid=0, groups=0}.
                        let peer = SockAddr {
                            family: AF_NETLINK,
                            body: alloc::vec![0u8; 10],
                        };
                        if n < bytes.len() {
                            SocketOpResult::ReceivedTruncated {
                                copied: n,
                                full_len: bytes.len(),
                                peer: Some(peer),
                            }
                        } else {
                            SocketOpResult::Received {
                                n,
                                peer: Some(peer),
                            }
                        }
                    }
                    None => SocketOpResult::Err(SockError::WouldBlock),
                }
            }
            SocketOp::Shutdown { how: _ } => SocketOpResult::Ok(0),
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    fn dispatch_netlink_generic(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => self.bind_netlink(&addr),
            SocketOp::Connect { addr } => self.connect_netlink(&addr),
            SocketOp::Send { buf, addr, .. } => {
                if let Some(result) = self.send_netlink_user(buf, addr.as_ref()) {
                    return result;
                }
                self.ensure_netlink_portid();
                let replies = match narf_net::netlink_generic::build_replies_with_options(
                    buf,
                    narf_net::netlink_generic::ReplyOptions {
                        ext_ack: self.netlink_ext_ack.load(Ordering::Acquire),
                        cap_ack: self.netlink_cap_ack.load(Ordering::Acquire),
                    },
                ) {
                    Ok(replies) => replies,
                    Err(()) => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::NetlinkGeneric { replies: queue } => {
                        queue.extend(replies);
                    }
                    _ => return SocketOpResult::Err(SockError::InvalidArg),
                }
                drop(state);
                narf_net::readiness::notify(0);
                SocketOpResult::Ok(buf.len() as u64)
            }
            SocketOp::Recv { buf, flags } => {
                let message = {
                    let mut state = self.state.lock();
                    match &mut *state {
                        SocketState::NetlinkGeneric { replies } => {
                            if flags & MSG_PEEK != 0 {
                                replies.front().cloned()
                            } else {
                                replies.pop_front()
                            }
                        }
                        _ => return SocketOpResult::Err(SockError::InvalidArg),
                    }
                };
                match message {
                    Some(message) => {
                        let n = buf.len().min(message.len());
                        buf[..n].copy_from_slice(&message[..n]);
                        let peer = Some(Self::netlink_sockaddr(0, 0));
                        if n < message.len() {
                            SocketOpResult::ReceivedTruncated {
                                copied: n,
                                full_len: message.len(),
                                peer,
                            }
                        } else {
                            SocketOpResult::Received { n, peer }
                        }
                    }
                    None => SocketOpResult::Err(SockError::WouldBlock),
                }
            }
            SocketOp::Shutdown { how: _ } => SocketOpResult::Ok(0),
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    fn dispatch_netlink_sock_diag(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => self.bind_netlink(&addr),
            SocketOp::Connect { addr } => self.connect_netlink(&addr),
            SocketOp::Send { buf, addr, .. } => {
                if let Some(result) = self.send_netlink_user(buf, addr.as_ref()) {
                    return result;
                }
                self.ensure_netlink_portid();
                let replies = match narf_net::netlink_diag::build_replies(buf) {
                    Ok(replies) => replies,
                    Err(()) => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::NetlinkSockDiag { replies: queue } => queue.extend(replies),
                    _ => return SocketOpResult::Err(SockError::InvalidArg),
                }
                drop(state);
                narf_net::readiness::notify(0);
                SocketOpResult::Ok(buf.len() as u64)
            }
            SocketOp::Recv { buf, flags } => {
                let message = {
                    let mut state = self.state.lock();
                    match &mut *state {
                        SocketState::NetlinkSockDiag { replies } => {
                            if flags & MSG_PEEK != 0 {
                                replies.front().cloned()
                            } else {
                                replies.pop_front()
                            }
                        }
                        _ => return SocketOpResult::Err(SockError::InvalidArg),
                    }
                };
                match message {
                    Some(message) => {
                        let n = buf.len().min(message.len());
                        buf[..n].copy_from_slice(&message[..n]);
                        let peer = Some(Self::netlink_sockaddr(0, 0));
                        if n < message.len() {
                            SocketOpResult::ReceivedTruncated {
                                copied: n,
                                full_len: message.len(),
                                peer,
                            }
                        } else {
                            SocketOpResult::Received { n, peer }
                        }
                    }
                    None => SocketOpResult::Err(SockError::WouldBlock),
                }
            }
            SocketOp::Shutdown { how: _ } => SocketOpResult::Ok(0),
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    fn dispatch_netlink_netfilter(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => self.bind_netlink(&addr),
            SocketOp::Connect { addr } => self.connect_netlink(&addr),
            SocketOp::Send { buf, addr, .. } => {
                if let Some(result) = self.send_netlink_user(buf, addr.as_ref()) {
                    return result;
                }
                self.ensure_netlink_portid();
                let replies = match narf_net::netlink_netfilter::build_replies(buf) {
                    Ok(replies) => replies,
                    Err(()) => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::NetlinkNetfilter { replies: queue } => queue.extend(replies),
                    _ => return SocketOpResult::Err(SockError::InvalidArg),
                }
                drop(state);
                narf_net::readiness::notify(0);
                SocketOpResult::Ok(buf.len() as u64)
            }
            SocketOp::Recv { buf, flags } => {
                let message = {
                    let mut state = self.state.lock();
                    match &mut *state {
                        SocketState::NetlinkNetfilter { replies } => {
                            if flags & MSG_PEEK != 0 {
                                replies.front().cloned()
                            } else {
                                replies.pop_front()
                            }
                        }
                        _ => return SocketOpResult::Err(SockError::InvalidArg),
                    }
                };
                match message {
                    Some(message) => {
                        let n = buf.len().min(message.len());
                        buf[..n].copy_from_slice(&message[..n]);
                        let peer = Some(Self::netlink_sockaddr(0, 0));
                        if n < message.len() {
                            SocketOpResult::ReceivedTruncated {
                                copied: n,
                                full_len: message.len(),
                                peer,
                            }
                        } else {
                            SocketOpResult::Received { n, peer }
                        }
                    }
                    None => SocketOpResult::Err(SockError::WouldBlock),
                }
            }
            SocketOp::Shutdown { how: _ } => SocketOpResult::Ok(0),
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
            SocketOp::Bind { addr } => self.bind_netlink(&addr),
            SocketOp::Connect { addr } => self.connect_netlink(&addr),
            // udev clients never send on the monitor; accept + discard.
            SocketOp::Send { buf, addr, .. } => {
                if let Some(result) = self.send_netlink_user(buf, addr.as_ref()) {
                    return result;
                }
                self.ensure_netlink_portid();
                SocketOpResult::Ok(buf.len() as u64)
            }
            SocketOp::Recv { buf, flags } => {
                let ev = {
                    let mut g = self.state.lock();
                    match &mut *g {
                        SocketState::NetlinkUevent { reader } => {
                            if flags & MSG_PEEK != 0 {
                                reader.peek(1).into_iter().next()
                            } else {
                                reader.drain(1).into_iter().next()
                            }
                        }
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
                        if n < bytes.len() {
                            SocketOpResult::ReceivedTruncated {
                                copied: n,
                                full_len: bytes.len(),
                                peer: Some(peer),
                            }
                        } else {
                            SocketOpResult::Received {
                                n,
                                peer: Some(peer),
                            }
                        }
                    }
                    None => SocketOpResult::Err(SockError::WouldBlock),
                }
            }
            SocketOp::Shutdown { how: _ } => SocketOpResult::Ok(0),
            _ => SocketOpResult::Err(SockError::NotSupported),
        }
    }

    /// `AF_NETLINK` no-op sink for protocols NARF does not model
    /// (NETLINK_AUDIT, NETLINK_GENERIC, NETLINK_NETFILTER, …). Every op that
    /// systemd's best-effort netlink open performs succeeds so it gets a
    /// usable fd: `bind`/`connect` return 0, `send` accepts and drops the
    /// message (audit/netfilter disabled), `recv` reports empty (WouldBlock →
    /// EAGAIN, exactly like a quiet socket). Returning a hard error here made
    /// the socket open surface as EPERM ("Failed to open netlink, ignoring").
    fn dispatch_netlink_sink(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => self.bind_netlink(&addr),
            SocketOp::Connect { addr } => self.connect_netlink(&addr),
            SocketOp::Send { buf, addr, .. } => {
                if let Some(result) = self.send_netlink_user(buf, addr.as_ref()) {
                    return result;
                }
                self.ensure_netlink_portid();
                SocketOpResult::Ok(buf.len() as u64)
            }
            SocketOp::Recv { .. } => SocketOpResult::Err(SockError::WouldBlock),
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
        if level == SOL_NETLINK {
            let value = match read_u32(value) {
                Ok(v) => v,
                Err(e) => return SocketOpResult::Err(e),
            };
            let flag = value != 0;
            match name {
                NETLINK_ADD_MEMBERSHIP | NETLINK_DROP_MEMBERSHIP => {
                    if !(1..=32).contains(&value) {
                        return SocketOpResult::Err(SockError::InvalidArg);
                    }
                    let bit = 1u32 << (value - 1);
                    if name == NETLINK_ADD_MEMBERSHIP {
                        self.netlink_groups.fetch_or(bit, Ordering::AcqRel);
                    } else {
                        self.netlink_groups.fetch_and(!bit, Ordering::AcqRel);
                    }
                }
                NETLINK_PKTINFO => self.netlink_pktinfo.store(flag, Ordering::Release),
                NETLINK_BROADCAST_ERROR => {
                    self.netlink_broadcast_error.store(flag, Ordering::Release)
                }
                NETLINK_NO_ENOBUFS => self.netlink_no_enobufs.store(flag, Ordering::Release),
                NETLINK_CAP_ACK => self.netlink_cap_ack.store(flag, Ordering::Release),
                NETLINK_EXT_ACK => self.netlink_ext_ack.store(flag, Ordering::Release),
                NETLINK_GET_STRICT_CHK => self.netlink_strict_check.store(flag, Ordering::Release),
                _ => return SocketOpResult::Err(SockError::NotSupported),
            }
            return SocketOpResult::Ok(0);
        }
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
            (SOL_SOCKET, SO_PASSCRED) => match read_u32(value) {
                Ok(v) => {
                    self.passcred.store(v != 0, Ordering::Release);
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
            (SOL_SOCKET, SO_PASSCRED) => write_bool(buf, self.passcred.load(Ordering::Acquire)),
            // SO_PEERCRED → struct ucred { pid_t pid; uid_t uid; gid_t gid; }
            // (12 bytes). Reports the connected peer's real credentials,
            // captured at connect()/accept()/socketpair() time. systemd's
            // Varlink / D-Bus / logind identify peers via SO_PEERCRED.
            (SOL_SOCKET, SO_PEERCRED) => {
                if buf.len() < 12 {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let c = self.peer_cred();
                buf[0..4].copy_from_slice(&c.pid.to_ne_bytes());
                buf[4..8].copy_from_slice(&c.uid.to_ne_bytes());
                buf[8..12].copy_from_slice(&c.gid.to_ne_bytes());
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
            (SOL_NETLINK, NETLINK_PKTINFO) => {
                write_bool(buf, self.netlink_pktinfo.load(Ordering::Acquire))
            }
            (SOL_NETLINK, NETLINK_BROADCAST_ERROR) => {
                write_bool(buf, self.netlink_broadcast_error.load(Ordering::Acquire))
            }
            (SOL_NETLINK, NETLINK_NO_ENOBUFS) => {
                write_bool(buf, self.netlink_no_enobufs.load(Ordering::Acquire))
            }
            (SOL_NETLINK, NETLINK_CAP_ACK) => {
                write_bool(buf, self.netlink_cap_ack.load(Ordering::Acquire))
            }
            (SOL_NETLINK, NETLINK_EXT_ACK) => {
                write_bool(buf, self.netlink_ext_ack.load(Ordering::Acquire))
            }
            (SOL_NETLINK, NETLINK_GET_STRICT_CHK) => {
                write_bool(buf, self.netlink_strict_check.load(Ordering::Acquire))
            }
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
                sender_cred: Ucred::default(),
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
                // Autobind (`Unnamed`) mints a fresh abstract name; a leading
                // NUL selects the abstract namespace; otherwise it's a path.
                let uaddr = match UnixAddr::parse(&addr.body) {
                    Some(UnixAddr::Unnamed) => UnixAddr::Abstract(autobind_name(true)),
                    Some(a) => a,
                    None => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let mut state = self.state.lock();
                if !matches!(&*state, SocketState::Fresh) {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                // Address-in-use check up front against the right registry.
                let in_use = match &uaddr {
                    UnixAddr::Path(p) => LISTENERS
                        .lock()
                        .as_ref()
                        .map(|m| m.contains_key(p))
                        .unwrap_or(false),
                    UnixAddr::Abstract(n) => ABSTRACT_STREAM
                        .lock()
                        .as_ref()
                        .map(|m| m.contains_key(n))
                        .unwrap_or(false),
                    UnixAddr::Unnamed => false,
                };
                if in_use {
                    return SocketOpResult::Err(SockError::AddrInUse);
                }
                // Abstract binds are complete at bind() (no separate listen
                // insert needed): register the socket now. Pathname binds keep
                // the historical bind-records-path / listen-inserts sequence.
                if let UnixAddr::Abstract(n) = &uaddr {
                    let mut reg = ABSTRACT_STREAM.lock();
                    reg.get_or_insert_with(BTreeMap::new)
                        .insert(n.clone(), self.clone());
                }
                *state = SocketState::UnixListener {
                    addr: uaddr,
                    backlog: 0,
                    pending: VecDeque::new(),
                };
                SocketOpResult::Ok(0)
            }
            SocketOp::Listen { backlog } => {
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::UnixListener {
                        addr, backlog: b, ..
                    } => {
                        *b = backlog;
                        // Pathname listeners insert into LISTENERS here (bind
                        // only recorded the path). Abstract listeners already
                        // registered at bind(), so this is a no-op for them.
                        if let UnixAddr::Path(p) = addr {
                            let p = p.clone();
                            drop(state);
                            let mut listeners = LISTENERS.lock();
                            let map = listeners.get_or_insert_with(BTreeMap::new);
                            map.insert(p, self.clone());
                        }
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
                let uaddr = match UnixAddr::parse(&addr.body) {
                    Some(a @ (UnixAddr::Path(_) | UnixAddr::Abstract(_))) => a,
                    _ => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let listener = match &uaddr {
                    UnixAddr::Path(p) => LISTENERS.lock().as_ref().and_then(|m| m.get(p).cloned()),
                    UnixAddr::Abstract(n) => ABSTRACT_STREAM
                        .lock()
                        .as_ref()
                        .and_then(|m| m.get(n).cloned()),
                    UnixAddr::Unnamed => None,
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
                // Credentials: the accepted server end owns the listener's
                // identity, and each end's SO_PEERCRED reports the other's.
                // (The listener process typically inherits/re-owns the
                // accepted fd, so the server end's local_cred = listener's.)
                let listener_cred = listener.local_cred();
                let client_cred = self.local_cred();
                server_end.set_local_cred(listener_cred);
                server_end.set_peer_cred(client_cred);
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
                        drop(state);
                        self.set_peer_cred(listener_cred);
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
                    sender_cred: Ucred::default(),
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

    /// AF_UNIX SOCK_DGRAM. Same shape as InetDgram but keyed by unix
    /// address (pathname or abstract name — sd_notify's $NOTIFY_SOCKET
    /// is an abstract datagram socket).
    fn dispatch_unix_dgram(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => {
                if addr.family != AF_UNIX {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let uaddr = match UnixAddr::parse(&addr.body) {
                    Some(UnixAddr::Unnamed) => UnixAddr::Abstract(autobind_name(false)),
                    Some(a) => a,
                    None => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let mut state = self.state.lock();
                if !matches!(&*state, SocketState::Fresh) {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                match &uaddr {
                    UnixAddr::Path(p) => {
                        let mut bound = UNIX_DGRAM_BOUND.lock();
                        let map = bound.get_or_insert_with(BTreeMap::new);
                        if map.contains_key(p) {
                            return SocketOpResult::Err(SockError::AddrInUse);
                        }
                        map.insert(p.clone(), self.clone());
                    }
                    UnixAddr::Abstract(n) => {
                        let mut bound = ABSTRACT_DGRAM.lock();
                        let map = bound.get_or_insert_with(BTreeMap::new);
                        if map.contains_key(n) {
                            return SocketOpResult::Err(SockError::AddrInUse);
                        }
                        map.insert(n.clone(), self.clone());
                    }
                    UnixAddr::Unnamed => return SocketOpResult::Err(SockError::InvalidArg),
                }
                *state = SocketState::UnixDgram {
                    addr: Some(uaddr),
                    inbox: VecDeque::new(),
                    peer: None,
                };
                SocketOpResult::Ok(0)
            }
            SocketOp::Connect { addr } => {
                if addr.family != AF_UNIX {
                    return SocketOpResult::Err(SockError::InvalidArg);
                }
                let uaddr = match UnixAddr::parse(&addr.body) {
                    Some(a @ (UnixAddr::Path(_) | UnixAddr::Abstract(_))) => a,
                    _ => return SocketOpResult::Err(SockError::InvalidArg),
                };
                let mut state = self.state.lock();
                if matches!(&*state, SocketState::Fresh) {
                    *state = SocketState::UnixDgram {
                        addr: None,
                        inbox: VecDeque::new(),
                        peer: Some(uaddr),
                    };
                    return SocketOpResult::Ok(0);
                }
                if let SocketState::UnixDgram { peer, .. } = &mut *state {
                    *peer = Some(uaddr);
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
                let (local_addr, dest_addr) = match &*state {
                    SocketState::UnixDgram { addr: la, peer, .. } => {
                        let dest = if let Some(a) = addr {
                            match UnixAddr::parse(&a.body) {
                                Some(d @ (UnixAddr::Path(_) | UnixAddr::Abstract(_))) => d,
                                _ => return SocketOpResult::Err(SockError::InvalidArg),
                            }
                        } else if let Some(p) = peer {
                            p.clone()
                        } else {
                            return SocketOpResult::Err(SockError::InvalidArg);
                        };
                        (la.clone(), dest)
                    }
                    // Unbound datagram sendto: Linux auto-binds an unnamed
                    // local address and delivers to the explicit destination.
                    // (We're inside dispatch_unix_dgram, so Fresh here is a
                    // SOCK_DGRAM socket — sd_notify sends from such a socket.)
                    SocketState::Fresh => {
                        let dest = match addr {
                            Some(a) => match UnixAddr::parse(&a.body) {
                                Some(d @ (UnixAddr::Path(_) | UnixAddr::Abstract(_))) => d,
                                _ => return SocketOpResult::Err(SockError::InvalidArg),
                            },
                            None => return SocketOpResult::Err(SockError::InvalidArg),
                        };
                        (None, dest)
                    }
                    _ => return SocketOpResult::Err(SockError::NotConnected),
                };
                let sender_cred = self.local_cred();
                drop(state);
                let dest_sock = match &dest_addr {
                    UnixAddr::Path(p) => UNIX_DGRAM_BOUND
                        .lock()
                        .as_ref()
                        .and_then(|m| m.get(p).cloned()),
                    UnixAddr::Abstract(n) => ABSTRACT_DGRAM
                        .lock()
                        .as_ref()
                        .and_then(|m| m.get(n).cloned()),
                    UnixAddr::Unnamed => None,
                };
                let dest_sock = match dest_sock {
                    Some(s) => s,
                    // No bound receiver. Linux returns ECONNREFUSED for a
                    // datagram sent to a missing named socket.
                    None => return SocketOpResult::Err(SockError::ConnectionRefused),
                };
                let pkt = DgramPacket {
                    peer_unix: local_addr,
                    sender_cred,
                    peer_addr: 0,
                    peer_port: 0,
                    payload: buf.to_vec(),
                };
                let mut ds = dest_sock.state.lock();
                if let SocketState::UnixDgram { inbox, .. } = &mut *ds {
                    inbox.push_back(pkt);
                }
                drop(ds);
                // Wake a receiver parked in recv/recvmsg/poll on the dest —
                // sd_notify sends one datagram and PID 1 blocks reading it.
                narf_net::readiness::notify(0);
                SocketOpResult::Ok(buf.len() as u64)
            }
            SocketOp::Recv { buf, flags: _ } => {
                let mut state = self.state.lock();
                if let SocketState::UnixDgram { inbox, .. } = &mut *state {
                    if let Some(pkt) = inbox.pop_front() {
                        let n = core::cmp::min(buf.len(), pkt.payload.len());
                        buf[..n].copy_from_slice(&pkt.payload[..n]);
                        let body = pkt.peer_unix.map(|a| a.to_body()).unwrap_or_default();
                        // Stash the sender's creds so a SO_PASSCRED recvmsg can
                        // attach them as SCM_CREDENTIALS.
                        *self.last_recv_cred.lock() = pkt.sender_cred;
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

/// Dropping the last reference to a connected socket end is a HANGUP for
/// the peer: its reads must start returning 0 (EOF) and its
/// `poll`/`epoll` must report `POLLIN`/`POLLHUP`.
///
/// Before this, `RingBuf::close` was reachable ONLY from an explicit
/// `shutdown(2)`. A process that simply `close(2)`d its end — or, far more
/// commonly, just EXITED and let fd-table teardown drop it — left the
/// peer's ring un-closed forever, so the peer saw neither data nor EOF and
/// parked until some coarse timeout.
///
/// dbus-daemon is the canonical victim: its babysitter reports an
/// activated service's exit status over a socketpair and then exits
/// WITHOUT closing it, and dbus waits for the resulting EOF to conclude
/// the activation. With no EOF it sat in `epoll_wait` for the full 120s
/// `service_start_timeout`, which is what made every failed D-Bus
/// activation cost two minutes and stalled the KDE Plasma session.
///
/// `Drop` is the right hook because it fires exactly when the LAST holder
/// goes away — which is precisely POSIX's "last descriptor closed", and
/// covers `close(2)`, `dup`'d copies, fork-inherited copies, and process
/// exit uniformly. (The global socket registry keeps only `Weak` handles,
/// so it does not pin the refcount.)
impl Drop for SocketFile {
    fn drop(&mut self) {
        // `tx` is the ring THIS end writes into and the PEER reads from,
        // so closing it is what surfaces EOF over there. `rx` belongs to
        // this dying end and needs no marking.
        let closed_tx = match &*self.state.lock() {
            SocketState::UnixConnected { tx, .. }
            | SocketState::InetConnected { tx, .. }
            | SocketState::Inet6Connected { tx, .. } => {
                tx.close();
                true
            }
            _ => false,
        };
        if closed_tx {
            // Same reasoning as `do_send`: go through `readiness::notify`
            // rather than a bare wake so the generation is bumped and a
            // peer parked in an INFINITE-timeout epoll_wait/poll actually
            // re-runs its readiness scan instead of silently re-parking.
            narf_net::readiness::notify(0);
        }
    }
}

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

    /// Buffered byte count — backs `SIOCINQ`/`FIONREAD` on a stream socket.
    fn len(&self) -> usize {
        self.inner.lock().len
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

// ── Abstract-namespace registries (sun_path[0] == '\0') ─────────
//
// Abstract AF_UNIX sockets have NO filesystem presence. The key is the
// raw name bytes after the leading NUL (may embed NULs / non-UTF-8), so
// these maps are keyed by `Vec<u8>` rather than the `String` path maps
// above. systemd's $NOTIFY_SOCKET (sd_notify datagram) and the private
// D-Bus stream socket both live here.

/// Abstract-namespace SOCK_STREAM / SOCK_SEQPACKET listeners: name → socket.
static ABSTRACT_STREAM: IrqSafeSpinLock<Option<BTreeMap<Vec<u8>, Arc<SocketFile>>>> =
    IrqSafeSpinLock::new(None);

/// Abstract-namespace SOCK_DGRAM bound sockets: name → socket.
static ABSTRACT_DGRAM: IrqSafeSpinLock<Option<BTreeMap<Vec<u8>, Arc<SocketFile>>>> =
    IrqSafeSpinLock::new(None);

/// Monotonic counter for autobind (`Unnamed`) addresses. Linux assigns a
/// 5-hex-digit abstract name; we mint `\0<hex>` names from this counter.
static AUTOBIND_NEXT: AtomicU32 = AtomicU32::new(1);

/// Mint a fresh, unused abstract name for an autobind (`bind` with
/// `addrlen == sizeof(sa_family_t)`). Linux uses `[0-9a-f]{5}`; we do the
/// same, retrying on the (vanishingly unlikely) collision.
fn autobind_name(stream: bool) -> Vec<u8> {
    loop {
        let n = AUTOBIND_NEXT.fetch_add(1, Ordering::Relaxed);
        let name = alloc::format!("{:05x}", n & 0xf_ffff).into_bytes();
        let taken = {
            let reg = if stream {
                ABSTRACT_STREAM.lock()
            } else {
                ABSTRACT_DGRAM.lock()
            };
            reg.as_ref().map(|m| m.contains_key(&name)).unwrap_or(false)
        };
        if !taken {
            return name;
        }
    }
}

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

// ── SIOCINQ / FIONREAD queue-length tests ───────────────────────
//
// systemd PID 1 issues `ioctl(fd, SIOCINQ, &n)` on its
// `$NOTIFY_SOCKET` AF_UNIX/SOCK_DGRAM socket to size a notification
// read. Exercise the byte-count logic (`inq_bytes`, which the ioctl
// serialises to user memory) directly so no user pointer is needed.

use narf_kernel_test::{kernel_test_in, TestResult};

/// An empty AF_UNIX datagram queue reports 0 bytes with success — never
/// an error. This is the case systemd hits at steady state (no pending
/// notification), where an errored ioctl produced the "Failed to read
/// AF_UNIX datagram queue length, ignoring" log.
fn smoke_siocinq_unix_dgram_empty_is_zero() -> TestResult {
    let sock = SocketFile::new(AF_UNIX, SOCK_DGRAM);
    // Bind-equivalent: move to the datagram state with an empty inbox.
    *sock.state.lock() = SocketState::UnixDgram {
        addr: None,
        inbox: VecDeque::new(),
        peer: None,
    };
    if sock.inq_bytes() != 0 {
        return TestResult::Fail("empty AF_UNIX dgram queue did not report 0 bytes");
    }
    TestResult::Pass
}
kernel_test_in!("userspace/socket", smoke_siocinq_unix_dgram_empty_is_zero);

/// A non-empty AF_UNIX datagram queue reports the size of the NEXT
/// (head-of-queue) datagram — matching Linux `SIOCINQ` semantics on a
/// datagram socket (one whole message per recv).
fn smoke_siocinq_unix_dgram_reports_head_len() -> TestResult {
    let sock = SocketFile::new(AF_UNIX, SOCK_DGRAM);
    let mut inbox = VecDeque::new();
    inbox.push_back(DgramPacket {
        peer_unix: None,
        sender_cred: Ucred::default(),
        peer_addr: 0,
        peer_port: 0,
        payload: alloc::vec![0u8; 7], // head datagram: 7 bytes
    });
    inbox.push_back(DgramPacket {
        peer_unix: None,
        sender_cred: Ucred::default(),
        peer_addr: 0,
        peer_port: 0,
        payload: alloc::vec![0u8; 3], // second datagram: ignored by SIOCINQ
    });
    *sock.state.lock() = SocketState::UnixDgram {
        addr: None,
        inbox,
        peer: None,
    };
    if sock.inq_bytes() != 7 {
        return TestResult::Fail("SIOCINQ did not report the head datagram's byte count");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    smoke_siocinq_unix_dgram_reports_head_len
);

/// The socket ioctl recognises ONLY `SIOCINQ`; any other request is an
/// unknown ioctl → `FsError::Unsupported` (the syscall layer maps this to
/// ENOTTY, Linux's `sock_ioctl` default).
fn smoke_socket_ioctl_unknown_is_unsupported() -> TestResult {
    let sock = SocketFile::new(AF_UNIX, SOCK_DGRAM);
    // 0xDEAD is not a request the socket handles; arg is unused because
    // the unknown-cmd branch returns before touching it.
    match sock.ioctl(0xDEAD, 0) {
        Err(FsError::Unsupported) => TestResult::Pass,
        _ => TestResult::Fail("unknown socket ioctl did not return Unsupported"),
    }
}
kernel_test_in!(
    "userspace/socket",
    smoke_socket_ioctl_unknown_is_unsupported
);
