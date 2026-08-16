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
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

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
/// Linux `AF_NETLINK`. Kernel-backed route, diagnostics, audit, netfilter,
/// uevent, and generic protocols are implemented explicitly. Other protocol
/// numbers retain user-to-user delivery but reject sends to an absent kernel
/// endpoint with `ECONNREFUSED`.
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
pub const NETLINK_LIST_MEMBERSHIPS: u32 = 9;
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
/// `NETLINK_AUDIT` — the kernel audit status and rule-enumeration protocol.
pub const NETLINK_AUDIT: u32 = 9;
/// `NETLINK_NETFILTER` — read-only nfnetlink conntrack dumps.
pub const NETLINK_NETFILTER: u32 = 12;
/// `NETLINK_KOBJECT_UEVENT` — the udev hotplug-monitor netlink protocol.
/// libudev opens `socket(AF_NETLINK, SOCK_DGRAM|SOCK_RAW, 15)` and reads
/// device-uevent messages off it; we bridge it to the kernel uevent ring.
pub const NETLINK_KOBJECT_UEVENT: u32 = 15;
/// `NETLINK_GENERIC` (genetlink) — the family-multiplexing protocol used by
/// nl80211, taskstats, thermal, etc. Note the numeric value coincides with
/// `AF_NETLINK` (16); they occupy different argument slots.
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
/// Linux Security Module peer label. NARF has no LSM label namespace, so
/// getsockopt reports ENOPROTOOPT rather than fabricating an authority label.
pub const SO_PEERSEC: u32 = 31;
pub const SO_PROTOCOL: u32 = 38;
pub const SO_DOMAIN: u32 = 39;
/// Supplementary groups captured from a Unix peer at connection time.
pub const SO_PEERGROUPS: u32 = 59;
/// pidfd naming the Unix peer. Socket peer credentials currently carry a PID
/// value but not a retained pidfd object, so getsockopt reports ENOPROTOOPT.
pub const SO_PEERPIDFD: u32 = 77;

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

/// A pathname UNIX socket is identified by the directory entry the caller
/// resolves, not by the spelling in `sun_path`. The backing filesystem plus
/// parent inode preserves aliases through a bind mount while a private
/// overmount remains distinct. This mirrors the VFS boundary without
/// pretending a mount-namespace ID is an inode.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct UnixPathKey {
    filesystem: usize,
    parent_ino: u64,
    /// Legacy initramfs directory handles are rebuilt on every lookup and do
    /// not expose an inode. In that case retain the mount-relative parent
    /// spelling as the stable portion of the VFS key.
    fallback_parent_path: Option<String>,
    name: String,
}

impl UnixPathKey {
    fn for_current_path(path: &str) -> Self {
        let (filesystem, parent_ino, fallback_parent_path, name) =
            crate::handlers::unix_socket_path_key(path).unwrap_or((0, 0, None, String::from(path)));
        Self {
            filesystem,
            parent_ino,
            fallback_parent_path,
            name,
        }
    }
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

/// Ancillary data carried by one received connectionless AF_UNIX datagram,
/// held between its dequeue and the recvmsg syscall's extraction of it.
/// Keyed per receiving task — see `SocketFile::dgram_recv_ancillary`.
#[derive(Default)]
struct DgramRecvAncillary {
    cred: Ucred,
    fds: Vec<ScmRightsFile>,
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
    Range,
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
            Self::Range => 34,              // ERANGE
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
    /// socket() time. Keys AF_INET bind tables and selects namespace-scoped
    /// netlink, routing, interface, and netfilter views.
    net_ns_id: core::sync::atomic::AtomicU64,
    /// Filesystem identity of this socket's bound pathname, if any.  Keep it
    /// with the endpoint so close/listen unregister the same inode even if an
    /// fd crossed into a different mount namespace.
    bound_unix_path: IrqSafeSpinLock<Option<UnixPathKey>>,
    /// Filesystem identity captured by a connected pathname datagram socket.
    /// `connect(2)` resolves its peer once; subsequent `send(2)` calls do not
    /// re-resolve it in whichever namespace happens to own a passed fd.
    connected_unix_path: IrqSafeSpinLock<Option<UnixPathKey>>,
    #[cfg(feature = "container")]
    net_namespace: IrqSafeSpinLock<Option<Arc<crate::namespaces::NetNamespace>>>,
    /// Credentials of the process that owns this socket end. Stamped by
    /// `sys_socket`/`sys_socketpair` at creation; surfaced to the peer via
    /// `SO_PEERCRED` and to a `SO_PASSCRED` recvmsg via `SCM_CREDENTIALS`.
    local_cred: IrqSafeSpinLock<Ucred>,
    /// Credentials of the connected peer. Filled in at connect()/accept()
    /// time (each end copies the other's `local_cred`). Read by
    /// `getsockopt(SO_PEERCRED)`.
    peer_cred: IrqSafeSpinLock<Ucred>,
    /// Supplementary groups owned by this endpoint and captured from its peer.
    /// Values are host-absolute gids; getsockopt translates them into the
    /// reader's user namespace.
    local_groups: IrqSafeSpinLock<Vec<u32>>,
    peer_groups: IrqSafeSpinLock<Vec<u32>>,
    /// `SO_PASSCRED` — recvmsg attaches an `SCM_CREDENTIALS` cmsg when set.
    passcred: AtomicBool,
    /// Ancillary data of the connectionless AF_UNIX datagram most recently
    /// dequeued BY EACH RECEIVING TASK, keyed by that task.
    ///
    /// Datagram ancillary data belongs to the RECORD that carried it, not to
    /// the socket, and dequeue is not atomic with extraction: `dispatch_op
    /// (Recv)` pops the packet and stashes its credentials here, and the
    /// recvmsg syscall reads them back only after copying the payload out to
    /// userspace. Socket-global slots therefore lose the association the
    /// moment a SECOND receiver dequeues inside that window — the first
    /// receiver goes on to report the second sender's identity.
    ///
    /// `systemd-udevd` is precisely that topology: many workers sending to
    /// one manager, which identifies the sender purely from SCM_CREDENTIALS
    /// (`hashmap_get(manager->workers, &sender)`). Attributing a worker's
    /// `INOTIFY_WATCH_REMOVE=1` to a different, idle worker makes the manager
    /// fail `assert(worker->event)` and abort.
    ///
    /// ORDER MATTERS for consumers: `unix_take_recv_fds` takes the rights and
    /// leaves the entry; `recvmsg_cred` REMOVES it. Take the fds first, or
    /// they are dropped with the entry. A plain `read(2)` wants neither and
    /// calls `discard_dgram_recv_ancillary`.
    dgram_recv_ancillary: IrqSafeSpinLock<BTreeMap<u64, DgramRecvAncillary>>,
    /// Readable-transition generation for connectionless datagram inboxes.
    /// A bound AF_UNIX DGRAM socket is the systemd `$NOTIFY_SOCKET` shape:
    /// after an EPOLLET consumer drains it, a refill can occur before epoll
    /// observes the temporary empty state. The generation preserves that edge.
    dgram_readable_token: AtomicU64,
    /// Readable-generation for an AF_UNIX listener's pending accept queue.
    /// An EPOLLET server can accept the final queued connection and receive a
    /// new one before its next epoll scan, leaving the sampled mask at POLLIN
    /// throughout. Each enqueue is nevertheless a new accept-ready edge.
    listener_readable_token: AtomicU64,
    /// `unix-latency-trace` only: tid that called `listen()` on this socket.
    /// The starved-accept sweep runs inside the watchdog's timer trap, where
    /// walking every task's fd table to find the acceptor would take the fd
    /// lock the interrupted CPU may already hold. Recording the acceptor at
    /// listen() time makes the sweep a pure read.
    #[cfg(feature = "unix-latency-trace")]
    listen_owner_tid: AtomicU64,
    /// `unix-latency-trace`: the fd `listen()` was called on, recorded by
    /// `sys_socket_listen` (the dispatch layer below does not see it).
    /// Compared against the acceptor's recorded poll fd set.
    #[cfg(feature = "unix-latency-trace")]
    listen_owner_fd: AtomicU32,
    /// Receive-progress generation for AF_NETLINK queues.  A monitor can
    /// drain one message between EPOLLET scans; advancing this token on that
    /// drain preserves the next queued message's edge without manufacturing
    /// an event while the socket stayed readable.
    netlink_readable_token: AtomicU64,
    /// AF_NETLINK local and connected peer addresses. Port ID zero means
    /// unbound; an explicit bind with nl_pid=0 allocates a unique ID.
    netlink_portid: AtomicU32,
    netlink_groups: AtomicU32,
    /// Full Linux multicast group-number membership. `sockaddr_nl.nl_groups`
    /// mirrors groups 1..=32; SOL_NETLINK can address higher group numbers.
    netlink_memberships: IrqSafeSpinLock<BTreeSet<u32>>,
    netlink_peer_portid: AtomicU32,
    netlink_peer_groups: AtomicU32,
    netlink_pktinfo: AtomicBool,
    netlink_broadcast_error: AtomicBool,
    netlink_no_enobufs: AtomicBool,
    netlink_cap_ack: AtomicBool,
    netlink_ext_ack: AtomicBool,
    netlink_strict_check: AtomicBool,
    /// Multicast group associated with each kernel-originated queued
    /// datagram. Kept parallel to the protocol-specific reply queue so
    /// NETLINK_PKTINFO can report the group of the datagram actually read.
    netlink_reply_groups: IrqSafeSpinLock<VecDeque<u32>>,
    netlink_last_recv_group: AtomicU32,
    /// Explicitly delegated NARF network-control authority. Never inferred
    /// from uid or Linux ambient capability bits.
    netlink_admin: IrqSafeSpinLock<Option<narf_net::AdminHandle>>,
    netfilter_admin: IrqSafeSpinLock<Option<narf_net::netfilter::NetfilterAdminHandle>>,
    /// Userspace-to-userspace unicast datagrams, independent of each
    /// protocol's kernel reply queue so sender port IDs remain attributable.
    netlink_user_inbox: IrqSafeSpinLock<VecDeque<NetlinkUserPacket>>,
    /// Membership in the KERNEL uevent multicast group (group 1) for a
    /// `NETLINK_KOBJECT_UEVENT` socket. False until a `bind` whose
    /// `sockaddr_nl.nl_groups` has bit 0 set.
    ///
    /// Linux ref: `net/netlink/af_netlink.c` — `netlink_bind` is what
    /// establishes multicast membership, and kernel broadcast
    /// (`netlink_broadcast` → `do_one_broadcast`) walks `mc_list` and skips
    /// any socket that is not a member of the destination group. So an
    /// unbound socket, or one bound with `nl_groups == 0`, receives no
    /// kernel uevents at all.
    ///
    /// This matters because groups=0 is a shape udev uses ON PURPOSE:
    /// `systemd-udevd` builds each worker's device monitor with
    /// `device_monitor_new_full(&worker_monitor, MONITOR_GROUP_NONE, -1)`,
    /// meaning "deliver me only the manager's unicast hand-offs". NARF used
    /// to attach the kernel uevent ring to every proto-15 socket, so every
    /// worker also replayed the boot coldplug set — SEQNUM=2 was processed
    /// seven times by workers forked once each, and a worker re-processing a
    /// device-node device answers with `INOTIFY_WATCH_REMOVE=1` for an event
    /// the manager never assigned it, tripping `assert(worker->event)` in
    /// `udev-manager.c:1199` and aborting the daemon.
    ///
    /// The ring READER is still created at `socket()` time, unchanged — the
    /// cursor position, and the boot-coldplug-replay decision that depends
    /// on the opening task's comm, must stay exactly as they were, because
    /// the replay window is chosen relative to socket creation and a
    /// bind-time reader would start at the wrong place. Only DELIVERY is
    /// gated, at the same read-side points Linux gates multicast:
    /// `recv`, poll readiness, the edge-trigger token, and `SIOCINQ`.
    ///
    /// Deliberately NOT gated: `netlink_user_inbox`. Manager unicasts and
    /// group-2 (`MONITOR_GROUP_UDEV`) user broadcasts are membership-checked
    /// separately in `broadcast_netlink_user`, and must keep flowing to a
    /// groups=0 socket — receiving those is the entire purpose of a worker
    /// monitor.
    netlink_uevent_subscribed: AtomicBool,
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
    /// AF_UNIX socket with a local address but not listening or connected.
    UnixBound { addr: UnixAddr },
    /// AF_UNIX listening socket at the named address (pathname or abstract).
    UnixListener {
        addr: UnixAddr,
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
        /// Local address retained when a client binds before connect().
        local_addr: Option<UnixAddr>,
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
    /// `AF_NETLINK` for a protocol NARF does not model. A coherent no-op sink: `bind`,
    /// `connect`, and `send` succeed (messages are dropped — audit/netfilter
    /// are disabled), `recv` reports empty (WouldBlock). This lets
    /// best-effort openers (systemd PID 1's audit setup) get a usable fd and
    /// proceed instead of failing the socket open with EPERM.
    NetlinkSink,
    /// `NETLINK_AUDIT` status and rule-enumeration response queue.
    NetlinkAudit { replies: VecDeque<Vec<u8>> },
    /// `NETLINK_GENERIC` control-family socket. Requests to `nlctrl` queue
    /// generic-netlink family discovery replies here.
    NetlinkGeneric { replies: VecDeque<Vec<u8>> },
    /// `NETLINK_SOCK_DIAG` response queue for `inet_diag_req_v2` dumps.
    NetlinkSockDiag { replies: VecDeque<Vec<u8>> },
    /// `NETLINK_NETFILTER` response queue for nfnetlink conntrack dumps.
    NetlinkNetfilter { replies: VecDeque<Vec<u8>> },
}

/// Open-file state transported by `SCM_RIGHTS`.
///
/// Descriptor flags such as `FD_CLOEXEC` belong to the sender's fd slot and
/// are intentionally not carried. File status flags belong to the open file
/// description and therefore must survive installation in the receiver.
#[derive(Clone)]
pub(crate) struct ScmRightsFile {
    pub(crate) ops: Arc<dyn FileOps>,
    pub(crate) status_flags: u32,
}

/// One enqueued UDP-style datagram. Owns the payload bytes (UDP
/// has no concept of partial reads — each recv yields one whole
/// packet, padded or truncated to the user buffer size).
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
    /// Per-datagram SCM_RIGHTS payload. AF_UNIX datagrams preserve message
    /// boundaries, so these descriptors must not share the stream ring.
    pub(crate) fds: Vec<ScmRightsFile>,
}

impl core::fmt::Debug for DgramPacket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DgramPacket")
            .field("peer_unix", &self.peer_unix)
            .field("sender_cred", &self.sender_cred)
            .field("peer_addr", &self.peer_addr)
            .field("peer_port", &self.peer_port)
            .field("payload", &self.payload)
            .field("fd_count", &self.fds.len())
            .finish()
    }
}

#[derive(Debug)]
struct NetlinkUserPacket {
    payload: Vec<u8>,
    sender_portid: u32,
    /// Destination multicast group as a `sockaddr_nl.nl_groups` MASK
    /// (0 for unicast). Linux reports this to the receiver via
    /// `netlink_group_mask(NETLINK_CB(skb).dst_group)` in `netlink_recvmsg`,
    /// and libudev's `device_monitor_receive_device` uses it to tell a
    /// multicast broadcast from a unicast message: anything arriving with
    /// `nl_groups == 0` is treated as unicast and DISCARDED unless it comes
    /// from the monitor's trusted sender. Dropping this field would make
    /// every udev broadcast silently ignored by its listeners.
    group: u32,
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
        } else if domain == AF_NETLINK && protocol == NETLINK_AUDIT {
            SocketState::NetlinkAudit {
                replies: VecDeque::new(),
            }
        } else if domain == AF_NETLINK && protocol != NETLINK_KOBJECT_UEVENT {
            // Unregistered kernel protocol. The socket still participates in
            // protocol-isolated user-to-user netlink; only kernel-directed
            // requests are rejected.
            SocketState::NetlinkSink
        } else if domain == AF_NETLINK {
            // NETLINK_KOBJECT_UEVENT → the udev hotplug monitor. Wire the
            // post-emit wake so a uevent emitted
            // while this monitor is parked in poll/epoll wakes it (the ring
            // lives in the fs crate, which can't reach the net readiness layer
            // directly). Idempotent — a plain atomic store.
            narf_filesystem::uevent::set_wake_hook(uevent_wake_hook);
            // A generic monitor starts at the ring TAIL: Linux
            // `NETLINK_KOBJECT_UEVENT` is not replayed on connect, and replaying
            // boot-time ADDs to libinput can tear down an already-created input
            // device.  systemd-udevd and PID 1 are the two deliberate
            // exceptions. NARF's systemd boot path queues the storage ADDs
            // before either has opened its monitor; without a bounded replay,
            // PID 1 never activates the fstab-generated UUID .device unit.
            // Replay only NARF's post-sysfs storage-coldplug window to the
            // systemd's device manager and udev daemon. Replaying every early
            // bring-up event is unsafe:
            // some precede their completed kobject and make udevd open a stale
            // DEVPATH. The marker is set immediately before the canonical
            // block ADDs that satisfy fstab UUID dependencies.
            let task = crate::handlers::current_task_id();
            let reader = if crate::handlers::proc_comm_of_task_matches(task, "systemd-udevd$")
                || crate::handlers::proc_comm_of_task_matches(task, "systemd$")
            {
                narf_filesystem::uevent::boot_udevd_replay_reader()
            } else {
                narf_filesystem::uevent::UeventReader::new()
            };
            // Debug-feature only: which task opened a uevent monitor, and
            // whether it got the bounded boot-coldplug replay. udevd opening
            // MANY monitors, or a monitor opened without replay, are both
            // invisible from inside the guest.
            #[cfg(feature = "unix-latency-trace")]
            {
                use core::fmt::Write as _;
                let comm = crate::handlers::proc_comm_of_task(task)
                    .unwrap_or_else(|| alloc::string::String::from("?"));
                let _ = writeln!(
                    narf_console::Writer,
                    "  uevent-sock: created tid={} comm={} replay={}",
                    task,
                    comm,
                    crate::handlers::proc_comm_of_task_matches(task, "systemd-udevd$")
                        || crate::handlers::proc_comm_of_task_matches(task, "systemd$")
                );
            }
            SocketState::NetlinkUevent { reader }
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
            bound_unix_path: IrqSafeSpinLock::new(None),
            connected_unix_path: IrqSafeSpinLock::new(None),
            #[cfg(feature = "container")]
            net_namespace: IrqSafeSpinLock::new(None),
            local_cred: IrqSafeSpinLock::new(Ucred::default()),
            peer_cred: IrqSafeSpinLock::new(Ucred::default()),
            local_groups: IrqSafeSpinLock::new(Vec::new()),
            peer_groups: IrqSafeSpinLock::new(Vec::new()),
            passcred: AtomicBool::new(false),
            dgram_recv_ancillary: IrqSafeSpinLock::new(BTreeMap::new()),
            dgram_readable_token: AtomicU64::new(0),
            listener_readable_token: AtomicU64::new(0),
            #[cfg(feature = "unix-latency-trace")]
            listen_owner_tid: AtomicU64::new(0),
            #[cfg(feature = "unix-latency-trace")]
            listen_owner_fd: AtomicU32::new(u32::MAX),
            netlink_readable_token: AtomicU64::new(0),
            netlink_portid: AtomicU32::new(0),
            netlink_groups: AtomicU32::new(0),
            netlink_memberships: IrqSafeSpinLock::new(BTreeSet::new()),
            netlink_peer_portid: AtomicU32::new(0),
            netlink_peer_groups: AtomicU32::new(0),
            netlink_pktinfo: AtomicBool::new(false),
            netlink_broadcast_error: AtomicBool::new(false),
            netlink_no_enobufs: AtomicBool::new(false),
            netlink_cap_ack: AtomicBool::new(false),
            netlink_ext_ack: AtomicBool::new(false),
            netlink_strict_check: AtomicBool::new(false),
            netlink_reply_groups: IrqSafeSpinLock::new(VecDeque::new()),
            netlink_last_recv_group: AtomicU32::new(0),
            netlink_admin: IrqSafeSpinLock::new(None),
            netfilter_admin: IrqSafeSpinLock::new(None),
            netlink_user_inbox: IrqSafeSpinLock::new(VecDeque::new()),
            netlink_uevent_subscribed: AtomicBool::new(false),
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
        if admin.net_ns_id().map_err(|_| SockError::InvalidArg)? != self.net_ns_id() {
            return Err(SockError::InvalidArg);
        }
        *self.netlink_admin.lock() = Some(admin);
        Ok(())
    }

    pub fn delegate_netfilter_admin(
        &self,
        admin: narf_net::netfilter::NetfilterAdminHandle,
    ) -> Result<(), SockError> {
        if self.domain != AF_NETLINK
            || self.protocol != NETLINK_NETFILTER
            || self.net_ns_id() != admin.net_ns_id()
        {
            return Err(SockError::InvalidArg);
        }
        admin
            .check(narf_net::netfilter::NetfilterRights::READ)
            .map_err(|_| SockError::InvalidArg)?;
        *self.netfilter_admin.lock() = Some(admin);
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
                socket
                    .netlink_reply_groups
                    .lock()
                    .push_back(group.trailing_zeros() + 1);
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

    /// Stamp each queued unicast netlink reply's `nlmsg_pid` with the
    /// destination socket's own port id. The Linux kernel sets a unicast
    /// reply's `nlmsg_pid` to the recipient's port id (see `netlink_ack` /
    /// `__nlmsg_put(skb, NETLINK_CB(in_skb).portid, ...)`), and sd-netlink's
    /// `parse_message_one` silently drops any non-broadcast message whose
    /// `nlmsg_pid` differs from its bound port. A reply stamped with 0 is
    /// therefore discarded, so a caller waiting on the ack (e.g. systemd's
    /// `loopback_setup`) never sees `n_messages` reach zero and spins in
    /// `ppoll` forever. Broadcast/multicast notifications keep `nlmsg_pid=0`
    /// (kernel origin) and are stamped separately, so only the direct replies
    /// pass through here. A `Vec` may carry more than one concatenated
    /// message; walk them by `nlmsg_len` alignment.
    fn stamp_netlink_reply_portid(messages: &mut [alloc::vec::Vec<u8>], portid: u32) {
        const NLMSG_HDRLEN: usize = 16;
        for msg in messages.iter_mut() {
            let mut off = 0;
            while off + NLMSG_HDRLEN <= msg.len() {
                let len = u32::from_ne_bytes([msg[off], msg[off + 1], msg[off + 2], msg[off + 3]])
                    as usize;
                if len < NLMSG_HDRLEN || off + len > msg.len() {
                    break;
                }
                // nlmsg_pid occupies bytes 12..16 of the nlmsghdr.
                msg[off + 12..off + 16].copy_from_slice(&portid.to_ne_bytes());
                off += (len + 3) & !3;
            }
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
        // Joining group 1 on NETLINK_KOBJECT_UEVENT is what subscribes this
        // socket to the KERNEL uevent multicast (Linux: `netlink_bind` →
        // `netlink_update_subscriptions`). A groups=0 bind — udev's
        // MONITOR_GROUP_NONE worker monitor — deliberately joins nothing.
        if self.protocol == NETLINK_KOBJECT_UEVENT && (groups & 1) != 0 {
            self.netlink_uevent_subscribed
                .store(true, Ordering::Release);
        }
        {
            let mut memberships = self.netlink_memberships.lock();
            memberships.retain(|group| *group > 32);
            for bit in 0..32 {
                if groups & (1u32 << bit) != 0 {
                    memberships.insert(bit + 1);
                }
            }
        }
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
        // Debug-feature only: udev's manager hands each device to a specific
        // worker by netlink UNICAST to that worker's autobound portid
        // (`device_monitor_send(monitor, &worker->address, dev)`). Log EVERY
        // send's resolved destination, including the (0,0) case that falls
        // through to "accept and discard" — a device silently dropped there
        // reaches no worker at all, and a device delivered to the wrong
        // worker makes that worker process an event it was never assigned,
        // which is what `assert(worker->event)` catches.
        #[cfg(feature = "unix-latency-trace")]
        {
            use core::fmt::Write as _;
            static SHOWN: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
            if SHOWN.fetch_add(1, Ordering::Relaxed) < 4000 {
                let task = crate::handlers::current_task_id();
                let comm = crate::handlers::proc_comm_of_task(task).unwrap_or_default();
                let _ = writeln!(
                    narf_console::Writer,
                    "  nl-send: tid={} comm={} proto={} to_port={} to_groups={} len={}",
                    task,
                    comm,
                    self.protocol,
                    destination.0,
                    destination.1,
                    buf.len()
                );
            }
        }
        if destination == (0, 0) {
            return None;
        }
        // Multicast: deliver to every socket subscribed to the group.
        //
        // This used to return NotSupported outright, on the reasoning that
        // "userspace multicast requires authority NARF does not grant". That
        // broke udev completely (task #12). After a worker processes a
        // device, udevd broadcasts the result to its libudev listeners on the
        // UDEV_MONITOR_UDEV group; EOPNOTSUPP there is not a slow path, it is
        // fatal:
        //
        //   sd-device-monitor(manager): Failed to send device to netlink
        //       monitor: Operation not supported
        //   Failed to broadcast event (SEQNUM=23) to libudev listeners
        //   Worker [20] exited with return code 1.
        //   Event loop failed: Operation not supported
        //
        // udevd's event loop dies, so /run/udev/data stays empty, no input
        // device ever gets a `seat` tag, libinput enumerates nothing, and the
        // Wayland seat advertises keyboard-only — the dead mouse.
        //
        // Linux does NOT refuse this. `netlink_sendmsg` gates multicast on
        // `netlink_allowed(sock, NL_CFG_F_NONROOT_SEND)` and fails with
        // EPERM, not EOPNOTSUPP — and udevd runs with CAP_NET_ADMIN, so it is
        // allowed. Matching Linux's permission model properly is task #12's
        // follow-up; refusing every sender was both the wrong errno and the
        // wrong answer for the one sender that matters.
        if destination.1 != 0 {
            return Some(self.broadcast_netlink_user(buf, destination.1));
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
                group: 0,
            });
        drop(sockets);
        narf_net::readiness::notify(0);
        Some(SocketOpResult::Ok(buf.len() as u64))
    }

    /// `sockaddr_nl.nl_groups` multicast send — Linux `netlink_broadcast`.
    ///
    /// `group_mask` is the raw `nl_groups` bitmask the sender supplied. Linux
    /// derives the group NUMBER with `ffs()` (the index of the lowest set
    /// bit, 1-based) and reports it back to receivers re-encoded as a mask
    /// via `netlink_group_mask()`, so that round-trip is preserved here.
    ///
    /// Delivery is best-effort: Linux's `netlink_sendmsg` ignores
    /// `netlink_broadcast`'s return value, so a broadcast with no subscribers
    /// still succeeds. Returning an error for an empty listener set would
    /// make udevd fail whenever nothing happened to be listening yet.
    fn broadcast_netlink_user(&self, buf: &[u8], group_mask: u32) -> SocketOpResult {
        // Linux `ffs(addr->nl_groups)`.
        let group = group_mask.trailing_zeros() + 1;
        let sender = self.ensure_netlink_portid();
        let targets: Vec<Arc<SocketFile>> = {
            let mut sockets = NETLINK_SOCKETS.lock();
            sockets.retain(|weak| weak.strong_count() != 0);
            sockets.iter().filter_map(Weak::upgrade).collect()
        };
        let mut delivered = 0usize;
        for target in targets {
            if target.protocol != self.protocol {
                continue;
            }
            // Never loop a broadcast back to its sender (Linux skips
            // `sk == ssk` in `do_one_broadcast`).
            if target.netlink_portid.load(Ordering::Acquire) == sender {
                continue;
            }
            if !target.netlink_memberships.lock().contains(&group) {
                continue;
            }
            target
                .netlink_user_inbox
                .lock()
                .push_back(NetlinkUserPacket {
                    payload: buf.to_vec(),
                    sender_portid: sender,
                    group: group_mask,
                });
            delivered += 1;
        }
        if delivered > 0 {
            // Wake any parked poll/epoll waiter on a subscribed socket.
            narf_net::readiness::notify(0);
        }
        SocketOpResult::Ok(buf.len() as u64)
    }

    fn recv_netlink_user(&self, buf: &mut [u8], flags: u32) -> Option<SocketOpResult> {
        let packet = {
            let mut inbox = self.netlink_user_inbox.lock();
            if flags & MSG_PEEK != 0 {
                inbox.front().map(|packet| NetlinkUserPacket {
                    payload: packet.payload.clone(),
                    sender_portid: packet.sender_portid,
                    group: packet.group,
                })
            } else {
                inbox.pop_front()
            }
        }?;
        if flags & MSG_PEEK == 0 {
            self.netlink_readable_token.fetch_add(1, Ordering::Release);
        }
        let n = buf.len().min(packet.payload.len());
        buf[..n].copy_from_slice(&packet.payload[..n]);
        // Report the ORIGINATING group, not a hardcoded 0. Linux's
        // `netlink_recvmsg` sets `addr->nl_groups =
        // netlink_group_mask(NETLINK_CB(skb).dst_group)`, and libudev keys
        // its unicast-vs-multicast trust decision on exactly this field: a
        // broadcast that arrives claiming nl_groups==0 is treated as an
        // untrusted unicast and dropped on the floor.
        self.netlink_last_recv_group
            .store(packet.group, Ordering::Release);
        let peer = Some(Self::netlink_sockaddr(packet.sender_portid, packet.group));
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

    fn queue_netlink_reply_groups(&self, count: usize) {
        self.netlink_reply_groups
            .lock()
            .extend(core::iter::repeat_n(0, count));
    }

    #[inline]
    fn note_netlink_receive(&self, flags: u32) {
        if flags & MSG_PEEK == 0 {
            self.netlink_readable_token.fetch_add(1, Ordering::Release);
        }
    }

    fn record_queued_netlink_group(&self, flags: u32) {
        let group = {
            let mut groups = self.netlink_reply_groups.lock();
            if flags & MSG_PEEK != 0 {
                groups.front().copied()
            } else {
                groups.pop_front()
            }
        }
        .unwrap_or(0);
        self.netlink_last_recv_group.store(group, Ordering::Release);
    }

    pub fn netlink_pktinfo(&self) -> Option<u32> {
        if self.domain == AF_NETLINK && self.netlink_pktinfo.load(Ordering::Acquire) {
            Some(self.netlink_last_recv_group.load(Ordering::Acquire))
        } else {
            None
        }
    }

    /// Byte length of the `NETLINK_LIST_MEMBERSHIPS` bitmap this socket would
    /// report: `ceil(highest_group / 32)` u32 words, expressed in bytes. Zero
    /// when the socket has joined no multicast groups. Linux answers a
    /// `getsockopt(SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, NULL, &len)` probe
    /// with exactly this value so callers can size their buffer; sd-netlink's
    /// `netlink_socket_get_multicast_groups()` issues that probe on every
    /// `sd_netlink_open()` (loopback-setup, udev, rtnetlink).
    pub fn netlink_list_memberships_len(&self) -> usize {
        self.netlink_memberships
            .lock()
            .last()
            .map(|group| (*group as usize).div_ceil(32) * 4)
            .unwrap_or(0)
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

    pub fn set_local_groups(&self, groups: Vec<u32>) {
        *self.local_groups.lock() = groups;
    }

    pub fn local_groups(&self) -> Vec<u32> {
        self.local_groups.lock().clone()
    }

    /// The connected peer's credentials (SO_PEERCRED source).
    pub fn peer_cred(&self) -> Ucred {
        *self.peer_cred.lock()
    }

    fn set_peer_cred(&self, cred: Ucred) {
        *self.peer_cred.lock() = cred;
    }

    fn set_peer_groups(&self, groups: Vec<u32>) {
        *self.peer_groups.lock() = groups;
    }

    pub fn peer_groups(&self) -> Vec<u32> {
        self.peer_groups.lock().clone()
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
        if self.kind == SOCK_DGRAM || self.kind == SOCK_SEQPACKET {
            let rx = match &*self.state.lock() {
                SocketState::UnixConnected { rx, .. } => Some(rx.clone()),
                _ => None,
            };
            if let Some(cred) = rx.and_then(|rx| rx.take_delivered_packet_cred()) {
                return cred;
            }
        }
        if self.kind == SOCK_DGRAM {
            if matches!(&*self.state.lock(), SocketState::UnixConnected { .. }) {
                *self.peer_cred.lock()
            } else {
                // Per-RECORD, keyed by the receiving task. Removing the entry
                // here is what bounds the map; any rights still attached were
                // not asked for and are dropped with it (see the field docs
                // for the required take-fds-first ordering).
                self.dgram_recv_ancillary
                    .lock()
                    .remove(&crate::handlers::current_task_id())
                    .map(|a| a.cred)
                    .unwrap_or_default()
            }
        } else {
            *self.peer_cred.lock()
        }
    }

    /// Stamp this socket's network-namespace id (see field docs).
    pub fn set_net_ns_id(&self, id: u64) {
        self.net_ns_id
            .store(id, core::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(feature = "container")]
    pub fn set_net_namespace(&self, namespace: Arc<crate::namespaces::NetNamespace>) {
        self.set_net_ns_id(namespace.id());
        *self.net_namespace.lock() = Some(namespace);
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
    pub fn unix_pair(kind: u32) -> (Arc<Self>, Arc<Self>) {
        let a = Self::new(AF_UNIX, kind);
        let b = Self::new(AF_UNIX, kind);
        let a_to_b = Arc::new(RingBuf::new());
        let b_to_a = Arc::new(RingBuf::new());
        *a.state.lock() = SocketState::UnixConnected {
            tx: a_to_b.clone(),
            rx: b_to_a.clone(),
            local_addr: None,
        };
        *b.state.lock() = SocketState::UnixConnected {
            tx: b_to_a,
            rx: a_to_b,
            local_addr: None,
        };
        (a, b)
    }

    pub fn unix_stream_pair() -> (Arc<Self>, Arc<Self>) {
        Self::unix_pair(SOCK_STREAM)
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
        let ga = a.local_groups();
        let gb = b.local_groups();
        a.set_peer_groups(gb);
        b.set_peer_groups(ga);
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
            SocketState::UnixBound { addr } | SocketState::UnixListener { addr, .. } => {
                Some(SockAddr {
                    family: AF_UNIX,
                    body: addr.to_body(),
                })
            }
            SocketState::UnixConnected {
                local_addr: Some(addr),
                ..
            } => Some(SockAddr {
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
            // Linux reports a connected unnamed AF_UNIX peer (including
            // socketpair endpoints) as a minimal sockaddr_un containing only
            // sa_family.  The crossed-ring state does not currently retain a
            // named peer address, but it still proves that a peer exists.
            SocketState::UnixConnected { .. } => Some(SockAddr {
                family: AF_UNIX,
                body: alloc::vec::Vec::new(),
            }),
            SocketState::Inet6Connected {
                peer_addr,
                peer_port,
                ..
            } => Some(make_sockaddr_in6(*peer_addr, *peer_port)),
            _ => None,
        }
    }

    /// Whether this socket owns a name in one of the global registries —
    /// i.e. whether [`Self::unregister`] would remove anything.
    ///
    /// Lets `sys_close` keep its expensive cross-process ownership scan off
    /// the hot path: only a bound or listening socket can strand a name, and
    /// those are a vanishing fraction of the sockets a system closes.
    pub fn has_registration(&self) -> bool {
        matches!(
            &*self.state.lock(),
            SocketState::UnixBound { .. }
                | SocketState::UnixListener { .. }
                | SocketState::UnixConnected {
                    local_addr: Some(_),
                    ..
                }
                | SocketState::InetListener { .. }
                | SocketState::Inet6Listener { .. }
                | SocketState::UnixDgram { addr: Some(_), .. }
                | SocketState::InetDgram { .. }
                | SocketState::InetWired { .. }
        )
    }

    /// Tear down listener / dgram-bound registry entries owned by
    /// this socket. Called from sys_close so the path / port is
    /// reusable on the next bind. Idempotent — Fresh / Connected
    /// sockets are no-ops.
    pub fn unregister(&self) {
        enum Reg {
            Unix(UnixPathKey),
            AbstractStream((u64, Vec<u8>)),
            Inet(u32, u16),
            Inet6([u8; 16], u16),
            UnixDgram(UnixPathKey),
            AbstractDgram((u64, Vec<u8>)),
            InetDgram(u32, u16),
            Tcb(u32),
            None,
        }
        let bound_path = self.bound_unix_path.lock().clone();
        let reg = {
            let state = self.state.lock();
            match &*state {
                SocketState::UnixBound { addr }
                | SocketState::UnixListener { addr, .. }
                | SocketState::UnixConnected {
                    local_addr: Some(addr),
                    ..
                } => match addr {
                    UnixAddr::Path(p) => Reg::Unix(
                        bound_path
                            .clone()
                            .unwrap_or_else(|| UnixPathKey::for_current_path(p)),
                    ),
                    UnixAddr::Abstract(n) => Reg::AbstractStream((self.net_ns_id(), n.clone())),
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
                    UnixAddr::Path(p) => Reg::UnixDgram(
                        bound_path
                            .clone()
                            .unwrap_or_else(|| UnixPathKey::for_current_path(p)),
                    ),
                    UnixAddr::Abstract(n) => Reg::AbstractDgram((self.net_ns_id(), n.clone())),
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
            if self.kind == SOCK_SEQPACKET || self.kind == SOCK_DGRAM {
                if let Some(rx) = match &*self.state.lock() {
                    SocketState::UnixConnected { rx, .. } => Some(rx.clone()),
                    _ => None,
                } {
                    return match rx.read_packet(buf, false) {
                        Some((n, _)) => {
                            // read() has no ancillary output: discard the
                            // record's rights and credential.
                            drop(rx.take_fds());
                            let _ = rx.take_delivered_packet_cred();
                            Ok(n)
                        }
                        // Closed peer = real EOF; empty-but-open =
                        // would-block. Linux `unix_seqpacket_recvmsg` /
                        // `unix_dgram_recvmsg` return -EAGAIN for the latter.
                        None if rx.is_closed() => Ok(0),
                        None => Err(FsError::WouldBlock),
                    };
                }
            }
            let r = self.do_recv(buf, 0);
            match r {
                Ok((n, _)) => {
                    // read(2) has no ancillary-data output. If this byte range
                    // crossed an AF_UNIX stream control marker, consume and
                    // discard those rights now so a later recvmsg(2) cannot
                    // receive descriptors attached to already-consumed bytes.
                    drop(self.unix_take_recv_fds());
                    // read(2) reports no credentials either, so clear the
                    // whole per-record entry rather than leaving a cred behind.
                    self.discard_dgram_recv_ancillary();
                    Ok(n)
                }
                // do_recv already distinguishes empty-but-open from EOF; pass
                // its explicit would-block result through unchanged.
                Err(SockError::WouldBlock) => Err(FsError::WouldBlock),
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
            SocketState::Fresh | SocketState::UnixBound { .. } => 0,
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
            SocketState::UnixConnected { rx, tx, .. }
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
                // Readable when an unread uevent is waiting AND this socket
                // joined the kernel uevent group; always writable (the udev
                // monitor is read-only but POLL_OUT is harmless). A
                // non-member must never be reported readable: recv would
                // answer EAGAIN and a level-triggered poller would spin.
                let mut bits = narf_filesystem::POLL_OUT;
                if self.netlink_uevent_subscribed.load(Ordering::Acquire) && reader.has_pending() {
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
            SocketState::NetlinkAudit { replies } => {
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

    fn poll_edge_token(&self) -> (u64, u64) {
        match &*self.state.lock() {
            SocketState::UnixConnected { rx, tx, .. }
            | SocketState::InetConnected { rx, tx, .. }
            | SocketState::Inet6Connected { rx, tx, .. } => {
                (rx.readable_token(), tx.writable_token())
            }
            SocketState::UnixDgram { .. } | SocketState::InetDgram { .. } => {
                (self.dgram_readable_token.load(Ordering::Acquire), 0)
            }
            SocketState::UnixListener { .. } => {
                (self.listener_readable_token.load(Ordering::Acquire), 0)
            }
            SocketState::NetlinkUevent { reader } => {
                // No membership, no edge: an unsubscribed monitor must not
                // advance its EPOLLET token on traffic it cannot receive.
                let rx_tok = if self.netlink_uevent_subscribed.load(Ordering::Acquire)
                    && reader.has_pending()
                {
                    narf_filesystem::uevent_current_seqnum()
                } else {
                    0
                };
                (rx_tok, 0)
            }
            SocketState::NetlinkRoute { replies }
            | SocketState::NetlinkGeneric { replies }
            | SocketState::NetlinkSockDiag { replies }
            | SocketState::NetlinkNetfilter { replies }
            | SocketState::NetlinkAudit { replies } => {
                let rx_tok = if !replies.is_empty() {
                    self.netlink_readable_token.load(Ordering::Acquire)
                } else {
                    0
                };
                (rx_tok, 0)
            }
            _ => (0, 0),
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
            | SocketState::NetlinkNetfilter { replies }
            | SocketState::NetlinkAudit { replies } => replies.front().map(Vec::len).unwrap_or(0),
            // A non-member of the kernel uevent group has nothing queued to
            // report, so SIOCINQ is 0 — matching the EAGAIN its recv gives.
            SocketState::NetlinkUevent { reader }
                if self.netlink_uevent_subscribed.load(Ordering::Acquire) =>
            {
                reader
                    .peek(1)
                    .into_iter()
                    .next()
                    .map(|event| event.to_netlink_bytes().len())
                    .unwrap_or(0)
            }
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
        // A connected AF_UNIX datagram socketpair uses the same crossed-ring
        // state as stream/seqpacket pairs, but retains datagram record
        // semantics in `do_send`/the Unix-connected recv branch. Named
        // datagram sockets still use the address-registry dispatcher.
        if self.domain == AF_UNIX
            && self.kind == SOCK_DGRAM
            && matches!(&*self.state.lock(), SocketState::UnixConnected { .. })
        {
            return self.dispatch_unix_stream(op);
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
            (AF_NETLINK, _) if self.protocol == NETLINK_AUDIT => self.dispatch_netlink_audit(op),
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
                let dest_portid = self.ensure_netlink_portid();
                let sent = buf.len() as u64;
                let admin = self.netlink_admin.lock().clone();
                let mut msgs = match narf_net::netlink_route::build_replies_with_options_in(
                    self.net_ns_id(),
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
                Self::stamp_netlink_reply_portid(&mut msgs, dest_portid);
                let reply_count = msgs.len();
                {
                    let mut g = self.state.lock();
                    match &mut *g {
                        SocketState::NetlinkRoute { replies } => {
                            replies.extend(msgs);
                            self.queue_netlink_reply_groups(reply_count);
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
                        self.note_netlink_receive(flags);
                        self.record_queued_netlink_group(flags);
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
                let dest_portid = self.ensure_netlink_portid();
                let mut replies = match narf_net::netlink_generic::build_replies_with_options(
                    buf,
                    narf_net::netlink_generic::ReplyOptions {
                        ext_ack: self.netlink_ext_ack.load(Ordering::Acquire),
                        cap_ack: self.netlink_cap_ack.load(Ordering::Acquire),
                    },
                ) {
                    Ok(replies) => replies,
                    Err(()) => return SocketOpResult::Err(SockError::InvalidArg),
                };
                Self::stamp_netlink_reply_portid(&mut replies, dest_portid);
                let reply_count = replies.len();
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::NetlinkGeneric { replies: queue } => {
                        queue.extend(replies);
                        self.queue_netlink_reply_groups(reply_count);
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
                        self.note_netlink_receive(flags);
                        self.record_queued_netlink_group(flags);
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
                let dest_portid = self.ensure_netlink_portid();
                let mut replies =
                    match narf_net::netlink_diag::build_replies_in(self.net_ns_id(), buf) {
                        Ok(replies) => replies,
                        Err(()) => return SocketOpResult::Err(SockError::InvalidArg),
                    };
                Self::stamp_netlink_reply_portid(&mut replies, dest_portid);
                let reply_count = replies.len();
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::NetlinkSockDiag { replies: queue } => {
                        queue.extend(replies);
                        self.queue_netlink_reply_groups(reply_count);
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
                        self.note_netlink_receive(flags);
                        self.record_queued_netlink_group(flags);
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
                let dest_portid = self.ensure_netlink_portid();
                let admin = self.netfilter_admin.lock().clone();
                let mut replies = match narf_net::netlink_netfilter::build_replies_authorized(
                    self.net_ns_id(),
                    buf,
                    admin.as_ref(),
                ) {
                    Ok(replies) => replies,
                    Err(()) => return SocketOpResult::Err(SockError::InvalidArg),
                };
                Self::stamp_netlink_reply_portid(&mut replies, dest_portid);
                let reply_count = replies.len();
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::NetlinkNetfilter { replies: queue } => {
                        queue.extend(replies);
                        self.queue_netlink_reply_groups(reply_count);
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
                        self.note_netlink_receive(flags);
                        self.record_queued_netlink_group(flags);
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

    fn dispatch_netlink_audit(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => self.bind_netlink(&addr),
            SocketOp::Connect { addr } => self.connect_netlink(&addr),
            SocketOp::Send { buf, addr, .. } => {
                if let Some(result) = self.send_netlink_user(buf, addr.as_ref()) {
                    return result;
                }
                let dest_portid = self.ensure_netlink_portid();
                let mut replies = match narf_net::netlink_audit::build_replies(buf) {
                    Ok(replies) => replies,
                    Err(()) => return SocketOpResult::Err(SockError::InvalidArg),
                };
                Self::stamp_netlink_reply_portid(&mut replies, dest_portid);
                let reply_count = replies.len();
                let mut state = self.state.lock();
                match &mut *state {
                    SocketState::NetlinkAudit { replies: queue } => {
                        queue.extend(replies);
                        self.queue_netlink_reply_groups(reply_count);
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
                        SocketState::NetlinkAudit { replies } => {
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
                        self.note_netlink_receive(flags);
                        self.record_queued_netlink_group(flags);
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
                // Kernel multicast reaches group-1 members only. A socket
                // that never bound, or bound with nl_groups=0 (udev's
                // MONITOR_GROUP_NONE worker monitor), is not on `mc_list`
                // and sees an empty queue — EAGAIN, not somebody else's
                // coldplug replay.
                if !self.netlink_uevent_subscribed.load(Ordering::Acquire) {
                    return SocketOpResult::Err(SockError::WouldBlock);
                }
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
                        // Boot-bringup diagnostic: WHO consumes each coldplug
                        // uevent. "udevd was never handed the DRM add" and
                        // "udevd read it and wrote no database" are the two
                        // halves of the udev seat failure and are otherwise
                        // indistinguishable — udevd's own log is unavailable
                        // when journald has not started. Bounded by a hard
                        // line budget so it can never become the stall it is
                        // meant to explain.
                        #[cfg(feature = "unix-latency-trace")]
                        {
                            use core::fmt::Write as _;
                            static SHOWN: core::sync::atomic::AtomicU32 =
                                core::sync::atomic::AtomicU32::new(0);
                            // Generous: a 64-line budget was spent almost
                            // entirely by PID 1's own monitor before udevd
                            // started, which made udevd look like it read two
                            // events and stopped. A capped probe going quiet
                            // is indistinguishable from the thing it watches
                            // going quiet.
                            const BUDGET: u32 = 4000;
                            if SHOWN.fetch_add(1, Ordering::Relaxed) < BUDGET {
                                let task = crate::handlers::current_task_id();
                                let comm = crate::handlers::proc_comm_of_task(task)
                                    .unwrap_or_else(|| alloc::string::String::from("?"));
                                let _ = writeln!(
                                    narf_console::Writer,
                                    "  uevent-rx: sock={:x} tid={} comm={} seq={} {}@{}",
                                    Arc::as_ptr(self) as *const () as usize & 0xffffff,
                                    task,
                                    comm,
                                    env.seqnum,
                                    env.action.as_str(),
                                    env.devpath
                                );
                            }
                        }
                        self.note_netlink_receive(flags);
                        self.netlink_last_recv_group.store(1, Ordering::Release);
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

    /// User-to-user transport for an AF_NETLINK protocol with no registered
    /// kernel endpoint. Binding and port-ID delivery remain available, while
    /// a request addressed to port ID zero reports `ECONNREFUSED` instead of
    /// silently discarding control-plane data.
    fn dispatch_netlink_sink(self: &Arc<Self>, op: SocketOp<'_>) -> SocketOpResult {
        match op {
            SocketOp::Bind { addr } => self.bind_netlink(&addr),
            SocketOp::Connect { addr } => self.connect_netlink(&addr),
            SocketOp::Send { buf, addr, .. } => {
                if let Some(result) = self.send_netlink_user(buf, addr.as_ref()) {
                    return result;
                }
                self.ensure_netlink_portid();
                SocketOpResult::Err(SockError::ConnectionRefused)
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
                    if value == 0 {
                        return SocketOpResult::Err(SockError::InvalidArg);
                    }
                    if name == NETLINK_ADD_MEMBERSHIP {
                        self.netlink_memberships.lock().insert(value);
                    } else {
                        self.netlink_memberships.lock().remove(&value);
                    }
                    if value <= 32 {
                        let bit = 1u32 << (value - 1);
                        if name == NETLINK_ADD_MEMBERSHIP {
                            self.netlink_groups.fetch_or(bit, Ordering::AcqRel);
                        } else {
                            self.netlink_groups.fetch_and(!bit, Ordering::AcqRel);
                        }
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
            (SOL_SOCKET, SO_PEERGROUPS) => {
                let groups = self.peer_groups();
                let needed = groups.len().saturating_mul(4);
                if buf.len() < needed {
                    return SocketOpResult::Err(SockError::Range);
                }
                for (slot, gid) in buf.chunks_exact_mut(4).zip(groups) {
                    slot.copy_from_slice(&gid.to_ne_bytes());
                }
                SocketOpResult::OptValue { n: needed }
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
            (SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS) => {
                // Linux reports the FULL required byte length in optlen (so a
                // NULL/short-buffer probe can size its allocation) while only
                // filling as many bytes of the bitmap as the caller's buffer
                // holds. `OptValue { n }` therefore carries the required
                // length, not the bytes written; the syscall handler copies
                // `min(n, in_len)` bytes back and writes `n` into optlen.
                let memberships = self.netlink_memberships.lock();
                let words = memberships
                    .last()
                    .map(|group| (*group as usize).div_ceil(32))
                    .unwrap_or(0);
                let required = words * 4;
                let fill = core::cmp::min(buf.len() / 4, words) * 4;
                buf[..fill].fill(0);
                for group in memberships.iter().copied() {
                    let word = (group as usize - 1) / 32;
                    let offset = word * 4;
                    if offset >= fill {
                        continue;
                    }
                    let mut value =
                        u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap_or([0; 4]));
                    value |= 1u32 << ((group - 1) % 32);
                    buf[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
                }
                SocketOpResult::OptValue { n: required }
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
                fds: Vec::new(),
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
                        .map(|m| m.contains_key(&UnixPathKey::for_current_path(p)))
                        .unwrap_or(false),
                    UnixAddr::Abstract(n) => ABSTRACT_STREAM
                        .lock()
                        .as_ref()
                        .map(|m| m.contains_key(&(self.net_ns_id(), n.clone())))
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
                        .insert((self.net_ns_id(), n.clone()), self.clone());
                }
                if let UnixAddr::Path(p) = &uaddr {
                    *self.bound_unix_path.lock() = Some(UnixPathKey::for_current_path(p));
                }
                *state = SocketState::UnixBound { addr: uaddr };
                SocketOpResult::Ok(0)
            }
            SocketOp::Listen { backlog: _ } => {
                // SO_PEERCRED on clients of a listening Unix socket reflects
                // the credentials in effect when listen() established the
                // endpoint (important for systemd socket activation).
                self.set_local_cred(crate::handlers::current_ucred());
                self.set_local_groups(crate::handlers::current_groups());
                let mut state = self.state.lock();
                let addr = match &*state {
                    SocketState::UnixBound { addr } => addr.clone(),
                    _ => return SocketOpResult::Err(SockError::InvalidArg),
                };
                *state = SocketState::UnixListener {
                    addr: addr.clone(),
                    pending: VecDeque::new(),
                };
                #[cfg(feature = "unix-latency-trace")]
                self.listen_owner_tid
                    .store(narf_scheduler::current_task_id().raw(), Ordering::Relaxed);
                // Pathname listeners insert into LISTENERS here. Abstract
                // addresses were reserved in bind(), so this is a no-op.
                if let UnixAddr::Path(p) = addr {
                    drop(state);
                    let key = self
                        .bound_unix_path
                        .lock()
                        .clone()
                        .unwrap_or_else(|| UnixPathKey::for_current_path(&p));
                    LISTENERS
                        .lock()
                        .get_or_insert_with(BTreeMap::new)
                        .insert(key, self.clone());
                }
                SocketOpResult::Ok(0)
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
                    UnixAddr::Path(p) => LISTENERS
                        .lock()
                        .as_ref()
                        .and_then(|m| m.get(&UnixPathKey::for_current_path(p)).cloned()),
                    UnixAddr::Abstract(n) => ABSTRACT_STREAM
                        .lock()
                        .as_ref()
                        .and_then(|m| m.get(&(self.net_ns_id(), n.clone())).cloned()),
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
                        local_addr: None,
                    };
                }
                // Credentials: the accepted server end owns the listener's
                // identity, and each end's SO_PEERCRED reports the other's.
                // (The listener process typically inherits/re-owns the
                // accepted fd, so the server end's local_cred = listener's.)
                let listener_cred = listener.local_cred();
                let listener_groups = listener.local_groups();
                // Linux snapshots the connector's effective credentials at
                // connect time. A process may legitimately setuid between
                // socket() and connect(); creation-time credentials would
                // grant D-Bus policy under the wrong identity.
                let client_cred = crate::handlers::current_ucred();
                let client_groups = crate::handlers::current_groups();
                self.set_local_cred(client_cred);
                self.set_local_groups(client_groups.clone());
                server_end.set_local_cred(listener_cred);
                server_end.set_local_groups(listener_groups.clone());
                server_end.set_peer_cred(client_cred);
                server_end.set_peer_groups(client_groups);
                {
                    let mut lst = listener.state.lock();
                    if let SocketState::UnixListener { pending, .. } = &mut *lst {
                        pending.push_back(server_end);
                        listener
                            .listener_readable_token
                            .fetch_add(1, Ordering::Release);
                    } else {
                        return SocketOpResult::Err(SockError::ConnectionRefused);
                    }
                }
                // Wayland/dbus connect-latency diagnostic: stamp WHO connected
                // to WHICH listener path and WHEN, so a slow accept()or is
                // measurable from the serial log (pairs with UNIXACC below).
                //
                // Also available under `unix-latency-trace` alone: the full
                // syscall firehose writes every syscall to the SYNCHRONOUS
                // serial console, which inflates the very gap these two lines
                // measure. Measuring it needs a quiet boot.
                #[cfg(any(feature = "syscall-trace", feature = "unix-latency-trace"))]
                {
                    use core::fmt::Write as _;
                    let comm =
                        crate::handlers::proc_comm_of_task(crate::handlers::current_task_id())
                            .unwrap_or_default();
                    let path = match &uaddr {
                        UnixAddr::Path(p) => p.as_str(),
                        UnixAddr::Abstract(_) => "<abstract>",
                        UnixAddr::Unnamed => "<unnamed>",
                    };
                    let _ = writeln!(
                        narf_console::Writer,
                        "UNIXENQ ms={} from={} path={}",
                        narf_scheduler::narf_time::monotonic_ns() / 1_000_000,
                        comm,
                        path,
                    );
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
                    SocketState::Fresh | SocketState::UnixBound { .. } => {
                        let local_addr = match &*state {
                            SocketState::UnixBound { addr } => Some(addr.clone()),
                            _ => None,
                        };
                        *state = SocketState::UnixConnected {
                            tx: a_to_b,
                            rx: b_to_a,
                            local_addr,
                        };
                        drop(state);
                        self.set_peer_cred(listener_cred);
                        self.set_peer_groups(listener_groups);
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
            SocketOp::Recv { buf, flags }
                if self.kind == SOCK_SEQPACKET || self.kind == SOCK_DGRAM =>
            {
                let state = self.state.lock();
                let rx = match &*state {
                    SocketState::UnixConnected { rx, .. } => rx.clone(),
                    _ => return SocketOpResult::Err(SockError::NotConnected),
                };
                drop(state);
                match rx.read_packet(buf, flags & MSG_PEEK != 0) {
                    Some((copied, full_len)) if copied < full_len => {
                        SocketOpResult::ReceivedTruncated {
                            copied,
                            full_len,
                            peer: None,
                        }
                    }
                    Some((n, _)) => SocketOpResult::Received { n, peer: None },
                    None if rx.is_closed() => SocketOpResult::Received { n: 0, peer: None },
                    None => SocketOpResult::Err(SockError::WouldBlock),
                }
            }
            SocketOp::Recv { buf, flags } => match self.do_recv(buf, flags) {
                Ok((n, peer)) => SocketOpResult::Received { n, peer },
                Err(e) => SocketOpResult::Err(e),
            },
            SocketOp::Shutdown { how } => {
                let state = self.state.lock();
                match &*state {
                    SocketState::UnixConnected { tx, rx, .. } => {
                        if how == SHUT_WR || how == SHUT_RDWR {
                            tx.close();
                        }
                        if how == SHUT_RD || how == SHUT_RDWR {
                            rx.close();
                        }
                        drop(state);
                        // Explicit shutdown must wake an infinite-timeout
                        // poll/epoll waiter just like final descriptor close.
                        narf_net::readiness::notify(0);
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
                            if let Ok(id) = narf_net::tcp_stack::listen_in(
                                self.net_ns_id(),
                                a,
                                port,
                                backlog.max(1) as usize,
                            ) {
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
                        child.set_net_ns_id(self.net_ns_id());
                        #[cfg(feature = "container")]
                        if let Some(namespace) = self.net_namespace.lock().clone() {
                            child.set_net_namespace(namespace);
                        }
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
                            match narf_net::tcp_stack::connect_in(self.net_ns_id(), ip_bytes, port)
                            {
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
                        drop(state);
                        narf_net::readiness::notify(0);
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
                    fds: Vec::new(),
                };
                let mut ds = dest_sock.state.lock();
                let delivered = if let SocketState::InetDgram { inbox, .. } = &mut *ds {
                    inbox.push_back(pkt);
                    true
                } else {
                    false // no bound InetDgram at the destination — dropped
                };
                drop(ds);
                if delivered {
                    dest_sock
                        .dgram_readable_token
                        .fetch_add(1, Ordering::Release);
                    // Wake a reader parked in poll/epoll on the destination.
                    // Without this a peer blocked in epoll_wait(-1)/poll(-1) on
                    // a bound UDP socket never wakes for a loopback datagram —
                    // an infinite-timeout park breaks only on the readiness
                    // generation bump, and the ~10 ms backstop re-checks the
                    // park condition without re-running the readiness scan.
                    // Mirrors the AF_UNIX dgram send path (dispatch_unix_dgram).
                    narf_net::readiness::notify(0);
                }
                SocketOpResult::Ok(buf.len() as u64)
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
        self.dispatch_unix_dgram_with_fds(op, Vec::new())
    }

    fn dispatch_unix_dgram_with_fds(
        self: &Arc<Self>,
        op: SocketOp<'_>,
        fds: Vec<ScmRightsFile>,
    ) -> SocketOpResult {
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
                        let key = UnixPathKey::for_current_path(p);
                        let mut bound = UNIX_DGRAM_BOUND.lock();
                        let map = bound.get_or_insert_with(BTreeMap::new);
                        if map.contains_key(&key) {
                            return SocketOpResult::Err(SockError::AddrInUse);
                        }
                        *self.bound_unix_path.lock() = Some(key.clone());
                        map.insert(key, self.clone());
                    }
                    UnixAddr::Abstract(n) => {
                        let mut bound = ABSTRACT_DGRAM.lock();
                        let map = bound.get_or_insert_with(BTreeMap::new);
                        let key = (self.net_ns_id(), n.clone());
                        if map.contains_key(&key) {
                            return SocketOpResult::Err(SockError::AddrInUse);
                        }
                        map.insert(key, self.clone());
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
                if let UnixAddr::Path(p) = &uaddr {
                    *self.connected_unix_path.lock() = Some(UnixPathKey::for_current_path(p));
                } else {
                    *self.connected_unix_path.lock() = None;
                }
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
                let explicit_dest = addr.is_some();
                let state = self.state.lock();
                let (local_addr, dest_addr, connected_path) = match &*state {
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
                        (la.clone(), dest, self.connected_unix_path.lock().clone())
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
                        (None, dest, None)
                    }
                    _ => return SocketOpResult::Err(SockError::NotConnected),
                };
                // SCM_CREDENTIALS names the sender's effective identity at
                // send time, not the identity it had when socket() ran.
                let sender_cred = crate::handlers::current_ucred();
                drop(state);
                let dest_sock = match &dest_addr {
                    UnixAddr::Path(p) => {
                        let key = if explicit_dest {
                            UnixPathKey::for_current_path(p)
                        } else {
                            connected_path.unwrap_or_else(|| UnixPathKey::for_current_path(p))
                        };
                        UNIX_DGRAM_BOUND
                            .lock()
                            .as_ref()
                            .and_then(|m| m.get(&key).cloned())
                    }
                    UnixAddr::Abstract(n) => ABSTRACT_DGRAM
                        .lock()
                        .as_ref()
                        .and_then(|m| m.get(&(self.net_ns_id(), n.clone())).cloned()),
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
                    fds,
                };
                let mut ds = dest_sock.state.lock();
                if let SocketState::UnixDgram { inbox, .. } = &mut *ds {
                    inbox.push_back(pkt);
                    dest_sock
                        .dgram_readable_token
                        .fetch_add(1, Ordering::Release);
                }
                drop(ds);
                // Wake a receiver parked in recv/recvmsg/poll on the dest —
                // sd_notify sends one datagram and PID 1 blocks reading it.
                narf_net::readiness::notify(0);
                SocketOpResult::Ok(buf.len() as u64)
            }
            SocketOp::Recv { buf, flags } => {
                // MSG_PEEK must LOOK without consuming: Linux's
                // `unix_dgram_recvmsg` takes a reference to the skb and leaves
                // it queued. Ignoring the flag and popping destroys the very
                // datagram the caller asked to inspect — and every size-probe
                // consumer peeks first. systemd's `next_datagram_size_fd()` is
                // exactly `recv(fd, NULL, 0, MSG_PEEK|MSG_TRUNC)`, which
                // `sd-device-monitor` calls before every real receive.
                let peek = flags & MSG_PEEK != 0;
                let mut state = self.state.lock();
                if let SocketState::UnixDgram { inbox, .. } = &mut *state {
                    let Some(front) = inbox.front() else {
                        return SocketOpResult::Err(SockError::WouldBlock);
                    };
                    let full_len = front.payload.len();
                    let n = core::cmp::min(buf.len(), full_len);
                    buf[..n].copy_from_slice(&front.payload[..n]);
                    let body = front
                        .peer_unix
                        .clone()
                        .map(|a| a.to_body())
                        .unwrap_or_default();
                    let sender_cred = front.sender_cred;
                    let receiver = crate::handlers::current_task_id();
                    // The udev-manager dispatch sequence, in dequeue order.
                    // `assert(worker->event)` fires while HANDLING a datagram
                    // and aborts before udevd can log which one; the last
                    // line printed here before the abort IS the killer
                    // datagram, with its sender named in both pid spaces.
                    #[cfg(feature = "unix-latency-trace")]
                    if !peek
                        && crate::handlers::proc_comm_of_task_matches(receiver, "systemd-udevd$")
                    {
                        use core::fmt::Write as _;
                        static SHOWN: core::sync::atomic::AtomicU32 =
                            core::sync::atomic::AtomicU32::new(0);
                        if SHOWN.fetch_add(1, Ordering::Relaxed) < 4000 {
                            let outer = front.sender_cred.pid;
                            let inner = crate::handlers::report_pid_to(receiver, outer as u64);
                            let mut txt = alloc::string::String::new();
                            for &b in front.payload.iter().take(40) {
                                txt.push(if b == b'\n' {
                                    '.'
                                } else if b.is_ascii_graphic() || b == b' ' {
                                    b as char
                                } else {
                                    '?'
                                });
                            }
                            let _ = writeln!(
                                narf_console::Writer,
                                "  udevm-rx: outer={outer} inner={inner} payload={txt}"
                            );
                        }
                    }
                    if peek {
                        // Per-message credentials are still reported for a
                        // peek, but the SCM_RIGHTS batch stays attached to the
                        // queued datagram: taking it here would hand the fds
                        // to the peek and leave the real receive with none.
                        self.dgram_recv_ancillary.lock().insert(
                            receiver,
                            DgramRecvAncillary {
                                cred: sender_cred,
                                fds: Vec::new(),
                            },
                        );
                    } else if let Some(pkt) = inbox.pop_front() {
                        // Stash this record's ancillary data against the
                        // RECEIVING TASK so a concurrent receiver's dequeue
                        // cannot overwrite it (see `dgram_recv_ancillary`).
                        self.dgram_recv_ancillary.lock().insert(
                            receiver,
                            DgramRecvAncillary {
                                cred: pkt.sender_cred,
                                fds: pkt.fds,
                            },
                        );
                    }
                    let peer = Some(SockAddr {
                        family: AF_UNIX,
                        body,
                    });
                    // Report the DATAGRAM's real length when it did not fit, so
                    // MSG_TRUNC answers a size probe instead of the truncated
                    // copy length (0 for the zero-byte probe shape).
                    if n < full_len {
                        return SocketOpResult::ReceivedTruncated {
                            copied: n,
                            full_len,
                            peer,
                        };
                    }
                    return SocketOpResult::Received { n, peer };
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
                    drop(state);
                    narf_net::readiness::notify(0);
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
        let n = if self.kind == SOCK_SEQPACKET || self.kind == SOCK_DGRAM {
            tx.write_packet(buf, crate::handlers::current_ucred())
        } else {
            tx.write(buf)
        };
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

    fn do_recv(&self, buf: &mut [u8], flags: u32) -> Result<(usize, Option<SockAddr>), SockError> {
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
        let n = if flags & MSG_PEEK != 0 {
            rx.peek(buf)
        } else {
            rx.read(buf)
        };
        if n == 0 && !buf.is_empty() && !rx.is_closed() {
            Err(SockError::WouldBlock)
        } else {
            Ok((n, None))
        }
    }

    /// AF_UNIX `sendmsg` with an SCM_RIGHTS fd batch: writes `buf` to the
    /// stream and queues `fds` for the peer's next `recvmsg`. Only valid on
    /// a connected AF_UNIX stream socket.
    pub(crate) fn unix_sendmsg(
        &self,
        buf: &[u8],
        fds: Vec<ScmRightsFile>,
    ) -> Result<usize, SockError> {
        let state = self.state.lock();
        let tx = match &*state {
            SocketState::UnixConnected { tx, .. } => tx,
            _ => return Err(SockError::NotConnected),
        };
        if tx.is_closed() {
            return Err(SockError::Pipe);
        }
        let packet = self.kind == SOCK_SEQPACKET || self.kind == SOCK_DGRAM;
        let n = if packet {
            tx.write_packet_with_fds(buf, fds, crate::handlers::current_ucred())
        } else {
            tx.write_stream_with_fds(buf, fds)
        };
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

    /// Send an AF_UNIX datagram with SCM_RIGHTS. `sd_notify` uses this exact
    /// shape for `FDSTORE=1`: descriptor-bearing notification datagrams are
    /// not AF_UNIX streams, so they must bypass `unix_sendmsg`'s stream ring.
    pub(crate) fn unix_dgram_sendmsg(
        self: &Arc<Self>,
        buf: &[u8],
        flags: u32,
        addr: Option<SockAddr>,
        fds: Vec<ScmRightsFile>,
    ) -> Result<usize, SockError> {
        if self.domain != AF_UNIX || self.kind != SOCK_DGRAM {
            return Err(SockError::InvalidArg);
        }
        match self.dispatch_unix_dgram_with_fds(SocketOp::Send { buf, flags, addr }, fds) {
            SocketOpResult::Ok(n) => Ok(n as usize),
            SocketOpResult::Err(e) => Err(e),
            _ => Err(SockError::InvalidArg),
        }
    }

    /// Drop this task's pending datagram ancillary entry outright.
    ///
    /// `read(2)` has no ancillary output, so it wants neither the rights nor
    /// the credentials; without this the entry would linger until the task's
    /// next datagram receive overwrote it.
    pub(crate) fn discard_dgram_recv_ancillary(&self) {
        self.dgram_recv_ancillary
            .lock()
            .remove(&crate::handlers::current_task_id());
    }

    /// Pop the next received SCM_RIGHTS fd batch from an AF_UNIX stream
    /// socket's receive ring (empty for non-unix sockets or when none were
    /// passed).
    pub(crate) fn unix_take_recv_fds(&self) -> Vec<ScmRightsFile> {
        let from_dgram = self
            .dgram_recv_ancillary
            .lock()
            .get_mut(&crate::handlers::current_task_id())
            .map(|a| core::mem::take(&mut a.fds))
            .unwrap_or_default();
        if !from_dgram.is_empty() {
            return from_dgram;
        }
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
    readable_token: AtomicU64,
    writable_token: AtomicU64,
}

struct RingInner {
    buf: Vec<u8>,
    head: usize,
    len: usize,
    /// Record queue for connected SOCK_SEQPACKET/SOCK_DGRAM pairs.
    packets: VecDeque<PacketRecord>,
    packet_bytes: usize,
    /// Ancillary batch attached to the record most recently consumed by
    /// recv/recvmsg. `recvmsg` takes it immediately after the data read.
    delivered_packet_fds: Option<Vec<ScmRightsFile>>,
    delivered_packet_cred: Option<Ucred>,
    /// Monotonic byte positions for stream ancillary association.
    stream_read_seq: u64,
    stream_write_seq: u64,
    /// AF_UNIX stream SCM_RIGHTS is attached to the first byte written by
    /// sendmsg, rather than queued independently of the byte stream.
    stream_controls: VecDeque<StreamControl>,
}

struct PacketRecord {
    data: Vec<u8>,
    fds: Vec<ScmRightsFile>,
    cred: Ucred,
}

struct StreamControl {
    offset: u64,
    fds: Vec<ScmRightsFile>,
}

impl core::fmt::Debug for RingInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RingInner")
            .field("head", &self.head)
            .field("len", &self.len)
            .field("stream_controls", &self.stream_controls.len())
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
                packets: VecDeque::new(),
                packet_bytes: 0,
                delivered_packet_fds: None,
                delivered_packet_cred: None,
                stream_read_seq: 0,
                stream_write_seq: 0,
                stream_controls: VecDeque::new(),
            }),
            closed: AtomicBool::new(false),
            readable_token: AtomicU64::new(0),
            writable_token: AtomicU64::new(0),
        }
    }

    /// Take ancillary rights associated with the most recent receive.
    fn take_fds(&self) -> Option<Vec<ScmRightsFile>> {
        self.inner.lock().delivered_packet_fds.take()
    }

    fn take_delivered_packet_cred(&self) -> Option<Ucred> {
        self.inner.lock().delivered_packet_cred.take()
    }

    fn write(&self, src: &[u8]) -> usize {
        let mut g = self.inner.lock();
        let was_readable = g.len > 0 || !g.packets.is_empty();
        let avail = RING_CAP - g.len;
        let n = core::cmp::min(src.len(), avail);
        for (i, &byte) in src.iter().enumerate().take(n) {
            let pos = (g.head + g.len + i) % RING_CAP;
            g.buf[pos] = byte;
        }
        g.len += n;
        g.stream_write_seq = g.stream_write_seq.saturating_add(n as u64);
        let became_readable = !was_readable && n != 0;
        drop(g);
        if became_readable {
            self.readable_token.fetch_add(1, Ordering::Release);
        }
        n
    }

    fn write_stream_with_fds(&self, src: &[u8], fds: Vec<ScmRightsFile>) -> usize {
        let mut g = self.inner.lock();
        let was_readable = g.len > 0 || !g.packets.is_empty();
        let avail = RING_CAP - g.len;
        let n = core::cmp::min(src.len(), avail);
        if n == 0 {
            return 0;
        }
        let marker = g.stream_write_seq;
        for (i, &byte) in src.iter().enumerate().take(n) {
            let pos = (g.head + g.len + i) % RING_CAP;
            g.buf[pos] = byte;
        }
        g.len += n;
        g.stream_write_seq = g.stream_write_seq.saturating_add(n as u64);
        if !fds.is_empty() {
            g.stream_controls.push_back(StreamControl {
                offset: marker,
                fds,
            });
        }
        let became_readable = !was_readable;
        drop(g);
        if became_readable {
            self.readable_token.fetch_add(1, Ordering::Release);
        }
        n
    }

    fn write_packet(&self, src: &[u8], cred: Ucred) -> usize {
        self.write_packet_with_fds(src, Vec::new(), cred)
    }

    fn write_packet_with_fds(&self, src: &[u8], fds: Vec<ScmRightsFile>, cred: Ucred) -> usize {
        let mut g = self.inner.lock();
        if src.len() > RING_CAP.saturating_sub(g.packet_bytes) {
            return 0;
        }
        g.packets.push_back(PacketRecord {
            data: src.to_vec(),
            fds,
            cred,
        });
        g.packet_bytes += src.len();
        drop(g);
        self.readable_token.fetch_add(1, Ordering::Release);
        src.len()
    }

    fn read(&self, dst: &mut [u8]) -> usize {
        let mut g = self.inner.lock();
        let was_writable = g.len < RING_CAP && g.packet_bytes < RING_CAP;
        g.delivered_packet_fds = None;
        let n = core::cmp::min(dst.len(), g.len);
        for (i, slot) in dst.iter_mut().enumerate().take(n) {
            let pos = (g.head + i) % RING_CAP;
            *slot = g.buf[pos];
        }
        g.head = (g.head + n) % RING_CAP;
        g.len -= n;
        let end = g.stream_read_seq.saturating_add(n as u64);
        let mut delivered = Vec::new();
        while g
            .stream_controls
            .front()
            .is_some_and(|control| control.offset < end)
        {
            if let Some(control) = g.stream_controls.pop_front() {
                delivered.extend(control.fds);
            }
        }
        g.stream_read_seq = end;
        if !delivered.is_empty() {
            g.delivered_packet_fds = Some(delivered);
        }
        let became_writable = !was_writable && n != 0;
        drop(g);
        if became_writable {
            self.writable_token.fetch_add(1, Ordering::Release);
        }
        n
    }

    /// Copy immediately readable bytes without advancing the stream head.
    fn peek(&self, dst: &mut [u8]) -> usize {
        let mut g = self.inner.lock();
        g.delivered_packet_fds = None;
        let n = core::cmp::min(dst.len(), g.len);
        for (i, slot) in dst.iter_mut().enumerate().take(n) {
            *slot = g.buf[(g.head + i) % RING_CAP];
        }
        let end = g.stream_read_seq.saturating_add(n as u64);
        let delivered: Vec<_> = g
            .stream_controls
            .iter()
            .take_while(|control| control.offset < end)
            .flat_map(|control| control.fds.iter().cloned())
            .collect();
        if !delivered.is_empty() {
            g.delivered_packet_fds = Some(delivered);
        }
        n
    }

    /// Read exactly one record, discarding any tail that does not fit.
    /// Returns `(copied, full_record_len)`.
    fn read_packet(&self, dst: &mut [u8], peek: bool) -> Option<(usize, usize)> {
        let mut g = self.inner.lock();
        let was_writable = g.len < RING_CAP && g.packet_bytes < RING_CAP;
        let packet = g.packets.front()?;
        let full = packet.data.len();
        let copied = dst.len().min(full);
        dst[..copied].copy_from_slice(&packet.data[..copied]);
        g.delivered_packet_cred = Some(packet.cred);
        if !peek {
            let packet = g.packets.pop_front().unwrap();
            g.packet_bytes = g.packet_bytes.saturating_sub(full);
            g.delivered_packet_fds = Some(packet.fds);
            let became_writable = !was_writable;
            drop(g);
            if became_writable {
                self.writable_token.fetch_add(1, Ordering::Release);
            }
        }
        Some((copied, full))
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.readable_token.fetch_add(1, Ordering::Release);
        }
    }

    fn readable_token(&self) -> u64 {
        self.readable_token.load(Ordering::Acquire)
    }

    fn writable_token(&self) -> u64 {
        self.writable_token.load(Ordering::Acquire)
    }

    fn has_data(&self) -> bool {
        let g = self.inner.lock();
        g.len > 0 || !g.packets.is_empty()
    }

    /// Buffered byte count — backs `SIOCINQ`/`FIONREAD` on a stream socket.
    fn len(&self) -> usize {
        let g = self.inner.lock();
        g.packets
            .front()
            .map(|packet| packet.data.len())
            .unwrap_or(g.len)
    }

    fn has_space(&self) -> bool {
        let g = self.inner.lock();
        g.len < RING_CAP && g.packet_bytes < RING_CAP
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

static LISTENERS: IrqSafeSpinLock<Option<BTreeMap<UnixPathKey, Arc<SocketFile>>>> =
    IrqSafeSpinLock::new(None);

/// `unix-latency-trace` starved-accept attribution sweep, called from the
/// stall watchdog's ~1 s window tick.
///
/// The `UNIXENQ`/`UNIXACC` pair measures how long a `connect()` waited for
/// its `accept()`, but a long gap has three mutually exclusive causes and
/// the timestamps alone cannot tell them apart. This prints, for every
/// named AF_UNIX listener with a non-empty pending queue, the listener's
/// own poll readiness plus the park state of the task that called
/// `listen()`:
///
///   * `ready` WITHOUT `POLLIN` (0x1) while `n > 0` — a poll_mask bug,
///     right here: the queue is non-empty and the scan says otherwise, so
///     no amount of waking helps.
///   * `parked=1` with CLIMBING `scans` across repeated sweeps — the
///     acceptor's poll re-scan keeps running and keeps not returning this
///     listener. Kernel readiness bug (and `ready` above says which half).
///   * `parked=1` with FROZEN `scans` and `checks` — the acceptor is in a
///     park that never re-fires. Lost wake.
///   * `parked=1` with `futex != 0`, or `pnfds=0` — the acceptor is
///     blocked in a NON-poll wait, so this listener is in no polled set at
///     all. The starvation is the acceptor's own event loop, not the
///     AF_UNIX wake path.
///   * `parked=0` with a climbing `scans` — it is running and simply has
///     not got round to accepting.
///
/// Every lock here is `try_lock`: the sweep runs in the timer trap, which
/// can interrupt a CPU already holding any of them. A skipped sample is
/// the correct outcome there — blocking would deadlock the machine we are
/// trying to observe.
impl SocketFile {
    /// Record the fd `listen()` was called on. See `listen_owner_fd`.
    #[cfg(feature = "unix-latency-trace")]
    pub fn set_listen_owner_fd(&self, fd: u32) {
        self.listen_owner_fd.store(fd, Ordering::Relaxed);
    }
}

#[cfg(feature = "unix-latency-trace")]
pub fn unix_listener_stall_sweep() {
    use core::fmt::Write as _;
    let Some(guard) = LISTENERS.try_lock() else {
        return;
    };
    let listeners: Vec<(String, Arc<SocketFile>)> = guard
        .as_ref()
        .map(|m| m.iter().map(|(k, v)| (k.name.clone(), v.clone())).collect())
        .unwrap_or_default();
    drop(guard);
    let now_ms = narf_scheduler::narf_time::monotonic_ns() / 1_000_000;
    for (name, l) in listeners {
        // Prefer the address recorded in the socket's own state: the
        // registry key's `name` is empty for listeners registered at bind()
        // time (abstract addresses), which is precisely the systemd/KDE
        // shape this sweep is aimed at.
        let (npend, addr) = match l.state.try_lock().as_deref() {
            Some(SocketState::UnixListener { pending, addr }) => (
                pending.len(),
                match addr {
                    UnixAddr::Path(p) => p.clone(),
                    UnixAddr::Abstract(a) => alloc::format!(
                        "<abstract:{}>",
                        a.iter()
                            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                            .collect::<String>()
                    ),
                    UnixAddr::Unnamed => String::from("<unnamed>"),
                },
            ),
            _ => continue,
        };
        if npend == 0 {
            continue;
        }
        let name = if name.is_empty() { addr } else { name };
        let ready = narf_filesystem::FileOps::poll_readiness(&*l);
        let tid = l.listen_owner_tid.load(Ordering::Relaxed);
        let _ = writeln!(
            narf_console::TrapWriter,
            "UNIXPEND ms={now_ms} name={name} n={npend} ready={ready:#x} owner_tid={tid} owner_fd={}",
            l.listen_owner_fd.load(Ordering::Relaxed) as i32
        );
        let Some(task) = crate::task::task_get(tid) else {
            let _ = writeln!(
                narf_console::TrapWriter,
                "UNIXPEND-OWNER name={name} tid={tid} GONE — listener outlived its acceptor"
            );
            continue;
        };
        let uc = &task.uctx;
        let _ = writeln!(
            narf_console::TrapWriter,
            "UNIXPEND-OWNER name={name} tid={tid} pid={} st={} parked={} scans={} checks={} pnfds={} epfd_enc={} netio={} futex={:#x} deadline={:#x}",
            task.pid.load(Ordering::Relaxed),
            task.state.load(Ordering::Relaxed),
            uc.parked_in_syscall.load(Ordering::Relaxed) as u8,
            uc.dbg_poll_scans.load(Ordering::Relaxed),
            uc.dbg_park_checks.load(Ordering::Relaxed),
            uc.poll_wait_nfds.load(Ordering::Relaxed),
            uc.epoll_wait_fd.load(Ordering::Relaxed),
            uc.net_io_wait.load(Ordering::Relaxed) as u8,
            uc.futex_uaddr.load(Ordering::Relaxed),
            uc.sleep_deadline_ns.load(Ordering::Relaxed),
        );

        // The owner above is only who called listen() — under socket
        // activation that is PID 1, NOT the daemon that inherited the fd and
        // actually accepts (dbus-broker / journald). Surface every task that
        // holds an fd to THIS listener object (Arc identity) with its park
        // state, so the census names the real stranded acceptor and the fd it
        // watches. `try_with_table` keeps this a NON-BLOCKING read — a table
        // whose lock the interrupted CPU already holds is skipped, not waited
        // on — which is exactly why `listen_owner_tid` avoided this walk; the
        // try-lock makes it trap-safe.
        let l_ptr = Arc::as_ptr(&l) as *const SocketFile;
        for t2 in narf_scheduler::all_task_ids() {
            let tid2 = t2.0;
            let held_fd = crate::fd::try_with_table(tid2, |tab| {
                tab.open_fd_numbers().into_iter().find(|&fd| {
                    tab.get(fd)
                        .and_then(|e| e.ops.as_any())
                        .and_then(|a| a.downcast_ref::<SocketFile>())
                        .is_some_and(|s| core::ptr::eq(s as *const SocketFile, l_ptr))
                })
            })
            .flatten();
            let Some(fd) = held_fd else {
                continue;
            };
            let Some(task2) = crate::task::task_get(tid2) else {
                continue;
            };
            let uc2 = &task2.uctx;
            let _ = writeln!(
                narf_console::TrapWriter,
                "UNIXPEND-HOLDER name={name} tid={tid2} fd={fd} pid={} st={} parked={} scans={} checks={} pnfds={} epfd_enc={} netio={} deadline={:#x}",
                task2.pid.load(Ordering::Relaxed),
                task2.state.load(Ordering::Relaxed),
                uc2.parked_in_syscall.load(Ordering::Relaxed) as u8,
                uc2.dbg_poll_scans.load(Ordering::Relaxed),
                uc2.dbg_park_checks.load(Ordering::Relaxed),
                uc2.poll_wait_nfds.load(Ordering::Relaxed),
                uc2.epoll_wait_fd.load(Ordering::Relaxed),
                uc2.net_io_wait.load(Ordering::Relaxed) as u8,
                uc2.sleep_deadline_ns.load(Ordering::Relaxed),
            );
        }
    }
}

/// Release a bound AF_UNIX pathname from the stream + dgram registries so
/// the address can be re-bound. Called by `unlink(2)` on a socket path —
/// dbus/wayland `unlink()` a stale socket before re-`bind()`-ing it, and
/// in Linux removing the socket inode frees the address. Returns true if
/// an entry was actually removed (the path was a live bound socket).
pub fn unbind_path(path: &str) -> bool {
    let key = UnixPathKey::for_current_path(path);
    let mut removed = false;
    if let Some(map) = LISTENERS.lock().as_mut() {
        removed |= map.remove(&key).is_some();
    }
    if let Some(map) = UNIX_DGRAM_BOUND.lock().as_mut() {
        removed |= map.remove(&key).is_some();
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
static UNIX_DGRAM_BOUND: IrqSafeSpinLock<Option<BTreeMap<UnixPathKey, Arc<SocketFile>>>> =
    IrqSafeSpinLock::new(None);

// ── Abstract-namespace registries (sun_path[0] == '\0') ─────────
//
// Abstract AF_UNIX sockets have NO filesystem presence. The key is the
// raw name bytes after the leading NUL (may embed NULs / non-UTF-8), so
// these maps are keyed by `Vec<u8>` rather than the `String` path maps
// above. systemd's $NOTIFY_SOCKET (sd_notify datagram) and the private
// D-Bus stream socket both live here.

/// Abstract-namespace SOCK_STREAM / SOCK_SEQPACKET listeners: name → socket.
type AbstractSocketRegistry = BTreeMap<(u64, Vec<u8>), Arc<SocketFile>>;

static ABSTRACT_STREAM: IrqSafeSpinLock<Option<AbstractSocketRegistry>> =
    IrqSafeSpinLock::new(None);

/// Abstract-namespace SOCK_DGRAM bound sockets: name → socket.
static ABSTRACT_DGRAM: IrqSafeSpinLock<Option<AbstractSocketRegistry>> = IrqSafeSpinLock::new(None);

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
            reg.as_ref()
                .map(|m| m.keys().any(|(_, existing)| existing == &name))
                .unwrap_or(false)
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
        fds: Vec::new(),
    });
    inbox.push_back(DgramPacket {
        peer_unix: None,
        sender_cred: Ucred::default(),
        peer_addr: 0,
        peer_port: 0,
        payload: alloc::vec![0u8; 3], // second datagram: ignored by SIOCINQ
        fds: Vec::new(),
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

/// SCM_RIGHTS belongs to the AF_UNIX message, not just stream sockets.
/// systemd's sd_notify FDSTORE path sends an unconnected datagram carrying a
/// descriptor; treating that as a stream produces ENOTCONN and prevents the
/// service from completing its READY=1 handshake.
fn smoke_unix_dgram_scm_rights_delivers_per_datagram() -> TestResult {
    let receiver = SocketFile::new(AF_UNIX, SOCK_DGRAM);
    let sender = SocketFile::new(AF_UNIX, SOCK_DGRAM);
    let addr = SockAddr {
        family: AF_UNIX,
        body: b"\0narf-test-fdstore".to_vec(),
    };
    if !matches!(
        receiver.dispatch_op(SocketOp::Bind { addr: addr.clone() }),
        SocketOpResult::Ok(0)
    ) {
        return TestResult::Fail("failed to bind AF_UNIX datagram receiver");
    }
    let passed: Arc<dyn FileOps> = SocketFile::new(AF_UNIX, SOCK_STREAM);
    let passed_right = ScmRightsFile {
        ops: passed.clone(),
        status_flags: 0,
    };
    match sender.unix_dgram_sendmsg(b"FDSTORE=1", 0, Some(addr), alloc::vec![passed_right]) {
        Ok(n) if n == b"FDSTORE=1".len() => {}
        _ => return TestResult::Fail("SCM_RIGHTS AF_UNIX datagram send failed"),
    }
    let mut payload = [0u8; 32];
    match receiver.dispatch_op(SocketOp::Recv {
        buf: &mut payload,
        flags: 0,
    }) {
        SocketOpResult::Received { n, .. } if &payload[..n] == b"FDSTORE=1" => {}
        _ => return TestResult::Fail("AF_UNIX datagram payload was not delivered"),
    }
    let received = receiver.unix_take_recv_fds();
    if received.len() != 1 || !Arc::ptr_eq(&received[0].ops, &passed) {
        return TestResult::Fail("AF_UNIX datagram SCM_RIGHTS batch was not delivered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    smoke_unix_dgram_scm_rights_delivers_per_datagram
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

fn smoke_unregistered_netlink_kernel_send_is_refused() -> TestResult {
    let sock = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, 31);
    match sock.dispatch_op(SocketOp::Send {
        buf: b"unsupported-kernel-request",
        flags: 0,
        addr: None,
    }) {
        SocketOpResult::Err(SockError::ConnectionRefused) => TestResult::Pass,
        _ => TestResult::Fail("unregistered netlink kernel endpoint silently accepted a send"),
    }
}
kernel_test_in!(
    "userspace/socket",
    smoke_unregistered_netlink_kernel_send_is_refused
);

/// systemd's device manager and systemd-udevd start after NARF queues the
/// distro storage coldplug window. Both need that bounded replay; generic
/// consumers (notably libinput) must remain tail-only.
fn smoke_systemd_netlink_replays_boot_coldplug_only() -> TestResult {
    use crate::handlers::{current_task_id, set_proc_comm};

    narf_filesystem::uevent::__reset_for_test();
    narf_filesystem::uevent::emit(
        narf_filesystem::uevent::UeventAction::Add,
        alloc::string::String::from("/devices/early/stale"),
        alloc::string::String::from("early"),
    );
    narf_filesystem::uevent::begin_boot_udevd_replay();
    narf_filesystem::uevent::emit(
        narf_filesystem::uevent::UeventAction::Add,
        alloc::string::String::from("/devices/virtual/block/smoke-efi"),
        alloc::string::String::from("block"),
    );

    let task = current_task_id();
    set_proc_comm(task, "systemd-udevd");
    let udevd = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    let udevd_event = match &*udevd.state.lock() {
        SocketState::NetlinkUevent { reader } => reader.peek(1).into_iter().next(),
        _ => None,
    };

    set_proc_comm(task, "systemd");
    let manager = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    let manager_event = match &*manager.state.lock() {
        SocketState::NetlinkUevent { reader } => reader.peek(1).into_iter().next(),
        _ => None,
    };

    set_proc_comm(task, "libinput");
    let generic = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    let generic_pending = match &*generic.state.lock() {
        SocketState::NetlinkUevent { reader } => reader.has_pending(),
        _ => true,
    };

    narf_filesystem::uevent::__reset_for_test();
    set_proc_comm(task, "");
    if udevd_event.as_ref().map(|event| event.devpath.as_str())
        != Some("/devices/virtual/block/smoke-efi")
    {
        return TestResult::Fail(
            "systemd-udevd did not receive only the bounded boot coldplug window",
        );
    }
    if manager_event.as_ref().map(|event| event.devpath.as_str())
        != Some("/devices/virtual/block/smoke-efi")
    {
        return TestResult::Fail("systemd did not receive the bounded boot coldplug window");
    }
    if generic_pending {
        return TestResult::Fail("generic uevent monitor replayed stale boot events");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    smoke_systemd_netlink_replays_boot_coldplug_only
);

/// EVERY replay-eligible monitor must receive the bounded boot-coldplug
/// window — including the second one a single task opens.
///
/// PID 1 opens two `NETLINK_KOBJECT_UEVENT` sockets and they have different
/// jobs: one is its own device manager's monitor, the other is the listening
/// fd for `systemd-udevd-kernel.socket`, which is handed to `systemd-udevd`
/// by socket activation. They are indistinguishable at `socket()` time — same
/// task, same comm, same protocol — so any rule that grants the replay window
/// "once per consumer" starves whichever one happens to be created second.
///
/// That is not hypothetical: an earlier attempt at a once-per-consumer grant
/// did exactly this. udevd's inherited socket started at the ring TAIL
/// (seqnum 11 in the Fedora gate) instead of the replay boundary (2), so it
/// never saw `add@/devices/platform/narf-drm/card0` at seqnum 3 — the single
/// event the whole udev seat gate depends on. Reverted, and pinned here.
///
/// Duplicate delivery to a FRESH monitor is harmless — it has consumed
/// nothing — so erring toward re-delivery is the safe direction. If a udevd
/// monitor-churn fix is ever needed, it must key on something that actually
/// distinguishes these two sockets, not on the opening task.
fn smoke_boot_coldplug_replay_reaches_every_eligible_monitor() -> TestResult {
    use crate::handlers::{current_task_id, set_proc_comm};

    narf_filesystem::uevent::__reset_for_test();
    narf_filesystem::uevent::begin_boot_udevd_replay();
    narf_filesystem::uevent::emit(
        narf_filesystem::uevent::UeventAction::Add,
        alloc::string::String::from("/devices/platform/narf-drm/card0"),
        alloc::string::String::from("drm"),
    );

    let task = current_task_id();
    set_proc_comm(task, "systemd");

    // PID 1's own device-manager monitor.
    let manager = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    // The listening fd for systemd-udevd-kernel.socket, opened by the SAME
    // task moments later and later handed to udevd.
    let activation = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);

    let first = match &*manager.state.lock() {
        SocketState::NetlinkUevent { reader } => reader.peek(1).into_iter().next(),
        _ => None,
    };
    let second = match &*activation.state.lock() {
        SocketState::NetlinkUevent { reader } => reader.peek(1).into_iter().next(),
        _ => None,
    };

    narf_filesystem::uevent::__reset_for_test();
    set_proc_comm(task, "");

    if first.as_ref().map(|e| e.devpath.as_str()) != Some("/devices/platform/narf-drm/card0") {
        return TestResult::Fail("PID 1's own uevent monitor missed the boot coldplug window");
    }
    if second.as_ref().map(|e| e.devpath.as_str()) != Some("/devices/platform/narf-drm/card0") {
        return TestResult::Fail(
            "the socket-activation uevent fd missed the boot coldplug window (udevd would never see the DRM ADD)",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    smoke_boot_coldplug_replay_reaches_every_eligible_monitor
);

/// A userspace multicast send must REACH the group's subscribers.
///
/// This is task #12's root cause. `send_netlink_user` used to answer any
/// `nl_groups != 0` with `NotSupported`, which is what udevd hit after every
/// processed device:
///
/// ```text
/// sd-device-monitor(manager): Failed to send device to netlink monitor:
///     Operation not supported
/// Failed to broadcast event (SEQNUM=23) to libudev listeners
/// Worker [20] exited with return code 1.
/// Event loop failed: Operation not supported
/// ```
///
/// That killed udevd's event loop, so `/run/udev/data` stayed empty, no input
/// device got a `seat` tag, libinput enumerated nothing, and the Wayland seat
/// came up keyboard-only — the dead mouse.
///
/// Linux permits this: `netlink_sendmsg` gates multicast on
/// `netlink_allowed(sock, NL_CFG_F_NONROOT_SEND)` and refuses with EPERM, not
/// EOPNOTSUPP; udevd holds CAP_NET_ADMIN and is allowed.
///
/// The peer-group assertion is not decoration. libudev's
/// `device_monitor_receive_device` treats a message arriving with
/// `nl_groups == 0` as an untrusted UNICAST and discards it, so delivering
/// the bytes while reporting group 0 would leave udev just as broken while
/// making this test pass. Linux reports
/// `netlink_group_mask(NETLINK_CB(skb).dst_group)`.
fn smoke_netlink_multicast_broadcast_reaches_group_subscriber() -> TestResult {
    const UDEV_GROUP_MASK: u32 = 2; // MONITOR_GROUP_UDEV
    let sender = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    let listener = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);

    if !matches!(
        listener.dispatch_op(SocketOp::Bind {
            addr: SocketFile::netlink_sockaddr(0, UDEV_GROUP_MASK),
        }),
        SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("listener could not bind to the udev multicast group");
    }

    let payload = b"add@/devices/platform/narf-input/input1/event1";
    match sender.dispatch_op(SocketOp::Send {
        buf: payload,
        flags: 0,
        addr: Some(SocketFile::netlink_sockaddr(0, UDEV_GROUP_MASK)),
    }) {
        SocketOpResult::Ok(n) if n == payload.len() as u64 => {}
        // The exact pre-fix failure.
        SocketOpResult::Err(SockError::NotSupported) => {
            return TestResult::Fail(
                "multicast send returned NotSupported — udevd's event loop dies here",
            )
        }
        _ => return TestResult::Fail("multicast send did not report the full payload length"),
    }

    let mut buf = [0u8; 128];
    let peer = match listener.dispatch_op(SocketOp::Recv {
        buf: &mut buf,
        flags: 0,
    }) {
        SocketOpResult::Received { n, peer } => {
            if n != payload.len() || &buf[..n] != payload {
                return TestResult::Fail("subscriber received the wrong broadcast bytes");
            }
            peer
        }
        _ => return TestResult::Fail("group subscriber never received the broadcast"),
    };
    match peer.as_ref().and_then(SocketFile::netlink_addr) {
        Some((_, groups)) if groups == UDEV_GROUP_MASK => TestResult::Pass,
        Some((_, 0)) => TestResult::Fail(
            "broadcast reported nl_groups=0 — libudev discards that as untrusted unicast",
        ),
        _ => TestResult::Fail("broadcast reported the wrong nl_groups to the receiver"),
    }
}
kernel_test_in!(
    "userspace/socket",
    smoke_netlink_multicast_broadcast_reaches_group_subscriber
);

/// The negative half: a broadcast goes to the group's subscribers and to
/// NOBODY else. Without this, "deliver to every netlink socket" would pass
/// the positive test above while flooding unrelated listeners.
///
/// Covers three exclusions: a socket subscribed to a DIFFERENT group, a
/// socket on a different PROTOCOL, and the sender itself (Linux skips
/// `sk == ssk` in `do_one_broadcast`).
fn smoke_netlink_multicast_skips_nonsubscribers_and_sender() -> TestResult {
    const UDEV_GROUP_MASK: u32 = 2;
    const KERNEL_GROUP_MASK: u32 = 1;
    let sender = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    let other_group = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    let other_proto = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);

    // The sender joins the very group it will broadcast to: even a genuine
    // subscriber must not receive its own broadcast.
    for (sock, mask) in [
        (&sender, UDEV_GROUP_MASK),
        (&other_group, KERNEL_GROUP_MASK),
        (&other_proto, UDEV_GROUP_MASK),
    ] {
        if !matches!(
            sock.dispatch_op(SocketOp::Bind {
                addr: SocketFile::netlink_sockaddr(0, mask),
            }),
            SocketOpResult::Ok(_)
        ) {
            return TestResult::Fail("setup: netlink bind rejected a valid group mask");
        }
    }

    if !matches!(
        sender.dispatch_op(SocketOp::Send {
            buf: b"add@/devices/virtual/should-not-fan-out",
            flags: 0,
            addr: Some(SocketFile::netlink_sockaddr(0, UDEV_GROUP_MASK)),
        }),
        SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("setup: multicast send failed");
    }

    let mut buf = [0u8; 128];
    for (sock, who) in [
        (&sender, "the sender received its own broadcast"),
        (
            &other_group,
            "a different-group subscriber received the broadcast",
        ),
        (
            &other_proto,
            "a different-protocol socket received the broadcast",
        ),
    ] {
        if let SocketOpResult::Received { .. } = sock.dispatch_op(SocketOp::Recv {
            buf: &mut buf,
            flags: 0,
        }) {
            return TestResult::Fail(who);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    smoke_netlink_multicast_skips_nonsubscribers_and_sender
);

fn smoke_netlink_lists_high_membership_groups() -> TestResult {
    let sock = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    for group in [2u32, 65] {
        if !matches!(
            sock.handle_setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group.to_ne_bytes()),
            SocketOpResult::Ok(0)
        ) {
            return TestResult::Fail("NETLINK_ADD_MEMBERSHIP rejected a valid group");
        }
    }
    let mut bitmap = [0u8; 12];
    if !matches!(
        sock.handle_getsockopt(SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, &mut bitmap),
        SocketOpResult::OptValue { n: 12 }
    ) {
        return TestResult::Fail("NETLINK_LIST_MEMBERSHIPS returned the wrong size");
    }
    if u32::from_ne_bytes(bitmap[0..4].try_into().unwrap_or([0; 4])) != 0b10
        || u32::from_ne_bytes(bitmap[8..12].try_into().unwrap_or([0; 4])) != 1
    {
        return TestResult::Fail("NETLINK_LIST_MEMBERSHIPS returned the wrong bitmap");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    smoke_netlink_lists_high_membership_groups
);

// Linux reports the FULL required bitmap length in optlen even when the caller
// passes a buffer too small to hold it (or an empty length-query buffer), so
// callers can size a second read. This backs the sd-netlink probe path.
fn smoke_netlink_list_memberships_reports_required_length() -> TestResult {
    let sock = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    // No groups joined: the length query reports zero and the accessor agrees.
    let mut empty: [u8; 0] = [];
    if !matches!(
        sock.handle_getsockopt(SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, &mut empty),
        SocketOpResult::OptValue { n: 0 }
    ) || sock.netlink_list_memberships_len() != 0
    {
        return TestResult::Fail("empty membership set did not report zero length");
    }
    if !matches!(
        sock.handle_setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &65u32.to_ne_bytes()),
        SocketOpResult::Ok(0)
    ) {
        return TestResult::Fail("NETLINK_ADD_MEMBERSHIP rejected group 65");
    }
    // group 65 needs 3 u32 words = 12 bytes. An empty query still reports 12.
    if !matches!(
        sock.handle_getsockopt(SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, &mut empty),
        SocketOpResult::OptValue { n: 12 }
    ) || sock.netlink_list_memberships_len() != 12
    {
        return TestResult::Fail("length query did not report the required 12 bytes");
    }
    // A short 4-byte buffer still reports the full 12-byte requirement and only
    // fills the word it can hold (word 0, which has no bits for group 65).
    let mut short = [0xFFu8; 4];
    if !matches!(
        sock.handle_getsockopt(SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS, &mut short),
        SocketOpResult::OptValue { n: 12 }
    ) {
        return TestResult::Fail("short buffer did not report the full required length");
    }
    if u32::from_ne_bytes(short) != 0 {
        return TestResult::Fail("short buffer word 0 was not cleared");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    smoke_netlink_list_memberships_reports_required_length
);

fn smoke_netlink_pktinfo_tracks_received_multicast_group() -> TestResult {
    let sock = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    let group = 5u32;
    if !matches!(
        sock.handle_setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group.to_ne_bytes()),
        SocketOpResult::Ok(0)
    ) || !matches!(
        sock.handle_setsockopt(SOL_NETLINK, NETLINK_PKTINFO, &1u32.to_ne_bytes()),
        SocketOpResult::Ok(0)
    ) {
        return TestResult::Fail("failed to configure netlink pktinfo smoke");
    }
    SocketFile::broadcast_netlink_route(1 << (group - 1), b"route-event");
    let mut buf = [0u8; 32];
    if !matches!(
        sock.dispatch_op(SocketOp::Recv {
            buf: &mut buf,
            flags: 0
        }),
        SocketOpResult::Received { n: 11, .. }
    ) {
        return TestResult::Fail("route multicast datagram was not received");
    }
    if sock.netlink_pktinfo() != Some(group) {
        return TestResult::Fail("NETLINK_PKTINFO did not report received multicast group");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    smoke_netlink_pktinfo_tracks_received_multicast_group
);

fn smoke_unix_stream_rights_follow_byte_boundaries() -> TestResult {
    let ring = RingBuf::new();
    let passed: Arc<dyn FileOps> = SocketFile::new(AF_UNIX, SOCK_STREAM);
    let passed_right = ScmRightsFile {
        ops: passed.clone(),
        status_flags: 0,
    };

    if ring.write(b"plain") != 5
        || ring.write_stream_with_fds(b"fd", alloc::vec![passed_right]) != 2
    {
        return TestResult::Fail("failed to seed stream control boundary");
    }

    let mut prefix = [0u8; 5];
    if ring.read(&mut prefix) != 5 || &prefix != b"plain" || ring.take_fds().is_some() {
        return TestResult::Fail("rights escaped before their marker byte");
    }

    let mut first = [0u8; 1];
    if ring.read(&mut first) != 1 || first[0] != b'f' {
        return TestResult::Fail("failed to cross stream control marker");
    }
    let Some(fds) = ring.take_fds() else {
        return TestResult::Fail("rights were not delivered at their marker byte");
    };
    if fds.len() != 1 || !Arc::ptr_eq(&fds[0].ops, &passed) {
        return TestResult::Fail("wrong rights batch delivered at stream marker");
    }
    if ring.take_fds().is_some() {
        return TestResult::Fail("stream rights batch was delivered more than once");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    smoke_unix_stream_rights_follow_byte_boundaries
);

fn smoke_unix_stream_multiple_rights_batches_preserve_order() -> TestResult {
    let ring = RingBuf::new();
    let first: Arc<dyn FileOps> = SocketFile::new(AF_UNIX, SOCK_STREAM);
    let second: Arc<dyn FileOps> = SocketFile::new(AF_UNIX, SOCK_STREAM);
    let first_right = ScmRightsFile {
        ops: first.clone(),
        status_flags: 0,
    };
    let second_right = ScmRightsFile {
        ops: second.clone(),
        status_flags: 0,
    };

    if ring.write_stream_with_fds(b"a", alloc::vec![first_right]) != 1
        || ring.write(b"-") != 1
        || ring.write_stream_with_fds(b"b", alloc::vec![second_right]) != 1
    {
        return TestResult::Fail("failed to seed multiple stream control batches");
    }

    let mut one = [0u8; 1];
    if ring.read(&mut one) != 1 || one[0] != b'a' {
        return TestResult::Fail("failed to consume first marker byte");
    }
    let Some(first_batch) = ring.take_fds() else {
        return TestResult::Fail("first rights batch was missing");
    };
    if first_batch.len() != 1 || !Arc::ptr_eq(&first_batch[0].ops, &first) {
        return TestResult::Fail("first rights batch was reordered");
    }

    let mut tail = [0u8; 2];
    if ring.read(&mut tail) != 2 || &tail != b"-b" {
        return TestResult::Fail("failed to consume second marker range");
    }
    let Some(second_batch) = ring.take_fds() else {
        return TestResult::Fail("second rights batch was missing");
    };
    if second_batch.len() != 1 || !Arc::ptr_eq(&second_batch[0].ops, &second) {
        return TestResult::Fail("second rights batch was reordered or duplicated");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    smoke_unix_stream_multiple_rights_batches_preserve_order
);
