//! Linux syscall ABI conformance — AF_UNIX `SOCK_STREAM` flow control and
//! SCM_RIGHTS record boundaries.
//!
//! The reference is `net/unix/af_unix.c`:
//!
//! - `unix_stream_sendmsg` splits a send into skbs of at most
//!   `min(sk_sndbuf / 2 - 64, SKB_MAX_HEAD(0) + UNIX_SKB_FRAGS_SZ)` bytes.
//!   `sock_alloc_send_pskb` admits each skb while the sender's
//!   `sk_wmem_alloc` (the summed `truesize` of its unread skbs) is below
//!   `sk_sndbuf`, and lets it overshoot. A non-blocking send is therefore
//!   all-or-EAGAIN up to one skb, and short only after a whole skb went out.
//! - `sk_wmem_alloc` drops only when the reader frees a WHOLE skb, and
//!   `unix_writable` reports POLLOUT while `wmem << 2 <= sk_sndbuf`.
//! - `unix_stream_read_generic` stops after an skb carrying SCM_RIGHTS, so
//!   one recvmsg returns at most one rights batch, and the rights arrive
//!   with the first byte of their send.
//!
//! Every expected count below was measured on x86_64 Linux with the default
//! 212992-byte `wmem_default`.
//!
//! Firefox's wayland-proxy forwards each recvmsg chunk (4096 bytes + up to
//! 28 fds) with one non-blocking sendmsg and DROPS whatever a short send did
//! not write. NARF's old stream ring wrote `min(len, free space)`, so a
//! nearly full peer produced exactly that short send, the Wayland stream
//! desynchronised, and libwayland-client aborted Firefox with "Message
//! length 5376 exceeds limit 4096".
//!
//! Sockets are non-blocking: the harness has no user task to park.
use crate::abi_test_support::*;
use alloc::vec::Vec;

const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;
const SOCK_NONBLOCK: u64 = 0o4000;
const SOL_SOCKET: u64 = 1;
const SO_SNDBUF: u64 = 7;
const SCM_RIGHTS: i32 = 1;
const MSG_PEEK: u64 = 0x2;
const MSG_CTRUNC: u32 = 0x8;
const MSG_DONTWAIT: u64 = 0x40;
const MSG_CMSG_CLOEXEC: u64 = 0x4000_0000;
const POLLOUT: u16 = 0x4;
/// libwayland's `MAX_FDS_OUT`, and the wayland-proxy's per-chunk fd limit.
const MAX_FDS: usize = 28;
/// libwayland's and the wayland-proxy's per-chunk byte limit.
const MAX_DATA: usize = 4096;

fn stream_pair() -> Result<(u64, u64), &'static str> {
    let mut sv = [0u8; 8];
    if call(
        Syscall::SocketPair.raw(),
        a3(
            AF_UNIX,
            SOCK_STREAM | SOCK_NONBLOCK,
            0,
            sv.as_mut_ptr() as u64,
        ),
    ) != Some(0)
    {
        return Err("socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK) failed");
    }
    Ok((
        i32::from_ne_bytes(sv[0..4].try_into().unwrap()) as u64,
        i32::from_ne_bytes(sv[4..8].try_into().unwrap()) as u64,
    ))
}

fn close(fd: u64) {
    let _ = call(Syscall::Close.raw(), a0(fd));
}

fn send(fd: u64, buf: &[u8]) -> Result<i64, &'static str> {
    call(
        Syscall::SocketSend.raw(),
        a3(fd, buf.as_ptr() as u64, buf.len() as u64, MSG_DONTWAIT),
    )
    .ok_or("send status")
}

fn recv(fd: u64, buf: &mut [u8], flags: u64) -> Result<i64, &'static str> {
    call(
        Syscall::SocketRecv.raw(),
        a3(fd, buf.as_mut_ptr() as u64, buf.len() as u64, flags),
    )
    .ok_or("recv status")
}

/// `sendmsg(fd, buf, SCM_RIGHTS = fds, flags)`.
fn sendmsg_fds(fd: u64, buf: &[u8], fds: &[i32], flags: u64) -> Result<i64, &'static str> {
    let mut iov = [0u8; 16];
    iov[0..8].copy_from_slice(&(buf.as_ptr() as u64).to_ne_bytes());
    iov[8..16].copy_from_slice(&(buf.len() as u64).to_ne_bytes());
    // CMSG_SPACE(28 * 4) = 16 + 112.
    let mut ctrl = [0u8; 16 + 4 * MAX_FDS];
    let mut msg = [0u8; 56];
    msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
    msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
    if !fds.is_empty() {
        let cmsg_len = 16 + 4 * fds.len();
        ctrl[0..8].copy_from_slice(&(cmsg_len as u64).to_ne_bytes());
        ctrl[8..12].copy_from_slice(&(SOL_SOCKET as i32).to_ne_bytes());
        ctrl[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
        for (i, f) in fds.iter().enumerate() {
            ctrl[16 + 4 * i..20 + 4 * i].copy_from_slice(&f.to_ne_bytes());
        }
        msg[32..40].copy_from_slice(&(ctrl.as_ptr() as u64).to_ne_bytes());
        msg[40..48].copy_from_slice(&(cmsg_len.next_multiple_of(8) as u64).to_ne_bytes());
    }
    call(
        Syscall::SocketSendMsg.raw(),
        a2(fd, msg.as_ptr() as u64, flags),
    )
    .ok_or("sendmsg status")
}

/// `recvmsg(fd, buf, room for 28 fds, flags)` → (bytes, received fds,
/// msg_flags). Received fds are returned for the caller to close/forward.
fn recvmsg_fds(fd: u64, buf: &mut [u8], flags: u64) -> Result<(i64, Vec<i32>, u32), &'static str> {
    let mut iov = [0u8; 16];
    iov[0..8].copy_from_slice(&(buf.as_mut_ptr() as u64).to_ne_bytes());
    iov[8..16].copy_from_slice(&(buf.len() as u64).to_ne_bytes());
    // The proxy's `CMSG_LEN(MAX_LIBWAY_FDS * sizeof(int32_t))`.
    let mut ctrl = [0u8; 16 + 4 * MAX_FDS];
    let mut msg = [0u8; 56];
    msg[16..24].copy_from_slice(&(iov.as_ptr() as u64).to_ne_bytes());
    msg[24..32].copy_from_slice(&1u64.to_ne_bytes());
    msg[32..40].copy_from_slice(&(ctrl.as_mut_ptr() as u64).to_ne_bytes());
    msg[40..48].copy_from_slice(&(ctrl.len() as u64).to_ne_bytes());
    let n = call(
        Syscall::SocketRecvMsg.raw(),
        a2(fd, msg.as_ptr() as u64, flags),
    )
    .ok_or("recvmsg status")?;
    let controllen = u64::from_ne_bytes(msg[40..48].try_into().unwrap()) as usize;
    let msg_flags = u32::from_ne_bytes(msg[48..52].try_into().unwrap());
    let mut fds = Vec::new();
    let mut off = 0;
    while n > 0 && off + 16 <= controllen {
        let len = u64::from_ne_bytes(ctrl[off..off + 8].try_into().unwrap()) as usize;
        let level = i32::from_ne_bytes(ctrl[off + 8..off + 12].try_into().unwrap());
        let kind = i32::from_ne_bytes(ctrl[off + 12..off + 16].try_into().unwrap());
        if len < 16 || off + len > controllen {
            return Err("recvmsg produced a malformed cmsghdr");
        }
        if level == SOL_SOCKET as i32 && kind == SCM_RIGHTS {
            for i in 0..(len - 16) / 4 {
                let p = off + 16 + 4 * i;
                fds.push(i32::from_ne_bytes(ctrl[p..p + 4].try_into().unwrap()));
            }
        }
        off += len.next_multiple_of(8);
    }
    Ok((n, fds, msg_flags))
}

fn pollout(fd: u64) -> Result<bool, &'static str> {
    let mut pfd = [0u8; 8];
    pfd[0..4].copy_from_slice(&(fd as i32).to_ne_bytes());
    pfd[4..6].copy_from_slice(&POLLOUT.to_ne_bytes());
    let r = call(Syscall::Poll.raw(), a2(pfd.as_mut_ptr() as u64, 1, 0)).ok_or("poll status")?;
    Ok(r == 1 && u16::from_ne_bytes(pfd[6..8].try_into().unwrap()) & POLLOUT != 0)
}

/// A spare descriptor to pass as SCM_RIGHTS.
fn passable_fd() -> Result<i32, &'static str> {
    let fd = call(Syscall::SocketOpen.raw(), a2(AF_UNIX, SOCK_STREAM, 0)).ok_or("socket status")?;
    if fd < 0 {
        return Err("socket() for an SCM_RIGHTS payload failed");
    }
    Ok(fd as i32)
}

/// Send `size`-byte chunks until EAGAIN; every send must be complete.
/// Returns how many were accepted.
fn sends_until_eagain(fd: u64, size: usize, limit: usize) -> Result<usize, &'static str> {
    let chunk = alloc::vec![0x5au8; size];
    for count in 0..=limit {
        let r = send(fd, &chunk)?;
        if r == EAGAIN {
            return Ok(count);
        }
        if r != size as i64 {
            return Err("a send of at most one skb was short instead of all-or-EAGAIN");
        }
    }
    Err("the peer accepted more sends than Linux's default sndbuf admits")
}

// ── Flow control ────────────────────────────────────────────────────────

/// A non-blocking stream send of at most one skb is all-or-EAGAIN, and the
/// default sndbuf admits exactly as many as Linux does.
fn smoke_abi_unix_stream_small_send_all_or_eagain() -> TestResult {
    with_setup(|| {
        // (send size, sends Linux accepts before -EAGAIN)
        for (size, linux) in [
            (1usize, 278usize),
            (1000, 93),
            (3000, 49),
            (4096, 44),
            (8192, 24),
            (36544, 6),
        ] {
            let (a, b) = stream_pair()?;
            let got = sends_until_eagain(a, size, linux);
            close(a);
            close(b);
            if got? != linux {
                return Err("non-blocking peer accepted a different number of sends than Linux");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/unix_stream",
    smoke_abi_unix_stream_small_send_all_or_eagain
);

/// A send larger than one skb is short only after at least one whole skb
/// went out, and only once sndbuf is exhausted.
fn smoke_abi_unix_stream_partial_only_after_full_skb() -> TestResult {
    with_setup(|| {
        let (a, b) = stream_pair()?;
        // 300000 bytes into an empty peer: six 36544-byte skbs fit.
        let huge = alloc::vec![0x11u8; 300_000];
        let r = send(a, &huge)?;
        close(a);
        close(b);
        if r != 6 * 36544 {
            return Err("an oversized send did not queue exactly six whole skbs");
        }

        let (a, b) = stream_pair()?;
        let chunk = alloc::vec![0x22u8; 40_000];
        for _ in 0..5 {
            if send(a, &chunk)? != 40_000 {
                close(a);
                close(b);
                return Err("a 40000-byte send short of sndbuf was not complete");
            }
        }
        // The sixth admits its first 36544-byte skb, then sndbuf is spent.
        let sixth = send(a, &chunk)?;
        let seventh = send(a, &chunk)?;
        close(a);
        close(b);
        if sixth != 36544 {
            return Err("a send that exhausted sndbuf did not stop at an skb boundary");
        }
        if seventh != EAGAIN {
            return Err("a send with sndbuf exhausted did not return EAGAIN");
        }
        Ok(())
    })
}
kernel_test_in!(
    "syscall_abi/unix_stream",
    smoke_abi_unix_stream_partial_only_after_full_skb
);

/// The sender's charge drops only when the reader consumes a WHOLE skb;
/// POLLOUT follows `unix_writable` (`wmem << 2 <= sndbuf`).
fn smoke_abi_unix_stream_space_returns_per_whole_skb() -> TestResult {
    with_setup(|| {
        let (a, b) = stream_pair()?;
        let res = (|| {
            if sends_until_eagain(a, 4096, 44)? != 44 {
                return Err("4096-byte fill did not stop where Linux does");
            }
            if pollout(a)? {
                return Err("a sender over its sndbuf reported POLLOUT");
            }
            let mut sink = alloc::vec![0u8; 4096];
            if recv(b, &mut sink[..1], 0)? != 1 {
                return Err("reading one byte failed");
            }
            // One byte of a 4096-byte skb frees nothing.
            if send(a, &sink[..1])? != EAGAIN {
                return Err("reading part of an skb released sender space");
            }
            if recv(b, &mut sink[..4095], 0)? != 4095 {
                return Err("reading the rest of the first skb failed");
            }
            if send(a, &sink)? != 4096 {
                return Err("consuming a whole skb did not release its space");
            }
            // Drain everything: an idle sender is writable again.
            let mut drain = alloc::vec![0u8; 65536];
            while recv(b, &mut drain, 0)? > 0 {}
            if !pollout(a)? {
                return Err("a drained sender did not report POLLOUT");
            }
            Ok(())
        })();
        close(a);
        close(b);
        res
    })
}
kernel_test_in!(
    "syscall_abi/unix_stream",
    smoke_abi_unix_stream_space_returns_per_whole_skb
);

/// SO_SNDBUF governs the skb size and the admission limit (Linux doubles
/// the value; 4096 → 8192, so skbs are 8192/2 - 64 = 4032 bytes).
fn smoke_abi_unix_stream_sndbuf_sets_flow_limit() -> TestResult {
    with_setup(|| {
        let (a, b) = stream_pair()?;
        let res = (|| {
            let v = 4096i32.to_ne_bytes();
            if call(
                Syscall::SocketSetSockOpt.raw(),
                SyscallArgs {
                    arg0: a,
                    arg1: SOL_SOCKET,
                    arg2: SO_SNDBUF,
                    arg3: v.as_ptr() as u64,
                    arg4: 4,
                    arg5: 0,
                },
            ) != Some(0)
            {
                return Err("setsockopt(SO_SNDBUF) failed");
            }
            let payload = alloc::vec![0x33u8; 10_000];
            if send(a, &payload)? != 2 * 4032 {
                return Err("SO_SNDBUF 4096 did not admit exactly two 4032-byte skbs");
            }
            if send(a, &payload[..1])? != EAGAIN {
                return Err("a sender past its SO_SNDBUF did not get EAGAIN");
            }
            let mut sink = alloc::vec![0u8; 4032];
            if recv(b, &mut sink, 0)? != 4032 || pollout(a)? {
                return Err("POLLOUT set while wmem << 2 still exceeds sndbuf");
            }
            if recv(b, &mut sink, 0)? != 4032 || !pollout(a)? {
                return Err("POLLOUT not set once the peer drained every skb");
            }
            Ok(())
        })();
        close(a);
        close(b);
        res
    })
}
kernel_test_in!(
    "syscall_abi/unix_stream",
    smoke_abi_unix_stream_sndbuf_sets_flow_limit
);

// ── SCM_RIGHTS boundaries ───────────────────────────────────────────────

fn expect_recv(
    fd: u64,
    cap: usize,
    want: &[u8],
    want_fds: usize,
    what: &'static str,
) -> Result<(), &'static str> {
    let mut buf = alloc::vec![0u8; cap];
    let (n, fds, _) = recvmsg_fds(fd, &mut buf, MSG_DONTWAIT)?;
    let nfds = fds.len();
    for f in fds {
        close(f as u64);
    }
    if n != want.len() as i64 || &buf[..want.len()] != want || nfds != want_fds {
        return Err(what);
    }
    Ok(())
}

/// One recvmsg returns at most one rights batch and stops at the end of the
/// skb carrying it; fd-less bytes before it are glued on.
fn smoke_abi_unix_stream_recv_stops_after_rights_skb() -> TestResult {
    with_setup(|| {
        let (a, b) = stream_pair()?;
        let fd = passable_fd()?;
        let res = (|| {
            let s = |buf: &[u8], fds: &[i32]| -> Result<(), &'static str> {
                if sendmsg_fds(a, buf, fds, MSG_DONTWAIT)? != buf.len() as i64 {
                    return Err("seeding sendmsg failed");
                }
                Ok(())
            };
            // Two rights batches never merge.
            s(b"aaaa", &[fd])?;
            s(b"bbbb", &[fd])?;
            expect_recv(b, 100, b"aaaa", 1, "recv merged two rights batches")?;
            expect_recv(b, 100, b"bbbb", 1, "second rights batch lost or merged")?;
            // Bytes after a rights skb wait for the next recv.
            s(b"aaaa", &[fd])?;
            s(b"cccc", &[])?;
            expect_recv(b, 100, b"aaaa", 1, "recv ran past a rights skb")?;
            expect_recv(b, 100, b"cccc", 0, "fd-less tail after rights skb wrong")?;
            // Plain bytes before a rights skb are glued on; it then stops.
            s(b"cccc", &[])?;
            s(b"aaaa", &[fd])?;
            s(b"dddd", &[])?;
            expect_recv(
                b,
                100,
                b"ccccaaaa",
                1,
                "recv did not glue plain + rights skb",
            )?;
            expect_recv(b, 100, b"dddd", 0, "tail after glued rights skb wrong")?;
            // A partial read of a rights skb delivers the rights with its first
            // byte; the remainder then reads on into plain bytes.
            s(b"aaaa", &[fd])?;
            s(b"cccc", &[])?;
            expect_recv(b, 2, b"aa", 1, "partial rights-skb read lost its fds")?;
            expect_recv(b, 100, b"aacccc", 0, "remainder of a rights skb wrong")?;
            // MSG_PEEK stops at the rights skb too.
            s(b"aaaa", &[fd])?;
            s(b"cccc", &[])?;
            let mut peek = [0u8; 100];
            if recv(b, &mut peek, MSG_PEEK | MSG_DONTWAIT)? != 4 {
                return Err("MSG_PEEK ran past a rights skb");
            }
            expect_recv(b, 100, b"aaaa", 1, "rights skb after peek wrong")?;
            expect_recv(b, 100, b"cccc", 0, "tail after peeked rights skb wrong")?;
            Ok(())
        })();
        close(fd as u64);
        close(a);
        close(b);
        res
    })
}
kernel_test_in!(
    "syscall_abi/unix_stream",
    smoke_abi_unix_stream_recv_stops_after_rights_skb
);

// ── wayland-proxy forwarder ─────────────────────────────────────────────

struct Rng(u32);
impl Rng {
    fn next(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 17;
        self.0 ^= self.0 << 5;
        self.0
    }
}

fn pattern(seq: u32, i: usize) -> u8 {
    (seq.wrapping_mul(31)
        .wrapping_add(i as u32 * 7)
        .wrapping_add(3)) as u8
}

/// Firefox's wayland-proxy, interleaved deterministically: a libwayland-like
/// writer fills pair A with framed messages (some carrying fds), the proxy
/// forwards each recvmsg chunk (4096 bytes + 28 fds) with ONE non-blocking
/// sendmsg into pair B exactly as `WaylandMessage::Read/Write` do, and a slow
/// reader validates every frame. A short proxy sendmsg (the proxy drops the
/// unsent tail), an MSG_CTRUNC, a bad header, a sequence gap, a corrupt byte
/// or an fd that arrives after its message all fail.
fn smoke_abi_unix_stream_wayland_proxy_forwarder() -> TestResult {
    const MESSAGES: u32 = 6000;
    with_setup(|| {
        let (app, proxy_in) = stream_pair()?;
        let (proxy_out, comp) = stream_pair()?;
        let payload_fd = passable_fd()?;
        let res = (|| {
            let mut rng = Rng(0x1234_5678);
            // Writer state: one libwayland output buffer.
            let mut out: Vec<u8> = Vec::new();
            let mut out_fds: Vec<i32> = Vec::new();
            let mut out_off = 0usize;
            let mut next_seq = 0u32;
            // Proxy state: one pending chunk.
            let mut chunk = alloc::vec![0u8; MAX_DATA];
            let mut chunk_len = 0usize;
            let mut chunk_fds: Vec<i32> = Vec::new();
            // Reader state.
            let mut acc: Vec<u8> = Vec::new();
            let mut fds_have = 0usize;
            let mut expect = 0u32;
            let mut proxy_eagain = 0u32;

            for _round in 0..2_000_000u32 {
                if expect == MESSAGES {
                    break;
                }
                // Writer: refill with whole messages, then flush.
                if out_off == out.len() && next_seq < MESSAGES {
                    out.clear();
                    out_fds.clear();
                    out_off = 0;
                    while next_seq < MESSAGES {
                        let mut size = 8 + 4 * (rng.next() as usize % ((MAX_DATA - 8) / 4 + 1));
                        if rng.next() % 4 != 0 {
                            size = 8 + 4 * (rng.next() as usize % 64);
                        }
                        let nfds = if rng.next() % 8 == 0 {
                            1 + rng.next() as usize % 4
                        } else {
                            0
                        };
                        if out.len() + size > MAX_DATA || out_fds.len() + nfds > MAX_FDS {
                            break;
                        }
                        out.extend_from_slice(&next_seq.to_ne_bytes());
                        out.extend_from_slice(&(((size as u32) << 16) | nfds as u32).to_ne_bytes());
                        let base = out.len() - 8;
                        for i in 8..size {
                            out.push(pattern(next_seq, i));
                        }
                        debug_assert_eq!(out.len() - base, size);
                        out_fds.extend(core::iter::repeat_n(payload_fd, nfds));
                        next_seq += 1;
                    }
                }
                if out_off < out.len() {
                    let r = sendmsg_fds(app, &out[out_off..], &out_fds, MSG_DONTWAIT)?;
                    if r > 0 {
                        out_off += r as usize;
                        out_fds.clear(); // rights ride on the first byte only
                    } else if r != EAGAIN {
                        return Err("writer sendmsg failed");
                    }
                }

                // Proxy: WaylandMessage::Read then ::Write.
                for _ in 0..2 {
                    if chunk_len == 0 {
                        let (n, fds, flags) =
                            recvmsg_fds(proxy_in, &mut chunk, MSG_CMSG_CLOEXEC | MSG_DONTWAIT)?;
                        if flags & MSG_CTRUNC != 0 {
                            return Err("proxy recvmsg saw MSG_CTRUNC (rights batches merged)");
                        }
                        if n == EAGAIN {
                            break;
                        }
                        if n <= 0 {
                            return Err("proxy recvmsg failed");
                        }
                        chunk_len = n as usize;
                        chunk_fds = fds;
                    }
                    let w = sendmsg_fds(
                        proxy_out,
                        &chunk[..chunk_len],
                        &chunk_fds,
                        MSG_CMSG_CLOEXEC | MSG_DONTWAIT,
                    )?;
                    if w == EAGAIN {
                        proxy_eagain += 1;
                        break;
                    }
                    if w != chunk_len as i64 {
                        // The real proxy logs "failed to write all data!" and
                        // drops the tail: the stream is now desynchronised.
                        return Err("proxy sendmsg was short (tail dropped → stream desync)");
                    }
                    for f in chunk_fds.drain(..) {
                        close(f as u64);
                    }
                    chunk_len = 0;
                }

                // Reader: slow and with random buffer sizes.
                if rng.next() % 3 != 0 {
                    continue;
                }
                let cap = 1 + rng.next() as usize % MAX_DATA;
                let mut buf = alloc::vec![0u8; cap];
                let (n, fds, flags) = recvmsg_fds(comp, &mut buf, MSG_DONTWAIT)?;
                if flags & MSG_CTRUNC != 0 {
                    return Err("reader recvmsg saw MSG_CTRUNC");
                }
                if n == EAGAIN {
                    continue;
                }
                if n <= 0 {
                    return Err("reader recvmsg failed");
                }
                fds_have += fds.len();
                for f in fds {
                    close(f as u64);
                }
                acc.extend_from_slice(&buf[..n as usize]);
                let mut off = 0;
                while acc.len() - off >= 8 {
                    let seq = u32::from_ne_bytes(acc[off..off + 4].try_into().unwrap());
                    let w1 = u32::from_ne_bytes(acc[off + 4..off + 8].try_into().unwrap());
                    let size = (w1 >> 16) as usize;
                    let mfds = (w1 & 0xffff) as usize;
                    if !(8..=MAX_DATA).contains(&size) || size % 4 != 0 {
                        return Err("reader: message length exceeds limit (stream desync)");
                    }
                    if seq != expect {
                        return Err("reader: message sequence gap (stream desync)");
                    }
                    if acc.len() - off < size {
                        break;
                    }
                    if (8..size).any(|i| acc[off + i] != pattern(seq, i)) {
                        return Err("reader: message payload corrupted");
                    }
                    if fds_have < mfds {
                        return Err("reader: a message's fds arrived after the message");
                    }
                    fds_have -= mfds;
                    expect += 1;
                    off += size;
                }
                acc.drain(..off);
            }
            if expect != MESSAGES {
                return Err("forwarder made no progress to the last message");
            }
            if fds_have != 0 {
                return Err("reader received more fds than the messages carried");
            }
            if proxy_eagain == 0 {
                return Err("the slow reader never filled the proxy's peer (test too weak)");
            }
            Ok(())
        })();
        close(payload_fd as u64);
        for fd in [app, proxy_in, proxy_out, comp] {
            close(fd);
        }
        res
    })
}
kernel_test_in!(
    "syscall_abi/unix_stream",
    smoke_abi_unix_stream_wayland_proxy_forwarder
);
