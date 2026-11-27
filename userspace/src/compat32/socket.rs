//! The i386 socket calls whose structures differ from the native ones
//! (`net/compat.c`, `net/socket.c`): `struct compat_msghdr` and
//! `compat_mmsghdr` with their `compat_iovec` arrays and `compat_cmsghdr`
//! control messages, the `socketcall` multiplexer, and the old 32-bit
//! `SO_RCVTIMEO`/`SO_SNDTIMEO` timevals.
//!
//! The native handlers read and write a `struct msghdr` through user
//! pointers, so each call builds the native structures on the caller's
//! stack ([`super::stage`]), runs the native handler against them and copies
//! the results back into the compat structures — Linux's
//! `get_compat_msghdr` / `cmsghdr_from_user_compat_to_kern` going in and
//! `put_cmsg_compat` / `scm_detach_fds_compat` coming out.

use alloc::vec::Vec;

use super::conv;
use super::stage::{self, Stage};
use super::table::{call_native, forward_args, succeeded};
use crate::errno::{to_ret, EINVAL, EMSGSIZE};
use crate::syscall::{Ia32Abi, Syscall, SyscallArgs, SyscallReturn, TrapContext};

const UIO_MAXIOV: u32 = 1024;
/// `MSG_CTRUNC`: the control data did not all fit.
const MSG_CTRUNC: u32 = 0x8;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
/// `SO_TIMESTAMP_OLD` / `SCM_TIMESTAMP`: a `struct timeval`.
const SO_TIMESTAMP_OLD: i32 = 29;
/// `SO_TIMESTAMPNS_OLD` / `SCM_TIMESTAMPNS`: a `struct timespec`.
const SO_TIMESTAMPNS_OLD: i32 = 35;
/// `SO_TIMESTAMPING_OLD` / `SCM_TIMESTAMPING`: three `struct timespec`s.
const SO_TIMESTAMPING_OLD: i32 = 37;
const SO_RCVTIMEO_OLD: u64 = 20;
const SO_SNDTIMEO_OLD: u64 = 21;

/// Bytes of a native `struct msghdr` / `struct mmsghdr`.
const MSGHDR: usize = 56;
const MMSGHDR: usize = 64;
/// Bytes of a `struct compat_msghdr` / `struct compat_mmsghdr`.
const COMPAT_MSGHDR: usize = 28;
const COMPAT_MMSGHDR: usize = 32;
/// Header bytes of a native and a compat `cmsghdr`.
const CMSG_HDR: usize = 16;
const COMPAT_CMSG_HDR: usize = 12;

fn args(arg0: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) -> SyscallArgs {
    SyscallArgs {
        arg0,
        arg1,
        arg2,
        arg3,
        arg4,
        arg5,
    }
}

fn get_u32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn get_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap_or([0; 8]))
}

/// `struct compat_msghdr`.
#[derive(Copy, Clone, Debug)]
struct CompatMsghdr {
    name: u32,
    namelen: u32,
    iov: u32,
    iovlen: u32,
    control: u32,
    controllen: u32,
    flags: u32,
}

impl CompatMsghdr {
    fn parse(raw: &[u8]) -> Self {
        Self {
            name: get_u32(raw, 0),
            namelen: get_u32(raw, 4),
            iov: get_u32(raw, 8),
            iovlen: get_u32(raw, 12),
            control: get_u32(raw, 16),
            controllen: get_u32(raw, 20),
            flags: get_u32(raw, 24),
        }
    }
}

fn read_compat_msghdr(ptr: u64) -> Result<CompatMsghdr, i64> {
    let mut raw = [0u8; COMPAT_MSGHDR];
    conv::read_user(ptr, &mut raw)?;
    Ok(CompatMsghdr::parse(&raw))
}

/// The native `struct iovec` array for `m`'s `compat_iovec`s
/// (`compat_import_iovec`): EMSGSIZE past UIO_MAXIOV, EINVAL for a negative
/// `compat_ssize_t` length.
fn native_iovecs(m: &CompatMsghdr) -> Result<Vec<u8>, i64> {
    if m.iovlen > UIO_MAXIOV {
        return Err(EMSGSIZE);
    }
    let n = m.iovlen as usize;
    let mut raw = alloc::vec![0u8; n * 8];
    if n != 0 {
        conv::read_user(u64::from(m.iov), &mut raw)?;
    }
    let mut out = Vec::with_capacity(n * 16);
    for i in 0..n {
        let len = conv::word(&raw, 2 * i + 1);
        if (len as i32) < 0 {
            return Err(EINVAL);
        }
        out.extend_from_slice(&u64::from(conv::word(&raw, 2 * i)).to_le_bytes());
        out.extend_from_slice(&u64::from(len).to_le_bytes());
    }
    Ok(out)
}

/// `cmsghdr_from_user_compat_to_kern`: the native control buffer for the
/// compat control messages `m` sends. Each record must hold its header and
/// fit in the buffer (EINVAL), and a non-empty buffer must carry at least
/// one record (EINVAL); the data is copied as it is.
fn native_cmsgs(m: &CompatMsghdr) -> Result<Vec<u8>, i64> {
    let len = m.controllen as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    let mut raw = alloc::vec![0u8; len];
    conv::read_user(u64::from(m.control), &mut raw)?;
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + COMPAT_CMSG_HDR <= len {
        let cmlen = get_u32(&raw, off) as usize;
        if cmlen < COMPAT_CMSG_HDR || cmlen > len - off {
            return Err(EINVAL);
        }
        let data = &raw[off + COMPAT_CMSG_HDR..off + cmlen];
        let start = out.len();
        out.extend_from_slice(&((CMSG_HDR + data.len()) as u64).to_le_bytes());
        out.extend_from_slice(&raw[off + 4..off + 12]); // level, type
        out.extend_from_slice(data);
        out.resize(start + (CMSG_HDR + data.len()).next_multiple_of(8), 0);
        off += cmlen.next_multiple_of(4);
    }
    if out.is_empty() {
        return Err(EINVAL);
    }
    Ok(out)
}

/// One native control message's data as the i386 caller receives it
/// (`put_cmsg_compat`): the old timestamps narrowed to their 32-bit
/// `old_timeval32` / `old_timespec32` forms, everything else as it is.
fn compat_cmsg_data(level: i32, kind: i32, data: &[u8]) -> Vec<u8> {
    let narrow = |words: usize| {
        let mut out = Vec::with_capacity(words * 4);
        for i in 0..words {
            if let Some(v) = data.get(i * 8..i * 8 + 8) {
                out.extend_from_slice(&v[..4]);
            }
        }
        out
    };
    match (level, kind) {
        (SOL_SOCKET, SO_TIMESTAMP_OLD) | (SOL_SOCKET, SO_TIMESTAMPNS_OLD) => narrow(2),
        (SOL_SOCKET, SO_TIMESTAMPING_OLD) => narrow(6),
        _ => data.to_vec(),
    }
}

/// The compat control messages for the native ones in `native`, fitted
/// into `cap` bytes the way `put_cmsg_compat` and `scm_detach_fds_compat`
/// fit them: a record that does not fit is cut (SCM_RIGHTS to whole fds)
/// and MSG_CTRUNC set. Returns the bytes, whether anything was cut, and the
/// received fds the caller cannot see, which must be closed again.
fn compat_cmsgs(native: &[u8], cap: usize) -> (Vec<u8>, bool, Vec<u32>) {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut lost_fds = Vec::new();
    let mut off = 0usize;
    while off + CMSG_HDR <= native.len() {
        let cmlen = get_u64(native, off) as usize;
        if cmlen < CMSG_HDR || cmlen > native.len() - off {
            break;
        }
        let level = get_u32(native, off + 8) as i32;
        let kind = get_u32(native, off + 12) as i32;
        let data = compat_cmsg_data(level, kind, &native[off + CMSG_HDR..off + cmlen]);
        off += cmlen.next_multiple_of(8);
        let room = cap - out.len();
        if room < COMPAT_CMSG_HDR {
            truncated = true;
            if level == SOL_SOCKET && kind == SCM_RIGHTS {
                lost_fds.extend(data.chunks_exact(4).map(|c| get_u32(c, 0)));
            }
            continue;
        }
        let rights = level == SOL_SOCKET && kind == SCM_RIGHTS;
        let mut keep = data.len();
        if COMPAT_CMSG_HDR + keep > room {
            truncated = true;
            keep = room - COMPAT_CMSG_HDR;
            if rights {
                keep -= keep % 4;
                lost_fds.extend(data[keep..].chunks_exact(4).map(|c| get_u32(c, 0)));
            }
        }
        // `scm_detach_fds_compat` writes no record for zero fds, and sizes
        // the one it writes by the fds it installed.
        if rights && keep == 0 {
            continue;
        }
        let full = if rights { keep } else { data.len() };
        let start = out.len();
        out.extend_from_slice(&((COMPAT_CMSG_HDR + keep) as u32).to_le_bytes());
        out.extend_from_slice(&level.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&data[..keep]);
        let space = (COMPAT_CMSG_HDR + full).next_multiple_of(4).min(room);
        out.resize(start + space, 0);
    }
    (out, truncated, lost_fds)
}

/// The native buffer a receive stages for `cap` compat control bytes: room
/// for whatever fits there, since a native record is at most 12 bytes
/// larger than its compat form and every record takes 12 compat bytes.
fn native_control_room(cap: u32) -> usize {
    if cap == 0 {
        0
    } else {
        cap as usize * 2 + CMSG_HDR
    }
}

/// A native `struct msghdr` staged for compat `m`: its name buffer as it is
/// (`struct sockaddr` is the same on both ABIs), native iovecs, and either
/// the native form of its control messages (`send`) or an empty native
/// control buffer to receive into. Returns the msghdr's staged address and,
/// for a receive, the control buffer's.
fn stage_msghdr(stage: &mut Stage, m: &CompatMsghdr, send: bool) -> Result<(u64, u64), i64> {
    let iov = native_iovecs(m)?;
    let iov_at = stage.put(&iov)?;
    let (ctrl_at, ctrl_len) = if send {
        let ctrl = native_cmsgs(m)?;
        (
            if ctrl.is_empty() {
                0
            } else {
                stage.put(&ctrl)?
            },
            ctrl.len(),
        )
    } else {
        let room = native_control_room(m.controllen);
        (if room == 0 { 0 } else { stage.alloc(room)? }, room)
    };
    let mut hdr = [0u8; MSGHDR];
    hdr[0..8].copy_from_slice(&u64::from(m.name).to_le_bytes());
    hdr[8..12].copy_from_slice(&m.namelen.to_le_bytes());
    hdr[16..24].copy_from_slice(&iov_at.to_le_bytes());
    hdr[24..32].copy_from_slice(&u64::from(m.iovlen).to_le_bytes());
    hdr[32..40].copy_from_slice(&ctrl_at.to_le_bytes());
    hdr[40..48].copy_from_slice(&(ctrl_len as u64).to_le_bytes());
    hdr[48..52].copy_from_slice(&m.flags.to_le_bytes());
    Ok((stage.put(&hdr)?, ctrl_at))
}

/// Stage bytes for one compat msghdr's native form: header, iovecs and
/// control room.
fn stage_bytes(m: &CompatMsghdr, send: bool) -> usize {
    let ctrl = if send {
        m.controllen as usize * 2 + 16
    } else {
        native_control_room(m.controllen)
    };
    MSGHDR + 16 + (m.iovlen.min(UIO_MAXIOV) as usize) * 16 + 16 + ctrl + 16
}

/// Copy a received native msghdr at `native_at` back into the compat one
/// at `compat_at` (`msg_namelen`, the control messages, `msg_controllen`,
/// `msg_flags`), closing any received fd the compat buffer could not carry.
fn finish_recv(
    ctx: &mut dyn TrapContext,
    m: &CompatMsghdr,
    compat_at: u64,
    native_at: u64,
    ctrl_at: u64,
) -> Result<(), i64> {
    let hdr = stage::read_back(native_at, MSGHDR)?;
    let namelen = get_u32(&hdr, 8);
    let native_ctrl_len = get_u64(&hdr, 40) as usize;
    let mut flags = get_u32(&hdr, 48);
    let mut ctrl_len = 0u32;
    if ctrl_at != 0 && native_ctrl_len != 0 {
        let native = stage::read_back(ctrl_at, native_ctrl_len)?;
        let (compat, truncated, lost) = compat_cmsgs(&native, m.controllen as usize);
        for fd in lost {
            let _ = call_native(
                ctx,
                Syscall::Close,
                args(u64::from(fd), 0, 0, 0, 0, 0),
                Ia32Abi::default(),
            );
        }
        if truncated {
            flags |= MSG_CTRUNC;
        }
        if !compat.is_empty() {
            conv::write_user(u64::from(m.control), &compat)?;
        }
        ctrl_len = compat.len() as u32;
    }
    conv::write_user(compat_at + 4, &namelen.to_le_bytes())?;
    conv::write_user(compat_at + 20, &ctrl_len.to_le_bytes())?;
    conv::write_user(compat_at + 24, &flags.to_le_bytes())?;
    Ok(())
}

/// Report `result` (a return to set, or an errno) for `variant`.
fn finish(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    result: Result<Option<SyscallReturn>, i64>,
) -> Option<Syscall> {
    match result {
        Ok(Some(ret)) => ctx.set_return(ret),
        // The native handler parked to re-execute the call: no result yet.
        Ok(None) => {}
        Err(e) => ctx.set_return(to_ret(e)),
    }
    Some(variant)
}

/// `sendmsg(fd, msg, flags)` (i386 370, `compat_sys_sendmsg`).
pub(crate) fn compat_sendmsg(
    ctx: &mut dyn TrapContext,
    fd: u64,
    msg: u64,
    flags: u64,
) -> Option<Syscall> {
    let result = sendmsg_staged(ctx, fd, msg, flags);
    finish(ctx, Syscall::SocketSendMsg, result)
}

fn sendmsg_staged(
    ctx: &mut dyn TrapContext,
    fd: u64,
    msg: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, i64> {
    let m = read_compat_msghdr(msg)?;
    let mut stage = Stage::new(ctx, stage_bytes(&m, true))?;
    let (at, _) = stage_msghdr(&mut stage, &m, true)?;
    let args = args(conv::sext(fd), at, flags, 0, 0, 0);
    Ok(call_native(
        ctx,
        Syscall::SocketSendMsg,
        args,
        Ia32Abi::default(),
    ))
}

/// `recvmsg(fd, msg, flags)` (i386 372, `compat_sys_recvmsg`).
pub(crate) fn compat_recvmsg(
    ctx: &mut dyn TrapContext,
    fd: u64,
    msg: u64,
    flags: u64,
) -> Option<Syscall> {
    let result = recvmsg_staged(ctx, fd, msg, flags);
    finish(ctx, Syscall::SocketRecvMsg, result)
}

fn recvmsg_staged(
    ctx: &mut dyn TrapContext,
    fd: u64,
    msg: u64,
    flags: u64,
) -> Result<Option<SyscallReturn>, i64> {
    let m = read_compat_msghdr(msg)?;
    let mut stage = Stage::new(ctx, stage_bytes(&m, false))?;
    let (at, ctrl_at) = stage_msghdr(&mut stage, &m, false)?;
    let args = args(conv::sext(fd), at, flags, 0, 0, 0);
    // A receive that parks re-executes the whole call later.
    let Some(ret) = call_native(ctx, Syscall::SocketRecvMsg, args, Ia32Abi::default()) else {
        return Ok(None);
    };
    if succeeded(&ret) {
        finish_recv(ctx, &m, msg, at, ctrl_at)?;
    }
    Ok(Some(ret))
}

/// The compat `mmsghdr` vector at `vec`, `vlen` entries (UIO_MAXIOV at
/// most, as `__sys_sendmmsg`/`do_recvmmsg` clamp it).
fn read_compat_mmsghdrs(vec: u64, vlen: u64) -> Result<Vec<CompatMsghdr>, i64> {
    let n = vlen.min(u64::from(UIO_MAXIOV)) as usize;
    let mut raw = alloc::vec![0u8; n * COMPAT_MMSGHDR];
    if n != 0 {
        conv::read_user(vec, &mut raw)?;
    }
    Ok(raw
        .chunks_exact(COMPAT_MMSGHDR)
        .map(CompatMsghdr::parse)
        .collect())
}

/// A native `mmsghdr` vector staged for `msgs`: the msghdr part of each
/// entry built as [`stage_msghdr`] builds one. Returns the vector's address
/// and each entry's staged control buffer.
fn stage_mmsghdrs(
    stage: &mut Stage,
    msgs: &[CompatMsghdr],
    send: bool,
) -> Result<(u64, Vec<u64>), i64> {
    let mut vec = alloc::vec![0u8; msgs.len() * MMSGHDR];
    let mut ctrls = Vec::with_capacity(msgs.len());
    for (i, m) in msgs.iter().enumerate() {
        let (at, ctrl_at) = stage_msghdr(stage, m, send)?;
        ctrls.push(ctrl_at);
        let hdr = stage::read_back(at, MSGHDR)?;
        vec[i * MMSGHDR..i * MMSGHDR + MSGHDR].copy_from_slice(&hdr);
    }
    Ok((stage.put(&vec)?, ctrls))
}

/// `sendmmsg(fd, mmsg, vlen, flags)` (i386 345, `compat_sys_sendmmsg`):
/// each sent entry's `msg_len` is written back.
pub(crate) fn compat_sendmmsg(
    ctx: &mut dyn TrapContext,
    fd: u64,
    vec: u64,
    vlen: u64,
    flags: u64,
) -> Option<Syscall> {
    let result = mmsg_staged(ctx, Syscall::Sendmmsg, fd, vec, vlen, flags, None);
    finish(ctx, Syscall::Sendmmsg, result)
}

/// `recvmmsg(fd, mmsg, vlen, flags, timeout)` (i386 337 with an
/// `old_timespec32` timeout, 417 `recvmmsg_time64` with a
/// `__kernel_timespec`): each received entry is copied back as `recvmsg`
/// copies its one, and the time left goes back to the caller's timeout.
pub(crate) fn compat_recvmmsg(
    ctx: &mut dyn TrapContext,
    fd: u64,
    vec: u64,
    vlen: u64,
    flags: u64,
    timeout: u64,
    time32: bool,
) -> Option<Syscall> {
    let recv = Some((timeout, time32));
    let result = mmsg_staged(ctx, Syscall::Recvmmsg, fd, vec, vlen, flags, recv);
    finish(ctx, Syscall::Recvmmsg, result)
}

/// An `old_timespec32` (or `old_timeval32`) at `ptr` as its native
/// two-`i64` form.
fn timespec32_to_native(ptr: u64) -> Result<[u8; 16], i64> {
    let mut ts = [0u8; 8];
    conv::read_user(ptr, &mut ts)?;
    let mut native = [0u8; 16];
    native[0..8].copy_from_slice(&i64::from(conv::word(&ts, 0) as i32).to_le_bytes());
    native[8..16].copy_from_slice(&i64::from(conv::word(&ts, 1) as i32).to_le_bytes());
    Ok(native)
}

fn mmsg_staged(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    fd: u64,
    vec: u64,
    vlen: u64,
    flags: u64,
    recv: Option<(u64, bool)>,
) -> Result<Option<SyscallReturn>, i64> {
    let send = recv.is_none();
    let msgs = read_compat_mmsghdrs(vec, vlen)?;
    let bytes = msgs.iter().map(|m| stage_bytes(m, send)).sum::<usize>()
        + msgs.len() * (MMSGHDR + MSGHDR)
        + 64;
    let mut stage = Stage::new(ctx, bytes)?;
    let (at, ctrls) = stage_mmsghdrs(&mut stage, &msgs, send)?;
    // A time32 receive timeout becomes a staged native `__kernel_timespec`.
    let (timeout, staged_timeout) = match recv {
        Some((ptr, true)) if ptr != 0 => {
            let native = timespec32_to_native(ptr)?;
            let staged = stage.put(&native)?;
            (staged, Some((ptr, staged)))
        }
        Some((ptr, _)) => (ptr, None),
        None => (0, None),
    };
    let args = args(conv::sext(fd), at, msgs.len() as u64, flags, timeout, 0);
    let Some(ret) = call_native(ctx, variant, args, Ia32Abi::default()) else {
        return Ok(None);
    };
    if !succeeded(&ret) {
        return Ok(Some(ret));
    }
    let done = (ret.value as usize).min(msgs.len());
    for (i, m) in msgs.iter().take(done).enumerate() {
        let native_at = at + (i * MMSGHDR) as u64;
        let compat_at = vec + (i * COMPAT_MMSGHDR) as u64;
        if !send {
            finish_recv(ctx, m, compat_at, native_at, ctrls[i])?;
        }
        let msg_len = stage::read_back(native_at + MSGHDR as u64, 4)?;
        conv::write_user(compat_at + COMPAT_MSGHDR as u64, &msg_len)?;
    }
    if let Some((user, staged)) = staged_timeout {
        let left = stage::read_back(staged, 16)?;
        let mut ts = [0u8; 8];
        ts[0..4].copy_from_slice(&left[0..4]);
        ts[4..8].copy_from_slice(&left[8..12]);
        conv::write_user(user, &ts)?;
    }
    Ok(Some(ret))
}

/// `setsockopt(fd, level, optname, optval, optlen)` (i386 366) and
/// `getsockopt(fd, level, optname, optval, optlen)` (365). `sock_setsockopt`
/// / `sock_getsockopt` read and write the old `SO_RCVTIMEO`/`SO_SNDTIMEO`
/// as an `old_timeval32` for a compat caller (`sock_set_timeout`,
/// `sock_get_timeout`); every other option has one layout.
pub(crate) fn compat_sockopt(ctx: &mut dyn TrapContext, set: bool) -> Option<Syscall> {
    let a = *ctx.args();
    let variant = if set {
        Syscall::SocketSetSockOpt
    } else {
        Syscall::SocketGetSockOpt
    };
    let (fd, level, optname) = (conv::sext(a.arg0), conv::sext(a.arg1), conv::sext(a.arg2));
    let timeo = level as i64 == i64::from(SOL_SOCKET)
        && matches!(optname, SO_RCVTIMEO_OLD | SO_SNDTIMEO_OLD);
    if !timeo {
        let optlen = if set { conv::sext(a.arg4) } else { a.arg4 };
        let args = args(fd, level, optname, a.arg3, optlen, 0);
        return forward_args(ctx, variant, args, Ia32Abi::default());
    }
    let result = if set {
        set_timeo_staged(ctx, fd, level, optname, a.arg3, a.arg4)
    } else {
        get_timeo_staged(ctx, fd, level, optname, a.arg3, a.arg4)
    };
    finish(ctx, variant, result)
}

/// `sock_set_timeout` for a compat caller: an `old_timeval32` (an optlen
/// below its 8 bytes is EINVAL) set as the native `struct timeval`.
fn set_timeo_staged(
    ctx: &mut dyn TrapContext,
    fd: u64,
    level: u64,
    optname: u64,
    optval: u64,
    optlen: u64,
) -> Result<Option<SyscallReturn>, i64> {
    if (optlen as u32 as i32) < 8 {
        return Err(EINVAL);
    }
    let native = timespec32_to_native(optval)?;
    let mut stage = Stage::new(ctx, 32)?;
    let at = stage.put(&native)?;
    let args = args(fd, level, optname, at, 16, 0);
    Ok(call_native(
        ctx,
        Syscall::SocketSetSockOpt,
        args,
        Ia32Abi::default(),
    ))
}

/// `sock_get_timeout` for a compat caller: the native `struct timeval`
/// narrowed to an `old_timeval32`, cut to the caller's optlen.
fn get_timeo_staged(
    ctx: &mut dyn TrapContext,
    fd: u64,
    level: u64,
    optname: u64,
    optval: u64,
    optlen: u64,
) -> Result<Option<SyscallReturn>, i64> {
    let mut len = [0u8; 4];
    conv::read_user(optlen, &mut len)?;
    let want = u32::from_le_bytes(len) as i32;
    if want < 0 {
        return Err(EINVAL);
    }
    let mut stage = Stage::new(ctx, 64)?;
    let val_at = stage.alloc(16)?;
    let len_at = stage.put(&16u32.to_le_bytes())?;
    let args = args(fd, level, optname, val_at, len_at, 0);
    let Some(ret) = call_native(ctx, Syscall::SocketGetSockOpt, args, Ia32Abi::default()) else {
        return Ok(None);
    };
    if !succeeded(&ret) {
        return Ok(Some(ret));
    }
    let native = stage::read_back(val_at, 16)?;
    let mut tv = [0u8; 8];
    tv[0..4].copy_from_slice(&native[0..4]);
    tv[4..8].copy_from_slice(&native[8..12]);
    let n = (want as usize).min(8);
    conv::write_user(optval, &tv[..n])?;
    conv::write_user(optlen, &(n as u32).to_le_bytes())?;
    Ok(Some(ret))
}

/// `socketcall(call, args)` (i386 102, `compat_sys_socketcall`): the socket
/// multiplexer. `args` points at the call's arguments as 32-bit words
/// (`nas[]` says how many); each call is served as its direct i386 entry,
/// SYS_SEND / SYS_RECV / SYS_ACCEPT as sendto / recvfrom / accept4 without
/// the address and flags, SYS_RECVMMSG with its `old_timespec32`.
pub(crate) fn compat_socketcall(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    use super::table::nr;
    // (nargs, direct i386 entry) by SYS_* call number, 1..=20.
    const CALLS: [(usize, u32); 21] = [
        (0, 0),
        (3, nr::SOCKET),
        (3, nr::BIND),
        (3, nr::CONNECT),
        (2, nr::LISTEN),
        (3, nr::ACCEPT4),
        (3, nr::GETSOCKNAME),
        (3, nr::GETPEERNAME),
        (4, nr::SOCKETPAIR),
        (4, nr::SENDTO),
        (4, nr::RECVFROM),
        (6, nr::SENDTO),
        (6, nr::RECVFROM),
        (2, nr::SHUTDOWN),
        (5, nr::SETSOCKOPT),
        (5, nr::GETSOCKOPT),
        (3, nr::SENDMSG),
        (3, nr::RECVMSG),
        (4, nr::ACCEPT4),
        (5, nr::RECVMMSG),
        (4, nr::SENDMMSG),
    ];
    let a = *ctx.args();
    let call = a.arg0 as u32 as i32;
    if !(1..=20).contains(&call) {
        ctx.set_return(to_ret(EINVAL));
        return None;
    }
    let (nargs, direct) = CALLS[call as usize];
    let mut raw = [0u8; 24];
    if let Err(e) = conv::read_user(a.arg1, &mut raw[..nargs * 4]) {
        ctx.set_return(to_ret(e));
        return None;
    }
    let w = |i: usize| u64::from(conv::word(&raw, i));
    // SYS_SEND / SYS_RECV carry no address (the words past `nargs` are 0),
    // SYS_ACCEPT no flags.
    let args = args(w(0), w(1), w(2), w(3), w(4), w(5));
    let mut inner = super::ctx::Ia32ArgsCtx::forwarding(ctx, args, Ia32Abi::default());
    super::table::dispatch(direct, &mut inner)
}
