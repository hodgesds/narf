#[allow(unused_imports)]
use super::*;

const MSG_CMSG_COMPAT: u32 = 0x8000_0000;
const MSG_EOR: u32 = 0x80;
const UIO_MAXIOV: usize = 1024;
const MSGHDR_SIZE: usize = 56;

pub(super) enum SendMsgResult {
    Sent { written: usize, complete: bool },
    WouldBlock,
    Error(i64),
}

/// `sendmsg(fd, msghdr, flags)` with Linux's native validation order:
/// compatibility-only flags, descriptor type, complete msghdr/address/iovec
/// import, ancillary import, payload copy, then protocol dispatch.
pub(crate) fn sys_socket_sendmsg(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let msg_ptr = args.arg1;
    let flags = args.arg2 as u32;

    // Native sendmsg never admits the in-kernel compat marker. Linux checks it
    // before fdget(), so it wins even for an invalid descriptor.
    if flags & MSG_CMSG_COMPAT != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let sock = match current_socket_result(fd) {
        Ok(socket) => socket,
        Err(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
            return;
        }
    };
    match sendmsg_on_socket(&sock, msg_ptr, flags, false) {
        SendMsgResult::Sent { written, .. } => ctx.set_return(SyscallReturn::ok(written as u64)),
        SendMsgResult::WouldBlock => {
            handler_sys_socket_send::socket_send_would_block(ctx, fd, flags, sock.as_ref())
        }
        SendMsgResult::Error(errno) => {
            ctx.set_return(SyscallReturn::ok((-errno) as u64));
        }
    }
}

/// Import and send one native `user_msghdr` through an already-resolved
/// socket. `allow_msg_eor` is true only for sendmmsg, matching Linux's
/// `allowed_msghdr_flags` argument.
pub(super) fn sendmsg_on_socket(
    sock: &alloc::sync::Arc<crate::socket::SocketFile>,
    msg_ptr: u64,
    mut flags: u32,
    allow_msg_eor: bool,
) -> SendMsgResult {
    let mut header = [0u8; MSGHDR_SIZE];
    // SAFETY: copy_from_user validates all 56 bytes before copying them.
    if unsafe { copy_from_user(&mut header, msg_ptr) }.is_err() {
        return SendMsgResult::Error(14); // EFAULT
    }

    let name_ptr = field_u64(&header, 0);
    let name_len = field_u32(&header, 8) as i32;
    let iov_ptr = field_u64(&header, 16);
    let iov_len_u64 = field_u64(&header, 24);
    let ctrl_ptr = field_u64(&header, 32);
    let ctrl_len_u64 = field_u64(&header, 40);
    let header_flags = field_u32(&header, 48);

    // __copy_msghdr imports/clamps the optional address before rejecting an
    // oversized iov count.
    let dest = match import_sendmsg_addr(name_ptr, name_len) {
        Ok(addr) => addr,
        Err(errno) => return SendMsgResult::Error(errno),
    };
    if iov_len_u64 > UIO_MAXIOV as u64 {
        return SendMsgResult::Error(90); // EMSGSIZE
    }
    let iov_len = iov_len_u64 as usize;
    let iov_bytes = match iov_len.checked_mul(16) {
        Some(bytes) => bytes,
        None => return SendMsgResult::Error(14), // EFAULT
    };
    let iov_raw = if iov_bytes == 0 {
        alloc::vec::Vec::new()
    } else {
        // SAFETY: complete iovec-array import; invalid array pointer is EFAULT.
        match unsafe { copy_from_user_vec(iov_ptr, iov_bytes) } {
            Ok(bytes) => bytes,
            Err(_) => return SendMsgResult::Error(14),
        }
    };

    // Import all vector descriptors and validate their source ranges before
    // ancillary processing, as Linux import_iovec does. Actual payload copying
    // remains deferred until after the control buffer has been imported.
    let mut vectors = alloc::vec::Vec::new();
    if vectors.try_reserve_exact(iov_len).is_err() {
        return SendMsgResult::Error(12); // ENOMEM
    }
    let mut total_len = 0usize;
    for i in 0..iov_len {
        let off = i * 16;
        let ptr = u64::from_ne_bytes(iov_raw[off..off + 8].try_into().unwrap());
        let len = u64::from_ne_bytes(iov_raw[off + 8..off + 16].try_into().unwrap());
        let Ok(len) = usize::try_from(len) else {
            return SendMsgResult::Error(22); // EINVAL
        };
        if len != 0 && validate_user_range(ptr, len).is_err() {
            return SendMsgResult::Error(14); // EFAULT
        }
        total_len = match total_len.checked_add(len) {
            Some(n) if n <= MAX_USER_COPY => n,
            _ => return SendMsgResult::Error(22), // bounded NARF transfer
        };
        vectors.push((ptr, len));
    }

    // Linux rejects an unrepresentable control length as ENOBUFS before
    // attempting the control copy. NARF also bounds the allocation at its
    // documented per-syscall copy ceiling, with the same resource errno.
    if ctrl_len_u64 > i32::MAX as u64 || ctrl_len_u64 > MAX_USER_COPY as u64 {
        return SendMsgResult::Error(105); // ENOBUFS
    }
    let passed_fds = match parse_scm_rights_fds(ctrl_ptr, ctrl_len_u64 as usize) {
        Ok(fds) => fds,
        Err(errno) => return SendMsgResult::Error(errno),
    };

    let mut total = alloc::vec::Vec::new();
    if total.try_reserve_exact(total_len).is_err() {
        return SendMsgResult::Error(12); // ENOMEM
    }
    for (ptr, len) in vectors {
        if len == 0 {
            continue;
        }
        let old_len = total.len();
        total.resize(old_len + len, 0);
        // SAFETY: the range was validated above; the guarded copy still catches
        // an unmap race and reports EFAULT rather than publishing partial data.
        if unsafe { copy_from_user(&mut total[old_len..], ptr) }.is_err() {
            return SendMsgResult::Error(14);
        }
    }

    if allow_msg_eor {
        flags |= header_flags & MSG_EOR;
    }
    #[cfg(feature = "syscall-trace")]
    crate::socket::dbg_dbus_peek("TX", &total);

    if !passed_fds.is_empty() {
        let result =
            if sock.domain == crate::socket::AF_UNIX && sock.kind == crate::socket::SOCK_DGRAM {
                sock.unix_dgram_sendmsg(&total, flags, dest, passed_fds)
            } else {
                sock.unix_sendmsg(&total, passed_fds)
            };
        return match result {
            Ok(n) => SendMsgResult::Sent {
                written: n,
                complete: n >= total_len,
            },
            Err(crate::socket::SockError::WouldBlock) => SendMsgResult::WouldBlock,
            Err(error) => SendMsgResult::Error(error.errno() as i64),
        };
    }

    match sock.dispatch_op(crate::socket::SocketOp::Send {
        buf: &total,
        flags,
        addr: dest,
    }) {
        crate::socket::SocketOpResult::Ok(n) => SendMsgResult::Sent {
            written: n as usize,
            complete: n as usize >= total_len,
        },
        crate::socket::SocketOpResult::Err(crate::socket::SockError::WouldBlock) => {
            SendMsgResult::WouldBlock
        }
        crate::socket::SocketOpResult::Err(error) => SendMsgResult::Error(error.errno() as i64),
        _ => SendMsgResult::Error(22),
    }
}

fn import_sendmsg_addr(ptr: u64, signed_len: i32) -> Result<Option<crate::socket::SockAddr>, i64> {
    if ptr == 0 {
        return Ok(None);
    }
    if signed_len < 0 {
        return Err(22); // EINVAL
    }
    let len = core::cmp::min(signed_len as usize, 128);
    if len == 0 {
        return Ok(None);
    }
    if len < 2 {
        return Err(22);
    }
    let mut bytes = alloc::vec![0u8; len];
    // SAFETY: guarded import of the clamped sockaddr_storage prefix.
    if unsafe { copy_from_user(&mut bytes, ptr) }.is_err() {
        return Err(14); // EFAULT
    }
    Ok(Some(crate::socket::SockAddr {
        family: u16::from_ne_bytes([bytes[0], bytes[1]]),
        body: bytes[2..].to_vec(),
    }))
}

#[inline]
fn field_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[inline]
fn field_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
