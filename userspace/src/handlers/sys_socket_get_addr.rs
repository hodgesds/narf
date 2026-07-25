#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_get_addr(ctx: &mut dyn TrapContext, peer: bool) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let len_ptr = args.arg2;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let op = if peer {
        crate::socket::SocketOp::GetPeerName
    } else {
        crate::socket::SocketOp::GetSockName
    };
    let result = sock.dispatch_op(op);
    match result {
        crate::socket::SocketOpResult::Addr(addr) => {
            // Read in length (caller-supplied capacity) via SMAP bracket.
            let in_len = if len_ptr != 0 {
                read_user_u32(len_ptr) as usize
            } else {
                0
            };
            // Pack as: family(u16) + body.
            let total = 2 + addr.body.len();
            let n = core::cmp::min(in_len, total);
            if addr_ptr != 0 && n >= 2 {
                let mut out = alloc::vec![0u8; n];
                let fam_bytes = addr.family.to_le_bytes();
                out[0] = fam_bytes[0];
                out[1] = fam_bytes[1];
                let body_n = n - 2;
                out[2..2 + body_n].copy_from_slice(&addr.body[..body_n]);
                // SAFETY: addr_ptr is a user VA; SMAP bracket inside copy_to_user.
                let _ = unsafe { copy_to_user(addr_ptr, &out) };
            }
            if len_ptr != 0 {
                write_user_u32(len_ptr, total as u32);
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => ctx.set_return(fail),
    }
}
