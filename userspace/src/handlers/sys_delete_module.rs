#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_delete_module(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let name_ptr = args.arg0 as *const u8;
    let name_len = args.arg1 as usize;
    if name_ptr.is_null() || name_len == 0 || name_len > 256 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    // SAFETY: caller pointer in the active AS; bounds-checked.
    let name_bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
    let name = match core::str::from_utf8(name_bytes) {
        Ok(s) => s,
        Err(_) => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64));
            return;
        }
    };
    match narf_modules::syscalls::sys_delete_module(name) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(e) => ctx.set_return(SyscallReturn::ok((e.to_errno() as i64) as u64)),
    }
}
