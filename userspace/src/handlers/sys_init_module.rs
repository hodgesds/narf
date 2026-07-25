#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_init_module(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ptr = args.arg0 as *const u8;
    let len = args.arg1 as usize;
    // arg2 = params_ptr — parsed/used by `narf_modules::loader` once
    // the param string parser lands. Phase 1 ignores user-supplied
    // params; modules read static `.narf_kparams` from their ELF.
    if ptr.is_null() || len == 0 || len > (1 << 28) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64));
        return;
    }
    // SAFETY: caller pointer in the active AS; bounds-checked by len.
    let bytes_user = unsafe { core::slice::from_raw_parts(ptr, len) };
    // Copy to kernel heap so the user can't mutate the buffer during
    // parsing.
    let owned: alloc::vec::Vec<u8> = bytes_user.to_vec();
    ctx.set_return(SyscallReturn::ok(init_module_result(
        narf_modules::syscalls::sys_init_module(&owned),
    )));
}
