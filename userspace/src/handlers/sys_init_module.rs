#[allow(unused_imports)]
use super::*;

const EPERM: i64 = 1;
const ENOEXEC: i64 = 8;
const EFBIG: i64 = 27;

#[inline]
fn fail(errno: i64) -> SyscallReturn {
    SyscallReturn::ok((-errno) as u64)
}

/// `init_module(2)` — `kernel/module/main.c::SYSCALL_DEFINE3(init_module)`.
///
/// ```text
/// err = may_init_module();          /* CAP_SYS_MODULE, else -EPERM */
/// if (err) return err;
/// err = copy_module_from_user(umod, len, &info);
/// ```
///
/// The capability test is FIRST, ahead of every argument check. An
/// unprivileged caller learns that it may not load modules and nothing about
/// whether its pointer or length were any good — which is the point, because
/// the checks below read user memory and a caller that may not load a module
/// has no business reaching them.
pub(crate) fn sys_init_module(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();

    // `may_init_module()`. Before this, ANY task could load a kernel module:
    // the handler consulted no capability at all.
    if !capable(CAP_SYS_MODULE) {
        ctx.set_return(fail(EPERM));
        return;
    }

    let ptr = args.arg0;
    let len = args.arg1 as usize;
    // arg2 = params_ptr — parsed/used by `narf_modules::loader` once the
    // param string parser lands. Phase 1 ignores user-supplied params;
    // modules read static `.narf_kparams` from their ELF.

    // `copy_module_from_user`: `if (info->len < sizeof(*(info->hdr))) return
    // -ENOEXEC;`. Too short to hold an Elf64 header is a malformed image, not
    // a bad argument, so it is ENOEXEC and not the EINVAL this used to give.
    const ELF64_EHDR_LEN: usize = 64;
    const MAX_MODULE_BYTES: usize = 1 << 28;
    if len < ELF64_EHDR_LEN {
        ctx.set_return(fail(ENOEXEC));
        return;
    }
    if len > MAX_MODULE_BYTES {
        ctx.set_return(fail(EFBIG));
        return;
    }

    // Copy through the checked path. This was a bare
    // `core::slice::from_raw_parts(ptr, len)` over a user-supplied pointer
    // and length with no `validate_user_range`, so a caller could name any
    // kernel address and have up to 256 MiB of it read into a heap buffer
    // that the loader then parsed. `copy_from_user_vec` confines both ends of
    // the range to the user half and brackets the copy, turning an unmapped
    // or kernel-half address into -EFAULT as Linux's `copy_chunked_from_user`
    // does.
    //
    // SAFETY: the range is validated inside `copy_from_user_vec` before any
    // access; this runs in the caller's address space, outside IRQ context.
    let owned = match unsafe { copy_from_user_vec(ptr, len) } {
        Ok(v) => v,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(init_module_result(
        narf_modules::syscalls::sys_init_module(&owned),
    )));
}
