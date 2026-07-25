#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_firmware_install(ctx: &mut dyn TrapContext) {
    // Privilege gate: pull the calling task's per-task firmware-
    // registry authority cap. Tasks granted authority via
    // `narf_firmware::grant_firmware_authority(pid)` hold a
    // live `Cap<FirmwareRegistry, Write>` here; tasks without
    // authority (or whose cap was revoked) see no entry and the
    // syscall fails.
    //
    // The trailer signature check inside `firmware::sys_install`
    // remains the second line of defense; this gate is the first.
    let pid = current_task_id();
    let auth = match narf_firmware::firmware_authority_of(pid) {
        Some(c) => c,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };

    let args = *ctx.args();
    let name_ptr = args.arg0;
    let name_len = args.arg1 as usize;
    let bytes_ptr = args.arg2;
    let bytes_len = args.arg3 as usize;
    if name_len == 0 || bytes_len == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // Cap the staging size so a userspace task can't ask the
    // kernel to copy gigabytes through the syscall path. 16 MiB
    // is well above any real firmware blob (QCNFA765 AMSS is
    // ~5 MiB) and below the limit that would force the registry
    // into a multi-page IOMMU-backed allocation Stage-7 owns.
    const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;
    if bytes_len > MAX_BLOB_BYTES {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // Copy name from user memory under SMAP bracket, then validate UTF-8.
    // The copy_user_path helper handles null/canonical checks.
    let name_str = match copy_user_path(name_ptr, name_len) {
        Some(s) => s,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // Leak the name into 'static memory. The registry stores it
    // by reference; on hot-replace the prior 'static name string
    // is dropped from the registry but stays leaked. Acceptable
    // because firmware-install events are rare (vendor updates,
    // not per-frame).
    let leaked: &'static str = alloc::boxed::Box::leak(name_str.into_boxed_str());

    // Copy firmware bytes from user memory into a kernel-owned Vec
    // under the SMAP bracket before passing into sys_install.
    let mut kbuf = alloc::vec![0u8; bytes_len];
    // SAFETY: `bytes_ptr` is the user blob pointer; copy_from_user range-validates
    // it and SMAP-brackets the read of `bytes_len` (<= MAX_BLOB_BYTES) bytes into `kbuf`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_from_user(&mut kbuf, bytes_ptr) }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // sys_install takes a raw pointer + len; feed it our kernel copy.
    // SAFETY: `kbuf.as_ptr()`/`bytes_len` describe the kernel-owned Vec just filled
    // above, valid and readable for `bytes_len` bytes for the duration of the call.
    // SAFETY: Valid memory or trusted environment
    let r = unsafe { narf_firmware::sys_install(leaked, kbuf.as_ptr(), bytes_len, &auth) };
    match r {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(_) => ctx.set_return(SyscallReturn::invalid_op()),
    }
}
