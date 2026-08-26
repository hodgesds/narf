#[allow(unused_imports)]
use super::*;

/// `uname(struct utsname*)` — Linux `SYSCALL_DEFINE1(newuname)`: the sole error
/// is a faulting (or NULL) destination, `copy_to_user(...) → -EFAULT`.
pub(crate) fn sys_uname(ctx: &mut dyn TrapContext) {
    let buf = ctx.args().arg0;
    if buf == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    // Per-task UTS namespace lives behind the `container` feature.
    // Without it the hostname / domainname are flat global strings.
    #[cfg(feature = "container")]
    let (hostname, domainname) = {
        let task = current_task_id();
        let ns = crate::namespaces::current_uts_ns(task);
        (ns.hostname(), ns.domainname())
    };
    #[cfg(not(feature = "container"))]
    let (hostname, domainname): (alloc::string::String, alloc::string::String) =
        (HOSTNAME.lock().clone(), DOMAINNAME.lock().clone());
    let mut kbuf = alloc::vec![0u8; UTSNAME_STRUCT_LEN];
    let mut off = 0usize;
    // sysname / nodename / release / version / machine / domainname.
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], "NARF");
    off += UTSNAME_FIELD_LEN;
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], &hostname);
    off += UTSNAME_FIELD_LEN;
    // `release` must parse as a modern kernel version: software (systemd,
    // glibc, ...) gates features on `uname -r >= X.Y`. systemd warns and
    // disables features below 5.4. Report a 6.x base with a narf suffix.
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], "6.1.0-narf");
    off += UTSNAME_FIELD_LEN;
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], "#1 SMP NARF");
    off += UTSNAME_FIELD_LEN;
    #[cfg(target_arch = "x86_64")]
    let machine = "x86_64";
    #[cfg(target_arch = "aarch64")]
    let machine = "aarch64";
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let machine = "unknown";
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], machine);
    off += UTSNAME_FIELD_LEN;
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], &domainname);
    let _ = off;
    // SAFETY: `buf` is the user `struct utsname` pointer (non-zero, checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of `kbuf`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
