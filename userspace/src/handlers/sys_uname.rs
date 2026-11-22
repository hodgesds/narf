#[allow(unused_imports)]
use super::*;

/// `uname(struct utsname*)` — Linux `SYSCALL_DEFINE1(newuname)`: the sole error
/// is a faulting (or NULL) destination, `copy_to_user(...) → -EFAULT`.
/// `uname -r`: also what `ETHTOOL_GDRVINFO` reports as a driver's version
/// when the driver sets none (`ethtool_get_drvinfo` uses `init_uts_ns`).
pub(crate) const UTS_RELEASE: &str = "6.1.0-narf";

pub(crate) fn sys_uname(ctx: &mut dyn TrapContext) {
    let buf = ctx.args().arg0;
    if buf == 0 {
        ctx.set_return(errno_ret(EFAULT));
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
    //
    // This is the Linux syscall ABI, not a native NARF identification
    // surface.  System services validate `uname -s` before enabling their
    // Linux code paths; in particular, udisks rejects any other value and
    // immediately retries its probe.  Keep the NARF identity in the release
    // and version fields instead.
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], "Linux");
    off += UTSNAME_FIELD_LEN;
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], &hostname);
    off += UTSNAME_FIELD_LEN;
    // `release` must parse as a modern kernel version: software (systemd,
    // glibc, ...) gates features on `uname -r >= X.Y`. systemd warns and
    // disables features below 5.4. Report a 6.x base with a narf suffix.
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], UTS_RELEASE);
    off += UTSNAME_FIELD_LEN;
    pack_utsname_field(&mut kbuf[off..off + UTSNAME_FIELD_LEN], "#1 SMP NARF");
    off += UTSNAME_FIELD_LEN;
    // `override_architecture` (kernel/sys.c): a task whose execution domain
    // is PER_LINUX32 sees `COMPAT_UTS_MACHINE` ("i686" on x86) — what
    // `setarch i686` / `linux32` ask for. Nothing else changes `machine`: an
    // IA-32 task that has not set the domain sees x86_64, as on Linux.
    #[cfg(target_arch = "x86_64")]
    let machine = {
        // `personality(p)` is the execution-domain byte; PER_LINUX32 = 8.
        const PER_MASK: u32 = 0x00FF;
        const PER_LINUX32: u32 = 0x0008;
        if current_personality() & PER_MASK == PER_LINUX32 {
            "i686"
        } else {
            "x86_64"
        }
    };
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
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
