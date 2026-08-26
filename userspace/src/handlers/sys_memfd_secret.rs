#[allow(unused_imports)]
use super::*;

/// `memfd_secret(flags)` — an anonymous fd-backed memory object. Linux
/// also unmaps the pages from the kernel's direct map; NARF has no such
/// map to hide them from, so it reuses the memfd backing. Only
/// FD_CLOEXEC is honoured.
pub(crate) fn sys_memfd_secret(ctx: &mut dyn TrapContext) {
    let flags = ctx.args().arg0 as u32;
    let task = current_task_id();
    // `mm/secretmem.c::SYSCALL_DEFINE1(memfd_secret)` allocates the
    // descriptor with `get_unused_fd_flags`: a full table is -EMFILE.
    #[cfg(feature = "linux-compat")]
    {
        let mfd = crate::linux_compat::MemFdFile::new(0);
        memfd_arc_register(&mfd);
        // FD_CLOEXEC shares MFD_CLOEXEC's bit value (1).
        let cloexec = (flags & crate::linux_compat::MFD_CLOEXEC) != 0;
        let install_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
        let fd = fd::install(task, crate::fd::FdEntry {
                ops: mfd,
                offset: 0,
                flags: install_flags,
                // memfd_secret(2), like memfd_create(2), returns an O_RDWR fd.
                status_flags: crate::fd::O_RDWR,
            });
        match fd {
            Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
            None => ctx.set_return(SyscallReturn::ok((-24i64) as u64)), // -EMFILE
        }
    }
    #[cfg(not(feature = "linux-compat"))]
    {
        let _ = flags;
        let ops = narf_filesystem::new_anon_memfile();
        match fd::install(task, crate::fd::FdEntry {
                ops,
                offset: 0,
                flags: 0,
                // memfd_secret(2), like memfd_create(2), returns an O_RDWR fd.
                status_flags: crate::fd::O_RDWR,
            }) {
            Some(n) => ctx.set_return(SyscallReturn::ok(n as u64)),
            None => ctx.set_return(SyscallReturn::ok((-24i64) as u64)), // -EMFILE
        }
    }
}
