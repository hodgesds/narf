//! `fd_io` test group (mechanically split from the original flat `tests` module).

#![allow(unused_imports)]
use super::*;

fn smoke_userspace_open_routes_through_vfs() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };

    // ── Tiny FS: one file `hello` returning fixed bytes. ──────────
    static FILE_BYTES: &[u8] = b"VFS-OPENED";
    struct StubFile;
    impl FileOps for StubFile {
        fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async move {
                let off = offset as usize;
                if off >= FILE_BYTES.len() {
                    return Ok(0);
                }
                let n = core::cmp::min(buf.len(), FILE_BYTES.len() - off);
                buf[..n].copy_from_slice(&FILE_BYTES[off..off + n]);
                Ok(n)
            })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            alloc::boxed::Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: FILE_BYTES.len() as u64,
                blocks: 1,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }
    struct StubDir;
    impl DirOps for StubDir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "hello" {
                Some(Arc::new(StubFile))
            } else {
                None
            }
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    struct StubFs;
    impl FsInstance for StubFs {
        fn root(&self) -> Arc<dyn DirOps> {
            Arc::new(StubDir)
        }
        fn name(&self) -> &str {
            "stub"
        }
    }

    // ── Mount the stub FS at "/test". ─────────────────────────────
    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    if registry().mount(&auth, "/test", StubFs).is_err() {
        return TestResult::Fail("VFS mount of stub failed");
    }

    // ── Wire the userspace fd + task-id lookups. ──────────────────
    fd::__test_reset();

    static FAKE_TASK: AtomicU64 = AtomicU64::new(99);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // ── Fire Open via kernel_syscall_entry. ───────────────────────
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }
    // Linux open(2) ABI: arg0 = NUL-terminated absolute path (the
    // mount prefix is part of the path), arg1 = flags.
    let path = b"/test/hello\0";
    let mut ctx = FakeCtx {
        #[cfg(target_arch = "x86_64")]
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: 0, // flags
            ..Default::default()
        },
        #[cfg(target_arch = "aarch64")]
        args: SyscallArgs {
            arg0: 0xffffffffffffff9c, // AT_FDCWD
            arg1: path.as_ptr() as u64,
            arg2: 0, // flags
            ..Default::default()
        },
        ret: None,
    };
    #[cfg(target_arch = "x86_64")]
    kernel_syscall_entry(Syscall::OpenFile.raw(), &mut ctx);
    #[cfg(target_arch = "aarch64")]
    kernel_syscall_entry(Syscall::Openat.raw(), &mut ctx);
    let opened_fd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as u32,
        _ => return TestResult::Fail("Open did not return Ok"),
    };
    if opened_fd != 3 {
        return TestResult::Fail("Open did not return fd 3");
    }

    // ── Read 16 via the new fd, expect FILE_BYTES. ────────────────
    let mut buf = [0u8; 16];
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: opened_fd as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: 16,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    let n = match rctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => return TestResult::Fail("Read after Open returned non-Ok"),
    };
    if n != FILE_BYTES.len() {
        return TestResult::Fail("Read returned wrong byte count");
    }
    if &buf[..n] != FILE_BYTES {
        return TestResult::Fail("Read returned wrong bytes");
    }

    // Cleanup so other tests don't trip over the mount.
    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_open_routes_through_vfs);

fn smoke_userspace_symlink_create_and_readlink_round_trip() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // Mount a fresh MemFs at /sl-test seeded with one regular file
    // `target` containing b"hello". Issue SYS_SYMLINK to create
    // /sl-test/sl pointing at "/sl-test/target", then SYS_READLINK
    // to read it back. Asserts the round-trip preserves the target
    // bytes exactly.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs, MountPoint};

    __test_clear_global();
    fd::__test_reset();

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("sl-test", &[("target", b"hello")]);
    let mount_handle = match registry().mount(&auth, "/sl-test", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("memfs mount failed"),
    };

    static FAKE_TASK: AtomicU64 = AtomicU64::new(99);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    // ── SYS_SYMLINK: target=/sl-test/target, link=/sl-test/sl ────
    // Linux symlink(target, linkpath): arg0 = target ptr, arg1 = linkpath ptr,
    // both NUL-terminated.
    let target = b"/sl-test/target\0";
    let link = b"/sl-test/sl\0";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target.as_ptr() as u64,
            arg1: link.as_ptr() as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Symlink.raw(), &mut ctx);
    match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {}
        _ => {
            let _ = registry().unmount(&mount_handle, "/sl-test");
            __test_clear_global();
            fd::__test_reset();
            return TestResult::Fail("Symlink did not return Ok(0)");
        }
    }

    // ── SYS_READLINK: read /sl-test/sl into a 32-byte buf. ────────
    let mut buf = [0u8; 32];
    let path = b"/sl-test/sl\0";
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            arg3: 0,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Readlink.raw(), &mut rctx);
    let n = match rctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => {
            let _ = registry().unmount(&mount_handle, "/sl-test");
            __test_clear_global();
            fd::__test_reset();
            return TestResult::Fail("Readlink returned non-Ok");
        }
    };
    // `target` now carries a trailing NUL for the Linux-shaped symlink call;
    // the stored link target (and readlink result) excludes it.
    let want = &target[..target.len() - 1];
    if n != want.len() {
        let _ = registry().unmount(&mount_handle, "/sl-test");
        __test_clear_global();
        fd::__test_reset();
        return TestResult::Fail("Readlink returned wrong byte count");
    }
    if &buf[..n] != want {
        let _ = registry().unmount(&mount_handle, "/sl-test");
        __test_clear_global();
        fd::__test_reset();
        return TestResult::Fail("Readlink target bytes mismatched");
    }

    // Cleanup so the registry doesn't accumulate mounts across tests.
    let _ = registry().unmount(&mount_handle, "/sl-test");
    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_symlink_create_and_readlink_round_trip
);

fn smoke_userspace_readlink_on_non_symlink_fails() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // Mount a fresh MemFs at /sl-fail with a regular file `regular`.
    // SYS_READLINK against it must return the -EINVAL (-22) wire value
    // because `regular` isn't FileType::Symlink — POSIX requires EINVAL
    // here so musl's realpath() (which treats anything but EINVAL as
    // fatal) keeps walking. See handlers.rs sys_readlink + commit
    // c8fbbcd1.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs, MountPoint};

    __test_clear_global();
    fd::__test_reset();

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let fs = MemFs::with_seeds("sl-fail", &[("regular", b"x")]);
    let mount_handle = match registry().mount(&auth, "/sl-fail", fs) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("memfs mount failed"),
    };

    static FAKE_TASK: AtomicU64 = AtomicU64::new(99);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    let path = b"/sl-fail/regular\0";
    let mut buf = [0u8; 32];
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            arg3: 0,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Readlink.raw(), &mut rctx);
    let v = match rctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            let _ = registry().unmount(&mount_handle, "/sl-fail");
            __test_clear_global();
            fd::__test_reset();
            return TestResult::Fail("Readlink returned non-Ok status");
        }
    };
    if v != ((-22i64) as u64) {
        let _ = registry().unmount(&mount_handle, "/sl-fail");
        __test_clear_global();
        fd::__test_reset();
        return TestResult::Fail("Readlink on non-symlink should return -EINVAL (-22)");
    }

    let _ = registry().unmount(&mount_handle, "/sl-fail");
    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_readlink_on_non_symlink_fails);

fn smoke_userspace_read_write_routes_through_fd_table() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};

    // Backing FileOps that records writes in a static + serves
    // bytes-of-offset on read.
    static WRITE_LOG: AtomicU64 = AtomicU64::new(0);
    WRITE_LOG.store(0, Ordering::Relaxed);

    struct CountingFile;
    impl FileOps for CountingFile {
        fn read<'a>(&'a self, offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            // Fill buf with low byte of (offset + i).
            for (i, b) in buf.iter_mut().enumerate() {
                *b = ((offset + i as u64) & 0xFF) as u8;
            }
            alloc::boxed::Box::pin(async move { Ok(buf.len()) })
        }
        fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            let n = buf.len();
            alloc::boxed::Box::pin(async move {
                WRITE_LOG.fetch_add(n as u64, Ordering::Relaxed);
                Ok(n)
            })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }

    // Pretend "task 7" is running.
    static FAKE_TASK: AtomicU64 = AtomicU64::new(7);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    install_task_id_lookup(task_lookup);

    // Open one fd in task 7's table.
    let fd_n = fd::with_table(7, |t| {
        t.open(FdEntry {
            ops: Arc::new(CountingFile),
            offset: 0,
            flags: 0,
            // The smoke exercises both read(2) and write(2) through one open
            // file description, so model an O_RDWR open rather than relying
            // on the old type-based access-mode exception.
            status_flags: crate::fd::O_RDWR,
        })
    })
    .expect("with_table");
    if fd_n != 3 {
        return TestResult::Fail("expected first user fd to be 3");
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Synthetic TrapContext for direct kernel-side dispatch.
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    // Read 16 bytes — handler should poll the future and update offset.
    let mut buf = [0u8; 16];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: 16,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    if ctx.ret != Some(SyscallReturn::ok(16)) {
        return TestResult::Fail("Read didn't return 16");
    }
    // Offset should now be 16.
    let got_offset = fd::with_table(7, |t| t.offset(fd_n)).flatten();
    if got_offset != Some(16) {
        return TestResult::Fail("Read didn't advance fd offset");
    }
    // Buffer content: bytes-of-offset starting at 0.
    for (i, b) in buf.iter().enumerate() {
        if *b != (i & 0xFF) as u8 {
            return TestResult::Fail("CountingFile read content mismatch");
        }
    }

    // Write 8 bytes — handler should poll the future + log.
    let payload = [0xABu8; 8];
    let mut ctx2 = FakeCtx {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: payload.as_ptr() as u64,
            arg2: 8,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx2);
    if ctx2.ret != Some(SyscallReturn::ok(8)) {
        return TestResult::Fail("Write didn't return 8");
    }
    if WRITE_LOG.load(Ordering::Relaxed) != 8 {
        return TestResult::Fail("FileOps::write didn't observe payload bytes");
    }
    // Offset should be 16 + 8 = 24.
    let got_offset2 = fd::with_table(7, |t| t.offset(fd_n)).flatten();
    if got_offset2 != Some(24) {
        return TestResult::Fail("Write didn't advance fd offset");
    }

    // Close.
    let mut ctx3 = FakeCtx {
        args: SyscallArgs {
            arg0: fd_n as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Close.raw(), &mut ctx3);
    if ctx3.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("Close didn't return 0");
    }
    // Closed fd should now error on Read.
    let mut buf2 = [0u8; 4];
    let mut ctx4 = FakeCtx {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: buf2.as_mut_ptr() as u64,
            arg2: 4,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx4);
    // read(2) on a closed fd → -EBADF (Linux-conformant; was InvalidOp).
    if ctx4.ret != Some(SyscallReturn::ok((-9i64) as u64)) {
        return TestResult::Fail("Read on closed fd should return -EBADF");
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_read_write_routes_through_fd_table
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_fcntl_flags_round_trip() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext, FD_CLOEXEC,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};

    struct Sink;
    impl FileOps for Sink {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            alloc::boxed::Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xD1);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    install_task_id_lookup(task_lookup);
    let task = FAKE_TASK.load(Ordering::Relaxed);
    let target = fd::with_table(task, |t| {
        t.open(FdEntry {
            ops: Arc::new(Sink),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .expect("with_table");

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    // F_SETFD(FD_CLOEXEC).
    const F_GETFD: u64 = 1;
    const F_SETFD: u64 = 2;
    let mut s_ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target as u64,
            arg1: F_SETFD,
            arg2: FD_CLOEXEC as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut s_ctx);
    if s_ctx.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("F_SETFD did not return 0");
    }

    // F_GETFD should now return FD_CLOEXEC.
    let mut g_ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target as u64,
            arg1: F_GETFD,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut g_ctx);
    match g_ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value == FD_CLOEXEC as u64 => {}
        _ => return TestResult::Fail("F_GETFD did not round-trip FD_CLOEXEC"),
    }

    // Linux checks that the fd is open before it dispatches the fcntl command.
    // D-Bus probes inherited descriptors with F_GETFD; reporting NARF's
    // internal InvalidOp as a successful zero makes every closed descriptor
    // look valid and causes it to walk a bogus inherited-fd set.
    let mut bad_ctx = FakeCtx {
        args: SyscallArgs {
            arg0: target.saturating_add(100) as u64,
            arg1: F_GETFD,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut bad_ctx);
    match bad_ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value as i64 == -9 => {}
        _ => return TestResult::Fail("F_GETFD on a closed fd did not return -EBADF"),
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_fcntl_flags_round_trip);

#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
fn smoke_userspace_fcntl_status_flags() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::{FileOps, FsFuture, Stat};

    struct S;
    impl FileOps for S {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            alloc::boxed::Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::FILE_RW,
                mtime_cycles: 0,
            }
        }
    }
    static TASK: AtomicU64 = AtomicU64::new(0xD3);
    fn t() -> u64 {
        TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    install_task_id_lookup(t);
    let task = TASK.load(Ordering::Relaxed);
    let fd_n = fd::with_table(task, |x| {
        x.open(FdEntry {
            ops: Arc::new(S),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    })
    .expect("table");

    __test_clear_global();
    let mut tbl = SyscallTable::new();
    install_core_syscalls(&mut tbl);
    install_global(tbl);

    struct C {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for C {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    // F_SETFL O_NONBLOCK | O_APPEND.
    let want = (crate::fd::O_NONBLOCK | crate::fd::O_APPEND) as u64;
    let mut s = C {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: 4,
            arg2: want,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut s);
    if s.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("F_SETFL did not return 0");
    }
    // F_GETFL should report the same bits (masked to the settable set).
    let mut g = C {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: 3,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut g);
    match g.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value & want == want => {}
        _ => return TestResult::Fail("F_GETFL did not round-trip O_NONBLOCK|O_APPEND"),
    }
    // Verify the shared open-file description carries the bits.
    let observed = fd::with_table(task, |x| x.status_flags(fd_n))
        .flatten()
        .unwrap_or(0);
    if (observed as u64) & want != want {
        return TestResult::Fail("FdEntry.status_flags missing the bits");
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
kernel_test_in!("userspace", smoke_userspace_fcntl_status_flags);

#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
fn smoke_userspace_fcntl_setlk_conflict() -> TestResult {
    use crate::fd::locks;
    locks::__test_reset();
    // Same key, two owners, overlapping write requests.
    let key: usize = 0xDEAD_BEEF;
    let a = locks::Lock {
        owner: 1,
        ty: locks::F_WRLCK,
        start: 0,
        len: 100,
    };
    let b = locks::Lock {
        owner: 2,
        ty: locks::F_WRLCK,
        start: 50,
        len: 100,
    };
    if locks::try_set(key, a).is_err() {
        return TestResult::Fail("first lock install must succeed");
    }
    match locks::try_set(key, b) {
        Err(blocker) if blocker.owner == 1 => {}
        Ok(()) => return TestResult::Fail("overlapping write lock must conflict"),
        Err(_) => return TestResult::Fail("blocker should be owner 1"),
    }
    // Probe must surface the same blocker.
    match locks::probe(key, b) {
        Some(l) if l.owner == 1 && l.ty == locks::F_WRLCK => {}
        _ => return TestResult::Fail("probe did not surface blocker"),
    }
    // Two readers must coexist.
    locks::__test_reset();
    let r1 = locks::Lock {
        owner: 1,
        ty: locks::F_RDLCK,
        start: 0,
        len: 100,
    };
    let r2 = locks::Lock {
        owner: 2,
        ty: locks::F_RDLCK,
        start: 50,
        len: 100,
    };
    if locks::try_set(key, r1).is_err() || locks::try_set(key, r2).is_err() {
        return TestResult::Fail("overlapping read locks must coexist");
    }
    // Release on owner-exit clears the bucket.
    locks::release_owner(1);
    locks::release_owner(2);
    if locks::probe(key, r1).is_some() {
        return TestResult::Fail("release_owner did not drain locks");
    }
    locks::__test_reset();
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", feature = "linux-compat"))]
kernel_test_in!("userspace", smoke_userspace_fcntl_setlk_conflict);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_pipe_round_trip() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xD3);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    fd::__test_reset();
    install_task_id_lookup(task_lookup);

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    // pipe(out) — kernel writes [read_fd, write_fd] to `out`.
    let mut fds: [i32; 2] = [-1, -1];
    let mut pctx = FakeCtx {
        args: SyscallArgs {
            arg0: fds.as_mut_ptr() as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pipe.raw(), &mut pctx);
    if pctx.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("Pipe did not return Ok");
    }
    if fds[0] < 3 || fds[1] < 3 || fds[0] == fds[1] {
        return TestResult::Fail("Pipe returned bad fd pair");
    }
    let read_fd = fds[0] as u32;
    let write_fd = fds[1] as u32;

    // Write 4 bytes to the writer.
    let payload = b"PIPE";
    let mut wctx = FakeCtx {
        args: SyscallArgs {
            arg0: write_fd as u64,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut wctx);
    if wctx.ret != Some(SyscallReturn::ok(payload.len() as u64)) {
        return TestResult::Fail("Pipe write did not return full byte count");
    }

    // Read 4 bytes from the reader.
    let mut buf = [0u8; 4];
    let mut rctx = FakeCtx {
        args: SyscallArgs {
            arg0: read_fd as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    if rctx.ret != Some(SyscallReturn::ok(4)) {
        return TestResult::Fail("Pipe read did not return 4");
    }
    if &buf != payload {
        return TestResult::Fail("Pipe round-trip bytes mismatch");
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_pipe_round_trip);

fn smoke_userspace_fd_table_roundtrip() -> TestResult {
    use crate::{fd, FdEntry};
    use alloc::sync::Arc;
    use narf_filesystem::{FileOps, FsFuture, Stat};

    // Tiny FileOps stub that returns a fixed buffer slice.
    struct FixedFile;
    impl FileOps for FixedFile {
        fn read<'a>(&'a self, _offset: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
            buf.fill(0xAB);
            alloc::boxed::Box::pin(async move { Ok(buf.len()) })
        }
        fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
            alloc::boxed::Box::pin(async move { Ok(buf.len()) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }

    fd::__test_reset();

    let task_a: u64 = 0xAA;
    let task_b: u64 = 0xBB;

    // Open in task A: first user fd is 3 (slots 0..=2 reserved).
    let fd_a = fd::with_table(task_a, |t| {
        t.open(FdEntry {
            ops: Arc::new(FixedFile),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    });
    if fd_a != Some(3) {
        return TestResult::Fail("first user fd should be 3");
    }

    // Independent task B starts with a fresh table.
    let fd_b = fd::with_table(task_b, |t| {
        t.open(FdEntry {
            ops: Arc::new(FixedFile),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    });
    if fd_b != Some(3) {
        return TestResult::Fail("task B should also get fd 3");
    }
    if fd::live_task_count() < 2 {
        return TestResult::Fail("two task tables should be live");
    }

    // Mutating the open-file-description offset.
    fd::with_table(task_a, |t| t.set_offset(3, 100));
    let off_a = fd::with_table(task_a, |t| t.offset(3)).flatten();
    if off_a != Some(100) {
        return TestResult::Fail("offset update did not stick");
    }
    let off_b = fd::with_table(task_b, |t| t.offset(3)).flatten();
    if off_b != Some(0) {
        return TestResult::Fail("task B's offset should be independent");
    }

    // fork copies descriptor slots but aliases each open-file description.
    let child = 0xCC;
    if fd::fork(task_a, child) < 4 {
        return TestResult::Fail("fork did not inherit the parent fd table");
    }
    fd::with_table(child, |t| {
        t.set_offset(3, 125);
        t.set_status_flags(3, crate::fd::O_NONBLOCK);
    });
    let parent_state =
        fd::with_table(task_a, |t| Some((t.offset(3)?, t.status_flags(3)?))).flatten();
    if parent_state != Some((125, crate::fd::O_NONBLOCK)) {
        return TestResult::Fail("fork did not share offset/status description state");
    }
    fd::detach(child);

    // Close fd 3 in A, then re-open should reuse slot 3.
    let closed = fd::with_table(task_a, |t| t.close(3));
    if closed != Some(true) {
        return TestResult::Fail("close should report true on live fd");
    }
    let reused = fd::with_table(task_a, |t| {
        t.open(FdEntry {
            ops: Arc::new(FixedFile),
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    });
    if reused != Some(3) {
        return TestResult::Fail("close + open should reuse slot 3");
    }

    // Detach task A; table count drops back.
    fd::detach(task_a);
    if fd::live_task_count() != 1 {
        return TestResult::Fail("detach did not drop task A's table");
    }

    fd::__test_reset();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_fd_table_roundtrip);

fn smoke_userspace_getrandom_fills_buffer() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // First call: fill a 16-byte buffer. Returns 16, buffer mostly
    // non-zero (false-positive rate of "all zeros under a real RNG"
    // is 2^-128 — tolerable as a smoke).
    let mut buf = [0u8; 16];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf.as_mut_ptr() as u64,
            arg1: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetRandom.raw(), &mut ctx);
    let n = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => return TestResult::Fail("getrandom did not return OK"),
    };
    if n != 16 {
        return TestResult::Fail("getrandom byte-count != 16");
    }
    if buf.iter().all(|&b| b == 0) {
        return TestResult::Fail("getrandom buffer is all zeros");
    }

    // Second call: fill again, expect a different stream.
    let prev = buf;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf.as_mut_ptr() as u64,
            arg1: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetRandom.raw(), &mut ctx);
    if buf == prev {
        return TestResult::Fail("two consecutive getrandom calls returned identical bytes");
    }

    // Null pointer rejected with -1.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 16,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetRandom.raw(), &mut ctx);
    let null_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );
    if !null_rejected {
        return TestResult::Fail("getrandom did not reject null buffer");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_getrandom_fills_buffer);

fn smoke_userspace_listdir_walks_memfs() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // Mount a fresh MemFs at /list-test seeded with three entries
    // and walk it via SYS_LISTDIR. Each call advances the cursor
    // by one; the kernel re-snapshots each invocation. End-of-
    // directory surfaces as `value = 0`.
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use narf_filesystem as fs;

    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let auth = fs::bootstrap_mount_authority();
    // The validate harness may have left /list-test behind from a
    // prior run; tolerate Busy to keep the test idempotent.
    let _ = fs::registry().mount(
        &auth,
        "/list-test",
        fs::MemFs::with_seeds(
            "list-test",
            &[("alpha", b"a"), ("beta", b"b"), ("gamma", b"c")],
        ),
    );

    fn one_call(path: &str, cursor: u64, out: &mut [u8]) -> Option<SyscallReturn> {
        struct FakeCtx {
            args: SyscallArgs,
            ret: Option<SyscallReturn>,
        }
        impl TrapContext for FakeCtx {
            fn args(&self) -> &SyscallArgs {
                &self.args
            }
            fn set_return(&mut self, r: SyscallReturn) {
                self.ret = Some(r);
            }
            fn user_rsp(&self) -> u64 {
                0
            }
            fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
                false
            }

            fn rip(&self) -> u64 {
                0
            }
            fn set_rip(&mut self, _rip: u64) {}
        }
        let mut ctx = FakeCtx {
            args: SyscallArgs {
                arg0: path.as_ptr() as u64,
                arg1: path.len() as u64,
                arg2: cursor,
                arg3: out.as_mut_ptr() as u64,
                arg4: out.len() as u64,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Listdir.raw(), &mut ctx);
        ctx.ret
    }

    fn parse(out: &[u8], n: usize) -> Option<(alloc::string::String, u32)> {
        if n < 8 {
            return None;
        }
        let name_len = u32::from_le_bytes(out[0..4].try_into().ok()?) as usize;
        let ftype = u32::from_le_bytes(out[4..8].try_into().ok()?);
        if 8 + name_len > n {
            return None;
        }
        let name = core::str::from_utf8(&out[8..8 + name_len]).ok()?.into();
        Some((name, ftype))
    }

    let mut buf = [0u8; 64];
    let mut names: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    let mut types_ok = true;

    for cursor in 0..4 {
        let r = match one_call("/list-test", cursor, &mut buf) {
            Some(r) if r.status == SyscallReturn::OK => r,
            _ => return TestResult::Fail("listdir returned non-OK"),
        };
        if cursor == 3 {
            // Past last entry — expect value = 0.
            if r.value != 0 {
                return TestResult::Fail("listdir cursor=3 did not surface end-of-dir");
            }
            break;
        }
        let n = r.value as usize;
        if n == 0 {
            return TestResult::Fail("listdir produced premature end-of-dir");
        }
        let (name, ft) = match parse(&buf, n) {
            Some(p) => p,
            None => return TestResult::Fail("listdir wire-decode failed"),
        };
        if ft != 0 {
            types_ok = false;
        } // 0 = File
        names.push(name);
    }

    __test_clear_global();

    names.sort();
    if names.as_slice() != ["alpha", "beta", "gamma"] {
        return TestResult::Fail("listdir entries did not match seed set");
    }
    if !types_ok {
        return TestResult::Fail("listdir reported non-File type for seeded files");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_listdir_walks_memfs);

fn smoke_userspace_ftruncate_grows_and_shrinks_memfile() -> TestResult {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};

    // Inline single-shot future poller — MemFs reads/writes are
    // immediately ready, so we don't need a real executor here.
    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        fn raw_waker() -> RawWaker {
            unsafe fn no_clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            unsafe fn no_op(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        // SAFETY: `raw_waker()` pairs a null data pointer with a static vtable whose
        // clone/wake/wake_by_ref/drop are all no-ops that never dereference the data
        // pointer, so the `RawWaker` upholds the `Waker` contract.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: future is on this stack frame and not moved.
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    // Mount a fresh MemFs with a seeded 6-byte file. Ftruncate
    // grows it to 16, shrinks to 3, then reads to verify each.
    let auth = bootstrap_mount_authority();
    let _ = registry().mount(
        &auth,
        "/trunc",
        MemFs::with_seeds("trunc-test", &[("f", b"abcdef")]),
    );

    let ops = registry()
        .resolve_absolute("/trunc/f", |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        })
        .flatten();
    let ops = match ops {
        Some(o) => o,
        None => return TestResult::Fail("resolve /trunc/f failed"),
    };

    // Initial size = 6.
    if ops.stat().size != 6 {
        return TestResult::Fail("initial file size != 6");
    }

    // Grow to 16. The new tail is zero-filled per POSIX.
    if poll_once(ops.truncate(16)).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("truncate grow failed");
    }
    if ops.stat().size != 16 {
        return TestResult::Fail("size after grow != 16");
    }
    let mut buf = [0xAAu8; 16];
    let n = match poll_once(ops.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("post-grow read failed"),
    };
    if n != 16 || &buf[0..6] != b"abcdef" || buf[6..16].iter().any(|&b| b != 0) {
        return TestResult::Fail("post-grow contents wrong");
    }

    // Shrink to 3. Re-stat must report 3 bytes; read confirms tail
    // is gone.
    if poll_once(ops.truncate(3)).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("truncate shrink failed");
    }
    if ops.stat().size != 3 {
        return TestResult::Fail("size after shrink != 3");
    }
    let mut buf2 = [0u8; 16];
    let n2 = match poll_once(ops.read(0, &mut buf2)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("post-shrink read failed"),
    };
    if n2 != 3 || &buf2[..3] != b"abc" {
        return TestResult::Fail("post-shrink contents wrong");
    }

    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_ftruncate_grows_and_shrinks_memfile
);

fn smoke_userspace_pread_pwrite_dont_move_cursor() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    crate::fd::__test_reset();

    let auth = bootstrap_mount_authority();
    let _ = registry().mount(
        &auth,
        "/pio",
        MemFs::with_seeds("pio-test", &[("f", b"abcdefghij")]),
    );

    // Open the file via SYS_OPEN.
    // Linux open(2) ABI: arg0 = NUL-terminated absolute path, arg1 = flags.
    let path = b"/pio/f\0";
    let mut ctx = FakeCtx {
        #[cfg(target_arch = "x86_64")]
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: 0, // flags
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        #[cfg(target_arch = "aarch64")]
        args: SyscallArgs {
            arg0: 0xffffffffffffff9c, // AT_FDCWD
            arg1: path.as_ptr() as u64,
            arg2: 0, // flags
            ..Default::default()
        },
        ret: None,
    };
    #[cfg(target_arch = "x86_64")]
    kernel_syscall_entry(Syscall::OpenFile.raw(), &mut ctx);
    #[cfg(target_arch = "aarch64")]
    kernel_syscall_entry(Syscall::Openat.raw(), &mut ctx);
    let fd = match ctx.ret {
        Some(r) if r.value != !0u64 => r.value as u32,
        _ => return TestResult::Fail("open /pio/f failed"),
    };

    // pread at offset 5 → "fghij" (5 bytes).
    let mut rbuf = [0u8; 5];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: rbuf.as_mut_ptr() as u64,
            arg2: rbuf.len() as u64,
            arg3: 5,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pread64.raw(), &mut ctx);
    let n = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => return TestResult::Fail("pread failed"),
    };
    if n != 5 || &rbuf != b"fghij" {
        return TestResult::Fail("pread contents wrong");
    }

    // The fd's offset must still be 0 — confirm with a regular read.
    let mut head = [0u8; 4];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: head.as_mut_ptr() as u64,
            arg2: head.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    let m = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => return TestResult::Fail("post-pread read failed"),
    };
    if m != 4 || &head != b"abcd" {
        return TestResult::Fail("pread moved the cursor");
    }

    // pwrite at offset 8 → overwrite "ij" with "ZZ".
    let payload = b"ZZ";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            arg3: 8,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pwrite64.raw(), &mut ctx);
    let pw = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => return TestResult::Fail("pwrite failed"),
    };
    if pw != 2 {
        return TestResult::Fail("pwrite did not write 2 bytes");
    }

    // Read at offset 8 to confirm.
    let mut tail = [0u8; 2];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: tail.as_mut_ptr() as u64,
            arg2: tail.len() as u64,
            arg3: 8,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pread64.raw(), &mut ctx);
    if &tail != b"ZZ" {
        return TestResult::Fail("pwrite did not stick");
    }

    let _ = crate::fd::with_table(0, |t| t.close(fd));
    crate::fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_pread_pwrite_dont_move_cursor);

/// `fd::open_fds` returns the exact set of open fd numbers, ascending, and
/// skips closed slots (holes). This backs `/proc/<pid>/fd` enumeration.
fn smoke_userspace_open_fds_enumerates_with_gaps() -> TestResult {
    let task = 0x0FD5_9001u64;
    // A fresh table pre-populates stdio at 0,1,2.
    let base = crate::fd::open_fds(task);
    if base != [0, 1, 2] {
        return TestResult::Fail("fresh table did not list stdio 0,1,2");
    }
    // Open three anon files → fds 3,4,5.
    let mut opened = [0u32; 3];
    for slot in opened.iter_mut() {
        let n = crate::fd::with_table(task, |t| {
            t.open(crate::fd::FdEntry {
                ops: narf_filesystem::memfs::new_anon_file(),
                offset: 0,
                flags: 0,
                status_flags: 0,
            })
        });
        match n {
            Some(fd) => *slot = fd,
            None => return TestResult::Fail("with_table open failed"),
        }
    }
    if opened != [3, 4, 5] || crate::fd::open_fds(task) != [0, 1, 2, 3, 4, 5] {
        return TestResult::Fail("open_fds did not list the newly opened fds");
    }
    // Close fd 4 → a hole; enumeration must skip it, not truncate at it.
    let closed = crate::fd::with_table(task, |t| t.close(4)).unwrap_or(false);
    if !closed {
        return TestResult::Fail("close(4) failed");
    }
    if crate::fd::open_fds(task) != [0, 1, 2, 3, 5] {
        return TestResult::Fail("open_fds did not skip the closed slot");
    }
    crate::fd::__test_reset();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_open_fds_enumerates_with_gaps);

fn smoke_userspace_getrusage_writes_18_i64s() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut buf = [0xFEi64; 18];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: buf.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getrusage.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("getrusage did not return OK");
    }
    // ru_utime (0-1), ru_stime (2-3, real since the kernel-time
    // bracket landed), and ru_maxrss (4) may all be non-zero now;
    // the 13 tail fields stay zero.
    if buf[0] < 0 || buf[1] < 0 {
        return TestResult::Fail("ru_utime negative");
    }
    if buf[2] < 0 || buf[3] < 0 || buf[4] < 0 {
        return TestResult::Fail("ru_stime/ru_maxrss negative");
    }
    for &field in &buf[5..18] {
        if field != 0 {
            return TestResult::Fail("tail field of rusage was not zero");
        }
    }

    // Null pointer rejected.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getrusage.raw(), &mut ctx);
    let null_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );
    if !null_rejected {
        return TestResult::Fail("getrusage did not reject null buffer");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_getrusage_writes_18_i64s);

fn smoke_userspace_fallocate_extends_and_zero_ranges_memfile() -> TestResult {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};

    fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
        fn raw_waker() -> RawWaker {
            unsafe fn no_clone(_: *const ()) -> RawWaker {
                raw_waker()
            }
            unsafe fn no_op(_: *const ()) {}
            const VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
            RawWaker::new(core::ptr::null(), &VTAB)
        }
        // SAFETY: `raw_waker()` pairs a null data pointer with a static vtable whose
        // clone/wake/wake_by_ref/drop are all no-ops that never dereference the data
        // pointer, so the `RawWaker` upholds the `Waker` contract.
        // SAFETY: Valid memory or trusted environment
        let waker = unsafe { Waker::from_raw(raw_waker()) };
        let mut cx = Context::from_waker(&waker);
        // SAFETY: `fut` lives in this stack frame and is never moved before the poll
        // completes, so pinning a mutable reference to it is sound.
        // SAFETY: Valid memory or trusted environment
        let pinned = unsafe { Pin::new_unchecked(&mut fut) };
        match pinned.poll(&mut cx) {
            Poll::Ready(v) => Some(v),
            Poll::Pending => None,
        }
    }

    let auth = bootstrap_mount_authority();
    let _ = registry().mount(
        &auth,
        "/falloc",
        MemFs::with_seeds(
            "falloc-test",
            &[("f", b"abcdefghij")], // 10 bytes
        ),
    );
    let ops = registry()
        .resolve_absolute("/falloc/f", |fs, rel| {
            narf_filesystem::resolve(fs.root(), rel).ok()
        })
        .flatten();
    let ops = match ops {
        Some(o) => o,
        None => return TestResult::Fail("resolve /falloc/f failed"),
    };

    // Direct trait round-trip — the syscall path adds nothing
    // beyond fd-table indirection and the smoke for that already
    // exists in the ftruncate test.
    if poll_once(ops.truncate(20)).and_then(|r| r.ok()).is_none() {
        return TestResult::Fail("baseline truncate failed");
    }
    if ops.stat().size != 20 {
        return TestResult::Fail("size after truncate(20) != 20");
    }
    let mut buf = [0xFFu8; 20];
    let n = match poll_once(ops.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read post-truncate failed"),
    };
    // First 10 bytes preserved; tail zero from the grow.
    if n != 20 || &buf[0..10] != b"abcdefghij" || buf[10..20].iter().any(|&b| b != 0) {
        return TestResult::Fail("post-truncate(20) contents wrong");
    }

    // Now exercise FALLOC_FL_ZERO_RANGE in-place: zero bytes
    // [3..7] of the file. The handler writes zeros; equivalent
    // to writing four 0u8 bytes at offset 3.
    let zeros = [0u8; 4];
    let written = match poll_once(ops.write(3, &zeros)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("write zeros failed"),
    };
    if written != 4 {
        return TestResult::Fail("zero-range write didn't write 4 bytes");
    }
    let mut buf2 = [0xAAu8; 20];
    let _ = poll_once(ops.read(0, &mut buf2));
    if &buf2[..3] != b"abc" || buf2[3..7] != [0; 4] || &buf2[7..10] != b"hij" {
        return TestResult::Fail("zero-range did not zero [3..7]");
    }

    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_fallocate_extends_and_zero_ranges_memfile
);

fn smoke_userspace_copy_file_range_round_trip() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);
    crate::fd::__test_reset();

    let auth = bootstrap_mount_authority();
    let _ = registry().mount(
        &auth,
        "/cfr",
        MemFs::with_seeds("cfr-test", &[("src", b"abcdefghij"), ("dst", b"")]),
    );

    fn open(path: &str, flags: u64) -> Option<u32> {
        struct FakeCtx {
            args: SyscallArgs,
            ret: Option<SyscallReturn>,
        }
        impl TrapContext for FakeCtx {
            fn args(&self) -> &SyscallArgs {
                &self.args
            }
            fn set_return(&mut self, r: SyscallReturn) {
                self.ret = Some(r);
            }
            fn user_rsp(&self) -> u64 {
                0
            }
            fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
                false
            }

            fn rip(&self) -> u64 {
                0
            }
            fn set_rip(&mut self, _rip: u64) {}
        }
        // Linux open(2) ABI: arg0 = NUL-terminated absolute path,
        // arg1 = flags.
        let mut cpath = alloc::vec::Vec::from(path.as_bytes());
        cpath.push(0);
        let mut ctx = FakeCtx {
            #[cfg(target_arch = "x86_64")]
            args: SyscallArgs {
                arg0: cpath.as_ptr() as u64,
                arg1: flags,
                ..SyscallArgs::default()
            },
            #[cfg(target_arch = "aarch64")]
            args: SyscallArgs {
                arg0: 0xffffffffffffff9c, // AT_FDCWD
                arg1: cpath.as_ptr() as u64,
                arg2: flags,
                ..SyscallArgs::default()
            },
            ret: None,
        };
        #[cfg(target_arch = "x86_64")]
        kernel_syscall_entry(Syscall::OpenFile.raw(), &mut ctx);
        #[cfg(target_arch = "aarch64")]
        kernel_syscall_entry(Syscall::Openat.raw(), &mut ctx);
        match ctx.ret {
            Some(r) if r.value != !0u64 => Some(r.value as u32),
            _ => None,
        }
    }

    let fd_in = match open("/cfr/src", crate::fd::O_RDONLY as u64) {
        Some(f) => f,
        None => return TestResult::Fail("open src failed"),
    };
    // O_RDWR keeps the output writable for copy_file_range and readable for
    // the positional verification below. Linux's f_mode checks require both.
    let fd_out = match open("/cfr/dst", crate::fd::O_RDWR as u64) {
        Some(f) => f,
        None => return TestResult::Fail("open dst failed"),
    };

    // Copy 5 bytes from src@0 → dst@0. Linux ABI: the offsets are
    // `loff_t *`, and NULL means "use + advance this fd's cursor".
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd_in as u64,
            arg1: 0, // off_in = NULL
            arg2: fd_out as u64,
            arg3: 0, // off_out = NULL
            arg4: 5,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::CopyFileRange.raw(), &mut ctx);
    let copied = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => return TestResult::Fail("copy_file_range did not return OK"),
    };
    if copied != 5 {
        return TestResult::Fail("copy_file_range did not copy 5 bytes");
    }

    // Verify dst contents via a positional read.
    let mut buf = [0u8; 5];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd_out as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Pread64.raw(), &mut ctx);
    if &buf != b"abcde" {
        return TestResult::Fail("dst contents wrong after copy_file_range");
    }

    // flags != 0 rejected with -EINVAL, as Linux does.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd_in as u64,
            arg1: 0,
            arg2: fd_out as u64,
            arg3: 0,
            arg4: 1,
            arg5: 1,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::CopyFileRange.raw(), &mut ctx);
    let flags_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-22i64) as u64,
    );
    if !flags_rejected {
        return TestResult::Fail("copy_file_range did not reject non-zero flags with -EINVAL");
    }

    crate::fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_copy_file_range_round_trip);

/// An eventfd's `write` must fire a readiness notify (and it must advertise
/// `readiness_notifies()`), so a blocking `poll`/`epoll` containing an eventfd
/// can PARK instead of busy-spinning. glib's main loop wakes its worker via an
/// eventfd write; without the notify a Qt/glib client (kwin) busy-spun its
/// event loop and — under the cooperative own-stack scheduler — starved a
/// same-CPU peer (dbus-daemon), stalling D-Bus round-trips ~25s.
#[cfg(target_arch = "x86_64")]
fn smoke_userspace_eventfd_write_fires_readiness_notify() -> TestResult {
    use narf_filesystem::FileOps;
    let ev = crate::io_mux::EventFd::new(0, 0);
    if !ev.readiness_notifies() {
        return TestResult::Fail("eventfd readiness_notifies() must be true so a poll can park");
    }
    let before = narf_net::readiness::generation();
    // write() adds to the counter and must bump the readiness generation.
    let r = crate::handlers::poll_blocking(ev.write(0, &1u64.to_le_bytes()));
    if !matches!(r, Some(Ok(8))) {
        return TestResult::Fail("eventfd write(8 bytes) did not return 8");
    }
    if narf_net::readiness::generation() <= before {
        return TestResult::Fail("eventfd write() did not bump the readiness generation");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace",
    smoke_userspace_eventfd_write_fires_readiness_notify
);

/// `thread_group_live_count` (backs /proc/[pid]/status `Threads:` and
/// stat field 20) reports 1 for an untracked single-threaded group and
/// the tracked count for a multi-threaded one.
fn smoke_userspace_thread_group_live_count() -> TestResult {
    use crate::handlers::{
        __test_thread_group_live_reset, thread_group_live_count, thread_group_live_dec_state,
        thread_group_live_inc,
    };
    __test_thread_group_live_reset();
    const PID: u64 = 7100;
    // Untracked group → implicit 1.
    if thread_group_live_count(PID) != 1 {
        __test_thread_group_live_reset();
        return TestResult::Fail("untracked group must count as 1 thread");
    }
    // Two CLONE_THREAD siblings join the implicit main → count 3.
    thread_group_live_inc(PID);
    thread_group_live_inc(PID);
    if thread_group_live_count(PID) != 3 {
        __test_thread_group_live_reset();
        return TestResult::Fail("tracked group must report its live thread count");
    }
    if thread_group_live_dec_state(PID) != (false, true)
        || thread_group_live_dec_state(PID) != (false, true)
        || thread_group_live_dec_state(PID) != (true, true)
    {
        __test_thread_group_live_reset();
        return TestResult::Fail("tracked group exit state lost multi-threaded provenance");
    }
    if thread_group_live_dec_state(PID + 1) != (true, false) {
        __test_thread_group_live_reset();
        return TestResult::Fail("untracked exit must stay on the single-thread fast path");
    }
    __test_thread_group_live_reset();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_thread_group_live_count);

fn smoke_userspace_getdents64_writes_linux_records() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use narf_filesystem::{bootstrap_mount_authority, registry, MemFs};
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    use crate::install_task_id_lookup;
    use core::sync::atomic::{AtomicU64, Ordering};
    static GD_TID: AtomicU64 = AtomicU64::new(0x6D70);
    fn gd_task() -> u64 {
        GD_TID.load(Ordering::Relaxed)
    }
    install_task_id_lookup(gd_task);

    __test_clear_global();
    crate::fd::__test_reset();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let auth = bootstrap_mount_authority();
    let gd_mount = registry()
        .mount(
            &auth,
            "/gd",
            MemFs::with_seeds(
                "gd-test",
                &[("alpha", b"a"), ("beta", b"b"), ("gamma", b"c")],
            ),
        )
        .ok();
    let cleanup_gd = || {
        if let Some(h) = &gd_mount {
            let _ = registry().unmount(h, "/gd");
        }
        crate::fd::__test_reset();
    };

    // getdents64 is now fd-based (Linux ABI). Open the directory to get
    // a dir fd, then read it.
    let fd = match crate::handlers::__test_open_dir_fd(gd_task(), "/gd") {
        Some(f) => f,
        None => {
            crate::handlers::__test_reset_task_id_lookup();
            cleanup_gd();
            return TestResult::Fail("could not open /gd as a directory fd");
        }
    };

    let mut buf = [0u8; 256];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getdents64.raw(), &mut ctx);
    // Done with the task-id lookup; reset so it doesn't leak into
    // sibling kernel_test cases that assume the default id.
    crate::handlers::__test_reset_task_id_lookup();
    let written = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as usize,
        _ => {
            cleanup_gd();
            return TestResult::Fail("getdents64 did not return OK");
        }
    };
    if written == 0 {
        cleanup_gd();
        return TestResult::Fail("getdents64 returned 0 bytes");
    }

    // Walk the records and collect names.
    let mut names: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    let mut pos = 0usize;
    while pos + 19 <= written {
        let reclen = u16::from_le_bytes(buf[pos + 16..pos + 18].try_into().unwrap()) as usize;
        if reclen < 20 || pos + reclen > written {
            break;
        }
        // d_name at offset 19, NUL-terminated.
        let name_start = pos + 19;
        let mut nlen = 0usize;
        while name_start + nlen < pos + reclen && buf[name_start + nlen] != 0 {
            nlen += 1;
        }
        let name = core::str::from_utf8(&buf[name_start..name_start + nlen]).unwrap();
        names.push(name.into());
        pos += reclen;
    }
    if pos != written {
        cleanup_gd();
        return TestResult::Fail("walk did not cover the written length exactly");
    }
    names.sort();
    if names.as_slice() != ["alpha", "beta", "gamma"] {
        cleanup_gd();
        return TestResult::Fail("getdents64 didn't enumerate all entries");
    }

    cleanup_gd();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_getdents64_writes_linux_records);

fn smoke_userspace_pipe_empty_read_is_would_block_until_writer_closes() -> TestResult {
    // The blocking-read decision behind shell `$(...)` substitution: a
    // pipe read end whose buffer is empty but whose writer is still open
    // must report `WouldBlock` (so sys_read parks and waits for data) — and
    // must return EOF once the last writer drops. The
    // writer drops here via the `Arc<PipeWrite>` going out of scope,
    // mirroring what `fd::detach` does when a writer task exits.
    use narf_filesystem::FileOps;
    let (r, w) = crate::pipe::pipe_pair();
    if !r.readiness_notifies() || !w.readiness_notifies() {
        return TestResult::Fail("pipe endpoints must advertise readiness notifications");
    }
    // Empty buffer + writer open → would-block.
    let mut empty = [0u8; 1];
    if !matches!(
        crate::handlers::poll_blocking(r.read(0, &mut empty)),
        Some(Err(narf_filesystem::FsError::WouldBlock))
    ) {
        return TestResult::Fail("empty pipe with open writer did not report would-block");
    }
    let before_write = narf_net::readiness::generation();
    let wr = crate::handlers::poll_blocking(w.write(0, b"x"));
    if !matches!(wr, Some(Ok(1))) {
        return TestResult::Fail("pipe readiness test write failed");
    }
    if narf_net::readiness::generation() <= before_write {
        return TestResult::Fail("pipe write did not notify readiness waiters");
    }
    let mut byte = [0u8; 1];
    if !matches!(
        crate::handlers::poll_blocking(r.read(0, &mut byte)),
        Some(Ok(1))
    ) {
        return TestResult::Fail("pipe readiness test read failed");
    }
    // Last writer closes → EOF.
    let before_close = narf_net::readiness::generation();
    drop(w);
    if narf_net::readiness::generation() <= before_close {
        return TestResult::Fail("pipe writer close did not notify readiness waiters");
    }
    if !matches!(
        crate::handlers::poll_blocking(r.read(0, &mut empty)),
        Some(Ok(0))
    ) {
        return TestResult::Fail("closed writer did not return EOF");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_pipe_empty_read_is_would_block_until_writer_closes
);

fn smoke_userspace_init_per_task_state_is_idempotent() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        init_per_task_state, install_core_syscalls, install_global, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    // Reset every per-task table so we observe the post-init state
    // from a known floor.
    crate::handlers::__test_uidgid_reset();
    crate::handlers::__test_hostname_reset();
    crate::handlers::__test_rlimit_reset();
    crate::handlers::__test_nice_reset();
    crate::handlers::__test_umask_reset();
    crate::handlers::__test_prctl_reset();

    // Single call wires everything.
    init_per_task_state();
    // Re-running must not corrupt state.
    init_per_task_state();

    // After init, getuid (a noop_ok-style call that depends on
    // UIDGID_TABLE existing) must return the default 0.
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetUid.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("getuid did not return 0 after init_per_task_state");
    }

    // gethostname must surface "narf".
    let mut buf = [0u8; 16];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf.as_mut_ptr() as u64,
            arg1: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetHostname.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.value as i64 == 4) {
        return TestResult::Fail("gethostname did not return 4 bytes");
    }
    if &buf[..4] != b"narf" {
        return TestResult::Fail("hostname not initialised to 'narf'");
    }

    // umask returns 0o022 default.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0o077,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Umask.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.value == 0o022) {
        return TestResult::Fail("umask default not 0o022 after init");
    }

    crate::handlers::__test_uidgid_reset();
    crate::handlers::__test_hostname_reset();
    crate::handlers::__test_rlimit_reset();
    crate::handlers::__test_nice_reset();
    crate::handlers::__test_umask_reset();
    crate::handlers::__test_prctl_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_init_per_task_state_is_idempotent
);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_memfd_seal_write_rejects_write() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::linux_compat::{F_SEAL_WRITE, MFD_ALLOW_SEALING};
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    crate::fd::__test_reset();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let name = "sealable";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: name.as_ptr() as u64,
            // Linux memfd_create(2) ABI: (name_ptr, flags) — flags in arg1.
            // The kernel ignores the name; only the flags word matters.
            arg1: MFD_ALLOW_SEALING as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::MemfdCreate.raw(), &mut ctx);
    let fd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as u32,
        _ => return TestResult::Fail("memfd_create failed"),
    };

    // Write before sealing — must succeed.
    let payload = b"hello";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx);
    let w1 = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 5);
    if !w1 {
        crate::fd::__test_reset();
        __test_clear_global();
        return TestResult::Fail("pre-seal write rejected");
    }

    // F_GET_SEALS before sealing — should be 0.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 1034, // F_GET_SEALS
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut ctx);
    let pre_seals = match ctx.ret {
        Some(r) => r.value as u32,
        None => return TestResult::Fail("fcntl F_GET_SEALS no return"),
    };

    // F_ADD_SEALS F_SEAL_WRITE.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 1033, // F_ADD_SEALS
            arg2: F_SEAL_WRITE as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut ctx);
    let add_ok = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0);

    // F_GET_SEALS post-add — F_SEAL_WRITE set.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 1034,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut ctx);
    let post_seals = match ctx.ret {
        Some(r) => r.value as u32,
        None => return TestResult::Fail("fcntl F_GET_SEALS no return (post)"),
    };

    // Write after sealing — Linux returns EPERM (not EROFS and not the
    // transport-level InvalidOp sentinel).
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: payload.as_ptr() as u64,
            arg2: payload.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut ctx);
    let w2_eperm = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64
    );

    crate::fd::__test_reset();
    __test_clear_global();

    if pre_seals != 0 {
        return TestResult::Fail("pre-seal F_GET_SEALS != 0");
    }
    if !add_ok {
        return TestResult::Fail("F_ADD_SEALS rejected");
    }
    if post_seals & F_SEAL_WRITE == 0 {
        return TestResult::Fail("F_SEAL_WRITE not visible after add");
    }
    if !w2_eperm {
        return TestResult::Fail("post-seal write did not return EPERM");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_memfd_seal_write_rejects_write);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_memfd_seal_seal_blocks_further_seals() -> TestResult {
    use crate::linux_compat::{F_SEAL_SEAL, F_SEAL_WRITE, MFD_ALLOW_SEALING};
    use crate::{
        install_core_syscalls, install_global, kernel_syscall_entry, syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    crate::fd::__test_reset();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let name = "lockdown";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: name.as_ptr() as u64,
            // Linux memfd_create(2) ABI: (name_ptr, flags) — flags in arg1.
            // The kernel ignores the name; only the flags word matters.
            arg1: MFD_ALLOW_SEALING as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::MemfdCreate.raw(), &mut ctx);
    let fd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as u32,
        _ => return TestResult::Fail("memfd_create failed"),
    };

    // Seal with F_SEAL_SEAL.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 1033,
            arg2: F_SEAL_SEAL as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut ctx);
    let seal_seal = matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0);

    // Now try to add F_SEAL_WRITE — must fail.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 1033,
            arg2: F_SEAL_WRITE as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Fcntl.raw(), &mut ctx);
    let further_rejected = matches!(ctx.ret, Some(r) if r.value == (-1i64) as u64);

    crate::fd::__test_reset();
    __test_clear_global();

    if !seal_seal {
        return TestResult::Fail("F_SEAL_SEAL add failed");
    }
    if !further_rejected {
        return TestResult::Fail("post F_SEAL_SEAL further add was accepted");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_memfd_seal_seal_blocks_further_seals
);

// ── Wave-69: statx smokes ──────────────────────────────────────────────
//
// The kernel implementation lives in handlers::sys_statx, gated by
// linux-compat. These four smokes confirm the wire shape, mask=0
// semantics, AT_EMPTY_PATH, and the linux_compat::Stat field offsets.

#[cfg(feature = "linux-compat")]
fn smoke_userspace_statx_known_file_reports_mode_size() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        fd,
        handlers::linux_compat::{Statx, AT_FDCWD},
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };

    struct StatxKnownFile;
    impl FileOps for StatxKnownFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 42,
                blocks: 1,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }
    struct StatxKnownDir;
    impl DirOps for StatxKnownDir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "probe" {
                Some(Arc::new(StatxKnownFile))
            } else {
                None
            }
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    struct StatxKnownFs;
    impl FsInstance for StatxKnownFs {
        fn root(&self) -> Arc<dyn DirOps> {
            Arc::new(StatxKnownDir)
        }
        fn name(&self) -> &str {
            "statx-known"
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/statx-known", StatxKnownFs);

    fd::__test_reset();

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xE001);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    let path = b"/statx-known/probe\0";
    let mut out = Statx::default();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: AT_FDCWD as u64,
            arg1: path.as_ptr() as u64,
            arg2: 0,     // flags
            arg3: 0xFFF, // mask = STATX_BASIC_STATS
            arg4: &mut out as *mut Statx as u64,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Statx.raw(), &mut ctx);

    fd::__test_reset();
    __test_clear_global();

    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("statx did not return Ok(0)");
    }
    if out.stx_size == 0 {
        return TestResult::Fail("stx_size is 0");
    }
    if out.stx_mode & 0o170000 != 0o100000 {
        return TestResult::Fail("stx_mode not regular-file");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_statx_known_file_reports_mode_size
);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_statx_mask_zero_still_fills_basic_fields() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // mask=0 — kernel fills what it can and sets stx_mask accordingly.
    use crate::{
        fd,
        handlers::linux_compat::{Statx, AT_FDCWD},
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };

    struct StatxM0File;
    impl FileOps for StatxM0File {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 7,
                blocks: 1,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }
    struct StatxM0Dir;
    impl DirOps for StatxM0Dir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "m0" {
                Some(Arc::new(StatxM0File))
            } else {
                None
            }
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    struct StatxM0Fs;
    impl FsInstance for StatxM0Fs {
        fn root(&self) -> Arc<dyn DirOps> {
            Arc::new(StatxM0Dir)
        }
        fn name(&self) -> &str {
            "statx-m0"
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/statx-m0", StatxM0Fs);

    fd::__test_reset();
    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xE002);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    let path = b"/statx-m0/m0\0";
    let mut out = Statx::default();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: AT_FDCWD as u64,
            arg1: path.as_ptr() as u64,
            arg2: 0, // flags
            arg3: 0, // mask = 0
            arg4: &mut out as *mut Statx as u64,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Statx.raw(), &mut ctx);

    fd::__test_reset();
    __test_clear_global();

    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("statx(mask=0) did not return Ok(0)");
    }
    if out.stx_mode == 0 {
        return TestResult::Fail("stx_mode not filled with mask=0");
    }
    if out.stx_size == 0 {
        return TestResult::Fail("stx_size not filled with mask=0");
    }
    if out.stx_ino == 0 {
        return TestResult::Fail("stx_ino not filled with mask=0");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_statx_mask_zero_still_fills_basic_fields
);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_statx_at_empty_path_uses_dirfd() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // Open a file fd, then statx(fd, "", AT_EMPTY_PATH, ...) — must
    // return the fd's own metadata.
    use crate::{
        fd,
        handlers::linux_compat::{Statx, AT_EMPTY_PATH},
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FsFuture, FsInstance,
        MountPoint, Stat,
    };

    struct StatxEpFile;
    impl FileOps for StatxEpFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 99,
                blocks: 1,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0,
            }
        }
    }
    struct StatxEpDir;
    impl DirOps for StatxEpDir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "ep" {
                Some(Arc::new(StatxEpFile))
            } else {
                None
            }
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    struct StatxEpFs;
    impl FsInstance for StatxEpFs {
        fn root(&self) -> Arc<dyn DirOps> {
            Arc::new(StatxEpDir)
        }
        fn name(&self) -> &str {
            "statx-ep"
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/statx-ep", StatxEpFs);

    fd::__test_reset();
    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xE003);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    // Open /statx-ep/ep to get a real fd.
    // Linux open(2) ABI: arg0 = NUL-terminated path, arg1 = flags.
    let path = b"/statx-ep/ep\0";
    let mut open_ctx = FakeCtx {
        #[cfg(target_arch = "x86_64")]
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: 0, // flags
            ..SyscallArgs::default()
        },
        #[cfg(target_arch = "aarch64")]
        args: SyscallArgs {
            arg0: 0xffffffffffffff9c, // AT_FDCWD
            arg1: path.as_ptr() as u64,
            arg2: 0, // flags
            ..SyscallArgs::default()
        },
        ret: None,
    };
    #[cfg(target_arch = "x86_64")]
    kernel_syscall_entry(Syscall::OpenFile.raw(), &mut open_ctx);
    #[cfg(target_arch = "aarch64")]
    kernel_syscall_entry(Syscall::Openat.raw(), &mut open_ctx);
    let opened_fd = match open_ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as i32,
        _ => {
            fd::__test_reset();
            __test_clear_global();
            return TestResult::Fail("open failed before AT_EMPTY_PATH statx");
        }
    };

    let empty: &[u8] = b"\0";
    let mut out = Statx::default();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: opened_fd as u64,
            arg1: empty.as_ptr() as u64,
            arg2: AT_EMPTY_PATH as u64, // flags
            arg3: 0xFFF,                // mask
            arg4: &mut out as *mut Statx as u64,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Statx.raw(), &mut ctx);

    fd::__test_reset();
    __test_clear_global();

    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("statx(AT_EMPTY_PATH) did not return Ok(0)");
    }
    if out.stx_size != 99 {
        return TestResult::Fail("stx_size via AT_EMPTY_PATH mismatch");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_statx_at_empty_path_uses_dirfd);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_statx_device_node_reports_rdev() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // Regression: a device node's FileOps::rdev() must surface in
    // statx's stx_rdev_major/minor. seatd / libudev validate a device's
    // type from its MAJOR:MINOR; a 0 rdev reads as "not a device" and
    // they refuse to open it (the weston-input EINVAL). Open a synthetic
    // char device (major 13, minor 64) and statx(fd, AT_EMPTY_PATH).
    use crate::{
        fd,
        handlers::linux_compat::{Statx, AT_EMPTY_PATH},
        install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global,
        Syscall, SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_capabilities::{Cap, Grant};
    use narf_filesystem::{
        bootstrap_mount_authority, registry, DirEntry, DirOps, FileOps, FileType, FsFuture,
        FsInstance, Mode, MountPoint, Stat,
    };

    // (major << 8) | minor for the small-number range; 13 = Linux evdev.
    const DEV_RDEV: u64 = (13 << 8) | 64;
    struct RdevFile;
    impl FileOps for RdevFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: 0,
                blocks: 0,
                mode: Mode {
                    file_type: FileType::Special,
                    perms: 0o660,
                },
                mtime_cycles: 0,
            }
        }
        fn rdev(&self) -> u64 {
            DEV_RDEV
        }
    }
    struct RdevDir;
    impl DirOps for RdevDir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "evdev" {
                Some(Arc::new(RdevFile))
            } else {
                None
            }
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
    }
    struct RdevFs;
    impl FsInstance for RdevFs {
        fn root(&self) -> Arc<dyn DirOps> {
            Arc::new(RdevDir)
        }
        fn name(&self) -> &str {
            "statx-rdev"
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    let _ = registry().mount(&auth, "/statx-rdev", RdevFs);

    fd::__test_reset();
    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xE004);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }
    install_task_id_lookup(task_lookup);
    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    struct FakeCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for FakeCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    let path = b"/statx-rdev/evdev\0";
    let mut open_ctx = FakeCtx {
        #[cfg(target_arch = "x86_64")]
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: 0,
            ..SyscallArgs::default()
        },
        #[cfg(target_arch = "aarch64")]
        args: SyscallArgs {
            arg0: 0xffffffffffffff9c, // AT_FDCWD
            arg1: path.as_ptr() as u64,
            arg2: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    #[cfg(target_arch = "x86_64")]
    kernel_syscall_entry(Syscall::OpenFile.raw(), &mut open_ctx);
    #[cfg(target_arch = "aarch64")]
    kernel_syscall_entry(Syscall::Openat.raw(), &mut open_ctx);
    let opened_fd = match open_ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value as i32,
        _ => {
            fd::__test_reset();
            __test_clear_global();
            return TestResult::Fail("open of synthetic device node failed");
        }
    };

    let empty: &[u8] = b"\0";
    let mut out = Statx::default();
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: opened_fd as u64,
            arg1: empty.as_ptr() as u64,
            arg2: AT_EMPTY_PATH as u64,
            arg3: 0xFFF,
            arg4: &mut out as *mut Statx as u64,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Statx.raw(), &mut ctx);

    fd::__test_reset();
    __test_clear_global();

    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("statx of device node did not return Ok(0)");
    }
    if out.stx_rdev_major != 13 {
        return TestResult::Fail("stx_rdev_major != 13 (rdev not plumbed through statx)");
    }
    if out.stx_rdev_minor != 64 {
        return TestResult::Fail("stx_rdev_minor != 64");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_statx_device_node_reports_rdev);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_linux_stat_layout_offsets() -> TestResult {
    // Compile-time check that linux_compat::Stat field offsets match
    // the Linux x86_64 ABI (man 2 stat).
    use crate::handlers::linux_compat::Stat;
    use core::mem::offset_of;

    if offset_of!(Stat, st_dev) != 0 {
        return TestResult::Fail("st_dev offset != 0");
    }
    if offset_of!(Stat, st_ino) != 8 {
        return TestResult::Fail("st_ino offset != 8");
    }
    if offset_of!(Stat, st_nlink) != 16 {
        return TestResult::Fail("st_nlink offset != 16");
    }
    if offset_of!(Stat, st_mode) != 24 {
        return TestResult::Fail("st_mode offset != 24");
    }
    if offset_of!(Stat, st_uid) != 28 {
        return TestResult::Fail("st_uid offset != 28");
    }
    if offset_of!(Stat, st_gid) != 32 {
        return TestResult::Fail("st_gid offset != 32");
    }
    if offset_of!(Stat, st_rdev) != 40 {
        return TestResult::Fail("st_rdev offset != 40");
    }
    if offset_of!(Stat, st_size) != 48 {
        return TestResult::Fail("st_size offset != 48");
    }
    if offset_of!(Stat, st_blksize) != 56 {
        return TestResult::Fail("st_blksize offset != 56");
    }
    if offset_of!(Stat, st_blocks) != 64 {
        return TestResult::Fail("st_blocks offset != 64");
    }
    if offset_of!(Stat, st_atim) != 72 {
        return TestResult::Fail("st_atim offset != 72");
    }
    if offset_of!(Stat, st_mtim) != 88 {
        return TestResult::Fail("st_mtim offset != 88");
    }
    if offset_of!(Stat, st_ctim) != 104 {
        return TestResult::Fail("st_ctim offset != 104");
    }
    TestResult::Pass
}
#[cfg(feature = "linux-compat")]
kernel_test_in!("userspace", smoke_userspace_linux_stat_layout_offsets);

/// A process whose stdout IS the PTY slave must have its writes readable on
/// the master — the exact chain a terminal emulator depends on.
///
/// This is the integration gap under the 31 unit tests in
/// `filesystem/src/devfs_pty_tests.rs`: every one of those drives the `Pty`
/// object directly (`read`, `write`, the ioctls). None routes
/// through the fd table and `sys_write`/`sys_read`, which is where a
/// terminal's shell actually lives. `foot` renders its grid and cursor but
/// shows no prompt (task #11) — "the shell produced nothing" is precisely a
/// break somewhere on this path, and nothing above the `Pty` object guarded
/// it.
///
/// Deliberately driven through `kernel_syscall_entry`, not the helpers: a
/// test that calls `PtySlave::write` proves the ring works and says nothing
/// about fd routing, the line discipline hookup, or `sys_read` on the
/// master. Both directions are asserted — slave→master is the shell's
/// output, master→slave its input — because a terminal needs both and only
/// one of them is the reported symptom.
#[cfg(feature = "linux-compat")]
fn smoke_userspace_pty_slave_as_stdout_reaches_master() -> TestResult {
    // Kernel-test fixture: stack buffers stand in for user pointers, so the
    // production `validate_user_range` predicate needs the scoped opt-in.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        fd, install_core_syscalls, install_global, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;

    struct StubIoCtx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for StubIoCtx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let task = crate::handlers::current_task_id();
    let (idx, pty) = narf_filesystem::devfs_pty::ptmx_open();
    let master_obj = narf_filesystem::devfs_pty::PtyMaster::new(pty);
    // Linux: ptmx_open() hands back a LOCKED slave; `unlockpt(3)` issues
    // TIOCSPTLCK(0) before anything may open /dev/pts/<n>. A terminal does
    // this between openpt and fork, so a test that skips it is testing a
    // state no terminal is ever in.
    let mut unlock: i32 = 0;
    if narf_filesystem::FileOps::ioctl(
        &master_obj,
        narf_filesystem::devfs_pty::TIOCSPTLCK,
        &mut unlock as *mut i32 as usize,
    ) != Ok(0)
    {
        narf_filesystem::devfs_pty::ptmx_close(idx);
        __test_clear_global();
        return TestResult::Fail("TIOCSPTLCK(0) (unlockpt) failed on a fresh master");
    }
    let master: Arc<dyn narf_filesystem::FileOps> = Arc::new(master_obj);
    let slave = match narf_filesystem::devfs_pty::pts_open_peer(idx) {
        Some(Ok(s)) => s,
        _ => {
            narf_filesystem::devfs_pty::ptmx_close(idx);
            __test_clear_global();
            return TestResult::Fail("pts_open_peer refused the freshly opened master");
        }
    };

    let install = |ops: Arc<dyn narf_filesystem::FileOps>, status_flags| {
        fd::with_table(task, |tab| {
            tab.open(FdEntry {
                ops,
                offset: 0,
                flags: 0,
                status_flags,
            })
        })
    };
    let slave: Arc<dyn narf_filesystem::FileOps> = slave;
    // posix_openpt/open(/dev/pts/N) are O_RDWR in the terminal-emulator path;
    // the integration smoke exercises both directions and must not construct
    // read-only descriptions then expect slave writes to succeed.
    let (mfd, sfd) = match (
        install(master.clone(), crate::fd::O_RDWR),
        install(slave.clone(), crate::fd::O_RDWR),
    ) {
        (Some(m), Some(s)) => (m, s),
        _ => {
            narf_filesystem::devfs_pty::ptmx_close(idx);
            __test_clear_global();
            return TestResult::Fail("could not install the pty ends in the fd table");
        }
    };

    let mut fail: Option<&'static str> = None;
    // Shell output: write on the SLAVE fd, read it on the MASTER fd.
    let out = b"narf$ ";
    let mut wctx = StubIoCtx {
        args: SyscallArgs {
            arg0: sfd as u64,
            arg1: out.as_ptr() as u64,
            arg2: out.len() as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Write.raw(), &mut wctx);
    if wctx.ret != Some(SyscallReturn::ok(out.len() as u64)) {
        fail = Some("write to the pty slave fd did not accept the prompt");
    }
    if fail.is_none() {
        let mut buf = [0u8; 32];
        let mut rctx = StubIoCtx {
            args: SyscallArgs {
                arg0: mfd as u64,
                arg1: buf.as_mut_ptr() as u64,
                arg2: buf.len() as u64,
                ..Default::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
        match rctx.ret {
            Some(r) if r.status == SyscallReturn::OK && r.value == out.len() as u64 => {
                if &buf[..out.len()] != out {
                    fail = Some("master read returned the wrong bytes");
                }
            }
            // The reported symptom: a terminal that reads 0 concludes its
            // shell exited and stops reading forever.
            Some(r) if r.status == SyscallReturn::OK && r.value == 0 => {
                fail = Some("master read returned 0 — phantom EOF with data queued")
            }
            _ => fail = Some("master read did not return the slave's output"),
        }
    }

    narf_filesystem::devfs_pty::ptmx_close(idx);
    __test_clear_global();
    match fail {
        Some(m) => TestResult::Fail(m),
        None => TestResult::Pass,
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_pty_slave_as_stdout_reaches_master
);

/// `TIOCSCTTY` on a PTY slave must install the tty's foreground process
/// group, not merely record the controlling tty.
///
/// Linux `__proc_set_tty` (drivers/tty/tty_jobctrl.c) does both at once:
///
/// ```c
/// tty->ctrl.pgrp    = get_pid(task_pgrp(current));
/// tty->ctrl.session = get_pid(task_session(current));
/// ```
///
/// NARF recorded only the ctty index, leaving `fg_pgrp` at 0. That is not a
/// cosmetic gap. bash's `initialize_job_control` runs
///
/// ```c
/// while ((terminal_pgrp = tcgetpgrp (shell_tty)) != -1) {
///     if (shell_pgrp != terminal_pgrp) { /* SIG_DFL */ kill (0, SIGTTIN); continue; }
///     break;
/// }
/// ```
///
/// so a `tcgetpgrp()` of 0 never equals the shell's own pgrp, and the shell
/// signals ITSELF with SIGTTIN — default action: stop. The measured symptom
/// was an interactive bash on a PTY that stayed alive forever having written
/// zero bytes: the empty `foot` window (task #11).
///
/// The assertion is deliberately the shell's own convergence condition
/// (`tcgetpgrp(slave) == getpgrp()`), not "fg_pgrp is nonzero" — a nonzero
/// but wrong pgrp hangs bash exactly as hard as a zero one.
#[cfg(feature = "linux-compat")]
fn smoke_userspace_pty_tiocsctty_installs_foreground_pgrp() -> TestResult {
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use alloc::sync::Arc;
    use narf_filesystem::devfs_pty::{TIOCGPGRP, TIOCGSID, TIOCSCTTY, TIOCSPTLCK};
    use narf_filesystem::FileOps;

    fn ctty_task() -> u64 {
        0x7c77
    }
    fn cleanup_ctty_fixture() {
        crate::handlers::__test_reset_task_id_lookup();
        crate::handlers::__test_ctty_reset();
        crate::handlers::__test_pgid_reset();
        crate::handlers::__test_sid_reset();
    }

    // Production boot installs both callbacks and process state. This direct
    // FileOps smoke must model a detached session leader explicitly.
    crate::install_task_id_lookup(ctty_task);
    crate::handlers::__test_ctty_reset();
    crate::handlers::__test_pgid_reset();
    crate::handlers::__test_sid_reset();
    crate::handlers::detach_controlling_tty(ctty_task());
    narf_filesystem::devfs_pty::set_controlling_tty_hook(crate::handlers::set_controlling_tty);

    let (idx, pty) = narf_filesystem::devfs_pty::ptmx_open();
    let master = narf_filesystem::devfs_pty::PtyMaster::new(pty);
    let mut unlock: i32 = 0;
    if FileOps::ioctl(&master, TIOCSPTLCK, &mut unlock as *mut i32 as usize) != Ok(0) {
        narf_filesystem::devfs_pty::ptmx_close(idx);
        cleanup_ctty_fixture();
        return TestResult::Fail("TIOCSPTLCK(0) (unlockpt) failed on a fresh master");
    }
    let slave = match narf_filesystem::devfs_pty::pts_open_peer(idx) {
        Some(Ok(s)) => s,
        _ => {
            narf_filesystem::devfs_pty::ptmx_close(idx);
            cleanup_ctty_fixture();
            return TestResult::Fail("pts_open_peer refused the freshly opened master");
        }
    };

    let mut fail: Option<&'static str> = None;

    // NEGATIVE: before anyone acquires the tty it has no session, so
    // TIOCGSID reports ENOTTY — Linux `tiocgsid`'s
    // `if (!real_tty->ctrl.session) return -ENOTTY;`.
    let mut sid_out: i32 = -1;
    if FileOps::ioctl(&*slave, TIOCGSID, &mut sid_out as *mut i32 as usize).is_ok() {
        fail = Some("TIOCGSID answered on a PTY that no session has acquired");
    }

    // POSITIVE: acquire the tty, then assert the shell's convergence
    // condition holds.
    if fail.is_none() && FileOps::ioctl(&*slave, TIOCSCTTY, 0).is_err() {
        fail = Some("TIOCSCTTY on an unlocked PTY slave failed");
    }
    if fail.is_none() {
        // Visible-pid space: this is what the shell's own getpgrp() returns.
        let want = crate::handlers::current_task_pgid_user();
        let mut got: i32 = -1;
        if want == 0 {
            // No scheduled task ⇒ the fixture cannot express the property.
            // Say so rather than passing vacuously.
            fail = Some("fixture has no current task: pgid 0, assertion would be vacuous");
        } else if FileOps::ioctl(&*slave, TIOCGPGRP, &mut got as *mut i32 as usize).is_err() {
            fail = Some("TIOCGPGRP failed after TIOCSCTTY");
        } else if got == 0 {
            // The exact pre-fix state.
            fail = Some("tcgetpgrp() == 0 after TIOCSCTTY — bash would SIGTTIN-stop itself");
        } else if got as u64 != want {
            fail = Some("tcgetpgrp() != getpgrp() after TIOCSCTTY — job control cannot converge");
        }
    }
    // The session half of the same `__proc_set_tty` store.
    if fail.is_none() {
        let want = crate::handlers::current_task_sid_user();
        let mut got: i32 = -1;
        match FileOps::ioctl(&*slave, TIOCGSID, &mut got as *mut i32 as usize) {
            Ok(_) if got as u64 == want => {}
            Ok(_) => fail = Some("TIOCGSID returned a session that is not the acquirer's"),
            Err(_) => fail = Some("TIOCGSID still reports ENOTTY after TIOCSCTTY"),
        }
    }

    drop(slave);
    narf_filesystem::devfs_pty::ptmx_close(idx);
    cleanup_ctty_fixture();
    match fail {
        Some(m) => TestResult::Fail(m),
        None => TestResult::Pass,
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_pty_tiocsctty_installs_foreground_pgrp
);

/// PTY job-control ioctls are syscall policy, not merely FileOps plumbing.
/// Pin Linux's ownership, fd-mode, endpoint and errno ordering through the
/// real ioctl dispatch path.
#[cfg(feature = "linux-compat")]
fn smoke_userspace_pty_job_control_ioctl_errno_matrix() -> TestResult {
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{fd, syscall::__test_clear_global, FdEntry};
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_filesystem::devfs_pty::{TIOCGPGRP, TIOCGSID, TIOCSCTTY, TIOCSPGRP, TIOCSPTLCK};
    use narf_filesystem::FileOps;

    const OWNER: u64 = 0x7d01;
    const OTHER: u64 = 0x7d02;
    const ENOTTY_ERR: i64 = 25;
    const EINVAL_ERR: i64 = 22;
    static ACTIVE: AtomicU64 = AtomicU64::new(OWNER);
    fn current() -> u64 {
        ACTIVE.load(Ordering::Acquire)
    }

    struct Ctx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for Ctx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, value: SyscallReturn) {
            self.ret = Some(value);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
            false
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    let call = |fd: u32, cmd: u32, arg: u64| {
        let mut ctx = Ctx {
            args: SyscallArgs {
                arg0: fd as u64,
                arg1: cmd as u64,
                arg2: arg,
                ..Default::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Ioctl.raw(), &mut ctx);
        ctx.ret.map(|ret| ret.value).unwrap_or(u64::MAX)
    };

    fd::__test_reset();
    crate::handlers::__test_ctty_reset();
    crate::handlers::__test_pgid_reset();
    crate::handlers::__test_sid_reset();
    crate::install_task_id_lookup(current);
    narf_filesystem::devfs_pty::set_controlling_tty_hook(crate::handlers::set_controlling_tty);
    __test_clear_global();
    let mut table = SyscallTable::new();
    install_core_syscalls(&mut table);
    install_global(table);

    let (idx, pty) = narf_filesystem::devfs_pty::ptmx_open();
    let master_obj = narf_filesystem::devfs_pty::PtyMaster::new(pty);
    let mut unlock = 0i32;
    if FileOps::ioctl(&master_obj, TIOCSPTLCK, &mut unlock as *mut i32 as usize) != Ok(0) {
        narf_filesystem::devfs_pty::ptmx_close(idx);
        return TestResult::Fail("could not unlock PTY fixture");
    }
    let Some(Ok(slave_obj)) = narf_filesystem::devfs_pty::pts_open_peer(idx) else {
        narf_filesystem::devfs_pty::ptmx_close(idx);
        return TestResult::Fail("could not open PTY slave fixture");
    };
    let master: Arc<dyn FileOps> = Arc::new(master_obj);
    let slave: Arc<dyn FileOps> = slave_obj;

    let install = |task, ops: Arc<dyn FileOps>, status_flags| {
        fd::with_table(task, |table| {
            table.open(FdEntry {
                ops,
                offset: 0,
                flags: 0,
                status_flags,
            })
        })
    };
    let Some(owner_ro) = install(OWNER, slave.clone(), crate::fd::O_RDWR) else {
        return TestResult::Fail("could not install owner PTY fd");
    };
    let Some(owner_wo) = install(OWNER, slave.clone(), crate::fd::O_WRONLY) else {
        return TestResult::Fail("could not install write-only PTY fd");
    };
    let Some(owner_master) = install(OWNER, master.clone(), crate::fd::O_RDWR) else {
        return TestResult::Fail("could not install owner PTY master");
    };
    let Some(other_slave) = install(OTHER, slave.clone(), crate::fd::O_RDWR) else {
        return TestResult::Fail("could not install foreign PTY slave");
    };
    let Some(other_master) = install(OTHER, master, crate::fd::O_RDWR) else {
        return TestResult::Fail("could not install foreign PTY master");
    };

    crate::handlers::detach_controlling_tty(OWNER);
    let mut fail = None;
    if call(owner_wo, TIOCSCTTY, 0) != (-1i64) as u64 {
        fail = Some("write-only TIOCSCTTY did not return EPERM");
    } else if call(owner_ro, TIOCSCTTY, 0) != 0 {
        fail = Some("detached session leader could not acquire PTY");
    } else if call(owner_wo, TIOCSCTTY, 0) != 0 {
        fail = Some("idempotent TIOCSCTTY checked fd mode before same-session success");
    }

    let mut pgrp = -1i32;
    if fail.is_none()
        && (call(owner_ro, TIOCGPGRP, &mut pgrp as *mut i32 as u64) != 0 || pgrp as u64 != OWNER)
    {
        fail = Some("TIOCGPGRP did not return the owner's visible process group");
    }
    let mut sid = -1i32;
    if fail.is_none()
        && (call(owner_ro, TIOCGSID, &mut sid as *mut i32 as u64) != 0 || sid as u64 != OWNER)
    {
        fail = Some("TIOCGSID did not return the owner's visible session");
    }

    ACTIVE.store(OTHER, Ordering::Release);
    if fail.is_none() && call(other_slave, TIOCGPGRP, 0) != (-ENOTTY_ERR) as u64 {
        fail = Some("foreign slave TIOCGPGRP did not return ENOTTY before pointer access");
    }
    let mut master_pgrp = -1i32;
    if fail.is_none()
        && (call(other_master, TIOCGPGRP, &mut master_pgrp as *mut i32 as u64) != 0
            || master_pgrp as u64 != OWNER)
    {
        fail = Some("PTY master did not bypass GET ownership or translate pgrp");
    }
    crate::handlers::detach_controlling_tty(OTHER);
    if fail.is_none() && call(other_slave, TIOCSCTTY, 1) != (-1i64) as u64 {
        fail = Some("unprivileged TIOCSCTTY steal did not return EPERM");
    }
    let mut other_group = OTHER as i32;
    if fail.is_none()
        && call(other_master, TIOCSPGRP, &mut other_group as *mut i32 as u64)
            != (-ENOTTY_ERR) as u64
    {
        fail = Some("foreign master TIOCSPGRP did not return ENOTTY");
    }

    ACTIVE.store(OWNER, Ordering::Release);
    let mut negative = -1i32;
    if fail.is_none()
        && call(owner_master, TIOCSPGRP, &mut negative as *mut i32 as u64) != (-EINVAL_ERR) as u64
    {
        fail = Some("negative TIOCSPGRP id did not return EINVAL");
    }
    let mut missing = 0x6fff_i32;
    if fail.is_none()
        && call(owner_master, TIOCSPGRP, &mut missing as *mut i32 as u64) != (-3i64) as u64
    {
        fail = Some("unknown TIOCSPGRP id did not return ESRCH");
    }
    let mut owner_group = OWNER as i32;
    if fail.is_none() && call(owner_master, TIOCSPGRP, &mut owner_group as *mut i32 as u64) != 0 {
        fail = Some("owner could not set its PTY foreground group");
    }

    narf_filesystem::devfs_pty::ptmx_close(idx);
    fd::__test_reset();
    crate::handlers::__test_reset_task_id_lookup();
    crate::handlers::__test_ctty_reset();
    crate::handlers::__test_pgid_reset();
    crate::handlers::__test_sid_reset();
    __test_clear_global();
    match fail {
        Some(message) => TestResult::Fail(message),
        None => TestResult::Pass,
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_pty_job_control_ioctl_errno_matrix
);

/// An O_NONBLOCK `read(2)` on an eventfd whose counter is 0 must return
/// **-EAGAIN**, never a bare 0.
///
/// Task #13 filed this as "EventFd::read returns Ok(0) — phantom EOF". The
/// `Ok(0)` at the FileOps layer is CORRECT and deliberate: NARF has no
/// `FsError::WouldBlock`; "empty but open" is explicit and `sys_read` turns
/// it into EAGAIN or a park (sys_read.rs).
///
/// What DID exist is a coverage hole. `smoke_io_mux_empty_reads_are_not_eof`
/// asserted only FileOps internals and deliberately did not exercise the
/// syscall. The regression now pins the explicit file-op error and the
/// syscall result, so neither layer can reintroduce a phantom EOF alone.
///
/// That EOF is not cosmetic: a 0 from an eventfd tells an event loop its
/// wakeup channel closed. The same shape (a spurious 0 on an O_NONBLOCK fd)
/// previously killed the KDE session bus via GLib's line-reader — see the
/// comment above the EAGAIN branch in sys_read.
fn smoke_userspace_eventfd_nonblock_read_is_eagain_not_eof() -> TestResult {
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        fd, install_core_syscalls, install_global, kernel_syscall_entry,
        syscall::__test_clear_global, FdEntry, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use alloc::sync::Arc;

    struct Ctx {
        args: SyscallArgs,
        ret: Option<SyscallReturn>,
    }
    impl TrapContext for Ctx {
        fn args(&self) -> &SyscallArgs {
            &self.args
        }
        fn set_return(&mut self, r: SyscallReturn) {
            self.ret = Some(r);
        }
        fn user_rsp(&self) -> u64 {
            0
        }
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    __test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let task = crate::handlers::current_task_id();
    let efd = crate::io_mux::EventFd::new(0, 0);
    let ops: Arc<dyn narf_filesystem::FileOps> = efd.clone();
    let Some(fd_n) = fd::with_table(task, |tab| {
        tab.open(FdEntry {
            ops,
            offset: 0,
            flags: 0,
            // Linux eventfd_file_create installs O_RDWR | user flags.
            status_flags: crate::fd::O_RDWR | crate::fd::O_NONBLOCK,
        })
    }) else {
        __test_clear_global();
        return TestResult::Fail("could not install the eventfd in the fd table");
    };

    let mut fail: Option<&'static str> = None;
    let mut buf = [0u8; 8];
    let mut rctx = Ctx {
        args: SyscallArgs {
            arg0: fd_n as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: 8,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut rctx);
    // -EAGAIN (11) as the negated value, matching how sys_read reports it.
    let want_eagain = SyscallReturn::ok((-11i64) as u64);
    match rctx.ret {
        Some(r) if r == want_eagain => {}
        // The exact regression: a bare 0 read as EOF by the event loop.
        Some(r) if r == SyscallReturn::ok(0) => {
            fail = Some("nonblocking eventfd read returned 0 — an event loop reads that as its wakeup channel closing")
        }
        _ => fail = Some("nonblocking eventfd read on an empty counter did not return -EAGAIN"),
    }

    // POSITIVE half: once a value is posted the SAME fd must deliver 8 bytes,
    // so this cannot be satisfied by a version that always reports EAGAIN.
    if fail.is_none() {
        let one = 1u64.to_le_bytes();
        let mut wctx = Ctx {
            args: SyscallArgs {
                arg0: fd_n as u64,
                arg1: one.as_ptr() as u64,
                arg2: 8,
                ..Default::default()
            },
            ret: None,
        };
        kernel_syscall_entry(Syscall::Write.raw(), &mut wctx);
        if wctx.ret != Some(SyscallReturn::ok(8)) {
            fail = Some("eventfd write did not accept 8 bytes");
        } else {
            let mut rctx2 = Ctx {
                args: SyscallArgs {
                    arg0: fd_n as u64,
                    arg1: buf.as_mut_ptr() as u64,
                    arg2: 8,
                    ..Default::default()
                },
                ret: None,
            };
            kernel_syscall_entry(Syscall::Read.raw(), &mut rctx2);
            match rctx2.ret {
                Some(r) if r == SyscallReturn::ok(8) => {
                    if u64::from_le_bytes(buf) != 1 {
                        fail = Some("eventfd read returned the wrong counter value");
                    }
                }
                _ => fail = Some("eventfd read with a pending value did not return 8"),
            }
        }
    }

    let _ = fd::with_table(task, |tab| tab.close(fd_n));
    __test_clear_global();
    match fail {
        Some(m) => TestResult::Fail(m),
        None => TestResult::Pass,
    }
}
kernel_test_in!(
    "userspace",
    smoke_userspace_eventfd_nonblock_read_is_eagain_not_eof
);
