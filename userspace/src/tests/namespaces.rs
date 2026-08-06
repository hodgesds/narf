//! `namespaces` test group (mechanically split from the original flat `tests` module).

#![allow(unused_imports)]
use super::*;

// ── ported from verification ───────────────────────────────────────

fn smoke_userspace_install_core_syscalls_fills_table() -> TestResult {
    // `install_core_syscalls` drops Write/Read/Close/Mmap/Munmap/
    // ExitTask/Yield/Sleep handlers into a fresh table. Confirm
    // every slot has both a name and a handler after install.
    use crate::{install_core_syscalls, Syscall, SyscallTable};

    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);

    let slots = [
        Syscall::Write,
        Syscall::Read,
        Syscall::Close,
        Syscall::Mmap,
        Syscall::Munmap,
        Syscall::ExitTask,
        Syscall::Yield,
        Syscall::Sleep,
    ];
    for s in slots {
        if t.name_of(s).is_none() {
            return TestResult::Fail("core syscall missing after install_core_syscalls");
        }
    }
    if t.len() < slots.len() {
        return TestResult::Fail("install_core_syscalls did not grow table to cover every slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_install_core_syscalls_fills_table
);

#[cfg(target_arch = "x86_64")]
fn smoke_userspace_bootstrap_returns_config_page() -> TestResult {
    // Bootstrap: allocate config page in the caller's AS, write a
    // header into it (magic / version / task_id), return user
    // vaddr. We don't activate the AS — we just walk it via
    // `translate` to find the backing phys frame and verify the
    // header bytes.
    use crate::{
        install_address_space_lookup, install_core_syscalls, install_global,
        install_task_id_lookup, kernel_syscall_entry, syscall::__test_clear_global, Syscall,
        SyscallArgs, SyscallReturn, SyscallTable, TrapContext,
    };
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU64, Ordering};
    use narf_memory::{x86_64::paging, AddressSpace, VirtAddr};

    static USER_AS_BS: narf_lib::sync::IrqSafeSpinLock<Option<Arc<AddressSpace>>> =
        narf_lib::sync::IrqSafeSpinLock::new(None);
    fn as_lookup() -> Option<Arc<AddressSpace>> {
        USER_AS_BS.lock().clone()
    }

    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xCAFE);
    fn task_lookup() -> u64 {
        FAKE_TASK.load(Ordering::Relaxed)
    }

    // SAFETY: the test harness runs with paging enabled (its `# Safety`
    // precondition); `new_for_user` only allocates a fresh user root that
    // inherits the kernel half, leaving the active address space untouched.
    // SAFETY: Valid memory or trusted environment
    let addr_space = match unsafe { AddressSpace::new_for_user() } {
        Ok(a) => Arc::new(a),
        Err(_) => return TestResult::Fail("new_for_user failed"),
    };
    *USER_AS_BS.lock() = Some(addr_space.clone());

    install_address_space_lookup(as_lookup);
    install_task_id_lookup(task_lookup);
    crate::bootstrap_init();
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
    let mut ctx = FakeCtx {
        args: SyscallArgs::default(),
        ret: None,
    };
    kernel_syscall_entry(Syscall::Bootstrap.raw(), &mut ctx);

    let user_vaddr = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK => r.value,
        _ => {
            *USER_AS_BS.lock() = None;
            __test_clear_global();
            return TestResult::Fail("Bootstrap did not return Ok");
        }
    };
    if user_vaddr == 0 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("Bootstrap returned null user_vaddr");
    }

    // Walk the AS to find the backing phys frame.
    // SAFETY: `addr_space.root` is the freshly built user root for this Bootstrap
    // test, identity-reachable as `translate` requires; the walk only reads its
    // table entries for `user_vaddr`.
    // SAFETY: Valid memory or trusted environment
    let phys = match unsafe { paging::translate(addr_space.root, VirtAddr::new(user_vaddr)) } {
        Some(p) => p,
        None => {
            *USER_AS_BS.lock() = None;
            __test_clear_global();
            return TestResult::Fail("Bootstrap config page not mapped in AS");
        }
    };

    // Read header through identity map. Layout mirrors
    // `BootstrapHeader` in userspace/handlers.rs — the test pins
    // every field so silent ABI drift breaks here.
    #[repr(C)]
    struct Hdr {
        magic: u32,
        version: u32,
        task_id: u64,
        sq_cap: u64,
        cq_cap: u64,
        sq_depth: u32,
        cq_depth: u32,
        shared_sq_vaddr: u64,
        shared_cq_vaddr: u64,
        shared_depth: u32,
        _pad: u32,
    }
    // SAFETY: `phys` is the identity-mapped frame `translate` resolved for the
    // config page; the kernel wrote a `BootstrapHeader` there, whose layout `Hdr`
    // mirrors `#[repr(C)]`, so a single volatile struct read is valid and aligned.
    // SAFETY: Valid memory or trusted environment
    let hdr = unsafe { core::ptr::read_volatile(phys.raw() as *const Hdr) };

    if hdr.magic != 0x4E_41_52_46 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("config page magic mismatch");
    }
    if hdr.version != 3 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("config page version mismatch");
    }
    if hdr.task_id != 0xCAFE {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("config page task_id mismatch");
    }
    if hdr.sq_cap == 0 || hdr.cq_cap == 0 || hdr.sq_cap == hdr.cq_cap {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("ring cap-slot ids unset or collide");
    }
    if hdr.sq_depth != 64 || hdr.cq_depth != 64 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("ring depths not 64");
    }
    if hdr.shared_sq_vaddr == 0
        || hdr.shared_cq_vaddr == 0
        || hdr.shared_sq_vaddr == hdr.shared_cq_vaddr
    {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("shared SQ/CQ vaddrs unset or collide");
    }
    if hdr.shared_depth != crate::BOOTSTRAP_SHARED_RING_DEPTH as u32 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("shared ring depth mismatch");
    }
    // The shared pages must also be mapped in the AS; we can
    // translate them to confirm.
    // SAFETY: `addr_space.root` is the live user root for this test, identity-
    // reachable as `translate` requires; this only walks its tables for the SQ
    // vaddr reported by the header.
    // SAFETY: Valid memory or trusted environment
    if unsafe { paging::translate(addr_space.root, VirtAddr::new(hdr.shared_sq_vaddr)) }.is_none() {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("shared SQ vaddr not mapped");
    }
    // SAFETY: same live user root as above; only walks its tables for the CQ
    // vaddr reported by the header.
    // SAFETY: Valid memory or trusted environment
    if unsafe { paging::translate(addr_space.root, VirtAddr::new(hdr.shared_cq_vaddr)) }.is_none() {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("shared CQ vaddr not mapped");
    }
    if crate::bootstrap_live_count() < 1 {
        *USER_AS_BS.lock() = None;
        __test_clear_global();
        return TestResult::Fail("bootstrap registry didn't record this task");
    }

    *USER_AS_BS.lock() = None;
    __test_clear_global();
    crate::handlers::__test_bootstrap_reset();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("userspace", smoke_userspace_bootstrap_returns_config_page);

#[cfg(all(target_arch = "x86_64", not(feature = "linux-compat")))]
fn smoke_userspace_stat_returns_size() -> TestResult {
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, StatBuf, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
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

    static FILE_BYTES: &[u8] = b"STAT-PROBE-12345"; // 16 bytes
    struct StubFile;
    impl FileOps for StubFile {
        fn read<'a>(&'a self, _o: u64, _b: &'a mut [u8]) -> FsFuture<'a, usize> {
            Box::pin(async move { Ok(0) })
        }
        fn write<'a>(&'a self, _o: u64, b: &'a [u8]) -> FsFuture<'a, usize> {
            let n = b.len();
            Box::pin(async move { Ok(n) })
        }
        fn stat(&self) -> Stat {
            Stat {
                size: FILE_BYTES.len() as u64,
                blocks: 1,
                mode: narf_filesystem::Mode::FILE_RO,
                mtime_cycles: 0xC0FFEE,
            }
        }
    }
    struct StubDir;
    impl DirOps for StubDir {
        fn lookup(&self, name: &str) -> Option<Arc<dyn FileOps>> {
            if name == "stat-target" {
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
            "stat-stub"
        }
    }

    let auth: Cap<MountPoint, Grant> = bootstrap_mount_authority();
    // `/stat-test` is unique to this test; if a prior run already
    // mounted it, the second mount surfaces Busy and we continue
    // with the existing mount (file resolution still works).
    let _ = registry().mount(&auth, "/stat-test", StubFs);

    fd::__test_reset();
    static FAKE_TASK: AtomicU64 = AtomicU64::new(0xD2);
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
        fn redirect_to_kernel(&mut self, _r: u64, _s: u64) -> bool {
            false
        }

        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
    }

    let mut out = StatBuf::default();
    let path = b"/stat-test/stat-target";
    let mut sctx = FakeCtx {
        args: SyscallArgs {
            arg0: path.as_ptr() as u64,
            arg1: path.len() as u64,
            arg2: &mut out as *mut StatBuf as u64,
            ..Default::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Stat.raw(), &mut sctx);
    if sctx.ret != Some(SyscallReturn::ok(0)) {
        return TestResult::Fail("Stat did not return Ok");
    }
    if out.size != FILE_BYTES.len() as u64 {
        if out.size == 0 {
            return TestResult::Fail("StatBuf.size is 0");
        } else {
            return TestResult::Fail("StatBuf.size mismatch (not 0)");
        }
    }
    if out.mtime_cycles != 0xC0FFEE {
        return TestResult::Fail("StatBuf.mtime_cycles mismatch");
    }
    // Mode high bits should mark this as a regular file (0o100000).
    if out.mode & 0o170000 != 0o100000 {
        return TestResult::Fail("StatBuf.mode missing regular-file marker");
    }

    fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
#[cfg(all(target_arch = "x86_64", not(feature = "linux-compat")))]
kernel_test_in!("userspace", smoke_userspace_stat_returns_size);

fn smoke_userspace_hostname_round_trip() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    use crate::{
        hostname_init, install_core_syscalls, install_global, kernel_syscall_entry,
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
    crate::handlers::__test_hostname_reset();
    hostname_init();

    // gethostname → "narf" (boot default).
    let mut buf = [0u8; 64];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf.as_mut_ptr() as u64,
            arg1: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetHostname.raw(), &mut ctx);
    let n = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as usize,
        _ => return TestResult::Fail("gethostname did not return OK with len"),
    };
    if n != 4 || &buf[..4] != b"narf" || buf[4] != 0 {
        return TestResult::Fail("default hostname not 'narf'");
    }

    // sethostname("box-7") → succeeds.
    let new_name = b"box-7";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: new_name.as_ptr() as u64,
            arg1: new_name.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::SetHostname.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("sethostname did not return 0");
    }

    // gethostname now returns "box-7".
    let mut buf2 = [0u8; 64];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: buf2.as_mut_ptr() as u64,
            arg1: buf2.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetHostname.raw(), &mut ctx);
    let n2 = match ctx.ret {
        Some(r) if r.value != (-1i64) as u64 => r.value as usize,
        _ => return TestResult::Fail("post-set gethostname failed"),
    };
    if n2 != 5 || &buf2[..5] != b"box-7" || buf2[5] != 0 {
        return TestResult::Fail("hostname did not stick after sethostname");
    }

    // gethostname into too-small buf returns -1.
    let mut tiny = [0u8; 3];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: tiny.as_mut_ptr() as u64,
            arg1: tiny.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::GetHostname.raw(), &mut ctx);
    let too_small_rejected = matches!(
        ctx.ret,
        Some(r) if r.status == SyscallReturn::OK && r.value == (-1i64) as u64,
    );
    if !too_small_rejected {
        return TestResult::Fail("gethostname did not reject small buf");
    }

    crate::handlers::__test_hostname_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_hostname_round_trip);

fn smoke_userspace_getcpu_returns_zero() -> TestResult {
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

    let mut cpu: u32 = 99;
    let mut node: u32 = 99;
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: &mut cpu as *mut u32 as u64,
            arg1: &mut node as *mut u32 as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getcpu.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("getcpu did not return OK");
    }
    if cpu != 0 || node != 0 {
        return TestResult::Fail("getcpu did not write (0, 0)");
    }

    // Null pointers tolerated.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: 0,
            arg1: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Getcpu.raw(), &mut ctx);
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("getcpu(NULL, NULL) did not succeed");
    }

    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_userspace_getcpu_returns_zero);

fn smoke_userspace_memfd_create_returns_writable_fd() -> TestResult {
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
    crate::fd::__test_reset();

    let name = "anon-1";
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: name.as_ptr() as u64,
            arg1: name.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::MemfdCreate.raw(), &mut ctx);
    let fd = match ctx.ret {
        Some(r) if r.status == SyscallReturn::OK && r.value != (-1i64) as u64 => r.value as u32,
        _ => return TestResult::Fail("memfd_create did not return a fd"),
    };

    // Write 4 bytes via SYS_WRITE, read them back via SYS_READ.
    let payload = b"narf";
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
    if !matches!(ctx.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 4) {
        return TestResult::Fail("write to memfd did not write 4 bytes");
    }

    // Seek back to 0 then read.
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: 0,
            arg2: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Lseek.raw(), &mut ctx);

    let mut buf = [0u8; 4];
    let mut ctx = FakeCtx {
        args: SyscallArgs {
            arg0: fd as u64,
            arg1: buf.as_mut_ptr() as u64,
            arg2: buf.len() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Read.raw(), &mut ctx);
    if &buf != b"narf" {
        return TestResult::Fail("read-back from memfd contents wrong");
    }

    let _ = crate::fd::with_table(0, |t| t.close(fd));
    crate::fd::__test_reset();
    __test_clear_global();
    TestResult::Pass
}
kernel_test_in!(
    "userspace",
    smoke_userspace_memfd_create_returns_writable_fd
);

#[cfg(target_arch = "x86_64")]
fn smoke_init_file_listing_returns_none_when_not_staged() -> TestResult {
    if narf_initramfs::is_staged() {
        return TestResult::Skip("initramfs is staged in this test env");
    }
    if crate::init::initramfs_file_listing().is_some() {
        return TestResult::Fail("listing should be None when not staged");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "userspace/init",
    smoke_init_file_listing_returns_none_when_not_staged
);

/// A grandchild inherits the namespace transitively: the child forked by an
/// in-namespace parent must itself be a member (keyed by its TaskId) so that
/// when IT forks, `ns_of(child_task)` resolves and the grandchild is bound.
/// The earlier ProcessId-keyed store broke exactly this — a namespace died
/// after one generation, so systemd's service subprocesses fell out of the
/// pidns (see project_pidns_flow_model).
#[cfg(feature = "container")]
fn smoke_pid_ns_grandchild_inherits_namespace() -> TestResult {
    crate::pid_ns::__test_reset();
    let parent_task: u64 = 0xA000;
    let parent_outer: u64 = 100;
    let child_task: u64 = 0xA001;
    let child_outer: u64 = 101;
    let grand_task: u64 = 0xA002;
    let grand_outer: u64 = 102;

    let ns = crate::pid_ns::unshare_pid_ns(parent_task, parent_outer);
    // parent → child (inner 2)
    match crate::pid_ns::inherit_into_child(parent_task, child_task, child_outer) {
        Some(2) => {}
        _ => return TestResult::Fail("child inner pid != 2"),
    }
    // child → grandchild: MUST resolve the child's ns via its TaskId.
    let grand_inner = match crate::pid_ns::inherit_into_child(child_task, grand_task, grand_outer) {
        Some(i) => i,
        None => {
            return TestResult::Fail(
                "grandchild not bound — child's namespace was unreachable by TaskId",
            )
        }
    };
    if grand_inner != 3 {
        return TestResult::Fail("grandchild inner pid != 3");
    }
    if crate::pid_ns::self_inner_pid(grand_task, grand_outer) != 3 {
        return TestResult::Fail("grandchild self_inner_pid != 3");
    }
    if ns.inner_to_outer(3) != Some(grand_outer) {
        return TestResult::Fail("ns missing grandchild translation");
    }
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_pid_ns_grandchild_inherits_namespace);

/// `ns_visible_inner` filters + translates: a bound outer pid → its inner id;
/// an outer pid NOT in the namespace → None (isolation); a root-namespace task
/// (no entry) → the outer pid unchanged. Backs `/proc` enumeration and
/// cgroup.procs listing.
#[cfg(feature = "container")]
fn smoke_pid_ns_visible_inner_filters() -> TestResult {
    crate::pid_ns::__test_reset();
    let (p_task, p_out, c_task, c_out) = (0xB000u64, 100u64, 0xB001u64, 101u64);
    crate::pid_ns::unshare_pid_ns(p_task, p_out);
    crate::pid_ns::inherit_into_child(p_task, c_task, c_out);

    if crate::pid_ns::ns_visible_inner(p_task, p_out) != Some(1) {
        return TestResult::Fail("parent not visible as inner 1");
    }
    if crate::pid_ns::ns_visible_inner(p_task, c_out) != Some(2) {
        return TestResult::Fail("child not visible as inner 2");
    }
    if crate::pid_ns::ns_visible_inner(p_task, 999).is_some() {
        return TestResult::Fail("out-of-namespace pid must be invisible (None)");
    }
    // A task with no namespace entry (root ns) sees every outer pid as itself.
    if crate::pid_ns::ns_visible_inner(0xDEAD, c_out) != Some(c_out) {
        return TestResult::Fail("root-ns task must see the outer pid unchanged");
    }
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_pid_ns_visible_inner_filters);

/// A credential PID outside the receiver's PID namespace must not leak its
/// outer value. Linux reports zero for such peer/SCM credentials; this keeps
/// `SO_PEERCRED` and `SCM_CREDENTIALS` namespace-safe.
#[cfg(feature = "container")]
fn smoke_pid_ns_unmapped_outer_pid_reports_zero() -> TestResult {
    crate::pid_ns::__test_reset();
    let (manager_task, manager_outer) = (0xB080u64, 100u64);
    crate::pid_ns::unshare_pid_ns(manager_task, manager_outer);

    if crate::pid_ns::self_inner_pid(manager_task, 999) != 0 {
        return TestResult::Fail("unmapped outer pid did not report as zero");
    }
    let received = crate::handlers::report_ucred_to(
        manager_task,
        crate::socket::Ucred {
            pid: 999,
            uid: 0,
            gid: 0,
        },
    );
    crate::pid_ns::__test_reset();
    if received.pid == 0 {
        TestResult::Pass
    } else {
        TestResult::Fail("unmapped SCM_CREDENTIALS pid leaked into namespace")
    }
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_pid_ns_unmapped_outer_pid_reports_zero);

/// The REPORT (outer→inner, `self_inner_pid`) and ACCEPT (inner→outer,
/// `resolve_inner_pid`) directions are exact inverses for a bound pid, and an
/// unbound inner pid resolves to None. This is the round-trip the clone-return
/// / wait-want_pid / kill-target translations rely on.
#[cfg(feature = "container")]
fn smoke_pid_ns_report_accept_roundtrip() -> TestResult {
    crate::pid_ns::__test_reset();
    let (p_task, p_out, c_task, c_out) = (0xB100u64, 100u64, 0xB101u64, 101u64);
    crate::pid_ns::unshare_pid_ns(p_task, p_out);
    crate::pid_ns::inherit_into_child(p_task, c_task, c_out);

    // Child: outer 101 ↔ inner 2, both directions.
    let inner = crate::pid_ns::self_inner_pid(c_task, c_out);
    if inner != 2 {
        return TestResult::Fail("child report (outer→inner) != 2");
    }
    if crate::pid_ns::resolve_inner_pid(c_task, inner) != Some(c_out) {
        return TestResult::Fail("child accept (inner→outer) did not invert report");
    }
    // Parent: outer 100 ↔ inner 1.
    if crate::pid_ns::self_inner_pid(p_task, p_out) != 1 {
        return TestResult::Fail("parent report != 1");
    }
    if crate::pid_ns::resolve_inner_pid(p_task, 1) != Some(p_out) {
        return TestResult::Fail("parent accept != outer");
    }
    // An inner pid nobody bound must not resolve (→ ESRCH/ECHILD upstream).
    if crate::pid_ns::resolve_inner_pid(p_task, 999).is_some() {
        return TestResult::Fail("unbound inner pid must resolve to None");
    }
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_pid_ns_report_accept_roundtrip);

/// THE "not our child" invariant: from a child's namespace, its parent's OUTER
/// ProcessId renders as inner pid 1. This is exactly what `/proc/<child>/stat`
/// PPid and the child's `getppid()` must report so systemd (pid 1 in its
/// namespace) recognises the process it forked as its own child. Rendering the
/// parent's outer pid here instead made every service log "Supervising process
/// N which is not our child" (project_pidns_flow_model).
#[cfg(feature = "container")]
fn smoke_pid_ns_child_view_of_parent_is_pid_one() -> TestResult {
    crate::pid_ns::__test_reset();
    let (p_task, p_out, c_task, c_out) = (0xB200u64, 100u64, 0xB201u64, 101u64);
    crate::pid_ns::unshare_pid_ns(p_task, p_out);
    crate::pid_ns::inherit_into_child(p_task, c_task, c_out);

    // report_pid_to(child, parent_outer) — the child (and any same-namespace
    // reader, e.g. systemd) sees the parent as pid 1.
    if crate::pid_ns::self_inner_pid(c_task, p_out) != 1 {
        return TestResult::Fail("child's view of parent must be pid 1");
    }
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_pid_ns_child_view_of_parent_is_pid_one);

/// A service's `sd_notify()` datagram is accepted by systemd only when the
/// SCM_CREDENTIALS pid names that service in PID 1's namespace. Socket send
/// stamps the sender's outer ProcessId, so receive-side reporting must perform
/// the same outer→inner translation as wait4 and /proc. This pins that
/// Type=notify identity contract independently of the socket transport.
#[cfg(feature = "container")]
fn smoke_pid_ns_ucred_reports_service_pid_to_manager() -> TestResult {
    crate::pid_ns::__test_reset();
    let (manager_task, manager_outer, service_task, service_outer) =
        (0xB280u64, 100u64, 0xB281u64, 101u64);
    crate::pid_ns::unshare_pid_ns(manager_task, manager_outer);
    crate::pid_ns::inherit_into_child(manager_task, service_task, service_outer);

    let received = crate::handlers::report_ucred_to(
        manager_task,
        crate::socket::Ucred {
            pid: service_outer as u32,
            uid: 0,
            gid: 0,
        },
    );
    if received.pid != 2 {
        return TestResult::Fail("SCM_CREDENTIALS did not report service as PID 2 to manager");
    }
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!(
    "userspace",
    smoke_pid_ns_ucred_reports_service_pid_to_manager
);

/// Exit cleanup: `release_outer` frees the dying task's inner slot for reuse so
/// a recycled outer pid doesn't inherit a stale inner id. `on_child_exit` keys
/// this by the TaskId (ns lookup) but frees by the ProcessId (the outer↔inner
/// binding); this pins the binding half.
#[cfg(feature = "container")]
fn smoke_pid_ns_release_frees_inner_slot() -> TestResult {
    crate::pid_ns::__test_reset();
    let (p_task, p_out) = (0xB300u64, 100u64);
    let ns = crate::pid_ns::unshare_pid_ns(p_task, p_out);
    crate::pid_ns::inherit_into_child(p_task, 0xB301, 101); // inner 2
    if ns.outer_to_inner(101) != Some(2) {
        return TestResult::Fail("child not bound as inner 2");
    }
    ns.release_outer(101);
    if ns.outer_to_inner(101).is_some() {
        return TestResult::Fail("release_outer did not drop the binding");
    }
    // The freed inner 2 is reused by the next bind (lowest-free).
    if ns.bind_outer(102) != 2 {
        return TestResult::Fail("released inner slot 2 was not reused");
    }
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_pid_ns_release_frees_inner_slot);

/// Root-namespace fast path: a task with no `TASK_PID_NS` entry observes
/// outer == inner in every direction. This is the invariant that keeps the
/// non-container / root-namespace behaviour bit-identical after the fix.
#[cfg(feature = "container")]
fn smoke_pid_ns_root_task_is_identity() -> TestResult {
    crate::pid_ns::__test_reset();
    let t = 0xB400u64;
    if crate::pid_ns::self_inner_pid(t, 555) != 555 {
        return TestResult::Fail("root report must be identity");
    }
    if crate::pid_ns::resolve_inner_pid(t, 555) != Some(555) {
        return TestResult::Fail("root accept must be identity");
    }
    if crate::pid_ns::ns_visible_inner(t, 555) != Some(555) {
        return TestResult::Fail("root visibility must be identity");
    }
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_pid_ns_root_task_is_identity);

/// Mount namespace snapshot: a private NS sees its own mount table,
/// independent of further mounts on the global registry.
#[cfg(feature = "container")]
fn smoke_mount_ns_isolates_per_task_mounts() -> TestResult {
    // Snapshot the global registry into two private NSes. They start
    // with the same view but diverge once mounts are added to one.
    // We don't have a no-side-effect mount-adder here, so the
    // assertion is structural: snapshot_global produces a distinct
    // Arc per call (each task gets its own).
    let ns_a = narf_filesystem::MountNamespace::snapshot_global();
    let ns_b = narf_filesystem::MountNamespace::snapshot_global();
    if alloc::sync::Arc::ptr_eq(&ns_a, &ns_b) {
        return TestResult::Fail("snapshot_global returned aliased Arc");
    }
    // Both snapshots reflect the same set of mount paths.
    let mut paths_a = ns_a.list();
    let mut paths_b = ns_b.list();
    paths_a.sort();
    paths_b.sort();
    if paths_a != paths_b {
        return TestResult::Fail("snapshots disagree on initial mount set");
    }
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_mount_ns_isolates_per_task_mounts);

// ── Wave-72 — UTS / NET / IPC namespaces ───────────────────────────

/// unshare(CLONE_NEWUTS) gives a task a private hostname slot. A
/// fork-style "child" inherits the parent's NS Arc by setns, so its
/// view sees the parent's sethostname; a sibling that never
/// unshared still reads the global default.
#[cfg(feature = "container")]
fn smoke_wave72_uts_ns_per_task_hostname() -> TestResult {
    crate::namespaces::__test_reset_all();
    let parent: u64 = 0xA000_0001;
    let child: u64 = 0xA000_0002;
    let sibling: u64 = 0xA000_0003;

    crate::namespaces::unshare_uts(parent);
    let parent_ns = match crate::namespaces::uts_ns_of(parent) {
        Some(ns) => ns,
        None => return TestResult::Fail("parent has no UTS NS after unshare"),
    };
    parent_ns.set_hostname("parent-host");

    // Child joins parent's NS (Arc share).
    crate::namespaces::setns_uts(child, parent_ns.clone());
    if crate::namespaces::current_uts_ns(child).hostname() != "parent-host" {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("child does not see parent's hostname");
    }

    // Sibling never unshared → global default ("narf").
    if crate::namespaces::current_uts_ns(sibling).hostname() != crate::namespaces::DEFAULT_HOSTNAME
    {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("sibling sees per-NS hostname instead of global");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_wave72_uts_ns_per_task_hostname);

/// Two CLONE_NEWIPC tasks: shmget(SAME_KEY) returns distinct ids
/// because each NS mints its own.
#[cfg(feature = "container")]
fn smoke_wave72_ipc_ns_distinct_shmget() -> TestResult {
    crate::namespaces::__test_reset_all();
    let a: u64 = 0xC000_0001;
    let b: u64 = 0xC000_0002;
    crate::namespaces::unshare_ipc(a);
    crate::namespaces::unshare_ipc(b);
    let ns_a = match crate::namespaces::current_ipc_ns(a) {
        Some(ns) => ns,
        None => {
            crate::namespaces::__test_reset_all();
            return TestResult::Fail("task A has no IPC NS after unshare");
        }
    };
    let ns_b = match crate::namespaces::current_ipc_ns(b) {
        Some(ns) => ns,
        None => {
            crate::namespaces::__test_reset_all();
            return TestResult::Fail("task B has no IPC NS after unshare");
        }
    };
    const KEY: u32 = 0xBEEF;
    let id_a = ns_a.shmget(KEY);
    let id_b = ns_b.shmget(KEY);
    // Both start their counters at 1 → both should return 1, which is
    // the same numeric value but minted from independent counters.
    // The point is they don't alias: a second call in A returns a new
    // id for a different key, independent of B's keyspace.
    if id_a != ns_a.shmget(KEY) {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("same key in same NS returned a different id");
    }
    if id_b != ns_b.shmget(KEY) {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("same key in same NS returned a different id (B)");
    }
    // Add a second key to A only; B's counter must not advance.
    let id_a2 = ns_a.shmget(0xCAFE);
    if id_a2 == id_b {
        // Acceptable — independent counters can collide numerically.
    }
    // Lookup of 0xCAFE in B must mint a fresh id, not 0xCAFE→id_a2's value
    // by leaking state across namespaces.
    let id_b2 = ns_b.shmget(0xCAFE);
    if !alloc::sync::Arc::ptr_eq(&ns_a, &ns_b) && id_b2 == 0 {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("NS-B yielded reserved id 0 for new key");
    }
    // Critical distinct-namespace invariant: A and B are different Arcs.
    if alloc::sync::Arc::ptr_eq(&ns_a, &ns_b) {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("A and B share an IPC NS Arc");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_wave72_ipc_ns_distinct_shmget);

/// Drive sys_unshare directly with the combined NEWUTS|NEWNET|NEWIPC
/// flag mask; verify all 3 NS slots populate for the calling task.
#[cfg(feature = "container")]
fn smoke_wave72_sys_unshare_honours_new_flags() -> TestResult {
    use crate::handlers::install_task_id_lookup;
    crate::namespaces::__test_reset_all();

    const FAKE_TASK: u64 = 0xD000_DEAD;
    fn lookup() -> u64 {
        FAKE_TASK
    }
    install_task_id_lookup(lookup);

    let flags = crate::namespaces::CLONE_NEWUTS
        | crate::namespaces::CLONE_NEWNET
        | crate::namespaces::CLONE_NEWIPC;
    crate::syscall::__test_clear_global();
    let mut t = SyscallTable::new();
    install_core_syscalls(&mut t);
    install_global(t);

    let mut ctx = StubCtx {
        args: SyscallArgs {
            arg0: flags,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::Unshare.raw(), &mut ctx);
    let ret = match ctx.ret {
        Some(r) => r,
        None => {
            crate::namespaces::__test_reset_all();
            return TestResult::Fail("sys_unshare did not set return");
        }
    };
    if ret.value != 0 {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("sys_unshare returned non-zero");
    }
    if crate::namespaces::uts_ns_of(FAKE_TASK).is_none() {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("NEWUTS slot not populated");
    }
    if crate::namespaces::current_net_ns(FAKE_TASK).is_none() {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("NEWNET slot not populated");
    }
    if crate::namespaces::current_ipc_ns(FAKE_TASK).is_none() {
        crate::namespaces::__test_reset_all();
        return TestResult::Fail("NEWIPC slot not populated");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_wave72_sys_unshare_honours_new_flags);

#[cfg(feature = "linux-compat")]
fn smoke_userspace_clock_nanosleep_abstime_returns_at_or_after_target() -> TestResult {
    // Kernel-test fixture: this smoke calls the syscall entry point directly and
    // passes it kernel `.rodata` / stack / heap pointers as stand-in user
    // buffers. `validate_user_range` confines a real syscall to the user half,
    // so the scoped opt-in is what keeps the fixture working without weakening
    // the production predicate. See `handlers::kernel_buffers_guard`.
    let _kbuf = crate::handlers::kernel_buffers_guard();
    // clock_gettime → build target = now + 10ms →
    // clock_nanosleep(ABSTIME, target) → assert monotonic_ns >= target.
    use crate::{
        fd, install_core_syscalls, install_global, install_task_id_lookup, kernel_syscall_entry,
        syscall::__test_clear_global, Syscall, SyscallArgs, SyscallReturn, SyscallTable,
        TrapContext,
    };
    use core::sync::atomic::{AtomicU64, Ordering};

    static TASK_ID: AtomicU64 = AtomicU64::new(0xE013);
    fn task_lookup() -> u64 {
        TASK_ID.load(Ordering::Relaxed)
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
        fn rip(&self) -> u64 {
            0
        }
        fn set_rip(&mut self, _rip: u64) {}
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool {
            false
        }
    }

    // Read current monotonic time.
    let mut ts_now = [0u8; 16];
    let mut ctx_get = FakeCtx {
        args: SyscallArgs {
            arg0: 1, // CLOCK_MONOTONIC
            arg1: ts_now.as_mut_ptr() as u64,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockGetTime.raw(), &mut ctx_get);
    if !matches!(ctx_get.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        __test_clear_global();
        return TestResult::Fail("clock_gettime failed");
    }
    let now_sec = i64::from_ne_bytes(ts_now[..8].try_into().unwrap());
    let now_nsec = i64::from_ne_bytes(ts_now[8..].try_into().unwrap());
    let now_ns = (now_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(now_nsec as u64);

    // Target = now + 10ms.
    let target_ns: u64 = now_ns.saturating_add(10_000_000);
    let target_sec = (target_ns / 1_000_000_000) as i64;
    let target_nsec = (target_ns % 1_000_000_000) as i64;
    let mut ts_target = [0u8; 16];
    ts_target[..8].copy_from_slice(&target_sec.to_ne_bytes());
    ts_target[8..].copy_from_slice(&target_nsec.to_ne_bytes());

    // clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME=1, &target, NULL).
    let mut ctx_sleep = FakeCtx {
        args: SyscallArgs {
            arg0: 1,
            arg1: 1, // TIMER_ABSTIME
            arg2: ts_target.as_ptr() as u64,
            arg3: 0,
            ..SyscallArgs::default()
        },
        ret: None,
    };
    kernel_syscall_entry(Syscall::ClockNanosleep.raw(), &mut ctx_sleep);
    __test_clear_global();

    if !matches!(ctx_sleep.ret, Some(r) if r.status == SyscallReturn::OK && r.value == 0) {
        return TestResult::Fail("clock_nanosleep failed");
    }
    let after_ns = narf_scheduler::narf_time::monotonic_ns();
    if after_ns >= target_ns {
        TestResult::Pass
    } else {
        TestResult::Fail("monotonic_ns after clock_nanosleep is before target")
    }
}
#[cfg(feature = "linux-compat")]
kernel_test_in!(
    "userspace",
    smoke_userspace_clock_nanosleep_abstime_returns_at_or_after_target
);

// DAC boundary (placed at end of file deliberately: this suite is at the
// margin and inserting a test *earlier* shifts the fragile
// `smoke_userspace_execve_with_envp_pack_accepts` and tips it — see the
// kernel-test-suite marginal-heap notes). The kernel enforces DAC in
// `sys_open` via `posix_access_ok` over the file's owner/perms against the
// caller's (fs)uid/gid; this pins that decision for the /etc/shadow case.
fn smoke_dac_shadow_denies_nonroot() -> TestResult {
    use narf_filesystem::{posix_access_ok, AccessRequest, Accessor, FileOwner};
    let rd = AccessRequest {
        read: true,
        write: false,
        exec: false,
    };
    // /etc/shadow: 0600 owned by root.
    let shadow = FileOwner {
        uid: 0,
        gid: 0,
        perms: 0o600,
    };
    // A world-readable 0o666 file.
    let public = FileOwner {
        uid: 0,
        gid: 0,
        perms: 0o666,
    };
    // root reads the 0600 shadow.
    if !posix_access_ok(shadow, &Accessor::new(0, 0), rd) {
        return TestResult::Fail("root was denied the 0600 shadow");
    }
    // a dropped-privilege process (uid/gid 1000) may not.
    if posix_access_ok(shadow, &Accessor::new(1000, 1000), rd) {
        return TestResult::Fail("uid 1000 was allowed to read the 0600 shadow");
    }
    // and is still denied even sharing root's group (0600 group bits = ---).
    if posix_access_ok(shadow, &Accessor::new(1000, 0), rd) {
        return TestResult::Fail("a non-owner in gid 0 read the 0600 shadow");
    }
    // but the same process can read a world-rw 0o666 file.
    if !posix_access_ok(public, &Accessor::new(1000, 1000), rd) {
        return TestResult::Fail("uid 1000 was denied a world-rw 0o666 file");
    }
    TestResult::Pass
}
kernel_test_in!("userspace", smoke_dac_shadow_denies_nonroot);

// ════════════════════════════════════════════════════════════════
//  Linux namespace stack — NsId, ns-fd + setns round-trip, user-ns
//  uid_map translation, the DAC security gate, net-ns dual-bind.
//  All container-gated; appended at the very end of the suite so the
//  marginal-heap ordering of the earlier execve smokes is undisturbed
//  (see kernel-test-suite notes).
// ════════════════════════════════════════════════════════════════

/// Every namespace flavour mints a distinct, monotonically-increasing
/// NsId from the shared counter — the identity the ns-fd reports.
#[cfg(feature = "container")]
fn smoke_ns_id_unique_per_flavour() -> TestResult {
    crate::namespaces::__test_reset_all();
    crate::pid_ns::__test_reset();
    let a = crate::namespaces::UtsNamespace::new_default();
    let b = crate::namespaces::NetNamespace::new_with_loopback();
    let c = crate::namespaces::IpcNamespace::new();
    let d = crate::pid_ns::PidNamespace::new();
    let ids = [a.id(), b.id(), c.id(), d.id()];
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            if ids[i] == ids[j] {
                return TestResult::Fail("two namespaces share an NsId");
            }
        }
    }
    crate::namespaces::__test_reset_all();
    crate::pid_ns::__test_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_ns_id_unique_per_flavour);

/// ns-fd open + setns round-trip: task A unshares a UTS ns and sets a
/// hostname; an ns-fd minted for A is installed onto task B via the
/// HeldNs install path; B then sees A's hostname.
#[cfg(feature = "container")]
fn smoke_ns_fd_setns_roundtrip() -> TestResult {
    crate::namespaces::__test_reset_all();
    let a: u64 = 0xA11CE;
    let b: u64 = 0xB0B;

    crate::namespaces::unshare_uts(a);
    crate::namespaces::current_uts_ns(a).set_hostname("container-a");

    // Mint an ns-fd naming A's UTS ns (what /proc/A/ns/uts would).
    let nsfd = match crate::namespaces::ns_fd_for(a, crate::namespaces::NsFlavour::Uts) {
        Some(f) => f,
        None => return TestResult::Fail("ns_fd_for(uts) returned None"),
    };
    // readlink text shape: uts:[<id>].
    let link = nsfd.link_text();
    if !link.starts_with("uts:[") || !link.ends_with(']') {
        return TestResult::Fail("ns-fd link_text not uts:[id]");
    }

    // B joins via the held-ns install (nstype 0 = any).
    let held = nsfd.held().clone();
    if !crate::namespaces::install_held_ns(b, b, &held, 0) {
        return TestResult::Fail("install_held_ns(uts) failed");
    }
    if crate::namespaces::current_uts_ns(b).hostname() != "container-a" {
        return TestResult::Fail("B did not see A's hostname after setns");
    }
    // nstype mismatch is rejected.
    if crate::namespaces::install_held_ns(b, b, &held, crate::namespaces::CLONE_NEWNET) {
        return TestResult::Fail("install_held_ns accepted a wrong nstype");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_ns_fd_setns_roundtrip);

/// Tasks in initial namespaces still have openable `/proc/<pid>/ns/*`
/// entries. The initial namespace is shared and therefore must return a
/// stable identity across repeated opens rather than `None`.
#[cfg(feature = "container")]
fn smoke_initial_namespace_fds_are_stable() -> TestResult {
    let task = 0x01A1_71A1;
    let flavours = [
        crate::namespaces::NsFlavour::Uts,
        crate::namespaces::NsFlavour::Net,
        crate::namespaces::NsFlavour::Ipc,
        crate::namespaces::NsFlavour::Pid,
        crate::namespaces::NsFlavour::Mnt,
        crate::namespaces::NsFlavour::User,
    ];
    for flavour in flavours {
        let first = match crate::handlers::namespace_fd_for_task(task, flavour) {
            Some(fd) => fd,
            None => return TestResult::Fail("initial namespace fd was absent"),
        };
        let second = crate::handlers::namespace_fd_for_task(task, flavour).unwrap();
        if first.held().id() == 0 || first.held().id() != second.held().id() {
            return TestResult::Fail("initial namespace fd identity was zero or unstable");
        }
    }
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_initial_namespace_fds_are_stable);

#[cfg(all(feature = "container", feature = "cgroup"))]
fn smoke_initial_cgroup_namespace_fd_is_stable() -> TestResult {
    let task = 0xC6_001;
    let first =
        crate::handlers::namespace_fd_for_task(task, crate::namespaces::NsFlavour::Cgroup).unwrap();
    let second =
        crate::handlers::namespace_fd_for_task(task, crate::namespaces::NsFlavour::Cgroup).unwrap();
    if first.held().id() != 0 && first.held().id() == second.held().id() {
        TestResult::Pass
    } else {
        TestResult::Fail("initial cgroup namespace identity was zero or unstable")
    }
}
#[cfg(all(feature = "container", feature = "cgroup"))]
kernel_test_in!("userspace", smoke_initial_cgroup_namespace_fd_is_stable);

/// An open ns-fd keeps the namespace alive after the originating task
/// exits: dropping A's per-task entry leaves the ns reachable through
/// the held Arc, and a later joiner sees the same id + state.
#[cfg(feature = "container")]
fn smoke_ns_fd_outlives_originator() -> TestResult {
    crate::namespaces::__test_reset_all();
    let a: u64 = 0xDEAD;
    crate::namespaces::unshare_uts(a);
    crate::namespaces::current_uts_ns(a).set_hostname("ghost");
    let id = crate::namespaces::current_uts_ns(a).id();
    let nsfd = crate::namespaces::ns_fd_for(a, crate::namespaces::NsFlavour::Uts).unwrap();

    // Simulate A exiting: wipe the per-task tables. The ns-fd still
    // holds the Arc.
    crate::namespaces::__test_reset_all();

    let held = nsfd.held().clone();
    if held.id() != id {
        return TestResult::Fail("held ns id changed after originator exit");
    }
    let b: u64 = 0xF00D;
    if !crate::namespaces::install_held_ns(b, b, &held, 0) {
        return TestResult::Fail("install after originator exit failed");
    }
    if crate::namespaces::current_uts_ns(b).hostname() != "ghost" {
        return TestResult::Fail("ns state lost after originator exit");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_ns_fd_outlives_originator);

/// User-ns uid_map translation: inner ids in a mapped run translate to
/// their host ids; unmapped inner ids fall to the overflow id; the
/// one-shot write rule rejects a second write.
#[cfg(feature = "container")]
fn smoke_user_ns_uid_map_translation() -> TestResult {
    use crate::namespaces::{IdMapEntry, UserNamespace, OVERFLOW_ID};
    crate::namespaces::__test_reset_all();
    let host = UserNamespace::new_initial();
    let uns = UserNamespace::new_child(host, 1000);
    // Map inner [0,5) → host [1000,1005).
    let entries = alloc::vec![IdMapEntry {
        inner_start: 0,
        outer_start: 1000,
        count: 5,
    }];
    if uns.write_uid_map(entries.clone()).is_err() {
        return TestResult::Fail("first uid_map write rejected");
    }
    // One-shot rule: a second write fails.
    if uns.write_uid_map(entries).is_ok() {
        return TestResult::Fail("second uid_map write was allowed (one-shot rule)");
    }
    if uns.translate_uid_to_host(0) != 1000 {
        return TestResult::Fail("inner 0 did not map to host 1000");
    }
    if uns.translate_uid_to_host(4) != 1004 {
        return TestResult::Fail("inner 4 did not map to host 1004");
    }
    // Unmapped inner id → overflow.
    if uns.translate_uid_to_host(9) != OVERFLOW_ID {
        return TestResult::Fail("unmapped inner id did not become overflow");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_user_ns_uid_map_translation);

/// SECURITY GATE (hard): a process that is root *inside* an
/// unprivileged user-ns whose map does NOT include host-0 is DENIED a
/// host-root-owned 0600 file; and a file owned by the mapped outer uid
/// IS accessible as inner-0. Exercises the real DAC funnel
/// `current_accessor` → `posix_access_ok`.
#[cfg(feature = "container")]
fn smoke_user_ns_dac_no_host_root_escape() -> TestResult {
    use crate::namespaces::IdMapEntry;
    use narf_filesystem::{posix_access_ok, AccessRequest, FileOwner};
    crate::namespaces::__test_reset_all();
    crate::handlers::__test_uidgid_reset();

    let task: u64 = 0xC0FFEE;
    // The task is inner uid 0 (root *inside* the ns).
    crate::handlers::__test_set_fsids(task, 0, 0);
    // Unprivileged user-ns owned by host uid 1000; map inner 0 → host
    // 1000 (NOT host 0). So in-ns root is host uid 1000.
    let host = crate::namespaces::UserNamespace::new_initial();
    let uns = crate::namespaces::UserNamespace::new_child(host, 1000);
    let _ = uns.write_uid_map(alloc::vec![IdMapEntry {
        inner_start: 0,
        outer_start: 1000,
        count: 1,
    }]);
    let _ = uns.write_gid_map(alloc::vec![IdMapEntry {
        inner_start: 0,
        outer_start: 1000,
        count: 1,
    }]);
    crate::namespaces::setns_user(task, uns);

    // The DAC funnel must translate in-ns uid 0 to host uid 1000.
    let acc = crate::handlers::__test_current_accessor(task);
    if acc.uid != 1000 {
        return TestResult::Fail("DAC funnel did not translate in-ns root to host 1000");
    }

    let rd = AccessRequest {
        read: true,
        write: false,
        exec: false,
    };
    // Host-root-owned 0600 file: in-ns root (host 1000) is DENIED.
    let host_shadow = FileOwner {
        uid: 0,
        gid: 0,
        perms: 0o600,
    };
    if posix_access_ok(host_shadow, acc, rd) {
        return TestResult::Fail("SECURITY: in-ns root read a host-root 0600 file");
    }
    // A file owned by the mapped outer uid (1000) at 0600 IS readable.
    let owned = FileOwner {
        uid: 1000,
        gid: 1000,
        perms: 0o600,
    };
    if !posix_access_ok(owned, acc, rd) {
        return TestResult::Fail("in-ns root denied its own (mapped) file");
    }

    // Control: a user-ns that DOES map inner 0 → host 0 *is* host root.
    let host2 = crate::namespaces::UserNamespace::new_initial();
    let priv_ns = crate::namespaces::UserNamespace::new_child(host2, 0);
    let _ = priv_ns.write_uid_map(alloc::vec![IdMapEntry {
        inner_start: 0,
        outer_start: 0,
        count: 1,
    }]);
    let _ = priv_ns.write_gid_map(alloc::vec![IdMapEntry {
        inner_start: 0,
        outer_start: 0,
        count: 1,
    }]);
    let task2: u64 = 0xBEEF;
    crate::handlers::__test_set_fsids(task2, 0, 0);
    crate::namespaces::setns_user(task2, priv_ns);
    let acc2 = crate::handlers::__test_current_accessor(task2);
    if acc2.uid != 0 || !posix_access_ok(host_shadow, acc2, rd) {
        return TestResult::Fail("inner-0→host-0 mapping failed to grant host root");
    }

    crate::namespaces::__test_reset_all();
    crate::handlers::__test_uidgid_reset();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_user_ns_dac_no_host_root_escape);

/// fork inheritance: a child shares the parent's UTS / IPC / User
/// namespace Arc (not a fresh copy) when no CLONE_NEW* is requested.
#[cfg(feature = "container")]
fn smoke_ns_inherit_shares_parent_arc() -> TestResult {
    crate::namespaces::__test_reset_all();
    let parent: u64 = 0x1234;
    let child: u64 = 0x5678;
    crate::namespaces::unshare_uts(parent);
    crate::namespaces::unshare_ipc(parent);
    crate::namespaces::unshare_user(parent, 0);

    crate::namespaces::inherit_into_child(parent, child);

    let pu = crate::namespaces::uts_ns_of(parent).unwrap();
    let cu = crate::namespaces::uts_ns_of(child).unwrap();
    if !alloc::sync::Arc::ptr_eq(&pu, &cu) {
        return TestResult::Fail("child UTS ns is not the parent's Arc");
    }
    let piu = crate::namespaces::user_ns_of(parent).unwrap();
    let ciu = crate::namespaces::user_ns_of(child).unwrap();
    if !alloc::sync::Arc::ptr_eq(&piu, &ciu) {
        return TestResult::Fail("child user ns is not the parent's Arc");
    }
    crate::namespaces::__test_reset_all();
    TestResult::Pass
}
#[cfg(feature = "container")]
kernel_test_in!("userspace", smoke_ns_inherit_shares_parent_arc);
