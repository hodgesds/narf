//! IA-32 emulation end to end (`verification/ia32-*`): Linux
//! `CONFIG_IA32_EMULATION` behaviour checked with real user code.
//!
//! Each program is a few hand-assembled i386 or x86_64 instructions in a
//! fresh address space below 4 GiB, run as an ordinary own-stack user task.
//! It reports through a data page the test reads back after the run:
//! offsets below `INPUT` are results the program stores, inputs (a
//! `user_desc`, a TLS block) sit from `INPUT` up.
//!
//! No ELF32 loader is involved: the process is built by hand with
//! `UserProcess::ia32` set, which is what the loader will set for an
//! `ELFCLASS32`/`EM_386` image.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_memory::{AddressSpace, PhysAddr, Region, RegionPerms, VirtAddr};
use narf_userspace::{install_core_syscalls, install_global, SyscallTable, UserProcess};

const CODE_VADDR: u64 = 0x0040_0000;
const STACK_VADDR: u64 = 0x0041_0000;
const DATA_VADDR: u64 = 0x0042_0000;
const PAGE_BYTES: u64 = 4096;
/// Data-page offset where the inputs a test plants begin.
const INPUT: usize = 0x100;

/// One hand-built program, the data page it reports through, and its
/// address space (held so the data frame outlives the task).
struct Program {
    process: Option<UserProcess>,
    _space: Arc<AddressSpace>,
    data: PhysAddr,
    pid: u64,
}

fn alloc_page() -> Result<PhysAddr, &'static str> {
    narf_memory::alloc_frame()
        .map(|frame| frame.start_address())
        .map_err(|_| "alloc frame")
}

/// Build `code` as a program entered in compatibility mode (`ia32`) or in
/// 64-bit mode, with `inputs` (offset, bytes) planted in its data page.
fn build(code: &[u8], ia32: bool, inputs: &[(usize, &[u8])]) -> Result<Program, &'static str> {
    if code.len() > PAGE_BYTES as usize {
        return Err("program larger than a page");
    }
    if inputs
        .iter()
        .any(|(off, bytes)| off + bytes.len() > PAGE_BYTES as usize || *off < INPUT)
    {
        return Err("input outside the data page's input area");
    }
    let code_phys = alloc_page()?;
    let stack_phys = alloc_page()?;
    let data_phys = alloc_page()?;
    // SAFETY: three fresh 4 KiB frames, written through the kernel direct
    // map; every copy stays inside its page (checked above).
    unsafe {
        core::ptr::write_bytes(code_phys.kernel_mut_ptr::<u8>(), 0, PAGE_BYTES as usize);
        core::ptr::copy_nonoverlapping(code.as_ptr(), code_phys.kernel_mut_ptr::<u8>(), code.len());
        core::ptr::write_bytes(stack_phys.kernel_mut_ptr::<u8>(), 0, PAGE_BYTES as usize);
        core::ptr::write_bytes(data_phys.kernel_mut_ptr::<u8>(), 0, PAGE_BYTES as usize);
        for (off, bytes) in inputs {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                data_phys.kernel_mut_ptr::<u8>().add(*off),
                bytes.len(),
            );
        }
    }
    // SAFETY: paging and the frame allocator are live in the kernel-test boot.
    let address_space = unsafe { AddressSpace::new_for_user() }.map_err(|_| "new_for_user")?;
    for (base, perms, phys) in [
        (CODE_VADDR, RegionPerms::READ | RegionPerms::EXEC, code_phys),
        (
            STACK_VADDR,
            RegionPerms::READ | RegionPerms::WRITE,
            stack_phys,
        ),
        (
            DATA_VADDR,
            RegionPerms::READ | RegionPerms::WRITE,
            data_phys,
        ),
    ] {
        address_space
            .map_region(Region {
                base: VirtAddr::new(base),
                len: PAGE_BYTES,
                perms,
                phys: alloc::vec![phys].into(),
            })
            .map_err(|_| "map region")?;
    }
    // SAFETY: the inactive root owns every mapped frame above.
    unsafe { address_space.materialize() }.map_err(|_| "materialize")?;
    let space = Arc::new(address_space);
    Ok(Program {
        process: Some(UserProcess {
            pid: narf_userspace::alloc_pid(),
            address_space: space.clone(),
            entry: narf_userspace::EntryPoint(VirtAddr::new(CODE_VADDR)),
            stack_top: VirtAddr::new(STACK_VADDR + PAGE_BYTES),
            fs_base: None,
            gs_base: 0,
            entry_arg: None,
            loaded_mappings: Vec::new(),
            program_bias: 0,
            page_in_plan: Vec::new(),
            ia32,
            segs: narf_userspace::UserSegments::default(),
        }),
        _space: space,
        data: data_phys,
        pid: 0,
    })
}

impl Program {
    fn u32_at(&self, off: usize) -> u32 {
        // SAFETY: `data` is this program's data frame, kept alive by
        // `_space`; `off + 4` is inside the page at every call site.
        unsafe { core::ptr::read_volatile(self.data.kernel_ptr::<u8>().add(off).cast::<u32>()) }
    }

    fn u64_at(&self, off: usize) -> u64 {
        // SAFETY: as `u32_at`.
        unsafe { core::ptr::read_volatile(self.data.kernel_ptr::<u8>().add(off).cast::<u64>()) }
    }

    fn bytes_at<const N: usize>(&self, off: usize) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, byte) in out.iter_mut().enumerate() {
            // SAFETY: as `u32_at`; `off + N` is inside the page.
            *byte = unsafe { core::ptr::read_volatile(self.data.kernel_ptr::<u8>().add(off + i)) };
        }
        out
    }
}

/// Spawn every program as its own process on the boot CPU, run the
/// executor until all of them exit, and tear the harness state down again.
fn run(programs: &mut [Program]) -> Result<(), &'static str> {
    // SAFETY: privileged harness context; the root stays live throughout.
    let original_root = unsafe { narf_arch::x86_64::cr::read_cr3() };
    narf_userspace::syscall::__test_clear_global();
    narf_userspace::user_task::__test_clear_hooks();
    narf_userspace::user_task::__test_clear_execve_hook();
    narf_userspace::handlers::__test_reset_task_id_lookup();
    narf_userspace::handlers::__test_wait_reset();
    narf_userspace::handlers::__test_signal_reset();
    narf_userspace::handlers::__test_sigaction_reset();
    narf_userspace::handlers::init_per_task_state();
    narf_scheduler::__reset_queues_for_test();

    let mut table = SyscallTable::new();
    install_core_syscalls(&mut table);
    install_global(table);
    let previous_as_lookup = narf_userspace::handlers::address_space_lookup();
    narf_userspace::install_address_space_lookup(narf_scheduler::current_address_space);
    narf_userspace::install_task_id_lookup(|| narf_scheduler::current_task_id().raw());
    narf_userspace::install_user_task_hooks();

    let mut pending = Vec::new();
    let mut ids = Vec::new();
    let mut missing = false;
    for program in programs.iter_mut() {
        let Some(process) = program.process.take() else {
            missing = true;
            continue;
        };
        program.pid = process.pid.raw();
        let task = narf_userspace::user_task::prepare_user_process_initial(
            process,
            narf_scheduler::TaskSpec::unthrottled(),
        );
        let id = task.task_id();
        narf_userspace::handlers::register_pid_task_mapping(program.pid, id.raw());
        ids.push(id);
        pending.push(task);
    }
    for task in pending {
        task.spawn();
    }
    narf_scheduler::run_until_empty();

    // SAFETY: restore the live harness root before user mappings go.
    unsafe { narf_arch::x86_64::cr::write_cr3(original_root) };
    let mut exited = true;
    for id in &ids {
        exited &= narf_userspace::task::task_has_exited(id.raw());
        narf_scheduler::__test_clear_published_address_space(*id);
    }
    narf_scheduler::__reset_queues_for_test();
    for id in &ids {
        narf_userspace::task::release_task(id.raw());
    }
    narf_userspace::handlers::__test_wait_reset();
    narf_userspace::user_task::__test_clear_hooks();
    narf_userspace::user_task::__test_clear_execve_hook();
    narf_userspace::syscall::__test_clear_global();
    narf_userspace::handlers::restore_address_space_lookup(previous_as_lookup);
    narf_userspace::handlers::__test_reset_task_id_lookup();
    if missing {
        return Err("a program was run twice");
    }
    if !exited {
        return Err("a user program did not exit");
    }
    Ok(())
}

const fn le32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

// ── int 0x80 is the i386 ABI ────────────────────────────────────────

/// `-ENOSYS` as an i386 caller sees it in eax.
const ENOSYS_EAX: u32 = (-38i32) as u32;

/// A compatibility-mode task: entered with CS = `__USER32_CS` and the
/// `start_thread_ia32` data segments, `int 0x80` getpid answers its pid in
/// eax, an unknown number answers -ENOSYS, and `exit` (i386 1) ends it.
fn smoke_ia32_compat_task_int80_getpid() -> TestResult {
    let data = le32(DATA_VADDR as u32);
    #[rustfmt::skip]
    let code: Vec<u8> = alloc::vec![
        0xBF, data[0], data[1], data[2], data[3], // mov edi, DATA
        0x31, 0xC0, 0x66, 0x8C, 0xC8, // xor eax, eax; mov ax, cs
        0x89, 0x07, //                    mov [edi], eax
        0x31, 0xC0, 0x66, 0x8C, 0xD8, // mov ax, ds
        0x89, 0x47, 0x08, //              mov [edi + 8], eax
        0x31, 0xC0, 0x66, 0x8C, 0xD0, // mov ax, ss
        0x89, 0x47, 0x0C, //              mov [edi + 12], eax
        0x31, 0xC0, 0x66, 0x8C, 0xE8, // mov ax, gs
        0x89, 0x47, 0x10, //              mov [edi + 16], eax
        0x31, 0xC0, 0x66, 0x8C, 0xC0, // mov ax, es
        0x89, 0x47, 0x14, //              mov [edi + 20], eax
        0x31, 0xC0, 0x66, 0x8C, 0xE0, // mov ax, fs
        0x89, 0x47, 0x18, //              mov [edi + 24], eax
        0xB8, 0x14, 0x00, 0x00, 0x00, // mov eax, 20 (getpid)
        0xCD, 0x80, //                    int 0x80
        0x89, 0x47, 0x04, //              mov [edi + 4], eax
        0xB8, 0xFF, 0x7F, 0x00, 0x00, // mov eax, 0x7fff (no such call)
        0xCD, 0x80, //                    int 0x80
        0x89, 0x47, 0x1C, //              mov [edi + 28], eax
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (exit)
        0x31, 0xDB, //                    xor ebx, ebx
        0xCD, 0x80, //                    int 0x80
        0x0F, 0x0B, //                    ud2
    ];
    let mut programs = match build(&code, true, &[]) {
        Ok(p) => [p],
        Err(why) => return TestResult::Fail(why),
    };
    if let Err(why) = run(&mut programs) {
        return TestResult::Fail(why);
    }
    let p = &programs[0];
    if p.u32_at(0) != 0x23 {
        return TestResult::Fail("a compat task's CS is not __USER32_CS (0x23)");
    }
    if p.u32_at(8) != 0x2B || p.u32_at(12) != 0x2B || p.u32_at(20) != 0x2B {
        return TestResult::Fail("a compat task did not start with DS = SS = ES = __USER_DS");
    }
    if p.u32_at(16) != 0 || p.u32_at(24) != 0 {
        return TestResult::Fail("a compat task did not start with FS = GS = 0");
    }
    if u64::from(p.u32_at(4)) != p.pid {
        return TestResult::Fail("int 0x80 getpid (i386 20) did not return the pid in eax");
    }
    if p.u32_at(28) != ENOSYS_EAX {
        return TestResult::Fail("an unknown i386 number did not answer -ENOSYS");
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/ia32-int80",
    smoke_ia32_compat_task_int80_getpid
);

/// `int 0x80` from a 64-bit task is the i386 ABI too (Linux
/// `do_int80_emulation`): eax selects the i386 call whatever rax's upper
/// half holds, ebx is zero-extended, rax carries the 64-bit result, and
/// rdx/r8 (not i386 registers) come back untouched.
fn smoke_ia32_int80_from_64bit_task_is_i386() -> TestResult {
    let data = le32(DATA_VADDR as u32);
    let uts = le32(DATA_VADDR as u32 + INPUT as u32);
    #[rustfmt::skip]
    let code: Vec<u8> = alloc::vec![
        // movabs rax, 0xDEADBEEF_00000014: i386 getpid, garbage above eax
        0x48, 0xB8, 0x14, 0x00, 0x00, 0x00, 0xEF, 0xBE, 0xAD, 0xDE,
        // movabs rdx, 0x8877665544332211 (sentinel)
        0x48, 0xBA, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        // movabs r8, 0x01FFEEDDCCBBAA99 (sentinel)
        0x49, 0xB8, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01,
        0xCD, 0x80, //                               int 0x80
        0xBF, data[0], data[1], data[2], data[3], // mov edi, DATA
        0x48, 0x89, 0x07, //                         mov [rdi], rax
        0x48, 0x89, 0x57, 0x08, //                   mov [rdi + 8], rdx
        0x4C, 0x89, 0x47, 0x10, //                   mov [rdi + 16], r8
        // movabs rbx, 0xFFFFFFFF_<DATA + INPUT>: only ebx is the argument
        0x48, 0xBB, uts[0], uts[1], uts[2], uts[3], 0xFF, 0xFF, 0xFF, 0xFF,
        0xB8, 0x7A, 0x00, 0x00, 0x00, //             mov eax, 122 (newuname)
        0xCD, 0x80, //                               int 0x80
        0x48, 0x89, 0x47, 0x18, //                   mov [rdi + 24], rax
        0xB8, 0x3C, 0x00, 0x00, 0x00, //             mov eax, 60 (exit)
        0x31, 0xFF, //                               xor edi, edi
        0x0F, 0x05, //                               syscall
        0x0F, 0x0B, //                               ud2
    ];
    let mut programs = match build(&code, false, &[]) {
        Ok(p) => [p],
        Err(why) => return TestResult::Fail(why),
    };
    if let Err(why) = run(&mut programs) {
        return TestResult::Fail(why);
    }
    let p = &programs[0];
    if p.u64_at(0) != p.pid {
        return TestResult::Fail("int 0x80 from a 64-bit task did not run i386 getpid (eax 20)");
    }
    if p.u64_at(8) != 0x8877_6655_4433_2211 {
        return TestResult::Fail("int 0x80 clobbered rdx");
    }
    if p.u64_at(16) != 0x01FF_EEDD_CCBB_AA99 {
        return TestResult::Fail("int 0x80 clobbered r8");
    }
    if p.u64_at(24) != 0 {
        return TestResult::Fail("i386 uname with garbage above ebx did not succeed");
    }
    // `sys_uname` reports Linux's sysname (the Linux ABI, not NARF's).
    if p.bytes_at::<6>(INPUT) != *b"Linux\0" {
        return TestResult::Fail("i386 uname did not write sysname through ebx");
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/ia32-int80",
    smoke_ia32_int80_from_64bit_task_is_i386
);
