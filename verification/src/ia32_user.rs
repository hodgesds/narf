//! IA-32 emulation end to end (`verification/ia32-*`): Linux
//! `CONFIG_IA32_EMULATION` behaviour checked with real user code.
//!
//! Each program is a few hand-assembled i386 or x86_64 instructions in a
//! fresh address space below 4 GiB, run as an ordinary own-stack user task.
//! It reports through a data page that [`run`] copies out before the
//! address space goes: offsets below `INPUT` are results the program stores,
//! inputs (a `user_desc`, a TLS block) sit from `INPUT` up.
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

/// One hand-built program, its address space, and the data page it
/// reported through, as [`run`] copied it out.
struct Program {
    process: Option<UserProcess>,
    space: Arc<AddressSpace>,
    results: Vec<u8>,
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
        space,
        results: Vec::new(),
        pid: 0,
    })
}

impl Program {
    /// `N` result bytes at `off` of the data page; zeros past what [`run`]
    /// copied out.
    fn bytes_at<const N: usize>(&self, off: usize) -> [u8; N] {
        let mut out = [0u8; N];
        if let Some(src) = self.results.get(off..off + N) {
            out.copy_from_slice(src);
        }
        out
    }

    fn u32_at(&self, off: usize) -> u32 {
        u32::from_le_bytes(self.bytes_at(off))
    }

    fn u64_at(&self, off: usize) -> u64 {
        u64::from_le_bytes(self.bytes_at(off))
    }
}

/// A fast periodic timer for the duration of a run, so user loops are
/// interrupted (and preempted) many times.
struct FastTimer {
    irqs_were_enabled: bool,
}

impl FastTimer {
    fn start() -> Self {
        let irqs_were_enabled = narf_arch::interrupts_enabled();
        // SAFETY: the interrupt controller and timer are initialized before
        // kernel tests run, and no IRQ-unsafe lock is held here.
        unsafe {
            narf_interrupts::x86_64::apic::start_timer(narf_interrupts::VECTOR_TIMER, 10_000);
            narf_arch::enable_interrupts();
        }
        Self { irqs_were_enabled }
    }
}

impl Drop for FastTimer {
    fn drop(&mut self) {
        // SAFETY: this guard armed the timer; restore the harness's IRQ state.
        unsafe {
            narf_arch::disable_interrupts();
            narf_interrupts::x86_64::apic::stop_timer();
            if self.irqs_were_enabled {
                narf_arch::enable_interrupts();
            }
        }
    }
}

/// Leave the running CPU with no user segment state: empty TLS slots, null
/// DS/ES/FS/GS and a zero user GS base, whatever the last task left.
fn reset_cpu_segments() {
    use narf_arch::x86_64::segments;
    narf_lib::sync::without_interrupts(|| {
        // SAFETY: CPL0 with the kernel GS live and IRQs masked; null
        // selectors always load.
        unsafe {
            segments::load_tls(&[0; 3]);
            segments::load_user_selectors(segments::UserSelectors::default(), &[0; 3]);
            narf_arch::x86_64::user_mode::set_user_gs_base(0);
        }
    });
}

/// Spawn every program as its own process on the boot CPU, run the
/// executor until all of them exit (under a fast timer when `fast_timer`),
/// copy each program's data page out, and tear the harness state down again.
///
/// The copy needs a user reference on each address space (Linux `mmget`,
/// as `access_process_vm` takes one): once a program's last task is gone its
/// mappings and frames go back (`mmput` → `exit_mmap`), and a program that
/// forked may have moved its data page off the frame `build` planted, by a
/// copy-on-write store. So the reference is taken before the run and the
/// page is read through the mapping, then the reference is dropped.
fn run(programs: &mut [Program], fast_timer: bool) -> Result<(), &'static str> {
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
    let users;
    {
        let _timer = fast_timer.then(FastTimer::start);
        for task in pending {
            task.spawn();
        }
        // Spawned tasks are users of their address spaces, so this cannot
        // find one at zero; none has run yet.
        users = programs
            .iter()
            .map(|program| program.space.mmget_not_zero())
            .collect::<Vec<_>>();
        narf_scheduler::run_until_empty();
    }
    reset_cpu_segments();

    // SAFETY: restore the live harness root before user mappings go.
    unsafe { narf_arch::x86_64::cr::write_cr3(original_root) };
    let held = users.iter().all(Option::is_some);
    for program in programs.iter_mut() {
        let frame = program
            .space
            .lookup(VirtAddr::new(DATA_VADDR))
            .map(|region| region.backing_at(0))
            .filter(|frame| frame.as_u64() != 0);
        program.results = match frame {
            // SAFETY: the data page's current backing frame, which the
            // user reference in `users` keeps mapped and allocated; a whole
            // page is readable through the kernel direct map.
            Some(frame) => unsafe {
                core::slice::from_raw_parts(frame.kernel_ptr::<u8>(), PAGE_BYTES as usize)
            }
            .to_vec(),
            None => Vec::new(),
        };
    }
    let mut exited = true;
    for id in &ids {
        exited &= narf_userspace::task::task_has_exited(id.raw());
        narf_scheduler::__test_clear_published_address_space(*id);
    }
    // The last user of each address space: its mappings go now.
    drop(users);
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
    if !held {
        return Err("a program's address space had no user once spawned");
    }
    if !exited {
        return Err("a user program did not exit");
    }
    if programs.iter().any(|program| program.results.is_empty()) {
        return Err("a program's data page was not mapped after the run");
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
    if let Err(why) = run(&mut programs, false) {
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
    if let Err(why) = run(&mut programs, false) {
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

// ── TLS: set_thread_area / get_thread_area and the switch ───────────

/// Little assembler for the TLS programs: bytes plus 8-bit branches.
struct Asm(Vec<u8>);

impl Asm {
    fn op(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }

    /// `op imm32` (B8+r forms and friends).
    fn op_imm(&mut self, bytes: &[u8], imm: u32) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self.0.extend_from_slice(&imm.to_le_bytes());
        self
    }

    fn here(&self) -> usize {
        self.0.len()
    }

    /// A short branch `op rel8` back to `target`.
    fn branch_back(&mut self, op: u8, target: usize) -> &mut Self {
        let rel = target as isize - (self.0.len() as isize + 2);
        self.0.extend_from_slice(&[op, rel as i8 as u8]);
        self
    }

    /// A short forward branch `op rel8`; returns the site to [`Self::land`].
    fn branch_fwd(&mut self, op: u8) -> usize {
        self.0.extend_from_slice(&[op, 0]);
        self.0.len()
    }

    /// Point the forward branch ending at `site` here.
    fn land(&mut self, site: usize) {
        self.0[site - 1] = (self.0.len() - site) as u8;
    }
}

const JNE: u8 = 0x75;
const JMP: u8 = 0xEB;

/// i386 `set_thread_area(ebx)`: `mov eax, 243; int 0x80`.
fn i386_set_thread_area(a: &mut Asm) {
    a.op_imm(&[0xB8], 243).op(&[0xCD, 0x80]);
}

/// i386 `exit(0)`, then a trap if it returned.
fn i386_exit(a: &mut Asm) {
    a.op_imm(&[0xB8], 1)
        .op(&[0x31, 0xDB, 0xCD, 0x80, 0x0F, 0x0B]);
}

/// A `struct user_desc` as the user passes it.
fn user_desc(entry: u32, base: u32, limit: u32, flags: u32) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&entry.to_le_bytes());
    b[4..8].copy_from_slice(&base.to_le_bytes());
    b[8..12].copy_from_slice(&limit.to_le_bytes());
    b[12..16].copy_from_slice(&flags.to_le_bytes());
    b
}

/// glibc's TLS flags: seg_32bit, limit_in_pages, useable.
const TLS_FLAGS: u32 = 0x51;
/// The flags of an `LDT_empty` request: read_exec_only, seg_not_present.
const EMPTY_FLAGS: u32 = 0x28;
const TLS_MAGIC: u32 = 0xC0DE_F00D;

/// `set_thread_area(-1)` hands out GDT entry 12 and writes it back, %gs =
/// 0x63 then reads the descriptor's base, `get_thread_area` reports the
/// slot, the Linux refusals answer -EINVAL, a full table answers -ESRCH,
/// and an `LDT_empty` request frees a slot for the next allocation.
fn smoke_ia32_set_thread_area_entry_12_and_gs_base() -> TestResult {
    let data = DATA_VADDR as u32;
    let desc_addr = data + INPUT as u32;
    let base = data + 0x200;
    let mut a = Asm(Vec::new());
    a.op_imm(&[0xBF], data) //                        mov edi, DATA
        .op_imm(&[0xBB], desc_addr); //               mov ebx, &desc_a
    i386_set_thread_area(&mut a);
    a.op(&[0x89, 0x07]) //                             mov [edi], eax
        .op(&[0x8B, 0x03, 0x89, 0x47, 0x04]) //       [edi+4] = entry_number
        .op_imm(&[0xB8], 0x63) //                     mov eax, 0x63
        .op(&[0x8E, 0xE8]) //                         mov gs, ax
        .op_imm(&[0x65, 0x8B, 0x05], 0) //            mov eax, gs:[0]
        .op(&[0x89, 0x47, 0x08]) //                   [edi+8]
        .op(&[0x31, 0xC0, 0x66, 0x8C, 0xE8]) //       mov ax, gs
        .op(&[0x89, 0x47, 0x0C]) //                   [edi+12]
        // get_thread_area(12) over a scribbled copy.
        .op_imm(&[0xC7, 0x43, 0x04], 0) //            [ebx+4] = 0 (base)
        .op_imm(&[0xC7, 0x03], 12) //                 [ebx] = 12
        .op_imm(&[0xB8], 244)
        .op(&[0xCD, 0x80])
        .op(&[0x89, 0x47, 0x10]) //                   [edi+16] = ret
        .op(&[0x8B, 0x43, 0x04, 0x89, 0x47, 0x14]) // [edi+20] = base
        .op(&[0x8B, 0x43, 0x0C, 0x89, 0x47, 0x18]) // [edi+24] = flags
        // A 16-bit request and entry 11: -EINVAL.
        .op_imm(&[0xBB], desc_addr + 0x10);
    i386_set_thread_area(&mut a);
    a.op(&[0x89, 0x47, 0x1C]).op_imm(&[0xBB], desc_addr + 0x20);
    i386_set_thread_area(&mut a);
    a.op(&[0x89, 0x47, 0x20]).op_imm(&[0xBB], desc_addr);
    // Allocate 13 and 14, then the full table answers -ESRCH.
    for (ret, entry) in [(0x24u8, Some(0x28u8)), (0x2C, Some(0x30)), (0x34, None)] {
        a.op_imm(&[0xC7, 0x03], u32::MAX); //         [ebx] = -1
        i386_set_thread_area(&mut a);
        a.op(&[0x89, 0x47, ret]);
        if let Some(entry) = entry {
            a.op(&[0x8B, 0x03, 0x89, 0x47, entry]);
        }
    }
    // Free 13 with LDT_empty; the next allocation takes it again.
    a.op_imm(&[0xBB], desc_addr + 0x30);
    i386_set_thread_area(&mut a);
    a.op(&[0x89, 0x47, 0x38])
        .op_imm(&[0xBB], desc_addr)
        .op_imm(&[0xC7, 0x03], u32::MAX);
    i386_set_thread_area(&mut a);
    a.op(&[0x8B, 0x03, 0x89, 0x47, 0x3C]);
    i386_exit(&mut a);

    let desc_a = user_desc(u32::MAX, base, 0xF_FFFF, TLS_FLAGS);
    let desc_16bit = user_desc(13, 0x1000, 1, 0);
    let desc_entry_11 = user_desc(11, base, 0xF_FFFF, TLS_FLAGS);
    let desc_empty = user_desc(13, 0, 0, EMPTY_FLAGS);
    let magic = TLS_MAGIC.to_le_bytes();
    let inputs = [
        (INPUT, desc_a.as_slice()),
        (INPUT + 0x10, desc_16bit.as_slice()),
        (INPUT + 0x20, desc_entry_11.as_slice()),
        (INPUT + 0x30, desc_empty.as_slice()),
        (0x200, magic.as_slice()),
    ];
    let mut programs = match build(&a.0, true, &inputs) {
        Ok(p) => [p],
        Err(why) => return TestResult::Fail(why),
    };
    if let Err(why) = run(&mut programs, false) {
        return TestResult::Fail(why);
    }
    let p = &programs[0];
    const EINVAL: u32 = (-22i32) as u32;
    const ESRCH: u32 = (-3i32) as u32;
    if p.u32_at(0) != 0 || p.u32_at(4) != 12 {
        return TestResult::Fail("set_thread_area(-1) did not hand out entry 12");
    }
    if p.u32_at(8) != TLS_MAGIC || p.u32_at(12) != 0x63 {
        return TestResult::Fail("%gs = 0x63 did not read the TLS descriptor's base");
    }
    if p.u32_at(16) != 0 || p.u32_at(20) != base || p.u32_at(24) != TLS_FLAGS {
        return TestResult::Fail("get_thread_area(12) did not report the slot");
    }
    if p.u32_at(28) != EINVAL || p.u32_at(32) != EINVAL {
        return TestResult::Fail("a 16-bit request or entry 11 was not -EINVAL");
    }
    if p.u32_at(36) != 0 || p.u32_at(40) != 13 || p.u32_at(44) != 0 || p.u32_at(48) != 14 {
        return TestResult::Fail("the next allocations did not hand out 13 and 14");
    }
    if p.u32_at(52) != ESRCH {
        return TestResult::Fail("a full TLS table did not answer -ESRCH");
    }
    if p.u32_at(56) != 0 || p.u32_at(60) != 13 {
        return TestResult::Fail("an LDT_empty request did not free its slot");
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/ia32-tls",
    smoke_ia32_set_thread_area_entry_12_and_gs_base
);

const OUTER_YIELDS: u32 = 200;
const INNER_READS: u32 = 20_000;

/// An i386 task that takes a TLS slot for a block at `DATA + tls_off`,
/// loads %gs with it, then reads `%gs:0` and %gs over and over, yielding
/// between bursts. [edi+8] = 1 when every read matched, 2 on the first
/// mismatch.
fn compat_tls_loop(tls_off: u32) -> Vec<u8> {
    let data = DATA_VADDR as u32;
    let mut a = Asm(Vec::new());
    a.op_imm(&[0xBF], data).op_imm(&[0xBB], data + INPUT as u32);
    i386_set_thread_area(&mut a);
    a.op(&[0x89, 0x07]) //                                 [edi] = ret
        .op(&[0x8B, 0x03, 0xC1, 0xE0, 0x03, 0x83, 0xC8, 0x03]) // eax = entry*8+3
        .op(&[0x8E, 0xE8]) //                              mov gs, ax
        .op(&[0x89, 0x47, 0x04]) //                        [edi+4] = selector
        .op_imm(&[0xBE], OUTER_YIELDS); //                 mov esi, N
    let outer = a.here();
    a.op_imm(&[0xB9], INNER_READS); //                     mov ecx, M
    let inner = a.here();
    a.op_imm(&[0x65, 0x8B, 0x05], 0) //                    mov eax, gs:[0]
        .op_imm(&[0x3B, 0x05], data + tls_off); //         cmp eax, [block]
    let bad1 = a.branch_fwd(JNE);
    a.op(&[0x31, 0xD2, 0x66, 0x8C, 0xEA]) //               mov dx, gs
        .op(&[0x3B, 0x57, 0x04]); //                       cmp edx, [edi+4]
    let bad2 = a.branch_fwd(JNE);
    a.op(&[0x49]).branch_back(JNE, inner); //              dec ecx; jnz
    a.op_imm(&[0xB8], 158).op(&[0xCD, 0x80]); //           sched_yield
    a.op(&[0x4E]).branch_back(JNE, outer); //              dec esi; jnz
    a.op_imm(&[0xC7, 0x47, 0x08], 1);
    let done = a.branch_fwd(JMP);
    a.land(bad1);
    a.land(bad2);
    a.op_imm(&[0xC7, 0x47, 0x08], 2).op(&[0x89, 0x4F, 0x0C]);
    a.land(done);
    i386_exit(&mut a);
    a.0
}

/// A 64-bit task with a GS base from `arch_prctl(ARCH_SET_GS)` that reads
/// `%gs:0`, GS and DS over and over, yielding between bursts. [rdi+8] = 1
/// when GS and DS stayed null and every read matched, 2 otherwise.
fn native_gs_loop() -> Vec<u8> {
    let data = DATA_VADDR as u32;
    let block = data + 0x200;
    let mut a = Asm(Vec::new());
    a.op_imm(&[0xB8], 158) //                              arch_prctl
        .op_imm(&[0xBF], 0x1001) //                        ARCH_SET_GS
        .op_imm(&[0xBE], block)
        .op(&[0x0F, 0x05])
        .op_imm(&[0xBF], data)
        .op(&[0x89, 0x07]) //                              [rdi] = ret
        .op_imm(&[0xBE], OUTER_YIELDS);
    let outer = a.here();
    a.op_imm(&[0xB9], INNER_READS);
    let inner = a.here();
    a.op_imm(&[0x65, 0x8B, 0x04, 0x25], 0) //              mov eax, gs:[0]
        .op_imm(&[0x3B, 0x04, 0x25], block); //            cmp eax, [block]
    let bad1 = a.branch_fwd(JNE);
    a.op(&[0x8C, 0xEA, 0x85, 0xD2]); //                    mov edx, gs; test
    let bad2 = a.branch_fwd(JNE);
    a.op(&[0x8C, 0xDA, 0x85, 0xD2]); //                    mov edx, ds; test
    let bad3 = a.branch_fwd(JNE);
    a.op(&[0xFF, 0xC9]).branch_back(JNE, inner); //        dec ecx; jnz
    a.op_imm(&[0xB8], 24).op(&[0x0F, 0x05]); //            sched_yield
    a.op(&[0xFF, 0xCE]).branch_back(JNE, outer); //        dec esi; jnz
    a.op_imm(&[0xC7, 0x47, 0x08], 1);
    let done = a.branch_fwd(JMP);
    a.land(bad1);
    a.land(bad2);
    a.land(bad3);
    a.op_imm(&[0xC7, 0x47, 0x08], 2)
        .op(&[0x89, 0x4F, 0x0C, 0x89, 0x57, 0x10]); //     [rdi+12] = ecx, [rdi+16] = edx
    a.land(done);
    a.op_imm(&[0xB8], 60)
        .op(&[0x31, 0xFF, 0x0F, 0x05, 0x0F, 0x0B]);
    a.0
}

/// Two i386 tasks hold slot 12 (both %gs = 0x63) with descriptors for
/// different blocks, and a 64-bit task keeps GS null with its own base,
/// all on one CPU under a fast timer: every switch, cooperative or
/// preemptive, must load the incoming task's descriptor, selectors and
/// base (Linux `load_TLS` + `load_seg_legacy`). A leaked descriptor reads
/// the other block (zero in this task's page); a leaked selector shows up
/// in the 64-bit task's GS or DS.
fn smoke_ia32_tls_kept_per_task_across_switches() -> TestResult {
    let data = DATA_VADDR as u32;
    let desc_at = |off: u32| user_desc(u32::MAX, data + off, 0xF_FFFF, TLS_FLAGS);
    let (desc_a, desc_b) = (desc_at(0x200), desc_at(0x300));
    let magic_a = 0xA1A1_0001u32.to_le_bytes();
    let magic_b = 0xB2B2_0002u32.to_le_bytes();
    let magic_c = 0xC3C3_0003u32.to_le_bytes();
    let built = (|| {
        Ok::<_, &'static str>([
            build(
                &compat_tls_loop(0x200),
                true,
                &[(INPUT, desc_a.as_slice()), (0x200, magic_a.as_slice())],
            )?,
            build(
                &compat_tls_loop(0x300),
                true,
                &[(INPUT, desc_b.as_slice()), (0x300, magic_b.as_slice())],
            )?,
            build(&native_gs_loop(), false, &[(0x200, magic_c.as_slice())])?,
        ])
    })();
    let mut programs = match built {
        Ok(p) => p,
        Err(why) => return TestResult::Fail(why),
    };
    if let Err(why) = run(&mut programs, true) {
        return TestResult::Fail(why);
    }
    for p in &programs[..2] {
        if p.u32_at(0) != 0 || p.u32_at(4) != 0x63 {
            return TestResult::Fail("an i386 task did not get slot 12 (%gs 0x63)");
        }
        if p.u32_at(8) != 1 {
            return TestResult::Fail("an i386 task saw another task's TLS across a switch");
        }
    }
    let native = &programs[2];
    if native.u32_at(0) != 0 {
        return TestResult::Fail("arch_prctl(ARCH_SET_GS) failed");
    }
    if native.u32_at(8) != 1 {
        return TestResult::Fail("a 64-bit task saw an i386 task's GS/DS or lost its GS base");
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/ia32-tls",
    smoke_ia32_tls_kept_per_task_across_switches
);

/// A TLS selector in SS must not take the kernel down when the task then
/// empties that slot: the `int 0x80` return `iretq` reloads SS from the GDT,
/// and a fault there would be at CPL 0. (Linux turns it into a SIGSEGV for
/// the task through `fixup_bad_iret`; NARF hands the task `__USER_DS`.)
/// The task loads SS = 0x63 over a flat slot-12 segment, empties slot 12
/// with `set_thread_area`, and must come back to user mode and exit.
fn smoke_ia32_emptied_ss_slot_does_not_fault_iret() -> TestResult {
    let data = DATA_VADDR as u32;
    let mut a = Asm(Vec::new());
    a.op_imm(&[0xBF], data).op_imm(&[0xBB], data + INPUT as u32);
    i386_set_thread_area(&mut a);
    a.op(&[0x89, 0x07]) //                                 [edi] = ret
        .op_imm(&[0xB8], 0x63)
        .op(&[0x8E, 0xD0]) //                              mov ss, ax
        .op_imm(&[0xBB], data + INPUT as u32 + 0x10);
    i386_set_thread_area(&mut a); //                       empty slot 12
    a.op(&[0x89, 0x47, 0x04]) //                           [edi+4] = ret
        .op(&[0x31, 0xC0, 0x66, 0x8C, 0xD0]) //            mov ax, ss
        .op(&[0x89, 0x47, 0x08]) //                        [edi+8]
        .op_imm(&[0xC7, 0x47, 0x0C], 1); //                [edi+12] = 1: back in user
    i386_exit(&mut a);
    // Slot 12 first: flat (base 0, 4 GiB) writable data, usable as a stack.
    let flat = user_desc(u32::MAX, 0, 0xF_FFFF, TLS_FLAGS);
    let empty = user_desc(12, 0, 0, EMPTY_FLAGS);
    let inputs = [(INPUT, flat.as_slice()), (INPUT + 0x10, empty.as_slice())];
    let mut programs = match build(&a.0, true, &inputs) {
        Ok(p) => [p],
        Err(why) => return TestResult::Fail(why),
    };
    if let Err(why) = run(&mut programs, false) {
        return TestResult::Fail(why);
    }
    let p = &programs[0];
    if p.u32_at(0) != 0 || p.u32_at(4) != 0 {
        return TestResult::Fail("set_thread_area failed");
    }
    if p.u32_at(12) != 1 {
        return TestResult::Fail("the task did not return to user mode after emptying its SS slot");
    }
    if p.u32_at(8) != 0x2B {
        return TestResult::Fail("the emptied SS selector was not replaced by __USER_DS");
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/ia32-tls-ss",
    smoke_ia32_emptied_ss_slot_does_not_fault_iret
);

// ── fork / vfork / clone from a compatibility-mode task ─────────────

/// i386 system call `nr` (eax), arguments already in ebx..ebp.
fn i386_call(a: &mut Asm, nr: u32) {
    a.op_imm(&[0xB8], nr).op(&[0xCD, 0x80]);
}

const CLONE_SETTLS: u32 = 0x0008_0000;
const SIGCHLD: u32 = 17;

/// The child half of the fork tests (edi = DATA): CS, GS and `%gs:[0]`
/// stored at DATA+0x80.. and written to the pipe's write end (fds[1] at
/// DATA+8), then `exit_group(0)`. The bytes mean the same as 64-bit code (no
/// 0x40-0x4F, no push/pop, no absolute-disp32 ModRM), so a child resumed in
/// the wrong mode reports that instead of hanging the run.
fn child_report(a: &mut Asm) {
    a.op(&[0x31, 0xC0, 0x66, 0x8C, 0xC8]) //            mov ax, cs
        .op_imm(&[0x89, 0x87], 0x80) //                 [edi+0x80]
        .op(&[0x31, 0xC0, 0x66, 0x8C, 0xE8]) //         mov ax, gs
        .op_imm(&[0x89, 0x87], 0x84) //                 [edi+0x84]
        .op(&[0x31, 0xDB, 0x65, 0x8B, 0x03]) //         mov eax, gs:[ebx = 0]
        .op_imm(&[0x89, 0x87], 0x88) //                 [edi+0x88]
        .op(&[0x8B, 0x5F, 0x08]) //                     ebx = fds[1]
        .op_imm(&[0x8D, 0x8F], 0x80) //                 ecx = DATA+0x80
        .op_imm(&[0xBA], 12); //                        edx = 12
    i386_call(a, 4); //                                 write
    a.op_imm(&[0xB8], 252)
        .op(&[0x31, 0xDB, 0xCD, 0x80, 0x0F, 0x0B]); //  exit_group(0)
}

/// The parent half (eax = the child's pid): close its write end, read the
/// child's 12-byte report into DATA+0x40, reap the child with `waitpid`
/// (i386 7) into DATA+0x20, and read its own `%gs:[0]` into DATA+0x24.
fn parent_collect(a: &mut Asm) {
    a.op(&[0x89, 0x47, 0x10]) //                        [edi+0x10] = pid
        .op(&[0x8B, 0x5F, 0x08]); //                    ebx = fds[1]
    i386_call(a, 6); //                                 close
    a.op(&[0x89, 0x47, 0x14])
        .op(&[0x8B, 0x5F, 0x04]) //                     ebx = fds[0]
        .op(&[0x8D, 0x4F, 0x40]) //                     ecx = DATA+0x40
        .op_imm(&[0xBA], 12);
    i386_call(a, 3); //                                 read
    a.op(&[0x89, 0x47, 0x18])
        .op(&[0x8B, 0x5F, 0x10]) //                     ebx = pid
        .op(&[0x8D, 0x4F, 0x20]) //                     ecx = &status
        .op(&[0x31, 0xD2]); //                          edx = 0
    i386_call(a, 7); //                                 waitpid
    a.op(&[0x89, 0x47, 0x1C])
        .op(&[0x31, 0xDB, 0x65, 0x8B, 0x03]) //         mov eax, gs:[ebx = 0]
        .op(&[0x89, 0x47, 0x24]);
    i386_exit(a);
}

/// Take TLS slot 12 for the block at DATA+0x200 (the `user_desc` at INPUT),
/// load %gs with it and open a pipe into DATA+4.
fn tls_and_pipe(a: &mut Asm) {
    let data = DATA_VADDR as u32;
    a.op_imm(&[0xBF], data).op_imm(&[0xBB], data + INPUT as u32);
    i386_set_thread_area(a);
    a.op(&[0x89, 0x47, 0x0C]) //                        [edi+12] = ret
        .op_imm(&[0xB8], 0x63)
        .op(&[0x8E, 0xE8]) //                           mov gs, ax
        .op(&[0x8D, 0x5F, 0x04]); //                    ebx = &fds
    i386_call(a, 42); //                                pipe
    a.op(&[0x89, 0x07]); //                             [edi] = ret
}

const MAGIC_PARENT: u32 = 0xA5A5_0012;
const MAGIC_CHILD: u32 = 0x5A5A_0013;

/// Check what `parent_collect` gathered: the child reported (CS, GS,
/// `%gs:[0]`) = (0x23, 0x63, `child_tls`), exited 0 and was reaped, and the
/// parent still reads its own block.
fn check_child_report(p: &Program, child_tls: u32) -> Result<(), &'static str> {
    if p.u32_at(0x0C) != 0 || p.u32_at(0) != 0 {
        return Err("set_thread_area or pipe failed in the parent");
    }
    let pid = p.u32_at(0x10);
    if pid as i32 <= 0 || u64::from(pid) == p.pid {
        return Err("the i386 fork/vfork/clone did not return a child pid");
    }
    if p.u32_at(0x18) != 12 {
        return Err("the parent did not receive the child's 12-byte report");
    }
    if p.u32_at(0x40) != 0x23 {
        return Err("the child did not resume in compatibility mode (CS 0x23)");
    }
    if p.u32_at(0x44) != 0x63 {
        return Err("the child did not keep the parent's %gs selector");
    }
    if p.u32_at(0x48) != child_tls {
        return Err("the child's %gs did not read the TLS block it should have");
    }
    if p.u32_at(0x1C) != pid || p.u32_at(0x20) != 0 {
        return Err("i386 waitpid did not reap the child's exit(0)");
    }
    if p.u32_at(0x24) != MAGIC_PARENT {
        return Err("the parent's %gs changed under the child's TLS");
    }
    Ok(())
}

/// fork (i386 2) and vfork (i386 190) from a compatibility-mode task: the
/// child returns to user mode in the parent's mode with the parent's TLS
/// descriptors and selectors (Linux `copy_thread`: `dup_task_struct` copied
/// `tls_array`, `save_fsgs` the selectors), so it runs i386 code with %gs
/// still reading the parent's block. It reports CS, GS and `%gs:[0]` through
/// a pipe; the parent reaps it with i386 `waitpid` (7).
fn smoke_ia32_fork_child_resumes_compat_with_parent_tls() -> TestResult {
    let data = DATA_VADDR as u32;
    let desc = user_desc(u32::MAX, data + 0x200, 0xF_FFFF, TLS_FLAGS);
    let magic = MAGIC_PARENT.to_le_bytes();
    for nr in [2u32, 190] {
        let mut a = Asm(Vec::new());
        tls_and_pipe(&mut a);
        i386_call(&mut a, nr);
        a.op(&[0x85, 0xC0]); //                         test eax, eax
        let parent = a.branch_fwd(JNE);
        child_report(&mut a);
        a.land(parent);
        parent_collect(&mut a);
        let inputs = [(INPUT, desc.as_slice()), (0x200, magic.as_slice())];
        let mut programs = match build(&a.0, true, &inputs) {
            Ok(p) => [p],
            Err(why) => return TestResult::Fail(why),
        };
        if let Err(why) = run(&mut programs, false) {
            return TestResult::Fail(why);
        }
        if let Err(why) = check_child_report(&programs[0], MAGIC_PARENT) {
            return TestResult::Fail(why);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/ia32-fork",
    smoke_ia32_fork_child_resumes_compat_with_parent_tls
);

/// i386 `clone(flags, newsp, parent_tid, tls, child_tid)` (120,
/// `compat_sys_ia32_clone`: CONFIG_CLONE_BACKWARDS, TLS in esi before the
/// child tid in edi) with CLONE_SETTLS: `tls` is a `struct user_desc` and
/// the child gets it in its own TLS slot (Linux `set_new_tls` →
/// `do_set_thread_area(p, -1, utls, 0)`), so the inherited %gs 0x63 reads
/// the new block in the child while the parent keeps its own.
fn smoke_ia32_clone_settls_gives_the_child_its_own_gs_base() -> TestResult {
    let data = DATA_VADDR as u32;
    let mut a = Asm(Vec::new());
    tls_and_pipe(&mut a);
    a.op_imm(&[0xBB], CLONE_SETTLS | SIGCHLD) //        ebx = flags
        .op(&[0x31, 0xC9]) //                           ecx = newsp = 0
        .op(&[0x31, 0xD2]) //                           edx = parent_tid = 0
        .op_imm(&[0xBE], data + INPUT as u32 + 0x10) // esi = tls = &desc_b
        .op(&[0x31, 0xFF]); //                          edi = child_tid = 0
    i386_call(&mut a, 120);
    a.op_imm(&[0xBF], data).op(&[0x85, 0xC0]); //       edi = DATA; test eax
    let parent = a.branch_fwd(JNE);
    child_report(&mut a);
    a.land(parent);
    parent_collect(&mut a);
    let desc_a = user_desc(u32::MAX, data + 0x200, 0xF_FFFF, TLS_FLAGS);
    let desc_b = user_desc(12, data + 0x300, 0xF_FFFF, TLS_FLAGS);
    let magic_a = MAGIC_PARENT.to_le_bytes();
    let magic_b = MAGIC_CHILD.to_le_bytes();
    let inputs = [
        (INPUT, desc_a.as_slice()),
        (INPUT + 0x10, desc_b.as_slice()),
        (0x200, magic_a.as_slice()),
        (0x300, magic_b.as_slice()),
    ];
    let mut programs = match build(&a.0, true, &inputs) {
        Ok(p) => [p],
        Err(why) => return TestResult::Fail(why),
    };
    if let Err(why) = run(&mut programs, false) {
        return TestResult::Fail(why);
    }
    match check_child_report(&programs[0], MAGIC_CHILD) {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "verification/ia32-fork",
    smoke_ia32_clone_settls_gives_the_child_its_own_gs_base
);

// ── i386 calls that park, and the signals that end a park ───────────

/// An i386 `read` (3) on an empty pipe parks the task (RIP rewound onto
/// `int 0x80` for re-execution) until a forked i386 child, after yielding a
/// few times, writes four bytes; the re-issued read returns them. The read
/// runs under the `/proc/<pid>/io` accounting context, which must hand the
/// park the real register file and RIP.
fn smoke_ia32_read_parks_on_an_empty_pipe_until_the_child_writes() -> TestResult {
    let data = DATA_VADDR as u32;
    let mut a = Asm(Vec::new());
    a.op_imm(&[0xBF], data).op(&[0x8D, 0x5F, 0x04]); // edi = DATA; ebx = &fds
    i386_call(&mut a, 42); //                           pipe
    a.op(&[0x89, 0x07]);
    i386_call(&mut a, 2); //                            fork
    a.op(&[0x85, 0xC0]);
    let parent = a.branch_fwd(JNE);
    // Child: yield a few times so the parent is parked, then write.
    a.op_imm(&[0xB9], 8); //                            ecx = 8
    let again = a.here();
    i386_call(&mut a, 158); //                          sched_yield
    a.op(&[0x83, 0xE9, 0x01]).branch_back(JNE, again); // sub ecx, 1; jnz
    a.op(&[0x8B, 0x5F, 0x08]) //                        ebx = fds[1]
        .op_imm(&[0x8D, 0x8F], 0x180) //                ecx = DATA+0x180
        .op_imm(&[0xBA], 4);
    i386_call(&mut a, 4); //                            write
    a.op_imm(&[0xB8], 252)
        .op(&[0x31, 0xDB, 0xCD, 0x80, 0x0F, 0x0B]);
    a.land(parent);
    a.op(&[0x89, 0x47, 0x10]) //                        [edi+0x10] = pid
        .op(&[0x8B, 0x5F, 0x04]) //                     ebx = fds[0]
        .op(&[0x8D, 0x4F, 0x40]) //                     ecx = DATA+0x40
        .op_imm(&[0xBA], 4);
    i386_call(&mut a, 3); //                            read: parks
    a.op(&[0x89, 0x47, 0x18])
        .op(&[0x8B, 0x5F, 0x10]) //                     ebx = pid
        .op(&[0x8D, 0x4F, 0x20]) //                     ecx = &status
        .op(&[0x31, 0xD2]);
    i386_call(&mut a, 7); //                            waitpid
    a.op(&[0x89, 0x47, 0x1C]);
    i386_exit(&mut a);
    let payload = *b"ia32";
    let mut programs = match build(&a.0, true, &[(0x180, payload.as_slice())]) {
        Ok(p) => [p],
        Err(why) => return TestResult::Fail(why),
    };
    if let Err(why) = run(&mut programs, false) {
        return TestResult::Fail(why);
    }
    let p = &programs[0];
    if p.u32_at(0) != 0 || p.u32_at(0x10) as i32 <= 0 {
        return TestResult::Fail("i386 pipe or fork failed");
    }
    if p.u32_at(0x18) != 4 || p.bytes_at::<4>(0x40) != payload {
        return TestResult::Fail("the parked i386 read did not return the child's bytes");
    }
    if p.u32_at(0x1C) != p.u32_at(0x10) || p.u32_at(0x20) != 0 {
        return TestResult::Fail("i386 waitpid did not reap the writer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/ia32-park",
    smoke_ia32_read_parks_on_an_empty_pipe_until_the_child_writes
);

const SA_RESTORER: u64 = 0x0400_0000;
const SA_RESTART: u64 = 0x1000_0000;
const SIGUSR1: u32 = 10;

/// A 64-bit task that installs a SIGUSR1 handler (native `rt_sigaction`,
/// `sa_flags` = `flags`), opens a pipe and parks in an `int 0x80` read on
/// it. The handler writes "sig!" into the pipe and counts itself at
/// DATA+0x20; the read's rax lands at DATA+0x18. rbp holds DATA throughout
/// (the i386 call uses ebx, ecx, edx). Returns the code and the
/// `struct kernel_sigaction` to plant at INPUT.
fn signalled_int80_reader(flags: u64) -> (Vec<u8>, [u8; 32]) {
    let data = DATA_VADDR as u32;
    let mut a = Asm(Vec::new());
    a.op_imm(&[0xBD], data) //                          mov ebp, DATA
        .op_imm(&[0xB8], 13) //                         rt_sigaction
        .op_imm(&[0xBF], SIGUSR1)
        .op_imm(&[0x48, 0x8D, 0xB5], INPUT as u32) //   lea rsi, [rbp+INPUT]
        .op(&[0x31, 0xD2]) //                           oact = NULL
        .op_imm(&[0x41, 0xBA], 8) //                    mov r10d, 8
        .op(&[0x0F, 0x05, 0x89, 0x45, 0x00]) //         syscall; [rbp] = eax
        .op_imm(&[0xB8], 293) //                        pipe2
        .op(&[0x48, 0x8D, 0x7D, 0x10]) //               lea rdi, [rbp+0x10]
        .op(&[0x31, 0xF6, 0x0F, 0x05, 0x89, 0x45, 0x08]) // flags 0; [rbp+8]
        .op_imm(&[0xB8], 3) //                          i386 read
        .op(&[0x8B, 0x5D, 0x10]) //                     ebx = fds[0]
        .op(&[0x8D, 0x4D, 0x40]) //                     ecx = DATA+0x40
        .op_imm(&[0xBA], 4)
        .op(&[0xCD, 0x80]) //                           int 0x80: parks
        .op(&[0x48, 0x89, 0x45, 0x18]) //               [rbp+0x18] = rax
        .op_imm(&[0xB8], 60)
        .op(&[0x31, 0xFF, 0x0F, 0x05, 0x0F, 0x0B]); //  exit(0)
    let handler = a.here() as u64;
    a.op_imm(&[0xBD], data)
        .op_imm(&[0xB8], 1) //                          write
        .op(&[0x8B, 0x7D, 0x14]) //                     edi = fds[1]
        .op_imm(&[0x48, 0x8D, 0xB5], 0x180) //          lea rsi, [rbp+0x180]
        .op_imm(&[0xBA], 4)
        .op(&[0x0F, 0x05])
        .op(&[0x83, 0x45, 0x20, 0x01, 0xC3]); //        add [rbp+0x20], 1; ret
    let restorer = a.here() as u64;
    a.op_imm(&[0xB8], 15).op(&[0x0F, 0x05, 0x0F, 0x0B]); // rt_sigreturn
    let mut act = [0u8; 32];
    act[0..8].copy_from_slice(&(CODE_VADDR + handler).to_le_bytes());
    act[8..16].copy_from_slice(&(SA_RESTORER | flags).to_le_bytes());
    act[16..24].copy_from_slice(&(CODE_VADDR + restorer).to_le_bytes());
    (a.0, act)
}

/// A 64-bit task that yields long enough for the readers to park, then
/// sends SIGUSR1 to the two pids planted at INPUT and INPUT+4.
fn signaller() -> Vec<u8> {
    let data = DATA_VADDR as u32;
    let mut a = Asm(Vec::new());
    a.op_imm(&[0xBD], data).op_imm(&[0x41, 0xBC], 64); // ebp = DATA; r12d = 64
    let again = a.here();
    a.op_imm(&[0xB8], 24).op(&[0x0F, 0x05]); //         sched_yield
    a.op(&[0x41, 0x83, 0xEC, 0x01]).branch_back(JNE, again); // sub r12d, 1
    for (pid_at, ret_at) in [(INPUT as u32, 0u8), (INPUT as u32 + 4, 4)] {
        a.op_imm(&[0xB8], 62) //                        kill
            .op_imm(&[0x8B, 0xBD], pid_at) //           edi = pid
            .op_imm(&[0xBE], SIGUSR1)
            .op(&[0x0F, 0x05, 0x89, 0x45, ret_at]);
    }
    a.op_imm(&[0xB8], 60)
        .op(&[0x31, 0xFF, 0x0F, 0x05, 0x0F, 0x0B]);
    a.0
}

/// A caught signal ends an `int 0x80` read parked on an empty pipe the way
/// Linux's `handle_signal` ends `-ERESTARTSYS`: with SA_RESTART the read is
/// re-issued after the handler (eax back to the i386 number, RIP on
/// `int 0x80`) and returns the bytes the handler wrote; without it the read
/// completes as -EINTR. 64-bit tasks make the i386 call, so the handler
/// runs on the 64-bit frame its native `rt_sigaction` asked for, as on
/// Linux (the frame follows the sigaction's ABI, not the interrupted call's).
fn smoke_ia32_int80_read_interrupted_by_a_signal_restarts_or_is_eintr() -> TestResult {
    let (restart_code, restart_act) = signalled_int80_reader(SA_RESTART);
    let (eintr_code, eintr_act) = signalled_int80_reader(0);
    let message = *b"sig!";
    let built = (|| {
        let restart = build(
            &restart_code,
            false,
            &[(INPUT, restart_act.as_slice()), (0x180, message.as_slice())],
        )?;
        let eintr = build(
            &eintr_code,
            false,
            &[(INPUT, eintr_act.as_slice()), (0x180, message.as_slice())],
        )?;
        let pid_of = |p: &Program| {
            p.process
                .as_ref()
                .map(|process| process.pid.raw() as u32)
                .ok_or("program already run")
        };
        let mut pids = [0u8; 8];
        pids[0..4].copy_from_slice(&pid_of(&restart)?.to_le_bytes());
        pids[4..8].copy_from_slice(&pid_of(&eintr)?.to_le_bytes());
        let signaller = build(&signaller(), false, &[(INPUT, pids.as_slice())])?;
        Ok::<_, &'static str>([restart, eintr, signaller])
    })();
    let mut programs = match built {
        Ok(p) => p,
        Err(why) => return TestResult::Fail(why),
    };
    if let Err(why) = run(&mut programs, false) {
        return TestResult::Fail(why);
    }
    let [restart, eintr, sender] = &programs;
    if sender.u32_at(0) != 0 || sender.u32_at(4) != 0 {
        return TestResult::Fail("kill(SIGUSR1) to a reader failed");
    }
    for p in [restart, eintr] {
        if p.u32_at(0) != 0 || p.u32_at(8) != 0 {
            return TestResult::Fail("a reader's rt_sigaction or pipe2 failed");
        }
        if p.u32_at(0x20) != 1 {
            return TestResult::Fail("the SIGUSR1 handler did not run exactly once");
        }
    }
    if restart.u64_at(0x18) != 4 || restart.bytes_at::<4>(0x40) != message {
        return TestResult::Fail("an SA_RESTART handler did not restart the i386 read");
    }
    if eintr.u64_at(0x18) != (-4i64) as u64 {
        return TestResult::Fail(
            "a handler without SA_RESTART did not end the i386 read with -EINTR",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/ia32-park",
    smoke_ia32_int80_read_interrupted_by_a_signal_restarts_or_is_eintr
);
