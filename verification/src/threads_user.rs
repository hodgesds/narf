//! System-wide task admission end to end (`verification/threads-max`):
//! Linux `kernel/fork.c` semantics checked with real user threads.
//!
//! Linux admits a new task while `nr_threads < max_threads`, where
//! `max_threads` is sized from RAM at boot (`set_max_threads`) and is the
//! `kernel.threads-max` sysctl. No fixed task count is part of that
//! contract, so a desktop with more than a thousand threads must still be
//! able to create more, and lowering the sysctl must stop a root thread
//! storm with -EAGAIN.

use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::ia32_user::{build, run, Asm, DATA_VADDR};

/// `CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD |
/// CLONE_SYSVSEM` — what glibc's `pthread_create` passes, minus the tid and
/// TLS flags this program has no use for.
const THREAD_FLAGS: u32 = 0x0005_0F00;
/// Data-page layout: the success count, the release word the threads wait
/// on, the first failing `clone` return and the sysctl `write` return.
const COUNT: u32 = 0;
const RELEASE: u32 = 8;
const ERRNO: u32 = 16;
const SYSCTL_WRITE: u32 = 24;
/// Inputs: the sysctl path, the value to set and the value to restore.
const PATH: u32 = 0x100;
const LIMIT: u32 = 0x140;
const RESTORE: u32 = 0x180;
const THREADS_MAX_PATH: &[u8] = b"/proc/sys/kernel/threads-max\0";
const EAGAIN: u64 = (-11i64) as u64;

/// Linux `set_max_threads` for this machine: `max_threads` such that the
/// tasks' kernel stacks take at most an eighth of RAM.
fn ram_max_threads() -> u64 {
    let stats = narf_memory::frame::stats();
    let pages = stats.total.saturating_sub(stats.reserved) as u64;
    let stack = narf_scheduler::stackful::DEFAULT_KERNEL_STACK_BYTES as u64;
    (pages * 4096 / (8 * stack)).clamp(20, 0x3fff_ffff)
}

fn at(off: u32) -> [u8; 4] {
    (DATA_VADDR as u32 + off).to_le_bytes()
}

/// `open(PATH, O_WRONLY)`, `write(fd, DATA + value, len)`, `close(fd)`,
/// storing the `write` return at `record` when given.
fn write_sysctl(a: &mut Asm, value: u32, len: u32, record: Option<u32>) {
    a.op(&[0xBF]).op(&at(PATH)); //                 mov edi, PATH
    a.op_imm(&[0xBE], 1).op(&[0x31, 0xD2]); //      O_WRONLY, mode 0
    a.op_imm(&[0xB8], 2).op(&[0x0F, 0x05]); //      open
    a.op(&[0x49, 0x89, 0xC6, 0x4C, 0x89, 0xF7]); // mov r14, rax; mov rdi, r14
    a.op(&[0xBE]).op(&at(value)).op_imm(&[0xBA], len); // buf, len
    a.op_imm(&[0xB8], 1).op(&[0x0F, 0x05]); //      write
    if let Some(off) = record {
        a.op(&[0x48, 0x89, 0x04, 0x25]).op(&at(off)); // mov [record], rax
    }
    a.op(&[0x4C, 0x89, 0xF7]); //                   mov rdi, r14
    a.op_imm(&[0xB8], 3).op(&[0x0F, 0x05]); //      close
}

/// x86_64: optionally set `kernel.threads-max` (`limit` = (len, restore
/// len)), try to create `threads` threads that park on a futex, count the
/// successes, record the first failure, put the sysctl back, then release
/// the threads and exit the group.
fn thread_storm(threads: u32, limit: Option<(u32, u32)>) -> Vec<u8> {
    let mut a = Asm(Vec::new());
    if let Some((len, _)) = limit {
        write_sysctl(&mut a, LIMIT, len, Some(SYSCTL_WRITE));
    }
    a.op(&[0x45, 0x31, 0xE4]); //                   xor r12d, r12d
    a.op_imm(&[0x41, 0xBD], threads); //            mov r13d, threads
    let top = a.here();
    a.op_imm(&[0xBF], THREAD_FLAGS); //             mov edi, flags
    a.op(&[0x31, 0xF6, 0x31, 0xD2]); //             xor esi, esi; xor edx, edx
    a.op(&[0x45, 0x31, 0xD2, 0x45, 0x31, 0xC0]); // xor r10d, r10d; xor r8d, r8d
    a.op_imm(&[0xB8], 56).op(&[0x0F, 0x05]); //     clone
    a.op(&[0x48, 0x85, 0xC0]); //                   test rax, rax
    a.op(&[0x0F, 0x84, 0, 0, 0, 0]); //             jz child (rel32, patched)
    let to_child = a.here();
    let to_fail = a.branch_fwd(0x78); //            js fail
    a.op(&[0x49, 0xFF, 0xC4, 0x41, 0xFF, 0xCD]); // inc r12; dec r13d
    a.branch_back(0x75, top); //                    jnz top
    let to_done = a.branch_fwd(0xEB); //            jmp done
    a.land(to_fail);
    a.op(&[0x48, 0x89, 0x04, 0x25]).op(&at(ERRNO)); // mov [ERRNO], rax
    a.land(to_done);
    a.op(&[0x4C, 0x89, 0x24, 0x25]).op(&at(COUNT)); // mov [COUNT], r12
    if let Some((_, restore_len)) = limit {
        write_sysctl(&mut a, RESTORE, restore_len, None);
    }
    a.op(&[0xC7, 0x04, 0x25])
        .op(&at(RELEASE))
        .op(&1u32.to_le_bytes()); // mov dword [RELEASE], 1
    a.op(&[0xBF]).op(&at(RELEASE)); //              mov edi, RELEASE
    a.op_imm(&[0xBE], 129).op_imm(&[0xBA], 0x7FFF_FFFF); // FUTEX_WAKE_PRIVATE, all
    a.op(&[0x45, 0x31, 0xD2]);
    a.op_imm(&[0xB8], 202).op(&[0x0F, 0x05]); //    futex
    a.op_imm(&[0xB8], 231)
        .op(&[0x31, 0xFF, 0x0F, 0x05, 0x0F, 0x0B]); // exit_group(0)
                                                    // child: wait until released, then exit. No stack use: the thread runs
                                                    // on its parent's stack pointer.
    let child = a.here();
    let rel = (child - to_child) as u32;
    a.0[to_child - 4..to_child].copy_from_slice(&rel.to_le_bytes());
    a.op(&[0xBF]).op(&at(RELEASE)); //              mov edi, RELEASE
    a.op_imm(&[0xBE], 128).op(&[0x31, 0xD2, 0x45, 0x31, 0xD2]); // FUTEX_WAIT_PRIVATE, 0
    a.op_imm(&[0xB8], 202).op(&[0x0F, 0x05]); //    futex
    a.op(&[0x83, 0x3C, 0x25]).op(&at(RELEASE)).op(&[0x00]); // cmp dword [RELEASE], 0
    a.branch_back(0x74, child); //                  je child
    a.op_imm(&[0xB8], 60)
        .op(&[0x31, 0xFF, 0x0F, 0x05, 0x0F, 0x0B]); // exit(0)
    a.0
}

/// More than 1024 threads exist at once when `threads-max` allows them:
/// every `clone` of an 1100-thread storm succeeds.
fn smoke_threads_beyond_1024_are_admitted() -> TestResult {
    const THREADS: u32 = 1100;
    let live = narf_scheduler::live_user_task_count() as u64;
    if ram_max_threads() < live + u64::from(THREADS) + 8 {
        return TestResult::Skip("guest RAM sizes threads-max below the storm");
    }
    let mut programs = match build(&thread_storm(THREADS, None), false, &[]) {
        Ok(p) => [p],
        Err(why) => return TestResult::Fail(why),
    };
    if let Err(why) = run(&mut programs, false) {
        return TestResult::Fail(why);
    }
    let p = &programs[0];
    if p.u64_at(COUNT as usize) == u64::from(THREADS) {
        return TestResult::Pass;
    }
    if p.u64_at(ERRNO as usize) == EAGAIN {
        return TestResult::Fail("a thread past the old 1024-task cap was refused with EAGAIN");
    }
    TestResult::Fail("the thread storm stopped short for a reason other than EAGAIN")
}
kernel_test_in!(
    "verification/threads-max",
    smoke_threads_beyond_1024_are_admitted
);

/// A root thread storm stops at `kernel.threads-max` with -EAGAIN — the
/// bound Linux keeps for exactly that case ("the check is only there to
/// stop root fork bombs"), which RLIMIT_NPROC does not apply to uid 0.
fn smoke_threads_max_stops_a_root_storm() -> TestResult {
    const ALLOWED: u64 = 3;
    // The program itself is one more live task; three threads fit after it.
    let limit = narf_scheduler::live_user_task_count() as u64 + 1 + ALLOWED;
    let limit_text = alloc::format!("{limit}");
    let restore_text = alloc::format!("{}", ram_max_threads());
    let code = thread_storm(
        10,
        Some((limit_text.len() as u32, restore_text.len() as u32)),
    );
    let inputs: [(usize, &[u8]); 3] = [
        (PATH as usize, THREADS_MAX_PATH),
        (LIMIT as usize, limit_text.as_bytes()),
        (RESTORE as usize, restore_text.as_bytes()),
    ];
    let mut programs = match build(&code, false, &inputs) {
        Ok(p) => [p],
        Err(why) => return TestResult::Fail(why),
    };
    if let Err(why) = run(&mut programs, false) {
        return TestResult::Fail(why);
    }
    let p = &programs[0];
    if p.u64_at(SYSCTL_WRITE as usize) != limit_text.len() as u64 {
        return TestResult::Fail("root could not write kernel.threads-max");
    }
    if p.u64_at(COUNT as usize) != ALLOWED {
        return TestResult::Fail("kernel.threads-max did not bound a root thread storm");
    }
    if p.u64_at(ERRNO as usize) != EAGAIN {
        return TestResult::Fail("a clone past kernel.threads-max was not -EAGAIN");
    }
    TestResult::Pass
}
kernel_test_in!(
    "verification/threads-max",
    smoke_threads_max_stops_a_root_storm
);
