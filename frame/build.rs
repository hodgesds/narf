// Emits the `usmp_active` cfg = "the user-task-smp machinery is actually live".
//
// That means the `user-task-smp` feature is enabled AND this is not the
// `kernel-test` harness build. The kernel-test path runtime-disables user-task
// migration (`enable_user_task_smp` is only called under `cfg(not(kernel-test))`),
// so the per-AP user-mode setup (per-CPU GDT/TSS, bigger AP stacks, syscall-body
// `sti`, EFER.NXE / CR4 parity) is dead code there. Worse, compiling it shifts
// `.text`/`.bss` enough to tip the marginal-buddy `execve` smoke. Gating that
// code on `usmp_active` instead of the raw feature keeps the kernel-test binary
// byte-identical when the feature is flipped on by default.
fn main() {
    println!("cargo:rustc-check-cfg=cfg(usmp_active)");
    let smp = std::env::var_os("CARGO_FEATURE_USER_TASK_SMP").is_some();
    let _ktest = std::env::var_os("CARGO_FEATURE_KERNEL_TEST").is_some();
    // Emit `usmp_active` whenever `user-task-smp` is on — INCLUDING the
    // kernel-test build. This previously also required `!kernel-test`, on the
    // theory that the kernel-test APs "only ever run kernel tasks" and so
    // don't need the per-CPU GDT/TSS/rsp0/IST + larger AP stacks that
    // `gdt::init_ap`/`percpu::init_ap` install. That was wrong and corrupted
    // memory: the 16 kernel-test APs shared the BSP's TSS/IST on 4 KiB
    // stacks, and concurrent traps (notably the TLB-shootdown IPI under
    // mmap/munmap stress) clobbered each other's stacks — a layout-roulette
    // garbage-context resume (#GP / #UD rip=0x3) that surfaced as the parked
    // "sched-vtable-uaf". Per-CPU AP trap stacks are required for SMP
    // correctness regardless of whether user tasks run on the APs.
    if smp {
        println!("cargo:rustc-cfg=usmp_active");
    }
}
