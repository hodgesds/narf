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
    let ktest = std::env::var_os("CARGO_FEATURE_KERNEL_TEST").is_some();
    if smp && !ktest {
        println!("cargo:rustc-cfg=usmp_active");
    }
}
