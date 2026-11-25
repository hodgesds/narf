//! `narf_scheduler` for the module: spawn on the module's executor, the
//! cooperative yield, and the synchronous bridges.

use core::future::Future;

/// Spawn a driver task on the module executor.
pub fn spawn<F: Future<Output = ()> + Send + 'static>(future: F) {
    super::spawn(future);
}

/// Yield to the executor once.
pub fn yield_now() -> narf_module_rt::time::YieldNow {
    narf_module_rt::time::yield_now()
}

/// `block_on`: drive one self-advancing future on the calling upcall (the
/// kernel bridge's contract — the future must not need another task).
pub fn block_on<F: Future>(future: F) -> F::Output {
    narf_module_rt::exec::block_on(future)
}

/// `responsive_spin_until`: sample `done` until it holds or `deadline`
/// passes, delaying 1 us between samples through `narf_udelay` (which keeps
/// the kernel's sleep pumps ticking). `true` when `done` held.
pub fn responsive_spin_until(
    mut done: impl FnMut() -> bool,
    deadline: super::narf_time::Deadline,
) -> bool {
    loop {
        if done() {
            return true;
        }
        if deadline.expired() {
            return done();
        }
        super::delay_ns(1_000);
    }
}
