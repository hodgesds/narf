//! Cross-crate fn-pointer hook installation, factored out of
//! `bare_main.rs` so the boot-time wiring is in one readable place
//! instead of scattered through 2.5 KLOC of staged setup.
//!
//! Every entry here is the same shape: a kernel-side crate
//! (filesystem, net, ...) needs a fn pointer from another crate
//! (userspace handlers, drivers, ...) wired in at boot. The
//! receiver crate stores the pointer in an `AtomicUsize` and
//! reads it on demand, so the dep direction stays one-way.

use core::fmt::Write as _;

use crate::console;

/// Wire every cross-crate fn-pointer hook the kernel needs at
/// boot time. Called once from `bare_main` after the per-task
/// initialisers (sigaction_init, signal_init, fd::init,
/// init_per_task_state) have run.
pub fn install_all_hooks() {
    install_console_signal_hook();
    install_proc_hooks();
    install_net_stack();
}

fn install_console_signal_hook() {
    // ^C / ^\ / ^Z input-byte handling into the console driver
    // so they deliver SIGINT/SIGQUIT/SIGTSTP to the foreground
    // task instead of bubbling up as ASCII bytes.
    narf_filesystem::install_console_signal_hook(
        narf_userspace::handlers::maybe_deliver_signal_for_input,
    );
}

fn install_proc_hooks() {
    // /proc per-pid hooks — exposes the live scheduler task list
    // and per-task metadata to /proc/[pid]/* and /proc/self/*.
    narf_filesystem::procfs::install_proc_hooks(
        narf_userspace::handlers::proc_current_pid,
        narf_userspace::handlers::proc_list_pids,
        narf_userspace::handlers::proc_task_info,
    );
}

fn install_net_stack() {
    // TCP-over-NIC: register the RX dispatch handler and spawn
    // an async RX-pump task. Drivers register their own (mac,
    // send_fn, drain_fn) at probe; the stack picks them up here.
    narf_net::tcp_stack::init();
    let _ = writeln!(
        console::Writer,
        "  net: tcp_stack init; iface count = {}",
        narf_net::iface::count()
    );
    narf_scheduler::spawn(async {
        // Background RX pump — drains the e1000 ring whenever the
        // executor visits this task. Kernel busy-wait paths (ARP
        // resolve, TCP handshake) call iface::drain_pump directly
        // so they don't depend on this loop.
        loop {
            while narf_drivers_net::e1000::rx_pump_step() {}
            narf_scheduler::yield_now().await;
        }
    });
}
