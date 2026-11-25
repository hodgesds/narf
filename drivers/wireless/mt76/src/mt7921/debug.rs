//! Debug-message gate for routine driver traces (Linux `dev_dbg` with
//! dynamic debug).
//!
//! Linux mt76 reports routine steps (firmware download stages, scan and
//! station-record commands, power sequencing) through `dev_dbg`, which never
//! reaches the kernel log unless dynamic debug enables it for the module.
//! NARF's `KERN_DEBUG` lines are still stored, and `dmesg` shows them, so the
//! routine traces are emitted only when the command line carries
//! `mt76.dyndbg=+p` ([`narf_boot::KernelCmdline::dyndbg_print`]). Joins,
//! disconnects, chip resets and failures stay on `pr_info`/`pr_err` paths.

use core::sync::atomic::{AtomicU8, Ordering};

const UNKNOWN: u8 = 0;
const OFF: u8 = 1;
const ON: u8 = 2;

static STATE: AtomicU8 = AtomicU8::new(UNKNOWN);

/// Whether `mt76.dyndbg=+p` enabled the driver's debug traces. The command
/// line is fixed after boot, so the answer is computed once.
pub(crate) fn enabled() -> bool {
    match STATE.load(Ordering::Relaxed) {
        ON => true,
        OFF => false,
        _ => {
            // Built in: `mt76.dyndbg=+p` on the kernel command line. A module
            // has no command-line export; its `debug=1` parameter (applied
            // from `mt76.debug=1` or the load arguments) is the same switch.
            #[cfg(feature = "builtin")]
            let on = narf_boot::args().dyndbg_print("mt76");
            #[cfg(feature = "module")]
            let on = narf_module_rt::param::get("debug").is_ok_and(|value| value == "1");
            STATE.store(if on { ON } else { OFF }, Ordering::Relaxed);
            on
        }
    }
}
