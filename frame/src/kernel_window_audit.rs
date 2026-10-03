//! Early, printing registration of the kernel image window audit
//! ([`narf_memory::kernel_window_audit`]).
//!
//! Frame-crate cases run among the first of a full run; the late registration
//! sits in `memory/src/tests.rs`. This one lives here because it prints what
//! the walk examined — leaf counts, physical runs, the owned and free totals,
//! and the original single-frame probe — and `narf-memory` has no console.

use core::fmt::Write;

use narf_console::Writer;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_kernel_window_audit_reports_what_it_checked() -> TestResult {
    let a = match narf_memory::kernel_window_audit::check() {
        Ok(a) => a,
        Err(r) => return r,
    };
    let _ = writeln!(
        Writer,
        "    kernel_window: va [{:#x}, {:#x}) leaves 4K={} 2M={} 2M-slots-in-1G={} runs={}{} \
covered_frames={} image_frames={}/{} allocator_owned={} free={} \
probe={:#x} probe_covered={} probe_mapped={}",
        a.lo,
        a.hi,
        a.leaves_4k,
        a.leaves_2m,
        a.slots_in_1g,
        a.nruns,
        if a.overflow { "+overflow" } else { "" },
        a.covered,
        a.image_covered,
        a.image_frames,
        a.owned,
        a.free,
        a.probe_phys,
        a.probe_covered,
        a.probe_mapped,
    );
    for &(s, e) in a.runs() {
        let _ = writeln!(Writer, "    kernel_window: run pa [{:#x}, {:#x})", s, e);
    }
    if let Some((s, e, o, f)) = a.first_bad {
        let _ = writeln!(
            Writer,
            "    kernel_window: first bad run pa [{:#x}, {:#x}) allocator_owned={} free={}",
            s, e, o, f
        );
    }
    a.verdict()
}
kernel_test_in!(
    "memory/kernel_window",
    smoke_kernel_window_audit_reports_what_it_checked
);
