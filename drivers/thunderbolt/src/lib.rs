//! Thunderbolt / USB4 host controller (NHI) driver.
//!
//! Modern Intel client platforms (Tiger Lake onward) ship a USB4 / TB
//! host controller — Intel "Maple Ridge" (TGL discrete), "Goshen Ridge"
//! (ADL discrete + on-die), "Barlow Ridge" (MTL / LNL) — that presents
//! on PCIe as the *NHI* (Native Host Interface). The NHI is the host-
//! side mailbox surface: BAR0 is a register block that talks to a
//! Connection Manager (CM) running firmware on the controller.
//!
//! Stage breakdown:
//! - **Stage-0** (landed): PCI match table + BAR0 mapping + identity
//!   register read; probe announce line.
//! - **Stage-1** (this commit): SW-CM control-packet encoding
//!   (`cm.rs`), adapter type decode (`adapter.rs`), switch
//!   enumeration + topology BFS walk (`switch.rs`). The walk is
//!   pure-logic + closure-driven so it can be unit-tested without
//!   talking to an NHI. The Stage::Late initcall logs a topology
//!   summary on probed controllers and skips cleanly otherwise.
//! - **Stage-2+**: ring-0 mailbox bring-up, PCIe / DP / USB3 tunnel
//!   setup, security levels, IOMMU / DMA-remap, CL0s / CL1 / CL2
//!   power-state management.
//!
//! Spec / reference:
//! - Linux `drivers/thunderbolt/nhi.c` — the PCI match table
//!   (`nhi_ids[]`) we mirror.
//! - Linux `drivers/thunderbolt/{tb,switch,ctl}.c` — the SW-CM
//!   topology walk we adapt.
//! - Linux `drivers/thunderbolt/tb_msgs.h` — control-packet header /
//!   address layout encoded in `cm.rs`.
//! - Linux `drivers/thunderbolt/tb_regs.h` — `enum tb_port_type`
//!   (adapter decode in `adapter.rs`) + `struct tb_regs_switch_header`
//!   (the Stage-1 switch fields).
//! - USB4 1.0 spec from USB-IF (public) §3 (adapter layer), §6 (host
//!   interface), §"Topology", §"Routing".

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod adapter;
pub mod cm;
pub mod nhi;
pub mod switch;

#[cfg(target_arch = "x86_64")]
mod tests;

/// Stage initcalls for this driver crate.
///
/// - `Stage::Device` (`intel-thunderbolt`): registers the PCI match
///   table. `probe_all_pci` later in the same stage binds drivers to
///   discovered NHI controllers.
/// - `Stage::Late` (`thunderbolt-topology`): runs after the bus has
///   probed all PCI devices. If an NHI was bound at `Stage::Device`,
///   this stage performs the Stage-1 topology walk and emits the
///   summary line; otherwise it returns `NotPresent` cleanly.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "intel-thunderbolt", || {
        nhi::register_pci_driver_thunderbolt();
        InitResult::Ok
    });
    // Stage::Late runs after `pci-probe-all` in Stage::Device — by
    // the time this fires `nhi::instance_count()` reflects whether
    // a controller was bound. Returning NotPresent on systems
    // without a TB controller keeps the stage trace clean and
    // avoids spawning a forever-sleeping topology task.
    narf_init::register(Stage::Late, "thunderbolt-topology", || {
        if nhi::instance_count() == 0 {
            return InitResult::NotPresent;
        }
        // Stage-1 topology walk is synchronous and bounded — there's
        // no actual ring-0 mailbox yet, so this is a no-op stub that
        // logs a single "no CM mailbox yet" line per controller.
        // Stage-2 turns this into a real walk; the wiring through
        // `switch::walk_topology` is already in place.
        emit_stage1_summary();
        InitResult::Ok
    });
}

/// Stage-1 announce. Logs one line per discovered NHI:
///   `thunderbolt: domain $i, awaiting Stage-2 mailbox bring-up (NHI vN, $h hops)`
///
/// The actual `switch::walk_topology` call is fully implemented but
/// needs Stage-2's NHI ring-0 mailbox to drive the probe closures —
/// invoking it with an unimplemented probe would just panic. Stage-1
/// proves the walk logic via the in-tree smokes; the boot-time line
/// here is a placeholder so the user can confirm Stage-1 fired.
fn emit_stage1_summary() {
    use core::fmt::Write as _;
    // We only know there's been *some* number of probes — Stage-0
    // doesn't yet vend a typed handle list. The single line below
    // refers to "domain 0" because that's the only domain Stage-0
    // surfaces; Stage-2's `ControllerRegistry` will iterate
    // domains.
    let n = nhi::instance_count();
    let ver = nhi::last_nhi_version();
    let hops = nhi::last_hop_count();
    let _ = writeln!(
        narf_console::Writer,
        "thunderbolt: domain 0 ({} controller{}, NHI v{:#04x}, {} hops) — Stage-1 topology walker ready, awaiting Stage-2 mailbox",
        n,
        if n == 1 { "" } else { "s" },
        ver,
        hops,
    );
}
