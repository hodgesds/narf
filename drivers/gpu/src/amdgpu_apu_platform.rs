//! APU platform singleton — the #1698 attach (tracker #2467).
//!
//! The APU SMU telemetry owner (`amdgpu_smu_apu_telemetry`) existed
//! with a verified decode and a `gpu_temp_mc` arm, but nothing ever
//! attached it: no production caller of `with_coherent_buffer` /
//! `publish_dram_addr` / `monitor` / `begin_epoch` existed, and no
//! APU platform singleton retained the owner. On an APU-only machine
//! `gpu_temp_mc` therefore stayed `None`. This module is the attach:
//!
//!   1. resolve the bound APU controller's register window (`gpu.regs`)
//!      and MP1 mailbox base (`mp1_mailbox_base`, window 1 on APUs);
//!   2. ask the SMU itself which generation it is (`detect_version` —
//!      `GetDriverIfVersion` → `SmuVersion::from_driver_if`); only
//!      SMU 12 (Renoir, driver-IF 0x0F) and SMU 13.0.4 (Phoenix,
//!      driver-IF 0x07) resolve, so any other generation is refused
//!      by the hardware's own answer, not by a family table —
//!      Raphael's SMU answers 5 (`amdgpu_smu_raphael`), and no new
//!      version constant is invented here;
//!   3. allocate the owner with its own DMA-coherent buffer
//!      (`with_coherent_buffer`), publish the buffer's address once
//!      (`publish_dram_addr`), begin an epoch and spawn the 1 s
//!      monitor (`monitor(owner, mailbox, epoch)`).
//!
//! # The `'static` handle story
//!
//! The mailbox adapter used to borrow the register window
//! (`SmuRegsAdapter<'a>` in `amdgpu.rs`), so no `'static` mailbox
//! handle existed on the APU path. The attach solves it by owning
//! the handle instead of borrowing it: `MmioRegion` is `Copy`
//! (phys/virt/len — a handle, not an owned mapping), so the
//! singleton copies `gpu.regs` out of the controller into an owned
//! adapter (`SmuRegsOwned`, next to `SmuRegsAdapter`) that
//! implements `SmuMmio` over the same indexed MMIO helpers. The
//! copy duplicates no ownership: the BAR mapping lives for the
//! device lifetime under PCI authority, exactly as the borrowed
//! adapter's `&MmioRegion` did.
//!
//! Both the owner and the mailbox are then retained for the device
//! lifetime by leaking them into `&'static mut` refs handed to the
//! spawned monitor. The leak is deliberate, not a shortcut: the SMU
//! keeps DMAing into the published buffer after `publish_dram_addr`
//! (dropping the owner would free frames the SMU still writes),
//! and the monitor holds the mailbox for as long as it runs. This
//! matches the leaked-`Box` PerCpu precedent in the repo
//! (AGENTS.md). `stop()` (via the epoch) ends the monitor; the
//! buffer is never unpublished or freed.
//!
//! # Shared INDEX/DATA latch
//!
//! The mailbox speaks through the MM_INDEX/MM_DATA indexed port,
//! whose latch is shared with every other `mm_read`/`mm_write`
//! user (modeset, backlight, GFX index, CP firmware). The monitor
//! is the first continuously-running indexed-port user, so the
//! pair is now atomic by construction: `amdgpu_index` holds a leaf
//! lock for each whole INDEX/DATA sequence, and the monitor's
//! refreshes — like every other indexed access — go through it.
//! A corrupted handshake read can only fail a refresh (the last
//! sample is retained, the error published); it can never
//! fabricate a sample.
//!
//! # Scope and refusal
//!
//! The attach runs at the top of `amdgpu_platform::start()`, before
//! `prepare()` — telemetry is independent of display, so a chip
//! whose display path is refused (Renoir/Cezanne/Rembrandt today)
//! still gets a temperature. Every refusal is a console line, not
//! a boot failure: the display bring-up proceeds without telemetry.
//! The attach is boot-once (an `ATTACHED` attempt guard) and is not
//! retried: on APUs the SMU PMFW is BIOS-resident, so no PSP load
//! precedes the mailbox use, and a SMU that does not answer the
//! bounded handshake has nothing a retry would fix.
//!
//! Fixture-validated end to end (see `tests`); silicon-untested —
//! no APU test hardware is known on Daniel's side.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::amdgpu::SmuRegsOwned;
use crate::amdgpu_smu::{detect_version, SmuMmio};
use crate::amdgpu_smu_apu_telemetry::{
    begin_epoch, monitor, ApuError, ApuTelemetryOwner, MetricsBuffer,
};

/// Attach attempted (succeeded or refused): `start()` runs once, and
/// the flag makes a second call a no-op even if the first attempt
/// refused partway — a refused attach is not retried.
static ATTACHED: AtomicBool = AtomicBool::new(false);

/// Publish an owner's transfer buffer and begin its monitor epoch.
///
/// The testable seam of the attach: production passes the
/// DMA-coherent owner and the owned mailbox; the kernel-test
/// fixture passes a fake buffer and `MockSmu`, then polls the
/// monitor by hand. The caller spawns `monitor(owner, mailbox,
/// epoch)` and retains both for the device lifetime.
pub(crate) fn publish_and_begin_epoch<B: MetricsBuffer, M: SmuMmio>(
    owner: &mut ApuTelemetryOwner<B>,
    mailbox: &mut M,
) -> Result<u64, ApuError> {
    owner.publish_dram_addr(mailbox)?;
    Ok(begin_epoch())
}

/// Attach the APU SMU telemetry owner: allocate it, publish its
/// buffer, retain it `'static` and spawn its 1 s monitor. A refusal
/// at any step logs and returns; the display bring-up in
/// `amdgpu_platform::start` proceeds without telemetry.
pub(crate) fn attach() {
    use core::fmt::Write as _;
    if ATTACHED.swap(true, Ordering::AcqRel) {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: APU telemetry attach already attempted"
        );
        return;
    }
    let resolved = crate::amdgpu::with_controller(|gpu| {
        if !gpu.is_apu() {
            return None;
        }
        let mp1_base = gpu.mp1_mailbox_base()?;
        Some((gpu.regs, mp1_base))
    })
    .flatten();
    let Some((regs, mp1_base)) = resolved else {
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: APU telemetry not attached: no APU controller or MP1 mailbox window"
        );
        return;
    };
    let mut mailbox = SmuRegsOwned::new(regs);
    // Ask the SMU which generation it is: only driver-IF 0x0F
    // (SMU 12) and 0x07 (SMU 13.0.4) resolve. Anything else is
    // refused here — by the hardware's own answer, not by a table.
    let version = match detect_version(&mut mailbox, mp1_base) {
        Some(version) => version,
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: APU telemetry not attached: SMU driver-IF version unrecognised (not SMU 12 / 13.0.4)"
            );
            return;
        }
    };
    let mut owner = match ApuTelemetryOwner::with_coherent_buffer(version, mp1_base) {
        Ok(owner) => owner,
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: APU telemetry not attached: DMA buffer allocation failed ({error:?})"
            );
            return;
        }
    };
    let epoch = match publish_and_begin_epoch(&mut owner, &mut mailbox) {
        Ok(epoch) => epoch,
        Err(error) => {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: APU telemetry not attached: publish failed ({error:?})"
            );
            return;
        }
    };
    // Retain both for the device lifetime: the SMU keeps DMAing into
    // the published buffer, and the monitor holds the mailbox. The
    // leak is deliberate — see the module docs.
    let owner = Box::leak(Box::new(owner));
    let mailbox = Box::leak(Box::new(mailbox));
    narf_scheduler::spawn(monitor(owner, mailbox, epoch));
    let _ = writeln!(
        narf_console::Writer,
        "amdgpu: APU telemetry attached (SMU {version:?}, 1 s cadence)"
    );
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_apu_platform_tests.rs"]
mod tests;
