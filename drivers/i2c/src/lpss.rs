//! Intel PCH LPSS I2C controller — Synopsys DesignWare core, INT3xxx /
//! 80860Fxx / 808622xx ACPI HIDs.
//!
//! Stage-0 skeleton — discovery + MMIO mapping + IC_COMP_TYPE sanity
//! read + bus registration. No transactions yet; `transfer()` returns
//! `BadHardware` so that an Intel-laptop boot lands a registered-but-
//! disabled bus entry instead of a half-working driver that silently
//! NACKs every i2c-hid descriptor read. The Stage-1 work (programming
//! IC_CON / IC_*CNT, FIFO state machine, IRQ routing) is intentionally
//! deferred — the AMD FCH variant in `crate::amd_fch` already implements
//! the same DW core programming sequence and once Stage-0 lands on real
//! Intel silicon (touchpad enumerates, parent bus registered, child
//! `i2c-hid-bind` finds it) the Stage-1 work is a near-mechanical
//! port of the FCH `enable` + `transfer` paths against the LPSS
//! register window.
//!
//! What "LPSS" means here
//! ----------------------
//! Intel's "Low-Power Sub-System" wraps the same DesignWare APB I2C IP
//! AMD FCH uses, but adds:
//! - An LPSS-private register page above the DW core (typically at
//!   offset 0x200; holds PCH-specific clock-gating + reset bits).
//! - On modern silicon (Tiger Lake / Alder Lake / Raptor Lake), the
//!   controllers are presented through ACPI as MMIO platform devices
//!   ("LPSS-ACPI" mode) — the firmware leaves PCI config space hidden
//!   so the OS finds them only via DSDT. Earlier silicon
//!   (Baytrail / Cherrytrail / Apollo Lake) exposes them as PCI
//!   devices with a `_HID` that begins `80860F4x` / `808622xx`. The
//!   _HID list below covers both modes; the modern path is the
//!   priority since the bring-up target is the Tiger Lake / Alder
//!   Lake-class laptop the user wants i2c-hid touchpad on.
//!
//! Why no transactions
//! -------------------
//! Two reasons:
//! 1. Stage-0 scope: "skeleton + audit" per the task. Registering an
//!    `I2cBus` whose `transfer()` works requires programming the LPSS
//!    clock-gating + reset registers correctly before the DW core
//!    will respond — that's chip-specific and needs real hardware to
//!    validate. Doing it without a way to test invites a
//!    silently-NACKing driver that's worse than a no-op stub.
//! 2. Hard cutover principle: when Stage-1 lands the `transfer()`
//!    will be wired through the same DW programming sequence as
//!    `crate::amd_fch`, and the stub here is replaced. No
//!    backwards-compat shims; the stub goes away.
//!
//! Sources (all public, cited per the project's GPL-2.0-or-later
//! relicense):
//! - Linux `drivers/i2c/busses/i2c-designware-platdrv.c` — the
//!   `dw_i2c_acpi_match` table is the authoritative source for the
//!   HID list below.
//! - Linux `drivers/acpi/acpi_lpss.c` — LPSS register layout +
//!   ACPI-presented LPSS device wiring.
//! - Intel "Tiger Lake Platform Controller Hub EDS Vol 2", "Alder
//!   Lake-P PCH EDS" — LPSS register set + IC_COMP_TYPE confirmation.
//! - Synopsys "DW_apb_i2c Databook" — DW core register map (shared
//!   with `crate::amd_fch`).

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use async_trait::async_trait;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_aml::resource::ResourceItem;
use narf_memory::PhysAddr;

use crate::{I2cBus, I2cError, I2cOp};

// ── ACPI HIDs we recognise ─────────────────────────────────────────
//
// The mapping mirrors Linux's `dw_i2c_acpi_match[]` and covers the
// LPSS-mode I2C controllers (both PCI-mode and ACPI-mode) that
// modern Intel silicon presents.
//
// ── Modern ACPI-mode (Tiger Lake / Alder Lake / Raptor Lake) ──
// INT33C2 / INT33C3 — Haswell ULT.
// INT3432 / INT3433 — Broadwell ULT (DDR3) / Broadwell-Y.
// INT3446 / INT3447 — Skylake / Kaby Lake LPSS I2C.
// INT34B7 / INT34BA — Tiger Lake / Alder Lake LPSS I2C.
// INT34C5         — Raptor Lake / Meteor Lake LPSS I2C.
// INTC1009        — Lakefield (LPSS I2C).
// INTC1010        — Jasper Lake.
//
// ── Older PCI-mode (Baytrail / Cherry Trail / Apollo Lake) ──
// 80860F41 — Baytrail/Cherry Trail LPSS I2C in PCI-mode.
// 808622C1 — Broxton / Apollo Lake LPSS I2C in PCI-mode.
//
// PCI-mode controllers appear in the namespace as device nodes
// with the _HID set and _CRS holding a Memory32Fixed for the BAR,
// so the same _CRS decode path picks them up. The Stage-1
// transition to "real transfers" handles any LPSS-PCI clock-gating
// quirks separately.
const LPSS_I2C_HIDS: &[&str] = &[
    // Tiger Lake / Alder Lake / Raptor Lake — bring-up priority.
    "INT34B7", "INT34BA", "INT34C5",
    // Skylake / Kaby Lake era.
    "INT3446", "INT3447",
    // Haswell / Broadwell.
    "INT33C2", "INT33C3", "INT3432", "INT3433",
    // Lakefield / Jasper Lake.
    "INTC1009", "INTC1010",
    // Older PCI-mode LPSS (Baytrail / Apollo Lake).
    "80860F41", "808622C1",
];

// ── DW I2C register offsets (shared with AMD FCH variant) ──────────
//
// The Intel LPSS I2C wraps the same Synopsys DW APB I2C core that
// `crate::amd_fch` drives. Offsets below are the DW core's; the LPSS
// private register page (clock-gating, reset, etc.) sits above the
// core at offset 0x200 and is Stage-1 territory.
//
// Same constants are duplicated here rather than imported from
// `amd_fch` because once Stage-1 lands we'll want them as a shared
// `crate::dw_i2c` module and we don't want to pre-build that
// abstraction speculatively — better to factor it out once we have
// two consumers in working order than to factor in advance and get
// the seams wrong.
const IC_COMP_TYPE: u64 = 0xfc;

/// DesignWare component-type magic — same value AMD FCH reports.
/// Reading this on the LPSS core confirms (a) the MMIO mapping is
/// pointing at a DW I2C IP block and (b) the LPSS clock/reset has
/// the core out of reset enough for the register file to respond.
const DW_COMP_TYPE_MAGIC: u32 = 0x4457_0140;

/// One Intel LPSS I2C controller. Stage-0 holds the MMIO base + a
/// disabled flag; `transfer()` is a stub. Stage-1 will add the same
/// fields the AMD FCH variant has (async bus mutex, last-target
/// cache, enabled flag flipped after `enable()` programs the core).
pub struct LpssI2c {
    name: String,
    mmio_base: PhysAddr,
    mmio_len: u64,
    /// Reserved for Stage-1: the IDT vector for the controller's
    /// interrupt line, decoded from `_CRS`'s ExtendedIrq. Held here
    /// so the Stage-0 audit confirms _CRS parsing reaches IRQ
    /// resource items (the FB-status panel can surface "controller
    /// found, irq=GSI17->v33" telemetry once it does).
    irq_vector: Option<u8>,
    /// Always false in Stage-0 — the controller is registered but not
    /// programmed. Stage-1 flips this true after `enable()` programs
    /// IC_CON + IC_*CNT + IC_ENABLE.
    enabled: AtomicBool,
}

impl core::fmt::Debug for LpssI2c {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LpssI2c")
            .field("name", &self.name)
            .field("mmio_base", &self.mmio_base)
            .field("mmio_len", &self.mmio_len)
            .field("irq_vector", &self.irq_vector)
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish()
    }
}

impl LpssI2c {
    /// Construct a controller against an already-decoded MMIO region
    /// + IRQ vector. Used both by `probe_all` (real discovery) and by
    /// the smoke tests (synthetic backing buffer instead of MMIO).
    pub fn new(
        name: String,
        mmio_base: PhysAddr,
        mmio_len: u64,
        irq_vector: Option<u8>,
    ) -> Self {
        Self {
            name,
            mmio_base,
            mmio_len,
            irq_vector,
            enabled: AtomicBool::new(false),
        }
    }

    #[inline]
    unsafe fn read32(&self, off: u64) -> u32 {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: caller is the single-threaded probe path; offset
        // bounds-checked above. Stage-1 will need a bus lock per the
        // FCH variant's pattern; for the Stage-0 IC_COMP_TYPE read
        // there's exactly one caller (`probe_component_type`).
        unsafe { narf_arch::mmio::read32(self.mmio_base.raw() + off) }
    }

    /// Read IC_COMP_TYPE and confirm we're talking to a DW I2C IP.
    /// Catches the "MMIO mapped but pointing at the wrong device"
    /// failure mode early. On Intel LPSS this also doubles as a
    /// "is the core out of reset" check — the LPSS clock-gating
    /// register page above 0x200 sometimes leaves the core powered-
    /// down at boot; in Stage-1 we'll touch the LPSS private regs
    /// to ungate first.
    pub fn probe_component_type(&self) -> Result<(), I2cError> {
        // SAFETY: probe-time, exclusive access to the MMIO window.
        let ct = unsafe { self.read32(IC_COMP_TYPE) };
        if ct == DW_COMP_TYPE_MAGIC {
            Ok(())
        } else {
            Err(I2cError::BadHardware)
        }
    }
}

#[async_trait]
impl I2cBus for LpssI2c {
    async fn transfer(&self, _addr: u8, _ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
        // Stage-0 stub. Registering the bus so `i2c-hid-bind` can
        // discover it through the registry is the whole point of
        // Stage-0; actually moving bytes on the wire is Stage-1.
        //
        // Returning BadHardware (rather than a panic / unimplemented!)
        // means the i2c-hid pump task exits cleanly when it tries
        // its first descriptor read, instead of crashing the kernel.
        Err(I2cError::BadHardware)
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ── Discovery ──────────────────────────────────────────────────────

/// One controller's _CRS-decoded resources. Shape matches
/// `amd_fch::CtrlResources` exactly — the AML resource encoding is
/// identical, only the parent device's _HID differs.
#[derive(Debug, Clone)]
struct CtrlResources {
    mmio_base: u64,
    mmio_len: u64,
    /// GSI of the controller's interrupt line. None when _CRS didn't
    /// surface an ExtendedIrq descriptor — Stage-1 driver would run
    /// in polled mode in that case.
    gsi: Option<u32>,
    #[allow(dead_code)] // Stage-1 will read this when routing IRQs.
    irq_flags: u8,
}

/// Decode `_CRS` for a controller node into the resources we need.
/// Returns None if no MMIO descriptor is present.
fn decode_ctrl_crs(path: &str) -> Option<CtrlResources> {
    let items = narf_aml::prt_crs::evaluate_crs_for(path).ok()?;
    let mut mmio: Option<(u64, u64)> = None;
    let mut gsi: Option<u32> = None;
    let mut irq_flags: u8 = 0;
    for item in items {
        match item {
            ResourceItem::Memory32Fixed { base, length, .. } => {
                if mmio.is_none() {
                    mmio = Some((base as u64, length as u64));
                }
            }
            ResourceItem::Memory32 { min, length, .. } => {
                if mmio.is_none() {
                    mmio = Some((min as u64, length as u64));
                }
            }
            ResourceItem::AddressSpace32 { kind, min, length, .. } if kind == 0 => {
                if mmio.is_none() {
                    mmio = Some((min as u64, length as u64));
                }
            }
            ResourceItem::AddressSpace64 { kind, min, length, .. } if kind == 0 => {
                if mmio.is_none() {
                    mmio = Some((min, length));
                }
            }
            ResourceItem::ExtendedIrq { flags, gsis } => {
                if let Some(&g) = gsis.first() {
                    gsi = Some(g);
                    irq_flags = flags;
                }
            }
            _ => {}
        }
    }
    let (mmio_base, mmio_len) = mmio?;
    Some(CtrlResources {
        mmio_base,
        mmio_len,
        gsi,
        irq_flags,
    })
}

/// Walk every LPSS I2C device in the AML namespace, decode its _CRS,
/// instantiate + register a driver per controller. Returns the count
/// of controllers successfully registered. Zero on non-Intel hardware
/// (or QEMU virt with no LPSS in DSDT) and is not an error.
pub fn probe_all() -> usize {
    let mut count = 0usize;
    for &hid in LPSS_I2C_HIDS {
        for node in narf_aml::find_all_devices_by_hid(hid) {
            if probe_one(&node.path).is_some() {
                count += 1;
            }
        }
    }
    count
}

fn probe_one(path: &str) -> Option<()> {
    use core::fmt::Write;

    let res = decode_ctrl_crs(path)?;

    // Stage-0: no IRQ routing yet (the Stage-1 transfer state
    // machine is what needs the vector). Leaving `irq_vector =
    // None` so the LpssI2c struct carries the GSI presence
    // information in its Debug output without yet committing a
    // real IDT vector — important because alloc::vector on
    // hardware with already-busy IRQ space can fail, and we don't
    // want a Stage-0 audit to consume vectors we can't make use
    // of yet.
    let irq_vec: Option<u8> = None;

    let driver = Arc::new(LpssI2c::new(
        path.to_string(),
        PhysAddr::new(res.mmio_base),
        res.mmio_len,
        irq_vec,
    ));

    if let Err(e) = driver.probe_component_type() {
        let _ = writeln!(
            narf_console::Writer,
            "  lpss-i2c: {} probe failed ({:?}) at {:#x}",
            path, e, res.mmio_base
        );
        // Probe failed — most likely the LPSS clock-gating register
        // page leaves the DW core powered-down at boot, and IC_COMP_TYPE
        // returns 0. Stage-1 will ungate first. For Stage-0 we still
        // register the bus so the i2c-hid-bind pass can find it and
        // log "parent bus present but not yet transactable" rather
        // than the misleading "parent bus not registered, skipping".
        let registered = crate::registry::register_unique(driver.clone());
        let _ = writeln!(
            narf_console::Writer,
            "  lpss-i2c: {} registered (stage-0 stub, transfers will return BadHardware)",
            path
        );
        let _ = registered;
        return Some(());
    }

    let registered = crate::registry::register_unique(driver.clone());
    let _ = writeln!(
        narf_console::Writer,
        "  lpss-i2c: detected at MMIO={:#x}+{:#x} {} irq=GSI{} (stage-0 stub)",
        res.mmio_base,
        res.mmio_len,
        path,
        res.gsi.map(|g| format!("{}", g)).unwrap_or_else(|| "?".into()),
    );
    let _ = registered;
    Some(())
}

/// Test-only: list the HIDs we recognise. Used by smokes that
/// verify the Tiger Lake / Alder Lake bring-up HIDs stay in the
/// table.
#[doc(hidden)]
pub fn recognised_hids() -> &'static [&'static str] {
    LPSS_I2C_HIDS
}

/// Test-only: explicit constructor for the synthetic-MMIO smokes.
#[doc(hidden)]
pub fn __new_for_test(
    name: String,
    mmio_base: PhysAddr,
    mmio_len: u64,
) -> LpssI2c {
    LpssI2c::new(name, mmio_base, mmio_len, None)
}
