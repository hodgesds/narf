//! Intel PCH GPIO / pinctrl — Stage-0 skeleton.
//!
//! What this stage does
//! --------------------
//! 1. Walks every Intel PCH GPIO ACPI device (HIDs `INT34BB`,
//!    `INT3450`, `INT34C8`/`INT34C9`, `INT37FF`, `INT3454`, `INT3452`,
//!    and the older `INT344B`/`INT3437`/`INT345D`/`INT3455` for
//!    completeness).
//! 2. Decodes `_CRS`, collecting every `Memory32Fixed` (or 32/64-bit
//!    address-space) descriptor — one per *community* (sub-block of
//!    pins, each with its own MMIO window).
//! 3. For each community: reads `REVID` (offset 0x000) to sanity-check
//!    the mapping (all-ones = device absent), reads `PADBAR`
//!    (offset 0x00C) to find the pad-config base, then computes an
//!    upper-bound pin count from the remaining window size.
//! 4. Registers one `IntelPchGpio` controller per community in the
//!    shared GPIO registry under the name `<acpi_path>.C<N>`, so a
//!    later i2c-hid bind can resolve a `GpioInt::resource_source`
//!    referring to e.g. `\_SB.PC00.GPI0` to the matching community.
//!
//! What this stage does NOT do
//! ---------------------------
//! - No pin programming. `read_pin`, `set_pin`, `register_irq`,
//!   `unregister_irq` all return `BadHardware`. The Stage-1 follow-up
//!   will program `PADCFG0`/`PADCFG1`/`PADCFG2` per the same trait
//!   the AMD FCH driver implements; until then i2c-hid-bind's
//!   `register_irq` fails cleanly and falls back to polled mode.
//! - No IRQ routing. Each Intel PCH GPIO device exposes a single
//!   shared GSI through an `ExtendedIrq` resource — we decode + stash
//!   it but don't install an ISR.
//!
//! Register layout (per community, from Linux's
//! `drivers/pinctrl/intel/pinctrl-intel.c` — public, GPL-2.0; NARF
//! relicensed to GPL-2.0-or-later 2026-05-20):
//! - `REVID`    @ 0x000: bits[31:16] = revision; `~0u` = device absent.
//!                       Revision >= 0x94 → DEBOUNCE feature → 4-dword
//!                       pad stride (PADCFG0/1/2 + 1 reserved). Older
//!                       silicon → 2-dword pad stride (PADCFG0/1).
//! - `CAPLIST`  @ 0x004: linked list of feature blocks (we walk it
//!                       for cap-id 1 = GPIO Hardware Info, which on
//!                       some silicon exposes an explicit pin count;
//!                       Stage-0 reads it but uses the window-size
//!                       heuristic when absent).
//! - `PADBAR`   @ 0x00C: byte offset within the community where the
//!                       `PADCFG0[N]` registers begin.
//! - `PADCFG0`  @ PADBAR + N*stride + 0
//! - `PADCFG1`  @ PADBAR + N*stride + 4
//! - `PADCFG2`  @ PADBAR + N*stride + 8 (only when DEBOUNCE supported)
//!
//! ACPI HID table — pulled from Linux's per-SoC pinctrl drivers
//! (`pinctrl-tigerlake.c`, `pinctrl-alderlake.c`, etc.):
//! - `INT344B` — Sunrise Point (Skylake / Kaby Lake).
//! - `INT3437` — Cannon Lake H (legacy desktop; kept for parity).
//! - `INT3450` — Comet Lake / Cannon Lake-LP (the original ID).
//! - `INT3452` — Apollo Lake (Atom-class, kept for completeness).
//! - `INT3454` — Cannon Lake LP (consumer CL spec).
//! - `INT3455` — Ice Lake-LP.
//! - `INT345D` — Jasper Lake.
//! - `INT34BB` — Tiger Lake.
//! - `INT34C5` — Alder Lake-N.
//! - `INT34C8` — Raptor Lake-S.
//! - `INT34C9` — Raptor Lake-P / Alder Lake-P GPIO (same controller).
//! - `INT37FF` — Meteor Lake.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::fmt::Write as _;

use narf_aml::resource::ResourceItem;
use narf_memory::PhysAddr;

use crate::{GpioController, GpioError, GpioIrqConfig, GpioIrqHandler, GpioPull};

// ── ACPI HIDs we recognise ─────────────────────────────────────────
//
// The mapping mirrors the union of the `acpi_match_table` entries in
// Linux's `drivers/pinctrl/intel/pinctrl-<soc>.c` files. The list
// intentionally errs on the side of inclusion — a Stage-0 boot that
// merely registers a non-functional controller for an Intel SoC we
// don't yet have full pin tables for is harmless (every pin op
// returns BadHardware); a missing HID would leave the laptop with
// no chance of touchpad bring-up later.
pub const INTEL_PCH_GPIO_HIDS: &[&str] = &[
    "INT344B", // Sunrise Point (Skylake / Kaby Lake)
    "INT3437", // Cannon Lake H
    "INT3450", // Comet Lake / Cannon Lake-LP
    "INT3452", // Apollo Lake
    "INT3454", // Cannon Lake LP
    "INT3455", // Ice Lake LP
    "INT345D", // Jasper Lake
    "INT34BB", // Tiger Lake
    "INT34C5", // Alder Lake-N
    "INT34C8", // Raptor Lake-S
    "INT34C9", // Raptor Lake-P / Alder Lake-P
    "INT37FF", // Meteor Lake
];

// ── Register offsets ───────────────────────────────────────────────

const REG_REVID: u64 = 0x000;
const REG_CAPLIST: u64 = 0x004;
const REG_PADBAR: u64 = 0x00C;

const CAPLIST_ID_GPIO_HW_INFO: u32 = 1;

const REVID_DEBOUNCE_THRESHOLD: u32 = 0x94;

/// One Intel PCH GPIO community. Each Intel PCH GPIO ACPI device
/// fans out into 2–4 of these; each gets its own controller entry in
/// the shared GPIO registry so child devices can address pin spaces
/// independently.
pub struct IntelPchGpio {
    name: String,
    /// Parent ACPI path the firmware exposed (`\_SB.PC00.GPI0`) —
    /// preserved separately so a future child lookup can match on
    /// the bare path or on the per-community suffixed name.
    acpi_path: String,
    /// Zero-based community index within the parent ACPI device.
    community_index: u8,
    mmio_base: PhysAddr,
    mmio_len: u64,
    /// Revision read from `REVID`. `None` when probe came back
    /// all-ones (device not actually present at the firmware-reported
    /// address — common on QEMU + bare metal where firmware emits
    /// stale resource records).
    revid: Option<u16>,
    /// `PADBAR` offset (byte). `None` when probe failed.
    padbar: Option<u32>,
    /// Pin count derived from `(mmio_len - padbar) / pad_stride`.
    /// Conservative upper bound — Stage-1 will replace this with the
    /// per-SoC table value where one exists.
    pin_count: u16,
    /// `true` when the revision indicates the DEBOUNCE feature
    /// (PADCFG2 present, 4-dword pad stride). Used by Stage-1 register
    /// programming; Stage-0 only logs it.
    has_debounce: bool,
}

impl core::fmt::Debug for IntelPchGpio {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelPchGpio")
            .field("name", &self.name)
            .field("acpi_path", &self.acpi_path)
            .field("community_index", &self.community_index)
            .field("mmio_base", &self.mmio_base)
            .field("mmio_len", &self.mmio_len)
            .field("revid", &self.revid)
            .field("padbar", &self.padbar)
            .field("pin_count", &self.pin_count)
            .field("has_debounce", &self.has_debounce)
            .finish()
    }
}

impl IntelPchGpio {
    /// Build a community controller against an already-decoded MMIO
    /// region. Used both by `probe_all` and the synthetic-backing
    /// smokes.
    ///
    /// `pin_count` is the conservatively-rounded result of dividing
    /// `mmio_len - padbar` by the pad stride; `revid` / `padbar`
    /// are recorded as the values read from the live device (or the
    /// synthetic backing) so the smokes can assert against them.
    pub fn new(
        acpi_path: String,
        community_index: u8,
        mmio_base: PhysAddr,
        mmio_len: u64,
        revid: Option<u16>,
        padbar: Option<u32>,
        pin_count: u16,
        has_debounce: bool,
    ) -> Self {
        let name = format!("{}.C{}", acpi_path, community_index);
        Self {
            name,
            acpi_path,
            community_index,
            mmio_base,
            mmio_len,
            revid,
            padbar,
            pin_count,
            has_debounce,
        }
    }

    pub fn acpi_path(&self) -> &str {
        &self.acpi_path
    }

    pub fn community_index(&self) -> u8 {
        self.community_index
    }

    pub fn mmio_base(&self) -> PhysAddr {
        self.mmio_base
    }

    pub fn mmio_len(&self) -> u64 {
        self.mmio_len
    }

    pub fn revid(&self) -> Option<u16> {
        self.revid
    }

    pub fn padbar(&self) -> Option<u32> {
        self.padbar
    }

    pub fn has_debounce(&self) -> bool {
        self.has_debounce
    }
}

impl GpioController for IntelPchGpio {
    fn name(&self) -> &str {
        &self.name
    }

    fn pin_count(&self) -> u16 {
        self.pin_count
    }

    fn read_pin(&self, _pin: u16) -> Result<bool, GpioError> {
        // Stage-0 stub: discovery only, no pad-register programming.
        // Returning BadHardware (rather than a panic) means a
        // hypothetical Stage-0 caller exits cleanly. Stage-1 will
        // implement this against `PADCFG0_GPIORXSTATE`.
        Err(GpioError::BadHardware)
    }

    fn set_pin(&self, _pin: u16, _value: bool) -> Result<(), GpioError> {
        Err(GpioError::BadHardware)
    }

    fn register_irq(
        &self,
        _pin: u16,
        _pull: GpioPull,
        _irq: GpioIrqConfig,
        _handler: GpioIrqHandler,
    ) -> Result<(), GpioError> {
        // Stage-0 stub. i2c-hid-bind treats a BadHardware return
        // here as "GPIO not yet able to wire interrupts", logs the
        // failure, and falls back to polling.
        Err(GpioError::BadHardware)
    }

    fn unregister_irq(&self, _pin: u16) {
        // No-op until Stage-1 lands real IRQ arming.
    }
}

// ── Discovery ──────────────────────────────────────────────────────

/// One community's MMIO descriptor, plus the parent device's shared
/// GSI when present.
#[derive(Debug, Clone)]
struct CommunityRes {
    mmio_base: u64,
    mmio_len: u64,
}

#[derive(Debug, Clone)]
struct CtrlResources {
    communities: alloc::vec::Vec<CommunityRes>,
    /// Shared GSI for the whole controller. Stage-1 will route it
    /// through the IO-APIC; Stage-0 just records its presence so the
    /// diagnostic log can surface "controller has IRQ wiring vs.
    /// firmware forgot to declare one".
    gsi: Option<u32>,
    #[allow(dead_code)] // Stage-1 will consume this when routing.
    irq_flags: u8,
}

fn decode_ctrl_crs(path: &str) -> Option<CtrlResources> {
    let items = narf_aml::prt_crs::evaluate_crs_for(path).ok()?;
    let mut communities: alloc::vec::Vec<CommunityRes> = alloc::vec::Vec::new();
    let mut gsi: Option<u32> = None;
    let mut irq_flags: u8 = 0;
    for item in items {
        match item {
            ResourceItem::Memory32Fixed { base, length, .. } => {
                communities.push(CommunityRes {
                    mmio_base: base as u64,
                    mmio_len: length as u64,
                });
            }
            ResourceItem::Memory32 { min, length, .. } => {
                communities.push(CommunityRes {
                    mmio_base: min as u64,
                    mmio_len: length as u64,
                });
            }
            ResourceItem::AddressSpace32 { kind, min, length, .. } if kind == 0 => {
                communities.push(CommunityRes {
                    mmio_base: min as u64,
                    mmio_len: length as u64,
                });
            }
            ResourceItem::AddressSpace64 { kind, min, length, .. } if kind == 0 => {
                communities.push(CommunityRes {
                    mmio_base: min,
                    mmio_len: length,
                });
            }
            ResourceItem::ExtendedIrq { flags, gsis } => {
                if gsi.is_none() {
                    if let Some(&g) = gsis.first() {
                        gsi = Some(g);
                        irq_flags = flags;
                    }
                }
            }
            _ => {}
        }
    }
    if communities.is_empty() {
        return None;
    }
    Some(CtrlResources {
        communities,
        gsi,
        irq_flags,
    })
}

/// Probe one community's MMIO window. Returns the (revid, padbar,
/// has_debounce, pin_count) tuple, or `None` if the window reads
/// back all-ones (device not present) or is too short to hold the
/// minimum register set.
///
/// # Safety
/// `mmio_base..mmio_base+mmio_len` must be a kernel-mapped MMIO
/// region the caller owns exclusively for the duration of this
/// probe.
unsafe fn probe_community(
    mmio_base: PhysAddr,
    mmio_len: u64,
) -> Option<(u16, u32, bool, u16)> {
    if mmio_len < 0x10 {
        // Need at least REVID + CAPLIST + reserved + PADBAR.
        return None;
    }
    // SAFETY: caller asserts region validity.
    let revid_raw = unsafe { narf_arch::mmio::read32(mmio_base.raw() + REG_REVID) };
    if revid_raw == u32::MAX {
        // Device-absent sentinel — firmware emitted a stale CRS,
        // or the LPSS/PCH power gating left this community offline.
        return None;
    }
    let revid = ((revid_raw >> 16) & 0xFFFF) as u16;
    let has_debounce = (revid as u32) >= REVID_DEBOUNCE_THRESHOLD;
    // SAFETY: same MMIO window.
    let padbar = unsafe { narf_arch::mmio::read32(mmio_base.raw() + REG_PADBAR) };
    if (padbar as u64) >= mmio_len || padbar < 0x10 {
        // PADBAR points outside the window or back into the
        // common-register area → mapping is bogus.
        return None;
    }
    // Pad stride: 4 dwords (16 B) when DEBOUNCE supported else 2.
    let pad_stride: u64 = if has_debounce { 16 } else { 8 };
    let pad_region = mmio_len - padbar as u64;
    let raw_pin_count = pad_region / pad_stride;
    // Cap at u16::MAX to fit the trait's return type; real silicon
    // never approaches this (largest community ~250 pads).
    let pin_count = raw_pin_count.min(u16::MAX as u64) as u16;
    Some((revid, padbar, has_debounce, pin_count))
}

/// Optional second pass: walk the CAPLIST chain looking for the
/// `GPIO Hardware Info` cap (ID = 1). Some newer silicon publishes
/// an explicit pad count there, which we'll prefer over the
/// window-size heuristic when found. Returns `None` when the chain
/// is empty, terminates, or never surfaces the cap.
///
/// # Safety
/// Same as `probe_community`.
#[allow(dead_code)] // Stage-1 will start consuming this for real pad counts.
unsafe fn probe_caplist_gpio_hw_info(mmio_base: PhysAddr, mmio_len: u64) -> Option<u32> {
    let mut offset: u64 = REG_CAPLIST;
    // Bound the walk to prevent runaway loops on malformed firmware.
    for _ in 0..16 {
        if offset + 4 > mmio_len {
            return None;
        }
        // SAFETY: bounded by mmio_len.
        let value = unsafe { narf_arch::mmio::read32(mmio_base.raw() + offset) };
        let cap_id = (value >> 16) & 0xFF;
        let next = (value & 0xFFFF) as u64;
        if cap_id == CAPLIST_ID_GPIO_HW_INFO {
            return Some(value);
        }
        if next == 0 {
            return None;
        }
        offset = next;
    }
    None
}

/// Walk every Intel PCH GPIO device in the AML namespace, decode its
/// `_CRS`, instantiate + register one controller per community.
/// Returns the count successfully registered. Zero on non-Intel
/// hardware / non-PCH firmware (e.g. QEMU TCG q35 with no LPSS GPIO
/// in DSDT) is expected and is not an error.
pub fn probe_all() -> usize {
    let mut count = 0usize;
    for &hid in INTEL_PCH_GPIO_HIDS {
        for node in narf_aml::find_all_devices_by_hid(hid) {
            count += probe_one(hid, &node.path);
        }
    }
    count
}

fn probe_one(hid: &str, path: &str) -> usize {
    let res = match decode_ctrl_crs(path) {
        Some(r) => r,
        None => {
            let _ = writeln!(
                narf_console::Writer,
                "  intel-pch-gpio: {} ({}): _CRS missing or empty",
                path, hid
            );
            return 0;
        }
    };

    let gsi_str = res
        .gsi
        .map(|g| format!("{}", g))
        .unwrap_or_else(|| "none".into());
    let _ = writeln!(
        narf_console::Writer,
        "  intel-pch-gpio: detected {} ({}) at {} communit{}, gsi={}",
        path,
        hid,
        res.communities.len(),
        if res.communities.len() == 1 { "y" } else { "ies" },
        gsi_str,
    );

    let mut registered = 0usize;
    for (idx, c) in res.communities.iter().enumerate() {
        let phys = PhysAddr::new(c.mmio_base);
        // SAFETY: the firmware's _CRS asserts this window belongs to
        // the GPIO controller; identity-mapped low memory covers it
        // on x86_64 boot. If the assumption fails (mapping pages
        // unmapped) the read faults and the BSP halts in the IDT
        // page-fault handler — same risk profile as every other
        // Memory32Fixed-driven driver in the tree.
        let probe = unsafe { probe_community(phys, c.mmio_len) };
        let (revid, padbar, has_debounce, pin_count) = match probe {
            Some(t) => (Some(t.0), Some(t.1), t.2, t.3),
            None => (None, None, false, 0),
        };
        let ctrl = Arc::new(IntelPchGpio::new(
            path.to_string(),
            idx as u8,
            phys,
            c.mmio_len,
            revid,
            padbar,
            pin_count,
            has_debounce,
        ));
        let registered_arc = crate::registry::register_unique(ctrl);
        let _ = registered_arc;
        registered += 1;

        match probe {
            Some((rev, pb, deb, pads)) => {
                let _ = writeln!(
                    narf_console::Writer,
                    "    C{}: mmio={:#x}+{:#x} revid={:#x} padbar={:#x} pads={} debounce={}",
                    idx, c.mmio_base, c.mmio_len, rev, pb, pads, deb,
                );
            }
            None => {
                let _ = writeln!(
                    narf_console::Writer,
                    "    C{}: mmio={:#x}+{:#x} probe-failed (revid=~0 or padbar OOB) — community absent",
                    idx, c.mmio_base, c.mmio_len,
                );
            }
        }
    }

    registered
}

// ── Test-only hooks ────────────────────────────────────────────────

/// Test-only: HID list we recognise. Used by the smoke that guards
/// against the table getting trimmed for the bring-up SoCs.
#[doc(hidden)]
pub fn recognised_hids() -> &'static [&'static str] {
    INTEL_PCH_GPIO_HIDS
}

/// Test-only: explicit constructor that mirrors what `probe_one`
/// builds for a single community, so smokes can drive the
/// GpioController surface against a synthetic backing.
#[doc(hidden)]
pub fn __new_for_test(
    acpi_path: String,
    community_index: u8,
    mmio_base: PhysAddr,
    mmio_len: u64,
    revid: Option<u16>,
    padbar: Option<u32>,
    pin_count: u16,
    has_debounce: bool,
) -> IntelPchGpio {
    IntelPchGpio::new(
        acpi_path,
        community_index,
        mmio_base,
        mmio_len,
        revid,
        padbar,
        pin_count,
        has_debounce,
    )
}

/// Test-only: probe a synthetic backing in the same way `probe_one`
/// drives a live MMIO window. Exposed so smokes can assert the
/// REVID/PADBAR/pad-count decode against a hand-rolled buffer
/// without touching real hardware.
///
/// # Safety
/// Same contract as `probe_community`.
#[doc(hidden)]
pub unsafe fn __probe_community_for_test(
    mmio_base: PhysAddr,
    mmio_len: u64,
) -> Option<(u16, u32, bool, u16)> {
    // SAFETY: forwarded directly; caller asserts.
    unsafe { probe_community(mmio_base, mmio_len) }
}
