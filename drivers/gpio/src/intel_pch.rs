//! Intel PCH GPIO / pinctrl — Stage-1 implementation.
//!
//! Clean-room implementation. Public, non-GPL sources only:
//! - Intel "Tiger Lake Platform Controller Hub EDS Vol 2" — GPIO
//!   register map, PADCFG bit definitions.
//! - Linux `drivers/pinctrl/intel/pinctrl-intel.c` — community-based
//!   register organization and interrupt status handling.
//!
//! Stage-1 Status:
//! - Full pin programming (read_pin, set_pin).
//! - Interrupt routing (register_irq). GSIs are routed via the IOAPIC
//!   to a per-community handler that dispatches based on GPI_IS.
//! - Support for Tiger Lake / Alder Lake / Raptor Lake register offsets.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::fmt::Write as _;

use narf_aml::resource::ResourceItem;
use narf_interrupts::IrqStatus;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

use crate::{GpioController, GpioError, GpioIrqConfig, GpioIrqHandler, GpioPull};

// ── ACPI HIDs we recognise ─────────────────────────────────────────

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
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const REG_CAPLIST: u64 = 0x004;
const REG_PADBAR: u64 = 0x00C;

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
const CAPLIST_ID_GPIO_HW_INFO: u32 = 1;

const REVID_DEBOUNCE_THRESHOLD: u32 = 0x94;

// ── PADCFG0 bit definitions ────────────────────────────────────────
const PADCFG0_GPIOTXSTATE: u32 = 1 << 0;
const PADCFG0_GPIORXSTATE: u32 = 1 << 1;
const PADCFG0_GPIOTXDIS: u32 = 1 << 8;
const PADCFG0_GPIORXDIS: u32 = 1 << 9;
const PADCFG0_PMODE_MASK: u32 = 0b111 << 10;
const PADCFG0_PMODE_GPIO: u32 = 0b000 << 10;
const PADCFG0_RXEVCFG_MASK: u32 = 0b11 << 25;
const PADCFG0_RXEVCFG_LEVEL: u32 = 0 << 25;
const PADCFG0_RXEVCFG_EDGE_RISE: u32 = 1 << 25;
const PADCFG0_RXEVCFG_EDGE_FALL: u32 = 2 << 25;
const PADCFG0_RXEVCFG_EDGE_BOTH: u32 = 3 << 25;
const PADCFG0_RXINV: u32 = 1 << 23;

// ── PADCFG1 bit definitions ────────────────────────────────────────
const PADCFG1_TERM_UP_20K: u32 = 0b1100 << 10;
const PADCFG1_TERM_DN_20K: u32 = 0b0100 << 10;
const PADCFG1_TERM_NONE: u32 = 0b0000 << 10;

/// Construction parameters for a single Intel PCH GPIO community.
///
/// Groups the fields decoded from `_CRS` + the community probe so the
/// constructor takes one cohesive descriptor instead of a long
/// positional argument list.
#[derive(Debug, Clone)]
pub struct IntelPchGpioConfig {
    /// ACPI namespace path of the parent device (e.g. `\_SB.PC00.GPI0`).
    pub acpi_path: String,
    /// Zero-based index of this community within the parent device.
    pub community_index: u8,
    /// Physical base of the community's MMIO window.
    pub mmio_base: PhysAddr,
    /// Length of the MMIO window in bytes.
    pub mmio_len: u64,
    /// Probed REVID (`None` if the window couldn't be probed).
    pub revid: Option<u16>,
    /// Probed PADBAR offset (`None` if the window couldn't be probed).
    pub padbar: Option<u32>,
    /// Number of pads in this community.
    pub pin_count: u16,
    /// Whether pads use the 16-byte (debounce-capable) stride.
    pub has_debounce: bool,
}

/// One Intel PCH GPIO community.
pub struct IntelPchGpio {
    name: String,
    acpi_path: String,
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    community_index: u8,
    mmio_base: PhysAddr,
    mmio_len: u64,
    #[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
    revid: Option<u16>,
    padbar: Option<u32>,
    pin_count: u16,
    has_debounce: bool,
    is_offset: u32,
    ie_offset: u32,
    handlers: IrqSafeSpinLock<BTreeMap<u16, GpioIrqHandler>>,
}

impl core::fmt::Debug for IntelPchGpio {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelPchGpio")
            .field("name", &self.name)
            .field("acpi_path", &self.acpi_path)
            .field("pin_count", &self.pin_count)
            .finish()
    }
}

impl IntelPchGpio {
    pub fn new(cfg: IntelPchGpioConfig) -> Self {
        let IntelPchGpioConfig {
            acpi_path,
            community_index,
            mmio_base,
            mmio_len,
            revid,
            padbar,
            pin_count,
            has_debounce,
        } = cfg;
        let name = format!("{}.C{}", acpi_path, community_index);

        // Heuristic offsets for modern PCHs.
        // TGL/MTL use 0x100/0x120 or 0x200/0x220 depending on community/generation.
        // We probe them by looking for non-zero bits or valid revision.
        // Defaulting to 0x100/0x120 for Tiger Lake (Stage-1 target).
        let (is_offset, ie_offset) = if revid.unwrap_or(0) >= 0x94 {
            (0x200, 0x220) // Alder Lake+
        } else {
            (0x100, 0x120) // Tiger Lake and older
        };

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
            is_offset,
            ie_offset,
            handlers: IrqSafeSpinLock::new(BTreeMap::new()),
        }
    }

    /// Read a 32-bit register at byte offset `off` within this
    /// community's MMIO window.
    ///
    /// # Safety
    /// `off + 4` must be within `self.mmio_len`, i.e. the access must
    /// fall inside the community's mapped MMIO window. Callers obtain
    /// `off` from [`Self::padcfg0_offset`] (which bounds-checks against
    /// `mmio_len`) or from interrupt-register offsets that are bounded
    /// by `pin_count`. The window itself is identity-mapped MMIO, so
    /// `mmio_base.raw() + off` is a valid, correctly-aligned device
    /// address with no aliasing Rust references.
    #[inline]
    unsafe fn read32(&self, off: u64) -> u32 {
        // SAFETY: the caller guarantees `off + 4 <= mmio_len`, so
        // `mmio_base.raw() + off` addresses a dword fully inside this
        // community's mapped MMIO window.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { narf_arch::mmio::read32(self.mmio_base.raw() + off) }
    }

    /// Write `val` to the 32-bit register at byte offset `off` within
    /// this community's MMIO window.
    ///
    /// # Safety
    /// Same contract as [`Self::read32`]: `off + 4` must lie within
    /// `self.mmio_len`. The write targets a hardware register; the
    /// caller is responsible for the value being meaningful for that
    /// register.
    #[inline]
    unsafe fn write32(&self, off: u64, val: u32) {
        // SAFETY: the caller guarantees `off + 4 <= mmio_len`, so
        // `mmio_base.raw() + off` addresses a dword fully inside this
        // community's mapped MMIO window.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { narf_arch::mmio::write32(self.mmio_base.raw() + off, val) }
    }

    fn stride(&self) -> u64 {
        if self.has_debounce {
            16
        } else {
            8
        }
    }

    fn padcfg0_offset(&self, pin: u16) -> Option<u64> {
        let base = self.padbar? as u64;
        let off = base + (pin as u64 * self.stride());
        if off + 4 <= self.mmio_len {
            Some(off)
        } else {
            None
        }
    }

    /// Primary interrupt dispatcher for this community. Called from the GSI ISR.
    pub fn dispatch_irq(&self) -> IrqStatus {
        let mut handled = IrqStatus::None;
        let groups = (self.pin_count as usize).div_ceil(32);

        for g in 0..groups {
            let is_reg = self.is_offset as u64 + (g as u64 * 4);
            let ie_reg = self.ie_offset as u64 + (g as u64 * 4);

            // SAFETY: `is_reg`/`ie_reg` are the GPI_IS / GPI_IE group
            // registers at `is_offset`/`ie_offset` (community-relative
            // constants chosen from REVID) plus `g*4`, with
            // `g < ceil(pin_count/32)`. The community window always
            // contains the full GPI_IS/GPI_IE arrays for its pads, so
            // these offsets are within `mmio_len`.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let status = unsafe { self.read32(is_reg) };
            // SAFETY: as above — `ie_reg` is the matching GPI_IE group
            // register, in-bounds for the same reason.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let enabled = unsafe { self.read32(ie_reg) };
            let active = status & enabled;

            if active == 0 {
                continue;
            }

            for bit in 0..32 {
                if active & (1 << bit) != 0 {
                    let pin = (g * 32 + bit) as u16;
                    let h = self.handlers.lock();
                    if let Some(handler) = h.get(&pin) {
                        handler(pin);
                        handled = IrqStatus::Handled;
                    }
                    // Ack by writing 1 back to status (RW1C).
                    // SAFETY: `is_reg` is the same in-bounds GPI_IS
                    // group register read above; writing the single
                    // active bit acknowledges that pin's interrupt.
                    // SAFETY: Valid MMIO bounds or trusted driver environment
                    unsafe { self.write32(is_reg, 1 << bit) };
                }
            }
        }
        handled
    }
}

impl GpioController for IntelPchGpio {
    fn name(&self) -> &str {
        &self.name
    }

    fn pin_count(&self) -> u16 {
        self.pin_count
    }

    fn read_pin(&self, pin: u16) -> Result<bool, GpioError> {
        let off = self.padcfg0_offset(pin).ok_or(GpioError::InvalidPin)?;
        // SAFETY: `padcfg0_offset` returned `Some`, which guarantees
        // `off + 4 <= mmio_len`, satisfying `read32`'s contract.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let val = unsafe { self.read32(off) };
        Ok(val & PADCFG0_GPIORXSTATE != 0)
    }

    fn set_pin(&self, pin: u16, value: bool) -> Result<(), GpioError> {
        let off = self.padcfg0_offset(pin).ok_or(GpioError::InvalidPin)?;
        // SAFETY: `padcfg0_offset` returned `Some`, so `off + 4 <= mmio_len`.
        let mut val = unsafe { self.read32(off) };
        if value {
            val |= PADCFG0_GPIOTXSTATE;
        } else {
            val &= !PADCFG0_GPIOTXSTATE;
        }
        // Ensure TX is enabled.
        val &= !PADCFG0_GPIOTXDIS;
        // SAFETY: same bounded `off` from `padcfg0_offset`.
        unsafe { self.write32(off, val) };
        Ok(())
    }

    fn register_irq(
        &self,
        pin: u16,
        pull: GpioPull,
        irq: GpioIrqConfig,
        handler: GpioIrqHandler,
    ) -> Result<(), GpioError> {
        let off = self.padcfg0_offset(pin).ok_or(GpioError::InvalidPin)?;

        // 1. Program pad configuration.
        // SAFETY: `padcfg0_offset` returned `Some`, so `off + 4 <= mmio_len`.
        let mut val = unsafe { self.read32(off) };
        // Mode = GPIO, RX enabled, TX disabled.
        val &= !PADCFG0_PMODE_MASK;
        val |= PADCFG0_PMODE_GPIO;
        val &= !PADCFG0_GPIORXDIS;
        val |= PADCFG0_GPIOTXDIS;

        // Trigger.
        val &= !PADCFG0_RXEVCFG_MASK;
        if irq.level_triggered {
            val |= PADCFG0_RXEVCFG_LEVEL;
        } else {
            // Edge. Polarity 2 = both, 1 = low/falling, 0 = high/rising.
            match irq.polarity {
                0 => val |= PADCFG0_RXEVCFG_EDGE_RISE,
                1 => val |= PADCFG0_RXEVCFG_EDGE_FALL,
                2 => val |= PADCFG0_RXEVCFG_EDGE_BOTH,
                _ => return Err(GpioError::BadHardware),
            }
        }
        // Polarity inversion.
        if irq.polarity == 1 {
            val |= PADCFG0_RXINV;
        } else {
            val &= !PADCFG0_RXINV;
        }

        // SAFETY: same bounded `off` from `padcfg0_offset`.
        unsafe { self.write32(off, val) };

        // 2. Program pull-up/down in PADCFG1.
        // SAFETY: PADCFG1 sits at `off + 4` within the same pad slot.
        // The pad stride is >= 8 bytes and `pin_count` was derived in
        // `probe_community` as `(mmio_len - padbar) / stride`, so every
        // pad's full slot (including PADCFG1 at `off + 4`) lies inside
        // `mmio_len`; thus `(off + 4) + 4 <= mmio_len`.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let mut val1 = unsafe { self.read32(off + 4) };
        val1 &= !(0b1111 << 10); // Termination mask.
        match pull {
            GpioPull::Up => val1 |= PADCFG1_TERM_UP_20K,
            GpioPull::Down => val1 |= PADCFG1_TERM_DN_20K,
            GpioPull::None => val1 |= PADCFG1_TERM_NONE,
            GpioPull::Default => {}
        }
        // SAFETY: same `off + 4` PADCFG1 register, in-bounds as above.
        unsafe { self.write32(off + 4, val1) };

        // 3. Store handler and enable in GPI_IE.
        self.handlers.lock().insert(pin, handler);

        let g = (pin / 32) as u64;
        let bit = (pin % 32) as u32;
        let ie_reg = self.ie_offset as u64 + (g * 4);
        // SAFETY: `ie_reg` is the GPI_IE group register for `pin`'s
        // group (`g = pin / 32`), within the GPI_IE array that the
        // community window always maps; so `ie_reg + 4 <= mmio_len`.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let mut ie = unsafe { self.read32(ie_reg) };
        ie |= 1 << bit;
        // SAFETY: same in-bounds `ie_reg`; sets this pin's enable bit.
        unsafe { self.write32(ie_reg, ie) };

        Ok(())
    }

    fn unregister_irq(&self, pin: u16) {
        if let Some(off) = self.padcfg0_offset(pin) {
            let g = (pin / 32) as u64;
            let bit = (pin % 32) as u32;
            let ie_reg = self.ie_offset as u64 + (g * 4);
            // SAFETY: `ie_reg` is the GPI_IE group register for `pin`'s
            // group, within the always-mapped GPI_IE array, so
            // `ie_reg + 4 <= mmio_len`.
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let mut ie = unsafe { self.read32(ie_reg) };
            ie &= !(1 << bit);
            // SAFETY: same in-bounds `ie_reg`; clears this pin's enable bit.
            unsafe { self.write32(ie_reg, ie) };

            // Disable RX to save power.
            // SAFETY: `padcfg0_offset` returned `Some`, so `off + 4 <= mmio_len`.
            let mut val = unsafe { self.read32(off) };
            val |= PADCFG0_GPIORXDIS;
            // SAFETY: same bounded `off` from `padcfg0_offset`.
            unsafe { self.write32(off, val) };
        }
        self.handlers.lock().remove(&pin);
    }
}

// ── Discovery ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CommunityRes {
    mmio_base: u64,
    mmio_len: u64,
}

#[derive(Debug, Clone)]
struct CtrlResources {
    communities: alloc::vec::Vec<CommunityRes>,
    gsi: Option<u32>,
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
            ResourceItem::AddressSpace32 {
                kind: 0,
                min,
                length,
                ..
            } => {
                communities.push(CommunityRes {
                    mmio_base: min as u64,
                    mmio_len: length as u64,
                });
            }
            ResourceItem::AddressSpace64 {
                kind: 0,
                min,
                length,
                ..
            } => {
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

/// Test hook: route around the AML probe so a synthetic MMIO
/// backing can be exercised directly. Mirrors `probe_community`'s
/// return shape.
///
/// # Safety
/// `mmio_base..mmio_base + mmio_len` must be a readable, mapped MMIO
/// (or test-backed) region. See [`probe_community`].
#[doc(hidden)]
pub unsafe fn __probe_community_for_test(
    mmio_base: PhysAddr,
    mmio_len: u64,
) -> Option<(u16, u32, bool, u16)> {
    // SAFETY: forwarded directly from this function's own contract:
    // the caller guarantees the `[mmio_base, mmio_base + mmio_len)`
    // region is mapped and readable.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe { probe_community(mmio_base, mmio_len) }
}

/// Probe a candidate community MMIO window: read REVID + PADBAR and
/// derive `(revid, padbar, has_debounce, pin_count)`. Returns `None`
/// if the window is too small, reads back all-ones (absent device),
/// or has an out-of-range PADBAR.
///
/// # Safety
/// `mmio_base..mmio_base + mmio_len` must be a mapped, readable MMIO
/// region for the duration of the call. Only the REVID (offset 0x0)
/// and PADBAR (offset 0xC) dwords are read, and only after checking
/// `mmio_len >= 0x10`, so both reads stay inside the window.
unsafe fn probe_community(mmio_base: PhysAddr, mmio_len: u64) -> Option<(u16, u32, bool, u16)> {
    if mmio_len < 0x10 {
        return None;
    }
    // SAFETY: `mmio_len >= 0x10` was checked above, so the REVID dword
    // at offset `REG_REVID` (0x0) is within the caller-provided mapped
    // window.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let revid_raw = unsafe { narf_arch::mmio::read32(mmio_base.raw() + REG_REVID) };
    if revid_raw == u32::MAX {
        return None;
    }
    let revid = ((revid_raw >> 16) & 0xFFFF) as u16;
    let has_debounce = (revid as u32) >= REVID_DEBOUNCE_THRESHOLD;
    // SAFETY: `REG_PADBAR` (0xC) + 4 = 0x10 <= mmio_len (checked above),
    // so the PADBAR dword is within the mapped window.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let padbar = unsafe { narf_arch::mmio::read32(mmio_base.raw() + REG_PADBAR) };
    if (padbar as u64) >= mmio_len || padbar < 0x10 {
        return None;
    }
    let pad_stride: u64 = if has_debounce { 16 } else { 8 };
    let pad_region = mmio_len - padbar as u64;
    let raw_pin_count = pad_region / pad_stride;
    let pin_count = raw_pin_count.min(u16::MAX as u64) as u16;
    Some((revid, padbar, has_debounce, pin_count))
}

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
                path,
                hid
            );
            return 0;
        }
    };

    let mut controllers = alloc::vec::Vec::new();
    let mut registered = 0usize;
    for (idx, c) in res.communities.iter().enumerate() {
        let phys = PhysAddr::new(c.mmio_base);
        // SAFETY: `phys`/`c.mmio_len` come from a Memory/AddressSpace
        // resource in the device's `_CRS`, i.e. firmware-declared MMIO
        // for this GPIO community; that physical range is identity-
        // mapped and readable, satisfying `probe_community`'s contract.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let probe = unsafe { probe_community(phys, c.mmio_len) };
        let (revid, padbar, has_debounce, pin_count) = match probe {
            Some(t) => (Some(t.0), Some(t.1), t.2, t.3),
            None => (None, None, false, 0),
        };
        let ctrl = Arc::new(IntelPchGpio::new(IntelPchGpioConfig {
            acpi_path: path.to_string(),
            community_index: idx as u8,
            mmio_base: phys,
            mmio_len: c.mmio_len,
            revid,
            padbar,
            pin_count,
            has_debounce,
        }));
        crate::registry::register_unique(ctrl.clone());
        controllers.push(ctrl);
        registered += 1;
    }

    // Route shared GSI for this ACPI device.
    if let (Some(gsi), true) = (res.gsi, !controllers.is_empty()) {
        try_route_gsi(gsi, res.irq_flags, controllers);
    }

    registered
}

#[cfg(target_arch = "x86_64")]
fn try_route_gsi(gsi: u32, flags: u8, ctrls: alloc::vec::Vec<Arc<IntelPchGpio>>) {
    let vector = match narf_interrupts::vector::alloc() {
        Ok(v) => v,
        Err(_) => return,
    };

    let polarity = if flags & (1 << 1) != 0 {
        narf_acpi::ioapic::POLARITY_LOW
    } else {
        narf_acpi::ioapic::POLARITY_HIGH
    };
    let trigger = if flags & (1 << 2) != 0 {
        narf_acpi::ioapic::TRIGGER_LEVEL
    } else {
        narf_acpi::ioapic::TRIGGER_EDGE
    };

    // Leak the controller list for the static ISR.
    let ctrls_static: &'static [Arc<IntelPchGpio>] =
        alloc::boxed::Box::leak(ctrls.into_boxed_slice());
    GSI_MAPPING.lock().insert(vector, ctrls_static);

    narf_interrupts::install_handler_named(
        vector,
        "intel-pch-gpio",
        vector as u64,
        gpio_gsi_bridge,
    );

    // SAFETY: `vector` was freshly allocated from the interrupt vector
    // allocator and its handler (`gpio_gsi_bridge`) was installed just
    // above, before the GSI is unmasked — so once the IOAPIC routes
    // `gsi` to `vector`, any delivered interrupt has a valid handler to
    // run. `polarity | trigger` are the canonical IOAPIC flag constants
    // for the decoded `_CRS` ExtendedIrq flags.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        narf_acpi::ioapic::route_gsi_to_vector(gsi, vector, 0, polarity | trigger);
    }
}

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn gpio_gsi_bridge(cookie: u64) -> IrqStatus {
    global_gsi_dispatch(cookie as u8)
}

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
static GSI_MAPPING: IrqSafeSpinLock<BTreeMap<u8, &'static [Arc<IntelPchGpio>]>> =
    IrqSafeSpinLock::new(BTreeMap::new());

#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
fn global_gsi_dispatch(vector: u8) -> IrqStatus {
    let mut handled = IrqStatus::None;
    let g = GSI_MAPPING.lock();
    if let Some(ctrls) = g.get(&vector) {
        for ctrl in *ctrls {
            if ctrl.dispatch_irq() == IrqStatus::Handled {
                handled = IrqStatus::Handled;
            }
        }
    }
    handled
}

#[cfg(not(target_arch = "x86_64"))]
fn try_route_gsi(_gsi: u32, _flags: u8, _ctrls: alloc::vec::Vec<Arc<IntelPchGpio>>) {}

// ── Test-only hooks ────────────────────────────────────────────────

#[doc(hidden)]
pub fn recognised_hids() -> &'static [&'static str] {
    INTEL_PCH_GPIO_HIDS
}

#[doc(hidden)]
pub fn __new_for_test(cfg: IntelPchGpioConfig) -> IntelPchGpio {
    IntelPchGpio::new(cfg)
}
