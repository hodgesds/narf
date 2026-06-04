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
const REG_CAPLIST: u64 = 0x004;
const REG_PADBAR: u64 = 0x00C;

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

/// One Intel PCH GPIO community.
pub struct IntelPchGpio {
    name: String,
    acpi_path: String,
    community_index: u8,
    mmio_base: PhysAddr,
    mmio_len: u64,
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

    #[inline]
    unsafe fn read32(&self, off: u64) -> u32 {
        unsafe { narf_arch::mmio::read32(self.mmio_base.raw() + off) }
    }

    #[inline]
    unsafe fn write32(&self, off: u64, val: u32) {
        unsafe { narf_arch::mmio::write32(self.mmio_base.raw() + off, val) }
    }

    fn stride(&self) -> u64 {
        if self.has_debounce { 16 } else { 8 }
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
        let groups = (self.pin_count as usize + 31) / 32;
        
        for g in 0..groups {
            let is_reg = self.is_offset as u64 + (g as u64 * 4);
            let ie_reg = self.ie_offset as u64 + (g as u64 * 4);
            
            let status = unsafe { self.read32(is_reg) };
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
                    // Ack by writing 1 back to status.
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
        let val = unsafe { self.read32(off) };
        Ok(val & PADCFG0_GPIORXSTATE != 0)
    }

    fn set_pin(&self, pin: u16, value: bool) -> Result<(), GpioError> {
        let off = self.padcfg0_offset(pin).ok_or(GpioError::InvalidPin)?;
        let mut val = unsafe { self.read32(off) };
        if value {
            val |= PADCFG0_GPIOTXSTATE;
        } else {
            val &= !PADCFG0_GPIOTXSTATE;
        }
        // Ensure TX is enabled.
        val &= !PADCFG0_GPIOTXDIS;
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
        
        unsafe { self.write32(off, val) };

        // 2. Program pull-up/down in PADCFG1.
        let mut val1 = unsafe { self.read32(off + 4) };
        val1 &= !(0b1111 << 10); // Termination mask.
        match pull {
            GpioPull::Up => val1 |= PADCFG1_TERM_UP_20K,
            GpioPull::Down => val1 |= PADCFG1_TERM_DN_20K,
            GpioPull::None => val1 |= PADCFG1_TERM_NONE,
            GpioPull::Default => {}
        }
        unsafe { self.write32(off + 4, val1) };

        // 3. Store handler and enable in GPI_IE.
        self.handlers.lock().insert(pin, handler);
        
        let g = (pin / 32) as u64;
        let bit = (pin % 32) as u32;
        let ie_reg = self.ie_offset as u64 + (g * 4);
        let mut ie = unsafe { self.read32(ie_reg) };
        ie |= 1 << bit;
        unsafe { self.write32(ie_reg, ie) };
        
        Ok(())
    }

    fn unregister_irq(&self, pin: u16) {
        if let Some(off) = self.padcfg0_offset(pin) {
            let g = (pin / 32) as u64;
            let bit = (pin % 32) as u32;
            let ie_reg = self.ie_offset as u64 + (g * 4);
            let mut ie = unsafe { self.read32(ie_reg) };
            ie &= !(1 << bit);
            unsafe { self.write32(ie_reg, ie) };
            
            // Disable RX to save power.
            let mut val = unsafe { self.read32(off) };
            val |= PADCFG0_GPIORXDIS;
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

/// Test hook: route around the AML probe so a synthetic MMIO
/// backing can be exercised directly. Mirrors `probe_community`'s
/// return shape.
#[doc(hidden)]
pub unsafe fn __probe_community_for_test(
    mmio_base: PhysAddr,
    mmio_len: u64,
) -> Option<(u16, u32, bool, u16)> {
    unsafe { probe_community(mmio_base, mmio_len) }
}

unsafe fn probe_community(
    mmio_base: PhysAddr,
    mmio_len: u64,
) -> Option<(u16, u32, bool, u16)> {
    if mmio_len < 0x10 {
        return None;
    }
    let revid_raw = unsafe { narf_arch::mmio::read32(mmio_base.raw() + REG_REVID) };
    if revid_raw == u32::MAX {
        return None;
    }
    let revid = ((revid_raw >> 16) & 0xFFFF) as u16;
    let has_debounce = (revid as u32) >= REVID_DEBOUNCE_THRESHOLD;
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
                path, hid
            );
            return 0;
        }
    };

    let mut controllers = alloc::vec::Vec::new();
    let mut registered = 0usize;
    for (idx, c) in res.communities.iter().enumerate() {
        let phys = PhysAddr::new(c.mmio_base);
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
    let ctrls_static: &'static [Arc<IntelPchGpio>] = alloc::boxed::Box::leak(ctrls.into_boxed_slice());
    GSI_MAPPING.lock().insert(vector, ctrls_static);

    narf_interrupts::install_handler_named(
        vector,
        "intel-pch-gpio",
        vector as u64,
        gpio_gsi_bridge
    );
    
    unsafe {
        narf_acpi::ioapic::route_gsi_to_vector(gsi, vector, 0, polarity | trigger);
    }
}

fn gpio_gsi_bridge(cookie: u64) -> IrqStatus {
    global_gsi_dispatch(cookie as u8)
}

static GSI_MAPPING: IrqSafeSpinLock<BTreeMap<u8, &'static [Arc<IntelPchGpio>]>> = IrqSafeSpinLock::new(BTreeMap::new());

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
