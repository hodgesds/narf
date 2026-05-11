//! AMD FCH GPIO controller — AMDI0030 ACPI HID.
//!
//! Clean-room implementation. Public, non-GPL sources only:
//! - AMD Family 17h Models 30h-3Fh PPR (Renoir / Picasso) — the FCH
//!   GPIO section publishes the 32-bit per-pin register layout this
//!   driver programs.
//!   <https://www.amd.com/system/files/TechDocs/55922-A1_PUB.zip>
//! - AMD Family 17h Models 60h-6Fh PPR (Lucienne / Renoir refresh).
//!   <https://www.amd.com/system/files/TechDocs/56176-A1_PUB.zip>
//! - ACPI 6.5 §6.4.3.8.1 (GpioInt resource template) — defines the
//!   level/polarity bits this driver consumes from `_CRS`.
//!   <https://uefi.org/specs/ACPI/6.5/>
//!
//! Per-pin register layout (PinControl[N], offset = N * 4):
//! - bit 11: Interrupt Status (RW1C — write 1 to clear)
//! - bit 12: Wake Status (RW1C)
//! - bit 16: PinSts — current pin level (read-only mirror of input)
//! - bit 21: Output Value — driven onto the pin when bit 22 = 1
//! - bit 22: Output Enable — 1 = drive, 0 = high-Z input
//! - bit 23: Pin Sw Cntrl In (debounce path enable)
//! - bit 28: Interrupt Enable — 1 = unmasked
//! - bit 29: Interrupt Delivery Enable — 1 = route to controller IRQ
//! - bits 9-10: Trigger / Active-level select for interrupts
//!     - bit 9 = TriggerType (0=edge, 1=level)
//!     - bit 10 = ActiveLevel (0=low, 1=high)
//!     - both set + bit 8 = both edges
//! - bits 17-19: Pull control (PullUpEnable / PullDownEnable / select)
//!
//! The block is a single MMIO window (typically 0xFED81500..0xFED81800,
//! 0x300 bytes = 192 pins, but laptops often expose 256 or more).
//! All pins share one GSI; the ISR scans pin-status registers in
//! 64-pin chunks (one cache line of 16 dwords) to find which
//! pin(s) fired.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use narf_aml::resource::ResourceItem;
use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::PhysAddr;

use crate::{GpioController, GpioError, GpioIrqConfig, GpioIrqHandler, GpioPull};

const AMD_FCH_GPIO_HID: &str = "AMDI0030";

// ── Per-pin register bits ──────────────────────────────────────────
const BIT_TRIGGER_LEVEL: u32 = 1 << 9;
const BIT_ACTIVE_HIGH: u32 = 1 << 10;
const BIT_INTR_STATUS: u32 = 1 << 11;
const BIT_PIN_STS: u32 = 1 << 16;
const BIT_PULL_UP: u32 = 1 << 19;
const BIT_PULL_DOWN: u32 = 1 << 20;
const BIT_OUTPUT_VALUE: u32 = 1 << 22;
const BIT_OUTPUT_ENABLE: u32 = 1 << 23;
const BIT_INTR_ENABLE: u32 = 1 << 28;
const BIT_INTR_DELIVERY: u32 = 1 << 29;

const PULL_MASK: u32 = BIT_PULL_UP | BIT_PULL_DOWN;
const TRIGGER_MASK: u32 = BIT_TRIGGER_LEVEL | BIT_ACTIVE_HIGH;
const INTR_CFG_MASK: u32 = BIT_INTR_ENABLE | BIT_INTR_DELIVERY | TRIGGER_MASK;

/// Maximum pins this driver supports. The AMD FCH block on Zen2
/// laptops exposes up to 256 pins (MMIO window 1 KiB); the array
/// of handlers is sized to match. Boards with smaller windows
/// just leave the upper slots `None`.
const MAX_PINS: usize = 256;

/// One AMD FCH GPIO controller.
pub struct AmdFchGpio {
    name: String,
    mmio_base: PhysAddr,
    mmio_len: u64,
    pin_count: u16,
    /// Allocated IDT vector + GSI. `None` when routing failed; in
    /// that case `register_irq` still installs the handler but it
    /// never fires.
    irq_vector: Option<u8>,
    /// Per-pin handler table. IrqSafeSpinLock so the ISR can scan
    /// it without disabling interrupts on the kernel side.
    handlers: IrqSafeSpinLock<[Option<GpioIrqHandler>; MAX_PINS]>,
}

impl core::fmt::Debug for AmdFchGpio {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AmdFchGpio")
            .field("name", &self.name)
            .field("mmio_base", &self.mmio_base)
            .field("mmio_len", &self.mmio_len)
            .field("pin_count", &self.pin_count)
            .field("irq_vector", &self.irq_vector)
            .finish()
    }
}

impl AmdFchGpio {
    pub fn new(
        name: String,
        mmio_base: PhysAddr,
        mmio_len: u64,
        irq_vector: Option<u8>,
    ) -> Self {
        let pin_count = (mmio_len / 4).min(MAX_PINS as u64) as u16;
        Self {
            name,
            mmio_base,
            mmio_len,
            pin_count,
            irq_vector,
            handlers: IrqSafeSpinLock::new([None; MAX_PINS]),
        }
    }

    fn pin_offset(&self, pin: u16) -> Option<u64> {
        if pin >= self.pin_count {
            None
        } else {
            Some(pin as u64 * 4)
        }
    }

    #[inline]
    unsafe fn read_reg(&self, off: u64) -> u32 {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: caller asserts pin index in range.
        unsafe { narf_arch::mmio::read32(self.mmio_base.raw() + off) }
    }

    #[inline]
    unsafe fn write_reg(&self, off: u64, val: u32) {
        debug_assert!(off + 4 <= self.mmio_len);
        // SAFETY: same.
        unsafe { narf_arch::mmio::write32(self.mmio_base.raw() + off, val) }
    }
}

impl GpioController for AmdFchGpio {
    fn name(&self) -> &str {
        &self.name
    }

    fn pin_count(&self) -> u16 {
        self.pin_count
    }

    fn read_pin(&self, pin: u16) -> Result<bool, GpioError> {
        let off = self.pin_offset(pin).ok_or(GpioError::InvalidPin)?;
        // SAFETY: offset is bounded by pin_offset.
        let v = unsafe { self.read_reg(off) };
        Ok(v & BIT_PIN_STS != 0)
    }

    fn set_pin(&self, pin: u16, value: bool) -> Result<(), GpioError> {
        let off = self.pin_offset(pin).ok_or(GpioError::InvalidPin)?;
        // SAFETY: offset bounded.
        let mut v = unsafe { self.read_reg(off) };
        if v & BIT_OUTPUT_ENABLE == 0 {
            return Err(GpioError::WrongDirection);
        }
        if value {
            v |= BIT_OUTPUT_VALUE;
        } else {
            v &= !BIT_OUTPUT_VALUE;
        }
        // SAFETY: same.
        unsafe { self.write_reg(off, v) };
        Ok(())
    }

    fn register_irq(
        &self,
        pin: u16,
        pull: GpioPull,
        irq: GpioIrqConfig,
        handler: GpioIrqHandler,
    ) -> Result<(), GpioError> {
        let off = self.pin_offset(pin).ok_or(GpioError::InvalidPin)?;

        // Slot bookkeeping first — refuse a different handler if one
        // is already installed; same handler is idempotent.
        {
            let mut tab = self.handlers.lock();
            match tab[pin as usize] {
                Some(existing) if existing as usize == handler as usize => {}
                Some(_) => return Err(GpioError::AlreadyRegistered),
                None => {}
            }
            tab[pin as usize] = Some(handler);
        }

        // Track this controller as the dispatch target for shared
        // ISR fan-out; idempotent across pins on the same controller.
        // SAFETY: we just stored ourselves; the address is stable
        // for the lifetime of the registry entry (Arc-pinned).
        register_for_dispatch(self as *const _);

        // Program pin: clear pull bits + trigger bits, then set
        // requested ones; ensure output disable; arm interrupt.
        // SAFETY: offset bounded.
        let mut v = unsafe { self.read_reg(off) };
        v &= !PULL_MASK;
        v &= !INTR_CFG_MASK;
        v &= !BIT_OUTPUT_ENABLE; // force input

        match pull {
            GpioPull::Up => v |= BIT_PULL_UP,
            GpioPull::Down => v |= BIT_PULL_DOWN,
            GpioPull::None | GpioPull::Default => {}
        }
        if irq.level_triggered {
            v |= BIT_TRIGGER_LEVEL;
        }
        // polarity: 0=ActiveHigh, 1=ActiveLow, 2=ActiveBoth
        match irq.polarity {
            0 => v |= BIT_ACTIVE_HIGH,
            1 => {}
            2 => {
                // Active-both: set both trigger and active-high; AMD's
                // bit 8 distinguishes "either edge" but the basic
                // edge-active-high config is the closest single-mode
                // approximation when bit 8 isn't available.
                v |= BIT_ACTIVE_HIGH;
            }
            _ => {}
        }
        v |= BIT_INTR_ENABLE | BIT_INTR_DELIVERY;
        // Clear any latched status before unmasking so we don't
        // dispatch a stale fire.
        v |= BIT_INTR_STATUS;
        // SAFETY: same.
        unsafe { self.write_reg(off, v) };
        Ok(())
    }

    fn unregister_irq(&self, pin: u16) {
        let off = match self.pin_offset(pin) {
            Some(o) => o,
            None => return,
        };
        // SAFETY: offset bounded.
        let mut v = unsafe { self.read_reg(off) };
        v &= !INTR_CFG_MASK;
        // Write-1-to-clear any latched interrupt + wake status so
        // the next register_irq starts from a clean slate.
        v |= BIT_INTR_STATUS;
        // SAFETY: same.
        unsafe { self.write_reg(off, v) };
        let mut tab = self.handlers.lock();
        tab[pin as usize] = None;
    }
}

// ── ISR dispatch ───────────────────────────────────────────────────
//
// Every AmdFchGpio that registers any pin's IRQ also registers
// itself as a dispatch target. The shared IDT vector handler walks
// the dispatch table, scans each controller for fired pins, and
// invokes the per-pin handler. The dispatch table is small (one
// entry per FCH GPIO block — most laptops have exactly one) and
// stable across boot: register-only, no unregister surface.

const MAX_DISPATCH: usize = 4;
/// Pointers stored as `usize` because raw pointers aren't `Send` and
/// the array lives in a `static`. Each slot is a `*const AmdFchGpio`
/// to a registry-pinned controller — see `register_for_dispatch`'s
/// safety contract.
static DISPATCH: IrqSafeSpinLock<[usize; MAX_DISPATCH]> =
    IrqSafeSpinLock::new([0usize; MAX_DISPATCH]);
static DISPATCH_LEN: AtomicUsize = AtomicUsize::new(0);

fn register_for_dispatch(p: *const AmdFchGpio) {
    let pv = p as usize;
    let mut tab = DISPATCH.lock();
    if tab.iter().any(|&q| q == pv) {
        return;
    }
    let len = DISPATCH_LEN.load(Ordering::Acquire);
    if len < MAX_DISPATCH {
        tab[len] = pv;
        DISPATCH_LEN.store(len + 1, Ordering::Release);
    }
}

fn shared_isr() {
    let len = DISPATCH_LEN.load(Ordering::Acquire);
    let snap: [usize; MAX_DISPATCH] = *DISPATCH.lock();
    for &pv in &snap[..len] {
        if pv == 0 {
            continue;
        }
        // SAFETY: pv was pushed by register_for_dispatch, which is
        // only called from a method on an Arc-pinned controller
        // owned by the global registry; the registry's slot is
        // never dropped after boot.
        let ctrl = unsafe { &*(pv as *const AmdFchGpio) };
        ctrl.dispatch_irqs();
    }
}

impl AmdFchGpio {
    /// Walk every pin, dispatch handler if InterruptStatus is set,
    /// and clear (write-1-to-clear) the latched status.
    fn dispatch_irqs(&self) {
        // Snapshot handler table inside the lock so the dispatch
        // body doesn't hold the spinlock across the user handler.
        let snapshot: [Option<GpioIrqHandler>; MAX_PINS] = *self.handlers.lock();
        for pin in 0..self.pin_count {
            let off = pin as u64 * 4;
            // SAFETY: pin < pin_count guarantees off + 4 <= mmio_len.
            let v = unsafe { self.read_reg(off) };
            if v & BIT_INTR_STATUS == 0 {
                continue;
            }
            // Clear status (RW1C) before invoking the handler so a
            // re-fire during the handler doesn't get lost.
            // SAFETY: same.
            unsafe { self.write_reg(off, v | BIT_INTR_STATUS) };
            if let Some(h) = snapshot[pin as usize] {
                h(pin);
            }
        }
    }
}

// ── Discovery ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CtrlResources {
    mmio_base: u64,
    mmio_len: u64,
    gsi: Option<u32>,
    irq_flags: u8,
}

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

static GSI_ROUTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_arch = "x86_64")]
fn route_shared_gsi(gsi: u32, acpi_flags: u8) -> Option<u8> {
    // The FCH GPIO block has a single shared GSI; route it once
    // even if multiple controllers exist (rare on AMD; one block
    // per socket).
    if GSI_ROUTED.load(Ordering::Acquire) {
        return None;
    }
    let v = narf_interrupts::vector::alloc().ok()?;
    let pol = if acpi_flags & (1 << 1) != 0 {
        narf_acpi::ioapic::POLARITY_LOW
    } else {
        narf_acpi::ioapic::POLARITY_HIGH
    };
    let trig = if acpi_flags & (1 << 2) != 0 {
        narf_acpi::ioapic::TRIGGER_LEVEL
    } else {
        narf_acpi::ioapic::TRIGGER_EDGE
    };
    narf_interrupts::install_handler(v, shared_isr);
    // SAFETY: vector + handler installed before unmask.
    if unsafe { narf_acpi::ioapic::route_gsi_to_vector(gsi, v, 0, pol | trig) } {
        GSI_ROUTED.store(true, Ordering::Release);
        Some(v)
    } else {
        let _ = narf_interrupts::vector::free(v);
        None
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn route_shared_gsi(_gsi: u32, _acpi_flags: u8) -> Option<u8> {
    None
}

/// Walk every AMDI0030 device in the AML namespace, instantiate +
/// register a controller. Returns the count successfully registered.
pub fn probe_all() -> usize {
    let mut count = 0usize;
    for node in narf_aml::find_all_devices_by_hid(AMD_FCH_GPIO_HID) {
        if probe_one(&node.path).is_some() {
            count += 1;
        }
    }
    count
}

fn probe_one(path: &str) -> Option<()> {
    use core::fmt::Write;

    let res = decode_ctrl_crs(path)?;
    let irq_vec = res.gsi.and_then(|g| route_shared_gsi(g, res.irq_flags));

    let driver = Arc::new(AmdFchGpio::new(
        path.to_string(),
        PhysAddr::new(res.mmio_base),
        res.mmio_len,
        irq_vec,
    ));
    let _ = crate::registry::register_unique(driver);

    let _ = writeln!(
        narf_console::Writer,
        "  amd-fch-gpio: {} mmio={:#x}+{:#x} gsi={} vec={}",
        path,
        res.mmio_base,
        res.mmio_len,
        res.gsi.map(|g| format!("{}", g)).unwrap_or_else(|| "none".into()),
        irq_vec
            .map(|v| format!("{}", v))
            .unwrap_or_else(|| "polled".into()),
    );
    Some(())
}

/// Test-only: HID we recognise.
#[doc(hidden)]
pub fn recognised_hid() -> &'static str {
    AMD_FCH_GPIO_HID
}

/// Test-only: drain dispatch table so each smoke starts fresh.
#[doc(hidden)]
pub fn __reset_dispatch_for_test() {
    let mut tab = DISPATCH.lock();
    for slot in tab.iter_mut() {
        *slot = 0;
    }
    DISPATCH_LEN.store(0, Ordering::Release);
    GSI_ROUTED.store(false, Ordering::Release);
}

/// Test-only: drive the shared ISR exactly as the IDT would.
#[doc(hidden)]
pub fn __dispatch_for_test() {
    shared_isr();
}
