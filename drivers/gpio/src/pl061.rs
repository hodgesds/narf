//! ARM PrimeCell PL061 GPIO controller (ARM DDI 0190) — the DT
//! binding (DT programme step 5). QEMU virt exposes one PL061 at
//! `0x0903_0000` (INTID 39); the same cell sits on many ARM SoCs.
//!
//! Eight pins. Data access is the PL061's masked form: the DATA
//! register's address bits [9:2] ARE the pin mask, so a single-pin
//! read/write touches only that pin. Direction lives in GPIODIR;
//! the shared [`GpioController`] trait has no direction setter
//! (the same is true for the AMD/Intel controllers), so direction
//! is programmed through this driver's inherent
//! [`Pl061::set_direction`] and `set_pin` consults GPIODIR
//! exactly like the AMD FCH driver consults its output-enable bit.
//!
//! Interrupts: `register_irq` programs GPIOIS/IBE/IEV/IE and
//! records the handler; [`Pl061::dispatch_pending`] is the
//! dispatch entry (reads GPIOMIS, clears via GPIOIC, calls the
//! handlers). Nothing in the tree hooks aarch64 GIC INTIDs into
//! the interrupt dispatch yet — the PL011 binding has the same
//! posture — so line delivery awaits that glue; the INTID is
//! published on the binding for it. PL061 has no pull
//! configuration hardware; `pull` arguments are accepted and
//! ignored (documented here so no consumer depends on them).

use alloc::string::String;
use alloc::sync::Arc;

use narf_lib::sync::IrqSafeSpinLock;
use narf_memory::ioremap::IoMapping;

use crate::{GpioController, GpioError, GpioIrqConfig, GpioIrqHandler, GpioPull};

// Register offsets (DDI 0190 §3). DATA is the masked window:
// offset (mask << 2) reads/writes only the masked pins.
const REG_DATA_BASE: usize = 0x000;
const REG_DIR: usize = 0x400;
const REG_IS: usize = 0x404;
const REG_IBE: usize = 0x408;
const REG_IEV: usize = 0x40C;
const REG_IE: usize = 0x410;
const REG_MIS: usize = 0x418;
const REG_IC: usize = 0x41C;
const REG_AFSEL: usize = 0x420;

/// PL061 pin count.
pub const PL061_PINS: u16 = 8;

/// One bound PL061 controller.
pub struct Pl061 {
    name: String,
    /// Kept so the ioremap lives as long as the controller (the
    /// PL011 pattern); `None` for the phys-mapped test form.
    _mapping: Option<IoMapping>,
    base_va: usize,
    handlers: IrqSafeSpinLock<[Option<GpioIrqHandler>; PL061_PINS as usize]>,
}

impl Pl061 {
    /// Construct over an ioremap'd register window.
    ///
    /// # Safety
    /// `mapping` must cover the PL061 register block (4 KiB).
    pub unsafe fn new(name: String, mapping: IoMapping) -> Self {
        let base_va = mapping.va() as usize;
        Self {
            name,
            _mapping: Some(mapping),
            base_va,
            handlers: IrqSafeSpinLock::new([None; PL061_PINS as usize]),
        }
    }

    /// Test-only constructor over a phys (direct-map) window —
    /// the `amd_fch::__new_for_test` pattern.
    ///
    /// # Safety
    /// Same contract as the AMD FCH test constructor: the window
    /// must be RAM (or real PL061 MMIO) for the controller's life.
    #[cfg(any(test, feature = "kernel-test"))]
    pub unsafe fn __new_for_test(name: &str, mmio_base: narf_memory::PhysAddr, len: usize) -> Self {
        let _ = len;
        Self {
            name: String::from(name),
            _mapping: None,
            base_va: mmio_base.raw() as usize,
            handlers: IrqSafeSpinLock::new([None; PL061_PINS as usize]),
        }
    }

    fn read_reg(&self, off: usize) -> u32 {
        // SAFETY: base_va covers the PL061 register block by
        // constructor contract; offsets are the fixed register map.
        unsafe { core::ptr::read_volatile((self.base_va + off) as *const u32) }
    }

    fn write_reg(&self, off: usize, v: u32) {
        // SAFETY: same contract as read_reg.
        unsafe { core::ptr::write_volatile((self.base_va + off) as *mut u32, v) }
    }

    fn set_bit(&self, off: usize, pin: u16, on: bool) {
        let v = self.read_reg(off);
        let bit = 1u32 << pin;
        self.write_reg(off, if on { v | bit } else { v & !bit });
    }

    fn pin_ok(pin: u16) -> Result<(), GpioError> {
        if pin < PL061_PINS {
            Ok(())
        } else {
            Err(GpioError::InvalidPin)
        }
    }

    /// Program a pin's direction (`true` = output). Driver-specific
    /// surface: the shared trait intentionally has no direction
    /// setter (see the module docs).
    pub fn set_direction(&self, pin: u16, output: bool) -> Result<(), GpioError> {
        Self::pin_ok(pin)?;
        self.set_bit(REG_DIR, pin, output);
        Ok(())
    }

    /// Current direction of a pin (`true` = output).
    pub fn direction(&self, pin: u16) -> Result<bool, GpioError> {
        Self::pin_ok(pin)?;
        Ok(self.read_reg(REG_DIR) & (1 << pin) != 0)
    }

    /// Dispatch pending interrupts: snapshot GPIOMIS, clear it,
    /// and call each registered handler. Returns the number of
    /// pins dispatched. This is the entry the aarch64 IRQ glue
    /// will call when it lands (and what the smokes drive).
    pub fn dispatch_pending(&self) -> u32 {
        let mis = self.read_reg(REG_MIS) & 0xFF;
        if mis == 0 {
            return 0;
        }
        self.write_reg(REG_IC, mis);
        let snapshot = *self.handlers.lock();
        let mut n = 0;
        for pin in 0..PL061_PINS {
            if mis & (1 << pin) != 0 {
                if let Some(handler) = snapshot[pin as usize] {
                    handler(pin);
                    n += 1;
                }
            }
        }
        n
    }
}

impl core::fmt::Debug for Pl061 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Pl061")
            .field("name", &self.name)
            .field("base_va", &self.base_va)
            .finish_non_exhaustive()
    }
}

impl GpioController for Pl061 {
    fn name(&self) -> &str {
        &self.name
    }

    fn pin_count(&self) -> u16 {
        PL061_PINS
    }

    fn read_pin(&self, pin: u16) -> Result<bool, GpioError> {
        Self::pin_ok(pin)?;
        // Masked data read: only this pin's bit can be set.
        let mask_off = (1usize << pin) << 2;
        Ok(self.read_reg(REG_DATA_BASE + mask_off) != 0)
    }

    fn set_pin(&self, pin: u16, value: bool) -> Result<(), GpioError> {
        Self::pin_ok(pin)?;
        if self.read_reg(REG_DIR) & (1 << pin) == 0 {
            return Err(GpioError::WrongDirection);
        }
        let mask_off = (1usize << pin) << 2;
        self.write_reg(REG_DATA_BASE + mask_off, if value { 1 << pin } else { 0 });
        Ok(())
    }

    fn register_irq(
        &self,
        pin: u16,
        _pull: GpioPull,
        irq: GpioIrqConfig,
        handler: GpioIrqHandler,
    ) -> Result<(), GpioError> {
        Self::pin_ok(pin)?;
        // PL061 cannot sense "both levels" — level + ActiveBoth is
        // the one configuration the hardware cannot express.
        if irq.level_triggered && irq.polarity == 2 {
            return Err(GpioError::BadHardware);
        }
        {
            let mut tab = self.handlers.lock();
            match tab[pin as usize] {
                Some(existing) if existing as usize != handler as usize => {
                    return Err(GpioError::AlreadyRegistered);
                }
                _ => tab[pin as usize] = Some(handler),
            }
        }
        // Sense: IS=1 level, IS=0 edge. Both-edges (edges only)
        // sets IBE; single-edge and level use IEV for polarity.
        self.set_bit(REG_IS, pin, irq.level_triggered);
        if !irq.level_triggered && irq.polarity == 2 {
            self.set_bit(REG_IBE, pin, true);
        } else {
            self.set_bit(REG_IBE, pin, false);
            self.set_bit(REG_IEV, pin, irq.polarity == 0);
        }
        // Clear any stale pending state, then unmask.
        self.write_reg(REG_IC, 1 << pin);
        self.set_bit(REG_IE, pin, true);
        Ok(())
    }

    fn unregister_irq(&self, pin: u16) {
        if pin >= PL061_PINS {
            return;
        }
        self.set_bit(REG_IE, pin, false);
        self.handlers.lock()[pin as usize] = None;
    }
}

// ── DT binding ──────────────────────────────────────────────────

/// What the PL061 DT binding bound (test introspection, PL011
/// shape).
#[derive(Debug)]
pub struct Pl061BoundInfo {
    /// GIC INTID the binding resolved, if the node carried one.
    pub intid: Option<u32>,
    /// Controller registry name.
    pub name: String,
}

pub(crate) static BOUND: IrqSafeSpinLock<Option<Pl061BoundInfo>> = IrqSafeSpinLock::new(None);

/// Test introspection: the INTID the DT binding resolved.
#[cfg(any(test, feature = "kernel-test"))]
pub fn bound_intid_for_test() -> Option<u32> {
    BOUND.lock().as_ref().and_then(|b| b.intid)
}

/// Test introspection: clear the bound record (smoke isolation).
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_bound_for_test() {
    *BOUND.lock() = None;
}

/// Register this crate's DT match entries with the bus match
/// table. Called from `register_initcalls` — composition-time
/// registration, census-neutral (bus registry state, not an
/// initcall); see the programme note in the crate docs.
pub fn register_dt_drivers() {
    narf_bus::register_dt_driver(narf_bus::DtMatch {
        name: "pl061",
        compatible: "arm,pl061",
        probe: probe_dt,
    });
}

fn probe_dt(
    dev: narf_bus::BusDevice,
    _cap: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
) -> Result<(), narf_bus::ProbeError> {
    use narf_bus::ProbeError;
    use narf_memory::ioremap::{ioremap, MmioAttrs};
    let narf_bus::BusKind::Platform(rec) = dev.kind else {
        return Err(ProbeError::NotForThisDriver);
    };
    let win = rec.reg_windows().first().ok_or(ProbeError::BadDevice)?;
    // SAFETY: the window is the device's DT reg window; ioremap
    // maps it device-nongathering for the binding's lifetime.
    let mapping = unsafe { ioremap(win.base.raw(), win.len.max(0x1000), MmioAttrs::Device) }
        .map_err(|_| ProbeError::Other("pl061: ioremap of the DT reg window failed"))?;
    let name = alloc::format!("pl061@{:#x}", win.base.raw());
    // SAFETY: the ioremap covers the PL061 register block.
    let ctrl = unsafe { Pl061::new(name.clone(), mapping) };
    // Software control of all pins (AFSEL=0), the Linux pl061
    // probe posture; directions stay at their reset state (input)
    // until a consumer programs them via set_direction.
    ctrl.write_reg(REG_AFSEL, 0);
    let intid = rec.irq_list().first().map(|i| i.intid);
    crate::registry::register_unique(Arc::new(ctrl));
    *BOUND.lock() = Some(Pl061BoundInfo { intid, name });
    Ok(())
}
