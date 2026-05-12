//! Input drivers (Stage-3 onwards).
//!
//! M0 surface: i8042 PS/2 keyboard on x86_64. Future modules:
//! virtio-input (cross-arch, lives under drivers/virtio/), USB HID
//! (depends on the xHCI stack maturing past structural-probe).
//!   <https://www.usb.org/document-library/device-class-definition-hid-111>

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]

extern crate alloc;

pub mod i2c_hid;
pub mod i2c_hid_bind;
#[cfg(target_arch = "x86_64")]
pub mod i8042;
#[cfg(target_arch = "x86_64")]
pub mod i8042_mouse;
pub mod wbdi;

/// Stage::Device initcalls for this driver crate.
///
/// Cross-arch: i2c-hid (PNP0C50 over an AMD-FCH or other I2C
/// controller). Dominant input class on ARM laptops/tablets and
/// modern x86 thin-and-lights — the cfg gate below previously
/// confined the whole register_initcalls body to x86_64 and
/// silently dropped i2c-hid on aarch64.
///
/// x86_64-only: i8042 PS/2 keyboard + mouse (no PS/2 controller
/// outside legacy PC platforms).
///
/// IRQ wiring (x86_64 i8042 path): each channel's handler
/// (`i8042::on_irq1`, `i8042_mouse::on_irq12`) gets routed
/// through the IOAPIC at its ISA-default GSI (1 for keyboard, 12
/// for mouse), with any MADT Interrupt Source Override applied
/// to remap the line. ISA bus default = edge-triggered
/// active-high (PC AT spec); ISO overrides honoured if present.
pub fn register_initcalls() {
    // i2c-hid-probe + i2c-hid-bind run on every arch — they
    // walk the AML namespace which is arch-independent.
    i2c_hid::register_initcalls();

    #[cfg(target_arch = "x86_64")]
    register_i8042_initcalls();
}

#[cfg(target_arch = "x86_64")]
fn register_i8042_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "i8042-kbd", || {
        // SAFETY: BSP boot context, no other agent driving 0x60/0x64.
        match unsafe { i8042::init() } {
            Ok(()) => {
                // SAFETY: ISA IRQ → IOAPIC routing call; the
                // handler is `pub unsafe fn on_irq1` because the
                // i8042 read it does is unsafe at module level,
                // but installation through the dispatch table is
                // safe (just stores a fn ptr).
                if !install_isa_irq(1, on_irq1_safe) {
                    // Routing failed — keyboard polled-only;
                    // not fatal.
                }
                InitResult::Ok
            }
            Err(_) => InitResult::NotPresent,
        }
    });
    narf_init::register(Stage::Device, "i8042-mouse", || {
        // SAFETY: BSP, post-keyboard-init.
        match unsafe { i8042_mouse::init() } {
            Ok(()) => {
                if !install_isa_irq(12, on_irq12_safe) {
                    // Routing failed — mouse polled-only.
                }
                InitResult::Ok
            }
            Err(_) => InitResult::NotPresent,
        }
    });
}

/// Wrapper to convert the `unsafe fn on_irq1` to the safe `fn()`
/// signature `narf_interrupts::install_handler` expects.
#[cfg(target_arch = "x86_64")]
fn on_irq1_safe() {
    // SAFETY: dispatch context — ISR runs with IRQs masked,
    // single-CPU ownership of the i8042 ports for the duration
    // of one handler invocation.
    unsafe {
        i8042::on_irq1();
    }
}

#[cfg(target_arch = "x86_64")]
fn on_irq12_safe() {
    // SAFETY: same.
    unsafe {
        i8042_mouse::on_irq12();
    }
}

/// Wire an ISA IRQ → IOAPIC route + install the synchronous
/// dispatch-table handler. Walks MADT ISO overrides to honour
/// any GSI / polarity / trigger remap for `isa_irq`.
///
/// Returns `false` when the routing fails (no MADT, no IOAPIC
/// covers the GSI, vector::alloc failed) — caller treats this
/// as "device works but only via polling fallback".
#[cfg(target_arch = "x86_64")]
fn install_isa_irq(isa_irq: u8, handler: fn()) -> bool {
    let mut overrides = [narf_acpi::IsaOverride::default(); narf_acpi::MAX_ISA_OVERRIDES];
    let n = narf_acpi::copy_isa_overrides(&mut overrides);
    let (gsi, flags) = overrides[..n]
        .iter()
        .find(|ov| ov.bus == 0 && ov.source == isa_irq)
        .map(|ov| {
            // ACPI 6.5 §5.2.12.5 flag decode (bus default for
            // ISA = active-high edge).
            let pol = match ov.flags & 0b11 {
                0b11 => narf_acpi::ioapic::POLARITY_LOW,
                _ => narf_acpi::ioapic::POLARITY_HIGH,
            };
            let trig = match (ov.flags >> 2) & 0b11 {
                0b11 => narf_acpi::ioapic::TRIGGER_LEVEL,
                _ => narf_acpi::ioapic::TRIGGER_EDGE,
            };
            (ov.gsi, pol | trig)
        })
        .unwrap_or((
            isa_irq as u32,
            narf_acpi::ioapic::POLARITY_HIGH | narf_acpi::ioapic::TRIGGER_EDGE,
        ));
    let v = match narf_interrupts::vector::alloc() {
        Ok(v) => v,
        Err(_) => return false,
    };
    narf_interrupts::install_handler(v, handler);
    // SAFETY: vector + handler installed before the IOAPIC
    // unmasks the line.
    unsafe { narf_acpi::ioapic::route_gsi_to_vector(gsi, v, 0, flags) }
}

// Per-crate smoke tests register against `narf-kernel-test` and
// land in the same `narf.tests` ELF section as the rest of the
// suite.
#[cfg(target_arch = "x86_64")]
mod tests;
