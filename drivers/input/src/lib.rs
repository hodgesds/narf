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

pub mod hid_elan;
pub mod hid_mt_features;
pub mod hid_multitouch;
pub mod hid_rmi;
pub mod hid_sensor;
pub mod i2c_hid;
pub mod i2c_hid_bind;
pub mod i2c_hid_touch;
#[cfg(target_arch = "x86_64")]
pub mod i8042;
#[cfg(target_arch = "x86_64")]
pub mod i8042_mouse;
pub mod rmi4_core;
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

    // HID multi-touch class driver — banner + class-table load.
    // Transport-specific probes (USB / i2c-HID) call into
    // `hid_multitouch::MtDevice::attach` when they find an
    // MT-shaped Report Descriptor.
    hid_multitouch::register_initcalls();

    // hid-rmi (Synaptics RMI4 over HID) — banner + device-id
    // table load. The USB-HID transport reads
    // `hid_rmi::RMI_DEVICE_TABLE` and `match_device()` when it
    // sees a Synaptics VID at enumeration time.
    hid_rmi::register_initcalls();

    // hid-elan — banner + device-id table load. Used by the i2c-HID
    // and USB-HID transports to recognise Elan touchpads with
    // vendor-specific report formats (HP Pavilion X2, Toshiba Click,
    // and a slice of Lenovo/Acer/MSI laptops).
    hid_elan::register_initcalls();

    #[cfg(target_arch = "x86_64")]
    register_i8042_initcalls();
}

#[cfg(target_arch = "x86_64")]
fn register_i8042_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "i8042-kbd", || {
        // SAFETY: BSP boot context, no other agent driving 0x60/0x64.
        let init_res = unsafe { i8042::init() };
        let init_ok = init_res.is_ok();
        narf_input::I8042_KBD_INIT_OK.store(init_ok, core::sync::atomic::Ordering::Release);
        if !init_ok {
            return InitResult::NotPresent;
        }
        // SAFETY: ISA IRQ → IOAPIC routing call; the handler is
        // `pub unsafe fn on_irq1` because the i8042 read it does
        // is unsafe at module level, but installation through the
        // dispatch table is safe (just stores a fn ptr).
        let irq_ok = install_isa_irq(1, on_irq1_safe);
        narf_input::I8042_KBD_IRQ_ROUTED.store(irq_ok, core::sync::atomic::Ordering::Release);
        use core::fmt::Write as _;
        let _ = writeln!(
            narf_console::Writer,
            "  i8042-kbd: init=ok irq1={}",
            if irq_ok { "routed" } else { "ROUTING_FAILED" },
        );
        InitResult::Ok
    });
    narf_init::register(Stage::Device, "i8042-mouse", || {
        // SAFETY: BSP, post-keyboard-init.
        let init_res = unsafe { i8042_mouse::init() };
        let init_ok = init_res.is_ok();
        narf_input::I8042_MOUSE_INIT_OK.store(init_ok, core::sync::atomic::Ordering::Release);
        use core::fmt::Write as _;
        if !init_ok {
            let _ = writeln!(
                narf_console::Writer,
                "  i8042-mouse: init=FAIL ({:?}) — no PS/2 mouse on AUX channel; \
                 touchpad must be on a different transport (USB internal / I2C)",
                init_res.err(),
            );
            return InitResult::NotPresent;
        }
        let irq_ok = install_isa_irq(12, on_irq12_safe);
        narf_input::I8042_MOUSE_IRQ_ROUTED.store(irq_ok, core::sync::atomic::Ordering::Release);
        let _ = writeln!(
            narf_console::Writer,
            "  i8042-mouse: init=ok irq12={}",
            if irq_ok { "routed" } else { "ROUTING_FAILED" },
        );
        InitResult::Ok
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
    let matched_override = overrides[..n]
        .iter()
        .find(|ov| ov.bus == 0 && ov.source == isa_irq)
        .copied();
    let (gsi, flags) = matched_override
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
    // Surface the ISA override + final GSI/flags so a missed
    // override (or a wrong-polarity / wrong-trigger default) shows
    // up in dmesg. Critical for diagnosing "init=ok irqN=routed
    // but IRQ never fires" — the routing might be writing a bit
    // pattern the chipset rejects.
    use core::fmt::Write as _;
    let _ = writeln!(
        narf_console::Writer,
        "  isa-irq: ISA{} → GSI{} flags=POL{} TRIG{} (override={})",
        isa_irq,
        gsi,
        if flags & narf_acpi::ioapic::POLARITY_LOW != 0 {
            "LOW"
        } else {
            "HIGH"
        },
        if flags & narf_acpi::ioapic::TRIGGER_LEVEL != 0 {
            "LEVEL"
        } else {
            "EDGE"
        },
        if matched_override.is_some() {
            "MADT"
        } else {
            "default"
        },
    );
    let v = match narf_interrupts::vector::alloc() {
        Ok(v) => v,
        Err(_) => return false,
    };
    narf_interrupts::install_handler(v, handler);
    // Stash the vector in `narf-input` so the FB panel can surface
    // its `narf_interrupts::fire_count(vector)`.
    match isa_irq {
        1 => narf_input::I8042_KBD_IRQ_VECTOR.store(v, core::sync::atomic::Ordering::Release),
        12 => narf_input::I8042_MOUSE_IRQ_VECTOR.store(v, core::sync::atomic::Ordering::Release),
        _ => {}
    }
    // SAFETY: vector + handler installed before the IOAPIC
    // unmasks the line.
    unsafe { narf_acpi::ioapic::route_gsi_to_vector(gsi, v, 0, flags) }
}

// Per-crate smoke tests register against `narf-kernel-test` and
// land in the same `narf.tests` ELF section as the rest of the
// suite.
#[cfg(target_arch = "x86_64")]
mod tests;
