//! I2C HID Input driver — clean-room.
//!
//! Spec: "HID Over I2C Protocol Specification" (Microsoft).
//! Supports touchpads and keyboards over I2C/I3C using the HID standard.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use narf_drivers::{Driver, DriverEnv, DriverFuture};
use narf_i3c::{I3cBus, I3cError, I3cOp};

pub struct I2cHidDriver {
    bus: Arc<dyn I3cBus>,
    addr: u8,
    hid_desc_register: u16,
}

impl core::fmt::Debug for I2cHidDriver {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("I2cHidDriver")
            .field("addr", &self.addr)
            .field("hid_desc_register", &self.hid_desc_register)
            .finish_non_exhaustive()
    }
}

impl I2cHidDriver {
    pub fn new(bus: Arc<dyn I3cBus>, addr: u8, hid_desc_register: u16) -> Self {
        Self {
            bus,
            addr,
            hid_desc_register,
        }
    }

    async fn read_report(&self) -> Result<Vec<u8>, I3cError> {
        // Implementation for Stage 5: Read HID report.
        let mut buf = [0u8; 64];
        let mut ops = [I3cOp::Read(&mut buf)];
        self.bus.transfer(self.addr, &mut ops).await?;
        Ok(buf.to_vec())
    }
}

impl Driver for I2cHidDriver {
    fn start<'a>(&'a mut self, _env: DriverEnv<'a>) -> DriverFuture<'a> {
        Box::pin(async move {
            // 1. Read HID Descriptor.
            // 2. Initialise device.
        })
    }

    fn quiesce<'a>(&'a mut self) -> DriverFuture<'a> {
        Box::pin(async move {})
    }
}

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Device, "i2c-hid-probe", || {
        // Discovery pass: enumerate AMD FCH I2C controllers and
        // every PNP0C50 (HID-over-I2C) child. Surfaces enough
        // real-HW data — controller MMIO base + IRQ, child slave
        // address — that the actual controller driver and HID
        // binding can be built against this output. Each line is
        // an iteration target, not a "this works" claim.

        // AMD FCH I2C controller HIDs as they show up in
        // Zen+/Zen2/Zen3 firmware. The list grows as we
        // encounter new boards; unknowns get logged generically
        // so we know which ID to add.
        const AMD_I2C_HIDS: &[&str] =
            &["AMDI0010", "AMDI0019", "AMDI0510", "AMDI0011"];

        let mut found_controller = false;
        for &hid in AMD_I2C_HIDS {
            for ctrl in narf_aml::find_all_devices_by_hid(hid) {
                found_controller = true;
                let _ = writeln!(
                    narf_console::Writer,
                    "  i2c-hid: AMD I2C controller {} ({})",
                    ctrl.path, hid
                );
                report_crs(&ctrl.path);
            }
        }
        if !found_controller {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid: no AMD FCH I2C controller (HIDs scanned: {:?})",
                AMD_I2C_HIDS
            );
        }

        let mut hid_count = 0usize;
        for child in narf_aml::find_all_devices_by_hid("PNP0C50") {
            hid_count += 1;
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid: HID-over-I2C device {}",
                child.path
            );
            report_crs(&child.path);
        }
        if hid_count == 0 {
            let _ = writeln!(
                narf_console::Writer,
                "  i2c-hid: no PNP0C50 children found"
            );
        }

        // Driver binding still pending — the controller driver
        // (drivers/i2c, AMD FCH MMIO) lands in the next commit;
        // i2c-hid binding is the commit after.
        InitResult::Ok
    });
}

/// Evaluate `<path>._CRS` and print each resource item we
/// recognize. For an I2C controller this surfaces the MMIO
/// region + IRQ. For a HID child it surfaces the I2cSerialBus
/// descriptor (slave address, parent bus) and the GpioInt
/// descriptor (interrupt pin) — both needed to wire up the
/// device end-to-end. Unknown descriptors are dumped as
/// (tag, length) so we know what's missing from the decoder.
fn report_crs(path: &str) {
    use narf_aml::resource::ResourceItem;
    match narf_aml::prt_crs::evaluate_crs_for(path) {
        Ok(items) => {
            for item in &items {
                match item {
                    ResourceItem::Memory32Fixed { base, length, .. } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: Memory32Fixed base={:#010x} length={:#x}",
                            base, length
                        );
                    }
                    ResourceItem::Memory32 {
                        min, max, length, ..
                    } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: Memory32 min={:#010x} max={:#010x} length={:#x}",
                            min, max, length
                        );
                    }
                    ResourceItem::AddressSpace32 {
                        kind, min, length, ..
                    } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: AddressSpace32 kind={} min={:#010x} length={:#x}",
                            kind, min, length
                        );
                    }
                    ResourceItem::AddressSpace64 {
                        kind, min, length, ..
                    } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: AddressSpace64 kind={} min={:#018x} length={:#x}",
                            kind, min, length
                        );
                    }
                    ResourceItem::Irq { mask, flags } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: Irq mask={:#x} flags={:?}",
                            mask, flags
                        );
                    }
                    ResourceItem::ExtendedIrq { flags, gsis } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: ExtendedIrq flags={:#x} gsis={:?}",
                            flags, gsis
                        );
                    }
                    ResourceItem::EndTag => {}
                    ResourceItem::Unknown { tag, payload } => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: Unknown tag={:#04x} len={}",
                            tag,
                            payload.len()
                        );
                    }
                    other => {
                        let _ = writeln!(
                            narf_console::Writer,
                            "    _CRS: {:?}",
                            other
                        );
                    }
                }
            }
        }
        Err(e) => {
            let _ = writeln!(
                narf_console::Writer,
                "    _CRS: evaluate failed ({:?})",
                e
            );
        }
    }
}
