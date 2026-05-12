//! GenericSerialBus OpRegion dispatcher (audit #5 real impl).
//!
//! AML's `OperationRegion(GSB, GenericSerialBus, 0, ...)` field
//! reads/writes route through `narf_aml::oregion::set_gsb_dispatcher`.
//! `narf-aml` can't depend on this crate (cycle: i2c → aml for
//! namespace walks), so this is the inverted-dependency hook.
//!
//! The dispatcher receives the OpRegion path. From that we walk
//! up to the parent device, evaluate its `_CRS` to find the
//! `I2cSerialBus` resource (carries the parent bus path + slave
//! address), look up the bus in our registry, and issue the I2C
//! transaction via `block_on` (sync→async bridge, since
//! `I2cBus::transfer` is async).
//!
//! Caching: OpRegion path → (bus path, slave address) lookup
//! happens on every call; could cache once per OpRegion path
//! since the _CRS result is stable. Defer that until perf
//! matters — typical Renoir _DSM bodies issue 1-3 GSB accesses
//! per call, so the _CRS evaluation cost is modest.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;

use narf_aml::oregion::GsbOp;
use narf_aml::resource::ResourceItem;

use crate::{I2cBus, I2cOp};

/// The dispatcher fn pointer that `narf-aml` calls. Public via
/// `crate::gsb::dispatch` so `register_initcalls` can install it.
pub fn dispatch(region_path: &str, byte_offset: u64, op: GsbOp) -> u64 {
    // 1. Walk up to the parent device path.
    let device_path = match region_path.rfind('.') {
        Some(i) => &region_path[..i],
        None => return 0,
    };

    // 2. Evaluate the device's _CRS, find the I2cSerialBus item.
    let items = match narf_aml::prt_crs::evaluate_crs_for(device_path) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let mut bus_path: Option<String> = None;
    let mut slave: Option<u8> = None;
    for it in items {
        if let ResourceItem::I2cSerialBus {
            slave_address,
            resource_source,
            ..
        } = it
        {
            bus_path = Some(resource_source);
            slave = Some((slave_address & 0x7f) as u8);
            break;
        }
    }
    let (bus_name, addr) = match (bus_path, slave) {
        (Some(b), Some(a)) => (b, a),
        _ => return 0,
    };

    // 3. Look up the bus in the registry.
    let bus: Arc<dyn I2cBus> = match crate::registry::find(&bus_name) {
        Some(b) => b,
        None => return 0,
    };

    // 4. Issue the I2C transaction via block_on. block_on holds
    //    no IrqSafeSpinLock at this point — aml's read_unit /
    //    write_unit dropped its locks before calling us.
    match op {
        GsbOp::Read { width } => i2c_read(&bus, addr, byte_offset as u8, width),
        GsbOp::Write { width, value } => {
            i2c_write(&bus, addr, byte_offset as u8, width, value);
            0
        }
    }
}

fn i2c_read(bus: &Arc<dyn I2cBus>, addr: u8, offset: u8, width: usize) -> u64 {
    // Standard I2C-attached register read: write the offset
    // byte, then read `width` bytes. Most HID-over-I2C and
    // touchpad GSB configurations use this pattern.
    let w = width.min(8);
    let mut buf = [0u8; 8];
    let reg = [offset];
    let bus_clone = bus.clone();
    let r = narf_scheduler::block_on(async move {
        let mut ops = [I2cOp::Write(&reg), I2cOp::Read(&mut buf[..w])];
        bus_clone.transfer(addr, &mut ops).await
    });
    if r.is_err() {
        return 0;
    }
    let mut acc = 0u64;
    for i in 0..w {
        acc |= (buf[i] as u64) << (i * 8);
    }
    acc
}

fn i2c_write(bus: &Arc<dyn I2cBus>, addr: u8, offset: u8, width: usize, value: u64) {
    // Standard I2C register write: prepend offset byte, then
    // `width` bytes of `value` little-endian.
    let w = width.min(8);
    let mut buf = [0u8; 9];
    buf[0] = offset;
    for i in 0..w {
        buf[1 + i] = ((value >> (i * 8)) & 0xff) as u8;
    }
    let bus_clone = bus.clone();
    let _ = narf_scheduler::block_on(async move {
        let mut ops = [I2cOp::Write(&buf[..1 + w])];
        bus_clone.transfer(addr, &mut ops).await
    });
}
