//! I2C client devices.
//!
//! A client is an (adapter, 7-bit address, device type) that the I2C
//! core has instantiated for a driver to bind — Linux's
//! `struct i2c_client`. Linux creates them from firmware descriptions,
//! board info, or by scanning: an adapter driver calls
//! `i2c_new_scanned_device` with a candidate address list and the core
//! keeps the first address that answers a probe. Drivers then bind to
//! clients of their type (`i2c_device_id`).
//!
//! NARF keeps the same split. Adapter drivers (piix4) instantiate
//! clients here; client drivers in other crates (hwmon `spd5118`)
//! enumerate the clients of their type with [`clients_of_kind`] and
//! probe them. A client stays registered whether or not a driver binds
//! it, as in Linux.
//!
//! Ref: drivers/i2c/i2c-core-base.c (`i2c_new_client_device`,
//! `i2c_new_scanned_device`, `i2c_default_probe`,
//! `i2c_check_addr_busy`, `i2c_check_7bit_addr_validity_strict`).

use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use crate::smbus::{I2cFunc, SmbusOp};
use crate::{I2cBus, I2cError};

/// One instantiated client device.
#[derive(Debug)]
pub struct I2cClient {
    bus: Arc<dyn I2cBus>,
    addr: u8,
    kind: &'static str,
}

impl I2cClient {
    /// The adapter the client sits on.
    pub fn bus(&self) -> &Arc<dyn I2cBus> {
        &self.bus
    }

    /// The client's 7-bit address.
    pub fn addr(&self) -> u8 {
        self.addr
    }

    /// The device type drivers match on (`i2c_board_info.type`).
    pub fn kind(&self) -> &'static str {
        self.kind
    }
}

static CLIENTS: IrqSafeSpinLock<Vec<Arc<I2cClient>>> = IrqSafeSpinLock::new(Vec::new());

/// `i2c_check_addr_validity` for a 7-bit address: everything but the
/// general-call address 0x00 (and anything over 7 bits).
pub fn addr_valid(addr: u8) -> bool {
    (0x01..=0x7f).contains(&addr)
}

/// `i2c_check_7bit_addr_validity_strict`, used before probing:
/// 0x00-0x07 and 0x78-0x7f are reserved by the I2C specification.
pub fn addr_valid_strict(addr: u8) -> bool {
    (0x08..=0x77).contains(&addr)
}

/// Whether `a` and `b` are the same adapter object. Linux's busy walk
/// visits one adapter's own children (`device_for_each_child` on
/// `adapter->dev`), so two adapters never share a client, whatever
/// their names. The data pointers are compared; the vtable halves of
/// the fat pointers are not identities.
fn same_adapter(a: &Arc<dyn I2cBus>, b: &Arc<dyn I2cBus>) -> bool {
    core::ptr::eq(Arc::as_ptr(a) as *const (), Arc::as_ptr(b) as *const ())
}

fn busy_in(clients: &[Arc<I2cClient>], bus: &Arc<dyn I2cBus>, addr: u8) -> bool {
    clients
        .iter()
        .any(|c| c.addr == addr && same_adapter(&c.bus, bus))
}

/// `i2c_check_addr_busy`: an address already has a client on this
/// adapter.
fn addr_busy(bus: &Arc<dyn I2cBus>, addr: u8) -> bool {
    busy_in(&CLIENTS.lock(), bus, addr)
}

/// `i2c_new_client_device`: register a client at a known address.
/// [`I2cError::InvalidArgs`] for the general-call address or one over
/// 7 bits, then [`I2cError::Busy`] when the address already has a
/// client (Linux `-EINVAL` / `-EBUSY`, in that order).
pub fn new_client_device(
    bus: &Arc<dyn I2cBus>,
    addr: u8,
    kind: &'static str,
) -> Result<Arc<I2cClient>, I2cError> {
    if !addr_valid(addr) {
        return Err(I2cError::InvalidArgs);
    }
    let client = Arc::new(I2cClient {
        bus: bus.clone(),
        addr,
        kind,
    });
    let mut g = CLIENTS.lock();
    if busy_in(&g, bus, addr) {
        return Err(I2cError::Busy);
    }
    g.push(client.clone());
    Ok(client)
}

/// `i2c_default_probe`: whether something answers at `addr`. Quick
/// write where safe; a receive-byte read in the 0x30-0x37 and
/// 0x50-0x5f ranges, where a quick write can corrupt EEPROMs or lock
/// up chips. Adapters with neither size report nothing there.
pub async fn default_probe(bus: &dyn I2cBus, addr: u8) -> bool {
    let func = bus.functionality();
    let eeprom_range = (addr & !0x07) == 0x30 || (addr & !0x0f) == 0x50;
    if !eeprom_range && func.contains(I2cFunc::SMBUS_QUICK) {
        bus.smbus_xfer(addr, SmbusOp::Quick { read: false })
            .await
            .is_ok()
    } else if func.contains(I2cFunc::SMBUS_READ_BYTE) {
        let mut dummy = 0u8;
        bus.smbus_xfer(addr, SmbusOp::ReceiveByte { out: &mut dummy })
            .await
            .is_ok()
    } else {
        false
    }
}

/// `i2c_new_scanned_device` with the default probe: instantiate a
/// `kind` client at the first address in `addrs` that is valid, free
/// and answers. `None` when nothing does (Linux `-ENODEV`).
pub async fn new_scanned_device(
    bus: &Arc<dyn I2cBus>,
    kind: &'static str,
    addrs: &[u8],
) -> Option<Arc<I2cClient>> {
    for &addr in addrs {
        if !addr_valid_strict(addr) || addr_busy(bus, addr) {
            continue;
        }
        if default_probe(bus.as_ref(), addr).await {
            return new_client_device(bus, addr, kind).ok();
        }
    }
    None
}

/// Every registered client of device type `kind`, in creation order.
pub fn clients_of_kind(kind: &str) -> Vec<Arc<I2cClient>> {
    CLIENTS
        .lock()
        .iter()
        .filter(|c| c.kind == kind)
        .cloned()
        .collect()
}

/// Every registered client, in creation order.
pub fn clients() -> Vec<Arc<I2cClient>> {
    CLIENTS.lock().clone()
}

#[doc(hidden)]
pub fn __reset_for_test() {
    CLIENTS.lock().clear();
}
