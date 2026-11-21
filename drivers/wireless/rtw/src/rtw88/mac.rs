// SPDX-License-Identifier: GPL-2.0-or-later
//! rtw88 MAC/FIFO bring-up entry points (`mac.c::rtw_mac_init`). The register
//! programming itself lives in `narf-drivers-wireless-rtl-chip`, generic over
//! `RegIo`, so the builtin driver and the loadable `.ko` share the exact byte
//! stream. This shim resolves the PCIe/USB `Hci` into the chip core's
//! [`MacParams`], bridges the native firmware-owner `Io` to `RegIo`, and
//! re-exports [`Info`]; DMA, MAC TX/RX and host queues stay closed pending RF.
use super::firmware_transport::{Error, Io};
use narf_drivers_wireless_rtl_chip::mac::{self as chip_mac, MacParams};
use narf_drivers_wireless_rtl_chip::{ChipError, RegIo};

pub use chip_mac::Info;

/// Host interface the MAC queue/FIFO programming follows (`rtw_hci_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Hci {
    Pcie,
    /// RTL8821CU / RTL8822BU: `rtwdev->hci.bulkout_num` selects the
    /// `rqpn_table_8821c`/`page_table_8821c` or `rqpn_table_8822b`/
    /// `page_table_8822b` rows; `speed` feeds `rtw_usb_interface_cfg`.
    Usb {
        bulkout: u8,
        speed: super::usb::Speed,
    },
}

/// Bridge the native firmware-owner `Io` (a `Send` superset of `RegIo`) to
/// `RegIo`. `RegIo` is foreign, so an orphan-rule-clean newtype carries the
/// blanket impl; it forwards each access 1:1 (no extra register traffic, so the
/// byte-exact FIFO/chip trace is preserved) and maps the error type.
struct IoReg<'a, T: Io>(&'a mut T);

/// Map the chip core's result back into the native error set. A plain fn (not a
/// `From` impl) keeps the broad `Error: From<_>` inference at unrelated `?`
/// sites unchanged.
fn from_chip(err: ChipError) -> Error {
    match err {
        ChipError::Access => Error::Access,
        ChipError::Gone => Error::Gone,
        ChipError::Timeout => Error::Timeout,
        ChipError::Prerequisite => Error::Prerequisite,
        ChipError::Unsupported => Error::Unsupported,
    }
}
/// Map a native register-transport error into the chip core's narrower set.
/// Register access only yields `Gone` (the device vanished) or `Access`.
fn to_chip(err: Error) -> ChipError {
    match err {
        Error::Gone => ChipError::Gone,
        Error::Timeout => ChipError::Timeout,
        Error::Prerequisite => ChipError::Prerequisite,
        Error::Unsupported => ChipError::Unsupported,
        _ => ChipError::Access,
    }
}

impl<T: Io> RegIo for IoReg<'_, T> {
    async fn read8(&mut self, reg: u16) -> Result<u8, ChipError> {
        self.0.read8(reg).await.map_err(to_chip)
    }
    async fn read16(&mut self, reg: u16) -> Result<u16, ChipError> {
        self.0.read16(reg).await.map_err(to_chip)
    }
    async fn read32(&mut self, reg: u16) -> Result<u32, ChipError> {
        self.0.read32(reg).await.map_err(to_chip)
    }
    async fn write8(&mut self, reg: u16, value: u8) -> Result<(), ChipError> {
        self.0.write8(reg, value).await.map_err(to_chip)
    }
    async fn write16(&mut self, reg: u16, value: u16) -> Result<(), ChipError> {
        self.0.write16(reg, value).await.map_err(to_chip)
    }
    async fn write32(&mut self, reg: u16, value: u32) -> Result<(), ChipError> {
        self.0.write32(reg, value).await.map_err(to_chip)
    }
    async fn delay_us(&mut self, us: u32) {
        self.0.delay_us(u64::from(us)).await
    }
}

/// `rtw_usb_init_burst_pkt_len` burst selector from the bus speed.
fn speed_burst(speed: super::usb::Speed) -> u8 {
    match speed {
        super::usb::Speed::Super => 0,
        super::usb::Speed::High => 1,
        super::usb::Speed::Full => 2,
    }
}

pub(super) async fn prepare(io: &mut impl Io) -> Result<Info, Error> {
    prepare_for(io, 0xc822).await
}
pub(super) async fn prepare_for(io: &mut impl Io, did: u16) -> Result<Info, Error> {
    prepare_on(io, did, Hci::Pcie).await
}
/// `mac.c::rtw_mac_init` for `hci`. USB exists for the C21 (RTL8821CU) and
/// B22 (RTL8822BU) dies; the PCIe byte stream is unchanged.
pub(super) async fn prepare_on(io: &mut impl Io, did: u16, hci: Hci) -> Result<Info, Error> {
    if !matches!(did, 0xc821 | 0xc822 | 0xb822) || did == 0xc822 && hci != Hci::Pcie {
        return Err(Error::Unsupported);
    }
    // `mac.c::txdma_queue_mapping` / `__priority_queue_cfg`: PCIe uses the fixed
    // 0xc5a0 map and die-specific page counts; USB the bulk-out-count row (the
    // rows live in the shared core, which both this and the `.ko` consume).
    let params = match hci {
        Hci::Pcie => MacParams {
            txdma_pq_map: 0xc5a0,
            pages: if did == 0xc821 {
                [16, 16, 16, 14]
            } else {
                [64; 4]
            },
            usb: None,
        },
        Hci::Usb { bulkout, speed } => {
            chip_mac::usb_mac_params(did, usize::from(bulkout), speed_burst(speed))
                .ok_or(Error::Unsupported)?
        }
    };
    chip_mac::prepare(&mut IoReg(io), did, params)
        .await
        .map_err(from_chip)
}
