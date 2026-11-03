// SPDX-License-Identifier: GPL-2.0-or-later
//! Original RTL8822BE ("B22") logical factory map.
//!
//! Linux `rtw8822b.c::rtw8822b_read_efuse` over `struct rtw8822b_efuse` /
//! `struct rtw8822be_efuse` (`rtw8822b.h`). The map comes from the same single
//! 1024-byte physical read (96 protected bytes excluded) that establishes the
//! PCIe MAC. Factory data selects hardware tables only; it authenticates no
//! country and grants no transmit power. RTL8821CE/RTL8822CE factory types are
//! distinct and can never be used for this chip, nor this one for them.
use super::efuse::{mac_is_valid, EfuseError, EfuseIo};
use super::regs::RTL_DEV_8822BE;
use narf_bus::MmioRegion;

/// `struct rtw8822b_efuse` field offsets in the 768-byte logical map.
mod at {
    pub const USB_MODE: usize = 0x06;
    pub const TXPWR_IDX: usize = 0x10;
    pub const CHANNEL_PLAN: usize = 0xb8;
    pub const XTAL_K: usize = 0xb9;
    pub const THERMAL: usize = 0xba;
    pub const PA_TYPE: usize = 0xbc;
    pub const LNA_2G: usize = 0xbd;
    pub const LNA_5G: usize = 0xbf;
    pub const RF_BOARD_OPTION: usize = 0xc1;
    pub const RF_BT_SETTING: usize = 0xc3;
    pub const SWING_2G: usize = 0xc6;
    pub const SWING_5G: usize = 0xc7;
    pub const RF_ANTENNA_OPTION: usize = 0xc9;
    pub const RFE_OPTION: usize = 0xca;
    pub const COUNTRY: usize = 0xcb;
    /// `rtw8822be_efuse::mac_addr` (union base 0xd0).
    pub const PCIE_MAC: usize = 0xd0;
}

/// `struct rtw_txpwr_idx` is 42 bytes; four RF paths start at 0x10.
pub const POWER_PATH_LEN: usize = 42;

#[derive(Clone)]
pub struct Factory8822b {
    logical: [u8; 768],
}
impl core::fmt::Debug for Factory8822b {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8822beFactory")
            .field("mac", &self.mac())
            .field("rfe", &self.rfe())
            .finish_non_exhaustive()
    }
}
impl Factory8822b {
    fn new(logical: [u8; 768]) -> Result<Self, EfuseError> {
        let factory = Self { logical };
        if !mac_is_valid(factory.mac()) {
            return Err(EfuseError::MacUninitialized);
        }
        Ok(factory)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn for_test(logical: [u8; 768]) -> Result<Self, EfuseError> {
        Self::new(logical)
    }
    /// `rtw8822be_efuse_parsing`: `ether_addr_copy(efuse->addr, map->e.mac_addr)`.
    pub fn mac(&self) -> [u8; 6] {
        self.logical[at::PCIE_MAC..at::PCIE_MAC + 6]
            .try_into()
            .unwrap()
    }
    /// `efuse->rfe_option = map->rfe_option` — the whole byte on 8822B
    /// (unlike 8821C's five-bit field); `rtw8822b_rfe_defs` is indexed by it.
    pub fn rfe(&self) -> u8 {
        self.logical[at::RFE_OPTION]
    }
    pub fn usb_mode_switch(&self) -> bool {
        self.logical[at::USB_MODE] & 0x80 != 0
    }
    pub fn board_option(&self) -> u8 {
        self.logical[at::RF_BOARD_OPTION]
    }
    /// `efuse->regd = map->rf_board_option & 0x7`.
    pub fn regd(&self) -> u8 {
        self.board_option() & 7
    }
    pub fn crystal(&self) -> u8 {
        self.logical[at::XTAL_K]
    }
    /// `pa_type_2g = pa_type_5g = map->pa_type`.
    pub fn pa_type(&self) -> u8 {
        self.logical[at::PA_TYPE]
    }
    /// `lna_type_2g = map->lna_type_2g[0]`.
    pub fn lna_2g(&self) -> u8 {
        self.logical[at::LNA_2G]
    }
    /// `lna_type_5g = map->lna_type_5g[0]`.
    pub fn lna_5g(&self) -> u8 {
        self.logical[at::LNA_5G]
    }
    pub fn channel_plan(&self) -> u8 {
        self.logical[at::CHANNEL_PLAN]
    }
    pub fn country(&self) -> [u8; 2] {
        self.logical[at::COUNTRY..at::COUNTRY + 2]
            .try_into()
            .unwrap()
    }
    pub fn bt_setting(&self) -> u8 {
        self.logical[at::RF_BT_SETTING]
    }
    /// `thermal_meter[RF_PATH_A] = thermal_meter_k = map->thermal_meter`.
    pub fn thermal(&self) -> u8 {
        self.logical[at::THERMAL]
    }
    pub fn swing_2g(&self) -> u8 {
        self.logical[at::SWING_2G]
    }
    pub fn swing_5g(&self) -> u8 {
        self.logical[at::SWING_5G]
    }
    pub fn antenna_option(&self) -> u8 {
        self.logical[at::RF_ANTENNA_OPTION]
    }
    /// Raw `txpwr_idx_table[path]`. Erased fields stay `0xff`; no default
    /// power is manufactured here.
    pub fn power_path(&self, path: u8) -> Option<&[u8]> {
        if path > 3 {
            return None;
        }
        let start = at::TXPWR_IDX + usize::from(path) * POWER_PATH_LEN;
        Some(&self.logical[start..start + POWER_PATH_LEN])
    }
    pub fn logical(&self) -> &[u8; 768] {
        &self.logical
    }
}

pub(super) fn read_factory8822b_with(
    io: &mut impl EfuseIo,
    did: u16,
) -> Result<Factory8822b, EfuseError> {
    if did != RTL_DEV_8822BE {
        return Err(EfuseError::UnsupportedChip);
    }
    Factory8822b::new(super::efuse::read_logical8822b_with(io, did)?)
}
/// # Safety
/// Same powered, exclusive BAR2 ownership contract as `efuse::read_mac`.
pub(super) unsafe fn read_factory8822b(
    mmio: &MmioRegion,
    did: u16,
) -> Result<Factory8822b, EfuseError> {
    if did != RTL_DEV_8822BE {
        return Err(EfuseError::UnsupportedChip);
    }
    // SAFETY: forwarded caller contract.
    Factory8822b::new(unsafe { super::efuse::read_logical8822b(mmio, did) }?)
}
