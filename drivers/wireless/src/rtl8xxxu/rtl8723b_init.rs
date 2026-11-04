//! RTL8723BU identity, multi-function EFUSE, power sequence, gen2 firmware
//! start and pre-firmware queue setup through the retained EP0 owner.
//!
//! Linux references (GPL-2.0-or-later, Linux 7.3-rc4):
//! - `rtl8xxxu/8723b.c::{rtl8723bu_identify_chip, rtl8723bu_parse_efuse,
//!   rtl8723bu_reset_8051, rtl8723b_emu_to_active, rtl8723bu_power_on,
//!   rtl8723bu_active_to_emu, rtl8723bu_fops}`
//! - `rtl8xxxu/core.c::{rtl8xxxu_read_efuse (is_multi_func),
//!   rtl8xxxu_disabled_to_emu, rtl8xxxu_init_queue_reserved_page,
//!   rtl8xxxu_init_queue_priority, rtl8xxxu_start_firmware
//!   (init_reg_hmtfr)}`
//!
//! The gen2 pieces shared with RTL8192EU (endpoint queue decode, queue
//! priority, PG-header EFUSE decode, H2C mailbox) are reused from
//! `rtl8192e_init`; only the 8723B-specific steps live here. Every transfer
//! goes through the one-shot owner; a transport error is terminal.

use super::device_init::Endpoints;
use super::firmware_transport::{ControlIo, Error, Owner};
use super::regs::*;
use super::rtl8192e_init::{queue_map, QueueMap, Queues, Vendor};

const REG_AFE_MISC: u16 = 0x0010;
const AFE_MISC_WL_XTAL_CTRL: u8 = 1 << 6;
const REG_RSV_CTRL: u16 = 0x001c;
const REG_LDOA15_CTRL: u16 = 0x0020;
const LDOA15_ENABLE: u8 = 1 << 0;
const REG_PWR_DATA: u16 = 0x0038;
pub(super) const PWR_DATA_EEPRPAD_RFE_CTRL_EN: u32 = 1 << 11;
const REG_GPIO_INTM: u16 = 0x0048;
const GPIO_INTM_EDGE_TRIG_IRQ: u16 = 1 << 9;
const REG_LEDCFG0: u16 = 0x004c;
const LEDCFG0_DPDT_SELECT: u32 = 1 << 23;
const REG_HSIMR: u16 = 0x0058;
const REG_GPIO_IO_SEL_2: u16 = 0x0062;
const REG_PAD_CTRL1: u16 = 0x0064;
const PAD_CTRL1_SW_DPDT_SEL_DATA: u8 = 1 << 0;
const REG_MULTI_FUNC_CTRL: u16 = 0x0068;
const MULTI_WIFI_FUNC_EN: u32 = 1 << 2;
const MULTI_WIFI_HW_ROF_EN: u8 = 1 << 3;
const MULTI_BT_FUNC_EN: u32 = 1 << 18;
const MULTI_GPS_FUNC_EN: u32 = 1 << 22;
const REG_SYS_CFG: u16 = 0x00f0;
const SYS_CFG_VENDOR_EXT_MASK: u32 = (1 << 18) | (1 << 19);
const SYS_CFG_TRP_VAUX_EN: u32 = 1 << 23;
const SYS_CFG_CHIP_VERSION_MASK: u32 = 0xf000;
const REG_GPIO_OUTSTS: u16 = 0x00f4;
const REG_RQPN: u16 = 0x0200;
const REG_RQPN_NPQ: u16 = 0x0214;
const RQPN_LOAD: u32 = 1 << 31;
const REG_BT_CONTROL_8723BU: u16 = 0x0764;
pub(super) const REG_WLAN_ACT_CONTROL_8723B: u16 = 0x076e;
const REG_NORMAL_SIE_EP_TX: u16 = 0xfe66;
/// Undocumented "antenna inverse" byte `rtl8723bu_power_on` writes.
const REG_ANTENNA_INVERSE_8723B: u16 = 0xfe08;
/// `0x0067[4]` BT_GPS_SEL (`rtl8723b_emu_to_active`).
const REG_BT_GPS_SEL_8723B: u16 = 0x0067;
const APS_FSMCO_SW_LPS: u32 = 1 << 10;
const APS_FSMCO_HW_SUSPEND: u32 = 1 << 11;
const APS_FSMCO_PCIE: u32 = 1 << 12;
const APS_FSMCO_HW_POWERDOWN: u32 = 1 << 15;
const APS_FSMCO_WLON_RESET: u32 = 1 << 16;
const SYS_FUNC_BBRSTB: u16 = 1 << 0;
const SYS_FUNC_BB_GLB_RSTN: u16 = 1 << 1;
const SYS_ISO_ANALOG_IPS: u8 = 1 << 5;
const CR_MAC_TX_ENABLE: u16 = 1 << 6;
const CR_MAC_RX_ENABLE: u16 = 1 << 7;

/// `rtl8723bu_fops.writeN_block_size`.
pub const WRITEN_BLOCK_SIZE: usize = 1024;
/// `rtl8723bu_fops.trxff_boundary`.
pub const TRXFF_BOUNDARY: u16 = 0x3f7f;
/// `rtl8723bu_fops.{total_page_num, page_num_hi, page_num_lo, page_num_norm}`
/// (`TX_TOTAL_PAGE_NUM_8723B`, `TX_PAGE_NUM_{HI,LO,NORM}_PQ_8723B`).
pub const TX_TOTAL_PAGES: u8 = 0xf7;
pub const TX_PAGE_NUM_HI: u8 = 0x0c;
pub const TX_PAGE_NUM_LO: u8 = 0x02;
pub const TX_PAGE_NUM_NORM: u8 = 0x02;
/// `rtl8xxxu_load_firmware` signature family of `rtl8723bu_nic.bin`.
pub const FIRMWARE_SIGNATURE: u16 = 0x5300;
/// `RTL8723B_TX_COUNT`.
pub const TX_COUNT: usize = 4;

/// Silicon identity read by `rtl8723bu_identify_chip`. 8723BU is always
/// 1T1R (`rf_paths = rx_paths = tx_paths = 1`) and multi-function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub cut: u8,
    pub vendor: Vendor,
    pub rom_rev: u8,
    pub has_wifi: bool,
    pub has_bluetooth: bool,
    pub has_gps: bool,
    pub queues: Queues,
}

impl Identity {
    pub fn name(self) -> &'static str {
        "8723BU"
    }
}

/// Decode `REG_SYS_CFG`/`REG_MULTI_FUNC_CTRL`/`REG_GPIO_OUTSTS`. Test silicon
/// is rejected as Linux does; an all-ones read is a missing device.
pub fn parse_identity(
    sys_cfg: u32,
    multi_func: u32,
    gpio_outsts: u32,
    queues: Queues,
) -> Result<Identity, Error> {
    if sys_cfg == u32::MAX || sys_cfg & SYS_CFG_TRP_VAUX_EN != 0 {
        return Err(Error::UnsupportedSilicon);
    }
    let vendor = match (sys_cfg & SYS_CFG_VENDOR_EXT_MASK) >> 18 {
        0 => Vendor::Tsmc,
        1 => Vendor::Smic,
        2 => Vendor::Umc,
        _ => Vendor::Unknown,
    };
    Ok(Identity {
        cut: ((sys_cfg & SYS_CFG_CHIP_VERSION_MASK) >> 12) as u8,
        vendor,
        rom_rev: (gpio_outsts >> 28) as u8,
        has_wifi: multi_func & MULTI_WIFI_FUNC_EN != 0,
        has_bluetooth: multi_func & MULTI_BT_FUNC_EN != 0,
        has_gps: multi_func & MULTI_GPS_FUNC_EN != 0,
        queues,
    })
}

/// Per-path 2.4 GHz power data from `struct rtl8723bu_efuse_tx_power`,
/// expanded as `rtl8723bu_parse_efuse` stores it: index 0 of `ofdm_diff`
/// and `ht20_diff` come from `ht20_ofdm_1s_diff.{a,b}`, `ht40_diff[0] = 0`,
/// indices 1..4 from `pwr_diff[i - 1]`. Diffs are signed 4-bit fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathPower {
    pub cck: [u8; 6],
    pub ht40: [u8; 5],
    pub ofdm_diff: [i8; TX_COUNT],
    pub ht20_diff: [i8; TX_COUNT],
    pub ht40_diff: [i8; TX_COUNT],
}

/// Factory data from `struct rtl8723bu_efuse`. `power[0]` is
/// `tx_power_index_A`, `power[1]` `tx_power_index_B` (the one
/// `rtl8723b_set_tx_power` programs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Factory {
    pub identity: Identity,
    pub mac: [u8; 6],
    pub power: [PathPower; 2],
    pub channel_plan: u8,
    /// `default_crystal_cap = xtal_k & 0x3f`.
    pub crystal_cap: u8,
    pub thermal: u8,
    pub iqk_lck: u8,
    pub pa_type: u8,
    pub lna_type_2g: u8,
    pub board_option: u8,
    pub bt_setting: u8,
    pub antenna_option: u8,
    pub rfe_option: u8,
    pub package_type: u8,
}

fn nibble(value: u8) -> i8 {
    ((value << 4) as i8) >> 4
}

fn path_power(map: &[u8; EFUSE_MAP_LEN], base: usize) -> PathPower {
    let mut power = PathPower {
        cck: map[base..base + 6].try_into().unwrap(),
        ht40: map[base + 6..base + 11].try_into().unwrap(),
        ofdm_diff: [0; TX_COUNT],
        ht20_diff: [0; TX_COUNT],
        ht40_diff: [0; TX_COUNT],
    };
    // `struct rtl8723au_idx`: a = low nibble, b = high nibble.
    power.ofdm_diff[0] = nibble(map[base + 11]);
    power.ht20_diff[0] = nibble(map[base + 11] >> 4);
    for i in 1..TX_COUNT {
        // `struct rtl8723bu_pwr_idx`: ht20:4, ht40:4 | ofdm:4, cck:4.
        let lo = map[base + 12 + (i - 1) * 2];
        let hi = map[base + 13 + (i - 1) * 2];
        power.ht20_diff[i] = nibble(lo);
        power.ht40_diff[i] = nibble(lo >> 4);
        power.ofdm_diff[i] = nibble(hi);
    }
    power
}

/// `rtl8723bu_parse_efuse` over the logical WiFi map. A missing `0x8129` ID
/// or a multicast/zero MAC (at `0x107`) is rejected; nothing is defaulted.
pub fn parse_efuse(identity: Identity, map: &[u8; EFUSE_MAP_LEN]) -> Result<Factory, Error> {
    if map[..2] != [0x29, 0x81] {
        return Err(Error::BadEfuse);
    }
    let mac: [u8; 6] = map[0x107..0x10d].try_into().unwrap();
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return Err(Error::BadEfuse);
    }
    Ok(Factory {
        identity,
        mac,
        power: [path_power(map, 0x10), path_power(map, 0x3a)],
        channel_plan: map[0xb8],
        crystal_cap: map[0xb9] & 0x3f,
        thermal: map[0xba],
        iqk_lck: map[0xbb],
        pa_type: map[0xbc],
        lna_type_2g: map[0xbd],
        board_option: map[0xc1],
        bt_setting: map[0xc3],
        antenna_option: map[0xc9],
        rfe_option: map[0xca],
        package_type: map[0x1fb],
    })
}

/// `rtl8xxxu_init_queue_reserved_page` with the 8723B page budget.
/// Returns `(REG_RQPN_NPQ, REG_RQPN)`.
pub fn reserved_pages(queues: Queues) -> (u32, u32) {
    let hq = if queues.high { TX_PAGE_NUM_HI } else { 0 } as u32;
    let lq = if queues.low { TX_PAGE_NUM_LO } else { 0 } as u32;
    let nq = if queues.normal { TX_PAGE_NUM_NORM } else { 0 } as u32;
    let eq = 0u32;
    let pubq = TX_TOTAL_PAGES as u32 - hq - lq - nq - 1;
    (nq | eq << 16, RQPN_LOAD | hq | lq << 8 | pubq << 16)
}

/// `rtl8723bu_identify_chip` plus the multi-function `rtl8xxxu_read_efuse`
/// and `rtl8723bu_parse_efuse`. The SIE queue set must be backed by real
/// bulk-OUT endpoints (Linux would index past `out_ep[]`).
pub(super) async fn factory<I: ControlIo>(
    owner: &Owner<I>,
    endpoints: Endpoints,
) -> Result<Factory, Error> {
    let sys_cfg = owner.read32(REG_SYS_CFG).await?;
    if sys_cfg == u32::MAX || sys_cfg & SYS_CFG_TRP_VAUX_EN != 0 {
        return Err(Error::UnsupportedSilicon);
    }
    let multi_func = owner.read32(REG_MULTI_FUNC_CTRL).await?;
    let gpio = owner.read32(REG_GPIO_OUTSTS).await?;
    let mut queues = Queues::from_sie(owner.read16(REG_NORMAL_SIE_EP_TX).await?);
    if queues.count() == 0 {
        queues = Queues::from_out_endpoints(endpoints.output_count)?;
    }
    if queues.count() > endpoints.output_count {
        return Err(Error::BadEndpoints);
    }
    let identity = parse_identity(sys_cfg, multi_func, gpio, queues)?;
    // `is_multi_func`: select the WiFi EFUSE cell. Linux does this after its
    // (side-effect-free) REG_9346CR read; the shared decoder reads it next.
    let value = owner.read32(REG_EFUSE_TEST).await?;
    owner
        .write32(
            REG_EFUSE_TEST,
            (value & !EFUSE_SELECT_MASK) | EFUSE_WIFI_SELECT,
        )
        .await?;
    let map = super::rtl8192e_init::read_efuse(owner).await?;
    parse_efuse(identity, &map)
}

async fn poll32<I: ControlIo>(
    owner: &Owner<I>,
    addr: u16,
    mask: u32,
    expected: u32,
) -> Result<(), Error> {
    for _ in 0..MAX_REG_POLL {
        if owner.read32(addr).await? & mask == expected {
            return Ok(());
        }
        owner.delay_us(10).await;
    }
    Err(Error::PowerTimeout)
}

/// `rtl8xxxu_disabled_to_emu`.
async fn disabled_to_emu<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    let value = owner.read8(REG_APS_FSMCO + 1).await?;
    owner
        .write8(REG_APS_FSMCO + 1, value & !((1 << 3) | (1 << 7)))
        .await?;
    let value = owner.read8(REG_GPIO_INTM + 2).await?;
    owner.write8(REG_GPIO_INTM + 2, value & !1).await?;
    let value = owner.read8(REG_APS_FSMCO + 1).await?;
    owner
        .write8(REG_APS_FSMCO + 1, value & !((1 << 3) | (1 << 4)))
        .await
}

async fn set8<I: ControlIo>(owner: &Owner<I>, addr: u16, set: u8, clear: u8) -> Result<(), Error> {
    let value = owner.read8(addr).await?;
    owner.write8(addr, (value & !clear) | set).await
}

async fn set32<I: ControlIo>(
    owner: &Owner<I>,
    addr: u16,
    set: u32,
    clear: u32,
) -> Result<(), Error> {
    let value = owner.read32(addr).await?;
    owner.write32(addr, (value & !clear) | set).await
}

/// `rtl8723b_emu_to_active`.
async fn emu_to_active<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    set8(owner, REG_LDOA15_CTRL, LDOA15_ENABLE, 0).await?;
    set8(owner, REG_BT_GPS_SEL_8723B, 0, 1 << 4).await?;
    owner.delay_us(1000).await;
    set8(owner, REG_SYS_ISO_CTRL, 0, SYS_ISO_ANALOG_IPS).await?;
    // Linux reads 8 bits and writes 32 (`val32 = rtl8xxxu_read8(..)`), so
    // bytes 1..3 of REG_APS_FSMCO are written as zero; kept verbatim.
    let value = owner.read8(REG_APS_FSMCO).await? as u32;
    owner
        .write32(REG_APS_FSMCO, value & !APS_FSMCO_SW_LPS)
        .await?;
    poll32(owner, REG_APS_FSMCO, 1 << 17, 1 << 17).await?;
    set32(owner, REG_APS_FSMCO, APS_FSMCO_WLON_RESET, 0).await?;
    set32(owner, REG_APS_FSMCO, 0, APS_FSMCO_HW_POWERDOWN).await?;
    set32(
        owner,
        REG_APS_FSMCO,
        0,
        APS_FSMCO_HW_SUSPEND | APS_FSMCO_PCIE,
    )
    .await?;
    set32(owner, REG_APS_FSMCO, APS_FSMCO_MAC_ENABLE, 0).await?;
    poll32(owner, REG_APS_FSMCO, APS_FSMCO_MAC_ENABLE, 0).await?;
    set8(owner, REG_AFE_MISC, AFE_MISC_WL_XTAL_CTRL, 0).await?;
    set8(owner, REG_GPIO_INTM + 1, 1 << 1, 0).await?;
    set8(owner, REG_GPIO_IO_SEL_2 + 1, 1 << 1, 0).await?;
    set8(owner, REG_GPIO_IO_SEL_2, 0, 1 << 1).await?;
    set8(owner, REG_HSIMR, 1 << 0, 0).await?;
    set8(owner, REG_HSIMR + 2, 1 << 1, 0).await?;
    set8(owner, REG_MULTI_FUNC_CTRL, MULTI_WIFI_HW_ROF_EN, 0).await?;
    set8(owner, REG_MULTI_FUNC_CTRL + 1, 1 << 6, 0).await
}

/// `rtl8723bu_power_on`: disabled→EMU→active, CR with MAC TX/RX (as Linux),
/// then the BT-coexistence power-on settings shared by 1- and 2-antenna
/// parts (PTA pad, BT control, WLAN act, S0S1 path, antenna inverse, RFE
/// pad, DPDT select).
pub(super) async fn power_on<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    disabled_to_emu(owner).await?;
    emu_to_active(owner).await?;
    let value = owner.read16(REG_CR).await?;
    owner
        .write16(
            REG_CR,
            value
                | (CR_HCI_TXDMA_ENABLE
                    | CR_HCI_RXDMA_ENABLE
                    | CR_TXDMA_ENABLE
                    | CR_RXDMA_ENABLE
                    | CR_PROTOCOL_ENABLE
                    | CR_SCHEDULE_ENABLE
                    | CR_MAC_TX_ENABLE
                    | CR_MAC_RX_ENABLE
                    | CR_SECURITY_ENABLE
                    | CR_CALTIMER_ENABLE),
        )
        .await?;
    owner.write8(REG_PAD_CTRL1 + 3, 0x20).await?;
    let value = owner.read16(REG_SYS_FUNC).await?;
    owner
        .write16(REG_SYS_FUNC, value | SYS_FUNC_BBRSTB | SYS_FUNC_BB_GLB_RSTN)
        .await?;
    owner.write8(REG_BT_CONTROL_8723BU + 1, 0x18).await?;
    owner.write8(REG_WLAN_ACT_CONTROL_8723B, 0x04).await?;
    owner.write32(REG_S0S1_PATH_SWITCH, 0x00).await?;
    owner.write8(REG_ANTENNA_INVERSE_8723B, 0x01).await?;
    let value = owner.read16(REG_PWR_DATA).await?;
    owner
        .write16(REG_PWR_DATA, value | PWR_DATA_EEPRPAD_RFE_CTRL_EN as u16)
        .await?;
    set32(owner, REG_LEDCFG0, LEDCFG0_DPDT_SELECT, 0).await?;
    set8(owner, REG_PAD_CTRL1, 0, PAD_CTRL1_SW_DPDT_SEL_DATA).await
}

/// `rtl8723bu_active_to_emu`. The MAC-off poll is terminal `PowerTimeout`
/// (Linux returns -EBUSY and skips the remaining steps as well).
pub(super) async fn active_to_emu<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    owner.write8(REG_RF_CTRL, 0).await?;
    let value = owner.read16(REG_GPIO_INTM).await?;
    owner
        .write16(REG_GPIO_INTM, value & !GPIO_INTM_EDGE_TRIG_IRQ)
        .await?;
    set32(owner, REG_APS_FSMCO, APS_FSMCO_WLON_RESET, 0).await?;
    set8(owner, REG_APS_FSMCO + 1, 1 << 1, 0).await?;
    let mut off = false;
    for _ in 0..MAX_REG_POLL {
        if owner.read8(REG_APS_FSMCO + 1).await? & (1 << 1) == 0 {
            off = true;
            break;
        }
        owner.delay_us(10).await;
    }
    if !off {
        return Err(Error::PowerTimeout);
    }
    set8(owner, REG_AFE_MISC, 0, AFE_MISC_WL_XTAL_CTRL).await?;
    set8(owner, REG_SYS_ISO_CTRL, SYS_ISO_ANALOG_IPS, 0).await?;
    set8(owner, REG_LDOA15_CTRL, 0, LDOA15_ENABLE).await
}

/// `rtl8723bu_reset_8051`.
pub(super) async fn reset_8051<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    set8(owner, REG_RSV_CTRL, 0, 1 << 1).await?;
    set8(owner, REG_RSV_CTRL + 1, 0, 1 << 0).await?;
    let sys_func = owner.read16(REG_SYS_FUNC).await? & !SYS_FUNC_CPU_ENABLE;
    owner.write16(REG_SYS_FUNC, sys_func).await?;
    set8(owner, REG_RSV_CTRL, 0, 1 << 1).await?;
    set8(owner, REG_RSV_CTRL + 1, 1 << 0, 0).await?;
    owner
        .write16(REG_SYS_FUNC, sys_func | SYS_FUNC_CPU_ENABLE)
        .await
}

/// `rtl8xxxu_init_device` between `power_on` and firmware download
/// (`needs_full_init`, so always cold): reserved pages, queue priority and
/// the `trxff_boundary = 0x3f7f` RX page boundary.
pub(super) async fn pre_firmware<I: ControlIo>(
    owner: &Owner<I>,
    factory: Factory,
) -> Result<QueueMap, Error> {
    let queues = factory.identity.queues;
    let map = queue_map(queues)?;
    let (npq, rqpn) = reserved_pages(queues);
    owner.write32(REG_RQPN_NPQ, npq).await?;
    owner.write32(REG_RQPN, rqpn).await?;
    let value = owner.read16(REG_TRXDMA_CTRL).await?;
    owner
        .write16(REG_TRXDMA_CTRL, (value & 7) | map.trxdma)
        .await?;
    owner.write16(REG_TRXFF_BNDY + 2, TRXFF_BOUNDARY).await?;
    Ok(map)
}
