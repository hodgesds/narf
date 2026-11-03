//! RTL8192EU identity, EFUSE, power sequence, gen2 firmware start and H2C
//! mailbox through the retained EP0 owner.
//!
//! Linux references (GPL-2.0-or-later, Linux 7.3-rc4):
//! - `rtl8xxxu/8192e.c::{rtl8192eu_identify_chip, rtl8192eu_parse_efuse,
//!   rtl8192e_crystal_afe_adjust, rtl8192e_disabled_to_emu,
//!   rtl8192e_emu_to_active, rtl8192eu_power_on, rtl8192eu_active_to_emu,
//!   rtl8192eu_emu_to_disabled}`
//! - `rtl8xxxu/core.c::{rtl8xxxu_config_endpoints_sie,
//!   rtl8xxxu_config_endpoints_no_sie, rtl8xxxu_read_efuse,
//!   rtl8xxxu_read_efuse8, rtl8xxxu_reset_8051,
//!   rtl8xxxu_init_queue_reserved_page, rtl8xxxu_init_queue_priority,
//!   rtl8xxxu_gen2_h2c_cmd}`
//!
//! Every transfer goes through the one-shot owner. A transport error is
//! terminal; no cleanup transfer is attempted after an ambiguous failure.

use core::sync::atomic::Ordering;

use super::device_init::Endpoints;
use super::firmware_transport::{ControlIo, Error, Owner};
use super::regs::*;
use super::rtl8192e as chip;

const REG_HPON_FSM: u16 = 0x00ec;
const HPON_FSM_BONDING_MASK: u32 = (1 << 22) | (1 << 23);
const HPON_FSM_BONDING_1T2R: u32 = 1 << 22;
const REG_SYS_CFG: u16 = 0x00f0;
const SYS_CFG_VENDOR_EXT_MASK: u32 = (1 << 18) | (1 << 19);
const SYS_CFG_TRP_VAUX_EN: u32 = 1 << 23;
const SYS_CFG_SPS_LDO_SEL: u32 = 1 << 24;
const SYS_CFG_CHIP_VERSION_MASK: u32 = 0xf000;
const REG_GPIO_OUTSTS: u16 = 0x00f4;
const REG_RSV_CTRL: u16 = 0x001c;
const REG_RF_CTRL_8192E: u16 = 0x001f;
const RF_ENABLE: u8 = 1 << 0;
const REG_AFE_PLL_CTRL: u16 = 0x0028;
const REG_LEDCFG2: u16 = 0x004e;
const LEDCFG2_DPDT_SELECT: u8 = 1 << 7;
const REG_AFE_CTRL4: u16 = 0x0078;
const REG_LDO_SW_CTRL: u16 = 0x007c;
const REG_HMBOX_0: u16 = 0x01d0;
const REG_HMBOX_EXT0_8723B: u16 = 0x01f0;
const REG_RQPN: u16 = 0x0200;
const REG_RQPN_NPQ: u16 = 0x0214;
const RQPN_LOAD: u32 = 1 << 31;
const REG_NORMAL_SIE_EP_TX: u16 = 0xfe66;
const CR_MAC_TX_ENABLE: u16 = 1 << 6;
const CR_MAC_RX_ENABLE: u16 = 1 << 7;
/// `EFUSE_REAL_CONTENT_LEN_8723A`, the read bound `rtl8xxxu_read_efuse` uses.
const EFUSE_REAL_CONTENT: u16 = 512;
/// `H2C_MAX_MBOX`.
const H2C_MAX_MBOX: u8 = 4;
/// `rtl8xxxu_gen2_h2c_cmd`: `retry = 100; do { .. } while (retry--)`.
const H2C_MBOX_POLLS: usize = 101;

/// `rtl8xxxu_identify_vendor_2bits` (`SYS_CFG_VENDOR_ID_{TSMC,SMIC,UMC}`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vendor {
    Tsmc,
    Smic,
    Umc,
    Unknown,
}

/// TX queues the SIE (or the endpoint count fallback) advertises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Queues {
    pub high: bool,
    pub normal: bool,
    pub low: bool,
}

impl Queues {
    /// `rtl8xxxu_config_endpoints_sie`.
    pub fn from_sie(sie: u16) -> Self {
        Self {
            high: sie & 0x000f != 0,
            normal: sie & 0x00f0 != 0,
            low: sie & 0x0f00 != 0,
        }
    }
    /// `rtl8xxxu_config_endpoints_no_sie` keyed by the bulk-OUT count.
    pub fn from_out_endpoints(count: u8) -> Result<Self, Error> {
        match count {
            1 => Ok(Self {
                high: true,
                normal: false,
                low: false,
            }),
            2 => Ok(Self {
                high: true,
                normal: true,
                low: false,
            }),
            3..=6 => Ok(Self {
                high: true,
                normal: true,
                low: true,
            }),
            _ => Err(Error::BadEndpoints),
        }
    }
    pub fn count(self) -> u8 {
        self.high as u8 + self.normal as u8 + self.low as u8
    }
}

/// Endpoint index (into `Endpoints::output`) for each TX queue, as
/// `rtl8xxxu_init_queue_priority` fills `priv->pipe_out[]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueMap {
    pub vo: u8,
    pub vi: u8,
    pub be: u8,
    pub bk: u8,
    pub mgmt: u8,
    pub high: u8,
    /// Value written into `REG_TRXDMA_CTRL[15:4]`.
    pub trxdma: u16,
}

/// `rtl8xxxu_init_queue_priority` for every non-8192F chip.
pub fn queue_map(queues: Queues) -> Result<QueueMap, Error> {
    const LOW: u16 = 1;
    const NORMAL: u16 = 2;
    const HIGH: u16 = 3;
    let (hiq, mgq, bkq, beq, viq, voq, hip, mgp, bkp, bep, vip, vop) = match queues.count() {
        1 => {
            let hi = if queues.high {
                HIGH
            } else if queues.low {
                LOW
            } else {
                NORMAL
            };
            (hi, hi, hi, hi, hi, hi, 0, 0, 0, 0, 0, 0)
        }
        2 => {
            let (hi, lo) = if queues.high && queues.low {
                (HIGH, LOW)
            } else if queues.normal && queues.low {
                (NORMAL, LOW)
            } else {
                (HIGH, NORMAL)
            };
            (hi, hi, lo, lo, hi, hi, 0, 0, 1, 1, 0, 0)
        }
        3 => {
            let (beq, bkq, viq, voq, mgq, hiq) = (LOW, LOW, NORMAL, HIGH, HIGH, HIGH);
            // Linux assigns `vop = viq ^ 3` (not voq); kept verbatim.
            (
                hiq,
                mgq,
                bkq,
                beq,
                viq,
                voq,
                (hiq ^ 3) as u8,
                (mgq ^ 3) as u8,
                (bkq ^ 3) as u8,
                (beq ^ 3) as u8,
                (viq ^ 3) as u8,
                (viq ^ 3) as u8,
            )
        }
        _ => return Err(Error::BadEndpoints),
    };
    Ok(QueueMap {
        vo: vop,
        vi: vip,
        be: bep,
        bk: bkp,
        mgmt: mgp,
        high: hip,
        trxdma: voq << 4 | viq << 6 | beq << 8 | bkq << 10 | mgq << 12 | hiq << 14,
    })
}

/// `rtl8xxxu_init_queue_reserved_page` with the 8192E page budget.
/// Returns `(REG_RQPN_NPQ, REG_RQPN)`.
pub fn reserved_pages(queues: Queues) -> (u32, u32) {
    let hq = if queues.high { chip::TX_PAGE_NUM_HI } else { 0 } as u32;
    let lq = if queues.low { chip::TX_PAGE_NUM_LO } else { 0 } as u32;
    let nq = if queues.normal {
        chip::TX_PAGE_NUM_NORM
    } else {
        0
    } as u32;
    let eq = 0u32;
    let pubq = chip::TX_TOTAL_PAGES as u32 - hq - lq - nq - 1;
    (nq | eq << 16, RQPN_LOAD | hq | lq << 8 | pubq << 16)
}

/// Silicon identity read by `rtl8192eu_identify_chip`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub cut: u8,
    /// 1 for RTL8191EU (1T2R bonding), 2 for RTL8192EU.
    pub tx_paths: u8,
    pub vendor: Vendor,
    pub rom_rev: u8,
    pub queues: Queues,
}

impl Identity {
    pub fn name(self) -> &'static str {
        if self.tx_paths == 1 {
            "8191EU"
        } else {
            "8192EU"
        }
    }
}

/// Decode `REG_SYS_CFG`/`REG_HPON_FSM`/`REG_GPIO_OUTSTS`. Test silicon
/// (`SYS_CFG_TRP_VAUX_EN`) is rejected as Linux does. An all-ones read is
/// treated as a missing device.
pub fn parse_identity(
    sys_cfg: u32,
    hpon_fsm: u32,
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
        tx_paths: if hpon_fsm & HPON_FSM_BONDING_MASK == HPON_FSM_BONDING_1T2R {
            1
        } else {
            2
        },
        vendor,
        rom_rev: (gpio_outsts >> 28) as u8,
        queues,
    })
}

/// Per-path 2.4 GHz power data from `struct rtl8192eu_efuse_tx_power`,
/// expanded exactly as `rtl8192eu_parse_efuse` stores it. Diff entries are
/// signed 4-bit EFUSE fields; index 0 of `ofdm_diff`/`ht40_diff` is zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathPower {
    pub cck: [u8; 6],
    pub ht40: [u8; 5],
    pub ofdm_diff: [i8; 4],
    pub ht20_diff: [i8; 4],
    pub ht40_diff: [i8; 4],
}

/// Factory data from `struct rtl8192eu_efuse`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Factory {
    pub identity: Identity,
    pub mac: [u8; 6],
    pub power: [PathPower; 2],
    pub channel_plan: u8,
    pub crystal_cap: u8,
    pub thermal: u8,
    pub iqk_lck: u8,
    pub pa_type: u8,
    pub lna_type_2g: u8,
    pub board_option: u8,
    pub antenna_option: u8,
}

fn nibble(value: u8) -> i8 {
    ((value << 4) as i8) >> 4
}

fn path_power(map: &[u8; EFUSE_MAP_LEN], base: usize) -> PathPower {
    let mut power = PathPower {
        cck: map[base..base + 6].try_into().unwrap(),
        ht40: map[base + 6..base + 11].try_into().unwrap(),
        ofdm_diff: [0; 4],
        ht20_diff: [0; 4],
        ht40_diff: [0; 4],
    };
    // `ht20_ofdm_1s_diff.b` is the high nibble.
    power.ht20_diff[0] = nibble(map[base + 11] >> 4);
    for i in 1..4 {
        // `struct rtl8723bu_pwr_idx`: ht20:4, ht40:4 | ofdm:4, cck:4.
        let lo = map[base + 12 + (i - 1) * 2];
        let hi = map[base + 13 + (i - 1) * 2];
        power.ht20_diff[i] = nibble(lo);
        power.ht40_diff[i] = nibble(lo >> 4);
        power.ofdm_diff[i] = nibble(hi);
    }
    power
}

/// `rtl8192eu_parse_efuse` over the logical map. A missing `0x8129` ID or a
/// multicast/zero MAC is rejected; nothing is defaulted.
pub fn parse_efuse(identity: Identity, map: &[u8; EFUSE_MAP_LEN]) -> Result<Factory, Error> {
    if map[..2] != [0x29, 0x81] {
        return Err(Error::BadEfuse);
    }
    let mac: [u8; 6] = map[0xd7..0xdd].try_into().unwrap();
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
        antenna_option: map[0xc9],
    })
}

/// Encode a gen2 H2C command (`struct h2c_cmd`): bytes 0..4 are the mailbox
/// word, bytes 4..8 the extension word. Returns `(ext, data)`.
pub fn h2c_words(command: &[u8]) -> Result<(Option<u32>, u32), Error> {
    if command.is_empty() || command.len() > 8 {
        return Err(Error::RuntimeState);
    }
    let mut raw = [0u8; 8];
    raw[..command.len()].copy_from_slice(command);
    let data = u32::from_le_bytes(raw[..4].try_into().unwrap());
    let ext = (command.len() > 4).then(|| u32::from_le_bytes(raw[4..].try_into().unwrap()));
    Ok((ext, data))
}

/// `rtl8xxxu_read_efuse8`.
async fn read_efuse8<I: ControlIo>(owner: &Owner<I>, offset: u16) -> Result<u8, Error> {
    owner.write8(REG_EFUSE_CTRL + 1, offset as u8).await?;
    let value = owner.read8(REG_EFUSE_CTRL + 2).await?;
    owner
        .write8(
            REG_EFUSE_CTRL + 2,
            (value & 0xfc) | ((offset >> 8) as u8 & 3),
        )
        .await?;
    let value = owner.read8(REG_EFUSE_CTRL + 3).await?;
    owner.write8(REG_EFUSE_CTRL + 3, value & 0x7f).await?;
    owner.read32(REG_EFUSE_CTRL).await?;
    let mut ready = false;
    for _ in 0..MAX_REG_POLL {
        if owner.read32(REG_EFUSE_CTRL).await? & (1 << 31) != 0 {
            ready = true;
            break;
        }
    }
    if !ready {
        return Err(Error::EfuseTimeout);
    }
    owner.delay_us(50).await;
    Ok(owner.read32(REG_EFUSE_CTRL).await? as u8)
}

/// `rtl8xxxu_read_efuse` (single-function chip). Decodes PG headers lazily,
/// stopping at the first `0xff` header like Linux.
pub(super) async fn read_efuse<I: ControlIo>(
    owner: &Owner<I>,
) -> Result<[u8; EFUSE_MAP_LEN], Error> {
    owner.read16(REG_9346CR).await?;
    owner.write8(REG_EFUSE_ACCESS, EFUSE_ACCESS_ENABLE).await?;
    let value = owner.read16(REG_SYS_ISO_CTRL).await?;
    if value & SYS_ISO_PWC_EV12V == 0 {
        owner
            .write16(REG_SYS_ISO_CTRL, value | SYS_ISO_PWC_EV12V)
            .await?;
    }
    let value = owner.read16(REG_SYS_FUNC).await?;
    if value & SYS_FUNC_ELDR == 0 {
        owner.write16(REG_SYS_FUNC, value | SYS_FUNC_ELDR).await?;
    }
    let value = owner.read16(REG_SYS_CLKR).await?;
    let clocks = SYS_CLK_LOADER_ENABLE | SYS_CLK_ANA8M;
    if value & clocks != clocks {
        owner.write16(REG_SYS_CLKR, value | clocks).await?;
    }
    let mut map = [0xff; EFUSE_MAP_LEN];
    let mut address = 0u16;
    while address < EFUSE_REAL_CONTENT {
        let header = read_efuse8(owner, address).await?;
        address += 1;
        if header == 0xff {
            break;
        }
        let (offset, mask) = if header & 0x1f == 0x0f {
            let ext = read_efuse8(owner, address).await?;
            address += 1;
            if ext & 0x0f == 0x0f {
                continue;
            }
            (
                ((header & 0xe0) >> 5) as usize | ((ext & 0xf0) >> 1) as usize,
                ext & 0x0f,
            )
        } else {
            ((header >> 4) as usize, header & 0x0f)
        };
        let mut map_addr = offset * 8;
        for word in 0..EFUSE_MAX_WORD_UNIT {
            if mask & (1 << word) != 0 {
                map_addr += 2;
                continue;
            }
            let low = read_efuse8(owner, address).await?;
            address += 1;
            if map_addr >= EFUSE_MAP_LEN - 1 {
                return Err(Error::BadEfuse);
            }
            map[map_addr] = low;
            map[map_addr + 1] = read_efuse8(owner, address).await?;
            address += 1;
            map_addr += 2;
        }
    }
    // Every prior transfer completed; closing the read gate is safe here.
    owner.write8(REG_EFUSE_ACCESS, EFUSE_ACCESS_DISABLE).await?;
    Ok(map)
}

/// `rtl8192eu_identify_chip` plus `rtl8xxxu_read_efuse` and
/// `rtl8192eu_parse_efuse`. The SIE queue set must be backed by real bulk-OUT
/// endpoints (Linux would index past `out_ep[]`).
pub(super) async fn factory<I: ControlIo>(
    owner: &Owner<I>,
    endpoints: Endpoints,
) -> Result<Factory, Error> {
    let sys_cfg = owner.read32(REG_SYS_CFG).await?;
    if sys_cfg == u32::MAX || sys_cfg & SYS_CFG_TRP_VAUX_EN != 0 {
        return Err(Error::UnsupportedSilicon);
    }
    let hpon = owner.read32(REG_HPON_FSM).await?;
    let gpio = owner.read32(REG_GPIO_OUTSTS).await?;
    let mut queues = Queues::from_sie(owner.read16(REG_NORMAL_SIE_EP_TX).await?);
    if queues.count() == 0 {
        queues = Queues::from_out_endpoints(endpoints.output_count)?;
    }
    if queues.count() > endpoints.output_count {
        return Err(Error::BadEndpoints);
    }
    let identity = parse_identity(sys_cfg, hpon, gpio, queues)?;
    let map = read_efuse(owner).await?;
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

/// `rtl8192e_crystal_afe_adjust`.
async fn crystal_afe_adjust<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    let value = owner.read8(REG_AFE_PLL_CTRL).await?;
    owner.write8(REG_AFE_PLL_CTRL, value & 0xfb).await?;
    let value = owner.read32(REG_AFE_CTRL4).await?;
    owner.write32(REG_AFE_CTRL4, value & 0xffff_fc7f).await?;
    let value = owner.read8(REG_AFE_PLL_CTRL).await?;
    owner.write8(REG_AFE_PLL_CTRL, value & 0xbf).await?;
    let value = owner.read32(REG_AFE_CTRL4).await?;
    owner.write32(REG_AFE_CTRL4, value & 0xffdf_ffff).await
}

/// `rtl8192e_emu_to_active`.
async fn emu_to_active<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    for clear in [1 << 7, 1 << 2, (1 << 3) | (1 << 4)] {
        let value = owner.read8(REG_APS_FSMCO + 1).await?;
        owner.write8(REG_APS_FSMCO + 1, value & !clear).await?;
    }
    poll32(owner, REG_APS_FSMCO, 1 << 17, 1 << 17).await?;
    let value = owner.read8(REG_APS_FSMCO + 2).await?;
    owner.write8(REG_APS_FSMCO + 2, value | 1).await?;
    let value = owner.read32(REG_APS_FSMCO).await?;
    owner
        .write32(REG_APS_FSMCO, value | APS_FSMCO_MAC_ENABLE)
        .await?;
    poll32(owner, REG_APS_FSMCO, APS_FSMCO_MAC_ENABLE, 0).await
}

/// `rtl8192eu_power_on`. Unlike the 8188E, Linux enables MAC TX/RX here.
pub(super) async fn power_on<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    if owner.read32(REG_SYS_CFG).await? & SYS_CFG_SPS_LDO_SEL != 0 {
        owner.write8(REG_LDO_SW_CTRL, 0xc3).await?;
    } else {
        let value = owner.read32(chip::REG_8192E_LDOV12_CTRL).await?;
        owner
            .write32(
                chip::REG_8192E_LDOV12_CTRL,
                (value & 0xff0f_ffff) | 0x0050_0000,
            )
            .await?;
        owner.write8(REG_LDO_SW_CTRL, 0x83).await?;
    }
    crystal_afe_adjust(owner).await?;
    // rtl8192e_disabled_to_emu
    let value = owner.read8(REG_APS_FSMCO + 1).await?;
    owner
        .write8(REG_APS_FSMCO + 1, value & !((1 << 3) | (1 << 4)))
        .await?;
    emu_to_active(owner).await?;
    owner.write16(REG_CR, 0).await?;
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
        .await
}

/// `rtl8192eu_active_to_emu`.
pub(super) async fn active_to_emu<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    let value = owner.read8(REG_RF_CTRL_8192E).await?;
    owner.write8(REG_RF_CTRL_8192E, value & !RF_ENABLE).await?;
    let value = owner.read8(REG_LEDCFG2).await?;
    owner
        .write8(REG_LEDCFG2, value & !LEDCFG2_DPDT_SELECT)
        .await?;
    let value = owner.read8(REG_APS_FSMCO + 1).await?;
    owner.write8(REG_APS_FSMCO + 1, value | (1 << 1)).await?;
    for _ in 0..MAX_REG_POLL {
        if owner.read8(REG_APS_FSMCO + 1).await? & (1 << 1) == 0 {
            return Ok(());
        }
        owner.delay_us(10).await;
    }
    Err(Error::PowerTimeout)
}

/// `rtl8192eu_emu_to_disabled`.
pub(super) async fn emu_to_disabled<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    let value = owner.read8(REG_APS_FSMCO + 1).await?;
    owner
        .write8(
            REG_APS_FSMCO + 1,
            (value & !((1 << 3) | (1 << 4))) | (1 << 3),
        )
        .await
}

/// `rtl8xxxu_reset_8051` (the generic reset the 8192EU fops select).
pub(super) async fn reset_8051<I: ControlIo>(owner: &Owner<I>) -> Result<(), Error> {
    let value = owner.read8(REG_RSV_CTRL + 1).await?;
    owner.write8(REG_RSV_CTRL + 1, value & !1).await?;
    let sys_func = owner.read16(REG_SYS_FUNC).await? & !SYS_FUNC_CPU_ENABLE;
    owner.write16(REG_SYS_FUNC, sys_func).await?;
    let value = owner.read8(REG_RSV_CTRL + 1).await?;
    owner.write8(REG_RSV_CTRL + 1, value | 1).await?;
    owner
        .write16(REG_SYS_FUNC, sys_func | SYS_FUNC_CPU_ENABLE)
        .await
}

/// `rtl8xxxu_init_device` between `power_on` and firmware download:
/// reserved pages (cold, `needs_full_init`), queue priority and the
/// `trxff_boundary = 0x3cff` RX page boundary.
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
    owner
        .write16(REG_TRXFF_BNDY + 2, chip::TRXFF_BOUNDARY)
        .await?;
    Ok(map)
}

/// `rtl8xxxu_gen2_h2c_cmd`. The mailbox index advances only after the
/// command words were written. Linux proceeds after an all-busy poll (its
/// `!retry` test sees -1); a still-busy mailbox is reported here instead.
pub(super) async fn h2c<I: ControlIo>(owner: &Owner<I>, command: &[u8]) -> Result<(), Error> {
    let (ext, data) = h2c_words(command)?;
    let claim = owner.h2c_claim()?;
    let mbox = claim.mailbox();
    let mut ready = false;
    for _ in 0..H2C_MBOX_POLLS {
        if owner.read8(REG_HMTFR).await? & (1 << mbox) == 0 {
            ready = true;
            break;
        }
    }
    if !ready {
        return Err(Error::MailboxBusy);
    }
    if let Some(ext) = ext {
        owner
            .write32(REG_HMBOX_EXT0_8723B + mbox as u16 * 4, ext)
            .await?;
    }
    owner.write32(REG_HMBOX_0 + mbox as u16 * 4, data).await?;
    claim.advance();
    Ok(())
}

/// Exclusive H2C mailbox claim (Linux `priv->h2c_mutex`).
pub(super) struct H2cClaim<'a> {
    pub(super) next: &'a core::sync::atomic::AtomicU8,
    pub(super) busy: &'a core::sync::atomic::AtomicBool,
}

impl H2cClaim<'_> {
    fn mailbox(&self) -> u8 {
        self.next.load(Ordering::Acquire) % H2C_MAX_MBOX
    }
    fn advance(&self) {
        let next = (self.mailbox() + 1) % H2C_MAX_MBOX;
        self.next.store(next, Ordering::Release);
    }
}

impl Drop for H2cClaim<'_> {
    fn drop(&mut self) {
        self.busy.store(false, Ordering::Release);
    }
}
