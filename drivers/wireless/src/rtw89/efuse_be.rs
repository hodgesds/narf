// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A "BE" generation EFUSE access.
//!
//! Mirrors Linux `rtw89/efuse_be.c` + the 8922A dispatch in
//! `rtw89/rtw8922a.c:876..895` (torvalds/linux @ cbbddb6). The BE EFUSE
//! protocol differs from the AX one in `efuse.rs` in every respect:
//! 4-byte-aligned DDV physical reads through `R_BE_EFUSE_CTRL`, a
//! power-cut enable/disable sequence around each dump, a 3-byte-header
//! logical parser over per-block windows, and a MAC address that (for
//! PCIe) is read from BAR registers, NOT from the logical map.
//!
//! Scope notes, all deliberate:
//! - The DAV physical path (`rtw89_dump_physical_efuse_map_dav_be`,
//!   XTAL_SI registers) is NOT implemented: 8922A's DAV sizes are 0
//!   (`chip_8922a::DAV_PHY_EFUSE_SIZE` / `DAV_LOG_EFUSE_SIZE`), so the
//!   Linux parse driver never takes that branch for this chip.
//! - The 8922D-only paths are NOT implemented: the SYS logical block
//!   and the vcore/dswr power-data readers (`rtw89_efuse_read_pwr_data_be`
//!   returns 0 immediately for non-8922D chips).
//! - TSSI / gain-offset power parsing from the RF block is the power
//!   profile remainder, not this module: only `rfe_type`, `xtal_k` and
//!   `country_code` are extracted here.
//! - Where Linux reads past the end of a truncated physical map, this
//!   port returns `BeEfuseError::Truncated` instead: NARF must not
//!   reproduce an out-of-bounds read as a feature.
//! - Poll timing: Linux polls RDY every 1 µs with a 1 s timeout and the
//!   power-state every 50 µs with a 5 ms timeout. The timeouts are
//!   protocol; the tick interval is host policy, expressed here through
//!   `efuse::Io::delay_us` so fixtures can observe it exactly.

use super::chip_8922a::{self, EfuseBlock, EfuseBlockKind};
use super::efuse::Io;

// ── BE EFUSE registers and bits (Linux `reg.h`) ─────────────────────

/// `R_BE_SYS_ISO_CTRL` (`reg.h:4405`).
pub(super) const SYS_ISO_CTRL: u32 = 0x0000;
/// `B_BE_PWC_EV2EF_S` (`reg.h:4409`).
pub(super) const PWC_EV2EF_S: u16 = 1 << 14;
/// `B_BE_PWC_EV2EF_B` (`reg.h:4410`).
pub(super) const PWC_EV2EF_B: u16 = 1 << 15;
/// `B_BE_ISO_EB2CORE` (`reg.h:4417`).
pub(super) const ISO_EB2CORE: u16 = 1 << 8;
/// `R_BE_SYS_WL_EFUSE_CTRL` (`reg.h:4419`).
pub(super) const SYS_WL_EFUSE_CTRL: u32 = 0x000A;
/// `B_BE_AUTOLOAD_SUS` (`reg.h:4424`).
pub(super) const AUTOLOAD_SUS: u32 = 1 << 5;
/// `R_BE_EFUSE_CTRL` (`reg.h:4479`).
pub(super) const EFUSE_CTRL: u32 = 0x0030;
/// `B_BE_EF_RDY` (`reg.h:4486`).
pub(super) const EF_RDY: u32 = 1 << 29;
/// `B_BE_EF_ADDR_MASK` (`reg.h:4480`).
pub(super) const EF_ADDR_MASK: u32 = 0xFFFF;
/// `R_BE_EFUSE_CTRL_1_V1` (`reg.h:4489`).
pub(super) const EFUSE_CTRL_1_V1: u32 = 0x0034;
/// `R_BE_WL_BT_PWR_CTRL` (`reg.h:4495`).
pub(super) const WL_BT_PWR_CTRL: u32 = 0x0068;
/// `B_BE_BT_DISN_EN` (`reg.h:4511`).
pub(super) const BT_DISN_EN: u32 = 1 << 16;
/// `R_BE_EFUSE_CTRL_2_V1` (`reg.h:4533`).
pub(super) const EFUSE_CTRL_2_V1: u32 = 0x00A4;
/// `B_BE_EF_BURST` (`reg.h:4552`).
pub(super) const EF_BURST: u32 = 1 << 19;
/// `R_BE_PMC_DBG_CTRL2` (`reg.h:4559`).
pub(super) const PMC_DBG_CTRL2: u32 = 0x00CC;
/// `B_BE_SYSON_DIS_PMCR_BE_WRMSK` (`reg.h:4561`).
pub(super) const SYSON_DIS_PMCR_BE_WRMSK: u8 = 1 << 2;
/// `R_BE_IC_PWR_STATE` (`reg.h:4645`).
pub(super) const IC_PWR_STATE: u32 = 0x03F0;
/// `B_BE_WHOLE_SYS_PWR_STE_MASK` = GENMASK(25, 16) (`reg.h:4646`).
/// Linux reads this field with `read32_mask`, which shifts right by
/// the mask's first set bit (16); `SYS_ACT` below is the SHIFTED value,
/// so comparisons must use `SYS_ACT << 16` against the raw register.
pub(super) const WHOLE_SYS_PWR_STE_MASK: u32 = 0x3FF << 16;
/// `MAC_AX_SYS_ACT` (`reg.h:4647`).
pub(super) const SYS_ACT: u32 = 0x220;

/// PCIe BAR address of the EFUSE MAC for PCIe
/// (`rtw8922a.c:847`, `rtw8922a_read_efuse_mac_addr`).
pub(super) const MAC_ADDR_PCIE: u32 = 0x3104;
/// USB BAR address of the EFUSE MAC for USB (`rtw8922a.c:856`).
pub(super) const MAC_ADDR_USB: u32 = 0x4078;
/// Logical-map offset of the EFUSE MAC for SDIO
/// (`rtw8922a.c:852`, `log_map + 0x001A`).
pub(super) const MAC_ADDR_SDIO_LOG_OFF: usize = 0x001A;

/// `EF_FV_OFSET_BE_V1` (`efuse.h:100`).
pub(super) const FV_OFFSET_BE_V1: u32 = 0x17CA;
/// `EF_CV_MASK` = bits 7..4 (`efuse.h:102`).
pub(super) const CV_MASK: u8 = 0xF0;
/// `EF_CV_INV` = 15 (`efuse.h:103`).
pub(super) const CV_INV: u8 = 15;
/// `EFUSE_THERMAL_K_OFFSET_BE` (`efuse_be.c:18`).
pub(super) const THERMAL_K_OFFSET_BE: u32 = 0x17CC;
/// `EFUSE_THERMAL_K_VALID_BE` = bit 9 (`efuse_be.c:19`).
pub(super) const THERMAL_K_VALID: u16 = 1 << 9;
/// `EFUSE_THERMAL_K_SIGN_BE` = bit 8 (`efuse_be.c:20`).
pub(super) const THERMAL_K_SIGN: u16 = 1 << 8;
/// `EFUSE_THERMAL_K_VAL_BE` = bits 7..0 (`efuse_be.c:21`).
pub(super) const THERMAL_K_VAL: u16 = 0xFF;
/// `EFUSE_SEC_BE_START` (`efuse_be.c:16`).
pub(super) const SEC_BE_START: u32 = 0x1580;
/// `EFUSE_SEC_BE_SIZE` (`efuse_be.c:17`).
pub(super) const SEC_BE_SIZE: usize = 4;
/// `EFUSE_SB_CRYP_SEL_ADDR` (`efuse_be.c:12`).
pub(super) const SB_CRYP_SEL_ADDR: u32 = 0x1582;
/// `EFUSE_SB_CRYP_SEL_DEFAULT` (`efuse_be.c:14`).
pub(super) const SB_CRYP_SEL_DEFAULT: u16 = 0xFFFF;
/// `EFUSE_EXTERNALPN_ADDR_BE` (`efuse_be.c:10`).
pub(super) const EXTERNALPN_ADDR_BE: u32 = 0x1580;
/// `EFUSE_SERIALNUM_ADDR_BE` (`efuse_be.c:11`).
pub(super) const SERIALNUM_ADDR_BE: u32 = 0x1581;
/// `sb_sel_mgn` (`efuse_be.c:28..30`).
pub(super) const SB_SEL_MGN: [u32; 2] = [0x8000100, 0xC000180];

/// RF logical-block field offsets, derived from `struct rtw8922a_efuse`
/// (`rtw8922a.h`): `country_code[2]`, `rsvd[0xe]`, `path_a_tssi` (6 + 5 +
/// 7 + 14 + 10 = 42), `path_b_tssi` (42), `rsvd1[0x54]`, `channel_plan`,
/// `xtal_k`, `rsvd2[0x7]`, `board_info`, `rsvd3[0x8]`, `rfe_type`.
/// country = 0, xtal_k = 2 + 14 + 42 + 42 + 84 + 1 = 185,
/// rfe_type = 185 + 1 + 7 + 1 + 8 = 202.
pub(super) const RF_COUNTRY_OFF: usize = 0;
/// Offset of `xtal_k` in the RF logical block (see above).
pub(super) const RF_XTAL_K_OFF: usize = 185;
/// Offset of `rfe_type` in the RF logical block (see above).
pub(super) const RF_RFE_TYPE_OFF: usize = 202;

/// Header field masks (`efuse_be.c:206..210`).
pub(super) const HDR_PAGE_MASK: u32 = 0xE0000;
/// `EFUSE_HDR_OFFSET_MASK` = bits 16..4 (`efuse_be.c:206`).
pub(super) const HDR_OFFSET_MASK: u32 = 0x1FFF0;
/// `EFUSE_HDR_OFFSET_DAV_MASK` = bits 11..4 (`efuse_be.c:207`).
pub(super) const HDR_OFFSET_DAV_MASK: u32 = 0xFF0;
/// `EFUSE_HDR_WORD_EN_MASK` = bits 3..0 (`efuse_be.c:208`).
pub(super) const HDR_WORD_EN_MASK: u32 = 0xF;
/// `RTW89_EFUSE_MAX_BLOCK_SIZE` (`efuse.h:47`).
pub(super) const MAX_BLOCK_SIZE: u32 = 0x10000;
/// `RTW89_EFUSE_BLOCK_ID_MASK` = bits 31..16 (`efuse.h:45`).
pub(super) const BLOCK_ID_MASK: u32 = 0xFFFF_0000;
/// `RTW89_EFUSE_BLOCK_SIZE_MASK` = bits 15..0 (`efuse.h:46`).
pub(super) const BLOCK_SIZE_MASK: u32 = 0xFFFF;

// Host-side IO for BE EFUSE access is the shared `efuse::Io` BAR-window
// contract (already implemented by the production `Mmio` adapter, so a
// future probe lane needs no new adapter). `delay_us` is observed by
// fixtures (the ISO sequence needs 1 ms sleeps; the RDY poll ticks at
// 1 µs, the power-state poll at 50 µs). A production implementation
// must use a spin-based delay if called with IRQs disabled.

/// BE EFUSE failures. Linux errno mapping in parentheses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BeEfuseError {
    /// Address or size not 4-byte aligned (-EINVAL).
    Unaligned,
    /// RDY poll timed out; power-cut left enabled, as in Linux (-EBUSY).
    Busy,
    /// Power-state poll timed out (-ETIMEDOUT; warned-and-continued by
    /// the dump wrapper, as in Linux).
    PowerStateTimeout,
    /// Block index beyond the EFUSE space (-EINVAL).
    InvalidBlock,
    /// Physical map too short for the header/word read (NARF-only
    /// bound; Linux reads unchecked here).
    Truncated,
    /// No cut version / no thermal K (both -ENOENT in Linux).
    NotPresent,
}

fn set_bits_u8(io: &mut impl Io, addr: u32, bits: u8) {
    let v = io.read8(addr as u64);
    io.write8(addr as u64, v | bits);
}

fn clear_bits_u8(io: &mut impl Io, addr: u32, bits: u8) {
    let v = io.read8(addr as u64);
    io.write8(addr as u64, v & !bits);
}

fn set_bits_u16(io: &mut impl Io, addr: u32, bits: u16) {
    let v = io.read16(addr as u64);
    io.write16(addr as u64, v | bits);
}

fn clear_bits_u16(io: &mut impl Io, addr: u32, bits: u16) {
    let v = io.read16(addr as u64);
    io.write16(addr as u64, v & !bits);
}

fn set_bits_u32(io: &mut impl Io, addr: u32, bits: u32) {
    let v = io.read32(addr as u64);
    io.write32(addr as u64, v | bits);
}

fn clear_bits_u32(io: &mut impl Io, addr: u32, bits: u32) {
    let v = io.read32(addr as u64);
    io.write32(addr as u64, v & !bits);
}

/// Whether the ISO sequence is skipped: Linux `aphy_patch` is false
/// exactly when the chip is 8922A and the cut version is CAV
/// (`efuse_be.c:37..39`). NARF's `cut` numbering is assumed to match
/// Linux's `cv` ordering (CAV = cut 0, the first cut); verify on silicon
/// if a cut mapping table ever appears.
fn skip_iso_sequence(cut_is_cav: bool) -> bool {
    cut_is_cav
}

/// `rtw89_enable_efuse_pwr_cut_ddv_be` (`efuse_be.c:32..51`).
fn enable_pwr_cut(io: &mut impl Io, cut_is_cav: bool) {
    set_bits_u8(io, PMC_DBG_CTRL2, SYSON_DIS_PMCR_BE_WRMSK);
    if !skip_iso_sequence(cut_is_cav) {
        set_bits_u16(io, SYS_ISO_CTRL, PWC_EV2EF_S);
        io.delay_us(1000);
        set_bits_u16(io, SYS_ISO_CTRL, PWC_EV2EF_B);
        clear_bits_u16(io, SYS_ISO_CTRL, ISO_EB2CORE);
    }
    set_bits_u32(io, EFUSE_CTRL_2_V1, EF_BURST);
}

/// `rtw89_disable_efuse_pwr_cut_ddv_be` (`efuse_be.c:53..71`).
fn disable_pwr_cut(io: &mut impl Io, cut_is_cav: bool) {
    if !skip_iso_sequence(cut_is_cav) {
        set_bits_u16(io, SYS_ISO_CTRL, ISO_EB2CORE);
        clear_bits_u16(io, SYS_ISO_CTRL, PWC_EV2EF_B);
        io.delay_us(1000);
        clear_bits_u16(io, SYS_ISO_CTRL, PWC_EV2EF_S);
    }
    clear_bits_u8(io, PMC_DBG_CTRL2, SYSON_DIS_PMCR_BE_WRMSK);
    clear_bits_u32(io, EFUSE_CTRL_2_V1, EF_BURST);
}

/// `rtw89_dump_physical_efuse_map_ddv_be` (`efuse_be.c:73..108`).
/// On RDY timeout returns `Busy` WITHOUT disabling power-cut, as Linux
/// does (the early return skips the disable call).
pub(super) fn dump_physical_ddv(
    io: &mut impl Io,
    cut_is_cav: bool,
    dump_addr: u32,
    out: &mut [u8],
) -> Result<(), BeEfuseError> {
    if dump_addr % 4 != 0 || out.len() % 4 != 0 {
        return Err(BeEfuseError::Unaligned);
    }
    enable_pwr_cut(io, cut_is_cav);
    let mut addr = dump_addr;
    let mut off = 0;
    while off < out.len() {
        // `efuse_ctl & ~B_BE_EF_RDY`: the address mask (bits 15..0)
        // never sets RDY (bit 29), so this is exactly `addr`.
        io.write32(EFUSE_CTRL as u64, addr & EF_ADDR_MASK);
        let mut ready = false;
        // `read_poll_timeout_atomic(..., 1, 1000000, ...)`: 1 µs ticks,
        // 1 s timeout.
        for _ in 0..1_000_000 {
            if io.read32(EFUSE_CTRL as u64) & EF_RDY != 0 {
                ready = true;
                break;
            }
            io.delay_us(1);
        }
        if !ready {
            return Err(BeEfuseError::Busy);
        }
        let data = io.read32(EFUSE_CTRL_1_V1 as u64);
        out[off..off + 4].copy_from_slice(&data.to_le_bytes());
        addr += 4;
        off += 4;
    }
    disable_pwr_cut(io, cut_is_cav);
    Ok(())
}

/// `rtw89_cnv_efuse_state_be` (`efuse_be.c:152..171`).
/// `idle = true` sets the BT-disable bit and returns Ok; `idle = false`
/// clears it and polls the whole-system power state for `SYS_ACT`.
pub(super) fn convert_state(io: &mut impl Io, idle: bool) -> Result<(), BeEfuseError> {
    if idle {
        set_bits_u32(io, WL_BT_PWR_CTRL, BT_DISN_EN);
        return Ok(());
    }
    clear_bits_u32(io, WL_BT_PWR_CTRL, BT_DISN_EN);
    // `read_poll_timeout(..., 50, 5000, ...)`: 50 µs ticks, 5 ms timeout.
    // The masked field is compared after the `read32_mask` shift (16).
    for _ in 0..100 {
        if io.read32(IC_PWR_STATE as u64) & WHOLE_SYS_PWR_STE_MASK == SYS_ACT << 16 {
            return Ok(());
        }
        io.delay_us(50);
    }
    if io.read32(IC_PWR_STATE as u64) & WHOLE_SYS_PWR_STE_MASK == SYS_ACT << 16 {
        return Ok(());
    }
    Err(BeEfuseError::PowerStateTimeout)
}

/// `rtw89_dump_physical_efuse_map_be` for the DDV path
/// (`efuse_be.c:173..205`). Empty output returns Ok immediately (no
/// state conversion at all, as in Linux). A state-conversion failure is
/// warned-and-continued, i.e. ignored here, as in Linux. A dump failure
/// returns early WITHOUT the trailing idle conversion, as in Linux.
pub(super) fn dump_physical(
    io: &mut impl Io,
    cut_is_cav: bool,
    dump_addr: u32,
    out: &mut [u8],
) -> Result<(), BeEfuseError> {
    if out.is_empty() {
        return Ok(());
    }
    let _ = convert_state(io, false);
    dump_physical_ddv(io, cut_is_cav, dump_addr, out)?;
    let _ = convert_state(io, true);
    Ok(())
}

/// One parsed logical word write, following the edge rules in
/// `rtw89_eeprom_parser_be` (`efuse_be.c:291..306`). Indices use
/// wrapping arithmetic to mirror the C unsigned arithmetic exactly:
/// in the first-word partial case `log_idx` can be `page_offset - 1`
/// (odd page offset), where the base wraps and `base + 1` is 0.
fn write_logical_word(
    log_map: &mut [u8],
    log_idx: u32,
    min: u32,
    max: u32,
    page_offset: u32,
    size: u32,
    word: [u8; 2],
) {
    let base = (log_idx as usize).wrapping_sub(page_offset as usize);
    if log_idx == min && page_offset > min {
        log_map[base.wrapping_add(1)] = word[1];
    } else if log_idx + 2 == max && page_offset + size < max {
        log_map[base] = word[0];
    } else {
        log_map[base] = word[0];
        log_map[base.wrapping_add(1)] = word[1];
    }
}

/// `rtw89_eeprom_parser_be` (`efuse_be.c:226..315`) for one block.
/// `phy_map` is the full physical dump (0x1300 bytes for 8922A);
/// `log_map` is filled with 0xff then overwritten for this block's
/// window. `sec_ctrl_size` is `chip->sec_ctrl_efuse_size` (4 for 8922A):
/// the parser starts at that physical index.
pub(super) fn parse_logical_block(
    phy_map: &[u8],
    block: &EfuseBlock,
    kind: EfuseBlockKind,
    sec_ctrl_size: u32,
    log_map: &mut [u8],
) -> Result<(), BeEfuseError> {
    let page = (block.offset & BLOCK_ID_MASK) >> 16;
    let page_offset = block.offset & BLOCK_SIZE_MASK;
    let size = block.size;
    if log_map.len() < size as usize {
        return Err(BeEfuseError::Truncated);
    }
    for b in log_map.iter_mut().take(size as usize) {
        *b = 0xff;
    }
    let min = page_offset & !1;
    let max = (page_offset + size + 1) & !1;
    let is_adie = kind == EfuseBlockKind::Adie;
    let mut phy_idx = sec_ctrl_size as usize;
    loop {
        let (blk_page, blk_idx, word_en) = if is_adie {
            let h0 = *phy_map.get(phy_idx).ok_or(BeEfuseError::Truncated)?;
            let h1 = *phy_map.get(phy_idx + 1).ok_or(BeEfuseError::Truncated)?;
            if h0 == 0xff || h1 == 0xff {
                break;
            }
            phy_idx += 2;
            let hdr = ((h0 as u32) << 8) | h1 as u32;
            (
                page,
                (hdr & HDR_OFFSET_DAV_MASK) >> 4,
                hdr & HDR_WORD_EN_MASK,
            )
        } else {
            let h0 = *phy_map.get(phy_idx).ok_or(BeEfuseError::Truncated)?;
            let h1 = *phy_map.get(phy_idx + 1).ok_or(BeEfuseError::Truncated)?;
            let h2 = *phy_map.get(phy_idx + 2).ok_or(BeEfuseError::Truncated)?;
            if h0 == 0xff || h1 == 0xff || h2 == 0xff {
                break;
            }
            phy_idx += 3;
            let hdr = ((h0 as u32) << 16) | ((h1 as u32) << 8) | h2 as u32;
            (
                (hdr & HDR_PAGE_MASK) >> 17,
                (hdr & HDR_OFFSET_MASK) >> 4,
                hdr & HDR_WORD_EN_MASK,
            )
        };
        if blk_idx >= MAX_BLOCK_SIZE >> 3 {
            return Err(BeEfuseError::InvalidBlock);
        }
        for i in 0..4u32 {
            // A set word-enable bit means the word is NOT present:
            // no bytes consumed, no index advance.
            if word_en & (1 << i) != 0 {
                continue;
            }
            if phy_idx >= phy_map.len().saturating_sub(1) {
                return Err(BeEfuseError::Truncated);
            }
            let log_idx = (blk_idx << 3) + (i << 1);
            if blk_page == page && log_idx >= min && log_idx < max {
                let val0 = phy_map[phy_idx];
                let val1 = phy_map[phy_idx + 1];
                write_logical_word(log_map, log_idx, min, max, page_offset, size, [val0, val1]);
            }
            // The advance is unconditional for present words, even
            // when the block belongs to another page.
            phy_idx += 2;
        }
        if phy_idx >= phy_map.len() {
            break;
        }
    }
    Ok(())
}

/// `rtw89_efuse_read_ecv_be` (`efuse_be.c:440..462`).
/// Returns the cut version, or `NotPresent` when the field reads 0xF.
pub(super) fn read_ecv(io: &mut impl Io, cut_is_cav: bool) -> Result<u8, BeEfuseError> {
    let dump_addr = FV_OFFSET_BE_V1 & !3;
    let mut buff = [0u8; 4];
    dump_physical(io, cut_is_cav, dump_addr, &mut buff)?;
    let val = buff[(FV_OFFSET_BE_V1 & 0x3) as usize];
    let ecv = (val & CV_MASK) >> 4;
    if ecv == CV_INV {
        return Err(BeEfuseError::NotPresent);
    }
    Ok(ecv)
}

/// `rtw89_efuse_read_thermal_k_be` (`efuse_be.c:464..486`).
/// Returns the signed thermal K, or `NotPresent` when the VALID bit
/// says no K is stored (Linux sets thermal_k = 0 and returns -ENOENT).
pub(super) fn read_thermal_k(io: &mut impl Io, cut_is_cav: bool) -> Result<i16, BeEfuseError> {
    let mut buff = [0u8; 4];
    dump_physical(io, cut_is_cav, THERMAL_K_OFFSET_BE, &mut buff)?;
    let val16 = u16::from_le_bytes([buff[0], buff[1]]);
    if val16 & THERMAL_K_VALID != 0 {
        return Err(BeEfuseError::NotPresent);
    }
    let mut k = (val16 & THERMAL_K_VAL) as i16;
    if val16 & THERMAL_K_SIGN != 0 {
        k = -k;
    }
    Ok(k)
}

/// MSS device-type decode (`efuse.c:403..421`, chip-independent table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MssDevType {
    WinlinInbox,
    NonlinInboxNonCob,
    NonlinInboxCob,
    NonwinInbox,
    Default,
}
impl MssDevType {
    /// Linux-mapped device index (`efuse.c:400..425`
    /// `get_mss_dev_type_idx`): the raw fuse nibbles 0xC/0xA/0x9/0x6
    /// map to 0/1/2/3 and the default 0xF stays 0xF
    /// (`RTW89_FW_MSS_DEV_TYPE_FWSEC_DEF`). This is the index
    /// `fw.c::__get_mssc_key_idx` multiplies into the MSS bitmap —
    /// the same index space the AX fuse decoder produces in
    /// `secure::Fuses`, so one signature-selection rule serves both
    /// generations.
    pub(super) const fn index(self) -> u8 {
        match self {
            Self::WinlinInbox => 0,
            Self::NonlinInboxNonCob => 1,
            Self::NonlinInboxCob => 2,
            Self::NonwinInbox => 3,
            Self::Default => 15,
        }
    }
}

/// Decoded firmware-secure state (`efuse_be.c:488..540` +
/// `efuse.c:370..402`). `secure_boot` is false on every early-out path
/// (default cryp-sel, invalid cryp-sel index, MSS decode failure), as
/// in Linux; `sb_sel_mgn` is still set when the index was valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SecureInfo {
    pub(super) secure_boot: bool,
    pub(super) sb_sel_mgn: Option<u32>,
    pub(super) mss_dev_type: Option<MssDevType>,
    pub(super) mss_cust_idx: u8,
    pub(super) mss_key_num: u8,
}
impl SecureInfo {
    /// Erased/default secure state: secure boot off, no magnitude, no
    /// MSS selection (the `sb_cryp_sel == 0xFFFF` early-out).
    pub(super) const fn disabled() -> Self {
        Self {
            secure_boot: false,
            sb_sel_mgn: None,
            mss_dev_type: None,
            mss_cust_idx: 0,
            mss_key_num: 0,
        }
    }
}

/// `get_sb_cryp_sel_idx` (`efuse_be.c:530..560`): the low byte must be
/// a palindrome over its 4 bit pairs with exactly one zero pair (base =
/// pair index * 16), and the high byte's nibbles must XOR to 0xF.
/// Returns `u16::MAX` on any violation (Linux's invalid sentinel).
fn sb_cryp_sel_idx(sb_cryp_sel: u16) -> u16 {
    let form = (sb_cryp_sel & 0xFF) as u8;
    let idx = (sb_cryp_sel >> 8) as u8;
    let mut cnt_zero = 0u8;
    let mut base = 0u16;
    for i in 0..4u8 {
        let low = (form >> i) & 1;
        let high = (form >> (7 - i)) & 1;
        if low != high {
            return u16::MAX;
        }
        if low != 0 {
            continue;
        }
        cnt_zero += 1;
        if cnt_zero == 1 {
            base = i as u16 * 16;
        } else {
            return u16::MAX;
        }
    }
    let low_nib = idx & 0x0F;
    let high_nib = (idx >> 4) & 0x0F;
    if (low_nib ^ high_nib) != 0xF {
        return u16::MAX;
    }
    base + low_nib as u16
}

/// `rtw89_efuse_recognize_mss_info_v1` (`efuse.c:370..402`), minus the
/// 8852B-only special case (b1 == 0xFF, b2 == 0x6E), which is
/// chip-gated and cannot fire for 8922A.
fn recognize_mss_v1(b1: u8, b2: u8) -> Result<(MssDevType, u8, u8), BeEfuseError> {
    let raw_type = b1 & 0x0F;
    let dev_type = match raw_type {
        0xC => MssDevType::WinlinInbox,
        0xA => MssDevType::NonlinInboxNonCob,
        0x9 => MssDevType::NonlinInboxCob,
        0x6 => MssDevType::NonwinInbox,
        0xF => MssDevType::Default,
        _ => return Err(BeEfuseError::NotPresent),
    };
    let cust_idx = 0x1F - (((b1 >> 4) & 0x0F) | (((b2 >> 6) & 0x01) << 4));
    let key_num = 0x0F - (b2 & 0x0F);
    Ok((dev_type, cust_idx, key_num))
}

/// `rtw89_efuse_read_fw_secure_be` (`efuse_be.c:488..540`).
pub(super) fn read_secure(io: &mut impl Io, cut_is_cav: bool) -> Result<SecureInfo, BeEfuseError> {
    let mut sec_map = [0u8; SEC_BE_SIZE];
    dump_physical(io, cut_is_cav, SEC_BE_START, &mut sec_map)?;
    let sb_cryp_sel = u16::from_le_bytes([
        sec_map[(SB_CRYP_SEL_ADDR - SEC_BE_START) as usize],
        sec_map[(SB_CRYP_SEL_ADDR - SEC_BE_START + 1) as usize],
    ]);
    let mut info = SecureInfo {
        secure_boot: false,
        sb_sel_mgn: None,
        mss_dev_type: None,
        mss_cust_idx: 0,
        mss_key_num: 0,
    };
    if sb_cryp_sel == SB_CRYP_SEL_DEFAULT {
        return Ok(info);
    }
    let idx = sb_cryp_sel_idx(sb_cryp_sel);
    if idx as usize >= SB_SEL_MGN.len() {
        return Ok(info);
    }
    info.sb_sel_mgn = Some(SB_SEL_MGN[idx as usize]);
    let b1 = sec_map[(EXTERNALPN_ADDR_BE - SEC_BE_START) as usize];
    let b2 = sec_map[(SERIALNUM_ADDR_BE - SEC_BE_START) as usize];
    match recognize_mss_v1(b1, b2) {
        Ok((dev_type, cust_idx, key_num)) => {
            info.mss_dev_type = Some(dev_type);
            info.mss_cust_idx = cust_idx;
            info.mss_key_num = key_num;
            info.secure_boot = true;
        }
        Err(_) => {
            // Linux `goto out` with secure_boot still false.
        }
    }
    Ok(info)
}

/// Host controller type, selecting the HCI_DIG block and the MAC source
/// in `BeFactory::read` (Linux `rtw89_parse_efuse_map_be` picks the USB
/// block only for USB; PCIe and SDIO share the PCIe/SDIO block).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Hci {
    Pcie,
    Usb,
    Sdio,
}

/// The 8922A factory read: MAC, RFE type, crystal cap, country code,
/// PHY-cap window, cut version, thermal K. This is the BE analog of
/// `Factory::read`'s output for AX chips, built from the BE physical
/// dump + logical parse instead of the AX `decode_map` path (which
/// must NOT be reused: the BE logical space is 0x70000 bytes across
/// per-block windows, not one flat 1536/2048-byte buffer).
///
/// MAC policy differs from Linux here on purpose: Linux logs and
/// randomizes on a zero MAC; NARF keeps the raw bytes and lets the
/// caller apply `mac_is_valid` (the AX factory does the same).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct BeFactory {
    pub(super) mac: [u8; 6],
    pub(super) rfe_type: u8,
    pub(super) xtal_cap: u8,
    pub(super) country: [u8; 2],
    pub(super) phycap: [u8; chip_8922a::PHYCAP_SIZE],
    pub(super) cv: Option<u8>,
    pub(super) thermal_k: Option<i16>,
    /// Firmware-secure fuse state (`read_secure`, Linux
    /// `rtw89_efuse_read_fw_secure_be`): the secure-download plan's
    /// input. A failed secure-window read fails this factory read
    /// rather than defaulting to secure-boot-off.
    pub(super) secure: SecureInfo,
}

fn read_mac(io: &mut impl Io, hci: Hci, hci_log: &[u8]) -> [u8; 6] {
    let mut mac = [0u8; 6];
    match hci {
        Hci::Pcie | Hci::Usb => {
            let base = if hci == Hci::Pcie {
                MAC_ADDR_PCIE
            } else {
                MAC_ADDR_USB
            };
            for i in 0..3 {
                let v = io.read16((base + (i as u32) * 2) as u64);
                mac[i * 2] = (v & 0xFF) as u8;
                mac[i * 2 + 1] = (v >> 8) as u8;
            }
        }
        Hci::Sdio => {
            mac.copy_from_slice(&hci_log[MAC_ADDR_SDIO_LOG_OFF..MAC_ADDR_SDIO_LOG_OFF + 6]);
        }
    }
    mac
}

impl BeFactory {
    /// `rtw89_parse_efuse_map_be` + the 8922A `read_efuse` dispatch
    /// (`efuse_be.c:340..428`, `rtw8922a.c:876..895`), minus the SYS
    /// block (8922D-only) and the DAV dump (8922A DAV sizes are 0).
    /// The autoload check is warn-and-continue in Linux, so a missing
    /// autoload bit does not fail this read.
    pub(super) fn read(
        io: &mut impl Io,
        cut_is_cav: bool,
        hci: Hci,
    ) -> Result<BeFactory, BeEfuseError> {
        let _ = io.read32(SYS_WL_EFUSE_CTRL as u64) & AUTOLOAD_SUS;
        let mut phy_map = [0u8; chip_8922a::PHYSICAL_EFUSE_SIZE];
        dump_physical(io, cut_is_cav, 0, &mut phy_map)?;
        let hci_block = match hci {
            Hci::Usb => (&chip_8922a::EFUSE_BLOCKS[3], EfuseBlockKind::HciDigUsb),
            _ => (&chip_8922a::EFUSE_BLOCKS[2], EfuseBlockKind::HciDigPcieSdio),
        };
        let mut hci_log = [0u8; 0x4800];
        parse_logical_block(
            &phy_map,
            hci_block.0,
            hci_block.1,
            chip_8922a::SEC_CTRL_EFUSE_SIZE as u32,
            &mut hci_log,
        )?;
        let mut rf_log = [0u8; 0x240];
        parse_logical_block(
            &phy_map,
            &chip_8922a::EFUSE_BLOCKS[1],
            EfuseBlockKind::Rf,
            chip_8922a::SEC_CTRL_EFUSE_SIZE as u32,
            &mut rf_log,
        )?;
        let mac = read_mac(io, hci, &hci_log);
        let mut phycap = [0u8; chip_8922a::PHYCAP_SIZE];
        dump_physical(io, cut_is_cav, chip_8922a::PHYCAP_ADDR, &mut phycap)?;
        let cv = read_ecv(io, cut_is_cav).ok();
        let thermal_k = match read_thermal_k(io, cut_is_cav) {
            Ok(k) => Some(k),
            Err(BeEfuseError::NotPresent) => None,
            Err(e) => return Err(e),
        };
        // The secure window is read last, in the same powered dump
        // window as the map above: the download plan must know the
        // real fuse state before any image is trusted.
        let secure = read_secure(io, cut_is_cav)?;
        Ok(BeFactory {
            mac,
            rfe_type: rf_log[RF_RFE_TYPE_OFF],
            xtal_cap: rf_log[RF_XTAL_K_OFF],
            country: [rf_log[RF_COUNTRY_OFF], rf_log[RF_COUNTRY_OFF + 1]],
            phycap,
            cv,
            thermal_k,
            secure,
        })
    }
}

/// `struct rtw89_power_trim_info` (core.h:7066) as parsed from the
/// PHY-cap window — the parse half of the 8922A power trim. The
/// application half (RF writes) is NOT here: it needs the
/// `RR_BIASA` TXG/TXA/BIASD field constants, which are a follow-up.
/// Linux stores the thermal trim as an s8 in a u8 array; NARF keeps
/// the signed value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Test-driven until the trim application (#1878 follow-up) consumes it.
pub(super) struct PowerTrim {
    /// `thermal_trim[2]` (s8, magnitude GENMASK(5, 0), BIT(6) set =
    /// positive; 0xFF on a path means unprogrammed: that path is 0
    /// and parsing stops there).
    pub(super) thermal: [i8; 2],
    /// `pg_thermal_trim`: false once the first unprogrammed path is hit.
    pub(super) pg_thermal: bool,
    /// `pa_bias_trim[2]` raw bytes (2G nibble low, 5G nibble high).
    pub(super) pa_bias: [u8; 2],
    /// `pad_bias_trim[2]` raw bytes (same nibble split).
    pub(super) pad_bias: [u8; 2],
    /// `pg_pa_bias_trim`: `phycap[0] != 0xFF`. Linux gates BOTH the
    /// PA-bias and the pad-bias application on this one flag.
    pub(super) pg_pa_pad: bool,
}

// The trim window (offsets 0x33/0x34/0x35) fits `PHYCAP_SIZE` 0x38.
const _: () = assert!(chip_8922a::PHYCAP_SIZE > 0x35);

impl BeFactory {
    /// `rtw8922a_phycap_parsing_thermal_trim` /
    /// `_pa_bias_trim` / `_pad_bias_trim` (rtw8922a.c:908..1005) over
    /// the PHY-cap window (`phycap_addr` 0x1700, offsets relative to
    /// it): thermal at {0x1706, 0x1733}, PA bias at {0x1707, 0x1734},
    /// pad bias at {0x1708, 0x1735}, PA/pad programmed flag at
    /// phycap[0] (0x1700). Parse only — no RF writes.
    #[allow(dead_code)] // Test-driven until the trim application (#1878 follow-up) consumes it.
    pub(super) fn power_trim(&self) -> PowerTrim {
        const THERMAL: [usize; 2] = [6, 0x33];
        const PA_BIAS: [usize; 2] = [7, 0x34];
        const PAD_BIAS: [usize; 2] = [8, 0x35];
        let mut thermal = [0i8; 2];
        let mut pg_thermal = true;
        for (i, &off) in THERMAL.iter().enumerate() {
            let raw = self.phycap[off];
            if raw == 0xFF {
                pg_thermal = false;
                break;
            }
            let mag = (raw & 0x3f) as i8;
            thermal[i] = if raw & 0x40 != 0 { mag } else { -mag };
        }
        PowerTrim {
            thermal,
            pg_thermal,
            pa_bias: [self.phycap[PA_BIAS[0]], self.phycap[PA_BIAS[1]]],
            pad_bias: [self.phycap[PAD_BIAS[0]], self.phycap[PAD_BIAS[1]]],
            pg_pa_pad: self.phycap[0] != 0xFF,
        }
    }
}

/// Read the full 8922A factory identity over PCIe BAR2: the BE
/// analog of `efuse::read_mac` for the probe path. `cut` is the
/// chip-version field from `R_AX_SYS_CFG1` (Linux reads `cv` from
/// that register for every generation, `core.c:7134`); CAV is cut 0
/// (`core.h:201`, `enum rtw89_cv`: `CHIP_CAV` first), which selects
/// the ISO-sequence skip in the BE power-cut protocol.
///
/// # Safety
/// Caller owns powered BAR2 exclusively, including SYS/PMC/EFUSE
/// controls.
pub(super) unsafe fn read_factory(
    mmio: &narf_bus::MmioRegion,
    cut: u8,
) -> Result<BeFactory, BeEfuseError> {
    // SAFETY: caller's owned-BAR2 contract.
    let mut io = super::efuse::Mmio(mmio);
    BeFactory::read(&mut io, cut == 0, Hci::Pcie)
}

impl BeEfuseError {
    /// Map onto the AX `EfuseError` the probe path reports
    /// (`ProbeError::Efuse`): busy/timeout conditions are timeouts,
    /// malformed-map conditions are malformed maps. `NotPresent`
    /// never escapes `BeFactory::read` (cut/thermal-K absences
    /// become `None` there).
    pub(super) const fn as_efuse_error(self) -> super::efuse::EfuseError {
        match self {
            BeEfuseError::Busy | BeEfuseError::PowerStateTimeout => {
                super::efuse::EfuseError::Timeout
            }
            _ => super::efuse::EfuseError::MalformedMap,
        }
    }
}
