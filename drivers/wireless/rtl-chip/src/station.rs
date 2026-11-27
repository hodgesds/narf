// SPDX-License-Identifier: GPL-2.0-or-later
//! Transport-agnostic rtw88 station port/MAC/DCF programming
//! (`mac80211.c::rtw_vif_port_config` / `rtw_ops_bss_info_changed` and the
//! adjacent `fw.c` register setup), generic over [`RegIo`]. The builtin
//! driver and the loadable `.ko` apply the identical register stream.
//!
//! Only the register stream lives here: own MAC (`REG_MACID`), peer BSSID
//! (`REG_BSSID`), the media-status (`REG_MS`) and AID (`REG_AID`) fields,
//! the beacon-control byte (`REG_BCN_CTRL`), the non-QoS DCF/WMM defaults
//! (`DCF_REGS` + slot) and the port-idle poll (`REG_TCR`). The firmware
//! mailbox words (`station_control::send`), the admission gate
//! (`station_allowed`, `Admission`) and the SME (assoc/keys/RA,
//! `station.rs`) stay in the consuming crate: `RegIo` cannot express them,
//! and the mailbox words are H2C firmware commands, not register writes.
//! The caller interleaves the H2C sends between the register pieces
//! (`prepare_initial` → sends → port-idle poll; `commit_peer` address →
//! sends → `commit_peer_tail`).
//!
//! Register layout: Linux rtw88 `reg.h` (`REG_MACID`, `REG_BSSID`, `REG_MS`,
//! `REG_BCN_CTRL`, `REG_TCR`); the AID field at `0x6a8` as written by
//! rtw88 (low 11 bits) and rtl8xxxu (`0xc000 | aid`); DCF defaults: Linux
//! `net/mac80211/wme.c` non-QoS defaults via rtw88
//! `mac80211.c::rtw_aifsn_to_aifs` (frozen in
//! `rtw88/REFERENCE_FIXTURES.md`, `station_control/*golden.rs`).
use crate::{ChipError as Error, RegIo as Io};

/// Own MAC address (`REG_MACID`, `0x610..0x615`); port 0.
pub const REG_MACID: u16 = 0x610;
/// Peer BSSID (`REG_BSSID`, `0x618..0x61d`).
pub const REG_BSSID: u16 = 0x618;
/// Media status (`REG_MS`); bits 17:16 carry the network type.
pub const REG_MS: u16 = 0x100;
/// `REG_MS` network-type field (bits 17:16).
pub const MS_NETTYPE_MASK: u32 = 0x30000;
/// `REG_MS` network type: no link (disconnected / initial).
pub const MS_NETTYPE_NO_LINK: u32 = 0;
/// `REG_MS` network type: associated infrastructure station.
pub const MS_NETTYPE_ASSOC: u32 = 2;
/// Association ID register; the low 11 bits carry the AID (1..=2007).
/// rtl8xxxu programs the same register as `0xc000 | aid`; rtw88 writes
/// only the AID field and leaves the high bits alone.
pub const REG_AID: u16 = 0x6a8;
/// `REG_AID` AID field (bits 10:0).
pub const AID_MASK: u32 = 0x7ff;
/// Beacon control (`REG_BCN_CTRL`).
pub const REG_BCN_CTRL: u16 = 0x550;
/// `REG_BCN_CTRL` beacon-function enable (bit 3; `mac::values`
/// `BIT_EN_BCN_FUNCTION`), cleared on station setup.
pub const BCN_CTRL_BEACON_EN: u8 = 1 << 3;
/// `REG_BCN_CTRL` bit 4, set on station setup: with the beacon function
/// clear, no AP/autobeacon or TSF-update service in this one-shot host
/// station.
pub const BCN_CTRL_STA_MODE: u8 = 1 << 4;
/// TX configuration (`REG_TCR`); bit 7 is polled clear after the initial
/// H2C sends.
pub const REG_TCR: u16 = 0x604;
/// `REG_TCR` port-idle bit (bit 7): clear once the port is idle.
pub const TCR_PORT_IDLE_BIT: u32 = 1 << 7;
/// DCF/EDCA parameter registers, one per access category (VO/VI/BE/BK).
pub const DCF_REGS: [u16; 4] = [0x500, 0x504, 0x508, 0x50c];
/// DCF field mask (TXOP/CWmax/CWmin/AIFS) written and read back per register.
pub const DCF_MASK: u32 = 0x07ff_ffff;
/// Slot-time register.
pub const SLOT_REG: u16 = 0x51b;

/// A usable station MAC: unicast and non-zero.
pub fn mac_valid(mac: [u8; 6]) -> bool {
    mac[0] & 1 == 0 && mac != [0; 6]
}

/// Write a 6-byte address starting at `base` (own MAC at [`REG_MACID`],
/// peer BSSID at [`REG_BSSID`], zeroes to clear).
pub async fn write_address(io: &mut impl Io, base: u16, mac: [u8; 6]) -> Result<(), Error> {
    for (i, byte) in mac.into_iter().enumerate() {
        io.write8(base + i as u16, byte).await?;
    }
    Ok(())
}

/// Read-modify-write a 32-bit field: `value` is the unshifted field value,
/// shifted into `bits` (mirrors `rtw88::radio::mask`). `bits == 0` or a
/// `value` that does not fit in `bits` is [`Error::Unsupported`]; an
/// all-ones read is [`Error::Gone`].
pub async fn mask(io: &mut impl Io, reg: u16, bits: u32, value: u32) -> Result<(), Error> {
    if bits == 0
        || value
            .checked_shl(bits.trailing_zeros())
            .is_none_or(|v| v & !bits != 0)
    {
        return Err(Error::Unsupported);
    }
    let old = io.read32(reg).await?;
    if old == u32::MAX {
        return Err(Error::Gone);
    }
    io.write32(reg, old & !bits | value << bits.trailing_zeros())
        .await
}

/// Non-QoS DCF parameters (`mac80211::ieee80211_set_wmm_default` with
/// `enable_qos=false`): AIFSN 2, TXOP 0, CWmax 1023 (2^10 - 1), CWmin 31
/// (2^5 - 1); AIFS = AIFSN * slot + SIFS, SIFS 16 on 5 GHz and 10
/// otherwise; the short slot is forced on 5 GHz (`mac80211` forces it on
/// ERP/5 GHz; `rtw_aifsn_to_aifs`). Returns the masked EDCA value and the
/// slot time.
pub fn dcf_params(short_slot: bool, band5: bool) -> (u32, u8) {
    let short = short_slot || band5;
    let slot = if short { 9 } else { 20 };
    let sifs = if band5 { 16 } else { 10 };
    let value = (10 << 12) | (5 << 8) | (2 * u32::from(slot) + sifs);
    (value, slot)
}

/// Program the non-QoS DCF/WMM defaults on all four EDCA registers plus
/// the slot time, verifying each write by readback ([`Error::Prerequisite`]
/// on mismatch, as the builtin `configure_dcf` does).
pub async fn configure_dcf(io: &mut impl Io, short_slot: bool, band5: bool) -> Result<(), Error> {
    let (value, slot) = dcf_params(short_slot, band5);
    for register in DCF_REGS {
        mask(io, register, DCF_MASK, value).await?;
        if io.read32(register).await? & DCF_MASK != value {
            return Err(Error::Prerequisite);
        }
    }
    io.write8(SLOT_REG, slot).await?;
    if io.read8(SLOT_REG).await? != slot {
        return Err(Error::Prerequisite);
    }
    Ok(())
}

/// `rtw_vif_port_config(PORT_SET_MAC_ADDR)`: port0 `REG_MACID`.
pub async fn port_address(io: &mut impl Io, mac: [u8; 6]) -> Result<(), Error> {
    if !mac_valid(mac) {
        return Err(Error::Prerequisite);
    }
    write_address(io, REG_MACID, mac).await
}

/// Register prefix of `prepare_initial`: own MAC, cleared peer BSSID,
/// `REG_MS`/`REG_AID` cleared, beacon function off, non-QoS DCF defaults.
/// The caller checks the station gate and own-MAC ownership first and
/// sends the H2C words after; see [`port_idle`] for the trailing poll.
pub async fn prepare_initial(io: &mut impl Io, own: [u8; 6]) -> Result<(), Error> {
    if !mac_valid(own) {
        return Err(Error::Prerequisite);
    }
    write_address(io, REG_MACID, own).await?;
    write_address(io, REG_BSSID, [0; 6]).await?;
    mask(io, REG_MS, MS_NETTYPE_MASK, MS_NETTYPE_NO_LINK).await?;
    mask(io, REG_AID, AID_MASK, 0).await?;
    // No AP/autobeacon or TSF-update service in this one-shot host station.
    let beacon = io.read8(REG_BCN_CTRL).await?;
    io.write8(
        REG_BCN_CTRL,
        beacon & !BCN_CTRL_BEACON_EN | BCN_CTRL_STA_MODE,
    )
    .await?;
    configure_dcf(io, false, false).await
}

/// Register part of `prepare_peer`: peer BSSID, `REG_MS`/`REG_AID`
/// cleared. The caller validates the peer and sends the RA H2C word after.
pub async fn prepare_peer(io: &mut impl Io, peer: [u8; 6]) -> Result<(), Error> {
    if !mac_valid(peer) {
        return Err(Error::Prerequisite);
    }
    write_address(io, REG_BSSID, peer).await?;
    mask(io, REG_MS, MS_NETTYPE_MASK, MS_NETTYPE_NO_LINK).await?;
    mask(io, REG_AID, AID_MASK, 0).await
}

/// Register tail of `commit_peer`, after the peer BSSID write and the
/// media/default-port H2C words: AID, DCF for the negotiated slot/band,
/// `REG_MS` to associated.
pub async fn commit_peer_tail(
    io: &mut impl Io,
    aid: u16,
    short_slot: bool,
    band5: bool,
) -> Result<(), Error> {
    if !(1..=2007).contains(&aid) {
        return Err(Error::Unsupported);
    }
    mask(io, REG_AID, AID_MASK, u32::from(aid)).await?;
    configure_dcf(io, short_slot, band5).await?;
    mask(io, REG_MS, MS_NETTYPE_MASK, MS_NETTYPE_ASSOC).await
}

/// Register part of `disconnect`: `REG_MS`/`REG_AID` cleared, peer BSSID
/// zeroed. The caller sends the media-off H2C word after.
pub async fn disconnect(io: &mut impl Io) -> Result<(), Error> {
    mask(io, REG_MS, MS_NETTYPE_MASK, MS_NETTYPE_NO_LINK).await?;
    mask(io, REG_AID, AID_MASK, 0).await?;
    write_address(io, REG_BSSID, [0; 6]).await
}

/// Single `REG_TCR` port-idle check: `true` once the port-idle bit is
/// clear. An all-ones read is [`Error::Gone`]. The caller polls this (6
/// attempts, 20 ms apart) with its own admission checks.
pub async fn port_idle(io: &mut impl Io) -> Result<bool, Error> {
    let value = io.read32(REG_TCR).await?;
    if value == u32::MAX {
        return Err(Error::Gone);
    }
    Ok(value & TCR_PORT_IDLE_BIT == 0)
}
