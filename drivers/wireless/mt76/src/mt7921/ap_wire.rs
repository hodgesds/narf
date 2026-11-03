//! Source-backed AP BSS, peer WTBL and embedded beacon TXD requests.
//! Linux mt7921/mcu.c mt7921_mcu_uni_add_beacon_offload and
//! mt76_connac_mac.c mt76_connac2_mac_write_txwi, BSS0/OMAC0/global WCID0.

use super::{association::LegacyRate, firmware_transport::Error, vif_slots::Vif};
use alloc::{vec, vec::Vec};

pub(super) const CE_BSS_CONNECTED: u8 = 0x16;
pub(super) const CE_BSS_ABORT: u8 = 0x17;
pub(super) const FIRST_PEER: u8 = 1;
pub(super) const LAST_PEER: u8 = 13;
pub(super) const BMC: u8 = 19;
pub(super) const MAX_AID: u16 = 20; // Linux mt7921.h / mac_sta_add admission

pub(super) fn rlm(channel: u8, five_ghz: bool, receive_chains: u8) -> [u8; 20] {
    let mut body = [0; 20];
    body[4..6].copy_from_slice(&2u16.to_le_bytes());
    body[6..8].copy_from_slice(&16u16.to_le_bytes());
    body[8] = channel;
    body[9] = channel;
    body[12] = 1; // retained legacy profile uses one TX chain
    body[13] = receive_chains;
    body[14] = 1; // short_st, mt76_connac_mcu_uni_set_chctx
    body[17] = u8::from(five_ghz);
    body
}

/// The AP's actual broadcast WCID. Firmware-offloaded connac2 STA update
/// with sta=None sends only WTBL, not a fabricated peer/AID/basic record.
pub(super) fn group() -> Vec<u8> {
    group_on(Vif::HOME)
}
/// `group` for `vif`'s BMC WCID (19 - idx) on its BSS.
pub(super) fn group_on(vif: Vif) -> Vec<u8> {
    let mut out = vec![0; 8];
    out[0] = vif.index();
    out[1] = vif.bmc();
    out[2] = 1;
    out[4] = 1;
    out[5] = 0xe;
    let wtbl = tlv(&mut out, 13, 12);
    out[wtbl + 4..wtbl + 8].copy_from_slice(&[vif.bmc(), 1, 3, 0]);
    let generic = tlv(&mut out, 0, 20);
    out[generic + 4..generic + 10].fill(0xff);
    out[generic + 10] = 0xe;
    let rx = tlv(&mut out, 1, 12);
    out[rx + 5..rx + 8].fill(1);
    let trans = tlv(&mut out, 6, 8);
    out[trans + 5..trans + 7].copy_from_slice(&[1, 1]);
    out[wtbl + 2..wtbl + 4].copy_from_slice(&52u16.to_le_bytes());
    out
}

/// Linux mt76_connac_mcu_uni_add_bss: AP active follows enable, while
/// station mode deliberately keeps an active disconnected BSS record.
pub(super) fn bss(
    own: [u8; 6],
    beacon_interval: u16,
    dtim_period: u8,
    five_ghz: bool,
    enable: bool,
    qos: bool,
) -> Result<[u8; 44], Error> {
    bss_on(
        Vif::HOME,
        own,
        beacon_interval,
        dtim_period,
        five_ghz,
        enable,
        qos,
    )
}
/// `bss` for `vif`: header `bss_idx`, `omac_idx`, `hw_bss_idx`, `wmm_idx`
/// and the vif's BMC WCID (Linux `mt76_connac_mcu_uni_add_bss`).
pub(super) fn bss_on(
    vif: Vif,
    own: [u8; 6],
    beacon_interval: u16,
    dtim_period: u8,
    five_ghz: bool,
    enable: bool,
    qos: bool,
) -> Result<[u8; 44], Error> {
    if own == [0; 6] || own[0] & 1 != 0 || beacon_interval == 0 || dtim_period == 0 {
        return Err(Error::Bounds);
    }
    let mut out = [0; 44];
    out[0] = vif.index();
    out[6..8].copy_from_slice(&32u16.to_le_bytes());
    out[8] = u8::from(enable);
    out[9] = vif.omac();
    out[10] = vif.index();
    out[12..16].copy_from_slice(&0x10002u32.to_le_bytes()); // INFRA_AP
    out[16] = u8::from(!enable);
    out[17] = vif.wmm();
    out[18..24].copy_from_slice(&own);
    out[24..26].copy_from_slice(&u16::from(vif.bmc()).to_le_bytes());
    out[26..28].copy_from_slice(&beacon_interval.to_le_bytes());
    out[28] = dtim_period;
    out[29] = if five_ghz { 1 } else { 6 };
    out[30..32].copy_from_slice(&u16::from(vif.bmc()).to_le_bytes());
    out[32..34].copy_from_slice(&(if five_ghz { 8u16 } else { 3 }).to_le_bytes());
    out[36..38].copy_from_slice(&15u16.to_le_bytes());
    out[38..40].copy_from_slice(&8u16.to_le_bytes());
    out[40] = u8::from(qos);
    Ok(out)
}

/// Actual AP peer WTBL/STA records; the caller must own this WCID's
/// generation and the authenticated association before authorization.
pub(super) struct PeerRecord {
    pub mac: [u8; 6],
    pub wcid: u8,
    pub aid: u16,
    pub newly: bool,
    pub qos: bool,
    pub five_ghz: bool,
    pub rates: u16,
    pub basic_rates: u16,
}
pub(super) fn peer(record: PeerRecord) -> Result<Vec<u8>, Error> {
    peer_on(Vif::HOME, record)
}
/// `peer` on `vif`'s BSS: `muar_idx = omac_idx` in both the STA_REC header
/// and WTBL generic (`mt76_connac_mcu_alloc_sta_req`,
/// `mt76_connac_mcu_wtbl_generic_tlv`).
pub(super) fn peer_on(vif: Vif, record: PeerRecord) -> Result<Vec<u8>, Error> {
    let PeerRecord {
        mac,
        wcid,
        aid,
        newly,
        qos,
        five_ghz,
        rates,
        basic_rates,
    } = record;
    if mac == [0; 6]
        || mac[0] & 1 != 0
        || !(FIRST_PEER..=LAST_PEER).contains(&wcid)
        || !(1..=MAX_AID).contains(&aid)
        || rates == 0
        || rates & !0x0fff != 0
        || basic_rates == 0
        || basic_rates & !rates != 0
        || five_ghz && rates & 15 != 0
    {
        return Err(Error::Bounds);
    }
    let mut out = vec![0; 8];
    out[0] = vif.index();
    out[1] = wcid;
    out[2] = 5;
    out[4] = 1;
    out[5] = vif.omac();
    let basic = tlv(&mut out, 0, 20);
    out[basic + 4..basic + 8].copy_from_slice(&0x10001u32.to_le_bytes()); // peer INFRA_STA
    out[basic + 8] = 2; // enabled native peer; host controlled port is separate
    out[basic + 9] = u8::from(qos);
    out[basic + 10..basic + 12].copy_from_slice(&aid.to_le_bytes());
    out[basic + 12..basic + 18].copy_from_slice(&mac);
    out[basic + 18..basic + 20].copy_from_slice(&(1u16 | u16::from(newly) << 1).to_le_bytes()); // EXTRA_VER | NEW
    let phy = tlv(&mut out, 0x15, 12);
    let basic_bitmap = if five_ghz {
        basic_rates >> 4
    } else {
        basic_rates
    };
    out[phy + 4..phy + 6].copy_from_slice(&basic_bitmap.to_le_bytes());
    out[phy + 6] = if five_ghz { 8 } else { 3 };
    let ra = tlv(&mut out, 1, 16);
    out[ra + 4..ra + 6].copy_from_slice(&((rates & 15) | ((rates >> 4) << 6)).to_le_bytes());
    let state = tlv(&mut out, 7, 12);
    out[state + 8] = 2; // actual associated MLME, distinct from controlled port
    let wtbl = tlv(&mut out, 13, 12);
    out[wtbl + 4..wtbl + 8].copy_from_slice(&[wcid, 1, 3, 0]);
    let generic = tlv(&mut out, 0, 20);
    out[generic + 4..generic + 10].copy_from_slice(&mac);
    out[generic + 10] = vif.omac();
    out[generic + 13] = u8::from(qos);
    out[generic + 16..generic + 18].copy_from_slice(&aid.to_le_bytes());
    let rx = tlv(&mut out, 1, 12);
    out[rx + 6..rx + 8].fill(1); // AP RCA1=0, RCA2=1, RV=1
    let trans = tlv(&mut out, 6, 8);
    out[trans + 5..trans + 7].copy_from_slice(&[1, 1]); // from-DS, no RX translation
    let length = (out.len() - wtbl) as u16;
    out[wtbl + 2..wtbl + 4].copy_from_slice(&length.to_le_bytes());
    Ok(out)
}

fn tlv(out: &mut Vec<u8>, tag: u16, length: u16) -> usize {
    let start = out.len();
    out.resize(start + usize::from(length), 0);
    out[start..start + 2].copy_from_slice(&tag.to_le_bytes());
    out[start + 2..start + 4].copy_from_slice(&length.to_le_bytes());
    start
}

pub(super) fn bss_connected(beacon_interval: u16, dtim_period: u8) -> [u8; 12] {
    let mut body = [0; 12];
    body[1] = dtim_period;
    // AP AID is zero; per-peer AIDs belong to the separate WCID owner.
    body[4..6].copy_from_slice(&beacon_interval.to_le_bytes());
    body
}

/// One exact firmware-owned beacon template, including its own native TXD.
/// Unlike CT packet submissions, this embeds no TXP or host DMA token.
/// TIM/CSA offsets must name validated IEs in the actual retained template.
pub(super) fn beacon(
    frame: &[u8],
    tim_offset: usize,
    csa_counter_offset: Option<usize>,
    rate: LegacyRate,
) -> Result<[u8; 530], Error> {
    if frame.len() < 36
        || frame.len() > 480
        || frame[..2] != [0x80, 0]
        || frame[4..10] != [0xff; 6]
        || frame[22] & 15 != 0
        || tim_offset < 36
        || frame.get(tim_offset) != Some(&5)
    {
        return Err(Error::Bounds);
    }
    let tim_length = *frame.get(tim_offset + 1).ok_or(Error::Bounds)? as usize;
    if tim_length < 4 || tim_offset + 2 + tim_length > frame.len() {
        return Err(Error::Bounds);
    }
    let csa = match csa_counter_offset {
        Some(counter)
            if counter >= 40
                && frame.get(counter - 4) == Some(&37)
                && frame.get(counter - 3) == Some(&3)
                && counter < frame.len() =>
        {
            32 + counter - 4
        }
        Some(_) => return Err(Error::Bounds),
        None => 0,
    };
    let packet_length = 32 + frame.len();
    let mut body = [0; 530];
    body[4..6].copy_from_slice(&7u16.to_le_bytes());
    body[6..8].copy_from_slice(&526u16.to_le_bytes());
    body[8..10].copy_from_slice(&((32 + tim_offset) as u16).to_le_bytes());
    body[10..12].copy_from_slice(&(csa as u16).to_le_bytes());
    body[14] = 1; // enable; BSS stop, not this TLV, disables the beacon
    body[16..18].copy_from_slice(&(packet_length as u16).to_le_bytes());
    let words = [
        packet_length as u32 | (3 << 23) | (0x12 << 25),
        (1 << 31) | (2 << 16) | (12 << 11),
        (1 << 31) | (1 << 13) | (1 << 10) | 8,
        (1 << 28) | (31 << 11) | 1,
        0,
        0,
        4 | (u32::from(rate.hardware()) << 16),
        8 << 16,
    ];
    for (wire, word) in body[18..50].chunks_exact_mut(4).zip(words) {
        wire.copy_from_slice(&word.to_le_bytes());
    }
    body[50..50 + frame.len()].copy_from_slice(frame);
    Ok(body)
}

/// Linux sta_cmd(enable=false): BASIC disconnect plus empty WTBL reset.
pub(super) fn delete_peer(mac: [u8; 6], wcid: u8, aid: u16) -> Result<Vec<u8>, Error> {
    delete_peer_on(Vif::HOME, mac, wcid, aid)
}
pub(super) fn delete_peer_on(vif: Vif, mac: [u8; 6], wcid: u8, aid: u16) -> Result<Vec<u8>, Error> {
    if mac == [0; 6]
        || mac[0] & 1 != 0
        || !(FIRST_PEER..=LAST_PEER).contains(&wcid)
        || !(1..=MAX_AID).contains(&aid)
    {
        return Err(Error::Bounds);
    }
    let mut out = vec![0; 8];
    out[0] = vif.index();
    out[1] = wcid;
    out[2] = 2;
    out[4] = 1;
    out[5] = vif.omac();
    let basic = tlv(&mut out, 0, 20);
    out[basic + 4..basic + 8].copy_from_slice(&0x10001u32.to_le_bytes());
    out[basic + 10..basic + 12].copy_from_slice(&aid.to_le_bytes());
    out[basic + 12..basic + 18].copy_from_slice(&mac);
    out[basic + 18..basic + 20].copy_from_slice(&1u16.to_le_bytes());
    let wtbl = tlv(&mut out, 13, 12);
    out[wtbl + 4] = wcid;
    out[wtbl + 5] = 1;
    Ok(out)
}
