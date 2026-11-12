// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B ordinary PCI TXWD, WD-info, WP and address-info records.
//! Linux rtw89/core.c descriptor builders and pci.c::rtw89_pci_txwd_submit.
//! Formatting supplies no RF, peer, key, controlled-port or DMA authority.
use super::{dma, mac::ChipId, tx_transport, txrx::TxwdInfo};
use alloc::vec::Vec;

pub(super) const HEADER: usize = 24 + 24 + 8 + 8;
/// RTL8852C `rtw89_txwd_body_v1` (32) + `rtw89_txwd_info` (24) + WP (8) +
/// at most two `rtw89_pci_tx_addr_info_32_v1` (6 each) for a [`MAX_MPDU`]
/// body (`TXADDR_INFO_LENTHG_V1_MAX` 2044).
pub(super) const C_HEADER_MAX: usize = 32 + 24 + 8 + 2 * 6;
pub(super) const MAX_MPDU: usize = 2304;
/// New TX fragments: maximum2346 plaintext+FCS, then16 CCMP overhead.
pub(super) const FRAGMENT_MAX_MPDU: usize = 2346 - 4 + 16;
pub(super) const DMA_MASK: u64 = 0xf_ffff_ffff;
pub(super) const DEPTH: u16 = 256;
pub(super) const IDENTITIES: u16 = 512;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Queue {
    /// Best effort, ACH0 / `RTW89_TX_QSEL_BE_0`.
    Data,
    /// Band0 management, CH8 / `RTW89_TX_QSEL_B0_MGMT`.
    Management,
    /// Background, ACH1 / `RTW89_TX_QSEL_BK_0`.
    Background,
    /// Video, ACH2 / `RTW89_TX_QSEL_VI_0`.
    Video,
    /// Voice, ACH3 / `RTW89_TX_QSEL_VO_0`.
    Voice,
    /// Band0 high queue, CH9 / `RTW89_TX_QSEL_B0_HI`: AP frames sent after
    /// the DTIM beacon (`IEEE80211_TX_CTL_SEND_AFTER_DTIM`). AP role only.
    High,
}
impl Queue {
    /// `rtw89_core_get_qsel` + `rtw89_core_get_ch_dma` for a QoS TID.
    pub(super) fn for_tid(tid: u8) -> Self {
        match super::qos::Ac::of(tid) {
            super::qos::Ac::BestEffort => Self::Data,
            super::qos::Ac::Background => Self::Background,
            super::qos::Ac::Video => Self::Video,
            super::qos::Ac::Voice => Self::Voice,
        }
    }
    pub(super) fn channel(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Background => 1,
            Self::Video => 2,
            Self::Voice => 3,
            Self::Management => 8,
            Self::High => 9,
        }
    }
    pub(super) fn qsel(self) -> u8 {
        match self {
            Self::Data => 0,
            Self::Background => 1,
            Self::Video => 2,
            Self::Voice => 3,
            Self::Management => 0x12,
            Self::High => 0x11,
        }
    }
    pub(super) fn regs(self) -> dma::TxRingRegs {
        self.regs_for(ChipId::Rtl8852B)
    }
    /// `chip->pci_info.dma_addr_set` ring registers: RTL8852C takes
    /// `rtw89_pci_ch_dma_addr_set_v1` (same ACH0..CH9 NUM/IDX, `_V1`
    /// DESA/BDRAM).
    pub(super) fn regs_for(self, chip: ChipId) -> dma::TxRingRegs {
        dma::addr_set_for_chip(chip).tx[self.channel() as usize]
    }
    /// `R_AX_PCIE_DMA_STOP1` bit for this channel (`B_AX_STOP_ACHn`/`CH8`/`CH9`).
    pub(super) fn stop_bit(self) -> u32 {
        1 << (8 + u32::from(self.channel()))
    }
    /// Ordinary rings: BE/MGMT always, BK/VI/VO only for the separately
    /// qualified all-AC QoS program.
    pub(super) fn ordinary(qos_all: bool) -> &'static [Self] {
        if qos_all {
            &[
                Self::Data,
                Self::Management,
                Self::Background,
                Self::Video,
                Self::Voice,
            ]
        } else {
            &[Self::Data, Self::Management]
        }
    }
}
/// `rate` flag for firmware rate adaptation (Linux data frames: USE_RATE=0,
/// DISDATAFB=0); the low bits carry `DATA_RTY_LOWEST_RATE`.
pub(super) const FIRMWARE_RA: u8 = 0x80;
/// With `FIRMWARE_RA`: `RTW89_TXWD_INFO0_DATA_ER` (Linux `desc_info->er_cap`
/// for an HE peer whose HE operation leaves ER SU enabled).
pub(super) const DATA_ER: u8 = 0x40;
/// `RTW89_HW_RATE_OFDM6`: the 5GHz management/fixed-rate floor (core.c
/// `rtw89_core_get_mgmt_rate`); `RTW89_HW_RATE_CCK1` is 0.
pub(super) const OFDM6: u8 = 4;
/// `B_AX_STOP_WPDMA`.
pub(super) const STOP_WPDMA: u32 = 1 << 19;
/// Every ordinary TX stop bit this station can open (ACH0..3, CH8, WPDMA).
pub(super) const STOP_ALL: u32 = 0xf00 | 1 << 16 | STOP_WPDMA;
/// Wildcard-addressed probe request (`fc 0x40`, DA/BSSID broadcast) from
/// `own`. It has no peer; the packet owner admits it without a peer token.
pub(super) fn probe_request(frame: &[u8], own: [u8; 6]) -> bool {
    frame.len() >= 24
        && frame[0] == 0x40
        && frame[1] == 0
        && frame[4..10] == [0xff; 6]
        && frame[10..16] == own
        && frame[16..22] == [0xff; 6]
}
/// QoS TID of a QoS DATA header, if any.
pub(super) fn qos_tid(frame: &[u8]) -> Option<u8> {
    (frame.first() == Some(&0x88)).then(|| frame.get(24).map(|b| b & 0x0f))?
}
/// TX A-MPDU fields of one QoS data MPDU on an operational originator
/// session (`rtw89_core_tx_update_ampdu_info`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Agg {
    /// `RTW89_TXWD_INFO1_MAX_AGGNUM`: session `agg_num` - 1.
    pub(super) num: u8,
    /// `RTW89_TXWD_INFO2_AMPDU_DENSITY`: peer HT minimum MPDU start spacing.
    pub(super) density: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Frame,
    Address,
    Metadata,
}
fn unicast(address: &[u8]) -> bool {
    address.len() == 6 && address != [0; 6] && address[0] & 1 == 0
}
pub(super) fn classify(frame: &[u8], own: [u8; 6]) -> Result<Queue, Error> {
    classify_with(frame, own, None)
}
pub(super) fn amsdu(frame: &[u8]) -> bool {
    frame.first() == Some(&0x88) && frame.get(24).is_some_and(|q| q & 0x80 != 0)
}
pub(super) fn classify_with(
    frame: &[u8],
    own: [u8; 6],
    limit: Option<usize>,
) -> Result<Queue, Error> {
    classify_profile(frame, own, limit, false)
}
/// Explicit source-qualified fragment format; original MPDU bytes and fragment
/// fields remain unchanged. This pure formatter grants no native admission.
pub(super) fn classify_fragment(frame: &[u8], own: [u8; 6]) -> Result<Queue, Error> {
    classify_profile(frame, own, None, true)
}
fn classify_profile(
    frame: &[u8],
    own: [u8; 6],
    limit: Option<usize>,
    fragments: bool,
) -> Result<Queue, Error> {
    let aggregate = amsdu(frame);
    if limit.is_some_and(|body| body == 0 || body > super::tx_amsdu::MAX_BODY) {
        return Err(Error::Frame);
    }
    let maximum = if aggregate {
        limit.ok_or(Error::Frame)?
            + 26
            + if frame.get(1).is_some_and(|fc| fc & 0x40 != 0) {
                16
            } else {
                0
            }
    } else if fragments {
        FRAGMENT_MAX_MPDU
    } else {
        MAX_MPDU
    };
    let minimum = if aggregate {
        26 + 46 + if frame[1] & 0x40 != 0 { 16 } else { 0 }
    } else {
        24
    };
    if !(minimum..=maximum).contains(&frame.len())
        || aggregate && (frame[1] & 0x80 != 0 || frame[16..22] != frame[4..10])
        || !unicast(&own)
        || frame[10..16] != own
        || frame[0] & 3 != 0
        || frame[1] & (16 | 32) != 0
        || !fragments && frame[1] & 4 != 0
        || fragments
            && (aggregate || frame[1] & 0x80 != 0 || frame[1] & 4 == 0 && frame[22] & 15 == 0)
        || fragments && frame[1] & 4 != 0 && frame[22] & 15 == 15
        || frame[1] & 128 != 0 && frame[0] != 0x88
        || !fragments && frame[22] & 15 != 0
    {
        return Err(Error::Frame);
    }
    match frame[0] {
        // One non-QoS three-address station. Optional modes are not admitted.
        // Association, authentication, disassociation, deauthentication and
        // (Block Ack) action frames.
        0x00 | 0xb0 if frame[1] & (3 | 64) == 0 => Ok(Queue::Management),
        // Robust management (disassociation, deauthentication, Action)
        // may carry host CCMP under PMF: RTL8852B has no
        // `hw_mgmt_tx_encrypt`, so the TXWD stays without SEC fields.
        0xa0 | 0xc0 | 0xd0 if frame[1] & 3 == 0 => Ok(Queue::Management),

        // Broadcast probe request of an active scan (see probe_request).
        0x40 if probe_request(frame, own) => Ok(Queue::Management),
        0x08 if frame[1] & 3 == 1 && unicast(&frame[4..10]) => Ok(Queue::Data),
        // QoS DATA: TID0..7, normal ack policy; HE +HTC carries EOSP.
        0x88 if frame[1] & 3 == 1
            && unicast(&frame[4..10])
            && frame.get(24).is_some_and(|b| {
                b & if aggregate { 0x68 } else { 0xe8 } == 0
                    && (b & 0x10 != 0) == (frame[1] & 128 != 0)
            })
            && frame.get(25) == Some(&0)
            && (frame[1] & 128 == 0
                || frame.get(26..30).is_some_and(|control| control[0] & 3 == 3)) =>
        {
            Ok(Queue::for_tid(frame[24]))
        }
        _ => Err(Error::Frame),
    }
}
pub(super) fn extent(address: u64, length: usize) -> Result<(), Error> {
    if length == 0
        || address == 0
        || address & 3 != 0
        || address
            .checked_add(length as u64 - 1)
            .is_none_or(|last| last > DMA_MASK)
    {
        return Err(Error::Address);
    }
    Ok(())
}
fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
/// Fixed CCK1,20MHz, port0, no hardware encryption or aggregation. All
/// reachable hardware RTS/CTS/ACK response rates remain the RF gate's duty.
pub(super) fn transmit(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    sequence: u16,
    address: u64,
    report: bool,
) -> Result<(Vec<u8>, Queue), Error> {
    transmit_rate(frame, own, mac_id, sequence, address, report, 0)
}
pub(super) fn transmit_rate(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    sequence: u16,
    address: u64,
    report: bool,
    rate: u8,
) -> Result<(Vec<u8>, Queue), Error> {
    transmit_agg(frame, own, mac_id, sequence, address, report, rate, None)
}
/// `transmit_rate` plus, for `agg`, `RTW89_TXWD_BODY3_AGG_EN`,
/// `INFO1_MAX_AGGNUM` and `INFO2_AMPDU_DENSITY` (Linux v7.2
/// `core.c::rtw89_build_txwd_body3`/`_info1`/`_info2`). Only firmware-RA
/// QoS DATA can be aggregated.
#[allow(clippy::too_many_arguments)]
pub(super) fn transmit_agg(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    sequence: u16,
    address: u64,
    report: bool,
    rate: u8,
    agg: Option<Agg>,
) -> Result<(Vec<u8>, Queue), Error> {
    transmit_profile(
        frame, own, mac_id, sequence, address, report, rate, agg, None,
    )
}
#[allow(clippy::too_many_arguments)]
pub(super) fn transmit_profile(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    sequence: u16,
    address: u64,
    report: bool,
    rate: u8,
    agg: Option<Agg>,
    limit: Option<usize>,
) -> Result<(Vec<u8>, Queue), Error> {
    transmit_profile_inner(Tx {
        chip: ChipId::Rtl8852B,
        frame,
        own,
        mac_id,
        sequence,
        address,
        report,
        rate,
        agg,
        limit,
        fragments: false,
    })
}
/// RTL8852A ordinary station TXWD (rtw8852a.c `rtw8852a_chip_info`:
/// `txwd_body_size` = sizeof(`rtw89_txwd_body`), the RTL8852B v0 layout,
/// and rtw8852ae.c `rtw89_pci_fill_txaddr_info`): management, non-QoS and
/// (under the signed RTL8852A programs) QoS data at a fixed rate or firmware
/// RA, with HE +HTC, `DATA_ER` and originator A-MPDU. A-MSDU subframes take
/// the B v0 path (mac80211 builds the aggregate; `rtw89_core_fill_txdesc`
/// writes no A-MSDU-specific TXWD field) under A's own `limit`, which never
/// exceeds `rtw8852a_chip_info.max_amsdu_limit` 3500 (rtw8852a.c:2356).
/// No fragments.
#[allow(clippy::too_many_arguments)]
pub(super) fn transmit_a(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    sequence: u16,
    address: u64,
    report: bool,
    rate: u8,
    agg: Option<Agg>,
    limit: Option<usize>,
) -> Result<(Vec<u8>, Queue), Error> {
    if limit.is_some_and(|body| body > super::tx_amsdu::MAX_BODY_A) {
        return Err(Error::Frame);
    }
    transmit_profile_inner(Tx {
        chip: ChipId::Rtl8852A,
        frame,
        own,
        mac_id,
        sequence,
        address,
        report,
        rate,
        agg,
        limit,
        fragments: false,
    })
}
/// RTL8851B ordinary station TXWD (rtw8851b.c `rtw8851b_chip_info`:
/// `txwd_body_size` = sizeof(`rtw89_txwd_body`), the RTL8852B v0 layout,
/// and rtw8851be.c `rtw89_pci_fill_txaddr_info`): management, non-QoS and
/// (under the signed RTL8851B programs) QoS data at a fixed rate or firmware
/// RA, with HE +HTC, `DATA_ER` and originator A-MPDU; no A-MSDU (no
/// RTL8851B A-MSDU program) and no fragments.
#[allow(clippy::too_many_arguments)]
pub(super) fn transmit_51(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    sequence: u16,
    address: u64,
    report: bool,
    rate: u8,
    agg: Option<Agg>,
) -> Result<(Vec<u8>, Queue), Error> {
    if amsdu(frame) {
        return Err(Error::Frame);
    }
    transmit_profile_inner(Tx {
        chip: ChipId::Rtl8851B,
        frame,
        own,
        mac_id,
        sequence,
        address,
        report,
        rate,
        agg,
        limit: None,
        fragments: false,
    })
}
/// New full native fragment emitter always fixes CCK1/no aggregation and host
/// sequence mode, including management. Original SW_SN/fragno stays on air.
pub(super) fn transmit_fragment(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    sequence: u16,
    address: u64,
    report: bool,
    rate: u8,
) -> Result<(Vec<u8>, Queue), Error> {
    // Fixed band floor only: CCK1 (2.4GHz) or OFDM6 (5GHz).
    if !matches!(rate, 0 | OFDM6) {
        return Err(Error::Metadata);
    }
    transmit_profile_inner(Tx {
        chip: ChipId::Rtl8852B,
        frame,
        own,
        mac_id,
        sequence,
        address,
        report,
        rate,
        agg: None,
        limit: None,
        fragments: true,
    })
}
struct Tx<'a> {
    chip: ChipId,
    frame: &'a [u8],
    own: [u8; 6],
    mac_id: u8,
    sequence: u16,
    address: u64,
    report: bool,
    rate: u8,
    agg: Option<Agg>,
    limit: Option<usize>,
    fragments: bool,
}
/// RTL8852C ordinary station TXWD (core.c `rtw89_core_fill_txdesc_v1`,
/// pci.c `rtw89_pci_fill_txaddr_info_v1`): management, non-QoS and (under
/// the signed C programs) QoS data at a fixed rate or firmware RA, with HE
/// +HTC, `DATA_ER` and originator A-MPDU; no A-MSDU or fragments. With
/// `sec_en` false the v1 body2 `TID_INDICATE`, body3 `AGG_EN`/`BK`, info0
/// `DATA_ER` (`rtw89_build_txwd_info0_v1`), info1 `MAX_AGGNUM`/`A_CTRL_BSR`/
/// `DATA_RTY_LOWEST_RATE` and info2 `AMPDU_DENSITY`
/// (`rtw89_build_txwd_info2_v1`) sit where v0 has them.
/// The v1 body carries `ADDR_INFO_NUM`, moves USE_RATE/DATA_RATE into body
/// dword7 and has no HW SSN fields (management keeps the host SW_SEQ).
#[allow(clippy::too_many_arguments)]
pub(super) fn transmit_c(
    frame: &[u8],
    own: [u8; 6],
    mac_id: u8,
    sequence: u16,
    address: u64,
    report: bool,
    rate: u8,
    agg: Option<Agg>,
) -> Result<(Vec<u8>, Queue), Error> {
    if amsdu(frame) {
        return Err(Error::Frame);
    }
    transmit_profile_inner(Tx {
        chip: ChipId::Rtl8852C,
        frame,
        own,
        mac_id,
        sequence,
        address,
        report,
        rate,
        agg,
        limit: None,
        fragments: false,
    })
}
fn transmit_profile_inner(tx: Tx<'_>) -> Result<(Vec<u8>, Queue), Error> {
    let Tx {
        chip,
        frame,
        own,
        mac_id,
        sequence,
        address,
        report,
        rate,
        agg,
        limit,
        fragments,
    } = tx;
    let queue = classify_profile(frame, own, limit, fragments)?;
    if agg.is_some_and(|agg| agg.density > 7 || qos_tid(frame).is_none() || rate & FIRMWARE_RA == 0)
    {
        return Err(Error::Metadata);
    }
    let adaptive = rate & FIRMWARE_RA != 0;
    if frame[1] & 0x80 != 0 && !adaptive {
        return Err(Error::Metadata);
    }
    let er = rate & DATA_ER != 0;
    let index = rate & !(FIRMWARE_RA | DATA_ER);
    if mac_id != 0
        || sequence >= IDENTITIES
        || index > 11
        || er && !adaptive
        || queue == Queue::Management && !matches!(rate, 0 | OFDM6)
    {
        return Err(Error::Metadata);
    }
    extent(address, frame.len())?;
    let c = match chip {
        ChipId::Rtl8852B => false,
        ChipId::Rtl8852C if !fragments && limit.is_none() => true,
        // RTL8852A: the AX v0 body (`txwd_body_size`/`txwd_info_size` as
        // RTL8852B, `rtw8852a.c:2473..2474` @ 05441d6, pci.c
        // `rtw89_pci_fill_txaddr_info`), A-MSDU to its 3500 ceiling
        // (`transmit_a`); fragments under the signed N5AF companion.
        ChipId::Rtl8852A => false,
        // RTL8851B: the AX v0 body (`txwd_body_size`/`txwd_info_size` as
        // RTL8852B, pci.c `rtw89_pci_fill_txaddr_info`); no A-MSDU or
        // fragment program.
        ChipId::Rtl8851B if !fragments && limit.is_none() => false,
        _ => return Err(Error::Metadata),
    };
    let prepare = if fragments {
        tx_transport::prepare_header_fragment
    } else if amsdu(frame) {
        tx_transport::prepare_header_amsdu
    } else {
        tx_transport::prepare_header
    };
    let baseline = prepare(
        chip,
        TxwdInfo {
            channel: queue.channel(),
            qsel: queue.qsel(),
            mac_id,
            pkt_size: frame.len() as u16,
        },
        sequence,
        address,
        frame,
    )
    .map_err(|_| Error::Frame)?;
    // TXWD body (24, v1 32), then the WD info, then WP + address info.
    let body = if c { 32 } else { 24 };
    let info = body;
    let mut bytes = alloc::vec![0; baseline.len() + 24];
    bytes[..body].copy_from_slice(&baseline[..body]);
    bytes[body + 24..].copy_from_slice(&baseline[body..]);
    let body0 = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Error::Metadata)?);
    // RTW89_TXWD_BODY2_TID_INDICATE from rtw89_core_get_tid_indicate.
    if qos_tid(frame).is_some_and(super::qos::tid_indicate) {
        let body2 = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| Error::Metadata)?);
        put(&mut bytes, 8, body2 | 1 << 23);
    }
    // Linux management uses hardware SSN selector1/mode1 (body0 v0 only;
    // `rtw89_build_txwd_body0_v1` has no HW SSN field, so C management
    // keeps the host SW_SEQ). Non-QoS data retains the supplied host
    // sequence; neither enables hardware crypto.
    put(
        &mut bytes,
        0,
        body0
            | 1 << 22
            | if queue == Queue::Management && !fragments && !c {
                5
            } else {
                0
            },
    );
    if adaptive {
        // rtw89_build_txwd_info0/1 for data: firmware RA owns the rate;
        // INFO1 DATA_RTY_LOWEST_RATE[24:16] bounds hardware retry fallback.
        put(&mut bytes, info, u32::from(er) << 15);
        let num = agg.map_or(0, |agg| u32::from(agg.num));
        put(
            &mut bytes,
            info + 4,
            u32::from(index) << 16 | num | u32::from(frame[1] & 0x80 != 0) << 14,
        );
    } else if c {
        // rtw89_build_txwd_body7_v1 USE_RATE_V1 + DATA_RATE[24:16];
        // rtw89_build_txwd_info0_v1 keeps DISDATAFB.
        put(&mut bytes, 28, 1 << 31 | u32::from(rate) << 16);
        put(&mut bytes, info, 1 << 10);
    } else {
        put(&mut bytes, info, 1 << 30 | 1 << 10 | u32::from(rate) << 16); // Source DATA_RATE[24:16].
    }
    if let Some(agg) = agg {
        let body3 = u32::from_le_bytes(bytes[12..16].try_into().map_err(|_| Error::Metadata)?);
        put(&mut bytes, 12, body3 | 1 << 12);
        put(&mut bytes, info + 8, u32::from(agg.density) << 18);
    }
    put(&mut bytes, info + 12, u32::from(report) << 10);
    put(
        &mut bytes,
        info + 16,
        1 << 31 | u32::from(frame[4] & 1 == 0) << 27,
    );
    Ok((bytes, queue))
}
/// `B_AX_STOP_CH9`: the AP high queue stop bit.
pub(super) const STOP_CH9: u32 = 1 << 17;
/// Every TX stop bit the AP role can open (ordinary plus CH9).
pub(super) const AP_STOP_ALL: u32 = STOP_ALL | STOP_CH9;
/// AP role rings: every ordinary ring plus the CH9 high queue.
pub(super) fn ap_queues(qos_all: bool) -> alloc::vec::Vec<Queue> {
    let mut queues = Queue::ordinary(qos_all).to_vec();
    queues.push(Queue::High);
    queues
}
/// One AP-role transmission (`rtw89_core_tx_update_desc_info` for an AP
/// vif): the MACID of the peer link or, without one, the vif MACID
/// (`rtw89_core_tx_get_mac_id`), the vif port used only for HIQ, and
/// `IEEE80211_TX_CTL_SEND_AFTER_DTIM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ApTx {
    pub(super) mac_id: u8,
    pub(super) port: u8,
    pub(super) after_dtim: bool,
    pub(super) report: bool,
    /// Fixed rate index (management: CCK1/OFDM6) or `FIRMWARE_RA | lowest`.
    pub(super) rate: u8,
}
/// The AP-role queue of `frame`: `rtw89_core_get_tx_type` (management and
/// any Null are MGMT), `rtw89_core_get_qsel_mgmt`/`rtw89_core_get_qsel`
/// with `hiq` mapping both to `RTW89_TX_QSEL_B0_HI`.
pub(super) fn classify_ap(frame: &[u8], own: [u8; 6], after_dtim: bool) -> Result<Queue, Error> {
    if frame.len() < 24 || frame.len() > MAX_MPDU || !unicast(&own) || frame[10..16] != own {
        return Err(Error::Frame);
    }
    let group = frame[4] & 1 != 0;
    let management = frame[0] & 0x0c == 0 || matches!(frame[0], 0x48 | 0xc8);
    // Only group-addressed frames are buffered for after-DTIM delivery.
    if after_dtim && !group {
        return Err(Error::Frame);
    }
    if frame[0] & 0x0c == 0 && frame[16..22] != own {
        return Err(Error::Frame);
    }
    // Group-addressed Null/QoS-Null, probe/auth/assoc responses are invalid.
    if group && (matches!(frame[0], 0x48 | 0xc8 | 0x10 | 0x30 | 0x50 | 0xb0)) {
        return Err(Error::Frame);
    }
    if !group && !unicast(&frame[4..10]) {
        return Err(Error::Frame);
    }
    Ok(if after_dtim {
        Queue::High
    } else if management {
        Queue::Management
    } else {
        qos_tid(frame).map_or(Queue::Data, Queue::for_tid)
    })
}
/// AP-role TXWD (`rtw89_core_fill_txdesc` for the AP vif): MACID, QSEL and
/// channel from [`classify_ap`], `INFO0_MULTIPORT_ID` = port for HIQ only,
/// management HW SSN selector1/mode1 with a fixed rate, data host
/// sequence with firmware RA or a fixed rate, `INFO4_RTS_EN` unicast only.
pub(super) fn transmit_ap(
    frame: &[u8],
    own: [u8; 6],
    tx: ApTx,
    sequence: u16,
    address: u64,
) -> Result<(Vec<u8>, Queue), Error> {
    let queue = classify_ap(frame, own, tx.after_dtim)?;
    let management = frame[0] & 0x0c == 0 || matches!(frame[0], 0x48 | 0xc8);
    let adaptive = tx.rate & FIRMWARE_RA != 0;
    let index = tx.rate & !(FIRMWARE_RA | DATA_ER);
    if tx.mac_id >= 128
        || tx.port > 4
        || tx.port != 0 && !tx.after_dtim
        || sequence >= IDENTITIES
        || index > 11
        || tx.rate & DATA_ER != 0
        || management && !matches!(tx.rate, 0 | OFDM6)
        // Group frames carry the vif MACID and no firmware RA peer.
        || frame[4] & 1 != 0 && adaptive
    {
        return Err(Error::Metadata);
    }
    extent(address, frame.len())?;
    let baseline = tx_transport::prepare_header_ap(
        TxwdInfo {
            channel: queue.channel(),
            qsel: queue.qsel(),
            mac_id: tx.mac_id,
            pkt_size: frame.len() as u16,
        },
        sequence,
        address,
        frame,
    )
    .map_err(|_| Error::Frame)?;
    let mut bytes = alloc::vec![0; HEADER];
    bytes[..24].copy_from_slice(&baseline[..24]);
    bytes[48..].copy_from_slice(&baseline[24..]);
    let body0 = u32::from_le_bytes(bytes[..4].try_into().map_err(|_| Error::Metadata)?);
    if qos_tid(frame).is_some_and(super::qos::tid_indicate) {
        let body2 = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| Error::Metadata)?);
        put(&mut bytes, 8, body2 | 1 << 23);
    }
    put(
        &mut bytes,
        0,
        body0 | 1 << 22 | if management { 5 } else { 0 },
    );
    let port = u32::from(tx.port) << 4;
    if adaptive {
        put(&mut bytes, 24, port);
        put(&mut bytes, 28, u32::from(index) << 16);
    } else {
        put(
            &mut bytes,
            24,
            1 << 30 | 1 << 10 | u32::from(tx.rate) << 16 | port,
        );
    }
    put(&mut bytes, 36, u32::from(tx.report) << 10);
    put(&mut bytes, 40, 1 << 31 | u32::from(frame[4] & 1 == 0) << 27);
    Ok((bytes, queue))
}
pub(super) fn descriptor(address: u64) -> Result<[u8; 8], Error> {
    descriptor_len(address, HEADER)
}
/// `rtw89_pci_txwd_submit` TX BD for a `txwd->len` = `length` header.
pub(super) fn descriptor_len(address: u64, length: usize) -> Result<[u8; 8], Error> {
    if !(HEADER..=C_HEADER_MAX).contains(&length) {
        return Err(Error::Metadata);
    }
    extent(address, length)?;
    let mut bytes = [0; 8];
    bytes[..2].copy_from_slice(&(length as u16).to_le_bytes());
    bytes[2..4].copy_from_slice(&(1 << 14 | ((address >> 32) as u16) << 6).to_le_bytes());
    bytes[4..].copy_from_slice(&(address as u32).to_le_bytes());
    Ok(bytes)
}

#[cfg(feature = "kernel-test")]
#[path = "packet_format/tests.rs"]
mod tests;

#[cfg(feature = "kernel-test")]
#[path = "packet_format/ap_tests.rs"]
mod ap_tests;
