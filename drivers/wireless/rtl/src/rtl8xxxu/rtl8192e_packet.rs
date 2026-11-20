// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EU native packet framing: the 40-byte gen2 TX descriptor
//! (`core.c::rtl8xxxu_tx` common fields + `rtl8xxxu_fill_txdesc_v2`), the
//! 24-byte `rtl8xxxu_rxdesc24` receive parse (`rtl8xxxu_parse_rxdesc24`),
//! the gen2 C2H RA report (`rtl8723bu_handle_c2h` /
//! `rtl8xxxu_c2hcmd_callback`) and the 8192E RX signal
//! (`rtl8723au_rx_parse_phystats` + `8192e.c::rtl8192e_cck_rssi`).
//!
//! Pure byte codec: no device access, no capability. Rate selection for
//! DATA belongs to firmware RA (gen2 leaves the descriptor rate at 0 and only
//! sets the fallback limit); management frames use the driver rate 1M with
//! a retry limit of 6, exactly as Linux.
use super::packet_codec::{access_category, data_tid, Error, Kind, MAX_TRANSFER};
use alloc::vec::Vec;

/// `sizeof(struct rtl8xxxu_txdesc40)`.
pub const TX_DESC: usize = 40;
/// `sizeof(struct rtl8xxxu_rxdesc24)`.
pub const RX_DESC: usize = 24;
/// `DESC_RATE_24M`, the RTS rate `rtl8xxxu_tx` picks when RTS/CTS is used.
pub const RTS_RATE_24M: u8 = 0x08;
/// `DESC_RATE_MCS0` / `DESC_RATE_MCS15`.
pub const DESC_RATE_MCS0: u8 = 0x0c;
pub const DESC_RATE_MCS15: u8 = 0x1b;
/// `C2H_8723B_RA_REPORT`.
pub const C2H_RA_REPORT: u8 = 0x0c;

const TXDESC_OWN: u8 = 1 << 7;
const TXDESC_FIRST_SEGMENT: u8 = 1 << 3;
const TXDESC_LAST_SEGMENT: u8 = 1 << 2;
const TXDESC_BROADMULTICAST: u8 = 1 << 0;
const TXDESC_QUEUE_MGNT: u32 = 0x12;
const TXDESC40_AGG_ENABLE: u32 = 1 << 12;
const TXDESC40_AGG_BREAK: u32 = 1 << 16;
const TXDESC_AMPDU_DENSITY_SHIFT: u32 = 20;
const TXDESC40_USE_DRIVER_RATE: u32 = 1 << 8;
const TXDESC40_CTS_SELF_ENABLE: u32 = 1 << 11;
const TXDESC40_RTS_CTS_ENABLE: u32 = 1 << 12;
const TXDESC40_HW_RTS_ENABLE: u32 = 1 << 13;
const TXDESC40_DATA_RATE_FB_SHIFT: u32 = 8;
const TXDESC40_RETRY_LIMIT_ENABLE: u32 = 1 << 17;
const TXDESC40_RETRY_LIMIT_SHIFT: u32 = 18;
const TXDESC40_RTS_RATE_SHIFT: u32 = 24;
const TXDESC40_SHORT_PREAMBLE: u32 = 1 << 4;
const TXDESC40_SEQ_SHIFT: u32 = 12;

/// Per-frame inputs `rtl8xxxu_tx` derives from mac80211 state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TxControl {
    /// `rtl8xxxu_get_macid`: 0 (`RTL8XXXU_BC_MC_MACID`) for the port-0
    /// station's AP entry.
    pub macid: u8,
    /// HT peer A-MPDU density (`ht_cap.ampdu_density`); `Some` only for QoS
    /// DATA to an HT peer (`ampdu_enable`).
    pub ampdu_density: Option<u8>,
    /// The frame's TID has an operational originator BA session
    /// (`priv->tid_tx_operational`).
    pub tid_operational: bool,
    /// `bss_conf.use_short_preamble` with a station entry.
    pub short_preamble: bool,
    /// `skb->len > rts_threshold`.
    pub use_rts: bool,
    /// `bss_conf.use_cts_prot`.
    pub use_cts_prot: bool,
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// `rtl8xxxu_calc_tx_desc_csum`: XOR of the first 32 bytes only (the
/// comment in Linux: "the descriptor checksum is still only calculated over
/// the initial 32 bytes"), with the field itself zeroed first.
pub fn checksum(packet: &mut [u8]) {
    packet[28..30].fill(0);
    let sum = packet[..32]
        .chunks_exact(2)
        .fold(0u16, |v, b| v ^ u16::from_le_bytes([b[0], b[1]]));
    packet[28..30].copy_from_slice(&sum.to_le_bytes());
}

/// Validate and frame one MPDU. The checks match the RTL8188EU codec:
/// unfragmented, protected-bit clear (software CCMP encrypts before this
/// codec and sets nothing here), management subtypes the station issues,
/// and ToDS DATA/QoS DATA with a valid TID.
pub fn transmit(frame: &[u8], kind: Kind, control: TxControl) -> Result<Vec<u8>, Error> {
    if frame.len() < 24 || frame.len() > MAX_TRANSFER - TX_DESC {
        return Err(Error::Length);
    }
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    if fc & 3 != 0 || frame[22] & 15 != 0 || fc & 0x0400 != 0 || control.macid >= 128 {
        return Err(Error::Header);
    }
    match kind {
        Kind::Management
            if fc & 0x0c != 0
                || fc & 0x0300 != 0
                || !matches!(frame[0], 0x00 | 0x20 | 0xa0 | 0xb0 | 0xc0 | 0xd0)
                || control.ampdu_density.is_some() =>
        {
            return Err(Error::Header);
        }
        Kind::Data
            if !matches!(frame[0], 0x08 | 0x88)
                || frame[1] & 3 != 1
                || frame[0] == 0x88
                    && !matches!(frame.get(24..26), Some(&[tid, 0]) if tid & 0xf8 == 0)
                || frame[0] != 0x88 && control.ampdu_density.is_some() =>
        {
            return Err(Error::Header);
        }
        _ => (),
    }
    Ok(encode(frame, kind, control))
}

/// The internally prepared broadcast probe (never accepted by `transmit`).
pub(super) fn transmit_probe(probe: &super::probe_runtime::Prepared) -> Vec<u8> {
    encode(probe.bytes(), Kind::Management, TxControl::default())
}
/// The internal payload-free (QoS) Null used for station power indication.
/// Like the RTL8188EU path the supplied SN is kept: HW_SEQ_ENABLE stays
/// clear because the station layer, not `IEEE80211_TX_CTL_ASSIGN_SEQ`,
/// assigns sequence numbers here.
pub(super) fn transmit_null(null: &super::ps_null::Prepared) -> Vec<u8> {
    encode(null.bytes(), Kind::Data, TxControl::default())
}

fn encode(frame: &[u8], kind: Kind, control: TxControl) -> Vec<u8> {
    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    let management = kind == Kind::Management;
    let mut out = alloc::vec![0; TX_DESC + frame.len()];
    out[..2].copy_from_slice(&(frame.len() as u16).to_le_bytes());
    out[2] = TX_DESC as u8;
    // ieee80211_get_DA: A3 for ToDS, else A1.
    let destination = if fc & 0x0300 == 0x0100 {
        frame[16]
    } else {
        frame[4]
    };
    out[3] = TXDESC_OWN
        | TXDESC_FIRST_SEGMENT
        | TXDESC_LAST_SEGMENT
        | if destination & 1 != 0 {
            TXDESC_BROADMULTICAST
        } else {
            0
        };
    // rtl8xxxu_queue_select (beacons are never sent by the station).
    let queue = if management {
        TXDESC_QUEUE_MGNT
    } else {
        u32::from(access_category(data_tid(frame)).0)
    };
    put(&mut out, 4, queue << 8 | u32::from(control.macid));
    let ampdu = control.ampdu_density.is_some();
    let mut dw2 = control
        .ampdu_density
        .map_or(0, |d| u32::from(d & 7) << TXDESC_AMPDU_DENSITY_SHIFT);
    dw2 |= if ampdu && control.tid_operational {
        TXDESC40_AGG_ENABLE
    } else {
        TXDESC40_AGG_BREAK
    };
    put(&mut out, 8, dw2);
    let rts = ampdu || control.use_rts || control.use_cts_prot;
    let rts_rate = if rts { RTS_RATE_24M } else { 0 };
    // fill_txdesc_v2: rate 0; DATA gets the 0x1f fallback limit, management
    // overwrites txdw4 with the driver rate + retry limit 6.
    let mut dw3 = 0;
    let mut dw4 = if management {
        dw3 |= TXDESC40_USE_DRIVER_RATE;
        6 << TXDESC40_RETRY_LIMIT_SHIFT | TXDESC40_RETRY_LIMIT_ENABLE
    } else {
        0x1f << TXDESC40_DATA_RATE_FB_SHIFT
    };
    dw4 |= u32::from(rts_rate) << TXDESC40_RTS_RATE_SHIFT;
    if ampdu || control.use_rts {
        dw3 |= TXDESC40_RTS_CTS_ENABLE | TXDESC40_HW_RTS_ENABLE;
    } else if control.use_cts_prot {
        // The vendor driver sets no HW_RTS_ENABLE for CTS-to-self.
        dw3 |= TXDESC40_CTS_SELF_ENABLE;
    }
    put(&mut out, 12, dw3);
    put(&mut out, 16, dw4);
    if control.short_preamble {
        put(&mut out, 20, TXDESC40_SHORT_PREAMBLE);
    }
    let sequence = u32::from(u16::from_le_bytes([frame[22], frame[23]]) >> 4);
    put(&mut out, 36, sequence << TXDESC40_SEQ_SHIFT);
    checksum(&mut out);
    out[TX_DESC..].copy_from_slice(frame);
    out
}

/// One received MPDU after `rtl8xxxu_parse_rxdesc24`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub bytes: Vec<u8>,
    /// `struct rtl8723au_phy_stats` bytes when `phy_stats` is set.
    pub phy: Vec<u8>,
    /// `rxmcs` (DESC rate: 0..=11 legacy, 12..=27 MCS0..15).
    pub rate: u8,
    pub bandwidth40: bool,
    pub tid: u8,
    pub qos: bool,
    pub macid: u8,
    /// `!swdec && security != NONE`: hardware decrypted. Software CCMP owns
    /// keys here, so such a frame is never admitted.
    pub decrypted: bool,
    pub amsdu: bool,
    pub paggr: bool,
    pub more_frag: bool,
    pub ldpc: bool,
    pub stbc: bool,
    /// `tsfl` (DW5).
    pub timestamp: u32,
}

impl Frame {
    pub fn ht(&self) -> bool {
        self.rate >= DESC_RATE_MCS0
    }
    /// Station admission: plaintext (software-crypto) MPDUs only, no
    /// fragments, no A-MSDU, legacy 20 MHz or HT MCS0..15 at 20 MHz or (when
    /// `ht40` is admitted) 40 MHz. A-MPDU members (`paggr`) only with an
    /// accepted recipient BA session (`ba`). Header must match the
    /// descriptor's QoS/TID view.
    pub fn admitted(&self, ht: bool, ht40: bool, ba: bool) -> bool {
        if self.decrypted || self.more_frag || self.amsdu || self.ldpc || self.stbc {
            return false;
        }
        let b = &self.bytes;
        // BlockAckReq (gen2 F9): a 20-byte control frame (FC + Duration +
        // RA + TA + BAR Control + Starting Sequence Control, FCS stripped
        // by the hardware), admitted for the recipient reorder advance.
        // The DATA checks below (24-byte header, QoS/TID view) do not
        // apply to it; a descriptor PAGGR claim on a control frame is
        // still refused.
        if b.len() == 20 && b.first() == Some(&0x84) && !self.paggr {
            return b[1] & 4 == 0;
        }
        if b.len() < 24 || b[22] & 15 != 0 || b[1] & 4 != 0 {
            return false;
        }
        let qos = b[0] & 0x8c == 0x88;
        if qos != self.qos {
            return false;
        }
        if qos {
            match b.get(24..26) {
                Some(q) if q[0] & 15 == self.tid && q[0] & 0xf0 == 0 && q[1] == 0 => {}
                _ => return false,
            }
        }
        if self.paggr && !(ba && qos && self.ht()) {
            return false;
        }
        if !self.ht() {
            return !self.bandwidth40 && self.rate <= 11;
        }
        ht && self.rate <= DESC_RATE_MCS15 && (!self.bandwidth40 || ht40)
    }
}

/// `struct rtl8xxxu_ra_report` input from a C2H RA report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RaReport {
    pub rate: u8,
    pub sgi: bool,
    pub macid: u8,
    pub ldpc: bool,
    pub txbf: bool,
    pub noisy: bool,
    /// `ra_report.bw`, only when the report is long enough
    /// (`offsetofend(ra_report.bw)`); `None` keeps the previous width.
    pub bandwidth40: Option<bool>,
}

impl RaReport {
    /// `rtl8xxxu_update_ra_report`: only legacy 0..=11 and MCS0..15 update
    /// the retained report; anything else is ignored.
    pub fn valid(&self) -> bool {
        self.rate <= DESC_RATE_MCS15
    }
    /// Spatial streams for an MCS report (`nss`), `None` for legacy.
    pub fn nss(&self) -> Option<u8> {
        (DESC_RATE_MCS0..=DESC_RATE_MCS15)
            .contains(&self.rate)
            .then_some(if self.rate < DESC_RATE_MCS0 + 8 { 1 } else { 2 })
    }
}

/// A `rpt_sel` record: gen2 C2H with `struct rtl8723bu_c2h` (id, seq, body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum C2h {
    RaReport(RaReport),
    Other { id: u8, seq: u8, payload: Vec<u8> },
}

/// Parse a C2H body (the descriptor's `pktlen` bytes after drvinfo/shift).
pub fn c2h(body: &[u8]) -> Result<C2h, Error> {
    let [id, seq, rest @ ..] = body else {
        return Err(Error::Length);
    };
    if *id != C2H_RA_REPORT {
        return Ok(C2h::Other {
            id: *id,
            seq: *seq,
            payload: rest.to_vec(),
        });
    }
    // rate/sgi, macid, ldpc/txbf/noisy, 3 reserved, bw.
    let [rs, macid, flags, ..] = rest else {
        return Err(Error::Length);
    };
    Ok(C2h::RaReport(RaReport {
        rate: rs & 0x7f,
        sgi: rs & 0x80 != 0,
        macid: *macid,
        ldpc: flags & 1 != 0,
        txbf: flags & 2 != 0,
        noisy: flags & 4 != 0,
        bandwidth40: rest.get(6).map(|bw| *bw == 1),
    }))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    Frame(Frame),
    C2h(C2h),
}

/// `rtl8xxxu_parse_rxdesc24` over one completed bulk-IN transfer. Records
/// follow at `roundup(pktlen + drvinfo + shift + 24, 8)`; parsing stops when
/// fewer than 24 bytes remain, like Linux. Every extent is checked before a
/// byte is copied. CRC32/ICV-error MPDUs are dropped (mac80211 discards
/// `RX_FLAG_FAILED_FCS_CRC`); C2H records never become MPDUs.
pub fn receive(bytes: &[u8]) -> Result<Vec<Record>, Error> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if bytes.len() > MAX_TRANSFER || bytes.len() < RX_DESC {
        return Err(Error::Length);
    }
    let mut records = Vec::new();
    let mut at = 0;
    while bytes.len() - at >= RX_DESC {
        let desc = &bytes[at..at + RX_DESC];
        let d0 = word(desc, 0);
        let d1 = word(desc, 4);
        let d2 = word(desc, 8);
        let d3 = word(desc, 12);
        let d4 = word(desc, 16);
        let length = (d0 & 0x3fff) as usize;
        let info = ((d0 >> 16) & 15) as usize * 8;
        let shift = ((d0 >> 24) & 3) as usize;
        let start = at + RX_DESC + info + shift;
        let end = start.checked_add(length).ok_or(Error::Length)?;
        let body = bytes.get(start..end).ok_or(Error::Length)?;
        if length == 0 {
            return Err(Error::Descriptor);
        }
        if d2 & (1 << 28) != 0 {
            records.push(Record::C2h(c2h(body)?));
        } else if d0 & ((1 << 14) | (1 << 15)) == 0 {
            // No multi-descriptor reassembly: FS and LS must both be set.
            if d0 & ((1 << 28) | (1 << 29)) != ((1 << 28) | (1 << 29)) || length < 10 {
                return Err(Error::Descriptor);
            }
            let bw = (d4 >> 4) & 3;
            if bw > 1 {
                return Err(Error::Descriptor);
            }
            records.push(Record::Frame(Frame {
                bytes: body.to_vec(),
                phy: if d0 & (1 << 26) != 0 {
                    bytes[at + RX_DESC..at + RX_DESC + info].to_vec()
                } else {
                    Vec::new()
                },
                rate: (d3 & 0x7f) as u8,
                bandwidth40: bw == 1,
                tid: ((d1 >> 8) & 15) as u8,
                qos: d0 & (1 << 23) != 0,
                macid: (d1 & 0x7f) as u8,
                decrypted: d0 & (1 << 27) == 0 && d0 & (7 << 20) != 0,
                amsdu: d1 & (1 << 13) != 0,
                paggr: d1 & (1 << 15) != 0,
                more_frag: d1 & (1 << 27) != 0,
                ldpc: d4 & 2 != 0,
                stbc: d4 & 4 != 0,
                timestamp: word(desc, 20),
            }));
        }
        let next = (end - at).next_multiple_of(8);
        at = match at.checked_add(next) {
            Some(n) if n <= bytes.len() => n,
            _ => break,
        };
    }
    Ok(records)
}

/// `rtl8723au_rx_parse_phystats` signal with `rtl8192e_cck_rssi`: CCK
/// (`rxmcs < DESC_RATE_6M`) uses LNA/VGA of `cck_agc_rpt_ofdm_cfosho_a`
/// (byte 5) and the table selected by `priv->cck_agc_report_type`; OFDM/HT
/// use `(cck_sig_qual_ofdm_pwdb_all >> 1) - 110` (byte 4).
pub fn signal(phy: &[u8], rate: u8, cck_agc_report_type: bool) -> Option<i8> {
    if rate < 4 {
        const TABLE_0: [i8; 8] = [15, 9, -10, -21, -23, -27, -43, -44];
        const TABLE_1: [i8; 8] = [24, 18, 13, -4, -11, -18, -31, -36];
        let agc = *phy.get(5)?;
        let lna = usize::from(agc >> 5);
        let vga = (agc & 31) as i8;
        let gain = if cck_agc_report_type {
            TABLE_1[lna]
        } else {
            TABLE_0[lna]
        };
        Some(gain.wrapping_sub(2 * vga))
    } else {
        Some(((*phy.get(4)? >> 1) as i8).wrapping_sub(110))
    }
}
