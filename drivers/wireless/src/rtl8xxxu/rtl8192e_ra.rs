// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192EU gen2 firmware rate adaptation over H2C, from Linux
//! `rtl8xxxu/core.c`: `rtl8xxxu_gen2_update_rate_mask`
//! (`H2C_8723B_MACID_CFG_RAID`), `rtl8xxxu_gen2_report_connect`
//! (`H2C_8723B_MEDIA_STATUS_RPT`), `rtl8xxxu_gen2_report_rssi`
//! (`H2C_8723B_RSSI_SETTING`), the 2.4 GHz `rtl8xxxu_refresh_rate_mask`
//! masks for 1SS/2SS, `rtl8xxxu_ra_iter`, the `BSS_CHANGED_ASSOC` joinbss
//! sequence of `rtl8xxxu_bss_info_changed`, and the C2H RA report fold of
//! `rtl8xxxu_update_ra_report`.
//!
//! Unlike the RTL8188EU (host RA in `rate_adaptation`), the 8192E firmware
//! picks DATA rates; the host only supplies the mask. Every mask sent is a
//! subset of the caller's admitted rate set: a peer mask with any bit
//! outside it is refused, never silently narrowed.
use super::firmware_transport::{ControlIo, Error, Owner};
use super::rate_adaptation::{level, signal_to_snr, Level};
use super::rtl8192e_packet::RaReport;

pub const H2C_MEDIA_STATUS_RPT: u8 = 0x01;
pub const H2C_MACID_CFG_RAID: u8 = 0x40;
pub const H2C_RSSI_SETTING: u8 = 0x42;
/// `H2C_MACID_ROLE_AP`: the station reports its AP entry with this role.
pub const MACID_ROLE_AP: u8 = 2;

const REG_FWHW_TXQ_CTRL: u16 = 0x0420;
const REG_TBTT_PROHIBIT: u16 = 0x0540;
const REG_BEACON_CTRL: u16 = 0x0550;
const BEACON_DISABLE_TSF_UPDATE: u8 = 1 << 4;
const REG_BCN_MAX_ERR: u16 = 0x055d;
const REG_BCN_PSR_RPT: u16 = 0x06a8;

/// `enum rtl8xxxu_rateid` values used on 2.4 GHz.
pub mod rate_id {
    pub const BGN_40M_2SS: u8 = 0;
    pub const BGN_40M_1SS: u8 = 1;
    pub const BGN_20M_2SS_BN: u8 = 2;
    pub const BGN_20M_1SS_BN: u8 = 3;
    pub const GN_N2SS: u8 = 4;
    pub const GN_N1SS: u8 = 5;
    pub const BG: u8 = 6;
    pub const G: u8 = 7;
    pub const B: u8 = 8;
}

/// `h2c.b_macid_cfg` (8 bytes): macid, RAID|SGI, bandwidth, ramask LE.
pub fn macid_cfg(mask: u32, rate_id: u8, sgi: bool, bandwidth40: bool, macid: u8) -> [u8; 8] {
    let m = mask.to_le_bytes();
    [
        H2C_MACID_CFG_RAID,
        macid,
        rate_id | if sgi { 0x80 } else { 0 },
        u8::from(bandwidth40),
        m[0],
        m[1],
        m[2],
        m[3],
    ]
}

/// `h2c.media_status_rpt` (4 bytes): connect bit 0, role in [7:4].
pub fn media_status(macid: u8, role: u8, connect: bool) -> [u8; 4] {
    [
        H2C_MEDIA_STATUS_RPT,
        u8::from(connect) | (role << 4),
        macid,
        0,
    ]
}

/// `h2c.rssi_report` (8 bytes on RTL8192E; only RTL8723B truncates to 4).
pub fn rssi_setting(macid: u8, rssi: u8) -> [u8; 8] {
    [H2C_RSSI_SETTING, macid, 0, rssi, 0, 0, 0, 0]
}

/// The AP's rates as mac80211 holds them in `ieee80211_sta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    /// `supp_rates[0]` (DESC rate bits 0..=11).
    pub legacy: u16,
    /// `ht_cap.mcs.rx_mask[0..2]`.
    pub mcs: [u8; 2],
    pub ht: bool,
    /// `ht_cap.cap & (SGI_20 | SGI_40)`.
    pub sgi: bool,
}

impl Peer {
    /// The raw `ramask` Linux builds at association.
    pub fn mask(&self) -> u32 {
        let mcs = if self.ht {
            u32::from(self.mcs[0]) << 12 | u32::from(self.mcs[1]) << 20
        } else {
            0
        };
        u32::from(self.legacy & 0xfff) | mcs
    }
}

/// One `update_rate_mask` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateMask {
    pub mask: u32,
    pub rate_id: u8,
    pub sgi: bool,
    pub bandwidth40: bool,
}

/// `rtl8xxxu_refresh_rate_mask` bitmap/rate-id selection for a 2.4 GHz
/// peer (`rtl8xxxu_wireless_mode` without 5 GHz/VHT). `two_ss` is
/// `tx_paths == 2 && rx_paths == 2` (RTL8192EU; the 1T2R RTL8191EU is 1SS).
pub fn level_mask(peer: Peer, level: Level, two_ss: bool, bandwidth40: bool) -> RateMask {
    let mut bitmap = peer.mask();
    let b = peer.legacy <= 0xf;
    let bg = !b && peer.legacy & 0xf != 0;
    let rate_id = if peer.ht {
        if b || bg {
            let rate_id = match (bandwidth40, two_ss) {
                (true, true) => rate_id::BGN_40M_2SS,
                (true, false) => rate_id::BGN_40M_1SS,
                (false, true) => rate_id::BGN_20M_2SS_BN,
                (false, false) => rate_id::BGN_20M_1SS_BN,
            };
            let (ss, low) = if two_ss {
                (
                    0x0f8f_0000,
                    if bandwidth40 {
                        0x0f8f_f015
                    } else {
                        0x0f8f_f005
                    },
                )
            } else {
                (
                    0x000f_0000,
                    if bandwidth40 {
                        0x000f_f015
                    } else {
                        0x000f_f005
                    },
                )
            };
            bitmap &= match level {
                Level::High => ss,
                Level::Mid => ss | 0xf000,
                _ => low,
            };
            rate_id
        } else if two_ss {
            // G|N_24G: Linux applies no level mask.
            rate_id::GN_N2SS
        } else {
            rate_id::GN_N1SS
        }
    } else if b {
        bitmap &= if bitmap & 0xc != 0 { 0xd } else { 0xf };
        rate_id::B
    } else if bg {
        bitmap &= match level {
            Level::High => 0xf00,
            Level::Mid => 0xff0,
            _ => 0xff5,
        };
        rate_id::BG
    } else {
        bitmap &= if level == Level::High { 0xf00 } else { 0xff0 };
        rate_id::G
    };
    RateMask {
        mask: bitmap,
        rate_id,
        sgi: peer.sgi,
        bandwidth40,
    }
}

/// `struct rtl8xxxu_ra_report` as the station reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxRate {
    pub desc_rate: u8,
    pub sgi: bool,
    pub bandwidth40: bool,
}

/// Station RA state for the one port-0 AP entry (macid 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ra {
    peer: Peer,
    admitted: u32,
    two_ss: bool,
    bandwidth40: bool,
    level: Level,
    tx_rate: Option<TxRate>,
}

impl Ra {
    /// Refuses (`RuntimeState`) an empty peer mask or one carrying any rate
    /// outside `admitted` (no narrowing: a 1T board whose admitted set lacks
    /// MCS8..15 refuses a 2SS peer), and 40 MHz for a non-HT peer.
    pub fn new(peer: Peer, admitted: u32, tx_paths: u8, bandwidth40: bool) -> Result<Self, Error> {
        let mask = peer.mask();
        if mask == 0 || mask & !admitted != 0 || mask >> 28 != 0 {
            return Err(Error::RuntimeState);
        }
        if bandwidth40 && !peer.ht || !matches!(tx_paths, 1 | 2) {
            return Err(Error::RuntimeState);
        }
        Ok(Self {
            peer,
            admitted,
            two_ss: tx_paths == 2,
            bandwidth40,
            level: Level::Init,
            tx_rate: None,
        })
    }
    pub fn level(&self) -> Level {
        self.level
    }
    pub fn tx_rate(&self) -> Option<TxRate> {
        self.tx_rate
    }
    /// The association `update_rate_mask(ramask, 0, sgi, bw)`. Linux passes
    /// the peer's 20/40 capability; this owner passes the operating width
    /// (never a 40 MHz request on an HT20 channel).
    pub fn connect_mask(&self) -> RateMask {
        RateMask {
            mask: self.peer.mask(),
            rate_id: 0,
            sgi: self.peer.sgi,
            bandwidth40: self.bandwidth40,
        }
    }
    /// `rtl8xxxu_refresh_rate_mask(signal, force = false)`: a request only
    /// when the RSSI level changes.
    pub fn refresh(&mut self, signal: i32) -> Option<RateMask> {
        let next = level(self.level, signal);
        if next == self.level {
            return None;
        }
        self.level = next;
        Some(level_mask(self.peer, next, self.two_ss, self.bandwidth40))
    }
    /// `rtl8xxxu_update_ra_report` from the association highest rate.
    fn connected(&mut self) {
        let mask = self.peer.mask();
        let highest = 31 - mask.leading_zeros() as u8;
        self.fold(highest, self.peer.sgi, Some(self.bandwidth40));
    }
    /// C2H RA report fold. Reports for another macid or a rate outside the
    /// admitted set are ignored, like Linux's invalid-rate early return.
    pub fn report(&mut self, report: &RaReport) {
        if report.macid != 0 || !report.valid() || self.admitted & (1 << report.rate) == 0 {
            return;
        }
        self.fold(report.rate, report.sgi, report.bandwidth40);
    }
    fn fold(&mut self, rate: u8, sgi: bool, bandwidth40: Option<bool>) {
        let previous = self.tx_rate.is_some_and(|r| r.bandwidth40);
        self.tx_rate = Some(TxRate {
            desc_rate: rate,
            sgi: sgi && rate >= 12,
            bandwidth40: rate >= 12 && bandwidth40.unwrap_or(previous),
        });
    }
}

impl<I: ControlIo> Owner<I> {
    /// `priv->fops->update_rate_mask` for macid 0.
    pub(super) async fn update_rate_mask_8192e(&self, request: RateMask) -> Result<(), Error> {
        let cmd = macid_cfg(
            request.mask,
            request.rate_id,
            request.sgi,
            request.bandwidth40,
            0,
        );
        super::rtl8192e_init::h2c(self, &cmd).await
    }

    /// `BSS_CHANGED_ASSOC` with `vif->cfg.assoc`: rate mask, beacon error
    /// limit, `rtl8xxxu_stop_tx_beacon`, joinbss `REG_BCN_PSR_RPT`, then the
    /// media-status connect that turns on firmware rate control.
    pub(super) async fn ra_connect_8192e(&self, ra: &mut Ra, aid: u16) -> Result<(), Error> {
        if aid == 0 || aid > 2007 {
            return Err(Error::RuntimeState);
        }
        self.update_rate_mask_8192e(ra.connect_mask()).await?;
        self.write8(REG_BCN_MAX_ERR, 0xff).await?;
        let txq = self.read8(REG_FWHW_TXQ_CTRL + 2).await? & !(1 << 6);
        self.write8(REG_FWHW_TXQ_CTRL + 2, txq).await?;
        self.write8(REG_TBTT_PROHIBIT + 1, 0x64).await?;
        let tbtt = self.read8(REG_TBTT_PROHIBIT + 2).await? & !1;
        self.write8(REG_TBTT_PROHIBIT + 2, tbtt).await?;
        self.write16(REG_BCN_PSR_RPT, 0xc000 | aid).await?;
        let cmd = media_status(0, MACID_ROLE_AP, true);
        super::rtl8192e_init::h2c(self, &cmd).await?;
        ra.connected();
        Ok(())
    }

    /// `BSS_CHANGED_ASSOC` without association: TSF updates off and the
    /// media-status disconnect.
    pub(super) async fn ra_disconnect_8192e(&self) -> Result<(), Error> {
        let ctrl = self.read8(REG_BEACON_CTRL).await? | BEACON_DISABLE_TSF_UPDATE;
        self.write8(REG_BEACON_CTRL, ctrl).await?;
        let cmd = media_status(0, MACID_ROLE_AP, false);
        super::rtl8192e_init::h2c(self, &cmd).await
    }

    /// `rtl8xxxu_ra_iter` (2 s watchdog): RSSI report, then a mask refresh
    /// when the level changed. `signal` is `-ewma_rssi_read`.
    pub(super) async fn ra_watchdog_8192e(&self, ra: &mut Ra, signal: i32) -> Result<(), Error> {
        let cmd = rssi_setting(0, signal_to_snr(signal));
        super::rtl8192e_init::h2c(self, &cmd).await?;
        if let Some(request) = ra.refresh(signal) {
            self.update_rate_mask_8192e(request).await?;
        }
        Ok(())
    }
}
