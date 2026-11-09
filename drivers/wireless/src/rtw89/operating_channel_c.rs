// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852C channel geometry and source coefficients. No native/RF grant.
//!
//! Pure Linux 7.3-rc4 derivations for a typed RTL8852C operating channel:
//! core.c `rtw89_channels_{2ghz,5ghz,6ghz}` primaries, IEEE 802.11 20/40/80/
//! 160MHz channelization (rtw8852c `support_bandwidths`) plus 6GHz 320MHz
//! EHT channelization, chan.c `rtw89_chan_create` (`rtw89_get_subband_type`,
//! `rtw89_get_tx_comp_band`, `rtw89_get_primary_chan_idx`,
//! `rtw89_get_primary_sb_idx`), phy.h gain band maps, phy.c
//! `rtw89_encode_chan_idx`, rtw8852c.c `rtw8852c_ctrl_sco_cck` /
//! `rtw8852c_ctrl_ch` SCO terms and rtw8852c_rfk.c TSSI groups. A profile is
//! a geometry fact only: admission still needs signed per-channel records and
//! the current regulatory rule over [`Profile::occupied`].

/// `enum rtw89_band`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Band {
    Ghz2 = 0,
    Ghz5 = 1,
    Ghz6 = 2,
}
/// Linux `enum rtw89_bandwidth` (`core.h`, torvalds/linux @ cbbddb6):
/// 20/40/80/160/320MHz = 0..4. This is the shared rtw89 width type the
/// channel-geometry and RFK layers carry: the BE RFK offload bodies map
/// the discriminant straight to the Linux width value
/// (`RTW89_CHANNEL_WIDTH_320` = 4), and the 8922A EHT width type
/// (`eht::Width`) is a separate, BE-only enum. 320MHz is 6GHz-only EHT
/// (IEEE 802.11be); it is NOT an RTL8852C station width (rtw8852c.c
/// `support_bandwidths` caps at 160MHz, `RTW89_5G_BW_NUM` stops at 160,
/// only `RTW89_6G_BW_NUM` reaches 320) and no 8852C station constructor
/// builds one on 2.4/5GHz. The 8852C chip programs below transcribe
/// Linux's default arms for 320MHz (they program nothing, or the 20MHz
/// default) rather than inventing a 320MHz C program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Width {
    Mhz20 = 0,
    Mhz40 = 1,
    Mhz80 = 2,
    Mhz160 = 3,
    Mhz320 = 4,
}
impl Width {
    pub(super) const fn mhz(self) -> u32 {
        20 << self as u32
    }
    const fn subchannels(self) -> u8 {
        1 << self as u8
    }
}
/// Linux core.c `rtw89_channels_5ghz` (UNII-1..4; `support_unii4`).
pub(super) const GHZ5: [u8; 28] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
];
/// Linux core.c `rtw89_channels_6ghz`: 1, 5, .., 233 (59 primaries).
pub(super) const fn is_6ghz_primary(primary: u8) -> bool {
    primary >= 1 && primary <= 233 && primary % 4 == 1
}
/// 6GHz preferred scanning channels (IEEE 802.11ax-2021 26.17.2.3.3:
/// every fourth 20MHz channel starting at 5).
pub(super) const fn is_psc(primary: u8) -> bool {
    is_6ghz_primary(primary) && primary % 16 == 5
}
const BARKER: [u32; 14] = [
    0x1fe4f, 0x1ff5e, 0x2006c, 0x2017b, 0x2028a, 0x20399, 0x204a8, 0x205b6, 0x206c5, 0x207d4,
    0x208e3, 0x209f2, 0x20b00, 0x20d8a,
];
const CCK: [u32; 14] = [
    0x2bdac, 0x2bf21, 0x2c095, 0x2c209, 0x2c37e, 0x2c4f2, 0x2c666, 0x2c7db, 0x2c94f, 0x2cac3,
    0x2cc38, 0x2cdac, 0x2cf21, 0x2d29e,
];
/// rtw8852c_rfk.c `TSSI_EXTRA_GROUP_BIT`.
pub(super) const TSSI_EXTRA: u32 = 1 << 31;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    band: Band,
    primary: u8,
    center: u8,
    width: Width,
}
const fn ghz5_index(primary: u8) -> Option<usize> {
    let mut i = 0;
    while i < GHZ5.len() {
        if GHZ5[i] == primary {
            return Some(i);
        }
        i += 1;
    }
    None
}
impl Profile {
    /// RTL8852C channel 1 / 20MHz, the initial chip-row program.
    pub(super) const INITIAL: Self = Self {
        band: Band::Ghz2,
        primary: 1,
        center: 1,
        width: Width::Mhz20,
    };
    /// A 20MHz primary on `band`.
    pub(super) const fn new20(band: Band, primary: u8) -> Option<Self> {
        let ok = match band {
            Band::Ghz2 => primary >= 1 && primary <= 14,
            Band::Ghz5 => ghz5_index(primary).is_some(),
            Band::Ghz6 => is_6ghz_primary(primary),
        };
        if ok {
            Some(Self {
                band,
                primary,
                center: primary,
                width: Width::Mhz20,
            })
        } else {
            None
        }
    }
    /// A 2.4GHz HT40 channel: the center is primary +/- 2 and both 20MHz
    /// halves must be channels 1..=13 (channel 14 is 20MHz/CCK only).
    pub(super) const fn new_2ghz_40(primary: u8, secondary_above: bool) -> Option<Self> {
        let secondary = if secondary_above {
            primary.wrapping_add(4)
        } else {
            primary.wrapping_sub(4)
        };
        if primary < 1 || primary > 13 || secondary < 1 || secondary > 13 {
            return None;
        }
        Some(Self {
            band: Band::Ghz2,
            primary,
            center: if secondary_above {
                primary + 2
            } else {
                primary - 2
            },
            width: Width::Mhz40,
        })
    }
    /// A 5/6GHz channel of `width` containing `primary`, at the unique IEEE
    /// channelization block (5GHz blocks start at 36/100/149, 6GHz at 1);
    /// every 20MHz subchannel of the block must be a Linux channel.
    /// 320MHz is 6GHz-only: 5GHz blocks leave the Linux channel set and
    /// are refused. 320MHz centers are spaced 160MHz (IEEE 802.11be EHT
    /// bonds two 160MHz channels, so a primary sits in two overlapping
    /// 320MHz channels); `new_wide` builds the 64-channel-aligned one
    /// (centers 31/95/159) and [`Self::new_6ghz_320`] builds any of the
    /// six valid centers (31/63/95/127/159/191) explicitly.
    pub(super) const fn new_wide(band: Band, primary: u8, width: Width) -> Option<Self> {
        let base = match band {
            Band::Ghz2 => return None,
            Band::Ghz5 => {
                if ghz5_index(primary).is_none() {
                    return None;
                }
                if primary < 100 {
                    36
                } else if primary < 149 {
                    100
                } else {
                    149
                }
            }
            Band::Ghz6 => {
                if !is_6ghz_primary(primary) {
                    return None;
                }
                1
            }
        };
        let n = width.subchannels();
        let start = base + ((primary - base) / 4 / n) * n * 4;
        let mut i = 0;
        while i < n {
            let ch = start as u32 + 4 * i as u32;
            let ok = match band {
                Band::Ghz5 => ch <= 255 && ghz5_index(ch as u8).is_some(),
                _ => ch <= 255 && is_6ghz_primary(ch as u8),
            };
            if !ok {
                return None;
            }
            i += 1;
        }
        Some(Self {
            band,
            primary,
            center: start + 2 * n - 2,
            width,
        })
    }
    /// A 6GHz 320MHz channel with an explicit center: the six valid IEEE
    /// 802.11be centers are 31 + 32k (31/63/95/127/159/191; 223's block
    /// runs past the 6GHz band edge at channel 233 and is refused by the
    /// subchannel check). `primary` must be one of the channel's sixteen
    /// 20MHz subchannels and every subchannel must be a Linux 6GHz
    /// primary.
    pub(super) const fn new_6ghz_320(primary: u8, center: u8) -> Option<Self> {
        if center < 31 || center > 223 || (center - 31) % 32 != 0 {
            return None;
        }
        if !is_6ghz_primary(primary) {
            return None;
        }
        let low = center - 30;
        let mut i = 0;
        let mut found = false;
        while i < 16 {
            let ch = low + 4 * i;
            if !is_6ghz_primary(ch) {
                return None;
            }
            if ch == primary {
                found = true;
            }
            i += 1;
        }
        if !found {
            return None;
        }
        Some(Self {
            band: Band::Ghz6,
            primary,
            center,
            width: Width::Mhz320,
        })
    }
    pub(super) const fn band(self) -> Band {
        self.band
    }
    pub(super) const fn primary(self) -> u8 {
        self.primary
    }
    /// Linux `chan->channel`.
    pub(super) const fn center(self) -> u8 {
        self.center
    }
    pub(super) const fn width(self) -> Width {
        self.width
    }
    /// cfg80211 `ieee80211_channel_to_frequency` (5GHz 182..196 is 4.9GHz
    /// Japan and never a Linux rtw89 channel).
    pub(super) const fn channel_mhz(band: Band, channel: u8) -> u32 {
        match band {
            Band::Ghz2 => {
                if channel == 14 {
                    2484
                } else {
                    2407 + 5 * channel as u32
                }
            }
            Band::Ghz5 => 5000 + 5 * channel as u32,
            Band::Ghz6 => {
                if channel == 2 {
                    5935
                } else {
                    5950 + 5 * channel as u32
                }
            }
        }
    }
    /// Linux `chan->freq` (the center frequency).
    pub(super) const fn center_mhz(self) -> u32 {
        Self::channel_mhz(self.band, self.center)
    }
    pub(super) const fn primary_mhz(self) -> u32 {
        Self::channel_mhz(self.band, self.primary)
    }
    /// The whole occupied span, for regulatory admission.
    pub(super) const fn occupied(self) -> (u32, u32) {
        let half = self.width.mhz() / 2;
        (self.center_mhz() - half, self.center_mhz() + half)
    }
    /// chan.c `rtw89_get_subband_type` (`enum rtw89_subband` values),
    /// transcribed literally including the `default:` arm: the 6GHz
    /// ranges leave 3-channel gaps (30..32, 62..64, ...) and any center
    /// in a gap falls to `RTW89_CH_6G_BAND_IDX0` (5). Every 320MHz center
    /// (31/63/95/127/159/191) sits in a gap, so every 320MHz channel
    /// has subband 5; no center reachable at 20/40/80/160MHz is in a
    /// gap, so the older widths are unaffected.
    pub(super) const fn subband(self) -> u8 {
        match self.band {
            Band::Ghz2 => 0,
            Band::Ghz5 => match self.center {
                0..=99 => 1,
                100..=148 => 3,
                _ => 4,
            },
            // RTW89_CH_6G_BAND_IDX0 (5) .. IDX7 (12); gap centers
            // (the 320MHz centers) fall to IDX0 by Linux's default arm.
            Band::Ghz6 => match self.center {
                1..=29 => 5,
                33..=61 => 6,
                65..=93 => 7,
                97..=125 => 8,
                129..=157 => 9,
                161..=189 => 10,
                193..=221 => 11,
                225..=253 => 12,
                _ => 5,
            },
        }
    }
    /// chan.c `rtw89_get_tx_comp_band`.
    pub(super) const fn tx_comp_band(self) -> u8 {
        match self.band {
            Band::Ghz2 => 0,
            Band::Ghz5 => {
                if self.center < 149 {
                    1
                } else {
                    2
                }
            }
            Band::Ghz6 => {
                if self.center < 65 {
                    2
                } else if self.center < 193 {
                    3
                } else {
                    4
                }
            }
        }
    }
    /// phy.h `rtw89_subband_to_bb_gain_band` (`RTW89_BB_GAIN_BAND_*`).
    pub(super) const fn gain_band(self) -> usize {
        match self.subband() {
            0 => 0,
            1 => 1,
            3 => 2,
            4 => 3,
            s => 4 + (s as usize - 5) / 2,
        }
    }
    /// phy.h `rtw89_subband_to_gain_offset_band_of_ofdm`
    /// (`RTW89_GAIN_OFFSET_*`; 2G OFDM = 1, 5G L/M/H = 2..4, 6G = 5..12).
    pub(super) const fn gain_offset_band(self) -> usize {
        match self.subband() {
            0 => 1,
            1 => 2,
            3 => 3,
            4 => 4,
            s => s as usize,
        }
    }
    /// phy.c `rtw89_encode_chan_idx(chan->primary_channel, band)` as
    /// written by `rtw8852c_ctrl_ch` to B_CH_IDX_SEG0.
    pub(super) const fn chan_idx(self) -> u8 {
        let p = self.primary;
        let (idx, base): (u8, u8) = match self.band {
            Band::Ghz2 => return p,
            Band::Ghz5 => match p {
                0..=99 => (2, 36),
                100..=131 => (3, 100),
                132..=148 => (4, 132),
                _ => (5, 149),
            },
            Band::Ghz6 => (7 + (p - 1) / 32, 1 + 32 * ((p - 1) / 32)),
        };
        (idx << 4) | ((p - base) >> 1)
    }
    /// chan.c `rtw89_get_primary_chan_idx` (`enum rtw89_sc_offset`).
    /// Linux switches on 20/40/80/160 only; 320MHz falls to `default:`
    /// and returns `RTW89_SC_DONT_CARE` (0).
    pub(super) const fn pri_ch_idx(self) -> u8 {
        let center = self.center_mhz();
        let primary = self.primary_mhz();
        match self.width {
            Width::Mhz20 => 0,
            Width::Mhz320 => 0,
            Width::Mhz40 => {
                if primary > center {
                    1
                } else {
                    2
                }
            }
            Width::Mhz80 | Width::Mhz160 => {
                if primary > center {
                    1 + 2 * ((primary - center - 10) / 20) as u8
                } else {
                    2 + 2 * ((center - primary - 10) / 20) as u8
                }
            }
        }
    }
    /// chan.c `rtw89_get_primary_sb_idx`.
    pub(super) const fn pri_sb_idx(self) -> u8 {
        // chan.c `prisb_cal_ofst[RTW89_CHANNEL_WIDTH_ORDINARY_NUM]`
        // = {0, 2, 6, 14, 30}.
        const OFST: [u8; 5] = [0, 2, 6, 14, 30];
        (OFST[self.width as usize] + self.primary - self.center) / 4
    }
    /// Linux `chan->rfsi_band` (`RFSI_CTRL_BAND_2GHZ` = 1, 5/6GHz = 0).
    pub(super) const fn rfsi_band(self) -> u8 {
        match self.band {
            Band::Ghz2 => 1,
            _ => 0,
        }
    }
    /// rtw8852c.c `rtw8852c_set_channel_bb` `cck_en`.
    pub(super) const fn cck_enabled(self) -> bool {
        matches!(self.band, Band::Ghz2)
    }
    /// rtw8852c.c `rtw8852c_ctrl_sco_cck(chan->channel,
    /// chan->primary_channel, bw)` barker/CCK thresholds (2.4GHz only).
    /// The 40MHz element follows Linux literally, including its
    /// `primary_ch == 1` case.
    pub(super) const fn sco_cck(self) -> Option<[u32; 2]> {
        if !matches!(self.band, Band::Ghz2) {
            return None;
        }
        let element = (match self.width {
            Width::Mhz20 => self.center - 1,
            Width::Mhz40 => {
                if self.primary == 1 {
                    self.center - 1 + 2
                } else {
                    self.center - 1 - 2
                }
            }
            // Linux: any other bandwidth is -EINVAL for CCK (320MHz is
            // 6GHz-only, so it never reaches here on a 2.4GHz profile).
            Width::Mhz80 | Width::Mhz160 | Width::Mhz320 => return None,
        }) as usize;
        if element >= 14 {
            return None;
        }
        Some([BARKER[element], CCK[element]])
    }
    /// rtw8852c.c `rtw8852c_ctrl_ch` R_FC0_V1 (center MHz) and R_FC0_BW
    /// `DIV_ROUND_CLOSEST(1 << 18, central_freq)`.
    pub(super) const fn sco_fc0(self) -> (u32, u32) {
        let fc = self.center_mhz();
        (fc, ((1 << 18) + fc / 2) / fc)
    }
    /// rtw8852c.c `rtw8852c_ctrl_ch` CCK pulse-shape coefficients
    /// (R_PCOEFF0..E_V1), 2.4GHz only; channel 14 has its own set.
    pub(super) const fn cck_pcoeff(self) -> Option<[u32; 8]> {
        if !matches!(self.band, Band::Ghz2) {
            return None;
        }
        Some(if self.center == 14 {
            [
                0x3b13ff, 0x1c42de, 0xfdb0ad, 0xf60f6e, 0xfd8f92, 0x2d011, 0x1c02c, 0xfff00a,
            ]
        } else {
            [
                0x3d23ff, 0x29b354, 0xfc1c8, 0xfdb053, 0xf86f9a, 0xfaef92, 0xfe5fcc, 0xffdff5,
            ]
        })
    }
    /// phy.c `rtw89_phy_get_txsc(chan, dbw)`.
    pub(super) const fn txsc(self, dbw: Width) -> u8 {
        let (p, c) = (self.primary, self.center);
        if self.width as u8 == dbw as u8 || matches!(self.width, Width::Mhz20) {
            return 0;
        }
        let above = p > c;
        match self.width {
            Width::Mhz40 => {
                if above {
                    1
                } else {
                    2
                }
            }
            Width::Mhz80 => {
                if matches!(dbw, Width::Mhz20) {
                    if above {
                        (p - c) >> 1
                    } else {
                        ((c - p) >> 1) + 1
                    }
                } else if above {
                    9
                } else {
                    10
                }
            }
            Width::Mhz160 => {
                let tmp = if above {
                    (p - c) >> 1
                } else {
                    ((c - p) >> 1) + 1
                };
                match dbw {
                    Width::Mhz20 => tmp,
                    Width::Mhz40 => match tmp {
                        1 | 3 => 9,
                        5 | 7 => 11,
                        2 | 4 => 10,
                        6 | 8 => 12,
                        _ => 0xff,
                    },
                    _ => {
                        if above {
                            13
                        } else {
                            14
                        }
                    }
                }
            }
            // Linux `rtw89_phy_get_txsc` switches on 40/80/160/80+80
            // only; 320MHz falls to `default:` and returns 0.
            Width::Mhz320 => 0,
            Width::Mhz20 => 0,
        }
    }
    /// rtw8852c.c `rtw8852c_set_channel_mac(MAC_0)`: (R_AX_WMAC_RFMOD
    /// 0xc010 bits 1:0, R_AX_TX_SUB_CARRIER_VALUE 0xc088 word, the
    /// R_AX_TXRATE_CHK 0xc628 bits set after clearing BAND_MODE|CHECK_CCK_EN|
    /// RTS_LIMIT_IN_OFDM6). Linux has no 320MHz arm in either switch:
    /// the txsc switch falls to `default:` (all txsc 0) and the RFMOD
    /// switch falls to `default:` (`AX_WMAC_RFMOD_20M`, 0), so a 320MHz
    /// profile programs (0, 0, chk) on the 8852C.
    pub(super) const fn mac_program(self) -> (u8, u32, u8) {
        let txsc20 = self.txsc(Width::Mhz20) as u32;
        let txsc40 = self.txsc(Width::Mhz40) as u32;
        let txsc80 = self.txsc(Width::Mhz80) as u32;
        let (rf_mod, sub_carrier) = match self.width {
            Width::Mhz20 => (0, 0),
            Width::Mhz40 => (1, txsc20 & 15),
            Width::Mhz80 => (2, (txsc20 & 15) | ((txsc40 & 15) << 4)),
            Width::Mhz160 => (
                3,
                (txsc20 & 15) | ((txsc40 & 15) << 4) | ((txsc80 & 15) << 8),
            ),
            Width::Mhz320 => (0, 0),
        };
        let chk = match self.band {
            Band::Ghz2 => 1 << 4,
            _ => (1 << 0) | (1 << 1),
        };
        (rf_mod, sub_carrier, chk)
    }
    /// rtw8852c_rfk.c TSSI groups of the center channel: (`_tssi_get_cck_group`
    /// for 2.4GHz, OFDM group, trim group). 6GHz uses `_tssi_get_6g_*`.
    /// Extra groups carry [`TSSI_EXTRA`] (average of idx and idx + 1).
    /// rtw8852c_rfk.c `_tssi_set_efuse_to_de`: `_tssi_get_cck_group(ch)`
    /// of `chan->channel` whatever the band (5/6GHz numbers fall to the
    /// switch default or alias 2.4GHz rows, literally as Linux).
    pub(super) const fn tssi_cck_group(self) -> u32 {
        tssi_cck_group(self.center)
    }
    pub(super) const fn tssi_groups(self) -> (Option<u32>, u32, u32) {
        let ch = self.center;
        match self.band {
            Band::Ghz6 => (None, tssi_6g_ofdm_group(ch), tssi_6g_trim_group(ch)),
            Band::Ghz2 => (
                Some(tssi_cck_group(ch)),
                tssi_ofdm_group(ch),
                tssi_trim_group(ch),
            ),
            Band::Ghz5 => (None, tssi_ofdm_group(ch), tssi_trim_group(ch)),
        }
    }
}
const fn tssi_cck_group(ch: u8) -> u32 {
    match ch {
        1..=2 => 0,
        3..=5 => 1,
        6..=8 => 2,
        9..=11 => 3,
        12..=13 => 4,
        14 => 5,
        _ => 0,
    }
}
/// `_tssi_get_ofdm_group`: 5GHz 20MHz groups 5..18 with 3-channel extra
/// groups between them (36..40 -> 5, 41..43 -> extra 5, ...).
const fn tssi_ofdm_group(ch: u8) -> u32 {
    const RUNS: [(u8, u8, u32); 14] = [
        (36, 40, 5),
        (44, 48, 6),
        (52, 56, 7),
        (60, 64, 8),
        (100, 104, 9),
        (108, 112, 10),
        (116, 120, 11),
        (124, 128, 12),
        (132, 136, 13),
        (140, 144, 14),
        (149, 153, 15),
        (157, 161, 16),
        (165, 169, 17),
        (173, 177, 18),
    ];
    match ch {
        1..=2 => return 0,
        3..=5 => return 1,
        6..=8 => return 2,
        9..=11 => return 3,
        12..=14 => return 4,
        _ => {}
    }
    let mut i = 0;
    while i < RUNS.len() {
        let (lo, hi, g) = RUNS[i];
        if ch >= lo && ch <= hi {
            return g;
        }
        // Extra group up to three channels after a run, unless the run ends a
        // UNII segment (64, 144, 177).
        if ch > hi && ch <= hi + 3 && !matches!(hi, 64 | 144 | 177) {
            return TSSI_EXTRA | g;
        }
        i += 1;
    }
    0
}
/// `_tssi_get_6g_ofdm_group`: 32 groups of 8 channels from 1; each 32-channel
/// subband has 4 groups, the first three followed by a 3-channel extra group.
const fn tssi_6g_ofdm_group(ch: u8) -> u32 {
    if ch < 1 || ch > 253 {
        return 0;
    }
    let block = (ch - 1) / 32;
    let offset = (ch - 1) % 32;
    let sub = offset / 8;
    let pos = offset % 8;
    let g = (block * 4 + sub) as u32;
    if pos <= 4 {
        g
    } else if sub < 3 && pos <= 7 {
        TSSI_EXTRA | g
    } else {
        0
    }
}
/// `_tssi_get_trim_group`.
const fn tssi_trim_group(ch: u8) -> u32 {
    match ch {
        1..=8 => 0,
        9..=14 => 1,
        36..=48 => 2,
        49..=51 => TSSI_EXTRA | 2,
        52..=64 => 3,
        100..=112 => 4,
        113..=115 => TSSI_EXTRA | 4,
        116..=128 => 5,
        132..=144 => 6,
        149..=177 => 7,
        _ => 0,
    }
}
/// `_tssi_get_6g_trim_group`: two 16-channel groups per 32-channel subband,
/// the first followed by a 3-channel extra group (14..16, 46..48, ...).
const fn tssi_6g_trim_group(ch: u8) -> u32 {
    if ch < 1 || ch > 253 {
        return 0;
    }
    let block = (ch - 1) / 32;
    let offset = (ch - 1) % 32;
    let g = (block * 2) as u32;
    match offset {
        0..=12 => g,
        13..=15 => TSSI_EXTRA | g,
        16..=28 => g + 1,
        _ => 0,
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "operating_channel_c/tests.rs"]
mod tests;
