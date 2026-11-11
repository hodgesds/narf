// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8852B operating-channel geometry/source coefficients (2.4/5GHz,
//! 20/40/80MHz = rtw8852b.c `support_bandwidths`). No native/RF grant.
//! Linux7.3-rc4 chan.c `rtw89_chan_create`, rtw8852b_common.c SCO/FIR;
//! rtw8852b_rfk.c TSSI groups. Used by the retained BB/RF/IQK/TSSI/power
//! retune composition; every program is gated by its own signed record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    primary: u8,
    center: u8,
    width: Width,
}
/// Linux `enum rtw89_bandwidth` station widths. RTL8852B supports
/// 20/40/80MHz (rtw8852b.c `support_bandwidths`): every B constructor
/// (`new_5ghz`, `new_wide`, `from_mhz`) refuses 160MHz. `Mhz160` exists only
/// for the RTL8852C station chandef (rtw8852c.c `support_bandwidths` has
/// `NL80211_CHAN_WIDTH_160`), built by [`Profile::new_5ghz_160`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Width {
    Mhz20 = 0,
    Mhz40 = 1,
    Mhz80 = 2,
    Mhz160 = 3,
}
impl Width {
    pub(super) const fn mhz(self) -> u32 {
        20 << self as u32
    }
    pub(super) const fn from_mhz(mhz: u32) -> Option<Self> {
        match mhz {
            20 => Some(Self::Mhz20),
            40 => Some(Self::Mhz40),
            80 => Some(Self::Mhz80),
            _ => None,
        }
    }
}
/// `rtw8852b_rfk.c` `TSSI_EXTRA_GROUP_BIT`: average groups idx and idx + 1.
pub(super) const TSSI_EXTRA: usize = 1 << 31;
const BARKER: [u32; 14] = [
    0x1cfea, 0x1d0e1, 0x1d1d7, 0x1d2cd, 0x1d3c3, 0x1d4b9, 0x1d5b0, 0x1d6a6, 0x1d79c, 0x1d892,
    0x1d988, 0x1da7f, 0x1db75, 0x1ddc4,
];
const CCK: [u32; 14] = [
    0x27de3, 0x27f35, 0x28088, 0x281da, 0x2832d, 0x2847f, 0x285d2, 0x28724, 0x28877, 0x289c9,
    0x28b1c, 0x28c6e, 0x28dc1, 0x290ed,
];
/// Linux core.c `rtw89_channels_5ghz` 20MHz primaries usable by RTL8852B (the
/// rtw8852b_table.c 5GHz WW limit/RU tables cover every one of them).
pub(super) const GHZ5: [u8; 28] = [
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165, 169, 173, 177,
];
/// Compact admission-mask slot: 2.4GHz primary N keeps bit N (unchanged
/// channel1..13 masks); 5GHz primaries follow at 16 + index in [`GHZ5`].
/// Linux phy.c `rtw89_channel_to_idx` (2.4/5GHz) of any channel number,
/// including 40/80MHz centers.
pub(super) const fn channel_to_idx(ch: u8) -> u8 {
    match ch {
        0..=14 => ch.saturating_sub(1),
        15..=64 => ch.saturating_sub(36) / 2,
        65..=144 => 15 + ch.saturating_sub(100) / 2,
        _ => 38 + ch.saturating_sub(149) / 2,
    }
}
const fn ghz5_contains(primary: u8) -> bool {
    let mut i = 0;
    while i < GHZ5.len() {
        if GHZ5[i] == primary {
            return true;
        }
        i += 1;
    }
    false
}
pub(super) const fn slot(primary: u8) -> Option<u8> {
    if primary >= 1 && primary <= 14 {
        return Some(primary);
    }
    let mut i = 0;
    while i < GHZ5.len() {
        if GHZ5[i] == primary {
            return Some(16 + i as u8);
        }
        i += 1;
    }
    None
}
/// Primaries (2.4GHz 1..=13, then 5GHz) in a compact admission mask.
pub(super) fn primaries(mask: u64) -> impl Iterator<Item = u8> {
    (1..=13u8)
        .chain(GHZ5)
        .filter(move |&primary| slot(primary).is_some_and(|bit| mask & (1u64 << bit) != 0))
}
impl Profile {
    pub(super) const INITIAL: Self = Self {
        primary: 1,
        center: 1,
        width: Width::Mhz20,
    };
    const fn narrow(primary: u8) -> Self {
        Self {
            primary,
            center: primary,
            width: Width::Mhz20,
        }
    }
    /// Pure source-plan binding, never measured power or a current RF grant.
    /// The 2.4GHz bytes are the unchanged v1 binding; 5GHz has its own domain;
    /// a 40/80MHz program binds under its own wide domain (20MHz bytes are
    /// never reinterpreted).
    pub(super) fn bind(self, hash: &mut narf_crypto::sha256::Sha256) {
        if self.width != Width::Mhz20 {
            hash.update(
                b"RTL8852B native wide actual primary/center/width/pri_ch/txsc/subband/SCO/TSSI groups v1",
            );
            hash.update(&[
                self.primary,
                self.center,
                self.width.mhz() as u8,
                self.band_index(),
                self.pri_ch_idx(),
                self.txsc(Width::Mhz20),
                self.txsc(Width::Mhz40),
                self.subband(),
                self.chan_idx(),
            ]);
            hash.update(&self.mhz().to_le_bytes());
            hash.update(&self.center_mhz().to_le_bytes());
            hash.update(&self.sco_compensation().to_le_bytes());
            for value in self.tssi_groups() {
                hash.update(&(value as u32).to_le_bytes());
            }
            return;
        }
        if self.is_5ghz() {
            hash.update(
                b"RTL8852B native5GHz20MHz actual primary/subband/chan_idx/SCO/TSSI groups v1",
            );
            hash.update(&[
                self.primary,
                20,
                self.subband(),
                self.chan_idx(),
                self.power_index(),
            ]);
            hash.update(&self.mhz().to_le_bytes());
            hash.update(&self.sco_compensation().to_le_bytes());
            hash.update(&self.tssi_groups().map(|value| value as u8));
            return;
        }
        hash.update(b"RTL8852B native2.4GHz20MHz actual primary/SCO/FIR/TSSI groups v1");
        hash.update(&[self.primary, 20, u8::from(self.cck_only())]);
        hash.update(&self.mhz().to_le_bytes());
        for value in self.sco().into_iter().chain([self.sco_compensation()]) {
            hash.update(&value.to_le_bytes());
        }
        hash.update(&self.tssi_groups().map(|value| value as u8));
    }
    pub(super) fn new(
        band: narf_wireless::association::channel::Band,
        primary: u8,
    ) -> Option<Self> {
        use narf_wireless::association::channel::Band;
        match band {
            Band::Ghz2 => (1..=14).contains(&primary),
            Band::Ghz5 => GHZ5.contains(&primary),
            _ => false,
        }
        .then_some(Self::narrow(primary))
    }
    /// A 2.4GHz HT40 channel (mac80211 `NL80211_CHAN_HT40PLUS/MINUS`): the
    /// center is primary +/- 2 and both 20MHz halves must be channels 1..=13
    /// (channel 14 is 20MHz/CCK only).
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
            primary,
            center: if secondary_above {
                primary + 2
            } else {
                primary - 2
            },
            width: Width::Mhz40,
        })
    }
    /// A 5GHz channel of `width` containing `primary`, at the unique IEEE
    /// channelization block (from 36/100/149); every 20MHz subchannel must be
    /// a Linux core.c `rtw89_channels_5ghz` channel, so a block leaving the
    /// set is refused (never narrowed).
    pub(super) const fn new_5ghz(primary: u8, width: Width) -> Option<Self> {
        if matches!(width, Width::Mhz160) {
            return None;
        }
        Self::block_5ghz(primary, width)
    }
    /// The RTL8852C 5GHz 160MHz chandef containing `primary` (IEEE blocks
    /// 36..64, 100..128 and 149..177, every subchannel a core.c
    /// `rtw89_channels_5ghz` channel). Never an RTL8852B profile: only the
    /// C station path (`command_native::wide_profiles_c160`) builds it.
    pub(super) const fn new_5ghz_160(primary: u8) -> Option<Self> {
        Self::block_5ghz(primary, Width::Mhz160)
    }
    const fn block_5ghz(primary: u8, width: Width) -> Option<Self> {
        if !ghz5_contains(primary) {
            return None;
        }
        let base = if primary < 100 {
            36
        } else if primary < 149 {
            100
        } else {
            149
        };
        let n = 1u8 << width as u8;
        let start = base + ((primary - base) / 4 / n) * n * 4;
        let mut i = 0;
        while i < n {
            let ch = start as u32 + 4 * i as u32;
            if ch > 255 || !ghz5_contains(ch as u8) {
                return None;
            }
            i += 1;
        }
        Some(Self {
            primary,
            center: start + 2 * n - 2,
            width,
        })
    }
    /// Typed profile from a cfg80211-style chandef: primary, width and (2.4GHz
    /// 40MHz only) the secondary side. `None` for anything not RTL8852B.
    pub(super) const fn new_wide(primary: u8, width: Width, secondary_above: bool) -> Option<Self> {
        match width {
            Width::Mhz20 => {
                if (primary >= 1 && primary <= 14) || ghz5_contains(primary) {
                    Some(Self::narrow(primary))
                } else {
                    None
                }
            }
            _ if primary <= 14 => {
                if matches!(width, Width::Mhz40) {
                    Self::new_2ghz_40(primary, secondary_above)
                } else {
                    None
                }
            }
            _ => Self::new_5ghz(primary, width),
        }
    }
    pub(super) const fn width(self) -> Width {
        self.width
    }
    /// The same primary narrowed to 20MHz (association/disconnect fallback).
    pub(super) const fn narrowed(self) -> Self {
        Self::narrow(self.primary)
    }
    /// Whether the secondary 20MHz is above the primary (2.4GHz HT40PLUS).
    pub(super) const fn secondary_above(self) -> bool {
        self.center > self.primary
    }
    /// chan.c `rtw89_get_primary_chan_idx` (`enum rtw89_sc_offset`).
    pub(super) const fn pri_ch_idx(self) -> u8 {
        let (p, c) = (self.primary as u32, self.center as u32);
        match self.width {
            Width::Mhz20 => 0,
            Width::Mhz40 => {
                if p > c {
                    1
                } else {
                    2
                }
            }
            Width::Mhz80 | Width::Mhz160 => {
                // MHz distances are 5 * channel distances.
                if p > c {
                    1 + 2 * ((5 * (p - c) - 10) / 20) as u8
                } else {
                    2 + 2 * ((5 * (c - p) - 10) / 20) as u8
                }
            }
        }
    }
    /// phy.c `rtw89_phy_get_txsc(chan, dbw)` for 20/40/80/160MHz.
    pub(super) const fn txsc(self, dbw: Width) -> u8 {
        let (p, c) = (self.primary, self.center);
        if self.width as u8 == dbw as u8 || matches!(self.width, Width::Mhz20) {
            return 0;
        }
        match self.width {
            Width::Mhz40 => {
                if p > c {
                    1
                } else {
                    2
                }
            }
            Width::Mhz160 => {
                let tmp = if p > c {
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
                        if p > c {
                            13
                        } else {
                            14
                        }
                    }
                }
            }
            _ => {
                if matches!(dbw, Width::Mhz20) {
                    if p > c {
                        (p - c) >> 1
                    } else {
                        ((c - p) >> 1) + 1
                    }
                } else if p > c {
                    9
                } else {
                    10
                }
            }
        }
    }
    /// The 20MHz subchannel centers of the occupied span, low to high.
    pub(super) fn subchannels(self) -> impl Iterator<Item = u8> {
        let n = 1u8 << self.width as u8;
        let low = self.center + 2 - 2 * n;
        (0..n).map(move |i| low + 4 * i)
    }
    /// The typed profile of an unambiguous 2.4GHz (1..=14) or 5GHz primary.
    pub(super) fn from_primary(primary: u8) -> Option<Self> {
        use narf_wireless::association::channel::Band;
        Self::new(
            if primary <= 14 {
                Band::Ghz2
            } else {
                Band::Ghz5
            },
            primary,
        )
    }
    pub(super) const fn primary(self) -> u8 {
        self.primary
    }
    /// Linux `chan->channel` (the center channel); equals the primary at 20MHz.
    pub(super) const fn center(self) -> u8 {
        self.center
    }
    pub(super) const fn is_5ghz(self) -> bool {
        self.primary > 14
    }
    pub(super) const fn band(self) -> narf_wireless::association::channel::Band {
        if self.is_5ghz() {
            narf_wireless::association::channel::Band::Ghz5
        } else {
            narf_wireless::association::channel::Band::Ghz2
        }
    }
    /// Linux `rtw89_band` index (2G = 0, 5G = 1).
    pub(super) const fn band_index(self) -> u8 {
        if self.is_5ghz() {
            1
        } else {
            0
        }
    }
    /// Linux chan.c `rtw89_get_subband_type` (`RTW89_CH_2G`/`5G_BAND_1/3/4`).
    pub(super) const fn subband(self) -> u8 {
        match self.center() {
            0..=14 => 0,
            36..=64 => 1,
            100..=144 => 3,
            _ => 4,
        }
    }
    /// Linux phy.h `rtw89_subband_to_bb_gain_band`.
    pub(super) const fn gain_band(self) -> usize {
        match self.subband() {
            0 => 0,
            1 => 1,
            3 => 2,
            _ => 3,
        }
    }
    /// Linux phy.h `rtw89_subband_to_gain_offset_band_of_ofdm`.
    pub(super) const fn gain_offset_band(self) -> usize {
        match self.subband() {
            0 => 1,
            1 => 2,
            3 => 3,
            _ => 4,
        }
    }
    /// Linux phy.c `rtw89_encode_chan_idx` (B_CH_IDX_SEG0).
    pub(super) const fn chan_idx(self) -> u8 {
        if !self.is_5ghz() {
            return self.primary;
        }
        let (idx, base) = match self.primary {
            36..=99 => (2, 36),
            100..=131 => (3, 100),
            132..=148 => (4, 132),
            _ => (5, 149),
        };
        (idx << 4) | ((self.primary - base) >> 1)
    }
    /// Linux phy.c `rtw89_channel_to_idx` for the 2G/5G limit tables.
    pub(super) const fn power_index(self) -> u8 {
        channel_to_idx(self.primary)
    }
    pub(super) const fn mhz(self) -> u32 {
        if self.primary == 14 {
            2484
        } else if self.is_5ghz() {
            5000 + 5 * self.primary as u32
        } else {
            2407 + 5 * self.primary as u32
        }
    }
    /// Linux `chan->freq` (the center frequency).
    pub(super) const fn center_mhz(self) -> u32 {
        if self.is_5ghz() {
            5000 + 5 * self.center as u32
        } else if self.center == 14 {
            2484
        } else {
            2407 + 5 * self.center as u32
        }
    }
    /// The whole occupied span (regulatory admission covers all of it).
    pub(super) const fn occupied(self) -> (u32, u32) {
        let half = self.width.mhz() / 2;
        (self.center_mhz() - half, self.center_mhz() + half)
    }
    pub(super) const fn cck_only(self) -> bool {
        self.primary == 14
    }
    /// Linux `__rtw8852bx_set_channel_bb` `cck_en = chan->channel <= 14`.
    pub(super) const fn cck_enabled(self) -> bool {
        !self.is_5ghz()
    }
    /// 2.4GHz SCO barker/CCK thresholds (`rtw8852bx_ctrl_sco_cck`, CCK only).
    pub(super) fn sco(self) -> [u32; 2] {
        let i = usize::from(self.primary.clamp(1, 14) - 1);
        [BARKER[i], CCK[i]]
    }
    /// Linux rtw8852b_common.c `rtw8852bx_sco_mapping(central_ch)`.
    pub(super) const fn sco_compensation(self) -> u32 {
        match self.center() {
            1 => 109,
            2..=6 => 108,
            7..=10 => 107,
            11..=14 => 106,
            36 | 38 => 51,
            40..=58 => 50,
            60..=64 => 49,
            100 | 102 => 48,
            104..=126 => 47,
            128..=151 => 46,
            153..=177 => 45,
            _ => 0,
        }
    }
    /// Linux rtw8852b_rfk.c `_tssi_get_{cck,ofdm,trim}_group` for the center
    /// channel. At 20MHz no 5GHz center is a TSSI_EXTRA_GROUP; a 40/80MHz
    /// center between two groups carries [`TSSI_EXTRA`] on the OFDM group
    /// (B trim groups have no extra entries).
    pub(super) const fn tssi_groups(self) -> [usize; 3] {
        let ch = self.center();
        let cck = match ch {
            1..=2 => 0,
            3..=5 => 1,
            6..=8 => 2,
            9..=11 => 3,
            12..=13 => 4,
            14 => 5,
            _ => 0,
        };
        let ofdm = match ch {
            14 => 4,
            1..=13 => cck,
            36..=40 => 5,
            44..=48 => 6,
            52..=56 => 7,
            60..=64 => 8,
            100..=104 => 9,
            108..=112 => 10,
            116..=120 => 11,
            124..=128 => 12,
            132..=136 => 13,
            140..=144 => 14,
            149..=153 => 15,
            157..=161 => 16,
            165..=169 => 17,
            41..=43 => TSSI_EXTRA | 5,
            49..=51 => TSSI_EXTRA | 6,
            57..=59 => TSSI_EXTRA | 7,
            105..=107 => TSSI_EXTRA | 9,
            113..=115 => TSSI_EXTRA | 10,
            121..=123 => TSSI_EXTRA | 11,
            129..=131 => TSSI_EXTRA | 12,
            137..=139 => TSSI_EXTRA | 13,
            154..=156 => TSSI_EXTRA | 15,
            162..=164 => TSSI_EXTRA | 16,
            170..=172 => TSSI_EXTRA | 17,
            173..=177 => 18,
            _ => 0,
        };
        let trim = match ch {
            1..=8 => 0,
            9..=14 => 1,
            36..=48 => 2,
            52..=64 => 3,
            100..=112 => 4,
            116..=128 => 5,
            132..=144 => 6,
            _ => 7,
        };
        [cck, ofdm, trim]
    }
    /// CCK TXFIR words. `rtw8852bx_ctrl_ch` writes the flat set on 5GHz too;
    /// only 2.4GHz `rtw8852bx_set_tx_shape` reprograms the DFIR shape.
    pub(super) const fn cck_fir(self, shape: u8) -> [u32; 8] {
        if self.primary == 14 {
            [
                0x023b13ff, 0x001c42de, 0x00fdb0ad, 0x00f60f6e, 0x00fd8f92, 0x0602d011, 0x0001c02c,
                0x00fff00a,
            ]
        } else if shape == 0 {
            [
                0x023d23ff, 0x0029b354, 0x000fc1c8, 0x00fdb053, 0x00f86f9a, 0x06faef92, 0x00fe5fcc,
                0x00ffdff5,
            ]
        } else {
            [
                0x023d83ff, 0x002c636a, 0x0013f204, 0x00008090, 0x00f87fb0, 0x06f99f83, 0x00fdbfba,
                0x00003ff5,
            ]
        }
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    /// Linux rtw8852b_rfk.c `_tssi_get_{cck,ofdm,trim}_group`, rtw8852b_common.c
    /// `rtw8852bx_sco_mapping` and typed geometry; bare/other bands refused.
    fn smoke_rtw89_b_operating_profile_matches_linux_groups_and_refuses_other_bands() -> TestResult
    {
        use narf_wireless::association::channel::{frequency_in, Band};
        if Profile::new(Band::Ghz2, 0).is_some()
            || Profile::new(Band::Ghz2, 15).is_some()
            || Profile::new(Band::Ghz5, 6).is_some()
            || Profile::new(Band::Ghz6, 1).is_some()
            || Profile::new(Band::Ghz2, 1) != Some(Profile::INITIAL)
        {
            return TestResult::Fail("profile accepted a non-2.4GHz or out-of-range primary");
        }
        const GROUPS: [[usize; 3]; 14] = [
            [0, 0, 0],
            [0, 0, 0],
            [1, 1, 0],
            [1, 1, 0],
            [1, 1, 0],
            [2, 2, 0],
            [2, 2, 0],
            [2, 2, 0],
            [3, 3, 1],
            [3, 3, 1],
            [3, 3, 1],
            [4, 4, 1],
            [4, 4, 1],
            [5, 4, 1],
        ];
        const COMP: [u32; 14] = [
            109, 108, 108, 108, 108, 108, 107, 107, 107, 107, 106, 106, 106, 106,
        ];
        for primary in 1..=14u8 {
            let Some(profile) = Profile::new(Band::Ghz2, primary) else {
                return TestResult::Fail("typed2.4GHz primary refused");
            };
            let i = usize::from(primary - 1);
            if profile.primary() != primary
                || Some(profile.mhz()) != frequency_in(Band::Ghz2, primary)
                || profile.occupied() != (profile.mhz() - 10, profile.mhz() + 10)
                || profile.cck_only() != (primary == 14)
                || profile.tssi_groups() != GROUPS[i]
                || profile.sco_compensation() != COMP[i]
                || profile.sco() != [BARKER[i], CCK[i]]
            {
                return TestResult::Fail("profile geometry/SCO/TSSI groups differ from Linux");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_b_operating_profile_matches_linux_groups_and_refuses_other_bands
    );
    /// Linux chan.c `rtw89_get_subband_type`, phy.c `rtw89_encode_chan_idx` /
    /// `rtw89_channel_to_idx`, rtw8852b_common.c `rtw8852bx_sco_mapping` and
    /// rtw8852b_rfk.c `_tssi_get_{ofdm,trim}_group` on every 5GHz primary.
    fn smoke_rtw89_b_operating_profile_5ghz_matches_linux_indices_and_groups() -> TestResult {
        use narf_wireless::association::channel::{frequency_in, Band};
        if Profile::new(Band::Ghz5, 38).is_some()
            || Profile::new(Band::Ghz5, 14).is_some()
            || Profile::new(Band::Ghz5, 181).is_some()
            || Profile::from_primary(34).is_some()
        {
            return TestResult::Fail("profile accepted a non-20MHz 5GHz primary");
        }
        let mut slots = 0u64;
        for primary in (1..=13u8).chain(GHZ5) {
            let Some(bit) = slot(primary) else {
                return TestResult::Fail("admitted primary has no mask slot");
            };
            if bit >= 64 || slots & (1 << bit) != 0 {
                return TestResult::Fail("mask slots collide");
            }
            slots |= 1 << bit;
        }
        if primaries(slots).count() != 13 + GHZ5.len() || slot(2) != Some(2) {
            return TestResult::Fail("2.4GHz mask bits moved or 5GHz slots lost");
        }
        // (primary, subband, chan_idx, power index, sco, ofdm group, trim group)
        const ROWS: [(u8, u8, u8, u8, u32, usize, usize); 9] = [
            (36, 1, 0x20, 0, 51, 5, 2),
            (48, 1, 0x26, 6, 50, 6, 2),
            (64, 1, 0x2e, 14, 49, 8, 3),
            (100, 3, 0x30, 15, 48, 9, 4),
            (128, 3, 0x3e, 29, 46, 12, 5),
            (144, 3, 0x46, 37, 46, 14, 6),
            (149, 4, 0x50, 38, 46, 15, 7),
            (165, 4, 0x58, 46, 45, 17, 7),
            (177, 4, 0x5e, 52, 45, 18, 7),
        ];
        for (primary, subband, idx, power, sco, ofdm, trim) in ROWS {
            let Some(profile) = Profile::from_primary(primary) else {
                return TestResult::Fail("typed5GHz primary refused");
            };
            if !profile.is_5ghz()
                || profile.cck_enabled()
                || profile.band() != Band::Ghz5
                || Some(profile.mhz()) != frequency_in(Band::Ghz5, primary)
                || profile.subband() != subband
                || profile.chan_idx() != idx
                || profile.power_index() != power
                || profile.sco_compensation() != sco
                || profile.tssi_groups()[1..] != [ofdm, trim]
            {
                return TestResult::Fail("5GHz profile index/group differs from Linux");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_b_operating_profile_5ghz_matches_linux_indices_and_groups
    );
    /// chan.c `rtw89_chan_create`/`rtw89_get_primary_chan_idx`, phy.c
    /// `rtw89_phy_get_txsc` and rtw8852b_rfk.c `_tssi_get_ofdm_group` extra
    /// groups for RTL8852B 40/80MHz chandefs; 160MHz and ill-formed refused.
    fn smoke_rtw89_b_operating_profile_wide_matches_linux_chandef_geometry() -> TestResult {
        if Profile::new_2ghz_40(1, false).is_some()
            || Profile::new_2ghz_40(10, true).is_some()
            || Profile::new_2ghz_40(14, false).is_some()
            || Profile::new_wide(6, Width::Mhz80, true).is_some()
            || Profile::new_5ghz(181, Width::Mhz40).is_some()
            || Width::from_mhz(160).is_some()
        {
            return TestResult::Fail("ill-formed wide chandef accepted");
        }
        // (primary, width, above, center, pri_ch_idx, txsc20, txsc40, ofdm group)
        type Row = (u8, Width, bool, u8, u8, u8, u8, usize);
        const ROWS: [Row; 11] = [
            (1, Width::Mhz40, true, 3, 2, 2, 0, 1),
            (9, Width::Mhz40, false, 7, 1, 1, 0, 2),
            (36, Width::Mhz40, false, 38, 2, 2, 0, 5),
            (48, Width::Mhz40, false, 46, 1, 1, 0, 6),
            (165, Width::Mhz40, false, 167, 2, 2, 0, 17),
            (36, Width::Mhz80, false, 42, 4, 4, 10, TSSI_EXTRA | 5),
            (40, Width::Mhz80, false, 42, 2, 2, 10, TSSI_EXTRA | 5),
            (44, Width::Mhz80, false, 42, 1, 1, 9, TSSI_EXTRA | 5),
            (48, Width::Mhz80, false, 42, 3, 3, 9, TSSI_EXTRA | 5),
            // Center 138 is a `_tssi_get_ofdm_group` extra (137..=139).
            (144, Width::Mhz80, false, 138, 3, 3, 9, TSSI_EXTRA | 13),
            (177, Width::Mhz80, false, 171, 3, 3, 9, TSSI_EXTRA | 17),
        ];
        for (primary, width, above, center, pri, txsc20, txsc40, ofdm) in ROWS {
            let Some(p) = Profile::new_wide(primary, width, above) else {
                return TestResult::Fail("valid wide chandef refused");
            };
            let half = width.mhz() / 2;
            if p.primary() != primary
                || p.center() != center
                || p.width() != width
                || p.pri_ch_idx() != pri
                || p.txsc(Width::Mhz20) != txsc20
                || p.txsc(Width::Mhz40) != txsc40
                || p.tssi_groups()[1] != ofdm
                || p.occupied() != (p.center_mhz() - half, p.center_mhz() + half)
                || p.narrowed() != Profile::from_primary(primary).unwrap()
                || p.subchannels().count() != 1 << width as usize
                || !p.subchannels().any(|ch| ch == primary)
            {
                return TestResult::Fail("wide geometry differs from Linux");
            }
        }
        // The 20MHz binding is unchanged by the width extension.
        let mut a = narf_crypto::sha256::Sha256::new();
        let mut b = narf_crypto::sha256::Sha256::new();
        Profile::INITIAL.bind(&mut a);
        Profile::new_2ghz_40(1, true).unwrap().bind(&mut b);
        if a.finalize() == b.finalize() {
            return TestResult::Fail("wide binding aliases the 20MHz identity");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_b_operating_profile_wide_matches_linux_chandef_geometry
    );
}
