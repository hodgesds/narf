// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! New noninitial2.4GHz20MHz geometry/source coefficients. No native/RF grant.
//! Linux7.3-rc4 rtw8852b_common.c SCO/FIR; rtw8852b_rfk.c TSSI groups.
//! Used by the retained BB/RF/IQK/TSSI/power retune composition; no native
//! caller selects a noninitial profile until per-channel qualification exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Profile {
    primary: u8,
}
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
    pub(super) const INITIAL: Self = Self { primary: 1 };
    /// Pure source-plan binding, never measured power or a current RF grant.
    /// The 2.4GHz bytes are the unchanged v1 binding; 5GHz has its own domain.
    pub(super) fn bind(self, hash: &mut narf_crypto::sha256::Sha256) {
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
        .then_some(Self { primary })
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
        self.primary
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
        match self.primary {
            1..=14 => self.primary - 1,
            36..=64 => (self.primary - 36) / 2,
            100..=144 => 15 + (self.primary - 100) / 2,
            _ => 38 + (self.primary - 149) / 2,
        }
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
    pub(super) const fn occupied(self) -> (u32, u32) {
        (self.mhz() - 10, self.mhz() + 10)
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
    /// channel. At 20MHz no 5GHz center is a TSSI_EXTRA_GROUP.
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
            _ => 18,
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
}
