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
impl Profile {
    pub(super) const INITIAL: Self = Self { primary: 1 };
    /// Pure source-plan binding, never measured power or a current RF grant.
    pub(super) fn bind(self, hash: &mut narf_crypto::sha256::Sha256) {
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
        (band == narf_wireless::association::channel::Band::Ghz2 && (1..=14).contains(&primary))
            .then_some(Self { primary })
    }
    pub(super) const fn primary(self) -> u8 {
        self.primary
    }
    pub(super) const fn mhz(self) -> u32 {
        if self.primary == 14 {
            2484
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
    pub(super) fn sco(self) -> [u32; 2] {
        [
            BARKER[usize::from(self.primary - 1)],
            CCK[usize::from(self.primary - 1)],
        ]
    }
    pub(super) const fn sco_compensation(self) -> u32 {
        match self.primary {
            1 => 109,
            2..=6 => 108,
            7..=10 => 107,
            _ => 106,
        }
    }
    pub(super) const fn tssi_groups(self) -> [usize; 3] {
        let cck = match self.primary {
            1..=2 => 0,
            3..=5 => 1,
            6..=8 => 2,
            9..=11 => 3,
            12..=13 => 4,
            _ => 5,
        };
        let ofdm = if self.primary == 14 { 4 } else { cck };
        [cck, ofdm, if self.primary <= 8 { 0 } else { 1 }]
    }
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
}
