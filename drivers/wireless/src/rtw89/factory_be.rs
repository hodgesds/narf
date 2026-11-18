// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A packed RF logical-map calibration fields, no hardware authority.
//! rtw8922a.h::rtw8922a_efuse/rtw8922a_tssi_offset and rtw8922a.c
//! ::rtw8922a_efuse_parsing_tssi/::rtw8922a_efuse_parsing_gain_offset.
//! Offsets follow packed byte arrays; no Rust/C struct casts.
use super::operating_channel_c::{Band, Profile};
use super::txpower_8922a::{GainProfile, PathEfuse, TssiProfile};
use alloc::vec::Vec;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Calibration {
    pub(super) tssi: TssiProfile,
    pub(super) gain: GainProfile,
}
impl Calibration {
    pub(super) fn from_logical(rf: &[u8]) -> Option<Self> {
        // Last source field: rx_gain_6g_b[8] at432..440.
        if rf.len() < 440 {
            return None;
        }
        let paths = core::array::from_fn(|path| {
            let base = 16 + 42 * path;
            let six = [256, 298][path];
            PathEfuse {
                therm: rf[208 + path],
                cck_tssi: rf[base..base + 6].try_into().unwrap(),
                bw40_tssi: rf[base + 6..base + 11].try_into().unwrap(),
                bw40_1s_tssi_5g: rf[base + 18..base + 32].try_into().unwrap(),
                bw40_1s_tssi_6g: rf[six..six + 32].try_into().unwrap(),
            }
        });
        let gains = core::array::from_fn(|path| {
            let base = 212 + path * 5;
            let six = 424 + path * 8;
            let mut raw = [0; 13];
            // Packed struct: OFDM before CCK. Gain enum: CCK before OFDM.
            raw[0] = rf[base + 1];
            raw[1] = rf[base];
            raw[2..5].copy_from_slice(&rf[base + 2..base + 5]);
            raw[5..].copy_from_slice(&rf[six..six + 8]);
            raw
        });
        Some(Self {
            tssi: TssiProfile::parse(paths),
            gain: GainProfile::parse(gains),
        })
    }
    /// Source rtw8922a_set_rx_gain_normal, path A then B, as PHY-relative
    /// unpositioned fields. Empty only for the source all-zero/all-FF validity
    /// rule; missing map data was refused by from_logical, never defaulted.
    pub(super) fn rx_gain_program(&self, profile: Profile) -> Vec<(u32, u32, u32)> {
        let mut out = Vec::new();
        if !self.gain.offset_valid() {
            return out;
        }
        for path in 0..2 {
            if profile.band() == Band::Ghz2 {
                let value = self.gain.offset(path, 0).unwrap().wrapping_neg();
                let fraction = (value as u8) & 3;
                let bias = if fraction == 0 {
                    0
                } else {
                    u32::from(4 - fraction) << 1
                };
                out.push((0x672c, 0x0000_000f, bias));
                out.push((0x672c, 0x0000_00f0, bias));
                let offset = i32::from(value >> 2) + i32::from(fraction != 0) + 0xdc;
                out.push((0x6750, 0x0000_00ff, offset as u32));
            }
            let offset = i32::from(self.gain.offset(path, profile.gain_offset_band()).unwrap());
            let path_offset = if path == 0 { 0 } else { 0x400 };
            out.push((0x40c8 + path_offset, 0xff00_0000, (offset + 0xf8) as u32));
            let mut value = offset * -4;
            let v1 = value.clamp(-128, 127);
            value -= v1;
            let v2 = value.clamp(-128, 127);
            value -= v2;
            let v3 = value.clamp(-128, 127);
            out.extend_from_slice(&[
                (0x41e8 + path_offset, 0xff, v1 as u32),
                (0x41f8 + path_offset, 0xff, v2 as u32),
                (0x41f8 + path_offset, 0xff00, v3 as u32),
                (0x41f8 + path_offset, 0xff0000, v1 as u32),
                (0x4208 + path_offset, 0xff0000, v2 as u32),
                (0x4208 + path_offset, 0xff000000, v3 as u32),
            ]);
        }
        out
    }
}
#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
    fn smoke_rtw8922a_actual_packed_factory_tssi_and_rx_gain_fields() -> TestResult {
        let mut rf = [0xff; 0x240];
        for (i, v) in rf.iter_mut().enumerate() {
            *v = i as u8;
        }
        let parsed = Calibration::from_logical(&rf).unwrap();
        kt_assert_eq!(parsed.tssi.thermal(0), Some(208));
        kt_assert_eq!(parsed.tssi.thermal(1), Some(209));
        kt_assert_eq!(parsed.tssi.cck(0, 0), Some(16));
        kt_assert_eq!(parsed.tssi.cck(1, 5), Some(63));
        kt_assert_eq!(parsed.tssi.mcs(0, 0), Some(22));
        kt_assert_eq!(parsed.tssi.mcs(0, 5), Some(34));
        kt_assert_eq!(parsed.tssi.mcs(1, 18), Some(89));
        kt_assert_eq!(parsed.tssi.mcs_6g(0, 31), Some(31));
        kt_assert_eq!(parsed.tssi.mcs_6g(1, 0), Some(42));
        kt_assert_eq!(parsed.gain.offset(0, 0), Some(-85));
        kt_assert_eq!(parsed.gain.offset(0, 1), Some(-84));
        kt_assert_eq!(parsed.gain.offset(0, 5), Some(-40));
        kt_assert_eq!(parsed.gain.offset(1, 12), Some(-55));
        kt_assert!(parsed.gain.offset_valid());
        kt_assert!(Calibration::from_logical(&rf[..439]).is_none());
        for value in [0, 0xff] {
            let blank = [value; 440];
            kt_assert!(!Calibration::from_logical(&blank)
                .unwrap()
                .gain
                .offset_valid());
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89/8922a",
        smoke_rtw8922a_actual_packed_factory_tssi_and_rx_gain_fields
    );
}
