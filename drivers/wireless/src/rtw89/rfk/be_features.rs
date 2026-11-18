// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! RTL8922A RFK features from the retained selected NORMAL suit:
//! fw.c::fw_feat_tbl/rtw89_fw_iterate_feature_cfg and fw.h W1 fields.
use super::super::{download_plan::DownloadPlan, mac::ChipId};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum PreNotify {
    V0,
    V1,
    V2,
    Disabled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) enum MccNotify {
    Disabled,
    V0,
    V1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct Features {
    version: [u8; 4],
    pub(in crate::rtw89) iqk_v0: bool,
    pub(in crate::rtw89) rxdck_v0: bool,
    pub(in crate::rtw89) pre: PreNotify,
    pub(in crate::rtw89) mcc: MccNotify,
}
impl Features {
    pub(in crate::rtw89) fn packet_mlme(&self) -> bool {
        self.version[0..2] == [0, 35]
            && u32::from_be_bytes(self.version) >= u32::from_be_bytes([0, 35, 8, 0])
    }
    pub(in crate::rtw89) fn addr_cam_v0(&self) -> bool {
        u32::from_be_bytes(self.version) < u32::from_be_bytes([0, 35, 84, 0])
    }
    pub(in crate::rtw89) fn from_plan(plan: &DownloadPlan) -> Option<Self> {
        let header = plan.header();
        if plan.chip() != ChipId::Rtl8922A || header.len() < 48 || header[15] != 1 {
            return None;
        }
        Some(Self::select(header[4..8].try_into().ok()?))
    }
    fn select(version: [u8; 4]) -> Self {
        // RTW89_FW_VER_CODE packs major/minor/sub/index in descending bytes;
        // on-wire W1 stores them in ascending LE byte positions.
        let code = u32::from_be_bytes(version);
        let v = |sub: u8| u32::from_be_bytes([0, 35, sub, 0]);
        Self {
            version,
            iqk_v0: code < v(28),
            rxdck_v0: code < v(42),
            pre: if code >= v(84) {
                PreNotify::Disabled
            } else if code >= v(49) {
                PreNotify::V2
            } else if code >= v(31) {
                PreNotify::V1
            } else {
                PreNotify::V0
            },
            mcc: if code >= v(84) {
                MccNotify::V1
            } else if code >= v(49) {
                MccNotify::V0
            } else {
                MccNotify::Disabled
            },
        }
    }
    pub(in crate::rtw89) fn version(&self) -> [u8; 4] {
        self.version
    }
    /// fw_feat_tbl: RTL8922A NO_PHYCAP_P1 before0.35.51.0.
    pub(in crate::rtw89) fn phycap_part1(&self) -> bool {
        u32::from_be_bytes(self.version) >= u32::from_be_bytes([0, 35, 51, 0])
    }
    /// rtw8922ae.c maps892b to rtw8922ae_vs_variant, whose actual
    /// fw_min_ver_code is0.35.54.0 (rtw8922a.c).
    pub(in crate::rtw89) fn supports_device(&self, device: u16) -> bool {
        match device {
            0x8922 => true,
            0x892b => u32::from_be_bytes(self.version) >= u32::from_be_bytes([0, 35, 54, 0]),
            _ => false,
        }
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtw89) fn fixture(version: [u8; 4]) -> Self {
        Self::select(version)
    }
}
#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, kt_assert_eq, TestResult};
    fn smoke_rtw8922a_rfk_firmware_feature_version_boundaries() -> TestResult {
        for (version, iqk, rx, pre, mcc) in [
            (
                [0, 35, 27, 255],
                true,
                true,
                PreNotify::V0,
                MccNotify::Disabled,
            ),
            (
                [0, 35, 28, 0],
                false,
                true,
                PreNotify::V0,
                MccNotify::Disabled,
            ),
            (
                [0, 35, 30, 255],
                false,
                true,
                PreNotify::V0,
                MccNotify::Disabled,
            ),
            (
                [0, 35, 31, 0],
                false,
                true,
                PreNotify::V1,
                MccNotify::Disabled,
            ),
            (
                [0, 35, 42, 0],
                false,
                false,
                PreNotify::V1,
                MccNotify::Disabled,
            ),
            (
                [0, 35, 48, 255],
                false,
                false,
                PreNotify::V1,
                MccNotify::Disabled,
            ),
            ([0, 35, 49, 0], false, false, PreNotify::V2, MccNotify::V0),
            ([0, 35, 83, 255], false, false, PreNotify::V2, MccNotify::V0),
            (
                [0, 35, 84, 0],
                false,
                false,
                PreNotify::Disabled,
                MccNotify::V1,
            ),
        ] {
            let f = Features::select(version);
            kt_assert_eq!(f.version(), version);
            kt_assert_eq!(f.iqk_v0, iqk);
            kt_assert_eq!(f.rxdck_v0, rx);
            kt_assert_eq!(f.pre, pre);
            kt_assert_eq!(f.mcc, mcc);
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89/8922a",
        smoke_rtw8922a_rfk_firmware_feature_version_boundaries
    );
}
