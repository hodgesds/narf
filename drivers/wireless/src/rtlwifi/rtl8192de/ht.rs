// SPDX-License-Identifier: GPL-2.0-or-later
//! RTL8192DE HT station profile.
//!
//! Mirrors `rtl8192ee/ht.rs`: the local TX MCS set names MCS8-15 only
//! when the signed envelope permission admits every two-stream rate —
//! and, for the 8192DE, only on a `RF_2T2R` function. A dual-dual
//! (1T1R) function never transmits two streams, however the board is
//! measured: `mode_info` gives `RfType::OneT1R` there, so
//! [`two_stream`] refuses it. The ARFR rate table
//! (`rate::rate_table_value`) already carries the MCS8-15 bits on
//! 2T2R (`0x0f0f_f005` N-mode mask); this module is the admission
//! gate that decides whether the station may offer them.
//!
//! Deliberately not here: the `LocalHt` / `LocalPhy` capability
//! advertisement (`_rtl_init_hw_ht_capab` values for the 8192DE,
//! including the dual-MAC `disable_amsdu_8k` consequence on MAX_AMSDU)
//! — the spec carries no 8192DE HT-capability values, so the
//! advertisement shape is a remainder, not a guess.

use super::envelope::Permission;
use super::RfType;

/// Full-order rate bits of MCS0-7 / MCS8-15.
pub const MCS0_7: u64 = 0xff << 12;
pub const MCS8_15: u64 = 0xff << 20;

/// HT is admitted when the permission holds a measured index for every
/// one-stream MCS (the legacy rates are always all admitted).
pub fn admitted(permission: &Permission) -> bool {
    permission.admitted_rates() & MCS0_7 == MCS0_7
}

/// Two-stream TX (MCS8-15) is admitted when the permission holds a
/// measured index for every two-stream rate and the function is
/// `RF_2T2R` (single / dual-single mode). Dual-dual functions are
/// 1T1R and never two-stream.
pub fn two_stream(permission: &Permission, rf_type: RfType) -> bool {
    rf_type == RfType::TwoT2R && permission.admitted_rates() & MCS8_15 == MCS8_15
}
