// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Signed measured RTL8852A radio program identities, the A counterpart of
//! `radio_policy` (B `N52B` v2 + `N52C`) and `radio_policy_c` (C `N5CB` v2 +
//! `N5CC`), with their own names and identities so no B or C record or
//! identity ever admits A (or vice versa).
//!
//! The six optional operating programs are the shared `radio_policy::Program`
//! bit layout and dependencies (WMM/QoS/RA/HT/HE/A-MPDU, byte 57 base flags
//! 3). Each enabled program extends the board identity in the fixed `ALL`
//! order, so a signed record authorizes exactly the emitter programs it was
//! measured with. The A recipes run over the common AX station fingerprints
//! (`station_control::{wmm,qos_all,firmware_ra,ht,he,ampdu}_fingerprint`)
//! sent through the A v0 TXWD path (`rtw89_core_fill_txdesc`, the same AX
//! v0 body B uses; A `max_amsdu_limit` is 3500, `max_tx_agg_num` 128).
//!
//! This module defines the program identities only. The A base/channel
//! record and the `Qualification` that loads it, plus the
//! `command_native::OrdinaryGrant::A` wiring that gates A radio access on
//! it, are a follow-up: they need the A station admission from #1870 step 2
//! (unmerged) on main first. Until then no A owner can consume these
//! programs, and no B/C record admits them.
use super::radio_policy::Program;
/// Profile byte 57: the B base flags with one bit per program.
const BASE_FLAGS: u8 = 3;
/// Optional operating programs an A base record may enable (byte 57, the
/// B `radio_policy::Program` bit layout and dependencies). All six have a
/// real A path (v0 TXWD station, A-MPDU and A-MSDU in `packet_core`).
pub(super) const PROGRAMS: [Program; 6] = [
    Program::Wmm,
    Program::QosAll,
    Program::FirmwareRa,
    Program::Ht,
    Program::He,
    Program::Ampdu,
];
fn programs_valid(flags: u8) -> bool {
    let known = PROGRAMS.iter().fold(BASE_FLAGS, |m, p| m | p.bit());
    Program::valid(flags) && flags & !known == 0
}
/// Extend an A identity by one enabled program (domain-separated from B's
/// `Program::extend` and C's `radio_policy_c::extend`; the station
/// H2C/TXWD programs are the common AX code the B fingerprints measure,
/// sent through the A v0 TXWD path).
fn extend(program: Program, identity: [u8; 32]) -> [u8; 32] {
    let mut hash = narf_crypto::sha256::Sha256::new();
    match program {
        Program::Wmm => {
            hash.update(
                b"NARF RTL8852A WMM BE/TID0 legacy12 optional operating recipe v1;txwd_body_v0",
            );
            hash.update(&identity);
            hash.update(&super::station_control::wmm_fingerprint());
        }
        Program::QosAll => {
            hash.update(b"NARF RTL8852A WMM all-AC TID0..7 optional operating recipe v1;txwd_body_v0;ach0..3_v0");
            hash.update(&identity);
            hash.update(&super::station_control::qos_all_fingerprint());
        }
        Program::FirmwareRa => {
            hash.update(
                b"NARF RTL8852A firmware RA legacy optional operating recipe v1;txwd_info0_v0",
            );
            hash.update(&identity);
            hash.update(&super::station_control::firmware_ra_fingerprint());
        }
        Program::Ht => {
            hash.update(b"NARF RTL8852A HT20 optional operating recipe v1;rx_desc_v0;bacam_v0");
            hash.update(&identity);
            hash.update(&super::station_control::ht_fingerprint());
        }
        Program::He => {
            hash.update(
                b"NARF RTL8852A HE20 optional operating recipe v1;txwd_info0_v0 DATA_ER;rx_desc_v0",
            );
            hash.update(&identity);
            hash.update(&super::station_control::he_fingerprint());
        }
        Program::Ampdu => {
            hash.update(b"NARF RTL8852A originator BA TX A-MPDU optional operating recipe v1;txwd_body3/info1/info2 v0 agg;max_tx_agg_num 128;max_amsdu 3500");
            hash.update(&identity);
            hash.update(&super::station_control::ampdu_fingerprint());
        }
    }
    hash.finalize()
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_policy_a/tests.rs"]
pub(super) mod tests;
