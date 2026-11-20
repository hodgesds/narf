//! Offline tests for the host-owned group-addressed replay check
//! (`dp_group_pn`) and the spectral applicability gate (`hw::spectral`).
//!
//! Oracles: the IV layouts are written out from IEEE 802.11-2020 Figure
//! 12-17 (CCMP header), Figure 12-25 (GCMP header) and Figure 12-7 (TKIP
//! Extended IV); the replay rules from mac80211 `wpa.c`
//! (`ieee80211_crypto_ccmp_decrypt`: `memcmp(pn, rx_pn) <= 0` is a replay)
//! and `tkip.c` (`ieee80211_tkip_decrypt_data`'s zero-RSC first-frame
//! exception); the spectral values from Linux `core.c::ath11k_hw_params`.
//! Not architecture-gated: these are pure byte/state checks.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::dp_group_pn::{self as gpn, GroupPnError, GroupRxKey};
use super::dp_ring::enc;
use super::hw::{spectral_supported, HwRev};

macro_rules! check {
    ($c:expr, $m:literal) => {
        if !$c {
            return TestResult::Fail($m);
        }
    };
}

const BSSID: [u8; 6] = [0x02, 0, 0, 0, 0, 0xaa];
const SRC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xbb];

/// FromDS | Protected group data header; `qos` adds a QoS Data subtype
/// with TID `tid` (QoS Control after Sequence Control).
fn hdr(qos: Option<u8>) -> Vec<u8> {
    let fc0 = if qos.is_some() { 0x88 } else { 0x08 };
    let mut h = vec![fc0, 0x42, 0, 0];
    h.extend_from_slice(&[0xff; 6]);
    h.extend_from_slice(&BSSID);
    h.extend_from_slice(&SRC);
    h.extend_from_slice(&[0x30, 0x00]);
    if let Some(tid) = qos {
        h.extend_from_slice(&[tid, 0]);
    }
    h
}

fn smoke_ath11k_group_pn_parse() -> TestResult {
    // CCMP: PN0 PN1 rsvd KeyID|ExtIV PN2 PN3 PN4 PN5.
    let mut f = hdr(None);
    f.extend_from_slice(&[0x06, 0x05, 0x00, 0x60, 0x04, 0x03, 0x02, 0x01]);
    check!(
        gpn::parse(&f, enc::CCMP_128)
            == Ok(gpn::GroupPn {
                key_idx: 1,
                pn: 0x0102_0304_0506,
                queue: 0,
            }),
        "CCMP PN / Key ID 1 / non-QoS queue 0"
    );
    // GCMP-256 shares the CCMP header layout (gcmp_hdr2pn).
    check!(
        gpn::parse(&f, enc::AES_GCMP_256).map(|p| p.pn) == Ok(0x0102_0304_0506),
        "GCMP PN"
    );
    // QoS data: security_idx = TID.
    let mut q = hdr(Some(5));
    q.extend_from_slice(&[0x01, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x00]);
    check!(
        gpn::parse(&q, enc::CCMP_256)
            == Ok(gpn::GroupPn {
                key_idx: 2,
                pn: 1,
                queue: 5,
            }),
        "QoS TID selects the replay counter"
    );
    // TKIP: TSC1 WEPSeed TSC0 KeyID|ExtIV TSC2 TSC3 TSC4 TSC5.
    let mut t = hdr(None);
    t.extend_from_slice(&[0x12, 0x32, 0x34, 0x20, 0x01, 0x00, 0x00, 0x00]);
    check!(
        gpn::parse(&t, enc::TKIP_MIC).map(|p| (p.key_idx, p.pn)) == Ok((0, 0x0001_1234)),
        "TKIP TSC = iv32 << 16 | iv16"
    );
    // Missing Ext IV bit and a truncated IV are refused.
    let mut n = hdr(None);
    n.extend_from_slice(&[1, 0, 0, 0x40, 0, 0, 0, 0]);
    check!(
        gpn::parse(&n, enc::CCMP_128) == Err(GroupPnError::NoExtIv),
        "Ext IV required"
    );
    check!(
        gpn::parse(&f[..f.len() - 1], enc::CCMP_128) == Err(GroupPnError::Short),
        "short IV"
    );
    check!(
        !gpn::has_replay_counter(enc::OPEN) && !gpn::has_replay_counter(enc::WEP_104),
        "no counter without TKIP/CCMP/GCMP"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_group_pn_parse);

fn smoke_ath11k_group_pn_replay_rules() -> TestResult {
    // CCMP with RSC 10: 10 replays, 11 passes, 11 again replays; TIDs are
    // independent.
    let mut k = GroupRxKey::new(3, 1, false, 10);
    check!(k.check(10, 0) == Err(GroupPnError::Replay), "PN == RSC");
    check!(
        k.check(11, 0).is_ok() && k.counter(0) == Some(11),
        "PN > RSC"
    );
    check!(k.check(11, 0) == Err(GroupPnError::Replay), "same PN");
    check!(k.check(9, 0) == Err(GroupPnError::Replay), "older PN");
    check!(
        k.check(10, 6) == Err(GroupPnError::Replay),
        "TID 6 still at the RSC"
    );
    check!(
        k.check(12, 6).is_ok() && k.counter(0) == Some(11),
        "per-TID counters"
    );
    // CCMP with RSC 0: PN 0 is a replay (memcmp == 0).
    let mut z = GroupRxKey::new(3, 1, false, 0);
    check!(z.check(0, 0) == Err(GroupPnError::Replay), "CCMP PN 0");
    // TKIP with RSC 0: the very first TSC 0 is accepted once.
    let mut t = GroupRxKey::new(3, 2, true, 0);
    check!(t.check(0, 0).is_ok(), "TKIP first frame at TSC 0");
    check!(
        t.check(0, 0) == Err(GroupPnError::Replay),
        "TKIP TSC 0 again"
    );
    // TKIP with a non-zero RSC: equal is a replay.
    let mut r = GroupRxKey::new(3, 2, true, 7);
    check!(
        r.check(7, 0) == Err(GroupPnError::Replay),
        "TKIP TSC == RSC"
    );
    check!(r.check(8, 0).is_ok(), "TKIP TSC > RSC");
    // The RSC is a 48-bit counter.
    let w = GroupRxKey::new(3, 1, false, u64::MAX);
    check!(w.counter(0) == Some(0xffff_ffff_ffff), "48-bit RSC");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_group_pn_replay_rules
);

fn smoke_ath11k_spectral_inapplicable_on_admitted_pci() -> TestResult {
    // ath11k_spectral_init: no FFT size → no DBRing, relay or WMI.
    for rev in [
        HwRev::Qca6390Hw20,
        HwRev::Wcn6855Hw20,
        HwRev::Wcn6855Hw21,
        HwRev::Qca2066Hw21,
        HwRev::Qca6698aqHw21,
    ] {
        let s = rev.spectral();
        check!(
            s.fft_sz == 0 && s.max_fft_bins == 0 && s.fft_hdr_len == 0,
            "admitted PCI profile defines no FFT report"
        );
        check!(
            !spectral_supported(rev, true) && !spectral_supported(rev, false),
            "spectral never initialised on an admitted profile"
        );
    }
    let q = HwRev::Qcn9074Hw10.spectral();
    check!(
        q.fft_sz == 2 && q.summary_pad_sz == 16 && q.fft_hdr_len == 24 && q.max_fft_bins == 1024,
        "QCN9074 spectral block"
    );
    check!(
        spectral_supported(HwRev::Qcn9074Hw10, true)
            && !spectral_supported(HwRev::Qcn9074Hw10, false),
        "QCN9074 additionally needs FREQINFO_IN_METADATA"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_spectral_inapplicable_on_admitted_pci
);
