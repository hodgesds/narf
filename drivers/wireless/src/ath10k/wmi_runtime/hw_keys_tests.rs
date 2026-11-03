//! Native wire cases for station hardware keys (unexecuted until the
//! coordinated native run).
use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
use zeroize::Zeroizing;

const BSSID: [u8; 6] = [2, 0x11, 0x22, 0x33, 0x44, 0x55];

fn key(pairwise: bool, key_id: u8) -> KeyInstall {
    KeyInstall {
        pairwise,
        key_id,
        material: Zeroizing::new(core::array::from_fn(|i| 0xa0 + i as u8)),
        token: 7,
    }
}
fn word(v: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(v[at..at + 4].try_into().unwrap())
}

/// wmi.c `ath10k_wmi_op_gen_vdev_install_key` for every struct dialect:
/// command ID, BSSID, key index, PAIRWISE/GROUP, AES_CCM, zero RSC/TSC and
/// the 16-octet key after the 92-octet struct.
fn smoke_ath10k_hw_keys_install_struct_dialects() -> TestResult {
    for (dialect, id) in [
        (Dialect::Main, 0x5009),
        (Dialect::TenOne, 0x901b),
        (Dialect::TenTwo, 0x901a),
        (Dialect::TenTwoFour, 0x901a),
        (Dialect::TenFour, 0x901d),
    ] {
        for (pairwise, idx) in [(true, 0u8), (false, 1), (false, 2)] {
            let Ok(c) = install(dialect, BSSID, &key(pairwise, idx)) else {
                return TestResult::Fail("install refused");
            };
            if c.len() != 4 + 92 + 16
                || word(&c, 0) != id
                || word(&c, 4) != 0
                || c[8..14] != BSSID
                || word(&c, 16) != u32::from(idx)
                || word(&c, 20) != u32::from(!pairwise)
                || word(&c, 24) != 4
                || c[28..84].iter().any(|b| *b != 0)
                || word(&c, 84) != 16
                || word(&c, 88) != 0
                || word(&c, 92) != 0
                || c[96..112] != *key(pairwise, idx).material
            {
                return TestResult::Fail("struct install layout");
            }
        }
    }
    if install(Dialect::Main, BSSID, &key(true, 1)).is_ok()
        || install(Dialect::Main, [0xff; 6], &key(false, 1)).is_ok()
        || install(Dialect::Main, BSSID, &key(false, 4)).is_ok()
    {
        return TestResult::Fail("invalid key index or peer accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/hw_keys",
    smoke_ath10k_hw_keys_install_struct_dialects
);

/// wmi-tlv.c `ath10k_wmi_tlv_op_gen_vdev_install_key`: tag 96 around the
/// same struct, then an ARRAY_BYTE (17) TLV of the 4-aligned key.
fn smoke_ath10k_hw_keys_install_tlv() -> TestResult {
    let Ok(c) = install(Dialect::Tlv, BSSID, &key(false, 2)) else {
        return TestResult::Fail("TLV install refused");
    };
    if c.len() != 4 + 4 + 92 + 4 + 16
        || word(&c, 0) != 0x5009
        || word(&c, 4) != (96 << 16) | 92
        || c[12..18] != BSSID
        || word(&c, 20) != 2
        || word(&c, 24) != 1
        || word(&c, 28) != 4
        || word(&c, 88) != 16
        || word(&c, 100) != (17 << 16) | 16
        || c[104..120] != *key(false, 2).material
    {
        return TestResult::Fail("TLV install layout");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/hw_keys",
    smoke_ath10k_hw_keys_install_tlv
);

/// mac.c `ath10k_peer_assoc_h_crypto` `peer_flags->pmf`: main/10.2/10.4
/// 0x10000000, TLV 0x08000000, none for 10.1; only with MFP firmware and a
/// PMF association.
fn smoke_ath10k_hw_keys_peer_pmf_flag_map() -> TestResult {
    let mfp = 1 << 12;
    if management_offload(Dialect::Main, mfp, true) != Some(0x1000_0000)
        || management_offload(Dialect::TenTwo, mfp, true) != Some(0x1000_0000)
        || management_offload(Dialect::TenFour, mfp, true) != Some(0x1000_0000)
        || management_offload(Dialect::Tlv, mfp, true) != Some(0x0800_0000)
        || management_offload(Dialect::TenOne, mfp, true).is_some()
        || management_offload(Dialect::Tlv, 0, true).is_some()
        || management_offload(Dialect::Tlv, mfp, false).is_some()
    {
        return TestResult::Fail("PMF peer flag map");
    }
    for (dialect, at) in [(Dialect::Main, 24), (Dialect::Tlv, 28)] {
        let mut command = alloc::vec![0u8; 64];
        command[at..at + 4].copy_from_slice(&5u32.to_le_bytes());
        let flag = peer_pmf_flag(dialect).unwrap();
        if mark_peer_pmf(dialect, &mut command, flag).is_err() || word(&command, at) != 5 | flag {
            return TestResult::Fail("peer_flags word");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/hw_keys",
    smoke_ath10k_hw_keys_peer_pmf_flag_map
);

/// htt.h `struct htt_security_indication`: AES-CCMP type 6 with the
/// unicast bit and LE peer ID; other types confirm nothing.
fn smoke_ath10k_hw_keys_security_indication() -> TestResult {
    let mut m = alloc::vec![0u8; 28];
    m[0] = SECURITY_INDICATION;
    m[1] = 0x86;
    m[2..4].copy_from_slice(&0x123u16.to_le_bytes());
    if security_indication(&m) != Some((0x123, true)) {
        return TestResult::Fail("unicast CCMP indication");
    }
    m[1] = 6;
    if security_indication(&m) != Some((0x123, false)) {
        return TestResult::Fail("group CCMP indication");
    }
    m[1] = 4;
    if security_indication(&m).is_some() || security_indication(&m[..3]).is_some() {
        return TestResult::Fail("TKIP or short indication confirmed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/hw_keys",
    smoke_ath10k_hw_keys_security_indication
);
