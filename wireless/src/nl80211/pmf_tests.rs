//! Required-PMF WPA2 admission through the real CONNECT parser.
use super::*;

// IEEE RSNE: CCMP group/pairwise, PSK, MFPC|MFPR, zero PMKIDs, BIP-CMAC128.
const REQUIRED: [u8; 28] = [
    48, 26, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, 192, 0, 0, 0, 0, 15,
    172, 6,
];

fn connect(ie: Option<&[u8]>, mfp: Option<u32>) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_attr(&mut bytes, 52, b"pmf-test");
    push_attr(&mut bytes, 254, &[0x42; 32]);
    for (kind, value) in [
        (75, 2u32),
        (76, 0x000fac02),
        (73, 0x000fac04),
        (74, 0x000fac04),
    ] {
        push_attr(&mut bytes, kind, &value.to_ne_bytes());
    }
    if let Some(mode) = mfp {
        push_attr(&mut bytes, 66, &mode.to_ne_bytes());
    }
    if let Some(ie) = ie {
        push_attr(&mut bytes, 42, ie);
    }
    bytes
}

fn check() -> Result<(), &'static str> {
    let supported = ConnectCaps {
        psk_offload: true,
        psk_mfp_offload: true,
        cipher_suites: &[crate::CIPHER_SUITE_CCMP, crate::CIPHER_SUITE_AES_CMAC],
        ..ConnectCaps::default()
    };
    let parse =
        |bytes: &[u8], caps| parse_operation_caps(CONNECT, &attributes(bytes).unwrap(), caps, 0);
    for length in [22, 24, 28] {
        let mut ie = REQUIRED[..length].to_vec();
        ie[1] = (length - 2) as u8;
        if !matches!(
            parse(&connect(Some(&ie), Some(1)), supported),
            Ok(Operation::Connect { cred: Credential::Psk(ref pmk), ie: ref actual, .. })
                if **pmk == [0x42; 32] && *actual == ie
        ) {
            return Err("required/default BIP PMF did not preserve the exact CONNECT request");
        }
    }
    let unsupported = ConnectCaps {
        psk_mfp_offload: false,
        ..supported
    };
    if !matches!(
        parse(&connect(Some(&REQUIRED), Some(1)), unsupported),
        Err(EOPNOTSUPP)
    ) {
        return Err("BIP cipher advertisement fabricated required-PMF handshake support");
    }
    let stub = InterfaceStub {
        name: "pmf-default-closed",
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    };
    if ConnectCaps::of(&stub).psk_mfp_offload {
        return Err("required-PMF offload default was not closed");
    }
    if !matches!(
        parse(&connect(None, None), unsupported),
        Ok(Operation::Connect { .. })
    ) {
        return Err("ordinary WPA2 CONNECT regressed");
    }
    for (ie, mode) in [
        (None, Some(1)),
        (Some(&REQUIRED[..]), Some(0)),
        (Some(&REQUIRED[..]), None),
        (Some(&REQUIRED[..]), Some(2)),
    ] {
        if parse(&connect(ie, mode), supported).is_ok() {
            return Err("required/optional MFP attributes silently downgraded");
        }
    }
    for offset in [2, 13, 19, 20, 27] {
        let mut ie = REQUIRED;
        ie[offset] = match offset {
            20 => 128,
            _ => ie[offset] ^ 1,
        };
        if parse(&connect(Some(&ie), Some(1)), supported).is_ok() {
            return Err("unsupported required-PMF version/suite/capability accepted");
        }
    }
    let mut missing_mfpc = REQUIRED;
    missing_mfpc[20] = 64;
    if parse(&connect(Some(&missing_mfpc), Some(1)), supported).is_ok() {
        return Err("MFPR without MFPC accepted");
    }
    let mut ocv = REQUIRED;
    ocv[21] = 64;
    if parse(&connect(Some(&ocv), Some(1)), supported).is_ok() {
        return Err("required OCV promise silently discarded by PMF offload");
    }
    for length in 0..REQUIRED.len() {
        if parse(&connect(Some(&REQUIRED[..length]), Some(1)), supported).is_ok() {
            return Err("truncated required-PMF RSNE accepted");
        }
    }
    let mut duplicate = REQUIRED.to_vec();
    duplicate.extend_from_slice(&REQUIRED);
    let mut trailing = REQUIRED.to_vec();
    trailing[1] += 1;
    trailing.push(0);
    for ie in [duplicate, trailing, alloc::vec![0; 2050]] {
        if parse(&connect(Some(&ie), Some(1)), supported).is_ok() {
            return Err("duplicate/trailing/unbounded required-PMF IE accepted");
        }
    }
    Ok(())
}

fn smoke_nl80211_required_pmf_psk_capability_and_rsne_admission() -> TestResult {
    check().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/nl80211",
    smoke_nl80211_required_pmf_psk_capability_and_rsne_admission
);
