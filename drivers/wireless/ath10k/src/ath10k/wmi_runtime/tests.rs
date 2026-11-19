use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
fn smoke_ath10k_wmi_native_management_variants_and_bounds() -> TestResult {
    for (dialect, features, golden) in [
        (Dialect::Main, 0, MGMT_MAIN),
        (Dialect::TenOne, 1, MGMT_MAIN_EXT),
        (Dialect::TenFour, 0, MGMT_104),
        (Dialect::Tlv, 0, MGMT_TLV),
    ] {
        let wire = Wire::new(dialect);
        let mut body = golden[4..].to_vec();
        let head = body.len() - 24;
        if dialect == Dialect::Tlv {
            let mut b = Vec::new();
            b.extend_from_slice(&((44u32 << 16) | 40).to_le_bytes());
            b.extend_from_slice(&body[..head]);
            b.extend_from_slice(&((17u32 << 16) | 24).to_le_bytes());
            b.extend_from_slice(&body[head..]);
            body = b;
        }
        let parsed = wire.management(&body, features);
        let expected = (0u8..24).collect::<Vec<_>>();
        if !parsed
            .is_ok_and(|p| p.channel == 36 && p.snr == 31 && p.status == 0 && p.frame == expected)
        {
            return TestResult::Fail("native Linux management RX header layout mismatch");
        }
        let end = body.len();
        body.pop();
        if wire.management(&body, features).is_ok() {
            return TestResult::Fail("truncated management MPDU passed advertised extent");
        }
        body.push(23);
        if dialect == Dialect::Tlv {
            body.extend_from_slice(&((44u32 << 16) | 40).to_le_bytes());
            body.extend_from_slice(&golden[4..44]);
            if wire.management(&body, features).is_ok() {
                return TestResult::Fail("duplicate authority-bearing management TLV accepted");
            }
        } else {
            put(
                &mut body,
                if dialect == Dialect::TenFour { 24 } else { 20 },
                0x40,
            );
            if wire.management(&body, features).is_ok() {
                return TestResult::Fail("EXT_INFO status read past unadvertised management tail");
            }
            body.resize(end + 8, 0);
            if !wire
                .management(&body, features)
                .is_ok_and(|p| p.status == 0x40 && p.frame == expected)
            {
                return TestResult::Fail("valid native management timestamp extension rejected");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_wmi_native_management_variants_and_bounds
);
fn smoke_ath10k_wmi_scan_id_and_stop_one_native_union() -> TestResult {
    for (dialect, golden) in [
        (Dialect::Main, STOP_MAIN),
        (Dialect::TenOne, STOP_10X),
        (Dialect::TenTwo, STOP_10X),
        (Dialect::TenTwoFour, STOP_10X),
        (Dialect::TenFour, STOP_10X),
        (Dialect::Tlv, STOP_TLV),
    ] {
        let wire = Wire::new(dialect);
        if wire.stop_scan(1).as_deref() != Ok(golden)
            || wire.scan(4095, &[2412]).is_err()
            || wire.scan(0, &[2412]) != Err(Error::Exhausted)
            || wire.scan(4096, &[2412]) != Err(Error::Exhausted)
        {
            return TestResult::Fail(
                "native scan ID prefix/lifetime boundary or STOP_ONE union mismatch",
            );
        }
    }
    if validate_channels(&[2412; 65]).is_ok()
        || frequency_to_channel(5955).is_some()
        || channel_to_frequency(0).is_some()
    {
        return TestResult::Fail("scan admitted duplicate/excess/unsupported-band channel");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_wmi_scan_id_and_stop_one_native_union
);
