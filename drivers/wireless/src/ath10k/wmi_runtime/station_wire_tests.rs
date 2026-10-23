use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("station_wire_golden.rs");
fn smoke_ath10k_wmi_station_prepare_all_native_dialects() -> TestResult {
    let p = Permission {
        factory: crate::ath10k::regulatory::Factory::from_eeprom(0x64).unwrap(),
        country: *b"US",
        frequency: 2412,
        half_dbm: 34,
    };
    for (dialect, rd, power, start, peer) in [
        (Dialect::Main, RD_MAIN, POWER_MAIN, START_MAIN, PEER_MAIN),
        (Dialect::TenOne, RD_10X, POWER_10X, START_10X, PEER_10X),
        (Dialect::TenTwo, RD_102, POWER_102, START_102, PEER_102),
        (Dialect::TenTwoFour, RD_102, POWER_102, START_102, PEER_102),
        (Dialect::TenFour, RD_104, POWER_104, START_104, PEER_104),
        (Dialect::Tlv, RD_TLV, POWER_TLV, START_TLV, PEER_TLV),
    ] {
        let w = Wire::new(dialect);
        if w.domain(p).as_deref() != Ok(rd)
            || w.power(p).as_deref() != Ok(power)
            || w.start_station(p, 100, 1).as_deref() != Ok(start)
            || w.peer([2, 8, 9, 10, 11, 12]).as_deref() != Ok(peer)
        {
            return TestResult::Fail(
                "native regulatory/power/STA-start/peer differs from independent Linux generator",
            );
        }
        let mut ack = alloc::vec![0;16];
        if dialect == Dialect::Tlv {
            ack.splice(..0, ((40u32 << 16) | 16).to_le_bytes());
        }
        if w.start_response(&ack) != Ok(Some(())) {
            return TestResult::Fail("valid native VDEV_START_RESPONSE refused");
        }
        let at = usize::from(dialect == Dialect::Tlv) * 4;
        put(&mut ack, at, 1);
        if w.start_response(&ack) != Ok(None) {
            return TestResult::Fail("another vdev START satisfied owner");
        }
        put(&mut ack, at, 0);
        put(&mut ack, at + 12, 3);
        if w.start_response(&ack) != Err(Error::Firmware(3)) {
            return TestResult::Fail("failed START opened vdev owner");
        }
        ack.pop();
        if w.start_response(&ack).is_ok() {
            return TestResult::Fail("short START status accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_wmi_station_prepare_all_native_dialects
);
