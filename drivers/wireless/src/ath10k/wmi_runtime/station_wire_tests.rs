use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
include!("station_wire_golden.rs");
fn smoke_ath10k_wmi_station_prepare_all_native_dialects() -> TestResult {
    let p = Permission {
        center: 2412,
        secondary: None,
        width80: false,
        center2: None,
        factory: crate::ath10k::regulatory::Factory::from_eeprom(0x64).unwrap(),
        country: *b"US",
        frequency: 2412,
        half_dbm: 34,
        radar: 0,
        hint: None,
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
        if w.domain(&p).as_deref() != Ok(rd)
            || w.power(&p).as_deref() != Ok(power)
            || w.start_station(0, &p, 100, 1).as_deref() != Ok(start)
            || w.peer(0, [2, 8, 9, 10, 11, 12]).as_deref() != Ok(peer)
        {
            return TestResult::Fail(
                "native regulatory/power/STA-start/peer differs from independent Linux generator",
            );
        }
        let mut ack = alloc::vec![0;16];
        if dialect == Dialect::Tlv {
            ack.splice(..0, ((40u32 << 16) | 16).to_le_bytes());
        }
        if w.start_response(0, &ack) != Ok(Some(())) {
            return TestResult::Fail("valid native VDEV_START_RESPONSE refused");
        }
        let at = usize::from(dialect == Dialect::Tlv) * 4;
        put(&mut ack, at, 1);
        if w.start_response(0, &ack) != Ok(None) {
            return TestResult::Fail("another vdev START satisfied owner");
        }
        put(&mut ack, at, 0);
        put(&mut ack, at + 12, 3);
        if w.start_response(0, &ack) != Err(Error::Firmware(3)) {
            return TestResult::Fail("failed START opened vdev owner");
        }
        ack.pop();
        if w.start_response(0, &ack).is_ok() {
            return TestResult::Fail("short START status accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi-runtime",
    smoke_ath10k_wmi_station_prepare_all_native_dialects
);

/// Linux wmi.c `ath10k_wmi_put_wmi_channel` for a station VDEV_START in
/// every dialect: VHT160 keeps the primary80 half in band_center_freq1 and
/// puts the whole 160 MHz center in band_center_freq2; VHT80_80 puts the
/// other segment. `WMI_CHAN_FLAG_DFS_CFREQ2` follows the radar state of
/// `center2 - 10`; no station start carries `WMI_CHAN_FLAG_DFS`.
fn smoke_ath10k_vht160_station_start_channel_centers_and_dfs_cfreq2() -> TestResult {
    use crate::ath10k::wmi_runtime::beacon_hints::bit;
    let receipt = |frequency: u16, center: u16, center2: u16, radar: &[u16]| Permission {
        center,
        secondary: Some(frequency + 20),
        width80: true,
        center2: Some(center2),
        factory: crate::ath10k::regulatory::Factory::from_eeprom(0x8348).unwrap(),
        country: *b"US",
        frequency,
        half_dbm: 46,
        radar: radar.iter().map(|f| bit(*f).unwrap()).fold(0, |a, b| a | b),
        hint: None,
    };
    let radar = [5260, 5280, 5300, 5320];
    let upper = [5500, 5520, 5540, 5560, 5580, 5600, 5620, 5640];
    // (receipt, band_center_freq1, band_center_freq2, DFS_CFREQ2)
    let cases = [
        // ch36 primary: other half ch52-64 is radar (5280 = 5290 - 10).
        (receipt(5180, 5210, 5290, &radar), 5210, 5250, true),
        // ch60 primary: other half ch36-48 is not radar.
        (receipt(5300, 5290, 5210, &radar), 5290, 5250, false),
        // ch116 primary on the all-radar ch100-128 span.
        (receipt(5580, 5610, 5530, &upper), 5610, 5570, true),
        // Discontiguous 80+80 keeps its separate segment center.
        (receipt(5180, 5210, 5775, &[]), 5210, 5775, false),
    ];
    for dialect in [
        Dialect::Main,
        Dialect::TenOne,
        Dialect::TenTwo,
        Dialect::TenTwoFour,
        Dialect::TenFour,
        Dialect::Tlv,
    ] {
        let chan = if dialect == Dialect::Tlv { 84 } else { 4 };
        for (p, cfreq1, cfreq2, dfs) in &cases {
            let Ok(start) = Wire::new(dialect).start_station(0, p, 100, 1) else {
                return TestResult::Fail("VHT160 station START refused");
            };
            let at =
                |o: usize| u32::from_le_bytes(start[chan + o..chan + o + 4].try_into().unwrap());
            if at(0) != u32::from(p.frequency)
                || at(4) != *cfreq1
                || at(8) != *cfreq2
                || at(12) & (1 << 15) != if *dfs { 1 << 15 } else { 0 }
                || at(12) & (1 << 10) != 0
                || super::start_center2(p) != (*cfreq2, if *dfs { 1 << 15 } else { 0 })
            {
                return TestResult::Fail("VHT160/80+80 START centers or DFS_CFREQ2");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/vht160",
    smoke_ath10k_vht160_station_start_channel_centers_and_dfs_cfreq2
);
