use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};
fn smoke_ath10k_legacy_wmi_ids_match_linux_main_enum() -> TestResult {
    // Independent enum oracle compiles local Linux's entire wmi_cmd_group,
    // wmi_cmd_id, wmi_event_id and wmi_vdev_param declarations in C.
    for (kind, raw) in [
        (WmiCmdId::Init, 1),
        (WmiCmdId::StartScan, 0x3001),
        (WmiCmdId::StopScan, 0x3002),
        (WmiCmdId::PdevSetParam, 0x4003),
        (WmiCmdId::PdevSetChannel, 0x4002),
        (WmiCmdId::VdevCreate, 0x5001),
        (WmiCmdId::VdevDelete, 0x5002),
        (WmiCmdId::VdevStart, 0x5003),
        (WmiCmdId::PeerCreate, 0x6001),
        (WmiCmdId::VdevSetParam, 0x5008),
    ] {
        if kind as u32 != raw || WmiCmdId::from_raw(raw) != Some(kind) {
            return TestResult::Fail("legacy MAIN command enum differs from native C oracle");
        }
    }
    for raw in [0x3000, 0x4000, 0x5000, 0x6000] {
        if WmiCmdId::from_raw(raw).is_some() {
            return TestResult::Fail("reserved zero-index group base classified as a command");
        }
    }
    if WmiEventId::from_raw(0x3001) != Some(WmiEventId::Scan)
        || WmiEventId::from_raw(0x1d003) != Some(WmiEventId::DebugMessage)
        || vdev_param::RTS_THRESHOLD != 1
        || vdev_param::FRAGMENTATION_THRESHOLD != 2
        || vdev_param::BEACON_INTERVAL != 3
        || vdev_param::DTIM_PERIOD != 13
    {
        return TestResult::Fail("MAIN event/parameter IDs alias another firmware operation");
    }
    let frame = build_vdev_set_param(1, vdev_param::BEACON_INTERVAL, 100);
    if frame != [8, 0x50, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 100, 0, 0, 0] {
        return TestResult::Fail("legacy helper serializes start instead of VDEV_SET_PARAM");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi",
    smoke_ath10k_legacy_wmi_ids_match_linux_main_enum
);
