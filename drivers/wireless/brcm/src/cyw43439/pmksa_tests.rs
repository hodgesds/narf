// SPDX-License-Identifier: GPL-2.0-or-later
//! Firmware PMKSA/PMKID cache (`pmkid_info`), Linux brcmfmac
//! `cfg80211.c::brcmf_cfg80211_{set,del,flush}_pmksa`,
//! `brcmf_update_pmklist`, `brcmf_pmksa_v3_op` and `fwil_types.h`.
use super::*;
use crate::cyw43439::{
    fullmac_fixture::{self as fixture, Firmware},
    ioctl::Direction,
    runtime::Error as RuntimeError,
    station::pmksa::{self, Cache, Entry},
};
use narf_wireless::PmksaEntry;

fn entry(last: u8) -> Entry {
    Entry {
        bssid: [2, 1, 2, 3, 4, last],
        pmkid: [last; 16],
        ssid: Vec::new(),
    }
}

fn vectors() -> Result<(), &'static str> {
    let mut cache = Cache::default();
    cache.set(entry(1)).map_err(|_| "set")?;
    cache.set(entry(2)).map_err(|_| "set")?;
    let mut replaced = entry(1);
    replaced.pmkid = [0xee; 16];
    cache.set(replaced.clone()).map_err(|_| "replace")?;
    let list = cache.encode_list();
    if list.len() != 356
        || list[..4] != 2u32.to_le_bytes()
        || list[4..10] != entry(1).bssid
        || list[10..26] != [0xee; 16]
        || list[26..32] != entry(2).bssid
        || list[32..48] != [2; 16]
        || list[48..].iter().any(|&b| b != 0)
    {
        return Err("pmkid_info differs from brcmf_pmk_list_le");
    }
    for last in 3..=16 {
        cache.set(entry(last)).map_err(|_| "fill")?;
    }
    if cache.set(entry(17)).is_ok() || cache.entries().len() != 16 {
        return Err("17th PMKSA was not refused as BRCMF_MAXPMKID");
    }
    cache.delete(entry(1).bssid).map_err(|_| "delete")?;
    if cache.entries()[0] != entry(2) || cache.delete(entry(1).bssid).is_ok() {
        return Err("del_pmksa did not compact or accepted an absent entry");
    }
    let mut ssid = entry(9);
    ssid.ssid = b"test".to_vec();
    let op = pmksa::encode_v3(Some(&ssid), true);
    if op.len() != 1800
        || op[..8] != [3, 0, 120, 0, 1, 0, 0, 0]
        || op[8..14] != ssid.bssid
        || op[14..30] != [9; 16]
        || op[30] != 16
        || op[83] != 4
        || op[84..88] != *b"test"
        || op[116..120] != [0xff; 4]
        || pmksa::encode_v3(Some(&ssid), false)[116..120] != [0; 4]
        || pmksa::encode_v3(None, false)[..8] != [3, 0, 8, 0, 0, 0, 0, 0]
    {
        return Err("v3 operation differs from brcmf_pmk_op_v3_le");
    }
    let mut version = [0u8; 16];
    version[12] = 12;
    if pmksa::v3_from_wlc_version(&version) != Ok(false) {
        return Err("wlc_ver 12 selected PMKID v3");
    }
    version[12] = 13;
    if pmksa::v3_from_wlc_version(&version) != Ok(true)
        || pmksa::v3_from_wlc_version(&version[..13]).is_ok()
    {
        return Err("wlc_ver parsing differs from brcmf_feat_wlc_version_overrides");
    }
    Ok(())
}
fn smoke_fullmac_pmksa_list_and_v3_operation_vectors() -> TestResult {
    vectors().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/pmksa",
    smoke_fullmac_pmksa_list_and_v3_operation_vectors
);

fn pmkid_writes<const PCIE: bool>(
    station: &crate::cyw43439::station::Station<fixture::Mock<PCIE>>,
) -> Vec<Vec<u8>> {
    station.runtime.fw.iovars(Direction::Set, b"pmkid_info")
}

fn station_sync<const PCIE: bool>(major: u16) -> Result<(), &'static str> {
    let mut fw = Firmware::new();
    fw.hook = Some(alloc::boxed::Box::new(move |_, command| {
        (command.iovar() == Some(b"wlc_ver") && command.direction == Direction::Get).then(|| {
            let mut reply = vec![0; 16];
            reply[12..14].copy_from_slice(&major.to_le_bytes());
            Ok(reply)
        })
    }));
    let mut station = fixture::init_station::<PCIE>(fw)?;
    let v3 = major >= 13;
    if station.pmkid_v3() != v3 {
        return Err("wlc_ver did not select the PMKID revision");
    }
    let mut desired = Cache::default();
    desired.set(entry(1)).unwrap();
    desired.set(entry(2)).unwrap();
    fixture::ready(station.sync_pmksa(&desired))
        .ok_or("sync pended")?
        .map_err(|_| "pmkid_info sync failed")?;
    let expected: Vec<Vec<u8>> = if v3 {
        vec![
            pmksa::encode_v3(None, false),
            pmksa::encode_v3(Some(&entry(1)), true),
            pmksa::encode_v3(Some(&entry(2)), true),
        ]
    } else {
        vec![desired.encode_list()]
    };
    if pmkid_writes(&station) != expected || station.programmed_pmksa() != Some(&desired) {
        return Err("pmkid_info writes differ from Linux");
    }
    // Unchanged desired state is not reprogrammed.
    let _ = fixture::ready(station.sync_pmksa(&desired)).ok_or("sync pended")?;
    if pmkid_writes(&station).len() != expected.len() {
        return Err("unchanged PMKSA list was rewritten");
    }
    // A firmware refusal leaves the list unknown and is retried in full.
    desired.delete(entry(1).bssid).unwrap();
    let refused = RuntimeError::Firmware((-23i32) as u32);
    station.runtime.fw.hook = Some(alloc::boxed::Box::new(move |_, command| {
        (command.iovar() == Some(b"pmkid_info")).then_some(Err(refused))
    }));
    if fixture::ready(station.sync_pmksa(&desired)) != Some(Err(refused))
        || station.programmed_pmksa().is_some()
        || station.runtime.fw.failed
    {
        return Err("refused pmkid_info was not left unknown and retryable");
    }
    station.runtime.fw.hook = None;
    let before = pmkid_writes(&station).len();
    fixture::ready(station.sync_pmksa(&desired))
        .ok_or("sync pended")?
        .map_err(|_| "retry failed")?;
    let retried = &pmkid_writes(&station)[before..];
    let expected: Vec<Vec<u8>> = if v3 {
        vec![
            pmksa::encode_v3(None, false),
            pmksa::encode_v3(Some(&entry(2)), true),
        ]
    } else {
        vec![desired.encode_list()]
    };
    if retried != expected.as_slice() || station.programmed_pmksa() != Some(&desired) {
        return Err("PMKSA retry did not rewrite the full desired list");
    }
    Ok(())
}
fn smoke_fullmac_pmksa_station_v1_and_v3_reconciliation() -> TestResult {
    for result in [
        station_sync::<false>(10),
        station_sync::<true>(12),
        station_sync::<true>(13),
        station_sync::<false>(14),
    ] {
        if let Err(error) = result {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/cyw43439/pmksa",
    smoke_fullmac_pmksa_station_v1_and_v3_reconciliation
);

fn last_pmkid_info(harness: &Harness) -> Option<Vec<u8>> {
    harness
        .bus
        .firmware
        .lock()
        .control_log()
        .into_iter()
        .rev()
        .find(|(c, b)| *c == 263 && b.starts_with(b"pmkid_info\0"))
        .map(|(_, body)| body[11..].to_vec())
}

fn device_order() -> Result<(), &'static str> {
    let harness = Harness::new(true)?;
    let device = &harness.device;
    let one = PmksaEntry {
        bssid: Some(AP),
        pmkid: Some([0x5a; 16]),
        ssid: None,
    };
    if device.set_pmksa(PmksaEntry {
        bssid: None,
        ..one.clone()
    }) != Err(22)
        || device.del_pmksa(one.clone()) != Err(22)
    {
        return Err("SET without BSSID or DEL of an absent PMKSA was not -EINVAL");
    }
    device.set_pmksa(one.clone()).map_err(|_| "set_pmksa")?;
    harness.scan_and_associate(true)?;
    let log = harness.bus.firmware.lock().control_log();
    let pmkid = log
        .iter()
        .position(|(c, b)| *c == 263 && b.starts_with(b"pmkid_info\0"))
        .ok_or("PMKSA list was not programmed")?;
    let join = log
        .iter()
        .position(|(c, _)| *c == 26)
        .ok_or("join missing")?;
    let mut expected = Cache::default();
    expected
        .set(Entry {
            bssid: AP,
            pmkid: [0x5a; 16],
            ssid: Vec::new(),
        })
        .unwrap();
    if pmkid > join || log[pmkid].1[11..] != expected.encode_list()[..] {
        return Err("pmkid_info was not current before the join");
    }
    // Flush is applied by the worker path and reaches firmware as an empty list.
    device.flush_pmksa().map_err(|_| "flush")?;
    ready(device.apply_pmksa())?;
    if last_pmkid_info(&harness) != Some(Cache::default().encode_list()) {
        return Err("flush_pmksa did not clear the firmware list");
    }
    Ok(())
}
fn smoke_cyw_pmksa_device_programs_before_join_and_flushes() -> TestResult {
    device_order().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/pmksa",
    smoke_cyw_pmksa_device_programs_before_join_and_flushes
);
