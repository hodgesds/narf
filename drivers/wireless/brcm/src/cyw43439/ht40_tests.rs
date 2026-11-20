//! Native BCDC occupied40MHz admission. A fixture reply is not a claim that
//! actual CYW43439 firmware/radio supports40MHz;20-only replies retain HT20.
use super::*;
use crate::cyw43439::phy_fixture::{Wide, WideFault};
use narf_wireless::reg::{db::Database, RegFlags, RegRule, RegulatoryDomain};

fn profile(above: bool, fault: WideFault) -> Wide {
    Wide {
        caps: [3, 0],
        inventory: vec![if above { 0x1808 } else { 0x1904 }],
        operating: if above { 0x1808 } else { 0x1904 },
        secondary: if above { 10 } else { 2 },
        fault,
    }
}
fn domain() -> RegulatoryDomain {
    let mut domain = firmware::domain();
    domain.rules[0].max_bandwidth_mhz = 40;
    domain
}
fn restricted(kind: u8) -> RegulatoryDomain {
    let mut policy = domain();
    policy.rules.push(RegRule {
        freq_start_mhz: 2456,
        freq_end_mhz: 2458,
        max_bandwidth_mhz: if kind == 4 { 20 } else { 40 },
        max_power_dbm: if kind == 5 { 10 } else { 17 },
        flags: match kind {
            0 => RegFlags::NO_IR,
            1 => RegFlags::DFS,
            2 => RegFlags::INDOOR_ONLY,
            3 => RegFlags::from_bits_retain(16),
            _ => RegFlags::empty(),
        },
    });
    policy
}
fn packet() -> Vec<u8> {
    let mut out = vec![0x4a; 60];
    out[..6].copy_from_slice(&AP);
    out[6..12].copy_from_slice(&OWN);
    out[12..14].copy_from_slice(&[8, 0]);
    out
}
fn native() -> Result<(), &'static str> {
    for above in [true, false] {
        let h = Harness::new_wide(false, None, false, profile(above, WideFault::None))?;
        if h.device
            .phy_capabilities(2400)
            .is_none_or(|c| c.ht[0] != 98 || c.ht[3] != 255)
            || h.device.phy_capabilities(5000).is_some()
        {
            return Err("native per-band40/SGI40 capability missing or aliased");
        }
        h.scan_and_associate(false)?;
        let commands = h.bus.firmware.lock().mfp_commands();
        let width = commands
            .iter()
            .position(|(id, b)| {
                *id == 263 && b.as_slice() == b"bw_cap\x00\x02\x00\x00\x00\x03\x00\x00\x00"
            })
            .ok_or("native40MHz cap publication missing")?;
        let join = commands
            .iter()
            .position(|(id, _)| *id == 26)
            .ok_or("native wider join missing")?;
        if width >= join
            || commands[join].1[48..50] != profile(above, WideFault::None).operating.to_le_bytes()
            || {
                let state = h.device.state.try_lock().unwrap();
                !state.station.ht_connection() || state.station.channel_width_mhz() != Some(40)
            }
        {
            return Err("wider cap/chanspec/actual HT receipt did not precede port");
        }
        ready(h.device.disassociate())?.map_err(|_| "wide native teardown")?;
        if h.device.link_up() || {
            let state = h.device.state.try_lock().unwrap();
            state.station.ht_connection() || state.station.channel_width_mhz().is_some()
        } {
            return Err("wide teardown retained port/PHY");
        }
    }
    for (secure, pmf) in [(false, false), (true, false), (true, true)] {
        composition_native(
            Harness::new_wide(secure, None, pmf, profile(true, WideFault::None))?,
            secure,
            pmf,
            true,
        )?;
    }
    Ok(())
}
fn smoke_cyw_firmware_qualified_ht40_sgi40_native_open_wpa2_pmf_dhcp_ip() -> TestResult {
    native().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ht40",
    smoke_cyw_firmware_qualified_ht40_sgi40_native_open_wpa2_pmf_dhcp_ip
);

fn fallback() -> Result<(), &'static str> {
    for variant in 0..4 {
        let mut wide = profile(true, WideFault::None);
        if variant == 0 {
            wide.caps[0] = 1;
        }
        if variant == 1 {
            wide.inventory.clear();
        }
        let db = Arc::new(Database::new());
        let mut policy = domain();
        if variant == 2 {
            policy.rules[0].max_bandwidth_mhz = 20;
        }
        if variant == 3 {
            policy = restricted(0);
        }
        db.install(policy);
        let h = Harness::new_wide(true, Some(db), false, wide)?;
        h.scan_and_associate(true)?;
        let commands = h.bus.firmware.lock().mfp_commands();
        if commands
            .iter()
            .any(|(id, b)| *id == 263 && b.starts_with(b"bw_cap\0") && b[11..15] == [3, 0, 0, 0])
            || commands
                .iter()
                .find(|(id, _)| *id == 26)
                .is_none_or(|(_, b)| b[48..50] != [6, 16])
            || {
                let state = h.device.state.try_lock().unwrap();
                !state.station.ht_connection() || state.station.channel_width_mhz() != Some(20)
            }
        {
            return Err("unqualified40MHz did not retain genuine constrained HT20");
        }
        if variant < 2
            && h.device
                .phy_capabilities(2400)
                .is_none_or(|c| c.ht[0] & 66 != 0)
        {
            return Err("20-only firmware/inventory advertised40MHz");
        }
    }
    let db = Arc::new(Database::new());
    db.install(restricted(5));
    let h = Harness::new_wide(true, Some(db), false, profile(true, WideFault::None))?;
    h.scan_and_associate(true)?;
    if h.bus.firmware.lock().qtxpowers().last().map(Vec::as_slice) != Some(&[40, 0, 0, 0][..]) {
        return Err("secondary-only power ceiling was not applied to40MHz");
    }
    Ok(())
}
fn smoke_cyw_ht40_capability_inventory_policy_fallback_and_secondary_power() -> TestResult {
    fallback().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ht40",
    smoke_cyw_ht40_capability_inventory_policy_fallback_and_secondary_power
);

fn denials() -> Result<(), &'static str> {
    if Harness::new_wide(true, None, false, profile(true, WideFault::Inventory)).is_ok() {
        return Err("malformed native chanspec inventory admitted");
    }
    for fault in [
        WideFault::CurrentWidth,
        WideFault::ResponseWidth,
        WideFault::ResponseSecondary,
        WideFault::RequestWidth,
        WideFault::CapReadback,
        WideFault::ChannelRestricted,
    ] {
        let h = Harness::new_wide(true, None, false, profile(true, fault))?;
        if h.scan_and_associate(true).is_ok()
            || h.device.link_up()
            || h.device.connected_bssid().is_some()
        {
            return Err("incorrect current/request/response width or cap readback opened port");
        }
        h.device.drain();
        if h.device.link_up() {
            return Err("late width receipt revived terminal owner");
        }
    }
    Ok(())
}
fn smoke_cyw_ht40_native_inventory_width_request_response_denials() -> TestResult {
    denials().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ht40",
    smoke_cyw_ht40_native_inventory_width_request_response_denials
);

fn live() -> Result<(), &'static str> {
    for kind in 0..7 {
        let db = Arc::new(Database::new());
        db.install(domain());
        let h = Harness::new_wide(
            true,
            Some(db.clone()),
            false,
            profile(true, WideFault::None),
        )?;
        h.scan_and_associate(true)?;
        let sent = h.bus.firmware.lock().sent_data();
        h.device
            .enqueue(&packet())
            .map_err(|_| "queued40MHz data fixture")?;
        if kind == 6 {
            db.clear();
        } else {
            db.install(restricted(kind));
        }
        h.device.drain();
        db.install(domain());
        h.device.drain();
        if h.device.link_up()
            || h.device.connected_bssid().is_some()
            || h.device.enqueue(&packet()).is_ok()
            || h.bus.firmware.lock().sent_data() != sent
        {
            return Err("secondary policy loss/reinstall retained wide queued TX or port");
        }
    }
    let db = Arc::new(Database::new());
    db.install(domain());
    let h = Harness::new_wide(
        true,
        Some(db.clone()),
        false,
        profile(true, WideFault::HoldResponse),
    )?;
    h.scan()?;
    {
        let mut future = pin!(h.device.associate(Harness::request(true)));
        let mut cx = Context::from_waker(Waker::noop());
        let mut held = false;
        for _ in 0..256 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return Err("native wider response did not wait");
            }
            if h.bus
                .firmware
                .lock()
                .mfp_commands()
                .iter()
                .any(|(id, b)| *id == 262 && b.starts_with(b"assoc_resp_ies\0"))
            {
                held = true;
                break;
            }
        }
        if !held {
            return Err("native wider response receipt was not reached");
        }
        db.install(restricted(0));
        h.bus.firmware.lock().release_wide();
        if !matches!(future.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
            return Err("secondary revocation did not reject resumed native wait");
        }
    }
    db.install(domain());
    h.device.drain();
    if h.device.link_up() || h.device.connected_bssid().is_some() {
        return Err("resumed wider receipt bypassed current secondary authority");
    }
    Ok(())
}
fn smoke_cyw_ht40_current_secondary_policy_closes_data_and_awaited_receipt() -> TestResult {
    live().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ht40",
    smoke_cyw_ht40_current_secondary_policy_closes_data_and_awaited_receipt
);

fn cancelled() -> Result<(), &'static str> {
    for fault in [WideFault::HoldCap, WideFault::HoldResponse] {
        let h = Harness::new_wide(true, None, false, profile(true, fault))?;
        if h.scan_and_associate(true).is_ok() {
            return Err("held native wider receipt opened port");
        }
        h.bus.firmware.lock().release_wide();
        h.device.drain();
        if h.device.link_up()
            || h.device.connected_bssid().is_some()
            || h.scan_and_associate(true).is_ok()
        {
            return Err("cancelled wider owner reused late native receipt");
        }
    }
    Ok(())
}
fn smoke_cyw_ht40_cancelled_width_or_phy_receipt_closes_owner() -> TestResult {
    cancelled().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/cyw43439/ht40",
    smoke_cyw_ht40_cancelled_width_or_phy_receipt_closes_owner
);
