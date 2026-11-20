//! BCM43602 firmware-owned HT40/SGI40 over actual CR4/common rings.
use super::*;
use crate::cyw43439::phy_fixture::{Wide, WideFault};
use narf_wireless::reg::{db::Database, RegFlags, RegRule, RegulatoryDomain};

fn profile(channel: u8, fault: WideFault) -> Wide {
    let (secondary, operating) = match channel {
        6 => (10, 0x1808),
        36 => (40, 0xd826),
        149 => (153, 0xd897), // center151 (0x97), lower primary149.
        _ => panic!("literal fixture channel"),
    };
    Wide {
        caps: [3, 7],
        inventory: vec![0x1808, 0xd826, 0xd897],
        operating,
        secondary,
        fault,
    }
}
fn domain() -> RegulatoryDomain {
    let mut policy = firmware::domain();
    policy.rules[0].max_bandwidth_mhz = 40;
    for (start, end) in [(5170, 5250), (5735, 5835)] {
        policy.rules.push(RegRule {
            freq_start_mhz: start,
            freq_end_mhz: end,
            max_bandwidth_mhz: 40,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        });
    }
    policy
}
fn restricted(kind: u8) -> RegulatoryDomain {
    let mut policy = domain();
    policy.rules.push(RegRule {
        freq_start_mhz: 5199,
        freq_end_mhz: 5201,
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
fn native() -> Result<(), &'static str> {
    for version in [5, 6] {
        for channel in [6, 36, 149] {
            let h = Harness::new_wide(
                version,
                false,
                channel,
                None,
                false,
                profile(channel, WideFault::None),
            )?;
            for &band in if channel > 14 {
                &[2400, 5000][..]
            } else {
                &[2400][..]
            } {
                if h.device
                    .phy_capabilities(band)
                    .is_none_or(|c| c.ht[0] != 98 || c.ht[3..6] != [255; 3])
                {
                    return Err("native per-band HT40/SGI40 chain capability missing");
                }
            }
            h.associate(false)?;
            let commands = h.bus.commands();
            let band = if channel <= 14 { 2u32 } else { 1u32 };
            let width = commands
                .iter()
                .position(|(id, b, _)| {
                    *id == 263
                        && b.starts_with(b"bw_cap\0")
                        && b[7..11] == band.to_le_bytes()
                        && b[11..15] == [3, 0, 0, 0]
                })
                .ok_or("native40MHz cap missing")?;
            let join = commands
                .iter()
                .position(|(id, _, _)| *id == 26)
                .ok_or("native40MHz join missing")?;
            if width >= join
                || commands[join].1[48..50]
                    != profile(channel, WideFault::None).operating.to_le_bytes()
                || {
                    let state = h.device.state.try_lock().unwrap();
                    !state.station.ht_connection() || state.station.channel_width_mhz() != Some(40)
                }
            {
                return Err("native cap/chanspec/response order did not bind40MHz port");
            }
            ready(h.device.disassociate())?.map_err(|_| "wide native teardown")?;
            if h.device.link_up()
                || {
                    let state = h.device.state.try_lock().unwrap();
                    state.station.ht_connection() || state.station.channel_width_mhz().is_some()
                }
                || h.bus.stats().5 != 0
            {
                return Err("wide teardown retained metadata or freed live DMA");
            }
        }
        for (secured, pmf, channel) in [(false, false, 6), (true, false, 36), (true, true, 149)] {
            composition_native(
                Harness::new_wide(
                    version,
                    secured,
                    channel,
                    None,
                    pmf,
                    profile(channel, WideFault::None),
                )?,
                secured,
                pmf,
                true,
            )?;
        }
    }
    Ok(())
}
fn smoke_brcmf_ht40_sgi40_dual_band_native_open_wpa2_pmf_dhcp_ip() -> TestResult {
    native().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ht40",
    smoke_brcmf_ht40_sgi40_dual_band_native_open_wpa2_pmf_dhcp_ip
);

fn fallback() -> Result<(), &'static str> {
    for variant in 0..4 {
        let mut wide = profile(36, WideFault::None);
        if variant == 0 {
            wide.caps[1] = 1;
        }
        if variant == 1 {
            wide.inventory.retain(|value| *value != 0xd826);
        }
        let db = Arc::new(Database::new());
        let mut policy = domain();
        if variant == 2 {
            policy.rules[1].max_bandwidth_mhz = 20;
        }
        if variant == 3 {
            policy = restricted(0);
        }
        db.install(policy);
        let h = Harness::new_wide(6, true, 36, Some(db), false, wide)?;
        if variant == 0
            && (h
                .device
                .phy_capabilities(5000)
                .is_none_or(|c| c.ht[0] & 66 != 0)
                || h.device
                    .phy_capabilities(2400)
                    .is_none_or(|c| c.ht[0] & 66 != 66))
        {
            return Err("one band's20MHz reply copied another band's40MHz capability");
        }
        h.associate(true)?;
        let commands = h.bus.commands();
        if commands
            .iter()
            .any(|(id, b, _)| *id == 263 && b.starts_with(b"bw_cap\0") && b[11..15] == [3, 0, 0, 0])
            || commands
                .iter()
                .find(|(id, _, _)| *id == 26)
                .is_none_or(|(_, b, _)| b[48..50] != [36, 208])
            || {
                let state = h.device.state.try_lock().unwrap();
                !state.station.ht_connection() || state.station.channel_width_mhz() != Some(20)
            }
        {
            return Err("unqualified40MHz did not retain constrained native HT20");
        }
    }
    let db = Arc::new(Database::new());
    db.install(restricted(5));
    let h = Harness::new_wide(6, true, 36, Some(db), false, profile(36, WideFault::None))?;
    h.associate(true)?;
    if h.bus
        .commands()
        .iter()
        .rfind(|(id, b, _)| *id == 263 && b.starts_with(b"qtxpower\0"))
        .is_none_or(|(_, b, _)| b[9..] != [40, 0, 0, 0])
    {
        return Err("secondary-only power ceiling not applied to entire40MHz grant");
    }
    Ok(())
}
fn smoke_brcmf_ht40_native_inventory_policy_fallback_and_secondary_power() -> TestResult {
    fallback().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ht40",
    smoke_brcmf_ht40_native_inventory_policy_fallback_and_secondary_power
);

fn denials() -> Result<(), &'static str> {
    for version in [5, 6] {
        if Harness::new_wide(
            version,
            true,
            36,
            None,
            false,
            profile(36, WideFault::Inventory),
        )
        .is_ok()
        {
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
            let h = Harness::new_wide(version, true, 36, None, false, profile(36, fault))?;
            if h.associate(true).is_ok()
                || h.device.link_up()
                || h.device.connected_bssid().is_some()
                || h.bus.stats().5 != 0
            {
                return Err("invalid cap/request/current/response width opened port or freed DMA");
            }
            h.bus.stale_authorization();
            h.pump();
            if h.device.link_up() {
                return Err("late native width receipt revived failed owner");
            }
        }
    }
    Ok(())
}
fn smoke_brcmf_ht40_native_width_current_peer_and_assoc_receipt_denials() -> TestResult {
    denials().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ht40",
    smoke_brcmf_ht40_native_width_current_peer_and_assoc_receipt_denials
);

fn live() -> Result<(), &'static str> {
    for kind in 0..7 {
        let db = Arc::new(Database::new());
        db.install(domain());
        let h = Harness::new_wide(
            6,
            true,
            36,
            Some(db.clone()),
            false,
            profile(36, WideFault::None),
        )?;
        h.associate(true)?;
        let (uplink, _) = packets();
        let before = h.bus.sent();
        h.device
            .enqueue(&uplink)
            .map_err(|_| "wide queued TX fixture")?;
        if kind == 6 {
            db.clear();
        } else {
            db.install(restricted(kind));
        }
        h.pump();
        db.install(domain());
        h.bus.stale_authorization();
        h.pump();
        if !h.closed(&uplink) || h.bus.sent() != before || h.bus.stats().5 != 0 {
            return Err("secondary revocation/reinstall retained queued wide TX or released DMA");
        }
    }
    let db = Arc::new(Database::new());
    db.install(domain());
    let h = Harness::new_wide(
        6,
        true,
        36,
        Some(db.clone()),
        false,
        profile(36, WideFault::HoldResponse),
    )?;
    h.scan()?;
    {
        let mut request = Harness::request(true);
        request.channel = 36;
        request.frequency_mhz = 5180;
        let mut future = pin!(h.device.associate(request));
        let mut cx = Context::from_waker(Waker::noop());
        let mut held = false;
        for _ in 0..256 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return Err("wider native response did not wait");
            }
            if h.bus
                .commands()
                .iter()
                .any(|(id, b, _)| *id == 262 && b.starts_with(b"assoc_resp_ies\0"))
            {
                held = true;
                break;
            }
        }
        if !held {
            return Err("native wider response receipt was not reached");
        }
        db.install(restricted(0));
        h.bus.release_wide();
        if !matches!(future.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
            return Err("secondary revocation did not reject resumed native receipt");
        }
    }
    db.install(domain());
    h.bus.stale_authorization();
    h.pump();
    if h.device.link_up() || h.device.connected_bssid().is_some() || h.bus.stats().5 != 0 {
        return Err("resumed width receipt bypassed occupied policy or released DMA");
    }
    Ok(())
}
fn smoke_brcmf_ht40_current_secondary_policy_fences_native_waits_and_data() -> TestResult {
    live().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ht40",
    smoke_brcmf_ht40_current_secondary_policy_fences_native_waits_and_data
);

fn cancelled() -> Result<(), &'static str> {
    for version in [5, 6] {
        for fault in [WideFault::HoldCap, WideFault::HoldResponse] {
            let h = Harness::new_wide(version, true, 36, None, false, profile(36, fault))?;
            if h.associate(true).is_ok() {
                return Err("held wider native receipt admitted port");
            }
            h.bus.release_wide();
            h.bus.stale_authorization();
            h.pump();
            let (uplink, _) = packets();
            if !h.closed(&uplink) || h.associate(true).is_ok() || h.bus.stats().5 != 0 {
                return Err("cancelled wider owner reused native receipt or released DMA");
            }
        }
    }
    Ok(())
}
fn smoke_brcmf_ht40_cancelled_cap_or_assoc_receipt_retains_dma() -> TestResult {
    cancelled().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/ht40",
    smoke_brcmf_ht40_cancelled_cap_or_assoc_receipt_retains_dma
);
