// SPDX-License-Identifier: GPL-2.0-or-later
//! Original CR4/msgbuf firmware snapshots and actual native completion rings.
//! Firmware owns per-width VHT rate control, CCMP and aggregation; these tests
//! prove host capability/occupied-channel/association and publication fences.
use super::*;
use crate::cyw43439::phy_fixture::{Vht80, VhtFault};
use narf_wireless::reg::{db::Database, RegFlags, RegRule, RegulatoryDomain};

fn profile(center: u8, fault: VhtFault) -> Vht80 {
    Vht80 {
        caps: [3, 7],
        mode: Some(1),
        txstreams: Some(3),
        txbf: [None, None],
        txbf_request: 0,
        // Independent brcmu_d11.c D11AC40/80 literals, both sideband sets.
        inventory: vec![
            0xd826, 0xd926, 0xd82e, 0xd92e, 0xe02a, 0xe12a, 0xe22a, 0xe32a, 0xd897, 0xd997, 0xd89f,
            0xd99f, 0xe09b, 0xe19b, 0xe29b, 0xe39b,
        ],
        center,
        fault,
    }
}
fn domain() -> RegulatoryDomain {
    let mut policy = firmware::domain();
    for (start, end) in [(5170, 5250), (5735, 5835)] {
        policy.rules.push(RegRule {
            freq_start_mhz: start,
            freq_end_mhz: end,
            max_bandwidth_mhz: 80,
            max_power_dbm: 17,
            flags: RegFlags::empty(),
        });
    }
    policy
}
fn remote_rule(kind: u8) -> RegulatoryDomain {
    let mut policy = domain();
    // Entirely outside primary36's20MHz and36+40's40MHz, inside80MHz.
    policy.rules.push(RegRule {
        freq_start_mhz: 5219,
        freq_end_mhz: 5221,
        max_bandwidth_mhz: if kind == 4 { 40 } else { 80 },
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
fn width(h: &Harness) -> Option<u32> {
    h.device
        .state
        .try_lock()
        .unwrap()
        .station
        .channel_width_mhz()
}
fn cap_written(h: &Harness, value: u8) -> bool {
    h.bus
        .commands()
        .iter()
        .any(|(id, b, _)| *id == 263 && b.starts_with(b"bw_cap\0") && b[11..15] == [value, 0, 0, 0])
}
fn request(h: &Harness, secured: bool) -> AssociateRequest {
    let mut request = Harness::request(secured);
    request.channel = u32::from(h.channel);
    request.frequency_mhz = h.frequency();
    request
}

fn native_matrix() -> Result<(), &'static str> {
    for version in [5, 6] {
        for (channel, center, spec) in [
            (36, 42, 0xe02au16),
            (40, 42, 0xe12a),
            (44, 42, 0xe22a),
            (48, 42, 0xe32a),
            (149, 155, 0xe09b),
            (153, 155, 0xe19b),
            (157, 155, 0xe29b),
            (161, 155, 0xe39b),
        ] {
            let mut native = profile(center, VhtFault::None);
            let tx = match channel % 3 {
                0 => 1,
                1 => 2,
                _ => 3,
            };
            native.txstreams = Some(tx);
            let h = Harness::new_vht(version, false, channel, None, false, 7, native)?;
            let caps = h
                .device
                .phy_capabilities(5000)
                .ok_or("native5GHz PHY missing")?;
            let vht = caps.vht.ok_or("native VHT capability missing")?;
            let tx_map = [0xfffeu16, 0xfffa, 0xffea][tx as usize - 1];
            if vht[..4] != [32, 0, 0, 0]
                || vht[4..6] != [0xea, 0xff]
                || vht[8..10] != tx_map.to_le_bytes()
                || caps.ht[3..6] != [255; 3]
                || h.device
                    .phy_capabilities(2400)
                    .is_none_or(|c| c.vht.is_some())
                || h.device.phy_capabilities(6000).is_some()
            {
                return Err("RX/TX NSS,SGI80 or band bound copied an unqualified capability");
            }
            h.associate(false)?;
            let commands = h.bus.commands();
            let wide = commands
                .iter()
                .position(|(id, b, _)| {
                    *id == 263 && b.starts_with(b"bw_cap\0") && b[11..15] == [7, 0, 0, 0]
                })
                .ok_or("native80MHz cap missing")?;
            let join = commands
                .iter()
                .position(|(id, _, _)| *id == 26)
                .ok_or("native VHT join missing")?;
            if wide >= join
                || commands[join].1[48..50] != spec.to_le_bytes()
                || width(&h) != Some(80)
                || !h.device.state.try_lock().unwrap().station.vht_connection()
                || !commands
                    .iter()
                    .any(|(id, b, _)| *id == 262 && b.starts_with(b"assoc_req_ies\0"))
                || !commands
                    .iter()
                    .any(|(id, b, _)| *id == 262 && b.starts_with(b"assoc_resp_ies\0"))
            {
                return Err("80MHz cap/current chanspec/original AP handshake did not bind port");
            }
            let mut queried = Vec::new();
            for (_, b, _) in commands
                .iter()
                .filter(|(id, b, _)| *id == 262 && b.starts_with(b"per_chan_info\0"))
            {
                queried.push(u32::from_le_bytes(b[14..18].try_into().unwrap()));
            }
            for constituent in [center - 6, center - 2, center + 2, center + 6] {
                if !queried.contains(&(0xd000 | u32::from(constituent))) {
                    return Err("native80MHz quarter was not individually qualified");
                }
            }
            ready(h.device.disassociate())?.map_err(|_| "native VHT teardown")?;
            if h.device.link_up() || width(&h).is_some() || h.bus.stats().5 != 0 {
                return Err("native VHT teardown retained authority or freed live DMA");
            }
        }
    }
    Ok(())
}
fn smoke_brcmf_vht80_native_all_sidebands_and_directional_nss() -> TestResult {
    native_matrix().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vht80",
    smoke_brcmf_vht80_native_all_sidebands_and_directional_nss
);

fn real_network() -> Result<(), &'static str> {
    for version in [5, 6] {
        for (secured, pmf, channel, center) in [
            (false, false, 36, 42),
            (true, false, 149, 155),
            (true, true, 48, 42),
        ] {
            let h = Harness::new_details(
                version,
                secured,
                secured,
                true,
                channel,
                None,
                Configuration {
                    mfp: pmf.then_some((true, true, 0)),
                    phy: Some((7, 0)),
                    wide: None,
                    vht: Some(profile(center, VhtFault::None)),
                },
            )?;
            // Signed exact-board selection, CR4/common DMA rings and actual
            // native TX status feed the real kernel DHCP/IP implementation.
            composition_native(h, secured, pmf, true)?;
        }
    }
    Ok(())
}
fn smoke_brcmf_vht80_signed_board_open_wpa2_pmf_real_dhcp_ip() -> TestResult {
    real_network().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vht80",
    smoke_brcmf_vht80_signed_board_open_wpa2_pmf_real_dhcp_ip
);

fn fallback() -> Result<(), &'static str> {
    for variant in 0..8 {
        let mut native = profile(42, VhtFault::None);
        let mut policy = domain();
        let expected = match variant {
            0 => {
                native.mode = None;
                40
            }
            1 => {
                native.mode = Some(0);
                40
            }
            2 => {
                native.txstreams = None;
                40
            }
            3 => {
                native.caps[1] = 3;
                40
            }
            4 => {
                native.inventory.retain(|c| c & 0xf800 != 0xe000);
                40
            }
            5 => {
                native.inventory.retain(|c| *c != 0xe02a);
                40
            }
            6 => {
                policy.rules[1].max_bandwidth_mhz = 40;
                40
            }
            _ => {
                policy.rules[1].max_bandwidth_mhz = 20;
                native.fault = VhtFault::RequestHt20;
                20
            }
        };
        let db = Arc::new(Database::new());
        db.install(policy);
        let h = Harness::new_vht(6, true, 36, Some(db), false, 7, native)?;
        h.associate(true)?;
        let actual_vht = h.device.state.try_lock().unwrap().station.vht_connection();
        if width(&h) != Some(expected)
            || cap_written(&h, 7)
            || actual_vht != (variant >= 5)
            || h.bus
                .commands()
                .iter()
                .find(|(id, _, _)| *id == 26)
                .is_none_or(|(_, b, _)| {
                    b[48..50] != (if expected == 40 { 0xd826u16 } else { 0xd024 }).to_le_bytes()
                })
        {
            return Err(
                "native capability/inventory/policy fallback changed VHT truth or actual width",
            );
        }
    }
    for kind in 0..5 {
        let db = Arc::new(Database::new());
        db.install(remote_rule(kind));
        let h = Harness::new_vht(6, true, 36, Some(db), false, 7, profile(42, VhtFault::None))?;
        h.associate(true)?;
        if width(&h) != Some(40)
            || cap_written(&h, 7)
            || !h.device.state.try_lock().unwrap().station.vht_connection()
        {
            return Err("remote-quarter restriction did not narrow original VHT80 offer before native programming");
        }
    }
    let db = Arc::new(Database::new());
    db.install(remote_rule(5));
    let h = Harness::new_vht(6, true, 36, Some(db), false, 7, profile(42, VhtFault::None))?;
    h.associate(true)?;
    if width(&h) != Some(80)
        || h.bus
            .commands()
            .iter()
            .rfind(|(id, b, _)| *id == 263 && b.starts_with(b"qtxpower\0"))
            .is_none_or(|(_, b, _)| b[9..] != [40, 0, 0, 0])
    {
        return Err("remote-quarter power was not applied to full80MHz emitter");
    }
    Ok(())
}
fn smoke_brcmf_vht80_native_fallback_preserves_vht_and_full_span_power() -> TestResult {
    fallback().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vht80",
    smoke_brcmf_vht80_native_fallback_preserves_vht_and_full_span_power
);

fn denials() -> Result<(), &'static str> {
    for version in [5, 6] {
        if Harness::new_vht(
            version,
            true,
            36,
            None,
            false,
            7,
            profile(42, VhtFault::Inventory),
        )
        .is_ok()
        {
            return Err("malformed native VHT inventory admitted");
        }
        for tx in [0, 4] {
            let mut native = profile(42, VhtFault::None);
            native.txstreams = Some(tx);
            if Harness::new_vht(version, true, 36, None, false, 7, native).is_ok() {
                return Err("invalid native TX NSS admitted");
            }
        }
        for fault in [
            VhtFault::CurrentWidth,
            VhtFault::ResponseWidth,
            VhtFault::ResponseCenter,
            VhtFault::ResponseMissing,
            VhtFault::ResponseBasic,
            VhtFault::RequestMissing,
            VhtFault::RequestHt20,
            VhtFault::RequestMcs,
            VhtFault::RequestSgi160,
            VhtFault::RequestDuplicate,
            VhtFault::CapReadback,
            VhtFault::ChannelRestricted,
        ] {
            let h = Harness::new_vht(version, true, 36, None, false, 7, profile(42, fault))?;
            if h.associate(true).is_ok()
                || h.device.link_up()
                || h.device.connected_bssid().is_some()
                || h.bus.stats().5 != 0
            {
                return Err(
                    "native VHT current/request/response/power failure opened port or freed DMA",
                );
            }
            h.bus.stale_authorization();
            h.pump();
            if h.device.link_up() {
                return Err("late VHT key/link receipt revived failed owner");
            }
        }
        let h = Harness::new_vht(
            version,
            true,
            36,
            None,
            false,
            7,
            profile(42, VhtFault::None),
        )?;
        h.bus.phy_profile(7, 6);
        if h.associate(true).is_ok() || h.device.link_up() {
            return Err("foreign current native BSSID opened VHT port");
        }
    }
    Ok(())
}
fn smoke_brcmf_vht80_native_request_response_inventory_and_current_denials() -> TestResult {
    denials().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vht80",
    smoke_brcmf_vht80_native_request_response_inventory_and_current_denials
);

fn live_and_cancelled() -> Result<(), &'static str> {
    let (uplink, downlink) = packets();
    for version in [5, 6] {
        for kind in 0..5 {
            let db = Arc::new(Database::new());
            db.install(domain());
            let h = Harness::new_vht(
                version,
                true,
                36,
                Some(db.clone()),
                false,
                7,
                profile(42, VhtFault::None),
            )?;
            h.associate(true)?;
            h.device
                .enqueue(&uplink)
                .map_err(|_| "queued native80 TX")?;
            let sent = h.bus.sent();
            db.install(remote_rule(kind));
            h.bus.downlink(&downlink);
            h.pump();
            db.install(domain());
            h.bus.stale_authorization();
            h.pump();
            if !h.closed(&uplink)
                || h.bus.sent() != sent
                || h.received(&downlink)
                || h.bus.stats().5 != 0
            {
                return Err(
                    "remote-quarter revoke/restore retained data or reopened native VHT owner",
                );
            }
        }
        for fault in [VhtFault::HoldCap, VhtFault::HoldResponse] {
            let h = Harness::new_vht(version, true, 36, None, false, 7, profile(42, fault))?;
            if h.associate(true).is_ok() {
                return Err("held native VHT receipt admitted data");
            }
            h.bus.release_vht();
            h.bus.stale_authorization();
            h.pump();
            if !h.closed(&uplink) || h.associate(true).is_ok() || h.bus.stats().5 != 0 {
                return Err("cancelled VHT receipt reopened control owner or freed native DMA");
            }
        }
    }
    let db = Arc::new(Database::new());
    db.install(domain());
    let h = Harness::new_vht(
        6,
        true,
        36,
        Some(db.clone()),
        false,
        7,
        profile(42, VhtFault::HoldResponse),
    )?;
    h.scan()?;
    {
        let mut future = pin!(h.device.associate(request(&h, true)));
        let mut cx = Context::from_waker(Waker::noop());
        let mut held = false;
        for _ in 0..256 {
            if future.as_mut().poll(&mut cx).is_ready() {
                return Err("VHT response was not held");
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
            return Err("held actual VHT response not reached");
        }
        db.install(remote_rule(0));
        h.bus.release_vht();
        if !matches!(future.as_mut().poll(&mut cx), Poll::Ready(Err(_))) {
            return Err("resumed VHT response ignored current remote-quarter policy");
        }
    }
    if h.device.link_up() || h.bus.stats().5 != 0 {
        return Err("resumed native VHT policy failure retained port or freed DMA");
    }
    Ok(())
}
fn smoke_brcmf_vht80_live_remote_policy_and_cancelled_native_receipts() -> TestResult {
    live_and_cancelled().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vht80",
    smoke_brcmf_vht80_live_remote_policy_and_cancelled_native_receipts
);

fn autonomous_channel_and_injection() -> Result<(), &'static str> {
    let (uplink, _) = packets();
    for version in [5, 6] {
        for injected in [
            vec![45, 26].into_iter().chain([0; 26]).collect::<Vec<_>>(),
            vec![61, 22].into_iter().chain([0; 22]).collect(),
            vec![191, 12].into_iter().chain([0; 12]).collect(),
            vec![192, 5, 1, 42, 0, 252, 255],
            vec![221, 7, 0, 80, 242, 2, 0, 1, 0],
        ] {
            let h = Harness::new_vht(
                version,
                true,
                36,
                None,
                false,
                7,
                profile(42, VhtFault::None),
            )?;
            h.scan()?;
            let mut req = request(&h, true);
            req.ie = injected;
            if ready(h.device.associate(req))?.is_ok()
                || h.bus.commands().iter().any(|(id, _, _)| *id == 26)
            {
                return Err("caller PHY/WMM bypassed driver-owned VHT request");
            }
        }
        let h = Harness::new_vht(
            version,
            true,
            36,
            None,
            false,
            7,
            profile(42, VhtFault::None),
        )?;
        h.associate(true)?;
        h.bus.channel_adopted();
        h.pump();
        h.bus.stale_authorization();
        h.pump();
        if !h.closed(&uplink) || h.bus.stats().5 != 0 {
            return Err("autonomous channel event retained old occupied VHT grant");
        }
    }
    Ok(())
}
fn smoke_brcmf_vht80_autonomous_channel_and_caller_phy_fail_closed() -> TestResult {
    autonomous_channel_and_injection().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vht80",
    smoke_brcmf_vht80_autonomous_channel_and_caller_phy_fail_closed
);

fn final_policy_boundaries() -> Result<(), &'static str> {
    let (uplink, downlink) = packets();
    for point in [
        ReceivePoint::AfterFrameAllocation,
        ReceivePoint::BeforeCallback,
    ] {
        let db = Arc::new(Database::new());
        db.install(domain());
        let h = Harness::new_vht(
            6,
            true,
            36,
            Some(db.clone()),
            false,
            7,
            profile(42, VhtFault::None),
        )?;
        h.associate(true)?;
        h.bus.downlink(&downlink);
        h.bus.downlink(&downlink);
        let frames = h.device.step();
        if frames.len() != 2 {
            return Err("actual native VHT DMA pair missing before final policy boundary");
        }
        let hit = Arc::new(AtomicBool::new(false));
        let unlocked = Arc::new(AtomicBool::new(true));
        let weak = Arc::downgrade(&h.device);
        let seen = hit.clone();
        let free = unlocked.clone();
        *h.device.receive_hook.lock() = Some(Arc::new(move |at| {
            if at != point || seen.swap(true, Ordering::AcqRel) {
                return;
            }
            let Some(device) = weak.upgrade() else {
                return;
            };
            let state_free = device.state.try_lock().is_some();
            let publication_free = device.publication.try_lock().is_some();
            let ring_free = device.rx.try_lock().is_some();
            free.store(
                state_free && publication_free && ring_free,
                Ordering::Release,
            );
            db.install(remote_rule(0));
        }));
        if h.device.deliver_received(frames)
            || !hit.load(Ordering::Acquire)
            || !unlocked.load(Ordering::Acquire)
            || !h.closed(&uplink)
            || h.received(&downlink)
            || h.bus.stats().5 != 0
        {
            return Err(
                "final IPC/callback policy boundary published old VHT prefix or held owner locks",
            );
        }
        *h.device.receive_hook.lock() = None;
    }
    Ok(())
}
fn smoke_brcmf_vht80_native_final_ipc_and_callback_remote_policy() -> TestResult {
    final_policy_boundaries().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vht80",
    smoke_brcmf_vht80_native_final_ipc_and_callback_remote_policy
);

static CALLBACK_DEVICE: IrqSafeSpinLock<Option<Arc<ModelDevice>>> = IrqSafeSpinLock::new(None);
static CALLBACK_COUNT: AtomicU64 = AtomicU64::new(0);
static CALLBACK_UNLOCKED: AtomicBool = AtomicBool::new(true);
fn close_from_stack(_: &str, _: &mut [u8]) {
    let Some(device) = CALLBACK_DEVICE.lock().clone() else {
        return;
    };
    CALLBACK_COUNT.fetch_add(1, Ordering::AcqRel);
    let state_free = device.state.try_lock().is_some();
    let pub_free = device.publication.try_lock().is_some();
    let ring_free = device.rx.try_lock().is_some();
    CALLBACK_UNLOCKED.store(state_free && pub_free && ring_free, Ordering::Release);
    device.close_host();
}
fn callback_close() -> Result<(), &'static str> {
    let h = Harness::new_vht(6, true, 36, None, false, 7, profile(42, VhtFault::None))?;
    h.associate(true)?;
    let (_, downlink) = packets();
    h.bus.downlink(&downlink);
    h.bus.downlink(&downlink);
    let frames = h.device.step();
    if frames.len() != 2 {
        return Err("native pair missing for reentrant close");
    }
    *CALLBACK_DEVICE.lock() = Some(h.device.clone());
    CALLBACK_COUNT.store(0, Ordering::Release);
    CALLBACK_UNLOCKED.store(true, Ordering::Release);
    narf_net::iface::install_rx_handler(close_from_stack);
    let delivered = h.device.deliver_received(frames);
    narf_net::iface::install_rx_handler(narf_net::tcp_stack::rx_handler);
    *CALLBACK_DEVICE.lock() = None;
    if !delivered
        || CALLBACK_COUNT.load(Ordering::Acquire) != 1
        || !CALLBACK_UNLOCKED.load(Ordering::Acquire)
        || h.received(&downlink)
        || h.device.link_up()
    {
        return Err("reentrant stack close retained old IPC/batch or held publication locks");
    }
    // Close/rejoin the same peer is a new receive incarnation. Captured old
    // native data cannot regain authority through equal BSSID/width.
    ready(h.device.disassociate())?.map_err(|_| "reentrant close native teardown")?;
    h.associate(true)?;
    h.bus.downlink(&downlink);
    let old = h.device.step();
    ready(h.device.disassociate())?.map_err(|_| "same-peer epoch native teardown")?;
    h.associate(true)?;
    if h.device.deliver_received(old) || h.received(&downlink) {
        return Err("same-peer rejoin retrospectively authorized old native batch");
    }
    h.bus.downlink(&downlink);
    h.pump();
    if !h.received(&downlink) {
        return Err("current receive incarnation failed its positive native control");
    }
    Ok(())
}
fn smoke_brcmf_vht80_reentrant_stack_close_and_same_peer_receive_epoch() -> TestResult {
    callback_close().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vht80",
    smoke_brcmf_vht80_reentrant_stack_close_and_same_peer_receive_epoch
);

fn beamforming() -> Result<(), &'static str> {
    // (bfe, bfr, txstreams, literal IEEE80211_VHT_CAP_* info incl. SGI80).
    // 0x0c1a5820 = SGI80|SU_BFR|SU_BFE|STS(2)|SOUND(2)|MU_BFR|MU_BFE|MRQ_MFB.
    let cases: [(Option<u32>, Option<u32>, u32, u32); 5] = [
        (Some(3), Some(3), 3, 0x0c1a_5820),
        (Some(1), Some(0), 1, 0x0000_1020),
        (Some(0), Some(2), 2, 0x0c09_4020),
        // Bits outside BRCMF_TXBF_{SU,MU} do not add capability.
        (Some(4), Some(0), 3, 0x0000_0020),
        (None, Some(1), 2, 0x0c01_4820),
    ];
    for version in [5, 6] {
        for (bfe, bfr, tx, literal) in cases {
            let mut native = profile(42, VhtFault::None);
            native.txstreams = Some(tx);
            native.txbf = [bfe, bfr];
            native.txbf_request = literal & !0x20;
            let h = Harness::new_vht(version, true, 36, None, false, 7, native)?;
            let vht = h
                .device
                .phy_capabilities(5000)
                .and_then(|caps| caps.vht)
                .ok_or("native VHT capability missing")?;
            if vht[..4] != literal.to_le_bytes() {
                return Err("VHT beamforming bits differ from Linux brcmf_update_vht_cap");
            }
            let queried = h
                .bus
                .commands()
                .iter()
                .filter(|(id, b, _)| {
                    *id == 262
                        && (b.starts_with(b"txbf_bfe_cap\0") || b.starts_with(b"txbf_bfr_cap\0"))
                })
                .count();
            if queried != 2 {
                return Err("both native beamforming capabilities were not queried");
            }
            h.associate(true)?;
            if !h.device.state.try_lock().unwrap().station.vht_connection() {
                return Err("beamforming-capable firmware request did not bind VHT");
            }
        }
        // Native capability without the matching firmware request bits is a
        // changed actual association request, not a successful VHT join.
        let mut native = profile(42, VhtFault::None);
        native.txbf = [Some(1), Some(1)];
        let h = Harness::new_vht(version, true, 36, None, false, 7, native)?;
        if h.associate(true).is_ok() || h.device.link_up() || h.bus.stats().5 != 0 {
            return Err("request without probed beamforming capability opened the port");
        }
    }
    Ok(())
}
fn smoke_brcmf_vht80_native_beamforming_capability_and_request() -> TestResult {
    beamforming().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/brcmfmac/vht80",
    smoke_brcmf_vht80_native_beamforming_capability_and_request
);
