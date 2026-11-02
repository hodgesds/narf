//! Original API77 CLIENT8 with actual tag10/MAC7/key/port and NoA receipts.
use super::*;
use crate::iwlwifi::p2p_client_fixture as p2p;
fn data() -> Vec<u8> {
    let mut out = AP.to_vec();
    out.extend_from_slice(&OWN);
    out.extend_from_slice(&[0x88, 0xb5, 1, 2, 3]);
    out
}
#[inline(never)]
fn join(f: &Fixture) -> Result<(), &'static str> {
    f.h.scan()?;
    let mut request = f.h.request();
    request.ie = p2p::request();
    run(f.h.device.associate(request))?
        .map_err(|_| "API77 P2P client actual tag10 native association/key/port")?;
    require(
        f.h.device.current_iftype() == 8
            && f.h.device.link_up()
            && f.h.device.connected_bssid() == Some(AP),
        "API77 P2P client actual current role/controlled port missing",
    )
}
fn notice(f: &Fixture, index: u8, window: Option<u8>, foreign: bool) {
    let mut actor = f.h.actor.lock();
    let mut beacon = p2p::beacon(actor.security.ap.beacon(), index, window);
    if foreign {
        beacon[10] = 4;
        beacon[16] = 4;
    }
    actor.inject(0xc1, 0, 0x8000, &envelope(&beacon));
}
#[inline(never)]
fn send(f: &Fixture, window: u32) -> Result<(), &'static str> {
    let before = f.h.actor.lock().security.data.len();
    f.h.device
        .enqueue(&data(), narf_net::TxMeta::default())
        .map_err(|_| "API77 P2P client native DATA enqueue")?;
    for _ in 0..128 {
        f.h.actor.lock().serve()?;
        f.h.device.step(None);
        f.h.actor.lock().serve()?;
    }
    let (after, last) = {
        let actor = f.h.actor.lock();
        (
            actor.security.data.len(),
            actor
                .commands
                .iter()
                .rev()
                .find(|(g, c, b)| {
                    (*g, *c) == (3, 8) && u32::from_le_bytes(b[8..12].try_into().unwrap()) == 7
                })
                .map(|(_, _, b)| u32::from_le_bytes(b[48..52].try_into().unwrap())),
        )
    };
    require(
        after > before && last == Some(window),
        "API77 P2P client DATA escaped current acknowledged CTWindow",
    )
}
#[inline(never)]
fn native() -> Result<(), &'static str> {
    let _platform = Platform::new();
    let f = Fixture::new_emission(10)?;
    join(&f)?;
    let native = {
        let mut state =
            f.h.device
                .state
                .try_lock()
                .ok_or("API77 P2P client State")?;
        state
            .owner
            .as_mut()
            .unwrap()
            .ap_hardware()
            .p2p_client_native()
            .ok_or("API77 P2P client native role absent")?
    };
    require(
        native.plan.own == OWN
            && native.plan.peer == AP
            && native.plan.local_device == p2p::LOCAL_DEVICE
            && native.plan.peer_device.device == p2p::PEER_DEVICE
            && native.desired() == 32,
        "API77 P2P client protocol/physical address ownership aliased",
    )?;
    for _ in 0..65 {
        notice(&f, 7, Some(99), true);
    }
    notice(&f, 2, Some(0xa8), false);
    send(&f, 40)?;
    notice(&f, 3, None, false);
    send(&f, 0)?;
    let mut down = OWN.to_vec();
    down.extend_from_slice(&AP);
    down.extend_from_slice(&[0x88, 0xb5, 7, 8, 9]);
    f.h.actor.lock().downlink(&down)?;
    require(
        f.h.device.step(None).len() == 1,
        "API77 P2P client actual key/PN RX missing",
    )?;
    run(f.h.device.disassociate())?.map_err(|_| "API77 P2P client actual native terminal close")?;
    let restored = f.h.actor.lock().client_mac == 4;
    require(
        restored && native.current().is_err() && !f.h.device.link_up(),
        "API77 P2P client stale native role survived default restoration",
    )
}
fn smoke_iwl_p2p_client_gen2_original_tag10_station7_noa_real_key_data_and_stop() -> TestResult {
    native().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/client",
    smoke_iwl_p2p_client_gen2_original_tag10_station7_noa_real_key_data_and_stop
);

#[inline(never)]
fn refuse() -> Result<(), &'static str> {
    let _platform = Platform::new();
    let f = Fixture::new_emission(10)?;
    f.h.scan()?;
    let before = f.h.actor.lock().commands.len();
    let mut request = f.h.request();
    request.ie = p2p::request();
    request.ie.extend_from_slice(&[48, 2, 1, 0]);
    require(
        run(f.h.device.associate(request))?.is_err(),
        "API77 P2P client caller replaced driver-owned security IEs",
    )?;
    let no_role = {
        let actor = f.h.actor.lock();
        !actor.commands[before..]
            .iter()
            .any(|(g, c, b)| (*g, *c) == (3, 8) && b[8] == 7)
    };
    require(
        no_role && !f.h.device.link_up(),
        "API77 P2P client refused metadata published actual MAC7/carrier",
    )?;
    drop(f);
    let f = Fixture::new_emission(10)?;
    f.h.scan()?;
    f.h.available.store(false, Ordering::Release);
    let before = f.h.actor.lock().commands.len();
    let mut request = f.h.request();
    request.ie = p2p::request();
    require(
        run(f.h.device.associate(request))?.is_err(),
        "API77 P2P client missing actual signed qualification reached RF",
    )?;
    let no_role = {
        let actor = f.h.actor.lock();
        !actor.commands[before..]
            .iter()
            .any(|(g, c, b)| (*g, *c) == (3, 8) && b[8] == 7)
    };
    require(
        no_role && !f.h.device.link_up(),
        "API77 P2P client source failure invented MAC7/port",
    )?;
    Ok(())
}
fn smoke_iwl_p2p_client_gen2_original_request_cannot_replace_security_owner() -> TestResult {
    refuse().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/p2p/client",
    smoke_iwl_p2p_client_gen2_original_request_cannot_replace_security_owner
);
