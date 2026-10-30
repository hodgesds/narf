//! Full Sc device/native AP-power update ownership over posted RFH/TFH.
use super::*;

fn associate(guard: &Guard) -> R {
    scan(guard.device())?;
    run(
        guard
            .device()
            .associate_in_domain(request(false), &policy()),
        service,
    )?
    .map_err(|_| "Sc native power fixture association")?;
    carrier(guard.device(), true)
}
fn tick() {
    let _ = drain();
    narf_scheduler::block_on_spin(narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(
        2_000_000,
    )));
}
fn until(mut ready: impl FnMut() -> bool) -> R {
    let deadline = narf_time::Deadline::after_ms(1500);
    loop {
        tick();
        if let Some(error) = HARNESS.lock().as_ref().unwrap().1.error {
            return Err(error);
        }
        if ready() {
            return Ok(());
        }
        if deadline.expired() {
            return Err("Sc retained AP-power progress stalled");
        }
    }
}
fn announce(limit: Option<u8>, hold: bool) -> R {
    let mut slot = HARNESS.lock();
    let wire = &mut slot.as_mut().unwrap().1;
    let mut beacon = wire.ap.beacon();
    if let Some(limit) = limit {
        let capability = half(&beacon, 34) | (1 << 8);
        beacon[34..36].copy_from_slice(&capability.to_le_bytes());
        // Authored legacy Country triplet channels1..11/max20dBm and
        // Power Constraint reduce that bound, without granting host country.
        beacon.extend_from_slice(&[7, 6, b'U', b'S', b' ', 1, 11, 20, 32, 1, 20 - limit]);
        wire.power_expectation = Some(i16::from(limit) * 8);
    }
    wire.fault = if hold { Fault::HoldPower } else { Fault::None };
    wire.mpdu(&beacon, false);
    Ok(())
}
fn power(device: &Device) -> Option<i8> {
    let state = device.state.try_lock()?;
    state
        .connection
        .as_ref()
        .map(|c| c.regulatory_program().power())
}
fn release_power() -> R {
    let mut slot = HARNESS.lock();
    let wire = &mut slot.as_mut().unwrap().1;
    let (command, group, sequence) = wire.held.take().ok_or("Sc power receipt was not held")?;
    require(
        (group, command) == (1, 0x9f),
        "Sc held foreign power command",
    )?;
    wire.fault = Fault::None;
    wire.firmware.inject(command, 0, sequence, &[]);
    Ok(())
}

fn smoke_sc_native_ap_power_precedes_activation_and_holds_queued_tx_until_receipt() -> TestResult {
    check(|| {
        let guard = Guard::new(false, Fault::None)?;
        associate(&guard)?;
        let device = guard.device();
        {
            let slot = HARNESS.lock();
            let commands = &slot.as_ref().unwrap().1.commands;
            let scalar = commands
                .iter()
                .position(|(g, c, b)| (*g, *c) == (1, 0x9f) && word(b, 0) == 0)
                .ok_or("Sc initial native scalar absent")?;
            let active = commands
                .iter()
                .position(|(g, c, b)| (*g, *c) == (3, 9) && word(b, 28) == 1)
                .ok_or("Sc native active link absent")?;
            require(
                scalar < active,
                "Sc activated autonomous link before host/AP scalar receipt",
            )?;
        }
        let before = HARNESS.lock().as_ref().unwrap().1.data.len();
        announce(Some(10), true)?;
        until(|| HARNESS.lock().as_ref().unwrap().1.held.is_some())?;
        let probe = udp_ipv4(
            AP,
            OWN,
            NETWORK.lease_ip,
            NETWORK.server_ip,
            49156,
            7,
            b"sc-held-ap-power",
        );
        send_frame(&probe, narf_net::TxMeta::default())
            .map_err(|_| "Sc pending power did not retain host TX")?;
        for _ in 0..8 {
            tick();
        }
        require(
            HARNESS.lock().as_ref().unwrap().1.data.len() == before,
            "Sc queued data passed unacknowledged AP power",
        )?;
        release_power()?;
        until(|| {
            power(device) == Some(10) && HARNESS.lock().as_ref().unwrap().1.data.len() == before + 1
        })?;
        {
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            require(
                wire.data.last().is_some_and(|(bytes, _)| bytes == &probe),
                "Sc power receipt lost queued frame identity",
            )?;
        }
        let count = HARNESS
            .lock()
            .as_ref()
            .unwrap()
            .1
            .commands
            .iter()
            .filter(|(g, c, _)| (*g, *c) == (1, 0x9f))
            .count();
        announce(None, false)?;
        for _ in 0..8 {
            tick();
        }
        require(
            power(device) == Some(10)
                && HARNESS
                    .lock()
                    .as_ref()
                    .unwrap()
                    .1
                    .commands
                    .iter()
                    .filter(|(g, c, _)| (*g, *c) == (1, 0x9f))
                    .count()
                    == count,
            "Sc missing later AP limit silently cleared/reprogrammed an existing bound",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/power",
    smoke_sc_native_ap_power_precedes_activation_and_holds_queued_tx_until_receipt
);

fn smoke_sc_ap_power_increase_updates_copied_policy_proof_before_native_receipt() -> TestResult {
    check(|| {
        let guard = Guard::new(false, Fault::None)?;
        associate(&guard)?;
        let device = guard.device();
        announce(Some(5), false)?;
        until(|| power(device) == Some(5))?;
        let copied = device
            .policy_fence
            .lock()
            .clone()
            .ok_or("Sc station policy fence absent")?;
        announce(Some(10), true)?;
        until(|| HARNESS.lock().as_ref().unwrap().1.held.is_some())?;
        let mut tightened = policy();
        tightened.rules[0].max_power_dbm = 6;
        guard.policy_db.install(tightened);
        require(
            copied.check().is_err(),
            "Sc copied proof retained stale low ceiling across a pending increase",
        )?;
        release_power()?;
        until(|| {
            !device.link_up()
                && device
                    .state
                    .try_lock()
                    .is_some_and(|s| s.hardware.is_failed())
        })?;
        let state = device
            .state
            .try_lock()
            .ok_or("Sc failed power owner retained state")?;
        require(
            state.connection.as_ref().is_none_or(|c| !c.authorized)
                && model::retained(&state.hardware).0 == 1,
            "Sc late power receipt reopened port or released uncertain native command DMA",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/power",
    smoke_sc_ap_power_increase_updates_copied_policy_proof_before_native_receipt
);
