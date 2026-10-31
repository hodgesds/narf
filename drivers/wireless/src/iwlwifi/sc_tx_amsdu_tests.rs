//! Actual Sc TLC/RFH and SMEM receipts precede plaintext aggregate TX in
//! real TFH DMA. Public IPC frames, native keys and credit owners stay live.
use super::*;

pub(super) fn image(versions: &[u8], profile: Option<&TxModel>) -> R<Vec<u8>> {
    let mut bytes = super::super::super::firmware_parser_tests::mld_image();
    require(word(&bytes, 88) == 48, "Sc TX authored firmware table tag")?;
    let old = word(&bytes, 92) as usize;
    bytes.splice(96..96 + old.next_multiple_of(4), versions.iter().copied());
    bytes[92..96].copy_from_slice(&(versions.len() as u32).to_le_bytes());
    if let Some(profile) = profile {
        for (index, bits) in [
            (1u32, if profile.cdb { 1u32 << 8 } else { 0 }),
            (2, if profile.extended { 1 << 16 } else { 0 }),
        ] {
            bytes.extend_from_slice(&30u32.to_le_bytes());
            bytes.extend_from_slice(&8u32.to_le_bytes());
            bytes.extend_from_slice(&index.to_le_bytes());
            bytes.extend_from_slice(&bits.to_le_bytes());
        }
    }
    Ok(bytes)
}
fn profile(extended: bool, cdb: bool) -> TxModel {
    // Literal SHARED_MEM_ALLOC_API v4. Addresses remain opaque zeros;
    // only actual reported FIFO sizes bound this software firmware model.
    let mut memory = vec![0; 260];
    memory[32..36].copy_from_slice(&2u32.to_le_bytes());
    for lmac in 0..2 {
        for fifo in 0..8 {
            let at = 40 + lmac * 72 + fifo * 4;
            memory[at..at + 4].copy_from_slice(&4096u32.to_le_bytes());
        }
    }
    TxModel {
        extended,
        cdb,
        version: 4,
        memory,
    }
}
fn phy(he: bool) -> PhyModel {
    PhyModel {
        width: if he { 2 } else { 0 },
        streams: if he { 2 } else { 1 },
        rates: if he { 3 } else { 2 },
        mcc_he: he,
        response_he: he,
    }
}
fn setup(secured: bool, phy: PhyModel, profile: TxModel, fault: Fault) -> R<Guard> {
    Guard::build_features(secured, fault, None, None, Some(phy), false, Some(profile))
}
fn ready(guard: &Guard, phy: PhyModel, secured: bool) -> R {
    let mut scan = scan_request();
    scan.channels = vec![u32::from(phy.channel())];
    scan.frequencies_mhz =
        vec![if phy.channel() <= 14 { 2407 } else { 5000 } + 5 * u32::from(phy.channel())];
    let found = run(guard.device().scan(scan), service)?.map_err(|_| "Sc TX native scan")?;
    require(found.len() == 1, "Sc TX BSS discovery")?;
    let mut req = request(secured);
    req.channel = u32::from(phy.channel());
    req.frequency_mhz =
        if phy.channel() <= 14 { 2407 } else { 5000 } + 5 * u32::from(phy.channel());
    run(
        guard.device().associate_in_domain(req, &he_tests::policy()),
        service,
    )?
    .map_err(|_| "Sc TX native association")?;
    carrier(guard.device(), true)
}
fn until(mut done: impl FnMut() -> bool) -> R {
    let deadline = narf_time::Deadline::after_ms(1500);
    loop {
        service()?;
        drain();
        if done() {
            return Ok(());
        }
        if deadline.expired() {
            return Err("Sc TX native progress bound");
        }
        narf_scheduler::sleep_pumps::run();
    }
}
fn report(size: u32, tids: u32) {
    let mut body = [0; 20];
    body[4..8].copy_from_slice(&2u32.to_le_bytes());
    body[12..16].copy_from_slice(&size.to_le_bytes());
    body[16..20].copy_from_slice(&tids.to_le_bytes());
    HARNESS
        .lock()
        .as_mut()
        .unwrap()
        .1
        .firmware
        .inject(0xf7, 5, 0x8000, &body);
}
fn enable(guard: &Guard) -> R {
    report(3839, 255);
    until(|| {
        guard
            .device()
            .state
            .try_lock()
            .is_some_and(|state| state.connection.as_ref().is_some_and(|c| c.can_batch(1)))
    })
}
fn packet(marker: u8, length: usize, bk: bool) -> Vec<u8> {
    let mut frame = udp_ipv4(
        AP,
        OWN,
        NETWORK.lease_ip,
        NETWORK.server_ip,
        49152,
        9999,
        &vec![marker; length],
    );
    if bk {
        frame[15] = 0x20;
        narf_net::pkt::set_ipv4_checksum(&mut frame[14..]);
    }
    frame
}
fn pair(guard: &Guard, first: &[u8], second: &[u8]) -> R {
    let state = guard
        .device()
        .state
        .try_lock()
        .ok_or("Sc TX enqueue state ownership")?;
    narf_net::iface::send_on(guard.device().name(), first)
        .map_err(|_| "Sc TX first public frame admission")?;
    narf_net::iface::send_on(guard.device().name(), second)
        .map_err(|_| "Sc TX second public frame admission")?;
    drop(state);
    flush()
}
fn smoke_sc_tx_amsdu_native_open_wpa2_and_he_lmac_fifo_receipts() -> TestResult {
    check(|| {
        for (secured, he, extended, cdb) in [
            (false, false, false, false),
            (true, false, true, false),
            (true, true, true, true),
        ] {
            let phy = phy(he);
            let mut model = profile(extended, cdb);
            if he {
                // Only actual CDB LMAC1 trigger BE FIFO5 admits this pair.
                for lmac in 0..2 {
                    for fifo in 0..8 {
                        let at = 40 + lmac * 72 + fifo * 4;
                        model.memory[at..at + 4].copy_from_slice(&256u32.to_le_bytes());
                    }
                }
                model.memory[132..136].copy_from_slice(&4096u32.to_le_bytes()); // 40+72+5*4
            }
            let guard = setup(secured, phy, model, Fault::None)?;
            ready(&guard, phy, secured)?;
            let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                .map_err(|_| "Sc TX actual kernel DORA")?;
            require(NETWORK.matches_lease(&lease), "Sc TX DHCP lease")?;
            enable(&guard)?;
            let first = packet(1, 200, false);
            let second = packet(2, 300, false);
            pair(&guard, &first, &second)?;
            let exact = {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                wire.aggregates.len() == 1
                    && wire.aggregates[0] == [first, second]
                    && wire
                        .data
                        .iter()
                        .rev()
                        .take(2)
                        .all(|(_, protected)| *protected == secured)
                    && wire
                        .commands
                        .iter()
                        .filter(|(g, c, _)| (*g, *c) == if extended { (2, 0) } else { (1, 0x25) })
                        .count()
                        == 1
            };
            require(exact, "Sc actual native A-MSDU/keys/FIFO/command receipts")?;
            run(guard.device().disassociate(), service)?.map_err(|_| "Sc TX native teardown")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/tx_amsdu",
    smoke_sc_tx_amsdu_native_open_wpa2_and_he_lmac_fifo_receipts
);

fn smoke_sc_tx_amsdu_native_tlc_tid_fifo_and_partial_checksum_fallbacks() -> TestResult {
    check(|| {
        let phy = phy(false);
        let mut model = profile(true, false);
        model.memory[44..48].copy_from_slice(&2048u32.to_le_bytes()); // BE FIFO1
        let guard = setup(true, phy, model, Fault::None)?;
        ready(&guard, phy, true)?;
        enable(&guard)?;
        let first = packet(3, 1000, false);
        let second = packet(4, 1000, false);
        pair(&guard, &first, &second)?;
        require(
            HARNESS.lock().as_ref().unwrap().1.aggregates.is_empty(),
            "Sc TX ignored actual FIFO margin",
        )?;
        report(3839, 1 << 1); // only BK/TID1 may batch
        flush()?;
        let first = packet(5, 50, false);
        let second = packet(6, 50, false);
        pair(&guard, &first, &second)?;
        require(
            HARNESS.lock().as_ref().unwrap().1.aggregates.is_empty(),
            "Sc TX ignored native TLC TID mask",
        )?;
        report(1999, 255);
        flush()?;
        pair(&guard, &first, &second)?;
        require(
            HARNESS.lock().as_ref().unwrap().1.aggregates.is_empty(),
            "Sc TX ignored TLC batching disable",
        )?;
        report(3839, 255);
        flush()?;
        {
            let state = guard
                .device()
                .state
                .try_lock()
                .ok_or("Sc partial checksum enqueue owner")?;
            let iface = narf_net::iface::lookup(guard.device().name())
                .ok_or("Sc partial checksum netdev")?;
            iface
                .xmit_meta(
                    &first,
                    narf_net::TxMeta::with_csum(narf_net::L4CsumKind::Udp),
                )
                .map_err(|_| "Sc partial checksum admission")?;
            narf_net::iface::send_on(guard.device().name(), &second)
                .map_err(|_| "Sc partial checksum peer admission")?;
            drop(state);
        }
        flush()?;
        let singles = {
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            wire.aggregates.is_empty()
                && wire.data.len() == 8
                && wire.data.iter().all(|(_, protected)| *protected)
        };
        require(
            singles,
            "Sc partial checksum/TLC/FIFO fallback lost frames or batched unsupported metadata",
        )?;
        run(guard.device().disassociate(), service)?.map_err(|_| "Sc TX fallback teardown")?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/tx_amsdu",
    smoke_sc_tx_amsdu_native_tlc_tid_fifo_and_partial_checksum_fallbacks
);

fn assets(
    phy: PhyModel,
    profile: &TxModel,
) -> R<(crate::firmware_asset::Asset, crate::firmware_asset::Asset)> {
    let mut versions = super::super::super::firmware_parser_tests::mld_commands();
    he_tests::versions(&mut versions, phy.rates);
    versions.extend_from_slice(&[0, 2, 0, profile.version]);
    let bytes = image(&versions, Some(profile))?;
    let (write, read) = narf_firmware::bootstrap_authority();
    for (name, payload) in [
        ("narf-test/iwl-tx-amsdu/executable", bytes.as_slice()),
        ("narf-test/iwl-tx-amsdu/pnvm", &[0x79u8; 32][..]),
    ] {
        crate::firmware_asset::tests::install(&write, name, payload, true)
            .map_err(|_| "Sc TX source fixture install")?;
    }
    Ok((
        crate::firmware_asset::load(
            &read,
            "narf-test/iwl-tx-amsdu/executable",
            16 * 1024 * 1024,
            true,
        )
        .map_err(|_| "Sc TX executable source")?,
        crate::firmware_asset::load(&read, "narf-test/iwl-tx-amsdu/pnvm", 64, true)
            .map_err(|_| "Sc TX PNVM source")?,
    ))
}
fn pending_pair(guard: &Guard, first: &[u8], second: &[u8], category: usize) -> R {
    let state = guard
        .device()
        .state
        .try_lock()
        .ok_or("Sc TX pending pair retained state")?;
    require(
        state.pending[category]
            .as_ref()
            .is_some_and(|p| p.frame().payload() == first)
            && state.pending_next[category]
                .as_ref()
                .is_some_and(|p| p.frame().payload() == second),
        "Sc TX credit pressure lost either original IPC frame",
    )
}
fn smoke_sc_tx_amsdu_native_credit_wrap_retains_both_frames_then_source_loss_pins_dma() -> TestResult
{
    check(|| {
        let phy = phy(false);
        let profile = profile(true, false);
        let (executable, pnvm) = assets(phy, &profile)?;
        let guard = Guard::build_features(
            true,
            Fault::None,
            None,
            Some((&executable, &pnvm)),
            Some(phy),
            false,
            Some(profile),
        )?;
        ready(&guard, phy, true)?;
        enable(&guard)?;
        HARNESS.lock().as_mut().unwrap().1.fault = Fault::HoldData;
        // BK is an even native queue ID. Fill the actual128-entry ring
        // and publish across its physical wrap after terminal credits.
        let fill = packet(7, 20, true);
        for _ in 0..super::super::super::data_queue::DEPTH - 1 {
            narf_net::iface::send_on(guard.device().name(), &fill)
                .map_err(|_| "Sc TX fill native queue")?;
            flush()?;
        }
        let first = packet(8, 20, true);
        let second = packet(9, 20, true);
        pair(&guard, &first, &second)?;
        pending_pair(&guard, &first, &second, 0)?;
        let before = HARNESS.lock().as_ref().unwrap().1.aggregates.len();
        {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            let (queue, pointer) = wire.held_data.remove(0);
            require(queue & 1 == 0, "Sc TX credit fixture missed even queue")?;
            wire.firmware.tx_complete(queue, pointer);
        }
        until(|| HARNESS.lock().as_ref().unwrap().1.aggregates.len() == before + 1)?;
        let exact = {
            let slot = HARNESS.lock();
            let wire = &slot.as_ref().unwrap().1;
            wire.aggregates.last() == Some(&vec![first, second])
        };
        require(
            exact,
            "Sc TX returned credit failed exact two-frame publication",
        )?;
        let wrapped1 = packet(10, 20, true);
        let wrapped2 = packet(11, 20, true);
        pair(&guard, &wrapped1, &wrapped2)?;
        pending_pair(&guard, &wrapped1, &wrapped2, 0)?;
        {
            let mut slot = HARNESS.lock();
            let wire = &mut slot.as_mut().unwrap().1;
            let (queue, pointer) = wire.held_data.remove(0);
            wire.firmware.tx_complete(queue, pointer);
        }
        until(|| HARNESS.lock().as_ref().unwrap().1.aggregates.len() == before + 2)?;
        let wrapped = {
            let slot = HARNESS.lock();
            slot.as_ref().unwrap().1.aggregates.last() == Some(&vec![wrapped1, wrapped2])
        };
        require(
            wrapped,
            "Sc TX physical ring wrap changed either original frame",
        )?;
        let blocked1 = packet(14, 20, true);
        let blocked2 = packet(15, 20, true);
        pair(&guard, &blocked1, &blocked2)?;
        pending_pair(&guard, &blocked1, &blocked2, 0)?;
        let published = HARNESS.lock().as_ref().unwrap().1.data.len();
        executable.cap.revoke();
        until(|| {
            guard
                .device()
                .state
                .try_lock()
                .is_some_and(|state| state.stop_completed)
        })?;
        carrier(guard.device(), false)?;
        let state = guard
            .device()
            .state
            .try_lock()
            .ok_or("Sc TX revoked owner retained state")?;
        require(
            state.needs_reset
                && state.hardware.is_failed()
                && model::retained(&state.hardware).2 != 0
                && state.pending.iter().all(Option::is_none)
                && state.pending_next.iter().all(Option::is_none),
            "Sc TX source loss released native DMA or retained unauthorised ingress",
        )?;
        drop(state);
        require(
            HARNESS.lock().as_ref().unwrap().1.data.len() == published,
            "Sc TX source revocation published another native frame",
        )?;
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/tx_amsdu",
    smoke_sc_tx_amsdu_native_credit_wrap_retains_both_frames_then_source_loss_pins_dma
);

fn smoke_sc_tx_amsdu_native_held_smem_receipt_source_loss_never_publishes_aggregate() -> TestResult
{
    check(|| {
        for which in 0..2 {
            let phy = phy(false);
            let profile = profile(which == 1, false);
            let (executable, pnvm) = assets(phy, &profile)?;
            let guard = Guard::build_features(
                true,
                Fault::HoldSmem,
                None,
                Some((&executable, &pnvm)),
                Some(phy),
                false,
                Some(profile),
            )?;
            ready(&guard, phy, true)?;
            report(3839, 255);
            until(|| HARNESS.lock().as_ref().unwrap().1.held.is_some())?;
            let first = packet(12, 20, false);
            let second = packet(13, 20, false);
            narf_net::iface::send_on(guard.device().name(), &first)
                .map_err(|_| "Sc held SMEM first ingress")?;
            narf_net::iface::send_on(guard.device().name(), &second)
                .map_err(|_| "Sc held SMEM second ingress")?;
            if which == 0 {
                executable.cap.revoke();
            } else {
                pnvm.cap.revoke();
            }
            {
                let mut slot = HARNESS.lock();
                let wire = &mut slot.as_mut().unwrap().1;
                let (cmd, group, sequence) =
                    wire.held.take().ok_or("Sc held SMEM command missing")?;
                require(
                    (group, cmd) == if which == 1 { (2, 0) } else { (1, 0x25) },
                    "Sc held another native query",
                )?;
                let response = wire.tx_model.as_ref().unwrap().memory.clone();
                wire.fault = Fault::None;
                wire.firmware.inject(cmd, group, sequence, &response);
            }
            until(|| {
                guard
                    .device()
                    .state
                    .try_lock()
                    .is_some_and(|state| state.stop_completed)
            })?;
            carrier(guard.device(), false)?;
            let state = guard
                .device()
                .state
                .try_lock()
                .ok_or("Sc held SMEM failed owner retained state")?;
            require(
                state.needs_reset
                    && state.hardware.is_failed()
                    && model::retained(&state.hardware).0 != 0,
                "Sc held SMEM lost uncertain native command ownership",
            )?;
            drop(state);
            let safe = {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                wire.aggregates.is_empty() && wire.data.is_empty()
            };
            require(
                safe,
                "Sc late SMEM receipt after authority loss published data",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/sc/tx_amsdu",
    smoke_sc_tx_amsdu_native_held_smem_receipt_source_loss_never_publishes_aggregate
);
