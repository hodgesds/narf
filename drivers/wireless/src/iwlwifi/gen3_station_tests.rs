//! API89 native station conversations with modeled firmware execution.
pub(super) use super::super::super::gen3_fixture::Case;
use super::*;

#[inline(never)]
pub(super) fn setup(
    case: Case,
    secured: bool,
    phy: Option<PhyModel>,
    tx: Option<TxModel>,
    fault: Fault,
) -> R<Box<Guard>> {
    let guard = Guard::build_native_profile(
        secured,
        fault,
        None,
        None,
        phy,
        NativeModel {
            receive_model: true.into(),
            tx_model: tx,
            api89: Some(case),
            bz: None,
        },
    )?;
    Ok(Box::new(guard))
}
fn legacy_ready(guard: &Guard, secured: bool) -> R {
    let found = run(guard.device().scan(scan_request()), service)?
        .map_err(|_| "API89 actual passive scan")?;
    require(
        found.len() == 1 && found[0].bssid == AP,
        "API89 actual RFH BSS identity",
    )?;
    run(
        guard
            .device()
            .associate_in_domain(request(secured), &policy()),
        service,
    )?
    .map_err(|_| "API89 native association")?;
    carrier(guard.device(), true)
}
fn smoke_api89_ty_so_cdb_and_ma_native_open_wpa2_dhcp_and_terminal_retirement() -> TestResult {
    check(|| {
        for case in [
            Case::Ty,
            Case::So,
            Case::SoLong,
            Case::SoImr,
            Case::SoCdb,
            Case::Ma,
        ] {
            for secured in [false, true] {
                let guard = setup(case, secured, None, None, Fault::None)?;
                legacy_ready(&guard, secured)?;
                let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                    .map_err(|_| "API89 actual kernel DORA")?;
                require(NETWORK.matches_lease(&lease), "API89 actual DHCP lease")?;
                let exact = {
                    let slot = HARNESS.lock();
                    let wire = &slot.as_ref().unwrap().1;
                    wire.rx_queues.len() == 2
                        && wire
                            .commands
                            .iter()
                            .any(|(g, c, b)| (*g, *c) == (5, 8) && b.len() == 32)
                        && wire
                            .commands
                            .iter()
                            .any(|(g, c, b)| (*g, *c) == (3, 10) && b.len() == 96)
                        && wire
                            .commands
                            .iter()
                            .any(|(g, c, b)| (*g, *c) == (5, 0xf) && b.len() == 28)
                        && (!secured
                            || wire
                                .commands
                                .iter()
                                .any(|(g, c, b)| (*g, *c) == (5, 2) && word(b, 12) == 0x10000))
                };
                require(exact, "API89 actual profile/queue/key-prefix transcript")?;
                run(guard.device().disassociate(), service)?
                    .map_err(|_| "API89 native disconnect")?;
                carrier(guard.device(), false)?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/api89",
    smoke_api89_ty_so_cdb_and_ma_native_open_wpa2_dhcp_and_terminal_retirement
);

fn smoke_api89_he20_40_80_native_sta1_tlc4_and_cdb_lmac_fifo_amsdu() -> TestResult {
    check(|| {
        for (case, width) in [(Case::Ty, 0), (Case::So, 1), (Case::SoCdb, 2)] {
            let phy = PhyModel {
                width,
                streams: 2,
                rates: 2,
                mcc_he: true,
                response_he: true,
            };
            let mut memory = tx_amsdu_tests::profile(true, case.cdb());
            if case.cdb() {
                for lmac in 0..2 {
                    for fifo in 0..8 {
                        let at = 40 + lmac * 72 + fifo * 4;
                        memory.memory[at..at + 4].copy_from_slice(&256u32.to_le_bytes());
                    }
                }
                memory.memory[132..136].copy_from_slice(&4096u32.to_le_bytes());
            }
            let guard = setup(case, true, Some(phy), Some(memory), Fault::None)?;
            tx_amsdu_tests::ready(&guard, phy, true)?;
            let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                .map_err(|_| "API89 HE actual DORA")?;
            require(NETWORK.matches_lease(&lease), "API89 HE DHCP lease")?;
            tx_amsdu_tests::enable(&guard)?;
            let first = tx_amsdu_tests::packet(0x51, 200, false);
            let second = tx_amsdu_tests::packet(0x52, 300, false);
            tx_amsdu_tests::pair(&guard, &first, &second)?;
            let native = {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                let peer = &wire
                    .commands
                    .iter()
                    .rev()
                    .find(|(g, c, _)| (*g, *c) == (3, 10))
                    .ok_or("API89 HE peer absent")?
                    .2;
                let tlc = &wire
                    .commands
                    .iter()
                    .rev()
                    .find(|(g, c, _)| (*g, *c) == (5, 0xf))
                    .ok_or("API89 HE TLC absent")?
                    .2;
                let link = &wire
                    .commands
                    .iter()
                    .rev()
                    .find(|(g, c, _)| (*g, *c) == (3, 9))
                    .ok_or("API89 HE link absent")?
                    .2;
                let phy_body = &wire
                    .commands
                    .iter()
                    .rev()
                    .find(|(g, c, _)| (*g, *c) == (1, 8))
                    .ok_or("API89 HE PHY absent")?
                    .2;
                peer.len() == 96
                    && word(peer, 92) & 1 != 0
                    && tlc.len() == 28
                    && tlc[..4] == [0; 4]
                    && tlc[4] == width
                    && tlc[5] == 3
                    && tlc[6] == 3
                    && half(tlc, 12) == 0xff
                    && half(tlc, 18) == 0xff
                    && word(link, 152) & 3 == word(link, 148) & 3
                    && word(phy_body, 16) == u32::from(case.cdb() && phy.channel() > 14)
                    && wire.aggregates.as_slice() == [vec![first, second]]
            };
            require(
                native,
                "API89 native HE/TLC4/MVM1/CDB/FIFO/plaintext A-MSDU transcript",
            )?;
            run(guard.device().disassociate(), service)?
                .map_err(|_| "API89 HE ordered retirement")?;
            carrier(guard.device(), false)?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/api89",
    smoke_api89_he20_40_80_native_sta1_tlc4_and_cdb_lmac_fifo_amsdu
);

#[cfg(feature = "kernel-test")]
fn smoke_api89_held_native_key_source_revoke_keeps_all_ring_prefixes_closed() -> TestResult {
    check(|| {
        let guard = setup(Case::Ty, true, None, None, Fault::HoldRxFence)?;
        let found = run(guard.device().scan(scan_request()), service)?
            .map_err(|_| "API89 held-key discovery")?;
        require(found.len() == 1, "API89 held-key BSS absent")?;
        let domain = policy();
        let mut join = Box::pin(guard.device().associate_in_domain(request(true), &domain));
        let mut cx = Context::from_waker(Waker::noop());
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            require(
                join.as_mut().poll(&mut cx).is_pending(),
                "API89 port opened before native key prefix",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held_rx.is_some() {
                break;
            }
            if deadline.expired() {
                return Err("API89 held-key progress bound");
            }
            narf_scheduler::sleep_pumps::run();
        }
        drop(join);
        carrier(guard.device(), false)?;
        guard.device().source.revoke_model_pci();
        for _ in 0..8 {
            drain();
            let _ = service();
        }
        let state = guard
            .device()
            .state
            .try_lock()
            .ok_or("API89 revoked retained state")?;
        require(
            state.hardware.is_failed()
                && !guard.device().link_up()
                && model::retained(&state.hardware).1 > 0
                && state.hardware.receive_queue_count() == 3
                && state.hardware.receive_capture_epoch().is_none(),
            "API89 revoked key owner reopened port or freed uncertain DMA",
        )
    })
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/wireless/iwlwifi/api89",
    smoke_api89_held_native_key_source_revoke_keeps_all_ring_prefixes_closed
);

fn smoke_api89_and_sc_global_mcc_width_caps_bound_every_programmed_station_span() -> TestResult {
    check(|| {
        for api89 in [false, true] {
            let phy = PhyModel {
                width: 2,
                streams: 2,
                rates: if api89 { 2 } else { 3 },
                mcc_he: true,
                response_he: true,
            };
            let guard = if api89 {
                setup(Case::Ty, true, Some(phy), None, Fault::None)?
            } else {
                Box::new(Guard::build(true, Fault::None, None, None, Some(phy))?)
            };
            HARNESS.lock().as_mut().unwrap().1.mcc_caps_override = Some(0);
            tx_amsdu_tests::ready(&guard, phy, true)?;
            let maximum = if api89 { 0 } else { 1 };
            let bounded = {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                wire.commands
                    .iter()
                    .filter(|(g, c, _)| (*g, *c) == (1, 8))
                    .all(|(_, _, body)| body[13] <= maximum)
                    && wire
                        .commands
                        .iter()
                        .filter(|(g, c, _)| (*g, *c) == (5, 0xf))
                        .all(|(_, _, body)| {
                            body[if api89 { 4 } else { 8 }] <= maximum
                                && body[if api89 { 5 } else { 9 }] != 3
                        })
                    && wire
                        .commands
                        .iter()
                        .filter(|(g, c, _)| (*g, *c) == (3, 8))
                        .all(|(_, _, body)| body[24] == 0)
            };
            require(
                bounded,
                "native MCC global width cap was replaced by per-channel width facts",
            )?;
            let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                .map_err(|_| "native narrowed MCC actual DORA")?;
            require(
                NETWORK.matches_lease(&lease),
                "native narrowed MCC DHCP lease",
            )?;
            run(guard.device().disassociate(), service)?
                .map_err(|_| "native narrowed MCC retirement")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/api89",
    smoke_api89_and_sc_global_mcc_width_caps_bound_every_programmed_station_span
);
