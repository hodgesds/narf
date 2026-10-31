//! Exact Bz core103 native conversations. Firmware execution is modeled.
use super::super::super::bz_fixture::Case;
use super::*;

#[inline(never)]
fn setup(
    case: Case,
    secured: bool,
    phy: Option<PhyModel>,
    tx: Option<TxModel>,
    fault: Fault,
) -> R<Box<Guard>> {
    Ok(Box::new(Guard::build_native_profile(
        secured,
        fault,
        None,
        None,
        phy,
        NativeModel {
            receive_model: ReceiveModel::NativeSc,
            tx_model: tx,
            api89: None,
            bz: Some(case),
        },
    )?))
}
fn ready(guard: &Guard, secured: bool) -> R {
    scan(guard.device())?;
    run(
        guard
            .device()
            .associate_in_domain(request(secured), &policy()),
        service,
    )?
    .map_err(|_| "Bz core103 actual station association")?;
    carrier(guard.device(), true)
}
fn smoke_bz_core103_exact_fm_wh_discrete_integrated_open_wpa2_dhcp_and_retirement() -> TestResult {
    check(|| {
        for case in [
            Case::FmDiscrete,
            Case::WhDiscrete,
            Case::FmIntegrated,
            Case::WhIntegrated,
        ] {
            for secured in [false, true] {
                let guard = setup(case, secured, None, None, Fault::None)?;
                ready(&guard, secured)?;
                let lease = narf_net::dhcp::dhcp_acquire(guard.device().name(), 0)
                    .map_err(|_| "Bz actual kernel DORA")?;
                require(NETWORK.matches_lease(&lease), "Bz actual DHCP lease")?;
                let actual = {
                    let slot = HARNESS.lock();
                    let wire = &slot.as_ref().unwrap().1;
                    wire.rx_queues.len() == 2
                        && wire
                            .commands
                            .iter()
                            .any(|(g, c, b)| (*g, *c) == (3, 10) && b.len() == 104)
                        && wire
                            .commands
                            .iter()
                            .any(|(g, c, b)| (*g, *c) == (5, 0xf) && b.len() == 44)
                        && wire
                            .commands
                            .iter()
                            .any(|(g, c, b)| (*g, *c) == (2, 1) && b.as_slice() == case.soc())
                };
                require(actual, "Bz actual MAC/STA/TLC/SoC/RFH source transcript")?;
                run(guard.device().disassociate(), service)?
                    .map_err(|_| "Bz actual ordered disconnect")?;
                carrier(guard.device(), false)?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/bz103",
    smoke_bz_core103_exact_fm_wh_discrete_integrated_open_wpa2_dhcp_and_retirement
);

fn smoke_bz_core103_he20_40_80_actual_tlc6_smem_and_plaintext_amsdu() -> TestResult {
    check(|| {
        for (case, width) in [
            (Case::FmDiscrete, 0),
            (Case::WhDiscrete, 1),
            (Case::FmIntegrated, 2),
        ] {
            let phy = PhyModel {
                width,
                streams: 2,
                rates: 3,
                mcc_he: true,
                response_he: true,
            };
            let guard = setup(
                case,
                true,
                Some(phy),
                Some(tx_amsdu_tests::profile(true, false)),
                Fault::None,
            )?;
            tx_amsdu_tests::ready(&guard, phy, true)?;
            tx_amsdu_tests::enable(&guard)?;
            let first = tx_amsdu_tests::packet(0x61, 200, false);
            let second = tx_amsdu_tests::packet(0x62, 300, false);
            tx_amsdu_tests::pair(&guard, &first, &second)?;
            let exact = {
                let slot = HARNESS.lock();
                let wire = &slot.as_ref().unwrap().1;
                wire.aggregates.as_slice() == [vec![first, second]]
                    && wire
                        .commands
                        .iter()
                        .any(|(g, c, b)| (*g, *c) == (2, 0) && b.is_empty())
                    && wire
                        .commands
                        .iter()
                        .rev()
                        .find(|(g, c, _)| (*g, *c) == (5, 0xf))
                        .is_some_and(|(_, _, b)| b.len() == 44 && b[8] == width && b[9] == 3)
            };
            require(exact, "Bz native HE/FIFO/plaintext aggregate transcript")?;
            run(guard.device().disassociate(), service)?.map_err(|_| "Bz HE retirement")?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/bz103",
    smoke_bz_core103_he20_40_80_actual_tlc6_smem_and_plaintext_amsdu
);

fn smoke_bz_core103_native_sae24_pmf_and_psk_pmf_key_receipts_and_dhcp() -> TestResult {
    check(|| {
        for case in [Case::FmDiscrete, Case::WhIntegrated] {
            for sae in [false, true] {
                let guard = setup(case, true, None, None, Fault::None)?;
                let akm = if sae { 24 } else { 6 };
                let ap = if sae {
                    security_tests::sae_ap(akm, narf_wifi_fixtures::ApSaePwe::HashToElement)?
                } else {
                    security_tests::psk_ap(akm)?
                };
                security_tests::install_ap(ap);
                HARNESS.lock().as_mut().unwrap().1.sae_h2e_only = sae;
                security_tests::associate(&guard, sae)?;
                security_tests::native_keys(akm)?;
                security_tests::data_after_keys(&guard)?;
                run(guard.device().disassociate(), service)?
                    .map_err(|_| "Bz PMF native retirement")?;
                carrier(guard.device(), false)?;
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/bz103",
    smoke_bz_core103_native_sae24_pmf_and_psk_pmf_key_receipts_and_dhcp
);

#[cfg(feature = "kernel-test")]
fn smoke_bz_core103_source_loss_during_final_real_rx_marker_retains_dma() -> TestResult {
    check(|| {
        let guard = setup(Case::WhDiscrete, true, None, None, Fault::HoldRxFence)?;
        scan(guard.device())?;
        let domain = policy();
        let mut join = Box::pin(guard.device().associate_in_domain(request(true), &domain));
        let deadline = narf_time::Deadline::after_ms(2000);
        loop {
            require(
                join.as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "Bz port passed final native ring marker",
            )?;
            service()?;
            if HARNESS.lock().as_ref().unwrap().1.held_rx.is_some() {
                break;
            }
            if deadline.expired() {
                return Err("Bz final ring marker progress bound");
            }
            narf_scheduler::sleep_pumps::run();
        }
        drop(join);
        guard.device().source.revoke_model_pci();
        for _ in 0..8 {
            let _ = drain();
            let _ = service();
        }
        let state = guard
            .device()
            .state
            .try_lock()
            .ok_or("Bz revoked retained state")?;
        require(
            state.hardware.is_failed()
                && !guard.device().link_up()
                && model::retained(&state.hardware).1 > 0
                && state.hardware.receive_queue_count() == 3
                && state.hardware.receive_capture_epoch().is_none(),
            "Bz source loss reopened epoch or released uncertain DMA",
        )
    })
}
#[cfg(feature = "kernel-test")]
kernel_test_in!(
    "drivers/wireless/iwlwifi/bz103",
    smoke_bz_core103_source_loss_during_final_real_rx_marker_retains_dma
);
