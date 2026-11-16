// SPDX-License-Identifier: GPL-2.0-or-later
//! Exercise the production EDMA owner and DMA GPM walk, with literal
//! Linux `gpio.c` timer boundaries and `btcoex.c` weight images.
use super::super::super::{btcoex, Chip};
use super::*;

const LOW: [u32; 4] = [0x0101_7d01, 0x3b3b_3b01, 0x3b3b_3b01, 0x3b3b_3b3b];
const NONE: [u32; 4] = [0x0101_7d01, 0x0101_0101, 0x0101_0101, 0x0101_0101];
const ALL: [u32; 4] = [0x0101_7d01, 0x4141_4101, 0x4141_4101, 0x4141_4141];

fn weights(model: &Model) -> [u32; 4] {
    [0x18b0, 0x18b4, 0x18b8, 0x18bc].map(|r| model.reg(r))
}
fn weight_writes(model: &Model) -> usize {
    model
        .writes
        .borrow()
        .iter()
        .filter(|&&(r, _)| (0x18b0..=0x18bc).contains(&r))
        .count()
}
fn live_link(model: &Model, chip: Chip) -> Result<SharedMciLink, &'static str> {
    let mut dma = model
        .allocate(mci::MCI_DMA_BUF_BYTES)
        .map_err(|_| "MCI allocation")?;
    dma.as_mut_slice().fill(0xfe);
    let mut state = btcoex::Btcoex::new(chip);
    btcoex::init_scheme(&mut state, true, super::super::super::HW_CAP_MCI);
    btcoex::init_mci(&mut state);
    state.mci.ready = true;
    state.mci.is_2g = true;
    state.mci.gpm_buf.fill(0xfe);
    state.mci.gpm_len = 16;
    state.mci.bt_state = mci::BtState::Awake;
    model.set(mci::AR_BTCOEX_CTRL, mci::AR_BTCOEX_CTRL_MCI_MODE_EN);
    Ok(Arc::new(narf_lib::sync::IrqSafeSpinLock::new(
        btcoex::MciLink::new(state, Some(Arc::new(dma))),
    )))
}
/// Device-side 16-byte coex-agent slot. Caller supplies literal wire words.
fn gpm(model: &Model, link: &SharedMciLink, slot: u32, payload: [u32; 3]) {
    let address = link.lock().dma.as_ref().unwrap().dma_addr().raw() as u32 + 256 + slot * 16;
    for (i, word) in [0, payload[0], payload[1], payload[2]]
        .into_iter()
        .enumerate()
    {
        model.put(address + i as u32 * 4, word);
    }
    model.set(mci::AR_MCI_GPM_1, (slot + 1) << mci::AR_MCI_GPM_WRITE_PTR_S);
    model.set(
        mci::AR_MCI_INTERRUPT_RX_MSG_RAW,
        mci::AR_MCI_INTERRUPT_RX_MSG_GPM,
    );
    model.set(0x4038, 0x80);
}
fn clear_irq(model: &Model) {
    model.set(0x4038, 0);
    model.set(0x1828, 0); // AR_MCI_INTERRUPT_RAW
    model.set(mci::AR_MCI_INTERRUPT_RX_MSG_RAW, 0);
}
fn poll(packet: &mut Packet<&Model>) -> Result<(), &'static str> {
    packet
        .service_begin()
        .map_err(|_| "coexistence service failed")?;
    packet.service_end().map_err(|_| "service_end failed")
}
fn timed_profiles(chip: Chip, pan_no_stomp: u64) -> Result<(), &'static str> {
    let model = Model::new();
    let link = live_link(&model, chip)?;
    // SAFETY: parked isolated model, with its own DMA allocations.
    let mut packet =
        unsafe { Packet::prepare(&model, LOCAL, link.clone()) }.map_err(|_| "prepare")?;
    packet.start().map_err(|_| "start")?;
    // No vector and no IRQ cause: timer service still runs.
    if packet.coex_wait_us() != Some(0) {
        return Err("resume not immediate");
    }
    poll(&mut packet)?;
    if weights(&model) != LOW || packet.coex_wait_us() != Some(20_000) {
        return Err("45ms/55% driver defaults not applied");
    }
    let before = weight_writes(&model);
    model.now.set(19_999);
    poll(&mut packet)?;
    if weight_writes(&model) != before || packet.coex_wait_us() != Some(1) {
        return Err("early timer write");
    }
    model.now.set(20_000);
    poll(&mut packet)?;
    if weights(&model) != NONE || packet.coex_wait_us() != Some(25_000) {
        return Err("default no-stomp edge");
    }
    model.now.set(45_000);
    poll(&mut packet)?;
    if weights(&model) != LOW {
        return Err("second default period");
    }
    let before = weight_writes(&model);
    model.now.set(200_000); // both old deadlines expired
    poll(&mut packet)?;
    if weights(&model) != LOW
        || weight_writes(&model) != before + 4
        || packet.coex_wait_us() != Some(20_000)
    {
        return Err("late service replayed stale edges");
    }
    *model.signal.borrow_mut() = Some(crate::ath9k::irq::Signal::new());
    packet.enable_interrupts().map_err(|_| "interrupts")?;
    // BNEP/PAN, handle 0, start/master/EDR, no voice fields.
    model.now.set(201_000);
    gpm(&model, &link, 0, [0x0004_050c, 0x0001_0101, 0]);
    poll(&mut packet)?;
    clear_irq(&model);
    if weights(&model) != LOW
        || packet.coex_wait_us() != Some(pan_no_stomp)
        || link.lock().btcoex.tx_prio != [52, 0, 52, 0, 0]
    {
        return Err("PAN GPM not applied in the same service pass");
    }
    // The live priority copy feeds the existing concurrent-weight path.
    // Only the fixture enables concurrent TX; production still requires
    // the separate calibrated TX-power/RSSI policy before enabling it.
    link.lock().btcoex.mci.concur_tx = true;
    model.now.set(201_000 + pan_no_stomp);
    poll(&mut packet)?;
    if weights(&model) != [0x0101_7d01, 0x3401_0101, 0x0134_0101, 0x0134_0134]
        || packet.coex_wait_us() != Some(26_000 - pan_no_stomp)
    {
        return Err("PAN no-stomp priority weights or 26ms period");
    }
    // Same profile outputs still rearm; the prior no-stomp is cancelled.
    link.lock().btcoex.mci.concur_tx = false;
    model.now.set(222_000);
    gpm(&model, &link, 1, [0x0004_050c, 0x0001_0101, 0]);
    poll(&mut packet)?;
    clear_irq(&model);
    if weights(&model) != LOW || packet.coex_wait_us() != Some(pan_no_stomp) {
        return Err("equal profile update failed to rearm");
    }
    // Stop PAN, then critical management handle 1 selects ALL (20ms,
    // 55%, no-stomp at 9ms), whose second edge must select LOW.
    gpm(&model, &link, 2, [0x0004_050c, 0x0001_0100, 0]);
    poll(&mut packet)?;
    gpm(&model, &link, 3, [0x0100_060c, 1, 0]);
    poll(&mut packet)?;
    clear_irq(&model);
    if weights(&model) != ALL || packet.coex_wait_us() != Some(9_000) {
        return Err("management stomp-all scheme");
    }
    model.now.set(231_000);
    poll(&mut packet)?;
    if weights(&model) != LOW {
        return Err("ALL did not transition to LOW");
    }
    // Band change disables weights and cancels timed work on 5GHz.
    link.lock().btcoex.mci.is_2g = false;
    poll(&mut packet)?;
    if weights(&model) != NONE || link.lock().btcoex.enabled || packet.coex_wait_us().is_some() {
        return Err("5GHz did not disable duty scheduling");
    }
    let before = weight_writes(&model);
    model.now.set(1_000_000);
    poll(&mut packet)?;
    if weight_writes(&model) != before {
        return Err("5GHz stale timer");
    }
    packet.stop().map_err(|_| "stop")?;
    Ok(())
}
fn mci_duty_profiles_ar9462() -> TestResult {
    match timed_profiles(Chip::Ar9462, 16_000) {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn mci_duty_profiles_ar9565() -> TestResult {
    match timed_profiles(Chip::Ar9565, 15_000) {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

fn lifecycle() -> Result<(), &'static str> {
    let model = Model::new();
    let link = live_link(&model, Chip::Ar9462)?;
    // SAFETY: parked isolated model with exclusive buffers.
    let mut packet =
        unsafe { Packet::prepare(&model, LOCAL, link.clone()) }.map_err(|_| "prepare")?;
    packet.start().map_err(|_| "start")?;
    *model.signal.borrow_mut() = Some(crate::ath9k::irq::Signal::new());
    packet.enable_interrupts().map_err(|_| "interrupts")?;
    poll(&mut packet)?;
    packet.wow_interrupts().map_err(|_| "WoW pause")?;
    let before = weight_writes(&model);
    model.now.set(80_000);
    // Radio holds normal IRQ/DMA service while WoW is armed. Exercise
    // only the timed path here; service_end restores the ordinary mask.
    packet.service_coex().map_err(|_| "WoW timer service")?;
    if packet.coex_wait_us().is_some() || weight_writes(&model) != before {
        return Err("WoW serviced a cancelled deadline");
    }
    packet.restore_interrupts().map_err(|_| "WoW restore")?;
    if packet.coex_wait_us() != Some(0) {
        return Err("WoW restore not rearmed");
    }
    poll(&mut packet)?;
    if weights(&model) != LOW || packet.coex_wait_us() != Some(20_000) {
        return Err("WoW restore reused old no-stomp edge");
    }
    packet.pause_for_reset().map_err(|_| "reset pause")?;
    if link.lock().duty_cycle_wait_us(200_000).is_some() {
        return Err("reset kept timer");
    }
    model.hp.borrow_mut().clear();
    model.lp.borrow_mut().clear();
    model.now.set(200_000);
    packet.resume_after_reset().map_err(|_| "reset resume")?;
    poll(&mut packet)?;
    if weights(&model) != LOW || packet.coex_wait_us() != Some(20_000) {
        return Err("reset reused old no-stomp edge");
    }
    packet.stop().map_err(|_| "stop")?;
    let before = weight_writes(&model);
    if link.lock().duty_cycle_wait_us(400_000).is_some() {
        return Err("stop kept timer");
    }
    let _ = packet.service_begin();
    if weight_writes(&model) != before {
        return Err("stopped owner wrote weights");
    }
    Ok(())
}
fn mci_duty_lifecycle() -> TestResult {
    match lifecycle() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

fn failures() -> Result<(), &'static str> {
    for lose_access in [true, false] {
        let model = Model::new();
        let link = live_link(&model, Chip::Ar9462)?;
        // SAFETY: parked isolated model, no physical hardware.
        let mut packet =
            unsafe { Packet::prepare(&model, LOCAL, link.clone()) }.map_err(|_| "prepare")?;
        packet.start().map_err(|_| "start")?;
        poll(&mut packet)?;
        model.now.set(20_000);
        let before = weight_writes(&model);
        if lose_access {
            model.master.set(false);
        } else {
            model.fail_write.set(Some(0x18b8));
        }
        if !matches!(packet.service_begin(), Err(Error::Access))
            || packet.phase() != Phase::Failed
            || link.lock().duty_cycle_wait_us(100_000).is_some()
        {
            return Err("failed authority/MMIO did not cancel timers and fail owner");
        }
        if weight_writes(&model) != before + if lose_access { 0 } else { 2 } {
            return Err("writes continued past first failed access");
        }
        let before = weight_writes(&model);
        model.now.set(100_000);
        let _ = packet.service_begin();
        if weight_writes(&model) != before {
            return Err("failed owner reused timer");
        }
        model.fail_write.set(None);
        let _ = packet.stop();
    }
    Ok(())
}
fn mci_duty_authority_and_mmio_failure() -> TestResult {
    match failures() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_duty_profiles_ar9462);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_duty_profiles_ar9565);
kernel_test_in!("drivers/wireless/ath9k/ar9003", mci_duty_lifecycle);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    mci_duty_authority_and_mmio_failure
);
