// SPDX-License-Identifier: GPL-2.0-or-later
//! Composed station -> EDMA -> associated-beacon RSSI -> MCI weights.
//! A test-only helper binds a DMA-observed candidate; this does not claim
//! an over-air authentication/association exchange.
use super::*;
use crate::ath9k::station;

const AUDIO: [u32; 4] = [0xffff_ff01, 0xffff_ffff, 0xffff_ff01, 0xffff_ffff];
type AudioRadio<'a> = station::Radio<&'a Model, Arc<station::tests::Env>, Packet<&'a Model>>;

fn audio_radio<'a>(model: &'a Model, link: SharedMciLink) -> Result<AudioRadio<'a>, &'static str> {
    // SAFETY: isolated parked model and exclusive coherent allocations.
    let packet = unsafe { Packet::prepare(model, LOCAL, link) }.map_err(|_| "audio prepare")?;
    *model.signal.borrow_mut() = Some(crate::ath9k::irq::Signal::new());
    let env = Arc::new(station::tests::Env {
        now: core::sync::atomic::AtomicU64::new(0),
        entropy: core::sync::atomic::AtomicBool::new(true),
    });
    let mut radio = station::Radio::new(packet, LOCAL, -95, env);
    radio.start().map_err(|_| "audio station start")?;
    radio.poll().map_err(|_| "audio first period")?;
    Ok(radio)
}

fn radio_receive(
    model: &Model,
    radio: &mut AudioRadio<'_>,
    bytes: &[u8],
    rssi: i8,
    crc: bool,
) -> Result<(), &'static str> {
    let address = model.lp.borrow()[0];
    model.receive(false, bytes, false);
    model.put(address + 20, u32::from(rssi as u8) << 24);
    if crc {
        model.put(address + 44, 5); // AR_RxDone | AR_CRCErr, no frame-ok.
    }
    radio.poll().map_err(|_| "audio native receive")?;
    Ok(())
}

fn radio_period(model: &Model, radio: &mut AudioRadio<'_>, at: u64) -> Result<(), &'static str> {
    model.now.set(at);
    radio.poll().map_err(|_| "audio period")?;
    Ok(())
}

fn audio_admission_and_filter(chip: Chip) -> Result<(), &'static str> {
    let model = Model::new();
    let link = live_link(&model, chip)?;
    let mut radio = audio_radio(&model, link.clone())?;
    let beacon = station::tests::Peer::new_rates(false, None).beacon();
    // A passive observation is cached, then this fixture binds that exact
    // candidate. The following observations use the real Radio::cache path.
    radio_receive(&model, &mut radio, &beacon, 0, false)?;
    station::tests::bind_cached_peer_for_mci(&mut radio, station::tests::AP)?;
    radio_receive(&model, &mut radio, &beacon, 40, false)?;
    model.now.set(1);
    gpm(&model, &link, 0, [0x0002_050c, 0x0001_0101, 0]);
    radio.poll().map_err(|_| "A2DP GPM")?;
    clear_irq(&model);
    if weights(&model) != LOW {
        return Err("strong A2DP initial weights");
    }
    let mut foreign = beacon.clone();
    foreign[10..16].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    foreign[16..22].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    let mut probe = beacon.clone();
    probe[0] = 0x50;
    probe[4..10].copy_from_slice(&LOCAL);
    for bytes in [&foreign[..], &probe[..], &beacon[..30]] {
        for _ in 0..6 {
            radio_receive(&model, &mut radio, bytes, 0, false)?;
        }
    }
    for _ in 0..6 {
        radio_receive(&model, &mut radio, &beacon, 0, true)?;
        radio_receive(&model, &mut radio, &beacon, i8::MIN, false)?;
    }
    for n in 1..=5 {
        radio_period(&model, &mut radio, 1 + n * 20_000)?;
        if weights(&model) != LOW {
            return Err("foreign/CRC/probe/short/bad-RSSI observation trained audio");
        }
    }
    // Source fixed-point LPF from 40 with one zero sample per period:
    // rounded RSSI 36,32,29,26,24. Weak counting begins in period five,
    // so AUDIO first appears in period nine. Duplicate sampling fails it.
    for n in 0..9 {
        let at = 120_001 + n * 20_000;
        if n < 5 {
            model.now.set(at - 1);
            radio_receive(&model, &mut radio, &beacon, 0, false)?;
        }
        radio_period(&model, &mut radio, at)?;
        if weights(&model) != if n == 8 { AUDIO } else { LOW } {
            return Err("source beacon LPF or fifth weak-period AUDIO boundary");
        }
    }
    // Temporary AUDIO must not replace the configured LOW no-stomp rule.
    radio_period(&model, &mut radio, 290_001)?;
    if weights(&model) != NONE {
        return Err("AUDIO changed configured LOW no-stomp behavior");
    }
    radio_period(&model, &mut radio, 300_001)?;
    if weights(&model) != LOW {
        return Err("AUDIO did not return to configured weights");
    }
    radio.stop().map_err(|_| "audio stop")?;
    Ok(())
}

fn smoke_ath9k_ar9462_mci_native_audio_rssi() -> TestResult {
    match audio_admission_and_filter(Chip::Ar9462) {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
fn smoke_ath9k_ar9565_mci_native_audio_rssi() -> TestResult {
    match audio_admission_and_filter(Chip::Ar9565) {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

fn audio_history() -> Result<(), &'static str> {
    let model = Model::new();
    let link = live_link(&model, Chip::Ar9462)?;
    let mut radio = audio_radio(&model, link.clone())?;
    let beacon = station::tests::Peer::new_rates(false, None).beacon();
    radio_receive(&model, &mut radio, &beacon, 25, false)?;
    station::tests::bind_cached_peer_for_mci(&mut radio, station::tests::AP)?;
    radio_receive(&model, &mut radio, &beacon, 25, false)?;
    model.now.set(1);
    // SCO/voice, T=12. Like A2DP, its single-profile period is 20 ms.
    gpm(&model, &link, 0, [0x0005_050c, 0x0001_0101, 12]);
    radio.poll().map_err(|_| "SCO GPM")?;
    clear_irq(&model);
    for n in 1..=3 {
        radio_period(&model, &mut radio, 1 + n * 20_000)?;
        if weights(&model) != LOW {
            return Err("SCO selected AUDIO before fifth period");
        }
    }
    // Source pause/resume cancels deadlines, retaining the four weak
    // periods. A resumed immediate period is therefore the fifth.
    link.lock().pause_duty_cycle();
    link.lock().resume_duty_cycle();
    radio_period(&model, &mut radio, 60_002)?;
    if weights(&model) != AUDIO {
        return Err("timer pause/resume discarded audio history or RSSI=25");
    }
    for at in [80_002, 100_002, 120_002, 140_002] {
        radio_period(&model, &mut radio, at)?;
        if weights(&model) != LOW {
            return Err("SCO weak period after AUDIO");
        }
    }
    // One associated 40 sample moves the LPF from 25 to 27 and must
    // clear the four weak periods, not select AUDIO at this boundary.
    model.now.set(160_001);
    radio_receive(&model, &mut radio, &beacon, 40, false)?;
    radio_period(&model, &mut radio, 160_002)?;
    if weights(&model) != LOW {
        return Err("strong associated RSSI did not clear weak-period count");
    }
    model.now.set(180_001);
    radio_receive(&model, &mut radio, &beacon, 0, false)?; // LPF -> 24.
    for at in [180_002, 200_002, 220_002, 240_002] {
        radio_period(&model, &mut radio, at)?;
        if weights(&model) != LOW {
            return Err("weak period count did not restart after strong RSSI");
        }
    }
    radio_period(&model, &mut radio, 260_002)?;
    if weights(&model) != AUDIO {
        return Err("fifth weak period after strong RSSI");
    }
    for at in [280_002, 300_002, 320_002] {
        radio_period(&model, &mut radio, at)?;
    }
    // Removing the audio profile must neither increment nor erase its
    // three-period history, even across delayed period service.
    model.now.set(331_000);
    gpm(&model, &link, 1, [0x0005_050c, 0x0001_0100, 12]);
    radio.poll().map_err(|_| "SCO stop GPM")?;
    clear_irq(&model);
    for at in [431_000, 532_000] {
        radio_period(&model, &mut radio, at)?;
        if weights(&model) != LOW {
            return Err("non-audio profile trained AUDIO");
        }
    }
    model.now.set(533_000);
    gpm(&model, &link, 2, [0x0005_050c, 0x0001_0101, 12]);
    radio.poll().map_err(|_| "SCO restart GPM")?;
    clear_irq(&model);
    if weights(&model) != LOW {
        return Err("profile restart did not retain three-period history");
    }
    radio_period(&model, &mut radio, 553_000)?;
    if weights(&model) != AUDIO {
        return Err("non-audio periods cleared or incremented audio history");
    }
    for at in [573_000, 593_000, 613_000, 633_000] {
        radio_period(&model, &mut radio, at)?;
    }
    let mut successor = beacon.clone();
    let next_ap = [2, 0, 0, 0, 0, 2];
    successor[10..16].copy_from_slice(&next_ap);
    successor[16..22].copy_from_slice(&next_ap);
    model.now.set(633_001);
    radio_receive(&model, &mut radio, &successor, 0, false)?;
    station::tests::bind_cached_peer_for_mci(&mut radio, next_ap)?;
    // Association reset installs the source RSSI marker (127), so a
    // new peer cannot consume the old peer's weak RSSI or four periods.
    radio_period(&model, &mut radio, 653_000)?;
    if weights(&model) != LOW {
        return Err("new association reused prior peer RSSI");
    }
    model.now.set(672_999);
    radio_receive(&model, &mut radio, &successor, 25, false)?;
    for at in [673_000, 693_000, 713_000, 733_000] {
        radio_period(&model, &mut radio, at)?;
        if weights(&model) != LOW {
            return Err("new associated RSSI counter boundary");
        }
    }
    radio_period(&model, &mut radio, 753_000)?;
    if weights(&model) != AUDIO {
        return Err("new associated beacon did not replace RSSI marker");
    }
    radio.stop().map_err(|_| "audio history stop")?;
    Ok(())
}

fn smoke_ath9k_mci_native_audio_history() -> TestResult {
    match audio_history() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9462_mci_native_audio_rssi
);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9565_mci_native_audio_rssi
);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_mci_native_audio_history
);
