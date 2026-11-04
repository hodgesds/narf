//! Exact native TX v9 command/TFH bytes, independent AP subframe decode,
//! hardware-key simulation and terminal owned-data completion.
use super::super::super::mvm_boot::feature_bits;
use super::*;

fn packet(tag: &[u8]) -> Vec<u8> {
    udp_ipv4(
        AP,
        OWN,
        NETWORK.lease_ip,
        NETWORK.server_ip,
        5000,
        5001,
        tag,
    )
}
fn fixture(protected: bool, qos: bool) -> Result<Harness, &'static str> {
    Harness::build_features(
        protected,
        true,
        5,
        3,
        false,
        false,
        feature_bits::TX_AMSDU | if qos { feature_bits::QOS_TIDS } else { 0 },
    )
}
fn enqueue(h: &Harness, frames: &[Vec<u8>]) -> Result<(), &'static str> {
    for frame in frames {
        h.device
            .enqueue(frame, narf_net::TxMeta::default())
            .map_err(|_| "A-MSDU input ring admission")?;
    }
    Ok(())
}
fn smoke_mvm_tx_amsdu_native_open_wpa2_tlc_fifo_and_single_completion() -> TestResult {
    check(|| {
        for protected in [false, true] {
            let h = fixture(protected, false)?;
            h.join()?;
            let frames = vec![packet(b"first"), packet(b"second")];
            enqueue(&h, &frames)?;
            h.pump()?;
            let actor = h.actor.lock();
            if actor.security.data != frames || actor.amsdu_packets.len() != 1 {
                return Err("native A-MSDU did not deliver exact subframes over one MPDU");
            }
            let raw = &actor.amsdu_packets[0];
            let length = usize::from(u16::from_le_bytes([raw[4], raw[5]]));
            let second = 50 + (frames[0].len() + 8).next_multiple_of(4);
            if raw[6..8] != [0, 0x4d]
                || raw[24..26] != [0x88, if protected { 0x41 } else { 1 }]
                || raw[40..46] != AP
                || raw[48..50] != [0x80, 0]
                || raw[50..62] != frames[0][..12]
                || raw[62..64] != ((frames[0].len() - 6) as u16).to_be_bytes()
                || raw[second..second + 12] != frames[1][..12]
                || raw.len() != 24 + length
            {
                return Err("native A-MSDU TXWD header/offload/length/padding/subframes");
            }
            drop(actor);
            if !h.device.link_up() || h.retained().2 != 0 {
                return Err("A-MSDU terminal receipt left DMA or closed port");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/tx_amsdu",
    smoke_mvm_tx_amsdu_native_open_wpa2_tlc_fifo_and_single_completion
);

fn smoke_mvm_tx_amsdu_requires_program_and_live_tlc_and_routes_qos_tid() -> TestResult {
    check(|| {
        for program in [false, true] {
            let h = if program {
                fixture(false, false)?
            } else {
                Harness::profile(false, true)?
            };
            h.join()?;
            let mut feedback = [
                0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 0,
            ];
            if !program {
                feedback[12..16].copy_from_slice(&3839u32.to_le_bytes());
            }
            h.actor.lock().inject(0xf7, 5, 0x8000, &feedback);
            h.device.step(None);
            let frames = vec![packet(b"one"), packet(b"two")];
            enqueue(&h, &frames)?;
            h.pump()?;
            if !h.actor.lock().amsdu_packets.is_empty() || h.actor.lock().security.data != frames {
                return Err(
                    "A-MSDU emitted without program/current TLC grant or lost fallback packets",
                );
            }
        }
        let h = fixture(false, true)?;
        h.join()?;
        let mut frames = vec![packet(b"tid5-first"), packet(b"tid5-second")];
        for frame in &mut frames {
            frame[15] = 160; // CS5 -> 802.1D UP5.
            frame[24..26].fill(0);
            let mut sum: u32 = frame[14..34]
                .chunks_exact(2)
                .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
                .sum();
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            frame[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
        }
        enqueue(&h, &frames)?;
        h.pump()?;
        let actor = h.actor.lock();
        if actor.security.data != frames
            || actor.amsdu_packets.len() != 1
            || actor.amsdu_packets[0][48] != 0x85
            || actor
                .tid_frames
                .iter()
                .any(|(tid, queue, _)| *tid != 5 || *queue != 29)
        {
            return Err("A-MSDU did not preserve current TID/AC/DQA mapping");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/tx_amsdu",
    smoke_mvm_tx_amsdu_requires_program_and_live_tlc_and_routes_qos_tid
);

fn smoke_mvm_tx_amsdu_power_revocation_keeps_uncertain_native_frame() -> TestResult {
    check(|| {
        let h = fixture(false, false)?;
        h.join()?;
        h.actor.lock().hold_amsdu = true;
        enqueue(&h, &[packet(b"held-one"), packet(b"held-two")])?;
        let mut held = false;
        for _ in 0..64 {
            h.device.step(None);
            h.actor.lock().serve()?;
            if h.actor.lock().held.is_some() {
                held = true;
                break;
            }
        }
        if !held {
            return Err("A-MSDU fixture did not retain native receipt");
        }
        h.power.revoke();
        h.actor.lock().release();
        h.pump()?;
        if h.device.link_up()
            || !h.device.terminal.load(Ordering::Acquire)
            || h.retained().2 != 1
            || h.actor.lock().amsdu_packets.len() != 1
        {
            return Err("revoked A-MSDU publication reopened carrier or discarded ambiguous DMA");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/tx_amsdu",
    smoke_mvm_tx_amsdu_power_revocation_keeps_uncertain_native_frame
);
