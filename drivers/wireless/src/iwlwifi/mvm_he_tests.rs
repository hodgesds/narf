//! Native HE command receipts and original +HTC RX geometry, retaining
//! the ordinary firmware-key/PN, controlled-port and measured-power owners.
use super::super::super::mvm_boot::feature_bits;
use super::*;

fn he_ies() -> Vec<u8> {
    let mut ies = ht_ies();
    let cap = [
        35, 1, 0, 0x20, 0, 0, 0, 0, 0x30, 10, 0, 0, 0, 0, 4, 1, 0x30, 0, 0xfc, 0xff, 0xfc, 0xff,
    ];
    ies.extend_from_slice(&[255, cap.len() as u8]);
    ies.extend_from_slice(&cap);
    // HE Operation: PE2, RTS1023, color7, basic NSS1 MCS0..7.
    ies.extend_from_slice(&[255, 7, 36, 0xf2, 0x3f, 0, 7, 0xfc, 0xff]);
    ies
}
fn fixture(protected: bool) -> Result<Harness, &'static str> {
    let h = Harness::build_features(protected, true, 5, 3, false, false, feature_bits::HE)?;
    {
        let mut actor = h.actor.lock();
        actor.beacon_ies = Some(he_ies());
        actor.response_ies = Some(he_ies());
        actor.rx_rate = 0x400; // source rates-v2 HE SU/MCS0/NSS1/20MHz
    }
    Ok(h)
}
fn packet() -> Vec<u8> {
    udp_ipv4(
        OWN,
        AP,
        NETWORK.server_ip,
        NETWORK.lease_ip,
        5000,
        5001,
        b"native HE",
    )
}
fn rx(h: &Harness, pn: u64, control: u8) -> Result<Vec<u8>, &'static str> {
    let mut bytes = if h.actor.lock().protected {
        h.actor
            .lock()
            .security
            .encrypted_rx_profile(&packet(), pn, false, Some(0))?
    } else {
        let mut frame = from_ap(&packet(), pn as u16);
        frame[0] = 0x88;
        frame.splice(24..24, [0, 0]);
        envelope(&frame)
    };
    bytes[48 + 1] |= 0x80 | 8;
    bytes[48 + 22..48 + 24].copy_from_slice(&(((pn as u16) & 4095) << 4).to_le_bytes());
    bytes[48 + 24] |= 0x10; // HE A-Control's EOSP convention
    bytes.splice(48 + 26..48 + 26, [control, 0, 0, 0]);
    let length = u16::from_le_bytes([bytes[0], bytes[1]]) + 4;
    bytes[..2].copy_from_slice(&length.to_le_bytes());
    bytes[16..20].copy_from_slice(&0x7f000000u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&0x400u32.to_le_bytes());
    Ok(bytes)
}
fn receive(h: &Harness, bytes: Vec<u8>) -> Vec<Vec<u8>> {
    h.actor.lock().inject(0xc1, 0, 0x8000, &bytes);
    h.device.step(None).into_iter().map(|p| p.0).collect()
}

fn smoke_mvm_he_native_open_wpa2_context_tlc_and_htc_replay() -> TestResult {
    check(|| {
        for protected in [false, true] {
            let h = fixture(protected)?;
            h.join()?;
            {
                let actor = h.actor.lock();
                let context = actor
                    .commands
                    .iter()
                    .find(|(g, c, _)| *g == 5 && *c == 7)
                    .ok_or("native HE context absent")?;
                let mut expected = [0; 80];
                expected[1] = 1;
                expected[4..8].copy_from_slice(&[0x80, 0x21, 0, 0]);
                expected[16] = 1;
                expected[24..40].fill(7);
                expected[40..44].copy_from_slice(&[7, 2, 0xff, 3]);
                if context.2 != expected {
                    return Err("HE v1 context diverged from fixed native source layout");
                }
                let mac = actor
                    .commands
                    .iter()
                    .find(|(g, c, b)| *g == 3 && *c == 8 && b[24] == 1)
                    .ok_or("native HE MAC support absent")?;
                let link = actor
                    .commands
                    .iter()
                    .find(|(g, c, b)| *g == 3 && *c == 9 && b[24] & 32 != 0)
                    .ok_or("native HE link parameters absent")?;
                let tlc = actor
                    .commands
                    .iter()
                    .find(|(g, c, _)| *g == 5 && *c == 15)
                    .ok_or("HE TLC absent")?;
                if mac.2[32..36] != [1, 0, 0, 0]
                    || link.2[100..104] != [2, 0, 0, 0]
                    || link.2[146..154] != [0xff, 3, 0, 0, 0, 0, 3, 0]
                    || link.2[165] != 7
                    || tlc.2[4..8] != [0, 3, 1, 0]
                    || tlc.2[12..20] != [0xff, 0, 0, 0, 0, 0, 0, 0]
                    || tlc.2[22] != 0
                {
                    return Err("native HE MAC/link/TLC bytes disagree with negotiated subset");
                }
            }
            if receive(&h, rx(&h, 301, 3)?) != [packet()] {
                return Err("native HE +HTC body or CCMP IV offset was not admitted");
            }
            if !receive(&h, rx(&h, 301, 3)?).is_empty() {
                return Err("HE +HTC replay advanced duplicate sequence/PN");
            }
            if !receive(&h, rx(&h, 302, 2)?).is_empty() {
                return Err("HT/VHT HT Control variant entered HE-only native profile");
            }
            if receive(&h, rx(&h, 302, 3)?) != [packet()] {
                return Err("rejected HT Control shape consumed PN or sequence ownership");
            }
            run(h.device.disassociate())?.map_err(|_| "native HE close")?;
            if h.retained() != (0, 0, 0) {
                return Err("HE terminal close retained idle queues");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/he",
    smoke_mvm_he_native_open_wpa2_context_tlc_and_htc_replay
);

fn smoke_mvm_he_requires_sku_program_response_and_retains_context_wait() -> TestResult {
    check(|| {
        let h = Harness::build_nvm_he(false, true, 2, 3, false, false, 0, 0, 1, true)?;
        {
            let mut actor = h.actor.lock();
            actor.beacon_ies = Some(he_ies());
            actor.response_ies = Some(he_ies());
        }
        h.join()?;
        if h.actor
            .lock()
            .commands
            .iter()
            .any(|(g, c, b)| *g == 5 && *c == 7 || *g == 5 && *c == 15 && b[5] == 3)
        {
            return Err("HE emitted under a tag2 program");
        }
        drop(h);
        let h = Harness::build_nvm_he(
            false,
            true,
            5,
            3,
            false,
            false,
            feature_bits::HE,
            0,
            1,
            false,
        )?;
        {
            let mut actor = h.actor.lock();
            actor.beacon_ies = Some(he_ies());
            actor.response_ies = Some(he_ies());
        }
        if h.join().is_ok() || h.device.link_up() {
            return Err("HE selected without native NVM SKU permission");
        }
        drop(h);
        let h = fixture(false)?;
        h.actor.lock().response_ies = Some(ht_ies());
        if h.join().is_ok() || h.device.link_up() {
            return Err("HE response omission left a carrier");
        }
        drop(h);
        let h = fixture(true)?;
        h.scan()?;
        h.actor.lock().hold_phy = Some(14);
        let request = h.request();
        let mut join = Box::pin(h.device.associate(request));
        for _ in 0..256 {
            if once(join.as_mut()).is_ready() {
                return Err("held HE context completed early");
            }
            h.actor.lock().serve()?;
            if h.actor.lock().held.is_some() {
                break;
            }
        }
        if h.actor.lock().held.is_none() || h.device.link_up() {
            return Err("native HE context receipt was not fenced");
        }
        drop(join);
        h.power.revoke();
        h.actor.lock().release();
        h.pump()?;
        if h.device.link_up() || !h.device.terminal.load(Ordering::Acquire) || h.retained().0 != 1 {
            return Err("revoked HE context waiter released uncertain DMA or admitted carrier");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2/he",
    smoke_mvm_he_requires_sku_program_response_and_retains_context_wait
);
