//! Actual coherent RX-ring prefix/copy boundaries. Capture specifications
//! are private observation fixtures; the native Session cases separately
//! prove the current real WDEV/admin/source/CNM composition before opening.
use super::*;
use crate::mt7921::firmware_transport::p2p_management_capture::Spec;
fn frame(local: [u8; 6], tag: u8) -> Vec<u8> {
    let mut frame = vec![0; 30];
    frame[0] = 0xd0;
    frame[4..10].copy_from_slice(&local);
    frame[10..16].copy_from_slice(&[2, 0, 0, 0, 0x79, 0xe1]);
    frame[16..22].fill(0xff);
    frame[24..].copy_from_slice(&[4, tag, 0x50, 0x6f, 0x9a, 9]);
    let mut packet = vec![0; 32 + frame.len()];
    let length = packet.len();
    packet[..4].copy_from_slice(&(2u32 << 27 | length as u32).to_le_bytes());
    packet[4..8].copy_from_slice(&(1u32 << 13 | 0x3ff).to_le_bytes());
    packet[8..12].copy_from_slice(&(1u32 << 30).to_le_bytes());
    packet[12..16].copy_from_slice(&(1u32 << 16 | 1 << 8).to_le_bytes());
    packet[28..32].copy_from_slice(&0x6464u32.to_le_bytes());
    packet[32..].copy_from_slice(&frame);
    packet
}
fn native() -> Result<(), &'static str> {
    let (mut words, mut hw) = rig().map_err(|_| "native management RX-ring fixture")?;
    hw.owner.published = true;
    let local = [2, 0, 0, 0, 0x79, 0xa1];
    let first = Spec {
        epoch: 0x7600_0001,
        filters: 1,
        cookie: 1,
        frequency_mhz: 2412,
        expires_ns: u64::MAX,
        local,
        vif: crate::mt7921::vif_slots::Vif::new(1).map_err(|_| "actual native VIF geometry")?,
        nss: 1,
    };
    {
        let storage = hw.owner.storage.as_mut().ok_or("native storage")?;
        storage.receive_epoch = 77;
        storage.receive_open = false;
    }
    let old = frame(local, 1);
    inject_rx(&mut words, &hw, 0, &old);
    let mut event = vec![0; 36];
    event[..4].copy_from_slice(&(7u32 << 27 | 36).to_le_bytes());
    event[28] = 0x55;
    inject_rx(&mut words, &hw, 1, &event);
    hw.configure_p2p_capture(Some(first))
        .map_err(|_| "native completed prefix before first management epoch")?;
    if hw
        .receive_p2p_management()
        .map_err(|_| "post-cut control queue")?
        .is_some()
        || hw.owner.storage.as_ref().unwrap().pending_data.len() != 1
        || !hw
            .owner
            .storage
            .as_ref()
            .unwrap()
            .pending_data
            .iter()
            .all(|packet| packet.epoch == 77 && !packet.port_open)
        || Backend::receive(&mut hw).map_err(|_| "preserved native command event")? != Some(event)
    {
        return Err(
            "new management capture grafted old native prefix or dropped home/event ownership",
        );
    }
    let fresh = frame(local, 2);
    inject_rx(&mut words, &hw, 0, &fresh);
    let copied = hw
        .receive_p2p_management()
        .map_err(|_| "fresh native management descriptor")?
        .ok_or("fresh captured descriptor")?;
    if copied.spec != first
        || copied.packet != fresh
        || hw.owner.storage.as_ref().unwrap().receive_open
    {
        return Err("actual native copy lost its private epoch or opened a station port");
    }
    let queued = frame(local, 3);
    inject_rx(&mut words, &hw, 0, &queued);
    let _ = hw
        .route_rx(None)
        .map_err(|_| "old management host queue copy")?;
    let prefix = frame(local, 4);
    inject_rx(&mut words, &hw, 0, &prefix);
    let second = Spec {
        epoch: first.epoch + 1,
        filters: 2,
        ..first
    };
    hw.configure_p2p_capture(Some(second))
        .map_err(|_| "replacement management epoch with native prefix")?;
    if hw
        .receive_p2p_management()
        .map_err(|_| "old queued/prefix capture after replace")?
        .is_some()
        || !hw
            .owner
            .storage
            .as_ref()
            .unwrap()
            .pending_data
            .iter()
            .any(|packet| packet.bytes == prefix && packet.epoch == 77 && !packet.port_open)
    {
        return Err(
            "new filter/source epoch inherited old host/native copies or rewrote home admission",
        );
    }
    let latest = frame(local, 5);
    inject_rx(&mut words, &hw, 0, &latest);
    let copied = hw
        .receive_p2p_management()
        .map_err(|_| "new generation actual descriptor")?
        .ok_or("new generation raw copy")?;
    if copied.spec != second || copied.packet != latest {
        return Err("native descriptor did not use replacement epoch");
    }
    let expired = Spec {
        epoch: second.epoch + 1,
        expires_ns: 0,
        ..second
    };
    if hw.configure_p2p_capture(Some(expired)) != Err(Error::Busy) {
        return Err("expired grant opened capture");
    }
    inject_rx(&mut words, &hw, 0, &frame(local, 6));
    if hw
        .receive_p2p_management()
        .map_err(|_| "closed copy after expired open refusal")?
        .is_some()
    {
        return Err("failed replacement revived an older management capture");
    }
    hw.owner.published = false;
    Ok(())
}
fn mt76_p2p_native_management_capture_cuts_real_ring_prefix_and_keeps_home_copy_facts() -> TestResult
{
    native().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
kernel_test_in!(
    "drivers/wireless/mt7921/p2p",
    mt76_p2p_native_management_capture_cuts_real_ring_prefix_and_keeps_home_copy_facts
);
