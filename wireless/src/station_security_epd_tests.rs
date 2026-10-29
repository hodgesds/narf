//! EtherType Protocol Discrimination (IEEE802.11-2020 5.1.4) framing of the
//! retained station owner.
use super::*;
fn epd_native(ethertype: u16, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![8, 2, 0, 0];
    frame.extend_from_slice(&OWN);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&AP);
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(body);
    frame
}
fn epd() -> Result<(), &'static str> {
    let mut s = security().with_epd(true);
    // RFC1042-framed EAPOL is not an EPD MSDU.
    if s.receive(&mpdu(native(&key_frame(0x8a, 1, AN, &[], None), false)), SN) != Ok(Rx::Ignored) {
        return Err("LPD EAPOL admitted in EPD mode");
    }
    if s.receive(
        &mpdu(epd_native(0x888e, &key_frame(0x8a, 1, AN, &[], None))),
        SN,
    ) != Ok(Rx::ReplyReady)
    {
        return Err("EPD M1 refused");
    }
    let m2 = s.pending_frame().ok_or("no M2")?.to_vec();
    if m2[24..26] != [0x88, 0x8e] || m2[26] != 1 || m2[27] != 3 {
        return Err("M2 not EPD-framed");
    }
    deliver(&mut s);
    let p = ptk(AN, SN);
    if s.receive(
        &mpdu(epd_native(
            0x888e,
            &key_frame(0x13ca, 2, AN, &kde(GTK), Some(&p)),
        )),
        SN,
    ) != Ok(Rx::ReplyReady)
    {
        return Err("EPD M3 refused");
    }
    deliver(&mut s);
    if !s.port_open() {
        return Err("EPD port closed");
    }
    let mut ethernet = AP.to_vec();
    ethernet.extend_from_slice(&OWN);
    ethernet.extend_from_slice(&[0x08, 0x00, 0x45, 0, 0, 20]);
    let tx = s.transmit_ethernet(&ethernet).map_err(|_| "EPD TX")?;
    if decrypt(&tx, &p.tk) != [0x08, 0x00, 0x45, 0, 0, 20] {
        return Err("EPD data body");
    }
    let rx = encrypt(&epd_native(0x0800, &[0x45, 1, 2]), &p.tk, 1, 0);
    let frame = match s.receive(&mpdu(rx), SN) {
        Ok(Rx::Data(frame)) => frame,
        _ => return Err("EPD data refused"),
    };
    let mut want = OWN.to_vec();
    want.extend_from_slice(&AP);
    want.extend_from_slice(&[0x08, 0x00, 0x45, 1, 2]);
    if s.ethernet(&frame) != Some(want) {
        return Err("EPD Ethernet conversion");
    }
    // A length value is never an EPD EtherType.
    let short = encrypt(&epd_native(0x0040, &[0; 4]), &p.tk, 2, 0);
    if s.receive(&mpdu(short), SN) != Ok(Rx::Ignored) {
        return Err("EPD length field admitted");
    }
    if s.transmit_amsdu_qos(&[&ethernet], 0, crate::amsdu::Limit::Ht3839) != Err(Error::Profile) {
        return Err("RFC1042 A-MSDU transmitted in EPD mode");
    }
    // LPD owners keep RFC1042 conversion.
    let lpd = established();
    let mut lpd_frame = vec![8, 2, 0, 0];
    lpd_frame.extend_from_slice(&OWN);
    lpd_frame.extend_from_slice(&AP);
    lpd_frame.extend_from_slice(&AP);
    lpd_frame.extend_from_slice(&[0, 0, 0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00, 0x45]);
    if lpd.ethernet(&lpd_frame).map(|e| e[12..].to_vec()) != Some(vec![0x08, 0x00, 0x45]) {
        return Err("LPD Ethernet conversion");
    }
    Ok(())
}
fn smoke_station_epd_framing_for_eapol_and_data() -> TestResult {
    match epd() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "wireless/station_security",
    smoke_station_epd_framing_for_eapol_and_data
);
