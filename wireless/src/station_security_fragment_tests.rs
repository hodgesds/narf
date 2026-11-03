//! Genuine EAPOL installs/rekeys plus immutable encrypted fragment trains.
use super::*;
fn ethernet() -> Vec<u8> {
    let mut out = vec![0; 1014];
    out[..6].copy_from_slice(&AP);
    out[6..12].copy_from_slice(&OWN);
    out[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    for (i, byte) in out[14..].iter_mut().enumerate() {
        *byte = i as u8;
    }
    out
}
fn train() -> Result<(), &'static str> {
    let mut s = established_with_seed(4095);
    let p = ptk(AN, SN);
    let ethernet = ethernet();
    let before = s.pair.as_ref().unwrap().key.fragment_model_tx_pn();
    let train = s
        .transmit_ethernet_fragments(&ethernet, Some(3), 256)
        .map_err(|_| "fragment train")?;
    let original: Vec<_> = train
        .frames()
        .iter()
        .map(|frame| (frame[22..24].to_vec(), frame[26..].to_vec()))
        .collect();
    let pn_before_nav = s.pair.as_ref().unwrap().key.fragment_model_tx_pn();
    let train = train
        .with_durations(&[1500, 1400, 1300, 1200, 314])
        .map_err(|_| "native NAV projection")?;
    if s.pair.as_ref().unwrap().key.fragment_model_tx_pn() != pn_before_nav
        || !train.current_key()
        || train
            .frames()
            .iter()
            .zip(&original)
            .any(|(frame, (sn, cipher))| frame[22..24] != sn[..] || frame[26..] != cipher[..])
    {
        return Err("NAV builder changed PN/SN/ciphertext/original key identity");
    }

    if !train.current_key()
        || train.frames().len() != 5
        || s.qos_sequence[3] != 0
        || s.sequence != 1
    {
        return Err("MSDU/train count or shared one-SN allocation");
    }
    let mut body = Vec::new();
    let mut replay = crate::ccmp::ReplayWindow {
        last_seen_pn: before,
    };
    for (index, frame) in train.frames().iter().enumerate() {
        let sc = u16::from_le_bytes([frame[22], frame[23]]);
        if sc >> 4 != 4095
            || usize::from(sc & 15) != index
            || (frame[1] & 4 != 0) != (index + 1 < train.frames().len())
        {
            return Err("fragment SN/number/MoreFrag");
        }
        let mut wire = frame[26..].to_vec();
        let plain = crate::ccmp::unprotect(
            &Ccm,
            &frame[..26],
            p.tk.as_slice().try_into().unwrap(),
            3,
            false,
            &mut replay,
            &mut wire,
        )
        .map_err(|_| "fragment AES/MIC/nonce")?;
        body.extend_from_slice(&plain);
        if replay.last_seen_pn != before + index as u64 + 1 {
            return Err("per-fragment PN order");
        }
    }
    if body[..8] != [0xaa, 0xaa, 3, 0, 0, 0, 8, 0] || body[8..] != ethernet[14..] {
        return Err("fragmented MSDU changed");
    }
    for invalid in [vec![], vec![0x8000; 5]] {
        let other = s
            .transmit_ethernet_fragments(&ethernet, Some(4), 256)
            .map_err(|_| "NAV refusal fixture")?;
        let pn = s.pair.as_ref().unwrap().key.fragment_model_tx_pn();
        let sn = s.qos_sequence[4];
        if other.with_durations(&invalid).is_ok()
            || s.pair.as_ref().unwrap().key.fragment_model_tx_pn() != pn
            || s.qos_sequence[4] != sn
            || !train.current_key()
        {
            return Err("NAV count/bit15 refusal mutated key/PN/SN or revived source");
        }
    }
    let count = s.pair.as_ref().unwrap().key.fragment_model_tx_pn();
    let sequence = s.qos_sequence[3];
    if s.transmit_ethernet_fragments(&ethernet, Some(3), 255)
        .is_ok()
        || s.transmit_ethernet_fragments(&ethernet, Some(16), 256)
            .is_ok()
        || s.pair.as_ref().unwrap().key.fragment_model_tx_pn() != count
        || s.qos_sequence[3] != sequence
    {
        return Err("invalid fragment admission consumed PN/SN");
    }
    let new = ptk([0x33; 32], [0x44; 32]);
    if s.receive(
        &mpdu(encrypt(
            &native(&key_frame(0x8a, 3, [0x33; 32], &[], None), false),
            &p.tk,
            1,
            0,
        )),
        [0x44; 32],
    ) != Ok(Rx::ReplyReady)
    {
        return Err("real pairwise rekey M1");
    }
    deliver(&mut s);
    if s.receive(
        &mpdu(encrypt(
            &native(
                &key_frame(0x13ca, 4, [0x33; 32], &kde([0x7d; 16]), Some(&new)),
                false,
            ),
            &p.tk,
            2,
            0,
        )),
        [0x44; 32],
    ) != Ok(Rx::ReplyReady)
        || !train.current_key()
    {
        return Err("fragment key retired before actual old-key M4 terminal");
    }
    deliver(&mut s);
    if train.current_key() {
        return Err("retained fragment train survived original key replacement");
    }
    let next = s
        .transmit_ethernet_fragments(&ethernet, None, 256)
        .map_err(|_| "new-key fragment train")?;
    s.fail();
    if next.current_key() {
        return Err("terminal Security left fragment key source current");
    }
    Ok(())
}
fn smoke_station_fragment_train_real_install_one_sn_per_fragment_pn_and_key_retirement(
) -> TestResult {
    train().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/station_security/fragment",
    smoke_station_fragment_train_real_install_one_sn_per_fragment_pn_and_key_retirement
);
fn ap_fragments(body: &[u8], tk: &[u8], pn: u64) -> Vec<Vec<u8>> {
    let count = body.len().div_ceil(80);
    let mut out = Vec::new();
    for (number, part) in body.chunks(80).enumerate() {
        let mut header = vec![8, 0x42 | if number + 1 < count { 4 } else { 0 }, 0, 0];
        header.extend_from_slice(&OWN);
        header.extend_from_slice(&AP);
        header.extend_from_slice(&AP);
        header.extend_from_slice(&(0x3210 | number as u16).to_le_bytes());
        let mut plaintext = part.to_vec();
        let wire = crate::ccmp::protect(
            &Ccm,
            &header,
            tk.try_into().unwrap(),
            pn + number as u64,
            0,
            0,
            false,
            &mut plaintext,
        )
        .unwrap();
        header.extend_from_slice(&wire);
        out.push(header);
    }
    out
}
fn protocol() -> Result<(), &'static str> {
    let mut s = established();
    let p = ptk(AN, SN);
    let data = kde([0x7d; 16]);
    let eapol = key_frame(0x1382, 3, [0; 32], &data, Some(&p));
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e];
    body.extend_from_slice(&eapol);
    let parts = ap_fragments(&body, &p.tk, 10);
    if parts.len() < 2 {
        return Err("EAPOL fixture not fragmented");
    }
    // Ordinary entry point preserves rejection. A non-native first fragment
    // cannot advance the optional cache or installed replay state either.
    if s.receive(&mpdu(parts[0].clone()), SN) != Ok(Rx::Ignored) {
        return Err("ordinary Security accepted fragment");
    }
    let invalid = Mpdu {
        bytes: parts[0].clone(),
        raw: false,
    };
    if s.receive_protected_fragment_with_nonce(&invalid, 0, || Some(SN)) != Ok(Rx::Ignored)
        || s.fragment_pending(0)
    {
        return Err("non-native fragment reached reassembly");
    }
    for (index, part) in parts.into_iter().enumerate() {
        let last = index + 1 == body.len().div_ceil(80);
        let result =
            s.receive_protected_fragment_with_nonce(&mpdu(part), index as u64, || Some(SN));
        if result != Ok(if last { Rx::ReplyReady } else { Rx::Ignored })
            || (!last && !s.fragment_pending(index as u64))
        {
            return Err("authenticated fragmented EAPOL bypassed/failed retained RSNA");
        }
    }
    if s.port_open() || s.pending_frame().is_none() {
        return Err("fragmented rekey bypassed reply terminal");
    }
    deliver(&mut s);
    if !s.port_open() || s.fragment_pending(10) {
        return Err("fragmented EAPOL group install/cached lifetime");
    }
    Ok(())
}
fn smoke_station_fragment_authenticated_rekey_reassembly_runs_original_eapol_owner() -> TestResult {
    protocol().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/station_security/fragment",
    smoke_station_fragment_authenticated_rekey_reassembly_runs_original_eapol_owner
);
fn plain_ap_fragments(body: &[u8]) -> Vec<Vec<u8>> {
    let count = body.len().div_ceil(80);
    let mut out = Vec::new();
    for (number, part) in body.chunks(80).enumerate() {
        let mut header = vec![8, 2 | if number + 1 < count { 4 } else { 0 }, 0, 0];
        header.extend_from_slice(&OWN);
        header.extend_from_slice(&AP);
        header.extend_from_slice(&AP);
        header.extend_from_slice(&(0x4320 | number as u16).to_le_bytes());
        header.extend_from_slice(part);
        out.push(header);
    }
    out
}
fn plain_eapol() -> Result<(), &'static str> {
    let mut s = security();
    let p = ptk(AN, SN);
    let mut nonces = 0;
    for (kind, key) in [
        (1, key_frame(0x8a, 1, AN, &[], None)),
        (3, key_frame(0x13ca, 2, AN, &kde(GTK), Some(&p))),
    ] {
        let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e];
        body.extend_from_slice(&key);
        let parts = plain_ap_fragments(&body);
        let count = parts.len();
        for (index, frame) in parts.into_iter().enumerate() {
            let prior = nonces;
            let result = s.receive_fragment_with_nonce(&mpdu(frame), index as u64, || {
                nonces += 1;
                Some(SN)
            });
            if result
                != Ok(if index + 1 == count {
                    Rx::ReplyReady
                } else {
                    Rx::Ignored
                })
                || index + 1 < count && nonces != prior
                || s.port_open()
            {
                return Err(
                    "plain fragmented initial EAPOL bypassed complete MIC/nonce/terminal owner",
                );
            }
        }
        if kind == 1 && nonces != 1 {
            return Err("fragmented M1 did not consume exactly one real nonce");
        }
        deliver(&mut s);
    }
    if !s.port_open() || s.pair.is_none() || s.fragment_pending(10) {
        return Err("fragmented initial M3 failed actual terminal key install");
    }
    let mut body = vec![0xaa, 0xaa, 3, 0, 0, 0, 8, 0];
    body.extend_from_slice(&[0x45; 200]);
    let parts = plain_ap_fragments(&body);
    for part in parts {
        if s.receive_fragment_with_nonce(&mpdu(part), 20, || None) != Ok(Rx::Ignored) {
            return Err("unprotected fragmented DATA gained a controlled port");
        }
    }
    if !s.port_open() {
        return Err("dropped plaintext DATA closed authenticated owner");
    }
    Ok(())
}
fn smoke_station_fragment_plain_initial_eapol_keeps_nonce_mic_and_terminal_authority() -> TestResult
{
    plain_eapol().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/station_security/fragment",
    smoke_station_fragment_plain_initial_eapol_keeps_nonce_mic_and_terminal_authority
);
fn pmf_fragments() -> Result<(), &'static str> {
    let mut rsn = crate::rsn::RsnIe::wpa2_psk_ccmp();
    rsn.rsn_capabilities = crate::rsn::RSN_CAP_MFP_CAPABLE;
    let rsn = rsn.encode_body();
    let mut s =
        Security::new(OWN, AP, &PMK, &rsn, &rsn, None, 2).map_err(|_| "PMF fragment RSNE")?;
    let p = ptk(AN, SN);
    if s.receive(&mpdu(native(&key_frame(0x8a, 1, AN, &[], None), false)), SN) != Ok(Rx::ReplyReady)
    {
        return Err("PMF fragment M1");
    }
    deliver(&mut s);
    let mut data = ie(48, &rsn).unwrap();
    data.extend_from_slice(&[0xdd, 22, 0, 0x0f, 0xac, 1, 2, 0]);
    data.extend_from_slice(&GTK);
    data.extend_from_slice(&[0xdd, 28, 0, 0x0f, 0xac, 9, 4, 0, 0, 0, 0, 0, 0, 0]);
    data.extend_from_slice(&[0x39; 16]);
    if s.receive(
        &mpdu(native(&key_frame(0x13ca, 2, AN, &data, Some(&p)), false)),
        SN,
    ) != Ok(Rx::ReplyReady)
    {
        return Err("PMF fragment authenticated real IGTK M3");
    }
    deliver(&mut s);
    let mut action = vec![0xd0, 0, 0, 0];
    action.extend_from_slice(&AP);
    action.extend_from_slice(&OWN);
    action.extend_from_slice(&AP);
    action.extend_from_slice(&0x9870u16.to_le_bytes());
    action.extend_from_slice(&[3; 600]);
    let train = s
        .protect_management_fragments(&action, 256)
        .map_err(|_| "PMF management train")?;
    let mut plain = Vec::new();
    let mut replay = crate::ccmp::ReplayWindow { last_seen_pn: 0 };
    for frame in train.frames() {
        let mut wire = frame[24..].to_vec();
        plain.extend_from_slice(
            &crate::ccmp::unprotect(
                &Ccm,
                &frame[..24],
                p.tk.as_slice().try_into().unwrap(),
                0,
                true,
                &mut replay,
                &mut wire,
            )
            .map_err(|_| "PMF fragment management nonce/AAD")?,
        );
    }
    if plain != action[24..] {
        return Err("PMF fragmented original action changed");
    }
    // AP sends the reverse robust management train under its same PTK. Every
    // fragment authenticates with the management nonce/replay index.
    let count = action[24..].chunks(100).len();
    let mut final_frame = None;
    for (number, part) in action[24..].chunks(100).enumerate() {
        let mut header = vec![0xd0, 0x40 | if number + 1 < count { 4 } else { 0 }, 0, 0];
        header.extend_from_slice(&OWN);
        header.extend_from_slice(&AP);
        header.extend_from_slice(&AP);
        header.extend_from_slice(&(0x4560 | number as u16).to_le_bytes());
        let mut body = part.to_vec();
        let wire = crate::ccmp::protect(
            &Ccm,
            &header,
            p.tk.as_slice().try_into().unwrap(),
            number as u64 + 1,
            0,
            0,
            true,
            &mut body,
        )
        .unwrap();
        header.extend_from_slice(&wire);
        match s
            .receive_management_fragment(&mpdu(header), number as u64)
            .map_err(|_| "PMF fragment receive")?
        {
            MgmtRx::Ignored if number + 1 < count => {}
            MgmtRx::Frame(frame) if number + 1 == count => final_frame = Some(frame),
            _ => return Err("PMF partial action delivered or complete lost"),
        }
    }
    let frame = final_frame.ok_or("complete PMF action")?;
    if frame[1] & 0x44 != 0
        || frame[22..24] != 0x4560u16.to_le_bytes()
        || frame[24..] != action[24..]
    {
        return Err("PMF fragment normalized header/body");
    }
    Ok(())
}
fn smoke_station_fragment_pmf_real_igtk_install_management_nonce_and_reassembly() -> TestResult {
    pmf_fragments().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
kernel_test_in!(
    "wireless/station_security/fragment",
    smoke_station_fragment_pmf_real_igtk_install_management_nonce_and_reassembly
);
