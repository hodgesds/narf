use super::*;
use alloc::sync::Arc;
use alloc::vec;
use narf_capabilities::{object_table, CapSlot, CapType, Rights};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::reg::{RegFlags, RegRule};
fn authority() -> Cap<FirmwareBlob, Read> {
    let (index, generation) = object_table::register(FirmwareBlob::KIND);
    // SAFETY: private freshly registered firmware object, exact Read type/rights;
    // no unsigned device/firmware lookup or production policy is bypassed.
    unsafe {
        Cap::mint(CapSlot::new(
            generation,
            index,
            Read::BITS,
            FirmwareBlob::KIND as u32,
        ))
    }
}
fn board(profile: Profile, seed: u8) -> Board {
    Board {
        identity: [seed; 32],
        mac: [2, 4, 6, 8, 10, 12],
        device: 0xc852,
        profile,
    }
}
fn header(b: &mut [u8; LENGTH], magic: &[u8; 4], version: u8) {
    b[..4].copy_from_slice(magic);
    b[4..8].copy_from_slice(&[version, 0, 128, 0]);
    b[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
    b[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    b[14..16].copy_from_slice(&0xc852u16.to_le_bytes());
    b[48..54].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
    b[58..60].copy_from_slice(&4i16.to_le_bytes());
    b[60..62].copy_from_slice(&76i16.to_le_bytes());
    for at in [62, 64, 66] {
        b[at..at + 2].copy_from_slice(&40i16.to_le_bytes());
    }
}
fn base_image(board: Board) -> [u8; LENGTH] {
    let mut b = [0; LENGTH];
    header(&mut b, b"N5CB", 2);
    b[16..48].copy_from_slice(&board.identity);
    b[54..58].copy_from_slice(&[1, 20, 1, BASE_FLAGS]);
    b
}
fn channel_image(base: &Qualification, board: Board) -> [u8; LENGTH] {
    let p = board.profile;
    let mut b = [0; LENGTH];
    header(&mut b, b"N5CC", 1);
    b[16..48].copy_from_slice(&binding(base, board).unwrap());
    b[54..58].copy_from_slice(&[1, width_mhz(p.width()), p.primary(), BASE_FLAGS]);
    b[68..70].copy_from_slice(&[p.band() as u8, p.center()]);
    b
}
fn rule(start: u32, end: u32, bw: u32, flags: RegFlags) -> RegRule {
    RegRule {
        freq_start_mhz: start,
        freq_end_mhz: end,
        max_bandwidth_mhz: bw,
        max_power_dbm: 20,
        flags,
    }
}
fn domain(rules: alloc::vec::Vec<RegRule>) -> Arc<RegulatoryDomain> {
    Arc::new(RegulatoryDomain {
        country_code: *b"US",
        rules,
    })
}
fn base(cap: Cap<FirmwareBlob, Read>) -> Qualification {
    let board = board(Profile::INITIAL, 7);
    let mut q =
        Qualification::from_verified(&base_image(board), Some([3; 32]), board, cap).unwrap();
    q.model_domain = Some(domain(vec![
        rule(2402, 2482, 40, RegFlags::empty()),
        rule(5170, 5250, 80, RegFlags::AUTO_BW),
        rule(5250, 5330, 80, RegFlags::AUTO_BW | RegFlags::DFS),
    ]));
    q
}
fn smoke_rtw8852c_full_radio_base_record_is_n5cb_v2_exact_and_revocable() -> TestResult {
    let exact = board(Profile::INITIAL, 7);
    let bytes = base_image(exact);
    let cap = authority();
    if !matches!(
        Qualification::from_verified(&bytes, None, exact, cap),
        Err(Error::Unsigned)
    ) {
        return TestResult::Fail("unsigned C full-radio record accepted");
    }
    for end in 0..bytes.len() {
        if Qualification::from_verified(&bytes[..end], Some([3; 32]), exact, cap).is_ok() {
            return TestResult::Fail("truncated C record accepted");
        }
    }
    for at in [0, 3, 4, 8, 12, 14, 16, 47, 48, 53, 54, 55, 56, 57, 68, 127] {
        let mut bad = bytes;
        bad[at] ^= 1;
        if Qualification::from_verified(&bad, Some([3; 32]), exact, cap).is_ok() {
            return TestResult::Fail("altered C full-radio record accepted");
        }
    }
    let mut b_magic = bytes;
    b_magic[..4].copy_from_slice(b"N52B");
    if Qualification::from_verified(&b_magic, Some([3; 32]), exact, cap).is_ok() {
        return TestResult::Fail("B N52B magic admitted C");
    }
    // The base record never stands for a noninitial profile.
    let other = board(Profile::new20(Band::Ghz2, 6).unwrap(), 7);
    if Qualification::from_verified(&bytes, Some([3; 32]), other, cap).is_ok() {
        return TestResult::Fail("base record admitted a noninitial identity");
    }
    let q = base(cap);
    if !q.matches(exact)
        || q.current().is_err()
        || !matches!(q.channel_allowed(Profile::INITIAL), Ok(true))
    {
        return TestResult::Fail("exact C base record refused");
    }
    if !matches!(
        q.channel_allowed(Profile::new20(Band::Ghz2, 6).unwrap()),
        Ok(false)
    ) {
        return TestResult::Fail("unprovisioned C channel admitted");
    }
    cap.revoke();
    if !matches!(q.current(), Err(Error::Authority)) || q.with_current(|| Ok(())).is_ok() {
        return TestResult::Fail("revoked C record still admits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_full_radio_base_record_is_n5cb_v2_exact_and_revocable
);
fn smoke_rtw8852c_channel_records_admit_exactly_their_profile_and_span() -> TestResult {
    let mut q = base(authority());
    let ch6 = Profile::new20(Band::Ghz2, 6).unwrap();
    let vht80 = Profile::new_wide(Band::Ghz5, 44, Width::Mhz80).unwrap();
    let vht160 = Profile::new_wide(Band::Ghz5, 36, Width::Mhz160).unwrap();
    if !noninitial().contains(&vht160)
        || noninitial().contains(&Profile::INITIAL)
        || noninitial().iter().any(|p| !admissible(*p))
        || admissible(Profile::new20(Band::Ghz2, 14).unwrap())
        || Profile::new20(Band::Ghz6, 37).is_some_and(admissible)
    {
        return TestResult::Fail("admissible C profile set wrong");
    }
    for profile in [ch6, vht80, vht160] {
        let b = board(profile, profile.primary());
        let bytes = channel_image(&q, b);
        // Signer must be the base signer; another record's profile refused.
        if Channel::from_verified(&q, b, &bytes, Some([9; 32]), authority()).is_ok()
            || Channel::from_verified(
                &q,
                board(Profile::new20(Band::Ghz2, 7).unwrap(), 1),
                &bytes,
                Some([3; 32]),
                authority(),
            )
            .is_ok()
        {
            return TestResult::Fail("C channel record admitted another signer/profile");
        }
        for at in [0, 4, 16, 54, 55, 56, 57, 68, 69, 70, 127] {
            let mut bad = bytes;
            bad[at] ^= 1;
            if Channel::from_verified(&q, b, &bad, Some([3; 32]), authority()).is_ok() {
                return TestResult::Fail("altered C channel record accepted");
            }
        }
        let record = match Channel::from_verified(&q, b, &bytes, Some([3; 32]), authority()) {
            Ok(record) => record,
            Err(_) => return TestResult::Fail("exact C channel record refused"),
        };
        q.install(record);
        if !q.channel_matches(b) || q.channel_matches(board(profile, 0x55)) {
            return TestResult::Fail("C channel record bound to wrong identity");
        }
    }
    // ch6 20MHz and 5GHz VHT80 (one AUTO_BW rule) pass; VHT160 spans two
    // AUTO_BW runs (5170..5330 => 160MHz) incl. a DFS half: passive admit.
    if !matches!(q.channel_allowed(ch6), Ok(true))
        || !matches!(q.channel_allowed(vht80), Ok(true))
        || !matches!(q.channel_allowed(vht160), Ok(true))
    {
        return TestResult::Fail("signed C channel refused under a passing rule");
    }
    // A rule narrower than the profile width refuses it; a gap refuses it.
    q.model_domain = Some(domain(vec![
        rule(2402, 2482, 40, RegFlags::empty()),
        rule(5170, 5250, 40, RegFlags::empty()),
        rule(5250, 5330, 80, RegFlags::empty()),
    ]));
    if !matches!(q.channel_allowed(vht80), Ok(false))
        || !matches!(q.channel_allowed(vht160), Ok(false))
    {
        return TestResult::Fail("C width above the host rule admitted");
    }
    q.model_domain = Some(domain(vec![
        rule(2402, 2482, 40, RegFlags::empty()),
        rule(5170, 5240, 160, RegFlags::empty()),
        rule(5250, 5330, 160, RegFlags::empty()),
    ]));
    if !matches!(q.channel_allowed(vht160), Ok(false)) {
        return TestResult::Fail("C span with a rule gap admitted");
    }
    // select gates the active envelope; an unloaded profile cannot be selected.
    if q.select(ch6).is_err() || q.active() != ch6 || q.with_current(|| Ok(())).is_err() {
        return TestResult::Fail("signed C profile not selectable");
    }
    let unloaded = Profile::new20(Band::Ghz5, 149).unwrap();
    if q.select(unloaded).is_ok() || q.active() != ch6 {
        return TestResult::Fail("unsigned C profile selected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_channel_records_admit_exactly_their_profile_and_span
);
fn smoke_rtw8852c_tx_current_refuses_frames_on_passive_spans() -> TestResult {
    let mut q = base(authority());
    let ch6 = Profile::new20(Band::Ghz2, 6).unwrap();
    let dfs = Profile::new20(Band::Ghz5, 52).unwrap();
    for profile in [ch6, dfs] {
        let b = board(profile, profile.primary());
        let bytes = channel_image(&q, b);
        match Channel::from_verified(&q, b, &bytes, Some([3; 32]), authority()) {
            Ok(record) => q.install(record),
            Err(_) => return TestResult::Fail("exact C channel record refused"),
        }
    }
    // Plain 2.4GHz spans admit frames on the base and on a noninitial record.
    if q.tx_current().is_err() || q.select(ch6).is_err() || q.tx_current().is_err() {
        return TestResult::Fail("C frame TX refused on a plain span");
    }
    // The DFS span admits the signed emissions (select/current) but no frame.
    if q.select(dfs).is_err()
        || q.current().is_err()
        || !matches!(q.tx_current(), Err(Error::Policy))
    {
        return TestResult::Fail("C frame TX admitted on a DFS span");
    }
    // Back on a plain span frames are admitted again; revocation refuses.
    let cap = q.authority;
    if q.select(Profile::INITIAL).is_err() || q.tx_current().is_err() {
        return TestResult::Fail("C frame TX not restored after leaving the DFS span");
    }
    cap.revoke();
    if !matches!(q.tx_current(), Err(Error::Authority)) {
        return TestResult::Fail("revoked C record admitted frame TX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_tx_current_refuses_frames_on_passive_spans
);
fn smoke_rtw8852c_base_record_programs_are_wmm_and_firmware_ra_only() -> TestResult {
    let exact = board(Profile::INITIAL, 7);
    let cap = authority();
    let flags = Program::FirmwareRa.flags();
    let mut bytes = base_image(exact);
    bytes[57] = flags;
    // The record measures the program-extended identity.
    if Qualification::from_verified(&bytes, Some([3; 32]), exact, cap).is_ok() {
        return TestResult::Fail("program flags accepted on the program-free identity");
    }
    bytes[16..48].copy_from_slice(&exact.with_programs(flags).identity);
    let Ok(mut q) = Qualification::from_verified(&bytes, Some([3; 32]), exact, cap) else {
        return TestResult::Fail("signed C WMM + firmware RA record refused");
    };
    q.model_domain = base(cap).model_domain;
    if !q.matches(exact)
        || q.allows(Program::Wmm) != Ok(true)
        || q.allows(Program::FirmwareRa) != Ok(true)
        || q.allows(Program::Ht) != Ok(false)
        || q.allows(Program::QosAll) != Ok(false)
    {
        return TestResult::Fail("C program allowances differ from the signed flags");
    }
    // Programs without a C path, unknown bits or unmet dependencies.
    for flags in [
        Program::Ht.flags(),
        Program::QosAll.flags(),
        Program::Ampdu.flags(),
        BASE_FLAGS | Program::FirmwareRa.bit(),
        0x7,
        0x6,
    ] {
        let mut bad = base_image(exact);
        bad[57] = flags;
        bad[16..48].copy_from_slice(&exact.with_programs(flags).identity);
        let accepted = Qualification::from_verified(&bad, Some([3; 32]), exact, cap).is_ok();
        if accepted != (flags == Program::Wmm.flags()) {
            return TestResult::Fail("C program flag admission differs");
        }
    }
    let plain = base(cap);
    if plain.allows(Program::Wmm) != Ok(false) {
        return TestResult::Fail("program-free C record allows WMM");
    }
    cap.revoke();
    if q.allows(Program::Wmm).is_ok() {
        return TestResult::Fail("revoked C record still allows a program");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_base_record_programs_are_wmm_and_firmware_ra_only
);
