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
const MAC: [u8; 6] = [2, 4, 6, 8, 10, 12];
fn board(profile: Profile, seed: u8) -> Board {
    Board {
        identity: [seed; 32],
        mac: MAC,
        device: 0xb851,
        profile,
    }
}
fn header(b: &mut [u8; LENGTH], magic: &[u8; 4], version: u8) {
    b[..4].copy_from_slice(magic);
    b[4..8].copy_from_slice(&[version, 0, 128, 0]);
    b[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
    b[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    b[14..16].copy_from_slice(&0xb851u16.to_le_bytes());
    b[48..54].copy_from_slice(&MAC);
    b[58..60].copy_from_slice(&4i16.to_le_bytes());
    b[60..62].copy_from_slice(&76i16.to_le_bytes());
    for at in [62, 64, 66] {
        b[at..at + 2].copy_from_slice(&40i16.to_le_bytes());
    }
}
fn base_image(board: Board) -> [u8; LENGTH] {
    let mut b = [0; LENGTH];
    header(&mut b, b"N51B", 2);
    b[16..48].copy_from_slice(&board.identity);
    b[54..58].copy_from_slice(&[1, 20, 1, BASE_FLAGS]);
    b
}
fn channel_image(base: &Qualification, board: Board) -> [u8; LENGTH] {
    let p = board.profile;
    let mut b = [0; LENGTH];
    header(&mut b, b"N51C", 1);
    b[16..48].copy_from_slice(&binding(base, board).unwrap());
    b[54..58].copy_from_slice(&[1, width_mhz(p.width()), p.primary(), BASE_FLAGS]);
    b[68..70].copy_from_slice(&[p.band_index(), p.center()]);
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
fn smoke_rtw8851b_full_radio_base_record_is_n51b_v2_exact_and_revocable() -> TestResult {
    let exact = board(Profile::INITIAL, 7);
    let bytes = base_image(exact);
    let cap = authority();
    if !matches!(
        Qualification::from_verified(&bytes, None, exact, cap),
        Err(Error::Unsigned)
    ) {
        return TestResult::Fail("unsigned RTL8851B full-radio record accepted");
    }
    for end in 0..bytes.len() {
        if Qualification::from_verified(&bytes[..end], Some([3; 32]), exact, cap).is_ok() {
            return TestResult::Fail("truncated RTL8851B record accepted");
        }
    }
    for at in [0, 3, 4, 8, 12, 14, 16, 47, 48, 53, 54, 55, 56, 57, 68, 127] {
        let mut bad = bytes;
        bad[at] ^= 1;
        if Qualification::from_verified(&bad, Some([3; 32]), exact, cap).is_ok() {
            return TestResult::Fail("altered RTL8851B full-radio record accepted");
        }
    }
    // Neither the B nor the C base magic admits RTL8851B, and no program
    // bit (no RTL8851B station path yet) is accepted.
    for magic in [b"N52B", b"N5CB"] {
        let mut other = bytes;
        other[..4].copy_from_slice(magic);
        if Qualification::from_verified(&other, Some([3; 32]), exact, cap).is_ok() {
            return TestResult::Fail("B/C base magic admitted RTL8851B");
        }
    }
    for bit in 2..8 {
        let mut programs = bytes;
        programs[57] |= 1 << bit;
        if Qualification::from_verified(&programs, Some([3; 32]), exact, cap).is_ok() {
            return TestResult::Fail("RTL8851B base record admitted a program bit");
        }
    }
    let ch6 = Profile::new_wide(6, Width::Mhz20, false).unwrap();
    if Qualification::from_verified(&bytes, Some([3; 32]), board(ch6, 7), cap).is_ok() {
        return TestResult::Fail("base record admitted a noninitial identity");
    }
    let q = base(cap);
    if !q.matches(exact)
        || q.current().is_err()
        || !matches!(q.channel_allowed(Profile::INITIAL), Ok(true))
        || !matches!(q.channel_allowed(ch6), Ok(false))
    {
        return TestResult::Fail("exact RTL8851B base record refused or unprovisioned admitted");
    }
    cap.revoke();
    if !matches!(q.current(), Err(Error::Authority)) || q.with_current(|| Ok(())).is_ok() {
        return TestResult::Fail("revoked RTL8851B record still admits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8851b_full_radio_base_record_is_n51b_v2_exact_and_revocable
);
fn smoke_rtw8851b_channel_records_admit_exactly_their_profile_and_span() -> TestResult {
    let mut q = base(authority());
    let ch6 = Profile::new_wide(6, Width::Mhz20, false).unwrap();
    let ht40_up = Profile::new_2ghz_40(5, true).unwrap();
    let ht40_down = Profile::new_2ghz_40(5, false).unwrap();
    let vht80 = Profile::new_wide(44, Width::Mhz80, false).unwrap();
    let set = noninitial();
    if set.contains(&Profile::INITIAL)
        || set.iter().any(|p| !admissible(*p))
        || !set.contains(&vht80)
        || !set.contains(&ht40_up)
        || !set.contains(&ht40_down)
        || set.iter().any(|p| p.width() == Width::Mhz160)
        || admissible(Profile::new_wide(14, Width::Mhz20, false).unwrap())
        || Profile::new_5ghz_160(36).is_some_and(admissible)
    {
        return TestResult::Fail("admissible RTL8851B profile set wrong");
    }
    // The two HT40 sides of one primary have distinct record names.
    if channel_name(ht40_up, MAC) == channel_name(ht40_down, MAC) {
        return TestResult::Fail("HT40 above/below share one RTL8851B record name");
    }
    for profile in [ch6, ht40_up, vht80] {
        let b = board(profile, profile.primary());
        let bytes = channel_image(&q, b);
        if Channel::from_verified(&q, b, &bytes, Some([9; 32]), authority()).is_ok()
            || Channel::from_verified(&q, board(ht40_down, 5), &bytes, Some([3; 32]), authority())
                .is_ok()
        {
            return TestResult::Fail("RTL8851B channel record admitted another signer/profile");
        }
        let mut c_magic = bytes;
        c_magic[..4].copy_from_slice(b"N5CC");
        if Channel::from_verified(&q, b, &c_magic, Some([3; 32]), authority()).is_ok() {
            return TestResult::Fail("C N5CC magic admitted an RTL8851B channel");
        }
        for at in [0, 4, 16, 54, 55, 56, 57, 68, 69, 70, 127] {
            let mut bad = bytes;
            bad[at] ^= 1;
            if Channel::from_verified(&q, b, &bad, Some([3; 32]), authority()).is_ok() {
                return TestResult::Fail("altered RTL8851B channel record accepted");
            }
        }
        match Channel::from_verified(&q, b, &bytes, Some([3; 32]), authority()) {
            Ok(record) => q.install(record),
            Err(_) => return TestResult::Fail("exact RTL8851B channel record refused"),
        }
        if !q.channel_matches(b) || q.channel_matches(board(profile, 0x55)) {
            return TestResult::Fail("RTL8851B channel record bound to wrong identity");
        }
    }
    if !matches!(q.channel_allowed(ch6), Ok(true))
        || !matches!(q.channel_allowed(ht40_up), Ok(true))
        || !matches!(q.channel_allowed(vht80), Ok(true))
        || !matches!(q.channel_allowed(ht40_down), Ok(false))
    {
        return TestResult::Fail("signed RTL8851B channel admission wrong under a passing rule");
    }
    // A rule narrower than the width refuses; a gap over the span refuses.
    q.model_domain = Some(domain(vec![
        rule(2402, 2482, 20, RegFlags::empty()),
        rule(5170, 5210, 80, RegFlags::empty()),
        rule(5220, 5250, 80, RegFlags::empty()),
    ]));
    if !matches!(q.channel_allowed(ht40_up), Ok(false))
        || !matches!(q.channel_allowed(vht80), Ok(false))
    {
        return TestResult::Fail("RTL8851B width above the rule or a span gap admitted");
    }
    q.model_domain = Some(domain(vec![
        rule(2402, 2482, 40, RegFlags::empty()),
        rule(5170, 5250, 80, RegFlags::AUTO_BW | RegFlags::DFS),
    ]));
    // A DFS 5GHz span admits the signed emissions but no frame.
    if q.select(vht80).is_err()
        || q.active() != vht80
        || q.current().is_err()
        || !matches!(q.tx_current(), Err(Error::Policy))
        || !matches!(q.channel_active(vht80), Ok(false))
    {
        return TestResult::Fail("RTL8851B frame TX admitted on a DFS span");
    }
    if q.select(ch6).is_err() || q.tx_current().is_err() || q.with_current(|| Ok(())).is_err() {
        return TestResult::Fail("signed RTL8851B 2.4GHz profile not selectable");
    }
    let unloaded = Profile::new_wide(149, Width::Mhz20, false).unwrap();
    if q.select(unloaded).is_ok() || q.active() != ch6 {
        return TestResult::Fail("unsigned RTL8851B profile selected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8851b_channel_records_admit_exactly_their_profile_and_span
);
