use super::*;
use alloc::sync::Arc;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_wireless::reg::{RegFlags, RegRule};
fn authority() -> Cap<FirmwareBlob, Read> {
    // Fresh live FirmwareBlob/Read fixture authority, minted via the
    // safe `Cap::bootstrap` path (SEC-B5, #1293: `Cap::mint` is
    // crate-private to `capabilities/`).
    Cap::bootstrap()
}
const MAC: [u8; 6] = [2, 4, 6, 8, 10, 12];
fn board(profile: Profile, seed: u8) -> Board {
    Board {
        identity: [seed; 32],
        mac: MAC,
        device: 0x8852,
        profile,
    }
}
fn header(b: &mut [u8; LENGTH], magic: &[u8; 4], version: u8) {
    b[..4].copy_from_slice(magic);
    b[4..8].copy_from_slice(&[version, 0, 128, 0]);
    b[8..12].copy_from_slice(&(LENGTH as u32).to_le_bytes());
    b[12..14].copy_from_slice(&0x10ecu16.to_le_bytes());
    b[14..16].copy_from_slice(&0x8852u16.to_le_bytes());
    b[48..54].copy_from_slice(&MAC);
    b[58..60].copy_from_slice(&4i16.to_le_bytes());
    b[60..62].copy_from_slice(&76i16.to_le_bytes());
    for at in [62, 64, 66] {
        b[at..at + 2].copy_from_slice(&40i16.to_le_bytes());
    }
}
fn base_image(board: Board) -> [u8; LENGTH] {
    let mut b = [0; LENGTH];
    header(&mut b, b"N5AB", 2);
    b[16..48].copy_from_slice(&board.identity);
    b[54..58].copy_from_slice(&[1, 20, 1, BASE_FLAGS]);
    b
}
fn channel_image(base: &Qualification, board: Board) -> [u8; LENGTH] {
    let p = board.profile;
    let mut b = [0; LENGTH];
    header(&mut b, b"N5AC", 1);
    b[16..48].copy_from_slice(&binding(base, board).unwrap());
    b[54..58].copy_from_slice(&[1, width_mhz(p.width()), p.primary(), BASE_FLAGS]);
    b[68..70].copy_from_slice(&[p.band_index(), p.center()]);
    b
}
fn fragment_record(request: &fragment::Request) -> [u8; LENGTH] {
    let mut b = [0; LENGTH];
    header(&mut b, b"N5AF", 1);
    b[16..48].copy_from_slice(&request.binding);
    b[54..58].copy_from_slice(&[1, 20, 1, 3]);
    b[58..60].copy_from_slice(&2346u16.to_le_bytes());
    b[60..64].copy_from_slice(&[16, 0, 3, 1]);
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
/// Explicit inert authenticated-record boundary for native register tests;
/// no production attach, measured RF envelope or physical receipt is minted.
pub(in crate::rtw89) fn fragment_model() -> (
    Qualification,
    Cap<FirmwareBlob, Read>,
    Cap<FirmwareBlob, Read>,
) {
    let base_cap = authority();
    let mut base = base(base_cap);
    let request = fragment::Request::new(&base).unwrap();
    let record = fragment_record(&request);
    let companion = authority();
    base.fragments = Some(
        fragment::Fragments::from_verified(&base, &request, &record, Some([3; 32]), companion)
            .unwrap(),
    );
    (base, base_cap, companion)
}

fn smoke_rtw89_a_radio_programs_follow_b_layout_and_extend_a_identity() -> TestResult {
    // The A program list is the shared six-program layout in `ALL` order,
    // and every program's flags (with its dependencies) validate.
    if PROGRAMS != Program::ALL {
        return TestResult::Fail("A program list differs from the shared program layout");
    }
    for program in Program::ALL {
        if !programs_valid(program.flags()) {
            return TestResult::Fail("A program flags refused");
        }
    }
    if !programs_valid(BASE_FLAGS) {
        return TestResult::Fail("A base flags refused");
    }
    // Incomplete base flags and unmet dependencies stay refused.
    for flags in [
        0x0,
        0x2,
        0x6,
        BASE_FLAGS | Program::FirmwareRa.bit(),
        BASE_FLAGS | Program::Ht.bit(),
        BASE_FLAGS | Program::He.bit(),
        BASE_FLAGS | Program::Ampdu.bit(),
        BASE_FLAGS | Program::QosAll.bit() | Program::He.bit(),
    ] {
        if programs_valid(flags) {
            return TestResult::Fail("A program flags admitted without base or dependencies");
        }
    }
    // Every program extends the identity deterministically, each to a
    // distinct identity, and the extension binds the input identity.
    let identity = [7u8; 32];
    let mut extended = [[0u8; 32]; 6];
    for (index, program) in Program::ALL.into_iter().enumerate() {
        let next = extend(program, identity);
        if next == identity || extend(program, identity) != next {
            return TestResult::Fail("A program did not extend its identity deterministically");
        }
        if extended[..index].contains(&next) {
            return TestResult::Fail("two A programs extended to the same identity");
        }
        extended[index] = next;
    }
    if extend(Program::Wmm, [8u8; 32]) == extended[0] {
        return TestResult::Fail("A program extension ignored its input identity");
    }
    // The full program set extends once per program in the fixed order.
    let full = Program::Ampdu.flags() | Program::He.bit() | Program::QosAll.bit();
    if !programs_valid(full) {
        return TestResult::Fail("A full program flags refused");
    }
    let mut running = identity;
    for program in Program::ALL {
        if full & program.bit() != 0 {
            running = extend(program, running);
        }
    }
    if running == identity || Program::ALL.iter().any(|p| extend(*p, identity) == running) {
        return TestResult::Fail("A full program extension did not compose per program");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_a_radio_programs_follow_b_layout_and_extend_a_identity
);
fn smoke_rtw8852a_full_radio_base_record_is_n5ab_v2_exact_and_revocable() -> TestResult {
    let exact = board(Profile::INITIAL, 7);
    let bytes = base_image(exact);
    let cap = authority();
    if !matches!(
        Qualification::from_verified(&bytes, None, exact, cap),
        Err(Error::Unsigned)
    ) {
        return TestResult::Fail("unsigned RTL8852A full-radio record accepted");
    }
    for end in 0..bytes.len() {
        if Qualification::from_verified(&bytes[..end], Some([3; 32]), exact, cap).is_ok() {
            return TestResult::Fail("truncated RTL8852A record accepted");
        }
    }
    for at in [0, 3, 4, 8, 12, 14, 16, 47, 48, 53, 54, 55, 56, 57, 68, 127] {
        let mut bad = bytes;
        bad[at] ^= 1;
        if Qualification::from_verified(&bad, Some([3; 32]), exact, cap).is_ok() {
            return TestResult::Fail("altered RTL8852A full-radio record accepted");
        }
    }
    // Neither the B, C nor 51 base magic admits RTL8852A, and a program
    // bit the signed identity does not cover is refused.
    for magic in [b"N52B", b"N5CB", b"N51B"] {
        let mut other = bytes;
        other[..4].copy_from_slice(magic);
        if Qualification::from_verified(&other, Some([3; 32]), exact, cap).is_ok() {
            return TestResult::Fail("B/C/51 base magic admitted RTL8852A");
        }
    }
    for bit in 2..8 {
        let mut programs = bytes;
        programs[57] |= 1 << bit;
        if Qualification::from_verified(&programs, Some([3; 32]), exact, cap).is_ok() {
            return TestResult::Fail("RTL8852A base record admitted a program bit");
        }
    }
    // A record whose identity covers the WMM + firmware-RA + HT + HE
    // programs (`Board::with_programs`) admits exactly those; A-MPDU and
    // all-AC QoS stay "no program".
    let flags = BASE_FLAGS
        | Program::Wmm.bit()
        | Program::FirmwareRa.bit()
        | Program::Ht.bit()
        | Program::He.bit();
    let mut programs = bytes;
    programs[16..48].copy_from_slice(&exact.with_programs(flags).identity);
    programs[57] = flags;
    match Qualification::from_verified(&programs, Some([3; 32]), exact, cap) {
        Ok(mut q) => {
            q.model_domain = Some(domain(vec![rule(2400, 2484, 40, RegFlags::empty())]));
            if !q.matches(exact)
                || !matches!(q.allows(Program::Ht), Ok(true))
                || !matches!(q.allows(Program::He), Ok(true))
                || !matches!(q.allows(Program::Ampdu), Ok(false))
                || !matches!(q.allows(Program::QosAll), Ok(false))
            {
                return TestResult::Fail("RTL8852A program record admitted the wrong programs");
            }
        }
        Err(_) => return TestResult::Fail("RTL8852A program record refused"),
    }
    if exact.with_programs(flags).identity == exact.identity
        || exact.with_programs(Program::Wmm.bit()).identity
            == exact.with_programs(Program::Ht.bit()).identity
    {
        return TestResult::Fail("RTL8852A programs not bound into the identity");
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
        return TestResult::Fail("exact RTL8852A base record refused or unprovisioned admitted");
    }
    cap.revoke();
    if !matches!(q.current(), Err(Error::Authority)) || q.with_current(|| Ok(())).is_ok() {
        return TestResult::Fail("revoked RTL8852A record still admits");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_full_radio_base_record_is_n5ab_v2_exact_and_revocable
);
fn smoke_rtw8852a_channel_records_admit_exactly_their_profile_and_span() -> TestResult {
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
        return TestResult::Fail("admissible RTL8852A profile set wrong");
    }
    // The two HT40 sides of one primary have distinct record names.
    if channel_name(ht40_up, MAC) == channel_name(ht40_down, MAC) {
        return TestResult::Fail("HT40 above/below share one RTL8852A record name");
    }
    for profile in [ch6, ht40_up, vht80] {
        let b = board(profile, profile.primary());
        let bytes = channel_image(&q, b);
        if Channel::from_verified(&q, b, &bytes, Some([9; 32]), authority()).is_ok()
            || Channel::from_verified(&q, board(ht40_down, 5), &bytes, Some([3; 32]), authority())
                .is_ok()
        {
            return TestResult::Fail("RTL8852A channel record admitted another signer/profile");
        }
        let mut c_magic = bytes;
        c_magic[..4].copy_from_slice(b"N5CC");
        if Channel::from_verified(&q, b, &c_magic, Some([3; 32]), authority()).is_ok() {
            return TestResult::Fail("C N5CC magic admitted an RTL8852A channel");
        }
        for at in [0, 4, 16, 54, 55, 56, 57, 68, 69, 70, 127] {
            let mut bad = bytes;
            bad[at] ^= 1;
            if Channel::from_verified(&q, b, &bad, Some([3; 32]), authority()).is_ok() {
                return TestResult::Fail("altered RTL8852A channel record accepted");
            }
        }
        match Channel::from_verified(&q, b, &bytes, Some([3; 32]), authority()) {
            Ok(record) => q.install(record),
            Err(_) => return TestResult::Fail("exact RTL8852A channel record refused"),
        }
        if !q.channel_matches(b) || q.channel_matches(board(profile, 0x55)) {
            return TestResult::Fail("RTL8852A channel record bound to wrong identity");
        }
    }
    if !matches!(q.channel_allowed(ch6), Ok(true))
        || !matches!(q.channel_allowed(ht40_up), Ok(true))
        || !matches!(q.channel_allowed(vht80), Ok(true))
        || !matches!(q.channel_allowed(ht40_down), Ok(false))
    {
        return TestResult::Fail("signed RTL8852A channel admission wrong under a passing rule");
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
        return TestResult::Fail("RTL8852A width above the rule or a span gap admitted");
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
        return TestResult::Fail("RTL8852A frame TX admitted on a DFS span");
    }
    if q.select(ch6).is_err() || q.tx_current().is_err() || q.with_current(|| Ok(())).is_err() {
        return TestResult::Fail("signed RTL8852A 2.4GHz profile not selectable");
    }
    let unloaded = Profile::new_wide(149, Width::Mhz20, false).unwrap();
    if q.select(unloaded).is_ok() || q.active() != ch6 {
        return TestResult::Fail("unsigned RTL8852A profile selected");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_channel_records_admit_exactly_their_profile_and_span
);
fn smoke_rtw8852a_fragment_companion_is_n5af_exact_and_gates_fragments() -> TestResult {
    let (base, original, companion) = fragment_model();
    if base.fragments_allowed() != Ok(true) || base.with_current(|| Ok(3)) != Ok(3) {
        return TestResult::Fail("N5AF actual finite joint current/invoke chain");
    }
    companion.revoke();
    if base.fragments_allowed().is_ok() || base.with_current(|| Ok(3)).is_ok() {
        return TestResult::Fail("revoked N5AF retained fragment emission");
    }
    let mut changed = base;
    changed.fragments = None;
    if changed.fragments_allowed() != Ok(false) || changed.current().is_err() {
        return TestResult::Fail("absent fragment record changed prior native program");
    }
    let request = fragment::Request::new(&changed).unwrap();
    let bytes = fragment_record(&request);
    for offset in [
        0, 4, 8, 12, 14, 16, 47, 48, 54, 57, 58, 60, 61, 62, 63, 64, 127,
    ] {
        let mut bad = bytes;
        bad[offset] ^= 1;
        if fragment::Fragments::from_verified(&changed, &request, &bad, Some([3; 32]), authority())
            .is_ok()
        {
            return TestResult::Fail("N5AF accepted malformed/source/digest/size/sequence program");
        }
    }
    if fragment::Fragments::from_verified(&changed, &request, &bytes, None, authority()).is_ok()
        || fragment::Fragments::from_verified(
            &changed,
            &request,
            &bytes,
            Some([4; 32]),
            authority(),
        )
        .is_ok()
    {
        return TestResult::Fail("N5AF bypassed original signer/source");
    }
    let mut b_magic = bytes;
    b_magic[..4].copy_from_slice(b"N52F");
    if fragment::Fragments::from_verified(&changed, &request, &b_magic, Some([3; 32]), authority())
        .is_ok()
    {
        return TestResult::Fail("B N52F magic admitted an RTL8852A fragment");
    }
    original.revoke();
    if fragment::Fragments::from_verified(&changed, &request, &bytes, Some([3; 32]), authority())
        .is_ok()
    {
        return TestResult::Fail("N5AF recaptured revoked installed original base");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852a_fragment_companion_is_n5af_exact_and_gates_fragments
);
