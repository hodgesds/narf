//! In-kernel tests for the record-based kernel log store.
//!
//! Most cases run on a PRIVATE heap-allocated [`Store`] so they can fill,
//! wrap and grow it without disturbing the live boot log.

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn read_one(st: &Store, cursor: &mut u64) -> Result<Vec<u8>, KmsgRead> {
    let mut buf = [0u8; PRINTK_MESSAGE_MAX];
    match st.kmsg_read(cursor, &mut buf) {
        KmsgRead::Record(n) => Ok(buf[..n].to_vec()),
        other => Err(other),
    }
}

/// `write_str` fragments of one line become ONE record, invisible until the
/// newline arrives; `\n` splits records.
fn smoke_klog_fragments_form_one_record() -> TestResult {
    let mut st = Store::boxed();
    st.append(4, 7_000, 0, b"abc");
    st.append(4, 8_000, 0, b" def");
    if st.next_seq != 0 {
        return TestResult::Fail("unterminated fragment must not be a record yet");
    }
    st.append(4, 9_000, 0, b"!\nsecond line\nthird");
    if st.next_seq != 2 {
        return TestResult::Fail("two newlines must commit exactly two records");
    }
    let d = st.desc(0);
    if st.rec_text(&d) != b"abc def!" || d.ts_nsec != 7_000 || d.flags != LOG_NEWLINE {
        return TestResult::Fail("fragments did not merge into one record stamped at the first");
    }
    if st.rec_text(&st.desc(1)) != b"second line" {
        return TestResult::Fail("second line wrong");
    }
    // A fragment longer than a record splits; the tail is flagged LOG_CONT.
    let mut st = Store::boxed();
    let long = [b'x'; RECORD_TEXT_MAX + 10];
    st.append(4, 0, 0, &long);
    st.append(4, 0, 0, b"\n");
    if st.next_seq != 2
        || st.desc(0).len as usize != RECORD_TEXT_MAX
        || st.desc(1).len != 10
        || st.desc(1).flags & LOG_CONT == 0
    {
        return TestResult::Fail("over-long line must split with LOG_CONT on the tail");
    }
    // An injected record lands between a pending fragment and its rest:
    // the fragment is committed first, the rest flagged as continuation.
    let mut st = Store::boxed();
    st.append(4, 0, 0, b"head-");
    st.emit(LOG_USER, 6, 0, b"user\n");
    st.append(4, 0, 0, b"tail\n");
    if st.next_seq != 3
        || st.rec_text(&st.desc(0)) != b"head-"
        || st.rec_text(&st.desc(1)) != b"user"
        || st.rec_text(&st.desc(2)) != b"tail"
        || st.desc(2).flags & LOG_CONT == 0
    {
        return TestResult::Fail("interleaved injection must keep arrival order");
    }
    // Fragments from two CPUs never merge into one record (Linux's
    // caller_id check); the interrupted CPU's remainder is LOG_CONT.
    let mut st = Store::boxed();
    st.append(4, 0, 0, b"cpu0-a ");
    st.append(4, 0, 1, b"cpu1 line\n");
    st.append(4, 0, 0, b"cpu0-b\n");
    if st.next_seq != 3
        || st.rec_text(&st.desc(0)) != b"cpu0-a "
        || st.rec_text(&st.desc(1)) != b"cpu1 line"
        || st.desc(1).flags & LOG_CONT != 0
        || st.rec_text(&st.desc(2)) != b"cpu0-b"
        || st.desc(2).flags & LOG_CONT == 0
    {
        return TestResult::Fail("cross-CPU fragments must not merge");
    }
    TestResult::Pass
}
kernel_test_in!("console/klog", smoke_klog_fragments_form_one_record);

/// `/dev/kmsg` record format: `prio,seq,ts_usec,flags;text\n`, with
/// non-printables and '\' hex-escaped (`msg_add_ext_text`).
fn smoke_klog_kmsg_record_format() -> TestResult {
    let mut st = Store::boxed();
    st.emit(LOG_USER, 6, 1_234_567_890, b"hi\tx\\y\n");
    st.append(3, 2_000, 0, b"kern\n");
    let mut cur = 0;
    let a = read_one(&st, &mut cur);
    if a.as_deref() != Ok(&b"14,0,1234567,-;hi\\x09x\\x5cy\n"[..]) {
        return TestResult::Fail("user record not formatted as a Linux ext record");
    }
    let b = read_one(&st, &mut cur);
    if b.as_deref() != Ok(&b"3,1,2,-;kern\n"[..]) {
        return TestResult::Fail("kernel record not formatted as a Linux ext record");
    }
    if read_one(&st, &mut cur) != Err(KmsgRead::Empty) || cur != 2 {
        return TestResult::Fail("caught-up read must be Empty (EAGAIN)");
    }
    TestResult::Pass
}
kernel_test_in!("console/klog", smoke_klog_kmsg_record_format);

/// One record per read; a buffer too small for the record is EINVAL and the
/// record is skipped (Linux advances the cursor before the size check).
fn smoke_klog_kmsg_too_small_skips() -> TestResult {
    let mut st = Store::boxed();
    st.append(6, 0, 0, b"first record\nsecond\n");
    let mut cur = 0;
    let mut small = [0u8; 8];
    if st.kmsg_read(&mut cur, &mut small) != KmsgRead::TooSmall {
        return TestResult::Fail("record larger than the buffer must be TooSmall");
    }
    if cur != 1 {
        return TestResult::Fail("TooSmall must advance past the record");
    }
    // An exactly-sized buffer succeeds and receives exactly one record.
    let want = b"6,1,0,-;second\n";
    let mut exact = [0u8; 15];
    if st.kmsg_read(&mut cur, &mut exact) != KmsgRead::Record(want.len()) || &exact != want {
        return TestResult::Fail("exact-size buffer must receive exactly one record");
    }
    TestResult::Pass
}
kernel_test_in!("console/klog", smoke_klog_kmsg_too_small_skips);

/// Overrun: a reader whose record was overwritten gets Dropped (EPIPE) once,
/// its cursor moved to the oldest survivor; then reads resume. Covers both
/// descriptor-count and text-space eviction.
fn smoke_klog_overrun_epipe_resync() -> TestResult {
    let mut st = Store::boxed();
    for _ in 0..(DEFAULT_DESC_COUNT + 5) {
        st.append(6, 0, 0, b"x\n");
    }
    if st.first_seq != 5 {
        return TestResult::Fail("descriptor ring did not evict exactly the overflow");
    }
    let mut cur = 0;
    if read_one(&st, &mut cur) != Err(KmsgRead::Dropped) || cur != 5 {
        return TestResult::Fail("overwritten cursor must be Dropped and resync to the oldest");
    }
    match read_one(&st, &mut cur) {
        Ok(r) if r.starts_with(b"6,5,") => {}
        _ => return TestResult::Fail("read after EPIPE must return the oldest record"),
    }
    // Text pressure: 1000-byte records, each with a distinct fill byte.
    let mut st = Store::boxed();
    let n = 3 * DEFAULT_LOG_BUF_LEN / 1000;
    for i in 0..n {
        let mut rec = [b'a' + (i % 26) as u8; 1001];
        rec[1000] = b'\n';
        st.append(6, 0, 0, &rec);
    }
    if st.first_seq == 0 || st.next_seq != n as u64 {
        return TestResult::Fail("text ring did not evict old records");
    }
    for seq in st.first_seq..st.next_seq {
        let d = st.desc(seq);
        let want = b'a' + (seq % 26) as u8;
        if d.seq != seq || d.len != 1000 || st.rec_text(&d).iter().any(|&b| b != want) {
            return TestResult::Fail("surviving record text corrupted by wrap");
        }
    }
    TestResult::Pass
}
kernel_test_in!("console/klog", smoke_klog_overrun_epipe_resync);

/// syslog(2) text: `<prio>[%5lu.%06lu] line\n` per line of a record
/// (`record_print_text` with printk.time=1).
fn smoke_klog_syslog_format() -> TestResult {
    let mut st = Store::boxed();
    st.append(3, 5_000_123_456, 0, b"disk on fire\n");
    st.emit(LOG_USER, 4, 12_345_678_901_000, b"a\nb");
    let mut out = [0u8; 256];
    let n = st.syslog_read_all(&mut out, false);
    let want: &[u8] =
        b"<3>[    5.000123] disk on fire\n<12>[12345.678901] a\n<12>[12345.678901] b\n";
    if &out[..n] != want {
        return TestResult::Fail("READ_ALL text differs from Linux syslog_print_all");
    }
    if st.syslog_all_size() != want.len() || st.syslog_size_unread() != want.len() {
        return TestResult::Fail("size accounting disagrees with the rendered text");
    }
    // READ_ALL with a small buffer keeps the NEWEST records that fit.
    let mut small = [0u8; 45];
    let n = st.syslog_read_all(&mut small, false);
    if &small[..n] != b"<12>[12345.678901] a\n<12>[12345.678901] b\n" {
        return TestResult::Fail("small READ_ALL must drop the oldest records, not the newest");
    }
    // READ drains, continuing partially-read records across calls.
    let mut got = Vec::new();
    let mut chunk = [0u8; 7];
    for _ in 0..100 {
        let n = st.syslog_read(&mut chunk);
        if n == 0 {
            break;
        }
        got.extend_from_slice(&chunk[..n]);
    }
    if got != want {
        return TestResult::Fail("partial READs must reassemble the full text");
    }
    if st.syslog_size_unread() != 0 {
        return TestResult::Fail("SIZE_UNREAD must be 0 after READ drained");
    }
    // READ_CLEAR returns the text and moves clear_seq past it.
    if st.syslog_read_all(&mut out, true) != want.len() || st.syslog_read_all(&mut out, false) != 0
    {
        return TestResult::Fail("READ_CLEAR must return then clear");
    }
    TestResult::Pass
}
kernel_test_in!("console/klog", smoke_klog_syslog_format);

/// `log_buf_len=`: memparse suffixes, power-of-two rounding, only growth
/// accepted, 2 GiB clamp (`log_buf_len_update`).
fn smoke_klog_log_buf_len_rounding() -> TestResult {
    let d = DEFAULT_LOG_BUF_LEN;
    let cases: [(&str, Option<usize>); 9] = [
        ("1M", Some(1 << 20)),
        ("200000", Some(1 << 18)),
        ("0x30000", Some(1 << 18)),
        ("3m", Some(4 << 20)),
        ("64k", None),  // smaller than the default: ignored
        ("128K", None), // equal: ignored
        ("junk", None), // memparse → 0
        ("0", None),
        ("5G", Some(1 << 31)), // clamped to LOG_BUF_LEN_MAX
    ];
    for (arg, want) in cases {
        if log_buf_len_value(arg, d) != want {
            return TestResult::Fail("log_buf_len rounding differs from log_buf_len_update");
        }
    }
    if memparse("0x") != 0 || memparse("010") != 8 || memparse("2k") != 2048 {
        return TestResult::Fail("memparse radix/suffix handling differs from Linux");
    }
    if log_buf_len() < DEFAULT_LOG_BUF_LEN {
        return TestResult::Fail("live log_buf_len below the CONFIG_LOG_BUF_SHIFT floor");
    }
    TestResult::Pass
}
kernel_test_in!("console/klog", smoke_klog_log_buf_len_rounding);

/// `setup_log_buf` migration keeps every record and its sequence number.
fn smoke_klog_grow_preserves_records() -> TestResult {
    let mut st = Store::boxed();
    for _ in 0..(DEFAULT_DESC_COUNT + 3) {
        st.append(5, 42, 0, b"rec\n");
    }
    let (first, next) = (st.first_seq, st.next_seq);
    let size = 1 << 18;
    let (Some(t), Some(dd)) = (
        try_zeroed(size, 0u8),
        try_zeroed(size >> PRB_AVGBITS, EMPTY_DESC),
    ) else {
        return TestResult::Skip("no memory for the grown rings");
    };
    let _ = st.grow(t, dd);
    if st.text().len() != size || st.first_seq != first || st.next_seq != next {
        return TestResult::Fail("grow changed the sequence range or size");
    }
    for s in first..next {
        let d = st.desc(s);
        if d.seq != s || st.rec_text(&d) != b"rec" || d.ts_nsec != 42 {
            return TestResult::Fail("grow lost or corrupted a record");
        }
    }
    st.append(5, 0, 0, b"after\n");
    if st.rec_text(&st.desc(next)) != b"after" {
        return TestResult::Fail("store unusable after grow");
    }
    TestResult::Pass
}
kernel_test_in!("console/klog", smoke_klog_grow_preserves_records);

/// Console-only output (syscall-trace) must not enter the store; a normal
/// `write_str` must.
fn smoke_klog_console_only_not_recorded() -> TestResult {
    use core::fmt::Write as _;
    let seq = next_seq();
    crate::write_str_console_only("narf-console-only-probe-7f3a\n");
    let tag = 0x8e1c;
    let _ = writeln!(crate::ConsoleOnlyWriter, "narf-console-only-probe-{tag:x}");
    let has = |hay: &[u8], n: &[u8]| hay.windows(n.len()).any(|w| w == n);
    if has(&text_since(seq), b"narf-console-only-probe") {
        return TestResult::Fail("console-only text leaked into the kernel log store");
    }
    crate::write_str("narf-console-store-probe-5d2b\n");
    if !has(&text_since(seq), b"narf-console-store-probe-5d2b") {
        return TestResult::Fail("write_str text missing from the kernel log store");
    }
    TestResult::Pass
}
kernel_test_in!("console/klog", smoke_klog_console_only_not_recorded);
