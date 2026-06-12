//! Kernel-test entries for the 9P2000 protocol layer.
//!
//! Pure-logic tests cover the wire-format codec (header, qid, stat,
//! walk-name validation). End-to-end tests exercise the protocol +
//! VFS adapter via `LoopbackTransport` — a synthetic in-process
//! 9P server that synthesises R-replies for each T-message. No DMA,
//! no `BlockDevice`, no real network.

use alloc::sync::Arc;

use narf_filesystem::{FileType, FsInstance};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::id::DomainId;

use crate::loopback::LoopbackTransport;
use crate::message::{
    decode_header, decode_rread, decode_rversion, encode_tread, encode_tversion, encode_twalk,
    qtype, validate_walk_name, MsgType, P9Stat, Qid, WireRead, WireWrite, HEADER_SIZE, NOFID,
    NOTAG,
};
use crate::session::{frame_message, P9Session};
use crate::volume::NinepVolume;

// ── Sync future helper (loopback completes synchronously) ─────────

fn poll_once<F: core::future::Future>(mut fut: F) -> Option<F::Output> {
    use core::pin::Pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw() -> RawWaker {
        unsafe fn no_clone(_: *const ()) -> RawWaker {
            raw()
        }
        unsafe fn no_op(_: *const ()) {}
        const VT: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VT)
    }
    // SAFETY: vtable's clone returns the same null RawWaker; the
    // wake/wake_by_ref/drop slots are no-ops, so the Waker
    // contract holds trivially.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let waker = unsafe { Waker::from_raw(raw()) };
    let mut cx = Context::from_waker(&waker);
    // SAFETY: we own `fut` on the stack and don't move it.
    let pinned = unsafe { Pin::new_unchecked(&mut fut) };
    match pinned.poll(&mut cx) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

// ── Protocol-codec smoke tests ────────────────────────────────────

fn smoke_9p_qid_roundtrip() -> TestResult {
    // Qid is the 13-byte type/version/path triple (intro(5)). Round-
    // trip a populated qid through the encoder + decoder and verify
    // bit-exact equality. Catches any endianness or field-ordering
    // regression in WireRead/WireWrite.
    let mut buf = [0u8; 13];
    let original = Qid {
        qid_type: qtype::DIR,
        version: 0xDEAD_BEEF,
        path: 0x0123_4567_89AB_CDEF,
    };
    {
        let mut w = WireWrite::new(&mut buf);
        if w.write_qid(&original).is_err() {
            return TestResult::Fail("write_qid encode failed");
        }
        if w.pos() != 13 {
            return TestResult::Fail("qid wire size != 13");
        }
    }
    let mut r = WireRead::new(&buf);
    let decoded = match r.read_qid() {
        Ok(q) => q,
        Err(_) => return TestResult::Fail("read_qid decode failed"),
    };
    if decoded != original {
        return TestResult::Fail("qid round-trip differs");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/9p", smoke_9p_qid_roundtrip);

fn smoke_9p_tversion_rversion_frame_decode() -> TestResult {
    // Build a Tversion with msize 8192 / version "9P2000", verify the
    // 7-byte header + body match what version(5) prescribes, then
    // hand-craft the corresponding Rversion bytes and decode them.
    let session = P9Session::new();
    let req = match frame_message(session.msize(), MsgType::Tversion, NOTAG, |w| {
        encode_tversion(w, 8192, "9P2000")
    }) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("frame_message Tversion failed"),
    };
    // Header layout: size[4] type[1] tag[2].
    if req.len() < HEADER_SIZE {
        return TestResult::Fail("framed Tversion too short");
    }
    let size = u32::from_le_bytes([req[0], req[1], req[2], req[3]]);
    if size as usize != req.len() {
        return TestResult::Fail("Tversion size header doesn't match length");
    }
    if req[4] != MsgType::Tversion as u8 {
        return TestResult::Fail("Tversion type byte wrong");
    }
    let tag = u16::from_le_bytes([req[5], req[6]]);
    if tag != NOTAG {
        return TestResult::Fail("Tversion tag should be NOTAG");
    }
    // Body: msize[4] then string[2]+bytes.
    let msize = u32::from_le_bytes([req[7], req[8], req[9], req[10]]);
    if msize != 8192 {
        return TestResult::Fail("Tversion msize wrong");
    }
    let nlen = u16::from_le_bytes([req[11], req[12]]) as usize;
    if nlen != 6 || &req[13..13 + nlen] != b"9P2000" {
        return TestResult::Fail("Tversion version string wrong");
    }

    // Now hand-craft an Rversion: size[4] type[1] tag[2] msize[4]
    // version[s].
    let body_after_hdr: u16 = 6;
    let total: u32 = (HEADER_SIZE + 4 + 2 + body_after_hdr as usize) as u32;
    let mut rep = alloc::vec![0u8; total as usize];
    rep[0..4].copy_from_slice(&total.to_le_bytes());
    rep[4] = MsgType::Rversion as u8;
    rep[5..7].copy_from_slice(&NOTAG.to_le_bytes());
    rep[7..11].copy_from_slice(&8192u32.to_le_bytes());
    rep[11..13].copy_from_slice(&body_after_hdr.to_le_bytes());
    rep[13..19].copy_from_slice(b"9P2000");

    let mut rd = WireRead::new(&rep);
    let (sz, mt, tg) = match decode_header(&mut rd) {
        Ok(t) => t,
        Err(_) => return TestResult::Fail("decode_header on Rversion failed"),
    };
    if sz != total || mt != MsgType::Rversion || tg != NOTAG {
        return TestResult::Fail("Rversion header decode mismatch");
    }
    let rv = match decode_rversion(&mut rd) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("decode_rversion failed"),
    };
    if rv.msize != 8192 || rv.version != "9P2000" {
        return TestResult::Fail("Rversion body decode mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/9p", smoke_9p_tversion_rversion_frame_decode);

fn smoke_9p_stat_decode_variable_length() -> TestResult {
    // Hand-build a stat structure with name="hello", uid="u",
    // gid="g", muid="m" and verify the body_len() / decode round-
    // trip. The leading size[2] must equal body_len() per stat(5).
    let original = P9Stat {
        kernel_type: 0x1234,
        kernel_dev: 0xCAFE_F00D,
        qid: Qid {
            qid_type: qtype::FILE,
            version: 1,
            path: 42,
        },
        mode: 0o644,
        atime: 100,
        mtime: 200,
        length: 5,
        name: alloc::string::String::from("hello"),
        uid: alloc::string::String::from("u"),
        gid: alloc::string::String::from("g"),
        muid: alloc::string::String::from("m"),
    };
    let body = original.body_len();
    let total = body + 2; // include the leading size[2]
    let mut buf = alloc::vec![0u8; total];
    {
        let mut w = WireWrite::new(&mut buf);
        if original.encode(&mut w).is_err() {
            return TestResult::Fail("stat encode failed");
        }
        if w.pos() != total {
            return TestResult::Fail("stat encode wrote wrong length");
        }
    }
    // Verify the leading size matches body_len.
    let claimed = u16::from_le_bytes([buf[0], buf[1]]) as usize;
    if claimed != body {
        return TestResult::Fail("stat leading size != body_len");
    }
    let mut r = WireRead::new(&buf);
    let decoded = match P9Stat::decode(&mut r) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("stat decode failed"),
    };
    if r.pos() != total {
        return TestResult::Fail("stat decode consumed wrong length");
    }
    if decoded.kernel_type != original.kernel_type
        || decoded.kernel_dev != original.kernel_dev
        || decoded.qid != original.qid
        || decoded.mode != original.mode
        || decoded.atime != original.atime
        || decoded.mtime != original.mtime
        || decoded.length != original.length
        || decoded.name != original.name
        || decoded.uid != original.uid
        || decoded.gid != original.gid
        || decoded.muid != original.muid
    {
        return TestResult::Fail("stat field mismatch after round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/9p", smoke_9p_stat_decode_variable_length);

fn smoke_9p_walk_name_validation() -> TestResult {
    // walk(5): components are 1..=255 bytes and must not contain '/'.
    if validate_walk_name("foo").is_err() {
        return TestResult::Fail("simple name should validate");
    }
    if validate_walk_name("").is_ok() {
        return TestResult::Fail("empty name must reject");
    }
    if validate_walk_name("a/b").is_ok() {
        return TestResult::Fail("slash in name must reject");
    }
    let too_long = alloc::string::String::from_utf8(alloc::vec![b'x'; 256]).unwrap();
    if validate_walk_name(&too_long).is_ok() {
        return TestResult::Fail("256-byte name must reject");
    }
    let max = alloc::string::String::from_utf8(alloc::vec![b'x'; 255]).unwrap();
    if validate_walk_name(&max).is_err() {
        return TestResult::Fail("255-byte name should validate");
    }
    // encode_twalk should reject more than 16 wnames.
    let lots: alloc::vec::Vec<&str> = alloc::vec!["a"; 17];
    let mut buf = [0u8; 1024];
    let mut w = WireWrite::new(&mut buf);
    if encode_twalk(&mut w, 0, 1, &lots).is_ok() {
        return TestResult::Fail("Twalk with 17 names must reject");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/9p", smoke_9p_walk_name_validation);

fn smoke_9p_rread_decode_count_prefix() -> TestResult {
    // Rread is `count[4] data[count]`. Build one by hand at the
    // body level (not framed) and verify decode_rread returns the
    // right slice.
    let payload = b"hello 9p";
    let mut buf = alloc::vec![0u8; 4 + payload.len()];
    buf[0..4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    buf[4..].copy_from_slice(payload);
    let mut r = WireRead::new(&buf);
    let data = match decode_rread(&mut r) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail("decode_rread failed"),
    };
    if data != payload {
        return TestResult::Fail("Rread payload mismatch");
    }
    if r.remaining() != 0 {
        return TestResult::Fail("Rread decode left trailing bytes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/9p", smoke_9p_rread_decode_count_prefix);

fn smoke_9p_tread_encode_layout() -> TestResult {
    // Tread body: fid[4] offset[8] count[4] = 16 bytes.
    let mut buf = [0u8; 16];
    let mut w = WireWrite::new(&mut buf);
    if encode_tread(&mut w, 0xDEAD_BEEF, 0x0123_4567_89AB_CDEF, 4096).is_err() {
        return TestResult::Fail("Tread encode failed");
    }
    if w.pos() != 16 {
        return TestResult::Fail("Tread body should be 16 bytes");
    }
    let fid = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if fid != 0xDEAD_BEEF {
        return TestResult::Fail("Tread fid wrong");
    }
    let mut o = [0u8; 8];
    o.copy_from_slice(&buf[4..12]);
    if u64::from_le_bytes(o) != 0x0123_4567_89AB_CDEF {
        return TestResult::Fail("Tread offset wrong");
    }
    let count = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
    if count != 4096 {
        return TestResult::Fail("Tread count wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/9p", smoke_9p_tread_encode_layout);

fn smoke_9p_nofid_notag_constants() -> TestResult {
    // Defensive: the values are spec-mandated, so guard against an
    // accidental change. attach(5) calls out NOFID = ~0u32; intro(5)
    // calls out NOTAG = ~0u16.
    if NOFID != 0xFFFF_FFFF {
        return TestResult::Fail("NOFID must be 0xFFFFFFFF");
    }
    if NOTAG != 0xFFFF {
        return TestResult::Fail("NOTAG must be 0xFFFF");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/9p", smoke_9p_nofid_notag_constants);

// ── End-to-end tests via LoopbackTransport ────────────────────────

fn smoke_9p_loopback_mount_and_enumerate() -> TestResult {
    // Build a synthetic tree: root with one file "greeting" containing
    // "hello 9p". Mount, enumerate root, look up the file, read the
    // bytes back. Exercises Tversion + Tattach + Twalk + Topen + Tread
    // + the directory-stat parser + the stream-of-stats reader.
    let transport: Arc<LoopbackTransport> = LoopbackTransport::new(&[("greeting", b"hello 9p")]);
    // We need an Arc<dyn Transport>; the struct's `new` returns
    // `Arc<LoopbackTransport>` which dyn-coerces.
    let t: Arc<dyn crate::session::Transport> = transport.clone();

    let vol = match poll_once(NinepVolume::mount(t, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            let _ = e;
            return TestResult::Fail("mount returned Err");
        }
        None => return TestResult::Fail("mount didn't complete synchronously"),
    };
    if vol.name() != "9p" {
        return TestResult::Fail("FsInstance name should be \"9p\"");
    }

    let root = vol.root();
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate_async failed"),
    };
    if entries.len() != 1 {
        return TestResult::Fail("expected exactly 1 entry");
    }
    if entries[0].0 != "greeting" || entries[0].1 != FileType::File {
        return TestResult::Fail("entry name/type mismatch");
    }

    let file = match poll_once(root.lookup_async("greeting")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup_async greeting failed"),
    };
    let st = match poll_once(file.stat_async()) {
        Some(Ok(s)) => s,
        _ => return TestResult::Fail("stat_async failed"),
    };
    if st.size != 8 || st.mode.file_type != FileType::File {
        return TestResult::Fail("stat fields mismatch");
    }

    let mut buf = [0u8; 32];
    let n = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read failed"),
    };
    if n != 8 || &buf[..n] != b"hello 9p" {
        return TestResult::Fail("read bytes mismatch");
    }

    // Verify the loopback handled at least the expected exchanges:
    // Tversion, Tattach, Topen(root), Tread(root), Twalk, Tstat,
    // Topen(file), Tread(file) ≥ 8 RPCs.
    if transport.rpc_count() < 8 {
        return TestResult::Fail("expected >= 8 RPCs through loopback");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/9p", smoke_9p_loopback_mount_and_enumerate);

fn smoke_9p_loopback_lookup_missing_returns_notfound() -> TestResult {
    use narf_filesystem::FsError;
    let transport = LoopbackTransport::new(&[("present", b"x")]);
    let t: Arc<dyn crate::session::Transport> = transport.clone();
    let vol = match poll_once(NinepVolume::mount(t, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = vol.root();
    match poll_once(root.lookup_async("absent")) {
        Some(Err(FsError::NotFound)) => TestResult::Pass,
        Some(Err(_)) => TestResult::Fail("expected NotFound, got other error"),
        Some(Ok(_)) => TestResult::Fail("lookup of absent file should fail"),
        None => TestResult::Fail("lookup_async didn't complete"),
    }
}
kernel_test_in!(
    "drivers/fs/9p",
    smoke_9p_loopback_lookup_missing_returns_notfound
);

fn smoke_9p_loopback_multiple_files_enumerate_in_order() -> TestResult {
    let transport = LoopbackTransport::new(&[("alpha", b"a"), ("beta", b"bb"), ("gamma", b"ccc")]);
    let t: Arc<dyn crate::session::Transport> = transport.clone();
    let vol = match poll_once(NinepVolume::mount(t, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = vol.root();
    let entries = match poll_once(root.enumerate_async(0, 16)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("enumerate failed"),
    };
    if entries.len() != 3 {
        return TestResult::Fail("expected 3 entries");
    }
    let names: alloc::vec::Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    if names != ["alpha", "beta", "gamma"] {
        return TestResult::Fail("enumerate order wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/9p",
    smoke_9p_loopback_multiple_files_enumerate_in_order
);

// ── Write-path smokes (Twrite / Rwrite) ─────────────────────────

fn smoke_9p_write_then_read_back() -> TestResult {
    // Round-trip a Twrite + Tread through the loopback transport.
    let transport = LoopbackTransport::new(&[("greet", b"initial-content")]);
    let t: Arc<dyn crate::session::Transport> = transport.clone();
    let vol = match poll_once(NinepVolume::mount(t, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = vol.root();
    let file = match poll_once(root.lookup_async("greet")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup greet failed"),
    };
    let payload = b"hello from Twrite";
    let n = match poll_once(file.write(0, payload)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("write failed"),
    };
    if n != payload.len() {
        return TestResult::Fail("short write");
    }
    let mut buf = [0u8; 64];
    let m = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read failed"),
    };
    if &buf[..m] != payload {
        return TestResult::Fail("read-back mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/9p", smoke_9p_write_then_read_back);

fn smoke_9p_write_at_offset_extends_file() -> TestResult {
    // Write past the current end of file; the server should
    // extend the file body to cover the gap (zeros) + new data.
    let transport = LoopbackTransport::new(&[("greet", b"abc")]);
    let t: Arc<dyn crate::session::Transport> = transport.clone();
    let vol = match poll_once(NinepVolume::mount(t, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = vol.root();
    let file = match poll_once(root.lookup_async("greet")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup failed"),
    };
    let n = match poll_once(file.write(10, b"xyz")) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("write at offset failed"),
    };
    if n != 3 {
        return TestResult::Fail("short write");
    }
    let mut buf = [0u8; 32];
    let m = match poll_once(file.read(0, &mut buf)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("read failed"),
    };
    if m != 13 || &buf[..3] != b"abc" || &buf[10..13] != b"xyz" {
        return TestResult::Fail("post-write contents wrong");
    }
    // Bytes 3..10 should be zero-filled.
    if buf[3..10].iter().any(|&b| b != 0) {
        return TestResult::Fail("gap not zero-filled");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/9p", smoke_9p_write_at_offset_extends_file);

fn smoke_9p_write_count_matches_request() -> TestResult {
    // The Rwrite count field is the bytes-written value the client
    // surfaces from FileOps::write.
    let transport = LoopbackTransport::new(&[("greet", b"")]);
    let t: Arc<dyn crate::session::Transport> = transport.clone();
    let vol = match poll_once(NinepVolume::mount(t, DomainId::DRIVER_0)) {
        Some(Ok(v)) => v,
        _ => return TestResult::Fail("mount failed"),
    };
    let root = vol.root();
    let file = match poll_once(root.lookup_async("greet")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup failed"),
    };
    let payload = b"exact-12-byt";
    let n = match poll_once(file.write(0, payload)) {
        Some(Ok(n)) => n,
        _ => return TestResult::Fail("write failed"),
    };
    if n != payload.len() {
        return TestResult::Fail("expected n == payload.len()");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/9p", smoke_9p_write_count_matches_request);
