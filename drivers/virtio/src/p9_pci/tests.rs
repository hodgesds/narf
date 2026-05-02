//! virtio-9p smokes — clean room (VirtIO 1.2 §5.9 + 9P2000.L spec).

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    MountTag, MountTagDecodeError,
    VIRTIO_9P_PCI_DEVICE, VIRTIO_9P_PCI_VENDOR,
};
use super::p9;

// ── Stage 1 ────────────────────────────────────────────────────────

fn smoke_p9_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let matched = registered.iter().any(|m|
        matches!(m.kind, MatchKind::VendorDevice {
            vendor: VIRTIO_9P_PCI_VENDOR, device: VIRTIO_9P_PCI_DEVICE,
        }));
    if !matched {
        return TestResult::Fail("virtio-9p PCI match table missing entry");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_p9_match_table);

fn smoke_p9_mount_tag_decode() -> TestResult {
    // VirtIO 1.2 §5.9.4: u16 LE length followed by `length` bytes.
    let tag = b"hostshare";
    let mut wire: Vec<u8> = Vec::new();
    wire.extend_from_slice(&(tag.len() as u16).to_le_bytes());
    wire.extend_from_slice(tag);
    let mt = match MountTag::decode(&wire) {
        Ok(m)  => m,
        Err(_) => return TestResult::Fail("decode failed"),
    };
    if mt.tag != tag {
        return TestResult::Fail("mount tag bytes mismatch");
    }
    if mt.encode() != wire {
        return TestResult::Fail("round-trip mismatch");
    }
    // Empty tag is valid.
    let empty = vec![0u8, 0u8];
    match MountTag::decode(&empty) {
        Ok(m) if m.tag.is_empty() => {}
        _ => return TestResult::Fail("empty-tag decode failed"),
    }
    // Truncated buffer: 1 byte (need 2 for len).
    if MountTag::decode(&[0u8]) != Err(MountTagDecodeError::TooShortForLen) {
        return TestResult::Fail("expected TooShortForLen");
    }
    // Length says 5 but only 3 bytes follow.
    let bad = [5u8, 0, b'a', b'b', b'c'];
    if MountTag::decode(&bad) != Err(MountTagDecodeError::TooShortForTag) {
        return TestResult::Fail("expected TooShortForTag");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_p9_mount_tag_decode);

// ── Stage 2: 9P2000.L round-trips ─────────────────────────────────

fn smoke_p9_tversion_roundtrip() -> TestResult {
    let m = p9::Tversion {
        tag:     0xFFFF,
        msize:   8192,
        version: b"9P2000.L".to_vec(),
    };
    let wire = m.encode();
    // Header: size includes itself.
    if (wire[0] as u32 | (wire[1] as u32) << 8
        | (wire[2] as u32) << 16 | (wire[3] as u32) << 24) as usize
        != wire.len()
    {
        return TestResult::Fail("Tversion size field wrong");
    }
    if wire[4] != p9::T_VERSION {
        return TestResult::Fail("Tversion type byte wrong");
    }
    let h = match p9::Header::decode(&wire) {
        Ok(h) => h, Err(_) => return TestResult::Fail("header decode"),
    };
    if h.tag != 0xFFFF || h.kind != p9::T_VERSION {
        return TestResult::Fail("header fields wrong");
    }
    match p9::Tversion::decode(&wire) {
        Ok(d) if d == m => TestResult::Pass,
        Ok(_)  => TestResult::Fail("Tversion mismatch"),
        Err(_) => TestResult::Fail("Tversion decode err"),
    }
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_p9_tversion_roundtrip);

fn smoke_p9_tattach_roundtrip() -> TestResult {
    let m = p9::Tattach {
        tag:     1,
        fid:     0,
        afid:    p9::NOFID,
        uname:   b"nobody".to_vec(),
        aname:   b"hostshare".to_vec(),
        n_uname: 65534,
    };
    let wire = m.encode();
    match p9::Tattach::decode(&wire) {
        Ok(d) if d == m => TestResult::Pass,
        Ok(_)  => TestResult::Fail("Tattach mismatch"),
        Err(_) => TestResult::Fail("Tattach decode err"),
    }
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_p9_tattach_roundtrip);

fn smoke_p9_twalk_roundtrip() -> TestResult {
    let m = p9::Twalk {
        tag:    2,
        fid:    0,
        newfid: 1,
        wnames: vec![b"etc".to_vec(), b"hostname".to_vec()],
    };
    let wire = match m.encode() {
        Ok(w)  => w,
        Err(_) => return TestResult::Fail("Twalk encode err"),
    };
    match p9::Twalk::decode(&wire) {
        Ok(d) if d == m => {}
        Ok(_)  => return TestResult::Fail("Twalk mismatch"),
        Err(_) => return TestResult::Fail("Twalk decode err"),
    }
    // Empty walk is valid (clones fid).
    let zero = p9::Twalk { tag: 3, fid: 4, newfid: 5, wnames: vec![] };
    let zw = zero.encode().unwrap();
    if p9::Twalk::decode(&zw).ok() != Some(zero) {
        return TestResult::Fail("zero-walk mismatch");
    }
    // > 16 wnames must fail.
    let too_many = p9::Twalk {
        tag: 4, fid: 0, newfid: 1,
        wnames: (0..17).map(|_| b"x".to_vec()).collect(),
    };
    if too_many.encode().is_ok() {
        return TestResult::Fail("Twalk should reject >16 wnames");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_p9_twalk_roundtrip);

fn smoke_p9_tlopen_roundtrip() -> TestResult {
    let m = p9::Tlopen { tag: 5, fid: 1, flags: 0o2 /* O_RDWR */ };
    let wire = m.encode();
    match p9::Tlopen::decode(&wire) {
        Ok(d) if d == m => TestResult::Pass,
        Ok(_)  => TestResult::Fail("Tlopen mismatch"),
        Err(_) => TestResult::Fail("Tlopen decode err"),
    }
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_p9_tlopen_roundtrip);

fn smoke_p9_tread_roundtrip() -> TestResult {
    let m = p9::Tread { tag: 6, fid: 1, offset: 0x1234_5678_DEAD_BEEF, count: 4096 };
    let wire = m.encode();
    match p9::Tread::decode(&wire) {
        Ok(d) if d == m => TestResult::Pass,
        Ok(_)  => TestResult::Fail("Tread mismatch"),
        Err(_) => TestResult::Fail("Tread decode err"),
    }
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_p9_tread_roundtrip);

fn smoke_p9_tclunk_roundtrip() -> TestResult {
    let m = p9::Tclunk { tag: 7, fid: 42 };
    let wire = m.encode();
    if wire.len() != p9::HEADER_LEN + 4 {
        return TestResult::Fail("Tclunk wire length wrong");
    }
    match p9::Tclunk::decode(&wire) {
        Ok(d) if d == m => TestResult::Pass,
        Ok(_)  => TestResult::Fail("Tclunk mismatch"),
        Err(_) => TestResult::Fail("Tclunk decode err"),
    }
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_p9_tclunk_roundtrip);

fn smoke_p9_qid_roundtrip() -> TestResult {
    let q = p9::Qid { kind: 0x80, version: 0xCAFEBABE, path: 0x0123_4567_89AB_CDEF };
    let mut buf = Vec::new();
    q.encode_into(&mut buf);
    if buf.len() != p9::QID_LEN {
        return TestResult::Fail("Qid wire length wrong");
    }
    match p9::Qid::decode(&buf) {
        Ok((d, n)) if d == q && n == p9::QID_LEN => TestResult::Pass,
        _ => TestResult::Fail("Qid decode mismatch"),
    }
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_p9_qid_roundtrip);

fn smoke_virtio_p9_pci_live_tversion() -> TestResult {
    use crate::p9_pci;
    if !p9_pci::is_probed() {
        return TestResult::Skip("no virtio-9p-pci device on this run");
    }
    let r = p9_pci::with_controller(|c| c.tversion(8192, "9P2000.L"));
    match r {
        Some(Ok(rv)) => {
            if rv.msize == 0 || rv.version.is_empty() {
                return TestResult::Fail("Rversion fields unset");
            }
            TestResult::Pass
        }
        Some(Err(_))  => TestResult::Fail("tversion failed"),
        None          => TestResult::Skip("controller missing"),
    }
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_virtio_p9_pci_live_tversion);

fn smoke_virtio_p9_pci_rversion_round_trip() -> TestResult {
    use crate::p9_pci::p9::Rversion;
    let want = Rversion {
        tag: 0xFFFF, msize: 8192,
        version: b"9P2000.L".to_vec(),
    };
    let bytes = want.encode();
    let got = match Rversion::decode(&bytes) {
        Ok(g)  => g,
        Err(_) => return TestResult::Fail("decode failed"),
    };
    if got != want { return TestResult::Fail("round-trip"); }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/p9_pci", smoke_virtio_p9_pci_rversion_round_trip);
