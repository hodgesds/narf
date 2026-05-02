//! Per-crate smoke tests for `narf-firmware`. Tests register via
//! `narf_kernel_test::kernel_test_in!` so the runner groups output
//! under `firmware`.

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    bootstrap_authority, install, open, register_in_tree, snapshot,
    source_for, view_of, BlobSource, FirmwareError, BLOB_TRAILER_MAGIC,
};
use crate::registry::__reset_for_test;

/// Build an unsigned firmware blob whose payload is the supplied
/// bytes followed by the all-zero "unsigned" sentinel trailer.
/// Useful only under `firmware-allow-unsigned`; signed-build
/// runners skip the smokes that depend on this helper.
fn build_unsigned_blob(payload: &[u8], version: Option<&str>) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(payload.len() + 256);
    out.extend_from_slice(payload);
    // 64-byte all-zero signature
    out.extend_from_slice(&[0u8; 64]);
    // 32-byte all-zero signer fingerprint
    out.extend_from_slice(&[0u8; 32]);
    // Metadata: TLV records. tag 0x01 = ASCII version string.
    let mut md = alloc::vec::Vec::new();
    if let Some(v) = version {
        md.push(0x01);
        md.push(v.len() as u8);
        md.extend_from_slice(v.as_bytes());
    }
    let mlen = md.len() as u32;
    out.extend_from_slice(&mlen.to_le_bytes());
    out.extend_from_slice(&md);
    out.extend_from_slice(&BLOB_TRAILER_MAGIC);
    out
}

fn smoke_firmware_trailer_decode_unsigned_blob() -> TestResult {
    // Round-trips the trailer parser: build a synthetic unsigned
    // blob, decode it, check payload + version + unsigned sentinel.
    use crate::signature;
    let blob = build_unsigned_blob(b"hello, firmware", Some("1.0.0"));
    let trailer = match signature::decode(&blob) {
        Ok(t)  => t,
        Err(_) => return TestResult::Fail("decode rejected synthetic blob"),
    };
    if trailer.payload != b"hello, firmware" {
        return TestResult::Fail("payload mismatch");
    }
    if !trailer.is_unsigned() {
        return TestResult::Fail("unsigned sentinel not detected");
    }
    if trailer.version.as_deref() != Some("1.0.0") {
        return TestResult::Fail("version metadata not recovered");
    }
    TestResult::Pass
}
kernel_test_in!("firmware", smoke_firmware_trailer_decode_unsigned_blob);

fn smoke_firmware_trailer_rejects_bad_magic() -> TestResult {
    use crate::signature;
    // Build a valid blob, corrupt the trailing magic.
    let mut blob = build_unsigned_blob(b"x", None);
    let n = blob.len();
    blob[n - 1] ^= 0xFF;
    match signature::decode(&blob) {
        Err(FirmwareError::BadFormat) => TestResult::Pass,
        Ok(_)  => TestResult::Fail("decode accepted corrupt magic"),
        Err(_) => TestResult::Fail("wrong error variant"),
    }
}
kernel_test_in!("firmware", smoke_firmware_trailer_rejects_bad_magic);

fn smoke_firmware_install_and_open_unsigned() -> TestResult {
    // Only meaningful when the build accepts unsigned blobs.
    if !cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("firmware-allow-unsigned off — registry rejects unsigned");
    }
    __reset_for_test();
    let payload = b"BHI test blob, ignore" as &[u8];
    let blob = build_unsigned_blob(payload, Some("0.0.1"));
    let (write, read) = bootstrap_authority();
    if install("test/blob", &blob, &write).is_err() {
        return TestResult::Fail("install rejected");
    }
    let cap = match open("test/blob", &read) {
        Ok(c)  => c,
        Err(_) => return TestResult::Fail("open after install"),
    };
    let view = match view_of(&cap) {
        Ok(v)  => v,
        Err(_) => return TestResult::Fail("view through cap"),
    };
    if view.bytes.len() != payload.len() {
        return TestResult::Fail("payload length mismatch through cap");
    }
    for (i, &b) in payload.iter().enumerate() {
        if view.bytes[i] != b {
            return TestResult::Fail("payload byte mismatch through cap");
        }
    }
    if source_for("test/blob") != Some(BlobSource::HotInstall) {
        return TestResult::Fail("source_for didn't report HotInstall");
    }
    TestResult::Pass
}
kernel_test_in!("firmware", smoke_firmware_install_and_open_unsigned);

fn smoke_firmware_register_in_tree_lands_in_in_tree_tier() -> TestResult {
    if !cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("firmware-allow-unsigned off");
    }
    __reset_for_test();
    let blob = build_unsigned_blob(b"in-tree fallback", None);
    if register_in_tree("vendor/in-tree-blob", &blob).is_err() {
        return TestResult::Fail("register_in_tree rejected");
    }
    if source_for("vendor/in-tree-blob") != Some(BlobSource::InTree) {
        return TestResult::Fail("source_for didn't report InTree");
    }
    let snap = snapshot();
    if !snap.iter().any(|e| e.name == "vendor/in-tree-blob"
        && e.source == BlobSource::InTree)
    {
        return TestResult::Fail("snapshot missing in-tree entry");
    }
    TestResult::Pass
}
kernel_test_in!("firmware", smoke_firmware_register_in_tree_lands_in_in_tree_tier);

fn smoke_firmware_open_unknown_blob_returns_not_found() -> TestResult {
    __reset_for_test();
    let (_w, read) = bootstrap_authority();
    match open("doesnt/exist", &read) {
        Err(FirmwareError::NotFound) => TestResult::Pass,
        Ok(_)  => TestResult::Fail("open succeeded for absent blob"),
        Err(_) => TestResult::Fail("wrong error variant"),
    }
}
kernel_test_in!("firmware", smoke_firmware_open_unknown_blob_returns_not_found);

fn smoke_firmware_unsigned_rejected_when_feature_off() -> TestResult {
    if cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("feature on — unsigned accepted");
    }
    __reset_for_test();
    let blob = build_unsigned_blob(b"x", None);
    let (write, _r) = bootstrap_authority();
    match install("nope/x", &blob, &write) {
        Err(FirmwareError::UnsignedRejected) => TestResult::Pass,
        Ok(_)  => TestResult::Fail("registry accepted unsigned blob in production build"),
        Err(_) => TestResult::Fail("wrong error variant"),
    }
}
kernel_test_in!("firmware", smoke_firmware_unsigned_rejected_when_feature_off);
