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

fn smoke_firmware_initramfs_scan_registers_under_suffix() -> TestResult {
    // The scanner strips `firmware/` from each archive path and
    // registers the suffix as the canonical name.  Build a CPIO
    // newc archive carrying one `firmware/test/blob.bin` entry +
    // one unrelated `etc/passwd`, run the scan, verify only the
    // firmware entry landed in the registry under the right name.
    if !cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("firmware-allow-unsigned off — unsigned blob rejected");
    }
    use crate::scan_initramfs;
    __reset_for_test();
    let blob_bytes = build_unsigned_blob(b"in-fs payload", None);
    // Synth CPIO newc: one regular file at "firmware/test/blob.bin"
    // with `blob_bytes` as data, one regular file at "etc/passwd"
    // with arbitrary data, and the TRAILER!!! sentinel.
    let archive = make_cpio_newc(&[
        ("firmware/test/blob.bin", &blob_bytes),
        ("etc/passwd",             b"root:x:0:0::/root:/bin/sh\n"),
    ]);
    // Leak the archive to satisfy the `'static` lifetime
    // `Initramfs::from_cpio` requires; this is a smoke-test
    // allocation only.
    let archive_static: &'static [u8] = alloc::boxed::Box::leak(
        archive.into_boxed_slice());
    let fs = match narf_filesystem::Initramfs::from_cpio(
        "fw-smoke", archive_static)
    {
        Ok(f)  => f,
        Err(_) => return TestResult::Fail("CPIO parse"),
    };
    let (write, _r) = bootstrap_authority();
    let n = match scan_initramfs(&fs, &write) {
        Ok(n)  => n,
        Err(_) => return TestResult::Fail("scan_initramfs"),
    };
    if n != 1 {
        return TestResult::Fail("expected exactly one firmware/* entry registered");
    }
    if source_for("test/blob.bin") != Some(BlobSource::Initramfs) {
        return TestResult::Fail("blob not registered under canonical suffix");
    }
    if source_for("etc/passwd").is_some() {
        return TestResult::Fail("non-firmware entry leaked into registry");
    }
    TestResult::Pass
}
kernel_test_in!("firmware", smoke_firmware_initramfs_scan_registers_under_suffix);

fn smoke_firmware_priority_hot_install_overrides_in_tree() -> TestResult {
    // Spec §5: hot-install entries override initramfs which
    // overrides in-tree. Register an in-tree blob under "name/X",
    // then install() under the same name; source_for must report
    // HotInstall and the cap-resolved bytes must be the new payload.
    if !cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("firmware-allow-unsigned off");
    }
    __reset_for_test();
    let in_tree = build_unsigned_blob(b"OLD: in-tree", None);
    let hot     = build_unsigned_blob(b"NEW: hot install", None);
    if register_in_tree("vendor/multi-tier", &in_tree).is_err() {
        return TestResult::Fail("register_in_tree");
    }
    let (write, read) = bootstrap_authority();
    if install("vendor/multi-tier", &hot, &write).is_err() {
        return TestResult::Fail("install");
    }
    if source_for("vendor/multi-tier") != Some(BlobSource::HotInstall) {
        return TestResult::Fail("priority not honored — expected HotInstall");
    }
    let cap = match open("vendor/multi-tier", &read) {
        Ok(c)  => c,
        Err(_) => return TestResult::Fail("open"),
    };
    let v = match view_of(&cap) {
        Ok(v)  => v,
        Err(_) => return TestResult::Fail("view"),
    };
    if !v.bytes.starts_with(b"NEW") {
        return TestResult::Fail("hot-install payload didn't override");
    }
    TestResult::Pass
}
kernel_test_in!("firmware", smoke_firmware_priority_hot_install_overrides_in_tree);

fn smoke_firmware_sys_install_trusted_loader_round_trip() -> TestResult {
    // Exercises the sys_firmware_install kernel-side path:
    //   1. install_trusted_loader_authority() → cap stashed.
    //   2. trusted_loader_authority() → cap visible.
    //   3. sys_install() through that cap → blob lands at HotInstall.
    // The actual trap-handler shim (sys_firmware_install in
    // narf-userspace) is exercised end-to-end only by the smoke
    // harness's user-mode-testbin path; this smoke covers the
    // lower half so a regression in the cap stash / call-through
    // is caught without spinning up a user task.
    if !cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("firmware-allow-unsigned off");
    }
    use crate::{install_trusted_loader_authority, trusted_loader_authority};
    __reset_for_test();
    let (write, _r) = bootstrap_authority();
    install_trusted_loader_authority(write);
    let auth = match trusted_loader_authority() {
        Some(a) => a,
        None    => return TestResult::Fail("trusted_loader_authority not stashed"),
    };
    let blob = build_unsigned_blob(b"sys_install round-trip", None);
    // SAFETY: blob is a kernel-owned heap allocation; ptr+len
    // describe a valid range for the duration of this call.
    let r = unsafe {
        crate::sys_install(
            "test/sys-install/blob",
            blob.as_ptr(),
            blob.len(),
            &auth,
        )
    };
    match r {
        Ok(()) => {}
        Err(_) => return TestResult::Fail("sys_install rejected"),
    }
    if source_for("test/sys-install/blob") != Some(BlobSource::HotInstall) {
        return TestResult::Fail("sys_install didn't land at HotInstall priority");
    }
    TestResult::Pass
}
kernel_test_in!("firmware", smoke_firmware_sys_install_trusted_loader_round_trip);

/// Build a minimal CPIO newc archive — header + path + data — for
/// each `(name, data)` plus the `TRAILER!!!` sentinel. Used by
/// `smoke_firmware_initramfs_scan_*` to exercise the walker
/// without depending on the test runner's real initramfs.
fn make_cpio_newc(files: &[(&str, &[u8])]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::new();
    let push_hex = |out: &mut alloc::vec::Vec<u8>, v: u32| {
        let s = alloc::format!("{:08x}", v);
        out.extend_from_slice(s.as_bytes());
    };
    let pad4 = |out: &mut alloc::vec::Vec<u8>| {
        while out.len() % 4 != 0 { out.push(0); }
    };
    for (name, data) in files.iter().copied() {
        let name_bytes = name.as_bytes();
        let nlen = (name_bytes.len() + 1) as u32; // include NUL
        out.extend_from_slice(b"070701");
        push_hex(&mut out, 0);                 // c_ino
        push_hex(&mut out, 0o100644);          // c_mode (S_IFREG | 0644)
        push_hex(&mut out, 0);                 // c_uid
        push_hex(&mut out, 0);                 // c_gid
        push_hex(&mut out, 1);                 // c_nlink
        push_hex(&mut out, 0);                 // c_mtime
        push_hex(&mut out, data.len() as u32); // c_filesize
        push_hex(&mut out, 0);                 // c_devmajor
        push_hex(&mut out, 0);                 // c_devminor
        push_hex(&mut out, 0);                 // c_rdevmajor
        push_hex(&mut out, 0);                 // c_rdevminor
        push_hex(&mut out, nlen);              // c_namesize (incl NUL)
        push_hex(&mut out, 0);                 // c_check
        out.extend_from_slice(name_bytes);
        out.push(0);
        pad4(&mut out);
        out.extend_from_slice(data);
        pad4(&mut out);
    }
    // Trailer.
    let trailer_name = b"TRAILER!!!";
    let nlen = (trailer_name.len() + 1) as u32;
    out.extend_from_slice(b"070701");
    push_hex(&mut out, 0);
    push_hex(&mut out, 0);
    push_hex(&mut out, 0);
    push_hex(&mut out, 0);
    push_hex(&mut out, 1);
    push_hex(&mut out, 0);
    push_hex(&mut out, 0);
    push_hex(&mut out, 0);
    push_hex(&mut out, 0);
    push_hex(&mut out, 0);
    push_hex(&mut out, 0);
    push_hex(&mut out, nlen);
    push_hex(&mut out, 0);
    out.extend_from_slice(trailer_name);
    out.push(0);
    pad4(&mut out);
    out
}
