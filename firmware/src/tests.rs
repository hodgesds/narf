//! Per-crate smoke tests for `narf-firmware`. Tests register via
//! `narf_kernel_test::kernel_test_in!` so the runner groups output
//! under `firmware`.

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::registry::{__reset_for_test, install_blob};
use crate::{
    bootstrap_authority, install, open, register_in_tree, scan_initramfs, snapshot, source_for,
    view_of, BlobSource, FirmwareError, BLOB_TRAILER_MAGIC,
};

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
    // Layout per `signature::decode`: payload | sig(64) | signer(32) |
    // metadata(mlen) | mlen(4) | magic(4). mlen sits at fixed offset
    // (n-8..n-4) so the decoder can find it without first knowing
    // metadata's length.
    out.extend_from_slice(&md);
    out.extend_from_slice(&mlen.to_le_bytes());
    out.extend_from_slice(&BLOB_TRAILER_MAGIC);
    out
}

fn smoke_firmware_trailer_decode_unsigned_blob() -> TestResult {
    // Round-trips the trailer parser: build a synthetic unsigned
    // blob, decode it, check payload + version + unsigned sentinel.
    use crate::signature;
    let blob = build_unsigned_blob(b"hello, firmware", Some("1.0.0"));
    let trailer = match signature::decode(&blob) {
        Ok(t) => t,
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
        Ok(_) => TestResult::Fail("decode accepted corrupt magic"),
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
        Ok(c) => c,
        Err(_) => return TestResult::Fail("open after install"),
    };
    let view = match view_of(&cap) {
        Ok(v) => v,
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
    if !snap
        .iter()
        .any(|e| e.name == "vendor/in-tree-blob" && e.source == BlobSource::InTree)
    {
        return TestResult::Fail("snapshot missing in-tree entry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware",
    smoke_firmware_register_in_tree_lands_in_in_tree_tier
);

fn smoke_firmware_open_unknown_blob_returns_not_found() -> TestResult {
    __reset_for_test();
    let (_w, read) = bootstrap_authority();
    match open("doesnt/exist", &read) {
        Err(FirmwareError::NotFound) => TestResult::Pass,
        Ok(_) => TestResult::Fail("open succeeded for absent blob"),
        Err(_) => TestResult::Fail("wrong error variant"),
    }
}
kernel_test_in!(
    "firmware",
    smoke_firmware_open_unknown_blob_returns_not_found
);

fn smoke_firmware_unsigned_rejected_when_feature_off() -> TestResult {
    if cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("feature on — unsigned accepted");
    }
    __reset_for_test();
    let blob = build_unsigned_blob(b"x", None);
    let (write, _r) = bootstrap_authority();
    match install("nope/x", &blob, &write) {
        Err(FirmwareError::UnsignedRejected) => TestResult::Pass,
        Ok(_) => TestResult::Fail("registry accepted unsigned blob in production build"),
        Err(_) => TestResult::Fail("wrong error variant"),
    }
}
kernel_test_in!(
    "firmware",
    smoke_firmware_unsigned_rejected_when_feature_off
);

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
        ("etc/passwd", b"root:x:0:0::/root:/bin/sh\n"),
    ]);
    // Leak the archive to satisfy the `'static` lifetime
    // `Initramfs::from_cpio` requires; this is a smoke-test
    // allocation only.
    let archive_static: &'static [u8] = alloc::boxed::Box::leak(archive.into_boxed_slice());
    let fs = match narf_filesystem::Initramfs::from_cpio("fw-smoke", archive_static) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("CPIO parse"),
    };
    let (write, _r) = bootstrap_authority();
    let n = match scan_initramfs(&fs, &write) {
        Ok(n) => n,
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
kernel_test_in!(
    "firmware",
    smoke_firmware_initramfs_scan_registers_under_suffix
);

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
    let hot = build_unsigned_blob(b"NEW: hot install", None);
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
        Ok(c) => c,
        Err(_) => return TestResult::Fail("open"),
    };
    let v = match view_of(&cap) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("view"),
    };
    if !v.bytes.starts_with(b"NEW") {
        return TestResult::Fail("hot-install payload didn't override");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware",
    smoke_firmware_priority_hot_install_overrides_in_tree
);

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
        None => return TestResult::Fail("trusted_loader_authority not stashed"),
    };
    let blob = build_unsigned_blob(b"sys_install round-trip", None);
    // SAFETY: blob is a kernel-owned heap allocation; ptr+len
    // describe a valid range for the duration of this call.
    let r =
        unsafe { crate::sys_install("test/sys-install/blob", blob.as_ptr(), blob.len(), &auth) };
    match r {
        Ok(()) => {}
        Err(_) => return TestResult::Fail("sys_install rejected"),
    }
    if source_for("test/sys-install/blob") != Some(BlobSource::HotInstall) {
        return TestResult::Fail("sys_install didn't land at HotInstall priority");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware",
    smoke_firmware_sys_install_trusted_loader_round_trip
);

fn smoke_firmware_trusted_signer_registry_round_trip() -> TestResult {
    use crate::signature::__reset_trusted_signers;
    use crate::{register_trusted_signer, trusted_signer_count};
    __reset_trusted_signers();
    if trusted_signer_count() != 0 {
        return TestResult::Fail("reset didn't clear trusted-signer list");
    }
    let fp1 = [0xA1u8; 32];
    let pk1 = [0xB2u8; 32];
    register_trusted_signer(fp1, pk1);
    if trusted_signer_count() != 1 {
        return TestResult::Fail("register didn't add entry");
    }
    // Re-registering the same fingerprint should be idempotent.
    register_trusted_signer(fp1, [0xC3u8; 32]);
    if trusted_signer_count() != 1 {
        return TestResult::Fail("re-register grew the list");
    }
    let fp2 = [0xD4u8; 32];
    register_trusted_signer(fp2, [0xE5u8; 32]);
    if trusted_signer_count() != 2 {
        return TestResult::Fail("second-fingerprint register didn't add entry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware",
    smoke_firmware_trusted_signer_registry_round_trip
);

fn smoke_firmware_loader_task_allowlist_round_trip() -> TestResult {
    use crate::{
        __reset_trusted_loader_tasks, add_trusted_firmware_loader_task,
        is_trusted_firmware_loader_task,
    };
    __reset_trusted_loader_tasks();
    if is_trusted_firmware_loader_task(7) {
        return TestResult::Fail("untouched allowlist accepts arbitrary pid");
    }
    add_trusted_firmware_loader_task(7);
    if !is_trusted_firmware_loader_task(7) {
        return TestResult::Fail("after-add lookup missed pid");
    }
    if is_trusted_firmware_loader_task(8) {
        return TestResult::Fail("allowlist accepts an unregistered pid");
    }
    // Idempotent re-add.
    add_trusted_firmware_loader_task(7);
    add_trusted_firmware_loader_task(7);
    let mut hits = 0;
    for pid in 0..16u64 {
        if is_trusted_firmware_loader_task(pid) {
            hits += 1;
        }
    }
    if hits != 1 {
        return TestResult::Fail("re-add grew the list");
    }
    TestResult::Pass
}
kernel_test_in!("firmware", smoke_firmware_loader_task_allowlist_round_trip);

fn smoke_firmware_initramfs_staging_round_trip() -> TestResult {
    // `install_initramfs` / `initramfs_staged` /
    // `__reset_staged_initramfs` are now thin deprecated shims
    // around `narf-initramfs`; the smoke calls the canonical API
    // directly so the eventual shim removal is invisible.
    use narf_initramfs::{
        __reset_staged as __reset_staged_initramfs, install as install_initramfs,
        is_staged as initramfs_staged,
    };
    if !cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("firmware-allow-unsigned off");
    }
    __reset_staged_initramfs();
    if initramfs_staged() {
        return TestResult::Fail("reset didn't clear staged initramfs");
    }
    // Build + leak a synthetic CPIO with a single firmware blob.
    let payload = build_unsigned_blob(b"staged from initramfs", None);
    let archive = make_cpio_newc(&[("firmware/staged/blob.bin", &payload)]);
    let archive_static: &'static [u8] = alloc::boxed::Box::leak(archive.into_boxed_slice());
    let fs = match narf_filesystem::Initramfs::from_cpio("fw-staging-smoke", archive_static) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("CPIO parse"),
    };
    let fs_static: &'static narf_filesystem::Initramfs =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
    install_initramfs(fs_static);
    if !initramfs_staged() {
        return TestResult::Fail("install_initramfs didn't take effect");
    }
    // Idempotent re-install.
    install_initramfs(fs_static);
    TestResult::Pass
}
kernel_test_in!("firmware", smoke_firmware_initramfs_staging_round_trip);

fn smoke_firmware_per_task_authority_grant_and_revoke() -> TestResult {
    use crate::{
        __reset_trusted_loader_tasks, firmware_authority_of, grant_firmware_authority,
        is_trusted_firmware_loader_task, revoke_firmware_authority,
    };
    __reset_trusted_loader_tasks();

    // Pre-grant: no entry, gate rejects.
    if firmware_authority_of(42).is_some() {
        return TestResult::Fail("untouched table holds a cap for arbitrary pid");
    }
    if is_trusted_firmware_loader_task(42) {
        return TestResult::Fail("untouched table accepts arbitrary pid");
    }

    // Grant + lookup.
    let cap1 = grant_firmware_authority(42);
    let cap_lookup = firmware_authority_of(42);
    if cap_lookup.is_none() {
        return TestResult::Fail("after-grant lookup missed pid");
    }
    if !is_trusted_firmware_loader_task(42) {
        return TestResult::Fail("trusted-loader probe missed granted pid");
    }
    // The granted cap must be live.
    if cap1.check_live().is_err() {
        return TestResult::Fail("granted cap not live");
    }

    // Re-grant replaces (idempotent on pid).
    let _cap2 = grant_firmware_authority(42);
    let mut hits = 0;
    for pid in 0..64u64 {
        if firmware_authority_of(pid).is_some() {
            hits += 1;
        }
    }
    if hits != 1 {
        return TestResult::Fail("re-grant grew the table");
    }

    // Revoke: lookup goes back to None.
    if !revoke_firmware_authority(42) {
        return TestResult::Fail("revoke didn't find pid");
    }
    if firmware_authority_of(42).is_some() {
        return TestResult::Fail("revoke didn't clear the entry");
    }
    if is_trusted_firmware_loader_task(42) {
        return TestResult::Fail("trusted-loader probe accepted revoked pid");
    }
    // Re-revoke is harmless and reports "no removal".
    if revoke_firmware_authority(42) {
        return TestResult::Fail("re-revoke claimed to remove a non-entry");
    }
    TestResult::Pass
}
kernel_test_in!(
    "firmware",
    smoke_firmware_per_task_authority_grant_and_revoke
);

// ── Hybrid model smokes (initramfs-only, rootfs-only, both+shadow) ──

fn smoke_firmware_hybrid_rootfs_only() -> TestResult {
    // Register a blob directly into the Rootfs tier (simulating what
    // `scan_rootfs` does after `root-mount-auto`). Verify source_for
    // reports Rootfs and open() returns it.
    if !cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("firmware-allow-unsigned off");
    }
    __reset_for_test();
    let blob = build_unsigned_blob(b"rootfs payload", None);
    // Directly install with BlobSource::Rootfs (same path scan_rootfs uses).
    if install_blob("vendor/rootfs-blob", &blob, BlobSource::Rootfs).is_err() {
        return TestResult::Fail("install Rootfs blob");
    }
    if source_for("vendor/rootfs-blob") != Some(BlobSource::Rootfs) {
        return TestResult::Fail("source_for didn't report Rootfs");
    }
    let (_w, read) = bootstrap_authority();
    let cap = match open("vendor/rootfs-blob", &read) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("open Rootfs blob"),
    };
    let v = match view_of(&cap) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("view Rootfs blob"),
    };
    if !v.bytes.starts_with(b"rootfs payload") {
        return TestResult::Fail("Rootfs payload bytes mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware", smoke_firmware_hybrid_rootfs_only);

fn smoke_firmware_hybrid_initramfs_only() -> TestResult {
    // Verifies the initramfs scanner path still works in isolation
    // (no rootfs entry for the same name — existing test covers this
    // more deeply via make_cpio_newc; this one confirms source==Initramfs
    // survives the Rootfs tier being added to the registry).
    if !cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("firmware-allow-unsigned off");
    }
    __reset_for_test();
    let blob_bytes = build_unsigned_blob(b"initramfs-only payload", None);
    let archive = make_cpio_newc(&[("firmware/init-only/blob.bin", &blob_bytes)]);
    let archive_static: &'static [u8] = alloc::boxed::Box::leak(archive.into_boxed_slice());
    let fs = match narf_filesystem::Initramfs::from_cpio("hybrid-initramfs-only", archive_static) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("CPIO parse"),
    };
    let (write, read) = bootstrap_authority();
    let n = match scan_initramfs(&fs, &write) {
        Ok(n) => n,
        Err(_) => return TestResult::Fail("scan_initramfs"),
    };
    if n != 1 {
        return TestResult::Fail("expected 1 entry from scan_initramfs");
    }
    if source_for("init-only/blob.bin") != Some(BlobSource::Initramfs) {
        return TestResult::Fail("source_for didn't report Initramfs");
    }
    // Rootfs tier must be empty — no shadowing here.
    if source_for("init-only/blob.bin") == Some(BlobSource::Rootfs) {
        return TestResult::Fail("Rootfs tier falsely shadowed Initramfs");
    }
    let cap = match open("init-only/blob.bin", &read) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("open"),
    };
    let v = match view_of(&cap) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("view"),
    };
    if !v.bytes.starts_with(b"initramfs-only payload") {
        return TestResult::Fail("payload mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("firmware", smoke_firmware_hybrid_initramfs_only);

fn smoke_firmware_hybrid_rootfs_shadows_initramfs() -> TestResult {
    // Linux hybrid model: initramfs entry registers first at lower
    // priority; rootfs entry registers second at higher priority and
    // shadows it. `open()` must resolve to the rootfs bytes.
    //
    // Mirrors the Linux convention where /lib/firmware/ takes
    // precedence over the initramfs copy (described in
    // linux/drivers/base/firmware_loader/main.c::fw_get_filesystem_firmware).
    if !cfg!(feature = "firmware-allow-unsigned") {
        return TestResult::Skip("firmware-allow-unsigned off");
    }
    __reset_for_test();
    const BLOB_NAME: &str = "vendor/shared/hw.bin";

    let init_blob = build_unsigned_blob(b"OLD: initramfs copy", None);
    let root_blob = build_unsigned_blob(b"NEW: rootfs copy", None);

    // Step 1: initramfs scan registers at Initramfs priority.
    let cpio_path = alloc::format!("firmware/{}", BLOB_NAME);
    let archive = make_cpio_newc(&[(cpio_path.as_str(), &init_blob)]);
    let archive_static: &'static [u8] = alloc::boxed::Box::leak(archive.into_boxed_slice());
    let fs = match narf_filesystem::Initramfs::from_cpio("hybrid-shadow-initramfs", archive_static)
    {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("CPIO parse"),
    };
    let (write, read) = bootstrap_authority();
    if scan_initramfs(&fs, &write).is_err() {
        return TestResult::Fail("scan_initramfs");
    }
    // Verify initramfs entry visible before rootfs scans.
    if source_for(BLOB_NAME) != Some(BlobSource::Initramfs) {
        return TestResult::Fail("before rootfs scan: source should be Initramfs");
    }

    // Step 2: rootfs scan registers same name at Rootfs priority.
    if install_blob(BLOB_NAME, &root_blob, BlobSource::Rootfs).is_err() {
        return TestResult::Fail("install Rootfs blob");
    }

    // After rootfs registration, source_for must report Rootfs (higher
    // priority wins in lookup).
    if source_for(BLOB_NAME) != Some(BlobSource::Rootfs) {
        return TestResult::Fail("after rootfs scan: source should be Rootfs (shadow)");
    }

    // open() must return rootfs bytes.
    let cap = match open(BLOB_NAME, &read) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("open after rootfs shadow"),
    };
    let v = match view_of(&cap) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("view"),
    };
    if !v.bytes.starts_with(b"NEW") {
        return TestResult::Fail("rootfs blob didn't shadow initramfs blob");
    }
    TestResult::Pass
}
kernel_test_in!("firmware", smoke_firmware_hybrid_rootfs_shadows_initramfs);

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
        while out.len() % 4 != 0 {
            out.push(0);
        }
    };
    for (name, data) in files.iter().copied() {
        let name_bytes = name.as_bytes();
        let nlen = (name_bytes.len() + 1) as u32; // include NUL
        out.extend_from_slice(b"070701");
        push_hex(&mut out, 0); // c_ino
        push_hex(&mut out, 0o100644); // c_mode (S_IFREG | 0644)
        push_hex(&mut out, 0); // c_uid
        push_hex(&mut out, 0); // c_gid
        push_hex(&mut out, 1); // c_nlink
        push_hex(&mut out, 0); // c_mtime
        push_hex(&mut out, data.len() as u32); // c_filesize
        push_hex(&mut out, 0); // c_devmajor
        push_hex(&mut out, 0); // c_devminor
        push_hex(&mut out, 0); // c_rdevmajor
        push_hex(&mut out, 0); // c_rdevminor
        push_hex(&mut out, nlen); // c_namesize (incl NUL)
        push_hex(&mut out, 0); // c_check
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
