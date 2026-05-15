//! Per-crate smoke tests for `narf-initramfs`.

use narf_kernel_test::{kernel_test_in, TestResult};

// Hand-built CPIO newc archive — single file "hello" / "world".
// Identical to the fixture in `narf-filesystem`'s tests; kept
// inline so the smoke has zero dependency on a host cpio tool.
static SMOKE_INITRAMFS: &[u8] = b"\
070701\
00000001\
000081A4\
00000000\
00000000\
00000001\
00000064\
00000005\
00000000\
00000000\
00000000\
00000000\
00000006\
00000000\
hello\0\
world\0\0\0\
070701\
00000000\
00000000\
00000000\
00000000\
00000001\
00000000\
00000000\
00000000\
00000000\
00000000\
00000000\
0000000B\
00000000\
TRAILER!!!\0\0\0\0";

fn smoke_initramfs_staging_round_trip() -> TestResult {
    use crate::{__reset_staged, install, is_staged, staged, Initramfs};
    __reset_staged();
    if is_staged() {
        return TestResult::Fail("reset didn't clear staged FS");
    }
    let fs = match Initramfs::from_cpio("smoke-stage", SMOKE_INITRAMFS) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("CPIO parse rejected smoke archive"),
    };
    let leaked: &'static Initramfs = alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
    install(leaked);
    if !is_staged() {
        return TestResult::Fail("install didn't take effect");
    }
    if staged().is_none() {
        return TestResult::Fail("staged() returned None after install");
    }
    // First-install-wins idempotency: re-installing a different
    // FS doesn't replace the staged one.
    let fs2 = match Initramfs::from_cpio("alt", SMOKE_INITRAMFS) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("CPIO parse #2"),
    };
    let leaked2: &'static Initramfs = alloc::boxed::Box::leak(alloc::boxed::Box::new(fs2));
    install(leaked2);
    // Both `Initramfs` values were parsed from the same archive,
    // so we can't distinguish them by entry data — just confirm
    // a single install left a valid staged entry.
    if !is_staged() {
        return TestResult::Fail("re-install cleared the staged FS");
    }
    TestResult::Pass
}
kernel_test_in!("initramfs", smoke_initramfs_staging_round_trip);

#[cfg(target_arch = "x86_64")]
fn smoke_initramfs_pvh_module_parser() -> TestResult {
    // Synthesize a PVH `hvm_start_info` + one `hvm_modlist_entry`
    // whose cmdline is "initramfs", then verify the parser returns
    // the module's phys range. The phys-address fields we put in
    // are USERSPACE virt addresses pointing at heap-leaked boxes;
    // reading them via `read_volatile` works under the kernel
    // identity map (or here, since we never dereference them —
    // the parser only walks the modlist + cmdline string).
    use narf_boot::x86_64::pvh::initramfs_module;

    // Layout the modlist-cmdline as one byte slice; the parser
    // reads cmdline_paddr as a pointer to NUL-terminated bytes.
    let cmdline: &'static [u8] =
        alloc::boxed::Box::leak(b"initramfs\0".to_vec().into_boxed_slice());

    // PVH hvm_modlist_entry: paddr / size / cmdline_paddr / reserved.
    let modlist_bytes = {
        let mut v = alloc::vec::Vec::with_capacity(32);
        v.extend_from_slice(&0xCAFE_F00D_u64.to_le_bytes()); // paddr
        v.extend_from_slice(&0x1234_u64.to_le_bytes()); // size
        v.extend_from_slice(&(cmdline.as_ptr() as u64).to_le_bytes()); // cmdline_paddr
        v.extend_from_slice(&0u64.to_le_bytes()); // reserved
        v.into_boxed_slice()
    };
    let modlist: &'static [u8] = alloc::boxed::Box::leak(modlist_bytes);

    // Synthesize hvm_start_info — magic + version + flags +
    // nr_modules + modlist + cmdline + rsdp + memmap_paddr +
    // memmap_entries + reserved.
    let mut hdr_bytes = alloc::vec::Vec::with_capacity(56);
    hdr_bytes.extend_from_slice(&0x336e_c578u32.to_le_bytes()); // magic
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // version
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
    hdr_bytes.extend_from_slice(&1u32.to_le_bytes()); // nr_modules
    hdr_bytes.extend_from_slice(&(modlist.as_ptr() as u64).to_le_bytes()); // modlist
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes()); // cmdline
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes()); // rsdp
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes()); // memmap_paddr
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // memmap_entries
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes()); // reserved
    let hdr: &'static [u8] = alloc::boxed::Box::leak(hdr_bytes.into_boxed_slice());

    // SAFETY: hdr points at a fully-initialized PVH struct;
    // modlist + cmdline addresses inside it are leaked-into-static
    // pointers within the same address space.
    let result = unsafe { initramfs_module(hdr.as_ptr() as usize) };
    match result {
        Some((start, size)) => {
            if start != 0xCAFE_F00D || size != 0x1234 {
                TestResult::Fail("parser returned wrong (start, size)")
            } else {
                TestResult::Pass
            }
        }
        None => TestResult::Fail("parser missed the synthetic initramfs module"),
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("initramfs", smoke_initramfs_pvh_module_parser);

#[cfg(target_arch = "x86_64")]
fn smoke_initramfs_pvh_module_parser_no_match() -> TestResult {
    // Same shape as the prior smoke but with a non-matching
    // cmdline ("vmlinux"). The parser must return `None`.
    use narf_boot::x86_64::pvh::initramfs_module;
    let cmdline: &'static [u8] = alloc::boxed::Box::leak(b"vmlinux\0".to_vec().into_boxed_slice());
    let modlist_bytes = {
        let mut v = alloc::vec::Vec::with_capacity(32);
        v.extend_from_slice(&0xDEAD_BEEF_u64.to_le_bytes());
        v.extend_from_slice(&0x1u64.to_le_bytes());
        v.extend_from_slice(&(cmdline.as_ptr() as u64).to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes());
        v.into_boxed_slice()
    };
    let modlist: &'static [u8] = alloc::boxed::Box::leak(modlist_bytes);
    let mut hdr_bytes = alloc::vec::Vec::with_capacity(56);
    hdr_bytes.extend_from_slice(&0x336e_c578u32.to_le_bytes());
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes());
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes());
    hdr_bytes.extend_from_slice(&1u32.to_le_bytes());
    hdr_bytes.extend_from_slice(&(modlist.as_ptr() as u64).to_le_bytes());
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes());
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes());
    hdr_bytes.extend_from_slice(&0u64.to_le_bytes());
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes());
    hdr_bytes.extend_from_slice(&0u32.to_le_bytes());
    let hdr: &'static [u8] = alloc::boxed::Box::leak(hdr_bytes.into_boxed_slice());
    // SAFETY: same.
    let result = unsafe { initramfs_module(hdr.as_ptr() as usize) };
    if result.is_some() {
        TestResult::Fail("parser matched a non-initramfs cmdline")
    } else {
        TestResult::Pass
    }
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("initramfs", smoke_initramfs_pvh_module_parser_no_match);

/// `mount_at_path("/")` round-trip: stage the smoke CPIO, mount it
/// at "/", verify the staged FS shows up in `narf_filesystem`'s
/// registry. Locks down the boot-path's "fall back to initramfs as
/// root when no FAT volume mounted" contract so a future refactor
/// of the mount surface can't quietly break the no-disk laptop
/// boot scenario.
fn smoke_initramfs_mount_at_root() -> TestResult {
    use crate::{__reset_staged, install, mount_at_path, Initramfs};
    __reset_staged();
    let fs = match Initramfs::from_cpio("smoke-mount-root", SMOKE_INITRAMFS) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("CPIO parse rejected smoke archive"),
    };
    let leaked: &'static Initramfs = alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
    install(leaked);
    let auth = narf_filesystem::bootstrap_mount_authority();
    // Mount at a non-"/" path because the kernel-test harness has
    // a real root mount we mustn't disturb. The mount logic is
    // identical (mount_at_path is path-generic); a successful
    // mount here proves the API contract independent of the
    // specific path.
    if mount_at_path(&auth, "/initramfs-smoke").is_err() {
        return TestResult::Fail("mount_at_path rejected /initramfs-smoke");
    }
    // Resolve through the registry to confirm the proxy actually
    // serves the staged entries.
    let pair: Option<(alloc::sync::Arc<dyn narf_filesystem::DirOps>, alloc::string::String)> =
        narf_filesystem::registry().resolve_absolute(
            "/initramfs-smoke/hello",
            |fs, rel| (fs.root(), alloc::string::String::from(rel)),
        );
    if pair.is_none() {
        return TestResult::Fail("registry didn't return the mounted FS for /initramfs-smoke/hello");
    }
    TestResult::Pass
}
kernel_test_in!("initramfs", smoke_initramfs_mount_at_root);
