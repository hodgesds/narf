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
    use crate::{install, is_staged, staged, __reset_staged, Initramfs};
    __reset_staged();
    if is_staged() {
        return TestResult::Fail("reset didn't clear staged FS");
    }
    let fs = match Initramfs::from_cpio("smoke-stage", SMOKE_INITRAMFS) {
        Ok(f)  => f,
        Err(_) => return TestResult::Fail("CPIO parse rejected smoke archive"),
    };
    let leaked: &'static Initramfs =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
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
        Ok(f)  => f,
        Err(_) => return TestResult::Fail("CPIO parse #2"),
    };
    let leaked2: &'static Initramfs =
        alloc::boxed::Box::leak(alloc::boxed::Box::new(fs2));
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
