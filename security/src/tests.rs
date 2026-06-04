//! Subsystem smokes for `narf-security`.

use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_redact_kernel_va_redacted() -> TestResult {
    use crate::redact::{kernel_va_cutoff, redact_pointer};
    use core::fmt::Write;
    let kernel_addr = kernel_va_cutoff();
    let r = redact_pointer(kernel_addr);
    if !r.is_kernel() {
        return TestResult::Fail("kernel address not classified as kernel half");
    }
    // Display should be "*" not the hex address.
    let mut buf = heapless_string();
    let _ = write!(buf, "{}", r);
    if buf.as_str() != "*" {
        return TestResult::Fail("kernel pointer not redacted to '*'");
    }
    TestResult::Pass
}
kernel_test_in!("security/redact", smoke_redact_kernel_va_redacted);

fn smoke_redact_user_va_passes_through() -> TestResult {
    use crate::redact::redact_pointer;
    use core::fmt::Write;
    let user_addr: u64 = 0x0000_0000_4000_1000;
    let r = redact_pointer(user_addr);
    if r.is_kernel() {
        return TestResult::Fail("user address misclassified as kernel half");
    }
    let mut buf = heapless_string();
    let _ = write!(buf, "{}", r);
    if buf.as_str() == "*" {
        return TestResult::Fail("user pointer was redacted");
    }
    if !buf.as_str().contains("4000") {
        return TestResult::Fail("user pointer hex didn't print");
    }
    TestResult::Pass
}
kernel_test_in!("security/redact", smoke_redact_user_va_passes_through);

fn smoke_cap_leak_clean_path() -> TestResult {
    use crate::cap_leak::{_reset_for_test, assert_no_cap_leak};
    _reset_for_test();
    // No caps held, no domain transition: clean.
    if assert_no_cap_leak().is_err() {
        return TestResult::Fail("clean path reported a leak");
    }
    TestResult::Pass
}
kernel_test_in!("security/cap_leak", smoke_cap_leak_clean_path);

fn smoke_cap_leak_detects_write_crossing_domain() -> TestResult {
    use crate::cap_leak::{
        _reset_for_test, assert_no_cap_leak, debug_acquire_write, debug_domain_transition,
        CapLeakError,
    };
    _reset_for_test();
    // Acquire a write cap in domain 0.
    debug_acquire_write(0x1234);
    // Cross to domain 7 — the write cap is still held; that's the leak.
    debug_domain_transition(7);
    match assert_no_cap_leak() {
        Err(CapLeakError::WriteCapCrossedDomain { from, to, .. }) => {
            if from != 0 || to != 7 {
                return TestResult::Fail("WriteCapCrossedDomain reported wrong domain ids");
            }
        }
        Err(e) => {
            // Any error type is acceptable here as long as something
            // fired — but we expect WriteCapCrossedDomain specifically.
            // Surface a diagnostic if a different variant fires.
            let _ = e;
            return TestResult::Fail("wrong CapLeakError variant");
        }
        Ok(()) => return TestResult::Fail("cap leak not detected"),
    }
    _reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "security/cap_leak",
    smoke_cap_leak_detects_write_crossing_domain
);

fn smoke_posture_floors_check() -> TestResult {
    use crate::posture::PostureReport;
    use core::sync::atomic::Ordering;
    let report = PostureReport::new();
    if report.floors_live() {
        return TestResult::Fail("empty report claimed floors live");
    }
    // Flip the floors on.
    report.smep.store(true, Ordering::Release);
    report.smap.store(true, Ordering::Release);
    report.w_xor_x.store(true, Ordering::Release);
    report.canary.store(true, Ordering::Release);
    report.kaslr.store(true, Ordering::Release);
    if !report.floors_live() {
        return TestResult::Fail("all floors set but floors_live false");
    }
    TestResult::Pass
}
kernel_test_in!("security/posture", smoke_posture_floors_check);

fn smoke_posture_extras_count() -> TestResult {
    use crate::posture::PostureReport;
    use core::sync::atomic::Ordering;
    let report = PostureReport::new();
    if report.extras_count() != 0 {
        return TestResult::Fail("empty report had nonzero extras");
    }
    report.cet_shstk.store(true, Ordering::Release);
    report.cet_ibt.store(true, Ordering::Release);
    report.pac_addr.store(true, Ordering::Release);
    if report.extras_count() != 3 {
        return TestResult::Fail("extras_count not 3 after flipping 3 bools");
    }
    TestResult::Pass
}
kernel_test_in!("security/posture", smoke_posture_extras_count);

// ── tiny no_std heapless string helper for the smokes ─────────────────

struct HeaplessString {
    buf: [u8; 32],
    len: usize,
}

impl HeaplessString {
    fn as_str(&self) -> &str {
        // SAFETY: write_str only writes UTF-8.
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len]) }
    }
}

impl core::fmt::Write for HeaplessString {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.buf.len() {
            return Err(core::fmt::Error);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

fn heapless_string() -> HeaplessString {
    HeaplessString {
        buf: [0; 32],
        len: 0,
    }
}
