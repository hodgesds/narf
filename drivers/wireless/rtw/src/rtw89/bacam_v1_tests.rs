use super::bacam_v1::*;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_rtw89_bacam_v1_encoding() -> TestResult {
    // bmap tiers: 512/256/64 boundaries (Linux uses strict >).
    if bmap_size(0) != 0
        || bmap_size(64) != 0
        || bmap_size(65) != 4
        || bmap_size(256) != 4
        || bmap_size(257) != 8
        || bmap_size(512) != 8
        || bmap_size(513) != 10
    {
        return TestResult::Fail("bacam bmap_size tiers");
    }

    // Worked example, hand-computed from the bitfields:
    // valid=1, macid=0x2A, tid=5, bmap=8, ssn=0xABC,
    // bitmap idx 3 + dynamic 8 = entry 11, band 1, no MLD:
    // w0 = 0xABC82A53, w1 = 0x0B000300.
    let Ok(h2c) = build_h2c(true, 0x2A, 5, 8, 0xABC, 3, 8, false, true) else {
        return TestResult::Fail("bacam build rejects valid input");
    };
    if h2c.w0 != 0xABC8_2A53 || h2c.w1 != 0x0B00_0300 {
        return TestResult::Fail("bacam v1 words");
    }
    // Free path: VALID clear, INIT_REQ still set.
    let Ok(free) = build_h2c(false, 0x2A, 5, 8, 0xABC, 3, 8, false, true) else {
        return TestResult::Fail("bacam free rejects valid input");
    };
    if free.w0 != 0xABC8_2A52 || free.w1 != 0x0B00_0300 {
        return TestResult::Fail("bacam v1 free words");
    }
    // MLD arm sets bit 10; band 0 leaves bit 9 clear.
    let Ok(mld) = build_h2c(true, 0, 0, 0, 0, 0, 8, true, false) else {
        return TestResult::Fail("bacam mld rejects valid input");
    };
    if mld.w1 != (0x08 << 24) | (1 << 10) | (1 << 8) {
        return TestResult::Fail("bacam v1 mld/band words");
    }

    // Fail-closed rejections (Linux would truncate these).
    if build_h2c(true, 0x100, 0, 0, 0, 0, 8, false, false).is_ok()
        || build_h2c(true, 0, 16, 0, 0, 0, 8, false, false).is_ok()
        || build_h2c(true, 0, 0, 16, 0, 0, 8, false, false).is_ok()
        || build_h2c(true, 0, 0, 0, 0x1000, 0, 8, false, false).is_ok()
        || build_h2c(true, 0, 0, 0, 0, 248, 8, false, false).is_ok()
    {
        return TestResult::Fail("bacam v1 accepts out-of-field input");
    }

    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_bacam_v1_encoding);

fn smoke_rtw89_bacam_v1_slots() -> TestResult {
    let Ok(mut map) = BaCam::new(24) else {
        return TestResult::Fail("bacam map rejects 24");
    };
    if BaCam::new(0).is_ok() || BaCam::new(25).is_ok() {
        return TestResult::Fail("bacam map accepts bad size");
    }
    // Lowest-free-first allocation.
    let a0 = match map.acquire(3) {
        Ok(idx) => idx,
        Err(_) => return TestResult::Fail("bacam acquire"),
    };
    let a1 = match map.acquire(7) {
        Ok(idx) => idx,
        Err(_) => return TestResult::Fail("bacam acquire"),
    };
    if a0 != 0 || a1 != 1 || map.tid_at(0) != Some(3) || map.tid_at(1) != Some(7) {
        return TestResult::Fail("bacam lowest-free allocation");
    }
    // Release frees for reuse; double release fails.
    if map.release(0).is_err() {
        return TestResult::Fail("bacam release semantics");
    }
    let a2 = match map.acquire(9) {
        Ok(idx) => idx,
        Err(_) => return TestResult::Fail("bacam reacquire"),
    };
    if a2 != 0 || map.release(0).is_err() || map.release(0).is_ok() || map.release(24).is_ok() {
        return TestResult::Fail("bacam release semantics");
    }
    // Fill the map, then: non-0/5 TID fails, TID 0 evicts the
    // lowest non-0/5 entry (idx 0 holds TID 1 after the fill).
    // Slot 1 holds TID 7, so 23 acquisitions fill the other slots.
    for _ in 0..23 {
        if map.acquire(1).is_err() {
            return TestResult::Fail("bacam fill");
        }
    }
    if map.acquire(2).is_ok() {
        return TestResult::Fail("bacam full map accepts TID 2");
    }
    let a3 = match map.acquire(0) {
        Ok(idx) => idx,
        Err(_) => return TestResult::Fail("bacam evict"),
    };
    if a3 != 0 || map.tid_at(0) != Some(0) {
        return TestResult::Fail("bacam TID 0 eviction");
    }
    // A map full of only TID 0/5 entries cannot evict.
    let Ok(mut map) = BaCam::new(2) else {
        return TestResult::Fail("bacam small map");
    };
    if map.acquire(0).is_err() || map.acquire(5).is_err() {
        return TestResult::Fail("bacam small fill");
    }
    if map.acquire(0).is_ok() || map.acquire(5).is_ok() {
        return TestResult::Fail("bacam evicts when nothing evictable");
    }
    // TID above the 4-bit field is rejected.
    if map.acquire(16).is_ok() {
        return TestResult::Fail("bacam accepts TID 16");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/rtw89", smoke_rtw89_bacam_v1_slots);
