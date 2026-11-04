//! FBC A fixtures. Expected conversations and CFB arithmetic are
//! hand-derived from the pinned `intel_fbc.c` functions cited in the
//! module header.

use super::*;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Default)]
struct Regs {
    map: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
}
impl Regs {
    fn set(&self, off: u64, v: u32) {
        self.map.borrow_mut().insert(off, v);
    }
    fn get(&self, off: u64) -> u32 {
        *self.map.borrow().get(&off).unwrap_or(&0)
    }
    fn log(&self) -> Vec<(u64, u32)> {
        self.writes.borrow().clone()
    }
    fn clear(&self) {
        self.writes.borrow_mut().clear();
    }
}
impl MmioWindow for Regs {
    fn read32(&self, off: u64) -> u32 {
        self.get(off)
    }
    fn write32(&self, off: u64, v: u32) {
        self.writes.borrow_mut().push((off, v));
        self.set(off, v);
    }
}

/// A 2880x1800 XR24 linear KMS framebuffer, stride 11520.
fn plane() -> Plane {
    Plane {
        kms_owned: true,
        format: Format::Xrgb8888,
        width: 2880,
        height: 1800,
        x: 0,
        y: 0,
        stride_bytes: 11520,
        per_pixel_alpha: false,
        rotated_90: false,
        interlaced: false,
        psr1: false,
        selective_update: false,
    }
}

fn owner() -> Fbc {
    Fbc::new(
        0x60_1000,
        cfb_size(Format::Xrgb8888, 2880, 1800, 11520),
        1,
        override_stride(Format::Xrgb8888, 2880, 11520),
    )
}

fn smoke_fbc_display14_eligibility_and_console_refusal() -> TestResult {
    if check_plane(&plane()) != Ok(()) {
        return TestResult::Fail("a fixed XR24 KMS framebuffer must be eligible");
    }
    let cases: [(Plane, Refusal); 9] = [
        (
            Plane {
                kms_owned: false,
                ..plane()
            },
            Refusal::NotKmsOwned,
        ),
        (
            Plane {
                format: Format::Other,
                ..plane()
            },
            Refusal::Format,
        ),
        (
            Plane {
                psr1: true,
                ..plane()
            },
            Refusal::Psr1,
        ),
        (
            Plane {
                selective_update: true,
                ..plane()
            },
            Refusal::SelectiveUpdate,
        ),
        (
            Plane {
                interlaced: true,
                ..plane()
            },
            Refusal::Interlaced,
        ),
        (
            Plane {
                per_pixel_alpha: true,
                ..plane()
            },
            Refusal::PerPixelAlpha,
        ),
        (
            Plane {
                format: Format::Rgb565,
                rotated_90: true,
                ..plane()
            },
            Refusal::Rotation,
        ),
        (
            Plane {
                width: 5121,
                ..plane()
            },
            Refusal::PlaneSize,
        ),
        (Plane { x: 5400, ..plane() }, Refusal::SurfaceSize),
    ];
    for (p, want) in cases {
        if check_plane(&p) != Err(want) {
            return TestResult::Fail("an ineligible plane must refuse with its reason");
        }
    }
    // The console framebuffer is refused before any register access.
    let regs = Regs::default();
    let mut fbc = owner();
    if fbc.flush(
        &regs,
        &Plane {
            kms_owned: false,
            ..plane()
        },
    ) != Err(Refusal::NotKmsOwned)
        || !regs.log().is_empty()
        || fbc.active()
    {
        return TestResult::Fail("the console framebuffer must never be compressed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_fbc",
    smoke_fbc_display14_eligibility_and_console_refusal
);

fn smoke_fbc_cfb_geometry_and_compression_limit() -> TestResult {
    // 2880 x 4 = 11520: ALIGN(11520, 512) = 11776; the minimum is
    // ALIGN(11520 + 64, 512) = 11776. Override: 11776 * 4 / 64 = 736.
    if cfb_stride(Format::Xrgb8888, 2880, 11520) != 11776
        || cfb_size(Format::Xrgb8888, 2880, 1800, 11520) != 1800 * 11776
        || override_stride(Format::Xrgb8888, 2880, 11520) != 736
    {
        return TestResult::Fail("CFB stride/size/override diverge from intel_fbc.c");
    }
    // 1920 x 4 = 7680 is 512-aligned, but the Wa_16011863758 minimum
    // ALIGN(7744, 512) = 8192 wins; height is capped at 2560.
    if cfb_stride(Format::Xrgb8888, 1920, 7680) != 8192
        || override_stride(Format::Xrgb8888, 1920, 7680) != 512
        || cfb_size(Format::Xrgb8888, 1920, 3000, 7680) != 2560 * 8192
        || min_limit(Format::Rgb565) != 2
        || min_limit(Format::Xrgb8888) != 1
    {
        return TestResult::Fail("minimum stride, height cap or min limit diverge");
    }
    // find_compression_limit: 2x at the minimum limit, then 1:1, 1:2, 1:4.
    let size = 10 << 20;
    let mut asked = Vec::new();
    let got = find_compression_limit(size, 1, |bytes| {
        asked.push(bytes);
        bytes <= 6 << 20
    });
    if got != Some((2, 5 << 20)) || asked != [20 << 20, 10 << 20, 5 << 20] {
        return TestResult::Fail("compression limit search order diverges");
    }
    if find_compression_limit(size, 1, |bytes| bytes < 2 << 20).is_some() {
        return TestResult::Fail("no admitted limit must refuse");
    }
    if !owner().covers(&plane())
        || owner().covers(&Plane {
            height: 4000,
            ..plane()
        })
    {
        return TestResult::Fail("cfb coverage must follow intel_fbc_is_cfb_ok");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_fbc",
    smoke_fbc_cfb_geometry_and_compression_limit
);

fn smoke_fbc_enable_activate_nuke_conversation() -> TestResult {
    let regs = Regs::default();
    regs.set(DPFC_CHICKEN, 1 << 2);
    regs.set(PIPE_CLKGATE_DIS2, 1 << 1);
    let mut fbc = Fbc::new(0x60_1000, 8 << 20, 2, 736);
    fbc.enable(&regs);
    fbc.activate(&regs);
    let expected = alloc::vec![
        (DPFC_CHICKEN, (1 << 2) | DPFC_CHICKEN_FORCE_SLB_INVALIDATION),
        (PIPE_CLKGATE_DIS2, (1 << 1) | DPFC_GATING_DIS),
        (DPFC_CB_BASE, 0x60_1000),
        (FBC_STRIDE, FBC_STRIDE_OVERRIDE | 368),
        (DPFC_CONTROL, DPFC_CTL_EN | (1 << DPFC_CTL_LIMIT_SHIFT)),
        (MSG_FBC_REND_STATE, FBC_REND_NUKE),
    ];
    if regs.log() != expected || !fbc.active() {
        return TestResult::Fail("enable/activate must follow intel_fbc.c for display 14");
    }
    if DPFC_CONTROL != 0x43208
        || DPFC_CB_BASE != 0x43200
        || FBC_STRIDE != 0x43228
        || MSG_FBC_REND_STATE != 0x50380
        || PIPE_CLKGATE_DIS2 != 0x60114
        || DPFC_CHICKEN != 0x43224
    {
        return TestResult::Fail("FBC register facts diverge from the pinned tree");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_fbc",
    smoke_fbc_enable_activate_nuke_conversation
);

fn smoke_fbc_flush_nukes_on_flip_and_dirtyfb() -> TestResult {
    let regs = Regs::default();
    let mut fbc = owner();
    // First latched flip: enable + activate (which nukes).
    if fbc.flush(&regs, &plane()) != Ok(()) || !fbc.active() {
        return TestResult::Fail("an eligible latched flip must activate FBC");
    }
    if regs.log().last() != Some(&(MSG_FBC_REND_STATE, FBC_REND_NUKE)) {
        return TestResult::Fail("activation must end with a nuke");
    }
    // A later flip or DIRTYFB with FBC still active: nuke only.
    regs.clear();
    if fbc.flush(&regs, &plane()) != Ok(()) || regs.log() != [(MSG_FBC_REND_STATE, FBC_REND_NUKE)] {
        return TestResult::Fail("a flush on an active FBC must only nuke");
    }
    // The KMS session that carries the flip invalidated first: flush
    // re-activates without re-running the enable workarounds.
    fbc.invalidate(&regs);
    regs.clear();
    if fbc.flush(&regs, &plane()) != Ok(())
        || regs
            .log()
            .iter()
            .any(|(o, _)| *o == DPFC_CB_BASE || *o == DPFC_CHICKEN)
        || regs.log().last() != Some(&(MSG_FBC_REND_STATE, FBC_REND_NUKE))
    {
        return TestResult::Fail("re-activation after invalidate must nuke, not re-enable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_fbc",
    smoke_fbc_flush_nukes_on_flip_and_dirtyfb
);

fn smoke_fbc_disabled_before_console_reclaim_suspend_and_reset() -> TestResult {
    let regs = Regs::default();
    let mut fbc = owner();
    let _ = fbc.flush(&regs, &plane());
    // Every KMS session, console restore, suspend quiesce and reset
    // recovery begins with invalidate/disable: compression stops before
    // any plane, console or takeover register is touched.
    regs.clear();
    fbc.invalidate(&regs);
    if fbc.active() || regs.get(DPFC_CONTROL) & DPFC_CTL_EN != 0 {
        return TestResult::Fail("invalidate must stop compression");
    }
    fbc.disable(&regs);
    if fbc.enabled() || regs.get(PIPE_CLKGATE_DIS2) & DPFC_GATING_DIS != 0 {
        return TestResult::Fail("disable must undo wa_18038517565");
    }
    // A console reclaim's flush (console scanned out) keeps FBC off.
    regs.clear();
    if fbc.flush(
        &regs,
        &Plane {
            kms_owned: false,
            ..plane()
        },
    ) != Err(Refusal::NotKmsOwned)
        || regs
            .log()
            .iter()
            .any(|&(o, v)| o == DPFC_CONTROL && v & DPFC_CTL_EN != 0)
    {
        return TestResult::Fail("console scanout must never re-enable FBC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_fbc",
    smoke_fbc_disabled_before_console_reclaim_suspend_and_reset
);

fn smoke_fbc_inherited_enable_untouched_and_refused() -> TestResult {
    // Firmware left FBC A enabled. This owner never activated it, so it
    // never clears it; the KMS takeover inventory keeps refusing it.
    let regs = Regs::default();
    regs.set(DPFC_CONTROL, DPFC_CTL_EN);
    let mut fbc = owner();
    fbc.invalidate(&regs);
    fbc.disable(&regs);
    if !regs.log().is_empty() || regs.get(DPFC_CONTROL) & DPFC_CTL_EN == 0 {
        return TestResult::Fail("an inherited FBC enable must not be adopted or cleared");
    }
    if crate::intel_gpu_kms::inherited_fetchers_idle(
        &regs,
        crate::intel_gpu::Generation::MeteorLake,
    )
    .is_ok()
    {
        return TestResult::Fail("an inherited FBC must still refuse KMS takeover");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_fbc",
    smoke_fbc_inherited_enable_untouched_and_refused
);
