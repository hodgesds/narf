//! Subsystem smokes for `narf-drivers-i2c`.
//!
//! Two concerns:
//! - The `I2cBus` trait + registry behave consistently (insert /
//!   list / find / dedupe, hermetic reset between tests).
//! - The AMD FCH driver's pre-flight checks fire correctly against
//!   a synthetic MMIO backing — `probe_component_type` separates a
//!   real DesignWare core from a bogus mapping, and `enable` writes
//!   the expected register sequence.
//!
//! No live-hardware assertions here — those happen at boot when the
//! `amd-fch-i2c` initcall logs each controller it finds. These
//! smokes just exercise the code paths that don't need a real I2C
//! device wedged into a real FCH.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use async_trait::async_trait;
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::amd_fch::{recognised_hids, AmdFchI2c};
use crate::lpss::{__new_for_test as lpss_new_for_test, recognised_hids as lpss_recognised_hids};
use crate::{registry, I2cBus, I2cError, I2cOp};
use narf_memory::PhysAddr;

// ── Mock I2C bus ─────────────────────────────────────────────────

#[derive(Debug)]
struct MockBus {
    name: alloc::string::String,
}

#[async_trait]
impl I2cBus for MockBus {
    async fn transfer(&self, _addr: u8, _ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
        Ok(())
    }
    fn name(&self) -> &str {
        &self.name
    }
}

// ── Synthetic MMIO backing (AMD FCH + Intel LPSS) ────────────────
//
// 1024 B (256 u32s) of zeroed memory, shared by both the AMD FCH
// and Intel LPSS smoke suites.  The DW core register window is
// < 0x100 (IC_COMP_TYPE at 0xfc = u32 index 63), and the LPSS
// private-register window extends to LPSS_PRIV_REMAP_ADDR+4 =
// 0x248 (584 B).  1024 B comfortably covers both.  We seed
// COMP_TYPE so probe_component_type passes; every "wait for bit
// clear" poll sees an initial 0 and exits immediately.

const DW_COMP_TYPE: u32 = 0x4457_0140;

fn make_synthetic_mmio(seed_comp_type: bool) -> (PhysAddr, u64) {
    // 1024 B aligned to 4 B (Vec<u32> guarantees 4-byte alignment).
    // Leak into a Box so the kernel-test harness can hold the addr
    // for the lifetime of the test without lifetime tracking.
    let buf: Box<[u32; 256]> = Box::new([0u32; 256]);
    let raw = Box::leak(buf);
    if seed_comp_type {
        // IC_COMP_TYPE is at byte offset 0xfc -> u32 index 63.
        raw[63] = DW_COMP_TYPE;
    }
    let phys = raw.as_ptr() as u64;
    (PhysAddr::new(phys), 1024)
}

// ── Smokes ───────────────────────────────────────────────────────

fn smoke_i2c_registry_dedupes_by_name() -> TestResult {
    registry::__reset_for_test();
    let a = Arc::new(MockBus {
        name: "\\_SB.I2CA".to_string(),
    });
    let b = Arc::new(MockBus {
        name: "\\_SB.I2CA".to_string(),
    });
    let r1 = registry::register_unique(a.clone());
    let r2 = registry::register_unique(b.clone());
    if registry::count() != 1 {
        return TestResult::Fail("dedupe didn't collapse identical name");
    }
    if !Arc::ptr_eq(&r1, &r2) {
        return TestResult::Fail("dedupe should return the existing Arc");
    }
    if registry::find("\\_SB.I2CA").is_none() {
        return TestResult::Fail("find missed the registered bus");
    }
    if registry::find("\\_SB.NOPE").is_some() {
        return TestResult::Fail("find returned a bus that wasn't registered");
    }
    registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_i2c_registry_dedupes_by_name);

fn smoke_i2c_registry_lists_multiple_buses() -> TestResult {
    registry::__reset_for_test();
    for name in ["\\_SB.I2CA", "\\_SB.I2CB", "\\_SB.I2CC"] {
        registry::register_unique(Arc::new(MockBus {
            name: name.to_string(),
        }));
    }
    if registry::count() != 3 {
        return TestResult::Fail("expected 3 registered buses");
    }
    let names: alloc::vec::Vec<_> = registry::list()
        .iter()
        .map(|b| b.name().to_string())
        .collect();
    for want in ["\\_SB.I2CA", "\\_SB.I2CB", "\\_SB.I2CC"] {
        if !names.iter().any(|n| n == want) {
            return TestResult::Fail("listed buses missing one we registered");
        }
    }
    registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_i2c_registry_lists_multiple_buses);

fn smoke_amd_fch_recognises_zen2_hid() -> TestResult {
    // The Zen2 laptop bring-up target uses AMDI0019 — guard against
    // someone trimming the list and silently dropping bring-up
    // hardware coverage.
    if !recognised_hids().contains(&"AMDI0019") {
        return TestResult::Fail("AMDI0019 (Zen2 FCH) not in recognised HID list");
    }
    if !recognised_hids().contains(&"AMDI0010") {
        return TestResult::Fail("AMDI0010 (Zen / Zen+) not in recognised HID list");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_recognises_zen2_hid);

fn smoke_amd_fch_probe_rejects_bad_mmio() -> TestResult {
    // No COMP_TYPE seed -> probe must reject with BadHardware. This
    // is the "MMIO mapping points at the wrong device" guard.
    let (phys, len) = make_synthetic_mmio(false);
    let drv = AmdFchI2c::new("smoke-bad".to_string(), phys, len, None);
    match drv.probe_component_type() {
        Err(I2cError::BadHardware) => TestResult::Pass,
        Err(other) => {
            let _ = other;
            TestResult::Fail("probe_component_type should return BadHardware on COMP_TYPE=0")
        }
        Ok(()) => TestResult::Fail("probe_component_type accepted COMP_TYPE=0"),
    }
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_probe_rejects_bad_mmio);

fn smoke_amd_fch_probe_accepts_good_mmio() -> TestResult {
    let (phys, len) = make_synthetic_mmio(true);
    let drv = AmdFchI2c::new("smoke-good".to_string(), phys, len, None);
    match drv.probe_component_type() {
        Ok(()) => TestResult::Pass,
        Err(_) => TestResult::Fail("probe_component_type rejected real DW magic"),
    }
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_probe_accepts_good_mmio);

fn smoke_amd_fch_enable_writes_expected_regs() -> TestResult {
    let (phys, len) = make_synthetic_mmio(true);
    let drv = AmdFchI2c::new("smoke-enable".to_string(), phys, len, None);
    if drv.enable().is_err() {
        return TestResult::Fail("enable() failed unexpectedly");
    }
    // Inspect the synthetic backing by re-reading via raw ptr.
    // SAFETY: we know the buffer is a leaked Box<[u32; 64]>; phys
    // is the address of the first element.
    let base = phys.raw() as *const u32;
    // IC_CON @ offset 0 (u32 index 0) — should have MASTER + SPEED_FAST + SLAVE_DIS + RESTART_EN
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let ic_con = unsafe { core::ptr::read_volatile(base) };
    let want = 1u32 | (0b10 << 1) | (1 << 6) | (1 << 5);
    if ic_con != want {
        return TestResult::Fail("IC_CON not programmed to master/fast/slave-dis/restart-en");
    }
    // IC_ENABLE @ 0x6c (u32 index 27) should be 1 after enable.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let ic_enable = unsafe { core::ptr::read_volatile(base.add(0x6c / 4)) };
    if ic_enable != 1 {
        return TestResult::Fail("IC_ENABLE not 1 after enable()");
    }
    // After disable() it should be 0.
    drv.disable();
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let ic_enable = unsafe { core::ptr::read_volatile(base.add(0x6c / 4)) };
    if ic_enable != 0 {
        return TestResult::Fail("IC_ENABLE not 0 after disable()");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_enable_writes_expected_regs);

fn smoke_amd_fch_transfer_refuses_when_disabled() -> TestResult {
    // A driver instance that hasn't run enable() must reject
    // transfer attempts with BadHardware — defends against client
    // drivers racing the controller's bring-up.
    narf_scheduler::__reset_queues_for_test();
    let (phys, len) = make_synthetic_mmio(true);
    let drv = AmdFchI2c::new("smoke-noenable".to_string(), phys, len, None);
    let bus: Arc<dyn I2cBus> = Arc::new(drv);
    let result = Arc::new(core::sync::atomic::AtomicI32::new(-1));
    let r = result.clone();
    narf_scheduler::spawn(async move {
        let mut buf = [0u8; 4];
        let mut ops = [I2cOp::Read(&mut buf)];
        let outcome = bus.transfer(0x2c, &mut ops).await;
        let code = match outcome {
            Err(I2cError::BadHardware) => 0,
            Err(_) => 1,
            Ok(()) => 2,
        };
        r.store(code, core::sync::atomic::Ordering::SeqCst);
    });
    narf_scheduler::run_until_empty();
    match result.load(core::sync::atomic::Ordering::SeqCst) {
        0 => TestResult::Pass,
        1 => TestResult::Fail("expected BadHardware before enable(), got different error"),
        2 => TestResult::Fail("transfer succeeded against a not-yet-enabled controller"),
        _ => TestResult::Fail("transfer task didn't run"),
    }
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_transfer_refuses_when_disabled);

// ── Intel LPSS smokes ────────────────────────────────────────────
//
// Stage-1: full driver. The smokes assert that
//
//   (1) the bring-up-target Tiger Lake / Alder Lake / Raptor Lake HIDs
//       stay in the recognised list — guarding against a future trim
//       that silently drops the laptop touchpad bus,
//   (2) the IC_COMP_TYPE probe accepts a real DW magic value and
//       rejects garbage, and
//   (3) the LPSS-specific ungate sequence (FUNC + APB + IDMA reset
//       de-assertion) writes the expected values to the private
//       register window.

fn smoke_lpss_i2c_recognises_modern_intel_hids() -> TestResult {
    // Tiger Lake / Alder Lake / Raptor Lake — the modern Intel laptop
    // bring-up target. Guard against the list being trimmed.
    for required in ["INT34B7", "INT34BA", "INT34C5"] {
        if !lpss_recognised_hids().contains(&required) {
            return TestResult::Fail("required Intel LPSS HID missing from list");
        }
    }
    // Older PCI-mode LPSS (Baytrail / Apollo Lake) — kept in for the
    // long tail of Intel-laptop firmware out there.
    for required in ["80860F41", "808622C1"] {
        if !lpss_recognised_hids().contains(&required) {
            return TestResult::Fail("required Intel LPSS-PCI HID missing from list");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_lpss_i2c_recognises_modern_intel_hids);

fn smoke_lpss_i2c_probe_rejects_bad_mmio() -> TestResult {
    // No COMP_TYPE seed -> probe must reject with BadHardware.
    let (phys, len) = make_synthetic_mmio(false);
    let drv = lpss_new_for_test("smoke-lpss-bad".to_string(), phys, len);
    match drv.probe_component_type() {
        Err(I2cError::BadHardware) => TestResult::Pass,
        Err(other) => {
            let _ = other;
            TestResult::Fail("LPSS probe_component_type should return BadHardware on COMP_TYPE=0")
        }
        Ok(()) => TestResult::Fail("LPSS probe_component_type accepted COMP_TYPE=0"),
    }
}
kernel_test_in!("drivers-i2c", smoke_lpss_i2c_probe_rejects_bad_mmio);

fn smoke_lpss_i2c_probe_accepts_good_mmio_and_ungates() -> TestResult {
    let (phys, len) = make_synthetic_mmio(true);
    let drv = lpss_new_for_test("smoke-lpss-good".to_string(), phys, len);
    match drv.probe_component_type() {
        Ok(()) => {
            // Check that the ungate sequence touched the private regs.
            // LPSS_PRIV_RESETS is at 0x204.
            let base = phys.raw() as *const u32;
            // SAFETY: Valid MMIO bounds or trusted driver environment
            let resets = unsafe { core::ptr::read_volatile(base.add(0x204 / 4)) };
            if resets != 0x7 {
                return TestResult::Fail("LPSS ungate didn't set PRIV_RESETS to 0x7");
            }
            TestResult::Pass
        }
        Err(_) => TestResult::Fail("LPSS probe_component_type rejected real DW magic"),
    }
}
kernel_test_in!(
    "drivers-i2c",
    smoke_lpss_i2c_probe_accepts_good_mmio_and_ungates
);

fn smoke_lpss_i2c_enable_writes_expected_regs() -> TestResult {
    let (phys, len) = make_synthetic_mmio(true);
    let drv = lpss_new_for_test("smoke-lpss-enable".to_string(), phys, len);
    if drv.enable().is_err() {
        return TestResult::Fail("LPSS enable() failed unexpectedly");
    }
    let base = phys.raw() as *const u32;
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let ic_con = unsafe { core::ptr::read_volatile(base) };
    let want = 1u32 | (0b10 << 1) | (1 << 6) | (1 << 5);
    if ic_con != want {
        return TestResult::Fail("LPSS IC_CON not programmed correctly");
    }
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let ic_enable = unsafe { core::ptr::read_volatile(base.add(0x6c / 4)) };
    if ic_enable != 1 {
        return TestResult::Fail("LPSS IC_ENABLE not 1 after enable()");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_lpss_i2c_enable_writes_expected_regs);

fn smoke_lpss_i2c_registers_into_shared_registry() -> TestResult {
    // The whole point of Stage-0 is that an LPSS driver instance,
    // once registered, is discoverable through the SAME registry
    // the FCH variant uses — so i2c-hid-bind doesn't need to know
    // which backend lives behind a given controller path.
    registry::__reset_for_test();
    let (phys, len) = make_synthetic_mmio(true);
    let drv = lpss_new_for_test("\\_SB.PC00.I2C2".to_string(), phys, len);
    let bus: Arc<dyn I2cBus> = Arc::new(drv);
    registry::register_unique(bus.clone());
    if registry::count() != 1 {
        return TestResult::Fail("LPSS bus didn't land in shared registry");
    }
    if registry::find("\\_SB.PC00.I2C2").is_none() {
        return TestResult::Fail("LPSS bus not findable by ACPI path");
    }
    registry::__reset_for_test();
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_lpss_i2c_registers_into_shared_registry);

// ── Intel i801 smokes ────────────────────────────────────────────

fn smoke_i801_smbus_rejects_transfer_when_disabled() -> TestResult {
    narf_scheduler::__reset_queues_for_test();
    let (phys, _len) = make_synthetic_mmio(false);
    let mmio = narf_bus::MmioRegion {
        phys,
        len: 32,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    let drv = crate::i801::__new_for_test("smoke-i801-disabled".to_string(), mmio);
    // disable the controller manually
    drv.enabled
        .store(false, core::sync::atomic::Ordering::Release);

    let bus: Arc<dyn I2cBus> = Arc::new(drv);
    let result = Arc::new(core::sync::atomic::AtomicI32::new(-1));
    let r = result.clone();
    narf_scheduler::spawn(async move {
        let mut buf = [0u8; 4];
        let mut ops = [I2cOp::Read(&mut buf)];
        let outcome = bus.transfer(0x2c, &mut ops).await;
        let code = match outcome {
            Err(I2cError::BadHardware) => 0,
            Err(_) => 1,
            Ok(()) => 2,
        };
        r.store(code, core::sync::atomic::Ordering::SeqCst);
    });
    narf_scheduler::run_until_empty();
    match result.load(core::sync::atomic::Ordering::SeqCst) {
        0 => TestResult::Pass,
        1 => TestResult::Fail("expected BadHardware, got different error"),
        2 => TestResult::Fail("transfer succeeded against a not-yet-enabled controller"),
        _ => TestResult::Fail("transfer task didn't run"),
    }
}
kernel_test_in!(
    "drivers-i2c",
    smoke_i801_smbus_rejects_transfer_when_disabled
);
