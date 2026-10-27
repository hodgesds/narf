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
use crate::dw_model::{BusEvent, DwModel, VirtualTarget, FIFO_DEPTH};
use crate::lpss::{
    __new_for_test as lpss_new_for_test, recognised_hids as lpss_recognised_hids, LpssI2c,
};
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
    let base = phys.kernel_ptr::<u32>();
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
            let base = phys.kernel_ptr::<u32>();
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
    let base = phys.kernel_ptr::<u32>();
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
        virt: phys.raw(),
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

// ── Behavioural DW model fixtures (#1029) ────────────────────────
//
// Everything below drives the PRODUCTION transfer state machines
// of both DW wrappers (AMD FCH + Intel LPSS) against the
// behavioural register model in `crate::dw_model` — FIFO
// fill/drain, IC_STATUS evolution, TX_ABRT raising, and a virtual
// target device on the bus. Before this lane the fixtures stopped
// at probe/enable; these are the first fixtures in the tree where
// an `I2cBus::transfer` over DW silicon semantics completes (or
// fails) end-to-end.

use alloc::vec::Vec;

/// One owned op for `run_dw_transfer` — the borrowed `I2cOp`s are
/// built inside the spawned task so the buffers outlive the call.
enum OpSpec {
    Write(Vec<u8>),
    Read(usize),
}

/// What `run_dw_transfer`'s spawned task hands back through the
/// outcome cell: the transfer result plus the read buffers.
type TransferOutcome = (Result<(), I2cError>, Vec<Vec<u8>>);

/// Run one `transfer()` on the test scheduler (the existing
/// spawn + run_until_empty idiom) and return its result plus the
/// read buffers (one per op, empty for writes).
fn run_dw_transfer(bus: Arc<dyn I2cBus>, addr: u8, specs: Vec<OpSpec>) -> TransferOutcome {
    narf_scheduler::__reset_queues_for_test();
    let cell: Arc<narf_lib::sync::IrqSafeSpinLock<Option<TransferOutcome>>> =
        Arc::new(narf_lib::sync::IrqSafeSpinLock::new(None));
    let cell2 = cell.clone();
    narf_scheduler::spawn(async move {
        let mut read_bufs: Vec<Vec<u8>> = specs
            .iter()
            .map(|s| match s {
                OpSpec::Write(_) => Vec::new(),
                OpSpec::Read(n) => alloc::vec![0u8; *n],
            })
            .collect();
        let result = {
            let mut ops: Vec<I2cOp<'_>> = Vec::with_capacity(specs.len());
            for (spec, buf) in specs.iter().zip(read_bufs.iter_mut()) {
                match spec {
                    OpSpec::Write(data) => ops.push(I2cOp::Write(data.as_slice())),
                    OpSpec::Read(_) => ops.push(I2cOp::Read(buf.as_mut_slice())),
                }
            }
            bus.transfer(addr, &mut ops).await
        };
        *cell2.lock() = Some((result, read_bufs));
    });
    narf_scheduler::run_until_empty();
    let mut guard = cell.lock();
    match guard.take() {
        Some(outcome) => outcome,
        None => (Err(I2cError::Timeout), Vec::new()),
    }
}

/// Build an enabled FCH controller over the model (probe + enable,
/// the production bring-up order).
fn fch_model_bus(model: &DwModel) -> Result<Arc<dyn I2cBus>, &'static str> {
    let drv = AmdFchI2c::with_regs(
        "smoke-dw-fch".to_string(),
        PhysAddr::new(0),
        1024,
        None,
        model.clone(),
    );
    if drv.probe_component_type().is_err() {
        return Err("FCH probe_component_type failed against the DW model");
    }
    if drv.enable().is_err() {
        return Err("FCH enable failed against the DW model");
    }
    Ok(Arc::new(drv))
}

/// Build an enabled LPSS controller over the model. LPSS probe
/// runs the ungate sequence first (its register writes land in the
/// model's stored file, asserted by the caller that cares).
fn lpss_model_bus(model: &DwModel) -> Result<Arc<dyn I2cBus>, &'static str> {
    let drv = LpssI2c::with_regs(
        "smoke-dw-lpss".to_string(),
        PhysAddr::new(0),
        1024,
        None,
        model.clone(),
    );
    if drv.probe_component_type().is_err() {
        return Err("LPSS probe_component_type failed against the DW model");
    }
    if drv.enable().is_err() {
        return Err("LPSS enable failed against the DW model");
    }
    Ok(Arc::new(drv))
}

const DW_ADDR: u8 = 0x2c;

/// Scenario: one write op lands its bytes in the target's
/// registers, inside exactly one START..STOP envelope.
fn scenario_write_end_to_end(bus: Arc<dyn I2cBus>, model: &DwModel) -> Result<(), &'static str> {
    let (result, _) = run_dw_transfer(
        bus,
        DW_ADDR,
        alloc::vec![OpSpec::Write(alloc::vec![0x10, 0xAA, 0xBB, 0xCC])],
    );
    if result.is_err() {
        return Err("write transfer failed against the DW model");
    }
    if model.target_reg(DW_ADDR, 0x10) != 0xAA
        || model.target_reg(DW_ADDR, 0x11) != 0xBB
        || model.target_reg(DW_ADDR, 0x12) != 0xCC
    {
        return Err("written bytes didn't land in the target registers");
    }
    let want = alloc::vec![
        BusEvent::Start { read: false },
        BusEvent::WriteByte(0x10),
        BusEvent::WriteByte(0xAA),
        BusEvent::WriteByte(0xBB),
        BusEvent::WriteByte(0xCC),
        BusEvent::Stop,
    ];
    if model.events(DW_ADDR) != want {
        return Err("bus conversation wasn't one START..STOP write envelope");
    }
    Ok(())
}

/// Scenario: write-the-pointer + read in one transfer — the
/// repeated-START conversation every register device (and the
/// I2C-HID descriptor fetch) depends on.
fn scenario_write_then_read_restart(
    bus: Arc<dyn I2cBus>,
    model: &DwModel,
) -> Result<(), &'static str> {
    let (result, bufs) = run_dw_transfer(
        bus,
        DW_ADDR,
        alloc::vec![OpSpec::Write(alloc::vec![0x20]), OpSpec::Read(4)],
    );
    if result.is_err() {
        return Err("write+read transfer failed against the DW model");
    }
    if bufs[1] != alloc::vec![0xDE, 0xAD, 0xBE, 0xEF] {
        return Err("read bytes don't match the target's registers");
    }
    let want = alloc::vec![
        BusEvent::Start { read: false },
        BusEvent::WriteByte(0x20),
        BusEvent::Restart { read: true },
        BusEvent::ReadByte(0xDE),
        BusEvent::ReadByte(0xAD),
        BusEvent::ReadByte(0xBE),
        BusEvent::ReadByte(0xEF),
        BusEvent::Stop,
    ];
    if model.events(DW_ADDR) != want {
        return Err("write+read didn't use a repeated START inside one envelope");
    }
    Ok(())
}

/// Scenario: a read longer than the RX FIFO depth completes by
/// interleaving command issue and FIFO drain — the transfer shape
/// descriptor/report reads actually take.
fn scenario_read_spans_fifo_depth(
    bus: Arc<dyn I2cBus>,
    model: &DwModel,
) -> Result<(), &'static str> {
    const READ_LEN: usize = 34; // > FIFO_DEPTH (16), not a multiple of it
    let (result, bufs) = run_dw_transfer(
        bus,
        DW_ADDR,
        alloc::vec![OpSpec::Write(alloc::vec![0x00]), OpSpec::Read(READ_LEN)],
    );
    if result.is_err() {
        return Err("FIFO-spanning read failed against the DW model");
    }
    let want: Vec<u8> = (0..READ_LEN as u8).collect();
    if bufs[1] != want {
        return Err("FIFO-spanning read returned wrong bytes");
    }
    if model.max_rx_level() != FIFO_DEPTH {
        return Err("RX FIFO never filled to depth — the drain interleave wasn't exercised");
    }
    if model.rx_pop_count() != READ_LEN {
        return Err("driver didn't pop exactly the bytes it issued reads for");
    }
    Ok(())
}

/// Scenario: transfer to an absent address surfaces
/// `I2cError::Nack`, the driver clears the abort through
/// IC_CLR_TX_ABRT, and the bus stays usable afterwards.
fn scenario_nack_absent_then_recover(
    bus: Arc<dyn I2cBus>,
    model: &DwModel,
) -> Result<(), &'static str> {
    // A target exists on the bus — at 0x30, not at DW_ADDR.
    let (result, _) = run_dw_transfer(
        bus.clone(),
        DW_ADDR,
        alloc::vec![OpSpec::Write(alloc::vec![0x00, 0x01])],
    );
    if result != Err(I2cError::Nack) {
        return Err("absent-address transfer didn't surface I2cError::Nack");
    }
    if model.tx_abrt_latched() {
        return Err("TX_ABRT still latched — the driver's check_abort didn't clear it");
    }
    let (result, _) = run_dw_transfer(
        bus,
        0x30,
        alloc::vec![OpSpec::Write(alloc::vec![0x00, 0x77])],
    );
    if result.is_err() {
        return Err("bus didn't recover for a present target after the NACK");
    }
    if model.target_reg(0x30, 0x00) != 0x77 {
        return Err("recovery transfer's byte didn't land");
    }
    Ok(())
}

/// Scenario: the I2C-HID descriptor conversation, byte-for-byte
/// the ops `I2cHidDriver::read_descriptor` (drivers/input) issues:
/// write the 2-byte descriptor register address 0x0001, repeated
/// START, read the 30-byte descriptor. The field assertions mirror
/// `HidDescriptor::parse`'s checks on the wire bytes it consumes;
/// the parser itself is the input crate's, this fixture's job is
/// proving the DW path delivers those bytes intact.
fn scenario_hid_descriptor(bus: Arc<dyn I2cBus>, model: &DwModel) -> Result<(), &'static str> {
    let (result, bufs) = run_dw_transfer(
        bus,
        DW_ADDR,
        alloc::vec![OpSpec::Write(alloc::vec![0x01, 0x00]), OpSpec::Read(30)],
    );
    if result.is_err() {
        return Err("HID descriptor transfer failed against the DW model");
    }
    let desc = &bufs[1];
    let r16 = |off: usize| u16::from_le_bytes([desc[off], desc[off + 1]]);
    if r16(0) != 30 {
        return Err("HID descriptor length field isn't 30");
    }
    if r16(2) != 0x0100 {
        return Err("HID descriptor bcdVersion isn't 0x0100");
    }
    if r16(4) != 85 || r16(6) != 0x0002 {
        return Err("HID report-descriptor length/register fields corrupted");
    }
    if r16(8) != 0x0003 || r16(10) != 64 {
        return Err("HID input register / max input length fields corrupted");
    }
    if r16(20) != 0x04F3 || r16(22) != 0x31A5 {
        return Err("HID vendor/product fields corrupted");
    }
    let events = model.events(DW_ADDR);
    if events.first() != Some(&BusEvent::Start { read: false })
        || !events.contains(&BusEvent::Restart { read: true })
        || events.iter().filter(|e| **e == BusEvent::Stop).count() != 1
    {
        return Err("HID descriptor fetch didn't run as one repeated-START envelope");
    }
    Ok(())
}

/// Plant the HID descriptor (see `scenario_hid_descriptor`) at
/// register 0x0001 of a 2-byte-addressed target on DW_ADDR.
fn attach_hid_target(model: &DwModel) {
    let mut desc = [0u8; 30];
    let fields: [(usize, u16); 12] = [
        (0, 30),      // wHIDDescLength
        (2, 0x0100),  // bcdVersion
        (4, 85),      // wReportDescLength
        (6, 0x0002),  // wReportDescRegister
        (8, 0x0003),  // wInputRegister
        (10, 64),     // wMaxInputLength
        (12, 0x0004), // wOutputRegister
        (14, 32),     // wMaxOutputLength
        (16, 0x0005), // wCommandRegister
        (18, 0x0006), // wDataRegister
        (20, 0x04F3), // wVendorId
        (22, 0x31A5), // wProductId
    ];
    for (off, val) in fields {
        desc[off..off + 2].copy_from_slice(&val.to_le_bytes());
    }
    desc[24..26].copy_from_slice(&1u16.to_le_bytes()); // wVersionId
    let mut target = VirtualTarget::new(DW_ADDR, 2);
    target.load(0x0001, &desc);
    model.attach(target);
}

fn smoke_amd_fch_dw_write_end_to_end() -> TestResult {
    let model = DwModel::new();
    model.attach(VirtualTarget::new(DW_ADDR, 1));
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    match scenario_write_end_to_end(bus, &model) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_dw_write_end_to_end);

fn smoke_amd_fch_dw_write_then_read_restart() -> TestResult {
    let model = DwModel::new();
    let mut target = VirtualTarget::new(DW_ADDR, 1);
    target.load(0x20, &[0xDE, 0xAD, 0xBE, 0xEF]);
    model.attach(target);
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    match scenario_write_then_read_restart(bus, &model) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_dw_write_then_read_restart);

fn smoke_amd_fch_dw_multi_op_write_write_read() -> TestResult {
    // Three ops, one envelope: same-direction ops are invisible on
    // the wire (the byte stream just continues), the direction
    // change to the read op is a repeated START, and there is
    // exactly one STOP, at the very end.
    let model = DwModel::new();
    let mut target = VirtualTarget::new(DW_ADDR, 1);
    target.load(0x42, &[0x99, 0x88]);
    model.attach(target);
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    let (result, bufs) = run_dw_transfer(
        bus,
        DW_ADDR,
        alloc::vec![
            OpSpec::Write(alloc::vec![0x40, 0x01]),
            OpSpec::Write(alloc::vec![0x02]),
            OpSpec::Read(2),
        ],
    );
    if result.is_err() {
        return TestResult::Fail("multi-op transfer failed against the DW model");
    }
    if bufs[2] != alloc::vec![0x99, 0x88] {
        return TestResult::Fail("multi-op read returned wrong bytes");
    }
    if model.target_reg(DW_ADDR, 0x40) != 0x01 || model.target_reg(DW_ADDR, 0x41) != 0x02 {
        return TestResult::Fail("multi-op write bytes landed in the wrong registers");
    }
    let want = alloc::vec![
        BusEvent::Start { read: false },
        BusEvent::WriteByte(0x40),
        BusEvent::WriteByte(0x01),
        BusEvent::WriteByte(0x02),
        BusEvent::Restart { read: true },
        BusEvent::ReadByte(0x99),
        BusEvent::ReadByte(0x88),
        BusEvent::Stop,
    ];
    if model.events(DW_ADDR) != want {
        return TestResult::Fail("multi-op conversation had the wrong envelope");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_dw_multi_op_write_write_read);

fn smoke_amd_fch_dw_read_spans_fifo_depth() -> TestResult {
    let model = DwModel::new();
    let mut target = VirtualTarget::new(DW_ADDR, 1);
    let pattern: Vec<u8> = (0..64u8).collect();
    target.load(0x00, &pattern);
    model.attach(target);
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    match scenario_read_spans_fifo_depth(bus, &model) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_dw_read_spans_fifo_depth);

fn smoke_amd_fch_dw_write_spans_fifo_depth_slow_wire() -> TestResult {
    // Slow the modelled wire (one command per 4 register reads)
    // so a 40-byte write genuinely fills the 16-deep TX FIFO and
    // the driver's TFNF wait engages, then still completes with
    // every byte in order.
    let model = DwModel::new();
    model.set_pump(4, 1);
    model.attach(VirtualTarget::new(DW_ADDR, 1));
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    let mut bytes = alloc::vec![0x50u8];
    bytes.extend(0..39u8);
    let (result, _) = run_dw_transfer(bus, DW_ADDR, alloc::vec![OpSpec::Write(bytes)]);
    if result.is_err() {
        return TestResult::Fail("slow-wire FIFO-spanning write didn't complete");
    }
    if model.max_tx_level() < 12 {
        return TestResult::Fail("TX FIFO never approached depth — TFNF wait wasn't exercised");
    }
    for i in 0..39u16 {
        if model.target_reg(DW_ADDR, 0x50 + i) != i as u8 {
            return TestResult::Fail("slow-wire write delivered bytes out of order");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers-i2c",
    smoke_amd_fch_dw_write_spans_fifo_depth_slow_wire
);

fn smoke_amd_fch_dw_nack_absent_then_recover() -> TestResult {
    let model = DwModel::new();
    model.attach(VirtualTarget::new(0x30, 1));
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    match scenario_nack_absent_then_recover(bus, &model) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_dw_nack_absent_then_recover);

fn smoke_amd_fch_dw_data_nack_maps_to_nack() -> TestResult {
    // Target ACKs its address and the first data byte, NAKs the
    // second: TX_ABRT_SOURCE bit 3 (ABRT_TXDATA_NOACK) must
    // surface as I2cError::Nack, the NAKed byte must not be
    // stored, and the rest of the write must never be delivered.
    let model = DwModel::new();
    let mut target = VirtualTarget::new(DW_ADDR, 1);
    target.set_nak_data_after(Some(1));
    model.attach(target);
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    let (result, _) = run_dw_transfer(
        bus,
        DW_ADDR,
        alloc::vec![OpSpec::Write(alloc::vec![0x10, 0xA0, 0xA1, 0xA2])],
    );
    if result != Err(I2cError::Nack) {
        return TestResult::Fail("data NAK didn't surface as I2cError::Nack");
    }
    if model.target_reg(DW_ADDR, 0x10) != 0xA0 {
        return TestResult::Fail("the ACKed data byte wasn't stored");
    }
    if model.target_reg(DW_ADDR, 0x11) != 0 {
        return TestResult::Fail("the NAKed byte was stored anyway");
    }
    let events = model.events(DW_ADDR);
    if !events.contains(&BusEvent::DataNak(0xA1)) || events.contains(&BusEvent::WriteByte(0xA2)) {
        return TestResult::Fail("bytes after the NAK were delivered");
    }
    if model.tx_abrt_latched() {
        return TestResult::Fail("TX_ABRT still latched after the data-NAK transfer");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_dw_data_nack_maps_to_nack);

fn smoke_amd_fch_dw_address_nack_maps_to_nack() -> TestResult {
    // Target present at DW_ADDR but NAKing its address phase (a
    // device held in reset / powered down): the model raises
    // ABRT_7B_ADDR_NOACK (bit 0) — the same source as an absent
    // device, but here the target is on the bus and records the
    // AddrNak. The transfer must surface I2cError::Nack, no byte
    // may be delivered, and the driver must clear the abort.
    let model = DwModel::new();
    let mut target = VirtualTarget::new(DW_ADDR, 1);
    target.set_nak_address(true);
    model.attach(target);
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    let (result, _) = run_dw_transfer(
        bus,
        DW_ADDR,
        alloc::vec![OpSpec::Write(alloc::vec![0x10, 0xA0])],
    );
    if result != Err(I2cError::Nack) {
        return TestResult::Fail("address NAK didn't surface as I2cError::Nack");
    }
    if model.events(DW_ADDR) != alloc::vec![BusEvent::AddrNak] {
        return TestResult::Fail("address-NAKed target saw more than the AddrNak");
    }
    if model.target_reg(DW_ADDR, 0x10) != 0 {
        return TestResult::Fail("a byte was stored despite the address NAK");
    }
    if model.tx_abrt_latched() {
        return TestResult::Fail("TX_ABRT still latched after the address-NAK transfer");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_dw_address_nack_maps_to_nack);

fn smoke_amd_fch_dw_abort_reason_mapping() -> TestResult {
    // ABRT_SBYTE_NORSTRT (bit 9) is none of the driver's special
    // cases → I2cError::Abort(source) with the source intact.
    let model = DwModel::new();
    model.attach(VirtualTarget::new(DW_ADDR, 1));
    model.inject_abort(1 << 9);
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    let (result, _) = run_dw_transfer(
        bus,
        DW_ADDR,
        alloc::vec![OpSpec::Write(alloc::vec![0x00, 0x01])],
    );
    if result != Err(I2cError::Abort(1 << 9)) {
        return TestResult::Fail("injected abort didn't surface as I2cError::Abort(source)");
    }
    // Arbitration loss (bit 12) → I2cError::ArbLost.
    let model = DwModel::new();
    model.attach(VirtualTarget::new(DW_ADDR, 1));
    model.inject_abort(1 << 12);
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    let (result, _) = run_dw_transfer(
        bus,
        DW_ADDR,
        alloc::vec![OpSpec::Write(alloc::vec![0x00, 0x01])],
    );
    if result != Err(I2cError::ArbLost) {
        return TestResult::Fail("injected arbitration loss didn't surface as I2cError::ArbLost");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_dw_abort_reason_mapping);

fn smoke_amd_fch_dw_timeout_when_target_stretches() -> TestResult {
    // A target that holds SCL low forever: the write fills the TX
    // FIFO, TFNF never returns, and the driver's poll budget
    // expires as I2cError::Timeout (not a hang, not a NACK).
    let model = DwModel::new();
    model.set_stretch(u32::MAX);
    model.attach(VirtualTarget::new(DW_ADDR, 1));
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    let mut bytes = alloc::vec![0x00u8];
    bytes.extend(0..19u8);
    let (result, _) = run_dw_transfer(bus, DW_ADDR, alloc::vec![OpSpec::Write(bytes)]);
    if result != Err(I2cError::Timeout) {
        return TestResult::Fail("stretched target didn't surface as I2cError::Timeout");
    }
    // Guard against a false pass: the timeout must have come from
    // the TFNF wait on a genuinely full TX FIFO, not from the
    // transfer never having run.
    if model.max_tx_level() != FIFO_DEPTH {
        return TestResult::Fail("TX FIFO never filled — the timeout wasn't the TFNF wait");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers-i2c",
    smoke_amd_fch_dw_timeout_when_target_stretches
);

fn smoke_amd_fch_dw_hid_descriptor_conversation() -> TestResult {
    let model = DwModel::new();
    attach_hid_target(&model);
    let bus = match fch_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    match scenario_hid_descriptor(bus, &model) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_dw_hid_descriptor_conversation);

fn smoke_lpss_dw_write_then_read_restart() -> TestResult {
    let model = DwModel::new();
    let mut target = VirtualTarget::new(DW_ADDR, 1);
    target.load(0x20, &[0xDE, 0xAD, 0xBE, 0xEF]);
    model.attach(target);
    let bus = match lpss_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    // The LPSS ungate sequence ran against the model during probe:
    // PRIV_RESETS (0x204) must hold FUNC|APB|IDMA de-asserted.
    if model.stored_reg(0x204) != 0x7 {
        return TestResult::Fail("LPSS ungate didn't reach the model's private window");
    }
    match scenario_write_then_read_restart(bus, &model) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_lpss_dw_write_then_read_restart);

fn smoke_lpss_dw_read_spans_fifo_depth() -> TestResult {
    let model = DwModel::new();
    let mut target = VirtualTarget::new(DW_ADDR, 1);
    let pattern: Vec<u8> = (0..64u8).collect();
    target.load(0x00, &pattern);
    model.attach(target);
    let bus = match lpss_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    match scenario_read_spans_fifo_depth(bus, &model) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_lpss_dw_read_spans_fifo_depth);

fn smoke_lpss_dw_nack_absent_then_recover() -> TestResult {
    let model = DwModel::new();
    model.attach(VirtualTarget::new(0x30, 1));
    let bus = match lpss_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    match scenario_nack_absent_then_recover(bus, &model) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_lpss_dw_nack_absent_then_recover);

fn smoke_lpss_dw_hid_descriptor_conversation() -> TestResult {
    let model = DwModel::new();
    attach_hid_target(&model);
    let bus = match lpss_model_bus(&model) {
        Ok(b) => b,
        Err(m) => return TestResult::Fail(m),
    };
    match scenario_hid_descriptor(bus, &model) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_lpss_dw_hid_descriptor_conversation);

// ── _CRS bus-speed fixtures (#772) ───────────────────────────────
//
// The pinned counts below are computed from the DW databook
// formulas as Linux implements them (`i2c_dw_scl_hcnt` /
// `i2c_dw_scl_lcnt`, tf = 300 ns, DIV_ROUND_CLOSEST at 1 MHz
// units) — hcnt = round(ic_clk_khz * (tHIGH + 300)) - 3,
// lcnt = round(ic_clk_khz * (tLOW + 300)) - 1, with
// (tHIGH, tLOW) = (4000, 4700) SS / (600, 1300) FS /
// (260, 500) FP — and were derived independently of the code in
// `crate::dw_speed` (hand/spreadsheet arithmetic on the Linux
// formulas), so a formula error on either side fails here.
//
// FCH input clock 133_000 kHz (AMD PPR):
//   SS 569/664, FS 117/212, FP 71/105.
// LPSS Cannon Lake input clock 216_000 kHz (intel-lpss-acpi.c
// cnl_i2c_info): SS 926/1079, FS 191/345, FP 118/172.
// LPSS Sunrise Point input clock 120_000 kHz (spt_i2c_info):
//   SS 513/599, FS 105/191.

use crate::dw_speed::{compose_bus_speed, timings_for, DwSpeedMode};
use crate::lpss::ic_clk_khz_for_hid;

// DW register byte offsets (same map both wrappers use).
const REG_IC_CON: u64 = 0x00;
const REG_IC_SS_SCL_HCNT: u64 = 0x14;
const REG_IC_SS_SCL_LCNT: u64 = 0x18;
const REG_IC_FS_SCL_HCNT: u64 = 0x1c;
const REG_IC_FS_SCL_LCNT: u64 = 0x20;
const REG_IC_ENABLE: u64 = 0x6c;
// IC_CON base: MASTER_MODE | IC_SLAVE_DISABLE | RESTART_EN.
const CON_BASE: u32 = (1 << 0) | (1 << 6) | (1 << 5);
const CON_STD: u32 = CON_BASE | (0b01 << 1);
const CON_FAST: u32 = CON_BASE | (0b10 << 1);
// Pre-#772 fixed defaults both wrappers must keep when no speed
// is declared (or none can be derived).
const LEGACY_SS_HCNT: u32 = 0x01b0;
const LEGACY_SS_LCNT: u32 = 0x01fb;
const LEGACY_FS_HCNT: u32 = 0x002f;
const LEGACY_FS_LCNT: u32 = 0x006a;

fn smoke_dw_speed_compose_slowest_wins() -> TestResult {
    // Masking-defeating case: two devices on one bus declaring
    // different speeds — the slowest declaration must compose
    // the bus, not the first, not the fastest.
    if compose_bus_speed(&[400_000, 100_000]) != Some(100_000) {
        return TestResult::Fail("two-device compose didn't pick the slowest (100k)");
    }
    if compose_bus_speed(&[1_000_000, 400_000, 350_000]) != Some(350_000) {
        return TestResult::Fail("three-device compose didn't pick the slowest (350k)");
    }
    if compose_bus_speed(&[400_000]) != Some(400_000) {
        return TestResult::Fail("single declaration didn't compose to itself");
    }
    // A 0 declaration means "not declared" (ACPI speed field
    // left zero) — it must not drag the bus to 0 Hz.
    if compose_bus_speed(&[0, 400_000]) != Some(400_000) {
        return TestResult::Fail("zero declaration poisoned the composition");
    }
    if compose_bus_speed(&[0, 0]).is_some() || compose_bus_speed(&[]).is_some() {
        return TestResult::Fail("no declarations should compose to None (defaults)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_dw_speed_compose_slowest_wins);

fn smoke_dw_speed_mode_rounding() -> TestResult {
    // Declared speeds round UP to the enclosing standard mode
    // (Linux i2c_dw_acpi_round_bus_speed), capped at Fast+.
    let cases: [(u32, DwSpeedMode); 7] = [
        (1, DwSpeedMode::Standard),
        (100_000, DwSpeedMode::Standard),
        (100_001, DwSpeedMode::Fast),
        (400_000, DwSpeedMode::Fast),
        (400_001, DwSpeedMode::FastPlus),
        (1_000_000, DwSpeedMode::FastPlus),
        // High-speed declarations clamp into Fast+ — these
        // wrappers do not program the DW HS count registers.
        (3_400_000, DwSpeedMode::FastPlus),
    ];
    for (hz, want) in cases {
        if DwSpeedMode::from_declared_hz(hz) != want {
            return TestResult::Fail("mode rounding picked the wrong mode");
        }
    }
    if DwSpeedMode::Standard.ic_con_speed_bits() != (0b01 << 1)
        || DwSpeedMode::Fast.ic_con_speed_bits() != (0b10 << 1)
        || DwSpeedMode::FastPlus.ic_con_speed_bits() != (0b10 << 1)
    {
        return TestResult::Fail("IC_CON speed field bits wrong for a mode");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_dw_speed_mode_rounding);

fn smoke_dw_speed_timings_pinned() -> TestResult {
    // (ic_clk_khz, declared Hz) -> (mode, ss_h, ss_l, fs_h, fs_l).
    let cases: [(u32, u32, DwSpeedMode, u32, u32, u32, u32); 6] = [
        (133_000, 100_000, DwSpeedMode::Standard, 569, 664, 117, 212),
        (133_000, 400_000, DwSpeedMode::Fast, 569, 664, 117, 212),
        (133_000, 1_000_000, DwSpeedMode::FastPlus, 569, 664, 71, 105),
        (216_000, 100_000, DwSpeedMode::Standard, 926, 1079, 191, 345),
        (
            216_000,
            1_000_000,
            DwSpeedMode::FastPlus,
            926,
            1079,
            118,
            172,
        ),
        (120_000, 400_000, DwSpeedMode::Fast, 513, 599, 105, 191),
    ];
    for (ic_clk, hz, mode, ss_h, ss_l, fs_h, fs_l) in cases {
        let t = timings_for(ic_clk, hz);
        if t.mode != mode
            || t.ss_hcnt != ss_h
            || t.ss_lcnt != ss_l
            || t.fs_hcnt != fs_h
            || t.fs_lcnt != fs_l
        {
            return TestResult::Fail("derived timings disagree with the pinned counts");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_dw_speed_timings_pinned);

fn smoke_lpss_ic_clk_table_grounded() -> TestResult {
    // Pinned from Linux intel-lpss-acpi.c (see the function's
    // doc): SPT I2C = 120 MHz, CNL I2C = 216 MHz; HIDs without a
    // cited rate stay ungrounded so no counts are derived.
    if ic_clk_khz_for_hid("INT3446") != Some(120_000)
        || ic_clk_khz_for_hid("INT3447") != Some(120_000)
    {
        return TestResult::Fail("SPT I2C clock not grounded at 120 MHz");
    }
    if ic_clk_khz_for_hid("INT34B7") != Some(216_000) {
        return TestResult::Fail("CNL I2C clock not grounded at 216 MHz");
    }
    for ungrounded in ["INT34C5", "INT34BA", "808622C1", "AMDI0019", ""] {
        if ic_clk_khz_for_hid(ungrounded).is_some() {
            return TestResult::Fail("ungrounded HID acquired a clock rate");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_lpss_ic_clk_table_grounded);

/// Assert the four SCL count registers + IC_CON + IC_ENABLE a
/// speed-aware `enable()` left in the model.
fn assert_dw_timing_regs(
    model: &DwModel,
    ss_h: u32,
    ss_l: u32,
    fs_h: u32,
    fs_l: u32,
    con: u32,
) -> Result<(), &'static str> {
    if model.stored_reg(REG_IC_SS_SCL_HCNT) != ss_h {
        return Err("IC_SS_SCL_HCNT mismatch");
    }
    if model.stored_reg(REG_IC_SS_SCL_LCNT) != ss_l {
        return Err("IC_SS_SCL_LCNT mismatch");
    }
    if model.stored_reg(REG_IC_FS_SCL_HCNT) != fs_h {
        return Err("IC_FS_SCL_HCNT mismatch");
    }
    if model.stored_reg(REG_IC_FS_SCL_LCNT) != fs_l {
        return Err("IC_FS_SCL_LCNT mismatch");
    }
    if model.stored_reg(REG_IC_CON) != con {
        return Err("IC_CON mismatch");
    }
    if model.stored_reg(REG_IC_ENABLE) != 1 {
        return Err("IC_ENABLE not set after enable()");
    }
    Ok(())
}

/// Build a probed + enabled FCH controller over the model with
/// a recorded bus speed (production probe order).
fn fch_model_bus_with_speed(
    model: &DwModel,
    speed: Option<u32>,
) -> Result<AmdFchI2c<DwModel>, &'static str> {
    let mut drv = AmdFchI2c::with_regs(
        "smoke-dw-fch-speed".to_string(),
        PhysAddr::new(0),
        1024,
        None,
        model.clone(),
    );
    drv.set_bus_speed_hz(speed);
    if drv.probe_component_type().is_err() {
        return Err("FCH probe_component_type failed against the DW model");
    }
    if drv.enable().is_err() {
        return Err("FCH enable failed against the DW model");
    }
    Ok(drv)
}

fn smoke_amd_fch_dw_speed_100k_programs_ss_counts() -> TestResult {
    let model = DwModel::new();
    let _drv = match fch_model_bus_with_speed(&model, Some(100_000)) {
        Ok(d) => d,
        Err(m) => return TestResult::Fail(m),
    };
    // 100 kHz declared: SS counts derived at 133 MHz, IC_CON
    // selects Standard; the FS pair still carries the derived
    // Fast counts (Linux derives both pairs).
    match assert_dw_timing_regs(&model, 569, 664, 117, 212, CON_STD) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers-i2c",
    smoke_amd_fch_dw_speed_100k_programs_ss_counts
);

fn smoke_amd_fch_dw_speed_400k_programs_fs_counts() -> TestResult {
    let model = DwModel::new();
    let _drv = match fch_model_bus_with_speed(&model, Some(400_000)) {
        Ok(d) => d,
        Err(m) => return TestResult::Fail(m),
    };
    // Same counts as the 100 kHz case, different IC_CON speed
    // field — together the pair proves the mode follows the
    // declared speed, not just the count derivation.
    match assert_dw_timing_regs(&model, 569, 664, 117, 212, CON_FAST) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers-i2c",
    smoke_amd_fch_dw_speed_400k_programs_fs_counts
);

fn smoke_amd_fch_dw_speed_1m_programs_fp_counts() -> TestResult {
    let model = DwModel::new();
    let _drv = match fch_model_bus_with_speed(&model, Some(1_000_000)) {
        Ok(d) => d,
        Err(m) => return TestResult::Fail(m),
    };
    // Fast-mode Plus: FP counts in the FS registers, IC_CON
    // still FAST (no HS programming).
    match assert_dw_timing_regs(&model, 569, 664, 71, 105, CON_FAST) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_amd_fch_dw_speed_1m_programs_fp_counts);

fn smoke_amd_fch_dw_speed_undeclared_keeps_defaults() -> TestResult {
    let model = DwModel::new();
    let _drv = match fch_model_bus_with_speed(&model, None) {
        Ok(d) => d,
        Err(m) => return TestResult::Fail(m),
    };
    // No _CRS speed on the bus: the pre-#772 fixed constants and
    // FAST selection must survive byte-for-byte.
    match assert_dw_timing_regs(
        &model,
        LEGACY_SS_HCNT,
        LEGACY_SS_LCNT,
        LEGACY_FS_HCNT,
        LEGACY_FS_LCNT,
        CON_FAST,
    ) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers-i2c",
    smoke_amd_fch_dw_speed_undeclared_keeps_defaults
);

fn smoke_amd_fch_dw_speed_100k_transfer_still_works() -> TestResult {
    // End-to-end at a composed 100 kHz: the speed programming
    // must not disturb the transfer state machine.
    let model = DwModel::new();
    model.attach(VirtualTarget::new(DW_ADDR, 1));
    let drv = match fch_model_bus_with_speed(&model, Some(100_000)) {
        Ok(d) => d,
        Err(m) => return TestResult::Fail(m),
    };
    match scenario_write_end_to_end(Arc::new(drv), &model) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers-i2c",
    smoke_amd_fch_dw_speed_100k_transfer_still_works
);

/// Build a probed + enabled LPSS controller over the model with
/// a recorded input clock + bus speed (production probe order).
fn lpss_model_bus_with_speed(
    model: &DwModel,
    ic_clk_khz: Option<u32>,
    speed: Option<u32>,
) -> Result<LpssI2c<DwModel>, &'static str> {
    let mut drv = LpssI2c::with_regs(
        "smoke-dw-lpss-speed".to_string(),
        PhysAddr::new(0),
        1024,
        None,
        model.clone(),
    );
    drv.set_ic_clk_khz(ic_clk_khz);
    drv.set_bus_speed_hz(speed);
    if drv.probe_component_type().is_err() {
        return Err("LPSS probe_component_type failed against the DW model");
    }
    if drv.enable().is_err() {
        return Err("LPSS enable failed against the DW model");
    }
    Ok(drv)
}

fn smoke_lpss_dw_speed_100k_programs_ss_counts() -> TestResult {
    let model = DwModel::new();
    // Tiger Lake-class controller (INT34B7, CNL info): 216 MHz.
    let _drv = match lpss_model_bus_with_speed(&model, Some(216_000), Some(100_000)) {
        Ok(d) => d,
        Err(m) => return TestResult::Fail(m),
    };
    match assert_dw_timing_regs(&model, 926, 1079, 191, 345, CON_STD) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_lpss_dw_speed_100k_programs_ss_counts);

fn smoke_lpss_dw_speed_1m_programs_fp_counts() -> TestResult {
    let model = DwModel::new();
    let _drv = match lpss_model_bus_with_speed(&model, Some(216_000), Some(1_000_000)) {
        Ok(d) => d,
        Err(m) => return TestResult::Fail(m),
    };
    match assert_dw_timing_regs(&model, 926, 1079, 118, 172, CON_FAST) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_lpss_dw_speed_1m_programs_fp_counts);

fn smoke_lpss_dw_speed_spt_clock_400k() -> TestResult {
    let model = DwModel::new();
    // Sunrise Point-class controller (INT3446/47): 120 MHz — a
    // second grounded clock, proving the clock is an input to
    // the derivation, not a baked-in constant.
    let _drv = match lpss_model_bus_with_speed(&model, Some(120_000), Some(400_000)) {
        Ok(d) => d,
        Err(m) => return TestResult::Fail(m),
    };
    match assert_dw_timing_regs(&model, 513, 599, 105, 191, CON_FAST) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_lpss_dw_speed_spt_clock_400k);

fn smoke_lpss_dw_speed_ungrounded_clock_keeps_defaults() -> TestResult {
    let model = DwModel::new();
    // A speed is declared but this HID's input clock is not
    // grounded: counts must NOT be derived from a guessed clock —
    // the fixed defaults stay.
    let _drv = match lpss_model_bus_with_speed(&model, None, Some(100_000)) {
        Ok(d) => d,
        Err(m) => return TestResult::Fail(m),
    };
    match assert_dw_timing_regs(
        &model,
        LEGACY_SS_HCNT,
        LEGACY_SS_LCNT,
        LEGACY_FS_HCNT,
        LEGACY_FS_LCNT,
        CON_FAST,
    ) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!(
    "drivers-i2c",
    smoke_lpss_dw_speed_ungrounded_clock_keeps_defaults
);

fn smoke_lpss_dw_speed_undeclared_keeps_defaults() -> TestResult {
    let model = DwModel::new();
    let _drv = match lpss_model_bus_with_speed(&model, Some(216_000), None) {
        Ok(d) => d,
        Err(m) => return TestResult::Fail(m),
    };
    match assert_dw_timing_regs(
        &model,
        LEGACY_SS_HCNT,
        LEGACY_SS_LCNT,
        LEGACY_FS_HCNT,
        LEGACY_FS_LCNT,
        CON_FAST,
    ) {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}
kernel_test_in!("drivers-i2c", smoke_lpss_dw_speed_undeclared_keeps_defaults);
