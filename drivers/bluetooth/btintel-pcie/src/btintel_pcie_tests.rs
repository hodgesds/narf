//! Kernel smokes for the Intel PCIe Bluetooth driver.
//!
//! Moved verbatim from `narf-bluetooth`'s `tests.rs` when the driver became
//! its own dual-build crate; the test group names (`bluetooth/btintel_pcie`)
//! are unchanged so existing `--subsystem` filters keep selecting them.

#![cfg(feature = "kernel-test")]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use narf_bluetooth::transport::LoopbackTransport;
use narf_kernel_test::{kernel_test_in, TestResult};

// ── Intel PCIe Bluetooth ────────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_match_table() -> TestResult {
    use crate::btintel_pcie as bt;
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    bt::register_pci_driver();
    let regs = registered_pci_drivers();
    for did in bt::SUPPORTED_DEVICE_IDS.iter().copied() {
        let found = regs.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: bt::BT_VENDOR, device,
            } if device == did)
        });
        if !found {
            return TestResult::Fail("btintel-pcie match table missing a device id");
        }
    }
    // The MS-03's 00:14.7.
    if !bt::is_supported_device(bt::BT_DEV_SCP_PTL_H484) || bt::BT_DEV_SCP_PTL_H484 != 0xE376 {
        return TestResult::Fail("btintel-pcie does not claim the MS-03's controller");
    }
    // The Wi-Fi half of the same CNVi package is a different function
    // with a different driver; claiming it would break both.
    if bt::is_supported_device(0xE340) {
        return TestResult::Fail("btintel-pcie claimed the CNVi Wi-Fi function");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_pcie_match_table);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_csr_layout() -> TestResult {
    use crate::btintel_pcie as bt;
    if bt::CSR_FUNC_CTRL != 0x024 || bt::CSR_HW_REV != 0x028 || bt::CSR_RF_ID != 0x09C {
        return TestResult::Fail("identity register offsets wrong");
    }
    if bt::CSR_BOOT_STAGE != 0x108 || bt::CSR_HBUS_TARG_WRPTR != 0x460 {
        return TestResult::Fail("boot-stage / doorbell offsets wrong");
    }
    // FUNC_CTRL bit positions. MAC_ACCESS_REQ (21) and
    // MAC_ACCESS_STS (20) are adjacent and easy to transpose; asking
    // on the status bit would wait forever.
    if bt::FUNC_CTRL_MAC_ACCESS_STS != 1 << 20 || bt::FUNC_CTRL_MAC_ACCESS_REQ != 1 << 21 {
        return TestResult::Fail("MAC access request/status bits transposed");
    }
    if bt::FUNC_CTRL_BUS_MASTER_STS != 1 << 28 || bt::FUNC_CTRL_BUS_MASTER_DISCON != 1 << 29 {
        return TestResult::Fail("bus-master bits wrong");
    }
    if bt::FUNC_CTRL_SW_RESET != 1 << 31 {
        return TestResult::Fail("SW_RESET is bit 31");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_pcie_csr_layout);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_cnvx_decode() -> TestResult {
    use crate::btintel_pcie as bt;
    // INTEL_CNVX_TOP_TYPE is bits 11:0, INTEL_CNVX_TOP_STEP is 27:24
    // — not adjacent fields, and not a plain low/high split.
    let cnvi = 0x0300_0A00u32; // Scorpius Peak, step 3
    if bt::cnvx_top_type(cnvi) != bt::CNVI_SCP {
        return TestResult::Fail("CNVi top type decoded wrong");
    }
    if bt::cnvx_top_step(cnvi) != 3 {
        return TestResult::Fail("CNVi step decoded wrong");
    }
    if bt::cnvi_name(bt::CNVI_SCP) != "ScorpiusPeak" {
        return TestResult::Fail("Panther Lake CNVi name wrong");
    }
    if bt::cnvi_name(bt::CNVI_BLAZARI) != "BlazarI" {
        return TestResult::Fail("Lunar Lake CNVi name wrong");
    }
    // Bits between the two fields must not leak into either.
    let noisy = 0x0FF0_FA00u32;
    if bt::cnvx_top_type(noisy) != 0xA00 {
        return TestResult::Fail("top type picked up bits above 11");
    }
    if bt::cnvx_top_step(noisy) != 0xF {
        return TestResult::Fail("step picked up bits outside 27:24");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_pcie_cnvx_decode);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_boot_stage_flags() -> TestResult {
    use crate::btintel_pcie as bt;
    // A clean shared hardware reset leaves BOOT_STAGE at exactly 0,
    // which is how the reset is checked.
    if bt::boot_stage_flags(0) != "none" {
        return TestResult::Fail("zero boot stage should render as none");
    }
    let running = bt::BOOT_STAGE_OPFW | bt::BOOT_STAGE_ALIVE | bt::BOOT_STAGE_MAC_ACCESS_ON;
    let s = bt::boot_stage_flags(running);
    if !s.contains("opfw") || !s.contains("alive") || !s.contains("mac-access") {
        return TestResult::Fail("running boot stage rendered wrong");
    }
    if s.contains("halted") {
        return TestResult::Fail("rendered a flag that was not set");
    }
    if bt::BOOT_STAGE_ALIVE != 1 << 23 || bt::BOOT_STAGE_DEVICE_HALTED != 1 << 14 {
        return TestResult::Fail("boot stage bit positions wrong");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_boot_stage_flags
);

// ── Intel PCIe Bluetooth: DMA rings ──────────────────────────────────

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_ring_layout_is_aligned_and_disjoint() -> TestResult {
    use crate::btintel_pcie::rings::{
        align_dma, RingLayout, CTX_INFO_BYTES, DMA_ALIGN, FRBD_BYTES, INDEX_ARRAY_BYTES, RX_DESCS,
        TFD_BYTES, TX_DESCS, URBD0_BYTES, URBD1_BYTES,
    };
    let l = RingLayout::new();
    // Every sub-region must start on a 128-byte boundary — Linux
    // aligns each piece before adding it to the running total.
    for off in [
        l.tfds, l.urbd0s, l.frbds, l.urbd1s, l.tr_hia, l.tr_tia, l.cr_hia, l.cr_tia, l.ctx_info,
    ] {
        if off % DMA_ALIGN != 0 {
            return TestResult::Fail("a ring sub-region is not 128-byte aligned");
        }
    }
    // Regions must not overlap: each has to start at or after the end
    // of the one before.
    let regions = [
        (l.tfds, TFD_BYTES * TX_DESCS as u64),
        (l.urbd0s, URBD0_BYTES * TX_DESCS as u64),
        (l.frbds, FRBD_BYTES * RX_DESCS as u64),
        (l.urbd1s, URBD1_BYTES * RX_DESCS as u64),
        (l.tr_hia, INDEX_ARRAY_BYTES),
        (l.tr_tia, INDEX_ARRAY_BYTES),
        (l.cr_hia, INDEX_ARRAY_BYTES),
        (l.cr_tia, INDEX_ARRAY_BYTES),
        (l.ctx_info, CTX_INFO_BYTES),
    ];
    let mut prev_end = 0u64;
    for (off, len) in regions {
        if off < prev_end {
            return TestResult::Fail("ring sub-regions overlap");
        }
        prev_end = off + len;
    }
    if l.total < prev_end || l.total % DMA_ALIGN != 0 {
        return TestResult::Fail("total does not cover every region");
    }
    if align_dma(1) != DMA_ALIGN || align_dma(DMA_ALIGN) != DMA_ALIGN {
        return TestResult::Fail("align_dma is wrong");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_ring_layout_is_aligned_and_disjoint
);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_ctx_info_offsets() -> TestResult {
    use crate::btintel_pcie::rings::*;
    // `struct ctx_info` is __packed and 38 dwords. A miscounted
    // offset points the device at the wrong ring, which looks like a
    // dead controller rather than a decode error.
    if CTX_INFO_BYTES != 152 {
        return TestResult::Fail("ctx_info is 38 dwords");
    }
    // The four index-array pointers are consecutive u64s after the
    // 16-byte header.
    if CI_OFF_ADDR_TR_HIA != 16
        || CI_OFF_ADDR_TR_TIA != 24
        || CI_OFF_ADDR_CR_HIA != 32
        || CI_OFF_ADDR_CR_TIA != 40
    {
        return TestResult::Fail("index-array pointer offsets wrong");
    }
    if CI_OFF_NUM_TR_IA != 48 || CI_OFF_NUM_CR_IA != 50 {
        return TestResult::Fail("index-array counts wrong");
    }
    if CI_OFF_ADDR_TFDQ != 56 || CI_OFF_ADDR_URBDQ0 != 64 {
        return TestResult::Fail("TX ring pointer offsets wrong");
    }
    if CI_OFF_ADDR_FRBDQ != 80 || CI_OFF_ADDR_URBDQ1 != 88 {
        return TestResult::Fail("RX ring pointer offsets wrong");
    }
    // Every named offset must fit the block and be aligned for the
    // width it is written at.
    for (off, width) in [
        (CI_OFF_ADDR_TR_HIA, 8u64),
        (CI_OFF_ADDR_CR_TIA, 8),
        (CI_OFF_ADDR_TFDQ, 8),
        (CI_OFF_ADDR_URBDQ1, 8),
        (CI_OFF_NUM_TFDQ, 2),
        (CI_OFF_URBDQ_DB_VEC, 2),
        (CI_OFF_DBG_FLAGS, 4),
    ] {
        if off + width > CTX_INFO_BYTES {
            return TestResult::Fail("a ctx_info field runs past the block");
        }
        if off % width != 0 {
            return TestResult::Fail("a ctx_info field is misaligned for its width");
        }
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_ctx_info_offsets
);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_doorbell_encoding() -> TestResult {
    use crate::btintel_pcie::rings::{doorbell, RX_DB_VEC, TX_DB_VEC};
    // Index in the low half, vector in the high half. The RX vector
    // is 513, which does not fit 8 bits — packing it into the wrong
    // field would ring the TX doorbell instead.
    if doorbell(7, TX_DB_VEC) != 7 {
        return TestResult::Fail("TX doorbell encoding wrong");
    }
    if doorbell(0, RX_DB_VEC) != 513 << 16 {
        return TestResult::Fail("RX doorbell vector not in the high half");
    }
    if doorbell(63, RX_DB_VEC) != (513 << 16) | 63 {
        return TestResult::Fail("doorbell index and vector overlap");
    }
    if RX_DB_VEC <= u8::MAX as u32 {
        return TestResult::Fail("RX_DB_VEC should not fit a byte — check the constant");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_doorbell_encoding
);

// ── Intel PCIe Bluetooth: system suspend/resume (#1576) ─────────────

/// Scripted `BOOT_STAGE` model for the PCIe D3 handshake.
///
/// Built from the power-state semantics themselves, never from the
/// implementation: writing D3_HOT makes the firmware raise
/// `D3_STATE_READY`; writing D0 clears it while the operational
/// image stays resident. `PowerCut` models the one transition the
/// firmware does NOT survive: after the D0 write the controller is
/// back in its ROM bootloader (`OPFW` clear).
#[cfg(target_arch = "x86_64")]
#[derive(Debug)]
struct FakePcieRegs {
    stage: core::sync::atomic::AtomicU32,
    writes: narf_lib::sync::IrqSafeSpinLock<Vec<u32>>,
    rearms: core::sync::atomic::AtomicU32,
    mode: FakePcieMode,
}

/// Which `BOOT_STAGE` script a [`FakePcieRegs`] plays back.
#[cfg(target_arch = "x86_64")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum FakePcieMode {
    /// D3 acks, D0 restores, firmware retained.
    Retained,
    /// The D3-ready bit never sets: the suspend handshake times out.
    NeverReady,
    /// D3 acks, but the D0 write finds the controller back in ROM.
    PowerCut,
}

#[cfg(target_arch = "x86_64")]
impl FakePcieRegs {
    fn new(mode: FakePcieMode) -> Self {
        use crate::btintel_pcie as bt;
        Self {
            stage: core::sync::atomic::AtomicU32::new(bt::BOOT_STAGE_OPFW | bt::BOOT_STAGE_ALIVE),
            writes: narf_lib::sync::IrqSafeSpinLock::new(Vec::new()),
            rearms: core::sync::atomic::AtomicU32::new(0),
            mode,
        }
    }

    fn writes(&self) -> Vec<u32> {
        self.writes.lock().clone()
    }

    fn rearms(&self) -> u32 {
        self.rearms.load(core::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(target_arch = "x86_64")]
impl crate::btintel_pcie::PciePowerRegs for FakePcieRegs {
    fn write_power_state(&self, state: u32) {
        use crate::btintel_pcie as bt;
        use core::sync::atomic::Ordering;
        self.writes.lock().push(state);
        match self.mode {
            FakePcieMode::Retained => {
                if state == bt::POWER_STATE_D3_HOT {
                    self.stage
                        .fetch_or(bt::BOOT_STAGE_D3_STATE_READY, Ordering::SeqCst);
                } else if state == bt::POWER_STATE_D0 {
                    self.stage
                        .fetch_and(!bt::BOOT_STAGE_D3_STATE_READY, Ordering::SeqCst);
                }
            }
            FakePcieMode::NeverReady => {}
            FakePcieMode::PowerCut => {
                if state == bt::POWER_STATE_D3_HOT {
                    self.stage
                        .fetch_or(bt::BOOT_STAGE_D3_STATE_READY, Ordering::SeqCst);
                } else if state == bt::POWER_STATE_D0 {
                    // Power was cut while suspended: back in ROM.
                    self.stage.store(bt::BOOT_STAGE_ROM, Ordering::SeqCst);
                }
            }
        }
    }

    fn boot_stage(&self) -> u32 {
        self.stage.load(core::sync::atomic::Ordering::SeqCst)
    }

    fn rearm_rx(&self) {
        self.rearms
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
}

/// Reset every registry the PCIe PM smokes touch, so each smoke
/// starts from a clean slate regardless of run order.
#[cfg(target_arch = "x86_64")]
fn btintel_pcie_pm_reset() {
    narf_bluetooth::transport::__test_reset();
    narf_bluetooth::controller::__test_reset_controllers();
    narf_bluetooth::pm::__reset_for_test();
    crate::btintel_pcie::__reset_for_test();
}

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_pm_suspend_resume() -> TestResult {
    use crate::btintel_pcie as bt;
    use narf_power::device_pm;

    btintel_pcie_pm_reset();
    // Isolate from the boot's real devices: the fan-out must run
    // only the PCIe ops under test.
    let _pm_registry = device_pm::__test_isolate_registry();

    let transport: Arc<dyn narf_bluetooth::transport::HciTransport> =
        Arc::new(LoopbackTransport::new("btintel-pcie-pm"));
    narf_bluetooth::transport::register(transport.clone());
    let index = narf_bluetooth::controller::register_ready_transport(
        transport.clone(),
        narf_bluetooth::controller::ControllerInfo::default(),
    );
    // The ops resolve the HCI index lazily by transport identity.
    if narf_bluetooth::controller::index_of_transport(&transport) != Some(index) {
        btintel_pcie_pm_reset();
        return TestResult::Fail("index_of_transport did not resolve the registered transport");
    }
    let regs = Arc::new(FakePcieRegs::new(FakePcieMode::Retained));
    device_pm::register_device_pm_ops(
        "btintel-pcie",
        Arc::new(bt::BtIntelPciePm::new(regs.clone(), transport.clone())),
    );

    // Suspend: the fan-out must park the pump and park the
    // controller in D3.
    if !device_pm::suspend_all_devices().ok() {
        btintel_pcie_pm_reset();
        return TestResult::Fail("suspend fan-out reported a failure on the retained path");
    }
    if !narf_bluetooth::pm::is_parked(index) || !narf_bluetooth::pm::parked_for_power(index) {
        btintel_pcie_pm_reset();
        return TestResult::Fail("suspend did not park the controller for power");
    }
    if regs.writes() != vec![bt::POWER_STATE_D3_HOT] || regs.rearms() != 0 {
        btintel_pcie_pm_reset();
        return TestResult::Fail("suspend did not write exactly one D3_HOT");
    }
    // Resume: D0, RX re-armed, pump unparked, firmware retained.
    if !device_pm::resume_all_devices().ok() {
        btintel_pcie_pm_reset();
        return TestResult::Fail("resume fan-out reported a failure on the retained path");
    }
    if narf_bluetooth::pm::is_parked(index) || narf_bluetooth::pm::parked_for_power(index) {
        btintel_pcie_pm_reset();
        return TestResult::Fail("resume did not unpark the controller");
    }
    if regs.writes() != vec![bt::POWER_STATE_D3_HOT, bt::POWER_STATE_D0] {
        btintel_pcie_pm_reset();
        return TestResult::Fail("resume did not write D0 after D3_HOT");
    }
    if regs.rearms() != 1 || bt::firmware_lost() {
        btintel_pcie_pm_reset();
        return TestResult::Fail(
            "resume did not re-arm RX exactly once, or misreported firmware loss",
        );
    }
    btintel_pcie_pm_reset();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_pm_suspend_resume
);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_pm_d3_timeout_aborts_and_rolls_back() -> TestResult {
    use crate::btintel_pcie as bt;
    use narf_power::device_pm;

    btintel_pcie_pm_reset();
    let _pm_registry = device_pm::__test_isolate_registry();

    let transport: Arc<dyn narf_bluetooth::transport::HciTransport> =
        Arc::new(LoopbackTransport::new("btintel-pcie-pm-timeout"));
    narf_bluetooth::transport::register(transport.clone());
    let index = narf_bluetooth::controller::register_ready_transport(
        transport.clone(),
        narf_bluetooth::controller::ControllerInfo::default(),
    );
    let regs = Arc::new(FakePcieRegs::new(FakePcieMode::NeverReady));
    device_pm::register_device_pm_ops(
        "btintel-pcie",
        Arc::new(bt::BtIntelPciePm::new(regs.clone(), transport.clone())),
    );

    // The firmware never acks D3: the suspend fan-out must report
    // the failure (so the orchestrator aborts the cycle) and the
    // pump must stay parked for the rollback resume.
    if device_pm::suspend_all_devices().ok() {
        btintel_pcie_pm_reset();
        return TestResult::Fail("suspend fan-out hid the D3 timeout");
    }
    if !narf_bluetooth::pm::is_parked(index) {
        btintel_pcie_pm_reset();
        return TestResult::Fail("failed suspend left the pump unparked");
    }
    // Rollback resume: D0 is a no-op against a device that never
    // entered D3, and the pump comes back.
    if !device_pm::resume_all_devices().ok() {
        btintel_pcie_pm_reset();
        return TestResult::Fail("rollback resume failed after the D3 timeout");
    }
    if narf_bluetooth::pm::is_parked(index) {
        btintel_pcie_pm_reset();
        return TestResult::Fail("rollback resume did not unpark the controller");
    }
    if regs.writes() != vec![bt::POWER_STATE_D3_HOT, bt::POWER_STATE_D0] {
        btintel_pcie_pm_reset();
        return TestResult::Fail("rollback resume did not write D0 after the failed D3");
    }
    btintel_pcie_pm_reset();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_pm_d3_timeout_aborts_and_rolls_back
);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_pm_resume_detects_firmware_loss() -> TestResult {
    use crate::btintel_pcie as bt;
    use narf_power::device_pm;

    btintel_pcie_pm_reset();
    let _pm_registry = device_pm::__test_isolate_registry();

    let transport: Arc<dyn narf_bluetooth::transport::HciTransport> =
        Arc::new(LoopbackTransport::new("btintel-pcie-pm-powercut"));
    narf_bluetooth::transport::register(transport.clone());
    let index = narf_bluetooth::controller::register_ready_transport(
        transport.clone(),
        narf_bluetooth::controller::ControllerInfo::default(),
    );
    let regs = Arc::new(FakePcieRegs::new(FakePcieMode::PowerCut));
    device_pm::register_device_pm_ops(
        "btintel-pcie",
        Arc::new(bt::BtIntelPciePm::new(regs.clone(), transport.clone())),
    );

    if !device_pm::suspend_all_devices().ok() {
        btintel_pcie_pm_reset();
        return TestResult::Fail("suspend fan-out failed before the power cut");
    }
    // Resume finds the controller back in ROM: report the failure,
    // record the loss, stay parked, do not re-arm RX for a
    // bootloader that cannot serve HCI.
    if device_pm::resume_all_devices().ok() {
        btintel_pcie_pm_reset();
        return TestResult::Fail("resume fan-out hid the firmware loss");
    }
    if !bt::firmware_lost() || !narf_bluetooth::pm::is_parked(index) || regs.rearms() != 0 {
        btintel_pcie_pm_reset();
        return TestResult::Fail("resume did not record the loss and stay parked");
    }
    // A later suspend must not veto the cycle over a controller
    // that has nothing left to quiesce: park-only, no new D3 write.
    if !device_pm::suspend_all_devices().ok() {
        btintel_pcie_pm_reset();
        return TestResult::Fail("suspend after firmware loss aborted the cycle");
    }
    if regs.writes() != vec![bt::POWER_STATE_D3_HOT, bt::POWER_STATE_D0] {
        btintel_pcie_pm_reset();
        return TestResult::Fail("suspend after firmware loss wrote D3 again");
    }
    // And resume keeps reporting the loss until firmware is
    // reloaded — it must not unpark the pump onto a bootloader.
    if device_pm::resume_all_devices().ok() || !narf_bluetooth::pm::is_parked(index) {
        btintel_pcie_pm_reset();
        return TestResult::Fail("resume after firmware loss unparked the controller");
    }
    btintel_pcie_pm_reset();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_pm_resume_detects_firmware_loss
);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_pm_boot_stage_predicates() -> TestResult {
    use crate::btintel_pcie as bt;
    // Bit positions, as in the CSR layout smoke: D3_STATE_READY is
    // bit 24, OPFW is bit 2 — transposing them would park the
    // controller in the wrong state or mistake a bootloader for
    // operational firmware.
    if bt::BOOT_STAGE_D3_STATE_READY != 1 << 24 || bt::BOOT_STAGE_OPFW != 1 << 2 {
        return TestResult::Fail("D3-ready / OPFW bit positions wrong");
    }
    if bt::is_d3_ready(0) || !bt::is_d3_ready(bt::BOOT_STAGE_D3_STATE_READY) {
        return TestResult::Fail("is_d3_ready misreads the ready bit");
    }
    if !bt::is_d3_ready(bt::BOOT_STAGE_OPFW | bt::BOOT_STAGE_D3_STATE_READY) {
        return TestResult::Fail("is_d3_ready misreads a combined stage");
    }
    if bt::is_opfw(0) || bt::is_opfw(bt::BOOT_STAGE_ROM) || bt::is_opfw(bt::BOOT_STAGE_IML) {
        return TestResult::Fail("is_opfw mistakes ROM/IML for operational firmware");
    }
    if !bt::is_opfw(bt::BOOT_STAGE_OPFW)
        || !bt::is_opfw(bt::BOOT_STAGE_OPFW | bt::BOOT_STAGE_D3_STATE_READY)
    {
        return TestResult::Fail("is_opfw misreads the operational bit");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_pm_boot_stage_predicates
);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_index_of_transport() -> TestResult {
    btintel_pcie_pm_reset();

    let transport: Arc<dyn narf_bluetooth::transport::HciTransport> =
        Arc::new(LoopbackTransport::new("btintel-pcie-pm-index"));
    let other: Arc<dyn narf_bluetooth::transport::HciTransport> =
        Arc::new(LoopbackTransport::new("btintel-pcie-pm-other"));
    narf_bluetooth::transport::register(transport.clone());
    // No controller yet: no index to resolve.
    if narf_bluetooth::controller::index_of_transport(&transport).is_some() {
        btintel_pcie_pm_reset();
        return TestResult::Fail("index_of_transport resolved an unregistered transport");
    }
    let index = narf_bluetooth::controller::register_ready_transport(
        transport.clone(),
        narf_bluetooth::controller::ControllerInfo::default(),
    );
    if narf_bluetooth::controller::index_of_transport(&transport) != Some(index) {
        btintel_pcie_pm_reset();
        return TestResult::Fail("index_of_transport did not resolve the registered transport");
    }
    // A different transport — even one with the same name — is not
    // this controller.
    if narf_bluetooth::controller::index_of_transport(&other).is_some() {
        btintel_pcie_pm_reset();
        return TestResult::Fail("index_of_transport confused two transports");
    }
    btintel_pcie_pm_reset();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_index_of_transport
);

// ── Intel PCIe Bluetooth: post-resume firmware reload (#1660) ────────

/// Recording stand-in for the device-side half of a reload.
///
/// Built from the reload semantics themselves, never from the
/// implementation: a reload re-enables BT and re-downloads, and
/// lands either an operational image or a failure. The flags let
/// one smoke walk every failure branch the orchestration must
/// survive: a failed re-enable, a failed download, a non-OP
/// landing — each must leave the loss recorded and the pump parked
/// for the supervisor's next attempt.
#[cfg(target_arch = "x86_64")]
#[derive(Debug)]
struct FakeFwReloader {
    calls: core::sync::atomic::AtomicU32,
    fail_re_enable: core::sync::atomic::AtomicBool,
    fail_download: core::sync::atomic::AtomicBool,
    land_iml: core::sync::atomic::AtomicBool,
}

#[cfg(target_arch = "x86_64")]
impl FakeFwReloader {
    fn new() -> Self {
        use core::sync::atomic::{AtomicBool, AtomicU32};
        Self {
            calls: AtomicU32::new(0),
            fail_re_enable: AtomicBool::new(false),
            fail_download: AtomicBool::new(false),
            land_iml: AtomicBool::new(false),
        }
    }

    fn calls(&self) -> u32 {
        self.calls.load(core::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(target_arch = "x86_64")]
impl crate::btintel_pcie::PcieFwReload for FakeFwReloader {
    fn reload_device(
        &self,
    ) -> Result<crate::btintel_pcie::fw::IntelVersionTlv, crate::btintel_pcie::ReloadDeviceError>
    {
        use crate::btintel_pcie as bt;
        use core::sync::atomic::Ordering;
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail_re_enable.load(Ordering::SeqCst) {
            return Err(bt::ReloadDeviceError::EnableFailed(
                bt::BtPcieError::AliveTimeout,
            ));
        }
        if self.fail_download.load(Ordering::SeqCst) {
            return Err(bt::ReloadDeviceError::DownloadFailed(
                bt::FirmwareLoadError::Fw(bt::fw::FwError::Timeout),
            ));
        }
        Ok(bt::fw::IntelVersionTlv {
            img_type: if self.land_iml.load(Ordering::SeqCst) {
                bt::fw::IMG_IML
            } else {
                bt::fw::IMG_OP
            },
            ..Default::default()
        })
    }
}

/// A controller driven through a scripted power-cut resume, with
/// everything the reload step needs held alive: the isolated PM
/// registry guard, the transport, its HCI index (when bring-up
/// ran), and the scripted regs.
#[cfg(target_arch = "x86_64")]
struct PowerCutFixture {
    _pm_registry: narf_power::device_pm::TestRegistryGuard,
    transport: Arc<dyn narf_bluetooth::transport::HciTransport>,
    index: Option<usize>,
    regs: Arc<FakePcieRegs>,
}

/// Drive a scripted power-cut resume: suspend parks the pump and
/// writes D3, resume finds the controller back in ROM, records the
/// loss, and stays parked. `register_controller` selects whether
/// the HCI bring-up ran — without it there is no index for the
/// reload step to unpark through.
#[cfg(target_arch = "x86_64")]
fn drive_power_cut(register_controller: bool) -> Result<PowerCutFixture, &'static str> {
    use crate::btintel_pcie as bt;
    use narf_power::device_pm;

    btintel_pcie_pm_reset();
    let _pm_registry = device_pm::__test_isolate_registry();

    let transport: Arc<dyn narf_bluetooth::transport::HciTransport> =
        Arc::new(LoopbackTransport::new("btintel-pcie-pm-reload"));
    narf_bluetooth::transport::register(transport.clone());
    let index = if register_controller {
        Some(narf_bluetooth::controller::register_ready_transport(
            transport.clone(),
            narf_bluetooth::controller::ControllerInfo::default(),
        ))
    } else {
        None
    };
    let regs = Arc::new(FakePcieRegs::new(FakePcieMode::PowerCut));
    device_pm::register_device_pm_ops(
        "btintel-pcie",
        Arc::new(bt::BtIntelPciePm::new(regs.clone(), transport.clone())),
    );

    if !device_pm::suspend_all_devices().ok() {
        return Err("suspend fan-out failed before the power cut");
    }
    if device_pm::resume_all_devices().ok() {
        return Err("resume fan-out hid the firmware loss");
    }
    if !bt::firmware_lost() {
        return Err("resume did not record the firmware loss");
    }
    if let Some(i) = index {
        if !narf_bluetooth::pm::is_parked(i) {
            return Err("resume did not stay parked after the power cut");
        }
    }
    Ok(PowerCutFixture {
        _pm_registry,
        transport,
        index,
        regs,
    })
}

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_pm_power_cut_reload_restores_hci() -> TestResult {
    use crate::btintel_pcie as bt;

    let fixture = match drive_power_cut(true) {
        Ok(f) => f,
        Err(msg) => {
            btintel_pcie_pm_reset();
            return TestResult::Fail(msg);
        }
    };
    let Some(index) = fixture.index else {
        btintel_pcie_pm_reset();
        return TestResult::Fail("power-cut fixture has no HCI index");
    };
    let reloader = FakeFwReloader::new();
    // The reload step: re-enable + re-download, clear the loss,
    // unpark the pump. The transport survived — same Arc, same HCI
    // index — so no re-registration happens, and the orchestration
    // itself never touches the rings (the re-arm lives in the
    // device-side step the fake stands in for).
    if bt::maybe_reload_firmware_with(&fixture.transport, &reloader) != bt::ReloadOutcome::Reloaded
    {
        btintel_pcie_pm_reset();
        return TestResult::Fail("reload step did not report Reloaded after the power cut");
    }
    if reloader.calls() != 1
        || bt::firmware_lost()
        || narf_bluetooth::pm::is_parked(index)
        || fixture.regs.rearms() != 0
        || fixture.regs.writes() != vec![bt::POWER_STATE_D3_HOT, bt::POWER_STATE_D0]
    {
        btintel_pcie_pm_reset();
        return TestResult::Fail("reload did not run once, clear the loss, and unpark the pump");
    }
    if narf_bluetooth::controller::index_of_transport(&fixture.transport) != Some(index) {
        btintel_pcie_pm_reset();
        return TestResult::Fail("reload changed the HCI index");
    }
    // A second step is a no-op: the loss is cleared, so the
    // supervisor must not download again.
    if bt::maybe_reload_firmware_with(&fixture.transport, &reloader) != bt::ReloadOutcome::NotNeeded
        || reloader.calls() != 1
    {
        btintel_pcie_pm_reset();
        return TestResult::Fail("reload step re-ran after the loss was cleared");
    }
    btintel_pcie_pm_reset();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_pm_power_cut_reload_restores_hci
);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_pm_reload_failure_stays_parked_and_retries() -> TestResult {
    use crate::btintel_pcie as bt;
    use core::sync::atomic::Ordering;

    let fixture = match drive_power_cut(true) {
        Ok(f) => f,
        Err(msg) => {
            btintel_pcie_pm_reset();
            return TestResult::Fail(msg);
        }
    };
    let Some(index) = fixture.index else {
        btintel_pcie_pm_reset();
        return TestResult::Fail("power-cut fixture has no HCI index");
    };
    let reloader = FakeFwReloader::new();

    // A non-operational landing is not a recovery: the loss stays
    // recorded and the pump stays parked.
    reloader.land_iml.store(true, Ordering::SeqCst);
    if bt::maybe_reload_firmware_with(&fixture.transport, &reloader) != bt::ReloadOutcome::Failed
        || !bt::firmware_lost()
        || !narf_bluetooth::pm::is_parked(index)
    {
        btintel_pcie_pm_reset();
        return TestResult::Fail("IML landing cleared the loss or unparked the pump");
    }
    reloader.land_iml.store(false, Ordering::SeqCst);

    // A failed download: same — parked, loss recorded, retryable.
    reloader.fail_download.store(true, Ordering::SeqCst);
    if bt::maybe_reload_firmware_with(&fixture.transport, &reloader) != bt::ReloadOutcome::Failed
        || !bt::firmware_lost()
        || !narf_bluetooth::pm::is_parked(index)
    {
        btintel_pcie_pm_reset();
        return TestResult::Fail("failed download cleared the loss or unparked the pump");
    }
    reloader.fail_download.store(false, Ordering::SeqCst);

    // A failed re-enable: same.
    reloader.fail_re_enable.store(true, Ordering::SeqCst);
    if bt::maybe_reload_firmware_with(&fixture.transport, &reloader) != bt::ReloadOutcome::Failed
        || !bt::firmware_lost()
        || !narf_bluetooth::pm::is_parked(index)
    {
        btintel_pcie_pm_reset();
        return TestResult::Fail("failed re-enable cleared the loss or unparked the pump");
    }
    reloader.fail_re_enable.store(false, Ordering::SeqCst);

    // All three branches retried cleanly: the next attempt reloads
    // and unparks.
    if bt::maybe_reload_firmware_with(&fixture.transport, &reloader) != bt::ReloadOutcome::Reloaded
        || bt::firmware_lost()
        || narf_bluetooth::pm::is_parked(index)
    {
        btintel_pcie_pm_reset();
        return TestResult::Fail("reload did not recover after the failures cleared");
    }
    if reloader.calls() != 4 {
        btintel_pcie_pm_reset();
        return TestResult::Fail("reload step did not run once per attempt");
    }
    btintel_pcie_pm_reset();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_pm_reload_failure_stays_parked_and_retries
);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_pm_reload_not_needed_without_loss() -> TestResult {
    use crate::btintel_pcie as bt;

    btintel_pcie_pm_reset();
    let transport: Arc<dyn narf_bluetooth::transport::HciTransport> =
        Arc::new(LoopbackTransport::new("btintel-pcie-pm-reload-idle"));
    narf_bluetooth::transport::register(transport.clone());
    let index = narf_bluetooth::controller::register_ready_transport(
        transport.clone(),
        narf_bluetooth::controller::ControllerInfo::default(),
    );
    let reloader = FakeFwReloader::new();
    // No suspend, no loss: the step must not touch the device.
    if bt::maybe_reload_firmware_with(&transport, &reloader) != bt::ReloadOutcome::NotNeeded
        || reloader.calls() != 0
    {
        btintel_pcie_pm_reset();
        return TestResult::Fail("reload step ran without a recorded loss");
    }
    if narf_bluetooth::pm::is_parked(index) {
        btintel_pcie_pm_reset();
        return TestResult::Fail("reload step parked a healthy controller");
    }
    btintel_pcie_pm_reset();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_pm_reload_not_needed_without_loss
);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_pm_reload_without_index_stays_lost() -> TestResult {
    use crate::btintel_pcie as bt;

    let fixture = match drive_power_cut(false) {
        Ok(f) => f,
        Err(msg) => {
            btintel_pcie_pm_reset();
            return TestResult::Fail(msg);
        }
    };
    let reloader = FakeFwReloader::new();
    // No HCI index (bring-up never ran): the step must fail before
    // touching the device and leave the loss recorded for the
    // supervisor's next attempt.
    if bt::maybe_reload_firmware_with(&fixture.transport, &reloader) != bt::ReloadOutcome::Failed
        || reloader.calls() != 0
        || !bt::firmware_lost()
    {
        btintel_pcie_pm_reset();
        return TestResult::Fail(
            "reload without an HCI index touched the device or cleared the loss",
        );
    }
    btintel_pcie_pm_reset();
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_pm_reload_without_index_stays_lost
);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_hci_packet_types() -> TestResult {
    use crate::btintel_pcie::rings::{
        HCI_ACL_PKT, HCI_CMD_PKT, HCI_EVT_PKT, HCI_ISO_PKT, HCI_SCO_PKT, HCI_TYPE_LEN,
    };
    // Intel prefixes packets with a 4-byte type word, not the 1-byte
    // BT SIG indicator the UART/USB transports use. Sending a 1-byte
    // prefix shifts every packet by three bytes.
    if HCI_TYPE_LEN != 4 {
        return TestResult::Fail("the Intel PCIe type prefix is 4 bytes");
    }
    if HCI_CMD_PKT != 1 || HCI_ACL_PKT != 2 || HCI_SCO_PKT != 3 {
        return TestResult::Fail("command/ACL/SCO type values wrong");
    }
    if HCI_EVT_PKT != 4 || HCI_ISO_PKT != 5 {
        return TestResult::Fail("event/ISO type values wrong");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_pcie_hci_packet_types
);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_pcie_queue_geometry() -> TestResult {
    use crate::btintel_pcie::rings::{
        BUFFER_SIZE, HCI_TYPE_LEN, NUM_QUEUES, RFH_HDR_BYTES, RXQ_NUM, RX_DESCS, TXQ_NUM, TX_DESCS,
    };
    if TX_DESCS != 32 || RX_DESCS != 64 {
        return TestResult::Fail("descriptor counts wrong");
    }
    if BUFFER_SIZE != 4096 {
        return TestResult::Fail("per-descriptor buffer is 4 KiB");
    }
    // The index arrays are indexed by queue number, so those have to
    // be distinct and inside the array.
    if TXQ_NUM == RXQ_NUM || RXQ_NUM >= NUM_QUEUES {
        return TestResult::Fail("queue numbering is inconsistent");
    }
    // A received packet loses the RFH header and the type word, so
    // the largest HCI payload must still be positive.
    if RFH_HDR_BYTES + HCI_TYPE_LEN >= BUFFER_SIZE {
        return TestResult::Fail("headers consume the whole buffer");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_pcie_queue_geometry);

// ── btintel-pcie firmware download ──────────────────────────────────
//
// The controller these exercise cannot be emulated, so the smokes
// pin the pure decode/plan layer against values captured from the
// real MS-03 part and the real signed blobs Intel ships:
//
//   Found device firmware: intel/ibt-00a0-01a1-iml.sfi
//   Boot Address: 0xb02ff000
//   Firmware Version: 15-18.26
//
// and, from `ibt-00a0-01a1-iml.sfi` itself, a CSS header version of
// 0x00010000 at offset 8, the byte 0x06 at offset 644, and an ECDSA
// CSS header version of 0x00020000 at offset 652.

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_fw_cnvx_pack_swab() -> TestResult {
    use crate::btintel_pcie::fw::cnvx_pack_swab;

    // CNVi top 0xA00 (Scorpius Peak) stepping 0 prints as 00a0, and
    // CNVr top 0xA10 stepping 1 as 01a1 — the byte swap is what turns
    // the packed 0xa000/0xa101 into the filename's leading zeroes.
    if cnvx_pack_swab(0xA00, 0) != 0x00A0 {
        return TestResult::Fail("CNVi 0xA00/0 should pack+swab to 0x00a0");
    }
    if cnvx_pack_swab(0xA10, 1) != 0x01A1 {
        return TestResult::Fail("CNVr 0xA10/1 should pack+swab to 0x01a1");
    }
    // A stepping that occupies the high nibble must not bleed into
    // the type field.
    if cnvx_pack_swab(0x900, 0xF) != 0x0F90 {
        return TestResult::Fail("BlazarI 0x900/15 should pack+swab to 0x0f90");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_fw_cnvx_pack_swab);

/// Build the version TLV stream the MS-03's ROM bootloader returns.
#[cfg(target_arch = "x86_64")]
fn ms03_version_tlvs() -> Vec<u8> {
    use crate::btintel_pcie::fw::*;
    let mut v = Vec::new();
    let mut push = |ty: u8, val: &[u8]| {
        v.push(ty);
        v.push(val.len() as u8);
        v.extend_from_slice(val);
    };
    // CNVi top: type 0xA00, stepping 0.
    push(TLV_CNVI_TOP, &0x0000_0A00u32.to_le_bytes());
    // CNVr top: type 0xA10, stepping 1.
    push(TLV_CNVR_TOP, &0x0100_0A10u32.to_le_bytes());
    // CNVi BT: hw platform 0x37, hw variant 0x1f (ScP).
    push(TLV_CNVI_BT, &0x001F_3700u32.to_le_bytes());
    push(TLV_IMAGE_TYPE, &[IMG_BOOTLOADER]);
    push(TLV_SBE_TYPE, &[SBE_ECDSA]);
    push(TLV_OTP_BDADDR, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    push(TLV_MIN_FW, &[15, 18, 26]);
    // An informational type this driver ignores must still be skipped
    // by its length rather than tripping the walk.
    push(0x24, b"Intel");
    v
}

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_fw_version_tlv_parse() -> TestResult {
    use crate::btintel_pcie::fw::*;

    let ver = match parse_version_tlv(&ms03_version_tlvs()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("MS-03 version TLV stream should parse"),
    };
    if ver.cnvi_top != 0x0000_0A00 || ver.cnvr_top != 0x0100_0A10 {
        return TestResult::Fail("CNVi/CNVr top words decoded wrong");
    }
    if ver.hw_platform() != HW_PLATFORM_INTEL {
        return TestResult::Fail("hw platform should decode to 0x37");
    }
    if ver.hw_variant() != 0x1F {
        return TestResult::Fail("hw variant should decode to 0x1f (Scorpius Peak)");
    }
    if ver.img_type != IMG_BOOTLOADER {
        return TestResult::Fail("img_type should decode to the ROM bootloader");
    }
    if ver.sbe_type != SBE_ECDSA {
        return TestResult::Fail("sbe_type should decode to ECDSA");
    }
    if ver.bdaddr_unconfigured() {
        return TestResult::Fail("a non-zero OTP address is not 'unconfigured'");
    }
    if (
        ver.min_fw_build_nn,
        ver.min_fw_build_cw,
        ver.min_fw_build_yy,
    ) != (15, 18, 26)
    {
        return TestResult::Fail("MIN_FW should decode as 15-18.26");
    }

    // A TLV whose length runs past the end of the stream must be
    // rejected, not read out of bounds into the next record.
    let mut truncated = ms03_version_tlvs();
    truncated.truncate(truncated.len() - 2);
    if parse_version_tlv(&truncated).is_ok() {
        return TestResult::Fail("a truncated TLV stream must be rejected");
    }

    // A record shorter than its type's minimum would otherwise decode
    // by reading the following record's bytes.
    let short = [TLV_CNVI_TOP, 2, 0x00, 0x0A, TLV_IMAGE_TYPE, 1, IMG_OP];
    if parse_version_tlv(&short).is_ok() {
        return TestResult::Fail("a CNVI_TOP shorter than 4 bytes must be rejected");
    }

    // An empty OTP address is how an unconfigured controller reports.
    let blank = [TLV_OTP_BDADDR, 6, 0, 0, 0, 0, 0, 0];
    match parse_version_tlv(&blank) {
        Ok(v) if v.bdaddr_unconfigured() => {}
        _ => return TestResult::Fail("an all-zero OTP address means unconfigured"),
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_fw_version_tlv_parse);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_fw_name_derivation() -> TestResult {
    use crate::btintel_pcie::fw::*;

    let mut ver = match parse_version_tlv(&ms03_version_tlvs()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("version TLV stream should parse"),
    };

    // This is the line the real machine prints:
    //   Found device firmware: intel/ibt-00a0-01a1-iml.sfi
    if fw_name(&ver, "sfi") != "intel/ibt-00a0-01a1-iml.sfi" {
        return TestResult::Fail("ROM bootloader should ask for the -iml image");
    }

    // Once the IML is running the name is driven by the firmware id,
    // and `-iml` must not come back or the part would reload the
    // loader instead of the operational image.
    ver.img_type = IMG_IML;
    ver.fw_id = alloc::string::String::from("0291");
    if fw_name(&ver, "sfi") != "intel/ibt-00a0-01a1-0291.sfi" {
        return TestResult::Fail("IML stage should ask for the fw_id-named image");
    }
    if fw_name(&ver, "ddc") != "intel/ibt-00a0-01a1-0291.ddc" {
        return TestResult::Fail("the DDC file follows the same stem");
    }

    // Without a firmware id, the legacy two-field name is the
    // fallback.
    ver.fw_id = alloc::string::String::new();
    if fw_name(&ver, "sfi") != "intel/ibt-00a0-01a1.sfi" {
        return TestResult::Fail("absent fw_id should fall back to the legacy name");
    }

    // `iml_name` ignores img_type — it is how an already-operational
    // controller names the loader it booted through.
    ver.img_type = IMG_OP;
    if iml_name(&ver, "sfi") != "intel/ibt-00a0-01a1-iml.sfi" {
        return TestResult::Fail("iml_name should not depend on img_type");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_fw_name_derivation);

/// A synthetic `.sfi` shaped like the real one: RSA CSS header, the
/// ECDSA marker and header, then `cmds` worth of payload.
#[cfg(target_arch = "x86_64")]
fn synthetic_sfi(payload: &[u8]) -> Vec<u8> {
    use crate::btintel_pcie::fw::*;
    let mut img = vec![0u8; PAYLOAD_OFFSET];
    img[CSS_HEADER_OFFSET..CSS_HEADER_OFFSET + 4].copy_from_slice(&RSA_HEADER_VER.to_le_bytes());
    img[ECDSA_OFFSET] = ECDSA_PRESENT_MARKER;
    img[ECDSA_OFFSET + CSS_HEADER_OFFSET..ECDSA_OFFSET + CSS_HEADER_OFFSET + 4]
        .copy_from_slice(&ECDSA_HEADER_VER.to_le_bytes());
    img.extend_from_slice(payload);
    img
}

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_fw_header_plan() -> TestResult {
    use crate::btintel_pcie::fw::*;

    let img = synthetic_sfi(&[]);

    // ECDSA: 128-byte CSS header, 96-byte key, 96-byte signature, all
    // taken from the second header at 644.
    let ecdsa = match plan_header_fragments(&img, 0x1F, SBE_ECDSA) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("ECDSA header plan should succeed"),
    };
    let want_ecdsa = [
        (FRAG_INIT, ECDSA_OFFSET, 128),
        (FRAG_PKEY, ECDSA_OFFSET + 128, 96),
        (FRAG_SIGN, ECDSA_OFFSET + 224, 96),
    ];
    if ecdsa.len() != 3 {
        return TestResult::Fail("ECDSA header is three fragments");
    }
    for (got, want) in ecdsa.iter().zip(want_ecdsa.iter()) {
        if (got.kind, got.offset, got.len) != *want {
            return TestResult::Fail("ECDSA header fragment offset/len/kind wrong");
        }
    }
    // Every ECDSA fragment must land inside the 320-byte header.
    for f in &ecdsa {
        if f.offset + f.len > PAYLOAD_OFFSET {
            return TestResult::Fail("ECDSA fragment runs past the header region");
        }
    }

    // RSA: 128-byte CSS header, 256-byte key, 256-byte signature from
    // the first header, and the signature must not run past 644.
    let rsa = match plan_header_fragments(&img, 0x1F, SBE_RSA) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("RSA header plan should succeed"),
    };
    let want_rsa = [
        (FRAG_INIT, 0, 128),
        (FRAG_PKEY, 128, 256),
        (FRAG_SIGN, 388, 256),
    ];
    for (got, want) in rsa.iter().zip(want_rsa.iter()) {
        if (got.kind, got.offset, got.len) != *want {
            return TestResult::Fail("RSA header fragment offset/len/kind wrong");
        }
    }
    if rsa[2].offset + rsa[2].len != RSA_HEADER_LEN {
        return TestResult::Fail("the RSA signature must end exactly at 644");
    }

    // A CSS header version that is not RSA is not an image we know.
    let mut bad = img.clone();
    bad[CSS_HEADER_OFFSET] = 0x99;
    if plan_header_fragments(&bad, 0x1F, SBE_ECDSA).is_ok() {
        return TestResult::Fail("a bad CSS header version must be rejected");
    }

    // On a dual-header part the 0x06 marker is what proves the ECDSA
    // header is really there; without it the offsets are guesses.
    let mut no_marker = img.clone();
    no_marker[ECDSA_OFFSET] = 0x00;
    if plan_header_fragments(&no_marker, 0x1F, SBE_ECDSA).is_ok() {
        return TestResult::Fail("a missing ECDSA marker must be rejected");
    }

    // An unknown secure-boot engine would otherwise silently send the
    // wrong header and fail verification much later.
    if plan_header_fragments(&img, 0x1F, 0x07).is_ok() {
        return TestResult::Fail("an unknown sbe_type must be rejected");
    }

    // Truncated images must not index past their end.
    if plan_header_fragments(&img[..600], 0x1F, SBE_ECDSA).is_ok() {
        return TestResult::Fail("an image shorter than the RSA header must be rejected");
    }
    if plan_header_fragments(&img[..700], 0x1F, SBE_ECDSA).is_ok() {
        return TestResult::Fail("an image shorter than both headers must be rejected");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_fw_header_plan);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_fw_payload_fragments() -> TestResult {
    use crate::btintel_pcie::fw::*;

    // One 4-byte command aligns on its own; a 3-byte command followed
    // by a 5-byte one only aligns as a pair, which is the whole point
    // of accumulating a run before emitting a fragment.
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x01, 0xFC, 1, 0xAA]); // 4 bytes
    payload.extend_from_slice(&[0x02, 0xFC, 0]); // 3 bytes
    payload.extend_from_slice(&[0x03, 0xFC, 2, 0xBB, 0xCC]); // 5 bytes
    let img = synthetic_sfi(&payload);

    let frags = match plan_payload_fragments(&img, PAYLOAD_OFFSET) {
        Ok(f) => f,
        Err(_) => return TestResult::Fail("aligned payload should plan"),
    };
    if frags.len() != 2 {
        return TestResult::Fail("payload should split into two aligned fragments");
    }
    if (frags[0].offset, frags[0].len) != (PAYLOAD_OFFSET, 4) {
        return TestResult::Fail("first fragment should be the lone 4-byte command");
    }
    if (frags[1].offset, frags[1].len) != (PAYLOAD_OFFSET + 4, 8) {
        return TestResult::Fail("second fragment should pair the 3- and 5-byte commands");
    }
    for f in &frags {
        if f.kind != FRAG_DATA {
            return TestResult::Fail("payload fragments are Data fragments");
        }
        if f.len % 4 != 0 {
            return TestResult::Fail("every fragment length must be 4-byte aligned");
        }
    }
    // The fragments must tile the payload exactly — no gap, no
    // overlap, ending on the last byte.
    let mut cursor = PAYLOAD_OFFSET;
    for f in &frags {
        if f.offset != cursor {
            return TestResult::Fail("fragments must tile the payload without gaps");
        }
        cursor += f.len;
    }
    if cursor != img.len() {
        return TestResult::Fail("fragments must cover the payload to its last byte");
    }

    // A command whose length runs past the end of the file must be
    // rejected rather than slicing out of bounds.
    let overrun = synthetic_sfi(&[0x01, 0xFC, 40, 0x00]);
    if plan_payload_fragments(&overrun, PAYLOAD_OFFSET).is_ok() {
        return TestResult::Fail("a command overrunning the image must be rejected");
    }

    // A payload that never reaches a 4-byte boundary before EOF is
    // malformed; emitting the unaligned tail would be rejected by the
    // bootloader with no useful diagnosis.
    let unaligned = synthetic_sfi(&[0x01, 0xFC, 0]);
    if plan_payload_fragments(&unaligned, PAYLOAD_OFFSET).is_ok() {
        return TestResult::Fail("an unaligned payload tail must be rejected");
    }

    // An empty payload is vacuously fine.
    match plan_payload_fragments(&synthetic_sfi(&[]), PAYLOAD_OFFSET) {
        Ok(f) if f.is_empty() => {}
        _ => return TestResult::Fail("an empty payload should plan to no fragments"),
    }

    // A start past the end is a caller bug, not a silent empty plan.
    if plan_payload_fragments(&img, img.len() + 1).is_ok() {
        return TestResult::Fail("a start past the image end must be rejected");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_fw_payload_fragments);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_fw_boot_param_scan() -> TestResult {
    use crate::btintel_pcie::fw::*;

    // The scan walks from byte zero as an HCI command stream, so the
    // synthetic image has to be walkable from the start for the
    // record to be reachable — exactly the property the real blobs
    // have and the reason Linux's odd-looking walk works.
    let mut img = Vec::new();
    // A filler command: opcode 0xfc02, 1 byte of payload.
    img.extend_from_slice(&[0x02, 0xFC, 1, 0x00]);
    // Intel_Write_Boot_Params carrying the MS-03's real values.
    img.extend_from_slice(&[0x0E, 0xFC, 7]);
    img.extend_from_slice(&0xB02F_F000u32.to_le_bytes());
    img.extend_from_slice(&[15, 18, 26]);

    let bp = match scan_boot_params(&img) {
        Some(b) => b,
        None => return TestResult::Fail("boot params should be found"),
    };
    if bp.boot_addr != 0xB02F_F000 {
        return TestResult::Fail("boot address should decode to 0xb02ff000");
    }
    if (bp.fw_build_num, bp.fw_build_ww, bp.fw_build_yy) != (15, 18, 26) {
        return TestResult::Fail("firmware version should decode as 15-18.26");
    }

    // No record at all means there is no address to reboot into, and
    // booting from zero would hang the controller.
    let none = [0x02u8, 0xFC, 1, 0x00, 0x03, 0xFC, 0];
    if scan_boot_params(&none).is_some() {
        return TestResult::Fail("an image without the record should report none");
    }

    // A record truncated mid-parameters must not read past the end.
    let mut short = img.clone();
    short.truncate(short.len() - 3);
    if scan_boot_params(&short).is_some() {
        return TestResult::Fail("a truncated boot-params record must not decode");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_fw_boot_param_scan);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_fw_ddc_and_limits() -> TestResult {
    use crate::btintel_pcie::fw::*;

    // The DDC file shipped for this part is four bytes: one record of
    // length 3 (a 2-byte id and a 1-byte value).
    let ddc = [0x03u8, 0x28, 0x01, 0x18];
    let recs = match plan_ddc_records(&ddc) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("the shipped DDC file should plan"),
    };
    if recs.len() != 1 || (recs[0].offset, recs[0].len) != (0, 4) {
        return TestResult::Fail("DDC record should span the whole 4-byte file");
    }

    // Two records back to back must tile exactly.
    let two = [0x03u8, 0x28, 0x01, 0x18, 0x04, 0x29, 0x01, 0x11, 0x22];
    match plan_ddc_records(&two) {
        Ok(r) if r.len() == 2 && r[1].offset == 4 && r[1].len == 5 => {}
        _ => return TestResult::Fail("two DDC records should tile exactly"),
    }

    // A record claiming more bytes than remain must be rejected.
    if plan_ddc_records(&[0x09u8, 0x28, 0x01]).is_ok() {
        return TestResult::Fail("an overlong DDC record must be rejected");
    }

    // A Secure Send carries the fragment type plus payload in the
    // command's single parameter-length byte, so the payload cap has
    // to leave room for that byte.
    if SECURE_SEND_MAX_FRAGMENT + 1 > u8::MAX as usize {
        return TestResult::Fail("secure-send fragment + type byte must fit one plen byte");
    }
    if SECURE_SEND_MAX_FRAGMENT != 252 {
        return TestResult::Fail("secure-send fragment cap should be 252");
    }

    // The payload starts after both headers; getting this wrong
    // shifts the entire command stream.
    if PAYLOAD_OFFSET != RSA_HEADER_LEN + ECDSA_HEADER_LEN || PAYLOAD_OFFSET != 964 {
        return TestResult::Fail("payload offset should be 644 + 320 = 964");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_fw_ddc_and_limits);

#[cfg(target_arch = "x86_64")]
fn smoke_btintel_fw_dsbr() -> TestResult {
    use crate::btintel_pcie::fw::*;

    // The MS-03's `UefiCnvCommonDSBR` variable body is 00 f1 00 00 00:
    // a one-byte header then the DSBR word 0x000000f1. (The four
    // attribute bytes efivarfs shows first are not part of the body.)
    let body = [0x00u8, 0xF1, 0x00, 0x00, 0x00];
    let dsbr = match parse_dsbr_variable(&body) {
        Some(d) => d,
        None => return TestResult::Fail("the MS-03 DSBR variable should decode"),
    };
    if dsbr != 0x0000_00F1 {
        return TestResult::Fail("DSBR word should decode to 0xf1");
    }
    // enable is bit 0; the value is bits 7:4.
    if dsbr_command_params(dsbr) != [0x01, 0x0F] {
        return TestResult::Fail("0xf1 should split into enable=1, dsbr=0xf");
    }
    // A platform that publishes nothing gets the disabled default,
    // which is still sent rather than skipped.
    if dsbr_command_params(0) != [0x00, 0x00] {
        return TestResult::Fail("an absent DSBR should send the disabled default");
    }
    // Only the two defined fields may reach the controller.
    if dsbr_command_params(0xFFFF_FFFF) != [0x01, 0x0F] {
        return TestResult::Fail("DSBR params must mask out undefined bits");
    }

    // A variable of the wrong size is not this structure, and reading
    // a u32 out of it would be reading someone else's bytes.
    if parse_dsbr_variable(&[0x00, 0xF1, 0x00, 0x00]).is_some() {
        return TestResult::Fail("a short DSBR variable must be rejected");
    }
    if parse_dsbr_variable(&[0x00, 0xF1, 0x00, 0x00, 0x00, 0x00]).is_some() {
        return TestResult::Fail("an overlong DSBR variable must be rejected");
    }

    // Scorpius Peak — the MS-03 — takes the command in its
    // intermediate loader and nowhere else.
    if !dsbr_required(HWID_SCP, IMG_IML, 0) {
        return TestResult::Fail("ScP in the IML image needs DSBR");
    }
    if dsbr_required(HWID_SCP, IMG_OP, 0) || dsbr_required(HWID_SCP, IMG_BOOTLOADER, 0) {
        return TestResult::Fail("ScP needs DSBR only in the IML image");
    }
    // BlazarI only at the B0 stepping.
    if !dsbr_required(HWID_BZRI, IMG_IML, 1) || dsbr_required(HWID_BZRI, IMG_IML, 0) {
        return TestResult::Fail("BlazarI needs DSBR only at stepping 1");
    }
    // Gale Peak2 / BlazarU are USB-only cases, so never over PCIe.
    if dsbr_required(HWID_GAP, IMG_OP, 0) || dsbr_required(HWID_BZRU, IMG_OP, 0) {
        return TestResult::Fail("GaP/BzrU DSBR is USB-only, not PCIe");
    }
    // Scorpius Peak2 onwards, in the IML.
    if !dsbr_required(HWID_SCP2, IMG_IML, 0) || !dsbr_required(HWID_SCP2F, IMG_IML, 0) {
        return TestResult::Fail("ScP2 and ScP2F need DSBR in the IML image");
    }
    if dsbr_required(HWID_SCP2, IMG_OP, 0) {
        return TestResult::Fail("ScP2 needs DSBR only in the IML image");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!("bluetooth/btintel_pcie", smoke_btintel_fw_dsbr);

/// The controller firmware download has the same ordering
/// requirement as the RTL8127 PHY patch: it runs from `Stage::Late`
/// and must come after the firmware scans, because `Stage::Late` runs
/// in registration order and narf-bluetooth registers before
/// narf-firmware. Getting this wrong leaves the controller parked in
/// its ROM bootloader with only a log line to show for it.
#[cfg(target_arch = "x86_64")]
fn smoke_btintel_firmware_runs_after_firmware_scans() -> TestResult {
    let late = narf_init::registered_names(narf_init::Stage::Late);
    let pos = |needle: &str| late.iter().position(|n| *n == needle);

    let (Some(download), Some(initramfs)) =
        (pos("btintel-pcie-firmware"), pos("firmware-scan-initramfs"))
    else {
        return TestResult::Skip("firmware or btintel initcalls not registered in this build");
    };

    if download < initramfs {
        return TestResult::Fail(
            "btintel-pcie-firmware runs before firmware-scan-initramfs; no blob will be found",
        );
    }
    if let Some(rootfs) = pos("firmware-scan-rootfs") {
        if download < rootfs {
            return TestResult::Fail(
                "btintel-pcie-firmware runs before firmware-scan-rootfs; no blob will be found",
            );
        }
    }

    // And the bring-up pass has to come after the download, since it
    // acts on whatever transports are registered by then. Inverted,
    // it would find an empty registry and silently bring nothing up.
    // Required, not optional: bare_main registers it unconditionally,
    // so its absence means the boot path lost the pass entirely.
    let Some(bringup) = pos("bluetooth-bringup") else {
        return TestResult::Fail("bluetooth-bringup is not registered; nothing drives bring-up");
    };
    if bringup < download {
        return TestResult::Fail(
            "bluetooth-bringup runs before btintel-pcie-firmware; no transport to bring up",
        );
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_firmware_runs_after_firmware_scans
);

/// The RX ring carries events, ACL and synchronous data interleaved
/// in one stream, while `HciTransport` asks for them through separate
/// calls. Without per-class queues, whichever call ran first would
/// consume and discard the other classes' traffic. This pins that
/// `recv_event` leaves ACL alone and vice versa.
#[cfg(target_arch = "x86_64")]
fn smoke_btintel_transport_demuxes_the_shared_ring() -> TestResult {
    use crate::btintel_pcie::rings::{HCI_ACL_PKT, HCI_EVT_PKT, HCI_ISO_PKT, HCI_SCO_PKT};
    use crate::btintel_pcie::transport::RxQueues;

    let q = RxQueues::new();

    // A Command Complete for HCI_Reset, then an ACL frame, then SCO —
    // the order a controller could plausibly deliver them in.
    q.file(HCI_EVT_PKT, vec![0x0E, 0x04, 0x01, 0x03, 0x0C, 0x00]);
    q.file(HCI_ACL_PKT, vec![0x01, 0x20, 0x02, 0x00, 0xAA, 0xBB]);
    q.file(HCI_SCO_PKT, vec![0x01, 0x00, 0x02, 0x11, 0x22]);

    if q.depths() != (1, 1, 1) {
        return TestResult::Fail("one packet of each class should land in its own queue");
    }

    // Taking the event must not disturb the other two.
    let ev = match q.pop_event() {
        Some(e) => e,
        None => return TestResult::Fail("the event should be available"),
    };
    if ev.code != 0x0E {
        return TestResult::Fail("wrong event code decoded");
    }
    if ev.params != [0x01, 0x03, 0x0C, 0x00] {
        return TestResult::Fail("event parameters decoded wrong");
    }
    if q.depths() != (0, 1, 1) {
        return TestResult::Fail("popping an event must not consume ACL or SCO");
    }

    match q.pop_acl() {
        Some(a) if a == [0x01, 0x20, 0x02, 0x00, 0xAA, 0xBB] => {}
        _ => return TestResult::Fail("the ACL frame should survive the event pop, intact"),
    }
    match q.pop_sco() {
        Some(s) if s == [0x01, 0x00, 0x02, 0x11, 0x22] => {}
        _ => return TestResult::Fail("the SCO frame should survive both pops, intact"),
    }
    if q.depths() != (0, 0, 0) {
        return TestResult::Fail("queues should be empty after draining each class");
    }

    // ISO shares the synchronous queue.
    q.file(HCI_ISO_PKT, vec![0x01, 0x00, 0x01, 0x42]);
    if q.depths().2 != 1 {
        return TestResult::Fail("ISO packets belong on the synchronous queue");
    }
    // Nothing should have been counted as lost or bad so far.
    if q.dropped() != 0 || q.malformed() != 0 {
        return TestResult::Fail("well-formed traffic must not count as dropped or malformed");
    }

    // An event too short to carry its own header, and a type word the
    // controller should never emit, are counted rather than guessed
    // at — and must not land on any queue.
    let before = q.depths();
    q.file(HCI_EVT_PKT, vec![0x0E]);
    q.file(0xDEAD_BEEF, vec![0x00]);
    if q.malformed() != 2 {
        return TestResult::Fail("a truncated event and an unknown type should both count");
    }
    if q.depths() != before {
        return TestResult::Fail("malformed packets must not be queued");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_transport_demuxes_the_shared_ring
);

/// A host that stops draining one class must not be able to grow the
/// queues without bound. Overflow drops the newest packet and counts
/// it, leaving the older (earlier in stream) ones in place.
#[cfg(target_arch = "x86_64")]
fn smoke_btintel_transport_queues_are_bounded() -> TestResult {
    use crate::btintel_pcie::rings::HCI_ACL_PKT;
    use crate::btintel_pcie::transport::{RxQueues, QUEUE_DEPTH};

    let q = RxQueues::new();
    for i in 0..QUEUE_DEPTH {
        q.file(HCI_ACL_PKT, vec![i as u8]);
    }
    if q.depths().1 != QUEUE_DEPTH {
        return TestResult::Fail("the queue should accept exactly QUEUE_DEPTH packets");
    }
    if q.dropped() != 0 {
        return TestResult::Fail("filling to capacity should drop nothing");
    }

    // One past capacity.
    q.file(HCI_ACL_PKT, vec![0xFF]);
    if q.depths().1 != QUEUE_DEPTH {
        return TestResult::Fail("the queue must not grow past QUEUE_DEPTH");
    }
    if q.dropped() != 1 {
        return TestResult::Fail("the overflowing packet should be counted");
    }

    // The oldest packet is still at the head — it is the newest that
    // was dropped, so the retained run stays in order from the front.
    match q.pop_acl() {
        Some(p) if p == [0x00] => {}
        _ => return TestResult::Fail("overflow should drop the newest, not the oldest"),
    }
    // And the dropped one never made it in.
    let mut seen_ff = false;
    while let Some(p) = q.pop_acl() {
        if p == [0xFF] {
            seen_ff = true;
        }
    }
    if seen_ff {
        return TestResult::Fail("the dropped packet must not be in the queue");
    }
    TestResult::Pass
}
#[cfg(target_arch = "x86_64")]
kernel_test_in!(
    "bluetooth/btintel_pcie",
    smoke_btintel_transport_queues_are_bounded
);
