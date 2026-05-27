//! ath10k smoke tests — co-located per project convention.
//!
//! Stage-0 set: pure-data PCI match table presence, HwRev decode,
//! chip-id-rev mask + per-chip register-offset tables. The
//! "real silicon" smoke (probe-bound device + CHIP_ID readback)
//! Skips cleanly when no ath10k part is bound — useful on the
//! QCA-equipped real-HW bring-up boxes, no-op on QEMU.

#![cfg(target_arch = "x86_64")]

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::ce::{
    self, validate, Ath10kMmio, CeDesc, CeDesc64, PipeDefault, RingConfig,
    DEFAULT_PIPE_CONFIG,
};
use super::hw::*;
use super::hw::ce_off;
use super::pci::{name_for, register_pci_driver};

// ── PCI match table ────────────────────────────────────────────────

fn smoke_ath10k_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    register_pci_driver();
    let registered = registered_pci_drivers();
    for &(vendor, device) in ALL_PCI_MATCHES {
        let matched = registered.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice {
                    vendor: v,
                    device: d,
                } if v == vendor && d == device
            )
        });
        if !matched {
            return TestResult::Fail("ath10k PCI match table missing a (vendor, device) pair");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath10k", smoke_ath10k_pci_match_table);

fn smoke_ath10k_name_for_known_ids() -> TestResult {
    if name_for(ATHEROS_VENDOR, QCA988X_DEVICE_ID) != "ath10k-qca988x" {
        return TestResult::Fail("qca988x name mismatch");
    }
    if name_for(ATHEROS_VENDOR, QCA6174_DEVICE_ID) != "ath10k-qca6174" {
        return TestResult::Fail("qca6174 name mismatch");
    }
    if name_for(ATHEROS_VENDOR, QCA9377_DEVICE_ID) != "ath10k-qca9377" {
        return TestResult::Fail("qca9377 name mismatch");
    }
    if name_for(UBNT_VENDOR, QCA988X_UBNT_DEVICE_ID) != "ath10k-qca988x-ubnt" {
        return TestResult::Fail("qca988x-ubnt name mismatch");
    }
    if name_for(0xDEAD, 0xBEEF) != "ath10k" {
        return TestResult::Fail("default name mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath10k", smoke_ath10k_name_for_known_ids);

// ── HwRev / chip-id ────────────────────────────────────────────────

fn smoke_ath10k_hw_rev_from_pci_id_coverage() -> TestResult {
    let expected = [
        (ATHEROS_VENDOR, QCA988X_DEVICE_ID, HwRev::Qca988x),
        (UBNT_VENDOR, QCA988X_UBNT_DEVICE_ID, HwRev::Qca988x),
        (ATHEROS_VENDOR, QCA6174_DEVICE_ID, HwRev::Qca6174),
        (ATHEROS_VENDOR, QCA6164_DEVICE_ID, HwRev::Qca6174),
        (ATHEROS_VENDOR, QCA99X0_DEVICE_ID, HwRev::Qca99x0),
        (ATHEROS_VENDOR, QCA9888_DEVICE_ID, HwRev::Qca9888),
        (ATHEROS_VENDOR, QCA9984_DEVICE_ID, HwRev::Qca9984),
        (ATHEROS_VENDOR, QCA9377_DEVICE_ID, HwRev::Qca9377),
        (ATHEROS_VENDOR, AR9462_DEVICE_ID, HwRev::Ar9462Legacy),
    ];
    for (v, d, e) in expected {
        match HwRev::from_pci_id(v, d) {
            Some(r) if r == e => {}
            other => {
                let _ = other;
                return TestResult::Fail("HwRev::from_pci_id mismatch");
            }
        }
    }
    if HwRev::from_pci_id(0xDEAD, 0xBEEF).is_some() {
        return TestResult::Fail("unknown PCI ID should be None");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath10k", smoke_ath10k_hw_rev_from_pci_id_coverage);

fn smoke_ath10k_chip_id_rev_extraction() -> TestResult {
    // `(rev << 8) | misc bits`. Linux docs: rev = (raw >> 8) & 0xF.
    // Mock a CHIP_ID = 0x000_0A37 -> rev = 0xA.
    if chip_id_rev(0x0000_0A37) != 0xA {
        return TestResult::Fail("chip_id_rev mis-shifts");
    }
    // Hi bits outside the mask are ignored.
    if chip_id_rev(0xFFFF_FFFF) != 0xF {
        return TestResult::Fail("chip_id_rev didn't mask high bits");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath10k", smoke_ath10k_chip_id_rev_extraction);

fn smoke_ath10k_per_chip_chip_id_addr_distinct() -> TestResult {
    // QCA6174 uses 0xF0; the rest use 0xEC.
    if soc_chip_id_address(HwRev::Qca6174) != 0x0000_00f0 {
        return TestResult::Fail("QCA6174 chip_id_address wrong");
    }
    if soc_chip_id_address(HwRev::Qca988x) != 0x0000_00ec {
        return TestResult::Fail("QCA988X chip_id_address wrong");
    }
    if soc_chip_id_address(HwRev::Qca9984) != 0x0000_00ec {
        return TestResult::Fail("QCA9984 chip_id_address wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_per_chip_chip_id_addr_distinct
);

fn smoke_ath10k_fw_indicator_address_per_chip() -> TestResult {
    // QCA988X / 6174 / 9377 — FW_INDICATOR at SOC_PCIE + 0x40.
    if fw_indicator_address(HwRev::Qca988x) != SOC_PCIE_BASE_ADDRESS + 0x40 {
        return TestResult::Fail("QCA988X FW_INDICATOR offset wrong");
    }
    // QCA99X0 / 9888 / 9984 — at +0x50.
    if fw_indicator_address(HwRev::Qca99x0) != SOC_PCIE_BASE_ADDRESS + 0x50 {
        return TestResult::Fail("QCA99X0 FW_INDICATOR offset wrong");
    }
    if fw_indicator_address(HwRev::Qca9984) != SOC_PCIE_BASE_ADDRESS + 0x50 {
        return TestResult::Fail("QCA9984 FW_INDICATOR offset wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_fw_indicator_address_per_chip
);

// ── Live-silicon smoke (Skip on QEMU) ──────────────────────────────

fn smoke_ath10k_probe_bound_or_skip() -> TestResult {
    if !super::pci::is_probed() {
        return TestResult::Skip("ath10k: no QCA part bound (expected on QEMU)");
    }
    // If we did probe, CHIP_ID must be sane (not all-0 / all-F).
    let raw = match super::pci::with_controller(|d| d.chip_id_raw) {
        Some(v) => v,
        None => return TestResult::Skip("ath10k: probed flag set but no controller borrowable"),
    };
    if raw == 0 || raw == 0xFFFF_FFFF {
        return TestResult::Fail("ath10k: bound device reports nonsense CHIP_ID");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_probe_bound_or_skip
);

// ── Stage 1: Copy Engine ring + descriptor ─────────────────────────

/// Mock MMIO that stages reads and records writes — same shape as
/// iwlwifi's smoke harness but BAR0-offset-keyed.
struct MockMmio {
    reads: VecDeque<(u64, u32)>,
    writes: Vec<(u64, u32)>,
    /// Default read for unstaged offsets — defaults to 0 so unrelated
    /// poll-loop reads don't false-positive as "device gone".
    default_read: u32,
}

impl MockMmio {
    fn new() -> Self {
        Self {
            reads: VecDeque::new(),
            writes: Vec::new(),
            default_read: 0,
        }
    }
    fn stage_read(&mut self, off: u64, val: u32) {
        self.reads.push_back((off, val));
    }
    fn last_write_to(&self, off: u64) -> Option<u32> {
        self.writes
            .iter()
            .rev()
            .find(|(o, _)| *o == off)
            .map(|(_, v)| *v)
    }
}

impl Ath10kMmio for MockMmio {
    fn read32(&mut self, off: u64) -> u32 {
        for i in 0..self.reads.len() {
            if self.reads[i].0 == off {
                return self.reads.remove(i).map(|(_, v)| v).unwrap_or(0);
            }
        }
        self.default_read
    }
    fn write32(&mut self, off: u64, value: u32) {
        self.writes.push((off, value));
    }
}

fn smoke_ath10k_program_src_ring_writes_expected_offsets() -> TestResult {
    let mut m = MockMmio::new();
    let cfg = RingConfig {
        pipe: 0,
        base_phys_lo: 0xC000_0000,
        nentries: 16,
        dmax_length: 0x0E80,
        host_int_disabled: false,
        src_byte_swap: false,
    };
    if ce::program_src_ring(&mut m, &cfg).is_err() {
        return TestResult::Fail("program_src_ring unexpectedly failed");
    }
    let base = CE_BASE_ADDRESSES[0];
    if m.last_write_to(base + ce_off::SR_BASE_LO) != Some(0xC000_0000) {
        return TestResult::Fail("SR_BASE_LO not written");
    }
    if m.last_write_to(base + ce_off::SR_SIZE) != Some(16 * CE_DESC_SIZE as u32) {
        return TestResult::Fail("SR_SIZE not written");
    }
    if m.last_write_to(base + ce_off::CTRL1) != Some(0x0E80) {
        return TestResult::Fail("CTRL1 dmax_length not written");
    }
    if m.last_write_to(base + ce_off::SR_WR_INDEX) != Some(0) {
        return TestResult::Fail("SR_WR_INDEX not zeroed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ce",
    smoke_ath10k_program_src_ring_writes_expected_offsets
);

fn smoke_ath10k_program_src_ring_honours_flags() -> TestResult {
    let mut m = MockMmio::new();
    let cfg = RingConfig {
        pipe: 3,
        base_phys_lo: 0x1000_0000,
        nentries: 32,
        dmax_length: 0x0040,
        host_int_disabled: true,
        src_byte_swap: true,
    };
    if ce::program_src_ring(&mut m, &cfg).is_err() {
        return TestResult::Fail("program_src_ring unexpectedly failed");
    }
    let base = CE_BASE_ADDRESSES[3];
    let ctrl1 = m.last_write_to(base + ce_off::CTRL1).unwrap_or(0);
    if ctrl1 & CE_CTRL1_DMAX_LENGTH_MASK != 0x0040 {
        return TestResult::Fail("CTRL1 dmax_length wrong");
    }
    if ctrl1 & CE_CTRL1_HOST_INT_DISABLE == 0 {
        return TestResult::Fail("CTRL1 host_int_disabled not set");
    }
    if ctrl1 & CE_CTRL1_SRC_RING_BYTE_SWAP_EN == 0 {
        return TestResult::Fail("CTRL1 src_byte_swap not set");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ce",
    smoke_ath10k_program_src_ring_honours_flags
);

fn smoke_ath10k_program_dst_ring_writes_expected_offsets() -> TestResult {
    let mut m = MockMmio::new();
    let cfg = RingConfig {
        pipe: 5,
        base_phys_lo: 0x2000_0000,
        nentries: 512,
        dmax_length: 0x0F00,
        host_int_disabled: false,
        src_byte_swap: false,
    };
    if ce::program_dst_ring(&mut m, &cfg).is_err() {
        return TestResult::Fail("program_dst_ring unexpectedly failed");
    }
    let base = CE_BASE_ADDRESSES[5];
    if m.last_write_to(base + ce_off::DR_BASE_LO) != Some(0x2000_0000) {
        return TestResult::Fail("DR_BASE_LO not written");
    }
    if m.last_write_to(base + ce_off::DR_SIZE) != Some(512 * CE_DESC_SIZE as u32) {
        return TestResult::Fail("DR_SIZE not written");
    }
    if m.last_write_to(base + ce_off::DR_WR_INDEX) != Some(0) {
        return TestResult::Fail("DR_WR_INDEX not zeroed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ce",
    smoke_ath10k_program_dst_ring_writes_expected_offsets
);

fn smoke_ath10k_validate_rejects_bad_pipe_and_nentries() -> TestResult {
    let bad_pipe = RingConfig {
        pipe: 13,
        base_phys_lo: 0,
        nentries: 8,
        dmax_length: 8,
        host_int_disabled: false,
        src_byte_swap: false,
    };
    if validate(&bad_pipe).is_ok() {
        return TestResult::Fail("validate accepted bad pipe");
    }
    let not_pow2 = RingConfig {
        pipe: 0,
        base_phys_lo: 0,
        nentries: 30,
        dmax_length: 8,
        host_int_disabled: false,
        src_byte_swap: false,
    };
    if validate(&not_pow2).is_ok() {
        return TestResult::Fail("validate accepted non-pow2 nentries");
    }
    let ok_dmax_max = RingConfig {
        pipe: 0,
        base_phys_lo: 0,
        nentries: 16,
        dmax_length: 0xFFFF,
        host_int_disabled: false,
        src_byte_swap: false,
    };
    if validate(&ok_dmax_max).is_err() {
        return TestResult::Fail("validate spuriously rejected dmax=0xFFFF");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ce",
    smoke_ath10k_validate_rejects_bad_pipe_and_nentries
);

fn smoke_ath10k_halt_pipe_polls_status() -> TestResult {
    let mut m = MockMmio::new();
    let base = CE_BASE_ADDRESSES[2];
    m.stage_read(base + CE_CMD_HALT_STATUS_OFFSET, 0);
    m.stage_read(base + CE_CMD_HALT_STATUS_OFFSET, CE_CMD_HALT_STATUS_HALTED);
    match ce::halt_pipe(&mut m, 2) {
        Ok(()) => {}
        Err(_) => return TestResult::Fail("halt_pipe should succeed"),
    }
    if m.last_write_to(base + ce_off::CMD) != Some(CE_CMD_HALT) {
        return TestResult::Fail("CE_CMD.HALT bit not written");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ce",
    smoke_ath10k_halt_pipe_polls_status
);

fn smoke_ath10k_halt_pipe_times_out_when_status_never_set() -> TestResult {
    let mut m = MockMmio::new();
    match ce::halt_pipe(&mut m, 4) {
        Err(ce::CeError::HaltTimeout) => TestResult::Pass,
        _ => TestResult::Fail("halt_pipe should time out"),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/ce",
    smoke_ath10k_halt_pipe_times_out_when_status_never_set
);

fn smoke_ath10k_default_pipe_config_shape() -> TestResult {
    if DEFAULT_PIPE_CONFIG.len() != 6 {
        return TestResult::Fail("default pipe config table size changed");
    }
    let p0 = DEFAULT_PIPE_CONFIG[0];
    if p0.pipe != 0 || !p0.is_src || p0.nentries != 16 {
        return TestResult::Fail("default pipe 0 wrong");
    }
    let p4 = DEFAULT_PIPE_CONFIG[4];
    if p4.pipe != 4 || !p4.is_src || p4.nentries != 256 {
        return TestResult::Fail("default pipe 4 (HTT TX) wrong");
    }
    let p5 = DEFAULT_PIPE_CONFIG[5];
    if p5.pipe != 5 || p5.is_src || p5.nentries != 512 {
        return TestResult::Fail("default pipe 5 (HTT RX) wrong");
    }
    for i in 0..DEFAULT_PIPE_CONFIG.len() {
        for j in (i + 1)..DEFAULT_PIPE_CONFIG.len() {
            if DEFAULT_PIPE_CONFIG[i].pipe == DEFAULT_PIPE_CONFIG[j].pipe {
                return TestResult::Fail("duplicate pipe id in default config");
            }
        }
    }
    // Silence unused-warning for PipeDefault import.
    let _ = PipeDefault { pipe: 9, is_src: false, nentries: 1, service: "" };
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/ce",
    smoke_ath10k_default_pipe_config_shape
);

fn smoke_ath10k_ce_desc_sizes() -> TestResult {
    if core::mem::size_of::<CeDesc>() != CE_DESC_SIZE {
        return TestResult::Fail("CeDesc not 8 bytes");
    }
    if core::mem::size_of::<CeDesc64>() != CE_DESC_SIZE_64 {
        return TestResult::Fail("CeDesc64 not 16 bytes");
    }
    let d = CeDesc::new(0x4000, 256, CE_DESC_FLAGS_GATHER);
    if !d.is_gather() {
        return TestResult::Fail("gather flag round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath10k/ce", smoke_ath10k_ce_desc_sizes);
