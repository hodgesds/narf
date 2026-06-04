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

use core::convert::TryInto;

use super::ce::{
    self, validate, Ath10kMmio, CeDesc, CeDesc64, PipeDefault, RingConfig, DEFAULT_PIPE_CONFIG,
};
use super::htc::{
    build_connect_service, build_setup_complete, decode_htc_hdr, encode_htc_hdr,
    parse_connect_service_response, run_handshake, svc, ConnectServiceResponse, ConnectStatus,
    HandshakeError, HtcHdr, MessageId, SVC_ID_HTT_DATA_MSG, SVC_ID_WMI_CONTROL,
};
use super::htt::{
    build_rx_ring_setup, decode_rx_indication, encode_rx_ring_cfg, h2t_msg_type,
    HTT_RX_RING_FILL_LEVEL, HTT_RX_RING_SIZE,
};
use super::hw::ce_off;
use super::hw::*;
use super::pci::{name_for, register_pci_driver};
use super::wmi::{
    build_pdev_set_param, build_vdev_create, build_vdev_set_param, decode_event, decode_wmi_hdr,
    encode_wmi_hdr, vdev_param, EventFrame, VdevSubtype, VdevType, WmiCmdHdr, WmiCmdId, WmiError,
    WmiEventId,
};
use alloc::vec;

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
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_hw_rev_from_pci_id_coverage
);

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
kernel_test_in!(
    "drivers/wireless/ath10k",
    smoke_ath10k_chip_id_rev_extraction
);

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
kernel_test_in!("drivers/wireless/ath10k", smoke_ath10k_probe_bound_or_skip);

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
    let _ = PipeDefault {
        pipe: 9,
        is_src: false,
        nentries: 1,
        service: "",
    };
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

// ── Stage 2: HTC frame codec ───────────────────────────────────────

fn smoke_ath10k_htc_hdr_round_trip() -> TestResult {
    let h = HtcHdr::tx(7, 0x1234, 0x55);
    let mut buf = [0u8; 16];
    if encode_htc_hdr(&h, &mut buf).is_err() {
        return TestResult::Fail("encode_htc_hdr failed");
    }
    let dec = match decode_htc_hdr(&buf) {
        Ok(d) => d,
        Err(()) => return TestResult::Fail("decode_htc_hdr failed"),
    };
    if dec.eid != 7 {
        return TestResult::Fail("eid round-trip wrong");
    }
    if dec.len != 0x1234 {
        return TestResult::Fail("len round-trip wrong");
    }
    if dec.control_byte1 != 0x55 {
        return TestResult::Fail("seq_no/control_byte1 round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htc",
    smoke_ath10k_htc_hdr_round_trip
);

fn smoke_ath10k_htc_hdr_decode_short_rejects() -> TestResult {
    let buf = [0u8; 4];
    if decode_htc_hdr(&buf).is_ok() {
        return TestResult::Fail("decode_htc_hdr accepted short buffer");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htc",
    smoke_ath10k_htc_hdr_decode_short_rejects
);

fn smoke_ath10k_htc_connect_service_round_trip() -> TestResult {
    let body = build_connect_service(SVC_ID_WMI_CONTROL, 0);
    // First 2 bytes = MessageId::ConnectService = 2.
    let msg_id = u16::from_le_bytes([body[0], body[1]]);
    if MessageId::from_raw(msg_id) != Some(MessageId::ConnectService) {
        return TestResult::Fail("connect_service msg_id wrong");
    }
    let svc_id = u16::from_le_bytes([body[2], body[3]]);
    if svc_id != SVC_ID_WMI_CONTROL {
        return TestResult::Fail("connect_service svc_id wrong");
    }

    // Build a synthetic response: msg_id=3, svc_id, status=0, eid=1, max_msg=0x800.
    let mut resp = [0u8; 8];
    resp[0..2].copy_from_slice(&(MessageId::ConnectServiceResponse as u16).to_le_bytes());
    resp[2..4].copy_from_slice(&SVC_ID_WMI_CONTROL.to_le_bytes());
    resp[4] = ConnectStatus::Success as u8;
    resp[5] = 1;
    resp[6..8].copy_from_slice(&0x0800u16.to_le_bytes());

    let parsed = match parse_connect_service_response(&resp) {
        Ok(p) => p,
        Err(()) => return TestResult::Fail("parse_connect_service_response failed"),
    };
    let expect = ConnectServiceResponse {
        service_id: SVC_ID_WMI_CONTROL,
        status: ConnectStatus::Success,
        endpoint_id: 1,
        max_msg_size: 0x0800,
    };
    if parsed != expect {
        return TestResult::Fail("parse_connect_service_response payload wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htc",
    smoke_ath10k_htc_connect_service_round_trip
);

fn smoke_ath10k_htc_service_id_packing() -> TestResult {
    if svc(1, 0) != SVC_ID_WMI_CONTROL {
        return TestResult::Fail("WMI svc id packing wrong");
    }
    if svc(3, 0) != SVC_ID_HTT_DATA_MSG {
        return TestResult::Fail("HTT data msg svc id packing wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htc",
    smoke_ath10k_htc_service_id_packing
);

fn smoke_ath10k_htc_setup_complete_encodes_flags() -> TestResult {
    let with = build_setup_complete(true);
    let without = build_setup_complete(false);
    if u16::from_le_bytes([with[0], with[1]]) != MessageId::SetupCompleteEx as u16 {
        return TestResult::Fail("setup-complete msg_id wrong");
    }
    let flags_with = u32::from_le_bytes(with[4..8].try_into().unwrap());
    let flags_without = u32::from_le_bytes(without[4..8].try_into().unwrap());
    if flags_with == 0 {
        return TestResult::Fail("rx_bundle_en=true should set flags bit");
    }
    if flags_without != 0 {
        return TestResult::Fail("rx_bundle_en=false should clear flags");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htc",
    smoke_ath10k_htc_setup_complete_encodes_flags
);

fn smoke_ath10k_htc_run_handshake_stub_returns_not_implemented() -> TestResult {
    match run_handshake() {
        Err(HandshakeError::NotImplemented) => TestResult::Pass,
        _ => TestResult::Fail("Stage-2 handshake should return NotImplemented"),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/htc",
    smoke_ath10k_htc_run_handshake_stub_returns_not_implemented
);

// ── Stage 2: WMI codec ─────────────────────────────────────────────

fn smoke_ath10k_wmi_hdr_round_trip() -> TestResult {
    let hdr = WmiCmdHdr::new(WmiCmdId::Init as u32);
    let mut buf = [0u8; 8];
    if encode_wmi_hdr(&hdr, &mut buf).is_err() {
        return TestResult::Fail("encode_wmi_hdr failed");
    }
    let dec = match decode_wmi_hdr(&buf) {
        Ok(d) => d,
        Err(()) => return TestResult::Fail("decode_wmi_hdr failed"),
    };
    if dec.cmd_id() != WmiCmdId::Init as u32 {
        return TestResult::Fail("cmd_id round-trip wrong");
    }
    if dec.plt_priv() != 0 {
        return TestResult::Fail("host should leave plt_priv = 0");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi",
    smoke_ath10k_wmi_hdr_round_trip
);

fn smoke_ath10k_wmi_cmd_id_masking() -> TestResult {
    let synth = WmiCmdHdr {
        cmd_id_and_priv: 0xAABB_CCCC,
    };
    if synth.cmd_id() != 0x00BB_CCCC {
        return TestResult::Fail("cmd_id mask leaks into priv field");
    }
    if synth.plt_priv() != 0xAA {
        return TestResult::Fail("plt_priv decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi",
    smoke_ath10k_wmi_cmd_id_masking
);

fn smoke_ath10k_wmi_build_pdev_set_param_layout() -> TestResult {
    let frame = build_pdev_set_param(0xDEAD, 0xBEEF);
    if frame.len() != 4 + 4 + 4 {
        return TestResult::Fail("frame size wrong (hdr + param_id + param_value)");
    }
    let hdr = decode_wmi_hdr(&frame[..4]).expect("decode hdr");
    if hdr.cmd_id() != WmiCmdId::PdevSetParam as u32 {
        return TestResult::Fail("cmd_id mismatch");
    }
    let param_id = u32::from_le_bytes(frame[4..8].try_into().unwrap());
    let param_value = u32::from_le_bytes(frame[8..12].try_into().unwrap());
    if param_id != 0xDEAD || param_value != 0xBEEF {
        return TestResult::Fail("payload round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi",
    smoke_ath10k_wmi_build_pdev_set_param_layout
);

fn smoke_ath10k_wmi_event_decode_classifies_ready() -> TestResult {
    let mut frame = vec![0u8; 4];
    frame[0..4].copy_from_slice(&(WmiEventId::Ready as u32).to_le_bytes());
    frame.extend_from_slice(&[0u8; 8]);
    let ev: EventFrame<'_> = match decode_event(&frame) {
        Ok(e) => e,
        Err(()) => return TestResult::Fail("decode_event failed"),
    };
    if ev.event_id != WmiEventId::Ready {
        return TestResult::Fail("event id classification wrong");
    }
    if ev.payload.len() != 8 {
        return TestResult::Fail("payload length wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi",
    smoke_ath10k_wmi_event_decode_classifies_ready
);

fn smoke_ath10k_wmi_send_stub_returns_not_implemented() -> TestResult {
    match super::wmi::wmi_send(&[0u8; 4]) {
        Err(WmiError::NotImplemented) => TestResult::Pass,
        _ => TestResult::Fail("Stage-2 wmi_send should return NotImplemented"),
    }
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi",
    smoke_ath10k_wmi_send_stub_returns_not_implemented
);

// ── Stage 3: HTT RX ring layout + encode ──────────────────────────

fn smoke_ath10k_htt_rx_ring_layout_encode() -> TestResult {
    use super::htt::rx_ring_flags;
    if HTT_RX_RING_SIZE != 2048 {
        return TestResult::Fail("HTT_RX_RING_SIZE != 2048");
    }
    if HTT_RX_RING_FILL_LEVEL != 1023 {
        return TestResult::Fail("HTT_RX_RING_FILL_LEVEL != 1023");
    }
    let setup = build_rx_ring_setup(0x1000_0000, 0x2000_0000);
    if setup.rx_ring_base_paddr != 0x1000_0000 {
        return TestResult::Fail("rx_ring_base_paddr mismatch");
    }
    if setup.fw_idx_shadow_reg_paddr != 0x2000_0000 {
        return TestResult::Fail("fw_idx_shadow_reg_paddr mismatch");
    }
    if setup.flags & rx_ring_flags::UNICAST_RX == 0 {
        return TestResult::Fail("UNICAST_RX flag not set");
    }
    if setup.flags & rx_ring_flags::MULTICAST_RX == 0 {
        return TestResult::Fail("MULTICAST_RX flag not set");
    }
    let enc = encode_rx_ring_cfg(&setup);
    // Header: msg_type=2, num_rings=1, pad, pad.
    if enc[0] != h2t_msg_type::RX_RING_CFG {
        return TestResult::Fail("encoded msg_type != RX_RING_CFG(2)");
    }
    if enc[1] != 1 {
        return TestResult::Fail("encoded num_rings != 1");
    }
    // base_paddr at bytes 8..12 (after 4-byte hdr + 4-byte shadow_paddr).
    let base = u32::from_le_bytes(enc[8..12].try_into().unwrap());
    if base != 0x1000_0000 {
        return TestResult::Fail("encoded base_paddr wrong");
    }
    let shadow = u32::from_le_bytes(enc[4..8].try_into().unwrap());
    if shadow != 0x2000_0000 {
        return TestResult::Fail("encoded shadow_paddr wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt",
    smoke_ath10k_htt_rx_ring_layout_encode
);

// ── Stage 3: WMI VDEV_CREATE encode ───────────────────────────────

fn smoke_ath10k_wmi_vdev_create_cmd_encode() -> TestResult {
    let mac: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let frame = build_vdev_create(0, VdevType::Sta, VdevSubtype::None, mac);
    // hdr(4) + vdev_id(4) + vdev_type(4) + vdev_subtype(4) + mac(6) + pad(2) = 24 bytes.
    if frame.len() != 24 {
        return TestResult::Fail("vdev_create frame size wrong (expected 24)");
    }
    let cmd_id = u32::from_le_bytes(frame[0..4].try_into().unwrap()) & 0x00FF_FFFF;
    if cmd_id != WmiCmdId::VdevCreate as u32 {
        return TestResult::Fail("cmd_id != WMI_VDEV_CREATE_CMDID");
    }
    let vdev_id = u32::from_le_bytes(frame[4..8].try_into().unwrap());
    if vdev_id != 0 {
        return TestResult::Fail("vdev_id != 0");
    }
    let vdev_type = u32::from_le_bytes(frame[8..12].try_into().unwrap());
    if vdev_type != VdevType::Sta as u32 {
        return TestResult::Fail("vdev_type != STA(2)");
    }
    if &frame[16..22] != &mac {
        return TestResult::Fail("mac_addr bytes wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi",
    smoke_ath10k_wmi_vdev_create_cmd_encode
);

fn smoke_ath10k_wmi_vdev_set_param_encode() -> TestResult {
    // hdr(4) + vdev_id(4) + param_id(4) + param_value(4) = 16 bytes.
    let frame = build_vdev_set_param(1, vdev_param::BEACON_INTERVAL, 100);
    if frame.len() != 16 {
        return TestResult::Fail("vdev_set_param frame size wrong (expected 16)");
    }
    let cmd_id = u32::from_le_bytes(frame[0..4].try_into().unwrap()) & 0x00FF_FFFF;
    // WMI_VDEV_SET_PARAM_CMDID = 0x5003.
    if cmd_id != 0x5003 {
        return TestResult::Fail("cmd_id != WMI_VDEV_SET_PARAM_CMDID (0x5003)");
    }
    let vdev_id = u32::from_le_bytes(frame[4..8].try_into().unwrap());
    if vdev_id != 1 {
        return TestResult::Fail("vdev_id != 1");
    }
    let param_id = u32::from_le_bytes(frame[8..12].try_into().unwrap());
    if param_id != vdev_param::BEACON_INTERVAL {
        return TestResult::Fail("param_id != BEACON_INTERVAL");
    }
    let param_val = u32::from_le_bytes(frame[12..16].try_into().unwrap());
    if param_val != 100 {
        return TestResult::Fail("param_value != 100");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/wmi",
    smoke_ath10k_wmi_vdev_set_param_encode
);

// ── Stage 3: HTT RX indication decode ─────────────────────────────

fn smoke_ath10k_htt_rx_indication_decode() -> TestResult {
    use super::htt::mpdu_status;
    // Build a synthetic T2H RX_IND message.
    // Layout: msg_type(1) + info0(1) + peer_id(2) + info1(4) = hdr 8 bytes
    //         + PPDU (44 bytes) + prefix/fw_rx_desc_bytes=0 (4 bytes)
    //         + mpdu_range[0]: count(1) + status(1) + pad(2) = 4 bytes.
    // Total = 8 + 44 + 4 + 4 = 60 bytes.
    let mut msg = vec![0u8; 60];
    msg[0] = super::htt::t2h_msg_type::RX_IND; // msg_type = 1
                                               // peer_id at bytes 2..4 = 42.
    msg[2..4].copy_from_slice(&42u16.to_le_bytes());
    // PPDU block occupies bytes 8..52 — leave zeroed.
    // fw_rx_desc_bytes at bytes 52..54 = 0 (no per-frame desc).
    msg[52] = 0;
    msg[53] = 0;
    // mpdu_range at bytes 56..60: count=3, status=OK=1, pad.
    msg[56] = 3; // mpdu_count
    msg[57] = mpdu_status::OK; // mpdu_range_status
    let ind = match decode_rx_indication(&msg) {
        Some(i) => i,
        None => return TestResult::Fail("decode_rx_indication returned None"),
    };
    if ind.hdr.peer_id != 42 {
        return TestResult::Fail("peer_id decode wrong");
    }
    if ind.mpdu_count != 3 {
        return TestResult::Fail("mpdu_count wrong");
    }
    if ind.mpdu_status != mpdu_status::OK {
        return TestResult::Fail("mpdu_status wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath10k/htt",
    smoke_ath10k_htt_rx_indication_decode
);
