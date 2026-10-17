//! ath11k smoke tests — co-located per project convention.
//!
//! Pure-data only: PCI match presence, hw_rev decode, WMI TLV
//! round-trip, DP ring sizing. Live silicon
//! is exercised by the probe-bound-or-skip smoke at the bottom —
//! that one Skips cleanly on QEMU.

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use super::dp::*;
use super::hw::*;
use super::mhi::*;
use super::pci::{is_probed, with_controller};
use super::wmi::*;

// ── PCI match table ────────────────────────────────────────────────

fn smoke_ath11k_pci_match_table_registers() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::pci::register_pci_driver();
    let registered = registered_pci_drivers();
    for &did in ALL_DEV_IDS {
        let found = registered.iter().any(|m| {
            matches!(
                m.kind,
                MatchKind::VendorDevice { vendor, device }
                    if vendor == QCOM_VENDOR && device == did
            )
        });
        if !found {
            return TestResult::Fail("ath11k PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_pci_match_table_registers
);

fn smoke_ath11k_name_for_known_ids() -> TestResult {
    if name_for(ATH11K_DEV_QCA6390) != "ath11k-qca6390" {
        return TestResult::Fail("qca6390 name mismatch");
    }
    if name_for(ATH11K_DEV_QCN9074) != "ath11k-qcn9074" {
        return TestResult::Fail("qcn9074 name mismatch");
    }
    if name_for(ATH11K_DEV_WCN6855) != "ath11k-wcn6855" {
        return TestResult::Fail("wcn6855 name mismatch");
    }
    if name_for(0xFFFF) != "ath11k" {
        return TestResult::Fail("default name mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_name_for_known_ids);

// ── ChipInfo decode ────────────────────────────────────────────────

fn smoke_ath11k_chip_for_pci_id_known_pairs() -> TestResult {
    // Positive: every Linux `ath11k_pci_id_table` entry resolves.
    for &(did, rev) in &[
        (ATH11K_DEV_QCA6390, HwRev::Qca6390Hw20),
        (ATH11K_DEV_WCN6855, HwRev::Wcn6855Hw20),
        (ATH11K_DEV_QCN9074, HwRev::Qcn9074Hw10),
    ] {
        match chip_for_pci_id(QCOM_VENDOR, did) {
            Some(c) if c.did == did && c.default_hw_rev == rev => {}
            _ => return TestResult::Fail("ath11k PCI id did not resolve to its ChipInfo"),
        }
    }
    // Negative: ath12k parts (WCN7850 1107, QCN9274 1109) and the
    // never-assigned 1105 are not ath11k; nor is a non-Qualcomm vid.
    for &did in &[0x1105u16, 0x1107, 0x1109] {
        if chip_for_pci_id(QCOM_VENDOR, did).is_some() {
            return TestResult::Fail("ath11k claimed a non-ath11k Qualcomm PCI id");
        }
    }
    if chip_for_pci_id(0x8086, ATH11K_DEV_WCN6855).is_some() {
        return TestResult::Fail("ath11k claimed a non-Qualcomm vendor id");
    }
    if ALL_DEV_IDS.len() != 3 {
        return TestResult::Fail("ath11k match table is not exactly Linux's three ids");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_chip_for_pci_id_known_pairs
);

fn smoke_ath11k_refine_hw_rev_wcn6855_subversions() -> TestResult {
    // Linux `ath11k_pci_probe`: WCN6855 major 2, minor 0x00/0x01 → HW2.0.
    for minor in [0x00, 0x01] {
        if refine_hw_rev(ATH11K_DEV_WCN6855, 2, minor, 0) != HwRev::Wcn6855Hw20 {
            return TestResult::Fail("WCN6855 2.0x not classified as HW2.0");
        }
        if needs_sub_version(ATH11K_DEV_WCN6855, 2, minor) {
            return TestResult::Fail("WCN6855 HW2.0 should not read TCSR_SOC_HW_SUB_VER");
        }
    }
    // minor 0x10/0x11 → classify by TCSR_SOC_HW_SUB_VER.
    for minor in [0x10, 0x11] {
        if !needs_sub_version(ATH11K_DEV_WCN6855, 2, minor) {
            return TestResult::Fail("WCN6855 2.1x must read TCSR_SOC_HW_SUB_VER");
        }
        for sub in [0x1019_A0E1, 0x1019_B0E1, 0x1019_C0E1, 0x1019_D0E1] {
            if refine_hw_rev(ATH11K_DEV_WCN6855, 2, minor, sub) != HwRev::Qca2066Hw21 {
                return TestResult::Fail("QCA2066 sub-version not classified as QCA2066");
            }
        }
        if refine_hw_rev(ATH11K_DEV_WCN6855, 2, minor, 0x001E_60E1) != HwRev::Qca6698aqHw21 {
            return TestResult::Fail("QCA6698AQ sub-version not classified as QCA6698AQ");
        }
        if refine_hw_rev(ATH11K_DEV_WCN6855, 2, minor, 0x1234_5678) != HwRev::Wcn6855Hw21 {
            return TestResult::Fail("other sub-version not classified as WCN6855 HW2.1");
        }
    }
    // Steppings Linux rejects (`unsupported_wcn6855_soc`).
    if refine_hw_rev(ATH11K_DEV_WCN6855, 2, 0x12, 0x1019_A0E1) != HwRev::Unknown {
        return TestResult::Fail("WCN6855 minor 0x12 must be unsupported, as in Linux");
    }
    if refine_hw_rev(ATH11K_DEV_WCN6855, 1, 0, 0) != HwRev::Unknown {
        return TestResult::Fail("WCN6855 major 1 must be unsupported, as in Linux");
    }
    if refine_hw_rev(ATH11K_DEV_QCA6390, 3, 0, 0) != HwRev::Unknown {
        return TestResult::Fail("QCA6390 major != 2 must be unsupported, as in Linux");
    }
    if refine_hw_rev(0x9999, 0, 0, 0) != HwRev::Unknown {
        return TestResult::Fail("unknown PCI id should produce HwRev::Unknown");
    }
    // Firmware dirs = Linux `hw_params.fw.dir`.
    for (rev, dir) in [
        (HwRev::Wcn6855Hw20, "WCN6855/hw2.0"),
        (HwRev::Wcn6855Hw21, "WCN6855/hw2.1"),
        (HwRev::Qca2066Hw21, "QCA2066/hw2.1"),
        (HwRev::Qca6698aqHw21, "QCA6698AQ/hw2.1"),
    ] {
        if rev.fw_dir() != Some(dir) {
            return TestResult::Fail("hw_rev firmware dir differs from Linux hw_params");
        }
    }
    if HwRev::Unknown.fw_dir().is_some() {
        return TestResult::Fail("HwRev::Unknown must have no firmware dir");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_refine_hw_rev_wcn6855_subversions
);

// ── Window-register arithmetic ─────────────────────────────────────

fn smoke_ath11k_window_constants_consistent() -> TestResult {
    // ATH11K_PCI_WINDOW_RANGE_MASK covers exactly the 19 low bits.
    if ATH11K_PCI_WINDOW_RANGE_MASK != (1u32 << 19) - 1 {
        return TestResult::Fail("window range mask not (1<<19)-1");
    }
    // Window value mask occupies bits [24:19].
    if ATH11K_PCI_WINDOW_VALUE_MASK != (0x3F) << 19 {
        return TestResult::Fail("window value mask not bits[24:19]");
    }
    // Enable bit is bit 30.
    if ATH11K_PCI_WINDOW_ENABLE_BIT != 1u32 << 30 {
        return TestResult::Fail("window enable bit not at bit 30");
    }
    // Linux `ath11k_pci_select_window` writes the window *number*
    // (FIELD_GET of bits[24:19]), not the shifted field. 0x1910010
    // (TCSR_SOC_HW_SUB_VER) lives in window 0x32.
    use super::pci::{window_of, window_select_value, windowed_bar_offset};
    if window_of(TCSR_SOC_HW_SUB_VER) != 0x32 {
        return TestResult::Fail("window_of(0x1910010) != 0x32");
    }
    if window_select_value(TCSR_SOC_HW_SUB_VER) != (1 << 30) | 0x32 {
        return TestResult::Fail("window select must write ENABLE | window number");
    }
    if windowed_bar_offset(TCSR_SOC_HW_SUB_VER) != 0x80000 + 0x10010 {
        return TestResult::Fail("windowed BAR offset wrong for 0x1910010");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_window_constants_consistent
);

// MHI protocol + host tests live in `mhi_tests.rs`.

// ── WMI TLV encoder ────────────────────────────────────────────────

fn smoke_ath11k_wmi_cmd_id_encode() -> TestResult {
    // WMI_TLV_CMD(GRP_SCAN) = ((4<<12) | 0x1) = 0x4001.
    if build_cmd_id(WMI_GRP_SCAN, 0) != 0x4001 {
        return TestResult::Fail("WMI_START_SCAN_CMDID encoding wrong");
    }
    // PEER group: ((7<<12) | 1) = 0x7001.
    if build_cmd_id(WMI_GRP_PEER, 0) != 0x7001 {
        return TestResult::Fail("PEER_CREATE_CMDID encoding wrong");
    }
    // sub_id increments correctly.
    if build_cmd_id(WMI_GRP_SCAN, 1) != 0x4002 {
        return TestResult::Fail("WMI_STOP_SCAN_CMDID encoding wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_cmd_id_encode);

fn smoke_ath11k_wmi_tlv_round_trip() -> TestResult {
    let mut b = WmiCmdBuilder::new(WMI_INIT_CMDID);
    b.push_u32_tlv(WMI_TAG_RESOURCE_CONFIG, 0xDEAD_BEEF);
    b.push_tlv(WMI_TAG_HOST_MEM_CHUNK, &[0xAA, 0xBB, 0xCC]);
    let bytes = b.finish();
    // Frame should start with the cmd_hdr.
    let cmd_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if cmd_id != WMI_INIT_CMDID {
        return TestResult::Fail("encoded cmd id wrong");
    }
    // Walk should yield two TLVs.
    let (evt_id, tlvs) = walk_event(&bytes).expect("walk_event ok");
    if evt_id != WMI_INIT_CMDID {
        return TestResult::Fail("walked cmd id wrong");
    }
    if tlvs.len() != 2 {
        return TestResult::Fail("expected 2 TLVs");
    }
    if tlvs[0].tag != WMI_TAG_RESOURCE_CONFIG {
        return TestResult::Fail("first TLV tag wrong");
    }
    if tlvs[0].payload.len() != 4 {
        return TestResult::Fail("first TLV payload size wrong");
    }
    let first_val = u32::from_le_bytes(tlvs[0].payload.try_into().unwrap());
    if first_val != 0xDEAD_BEEF {
        return TestResult::Fail("first TLV payload value wrong");
    }
    // Second TLV is 3-byte payload + 1-byte pad in the stream.
    if tlvs[1].tag != WMI_TAG_HOST_MEM_CHUNK {
        return TestResult::Fail("second TLV tag wrong");
    }
    if tlvs[1].payload != [0xAA, 0xBB, 0xCC] {
        return TestResult::Fail("second TLV payload wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_tlv_round_trip);

fn smoke_ath11k_wmi_build_init_cmd() -> TestResult {
    let rc = ResourceConfig {
        num_vdevs: 3,
        num_peers: 16,
        num_tids: 256,
        tx_chain_mask: 0x3,
        rx_chain_mask: 0x3,
        ..Default::default()
    };
    let bytes = build_init_cmd(&rc);
    let (evt_id, tlvs) = walk_event(&bytes).expect("walk_event ok");
    if evt_id != WMI_INIT_CMDID {
        return TestResult::Fail("init cmd id wrong");
    }
    if tlvs.len() != 2 {
        return TestResult::Fail("INIT should have 2 TLVs (init_cmd + resource_config)");
    }
    if tlvs[0].tag != WMI_TAG_INIT_CMD {
        return TestResult::Fail("first TLV not WMI_TAG_INIT_CMD");
    }
    if tlvs[1].tag != WMI_TAG_RESOURCE_CONFIG {
        return TestResult::Fail("second TLV not WMI_TAG_RESOURCE_CONFIG");
    }
    if tlvs[1].payload.len() != 40 {
        return TestResult::Fail("resource_config payload should be 40 bytes");
    }
    // Spot-check encoded num_vdevs == 3.
    let num_vdevs = u32::from_le_bytes(tlvs[1].payload[0..4].try_into().unwrap());
    if num_vdevs != 3 {
        return TestResult::Fail("num_vdevs not round-tripped");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_wmi_build_init_cmd);

fn smoke_ath11k_wmi_truncated_tlv_detected() -> TestResult {
    // Build a frame, lop off the last byte, expect Truncated.
    let mut b = WmiCmdBuilder::new(WMI_INIT_CMDID);
    b.push_u32_tlv(WMI_TAG_RESOURCE_CONFIG, 0xCAFE_F00D);
    let mut bytes = b.finish();
    bytes.pop();
    match walk_event(&bytes) {
        Err(WmiDecodeError::Truncated { .. }) => TestResult::Pass,
        // The 4-byte payload becomes 3 bytes; with padding the
        // stream might end exactly at a TLV boundary, in which
        // case the decoder reports the truncation via remaining-
        // byte mismatch. Either Truncated or a *shorter* tlv list
        // is acceptable. We test the obvious failure mode here.
        other => {
            let _ = other; // hush unused
            TestResult::Fail("expected Truncated on truncated input")
        }
    }
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_wmi_truncated_tlv_detected
);

// ── DP descriptor sizing ───────────────────────────────────────────

fn smoke_ath11k_dp_ring_default_sizes() -> TestResult {
    if default_ring_size(HalRingType::TclData) != DP_TCL_DATA_RING_SIZE {
        return TestResult::Fail("TCL_DATA default size mismatch");
    }
    if default_ring_size(HalRingType::ReoDst) != DP_REO_DST_RING_SIZE {
        return TestResult::Fail("REO_DST default size mismatch");
    }
    if default_ring_size(HalRingType::WbmIdleListEnd) != 0 {
        return TestResult::Fail("WBM_IDLE_LIST_END should have zero default size");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_ring_default_sizes
);

fn smoke_ath11k_dp_descriptor_sizes() -> TestResult {
    if HalTclDataCmd::SIZE != 32 {
        return TestResult::Fail("HAL_TCL_DATA_CMD size should be 32 bytes");
    }
    if HalReoDstDesc::SIZE != 32 {
        return TestResult::Fail("HAL_REO_DST_DESC size should be 32 bytes");
    }
    // Round-trip TCL data cmd.
    let mut tcl = HalTclDataCmd::default();
    tcl.set_buf_dma(0x1_0000_2000);
    tcl.set_data_len(0x0400);
    if tcl.buf_addr_lo != 0x0000_2000 {
        return TestResult::Fail("TCL_DATA buf_addr_lo wrong");
    }
    if tcl.info0 & 0xFF != 1 {
        return TestResult::Fail("TCL_DATA buf_addr_hi wrong");
    }
    if tcl.info1 & 0xFFFF != 0x0400 {
        return TestResult::Fail("TCL_DATA data length wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_descriptor_sizes);

fn smoke_ath11k_dp_ring_dir_classification() -> TestResult {
    if HalRingType::TclData.default_dir() != HalRingDir::SrcRing {
        return TestResult::Fail("TCL_DATA should be a source ring");
    }
    if HalRingType::ReoDst.default_dir() != HalRingDir::DstRing {
        return TestResult::Fail("REO_DST should be a destination ring");
    }
    if HalRingType::TclStatus.default_dir() != HalRingDir::DstRing {
        return TestResult::Fail("TCL_STATUS should be a destination ring");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_ring_dir_classification
);

// ── Live-silicon smoke ─────────────────────────────────────────────
//
// QEMU doesn't emulate any ath11k part — Skip cleanly so the
// real-HW lane lights up without restructuring the test list.

fn smoke_ath11k_probe_bound_or_skip() -> TestResult {
    if !is_probed() {
        return TestResult::Skip("ath11k: no ath11k device bound (expected on QEMU)");
    }
    let hw_rev = match with_controller(|d| d.hw_rev) {
        Some(r) => r,
        None => return TestResult::Skip("ath11k: probed flag set but no controller"),
    };
    if hw_rev == HwRev::Unknown {
        return TestResult::Fail("ath11k: bound device reports HwRev::Unknown");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_probe_bound_or_skip);

// ── Stage 3: WMI VDEV commands ─────────────────────────────────────

fn smoke_ath11k_wmi_vdev_create_encode() -> TestResult {
    let mac: [u8; 6] = [0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let frame = build_vdev_create(0, vdev_type::STA, mac, 0);
    // cmd_hdr(4) + VDEV_CREATE_CMD TLV hdr(4) + payload(36)
    //           + ARRAY_STRUCT TLV hdr(4) + streams(24) = 72 bytes.
    if frame.len() < 16 {
        return TestResult::Fail("vdev_create frame too short");
    }
    let cmd_id = u32::from_le_bytes(frame[0..4].try_into().unwrap()) & 0x00FF_FFFF;
    if cmd_id != WMI_VDEV_CREATE_CMDID {
        return TestResult::Fail("cmd_id != WMI_VDEV_CREATE_CMDID");
    }
    // walk_event parses from the cmd_hdr (offset 0), treating it as the event id.
    let (evt_id, tlvs) = match walk_event(&frame) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("walk_event failed on vdev_create frame"),
    };
    if evt_id != WMI_VDEV_CREATE_CMDID {
        return TestResult::Fail("walk_event evt_id != WMI_VDEV_CREATE_CMDID");
    }
    if tlvs.is_empty() {
        return TestResult::Fail("no TLVs in vdev_create frame");
    }
    // First TLV is VDEV_CREATE_CMD; payload[0..4] = vdev_id.
    if tlvs[0].payload.len() < 4 {
        return TestResult::Fail("first TLV payload too short");
    }
    let vdev_id = u32::from_le_bytes(tlvs[0].payload[0..4].try_into().unwrap());
    if vdev_id != 0 {
        return TestResult::Fail("vdev_id != 0 in first TLV");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k/wmi",
    smoke_ath11k_wmi_vdev_create_encode
);

fn smoke_ath11k_wmi_vdev_set_param_channel_encode() -> TestResult {
    let frame = build_vdev_set_param(0, vdev_param::CHANNEL, 5180);
    // cmd_hdr(4) + VDEV_SET_PARAM_CMD TLV hdr(4) + payload(12) = 20 bytes.
    if frame.len() != 20 {
        return TestResult::Fail("vdev_set_param frame size wrong (expected 20)");
    }
    let cmd_id = u32::from_le_bytes(frame[0..4].try_into().unwrap()) & 0x00FF_FFFF;
    if cmd_id != WMI_VDEV_SET_PARAM_CMDID {
        return TestResult::Fail("cmd_id != WMI_VDEV_SET_PARAM_CMDID");
    }
    // cmd_id must differ from ath10k's 0x5003.
    if cmd_id == 0x5003 {
        return TestResult::Fail("ath11k set_param cmd_id wrongly matches ath10k 0x5003");
    }
    // TLV payload at offset 8: vdev_id(4) + param_id(4) + param_value(4).
    let param_id = u32::from_le_bytes(frame[12..16].try_into().unwrap());
    let param_val = u32::from_le_bytes(frame[16..20].try_into().unwrap());
    if param_id != vdev_param::CHANNEL {
        return TestResult::Fail("param_id != CHANNEL");
    }
    if param_val != 5180 {
        return TestResult::Fail("param_value != 5180");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k/wmi",
    smoke_ath11k_wmi_vdev_set_param_channel_encode
);

// ── Phase 1: power-up sequence (Linux ath11k_pci_sw_reset) ─────────

mod fake_io {
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    use super::super::power::ChipIo;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Op {
        R(u32),
        W(u32, u32),
        Delay(u32),
        RestoreWindow,
    }

    /// Register file: writes stick unless the offset is `stuck`, in
    /// which case reads always return the stuck value.
    #[derive(Default)]
    pub struct FakeIo {
        pub regs: RefCell<BTreeMap<u32, u32>>,
        pub stuck: BTreeMap<u32, u32>,
        pub ops: RefCell<Vec<Op>>,
    }

    impl ChipIo for FakeIo {
        fn read32(&self, offset: u32) -> u32 {
            self.ops.borrow_mut().push(Op::R(offset));
            if let Some(&v) = self.stuck.get(&offset) {
                return v;
            }
            *self.regs.borrow().get(&offset).unwrap_or(&0)
        }
        fn write32(&self, offset: u32, value: u32) {
            self.ops.borrow_mut().push(Op::W(offset, value));
            self.regs.borrow_mut().insert(offset, value);
        }
        fn delay_ms(&self, ms: u32) {
            self.ops.borrow_mut().push(Op::Delay(ms));
        }
        fn restore_window(&self) {
            self.ops.borrow_mut().push(Op::RestoreWindow);
        }
    }
}

fn smoke_ath11k_sw_reset_matches_linux_sequence() -> TestResult {
    use super::power::*;
    use fake_io::{FakeIo, Op::*};
    let io = FakeIo::default();
    io.regs.borrow_mut().insert(WLAON_QFPROM_PWR_CTRL_REG, 0xF);
    io.regs.borrow_mut().insert(PCIE_SOC_GLOBAL_RESET, 0x10);
    io.regs.borrow_mut().insert(WLAON_SOC_RESET_CAUSE_REG, 0x5);
    io.regs.borrow_mut().insert(MHISTATUS, 0x4); // SYSERR latched
                                                 // WCN6855: fix_l1ss = false.
    let report = sw_reset(&io, true, None);
    let expected = [
        Delay(100),
        // ath11k_pci_enable_ltssm
        R(PCIE_PCIE_PARF_LTSSM),
        W(PCIE_PCIE_PARF_LTSSM, PARM_LTSSM_VALUE),
        R(PCIE_PCIE_PARF_LTSSM),
        R(GCC_GCC_PCIE_HOT_RST),
        W(GCC_GCC_PCIE_HOT_RST, GCC_GCC_PCIE_HOT_RST_VAL),
        R(GCC_GCC_PCIE_HOT_RST),
        Delay(5),
        // ath11k_pci_clear_all_intrs
        W(PCIE_PCIE_INT_ALL_CLEAR, PCIE_INT_CLEAR_ALL),
        // ath11k_pci_set_wlaon_pwr_ctrl: clear VDD4BLOW (bit 2)
        R(WLAON_QFPROM_PWR_CTRL_REG),
        W(WLAON_QFPROM_PWR_CTRL_REG, 0xB),
        // ath11k_mhi_clear_vector
        W(0x360, 0),
        W(0x368, 0),
        W(0x394, 0),
        W(0x39C, 0),
        // ath11k_pci_clear_dbg_registers
        R(PCIE_Q6_COOKIE_ADDR),
        R(WLAON_WARM_SW_ENTRY),
        Delay(10),
        W(WLAON_WARM_SW_ENTRY, 0),
        Delay(10),
        R(WLAON_WARM_SW_ENTRY),
        R(WLAON_SOC_RESET_CAUSE_REG),
        // ath11k_pci_soc_global_reset: set V, then toggle it back
        R(PCIE_SOC_GLOBAL_RESET),
        W(PCIE_SOC_GLOBAL_RESET, 0x11),
        Delay(10),
        W(PCIE_SOC_GLOBAL_RESET, 0x10),
        Delay(10),
        R(PCIE_SOC_GLOBAL_RESET),
        RestoreWindow,
        // ath11k_mhi_set_mhictrl_reset
        R(0x48),
        W(0x38, 0x2),
        Delay(10),
    ];
    if io.ops.borrow().as_slice() != expected {
        return TestResult::Fail("sw_reset(power_on) op sequence differs from Linux");
    }
    if report.ltssm != PARM_LTSSM_VALUE
        || report.reset_cause != 0x5
        || report.mhistatus != 0x4
        || report.link_down_after_reset
        || report.l1ss_failed_reg.is_some()
    {
        return TestResult::Fail("sw_reset report fields wrong on a healthy chip");
    }
    // power_on = false skips LTSSM / interrupt clear / WLAON / L1SS.
    let io = FakeIo::default();
    let _ = sw_reset(&io, false, None);
    if io.ops.borrow().contains(&R(PCIE_PCIE_PARF_LTSSM)) {
        return TestResult::Fail("sw_reset(power_on=false) touched LTSSM");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_sw_reset_matches_linux_sequence
);

fn smoke_ath11k_power_up_failure_paths() -> TestResult {
    use super::power::*;
    use fake_io::{FakeIo, Op};
    // LTSSM never settles and reads all-ones: 5 retries, 5 ms apart.
    let mut io = FakeIo::default();
    io.stuck.insert(PCIE_PCIE_PARF_LTSSM, 0xffff_ffff);
    let mut report = PowerUpReport::default();
    enable_ltssm(&io, &mut report);
    let writes = io
        .ops
        .borrow()
        .iter()
        .filter(|o| matches!(o, Op::W(PCIE_PCIE_PARF_LTSSM, _)))
        .count();
    if writes != 5 || report.ltssm != 0xffff_ffff {
        return TestResult::Fail("stuck LTSSM must be retried exactly 5 times");
    }
    // Link down after global reset is reported, not fatal.
    io = FakeIo::default();
    io.stuck.insert(PCIE_SOC_GLOBAL_RESET, 0xffff_ffff);
    let report = sw_reset(&io, true, None);
    if !report.link_down_after_reset {
        return TestResult::Fail("all-ones after global reset not reported as link down");
    }
    if !io.ops.borrow().contains(&Op::W(0x38, 0x2)) {
        return TestResult::Fail("MHICTRL reset must still run after a link-down warning");
    }
    // set_link_reg: a register that never takes the value fails after
    // 10 attempts, 2 ms apart, naming the register.
    io = FakeIo::default();
    io.stuck.insert(0x1000, 0x0);
    if set_link_reg(&io, 0x1000, 0x52, 0xff) != Err(0x1000) {
        return TestResult::Fail("set_link_reg must fail with the stuck register offset");
    }
    let attempts = io
        .ops
        .borrow()
        .iter()
        .filter(|o| matches!(o, Op::W(0x1000, _)))
        .count();
    if attempts != 10 {
        return TestResult::Fail("set_link_reg must make exactly 10 write attempts");
    }
    // Already-correct register: no write at all.
    io = FakeIo::default();
    io.regs.borrow_mut().insert(0x2000, 0x1252);
    if set_link_reg(&io, 0x2000, 0x52, 0xff) != Ok(())
        || io.ops.borrow().iter().any(|o| matches!(o, Op::W(..)))
    {
        return TestResult::Fail("set_link_reg wrote a register already holding the value");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_power_up_failure_paths
);

fn smoke_ath11k_fix_l1ss_programs_qca6390_phy() -> TestResult {
    use super::power::*;
    use fake_io::FakeIo;
    let regs = match HwRev::Qca6390Hw20.params().and_then(|p| p.fix_l1ss) {
        Some(r) => r,
        None => return TestResult::Fail("QCA6390 must have fix_l1ss (Linux true)"),
    };
    let io = FakeIo::default();
    if fix_l1ss(&io, &regs).is_err() {
        return TestResult::Fail("fix_l1ss failed on a writable register file");
    }
    let r = io.regs.borrow();
    let get = |o: u32| *r.get(&o).unwrap_or(&0);
    if get(0x01e0_c0ac) != 0x10
        || get(0x01e0_c628) != 0x02
        || get(0x01e0_c62c) != 0x52
        || get(0x01e0_c634) != 0xff
    {
        return TestResult::Fail("fix_l1ss did not program Linux's qca6390 PHY values");
    }
    // WCN6855 family: fix_l1ss = false in every Linux hw_params entry.
    for rev in [
        HwRev::Wcn6855Hw20,
        HwRev::Wcn6855Hw21,
        HwRev::Qca2066Hw21,
        HwRev::Qca6698aqHw21,
    ] {
        match rev.params() {
            Some(p) if p.fix_l1ss.is_none() && !p.static_window_map => {}
            _ => return TestResult::Fail("WCN6855-family hw_params differ from Linux"),
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_fix_l1ss_programs_qca6390_phy
);

fn smoke_ath11k_msi_user_assignment() -> TestResult {
    // Linux ath11k_pcic_get_user_msi_assignment for WCN6855 HW2.1
    // with ep_base_data 64: user_base_data = base_vector + 64.
    let p = match HwRev::Wcn6855Hw21.params() {
        Some(p) => p,
        None => return TestResult::Fail("WCN6855 HW2.1 has no hw_params"),
    };
    if p.msi.total_vectors != 32 {
        return TestResult::Fail("WCN6855 must request 32 MSI vectors");
    }
    for (name, want) in [
        ("MHI", (3, 64, 0)),
        ("CE", (10, 67, 3)),
        ("WAKE", (1, 77, 13)),
        ("DP", (18, 78, 14)),
    ] {
        if p.msi.user_assignment(name, 64) != Some(want) {
            return TestResult::Fail("WCN6855 MSI user layout differs from Linux");
        }
    }
    if p.msi.user_assignment("BOGUS", 64).is_some() {
        return TestResult::Fail("unknown MSI user must not resolve");
    }
    // Single-vector fallback: every user on vector 0, MHI still 3.
    if MSI_CONFIG_ONE.user_assignment("CE", 50) != Some((1, 50, 0))
        || MSI_CONFIG_ONE.user_assignment("MHI", 50) != Some((3, 50, 0))
    {
        return TestResult::Fail("one-MSI fallback layout differs from Linux");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_msi_user_assignment);

// Suppress the unused-import warning when the `Vec` import isn't
// used by any helper above (compiler can't tell from the macro
// expansion).
#[allow(dead_code)]
fn _force_used() {
    let _: Vec<u8> = Vec::new();
}
