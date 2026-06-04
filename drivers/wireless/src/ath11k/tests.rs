//! ath11k smoke tests — co-located per project convention.
//!
//! Pure-data only: PCI match presence, hw_rev decode, MHI ring
//! arithmetic, WMI TLV round-trip, DP ring sizing. Live silicon
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
    if name_for(ATH11K_DEV_WCN7850) != "ath11k-wcn7850" {
        return TestResult::Fail("wcn7850 name mismatch");
    }
    if name_for(0xFFFF) != "ath11k" {
        return TestResult::Fail("default name mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_name_for_known_ids);

// ── ChipInfo decode ────────────────────────────────────────────────

fn smoke_ath11k_chip_for_pci_id_known_pairs() -> TestResult {
    let qca = chip_for_pci_id(QCOM_VENDOR, ATH11K_DEV_QCA6390).expect("qca6390");
    if qca.default_hw_rev != HwRev::Qca6390Hw20 {
        return TestResult::Fail("QCA6390 default hw_rev mismatch");
    }
    if qca.display_name != "QCA6390" {
        return TestResult::Fail("QCA6390 display_name mismatch");
    }
    let none = chip_for_pci_id(0x8086, 0x2723);
    if none.is_some() {
        return TestResult::Fail("Intel PCI id should not match ath11k");
    }
    let none2 = chip_for_pci_id(QCOM_VENDOR, 0x0000);
    if none2.is_some() {
        return TestResult::Fail("unknown Qualcomm device id should not match");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_chip_for_pci_id_known_pairs
);

fn smoke_ath11k_refine_hw_rev_wcn6855_subversions() -> TestResult {
    // WCN6855 2.0 stays WCN6855 2.0.
    if refine_hw_rev(ATH11K_DEV_WCN6855, 2, 0) != HwRev::Wcn6855Hw20 {
        return TestResult::Fail("WCN6855 major=2 minor=0 not classified as HW2.0");
    }
    // 2.1 → WCN6855 2.1.
    if refine_hw_rev(ATH11K_DEV_WCN6855, 2, 1) != HwRev::Wcn6855Hw21 {
        return TestResult::Fail("WCN6855 major=2 minor=1 not classified as HW2.1");
    }
    // 2.16+ → QCA2066 (the rebadged WCN6855 variant).
    if refine_hw_rev(ATH11K_DEV_WCN6855, 2, 0x12) != HwRev::Qca2066Hw21 {
        return TestResult::Fail("WCN6855 major=2 minor>=0x10 not classified as QCA2066");
    }
    // Unrelated PCI ID always falls through.
    if refine_hw_rev(0x9999, 0, 0) != HwRev::Unknown {
        return TestResult::Fail("unknown PCI id should produce HwRev::Unknown");
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
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_window_constants_consistent
);

// ── MHI ring arithmetic ────────────────────────────────────────────

fn smoke_ath11k_mhi_ring_push_pop_modular() -> TestResult {
    let mut r = MhiRing::new(8);
    if !r.is_empty() {
        return TestResult::Fail("freshly-allocated ring should be empty");
    }
    if r.is_full() {
        return TestResult::Fail("freshly-allocated ring should not be full");
    }
    // Push 7 (capacity - 1 since MHI reserves a slot).
    for i in 0..7 {
        if r.push(MhiTre::pack_data(0x1000 + i, 64, true, false, false, false))
            .is_none()
        {
            return TestResult::Fail("push under capacity rejected");
        }
    }
    if !r.is_full() {
        return TestResult::Fail("ring at capacity-1 not classified as full");
    }
    // One more push refused.
    if r.push(MhiTre::default()).is_some() {
        return TestResult::Fail("push past capacity should fail");
    }
    // Pop one + push one — verifies modular wrap behaviour.
    if r.pop().is_none() {
        return TestResult::Fail("pop on full ring should succeed");
    }
    if r.is_full() {
        return TestResult::Fail("ring shouldn't be full after one pop");
    }
    if r.push(MhiTre::default()).is_none() {
        return TestResult::Fail("push after pop should succeed");
    }
    if !r.is_full() {
        return TestResult::Fail("ring should be full again after push");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mhi_ring_push_pop_modular
);

fn smoke_ath11k_mhi_tre_pack_and_unpack() -> TestResult {
    let dma = 0x1234_5678_9ABC_DEF0u64;
    let tre = MhiTre::pack_data(dma, 0x0040, true, true, false, false);
    if tre.dma() != dma {
        return TestResult::Fail("dma round-trip wrong");
    }
    if tre.len() != 0x0040 {
        return TestResult::Fail("payload length wrong");
    }
    if tre.tre_type() != 0x02 {
        return TestResult::Fail("TRE type for data should be 0x02");
    }
    if !tre.ieot() || !tre.ieob() {
        return TestResult::Fail("IEOT/IEOB bits not honoured");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_mhi_tre_pack_and_unpack
);

fn smoke_ath11k_mhi_channel_tables() -> TestResult {
    // QCA6390 channel set: ch20/ch21 IPCR, 64 elements.
    let qca = channels_for_did(ATH11K_DEV_QCA6390);
    if qca.len() != 2 {
        return TestResult::Fail("QCA6390 channel count should be 2");
    }
    if qca[0].num != 20 || qca[1].num != 21 {
        return TestResult::Fail("QCA6390 channels should be 20/21");
    }
    if qca[0].num_elements != 64 {
        return TestResult::Fail("QCA6390 ch20 should have 64 elements");
    }
    // QCN9074 — same pair, 32 elements.
    let qcn = channels_for_did(ATH11K_DEV_QCN9074);
    if qcn[0].num_elements != 32 {
        return TestResult::Fail("QCN9074 ch20 should have 32 elements");
    }
    // WCN6855 falls back to QCA6390 layout.
    let wcn = channels_for_did(ATH11K_DEV_WCN6855);
    if wcn[0].num_elements != 64 {
        return TestResult::Fail("WCN6855 should share QCA6390 channel layout");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mhi_channel_tables);

fn smoke_ath11k_mhi_doorbell_offsets() -> TestResult {
    if ch_doorbell_offset(0) != MHI_CHDB_BASE {
        return TestResult::Fail("ch0 doorbell should be at MHI_CHDB_BASE");
    }
    if ch_doorbell_offset(20) != MHI_CHDB_BASE + 20 * 8 {
        return TestResult::Fail("ch20 doorbell offset wrong");
    }
    if er_doorbell_offset(1) != MHI_ERDB_BASE + 8 {
        return TestResult::Fail("er1 doorbell offset wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mhi_doorbell_offsets);

fn smoke_ath11k_mhi_exec_env_decode() -> TestResult {
    if MhiExecEnv::from_raw(0) != MhiExecEnv::Pbl {
        return TestResult::Fail("raw 0 should decode to Pbl");
    }
    if MhiExecEnv::from_raw(2) != MhiExecEnv::Amss {
        return TestResult::Fail("raw 2 should decode to Amss");
    }
    if MhiExecEnv::from_raw(0xff) != MhiExecEnv::Disabled {
        return TestResult::Fail("raw 0xff should decode to Disabled");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_mhi_exec_env_decode);

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

// Suppress the unused-import warning when the `Vec` import isn't
// used by any helper above (compiler can't tell from the macro
// expansion).
#[allow(dead_code)]
fn _force_used() {
    let _: Vec<u8> = Vec::new();
}
