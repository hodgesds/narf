use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

fn smoke_tx_power_command_versions_and_units() -> TestResult {
    for (version, length) in [(10, 108), (11, 116)] {
        let command = station_api::tx_power(version, 17).unwrap();
        if command.len() != length
            || command[..8] != [0; 8]
            || command[8..10] != [136, 0]
            || command[10..].iter().any(|&b| b != 0)
        {
            return TestResult::Fail("TX power wire layout/units");
        }
        let negative = station_api::tx_power(version, -3).unwrap();
        if negative[8..10] != (-24i16).to_le_bytes() {
            return TestResult::Fail("negative TX power signed encoding");
        }
    }
    if station_api::tx_power(9, 17).is_ok() {
        return TestResult::Fail("unknown TX power layout accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_tx_power_command_versions_and_units
);

fn tlv(bytes: &mut Vec<u8>, tag: u32, payload: &[u8]) {
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize((bytes.len() + 3) & !3, 0);
}

fn image() -> Vec<u8> {
    let mut bytes = alloc::vec![0;88];
    bytes[4..8].copy_from_slice(&IWL_TLV_UCODE_MAGIC.to_le_bytes());
    tlv(&mut bytes, 52, &[1, 2, 3, 4]);
    tlv(&mut bytes, 48, &[1, 0, 99, 8, 0xd, 1, 18, 0]);
    tlv(&mut bytes, 30, &[1, 0, 0, 0, 1, 0, 0, 0]);
    tlv(&mut bytes, 23, &[0x11, 0x22, 0x33, 0x44]);
    tlv(&mut bytes, 22, &[0, 0, 0, 0, 0x12, 0, 0, 0, 0x34, 0, 0, 0]);
    tlv(&mut bytes, 24, &[0, 0x10, 0, 0, 1, 2, 3, 4]);
    tlv(&mut bytes, 24, &CPU1_CPU2_SEPARATOR.to_le_bytes());
    tlv(&mut bytes, 19, &[0, 0x20, 0, 0, 5, 6, 7, 8]);
    tlv(&mut bytes, 19, &PAGING_SEPARATOR.to_le_bytes());
    tlv(&mut bytes, 19, &[0, 0x30, 0, 0, 9, 10, 11, 12]);
    bytes
}

fn smoke_modern_firmware_metadata_and_sections() -> TestResult {
    let bytes = image();
    let fw = parse_ucode(&bytes).unwrap();
    if fw.api.iml != Some([1, 2, 3, 4].as_slice())
        || fw.api.versions(1, 0xd) != Some((18, 0))
        || !fw.api.has_capability(32)
        || fw.api.has_capability(256)
        || fw.api.phy_config != 0x44332211
        || fw.api.calibration != [0x12, 0x34]
    {
        return TestResult::Fail("firmware metadata was lost or misdecoded");
    }
    let map = boot_context::section_map(&fw).unwrap();
    if map != [(0, 636), (2, 124), (4, 1148)] {
        return TestResult::Fail("LMAC/UMAC/paging DMA map order");
    }
    let mut bad = fw.clone();
    bad.rt_sections.swap(0, 1);
    if boot_context::section_map(&bad).is_ok() {
        return TestResult::Fail("accepted leading CPU separator");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_modern_firmware_metadata_and_sections
);

fn smoke_modern_tlv_truncation_rejected() -> TestResult {
    let mut bytes = image();
    bytes.push(1);
    if parse_ucode(&bytes).is_ok() {
        return TestResult::Fail("short trailing TLV accepted");
    }
    let mut bytes = image();
    tlv(&mut bytes, 52, &[1]);
    bytes.pop();
    if parse_ucode(&bytes).is_ok() {
        return TestResult::Fail("missing TLV padding accepted");
    }
    let mut bytes = image();
    tlv(&mut bytes, 48, &[1, 2, 3]);
    if parse_ucode(&bytes).is_ok() {
        return TestResult::Fail("partial command version accepted");
    }
    let mut bytes = image();
    tlv(&mut bytes, 30, &[0; 7]);
    if parse_ucode(&bytes).is_ok() {
        return TestResult::Fail("partial capability accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_modern_tlv_truncation_rejected
);

fn smoke_boot_context_wire_units() -> TestResult {
    let q = boot_context::BootQueues {
        free: 0x123456789000,
        used: 0x23456789a000,
        status: 0x3456789ab000,
        command: 0x456789abc000,
        rx_depth: 512,
        command_depth: 128,
    };
    let out = boot_context::context(q, 0x56789abcd000, 0x6789abcde000).unwrap();
    if out.len() != 104
        || out[52..60] != q.command.to_le_bytes()
        || out[60..68] != q.used.to_le_bytes()
        || out[68..72] != [4, 0, 9, 0]
        || out[96..100] != 1660u32.to_le_bytes()
        || out[24..32] != 0x56789abcd800u64.to_le_bytes()
        || out[32..40] != 0x56789abcdc00u64.to_le_bytes()
    {
        return TestResult::Fail("context address/size units mismatch");
    }
    let scratch = boot_context::scratch(0x1234, q.free);
    if scratch.len() != 1724
        || scratch[4..6] != 431u16.to_le_bytes()
        || scratch[8..12] != 0x000f0000u32.to_le_bytes()
        || scratch[48..56] != q.free.to_le_bytes()
    {
        return TestResult::Fail("scratch header/RX free pointer mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_boot_context_wire_units
);

fn smoke_pnvm_selection_and_lengths() -> TestResult {
    let mut bytes = Vec::new();
    tlv(&mut bytes, 64, &[9; 12]);
    tlv(&mut bytes, 19, &[0, 0, 0, 0, 99]);
    tlv(&mut bytes, 64, &[1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0]);
    tlv(&mut bytes, 58, &[0x23, 1, 0x56, 4]);
    tlv(&mut bytes, 19, &[0, 0, 0, 0, 42]);
    tlv(&mut bytes, 19, &0xddddeeeeu32.to_le_bytes());
    tlv(&mut bytes, 7, &[0, 0, 0, 0, 2, 0, 0, 0, 43, 44]);
    let chunks = match pnvm::select(&bytes, [1, 2, 3], 0x123, 0x456) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("valid PNVM selection failed"),
    };
    if chunks != [vec![42].as_slice(), vec![43, 44].as_slice()] {
        return TestResult::Fail("PNVM mixed SKUs or consumed deprecated marker");
    }
    if pnvm::select(&bytes, [1, 2, 4], 0x123, 0x456).is_ok()
        || pnvm::select(&bytes, [1, 2, 3], 0x123, 0x457).is_ok()
    {
        return TestResult::Fail("PNVM accepted mismatched SKU/hardware");
    }
    bytes.pop();
    if pnvm::select(&bytes, [1, 2, 3], 0x123, 0x456).is_ok() {
        return TestResult::Fail("truncated PNVM accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_pnvm_selection_and_lengths
);

fn smoke_scan_nvm_and_band_numbering() -> TestResult {
    let mut nvm = vec![0; 468];
    nvm[12] = 3;
    nvm[16] = 3;
    nvm[24] = 110;
    nvm[28] = 1;
    nvm[28 + 14 * 4] = 1;
    let info = station_api::Nvm::parse(4, &nvm).unwrap();
    if info.channels != [1, 36] {
        return TestResult::Fail("NVM profile channel mapping");
    }
    let scan = scan_api::passive(18, 0, &info.channels).unwrap();
    if scan.len() != 1948
        || scan[45] != 2
        || scan[48..52] != (1u32 << 30).to_le_bytes()
        || scan[56..60] != [0; 4]
        || scan[52] != 1
        || scan[60] != 36
        || scan[594] != 1
    {
        return TestResult::Fail("scan v18 channel band/count/periodic encoding");
    }
    nvm[24] = 111;
    if station_api::Nvm::parse(4, &nvm).is_ok() || scan_api::passive(13, 0, &[1]).is_ok() {
        return TestResult::Fail("unsupported NVM/scan geometry accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_scan_nvm_and_band_numbering
);

fn smoke_frame_receive_padding_mic_and_replay() -> TestResult {
    let local = [2, 1, 2, 3, 4, 5];
    let ap = [2, 6, 7, 8, 9, 10];
    let mut bytes = vec![0; 64 + 50];
    bytes[0] = 50;
    bytes[2] = 0x20;
    bytes[3] = 0x20; // 4-byte trailer, 2-byte pad
    boot_context::put32(&mut bytes, 12, 0x243); // good CRC/overrun + CCM + MIC
    bytes[64] = 8;
    bytes[65] = 0x42; // data FromDS, protected
    bytes[68..74].copy_from_slice(&local);
    bytes[74..80].copy_from_slice(&ap);
    bytes[80..86].fill(0x12);
    bytes[88..96].copy_from_slice(&narf_wireless::ccmp::build_ccmp_header(5, 0));
    bytes[98..110].copy_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3, 4]);
    let mut replay = frame_api::Replay::default();
    let mut bad = bytes.clone();
    bad[12] &= !0x40;
    if frame_api::receive(&scan_api::mpdu(&bad).unwrap(), local, ap, true, &mut replay).is_some()
        || replay.pairwise[16] != 0
    {
        return TestResult::Fail("bad MIC advanced replay state");
    }
    let mpdu = scan_api::mpdu(&bytes).unwrap();
    let frame = frame_api::receive(&mpdu, local, ap, true, &mut replay).unwrap();
    if frame[..6] != local
        || frame[6..12] != [0x12; 6]
        || frame[12..] != [8, 0, 1, 2, 3, 4]
        || replay.pairwise[16] != 5
    {
        return TestResult::Fail("RX padding/IV/trailer or Ethernet conversion");
    }
    if frame_api::receive(&mpdu, local, ap, true, &mut replay).is_some() {
        return TestResult::Fail("CCMP replay accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_frame_receive_padding_mic_and_replay
);

fn smoke_frame_transmit_address_mapping() -> TestResult {
    let local = [2, 1, 2, 3, 4, 5];
    let ap = [2, 6, 7, 8, 9, 10];
    let mut ethernet = vec![0; 18];
    ethernet[..6].fill(0xff);
    ethernet[6..12].copy_from_slice(&local);
    ethernet[12..].copy_from_slice(&[8, 0, 1, 2, 3, 4]);
    let frame = frame_api::transmit(local, ap, 0x1234, &ethernet, true).unwrap();
    if frame[..2] != [8, 0x41]
        || frame[4..10] != ap
        || frame[10..16] != local
        || frame[16..22] != [0xff; 6]
        || frame[22..24] != [0x40, 0x23]
        || frame[24..] != [0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3, 4]
    {
        return TestResult::Fail("TX 802.11 mapping");
    }
    ethernet[6] ^= 1;
    if frame_api::transmit(local, ap, 0, &ethernet, false).is_some() {
        return TestResult::Fail("foreign Ethernet source accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/protocol",
    smoke_frame_transmit_address_mapping
);
