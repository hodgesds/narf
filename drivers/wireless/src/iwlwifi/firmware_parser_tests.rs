//! Authored TLV inputs. No vendor image, extracted metadata or device loading.
use super::*;
use alloc::vec;
use narf_kernel_test::{kernel_test_in, TestResult};

// Deliberately small command inventories for the native protocol models.
// Each row is opcode, group, command version, response version (fw/file.h).
const MVM_COMMANDS: &[[u8; 4]] = &[
    [0x18, 1, 12, 2], // disabled peer ADD
    [0x19, 1, 2, 0],  // peer REMOVE
    [0x17, 5, 3, 2],  // queue configuration
    [0x9f, 1, 5, 0],  // transmit power
    [0xd, 1, 15, 0],  // passive scan prerequisite
    [0xc, 1, 5, 0],   // reduced scan configuration
    [8, 3, 1, 0],     // inactive MAC prerequisite
    [0xd2, 1, 4, 0],  // beacon filter
    [0xd1, 1, 3, 0],  // smart FIFO
    [0xa9, 1, 1, 0],  // MAC power
    [0xc8, 1, 1, 3],  // MCC response used by the Gen2 model
];
const MLD_COMMANDS: &[[u8; 4]] = &[
    [8, 3, 3, 0],     // MAC
    [9, 3, 8, 0],     // LINK
    [10, 3, 2, 0],    // STA
    [8, 1, 6, 0],     // PHY
    [0x17, 5, 3, 2],  // queue configuration
    [0x16, 5, 2, 0],  // TX flush
    [0x18, 5, 1, 0],  // key configuration
    [0xc, 1, 5, 0],   // antenna configuration
    [2, 0xc, 1, 4],   // NVM
    [0x9b, 1, 6, 0],  // coexistence
    [1, 2, 2, 0],     // SoC configuration
    [0x77, 1, 7, 0],  // device power
    [0x98, 1, 1, 0],  // NVM chain
    [0x9f, 1, 10, 0], // transmit power
    [0xf, 5, 6, 0],   // TLC v6, the 44-byte rate configuration contract
    [0xc, 3, 1, 0],   // STA removal
    [5, 3, 3, 0],     // association
    [0xd, 1, 18, 0],  // scan
    [0xc5, 0, 0, 7],  // receive notification
    [0xc8, 1, 1, 8],  // MCC response used by the MLD model
];

fn tlv(bytes: &mut Vec<u8>, tag: u32, payload: &[u8]) {
    bytes.extend_from_slice(&tag.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
}
fn image(commands: &[[u8; 4]]) -> Vec<u8> {
    let mut bytes = vec![0; 88];
    bytes[4..8].copy_from_slice(&0x0a4c_5749u32.to_le_bytes());
    bytes[8..24].copy_from_slice(b"rust-parser-test");
    bytes[72..76].copy_from_slice(&0x0102_0304u32.to_le_bytes());
    bytes[76..80].copy_from_slice(&9u32.to_le_bytes());
    tlv(&mut bytes, 48, &commands.concat());
    tlv(&mut bytes, 29, &[1, 0, 0, 0, 0, 0x20, 0, 0]);
    bytes
}
pub(super) fn mvm_image() -> Vec<u8> {
    let mut bytes = image(MVM_COMMANDS);
    // Legacy header API occupies bits8..15; display-version TLVs are unrelated.
    bytes[72..76].copy_from_slice(&0x0102_4d04u32.to_le_bytes());
    // Select reduced scan configuration, beacon-filter v4 and MLD MAC in
    // the model. LAR remains an explicit per-test choice, never a default.
    tlv(&mut bytes, 29, &[1, 0, 0, 0, 0, 0x80, 0, 1]);
    tlv(&mut bytes, 30, &[3, 0, 0, 0, 0, 0x40, 0, 0]);
    bytes
}
pub(super) fn mld_commands() -> Vec<u8> {
    // Exercise the production TLV decoder before supplying the model table.
    let bytes = image(MLD_COMMANDS);
    parse_ucode(&bytes).unwrap().api.commands.to_vec()
}

pub(super) fn mld_image() -> Vec<u8> {
    image(MLD_COMMANDS)
}

fn smoke_iwlwifi_authored_tlv_sections_and_first_command_version() -> TestResult {
    let mut bytes = image(&[[0xd, 1, 18, 0], [0xd, 1, 29, 4]]);
    tlv(&mut bytes, 27, &2u32.to_le_bytes());
    tlv(&mut bytes, 36, &[3, 0, 0, 0, 5, 0, 0, 0, 77, 0, 0, 0]);
    tlv(&mut bytes, 30, &[7, 0, 0, 0, 0, 0, 0, 0x80]);
    tlv(&mut bytes, 22, &[0, 0, 0, 0, 0x12, 0, 0, 0, 0x34, 0, 0, 0]);
    tlv(&mut bytes, 23, &[0x11, 0x22, 0x33, 0x44]);
    tlv(&mut bytes, 52, &[0xa1, 0xa2, 0xa3]);
    tlv(&mut bytes, 74, &[0xb1, 0xb2]);
    tlv(&mut bytes, 24, &[0, 0x10, 0, 0, 1, 2, 3]);
    tlv(&mut bytes, 19, &CPU1_CPU2_SEPARATOR.to_le_bytes());
    tlv(&mut bytes, 20, &[0, 0x20, 0, 0, 4, 5]);
    let parsed = parse_ucode(&bytes).unwrap();
    if parsed.header.version != 0x0102_0304
        || parsed.header.build != 9
        || parsed.header.human_readable != "rust-parser-test"
        || parsed.num_of_cpu != 2
        || parsed.fw_version != Some((3, 5, 77))
        || parsed.api.versions(1, 0xd) != Some((18, 0))
        || parsed.api.versions(3, 0xd).is_some()
        || !parsed.api.has_capability(255)
        || parsed.api.has_capability(256)
        || parsed.api.api_changes[1] != 1 << 13
        || parsed.api.calibration != [0x12, 0x34]
        || parsed.api.phy_config != 0x4433_2211
        || parsed.api.iml != Some(&[0xa1, 0xa2, 0xa3][..])
        || parsed.api.pnvm != Some(&[0xb1, 0xb2][..])
        || parsed.rt_sections.len() != 2
        || parsed.rt_sections[0].dest_offset != 0x1000
        || parsed.rt_sections[0].payload != [1, 2, 3]
        || parsed.rt_sections[1].dest_offset != CPU1_CPU2_SEPARATOR
        || !parsed.rt_sections[1].payload.is_empty()
        || parsed.init_sections.len() != 1
        || parsed.init_sections[0].dest_offset != 0x2000
        || parsed.init_sections[0].payload != [4, 5]
    {
        return TestResult::Fail("authored TLV fields, sections or first-match command lookup");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi",
    smoke_iwlwifi_authored_tlv_sections_and_first_command_version
);

fn smoke_iwlwifi_authored_tlv_truncation_and_invalid_shapes() -> TestResult {
    let mut bytes = mvm_image();
    tlv(&mut bytes, 52, &[1, 2, 3]);
    for end in [0, 87, bytes.len() - 4, bytes.len() - 2, bytes.len() - 1] {
        if parse_ucode(&bytes[..end]).is_ok() {
            return TestResult::Fail("truncated TLV header, payload or padding admitted");
        }
    }
    for (tag, payload) in [(48, &[1, 2, 3][..]), (30, &[0; 7][..]), (52, &[][..])] {
        let mut bad = mvm_image();
        tlv(&mut bad, tag, payload);
        if parse_ucode(&bad).is_ok() {
            return TestResult::Fail("malformed known firmware API record admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi",
    smoke_iwlwifi_authored_tlv_truncation_and_invalid_shapes
);
