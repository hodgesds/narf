//! i40e smokes.
//!
//! The 700-series bring-up is almost entirely firmware dialogue, so
//! what is checkable without silicon is the wire format: descriptor
//! layout, flag and opcode values, register offsets, and the
//! response decoders. Those are exactly the places a transcription
//! error from `i40e_register.h` / `libie/adminq.h` would hide.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    desc_buf_addr, is_supported_device, mac_is_invalid, name_for, set_desc_buf_addr, AqDesc,
    AqError, AqOpcode, FirmwareVersion, LinkSpeed, LinkStatus, MacAddresses, AQC_LARGE_BUF_CHECK,
    AQLEN_ENABLE, AQ_BUF_BYTES, AQ_FLAG_BUF, AQ_FLAG_DD, AQ_FLAG_ERR, AQ_FLAG_LB, AQ_FLAG_RD,
    AQ_RING_BYTES, AQ_RING_LEN, GLNVM_ULD_READY, I40E_DEV_SFP_XL710, I40E_VENDOR,
    LINK_INFO_LINK_UP, LINK_INFO_MEDIA_AVAILABLE, MAC_ADDR_LAN_VALID, PFGEN_CTRL_PFSWR,
    REG_GLGEN_RSTAT, REG_GLNVM_ULD, REG_PFGEN_CTRL, REG_PF_ARQBAL, REG_PF_ARQT, REG_PF_ATQBAH,
    REG_PF_ATQBAL, REG_PF_ATQH, REG_PF_ATQLEN, REG_PF_ATQT, SUPPORTED_DEVICE_IDS,
};

// ── PCI match table ──────────────────────────────────────────────────

fn smoke_i40e_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    for did in SUPPORTED_DEVICE_IDS.iter().copied() {
        let matched = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: I40E_VENDOR, device,
            } if device == did)
        });
        if !matched {
            return TestResult::Fail("i40e PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_pci_match_table);

fn smoke_i40e_claims_ms03_x710() -> TestResult {
    // The MS-03 carries a dual-port X710 for 10GbE SFP+ reporting
    // 8086:1572 at 59:00.0 and 59:00.1.
    if !is_supported_device(I40E_DEV_SFP_XL710) {
        return TestResult::Fail("i40e does not claim 8086:1572");
    }
    if name_for(I40E_DEV_SFP_XL710) != "i40e-x710-sfp" {
        return TestResult::Fail("X710 SFP+ SKU name wrong");
    }
    if is_supported_device(0x125B) {
        return TestResult::Fail("i40e claimed an igc device id");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_claims_ms03_x710);

// ── Admin Queue descriptor wire format ───────────────────────────────

fn smoke_i40e_aq_desc_layout() -> TestResult {
    // `LIBIE_CHECK_STRUCT_LEN(32, libie_aq_desc)`.
    if core::mem::size_of::<AqDesc>() != 32 {
        return TestResult::Fail("AqDesc is not 32 bytes");
    }
    // A ring of AQ_RING_LEN descriptors must be a whole number of
    // descriptors and fit the 10-bit length field.
    if AQ_RING_BYTES != AQ_RING_LEN as usize * 32 {
        return TestResult::Fail("AQ_RING_BYTES disagrees with AQ_RING_LEN");
    }
    if AQ_RING_LEN == 0 || AQ_RING_LEN > 1023 {
        return TestResult::Fail("AQ ring length does not fit ATQLEN[9:0]");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_aq_desc_layout);

fn smoke_i40e_aq_flag_bits() -> TestResult {
    // `LIBIE_AQ_FLAG_*` — getting DD or ERR wrong would make every
    // command look complete, or every completion look like a failure.
    if AQ_FLAG_DD != 0x0001 {
        return TestResult::Fail("AQ_FLAG_DD wrong");
    }
    if AQ_FLAG_ERR != 0x0004 {
        return TestResult::Fail("AQ_FLAG_ERR wrong");
    }
    if AQ_FLAG_LB != 0x0200 {
        return TestResult::Fail("AQ_FLAG_LB wrong");
    }
    if AQ_FLAG_RD != 0x0400 {
        return TestResult::Fail("AQ_FLAG_RD wrong");
    }
    if AQ_FLAG_BUF != 0x1000 {
        return TestResult::Fail("AQ_FLAG_BUF wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_aq_flag_bits);

fn smoke_i40e_aq_opcodes() -> TestResult {
    if AqOpcode::GetVersion as u16 != 0x0001 {
        return TestResult::Fail("get_version opcode wrong");
    }
    if AqOpcode::DriverVersion as u16 != 0x0002 {
        return TestResult::Fail("driver_version opcode wrong");
    }
    if AqOpcode::QueueShutdown as u16 != 0x0003 {
        return TestResult::Fail("queue_shutdown opcode wrong");
    }
    if AqOpcode::MacAddressRead as u16 != 0x0107 {
        return TestResult::Fail("mac_address_read opcode wrong");
    }
    if AqOpcode::ClearPxeMode as u16 != 0x0110 {
        return TestResult::Fail("clear_pxe_mode opcode wrong");
    }
    if AqOpcode::GetLinkStatus as u16 != 0x0607 {
        return TestResult::Fail("get_link_status opcode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_aq_opcodes);

fn smoke_i40e_desc_buf_addr_round_trip() -> TestResult {
    // An indirect command's buffer address goes in the last eight
    // bytes of params as addr_high then addr_low, both little-endian.
    let mut d = AqDesc::default();
    let phys = 0x0000_1234_ABCD_E000u64;
    set_desc_buf_addr(&mut d, phys);
    if desc_buf_addr(&d) != phys {
        return TestResult::Fail("buffer address did not round-trip");
    }
    // addr_high occupies params[8..12].
    if d.params[8..12] != 0x0000_1234u32.to_le_bytes() {
        return TestResult::Fail("addr_high landed in the wrong slot");
    }
    if d.params[12..16] != 0xABCD_E000u32.to_le_bytes() {
        return TestResult::Fail("addr_low landed in the wrong slot");
    }
    // The first eight bytes are command parameters and must be
    // untouched.
    if d.params[0..8] != [0u8; 8] {
        return TestResult::Fail("set_desc_buf_addr clobbered command params");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_desc_buf_addr_round_trip);

// ── Register offsets ─────────────────────────────────────────────────

fn smoke_i40e_register_offsets() -> TestResult {
    // Straight from `i40e_register.h`. The ATQ/ARQ blocks are
    // interleaved at 0x80 strides, which is easy to transpose.
    if REG_PF_ATQBAL != 0x0008_0000 || REG_PF_ATQBAH != 0x0008_0100 {
        return TestResult::Fail("ATQ base registers wrong");
    }
    if REG_PF_ATQLEN != 0x0008_0200 || REG_PF_ATQH != 0x0008_0300 || REG_PF_ATQT != 0x0008_0400 {
        return TestResult::Fail("ATQ len/head/tail registers wrong");
    }
    if REG_PF_ARQBAL != 0x0008_0080 || REG_PF_ARQT != 0x0008_0480 {
        return TestResult::Fail("ARQ registers wrong");
    }
    if REG_PFGEN_CTRL != 0x0009_2400 || PFGEN_CTRL_PFSWR != 1 {
        return TestResult::Fail("PFGEN_CTRL wrong");
    }
    if REG_GLGEN_RSTAT != 0x000B_8188 || REG_GLNVM_ULD != 0x000B_6008 {
        return TestResult::Fail("reset-status registers wrong");
    }
    if GLNVM_ULD_READY != (1 << 3 | 1 << 4) {
        return TestResult::Fail("GLNVM_ULD ready mask wrong");
    }
    if AQLEN_ENABLE != 1 << 31 {
        return TestResult::Fail("AQLEN enable bit wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_register_offsets);

// ── Response decoders ────────────────────────────────────────────────

fn smoke_i40e_get_version_decode() -> TestResult {
    // struct libie_aqc_get_ver: rom_ver:le32, fw_build:le32,
    // fw_branch:u8, fw_major:u8, fw_minor:u8, fw_patch:u8,
    // api_branch:u8, api_major:u8, api_minor:u8, api_patch:u8.
    let mut p = [0u8; 16];
    p[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    p[4..8].copy_from_slice(&0x0000_1234u32.to_le_bytes());
    p[8] = 0; // fw_branch
    p[9] = 9; // fw_major
    p[10] = 5; // fw_minor
    p[11] = 0; // fw_patch
    p[12] = 0; // api_branch
    p[13] = 1; // api_major
    p[14] = 15; // api_minor
    let v = FirmwareVersion::parse(&p);
    if v.rom_version != 0xDEAD_BEEF || v.fw_build != 0x1234 {
        return TestResult::Fail("rom/build decoded wrong");
    }
    if v.fw_major != 9 || v.fw_minor != 5 {
        return TestResult::Fail("firmware version decoded wrong");
    }
    if v.api_major != 1 || v.api_minor != 15 {
        return TestResult::Fail("API version decoded wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_get_version_decode);

fn smoke_i40e_link_status_decode() -> TestResult {
    // struct i40e_aqc_get_link_status: command_flags:le16,
    // phy_type:u8, link_speed:u8, link_info:u8, ...
    let mut p = [0u8; 16];
    p[2] = 0x07; // phy_type
    p[3] = 1 << 3; // I40E_LINK_SPEED_10GB
    p[4] = LINK_INFO_LINK_UP | LINK_INFO_MEDIA_AVAILABLE;
    p[8..10].copy_from_slice(&9728u16.to_le_bytes());
    let s = LinkStatus::parse(&p);
    if !s.link_up || !s.media_available {
        return TestResult::Fail("link_info decoded wrong");
    }
    if s.speed() != LinkSpeed::Speed10Gb || s.speed().label() != "10G" {
        return TestResult::Fail("10G speed decoded wrong");
    }
    if s.max_frame_size != 9728 {
        return TestResult::Fail("max_frame_size decoded wrong");
    }

    // An SFP+ cage with no module: PF healthy, link down, no media.
    let mut empty = [0u8; 16];
    empty[4] = 0;
    let s2 = LinkStatus::parse(&empty);
    if s2.link_up || s2.media_available {
        return TestResult::Fail("empty cage should read down with no media");
    }
    if s2.speed() != LinkSpeed::Unknown {
        return TestResult::Fail("no speed bits should decode to Unknown");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_link_status_decode);

fn smoke_i40e_link_speed_is_a_bitmask_not_an_ordinal() -> TestResult {
    // `enum i40e_aq_link_speed` is one-hot and its shifts are not in
    // speed order — 2.5G is bit 0 and 5G is bit 7. Reading the byte
    // as an ordinal would silently mislabel every link.
    if LinkSpeed::from_byte(1 << 0) != LinkSpeed::Speed2_5Gb {
        return TestResult::Fail("bit 0 is 2.5G, not 100M");
    }
    if LinkSpeed::from_byte(1 << 1) != LinkSpeed::Speed100Mb {
        return TestResult::Fail("bit 1 is 100M");
    }
    if LinkSpeed::from_byte(1 << 2) != LinkSpeed::Speed1Gb {
        return TestResult::Fail("bit 2 is 1G");
    }
    if LinkSpeed::from_byte(1 << 4) != LinkSpeed::Speed40Gb {
        return TestResult::Fail("bit 4 is 40G");
    }
    if LinkSpeed::from_byte(1 << 7) != LinkSpeed::Speed5Gb {
        return TestResult::Fail("bit 7 is 5G, not the fastest rate");
    }
    if LinkSpeed::from_byte(0) != LinkSpeed::Unknown {
        return TestResult::Fail("zero must decode to Unknown");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/i40e",
    smoke_i40e_link_speed_is_a_bitmask_not_an_ordinal
);

fn smoke_i40e_mac_address_decode() -> TestResult {
    // struct i40e_aqc_mac_address_read_data — four 6-byte addresses,
    // PF LAN first.
    let mut buf = [0u8; 24];
    buf[0..6].copy_from_slice(&[0x3C, 0xFD, 0xFE, 0x01, 0x02, 0x03]);
    buf[12..18].copy_from_slice(&[0x3C, 0xFD, 0xFE, 0x0A, 0x0B, 0x0C]);
    let m = match MacAddresses::parse(&buf) {
        Some(m) => m,
        None => return TestResult::Fail("24-byte buffer rejected"),
    };
    if m.pf_lan != [0x3C, 0xFD, 0xFE, 0x01, 0x02, 0x03] {
        return TestResult::Fail("PF LAN MAC decoded wrong");
    }
    if m.port != [0x3C, 0xFD, 0xFE, 0x0A, 0x0B, 0x0C] {
        return TestResult::Fail("port MAC decoded wrong");
    }
    if MacAddresses::parse(&buf[..23]).is_some() {
        return TestResult::Fail("short buffer accepted");
    }
    if MAC_ADDR_LAN_VALID != 0x10 {
        return TestResult::Fail("I40E_AQC_LAN_ADDR_VALID wrong");
    }
    if !mac_is_invalid([0; 6]) || !mac_is_invalid([0xFF; 6]) {
        return TestResult::Fail("sentinel MACs must be rejected");
    }
    if mac_is_invalid([0x3C, 0xFD, 0xFE, 0x01, 0x02, 0x03]) {
        return TestResult::Fail("a real MAC was rejected");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_mac_address_decode);

fn smoke_i40e_aq_error_decode() -> TestResult {
    if !AqError::from_retval(0).is_ok() {
        return TestResult::Fail("retval 0 is not OK");
    }
    if AqError::from_retval(3) != AqError::Esrch {
        return TestResult::Fail("retval 3 is ESRCH (bad opcode)");
    }
    if AqError::from_retval(14) != AqError::Einval {
        return TestResult::Fail("retval 14 is EINVAL");
    }
    if AqError::from_retval(21) != AqError::Emode {
        return TestResult::Fail("retval 21 is EMODE");
    }
    // An unnamed code must survive rather than be flattened to OK.
    match AqError::from_retval(99) {
        AqError::Other(99) => {}
        _ => return TestResult::Fail("unknown retval was not preserved"),
    }
    if AqError::from_retval(99).is_ok() {
        return TestResult::Fail("unknown retval must not read as success");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_aq_error_decode);

fn smoke_i40e_aq_buffer_sizing() -> TestResult {
    // `LIBIE_AQ_LG_BUF` is 512: a buffer larger than that needs the
    // LB flag set alongside BUF.
    if AQC_LARGE_BUF_CHECK != 512 {
        return TestResult::Fail("large-buffer threshold wrong");
    }
    if AQ_BUF_BYTES <= AQC_LARGE_BUF_CHECK as usize {
        return TestResult::Fail("per-slot buffer should exceed the LB threshold");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_aq_buffer_sizing);
