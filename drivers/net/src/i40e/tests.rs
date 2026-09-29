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

// ── HMC: FPM sizing ──────────────────────────────────────────────────

fn smoke_i40e_hmc_fpm_layout() -> TestResult {
    use super::hmc::{align_l2obj_base, calculate_l2fpm_size, OBJ_SIZE_RXQ, OBJ_SIZE_TXQ};
    if OBJ_SIZE_TXQ != 128 || OBJ_SIZE_RXQ != 32 {
        return TestResult::Fail("LAN object sizes wrong");
    }
    if align_l2obj_base(0) != 0 || align_l2obj_base(1) != 512 || align_l2obj_base(512) != 512 {
        return TestResult::Fail("512-byte alignment wrong");
    }
    // One TX + one RX queue: 128 -> pad to 512, + 32 -> pad to 1024,
    // then two more zero-count classes that only contribute padding.
    if calculate_l2fpm_size(1, 1, 0, 0) != 1024 {
        return TestResult::Fail("one queue pair should need 1024 FPM bytes");
    }
    // Four TX queues fill 512 exactly, so the RX class starts right
    // after with no extra pad.
    if calculate_l2fpm_size(4, 1, 0, 0) != 1024 {
        return TestResult::Fail("4 TX queues should fill the first 512-byte block exactly");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_hmc_fpm_layout);

fn smoke_i40e_hmc_base_register_is_in_512_byte_units() -> TestResult {
    use super::hmc::fpm_base_to_reg;
    // GLHMC_LAN*BASE holds the FPM offset divided by 512. Writing a
    // byte offset points the device 512x too far into FPM, which
    // reads back as an all-zero context.
    if fpm_base_to_reg(0) != 0 {
        return TestResult::Fail("base 0 should encode as 0");
    }
    if fpm_base_to_reg(512) != 1 {
        return TestResult::Fail("base 512 should encode as 1, not 512");
    }
    if fpm_base_to_reg(1024) != 2 {
        return TestResult::Fail("base 1024 should encode as 2");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/i40e",
    smoke_i40e_hmc_base_register_is_in_512_byte_units
);

// ── HMC: context bit packing ─────────────────────────────────────────

fn smoke_i40e_ctx_field_round_trip() -> TestResult {
    use super::hmc::{read_ctx_field, write_ctx_field, CtxField, OBJ_SIZE_TXQ};
    let mut ctx = [0u8; OBJ_SIZE_TXQ as usize];

    // A field that straddles a byte boundary and is not byte-aligned:
    // `qlen`, 13 bits at bit 161.
    let qlen = CtxField {
        name: "qlen",
        lsb: 161,
        width: 13,
    };
    write_ctx_field(&mut ctx, qlen, 64);
    if read_ctx_field(&ctx, qlen) != 64 {
        return TestResult::Fail("13-bit unaligned field did not round-trip");
    }
    // Byte 20 holds bits 160..167, so a value of 64 shifted up one
    // bit lands as 0x80.
    if ctx[20] != 0x80 {
        return TestResult::Fail("qlen did not land at bit 161");
    }

    // A 64-bit field must not be truncated by the width mask.
    let wb = CtxField {
        name: "head_wb_addr",
        lsb: 192,
        width: 64,
    };
    let addr = 0xDEAD_BEEF_CAFE_F000u64;
    write_ctx_field(&mut ctx, wb, addr);
    if read_ctx_field(&ctx, wb) != addr {
        return TestResult::Fail("64-bit field did not round-trip");
    }

    // A 57-bit field must drop the top bits rather than smear into
    // its neighbour.
    let mut ctx2 = [0u8; OBJ_SIZE_TXQ as usize];
    let base = CtxField {
        name: "base",
        lsb: 32,
        width: 57,
    };
    write_ctx_field(&mut ctx2, base, u64::MAX);
    if read_ctx_field(&ctx2, base) != (1u64 << 57) - 1 {
        return TestResult::Fail("57-bit field was not truncated to its width");
    }
    // `fc_ena` sits at bit 89, immediately above `base`. It must
    // still be clear.
    let fc = CtxField {
        name: "fc_ena",
        lsb: 89,
        width: 1,
    };
    if read_ctx_field(&ctx2, fc) != 0 {
        return TestResult::Fail("an over-wide value bled into the next field");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_ctx_field_round_trip);

fn smoke_i40e_ctx_tables_are_disjoint() -> TestResult {
    use super::hmc::{
        table_is_disjoint, OBJ_SIZE_RXQ, OBJ_SIZE_TXQ, RXQ_CTX_FIELDS, TXQ_CTX_FIELDS,
    };
    // Overlapping entries would corrupt a neighbouring field on every
    // write, and a field past the end would be silently dropped.
    if !table_is_disjoint(TXQ_CTX_FIELDS, OBJ_SIZE_TXQ) {
        return TestResult::Fail("TX context table overlaps or overruns");
    }
    if !table_is_disjoint(RXQ_CTX_FIELDS, OBJ_SIZE_RXQ) {
        return TestResult::Fail("RX context table overlaps or overruns");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_ctx_tables_are_disjoint);

fn smoke_i40e_ctx_line_offsets() -> TestResult {
    use super::hmc::{ctx_field, RXQ_CTX_FIELDS, TXQ_CTX_FIELDS};
    // Linux writes these offsets as `33 + 128` and `84 + (7 * 128)`
    // because the context is addressed in 128-bit lines. The
    // pre-computed absolute bit positions have to match.
    let qlen = match ctx_field(TXQ_CTX_FIELDS, "qlen") {
        Some(f) => f,
        None => return TestResult::Fail("TX qlen field missing"),
    };
    if qlen.lsb != 161 || qlen.width != 13 {
        return TestResult::Fail("TX qlen is 13 bits at 33 + 128");
    }
    let rdylist = match ctx_field(TXQ_CTX_FIELDS, "rdylist") {
        Some(f) => f,
        None => return TestResult::Fail("TX rdylist field missing"),
    };
    if rdylist.lsb != 980 || rdylist.width != 10 {
        return TestResult::Fail("TX rdylist is 10 bits at 84 + 7*128");
    }
    let crc = match ctx_field(TXQ_CTX_FIELDS, "crc") {
        Some(f) => f,
        None => return TestResult::Fail("TX crc field missing"),
    };
    if crc.lsb != 896 {
        return TestResult::Fail("TX crc starts line 7 at bit 896");
    }
    // RX has no line offsets, but `rxmax` at 174 is a common typo
    // target (the field before it ends at 128).
    let rxmax = match ctx_field(RXQ_CTX_FIELDS, "rxmax") {
        Some(f) => f,
        None => return TestResult::Fail("RX rxmax field missing"),
    };
    if rxmax.lsb != 174 || rxmax.width != 14 {
        return TestResult::Fail("RX rxmax is 14 bits at 174");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_ctx_line_offsets);

// ── Queue contexts ───────────────────────────────────────────────────

fn smoke_i40e_tx_context_base_is_in_128_byte_units() -> TestResult {
    use super::hmc::{ctx_field, read_ctx_field, TXQ_CTX_FIELDS};
    use super::ring::{pack_tx_context, TxQueueContext};
    let ring_phys = 0x0000_0001_2340_0000u64;
    let ctx = pack_tx_context(TxQueueContext {
        ring_phys,
        qlen: 64,
        head_wb_phys: ring_phys + 1024,
        rdylist: 0x123,
    });
    let base = match ctx_field(TXQ_CTX_FIELDS, "base") {
        Some(f) => f,
        None => return TestResult::Fail("base field missing"),
    };
    // The context stores the address divided by 128. Storing the raw
    // address would point the device 128x too far into memory.
    if read_ctx_field(&ctx, base) != ring_phys / 128 {
        return TestResult::Fail("TX context base is not the address / 128");
    }
    // head_wb_addr, by contrast, is a whole 64-bit address.
    let wb = match ctx_field(TXQ_CTX_FIELDS, "head_wb_addr") {
        Some(f) => f,
        None => return TestResult::Fail("head_wb_addr field missing"),
    };
    if read_ctx_field(&ctx, wb) != ring_phys + 1024 {
        return TestResult::Fail("head_wb_addr must be a whole address, not divided");
    }
    let qlen = match ctx_field(TXQ_CTX_FIELDS, "qlen") {
        Some(f) => f,
        None => return TestResult::Fail("qlen field missing"),
    };
    if read_ctx_field(&ctx, qlen) != 64 {
        return TestResult::Fail("qlen wrong");
    }
    let rdylist = match ctx_field(TXQ_CTX_FIELDS, "rdylist") {
        Some(f) => f,
        None => return TestResult::Fail("rdylist field missing"),
    };
    if read_ctx_field(&ctx, rdylist) != 0x123 {
        return TestResult::Fail("rdylist must carry the VSI's qs_handle");
    }
    let new_ctx = match ctx_field(TXQ_CTX_FIELDS, "new_context") {
        Some(f) => f,
        None => return TestResult::Fail("new_context field missing"),
    };
    if read_ctx_field(&ctx, new_ctx) != 1 {
        return TestResult::Fail("new_context must be set");
    }
    let wb_ena = match ctx_field(TXQ_CTX_FIELDS, "head_wb_ena") {
        Some(f) => f,
        None => return TestResult::Fail("head_wb_ena field missing"),
    };
    if read_ctx_field(&ctx, wb_ena) != 1 {
        return TestResult::Fail("head writeback must be enabled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/i40e",
    smoke_i40e_tx_context_base_is_in_128_byte_units
);

fn smoke_i40e_rx_context_units() -> TestResult {
    use super::hmc::{ctx_field, read_ctx_field, RXQ_CTX_FIELDS};
    use super::ring::{pack_rx_context, RxQueueContext, RX_BUF_BYTES, RX_MAX_FRAME};
    let ring_phys = 0x0000_0002_4680_0000u64;
    let ctx = pack_rx_context(RxQueueContext {
        ring_phys,
        qlen: 64,
        buf_bytes: RX_BUF_BYTES as u16,
        max_frame: RX_MAX_FRAME,
    });
    let get = |name: &str| ctx_field(RXQ_CTX_FIELDS, name).map(|f| read_ctx_field(&ctx, f));

    if get("base") != Some(ring_phys / 128) {
        return TestResult::Fail("RX context base is not the address / 128");
    }
    // dbuff counts 128-byte units too: a 2 KiB buffer is 16.
    if get("dbuff") != Some(16) {
        return TestResult::Fail("dbuff must be the buffer size / 128");
    }
    if get("qlen") != Some(64) {
        return TestResult::Fail("RX qlen wrong");
    }
    if get("rxmax") != Some(RX_MAX_FRAME as u64) {
        return TestResult::Fail("rxmax wrong");
    }
    // dsize 0 selects 16-byte descriptors, which is the format the
    // ring code reads back.
    if get("dsize") != Some(0) {
        return TestResult::Fail("dsize must be 0 for 16-byte descriptors");
    }
    if get("crcstrip") != Some(1) {
        return TestResult::Fail("CRC strip should be on");
    }
    // The datasheet requires both of these at init.
    if get("prefena") != Some(1) {
        return TestResult::Fail("prefena must be set at init");
    }
    if get("lrxqthresh") != Some(1) {
        return TestResult::Fail("lrxqthresh must be at least 1");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_rx_context_units);

// ── Descriptors ──────────────────────────────────────────────────────

fn smoke_i40e_tx_descriptor_encoding() -> TestResult {
    use super::ring::{
        build_tx_desc, TXD_QW1_CMD_SHIFT, TXD_QW1_TX_BUF_SZ_SHIFT, TX_DESC_CMD_EOP,
        TX_DESC_CMD_ICRC, TX_DESC_CMD_RS, TX_DESC_DTYPE_DATA,
    };
    let (addr, qw1) = build_tx_desc(0x1234_5678_9ABC_D000, 128);
    if addr != 0x1234_5678_9ABC_D000 {
        return TestResult::Fail("buffer address word wrong");
    }
    if qw1 & 0xF != TX_DESC_DTYPE_DATA {
        return TestResult::Fail("DTYPE must be DATA in the low nibble");
    }
    let cmd = (qw1 >> TXD_QW1_CMD_SHIFT) & 0xFFF;
    if cmd & TX_DESC_CMD_EOP == 0 {
        return TestResult::Fail("EOP not set");
    }
    if cmd & TX_DESC_CMD_RS == 0 {
        return TestResult::Fail("RS not set — without it head never advances");
    }
    if cmd & TX_DESC_CMD_ICRC == 0 {
        return TestResult::Fail("ICRC not set — the device would not append FCS");
    }
    // The length lives at bit 34, well above the command field.
    if (qw1 >> TXD_QW1_TX_BUF_SZ_SHIFT) & 0x3FFF != 128 {
        return TestResult::Fail("buffer size is not at bit 34");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_tx_descriptor_encoding);

fn smoke_i40e_rx_descriptor_decode() -> TestResult {
    use super::ring::{
        rx_desc_done, rx_desc_eof, rx_desc_errors, rx_desc_len, RXD_QW1_ERROR_SHIFT,
        RXD_QW1_LENGTH_PBUF_SHIFT,
    };
    // DD + EOF set, length 1514, no errors.
    let sel = 0b11u64 | (1514u64 << RXD_QW1_LENGTH_PBUF_SHIFT);
    if !rx_desc_done(sel) || !rx_desc_eof(sel) {
        return TestResult::Fail("DD / EOF decode wrong");
    }
    if rx_desc_len(sel) != 1514 {
        return TestResult::Fail("length is 14 bits at 38");
    }
    if rx_desc_errors(sel) != 0 {
        return TestResult::Fail("no error bits should be set");
    }
    // An un-written descriptor must not look done.
    if rx_desc_done(0) {
        return TestResult::Fail("a zero descriptor must not read as done");
    }
    // Error bits live at 19 and must not be confused with the status
    // field below them.
    let bad = sel | (0x20u64 << RXD_QW1_ERROR_SHIFT);
    if rx_desc_errors(bad) != 0x20 {
        return TestResult::Fail("error field is 8 bits at 19");
    }
    if rx_desc_len(bad) != 1514 {
        return TestResult::Fail("error bits leaked into the length");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_rx_descriptor_decode);

// ── Queue enable / allocation ────────────────────────────────────────

fn smoke_i40e_queue_enable_bits() -> TestResult {
    use super::ring::{QENA_REQ, QENA_STAT};
    // QENA_STAT is bit 2, not bit 1. Polling the wrong bit makes
    // every enable look like it timed out.
    if QENA_REQ != 1 << 0 {
        return TestResult::Fail("QENA_REQ is bit 0");
    }
    if QENA_STAT != 1 << 2 {
        return TestResult::Fail("QENA_STAT is bit 2, not bit 1");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_queue_enable_bits);

fn smoke_i40e_queue_register_strides() -> TestResult {
    use super::ring::{
        reg_qrx_ena, reg_qrx_tail, reg_qtx_ctl, reg_qtx_ena, reg_qtx_head, reg_qtx_tail,
    };
    if reg_qtx_ena(0) != 0x0010_0000 || reg_qtx_ena(1) != 0x0010_0004 {
        return TestResult::Fail("QTX_ENA base or stride wrong");
    }
    if reg_qtx_tail(0) != 0x0010_8000 || reg_qtx_ctl(0) != 0x0010_4000 {
        return TestResult::Fail("QTX_TAIL / QTX_CTL base wrong");
    }
    if reg_qtx_head(0) != 0x000E_4000 {
        return TestResult::Fail("QTX_HEAD base wrong");
    }
    if reg_qrx_ena(0) != 0x0012_0000 || reg_qrx_tail(0) != 0x0012_8000 {
        return TestResult::Fail("QRX_ENA / QRX_TAIL base wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_queue_register_strides);

fn smoke_i40e_qalloc_decode() -> TestResult {
    use super::ring::decode_qalloc;
    // FIRSTQ in 10:0, LASTQ in 26:16.
    let (first, last) = decode_qalloc(0x0040_0010);
    if first != 0x10 {
        return TestResult::Fail("FIRSTQ decode wrong");
    }
    if last != 0x40 {
        return TestResult::Fail("LASTQ decode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_qalloc_decode);

fn smoke_i40e_ring_geometry() -> TestResult {
    use super::ring::{DESC_BYTES, RING_BYTES, RING_LEN};
    // The datasheet requires a multiple of 32, at least 64, and
    // `qlen` is 13 bits.
    if RING_LEN < 64 || RING_LEN % 32 != 0 || RING_LEN > 8160 {
        return TestResult::Fail("ring length violates the descriptor-count rules");
    }
    // One descriptor of slack past the ring is where the TX head
    // writeback lands; without it the device would scribble past the
    // allocation.
    if RING_BYTES != RING_LEN as u64 * DESC_BYTES + DESC_BYTES {
        return TestResult::Fail("ring allocation has no head-writeback slack");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_ring_geometry);

// ── Switch / VSI decode ──────────────────────────────────────────────

fn smoke_i40e_switch_config_decode() -> TestResult {
    use super::vsi::{SwitchConfig, ELEMENT_TYPE_MAC, ELEMENT_TYPE_VSI};
    let mut buf = alloc::vec![0u8; 16 + 32];
    // header: num_reported = 2, num_total = 2
    buf[0..2].copy_from_slice(&2u16.to_le_bytes());
    buf[2..4].copy_from_slice(&2u16.to_le_bytes());
    // element 0: a MAC element
    buf[16] = ELEMENT_TYPE_MAC;
    buf[18..20].copy_from_slice(&0x0002u16.to_le_bytes());
    // element 1: the PF's VSI, seid 0x0200, uplink 0x0010
    buf[32] = ELEMENT_TYPE_VSI;
    buf[34..36].copy_from_slice(&0x0200u16.to_le_bytes());
    buf[36..38].copy_from_slice(&0x0010u16.to_le_bytes());

    let cfg = match SwitchConfig::parse(&buf) {
        Some(c) => c,
        None => return TestResult::Fail("well-formed switch config rejected"),
    };
    if cfg.num_reported != 2 || cfg.elements.len() != 2 {
        return TestResult::Fail("element count wrong");
    }
    let main = match cfg.main_vsi() {
        Some(e) => e,
        None => return TestResult::Fail("did not find the single VSI element"),
    };
    if main.seid != 0x0200 || main.uplink_seid != 0x0010 {
        return TestResult::Fail("VSI element decoded wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_switch_config_decode);

fn smoke_i40e_switch_config_refuses_ambiguous_vsi() -> TestResult {
    use super::vsi::{SwitchConfig, ELEMENT_TYPE_VSI};
    // Two VSI elements: which one is the PF's is a guess, and
    // guessing wrong attaches the queues to someone else's VSI.
    let mut buf = alloc::vec![0u8; 16 + 32];
    buf[0..2].copy_from_slice(&2u16.to_le_bytes());
    buf[16] = ELEMENT_TYPE_VSI;
    buf[18..20].copy_from_slice(&0x0200u16.to_le_bytes());
    buf[32] = ELEMENT_TYPE_VSI;
    buf[34..36].copy_from_slice(&0x0201u16.to_le_bytes());
    let cfg = match SwitchConfig::parse(&buf) {
        Some(c) => c,
        None => return TestResult::Fail("parse failed"),
    };
    if cfg.main_vsi().is_some() {
        return TestResult::Fail("two VSI elements must not resolve to a main VSI");
    }
    // A truncated buffer must not be read past its end.
    let short = alloc::vec![0u8; 8];
    if SwitchConfig::parse(&short).is_some() {
        return TestResult::Fail("a sub-header buffer was accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/i40e",
    smoke_i40e_switch_config_refuses_ambiguous_vsi
);

fn smoke_i40e_vsi_properties_offsets() -> TestResult {
    use super::vsi::{
        VsiParams, VSI_OFF_QS_HANDLE, VSI_OFF_QUEUE_MAPPING, VSI_OFF_TC_MAPPING,
        VSI_PROPERTIES_BYTES, VSI_TC_QUE_NUMBER_SHIFT,
    };
    // qs_handle starts the response section at byte 96 — the comment
    // in Linux's struct says the first 96 bytes are written by
    // software, which is the cross-check on this offset.
    if VSI_OFF_QS_HANDLE != 96 {
        return TestResult::Fail("qs_handle is at byte 96");
    }
    if VSI_OFF_QUEUE_MAPPING != 30 || VSI_OFF_TC_MAPPING != 62 {
        return TestResult::Fail("queue_mapping / tc_mapping offsets wrong");
    }
    if VSI_PROPERTIES_BYTES != 128 {
        return TestResult::Fail("VSI properties are 128 bytes");
    }
    // tc_mapping's queue-count field stores log2 of the count, so a
    // stored 0 means one queue rather than none.
    let one = VsiParams {
        tc_mapping_0: 0,
        ..Default::default()
    };
    if one.tc0_queue_count() != 1 {
        return TestResult::Fail("a stored 0 must decode to one queue, not zero");
    }
    let eight = VsiParams {
        tc_mapping_0: 3 << VSI_TC_QUE_NUMBER_SHIFT,
        ..Default::default()
    };
    if eight.tc0_queue_count() != 8 {
        return TestResult::Fail("queue count is 2^field");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_vsi_properties_offsets);

fn smoke_i40e_macvlan_element_encoding() -> TestResult {
    use super::vsi::{
        encode_macvlan_element, BROADCAST_MAC, MACVLAN_ADD_IGNORE_VLAN, MACVLAN_ADD_PERFECT_MATCH,
        MACVLAN_ELEMENT_BYTES,
    };
    let mac = [0x3C, 0xFD, 0xFE, 0x01, 0x02, 0x03];
    let flags = MACVLAN_ADD_PERFECT_MATCH | MACVLAN_ADD_IGNORE_VLAN;
    let e = encode_macvlan_element(mac, flags, 0);
    if e.len() != MACVLAN_ELEMENT_BYTES {
        return TestResult::Fail("element is 16 bytes");
    }
    if e[0..6] != mac {
        return TestResult::Fail("MAC is not at offset 0");
    }
    // vlan_tag occupies 6..8 and must stay zero with IGNORE_VLAN set.
    if e[6..8] != [0, 0] {
        return TestResult::Fail("vlan_tag should be zero");
    }
    if u16::from_le_bytes([e[8], e[9]]) != flags {
        return TestResult::Fail("flags are at offset 8");
    }
    if BROADCAST_MAC != [0xFF; 6] {
        return TestResult::Fail("broadcast address wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_macvlan_element_encoding);

fn smoke_i40e_new_aq_opcodes() -> TestResult {
    use super::AqOpcode;
    if AqOpcode::GetSwitchConfig as u16 != 0x0200 {
        return TestResult::Fail("get_switch_config opcode wrong");
    }
    if AqOpcode::GetVsiParameters as u16 != 0x0212 {
        return TestResult::Fail("get_vsi_parameters opcode wrong");
    }
    if AqOpcode::AddMacvlan as u16 != 0x0250 {
        return TestResult::Fail("add_macvlan opcode wrong");
    }
    if AqOpcode::SetLinkRestartAn as u16 != 0x0605 {
        return TestResult::Fail("set_link_restart_an opcode wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_new_aq_opcodes);

fn smoke_i40e_rx_tail_holds_back_one_slot() -> TestResult {
    use super::ring::{RING_LEN, RX_TAIL_INIT};
    // The device owns [head, tail). Publishing tail == RING_LEN is
    // not a legal descriptor index, and tail == head reads as an
    // empty ring rather than a full one — so exactly one slot is
    // always held back, matching Linux's I40E_DESC_UNUSED().
    if RX_TAIL_INIT != RING_LEN - 1 {
        return TestResult::Fail("initial RX tail must hold back one slot");
    }
    if RX_TAIL_INIT >= RING_LEN {
        return TestResult::Fail("initial RX tail is not a valid descriptor index");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_rx_tail_holds_back_one_slot);

fn smoke_i40e_vsi_queue_map_guard() -> TestResult {
    use super::vsi::{VsiParams, VSI_QUE_MAP_NONCONTIG};
    // The driver drives PF-relative queue 0 and only accepts a VSI
    // whose context agrees. A non-contiguous map means
    // `queue_mapping[0]` is a queue id rather than a base, so reading
    // it as a base would point at the wrong queue entirely.
    let contiguous_at_zero = VsiParams::default();
    if !contiguous_at_zero.is_contiguous() || contiguous_at_zero.queue_mapping_0 != 0 {
        return TestResult::Fail("a zeroed VSI context should read as contiguous at queue 0");
    }
    let noncontig = VsiParams {
        mapping_flags: VSI_QUE_MAP_NONCONTIG,
        ..Default::default()
    };
    if noncontig.is_contiguous() {
        return TestResult::Fail("NONCONTIG flag was not detected");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_vsi_queue_map_guard);

// ── Per-port interface naming ────────────────────────────────────────

fn smoke_i40e_interface_names_are_unique() -> TestResult {
    use super::{interface_name, INTERFACE_NAMES};
    // The registry rejects duplicate names, so a repeated entry would
    // leave a port silently unregistered.
    for (i, a) in INTERFACE_NAMES.iter().enumerate() {
        for b in INTERFACE_NAMES.iter().skip(i + 1) {
            if a == b {
                return TestResult::Fail("duplicate interface name in the table");
            }
        }
        if a.is_empty() {
            return TestResult::Fail("empty interface name");
        }
    }
    if interface_name(0) != Some("i40e0") || interface_name(1) != Some("i40e1") {
        return TestResult::Fail("names are not assigned in probe order");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_interface_names_are_unique);

fn smoke_i40e_interface_name_table_is_bounded() -> TestResult {
    use super::{interface_name, INTERFACE_NAMES};
    // Past the table the probe must report `None` rather than reuse a
    // name. Reuse would hit the registry's duplicate check and leave
    // the port unregistered with no explanation.
    if interface_name(INTERFACE_NAMES.len()).is_some() {
        return TestResult::Fail("index past the table must not resolve to a name");
    }
    if interface_name(INTERFACE_NAMES.len() - 1).is_none() {
        return TestResult::Fail("the last table entry should resolve");
    }
    // A 4-port X710 presents four PFs; the table must cover more than
    // one such card or a second card's ports go unnamed.
    if INTERFACE_NAMES.len() < 8 {
        return TestResult::Fail("table is too small for more than one 4-port card");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/i40e",
    smoke_i40e_interface_name_table_is_bounded
);

// ── Link-status events ───────────────────────────────────────────────

fn smoke_i40e_link_status_packing_round_trip() -> TestResult {
    use super::LinkStatus;
    let s = LinkStatus {
        link_up: true,
        media_available: true,
        lse_enabled: true,
        phy_type: 0x1D,
        speed_raw: 1 << 3,
        max_frame_size: 9728,
    };
    if LinkStatus::decode(s.encode()) != s {
        return TestResult::Fail("link status did not survive the atomic packing");
    }
    // The three flags must not alias each other.
    let only_up = LinkStatus {
        link_up: true,
        ..Default::default()
    };
    let d = LinkStatus::decode(only_up.encode());
    if !d.link_up || d.media_available || d.lse_enabled {
        return TestResult::Fail("link flags alias in the packed word");
    }
    // An empty cage: no media, link down, but reporting armed.
    let empty = LinkStatus {
        lse_enabled: true,
        ..Default::default()
    };
    let d = LinkStatus::decode(empty.encode());
    if d.link_up || d.media_available || !d.lse_enabled {
        return TestResult::Fail("empty-cage state decoded wrong");
    }
    if LinkStatus::decode(0) != LinkStatus::default() {
        return TestResult::Fail("a zero word should decode to the default state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/i40e",
    smoke_i40e_link_status_packing_round_trip
);

fn smoke_i40e_lse_flags() -> TestResult {
    use super::{LinkStatus, AQ_LSE_DISABLE, AQ_LSE_ENABLE, AQ_LSE_IS_ENABLED};
    if AQ_LSE_ENABLE != 0x3 || AQ_LSE_DISABLE != 0x2 || AQ_LSE_IS_ENABLED != 0x1 {
        return TestResult::Fail("LSE constants wrong");
    }
    // The response reports whether reporting is armed in the low bit
    // of command_flags. Missing it means the pump can sit idle with
    // nothing ever arriving and no indication why.
    let mut params = [0u8; 16];
    params[0..2].copy_from_slice(&AQ_LSE_IS_ENABLED.to_le_bytes());
    if !LinkStatus::parse(&params).lse_enabled {
        return TestResult::Fail("LSE_IS_ENABLED not decoded from command_flags");
    }
    let off = [0u8; 16];
    if LinkStatus::parse(&off).lse_enabled {
        return TestResult::Fail("LSE reported armed when command_flags is clear");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_lse_flags);

fn smoke_i40e_arq_head_mask() -> TestResult {
    use super::{AQ_RING_LEN, ARQH_MASK};
    // ARQH is 10 bits; the upper bits of the register are not part of
    // the index. Using the raw register value would compare a huge
    // number against the cursor and drain the whole ring.
    if ARQH_MASK != 0x3FF {
        return TestResult::Fail("ARQH mask wrong");
    }
    if (AQ_RING_LEN as u32) > ARQH_MASK + 1 {
        return TestResult::Fail("ring is larger than the head index can address");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/i40e", smoke_i40e_arq_head_mask);

fn smoke_i40e_arq_work_limit_covers_the_ring() -> TestResult {
    use super::{AQ_RING_LEN, AQ_WORK_LIMIT};
    // The batch bound has to exceed the ring, or a full ring could
    // never be drained in one pass and the pump would fall behind
    // under sustained events.
    if AQ_WORK_LIMIT < AQ_RING_LEN as u32 {
        return TestResult::Fail("work limit is smaller than the ARQ ring");
    }
    if AQ_WORK_LIMIT == 0 {
        return TestResult::Fail("a zero work limit would drain nothing");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/i40e",
    smoke_i40e_arq_work_limit_covers_the_ring
);
