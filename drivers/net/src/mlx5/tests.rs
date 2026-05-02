//! mlx5 driver smokes — co-located with the driver per project
//! convention. Wires into `narf-kernel-test` so the runner groups
//! results under `drivers/net/mlx5`.
//!
//! Stage 1 cover:
//! - PCI match table contains an entry for every documented
//!   ConnectX-4..6 device id.
//! - `decode_init_segment` round-trips a synthetic BE-encoded
//!   buffer.
//! - `is_initializing` reads bit 31 of the `0x0FFC` register.
//!
//! Stage 2 cover:
//! - `build_cqe_inline` BE-encodes the opcode at offset 0x10.
//! - `compute_signature` is the byte-XOR-excluding-signature.
//! - `is_complete` tracks the ownership bit (bit 0 of byte 0x3F).
//! - `decode_response` round-trips a `simulate_completion` reply.
//! - `decode_response` rejects HW-owned CQEs and FW-error status.
//! - `CmdStatus::from_raw` maps documented codes; unmapped → Unknown.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    decode_init_segment, is_initializing,
    INIT_SEGMENT_LEN, MLX5_VENDOR,
    MLX5_DEV_CX4, MLX5_DEV_CX4_LX, MLX5_DEV_CX4_LX_VF,
    MLX5_DEV_CX5, MLX5_DEV_CX5_EX, MLX5_DEV_CX6, MLX5_DEV_CX6_DX,
};

// Helper: build a 4 KiB init-segment buffer with chosen field
// values, BE-encoded as the PRM specifies.
fn synth_segment(
    fw_major: u16, fw_minor: u16, fw_sub: u16,
    cmd_iface: u16,
    cmdq_high: u32, cmdq_low_sz: u32,
    cmd_dbell: u32,
    initializing: bool,
) -> [u8; INIT_SEGMENT_LEN] {
    let mut raw = [0u8; INIT_SEGMENT_LEN];
    raw[0x00..0x02].copy_from_slice(&fw_major.to_be_bytes());
    raw[0x02..0x04].copy_from_slice(&fw_minor.to_be_bytes());
    raw[0x04..0x06].copy_from_slice(&fw_sub.to_be_bytes());
    raw[0x06..0x08].copy_from_slice(&cmd_iface.to_be_bytes());
    raw[0x10..0x14].copy_from_slice(&cmdq_high.to_be_bytes());
    raw[0x14..0x18].copy_from_slice(&cmdq_low_sz.to_be_bytes());
    raw[0x18..0x1C].copy_from_slice(&cmd_dbell.to_be_bytes());
    let init = if initializing { 1u32 << 31 } else { 0 };
    raw[0x0FFC..0x1000].copy_from_slice(&init.to_be_bytes());
    raw
}

// ── PCI match table ────────────────────────────────────────────────

fn smoke_mlx5_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let want = [
        MLX5_DEV_CX4, MLX5_DEV_CX4_LX, MLX5_DEV_CX4_LX_VF,
        MLX5_DEV_CX5, MLX5_DEV_CX5_EX, MLX5_DEV_CX6, MLX5_DEV_CX6_DX,
    ];
    for did in want {
        let matched = registered.iter().any(|m|
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: MLX5_VENDOR, device,
            } if device == did));
        if !matched {
            return TestResult::Fail("mlx5 PCI match table missing a device id");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_pci_match_table);

// ── Init-segment decoder ───────────────────────────────────────────

fn smoke_mlx5_init_segment_round_trip() -> TestResult {
    // Plausible ConnectX-5 fw_rev: 16.27.4000, cmd-iface rev 5,
    // cmdq at phys 0x0000_0001_8000_0000, log_size 6 (=> 64
    // outstanding cmds). cmdq_low_sz packs (low 28 bits of addr) | sz.
    let cmdq_addr_high = 0x0000_0001u32;
    let cmdq_low_sz    = 0x8000_0006u32; // low addr bits .. | sz=6
    let raw = synth_segment(
        16, 27, 4000,
        5,
        cmdq_addr_high, cmdq_low_sz,
        0xDEAD_BEEF,
        /* initializing */ false,
    );
    let seg = decode_init_segment(&raw);
    if seg.fw_rev_major != 16
       || seg.fw_rev_minor != 27
       || seg.fw_rev_subminor != 4000 {
        return TestResult::Fail("fw_rev decode wrong");
    }
    if seg.cmd_interface_rev != 5 {
        return TestResult::Fail("cmd_interface_rev decode wrong");
    }
    if seg.cmdq_log_size != 6 {
        return TestResult::Fail("cmdq_log_size decode wrong");
    }
    let want_addr =
        ((cmdq_addr_high as u64) << 32) | (cmdq_low_sz as u64 & !0xFu64);
    if seg.cmdq_addr != want_addr {
        return TestResult::Fail("cmdq_addr assembly wrong");
    }
    if seg.cmd_dbell_vector != 0xDEAD_BEEF {
        return TestResult::Fail("cmd_dbell_vector decode wrong");
    }
    if seg.initializing {
        return TestResult::Fail("synthesised !initializing decoded as initializing");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_init_segment_round_trip);

// ── initializing-bit reader ────────────────────────────────────────

fn smoke_mlx5_is_initializing_bit() -> TestResult {
    let init_yes = synth_segment(1, 0, 0, 0, 0, 0, 0, true);
    if !is_initializing(&init_yes) {
        return TestResult::Fail("initializing=true buffer read as cleared");
    }
    let init_no = synth_segment(1, 0, 0, 0, 0, 0, 0, false);
    if is_initializing(&init_no) {
        return TestResult::Fail("initializing=false buffer read as set");
    }
    // Verify we're checking the documented bit (31), not bit 0 by
    // mistake: a buffer with bit 0 set MUST not register as
    // initializing.
    let mut bit0 = synth_segment(1, 0, 0, 0, 0, 0, 0, false);
    let v = 0x0000_0001u32;
    bit0[0x0FFC..0x1000].copy_from_slice(&v.to_be_bytes());
    if is_initializing(&bit0) {
        return TestResult::Fail("bit-0 spuriously read as initializing — wrong bit");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_is_initializing_bit);

// ── Stage 2: command-mailbox layout ────────────────────────────────

use super::cmd::{
    build_cqe_inline, compute_signature, decode_response, is_complete,
    simulate_completion, CmdError, CmdOp, CmdStatus, CQE_LEN,
    CQE_OFF_OPCODE, CQE_OFF_INPUT_MOD, CQE_OFF_STATUS_OWN,
    CQE_OFF_SIGNATURE, CQE_OFF_TYPE, CQE_TYPE_MAILBOX,
    STATUS_OWN_BIT,
};

fn smoke_mlx5_cqe_nop_opcode_be_encoded() -> TestResult {
    let cqe = match build_cqe_inline(CmdOp::Nop, 0xDEAD_BEEF, &[], 0x42) {
        Ok(c)  => c,
        Err(_) => return TestResult::Fail("build_cqe_inline rejected NOP"),
    };
    // Opcode 0x0101, BE → bytes [0x01, 0x01] at offset 0x10.
    if cqe[CQE_OFF_OPCODE] != 0x01 || cqe[CQE_OFF_OPCODE + 1] != 0x01 {
        return TestResult::Fail("NOP opcode not BE-encoded at offset 0x10");
    }
    // input_modifier 0xDEAD_BEEF, BE at offset 0x14.
    let want = [0xDE, 0xAD, 0xBE, 0xEF];
    if cqe[CQE_OFF_INPUT_MOD..CQE_OFF_INPUT_MOD + 4] != want {
        return TestResult::Fail("input_modifier not BE-encoded at offset 0x14");
    }
    if cqe[CQE_OFF_TYPE] != CQE_TYPE_MAILBOX {
        return TestResult::Fail("CQE type field not set to mailbox (0x07)");
    }
    if cqe[CQE_OFF_STATUS_OWN] & STATUS_OWN_BIT == 0 {
        return TestResult::Fail("ownership bit not set after build (SW must hand off)");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_nop_opcode_be_encoded);

fn smoke_mlx5_cqe_signature_xor() -> TestResult {
    let cqe = build_cqe_inline(CmdOp::Nop, 0, &[1, 2, 3, 4], 0xAA).unwrap();
    let sig = cqe[CQE_OFF_SIGNATURE];
    let recomputed = compute_signature(&cqe);
    if sig != recomputed {
        return TestResult::Fail("stored signature does not match recompute");
    }
    // XOR all bytes including signature should equal 0 (because the
    // signature is exactly the XOR of all other bytes).
    let mut xor = 0u8;
    for &b in cqe.iter() { xor ^= b; }
    if xor != 0 {
        return TestResult::Fail("signature is not the XOR-checksum of the CQE");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_signature_xor);

fn smoke_mlx5_cqe_is_complete_tracks_own_bit() -> TestResult {
    let mut cqe = build_cqe_inline(CmdOp::Nop, 0, &[], 0).unwrap();
    if is_complete(&cqe) {
        return TestResult::Fail("freshly built CQE reported complete (own bit cleared)");
    }
    cqe[CQE_OFF_STATUS_OWN] &= !STATUS_OWN_BIT;
    if !is_complete(&cqe) {
        return TestResult::Fail("CQE with own=0 reported as not complete");
    }
    // Higher bits in status_own MUST NOT be confused for the own
    // bit.
    cqe[CQE_OFF_STATUS_OWN] = 0xFE;
    if !is_complete(&cqe) {
        return TestResult::Fail("only bit 0 of status_own is the own bit");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_is_complete_tracks_own_bit);

fn smoke_mlx5_cqe_decode_response_round_trip() -> TestResult {
    let mut cqe = build_cqe_inline(CmdOp::QueryHcaCap, 0, &[], 0x55).unwrap();
    // HW still owns → decode_response must refuse.
    if !matches!(decode_response(&cqe), Err(CmdError::NotComplete)) {
        return TestResult::Fail(
            "decode_response did not refuse a HW-owned CQE");
    }
    let payload = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    simulate_completion(&mut cqe, /* status */ 0, /* syn */ 0,
                        /* output_mod */ 0xCAFE_F00D, &payload);
    let resp = match decode_response(&cqe) {
        Ok(r)  => r,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("decode_response failed on a clean OK reply");
        }
    };
    if resp.status != CmdStatus::Ok { return TestResult::Fail("status not OK"); }
    if resp.output_modifier != 0xCAFE_F00D {
        return TestResult::Fail("output_modifier not BE-decoded");
    }
    if resp.inline_output != payload {
        return TestResult::Fail("inline_output bytes did not round-trip");
    }
    if resp.token != 0x55 {
        return TestResult::Fail("token did not survive round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_decode_response_round_trip);

fn smoke_mlx5_cqe_fw_status_surfaced() -> TestResult {
    let mut cqe = build_cqe_inline(CmdOp::Nop, 0, &[], 0).unwrap();
    // BAD_PARAM with syndrome 0xABCDEF.
    simulate_completion(&mut cqe, 0x03, 0x00AB_CDEF, 0, &[]);
    match decode_response(&cqe) {
        Err(CmdError::FwStatus(CmdStatus::BadParam, syn)) if syn == 0x00AB_CDEF
            => TestResult::Pass,
        Err(CmdError::FwStatus(_, _))
            => TestResult::Fail("FwStatus mapped wrong status code"),
        _ => TestResult::Fail(
            "non-OK status was not reported as FwStatus"),
    }
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_fw_status_surfaced);

fn smoke_mlx5_cmd_status_from_raw_catalog() -> TestResult {
    let pairs: &[(u8, CmdStatus)] = &[
        (0x00, CmdStatus::Ok),
        (0x01, CmdStatus::InternalErr),
        (0x02, CmdStatus::BadOp),
        (0x03, CmdStatus::BadParam),
        (0x04, CmdStatus::BadSysState),
        (0x05, CmdStatus::BadResource),
        (0x06, CmdStatus::ResourceBusy),
        (0x08, CmdStatus::ExceedLim),
        (0x09, CmdStatus::BadResState),
        (0x0A, CmdStatus::BadIndex),
        (0x0F, CmdStatus::NoResources),
        (0x50, CmdStatus::BadInputLen),
        (0x51, CmdStatus::BadOutputLen),
    ];
    for &(raw, want) in pairs {
        if CmdStatus::from_raw(raw) != want {
            return TestResult::Fail("CmdStatus::from_raw catalog mismatch");
        }
    }
    // Any unmapped byte falls into Unknown(b).
    match CmdStatus::from_raw(0x7F) {
        CmdStatus::Unknown(0x7F) => TestResult::Pass,
        _ => TestResult::Fail("unmapped status code lost the raw byte"),
    }
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cmd_status_from_raw_catalog);

fn smoke_mlx5_cqe_inline_overflow() -> TestResult {
    let too_long = [0u8; 9];
    match build_cqe_inline(CmdOp::Nop, 0, &too_long, 0) {
        Err(CmdError::InlineOverflow) => TestResult::Pass,
        _ => TestResult::Fail(
            "build_cqe_inline accepted a >8-byte inline input"),
    }
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_inline_overflow);

// Compile-time guard: CQE struct length is exactly 64 bytes.
const _: () = assert!(CQE_LEN == 64);
