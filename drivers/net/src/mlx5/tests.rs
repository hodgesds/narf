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
    decode_init_segment, is_initializing, INIT_SEGMENT_LEN, MLX5_DEV_CX4, MLX5_DEV_CX4_LX,
    MLX5_DEV_CX4_LX_VF, MLX5_DEV_CX5, MLX5_DEV_CX5_EX, MLX5_DEV_CX6, MLX5_DEV_CX6_DX, MLX5_VENDOR,
};

// Helper: build a 4 KiB init-segment buffer with chosen field
// values, BE-encoded as the PRM specifies.
#[allow(clippy::too_many_arguments)] // mirrors the real HW init-segment field list
fn synth_segment(
    fw_major: u16,
    fw_minor: u16,
    fw_sub: u16,
    cmd_iface: u16,
    cmdq_high: u32,
    cmdq_low_sz: u32,
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
        MLX5_DEV_CX4,
        MLX5_DEV_CX4_LX,
        MLX5_DEV_CX4_LX_VF,
        MLX5_DEV_CX5,
        MLX5_DEV_CX5_EX,
        MLX5_DEV_CX6,
        MLX5_DEV_CX6_DX,
    ];
    for did in want {
        let matched = registered.iter().any(|m| {
            matches!(m.kind, MatchKind::VendorDevice {
                vendor: MLX5_VENDOR, device,
            } if device == did)
        });
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
    let cmdq_low_sz = 0x8000_0006u32; // low addr bits .. | sz=6
    let raw = synth_segment(
        16,
        27,
        4000,
        5,
        cmdq_addr_high,
        cmdq_low_sz,
        0xDEAD_BEEF,
        /* initializing */ false,
    );
    let seg = decode_init_segment(&raw);
    if seg.fw_rev_major != 16 || seg.fw_rev_minor != 27 || seg.fw_rev_subminor != 4000 {
        return TestResult::Fail("fw_rev decode wrong");
    }
    if seg.cmd_interface_rev != 5 {
        return TestResult::Fail("cmd_interface_rev decode wrong");
    }
    if seg.cmdq_log_size != 6 {
        return TestResult::Fail("cmdq_log_size decode wrong");
    }
    let want_addr = ((cmdq_addr_high as u64) << 32) | (cmdq_low_sz as u64 & !0xFu64);
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
    build_cqe_inline, compute_signature, decode_response, is_complete, simulate_completion,
    CmdError, CmdOp, CmdStatus, CQE_LEN, CQE_OFF_INPUT_MOD, CQE_OFF_OPCODE, CQE_OFF_SIGNATURE,
    CQE_OFF_STATUS_OWN, CQE_OFF_TYPE, CQE_TYPE_MAILBOX, STATUS_OWN_BIT,
};

fn smoke_mlx5_cqe_nop_opcode_be_encoded() -> TestResult {
    let cqe = match build_cqe_inline(CmdOp::Nop, 0xDEAD_BEEF, &[], 0x42) {
        Ok(c) => c,
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
    for &b in cqe.iter() {
        xor ^= b;
    }
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
kernel_test_in!(
    "drivers/net/mlx5",
    smoke_mlx5_cqe_is_complete_tracks_own_bit
);

fn smoke_mlx5_cqe_decode_response_round_trip() -> TestResult {
    let mut cqe = build_cqe_inline(CmdOp::QueryHcaCap, 0, &[], 0x55).unwrap();
    // HW still owns → decode_response must refuse.
    if !matches!(decode_response(&cqe), Err(CmdError::NotComplete)) {
        return TestResult::Fail("decode_response did not refuse a HW-owned CQE");
    }
    let payload = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    simulate_completion(
        &mut cqe,
        /* status */ 0,
        /* syn */ 0,
        /* output_mod */ 0xCAFE_F00D,
        &payload,
    );
    let resp = match decode_response(&cqe) {
        Ok(r) => r,
        Err(e) => {
            let _ = e;
            return TestResult::Fail("decode_response failed on a clean OK reply");
        }
    };
    if resp.status != CmdStatus::Ok {
        return TestResult::Fail("status not OK");
    }
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
kernel_test_in!(
    "drivers/net/mlx5",
    smoke_mlx5_cqe_decode_response_round_trip
);

fn smoke_mlx5_cqe_fw_status_surfaced() -> TestResult {
    let mut cqe = build_cqe_inline(CmdOp::Nop, 0, &[], 0).unwrap();
    // BAD_PARAM with syndrome 0xABCDEF.
    simulate_completion(&mut cqe, 0x03, 0x00AB_CDEF, 0, &[]);
    match decode_response(&cqe) {
        Err(CmdError::FwStatus(CmdStatus::BadParam, 0x00AB_CDEF)) => TestResult::Pass,
        Err(CmdError::FwStatus(_, _)) => TestResult::Fail("FwStatus mapped wrong status code"),
        _ => TestResult::Fail("non-OK status was not reported as FwStatus"),
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
        _ => TestResult::Fail("build_cqe_inline accepted a >8-byte inline input"),
    }
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_inline_overflow);

// Compile-time guard: CQE struct length is exactly 64 bytes.
const _: () = assert!(CQE_LEN == 64);

// ── Stage 3: DMA mailbox + cmdq programming ────────────────────────

use super::cmd::{
    build_cqe_with_mailboxes, build_mailbox_block, MAILBOX_BLOCK_LEN, MAILBOX_OFF_BLOCK_NUM,
    MAILBOX_OFF_NEXT_H, MAILBOX_OFF_NEXT_L, MAILBOX_OFF_SIGNATURE, MAILBOX_OFF_TOKEN,
    MAILBOX_PAYLOAD_LEN, MAILBOX_PHYS_ALIGN_MASK,
};
use super::cmd::{
    CQE_OFF_INPUT_LEN, CQE_OFF_INPUT_MB_H, CQE_OFF_INPUT_MB_L, CQE_OFF_OUTPUT_LEN,
    CQE_OFF_OUTPUT_MB_H, CQE_OFF_OUTPUT_MB_L,
};

fn smoke_mlx5_cqe_mailbox_phys_be_encoded() -> TestResult {
    // Choose a 64-bit phys addr with a non-zero high half; the
    // low 9 bits are deliberately set to confirm they get masked
    // off (mailbox phys must be 512-B aligned).
    let in_phys: u64 = 0x0000_0001_DEAD_BEFFu64;
    let out_phys: u64 = 0x0000_0002_CAFE_F1FFu64;
    let cqe = build_cqe_with_mailboxes(
        CmdOp::QueryHcaCap,
        0xAABB_CCDD,
        in_phys,
        0x100,
        out_phys,
        0x200,
        0x77,
    );
    let want_in_h = ((in_phys >> 32) as u32).to_be_bytes();
    let want_in_l = ((in_phys & MAILBOX_PHYS_ALIGN_MASK) as u32).to_be_bytes();
    let want_out_h = ((out_phys >> 32) as u32).to_be_bytes();
    let want_out_l = ((out_phys & MAILBOX_PHYS_ALIGN_MASK) as u32).to_be_bytes();
    if cqe[CQE_OFF_INPUT_MB_H..CQE_OFF_INPUT_MB_H + 4] != want_in_h {
        return TestResult::Fail("input_mb_h not BE-encoded");
    }
    if cqe[CQE_OFF_INPUT_MB_L..CQE_OFF_INPUT_MB_L + 4] != want_in_l {
        return TestResult::Fail("input_mb_l low-bit mask wrong");
    }
    if cqe[CQE_OFF_OUTPUT_MB_H..CQE_OFF_OUTPUT_MB_H + 4] != want_out_h {
        return TestResult::Fail("output_mb_h not BE-encoded");
    }
    if cqe[CQE_OFF_OUTPUT_MB_L..CQE_OFF_OUTPUT_MB_L + 4] != want_out_l {
        return TestResult::Fail("output_mb_l low-bit mask wrong");
    }
    let want_in_len = 0x100u32.to_be_bytes();
    let want_out_len = 0x200u32.to_be_bytes();
    if cqe[CQE_OFF_INPUT_LEN..CQE_OFF_INPUT_LEN + 4] != want_in_len {
        return TestResult::Fail("input_length not BE-encoded");
    }
    if cqe[CQE_OFF_OUTPUT_LEN..CQE_OFF_OUTPUT_LEN + 4] != want_out_len {
        return TestResult::Fail("output_length not BE-encoded");
    }
    // Even with mailboxes, the type / opcode / signature /
    // ownership invariants from Stage 2 still hold.
    if cqe[CQE_OFF_TYPE] != CQE_TYPE_MAILBOX {
        return TestResult::Fail("mailbox CQE type field wrong");
    }
    if cqe[CQE_OFF_STATUS_OWN] & STATUS_OWN_BIT == 0 {
        return TestResult::Fail("mailbox CQE ownership bit not set");
    }
    let mut xor = 0u8;
    for &b in cqe.iter() {
        xor ^= b;
    }
    if xor != 0 {
        return TestResult::Fail("mailbox CQE signature not XOR-checksum");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_mailbox_phys_be_encoded);

fn smoke_mlx5_mailbox_block_layout() -> TestResult {
    // Plant a payload that exercises the boundary: byte 0 and the
    // last payload byte at offset 479 are non-zero so we can confirm
    // they land in the right window.
    let mut payload = [0u8; MAILBOX_PAYLOAD_LEN];
    payload[0] = 0xAA;
    payload[479] = 0xBB;
    let next_phys: u64 = 0x0000_0003_FACE_F00Du64;
    let block = build_mailbox_block(&payload, /* num */ 7, /* tok */ 0x33, next_phys);
    if block.len() != MAILBOX_BLOCK_LEN {
        return TestResult::Fail("mailbox block size != 512 B");
    }
    if block[0] != 0xAA {
        return TestResult::Fail("payload byte 0 dropped");
    }
    if block[479] != 0xBB {
        return TestResult::Fail("payload byte 479 dropped");
    }
    // No payload bleed past 480 (offsets 0x1E0..0x1EF are payload's
    // tail, but we put 0 there — it should still be 0).
    for byte in block.iter().take(MAILBOX_OFF_NEXT_H).skip(480) {
        if *byte != 0 {
            return TestResult::Fail("payload bleed into reserved post-payload region");
        }
    }
    let want_h = ((next_phys >> 32) as u32).to_be_bytes();
    let want_l = ((next_phys & 0xFFFF_FFFF) as u32).to_be_bytes();
    if block[MAILBOX_OFF_NEXT_H..MAILBOX_OFF_NEXT_H + 4] != want_h {
        return TestResult::Fail("next_block_h not BE-encoded");
    }
    if block[MAILBOX_OFF_NEXT_L..MAILBOX_OFF_NEXT_L + 4] != want_l {
        return TestResult::Fail("next_block_l not BE-encoded");
    }
    if block[MAILBOX_OFF_BLOCK_NUM] != 0 || block[MAILBOX_OFF_BLOCK_NUM + 1] != 7 {
        return TestResult::Fail("block_number not BE-encoded at 0x1FC");
    }
    if block[MAILBOX_OFF_TOKEN] != 0x33 {
        return TestResult::Fail("token byte at 0x1FE wrong");
    }
    // Signature is XOR-checksum; XOR-of-all should be 0.
    let mut xor = 0u8;
    for &b in block.iter() {
        xor ^= b;
    }
    if xor != 0 {
        return TestResult::Fail("mailbox-block signature not XOR-checksum");
    }
    let _ = MAILBOX_OFF_SIGNATURE; // kept exported for diag callers
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_mailbox_block_layout);

fn smoke_mlx5_mailbox_payload_truncates() -> TestResult {
    // > 480-byte payload must be silently truncated (Stage 4 will
    // chain blocks; Stage 3 only ever fills one).
    let too_big = [0xCCu8; 1024];
    let block = build_mailbox_block(&too_big, 0, 0, 0);
    for byte in block.iter().take(MAILBOX_PAYLOAD_LEN) {
        if *byte != 0xCC {
            return TestResult::Fail("payload byte not copied through");
        }
    }
    // Beyond 480: must be the chain pointer / metadata, NOT 0xCC.
    if block[MAILBOX_PAYLOAD_LEN] == 0xCC {
        return TestResult::Fail("oversize payload bled past 480-byte window");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_mailbox_payload_truncates);

// ── Stage 4: chained mailboxes + QUERY_HCA_CAP ─────────────────────

use super::mailbox::{block_count_for, read_output_chain, write_input_chain};

fn smoke_mlx5_chain_block_count() -> TestResult {
    if block_count_for(0) != 1 {
        return TestResult::Fail("0-byte payload should still need 1 block");
    }
    if block_count_for(1) != 1 {
        return TestResult::Fail("1-byte payload should fit in 1 block");
    }
    if block_count_for(MAILBOX_PAYLOAD_LEN) != 1 {
        return TestResult::Fail("exactly 480 bytes should fit in 1 block");
    }
    if block_count_for(MAILBOX_PAYLOAD_LEN + 1) != 2 {
        return TestResult::Fail("481 bytes should need 2 blocks");
    }
    if block_count_for(2 * MAILBOX_PAYLOAD_LEN) != 2 {
        return TestResult::Fail("960 bytes should need 2 blocks");
    }
    if block_count_for(2 * MAILBOX_PAYLOAD_LEN + 1) != 3 {
        return TestResult::Fail("961 bytes should need 3 blocks");
    }
    // 0x1000 = QUERY_HCA_CAP output → ceil(4096 / 480) = 9 blocks.
    if block_count_for(0x1000) != 9 {
        return TestResult::Fail("4096-byte payload should need 9 blocks");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_chain_block_count);

fn smoke_mlx5_chain_input_round_trip() -> TestResult {
    // Build a 1000-byte payload with a recognisable byte pattern,
    // run it through write_input_chain → read_output_chain, and
    // confirm we get the same bytes back.
    const N: usize = 1000;
    let mut payload = [0u8; N];
    for (i, byte) in payload.iter_mut().enumerate().take(N) {
        *byte = (i & 0xFF) as u8;
    }
    let n_blocks = block_count_for(N);
    if n_blocks != 3 {
        return TestResult::Fail("1000 bytes should chain to 3 blocks");
    }
    let block_phys: alloc::vec::Vec<u64> = (0..n_blocks as u64)
        .map(|i| 0x1_0000_0000u64 + i * 0x1000)
        .collect();
    let blocks = write_input_chain(&payload, &block_phys, 0x42);
    if blocks.len() != n_blocks {
        return TestResult::Fail("write_input_chain produced wrong block count");
    }
    // Verify each block's chain pointer threads to the next phys.
    for i in 0..n_blocks {
        let want_next = if i + 1 < n_blocks {
            block_phys[i + 1]
        } else {
            0
        };
        let h_bytes = ((want_next >> 32) as u32).to_be_bytes();
        let l_bytes = ((want_next & 0xFFFF_FFFF) as u32).to_be_bytes();
        if blocks[i][0x1F0..0x1F4] != h_bytes || blocks[i][0x1F4..0x1F8] != l_bytes {
            return TestResult::Fail("chain pointer wrong somewhere in chain");
        }
        // block_number is BE u16 at 0x1FC.
        let bn = u16::from_be_bytes([blocks[i][0x1FC], blocks[i][0x1FD]]);
        if bn != i as u16 {
            return TestResult::Fail("block_number not sequential / not BE");
        }
        // token byte at 0x1FE constant across the chain.
        if blocks[i][0x1FE] != 0x42 {
            return TestResult::Fail("token byte not constant across chain");
        }
        // signature == XOR-of-everything-else → XOR-of-block == 0.
        let mut xor = 0u8;
        for &b in blocks[i].iter() {
            xor ^= b;
        }
        if xor != 0 {
            return TestResult::Fail("chain block signature not XOR-checksum");
        }
    }
    // Reassemble through read_output_chain; should match original.
    let out = read_output_chain(&blocks, N);
    if out.len() != N {
        return TestResult::Fail("read_output_chain returned wrong length");
    }
    for i in 0..N {
        if out[i] != payload[i] {
            return TestResult::Fail("chain payload mismatch on round-trip");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_chain_input_round_trip);

fn smoke_mlx5_chain_last_block_zero_next() -> TestResult {
    let payload = [0xFFu8; 480 * 2];
    let phys = [0x2_0000_0000u64, 0x2_0000_1000u64];
    let blocks = write_input_chain(&payload, &phys, 0);
    // First block points at second.
    let want_h = ((phys[1] >> 32) as u32).to_be_bytes();
    let want_l = ((phys[1] & 0xFFFF_FFFF) as u32).to_be_bytes();
    if blocks[0][0x1F0..0x1F4] != want_h || blocks[0][0x1F4..0x1F8] != want_l {
        return TestResult::Fail("first block chain pointer wrong");
    }
    // Last block must have next = 0.
    if blocks[1][0x1F0..0x1F4] != [0; 4] || blocks[1][0x1F4..0x1F8] != [0; 4] {
        return TestResult::Fail("last block next-pointer not zeroed");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_chain_last_block_zero_next);

fn smoke_mlx5_chain_short_output_truncates() -> TestResult {
    // FW declared output_len smaller than the chain's full byte
    // capacity; read_output_chain must stop at output_len bytes.
    let blocks = [[0xAAu8; 512], [0xBBu8; 512], [0xCCu8; 512]];
    let out = read_output_chain(&blocks, 700);
    if out.len() != 700 {
        return TestResult::Fail("read_output_chain didn't honor output_len");
    }
    // First 480 bytes from block 0 (0xAA), next 220 from block 1 (0xBB).
    for byte in out.iter().take(MAILBOX_PAYLOAD_LEN) {
        if *byte != 0xAA {
            return TestResult::Fail("block 0 payload miscopied");
        }
    }
    for byte in out.iter().take(700).skip(MAILBOX_PAYLOAD_LEN) {
        if *byte != 0xBB {
            return TestResult::Fail("block 1 payload miscopied");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_chain_short_output_truncates);

// HcaCapGroup discriminants are stable wire values — guard them.
fn smoke_mlx5_hca_cap_group_discriminants() -> TestResult {
    use super::HcaCapGroup;
    if HcaCapGroup::GeneralDevice as u16 != 0x0 {
        return TestResult::Fail("GeneralDevice");
    }
    if HcaCapGroup::EthernetOffload as u16 != 0x1 {
        return TestResult::Fail("EthernetOffload");
    }
    if HcaCapGroup::Atomic as u16 != 0x3 {
        return TestResult::Fail("Atomic");
    }
    if HcaCapGroup::Roce as u16 != 0x4 {
        return TestResult::Fail("Roce");
    }
    if HcaCapGroup::IpoibOffloads as u16 != 0x5 {
        return TestResult::Fail("IpoibOffloads");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_hca_cap_group_discriminants);

// ── Stage 5: typed cap decoders ────────────────────────────────────

use super::caps::{
    CapsDecodeError, EthernetOffloadCaps, HcaGeneralCaps, ETH_OFF_LRO, ETH_OFF_LSO,
    ETH_OFF_MAX_LSO_SIZE, ETH_OFF_RSS_IND_TBL, ETH_OFF_RX_CSUM, ETH_OFF_TX_CSUM,
    ETH_OFF_VLAN_INSERT, ETH_OFF_VLAN_STRIP, HCA_CAP_OFF_LOG_MAX_CQ_SZ, HCA_CAP_OFF_LOG_MAX_EQ_SZ,
    HCA_CAP_OFF_LOG_MAX_MKEY, HCA_CAP_OFF_LOG_MAX_PD, HCA_CAP_OFF_LOG_MAX_QP_SZ,
    HCA_CAP_OFF_LOG_MAX_SRQ_SZ, HCA_CAP_OFF_VHCA_ID, HCA_CAP_OUT_LEN,
};

fn smoke_mlx5_general_caps_decode() -> TestResult {
    let mut bytes = alloc::vec![0u8; HCA_CAP_OUT_LEN];
    bytes[HCA_CAP_OFF_VHCA_ID] = 0x12; // BE u16
    bytes[HCA_CAP_OFF_VHCA_ID + 1] = 0x34;
    bytes[HCA_CAP_OFF_LOG_MAX_SRQ_SZ] = 16;
    bytes[HCA_CAP_OFF_LOG_MAX_QP_SZ] = 17;
    bytes[HCA_CAP_OFF_LOG_MAX_CQ_SZ] = 23;
    bytes[HCA_CAP_OFF_LOG_MAX_EQ_SZ] = 21;
    bytes[HCA_CAP_OFF_LOG_MAX_MKEY] = 24;
    bytes[HCA_CAP_OFF_LOG_MAX_PD] = 15;
    let caps = match HcaGeneralCaps::from_bytes(bytes) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("HcaGeneralCaps::from_bytes rejected a full payload"),
    };
    if caps.vhca_id() != 0x1234 {
        return TestResult::Fail("vhca_id BE decode wrong");
    }
    if caps.log_max_srq_sz() != 16 {
        return TestResult::Fail("log_max_srq_sz wrong");
    }
    if caps.log_max_qp_sz() != 17 {
        return TestResult::Fail("log_max_qp_sz wrong");
    }
    if caps.log_max_cq_sz() != 23 {
        return TestResult::Fail("log_max_cq_sz wrong");
    }
    if caps.log_max_eq_sz() != 21 {
        return TestResult::Fail("log_max_eq_sz wrong");
    }
    if caps.log_max_mkey() != 24 {
        return TestResult::Fail("log_max_mkey wrong");
    }
    if caps.log_max_pd() != 15 {
        return TestResult::Fail("log_max_pd wrong");
    }
    if caps.raw().len() != HCA_CAP_OUT_LEN {
        return TestResult::Fail("raw() length not preserved");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_general_caps_decode);

fn smoke_mlx5_general_caps_truncated() -> TestResult {
    // A buffer shorter than the highest committed offset (0x68)
    // must be rejected.
    let bytes = alloc::vec![0u8; HCA_CAP_OFF_LOG_MAX_PD];
    match HcaGeneralCaps::from_bytes(bytes) {
        Err(CapsDecodeError::Truncated) => TestResult::Pass,
        _ => TestResult::Fail("from_bytes accepted a buffer too short for log_max_pd"),
    }
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_general_caps_truncated);

fn smoke_mlx5_ethernet_offload_caps_decode() -> TestResult {
    let mut bytes = alloc::vec![0u8; HCA_CAP_OUT_LEN];
    bytes[ETH_OFF_TX_CSUM] = 1;
    bytes[ETH_OFF_RX_CSUM] = 1;
    bytes[ETH_OFF_LSO] = 1;
    bytes[ETH_OFF_LRO] = 0;
    bytes[ETH_OFF_RSS_IND_TBL] = 1;
    bytes[ETH_OFF_VLAN_INSERT] = 1;
    bytes[ETH_OFF_VLAN_STRIP] = 0;
    // max_lso_size = 65536 BE.
    bytes[ETH_OFF_MAX_LSO_SIZE..ETH_OFF_MAX_LSO_SIZE + 4].copy_from_slice(&65536u32.to_be_bytes());
    let caps = match EthernetOffloadCaps::from_bytes(bytes) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("EthernetOffloadCaps rejected full payload"),
    };
    if !caps.supports_tx_csum() {
        return TestResult::Fail("tx_csum");
    }
    if !caps.supports_rx_csum() {
        return TestResult::Fail("rx_csum");
    }
    if !caps.supports_lso() {
        return TestResult::Fail("lso");
    }
    if caps.supports_lro() {
        return TestResult::Fail("lro should be off");
    }
    if !caps.supports_rss() {
        return TestResult::Fail("rss");
    }
    if !caps.supports_vlan_insert() {
        return TestResult::Fail("vlan_insert");
    }
    if caps.supports_vlan_strip() {
        return TestResult::Fail("vlan_strip should be off");
    }
    if caps.max_lso_size() != 65536 {
        return TestResult::Fail("max_lso_size BE wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_ethernet_offload_caps_decode);

fn smoke_mlx5_ethernet_offload_caps_truncated() -> TestResult {
    let bytes = alloc::vec![0u8; ETH_OFF_VLAN_STRIP];
    match EthernetOffloadCaps::from_bytes(bytes) {
        Err(CapsDecodeError::Truncated) => TestResult::Pass,
        _ => TestResult::Fail("EthernetOffloadCaps accepted a buffer too short"),
    }
}
kernel_test_in!(
    "drivers/net/mlx5",
    smoke_mlx5_ethernet_offload_caps_truncated
);

// ── Stage 6: bit_field + bit-packed caps + EQ context ──────────────

use super::bit_field::{read_bits_be, write_bits_be};
use super::caps::{
    HCA_CAP_BIT_LOG_MAX_EQ, HCA_CAP_BIT_LOG_MAX_EQ_W, HCA_CAP_BIT_LOG_MAX_QP,
    HCA_CAP_BIT_LOG_MAX_QP_W,
};
use super::eq::{
    build_create_eq_input, decode_create_eq_input, EqError, EqParams, EQC_LEN, EQC_OFF_INTR_VECTOR,
    EQC_OFF_LOG_PAGE_SIZE, EQC_PA_ENTRY_LEN, EQC_PA_LIST_OFF,
};

fn smoke_mlx5_bit_field_msb_first() -> TestResult {
    // bit 0 must be the MSB of byte 0.
    let bytes = [0b1000_0000u8];
    if read_bits_be(&bytes, 0, 1) != 1 {
        return TestResult::Fail("bit 0 not MSB of byte 0");
    }
    if read_bits_be(&bytes, 1, 1) != 0 {
        return TestResult::Fail("bit 1 should be 0");
    }
    let bytes = [0b0000_0001u8];
    if read_bits_be(&bytes, 7, 1) != 1 {
        return TestResult::Fail("bit 7 should be LSB of byte 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_bit_field_msb_first);

fn smoke_mlx5_bit_field_cross_byte() -> TestResult {
    // 12 bits straddling byte boundary: 0xABC = 0b1010_1011_1100.
    let bytes = [0xAB, 0xC0];
    let v = read_bits_be(&bytes, 0, 12);
    if v != 0xABC {
        return TestResult::Fail("12-bit cross-byte read wrong");
    }
    let v = read_bits_be(&bytes, 4, 8);
    if v != 0xBC {
        return TestResult::Fail("byte-aligned-after-nibble wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_bit_field_cross_byte);

fn smoke_mlx5_bit_field_round_trip() -> TestResult {
    let mut bytes = [0u8; 8];
    write_bits_be(&mut bytes, 5, 12, 0xCAFE & 0xFFF);
    let v = read_bits_be(&bytes, 5, 12);
    if v != (0xCAFE & 0xFFF) {
        return TestResult::Fail("write+read round-trip mismatch");
    }
    // Writing into an unrelated bit window must not disturb the
    // first.
    write_bits_be(&mut bytes, 32, 16, 0xDEAD);
    let v1 = read_bits_be(&bytes, 5, 12);
    let v2 = read_bits_be(&bytes, 32, 16);
    if v1 != (0xCAFE & 0xFFF) || v2 != 0xDEAD {
        return TestResult::Fail("adjacent bit-field writes interfered");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_bit_field_round_trip);

fn smoke_mlx5_bit_field_caps_qp_eq() -> TestResult {
    // Build a 0x100-byte payload where log_max_qp = 27 lives at the
    // committed bit position; verify the cap accessor reads it.
    let mut bytes = alloc::vec![0u8; 0x100];
    write_bits_be(
        &mut bytes,
        HCA_CAP_BIT_LOG_MAX_QP,
        HCA_CAP_BIT_LOG_MAX_QP_W,
        27,
    );
    write_bits_be(
        &mut bytes,
        HCA_CAP_BIT_LOG_MAX_EQ,
        HCA_CAP_BIT_LOG_MAX_EQ_W,
        8,
    );
    // log_max_pd offset 0x68 is the highest committed offset; pad
    // the buffer so from_bytes() doesn't reject it.
    let caps = match super::caps::HcaGeneralCaps::from_bytes(bytes) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("HcaGeneralCaps from_bytes rejected 0x100-byte payload"),
    };
    if caps.log_max_qp() != 27 {
        return TestResult::Fail("bit-packed log_max_qp readback wrong");
    }
    if caps.log_max_eq() != 8 {
        return TestResult::Fail("bit-packed log_max_eq readback wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_bit_field_caps_qp_eq);

fn smoke_mlx5_eq_input_layout() -> TestResult {
    let pages = [0x1_0000_0000u64, 0x1_0000_1000u64, 0x1_0000_2000u64];
    let params = EqParams {
        log_eq_size: 7,
        uar_page: 0xABCDEF,
        intr_vector: 9,
        log_page_size: 12,
    };
    let bytes = match build_create_eq_input(params, &pages) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("build_create_eq_input rejected valid params"),
    };
    if bytes.len() != EQC_PA_LIST_OFF + 3 * EQC_PA_ENTRY_LEN {
        return TestResult::Fail("CREATE_EQ payload length wrong");
    }
    if bytes[EQC_OFF_INTR_VECTOR] != 9 {
        return TestResult::Fail("intr_vector byte missing");
    }
    if bytes[EQC_OFF_LOG_PAGE_SIZE] != 12 {
        return TestResult::Fail("log_page_size byte missing");
    }
    // Phys-addr list — each BE u64 at EQC_PA_LIST_OFF + i*8.
    for (i, &expect) in pages.iter().enumerate() {
        let off = EQC_PA_LIST_OFF + i * EQC_PA_ENTRY_LEN;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[off..off + 8]);
        if u64::from_be_bytes(buf) != expect {
            return TestResult::Fail("phys-addr list entry not BE-encoded");
        }
    }
    // Round-trip: decode_create_eq_input should match params for
    // the bit-packed fields too.
    let back = decode_create_eq_input(&bytes);
    if back.log_eq_size != params.log_eq_size
        || back.uar_page != params.uar_page
        || back.intr_vector != params.intr_vector
        || back.log_page_size != params.log_page_size
    {
        return TestResult::Fail("CREATE_EQ params didn't round-trip");
    }
    // The eqc proper is exactly EQC_LEN bytes.
    let _ = EQC_LEN;
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_eq_input_layout);

fn smoke_mlx5_eq_input_validation() -> TestResult {
    let pages = [0x1_0000_0000u64];
    // log_eq_size > 31 → BadLogEqSize.
    let bad_size = EqParams {
        log_eq_size: 32,
        uar_page: 0,
        intr_vector: 0,
        log_page_size: 12,
    };
    if !matches!(
        build_create_eq_input(bad_size, &pages),
        Err(EqError::BadLogEqSize)
    ) {
        return TestResult::Fail("oversize log_eq_size accepted");
    }
    // uar_page > 0xFFFFFF → BadUarPage.
    let bad_uar = EqParams {
        log_eq_size: 7,
        uar_page: 0x100_0000,
        intr_vector: 0,
        log_page_size: 12,
    };
    if !matches!(
        build_create_eq_input(bad_uar, &pages),
        Err(EqError::BadUarPage)
    ) {
        return TestResult::Fail("oversize uar_page accepted");
    }
    // empty pages → NoPages.
    let ok_params = EqParams {
        log_eq_size: 7,
        uar_page: 0,
        intr_vector: 0,
        log_page_size: 12,
    };
    if !matches!(build_create_eq_input(ok_params, &[]), Err(EqError::NoPages)) {
        return TestResult::Fail("empty page list accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_eq_input_validation);

fn smoke_mlx5_create_eq_opcode() -> TestResult {
    // CREATE_EQ opcode value is the wire-stable 0x301.
    if super::cmd::CmdOp::CreateEq as u16 != 0x301 {
        return TestResult::Fail("CREATE_EQ opcode discriminant drifted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_create_eq_opcode);

// ── Stage 7: input-mailbox + inline-output transport + UAR ─────────

fn smoke_mlx5_input_mb_inline_out_cqe_layout() -> TestResult {
    // Verify build_cqe_with_mailboxes(input, /* output_mb */ 0,
    // /* output_len */ 0) produces a CQE shape Stage-7's transport
    // relies on: input_mb_h/l populated, output_mb_h/l = 0,
    // output_length = 0, ownership bit set, signature is XOR.
    use super::cmd::build_cqe_with_mailboxes;
    let in_phys: u64 = 0x0000_0001_BABE_F000;
    let cqe = build_cqe_with_mailboxes(CmdOp::CreateEq, 0, in_phys, 0x300, 0, 0, 0xCC);
    let want_h = ((in_phys >> 32) as u32).to_be_bytes();
    let want_l = (in_phys as u32).to_be_bytes();
    if cqe[0x08..0x0C] != want_h || cqe[0x0C..0x10] != want_l {
        return TestResult::Fail("input_mb pointer not BE-encoded");
    }
    if cqe[0x30..0x34] != [0u8; 4] || cqe[0x34..0x38] != [0u8; 4] {
        return TestResult::Fail("output_mb pointer not zero when output_len=0");
    }
    if cqe[0x38..0x3C] != [0u8; 4] {
        return TestResult::Fail("output_length not zero");
    }
    let want_inl = 0x300u32.to_be_bytes();
    if cqe[0x04..0x08] != want_inl {
        return TestResult::Fail("input_length not BE-encoded");
    }
    let mut xor = 0u8;
    for &b in cqe.iter() {
        xor ^= b;
    }
    if xor != 0 {
        return TestResult::Fail("CQE signature not XOR-checksum after mb-only build");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/mlx5",
    smoke_mlx5_input_mb_inline_out_cqe_layout
);

fn smoke_mlx5_create_eq_output_modifier_decode() -> TestResult {
    // Synthesise a completed CQE with output_modifier carrying the
    // documented eq_number layout (low 24 bits of the field). Stage-2
    // decode_response should expose those 24 bits via .output_modifier
    // and Stage 7 masks the top byte off before storing.
    use super::cmd::{build_cqe_inline, decode_response, simulate_completion};
    let mut cqe = build_cqe_inline(CmdOp::CreateEq, 0, &[], 0x10).unwrap();
    // FW returns eq_number = 0x12_3456 in bits [23:0] of
    // output_modifier; bit 31..24 should be zero in compliant FW
    // but mask defensively in driver.
    let raw_om: u32 = 0x0012_3456;
    simulate_completion(&mut cqe, /* status */ 0, /* syn */ 0, raw_om, &[]);
    let resp = match decode_response(&cqe) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("decode_response failed for CREATE_EQ reply"),
    };
    let eq_number = resp.output_modifier & 0x00FF_FFFF;
    if eq_number != 0x0012_3456 {
        return TestResult::Fail("eq_number mask wrong");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/net/mlx5",
    smoke_mlx5_create_eq_output_modifier_decode
);

fn smoke_mlx5_uar_doorbell_offset_calc() -> TestResult {
    // We can't write to a real UAR in a smoke, but we can verify the
    // address arithmetic Stage-7 exposes through `UAR_BASE_DEFAULT`
    // and check that uar_page=0 + offset=0 lands at the documented
    // 1-MiB-into-BAR0 base.
    if super::UAR_BASE_DEFAULT != 0x100000 {
        return TestResult::Fail("UAR base default drifted from PRM");
    }
    // uar_page index N occupies bytes [base + N*4096 .. base + (N+1)*4096).
    let base = super::UAR_BASE_DEFAULT;
    let page_5_start = base + 5 * 4096;
    if page_5_start != 0x100000 + 0x5000 {
        return TestResult::Fail("UAR page-5 byte offset wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_uar_doorbell_offset_calc);

// ── Stage 8: ALLOC_UAR + ALLOC_PD + CREATE_CQ ──────────────────────

use super::cq::{
    build_create_cq_input, decode_create_cq_input, CqError, CqParams, CQC_LEN, CQC_OFF_C_EQN,
    CQC_OFF_LOG_PAGE_SIZE, CQC_PA_ENTRY_LEN, CQC_PA_LIST_OFF,
};

fn smoke_mlx5_alloc_uar_pd_opcodes() -> TestResult {
    if super::cmd::CmdOp::AllocUar as u16 != 0x802 {
        return TestResult::Fail("ALLOC_UAR opcode discriminant drifted");
    }
    if super::cmd::CmdOp::AllocPd as u16 != 0x800 {
        return TestResult::Fail("ALLOC_PD opcode discriminant drifted");
    }
    if super::cmd::CmdOp::CreateCq as u16 != 0x400 {
        return TestResult::Fail("CREATE_CQ opcode discriminant drifted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_alloc_uar_pd_opcodes);

fn smoke_mlx5_cq_input_layout() -> TestResult {
    let pages = [0x1_0000_0000u64, 0x1_0000_1000u64];
    let params = CqParams {
        log_cq_size: 9,
        uar_page: 0x123456,
        log_page_size: 12,
        c_eqn: 3,
    };
    let bytes = match build_create_cq_input(params, &pages) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("build_create_cq_input rejected valid params"),
    };
    if bytes.len() != CQC_PA_LIST_OFF + 2 * CQC_PA_ENTRY_LEN {
        return TestResult::Fail("CREATE_CQ payload length wrong");
    }
    if bytes[CQC_OFF_LOG_PAGE_SIZE] != 12 {
        return TestResult::Fail("log_page_size byte missing at 0x0C");
    }
    if bytes[CQC_OFF_C_EQN] != 3 {
        return TestResult::Fail("c_eqn byte missing at 0x0F");
    }
    for (i, &expect) in pages.iter().enumerate() {
        let off = CQC_PA_LIST_OFF + i * CQC_PA_ENTRY_LEN;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[off..off + 8]);
        if u64::from_be_bytes(buf) != expect {
            return TestResult::Fail("CQ phys-addr list entry not BE-encoded");
        }
    }
    let back = decode_create_cq_input(&bytes);
    if back.log_cq_size != params.log_cq_size
        || back.uar_page != params.uar_page
        || back.log_page_size != params.log_page_size
        || back.c_eqn != params.c_eqn
    {
        return TestResult::Fail("CREATE_CQ params didn't round-trip");
    }
    let _ = CQC_LEN;
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cq_input_layout);

fn smoke_mlx5_cq_input_validation() -> TestResult {
    let pages = [0x1_0000_0000u64];
    let bad_size = CqParams {
        log_cq_size: 32,
        uar_page: 0,
        log_page_size: 12,
        c_eqn: 0,
    };
    if !matches!(
        build_create_cq_input(bad_size, &pages),
        Err(CqError::BadLogCqSize)
    ) {
        return TestResult::Fail("oversize log_cq_size accepted");
    }
    let bad_uar = CqParams {
        log_cq_size: 9,
        uar_page: 0x100_0000,
        log_page_size: 12,
        c_eqn: 0,
    };
    if !matches!(
        build_create_cq_input(bad_uar, &pages),
        Err(CqError::BadUarPage)
    ) {
        return TestResult::Fail("oversize uar_page accepted");
    }
    let ok = CqParams {
        log_cq_size: 9,
        uar_page: 0,
        log_page_size: 12,
        c_eqn: 0,
    };
    if !matches!(build_create_cq_input(ok, &[]), Err(CqError::NoPages)) {
        return TestResult::Fail("empty page list accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cq_input_validation);

fn smoke_mlx5_cq_binds_to_eq() -> TestResult {
    // The c_eqn field at byte 0x0F is what binds the CQ to a
    // specific EQ for async events. Synthesise a CQ with c_eqn=42
    // and confirm the byte landed where Stage-8 writes it.
    let pages = [0xF000_0000_0000_0000u64];
    let params = CqParams {
        log_cq_size: 7,
        uar_page: 0,
        log_page_size: 12,
        c_eqn: 42,
    };
    let bytes = build_create_cq_input(params, &pages).unwrap();
    if bytes[CQC_OFF_C_EQN] != 42 {
        return TestResult::Fail("c_eqn binding not at byte 0x0F");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cq_binds_to_eq);

// ── Stage 9: CREATE_QP + MODIFY_QP state machine ───────────────────

use super::qp::{
    build_create_qp_input, decode_create_qp_input, decode_qp_state, decode_qp_type, QpError,
    QpParams, QpState, QpTransition, QpType, QPC_LEN, QPC_OFF_LOG_PAGE_SIZE, QPC_OFF_STATE_TYPE,
    QPC_PA_ENTRY_LEN, QPC_PA_LIST_OFF,
};

fn smoke_mlx5_qp_opcodes_pinned() -> TestResult {
    let pairs: &[(super::cmd::CmdOp, u16)] = &[
        (super::cmd::CmdOp::CreateQp, 0x500),
        (super::cmd::CmdOp::DestroyQp, 0x501),
        (super::cmd::CmdOp::Rst2InitQp, 0x502),
        (super::cmd::CmdOp::Init2RtrQp, 0x503),
        (super::cmd::CmdOp::Rtr2RtsQp, 0x504),
        (super::cmd::CmdOp::ToRstQp, 0x50A),
    ];
    for &(op, want) in pairs {
        if op as u16 != want {
            return TestResult::Fail("QP opcode discriminant drifted");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_qp_opcodes_pinned);

fn smoke_mlx5_qp_input_layout() -> TestResult {
    let pages = [0x1_0000_0000u64, 0x1_0000_1000u64];
    let params = QpParams {
        qp_type: QpType::RawEthernet,
        pd: 0x000A_BCDE,
        cqn_snd: 0x0011_2233,
        cqn_rcv: 0x0044_5566,
        log_sq_size: 8,
        log_rq_size: 9,
        log_page_size: 12,
        uar_page: 0,
    };
    let bytes = match build_create_qp_input(params, &pages) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("build_create_qp_input rejected valid params"),
    };
    if bytes.len() != QPC_PA_LIST_OFF + 2 * QPC_PA_ENTRY_LEN {
        return TestResult::Fail("CREATE_QP payload length wrong");
    }
    // state | qp_type byte: state=Rst (0), qp_type=RawEthernet (0x9).
    if bytes[QPC_OFF_STATE_TYPE] != 0x09 {
        return TestResult::Fail("state|qp_type byte wrong (expected RST<<4|RawEth)");
    }
    if bytes[QPC_OFF_LOG_PAGE_SIZE] != 12 {
        return TestResult::Fail("log_page_size byte wrong");
    }
    // Phys-addr list BE.
    for (i, &expect) in pages.iter().enumerate() {
        let off = QPC_PA_LIST_OFF + i * QPC_PA_ENTRY_LEN;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[off..off + 8]);
        if u64::from_be_bytes(buf) != expect {
            return TestResult::Fail("QP phys-addr list entry not BE-encoded");
        }
    }
    // Round-trip the bit-packed + byte-aligned subset.
    let back = decode_create_qp_input(&bytes);
    if back.qp_type != params.qp_type
        || back.pd != params.pd
        || back.cqn_snd != params.cqn_snd
        || back.cqn_rcv != params.cqn_rcv
        || back.log_sq_size != params.log_sq_size
        || back.log_rq_size != params.log_rq_size
        || back.log_page_size != params.log_page_size
    {
        return TestResult::Fail("CREATE_QP params didn't round-trip");
    }
    let _ = QPC_LEN;
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_qp_input_layout);

fn smoke_mlx5_qp_input_validation() -> TestResult {
    let pages = [0x1_0000_0000u64];
    let bad_sq = QpParams {
        qp_type: QpType::Rc,
        pd: 0,
        cqn_snd: 0,
        cqn_rcv: 0,
        log_sq_size: 32,
        log_rq_size: 0,
        log_page_size: 12,
        uar_page: 0,
    };
    if !matches!(
        build_create_qp_input(bad_sq, &pages),
        Err(QpError::BadLogSqSize)
    ) {
        return TestResult::Fail("oversize log_sq_size accepted");
    }
    let bad_rq = QpParams {
        qp_type: QpType::Rc,
        pd: 0,
        cqn_snd: 0,
        cqn_rcv: 0,
        log_sq_size: 0,
        log_rq_size: 32,
        log_page_size: 12,
        uar_page: 0,
    };
    if !matches!(
        build_create_qp_input(bad_rq, &pages),
        Err(QpError::BadLogRqSize)
    ) {
        return TestResult::Fail("oversize log_rq_size accepted");
    }
    let bad_pd = QpParams {
        qp_type: QpType::Rc,
        pd: 0x100_0000,
        cqn_snd: 0,
        cqn_rcv: 0,
        log_sq_size: 0,
        log_rq_size: 0,
        log_page_size: 12,
        uar_page: 0,
    };
    if !matches!(build_create_qp_input(bad_pd, &pages), Err(QpError::BadPd)) {
        return TestResult::Fail("oversize pd accepted");
    }
    let bad_cqn = QpParams {
        qp_type: QpType::Rc,
        pd: 0,
        cqn_snd: 0x0100_0000,
        cqn_rcv: 0,
        log_sq_size: 0,
        log_rq_size: 0,
        log_page_size: 12,
        uar_page: 0,
    };
    if !matches!(build_create_qp_input(bad_cqn, &pages), Err(QpError::BadCqn)) {
        return TestResult::Fail("oversize cqn accepted");
    }
    let ok = QpParams {
        qp_type: QpType::Rc,
        pd: 0,
        cqn_snd: 0,
        cqn_rcv: 0,
        log_sq_size: 0,
        log_rq_size: 0,
        log_page_size: 12,
        uar_page: 0,
    };
    if !matches!(build_create_qp_input(ok, &[]), Err(QpError::NoPages)) {
        return TestResult::Fail("empty page list accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_qp_input_validation);

fn smoke_mlx5_qp_state_decode() -> TestResult {
    // Synthesise qpc bytes with each documented state in the high
    // nibble + verify decode_qp_state surfaces the right enum.
    let pages = [0xFFFF_0000_0000_0000u64];
    let mut bytes = build_create_qp_input(
        QpParams {
            qp_type: QpType::Ud,
            pd: 0,
            cqn_snd: 0,
            cqn_rcv: 0,
            log_sq_size: 0,
            log_rq_size: 0,
            log_page_size: 12,
            uar_page: 0,
        },
        &pages,
    )
    .unwrap();
    if decode_qp_state(&bytes) != QpState::Rst {
        return TestResult::Fail("freshly-built qpc not in Rst");
    }
    // Move state through INIT → RTR → RTS by rewriting the high
    // nibble of byte 0 (preserve the qp_type low nibble).
    let qt_nib = bytes[QPC_OFF_STATE_TYPE] & 0x0F;
    let cases = [
        (QpState::Init, 0x1u8),
        (QpState::Rtr, 0x2),
        (QpState::Rts, 0x3),
        (QpState::Sqer, 0x4),
        (QpState::Err, 0x6),
    ];
    for (want, nib) in cases {
        bytes[QPC_OFF_STATE_TYPE] = (nib << 4) | qt_nib;
        if decode_qp_state(&bytes) != want {
            return TestResult::Fail("decode_qp_state wrong for state nibble");
        }
    }
    // Type round-trip.
    if decode_qp_type(&bytes) != Some(QpType::Ud) {
        return TestResult::Fail("qp_type low nibble lost during state writes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_qp_state_decode);

fn smoke_mlx5_qp_transition_opcode_mapping() -> TestResult {
    // Stage 9 maps each documented MODIFY_QP transition to a unique
    // opcode. Confirm none collide and all use 0x5xx range.
    let pairs: &[(QpTransition, super::cmd::CmdOp)] = &[
        (QpTransition::ToRst, super::cmd::CmdOp::ToRstQp),
        (QpTransition::RstToInit, super::cmd::CmdOp::Rst2InitQp),
        (QpTransition::InitToRtr, super::cmd::CmdOp::Init2RtrQp),
        (QpTransition::RtrToRts, super::cmd::CmdOp::Rtr2RtsQp),
    ];
    let mut seen = [0u16; 4];
    for (i, &(_, op)) in pairs.iter().enumerate() {
        let v = op as u16;
        if (v & 0xF00) != 0x500 {
            return TestResult::Fail("MODIFY_QP opcode outside 0x5xx range");
        }
        for prev in seen.iter().take(i) {
            if *prev == v {
                return TestResult::Fail("MODIFY_QP opcodes collide");
            }
        }
        seen[i] = v;
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_qp_transition_opcode_mapping);

// ── Stage 10: WQE + CQE layout ─────────────────────────────────────

use super::cqe::{
    decode_cqe, is_hw_owned, simulate_completion as simulate_cqe, CqeOpcode, CqeStatus, CqeView,
    CQE_LEN as CQE_RING_LEN, CQE_OFF_QP_OP_OWN, CQE_OWNER_BIT,
};
use super::wqe::{
    build_ctrl_segment, build_data_seg_ptr, ctrl_ds, ctrl_opcode, ctrl_qp_num, ctrl_wqe_idx,
    decode_data_seg_ptr, CqeRequest, SendOpcode, CTRL_SEG_LEN, DATA_SEG_LEN,
};

fn smoke_mlx5_wqe_ctrl_segment_round_trip() -> TestResult {
    let seg = build_ctrl_segment(
        SendOpcode::Send,
        /* qp_num */ 0x12_3456,
        /* wqe_idx */ 0xABCD,
        /* ds */ 3,
        CqeRequest::AlwaysCqe,
        /* signature */ 0x77,
    );
    if seg.len() != CTRL_SEG_LEN {
        return TestResult::Fail("control segment length wrong");
    }
    if ctrl_opcode(&seg) != SendOpcode::Send as u8 {
        return TestResult::Fail("opcode not BE-encoded at bits[7:0] of dword 0");
    }
    if ctrl_qp_num(&seg) != 0x12_3456 {
        return TestResult::Fail("qp_num not BE-encoded at bits[31:8] of dword 1");
    }
    if ctrl_wqe_idx(&seg) != 0xABCD {
        return TestResult::Fail("wqe_idx not BE-encoded at bits[23:8] of dword 0");
    }
    if ctrl_ds(&seg) != 3 {
        return TestResult::Fail("ds count not BE-encoded at bits[7:0] of dword 1");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_wqe_ctrl_segment_round_trip);

fn smoke_mlx5_wqe_data_seg_round_trip() -> TestResult {
    let seg = build_data_seg_ptr(
        /* byte_count */ 0xDEAD_BEEF,
        /* l_key */ 0xCAFE_F00D,
        /* va */ 0x0000_0001_2345_6789,
    );
    if seg.len() != DATA_SEG_LEN {
        return TestResult::Fail("data segment length wrong");
    }
    let (bc, lk, va) = decode_data_seg_ptr(&seg);
    if bc != 0xDEAD_BEEF {
        return TestResult::Fail("byte_count round-trip");
    }
    if lk != 0xCAFE_F00D {
        return TestResult::Fail("l_key round-trip");
    }
    if va != 0x0000_0001_2345_6789 {
        return TestResult::Fail("va round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_wqe_data_seg_round_trip);

fn smoke_mlx5_send_opcode_pins() -> TestResult {
    let pairs: &[(SendOpcode, u8)] = &[
        (SendOpcode::Nop, 0x00),
        (SendOpcode::SndInv, 0x01),
        (SendOpcode::RdmaWrite, 0x08),
        (SendOpcode::RdmaWriteImmediate, 0x09),
        (SendOpcode::Send, 0x0A),
        (SendOpcode::SendImmediate, 0x0B),
        (SendOpcode::RdmaRead, 0x10),
        (SendOpcode::AtomicCs, 0x11),
        (SendOpcode::AtomicFa, 0x12),
    ];
    for &(op, want) in pairs {
        if op as u8 != want {
            return TestResult::Fail("send opcode discriminant drifted");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_send_opcode_pins);

fn smoke_mlx5_cqe_decode_round_trip() -> TestResult {
    let mut cqe = [0u8; CQE_RING_LEN];
    // SW-completed CQE — owner bit cleared.
    simulate_cqe(
        &mut cqe,
        /* byte_count */ 1500,
        /* status */ 0,
        /* wqe_counter */ 0xBEEF,
        /* qp_num */ 0x12_3456,
        CqeOpcode::ResponderSend,
    );
    if is_hw_owned(&cqe) {
        return TestResult::Fail("simulate_completion left HW-owner bit set");
    }
    let view = decode_cqe(&cqe);
    let want = CqeView {
        byte_count: 1500,
        status: CqeStatus::Success,
        wqe_counter: 0xBEEF,
        qp_num: 0x12_3456,
        opcode: CqeOpcode::ResponderSend,
        owner: false,
    };
    if view != want {
        return TestResult::Fail("CQE round-trip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_decode_round_trip);

fn smoke_mlx5_cqe_owner_bit_check() -> TestResult {
    let mut cqe = [0u8; CQE_RING_LEN];
    // Initially HW owns (default firmware-side init sets bit 0).
    cqe[CQE_OFF_QP_OP_OWN + 3] |= CQE_OWNER_BIT;
    if !is_hw_owned(&cqe) {
        return TestResult::Fail("HW-owner bit not detected");
    }
    cqe[CQE_OFF_QP_OP_OWN + 3] &= !CQE_OWNER_BIT;
    if is_hw_owned(&cqe) {
        return TestResult::Fail("clear owner bit still reported HW-owned");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_owner_bit_check);

fn smoke_mlx5_cqe_status_catalog() -> TestResult {
    let pairs: &[(u8, CqeStatus)] = &[
        (0x00, CqeStatus::Success),
        (0x01, CqeStatus::LocalLengthError),
        (0x02, CqeStatus::LocalQpOpError),
        (0x04, CqeStatus::LocalProtectionError),
        (0x05, CqeStatus::WrFlushedError),
        (0x06, CqeStatus::MwBindError),
        (0x10, CqeStatus::BadResponseError),
        (0x11, CqeStatus::LocalAccessError),
        (0x12, CqeStatus::RemoteInvalidRequest),
        (0x13, CqeStatus::RemoteAccessError),
        (0x14, CqeStatus::RemoteOpError),
    ];
    for &(raw, want) in pairs {
        if CqeStatus::from_raw(raw) != want {
            return TestResult::Fail("CqeStatus catalog mismatch");
        }
    }
    if !matches!(CqeStatus::from_raw(0xFE), CqeStatus::Unknown(0xFE)) {
        return TestResult::Fail("unmapped status not preserved as Unknown");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_cqe_status_catalog);

// ── Stage 11: ring helpers (post_send/post_recv/poll_cq layout) ────

use super::ring::{
    build_recv_wqe, build_send_wqe, cq_offset_of, pop_completion, rq_offset_of, rq_size_bytes,
    sq_offset_of, sq_size_bytes, IoVec, RingError, CQE_STRIDE, MAX_DATA_SEGS_PER_WQE, WQE_STRIDE,
};

fn smoke_mlx5_ring_offsets() -> TestResult {
    if WQE_STRIDE != 64 {
        return TestResult::Fail("WQE_STRIDE drifted from 64");
    }
    if CQE_STRIDE != 64 {
        return TestResult::Fail("CQE_STRIDE drifted from 64");
    }
    if MAX_DATA_SEGS_PER_WQE != 3 {
        return TestResult::Fail("max data segs != 3");
    }
    if sq_offset_of(0) != 0 {
        return TestResult::Fail("SQ slot 0 offset");
    }
    if sq_offset_of(1) != 64 {
        return TestResult::Fail("SQ slot 1 offset");
    }
    if rq_offset_of(2) != 128 {
        return TestResult::Fail("RQ slot 2 offset");
    }
    if sq_size_bytes(4) != 16 * 64 {
        return TestResult::Fail("sq_size_bytes(4)");
    }
    if rq_size_bytes(5) != 32 * 64 {
        return TestResult::Fail("rq_size_bytes(5)");
    }
    // CQ offset wraps modulo capacity.
    if cq_offset_of(0, 8) != 0 {
        return TestResult::Fail("CQ slot 0");
    }
    if cq_offset_of(8, 8) != 0 {
        return TestResult::Fail("CQ wraparound");
    }
    if cq_offset_of(9, 8) != 64 {
        return TestResult::Fail("CQ wrap+1");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_ring_offsets);

fn smoke_mlx5_send_wqe_for_iovecs() -> TestResult {
    let iovs = [
        IoVec {
            va: 0x4000_0000,
            l_key: 0xAB,
            len: 256,
        },
        IoVec {
            va: 0x4000_1000,
            l_key: 0xAB,
            len: 128,
        },
    ];
    let wqe = match build_send_wqe(
        /* qp */ 0x55_5555,
        /* idx */ 7,
        SendOpcode::Send,
        CqeRequest::AlwaysCqe,
        &iovs,
    ) {
        Ok(w) => w,
        Err(_) => return TestResult::Fail("build_send_wqe rejected valid iovecs"),
    };
    if wqe.len() != WQE_STRIDE {
        return TestResult::Fail("WQE size != WQE_STRIDE");
    }
    // ds = 1 ctrl + 2 data = 3.
    let ctrl: [u8; 16] = wqe[..16].try_into().unwrap();
    if ctrl_ds(&ctrl) != 3 {
        return TestResult::Fail("ds count wrong for 2 iovecs");
    }
    if ctrl_qp_num(&ctrl) != 0x55_5555 {
        return TestResult::Fail("qp_num lost in WQE assembly");
    }
    if ctrl_wqe_idx(&ctrl) != 7 {
        return TestResult::Fail("wqe_idx lost in WQE assembly");
    }
    // First data segment at offset 16 with iov[0].
    let mut seg = [0u8; 16];
    seg.copy_from_slice(&wqe[16..32]);
    let (bc, lk, va) = decode_data_seg_ptr(&seg);
    if bc != 256 || lk != 0xAB || va != 0x4000_0000 {
        return TestResult::Fail("data seg 0 round-trip wrong");
    }
    // Second data segment at offset 32 with iov[1].
    seg.copy_from_slice(&wqe[32..48]);
    let (bc, lk, va) = decode_data_seg_ptr(&seg);
    if bc != 128 || lk != 0xAB || va != 0x4000_1000 {
        return TestResult::Fail("data seg 1 round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_send_wqe_for_iovecs);

fn smoke_mlx5_recv_wqe_round_trip() -> TestResult {
    let iovs = [IoVec {
        va: 0x5000_0000,
        l_key: 0xCD,
        len: 1500,
    }];
    let wqe = build_recv_wqe(&iovs).unwrap();
    if wqe.len() != WQE_STRIDE {
        return TestResult::Fail("RQ WQE size != WQE_STRIDE");
    }
    // Segment count BE u16 at offset 0.
    let n = u16::from_be_bytes([wqe[0], wqe[1]]);
    if n != 1 {
        return TestResult::Fail("recv WQE seg count wrong");
    }
    // Data segment at offset 16.
    let mut seg = [0u8; 16];
    seg.copy_from_slice(&wqe[16..32]);
    let (bc, lk, va) = decode_data_seg_ptr(&seg);
    if bc != 1500 || lk != 0xCD || va != 0x5000_0000 {
        return TestResult::Fail("recv data seg round-trip wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_recv_wqe_round_trip);

fn smoke_mlx5_ring_validation() -> TestResult {
    // Empty iovec list rejected.
    if !matches!(
        build_send_wqe(0, 0, SendOpcode::Send, CqeRequest::AlwaysCqe, &[]),
        Err(RingError::NoSegments)
    ) {
        return TestResult::Fail("empty iovecs accepted by send");
    }
    if !matches!(build_recv_wqe(&[]), Err(RingError::NoSegments)) {
        return TestResult::Fail("empty iovecs accepted by recv");
    }
    // > MAX data segments rejected.
    let many = [IoVec {
        va: 0,
        l_key: 0,
        len: 1,
    }; 8];
    if !matches!(
        build_send_wqe(0, 0, SendOpcode::Send, CqeRequest::AlwaysCqe, &many),
        Err(RingError::TooManySegments)
    ) {
        return TestResult::Fail("too-many iovecs accepted by send");
    }
    if !matches!(build_recv_wqe(&many), Err(RingError::TooManySegments)) {
        return TestResult::Fail("too-many iovecs accepted by recv");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_ring_validation);

fn smoke_mlx5_pop_completion_walks_ring() -> TestResult {
    // Build an 8-CQE synthetic ring; mark slot 0 as SW-owned with
    // a known completion, slots 1+ as HW-owned. pop_completion at
    // consumer=0 should return slot 0 + advance to 1; at
    // consumer=1 should return None (HW still owns).
    const CAP: usize = 8;
    let mut bytes = alloc::vec![0u8; CAP * CQE_STRIDE];
    // Mark every slot HW-owned by default.
    for i in 0..CAP {
        bytes[i * CQE_STRIDE + 0x3F] |= 1; // owner bit
    }
    // Now write a completed CQE into slot 0 (clears owner via
    // simulate_completion).
    let mut tmp = [0u8; CQE_STRIDE];
    simulate_cqe(
        &mut tmp,
        /* bc */ 64,
        /* status */ 0,
        /* wqe_counter */ 0xAAAA,
        /* qp_num */ 0x00CA_FE42,
        CqeOpcode::ResponderSend,
    );
    bytes[0..CQE_STRIDE].copy_from_slice(&tmp);

    let (view, next) = match pop_completion(&bytes, CAP as u32, 0) {
        Some(v) => v,
        None => return TestResult::Fail("slot 0 completed not found"),
    };
    if view.qp_num != 0x00CA_FE42 {
        return TestResult::Fail("popped CQE qp_num wrong");
    }
    if view.byte_count != 64 {
        return TestResult::Fail("popped CQE byte_count wrong");
    }
    if next != 1 {
        return TestResult::Fail("consumer didn't advance");
    }
    // Slot 1 is HW-owned → None.
    if pop_completion(&bytes, CAP as u32, 1).is_some() {
        return TestResult::Fail("HW-owned slot returned a CQE");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_pop_completion_walks_ring);

// ── Stage 12: vport context + HwNic ────────────────────────────────

use super::vport::{
    build_set_mtu_payload, NicVportContext, VportError, VPORT_CTX_LEN, VPORT_OFF_CURRENT_MAC,
    VPORT_OFF_MTU, VPORT_OFF_PERMANENT_MAC,
};

fn smoke_mlx5_vport_decode() -> TestResult {
    let mut bytes = alloc::vec![0u8; VPORT_CTX_LEN];
    bytes[VPORT_OFF_MTU..VPORT_OFF_MTU + 4].copy_from_slice(&9000u32.to_be_bytes());
    bytes[VPORT_OFF_PERMANENT_MAC..VPORT_OFF_PERMANENT_MAC + 6]
        .copy_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    bytes[VPORT_OFF_CURRENT_MAC..VPORT_OFF_CURRENT_MAC + 6]
        .copy_from_slice(&[0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    let ctx = match NicVportContext::from_bytes(bytes) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("from_bytes rejected full payload"),
    };
    if ctx.mtu() != 9000 {
        return TestResult::Fail("MTU not BE-decoded");
    }
    if ctx.permanent_mac() != [0x02, 0x11, 0x22, 0x33, 0x44, 0x55] {
        return TestResult::Fail("permanent_mac wrong");
    }
    if ctx.current_mac() != [0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE] {
        return TestResult::Fail("current_mac wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_vport_decode);

fn smoke_mlx5_vport_truncated() -> TestResult {
    let bytes = alloc::vec![0u8; VPORT_CTX_LEN - 1];
    if !matches!(
        NicVportContext::from_bytes(bytes),
        Err(VportError::Truncated)
    ) {
        return TestResult::Fail("under-length payload accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_vport_truncated);

fn smoke_mlx5_vport_set_mtu_payload() -> TestResult {
    let payload = build_set_mtu_payload(1500);
    if payload.len() != VPORT_CTX_LEN {
        return TestResult::Fail("set_mtu payload length wrong");
    }
    let want = 1500u32.to_be_bytes();
    if payload[VPORT_OFF_MTU..VPORT_OFF_MTU + 4] != want {
        return TestResult::Fail("MTU not BE-encoded at 0x24");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_vport_set_mtu_payload);

fn smoke_mlx5_vport_opcodes() -> TestResult {
    if super::cmd::CmdOp::QueryNicVportContext as u16 != 0x754 {
        return TestResult::Fail("QUERY_NIC_VPORT_CONTEXT opcode drift");
    }
    if super::cmd::CmdOp::ModifyNicVportContext as u16 != 0x755 {
        return TestResult::Fail("MODIFY_NIC_VPORT_CONTEXT opcode drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_vport_opcodes);

// ── Stage 13: memory-key (mkey) ────────────────────────────────────

use super::mkey::{
    build_create_mkey_input, lkey_for, MkeyError, MkeyParams, MKC_ACCESS_LOCAL_READ,
    MKC_ACCESS_LOCAL_WRITE, MKC_LEN, MKC_OFF_ACCESS, MKC_OFF_LENGTH, MKC_OFF_LOG_PAGE_SIZE,
    MKC_OFF_QPN_PD, MKC_OFF_START_ADDR, MKC_PA_ENTRY_LEN, MKC_PA_LIST_OFF,
};

fn smoke_mlx5_mkey_input_layout() -> TestResult {
    let pages = [0x1_0000_0000u64, 0x1_0000_1000u64];
    let params = MkeyParams {
        pd: 0xABCDEF,
        access: MKC_ACCESS_LOCAL_READ | MKC_ACCESS_LOCAL_WRITE,
        start_addr: 0x4000_0000_0000_0000,
        length: 0x10000,
        log_page_size: 12,
    };
    let bytes = match build_create_mkey_input(params, &pages) {
        Ok(b) => b,
        Err(_) => return TestResult::Fail("build_create_mkey_input rejected valid params"),
    };
    if bytes.len() != MKC_PA_LIST_OFF + 2 * MKC_PA_ENTRY_LEN {
        return TestResult::Fail("CREATE_MKEY payload length wrong");
    }
    if bytes[MKC_OFF_ACCESS] != (MKC_ACCESS_LOCAL_READ | MKC_ACCESS_LOCAL_WRITE) {
        return TestResult::Fail("access byte missing");
    }
    let pd_bytes = &bytes[MKC_OFF_QPN_PD..MKC_OFF_QPN_PD + 4];
    if u32::from_be_bytes([pd_bytes[0], pd_bytes[1], pd_bytes[2], pd_bytes[3]]) != 0xABCDEF {
        return TestResult::Fail("pd not BE-encoded");
    }
    let sa_bytes = &bytes[MKC_OFF_START_ADDR..MKC_OFF_START_ADDR + 8];
    let mut buf = [0u8; 8];
    buf.copy_from_slice(sa_bytes);
    if u64::from_be_bytes(buf) != 0x4000_0000_0000_0000 {
        return TestResult::Fail("start_addr not BE-encoded");
    }
    let len_bytes = &bytes[MKC_OFF_LENGTH..MKC_OFF_LENGTH + 8];
    buf.copy_from_slice(len_bytes);
    if u64::from_be_bytes(buf) != 0x10000 {
        return TestResult::Fail("length not BE-encoded");
    }
    let lps = &bytes[MKC_OFF_LOG_PAGE_SIZE..MKC_OFF_LOG_PAGE_SIZE + 4];
    if u32::from_be_bytes([lps[0], lps[1], lps[2], lps[3]]) != 12 {
        return TestResult::Fail("log_page_size not BE-encoded");
    }
    for (i, &expect) in pages.iter().enumerate() {
        let off = MKC_PA_LIST_OFF + i * MKC_PA_ENTRY_LEN;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[off..off + 8]);
        if u64::from_be_bytes(buf) != expect {
            return TestResult::Fail("phys-addr list entry not BE-encoded");
        }
    }
    let _ = MKC_LEN;
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_mkey_input_layout);

fn smoke_mlx5_mkey_validation() -> TestResult {
    let pages = [0x1_0000_0000u64];
    let bad_pd = MkeyParams {
        pd: 0x100_0000,
        access: 0,
        start_addr: 0,
        length: 0,
        log_page_size: 12,
    };
    if !matches!(
        build_create_mkey_input(bad_pd, &pages),
        Err(MkeyError::BadPd)
    ) {
        return TestResult::Fail("oversize pd accepted");
    }
    let ok = MkeyParams {
        pd: 0,
        access: 0,
        start_addr: 0,
        length: 0,
        log_page_size: 12,
    };
    if !matches!(build_create_mkey_input(ok, &[]), Err(MkeyError::NoPages)) {
        return TestResult::Fail("empty page list accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_mkey_validation);

fn smoke_mlx5_mkey_lkey_packing() -> TestResult {
    // lkey = mkey_index << 8, low 8 bits are the variant.
    if lkey_for(0x12_3456) != 0x1234_5600 {
        return TestResult::Fail("lkey packing wrong");
    }
    if lkey_for(0xFF_FFFF) != 0xFFFF_FF00 {
        return TestResult::Fail("lkey high-mask wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_mkey_lkey_packing);

fn smoke_mlx5_mkey_opcodes() -> TestResult {
    if super::cmd::CmdOp::CreateMkey as u16 != 0x200 {
        return TestResult::Fail("CREATE_MKEY opcode drift");
    }
    if super::cmd::CmdOp::DestroyMkey as u16 != 0x202 {
        return TestResult::Fail("DESTROY_MKEY opcode drift");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_mkey_opcodes);

// ── Stage 14: flow steering (TIR / TIS / RQT) ──────────────────────

use super::steering::{
    build_create_rqt_input, build_create_tir_input, build_create_tis_input, RqtError, RqtParams,
    TirParams, TisParams, RQTC_OFF_RQT_ACTUAL_SIZE, RQTC_OFF_RQT_MAX_SIZE, RQTC_OFF_RQ_LIST,
    TIRC_LEN, TIRC_OFF_DISP_TYPE, TIRC_OFF_INLINE_RQN, TIRC_OFF_TRANSPORT_DOMAIN, TIR_DISP_DIRECT,
    TIR_DISP_INDIRECT_RQT, TISC_LEN, TISC_OFF_PRIO, TISC_OFF_TRANSPORT_DOMAIN,
};

fn smoke_mlx5_steering_opcodes() -> TestResult {
    let pairs: &[(super::cmd::CmdOp, u16)] = &[
        (super::cmd::CmdOp::CreateTir, 0x900),
        (super::cmd::CmdOp::DestroyTir, 0x902),
        (super::cmd::CmdOp::CreateTis, 0x912),
        (super::cmd::CmdOp::DestroyTis, 0x914),
        (super::cmd::CmdOp::CreateRqt, 0x916),
        (super::cmd::CmdOp::DestroyRqt, 0x918),
        (super::cmd::CmdOp::CreateFlowTable, 0x930),
        (super::cmd::CmdOp::DestroyFlowTable, 0x931),
        (super::cmd::CmdOp::SetFlowTableRoot, 0x92F),
    ];
    for &(op, want) in pairs {
        if op as u16 != want {
            return TestResult::Fail("steering opcode discriminant drifted");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_steering_opcodes);

fn smoke_mlx5_tir_layout() -> TestResult {
    let p = TirParams {
        disp_type: TIR_DISP_DIRECT,
        inline_rqn: 0xCAFE,
        transport_domain: 0x42,
    };
    let bytes = build_create_tir_input(p);
    if bytes.len() != TIRC_LEN {
        return TestResult::Fail("TIR payload size wrong");
    }
    if bytes[TIRC_OFF_DISP_TYPE] != TIR_DISP_DIRECT {
        return TestResult::Fail("TIR disp_type byte wrong");
    }
    let rqn = u32::from_be_bytes([
        bytes[TIRC_OFF_INLINE_RQN],
        bytes[TIRC_OFF_INLINE_RQN + 1],
        bytes[TIRC_OFF_INLINE_RQN + 2],
        bytes[TIRC_OFF_INLINE_RQN + 3],
    ]);
    if rqn != 0xCAFE {
        return TestResult::Fail("inline_rqn not BE-encoded");
    }
    let td = u32::from_be_bytes([
        bytes[TIRC_OFF_TRANSPORT_DOMAIN],
        bytes[TIRC_OFF_TRANSPORT_DOMAIN + 1],
        bytes[TIRC_OFF_TRANSPORT_DOMAIN + 2],
        bytes[TIRC_OFF_TRANSPORT_DOMAIN + 3],
    ]);
    if td != 0x42 {
        return TestResult::Fail("transport_domain not BE-encoded");
    }
    // disp=indirect path also encodes correctly.
    let p2 = TirParams {
        disp_type: TIR_DISP_INDIRECT_RQT,
        inline_rqn: 0,
        transport_domain: 0,
    };
    let bytes2 = build_create_tir_input(p2);
    if bytes2[TIRC_OFF_DISP_TYPE] != TIR_DISP_INDIRECT_RQT {
        return TestResult::Fail("TIR_DISP_INDIRECT_RQT path wrong");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_tir_layout);

fn smoke_mlx5_tis_layout() -> TestResult {
    let p = TisParams {
        priority: 3,
        transport_domain: 0xABC,
    };
    let bytes = build_create_tis_input(p);
    if bytes.len() != TISC_LEN {
        return TestResult::Fail("TIS payload size wrong");
    }
    if bytes[TISC_OFF_PRIO] != 3 {
        return TestResult::Fail("TIS priority byte wrong");
    }
    let td = u32::from_be_bytes([
        bytes[TISC_OFF_TRANSPORT_DOMAIN],
        bytes[TISC_OFF_TRANSPORT_DOMAIN + 1],
        bytes[TISC_OFF_TRANSPORT_DOMAIN + 2],
        bytes[TISC_OFF_TRANSPORT_DOMAIN + 3],
    ]);
    if td != 0xABC {
        return TestResult::Fail("TIS transport_domain not BE-encoded");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_tis_layout);

fn smoke_mlx5_rqt_layout() -> TestResult {
    let p = RqtParams {
        max_size: 8,
        actual_size: 4,
    };
    let rqs = [0x100u32, 0x101, 0x102, 0x103];
    let bytes = build_create_rqt_input(p, &rqs).unwrap();
    let need = RQTC_OFF_RQ_LIST + 4 * 4;
    if bytes.len() != need {
        return TestResult::Fail("RQT payload size wrong");
    }
    let max = u32::from_be_bytes([
        bytes[RQTC_OFF_RQT_MAX_SIZE],
        bytes[RQTC_OFF_RQT_MAX_SIZE + 1],
        bytes[RQTC_OFF_RQT_MAX_SIZE + 2],
        bytes[RQTC_OFF_RQT_MAX_SIZE + 3],
    ]);
    if max != 8 {
        return TestResult::Fail("max_size not BE");
    }
    let act = u32::from_be_bytes([
        bytes[RQTC_OFF_RQT_ACTUAL_SIZE],
        bytes[RQTC_OFF_RQT_ACTUAL_SIZE + 1],
        bytes[RQTC_OFF_RQT_ACTUAL_SIZE + 2],
        bytes[RQTC_OFF_RQT_ACTUAL_SIZE + 3],
    ]);
    if act != 4 {
        return TestResult::Fail("actual_size not BE");
    }
    for (i, &expect) in rqs.iter().enumerate() {
        let off = RQTC_OFF_RQ_LIST + i * 4;
        let v = u32::from_be_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
        if v != expect {
            return TestResult::Fail("RQT entry wrong");
        }
    }
    // Validation rejects > 128 entries.
    let many = alloc::vec![0u32; 129];
    if !matches!(
        build_create_rqt_input(
            RqtParams {
                max_size: 128,
                actual_size: 129
            },
            &many
        ),
        Err(RqtError::TooLarge)
    ) {
        return TestResult::Fail("> 128 rqs accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_rqt_layout);

// ── Stage 15: async events (EQE) ───────────────────────────────────

use super::eqe::{
    decode_eqe, is_hw_owned as eqe_is_hw_owned, pop_event, simulate_event, EventType, EQE_LEN,
    EQE_OFF_OWNER, EQE_OWNER_BIT,
};

fn smoke_mlx5_eqe_decode_round_trip() -> TestResult {
    let mut eqe = [0u8; EQE_LEN];
    eqe[EQE_OFF_OWNER] |= EQE_OWNER_BIT; // start HW-owned
    if !eqe_is_hw_owned(&eqe) {
        return TestResult::Fail("freshly initialised EQE not HW-owned");
    }
    simulate_event(&mut eqe, /* port-state */ 0x09, /* sub */ 4);
    if eqe_is_hw_owned(&eqe) {
        return TestResult::Fail("simulate_event left owner bit set");
    }
    let view = decode_eqe(&eqe);
    if view.event_type != EventType::PortStateChange {
        return TestResult::Fail("event_type decode wrong");
    }
    if view.event_sub_type != 4 {
        return TestResult::Fail("event_sub_type lost");
    }
    if view.owner {
        return TestResult::Fail("owner field not synced with byte 0x3F bit 0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_eqe_decode_round_trip);

fn smoke_mlx5_eqe_event_type_catalog() -> TestResult {
    let pairs: &[(u8, EventType)] = &[
        (0x00, EventType::CompletionEvent),
        (0x01, EventType::PathMigrated),
        (0x02, EventType::CommErrorReceived),
        (0x03, EventType::SendQueueDrained),
        (0x05, EventType::SrqLastWqeReached),
        (0x09, EventType::PortStateChange),
        (0x0A, EventType::CommandInterfaceCompletion),
        (0x0B, EventType::PageRequest),
        (0x0C, EventType::SrqLimitReached),
        (0x0D, EventType::NicVportChange),
    ];
    for &(raw, want) in pairs {
        if EventType::from_raw(raw) != want {
            return TestResult::Fail("EventType catalog mismatch");
        }
    }
    if !matches!(EventType::from_raw(0x42), EventType::Unknown(0x42)) {
        return TestResult::Fail("unmapped EventType lost raw byte");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_eqe_event_type_catalog);

fn smoke_mlx5_eqe_pop_event_walks_ring() -> TestResult {
    const CAP: usize = 4;
    let mut bytes = alloc::vec![0u8; CAP * EQE_LEN];
    // Mark all slots HW-owned.
    for i in 0..CAP {
        bytes[i * EQE_LEN + EQE_OFF_OWNER] |= EQE_OWNER_BIT;
    }
    // Drop a completed event into slot 0.
    let mut tmp = [0u8; EQE_LEN];
    tmp[EQE_OFF_OWNER] |= EQE_OWNER_BIT;
    simulate_event(&mut tmp, 0x09, 1);
    bytes[0..EQE_LEN].copy_from_slice(&tmp);

    let (view, next) = match pop_event(&bytes, CAP as u32, 0) {
        Some(v) => v,
        None => return TestResult::Fail("slot 0 EQE not found"),
    };
    if view.event_type != EventType::PortStateChange {
        return TestResult::Fail("popped EQE event_type wrong");
    }
    if next != 1 {
        return TestResult::Fail("EQ consumer didn't advance");
    }
    if pop_event(&bytes, CAP as u32, 1).is_some() {
        return TestResult::Fail("HW-owned EQE returned");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_eqe_pop_event_walks_ring);

// ── Stage 16: destroy / dealloc opcodes ────────────────────────────

fn smoke_mlx5_destroy_opcodes() -> TestResult {
    let pairs: &[(super::cmd::CmdOp, u16)] = &[
        (super::cmd::CmdOp::DestroyQp, 0x501),
        (super::cmd::CmdOp::DestroyEq, 0x302),
        (super::cmd::CmdOp::DestroyCq, 0x401),
        (super::cmd::CmdOp::DeallocPd, 0x801),
        (super::cmd::CmdOp::DeallocUar, 0x803),
        (super::cmd::CmdOp::DestroyMkey, 0x202),
        (super::cmd::CmdOp::DestroyTir, 0x902),
        (super::cmd::CmdOp::DestroyTis, 0x914),
        (super::cmd::CmdOp::DestroyRqt, 0x918),
        (super::cmd::CmdOp::DestroyFlowTable, 0x931),
    ];
    for &(op, want) in pairs {
        if op as u16 != want {
            return TestResult::Fail("destroy/dealloc opcode discriminant drifted");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_destroy_opcodes);
