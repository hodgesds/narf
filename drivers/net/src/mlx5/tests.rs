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

// ── Stage 3: DMA mailbox + cmdq programming ────────────────────────

use super::cmd::{
    build_cqe_with_mailboxes, build_mailbox_block,
    MAILBOX_BLOCK_LEN, MAILBOX_PAYLOAD_LEN, MAILBOX_OFF_BLOCK_NUM,
    MAILBOX_OFF_NEXT_H, MAILBOX_OFF_NEXT_L, MAILBOX_OFF_SIGNATURE,
    MAILBOX_OFF_TOKEN, MAILBOX_PHYS_ALIGN_MASK,
};
use super::cmd::{
    CQE_OFF_INPUT_LEN, CQE_OFF_INPUT_MB_H, CQE_OFF_INPUT_MB_L,
    CQE_OFF_OUTPUT_LEN, CQE_OFF_OUTPUT_MB_H, CQE_OFF_OUTPUT_MB_L,
};

fn smoke_mlx5_cqe_mailbox_phys_be_encoded() -> TestResult {
    // Choose a 64-bit phys addr with a non-zero high half; the
    // low 9 bits are deliberately set to confirm they get masked
    // off (mailbox phys must be 512-B aligned).
    let in_phys:  u64 = 0x0000_0001_DEAD_BEFFu64;
    let out_phys: u64 = 0x0000_0002_CAFE_F1FFu64;
    let cqe = build_cqe_with_mailboxes(
        CmdOp::QueryHcaCap, 0xAABB_CCDD,
        in_phys,  0x100,
        out_phys, 0x200,
        0x77,
    );
    let want_in_h  = ((in_phys  >> 32) as u32).to_be_bytes();
    let want_in_l  = ((in_phys  & MAILBOX_PHYS_ALIGN_MASK) as u32).to_be_bytes();
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
    let want_in_len  = 0x100u32.to_be_bytes();
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
    for &b in cqe.iter() { xor ^= b; }
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
    payload[0]   = 0xAA;
    payload[479] = 0xBB;
    let next_phys: u64 = 0x0000_0003_FACE_F00Du64;
    let block = build_mailbox_block(&payload, /* num */ 7, /* tok */ 0x33, next_phys);
    if block.len() != MAILBOX_BLOCK_LEN {
        return TestResult::Fail("mailbox block size != 512 B");
    }
    if block[0]   != 0xAA { return TestResult::Fail("payload byte 0 dropped"); }
    if block[479] != 0xBB { return TestResult::Fail("payload byte 479 dropped"); }
    // No payload bleed past 480 (offsets 0x1E0..0x1EF are payload's
    // tail, but we put 0 there — it should still be 0).
    for i in 480..MAILBOX_OFF_NEXT_H {
        if block[i] != 0 {
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
    if block[MAILBOX_OFF_BLOCK_NUM] != 0
       || block[MAILBOX_OFF_BLOCK_NUM + 1] != 7 {
        return TestResult::Fail("block_number not BE-encoded at 0x1FC");
    }
    if block[MAILBOX_OFF_TOKEN] != 0x33 {
        return TestResult::Fail("token byte at 0x1FE wrong");
    }
    // Signature is XOR-checksum; XOR-of-all should be 0.
    let mut xor = 0u8;
    for &b in block.iter() { xor ^= b; }
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
    for i in 0..MAILBOX_PAYLOAD_LEN {
        if block[i] != 0xCC {
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

use super::mailbox::{
    block_count_for, read_output_chain, write_input_chain,
};

fn smoke_mlx5_chain_block_count() -> TestResult {
    if block_count_for(0)   != 1 { return TestResult::Fail("0-byte payload should still need 1 block"); }
    if block_count_for(1)   != 1 { return TestResult::Fail("1-byte payload should fit in 1 block"); }
    if block_count_for(MAILBOX_PAYLOAD_LEN)     != 1
       { return TestResult::Fail("exactly 480 bytes should fit in 1 block"); }
    if block_count_for(MAILBOX_PAYLOAD_LEN + 1) != 2
       { return TestResult::Fail("481 bytes should need 2 blocks"); }
    if block_count_for(2 * MAILBOX_PAYLOAD_LEN) != 2
       { return TestResult::Fail("960 bytes should need 2 blocks"); }
    if block_count_for(2 * MAILBOX_PAYLOAD_LEN + 1) != 3
       { return TestResult::Fail("961 bytes should need 3 blocks"); }
    // 0x1000 = QUERY_HCA_CAP output → ceil(4096 / 480) = 9 blocks.
    if block_count_for(0x1000) != 9
       { return TestResult::Fail("4096-byte payload should need 9 blocks"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_chain_block_count);

fn smoke_mlx5_chain_input_round_trip() -> TestResult {
    // Build a 1000-byte payload with a recognisable byte pattern,
    // run it through write_input_chain → read_output_chain, and
    // confirm we get the same bytes back.
    const N: usize = 1000;
    let mut payload = [0u8; N];
    for i in 0..N { payload[i] = (i & 0xFF) as u8; }
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
        let want_next = if i + 1 < n_blocks { block_phys[i + 1] } else { 0 };
        let h_bytes = ((want_next >> 32) as u32).to_be_bytes();
        let l_bytes = ((want_next & 0xFFFF_FFFF) as u32).to_be_bytes();
        if blocks[i][0x1F0..0x1F4] != h_bytes
           || blocks[i][0x1F4..0x1F8] != l_bytes {
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
        for &b in blocks[i].iter() { xor ^= b; }
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
    if blocks[0][0x1F0..0x1F4] != want_h
       || blocks[0][0x1F4..0x1F8] != want_l {
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
    for i in 0..MAILBOX_PAYLOAD_LEN {
        if out[i] != 0xAA {
            return TestResult::Fail("block 0 payload miscopied");
        }
    }
    for i in MAILBOX_PAYLOAD_LEN..700 {
        if out[i] != 0xBB {
            return TestResult::Fail("block 1 payload miscopied");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_chain_short_output_truncates);

// HcaCapGroup discriminants are stable wire values — guard them.
fn smoke_mlx5_hca_cap_group_discriminants() -> TestResult {
    use super::HcaCapGroup;
    if HcaCapGroup::GeneralDevice  as u16 != 0x0 { return TestResult::Fail("GeneralDevice"); }
    if HcaCapGroup::EthernetOffload as u16 != 0x1 { return TestResult::Fail("EthernetOffload"); }
    if HcaCapGroup::Atomic         as u16 != 0x3 { return TestResult::Fail("Atomic"); }
    if HcaCapGroup::Roce           as u16 != 0x4 { return TestResult::Fail("Roce"); }
    if HcaCapGroup::IpoibOffloads  as u16 != 0x5 { return TestResult::Fail("IpoibOffloads"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_hca_cap_group_discriminants);

// ── Stage 5: typed cap decoders ────────────────────────────────────

use super::caps::{
    CapsDecodeError, EthernetOffloadCaps, HcaGeneralCaps,
    HCA_CAP_OFF_LOG_MAX_CQ_SZ, HCA_CAP_OFF_LOG_MAX_EQ_SZ,
    HCA_CAP_OFF_LOG_MAX_MKEY, HCA_CAP_OFF_LOG_MAX_PD,
    HCA_CAP_OFF_LOG_MAX_QP_SZ, HCA_CAP_OFF_LOG_MAX_SRQ_SZ,
    HCA_CAP_OFF_VHCA_ID, HCA_CAP_OUT_LEN,
    ETH_OFF_LRO, ETH_OFF_LSO, ETH_OFF_MAX_LSO_SIZE, ETH_OFF_RSS_IND_TBL,
    ETH_OFF_RX_CSUM, ETH_OFF_TX_CSUM, ETH_OFF_VLAN_INSERT,
    ETH_OFF_VLAN_STRIP,
};

fn smoke_mlx5_general_caps_decode() -> TestResult {
    let mut bytes = alloc::vec![0u8; HCA_CAP_OUT_LEN];
    bytes[HCA_CAP_OFF_VHCA_ID]        = 0x12; // BE u16
    bytes[HCA_CAP_OFF_VHCA_ID + 1]    = 0x34;
    bytes[HCA_CAP_OFF_LOG_MAX_SRQ_SZ] = 16;
    bytes[HCA_CAP_OFF_LOG_MAX_QP_SZ]  = 17;
    bytes[HCA_CAP_OFF_LOG_MAX_CQ_SZ]  = 23;
    bytes[HCA_CAP_OFF_LOG_MAX_EQ_SZ]  = 21;
    bytes[HCA_CAP_OFF_LOG_MAX_MKEY]   = 24;
    bytes[HCA_CAP_OFF_LOG_MAX_PD]     = 15;
    let caps = match HcaGeneralCaps::from_bytes(bytes) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("HcaGeneralCaps::from_bytes rejected a full payload"),
    };
    if caps.vhca_id() != 0x1234 { return TestResult::Fail("vhca_id BE decode wrong"); }
    if caps.log_max_srq_sz() != 16 { return TestResult::Fail("log_max_srq_sz wrong"); }
    if caps.log_max_qp_sz()  != 17 { return TestResult::Fail("log_max_qp_sz wrong"); }
    if caps.log_max_cq_sz()  != 23 { return TestResult::Fail("log_max_cq_sz wrong"); }
    if caps.log_max_eq_sz()  != 21 { return TestResult::Fail("log_max_eq_sz wrong"); }
    if caps.log_max_mkey()   != 24 { return TestResult::Fail("log_max_mkey wrong"); }
    if caps.log_max_pd()     != 15 { return TestResult::Fail("log_max_pd wrong"); }
    if caps.raw().len()      != HCA_CAP_OUT_LEN
       { return TestResult::Fail("raw() length not preserved"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_general_caps_decode);

fn smoke_mlx5_general_caps_truncated() -> TestResult {
    // A buffer shorter than the highest committed offset (0x68)
    // must be rejected.
    let bytes = alloc::vec![0u8; HCA_CAP_OFF_LOG_MAX_PD];
    match HcaGeneralCaps::from_bytes(bytes) {
        Err(CapsDecodeError::Truncated) => TestResult::Pass,
        _ => TestResult::Fail(
            "from_bytes accepted a buffer too short for log_max_pd"),
    }
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_general_caps_truncated);

fn smoke_mlx5_ethernet_offload_caps_decode() -> TestResult {
    let mut bytes = alloc::vec![0u8; HCA_CAP_OUT_LEN];
    bytes[ETH_OFF_TX_CSUM]     = 1;
    bytes[ETH_OFF_RX_CSUM]     = 1;
    bytes[ETH_OFF_LSO]         = 1;
    bytes[ETH_OFF_LRO]         = 0;
    bytes[ETH_OFF_RSS_IND_TBL] = 1;
    bytes[ETH_OFF_VLAN_INSERT] = 1;
    bytes[ETH_OFF_VLAN_STRIP]  = 0;
    // max_lso_size = 65536 BE.
    bytes[ETH_OFF_MAX_LSO_SIZE..ETH_OFF_MAX_LSO_SIZE + 4]
        .copy_from_slice(&65536u32.to_be_bytes());
    let caps = match EthernetOffloadCaps::from_bytes(bytes) {
        Ok(c) => c,
        Err(_) => return TestResult::Fail("EthernetOffloadCaps rejected full payload"),
    };
    if !caps.supports_tx_csum()        { return TestResult::Fail("tx_csum"); }
    if !caps.supports_rx_csum()        { return TestResult::Fail("rx_csum"); }
    if !caps.supports_lso()            { return TestResult::Fail("lso"); }
    if  caps.supports_lro()            { return TestResult::Fail("lro should be off"); }
    if !caps.supports_rss()            { return TestResult::Fail("rss"); }
    if !caps.supports_vlan_insert()    { return TestResult::Fail("vlan_insert"); }
    if  caps.supports_vlan_strip()     { return TestResult::Fail("vlan_strip should be off"); }
    if  caps.max_lso_size() != 65536   { return TestResult::Fail("max_lso_size BE wrong"); }
    TestResult::Pass
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_ethernet_offload_caps_decode);

fn smoke_mlx5_ethernet_offload_caps_truncated() -> TestResult {
    let bytes = alloc::vec![0u8; ETH_OFF_VLAN_STRIP];
    match EthernetOffloadCaps::from_bytes(bytes) {
        Err(CapsDecodeError::Truncated) => TestResult::Pass,
        _ => TestResult::Fail(
            "EthernetOffloadCaps accepted a buffer too short"),
    }
}
kernel_test_in!("drivers/net/mlx5", smoke_mlx5_ethernet_offload_caps_truncated);

// ── Stage 6: bit_field + bit-packed caps + EQ context ──────────────

use super::bit_field::{read_bits_be, write_bits_be};
use super::eq::{
    build_create_eq_input, decode_create_eq_input, EqError, EqParams,
    EQC_LEN, EQC_OFF_INTR_VECTOR, EQC_OFF_LOG_PAGE_SIZE,
    EQC_PA_ENTRY_LEN, EQC_PA_LIST_OFF,
};
use super::caps::{
    HCA_CAP_BIT_LOG_MAX_EQ, HCA_CAP_BIT_LOG_MAX_EQ_W,
    HCA_CAP_BIT_LOG_MAX_QP, HCA_CAP_BIT_LOG_MAX_QP_W,
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
    if v != 0xBC { return TestResult::Fail("byte-aligned-after-nibble wrong"); }
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
    let v1 = read_bits_be(&bytes,  5, 12);
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
    write_bits_be(&mut bytes,
        HCA_CAP_BIT_LOG_MAX_QP, HCA_CAP_BIT_LOG_MAX_QP_W, 27);
    write_bits_be(&mut bytes,
        HCA_CAP_BIT_LOG_MAX_EQ, HCA_CAP_BIT_LOG_MAX_EQ_W, 8);
    // log_max_pd offset 0x68 is the highest committed offset; pad
    // the buffer so from_bytes() doesn't reject it.
    let caps = match super::caps::HcaGeneralCaps::from_bytes(bytes) {
        Ok(c)  => c,
        Err(_) => return TestResult::Fail(
            "HcaGeneralCaps from_bytes rejected 0x100-byte payload"),
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
        log_eq_size:    7,
        uar_page:       0xABCDEF,
        intr_vector:    9,
        log_page_size:  12,
    };
    let bytes = match build_create_eq_input(params, &pages) {
        Ok(b)  => b,
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
    if back.log_eq_size  != params.log_eq_size
       || back.uar_page     != params.uar_page
       || back.intr_vector  != params.intr_vector
       || back.log_page_size != params.log_page_size {
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
    let bad_size = EqParams { log_eq_size: 32, uar_page: 0,
                              intr_vector: 0, log_page_size: 12 };
    if !matches!(build_create_eq_input(bad_size, &pages), Err(EqError::BadLogEqSize)) {
        return TestResult::Fail("oversize log_eq_size accepted");
    }
    // uar_page > 0xFFFFFF → BadUarPage.
    let bad_uar = EqParams { log_eq_size: 7, uar_page: 0x100_0000,
                             intr_vector: 0, log_page_size: 12 };
    if !matches!(build_create_eq_input(bad_uar, &pages), Err(EqError::BadUarPage)) {
        return TestResult::Fail("oversize uar_page accepted");
    }
    // empty pages → NoPages.
    let ok_params = EqParams { log_eq_size: 7, uar_page: 0,
                               intr_vector: 0, log_page_size: 12 };
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
