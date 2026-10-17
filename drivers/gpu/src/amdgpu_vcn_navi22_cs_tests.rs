//! Model tests for the Navi22 media CS checks (`vcn_v3_0_dec_msg`,
//! `amdgpu_jpeg_dec_parse_cs`, the session table) and for the media ring
//! frames against Linux's emit order, written out here with literal opcodes
//! from vcn_v2_0.c / jpeg_v2_0.c / gmc_v10_0.c rather than the module's
//! constants.
use super::*;
use crate::amdgpu_navi22_submit::{encode_media, Ib, MediaFrame, VmRef};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

/// A client buffer: byte offset from the message start -> dword.
fn reader(words: &[u32]) -> impl Fn(u64) -> Option<u32> + '_ {
    move |at| {
        if at % 4 != 0 {
            return None;
        }
        words.get((at / 4) as usize).copied()
    }
}
/// Mesa's create message (`rvcn_dec_message_header` + one create buffer
/// index entry + `rvcn_dec_message_create`), handle `h`, codec `codec`.
fn create_msg(h: u32, codec: u32) -> Vec<u32> {
    let mut m = vec![0u32; 64];
    // header_size, total_size, num_buffers, msg_type, stream_handle, fb#
    m[..6].copy_from_slice(&[0x28, 0x38, 1, MSG_CREATE, h, 0]);
    // index: message_id, offset, size, filled
    m[6..10].copy_from_slice(&[MESSAGE_CREATE, 0x28, 0x10, 0]);
    // create: stream_type, session_flags, width, height
    m[10..14].copy_from_slice(&[codec, 0, 1920, 1088]);
    m
}

fn vcn_navi22_cs_decode_ib_scan_matches_patch_cs_in_place() -> TestResult {
    // Mesa radeon_vcn_dec send_cmd: DATA0 lo, DATA1 hi, CMD (msg buffer = 0)
    // then a feedback/bitstream command (CMD != 0) that is not a message.
    let ib = [
        0x10,
        0x0010_0000,
        0x11,
        0x7000,
        0x0f,
        0, // message at 0x7000_0010_0000
        0x10,
        0x0020_0000,
        0x11,
        0x7000,
        0x0f,
        0x2, // bitstream: CMD 1 << 1
        0x29,
        0, // NOP
    ];
    let found = dec_ib_messages(&ib);
    if found != [0x7000_0010_0000] {
        return TestResult::Fail("message addresses from DATA0/DATA1/CMD 0");
    }
    // A trailing odd dword reads its value as 0 (Linux reads past it).
    if dec_ib_messages(&[0x10, 4, 0x11, 0, 0x0f]) != [4] {
        return TestResult::Fail("odd-length IB scan");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_cs_decode_ib_scan_matches_patch_cs_in_place
);

fn vcn_navi22_cs_decode_message_checks_match_vcn_v3_0_dec_msg() -> TestResult {
    let good = create_msg(0x55, 0x7);
    let avail = (good.len() * 4) as u64;
    let ok = check_dec_msg(0x1000, avail, reader(&good), false);
    if ok
        != Ok(Message {
            kind: MSG_CREATE,
            handle: 0x55,
        })
    {
        return TestResult::Fail("well-formed H.264 create message refused");
    }
    let mut cases: Vec<(&str, u64, u64, Vec<u32>, MsgError)> = Vec::new();
    cases.push((
        "misaligned",
        0x1004,
        avail,
        good.clone(),
        MsgError::Misaligned,
    ));
    cases.push(("12 bytes", 0x1000, 12, good.clone(), MsgError::TooShort));
    let mut big = good.clone();
    big[1] = avail as u32 + 4;
    cases.push((
        "header past BO",
        0x1000,
        avail,
        big,
        MsgError::HeaderOverflow,
    ));
    let mut many = good.clone();
    many[2] = 3; // 6 + 3*4 = 18 dwords > 0x38/4 = 14
    cases.push((
        "buffers past length",
        0x1000,
        avail,
        many,
        MsgError::TooManyBuffers,
    ));
    let mut wrap = good.clone();
    wrap[1] = 0x40;
    wrap[2] = 0x4000_0000; // num_buffers > len_dw
    cases.push((
        "num_buffers > len_dw",
        0x1000,
        avail,
        wrap,
        MsgError::TooManyBuffers,
    ));
    let mut oob = good.clone();
    oob[7] = avail as u32 - 8; // offset + 16 > avail
    cases.push((
        "create buffer past BO",
        0x1000,
        avail,
        oob,
        MsgError::BufferOutOfBounds,
    ));
    let mut small = good.clone();
    small[8] = 3;
    cases.push((
        "create buffer < 4 bytes",
        0x1000,
        avail,
        small,
        MsgError::BufferOutOfBounds,
    ));
    let mut overflow = good.clone();
    overflow[7] = u32::MAX - 2;
    cases.push((
        "offset + size overflow",
        0x1000,
        avail,
        overflow,
        MsgError::BufferOutOfBounds,
    ));
    for (_name, addr, avail, words, want) in &cases {
        if check_dec_msg(*addr, *avail, reader(words), false) != Err(*want) {
            return TestResult::Fail("malformed decode message accepted or misclassified");
        }
    }
    // Non-create messages are passed after the header checks only.
    let mut decode = good.clone();
    decode[3] = MSG_DECODE;
    decode[2] = 1000;
    if check_dec_msg(0x1000, avail, reader(&decode), false)
        != Ok(Message {
            kind: MSG_DECODE,
            handle: 0x55,
        })
    {
        return TestResult::Fail("decode message header handling");
    }
    // vcn_v3_0_limit_sched: AV1 (0x13) needs VCN0; H.264/HEVC/VP9 do not.
    let av1 = create_msg(9, 0x13);
    let hevc = create_msg(9, 0x10);
    if check_dec_msg(0, avail, reader(&av1), true) != Err(MsgError::NeedsVcn0)
        || check_dec_msg(0, avail, reader(&av1), false).is_err()
        || check_dec_msg(0, avail, reader(&hevc), true).is_err()
    {
        return TestResult::Fail("limit_sched codec routing");
    }
    // A buffer index that is not a create entry is skipped.
    let mut other = good.clone();
    other[6] = 2;
    other[7] = u32::MAX;
    if check_dec_msg(0, avail, reader(&other), false).is_err() {
        return TestResult::Fail("non-create buffer index checked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_cs_decode_message_checks_match_vcn_v3_0_dec_msg
);

fn vcn_navi22_cs_sessions_follow_uvd_handle_rules() -> TestResult {
    let mut s = Sessions::new();
    let m = |kind, handle| Message { kind, handle };
    let (a, b) = (11, 22);
    if s.apply(m(MSG_CREATE, 1), a).is_err()
        || s.apply(m(MSG_CREATE, 1), b) != Err(SessionError::Invalid)
        || s.apply(m(MSG_CREATE, 1), a) != Err(SessionError::Invalid)
        || s.apply(m(MSG_DECODE, 1), a).is_err()
    {
        return TestResult::Fail("create / duplicate / own decode");
    }
    // Wrong session: another client's handle, or one never created.
    if s.apply(m(MSG_DECODE, 1), b) != Err(SessionError::Invalid)
        || s.apply(m(MSG_DESTROY, 1), b) != Err(SessionError::Invalid)
        || s.apply(m(MSG_DECODE, 2), a) != Err(SessionError::Unknown)
        || s.apply(m(MSG_CREATE, 0), a) != Err(SessionError::Invalid)
        || s.apply(m(7, 1), a) != Err(SessionError::Invalid)
    {
        return TestResult::Fail("cross-client or unknown session accepted");
    }
    if s.apply(m(MSG_DESTROY, 1), a).is_err()
        || s.count() != 0
        || s.apply(m(MSG_DESTROY, 1), a).is_err()
        || s.apply(m(MSG_DECODE, 1), a) != Err(SessionError::Unknown)
    {
        return TestResult::Fail("destroy frees the handle");
    }
    for h in 1..=MAX_SESSIONS as u32 {
        if s.apply(m(MSG_CREATE, h), if h % 2 == 0 { a } else { b })
            .is_err()
        {
            return TestResult::Fail("filling the session table");
        }
    }
    if s.apply(m(MSG_CREATE, 1000), a) != Err(SessionError::Full) {
        return TestResult::Fail("session limit (ENOSPC)");
    }
    s.forget(a);
    if s.count() != MAX_SESSIONS / 2 || s.apply(m(MSG_CREATE, 1000), a).is_err() {
        return TestResult::Fail("closing a client frees its sessions only");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_cs_sessions_follow_uvd_handle_rules
);

fn vcn_navi22_cs_jpeg_parse_matches_amdgpu_jpeg_dec_parse_cs() -> TestResult {
    let pj =
        |reg: u32, res: u32, cond: u32, kind: u32| reg | (res << 18) | (cond << 24) | (kind << 28);
    let good = [
        pj(0x4000, 0, 0, 0),
        1,
        pj(0x41c2, 0, 0, 0),
        2,
        pj(0x4089, 0, 3, 3),
        3,
        0x6000_0000,
        0, // CP_PACKETJ_NOP
    ];
    if parse_jpeg_ib(&good).is_err() {
        return TestResult::Fail("valid JPEG IB refused");
    }
    for bad in [
        [pj(0x3fff, 0, 0, 0), 0],  // below the JPEG window
        [pj(0x41c3, 0, 0, 0), 0],  // above it
        [pj(0x4120, 0, 0, 0), 0],  // atomic range start
        [pj(0x412a, 0, 3, 3), 0],  // atomic range end
        [pj(0x4000, 1, 0, 0), 0],  // reserved bits
        [pj(0x4000, 0, 1, 0), 0],  // type 0 needs condition 0
        [pj(0x4000, 0, 0, 3), 0],  // type 3 needs condition 3
        [pj(0x4000, 0, 0, 2), 0],  // type 2 (kernel-only)
        [pj(0x0001, 0, 0, 6), 0],  // type 6 other than the NOP
        [pj(0, 0, 0, 7), 0],       // type 7 (kernel trap packet)
        [pj(0x1bfff, 0, 0, 0), 0], // JRBC external register (kernel only)
    ] {
        if parse_jpeg_ib(&bad) != Err(MsgError::JpegPacket) {
            return TestResult::Fail("forbidden JPEG packet accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_cs_jpeg_parse_matches_amdgpu_jpeg_dec_parse_cs
);

const MMHUB: u32 = 0x1a000;
/// OSSSYS segment 0 (0x10a0) + mmIH_VMID_0_LUT_MM (0x10) + VMID 3.
const LUT: u32 = 0x10a0 + 0x10 + 3;
const PTB: u64 = 0x0000_0001_2345_6001;
fn vm(vmid: u8) -> VmRef {
    VmRef {
        vmid,
        page_table_base: PTB,
        pasid: 0x42,
        flush: true,
        map_pasid: true,
    }
}

/// Linux, one function per emitter, with literal opcodes.
mod linux {
    use alloc::vec::Vec;
    pub fn p0(reg: u32) -> u32 {
        reg
    }
    // vcn_v2_0_dec_ring_emit_wreg / _reg_wait
    pub fn dec_wreg(w: &mut Vec<u32>, reg: u32, val: u32) {
        w.extend([
            p0(0x10),
            reg << 2,
            p0(0x11),
            val,
            p0(0x0f),
            0x8000_0000 | (4 << 1),
        ]);
    }
    pub fn dec_wait(w: &mut Vec<u32>, reg: u32, val: u32, mask: u32) {
        w.extend([
            p0(0x10),
            reg << 2,
            p0(0x11),
            val,
            p0(0x66),
            mask,
            p0(0x0f),
            0x8000_0000 | (6 << 1),
        ]);
    }
    pub fn enc_wreg(w: &mut Vec<u32>, reg: u32, val: u32) {
        w.extend([0xb, reg << 2, val]);
    }
    pub fn enc_wait(w: &mut Vec<u32>, reg: u32, val: u32, mask: u32) {
        w.extend([0xc, reg << 2, mask, val]);
    }
    pub fn pj(reg: u32, cond: u32, kind: u32) -> u32 {
        reg | (cond << 24) | (kind << 28)
    }
    pub fn jpeg_wreg(w: &mut Vec<u32>, reg: u32, val: u32) {
        let off = reg << 2;
        w.push(pj(0x1bfff, 0, 0));
        if (0x10000..=0x105ff).contains(&off) {
            w.extend([0, pj(off >> 2, 0, 0)]);
        } else {
            w.extend([off, pj(0x18000, 0, 0)]);
        }
        w.push(val);
    }
    pub fn jpeg_wait(w: &mut Vec<u32>, reg: u32, val: u32, mask: u32) {
        let off = reg << 2;
        w.extend([
            pj(0x4085, 0, 0),
            0x0140_0200,
            pj(0x4084, 0, 0),
            val,
            pj(0x1bfff, 0, 0),
        ]);
        if (0x10000..=0x105ff).contains(&off) {
            w.extend([0, pj(off >> 2, 0, 3)]);
        } else {
            w.extend([off, pj(0x18000, 0, 3)]);
        }
        w.push(mask);
    }
    /// gmc_v10_0_emit_flush_gpu_tlb (MMHUB: semaphore) + the ring's tail.
    pub fn flush(
        w: &mut Vec<u32>,
        wreg: fn(&mut Vec<u32>, u32, u32),
        wait: fn(&mut Vec<u32>, u32, u32, u32),
        mmhub: u32,
        eng: u32,
        vmid: u32,
        pd: u64,
    ) {
        let req = (1 << vmid) | (1 << 19) | (1 << 20) | (1 << 21) | (1 << 22) | (1 << 23);
        wait(w, mmhub + 0x6d1 + eng, 1, 1);
        wreg(w, mmhub + 0x72b + 2 * vmid, pd as u32);
        wreg(w, mmhub + 0x72c + 2 * vmid, (pd >> 32) as u32);
        wreg(w, mmhub + 0x6e3 + eng, req);
        wait(w, mmhub + 0x6f5 + eng, 1 << vmid, 1 << vmid);
        wreg(w, mmhub + 0x6d1 + eng, 0);
        wait(w, mmhub + 0x72b + 2 * vmid, pd as u32, 0xffff_ffff);
    }
}

fn vcn_navi22_cs_media_frames_follow_linux_emit_order() -> TestResult {
    use linux::*;
    let fence = 0x8_0080_3000u64;
    let frame = |ring, flush: bool, ibs: &'static [Ib]| MediaFrame {
        ring,
        mmhub: MMHUB,
        engine: ring.inv_engine(1),
        flush: flush.then_some(vm(3)),
        pasid_map: flush.then_some((LUT, 0x42)),
        vmid: 3,
        ibs,
        fence,
        seq: 9,
        ring_base: 0x8_0090_0000,
    };
    static IBS: [Ib; 2] = [
        Ib {
            va: 0x7000_0010_0000,
            dwords: 64,
        },
        Ib {
            va: 0x7000_0020_0040,
            dwords: 16,
        },
    ];
    // Decode: insert_start, flush, insert_start, IBs, fence, insert_end.
    let mut want = Vec::new();
    let start = [p0(0x10), 0, p0(0x0f), 0x8000_0000 | (0xa << 1)];
    want.extend(start);
    flush(&mut want, dec_wreg, dec_wait, MMHUB, 0, 3, PTB);
    dec_wreg(&mut want, LUT, 0x42); // gmc_v10_0_emit_pasid_mapping (_LUT_MM)
    want.extend(start);
    for ib in &IBS {
        want.extend([
            p0(0x431),
            3,
            p0(0x3b4),
            ib.va as u32,
            p0(0x3b5),
            (ib.va >> 32) as u32,
            p0(0x25c),
            ib.dwords,
        ]);
    }
    want.extend([
        p0(0x27),
        9,
        p0(0x10),
        fence as u32,
        p0(0x11),
        (fence >> 32) as u32 & 0xff,
        p0(0x0f),
        0x8000_0000,
        p0(0x10),
        0,
        p0(0x11),
        0,
        p0(0x0f),
        0x8000_0002,
        p0(0x0f),
        0x8000_0000 | (0xb << 1),
    ]);
    if encode_media(&frame(MediaRing::Dec, true, &IBS)) != want {
        return TestResult::Fail("decode frame differs from amdgpu_ib_schedule on vcn_v3_0 dec");
    }
    // Without a flush: start, IBs, fence, end only.
    let unflushed = encode_media(&frame(MediaRing::Dec, false, &IBS));
    if unflushed.len() != 4 + 16 + 14 + 2 || unflushed[4] != p0(0x431) {
        return TestResult::Fail("decode frame without flush");
    }
    // Encode ring 0 (MMHUB engine 1): flush, IB, fence + trap, end.
    let mut want = Vec::new();
    flush(&mut want, enc_wreg, enc_wait, MMHUB, 1, 3, PTB);
    enc_wreg(&mut want, LUT, 0x42);
    for ib in &IBS {
        want.extend([2, 3, ib.va as u32, (ib.va >> 32) as u32, ib.dwords]);
    }
    want.extend([3, fence as u32, (fence >> 32) as u32, 9, 4, 1]);
    if encode_media(&frame(MediaRing::Enc(0), true, &IBS)) != want {
        return TestResult::Fail("encode frame differs from vcn_v3_0 enc ring");
    }
    // JPEG (engine 5 with VCN1 harvested): start, flush, start, IBs from
    // the kernel copy at VMID 0, fence, end.
    let base = 0x8_0090_0000u64;
    let jstart = [pj(0x1bfff, 0, 0), 0x68e04, pj(0x18000, 0, 0), 0x8001_0000];
    let mut want = Vec::new();
    want.extend(jstart);
    flush(&mut want, jpeg_wreg, jpeg_wait, MMHUB, 5, 3, PTB);
    jpeg_wreg(&mut want, LUT, 0x42);
    want.extend(jstart);
    for ib in &IBS {
        want.extend([
            pj(0x4149, 0, 0),
            3 << 3,
            pj(0x40cf, 0, 0),
            0,
            pj(0x40d1, 0, 0),
            0x333,
            pj(0x40e8, 0, 0),
            ib.va as u32,
            pj(0x40e9, 0, 0),
            (ib.va >> 32) as u32,
            pj(0x4082, 0, 0),
            ib.dwords,
            pj(0x40ec, 0, 0),
            base as u32,
            pj(0x40ed, 0, 0),
            (base >> 32) as u32,
            pj(0, 0, 2),
            0,
            pj(0x4085, 0, 0),
            0x0140_0200,
            pj(0x4084, 0, 0),
            2,
            pj(0x4089, 3, 3),
            2,
        ]);
    }
    want.extend([
        pj(0x402a, 0, 0),
        9,
        pj(0x402b, 0, 0),
        9,
        pj(0x40ea, 0, 0),
        fence as u32,
        pj(0x40eb, 0, 0),
        (fence >> 32) as u32,
        pj(0x4029, 0, 0),
        8,
        pj(0x4029, 0, 4),
        0,
        pj(0x1bfff, 0, 0),
        0x3fbc,
        pj(0x18000, 0, 0),
        1,
        pj(0, 0, 7),
        0,
        pj(0x1bfff, 0, 0),
        0x68e04,
        pj(0x18000, 0, 0),
        0x0001_0000,
    ]);
    if encode_media(&frame(MediaRing::Jpeg, true, &IBS)) != want {
        return TestResult::Fail("JPEG frame differs from jpeg_v3_0 dec ring");
    }
    // amdgpu_gmc_allocate_vm_inv_eng on MMHUB (bitmap 0x1fff3).
    let engines = |n| MediaRing::ALL.map(|r| r.inv_engine(n));
    if engines(1) != [0, 1, 4, 5] || engines(3) != [0, 1, 4, 8] {
        return TestResult::Fail("MMHUB invalidation engine allocation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_cs_media_frames_follow_linux_emit_order
);

fn vcn_navi22_cs_media_ring_routing_follows_amdgpu_ctx() -> TestResult {
    let routes = [
        (
            media_ring(uapi::AMDGPU_HW_IP_VCN_DEC, 0, 0),
            Some(MediaRing::Dec),
        ),
        (media_ring(uapi::AMDGPU_HW_IP_VCN_DEC, 0, 1), None),
        (media_ring(uapi::AMDGPU_HW_IP_VCN_DEC, 1, 0), None),
        (
            media_ring(uapi::AMDGPU_HW_IP_VCN_ENC, 0, 0),
            Some(MediaRing::Enc(0)),
        ),
        (media_ring(uapi::AMDGPU_HW_IP_VCN_ENC, 0, 1), None),
        (
            media_ring(uapi::AMDGPU_HW_IP_VCN_JPEG, 0, 0),
            Some(MediaRing::Jpeg),
        ),
        (media_ring(uapi::AMDGPU_HW_IP_UVD, 0, 0), None),
        (media_ring(uapi::AMDGPU_HW_IP_VCE, 0, 0), None),
    ];
    if routes.iter().any(|(got, want)| got != want) {
        return TestResult::Fail("media entity routing");
    }
    // Nothing is routed until a verified owner registers its rings.
    if MEDIA.lock().is_none() && ring_id(uapi::AMDGPU_HW_IP_VCN_DEC, 0, 0).is_some() {
        return TestResult::Fail("media ring offered without a registered owner");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_cs_media_ring_routing_follows_amdgpu_ctx
);

/// `amdgpu_vm_flush` on a ring without `emit_pipeline_sync` returns early
/// unless the VM flushes, so a media grant's PASID remap rides along with a
/// flush only (and is not recorded as done otherwise).
fn vcn_navi22_cs_media_grant_maps_pasid_only_with_a_flush() -> TestResult {
    use crate::amdgpu_navi22_submit::media_grant;
    use crate::amdgpu_vmid::Grant;
    let g = |needs_flush, map_pasid| Grant {
        vmid: 2,
        needs_flush,
        map_pasid,
    };
    if media_grant(g(false, true)) != g(false, false)
        || media_grant(g(true, true)) != g(true, true)
        || media_grant(g(true, false)) != g(true, false)
    {
        return TestResult::Fail("PASID mapping without a VM flush on a media ring");
    }
    // And the frame carries no LUT write without a flush.
    let ibs = [Ib {
        va: 0x1000,
        dwords: 4,
    }];
    let words = encode_media(&MediaFrame {
        ring: MediaRing::Enc(0),
        mmhub: MMHUB,
        engine: 1,
        flush: None,
        pasid_map: None,
        vmid: 2,
        ibs: &ibs,
        fence: 0x1000,
        seq: 1,
        ring_base: 0,
    });
    if words.first() != Some(&2) || words.len() != 5 + 6 {
        return TestResult::Fail("unflushed encode frame");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi22",
    vcn_navi22_cs_media_grant_maps_pasid_only_with_a_flush
);
