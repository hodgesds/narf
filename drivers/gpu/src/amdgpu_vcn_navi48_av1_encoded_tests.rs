use super::*;
use av1_encoded::inspect;
const LOSSLESS: &[u8] = include_bytes!("../fixtures/vcn5/av1_encode/parser-lossless.obu");
const Q1: &[u8] = include_bytes!("../fixtures/vcn5/av1_encode/reference-frame.obu");
const Q20: &[u8] = include_bytes!("../fixtures/vcn5/av1_encode/parser-q20.obu");
fn vcn5_av1_encoded_parser_matches_independent_lossless_and_lossy_output() -> TestResult {
    for (stream, q, tx, offset, bytes) in [
        (LOSSLESS, 0, 0, 6, 213),
        (Q1, 4, 2, 7, 36),
        (Q20, 80, 2, 7, 33),
    ] {
        let p = inspect(stream).unwrap();
        assert_eq!(
            (p.base_q_idx, p.tx_mode, p.tile_offset, p.tile_bytes),
            (q, tx, offset, bytes)
        );
        assert_eq!(p.quant_delta, [0; 5]);
        assert_eq!(p.filter_level, [0; 4]);
        assert_eq!(p.ref_deltas, [1, 0, 0, 0, -1, 0, -1, -1]);
        assert_eq!(p.mode_deltas, [0; 2]);
        assert_eq!(p.mode_ref_delta_enabled, q != 0);
        assert!(!p.mode_ref_delta_update);
        assert_eq!(p.sharpness, 0);
        assert!(!p.reduced_tx_set);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_av1_encoded_parser_matches_independent_lossless_and_lossy_output
);
fn vcn5_av1_encoded_parser_refuses_unsupported_shape_length_and_alignment() -> TestResult {
    for n in 0..Q1.len() {
        assert!(inspect(&Q1[..n]).is_none());
    }
    for at in [0, 1, 2, 3, 4, 5, 17, 18, 19, 38, 39] {
        let mut stream = Q1.to_vec();
        stream[2 + at / 8] ^= 1 << (7 - at % 8);
        assert!(
            inspect(&stream).is_none(),
            "accepted fixed-header mutation{at}"
        );
    }
    for header in [0, 0x12, 0x30, 0x36, 0x3a, 0xb2] {
        let mut stream = Q1.to_vec();
        stream[0] = header;
        assert!(inspect(&stream).is_none());
    }
    let mut extra = Q1.to_vec();
    extra.push(0);
    assert!(inspect(&extra).is_none());
    for length in [0, 1, 35, 37, 127, 128, 255] {
        let mut stream = Q1.to_vec();
        stream[1] = length;
        assert!(inspect(&stream).is_none());
    }
    assert!(inspect(&[0x32, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0]).is_none());
    assert!(inspect(&[0x32, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0]).is_none());
    // A valid variable-width leb128 remains permitted; it is bounded, exact,
    // and relocates the parsed tile rather than treating length bytes as data.
    let mut wide = vec![0x32, Q1[1] | 0x80, 0];
    wide.extend_from_slice(&Q1[2..]);
    assert_eq!(inspect(&wide).unwrap().tile_offset, 8);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_av1_encoded_parser_refuses_unsupported_shape_length_and_alignment
);
fn encoded_bits(bits: &[(u8, usize)]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut at = 0;
    for &(value, count) in bits {
        for bit in (0..count).rev() {
            if at % 8 == 0 {
                data.push(0);
            }
            let i = data.len() - 1;
            data[i] |= (((u32::from(value) >> bit) & 1) as u8) << (7 - at % 8);
            at += 1;
        }
    }
    data.push(0x5a); // opaque nonempty tile, not purported entropy data.
    let mut frame = vec![0x32, data.len() as u8];
    frame.extend_from_slice(&data);
    frame
}
fn vcn5_av1_encoded_parser_preserves_dynamic_quant_filter_and_signed_updates() -> TestResult {
    // The seven-bit signed fields use su(7), not sign-last literals. Nonzero
    // quant/filter state must reach the decoder verbatim, including defaults
    // for ref entries whose update bit is zero.
    let frame = encoded_bits(&[
        (0b100100, 6),
        (4, 8),
        (1, 1),
        (0x7f, 7),
        (1, 1),
        (2, 7),
        (1, 1),
        (0x40, 7),
        (0, 3),
        (3, 6),
        (4, 6),
        (5, 6),
        (6, 6),
        (7, 3),
        (1, 1),
        (1, 1),
        (1, 1),
        (0x7e, 7),
        (0, 1),
        (0, 1),
        (0, 1),
        (1, 1),
        (0x3f, 7),
        (0, 1),
        (0, 1),
        (0, 1),
        (1, 1),
        (0x40, 7),
        (1, 1),
        (0x3f, 7),
        (1, 1),
        (0, 1),
    ]);
    let p = inspect(&frame).unwrap();
    assert_eq!(p.quant_delta, [-1, 2, -64, 2, -64]);
    assert_eq!(p.filter_level, [3, 4, 5, 6]);
    assert_eq!(p.sharpness, 7);
    assert!(p.mode_ref_delta_enabled && p.mode_ref_delta_update);
    assert_eq!(p.ref_deltas, [-2, 0, 0, 0, 63, 0, -1, -1]);
    assert_eq!(p.mode_deltas, [-64, 63]);
    assert_eq!(p.tx_mode, 2);
    // qindex0 alone does not imply lossless when a plane delta is nonzero.
    let frame = encoded_bits(&[
        (0b100100, 6),
        (0, 8),
        (1, 1),
        (1, 7),
        (0, 2),
        (0, 2),
        (0, 12),
        (0, 3),
        (0, 1),
        (0, 1),
        (0, 1),
    ]);
    let p = inspect(&frame).unwrap();
    assert_eq!(p.base_q_idx, 0);
    assert_eq!(p.quant_delta, [1, 0, 0, 0, 0]);
    assert_eq!(p.tx_mode, 1);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/vcn-navi48",
    vcn5_av1_encoded_parser_preserves_dynamic_quant_filter_and_signed_updates
);
