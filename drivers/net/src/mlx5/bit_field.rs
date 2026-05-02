//! Bit-field reader/writer for big-endian-bit-numbered structures.
//!
//! mlx5 layouts (CQE op fields, EQ context, HCA caps) declare fields
//! with widths in MSB-first order across 32-bit BE words — `mlx5_ifc`
//! convention. To address those fields uniformly we use an absolute
//! bit offset where bit 0 is the MSB of byte 0.
//!
//! ```text
//! byte 0:   [b0 b1 b2 b3 b4 b5 b6 b7]
//! byte 1:   [b8 b9 …                ]
//! ```
//!
//! Width is in [1, 64]; the result rides in the low `width` bits of
//! a `u64`.

/// Read `width` bits starting at `bit_offset`. MSB-first per byte.
/// Panics in debug if the read runs off the end of the slice.
pub fn read_bits_be(bytes: &[u8], bit_offset: usize, width: usize) -> u64 {
    debug_assert!(width <= 64, "width > 64");
    debug_assert!(bit_offset + width <= bytes.len() * 8,
                  "bit-field runs past end of slice");
    let mut acc: u64 = 0;
    for i in 0..width {
        let bit_idx  = bit_offset + i;
        let byte_idx = bit_idx / 8;
        let in_byte  = 7 - (bit_idx % 8);
        let v = (bytes[byte_idx] >> in_byte) & 1;
        acc = (acc << 1) | (v as u64);
    }
    acc
}

/// Write the low `width` bits of `value` into `bytes` starting at
/// `bit_offset`. MSB-first per byte. Panics in debug if the write
/// runs off the slice or `value` overflows `width` bits.
pub fn write_bits_be(
    bytes:      &mut [u8],
    bit_offset: usize,
    width:      usize,
    value:      u64,
) {
    debug_assert!(width <= 64, "width > 64");
    debug_assert!(bit_offset + width <= bytes.len() * 8,
                  "bit-field runs past end of slice");
    debug_assert!(width == 64 || value < (1u64 << width),
                  "value overflows width bits");
    for i in 0..width {
        let bit_idx  = bit_offset + i;
        let byte_idx = bit_idx / 8;
        let in_byte  = 7 - (bit_idx % 8);
        // Bit `i` of value (MSB-first) → position `in_byte` of byte.
        let bit = ((value >> (width - 1 - i)) & 1) as u8;
        bytes[byte_idx] = (bytes[byte_idx] & !(1 << in_byte))
                        | (bit << in_byte);
    }
}
