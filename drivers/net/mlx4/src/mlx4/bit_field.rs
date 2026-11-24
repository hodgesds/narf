//! Big-endian, MSB-first bit-field access for mlx4 context structures.
//!
//! ConnectX-3 context structures (QP/CQ/EQ) are mostly byte-aligned
//! big-endian scalars, but a handful of fields are packed into sub-byte
//! runs — the QP `flags` carry the service type in bits 16..19 and the
//! target state in bits 28..31, the `rq_size_stride`/`sq_size_stride`
//! bytes split a log-size and a log-stride, and the EQ/CQ `flags` encode
//! status and state nibbles. Addressing those uniformly needs an absolute
//! bit index where bit 0 is the most-significant bit of byte 0:
//!
//! ```text
//! byte 0:   [ bit0 bit1 bit2 bit3 bit4 bit5 bit6 bit7 ]
//! byte 1:   [ bit8 bit9 ...                           ]
//! ```
//!
//! `width` is in `1..=64`; the value occupies the low `width` bits of the
//! returned `u64`.

/// Read `width` MSB-first bits starting at absolute `bit_offset`.
///
/// Panics in debug if the span runs past the end of `bytes`.
pub fn read_bits_be(bytes: &[u8], bit_offset: usize, width: usize) -> u64 {
    debug_assert!((1..=64).contains(&width), "width out of range");
    debug_assert!(
        bit_offset + width <= bytes.len() * 8,
        "bit-field read past end of slice"
    );
    let mut acc: u64 = 0;
    for i in 0..width {
        let idx = bit_offset + i;
        let bit = (bytes[idx / 8] >> (7 - (idx % 8))) & 1;
        acc = (acc << 1) | u64::from(bit);
    }
    acc
}

/// Write the low `width` bits of `value` MSB-first starting at absolute
/// `bit_offset`, leaving the surrounding bits untouched.
///
/// Panics in debug if the span runs past the end of `bytes` or `value`
/// does not fit in `width` bits.
pub fn write_bits_be(bytes: &mut [u8], bit_offset: usize, width: usize, value: u64) {
    debug_assert!((1..=64).contains(&width), "width out of range");
    debug_assert!(
        bit_offset + width <= bytes.len() * 8,
        "bit-field write past end of slice"
    );
    debug_assert!(
        width == 64 || value < (1u64 << width),
        "value does not fit in width bits"
    );
    for i in 0..width {
        let idx = bit_offset + i;
        let byte = idx / 8;
        let shift = 7 - (idx % 8);
        let bit = ((value >> (width - 1 - i)) & 1) as u8;
        bytes[byte] = (bytes[byte] & !(1 << shift)) | (bit << shift);
    }
}
