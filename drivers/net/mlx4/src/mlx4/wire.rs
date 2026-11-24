//! Big-endian scalar get/put helpers for mlx4 mailbox and context byte
//! buffers.
//!
//! Every ConnectX-3 command mailbox, context structure and descriptor is
//! big-endian on the wire (PRM §1.4). These helpers read/write BE scalars
//! at a byte offset without the `try_into().unwrap()` panic path, so the
//! context builders stay terse. Sub-byte bit-packed fields use
//! [`super::bit_field`] instead.

#[inline]
pub fn get_u8(b: &[u8], off: usize) -> u8 {
    b[off]
}

#[inline]
pub fn get_be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

#[inline]
pub fn get_be32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline]
pub fn get_be64(b: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}

#[inline]
pub fn put_u8(b: &mut [u8], off: usize, v: u8) {
    b[off] = v;
}

#[inline]
pub fn put_be16(b: &mut [u8], off: usize, v: u16) {
    let x = v.to_be_bytes();
    b[off] = x[0];
    b[off + 1] = x[1];
}

#[inline]
pub fn put_be32(b: &mut [u8], off: usize, v: u32) {
    let x = v.to_be_bytes();
    b[off..off + 4].copy_from_slice(&x);
}

#[inline]
pub fn put_be64(b: &mut [u8], off: usize, v: u64) {
    let x = v.to_be_bytes();
    b[off..off + 8].copy_from_slice(&x);
}
