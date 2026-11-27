//! Module-side AML quad codec (no `alloc`, no kernel crates).
//!
//! The twin of the kernel-side codec in `modules/src/kabi_platform.rs`:
//! the same 32-byte quad stream, the same tags and limits, the same
//! wire format — but this side only needs the shapes the driver
//! actually uses. Every method the ThinkPad driver calls takes
//! Integer arguments and returns an Integer, so this codec encodes
//! Integer argument lists and decodes Integer results. A future
//! caller that needs String/Buffer/Package results (the `_PSS`
//! Package fetch) extends this file to the full codec — the kernel
//! side already decodes the full tree.
//!
//! Layout (identical to `kabi_platform.rs`): 32-byte quads,
//! pre-order traversal; bytes 0..4 tag (`u32` LE), bytes 4..8
//! reserved (must be zero), bytes 8..16 Integer value (`u64` LE),
//! bytes 16..24 payload offset, bytes 24..32 length. Tag 0 is
//! Integer, 1 String, 2 Buffer, 3 Package. Bounds: at most 64
//! nodes, depth at most 4, payload at most 4096 bytes.

/// Bytes per quad node.
pub const QUAD_LEN: usize = 32;

/// Quad tag for an Integer node.
pub const TAG_INTEGER: u32 = 0;
/// Quad tag for a String node.
pub const TAG_STRING: u32 = 1;
/// Quad tag for a Buffer node.
pub const TAG_BUFFER: u32 = 2;
/// Quad tag for a Package node.
pub const TAG_PACKAGE: u32 = 3;

/// Maximum nodes in one args/result tree.
pub const MAX_NODES: usize = 64;
/// Maximum nesting depth of a Package tree.
pub const MAX_DEPTH: usize = 4;
/// Maximum String/Buffer payload bytes in one call.
pub const MAX_PAYLOAD_BYTES: usize = 4096;

/// Encode Integer arguments into `quads` (one 32-byte quad per
/// argument, reserved field zeroed). Returns the bytes written, or
/// `Err(())` when `quads` is too small. No payload bytes are
/// produced — Integer nodes carry their value inline.
pub fn encode_integer_args(args: &[u64], quads: &mut [u8]) -> Result<usize, ()> {
    if args.len() > MAX_NODES || quads.len() < args.len() * QUAD_LEN {
        return Err(());
    }
    for (i, value) in args.iter().enumerate() {
        let q = &mut quads[i * QUAD_LEN..(i + 1) * QUAD_LEN];
        q[0..4].copy_from_slice(&TAG_INTEGER.to_le_bytes());
        // Bytes 4..8 stay zero (reserved); 16..24 and 24..32 stay
        // zero (no payload for an Integer node).
        q[8..16].copy_from_slice(&value.to_le_bytes());
    }
    Ok(args.len() * QUAD_LEN)
}

/// Decode an Integer result from the kernel's single-buffer layout
/// (quads first, payload after). Requires at least one quad whose
/// tag is Integer; returns the value, or `Err(())` for a short
/// buffer or a non-Integer first node. The caller checks the total
/// length against `out_needed` first — a result longer than the
/// buffer is `-ENOSPC`, not a decode error.
pub fn decode_integer_result(out: &[u8]) -> Result<u64, ()> {
    if out.len() < QUAD_LEN {
        return Err(());
    }
    let tag = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
    if tag != TAG_INTEGER {
        return Err(());
    }
    Ok(u64::from_le_bytes([
        out[8], out[9], out[10], out[11], out[12], out[13], out[14], out[15],
    ]))
}
