//! NVIDIA host FIFO push-buffer codec — clean-room.
//!
//! Reference: **`open-gpu-doc/manuals/turing/tu102/dev_pbdma.ref.txt`**
//! (host FIFO + push-buffer DMA), plus the Turing host-class
//! method-cell layout from
//! `open-gpu-doc/classes/host/clc36f.h` (NVC36F = Turing+ host
//! class). Cross-checked against ga102 / ad102 — the format is
//! arch-stable from Turing onward.
//!
//! License note: open-gpu-doc and `clc36f.h` (under
//! `open-gpu-doc/classes`) are both MIT-licensed. **No GPL Linux
//! `nouveau` source consulted.**
//!
//! ## Push-buffer model
//!
//! NVIDIA exposes work to the GPU through **GPFIFO** — a ring of
//! 64-bit entries each pointing at a *push buffer*. A push buffer
//! is a flat array of 32-bit method-cells; each cell either:
//!
//! - Encodes a method header (subchannel + method address +
//!   operand count + operand mode), or
//! - Carries an operand consumed by the most-recent method.
//!
//! GPFIFO entry layout (Turing+, 64-bit):
//!
//! ```text
//!   bits 31:0   GET[31:2] | GET_HI[1:0]    push-buffer phys low
//!   bits 47:32  GET[39:32]                 push-buffer phys high
//!   bits 50:48  SUBROUTINE_LEVEL
//!   bit  62     SYNC_WAIT                  fence semantics
//!   bit  63     PRIVILEGE_LEVEL            kernel vs user
//! ```
//!
//! Method-cell layout (per `clc36f.h`):
//!
//! ```text
//!   bits 12:0   method address (4-byte units)
//!   bits 15:13  subchannel
//!   bits 28:16  parameter count
//!   bits 31:29  operand_mode (INC / NON_INC / IMMD)
//! ```
//!
//! ## Scope
//!
//! Codec only — produces the wire bits for GPFIFO entries and
//! method cells. Ring management (USERD / GP_PUT / GP_GET
//! pointer-bumping) lives in the Stage-3 driver core.

use core::convert::TryInto;

// ── Method-cell operand modes ────────────────────────────────────

/// Method-cell operand mode field (bits[31:29]). PRM:
/// `clc36f.h` §"NVC36F_DMA_INCR_*".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum OperandMode {
    /// `INC` — each operand consumed advances the method
    /// address by 4 bytes (the typical mode).
    Increment = 0b001,
    /// `NON_INC` — every operand goes to the same method addr.
    NonIncrement = 0b011,
    /// `IMMD` — the operand is encoded *inside* the cell
    /// (parameter count field carries the immediate).
    Immediate = 0b100,
    /// `INC_ONCE` — first operand goes to the method address,
    /// subsequent operands all hit the next method.
    IncrementOnce = 0b101,
}

impl OperandMode {
    pub const fn encode(self) -> u32 {
        (self as u32) << 29
    }
}

/// Documented Turing+ subchannel assignments
/// (`clc36f.h` §"NVC36F_SUBCHANNEL_*").
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Subchannel {
    /// `NVC36F_SUBCHANNEL_3D` — graphics.
    Graphics = 0,
    /// `NVC36F_SUBCHANNEL_COMPUTE` — compute / CUDA.
    Compute = 1,
    /// `NVC36F_SUBCHANNEL_I2M` — inline-to-memory copy.
    InlineToMemory = 2,
    /// `NVC36F_SUBCHANNEL_2D` — twod (legacy 2D blits).
    TwoD = 3,
    /// `NVC36F_SUBCHANNEL_COPY` — DMA copy engine.
    Copy = 4,
}

impl Subchannel {
    pub const fn encode(self) -> u32 {
        (self as u32) << 13
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FifoError {
    /// Method address doesn't fit in 13 bits, or isn't 4-byte
    /// aligned.
    BadMethodAddr,
    /// Parameter count exceeds the 13-bit field width (8191).
    TooManyParameters,
    /// Push-buffer phys address has bits set outside the 40-bit
    /// documented range.
    PhysOutOfRange,
}

/// Encode a method header cell.
///
/// `method` is the byte address (must be 4-byte aligned, ≤
/// `0x1FFC`); `count` is the number of 32-bit operand cells that
/// follow this header.
pub fn build_method(
    sub: Subchannel,
    method: u16,
    count: u16,
    mode: OperandMode,
) -> Result<u32, FifoError> {
    if method & 0x3 != 0 || method > 0x1FFC {
        return Err(FifoError::BadMethodAddr);
    }
    if count > 0x1FFF {
        return Err(FifoError::TooManyParameters);
    }
    let v = ((method as u32) >> 2)
        | sub.encode()
        | ((count as u32) << 16)
        | mode.encode();
    Ok(v)
}

/// Decode a method header cell into `(subchannel, method addr,
/// operand count, operand mode-bits)`.
pub fn parse_method(cell: u32) -> (u32, u16, u16, u32) {
    let method = ((cell & 0x1FFF) as u16) << 2;
    let sub = (cell >> 13) & 0x7;
    let count = ((cell >> 16) & 0x1FFF) as u16;
    let mode = (cell >> 29) & 0x7;
    (sub, method, count, mode)
}

// ── GPFIFO entry ─────────────────────────────────────────────────

/// One Turing+ GPFIFO entry. The `lo` / `hi` are the 32-bit
/// halves the host writes to the GPFIFO ring.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GpfifoEntry {
    pub lo: u32,
    pub hi: u32,
}

/// Build a GPFIFO entry pointing at a push buffer at `phys` with
/// `dword_count` 32-bit cells.
///
/// `phys` must be 4-byte aligned (the GPFIFO encodes the low
/// two address bits as flags). `dword_count` must fit in 21
/// bits (the `LENGTH` field in `clc36f.h`).
pub fn build_gpfifo_entry(phys: u64, dword_count: u32) -> Result<GpfifoEntry, FifoError> {
    if phys & 0x3 != 0 || phys >= (1u64 << 40) {
        return Err(FifoError::PhysOutOfRange);
    }
    if dword_count > 0x1F_FFFF {
        return Err(FifoError::TooManyParameters);
    }
    // `clc36f.h` GPFIFO layout: lo holds bits[31:0] of phys (with
    // bits[1:0] reserved and bit 0 used as `SYNC_WAIT_DISABLE`),
    // hi holds bits[39:32] of phys plus the 21-bit length field
    // and the privilege/sync flags. Stage-2 leaves both flags
    // clear.
    let phys_lo = (phys as u32) & !0x3;
    let phys_hi = ((phys >> 32) & 0xFF) as u32;
    let hi = phys_hi | (dword_count << 10);
    Ok(GpfifoEntry { lo: phys_lo, hi })
}

/// Parse a GPFIFO entry's `(phys, dword_count)`. Inverse of
/// `build_gpfifo_entry` modulo the flag bits, which Stage-2
/// keeps zero.
pub fn parse_gpfifo_entry(entry: &GpfifoEntry) -> (u64, u32) {
    let phys_lo = (entry.lo & !0x3) as u64;
    let phys_hi = ((entry.hi & 0xFF) as u64) << 32;
    let phys = phys_lo | phys_hi;
    let length = (entry.hi >> 10) & 0x1F_FFFF;
    (phys, length)
}

/// Encode a method+single-operand pair into a 2-cell push-buffer
/// fragment. Convenience for the common case of "set one
/// register".
pub fn build_method_with_operand(
    sub: Subchannel,
    method: u16,
    operand: u32,
) -> Result<[u32; 2], FifoError> {
    let header = build_method(sub, method, 1, OperandMode::Increment)?;
    Ok([header, operand])
}

/// Convert a 32-bit cell stream to a byte buffer (little-endian).
pub fn dwords_to_bytes(words: &[u32], out: &mut [u8]) -> Result<usize, FifoError> {
    if out.len() < words.len() * 4 {
        return Err(FifoError::TooManyParameters);
    }
    for (i, w) in words.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    Ok(words.len() * 4)
}

/// Convert a byte buffer back to a 32-bit cell stream.
pub fn bytes_to_dwords(bytes: &[u8], out: &mut [u32]) -> Result<usize, FifoError> {
    if bytes.len() % 4 != 0 {
        return Err(FifoError::BadMethodAddr);
    }
    let n = bytes.len() / 4;
    if out.len() < n {
        return Err(FifoError::TooManyParameters);
    }
    for i in 0..n {
        out[i] = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().unwrap());
    }
    Ok(n)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_method_round_trip() -> TestResult {
        let cell = match build_method(Subchannel::Graphics, 0x100, 4, OperandMode::Increment) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        let (sub, method, count, mode) = parse_method(cell);
        if sub != 0 {
            return TestResult::Fail("subchannel lost in encode");
        }
        if method != 0x100 {
            return TestResult::Fail("method address lost");
        }
        if count != 4 {
            return TestResult::Fail("count lost");
        }
        if mode != OperandMode::Increment as u32 {
            return TestResult::Fail("mode lost");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/nvidia_gpu_fifo", smoke_method_round_trip);

    fn smoke_method_rejects_unaligned() -> TestResult {
        match build_method(Subchannel::Graphics, 0x102, 1, OperandMode::Increment) {
            Err(FifoError::BadMethodAddr) => TestResult::Pass,
            _ => TestResult::Fail("non-4B method addr must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_fifo",
        smoke_method_rejects_unaligned
    );

    fn smoke_gpfifo_round_trip() -> TestResult {
        let phys = 0x0000_0007_FEED_C000u64;
        let entry = match build_gpfifo_entry(phys, 64) {
            Ok(e) => e,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        let (decoded_phys, len) = parse_gpfifo_entry(&entry);
        if decoded_phys != phys {
            return TestResult::Fail("phys lost in round trip");
        }
        if len != 64 {
            return TestResult::Fail("length lost in round trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/nvidia_gpu_fifo", smoke_gpfifo_round_trip);

    fn smoke_gpfifo_rejects_oversize_phys() -> TestResult {
        match build_gpfifo_entry(1u64 << 40, 1) {
            Err(FifoError::PhysOutOfRange) => TestResult::Pass,
            _ => TestResult::Fail(">40-bit phys must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_fifo",
        smoke_gpfifo_rejects_oversize_phys
    );

    fn smoke_method_with_operand_layout() -> TestResult {
        let cells = match build_method_with_operand(Subchannel::Compute, 0x200, 0xCAFE_BABE) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        if cells[1] != 0xCAFE_BABE {
            return TestResult::Fail("operand mis-placed");
        }
        let (sub, method, count, _) = parse_method(cells[0]);
        if sub != Subchannel::Compute as u32 {
            return TestResult::Fail("compute subchannel mis-encoded");
        }
        if method != 0x200 || count != 1 {
            return TestResult::Fail("header field mis-encoded");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/nvidia_gpu_fifo",
        smoke_method_with_operand_layout
    );
}
