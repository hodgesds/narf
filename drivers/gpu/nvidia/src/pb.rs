//! Pushbuffer assembly — builds the byte stream the GPU's FIFO
//! front-end consumes.
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nouveau_dma.c`**
//!   — generic `nouveau_dma_*` ring-buffer encoder. The host
//!   driver picks up the current PUT pointer, emits header +
//!   data words, advances PUT, then writes the doorbell.
//! - **`drivers/gpu/drm/nouveau/nv50_fbcon.c`** — older PB
//!   submission example (Maxwell+ uses the channel ring through
//!   USERD.GP_PUT / GP_GET, but the per-method words are the
//!   same shape).
//!
//! ## Usage
//!
//! ```ignore
//! let mut pb = PbBuilder::new(&mut buf);
//! // CE: source/dest 64-bit, line_length, line_count, then
//! // LAUNCH_DMA at the end (Inc, 1 word).
//! pb.write_inc(CE_OFFSET_IN_UPPER, &[(src >> 32) as u32, src as u32]);
//! pb.write_inc(CE_OFFSET_OUT_UPPER, &[(dst >> 32) as u32, dst as u32]);
//! pb.write_inc(CE_LINE_LENGTH_IN, &[len]);
//! pb.write_inc(CE_LINE_COUNT, &[1]);
//! pb.write_inc(CE_LAUNCH_DMA, &[CE_FLAGS_BLOCKING]);
//! ```

#![allow(dead_code)]

use crate::fifo::{pb_header, PbType};

/// Errors raised when assembling a pushbuffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PbError {
    /// Caller passed a method with size > 2^13 - 1.
    SizeTooLarge,
    /// Underlying byte buffer ran out of space.
    BufferFull,
}

/// Streams 32-bit method/data words into a caller-owned byte
/// buffer (little-endian).
pub struct PbBuilder<'a> {
    buf: &'a mut [u8],
    cursor: usize,
}

impl<'a> core::fmt::Debug for PbBuilder<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PbBuilder")
            .field("cursor", &self.cursor)
            .field("capacity", &self.buf.len())
            .finish()
    }
}

impl<'a> PbBuilder<'a> {
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, cursor: 0 }
    }

    /// Bytes written so far.
    pub const fn len(&self) -> usize {
        self.cursor
    }

    /// True if no entries have been written.
    pub const fn is_empty(&self) -> bool {
        self.cursor == 0
    }

    /// Free bytes remaining in the buffer.
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.cursor
    }

    /// Write a header word + `data` payload with the given method
    /// space-walk type. Single call emits 4 + 4*data.len() bytes.
    pub fn write(&mut self, method: u16, data: &[u32], pb_type: PbType) -> Result<(), PbError> {
        if data.len() > 0x1FFF {
            return Err(PbError::SizeTooLarge);
        }
        let total = 4 + 4 * data.len();
        if self.cursor + total > self.buf.len() {
            return Err(PbError::BufferFull);
        }
        let hdr = pb_header(method, data.len() as u16, pb_type);
        self.put_u32(hdr);
        for w in data.iter().copied() {
            self.put_u32(w);
        }
        Ok(())
    }

    /// Convenience — incrementing-method write.
    pub fn write_inc(&mut self, method: u16, data: &[u32]) -> Result<(), PbError> {
        self.write(method, data, PbType::Inc)
    }

    /// Convenience — non-incrementing-method write.
    pub fn write_non_inc(&mut self, method: u16, data: &[u32]) -> Result<(), PbError> {
        self.write(method, data, PbType::NonInc)
    }

    fn put_u32(&mut self, w: u32) {
        let bytes = w.to_le_bytes();
        self.buf[self.cursor] = bytes[0];
        self.buf[self.cursor + 1] = bytes[1];
        self.buf[self.cursor + 2] = bytes[2];
        self.buf[self.cursor + 3] = bytes[3];
        self.cursor += 4;
    }
}

/// Build a fence-release suffix at the end of a pushbuffer.
/// Emits SEMAPHOREA + B + C + D in one incrementing-method block.
/// Cite `nouveau_dma.c::nv50_dma_push_*`.
pub fn append_fence_release(
    pb: &mut PbBuilder<'_>,
    sem_phys: u64,
    seqno: u32,
) -> Result<(), PbError> {
    use crate::fence::{SEMAPHOREA, SEMAPHORED_RELEASE};
    // Inc-write block at method SEMAPHOREA, 4 words: high/low
    // address, payload, OPERATION = RELEASE.
    pb.write_inc(
        SEMAPHOREA,
        &[
            ((sem_phys >> 32) & 0xFFFF_FFFF) as u32,
            (sem_phys & 0xFFFF_FFFF) as u32,
            seqno,
            SEMAPHORED_RELEASE,
        ],
    )
}
