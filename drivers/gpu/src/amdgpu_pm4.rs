//! AMDGPU PM4 (Packet Manager 4) packet builder — clean-room.
//!
//! Reference: AMD Vega ISA + PM4 Packet Format Reference (public,
//! GPUOpen). Section numbers below (`§P.x`) refer to that doc.
//!
//! ## Format
//!
//! Every PM4 packet is a 32-bit header followed by `count + 1`
//! 32-bit data words. Header layout:
//!
//! ```text
//! bits 31:30  packet type           (0 = NOP, 2 = TYPE2, 3 = TYPE3)
//! bits 29:16  count - 1             (data word count, minus one)
//! bits 15:8   opcode                (TYPE3-only)
//! bits  7:0   reserved / predicate  (varies)
//! ```
//!
//! TYPE3 packets are the bread-and-butter (compute / draw / DMA);
//! TYPE2 / NOP / TYPE0 exist for legacy compat. Stage-4 ships
//! TYPE3 with three opcodes: `INDIRECT_BUFFER` (chain-into-IB),
//! `WRITE_DATA` (host→GPU memory write), `WAIT_REG_MEM`
//! (GPU-side spin-wait on a register or memory address).
//!
//! ## Scope
//!
//! Builder for the in-memory packet bytes. Doesn't enqueue —
//! that's `amdgpu::gfx_ring`'s job. Doesn't decode either —
//! we're producing packets, not consuming them.

/// PM4 packet types (§P.1.1).
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PacketType {
    Type0 = 0,
    Type2 = 2,
    Type3 = 3,
}

/// A subset of PM4 TYPE3 opcodes we care about. Full table lives
/// in the public PM4 reference; Stage-4 ships the ones a
/// compute / DMA submission path uses.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Pm4Op {
    /// Branch into another packet stream living at `ib_base`.
    /// The GPU returns to the next packet after the IB completes.
    IndirectBuffer = 0x3F,
    /// Host writes `data` to the GPU-visible address `dst`. Used
    /// to publish completion fences.
    WriteData      = 0x37,
    /// GPU-side `wait_until((mmio_or_mem & mask) cmp ref)`.
    WaitRegMem     = 0x3C,
    /// No-op; pads a ring to 16-byte alignment without side effects.
    Nop            = 0x10,
}

/// PM4 packet builder. Writes 32-bit words into `out`; returns
/// the byte length the caller should advance the ring's
/// write-pointer by (always a multiple of 4).
#[derive(Debug)]
pub struct Pm4Builder<'a> {
    out: &'a mut [u32],
    pos: usize,
}

/// Errors from packet construction.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Pm4Error {
    /// Output buffer too small for the packet being built.
    OutOfRoom,
    /// Caller-supplied count doesn't fit in 14 bits.
    BadCount,
}

impl<'a> Pm4Builder<'a> {
    pub fn new(out: &'a mut [u32]) -> Self { Self { out, pos: 0 } }

    pub fn bytes_written(&self) -> usize { self.pos * 4 }

    fn push(&mut self, w: u32) -> Result<(), Pm4Error> {
        if self.pos >= self.out.len() { return Err(Pm4Error::OutOfRoom); }
        self.out[self.pos] = w;
        self.pos += 1;
        Ok(())
    }

    /// Build the TYPE3 header word (§P.1.2).
    fn type3_header(opcode: Pm4Op, data_word_count: usize) -> Result<u32, Pm4Error> {
        if data_word_count == 0 || data_word_count > 0x4000 {
            return Err(Pm4Error::BadCount);
        }
        let count_minus_one = (data_word_count as u32 - 1) & 0x3FFF;
        Ok((PacketType::Type3 as u32) << 30
            | count_minus_one << 16
            | (opcode as u32) << 8)
    }

    /// Push a NOP padding packet of `n_words` (≥ 1).
    pub fn nop(&mut self, n_words: usize) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::Nop, n_words)?;
        self.push(hdr)?;
        for _ in 0..n_words { self.push(0)?; }
        Ok(())
    }

    /// `INDIRECT_BUFFER` — branch to `ib_base` for `ib_size_dw`
    /// dwords of additional packets. Returns control to the
    /// next post-IB packet automatically.
    ///
    /// Ring placement: 4 dwords (header + 3 data).
    pub fn indirect_buffer(
        &mut self,
        ib_base:    u64,
        ib_size_dw: u32,
        vmid:       u8,
    ) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::IndirectBuffer, 3)?;
        self.push(hdr)?;
        self.push(ib_base as u32)?;
        self.push((ib_base >> 32) as u32)?;
        // Spec: bits[19:0] = size in dwords; bits[27:24] = VMID.
        self.push((ib_size_dw & 0x000F_FFFF)
            | ((vmid as u32 & 0xF) << 24))?;
        Ok(())
    }

    /// `WRITE_DATA` — emit a 32-bit value at `dst_addr`. Used
    /// for fence publication: the GPU writes a sequence number
    /// to host-coherent memory once the packet retires.
    ///
    /// Ring placement: 5 dwords (header + 4 data).
    pub fn write_data(&mut self, dst_addr: u64, value: u32) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::WriteData, 4)?;
        self.push(hdr)?;
        // Control word: `dst_sel = MEM (5)` + `wr_confirm = 1` so
        // the engine waits for the write to settle before
        // signaling the ring as drained. Per AMD GPUOpen docs.
        const CTRL_DST_MEM:    u32 = 5 << 8;
        const CTRL_WR_CONFIRM: u32 = 1 << 20;
        self.push(CTRL_DST_MEM | CTRL_WR_CONFIRM)?;
        self.push(dst_addr as u32)?;
        self.push((dst_addr >> 32) as u32)?;
        self.push(value)?;
        Ok(())
    }

    /// `WAIT_REG_MEM` — block the engine until `(mem(addr) & mask)
    /// == reference`. The host uses this to gate one IB on the
    /// completion fence of an earlier IB.
    ///
    /// Ring placement: 7 dwords (header + 6 data).
    pub fn wait_reg_mem_eq(
        &mut self,
        mem_addr:  u64,
        reference: u32,
        mask:      u32,
    ) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::WaitRegMem, 6)?;
        self.push(hdr)?;
        // info: `mem_space=1 (MEM), function=3 (>=)` per public PM4 docs.
        const INFO_MEM_SPACE: u32 = 1 << 4;
        const INFO_FUNC_EQ:   u32 = 3;
        self.push(INFO_MEM_SPACE | INFO_FUNC_EQ)?;
        self.push(mem_addr as u32)?;
        self.push((mem_addr >> 32) as u32)?;
        self.push(reference)?;
        self.push(mask)?;
        // poll_interval in retries.
        self.push(4)?;
        Ok(())
    }
}
