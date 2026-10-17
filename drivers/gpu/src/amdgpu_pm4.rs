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
    WriteData = 0x37,
    /// GPU-side `wait_until((mmio_or_mem & mask) cmp ref)`.
    WaitRegMem = 0x3C,
    /// No-op; pads a ring to 16-byte alignment without side effects.
    Nop = 0x10,
    /// Cache-flush + invalidate. Issued between draws / dispatches
    /// so subsequent reads see the just-written data. Required
    /// after any kernel that writes through L1/L2 before the host
    /// or another engine consumes the result.
    AcquireMem = 0x58,
    /// Bulk-write `count` dwords of host-supplied state to a
    /// contiguous CONTEXT register range, starting at
    /// `CONTEXT_REG_OFFSET + reg_offset`. Used during shader-state
    /// init / draw setup.
    SetContextReg = 0x69,
    /// Same shape as `SetContextReg` but writes into the CONFIG
    /// register range (chip-wide state, not per-context). Used
    /// during ring bring-up to program GRBM / SQ defaults.
    SetConfigReg = 0x68,
    /// Sets up a render context — used in conjunction with the
    /// state-init blob the GPU loads at ring start.
    ContextControl = 0x28,
    /// Stall the PFP until the ME catches up (`nvd.h` 0x42).
    PfpSyncMe = 0x42,
    /// End-of-pipe event with a memory write and optional interrupt
    /// (`nvd.h` 0x49).
    ReleaseMem = 0x49,
}

// ── ACQUIRE_MEM coher-cntl bits (GFX9 only) ───────────────────────
//
// Each bit gates flushing one cache. Positions verified against
// `soc15d.h`'s `PACKET3_ACQUIRE_MEM_CP_COHER_CNTL_*` setters.
//
// LINUX-GAP: `CP_COHER_CNTL` is the GFX9 form. GFX10 and up moved cache
// invalidation into a **ninth dword**, `GCR_CNTL`, with an entirely different
// field layout — GLI_INV at 0, GLM_WB/INV at 4/5, GLK_WB/INV at 6/7, GLV_INV
// at 8, GL1_INV at 9, GL2_DISCARD/INV/WB at 13/14/15, SEQ at 16
// (`nvd.h`). None of the bits below exist there, so a GFX11 ring fed
// [`ACQUIRE_FULL_SHADER_INVALIDATE`] through [`Pm4Builder::acquire_mem`]
// would set reserved bits in COHER_CNTL, invalidate nothing, and be one dword
// short of the packet the CP expects. [`Pm4Builder::acquire_mem_gfx11`] is the
// form for the target chip.

/// L1 texture cache invalidate.
pub const ACQUIRE_TCL1_ACTION_ENA: u32 = 1 << 22;
/// L2 texture cache (TC = "texture cache" / "L2") action.
pub const ACQUIRE_TC_ACTION_ENA: u32 = 1 << 23;
/// L2 writeback (write dirty TC lines back before invalidate).
pub const ACQUIRE_TC_WB_ACTION_ENA: u32 = 1 << 18;
/// Shader instruction cache invalidate.
pub const ACQUIRE_SH_ICACHE_ACTION_ENA: u32 = 1 << 29;
/// Shader scalar-cache invalidate.
pub const ACQUIRE_SH_KCACHE_ACTION_ENA: u32 = 1 << 27;
/// Color buffer dest-base flush enable bits[7:0] — one per render target.
pub const ACQUIRE_CB_DEST_BASE_ENA: u32 = 0x000000FF;
/// Depth buffer dest-base flush enable.
pub const ACQUIRE_DB_DEST_BASE_ENA: u32 = 1 << 14;

/// Composite mask: invalidate every shader-visible cache. Use this
/// between compute dispatches when the next dispatch can't trust
/// any cache residency. **GFX9 only** — see the gap note above.
pub const ACQUIRE_FULL_SHADER_INVALIDATE: u32 = ACQUIRE_TCL1_ACTION_ENA
    | ACQUIRE_TC_ACTION_ENA
    | ACQUIRE_TC_WB_ACTION_ENA
    | ACQUIRE_SH_ICACHE_ACTION_ENA
    | ACQUIRE_SH_KCACHE_ACTION_ENA;

/// The GFX10+ `GCR_CNTL` equivalent: write back and invalidate every
/// shader-visible cache. Fields from `nvd.h` via
/// [`crate::amdgpu_pm4_defs`], which audited exact. `GLI_INV` takes the
/// two-bit encoding 1 (ALL) rather than a flag.
pub const GCR_FULL_SHADER_INVALIDATE: u32 = {
    use crate::amdgpu_pm4_defs as d;
    d::packet3_acquire_mem_gcr_cntl_gli_inv(1)
        | d::packet3_acquire_mem_gcr_cntl_glm_wb(1)
        | d::packet3_acquire_mem_gcr_cntl_glm_inv(1)
        | d::packet3_acquire_mem_gcr_cntl_glk_wb(1)
        | d::packet3_acquire_mem_gcr_cntl_glk_inv(1)
        | d::packet3_acquire_mem_gcr_cntl_glv_inv(1)
        | d::packet3_acquire_mem_gcr_cntl_gl1_inv(1)
        | d::packet3_acquire_mem_gcr_cntl_gl2_inv(1)
        | d::packet3_acquire_mem_gcr_cntl_gl2_wb(1)
};

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
    pub fn new(out: &'a mut [u32]) -> Self {
        Self { out, pos: 0 }
    }

    pub fn bytes_written(&self) -> usize {
        self.pos * 4
    }

    fn push(&mut self, w: u32) -> Result<(), Pm4Error> {
        if self.pos >= self.out.len() {
            return Err(Pm4Error::OutOfRoom);
        }
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
        Ok((PacketType::Type3 as u32) << 30 | count_minus_one << 16 | (opcode as u32) << 8)
    }

    /// Push a NOP padding packet of `n_words` (≥ 1).
    pub fn nop(&mut self, n_words: usize) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::Nop, n_words)?;
        self.push(hdr)?;
        for _ in 0..n_words {
            self.push(0)?;
        }
        Ok(())
    }

    /// `INDIRECT_BUFFER` — branch to `ib_base` for `ib_size_dw`
    /// dwords of additional packets. Returns control to the
    /// next post-IB packet automatically.
    ///
    /// Ring placement: 4 dwords (header + 3 data).
    pub fn indirect_buffer(
        &mut self,
        ib_base: u64,
        ib_size_dw: u32,
        vmid: u8,
    ) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::IndirectBuffer, 3)?;
        self.push(hdr)?;
        self.push(ib_base as u32)?;
        self.push((ib_base >> 32) as u32)?;
        // Spec: bits[19:0] = size in dwords; bits[27:24] = VMID.
        self.push((ib_size_dw & 0x000F_FFFF) | ((vmid as u32 & 0xF) << 24))?;
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
        const CTRL_DST_MEM: u32 = 5 << 8;
        const CTRL_WR_CONFIRM: u32 = 1 << 20;
        self.push(CTRL_DST_MEM | CTRL_WR_CONFIRM)?;
        self.push(dst_addr as u32)?;
        self.push((dst_addr >> 32) as u32)?;
        self.push(value)?;
        Ok(())
    }

    /// `ACQUIRE_MEM` — flush / invalidate caches across a memory
    /// range. Caller passes the coher_cntl mask (which caches to
    /// touch), the byte range, and the poll interval; the GPU
    /// stalls the pipeline until all the requested writebacks
    /// complete and all the requested invalidations land.
    ///
    /// Pass `coher_size = !0u32` and `coher_base = 0` to acquire
    /// the entire memory space — the simplest fence between two
    /// kernels that share no specific buffer.
    ///
    /// Ring placement: 7 dwords (header + 6 data).
    pub fn acquire_mem(
        &mut self,
        coher_cntl: u32,
        coher_base: u64,
        coher_size: u64,
        poll_interval: u32,
    ) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::AcquireMem, 6)?;
        self.push(hdr)?;
        self.push(coher_cntl)?;
        self.push(coher_size as u32)?;
        self.push((coher_size >> 32) as u32)?;
        self.push(coher_base as u32)?;
        self.push((coher_base >> 32) as u32)?;
        self.push(poll_interval)?;
        Ok(())
    }

    /// `ACQUIRE_MEM` in its GFX10+ form: the same six payload dwords followed
    /// by a seventh, `GCR_CNTL`, which is where cache invalidation lives from
    /// GFX10 onward (`nvd.h`). `COHER_CNTL` keeps only `ENGINE_SEL` at bit 31.
    ///
    /// `gcr_cntl` is built from the `packet3_acquire_mem_gcr_cntl_*` encoders
    /// in [`crate::amdgpu_pm4_defs`], or [`GCR_FULL_SHADER_INVALIDATE`] for
    /// the equivalent of the GFX9 composite.
    pub fn acquire_mem_gfx11(
        &mut self,
        coher_cntl: u32,
        coher_base: u64,
        coher_size: u64,
        poll_interval: u32,
        gcr_cntl: u32,
    ) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::AcquireMem, 7)?;
        self.push(hdr)?;
        self.push(coher_cntl)?;
        self.push(coher_size as u32)?;
        self.push((coher_size >> 32) as u32)?;
        self.push(coher_base as u32)?;
        self.push((coher_base >> 32) as u32)?;
        self.push(poll_interval)?;
        self.push(gcr_cntl)?;
        Ok(())
    }

    /// `SET_CONTEXT_REG` — write `values` into a contiguous CONTEXT
    /// register range starting at `reg_offset` (relative to the
    /// CONTEXT_REG_OFFSET base = 0xA000 on GFX9). Used during
    /// draw setup to push shader state.
    ///
    /// Ring placement: 2 + N dwords (header + 1 setup + N values).
    pub fn set_context_reg(&mut self, reg_offset: u16, values: &[u32]) -> Result<(), Pm4Error> {
        if values.is_empty() {
            return Err(Pm4Error::BadCount);
        }
        let hdr = Self::type3_header(Pm4Op::SetContextReg, 1 + values.len())?;
        self.push(hdr)?;
        self.push(reg_offset as u32)?;
        for &v in values {
            self.push(v)?;
        }
        Ok(())
    }

    /// `SET_CONFIG_REG` — same shape as `set_context_reg` but for
    /// chip-wide CONFIG registers (offset base 0x2000 on GFX9).
    pub fn set_config_reg(&mut self, reg_offset: u16, values: &[u32]) -> Result<(), Pm4Error> {
        if values.is_empty() {
            return Err(Pm4Error::BadCount);
        }
        let hdr = Self::type3_header(Pm4Op::SetConfigReg, 1 + values.len())?;
        self.push(hdr)?;
        self.push(reg_offset as u32)?;
        for &v in values {
            self.push(v)?;
        }
        Ok(())
    }

    /// `CONTEXT_CONTROL` — set the load/shadow control word for
    /// the upcoming context. `load_enable_mask` is bit 31 of the
    /// first dword; `shadow_enable_mask` is bit 31 of the second.
    /// Linux uses 0x80000000 / 0x80000000 to enable both.
    ///
    /// Ring placement: 3 dwords (header + 2 data).
    pub fn context_control(
        &mut self,
        load_enable: u32,
        shadow_enable: u32,
    ) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::ContextControl, 2)?;
        self.push(hdr)?;
        self.push(load_enable)?;
        self.push(shadow_enable)?;
        Ok(())
    }

    /// `WAIT_REG_MEM` — block the engine until `(mem(addr) & mask)
    /// == reference`. The host uses this to gate one IB on the
    /// completion fence of an earlier IB.
    ///
    /// Ring placement: 7 dwords (header + 6 data).
    pub fn wait_reg_mem_eq(
        &mut self,
        mem_addr: u64,
        reference: u32,
        mask: u32,
    ) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::WaitRegMem, 6)?;
        self.push(hdr)?;
        // info: `mem_space=1 (MEM), function=3 (>=)` per public PM4 docs.
        const INFO_MEM_SPACE: u32 = 1 << 4;
        const INFO_FUNC_EQ: u32 = 3;
        self.push(INFO_MEM_SPACE | INFO_FUNC_EQ)?;
        self.push(mem_addr as u32)?;
        self.push((mem_addr >> 32) as u32)?;
        self.push(reference)?;
        self.push(mask)?;
        // poll_interval in retries.
        self.push(4)?;
        Ok(())
    }

    /// `gfx_v1x_0_wait_reg_mem` (GFX10..12): wait until `(value & mask) ==
    /// reference` (function 3), reading register `addr0` (`memory` false)
    /// or memory at `addr1:addr0`; with `write` (operation 1) first write
    /// `reference` to register `addr0` and wait on register `addr1`. `pfp`
    /// runs it on the PFP (engine 1), `interval` is the poll interval.
    #[allow(clippy::too_many_arguments)]
    pub fn wait_reg_mem(
        &mut self,
        pfp: bool,
        memory: bool,
        write: bool,
        addr0: u32,
        addr1: u32,
        reference: u32,
        mask: u32,
        interval: u32,
    ) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::WaitRegMem, 6)?;
        self.push(hdr)?;
        self.push(3 | u32::from(memory) << 4 | u32::from(write) << 6 | u32::from(pfp) << 8)?;
        self.push(addr0)?;
        self.push(addr1)?;
        self.push(reference)?;
        self.push(mask)?;
        self.push(interval)
    }

    /// `gfx_v1x_0_ring_emit_wreg`: register `reg` (an absolute dword index)
    /// written with `value`, confirmed; on a graphics ring through the PFP
    /// (`WRITE_DATA_ENGINE_SEL(1)`).
    pub fn write_reg(&mut self, reg: u32, value: u32, gfx: bool) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::WriteData, 4)?;
        self.push(hdr)?;
        const WR_CONFIRM: u32 = 1 << 20;
        self.push(WR_CONFIRM | u32::from(gfx) << 30)?;
        self.push(reg)?;
        self.push(0)?;
        self.push(value)
    }

    /// `gfx_v1x_0_ring_emit_reg_wait`: wait on register `reg` from the ME.
    pub fn reg_wait(&mut self, reg: u32, value: u32, mask: u32) -> Result<(), Pm4Error> {
        self.wait_reg_mem(false, false, false, reg, 0, value, mask, 0x20)
    }

    /// `gfx_v1x_0_ring_emit_reg_write_reg_wait`: write `reference` to `reg0`
    /// and wait for `(reg1 & mask) == mask` — from the PFP on a graphics
    /// ring.
    pub fn reg_write_reg_wait(
        &mut self,
        reg0: u32,
        reg1: u32,
        reference: u32,
        mask: u32,
        gfx: bool,
    ) -> Result<(), Pm4Error> {
        self.wait_reg_mem(gfx, false, true, reg0, reg1, reference, mask, 0x20)
    }

    /// `PFP_SYNC_ME`.
    pub fn pfp_sync_me(&mut self) -> Result<(), Pm4Error> {
        let hdr = Self::type3_header(Pm4Op::PfpSyncMe, 1)?;
        self.push(hdr)?;
        self.push(0)
    }

    /// `gfx_v1x_0_ring_emit_fence`: RELEASE_MEM on
    /// CACHE_FLUSH_AND_INV_TS_EVENT (index 5) with GL2 writeback and
    /// sequenced cache actions (policy 3), writing `seq` (32 or 64 bits)
    /// to `addr` once prior work is done, and interrupting with `interrupt`.
    pub fn release_mem_fence(
        &mut self,
        addr: u64,
        seq: u64,
        bits64: bool,
        interrupt: bool,
    ) -> Result<(), Pm4Error> {
        if addr & if bits64 { 7 } else { 3 } != 0 {
            return Err(Pm4Error::BadCount);
        }
        let hdr = Self::type3_header(Pm4Op::ReleaseMem, 7)?;
        self.push(hdr)?;
        const GCR_SEQ: u32 = 1 << 22;
        const GCR_GL2_WB: u32 = 1 << 21;
        const CACHE_FLUSH_AND_INV_TS_EVENT: u32 = 0x14;
        self.push(GCR_SEQ | GCR_GL2_WB | 3 << 25 | CACHE_FLUSH_AND_INV_TS_EVENT | 5 << 8)?;
        self.push(if bits64 { 2 } else { 1 } << 29 | if interrupt { 2 << 24 } else { 0 })?;
        self.push(addr as u32)?;
        self.push((addr >> 32) as u32)?;
        self.push(seq as u32)?;
        self.push((seq >> 32) as u32)?;
        self.push(0)
    }

    /// `gmc_v1x_0_emit_flush_gpu_tlb` then `gfx_v1x_0_ring_emit_vm_flush`
    /// (identical on GMC 11 and 12): on hub `regs` at GC/MMHUB register
    /// base `base` (absolute dwords), through invalidation engine `eng`
    /// (the ring's own), point `vmid` at page directory `pd_addr` and
    /// invalidate its translations, holding the engine semaphore on a hub
    /// that uses one; a graphics ring then syncs the PFP to the ME.
    pub fn vm_flush(
        &mut self,
        regs: &crate::amdgpu_vmhub_regs::VmHubRegs,
        base: u32,
        eng: u32,
        vmid: u8,
        pd_addr: u64,
        gfx: bool,
    ) -> Result<(), Pm4Error> {
        let eng = regs.eng_distance * eng;
        let ctx = regs.ctx_addr_distance * u32::from(vmid);
        if regs.semaphore {
            self.reg_wait(base + regs.inv_eng0_sem + eng, 1, 1)?;
        }
        self.write_reg(base + regs.ctx0_pt_base_lo + ctx, pd_addr as u32, gfx)?;
        self.write_reg(
            base + regs.ctx0_pt_base_hi + ctx,
            (pd_addr >> 32) as u32,
            gfx,
        )?;
        self.reg_write_reg_wait(
            base + regs.inv_eng0_req + eng,
            base + regs.inv_eng0_ack + eng,
            crate::amdgpu_vmhub_regs::invalidate_req(vmid, 0),
            1 << vmid,
            gfx,
        )?;
        if regs.semaphore {
            self.write_reg(base + regs.inv_eng0_sem + eng, 0, gfx)?;
        }
        if gfx {
            self.pfp_sync_me()?;
        }
        Ok(())
    }

    /// `gfx_v12_0_ring_emit_ib_compute`: an IB with `INDIRECT_BUFFER_VALID`
    /// (bit 23) set in its control word, as compute rings require.
    pub fn indirect_buffer_valid(
        &mut self,
        ib: u64,
        dwords: u32,
        vmid: u8,
    ) -> Result<(), Pm4Error> {
        self.indirect_buffer(ib, dwords, vmid)?;
        self.out[self.pos - 1] |= 1 << 23;
        Ok(())
    }

    /// Words written so far.
    pub fn words(&self) -> &[u32] {
        &self.out[..self.pos]
    }
}
