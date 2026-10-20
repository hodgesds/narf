// SPDX-License-Identifier: GPL-2.0-or-later
// Ring emitters adapted from Linux jpeg_v4_0_3.c and gmc_v12_0.c:
// Copyright 2022-2023 Advanced Micro Devices, Inc.
// Upstream permission notices: ../JPEG-NOTICES.
//! JPEG5 client frames on a wrapping JRBC ring. Like Linux's parse_cs path,
//! each client IB runs as a validated kernel copy at VMID0 while the
//! decoder's data accesses use the client's MMHUB VMID.
use super::*;
use crate::amdgpu_gfx12_queue::Job;
use alloc::vec::Vec;

/// Kernel copy slots; one per job that may still be in flight.
pub const SLOTS: usize = 4;
/// One job's IB copies (NARF bound, as Navi22's `JPEG_IB_SLOT`).
pub const SLOT_BYTES: u64 = 64 << 10;
pub(super) const CLIENT_BYTES: u64 = SLOTS as u64 * SLOT_BYTES;
/// amdgpu_ring_alloc bound per job: flush 40 + PASID 4 + start/end 8 +
/// HDP 4 + 8 IBs x 22 + fence 18 = 250 dwords.
const FRAME: usize = 256;
/// amdgpu_gmc_allocate_vm_inv_eng hands MMHUB engines out in ring order:
/// VCN0's unified ring takes 0, JPEG0's decode ring 1.
const INV_ENG: u32 = 1;
const EXTERNAL: u32 = 0x1bfff;
const EXTERNAL_WRITE: u32 = 0x18000;
const RING_DW: u32 = 1024;

/// jpeg_v4_0_3_dec_ring_emit_wreg with NORMALIZE_JPEG_REG_OFFSET (JPEG5
/// has no RRMT capability). `reg` is a dword register index.
fn wreg(out: &mut Vec<u32>, reg: u32, value: u32) {
    let offset = (reg & 0x1ffff) << 2;
    if (0x10000..=0x105ff).contains(&offset) {
        out.extend_from_slice(&[EXTERNAL, 0, offset >> 2, value]);
    } else {
        out.extend_from_slice(&[EXTERNAL, offset, EXTERNAL_WRITE, value]);
    }
}
/// jpeg_v4_0_3_dec_ring_emit_reg_wait.
fn reg_wait(out: &mut Vec<u32>, reg: u32, value: u32, mask: u32) {
    let offset = (reg & 0x1ffff) << 2;
    out.extend_from_slice(&[0x4085, 0x01400200, 0x4084, value, EXTERNAL]);
    if (0x10000..=0x105ff).contains(&offset) {
        out.extend_from_slice(&[0, offset >> 2 | 3 << 28, mask]);
    } else {
        out.extend_from_slice(&[offset, EXTERNAL_WRITE | 3 << 28, mask]);
    }
}

/// Registers a VMID0 kernel IB copy must never write, although Linux's
/// `amdgpu_jpeg_dec_parse_cs` allows them: GPCOM fence/trap commands, the
/// JRBC ring/IB controls, the JRBC and decoder VMIDs and the fence address.
/// An IB that changed any of these would execute or write outside the
/// client's address space. Mesa's JPEG paths write none of them (they use
/// the IB-local condition registers 0x408e/0x408f instead).
const PRIVILEGED: [core::ops::RangeInclusive<u32>; 5] = [
    0x404d..=0x404f,
    0x4080..=0x408d,
    0x4094..=0x4094,
    0x40a0..=0x40af,
    0x40b6..=0x40bf,
];
/// `amdgpu_jpeg_dec_parse_cs` plus the privileged-register exclusion.
pub fn validate_ib(words: &[u32]) -> Result<(), Error> {
    if words.is_empty() || words.len() % 2 != 0 {
        return Err(Error::Invalid);
    }
    crate::amdgpu_vcn_navi22_cs::parse_jpeg_ib(words).map_err(|_| Error::Invalid)?;
    for pair in words.chunks_exact(2) {
        let (reg, kind) = (pair[0] & 0x3ffff, pair[0] >> 28);
        if matches!(kind, 0 | 3) && PRIVILEGED.iter().any(|r| r.contains(&reg)) {
            return Err(Error::Invalid);
        }
    }
    Ok(())
}

/// One client frame in amdgpu_ib_schedule order: VM flush and PASID
/// mapping (amdgpu_vm_flush), insert_start, HDP flush, the IBs at VMID0
/// with the client's decoder VMID, the fence/trap and insert_end.
pub(super) fn frame(
    job: &Job,
    mm: u32,
    oss: u32,
    ring: u64,
    fence: u64,
    sequence: u32,
) -> Result<Vec<u32>, Error> {
    let count = usize::from(job.ib_count);
    if !(1..16).contains(&job.vmid)
        || count == 0
        || count > job.ibs.len()
        || mm.checked_add(0x62e).is_none_or(|end| end > 0x1ffff)
        || oss.checked_add(0x1f).is_none_or(|end| end > 0x1ffff)
        || fence & 3 != 0
        || fence >= 1 << 48
        || ring & 0xff != 0
        || ring >= 1 << 48
    {
        return Err(Error::Invalid);
    }
    let mut out = Vec::with_capacity(FRAME);
    let hub = crate::amdgpu_vmhub_regs::MMHUB_V4_1;
    let vmid = u32::from(job.vmid);
    let ctx = hub.ctx_addr_distance * vmid;
    let eng = hub.eng_distance * INV_ENG;
    if job.flush {
        // gmc_v12_0_emit_flush_gpu_tlb, then jpeg_v4_0_3_dec_ring_emit_vm_flush's
        // wait for the page-table base write.
        if hub.semaphore {
            reg_wait(&mut out, mm + hub.inv_eng0_sem + eng, 1, 1);
        }
        wreg(&mut out, mm + hub.ctx0_pt_base_lo + ctx, job.pd_addr as u32);
        wreg(
            &mut out,
            mm + hub.ctx0_pt_base_hi + ctx,
            (job.pd_addr >> 32) as u32,
        );
        // amdgpu_ring_emit_reg_write_reg_wait_helper: JPEG has no oneshot.
        wreg(
            &mut out,
            mm + hub.inv_eng0_req + eng,
            crate::amdgpu_vmhub_regs::invalidate_req(job.vmid, 0),
        );
        reg_wait(&mut out, mm + hub.inv_eng0_ack + eng, 1 << vmid, 1 << vmid);
        if hub.semaphore {
            wreg(&mut out, mm + hub.inv_eng0_sem + eng, 0);
        }
        reg_wait(
            &mut out,
            mm + hub.ctx0_pt_base_lo + ctx,
            job.pd_addr as u32,
            u32::MAX,
        );
    }
    if job.map_pasid {
        // gmc_v12_0_emit_pasid_mapping: IH_VMID_0_LUT_MM for MMHUB rings.
        wreg(&mut out, oss + 0x10 + vmid, u32::from(job.pasid));
    }
    out.extend_from_slice(&[EXTERNAL, 0x69004, EXTERNAL_WRITE, 0x80010000]);
    // amdgpu_device_flush_hdp: no emit_hdp_flush, so the remapped flush word.
    wreg(&mut out, 0x7f000 / 4, 0);
    let data = vmid | vmid << 4 | vmid << 8;
    for &(address, dwords) in &job.ibs[..count] {
        if address & 0xff != 0 || address >= 1 << 48 || dwords == 0 || dwords > 0xf_ffff {
            return Err(Error::Invalid);
        }
        out.extend_from_slice(&[
            0x40a4,
            0,
            0x40a6,
            data,
            0x40b6,
            address as u32,
            0x40b7,
            (address >> 32) as u32,
            0x4082,
            dwords,
            0x42d4,
            ring as u32,
            0x42d5,
            (ring >> 32) as u32,
            0x20000000,
            0,
            0x4085,
            0x01400200,
            0x4084,
            2,
            0x33004089,
            2,
        ]);
    }
    out.extend_from_slice(&[
        0x404e,
        sequence,
        0x404f,
        sequence,
        0x40ab,
        fence as u32,
        0x40ac,
        (fence >> 32) as u32,
        0x404d,
        8,
        0x4000404d,
        0,
        words::NOP,
        0,
        words::NOP,
        0,
        0x70000000,
        0,
    ]);
    out.extend_from_slice(&[EXTERNAL, 0x69004, EXTERNAL_WRITE, 0x10000]);
    if out.len() > FRAME {
        return Err(Error::Invalid);
    }
    Ok(out)
}

impl<I: Io> Engine<I> {
    pub(super) fn open_clients(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Verified | State::DecodeVerified)
            || self.reg(RPTR)? != self.wptr
        {
            return Err(Error::Busy);
        }
        if self.client_memory.is_none() {
            let memory = self
                .pool
                .reserve(CLIENT_BYTES)
                .map_err(|_| Error::Allocation)?;
            if memory
                .address()
                .checked_add(CLIENT_BYTES)
                .is_none_or(|end| end > 1 << 48)
                || memory.address() & 0xff != 0
            {
                return Err(Error::Invalid);
            }
            self.client_memory = Some(memory);
        }
        self.shared_range()?;
        // Fetched by JRBC once a frame names it; only stop retires it.
        self.client_memory.as_mut().unwrap().publish();
        self.state = State::Clients;
        Ok(())
    }
    /// Copy validated IBs into `slot`, 256-byte aligned like amdgpu_ib_get.
    pub(super) fn stage(
        &mut self,
        slot: usize,
        copies: &[Vec<u32>],
    ) -> Result<Vec<(u64, u32)>, Error> {
        if self.state != State::Clients
            || slot >= SLOTS
            || copies.is_empty()
            || copies.len() > crate::amdgpu_gfx12_queue::MAX_JOB_IBS
        {
            return Err(Error::Invalid);
        }
        let memory = self.client_memory.as_ref().ok_or(Error::Busy)?;
        let (map, base) = (memory.mapping(), memory.address());
        let mut at = slot as u64 * SLOT_BYTES;
        let end = at + SLOT_BYTES;
        let mut placed = Vec::with_capacity(copies.len());
        for copy in copies {
            validate_ib(copy)?;
            let bytes = copy.len() as u64 * 4;
            if at.checked_add(bytes).is_none_or(|e| e > end) {
                return Err(Error::Invalid);
            }
            placed.push((at, copy));
            at = (at + bytes + 0xff) & !0xff;
        }
        let ibs = placed
            .iter()
            .map(|(at, copy)| (base + at, copy.len() as u32))
            .collect();
        self.access(|io, l| {
            for (at, copy) in &placed {
                for (n, &word) in copy.iter().enumerate() {
                    io.memory_write(map, at + n as u64 * 4, word);
                }
            }
            flush(io, l)
        })?;
        Ok(ibs)
    }
    fn emit_client(&mut self, words: &[u32]) -> Result<u32, Error> {
        if self.state != State::Clients || words.is_empty() || words.len() % 2 != 0 {
            return Err(Error::Invalid);
        }
        let padded = (words.len() as u32 + 15) & !15;
        let rptr = self.reg(RPTR)?;
        if rptr >= RING_DW {
            return Err(Error::Readback);
        }
        // ptr_mask is buf_mask: keep a gap so equal pointers mean empty.
        let pending = self.wptr.wrapping_sub(rptr) & (RING_DW - 1);
        if pending + padded >= RING_DW {
            return Err(Error::Busy);
        }
        self.shared_range()?;
        let next = (self.wptr + padded) & (RING_DW - 1);
        let (map, start) = (self.memory.mapping(), self.wptr);
        self.access(|io, l| {
            for n in 0..padded {
                let value = words.get(n as usize).copied().unwrap_or(if n % 2 == 0 {
                    words::NOP
                } else {
                    0
                });
                let at = RING + u64::from((start + n) & (RING_DW - 1)) * 4;
                io.memory_write(map, at, value);
            }
            io.memory_write(map, WRITEBACK, next);
            flush(io, l)?;
            // Publication is last; afterwards the caller owns the sequence
            // and must retain the job's resources through error recovery.
            io.doorbell(DOORBELL, next);
            Ok(())
        })?;
        self.wptr = next;
        Ok(next)
    }
    pub(super) fn submit(&mut self, job: Job) -> Result<u32, Error> {
        if self.state != State::Clients {
            return Err(Error::Busy);
        }
        let memory = self.client_memory.as_ref().ok_or(Error::Busy)?;
        let base = memory.address();
        // Only staged kernel copies: each IB inside one slot of the arena.
        for &(address, dwords) in &job.ibs[..usize::from(job.ib_count).min(job.ibs.len())] {
            let offset = address.checked_sub(base).ok_or(Error::Invalid)?;
            let end = offset
                .checked_add(u64::from(dwords) * 4)
                .ok_or(Error::Invalid)?;
            if offset >= CLIENT_BYTES || end > (offset / SLOT_BYTES + 1) * SLOT_BYTES {
                return Err(Error::Invalid);
            }
        }
        let seq = self.seq.wrapping_add(1);
        let main = self.memory.address();
        let words = frame(
            &job,
            (self.layout.mm / 4) as u32,
            (self.layout.oss / 4) as u32,
            main + RING,
            main + FENCE,
            seq,
        )?;
        match self.emit_client(&words) {
            Ok(_) => {
                self.seq = seq;
                Ok(seq)
            }
            Err(e @ (Error::Busy | Error::Invalid)) => Err(e),
            Err(e) => {
                self.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// Retire a ring that may still hold an unfinished job: JMI soft reset
    /// (jpeg_v5_0_0_stop) and fresh clean-DMA evidence before static power
    /// gating. Only success permits PowerDownJpeg or a restart.
    pub(super) async fn reset_stop(&mut self) -> Result<(), Error> {
        if matches!(
            self.state,
            State::Prepared | State::Stopped | State::Stopping | State::Starting
        ) {
            return Err(Error::Busy);
        }
        self.state = State::Stopping;
        let result = async {
            self.shared_range()?;
            self.set(IRQ, 0x100, 0)?;
            self.set(JMI, 1, 1)?;
            self.wait(CLEAN, CLEAN_MASK, CLEAN_VALUE).await?;
            self.set(CNTL, 3, 3)?;
            self.set(DB, 1 << 30, 0)?;
            self.set(CG_CTRL, 1 << 16, 1 << 16)?;
            self.set(CG_GATE, CG_GATES, CG_GATES)?;
            self.set(POWER, 1, 1)?;
            self.set(DLDO_CONFIG, 3 << 4, 2 << 4)?;
            self.wait(DLDO_STATUS, 4, 4).await?;
            self.shared_range()
        }
        .await
        .and_then(|()| self.access(|_, _| Ok(())));
        self.state = match result {
            Ok(()) => State::Stopped,
            Err(e) => State::Failed(e),
        };
        if result.is_ok() {
            // SAFETY: JMI was reset with every read/write channel clean and
            // no MC write pending, then the JRBC doorbell and power domain
            // were closed; nothing can fetch these ranges until restart.
            unsafe {
                self.memory.stopped();
                for memory in [self.decode_memory.as_mut(), self.client_memory.as_mut()]
                    .into_iter()
                    .flatten()
                {
                    memory.stopped();
                }
            }
        }
        result
    }
}
pub(super) fn client_fence(
    io: &mut impl Io,
    authority: Cap<BusDeviceCap, Write>,
    l: Layout,
    map: MmioRegion,
) -> Result<u32, Error> {
    let value = authority
        .invoke(Op(|| {
            checked(io.read(l.vcn + u64::from(STATUS) * 4))?;
            flush(io, l)?;
            let value = io.memory_read(map, FENCE);
            checked(io.read(l.vcn + u64::from(STATUS) * 4))?;
            checked(io.read(l.nbio + 0xc3 * 4))?;
            Ok(value)
        }))
        .map_err(|_| Error::Revoked)??;
    authority.invoke(Op(|| ())).map_err(|_| Error::Revoked)?;
    Ok(value)
}
