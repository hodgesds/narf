//! VCN5 client frames, vcn_v5_0_0's vcn_v2_0 unified ring emitters.
//! Used only with a separately owned MMHUB VMID and pinned job resources.
use super::*;
use crate::amdgpu_gfx12_queue::Job;

pub(super) const JOB_DWORDS: usize = 256;
struct Slot {
    words: [u32; JOB_DWORDS],
    used: usize,
}
impl Slot {
    fn push(&mut self, words: &[u32]) -> Result<(), Error> {
        let end = self.used.checked_add(words.len()).ok_or(Error::Invalid)?;
        self.words
            .get_mut(self.used..end)
            .ok_or(Error::Invalid)?
            .copy_from_slice(words);
        self.used = end;
        Ok(())
    }
    fn write(&mut self, reg: u32, value: u32) -> Result<(), Error> {
        self.push(&[0xb, reg.checked_mul(4).ok_or(Error::Invalid)?, value])
    }
    fn wait(&mut self, reg: u32, value: u32, mask: u32) -> Result<(), Error> {
        self.push(&[0xc, reg.checked_mul(4).ok_or(Error::Invalid)?, mask, value])
    }
}
/// MMHUB invalidation engine 0 is private to VCN0 (CPU uses 17; no UMSCH
/// or JPEG client ring shares it). `oss` is OSSSYS bank 0's dword base.
pub(super) fn job_words(
    job: Job,
    mm: u32,
    oss: u32,
    fence: u64,
    sequence: u32,
) -> Result<[u32; JOB_DWORDS], Error> {
    let count = usize::from(job.ib_count);
    if !(1..16).contains(&job.vmid)
        || count == 0
        || count > job.ibs.len()
        || mm
            .checked_add(0x62e)
            .and_then(|at| at.checked_mul(4))
            .is_none()
        || oss
            .checked_add(0x1f)
            .and_then(|at| at.checked_mul(4))
            .is_none()
        || fence & 3 != 0
        || fence >= 1 << 48
        || job.ibs[..count]
            .iter()
            .any(|&(at, dw)| at & 3 != 0 || dw == 0 || dw > 0xf_ffff)
    {
        return Err(Error::Invalid);
    }
    let mut slot = Slot {
        words: [0; JOB_DWORDS],
        used: 0,
    };
    let hub = crate::amdgpu_vmhub_regs::MMHUB_V4_1;
    let vmid = u32::from(job.vmid);
    if job.flush {
        if hub.semaphore {
            slot.wait(mm + hub.inv_eng0_sem, 1, 1)?;
        }
        let ctx = hub.ctx_addr_distance * vmid;
        slot.write(mm + hub.ctx0_pt_base_lo + ctx, job.pd_addr as u32)?;
        slot.write(mm + hub.ctx0_pt_base_hi + ctx, (job.pd_addr >> 32) as u32)?;
        slot.write(
            mm + hub.inv_eng0_req,
            crate::amdgpu_vmhub_regs::invalidate_req(job.vmid, 0),
        )?;
        slot.wait(mm + hub.inv_eng0_ack, 1 << vmid, 1 << vmid)?;
        if hub.semaphore {
            slot.write(mm + hub.inv_eng0_sem, 0)?;
        }
        // vcn_v2_0_enc_ring_emit_vm_flush also waits for the PTB low word,
        // after gmc_v12_0's invalidate/semaphore sequence.
        slot.wait(mm + hub.ctx0_pt_base_lo + ctx, job.pd_addr as u32, u32::MAX)?;
    }
    if job.map_pasid {
        // gmc_v12_0_emit_pasid_mapping uses IH_VMID_0_LUT_MM on MMHUB.
        slot.write(oss + 0x10 + vmid, u32::from(job.pasid))?;
    }
    // amdgpu_device_flush_hdp -> amdgpu_hdp_generic_flush: VCN has no
    // emit_hdp_flush callback, so emit_wreg writes the remapped flush word.
    slot.write(0x7f000 / 4, 0)?;
    for &(address, dwords) in &job.ibs[..count] {
        slot.push(&[2, vmid, address as u32, (address >> 32) as u32, dwords])?;
    }
    // no_user_fence: only the owned kernel fence, 32-bit, then TRAP/END.
    slot.push(&[3, fence as u32, (fence >> 32) as u32, sequence, 4, 1])?;
    Ok(slot.words)
}

impl<I: Io> Engine<I> {
    pub(super) fn submit(&mut self, job: Job) -> Result<u32, Error> {
        if self.state != State::InterruptVerified {
            return Err(Error::Busy);
        }
        let seq = self.seq.wrapping_add(1);
        let words = job_words(
            job,
            (self.layout.mm / 4) as u32,
            (self.layout.oss / 4) as u32,
            self.memory.address() + FENCE,
            seq,
        )?;
        let result = self.emit(&words);
        match result {
            Ok(_) => {
                self.seq = seq;
                Ok(seq)
            }
            Err(Error::Busy | Error::Invalid) => result,
            Err(e) => {
                self.state = State::Failed(e);
                Err(e)
            }
        }
    }
    pub(super) fn completed_job(&mut self) -> Result<u32, Error> {
        let map = self.memory.mapping();
        self.access(|io, l| {
            checked(io.read(l.vcn + u64::from(STATUS) * 4))?;
            flush(io, l)?;
            Ok(io.memory_read(map, FENCE))
        })
    }
}
