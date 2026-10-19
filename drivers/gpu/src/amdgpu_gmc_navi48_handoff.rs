//! Fresh client-context ownership checks before transferring IRQ controls.
use super::*;
use crate::amdgpu_vmhub_regs as hub;

impl<I: Io> Engine<I> {
    pub(super) fn fault_contexts(&mut self) -> Result<[u32; 2], Error> {
        if self.state != State::ClientsReady {
            return Err(Error::Busy);
        }
        let geometry = self.geometry.ok_or(Error::Invalid)?;
        let root = geometry.physical(self.memory.address() + EMPTY_ROOT) | 1;
        let vm = crate::amdgpu_vm::Geometry::GMC12;
        let layout = self.layout;
        self.access(|io| {
            let mut controls = [0; 2];
            for (i, (bank, regs)) in layout
                .bases
                .into_iter()
                .zip([hub::GFXHUB_V12_0, hub::MMHUB_V4_1])
                .enumerate()
            {
                let cntl = hub::vmid_cntl_value(&regs, vm.num_level(), vm.block_size as u8, true);
                for vmid in 1..16u32 {
                    let reg = |r: u32, stride: u32| bank + u64::from(r + stride * vmid) * 4;
                    if checked(io.read(reg(regs.ctx0_cntl, regs.ctx_distance)))? != cntl {
                        return Err(Error::Invalid);
                    }
                    for (lo_reg, hi_reg, expected) in [
                        (regs.ctx0_pt_base_lo, regs.ctx0_pt_base_hi, root),
                        (regs.ctx0_pt_start_lo, regs.ctx0_pt_start_hi, 0),
                        (regs.ctx0_pt_end_lo, regs.ctx0_pt_end_hi, vm.max_pfn - 1),
                    ] {
                        let lo = io.read(reg(lo_reg, regs.ctx_addr_distance));
                        // The end page has a valid all-ones low word. Its high
                        // word is still checked for device removal.
                        if lo == u32::MAX && expected as u32 != u32::MAX {
                            return Err(Error::DeviceGone);
                        }
                        let hi = checked(io.read(reg(hi_reg, regs.ctx_addr_distance)))?;
                        if u64::from(lo) | u64::from(hi) << 32 != expected {
                            return Err(Error::Invalid);
                        }
                    }
                }
                controls[i] = cntl;
            }
            Ok(controls)
        })
    }
}
impl Gmc {
    /// Before any client submission, verify all client VMIDs still describe
    /// this owner's empty root and native nonretrying configuration. The IRQ
    /// monitor must use the same permanent register mapping.
    pub(crate) fn fault_contexts(&mut self, regs: MmioRegion) -> Result<[u32; 2], Error> {
        let own = self.engine.io.0;
        if own.phys != regs.phys || own.virt != regs.virt || own.len != regs.len {
            return Err(Error::Invalid);
        }
        self.engine.fault_contexts()
    }
}
