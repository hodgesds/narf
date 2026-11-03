//! GC 10.3 graphics timeout evidence. Called only after the watchdog reports
//! a hang, under the platform owner and a GFXOFF reference. Like Linux's
//! gfx_v10_0_dump_ip_state, reads status without changing selectors or CP/VM
//! control. Register values and the bounded ring window are observations,
//! not an atomic hardware snapshot or proof that an IB executed.
use super::{checked, regs::*, Error, Hw, Io, Queue, FENCE, RING_DW, RPTR, VM_FENCE};

// GC 10.3 offsets: CP/GRBM use the common gc_10_1_0 definitions included by
// gfx_v10_0.c. GCVM must use gc_10_3_0: its fault registers moved from GC10.1.
// linux-ctx: hdr=gc seg=0
const REGISTERS: [(&str, Reg); 31] = [
    ("GRBM_STATUS", Reg(0, 0x0da4)),  // linux: mmGRBM_STATUS
    ("GRBM_STATUS2", Reg(0, 0x0da2)), // linux: mmGRBM_STATUS2
    ("GRBM_STATUS3", Reg(0, 0x0da7)), // linux: mmGRBM_STATUS3
    ("CP_STAT", CP_STAT),
    ("CP_STALLED_STAT1", Reg(0, 0x0f3d)), // linux: mmCP_STALLED_STAT1
    ("CP_STALLED_STAT2", Reg(0, 0x0f3e)), // linux: mmCP_STALLED_STAT2
    ("CP_STALLED_STAT3", Reg(0, 0x0f3c)), // linux: mmCP_STALLED_STAT3
    ("CP_BUSY_STAT", Reg(0, 0x0f3f)),     // linux: mmCP_BUSY_STAT
    ("CP_GFX_ERROR", Reg(0, 0x1ddb)),     // linux: mmCP_GFX_ERROR
    ("CP_ME_HEADER_DUMP", Reg(0, 0x0f41)), // linux: mmCP_ME_HEADER_DUMP
    ("CP_PFP_HEADER_DUMP", Reg(0, 0x0f42)), // linux: mmCP_PFP_HEADER_DUMP
    ("CP_ME_INSTR_PNTR", Reg(0, 0x0f46)), // linux: mmCP_ME_INSTR_PNTR
    ("CP_PFP_INSTR_PNTR", Reg(0, 0x0f45)), // linux: mmCP_PFP_INSTR_PNTR
    ("CP_RB0_RPTR", CP_RB0_RPTR),
    ("CP_RB0_WPTR", CP_RB0_WPTR),
    ("CP_RB0_WPTR_HI", CP_RB0_WPTR_HI),
    ("CPG_UTCL1_STATUS", Reg(0, 0x1f54)), // linux: mmCPG_UTCL1_STATUS
    ("CPC_UTCL1_STATUS", Reg(0, 0x1f55)), // linux: mmCPC_UTCL1_STATUS
    ("CPF_UTCL1_STATUS", Reg(0, 0x1f56)), // linux: mmCPF_UTCL1_STATUS
    ("GCVM_FAULT_STATUS", Reg(0, 0x15c8)), // linux: mmGCVM_L2_PROTECTION_FAULT_STATUS
    ("GCVM_FAULT_ADDR_LO", Reg(0, 0x15c9)), // linux: mmGCVM_L2_PROTECTION_FAULT_ADDR_LO32
    ("GCVM_FAULT_ADDR_HI", Reg(0, 0x15ca)), // linux: mmGCVM_L2_PROTECTION_FAULT_ADDR_HI32
    ("GDS_VM_PROTECTION_FAULT", Reg(0, 0x1364)), // linux: mmGDS_VM_PROTECTION_FAULT
    // linux-ctx: seg=1
    ("CP_IB1_BASE_LO", Reg(1, 0x20cc)), // linux: mmCP_IB1_BASE_LO
    ("CP_IB1_BASE_HI", Reg(1, 0x20cd)), // linux: mmCP_IB1_BASE_HI
    ("CP_IB1_BUFSZ", Reg(1, 0x20ce)),   // linux: mmCP_IB1_BUFSZ
    ("CP_IB1_OFFSET", Reg(1, 0x2092)),  // linux: mmCP_IB1_OFFSET@gc101
    ("CP_IB2_BASE_LO", Reg(1, 0x20cf)), // linux: mmCP_IB2_BASE_LO
    ("CP_IB2_BASE_HI", Reg(1, 0x20d0)), // linux: mmCP_IB2_BASE_HI
    ("CP_IB2_BUFSZ", Reg(1, 0x20d1)),   // linux: mmCP_IB2_BUFSZ
    ("CP_IB2_OFFSET", Reg(1, 0x2093)),  // linux: mmCP_IB2_OFFSET
];
// linux-ctx: reset
const WINDOW: usize = 48;
const BEFORE_RPTR: u64 = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    registers: [u32; REGISTERS.len()],
    ring_address: u64,
    software_wptr: u64,
    emitted: u32,
    rptr_writeback: u32,
    fence: u32,
    vm_fence: u32,
    window_start: u64,
    words: [u32; WINDOW],
}

pub(super) fn capture<I: Io>(hw: &mut Hw<I>, queue: &Queue) -> Result<Snapshot, Error> {
    hw.access(|io, layout| {
        checked(io.read(layout.reg(CP_STAT)))?;
        let registers = REGISTERS.map(|(_, reg)| io.read(layout.reg(reg)));
        // One invalidate makes the writebacks and ring window CPU-visible.
        let rptr_writeback = queue.read(io, layout, RPTR);
        checked(io.read(layout.hdp + 0xd1 * 4))?;
        let window_start = (u64::from(registers[13]) + RING_DW - BEFORE_RPTR) % RING_DW;
        let words = core::array::from_fn(|i| {
            io.read_memory(queue.map(), ((window_start + i as u64) % RING_DW) * 4)
        });
        let snapshot = Snapshot {
            registers,
            ring_address: queue.address(0),
            software_wptr: queue.wptr,
            emitted: queue.seq,
            rptr_writeback,
            fence: io.read_memory(queue.map(), FENCE),
            vm_fence: io.read_memory(queue.map(), VM_FENCE),
            window_start,
            words,
        };
        checked(io.read(layout.reg(CP_STAT)))?;
        Ok(snapshot)
    })
}

impl Snapshot {
    /// Serial output runs after the platform owner and GFXOFF lease drop.
    pub(crate) fn report(&self) {
        use core::fmt::Write;
        let _ = writeln!(
            narf_console::Writer,
            "amdgpu: navi22 Gfx hang ring={:#x} sw_wptr={:#x} rptr_wb={:#x} emitted={} fence={} vm_fence={}",
            self.ring_address, self.software_wptr, self.rptr_writeback,
            self.emitted, self.fence, self.vm_fence
        );
        for ((name, _), value) in REGISTERS.iter().zip(self.registers) {
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 Gfx hang {name}={value:#010x}"
            );
        }
        for (i, words) in self.words.chunks_exact(8).enumerate() {
            let offset = (self.window_start + (i * 8) as u64) % RING_DW;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 Gfx hang ring_dw[{offset:#x}]={words:08x?}"
            );
        }
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use crate::amdgpu_cp_navi22::{doorbell, tests::*, Kind, Queue, WB};
    use crate::amdgpu_fence_navi22::Engine;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn rdna2_hang_snapshot_preserves_stalled_queue_and_wraps_ring() -> TestResult {
        let pool = pool(1 << 20);
        let mut queue = Queue::new(&pool, Kind::Cp, doorbell::GFX_RING0, Engine::Gfx).unwrap();
        let mut hw = hw(Model::new());
        queue.clear(&mut hw.io);
        for i in 0..RING_DW {
            queue.write(&mut hw.io, i * 4, &[0xcafe_0000 | i as u32]);
        }
        queue.write(&mut hw.io, WB, &[0x71, 0, 0x900, 0, 1, 0, 0, 0, 2]);
        queue.wptr = 0x900;
        queue.seq = 3;
        // Deliberately poisoned inherited selectors must remain untouched.
        hw.io.regs.insert(r(GRBM_GFX_CNTL), 0x5020);
        hw.io.regs.insert(r(GRBM_GFX_INDEX), 0x1234);
        hw.io.regs.insert(r(CP_STAT), 0x8000_0000);
        hw.io.regs.insert(r(CP_RB0_RPTR), 3);
        hw.io.regs.insert(r(Reg(0, 0x15c8)), 0xdead_beef);
        let memory = hw.io.mem.clone();
        let registers = hw.io.regs.clone();
        hw.io.writes.clear();
        let snapshot = capture(&mut hw, &queue).unwrap();
        assert_eq!(
            (snapshot.emitted, snapshot.fence, snapshot.vm_fence),
            (3, 1, 2)
        );
        assert_eq!(
            (snapshot.rptr_writeback, snapshot.software_wptr),
            (0x71, 0x900)
        );
        assert_eq!(snapshot.registers[19], 0xdead_beef);
        assert_eq!(snapshot.window_start, RING_DW - 13);
        for (i, word) in snapshot.words.iter().enumerate() {
            assert_eq!(
                *word,
                0xcafe_0000 | ((RING_DW - 13 + i as u64) % RING_DW) as u32
            );
        }
        assert_eq!(hw.io.mem, memory);
        assert_eq!(hw.io.writes, [(HDP + 0xd1 * 4, 1)]);
        assert!(hw.io.doorbells.is_empty());
        for (address, value) in registers {
            assert_eq!(hw.io.regs.get(&address), Some(&value));
        }
        assert_eq!((queue.wptr, queue.seq), (0x900, 3));
        // A raw all-ones RPTR is bounded before accessing ring memory.
        hw.io.regs.insert(r(CP_RB0_RPTR), u32::MAX);
        assert!(capture(&mut hw, &queue).unwrap().window_start < RING_DW);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/rdna2-hang",
        rdna2_hang_snapshot_preserves_stalled_queue_and_wraps_ring
    );

    fn rdna2_hang_snapshot_refuses_revoked_or_lost_device() -> TestResult {
        let pool = pool(1 << 20);
        let queue = Queue::new(&pool, Kind::Cp, doorbell::GFX_RING0, Engine::Gfx).unwrap();
        let mut hw = hw(Model::new());
        hw.io.regs.insert(r(CP_STAT), u32::MAX);
        assert_eq!(capture(&mut hw, &queue), Err(Error::DeviceGone));
        assert!(hw.io.writes.is_empty());
        hw.io.regs.insert(r(CP_STAT), 0);
        hw.authority.revoke();
        assert_eq!(capture(&mut hw, &queue), Err(Error::Revoked));
        assert!(hw.io.writes.is_empty());
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/amdgpu/rdna2-hang",
        rdna2_hang_snapshot_refuses_revoked_or_lost_device
    );
}
