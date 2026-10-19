//! Discrete RDNA2 SDMA0 cold-start and translated VRAM write/copy/fence proof.
//! Register/packet sources: Linux sdma_v5_2.c, gc_10_3_0_{offset,sh_mask}.h,
//! navi10_sdma_pkt_open.h. No host DMA, user submissions, IRQs or recovery.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip, amdgpu_gmc_navi22 as gmc,
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
const BYTES: u64 = 8192; // linux: n/a (NARF ring + writeback allocation)
const RPTR: u64 = 4096; // linux: n/a (NARF writeback layout)
const WPTR: u64 = 4104; // linux: n/a (NARF writeback layout)
const FENCE: u64 = 8188; // linux: n/a (last dword of GMC's destination page)
const SEQUENCE: u32 = 0x6750_0022; // linux: n/a (NARF fence sequence)
                                   // linux-ctx: hdr=gc seg=0
const RESET: u32 = 0x0da8; // linux: mmGRBM_SOFT_RESET
const RESET_SDMA0: u32 = 1 << 23; // linux: GRBM_SOFT_RESET__SOFT_RESET_SDMA0_MASK
const RB_CNTL: u32 = 0x80; // linux: mmSDMA0_GFX_RB_CNTL
const RB_RPTR: u32 = 0x83; // linux: mmSDMA0_GFX_RB_RPTR
const RB_WPTR: u32 = 0x85; // linux: mmSDMA0_GFX_RB_WPTR
                           // linux-ctx: reset
const TRAP_END: u32 = 192; // linux: n/a (first submission plus one 16-dword TRAP block)
const PATTERN: [u32; 16] = [
    0x01234567, 0x89abcdef, 0x76543210, 0xfedcba98, 0xaaaaaaaa, 0x55555555, 0xff00ff00, 0x00ff00ff,
    0x00000001, 0x80000000, 0x01010101, 0x10101010, 0x67506750, 0x00220022, 0xdeadbeef, 0xcafebabe,
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Timeout,
    DataMismatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    ResetAsserted,
    ResetReleased,
    Programming,
    Submitted,
    Verified,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub copied_bytes: u32,
    pub fence: u32,
    pub read_pointer: u64,
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    gc: u64,
    nbio: u64,
    hdp: u64,
    /// RCC_CONFIG_MEMSIZE (`gmc.mc_vram_size`): the FB aperture's length.
    vram_size: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR || gpu.chip.did != crate::amdgpu::NAVI22 {
            return Err(Error::Unsupported);
        }
        Self::resolve_for(gpu, &crate::amdgpu_rdna2::NAVI22)
    }
    fn resolve_rdna2(gpu: &AmdGpu) -> Result<Self, Error> {
        let profile = crate::amdgpu_rdna2::for_pci_id(gpu.chip.vid, gpu.chip.did)
            .ok_or(Error::Unsupported)?;
        Self::resolve_for(gpu, profile)
    }
    fn resolve_for(gpu: &AmdGpu, profile: &crate::amdgpu_rdna2::Profile) -> Result<Self, Error> {
        // linux: n/a (BAR5 bound: MMIO_REG_HOLE_OFFSET + 4)
        if gpu.regs.len < 0x7f004 {
            return Err(Error::Unsupported);
        }
        let mut blocks = gpu
            .ip_blocks
            .iter()
            .filter(|b| b.hw_id == ip::HW_ID_SDMA0 && b.instance == 0);
        let sdma = blocks.next().ok_or(Error::Unsupported)?;
        // linux: n/a (exact per-ASIC SDMA5.2 discovery version)
        if blocks.next().is_some()
            || (sdma.major, sdma.minor, sdma.revision) != profile.sdma_version
        {
            return Err(Error::Unsupported);
        }
        let resolve = |id, versions: &[(u8, u8, u8)], index, last| {
            bank(gpu, id, versions, index, last).map_err(|_| Error::Unsupported)
        };
        Ok(Self {
            // SDMA0 is in GC bank zero, NOT the standalone discovery SDMA bank.
            vram_size: gpu.vram.size,
            // linux-lit: 0=mmGCMC_VM_FB_LOCATION_TOP_BASE_IDX@gc; 0x16fd=mmGCMC_VM_FB_LOCATION_TOP@gc
            gc: resolve(ip::HW_ID_GC, &[profile.gc_version], 0, 0x16fd)?,
            nbio: resolve(
                ip::HW_ID_NBIF,
                &[
                    (2, 3, 0),
                    (2, 3, 1),
                    (2, 3, 2),
                    (3, 3, 0),
                    (3, 3, 1),
                    (3, 3, 2),
                    (3, 3, 3),
                ],
                2,     // linux-lit: 2=mmREMAP_HDP_MEM_FLUSH_CNTL_BASE_IDX
                0x12d, // linux-lit: 0x12d=mmREMAP_HDP_MEM_FLUSH_CNTL
            )?,
            hdp: resolve(
                ip::HW_ID_HDP,
                &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3), (5, 0, 4)],
                0,    // linux-lit: 0=mmHDP_READ_CACHE_INVALIDATE_BASE_IDX
                0xd1, // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
            )?,
        })
    }
}
trait Io {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32;
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32);
    /// Hardware reset settling time. Models may yield deterministically so
    /// cancellation tests need not win a 50-us scheduling window under QEMU.
    async fn reset_delay(&mut self) {
        delay(50).await;
    }
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: Layout bounds GC/NBIO/HDP registers and the HDP remap. The
        // exclusive owner invokes every I/O batch under live PCI authority.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same validated register mapping and live authority.
        unsafe { self.0.write32(address, value) };
    }
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32 {
        // SAFETY: internal offsets are bounded by the retained ring allocation
        // or the borrowed GMC's two owned test pages, both permanently mapped.
        unsafe { map.read32(offset) }
    }
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: same retained allocations and bounded dword offsets.
        unsafe { map.write32(offset, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn checked(value: u32) -> Result<u32, Error> {
    if value == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(value)
    }
}
fn update<I: Io>(io: &mut I, gc: u64, reg: u32, mask: u32, value: u32) -> Result<(), Error> {
    let address = gc + u64::from(reg) * 4;
    let old = checked(io.read(address))?;
    io.write(address, (old & !mask) | value);
    Ok(())
}
fn flush<I: Io>(io: &mut I, l: Layout) {
    fence(Ordering::SeqCst);
    // linux: n/a (literal in nbio_v2_3.c:MMIO_REG_HOLE_OFFSET 0x80000 - PAGE_SIZE, + KFD_MMIO_REMAP_HDP_MEM_FLUSH_CNTL 0)
    io.write(0x7f000, 0);
    io.read(l.nbio + 0xc3 * 4); // linux-lit: 0xc3=mmRCC_DEV0_EPF0_RCC_CONFIG_MEMSIZE
    fence(Ordering::SeqCst);
}
fn invalidate<I: Io>(io: &mut I, l: Layout) {
    io.write(l.hdp + 0xd1 * 4, 1); // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
    io.read(l.hdp + 0xd1 * 4); // linux-lit: 0xd1=mmHDP_READ_CACHE_INVALIDATE
    fence(Ordering::SeqCst);
}
fn packets(aperture: gmc::Aperture) -> [u32; 32] {
    let mut words = [0; 32];
    words[..4].copy_from_slice(&[
        // linux-lit: 2=SDMA_PKT_HEADER_OP(SDMA_OP_WRITE) | SDMA_PKT_HEADER_SUB_OP(SDMA_SUBOP_WRITE_LINEAR)
        2,
        aperture.source as u32,
        (aperture.source >> 32) as u32,
        15, // linux-lit: 15=SDMA_PKT_WRITE_UNTILED_DW_3_COUNT(16 - 1)
    ]);
    words[4..20].copy_from_slice(&PATTERN);
    words[20..27].copy_from_slice(&[
        // linux-lit: 1=SDMA_PKT_HEADER_OP(SDMA_OP_COPY) | SDMA_PKT_HEADER_SUB_OP(SDMA_SUBOP_COPY_LINEAR)
        1,
        63, // linux-lit: 63=SDMA_PKT_COPY_LINEAR_COUNT_COUNT(64 - 1)
        0,  // linux: n/a (COPY_LINEAR parameter dword 0, as sdma_v5_2_emit_copy_buffer)
        aperture.source as u32,
        (aperture.source >> 32) as u32,
        aperture.destination as u32,
        (aperture.destination >> 32) as u32,
    ]);
    // linux: n/a (NARF layout: fence in last dword of destination page)
    let address = aperture.destination + 4092;
    // linux-lit: 0x30005=SDMA_PKT_HEADER_OP(SDMA_OP_FENCE) | SDMA_PKT_FENCE_HEADER_MTYPE(0x3)
    words[27..31].copy_from_slice(&[0x30005, address as u32, (address >> 32) as u32, SEQUENCE]);
    // Single-dword NOP pads the submission to a sixteen-dword boundary.
    words
}
async fn delay(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    state: State,
    proof: Option<Proof>,
    trapped: bool,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
    }
    async fn initialize(
        &mut self,
        aperture: gmc::Aperture,
        target: MmioRegion,
    ) -> Result<Proof, Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.state = State::Programming;
        let result = self.initialize_inner(aperture, target).await;
        self.state = if result.is_ok() {
            State::Verified
        } else {
            State::Failed
        };
        if let Ok(proof) = result {
            self.proof = Some(proof);
        }
        result
    }
    async fn initialize_inner(
        &mut self,
        aperture: gmc::Aperture,
        target: MmioRegion,
    ) -> Result<Proof, Error> {
        let l = self.layout;
        let address = self.memory.address();
        self.access(|io| {
            // linux-lit: 0x16fc=mmGCMC_VM_FB_LOCATION_BASE@gc; 0xffffff=GCMC_VM_FB_LOCATION_BASE__FB_BASE_MASK@gc
            let fb = u64::from(checked(io.read(l.gc + 0x16fc * 4))? & 0xffffff) << 24;
            // amdgpu_gmc_vram_location: vram_end = vram_start + mc_vram_size
            // - 1. FB_LOCATION_TOP is VBIOS/previous-driver state (16 MiB
            // granular) and is only checked for a present device here.
            checked(io.read(l.gc + 0x16fd * 4))?;
            let end = fb.checked_add(l.vram_size).ok_or(Error::Invalid)?;
            // The boot aperture is the head of Linux's BEST_FIT GART range
            // (0 below a high FB), never inside the FB aperture itself.
            let aperture_end = aperture.start.checked_add(aperture.size);
            if target.len != 8192 // linux: n/a (NARF GMC test-page size)
                || address < fb
                || address.checked_add(BYTES).is_none_or(|v| v > end)
                || end >= 1 << 48 // linux: n/a (48-bit gmc_v10 mc_mask bound)
                || aperture.size != 2 << 20 // linux: n/a (NARF GMC boot aperture size)
                || aperture.start % (2 << 20) != 0
                // linux: n/a (48-bit gmc_v10 mc_mask bound)
                || aperture_end.is_none_or(|v| v > 1 << 48)
                || (aperture.start < end && aperture_end.is_some_and(|v| fb < v))
                || aperture.source != aperture.start
                // linux: n/a (NARF GMC test-page layout)
                || aperture.destination != aperture.start + 4096
                // linux-lit: 0x12d=mmREMAP_HDP_MEM_FLUSH_CNTL
                || checked(io.read(l.nbio + 0x12d * 4))? != 0x7f000
            {
                return Err(Error::Invalid);
            }
            // Never reset an inherited ring or a concurrently owned engine.
            // linux-lit: 0x80=mmSDMA0_GFX_RB_CNTL@gc; 0xd8=mmSDMA0_PAGE_RB_CNTL@gc
            // linux-lit: 0x130=mmSDMA0_RLC0_RB_CNTL@gc; 0x188=mmSDMA0_RLC1_RB_CNTL@gc
            for reg in [0x80, 0xd8, 0x130, 0x188] {
                // linux-lit: 1=SDMA0_GFX_RB_CNTL__RB_ENABLE_MASK@gc
                if checked(io.read(l.gc + reg * 4))? & 1 != 0 {
                    return Err(Error::Busy);
                }
            }
            // sdma_v5_2_start soft-resets SDMA without first requiring
            // SDMA0_STATUS_REG.IDLE; only a GRBM reset already in flight
            // is refused here.
            if checked(io.read(l.gc + u64::from(RESET) * 4))? != 0 {
                return Err(Error::Busy);
            }
            Ok(())
        })?;
        // Publish before reset/programming so every started attempt retains
        // ring/writeback storage even if its future is cancelled mid-reset.
        self.memory.publish();
        self.state = State::ResetAsserted;
        self.access(|io| {
            update(io, l.gc, RESET, RESET_SDMA0, RESET_SDMA0)?;
            checked(io.read(l.gc + u64::from(RESET) * 4))?;
            Ok(())
        })?;
        self.io.reset_delay().await;
        self.state = State::ResetReleased;
        self.access(|io| {
            update(io, l.gc, RESET, RESET_SDMA0, 0)?;
            checked(io.read(l.gc + u64::from(RESET) * 4))?;
            Ok(())
        })?;
        self.io.reset_delay().await;
        self.state = State::Programming;
        let map = self.memory.mapping();
        let words = packets(aperture);
        self.access(|io| {
            for offset in (0..BYTES).step_by(4) {
                io.write_memory(map, offset, 0);
            }
            for (i, value) in words.into_iter().enumerate() {
                io.write_memory(map, i as u64 * 4, value);
            }
            for offset in (0..8192).step_by(4) {
                // linux: n/a (NARF GMC test-page size)
                io.write_memory(target, offset, 0);
            }
            flush(io, l);
            // Only one privileged direct ring, VMID0. No traps, paging IRQs,
            // preemption, automatic context switches or indirect buffers.
            // linux-lit: 0x1c=mmSDMA0_CNTL@gc; 2=SDMA0_CNTL__UTC_L1_ENABLE_MASK@gc
            // linux-lit: 0x700600bf=SDMA0_CNTL__TRAP_ENABLE_MASK@gc | SDMA0_CNTL__UTC_L1_ENABLE_MASK@gc | SDMA0_CNTL__SEM_WAIT_INT_ENABLE_MASK@gc | SDMA0_CNTL__DATA_SWAP_ENABLE_MASK@gc | SDMA0_CNTL__FENCE_SWAP_ENABLE_MASK@gc | SDMA0_CNTL__MIDCMD_PREEMPT_ENABLE_MASK@gc | SDMA0_CNTL__PAGE_INT_ENABLE_MASK@gc | SDMA0_CNTL__MIDCMD_WORLDSWITCH_ENABLE_MASK@gc | SDMA0_CNTL__AUTO_CTXSW_ENABLE_MASK@gc | SDMA0_CNTL__CTXEMPTY_INT_ENABLE_MASK@gc | SDMA0_CNTL__FROZEN_INT_ENABLE_MASK@gc | SDMA0_CNTL__IB_PREEMPT_INT_ENABLE_MASK@gc
            update(io, l.gc, 0x1c, 0x700600bf, 2)?;
            // linux-lit: 0x2a=mmSDMA0_F32_CNTL@gc; 1=SDMA0_F32_CNTL__HALT_MASK@gc
            update(io, l.gc, 0x2a, 1, 1)?; // halt while programming
            io.write(l.gc + 0x21 * 4, 0); // linux-lit: 0x21=mmSDMA0_SEM_WAIT_FAIL_TIMER_CNTL@gc
                                          // linux-lit: 0x0f80323f=SDMA0_GFX_RB_CNTL__RB_ENABLE_MASK@gc | SDMA0_GFX_RB_CNTL__RB_SIZE_MASK@gc | SDMA0_GFX_RB_CNTL__RB_SWAP_ENABLE_MASK@gc | SDMA0_GFX_RB_CNTL__RPTR_WRITEBACK_ENABLE_MASK@gc | SDMA0_GFX_RB_CNTL__RPTR_WRITEBACK_SWAP_ENABLE_MASK@gc | SDMA0_GFX_RB_CNTL__RB_PRIV_MASK@gc | SDMA0_GFX_RB_CNTL__RB_VMID_MASK@gc
                                          // linux-lit: 0x00801014=SDMA0_GFX_RB_CNTL__RB_PRIV_MASK@gc | SDMA0_GFX_RB_CNTL__RPTR_WRITEBACK_ENABLE_MASK@gc | (10 << SDMA0_GFX_RB_CNTL__RB_SIZE__SHIFT@gc)
            update(io, l.gc, RB_CNTL, 0x0f80323f, 0x00801014)?;
            // linux-lit: 0x8a=mmSDMA0_GFX_IB_CNTL@gc; 0x000f0011=SDMA0_GFX_IB_CNTL__IB_ENABLE_MASK@gc | SDMA0_GFX_IB_CNTL__IB_SWAP_ENABLE_MASK@gc | SDMA0_GFX_IB_CNTL__CMD_VMID_MASK@gc
            update(io, l.gc, 0x8a, 0x000f0011, 0)?;
            io.write(l.gc + 0xb5 * 4, 1); // linux-lit: 0xb5=mmSDMA0_GFX_MINOR_PTR_UPDATE@gc
                                          // linux-lit: 0x83=mmSDMA0_GFX_RB_RPTR@gc; 0x84=mmSDMA0_GFX_RB_RPTR_HI@gc; 0x85=mmSDMA0_GFX_RB_WPTR@gc; 0x86=mmSDMA0_GFX_RB_WPTR_HI@gc
            for reg in [0x83, 0x84, 0x85, 0x86] {
                io.write(l.gc + reg * 4, 0);
            }
            // linux-lit: 0x88=mmSDMA0_GFX_RB_RPTR_ADDR_HI@gc; 0x89=mmSDMA0_GFX_RB_RPTR_ADDR_LO@gc
            // linux-lit: 0xb2=mmSDMA0_GFX_RB_WPTR_POLL_ADDR_HI@gc; 0xb3=mmSDMA0_GFX_RB_WPTR_POLL_ADDR_LO@gc
            for (hi, lo, value) in [(0x88, 0x89, address + RPTR), (0xb2, 0xb3, address + WPTR)] {
                io.write(l.gc + hi * 4, (value >> 32) as u32);
                io.write(l.gc + lo * 4, value as u32);
            }
            // linux-lit: 0x81=mmSDMA0_GFX_RB_BASE@gc
            io.write(l.gc + 0x81 * 4, (address >> 8) as u32);
            // linux-lit: 0x82=mmSDMA0_GFX_RB_BASE_HI@gc
            io.write(l.gc + 0x82 * 4, (address >> 40) as u32);
            // linux-lit: 0x87=mmSDMA0_GFX_RB_WPTR_POLL_CNTL@gc; 4=SDMA0_GFX_RB_WPTR_POLL_CNTL__F32_POLL_ENABLE_MASK@gc
            update(io, l.gc, 0x87, 4, 4)?;
            // linux-lit: 0x92=mmSDMA0_GFX_DOORBELL@gc; 28=SDMA0_GFX_DOORBELL__ENABLE__SHIFT@gc
            update(io, l.gc, 0x92, 1 << 28, 0)?; // MMIO wptr, no BAR2 doorbell
            io.write(l.gc + 0xb5 * 4, 0); // linux-lit: 0xb5=mmSDMA0_GFX_MINOR_PTR_UPDATE@gc
                                          // linux-lit: 0x3c=mmSDMA0_UTCL1_CNTL@gc; 0xe3e=SDMA0_UTCL1_CNTL__RESP_MODE_MASK@gc | SDMA0_UTCL1_CNTL__REDO_DELAY_MASK@gc
                                          // linux-lit: 9=SDMA0_UTCL1_CNTL__RESP_MODE__SHIFT@gc; 1=SDMA0_UTCL1_CNTL__REDO_DELAY__SHIFT@gc
            update(io, l.gc, 0x3c, 0xe3e, (3 << 9) | (9 << 1))?;
            // linux-lit: 0x48=mmSDMA0_UTCL1_PAGE@gc; 0xff0fff=0xFF0FFF
            // linux-lit: 0x0100e000=(2 << 12) | (3 << 14) | SDMA0_UTCL1_PAGE__LLC_NOALLOC_MASK@gc
            update(io, l.gc, 0x48, !0xff0fff, 0x0100e000)?; // NOA read, bypass write
                                                            // linux-lit: 0x2a=mmSDMA0_F32_CNTL@gc; 1=SDMA0_F32_CNTL__HALT_MASK@gc
            update(io, l.gc, 0x2a, 1, 0)?;
            update(io, l.gc, RB_CNTL, 1, 1)?; // linux-lit: 1=SDMA0_GFX_RB_CNTL__RB_ENABLE_MASK@gc
            Ok(())
        })?;
        self.state = State::Submitted;
        self.access(|io| {
            // linux: n/a (128-byte first submission)
            io.write_memory(map, WPTR, 128); // pointers are bytes, not dwords
            flush(io, l);
            io.write(l.gc + u64::from(RB_WPTR) * 4, 128);
            // linux-lit: 1=mmSDMA0_GFX_RB_WPTR_HI@gc - mmSDMA0_GFX_RB_WPTR@gc
            io.write(l.gc + u64::from(RB_WPTR + 1) * 4, 0);
            Ok(())
        })?;
        // linux: n/a (AMDGPU_IB_TEST_TIMEOUT-style 1 s NARF bound)
        let deadline = narf_time::Deadline::after_ms(1000);
        loop {
            let proof = self.access(|io| {
                invalidate(io, l);
                let fence = io.read_memory(target, FENCE);
                let lo = checked(io.read(l.gc + u64::from(RB_RPTR) * 4))?;
                // linux-lit: 1=mmSDMA0_GFX_RB_RPTR_HI@gc - mmSDMA0_GFX_RB_RPTR@gc
                let hi = checked(io.read(l.gc + u64::from(RB_RPTR + 1) * 4))?;
                let read_pointer = u64::from(lo) | (u64::from(hi) << 32);
                let writeback = u64::from(io.read_memory(map, RPTR))
                    | (u64::from(io.read_memory(map, RPTR + 4)) << 32);
                if fence != SEQUENCE || read_pointer != 128 || writeback != 128 {
                    return Ok(None);
                }
                for (i, value) in PATTERN.into_iter().enumerate() {
                    for page in [0, 4096] {
                        if io.read_memory(target, page + i as u64 * 4) != value {
                            return Err(Error::DataMismatch);
                        }
                    }
                }
                Ok(Some(Proof {
                    copied_bytes: 64, // linux: n/a (NARF proof field)
                    fence,
                    read_pointer,
                }))
            })?;
            if let Some(proof) = proof {
                return Ok(proof);
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay(1000).await; // linux: n/a (NARF poll interval)
        }
    }
}
impl<I: Io> Engine<I> {
    /// sdma_v5_2_ring_emit_fence's FLAG_INT tail: SDMA_OP_TRAP with an
    /// INT_CONTEXT, after setting SDMA0_CNTL.TRAP_ENABLE
    /// (sdma_v5_2_set_trap_irq_state). Single use, never replayed.
    async fn trap(&mut self, context: u32) -> Result<(), Error> {
        if self.state != State::Verified || self.trapped {
            return Err(Error::Busy);
        }
        self.trapped = true;
        let result = self.trap_inner(context).await;
        if result.is_err() {
            self.state = State::Failed;
        }
        result
    }
    async fn trap_inner(&mut self, context: u32) -> Result<(), Error> {
        let l = self.layout;
        let map = self.memory.mapping();
        self.access(|io| {
            io.write_memory(map, 128, 6); // linux-lit: 6=SDMA_PKT_HEADER_OP(SDMA_OP_TRAP)
                                          // linux-lit: 0x0fff_ffff=SDMA_PKT_TRAP_INT_CONTEXT_int_context_mask
            io.write_memory(map, 132, context & 0x0fff_ffff);
            // linux: n/a (NARF NOP padding range)
            for offset in (136..u64::from(TRAP_END)).step_by(4) {
                io.write_memory(map, offset, 0); // NOP padding
            }
            // linux-lit: 0x1c=mmSDMA0_CNTL@gc; 1=SDMA0_CNTL__TRAP_ENABLE_MASK@gc
            update(io, l.gc, 0x1c, 1, 1)?;
            io.write_memory(map, WPTR, TRAP_END);
            flush(io, l);
            io.write(l.gc + u64::from(RB_WPTR) * 4, TRAP_END);
            // linux-lit: 1=mmSDMA0_GFX_RB_WPTR_HI@gc - mmSDMA0_GFX_RB_WPTR@gc
            io.write(l.gc + u64::from(RB_WPTR + 1) * 4, 0);
            Ok(())
        })?;
        let deadline = narf_time::Deadline::after_ms(100); // linux: n/a (NARF bound)
        loop {
            let done = self.access(|io| {
                invalidate(io, l);
                let lo = checked(io.read(l.gc + u64::from(RB_RPTR) * 4))?;
                // linux-lit: 1=mmSDMA0_GFX_RB_RPTR_HI@gc - mmSDMA0_GFX_RB_RPTR@gc
                checked(io.read(l.gc + u64::from(RB_RPTR + 1) * 4))?;
                Ok(lo == TRAP_END && io.read_memory(map, RPTR) == TRAP_END)
            })?;
            if done {
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay(1000).await; // linux: n/a (NARF poll interval)
        }
    }
}
#[derive(Debug)]
pub struct Sdma {
    engine: Engine<Mmio>,
}
impl Sdma {
    /// Reserve a VRAM ring and writeback page without I/O.
    /// # Safety
    /// Caller owns this physical Navi22 GPU, SDMA0/GC/HDP/PM/reset and the
    /// matching permanent VRAM pool exclusively. No live queues or clients.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        Self::with_layout(gpu.regs, authority, pool, Layout::resolve(gpu)?)
    }
    /// Reserve an SDMA0 proof ring for a known discrete RDNA2 ASIC.
    /// No device writes or implicit native startup occur during construction.
    ///
    /// # Safety
    /// Same exclusive physical GPU, SDMA0/GC/HDP/reset/PM and matching permanent
    /// VRAM pool contract as `new`. Other engines/clients must remain inactive.
    pub unsafe fn new_rdna2(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
    ) -> Result<Self, Error> {
        Self::with_layout(gpu.regs, authority, pool, Layout::resolve_rdna2(gpu)?)
    }
    fn with_layout(
        registers: MmioRegion,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        layout: Layout,
    ) -> Result<Self, Error> {
        Ok(Self {
            engine: Engine {
                layout,
                io: Mmio(registers),
                authority,
                memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
                state: State::Prepared,
                proof: None,
                trapped: false,
            },
        })
    }
    /// Start SDMA0 and prove translated VRAM write/copy/fence execution once.
    /// # Safety
    /// PSP/RLC/SDMA firmware is ready, trained VRAM and the matching GPU's GMC
    /// translations are retained, gating is disabled, and new's ownership
    /// contract still holds. No second owner/reset after cancellation/failure.
    pub async unsafe fn initialize(&mut self, gmc: &mut gmc::Gmc) -> Result<Proof, Error> {
        let aperture = gmc.aperture().ok_or(Error::Invalid)?;
        let target = gmc.test_mapping().ok_or(Error::Invalid)?;
        self.engine.initialize(aperture, target).await
    }
    pub fn state(&self) -> State {
        self.engine.state
    }
    pub fn proof(&self) -> Option<Proof> {
        self.engine.proof
    }
    /// Raise one SDMA0 TRAP interrupt after a verified start. Needs no new
    /// safety contract: it only appends to this owner's verified ring.
    pub(crate) async fn trap(&mut self, context: u32) -> Result<(), Error> {
        self.engine.trap(context).await
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_sdma_navi22_tests.rs"]
mod tests;
