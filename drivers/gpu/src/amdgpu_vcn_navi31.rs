//! RDNA3 VCN 4.0 unified-queue owner for Navi31 (VCN instance 0).
//!
//! Grounded in Linux 7.4-rc2 `vcn_v4_0.c` / `amdgpu_vcn.h` /
//! `vcn_4_0_0_offset.h` / `vcn_4_0_0_sh_mask.h` (ref tree
//! `~/workspace/scratch/linux-amd-ref`). Every register below is the v4.0.0
//! value; nothing is copied from the Navi48 VCN5 owner, whose registers
//! differ. The shape (generic `Io`, `Engine`, fence proof, DPG module)
//! follows that owner.
//!
//! Scope: instance 0 only. Navi31 has two VCN instances; instance 1 (no AV1
//! rows in `soc21.c`) has no owner yet. The caller issues SMU 13.0.0
//! PowerUpVcn (0x2A) before `start` and PowerDownVcn (0x2B) after `stop`;
//! this owner never sends SMU messages. DPG is a runtime upgrade after the
//! static proofs (`enable_dpg`), mirroring the Navi48 owner; Linux's
//! direct-DPG start is not replicated. The VCN firmware blob
//! (`amdgpu/vcn_4_0_0.bin` for Navi31/32, `amdgpu/vcn_4_0_4.bin` for
//! Navi33) is loaded by the PSP session; this owner takes its TMR address
//! via `MediaFirmware` and programs the VCPU cache windows from it.
//!
//! Unresolved: whether UVD 4.0.3 behaves differently from `vcn_v4_0`
//! beyond the ring. 4.0.3 is a separate Linux block (`vcn_v4_0_3` +
//! `jpeg_v4_0_3`, firmware `amdgpu/vcn_4_0_3.bin`, `VcnVersion::V4_0_3`
//! since #2468) — no family is known to report it, and this owner
//! correctly refuses it (`Layout::resolve` fails closed on (4,0,3)).
//! Navi31's NBIO version is blob-sourced, so the doorbell-range write
//! fails closed unless NBIF is (7,0,0)|(7,0,1).
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_psp_ring::{bank, MediaFirmware, Psp},
    amdgpu_vram::{Pool, Reservation},
};
use core::sync::atomic::{fence, Ordering};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

#[path = "amdgpu_vcn_navi31_dpg.rs"]
mod dpg;

// vcn_4_0_0_offset.h: all registers below are in VCN instance 0, bank 1.
mod regs {
    pub const PGFSM_CONFIG: u32 = 0x0000; // regUVD_PGFSM_CONFIG
    pub const PGFSM_STATUS: u32 = 0x0001; // regUVD_PGFSM_STATUS
    pub const POWER_STATUS: u32 = 0x0002; // regUVD_POWER_STATUS
    pub const DPG_PAUSE: u32 = 0x0014; // regUVD_DPG_PAUSE
    pub const ADDR_CONFIG: u32 = 0x0042; // regUVD_GFX10_ADDR_CONFIG
    pub const DB_CTRL: u32 = 0x0072; // regVCN_RB1_DB_CTRL
    pub const RB_ENABLE: u32 = 0x0085; // regVCN_RB_ENABLE
    pub const RPTR: u32 = 0x00ac; // regUVD_RB_RPTR
    pub const WPTR: u32 = 0x00ad; // regUVD_RB_WPTR
    pub const CGC_GATE: u32 = 0x00c1; // regUVD_CGC_GATE
    pub const CGC_CTRL: u32 = 0x00c2; // regUVD_CGC_CTRL
    pub const SUVD_CGC_GATE: u32 = 0x00c4; // regUVD_SUVD_CGC_GATE
    pub const SUVD_CGC_CTRL: u32 = 0x00c6; // regUVD_SUVD_CGC_CTRL
    pub const MASTINT: u32 = 0x00e1; // regUVD_MASTINT_EN
    pub const RB_LO: u32 = 0x00ea; // regUVD_RB_BASE_LO
    pub const RB_HI: u32 = 0x00eb; // regUVD_RB_BASE_HI
    pub const RB_SIZE: u32 = 0x00ec; // regUVD_RB_SIZE
    pub const ARB: u32 = 0x0106; // regUVD_RB_ARB_CTRL
    pub const STATUS: u32 = 0x0143; // regUVD_STATUS
    pub const RESET: u32 = 0x0147; // regUVD_SOFT_RESET
    pub const CACHE_OFFSET: [u32; 3] = [0x0180, 0x0182, 0x0184]; // regUVD_VCPU_CACHE_OFFSET{0,1,2}
    pub const CACHE_SIZE: [u32; 3] = [0x0181, 0x0183, 0x0185]; // regUVD_VCPU_CACHE_SIZE{0,1,2}
    pub const NC_OFFSET: u32 = 0x0192; // regUVD_VCPU_NONCACHE_OFFSET0
    pub const NC_SIZE: u32 = 0x0193; // regUVD_VCPU_NONCACHE_SIZE0
    pub const VCPU: u32 = 0x0196; // regUVD_VCPU_CNTL
    pub const MPC_CNTL: u32 = 0x01d4; // regUVD_MPC_CNTL
    pub const MUXA0: u32 = 0x01d6; // regUVD_MPC_SET_MUXA0
    pub const MUXB0: u32 = 0x01d8; // regUVD_MPC_SET_MUXB0
    pub const MUX: u32 = 0x01da; // regUVD_MPC_SET_MUX
    pub const NC_LO: u32 = 0x0240; // regUVD_LMI_VCPU_NC0_64BIT_BAR_LOW
    pub const CACHE_LO: [u32; 3] = [0x0244, 0x0270, 0x0274]; // regUVD_LMI_VCPU_CACHE{,1,2}_64BIT_BAR_LOW
    pub const LMI2: u32 = 0x02ae; // regUVD_LMI_CTRL2
    pub const LMI: u32 = 0x02b0; // regUVD_LMI_CTRL
    pub const LMI_STATUS: u32 = 0x02b1; // regUVD_LMI_STATUS
    pub const RAS_CNTL: u32 = 0x02df; // regVCN_RAS_CNTL
    pub const SYS_INT_EN: u32 = 0x00e2; // regUVD_SYS_INT_EN
}
use regs::*;

// vcn_4_0_0_sh_mask.h / amdgpu_vcn.h field values.
const VCPU_CLOCK: u32 = 1 << 9; // UVD_VCPU_CNTL__CLK_EN_MASK
const VCPU_RESET: u32 = 1 << 28; // UVD_VCPU_CNTL__BLK_RST_MASK
const VCPU_PRB_TIMEOUT: u32 = 0xff << 20; // UVD_VCPU_CNTL__PRB_TIMEOUT_VAL__SHIFT 0x14
const MASTINT_VCPU_EN: u32 = 0x2;
const STATUS_BUSY: u32 = 0x4; // UVD_STATUS__UVD_BUSY
const STATUS_IDLE: u32 = 0x2; // UVD_STATUS__IDLE
const RESET_LMI: u32 = 0x4;
const RESET_LMI_UMC: u32 = 0x2000;
const LMI_STATIC: u32 = 0x203100; // WRITE_CLEAN_TIMER_EN|MASK_MC_URGENT|DATA_COHERENCY_EN|VCPU_DATA_COHERENCY_EN
const LMI_DPG: u32 = 0x0030_7308; // LMI_STATIC|REQ_MODE|CRC_RESET|(8<<0)|0x100000
const LMI2_STALL: u32 = 0x100;
const LMI2_DPG: u32 = 0x1f << 17; // RE_OFLD_MIF_WR_REQ_NUM__SHIFT 0x11
const LMI_CLEAN: u32 = 0xf; // READ|WRITE|WRITE_RAW|VCPU_LMI_WRITE_CLEAN
const LMI_UMC_CLEAN: u32 = 0x240; // UMC_READ_CLEAN_RAW|UMC_WRITE_CLEAN_RAW
const ARB_VCPU_DIS: u32 = 0x8;
const RB1: u32 = 0x4; // VCN_RB_ENABLE__RB1_EN_MASK
const ALL_RBS: u32 = 0x3c; // RB1..RB4
const POWER_STATUS_MASK: u32 = 0x3;
const POWER_PG_MODE: u32 = 0x4;
const POWER_PG_EN: u32 = 0x100;
const DPG_PAUSE_REQ: u32 = 0x4; // NJ_PAUSE_DPG_REQ
const DPG_PAUSE_ACK: u32 = 0x8; // NJ_PAUSE_DPG_ACK
const RAS_VALUE: u32 = 0x1111; // VCPU_VCODEC_REARM|IH_EN|PMI_EN|STALL_EN
const RAS_SYS_INT_EN: u32 = 0x0400_0000; // RASCNTL_VCPU_VCODEC_EN
                                         // vcn_v4_0_disable_static_power_gating, PG-support branch: UVDM/UVDS/UVDLM=1,
                                         // UVDF/UVDTC/UVDB/UVDTA/UVDTD/UVDTE/UVDE/UVDAB/UVDTB/UVDNA/UVDNB=2 (UVDJ
                                         // untouched). Wait value is the amdgpu_vcn.h enum
                                         // UVD_PGFSM_STATUS__UVDM_UVDU_UVDLM_PWR_ON_3_0.
const PGFSM_CONFIG_PG_ON: u32 = 0x2a2a_9aa5;
const PGFSM_STATUS_PG_ON: u32 = 0x2a2a_8aa0;
const PGFSM_STATUS_MASK: u32 = 0x3f3f_ffff;
// Non-PG branch: the same fourteen fields all 1 (UVDJ untouched), instance 0
// waits for 0.
const PGFSM_CONFIG_ALL_ONE: u32 = 0x1515_5555;
// vcn_v4_0_enable_static_power_gating, PG-support branch: all fourteen
// fields 2.
const PGFSM_CONFIG_ALL_TWO: u32 = 0x2a2a_aaaa;
// vcn_v4_0_disable_clock_gating (amdgpu_vcn.h / vcn_4_0_0_sh_mask.h).
const CGC_CTRL_VALUE: u32 = 0x104; // (1<<CLK_GATE_DLY_TIMER shift 2)|(4<<CLK_OFF_DELAY shift 6)
const CGC_GATE_CLEAR: u32 = 0x17_ffff;
const CGC_CTRL_MODE_CLEAR: u32 = 0xffff_f800;
const SUVD_GATE_SET: u32 = 0x1fe_ffff;
const SUVD_CTRL_CLEAR: u32 = 0x3ff;
// amdgpu_vcn.h: AMDGPU_FW_SHARED_FLAG_0_UNIFIED_QUEUE | AMDGPU_VCN_SMU_DPM_INTERFACE_FLAG.
const FW_SHARED_PRESENT: u32 = 0x804;
// fw_queue_mode (amdgpu_vcn.h).
const FW_QUEUE_RING_RESET: u8 = 1;
const FW_QUEUE_DPG_HOLD_OFF: u8 = 2;

const STACK_BYTES: u64 = 128 << 10; // AMDGPU_VCN_STACK_SIZE
const CONTEXT_BYTES: u64 = 512 << 10; // AMDGPU_VCN_CONTEXT_SIZE
const SHARED: u64 = STACK_BYTES + CONTEXT_BYTES;
const RING: u64 = SHARED + 4096;
const FENCE: u64 = RING + 4096;
const WRITEBACK: u64 = FENCE + 4;
const BYTES: u64 = FENCE + 4096;
/// Linux `vcn_v4_0_sw_init`: 512 dwords, doorbell index
/// `(vcn_ring0_1 << 1) + 2 + 8*i` for instance 0 (non-SRIOV).
const RING_SIZE_DW: u32 = 512;
/// `soc21_init_doorbell_index`: `vcn_ring0_1 = AMDGPU_NAVI10_DOORBELL64_VCN0_1`
/// (0x188), so the instance-0 doorbell base is 0x310 and the unified ring's
/// is 0x312.
const DOORBELL_BASE: u32 = 0x310;
const DOORBELL: u32 = DOORBELL_BASE + 2;
/// nbio_v7_0 `vcn_doorbell_range`: `mmBIF_MMSCH0_DOORBELL_RANGE`, bank 2.
const NBIO_RANGE: u32 = 0x01d3;
/// nbio_v7_0 fields: OFFSET shift 2, SIZE shift 0x10; use_doorbell sets
/// OFFSET=0x310, SIZE=8.
const NBIO_RANGE_VALUE: u32 = (DOORBELL_BASE << 2) | (8 << 16);
const NBIO_RANGE_MASK: u32 = 0x1f0ffc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Readback,
    Timeout,
    BootFailed,
    Sram(crate::amdgpu_psp_ring::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Starting,
    Ready,
    Testing,
    Verified,
    Stopping,
    Stopped,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub sequence: u32,
    /// Observed dword ring pointer (the initial proofs do not wrap).
    pub read_pointer: u32,
}

/// Codec capability row from `soc21.c` (`vcn_4_0_0_video_codecs_*`),
/// instance 0. Instance 1 has no AV1 rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    Avc,
    Hevc,
    Vp9,
    Av1,
    Jpeg,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodecCap {
    pub codec: Codec,
    pub max_width: u32,
    pub max_height: u32,
    pub encode: bool,
}
/// Instance-0 decode/encode maxima (`soc21.c`).
pub const fn codec_caps() -> &'static [CodecCap] {
    &[
        CodecCap {
            codec: Codec::Avc,
            max_width: 4096,
            max_height: 4096,
            encode: false,
        },
        CodecCap {
            codec: Codec::Hevc,
            max_width: 8192,
            max_height: 4352,
            encode: false,
        },
        CodecCap {
            codec: Codec::Jpeg,
            max_width: 16384,
            max_height: 16384,
            encode: false,
        },
        CodecCap {
            codec: Codec::Vp9,
            max_width: 8192,
            max_height: 4352,
            encode: false,
        },
        CodecCap {
            codec: Codec::Av1,
            max_width: 8192,
            max_height: 4352,
            encode: false,
        },
        CodecCap {
            codec: Codec::Avc,
            max_width: 4096,
            max_height: 4096,
            encode: true,
        },
        CodecCap {
            codec: Codec::Hevc,
            max_width: 8192,
            max_height: 4352,
            encode: true,
        },
        CodecCap {
            codec: Codec::Av1,
            max_width: 8192,
            max_height: 4352,
            encode: true,
        },
    ]
}

/// Firmware blob for a discovered VCN version (`amdgpu_vcn.c`).
/// (4,0,2) is Phoenix, not this owner's scope.
pub fn firmware_name(version: (u8, u8, u8)) -> Option<&'static str> {
    match version {
        (4, 0, 0) => Some("amdgpu/vcn_4_0_0.bin"),
        (4, 0, 4) => Some("amdgpu/vcn_4_0_4.bin"),
        _ => None,
    }
}

/// Discovered VCN version for a Navi3x die, by its GC version
/// (`gfx_v11_0.c` / `soc21.c`; lane 1's corrected die<->GC pairing):
/// Navi31 GC 11.0.0 and Navi32 GC 11.0.3 are VCN 4.0.0, Navi33 GC 11.0.2 is
/// VCN 4.0.4. This resolves the Navi33 question in the Linux discovery
/// switch (`amdgpu_discovery.c`): (4,0,4) is in the `vcn_v4_0` block, not
/// Gentoo-table-only.
pub fn version_for_gc(gc: (u8, u8, u8)) -> Option<(u8, u8, u8)> {
    match gc {
        (11, 0, 0) | (11, 0, 3) => Some((4, 0, 0)),
        (11, 0, 2) => Some((4, 0, 4)),
        _ => None,
    }
}

/// VCN 4.0 versions this owner drives: (4,0,0) Navi31/32, (4,0,4) Navi33.
const VCN_VERSIONS: [(u8, u8, u8); 2] = [(4, 0, 0), (4, 0, 4)];
/// GC versions on Navi3x (`gfx_v11_0.c`; `regGB_ADDR_CONFIG` 0x13de comes
/// from the single `gc_11_0_0_offset.h` include, which covers all 11.0.x).
const GC_VERSIONS: [(u8, u8, u8); 3] = [(11, 0, 0), (11, 0, 2), (11, 0, 3)];
/// NBIF versions carrying `vcn_doorbell_range` (nbio_v7_0). Navi31's NBIO
/// version is blob-sourced; any other version fails closed here.
const NBIO_VERSIONS: [(u8, u8, u8); 2] = [(7, 0, 0), (7, 0, 1)];

#[derive(Clone, Copy, Debug)]
struct Layout {
    vcn: u64,
    nbio: u64,
    gc: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.regs.len < 0x7f004 {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            vcn: bank(gpu, ip::HW_ID_VCN, &VCN_VERSIONS, 1, LMI_STATUS)
                .map_err(|_| Error::Unsupported)?,
            nbio: bank(gpu, ip::HW_ID_NBIF, &NBIO_VERSIONS, 2, NBIO_RANGE)
                .map_err(|_| Error::Unsupported)?,
            gc: bank(gpu, ip::HW_ID_GC, &GC_VERSIONS, 0, 0x13de).map_err(|_| Error::Unsupported)?,
        })
    }
}

pub(crate) trait Io {
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, value: u32);
    fn memory_read(&mut self, map: MmioRegion, at: u64) -> u32;
    fn memory_write(&mut self, map: MmioRegion, at: u64, value: u32);
    fn memory_read8(&mut self, map: MmioRegion, at: u64) -> u8;
    fn memory_write8(&mut self, map: MmioRegion, at: u64, value: u8);
    fn doorbell(&mut self, at: u32, value: u32);
    async fn delay(&mut self, us: u64) {
        narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Mmio {
    pub(crate) regs: MmioRegion,
    pub(crate) doorbells: MmioRegion,
}
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: Layout bounds every register; Engine invokes live authority.
        unsafe { self.regs.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: the same bounded register map and live authority.
        unsafe { self.regs.write32(at, value) };
    }
    fn memory_read(&mut self, map: MmioRegion, at: u64) -> u32 {
        // SAFETY: Engine uses dwords inside its retained allocation only.
        unsafe { map.read32(at) }
    }
    fn memory_write(&mut self, map: MmioRegion, at: u64, value: u32) {
        // SAFETY: the same retained allocation and bounded dword offsets.
        unsafe { map.write32(at, value) };
    }
    fn doorbell(&mut self, at: u32, value: u32) {
        // SAFETY: constructor bounds DOORBELL; caller owns this BAR2 range.
        unsafe { self.doorbells.write32(u64::from(at) * 4, value) };
    }
    fn memory_read8(&mut self, map: MmioRegion, at: u64) -> u8 {
        // SAFETY: the queue_mode byte belongs to this retained shared page.
        unsafe { map.read8(at) }
    }
    fn memory_write8(&mut self, map: MmioRegion, at: u64, value: u8) {
        // SAFETY: byte writes preserve adjacent firmware-owned queue_status.
        unsafe { map.write8(at, value) };
    }
}

/// `amdgpu_vcn_psp_update_sram`: PSP writes one instance's DPG register
/// list (offset/value pairs) into that instance's DPG SRAM. Instance 0 only.
///
/// The `async fn` form is kept deliberately: this trait is for in-crate use
/// only (the public surface is the `Vcn` owner), and no auto-trait bound is
/// needed on its future.
#[allow(async_fn_in_trait)]
pub trait Sram {
    async fn load(&mut self, words: &[u32]) -> Result<(), Error>;
}
impl Sram for Psp {
    async fn load(&mut self, words: &[u32]) -> Result<(), Error> {
        self.load_vcn_sram(0, words).await.map_err(Error::Sram)
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
fn checked(v: u32) -> Result<u32, Error> {
    if v == u32::MAX {
        Err(Error::DeviceGone)
    } else {
        Ok(v)
    }
}
fn update<I: Io>(io: &mut I, at: u64, mask: u32, value: u32) -> Result<(), Error> {
    let old = checked(io.read(at))?;
    io.write(at, (old & !mask) | value);
    if checked(io.read(at))? & mask != value {
        return Err(Error::Readback);
    }
    Ok(())
}
fn flush<I: Io>(io: &mut I, l: Layout) -> Result<(), Error> {
    fence(Ordering::SeqCst);
    io.write(0x7f000, 0);
    // The programmed doorbell-range register is the NBIO readback: it
    // proves the range write landed before the doorbell is rung.
    checked(io.read(l.nbio + u64::from(NBIO_RANGE) * 4))?;
    fence(Ordering::SeqCst);
    Ok(())
}

/// VCN's 512-dword ring exposes masked 32-bit pointers. A normal pending
/// predecessor can be numerically greater than a newly wrapped producer.
/// Accept only progress within this exact nonempty published span.
fn proof_pointer(pointer: u32, start: u32, next: u32) -> Result<(), Error> {
    if (pointer | start | next) & !511 != 0
        || start == next
        || (pointer.wrapping_sub(start) & 511) > (next.wrapping_sub(start) & 511)
    {
        return Err(Error::Readback);
    }
    Ok(())
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    firmware_bytes: u32,
    /// Device's `AMD_PG_SUPPORT_VCN` flag: selects the power-gating branch
    /// of `vcn_v4_0_disable/enable_static_power_gating`. A bringup input,
    /// not hardcoded: DPG-capable parts take the DPG path instead and never
    /// reach the static power-gating branch.
    pg: bool,
    state: State,
    addr_config: Option<u32>,
    dpg: bool,
    proof: Option<Proof>,
    wptr: u32,
    seq: u32,
}
impl<I: Io> Engine<I> {
    fn access<T>(
        &mut self,
        f: impl FnOnce(&mut I, Layout) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let io = &mut self.io;
        let l = self.layout;
        self.authority
            .invoke(Op(|| f(io, l)))
            .map_err(|_| Error::Revoked)?
    }
    fn reg(&mut self, reg: u32) -> Result<u32, Error> {
        self.access(|io, l| checked(io.read(l.vcn + u64::from(reg) * 4)))
    }
    fn set(&mut self, reg: u32, mask: u32, value: u32) -> Result<(), Error> {
        self.access(|io, l| update(io, l.vcn + u64::from(reg) * 4, mask, value))
    }
    async fn wait(&mut self, reg: u32, mask: u32, value: u32) -> Result<(), Error> {
        for _ in 0..2000 {
            if self.reg(reg)? & mask == value {
                return Ok(());
            }
            self.io.delay(50).await;
        }
        Err(Error::Timeout)
    }
    /// `vcn_v4_0_disable_static_power_gating`.
    async fn disable_static_power_gating(&mut self) -> Result<(), Error> {
        if self.pg {
            self.set(PGFSM_CONFIG, u32::MAX, PGFSM_CONFIG_PG_ON)?;
            self.wait(PGFSM_STATUS, PGFSM_STATUS_MASK, PGFSM_STATUS_PG_ON)
                .await?;
            // UVDM_UVDU_PWR_ON (0x2) | PG_EN (0x100), clearing 0x103.
            self.set(POWER_STATUS, 0x103, 0x102)?;
        } else {
            self.set(PGFSM_CONFIG, u32::MAX, PGFSM_CONFIG_ALL_ONE)?;
            self.wait(PGFSM_STATUS, PGFSM_STATUS_MASK, 0).await?;
            self.set(POWER_STATUS, 0x103, 0)?;
        }
        Ok(())
    }
    /// `vcn_v4_0_enable_static_power_gating` (PG-support branch only;
    /// the non-PG branch is a no-op in Linux).
    async fn enable_static_power_gating(&mut self) -> Result<(), Error> {
        if !self.pg {
            return Ok(());
        }
        // Before power off, the TILES_OFF indicator has to be turned on.
        self.set(POWER_STATUS, 0x1, 0x1)?;
        self.set(PGFSM_CONFIG, u32::MAX, PGFSM_CONFIG_ALL_TWO)?;
        self.wait(PGFSM_STATUS, PGFSM_STATUS_MASK, PGFSM_CONFIG_ALL_TWO)
            .await
    }
    /// `vcn_v4_0_disable_clock_gating` (non-MGCG branch; MGCG returns
    /// early in Linux, which this owner does not model — the caller
    /// reports MGCG parts as unsupported until that branch is grounded).
    async fn disable_clock_gating(&mut self) -> Result<(), Error> {
        // CGC_CTRL: clear DYN_CLOCK_MODE, set DLY_TIMER=1, OFF_DELAY=4.
        self.set(CGC_CTRL, 0x1, CGC_CTRL_VALUE)?;
        self.set(CGC_GATE, CGC_GATE_CLEAR, 0)?;
        self.wait(CGC_GATE, u32::MAX, 0).await?;
        self.set(CGC_CTRL, CGC_CTRL_MODE_CLEAR, 0)?;
        self.set(SUVD_CGC_GATE, SUVD_GATE_SET, SUVD_GATE_SET)?;
        self.set(SUVD_CGC_CTRL, SUVD_CTRL_CLEAR, 0)?;
        Ok(())
    }
    /// `vcn_v4_0_enable_clock_gating` (non-MGCG branch).
    fn enable_clock_gating(&mut self) -> Result<(), Error> {
        self.set(CGC_CTRL, CGC_CTRL_VALUE, CGC_CTRL_VALUE)?;
        self.set(CGC_CTRL, CGC_CTRL_MODE_CLEAR, CGC_CTRL_MODE_CLEAR)?;
        self.set(SUVD_CGC_CTRL, SUVD_CTRL_CLEAR, SUVD_CTRL_CLEAR)?;
        Ok(())
    }
    /// `vcn_v4_0_mc_resume`: cache window 0 is the PSP-loaded firmware
    /// image (`image`, page-aligned `firmware_bytes + 8`), window 1 the
    /// stack, window 2 the context, non-cache the fw_shared page.
    fn mc_resume(&mut self, image: u64) -> Result<(), Error> {
        let bytes = self.firmware_bytes.checked_add(8).ok_or(Error::Invalid)?;
        let fw_size = bytes.checked_add(4095).ok_or(Error::Invalid)? & !4095;
        let base = self.memory.address();
        for (i, (addr, size)) in [
            (image, fw_size),
            (base, STACK_BYTES as u32),
            (base + STACK_BYTES, CONTEXT_BYTES as u32),
        ]
        .into_iter()
        .enumerate()
        {
            self.set(CACHE_LO[i], u32::MAX, addr as u32)?;
            self.set(CACHE_LO[i] + 1, u32::MAX, (addr >> 32) as u32)?;
            self.set(CACHE_OFFSET[i], u32::MAX, 0)?;
            self.set(CACHE_SIZE[i], u32::MAX, size)?;
        }
        self.set(NC_LO, u32::MAX, (base + SHARED) as u32)?;
        self.set(NC_LO + 1, u32::MAX, ((base + SHARED) >> 32) as u32)?;
        self.set(NC_OFFSET, u32::MAX, 0)?;
        self.set(NC_SIZE, u32::MAX, 4096)?;
        Ok(())
    }
    async fn start(&mut self, image: u64) -> Result<(), Error> {
        if !matches!(self.state, State::Prepared | State::Stopped) {
            return Err(Error::Busy);
        }
        let fw_size = (u64::from(self.firmware_bytes) + 8 + 4095) & !4095;
        if image == 0
            || image & 0xfff != 0
            || image.checked_add(fw_size).is_none_or(|end| end > 1 << 48)
        {
            return Err(Error::Invalid);
        }
        if self.reg(RB_ENABLE)? & ALL_RBS != 0 || self.reg(VCPU)? & VCPU_RESET == 0 {
            return Err(Error::Busy);
        }
        // The NBIO doorbell range must be unprogrammed before start; the
        // VCN owner programs it, and the JPEG owner verifies it.
        if self.access(|io, l| checked(io.read(l.nbio + u64::from(NBIO_RANGE) * 4)))?
            & NBIO_RANGE_MASK
            != 0
        {
            return Err(Error::Busy);
        }
        self.state = State::Starting;
        self.proof = None;
        self.memory.publish();
        let result = self
            .start_inner(image)
            .await
            .and_then(|()| self.access(|_, _| Ok(())));
        self.state = match result {
            Ok(()) => State::Ready,
            Err(e) => State::Failed(e),
        };
        result
    }
    async fn start_inner(&mut self, image: u64) -> Result<(), Error> {
        self.dpg = false;
        self.restore(image).await
    }
    /// `vcn_v4_0_start` (static path; DPG-capable parts use `enable_dpg`
    /// after this instead of Linux's direct-DPG start).
    async fn restore(&mut self, image: u64) -> Result<(), Error> {
        let map = self.memory.mapping();
        // Yield between pages; cancellation conservatively retains the whole
        // allocation before even the first VCPU address is published.
        for page in (0..BYTES).step_by(4096) {
            self.access(|io, l| {
                for at in (page..page + 4096).step_by(4) {
                    io.memory_write(map, at, 0);
                }
                flush(io, l)
            })?;
            self.io.delay(1).await;
        }
        self.access(|io, l| {
            io.memory_write(map, SHARED, FW_SHARED_PRESENT); // unified queue + dGPU SMU interface
            io.memory_write(map, SHARED + 16, 1); // sq.is_enabled, queue_mode=0
            flush(io, l)
        })?;
        self.disable_static_power_gating().await?;
        self.set(STATUS, STATUS_BUSY, STATUS_BUSY)?;
        self.disable_clock_gating().await?;
        self.set(VCPU, VCPU_CLOCK, VCPU_CLOCK)?;
        self.set(MASTINT, MASTINT_VCPU_EN, 0)?;
        self.set(LMI2, LMI2_STALL, 0)?;
        self.set(RESET, RESET_LMI | RESET_LMI_UMC, 0)?;
        self.set(LMI, LMI_STATIC, LMI_STATIC)?;
        self.set(MPC_CNTL, 0x38, 0x10)?; // REPLACEMENT_MODE 2
        self.set(MUXA0, u32::MAX, 0x40c_2040)?; // 1<<6|2<<12|3<<18|4<<24
        self.set(MUXB0, u32::MAX, 0x40c_2040)?;
        self.set(MUX, u32::MAX, 0x88)?; // 0<<0|1<<3|2<<6
        self.mc_resume(image)?;
        let addr_config = {
            // gc_11_0_0_offset.h: regGB_ADDR_CONFIG, BASE_IDX 0.
            let value = self.access(|io, l| checked(io.read(l.gc + 0x13de * 4)))?;
            self.addr_config = Some(value);
            value
        };
        self.set(ADDR_CONFIG, u32::MAX, addr_config)?;
        self.set(ARB, ARB_VCPU_DIS, 0)?;
        self.set(VCPU, VCPU_RESET, 0)?;
        let mut booted = false;
        for _ in 0..10 {
            for _ in 0..100 {
                if self.reg(STATUS)? & STATUS_IDLE != 0 {
                    booted = true;
                    break;
                }
                self.io.delay(10_000).await;
            }
            if booted {
                break;
            }
            self.set(VCPU, VCPU_RESET, VCPU_RESET)?;
            self.io.delay(10_000).await;
            self.set(VCPU, VCPU_RESET, 0)?;
            self.io.delay(10_000).await;
        }
        if !booted {
            return Err(Error::BootFailed);
        }
        // Master IRQ stays masked until an independent owner is registered.
        self.set(MASTINT, MASTINT_VCPU_EN, MASTINT_VCPU_EN)?;
        // Clear the busy bit of VCN_STATUS (VCPU_REPORT field, bit 2).
        self.set(STATUS, STATUS_BUSY, 0)?;
        self.set(DB_CTRL, 0x4fff_fffc, DOORBELL << 2 | 1 << 30)?;
        self.set(RB_LO, u32::MAX, (self.memory.address() + RING) as u32)?;
        self.set(
            RB_HI,
            u32::MAX,
            ((self.memory.address() + RING) >> 32) as u32,
        )?;
        self.set(RB_SIZE, u32::MAX, RING_SIZE_DW)?;
        self.set(RB_ENABLE, RB1, 0)?;
        self.shared_mode(FW_QUEUE_RING_RESET, FW_QUEUE_RING_RESET)?;
        self.set(RPTR, u32::MAX, 0)?;
        self.set(WPTR, u32::MAX, 0)?;
        if self.reg(RPTR)? != 0 {
            return Err(Error::Readback);
        }
        self.wptr = 0;
        self.set(RB_ENABLE, RB1, RB1)?;
        self.shared_mode(FW_QUEUE_RING_RESET | FW_QUEUE_DPG_HOLD_OFF, 0)?;
        self.access(|io, l| {
            update(
                io,
                l.nbio + u64::from(NBIO_RANGE) * 4,
                NBIO_RANGE_MASK,
                NBIO_RANGE_VALUE,
            )?;
            checked(io.read(l.vcn + u64::from(STATUS) * 4))?;
            Ok(())
        })
    }
    fn shared_mode(&mut self, mask: u8, value: u8) -> Result<(), Error> {
        let map = self.memory.mapping();
        self.access(|io, l| {
            let old = io.memory_read8(map, SHARED + 17);
            io.memory_write8(map, SHARED + 17, (old & !mask) | value);
            flush(io, l)
        })
    }
    fn emit(&mut self, words: &[u32]) -> Result<u32, Error> {
        // Starting is the DPG upgrade: the probe emits while the engine is
        // being restored, before it is Ready again.
        if !matches!(
            self.state,
            State::Ready | State::Testing | State::Verified | State::Starting
        ) {
            return Err(Error::Busy);
        }
        if words.is_empty() || words.len() > 448 {
            return Err(Error::Invalid);
        }
        let padded = (words.len() as u32 + 63) & !63;
        // VCN has no support_64bit_ptrs: amdgpu_ring's ptr_mask is its
        // buf_mask. Leave space so equal masked pointers mean empty.
        let pending = self.wptr.wrapping_sub(self.reg(RPTR)?) & 511;
        if pending + padded >= 512 {
            return Err(Error::Busy);
        }
        let next = self.wptr.wrapping_add(padded) & 511;
        let map = self.memory.mapping();
        let wptr = self.wptr;
        self.access(|io, l| {
            for n in 0..padded {
                let at = RING + u64::from(wptr.wrapping_add(n) & 511) * 4;
                io.memory_write(map, at, words.get(n as usize).copied().unwrap_or(0));
            }
            io.memory_write(map, WRITEBACK, next);
            flush(io, l)?;
            io.doorbell(DOORBELL, next);
            // Publication is the last operation. Client callers must receive
            // the sequence even if the device fails immediately afterwards,
            // so they retain job resources until retirement/error recovery.
            Ok(())
        })?;
        self.wptr = next;
        Ok(next)
    }
    async fn prove(&mut self) -> Result<Proof, Error> {
        if self.state != State::Ready {
            return Err(Error::Busy);
        }
        self.state = State::Testing;
        let result = self
            .prove_inner()
            .await
            .and_then(|proof| self.access(|_, _| Ok(proof)));
        self.state = match result {
            Ok(_) => State::Verified,
            Err(e) => State::Failed(e),
        };
        if let Ok(proof) = result {
            self.proof = Some(proof);
        }
        result
    }
    async fn prove_inner(&mut self) -> Result<Proof, Error> {
        let map = self.memory.mapping();
        // Start clears the fence word; proof zero could match unwritten data.
        self.seq = self.seq.wrapping_add(1).max(1);
        let seq = self.seq;
        let at = self.memory.address() + FENCE;
        let start = self.wptr;
        let next = self.emit(&[3, at as u32, (at >> 32) as u32, seq, 4, 1])?;
        for _ in 0..2000 {
            let rptr = self.reg(RPTR)?;
            proof_pointer(rptr, start, next)?;
            let complete = self.access(|io, l| {
                flush(io, l)?;
                Ok(io.memory_read(map, FENCE) == seq)
            })?;
            if rptr == next && complete {
                self.fence_guards(next)?;
                return Ok(Proof {
                    sequence: seq,
                    read_pointer: rptr,
                });
            }
            self.io.delay(50).await;
        }
        Err(Error::Timeout)
    }
    /// The fence is exactly one dword. A wider/stray firmware write must
    /// neither overwrite the CPU write-pointer word nor its page's guards.
    fn fence_guards(&mut self, next: u32) -> Result<(), Error> {
        let map = self.memory.mapping();
        self.access(|io, l| {
            flush(io, l)?;
            if io.memory_read(map, WRITEBACK) != next
                || (FENCE + 8..FENCE + 4096)
                    .step_by(4)
                    .any(|at| io.memory_read(map, at) != 0)
            {
                return Err(Error::Readback);
            }
            Ok(())
        })
    }

    async fn stop(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::Ready | State::Verified) {
            return Err(Error::Busy);
        }
        self.state = State::Stopping;
        let result = self
            .stop_inner()
            .await
            .and_then(|()| self.access(|_, _| Ok(())));
        self.state = match result {
            Ok(()) => State::Stopped,
            Err(e) => State::Failed(e),
        };
        if result.is_ok() {
            // SAFETY: VCPU reset/clock and LMI resets follow drained ring,
            // VCPU/UMC write-clean checks; every address user is retired.
            unsafe {
                self.memory.stopped();
            }
        }
        result
    }
    /// `vcn_v4_0_stop` (static path) or `vcn_v4_0_stop_dpg_mode` (DPG path).
    async fn stop_inner(&mut self) -> Result<(), Error> {
        // fw_shared->sq.queue_mode |= FW_QUEUE_DPG_HOLD_OFF (before either
        // branch, as in Linux).
        self.shared_mode(FW_QUEUE_DPG_HOLD_OFF, FW_QUEUE_DPG_HOLD_OFF)?;
        if self.dpg {
            return self.stop_dpg().await;
        }
        // Wait for VCN idle.
        self.wait(STATUS, 0x7, STATUS_IDLE).await?;
        self.wait(LMI_STATUS, LMI_CLEAN, LMI_CLEAN).await?;
        // Disable LMI UMC channel.
        self.set(LMI2, LMI2_STALL, LMI2_STALL)?;
        self.wait(LMI_STATUS, LMI_UMC_CLEAN, LMI_UMC_CLEAN).await?;
        // Block VCPU register access.
        self.set(ARB, ARB_VCPU_DIS, ARB_VCPU_DIS)?;
        // Reset VCPU.
        self.set(VCPU, VCPU_RESET, VCPU_RESET)?;
        // Disable VCPU clock.
        self.set(VCPU, VCPU_CLOCK, 0)?;
        // Apply soft reset: UMC first, then LMI.
        self.set(RESET, RESET_LMI_UMC, RESET_LMI_UMC)?;
        self.set(RESET, RESET_LMI, RESET_LMI)?;
        // Clear status.
        self.set(STATUS, u32::MAX, 0)?;
        // Apply HW clock gating, then enable VCN power gating.
        self.enable_clock_gating()?;
        self.enable_static_power_gating().await?;
        self.reg(STATUS)?;
        Ok(())
    }
}

/// Native VCN 4.0 instance 0, with an owned static-power VCPU and unified ring.
#[derive(Debug)]
pub struct Vcn {
    engine: Engine<Mmio>,
}
impl Vcn {
    /// # Safety
    /// Own this physical Navi31/32/33's VCN instance 0, NBIF media range
    /// and BAR2 doorbells exclusively. The permanent pool matches its boot
    /// inventory; retain PSP's VCN TMR, trained VRAM and ready MMHUB VMID0
    /// throughout. Exclude reset/PM and competing VCPU/ring/clock writers.
    /// This is a cold owner, never an attach to firmware's running media
    /// engine. `pg` is the device's `AMD_PG_SUPPORT_VCN` flag.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        doorbells: MmioRegion,
        firmware_bytes: usize,
        pg: bool,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        if firmware_bytes == 0
            || firmware_bytes > 4 << 20
            || doorbells.len < (u64::from(DOORBELL) + 1) * 4
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            engine: Engine {
                io: Mmio {
                    regs: gpu.regs,
                    doorbells,
                },
                authority,
                layout,
                memory: pool.reserve(BYTES).map_err(|_| Error::Allocation)?,
                firmware_bytes: firmware_bytes as u32,
                pg,
                state: State::Prepared,
                addr_config: None,
                dpg: false,
                proof: None,
                wptr: 0,
                seq: 0,
            },
        })
    }
    /// # Safety
    /// `new`'s exclusions hold; SMU 13.0.0 PowerUpVcn(instance 0) has
    /// completed, and `firmware.vcn` is the retained PSP session's VCN
    /// firmware TMR address. Keep this owner after error/cancellation
    /// until reset.
    pub async unsafe fn start(&mut self, firmware: MediaFirmware) -> Result<(), Error> {
        self.engine.start(firmware.vcn.ok_or(Error::Invalid)?).await
    }
    /// Prove native unified-ring fence execution and complete RPTR drain.
    /// This proves transport, not codec execution or CPU MSI delivery.
    /// # Safety
    /// Keep `start`'s exclusions and every memory/firmware owner alive.
    pub async unsafe fn prove(&mut self) -> Result<Proof, Error> {
        self.engine.prove().await
    }
    /// Stop the VCPU and retire the ring. The caller issues SMU 13.0.0
    /// PowerDownVcn after this returns.
    /// # Safety
    /// Keep `start`'s exclusions; every client job is retired.
    pub async unsafe fn stop(&mut self) -> Result<(), Error> {
        self.engine.stop().await
    }
    /// Upgrade a started, drained engine to DPG restore. `ras` selects the
    /// VCN RAS words in the SRAM program (device RAS support).
    /// # Safety
    /// Matching PSP/TMR, registered IH/GMC and exclusive drained client
    /// owner.
    pub async unsafe fn enable_dpg(
        &mut self,
        sram: &mut impl Sram,
        ras: bool,
    ) -> Result<(), Error> {
        self.engine.enable_dpg(sram, ras).await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_vcn_navi31_tests.rs"]
mod tests;
