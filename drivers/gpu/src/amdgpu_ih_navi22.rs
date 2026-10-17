//! Navi22 OSSSYS 5.0.3 interrupt handler ring, host delivery and SOC15 IV
//! dispatch. Linux navi10_ih.c, amdgpu_ih.c, amdgpu_irq.c and nbio_v2_3.c
//! (ih_control/ih_doorbell_range); osssys_5_0_0_{offset,sh_mask}.h. Linux
//! sizes only RB0 for navy_flounder (navi10_ih_sw_init sets ih1/ih2 ring_size
//! to zero), so RB1/RB2 stay disabled. No KFD forwarding, retry CAM or soft ring.
//!
//! Deliberate differences from Linux, each forced by the current NARF state:
//! - The 256 KiB ring and its wptr writeback live in owned VRAM, addressed with
//!   MC_SPACE=4 through the VMID0 system aperture amdgpu_gmc_navi22 programs.
//!   Linux uses GTT, but NARF VMID0 has no system-memory PTEs yet. CPU reads go
//!   through BAR0 after an HDP read-cache invalidation.
//! - The rptr is written through IH_RB_RPTR with the IH doorbell disabled (the
//!   use_doorbell=false branch of navi10_ih_doorbell_rptr/ih_doorbell_range):
//!   this owner has no BAR2 mapping. Linux's doorbell index would be
//!   AMDGPU_NAVI10_DOORBELL_IH << 1 = 0x2f0.
//! - Delivery is MSI-X entry 0, then MSI, then observable polling. Probe has
//!   set INTX_DISABLE, so there is no legacy INTx route.
//!
//! The IRQ handler only records the event; IVs are decoded and dispatched by
//! task-context drains driven by subscribers (interrupt wake or watchdog).
use crate::{
    amdgpu::AmdGpu,
    amdgpu_discovery as ip,
    amdgpu_psp_ring::bank,
    amdgpu_vram::{Pool, Reservation},
};
use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{fence, AtomicBool, AtomicU16, AtomicU64, AtomicU8, Ordering},
    task::{Context, Poll, Waker},
};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};
use narf_lib::{mutex::Mutex, sync::IrqSafeSpinLock};

const RING: u64 = 256 * 1024; // IH_RING_SIZE
const BYTES: u64 = RING + 4096; // ring, then a writeback page
const WPTR_WB: u64 = RING;
const MASK: u32 = (RING - 1) as u32;
const RB_SIZE: u32 = 16; // order_base_2(ring_size / 4)
const BATCH: usize = 32; // AMDGPU_IH_MAX_NUM_IVS
const ROUNDS: usize = 8;
const QUEUE: usize = 64;
const SLOTS: usize = 64;
const CLIENTS: u8 = 0x20; // SOC15_IH_CLIENTID_MAX
const NO_VECTOR: u16 = 0x100;

// OSSSYS 5.0.0 offsets, BASE_IDX 0. WPTR_ADDR_HI/LO are reversed vs OSSSYS 4.0.
const RB_CNTL: u32 = 0x80;
const RB_BASE: u32 = 0x81;
const RB_BASE_HI: u32 = 0x82;
const RB_RPTR: u32 = 0x83;
const RB_WPTR: u32 = 0x84;
const WPTR_ADDR_HI: u32 = 0x85;
const WPTR_ADDR_LO: u32 = 0x86;
const DOORBELL_RPTR: u32 = 0x87;
const RB_CNTL_RING1: u32 = 0x8c;
const RB_CNTL_RING2: u32 = 0x98;
const IH_CNTL2: u32 = 0xc1;
// NBIO 2.3 offsets, BASE_IDX 2.
const INTERRUPT_CNTL: u32 = 0xf1;
const INTERRUPT_CNTL2: u32 = 0xf2;
const REMAP_HDP_FLUSH: u32 = 0x12d;
const IH_DOORBELL_RANGE: u32 = 0x1d2;
const HDP_READ_CACHE_INVALIDATE: u32 = 0xd1;

// IH_RB_CNTL fields.
const ENABLE: u32 = 1;
const GPU_TS: u32 = 1 << 7;
const WRITEBACK: u32 = 1 << 8;
const OVERFLOW_ENABLE: u32 = 1 << 16;
const ENABLE_INTR: u32 = 1 << 17;
const MC_SNOOP: u32 = 1 << 20;
const RPTR_REARM: u32 = 1 << 21;
const MC_RO: u32 = 1 << 22;
const MC_VMID: u32 = 0xf << 24;
const MC_SPACE: u32 = 7 << 28;
const OVERFLOW_CLEAR: u32 = 1 << 31;
const SIZE_MASK: u32 = 0x3e;
const THRESHOLD: u32 = 0xf000; // RB_USED_INT_THRESHOLD, rings 1 and 2
const RB_OVERFLOW: u32 = 1; // IH_RB_WPTR
                            // IH_CNTL2 SELF_IV_FORCE_WPTR_UPDATE_{TIMEOUT,ENABLE}.
const FORCE_TIMEOUT: u32 = 0x1f;
const FORCE_ENABLE: u32 = 1 << 8;
// INTERRUPT_CNTL IH_DUMMY_RD_OVERRIDE / IH_REQ_NONSNOOP_EN, range SIZE.
const DUMMY_RD_OVERRIDE: u32 = 1;
const REQ_NONSNOOP: u32 = 1 << 3;
const DOORBELL_SIZE: u32 = 0x1f << 16;

/// SOC15 client and source ids. Clients: soc15_ih_clientid.h; sources from
/// the matching ivsrcid headers and the Linux IP handlers that register them.
pub mod source {
    use super::Source;
    pub mod client {
        pub const IH: u8 = 0x00;
        pub const DCE: u8 = 0x04;
        /// SOC15_IH_CLIENTID_VCN1 (UVD1) and SOC15_IH_CLIENTID_VCN (UVD).
        pub const VCN1: u8 = 0x0e;
        pub const VCN: u8 = 0x10;
        pub const SDMA0: u8 = 0x08;
        pub const SDMA1: u8 = 0x09;
        pub const THM: u8 = 0x0f;
        pub const VMC: u8 = 0x12;
        pub const GRBM_CP: u8 = 0x14;
        pub const ROM_SMUIO: u8 = 0x16;
        pub const UTCL2: u8 = 0x1b;
        pub const MP1: u8 = 0x1f;
    }
    const fn s(client: u8, src: u8) -> Source {
        Source { client, src }
    }
    /// gfx_v10_0_sw_init: GFX_10_1__SRCID__CP_* on GRBM_CP. ring_id is the
    /// ME/pipe/queue, see [`super::Iv::cp_queue`].
    pub const GFX_EOP: Source = s(client::GRBM_CP, 181);
    pub const GFX_BAD_OPCODE: Source = s(client::GRBM_CP, 183);
    pub const GFX_PRIV_REG: Source = s(client::GRBM_CP, 184);
    pub const GFX_PRIV_INSTR: Source = s(client::GRBM_CP, 185);
    /// sdma_v5_2_sw_init: SDMA{0,1}_5_0__SRCID__SDMA_TRAP; src_data[0] carries
    /// the TRAP packet INT_CONTEXT and ring_id 0 is the gfx queue.
    pub const SDMA0_TRAP: Source = s(client::SDMA0, 224);
    pub const SDMA1_TRAP: Source = s(client::SDMA1, 224);
    /// vcn_v3_0_sw_init: VCN_2_0__SRCID__UVD_SYSTEM_MESSAGE_INTERRUPT (decode)
    /// and UVD_ENC_GENERAL_PURPOSE + j (encode ring j) per instance client;
    /// jpeg_v3_0_sw_init: VCN_2_0__SRCID__JPEG_DECODE on the VCN client.
    pub const VCN0_DEC: Source = s(client::VCN, 124);
    pub const VCN0_ENC: [Source; 2] = [s(client::VCN, 119), s(client::VCN, 120)];
    pub const VCN1_DEC: Source = s(client::VCN1, 124);
    pub const VCN1_ENC: [Source; 2] = [s(client::VCN1, 119), s(client::VCN1, 120)];
    pub const JPEG_DEC: Source = s(client::VCN, 153);
    /// gmc_v10_0_sw_init: VMC (MMHUB) and UTCL2 (GFXHUB) faults.
    pub const VMC_FAULT: Source = s(client::VMC, 0);
    pub const UTCL2_FAULT: Source = s(client::UTCL2, 0);
    /// DCN_1_0__SRCID__DC_HPD1_INT is shared by every HPD and HPD-RX line;
    /// src_data[0] is the context id, see [`super::Iv::hpd`].
    pub const DCN_HPD: Source = s(client::DCE, 9);
    pub const DCN_DMUB_OUTBOX: Source = s(client::DCE, 0x68);
    /// smu_v11_0_register_irq_handler: thermal L2H/H2L, CTF GPIO19, SMU.
    pub const THERMAL_HIGH: Source = s(client::THM, 0);
    pub const THERMAL_LOW: Source = s(client::THM, 1);
    pub const THERMAL_CTF: Source = s(client::ROM_SMUIO, 83);
    pub const SMU_TO_DRIVER: Source = s(client::MP1, 0xfe);
    /// Vblank as amdgpu_dm uses it on DCN: OTG VSTARTUP (DC_D1_OTG_VSTARTUP + n).
    pub const fn vblank(otg: u8) -> Option<Source> {
        if otg < 6 {
            Some(s(client::DCE, 0x3c + otg))
        } else {
            None
        }
    }
    /// OTGn_IHC_V_UPDATE_NO_LOCK_INTERRUPT, n starting at OTG0 (0x57).
    pub const fn vupdate(otg: u8) -> Option<Source> {
        if otg < 6 {
            Some(s(client::DCE, 0x57 + otg))
        } else {
            None
        }
    }
    /// HUBPn_FLIP_INTERRUPT (0x4f + n).
    pub const fn pflip(hubp: u8) -> Option<Source> {
        if hubp < 6 {
            Some(s(client::DCE, 0x4f + hubp))
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Busy,
    Allocation,
    Revoked,
    DeviceGone,
    Timeout,
    /// The engine asked to raise the event did not submit it.
    Source,
    Closed(Closed),
}
/// Terminal outcome delivered to every waiter instead of a hang.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Closed {
    /// This subscription was revoked or replaced by a newer generation.
    Revoked,
    Disabled,
    DeviceLost,
    AuthorityRevoked,
    /// Ring programming failed; no interrupts will be delivered.
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Programming,
    Enabled,
    Disabled,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Pending,
    MsiX { vector: u8 },
    Msi { vector: u8 },
    Polling,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Source {
    pub client: u8,
    pub src: u8,
}
/// Decoded 32-byte SOC15 IV (amdgpu_ih_decode_iv_helper).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Iv {
    pub client: u8,
    pub src: u8,
    pub ring_id: u8,
    pub vmid: u8,
    pub vmid_src: bool,
    pub timestamp: u64,
    pub timestamp_src: bool,
    pub pasid: u16,
    pub node_id: u8,
    pub src_data: [u32; 4],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpQueue {
    pub me: u8,
    pub pipe: u8,
    pub queue: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageFault {
    /// true for MMHUB (VMC client), false for GFXHUB (UTCL2).
    pub mmhub: bool,
    pub address: u64,
    pub retry: bool,
    pub write: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hpd {
    pub instance: u8,
    pub rx: bool,
}
impl Iv {
    pub const fn decode(dw: [u32; 8]) -> Self {
        Self {
            client: dw[0] as u8,
            src: (dw[0] >> 8) as u8,
            ring_id: (dw[0] >> 16) as u8,
            vmid: ((dw[0] >> 24) & 0xf) as u8,
            vmid_src: dw[0] >> 31 != 0,
            timestamp: dw[1] as u64 | (((dw[2] & 0xffff) as u64) << 32),
            timestamp_src: dw[2] >> 31 != 0,
            pasid: dw[3] as u16,
            node_id: (dw[3] >> 16) as u8,
            src_data: [dw[4], dw[5], dw[6], dw[7]],
        }
    }
    pub const fn source(&self) -> Source {
        Source {
            client: self.client,
            src: self.src,
        }
    }
    /// gfx_v10_0_eop_irq ring_id layout.
    pub const fn cp_queue(&self) -> CpQueue {
        CpQueue {
            me: (self.ring_id & 0x0c) >> 2,
            pipe: self.ring_id & 3,
            queue: (self.ring_id & 0x70) >> 4,
        }
    }
    /// gmc_v10_0_process_interrupt address/flag decode.
    pub const fn page_fault(&self) -> Option<PageFault> {
        if self.src != 0
            || (self.client != source::client::VMC && self.client != source::client::UTCL2)
        {
            return None;
        }
        Some(PageFault {
            mmhub: self.client == source::client::VMC,
            address: ((self.src_data[0] as u64) << 12) | (((self.src_data[1] & 0xf) as u64) << 44),
            retry: self.src_data[1] & 0x80 != 0,
            write: self.src_data[1] & 0x20 != 0,
        })
    }
    /// irq_service_dcn30 HPD context ids: 0..5 HPDn, 6..11 HPDn_RX.
    pub const fn hpd(&self) -> Option<Hpd> {
        if self.client != source::client::DCE || self.src != 9 || self.src_data[0] > 11 {
            return None;
        }
        let context = self.src_data[0] as u8;
        Some(Hpd {
            instance: context % 6,
            rx: context >= 6,
        })
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub interrupts: u64,
    pub drained: u64,
    pub unhandled: u64,
    pub malformed: u64,
    pub overflows: u64,
    /// IVs a full subscriber mailbox discarded (oldest first).
    pub dropped: u64,
    /// Drains that found IVs with no interrupt recorded since the last drain.
    pub unsignalled: u64,
    pub watchdog: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub iv: Iv,
    /// The host vector fired between submission and observation.
    pub interrupt: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub delivery: Delivery,
    /// The previous owner left RB0 enabled; it was disabled before reprogramming.
    pub inherited: bool,
    pub proof: Option<Result<Proof, Error>>,
    pub stats: Stats,
}

#[derive(Clone, Copy, Debug)]
struct Layout {
    oss: u64,
    nbio: u64,
    hdp: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if gpu.chip.vid != crate::amdgpu::AMD_VENDOR
            || gpu.chip.did != crate::amdgpu::NAVI22
            || gpu.regs.len < 0x7f004
        {
            return Err(Error::Unsupported);
        }
        let resolve = |id, versions: &[(u8, u8, u8)], index, last| {
            bank(gpu, id, versions, index, last).map_err(|_| Error::Unsupported)
        };
        Ok(Self {
            oss: resolve(ip::HW_ID_OSSSYS, &[(5, 0, 3)], 0, IH_CNTL2)?,
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
                2,
                IH_DOORBELL_RANGE,
            )?,
            hdp: resolve(
                ip::HW_ID_HDP,
                &[(5, 0, 0), (5, 0, 1), (5, 0, 2), (5, 0, 3), (5, 0, 4)],
                0,
                HDP_READ_CACHE_INVALIDATE,
            )?,
        })
    }
}
trait Io: Send {
    fn read(&mut self, address: u64) -> u32;
    fn write(&mut self, address: u64, value: u32);
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32;
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32);
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, address: u64) -> u32 {
        // SAFETY: Layout bounds OSSSYS/NBIO/HDP and the HDP remap. The
        // exclusive owner invokes every I/O batch under live PCI authority.
        unsafe { self.0.read32(address) }
    }
    fn write(&mut self, address: u64, value: u32) {
        // SAFETY: same validated register mapping and live authority.
        unsafe { self.0.write32(address, value) };
    }
    fn read_memory(&mut self, map: MmioRegion, offset: u64) -> u32 {
        // SAFETY: offsets are bounded by the retained BYTES ring allocation.
        unsafe { map.read32(offset) }
    }
    fn write_memory(&mut self, map: MmioRegion, offset: u64, value: u32) {
        // SAFETY: same retained allocation and bounded dword offsets.
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
async fn delay(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}
#[derive(Clone, Copy, Debug, Default)]
struct Batch {
    count: usize,
    more: bool,
    overflow: bool,
    malformed: u64,
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    memory: Reservation,
    /// Bus address for NBIO's dummy read (Linux adev->dummy_page_addr).
    dummy: u64,
    state: State,
    rptr: u32,
    inherited: bool,
}
impl<I: Io> Engine<I> {
    fn access<T>(
        &mut self,
        f: impl FnOnce(&mut I, Layout) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let (io, layout) = (&mut self.io, self.layout);
        self.authority
            .invoke(Op(|| f(io, layout)))
            .map_err(|_| Error::Revoked)?
    }
    fn reg(l: Layout, reg: u32) -> u64 {
        l.oss + u64::from(reg) * 4
    }
    fn nbio(l: Layout, reg: u32) -> u64 {
        l.nbio + u64::from(reg) * 4
    }
    fn update(io: &mut I, address: u64, mask: u32, value: u32) -> Result<u32, Error> {
        let next = (checked(io.read(address))? & !mask) | value;
        io.write(address, next);
        Ok(next)
    }
    /// Read-only checks; must succeed before any host routing or writes.
    fn preflight(&mut self) -> Result<(), Error> {
        if self.state != State::Prepared {
            return Err(Error::Busy);
        }
        let address = self.memory.address();
        if address % 256 != 0 || address.checked_add(BYTES).is_none_or(|end| end > 1 << 48) {
            return Err(Error::Invalid);
        }
        let inherited = self.access(|io, l| {
            if checked(io.read(Self::nbio(l, REMAP_HDP_FLUSH)))? != 0x7f000 {
                return Err(Error::Invalid);
            }
            Ok(checked(io.read(Self::reg(l, RB_CNTL)))? & ENABLE != 0)
        })?;
        self.inherited = inherited;
        Ok(())
    }
    /// navi10_ih_toggle_ring_interrupts(ring 0).
    fn toggle(io: &mut I, l: Layout, enable: bool) -> Result<(), Error> {
        let bits = if enable { ENABLE | ENABLE_INTR } else { 0 };
        Self::update(
            io,
            Self::reg(l, RB_CNTL),
            ENABLE | ENABLE_INTR | GPU_TS,
            bits | GPU_TS,
        )?;
        if !enable {
            io.write(Self::reg(l, RB_RPTR), 0);
            io.write(Self::reg(l, RB_WPTR), 0);
        }
        Ok(())
    }
    /// force_update_wptr_for_self_int(adev, 0, 8, enable), OSSSYS >= 5.0.3.
    fn self_int(io: &mut I, l: Layout, enable: bool) -> Result<(), Error> {
        let cntl2 = checked(io.read(Self::reg(l, IH_CNTL2)))?;
        let cntl2 =
            (cntl2 & !(FORCE_TIMEOUT | FORCE_ENABLE)) | 8 | if enable { FORCE_ENABLE } else { 0 };
        Self::update(io, Self::reg(l, RB_CNTL_RING1), THRESHOLD, 0)?;
        Self::update(io, Self::reg(l, RB_CNTL_RING2), THRESHOLD, 0)?;
        io.write(Self::reg(l, IH_CNTL2), cntl2);
        Ok(())
    }
    /// navi10_ih_irq_init with nbio_v2_3 ih_control/ih_doorbell_range. No
    /// IH_CHICKEN write: Linux sets MC_SPACE_GPA only for direct firmware load.
    fn program(&mut self, msi: bool) -> Result<(), Error> {
        self.state = State::Programming;
        let address = self.memory.address();
        let writeback = address + WPTR_WB;
        let dummy = self.dummy;
        let map = self.memory.mapping();
        self.access(|io, l| {
            for offset in (0..BYTES).step_by(4) {
                io.write_memory(map, offset, 0);
            }
            fence(Ordering::SeqCst);
            io.write(0x7f000, 0);
            io.read(Self::nbio(l, 0xc3));
            fence(Ordering::SeqCst);
            Ok(())
        })?;
        // Publish before IH can retain the ring/writeback address.
        self.memory.publish();
        self.access(|io, l| {
            Self::toggle(io, l, false)?;
            io.write(Self::nbio(l, INTERRUPT_CNTL2), (dummy >> 8) as u32);
            // Dummy read off with MSI, on without. NONSNOOP stays 0 as Linux.
            Self::update(
                io,
                Self::nbio(l, INTERRUPT_CNTL),
                DUMMY_RD_OVERRIDE | REQ_NONSNOOP,
                0,
            )?;
            io.write(Self::reg(l, RB_BASE), (address >> 8) as u32);
            io.write(Self::reg(l, RB_BASE_HI), ((address >> 40) & 0xff) as u32);
            Self::update(
                io,
                Self::reg(l, RB_CNTL),
                MC_SPACE
                    | OVERFLOW_CLEAR
                    | OVERFLOW_ENABLE
                    | SIZE_MASK
                    | WRITEBACK
                    | MC_SNOOP
                    | MC_RO
                    | MC_VMID
                    | RPTR_REARM,
                (4 << 28)
                    | OVERFLOW_CLEAR
                    | OVERFLOW_ENABLE
                    | (RB_SIZE << 1)
                    | WRITEBACK
                    | MC_SNOOP
                    | if msi { RPTR_REARM } else { 0 },
            )?;
            io.write(Self::reg(l, WPTR_ADDR_LO), writeback as u32 & !3);
            io.write(
                Self::reg(l, WPTR_ADDR_HI),
                (writeback >> 32) as u32 & 0xffff,
            );
            io.write(Self::reg(l, RB_WPTR), 0);
            io.write(Self::reg(l, RB_RPTR), 0);
            io.write(Self::reg(l, DOORBELL_RPTR), 0);
            Self::update(io, Self::nbio(l, IH_DOORBELL_RANGE), DOORBELL_SIZE, 0)?;
            Self::toggle(io, l, true)?;
            Self::self_int(io, l, true)
        })?;
        self.rptr = 0;
        self.state = State::Enabled;
        Ok(())
    }
    /// navi10_ih_get_wptr: writeback first, register only on overflow.
    fn wptr(io: &mut I, l: Layout, map: MmioRegion, rptr: &mut u32) -> Result<(u32, bool), Error> {
        let writeback = io.read_memory(map, WPTR_WB);
        if writeback & RB_OVERFLOW == 0 {
            return Ok((writeback & MASK, false));
        }
        let wptr = checked(io.read(Self::reg(l, RB_WPTR)))?;
        if wptr & RB_OVERFLOW == 0 {
            return Ok((wptr & MASK, false));
        }
        let wptr = wptr & !RB_OVERFLOW;
        // Resume from the oldest vector not yet overwritten.
        *rptr = wptr.wrapping_add(32) & MASK;
        let cntl = Self::update(io, Self::reg(l, RB_CNTL), OVERFLOW_CLEAR, OVERFLOW_CLEAR)?;
        io.write(Self::reg(l, RB_CNTL), cntl & !OVERFLOW_CLEAR);
        Ok((wptr & MASK, true))
    }
    /// One bounded amdgpu_ih_process pass; always writes back the rptr.
    fn collect(&mut self, out: &mut [Iv; BATCH]) -> Result<Batch, Error> {
        let map = self.memory.mapping();
        let mut rptr = self.rptr;
        let batch = self.access(|io, l| {
            io.write(l.hdp + u64::from(HDP_READ_CACHE_INVALIDATE) * 4, 1);
            io.read(l.hdp + u64::from(HDP_READ_CACHE_INVALIDATE) * 4);
            fence(Ordering::SeqCst);
            let (wptr, overflow) = Self::wptr(io, l, map, &mut rptr)?;
            let mut batch = Batch {
                overflow,
                ..Batch::default()
            };
            // IVs are 32 bytes; a misaligned pointer cannot be followed.
            if wptr % 32 != 0 {
                batch.malformed += 1;
            }
            let wptr = wptr & !31;
            rptr &= !31;
            while rptr != wptr && batch.count < BATCH {
                let mut dw = [0; 8];
                for (index, word) in dw.iter_mut().enumerate() {
                    *word = io.read_memory(map, u64::from(rptr) + index as u64 * 4);
                }
                rptr = (rptr + 32) & MASK;
                if dw[0] == u32::MAX {
                    checked(io.read(Self::reg(l, RB_CNTL)))?;
                }
                let iv = Iv::decode(dw);
                if dw[0] == u32::MAX || iv.client >= CLIENTS {
                    batch.malformed += 1;
                    continue;
                }
                out[batch.count] = iv;
                batch.count += 1;
            }
            batch.more = rptr != wptr;
            io.write(Self::reg(l, RB_RPTR), rptr);
            Ok(batch)
        });
        self.rptr = rptr;
        batch
    }
    /// navi10_ih_irq_disable register writes; the caller waits 1 ms.
    fn disable(&mut self) -> Result<(), Error> {
        if self.state != State::Enabled {
            return Err(Error::Busy);
        }
        self.state = State::Disabled;
        self.access(|io, l| {
            Self::self_int(io, l, false)?;
            Self::toggle(io, l, false)
        })?;
        self.rptr = 0;
        Ok(())
    }
}

#[derive(Debug)]
struct Slot {
    source: Source,
    generation: u64,
    queue: VecDeque<Iv>,
    waker: Option<Waker>,
    lost: u64,
}
#[derive(Debug, Default)]
struct Table {
    next: u64,
    slots: Vec<Slot>,
}
/// IRQ-visible state. The IRQ handler touches only atomics here.
struct Hub {
    table: IrqSafeSpinLock<Table>,
    closed: AtomicU8,
    pending: AtomicBool,
    vector: AtomicU16,
    delivery: AtomicU8,
    interrupts: AtomicU64,
    drained: AtomicU64,
    unhandled: AtomicU64,
    malformed: AtomicU64,
    overflows: AtomicU64,
    dropped: AtomicU64,
    unsignalled: AtomicU64,
    watchdog: AtomicU64,
}
fn closed_code(reason: Closed) -> u8 {
    match reason {
        Closed::Revoked => 1,
        Closed::Disabled => 2,
        Closed::DeviceLost => 3,
        Closed::AuthorityRevoked => 4,
        Closed::Failed => 5,
    }
}
impl Hub {
    fn new() -> Self {
        Self {
            table: IrqSafeSpinLock::new(Table::default()),
            closed: AtomicU8::new(0),
            pending: AtomicBool::new(false),
            vector: AtomicU16::new(NO_VECTOR),
            delivery: AtomicU8::new(0),
            interrupts: AtomicU64::new(0),
            drained: AtomicU64::new(0),
            unhandled: AtomicU64::new(0),
            malformed: AtomicU64::new(0),
            overflows: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            unsignalled: AtomicU64::new(0),
            watchdog: AtomicU64::new(0),
        }
    }
    /// Minimal IRQ-context work: record and leave decoding to task context.
    fn record_interrupt(&self) {
        self.interrupts.fetch_add(1, Ordering::Relaxed);
        self.pending.store(true, Ordering::Release);
    }
    fn closed(&self) -> Result<(), Closed> {
        match self.closed.load(Ordering::Acquire) {
            0 => Ok(()),
            1 => Err(Closed::Revoked),
            2 => Err(Closed::Disabled),
            3 => Err(Closed::DeviceLost),
            4 => Err(Closed::AuthorityRevoked),
            _ => Err(Closed::Failed),
        }
    }
    /// First terminal reason wins; every parked waiter is woken.
    fn close(&self, reason: Closed) {
        let _ = self.closed.compare_exchange(
            0,
            closed_code(reason),
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let wakers: Vec<Waker> = {
            let mut table = self.table.lock();
            table
                .slots
                .iter_mut()
                .filter_map(|s| s.waker.take())
                .collect()
        };
        wakers.into_iter().for_each(Waker::wake);
    }
    fn delivery(&self) -> Delivery {
        let vector = self.vector.load(Ordering::Acquire) as u8;
        match self.delivery.load(Ordering::Acquire) {
            1 => Delivery::MsiX { vector },
            2 => Delivery::Msi { vector },
            3 => Delivery::Polling,
            _ => Delivery::Pending,
        }
    }
    fn set_delivery(&self, delivery: Delivery) {
        let (kind, vector) = match delivery {
            Delivery::Pending => (0, NO_VECTOR),
            Delivery::MsiX { vector } => (1, u16::from(vector)),
            Delivery::Msi { vector } => (2, u16::from(vector)),
            Delivery::Polling => (3, NO_VECTOR),
        };
        self.vector.store(vector, Ordering::Release);
        self.delivery.store(kind, Ordering::Release);
    }
    fn vector(&self) -> Option<u8> {
        let vector = self.vector.load(Ordering::Acquire);
        (vector != NO_VECTOR).then_some(vector as u8)
    }
    /// Watchdog period: a lost MSI is recovered within 10 ms; polling mode
    /// samples every millisecond.
    fn watchdog_us(&self) -> u64 {
        if self.delivery() == Delivery::Polling {
            1000
        } else {
            10_000
        }
    }
    fn dispatch(&self, ivs: &[Iv]) {
        let mut wakers = Vec::new();
        {
            let mut table = self.table.lock();
            for iv in ivs {
                let Some(slot) = table.slots.iter_mut().find(|s| s.source == iv.source()) else {
                    self.unhandled.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if slot.queue.len() >= QUEUE {
                    slot.queue.pop_front();
                    slot.lost += 1;
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
                slot.queue.push_back(*iv);
                if let Some(waker) = slot.waker.take() {
                    wakers.push(waker);
                }
            }
        }
        wakers.into_iter().for_each(Waker::wake);
    }
    fn stats(&self) -> Stats {
        let load = |v: &AtomicU64| v.load(Ordering::Relaxed);
        Stats {
            interrupts: load(&self.interrupts),
            drained: load(&self.drained),
            unhandled: load(&self.unhandled),
            malformed: load(&self.malformed),
            overflows: load(&self.overflows),
            dropped: load(&self.dropped),
            unsignalled: load(&self.unsignalled),
            watchdog: load(&self.watchdog),
        }
    }
}
trait Port: Send + Sync {
    fn hub(&self) -> &Hub;
    fn drain(&self) -> Result<usize, Closed>;
}
struct Shared<I: Io> {
    hub: Hub,
    engine: Mutex<Engine<I>>,
}
impl<I: Io> Port for Shared<I> {
    fn hub(&self) -> &Hub {
        &self.hub
    }
    fn drain(&self) -> Result<usize, Closed> {
        self.hub.closed()?;
        // A concurrent drainer dispatches on our behalf; waiters stay parked
        // on the vector and their watchdog.
        let Some(mut engine) = self.engine.try_lock() else {
            return Ok(0);
        };
        if engine.state != State::Enabled {
            return Ok(0);
        }
        let signalled = self.hub.pending.swap(false, Ordering::AcqRel);
        let mut total = 0;
        for _ in 0..ROUNDS {
            let mut ivs = [Iv::default(); BATCH];
            let batch = match engine.collect(&mut ivs) {
                Ok(batch) => batch,
                Err(error) => {
                    engine.state = State::Failed;
                    let reason = if error == Error::Revoked {
                        Closed::AuthorityRevoked
                    } else {
                        Closed::DeviceLost
                    };
                    drop(engine);
                    self.hub.close(reason);
                    return Err(reason);
                }
            };
            let hub = &self.hub;
            hub.malformed.fetch_add(batch.malformed, Ordering::Relaxed);
            hub.overflows
                .fetch_add(u64::from(batch.overflow), Ordering::Relaxed);
            hub.drained.fetch_add(batch.count as u64, Ordering::Relaxed);
            hub.dispatch(&ivs[..batch.count]);
            total += batch.count;
            if !batch.more {
                break;
            }
        }
        if total != 0 && !signalled {
            self.hub.unsignalled.fetch_add(1, Ordering::Relaxed);
        }
        Ok(total)
    }
}

/// Cloneable dispatch endpoint for other Navi22 owners (rings, VM, DCN).
#[derive(Clone)]
pub struct Handle(Arc<dyn Port>);
impl core::fmt::Debug for Handle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Handle")
            .field("delivery", &self.delivery())
            .finish_non_exhaustive()
    }
}
impl Handle {
    /// Claim the only route for `source`. Subscribing before IH enable is
    /// allowed; a second live owner is `Busy`.
    pub fn subscribe(&self, source: Source) -> Result<Subscription, Error> {
        let hub = self.0.hub();
        hub.closed().map_err(Error::Closed)?;
        let mut queue = VecDeque::new();
        queue
            .try_reserve_exact(QUEUE)
            .map_err(|_| Error::Allocation)?;
        let mut table = hub.table.lock();
        if table.slots.iter().any(|s| s.source == source) {
            return Err(Error::Busy);
        }
        if table.slots.len() >= SLOTS || table.slots.try_reserve(1).is_err() {
            return Err(Error::Allocation);
        }
        table.next += 1;
        let generation = table.next;
        table.slots.push(Slot {
            source,
            generation,
            queue,
            waker: None,
            lost: 0,
        });
        drop(table);
        Ok(Subscription {
            port: self.0.clone(),
            source,
            generation,
        })
    }
    /// Revoke the current owner of `source`; its waiter observes
    /// `Closed::Revoked` and never receives a later owner's IVs.
    pub fn revoke(&self, source: Source) -> bool {
        let waker = {
            let mut table = self.0.hub().table.lock();
            let Some(index) = table.slots.iter().position(|s| s.source == source) else {
                return false;
            };
            table.slots.swap_remove(index).waker
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        true
    }
    /// Drain the ring in task context. Never call from an IRQ handler.
    pub fn drain(&self) -> Result<usize, Closed> {
        self.0.drain()
    }
    /// Report device loss (e.g. from PCIe recovery); every waiter terminates.
    pub fn close(&self, reason: Closed) {
        self.0.hub().close(reason);
    }
    pub fn delivery(&self) -> Delivery {
        self.0.hub().delivery()
    }
    pub fn stats(&self) -> Stats {
        self.0.hub().stats()
    }
}

/// Generation-tagged ownership of one (client, src) route.
pub struct Subscription {
    port: Arc<dyn Port>,
    source: Source,
    generation: u64,
}
impl core::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Subscription")
            .field("source", &self.source)
            .field("generation", &self.generation)
            .finish_non_exhaustive()
    }
}
impl Subscription {
    pub fn source(&self) -> Source {
        self.source
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// IVs dropped from this mailbox because it was full.
    pub fn lost(&self) -> u64 {
        let table = self.port.hub().table.lock();
        table
            .slots
            .iter()
            .find(|s| s.generation == self.generation)
            .map_or(0, |s| s.lost)
    }
    fn pop(&self, waker: Option<&Waker>) -> Result<Option<Iv>, Closed> {
        let mut table = self.port.hub().table.lock();
        let slot = table
            .slots
            .iter_mut()
            .find(|s| s.generation == self.generation)
            .ok_or(Closed::Revoked)?;
        if let Some(iv) = slot.queue.pop_front() {
            return Ok(Some(iv));
        }
        if let Some(waker) = waker {
            slot.waker = Some(waker.clone());
        }
        Ok(None)
    }
    /// Queued IVs are delivered before a terminal error.
    pub fn try_next(&mut self) -> Result<Option<Iv>, Closed> {
        if let Some(iv) = self.pop(None)? {
            return Ok(Some(iv));
        }
        self.port.hub().closed()?;
        let drained = self.port.drain();
        if let Some(iv) = self.pop(None)? {
            return Ok(Some(iv));
        }
        drained?;
        self.port.hub().closed()?;
        Ok(None)
    }
    /// Wait for the next IV. Woken by dispatch, the host vector, or the
    /// watchdog; cancellation only drops this waiter's registrations.
    pub fn wait(&mut self) -> Next<'_> {
        Next {
            subscription: self,
            timer: None,
            vector: None,
        }
    }
}
impl Drop for Subscription {
    fn drop(&mut self) {
        let mut table = self.port.hub().table.lock();
        table.slots.retain(|s| s.generation != self.generation);
    }
}
#[must_use = "futures do nothing unless polled"]
pub struct Next<'a> {
    subscription: &'a mut Subscription,
    timer: Option<narf_time::SleepUntil>,
    vector: Option<(u8, Waker)>,
}
impl core::fmt::Debug for Next<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Next")
            .field("subscription", &self.subscription)
            .finish_non_exhaustive()
    }
}
impl Future for Next<'_> {
    type Output = Result<Iv, Closed>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        loop {
            match this.subscription.try_next() {
                Ok(Some(iv)) => return Poll::Ready(Ok(iv)),
                Err(reason) => return Poll::Ready(Err(reason)),
                Ok(None) => {}
            }
            // Park under the table lock so a concurrent dispatch/close cannot
            // be missed, then recheck termination.
            match this.subscription.pop(Some(cx.waker())) {
                Ok(Some(iv)) => return Poll::Ready(Ok(iv)),
                Err(reason) => return Poll::Ready(Err(reason)),
                Ok(None) => {}
            }
            let hub = this.subscription.port.hub();
            if let Err(reason) = hub.closed() {
                return Poll::Ready(Err(reason));
            }
            if let Some(vector) = hub.vector() {
                narf_interrupts::dispatch::set_waker(vector, cx.waker().clone());
                this.vector = Some((vector, cx.waker().clone()));
            }
            let period = hub.watchdog_us();
            let timer = this.timer.get_or_insert_with(|| {
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(period).as_instant())
            });
            if Pin::new(timer).poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.timer = None;
            hub.watchdog.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl Drop for Next<'_> {
    fn drop(&mut self) {
        if let Some((vector, waker)) = self.vector.take() {
            narf_interrupts::dispatch::clear_waker(vector, &waker);
        }
    }
}

fn interrupt(cookie: u64) -> narf_interrupts::IrqStatus {
    // SAFETY: the cookie is a Hub inside an Arc whose clone was leaked when
    // the handler was installed; it is never freed.
    let hub = unsafe { &*(cookie as *const Hub) };
    hub.record_interrupt();
    narf_interrupts::IrqStatus::Handled
}

#[derive(Debug)]
enum Route {
    None,
    MsiX(narf_bus::MsixTable),
    Msi,
}

/// Exclusive IH ring owner.
pub struct Ih {
    shared: Arc<Shared<Mmio>>,
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    // Never freed: NBIO may hold its address until reset.
    _dummy: core::mem::ManuallyDrop<narf_io::DmaBuffer>,
    route: Route,
    state: State,
    proof: Option<Result<Proof, Error>>,
}
impl core::fmt::Debug for Ih {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ih")
            .field("state", &self.state)
            .field("route", &self.route)
            .field("proof", &self.proof)
            .finish_non_exhaustive()
    }
}
impl Ih {
    /// Reserve the VRAM ring/writeback and NBIO dummy page without I/O.
    /// # Safety
    /// Caller owns this physical Navi22 GPU, OSSSYS/NBIO/HDP, its PCI
    /// interrupt capabilities and the matching permanent VRAM pool exclusively.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pool: &Pool,
        device: BusDevice,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        let memory = pool.reserve(BYTES).map_err(|_| Error::Allocation)?;
        let dummy = narf_io::alloc_coherent(4096, narf_lib::id::DomainId::DRIVER_0)
            .map_err(|_| Error::Allocation)?;
        // SAFETY: freshly allocated, exclusively owned 4 KiB page.
        unsafe { core::ptr::write_bytes(dummy.cpu_mut_ptr::<u8>(), 0, 4096) };
        let engine = Engine {
            io: Mmio(gpu.regs),
            authority,
            layout,
            memory,
            dummy: dummy.dma_addr().raw(),
            state: State::Prepared,
            rptr: 0,
            inherited: false,
        };
        Ok(Self {
            shared: Arc::new(Shared {
                hub: Hub::new(),
                engine: Mutex::new(engine),
            }),
            device,
            authority,
            _dummy: core::mem::ManuallyDrop::new(dummy),
            route: Route::None,
            state: State::Prepared,
            proof: None,
        })
    }
    pub fn handle(&self) -> Handle {
        Handle(self.shared.clone())
    }
    /// amdgpu_irq_init then navi10_ih_hw_init: route one host vector, then
    /// program and enable RB0. Routing failure degrades to polling.
    /// # Safety
    /// GMC VMID0 is ready (the ring is reached through its system aperture),
    /// and `new`'s ownership contract still holds. No second owner after
    /// failure or cancellation.
    pub async unsafe fn initialize(&mut self) -> Result<Delivery, Error> {
        let shared = self.shared.clone();
        let result = {
            let mut engine = shared.engine.lock().await;
            match engine.preflight() {
                Ok(()) => {
                    // SAFETY: forwarded exclusive PCI function ownership.
                    let delivery = unsafe { self.route() };
                    self.shared.hub.set_delivery(delivery);
                    let msi = !matches!(delivery, Delivery::Polling);
                    engine.program(msi).map(|()| delivery).inspect_err(|_| {
                        engine.state = State::Failed;
                    })
                }
                Err(Error::Busy) => Err(Error::Busy),
                Err(error) => {
                    engine.state = State::Failed;
                    Err(error)
                }
            }
        };
        match result {
            Ok(_) => self.state = State::Enabled,
            Err(Error::Busy) => {}
            Err(_) => {
                self.state = State::Failed;
                self.shared.hub.close(Closed::Failed);
            }
        }
        result
    }
    /// # Safety
    /// Caller owns the PCI function's config space and MSI-X table.
    unsafe fn route(&mut self) -> Delivery {
        #[cfg(target_arch = "x86_64")]
        {
            use narf_interrupts::{dispatch, vector};
            let (cap, device) = (&self.authority, &self.device);
            if narf_bus::pci::set_command(cap, device, narf_bus::pci::cmd::BUS_MASTER).is_err() {
                return Delivery::Polling;
            }
            let cookie = &self.shared.hub as *const Hub as u64;
            // SAFETY: APIC initialization precedes device initcalls.
            let target = unsafe { narf_interrupts::current_cpu_target_id() };
            if target > 255 {
                return Delivery::Polling;
            }
            let Ok(vector) = vector::alloc() else {
                return Delivery::Polling;
            };
            // The handler's Hub must outlive every possible delivery.
            core::mem::forget(self.shared.clone());
            dispatch::install_handler_named(vector, "amdgpu-navi22-ih", cookie, interrupt);
            if let Ok(mut table) = narf_bus::enable_msix(cap, device) {
                // SAFETY: owned function; IH sources are still disabled.
                unsafe { table.disable() };
                if table.alloc_vector().is_some()
                    // SAFETY: one owned vector, installed handler, valid target.
                    && unsafe { table.program_vector(0, target, vector) }.is_ok()
                    // SAFETY: same owned config space.
                    && unsafe { table.enable() }.is_ok()
                {
                    self.route = Route::MsiX(table);
                    return Delivery::MsiX { vector };
                }
                // SAFETY: nothing was delivered through this table.
                unsafe { table.disable() };
            }
            if let Ok(mut cfg) = narf_bus::msi::enable_msi(cap, device, 1) {
                // SAFETY: owned config space; vector and handler installed.
                if unsafe { narf_bus::msi::program_msi(&mut cfg, target, vector) }.is_ok()
                    // SAFETY: same.
                    && unsafe { narf_bus::msi::enable(&cfg) }.is_ok()
                {
                    self.route = Route::Msi;
                    return Delivery::Msi { vector };
                }
            }
            dispatch::remove_handler(vector, "amdgpu-navi22-ih", cookie);
            dispatch::synchronize_irq(vector);
            let _ = vector::free(vector);
            Delivery::Polling
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            Delivery::Polling
        }
    }
    /// Bounded navi10_ih_irq_disable; every waiter receives `Disabled`.
    /// The ring stays quarantined and the vector stays reserved.
    /// # Safety
    /// Same ownership as `new`; consumers no longer depend on IH delivery.
    pub async unsafe fn disable(&mut self) -> Result<(), Error> {
        let result = self.shared.engine.lock().await.disable();
        if result != Err(Error::Busy) {
            delay(1000).await;
            self.state = State::Disabled;
            #[cfg(target_arch = "x86_64")]
            if let Some(vector) = self.shared.hub.vector() {
                match &mut self.route {
                    // SAFETY: IH has stopped raising interrupts.
                    Route::MsiX(table) => unsafe { table.disable() },
                    Route::Msi | Route::None => {}
                }
                narf_interrupts::dispatch::disable_irq(vector);
                narf_interrupts::dispatch::synchronize_irq(vector);
            }
            self.shared.hub.close(Closed::Disabled);
        }
        result
    }
    /// Bounded (100 ms) round trip for an event the caller just raised.
    /// The result is retained in `status()`.
    pub(crate) async fn prove(
        &mut self,
        waiter: &mut Subscription,
        context: u32,
        interrupts: u64,
    ) -> Result<Proof, Error> {
        let result = prove(&self.shared.hub, waiter, context, interrupts).await;
        self.proof = Some(result);
        result
    }
    pub(crate) fn interrupts(&self) -> u64 {
        self.shared.hub.interrupts.load(Ordering::Acquire)
    }
    pub(crate) fn record_proof(&mut self, error: Error) {
        self.proof = Some(Err(error));
    }
    pub fn state(&self) -> State {
        self.shared
            .engine
            .try_lock()
            .map_or(self.state, |engine| engine.state)
    }
    pub fn status(&self) -> Status {
        Status {
            state: self.state(),
            delivery: self.shared.hub.delivery(),
            inherited: self
                .shared
                .engine
                .try_lock()
                .is_some_and(|engine| engine.inherited),
            proof: self.proof,
            stats: self.shared.hub.stats(),
        }
    }
}
async fn prove(
    hub: &Hub,
    waiter: &mut Subscription,
    context: u32,
    interrupts: u64,
) -> Result<Proof, Error> {
    let deadline = narf_time::Deadline::after_ms(100);
    loop {
        if let Some(iv) = waiter.try_next().map_err(Error::Closed)? {
            if iv.ring_id == 0 && iv.src_data[0] & 0x0fff_ffff == context {
                // Allow the MSI write a further 10 ms to be observed.
                let late = narf_time::Deadline::after_ms(10);
                while hub.interrupts.load(Ordering::Acquire) == interrupts
                    && hub.vector().is_some()
                    && !late.expired()
                {
                    delay(500).await;
                }
                return Ok(Proof {
                    iv,
                    interrupt: hub.interrupts.load(Ordering::Acquire) != interrupts,
                });
            }
            continue;
        }
        if deadline.expired() {
            return Err(Error::Timeout);
        }
        delay(1000).await;
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_ih_navi22_tests.rs"]
mod tests;
