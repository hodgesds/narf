//! Native GC12/MMHUB4.1 fault sources owned by the independent IH service.
//! The monitor preserves evidence and contains reporting; per-owner delivery
//! and recovery generations live in amdgpu_navi48_dispatch. There is no VM
//! replay, PTE repair or GPU reset. Poison/ECC vectors are not faults: the
//! retained RAS monitor (amdgpu_navi48_ras) does exactly what Linux does.
pub use crate::amdgpu_navi48_sources::{CommandFault, Poison, SdmaFault, ShaderError};
use crate::{
    amdgpu::AmdGpu, amdgpu_discovery as ip, amdgpu_ih7 as ih, amdgpu_navi48_ras as ras,
    amdgpu_navi48_sources as src, amdgpu_psp_ring::bank,
};
use narf_bus::{BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, CapError, CapOp, Write};

const VM_MASK: u32 = 0x555400;
const CP_MASKS: [u32; 2] = [0x01c00000, 0x01800000];
#[path = "amdgpu_navi48_faults_recovery.rs"]
mod recovery;
pub use recovery::Scope as RecoveryScope;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Busy,
    Revoked,
    DeviceGone,
    Readback,
    Gmc(crate::amdgpu_gmc_navi48::Error),
    DeviceResetRequired,
    Ras(ras::Error),
}
impl From<ras::Error> for Error {
    fn from(e: ras::Error) -> Self {
        match e {
            ras::Error::DeviceGone => Error::DeviceGone,
            e => Error::Ras(e),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Prepared,
    Arming,
    Armed,
    /// Fault sources are masked; this does not mean engines are quiescent.
    Contained,
    /// All client retirement stays frozen until every owned ring is reset.
    Recovering,
    Failed(Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hub {
    Gfx,
    Mm,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Vm {
        hub: Hub,
        page: u64,
        write: bool,
        retry: bool,
    },
    Command {
        fault: CommandFault,
        me: u8,
        pipe: u8,
        queue: u8,
    },
    /// SDMA7 error sources (sdma_v7_0 registers none of them; the IV is the
    /// only evidence). Instance and queue come from the IV ring ID.
    Sdma {
        fault: SdmaFault,
        instance: u8,
        queue: u8,
    },
    /// SQ error word: illegal instruction or memory violation, with the
    /// 21-bit detail field and the IV's VMID/PASID naming the context.
    Shader { error: ShaderError, detail: u32 },
    /// A hub protection latch found set by `sweep` after IH vectors were
    /// lost; the latch's own VMID is the only context evidence.
    Latched { hub: Hub },
}
fn classify(event: ih::Event) -> Option<Kind> {
    let v = event.vector;
    Some(match src::classify(&event) {
        src::Class::Fault(src::Fault::Vm { mm_hub }) => Kind::Vm {
            hub: if mm_hub { Hub::Mm } else { Hub::Gfx },
            page: (u64::from(v.data[0]) << 12) | (u64::from(v.data[1] & 15) << 44),
            write: v.data[1] & 0x20 != 0,
            retry: v.data[1] & 0x80 != 0,
        },
        src::Class::Fault(src::Fault::Command { fault, queue }) => Kind::Command {
            fault,
            me: queue.me,
            pipe: queue.pipe,
            queue: queue.queue,
        },
        src::Class::Fault(src::Fault::Sdma {
            fault,
            instance,
            queue,
        }) => Kind::Sdma {
            fault,
            instance,
            queue,
        },
        src::Class::Fault(src::Fault::Shader { error, detail }) => Kind::Shader { error, detail },
        _ => return None,
    })
}
/// A hub latch snapshot, which can describe a different concurrent fault than
/// the IV. Keep its own VMID and raw value instead of assigning it to a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protection {
    pub raw: u32,
    pub more_faults: bool,
    pub walker_error: u8,
    pub permission_faults: u8,
    pub mapping_error: bool,
    pub client: u16,
    pub write: bool,
    pub vmid: u8,
}
impl Protection {
    fn decode(raw: u32) -> Self {
        Self {
            raw,
            more_faults: raw & 1 != 0,
            walker_error: ((raw >> 1) & 7) as u8,
            permission_faults: ((raw >> 4) & 15) as u8,
            mapping_error: raw & 0x100 != 0,
            client: ((raw >> 9) & 0x1ff) as u16,
            write: raw & 0x40000 != 0,
            vmid: ((raw >> 20) & 15) as u8,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    /// The IV, or `None` for a latch found by `sweep`.
    pub event: Option<ih::Event>,
    pub kind: Kind,
    pub protection: Option<Protection>,
    /// The VM latch-clear write was posted. CP faults have no VM latch to clear.
    pub acknowledged: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status {
    pub state: State,
    pub count: u64,
    /// The first fault since boot: later faults are usually consequences, so
    /// its evidence is never overwritten.
    pub first: Option<Record>,
    pub last: Option<Record>,
    /// A failed mask attempt means hardware sources may still be enabled.
    pub mask_error: Option<Error>,
    pub recovery: RecoveryScope,
    pub recoveries: u64,
}
#[derive(Clone, Copy, Debug)]
struct Layout {
    gfx: u64,
    mm: u64,
}
impl Layout {
    fn resolve(gpu: &AmdGpu) -> Result<Self, Error> {
        if crate::amdgpu_rdna4::Rdna4Chip::of(gpu).is_none() {
            return Err(Error::Unsupported);
        }
        Ok(Self {
            gfx: bank(
                gpu,
                ip::HW_ID_GC,
                crate::amdgpu_rdna4::GC_VERSIONS,
                0,
                0x1e25,
            )
            .map_err(|_| Error::Unsupported)?,
            mm: bank(gpu, ip::HW_ID_MMHUB, &[(4, 1, 0)], 0, 0x573)
                .map_err(|_| Error::Unsupported)?,
        })
    }
    fn controls(self, clients: bool) -> impl ExactSizeIterator<Item = (u64, u32)> {
        let kernel = [
            (self.gfx + 0x1624 * 4, VM_MASK),
            (self.mm + 0x564 * 4, VM_MASK),
            (self.gfx + 0x1e0a * 4, CP_MASKS[0]),
            (self.gfx + 0x1e25 * 4, CP_MASKS[1]),
            // SDMA0_CNTL.TRAP_ENABLE; exclusively owned after cold start.
            (self.gfx + 0x0d * 4, 1),
        ];
        (0..if clients { 35 } else { 5 }).map(move |i| {
            if i < 5 {
                kernel[i]
            } else {
                let n = i - 5;
                let base = [kernel[0].0, kernel[1].0][n / 15];
                (base + (n % 15 + 1) as u64 * 4, VM_MASK)
            }
        })
    }
    fn latch(self, hub: Hub) -> (u64, u64) {
        match hub {
            Hub::Gfx => (self.gfx + 0x15d0 * 4, self.gfx + 0x15cc * 4),
            Hub::Mm => (self.mm + 0x4f0 * 4, self.mm + 0x4ec * 4),
        }
    }
}
trait Io {
    fn read(&mut self, at: u64) -> u32;
    fn write(&mut self, at: u64, value: u32);
}
#[derive(Debug)]
struct Mmio(MmioRegion);
impl Io for Mmio {
    fn read(&mut self, at: u64) -> u32 {
        // SAFETY: discovery bounds all fault registers; every batch invokes
        // current authority and the retained monitor owns these controls.
        unsafe { self.0.read32(at) }
    }
    fn write(&mut self, at: u64, value: u32) {
        // SAFETY: same bounded, exclusive, currently authorized MMIO.
        unsafe { self.0.write32(at, value) }
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
#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    layout: Layout,
    status: Status,
    published: u64,
    owned_clients: bool,
    controls: [u32; 35],
    recovery_mark: u64,
}
impl<I: Io> Engine<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> Result<T, Error>) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)?
    }
    fn enable(&mut self, clients: Option<[u32; 2]>) -> Result<(), Error> {
        if self.status.state != State::Prepared {
            return Err(Error::Busy);
        }
        self.status.state = State::Arming;
        self.owned_clients = clients.is_some();
        let result = self.enable_inner(clients);
        match result {
            Ok(()) => self.status.state = State::Armed,
            Err(e) => {
                self.status.state = State::Failed(e);
                self.status.mask_error = self.mask().err();
            }
        }
        result
    }
    fn enable_inner(&mut self, clients: Option<[u32; 2]>) -> Result<(), Error> {
        let layout = self.layout;
        let owned_clients = self.owned_clients;
        let values = self.access(|io| {
            let mut values = [0; 35];
            for (i, (at, mask)) in layout.controls(owned_clients).enumerate() {
                values[i] = checked(io.read(at))?;
                if values[i] & mask != 0 {
                    return Err(Error::Busy);
                }
                if i < 2 {
                    // Owned flat VMID0, retry disabled.
                    if values[i] & 0x101 != 1 {
                        return Err(Error::Busy);
                    }
                    if clients.is_none() {
                        for vmid in 1..16 {
                            if checked(io.read(at + vmid * 4))? & 1 != 0 {
                                return Err(Error::Busy);
                            }
                        }
                    }
                } else if i >= 5 && Some(values[i]) != clients.map(|v| v[(i - 5) / 15]) {
                    return Err(Error::Busy);
                }
            }
            Ok(values)
        })?;
        for (i, (at, mask)) in layout.controls(owned_clients).enumerate() {
            self.published |= 1 << i;
            self.access(|io| {
                // The service exclusively owns CP interrupt-control writes.
                // Enable EOP here too, so a queue proof never races a fault
                // mask with a competing read/modify/write of the same register.
                let value = values[i] | mask | if (2..4).contains(&i) { 0x84000000 } else { 0 };
                io.write(at, value);
                if checked(io.read(at))? != value {
                    return Err(Error::Readback);
                }
                Ok(())
            })?;
            self.controls[i] = values[i] | if (2..4).contains(&i) { 0x84000000 } else { 0 };
        }
        // A revocation during the final write batch must not publish Armed.
        self.access(|_| Ok(()))
    }
    // Try every owned mask even if one fails; never alter VM translation policy,
    // default-page policy, CP EOP enables or other interrupt classes. Also
    // disable the owned SDMA trap source after a fault or service failure.
    fn mask(&mut self) -> Result<(), Error> {
        let mut error = None;
        for (i, (at, mask)) in self.layout.controls(self.owned_clients).enumerate() {
            if self.published & (1 << i) == 0 {
                continue;
            }
            if let Err(e) = self.access(|io| {
                let value = checked(io.read(at))? & !mask;
                io.write(at, value);
                if checked(io.read(at))? != value {
                    return Err(Error::Readback);
                }
                Ok(())
            }) {
                error.get_or_insert(e);
            }
        }
        error.map_or(Ok(()), Err)
    }
    fn handle(&mut self, event: ih::Event) -> Result<(), Error> {
        let Some(kind) = classify(event) else {
            return Ok(());
        };
        // Preserve the IV even if the capability was revoked before MMIO.
        self.record(Record {
            event: Some(event),
            kind,
            protection: None,
            acknowledged: false,
        });
        match self.status.state {
            State::Armed | State::Contained | State::Recovering => {}
            State::Failed(e) => return Err(e),
            _ => return Err(Error::Busy),
        }
        let result = self.handle_inner(event, kind);
        if let Err(e) = result {
            self.status.state = State::Failed(e);
            self.status.mask_error = self.mask().err();
        }
        result
    }
    fn handle_inner(&mut self, event: ih::Event, kind: Kind) -> Result<(), Error> {
        if let Kind::Vm { hub, .. } = kind {
            let (status, control) = self.layout.latch(hub);
            let raw = self.access(|io| {
                // GC's fast GRBM interface needs a dummy read before the latch
                // is current. Linux uses vmid_src, while client selects the hub.
                if !event.vector.vmid_source {
                    checked(io.read(status))?;
                }
                checked(io.read(status))
            })?;
            self.update_last(|r| r.protection = Some(Protection::decode(raw)));
            // A latch has no PASID, even when its VMID matches the IV: it
            // may describe another fault after that VMID was reassigned.
            self.status.recovery.latch(hub, Protection::decode(raw));
            // amdgpu_vm_update_fault_cache: the IV's PASID names the client
            // (each job maps its VMID to it in the IH LUT).
            if let Kind::Vm { hub, page, .. } = kind {
                crate::amdgpu_vmid::record_fault(
                    event.vector.pasid,
                    crate::amdgpu_vmid::FaultInfo {
                        addr: page,
                        status: raw,
                        vmhub: match hub {
                            Hub::Gfx => 0,
                            Hub::Mm => 1,
                        },
                    },
                );
            }
            self.acknowledge(control)?;
        }
        self.contain()
    }
    /// Complete the latest record, and the first one while they coincide.
    fn update_last(&mut self, f: impl Fn(&mut Record)) {
        if let Some(r) = self.status.last.as_mut() {
            f(r);
        }
        if self.status.count == 1 {
            if let Some(r) = self.status.first.as_mut() {
                f(r);
            }
        }
    }
    // Retain the latch before acknowledging it. Do not retry a fault, fill a
    // PTE or redirect any failed access into host memory.
    fn acknowledge(&mut self, control: u64) -> Result<(), Error> {
        self.access(|io| {
            let value = checked(io.read(control))?;
            io.write(control, value | 1);
            checked(io.read(control))?; // post the self-clearing write
            Ok(())
        })?;
        self.update_last(|r| r.acknowledged = true);
        Ok(())
    }
    fn contain(&mut self) -> Result<(), Error> {
        if self.status.state == State::Armed {
            self.mask()?;
            self.status.state = State::Contained;
        }
        Ok(())
    }
    /// After lost vectors a VM fault IV may have been overwritten. Read both
    /// hub latches (with GC's fast-GRBM dummy read); a set latch is recorded,
    /// acknowledged and contained like an IV-reported fault. Returns the
    /// latched VMID per hub, `[gfx, mm]`.
    fn sweep(&mut self) -> Result<[Option<u8>; 2], Error> {
        match self.status.state {
            State::Armed | State::Contained | State::Recovering => {}
            State::Failed(e) => return Err(e),
            _ => return Err(Error::Busy),
        }
        let result = self.sweep_inner();
        if let Err(e) = result {
            self.status.state = State::Failed(e);
            self.status.mask_error = self.mask().err();
        }
        result
    }
    fn sweep_inner(&mut self) -> Result<[Option<u8>; 2], Error> {
        let mut found = [None; 2];
        for (i, hub) in [Hub::Gfx, Hub::Mm].into_iter().enumerate() {
            let (status, control) = self.layout.latch(hub);
            let raw = self.access(|io| {
                if hub == Hub::Gfx {
                    checked(io.read(status))?;
                }
                checked(io.read(status))
            })?;
            if raw == 0 {
                continue;
            }
            let protection = Protection::decode(raw);
            self.record(Record {
                event: None,
                kind: Kind::Latched { hub },
                protection: Some(protection),
                acknowledged: false,
            });
            self.acknowledge(control)?;
            self.contain()?;
            found[i] = Some(protection.vmid);
        }
        Ok(found)
    }
    fn stop(&mut self) {
        if let Err(e) = self.mask() {
            self.status.mask_error = Some(e);
            self.status.state = State::Failed(e);
        } else if self.status.state == State::Armed {
            self.status.state = State::Contained;
        }
    }
}
#[derive(Debug)]
pub(crate) struct Monitor(Engine<Mmio>, ras::Monitor);
impl Monitor {
    /// # Safety
    /// Own this physical GPU and permanent register mapping. After arming,
    /// retain the monitor and exclude concurrent GMC/CP/SDMA IRQ controls, reset/PM.
    /// Construction validates layout/authority without device writes.
    pub(crate) unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
    ) -> Result<Self, Error> {
        let layout = Layout::resolve(gpu)?;
        authority.invoke(Op(|| ())).map_err(|_| Error::Revoked)?;
        // SAFETY: forwarded ownership; construction performs no device access.
        let ras = unsafe { ras::Monitor::new(gpu, authority) }?;
        Ok(Self(
            Engine {
                io: Mmio(gpu.regs),
                authority,
                layout,
                status: Status {
                    state: State::Prepared,
                    count: 0,
                    first: None,
                    last: None,
                    mask_error: None,
                    recovery: RecoveryScope::default(),
                    recoveries: 0,
                },
                published: 0,
                owned_clients: false,
                controls: [0; 35],
                recovery_mark: 0,
            },
            ras,
        ))
    }
    /// # Safety
    /// Matching GMC and kernel queues are ready; no client has submitted work.
    /// Initialized IH rings and this monitor are retained together, with a
    /// consumer independent of boot locks. Exclude all context/IRQ writers.
    pub(crate) unsafe fn enable(
        &mut self,
        gmc: &mut crate::amdgpu_gmc_navi48::Gmc,
    ) -> Result<(), Error> {
        if self.0.status.state != State::Prepared {
            return Err(Error::Busy);
        }
        let clients = gmc.fault_contexts(self.0.io.0).map_err(|e| {
            let error = Error::Gmc(e);
            self.0.status.state = State::Failed(error);
            error
        })?;
        self.0.enable(Some(clients))?;
        // amdgpu_umc_ras_late_init / soc24_common_late_init, when Linux's
        // RAS policy for this board enables them.
        self.1.arm().map_err(Error::from)
    }
    /// Record and contain a fault vector, or run Linux's RAS handler for a
    /// poison/ECC vector. Returns a RAS event that requires a device reset.
    pub(crate) fn handle(&mut self, event: ih::Event) -> Result<Option<ras::Fatal>, Error> {
        self.0.handle(event)?;
        match src::classify(&event) {
            src::Class::Poison(p) => self.1.handle(event, p).map_err(Error::from),
            _ => Ok(None),
        }
    }
    /// Linux's per-interrupt fatal-error poll (no-op unless DF RAS is on).
    pub(crate) fn poll_ras(&mut self) -> Result<Option<ras::Fatal>, Error> {
        self.1.poll().map_err(Error::from)
    }
    pub(crate) fn ras_status(&self) -> ras::Status {
        self.1.status()
    }
    pub(crate) fn sweep(&mut self) -> Result<[Option<u8>; 2], Error> {
        self.0.sweep()
    }
    pub(crate) fn stop(&mut self) {
        self.0.stop();
    }
    pub(crate) fn status(&self) -> Status {
        self.0.status
    }
    pub(crate) fn begin_recovery(&mut self) -> Result<u64, Error> {
        self.0.begin_recovery()
    }
    /// # Safety
    /// Every owned graphics, compute and SDMA0 ring has reset and passed its
    /// fence test since begin_recovery; no new submission is possible. The IH
    /// service has drained old vectors and swept both fault latches.
    pub(crate) unsafe fn rearm(&mut self, mark: u64) -> Result<RecoveryScope, Error> {
        self.0.rearm(mark)
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_faults_tests.rs"]
mod tests;
