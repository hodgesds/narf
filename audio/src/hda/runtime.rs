use super::*;
use crate::{
    hda_codec::Codec,
    native_irq::{Kind, Route, State},
};
use alloc::{sync::Arc, vec::Vec};
use core::{
    mem::ManuallyDrop,
    sync::atomic::{fence, AtomicBool, Ordering},
};
use narf_bus::{bar, BusDevice, BusDeviceCap};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent, DmaBuffer};
use narf_lib::{id::DomainId, sync::IrqSafeSpinLock};
use narf_time::Deadline;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HdaError {
    BarMapFailed,
    ResetTimeout,
    CorbResetTimeout,
    NoCodecs,
    NoOutputStream,
    DmaAllocFailed,
    CommandTimeout,
    FirmwareMissing,
    FirmwarePatchMalformed,
    Busy,
    DeviceFailed,
}
#[derive(Debug, Default)]
struct Commands {
    wp: u16,
    rp: u16,
}

pub struct IntelHda {
    pub(super) bar0: bar::MmioRegion,
    corb: ManuallyDrop<DmaBuffer>,
    rirb: ManuallyDrop<DmaBuffer>,
    commands: IrqSafeSpinLock<Commands>,
    busy: AtomicBool,
    pub(super) irq: Arc<State>,
    route: Option<Route>,
    pub irq_vector: Option<u8>,
    counts: (u8, u8, u8),
    codecs: Vec<CodecInfo>,
    pub(super) graphs: Vec<Codec>,
    pub(super) outputs: Vec<super::routing::Path>,
    pub(super) input: Option<super::routing::Path>,
    pub(super) streams: [IrqSafeSpinLock<super::stream::Stream>; 2],
    pub(super) irq_control: IrqSafeSpinLock<()>,
    pub(super) volume: IrqSafeSpinLock<super::routing::Volume>,
    pub ready: bool,
}
impl core::fmt::Debug for IntelHda {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelHda")
            .field("codecs", &self.codecs)
            .field("counts", &self.counts)
            .field("ready", &self.ready)
            .finish()
    }
}

pub(super) fn wait(mut predicate: impl FnMut() -> bool, ms: u64) -> bool {
    narf_scheduler::responsive_spin_until(&mut predicate, Deadline::after_ms(ms))
}
pub(super) fn delay_us(us: u64) {
    let deadline = Deadline::after_us(us);
    narf_scheduler::responsive_spin_until(|| deadline.expired(), Deadline::after_us(us + 1000));
}

impl IntelHda {
    /// # Safety
    /// Caller exclusively owns this PCI function and its DMA engines.
    pub unsafe fn bring_up(
        device: &BusDevice,
        cap: &Cap<BusDeviceCap, Write>,
    ) -> Result<Self, HdaError> {
        // SAFETY: Bus probing has exclusively claimed this function and its BAR.
        let bar = unsafe { bar::map_bar(device, 0) }.map_err(|_| HdaError::BarMapFailed)?;
        if bar.len < 0x100 {
            return Err(HdaError::BarMapFailed);
        }
        // AMD SB cache snooping, matching azx_init_pci; never touch Intel TCSEL.
        if device.id.vendor == 0x1022 {
            cap.check_live().map_err(|_| HdaError::DeviceFailed)?;
            if let narf_bus::BusKind::Pcie { cfg_phys, .. } = device.kind {
                // SAFETY: claimed function's vendor-specific byte, not a status dword.
                unsafe {
                    let p =
                        narf_bus::ecam::ptr_for(cfg_phys, 0x42).ok_or(HdaError::BarMapFailed)?;
                    p.write_volatile((p.read_volatile() & !7) | 2);
                }
            }
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let mut dev = unsafe { Self::initialize(bar) }?;
        dev.route = Route::new(device, cap, dev.irq.clone());
        dev.irq_vector = dev.route.as_ref().map(|r| r.vector);
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write32(
                REG_INTCTL,
                if dev.route.is_some() {
                    INTCTL_GIE | INTCTL_CIE
                } else {
                    0
                },
            );
        }
        Ok(dev)
    }

    /// # Safety
    /// The window is exclusively owned and has space for all advertised streams.
    pub(super) unsafe fn initialize(bar: bar::MmioRegion) -> Result<Self, HdaError> {
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write32(REG_INTCTL, 0);
            bar.write8(REG_CORBCTL, 0);
            bar.write8(REG_RIRBCTL, 0);
            bar.write32(REG_GCTL, 0);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { bar.read32(REG_GCTL) } & 1 == 0, 100) {
            return Err(HdaError::ResetTimeout);
        }
        delay_us(100);
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write32(REG_GCTL, GCTL_CRST);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { bar.read32(REG_GCTL) } & 1 != 0, 100) {
            return Err(HdaError::ResetTimeout);
        }
        delay_us(1000);
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let gcap = unsafe { bar.read16(REG_GCAP) };
        let counts = (
            ((gcap >> 8) & 15) as u8,
            ((gcap >> 12) & 15) as u8,
            ((gcap >> 4) & 15) as u8,
        );
        if counts.0 + counts.1 + counts.2 > 30 || sd_base(counts.0 + counts.1 + counts.2) > bar.len
        {
            return Err(HdaError::BarMapFailed);
        }
        let corb =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| HdaError::DmaAllocFailed)?;
        let rirb =
            alloc_coherent(4096, DomainId::DRIVER_0).map_err(|_| HdaError::DmaAllocFailed)?;
        if gcap & 1 == 0 && (corb.dma_addr().raw() >> 32 != 0 || rirb.dma_addr().raw() >> 32 != 0) {
            return Err(HdaError::DmaAllocFailed);
        }
        let mut dev = Self {
            bar0: bar,
            corb: ManuallyDrop::new(corb),
            rirb: ManuallyDrop::new(rirb),
            commands: IrqSafeSpinLock::new(Commands::default()),
            busy: AtomicBool::new(false),
            irq: State::new(bar, Kind::Hda),
            route: None,
            irq_vector: None,
            counts,
            codecs: Vec::new(),
            graphs: Vec::new(),
            outputs: Vec::new(),
            input: None,
            streams: [
                IrqSafeSpinLock::new(super::stream::Stream::new(counts.0, false)),
                IrqSafeSpinLock::new(super::stream::Stream::new(0, true)),
            ],
            irq_control: IrqSafeSpinLock::new(()),
            volume: IrqSafeSpinLock::new(super::routing::Volume {
                left: 87,
                right: 87,
                enabled: true,
            }),
            ready: false,
        };
        // From here Drop resets/quarantines all published DMA on every failure.
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if unsafe { bar.read8(REG_CORBSIZE) } & 0x40 == 0
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            || unsafe { bar.read8(REG_RIRBSIZE) } & 0x40 == 0
        {
            return Err(HdaError::DeviceFailed);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write8(REG_CORBSIZE, CORBSIZE_256);
            bar.write8(REG_RIRBSIZE, RIRBSIZE_256);
            bar.write32(REG_CORBLBASE, dev.corb.dma_addr().raw() as u32);
            bar.write32(REG_CORBUBASE, (dev.corb.dma_addr().raw() >> 32) as u32);
            bar.write32(REG_RIRBLBASE, dev.rirb.dma_addr().raw() as u32);
            bar.write32(REG_RIRBUBASE, (dev.rirb.dma_addr().raw() >> 32) as u32);
            bar.write16(REG_CORBWP, 0);
            bar.write16(REG_CORBRP, 1 << 15);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { bar.read16(REG_CORBRP) } & (1 << 15) != 0, 100) {
            return Err(HdaError::CorbResetTimeout);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write16(REG_CORBRP, 0);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        if !wait(|| unsafe { bar.read16(REG_CORBRP) } & (1 << 15) == 0, 100) {
            return Err(HdaError::CorbResetTimeout);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write16(REG_RIRBWP, 1 << 15);
            bar.write16(REG_RINTCNT, 1);
            bar.write8(REG_RIRBSTS, bar.read8(REG_RIRBSTS) & 5);
            bar.write8(REG_CORBSTS, bar.read8(REG_CORBSTS) & 1);
            bar.write8(REG_RIRBCTL, RIRBCTL_RUN | RIRBCTL_RINTCTL | RIRBCTL_OIC);
            bar.write8(REG_CORBCTL, CORBCTL_RUN | CORBCTL_CMEIE);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let mask = unsafe { bar.read16(REG_STATESTS) } & 0x7fff;
        for cad in 0..15 {
            if mask & (1 << cad) == 0 {
                continue;
            }
            // SAFETY: The live controller owns the command rings; its command lease serializes access.
            let vendor = unsafe { dev.send_verb(make_verb(cad, 0, VERB_GET_PARAMETER)) }?;
            if vendor == 0 || vendor == u32::MAX {
                continue;
            }
            let mut error = None;
            let graph = crate::hda_codec::enumerate(cad, |command| {
                if error.is_some() {
                    return 0;
                }
                // SAFETY: The live controller owns the command rings; its command lease serializes access.
                match unsafe { dev.send_verb(command) } {
                    Ok(v) => v,
                    Err(e) => {
                        error = Some(e);
                        0
                    }
                }
            });
            if let Some(e) = error {
                return Err(e);
            }
            dev.codecs.push(CodecInfo {
                addr: cad,
                vendor_id: vendor,
                revision_id: graph.revision,
                afg_node_id: (graph.afg_nid != 0).then_some(graph.afg_nid),
            });
            if graph.afg_nid != 0 {
                dev.graphs.push(graph);
            }
        }
        if dev.codecs.is_empty() {
            return Err(HdaError::NoCodecs);
        }
        dev.discover_paths();
        dev.ready = !dev.outputs.is_empty() || dev.input.is_some();
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            bar.write16(REG_STATESTS, mask);
            bar.write32(REG_GCTL, GCTL_CRST | GCTL_UNSOL);
            bar.write32(
                REG_INTCTL,
                if dev.route.is_some() {
                    INTCTL_GIE | INTCTL_CIE
                } else {
                    0
                },
            );
        }
        Ok(dev)
    }

    fn acquire_command(&self) -> Result<CommandLease<'_>, HdaError> {
        if self.irq.failed.load(Ordering::Acquire) {
            return Err(HdaError::DeviceFailed);
        }
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| HdaError::Busy)?;
        Ok(CommandLease {
            dev: self,
            pending: false,
        })
    }
    fn post(&self, verb: u32) -> Result<(), HdaError> {
        let mut state = self.commands.lock();
        let next = (state.wp + 1) & 255;
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let rp = unsafe { self.bar0.read16(REG_CORBRP) } & 255;
        if next == rp {
            return Err(HdaError::Busy);
        }
        // SAFETY: Command lock owns the next in-range CORB slot; the BAR remains mapped.
        unsafe {
            self.corb
                .cpu_mut_ptr::<u32>()
                .add(next as usize)
                .write_volatile(verb);
        }
        fence(Ordering::Release);
        state.wp = next;
        // SAFETY: Command lock owns the next in-range CORB slot; the BAR remains mapped.
        unsafe {
            self.bar0.write16(REG_CORBWP, next);
        }
        Ok(())
    }
    fn response(&self, cad: u8) -> Result<Option<u32>, HdaError> {
        if self.irq.failed.load(Ordering::Acquire) {
            return Err(HdaError::DeviceFailed);
        }
        let mut state = self.commands.lock();
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let wp = unsafe { self.bar0.read16(REG_RIRBWP) };
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let status = unsafe { self.bar0.read8(REG_RIRBSTS) };
        if wp == u16::MAX
            || status & RIRBSTS_RIRBOIS != 0
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            || unsafe { self.bar0.read8(REG_CORBSTS) } & 1 != 0
        {
            return Err(HdaError::DeviceFailed);
        }
        // The polled boot path has no IRQ handler yet. Acknowledge response
        // status here too: controllers may pause CORB at the RINTCNT threshold.
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe { self.bar0.write8(REG_RIRBSTS, status & 1) };
        while state.rp != (wp & 255) {
            state.rp = (state.rp + 1) & 255;
            fence(Ordering::Acquire);
            // SAFETY: Masked RIRB index is within the owned 256-entry coherent completion ring.
            let (value, extra) = unsafe {
                let p = self.rirb.cpu_ptr::<u32>().add(state.rp as usize * 2);
                (p.read_volatile(), p.add(1).read_volatile())
            };
            // Unsolicited jack events advance RIRB independently of CORB.
            // Jack state is refreshed by the service task; never use this as a reply.
            if extra & 0x10 == 0 && extra as u8 & 15 == cad {
                return Ok(Some(value));
            }
        }
        Ok(None)
    }
    /// # Safety
    /// This object exclusively owns the controller command transport.
    pub unsafe fn send_verb(&self, verb: u32) -> Result<u32, HdaError> {
        let mut lease = self.acquire_command()?;
        self.post(verb)?;
        lease.pending = true;
        let mut reply = Ok(None);
        let done = wait(
            || {
                reply = self.response((verb >> 28) as u8);
                !matches!(reply, Ok(None))
            },
            100,
        );
        if !done {
            narf_console::write_str(&alloc::format!(
                "hda: verb {:#x} timeout: CORB wp/rp={:#x}/{:#x} RIRB wp={:#x} ctl={:#x}/{:#x}\n",
                verb,
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe { self.bar0.read16(REG_CORBWP) },
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe { self.bar0.read16(REG_CORBRP) },
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe { self.bar0.read16(REG_RIRBWP) },
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe { self.bar0.read8(REG_CORBCTL) },
                // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
                unsafe { self.bar0.read8(REG_RIRBCTL) },
            ));
            return Err(HdaError::CommandTimeout);
        }
        let value = reply?.ok_or(HdaError::CommandTimeout)?;
        lease.pending = false;
        Ok(value)
    }
    /// Bounded IRQ/timer wait. Cancellation poisons the transport until reset,
    /// preventing a late response from being assigned to a subsequent command.
    /// # Safety
    /// Same exclusive device ownership as send_verb.
    pub async unsafe fn send_verb_async(&self, verb: u32) -> Result<u32, HdaError> {
        let mut lease = self.acquire_command()?;
        self.post(verb)?;
        lease.pending = true;
        let deadline = Deadline::after_ms(100);
        loop {
            // Arm before checking the ring to close the completion/wake race.
            let waiter = self
                .irq_vector
                .map(|v| narf_interrupts::wait_for_irq_until(v, Deadline::after_ms(1)));
            if let Some(value) = self.response((verb >> 28) as u8)? {
                lease.pending = false;
                return Ok(value);
            }
            if deadline.expired() {
                return Err(HdaError::CommandTimeout);
            }
            if let Some(waiter) = waiter {
                let _ = waiter.await;
            } else {
                narf_time::SleepUntil::new(Deadline::after_ms(1).as_instant()).await;
            }
        }
    }
    pub fn stream_counts(&self) -> (u8, u8, u8) {
        self.counts
    }
    pub fn codecs(&self) -> &[CodecInfo] {
        &self.codecs
    }
    pub fn output_stream_idx(&self) -> u8 {
        self.counts.0
    }
    pub fn period_bytes(&self) -> u32 {
        4096
    }
    pub fn period_samples(&self) -> usize {
        2048
    }
    /// # Safety
    /// The controller mapping remains exclusively owned.
    pub unsafe fn drain_irq(&self) {
        self.irq.service();
    }
    /// # Safety
    /// Caller owns this controller and trusts the firmware verb patch.
    pub unsafe fn load_codec_patch(
        &self,
        blob_name: &str,
        fw_authority: &narf_capabilities::Cap<
            narf_firmware::FirmwareRegistry,
            narf_capabilities::Read,
        >,
    ) -> Result<u32, HdaError> {
        let cap =
            narf_firmware::open(blob_name, fw_authority).map_err(|_| HdaError::FirmwareMissing)?;
        let view = narf_firmware::view_of(&cap).map_err(|_| HdaError::FirmwareMissing)?;
        let bytes = view.bytes;
        if bytes.len() % 4 != 0 {
            return Err(HdaError::FirmwarePatchMalformed);
        }
        let mut sent = 0u32;
        let mut i = 0;
        while i + 4 <= bytes.len() {
            let verb = u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]);
            // SAFETY: caller-asserted exclusive ownership.
            let _ = unsafe { self.send_verb(verb)? };
            sent += 1;
            i += 4;
        }
        // Record the firmware coupling on the bound driver.
        narf_drivers::set_bound_firmware(
            "hda0",
            narf_drivers::BoundFirmware {
                blob_name: alloc::string::String::from(blob_name),
                sha256: view.sha256,
                signer: view.signer,
                version: None,
            },
        );
        Ok(sent)
    }

    fn service(&self) {
        self.irq.service();
        for state in &self.streams {
            state.lock().update(self);
        }
    }
}
struct CommandLease<'a> {
    dev: &'a IntelHda,
    pending: bool,
}
impl Drop for CommandLease<'_> {
    fn drop(&mut self) {
        if self.pending {
            self.dev.irq.failed.store(true, Ordering::Release);
        }
        self.dev.busy.store(false, Ordering::Release);
    }
}
impl Drop for IntelHda {
    fn drop(&mut self) {
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            self.bar0.write32(REG_INTCTL, 0);
            self.bar0.write8(REG_CORBCTL, 0);
            self.bar0.write8(REG_RIRBCTL, 0);
        }
        self.route.take();
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        unsafe {
            self.bar0.write32(REG_GCTL, 0);
        }
        // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
        let stopped = wait(|| unsafe { self.bar0.read32(REG_GCTL) } & 1 == 0, 100);
        for stream in &self.streams {
            if let Some(ring) = stream.lock().ring.take() {
                if !stopped {
                    core::mem::forget(ring);
                }
            }
        }
        if stopped {
            // SAFETY: Controller owns this live BAR; fixed register offsets are inside the validated window.
            unsafe {
                ManuallyDrop::drop(&mut self.corb);
                ManuallyDrop::drop(&mut self.rirb);
            }
        }
    }
}

static CONTROLLERS: IrqSafeSpinLock<Vec<(narf_bus::BusAddr, Arc<IntelHda>, u32)>> =
    IrqSafeSpinLock::new(Vec::new());
pub fn controller() -> Option<Arc<IntelHda>> {
    let all = CONTROLLERS.lock();
    all.iter()
        .find(|(_, c, _)| !c.outputs.is_empty())
        .or_else(|| all.first())
        .map(|(_, c, _)| c.clone())
}
pub fn capture_card() -> Option<u32> {
    CONTROLLERS
        .lock()
        .iter()
        .find(|(_, c, _)| c.input.is_some())
        .map(|(_, _, card)| *card)
}
pub fn is_probed() -> bool {
    controller().is_some_and(|c| !c.outputs.is_empty())
}
pub fn stream_counts() -> Option<(u8, u8, u8)> {
    controller().map(|c| c.stream_counts())
}
pub fn codec_count() -> Option<u8> {
    controller().map(|c| c.codecs.len() as u8)
}
pub fn with_controller<R>(f: impl FnOnce(&IntelHda) -> R) -> Option<R> {
    controller().map(|c| f(&c))
}
#[doc(hidden)]
pub fn __reset_for_test() {
    let old = core::mem::take(&mut *CONTROLLERS.lock());
    for (_, _, card) in &old {
        narf_drivers_sound::unregister_hardware_card(*card);
    }
    drop(old);
}
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    if device.id.class != 0x040300 {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    if CONTROLLERS
        .lock()
        .iter()
        .any(|(addr, _, _)| *addr == device.addr)
    {
        return Ok(());
    }
    crate::native_pci::power_on(&device, &cap)?;
    narf_bus::pci::set_command(
        &cap,
        &device,
        narf_bus::pci::cmd::MEM_SPACE
            | narf_bus::pci::cmd::BUS_MASTER
            | narf_bus::pci::cmd::INTX_DISABLE,
    )
    .map_err(|_| narf_bus::ProbeError::BadDevice)?;
    let dev = Arc::new(
        // SAFETY: Bus probing has exclusively claimed this function and its BAR.
        unsafe { IntelHda::bring_up(&device, &cap) }.map_err(|error| {
            narf_bus::ProbeError::Other(match error {
                HdaError::BarMapFailed => "HDA BAR invalid",
                HdaError::ResetTimeout => "HDA controller reset timed out",
                HdaError::CorbResetTimeout => "HDA CORB reset timed out",
                HdaError::NoCodecs => "HDA no codecs responded",
                HdaError::DmaAllocFailed => "HDA DMA allocation failed",
                HdaError::CommandTimeout => "HDA codec command timed out",
                HdaError::DeviceFailed => "HDA command engine failed",
                _ => "HDA initialization failed",
            })
        })?,
    );
    if !dev.ready {
        return Err(narf_bus::ProbeError::NotForThisDriver);
    }
    let info = narf_drivers_sound::CardInfo {
        index: 0,
        driver: "hda",
        id: "HDA",
        name: "HD Audio",
        playback_count: u32::from(!dev.outputs.is_empty()),
        capture_count: u32::from(dev.input.is_some()),
    };
    let card = narf_drivers_sound::register_hardware_card_at(
        info,
        Arc::new(super::stream::Card(dev.clone())),
        Some(device.addr),
    );
    CONTROLLERS.lock().push((device.addr, dev.clone(), card));
    let weak = Arc::downgrade(&dev);
    narf_scheduler::spawn(async move {
        loop {
            narf_time::SleepUntil::new(Deadline::after_ms(2).as_instant()).await;
            let Some(dev) = weak.upgrade() else {
                break;
            };
            dev.service();
        }
    });
    let weak = Arc::downgrade(&dev);
    narf_scheduler::spawn(async move {
        loop {
            narf_time::SleepUntil::new(Deadline::after_ms(100).as_instant()).await;
            let Some(dev) = weak.upgrade() else {
                break;
            };
            let _ = dev.refresh_jacks();
        }
    });
    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: "hda".into(),
        kind: narf_drivers::BoundKind::Audio,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Audio.default_domain(),
    });
    Ok(())
}

#[cfg(feature = "kernel-test")]
#[path = "runtime_tests.rs"]
mod tests;
