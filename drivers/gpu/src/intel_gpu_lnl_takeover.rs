//! LNL/PTL retained headless takeover and shared-GGTT media ordering.
//!
//! MIT Linux b90c984d: xe_device.c::__xe_driver_flr documents reset of GT,
//! display and stolen memory; xe uses it during shutdown/fini, not probe.
//! NARF uses that explicit reset/ACK contract only before constructing a fresh
//! GT arena, then performs complete GT initialization with no inherited image.
//! xe_ggtt.c::ggtt_update_access_counter and xe_wa_oob.rules select the media
//! 20.00/all steps or30.00/preB0 WA at63 PTEs. No HuC or media scheduling is admitted here.
//!
//! The opted-in Lunar Lake display-20 function never runs that FLR: its
//! receipt comes from [`Receipt::admit_display`], which preserves the lit
//! panel and leaves the GT-only reset to `HardwareInit` (see there).
use crate::intel_gpu_aux::MmioWindow;
use core::task::Poll;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Busy,
    Unavailable,
    Timeout,
    State,
}

fn read(mmio: &impl MmioWindow, reg: u64) -> Result<u32, Error> {
    let value = mmio.read32(reg);
    if value == u32::MAX {
        Err(Error::Unavailable)
    } else {
        Ok(value)
    }
}
fn pf(mmio: &impl MmioWindow) -> Result<(), Error> {
    if read(mmio, 0x1901f8)? & 1 != 0 || read(mmio, 0x10100c)? & 0x80000000 != 0 {
        return Err(Error::Unsupported);
    }
    Ok(())
}

/// A completed driver FLR bound to this exact physical function/BAR mapping.
/// No safe constructor exists outside the acknowledged reset sequence.
#[derive(Debug)]
pub(crate) struct Receipt {
    device: u16,
    function: narf_bus::BusAddr,
    bar: u64,
    len: u64,
    incarnation: u64,
    display: Option<u32>,
    fresh: Fresh,
}

/// How a [`Receipt`] established its fresh incarnation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Fresh {
    /// `__xe_driver_flr`: GT, display and stolen memory were reset.
    DriverFlr,
    /// No driver FLR: the display-20 route owns the lit display and the GT
    /// is reset alone (GRDOM_GUC, GRDOM_FULL) before any PTE.
    DisplayOwned,
}

static NEXT_FLR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// `GU_CNTL` / `DRIVERFLR` and `GU_DEBUG` / `DRIVERFLR_STATUS` (xe_regs.h;
/// both flags are bit 31).
const GU_CNTL: u64 = 0x101010;
const GU_DEBUG: u64 = 0x101018;
const DRIVERFLR: u32 = 1 << 31;
/// `VF_CAP_REG`.
const VF_CAP: u64 = 0x1901f8;

fn next_incarnation() -> Result<u64, Error> {
    NEXT_FLR
        .fetch_update(
            core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed,
            |value| value.checked_add(1),
        )
        .map_err(|_| Error::State)
}

impl Receipt {
    pub(crate) fn matches(
        &self,
        device: narf_bus::BusDevice,
        bar: narf_bus::bar::MmioRegion,
        mmio: &impl MmioWindow,
    ) -> bool {
        self.device == device.id.device
            && self.function == device.addr
            && self.bar == bar.phys.raw()
            && self.len == bar.len
            && self.incarnation != 0
            && match self.fresh {
                Fresh::DriverFlr => {
                    pf(mmio).is_ok()
                        && read(mmio, GU_CNTL).is_ok_and(|v| v & DRIVERFLR == 0)
                        && read(mmio, GU_DEBUG).is_ok_and(|v| v & DRIVERFLR == 0)
                        && post_flr_display(mmio, self.device).is_ok_and(|gmd| gmd == self.display)
                }
                Fresh::DisplayOwned => display_owned_current(mmio, self.display),
            }
    }

    /// Whether this receipt preserved the display (no driver FLR).
    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn display_preserving(&self) -> bool {
        self.fresh == Fresh::DisplayOwned
    }

    /// The display-preserving fresh-GT admission of the opted-in Lunar Lake
    /// display-20 function. No driver FLR runs.
    ///
    /// MIT Linux b90c984d: `xe_device_probe` never triggers
    /// `__xe_driver_flr`; it only arms it for `xe_driver_flr_fini` (failed
    /// probe), `xe_device_shutdown` and a wedged device. Probe freshens the
    /// GT with `xe_uc_init_post_hwconfig` → `xe_uc_sanitize_reset` →
    /// `xe_guc_reset` (`GDRST` = `GRDOM_GUC`), and `xe_gt.c::do_gt_reset`
    /// (`GDRST` = `GRDOM_FULL`) is the reset `gt_reset_worker` and
    /// `xe_gt_shutdown` run while display keeps scanning out. NARF's
    /// `HardwareInit` runs `GRDOM_GUC` then `GRDOM_FULL` on the primary GT,
    /// and `MediaQuiesce` the same pair on the media GT, before its cache
    /// policy may publish the first GGTT PTE. That GT-only reset meets the
    /// headless FLR's inherited-GT rationale (GuC, engines, contexts).
    /// Wa_14015076503 around `do_gt_reset` is media 13.00 only.
    ///
    /// What the FLR also provided is proved here instead, read-only:
    /// - no FLR is in flight (`GU_CNTL.DRIVERFLR`); a stale
    ///   `GU_DEBUG.DRIVERFLR_STATUS` is acknowledged once (W1C, the only
    ///   write, as `__xe_driver_flr` does before its trigger), so any later
    ///   FLR fails every PTE write's [`Self::matches`];
    /// - the display is the qualified 20.00 IP with Pipe A fused in and lit
    ///   (the route's owned panel);
    /// - no inherited display DMA producer exists outside that primary:
    ///   Pipes B–D dark, every other universal plane and every cursor off,
    ///   every DSB idle, FBC A–D off, no pipe-DMC flip queue armed and no
    ///   pipe B–D DMC enabled. A powered-down well reads zero, which is
    ///   accepted: an unpowered pipe cannot fetch.
    ///
    /// Stolen memory is not wiped: the boot framebuffer stays live and the
    /// GT arena never maps DSM. `GU_CNTL_PROTECTED.DRIVERINT_FLR_DIS` is not
    /// required clear, since no FLR is requested.
    pub(crate) fn admit_display(
        device: narf_bus::BusDevice,
        bar: narf_bus::bar::MmioRegion,
        mmio: &impl MmioWindow,
        current: impl FnOnce() -> bool,
    ) -> Result<Self, Error> {
        if !current() {
            return Err(Error::Unavailable);
        }
        if device.id.vendor != 0x8086
            || !matches!(device.addr, narf_bus::BusAddr::Pcie(_))
            || !crate::intel_gpu_gt::GtPlatform::from_pci(device.id.vendor, device.id.device)
                .is_some_and(|p| p.is_lnl())
            || bar.phys.raw() == 0
            || bar.phys.raw() & 4095 != 0
            || bar.len < 16 * 1024 * 1024
        {
            return Err(Error::Unsupported);
        }
        if read(mmio, VF_CAP)? & 1 != 0 {
            return Err(Error::Unsupported);
        }
        if read(mmio, GU_CNTL)? & DRIVERFLR != 0 {
            return Err(Error::Busy);
        }
        let gmd = read(mmio, crate::intel_gpu_xe2lpd::GMD_ID_DISPLAY)?;
        if gmd != read(mmio, crate::intel_gpu_xe2lpd::GMD_ID_DISPLAY)?
            || crate::intel_gpu_xe2lpd::DisplayIp::decode(gmd)
                != Ok(crate::intel_gpu_xe2lpd::DisplayIp::Xe2Lpd)
        {
            return Err(Error::Unsupported);
        }
        if read(mmio, crate::intel_gpu_xe2lpd::SKL_DFSM)?
            & crate::intel_gpu_xe2lpd::DFSM_PIPE_A_DISABLE
            != 0
        {
            return Err(Error::Unsupported);
        }
        if read(mmio, 0x70008)? & 0xc0000000 != 0xc0000000 {
            return Err(Error::State);
        }
        display_producers_idle(mmio)?;
        if read(mmio, GU_DEBUG)? & DRIVERFLR != 0 {
            mmio.write32(GU_DEBUG, DRIVERFLR);
            if read(mmio, GU_DEBUG)? & DRIVERFLR != 0 {
                return Err(Error::State);
            }
        }
        Ok(Self {
            device: device.id.device,
            function: device.addr,
            bar: bar.phys.raw(),
            len: bar.len,
            incarnation: next_incarnation()?,
            display: Some(gmd),
            fresh: Fresh::DisplayOwned,
        })
    }
}

/// The per-PTE proof of a display-preserving receipt: still a PF, no FLR in
/// flight or completed since admission, and the same display IP.
fn display_owned_current(m: &impl MmioWindow, display: Option<u32>) -> bool {
    read(m, VF_CAP).is_ok_and(|v| v & 1 == 0)
        && read(m, GU_CNTL).is_ok_and(|v| v & DRIVERFLR == 0)
        && read(m, GU_DEBUG).is_ok_and(|v| v & DRIVERFLR == 0)
        && display.is_some_and(|gmd| {
            read(m, crate::intel_gpu_xe2lpd::GMD_ID_DISPLAY).is_ok_and(|v| v == gmd)
        })
}

/// Display 20.00 (`xe2_lpd_display`) inventory: four pipes, the primary and
/// four sprites per pipe (`num_sprites` is 4 on display >= 13), three DSBs
/// per pipe and FBC A–D. Only Pipe A's primary (the route's surface) may
/// fetch. Every access is a read.
fn display_producers_idle(m: &impl MmioWindow) -> Result<(), Error> {
    for pipe in 0..4u64 {
        let base = 0x70000 + pipe * 0x1000;
        // TRANSCONF(B–D): enable | state.
        if pipe != 0 && read(m, base + 0x8)? & 0xc0000000 != 0 {
            return Err(Error::Busy);
        }
        // CUR_CTL: MCURSOR_MODE_MASK.
        if read(m, base + 0x80)? & 0x27 != 0 {
            return Err(Error::Busy);
        }
        // PLANE_CTL(pipe, 1..=5): PLANE_CTL_ENABLE.
        for plane in 1..=5u64 {
            if pipe == 0 && plane == 1 {
                continue;
            }
            if read(m, base + 0x80 + plane * 0x100)? & (1 << 31) != 0 {
                return Err(Error::Busy);
            }
        }
        // DSB_CTRL(pipe, 0..3): DSB_ENABLE | DSB_STATUS_BUSY.
        for dsb in 0..3u64 {
            if read(m, base + 0xb08 + dsb * 0x100)? & ((1 << 31) | 1) != 0 {
                return Err(Error::Busy);
            }
        }
        // PIPEDMC_FQ_CTRL(pipe): PIPEDMC_FQ_CTRL_ENABLE.
        if read(m, 0x5f078 + pipe * 0x400)? & (1 << 31) != 0 {
            return Err(Error::Busy);
        }
    }
    // ILK_DPFC_CONTROL(FBC A–D): DPFC_CTL_EN.
    for fbc in 0..4u64 {
        if read(m, 0x43208 + fbc * 0x40)? & (1 << 31) != 0 {
            return Err(Error::Busy);
        }
    }
    // MTL_PIPEDMC_CONTROL: PIPEDMC_ENABLE_MTL(B–D).
    if read(m, 0x45250)? & 0x1110 != 0 {
        return Err(Error::Busy);
    }
    Ok(())
}

/// Polling has separate source 3s bounds for pending, teardown and reinit.
/// Cancellation retains this state in the PCI owner. No wake/IP/cache proof
/// sampled before a trigger may be reused afterward.
#[derive(Debug)]
pub(crate) struct DriverFlr {
    device: u16,
    function: narf_bus::BusAddr,
    bar: u64,
    len: u64,
    incarnation: u64,
    phase: u8,
    deadline: u64,
}
impl DriverFlr {
    pub(crate) fn new(
        device: narf_bus::BusDevice,
        bar: narf_bus::bar::MmioRegion,
        now: u64,
    ) -> Result<Self, Error> {
        Self::new_profile(device, bar, now, false)
    }
    pub(crate) fn new_bmg(
        device: narf_bus::BusDevice,
        bar: narf_bus::bar::MmioRegion,
        now: u64,
    ) -> Result<Self, Error> {
        Self::new_profile(device, bar, now, true)
    }
    fn new_profile(
        device: narf_bus::BusDevice,
        bar: narf_bus::bar::MmioRegion,
        now: u64,
        bmg: bool,
    ) -> Result<Self, Error> {
        if device.id.vendor != 0x8086
            || !matches!(device.addr, narf_bus::BusAddr::Pcie(_))
            || !crate::intel_gpu_gt::GtPlatform::from_pci(device.id.vendor, device.id.device)
                .is_some_and(|p| {
                    if bmg {
                        p == crate::intel_gpu_gt::GtPlatform::Battlemage
                    } else {
                        p.is_headless_integrated()
                    }
                })
            || bar.phys.raw() == 0
            || bar.phys.raw() & 4095 != 0
            || bar.len < 16 * 1024 * 1024
        {
            return Err(Error::Unsupported);
        }
        let incarnation = next_incarnation()?;
        Ok(Self {
            device: device.id.device,
            function: device.addr,
            bar: bar.phys.raw(),
            len: bar.len,
            incarnation,
            phase: 0,
            deadline: now.checked_add(3_000_000_000).ok_or(Error::Timeout)?,
        })
    }
    /// Caller proves exclusive physical-function ownership, PCI D0 and no
    /// existing GT/display clients on every poll, before this method's MMIO.
    pub(crate) fn poll(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
        current: impl FnOnce() -> bool,
    ) -> Poll<Result<Receipt, Error>> {
        if !current() {
            return Poll::Ready(Err(Error::Unavailable));
        }
        pf(mmio)?;
        // __xe_driver_flr waits with xe_mmio_wait32, whose final read after
        // the loop wins over the timeout: a late poll that finds the phase's
        // condition met progresses. Each phase re-arms the 3 s bound.
        match self.advance(mmio, now) {
            Poll::Pending if now >= self.deadline => Poll::Ready(Err(Error::Timeout)),
            result => result,
        }
    }
    fn advance(&mut self, mmio: &impl MmioWindow, now: u64) -> Poll<Result<Receipt, Error>> {
        match self.phase {
            0 => {
                let control = read(mmio, 0x101010)?;
                if control & 0x80000000 != 0 {
                    return Poll::Pending;
                }
                mmio.write32(0x101018, 0x80000000);
                // Fresh W1C clear is mandatory: a stale ACK cannot authorize
                // any new mapping if this invocation lost write authority.
                if read(mmio, 0x101018)? & 0x80000000 != 0 {
                    return Poll::Ready(Err(Error::State));
                }
                mmio.write32(0x101010, control | 0x80000000);
                let _ = read(mmio, 0x101010)?;
                self.phase = 1;
                self.deadline = now.checked_add(3_000_000_000).ok_or(Error::Timeout)?;
                Poll::Pending
            }
            1 => {
                if read(mmio, 0x101010)? & 0x80000000 != 0 {
                    return Poll::Pending;
                }
                self.phase = 2;
                self.deadline = now.checked_add(3_000_000_000).ok_or(Error::Timeout)?;
                Poll::Pending
            }
            2 => {
                if read(mmio, 0x101018)? & 0x80000000 == 0 {
                    return Poll::Pending;
                }
                mmio.write32(0x101018, 0x80000000);
                if read(mmio, 0x101018)? & 0x80000000 != 0 {
                    return Poll::Ready(Err(Error::State));
                }
                self.phase = 3;
                let display = post_flr_display(mmio, self.device)?;
                Poll::Ready(Ok(Receipt {
                    device: self.device,
                    function: self.function,
                    bar: self.bar,
                    len: self.len,
                    incarnation: self.incarnation,
                    display,
                    fresh: Fresh::DriverFlr,
                }))
            }
            _ => Poll::Ready(Err(Error::State)),
        }
    }
}

/// Immutable media identity observed under this owner's GT wake. The owner
/// keeps the media GuC in reset and all media engines reset/idle, and admits
/// no media client until every GGTT mapping has been invalidated.
#[derive(Copy, Clone, Debug)]
pub(crate) struct MediaProof {
    gmd: u32,
}
impl MediaProof {
    pub(crate) fn current(self, mmio: &impl MmioWindow) -> Result<(), Error> {
        if read(mmio, 0x1901f8)? & 1 != 0 {
            return Err(Error::Unsupported);
        }
        if read(mmio, 0x38a188)? & 1 == 0
            || read(mmio, 0x380dfc)? & 1 == 0
            || read(mmio, 0x38941c)? != 0
            || read(mmio, 0x38c000)? & 1 == 0
            || read(mmio, 0x38c314)? & 1 != 0
            || read(mmio, 0x380d8c)? != self.gmd
        {
            return Err(Error::State);
        }
        Ok(())
    }
    /// Called after each complete 64-bit PTE, including invalidations, under
    /// the arena lock. The 63-PTE counter is shared by all arena writers.
    pub(crate) fn after_pte(
        self,
        mmio: &impl MmioWindow,
        count: &core::cell::Cell<u8>,
    ) -> Result<(), Error> {
        self.current(mmio)?;
        // Wa22019338487: media20.00 all steps; media30.00 A0 only.
        // The immutable GMD was captured under the retained media wake.
        let version = (self.gmd >> 22) * 100 + ((self.gmd >> 14) & 255);
        if version == 1301 || version == 3000 && self.gmd & 63 >= 4 {
            return Ok(());
        }
        let next = count.get() + 1;
        if next == 63 {
            mmio.write32(0x380d8c, 0);
            count.set(0);
        } else {
            count.set(next);
        }
        self.current(mmio)
    }
}

#[derive(Debug)]
pub(crate) struct MediaQuiesce {
    expected: u16,
    phase: u8,
    deadline: u64,
    gmd: u32,
    releasing: bool,
}
impl MediaQuiesce {
    pub(crate) fn for_platform(platform: crate::intel_gpu_gt::GtPlatform) -> Self {
        let mut state = Self::new();
        state.expected = if platform.is_ptl() { 3000 } else { 2000 };
        state
    }
    pub(crate) fn for_bmg() -> Self {
        let mut state = Self::new();
        state.expected = 1301;
        state
    }
    pub(crate) fn new() -> Self {
        Self {
            expected: 2000,
            phase: 0,
            deadline: 0,
            gmd: 0,
            releasing: false,
        }
    }
    pub(crate) fn poll(
        &mut self,
        mmio: &impl MmioWindow,
        now: u64,
    ) -> Poll<Result<MediaProof, Error>> {
        if self.phase == 0 {
            if read(mmio, 0x38a188)? & 1 != 0 || read(mmio, 0x380dfc)? & 1 != 0 {
                return Poll::Ready(Err(Error::Busy));
            }
            self.deadline = now.checked_add(50_000_000).ok_or(Error::Timeout)?;
            mmio.write32(0x38a188, 0x00010001);
            let _ = read(mmio, 0x38a188)?;
            self.phase = 1;
            return Poll::Pending;
        }
        if self.phase == 4 {
            let proof = MediaProof { gmd: self.gmd };
            proof.current(mmio)?;
            return Poll::Ready(Ok(proof));
        }
        // xe_force_wake / xe_mmio_wait32 final read: the media ACK and the
        // GRDOM_GUC/GRDOM_FULL reads precede the deadline. A late poll that
        // finds the condition met progresses; each phase re-arms its bound.
        match self.advance(mmio, now) {
            Poll::Pending if now >= self.deadline => Poll::Ready(Err(Error::Timeout)),
            result => result,
        }
    }
    fn advance(&mut self, mmio: &impl MmioWindow, now: u64) -> Poll<Result<MediaProof, Error>> {
        if read(mmio, 0x380dfc)? & 1 == 0 {
            return Poll::Pending;
        }
        if read(mmio, 0x38a188)? & 1 == 0 {
            return Poll::Ready(Err(Error::State));
        }
        match self.phase {
            1 => {
                let a = read(mmio, 0x380d8c)?;
                if a != read(mmio, 0x380d8c)?
                    || (a >> 22) * 100 + ((a >> 14) & 255) != u32::from(self.expected)
                {
                    return Poll::Ready(Err(Error::Unsupported));
                }
                self.gmd = a;
                if read(mmio, 0x38941c)? != 0 {
                    return Poll::Ready(Err(Error::Busy));
                }
                mmio.write32(0x38941c, 8);
                self.phase = 2;
                self.deadline = now.checked_add(5_000_000).ok_or(Error::Timeout)?;
                Poll::Pending
            }
            2 => {
                if read(mmio, 0x38941c)? & 8 != 0 {
                    return Poll::Pending;
                }
                if read(mmio, 0x38c000)? & 1 == 0 || read(mmio, 0x38c314)? & 1 != 0 {
                    return Poll::Pending;
                }
                mmio.write32(0x38941c, 1);
                self.phase = 3;
                self.deadline = now.checked_add(5_000_000).ok_or(Error::Timeout)?;
                Poll::Pending
            }
            3 => {
                if read(mmio, 0x38941c)? & 1 != 0 {
                    return Poll::Pending;
                }
                let proof = MediaProof { gmd: self.gmd };
                proof.current(mmio)?;
                self.phase = 4;
                Poll::Ready(Ok(proof))
            }
            4 => {
                let proof = MediaProof { gmd: self.gmd };
                proof.current(mmio)?;
                Poll::Ready(Ok(proof))
            }
            _ => Poll::Ready(Err(Error::State)),
        }
    }
    /// Every arena mapping must be invalidated while the media wake is still
    /// held. GuCGt calls this only after scheduler/boot/CT resource retirement.
    pub(crate) fn release(&mut self, mmio: &impl MmioWindow, now: u64) -> Poll<Result<(), Error>> {
        if self.phase == 0 {
            return Poll::Ready(Ok(()));
        }
        if !self.releasing {
            MediaProof { gmd: self.gmd }.current(mmio)?;
            mmio.write32(0x38a188, 0x00010000);
            let _ = read(mmio, 0x38a188)?;
            self.deadline = now.checked_add(50_000_000).ok_or(Error::Timeout)?;
            self.releasing = true;
        }
        if read(mmio, 0x380dfc)? & 1 != 0 {
            // A sleep ACK that cleared before a late poll is success.
            return if now >= self.deadline {
                Poll::Ready(Err(Error::Timeout))
            } else {
                Poll::Pending
            };
        }
        self.phase = 0;
        Poll::Ready(Ok(()))
    }
}

/// Secondary guards in a *fresh completed full-display-reset incarnation*.
/// Retirement of inherited MainDMC/DSB producers comes from driver FLR's
/// documented whole-display reset; a powered-off read is never interpreted
/// as a disabled plane. This profile never initializes display or DMC.
fn post_flr_display(m: &impl MmioWindow, device: u16) -> Result<Option<u32>, Error> {
    if read(m, 0x10100c)? & (1 << 9) == 0 {
        return Ok(None);
    }
    let platform =
        crate::intel_gpu_gt::GtPlatform::from_pci(0x8086, device).ok_or(Error::Unsupported)?;
    let expected = if platform.is_ptl() {
        3000
    } else if platform.is_lnl() {
        2000
    } else if platform == crate::intel_gpu_gt::GtPlatform::Battlemage {
        1401
    } else {
        return Err(Error::Unsupported);
    };
    let a = read(m, 0x510a0)?;
    if a != read(m, 0x510a0)? || (a >> 22) * 100 + ((a >> 14) & 255) != expected {
        return Err(Error::Unsupported);
    }
    // Secondary refusal probes only: distribution or gated zeroes are not an
    // inactive proof. Inherited producer retirement comes from completed FLR.
    if read(m, 0x42000)? & 0x0c000000 != 0x0c000000 {
        return Err(Error::Unavailable);
    }
    if read(m, 0x45504)? != 0 || read(m, 0x45250)? & 0x1111 != 0 {
        return Err(Error::Busy);
    }
    let mask = (3 << 2) | (3 << 10) | (3 << 12) | (3 << 14) | (3 << 16);
    // PW2 and pipe A-D wells must remain off, including other agents' refs.
    // Display30.00 changes PGB's parent toPG1 (power_map.c:1596ff),
    // but keeps these exact request/state indices. No well is enabled here.
    for reg in [0x45400, 0x45404, 0x45408, 0x4540c] {
        if read(m, reg)? & mask != 0 {
            return Err(Error::Busy);
        }
    }
    if read(m, 0x70008)? & 0xc0000000 != 0 {
        return Err(Error::Busy);
    }
    let fbc_count = if platform == crate::intel_gpu_gt::GtPlatform::Battlemage {
        2
    } else {
        4
    };
    for id in 0..fbc_count {
        if read(m, 0x43208 + id * 0x40)? & 0x80000000 != 0 {
            return Err(Error::Busy);
        }
    }
    Ok(Some(a))
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec::Vec};
    use core::cell::{Cell, RefCell};
    use narf_kernel_test::{kernel_test_in, TestResult};
    struct Registers {
        regs: RefCell<BTreeMap<u64, u32>>,
        writes: RefCell<Vec<(u64, u32)>>,
        sticky: Cell<bool>,
    }
    impl Registers {
        fn new() -> Self {
            Self {
                regs: RefCell::new(BTreeMap::new()),
                writes: RefCell::new(Vec::new()),
                sticky: Cell::new(false),
            }
        }
        fn set(&self, r: u64, v: u32) {
            self.regs.borrow_mut().insert(r, v);
        }
    }
    impl MmioWindow for Registers {
        fn read32(&self, r: u64) -> u32 {
            *self.regs.borrow().get(&r).unwrap_or(&0)
        }
        fn write32(&self, r: u64, v: u32) {
            self.writes.borrow_mut().push((r, v));
            if r == 0x380d8c {
                return;
            }
            if r == 0x101018 {
                if !self.sticky.get() {
                    let old = self.read32(r);
                    self.set(r, old & !v);
                }
            } else {
                let old = self.read32(r);
                self.set(
                    r,
                    if r == 0x38a188 {
                        (old & !(v >> 16)) | (v & (v >> 16))
                    } else {
                        v
                    },
                );
            }
        }
    }
    fn identity() -> (narf_bus::BusDevice, narf_bus::bar::MmioRegion) {
        let addr = narf_bus::PcieAddr::new(0, 0, 2, 0);
        let d = narf_bus::BusDevice {
            addr: narf_bus::BusAddr::Pcie(addr),
            id: narf_bus::DeviceId {
                vendor: 0x8086,
                device: 0x6420,
                class: 0x030000,
                subsystem_vendor: 0,
                subsystem_id: 0,
            },
            kind: narf_bus::BusKind::Pcie {
                addr,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        };
        let b = narf_bus::bar::MmioRegion {
            phys: narf_memory::PhysAddr::new(0x10000000),
            virt: 0,
            len: 16 << 20,
            kind: narf_bus::bar::BarKind::Mmio64 {
                prefetchable: false,
            },
        };
        (d, b)
    }
    fn smoke_lnl_driver_flr_fresh_ack_exclusions_and_media_63_pte() -> TestResult {
        use narf_graphics::console::BootFramebufferAdmission as Admission;
        // Local production gates only; never seal the real globals in tests.
        let mut registered = Admission::new();
        assert!(registered.publish());
        assert!(!registered.close_if_never(true));
        let mut paused = Admission::new();
        assert!(!paused.close_if_never(false));
        assert!(paused.publish());
        assert!(!paused.close_if_never(true));
        let mut closed = Admission::new();
        assert!(closed.close_if_never(true));
        assert!(!closed.publish());
        assert!(closed.close_if_never(false));

        // Actual production arena stages no PTE and rejects a cache proof
        // without the consumed FLR receipt, even when an adapter supplies PAT.
        {
            use crate::intel_gpu_rcs::{GgttArena, GpuAllocator, SharedArena};
            let mut mmio = alloc::vec![0u32;4*1024*1024];
            let (_, mut bar) = identity();
            bar.virt = mmio.as_mut_ptr() as u64;
            let cap=narf_capabilities::Cap::<narf_bus::BusDeviceCap,narf_capabilities::Write>::bootstrap();
            let platform = crate::intel_gpu_gt::GtPlatform::Integrated(
                crate::intel_gpu::Generation::LunarLake,
            );
            let mut arena = SharedArena::new(GgttArena::for_gt(bar, cap, platform));
            let mut backing = arena.alloc(1).unwrap();
            assert!(!crate::intel_gpu_guc_boot::BootAllocator::lnl_takeover_ready(&arena));
            let policy = crate::intel_gpu_gt_hw::CachePolicy {
                platform,
                ggtt_pat: 2,
                media: Some(MediaProof { gmd: 20 << 22 }),
            };
            assert!(arena.configure_cache(&mut backing, policy).is_err());
            assert!(mmio[0x800000 / 4..].iter().all(|v| *v == 0));
            arena.free(backing);
            assert_eq!(arena.live_allocations(), 0);
        }
        let platform =
            crate::intel_gpu_gt::GtPlatform::Integrated(crate::intel_gpu::Generation::LunarLake);
        for id in [0x6420, 0x64a0, 0x64b0] {
            assert_eq!(
                crate::intel_gpu_gt::GtPlatform::from_pci(0x8086, id),
                Some(platform)
            );
            let p = platform.guc().unwrap();
            assert_eq!(
                (p.firmware, p.minimum_version),
                ("xe/lnl_guc_70.bin", (70, 53, 0))
            );
            assert_eq!(
                (
                    platform.physical_bits(),
                    platform.ppgtt_root_level(),
                    platform.guc_forcewake_ack()
                ),
                (46, 4, Some(0xdfc))
            );
        }
        assert!(!crate::intel_gpu::Generation::LunarLake.display_supported());
        assert!(!crate::intel_gpu::Generation::LunarLake.external_display_supported());
        assert!(!crate::intel_gpu::Generation::LunarLake.backlight_supported());
        assert!(crate::intel_gpu::Generation::LunarLake
            .region_generation()
            .is_none());
        assert!(crate::intel_gpu_gt::GtPlatform::from_pci(0x8086, 0xfd80).is_none());
        let (device, bar) = identity();
        for (reg, value) in [(0x10100c, 0x80000000), (0x1901f8, 1)] {
            let m = Registers::new();
            m.set(reg, value);
            let mut f = DriverFlr::new(device, bar, 0).unwrap();
            assert!(matches!(
                f.poll(&m, 0, || true),
                Poll::Ready(Err(Error::Unsupported))
            ));
            assert!(m.writes.borrow().is_empty());
        }
        let m = Registers::new();
        m.set(0x101018, 0x80000000);
        m.sticky.set(true);
        let mut f = DriverFlr::new(device, bar, 0).unwrap();
        assert!(matches!(
            f.poll(&m, 0, || true),
            Poll::Ready(Err(Error::State))
        ));
        assert_eq!(*m.writes.borrow(), [(0x101018, 0x80000000)]);
        let m = Registers::new();
        m.set(0x101010, 0x80000000);
        let mut f = DriverFlr::new(device, bar, 0).unwrap();
        assert!(f.poll(&m, 1, || true).is_pending());
        assert!(matches!(
            f.poll(&m, 3_000_000_000, || true),
            Poll::Ready(Err(Error::Timeout))
        ));
        assert!(m.writes.borrow().is_empty());
        let m = Registers::new();
        let mut f = DriverFlr::new(device, bar, 0).unwrap();
        assert!(matches!(
            f.poll(&m, 0, || false),
            Poll::Ready(Err(Error::Unavailable))
        ));
        assert!(m.writes.borrow().is_empty());
        let m = Registers::new();
        m.set(0x101018, 0x80000000);
        let mut f = DriverFlr::new(device, bar, 0).unwrap();
        assert!(f.poll(&m, 0, || true).is_pending());
        m.set(0x101010, 0);
        assert!(f.poll(&m, 1, || true).is_pending());
        assert!(f.poll(&m, 2, || true).is_pending());
        m.set(0x101018, 0x80000000);
        let Poll::Ready(Ok(receipt)) = f.poll(&m, 3, || true) else {
            panic!("fresh ACK")
        };
        assert!(receipt.matches(device, bar, &m));
        let mut wrong = device;
        wrong.addr = narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(0, 0, 3, 0));
        assert!(!receipt.matches(wrong, bar, &m));
        let mut wrong_bar = bar;
        wrong_bar.len /= 2;
        assert!(!receipt.matches(device, wrong_bar, &m));
        assert!(matches!(
            f.poll(&m, 4, || true),
            Poll::Ready(Err(Error::State))
        ));
        // Post-reset active display DC state refuses the proof despite ACK.
        let m = Registers::new();
        m.set(0x10100c, 1 << 9);
        m.set(0x510a0, 20 << 22);
        m.set(0x42000, 0x0c000000);
        m.set(0x45504, 1);
        let mut f = DriverFlr::new(device, bar, 0).unwrap();
        assert!(f.poll(&m, 0, || true).is_pending());
        m.set(0x101010, 0);
        assert!(f.poll(&m, 1, || true).is_pending());
        m.set(0x101018, 0x80000000);
        assert!(matches!(
            f.poll(&m, 2, || true),
            Poll::Ready(Err(Error::Busy))
        ));
        let m = Registers::new();
        m.set(0x380d8c, 20 << 22);
        let mut media = MediaQuiesce::new();
        assert!(media.poll(&m, 0).is_pending());
        assert!(media.poll(&m, 1).is_pending());
        m.set(0x380dfc, 1);
        assert!(media.poll(&m, 2).is_pending());
        m.set(0x38941c, 0);
        m.set(0x38c000, 1);
        m.set(0x38c314, 1);
        assert!(media.poll(&m, 3).is_pending());
        m.set(0x38c314, 0);
        assert!(media.poll(&m, 4).is_pending());
        m.set(0x38941c, 0);
        let Poll::Ready(Ok(proof)) = media.poll(&m, 5) else {
            panic!("full media retirement")
        };
        assert!(matches!(media.poll(&m, 10_000_000), Poll::Ready(Ok(_))));
        let count = Cell::new(0);
        for _ in 0..125 {
            proof.after_pte(&m, &count).unwrap();
        }
        assert_eq!(count.get(), 62);
        assert_eq!(
            m.writes
                .borrow()
                .iter()
                .filter(|(r, _)| *r == 0x380d8c)
                .count(),
            1
        );
        proof.after_pte(&m, &count).unwrap();
        assert_eq!(count.get(), 0);
        assert_eq!(
            m.writes
                .borrow()
                .iter()
                .filter(|(r, _)| *r == 0x380d8c)
                .count(),
            2
        );
        m.set(0x38c314, 1);
        assert!(proof.after_pte(&m, &count).is_err());
        assert_eq!(count.get(), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_lnl_driver_flr_fresh_ack_exclusions_and_media_63_pte
    );
    fn smoke_lnl_flr_and_media_late_polls_after_settled_condition() -> TestResult {
        // __xe_driver_flr's and __domain_wait's xe_mmio_wait32 read once
        // more after the timeout: a condition met before a poll delayed past
        // the bound is progress, never Timeout.
        let (device, bar) = identity();
        let m = Registers::new();
        let mut f = DriverFlr::new(device, bar, 0).unwrap();
        assert!(f.poll(&m, 0, || true).is_pending());
        m.set(0x101010, 0); // teardown done before a poll past the 3 s bound
        assert!(f.poll(&m, 3_000_000_005, || true).is_pending());
        assert!(f.poll(&m, 3_000_000_006, || true).is_pending());
        m.set(0x101018, 0x80000000); // re-init done before another late poll
        assert!(matches!(
            f.poll(&m, 6_000_000_010, || true),
            Poll::Ready(Ok(_))
        ));
        let m = Registers::new();
        m.set(0x380d8c, 20 << 22);
        let mut media = MediaQuiesce::new();
        assert!(media.poll(&m, 0).is_pending());
        m.set(0x380dfc, 1); // media wake ACK, past its 50 ms bound
        let mut now = 50_000_005;
        assert!(media.poll(&m, now).is_pending());
        assert_eq!(m.read32(0x38941c), 8);
        m.set(0x38941c, 0);
        m.set(0x38c000, 1);
        now += 5_000_005; // GRDOM_GUC, GuC reset and DMA idle, past 5 ms
        assert!(media.poll(&m, now).is_pending());
        assert_eq!(m.read32(0x38941c), 1);
        m.set(0x38941c, 0);
        now += 5_000_005; // GRDOM_FULL, past 5 ms
        assert!(matches!(media.poll(&m, now), Poll::Ready(Ok(_))));
        now += 1;
        assert!(media.release(&m, now).is_pending());
        m.set(0x380dfc, 0); // sleep ACK, past its 50 ms bound
        assert_eq!(media.release(&m, now + 50_000_005), Poll::Ready(Ok(())));
        // An ACK that never clears still fails at the same bound.
        let m = Registers::new();
        m.set(0x380d8c, 20 << 22);
        let mut media = MediaQuiesce::new();
        assert!(media.poll(&m, 0).is_pending());
        assert!(media.poll(&m, 49_999_999).is_pending());
        assert!(matches!(
            media.poll(&m, 50_000_000),
            Poll::Ready(Err(Error::Timeout))
        ));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_lnl_flr_and_media_late_polls_after_settled_condition
    );
    fn smoke_ptl_driver_flr_profiles_media_steps_and_first_pte_refusal() -> TestResult {
        use narf_graphics::console::BootFramebufferAdmission as Admission;
        // Local production gates only; never seal the real globals in tests.
        let mut registered = Admission::new();
        assert!(registered.publish());
        assert!(!registered.close_if_never(true));
        let mut paused = Admission::new();
        assert!(!paused.close_if_never(false));
        assert!(paused.publish());
        assert!(!paused.close_if_never(true));
        let mut closed = Admission::new();
        assert!(closed.close_if_never(true));
        assert!(!closed.publish());
        assert!(closed.close_if_never(false));

        // Actual production arena stages no PTE and rejects a cache proof
        // without the consumed FLR receipt, even when an adapter supplies PAT.
        {
            use crate::intel_gpu_rcs::{GgttArena, GpuAllocator, SharedArena};
            let mut mmio = alloc::vec![0u32;4*1024*1024];
            let (_, mut bar) = identity();
            bar.virt = mmio.as_mut_ptr() as u64;
            let cap=narf_capabilities::Cap::<narf_bus::BusDeviceCap,narf_capabilities::Write>::bootstrap();
            let platform = crate::intel_gpu_gt::GtPlatform::Integrated(
                crate::intel_gpu::Generation::PantherLake,
            );
            let mut arena = SharedArena::new(GgttArena::for_gt(bar, cap, platform));
            let mut backing = arena.alloc(1).unwrap();
            assert!(!crate::intel_gpu_guc_boot::BootAllocator::lnl_takeover_ready(&arena));
            let policy = crate::intel_gpu_gt_hw::CachePolicy {
                platform,
                ggtt_pat: 2,
                media: Some(MediaProof { gmd: 30 << 22 }),
            };
            assert!(arena.configure_cache(&mut backing, policy).is_err());
            assert!(mmio[0x800000 / 4..].iter().all(|v| *v == 0));
            arena.free(backing);
            assert_eq!(arena.live_allocations(), 0);
        }
        let platform =
            crate::intel_gpu_gt::GtPlatform::Integrated(crate::intel_gpu::Generation::PantherLake);
        for id in [
            0xb080, 0xb081, 0xb082, 0xb083, 0xb084, 0xb085, 0xb086, 0xb087, 0xb08f, 0xb090, 0xb0a0,
            0xb0b0,
        ] {
            assert_eq!(
                crate::intel_gpu_gt::GtPlatform::from_pci(0x8086, id),
                Some(platform)
            );
            let p = platform.guc().unwrap();
            assert_eq!(
                (p.firmware, p.minimum_version),
                ("xe/ptl_guc_70.bin", (70, 54, 0))
            );
            assert_eq!(
                (
                    platform.physical_bits(),
                    platform.ppgtt_root_level(),
                    platform.guc_forcewake_ack()
                ),
                (46, 4, Some(0xdfc))
            );
        }
        assert!(!crate::intel_gpu::Generation::PantherLake.display_supported());
        assert!(!crate::intel_gpu::Generation::PantherLake.external_display_supported());
        assert!(!crate::intel_gpu::Generation::PantherLake.backlight_supported());
        assert!(crate::intel_gpu::Generation::PantherLake
            .region_generation()
            .is_none());
        assert!(crate::intel_gpu_gt::GtPlatform::from_pci(0x8086, 0xfd80).is_none());
        let (mut device, bar) = identity();
        device.id.device = 0xb080;
        for (reg, value) in [(0x10100c, 0x80000000), (0x1901f8, 1)] {
            let m = Registers::new();
            m.set(reg, value);
            let mut f = DriverFlr::new(device, bar, 0).unwrap();
            assert!(matches!(
                f.poll(&m, 0, || true),
                Poll::Ready(Err(Error::Unsupported))
            ));
            assert!(m.writes.borrow().is_empty());
        }
        let m = Registers::new();
        m.set(0x101018, 0x80000000);
        m.sticky.set(true);
        let mut f = DriverFlr::new(device, bar, 0).unwrap();
        assert!(matches!(
            f.poll(&m, 0, || true),
            Poll::Ready(Err(Error::State))
        ));
        assert_eq!(*m.writes.borrow(), [(0x101018, 0x80000000)]);
        let m = Registers::new();
        m.set(0x101010, 0x80000000);
        let mut f = DriverFlr::new(device, bar, 0).unwrap();
        assert!(f.poll(&m, 1, || true).is_pending());
        assert!(matches!(
            f.poll(&m, 3_000_000_000, || true),
            Poll::Ready(Err(Error::Timeout))
        ));
        assert!(m.writes.borrow().is_empty());
        let m = Registers::new();
        let mut f = DriverFlr::new(device, bar, 0).unwrap();
        assert!(matches!(
            f.poll(&m, 0, || false),
            Poll::Ready(Err(Error::Unavailable))
        ));
        assert!(m.writes.borrow().is_empty());
        let m = Registers::new();
        m.set(0x101018, 0x80000000);
        let mut f = DriverFlr::new(device, bar, 0).unwrap();
        assert!(f.poll(&m, 0, || true).is_pending());
        m.set(0x101010, 0);
        assert!(f.poll(&m, 1, || true).is_pending());
        assert!(f.poll(&m, 2, || true).is_pending());
        m.set(0x101018, 0x80000000);
        let Poll::Ready(Ok(receipt)) = f.poll(&m, 3, || true) else {
            panic!("fresh ACK")
        };
        assert!(receipt.matches(device, bar, &m));
        let mut wrong = device;
        wrong.addr = narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(0, 0, 3, 0));
        assert!(!receipt.matches(wrong, bar, &m));
        let mut wrong_bar = bar;
        wrong_bar.len /= 2;
        assert!(!receipt.matches(device, wrong_bar, &m));
        assert!(matches!(
            f.poll(&m, 4, || true),
            Poll::Ready(Err(Error::State))
        ));
        // Post-reset active display DC state refuses the proof despite ACK.
        let m = Registers::new();
        m.set(0x10100c, 1 << 9);
        m.set(0x510a0, 30 << 22);
        m.set(0x42000, 0x0c000000);
        m.set(0x45504, 1);
        let mut f = DriverFlr::new(device, bar, 0).unwrap();
        assert!(f.poll(&m, 0, || true).is_pending());
        m.set(0x101010, 0);
        assert!(f.poll(&m, 1, || true).is_pending());
        m.set(0x101018, 0x80000000);
        assert!(matches!(
            f.poll(&m, 2, || true),
            Poll::Ready(Err(Error::Busy))
        ));
        let m = Registers::new();
        m.set(0x380d8c, 30 << 22);
        let mut media = MediaQuiesce::for_platform(platform);
        assert!(media.poll(&m, 0).is_pending());
        assert!(media.poll(&m, 1).is_pending());
        m.set(0x380dfc, 1);
        assert!(media.poll(&m, 2).is_pending());
        m.set(0x38941c, 0);
        m.set(0x38c000, 1);
        m.set(0x38c314, 1);
        assert!(media.poll(&m, 3).is_pending());
        m.set(0x38c314, 0);
        assert!(media.poll(&m, 4).is_pending());
        m.set(0x38941c, 0);
        let Poll::Ready(Ok(proof)) = media.poll(&m, 5) else {
            panic!("full media retirement")
        };
        assert!(matches!(media.poll(&m, 10_000_000), Poll::Ready(Ok(_))));
        let count = Cell::new(0);
        for _ in 0..125 {
            proof.after_pte(&m, &count).unwrap();
        }
        assert_eq!(count.get(), 62);
        assert_eq!(
            m.writes
                .borrow()
                .iter()
                .filter(|(r, _)| *r == 0x380d8c)
                .count(),
            1
        );
        proof.after_pte(&m, &count).unwrap();
        assert_eq!(count.get(), 0);
        assert_eq!(
            m.writes
                .borrow()
                .iter()
                .filter(|(r, _)| *r == 0x380d8c)
                .count(),
            2
        );
        // Media30.00 B0 does not receive Wa22019338487's dummy GMD write.
        m.set(0x380d8c, 30 << 22 | 4);
        let b0 = MediaProof { gmd: 30 << 22 | 4 };
        for _ in 0..126 {
            b0.after_pte(&m, &count).unwrap();
        }
        assert_eq!(
            m.writes
                .borrow()
                .iter()
                .filter(|(r, _)| *r == 0x380d8c)
                .count(),
            2
        );
        m.set(0x380d8c, 30 << 22);
        m.set(0x38c314, 1);
        assert!(proof.after_pte(&m, &count).is_err());
        assert_eq!(count.get(), 0);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gt",
        smoke_ptl_driver_flr_profiles_media_steps_and_first_pte_refusal
    );
}
