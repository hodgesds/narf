//! Presentation of the lit Navi22 pipe: the back buffer, VSYNC page flips,
//! the scanout position behind DRM vblanks, the hardware cursor and the
//! pflip/vupdate interrupts, on top of the pipeline that activated the pipe
//! (`amdgpu_navi22_modeset`). The pipeline's activation surface is buffer 0;
//! this owner reserves buffer 1 with the same geometry. A flip HDP-flushes
//! the producer's writes, arms the back buffer (`amdgpu_dcn30_flip`) and
//! completes when SURFACE_EARLIEST_INUSE names it, which is also when the
//! previous front stops being fetched and becomes the back buffer.
//!
//! Failure is terminal for presentation: a flip that did not latch in time
//! leaves which buffer is fetched unknown, so the owner enters `Failed`, both
//! surfaces stay reserved and only teardown is allowed. Nothing is retried.
use crate::{
    amdgpu::AmdGpu,
    amdgpu_dcn30_cursor::{self as cursor, Cursor},
    amdgpu_dcn30_flip::{Flip, Interrupt, Position},
    amdgpu_dcn_clk::Error,
    amdgpu_dml::Timing,
    amdgpu_vram::{Pool, Reservation},
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Write};
use narf_graphics_driver::generic::GenericFb;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Running,
    /// A flip is armed and not yet latched (cancellation leaves this).
    Flipping,
    Failed(Error),
    Stopped,
}

/// A completed flip: the new front and the previous one, now the back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlipDone {
    pub front: u64,
    pub back: u64,
    pub frame: u32,
}

/// One scanout buffer: its GPU address and CPU view.
#[derive(Clone, Copy, Debug)]
pub struct Surface {
    pub address: u64,
    pub fb: GenericFb,
}

/// Which of the two buffers is shown; pure bookkeeping, tested alone.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Buffers {
    pub(crate) surfaces: [Option<Surface>; 2],
    pub(crate) front: usize,
}
impl Buffers {
    pub(crate) fn new(front: Surface) -> Self {
        Self {
            surfaces: [Some(front), None],
            front: 0,
        }
    }
    pub(crate) fn front(&self) -> Surface {
        self.surfaces[self.front].expect("the front always exists")
    }
    pub(crate) fn back(&self) -> Option<Surface> {
        self.surfaces[1 - self.front]
    }
    /// The flip to the back buffer latched: roles swap.
    pub(crate) fn swap(&mut self) -> Result<(), Error> {
        self.back().ok_or(Error::Invalid)?;
        self.front = 1 - self.front;
        Ok(())
    }
}

/// The flip deadline for a timing: four frames plus 20 ms of slack, at least
/// 50 ms (a VSYNC flip latches at the next VUPDATE, within one frame).
pub fn flip_timeout_us(timing: &Timing) -> u64 {
    let frame_us = (u64::from(timing.h_total) * u64::from(timing.v_total) * 1000)
        .checked_div(u64::from(timing.pixel_clock_khz))
        .unwrap_or(0);
    (4 * frame_us + 20_000).max(50_000)
}

/// The vblank clock for a position read, in DRM's terms (see
/// `amdgpu_dcn401_otg::ScanoutPosition::phase`: same OTG semantics).
pub fn vblank_phase(p: Position, timing: &Timing) -> Option<crate::amdgpu_dcn401_otg::VblankPhase> {
    crate::amdgpu_dcn401_otg::ScanoutPosition {
        frame: p.frame,
        vpos: p.vpos,
        hpos: p.hpos,
        vblank_start: p.vblank_start,
        vblank_end: p.vblank_end,
        timing: *timing,
    }
    .phase()
}

/// The pflip and vupdate subscriptions of the pipe.
struct Irq {
    flip: Option<crate::amdgpu_ih_navi22::Subscription>,
    vupdate: Option<crate::amdgpu_ih_navi22::Subscription>,
}

/// Presentation owner of one lit pipe.
pub struct Scanout {
    flip: Flip,
    cursor: Cursor,
    timing: Timing,
    refclk_khz: u32,
    buffers: Buffers,
    /// CPU mappings, indexed like `buffers.surfaces`.
    maps: [Option<narf_bus::MmioRegion>; 2],
    back: Option<Reservation>,
    cursor_image: Option<(Reservation, u64)>,
    irq: Irq,
    state: State,
    flips: u64,
    vrr: Option<crate::amdgpu_freesync::Drr>,
}
impl core::fmt::Debug for Scanout {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Scanout")
            .field("pipe", &self.flip.pipe())
            .field("state", &self.state)
            .field("buffers", &self.buffers)
            .field("cursor", &self.cursor.shown())
            .field("flips", &self.flips)
            .finish_non_exhaustive()
    }
}

impl Scanout {
    /// Adopt the activation surface `front` (mapped by `map`) of a running
    /// pipe.
    ///
    /// # Safety
    /// The caller's pipeline lit `pipe` with `front` (`address` is what its
    /// HUBP was programmed with), keeps it reserved for this owner's
    /// lifetime and serializes every access to the pipe's HUBP/DPP/OTG/MPC
    /// registers with this owner; permanent mappings and PCI authority.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        pipe: u8,
        front: Surface,
        map: narf_bus::MmioRegion,
        timing: Timing,
        refclk_khz: u32,
    ) -> Result<Self, Error> {
        // SAFETY: forwarded pipe ownership.
        let mut flip = unsafe { Flip::new(gpu, authority, pipe) }?;
        flip.adopt(front.address);
        Ok(Self {
            flip,
            // SAFETY: as above.
            cursor: unsafe { Cursor::new(gpu, authority, pipe) }?,
            timing,
            refclk_khz,
            buffers: Buffers::new(front),
            maps: [Some(map), None],
            back: None,
            cursor_image: None,
            irq: Irq {
                flip: None,
                vupdate: None,
            },
            state: State::Running,
            flips: 0,
            vrr: None,
        })
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn timing(&self) -> Timing {
        self.timing
    }
    pub fn flips(&self) -> u64 {
        self.flips
    }
    pub fn front(&self) -> Surface {
        self.buffers.front()
    }
    pub fn back(&self) -> Option<Surface> {
        self.buffers.back()
    }
    pub fn cursor(&self) -> Option<cursor::Shown> {
        self.cursor.shown()
    }
    fn running(&self) -> Result<(), Error> {
        match self.state {
            State::Running => Ok(()),
            _ => Err(Error::Busy),
        }
    }

    /// Subscribe to the pipe's pflip and vupdate sources, then enable them
    /// in HUBP/OTG (`dm_pflip_high_irq`/`dm_vupdate_high_irq` sources of
    /// `amdgpu_dm`, enabled as `dal_irq_service_set`). Subscribing first
    /// means no raised vector is unrouted. Polling still decides every
    /// completion; the vectors only shorten the wait.
    pub fn enable_interrupts(
        &mut self,
        ih: &crate::amdgpu_ih_navi22::Handle,
    ) -> Result<(), crate::amdgpu_ih_navi22::Error> {
        use crate::amdgpu_ih_navi22::{source, Error as IhError};
        let pipe = self.flip.pipe();
        let flip = ih.subscribe(source::pflip(pipe).ok_or(IhError::Invalid)?)?;
        let vupdate = ih.subscribe(source::vupdate(pipe).ok_or(IhError::Invalid)?)?;
        for which in [Interrupt::Flip, Interrupt::Vupdate] {
            // Acknowledge anything stale before enabling.
            let _ = self.flip.ack(which);
            self.flip
                .set_interrupt(which, true)
                .map_err(|_| IhError::DeviceGone)?;
        }
        self.irq = Irq {
            flip: Some(flip),
            vupdate: Some(vupdate),
        };
        Ok(())
    }
    /// Mask both sources again, then drop the subscriptions.
    fn disable_interrupts(&mut self) {
        for which in [Interrupt::Flip, Interrupt::Vupdate] {
            let _ = self.flip.set_interrupt(which, false);
            let _ = self.flip.ack(which);
        }
        self.irq = Irq {
            flip: None,
            vupdate: None,
        };
    }
    pub fn interrupts_enabled(&self) -> bool {
        self.irq.flip.is_some()
    }

    /// Reserve, clear and publish the back buffer (once). Touches no display
    /// register; `flush` is the pipeline's HDP flush.
    pub async fn prepare_back(
        &mut self,
        pool: &Pool,
        mut flush: impl FnMut() -> Result<(), Error>,
    ) -> Result<Surface, Error> {
        self.running()?;
        if let Some(back) = self.buffers.back() {
            return Ok(back);
        }
        let front = self.buffers.front();
        let bytes = u64::from(front.fb.pitch) * u64::from(front.fb.height);
        let mut memory = pool.reserve(bytes).map_err(|_| Error::Allocation)?;
        let map = memory.mapping();
        for start in (0..bytes).step_by(65536) {
            // linux: n/a (NARF clear chunk)
            let end = (start + 65536).min(bytes);
            for offset in (start..end).step_by(4) {
                // SAFETY: an owned, unpublished reservation's mapping.
                unsafe { map.write32(offset, 0) };
            }
            if end < bytes {
                narf_scheduler::yield_now().await;
            }
        }
        flush()?;
        memory.publish();
        let back = Surface {
            address: memory.address(),
            fb: GenericFb {
                addr: map.phys.raw(),
                ..front.fb
            },
        };
        self.back = Some(memory);
        self.buffers.surfaces[1] = Some(back);
        self.maps[1] = Some(map);
        Ok(back)
    }
    /// Write part of one row of the next frame into the back buffer, which
    /// no fetch reads while the pipe runs and no flip is armed.
    pub fn upload_back(&mut self, x: u32, y: u32, pixels: &[u32]) -> Result<(), Error> {
        self.running()?;
        let back = self.buffers.back().ok_or(Error::Invalid)?;
        let count = u32::try_from(pixels.len()).map_err(|_| Error::Invalid)?;
        if count == 0
            || y >= back.fb.height
            || x.checked_add(count).is_none_or(|end| end > back.fb.width)
        {
            return Err(Error::Invalid);
        }
        let map = self.maps[1 - self.buffers.front].ok_or(Error::Invalid)?;
        let start = u64::from(y) * u64::from(back.fb.pitch) + u64::from(x) * 4;
        if start + u64::from(count) * 4 > map.len {
            return Err(Error::Invalid);
        }
        for (i, &pixel) in pixels.iter().enumerate() {
            // SAFETY: bounds checked against the back buffer's mapping,
            // which no fetch reads until the next flip.
            unsafe { map.write32(start + i as u64 * 4, pixel) };
        }
        Ok(())
    }

    /// The OTG owner has committed these bounds while holding the same
    /// platform lock. Flip waits account for the longest admitted frame.
    pub fn configure_vrr(
        &mut self,
        bounds: Option<crate::amdgpu_freesync::Drr>,
    ) -> Result<(), Error> {
        self.running()?;
        if bounds.is_some_and(|b| {
            b.v_total_min < self.timing.v_total
                || b.v_total_min > b.v_total_max
                || b.v_total_max > crate::amdgpu_freesync::MAX_V_TOTAL
        }) {
            return Err(Error::Invalid);
        }
        self.vrr = bounds;
        Ok(())
    }
    /// Present the back buffer at the next VUPDATE and wait (bounded) until
    /// the HUBP reports it the earliest surface in use. On success the old
    /// front becomes the back buffer. On timeout or device loss the owner
    /// fails: both buffers stay reserved.
    pub async fn flip(
        &mut self,
        mut flush: impl FnMut() -> Result<(), Error>,
    ) -> Result<FlipDone, Error> {
        self.running()?;
        let back = self.buffers.back().ok_or(Error::Invalid)?;
        let front = self.buffers.front();
        // The producer's CPU writes must reach VRAM before the latch.
        flush()?;
        self.flip.program(back.address)?;
        self.state = State::Flipping;
        if self.vrr.is_some() {
            if let Err(error) = self.flip.manual_trigger() {
                self.state = State::Failed(error);
                return Err(error);
            }
        }
        let result = self.wait_latched().await;
        match result {
            Ok(()) => {
                self.buffers.swap()?;
                self.state = State::Running;
                self.flips += 1;
                let frame = self.flip.position().map(|p| p.frame).unwrap_or(0);
                Ok(FlipDone {
                    front: back.address,
                    back: front.address,
                    frame,
                })
            }
            Err(error) => {
                self.state = State::Failed(error);
                Err(error)
            }
        }
    }
    /// `hubp2_is_flip_pending` until clear, woken by pflip/vupdate vectors
    /// (each acknowledged as `dal_irq_service_ack`) or the poll period.
    async fn wait_latched(&mut self) -> Result<(), Error> {
        use crate::amdgpu_dcn30_flip::POLL_US;
        let mut longest = self.timing;
        if let Some(bounds) = self.vrr {
            longest.v_total = bounds.v_total_max;
        }
        let deadline = narf_time::Deadline::after_us(flip_timeout_us(&longest));
        loop {
            if !self.flip.pending()? {
                let _ = self.flip.ack(Interrupt::Flip);
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            let poll = narf_time::Deadline::after_us(POLL_US);
            match self.irq.flip.as_mut() {
                Some(sub) => match narf_time::timeout(poll, sub.wait()).await {
                    Ok(Ok(_)) => {
                        self.flip.ack(Interrupt::Flip)?;
                    }
                    // A closed endpoint (IH disabled) falls back to polling.
                    Ok(Err(_)) => self.irq.flip = None,
                    Err(_) => {}
                },
                None => narf_time::SleepUntil::new(poll.as_instant()).await,
            }
            // Drain VUPDATE so the mailbox and the latch stay current.
            if let Some(sub) = self.irq.vupdate.as_mut() {
                match sub.try_next() {
                    Ok(Some(_)) => {
                        self.flip.ack(Interrupt::Vupdate)?;
                    }
                    Ok(None) => {}
                    Err(_) => self.irq.vupdate = None,
                }
            }
        }
    }
    pub fn vrr_active(&self) -> bool {
        self.vrr.is_some()
    }
    /// A stretched blank can exceed the nominal total. Use the last
    /// completed hardware total, bounded by the admitted range, and never
    /// reject an in-range live beam just because the nominal frame ended.
    pub fn vblank_phase(&mut self) -> Result<crate::amdgpu_dcn401_otg::VblankPhase, Error> {
        if matches!(self.state, State::Stopped) {
            return Err(Error::Busy);
        }
        let Some(bounds) = self.vrr else {
            return vblank_phase(self.position()?, &self.timing).ok_or(Error::Invalid);
        };
        let (position, total) = self.flip.position_drr()?;
        if position.vpos >= bounds.v_total_max {
            return Err(Error::Invalid);
        }
        let mut timing = self.timing;
        timing.v_total = total
            .max(bounds.v_total_min)
            .max(position.vpos + 1)
            .min(bounds.v_total_max);
        vblank_phase(position, &timing).ok_or(Error::Invalid)
    }
    /// The OTG position, for vblank counts and timestamps.
    pub fn position(&mut self) -> Result<Position, Error> {
        if matches!(self.state, State::Stopped) {
            return Err(Error::Busy);
        }
        self.flip.position()
    }

    /// Show a premultiplied ARGB8888 image of at most 256x256 at `at` (the
    /// image's top-left, may be negative). The image is uploaded once into
    /// an owned 256x256 surface; an identical image only moves.
    pub fn set_cursor(
        &mut self,
        pool: &Pool,
        (width, height, pixels): (u32, u32, &[u32]),
        at: (i32, i32),
        mut flush: impl FnMut() -> Result<(), Error>,
    ) -> Result<cursor::Shown, Error> {
        self.running()?;
        if !(1..=cursor::CURSOR_MAX).contains(&width)
            || !(1..=cursor::CURSOR_MAX).contains(&height)
            || pixels.len() != (width * height) as usize
        {
            return Err(Error::Invalid);
        }
        let digest = image_digest(width, height, pixels);
        let fresh = self.cursor_image.as_ref().is_none_or(|(_, d)| *d != digest);
        if self.cursor_image.is_none() {
            let bytes = u64::from(cursor::PITCH) * u64::from(cursor::CURSOR_MAX) * 4;
            let mut memory = pool.reserve(bytes).map_err(|_| Error::Allocation)?;
            memory.publish();
            self.cursor_image = Some((memory, 0));
        }
        let (memory, stored) = self.cursor_image.as_mut().ok_or(Error::Invalid)?;
        let address = memory.address();
        if fresh {
            let map = memory.mapping();
            for y in 0..cursor::CURSOR_MAX {
                for x in 0..cursor::PITCH {
                    let pixel = if x < width && y < height {
                        pixels[(y * width + x) as usize]
                    } else {
                        0
                    };
                    // SAFETY: inside the owned 256x256 cursor surface.
                    unsafe { map.write32(u64::from(y * cursor::PITCH + x) * 4, pixel) };
                }
            }
            flush()?;
            *stored = digest;
        }
        let view = (self.timing.h_active, self.timing.v_active);
        let clocks = (self.refclk_khz, self.timing.pixel_clock_khz);
        match self.cursor.shown() {
            Some(s) if !fresh && (s.width, s.height) == (width, height) => {
                self.cursor.move_to(at, view, clocks)
            }
            _ => self.cursor.show(address, (width, height), at, view, clocks),
        }
    }
    /// Move the shown cursor; an image must have been set.
    pub fn move_cursor(&mut self, at: (i32, i32)) -> Result<cursor::Shown, Error> {
        self.running()?;
        let view = (self.timing.h_active, self.timing.v_active);
        let clocks = (self.refclk_khz, self.timing.pixel_clock_khz);
        self.cursor.move_to(at, view, clocks)
    }
    pub fn hide_cursor(&mut self) -> Result<(), Error> {
        self.cursor.hide()
    }

    /// Stop presenting before the pipeline tears the pipe down: cursor off,
    /// interrupts masked. A failed owner keeps its state. The surfaces stay
    /// reserved until `release` after a successful pipeline stop.
    pub fn stop(&mut self) -> Result<(), Error> {
        let hidden = self.cursor.hide();
        self.disable_interrupts();
        if matches!(self.state, State::Running) {
            self.state = State::Stopped;
        }
        hidden
    }
    /// Return the back buffer and cursor surface to the pool.
    ///
    /// # Safety
    /// `stop` ran and the pipeline's `disable` then succeeded (HUBP blanked
    /// after its outstanding requests retired, OTG stopped), and every CPU
    /// view of these surfaces has retired.
    pub unsafe fn release(mut self) -> Result<(), Error> {
        if self.state != State::Stopped {
            // A failed flip leaves fetch ownership unknown: keep quarantine
            // (dropping a published reservation keeps its exclusion).
            return Err(Error::Busy);
        }
        for memory in [self.back.take(), self.cursor_image.take().map(|(m, _)| m)]
            .into_iter()
            .flatten()
        {
            let mut memory = memory;
            // SAFETY: the caller's proof that no engine reads them.
            unsafe { memory.stopped() };
        }
        Ok(())
    }
}

/// A cheap identity for an uploaded cursor image (FNV-1a over size and pixels).
fn image_digest(width: u32, height: u32, pixels: &[u32]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // linux: n/a (FNV-1a offset basis)
    for word in [width, height].iter().chain(pixels) {
        for b in word.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3); // linux: n/a (FNV-1a prime)
        }
    }
    h | 1
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_scanout_tests.rs"]
mod tests;
