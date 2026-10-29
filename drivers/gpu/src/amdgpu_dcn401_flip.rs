//! Native DCN401 double-buffered page flip of a live single-pipe scanout.
//! Linux: hubp401_program_surface_flip_and_addr (VSYNC flip type; the low
//! address write publishes the high half) inside the pipe-control lock, and
//! completion as dcn401_post_unlock_program_front_end and amdgpu_dm's pflip
//! handling observe it: no flip pending and EARLIEST_INUSE at the new address.
use super::*;
use crate::amdgpu_gmc_navi48::{DisplayContext, Gmc};
use narf_graphics_driver::generic::GenericFb;

/// A completed flip: the HUBP reported the new address in use, so the
/// previous one (`back`) is no longer fetched. A staged buffer it names is
/// the plane's back buffer again and may be rewritten; a client framebuffer
/// it names may be unpinned (amdgpu_dm_plane_helper_cleanup_fb runs after
/// the flip that replaced it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlipDone {
    pub pipe: u8,
    pub front: u64,
    pub back: u64,
    /// Frame count sampled after the new address latched.
    pub frame: u32,
}

/// A client framebuffer a plane scans out in place, as
/// amdgpu_dm_plane_fill_plane_buffer_attributes hands DC its address and
/// plane_size: the pinned buffer's GPU address plus offsets[0], its
/// pitch, and a 4:2:0 framebuffer's chroma plane (offsets[1] -
/// offsets[0], pitches[1]). Its size, format, tiling and DCC are the
/// plane's (a framebuffer that differs waits for the plane update or
/// relight that switches them); only the address and pitches flip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalSurface {
    pub address: u64,
    pub pitch_bytes: u32,
    pub chroma: Option<(u64, u32)>,
    /// The pinned buffer's last byte, which must lie in the frame-buffer
    /// aperture with every byte the plane fetches.
    pub last: u64,
    /// The buffer is no GFX12 DCC buffer, or one amdgpu_vram_mgr_new's DCC
    /// placement put at gmc_v12_0_get_dcc_alignment
    /// (`amdgpu_gem::ScanoutPin::dcc_aligned`). A DCC plane fetches only
    /// such a buffer.
    pub dcc_aligned: bool,
}

/// What a flipping plane shows next: its staged back buffer (the copy the
/// presenter made), or a client framebuffer in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlipSource {
    Back,
    External(ExternalSurface),
}

impl ExternalSurface {
    /// The plane `from` fetching this framebuffer, if hubp401 can: a
    /// non-zero 256-byte-aligned address (and chroma address), a pitch of
    /// whole pixels at least the staged one and within PITCH's 14 bits
    /// (likewise the chroma's), every fetched row inside the buffer, the
    /// chroma plane exactly when the plane is 4:2:0, and for a DCC plane a
    /// buffer at the DCC VRAM alignment.
    pub(in crate::amdgpu_dcn401_otg) fn applied(
        self,
        from: SurfaceApplied,
    ) -> Result<SurfaceApplied, Error> {
        let r = from.request;
        let format = r.format;
        let staged = r.bytes();
        let pitch_ok = |pitch: u32, min: u32, cpp: u32| {
            cpp != 0 && pitch >= min && pitch % cpp == 0 && pitch / cpp <= 0x4000
        };
        // The last byte a plane of `rows` rows at `pitch` reaches from `at`.
        let reach = |at: u64, pitch: u32, rows: u32| {
            at.checked_add(u64::from(pitch) * u64::from(rows))
                .and_then(|end| end.checked_sub(1))
        };
        let luma_end = reach(self.address, self.pitch_bytes, r.height).ok_or(Error::Invalid)?;
        if self.address == 0
            || self.address % 256 != 0
            || !pitch_ok(
                self.pitch_bytes,
                staged.pitch_bytes,
                format.bytes_per_pixel(),
            )
            || luma_end > self.last
            || (r.surface.tiling.dcc.is_some() && !self.dcc_aligned)
        {
            return Err(Error::Invalid);
        }
        match (self.chroma, staged.chroma) {
            (None, None) => {}
            (Some((offset, pitch)), Some((_, min))) => {
                let at = self.address.checked_add(offset).ok_or(Error::Invalid)?;
                let end = reach(at, pitch, r.height.div_ceil(2)).ok_or(Error::Invalid)?;
                if at % 256 != 0
                    || !pitch_ok(pitch, min, format.chroma_bytes_per_pixel())
                    || end > self.last
                {
                    return Err(Error::Invalid);
                }
            }
            _ => return Err(Error::Invalid),
        }
        Ok(SurfaceApplied {
            address: self.address,
            pitch_bytes: self.pitch_bytes,
            chroma: self.chroma,
            ..from
        })
    }
}

/// Which plane of the live scanout `pipe` is: 0 the primary, k the k-th
/// overlay from the bottom.
fn plane_index(scanout: &ScanoutRunning, pipe: u8) -> Option<usize> {
    if scanout.pipe == pipe {
        return Some(0);
    }
    scanout
        .overlays
        .iter()
        .position(|o| o.is_some_and(|o| o.pipe == pipe))
        .map(|k| k + 1)
}

impl<I: Io> Engine<I> {
    /// Every retained report names the surface by value; after a flip the
    /// front address changes in all of them together.
    fn retarget(
        &mut self,
        pipe: u8,
        from: SurfaceApplied,
        to: SurfaceApplied,
    ) -> Result<(), Error> {
        let slot = usize::from(pipe);
        let address = to.address;
        let s = &mut self.status;
        let (Some(dpp), Some(mpc), Some(mut requestor), Some(mut scanout)) =
            (s.dpps[slot], s.mpcs[slot], s.requestor, s.scanout)
        else {
            return Err(Error::Invalid);
        };
        let plane = plane_index(&scanout, pipe).ok_or(Error::Invalid)?;
        let (named, fetched) = match plane {
            0 => (Some(requestor.surface), scanout.address),
            k => (
                requestor.overlays[k - 1],
                scanout.overlays[k - 1].map_or(0, |o| o.address),
            ),
        };
        if s.surfaces[slot] != Some(from)
            || dpp.surface != from
            || mpc.dpp.surface != from
            || named != Some(from)
            || fetched != from.address
        {
            return Err(Error::Invalid);
        }
        s.surfaces[slot] = Some(to);
        s.dpps[slot] = Some(DppApplied { surface: to, ..dpp });
        s.mpcs[slot] = Some(MpcApplied {
            dpp: DppApplied {
                surface: to,
                ..mpc.dpp
            },
            ..mpc
        });
        match plane {
            0 => {
                requestor.surface = to;
                scanout.address = address;
            }
            k => {
                requestor.overlays[k - 1] = Some(to);
                if let Some(o) = scanout.overlays[k - 1].as_mut() {
                    o.address = address;
                }
            }
        }
        s.requestor = Some(requestor);
        s.scanout = Some(scanout);
        Ok(())
    }
    /// The live scanout (of the selected display) fetching plane `pipe`,
    /// and the address that plane fetches.
    fn live_plane(&self, pipe: u8) -> Option<(ScanoutRunning, u64)> {
        let s = self.status.scanout?;
        if self.status.state != State::ScanoutRunning(s.pipe) {
            return None;
        }
        let address = match plane_index(&s, pipe)? {
            0 => s.address,
            k => s.overlays[k - 1]?.address,
        };
        Some((s, address))
    }
}

impl Surfaces {
    /// Allocate, clear and publish a second buffer with the front's geometry.
    /// Allowed while staged or while the pipe scans out: it touches no
    /// display register, only owned VRAM and the HDP flush.
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_back<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pool: &Pool,
        pipe: u8,
        config: DisplayContext,
    ) -> Result<u64, Error> {
        let slot = usize::from(pipe);
        // The primary or an overlay of the live scanout, or a staged plane.
        let live = e.live_plane(pipe).is_some();
        if !(live || e.status.state.reusable()) {
            return Err(Error::Busy);
        }
        let surface = self
            .0
            .get_mut(slot)
            .and_then(Option::as_mut)
            .ok_or(Error::Invalid)?;
        if surface.back.is_some() || e.status.surfaces[slot] != Some(surface.applied) {
            return Err(Error::Busy);
        }
        crate::amdgpu_dcn401_otg::surfaces_changed();
        let memory = pool
            .reserve(surface.applied.bytes)
            .map_err(|_| Error::Allocation)?;
        // As for the front: the whole allocation must translate through FB.
        if memory.address() < config.fb_base
            || memory
                .address()
                .checked_add(memory.size() - 1)
                .is_none_or(|last| last > config.fb_top || last >= 1 << 48)
        {
            return Err(Error::Invalid);
        }
        let mut memory = memory;
        let map = memory.mapping();
        for start in (0..map.len).step_by(65536) {
            let end = (start + 65536).min(map.len);
            e.access(|_| {
                for offset in (start..end).step_by(4) {
                    // SAFETY: live authority and an owned, unpublished VRAM mapping.
                    unsafe { map.write32(offset, 0) };
                }
                Ok(())
            })?;
            if end < map.len {
                narf_scheduler::yield_now().await;
            }
        }
        e.flush_surface_writes()?;
        memory.publish();
        let address = memory.address();
        // Retained even if the state moved meanwhile, until explicit surface release.
        let surface = self.0[slot].as_mut().ok_or(Error::Invalid)?;
        surface.back = Some(memory);
        if live && e.live_plane(pipe).is_none() {
            return Err(Error::Busy);
        }
        Ok(address)
    }
    /// CPU view of the back buffer, for drawing the next frame.
    pub(in crate::amdgpu_dcn401_otg) fn back_framebuffer(
        &self,
        pipe: u8,
    ) -> Result<GenericFb, Error> {
        let surface = self
            .0
            .get(usize::from(pipe))
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        let back = surface.back.as_ref().ok_or(Error::Invalid)?;
        let a = surface.applied;
        Ok(GenericFb::new(
            back.mapping().phys.raw(),
            a.request.width,
            a.request.height,
            a.request.bytes().pitch_bytes,
            (a.request.format.bytes_per_pixel() * 8) as u8,
        ))
    }
    /// Write part of one row of the next frame (packed 32-bit words from
    /// pixel `x`, as the front's `upload` takes them) into the back buffer of
    /// a live pipe. The back buffer is the one surface no HUBP fetches while the
    /// pipe scans out and no flip is in progress, so this is the live update
    /// path that never races scanout; the front's `upload` stays
    /// stopped-only. No raw CPU pointer escapes. The writes become visible to
    /// display when the next `flip` HDP-flushes them before latching.
    pub(in crate::amdgpu_dcn401_otg) fn upload_back<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        x: u32,
        y: u32,
        pixels: &[u32],
    ) -> Result<(), Error> {
        let surface = self
            .0
            .get(usize::from(pipe))
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        let back = surface.back.as_ref().ok_or(Error::Invalid)?;
        let a = surface.applied;
        let start = a.row_words(x, y, pixels.len())?;
        // Only while this plane scans out its front: during a flip which
        // buffer is fetched is in transition, and after a failure it is
        // unknown.
        let (_, fetched) = e.live_plane(pipe).ok_or(Error::Busy)?;
        if fetched != a.address || back.address() == a.address {
            return Err(Error::Busy);
        }
        let map = back.mapping();
        e.access(|_| {
            for (index, &pixel) in pixels.iter().enumerate() {
                // SAFETY: checked row bounds within the retained back buffer,
                // which no display fetch reads until the next flip.
                unsafe { map.write32(start + index as u64 * 4, pixel) };
            }
            Ok(())
        })
    }
    /// `upload_back` by surface byte offset rather than pixel row: packed
    /// 32-bit words written from byte `offset` of the back buffer, within
    /// the surface's bytes (both planes of a 4:2:0 surface, a tiled
    /// surface's swizzle blocks). The presenter copies tiled and 4:2:0
    /// framebuffers this way, block row by block row.
    pub(in crate::amdgpu_dcn401_otg) fn upload_back_bytes<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        offset: u64,
        words: &[u32],
    ) -> Result<(), Error> {
        let surface = self
            .0
            .get(usize::from(pipe))
            .and_then(Option::as_ref)
            .ok_or(Error::Invalid)?;
        let back = surface.back.as_ref().ok_or(Error::Invalid)?;
        let a = surface.applied;
        let end = (words.len() as u64)
            .checked_mul(4)
            .and_then(|n| n.checked_add(offset))
            .ok_or(Error::Invalid)?;
        if words.is_empty() || offset % 4 != 0 || end > a.bytes {
            return Err(Error::Invalid);
        }
        let (_, fetched) = e.live_plane(pipe).ok_or(Error::Busy)?;
        if fetched != a.address || back.address() == a.address {
            return Err(Error::Busy);
        }
        let map = back.mapping();
        e.access(|_| {
            for (index, &word) in words.iter().enumerate() {
                // SAFETY: checked bounds within the retained back buffer,
                // which no display fetch reads until the next flip.
                unsafe { map.write32(offset + index as u64 * 4, word) };
            }
            Ok(())
        })
    }
    /// Present the back buffer at the next VUPDATE and wait for the HUBP to
    /// report it in use. Any failure quarantines the pipe; both buffers stay
    /// allocated because which one is still fetched is then unknown.
    pub(in crate::amdgpu_dcn401_otg) async fn flip<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        crystal_khz: u32,
        owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<FlipDone, Error> {
        let done = self.flip_planes(e, pipe, 1, crystal_khz, owners).await?;
        done[0].ok_or(Error::Invalid)
    }
    /// Flip the planes in `planes` (bit 0 the primary, bit k the k-th
    /// overlay from the bottom) of display `pipe`'s live scanout to their
    /// back buffers together (`flip_sources` with `FlipSource::Back`).
    pub(in crate::amdgpu_dcn401_otg) async fn flip_planes<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        planes: u8,
        crystal_khz: u32,
        owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<[Option<FlipDone>; 1 + MAX_OVERLAYS], Error> {
        if planes == 0 || planes >> (1 + MAX_OVERLAYS) != 0 {
            return Err(Error::Invalid);
        }
        let sources = core::array::from_fn(|k| (planes & 1 << k != 0).then_some(FlipSource::Back));
        self.flip_sources(e, pipe, sources, crystal_khz, owners)
            .await
    }
    /// Flip each plane `sources` names (index 0 the primary, k the k-th
    /// overlay from the bottom) of display `pipe`'s live scanout together:
    /// to its back buffer, or to a client framebuffer scanned out in place
    /// (no copy: only the plane's address, and its pitches when they
    /// differ, change). Every new address goes under the one OTG lock,
    /// latching at the same VUPDATE (commit_planes_for_stream's single
    /// pipe-control lock over all the stream's planes). Each flipped
    /// plane's report, in plane order. A plane flipped to its back buffer
    /// swaps it with the staged buffer it showed (if it showed one); one
    /// flipped to a client framebuffer keeps both staged buffers unfetched.
    pub(in crate::amdgpu_dcn401_otg) async fn flip_sources<I: Io>(
        &mut self,
        e: &mut Engine<I>,
        pipe: u8,
        sources: [Option<FlipSource>; 1 + MAX_OVERLAYS],
        crystal_khz: u32,
        mut owners: impl FnMut() -> Result<(dccg::Applied, DisplayContext), Error>,
    ) -> Result<[Option<FlipDone>; 1 + MAX_OVERLAYS], Error> {
        let running = e.status.scanout.ok_or(Error::Invalid)?;
        if e.status.state != State::ScanoutRunning(pipe) || running.pipe != pipe {
            return Err(Error::Busy);
        }
        if sources.iter().all(Option::is_none) {
            return Err(Error::Invalid);
        }
        let deadlines = e.status.deadlines.ok_or(Error::Invalid)?;
        let current = owners()?;
        let config = current.1;
        // Each flipping plane's pipe, what it shows now and what it shows
        // next.
        let mut flips: [Option<(u8, SurfaceApplied, SurfaceApplied, FlipSource)>;
            1 + MAX_OVERLAYS] = [None; 1 + MAX_OVERLAYS];
        for (k, (slot, source)) in flips.iter_mut().zip(sources).enumerate() {
            let Some(source) = source else { continue };
            let q = match k {
                0 => pipe,
                k => running.overlays[k - 1].ok_or(Error::Invalid)?.pipe,
            };
            let surface = self
                .0
                .get(usize::from(q))
                .and_then(Option::as_ref)
                .ok_or(Error::Invalid)?;
            let from = surface.applied;
            let to = match source {
                FlipSource::Back => {
                    let back = surface.back.as_ref().ok_or(Error::Invalid)?;
                    from.at_staged(back.address())
                }
                FlipSource::External(x) => {
                    // amdgpu_display_supported_domains: VRAM only on this
                    // dGPU, so the whole buffer translates through FB.
                    if x.address < config.fb_base || x.last > config.fb_top || x.last >= 1 << 48 {
                        return Err(Error::Invalid);
                    }
                    let to = x.applied(from)?;
                    // Never one of this plane's own staged buffers.
                    if to.address == surface.memory.address()
                        || surface.back.as_ref().map(Reservation::address) == Some(to.address)
                    {
                        return Err(Error::Invalid);
                    }
                    to
                }
            };
            *slot = Some((q, from, to, source));
        }
        let p = self.scanout_bound(e, deadlines, crystal_khz, current)?;
        if p.address != running.address || p.overlays != running.overlays {
            return Err(Error::Invalid);
        }
        let mut next = p;
        if let Some((_, _, to, _)) = flips[0] {
            next.address = to.address;
        }
        for (k, o) in next.overlays.iter_mut().enumerate() {
            if let (Some(o), Some((_, _, to, _))) = (o.as_mut(), flips[k + 1]) {
                o.address = to.address;
            }
        }
        e.live_fetch(pipe, p.address)?;
        e.flip_quiet(pipe)?;
        // The producer's CPU writes to the back buffers must be in VRAM first.
        e.flush_surface_writes()?;
        e.status.state = State::Flipping(pipe);
        let result = async {
            // The records name the new surfaces first: their pitches and
            // chroma planes are what the flip programs under the lock.
            for (q, from, to, _) in flips.iter().flatten() {
                e.retarget(*q, *from, *to)?;
            }
            let frame = e.flip_from(next, Some(p)).await?;
            if owners()? != current {
                return Err(Error::Busy);
            }
            let mut done = [None; 1 + MAX_OVERLAYS];
            for (slot, flip) in done.iter_mut().zip(flips) {
                let Some((q, from, to, source)) = flip else {
                    continue;
                };
                let surface = self.0[usize::from(q)].as_mut().ok_or(Error::Invalid)?;
                if source == FlipSource::Back {
                    let front = surface.back.take().ok_or(Error::Invalid)?;
                    surface.back = Some(core::mem::replace(&mut surface.memory, front));
                }
                surface.applied = to;
                *slot = Some(FlipDone {
                    pipe: q,
                    front: to.address,
                    back: from.address,
                    frame,
                });
            }
            self.scanout_bound(e, deadlines, crystal_khz, current)?;
            e.live_fetch(pipe, next.address)?;
            Ok(done)
        }
        .await;
        match result {
            Ok(done) => {
                e.status.state = State::ScanoutRunning(pipe);
                Ok(done)
            }
            Err(err) => {
                e.status.state = State::Failed(err);
                Err(err)
            }
        }
    }
}

impl Otg {
    /// Allocate the back buffer of a staged or live pipe.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/HDP writers; the buffer
    /// is retained by the pipe until explicit surface release.
    pub async unsafe fn prepare_back_buffer(
        &mut self,
        pool: &Pool,
        gmc: &mut Gmc,
        pipe: u8,
    ) -> Result<u64, Error> {
        // SAFETY: the caller's obligations; display k scans out on pipe k.
        unsafe { self.prepare_plane_back_buffer(pool, gmc, pipe, pipe) }.await
    }
    /// `prepare_back_buffer` for plane `pipe` of display `display`: its
    /// primary (`pipe == display`) or one of its overlays.
    /// # Safety
    /// As for `prepare_back_buffer`.
    pub async unsafe fn prepare_plane_back_buffer(
        &mut self,
        pool: &Pool,
        gmc: &mut Gmc,
        display: u8,
        pipe: u8,
    ) -> Result<u64, Error> {
        self.0.select_display(display)?;
        let config = gmc.display_context(self.0.io.0).map_err(Error::Memory)?;
        self.1.prepare_back(&mut self.0, pool, pipe, config).await
    }
    /// The back buffer as a CPU framebuffer (bus-physical BAR address).
    pub fn back_framebuffer(&self, pipe: u8) -> Result<GenericFb, Error> {
        self.1.back_framebuffer(pipe)
    }
    /// Write part of one row of the next frame into a live pipe's back
    /// buffer; `flip` publishes it.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent display/HDP writers.
    pub unsafe fn upload_back_buffer(
        &mut self,
        pipe: u8,
        x: u32,
        y: u32,
        pixels: &[u32],
    ) -> Result<(), Error> {
        // SAFETY: the caller's obligations; display k scans out on pipe k.
        unsafe { self.upload_plane_back_buffer(pipe, pipe, x, y, pixels) }
    }
    /// `upload_back_buffer` into plane `pipe` of display `display`.
    /// # Safety
    /// As for `upload_back_buffer`.
    pub unsafe fn upload_plane_back_buffer(
        &mut self,
        display: u8,
        pipe: u8,
        x: u32,
        y: u32,
        pixels: &[u32],
    ) -> Result<(), Error> {
        self.0.select_display(display)?;
        self.1.upload_back(&mut self.0, pipe, x, y, pixels)
    }
    /// `upload_plane_back_buffer` by byte offset into the surface
    /// (`Surfaces::upload_back_bytes`).
    /// # Safety
    /// As for `upload_back_buffer`.
    pub unsafe fn upload_plane_back_bytes(
        &mut self,
        display: u8,
        pipe: u8,
        offset: u64,
        words: &[u32],
    ) -> Result<(), Error> {
        self.0.select_display(display)?;
        self.1.upload_back_bytes(&mut self.0, pipe, offset, words)
    }
    /// Flip a live scanout to its back buffer at the next VUPDATE.
    /// # Safety
    /// The back buffer must hold the complete next frame and no CPU writer
    /// may touch it until another flip. Exclude firmware/FAMS and concurrent
    /// display/hub/VM/IRQ/clock/reset/power writers.
    pub async unsafe fn flip(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
        crystal_khz: u32,
    ) -> Result<FlipDone, Error> {
        // Display k scans out on pipe k: address that display's records.
        self.0.select_display(pipe)?;
        let regs = self.0.io.0;
        self.1
            .flip(&mut self.0, pipe, crystal_khz, || {
                Ok((
                    dccg.retained_timing_clock(regs, clocks, pipe)
                        .map_err(Error::PipeClocks)?,
                    gmc.display_context(regs).map_err(Error::Memory)?,
                ))
            })
            .await
    }
    /// Flip the planes in `planes` (bit 0 the primary, bit k the k-th
    /// overlay) of display `pipe`'s live scanout to their back buffers at
    /// the same VUPDATE.
    /// # Safety
    /// As for `flip`, for every flipping plane's back buffer.
    pub async unsafe fn flip_planes(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
        planes: u8,
        crystal_khz: u32,
    ) -> Result<[Option<FlipDone>; 1 + MAX_OVERLAYS], Error> {
        self.0.select_display(pipe)?;
        let regs = self.0.io.0;
        self.1
            .flip_planes(&mut self.0, pipe, planes, crystal_khz, || {
                Ok((
                    dccg.retained_timing_clock(regs, clocks, pipe)
                        .map_err(Error::PipeClocks)?,
                    gmc.display_context(regs).map_err(Error::Memory)?,
                ))
            })
            .await
    }
    /// Flip display `pipe`'s planes to what `sources` names (`flip_sources`):
    /// back buffers and client framebuffers scanned out in place, at the
    /// same VUPDATE.
    /// # Safety
    /// As for `flip`, for every flipping back buffer; every client
    /// framebuffer must stay pinned in VRAM, unmoved and unfreed, until a
    /// later flip's `FlipDone` (or the plane's stop) shows it no longer
    /// fetched.
    pub async unsafe fn flip_sources(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        gmc: &mut Gmc,
        pipe: u8,
        sources: [Option<FlipSource>; 1 + MAX_OVERLAYS],
        crystal_khz: u32,
    ) -> Result<[Option<FlipDone>; 1 + MAX_OVERLAYS], Error> {
        self.0.select_display(pipe)?;
        let regs = self.0.io.0;
        self.1
            .flip_sources(&mut self.0, pipe, sources, crystal_khz, || {
                Ok((
                    dccg.retained_timing_clock(regs, clocks, pipe)
                        .map_err(Error::PipeClocks)?,
                    gmc.display_context(regs).map_err(Error::Memory)?,
                ))
            })
            .await
    }
    /// What display `pipe`'s HUBPs fetch, when that is known: each plane's
    /// address while it scans out (index 0 the primary, k the k-th overlay
    /// from the bottom), nothing once its fetch is stopped (no scanout
    /// recorded, the display at rest), none while a change is in flight or
    /// after a failure (which buffer is fetched is then unknown, so nothing
    /// it may fetch can be released).
    pub fn fetched_addresses(&self, pipe: u8) -> Option<[Option<u64>; 1 + MAX_OVERLAYS]> {
        let status = self.display_status(pipe)?;
        match status.scanout {
            Some(s) if status.state == State::ScanoutRunning(pipe) && s.pipe == pipe => {
                let mut out = [None; 1 + MAX_OVERLAYS];
                out[0] = Some(s.address);
                for (o, overlay) in out[1..].iter_mut().zip(s.overlays) {
                    *o = overlay.map(|x| x.address);
                }
                Some(out)
            }
            None if status.state.reusable() => Some([None; 1 + MAX_OVERLAYS]),
            _ => None,
        }
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_flip_tests.rs"]
mod tests;
