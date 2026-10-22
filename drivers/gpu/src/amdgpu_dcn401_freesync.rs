//! FreeSync SPD publication belongs to the same retained per-display owner
//! as its DRR timing. Packet indices follow DC's DIO/HPO encoders: HDMI 3,
//! DP 2. A pending VPG update is never reported as completed on cancellation.
use super::*;
use crate::amdgpu_hdr::InfoPacket;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Tmds(u8),
    Dp(u8),
    Uhbr(u8),
    Frl,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreesyncApplied {
    pub pipe: u8,
    pub packet: InfoPacket,
    pub complete: bool,
    route: Route,
}

impl<I: Io> Engine<I> {
    fn freesync_route(&self, pipe: u8) -> Result<Route, Error> {
        self.drr_timing(pipe)?;
        if let Some(v) = self
            .status
            .hdmi_video_running
            .filter(|v| v.link.request.pipe == pipe)
        {
            Ok(Route::Tmds(v.link.request.stream))
        } else if let Some(v) = self
            .status
            .dp_video_running
            .filter(|v| v.frontend.request.pipe == pipe)
        {
            if v.frontend.link.phy.settings.mst {
                return Err(Error::Unsupported);
            }
            Ok(Route::Dp(v.frontend.request.stream))
        } else if let Some(v) = self
            .status
            .uhbr_video_running
            .filter(|v| v.timing.blank.request.pipe == pipe)
        {
            if v.link.settings.mst {
                return Err(Error::Unsupported);
            }
            Ok(Route::Uhbr(v.stream))
        } else if self
            .status
            .frl_video_running
            .is_some_and(|v| v.request.pipe == pipe)
        {
            Ok(Route::Frl)
        } else {
            Err(Error::Busy)
        }
    }
    /// Stop only FreeSync's packet. Audio, VSC, HDR and PPS keep their own
    /// enables. This path is synchronous and runs before fetch/timing stops.
    pub(super) fn freesync_off(&mut self, pipe: u8) -> Result<(), Error> {
        let Some(applied) = self.status.freesync.filter(|v| v.pipe == pipe) else {
            return Ok(());
        };
        match applied.route {
            Route::Tmds(_) => {
                let mut plan = self.status.hdmi_link_ready.ok_or(Error::Invalid)?;
                self.hdmi_update_live(&mut plan, 14, 3 << 12, 0)?;
                self.hdmi_update_live(&mut plan, 18, 0xffff_0000, 0)?;
                self.status.hdmi_link_ready = Some(plan);
                if let Some(v) = self.status.hdmi_video_running.as_mut() {
                    v.link = plan;
                }
            }
            Route::Dp(stream) => {
                let at = DpStream::Dio(stream).at(self.layout, 0x2141);
                self.update(at, 1 << 22, 0)?;
                if self.read(at)? & !1 == 0 {
                    self.update(at, 1, 0)?;
                }
            }
            Route::Uhbr(stream) => {
                self.update(DpStream::Hpo(stream).at(self.layout, 0x366e), 1, 0)?
            }
            Route::Frl => self.update(self.layout.mpc_base + 0x8e6 * 4, 3 << 12, 0)?,
        }
        self.status.freesync = None;
        Ok(())
    }
    async fn freesync_publish(&mut self, route: Route, packet: InfoPacket) -> Result<(), Error> {
        match route {
            Route::Tmds(stream) => {
                self.hdmi_packet(stream, 3, &packet.bytes()).await?;
                let mut plan = self.status.hdmi_link_ready.ok_or(Error::Invalid)?;
                self.hdmi_update_live(&mut plan, 14, 3 << 12, 3 << 12)?;
                self.hdmi_update_live(&mut plan, 18, 0xffff_0000, 2 << 16)?;
                self.status.hdmi_link_ready = Some(plan);
                if let Some(v) = self.status.hdmi_video_running.as_mut() {
                    v.link = plan;
                }
            }
            Route::Dp(stream) => {
                self.dp_packet(stream, 2, packet).await?;
                self.update(
                    DpStream::Dio(stream).at(self.layout, 0x2141),
                    (1 << 22) | 1,
                    (1 << 22) | 1,
                )?;
            }
            Route::Uhbr(stream) => {
                self.uhbr_packet(stream, 2, packet).await?;
                self.update(DpStream::Hpo(stream).at(self.layout, 0x366e), 1, 1)?;
                self.update(DpStream::Hpo(stream).at(self.layout, 0x367b), 1, 1)?;
            }
            Route::Frl => self.frl_vpg_packet(3, &packet.bytes()).await?,
        }
        Ok(())
    }
    pub(super) async fn set_freesync(
        &mut self,
        pipe: u8,
        drr: Option<crate::amdgpu_freesync::Drr>,
        packet: InfoPacket,
    ) -> Result<Option<DrrApplied>, Error> {
        let route = self.freesync_route(pipe)?;
        let hdmi = matches!(route, Route::Tmds(_) | Route::Frl);
        if !packet.valid || (if hdmi { packet.hb[0] } else { packet.hb[1] }) != 0x83 {
            return Err(Error::Invalid);
        }
        let applied = self.configure_drr(pipe, drr).await?;
        let record = FreesyncApplied {
            pipe,
            packet,
            complete: true,
            route,
        };
        if self.status.freesync == Some(record) {
            return Ok(applied);
        }
        let prior = self.status.state;
        self.status.freesync = Some(FreesyncApplied {
            complete: false,
            ..record
        });
        // Pending packet publication is sticky across a dropped future.
        self.status.state = State::Failed(Error::Busy);
        match self.freesync_publish(route, packet).await {
            Ok(()) => {
                self.status.freesync = Some(record);
                self.status.state = prior;
                Ok(applied)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// Apply DRR and the AMD FreeSync SPD to the same running display.
    /// A cancelled or failed packet update requires retained-owner recovery.
    /// # Safety
    /// Exclude firmware/FAMS and concurrent timing/stream writers.
    pub async unsafe fn set_freesync(
        &mut self,
        pipe: u8,
        drr: Option<crate::amdgpu_freesync::Drr>,
        packet: InfoPacket,
    ) -> Result<Option<DrrApplied>, Error> {
        self.0.select_display(pipe)?;
        self.0.set_freesync(pipe, drr, packet).await
    }
}

/// A real started-video fixture supplies the retained encoder; model its
/// fetch latch, then verify active/inactive packets without changing HDR.
#[cfg(feature = "kernel-test")]
pub(super) async fn packet_cycle<I: Io>(e: &mut Engine<I>, pipe: u8) -> [u32; 18] {
    let previous = e.status.state;
    let (fixture, _) = super::drr::tests::live(pipe);
    e.status.scanout = fixture.status.scanout;
    e.status.state = State::ScanoutRunning(pipe);
    let t = e.status.pipes[usize::from(pipe)].unwrap().request.timing;
    let range = crate::amdgpu_freesync::VrrRange {
        min_hz: 30,
        max_hz: 144,
    };
    let route = e.freesync_route(pipe).unwrap();
    let hdmi = matches!(route, Route::Tmds(_) | Route::Frl);
    let mut words = [0; 18];
    for (i, active) in [true, false].into_iter().enumerate() {
        let packet = crate::amdgpu_freesync::info_packet(&t, range, hdmi, active).unwrap();
        let drr = active.then(|| crate::amdgpu_freesync::drr(&t, range).unwrap());
        e.set_freesync(pipe, drr, packet).await.unwrap();
        assert_eq!(e.status.freesync.unwrap().packet, packet);
        assert!(e.status.freesync.unwrap().complete);
        assert_eq!(e.status.drr.map(|v| v.drr), drr);
        words[i * 9..i * 9 + 9].copy_from_slice(&packet.words());
    }
    e.freesync_off(pipe).unwrap();
    assert!(e.status.freesync.is_none());
    e.status.scanout = None;
    e.status.state = previous;
    words
}
