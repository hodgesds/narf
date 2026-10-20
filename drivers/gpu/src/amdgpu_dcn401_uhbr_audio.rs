//! DCN401 UHBR SST LPCM: dcn31 HPO stream encoder + APG, and Azalia.
//! APG instance follows the HPO stream; its input mux chooses the endpoint.
use super::*;
use crate::amdgpu_dcn401_otg::dp_phy::training::uhbr::video::{uhbr_dsc_payload, uhbr_payload};
#[path = "amdgpu_dcn401_uhbr_audio_bw.rs"]
mod bandwidth;

const SOURCE: u64 = 0x3625;
const CONTROL: u64 = 0x3630;
const CONTROL2: u64 = 0x3631;
const DEBUG: u64 = 0x3632;
const MEM: u64 = 0x3644;
const SDP: u64 = 0x367b;
const PACKETS: u64 = 0x367c;

/// Filter LPCM against the actual trained UHBR link and native blank budget;
/// compressed SADs pass through as dce_aud_az_configure programs them. No
/// surviving LPCM rate means silent video.
#[cfg(feature = "kernel-test")]
pub(crate) fn uhbr_audio_info(
    info: AudioInfo,
    timing: &Timing,
    bpc: u32,
    settings: UhbrSettings,
) -> Option<AudioInfo> {
    uhbr_audio_info_with(info, timing, bpc, settings, None)
}
/// `uhbr_audio_info` for a stream compressed with `dsc`: the budget at its
/// compressed bits per pixel and slices, against the blank width the
/// compressed stream's payload programs (uhbr_dsc_payload), as
/// build_audio_output passes dsc_cfg to check_audio_bandwidth_dp.
pub(crate) fn uhbr_audio_info_with(
    info: AudioInfo,
    timing: &Timing,
    bpc: u32,
    settings: UhbrSettings,
    dsc: Option<&crate::amdgpu_dsc::DscConfig>,
) -> Option<AudioInfo> {
    let audio_dsc = super::bandwidth::AudioDsc::of(dsc);
    // Validate before uhbr_payload's blank subtraction and fixed-point math.
    bandwidth::rates(timing, bpc, settings, 0, 2, 0, audio_dsc)?;
    let width = hblank_width(timing, bpc, settings, dsc)?;
    filtered_audio_info(info, |channels, rates| {
        bandwidth::rates(timing, bpc, settings, width, channels, rates, audio_dsc)
    })
}
/// The minimum blank symbol width the stream's payload programs.
fn hblank_width(
    timing: &Timing,
    bpc: u32,
    settings: UhbrSettings,
    dsc: Option<&crate::amdgpu_dsc::DscConfig>,
) -> Option<u16> {
    match dsc {
        Some(cfg) => uhbr_dsc_payload(timing, cfg, settings),
        None => uhbr_payload(timing, bpc, settings),
    }
    .map(|p| p.hblank_symbols)
}
/// dce_aud_az_configure's HBR probe: 192-kHz eight-channel audio within the
/// same blanking budget.
fn uhbr_hbr(
    timing: &Timing,
    bpc: u32,
    settings: UhbrSettings,
    dsc: Option<&crate::amdgpu_dsc::DscConfig>,
) -> bool {
    hblank_width(timing, bpc, settings, dsc)
        .and_then(|w| {
            bandwidth::rates(
                timing,
                bpc,
                settings,
                w,
                8,
                0x40,
                super::bandwidth::AudioDsc::of(dsc),
            )
        })
        .is_some_and(|r| r & 0x40 != 0)
}
fn bpc(v: &UhbrVideoRunning) -> u32 {
    match v.timing.blank.request.depth {
        ColorDepth::Bpc8 => 8,
        ColorDepth::Bpc10 => 10,
        ColorDepth::Bpc12 => 12,
    }
}
impl<I: Io> Engine<I> {
    fn uhbr_audio_video(&self, path: Path) -> Result<UhbrVideoRunning, Error> {
        let v = self.status.uhbr_video_running.ok_or(Error::Busy)?;
        match self.status.state {
            State::UhbrVideoRunning(s) if s == v.stream => {}
            State::ScanoutRunning(p) if p == v.timing.blank.request.pipe => {
                if !self
                    .status
                    .scanout
                    .is_some_and(|s| s.pipe == p && s.stream == v.stream)
                {
                    return Err(Error::Invalid);
                }
            }
            _ => return Err(Error::Busy),
        }
        if v.link.path != path {
            return Err(Error::Invalid);
        }
        Ok(v)
    }
    pub(in crate::amdgpu_dcn401_otg) fn uhbr_audio_quiet(
        &mut self,
        stream: u8,
    ) -> Result<(), Error> {
        for (r, mask) in [
            (CONTROL, 6),
            (CONTROL2, 0x1000001),
            (DEBUG, 0xff000003),
            (PACKETS, 0x3000001f),
        ] {
            if self.read(DpStream::Hpo(stream).at(self.layout, r))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    pub(in crate::amdgpu_dcn401_otg) fn uhbr_audio_verify(
        &mut self,
        v: &UhbrVideoRunning,
        a: &DisplayAudio,
    ) -> Result<(), Error> {
        self.uhbr_audio_verify_state(v, a, true)
    }
    fn uhbr_audio_verify_state(
        &mut self,
        v: &UhbrVideoRunning,
        a: &DisplayAudio,
        enabled: bool,
    ) -> Result<(), Error> {
        if !a.dp || a.endpoint != v.stream {
            return Err(Error::Invalid);
        }
        let l = self.layout;
        let at = |r| DpStream::Hpo(v.stream).at(l, r);
        for (r, mask, value) in [
            (SOURCE, 7, u32::from(a.endpoint)),
            (CONTROL, 6, 0),
            (CONTROL2, 0x100ff01, u32::from(enabled)),
            (DEBUG, 0xff00ff03, 0xff00),
            (MEM, 0x30, 0),
            (SDP, 1, 1),
            (PACKETS, 0x3000001f, 7),
            (0x366b, 0xffff, u32::from(v.payload.hblank_symbols)),
        ] {
            if self.read(at(r))? & mask != value {
                return Err(Error::Readback(at(r)));
            }
        }
        if v.link.settings.mst {
            self.uhbr_mst_audio_payload(v)?;
        }
        if self.az_read(a.endpoint, AZ_HOT_PLUG)? & (AUDIO_ENABLED | CLOCK_GATING_DISABLE)
            != AUDIO_ENABLED
        {
            return Err(Error::Readback(self.az_at(a.endpoint)));
        }
        Ok(())
    }
    /// An MST stream's audio rides its completed payload: the unblanked
    /// stream acknowledged by the manager, with exactly one allocation row
    /// on its link encoder naming it at its recorded slots.
    fn uhbr_mst_audio_payload(&mut self, v: &UhbrVideoRunning) -> Result<(), Error> {
        let l = self.layout;
        let sat = |vc: u64| DpStream::Hpo(v.link.link).at(l, 0x36bf + vc);
        let mut rows = 0;
        for vc in 0..4 {
            let row = self.read(sat(vc))?;
            if row & 0x7f00 != 0 && row & 7 == u32::from(v.stream) {
                if row >> 8 & 0x7f != u32::from(v.payload.slots) {
                    return Err(Error::Readback(sat(vc)));
                }
                rows += 1;
            }
        }
        if rows != 1 || !v.acknowledged {
            return Err(Error::Readback(sat(0)));
        }
        Ok(())
    }
    /// LPCM on the running 128b/132b stream: SST (`mst` None), or an MST
    /// stream whose manager payload of `mst` slots completed. Linux budgets
    /// both against the whole link and the timing's blank width.
    pub(super) async fn start_uhbr_audio(
        &mut self,
        path: Path,
        info: AudioInfo,
        mst: Option<u8>,
    ) -> Result<DisplayAudio, Error> {
        if self.status.uhbr_audio.is_some() {
            return Err(Error::Busy);
        }
        let v = self.uhbr_audio_video(path)?;
        match mst {
            // MST needs a completed manager payload as well as running video.
            None if v.link.settings.mst => return Err(Error::Unsupported),
            Some(_) if !v.link.settings.mst => return Err(Error::Invalid),
            Some(slots) if slots != v.payload.slots => return Err(Error::Invalid),
            Some(_) => self.uhbr_mst_audio_payload(&v)?,
            None => {}
        }
        let t = v.timing.blank.timing.request.timing;
        // A compressed stream's audio (Linux keeps it; build_audio_output
        // passes the DSC config to the budget).
        let dsc = v.timing.blank.timing.request.dsc;
        let info = uhbr_audio_info_with(info, &t, bpc(&v), v.link.settings, dsc.as_ref())
            .ok_or(Error::Unsupported)?;
        let (descriptors, ac3, _) = descriptors(&info, &t, None);
        let a = DisplayAudio {
            info,
            dp: true,
            endpoint: v.stream,
            channels: 0xff,
            descriptors,
            hbr: uhbr_hbr(&t, bpc(&v), v.link.settings, dsc.as_ref()),
        };
        if !self.audio_endpoint_available(a.endpoint) {
            return Err(Error::Busy);
        }
        self.uhbr_video_verify_running(&v)?;
        if self.az_read(a.endpoint, AZ_HOT_PLUG)? & AUDIO_ENABLED != 0 {
            return Err(Error::Busy);
        }
        let previous = self.status.state;
        self.status.uhbr_audio = Some(a);
        self.status.state = State::StartingUhbrAudio(v.stream);
        let result = async {
            let l = self.layout;
            let at = |r| DpStream::Hpo(v.stream).at(l, r);
            self.audio_wall_dto()?;
            // DCN401 has no DP_STREAM_ENC_APG_CLOCK_EN field.
            self.update(at(SOURCE), 7, u32::from(a.endpoint))?;
            self.update(at(CONTROL2), 0xff00, 0)?;
            self.update(at(DEBUG), 0xff00, 0xff00)?;
            self.update(at(MEM), 0x30, 0)?;
            self.hdmi_audio_endpoint(&a, ac3)?;
            self.az_update(
                a.endpoint,
                AZ_HOT_PLUG,
                AUDIO_ENABLED | 1,
                AUDIO_ENABLED | 1,
            )?;
            self.az_update(a.endpoint, AZ_HOT_PLUG, 1, 0)?;
            self.update(at(PACKETS), 1, 1)?;
            self.update(at(PACKETS), 6, 6)?;
            self.update(at(SDP), 1, 1)?;
            self.update(at(CONTROL), 2, 2)?;
            self.wait(at(CONTROL), 4, 4, 10).await?;
            self.update(at(CONTROL), 2, 0)?;
            self.wait(at(CONTROL), 4, 0, 10).await?;
            // Recheck video/link/route after both reset waits, before APG enable.
            self.uhbr_video_verify_transport(&v)?;
            self.uhbr_audio_verify_state(&v, &a, false)?;
            self.update(at(CONTROL2), 1, 1)?;
            self.uhbr_video_verify_running(&v)
        }
        .await;
        match result {
            Ok(()) => {
                self.status.state = previous;
                Ok(a)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    pub(super) fn stop_uhbr_audio(&mut self, path: Path) -> Result<(), Error> {
        let a = self.status.uhbr_audio.ok_or(Error::Invalid)?;
        let v = self.uhbr_audio_video(path)?;
        self.uhbr_video_verify_running(&v)?;
        let result = (|| {
            let l = self.layout;
            let at = |r| DpStream::Hpo(v.stream).at(l, r);
            self.update(at(PACKETS), 0xf, 0)?;
            // The running video owner established SDP_STREAM_ENABLE. Preserve
            // it; video teardown disables it after the last producer is stopped.
            self.update(at(CONTROL2), 1, 0)?;
            self.az_disable(a.endpoint)?;
            self.uhbr_audio_quiet(v.stream)?;
            if self.az_read(a.endpoint, AZ_HOT_PLUG)? & (AUDIO_ENABLED | 1) != 0 {
                return Err(Error::Readback(self.az_at(a.endpoint)));
            }
            self.status.uhbr_audio = None;
            self.audio_wall_dto()?;
            self.uhbr_video_verify_running(&v)
        })();
        if let Err(e) = result {
            self.status.uhbr_audio = Some(a);
            self.status.state = State::Failed(e);
            return Err(e);
        }
        Ok(())
    }
}
