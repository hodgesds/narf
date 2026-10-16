//! DCN401 UHBR SST LPCM: dcn31 HPO stream encoder + APG, and Azalia.
//! APG instance follows the HPO stream; its input mux chooses the endpoint.
use super::*;
use crate::amdgpu_dcn401_otg::dp_phy::training::uhbr::video::uhbr_payload;
#[path = "amdgpu_dcn401_uhbr_audio_bw.rs"]
mod bandwidth;

const SOURCE: u64 = 0x3625;
const CONTROL: u64 = 0x3630;
const CONTROL2: u64 = 0x3631;
const DEBUG: u64 = 0x3632;
const MEM: u64 = 0x3644;
const SDP: u64 = 0x367b;
const PACKETS: u64 = 0x367c;

/// Filter LPCM against the actual trained UHBR link and native blank budget.
/// No surviving rates means silent video; no unsupported endpoint is exposed.
pub(crate) fn uhbr_lpcm_info(
    info: AudioInfo,
    timing: &Timing,
    bpc: u32,
    settings: UhbrSettings,
) -> Option<AudioInfo> {
    // Validate before uhbr_payload's blank subtraction and fixed-point math.
    bandwidth::rates(timing, bpc, settings, 0, 2, 0)?;
    let payload = uhbr_payload(timing, bpc, settings)?;
    let mut info = lpcm_info(info)?;
    for mode in &mut info.modes[..usize::from(info.mode_count)] {
        mode.rates = bandwidth::rates(
            timing,
            bpc,
            settings,
            payload.hblank_symbols,
            mode.channels,
            mode.rates,
        )?;
    }
    lpcm_info(info)
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
        if !a.dp || a.endpoint != v.stream || a.hbr {
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
        if self.az_read(a.endpoint, AZ_HOT_PLUG)? & (AUDIO_ENABLED | CLOCK_GATING_DISABLE)
            != AUDIO_ENABLED
        {
            return Err(Error::Readback(self.az_at(a.endpoint)));
        }
        Ok(())
    }
    pub(super) async fn start_uhbr_audio(
        &mut self,
        path: Path,
        info: AudioInfo,
    ) -> Result<DisplayAudio, Error> {
        if self.status.uhbr_audio.is_some() {
            return Err(Error::Busy);
        }
        let v = self.uhbr_audio_video(path)?;
        let t = v.timing.blank.timing.request.timing;
        let info = uhbr_lpcm_info(info, &t, bpc(&v), v.link.settings).ok_or(Error::Unsupported)?;
        let (descriptors, _, _) = descriptors(&info, &t, None);
        let a = DisplayAudio {
            info,
            dp: true,
            endpoint: v.stream,
            channels: 0xff,
            descriptors,
            hbr: false,
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
            self.hdmi_audio_endpoint(&a, false)?;
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
