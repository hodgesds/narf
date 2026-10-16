//! DCN401 FRL LPCM: AFMT4, tribyte ACR and the pipe's Azalia endpoint.
//! Linux: hpo_enc401_setup_hdmi_audio + afmt3_setup_hdmi_audio. AFMT4 has
//! no DIO AFMT_CNTL clock; afmt3 clears MEM_PWR_FORCE during source setup.
use super::*;
use crate::amdgpu_frl_cap::{FrlBorrow, FrlCap};
use crate::amdgpu_navi48_boot::{frl_audio, frl_carries, FrlRate};

const FRL_ACR: u64 = 0x8e2;
const FRL_INFO: u64 = 0x8e3;
const FRL_PACKET: u64 = 0x92a;
const FRL_PACKET2: u64 = 0x91d;
const FRL_SRC: u64 = 0x92d;
const FRL_MEM: u64 = 0x92f;

/// frl_get_audio_clock_info: N/CTS at each lane character clock, both
/// rounding directions. Component depth and pixel rate do not change ACR.
fn frl_acr(character_khz: u32) -> Option<[u32; 6]> {
    Some(match character_khz {
        166_666 | 166_667 => [4224, 171875, 5292, 156250, 5760, 156250],
        333_333 | 333_334 => [4032, 328125, 5292, 312500, 6048, 328125],
        444_444 | 444_445 => [4032, 437500, 3969, 312500, 6048, 437500],
        555_555 | 555_556 => [3456, 468750, 3969, 390625, 5184, 468750],
        666_666 | 666_667 => [3072, 500000, 3969, 468750, 4752, 515625],
        _ => return None,
    })
}

impl<I: Io> Engine<I> {
    fn frl_audio_video(&self, path: Path) -> Result<FrlVideoRunning, Error> {
        let v = self.status.frl_video_running.ok_or(Error::Busy)?;
        if !matches!(self.status.state,
            State::FrlVideoRunning(p) | State::ScanoutRunning(p) if p == v.request.pipe)
        {
            return Err(Error::Busy);
        }
        if v.link.path != path {
            return Err(Error::Invalid);
        }
        if let State::ScanoutRunning(p) = self.status.state {
            if !self
                .status
                .scanout
                .is_some_and(|s| s.pipe == p && s.stream == p)
            {
                return Err(Error::Invalid);
            }
        }
        Ok(v)
    }
    /// The running video must already reserve this audio budget. Adding
    /// audio never silently changes its borrow mode or packets per line.
    fn frl_audio_budget(v: &FrlVideoRunning, info: AudioInfo) -> Result<(), Error> {
        let rate = (1..=6)
            .filter_map(FrlRate::new)
            .find(|r| {
                let khz = u32::from(r.gbps()) * 1_000_000 / 18;
                r.lanes() == v.link.lanes && (khz..=khz + 1).contains(&v.link.character_khz)
            })
            .ok_or(Error::Unsupported)?;
        let blank = v.timing.blank;
        let t = blank.timing.request.timing;
        let bpc = match blank.request.depth {
            ColorDepth::Bpc8 => 8,
            ColorDepth::Bpc10 => 10,
            ColorDepth::Bpc12 => 12,
        };
        let Some(FrlCap::Ok {
            audio_packets_line,
            borrow,
        }) = frl_carries(
            &t,
            bpc,
            blank.request.ycbcr420,
            rate,
            frl_audio(Some(info), t.v_active),
        )
        else {
            return Err(Error::Unsupported);
        };
        if audio_packets_line != u32::from(v.request.audio_packets_line)
            || (borrow == FrlBorrow::FromBlank) != v.request.borrow_from_blank
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub(in crate::amdgpu_dcn401_otg) fn frl_audio_quiet(&mut self) -> Result<(), Error> {
        for (reg, mask) in [(FRL_PACKET, 1), (FRL_ACR, 0x1003)] {
            if self.read(self.frl_at(reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        Ok(())
    }
    /// Reused by live video checks and source-test updates. No recursive
    /// video verification here: those callers already checked the stream.
    pub(in crate::amdgpu_dcn401_otg) fn frl_audio_verify(
        &mut self,
        v: &FrlVideoRunning,
        a: &DisplayAudio,
    ) -> Result<(), Error> {
        if a.dp || a.endpoint != v.request.pipe {
            return Err(Error::Invalid);
        }
        Self::frl_audio_budget(v, a.info)?;
        for (reg, mask, value) in [
            (FRL_PACKET, 1, 1),
            (FRL_SRC, 7, u32::from(a.endpoint)),
            (FRL_PACKET2, 0x1000_ff01, u32::from(a.channels) << 8),
            (FRL_ACR, 0x8000_1103, 0x1000),
            (FRL_INFO, 0x7fff_7000, 2 << 16 | 0x1000),
            (FRL_MEM, 0x30, 0),
            (0x8e1, 0x1f, u32::from(v.request.audio_packets_line)),
            (0x908, 3, if v.request.borrow_from_blank { 2 } else { 0 }),
        ] {
            let at = self.frl_at(reg);
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        let nc = frl_acr(v.link.character_khz).ok_or(Error::Unsupported)?;
        for (i, rate) in nc.chunks_exact(2).enumerate() {
            for (reg, mask, value) in [
                (0x8f2 + 2 * i as u64, 0xffff_f000, rate[1] << 12),
                (0x8f3 + 2 * i as u64, 0xfffff, rate[0]),
            ] {
                let at = self.frl_at(reg);
                if self.read(at)? & mask != value {
                    return Err(Error::Readback(at));
                }
            }
        }
        if self.az_read(a.endpoint, AZ_HOT_PLUG)? & (AUDIO_ENABLED | CLOCK_GATING_DISABLE)
            != AUDIO_ENABLED
        {
            return Err(Error::Readback(self.az_at(a.endpoint)));
        }
        Ok(())
    }
    pub(super) fn start_frl_audio(
        &mut self,
        path: Path,
        info: AudioInfo,
    ) -> Result<DisplayAudio, Error> {
        if self.status.frl_audio.is_some() {
            return Err(Error::Busy);
        }
        let v = self.frl_audio_video(path)?;
        let blank = v.timing.blank;
        let t = blank.timing.request.timing;
        let info = frl_lpcm_info(info, t.v_active).ok_or(Error::Unsupported)?;
        Self::frl_audio_budget(&v, info)?;
        let nc = frl_acr(v.link.character_khz).ok_or(Error::Unsupported)?;
        let depth = match blank.request.depth {
            ColorDepth::Bpc8 => dmub::TmdsDepth::Bpc8,
            ColorDepth::Bpc10 => dmub::TmdsDepth::Bpc10,
            ColorDepth::Bpc12 => dmub::TmdsDepth::Bpc12,
        };
        let (descriptors, _, _) = descriptors(&info, &t, Some(depth));
        if descriptors[0] & 0x7f00 == 0 {
            return Err(Error::Unsupported);
        }
        let a = DisplayAudio {
            info,
            dp: false,
            endpoint: v.request.pipe,
            channels: channels(info.speakers),
            descriptors,
            hbr: false,
        };
        if !self.audio_endpoint_available(a.endpoint) {
            return Err(Error::Busy);
        }
        self.frl_video_verify_running(&v)?;
        if self.az_read(a.endpoint, AZ_HOT_PLUG)? & AUDIO_ENABLED != 0 {
            return Err(Error::Busy);
        }
        // No await after publication: one poll finishes or retains the audio
        // and display owners in Failed. The wall DTO sees the new candidate.
        self.status.frl_audio = Some(a);
        let result = (|| {
            self.audio_wall_dto()?;
            let at = self.frl_at(FRL_PACKET);
            self.access(|io| {
                let old = checked(io.read(at))?;
                io.write(at, old | 0x0400_0000);
                Ok(())
            })?;
            for (reg, mask, value) in [
                (FRL_PACKET2, 0x1000_0001, 0),
                (0x920, 0x30f0_0000, 0x0010_0000),
                (0x921, 0x00f0_0000, 0x0020_0000),
                (0x927, 0x00ff_ffff, 0x0087_6543),
                (FRL_ACR, 0x8000_1100, 0x1000),
            ] {
                self.update(self.frl_at(reg), mask, value)?;
            }
            for (i, rate) in nc.chunks_exact(2).enumerate() {
                self.update(
                    self.frl_at(0x8f2 + 2 * i as u64),
                    0xffff_f000,
                    rate[1] << 12,
                )?;
                self.update(self.frl_at(0x8f3 + 2 * i as u64), 0xfffff, rate[0])?;
            }
            self.update(self.frl_at(FRL_SRC), u32::MAX, u32::from(a.endpoint))?;
            self.update(self.frl_at(FRL_PACKET2), 0xff00, u32::from(a.channels) << 8)?;
            self.update(self.frl_at(FRL_MEM), 0x30, 0)?;
            self.hdmi_audio_endpoint(&a, false)?;
            let at = self.frl_at(0x92b);
            self.access(|io| {
                let old = checked(io.read(at))?;
                io.write(at, old | 0x80);
                Ok(())
            })?;
            self.update(self.frl_at(FRL_INFO), 0x7fff_7000, 2 << 16 | 0x1000)?;
            self.az_update(
                a.endpoint,
                AZ_HOT_PLUG,
                AUDIO_ENABLED | 1,
                AUDIO_ENABLED | 1,
            )?;
            self.az_update(a.endpoint, AZ_HOT_PLUG, 1, 0)?;
            self.update(self.frl_at(FRL_PACKET), 1, 1)?;
            self.frl_video_verify_running(&v)
        })();
        if let Err(e) = result {
            self.status.state = State::Failed(e);
            return Err(e);
        }
        Ok(a)
    }
    pub(super) fn stop_frl_audio(&mut self, path: Path) -> Result<(), Error> {
        let a = self.status.frl_audio.ok_or(Error::Invalid)?;
        let v = self.frl_audio_video(path)?;
        self.frl_video_verify_running(&v)?;
        let result = (|| {
            self.update(self.frl_at(FRL_PACKET), 1, 0)?;
            self.update(self.frl_at(FRL_ACR), 0x1003, 0)?;
            // Keep the stream owner's Audio InfoFrame and AFMT memory state.
            self.az_disable(a.endpoint)?;
            self.frl_audio_quiet()?;
            if self.az_read(a.endpoint, AZ_HOT_PLUG)? & (AUDIO_ENABLED | 1) != 0 {
                return Err(Error::Readback(self.az_at(a.endpoint)));
            }
            self.status.frl_audio = None;
            self.audio_wall_dto()?;
            self.frl_video_verify_running(&v)
        })();
        if let Err(e) = result {
            self.status.frl_audio = Some(a);
            self.status.state = State::Failed(e);
            return Err(e);
        }
        Ok(())
    }
}
