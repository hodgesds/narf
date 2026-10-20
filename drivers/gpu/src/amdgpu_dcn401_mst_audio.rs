//! Legacy MST LPCM uses the stream's DIO AFMT, not the shared link's index.
//! Only a completed manager payload plus fresh source SAT/VC witnesses may
//! expose an endpoint. Audio never changes that allocation or another stream.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MstAudioPayload {
    pub slots: u8,
    /// DP_MSE_RATE_CNTL for the retained timing and trained link.
    pub rate: u32,
}

/// Legacy MST LPCM within Linux's blanking budget; compressed SADs pass
/// through as dce_aud_az_configure programs them.
#[cfg(feature = "kernel-test")]
pub(crate) fn mst_audio_info(
    info: AudioInfo,
    timing: &Timing,
    bpc: u32,
    settings: DpPhySettings,
) -> Option<AudioInfo> {
    mst_audio_info_with(info, timing, bpc, settings, None)
}
/// `mst_audio_info` for a stream compressed with `dsc`: Linux budgets its
/// DSC bits per pixel and slice EOC symbols (build_audio_output's dsc_cfg).
pub(crate) fn mst_audio_info_with(
    info: AudioInfo,
    timing: &Timing,
    bpc: u32,
    settings: DpPhySettings,
    dsc: Option<&crate::amdgpu_dsc::DscConfig>,
) -> Option<AudioInfo> {
    let dsc = bandwidth::AudioDsc::of(dsc);
    filtered_audio_info(info, |channels, rates| {
        bandwidth::rates(
            timing,
            bpc,
            bandwidth::AudioLink::Mst(settings),
            channels,
            rates,
            dsc,
        )
    })
}
/// dce_aud_az_configure's HBR probe on the MST stream.
fn mst_hbr(
    timing: &Timing,
    bpc: u32,
    settings: DpPhySettings,
    dsc: Option<&crate::amdgpu_dsc::DscConfig>,
) -> bool {
    bandwidth::rates(
        timing,
        bpc,
        bandwidth::AudioLink::Mst(settings),
        8,
        0x40,
        bandwidth::AudioDsc::of(dsc),
    )
    .is_some_and(|r| r & 0x40 != 0)
}
fn depth(f: &DpFrontendReady) -> u32 {
    match f.blank.request.depth {
        ColorDepth::Bpc8 => 8,
        ColorDepth::Bpc10 => 10,
        ColorDepth::Bpc12 => 12,
    }
}
fn payload(f: &DpFrontendReady, slots: u8) -> Result<MstAudioPayload, Error> {
    let s = f.link.phy.settings;
    if !s.mst
        || !matches!(s.lanes, 1 | 2 | 4)
        || slots == 0
        || slots > 63
        || f.blank.request.ycbcr420
    {
        return Err(Error::Unsupported);
    }
    let raw = s.rate as u32 * 27_000 * 8 * u32::from(s.lanes);
    let link = if f.link.fec { raw / 100 * 97 } else { raw };
    let request = &f.blank.timing.request;
    // A compressed stream's VC rate is its compressed bandwidth
    // (dc_bandwidth_in_kbps_from_timing), as the manager programmed it.
    let kbps = match request.dsc {
        Some(cfg) => crate::amdgpu_dsc::dsc_kbps(
            &crate::amdgpu_dcn401_otg::dsc_hw::dsc_timing(&request.timing, cfg.bpc),
            cfg.bpp_x16,
            cfg.slices_h,
        ),
        None => request
            .timing
            .pixel_clock_khz
            .checked_mul(depth(f) * 3)
            .ok_or(Error::Invalid)?,
    };
    let (x, y) = vc_rate(kbps, link).ok_or(Error::Invalid)?;
    if kbps == 0 || x + u32::from(y != 0) > u32::from(slots) {
        return Err(Error::Invalid);
    }
    Ok(MstAudioPayload {
        slots,
        rate: x << 26 | y,
    })
}
impl<I: Io> Engine<I> {
    pub(in crate::amdgpu_dcn401_otg) fn mst_audio_verify_payload(
        &mut self,
        f: &DpFrontendReady,
        p: MstAudioPayload,
    ) -> Result<(), Error> {
        if payload(f, p.slots)? != p {
            return Err(Error::Invalid);
        }
        let l = self.layout;
        let link = |r| DpStream::Dio(f.link.phy.path.transmitter).at(l, r);
        let stream = |r| DpStream::Dio(f.request.stream).at(l, r);
        for (at, mask, value) in [
            (link(0x2153), 0x103, 0),
            (stream(0x214f), 1, 0),
            (stream(0x214d), u32::MAX, p.rate),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        let mut found = false;
        let mut seen = 0u8;
        let mut total = 0u32;
        let allowed = self.display_records().fold(0u8, |mask, status| {
            status.dp_frontend_ready.map_or(mask, |other| {
                if other.link.phy.settings.mst && other.link.phy.path == f.link.phy.path {
                    mask | (1 << other.request.stream)
                } else {
                    mask
                }
            })
        });
        for at in [link(0x2150), link(0x2151)] {
            let value = self.read(at)?;
            for shift in [0, 16] {
                let row = value >> shift;
                let s = (row & 7) as u8;
                let n = (row >> 8 & 63) as u8;
                if n == 0 {
                    continue;
                }
                if s >= 4 || seen & (1 << s) != 0 {
                    return Err(Error::Readback(at));
                }
                seen |= 1 << s;
                total += u32::from(n);
                if s == f.request.stream {
                    if n != p.slots {
                        return Err(Error::Readback(at));
                    }
                    found = true;
                } else if allowed & (1 << s) == 0 {
                    return Err(Error::Readback(at));
                }
            }
        }
        if !found || total > 63 {
            return Err(Error::Readback(link(0x2150)));
        }
        Ok(())
    }
    pub(in crate::amdgpu_dcn401_otg) async fn start_mst_audio(
        &mut self,
        path: Path,
        info: AudioInfo,
        slots: u8,
    ) -> Result<DisplayAudio, Error> {
        // 128b/132b MST: the HPO stream's APG, budgeted as Linux budgets
        // 128b/132b SST.
        if self.status.uhbr_video_running.is_some() {
            return self.start_uhbr_audio(path, info, Some(slots)).await;
        }
        if self.status.dp_audio.is_some() || self.status.mst_audio_payload.is_some() {
            return Err(Error::Busy);
        }
        let f = self.dp_audio_frontend(path)?;
        let p = payload(&f, slots)?;
        let t = f.blank.timing.request.timing;
        let dsc = f.blank.timing.request.dsc;
        let info = mst_audio_info_with(info, &t, depth(&f), f.link.phy.settings, dsc.as_ref())
            .ok_or(Error::Unsupported)?;
        let (descriptors, ac3, _) = descriptors(&info, &t, None);
        let a = DisplayAudio {
            info,
            dp: true,
            endpoint: f.request.stream,
            channels: channels(info.speakers),
            descriptors,
            hbr: mst_hbr(&t, depth(&f), f.link.phy.settings, dsc.as_ref()),
        };
        if !self.audio_endpoint_available(a.endpoint) {
            return Err(Error::Busy);
        }
        self.dp_audio_verify_transport()?;
        self.mst_audio_verify_payload(&f, p)?;
        self.mst_audio_quiet(&f)?;
        if self.az_read(a.endpoint, AZ_HOT_PLUG)? & AUDIO_ENABLED != 0 {
            return Err(Error::Busy);
        }
        self.status.dp_audio = Some(a);
        self.status.mst_audio_payload = Some(p);
        // dp_audio_start performs no suspended hardware wait. Record both
        // owners first and retain them on any partial programming failure.
        let result = async {
            self.dp_audio_start(f, a, ac3).await?;
            self.dp_audio_verify_transport()
        }
        .await;
        if let Err(e) = result {
            self.status.state = State::Failed(e);
            return Err(e);
        }
        Ok(a)
    }
    /// No audio clock, samples or packets. As for SST, a compressed stream's
    /// PPS owner holds the AFMT clock and secondary master, and the video's
    /// VSC/HDR SDPs hold GSP0/GSP3 and the master.
    fn mst_audio_quiet(&mut self, f: &DpFrontendReady) -> Result<(), Error> {
        let pps = u32::from(f.blank.timing.request.dsc.is_some());
        let sdp = f.request.sdp_enables();
        let at = |r| DpStream::Dio(f.request.stream).at(self.layout, r);
        for (reg, mask, value) in [
            (at(AFMT_CNTL), 1, pps),
            (at(AFMT_PACKET), 1, 0),
            (at(DP_SEC_CNTL), 0x1ff1_1111, pps | sdp),
        ] {
            if self.read(reg)? & mask != value {
                return Err(Error::Readback(reg));
            }
        }
        Ok(())
    }
    pub(super) fn stop_mst_audio(
        &mut self,
        f: DpFrontendReady,
        a: DisplayAudio,
    ) -> Result<(), Error> {
        let p = self.status.mst_audio_payload.ok_or(Error::Invalid)?;
        self.dp_audio_verify_transport()?;
        self.dp_audio_verify(&f, &a)?;
        let result = (|| {
            let layout = self.layout;
            let at = |r| DpStream::Dio(f.request.stream).at(layout, r);
            // disable_dio_audio_packet as for SST: the PPS keeps the AFMT
            // clock and master; info packets keep the master.
            let pps = u32::from(f.blank.timing.request.dsc.is_some());
            self.update(at(AFMT_PACKET), 1, 0)?;
            self.update(at(DP_SEC_CNTL), DP_SEC_AUDIO | 0x1_0000, pps)?;
            if pps == 0 && self.read(at(DP_SEC_CNTL))? != 0 {
                self.update(at(DP_SEC_CNTL), 1, 1)?;
            }
            self.update(at(AFMT_CNTL), 1, pps)?;
            self.az_disable(a.endpoint)?;
            self.mst_audio_quiet(&f)?;
            if self.az_read(a.endpoint, AZ_HOT_PLUG)? & (AUDIO_ENABLED | 1) != 0 {
                return Err(Error::Readback(self.az_at(a.endpoint)));
            }
            self.mst_audio_verify_payload(&f, p)?;
            self.status.dp_audio = None;
            self.status.mst_audio_payload = None;
            self.audio_wall_dto()?;
            self.dp_audio_verify_transport()
        })();
        if let Err(e) = result {
            self.status.dp_audio = Some(a);
            self.status.mst_audio_payload = Some(p);
            self.status.state = State::Failed(e);
            return Err(e);
        }
        Ok(())
    }
}
impl Otg {
    /// Start LPCM on the selected MST stream's completed payload (DIO on
    /// 8b/10b, the HPO stream's APG on 128b/132b).
    /// # Safety
    /// The manager has completed the sink/source payload transaction and owns
    /// `slots` for this stream. Exclude other payload/audio/video writers, as
    /// for start_dp_audio. A retained allocation is not permission to replay
    /// an uncertain manager transaction.
    pub(crate) async unsafe fn start_mst_audio(
        &mut self,
        path: Path,
        info: AudioInfo,
        slots: u8,
    ) -> Result<DisplayAudio, Error> {
        self.0.start_mst_audio(path, info, slots).await
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn dcn401_mst_audio_bandwidth_matches_linux() -> TestResult {
        for line in include_str!("../tests/dcn401_mst_audio/vectors.txt").lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (inputs, want) = line.split_once(" = ").unwrap();
            let v: alloc::vec::Vec<u32> = inputs
                .split_whitespace()
                .map(|s| s.parse().unwrap())
                .collect();
            let timing = Timing {
                pixel_clock_khz: v[0],
                h_active: v[1],
                h_total: v[2],
                h_front_porch: 1,
                h_sync_width: 1,
                v_active: 1080,
                v_total: 1125,
                v_front_porch: 1,
                v_sync_width: 1,
                h_sync_positive: true,
                v_sync_positive: true,
            };
            let settings = DpPhySettings {
                lanes: v[5] as u8,
                mst: true,
                rate: match v[4] {
                    6 => crate::dp_link_training::LinkRate::Rbr,
                    10 => crate::dp_link_training::LinkRate::Hbr,
                    20 => crate::dp_link_training::LinkRate::Hbr2,
                    _ => crate::dp_link_training::LinkRate::Hbr3,
                },
            };
            assert_eq!(
                bandwidth::rates(
                    &timing,
                    v[3],
                    bandwidth::AudioLink::Mst(settings),
                    v[6] as u8,
                    127,
                    None
                ),
                Some(want.parse().unwrap()),
                "{line}"
            );
        }
        TestResult::Pass
    }
    /// Compressed legacy MST streams (no minimum blank width on 8b/10b).
    fn dcn401_mst_dsc_audio_bandwidth_matches_linux() -> TestResult {
        let mut n = 0;
        for line in include_str!("../tests/dcn401_mst_audio/dsc_vectors.txt").lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (inputs, want) = line.split_once(" = ").unwrap();
            let v: alloc::vec::Vec<u32> = inputs
                .split_whitespace()
                .map(|s| s.parse().unwrap())
                .collect();
            assert_eq!(v[9], 0, "{line}");
            let timing = Timing {
                pixel_clock_khz: v[0],
                h_active: v[1],
                h_total: v[2],
                h_front_porch: 1,
                h_sync_width: 1,
                v_active: 2160,
                v_total: 2250,
                v_front_porch: 1,
                v_sync_width: 1,
                h_sync_positive: true,
                v_sync_positive: true,
            };
            let settings = DpPhySettings {
                lanes: v[5] as u8,
                mst: true,
                rate: match v[4] {
                    10 => crate::dp_link_training::LinkRate::Hbr,
                    20 => crate::dp_link_training::LinkRate::Hbr2,
                    _ => crate::dp_link_training::LinkRate::Hbr3,
                },
            };
            let dsc = bandwidth::AudioDsc {
                bpp_x16: v[7],
                slices: v[8],
            };
            assert_eq!(
                bandwidth::rates(
                    &timing,
                    v[3],
                    bandwidth::AudioLink::Mst(settings),
                    v[6] as u8,
                    127,
                    Some(dsc)
                ),
                Some(want.parse().unwrap()),
                "{line}"
            );
            n += 1;
        }
        assert_eq!(n, 1512);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn401-mst-audio",
        dcn401_mst_dsc_audio_bandwidth_matches_linux
    );
    kernel_test_in!(
        "drivers/gpu/dcn401-mst-audio",
        dcn401_mst_audio_bandwidth_matches_linux
    );
}
