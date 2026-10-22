//! Owned MST DP-to-HDMI endpoint limits. Capability fields and autonomous
//! post-training state follow link_dp_capability.c; DSC policy follows
//! get_conv_frl_bw/build_frl_mst_dsc_params. This source sends DP PPS/SDPs;
//! it never programs the source HDMI PHY or starts PCON source-controlled LT.
use super::*;
use crate::amdgpu_frl_cap::FrlAudio;
use crate::amdgpu_navi48_boot::modeset::{self, FrlDscStream, HdmiCaps};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Unavailable,
    Training,
    SourceControlled,
    Tmds,
    Frl,
}
/// A selected AUX route's immutable endpoint capabilities plus its most
/// recently confirmed autonomous output. Running streams retain their own
/// snapshot; refreshing dark proposals never rewrites a running payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pcon {
    pub aux: DscAux,
    pub detailed: [u8; 4],
    pub hdmi: HdmiCaps,
    pub audio: FrlAudio,
    pub passthrough: bool,
    pub state: State,
    pub raw_rate: u8,
    pub dsc_rate: u8,
}
impl Pcon {
    fn audio_for(self, t: &Timing) -> FrlAudio {
        FrlAudio {
            layout: if t.v_active > 576 {
                self.audio.layout
            } else {
                0
            },
            ..self.audio
        }
    }
    fn vic(self, t: &Timing) -> crate::amdgpu_dsc::Vic {
        let avi = modeset::hdmi_avi(self.hdmi, t);
        crate::amdgpu_dsc::Vic {
            cta: avi.vic,
            hdmi: avi.hdmi_vic,
        }
    }
    fn rgb(self, t: &Timing, bpc: u8) -> bool {
        let vic = self.vic(t).cta;
        let only420 =
            vic != 0 && self.hdmi.y420_only[usize::from(vic / 64)] & (1 << (vic % 64)) != 0;
        let converter_bpc = match self.detailed[2] & 3 {
            0 => 8,
            1 => 10,
            2 => 12,
            _ => 16,
        };
        !only420
            && bpc <= converter_bpc
            && match bpc {
                8 => true,
                10 => self.hdmi.dc30,
                12 => self.hdmi.dc36,
                _ => false,
            }
    }
    pub fn raw_allowed(self, t: &Timing, bpc: u8) -> bool {
        if !self.rgb(t, bpc) {
            return false;
        }
        match self.state {
            State::Frl => modeset::FrlRate::new(self.raw_rate).is_some_and(|rate| {
                modeset::frl_carries(t, bpc, false, rate, self.audio_for(t)).is_some()
            }),
            State::Tmds => {
                let character = (u64::from(t.pixel_clock_khz) * u64::from(bpc)).div_ceil(8);
                character <= u64::from(self.detailed[1]) * 2500
                    && modeset::hdmi_format(self.hdmi, t, bpc)
                        .is_some_and(|(depth, y420)| !y420 && modeset::depth_bpc(depth) == bpc)
            }
            _ => false,
        }
    }
    /// DP compressed input may either be decompressed by the converter
    /// into a raw HDMI output, or passed to a real HDMI DSC endpoint.
    pub fn allows(self, t: &Timing, bpc: u8, cfg: Option<&DscConfig>) -> bool {
        let Some(cfg) = cfg else {
            return self.raw_allowed(t, bpc);
        };
        if cfg.bpc != bpc {
            return false;
        }
        if !self.passthrough {
            return self.raw_allowed(t, bpc);
        }
        if self.state != State::Frl || !self.rgb(t, bpc) {
            return false;
        }
        let Some(caps) = self.hdmi.dsc else {
            return false;
        };
        let Some(rate) = modeset::FrlRate::new(self.dsc_rate) else {
            return false;
        };
        let cfg = DscConfig {
            frl: Some(crate::amdgpu_dsc::FrlDscLink {
                all_bpp: caps.all_bpp,
                max_rate: self.dsc_rate,
            }),
            ..*cfg
        };
        modeset::frl_dsc_carries(
            t,
            FrlDscStream {
                cfg,
                vic: self.vic(t),
            },
            rate,
            self.audio_for(t),
        )
        .is_some()
    }
    pub fn profile(self, s: &DscStream, link: &DscLink) -> (StreamConstraints, Option<DscConfig>) {
        let raw_allowed = self.raw_allowed(&s.timing, s.bpc);
        let denied = StreamConstraints {
            raw_allowed,
            dsc_range: None,
        };
        let Some(caps) = s.dsc else {
            return (denied, None);
        };
        if !self.passthrough {
            if !raw_allowed {
                return (denied, None);
            }
            let dt = mst_dsc_timing(&s.timing, s.bpc);
            let (min, max) = amdgpu_dsc::policy_bpp_x16(&dt, link.encoding);
            let cfg = config(s, link);
            let range = amdgpu_dsc::bandwidth_range(
                &caps,
                link.max_dispclk_khz,
                min,
                max,
                &dt,
                link.encoding,
            )
            .and_then(|mut r| {
                let c = cfg?;
                let step = (16 / caps.bpp_increment_div.max(1)).max(1);
                r.min_bpp_x16 = r.min_bpp_x16.div_ceil(step) * step;
                r.max_bpp_x16 = r.max_bpp_x16 / step * step;
                if r.max_bpp_x16 < r.min_bpp_x16 {
                    return None;
                }
                r.min_kbps = amdgpu_dsc::dsc_kbps(&dt, r.min_bpp_x16, c.slices_h);
                r.max_kbps = amdgpu_dsc::dsc_kbps(&dt, r.max_bpp_x16, c.slices_h);
                Some(r)
            });
            return (
                StreamConstraints {
                    raw_allowed,
                    dsc_range: range,
                },
                cfg,
            );
        }
        if self.state != State::Frl || self.dsc_rate == 0 || !self.rgb(&s.timing, s.bpc) {
            return (denied, None);
        }
        let dt = mst_dsc_timing(&s.timing, s.bpc);
        let Some(mut cfg) = amdgpu_dsc::compute_frl_config(
            &caps,
            link.max_dispclk_khz,
            self.dsc_rate,
            &dt,
            self.vic(&s.timing),
        ) else {
            return (denied, None);
        };
        let (min, policy_max) = amdgpu_dsc::policy_bpp_x16(&dt, link.encoding);
        let max = cfg.bpp_x16.min(policy_max);
        if max < min {
            return (denied, None);
        }
        let min = if caps.all_bpp { min } else { max };
        if min == 0 || max < min {
            return (denied, None);
        }
        // Capacity/padding is the existing primary FRL model, including
        // supported LPCM. Search only the finite DSC bpp precision range.
        let Some(max) = (min..=max).rev().find(|&bpp| {
            self.allows(
                &s.timing,
                s.bpc,
                Some(&DscConfig {
                    bpp_x16: bpp,
                    ..cfg
                }),
            )
        }) else {
            return (denied, None);
        };
        if !self.allows(
            &s.timing,
            s.bpc,
            Some(&DscConfig {
                bpp_x16: min,
                ..cfg
            }),
        ) {
            return (denied, None);
        }
        cfg.bpp_x16 = max;
        cfg.frl = None; // Native source is DP; the FRL link belongs to PCON.
        let range = amdgpu_dsc::BwRange {
            min_bpp_x16: min,
            max_bpp_x16: max,
            min_kbps: amdgpu_dsc::dsc_kbps(&dt, min, cfg.slices_h),
            max_kbps: amdgpu_dsc::dsc_kbps(&dt, max, cfg.slices_h),
            stream_kbps: amdgpu_dsc::stream_kbps(&dt, link.encoding),
        };
        (
            StreamConstraints {
                raw_allowed,
                dsc_range: Some(range),
            },
            Some(cfg),
        )
    }
}
/// Highest reported trained rate, as intersect_frl_link_bw_support. Never
/// infer a completed link from an empty mask or silently exceed its caps.
fn trained_rate(post: u8) -> u8 {
    (1..=6)
        .rev()
        .find(|&rate| post & (1 << rate) != 0)
        .unwrap_or(0)
}
async fn one<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    at: DscAux,
    address: u32,
) -> Result<u8, MstError<A::Error>> {
    Ok(super::read(manager, aux, topology, at, address, 1).await?[0])
}
/// All status reads are required for FRL. A source-controlled or unsettled
/// converter stays published but grants neither raw nor compressed FRL.
pub async fn refresh<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    old: Pcon,
) -> Result<Pcon, MstError<A::Error>> {
    let mut p = Pcon {
        state: State::Unavailable,
        raw_rate: 0,
        dsc_rate: 0,
        ..old
    };
    let detailed = super::read(manager, aux, topology, p.aux, 0x80, 4).await?;
    if detailed.as_slice() != p.detailed || p.detailed[0] & 7 != 3 {
        return Ok(p);
    }
    if p.passthrough && one(manager, aux, topology, p.aux, DSC_SUPPORT).await? & PASSTHROUGH == 0 {
        return Ok(p);
    }
    let declared = (p.detailed[2] >> 2) & 7;
    if declared > 6 {
        return Ok(p);
    }
    if declared != 0 && one(manager, aux, topology, p.aux, 0x305a).await? & 8 != 0 {
        p.state = State::SourceControlled;
        return Ok(p);
    }
    if declared == 0 || p.hdmi.max_frl_rate == 0 {
        p.state = State::Tmds;
        return Ok(p);
    }
    if !p.hdmi.hdmi || !p.hdmi.scdc {
        return Ok(p);
    }
    let autonomous = one(manager, aux, topology, p.aux, 0x303c).await?;
    let tx = one(manager, aux, topology, p.aux, 0x303b).await?;
    let post = one(manager, aux, topology, p.aux, 0x3036).await?;
    if autonomous & 1 != 0 || tx & 2 == 0 || autonomous & 0x80 != 0 && post & 0x80 == 0 {
        p.state = State::Training;
        return Ok(p);
    }
    let rate = trained_rate(post);
    if rate == 0 {
        if post & 1 == 0 && tx & 1 != 0 {
            p.state = State::Tmds;
        }
        return Ok(p);
    }
    p.state = State::Frl;
    p.raw_rate = declared.min(p.hdmi.max_frl_rate).min(rate);
    p.dsc_rate = p.hdmi.dsc.map_or(0, |d| d.max_frl_rate).min(p.raw_rate);
    Ok(p)
}
/// A detailed HDMI downstream port is retained even without DSC. Missing
/// FRL state must not erase the endpoint and fall back to unconstrained DP.
pub async fn probe<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    at: DscAux,
    edid: &[u8],
    basic: u8,
) -> Result<Option<Pcon>, MstError<A::Error>> {
    let hdmi = modeset::hdmi_caps(edid);
    let p = Pcon {
        aux: at,
        detailed: [0; 4],
        hdmi,
        audio: modeset::frl_audio(modeset::sink_audio_info(edid), u32::MAX),
        passthrough: basic & PASSTHROUGH != 0
            && hdmi.dsc.is_some_and(|d| d.max_frl_rate > 0)
            && hdmi.max_frl_rate > 0,
        state: State::Unavailable,
        raw_rate: 0,
        dsc_rate: 0,
    };
    // A failed capability read must not turn a virtual converter into an
    // unconstrained DP endpoint. Only a positive ordinary-DP identity permits
    // None. A terminal NAK retains an unavailable endpoint; uncertainty is
    // propagated to the caller's retained sideband journal.
    let downstream = match one(manager, aux, topology, at, 5).await {
        Ok(v) => v,
        Err(MstError::Nak(_)) => return Ok(Some(p)),
        Err(e) => return Err(e),
    };
    if downstream & 1 == 0 || downstream & 6 == 0 {
        return Ok(None);
    }
    if downstream & 6 != 4 || downstream & 0x10 == 0 {
        return Ok(Some(p));
    }
    let detailed = match super::read(manager, aux, topology, at, 0x80, 4).await {
        Ok(v) => <[u8; 4]>::try_from(v.as_slice()).map_err(|_| MstError::Malformed)?,
        Err(MstError::Nak(_)) => return Ok(Some(p)),
        Err(e) => return Err(e),
    };
    if detailed[0] & 7 != 3 {
        return Ok(Some(p));
    }
    let p = Pcon { detailed, ..p };
    match refresh(manager, aux, topology, p).await {
        Ok(v) => Ok(Some(v)),
        Err(MstError::Nak(_)) => Ok(Some(p)),
        Err(e) => Err(e),
    }
}
#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_mst_pcon_tests.rs"]
mod tests;
