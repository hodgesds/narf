//! Single-stream SubVP expansion from DML21 core_dcn4's phantom descriptor
//! expansion and PMO metadata. The caller supplies a MALL capacity owned by
//! this display; a successful calculation alone never enables firmware.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubvpProof {
    pub mall_bytes: u32,
    pub phantom: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Phantom {
    pub plan: Plan,
    pub mall_bytes: u32,
    pub mall_ways: u8,
}

impl Phantom {
    pub(crate) fn readmits(&self) -> bool {
        let Some(proof) = self.plan.pstate.and_then(|p| p.subvp) else {
            return false;
        };
        self.plan
            .subvp_main_mode()
            .and_then(|mode| {
                admit_subvp(
                    &self.plan.soc,
                    &self.plan.pstate?.uclk,
                    &mode,
                    proof.mall_bytes,
                )
                .ok()
                .flatten()
            })
            .is_some_and(|s| s.phantom.as_deref() == Some(self))
    }
}

/// The first native owner supports a single linear, unscaled RGB plane,
/// fixed refresh, one main HUBP and one phantom HUBP. Other configurations
/// retain the ordinary PMO search and pinned fallback.
pub fn admit_subvp(
    soc: &Soc,
    uclk: &UclkLevels,
    mode: &Mode,
    mall_bytes: u32,
) -> Result<Option<Supported>, Error> {
    if !(8 * 1024 * 1024..=64 * 1024 * 1024).contains(&mall_bytes)
        || !mall_bytes.is_power_of_two()
        || mode.dsc.is_some()
        || mode.encoding.is_420()
    {
        return Ok(None);
    }
    let normal = admit(soc, uclk, &[*mode], true)?;
    if !matches!(normal, Pstate::Pinned(Pinned::Firmware(Method::FwSvp))) {
        return Ok(None);
    }
    let mut main = mcache_shapes(soc, &[*mode], Policy::NATIVE)?;
    let p = prepare(soc, &mut main)?;
    let s = main[0];
    let pl = s.plane;
    if main.len() != 1
        || s.dpps != 1
        || s.odm != 1
        || pl.source != Source::Rgb
        || pl.swizzle != Swizzle::Linear
        || pl.dcc
        || pl.vertical_scan
        || pl.h_ratio != Plane::UNITY
        || pl.v_ratio != Plane::UNITY
        || u32::from(pl.viewport_width) != mode.timing.h_active
        || u32::from(pl.viewport_height) != mode.timing.v_active
    {
        return Ok(None);
    }
    let table = min_clock_table(soc, uclk);
    for lat in 0..table.len() {
        let Ok((base, _)) = run(soc, &main, &p, &table, uclk, lat, &Overrides::NONE) else {
            continue;
        };
        let m = meta(&mode.timing, 1, s.phantom_lines(base.lat.urgent));
        let vactive = m.phantom_vactive as u32;
        let height = vactive.div_ceil(16) * 16;
        if height > u32::from(pl.viewport_height)
            || m.phantom_vtotal > 32767
            || m.subvp.allow_start >= m.subvp.allow_end
            || m.nom_refresh_hz > SUBVP_MAX_REFRESH_HZ
        {
            continue;
        }
        let mut phantom_mode = *mode;
        phantom_mode.timing.v_active = vactive;
        phantom_mode.timing.v_total = m.phantom_vtotal as u32;
        phantom_mode.timing.v_front_porch = m.phantom_vfp as u32;
        phantom_mode.timing.v_sync_width = 1;
        let mut phantom_plane = pl;
        phantom_plane.viewport_height = height as u16;
        phantom_mode.planes[0] = Some(phantom_plane);
        let mut phantom =
            Shape::with_pipes(&phantom_mode, phantom_plane, 1, 1, 1, soc.umc_channels)?;
        phantom.stream = 1;
        phantom.phantom = true;
        let mut shapes = [s, phantom];
        let p = prepare(soc, &mut shapes)?;
        let mut ov = Overrides::NONE;
        let (_, mut sup) = match run(soc, &shapes, &p, &table, uclk, lat, &ov) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let next = Overrides::all(SR_ENTER_PLUS_EXIT_US);
        if stutter_allowed(&shapes) {
            if let Ok((_, supported)) = run(soc, &shapes, &p, &table, uclk, lat, &next) {
                ov = next;
                sup = supported;
            }
        }
        // Linear ReadBlockWidth=256/bpp, ReadBlockHeight=1, stationary
        // viewport. Reserve its full aligned footprint plus DC's two cache
        // lines for worst-case alignment when converting bytes to ways.
        let width = u32::from(pl.viewport_width).div_ceil(256 / u32::from(pl.bytes_per_pixel))
            * (256 / u32::from(pl.bytes_per_pixel));
        let bytes = width * height * u32::from(pl.bytes_per_pixel);
        let lines_per_way = mall_bytes / 64 / 16;
        let ways = (bytes / 64 + 2).div_ceil(lines_per_way);
        if bytes > mall_bytes || ways > 16 {
            continue;
        }
        let level = table[lat];
        let active = minimums(
            &sup,
            &level,
            soc.umc_channels,
            Some(URGENT_ACTIVE),
            AVERAGE_ACTIVE,
        );
        let mall = Support {
            average_sdp_kbps: sup.mall_average[0],
            average_dram_kbps: sup.mall_average[1],
            urgent_sdp_kbps: sup.mall_urgent[0],
            urgent_dram_kbps: sup.mall_urgent[1],
            ..sup
        };
        let prefetch = minimums(
            &mall,
            &level,
            soc.umc_channels,
            Some(URGENT_PREFETCH),
            AVERAGE_PREFETCH,
        );
        let idle = minimums(&sup, &level, soc.umc_channels, None, IDLE_AVERAGE);
        let clocks = |v: [f64; 3]| -> Option<MinClocks> {
            Some(MinClocks {
                uclk_khz: uclk_dpm(uclk, v[0])?,
                fclk_khz: (v[1] <= f64::from(soc.fclk_khz[1])).then_some(v[1] as u32)?,
                dcfclk_khz: (v[2] <= f64::from(soc.dcfclk_khz[1])).then_some(v[2] as u32)?,
            })
        };
        let Some(active) = clocks(core::array::from_fn(|i| max_f(active[i], prefetch[i]))) else {
            continue;
        };
        let Some(idle) = clocks(idle) else {
            continue;
        };
        let ctx = Ctx {
            level: Level {
                uclk_khz: active.uclk_khz,
                fclk_khz: active.fclk_khz,
                dcfclk_khz: active.dcfclk_khz,
                dram_bw_kbps: u64::from(active.uclk_khz)
                    * u64::from(soc.umc_channels)
                    * CHANNEL_BYTES
                    * TRANSACTIONS_PER_CLOCK,
            },
            index: uclk
                .levels()
                .iter()
                .position(|&v| v == active.uclk_khz)
                .unwrap_or(0),
            ..ctx_at(&table, uclk, lat)
        };
        let mut plans = program(soc, &[*mode, phantom_mode], &shapes, &p, &ctx, &ov, None)?;
        let mut phantom = plans.pop().ok_or(Error::Invalid)?;
        let mut main = plans.pop().ok_or(Error::Invalid)?;
        for (plan, is_phantom) in [(&mut main, false), (&mut phantom, true)] {
            plan.stream = u8::from(is_phantom);
            plan.streams = [None; MAX_STREAMS - 1];
            plan.pstate = Some(PlanPstate {
                uclk: *uclk,
                fams2: true,
                method: Method::FwSvp,
                drr: [None; MAX_STREAMS],
                subvp: Some(SubvpProof {
                    mall_bytes,
                    phantom: is_phantom,
                }),
            });
        }
        // Phantom readmission reconstructs from the main mode retained here.
        phantom.streams[0] = Some(*mode);
        let usable = main
            .planes
            .iter()
            .flatten()
            .all(|p| p.ttu.min_ttu_vblank > main.watermarks.uclk_pstate);
        let mut fams = [Fams2Stream::default(); MAX_STREAMS];
        fams[0] = fams2_stream(&mode.timing, &m, Method::FwSvp, usable);
        fams[0].allow_start_otg_vline = m.subvp.allow_start as u16;
        fams[0].allow_end_otg_vline = m.subvp.allow_end as u16;
        fams[0].clamp_vtotal_min = true;
        fams[0].subvp = Some(SubvpSubstate {
            phantom_vtotal: m.phantom_vtotal as u16,
            phantom_vactive: m.phantom_vactive as u16,
            programming_delay: m.subvp_programming as u8 as u16,
            prefetch_to_mall: m.subvp_prefetch_to_mall as u8 as u16,
        });
        return Ok(Some(Supported {
            plans: alloc::vec![main],
            methods: [Method::FwSvp, Method::Na, Method::Na, Method::Na],
            level: lat as u8,
            active,
            idle,
            fclk_pstate: true,
            fams2_required: true,
            fams2_streams: alloc::boxed::Box::new(fams),
            phantom: Some(alloc::boxed::Box::new(Phantom {
                plan: phantom,
                mall_bytes: bytes,
                mall_ways: ways as u8,
            })),
        }));
    }
    Ok(None)
}
