//! Several Navi22 displays lit together, as Linux DC commits a context with
//! more than one stream on DCN3.0:
//!
//! - resources (`dcn30_resource.c`): each stream's pipe, DIG frontend and
//!   clock source as for one stream, a PHY PLL shared by HDMI streams of
//!   identical timing (`resource_find_used_clk_src_for_sharing`), the ODM
//!   secondary pipe from the top of the pool (`dcn30_find_split_pipe`) and
//!   each pipe's own DSC engine (`dcn20_acquire_dsc`, one per pipe);
//! - admission: every stream's timing, then one joint DML30 plan
//!   ([`crate::amdgpu_dml30::plan_joint`]): one DISPCLK/DPPCLK, one HUBBUB
//!   watermark set, each pipe its own DLG/TTU, ODM 2:1 where one pipe
//!   cannot carry a stream (DCN3.0's DET is a fixed 184 KiB per pipe, so
//!   there is no DET split to program);
//! - `dc_commit_state`: `dcn30_init_hw` once, `prepare_bandwidth` once for
//!   the whole context (clocks, then watermarks), then per stream
//!   `dce110_apply_single_controller_ctx_to_hw` (`dcn20_enable_stream_timing`
//!   with `optc3_set_odm_combine`, then `link_set_dpms_on`: HDMI, DP SST,
//!   DP SST with DSC and FEC, or a DP MST stream with its VC payload), then
//!   `dcn20_program_front_end_for_ctx` for every pipe under its OTG's lock;
//! - teardown in the reverse order.
//!
//! The single-stream [`Pipeline`] stays the owner of each stream's blocks;
//! this owner sequences them (the first pipeline also does the shared init,
//! clocks and HUBBUB). Everything is retained on failure; nothing is
//! retried or reset.
use super::*;
use crate::{
    amdgpu_dcn30_dsc as dsc, amdgpu_dcn30_mst as mst,
    amdgpu_dml30::{JointPlan, Odm, PlanePlan},
    dp_mst_mgr,
};

// ── Resources for several streams ──────────────────────────────────────

/// The resources one stream of a multi-stream context holds: its route,
/// its ODM secondary pipe, and whether each of its pipes' DSC engines is
/// in use (DSC n belongs to pipe n).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lease {
    pub route: Route,
    pub odm_pipe: Option<u8>,
    pub dsc: bool,
}
impl Lease {
    /// The stream's pipes, OTG master first.
    pub fn pipes(&self) -> impl Iterator<Item = u8> {
        core::iter::once(self.route.pipe).chain(self.odm_pipe)
    }
}

/// `resource_are_streams_timing_synchronizable` for two 8-bpc RGB TMDS
/// streams (equal clamping depth, PHY clock and view format; no
/// `ignore_msa_timing_param`).
pub fn synchronizable(a: &Timing, b: &Timing) -> bool {
    a.h_total == b.h_total
        && a.v_total == b.v_total
        && a.h_active == b.h_active
        && a.v_active == b.v_active
        && a.v_front_porch == b.v_front_porch
        && a.pixel_clock_khz == b.pixel_clock_khz
}

impl Resources {
    /// One fewer stream on PHY PLL `pll`: true while others still share it.
    pub(super) fn unshare_pll(&mut self, pll: u8) -> bool {
        let p = usize::from(pll);
        if self.pll_sharers[p] > 0 {
            self.pll_sharers[p] -= 1;
            return true;
        }
        self.pll_timing[p] = None;
        false
    }
    /// `resource_map_pool_resources` + `resource_map_clock_resources` for
    /// one stream of a multi-stream context at `timing`, then
    /// `dcn30_internal_validate_bw`'s ODM split and DSC acquisition: the
    /// first free pipe; the DIG frontend [`Resources::acquire`] picks; for
    /// HDMI the PLL of an earlier stream whose timing is synchronizable
    /// (`is_sharable_clk_src`; DP streams use the DP DTO and never share),
    /// else the first free one; for ODM 2:1 the highest free pipe as the
    /// secondary; and DSC n for each pipe n. All or nothing.
    pub fn acquire_stream(
        &mut self,
        connector: &Connector,
        timing: &Timing,
        odm: Odm,
        dsc: bool,
    ) -> Result<Lease, Error> {
        let mut next = *self;
        let pipe = first_free(next.pipes, next.capacity).ok_or(Error::Busy)?;
        let preferred = connector.path.transmitter;
        if preferred >= next.capacity {
            return Err(Error::Invalid);
        }
        let stream = if next.streams & 1 << preferred == 0 {
            preferred
        } else {
            (0..next.capacity)
                .rev()
                .find(|i| next.streams & 1 << i == 0)
                .ok_or(Error::Busy)?
        };
        let clock = match connector.signal {
            Signal::DisplayPort => ClockSource::DpDto,
            Signal::Hdmi => {
                let shared = (0..next.capacity).find(|&p| {
                    next.plls & 1 << p != 0
                        && next.pll_timing[usize::from(p)]
                            .is_some_and(|t| synchronizable(&t, timing))
                });
                match shared {
                    Some(p) => {
                        next.pll_sharers[usize::from(p)] += 1;
                        ClockSource::Pll(p)
                    }
                    None => {
                        let p = first_free(next.plls, next.capacity).ok_or(Error::Busy)?;
                        next.plls |= 1 << p;
                        next.pll_sharers[usize::from(p)] = 0;
                        next.pll_timing[usize::from(p)] = Some(*timing);
                        ClockSource::Pll(p)
                    }
                }
            }
        };
        next.pipes |= 1 << pipe;
        next.streams |= 1 << stream;
        let odm_pipe = match odm {
            Odm::None => None,
            Odm::TwoToOne => {
                let p = (0..next.capacity)
                    .rev()
                    .find(|i| next.pipes & 1 << i == 0)
                    .ok_or(Error::Busy)?;
                next.pipes |= 1 << p;
                Some(p)
            }
        };
        let lease = Lease {
            route: Route {
                pipe,
                stream,
                clock,
            },
            odm_pipe,
            dsc,
        };
        if dsc {
            for p in lease.pipes() {
                if next.dscs & 1 << p != 0 {
                    return Err(Error::Busy);
                }
                next.dscs |= 1 << p;
            }
        }
        *self = next;
        Ok(lease)
    }
    /// Return a retired stream's resources to the pool.
    pub fn release_stream(&mut self, lease: &Lease) {
        self.release(lease.route);
        if let Some(p) = lease.odm_pipe {
            self.pipes &= !(1 << p);
        }
        if lease.dsc {
            for p in lease.pipes() {
                self.dscs &= !(1 << p);
            }
        }
    }
}

// ── ODM combine and MPC rate control (DCN3.0 OPTC/MPC) ─────────────────

const ODM0_OPTC_DATA_SOURCE_SELECT: u64 = 0x1acb; // linux: mmODM0_OPTC_DATA_SOURCE_SELECT
const OPTC_SEG0_SHIFT: u32 = 8; // linux: ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG0_SRC_SEL__SHIFT
const OPTC_SEG1_SHIFT: u32 = 12; // linux: ODM0_OPTC_DATA_SOURCE_SELECT__OPTC_SEG1_SRC_SEL__SHIFT
const ODM0_OPTC_WIDTH_CONTROL: u64 = 0x1ace; // linux: mmODM0_OPTC_WIDTH_CONTROL
const OPTC_SEGMENT_WIDTH: u32 = 0x1fff; // linux: ODM0_OPTC_WIDTH_CONTROL__OPTC_SEGMENT_WIDTH_MASK
const ODM0_OPTC_MEMORY_CONFIG: u64 = 0x1ad0; // linux: mmODM0_OPTC_MEMORY_CONFIG
const OTG0_OTG_H_TIMING_CNTL: u64 = 0x1b2e; // linux: mmOTG0_OTG_H_TIMING_CNTL
/// `MPC_OUTn_MUX` (DCN base index 3, stride 4) and its rate control.
const MPC_OUT0_MUX: u64 = 0x0580; // linux: mmMPC_OUT0_MUX
const MPC_OUT_STRIDE: u64 = 4; // linux: mmMPC_OUT1_MUX - mmMPC_OUT0_MUX
const MPC_OUT_RATE_CONTROL_DISABLE: u32 = 1 << 8; // linux: MPC_OUT0_MUX__MPC_OUT_RATE_CONTROL_DISABLE_MASK
const MPC_OUT_RATE_CONTROL: u32 = 1 << 9; // linux: MPC_OUT0_MUX__MPC_OUT_RATE_CONTROL_MASK

impl Pipeline {
    fn odm_reg(&self, reg: u64) -> u64 {
        self.d2(reg + u64::from(self.route.pipe) * ODM_STRIDE)
    }
    /// `optc3_set_odm_combine` for two OPPs: each instance's two memories,
    /// the two input segments, the segment width and H timing divided by
    /// two. The shared OTG owner's timing programming writes the bypass
    /// form of these registers, so this runs after it (still before the
    /// OTG starts), where Linux runs it just before.
    fn set_odm_combine(&mut self, opps: [u8; 2], segment_width: u32) -> Result<(), Error> {
        if opps.iter().any(|&o| o >= PIPES)
            || segment_width == 0
            || segment_width > OPTC_SEGMENT_WIDTH
        {
            return Err(Error::Invalid);
        }
        let memory = 0x3u32 << (opps[0] * 2) | 0x3 << (opps[1] * 2);
        self.regs
            .write(self.odm_reg(ODM0_OPTC_MEMORY_CONFIG), memory)?;
        self.regs.write(
            self.odm_reg(ODM0_OPTC_DATA_SOURCE_SELECT),
            1 | u32::from(opps[0]) << OPTC_SEG0_SHIFT | u32::from(opps[1]) << OPTC_SEG1_SHIFT,
        )?;
        self.regs.update(
            self.odm_reg(ODM0_OPTC_WIDTH_CONTROL),
            OPTC_SEGMENT_WIDTH,
            segment_width,
        )?;
        self.regs.write(self.otg_reg(OTG0_OTG_H_TIMING_CNTL), 1)
    }
    /// `optc3_set_odm_bypass`: one segment from this OTG's own OPP, the
    /// others parked, no division and no memory.
    fn set_odm_bypass(&mut self) -> Result<(), Error> {
        let pipe = u32::from(self.route.pipe);
        self.regs.write(
            self.odm_reg(ODM0_OPTC_DATA_SOURCE_SELECT),
            pipe << OPTC_SEG0_SHIFT | 0xf << 12 | 0xf << 16 | 0xf << 20,
        )?;
        self.regs
            .update(self.otg_reg(OTG0_OTG_H_TIMING_CNTL), 0x3, 0)?;
        self.regs.write(self.odm_reg(ODM0_OPTC_MEMORY_CONFIG), 0)
    }
    /// `mpc3_set_out_rate_control`: DCN3.0 always turns the MPC's output
    /// rate and flow control off, for every OPP of the stream.
    pub(super) fn mpc_rate_control_off(&mut self, opp: u8) -> Result<(), Error> {
        let reg = self.dcn3 + (MPC_OUT0_MUX + u64::from(opp) * MPC_OUT_STRIDE) * 4;
        self.regs.update(
            reg,
            MPC_OUT_RATE_CONTROL_DISABLE | MPC_OUT_RATE_CONTROL,
            MPC_OUT_RATE_CONTROL_DISABLE,
        )
    }
    /// `dcn20_power_on_plane_resources` for pipe `pipe` (an ODM slice);
    /// as [`Pipeline::power_on_plane`].
    async fn power_on_pipe(&mut self, pipe: u8) -> Result<(), Error> {
        let p = u64::from(pipe);
        let request = self.d2(DC_IP_REQUEST_CNTL);
        self.regs.write(request, 1)?;
        if pipe != 5 {
            for domain in [2 * p + 1, 2 * p] {
                let config = self.d2(DOMAIN0_PG_CONFIG + 2 * domain);
                self.regs.update(config, DOMAIN_POWER_GATE, 0)?;
                if !self
                    .regs
                    .wait(config + 4, DOMAIN_PGFSM_PWR_STATUS, 0, 1, 1000)
                    .await?
                {
                    let _ = self.regs.write(request, 0);
                    return Err(Error::Block(crate::amdgpu_dcn_clk::Error::Timeout));
                }
            }
        }
        self.regs.write(request, 0)?;
        let clock = self.d2(HUBP0_HUBP_CLK_CNTL + p * HUBP_STRIDE);
        self.regs
            .update(clock, HUBP_CLOCK_ENABLE, HUBP_CLOCK_ENABLE)
    }
    /// `HUBP_UNDERFLOW_STATUS` of pipe `pipe`, cleared or read.
    fn hubp_underflow(&mut self, pipe: u8, clear: bool) -> Result<u8, Error> {
        let reg = self.d2(HUBP0_DCHUBP_CNTL + u64::from(pipe) * HUBP_STRIDE);
        if clear {
            self.regs
                .update(reg, HUBP_UNDERFLOW_CLEAR, HUBP_UNDERFLOW_CLEAR)?;
            return Ok(0);
        }
        Ok(((self.regs.read(reg)? & HUBP_UNDERFLOW_STATUS) >> 28) as u8)
    }
    /// `hubp2_program_deadline`'s cursor half for pipe `pipe`.
    fn program_cursor_ttu_at(
        &mut self,
        pipe: u8,
        ttu: Option<dml30::CursorTtu>,
    ) -> Result<(), Error> {
        let Some(ttu) = ttu else {
            return Ok(());
        };
        let hubp = u64::from(pipe) * HUBP_STRIDE;
        self.regs.write(
            self.d2(HUBP0_DCN_CUR0_TTU_CNTL0 + hubp),
            ttu.refcyc_per_req_delivery & 0x007f_ffff
                | (ttu.qos_level_fixed & 0xf) << 24
                | (ttu.qos_ramp_disable & 1) << 28,
        )?;
        self.regs.write(
            self.d2(HUBP0_DCN_CUR0_TTU_CNTL1 + hubp),
            ttu.refcyc_per_req_delivery_pre & 0x007f_ffff,
        )
    }
}

/// An ODM secondary pipe's front end: the second half of the line.
#[derive(Debug)]
pub struct Slice {
    pub pipe: u8,
    hubp: Hubp,
    dpp: Dpp,
    mpc: Mpc,
    opp: Opp,
}

// ── Requests and admission ─────────────────────────────────────────────

/// One display of a configuration: a board connector (index `link` in the
/// board's connector list, which is also its AUX index), the sink on it
/// and, for an MST end device behind it, that device.
#[derive(Clone, Debug)]
pub struct Request {
    pub link: usize,
    pub connector: Connector,
    pub sink: Sink,
    /// DRM's timing; None: the sink's preferred.
    pub want: Option<Timing>,
    pub mst: Option<dp_mst_mgr::Sink>,
}

/// One admitted stream: its timing and what carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPlan {
    pub timing: Timing,
    /// The HDMI stream m5hdmi's `select_hdmi` admitted (format, clocks,
    /// scrambling, InfoFrames).
    pub hdmi: Option<hdmi::Stream>,
    /// The DP link the stream trains at (`decide_dp_link_settings` on the
    /// verified link), or the shared MST link.
    pub link: Option<DpLink>,
    pub dsc: Option<DscConfig>,
    /// An MST stream's PBN, time slots and VC rate.
    pub mst: Option<(u16, u8, (u32, u32))>,
}
use crate::amdgpu_dsc::DscConfig;

/// What the admission knows of each connector before it decides: the HDMI
/// ceilings from the VBIOS encoder caps, or the DP link verified at
/// detection plus the sink's DSC and FEC caps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DpExtra {
    pub hdmi: Option<hdmi::Limits>,
    pub verified: Option<DpLink>,
    pub dsc: [u8; 16],
    pub fec: u8,
}

/// The DCN30 stream for one candidate.
fn dml_stream(
    timing: &Timing,
    vco_khz: u32,
    phy_khz: u32,
    dsc: Option<&DscConfig>,
) -> dml30::Stream {
    dml30::Stream {
        config: config(timing, vco_khz),
        dsc: dsc.map(|c| dml30::Dsc {
            slices: c.slices_h,
            bits_per_pixel_x16: c.bpp_x16,
        }),
        phy_khz,
    }
}

/// The candidate timing of one request: DRM's, else the first EDID timing
/// (preferred first) the stream's link can carry that also passes
/// single-stream admission. HDMI is `select_hdmi`'s choice; DP SST checks
/// `dp_validate_mode_timing` on the verified link and takes DSC (with
/// FEC) when the uncompressed stream exceeds it and the sink compresses;
/// an MST device needs its time slots on the shared link.
fn candidate(
    r: &Request,
    extra: &DpExtra,
    soc: &dml30::Soc,
    vco_khz: u32,
) -> Result<(StreamPlan, dml30::Stream), Error> {
    if r.connector.signal == Signal::Hdmi {
        let limits = extra.hdmi.unwrap_or(hdmi::Limits::DEFAULT);
        let (timing, stream, _) = select_hdmi(&r.sink, soc, vco_khz, r.want, limits)?;
        if stream.avi.is_none() {
            return Err(Error::NoSink);
        }
        let plan = StreamPlan {
            timing,
            hdmi: Some(stream),
            link: None,
            dsc: None,
            mst: None,
        };
        return Ok((
            plan,
            dml_stream(&timing, vco_khz, stream.character_khz, None),
        ));
    }
    let verified = extra.verified.ok_or(Error::NoSink)?;
    let phy = u32::from(verified.rate) * dp::LINK_RATE_REF_KHZ;
    let timings = crate::amdgpu_navi48_boot::edid_timings(&r.sink.edid);
    let mut order: Vec<Timing> = Vec::new();
    if let Some(w) = r.want {
        order.push(w);
    } else {
        order.extend(timings.iter().copied());
    }
    let bpp = Depth::Bpc8.bits_per_pixel();
    for timing in order {
        if timing.pixel_clock_khz < 25_000 || !timings.contains(&timing) {
            continue;
        }
        let (link, dsc, mst) = if r.mst.is_some() {
            let kbps = dp_link::bandwidth_kbps(verified) as u32;
            match mst::budget(timing.pixel_clock_khz, kbps) {
                Some(b) => (verified, None, Some(b)),
                None => continue,
            }
        } else if let Some(link) =
            dp_link::decide_link_settings(verified, timing.pixel_clock_khz, bpp)
                .filter(|_| dp_fits(&timing, verified))
        {
            (link, None, None)
        } else {
            // FEC costs 3% of the verified link.
            let kbps = dp_link::bandwidth_kbps(verified) * 97 / 100;
            match dsc::select(&timing, &extra.dsc, extra.fec, kbps as u32) {
                Some(c) => (verified, Some(c), None),
                None => continue,
            }
        };
        let stream = dml_stream(&timing, vco_khz, phy, dsc.as_ref());
        if dml30::plan_joint(core::slice::from_ref(&stream), soc).is_err() {
            continue;
        }
        let plan = StreamPlan {
            timing,
            hdmi: None,
            link: Some(link),
            dsc,
            mst,
        };
        return Ok((plan, stream));
    }
    Err(Error::NoMode)
}

/// Joint admission of every request (`dcn30_validate_bandwidth` on the
/// whole context): each stream's candidate, the MST streams' slots
/// together within one link, then one DML30 plan for all of them.
///
/// `states` are the bounding-box states ascending ([`dml30::Soc::states`]);
/// each stream is chosen at the top one, the joint plan is the lowest state
/// that supports them all, which is also returned.
pub fn admit(
    requests: &[Request],
    extras: &[DpExtra],
    states: &[dml30::Soc],
    vco_khz: u32,
) -> Result<(Vec<StreamPlan>, JointPlan, dml30::Soc), Error> {
    let soc = states.last().ok_or(Error::Invalid)?;
    if requests.is_empty() || requests.len() > usize::from(PIPES) || extras.len() != requests.len()
    {
        return Err(Error::Invalid);
    }
    let mut plans = Vec::new();
    let mut streams = Vec::new();
    plans
        .try_reserve_exact(requests.len())
        .map_err(|_| Error::Allocation)?;
    streams
        .try_reserve_exact(requests.len())
        .map_err(|_| Error::Allocation)?;
    for (r, e) in requests.iter().zip(extras) {
        let (plan, stream) = candidate(r, e, soc, vco_khz)?;
        plans.push(plan);
        streams.push(stream);
    }
    // One MST branch tree on one connector: at most four streams within
    // its 63 slots.
    let mst: Vec<usize> = (0..requests.len())
        .filter(|&k| requests[k].mst.is_some())
        .collect();
    if let Some(&first) = mst.first() {
        let link = requests[first].link;
        let slots: u32 = mst
            .iter()
            .map(|&k| u32::from(plans[k].mst.map_or(0, |m| m.1)))
            .sum();
        if mst.iter().any(|&k| requests[k].link != link)
            || mst.len() > mst::MAX_STREAMS
            || slots > u32::from(mst::SLOTS)
            || requests.iter().any(|r| r.mst.is_none() && r.link == link)
        {
            return Err(Error::Unsupported);
        }
    }
    let (state, joint) = dml30::plan_joint_lowest(&streams, states).map_err(Error::Mode)?;
    Ok((plans, joint, states[state]))
}

// ── The multi-stream owner ─────────────────────────────────────────────

/// The AUX channels of every board connector, by index.
pub trait Links: Send {
    fn read(
        &mut self,
        link: usize,
        address: u32,
        data: &mut [u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;
    fn write(
        &mut self,
        link: usize,
        address: u32,
        data: &[u8],
    ) -> impl Future<Output = Result<(), Error>> + Send;
}
/// One connector's AUX out of [`Links`].
pub struct On<'a, L: Links> {
    pub links: &'a mut L,
    pub link: usize,
}
impl<L: Links> core::fmt::Debug for On<'_, L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("On").field("link", &self.link).finish()
    }
}
impl<L: Links> Aux for On<'_, L> {
    async fn read(&mut self, address: u32, data: &mut [u8]) -> Result<(), Error> {
        self.links.read(self.link, address, data).await
    }
    async fn write(&mut self, address: u32, data: &[u8]) -> Result<(), Error> {
        self.links.write(self.link, address, data).await
    }
}
/// The board's connectors through [`crate::amdgpu_navi22_display::Display`].
impl Links for crate::amdgpu_navi22_display::Display {
    async fn read(&mut self, link: usize, address: u32, data: &mut [u8]) -> Result<(), Error> {
        crate::amdgpu_navi22_display::DisplayAux {
            display: self,
            index: link,
        }
        .read(address, data)
        .await
    }
    async fn write(&mut self, link: usize, address: u32, data: &[u8]) -> Result<(), Error> {
        crate::amdgpu_navi22_display::DisplayAux {
            display: self,
            index: link,
        }
        .write(address, data)
        .await
    }
}

/// The VBIOS transmitter calls of one DP connector in DP or DP MST mode.
struct LinkPhy<'a> {
    tables: &'a Tables<'a>,
    regs: MmioRegion,
    authority: Cap<BusDeviceCap, Write>,
    connector: Connector,
    mode: TransmitterMode,
}
impl LinkPhy<'_> {
    fn call(
        &mut self,
        action: TransmitterAction,
        rate: u8,
        lanes: u8,
        connector: u8,
        set: u8,
    ) -> Result<(), Error> {
        // SAFETY: the multi-stream owner's exclusive display ownership.
        let bus = Rc::new(RefCell::new(unsafe {
            bios::Mmio::new(self.regs, self.authority)
        }));
        let control = Transmitter {
            action,
            transmitter: self.connector.path.transmitter,
            mode: if action == TransmitterAction::SetupVsemph {
                TransmitterMode::DisplayPort
            } else {
                self.mode
            },
            lanes,
            hpd: self.connector.hpd,
            connector,
            symbol_khz: u32::from(rate) * dp::LINK_RATE_REF_KHZ,
        };
        Ok(self.tables.transmitter_lane(bus, &control, set)?)
    }
}
impl dp::Phy for LinkPhy<'_> {
    /// `dcn10_link_encoder_enable_dp_output` / `_enable_dp_mst_output`.
    fn enable(&mut self, rate: u8, lanes: u8) -> Result<(), Error> {
        self.call(TransmitterAction::Enable, rate, lanes, 0, 0)
    }
    fn lane_settings(&mut self, rate: u8, lanes: u8, lane_set: u8) -> Result<(), Error> {
        let id = self.connector.object_id();
        self.call(TransmitterAction::SetupVsemph, rate, lanes, id, lane_set)
    }
    fn disable(&mut self) -> Result<(), Error> {
        let id = self.connector.object_id();
        self.call(TransmitterAction::Disable, 0, 0, id, 0)
    }
}

/// The DIO source trained FEC-ready: the link layer's source with
/// `enc2_fec_set_ready` on the transmitter.
struct FecSource<'a> {
    inner: dp::DioSource<'a>,
    dsc: &'a mut dsc::Dsc,
    transmitter: u8,
}
impl dp_link::Source for FecSource<'_> {
    fn enable(&mut self, link: DpLink) -> Result<(), Error> {
        self.inner.enable(link)
    }
    fn pattern(&mut self, tps: dp_link::Tps) -> Result<(), Error> {
        self.inner.pattern(tps)
    }
    fn video(&mut self) -> Result<(), Error> {
        self.inner.video()
    }
    fn drive(&mut self, link: DpLink, swing: u8, pre: u8) -> Result<(), Error> {
        self.inner.drive(link, swing, pre)
    }
    fn disable(&mut self) -> Result<(), Error> {
        self.inner.disable()
    }
    fn fec_ready(&mut self, ready: bool) -> Result<(), Error> {
        self.dsc.fec_ready(self.transmitter, ready)
    }
}

/// Where the multi-stream sequence is (the enable order).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    Prepared,
    InitHw,
    Admitted,
    Bandwidth,
    Streams,
    FrontEnd,
    Verify,
    Running,
    Stopping,
    Stopped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupState {
    At(Phase),
    Failed { phase: Phase, error: Error },
}

/// Several streams lit as one DC context.
pub struct Group {
    gpu: AmdGpu,
    authority: Cap<BusDeviceCap, Write>,
    requests: Vec<Request>,
    members: Vec<Pipeline>,
    slices: Vec<Option<Slice>>,
    leases: Vec<Lease>,
    plans: Vec<StreamPlan>,
    joint: Option<JointPlan>,
    resources: Resources,
    dsc: Option<dsc::Dsc>,
    mst_source: Option<mst::Source>,
    mst: Option<mst::Link>,
    /// The trained MST link: connector index, transmitter, rate, lanes.
    mst_link: Option<(usize, u8, DpLink)>,
    /// Per member: the furthest per-stream step that started.
    reached: Vec<Step>,
    dsc_on: Vec<bool>,
    fec_on: Vec<bool>,
    payload: Vec<bool>,
    state: GroupState,
    phase: Phase,
}
impl core::fmt::Debug for Group {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Group")
            .field("leases", &self.leases)
            .field("state", &self.state)
            .finish()
    }
}

impl Group {
    /// # Safety
    /// As [`Pipeline::new`], for the whole display engine; `requests` name
    /// distinct sinks on the board's connectors.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        requests: &[Request],
    ) -> Result<Self, Error> {
        let first = requests.first().ok_or(Error::Invalid)?;
        if requests.len() > usize::from(PIPES) {
            return Err(Error::Unsupported);
        }
        // The first stream's route is the same whatever the others need:
        // pipe 0, its preferred frontend, the first PLL or the DP DTO.
        let route = Resources::for_gpu(gpu)?.acquire(&first.connector)?;
        // SAFETY: forwarded.
        let lead = unsafe { Pipeline::new(gpu, authority, first.connector, route) }?;
        let mut members = Vec::new();
        members
            .try_reserve_exact(requests.len())
            .map_err(|_| Error::Allocation)?;
        members.push(lead);
        let mut copy = Vec::new();
        copy.try_reserve_exact(requests.len())
            .map_err(|_| Error::Allocation)?;
        copy.extend(requests.iter().cloned());
        let profile = crate::amdgpu_dcn_profile::Profile::resolve(gpu)?;
        let dcn2 = profile.bank(gpu, 2, dsc::LAST_REG.max(mst::LAST_REG))?;
        let regs = Regs {
            window: Window::new(gpu.regs),
            authority,
        };
        Ok(Self {
            gpu: snapshot(gpu)?,
            authority,
            requests: copy,
            members,
            slices: Vec::new(),
            leases: Vec::new(),
            plans: Vec::new(),
            joint: None,
            resources: Resources::for_gpu(gpu)?,
            dsc: Some(dsc::Dsc::new(regs, dcn2).for_profile(profile)),
            mst_source: Some(mst::Source::new(regs, dcn2)),
            mst: None,
            mst_link: None,
            reached: Vec::new(),
            dsc_on: Vec::new(),
            fec_on: Vec::new(),
            payload: Vec::new(),
            state: GroupState::At(Phase::Prepared),
            phase: Phase::Prepared,
        })
    }
    pub fn state(&self) -> GroupState {
        self.state
    }
    pub fn leases(&self) -> &[Lease] {
        &self.leases
    }
    pub fn plans(&self) -> &[StreamPlan] {
        &self.plans
    }
    pub fn joint(&self) -> Option<&JointPlan> {
        self.joint.as_ref()
    }
    /// Each stream's pipeline (scanout, outputs, underflow).
    pub fn members(&self) -> &[Pipeline] {
        &self.members
    }
    pub fn members_mut(&mut self) -> &mut [Pipeline] {
        &mut self.members
    }
    /// The MST session, while one runs.
    pub fn mst(&self) -> Option<&mst::Link> {
        self.mst.as_ref()
    }
    fn at(&mut self, phase: Phase) {
        self.phase = phase;
        self.state = GroupState::At(phase);
    }

    /// Light every request together. `power` is the retained SMU's
    /// display-power step; `links` every board connector (index = AUX
    /// index); `draw(k, y, row)` fills stream k's rows before fetch.
    ///
    /// # Safety
    /// As [`Pipeline::enable`] for every stream.
    #[allow(clippy::too_many_arguments)]
    pub async unsafe fn enable<L: Links>(
        &mut self,
        power: impl Future<Output = Result<(), crate::amdgpu_dcn_clk::Error>>,
        pool: &Pool,
        tables: &Tables<'_>,
        board: Board,
        links: &[Connector],
        aux: &mut L,
        draw: impl Fn(usize, u32, &mut [u32]),
    ) -> Result<Vec<Output>, Error> {
        if self.state != GroupState::At(Phase::Prepared) {
            return Err(Error::Busy);
        }
        match self
            .bring_up(power, pool, tables, board, links, aux, &draw)
            .await
        {
            Ok(outputs) => {
                self.at(Phase::Running);
                Ok(outputs)
            }
            Err(error) => {
                let phase = self.phase;
                let _ = self.tear_down(tables, aux).await;
                self.state = GroupState::Failed { phase, error };
                Err(error)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn bring_up<L: Links>(
        &mut self,
        power: impl Future<Output = Result<(), crate::amdgpu_dcn_clk::Error>>,
        pool: &Pool,
        tables: &Tables<'_>,
        board: Board,
        links: &[Connector],
        aux: &mut L,
        draw: &impl Fn(usize, u32, &mut [u32]),
    ) -> Result<Vec<Output>, Error> {
        // dcn30_init_hw and the GOP takeover, once, through the first
        // stream's pipeline.
        self.at(Phase::InitHw);
        self.members[0].at(Step::InitHw);
        self.members[0].init_hw(tables, links).await?;
        let levels = self.members[0]
            .clocks
            .start_with(power)
            .await
            .map_err(Error::Block)?;
        let refclk = self.members[0]
            .hubbub
            .dchub_refclk_khz(board.crystal_khz)
            .map_err(Error::Hubbub)?;
        let soc =
            dml30::Soc::from_board(&levels, board.channels, board.channel_width_bytes, refclk)
                .and_then(|soc| soc.for_gpu(&self.gpu))
                .map_err(Error::Mode)?;

        // Every stream's pipeline on its provisional route: the pipe, the
        // frontend and the kind of clock source are what the final lease
        // gives (only a shared HDMI PLL can differ), so detection's DP link
        // half (`discover_dp`) runs on each connector's own blocks.
        let mut provisional = Resources::for_gpu(&self.gpu)?;
        provisional.acquire(&self.requests[0].connector)?;
        for k in 1..self.requests.len() {
            let connector = self.requests[k].connector;
            let route = provisional.acquire(&connector)?;
            // SAFETY: the owner's exclusive display ownership.
            let member = unsafe { Pipeline::new(&self.gpu, self.authority, connector, route) }?;
            self.members.push(member);
        }
        // What admission needs per connector: HDMI ceilings, the verified DP
        // link (once per MST root), DSC/FEC caps; then the MST session.
        let mut extras = Vec::new();
        extras
            .try_reserve_exact(self.requests.len())
            .map_err(|_| Error::Allocation)?;
        let mut mst_verified = None;
        for k in 0..self.requests.len() {
            let r = self.requests[k].clone();
            let mut e = DpExtra::default();
            match r.connector.signal {
                Signal::Hdmi => e.hdmi = Some(self.members[k].hdmi_limits(tables)),
                Signal::DisplayPort if r.mst.is_some() && mst_verified.is_some() => {
                    e.verified = mst_verified;
                }
                Signal::DisplayPort => {
                    let mut port = On {
                        links: aux,
                        link: r.link,
                    };
                    lend_clocks(&mut self.members, k);
                    let verified = self.members[k]
                        .discover_dp(tables, &r.sink, &mut port)
                        .await;
                    lend_clocks(&mut self.members, k);
                    let verified = verified?;
                    e.verified = Some(verified);
                    if r.mst.is_some() {
                        mst_verified = Some(verified);
                    } else if let Ok((d, f)) = dsc::sink_caps(&mut port).await {
                        e.dsc = d;
                        e.fec = f;
                    }
                }
            }
            extras.push(e);
        }
        if let Some(r) = self.requests.iter().find(|r| r.mst.is_some()) {
            let caps = r.sink.dpcd.ok_or(Error::NoSink)?;
            let mut link = mst::Link::default();
            let mut port = On {
                links: aux,
                link: r.link,
            };
            link.start(&mut mst::NativeAux(&mut port), &caps).await?;
            self.mst = Some(link);
        }
        let states = soc.states(levels.range(crate::amdgpu_dcn30_clk::Clock::Memory).mhz());
        let (plans, joint, soc) = admit(&self.requests, &extras, &states, levels.vco_khz)?;
        self.at(Phase::Admitted);

        // The pool from empty: every stream's lease.
        let mut resources = Resources::for_gpu(&self.gpu)?;
        let mut leases = Vec::new();
        leases
            .try_reserve_exact(plans.len())
            .map_err(|_| Error::Allocation)?;
        for ((r, p), plane) in self.requests.iter().zip(&plans).zip(&joint.planes) {
            leases.push(resources.acquire_stream(
                &r.connector,
                &p.timing,
                plane.odm,
                p.dsc.is_some(),
            )?);
        }
        for (m, lease) in self.members.iter_mut().zip(&leases) {
            if (m.route.pipe, m.route.stream) != (lease.route.pipe, lease.route.stream) {
                return Err(Error::Invalid);
            }
            m.route = lease.route;
        }
        for (m, p) in self.members.iter_mut().zip(&plans) {
            m.hdmi = p.hdmi;
        }
        self.slices.clear();
        for lease in &leases {
            let slice = match lease.odm_pipe {
                // SAFETY: the pipe is this stream's lease, owned exclusively.
                Some(pipe) => Some(unsafe {
                    Slice {
                        pipe,
                        hubp: Hubp::new(&self.gpu, self.authority, pipe)?,
                        dpp: Dpp::new(&self.gpu, self.authority, pipe)?,
                        mpc: Mpc::new(&self.gpu, self.authority, pipe)?,
                        opp: Opp::new(&self.gpu, self.authority, pipe)?,
                    }
                }),
                None => None,
            };
            self.slices.push(slice);
        }
        let n = leases.len();
        self.reached = alloc::vec![Step::Prepared; n];
        self.dsc_on = alloc::vec![false; n];
        self.fec_on = alloc::vec![false; n];
        self.payload = alloc::vec![false; n];
        self.resources = resources;
        self.leases = leases;
        self.plans = plans;
        let inherited = self.members[0].inherited;
        for (k, member) in self.members.iter_mut().enumerate() {
            member.admitted = Some(Admitted {
                soc,
                refclk_khz: refclk,
                plan: single_plan(&joint, k)?,
                offered: offered_on(
                    &self.requests[k].sink,
                    &soc,
                    levels.vco_khz,
                    extras[k].verified,
                ),
            });
            member.inherited = inherited;
        }

        // Surfaces, drawn and flushed before any pipe fetches.
        let mut fbs = Vec::new();
        fbs.try_reserve_exact(n).map_err(|_| Error::Allocation)?;
        for k in 0..n {
            let timing = self.plans[k].timing;
            let pitch = pitch(&timing);
            let bytes = u64::from(pitch) * 4 * u64::from(timing.v_active);
            let mut reservation = pool.reserve(bytes).map_err(|_| Error::Allocation)?;
            let mapping = reservation.mapping();
            fill(
                mapping,
                pitch,
                timing.h_active,
                timing.v_active,
                &|y, row: &mut [u32]| draw(k, y, row),
            );
            self.members[k].hdp_flush()?;
            reservation.publish();
            fbs.push(narf_graphics_driver::generic::GenericFb::new(
                mapping.phys.raw(),
                timing.h_active,
                timing.v_active,
                pitch * 4,
                32,
            ));
            self.members[k].scanout = Some(reservation);
        }

        // prepare_bandwidth for the whole context: accelerated mode, the
        // clocks every stream needs, then the one watermark set.
        self.at(Phase::Bandwidth);
        let lead = &mut self.members[0];
        lead.at(Step::Clocks);
        lead.regs.update(
            lead.nbio1 + BIOS_SCRATCH_6 * 4,
            ATOM_S6_ACC_MODE,
            ATOM_S6_ACC_MODE,
        )?;
        let clocks = levels
            .plan(
                joint.clocks.dispclk_khz,
                joint.clocks.dppclk_khz,
                joint.clocks.dcfclk_khz,
            )
            .map_err(Error::Block)?;
        lead.clocks
            .prepare_displays(clocks, self.requests.len() as u8)
            .await
            .map_err(Error::Block)?;
        lead.at(Step::Watermarks);
        // SAFETY: no HUBP fetches yet.
        unsafe { lead.hubbub.program(&joint.hubbub, refclk) }.map_err(Error::Hubbub)?;

        // Each stream's timing and link, in context order.
        self.at(Phase::Streams);
        for k in 0..n {
            lend_clocks(&mut self.members, k);
            let r = self.enable_stream(k, &joint, tables, aux).await;
            lend_clocks(&mut self.members, k);
            r?;
        }

        // The front end of every pipe, latched at each OTG's unlock.
        self.at(Phase::FrontEnd);
        for member in self.members.iter_mut() {
            member.at(Step::Plane);
            member.lock().await?;
        }
        for k in 0..n {
            lend_clocks(&mut self.members, k);
            let r = self.program_front_end(k, &joint.planes[k]).await;
            lend_clocks(&mut self.members, k);
            r?;
        }
        for k in 0..n {
            self.members[k].hubp.unblank().await?;
            if let Some(s) = self.slices[k].as_mut() {
                s.hubp.unblank().await?;
            }
            self.members[k].clear_underflow()?;
            if let Some(pipe) = self.slices[k].as_ref().map(|s| s.pipe) {
                self.members[k].hubp_underflow(pipe, true)?;
            }
        }
        for member in self.members.iter_mut() {
            member.unlock()?;
        }
        for k in 0..n {
            let timing = self.plans[k].timing;
            let sink = self.requests[k].sink.clone();
            lend_clocks(&mut self.members, k);
            self.members[k].start_audio(&timing, &sink).await;
            lend_clocks(&mut self.members, k);
        }

        // A bounded watch over the slowest stream's two frames.
        self.at(Phase::Verify);
        let frame = self
            .plans
            .iter()
            .map(|p| frame_us(&p.timing))
            .max()
            .unwrap_or(0);
        for member in self.members.iter_mut() {
            member.at(Step::Verify);
        }
        sleep_us(frame * u64::from(VERIFY_FRAMES)).await;
        let mut first_underflow = None;
        for k in 0..n {
            let mut underflow = self.members[k].read_underflow()?;
            if let Some(pipe) = self.slices[k].as_ref().map(|s| s.pipe) {
                let hubp = self.members[k].hubp_underflow(pipe, false)?;
                if hubp != 0 {
                    let u = underflow.get_or_insert(Underflow {
                        otg: false,
                        hubp: 0,
                    });
                    u.hubp |= hubp;
                }
            }
            if let Some(u) = underflow {
                if let Some(s) = self.slices[k].as_mut() {
                    let _ = s.opp.set_blank(true);
                }
                let e = self.members[k].quarantine(u);
                first_underflow.get_or_insert(e);
            }
        }
        if let Some(e) = first_underflow {
            return Err(e);
        }
        for k in 0..n {
            let mut port = On {
                links: aux,
                link: self.requests[k].link,
            };
            self.members[k]
                .report_hdmi_status(&mut port, "settled")
                .await;
        }
        let mut outputs = Vec::new();
        outputs
            .try_reserve_exact(n)
            .map_err(|_| Error::Allocation)?;
        for (k, fb) in fbs.iter().enumerate() {
            let plane = &joint.planes[k];
            let m = &mut self.members[k];
            let output = Output {
                connector: m.connector,
                route: m.route,
                timing: self.plans[k].timing,
                link: m.link.or(self.mst_link.map(|l| l.2)),
                prefetch_mode: joint.prefetch_mode,
                v_startup: plane.prefetch.v_startup,
                dispclk_khz: clocks.display_khz,
                dppclk_khz: plane.dppclk_khz,
                inherited: m.inherited,
                scanout: *fb,
            };
            m.state = State::At(Step::Running);
            m.output = Some(output);
            outputs.push(output);
        }
        self.joint = Some(joint);
        Ok(outputs)
    }

    /// `dce110_apply_single_controller_ctx_to_hw` for stream `k`: its DSC
    /// engines powered (`dcn20_disable_stream_gating`), then
    /// `dcn20_enable_stream_timing` (ODM combine, OPTC clocks, pixel clock,
    /// timing, MPC rate control, each OPP, black, OTG on, one frame), then
    /// `link_set_dpms_on`.
    async fn enable_stream<L: Links>(
        &mut self,
        k: usize,
        joint: &JointPlan,
        tables: &Tables<'_>,
        aux: &mut L,
    ) -> Result<(), Error> {
        let plan = self.plans[k];
        let lease = self.leases[k];
        let plane = &joint.planes[k];
        let timing = plan.timing;
        let signal = self.requests[k].connector.signal;
        if lease.dsc {
            let dsc = self.dsc.as_mut().ok_or(Error::Invalid)?;
            for p in lease.pipes() {
                if !dsc.power(p, true).await? {
                    return Err(Error::Block(crate::amdgpu_dcn_clk::Error::Timeout));
                }
            }
        }
        self.reached[k] = Step::PixelClock;
        let m = &mut self.members[k];
        m.at(Step::PixelClock);
        m.enable_optc_clock().await?;
        m.program_pix_clk(tables, timing.pixel_clock_khz)?;
        self.reached[k] = Step::Timing;
        m.at(Step::Timing);
        let sync = GlobalSync {
            v_startup_lines: plane.prefetch.v_startup,
            v_update_offset_pix: plane.prefetch.v_update_offset_pix,
            v_update_width_pix: plane.prefetch.v_update_width_pix,
            v_ready_offset_pix: plane.prefetch.v_ready_offset_pix,
        };
        match signal {
            Signal::Hdmi => m.otg.program_tmds_timing(&timing, &sync)?,
            Signal::DisplayPort => m.otg.program_timing(&timing, &sync)?,
        }
        let width = timing.h_active / plane.odm.pipes();
        if let Some(slice) = self.slices[k].as_mut() {
            m.set_odm_combine([lease.route.pipe, slice.pipe], width)?;
            m.mpc_rate_control_off(slice.pipe)?;
            slice.opp.program(Encoding::Rgb, width, timing.v_active)?;
            slice.opp.set_blank(true)?;
        }
        m.mpc_rate_control_off(lease.route.pipe)?;
        m.opp.program(Encoding::Rgb, width, timing.v_active)?;
        m.opp.set_blank(true)?;
        m.hdmi_format().await?;
        self.reached[k] = Step::Start;
        m.at(Step::Start);
        m.otg.enable()?;
        sleep_us(frame_us(&timing)).await;
        self.reached[k] = Step::Link;
        m.at(Step::Link);
        m.dig.connect_to_otg(lease.route.pipe)?;
        let sink = self.requests[k].sink.clone();
        let link = self.requests[k].link;
        match (signal, plan.hdmi, plan.dsc, plan.mst) {
            (Signal::Hdmi, Some(_), _, _) => {
                m.link_hdmi(tables, &mut On { links: aux, link }).await?
            }
            (Signal::DisplayPort, _, None, None) => {
                m.link_dp(tables, &timing, &sink, &mut On { links: aux, link })
                    .await?
            }
            (Signal::DisplayPort, _, Some(cfg), None) => {
                self.link_dp_dsc(k, tables, &cfg, aux).await?
            }
            (Signal::DisplayPort, _, None, Some(budget)) => {
                self.link_mst(k, tables, budget, aux).await?
            }
            _ => return Err(Error::Invalid),
        }
        Ok(())
    }

    /// `link_set_dpms_on` for a DP SST stream with DSC: DSC on the stream
    /// (`link_set_dsc_enable`: every engine, the encoder, the OPTC) before
    /// the DIG backend connects, training FEC-ready on the link layer
    /// (`train_with_retries_fec`) and FEC on after it, then `enable_stream`,
    /// DSC on in the sink with the PPS SDP, unblank.
    async fn link_dp_dsc<L: Links>(
        &mut self,
        k: usize,
        tables: &Tables<'_>,
        cfg: &DscConfig,
        aux: &mut L,
    ) -> Result<(), Error> {
        let timing = self.plans[k].timing;
        let setting = self.plans[k].link.ok_or(Error::NoSink)?;
        let lease = self.leases[k];
        let link = self.requests[k].link;
        let dsc_plan = dsc::plan(&timing, cfg, lease.odm_pipe.is_some())?;
        let transmitter = self.members[k].connector.path.transmitter;
        let caps = self.members[k].dp.caps.ok_or(Error::NoSink)?;
        let mut port = On { links: aux, link };
        let m = &mut self.members[k];
        m.dig.setup(DigMode::DisplayPort)?;
        m.dig.setup_stereo_sync(lease.route.pipe)?;
        let feature = caps.dprx_feature;
        let vsc_colorimetry = feature & 1 << 3 != 0;
        let vsc = vsc_colorimetry.then(|| dp::vsc_packet(Depth::Bpc8));
        m.dp_stream.set_stream_attribute(
            &timing,
            Depth::Bpc8,
            vsc_colorimetry,
            feature & 1 << 1 != 0,
        )?;
        m.dp_stream.update_info_packets(vsc.as_ref()).await?;
        // link_set_dsc_on_stream(true).
        let dsc = self.dsc.as_mut().ok_or(Error::Invalid)?;
        for p in lease.pipes() {
            dsc.start(p, p, &dsc_plan.engine)?;
        }
        self.dsc_on[k] = true;
        dsc.encoder(lease.route.stream, Some(&dsc_plan.picture))?;
        dsc.optc(lease.route.pipe, Some(&dsc_plan.picture))?;
        let m = &mut self.members[k];
        let phy_max = m
            .clocks
            .levels()
            .map_or(0, |l| l.range(Clock::Phy).max_khz());
        let link_khz = (u32::from(setting.rate) * dp::LINK_RATE_REF_KHZ).min(phy_max);
        m.clocks.phy_floor(link_khz).await.map_err(Error::Block)?;
        m.dig.connect_be_to_fe(true)?;
        let mut phy = LinkPhy {
            tables,
            regs: m.gpu.regs,
            authority: m.regs.authority,
            connector: m.connector,
            mode: TransmitterMode::DisplayPort,
        };
        self.fec_on[k] = true;
        let mut source = FecSource {
            inner: dp::DioSource {
                link: m.dp_link,
                phy: &mut phy,
            },
            dsc,
            transmitter,
        };
        let trained =
            dp_link::train_with_retries_fec(&mut port, &mut source, &caps, setting, true).await?;
        m.link = Some(trained);
        // dp_set_fec_enable after 1000 link-layer codes.
        sleep_us(7).await;
        dsc.fec_enable(transmitter, true)?;
        m.dig.setup(DigMode::DisplayPort)?;
        m.dig.connect_be_to_fe(true)?;
        m.dp_stream.update_info_packets(vsc.as_ref()).await?;
        // dp_set_dsc_on_rx and link_set_dsc_pps_packet.
        port.write(dsc::DPCD_DSC_ENABLE, &[1]).await?;
        let packed = crate::amdgpu_dsc::pack_pps(&dsc_plan.picture.pps);
        dsc.pps(lease.route.stream, Some(&packed)).await?;
        m.dp_stream
            .unblank(timing.pixel_clock_khz, trained.rate)
            .await
    }

    /// `link_set_dpms_on` for a DP MST stream: the shared link trained
    /// once in MST mode at the verified link (`enable_link_dp_mst`, through
    /// `enable_dp_mst_output` and the link layer's
    /// `train_with_retries`), then the stream's attribute, `enable_stream`
    /// (its frontend joins the backend), `allocate_mst_payload`, unblank.
    async fn link_mst<L: Links>(
        &mut self,
        k: usize,
        tables: &Tables<'_>,
        budget: (u16, u8, (u32, u32)),
        aux: &mut L,
    ) -> Result<(), Error> {
        let timing = self.plans[k].timing;
        let setting = self.plans[k].link.ok_or(Error::NoSink)?;
        let lease = self.leases[k];
        let link = self.requests[k].link;
        let sink = self.requests[k].mst.ok_or(Error::Invalid)?;
        let transmitter = self.members[k].connector.path.transmitter;
        // The root's caps, from whichever stream's pipeline discovered it.
        let caps = (0..self.members.len())
            .filter(|&j| self.requests[j].link == link)
            .find_map(|j| self.members[j].dp.caps)
            .ok_or(Error::NoSink)?;
        let mut port = On { links: aux, link };
        let m = &mut self.members[k];
        m.dig.setup(DigMode::DpMst)?;
        m.dig.setup_stereo_sync(lease.route.pipe)?;
        m.dp_stream
            .set_stream_attribute(&timing, Depth::Bpc8, false, false)?;
        m.dp_stream.update_info_packets(None).await?;
        let trained = match self.mst_link {
            Some((l, t, trained)) if l == link && t == transmitter => trained,
            Some(_) => return Err(Error::Unsupported),
            None => {
                let phy_max = m
                    .clocks
                    .levels()
                    .map_or(0, |l| l.range(Clock::Phy).max_khz());
                let link_khz = (u32::from(setting.rate) * dp::LINK_RATE_REF_KHZ).min(phy_max);
                m.clocks.phy_floor(link_khz).await.map_err(Error::Block)?;
                m.dig.connect_be_to_fe(true)?;
                let mut phy = LinkPhy {
                    tables,
                    regs: m.gpu.regs,
                    authority: m.regs.authority,
                    connector: m.connector,
                    mode: TransmitterMode::DpMst,
                };
                let mut source = dp::DioSource {
                    link: m.dp_link,
                    phy: &mut phy,
                };
                let trained =
                    dp_link::train_with_retries(&mut port, &mut source, &caps, setting).await?;
                self.mst_link = Some((link, transmitter, trained));
                trained
            }
        };
        let (pbn, slots, vc) = budget;
        let m = &mut self.members[k];
        m.dig.setup(DigMode::DpMst)?;
        m.dig.connect_be_to_fe(true)?;
        m.dp_stream.update_info_packets(None).await?;
        let source = self.mst_source.as_mut().ok_or(Error::Invalid)?;
        let session = self.mst.as_mut().ok_or(Error::Invalid)?;
        self.payload[k] = true;
        session
            .add(
                &mut mst::NativeAux(&mut port),
                source,
                transmitter,
                sink,
                lease.route.stream,
                pbn,
                slots,
                vc,
            )
            .await?;
        self.members[k]
            .dp_stream
            .unblank(timing.pixel_clock_khz, trained.rate)
            .await
    }

    /// `dcn20_program_front_end_for_ctx` for stream `k`'s pipes, under its
    /// OTG's lock: the OPPs out of black, each pipe's power domains, DPP
    /// DTO, DPP, MPCC, HUBP (VTG, pacing, its slice of the surface) and the
    /// cursor's pacing.
    async fn program_front_end(&mut self, k: usize, plane: &PlanePlan) -> Result<(), Error> {
        let timing = self.plans[k].timing;
        let m = &mut self.members[k];
        let master = m.route.pipe;
        let address = m.scanout_address().ok_or(Error::Invalid)?;
        let pitch = pitch(&timing);
        m.opp.set_blank(false)?;
        if let Some(s) = self.slices[k].as_mut() {
            s.opp.set_blank(false)?;
        }
        m.power_on_plane().await?;
        if let Some(pipe) = self.slices[k].as_ref().map(|s| s.pipe) {
            m.power_on_pipe(pipe).await?;
        }
        let left = plane.pipes[0].ok_or(Error::Invalid)?;
        m.clocks
            .pipe_clock(master, plane.dppclk_khz)
            .map_err(Error::Block)?;
        m.dpp
            .program(Format::Rgb32, left.viewport_width, timing.v_active)?;
        m.mpc.mux_plane(master, master)?;
        let surface = Surface {
            address,
            format: Format::Rgb32,
            pitch,
            viewport_width: left.viewport_width,
            viewport_height: timing.v_active,
        };
        m.hubp.select_vtg(master)?;
        m.hubp
            .program_at(&surface, &left.registers, left.viewport_x)?;
        m.program_cursor_ttu(left.cursor)?;
        if let (Some(s), Some(right)) = (self.slices[k].as_mut(), plane.pipes[1]) {
            m.clocks
                .pipe_clock(s.pipe, plane.dppclk_khz)
                .map_err(Error::Block)?;
            s.dpp
                .program(Format::Rgb32, right.viewport_width, timing.v_active)?;
            s.mpc.mux_plane(s.pipe, s.pipe)?;
            let surface = Surface {
                viewport_width: right.viewport_width,
                ..surface
            };
            s.hubp.select_vtg(master)?;
            s.hubp
                .program_at(&surface, &right.registers, right.viewport_x)?;
            m.program_cursor_ttu_at(s.pipe, right.cursor)?;
        }
        Ok(())
    }

    /// Stop every stream: audio, the front ends, the links (DSC, FEC and
    /// MST payloads included), the OTGs, ODM and OPTC clocks, the DSC
    /// domains. Each step runs even after an earlier one failed.
    async fn tear_down<L: Links>(&mut self, tables: &Tables<'_>, aux: &mut L) -> Result<(), Error> {
        let mut first = Ok(());
        let mut record = |r: Result<(), Error>| {
            if first.is_ok() {
                first = r;
            }
        };
        let n = self.leases.len().min(self.members.len());
        for k in (0..n).rev() {
            let reached = self.reached[k];
            let lease = self.leases[k];
            let link = self.requests[k].link;
            let signal = self.requests[k].connector.signal;
            let dig = lease.route.stream;
            lend_clocks(&mut self.members, k);
            let m = &mut self.members[k];
            if m.reached >= Step::Plane && m.audio.record(dig).is_some() {
                let _ = m.audio.stop(dig, &mut m.clocks).await;
            }
            if reached >= Step::Timing {
                record(m.opp.set_blank(true).map_err(Error::Block));
                if let Some(s) = self.slices[k].as_mut() {
                    record(s.opp.set_blank(true).map_err(Error::Block));
                }
            }
            if m.reached >= Step::Plane {
                record(m.mpc.release(lease.route.pipe).map_err(Error::Block));
                record(m.hubp.blank().await.map_err(Error::Block));
                if let Some(s) = self.slices[k].as_mut() {
                    record(s.mpc.release(s.pipe).map_err(Error::Block));
                    record(s.hubp.blank().await.map_err(Error::Block));
                }
            }
            if reached >= Step::Link {
                let mut port = On { links: aux, link };
                match (signal, self.requests[k].mst) {
                    (Signal::Hdmi, _) => record(m.unlink_hdmi(tables)),
                    (Signal::DisplayPort, None) => {
                        if self.dsc_on[k] {
                            let _ = port.write(dsc::DPCD_DSC_ENABLE, &[0]).await;
                        }
                        record(m.unlink_dp(tables, &mut port).await);
                        if let Some(dsc) = self.dsc.as_mut() {
                            if self.fec_on[k] {
                                let t = m.connector.path.transmitter;
                                record(dsc.fec_enable(t, false));
                                record(dsc.fec_ready(t, false));
                                let _ = port.write(dsc::DPCD_FEC_CONFIGURATION, &[0]).await;
                                self.fec_on[k] = false;
                            }
                            if self.dsc_on[k] {
                                record(dsc.optc(lease.route.pipe, None));
                                record(dsc.encoder(dig, None));
                                record(dsc.pps(dig, None).await);
                                for p in lease.pipes() {
                                    record(dsc.stop(p));
                                }
                                self.dsc_on[k] = false;
                            }
                        }
                    }
                    (Signal::DisplayPort, Some(_)) => {
                        record(m.dp_stream.blank().await);
                        if self.payload[k] {
                            if let (Some(session), Some(source)) =
                                (self.mst.as_mut(), self.mst_source.as_mut())
                            {
                                let t = m.connector.path.transmitter;
                                record(
                                    session
                                        .remove(
                                            &mut mst::NativeAux(&mut port),
                                            source,
                                            t,
                                            dig,
                                            true,
                                        )
                                        .await,
                                );
                            }
                            self.payload[k] = false;
                        }
                        record(m.dp_stream.stop_info_packets());
                        record(m.dig.connect_be_to_fe(false).map_err(Error::Hdmi));
                        // The last MST stream takes the shared link down.
                        let last = self.payload.iter().all(|p| !p)
                            && (0..k).all(|j| {
                                self.requests[j].mst.is_none() || self.reached[j] < Step::Link
                            });
                        if last && self.mst_link.is_some() {
                            sleep_us(DP_BLANK_SETTLE_US).await;
                            let _ = port.write(dp::DPCD_SET_POWER, &[dp::SET_POWER_D3]).await;
                            if matches!(m.dp_link.enabled(), Ok(true)) {
                                let mut phy = LinkPhy {
                                    tables,
                                    regs: m.gpu.regs,
                                    authority: m.regs.authority,
                                    connector: m.connector,
                                    mode: TransmitterMode::DpMst,
                                };
                                record(dp::Phy::disable(&mut phy));
                                record(m.dp_link.reset());
                            }
                            if let Some(session) = self.mst.as_mut() {
                                session.stop(&mut mst::NativeAux(&mut port)).await;
                            }
                            self.mst_link = None;
                        }
                    }
                }
            }
            if reached >= Step::Start {
                record(m.otg.disable().await.map_err(Error::Block));
            }
            if reached >= Step::Timing && lease.odm_pipe.is_some() {
                record(m.set_odm_bypass());
            }
            if reached >= Step::PixelClock {
                record(m.disable_optc_clock());
            }
            if lease.dsc {
                if let Some(dsc) = self.dsc.as_mut() {
                    for p in lease.pipes() {
                        let _ = dsc.power(p, false).await;
                    }
                }
            }
            self.reached[k] = Step::Stopped;
            m.reached = Step::Stopped;
            m.state = State::At(Step::Stopped);
            m.output = None;
            lend_clocks(&mut self.members, k);
        }
        first
    }

    /// Stop every stream. The scanouts stay published until each member's
    /// [`Pipeline::release_scanout`].
    pub async fn disable<L: Links>(
        &mut self,
        tables: &Tables<'_>,
        aux: &mut L,
    ) -> Result<(), Error> {
        match self.state {
            GroupState::At(Phase::Prepared | Phase::Stopping | Phase::Stopped)
            | GroupState::Failed { .. } => return Err(Error::Busy),
            _ => {}
        }
        self.at(Phase::Stopping);
        let result = self.tear_down(tables, aux).await;
        self.state = match result {
            Ok(()) => GroupState::At(Phase::Stopped),
            Err(error) => GroupState::Failed {
                phase: Phase::Stopping,
                error,
            },
        };
        result
    }
}

/// DCN3.0 has one DAL clock owner (`clk_mgr`) for the whole context: the
/// first stream's started manager. Swapped into member `k` for that
/// stream's clock requests (PHY floor, DPP DTO, Azalia wake) and back by a
/// second call; a no-op for the first stream.
fn lend_clocks(members: &mut [Pipeline], k: usize) {
    if k != 0 && k < members.len() {
        let (lead, rest) = members.split_at_mut(1);
        core::mem::swap(&mut lead[0].clocks, &mut rest[k - 1].clocks);
    }
}

/// Stream `k`'s plane as the single-stream [`dml30::Plan`] KMS reads.
fn single_plan(joint: &JointPlan, k: usize) -> Result<dml30::Plan, Error> {
    let plane = joint.planes.get(k).ok_or(Error::Invalid)?;
    let pipe = plane.pipes[0].ok_or(Error::Invalid)?;
    Ok(dml30::Plan {
        prefetch_mode: joint.prefetch_mode,
        geometry: plane.geometry,
        clocks: joint.clocks,
        watermarks: joint.watermarks,
        prefetch: plane.prefetch,
        registers: pipe.registers,
        hubbub: joint.hubbub,
        dram_clock_change: joint.dram_clock_change,
        urgent_bandwidth_thousandths: joint.urgent_bandwidth_thousandths,
        cursor: pipe.cursor,
    })
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_multi_tests.rs"]
mod tests;
