//! Native DP 128b/132b (UHBR) SST link start, training and stop.
//!
//! The PHY and an HPO link encoder come up by firmware, as Linux's
//! enable_hpo_dp_link_output does it: one DMUB transmitter-control ENABLE
//! (DP_MST mode, the HPO instance). DC itself writes neither the PHY mux,
//! SYMCLK32_LE nor the encoder's DPHY enable and lane count; this owner
//! observes them. Training is Linux's dp_perform_128b_132b_link_training
//! toward the sink (any repeater chain set non-transparent and training its
//! own hops): TPS1, TPS2 with the sink's TX FFE presets, then the clock
//! data switch, and the link left active (idle). Streams, payload and
//! scanout are separate owners.
use super::*;
pub use dmub::UhbrRate;
#[path = "amdgpu_dcn401_uhbr_video.rs"]
pub(in crate::amdgpu_dcn401_otg) mod video;
pub use video::{uhbr_mst_dsc_rate, uhbr_mst_rate, UhbrPayload, UhbrVideoRunning};

const LINK_CLOCK: u64 = 0x369f;
const CONTROL: u64 = 0x36b4;
const STATUS: u64 = 0x36b5;
const CHANNEL_CODING_SET: u32 = 0x108;
const UHBR_AUX_RD_INTERVAL: u32 = 0x2216;
const UHBR_RATES: u32 = 0x2215;
const LANE_ALIGN: u32 = 0x205;
/// DP_DPHY_SYM32_CONTROL MODE: 128b/132b TPS1, TPS2 and the active link.
const MODE_TPS1: u8 = 0;
const MODE_TPS2: u8 = 1;
const MODE_ACTIVE: u8 = 2;
/// decide_128b_132b_training_settings.
const EQ_LOOP_LIMIT: u8 = 20;
const EQ_WAIT_LIMIT_US: u64 = 400_000;
const PATTERN_TIME_US: u64 = 2_500;
const CDS_WAIT_PER_HOP_US: u64 = 20_000;

/// A 128b/132b link: lane count and per-lane rate, and whether it runs
/// MST (its streams' payloads then belong to the MST manager).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UhbrSettings {
    pub lanes: u8,
    pub rate: UhbrRate,
    pub mst: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UhbrLinkTrained {
    pub path: Path,
    pub settings: UhbrSettings,
    /// The HPO link encoder the firmware routed this PHY to.
    pub link: u8,
    /// Observed physical lanes, independent of board lane mapping.
    pub physical_lanes: u8,
    /// The TX FFE preset in use: the highest any active lane requested.
    pub preset: u8,
    pub eq_loops: u8,
    /// Repeaters (non-transparent) between source and sink; zero for none.
    pub repeaters: u8,
    /// The encoder's training mode as last set (MODE_*).
    mode: u8,
}
pub(in super::super::super) trait UhbrTransport: Transport {
    fn enable_uhbr(
        &mut self,
        path: Path,
        settings: UhbrSettings,
        link: u8,
    ) -> impl Future<Output = Result<(), dmub::Error>> + Send;
    fn uhbr_ffe(
        &mut self,
        path: Path,
        settings: UhbrSettings,
        preset: u8,
    ) -> impl Future<Output = Result<(), dmub::Error>> + Send;
    fn disable_uhbr(&mut self, path: Path) -> impl Future<Output = Result<(), dmub::Error>> + Send;
}
impl UhbrTransport for dmub::Dmub {
    async fn enable_uhbr(
        &mut self,
        path: Path,
        settings: UhbrSettings,
        link: u8,
    ) -> Result<(), dmub::Error> {
        self.enable_uhbr(path, settings.lanes, settings.rate, link)
            .await
    }
    async fn uhbr_ffe(
        &mut self,
        path: Path,
        settings: UhbrSettings,
        preset: u8,
    ) -> Result<(), dmub::Error> {
        self.set_uhbr_ffe(path, settings.lanes, settings.rate, preset)
            .await
    }
    async fn disable_uhbr(&mut self, path: Path) -> Result<(), dmub::Error> {
        // dcn31_hpo_dp_link_enc_disable_output: DISABLE as SST (digmode 0).
        self.disable_hpo_dp(path, dmub::DpSignal::Sst).await
    }
}
/// A 128b/132b lane status/adjust block (0x202..0x207) as Linux reads it.
fn uhbr_eq_done(status: [u8; 6], lanes: u8) -> bool {
    (0..lanes).all(|l| lane_bits(status, l) & 2 != 0)
}
fn uhbr_symbol_locked(status: [u8; 6], lanes: u8) -> bool {
    (0..lanes).all(|l| lane_bits(status, l) & 4 != 0)
}
const EQ_INTERLANE_ALIGN_DONE: u8 = 4;
const CDS_INTERLANE_ALIGN_DONE: u8 = 8;
const LT_FAILED: u8 = 0x10;
/// Each lane's requested TX_FFE_PRESET_VALUE (all four, as the sink lists
/// them; Linux writes these back to the sink as they are).
fn requested_presets(status: [u8; 6]) -> [u8; 4] {
    core::array::from_fn(|l| status[4 + l / 2] >> (4 * (l % 2)) & 0xf)
}
/// The preset the source transmits: the highest over the active lanes
/// (disallow_per_lane_settings).
fn source_preset(requests: [u8; 4], lanes: u8) -> u8 {
    requests[..usize::from(lanes)]
        .iter()
        .copied()
        .max()
        .unwrap_or(0)
}
/// DP_128B132B_TRAINING_AUX_RD_INTERVAL: (value + 1) units of 2 ms, or of
/// 1 ms with bit 7.
fn uhbr_interval_us(raw: u8) -> u64 {
    (u64::from(raw & 0x7f) + 1) * if raw & 0x80 != 0 { 1000 } else { 2000 }
}
impl<I: Io> Engine<I> {
    fn uhbr_at(&self, link: u8, reg: u64) -> u64 {
        DpStream::Hpo(link).at(self.layout, reg)
    }
    fn phy_mux(&self, phy: u8) -> u64 {
        self.layout.base + (0x179a + 3 * u64::from(phy)) * 4
    }
    /// The running link's firmware-made state, and nothing else awake.
    fn uhbr_verify(&mut self, plan: &UhbrLinkTrained) -> Result<(), Error> {
        self.uhbr_verify_owned(plan, None, None)
    }
    /// As `uhbr_verify`, with a stream encoder and timing the link's video
    /// owner holds exempt.
    pub(in super::super::super) fn uhbr_verify_owned(
        &mut self,
        plan: &UhbrLinkTrained,
        stream: Option<u8>,
        timing: Option<u8>,
    ) -> Result<(), Error> {
        let phy = plan.path.transmitter;
        self.dp_phy_consumers_hpo(phy, None, timing, Some(plan.link), stream)?;
        self.dp_phy_untrained(phy)?;
        self.uhbr_witnesses(plan)
    }
    fn uhbr_witnesses(&mut self, plan: &UhbrLinkTrained) -> Result<(), Error> {
        let l = self.layout;
        let phy = plan.path.transmitter;
        let lanes = phy_at(l, phy, 0x2943);
        if active_lanes(self.read(lanes)?, plan.settings.lanes) != Some(plan.physical_lanes) {
            return Err(Error::Readback(lanes));
        }
        let root = (u32::from(phy) | 8) << (4 * plan.link);
        for (at, mask, value) in [
            (
                phy_at(l, phy, 0x2931),
                0x6f0,
                0x600 | u32::from(plan.physical_lanes) << 4,
            ),
            (self.phy_mux(phy), 0x703, u32::from(plan.link) << 8 | 2),
            (l.link_clock, 0xf << (4 * plan.link), root),
            (self.uhbr_at(plan.link, LINK_CLOCK), 0x11, 0x11),
            (
                self.uhbr_at(plan.link, CONTROL),
                0x33,
                1 | u32::from(plan.mode) << 4,
            ),
            (self.uhbr_at(plan.link, STATUS), 3, 1),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    /// dcn31_hpo_dp_link_enc_set_link_test_pattern for the training modes.
    fn uhbr_mode(&mut self, plan: &mut UhbrLinkTrained, mode: u8) -> Result<(), Error> {
        self.uhbr_verify(plan)?;
        self.update(self.uhbr_at(plan.link, CONTROL), 0x30, u32::from(mode) << 4)?;
        plan.mode = mode;
        self.uhbr_verify(plan)
    }
    /// Everything quiet before the firmware is asked for the link: the
    /// PHY's DIO backend and lanes off, the HPO link encoder stopped with an
    /// empty allocation table, and no PHY routed to it.
    fn uhbr_plan(&mut self, path: Path, settings: UhbrSettings, link: u8) -> Result<(), Error> {
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        if path.connector != Connector::DisplayPort {
            return Err(Error::Unsupported);
        }
        if path.transmitter >= 4
            || !(1..=4).contains(&path.hpd)
            || path.aux.is_none_or(|a| a >= 4)
            || !matches!(settings.lanes, 1 | 2 | 4)
            || link >= 4
        {
            return Err(Error::Invalid);
        }
        let phy = path.transmitter;
        self.dp_phy_consumers(phy)?;
        self.dp_phy_untrained(phy)?;
        self.dp_phy_off(phy)?;
        for p in 0..4 {
            let mux = self.read(self.phy_mux(p))?;
            if mux & 3 == 2 && (mux >> 8) & 7 == u32::from(link) {
                return Err(Error::Busy);
            }
        }
        for (reg, mask) in [(LINK_CLOCK, 0x11), (CONTROL, 3), (STATUS, 0x1f1003)] {
            if self.read(self.uhbr_at(link, reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        // DP_DPHY_SYM32_SAT_VC0..5 and their status: no allocation.
        for row in 0..6 {
            for reg in [0x36bf, 0x36c5] {
                if self.read(self.uhbr_at(link, reg + row))? & 0x7f00 != 0 {
                    return Err(Error::Busy);
                }
            }
        }
        Ok(())
    }
    /// dp_enable_link_phy for 128b/132b: the firmware enable, then the
    /// lanes, TX clocks, mux, SYMCLK32_LE and encoder it brings up.
    async fn uhbr_enable(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
    ) -> Result<(), Error> {
        io.enable_uhbr(plan.path, plan.settings, plan.link)
            .await
            .map_err(Error::Firmware)?;
        let l = self.layout;
        let phy = plan.path.transmitter;
        let lanes = phy_at(l, phy, 0x2943);
        let deadline = narf_time::Deadline::after_us(100_000);
        loop {
            if let Some(mask) = active_lanes(self.read(lanes)?, plan.settings.lanes) {
                plan.physical_lanes = mask;
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout(lanes));
            }
            io.delay(1).await;
        }
        for (at, mask, value) in [
            (
                phy_at(l, phy, 0x2931),
                0x6f0,
                0x600 | u32::from(plan.physical_lanes) << 4,
            ),
            (self.uhbr_at(plan.link, LINK_CLOCK), 0x11, 0x11),
            (self.uhbr_at(plan.link, STATUS), 3, 1),
        ] {
            self.wait(at, mask, value, 100_000).await?;
        }
        plan.mode = ((self.read(self.uhbr_at(plan.link, CONTROL))? >> 4) & 3) as u8;
        self.uhbr_verify(plan)
    }
    /// dpcd_exit_training_mode: TRAINING_PATTERN_SET cleared, then up to 10
    /// ms (300 ms per repeater) for the intra-hop AUX reply indication to
    /// clear. Linux carries on regardless.
    async fn uhbr_exit_training(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &UhbrLinkTrained,
    ) -> Result<(), Error> {
        write(io, plan.path, 0x102, &mut [0]).await?;
        let polls = if plan.repeaters != 0 {
            u32::from(plan.repeaters) * 300
        } else {
            10
        };
        for _ in 0..polls {
            if read::<1>(io, plan.path, LANE_ALIGN).await?[0] & 8 == 0 {
                break;
            }
            io.delay(1000).await;
        }
        self.uhbr_verify(plan)
    }
    /// The sink's and any repeater chain's caps, before the PHY: the sink
    /// codes 128b/132b, lists the rate (or a better one; UHBR13.5 only where
    /// listed) and has the lanes, with no MST owner, and a revision 1.4
    /// chain carries the rate too. Returns the chain's raw count.
    async fn uhbr_caps(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
        s: UhbrSettings,
    ) -> Result<Option<Lttpr>, Error> {
        let mut dpcd = read::<16>(io, path, 0).await?;
        if dpcd[14] & 0x80 != 0 {
            let extended = read::<16>(io, path, 0x2200).await?;
            if extended[0] >= dpcd[0] {
                dpcd = extended;
            }
        }
        if !matches!(dpcd[0], 0x12..=0x14 | 0x20 | 0x21) || !matches!(dpcd[2] & 0x1f, 1 | 2 | 4) {
            return Err(invalid_caps());
        }
        let best = |bits: u8| {
            UhbrRate::ALL
                .into_iter()
                .rev()
                .find(|r| bits & r.dpcd_bit() != 0)
        };
        let carries = |bits: u8| {
            best(bits).is_some_and(|b| s.rate <= b)
                && (s.rate != UhbrRate::Uhbr13_5 || bits & 4 != 0)
        };
        if dpcd[6] & 2 == 0 || s.lanes > dpcd[2] & 0x1f {
            return Err(Error::Unsupported);
        }
        if !carries(read::<1>(io, path, UHBR_RATES).await?[0]) {
            return Err(Error::Unsupported);
        }
        // SST: no active MST/up-request owner. MST: the topology manager
        // set MST_EN first (drm_dp_mst_topology_mgr_set_mst).
        let mstm = read::<1>(io, path, 0x111).await?[0];
        if s.mst {
            if mstm & 1 == 0 {
                return Err(Error::Invalid);
            }
        } else if mstm & 7 != 0 {
            return Err(Error::Busy); // active MST/up-request owner
        }
        // retrieve_link_cap's repeater probe under the LTTPR AUX timeout.
        self.aux_timeout(path, AUX_TIMEOUT_LTTPR_US)?;
        let caps = match read::<10>(io, path, LTTPR_CAPS).await {
            Ok(caps) => Some(caps),
            Err(Error::Firmware(dmub::Error::Aux(1))) => None,
            Err(e) => return Err(e),
        };
        let chain = caps.and_then(|c| Lttpr::parse(c, true).map(|r| (c, r)));
        let Some((caps, r)) = chain else {
            self.aux_timeout(path, AUX_TIMEOUT_DEFAULT_US)?;
            return Ok(None);
        };
        // get_lttpr_max_link_rate: a revision 1.4 chain's 128b/132b rates
        // bound the link like the sink's.
        if s.lanes > r.max_lanes || (caps[0] >= 0x14 && !carries(caps[7])) {
            return Err(Error::Unsupported);
        }
        Ok(Some(r))
    }
    /// With the PHY up: the receiver to D0 (dp_enable_link_phy), the
    /// training exit, the repeater chain's count and modes, 128b/132b
    /// channel coding and the link settings.
    async fn uhbr_sink(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
        chain: Option<Lttpr>,
    ) -> Result<(), Error> {
        let path = plan.path;
        let s = plan.settings;
        write(io, path, 0x600, &mut [1]).await?;
        io.delay(1000).await;
        if read::<1>(io, path, 0x600).await?[0] & 7 != 1 {
            return Err(sink_readback(0x600));
        }
        self.uhbr_verify(plan)?;
        self.uhbr_exit_training(io, plan).await?;
        if let Some(r) = chain {
            // The count and transparent mode retrieve_link_cap leaves, then
            // dp_decide_128b_132b_lttpr_mode's non-transparent mode.
            write(io, path, LTTPR_TOTAL_COUNT, &mut [r.raw_count]).await?;
            write(io, path, LTTPR_MODE, &mut [LTTPR_MODE_TRANSPARENT]).await?;
            write(io, path, LTTPR_MODE, &mut [LTTPR_MODE_NON_TRANSPARENT]).await?;
        }
        write(io, path, CHANNEL_CODING_SET, &mut [2]).await?;
        // dpcd_set_link_settings: 0.5% downspread, lanes without enhanced
        // framing or post-LT adjustment, the 128b/132b rate code.
        write(io, path, 0x107, &mut [0x10]).await?;
        write(io, path, 0x101, &mut [s.lanes]).await?;
        write(io, path, 0x100, &mut [s.rate.dpcd_code()]).await?;
        self.uhbr_verify(plan)
    }
    async fn uhbr_status(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &UhbrLinkTrained,
    ) -> Result<[u8; 6], Error> {
        let status = read::<6>(io, plan.path, 0x202).await?;
        self.uhbr_verify(plan)?;
        Ok(status)
    }
    async fn uhbr_ffe(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
        preset: u8,
    ) -> Result<(), Error> {
        self.uhbr_verify(plan)?;
        io.uhbr_ffe(plan.path, plan.settings, preset)
            .await
            .map_err(Error::Firmware)?;
        plan.preset = preset;
        self.uhbr_verify(plan)
    }
    /// dp_perform_128b_132b_channel_eq_done_sequence.
    async fn uhbr_eq(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
    ) -> Result<(), Error> {
        let path = plan.path;
        let lanes = plan.settings.lanes;
        let failed = || Error::DpTraining(DpTrainingError::Equalization);
        self.uhbr_mode(plan, MODE_TPS1)?;
        write(io, path, 0x102, &mut [1]).await?;
        let mut interval = uhbr_interval_us(read::<1>(io, path, UHBR_AUX_RD_INTERVAL).await?[0]);
        let mut status = self.uhbr_status(io, plan).await?;
        let mut requests = requested_presets(status);
        self.uhbr_ffe(io, plan, source_preset(requests, lanes))
            .await?;
        self.uhbr_mode(plan, MODE_TPS2)?;
        // TRAINING_PATTERN_SET 2 and the active lanes' requests in one burst.
        let mut burst = [0u8; 5];
        burst[0] = 2;
        burst[1..1 + usize::from(lanes)].copy_from_slice(&requests[..usize::from(lanes)]);
        write(io, path, 0x102, &mut burst).await?;
        let mut wait = 0;
        let mut loops = 1;
        loop {
            io.delay(interval).await;
            wait += interval;
            status = self.uhbr_status(io, plan).await?;
            requests = requested_presets(status);
            interval = uhbr_interval_us(read::<1>(io, path, UHBR_AUX_RD_INTERVAL).await?[0]);
            plan.eq_loops = loops;
            if uhbr_eq_done(status, lanes) {
                break;
            }
            if loops >= EQ_LOOP_LIMIT || status[2] & LT_FAILED != 0 {
                return Err(failed());
            }
            self.uhbr_ffe(io, plan, source_preset(requests, lanes))
                .await?;
            write(io, path, 0x103, &mut requests).await?;
            loops += 1;
        }
        // EQ interlane alignment, within 400 ms of training altogether.
        loop {
            if status[2] & EQ_INTERLANE_ALIGN_DONE != 0 {
                return Ok(());
            }
            if wait >= EQ_WAIT_LIMIT_US || status[2] & LT_FAILED != 0 {
                return Err(failed());
            }
            io.delay(PATTERN_TIME_US).await;
            wait += PATTERN_TIME_US;
            status = self.uhbr_status(io, plan).await?;
        }
    }
    /// dp_perform_128b_132b_cds_done_sequence; the hardware keeps TPS2.
    async fn uhbr_cds(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
    ) -> Result<(), Error> {
        write(io, plan.path, 0x102, &mut [3]).await?;
        let limit = (u64::from(plan.repeaters) + 1) * CDS_WAIT_PER_HOP_US;
        let mut wait = 0;
        loop {
            io.delay(PATTERN_TIME_US).await;
            wait += PATTERN_TIME_US;
            let status = self.uhbr_status(io, plan).await?;
            if uhbr_symbol_locked(status, plan.settings.lanes)
                && status[2] & CDS_INTERLANE_ALIGN_DONE != 0
            {
                return Ok(());
            }
            if status[2] & LT_FAILED != 0 || wait >= limit {
                return Err(Error::DpTraining(DpTrainingError::ClockDataSwitch));
            }
        }
    }
    /// The training exit, the encoder to the active (idle) link, and
    /// dp_check_link_loss_status after 5 ms: every lane's CR done, channel
    /// EQ done and symbol lock, with interlane alignment (0x204 bit 0), as
    /// Linux requires of 128b/132b links too.
    async fn uhbr_finish(
        &mut self,
        io: &mut impl UhbrTransport,
        plan: &mut UhbrLinkTrained,
    ) -> Result<(), Error> {
        self.uhbr_exit_training(io, plan).await?;
        self.uhbr_mode(plan, MODE_ACTIVE)?;
        io.delay(5000).await;
        let status = read::<6>(io, plan.path, 0x200).await?;
        let lanes = [status[2], status[3], status[4], 0, 0, 0];
        if !(0..plan.settings.lanes).all(|l| lane_bits(lanes, l) & 7 == 7) || status[4] & 1 == 0 {
            return Err(Error::DpTraining(DpTrainingError::LinkLost));
        }
        self.uhbr_verify(plan)
    }
    /// Enable the PHY on HPO link encoder `link` at `settings` and train
    /// the sink. A confirmed training refusal exits training and leaves
    /// UhbrLinkRefused for `stop_uhbr_link`; uncertain failures quarantine.
    pub(in super::super::super) async fn train_uhbr_link(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
        settings: UhbrSettings,
        link: u8,
    ) -> Result<UhbrLinkTrained, Error> {
        if !io.ready() {
            return Err(Error::Busy);
        }
        self.uhbr_plan(path, settings, link)?;
        let chain = self.uhbr_caps(io, path, settings).await?;
        self.uhbr_plan(path, settings, link)?;
        let mut plan = UhbrLinkTrained {
            path,
            settings,
            link,
            physical_lanes: 0,
            preset: 0,
            eq_loops: 0,
            repeaters: chain.map_or(0, |r| r.count),
            mode: 0,
        };
        self.status.state = State::TrainingUhbr(path.transmitter);
        let mut enabled = false;
        let mut result = async {
            self.uhbr_enable(io, &mut plan).await?;
            enabled = true;
            self.uhbr_sink(io, &mut plan, chain).await?;
            self.uhbr_eq(io, &mut plan).await?;
            self.uhbr_cds(io, &mut plan).await?;
            self.uhbr_finish(io, &mut plan).await
        }
        .await;
        // A refusal the sink confirmed still exits training, as Linux does
        // before disabling the PHY (the encoder stays on its last pattern).
        let refused = matches!(
            result,
            Err(Error::DpTraining(
                DpTrainingError::Equalization
                    | DpTrainingError::ClockDataSwitch
                    | DpTrainingError::LinkLost
            ))
        );
        if refused {
            if let Err(e) = self.uhbr_exit_training(io, &plan).await {
                result = Err(e);
            }
        }
        match result {
            Ok(()) => {
                self.status.uhbr_link = Some(plan);
                self.status.state = State::UhbrLinkTrained(path.transmitter);
                Ok(plan)
            }
            Err(e) if refused && enabled => {
                self.status.uhbr_link = Some(plan);
                self.status.state = State::UhbrLinkRefused(path.transmitter);
                Err(e)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// disable_link_dp for 128b/132b: an SST sink to D3 (unless gone), then
    /// disable_hpo_dp_link_output: the encoder's DPHY and clock off, the
    /// firmware DISABLE, lanes and TX clocks proven off, and the encoder's
    /// SYMCLK32_LE route parked (dccg401_disable_symclk32_le).
    async fn stop_uhbr_link_with(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
        sink: bool,
    ) -> Result<(), Error> {
        let t = path.transmitter;
        if !matches!(self.status.state, State::UhbrLinkTrained(x) | State::UhbrLinkRefused(x) if x == t)
            || !io.ready()
        {
            return Err(Error::Busy);
        }
        let plan = self.status.uhbr_link.ok_or(Error::Invalid)?;
        if plan.path != path {
            return Err(Error::Invalid);
        }
        // An attached display never stops the MST link it rides, nor the
        // owner while another display streams on it.
        if self.status.mst_owner.is_some() || self.displays.siblings.transmitters & bit(t) != 0 {
            return Err(Error::Busy);
        }
        self.uhbr_verify(&plan)?;
        self.status.state = State::StoppingUhbrLink(t);
        let l = self.layout;
        let result = async {
            // An idle MST branch stays powered for AUX and up requests.
            if sink && !plan.settings.mst {
                write(io, path, 0x600, &mut [2]).await?;
                self.uhbr_verify(&plan)?;
            }
            let at = |r| DpStream::Hpo(plan.link).at(l, r);
            self.update(at(CONTROL), 1, 0)?;
            self.wait(at(STATUS), 0x1f1003, 0, 100_000).await?;
            self.update(at(LINK_CLOCK), 1, 0)?;
            self.wait(at(LINK_CLOCK), 0x11, 0, 1000).await?;
            io.disable_uhbr(path).await.map_err(Error::Firmware)?;
            self.wait(phy_at(l, t, 0x2943), LANES_MASK, LANES_OFF, 100_000)
                .await?;
            self.wait(phy_at(l, t, 0x2931), TX_CLOCKS, 0, 100_000)
                .await?;
            self.update(l.link_clock, 0xf << (4 * plan.link), 0)?;
            self.dp_phy_consumers(t)?;
            self.dp_phy_off(t)
        }
        .await;
        match result {
            Ok(()) => {
                self.status.uhbr_link = None;
                self.status.state = State::DpPhyDisabled;
                Ok(())
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    pub(in super::super::super) async fn stop_uhbr_link(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
    ) -> Result<(), Error> {
        self.stop_uhbr_link_with(io, path, true).await
    }
    /// The sink is gone (HPD low): no sink D3 write.
    pub(in super::super::super) async fn stop_unplugged_uhbr_link(
        &mut self,
        io: &mut impl UhbrTransport,
        path: Path,
    ) -> Result<(), Error> {
        if self.hpd_sense(path)? {
            return Err(Error::Busy);
        }
        self.stop_uhbr_link_with(io, path, false).await
    }
}
impl Otg {
    /// Enable and train a 128b/132b link on HPO link encoder `link`.
    /// # Safety
    /// enable_dp_phy's obligations, with `settings` within what the board,
    /// sink and any repeater chain allow and `link` unused by any display.
    pub(crate) async unsafe fn train_uhbr_link(
        &mut self,
        clocks: &mut clocks::ClockManager,
        io: &mut dmub::Dmub,
        path: Path,
        settings: UhbrSettings,
        link: u8,
    ) -> Result<UhbrLinkTrained, Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        let (held, layout) = self.0.held();
        clocks
            .pipe_clocks_except(self.0.io.0, &|at| held_by_sibling(held, layout, at))
            .map_err(Error::Clocks)?;
        self.0.train_uhbr_link(io, path, settings, link).await
    }
    /// Stop a trained or refused 128b/132b link with no stream on it.
    /// # Safety
    /// As for `stop_dp_link`.
    pub(crate) async unsafe fn stop_uhbr_link(
        &mut self,
        io: &mut dmub::Dmub,
        path: Path,
    ) -> Result<(), Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.stop_uhbr_link(io, path).await
    }
    /// As `stop_uhbr_link` for a departed sink: no AUX, refused while HPD
    /// is high.
    /// # Safety
    /// As for `stop_uhbr_link`.
    pub(crate) async unsafe fn stop_unplugged_uhbr_link(
        &mut self,
        io: &mut dmub::Dmub,
        path: Path,
    ) -> Result<(), Error> {
        if !io.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.stop_unplugged_uhbr_link(io, path).await
    }
}
