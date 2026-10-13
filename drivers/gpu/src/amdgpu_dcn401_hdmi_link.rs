//! Native DCN401 TMDS HDMI link bring-up and teardown for one 8-bpc RGB
//! stream up to 600 MHz, scrambled with a 1/4-rate clock channel above
//! 340 MHz (the sink's SCDC is the caller's; no deep colour). Linux order:
//! dcn401_program_pix_clk (SET_PIXEL_CLOCK, deep-colour resync),
//! link_set_dpms_on_pre_enable_link (dcn401_link_encoder_setup,
//! enc401_stream_encoder_hdmi_set_stream_attribute) and enable_link_hdmi
//! (setup_dio_stream_encoder, dcn10_link_encoder_enable_tmds_output). Like
//! dcn401_enable_stream, TMDS never routes the DCCG frontend symclk.
//! No Audio InfoFrame is sent: this owner carries no audio.
use super::*;
use crate::{
    amdgpu_dcn_inventory::{Connector, Path},
    amdgpu_dmub_navi48 as dmub,
};
use core::future::Future;

#[path = "amdgpu_dcn401_hdmi_video.rs"]
mod video;
pub use video::HdmiVideoRunning;

/// Highest TMDS character rate without scrambling (HDMI 1.4). Above it the
/// stream scrambles and the clock channel runs at 1/4 rate. Linux's encoder
/// switches at >= 340 MHz but tells the sink only at > 340 MHz; both use > here
/// so source and sink can never disagree.
pub const TMDS_SCRAMBLE_KHZ: u32 = 340_000;
/// Linux's TMDS ceiling (dcn401_program_pix_clk); 25 MHz is HDMI's floor.
pub const TMDS_MAX_KHZ: u32 = 600_000;
const TMDS_MIN_KHZ: u32 = 25_000;
const LANES_MASK: u32 = 0x3e3e3e3e;
const LANES_OFF: u32 = 0x02020202;
const TX_CLOCKS: u32 = 0x6f0;
// DIG_FE_CLK_CNTL: DISPCLK_G and SYMCLK_FE_G clock-on with CLK_EN, no reset.
const FE_ON: u32 = 0xc10;
// DIG_BE_CLK_CNTL: SYMCLK_G clock-on and CLK_EN. TMDS/HDCP clock-on bits are
// not required: Linux never waits for them.
const BE_ON: u32 = 0x810;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HdmiLinkRequest {
    pub stream: u8,
    pub pipe: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HdmiLinkReady {
    pub path: Path,
    pub request: HdmiLinkRequest,
    pub blank: BlankApplied,
    pub pixel_khz: u32,
    /// Above TMDS_SCRAMBLE_KHZ: scrambled, 1/4-rate clock channel.
    pub scrambled: bool,
    controls: [u32; 17],
    /// Every backend's frontend selection, so no other route moves.
    backend_routes: [u32; 4],
    /// The stream's DCCG symclk route, which TMDS leaves untouched.
    clock_route: u32,
    /// Transmitter enabled: lanes, TX clocks and both clock-on witnesses live.
    on: bool,
}
impl HdmiLinkReady {
    fn registers(self, l: Layout) -> [(u64, u32); 17] {
        let phy = self.path.transmitter;
        let s = self.request.stream;
        let be = |r| DpStream::Dio(phy).at(l, r);
        let fe = |r| DpStream::Dio(s).at(l, r);
        let bank1 = l.dio_clock - 0xa0 * 4;
        [
            (l.base + (0x179a + 3 * u64::from(phy)) * 4, 0x773), // DIO/HPO mux
            (be(0x20bc), 0x70007f01), // HPD, frontend selection, dual-link
            (be(0x20bb), 0x77),       // backend mode, clock request, resets
            (be(0x20bd), 1),          // backend enable
            (be(0x20eb), 1),          // TMDS_CTL0, Linux's legacy setting
            (bank1 + (0x40 + u64::from(phy)) * 4, 0x30), // PHYPLL deep colour
            (fe(0x2093), 0x177),      // OTG source, stereo source and gate
            (fe(0x2094), 0x37),       // frontend mode, clock request, reset
            (fe(0x2095), 1),          // frontend enable
            (fe(0x209b), 0x3ff),      // FIFO; RESET_DONE is checked separately
            // Stream mappers are contiguous, NOT in the DIO stride.
            (l.base + (0x1f0d + u64::from(s)) * 4, 7),
            (fe(0x209e), 0x3100701f), // HDMI_CONTROL (not error/metadata status)
            (fe(0x20a2), 0x1031),     // GC/NULL send, ACP off
            (fe(0x20a8), 1),          // GC AVMUTE
            (fe(0x20a5), u32::MAX),   // generic packets 0..7: only AVI (0)
            (fe(0x20a9), 0xffff),     // generic packet 0 line
            (fe(0x20b1), 0x1000),     // HDMI_DB_DISABLE
        ]
    }
}
pub(super) trait Firmware {
    fn ready(&self) -> bool;
    fn pixel_clock(
        &mut self,
        path: Path,
        pipe: u8,
        khz: u32,
    ) -> impl Future<Output = Result<(), dmub::Error>> + Send;
    fn stream_setup(
        &mut self,
        stream: u8,
        khz: u32,
    ) -> impl Future<Output = Result<(), dmub::Error>> + Send;
    fn enable(
        &mut self,
        path: Path,
        khz: u32,
    ) -> impl Future<Output = Result<(), dmub::Error>> + Send;
    fn disable(&mut self, path: Path) -> impl Future<Output = Result<(), dmub::Error>> + Send;
}
impl Firmware for dmub::Dmub {
    fn ready(&self) -> bool {
        self.state() == dmub::State::Running && self.mailbox_state() == dmub::MailboxState::Ready
    }
    async fn pixel_clock(&mut self, path: Path, pipe: u8, khz: u32) -> Result<(), dmub::Error> {
        self.set_tmds_pixel_clock(path, pipe, khz).await
    }
    async fn stream_setup(&mut self, stream: u8, khz: u32) -> Result<(), dmub::Error> {
        self.setup_hdmi_stream(stream, khz).await
    }
    async fn enable(&mut self, path: Path, khz: u32) -> Result<(), dmub::Error> {
        self.enable_tmds(path, khz).await
    }
    async fn disable(&mut self, path: Path) -> Result<(), dmub::Error> {
        self.disable_tmds(path).await
    }
}
fn phy_at(l: Layout, phy: u8, reg: u64) -> u64 {
    l.base + (reg + u64::from(phy) * 0xd8) * 4
}
/// All four TMDS lanes report CLK_RDY without reset, disable or a pending
/// handshake (DATA_EN is not a witness), as the DP PHY owner reads them.
fn lanes_active(value: u32) -> bool {
    (0..4).all(|lane| (value >> (8 * lane)) & 0x37 == 4)
}
/// The AVI InfoFrame Linux's set_avi_info_frame builds for this stream: RGB,
/// active format valid with both bars, underscan, uniform scaling, picture
/// aspect, IT content. VIC stays 0 and RGB quantization at its default: narf
/// matches no CTA mode, and CTA-861 gives a VIC-0 (IT) format full-range RGB,
/// which is what this owner sends. Returns HB0..HB3 then SB0..SB27, as the
/// nine VPG_GENERIC_PACKET_DATA words carry them (HB3 and SB28.. stay zero).
pub(in crate::amdgpu_dcn401_otg) fn avi_infoframe(t: &crate::amdgpu_dml::Timing) -> [u8; 36] {
    let mut p = [0u8; 36];
    p[..3].copy_from_slice(&[0x82, 2, 13]);
    let sb = &mut p[4..];
    sb[1] = 2 | 3 << 2 | 1 << 4; // S underscan, B both bars, A0 valid, Y RGB
    sb[2] = 8; // R same as picture, M no data, C no data
    sb[3] = 1 << 7; // SC uniform, Q default, EC 0, ITC
                    // Linux's bar fields: borders are zero, so bottom/right are total + 1.
    sb[8..10].copy_from_slice(&((t.v_total + 1) as u16).to_le_bytes());
    sb[12..14].copy_from_slice(&((t.h_total + 1) as u16).to_le_bytes());
    let sum = p[..3]
        .iter()
        .chain(&p[5..18])
        .fold(0u8, |s, b| s.wrapping_add(*b));
    p[4] = 0u8.wrapping_sub(sum);
    p
}
impl<I: Io> Engine<I> {
    /// Every consumer outside this link must be idle. The owned backend/PHY,
    /// frontend and (when `timing`) the pipe's OTG are checked by their own
    /// witnesses instead.
    fn hdmi_consumers(&mut self, plan: &HdmiLinkReady, timing: bool) -> Result<(), Error> {
        let l = self.layout;
        let (phy, s, pipe) = (
            plan.path.transmitter,
            plan.request.stream,
            plan.request.pipe,
        );
        let be = |r| DpStream::Dio(phy).at(l, r);
        let fe = |r| DpStream::Dio(s).at(l, r);
        let owned = [
            be(0x20bb),
            be(0x20bd),
            phy_at(l, phy, 0x2943),
            phy_at(l, phy, 0x2931),
            fe(0x2094),
            fe(0x2095),
            fe(0x209b),
        ];
        for (reg, mask) in l.idle {
            if owned.contains(&reg)
                || timing && (reg == l.otg(pipe, CONTROL) || reg == l.otg(pipe, CLOCK))
            {
                continue;
            }
            if self.read(reg)? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        // No HPO stream root or forced DCIO->PHY clock may share this PHY.
        if self.read(l.link_clock - 4)? & 0x8888 != 0
            || self.read(l.base + (0x52 + u64::from(phy)) * 4)? & 1 != 0
        {
            return Err(Error::Busy);
        }
        for p in 0..4 {
            if p != s {
                self.dp_encoder_quiet(DpStream::Dio(p))?;
            }
            self.dp_encoder_quiet(DpStream::Hpo(p))?;
            if self.read(l.otg(p, LOCK))? & 0x101 != 0 || self.read(l.otg(p, CLOCK))? & 0x10 != 0 {
                return Err(Error::Busy);
            }
        }
        // Packet, audio, metadata and DP-video producers need their own owners.
        for (reg, mask) in [
            (0x2091, 0x1010),     // dynamic metadata enable/pending
            (0x209d, 1),          // HDMI metadata
            (0x20a6, u32::MAX),   // generic packets 8..14
            (0x20a7, 0x3fffffff), // immediate generic send/pending
            (0x2122, 0x10001),    // DP video
        ] {
            if self.read(fe(reg))? & mask != 0 {
                return Err(Error::Busy);
            }
        }
        if self.read(fe(0x2094))? & 0x5020 != 0 || self.read(fe(0x209e))? & 0x400 != 0 {
            return Err(Error::Busy);
        }
        Ok(())
    }
    /// The plan's owned registers, routes and phase witnesses. `timing`
    /// exempts the pipe's running OTG; its blank/OPP state is the video
    /// owner's to check.
    pub(in crate::amdgpu_dcn401_otg) fn hdmi_link_verify(
        &mut self,
        plan: HdmiLinkReady,
        timing: bool,
    ) -> Result<(), Error> {
        self.hdmi_consumers(&plan, timing)?;
        let l = self.layout;
        for ((at, mask), expected) in plan.registers(l).into_iter().zip(plan.controls) {
            if self.read(at)? & mask != expected {
                return Err(Error::Readback(at));
            }
        }
        for b in 0..4 {
            let at = DpStream::Dio(b).at(l, 0x20bc);
            if self.read(at)? & 0x7f00 != plan.backend_routes[usize::from(b)] {
                return Err(Error::Readback(at));
            }
        }
        let route = l.dio_clock + u64::from(plan.request.stream) * 4;
        if self.read(route)? & 0x711 != plan.clock_route {
            return Err(Error::Readback(route));
        }
        let pixel = (l.dio_clock - 0xa0 * 4) + (0x80 + 4 * u64::from(plan.request.pipe)) * 4;
        if self.read(pixel)? & 0x1010 != 0 {
            return Err(Error::Readback(pixel)); // DP DTO must stay off for TMDS
        }
        let phy = plan.path.transmitter;
        let be = |r| DpStream::Dio(phy).at(l, r);
        let fe = |r| DpStream::Dio(plan.request.stream).at(l, r);
        if plan.on {
            let lanes = phy_at(l, phy, 0x2943);
            if !lanes_active(self.read(lanes)?) {
                return Err(Error::Readback(lanes));
            }
            for (at, mask, value) in [
                (phy_at(l, phy, 0x2931), TX_CLOCKS, TX_CLOCKS),
                (be(0x20bb), BE_ON, BE_ON),
                (fe(0x2094), 0xc30, FE_ON),
                // RESET_DONE follows the owned reset request once symclk runs.
                (fe(0x209b), 0x100000, (plan.controls[9] & 2) << 19),
            ] {
                if self.read(at)? & mask != value {
                    return Err(Error::Readback(at));
                }
            }
        } else {
            self.hdmi_phy_off(phy)?;
        }
        if !timing && self.read(l.otg(plan.request.pipe, CONTROL))? & 0x10001 != 0 {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn hdmi_phy_off(&mut self, phy: u8) -> Result<(), Error> {
        let l = self.layout;
        for (at, mask, value) in [
            (phy_at(l, phy, 0x2943), LANES_MASK, LANES_OFF),
            (phy_at(l, phy, 0x2931), TX_CLOCKS, 0),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    fn hdmi_update(
        &mut self,
        plan: &mut HdmiLinkReady,
        slot: usize,
        mask: u32,
        value: u32,
    ) -> Result<(), Error> {
        self.hdmi_link_verify(*plan, false)?;
        self.update(plan.registers(self.layout)[slot].0, mask, value)?;
        plan.controls[slot] = (plan.controls[slot] & !mask) | value;
        Ok(())
    }
    fn hdmi_route(&mut self, plan: &mut HdmiLinkReady, connect: bool) -> Result<(), Error> {
        let value = if connect {
            0x100 << plan.request.stream
        } else {
            0
        };
        self.hdmi_update(plan, 1, 0x7f00, value)?;
        plan.backend_routes[usize::from(plan.path.transmitter)] = value;
        Ok(())
    }
    /// enc35_reset_fifo: with the frontend symclk on, wait for each
    /// RESET_DONE edge; without it, only the native 10 us settle applies.
    async fn hdmi_fifo(&mut self, plan: &mut HdmiLinkReady, timing: bool) -> Result<(), Error> {
        let fifo = plan.registers(self.layout)[9].0;
        let clock = plan.registers(self.layout)[7].0;
        for reset in [true, false] {
            self.hdmi_link_verify(*plan, timing)?;
            self.update(fifo, 2, u32::from(reset) << 1)?;
            plan.controls[9] = (plan.controls[9] & !2) | u32::from(reset) << 1;
            if self.read(clock)? & 0x800 != 0 {
                self.wait(fifo, 0x100000, u32::from(reset) << 20, 5000)
                    .await?;
            } else {
                narf_time::SleepUntil::new(narf_time::Deadline::after_us(10).as_instant()).await;
            }
        }
        self.hdmi_link_verify(*plan, timing)?;
        self.update(fifo, 1, 1)?;
        plan.controls[9] |= 1;
        Ok(())
    }
    /// enc3_update_hdmi_info_packet(0, AVI): DB disable, VPG power-on if
    /// gated, conflict clear, nine data words, immediate update, then send
    /// every frame on line 2. No AFMT audio clock: this owner has no audio.
    async fn hdmi_avi(&mut self, plan: &mut HdmiLinkReady) -> Result<(), Error> {
        let l = self.layout;
        let stream = plan.request.stream;
        let vpg = move |r| DpStream::Dio(stream).at(l, r);
        self.hdmi_update(plan, 16, 0x1000, 0x1000)?;
        self.hdmi_link_verify(*plan, false)?;
        if self.read(vpg(0x206d))? & 0x100 != 0 {
            self.update(vpg(0x206d), 0x11, 1)?;
            self.wait(vpg(0x206d), 0x100, 0, 1000).await?;
        }
        self.wait(vpg(0x206c), 2, 0, 500).await?;
        let packet = avi_infoframe(&plan.blank.timing.request.timing);
        self.access(|io| {
            // CONFLICT_CLR and the data port are commands, not stored state.
            let status = checked(io.read(vpg(0x206c)))?;
            io.write(vpg(0x206c), status | 0x10);
            let access = checked(io.read(vpg(0x2068)))?;
            io.write(vpg(0x2068), access & !0xff);
            for word in packet.chunks_exact(4) {
                io.write(
                    vpg(0x2069),
                    u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
                );
            }
            // Self-clearing: latch the double-buffered packet immediately.
            let immediate = checked(io.read(vpg(0x206b)))?;
            io.write(vpg(0x206b), immediate | 1);
            Ok(())
        })?;
        self.hdmi_update(plan, 14, 3, 3)?;
        self.hdmi_update(plan, 15, 0xffff, 2)
    }
    fn hdmi_link_plan(
        &mut self,
        path: Path,
        request: HdmiLinkRequest,
        clock: dccg::Applied,
    ) -> Result<HdmiLinkReady, Error> {
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        if path.connector != Connector::HdmiTypeA {
            return Err(Error::Unsupported);
        }
        if path.transmitter >= 4
            || !(1..=4).contains(&path.hpd)
            || request.stream >= 4
            || request.pipe >= 4
        {
            return Err(Error::Invalid);
        }
        let blank = self.status.blanks[usize::from(request.pipe)].ok_or(Error::Invalid)?;
        if blank.request.pipe != request.pipe
            || self.blank_timing(blank.request, clock)? != blank.timing
        {
            return Err(Error::Invalid);
        }
        let timing = blank.timing.request;
        if timing.signal != Signal::Tmds || blank.request.depth != ColorDepth::Bpc8 {
            return Err(Error::Unsupported);
        }
        // RGB: Linux's dcn401_calculate_dccg_tmds_div_value picks divide-by-4.
        if clock.request.pixel
            != (dccg::PixelClock::Tmds {
                divider: dccg::TmdsDivider::By4,
            })
        {
            return Err(Error::Unsupported);
        }
        timing.validate_clock(clock)?;
        timing.plan()?;
        let pixel_khz = timing.timing.pixel_clock_khz;
        if !(TMDS_MIN_KHZ..=TMDS_MAX_KHZ).contains(&pixel_khz) {
            return Err(Error::Unsupported);
        }
        let l = self.layout;
        let mut plan = HdmiLinkReady {
            path,
            request,
            blank,
            pixel_khz,
            scrambled: pixel_khz > TMDS_SCRAMBLE_KHZ,
            controls: [0; 17],
            backend_routes: [0; 4],
            clock_route: 0,
            on: false,
        };
        for (i, (at, mask)) in plan.registers(l).into_iter().enumerate() {
            plan.controls[i] = self.read(at)? & mask;
        }
        for b in 0..4 {
            let route = self.read(DpStream::Dio(b).at(l, 0x20bc))? & 0x7f00;
            plan.backend_routes[usize::from(b)] = route;
            if route & 0x100 << request.stream != 0 {
                return Err(Error::Busy);
            }
        }
        plan.clock_route = self.read(l.dio_clock + u64::from(request.stream) * 4)? & 0x711;
        // A stopped backend with no frontend, dual link or pending reset; an
        // idle frontend with a stopped FIFO; and no frontend symclk route.
        let be = |r| DpStream::Dio(path.transmitter).at(l, r);
        let fe = |r| DpStream::Dio(request.stream).at(l, r);
        if plan.controls[1] & 0x7f01 != 0
            || plan.controls[3] != 0
            || self.read(be(0x20bb))? & (clocks::backend_clock_mask(path.transmitter) | 0x60) != 0
            || self.read(fe(0x2094))? & 0x2c30 != 0
            || plan.controls[8] != 0
            || self.read(fe(0x209b))? & 0x100083 != 0
            || plan.clock_route & 0x10 != 0
            || plan.controls[14] != 0
        {
            return Err(Error::Busy);
        }
        self.hdmi_link_verify(plan, false)?;
        Ok(plan)
    }
    async fn hdmi_link_start(
        &mut self,
        firmware: &mut impl Firmware,
        plan: &mut HdmiLinkReady,
    ) -> Result<(), Error> {
        let (path, khz) = (plan.path, plan.pixel_khz);
        let (stream, pipe) = (plan.request.stream, plan.request.pipe);
        // dcn401_program_pix_clk: PHY PLL, then the deep-colour resync (24 bpp).
        self.hdmi_link_verify(*plan, false)?;
        firmware
            .pixel_clock(path, pipe, khz)
            .await
            .map_err(Error::Firmware)?;
        self.hdmi_update(plan, 5, 0x30, 0)?;
        self.hdmi_update(plan, 4, 1, 1)?;
        // dcn401_link_encoder_setup(HDMI), with the HPD source and DIO mux.
        for (slot, mask, value) in [
            (0, 3, 0),
            (1, 0x70000000, u32::from(path.hpd - 1) << 28),
            (2, 7, 3),
            (2, 0x10, 0x10),
            (3, 1, 1),
        ] {
            self.hdmi_update(plan, slot, mask, value)?;
        }
        // enc401_stream_encoder_hdmi_set_stream_attribute.
        self.hdmi_link_verify(*plan, false)?;
        firmware
            .stream_setup(stream, khz)
            .await
            .map_err(Error::Firmware)?;
        for (slot, mask, value) in [
            (6, 7, u32::from(pipe)),         // dig_connect_to_otg
            (6, 0x70, u32::from(pipe) << 4), // stereo sync source
            (6, 0x100, 0x100),               // stereo sync gate (stereo off)
            (11, 0x7000, 0),                 // RGB pixel encoding and colour format
            // GEN v1, keepout, no extra NULL; above 340 MHz the data
            // scrambler and the 1/4-rate clock channel (HDMI_CLOCK_CHANNEL_RATE).
            (11, 0x0100001f, 0x19 | if plan.scrambled { 0x6 } else { 0 }),
            (11, 0x30000000, 0), // 24-bit depth
            (12, 0x31, 0x31),    // GC every frame, NULL packets
            (12, 0x1000, 0),     // no ACP
            (13, 1, 0),          // AVMUTE off
        ] {
            self.hdmi_update(plan, slot, mask, value)?;
        }
        self.hdmi_avi(plan).await?;
        // setup_dio_stream_encoder: BE<-FE, TMDS-HDMI frontend, stream mapper,
        // one pixel per cycle, then enc35_enable_fifo.
        self.hdmi_route(plan, true)?;
        for (slot, mask, value) in [
            (7, 7, 3),
            (7, 0x10, 0x10),
            (8, 1, 1),
            (10, 7, u32::from(path.transmitter)),
            (9, 0x300, 0),
            (9, 0x7c, 7 << 2),
        ] {
            self.hdmi_update(plan, slot, mask, value)?;
        }
        self.hdmi_fifo(plan, false).await?;
        // dcn10_link_encoder_enable_tmds_output, then observe the transmitter.
        self.hdmi_link_verify(*plan, false)?;
        firmware.enable(path, khz).await.map_err(Error::Firmware)?;
        let l = self.layout;
        let phy = path.transmitter;
        let lanes = phy_at(l, phy, 0x2943);
        let deadline = narf_time::Deadline::after_us(100_000);
        while !lanes_active(self.read(lanes)?) {
            if deadline.expired() {
                return Err(Error::Timeout(lanes));
            }
            narf_time::SleepUntil::new(narf_time::Deadline::after_us(1).as_instant()).await;
        }
        self.wait(phy_at(l, phy, 0x2931), TX_CLOCKS, TX_CLOCKS, 100_000)
            .await?;
        self.wait(DpStream::Dio(phy).at(l, 0x20bb), BE_ON, BE_ON, 100_000)
            .await?;
        self.wait(DpStream::Dio(stream).at(l, 0x2094), 0xc30, FE_ON, 100_000)
            .await?;
        plan.on = true;
        self.hdmi_link_verify(*plan, false)
    }
    pub(in crate::amdgpu_dcn401_otg) async fn prepare_hdmi_link(
        &mut self,
        firmware: &mut impl Firmware,
        path: Path,
        request: HdmiLinkRequest,
        clock: dccg::Applied,
    ) -> Result<HdmiLinkReady, Error> {
        if !firmware.ready() {
            return Err(Error::Busy);
        }
        let mut plan = self.hdmi_link_plan(path, request, clock)?;
        self.status.state = State::PreparingHdmiLink(path.transmitter);
        match self.hdmi_link_start(firmware, &mut plan).await {
            Ok(()) => {
                self.status.hdmi_link_ready = Some(plan);
                self.status.state = State::HdmiLinkReady(path.transmitter);
                Ok(plan)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    async fn hdmi_link_stop(
        &mut self,
        firmware: &mut impl Firmware,
        plan: &mut HdmiLinkReady,
    ) -> Result<(), Error> {
        let l = self.layout;
        let phy = plan.path.transmitter;
        let be = |r| DpStream::Dio(phy).at(l, r);
        // dcn10_link_encoder_disable_output: firmware owns the backend and
        // RDPCS controls; observe them, never manufacture off witnesses.
        self.hdmi_link_verify(*plan, false)?;
        firmware.disable(plan.path).await.map_err(Error::Firmware)?;
        self.wait(be(0x20bd), 1, 0, 100_000).await?;
        self.wait(
            be(0x20bb),
            clocks::backend_clock_mask(phy) | 0x60,
            0,
            100_000,
        )
        .await?;
        self.wait(phy_at(l, phy, 0x2943), LANES_MASK, LANES_OFF, 100_000)
            .await?;
        self.wait(phy_at(l, phy, 0x2931), TX_CLOCKS, 0, 100_000)
            .await?;
        // The firmware may leave the backend in TMDS or DP mode; nothing else.
        let clock = self.read(be(0x20bb))? & 0x77;
        if !matches!(clock & 7, 0 | 3) || clock & 0x70 != 0 {
            return Err(Error::Readback(be(0x20bb)));
        }
        plan.controls[2] = clock;
        plan.controls[3] = 0;
        plan.on = false;
        // reset_dio_stream_encoder: FIFO, frontend, then the BE<-FE route;
        // enc1_reset_hdmi_stream_attribute restores the native defaults.
        self.hdmi_update(plan, 9, 1, 0)?;
        self.hdmi_update(plan, 8, 1, 0)?;
        self.hdmi_update(plan, 7, 0x10, 0)?;
        let fe_clock = plan.registers(l)[7].0;
        self.wait(fe_clock, 0x2c10, 0, 1000).await?;
        self.hdmi_update(plan, 9, 0x300, 0)?;
        self.hdmi_route(plan, false)?;
        // enc3_stream_encoder_stop_hdmi_info_packets for the AVI packet.
        self.hdmi_update(plan, 14, 3, 0)?;
        self.hdmi_update(plan, 15, 0xffff, 0)?;
        self.hdmi_update(plan, 11, 0x0100001f, 0x11)?;
        self.hdmi_link_verify(*plan, false)
    }
    pub(in crate::amdgpu_dcn401_otg) async fn stop_hdmi_link(
        &mut self,
        firmware: &mut impl Firmware,
        path: Path,
    ) -> Result<(), Error> {
        let mut plan = self.status.hdmi_link_ready.ok_or(Error::Invalid)?;
        if self.status.state != State::HdmiLinkReady(path.transmitter) || !firmware.ready() {
            return Err(Error::Busy);
        }
        if plan.path != path {
            return Err(Error::Invalid);
        }
        self.hdmi_link_verify(plan, false)?;
        self.status.state = State::StoppingHdmiLink(path.transmitter);
        match self.hdmi_link_stop(firmware, &mut plan).await {
            Ok(()) => {
                self.status.hdmi_link_ready = None;
                self.status.state = State::HdmiLinkStopped;
                Ok(())
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// Program the PHY PLL, encoders and transmitter of one direct TMDS HDMI
    /// port for the staged black timing of `request.pipe`, with that timing
    /// still stopped.
    /// # Safety
    /// Validated direct HDMI path without retimers, ACPI interlocks or SSC
    /// workarounds. The sink accepts this mode, and its SCDC TMDS
    /// configuration (scrambling and 1/40 clock ratio above 340 MHz, neither
    /// at or below) was written first, as Linux's write_scdc_data does. Exclude CPU/firmware/FAMS and display/link/clock/power/reset
    /// writers and audio/metadata/HDCP producers; retain every allocation and
    /// translation. Success proves transmitter and clock witnesses only, not
    /// sink presentation; failure or cancellation needs independent recovery.
    pub(crate) async unsafe fn prepare_hdmi_link(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        firmware: &mut dmub::Dmub,
        path: Path,
        request: HdmiLinkRequest,
    ) -> Result<HdmiLinkReady, Error> {
        if !firmware.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        let clock = dccg
            .retained_timing_clock(self.0.io.0, clocks, request.pipe)
            .map_err(Error::PipeClocks)?;
        let history = self.0.status.hdmi_link_ready;
        let ready = self
            .0
            .prepare_hdmi_link(firmware, path, request, clock)
            .await?;
        match dccg.retained_timing_clock(self.0.io.0, clocks, request.pipe) {
            Ok(current) if current == clock => Ok(ready),
            result => {
                let e = result
                    .err()
                    .map(Error::PipeClocks)
                    .unwrap_or(Error::Invalid);
                self.0.status.hdmi_link_ready = history;
                self.0.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
    /// Disable this owner's transmitter and frontend with the timing stopped.
    /// # Safety
    /// prepare_hdmi_link's exclusion and retention obligations. Success proves
    /// backend/lane/TX-clock and frontend clock-off readback, not analog power.
    pub(crate) async unsafe fn stop_hdmi_link(
        &mut self,
        firmware: &mut dmub::Dmub,
        path: Path,
    ) -> Result<(), Error> {
        if !firmware.matches_display(self.0.io.0, self.0.layout.base) {
            return Err(Error::Invalid);
        }
        self.0.stop_hdmi_link(firmware, path).await
    }
}
