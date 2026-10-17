//! Native DCN401 Display Stream Compression on a pipe's own DSC (DSC n on
//! OPP n; with ODM 2:1 each segment's OPP feeds its own DSC, which
//! compresses half the line with half the slices), as Linux's
//! link_set_dsc_on_stream drives it for DP SST:
//! the DSC power domain (dcn32_dsc_pg_control), dsc_write_to_registers,
//! dsc401_enable from the OPP, then optc2/3_set_dsc_config. Stop is the
//! reverse: OPTC DSC off, dsc401_disconnect and dsc401_disable, the domain
//! gated. DSCCLK is the clock owner's (dccg401_set_dto_dscclk).
use super::*;
use crate::amdgpu_dsc::{self, DscConfig, DscRegisters, DscTiming, Encoding, PixelFormat};

/// DSC_TOP0 .. DSC_TOP3 (DCN bank 2), 0x5c apart.
const DSC_BASE: u64 = 0x3000;
const DSC_STRIDE: u64 = 0x5c;
const TOP_CONTROL: u64 = 0;
const DEBUG_CONTROL: u64 = 1;
const CIF_CONFIG0: u64 = 5;
const CONFIG0: u64 = 0xa;
const CONFIG1: u64 = 0xb;
const INTERRUPT_CONTROL0: u64 = 0xe;
const PPS_CONFIG0: u64 = 0x12;
/// DSCRM0_DSCRM_DSC_FORWARD_CONFIG; DSCRM n follows.
const FORWARD: u64 = 0x1a64;
/// OPTC_BYTES_PER_PIXEL and OPTC_WIDTH_CONTROL (ODM n).
const BYTES_PER_PIXEL: u64 = 0x1acd;
const WIDTH_CONTROL: u64 = 0x1ace;
/// DSC401's max_image_width.
const MAX_IMAGE_WIDTH: u32 = 5184;

/// The DSC timing a DP RGB stream's DSC compresses.
pub(super) fn dsc_timing(t: &Timing) -> DscTiming {
    DscTiming {
        pix_clk_100hz: t.pixel_clock_khz * 10,
        h_active: t.h_active,
        h_total: t.h_total,
        v_active: t.v_active,
        v_total: t.v_total,
        bpc: 8,
        encoding: Encoding::Rgb,
    }
}

/// dsc401_validate_stream plus this owner's shape: one DSC per ODM segment
/// (at most four slices each, the slices split evenly) on an 8-bit RGB
/// 8b/10b DP stream. These are the whole picture's registers: the PPS the
/// sink receives and the OPTC's bytes per pixel and slice width.
pub(super) fn dsc_registers(request: &Request, cfg: &DscConfig) -> Result<DscRegisters, Error> {
    let segments = if request.odm.is_some() { 2 } else { 1 };
    if request.signal != Signal::DisplayPort
        || request.ycbcr420
        || cfg.slices_h % segments != 0
        || cfg.slices_h > 4 * segments
        || request.timing.h_active > MAX_IMAGE_WIDTH * segments
    {
        return Err(Error::Unsupported);
    }
    amdgpu_dsc::prepare(&dsc_timing(&request.timing), cfg).ok_or(Error::Invalid)
}

/// One segment DSC's registers: Linux's dsc_cfg with pic_width and
/// num_slices_h divided by the ODM segment count (the whole picture's
/// without ODM).
fn segment_registers(request: &Request, cfg: &DscConfig) -> Result<DscRegisters, Error> {
    let full = dsc_registers(request, cfg)?;
    if request.odm.is_none() {
        return Ok(full);
    }
    let t = request.timing;
    let half = Timing {
        pixel_clock_khz: t.pixel_clock_khz / 2,
        h_active: t.h_active / 2,
        h_total: t.h_total / 2,
        ..t
    };
    let cfg = DscConfig {
        slices_h: cfg.slices_h / 2,
        ..*cfg
    };
    let segment = amdgpu_dsc::prepare(&dsc_timing(&half), &cfg).ok_or(Error::Invalid)?;
    // Both halves slice the line identically, so the OPTC sees one slice
    // width and byte rate either way.
    if segment.slice_width != full.slice_width || segment.bytes_per_pixel != full.bytes_per_pixel {
        return Err(Error::Invalid);
    }
    Ok(segment)
}

/// dsc_write_to_registers' values for DSC registers 0x00..0x28 (offset,
/// value), each written whole (REG_SET) and masked to its fields.
fn dsc_values(r: &DscRegisters) -> alloc::vec::Vec<(u64, u32)> {
    let p = &r.pps;
    let bpc = u32::from(p.bits_per_component);
    let mut v = alloc::vec![
        (DEBUG_CONTROL, 0),
        (
            CIF_CONFIG0,
            (r.pixel_format as u32) << 12 & 0x7000 | bpc << 16 & 0xf_0000
        ),
        (
            CONFIG0,
            r.ich_reset_at_eol & 0xf
                | (r.slices_h - 1) << 4 & 0x30
                | u32::from(r.alternate_ich_encoding) << 8
                | (r.slices_v - 1) << 16,
        ),
        (CONFIG1, r.rc_buffer_model_size & 0x3_ffff),
        (INTERRUPT_CONTROL0, 0),
    ];
    let native = matches!(
        r.pixel_format,
        PixelFormat::Native422 | PixelFormat::Native420
    );
    let bpp = if native { r.bpp_x32 } else { r.bpp_x32 >> 1 };
    let pair = |a: u32, b: u32| a & 0xffff | b << 16;
    let range = |i: usize| {
        let (min, max, ofs) = p.rc_range_params[i];
        u32::from(min) & 0x1f | (u32::from(max) & 0x1f) << 5 | (u32::from(ofs) & 0x3f) << 10
    };
    let th = |i: usize| u32::from(p.rc_buf_thresh[i]) & 0xff;
    let pps = [
        u32::from(p.dsc_version_minor) & 0xf
            | (u32::from(p.line_buf_depth) & 0xf) << 24
            | (bpc & 0xf) << 28,
        bpp & 0x3ff
            | u32::from(r.pixel_format == PixelFormat::Simple422) << 11
            | u32::from(r.pixel_format == PixelFormat::Rgb) << 12
            | u32::from(p.block_pred_enable) << 13
            | u32::from(r.pixel_format == PixelFormat::Native422) << 14
            | u32::from(r.pixel_format == PixelFormat::Native420) << 15
            | u32::from(p.slice_chunk_size) << 16,
        pair(u32::from(p.pic_width), u32::from(p.pic_height)),
        pair(u32::from(p.slice_width), u32::from(p.slice_height)),
        u32::from(p.initial_xmit_delay) & 0x3ff,
        u32::from(p.initial_scale_value) & 0x3f | u32::from(p.scale_increment_interval) << 16,
        u32::from(p.scale_decrement_interval) & 0xfff
            | (u32::from(p.first_line_bpg_offset) & 0x1f) << 16
            | (u32::from(p.second_line_bpg_offset) & 0x1f) << 24,
        pair(u32::from(p.nfl_bpg_offset), u32::from(p.slice_bpg_offset)),
        pair(
            u32::from(p.nsl_bpg_offset),
            u32::from(p.second_line_offset_adj),
        ),
        pair(u32::from(p.initial_offset), u32::from(p.final_offset)),
        u32::from(p.flatness_min_qp) & 0x1f
            | (u32::from(p.flatness_max_qp) & 0x1f) << 8
            | u32::from(p.rc_model_size) << 16,
        u32::from(p.rc_edge_factor) & 0xf
            | (u32::from(p.rc_quant_incr_limit0) & 0x1f) << 8
            | (u32::from(p.rc_quant_incr_limit1) & 0x1f) << 16
            | (u32::from(p.rc_tgt_offset_low) & 0xf) << 24
            | (u32::from(p.rc_tgt_offset_high) & 0xf) << 28,
        th(0) | th(1) << 8 | th(2) << 16 | th(3) << 24,
        th(4) | th(5) << 8 | th(6) << 16 | th(7) << 24,
        th(8) | th(9) << 8 | th(10) << 16 | th(11) << 24,
        th(12) | th(13) << 8 | range(0) << 16,
        range(1) | range(2) << 16,
        range(3) | range(4) << 16,
        range(5) | range(6) << 16,
        range(7) | range(8) << 16,
        range(9) | range(10) << 16,
        range(11) | range(12) << 16,
        range(13) | range(14) << 16,
    ];
    v.extend(
        pps.iter()
            .enumerate()
            .map(|(i, &x)| (PPS_CONFIG0 + i as u64, x)),
    );
    v
}

impl<I: Io> Engine<I> {
    fn dsc_at(&self, dsc: u8, reg: u64) -> u64 {
        self.layout.base + (DSC_BASE + u64::from(dsc) * DSC_STRIDE + reg) * 4
    }
    fn dsc_forward_at(&self, dsc: u8) -> u64 {
        self.layout.base + (FORWARD + u64::from(dsc)) * 4
    }
    /// DSC `dsc` neither clocked nor forwarding, and no other DSC fed by
    /// OPP `dsc`.
    pub(super) fn dsc_idle(&mut self, dsc: u8) -> Result<(), Error> {
        for k in 0..4u8 {
            let forward = self.read(self.dsc_forward_at(k))?;
            let mine = k == dsc;
            if forward & 1 != 0 && (mine || (forward >> 4) & 7 == u32::from(dsc)) {
                return Err(Error::Busy);
            }
        }
        if self.dsc_powered(dsc)? && self.read(self.dsc_at(dsc, TOP_CONTROL))? & 1 != 0 {
            return Err(Error::Busy);
        }
        Ok(())
    }
    fn dsc_powered(&mut self, dsc: u8) -> Result<bool, Error> {
        // DOMAIN16-19_PG_STATUS: PGFSM power status 0 on, 2 off.
        let status = self.layout.base + (0x8a + 2 * u64::from(dsc)) * 4;
        Ok(self.read(status)? & 0xc000_0000 == 0)
    }
    /// dcn32_dsc_pg_control.
    async fn dsc_power(&mut self, dsc: u8, on: bool) -> Result<(), Error> {
        let l = self.layout;
        let ip_request = l.base + 0xa0 * 4;
        let original = self.read(ip_request)? & 1;
        if original == 0 {
            self.update(ip_request, 1, 1)?;
        }
        let config = l.base + (0x89 + 2 * u64::from(dsc)) * 4;
        let status = l.base + (0x8a + 2 * u64::from(dsc)) * 4;
        self.update(config, 1, u32::from(!on))?;
        self.wait(status, 0xc000_0000, if on { 0 } else { 0x8000_0000 }, 1000)
            .await?;
        if original == 0 {
            self.update(ip_request, 1, 0)?;
        }
        Ok(())
    }
    /// DSC on `pipe` for the prepared request: power, registers, enable
    /// from the OPP, then the OPTC's DSC mode, bytes per pixel and slice
    /// width.
    pub(super) async fn start_dsc(
        &mut self,
        request: &Request,
        cfg: &DscConfig,
    ) -> Result<(), Error> {
        let regs = dsc_registers(request, cfg)?;
        let segment = segment_registers(request, cfg)?;
        let pipe = request.pipe;
        // Each segment's DSC from its own OPP, the left one (this pipe's)
        // first, as dcn401_add_dsc_sequence_for_odm_change orders them.
        for dsc in core::iter::once(pipe).chain(request.odm) {
            self.dsc_idle(dsc)?;
            if !self.dsc_powered(dsc)? {
                self.dsc_power(dsc, true).await?;
            }
            for (reg, value) in dsc_values(&segment) {
                let at = self.dsc_at(dsc, reg);
                self.access(|io| {
                    io.write(at, value);
                    Ok(())
                })?;
                if self.read(at)? != value {
                    return Err(Error::Readback(at));
                }
            }
            self.update(self.dsc_at(dsc, TOP_CONTROL), 1, 1)?;
            self.update(self.dsc_forward_at(dsc), 0x71, 1 | u32::from(dsc) << 4)?;
        }
        let l = self.layout;
        self.update(l.odm(pipe, FORMAT), 0x30, 1 << 4)?; // OPTC_DSC_ENABLED_444
        let bytes = l.odm(pipe, BYTES_PER_PIXEL);
        self.access(|io| {
            io.write(bytes, regs.bytes_per_pixel & 0x7fff_ffff);
            Ok(())
        })?;
        if self.read(bytes)? != regs.bytes_per_pixel & 0x7fff_ffff {
            return Err(Error::Readback(bytes));
        }
        self.update(
            l.odm(pipe, WIDTH_CONTROL),
            0x1fff_0000,
            regs.slice_width << 16,
        )?;
        // optc3_set_dsc_config: V_SYNC_MODE stays 0 off HDMI FRL.
        Ok(())
    }
    /// The running DSC as programmed for `request`.
    pub(super) fn dsc_running(&mut self, request: &Request, cfg: &DscConfig) -> Result<(), Error> {
        let regs = dsc_registers(request, cfg)?;
        let segment = segment_registers(request, cfg)?;
        let pipe = request.pipe;
        for dsc in core::iter::once(pipe).chain(request.odm) {
            for (reg, value) in dsc_values(&segment) {
                let at = self.dsc_at(dsc, reg);
                if self.read(at)? != value {
                    return Err(Error::Readback(at));
                }
            }
            for (at, mask, value) in [
                (self.dsc_at(dsc, TOP_CONTROL), 1, 1),
                (self.dsc_forward_at(dsc), 0x71, 1 | u32::from(dsc) << 4),
            ] {
                if self.read(at)? & mask != value {
                    return Err(Error::Readback(at));
                }
            }
        }
        let l = self.layout;
        for (at, mask, value) in [
            (l.odm(pipe, FORMAT), 0x30, 0x10),
            (
                l.odm(pipe, BYTES_PER_PIXEL),
                0x7fff_ffff,
                regs.bytes_per_pixel & 0x7fff_ffff,
            ),
            (
                l.odm(pipe, WIDTH_CONTROL),
                0x1fff_0000,
                regs.slice_width << 16,
            ),
        ] {
            if self.read(at)? & mask != value {
                return Err(Error::Readback(at));
            }
        }
        Ok(())
    }
    /// link_set_dsc_on_stream(false) for the pipe's own DSC: OPTC DSC off,
    /// disconnect, disable, then power gating (dcn32_update_dsc_pg). A DSC
    /// never enabled is left as it is.
    pub(super) async fn stop_dsc(&mut self, pipe: u8) -> Result<(), Error> {
        let l = self.layout;
        let forward = self.read(self.dsc_forward_at(pipe))?;
        if forward & 1 != 0 && (forward >> 4) & 7 != u32::from(pipe) {
            return Err(Error::Busy);
        }
        let powered = self.dsc_powered(pipe)?;
        let clocked = powered && self.read(self.dsc_at(pipe, TOP_CONTROL))? & 1 != 0;
        if self.read(l.odm(pipe, FORMAT))? & 0x30 != 0 {
            self.update(l.odm(pipe, FORMAT), 0x30, 0)?;
            self.update(l.odm(pipe, BYTES_PER_PIXEL), 0x7fff_ffff, 0)?;
            self.update(l.odm(pipe, WIDTH_CONTROL), 0x1fff_0000, 0)?;
        }
        if forward & 1 == 0 && !clocked {
            return Ok(());
        }
        self.update(self.dsc_forward_at(pipe), 1, 0)?;
        self.update(self.dsc_at(pipe, TOP_CONTROL), 1, 0)?;
        if powered {
            self.dsc_power(pipe, false).await?;
        }
        Ok(())
    }
}
impl Otg {
    /// Run DSC `pipe`'s DSCCLK from its DTO for `pipe`'s retained pixel
    /// clock (above 48 MHz). Returns whether the DTO runs.
    pub(crate) fn start_dscclk(
        &mut self,
        clocks: &mut clocks::ClockManager,
        dccg: &mut dccg::Dccg,
        pipe: u8,
    ) -> Result<bool, Error> {
        dccg.start_dscclk(self.0.io.0, clocks, pipe)
            .map_err(Error::PipeClocks)
    }
    /// DSC `pipe`'s DSCCLK back on REFCLK; its DSC must be off.
    pub(crate) fn stop_dscclk(&mut self, dccg: &mut dccg::Dccg, pipe: u8) -> Result<(), Error> {
        if pipe >= 4 {
            return Err(Error::Invalid);
        }
        let forward = self.0.read(self.0.dsc_forward_at(pipe))?;
        if forward & 1 != 0 {
            return Err(Error::Busy);
        }
        dccg.stop_dscclk(self.0.io.0, pipe)
            .map_err(Error::PipeClocks)
    }
}
