//! Navi22 DCN3.0 and Phoenix DCN3.1.4 DisplayPort stream encoder: the main stream attributes a sink
//! needs to interpret the pixels, the M/N rate ratio, and the video stream
//! enable. Offsets and fields are `dcn_3_1_4_offset.h`/`dcn_3_1_4_sh_mask.h` at
//! DCN base index 2 with the 0x100 per-instance stride the DIG blocks use;
//! sequencing follows Linux
//! `dcn10_stream_encoder.c::enc1_stream_encoder_dp_set_stream_attribute` and
//! `dcn314_dio_stream_encoder.c::enc314_stream_encoder_dp_unblank`.
//!
//! This is the stream (front-end) half of the DIO. The link half — transmitter
//! enable, training patterns and drive levels — is [`crate::amdgpu_dio`].
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_dcn_profile::Profile, amdgpu_dml::Timing,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// Profile selects DCN30 or DCN314; shared ids below were compared against
// both Linux offset and mask headers. Generation differences stay explicit.
// linux-ctx: hdr=dcn seg=2
const DP_PIXEL_FORMAT: u64 = 0x2109; // linux: mmDP0_DP_PIXEL_FORMAT
const DP_MSA_COLORIMETRY: u64 = 0x210a; // linux: mmDP0_DP_MSA_COLORIMETRY
const DP_VID_STREAM_CNTL: u64 = 0x210c; // linux: mmDP0_DP_VID_STREAM_CNTL
const DP_STEER_FIFO: u64 = 0x210d; // linux: mmDP0_DP_STEER_FIFO
const DP_MSA_MISC: u64 = 0x210e; // linux: mmDP0_DP_MSA_MISC
const DP_VID_TIMING: u64 = 0x2110; // linux: mmDP0_DP_VID_TIMING
const DP_VID_N: u64 = 0x2111; // linux: mmDP0_DP_VID_N
const DP_VID_M: u64 = 0x2112; // linux: mmDP0_DP_VID_M
const DP_MSA_TIMING_PARAM1: u64 = 0x214c; // linux: mmDP0_DP_MSA_TIMING_PARAM1
const DP_MSA_TIMING_PARAM2: u64 = 0x214d; // linux: mmDP0_DP_MSA_TIMING_PARAM2
const DP_MSA_TIMING_PARAM3: u64 = 0x214e; // linux: mmDP0_DP_MSA_TIMING_PARAM3
const DP_MSA_TIMING_PARAM4: u64 = 0x214f; // linux: mmDP0_DP_MSA_TIMING_PARAM4
const STRIDE: u64 = 0x100; // linux: mmDP1_DP_PIXEL_FORMAT - mmDP0_DP_PIXEL_FORMAT
#[cfg(feature = "kernel-test")]
// linux: n/a (test-only bank bound)
const LAST_REG: u32 = (DP_MSA_TIMING_PARAM4 + 4 * STRIDE) as u32;
/// `DP_PIXEL_ENCODING_TYPE_RGB444`.
// linux: n/a (enum dp_pixel_encoding_type in inc/hw/stream_encoder.h; not in checker set)
const PIXEL_ENCODING_RGB: u32 = 0;

// `DP0_DP_PIXEL_FORMAT` fields, from `dcn_3_1_4_sh_mask.h`:
//
//   DP_PIXEL_ENCODING                  0x00000007
//   DP_COMPONENT_DEPTH                 0x07000000
//   DP_PIXEL_PER_CYCLE_PROCESSING_MODE 0x40000000
//
// LINUX-GAP: the last was masked `0x3 << 30`, one bit wider than the single bit
// it is, so the update also cleared reserved bit 31. The field is written with a
// one-bit value everywhere Linux touches it (`odm_combine` in
// `dcn314_dio_stream_encoder.c:101`, `two_pixel_per_cyle ? 1 : 0` in dcn32's).
const DP_PIXEL_ENCODING: u32 = 0x0000_0007; // linux: DP0_DP_PIXEL_FORMAT__DP_PIXEL_ENCODING_MASK
const DP_COMPONENT_DEPTH: u32 = 0x0700_0000; // linux: DP0_DP_PIXEL_FORMAT__DP_COMPONENT_DEPTH_MASK
                                             // linux: n/a (DCN 3.1.4 path; field absent from dcn_3_0_0_sh_mask.h)
const DP_PIXEL_PER_CYCLE_PROCESSING_MODE: u32 = 0x4000_0000;
/// The M/N generator measures against a fixed N, which Linux seeds at 0x8000
/// because auto-measurement needs a full symbol cycle to take over.
// linux: n/a (literal in dcn10_stream_encoder.c:enc1_stream_encoder_dp_unblank, n_vid)
const N_VID: u32 = 0x8000;
/// Every DisplayPort link rate is a multiple of this reference.
// linux: n/a (LINK_RATE_REF_FREQ_IN_KHZ, include/link_service_types.h; not in checker set)
const LINK_RATE_REF_KHZ: u64 = 27_000;

/// Bits per component on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    Bpc6,
    Bpc8,
    Bpc10,
}
impl Depth {
    /// `DP_COMPONENT_PIXEL_DEPTH_*`.
    fn code(self) -> u32 {
        match self {
            // linux: n/a (enum dp_component_depth in inc/hw/stream_encoder.h; not in checker set)
            Depth::Bpc6 => 0,
            // linux: n/a (enum dp_component_depth in inc/hw/stream_encoder.h; not in checker set)
            Depth::Bpc8 => 1,
            // linux: n/a (enum dp_component_depth in inc/hw/stream_encoder.h; not in checker set)
            Depth::Bpc10 => 2,
        }
    }
    /// The MSA MISC0 colorimetry field uses its own numbering.
    fn colorimetry(self) -> u32 {
        match self {
            // linux: n/a (literal in enc1_stream_encoder_dp_set_stream_attribute, colorimetry_bpc)
            Depth::Bpc6 => 0,
            // linux: n/a (literal in enc1_stream_encoder_dp_set_stream_attribute, colorimetry_bpc)
            Depth::Bpc8 => 1,
            // linux: n/a (literal in enc1_stream_encoder_dp_set_stream_attribute, colorimetry_bpc)
            Depth::Bpc10 => 2,
        }
    }
    pub fn bits_per_pixel(self) -> u32 {
        match self {
            Depth::Bpc6 => 18,
            Depth::Bpc8 => 24,
            Depth::Bpc10 => 30,
        }
    }
}

trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    base: u64,
}
impl Io for Mmio {
    fn read(&mut self, reg: u64) -> u32 {
        // SAFETY: constructor bounds the DIO bank and retains the mapping.
        unsafe { self.regs.read32(self.base + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounded bank; this is the sole owner of the frontend.
        unsafe { self.regs.write32(self.base + reg * 4, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
async fn delay_us(microseconds: u64) {
    narf_time::SleepUntil::new(
        narf_time::Deadline::after_ms(microseconds.div_ceil(1000)).as_instant(),
    )
    .await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Idle,
    Programmed,
    Streaming,
}

#[derive(Debug)]
struct Engine<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    instance: u8,
    state: State,
    profile: Profile,
}
impl<I: Io> Engine<I> {
    fn reg(&self, reg: u64) -> u64 {
        reg + self.instance as u64 * STRIDE
    }
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    fn set(&mut self, reg: u64, value: u32) -> Result<(), Error> {
        let reg = self.reg(reg);
        self.access(|io| io.write(reg, value))
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        let reg = self.reg(reg);
        self.access(|io| {
            let old = io.read(reg);
            if old == u32::MAX {
                return Err(Error::DeviceGone);
            }
            io.write(reg, (old & !mask) | (value & mask));
            Ok(())
        })?
    }
    /// `enc1_stream_encoder_dp_set_stream_attribute` for uncompressed RGB in the
    /// sRGB full-range colour space. The sink reads these to lay the pixels out,
    /// so they describe the timing rather than program it.
    fn program(&mut self, timing: &Timing, depth: Depth) -> Result<(), Error> {
        if self.state == State::Streaming {
            // Changing attributes under a live stream shows corrupt pixels.
            return Err(Error::Busy);
        }
        let h_blank = timing
            .h_total
            .checked_sub(timing.h_active)
            .ok_or(Error::Invalid)?;
        let h_back_porch = h_blank
            .checked_sub(timing.h_front_porch)
            .and_then(|v| v.checked_sub(timing.h_sync_width))
            .ok_or(Error::Invalid)?;
        // Active starts at the leading edge of sync plus the back porch, which
        // is the same count as the blank end the timing generator uses.
        let h_active_start = timing.h_sync_width + h_back_porch;
        let v_active_start = timing
            .v_total
            .checked_sub(timing.v_active)
            .and_then(|v| v.checked_sub(timing.v_front_porch))
            .ok_or(Error::Invalid)?;
        for value in [
            timing.h_total,
            timing.v_total,
            h_active_start,
            v_active_start,
            timing.h_active,
            timing.v_active,
            timing.h_sync_width,
            timing.v_sync_width,
        ] {
            if value == 0 || value > 0x7fff {
                return Err(Error::Invalid);
            }
        }

        self.update(
            DP_PIXEL_FORMAT,
            DP_PIXEL_ENCODING
                | DP_COMPONENT_DEPTH
                | if self.profile == Profile::Dcn314 {
                    DP_PIXEL_PER_CYCLE_PROCESSING_MODE
                } else {
                    0
                },
            PIXEL_ENCODING_RGB | depth.code() << DP_COMPONENT_DEPTH.trailing_zeros(),
        )?;
        // MISC0: colorimetry depth in bits 7:5, full-range RGB elsewhere.
        // linux-lit: 24=DP0_DP_MSA_COLORIMETRY__DP_MSA_MISC0__SHIFT
        self.set(DP_MSA_COLORIMETRY, depth.colorimetry() << 5 << 24)?;
        // MISC1: no VSC SDP colorimetry override, not Y-only.
        self.update(DP_MSA_MISC, 0xc0, 0)?;
        // linux-lit: 16=DP0_DP_MSA_TIMING_PARAM1__DP_MSA_HTOTAL__SHIFT
        self.set(DP_MSA_TIMING_PARAM1, timing.v_total | timing.h_total << 16)?;
        // linux-lit: 16=DP0_DP_MSA_TIMING_PARAM2__DP_MSA_HSTART__SHIFT
        self.set(DP_MSA_TIMING_PARAM2, v_active_start | h_active_start << 16)?;
        // The polarity fields mean "negative", like the timing generator's.
        self.set(
            DP_MSA_TIMING_PARAM3,
            timing.v_sync_width
                // linux-lit: 15=DP0_DP_MSA_TIMING_PARAM3__DP_MSA_VSYNCPOLARITY__SHIFT
                | u32::from(!timing.v_sync_positive) << 15
                // linux-lit: 16=DP0_DP_MSA_TIMING_PARAM3__DP_MSA_HSYNCWIDTH__SHIFT
                | timing.h_sync_width << 16
                // linux-lit: 31=DP0_DP_MSA_TIMING_PARAM3__DP_MSA_HSYNCPOLARITY__SHIFT
                | u32::from(!timing.h_sync_positive) << 31,
        )?;
        self.set(
            DP_MSA_TIMING_PARAM4,
            // linux-lit: 16=DP0_DP_MSA_TIMING_PARAM4__DP_MSA_HWIDTH__SHIFT
            timing.v_active | timing.h_active << 16,
        )?;
        self.state = State::Programmed;
        Ok(())
    }
    /// Seed the M/N rate ratio before handing it to the auto-measurement, which
    /// needs a full symbol cycle to take over. `rate` is the DPCD link-rate code
    /// the training settled on, not a frequency.
    fn program_rate(&mut self, pixel_clock_khz: u32, rate: u8) -> Result<(), Error> {
        let link_khz = rate as u64 * LINK_RATE_REF_KHZ;
        if link_khz == 0 {
            return Err(Error::Invalid);
        }
        let m_vid = (N_VID as u64 * pixel_clock_khz as u64) / link_khz;
        // A stream faster than its link cannot be carried; the ratio must be
        // below one, so refuse rather than program a wrapped M.
        if m_vid == 0 || m_vid >= N_VID as u64 {
            return Err(Error::Invalid);
        }
        // linux-lit: 8=DP0_DP_VID_TIMING__DP_VID_M_N_GEN_EN__SHIFT
        self.update(DP_VID_TIMING, 1 << 8, 0)?;
        self.set(DP_VID_N, N_VID)?;
        self.set(DP_VID_M, m_vid as u32)?;
        // One pixel per container, so no N multiplier.
        // linux-lit: 8=DP0_DP_VID_TIMING__DP_VID_M_N_GEN_EN__SHIFT
        // linux-lit: 10=DP0_DP_VID_TIMING__DP_VID_N_MUL__SHIFT
        // linux-lit: 0x3=DP0_DP_VID_TIMING__DP_VID_N_MUL_MASK >> DP0_DP_VID_TIMING__DP_VID_N_MUL__SHIFT
        self.update(DP_VID_TIMING, 1 << 8 | 0x3 << 10, 1 << 8)?;
        if self.profile == Profile::Dcn314 {
            self.update(DP_PIXEL_FORMAT, DP_PIXEL_PER_CYCLE_PROCESSING_MODE, 0)?;
        }
        Ok(())
    }
    /// `enc314_stream_encoder_dp_unblank`: stop the stream, reset the steering
    /// FIFO so a mode transition's overflow cannot persist, let the logic prime,
    /// then enable. The hardware starts sending at the next vblank edge.
    async fn unblank(&mut self) -> Result<(), Error> {
        if self.state == State::Idle {
            return Err(Error::Busy);
        }
        // linux-lit: 1=DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_ENABLE_MASK
        self.update(DP_VID_STREAM_CNTL, 1, 0)?;
        let status = self.reg(DP_VID_STREAM_CNTL);
        let deadline = narf_time::Deadline::after_ms(50);
        loop {
            let value = self.access(|io| io.read(status))?;
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            // linux-lit: 16=DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_STATUS__SHIFT
            if value & 1 << 16 == 0 {
                break;
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay_us(1000).await;
        }
        if self.profile.is_dcn30() {
            // enc2_stream_encoder_dp_unblank also resets the DIG frontend.
            // linux-lit: 0x208b=mmDIG0_DIG_FE_CNTL; 10=DIG0_DIG_FE_CNTL__DIG_START__SHIFT
            self.update(0x208b, 1 << 10, 1 << 10)?; // DIG_FE_CNTL.DIG_START
            delay_us(1).await;
            // linux-lit: 0x208b=mmDIG0_DIG_FE_CNTL; 10=DIG0_DIG_FE_CNTL__DIG_START__SHIFT
            self.update(0x208b, 1 << 10, 0)?;
        }
        // linux-lit: 1=DP0_DP_STEER_FIFO__DP_STEER_FIFO_RESET_MASK
        self.update(DP_STEER_FIFO, 1, 1)?;
        delay_us(10).await;
        // linux-lit: 1=DP0_DP_STEER_FIFO__DP_STEER_FIFO_RESET_MASK
        self.update(DP_STEER_FIFO, 1, 0)?;
        // A few video lines for the DIG and DP logic to prime.
        delay_us(100).await;
        // linux-lit: 1=DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_ENABLE_MASK
        self.update(DP_VID_STREAM_CNTL, 1, 1)?;
        self.state = State::Streaming;
        Ok(())
    }
    /// Stop the stream and wait for the encoder to confirm it has stopped.
    async fn blank(&mut self) -> Result<(), Error> {
        // linux-lit: 1=DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_ENABLE_MASK
        self.update(DP_VID_STREAM_CNTL, 1, 0)?;
        let status = self.reg(DP_VID_STREAM_CNTL);
        let deadline = narf_time::Deadline::after_ms(50);
        loop {
            let value = self.access(|io| io.read(status))?;
            if value == u32::MAX {
                return Err(Error::DeviceGone);
            }
            // linux-lit: 16=DP0_DP_VID_STREAM_CNTL__DP_VID_STREAM_STATUS__SHIFT
            if value & 1 << 16 == 0 {
                self.state = State::Programmed;
                return Ok(());
            }
            if deadline.expired() {
                return Err(Error::Timeout);
            }
            delay_us(1000).await;
        }
    }
}

/// One owned DCN30/DCN314 DisplayPort stream encoder.
#[derive(Debug)]
pub struct Stream(Engine<Mmio>);
impl Stream {
    /// # Safety
    /// Caller exclusively owns this stream frontend for the object's lifetime,
    /// holds matching PCI authority and a permanent register mapping, and must
    /// keep the link encoder it feeds trained for as long as it streams.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        instance: u8,
    ) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if instance >= profile.streams() {
            return Err(Error::Invalid);
        }
        let base = profile.bank(
            gpu,
            2, // linux-lit: 2=mmDP0_DP_PIXEL_FORMAT_BASE_IDX
            // linux-ctx: reset
            (DP_MSA_TIMING_PARAM4 + u64::from(profile.streams() - 1) * STRIDE) as u32,
        )?;
        Ok(Self(Engine {
            io: Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base,
            },
            authority,
            instance,
            state: State::Idle,
            profile,
        }))
    }
    pub fn state(&self) -> State {
        self.0.state
    }
    /// Describe the stream to the sink and seed its rate ratio. `rate` is the
    /// DPCD link-rate code the link training settled on.
    pub fn program(&mut self, timing: &Timing, depth: Depth, rate: u8) -> Result<(), Error> {
        self.0.program(timing, depth)?;
        self.0.program_rate(timing.pixel_clock_khz, rate)
    }
    pub async fn unblank(&mut self) -> Result<(), Error> {
        self.0.unblank().await
    }
    pub async fn blank(&mut self) -> Result<(), Error> {
        self.0.blank().await
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn_stream_tests.rs"]
mod tests;
