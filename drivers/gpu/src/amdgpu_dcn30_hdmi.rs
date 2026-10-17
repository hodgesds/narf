//! Navi22 DCN3.0 HDMI TMDS stream: the DIG frontend/backend and VPG register
//! half of Linux's HDMI enable, around the VBIOS STREAM_SETUP and transmitter
//! tables that `amdgpu_navi22_bios` runs. Sequences follow
//! `dcn30_dio_stream_encoder.c::enc3_stream_encoder_hdmi_set_stream_attribute`,
//! `enc3_update_hdmi_info_packet`, `enc3_stream_encoder_update_hdmi_info_packets`
//! and `enc3_stream_encoder_stop_hdmi_info_packets`, `dcn30_vpg.c::
//! vpg3_update_generic_info_packet`, `dcn10_stream_encoder.c::
//! enc1_dig_connect_to_otg` and `dcn10_link_encoder.c::dcn10_link_encoder_setup`
//! / `connect_dig_be_to_fe`. Offsets and masks are `dcn_3_0_0_offset.h` /
//! `_sh_mask.h` at DCN base index 2; DIG frontends, backends and VPGs stride
//! 0x100.
//!
//! Scope is 8-bpc RGB TMDS at or below 340 MHz: no scrambling (which needs
//! the sink's SCDC first), no deep colour, no audio. Linux also starts the
//! Audio InfoFrame; with no audio endpoint here nothing is sent for it.
use crate::{amdgpu::AmdGpu, amdgpu_dcn_profile::Profile};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// linux-ctx: hdr=dcn seg=2
// linux: mmDIG1_DIG_FE_CNTL - mmDIG0_DIG_FE_CNTL
const STRIDE: u64 = 0x100;
// VPG instance (per stream frontend).
// linux: mmVPG0_VPG_GENERIC_PACKET_ACCESS_CTRL
const VPG_GENERIC_PACKET_ACCESS_CTRL: u64 = 0x2068;
// linux: mmVPG0_VPG_GENERIC_PACKET_DATA
const VPG_GENERIC_PACKET_DATA: u64 = 0x2069;
// linux: mmVPG0_VPG_GSP_IMMEDIATE_UPDATE_CTRL
const VPG_GSP_IMMEDIATE_UPDATE_CTRL: u64 = 0x206b;
// linux: mmVPG0_VPG_GENERIC_STATUS
const VPG_GENERIC_STATUS: u64 = 0x206c;
// DIG frontend.
// linux: mmDIG0_DIG_FE_CNTL
const DIG_FE_CNTL: u64 = 0x208b;
// linux: mmDIG0_HDMI_CONTROL
const HDMI_CONTROL: u64 = 0x2093;
// linux: mmDIG0_HDMI_VBI_PACKET_CONTROL
const HDMI_VBI_PACKET_CONTROL: u64 = 0x2097;
// linux: mmDIG0_HDMI_GENERIC_PACKET_CONTROL0
const HDMI_GENERIC_PACKET_CONTROL0: u64 = 0x209a;
// linux: mmDIG0_HDMI_GC
const HDMI_GC: u64 = 0x209d;
/// `HDMI_GENERIC_PACKET_CONTROL1..4`: GENERIC0/1, 2/3, 4/5 and 6/7 lines.
// linux: mmDIG0_HDMI_GENERIC_PACKET_CONTROL1; mmDIG0_HDMI_GENERIC_PACKET_CONTROL2; mmDIG0_HDMI_GENERIC_PACKET_CONTROL3; mmDIG0_HDMI_GENERIC_PACKET_CONTROL4
const HDMI_GENERIC_PACKET_LINES: [u64; 4] = [0x209e, 0x209f, 0x20a0, 0x20a1];
// linux: mmDIG0_HDMI_DB_CONTROL
const HDMI_DB_CONTROL: u64 = 0x20a6;
// linux: mmDIG0_AFMT_CNTL
const AFMT_CNTL: u64 = 0x20af;
// DIG backend.
const DIG_BE_CNTL: u64 = 0x20b0; // linux: mmDIG0_DIG_BE_CNTL
const DIG_BE_EN_CNTL: u64 = 0x20b1; // linux: mmDIG0_DIG_BE_EN_CNTL
const LAST_REG: u32 = (DIG_BE_EN_CNTL + 5 * STRIDE) as u32; // linux: mmDIG5_DIG_BE_EN_CNTL

// linux-ctx: reset
// linux: DIG0_DIG_FE_CNTL__DIG_SOURCE_SELECT_MASK
const DIG_SOURCE_SELECT: u32 = 0x7;
// linux: DIG0_DIG_FE_CNTL__DIG_STEREOSYNC_SELECT_MASK
const DIG_STEREOSYNC_SELECT: u32 = 0x70;
// linux: DIG0_DIG_FE_CNTL__DIG_STEREOSYNC_GATE_EN_MASK
const DIG_STEREOSYNC_GATE_EN: u32 = 1 << 8;
// linux: DIG0_DIG_FE_CNTL__TMDS_PIXEL_ENCODING_MASK
const TMDS_PIXEL_ENCODING: u32 = 1 << 28;
// linux: DIG0_DIG_FE_CNTL__TMDS_COLOR_FORMAT_MASK
const TMDS_COLOR_FORMAT: u32 = 0xc000_0000;
// linux: DIG0_HDMI_CONTROL__HDMI_KEEPOUT_MODE_MASK
const HDMI_KEEPOUT_MODE: u32 = 1 << 0;
// linux: DIG0_HDMI_CONTROL__HDMI_DATA_SCRAMBLE_EN_MASK
const HDMI_DATA_SCRAMBLE_EN: u32 = 1 << 1;
// linux: DIG0_HDMI_CONTROL__HDMI_CLOCK_CHANNEL_RATE_MASK
const HDMI_CLOCK_CHANNEL_RATE: u32 = 1 << 2;
// linux: DIG0_HDMI_CONTROL__HDMI_NO_EXTRA_NULL_PACKET_FILLED_MASK
const HDMI_NO_EXTRA_NULL_PACKET_FILLED: u32 = 1 << 3;
// linux: DIG0_HDMI_CONTROL__HDMI_PACKET_GEN_VERSION_MASK
const HDMI_PACKET_GEN_VERSION: u32 = 1 << 4;
// linux: DIG0_HDMI_CONTROL__HDMI_DEEP_COLOR_ENABLE_MASK
const HDMI_DEEP_COLOR_ENABLE: u32 = 1 << 24;
// linux: DIG0_HDMI_CONTROL__HDMI_DEEP_COLOR_DEPTH_MASK
const HDMI_DEEP_COLOR_DEPTH: u32 = 0x3000_0000;
// linux: DIG0_HDMI_VBI_PACKET_CONTROL__HDMI_NULL_SEND_MASK
const HDMI_NULL_SEND: u32 = 1 << 0;
// linux: DIG0_HDMI_VBI_PACKET_CONTROL__HDMI_GC_SEND_MASK
const HDMI_GC_SEND: u32 = 1 << 4;
// linux: DIG0_HDMI_VBI_PACKET_CONTROL__HDMI_GC_CONT_MASK
const HDMI_GC_CONT: u32 = 1 << 5;
// linux: DIG0_HDMI_VBI_PACKET_CONTROL__HDMI_ACP_SEND_MASK
const HDMI_ACP_SEND: u32 = 1 << 12;
// linux: DIG0_HDMI_GC__HDMI_GC_AVMUTE_MASK
const HDMI_GC_AVMUTE: u32 = 1 << 0;
// linux: DIG0_HDMI_DB_CONTROL__HDMI_DB_DISABLE_MASK
const HDMI_DB_DISABLE: u32 = 1 << 12;
// linux: DIG0_AFMT_CNTL__AFMT_AUDIO_CLOCK_EN_MASK
const AFMT_AUDIO_CLOCK_EN: u32 = 1 << 0;
// linux: VPG0_VPG_GENERIC_STATUS__VPG_GENERIC_CONFLICT_OCCURED_MASK
const VPG_GENERIC_CONFLICT_OCCURED: u32 = 1 << 1;
// linux: VPG0_VPG_GENERIC_STATUS__VPG_GENERIC_CONFLICT_CLR_MASK
const VPG_GENERIC_CONFLICT_CLR: u32 = 1 << 4;
// linux: VPG0_VPG_GENERIC_PACKET_ACCESS_CTRL__VPG_GENERIC_DATA_INDEX_MASK
const VPG_GENERIC_DATA_INDEX: u32 = 0xff;
// linux: DIG0_DIG_BE_CNTL__DIG_FE_SOURCE_SELECT_MASK
const DIG_FE_SOURCE_SELECT: u32 = 0x7f00;
// linux: DIG0_DIG_BE_CNTL__DIG_MODE_MASK
const DIG_MODE: u32 = 0x0007_0000;
// linux: DIG0_DIG_BE_EN_CNTL__DIG_ENABLE_MASK
const DIG_ENABLE: u32 = 1 << 0;
/// `enc3_update_hdmi_info_packet` sends on line 2.
// linux: n/a (literal `line = 2` in dcn30_dio_stream_encoder.c:enc3_update_hdmi_info_packet)
const INFO_PACKET_LINE: u32 = 2;
/// The highest TMDS rate without scrambling (`HDMI_CLOCK_CHANNEL_RATE_MORE_340M`).
// linux: n/a (HDMI_CLOCK_CHANNEL_RATE_MORE_340M, local #define in dcn30_dio_stream_encoder.c)
pub const TMDS_SCRAMBLE_KHZ: u32 = 340_000;
/// Packets `enc3_stream_encoder_update_hdmi_info_packets` manages: AVI (0) is
/// sent; vendor (1), gamut (2), SPD (3), HDR (4), HF-VSIF (5), VTEM (6) not.
// linux: n/a (packet indices 0..6 in dcn30_dio_stream_encoder.c:enc3_stream_encoder_update_hdmi_info_packets)
const MANAGED_PACKETS: u32 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unsupported,
    Invalid,
    Revoked,
    DeviceGone,
    /// The backend already drives a link it did not get from this owner.
    Busy,
    /// The VPG reported a GSP memory conflict that never cleared.
    Conflict,
}

pub(crate) trait Io: Send {
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
        // SAFETY: constructor bounds the DCN bank and retains the mapping.
        unsafe { self.regs.read32(self.base + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounded bank; this owner holds the frontend/backend.
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
async fn sleep_us(us: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_us(us).as_instant()).await;
}

#[derive(Debug)]
pub(crate) struct Engine<I: Io> {
    pub(crate) io: I,
    authority: Cap<BusDeviceCap, Write>,
    dig: u8,
    transmitter: u8,
}
impl<I: Io> Engine<I> {
    pub(crate) fn new_with(
        io: I,
        authority: Cap<BusDeviceCap, Write>,
        dig: u8,
        transmitter: u8,
    ) -> Self {
        Self {
            io,
            authority,
            dig,
            transmitter,
        }
    }
    fn fe(&self, reg: u64) -> u64 {
        reg + u64::from(self.dig) * STRIDE
    }
    fn be(&self, reg: u64) -> u64 {
        reg + u64::from(self.transmitter) * STRIDE
    }
    fn read(&mut self, reg: u64) -> Result<u32, Error> {
        let io = &mut self.io;
        let value = self
            .authority
            .invoke(Op(|| io.read(reg)))
            .map_err(|_| Error::Revoked)?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(value)
    }
    fn write(&mut self, reg: u64, value: u32) -> Result<(), Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| io.write(reg, value)))
            .map_err(|_| Error::Revoked)
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        let old = self.read(reg)?;
        self.write(reg, (old & !mask) | (value & mask))
    }
    /// The backend must be idle before this owner programs it.
    pub(crate) fn check_idle(&mut self) -> Result<(), Error> {
        if self.read(self.be(DIG_BE_EN_CNTL))? & DIG_ENABLE != 0 {
            return Err(Error::Busy);
        }
        Ok(())
    }
    /// `enc1_dig_connect_to_otg`: the frontend takes its pixels from `otg`.
    pub(crate) fn connect_to_otg(&mut self, otg: u8) -> Result<(), Error> {
        // linux: n/a (NARF bound: DCN30 has six OTGs)
        if otg >= 6 {
            return Err(Error::Invalid);
        }
        self.update(self.fe(DIG_FE_CNTL), DIG_SOURCE_SELECT, u32::from(otg))
    }
    /// `enc1_setup_stereo_sync(otg, false)`: stereo sync from `otg`, gated.
    pub(crate) fn setup_stereo_sync(&mut self, otg: u8) -> Result<(), Error> {
        // linux: n/a (NARF bound: DCN30 has six OTGs)
        if otg >= 6 {
            return Err(Error::Invalid);
        }
        self.update(
            self.fe(DIG_FE_CNTL),
            DIG_STEREOSYNC_SELECT | DIG_STEREOSYNC_GATE_EN,
            // linux-lit: 4=DIG0_DIG_FE_CNTL__DIG_STEREOSYNC_SELECT__SHIFT
            u32::from(otg) << 4 | DIG_STEREOSYNC_GATE_EN,
        )
    }
    /// `dcn10_link_encoder_setup`: the backend's DIG_MODE for the signal.
    pub(crate) fn setup(&mut self, mode: DigMode) -> Result<(), Error> {
        // linux-lit: 16=DIG0_DIG_BE_CNTL__DIG_MODE__SHIFT
        self.update(self.be(DIG_BE_CNTL), DIG_MODE, (mode as u32) << 16)
    }
    /// `dcn10_link_encoder_connect_dig_be_to_fe`: add or drop this frontend
    /// in the backend's one-hot source mask, keeping any other frontend.
    pub(crate) fn connect_be_to_fe(&mut self, connect: bool) -> Result<(), Error> {
        let be = self.read(self.be(DIG_BE_CNTL))?;
        // linux-lit: 8=DIG0_DIG_BE_CNTL__DIG_FE_SOURCE_SELECT__SHIFT
        let source = 1 << (8 + u32::from(self.dig));
        let field = if connect {
            (be & DIG_FE_SOURCE_SELECT) | source
        } else {
            be & DIG_FE_SOURCE_SELECT & !source
        };
        self.update(self.be(DIG_BE_CNTL), DIG_FE_SOURCE_SELECT, field)
    }
    /// `enc1_stream_encoder_set_avmute`.
    pub(crate) fn set_avmute(&mut self, mute: bool) -> Result<(), Error> {
        self.update(
            self.fe(HDMI_GC),
            HDMI_GC_AVMUTE,
            if mute { HDMI_GC_AVMUTE } else { 0 },
        )
    }
    /// The register half of `enc3_stream_encoder_hdmi_set_stream_attribute`
    /// after the VBIOS STREAM_SETUP: RGB pixel encoding, the HDMI engine at
    /// 8 bpc without scrambling, GC/NULL packets every frame, ACP off, and
    /// AVMUTE released.
    pub(crate) fn stream_attribute(&mut self, character_khz: u32) -> Result<(), Error> {
        if character_khz == 0 || character_khz >= TMDS_SCRAMBLE_KHZ {
            return Err(Error::Unsupported);
        }
        self.update(self.fe(DIG_FE_CNTL), TMDS_PIXEL_ENCODING, 0)?;
        self.update(self.fe(DIG_FE_CNTL), TMDS_COLOR_FORMAT, 0)?;
        self.update(
            self.fe(HDMI_CONTROL),
            HDMI_PACKET_GEN_VERSION
                | HDMI_KEEPOUT_MODE
                | HDMI_DEEP_COLOR_ENABLE
                | HDMI_DATA_SCRAMBLE_EN
                | HDMI_NO_EXTRA_NULL_PACKET_FILLED
                | HDMI_CLOCK_CHANNEL_RATE,
            HDMI_PACKET_GEN_VERSION | HDMI_KEEPOUT_MODE | HDMI_NO_EXTRA_NULL_PACKET_FILLED,
        )?;
        self.update(self.fe(HDMI_CONTROL), HDMI_DEEP_COLOR_DEPTH, 0)?;
        self.update(
            self.fe(HDMI_VBI_PACKET_CONTROL),
            HDMI_GC_CONT | HDMI_GC_SEND | HDMI_NULL_SEND,
            HDMI_GC_CONT | HDMI_GC_SEND | HDMI_NULL_SEND,
        )?;
        self.update(self.fe(HDMI_VBI_PACKET_CONTROL), HDMI_ACP_SEND, 0)?;
        self.update(self.fe(HDMI_GC), HDMI_GC_AVMUTE, 0)
    }
    /// `vpg3_update_generic_info_packet(index, packet, immediate)`.
    async fn vpg_packet(&mut self, index: u32, packet: &[u8; 36]) -> Result<(), Error> {
        let status = self.fe(VPG_GENERIC_STATUS);
        let mut clear = false;
        // linux: n/a (max_retries = 50, literal in dcn30_vpg.c:vpg3_update_generic_info_packet)
        for _ in 0..50 {
            if self.read(status)? & VPG_GENERIC_CONFLICT_OCCURED == 0 {
                clear = true;
                break;
            }
            // linux: n/a (REG_WAIT delay 10 us, literal in dcn30_vpg.c:vpg3_update_generic_info_packet)
            sleep_us(10).await;
        }
        if !clear {
            return Err(Error::Conflict);
        }
        self.update(status, VPG_GENERIC_CONFLICT_CLR, VPG_GENERIC_CONFLICT_CLR)?;
        self.update(
            self.fe(VPG_GENERIC_PACKET_ACCESS_CTRL),
            VPG_GENERIC_DATA_INDEX,
            // linux: n/a (packet_index*9, literal in dcn30_vpg.c:vpg3_update_generic_info_packet)
            index * 9,
        )?;
        // HB0..HB3, then the first 32 SB bytes; the last four are never used.
        for word in packet.chunks_exact(4) {
            self.write(
                self.fe(VPG_GENERIC_PACKET_DATA),
                u32::from_le_bytes([word[0], word[1], word[2], word[3]]),
            )?;
        }
        self.update(
            self.fe(VPG_GSP_IMMEDIATE_UPDATE_CTRL),
            1 << index,
            1 << index,
        )
    }
    /// `HDMI_GENERIC_PACKET_CONTROL0` CONT/SEND and the packet's line field.
    fn packet_control(&mut self, index: u32, send: bool) -> Result<(), Error> {
        // linux-lit: 0x3=DIG0_HDMI_GENERIC_PACKET_CONTROL0__HDMI_GENERIC0_SEND_MASK | DIG0_HDMI_GENERIC_PACKET_CONTROL0__HDMI_GENERIC0_CONT_MASK; 4=DIG0_HDMI_GENERIC_PACKET_CONTROL0__HDMI_GENERIC1_SEND__SHIFT
        let bits = 0x3 << (4 * index);
        self.update(
            self.fe(HDMI_GENERIC_PACKET_CONTROL0),
            bits,
            if send { bits } else { 0 },
        )?;
        let reg = HDMI_GENERIC_PACKET_LINES[(index / 2) as usize];
        // linux-lit: 16=DIG0_HDMI_GENERIC_PACKET_CONTROL1__HDMI_GENERIC1_LINE__SHIFT
        let shift = 16 * (index % 2);
        self.update(
            self.fe(reg),
            // linux-lit: 0xffff=DIG0_HDMI_GENERIC_PACKET_CONTROL1__HDMI_GENERIC0_LINE_MASK
            0xffff << shift,
            if send { INFO_PACKET_LINE << shift } else { 0 },
        )
    }
    /// `enc3_stream_encoder_update_hdmi_info_packets` with only the AVI
    /// InfoFrame valid.
    pub(crate) async fn info_packets(&mut self, avi: &[u8; 36]) -> Result<(), Error> {
        // linux: n/a (HDMI_INFOFRAME_TYPE_AVI = 0x82, include/linux/hdmi.h; not in checker header set)
        if avi[0] != 0x82 {
            return Err(Error::Invalid);
        }
        self.update(self.fe(HDMI_DB_CONTROL), HDMI_DB_DISABLE, HDMI_DB_DISABLE)?;
        self.update(self.fe(AFMT_CNTL), AFMT_AUDIO_CLOCK_EN, AFMT_AUDIO_CLOCK_EN)?;
        self.vpg_packet(0, avi).await?;
        self.packet_control(0, true)?;
        for index in 1..MANAGED_PACKETS {
            self.packet_control(index, false)?;
        }
        Ok(())
    }
    /// `enc3_stream_encoder_stop_hdmi_info_packets` for packets 0..7.
    pub(crate) fn stop_info_packets(&mut self) -> Result<(), Error> {
        self.write(self.fe(HDMI_GENERIC_PACKET_CONTROL0), 0)?;
        for reg in HDMI_GENERIC_PACKET_LINES {
            self.write(self.fe(reg), 0)?;
        }
        Ok(())
    }
}

/// `DIG_BE_CNTL.DIG_MODE` values `dcn10_link_encoder_setup` writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigMode {
    /// `SIGNAL_TYPE_DISPLAY_PORT` (SST).
    // linux: n/a (DIG_MODE 0, literal in dcn10_link_encoder.c:dcn10_link_encoder_setup)
    DisplayPort = 0,
    /// `SIGNAL_TYPE_HDMI_TYPE_A`.
    Hdmi = 3, // linux: n/a (DIG_MODE 3, literal in dcn10_link_encoder.c:dcn10_link_encoder_setup)
}

/// One HDMI stream frontend `dig` routed to physical transmitter `transmitter`.
#[derive(Debug)]
pub struct Hdmi(Engine<Mmio>);
impl Hdmi {
    /// # Safety
    /// Caller exclusively owns DIG frontend `dig`, its VPG and backend
    /// `transmitter` for the object's lifetime, holds matching PCI authority
    /// and a permanent register mapping.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        dig: u8,
        transmitter: u8,
    ) -> Result<Self, Error> {
        if Profile::resolve(gpu).map_err(|_| Error::Unsupported)? != Profile::Navi22 {
            return Err(Error::Unsupported);
        }
        // linux: n/a (NARF bound: six DIG frontends/backends)
        if dig >= 6 || transmitter >= 6 {
            return Err(Error::Invalid);
        }
        let base = Profile::Navi22
            .bank(gpu, 2, LAST_REG) // linux-lit: 2=mmDIG0_DIG_FE_CNTL_BASE_IDX
            .map_err(|_| Error::Unsupported)?;
        Ok(Self(Engine::new_with(
            Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base,
            },
            authority,
            dig,
            transmitter,
        )))
    }
    pub fn check_idle(&mut self) -> Result<(), Error> {
        self.0.check_idle()
    }
    pub fn connect_to_otg(&mut self, otg: u8) -> Result<(), Error> {
        self.0.connect_to_otg(otg)
    }
    pub fn setup(&mut self, mode: DigMode) -> Result<(), Error> {
        self.0.setup(mode)
    }
    pub fn setup_stereo_sync(&mut self, otg: u8) -> Result<(), Error> {
        self.0.setup_stereo_sync(otg)
    }
    pub fn connect_be_to_fe(&mut self, connect: bool) -> Result<(), Error> {
        self.0.connect_be_to_fe(connect)
    }
    pub fn set_avmute(&mut self, mute: bool) -> Result<(), Error> {
        self.0.set_avmute(mute)
    }
    pub fn stream_attribute(&mut self, character_khz: u32) -> Result<(), Error> {
        self.0.stream_attribute(character_khz)
    }
    pub async fn info_packets(&mut self, avi: &[u8; 36]) -> Result<(), Error> {
        self.0.info_packets(avi).await
    }
    pub fn stop_info_packets(&mut self) -> Result<(), Error> {
        self.0.stop_info_packets()
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use narf_kernel_test::{kernel_test_in, TestResult};

    struct Fake {
        regs: Vec<u32>,
        data: Vec<u32>,
        conflict: bool,
    }
    impl Io for Fake {
        fn read(&mut self, reg: u64) -> u32 {
            let v = self.regs[reg as usize];
            if reg % STRIDE == VPG_GENERIC_STATUS % STRIDE && self.conflict {
                return v | VPG_GENERIC_CONFLICT_OCCURED;
            }
            v
        }
        fn write(&mut self, reg: u64, value: u32) {
            if reg % STRIDE == VPG_GENERIC_PACKET_DATA % STRIDE && reg > 0x2000 {
                self.data.push(value);
            }
            self.regs[reg as usize] = value;
        }
    }
    fn engine(dig: u8, transmitter: u8) -> Engine<Fake> {
        Engine::new_with(
            Fake {
                regs: vec![0; LAST_REG as usize + 1],
                data: Vec::new(),
                conflict: false,
            },
            Cap::bootstrap(),
            dig,
            transmitter,
        )
    }
    fn run<T>(f: impl core::future::Future<Output = T>) -> T {
        narf_scheduler::block_on_spin(f)
    }

    fn dcn30_hdmi_routes_and_programs_tmds_stream() -> TestResult {
        let mut e = engine(1, 3);
        // GOP left HDMI_CONTROL with deep colour and scrambling set.
        e.io.regs[(HDMI_CONTROL + STRIDE) as usize] =
            HDMI_DEEP_COLOR_ENABLE | HDMI_DATA_SCRAMBLE_EN | 0x1000_0000;
        if e.check_idle().is_err()
            || e.connect_to_otg(2).is_err()
            || e.setup(DigMode::Hdmi).is_err()
            || e.connect_be_to_fe(true).is_err()
            || e.stream_attribute(148_500).is_err()
        {
            return TestResult::Fail("HDMI stream setup");
        }
        let r = &e.io.regs;
        // Literal DCN30 ids: DIG3_DIG_BE_CNTL 0x23b0, DIG1_DIG_FE_CNTL 0x218b,
        // DIG1_HDMI_CONTROL 0x2193, DIG1_HDMI_VBI_PACKET_CONTROL 0x2197.
        if r[0x23b0] != 3 << 16 | 1 << 9
            || r[0x218b] & 7 != 2
            || r[0x2193]
                != HDMI_PACKET_GEN_VERSION | HDMI_KEEPOUT_MODE | HDMI_NO_EXTRA_NULL_PACKET_FILLED
            || r[0x2197] != HDMI_GC_CONT | HDMI_GC_SEND | HDMI_NULL_SEND
        {
            return TestResult::Fail("HDMI registers");
        }
        if e.stream_attribute(340_000) != Err(Error::Unsupported) {
            return TestResult::Fail("scrambled rate admitted");
        }
        e.io.regs[0x23b1] = 1;
        if e.check_idle() != Err(Error::Busy) {
            return TestResult::Fail("live backend claimed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn30-hdmi",
        dcn30_hdmi_routes_and_programs_tmds_stream
    );

    fn dcn30_hdmi_sends_only_the_avi_infoframe_and_stops() -> TestResult {
        let mut e = engine(0, 0);
        let mut avi = [0u8; 36];
        avi[..4].copy_from_slice(&[0x82, 2, 13, 0]);
        avi[8] = 16;
        if run(e.info_packets(&avi)).is_err() {
            return TestResult::Fail("AVI packet");
        }
        let r = &e.io.regs;
        // Nine VPG words for generic packet 0, immediate update, then
        // GENERIC0 CONT/SEND on line 2 and every other managed packet off.
        if e.io.data.len() != 9
            || e.io.data[0] != u32::from_le_bytes([0x82, 2, 13, 0])
            || r[VPG_GENERIC_PACKET_ACCESS_CTRL as usize] != 0
            || r[VPG_GSP_IMMEDIATE_UPDATE_CTRL as usize] & 1 == 0
            || r[HDMI_GENERIC_PACKET_CONTROL0 as usize] != 3
            || r[0x209e] != 2
            || r[HDMI_DB_CONTROL as usize] & HDMI_DB_DISABLE == 0
        {
            return TestResult::Fail("AVI programming");
        }
        e.io.conflict = true;
        if run(e.info_packets(&avi)) != Err(Error::Conflict) {
            return TestResult::Fail("VPG conflict ignored");
        }
        if run(e.info_packets(&[0; 36])) != Err(Error::Invalid) {
            return TestResult::Fail("non-AVI packet");
        }
        e.io.regs[DIG_BE_CNTL as usize] = 3 << 16 | 1 << 8;
        if e.stop_info_packets().is_err()
            || e.set_avmute(true).is_err()
            || e.connect_be_to_fe(false).is_err()
            || e.io.regs[HDMI_GENERIC_PACKET_CONTROL0 as usize] != 0
            || e.io.regs[HDMI_GC as usize] & HDMI_GC_AVMUTE == 0
            || e.io.regs[DIG_BE_CNTL as usize] & DIG_FE_SOURCE_SELECT != 0
        {
            return TestResult::Fail("stop");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/dcn30-hdmi",
        dcn30_hdmi_sends_only_the_avi_infoframe_and_stops
    );
}
