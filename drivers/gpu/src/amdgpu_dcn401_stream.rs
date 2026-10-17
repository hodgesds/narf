//! Native DP video blanking, before PHY/encoder retirement. Linux DCN401
//! installs enc1_stream_encoder_dp_blank and dcn31_hpo_dp_stream_enc_dp_blank.
//! Link, stream and timing clocks remain owned and enabled as inherited.
use super::*;

#[path = "amdgpu_dcn401_encoder.rs"]
mod encoder;
pub use encoder::DpEncoderRetired;

const DIO_CLOCK: u64 = 0x2094;
const DIO_ENABLE: u64 = 0x2095;
const DIO_VIDEO: u64 = 0x2122;
const DIO_FIFO: u64 = 0x2123;
const HPO_CLOCK: u64 = 0x3623;
const HPO_RAMP: u64 = 0x3626;
const HPO_CONTROL: u64 = 0x365d;
const HPO_FIFO: u64 = 0x365e;
const HPO_SDP: u64 = 0x367b;
const HPO_VIDEO: u64 = 0x3685;

/// Native stream encoder instance, independent of OTG and physical transmitter.
/// Both families have four instances. This operation never infers board routing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpStream {
    Dio(u8),
    Hpo(u8),
}
impl DpStream {
    fn index(self) -> u8 {
        match self {
            Self::Dio(i) | Self::Hpo(i) => i,
        }
    }
    pub(super) fn at(self, l: Layout, reg: u64) -> u64 {
        let stride = match self {
            Self::Dio(_) => 0x124,
            Self::Hpo(_) => 0xd4,
        };
        l.base + (reg + u64::from(self.index()) * stride) * 4
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpBlanked {
    pub stream: DpStream,
    /// Requested or acknowledged video was active on entry. Secondary packets
    /// alone do not set this flag; it is diagnostic, not a retirement proof.
    pub was_active: bool,
}
#[derive(Clone, Copy)]
struct Snapshot {
    clock: u32,
    control: u32,
    video: u32,
}
impl<I: Io> Engine<I> {
    fn dp_snapshot(&mut self, stream: DpStream) -> Result<Snapshot, Error> {
        let l = self.layout;
        let at = |r| stream.at(l, r);
        let (clock, control, video) = match stream {
            DpStream::Dio(_) => (DIO_CLOCK, DIO_ENABLE, DIO_VIDEO),
            DpStream::Hpo(_) => (HPO_CLOCK, HPO_CONTROL, HPO_VIDEO),
        };
        Ok(Snapshot {
            clock: self.read(at(clock))?,
            control: self.read(at(control))?,
            video: self.read(at(video))?,
        })
    }
    fn dp_preflight(&mut self, stream: DpStream) -> Result<Snapshot, Error> {
        if stream.index() >= 4 {
            return Err(Error::Invalid);
        }
        if !self.status.state.reusable() {
            return Err(Error::Busy);
        }
        let s = self.dp_snapshot(stream)?;
        let l = self.layout;
        let at = |r| stream.at(l, r);
        match stream {
            DpStream::Dio(_) => {
                let reset = self.read(at(DIO_FIFO))? & 6;
                if s.clock & 0x20 != 0 || !matches!(reset, 0 | 6) {
                    return Err(Error::Busy);
                }
                if s.video & 0x10001 != 0 {
                    // Never blank an HDMI/DVI frontend or a stream whose
                    // clocks/reset state cannot complete the VBLANK handshake.
                    if !matches!(s.clock & 7, 0 | 5) {
                        return Err(Error::Unsupported);
                    }
                    if s.clock & 0x10 == 0 || s.control & 1 == 0 || reset != 0 {
                        return Err(Error::Busy);
                    }
                }
            }
            DpStream::Hpo(_) => {
                let fifo = self.read(at(HPO_FIFO))?;
                let ramp = self.read(at(HPO_RAMP))?;
                let sdp = self.read(at(HPO_SDP))?;
                if s.control & 0x110 != 0 || fifo & 0x110 != 0 || ramp & 0x100010 != 0 {
                    return Err(Error::Busy);
                }
                let active = s.video & 0x101 != 0 || (fifo | ramp | sdp) & 1 != 0;
                if active && (s.clock & 1 == 0 || s.control & 1 == 0) {
                    return Err(Error::Busy);
                }
            }
        }
        Ok(s)
    }
    fn dp_blank_readback(&mut self, stream: DpStream, before: Snapshot) -> Result<(), Error> {
        let after = self.dp_snapshot(stream)?;
        let l = self.layout;
        let at = |r| stream.at(l, r);
        let (clock, control, video, clock_mask, control_mask, video_mask) = match stream {
            DpStream::Dio(_) => (DIO_CLOCK, DIO_ENABLE, DIO_VIDEO, 0x37, 1, 0x10001),
            DpStream::Hpo(_) => (HPO_CLOCK, HPO_CONTROL, HPO_VIDEO, 1, 0x111, 0x101),
        };
        for (reg, actual, mask, expected) in [
            (clock, after.clock, clock_mask, before.clock),
            (control, after.control, control_mask, before.control),
            (video, after.video, video_mask, 0),
        ] {
            if actual & mask != expected & mask {
                return Err(Error::Readback(at(reg)));
            }
        }
        match stream {
            DpStream::Dio(_) if before.video & 0x10001 != 0 => {
                if self.read(at(DIO_FIFO))? & 6 != 6 {
                    return Err(Error::Readback(at(DIO_FIFO)));
                }
            }
            DpStream::Hpo(_) => {
                for (r, mask) in [(HPO_SDP, 1), (HPO_FIFO, 0x111), (HPO_RAMP, 0x100011)] {
                    if self.read(at(r))? & mask != 0 {
                        return Err(Error::Readback(at(r)));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    async fn dp_blank_inner(&mut self, stream: DpStream, s: Snapshot) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| stream.at(l, r);
        match stream {
            DpStream::Dio(_) if s.video & 0x10001 != 0 => {
                // Defer until vertical blank. Even an inherited enable=0,
                // status=1 must drain before resetting the steering FIFO.
                self.update(at(DIO_VIDEO), 0x300, 0x200)?;
                self.update(at(DIO_VIDEO), 1, 0)?;
                self.wait(at(DIO_VIDEO), 0x10001, 0, 150_000).await?;
                self.update(at(DIO_FIFO), 2, 2)?;
                self.wait(at(DIO_FIFO), 6, 6, 1000).await?;
            }
            DpStream::Hpo(_) if s.clock & 1 != 0 => {
                self.update(at(HPO_VIDEO), 1, 0)?;
                self.wait(at(HPO_VIDEO), 0x101, 0, 150_000).await?;
                // Native ordering: video acknowledgement precedes secondary
                // packet and both FIFO disables. Keep SYM32/stream clocks on.
                self.update(at(HPO_SDP), 1, 0)?;
                self.update(at(HPO_FIFO), 1, 0)?;
                self.update(at(HPO_RAMP), 1, 0)?;
            }
            _ => {} // Already blank; do not wake a disabled stream encoder.
        }
        self.dp_blank_readback(stream, s)
    }
    pub(super) async fn blank_dp_stream(&mut self, stream: DpStream) -> Result<DpBlanked, Error> {
        let s = self.dp_preflight(stream)?;
        self.status.state = State::BlankingDp(stream);
        match self.dp_blank_inner(stream, s).await {
            Ok(()) => {
                let blank = DpBlanked {
                    stream,
                    was_active: s.video
                        & match stream {
                            DpStream::Dio(_) => 0x10001,
                            DpStream::Hpo(_) => 0x101,
                        }
                        != 0,
                };
                self.status.dp_blanked = Some(blank);
                self.status.state = State::DpBlanked;
                Ok(blank)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// Blank one native legacy or HPO DisplayPort video stream. Link/stream
    /// clocks and timing remain retained for subsequent encoder/PHY retirement.
    /// DIO audio/secondary packets are not stopped by this video-only operation.
    /// # Safety
    /// Stop CPU scanout writers, exclude firmware/FAMS and all concurrent
    /// display/audio/packet/link/clock/power writers, and retain every associated
    /// allocation and translation. Success never permits freeing/reusing memory
    /// or changing clocks without the independent owners' live checks. This is
    /// not sink power-down, link retirement, HDMI blanking or an MST teardown.
    pub async unsafe fn blank_dp_stream(&mut self, stream: DpStream) -> Result<DpBlanked, Error> {
        self.0.blank_dp_stream(stream).await
    }
}
