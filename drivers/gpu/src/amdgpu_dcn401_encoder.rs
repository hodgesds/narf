//! Stream encoder retirement after acknowledged video blanking. Native Linux
//! reset_dio_stream_encoder/enc35_disable_fifo and HPO DP disable sequencing.
//! Backend shutdown, sink/MST teardown and audio/metadata retirement are separate.
use super::*;

const DIO_PIXEL_FIFO: u64 = 0x209b;
const DIO_BACKEND: u64 = 0x20bc;
const DIO_BACKEND_ENABLE: u64 = 0x20bd;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DpEncoderRetired {
    pub stream: DpStream,
    /// DIO backends whose selected frontend bit was removed. HPO leaves its
    /// independent stream/link mapping intact and reports zero here.
    pub detached_backends: u8,
}
struct Plan {
    result: DpEncoderRetired,
    mode: u32,
    routes: [u32; 4],
}
impl<I: Io> Engine<I> {
    fn dp_encoder_quiet(&mut self, stream: DpStream) -> Result<(), Error> {
        let l = self.layout;
        let at = |r| stream.at(l, r);
        match stream {
            DpStream::Dio(_) => {
                // Secondary/audio packet scheduling and metadata transactions
                // belong to their owners. Never gate them as a side effect.
                for (r, mask) in [
                    (DIO_VIDEO, 0x10001),
                    (DIO_PIXEL_FIFO, 0x100002), // reset request/status
                    (0x2141, 0x1ff11111),       // DP_SEC_CNTL, including audio/GSP0-7
                    (0x2091, 0x1010),           // DME enable and pending double buffer
                ] {
                    if self.read(at(r))? & mask != 0 {
                        return Err(Error::Busy);
                    }
                }
                for r in 0x2174..=0x2177 {
                    // GSP8-11 have separate enable, send, pending/active bits.
                    if self.read(at(r))? & 0x309f != 0 {
                        return Err(Error::Busy);
                    }
                }
            }
            DpStream::Hpo(_) => {
                for (r, mask) in [
                    (HPO_VIDEO, 0x101),
                    (HPO_CONTROL, 0x110),
                    (HPO_SDP, 1),
                    (HPO_FIFO, 0x111),
                    (HPO_RAMP, 0x100011),
                ] {
                    if self.read(at(r))? & mask != 0 {
                        return Err(Error::Busy);
                    }
                }
            }
        }
        Ok(())
    }
    fn dp_encoder_plan(&mut self, stream: DpStream) -> Result<Plan, Error> {
        let s = self.dp_preflight(stream)?;
        self.dp_encoder_quiet(stream)?;
        let mut plan = Plan {
            result: DpEncoderRetired {
                stream,
                detached_backends: 0,
            },
            mode: s.clock & 7,
            routes: [0; 4],
        };
        if let DpStream::Dio(p) = stream {
            if !matches!(plan.mode, 0 | 5) {
                return Err(Error::Unsupported);
            }
            // Resolve the actual many-to-many backend routing, not the OTG
            // index or stream number. A live unrelated output is left alone.
            // Legacy SST requires backend-off before frontend disable. Until
            // native MST teardown exists, require it for MST frontends too.
            for b in 0..4 {
                let backend = DpStream::Dio(b);
                let route = self.read(backend.at(self.layout, DIO_BACKEND))? & 0x7f00;
                if route & 0x7000 != 0 {
                    return Err(Error::Unsupported);
                }
                plan.routes[usize::from(b)] = route;
                if route & (0x100 << p) != 0 {
                    if self.read(backend.at(self.layout, DIO_BACKEND_ENABLE))? & 1 != 0 {
                        return Err(Error::Busy);
                    }
                    plan.result.detached_backends |= 1 << b;
                }
            }
        }
        Ok(plan)
    }
    fn dp_encoder_routes(&mut self, plan: &Plan, detached: bool) -> Result<(), Error> {
        if let DpStream::Dio(p) = plan.result.stream {
            for b in 0..4 {
                let backend = DpStream::Dio(b);
                let at = backend.at(self.layout, DIO_BACKEND);
                let expected =
                    plan.routes[usize::from(b)] & if detached { !(0x100 << p) } else { u32::MAX };
                if self.read(at)? & 0x7f00 != expected {
                    return Err(Error::Readback(at));
                }
                if plan.result.detached_backends & (1 << b) != 0
                    && self.read(backend.at(self.layout, DIO_BACKEND_ENABLE))? & 1 != 0
                {
                    return Err(Error::Busy);
                }
            }
        }
        Ok(())
    }
    async fn dp_encoder_disable(&mut self, plan: &Plan) -> Result<(), Error> {
        let stream = plan.result.stream;
        let l = self.layout;
        let at = |r| stream.at(l, r);
        match stream {
            DpStream::Dio(p) => {
                self.update(at(DIO_PIXEL_FIFO), 1, 0)?;
                self.update(at(DIO_ENABLE), 1, 0)?;
                self.update(at(DIO_CLOCK), 0x10, 0)?;
                // Monitor only frontend DISPCLK/SYMCLK; AFMT clocks belong to
                // audio and can remain running independently of this stream.
                self.wait(at(DIO_CLOCK), 0xc10, 0, 1000).await?;
                self.dp_encoder_quiet(stream)?;
                self.dp_encoder_routes(plan, false)?;
                self.update(at(DIO_PIXEL_FIFO), 0x300, 0)?;
                for b in 0..4 {
                    if plan.result.detached_backends & (1 << b) != 0 {
                        self.update(DpStream::Dio(b).at(l, DIO_BACKEND), 0x100 << p, 0)?;
                    }
                }
                for (r, mask, value) in [
                    (DIO_PIXEL_FIFO, 0x100303, 0),
                    (DIO_ENABLE, 1, 0),
                    (DIO_CLOCK, 0xc37, plan.mode),
                ] {
                    if self.read(at(r))? & mask != value {
                        return Err(Error::Readback(at(r)));
                    }
                }
                self.dp_encoder_routes(plan, true)?;
            }
            DpStream::Hpo(_) => {
                self.update(at(HPO_CONTROL), 1, 0)?;
                self.update(at(HPO_CLOCK), 1, 0)?;
                self.wait(at(HPO_CLOCK), 0x11111, 0, 1000).await?;
                if self.read(at(HPO_CONTROL))? & 0x111 != 0 {
                    return Err(Error::Readback(at(HPO_CONTROL)));
                }
            }
        }
        self.dp_encoder_quiet(stream)
    }
    pub(in super::super) async fn retire_dp_encoder(
        &mut self,
        stream: DpStream,
    ) -> Result<DpEncoderRetired, Error> {
        let plan = self.dp_encoder_plan(stream)?;
        self.status.state = State::RetiringDpEncoder(stream);
        match self.dp_encoder_disable(&plan).await {
            Ok(()) => {
                self.status.dp_encoder_retired = Some(plan.result);
                self.status.state = State::DpEncoderRetired;
                Ok(plan.result)
            }
            Err(e) => {
                self.status.state = State::Failed(e);
                Err(e)
            }
        }
    }
}
impl Otg {
    /// Disable a blank native DP stream encoder and acknowledge its clocks off.
    /// DIO additionally disconnects only this frontend's disabled backend routes.
    /// # Safety
    /// Stop CPU scanout writers, exclude firmware/FAMS and concurrent display,
    /// audio/packet/link/clock/power writers, and retain all associated memory
    /// and translations. Independently retire sink/MST payload bookkeeping and
    /// audio/metadata producers. Success never retires PHYs, timing, VPG/APG/AFMT,
    /// HUBP fetches or memory. Retain the owner on error or cancellation.
    pub async unsafe fn retire_dp_encoder(
        &mut self,
        stream: DpStream,
    ) -> Result<DpEncoderRetired, Error> {
        self.0.retire_dp_encoder(stream).await
    }
}
