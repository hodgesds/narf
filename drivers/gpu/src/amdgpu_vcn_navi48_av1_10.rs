//! Retained 10-bit P010 AV1 keyframe proof with Mesa Tier3 unified-DT; models do not decode AV1.
use super::*;
use crate::amdgpu_navi48_interrupts::Observer;
use av1_10_words as d;

impl<I: Io> Engine<I> {
    pub(super) async fn prove_av1_10(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<DecodeProof, Error> {
        if self.av1_10_result.is_some() {
            return Err(Error::Busy);
        }
        let prior = match self.state {
            State::IbVerified => self
                .ib_result
                .ok_or(Error::Busy)?
                .map_err(|_| Error::Busy)?,
            State::Av1Verified => {
                self.av1_result
                    .ok_or(Error::Busy)?
                    .map_err(|_| Error::Busy)?
                    .completion
            }
            State::Vp9TenVerified => {
                self.vp9_10_result
                    .ok_or(Error::Busy)?
                    .map_err(|_| Error::Busy)?
                    .completion
            }
            State::Vp9Verified => {
                self.vp9_result
                    .ok_or(Error::Busy)?
                    .map_err(|_| Error::Busy)?
                    .completion
            }
            State::Hevc10Verified => {
                self.hevc10_result
                    .ok_or(Error::Busy)?
                    .map_err(|_| Error::Busy)?
                    .completion
            }
            State::HevcVerified => {
                self.hevc_result
                    .ok_or(Error::Busy)?
                    .map_err(|_| Error::Busy)?
                    .completion
            }
            State::DecodeVerified => {
                self.decode_result
                    .ok_or(Error::Busy)?
                    .map_err(|_| Error::Busy)?
                    .completion
            }
            _ => return Err(Error::Busy),
        };
        if self.seq != prior.fence.sequence || self.reg(RPTR)? != self.wptr {
            return Err(Error::Busy);
        }
        if self.av1_10_memory.is_none() {
            self.av1_10_memory = Some(
                self.ib_pool
                    .reserve(d::BYTES)
                    .map_err(|_| Error::Allocation)?,
            );
        }
        d::validate(self.av1_10_memory.as_ref().unwrap().address())?;
        self.state = State::Av1TenTesting;
        self.av1_10_result = Some(Err(Error::Busy));
        self.av1_10_memory.as_mut().unwrap().publish();
        let result = self
            .prove_av1_10_inner(observer)
            .await
            .and_then(|proof| self.access(|_, _| Ok(proof)));
        self.state = match result {
            Ok(_) => State::Av1TenVerified,
            Err(e) => State::Failed(e),
        };
        self.av1_10_result = Some(result);
        result
    }
    async fn prove_av1_10_inner(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<DecodeProof, Error> {
        let memory = self.av1_10_memory.as_ref().ok_or(Error::Busy)?;
        let (map, base) = (memory.mapping(), memory.address());
        self.decode_av1_10_frame(map, base, observer).await
    }
}
