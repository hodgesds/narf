//! Fresh unified-ring interrupt proof through the independent IH service.
use super::*;
use crate::amdgpu_navi48_interrupts::{Observer, Source};

impl<I: Io> Engine<I> {
    pub(super) async fn prove_interrupts(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<InterruptProof, Error> {
        if self.state != State::Verified || self.interrupt_result.is_some() {
            return Err(Error::Busy);
        }
        self.state = State::InterruptTesting;
        self.interrupt_result = Some(Err(Error::Busy));
        let result = self
            .prove_interrupts_inner(observer)
            .await
            .and_then(|proof| self.access(|_, _| Ok(proof)));
        self.state = match result {
            Ok(_) => State::InterruptVerified,
            Err(e) => State::Failed(e),
        };
        self.interrupt_result = Some(result);
        result
    }
    async fn prove_interrupts_inner(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<InterruptProof, Error> {
        // Sampling drains stale IVs and checks live route/IRQ state before
        // enabling any source or publishing this proof's new command frame.
        let sample = observer
            .sample(Source::Vcn0)
            .await
            .map_err(Error::Interrupts)?;
        self.set(MASTINT, 2, 2)?;
        self.seq = self.seq.wrapping_add(1).max(1);
        let seq = self.seq;
        let at = self.memory.address() + FENCE;
        let next = self.emit(&[3, at as u32, (at >> 32) as u32, seq, 4, 1])?;
        let map = self.memory.mapping();
        for _ in 0..2000 {
            let rptr = self.reg(RPTR)?;
            if rptr.wrapping_sub(next) as i32 > 0 {
                return Err(Error::Readback);
            }
            let memory = self.access(|io, l| {
                flush(io, l)?;
                Ok(io.memory_read(map, FENCE) == seq)
            })?;
            let event = observer.observed(sample).await.map_err(Error::Interrupts)?;
            if rptr == next && memory && event {
                self.fence_guards(next)?;
                return Ok(InterruptProof {
                    fence: Proof {
                        sequence: seq,
                        read_pointer: rptr,
                    },
                    msi_verified: sample.vector.is_some(),
                });
            }
            self.io.delay(50).await;
        }
        Err(Error::Timeout)
    }
}
