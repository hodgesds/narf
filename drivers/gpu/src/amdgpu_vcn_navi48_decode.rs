//! Retained, fixed IGT AVC picture test. Physical codec acceptance is separate
//! from this module's packet, storage and completion models.
use super::*;
use crate::amdgpu_navi48_interrupts::{Observer, Source};
use decode_words as d;

impl<I: Io> Engine<I> {
    pub(super) async fn prove_decode(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<DecodeProof, Error> {
        if self.state != State::IbVerified || self.decode_result.is_some() {
            return Err(Error::Busy);
        }
        let prior = self
            .ib_result
            .ok_or(Error::Busy)?
            .map_err(|_| Error::Busy)?;
        if self.seq != prior.fence.sequence || self.reg(RPTR)? != self.wptr {
            return Err(Error::Busy);
        }
        if self.decode_memory.is_none() {
            self.decode_memory = Some(
                self.ib_pool
                    .reserve(d::BYTES)
                    .map_err(|_| Error::Allocation)?,
            );
        }
        d::validate(self.decode_memory.as_ref().unwrap().address())?;
        self.state = State::DecodeTesting;
        self.decode_result = Some(Err(Error::Busy));
        self.decode_memory.as_mut().unwrap().publish();
        let result = self
            .prove_decode_inner(observer)
            .await
            .and_then(|proof| self.access(|_, _| Ok(proof)));
        self.state = match result {
            Ok(_) => State::DecodeVerified,
            Err(e) => State::Failed(e),
        };
        self.decode_result = Some(result);
        result
    }
    fn decode_bytes(&mut self, map: MmioRegion, at: u64, bytes: &[u8]) -> Result<(), Error> {
        self.access(|io, l| {
            for (i, word) in bytes.chunks(4).enumerate() {
                let mut value = [0; 4];
                value[..word.len()].copy_from_slice(word);
                io.memory_write(map, at + i as u64 * 4, u32::from_le_bytes(value));
            }
            flush(io, l)
        })
    }
    async fn prove_decode_inner(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<DecodeProof, Error> {
        let memory = self.decode_memory.as_ref().ok_or(Error::Busy)?;
        let (map, base) = (memory.mapping(), memory.address());
        let create = d::ib(base, d::Phase::Create)?;
        let decode = d::ib(base, d::Phase::Decode)?;
        let destroy = d::ib(base, d::Phase::Destroy)?;
        // Every output starts at zero. Only hardware can produce the nonzero
        // reference checksum; stale picture data cannot satisfy this run.
        for page in (0..d::BYTES).step_by(4096) {
            self.access(|io, l| {
                let value = if d::GUARDS.contains(&page) {
                    d::GUARD
                } else {
                    0
                };
                for at in (page..page + 4096).step_by(4) {
                    io.memory_write(map, at, value);
                }
                flush(io, l)
            })?;
            self.io.delay(1).await;
        }
        for (at, bytes) in [
            (d::CREATE_MSG, d::CREATE_MSG_BYTES),
            (d::DECODE_MSG, d::DECODE_MSG_BYTES),
            (
                d::DECODE_MSG + d::DECODE_MSG_BYTES.len() as u64,
                d::AVC_BYTES,
            ),
            (d::DESTROY_MSG, d::DESTROY_MSG_BYTES),
            (d::FEEDBACK, d::FEEDBACK_BYTES),
            (d::SCALING, d::SCALING_BYTES),
            (d::BITSTREAM, d::STREAM),
        ] {
            self.decode_bytes(map, at, bytes)?;
        }
        for (at, words) in [
            (d::CREATE_IB, &create),
            (d::DECODE_IB, &decode),
            (d::DESTROY_IB, &destroy),
        ] {
            self.access(|io, l| {
                for (i, &word) in words.iter().enumerate() {
                    io.memory_write(map, at + i as u64 * 4, word);
                }
                flush(io, l)
            })?;
        }
        let sample = observer
            .sample(Source::Vcn0)
            .await
            .map_err(Error::Interrupts)?;
        self.seq = self.seq.wrapping_add(1).max(1);
        let sequence = self.seq;
        let mut frame = [0; 24];
        frame[..3].copy_from_slice(&[0xb, 0x7f000, 0]);
        for (i, offset) in [d::CREATE_IB, d::DECODE_IB, d::DESTROY_IB]
            .into_iter()
            .enumerate()
        {
            let at = base + offset;
            frame[3 + i * 5..8 + i * 5].copy_from_slice(&[2, 0, at as u32, (at >> 32) as u32, 43]);
        }
        let at = self.memory.address() + FENCE;
        frame[18..].copy_from_slice(&[3, at as u32, (at >> 32) as u32, sequence, 4, 1]);
        let next = self.emit(&frame)?;
        let mut complete = false;
        for _ in 0..20_000 {
            let pointer = self.reg(RPTR)?;
            if pointer > next {
                return Err(Error::Readback);
            }
            let fence = self.completed_job()? == sequence;
            let irq = observer.observed(sample).await.map_err(Error::Interrupts)?;
            if pointer == next && fence && irq {
                complete = true;
                break;
            }
            self.io.delay(50).await;
        }
        if !complete {
            return Err(Error::Timeout);
        }
        let mut sum = 0u64;
        for page in (0..d::TARGET_BYTES).step_by(4096) {
            sum += self.access(|io, l| {
                flush(io, l)?;
                let mut sum = 0u64;
                for at in (page..page + 4096).step_by(4) {
                    for byte in io.memory_read(map, d::TARGET + at).to_le_bytes() {
                        sum += u64::from(byte);
                    }
                }
                Ok(sum)
            })?;
            self.io.delay(1).await;
        }
        self.fence_guards(next)?;
        for guard in d::GUARDS {
            self.access(|io, l| {
                flush(io, l)?;
                for at in (guard..guard + 4096).step_by(4) {
                    if io.memory_read(map, at) != d::GUARD {
                        return Err(Error::Readback);
                    }
                }
                Ok(())
            })?;
        }
        for (at, expected) in [
            (d::CREATE_IB, &create),
            (d::DECODE_IB, &decode),
            (d::DESTROY_IB, &destroy),
        ] {
            self.access(|io, l| {
                flush(io, l)?;
                for n in 0..1024 {
                    if io.memory_read(map, at + n * 4)
                        != expected.get(n as usize).copied().unwrap_or(0)
                    {
                        return Err(Error::Readback);
                    }
                }
                Ok(())
            })?;
        }
        if !observer.observed(sample).await.map_err(Error::Interrupts)? {
            return Err(Error::Timeout);
        }
        if sum != d::EXPECTED_SUM {
            return Err(Error::DecodeChecksum(sum));
        }
        Ok(DecodeProof {
            completion: InterruptProof {
                fence: Proof {
                    sequence,
                    read_pointer: next,
                },
                msi_verified: sample.vector.is_some(),
            },
            output_sum: sum,
        })
    }
}
