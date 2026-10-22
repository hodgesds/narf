//! Retained original Main10 IDR proof. Synthetic models do not decode HEVC.
use super::*;
use crate::amdgpu_navi48_interrupts::{Observer, Source};
use hevc10_words as d;

impl<I: Io> Engine<I> {
    pub(super) async fn prove_hevc10(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<DecodeProof, Error> {
        if self.hevc10_result.is_some() {
            return Err(Error::Busy);
        }
        let prior = match self.state {
            State::IbVerified => self
                .ib_result
                .ok_or(Error::Busy)?
                .map_err(|_| Error::Busy)?,
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
        if self.hevc10_memory.is_none() {
            self.hevc10_memory = Some(
                self.ib_pool
                    .reserve(d::BYTES)
                    .map_err(|_| Error::Allocation)?,
            );
        }
        d::validate(self.hevc10_memory.as_ref().unwrap().address())?;
        self.state = State::Hevc10Testing;
        self.hevc10_result = Some(Err(Error::Busy));
        self.hevc10_memory.as_mut().unwrap().publish();
        let result = self
            .prove_hevc10_inner(observer)
            .await
            .and_then(|proof| self.access(|_, _| Ok(proof)));
        self.state = match result {
            Ok(_) => State::Hevc10Verified,
            Err(e) => State::Failed(e),
        };
        self.hevc10_result = Some(result);
        result
    }
    fn hevc10_bytes(&mut self, map: MmioRegion, at: u64, bytes: &[u8]) -> Result<(), Error> {
        self.access(|io, l| {
            for (i, word) in bytes.chunks(4).enumerate() {
                let mut value = [0; 4];
                value[..word.len()].copy_from_slice(word);
                io.memory_write(map, at + i as u64 * 4, u32::from_le_bytes(value));
            }
            flush(io, l)
        })
    }
    async fn prove_hevc10_inner(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<DecodeProof, Error> {
        let memory = self.hevc10_memory.as_ref().ok_or(Error::Busy)?;
        let (map, base) = (memory.mapping(), memory.address());
        let create = d::ib(base, d::Phase::Create)?;
        let decode = d::ib(base, d::Phase::Decode)?;
        let destroy = d::ib(base, d::Phase::Destroy)?;
        // Every output starts at zero. Only hardware can produce the nonzero
        // reference pixels; stale picture data cannot satisfy this run.
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
        let create_msg = d::create_message();
        let decode_msg = d::decode_message();
        let destroy_msg = d::destroy_message();
        let mut feedback = [0u8; 44];
        feedback[..4].copy_from_slice(&44u32.to_le_bytes());
        feedback[4..8].copy_from_slice(&44u32.to_le_bytes());
        for (at, bytes) in [
            (d::CREATE_MSG, create_msg.as_slice()),
            (d::DECODE_MSG, decode_msg.as_slice()),
            (d::DESTROY_MSG, destroy_msg.as_slice()),
            (d::FEEDBACK, feedback.as_slice()),
            (d::SCALING, [16u8; 992].as_slice()),
            (d::BITSTREAM, d::STREAM),
        ] {
            self.hevc10_bytes(map, at, bytes)?;
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
        let start = self.wptr;
        let next = self.emit(&frame)?;
        let mut complete = false;
        for _ in 0..20_000 {
            let pointer = self.reg(RPTR)?;
            proof_pointer(pointer, start, next)?;
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
                    for (i, byte) in io
                        .memory_read(map, d::TARGET + at)
                        .to_le_bytes()
                        .into_iter()
                        .enumerate()
                    {
                        let offset = at + i as u64;
                        if byte != d::expected(offset) {
                            return Err(Error::DecodePixel(offset as u32));
                        }
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
        self.access(|io, l| {
            flush(io, l)?;
            if io.memory_read(map, d::FEEDBACK + 24) != 0 {
                return Err(Error::Readback);
            }
            for (at, bytes) in [
                (d::BITSTREAM, d::STREAM),
                (d::SCALING, [16u8; 992].as_slice()),
            ] {
                for (n, expected) in bytes.chunks(4).enumerate() {
                    let mut word = [0u8; 4];
                    word[..expected.len()].copy_from_slice(expected);
                    if io.memory_read(map, at + n as u64 * 4) != u32::from_le_bytes(word) {
                        return Err(Error::Readback);
                    }
                }
            }
            Ok(())
        })?;
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
