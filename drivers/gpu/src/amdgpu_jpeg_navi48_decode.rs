//! Retained kernel-VMID0 picture proof; software models do not decode JPEG.
use super::*;
use crate::amdgpu_navi48_interrupts::{Observer, Source};
use alloc::vec::Vec;
use decode_words as d;
impl<I: Io> Engine<I> {
    pub(super) async fn prove_decode(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<DecodeProof, Error> {
        if self.state != State::Verified || self.decode_result.is_some() {
            return Err(Error::Busy);
        }
        let previous = self.result.ok_or(Error::Busy)?.map_err(|_| Error::Busy)?;
        if self.seq != previous.sequence
            || self.wptr != previous.read_pointer
            || self.reg(RPTR)? != self.wptr
        {
            return Err(Error::Busy);
        }
        if self.decode_memory.is_none() {
            self.decode_memory = Some(self.pool.reserve(d::BYTES).map_err(|_| Error::Allocation)?);
        }
        d::validate(self.decode_memory.as_ref().unwrap().address())?;
        self.state = State::DecodeTesting;
        self.decode_result = Some(Err(Error::Busy));
        self.decode_memory.as_mut().unwrap().publish();
        let result = self
            .prove_decode_inner(observer, previous)
            .await
            .and_then(|p| self.access(|_, _| Ok(p)));
        self.state = match result {
            Ok(_) => State::DecodeVerified,
            Err(e) => State::Failed(e),
        };
        self.decode_result = Some(result);
        result
    }
    async fn prove_decode_inner(
        &mut self,
        observer: &mut impl Observer,
        previous: Proof,
    ) -> Result<DecodeProof, Error> {
        let memory = self.decode_memory.as_ref().ok_or(Error::Busy)?;
        let (map, base) = (memory.mapping(), memory.address());
        let ib = d::ib(base)?;
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
        self.access(|io, l| {
            for (n, bytes) in d::STREAM.chunks(4).enumerate() {
                let mut word = [0; 4];
                word[..bytes.len()].copy_from_slice(bytes);
                io.memory_write(map, d::INPUT + n as u64 * 4, u32::from_le_bytes(word));
            }
            for (n, &value) in ib.iter().enumerate() {
                io.memory_write(map, d::IB + n as u64 * 4, value);
            }
            flush(io, l)
        })?;
        // No intervening job or client may use this fence: the transport
        // witness drained before entry, and this owner still excludes them.
        let kernel = self.memory.mapping();
        self.access(|io, l| {
            io.memory_write(kernel, FENCE, 0);
            io.memory_write(kernel, FENCE + 4, 0);
            flush(io, l)
        })?;
        let sample = observer
            .sample(Source::Jpeg0)
            .await
            .map_err(Error::Interrupts)?;
        self.seq = self.seq.wrapping_add(1).max(1);
        let sequence = self.seq;
        let main = self.memory.address();
        let frame = words::ib_frame(
            main + RING,
            base + d::IB,
            main + FENCE,
            sequence,
            ib.len() as u32,
        );
        let next = self.emit(&frame)?;
        let mut complete = false;
        for _ in 0..20_000 {
            let pointer = self.reg(RPTR)?;
            if pointer > next {
                return Err(Error::Readback);
            }
            let done = self.access(|io, l| {
                flush(io, l)?;
                Ok(io.memory_read(kernel, FENCE) == sequence)
            })?;
            let irq = observer.observed(sample).await.map_err(Error::Interrupts)?;
            if pointer == next && done && irq {
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
                    if at % d::PITCH < d::WIDTH {
                        for b in io.memory_read(map, d::TARGET + at).to_le_bytes() {
                            sum += u64::from(b);
                        }
                    }
                }
                Ok(sum)
            })?;
            self.io.delay(1).await;
        }
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
            self.io.delay(1).await;
        }
        // Immutable input includes all zero padding through the 8 KiB range.
        for page in (d::INPUT..d::INPUT + d::INPUT_BYTES).step_by(4096) {
            self.access(|io, l| {
                flush(io, l)?;
                for at in (page..page + 4096).step_by(4) {
                    let mut expected = [0; 4];
                    for (n, byte) in expected.iter_mut().enumerate() {
                        *byte = d::STREAM
                            .get((at - d::INPUT) as usize + n)
                            .copied()
                            .unwrap_or(0);
                    }
                    if io.memory_read(map, at) != u32::from_le_bytes(expected) {
                        return Err(Error::Readback);
                    }
                }
                Ok(())
            })?;
            self.io.delay(1).await;
        }
        self.access(|io, l| {
            flush(io, l)?;
            for n in 0..1024u64 {
                if io.memory_read(map, d::IB + n * 4) != ib.get(n as usize).copied().unwrap_or(0) {
                    return Err(Error::Readback);
                }
            }
            Ok(())
        })?;
        self.decode_kernel_guards(previous, sequence, next, &frame)
            .await?;
        if !observer.observed(sample).await.map_err(Error::Interrupts)? {
            return Err(Error::Timeout);
        }
        self.shared_range()?;
        if sum != d::EXPECTED_SUM {
            return Err(Error::DecodeChecksum(sum));
        }
        Ok(DecodeProof {
            completion: Proof {
                sequence,
                read_pointer: next,
                msi_verified: sample.vector.is_some(),
            },
            output_sum: sum,
        })
    }
    async fn decode_kernel_guards(
        &mut self,
        previous: Proof,
        sequence: u32,
        next: u32,
        frame: &[u32],
    ) -> Result<(), Error> {
        let map = self.memory.mapping();
        for guard in [0, END_GUARD] {
            self.access(|io, l| {
                flush(io, l)?;
                for at in (guard..guard + 4096).step_by(4) {
                    if io.memory_read(map, at) != GUARD {
                        return Err(Error::Readback);
                    }
                }
                Ok(())
            })?;
            self.io.delay(1).await;
        }
        let base = self.memory.address();
        let mut expected = Vec::with_capacity(1024);
        for command in [
            words::direct(),
            words::ib_frame(base + RING, base + IB, base + FENCE, previous.sequence, 16),
            frame.to_vec(),
        ] {
            expected.extend_from_slice(&command);
            while expected.len() & 15 != 0 {
                expected.extend_from_slice(&[words::NOP, 0]);
            }
        }
        if expected.len() != next as usize {
            return Err(Error::Readback);
        }
        self.access(|io, l| {
            flush(io, l)?;
            let ib = words::kernel_ib();
            for n in 0..1024u64 {
                if io.memory_read(map, RING + n * 4)
                    != expected.get(n as usize).copied().unwrap_or(0)
                    || io.memory_read(map, IB + n * 4) != ib.get(n as usize).copied().unwrap_or(0)
                {
                    return Err(Error::Readback);
                }
                let actual = io.memory_read(map, FENCE + n * 4);
                if n == 1 {
                    if actual != 0 && actual != sequence {
                        return Err(Error::Readback);
                    }
                } else if actual
                    != match n {
                        0 => sequence,
                        2 => next,
                        _ => 0,
                    }
                {
                    return Err(Error::Readback);
                }
            }
            Ok(())
        })
    }
}
