//! Fresh direct-pitch and kernel-IB witnesses through JPEG0's native trap.
use super::*;
use crate::amdgpu_navi48_interrupts::{Observer, Source};
impl<I: Io> Engine<I> {
    pub(super) async fn prove(&mut self, observer: &mut impl Observer) -> Result<Proof, Error> {
        if self.state != State::Ready || self.result.is_some() {
            return Err(Error::Busy);
        }
        self.state = State::Testing;
        self.result = Some(Err(Error::Busy));
        let result = self
            .prove_inner(observer)
            .await
            .and_then(|p| self.access(|_, _| Ok(p)));
        self.state = match result {
            Ok(_) => State::Verified,
            Err(e) => State::Failed(e),
        };
        self.result = Some(result);
        result
    }
    async fn prove_inner(&mut self, observer: &mut impl Observer) -> Result<Proof, Error> {
        self.set(PITCH, u32::MAX, 0xcafedead)?;
        let direct = words::direct();
        let first = self.emit(&direct)?;
        let mut ready = false;
        for _ in 0..2000 {
            let pointer = self.reg(RPTR)?;
            if pointer > first {
                return Err(Error::Readback);
            }
            if pointer == first && self.reg(PITCH)? == 0xabadcafe {
                ready = true;
                break;
            }
            self.io.delay(50).await;
        }
        if !ready {
            return Err(Error::Timeout);
        }
        let map = self.memory.mapping();
        let ib = words::kernel_ib();
        self.access(|io, l| {
            for (n, &value) in ib.iter().enumerate() {
                io.memory_write(map, IB + n as u64 * 4, value);
            }
            flush(io, l)
        })?;
        self.set(PITCH, u32::MAX, 0xcafedead)?;
        let sample = observer
            .sample(Source::Jpeg0)
            .await
            .map_err(Error::Interrupts)?;
        self.set(IRQ, 0x100, 0x100)?;
        self.seq = self.seq.wrapping_add(1).max(1);
        let sequence = self.seq;
        let base = self.memory.address();
        let frame = words::ib_frame(base + RING, base + IB, base + FENCE, sequence, 16);
        let next = self.emit(&frame)?;
        let mut complete = false;
        for _ in 0..2000 {
            let pointer = self.reg(RPTR)?;
            if pointer > next {
                return Err(Error::Readback);
            }
            let done = self.access(|io, l| {
                flush(io, l)?;
                Ok(io.memory_read(map, FENCE) == sequence)
            })?;
            let irq = observer.observed(sample).await.map_err(Error::Interrupts)?;
            if pointer == next && done && irq && self.reg(PITCH)? == 0xdeadbeef {
                complete = true;
                break;
            }
            self.io.delay(50).await;
        }
        if !complete {
            return Err(Error::Timeout);
        }
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
        self.access(|io, l| {
            flush(io, l)?;
            for n in 0..1024u64 {
                let actual = io.memory_read(map, FENCE + n * 4);
                if n == 1 {
                    // GPCOM reserves both data dwords; high may be unwritten.
                    if actual != 0 && actual != sequence {
                        return Err(Error::Readback);
                    }
                    continue;
                }
                let expected = match n {
                    0 => sequence,
                    2 => next,
                    _ => 0,
                };
                if actual != expected {
                    return Err(Error::Readback);
                }
            }
            Ok(())
        })?;
        self.io.delay(1).await;
        self.access(|io, l| {
            flush(io, l)?;
            for n in 0..1024u64 {
                if io.memory_read(map, IB + n * 4) != ib.get(n as usize).copied().unwrap_or(0) {
                    return Err(Error::Readback);
                }
                let expected = if n < u64::from(first) {
                    direct.get(n as usize).copied().unwrap_or(if n % 2 == 0 {
                        words::NOP
                    } else {
                        0
                    })
                } else if n < u64::from(next) {
                    frame
                        .get((n - u64::from(first)) as usize)
                        .copied()
                        .unwrap_or(if n % 2 == 0 { words::NOP } else { 0 })
                } else {
                    0
                };
                if io.memory_read(map, RING + n * 4) != expected {
                    return Err(Error::Readback);
                }
            }
            Ok(())
        })?;
        if !observer.observed(sample).await.map_err(Error::Interrupts)? {
            return Err(Error::Timeout);
        }
        self.shared_range()?;
        Ok(Proof {
            sequence,
            read_pointer: next,
            msi_verified: sample.vector.is_some(),
        })
    }
}
