//! Owned kernel-VMID0 firmware session IB test, amdgpu_vcn_unified_ring_test_ib.
use super::*;
use crate::amdgpu_navi48_interrupts::{Observer, Source};
use ib_words as words;

impl<I: Io> Engine<I> {
    pub(super) async fn prove_ibs(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<InterruptProof, Error> {
        if self.state != State::InterruptVerified || self.ib_result.is_some() {
            return Err(Error::Busy);
        }
        let previous = self
            .interrupt_result
            .ok_or(Error::Busy)?
            .map_err(|_| Error::Busy)?;
        if self.seq != previous.fence.sequence || self.reg(RPTR)? != self.wptr {
            return Err(Error::Busy);
        }
        if self.ib_memory.is_none() {
            self.ib_memory = Some(
                self.ib_pool
                    .reserve(words::IB_BYTES)
                    .map_err(|_| Error::Allocation)?,
            );
        }
        self.state = State::IbTesting;
        self.ib_result = Some(Err(Error::Busy));
        // Retain both firmware context and commands before the first await.
        self.ib_memory.as_mut().unwrap().publish();
        let result = self
            .prove_ibs_inner(observer)
            .await
            .and_then(|proof| self.access(|_, _| Ok(proof)));
        self.state = match result {
            Ok(_) => State::IbVerified,
            Err(e) => State::Failed(e),
        };
        self.ib_result = Some(result);
        result
    }
    async fn prove_ibs_inner(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<InterruptProof, Error> {
        let memory = self.ib_memory.as_ref().ok_or(Error::Busy)?;
        let map = memory.mapping();
        let base = memory.address();
        let encode_create = words::encode(base, true)?;
        let encode_destroy = words::encode(base, false)?;
        let decode_create = words::decode(base + words::DECODE_CREATE_MSG)?;
        let decode_destroy = words::decode(base + words::DECODE_DESTROY_MSG)?;
        for page in (0..words::IB_BYTES).step_by(4096) {
            self.access(|io, l| {
                for at in (page..page + 4096).step_by(4) {
                    io.memory_write(map, at, 0);
                }
                flush(io, l)
            })?;
            self.io.delay(1).await;
        }
        for (offset, data) in [
            (words::ENCODE_CREATE, encode_create.as_slice()),
            (words::ENCODE_DESTROY, encode_destroy.as_slice()),
            (words::DECODE_CREATE, decode_create.as_slice()),
            (words::DECODE_DESTROY, decode_destroy.as_slice()),
            (
                words::DECODE_CREATE_MSG,
                words::decode_message(true).as_slice(),
            ),
            (
                words::DECODE_DESTROY_MSG,
                words::decode_message(false).as_slice(),
            ),
        ] {
            self.access(|io, l| {
                for (i, &word) in data.iter().enumerate() {
                    io.memory_write(map, offset + i as u64 * 4, word);
                }
                flush(io, l)
            })?;
        }
        let sample = observer
            .sample(Source::Vcn0)
            .await
            .map_err(Error::Interrupts)?;
        // A zero proof could match the cleared fence after sequence wrap.
        self.seq = self.seq.wrapping_add(1).max(1);
        let sequence = self.seq;
        let mut frame = [0; 29];
        frame[..3].copy_from_slice(&[0xb, 0x7f000, 0]);
        for (i, (offset, length)) in [
            (words::ENCODE_CREATE, 21),
            (words::ENCODE_DESTROY, 21),
            (words::DECODE_CREATE, 43),
            (words::DECODE_DESTROY, 43),
        ]
        .into_iter()
        .enumerate()
        {
            let address = base + offset;
            // Kernel VMID0 only; this is not a client submission bypass.
            frame[3 + i * 5..8 + i * 5].copy_from_slice(&[
                2,
                0,
                address as u32,
                (address >> 32) as u32,
                length,
            ]);
        }
        let at = self.memory.address() + FENCE;
        frame[23..].copy_from_slice(&[3, at as u32, (at >> 32) as u32, sequence, 4, 1]);
        let start = self.wptr;
        let next = self.emit(&frame)?;
        for _ in 0..20_000 {
            let pointer = self.reg(RPTR)?;
            proof_pointer(pointer, start, next)?;
            let complete = self.completed_job()? == sequence;
            let interrupt = observer.observed(sample).await.map_err(Error::Interrupts)?;
            if pointer == next && complete && interrupt {
                self.fence_guards(next)?;
                // Firmware may write its context and message allocations.
                // Command pages and their padding are immutable kernel IBs.
                for (offset, expected) in [
                    (words::ENCODE_CREATE, encode_create.as_slice()),
                    (words::ENCODE_DESTROY, encode_destroy.as_slice()),
                    (words::DECODE_CREATE, decode_create.as_slice()),
                    (words::DECODE_DESTROY, decode_destroy.as_slice()),
                ] {
                    self.access(|io, l| {
                        flush(io, l)?;
                        for n in 0..1024 {
                            if io.memory_read(map, offset + n * 4)
                                != expected.get(n as usize).copied().unwrap_or(0)
                            {
                                return Err(Error::Readback);
                            }
                        }
                        Ok(())
                    })?;
                }
                return Ok(InterruptProof {
                    fence: Proof {
                        sequence,
                        read_pointer: pointer,
                    },
                    msi_verified: sample.vector.is_some(),
                });
            }
            self.io.delay(50).await;
        }
        Err(Error::Timeout)
    }
}
