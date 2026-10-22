//! Retained kernel-VMID0 fixed IDR encode proof; models do not encode pixels.
use super::*;
use crate::amdgpu_navi48_interrupts::{Observer, Source};
use alloc::vec::Vec;
use encode_words as e;

impl<I: Io> Engine<I> {
    pub(super) async fn prove_encode(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<EncodeProof, Error> {
        if self.encode_result.is_some() {
            return Err(Error::Busy);
        }
        let prior = match self.state {
            State::IbVerified => self
                .ib_result
                .ok_or(Error::Busy)?
                .map_err(|_| Error::Busy)?,
            State::Av1TenVerified => {
                self.av1_10_result
                    .ok_or(Error::Busy)?
                    .map_err(|_| Error::Busy)?
                    .completion
            }
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
        if self.encode_memory.is_none() {
            self.encode_memory = Some(
                self.ib_pool
                    .reserve(e::BYTES)
                    .map_err(|_| Error::Allocation)?,
            );
        }
        e::validate(self.encode_memory.as_ref().unwrap().address())?;
        self.state = State::EncodeTesting;
        self.encode_result = Some(Err(Error::Busy));
        self.encode_memory.as_mut().unwrap().publish();
        let result = self
            .prove_encode_inner(observer)
            .await
            .and_then(|p| self.access(|_, _| Ok(p)));
        self.state = match result {
            Ok(_) => State::EncodeVerified,
            Err(error) => State::Failed(error),
        };
        self.encode_result = Some(result);
        result
    }
    async fn prove_encode_inner(
        &mut self,
        observer: &mut impl Observer,
    ) -> Result<EncodeProof, Error> {
        let memory = self.encode_memory.as_ref().ok_or(Error::Busy)?;
        let (map, base) = (memory.mapping(), memory.address());
        let create = e::ib(base, e::Phase::Create)?;
        let encode = e::ib(base, e::Phase::Encode)?;
        let destroy = e::ib(base, e::Phase::Destroy)?;
        for page in (0..e::BYTES).step_by(4096) {
            self.access(|io, l| {
                let value = if e::GUARDS.contains(&page) {
                    e::GUARD
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
        // The source is tightly packed NV12; hardware uses a 256-byte pitch.
        // Preserve zero padding and bound every read to the pinned fixture.
        for page in (0..e::INPUT_BYTES).step_by(4096) {
            self.access(|io, l| {
                for at in (page..page + 4096).step_by(4) {
                    let column = at % e::PITCH;
                    if column < u64::from(e::WIDTH) {
                        let from = ((at / e::PITCH) * u64::from(e::WIDTH) + column) as usize;
                        io.memory_write(
                            map,
                            e::INPUT + at,
                            u32::from_le_bytes(e::FRAME[from..from + 4].try_into().unwrap()),
                        );
                    }
                }
                flush(io, l)
            })?;
            self.io.delay(1).await;
        }
        let commands = [
            (e::CREATE_IB, &create, 4096),
            (e::ENCODE_IB, &encode, 8192),
            (e::DESTROY_IB, &destroy, 4096),
        ];
        for &(at, words, _) in &commands {
            for (page, chunk) in words.chunks(1024).enumerate() {
                self.access(|io, l| {
                    for (i, &word) in chunk.iter().enumerate() {
                        io.memory_write(map, at + (page * 4096 + i * 4) as u64, word);
                    }
                    flush(io, l)
                })?;
                self.io.delay(1).await;
            }
        }
        let sample = observer
            .sample(Source::Vcn0)
            .await
            .map_err(Error::Interrupts)?;
        self.seq = self.seq.wrapping_add(1).max(1);
        let sequence = self.seq;
        let mut frame = [0; 24];
        frame[..3].copy_from_slice(&[0xb, 0x7f000, 0]);
        for (i, &(offset, words, _)) in commands.iter().enumerate() {
            let at = base + offset;
            frame[3 + i * 5..8 + i * 5].copy_from_slice(&[
                2,
                0,
                at as u32,
                (at >> 32) as u32,
                words.len() as u32,
            ]);
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
        let size = self.access(|io, l| {
            flush(io, l)?;
            // Mesa radeon_vcn_enc.c::radeon_enc_get_feedback: word 1
            // validates feedback; words 6/8 are end/start byte offsets.
            let valid = io.memory_read(map, e::FEEDBACK + 4);
            let end = io.memory_read(map, e::FEEDBACK + 6 * 4);
            let start = io.memory_read(map, e::FEEDBACK + 8 * 4);
            if valid == 0 || start != 0 || end <= start {
                return Err(Error::EncodeOutput);
            }
            Ok(end - start)
        })?;
        if size == 0 || u64::from(size) > e::OUTPUT_BYTES {
            return Err(Error::EncodeOutput);
        }
        let mut stream = Vec::with_capacity(size as usize);
        for page in (0..u64::from(size)).step_by(4096) {
            self.access(|io, l| {
                flush(io, l)?;
                for at in (page..(page + 4096).min(u64::from(size))).step_by(4) {
                    let word = io.memory_read(map, e::OUTPUT + at).to_le_bytes();
                    let count = (u64::from(size) - at).min(4) as usize;
                    stream.extend_from_slice(&word[..count]);
                }
                Ok(())
            })?;
            self.io.delay(1).await;
        }
        self.fence_guards(next)?;
        for guard in e::GUARDS {
            self.access(|io, l| {
                flush(io, l)?;
                for at in (guard..guard + 4096).step_by(4) {
                    if io.memory_read(map, at) != e::GUARD {
                        return Err(Error::Readback);
                    }
                }
                Ok(())
            })?;
        }
        for &(at, words, bytes) in &commands {
            for page in (0..bytes).step_by(4096) {
                self.access(|io, l| {
                    flush(io, l)?;
                    for n in (page..page + 4096).step_by(4) {
                        if io.memory_read(map, at + n)
                            != words.get(n as usize / 4).copied().unwrap_or(0)
                        {
                            return Err(Error::Readback);
                        }
                    }
                    Ok(())
                })?;
                self.io.delay(1).await;
            }
        }
        for page in (0..e::INPUT_BYTES).step_by(4096) {
            self.access(|io, l| {
                flush(io, l)?;
                for at in (page..page + 4096).step_by(4) {
                    let column = at % e::PITCH;
                    let expected = if column < u64::from(e::WIDTH) {
                        let from = ((at / e::PITCH) * u64::from(e::WIDTH) + column) as usize;
                        u32::from_le_bytes(e::FRAME[from..from + 4].try_into().unwrap())
                    } else {
                        0
                    };
                    if io.memory_read(map, e::INPUT + at) != expected {
                        return Err(Error::Readback);
                    }
                }
                Ok(())
            })?;
            self.io.delay(1).await;
        }
        if !observer.observed(sample).await.map_err(Error::Interrupts)? {
            return Err(Error::Timeout);
        }
        let picture = h264::inspect(&stream).ok_or(Error::EncodeOutput)?;
        if picture.width != e::WIDTH
            || picture.height != e::HEIGHT
            || picture.slice_type != 2
            || !picture.idr
        {
            return Err(Error::EncodeOutput);
        }
        Ok(EncodeProof {
            completion: InterruptProof {
                fence: Proof {
                    sequence,
                    read_pointer: next,
                },
                msi_verified: sample.vector.is_some(),
            },
            output_bytes: size,
            profile: picture.profile,
        })
    }
}
