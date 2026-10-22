// SPDX-License-Identifier: MIT
use super::*;
use av1_320_words as d;
const STREAM: &[u8] = include_bytes!("../fixtures/vcn5/av1_encode/reference-frame.obu");

// Synthetic DMA completion is not a AV1 decoder. Omit the opaque 36.7 MiB
// firmware context tail while counting every initialization write. Addresses,
// descriptors and the real Pool reservation still cover the entire context.
#[derive(Default)]
pub(super) struct Model {
    base: Option<u64>,
    expected_phys: Option<u64>,
    memory: Vec<u8>,
    context_zeroes: u64,
    pub(super) stages: u8,
    pub(super) fault: u8,
}
impl Model {
    pub(super) fn base_for_test(&self) -> Option<u64> {
        self.base
    }
    pub(super) fn bind(&mut self, memory: &Reservation) {
        assert_eq!(memory.size(), d::BYTES);
        self.base = Some(memory.address());
        self.expected_phys = Some(memory.mapping().phys.raw());
    }
    const OMIT_START: u64 = d::CONTEXT + d::DEFAULT_CDF.len() as u64;
    const OMIT_END: u64 = d::SESSION_END_GUARD;
    const OMIT: u64 = Self::OMIT_END - Self::OMIT_START;
    fn index(at: u64) -> Option<usize> {
        assert!(at < d::BYTES);
        if at < Self::OMIT_START {
            Some(at as usize)
        } else if at >= Self::OMIT_END {
            Some((at - Self::OMIT) as usize)
        } else {
            None
        }
    }
    pub(super) fn contains(&self, at: u64) -> bool {
        self.base
            .is_some_and(|base| (base..base + d::BYTES).contains(&at))
    }
    pub(super) fn read(&self, map: MmioRegion, at: u64) -> Option<u32> {
        (map.len == d::BYTES && self.expected_phys == Some(map.phys.raw())).then(|| self.word(at))
    }
    fn word(&self, at: u64) -> u32 {
        Self::index(at).map_or(0, |i| {
            u32::from_le_bytes(self.memory[i..i + 4].try_into().unwrap())
        })
    }
    pub(super) fn write(&mut self, map: MmioRegion, at: u64, word: u32) -> bool {
        if map.len != d::BYTES || self.expected_phys != Some(map.phys.raw()) {
            return false;
        }
        let base = GPU + map.phys.raw() - 0x90004000;
        if let Some(old) = self.base {
            assert_eq!(base, old);
        }
        self.base = Some(base);
        self.memory.resize((d::BYTES - Self::OMIT) as usize, 0x5a);
        if at == 0 {
            self.context_zeroes = 0;
        }
        if Self::index(at).is_none() {
            assert_eq!(word, 0);
            self.context_zeroes += 4;
        } else {
            self.store(at, word);
        }
        true
    }
    fn store(&mut self, at: u64, word: u32) {
        let i = Self::index(at).unwrap();
        self.memory[i..i + 4].copy_from_slice(&word.to_le_bytes());
    }
    fn bytes(&self, at: u64, len: usize) -> &[u8] {
        let i = Self::index(at).unwrap();
        &self.memory[i..i + len]
    }
    pub(super) fn ib(&mut self, address: u64, len: u32) -> bool {
        let base = self.base.unwrap();
        let phase =
            [d::Phase::Create, d::Phase::Decode, d::Phase::Destroy][(self.stages % 3) as usize];
        let ib = d::ib(base, phase).unwrap();
        assert_eq!(len as usize, ib.as_slice().len());
        for (i, &w) in ib.as_slice().iter().enumerate() {
            assert_eq!(self.word(address - base + i as u64 * 4), w);
        }
        let (msg, bytes) = match phase {
            d::Phase::Create => (d::CREATE_MSG, d::create_message().to_vec()),
            d::Phase::Decode => (
                d::DECODE_MSG,
                d::keyframe_message(picture()).unwrap().to_vec(),
            ),
            d::Phase::Destroy => (d::DESTROY_MSG, d::destroy_message().to_vec()),
        };
        assert_eq!(self.bytes(msg, bytes.len()), bytes.as_slice());
        assert_eq!(self.context_zeroes, Self::OMIT);
        if phase != d::Phase::Destroy {
            assert_eq!(self.bytes(d::CONTEXT, d::DEFAULT_CDF.len()), d::DEFAULT_CDF);
        }
        if phase == d::Phase::Decode {
            // Includes the actual Mesa tier3 reference package with num_bufs=0.
            assert_eq!(&ib.as_slice()[43..], &[16, 12, 8, 0]);
            assert_eq!(
                self.bytes(d::BITSTREAM, stream().len()),
                stream().as_slice()
            );
            assert!(self
                .bytes(d::TARGET, d::TARGET_BYTES as usize)
                .iter()
                .all(|b| *b == 0));
            if self.fault == 4 {
                return false;
            }
            if self.fault != 1 {
                for at in 0..d::TARGET_BYTES {
                    self.memory[Self::index(d::TARGET + at).unwrap()] =
                        d::expected(at).unwrap_or(0);
                }
            }
            match self.fault {
                2 => self.memory[Self::index(d::TARGET).unwrap()] += 5,
                8 => self.memory[Self::index(d::TARGET + 49152).unwrap()] += 5,
                9 | 10 => {
                    for at in 0..d::TARGET_BYTES {
                        if d::expected(at).is_some() {
                            self.memory[Self::index(d::TARGET + at).unwrap()] += 1;
                        }
                    }
                    if self.fault == 9 {
                        self.memory[Self::index(d::TARGET).unwrap()] += 1;
                    }
                }
                3 => self.store(d::TARGET_END_GUARD, 0),
                5 => self.memory[Self::index(d::BITSTREAM).unwrap()] ^= 1,
                6 => self.store(d::FEEDBACK + 24, 1),
                7 => self.store(d::DECODE_IB + 4092, 1),
                12 => self.memory[Self::index(d::TARGET + 320).unwrap()] = 1,
                11 => self.store(d::CONTEXT + 256, self.word(d::CONTEXT + 256) ^ 1),
                _ => {}
            }
        }
        self.stages += 1;
        true
    }
}
fn stream() -> Vec<u8> {
    let mut data = av1_encode_words::HEADERS.to_vec();
    data.extend_from_slice(STREAM);
    data
}
fn picture() -> d::Keyframe {
    let p = av1_encoded::inspect(STREAM).unwrap();
    d::Keyframe {
        bitstream_bytes: stream().len() as u32,
        tile_offset: p.tile_offset + av1_encode_words::HEADERS.len() as u32,
        tile_bytes: p.tile_bytes,
        base_q_idx: p.base_q_idx,
        quant_delta: p.quant_delta,
        filter_level: p.filter_level,
        sharpness: p.sharpness,
        mode_ref_delta_enabled: p.mode_ref_delta_enabled,
        mode_ref_delta_update: p.mode_ref_delta_update,
        ref_deltas: p.ref_deltas,
        mode_deltas: p.mode_deltas,
        tx_mode: p.tx_mode,
        reduced_tx_set: p.reduced_tx_set,
    }
}
