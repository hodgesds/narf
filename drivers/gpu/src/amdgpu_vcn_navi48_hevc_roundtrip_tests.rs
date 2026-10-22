// SPDX-License-Identifier: MIT
use super::*;
use hevc_roundtrip_words as d;
const STREAM: &[u8] = include_bytes!("../fixtures/vcn5/hevc_encode/reference.hevc");

// Synthetic DMA writes exercise completion/ownership; this is not an HEVC decoder.
#[derive(Default)]
pub(super) struct Model {
    base: Option<u64>,
    memory: Vec<u8>,
    pub(super) stages: u8,
    pub(super) fault: u8,
}
impl Model {
    pub(super) fn contains(&self, at: u64) -> bool {
        self.base
            .is_some_and(|base| (base..base + d::BYTES).contains(&at))
    }
    pub(super) fn read(&self, map: MmioRegion, at: u64) -> Option<u32> {
        (map.len == d::BYTES).then(|| self.word(at))
    }
    fn word(&self, at: u64) -> u32 {
        u32::from_le_bytes(
            self.memory[at as usize..at as usize + 4]
                .try_into()
                .unwrap(),
        )
    }
    pub(super) fn write(&mut self, map: MmioRegion, at: u64, word: u32) -> bool {
        if map.len != d::BYTES {
            return false;
        }
        let base = GPU + map.phys.raw() - 0x90004000;
        if let Some(old) = self.base {
            assert_eq!(base, old);
        }
        self.base = Some(base);
        self.memory.resize(d::BYTES as usize, 0x5a);
        self.store(at, word);
        true
    }
    fn store(&mut self, at: u64, word: u32) {
        self.memory[at as usize..at as usize + 4].copy_from_slice(&word.to_le_bytes());
    }
    pub(super) fn ib(&mut self, address: u64, len: u32) -> bool {
        let base = self.base.unwrap();
        assert_eq!(len, 43);
        let phase =
            [d::Phase::Create, d::Phase::Decode, d::Phase::Destroy][(self.stages % 3) as usize];
        let expected = d::ib(base, phase).unwrap();
        for (i, w) in expected.into_iter().enumerate() {
            assert_eq!(self.word(address - base + i as u64 * 4), w);
        }
        let (msg, bytes) = match phase {
            d::Phase::Create => (d::CREATE_MSG, d::create_message().to_vec()),
            d::Phase::Decode => (
                d::DECODE_MSG,
                d::decode_message(STREAM.len() as u32).unwrap().to_vec(),
            ),
            d::Phase::Destroy => (d::DESTROY_MSG, d::destroy_message().to_vec()),
        };
        assert_eq!(
            &self.memory[msg as usize..msg as usize + bytes.len()],
            bytes.as_slice()
        );
        if phase == d::Phase::Decode {
            assert_eq!(
                &self.memory[d::BITSTREAM as usize..d::BITSTREAM as usize + STREAM.len()],
                STREAM
            );
            assert!(
                self.memory[d::TARGET as usize..d::TARGET_END_GUARD as usize]
                    .iter()
                    .all(|b| *b == 0)
            );
            if self.fault == 4 {
                return false;
            }
            if self.fault != 1 {
                for at in 0..d::TARGET_BYTES {
                    self.memory[(d::TARGET + at) as usize] = d::expected(at);
                }
            }
            match self.fault {
                // Balanced corruption defeats the old AVC-style additive checksum.
                2 => {
                    self.memory[d::TARGET as usize] += 5;
                    self.memory[d::TARGET as usize + 1] -= 5;
                }
                3 => self.store(d::TARGET_END_GUARD, 0),
                5 => self.memory[d::BITSTREAM as usize] ^= 1,
                6 => self.store(d::FEEDBACK + 24, 1),
                7 => self.store(d::DECODE_IB + 4092, 1),
                8 | 10 => {
                    for at in 0..d::TARGET_BYTES {
                        self.memory[(d::TARGET + at) as usize] +=
                            if self.fault == 8 { 2 } else { 1 };
                    }
                }
                9 => self.memory[(d::TARGET + d::WIDTH * d::HEIGHT) as usize] += 5,
                _ => {}
            }
        }
        self.stages += 1;
        true
    }
}
