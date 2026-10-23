// SPDX-License-Identifier: ISC
// Copyright (c) 2015-2016 Qualcomm Atheros, Inc.
//! Owned firmware code-swap segment; Linux ath10k/swap.{c,h}.

use super::{
    bmi::BmiError,
    dma::{barrier, Memory},
};
use alloc::vec::Vec;
use core::ops::Range;

pub(super) struct Layout {
    pub size: usize,
    pub target: u32,
    regions: Vec<Range<usize>>,
    payload: usize,
}

fn word(bytes: &[u8], offset: usize) -> Result<u32, BmiError> {
    let bytes = bytes.get(offset..offset + 4).ok_or(BmiError::BadResponse)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

impl Layout {
    pub fn parse(bytes: &[u8]) -> Result<Self, BmiError> {
        if bytes.is_empty() || bytes.len() > 512 * 1024 {
            return Err(BmiError::BadResponse);
        }
        let mut regions = Vec::new();
        let mut at = 0usize;
        let mut payload = 0usize;
        let target = loop {
            let length = word(bytes, at + 4)? as usize;
            if length == 0 {
                if bytes.len() - at != 16 || bytes[at..at + 12] != [0; 12] {
                    return Err(BmiError::BadResponse);
                }
                let target = word(bytes, at + 12)?;
                if target == 0 || target == u32::MAX || target & 3 != 0 || payload == 0 {
                    return Err(BmiError::BadResponse);
                }
                break target;
            }
            let start = at.checked_add(8).ok_or(BmiError::AddressOverflow)?;
            let end = start.checked_add(length).ok_or(BmiError::AddressOverflow)?;
            if end > bytes.len() {
                return Err(BmiError::BadResponse);
            }
            regions.push(start..end);
            payload += length;
            at = end;
        };
        Ok(Self {
            size: bytes.len().next_multiple_of(2),
            target,
            regions,
            payload,
        })
    }

    /// Fill a retained coherent allocation before advertising its DMA address.
    pub fn fill(&self, bytes: &[u8], memory: &mut impl Memory) -> Result<[u8; 208], BmiError> {
        let end = memory
            .dma_address()
            .checked_add(self.size as u64)
            .ok_or(BmiError::AddressOverflow)?;
        if memory.len() < self.size || end > 1u64 << 32 || memory.dma_address() & 3 != 0 {
            return Err(BmiError::BadResponse);
        }
        for offset in 0..self.size {
            memory.write(offset, 0);
        }
        let mut offset = 0;
        for region in &self.regions {
            let data = bytes.get(region.clone()).ok_or(BmiError::BadResponse)?;
            for &byte in data {
                memory.write(offset, byte);
                offset += 1;
            }
        }
        barrier();
        let mut info = [0; 208];
        for (at, value) in [
            (0, self.payload as u32),
            (4, 1),
            (8, self.size as u32),
            (12, self.size.ilog2()),
            (16, memory.dma_address() as u32),
        ] {
            info[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        Ok(info)
    }
}
