// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Immutable B PHY overrides retained from the same verified firmware container.
use super::{mac::ChipId, prepared::PreparedFirmware, radio_table::Pair, radio_tables_b};
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Container,
    Element,
    Memory,
    Unsupported,
}
#[derive(Debug)]
pub(super) struct Element {
    pub id: u32,
    pub version: [u8; 4],
    pub bytes: Vec<u8>,
}
#[derive(Debug)]
pub(super) struct Assets {
    tables: [Option<Vec<Pair>>; 5],
    elements: Vec<Element>,
    container_digest: [u8; 32],
    firmware_version: [u8; 4],
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, Error> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(Error::Container)?
            .try_into()
            .map_err(|_| Error::Container)?,
    ))
}
fn copy(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())
        .map_err(|_| Error::Memory)?;
    out.extend_from_slice(bytes);
    Ok(out)
}
impl Assets {
    pub fn from_prepared(image: &PreparedFirmware) -> Result<Self, Error> {
        if image.chip() != ChipId::Rtl8852B {
            return Err(Error::Unsupported);
        }
        let mut result = Self::parse(image.container())?;
        result.firmware_version = image
            .image()
            .get(4..8)
            .ok_or(Error::Container)?
            .try_into()
            .map_err(|_| Error::Container)?;
        Ok(result)
    }
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(bytes);
        let mut result = Self {
            tables: core::array::from_fn(|_| None),
            elements: Vec::new(),
            container_digest: digest.finalize(),
            firmware_version: [0; 4],
        };
        // Legacy single-image firmware has no MFW element region. B retains
        // Linux's explicit static-table transition fallback for that format.
        if bytes.first() != Some(&255) {
            return Ok(result);
        }
        let count = usize::from(*bytes.get(1).ok_or(Error::Container)?);
        if count == 0 || 16 + count * 16 > bytes.len() {
            return Err(Error::Container);
        }
        let mut end = 16 + count * 16;
        for index in 0..count {
            let entry = 16 + index * 16;
            let offset = u32_at(bytes, entry + 4)? as usize;
            let length = u32_at(bytes, entry + 8)? as usize;
            if length == 0 || offset < end {
                return Err(Error::Container);
            }
            end = offset
                .checked_add(length)
                .filter(|&v| v <= bytes.len())
                .ok_or(Error::Container)?;
        }
        let mut cursor = end.checked_add(15).ok_or(Error::Container)? & !15;
        while cursor < bytes.len() {
            if bytes.len() - cursor < 32 {
                // Only the trailing alignment padding is outside a header.
                if bytes.len() - cursor > 15 || bytes[cursor..].iter().any(|&v| v != 0) {
                    return Err(Error::Element);
                }
                break;
            }
            let id = u32_at(bytes, cursor)?;
            let size = u32_at(bytes, cursor + 4)? as usize;
            let body = cursor.checked_add(32).ok_or(Error::Element)?;
            let next = body
                .checked_add(size)
                .filter(|&v| v <= bytes.len())
                .ok_or(Error::Element)?;
            let aid = u16::from_le_bytes(bytes[cursor + 12..cursor + 14].try_into().unwrap());
            // core.c assigns hal.aid from XTAL only for BE; B uses the AX
            // layout's aid0. This is chip semantics, never an invented board ID.
            if aid == 0 {
                if let Some(index) = match id {
                    2 => Some(0),
                    3 => Some(1),
                    4 => Some(2),
                    5 => Some(3),
                    8 => Some(4),
                    _ => None,
                } {
                    let idx = bytes[cursor + 24];
                    if (id == 4 && idx != 0)
                        || (id == 5 && idx != 1)
                        || size == 0
                        || size % 8 != 0
                        || size / 8 > 65536
                    {
                        return Err(Error::Element);
                    }
                    if result.tables[index].is_none() {
                        let mut pairs = Vec::new();
                        pairs
                            .try_reserve_exact(size / 8)
                            .map_err(|_| Error::Memory)?;
                        for pair in bytes[body..next].chunks_exact(8) {
                            pairs.push(Pair(u32_at(pair, 0)?, u32_at(pair, 4)?));
                        }
                        result.tables[index] = Some(pairs);
                    }
                } else {
                    // Keep actual power/tracking/regulatory/other data until
                    // its typed consumer validates layout and real RFE policy.
                    result.elements.try_reserve(1).map_err(|_| Error::Memory)?;
                    result.elements.push(Element {
                        id,
                        version: bytes[cursor + 8..cursor + 12].try_into().unwrap(),
                        bytes: copy(&bytes[cursor + 24..next])?,
                    });
                }
            }
            cursor = next.checked_add(15).ok_or(Error::Element)? & !15;
        }
        Ok(result)
    }
    pub fn firmware_version(&self) -> [u8; 4] {
        self.firmware_version
    }
    /// Bind the actual signed container and corrected-cut/RFE table selection,
    /// including static fallback. A different embedded table cannot reuse a
    /// measured board recipe even when its firmware code image is identical.
    pub fn bind(
        &self,
        hash: &mut narf_crypto::sha256::Sha256,
        rfe: u8,
        cut: u8,
    ) -> Result<(), Error> {
        hash.update(&self.container_digest);
        hash.update(&self.firmware_version);
        for i in 0..5 {
            let program =
                super::radio_table::program(self.table(i).ok_or(Error::Element)?, rfe, cut)
                    .map_err(|_| Error::Element)?;
            hash.update(&(program.len() as u32).to_le_bytes());
            for Pair(address, value) in program {
                hash.update(&address.to_le_bytes());
                hash.update(&value.to_le_bytes());
            }
        }
        Ok(())
    }
    pub fn table(&self, index: usize) -> Option<&[Pair]> {
        let defaults = [
            radio_tables_b::BB,
            radio_tables_b::GAIN,
            radio_tables_b::RF_A,
            radio_tables_b::RF_B,
            radio_tables_b::NCTL,
        ];
        Some(
            self.tables
                .get(index)?
                .as_deref()
                .unwrap_or(defaults[index]),
        )
    }
    pub fn elements(&self) -> &[Element] {
        &self.elements
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    include!("radio_assets/golden.rs");
    fn container() -> Vec<u8> {
        let mut bytes = vec![0; MFW + INFO + 16];
        bytes[0] = 255;
        bytes[1] = 1;
        bytes[MFW + 4..MFW + 8].copy_from_slice(&((MFW + INFO) as u32).to_le_bytes());
        bytes[MFW + 8..MFW + 12].copy_from_slice(&16u32.to_le_bytes());
        bytes
    }
    fn add(bytes: &mut Vec<u8>, id: u32, aid: u16, idx: u8, payload: &[u8]) {
        let start = bytes.len();
        bytes.resize(start + HEADER, 0);
        bytes[start..start + 4].copy_from_slice(&id.to_le_bytes());
        bytes[start + SIZE..start + SIZE + 4]
            .copy_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes[start + AID..start + AID + 2].copy_from_slice(&aid.to_le_bytes());
        bytes[start + INDEX] = idx;
        bytes.extend_from_slice(payload);
        bytes.resize(bytes.len().div_ceil(16) * 16, 0);
    }
    fn smoke_rtw89_b_radio_assets_retain_exact_firmware_overrides() -> TestResult {
        let pair = [0x55u32.to_le_bytes(), 0x12345u32.to_le_bytes()].concat();
        let mut bytes = container();
        add(&mut bytes, 2, 7, 0, &pair);
        add(&mut bytes, 2, 0, 0, &pair);
        add(&mut bytes, 2, 0, 0, &[0x5a; 8]);
        add(&mut bytes, 5, 0, 1, &pair);
        add(&mut bytes, 9, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8]);
        let assets = Assets::parse(&bytes).unwrap();
        if assets.table(0) != Some(&[Pair(0x55, 0x12345)][..])
            || assets.table(3) != Some(&[Pair(0x55, 0x12345)][..])
            || assets.table(2) != Some(radio_tables_b::RF_A)
            || assets.elements().len() != 1
            || assets.elements()[0].bytes[POWER - INDEX..] != [1, 2, 3, 4, 5, 6, 7, 8]
        {
            return TestResult::Fail(
                "radio assets did not preserve first aid-matched PHY override and real power bytes",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_b_radio_assets_retain_exact_firmware_overrides
    );
    fn smoke_rtw89_b_radio_assets_reject_partial_or_misdirected_elements() -> TestResult {
        for (id, idx, payload) in [
            (4, 1, &[0u8; 8][..]),
            (5, 0, &[0u8; 8][..]),
            (2, 0, &[0u8; 7][..]),
            (2, 0, &[][..]),
        ] {
            let mut bytes = container();
            add(&mut bytes, id, 0, idx, payload);
            if Assets::parse(&bytes).is_ok() {
                return TestResult::Fail("invalid PHY element geometry/path accepted");
            }
        }
        let mut bytes = container();
        add(&mut bytes, 2, 0, 0, &[0u8; 8]);
        for end in MFW + INFO + 17..MFW + INFO + 16 + REGS + 8 {
            if Assets::parse(&bytes[..end]).is_ok() {
                return TestResult::Fail("truncated firmware element accepted");
            }
        }
        bytes[20..24].copy_from_slice(&16u32.to_le_bytes());
        if Assets::parse(&bytes).is_ok() {
            return TestResult::Fail("MFW table overlap became a PHY asset region");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_b_radio_assets_reject_partial_or_misdirected_elements
    );
}
