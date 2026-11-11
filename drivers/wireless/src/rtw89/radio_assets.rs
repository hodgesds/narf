// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Immutable A/B/C PHY tables retained from the same verified firmware container.
//!
//! RTL8852B keeps its static rtw8852b_table.c fallback. RTL8852C mirrors
//! `rtw8852c_chip_info.rf_table = {radiob, radioa}`: the firmware RADIO_A
//! element carries `reg2.idx` 1 and RADIO_B idx 0 (fw.c
//! `rtw89_build_phy_tbl_from_elm` stores by idx, writes by element path).
//! NARF carries no static rtw8852c_table.c copy, so a C container lacking
//! any of BB/GAIN/RADIO_A/RADIO_B/NCTL is refused rather than defaulted.
//! RTL8851B mirrors `rtw8851b_chip_info.rf_table = {radioa}` (one RF path):
//! the shipped `rtw8851b_fw-1.bin` carries BB, GAIN, RADIO_A idx 0 and NCTL;
//! a RADIO_B element is refused and, with no static rtw8851b_table.c copy, a
//! container missing any of the four is refused (`Error::Element`).
//!
//! RTL8852A mirrors `rtw8852a_chip_info` (`.bb_table`, `.rf_table =
//! {radioa, radiob}`, `.nctl_table`, `.dig_table`): the static
//! `rtw8852a_table.c` copy is the fallback for BB/RF_A/RF_B/NCTL, with the
//! idx == path slot order (RADIO_A idx 0, RADIO_B idx 1). Linux's
//! `.bb_gain_table` is NULL, so there is no static gain fallback: a
//! firmware GAIN element programs index 1 when present, and `bind` skips
//! it otherwise.
//!
//! RTL8922A mirrors `rtw8922a_chip_info.rf_table = {}` (and
//! `bb_table` / `bb_gain_table` / `nctl_table` / `dflt_parms` all NULL,
//! "load parm from fw"): the element-built tables are the only source.
//! fw.c `rtw89_build_phy_tbl_from_elm` stores a RADIO element at
//! `rf_radio[reg2.idx]` and phy.c `rtw89_phy_init_rf_reg` reads
//! `rf_radio[path]`, so the idx must equal the path — RADIO_A idx 0,
//! RADIO_B idx 1 (the B order, not the C `{radiob, radioa}` static
//! order). With no static rtw8922a_table.c copy, a container missing
//! any of the five tables is refused (`Error::Element`).
//!
//! Aid note (all chips): core.c assigns `hal.aid` from XTAL only for
//! BE; fw.c ignores an element whose nonzero aid differs from
//! `hal.aid`. NARF keeps only aid-0 elements and skips every other
//! element entirely — a documented narrowing, not a silent default:
//! a BE container whose PHY tables all carry a nonzero aid is refused
//! for missing tables rather than matched against an unknown aid.
use super::{
    mac::ChipId, prepared::PreparedFirmware, radio_table::Pair, radio_tables_a, radio_tables_b,
};
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
    chip: ChipId,
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
        if !matches!(
            image.chip(),
            ChipId::Rtl8852A
                | ChipId::Rtl8852B
                | ChipId::Rtl8852C
                | ChipId::Rtl8851B
                | ChipId::Rtl8922A
        ) {
            return Err(Error::Unsupported);
        }
        let mut result = Self::parse_for(image.chip(), image.container())?;
        result.firmware_version = image
            .image()
            .get(4..8)
            .ok_or(Error::Container)?
            .try_into()
            .map_err(|_| Error::Container)?;
        Ok(result)
    }
    #[cfg(any(test, feature = "kernel-test"))]
    fn parse(bytes: &[u8]) -> Result<Self, Error> {
        Self::parse_for(ChipId::Rtl8852B, bytes)
    }
    pub(super) fn parse_for(chip: ChipId, bytes: &[u8]) -> Result<Self, Error> {
        let c = chip == ChipId::Rtl8852C;
        let n51 = chip == ChipId::Rtl8851B;
        let be = chip == ChipId::Rtl8922A;
        // Chips without a static table fallback in NARF.
        let no_static = c || n51 || be;
        let mut digest = narf_crypto::sha256::Sha256::new();
        digest.update(bytes);
        let mut result = Self {
            chip,
            tables: core::array::from_fn(|_| None),
            elements: Vec::new(),
            container_digest: digest.finalize(),
            firmware_version: [0; 4],
        };
        // Legacy single-image firmware has no MFW element region. B retains
        // Linux's explicit static-table transition fallback for that format.
        if bytes.first() != Some(&255) {
            return if no_static {
                Err(Error::Element)
            } else {
                Ok(result)
            };
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
                    // Path slot = reg2.idx in Linux; B ships A at 0, C ships
                    // `{radiob, radioa}` so RADIO_A is slot 1 and RADIO_B 0.
                    // BE (8922A, empty static rf_table) takes the idx == path
                    // order: fw.c stores at rf_radio[idx] and phy.c reads
                    // rf_radio[path].
                    let (a, b) = if c { (1, 0) } else { (0, 1) };
                    if (id == 4 && idx != a)
                        || (id == 5 && (n51 || idx != b))
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
        if c && result.tables.iter().any(Option::is_none)
            || n51 && [0, 1, 2, 4].iter().any(|&i| result.tables[i].is_none())
            || be && result.tables.iter().any(Option::is_none)
        {
            return Err(Error::Element);
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
            if i == 3 && self.chip == ChipId::Rtl8851B {
                // One RF path: no RADIO_B program exists to bind.
                continue;
            }
            if i == 1 && self.chip == ChipId::Rtl8852A && self.table(1).is_none() {
                // No static A gain table and no firmware GAIN element:
                // nothing to bind for index 1.
                continue;
            }
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
    pub fn chip(&self) -> ChipId {
        self.chip
    }
    /// Index 0 BB, 1 BB gain, 2 RF path A, 3 RF path B, 4 NCTL. RTL8851B
    /// has no path B table (index 3 is `None`). RTL8852A has no static
    /// gain table (index 1 is `None` unless a firmware GAIN element is
    /// present). RTL8922A returns the firmware tables (no static fallback).
    pub fn table(&self, index: usize) -> Option<&[Pair]> {
        if matches!(
            self.chip,
            ChipId::Rtl8852C | ChipId::Rtl8851B | ChipId::Rtl8922A
        ) {
            return self.tables.get(index)?.as_deref();
        }
        if self.chip == ChipId::Rtl8852A && index == 1 {
            // Linux `rtw8852a_chip_info.bb_gain_table` is NULL: no static
            // gain table exists; only a firmware GAIN element programs it.
            return self.tables.get(1)?.as_deref();
        }
        let defaults = if self.chip == ChipId::Rtl8852A {
            [
                radio_tables_a::BB,
                &[][..],
                radio_tables_a::RF_A,
                radio_tables_a::RF_B,
                radio_tables_a::NCTL,
            ]
        } else {
            [
                radio_tables_b::BB,
                radio_tables_b::GAIN,
                radio_tables_b::RF_A,
                radio_tables_b::RF_B,
                radio_tables_b::NCTL,
            ]
        };
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
    fn smoke_rtw89_c_radio_assets_follow_linux_radiob_radioa_slots() -> TestResult {
        let pair = |a: u32| [a.to_le_bytes(), 0x12345u32.to_le_bytes()].concat();
        // The shipped rtw8852c_fw-{1,2}.bin layout: BB, GAIN, RADIO_A idx1,
        // RADIO_B idx0, NCTL; all aid 0.
        let full = |a_idx: u8, b_idx: u8, skip: Option<u32>| {
            let mut bytes = container();
            for (id, idx) in [(2, 0), (3, 0), (4, a_idx), (5, b_idx), (8, 0)] {
                if skip != Some(id) {
                    add(&mut bytes, id, 0, idx, &pair(0x100 + id));
                }
            }
            bytes
        };
        let Ok(assets) = Assets::parse_for(ChipId::Rtl8852C, &full(1, 0, None)) else {
            return TestResult::Fail("C RADIO_A idx1 / RADIO_B idx0 container refused");
        };
        for (index, id) in [(0, 2), (1, 3), (2, 4), (3, 5), (4, 8)] {
            if assets.table(index) != Some(&[Pair(0x100 + id, 0x12345)][..]) {
                return TestResult::Fail("C element did not land in its Linux path table");
            }
        }
        if assets.chip() != ChipId::Rtl8852C {
            return TestResult::Fail("C assets lost their chip");
        }
        // B slot order on a C container, and any missing table, are refused:
        // no static rtw8852c_table.c fallback is fabricated.
        if Assets::parse_for(ChipId::Rtl8852C, &full(0, 1, None)).is_ok() {
            return TestResult::Fail("C accepted the B radio slot order");
        }
        for id in [2, 3, 4, 5, 8] {
            if Assets::parse_for(ChipId::Rtl8852C, &full(1, 0, Some(id))).is_ok() {
                return TestResult::Fail("C container with a missing PHY table was defaulted");
            }
        }
        if Assets::parse_for(ChipId::Rtl8852C, &[0u8; 64]).is_ok() {
            return TestResult::Fail("legacy C image without elements produced PHY tables");
        }
        // B on the same C layout keeps refusing it, byte-identically to before.
        if Assets::parse(&full(1, 0, None)).is_ok() {
            return TestResult::Fail("B accepted the C radio slot order");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_c_radio_assets_follow_linux_radiob_radioa_slots
    );
    fn smoke_rtw89_n51_radio_assets_follow_linux_single_radioa_slot() -> TestResult {
        let pair = |a: u32| [a.to_le_bytes(), 0x12345u32.to_le_bytes()].concat();
        // The shipped rtw8851b_fw-1.bin layout: BB, GAIN, RADIO_A idx0, NCTL
        // (aid 0), followed by power/tracking elements kept verbatim.
        let full = |a_idx: u8, extra_b: bool, skip: Option<u32>| {
            let mut bytes = container();
            for (id, idx) in [(2, 0), (3, 0), (4, a_idx), (8, 0)] {
                if skip != Some(id) {
                    add(&mut bytes, id, 0, idx, &pair(0x100 + id));
                }
            }
            if extra_b {
                add(&mut bytes, 5, 0, 0, &pair(0x105));
            }
            add(&mut bytes, 18, 0, 255, &[1, 2, 3, 4, 5, 6, 7, 8]);
            bytes
        };
        let Ok(assets) = Assets::parse_for(ChipId::Rtl8851B, &full(0, false, None)) else {
            return TestResult::Fail("8851B BB/GAIN/RADIO_A idx0/NCTL container refused");
        };
        for (index, id) in [(0, 2), (1, 3), (2, 4), (4, 8)] {
            if assets.table(index) != Some(&[Pair(0x100 + id, 0x12345)][..]) {
                return TestResult::Fail("8851B element did not land in its Linux table");
            }
        }
        if assets.table(3).is_some()
            || assets.chip() != ChipId::Rtl8851B
            || assets.elements().len() != 1
            || assets.elements()[0].id != 18
        {
            return TestResult::Fail("8851B grew a path-B table or lost its retained elements");
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        if assets.bind(&mut hash, 1, 0).is_err() {
            return TestResult::Fail("8851B one-path table set did not bind");
        }
        if Assets::parse_for(ChipId::Rtl8851B, &full(1, false, None)).is_ok()
            || Assets::parse_for(ChipId::Rtl8851B, &full(0, true, None)).is_ok()
        {
            return TestResult::Fail("8851B accepted a second RF path slot");
        }
        for id in [2, 3, 4, 8] {
            if Assets::parse_for(ChipId::Rtl8851B, &full(0, false, Some(id))).is_ok() {
                return TestResult::Fail("8851B container with a missing PHY table was defaulted");
            }
        }
        if Assets::parse_for(ChipId::Rtl8851B, &[0u8; 64]).is_ok() {
            return TestResult::Fail("legacy 8851B image without elements produced PHY tables");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_n51_radio_assets_follow_linux_single_radioa_slot
    );
    fn smoke_rtw89_be_radio_assets_follow_linux_empty_rf_table() -> TestResult {
        let pair = |a: u32| [a.to_le_bytes(), 0x12345u32.to_le_bytes()].concat();
        // The 8922A layout: BB, GAIN, RADIO_A idx0, RADIO_B idx1, NCTL;
        // all aid 0 (rtw8922a_chip_info.rf_table = {}: the element idx
        // must equal the path, fw.c rf_radio[idx] / phy.c rf_radio[path]).
        let full = |a_idx: u8, b_idx: u8, skip: Option<u32>| {
            let mut bytes = container();
            for (id, idx) in [(2, 0), (3, 0), (4, a_idx), (5, b_idx), (8, 0)] {
                if skip != Some(id) {
                    add(&mut bytes, id, 0, idx, &pair(0x100 + id));
                }
            }
            add(&mut bytes, 9, 0, 0, &[1, 2, 3, 4, 5, 6, 7, 8]);
            bytes
        };
        let Ok(assets) = Assets::parse_for(ChipId::Rtl8922A, &full(0, 1, None)) else {
            return TestResult::Fail("8922A BB/GAIN/RADIO_A idx0/RADIO_B idx1/NCTL refused");
        };
        for (index, id) in [(0, 2), (1, 3), (2, 4), (3, 5), (4, 8)] {
            if assets.table(index) != Some(&[Pair(0x100 + id, 0x12345)][..]) {
                return TestResult::Fail("8922A element did not land in its Linux path table");
            }
        }
        if assets.chip() != ChipId::Rtl8922A
            || assets.elements().len() != 1
            || assets.elements()[0].id != 9
        {
            return TestResult::Fail("8922A lost its chip or its retained TXPWR element");
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        if assets.bind(&mut hash, 1, 0).is_err() {
            return TestResult::Fail("8922A five-table set did not bind");
        }
        // The C `{radiob, radioa}` slot order, and any missing table,
        // are refused: no static rtw8922a_table.c fallback is fabricated.
        if Assets::parse_for(ChipId::Rtl8922A, &full(1, 0, None)).is_ok() {
            return TestResult::Fail("8922A accepted the C radio slot order");
        }
        for id in [2, 3, 4, 5, 8] {
            if Assets::parse_for(ChipId::Rtl8922A, &full(0, 1, Some(id))).is_ok() {
                return TestResult::Fail("8922A container with a missing PHY table was defaulted");
            }
        }
        if Assets::parse_for(ChipId::Rtl8922A, &[0u8; 64]).is_ok() {
            return TestResult::Fail("legacy 8922A image without elements produced PHY tables");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_be_radio_assets_follow_linux_empty_rf_table
    );
    fn smoke_rtw89_a_radio_assets_follow_linux_static_tables_and_optional_gain() -> TestResult {
        let pair = |a: u32| [a.to_le_bytes(), 0x12345u32.to_le_bytes()].concat();
        // Legacy single-image firmware: the static rtw8852a_table.c copy
        // is the fallback for BB/RF_A/RF_B/NCTL; there is no static gain
        // table (`rtw8852a_chip_info.bb_gain_table` is NULL).
        let Ok(assets) = Assets::parse_for(ChipId::Rtl8852A, &[0u8; 64]) else {
            return TestResult::Fail("legacy RTL8852A image refused");
        };
        if assets.table(0) != Some(radio_tables_a::BB)
            || assets.table(1).is_some()
            || assets.table(2) != Some(radio_tables_a::RF_A)
            || assets.table(3) != Some(radio_tables_a::RF_B)
            || assets.table(4) != Some(radio_tables_a::NCTL)
            || assets.chip() != ChipId::Rtl8852A
        {
            return TestResult::Fail("RTL8852A static table fallback differs");
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        if assets.bind(&mut hash, 1, 1).is_err() {
            return TestResult::Fail("RTL8852A static table set did not bind without gain");
        }
        // A firmware GAIN element programs index 1 and binds with it.
        let mut bytes = container();
        add(&mut bytes, 3, 0, 0, &pair(0x103));
        let Ok(assets) = Assets::parse_for(ChipId::Rtl8852A, &bytes) else {
            return TestResult::Fail("RTL8852A firmware GAIN container refused");
        };
        if assets.table(1) != Some(&[Pair(0x103, 0x12345)][..])
            || assets.table(0) != Some(radio_tables_a::BB)
        {
            return TestResult::Fail("RTL8852A firmware GAIN did not land in index 1");
        }
        let mut hash = narf_crypto::sha256::Sha256::new();
        if assets.bind(&mut hash, 1, 1).is_err() {
            return TestResult::Fail("RTL8852A table set with firmware gain did not bind");
        }
        // The C `{radiob, radioa}` slot order is refused for A; a
        // firmware RADIO_B at idx 1 is accepted as an override.
        let mut bytes = container();
        add(&mut bytes, 4, 0, 1, &pair(0x104));
        if Assets::parse_for(ChipId::Rtl8852A, &bytes).is_ok() {
            return TestResult::Fail("RTL8852A accepted the C radio slot order");
        }
        let mut bytes = container();
        add(&mut bytes, 5, 0, 1, &pair(0x105));
        let Ok(assets) = Assets::parse_for(ChipId::Rtl8852A, &bytes) else {
            return TestResult::Fail("RTL8852A firmware RADIO_B idx1 container refused");
        };
        if assets.table(3) != Some(&[Pair(0x105, 0x12345)][..]) {
            return TestResult::Fail("RTL8852A firmware RADIO_B did not land in index 3");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw89_a_radio_assets_follow_linux_static_tables_and_optional_gain
    );
}
