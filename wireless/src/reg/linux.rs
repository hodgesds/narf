//! Linux wireless-regdb v20 (`net/wireless/reg.c` fwdb_*).
//! Authentication belongs to the firmware build: these parsers never confer it.
use super::{RegFlags, RegRule, RegulatoryDomain, WmmRule};
use alloc::vec::Vec;

fn bytes(data: &[u8], at: usize, len: usize) -> Result<&[u8], &'static str> {
    data.get(at..at.checked_add(len).ok_or("regdb offset overflow")?)
        .ok_or("truncated regulatory database")
}
fn be16(data: &[u8], at: usize) -> Result<u16, &'static str> {
    Ok(u16::from_be_bytes(bytes(data, at, 2)?.try_into().unwrap()))
}
fn be32(data: &[u8], at: usize) -> Result<u32, &'static str> {
    Ok(u32::from_be_bytes(bytes(data, at, 4)?.try_into().unwrap()))
}
pub(crate) fn valid_alpha2(alpha2: [u8; 2]) -> bool {
    alpha2 == *b"00" || alpha2.iter().all(u8::is_ascii_uppercase)
}

fn collection(data: &[u8], alpha2: [u8; 2]) -> Result<usize, &'static str> {
    if !valid_alpha2(alpha2) || be32(data, 0)? != 0x5247_4442 || be32(data, 4)? != 20 {
        return Err("invalid regulatory database header or country");
    }
    let mut selected = None;
    let mut previous = None;
    let mut first_collection = data.len();
    // Country entries are 4-byte records followed by a zero terminator.
    // Bound the walk independently of a trusted but unexpectedly large file.
    for index in 0..1024 {
        let at = 8 + index * 4;
        let entry = bytes(data, at, 4)?;
        let ptr = usize::from(be16(entry, 2)?) * 4;
        if ptr == 0 {
            if entry != [0; 4] || at + 4 > first_collection {
                return Err("invalid regulatory country table");
            }
            return selected.ok_or("regulatory country not found");
        }
        let country: [u8; 2] = entry[..2].try_into().unwrap();
        if !valid_alpha2(country) || previous.is_some_and(|old| old >= country) {
            return Err("invalid regulatory country ordering");
        }
        bytes(data, ptr, 3)?;
        first_collection = first_collection.min(ptr);
        previous = Some(country);
        if country == alpha2 {
            selected = Some(ptr);
        }
    }
    Err("regulatory country table too large")
}

fn etsi_wmm(data: &[u8], at: usize) -> Result<bool, &'static str> {
    let encoded = bytes(data, at, 32)?;
    let expected = WmmRule::ETSI;
    for (raw, rule) in encoded
        .chunks_exact(4)
        .zip(expected.client.iter().chain(expected.ap.iter()))
    {
        let min = (1u16 << (raw[0] >> 4)) - 1;
        let max = (1u16 << (raw[0] & 15)) - 1;
        if min >= max || raw[1] == 0 {
            return Err("invalid regulatory WMM rule");
        }
        if min != rule.cw_min
            || max != rule.cw_max
            || raw[1] != rule.aifsn
            || u32::from(be16(raw, 2)?) * 1000 != u32::from(rule.cot_us)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Decode one country, conservatively projecting kHz/mBm onto the existing
/// MHz/dBm driver interface. NO_OFDM rules are unavailable until drivers can
/// enforce that modulation restriction; they never become unrestricted rules.
pub(crate) fn country(
    data: &[u8],
    alpha2: [u8; 2],
) -> Result<(RegulatoryDomain, u8), &'static str> {
    let coll = collection(data, alpha2)?;
    let header = bytes(data, coll, 3)?;
    let count = usize::from(header[1]);
    if header[0] != 3 || count == 0 || count > 64 || header[2] > 3 {
        return Err("unsupported regulatory collection");
    }
    let pointers = bytes(data, coll + 4, count * 2)?;
    let mut rules = Vec::new();
    for pointer in pointers.chunks_exact(2) {
        let at = usize::from(be16(pointer, 0)?) * 4;
        let len = usize::from(bytes(data, at, 1)?[0]);
        if !matches!(len, 16 | 18 | 20) {
            return Err("unsupported regulatory rule extension");
        }
        let raw = bytes(data, at, len)?;
        let flags = raw[1];
        if flags & !0x1f != 0 {
            return Err("unknown regulatory rule flags");
        }
        if len >= 18 && be16(raw, 16)? != 0 {
            return Err("unsupported regulatory CAC timeout");
        }
        let mut mapped = RegFlags::empty();
        if flags & 2 != 0 {
            mapped |= RegFlags::INDOOR_ONLY;
        }
        if flags & 4 != 0 {
            mapped |= RegFlags::DFS;
        }
        if flags & 8 != 0 {
            mapped |= RegFlags::NO_IR;
        }
        if flags & 16 != 0 {
            mapped |= RegFlags::AUTO_BW;
        }
        if len == 20 {
            if !etsi_wmm(data, usize::from(be16(raw, 18)?) * 4)? {
                return Err("unsupported regulatory WMM parameters");
            }
            mapped |= RegFlags::WMM_ETSI;
        }
        let start_khz = be32(raw, 4)?;
        let end_khz = be32(raw, 8)?;
        let bandwidth_khz = be32(raw, 12)?;
        if start_khz >= end_khz || bandwidth_khz == 0 {
            return Err("invalid regulatory frequency range");
        }
        let start = start_khz.div_ceil(1000);
        let end = end_khz / 1000;
        let bandwidth = bandwidth_khz / 1000;
        let power =
            i8::try_from(be16(raw, 2)? / 100).map_err(|_| "unsupported regulatory power range")?;
        if start >= end || bandwidth == 0 {
            return Err("unrepresentable regulatory frequency range");
        }
        if flags & 1 != 0 {
            continue;
        }
        rules.push(RegRule {
            freq_start_mhz: start,
            freq_end_mhz: end,
            max_bandwidth_mhz: bandwidth,
            max_power_dbm: power,
            flags: mapped,
        });
    }
    if rules.is_empty() {
        return Err("no supported regulatory rules");
    }
    Ok((
        RegulatoryDomain {
            country_code: alpha2,
            rules,
        },
        header[2],
    ))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "linux_tests.rs"]
mod tests;
