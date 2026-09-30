use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

#[derive(Clone)]
pub struct RegulatoryDomain {
    pub country_code: [u8; 2],
    pub rules: Vec<RegRule>,
}

#[derive(Clone)]
pub struct RegRule {
    pub freq_start_mhz: u32,
    pub freq_end_mhz: u32,
    pub max_bandwidth_mhz: u32,
    pub max_power_dbm: i8,
    pub flags: RegFlags,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RegFlags: u32 {
        const DFS        = 1 << 0;
        const INDOOR_ONLY = 1 << 1;
        const NO_P2P     = 1 << 2;
    }
}

/// Decode a deployment-selected regulatory policy. Callers must authenticate
/// the enclosing blob before installing it; parsing does not establish trust.
/// NRGD v1: magic[4], version:u16, country[2], count:u16, reserved:u16,
/// followed by 16-byte rules (start/end/bandwidth:u32, power:i8,
/// flags:u8, reserved:u16), all integers little-endian.
pub fn parse_policy(bytes: &[u8]) -> Result<RegulatoryDomain, &'static str> {
    if bytes.len() < 12
        || &bytes[..4] != b"NRGD"
        || bytes[4..6] != [1, 0]
        || bytes[10..12] != [0; 2]
        || !bytes[6..8].iter().all(u8::is_ascii_uppercase)
    {
        return Err("invalid regulatory policy header");
    }
    let count = u16::from_le_bytes(bytes[8..10].try_into().unwrap()) as usize;
    if count == 0 || count > 64 || bytes.len() != 12 + count * 16 {
        return Err("invalid regulatory rule count");
    }
    let mut rules = Vec::new();
    for raw in bytes[12..].chunks_exact(16) {
        let start = u32::from_le_bytes(raw[..4].try_into().unwrap());
        let end = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let bandwidth = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        let flags = RegFlags::from_bits(u32::from(raw[13])).ok_or("unknown regulatory flags")?;
        if start < 2000
            || end > 71000
            || end <= start
            || bandwidth == 0
            || bandwidth > end - start
            || raw[14..] != [0; 2]
        {
            return Err("invalid regulatory rule");
        }
        rules.push(RegRule {
            freq_start_mhz: start,
            freq_end_mhz: end,
            max_bandwidth_mhz: bandwidth,
            max_power_dbm: raw[12] as i8,
            flags,
        });
    }
    Ok(RegulatoryDomain {
        country_code: bytes[6..8].try_into().unwrap(),
        rules,
    })
}

pub mod db {
    use super::*;

    static ACTIVE_DOMAIN: IrqSafeSpinLock<Option<RegulatoryDomain>> = IrqSafeSpinLock::new(None);

    pub fn set_domain(domain: RegulatoryDomain) {
        *ACTIVE_DOMAIN.lock() = Some(domain);
    }

    pub fn get_domain() -> Option<RegulatoryDomain> {
        ACTIVE_DOMAIN.lock().as_ref().map(|d| RegulatoryDomain {
            country_code: d.country_code,
            rules: d.rules.clone(),
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn smoke_regulatory_policy_boundaries() -> TestResult {
        let mut bytes = alloc::vec![0;28];
        bytes[..4].copy_from_slice(b"NRGD");
        bytes[4] = 1;
        bytes[6..8].copy_from_slice(b"US");
        bytes[8] = 1;
        bytes[12..16].copy_from_slice(&2402u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&2472u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&20u32.to_le_bytes());
        bytes[24] = 17;
        let domain = parse_policy(&bytes).unwrap();
        if domain.country_code != *b"US" || domain.rules[0].max_power_dbm != 17 {
            return TestResult::Fail("regulatory policy decode");
        }
        bytes[25] = 0x80;
        if parse_policy(&bytes).is_ok() {
            return TestResult::Fail("unknown rule flags accepted");
        }
        bytes[25] = 0;
        bytes.pop();
        if parse_policy(&bytes).is_ok() {
            return TestResult::Fail("truncated rule accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("wireless/regulatory", smoke_regulatory_policy_boundaries);
}
