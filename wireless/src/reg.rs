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
