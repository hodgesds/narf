use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WirelessError {
    NotSupported,
    Busy,
    Timeout,
    InvalidArgs,
    HardwareError,
    Denied,
}

pub struct WirelessIfaceInfo {
    pub base_name: String,
    pub base_mac: [u8; 6],
    pub bands: Vec<WirelessBand>,
    pub modes: WirelessModes,
    pub hw_caps: HwCaps,
}

pub struct WirelessBand {
    pub freq_mhz: u32,
    pub channels: Vec<u32>,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct WirelessModes: u32 {
        const STATION = 1 << 0;
        const AP      = 1 << 1;
        const MONITOR = 1 << 2;
        const P2P     = 1 << 3;
    }
}

pub struct HwCaps {
    pub ht_supported: bool,
    pub vht_supported: bool,
    pub he_supported: bool,
    pub eht_supported: bool,
}

/// Band-specific IEEE capability bodies, also used for nl80211 wiphy data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhyCapabilities {
    pub ht: [u8; 26],
    pub vht: Option<[u8; 12]>,
}

pub type WirelessIface = dyn crate::WirelessNetIface;

/// WMM queue identity, in firmware-independent BK/BE/VI/VO order.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AccessCategory {
    Background = 0,
    BestEffort = 1,
    Video = 2,
    Voice = 3,
}
impl AccessCategory {
    pub const ALL: [Self; 4] = [Self::Background, Self::BestEffort, Self::Video, Self::Voice];
}
