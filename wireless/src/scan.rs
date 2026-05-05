use alloc::vec::Vec;

pub struct ScanRequest {
    pub ssids: Vec<Vec<u8>>,
    pub channels: Vec<u32>,
    pub active: bool,
}

pub struct ScanResult {
    pub bss_list: Vec<BssInfo>,
}

pub struct BssInfo {
    pub bssid: [u8; 6],
    pub ssid: Vec<u8>,
    pub channel: u32,
    pub rssi: i8,
    pub security: BssSecurity,
}

#[derive(Debug, Clone, Copy)]
pub enum BssSecurity {
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
}
