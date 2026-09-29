//! MLD firmware commands used for a single legacy-rate station link.
//! Layouts: Linux iwlwifi fw/api/{mac-cfg,phy-ctxt,nvm-reg}.h.

use super::boot_context::{put16, put32};
use alloc::vec::Vec;

const CHANNELS: [u8; 51] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80,
    84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161,
    165, 169, 173, 177, 181,
];

pub fn channel_index(channel: u8) -> Option<usize> {
    CHANNELS.iter().position(|&ch| ch == channel)
}

#[derive(Debug)]
pub struct Nvm {
    pub tx_chains: u32,
    pub rx_chains: u32,
    pub channels: Vec<u8>,
}

impl Nvm {
    /// Versions 4/5 share the header and the first 51 channel profiles.
    /// This interface currently selects 2.4/5 GHz by channel number;
    /// 6 GHz needs a band-qualified request to avoid channel aliasing.
    pub fn parse(version: u8, bytes: &[u8]) -> Result<Self, &'static str> {
        let capacity = match version {
            4 => 110,
            5 => 115,
            _ => return Err("unsupported NVM response version"),
        };
        if bytes.len() != 28 + capacity * 4 {
            return Err("invalid NVM response length");
        }
        let count = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
        if count > capacity {
            return Err("invalid NVM channel count");
        }
        let tx_chains = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) & 3;
        let rx_chains = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) & 3;
        if tx_chains == 0 || rx_chains == 0 {
            return Err("NVM has no usable antennas");
        }
        let channels = CHANNELS
            .into_iter()
            .take(count)
            .enumerate()
            .filter_map(|(i, channel)| {
                let flags = u32::from_le_bytes(bytes[28 + 4 * i..32 + 4 * i].try_into().unwrap());
                (flags & 1 != 0).then_some(channel)
            })
            .collect();
        Ok(Self {
            tx_chains,
            rx_chains,
            channels,
        })
    }
}

pub fn mac(action: u32, address: [u8; 6], aid: Option<u16>) -> [u8; 52] {
    let mut out = [0; 52];
    put32(&mut out, 4, action);
    put32(&mut out, 8, 5); // BSS station
    out[12..18].copy_from_slice(&address);
    put32(&mut out, 20, (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4));
    if let Some(aid) = aid {
        out[36] = 1;
        put16(&mut out, 40, aid);
    }
    out
}

pub fn phy(action: u32, channel: u8) -> [u8; 32] {
    let mut out = [0; 32];
    put32(&mut out, 4, action);
    put32(&mut out, 8, channel as u32);
    out[12] = u8::from(channel <= 14); // PHY_BAND_24=1, PHY_BAND_5=0
    out[28] = 4; // unused secondary control channel, opposite primary
    out
}

pub fn link(
    action: u32,
    address: [u8; 6],
    active: bool,
    channel: u8,
    beacon_interval: u16,
    dtim: u8,
) -> [u8; 208] {
    let mut out = [0; 208];
    put32(&mut out, 0, action);
    put32(&mut out, 12, if active { 0 } else { u32::MAX });
    out[16..22].copy_from_slice(&address);
    if action == 2 {
        put32(&mut out, 24, 0x1f);
    } // active, rates, protection, QoS, beacon timing
    put32(&mut out, 28, u32::from(active));
    put32(&mut out, 36, if channel <= 14 { 0xf } else { 0 });
    put32(&mut out, 40, 0x15); // mandatory OFDM 6/12/24 Mbps
    put32(&mut out, 48, 1); // short slot
    for ac in 0..5 {
        let p = 60 + 8 * ac;
        put16(&mut out, p, 15);
        put16(&mut out, p + 2, 1023);
        out[p + 4] = 3; // AIFSN
    }
    put32(&mut out, 136, beacon_interval as u32);
    put32(&mut out, 140, beacon_interval as u32 * dtim.max(1) as u32);
    out
}

pub fn peer(address: [u8; 6]) -> [u8; 104] {
    let mut out = [0; 104];
    out[8..14].copy_from_slice(&address);
    out[16..22].copy_from_slice(&address);
    // Station/link ID 0, type PEER=0. No HT/HE/EHT or aggregation.
    out
}

pub fn scan_config(nvm: &Nvm) -> [u8; 12] {
    let mut out = [0; 12];
    put32(&mut out, 4, nvm.tx_chains);
    put32(&mut out, 8, nvm.rx_chains);
    out
}
/// REDUCE_TX_POWER_CMD v10/v11, link 0. Firmware takes eighth-dBm
/// units and applies this ceiling in addition to its regulatory limits.
pub fn tx_power(version: u8, dbm: i8) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let length = match version {
        10 => 108,
        11 => 116,
        _ => return Err("unsupported TX power command"),
    };
    let mut body = alloc::vec![0; length];
    body[8..10].copy_from_slice(&(i16::from(dbm) * 8).to_le_bytes());
    Ok(body)
}
