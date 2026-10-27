// SPDX-License-Identifier: GPL-2.0-or-later
//! Native firmware conversation data, independent of station_phy encoders.
//! HT shape follows Linux brcmf_update_ht_cap; WMM is an IEEE parameter IE.
use alloc::{vec, vec::Vec};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WideFault {
    None,
    Inventory,
    CurrentWidth,
    ResponseWidth,
    ResponseSecondary,
    RequestWidth,
    CapReadback,
    ChannelRestricted,
    HoldCap,
    HoldResponse,
}
#[derive(Clone, Debug)]
pub(crate) struct Wide {
    /// Actual initial per-band firmware replies,2GHz then5GHz.
    pub caps: [u32; 2],
    pub inventory: Vec<u32>,
    pub operating: u16,
    pub secondary: u8,
    pub fault: WideFault,
}
impl Wide {
    pub(crate) fn beacon(&self, channel: u8, chains: u32) -> Vec<u8> {
        let mut observed = self.clone();
        observed.fault = WideFault::None;
        observed.response(channel, chains)
    }
    pub(crate) fn list(&self) -> Vec<u8> {
        let mut out = (if self.fault == WideFault::Inventory {
            384
        } else {
            self.inventory.len() as u32
        })
        .to_le_bytes()
        .to_vec();
        for value in &self.inventory {
            out.extend_from_slice(&value.to_le_bytes());
        }
        out
    }
    pub(crate) fn request(&self, chains: u32, wide: bool) -> Vec<u8> {
        let mut ies = request(chains);
        if wide && self.fault != WideFault::RequestWidth {
            ies[2] |= 2 | 64;
        }
        ies
    }
    pub(crate) fn response(&self, channel: u8, chains: u32) -> Vec<u8> {
        let mut ies = response(channel, chains);
        ies[2] |= 2 | 64;
        if self.fault != WideFault::ResponseWidth {
            ies[31] = 4 | if self.secondary > channel { 1 } else { 3 };
        }
        if self.fault == WideFault::ResponseSecondary {
            ies[31] ^= 2;
        }
        ies
    }
}

pub(crate) fn request(chains: u32) -> Vec<u8> {
    let mut body = [0; 26];
    body[..3].copy_from_slice(&[32, 16, 31]);
    body[3..3 + chains.count_ones() as usize].fill(255);
    body[15] = 1;
    let mut ies = vec![45, 26];
    ies.extend_from_slice(&body);
    ies.extend_from_slice(&[221, 7, 0, 80, 242, 2, 0, 1, 0]);
    ies
}
pub(crate) fn response(channel: u8, chains: u32) -> Vec<u8> {
    let mut ies = request(chains)[..28].to_vec();
    let mut operation = [0; 22];
    operation[0] = channel;
    operation[6] = 1; // MCS0 is mandatory; higher rates remain optional.
    ies.extend_from_slice(&[61, 22]);
    ies.extend_from_slice(&operation);
    ies.extend_from_slice(&[
        221, 24, 0, 80, 242, 2, 1, 1, 0, 0, 3, 164, 0, 0, 39, 164, 0, 0, 66, 67, 94, 0, 98, 50, 47,
        0,
    ]);
    ies
}

/// Native5GHz VHT conversation literals. These are firmware-side wire
/// snapshots, never a host PHY/board grant or physical acceptance evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VhtFault {
    None,
    Inventory,
    CurrentWidth,
    ResponseWidth,
    ResponseCenter,
    ResponseMissing,
    ResponseBasic,
    RequestMissing,
    RequestHt20,
    RequestMcs,
    RequestSgi160,
    RequestDuplicate,
    CapReadback,
    ChannelRestricted,
    HoldCap,
    HoldResponse,
}
#[derive(Clone, Debug)]
pub(crate) struct Vht80 {
    pub caps: [u32; 2],
    pub mode: Option<u32>,
    pub txstreams: Option<u32>,
    pub inventory: Vec<u32>,
    pub center: u8,
    pub fault: VhtFault,
}
impl Vht80 {
    pub(crate) fn channel(&self, primary: u8, width: u32) -> u16 {
        let index = (u16::from(primary) + 6 - u16::from(self.center)) / 4;
        match width {
            80 => 0xe000 | (index << 8) | u16::from(self.center),
            40 => {
                let buddy = if index & 1 == 0 {
                    primary + 4
                } else {
                    primary - 4
                };
                0xd800
                    | if buddy < primary { 0x100 } else { 0 }
                    | ((u16::from(primary) + u16::from(buddy)) / 2)
            }
            _ => 0xd000 | u16::from(primary),
        }
    }
    pub(crate) fn list(&self) -> Vec<u8> {
        let count = if self.fault == VhtFault::Inventory {
            384
        } else {
            self.inventory.len() as u32
        };
        let mut b = count.to_le_bytes().to_vec();
        for value in &self.inventory {
            b.extend_from_slice(&value.to_le_bytes());
        }
        b
    }
    fn map(streams: u32) -> u16 {
        (0..streams.min(3)).fold(0xffff, |map, i| (map & !(3 << (i * 2))) | (2 << (i * 2)))
    }
    fn capability(&self, chains: u32) -> [u8; 12] {
        let mut b = [0; 12];
        b[..4].copy_from_slice(&32u32.to_le_bytes());
        b[4..6].copy_from_slice(&Self::map(chains.count_ones()).to_le_bytes());
        b[8..10].copy_from_slice(
            &Self::map(self.txstreams.unwrap_or(chains.count_ones())).to_le_bytes(),
        );
        b
    }
    pub(crate) fn request(&self, chains: u32, width: u32) -> Vec<u8> {
        let qualified = self.mode.is_some_and(|m| m != 0)
            && self.txstreams.is_some_and(|n| (1..=3).contains(&n))
            && self.caps[1] & 7 == 7
            && self.inventory.iter().any(|c| c & 0xf800 == 0xe000)
            && self.inventory.iter().any(|c| c & 0xf800 == 0xd800);
        let mut ies = request(chains);
        if (width > 20 || qualified) && self.fault != VhtFault::RequestHt20 {
            ies[2] |= 2 | 64;
        }
        ies.extend_from_slice(&[1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108]);
        if qualified && self.fault != VhtFault::RequestMissing {
            let mut cap = self.capability(chains);
            if self.fault == VhtFault::RequestMcs {
                cap[4..6].copy_from_slice(&0xffaau16.to_le_bytes());
            }
            if self.fault == VhtFault::RequestSgi160 {
                cap[0] |= 64;
            }
            ies.extend_from_slice(&[191, 12]);
            ies.extend_from_slice(&cap);
            if self.fault == VhtFault::RequestDuplicate {
                ies.extend_from_slice(&[191, 12]);
                ies.extend_from_slice(&cap);
            }
        }
        ies
    }
    pub(crate) fn beacon(&self, primary: u8, chains: u32) -> Vec<u8> {
        let mut value = self.clone();
        value.fault = VhtFault::None;
        value.response(primary, chains)
    }
    pub(crate) fn response(&self, primary: u8, chains: u32) -> Vec<u8> {
        let mut ies = response(primary, chains);
        ies[2] |= 2 | 64;
        let index = (primary + 6 - self.center) / 4;
        ies[31] = 4 | if index & 1 == 0 { 1 } else { 3 };
        ies.extend_from_slice(&[1, 8, 0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108]);
        if self.fault == VhtFault::ResponseMissing {
            return ies;
        }
        ies.extend_from_slice(&[191, 12]);
        ies.extend_from_slice(&self.capability(chains));
        let width = if self.fault == VhtFault::ResponseWidth {
            0
        } else {
            1
        };
        let center = if self.fault == VhtFault::ResponseCenter {
            self.center + 16
        } else {
            self.center
        };
        ies.extend_from_slice(&[192, 5, width, if width == 0 { 0 } else { center }, 0]);
        ies.extend_from_slice(
            &if self.fault == VhtFault::ResponseBasic {
                0xff00u16
            } else {
                0xfffcu16
            }
            .to_le_bytes(),
        );
        ies
    }
}
