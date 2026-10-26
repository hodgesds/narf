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
