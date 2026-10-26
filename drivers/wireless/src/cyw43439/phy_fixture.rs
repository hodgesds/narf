// SPDX-License-Identifier: GPL-2.0-or-later
//! Native firmware conversation data, independent of station_phy encoders.
//! HT shape follows Linux brcmf_update_ht_cap; WMM is an IEEE parameter IE.
use alloc::{vec, vec::Vec};

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
