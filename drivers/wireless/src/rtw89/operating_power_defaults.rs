// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Frozen Linux7.3-rc4 source WW0/20MHz channel1..14 power table units.
//! Not dBm, host permission, measured RF maxima or an emission grant.
// Source rtw8852b_table.c SHA256 bcee2f4357f6ada16c831f460edc5e00c5471a79333b606e36cfa0b630352d09
#[derive(Clone, Copy)]
pub(super) struct ChannelPower {
    pub limits: [[i8; 8]; 2],
    pub ru: [[i8; 3]; 2],
}
pub(super) const CHANNELS: [ChannelPower; 14] = [
    ChannelPower {
        limits: [[56, 0, 0, 0, 58, 0, 58, 0], [44, 0, 0, 0, 46, 0, 46, 34]],
        ru: [[32, 42, 56], [20, 32, 44]],
    }, // channel1
    ChannelPower {
        limits: [[56, 0, 0, 0, 58, 0, 58, 0], [44, 0, 0, 0, 46, 0, 46, 34]],
        ru: [[32, 44, 56], [22, 32, 44]],
    }, // channel2
    ChannelPower {
        limits: [[56, 0, 50, 0, 58, 0, 58, 0], [44, 0, 44, 0, 46, 0, 46, 34]],
        ru: [[32, 44, 56], [22, 32, 44]],
    }, // channel3
    ChannelPower {
        limits: [[56, 0, 50, 0, 58, 0, 58, 0], [44, 0, 44, 0, 46, 0, 46, 34]],
        ru: [[32, 44, 56], [22, 32, 44]],
    }, // channel4
    ChannelPower {
        limits: [[56, 0, 50, 0, 58, 0, 58, 0], [44, 0, 44, 0, 46, 0, 46, 34]],
        ru: [[32, 44, 56], [22, 32, 44]],
    }, // channel5
    ChannelPower {
        limits: [[56, 0, 56, 0, 58, 0, 58, 0], [44, 0, 44, 0, 46, 0, 46, 34]],
        ru: [[32, 44, 56], [22, 32, 44]],
    }, // channel6
    ChannelPower {
        limits: [[56, 0, 50, 0, 58, 0, 58, 0], [44, 0, 34, 0, 46, 0, 46, 34]],
        ru: [[32, 44, 56], [22, 32, 44]],
    }, // channel7
    ChannelPower {
        limits: [[56, 0, 50, 0, 58, 0, 58, 0], [44, 0, 34, 0, 46, 0, 46, 34]],
        ru: [[32, 44, 56], [22, 32, 44]],
    }, // channel8
    ChannelPower {
        limits: [[56, 0, 50, 0, 58, 0, 58, 0], [44, 0, 34, 0, 46, 0, 46, 34]],
        ru: [[32, 44, 56], [22, 32, 44]],
    }, // channel9
    ChannelPower {
        limits: [[56, 0, 42, 0, 58, 0, 58, 0], [44, 0, 30, 0, 46, 0, 46, 34]],
        ru: [[32, 44, 56], [22, 32, 44]],
    }, // channel10
    ChannelPower {
        limits: [[56, 0, 30, 0, 58, 0, 58, 0], [44, 0, 30, 0, 46, 0, 46, 34]],
        ru: [[32, 44, 56], [22, 32, 44]],
    }, // channel11
    ChannelPower {
        limits: [[56, 0, 0, 0, 54, 0, 54, 0], [44, 0, 0, 0, 46, 0, 46, 34]],
        ru: [[32, 44, 50], [22, 32, 38]],
    }, // channel12
    ChannelPower {
        limits: [[56, 0, 0, 0, 50, 0, 50, 0], [42, 0, 0, 0, 42, 0, 42, 34]],
        ru: [[32, 38, 46], [20, 32, 34]],
    }, // channel13
    ChannelPower {
        limits: [[76, 0, 0, 0, 0, 0, 0, 0], [64, 0, 0, 0, 0, 0, 0, 0]],
        ru: [[0, 0, 0], [0, 0, 0]],
    }, // channel14
];
