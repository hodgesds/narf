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
/// Linux rtw8852b_table.c `rtw89_8852b_txpwr_lmt_5g[0][ntx][rs][bf][RTW89_WW]`
/// (CCK absent on 5GHz, so CCK slots stay 0) and `rtw89_8852b_txpwr_lmt_ru_5g
/// [ru][ntx][RTW89_WW]` at `rtw89_channel_to_idx`, in `operating_channel::GHZ5`
/// order. Same frozen source file as `CHANNELS`.
pub(super) const CHANNELS_5GHZ: [ChannelPower; 28] = [
    ChannelPower {
        limits: [[0, 0, 0, 0, 42, 0, 42, 0], [0, 0, 0, 0, 30, 0, 30, 14]],
        ru: [[24, 34, 44], [1, 10, 20]],
    }, // channel36
    ChannelPower {
        limits: [[0, 0, 0, 0, 42, 0, 42, 0], [0, 0, 0, 0, 32, 0, 30, 14]],
        ru: [[24, 34, 44], [4, 14, 18]],
    }, // channel40
    ChannelPower {
        limits: [[0, 0, 0, 0, 42, 0, 42, 0], [0, 0, 0, 0, 30, 0, 30, 14]],
        ru: [[24, 34, 44], [1, 10, 22]],
    }, // channel44
    ChannelPower {
        limits: [[0, 0, 0, 0, 42, 0, 42, 0], [0, 0, 0, 0, 30, 0, 30, 14]],
        ru: [[12, 26, 38], [1, 10, 22]],
    }, // channel48
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 20, 34]],
    }, // channel52
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 20, 34]],
    }, // channel56
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 46], [12, 22, 36]],
    }, // channel60
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 46], [12, 22, 36]],
    }, // channel64
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 22, 36]],
    }, // channel100
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 22, 36]],
    }, // channel104
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 22, 36]],
    }, // channel108
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 22, 36]],
    }, // channel112
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 22, 36]],
    }, // channel116
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 22, 36]],
    }, // channel120
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 22, 36]],
    }, // channel124
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 22, 36]],
    }, // channel128
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 22, 36]],
    }, // channel132
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 22, 36]],
    }, // channel136
    ChannelPower {
        limits: [[0, 0, 0, 0, 52, 0, 52, 0], [0, 0, 0, 0, 40, 0, 40, 28]],
        ru: [[24, 34, 48], [12, 22, 36]],
    }, // channel140
    ChannelPower {
        limits: [[0, 0, 0, 0, 68, 0, 64, 0], [0, 0, 0, 0, 50, 0, 50, 36]],
        ru: [[44, 52, 64], [30, 38, 48]],
    }, // channel144
    ChannelPower {
        limits: [[0, 0, 0, 0, 28, 0, 28, 0], [0, 0, 0, 0, 16, 0, 16, 4]],
        ru: [[26, 28, 28], [14, 16, 16]],
    }, // channel149
    ChannelPower {
        limits: [[0, 0, 0, 0, 28, 0, 28, 0], [0, 0, 0, 0, 16, 0, 16, 4]],
        ru: [[26, 28, 28], [14, 16, 16]],
    }, // channel153
    ChannelPower {
        limits: [[0, 0, 0, 0, 28, 0, 28, 0], [0, 0, 0, 0, 16, 0, 16, 4]],
        ru: [[26, 28, 28], [14, 16, 16]],
    }, // channel157
    ChannelPower {
        limits: [[0, 0, 0, 0, 28, 0, 28, 0], [0, 0, 0, 0, 16, 0, 16, 4]],
        ru: [[26, 28, 28], [14, 16, 16]],
    }, // channel161
    ChannelPower {
        limits: [[0, 0, 0, 0, 28, 0, 28, 0], [0, 0, 0, 0, 16, 0, 16, 4]],
        ru: [[26, 28, 28], [14, 16, 16]],
    }, // channel165
    ChannelPower {
        limits: [[0, 0, 0, 0, 76, 0, 78, 0], [0, 0, 0, 0, 50, 0, 50, 50]],
        ru: [[32, 44, 56], [16, 28, 40]],
    }, // channel169
    ChannelPower {
        limits: [[0, 0, 0, 0, 76, 0, 78, 0], [0, 0, 0, 0, 50, 0, 52, 52]],
        ru: [[32, 44, 56], [16, 30, 40]],
    }, // channel173
    ChannelPower {
        limits: [[0, 0, 0, 0, 76, 0, 78, 0], [0, 0, 0, 0, 50, 0, 52, 52]],
        ru: [[32, 44, 56], [16, 30, 40]],
    }, // channel177
];
