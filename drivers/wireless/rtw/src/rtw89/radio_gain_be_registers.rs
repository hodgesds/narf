// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! rtw8922a.c::rtw8922a_set_lna_tia_gain / ::rtw8922a_set_rpl_gain.
use super::GainRegister;
pub(super) const BB_GAIN_LNA: &[GainRegister] = &[
    GainRegister {
        g: [0x409c, 0x449c],
        a: [0x406C, 0x446C],
        gm: 0xFF00,
        am: 0xFF,
    },
    GainRegister {
        g: [0x409c, 0x449c],
        a: [0x406C, 0x446C],
        gm: 0xFF000000,
        am: 0xFF0000,
    },
    GainRegister {
        g: [0x40a0, 0x44a0],
        a: [0x4070, 0x4470],
        gm: 0xFF00,
        am: 0xFF,
    },
    GainRegister {
        g: [0x40a0, 0x44a0],
        a: [0x4070, 0x4470],
        gm: 0xFF000000,
        am: 0xFF0000,
    },
    GainRegister {
        g: [0x40a4, 0x44a4],
        a: [0x4074, 0x4474],
        gm: 0xFF00,
        am: 0xFF,
    },
    GainRegister {
        g: [0x40a4, 0x44a4],
        a: [0x4074, 0x4474],
        gm: 0xFF000000,
        am: 0xFF0000,
    },
    GainRegister {
        g: [0x40a8, 0x44a8],
        a: [0x4078, 0x4478],
        gm: 0xFF00,
        am: 0xFF,
    },
];
pub(super) const BB_GAIN_TIA: &[GainRegister] = &[
    GainRegister {
        g: [0x4054, 0x4454],
        a: [0x4054, 0x4454],
        gm: 0x7FC0000,
        am: 0x1FF,
    },
    GainRegister {
        g: [0x4058, 0x4458],
        a: [0x4054, 0x4454],
        gm: 0x1FF,
        am: 0x3FE00,
    },
];
pub(super) const BB_OP1DB_LNA: &[GainRegister] = &[
    GainRegister {
        g: [0x40ac, 0x44ac],
        a: [0x4078, 0x4478],
        gm: 0xFF00,
        am: 0xFF000000,
    },
    GainRegister {
        g: [0x40ac, 0x44ac],
        a: [0x407c, 0x447c],
        gm: 0xFF0000,
        am: 0xFF,
    },
    GainRegister {
        g: [0x40ac, 0x44ac],
        a: [0x407c, 0x447c],
        gm: 0xFF000000,
        am: 0xFF00,
    },
    GainRegister {
        g: [0x40b0, 0x44b0],
        a: [0x407c, 0x447c],
        gm: 0xFF,
        am: 0xFF0000,
    },
    GainRegister {
        g: [0x40b0, 0x44b0],
        a: [0x407c, 0x447c],
        gm: 0xFF00,
        am: 0xFF000000,
    },
    GainRegister {
        g: [0x40b0, 0x44b0],
        a: [0x4080, 0x4480],
        gm: 0xFF0000,
        am: 0xFF,
    },
    GainRegister {
        g: [0x40b0, 0x44b0],
        a: [0x4080, 0x4480],
        gm: 0xFF000000,
        am: 0xFF00,
    },
];
pub(super) const BB_OP1DB_TIA_LNA: &[GainRegister] = &[
    GainRegister {
        g: [0x40b4, 0x44b4],
        a: [0x4080, 0x4480],
        gm: 0xFF0000,
        am: 0xFF000000,
    },
    GainRegister {
        g: [0x40b4, 0x44b4],
        a: [0x4084, 0x4484],
        gm: 0xFF000000,
        am: 0xFF,
    },
    GainRegister {
        g: [0x40b8, 0x44b8],
        a: [0x4084, 0x4484],
        gm: 0xFF,
        am: 0xFF00,
    },
    GainRegister {
        g: [0x40b8, 0x44b8],
        a: [0x4084, 0x4484],
        gm: 0xFF00,
        am: 0xFF0000,
    },
    GainRegister {
        g: [0x40b8, 0x44b8],
        a: [0x4084, 0x4484],
        gm: 0xFF0000,
        am: 0xFF000000,
    },
    GainRegister {
        g: [0x40b8, 0x44b8],
        a: [0x4088, 0x4488],
        gm: 0xFF000000,
        am: 0xFF,
    },
    GainRegister {
        g: [0x40bc, 0x44bc],
        a: [0x4088, 0x4488],
        gm: 0xFF,
        am: 0xFF00,
    },
    GainRegister {
        g: [0x40bc, 0x44bc],
        a: [0x4088, 0x4488],
        gm: 0xFF00,
        am: 0xFF0000,
    },
];
pub(super) const RPL_COMP_BW160: &[(u32, u32)] = &[
    (0x41E8, 0xFF00),
    (0x41E8, 0xFF0000),
    (0x41E8, 0xFF000000),
    (0x41EC, 0xFF),
    (0x41EC, 0xFF00),
    (0x41EC, 0xFF0000),
    (0x41EC, 0xFF000000),
    (0x41F0, 0xFF),
];
pub(super) const RPL_COMP_BW80: &[(u32, u32)] = &[
    (0x41F4, 0xFF),
    (0x41F4, 0xFF00),
    (0x41F4, 0xFF0000),
    (0x41F4, 0xFF000000),
];
pub(super) const RPL_COMP_BW40: &[(u32, u32)] = &[(0x41F0, 0xFF0000), (0x41F0, 0xFF000000)];
pub(super) const RPL_COMP_BW20: &[(u32, u32)] = &[(0x41F0, 0xFF00)];
