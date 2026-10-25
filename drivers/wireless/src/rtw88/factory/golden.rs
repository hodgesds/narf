// Frozen reference data; source provenance is recorded in this file and rtw88/REFERENCE_FIXTURES.md.
// sizeof/offsetof from actual Linux rtw8822c.h and main.h packed declarations.
const LINUX_FACTORY: &[(usize, usize)] = &[
    (16, 168),
    (184, 1),
    (185, 1),
    (193, 1),
    (195, 1),
    (202, 1),
    (203, 2),
    (208, 1),
    (209, 1),
    (288, 6),
];
const LINUX_POWER_PATH: usize = 42;
const LINUX_TRIM_ADDRESSES: [u16; 19] = [
    495, 432, 468, 494, 466, 492, 488, 484, 480, 476, 491, 487, 483, 479, 475, 470, 469, 472, 471,
];
// Original Linux efuse.h report field macros.
const LINUX_HW_FEATURES: &[(u32, [u8; 5])] = &[
    (0x0, [0, 0, 0, 0, 0]),
    (0xffffffff, [15, 7, 3, 7, 3]),
    (0xc570002, [2, 7, 2, 2, 3]),
    (0xa5a55a5a, [10, 5, 0, 5, 1]),
];
