// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Frozen reference data; source provenance is recorded in this file and rtw89/REFERENCE_FIXTURES.md.
// Original B source power SHA256 2e5e08aae88660a6fc444a38fa99ae314df03c2a13d42486afe590b651f5feb3
pub(super) const CASES: &[(u8, bool, u8, u32, u64)] = &[
    (0, false, 0, 58, 0x857b45c66268e20d),
    (0, false, 1, 58, 0x3c5c22b29566f632),
    (0, true, 0, 58, 0xbab481b84f81ccba),
    (0, true, 1, 58, 0x2dd51fda0d4ee01d),
    (165, false, 0, 58, 0x9c86c5e6413e59df),
    (165, false, 1, 58, 0x8fe34d6b01443200),
    (165, true, 0, 58, 0xbd065d880d66e080),
    (165, true, 1, 58, 0xddd72ccd1dcd9687),
];
