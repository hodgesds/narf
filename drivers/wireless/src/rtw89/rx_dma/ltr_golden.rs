// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Frozen reference data; source provenance is recorded in this file and rtw89/REFERENCE_FIXTURES.md.
// Original Linux LTR callback/macros SHA256 f02e9687c42be6fba75345fce6c80a9c5d2e9d2312817bdb5f0e00a582efd094
type LtrGolden = (bool,u8,&'static [(u32,u32)]);
pub(super) const LTR: &[LtrGolden] = &[
(false,0,&[]),
(true,0,&[(0x8410,0x43),(0x8410,0x2043),(0x8410,0x2743),(0x8414,0x28),(0x8414,0x280028),(0x8418,0x90039003),(0x841c,0x880b880b),]),
(false,165,&[]),
(true,165,&[(0x8410,0xa5a5a5e7),(0x8410,0xa5a5a5e7),(0x8410,0xa5a5a7e7),(0x8414,0xa5a5a028),(0x8414,0xa028a028),(0x8418,0x90039003),(0x841c,0x880b880b),]),
];
