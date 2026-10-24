// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Original Linux firmware scheduler SHA256 31339c577a21c3d238293a9c9690c2d34f6e8da0a7af1b4edd11465a5ea154a7
pub(super) const CASES: &[(u8,u16,u32,u64)] = &[
(0,0,16,0x41d428ddbf3e43db),
(0,65535,16,0xecbe037c1763b8f),
(0,23130,16,0xb1a914f7608b113f),
(165,0,16,0x34cfbed212a115fb),
(165,65535,16,0x56c4757dc9a954ef),
(165,23130,16,0x25f065bc7c0f1f1f),
];
