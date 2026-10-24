// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Original Linux B radio init callbacks/tables SHA256 bc1d7e9c1008e532af9ea0b5b6f1589afe6c5e6c97a71de9262a301c13521f27
type InitGolden = (u8,u8,u8,u32,u64,u32,u64,bool);
pub(super) const CASES: &[InitGolden] = &[
(0,1,0,2916,0xcda1de6547f40bc,1328,0x3bb90ef7b9a7db50,false),
(0,1,1,2916,0x14ab3c19e85fbee,1328,0x3bb90ef7b9a7db50,false),
(0,5,0,2916,0x14ab3c19e85fbee,1328,0x3bb90ef7b9a7db50,false),
(0,5,1,2916,0x14ab3c19e85fbee,1328,0x3bb90ef7b9a7db50,false),
(0,16,0,1035,0x756c46ca294e235a,1328,0x3bb90ef7b9a7db50,true),
(0,16,1,1035,0x756c46ca294e235a,1328,0x3bb90ef7b9a7db50,true),
(165,1,0,2916,0x241444d84369c40c,1328,0x3bb90ef7b9a7db50,false),
(165,1,1,2916,0x5dc62d032805a5e,1328,0x3bb90ef7b9a7db50,false),
(165,5,0,2916,0x5dc62d032805a5e,1328,0x3bb90ef7b9a7db50,false),
(165,5,1,2916,0x5dc62d032805a5e,1328,0x3bb90ef7b9a7db50,false),
(165,16,0,1035,0xd907700032f2f9aa,1328,0x3bb90ef7b9a7db50,true),
(165,16,1,1035,0xd907700032f2f9aa,1328,0x3bb90ef7b9a7db50,true),
];
