// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Frozen reference data; source provenance is recorded in this file and rtw89/REFERENCE_FIXTURES.md.
// Copyright(c) 2019-2020 Realtek Corporation
// Original Linux table/selector SHA256 b5ff4992da105a766537f9553f08bda151c952ac45c3a4d2ceab7477e0b729db
// RTL8852A selected-program cases over [BB, RF_A, RF_B, NCTL] (no GAIN:
// `rtw8852a_chip_info.bb_gain_table` is NULL). Digests are the FNV-1a
// `digest` in tests.rs over the selected pairs, computed by an independent
// Python port of `radio_table::program` over the Linux tables. The
// (0x99, 1) RF cases are rejected: no headline matches RFE 0x99 and A has
// no rfe-255 wildcard headline (B's BB falls back to its 0xf0ff0001
// headline instead, as the (0x99, 1) BB case shows).
pub(super) const A_CASES: &[(usize, u8, u8, u32, u64, bool)] = &[
    (0, 1, 1, 933, 0x340f66f9c05719dd, false),
    (0, 0x33, 1, 933, 0x046e0b2cd3583d0f, false),
    (0, 0x99, 1, 933, 0x340f66f9c05719dd, false),
    (1, 1, 1, 1412, 0x2b01c13e8cfd1db7, false),
    (1, 0x33, 1, 1412, 0x09e1b534dbb6891e, false),
    (1, 0x36, 2, 1412, 0x09e1b534dbb6891e, false),
    (1, 0x99, 1, 0, 0, true),
    (2, 1, 1, 1417, 0xaf0b6cc70ab89c7f, false),
    (2, 0x33, 1, 1417, 0x55f3bdd93cc229c8, false),
    (2, 0x99, 1, 0, 0, true),
    (3, 1, 1, 1036, 0x81e4abe6f6ef17a4, false),
];
