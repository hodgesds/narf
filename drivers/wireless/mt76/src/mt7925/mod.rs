//! MediaTek MT7925 (Wi-Fi 7 2x2, CONNAC3) PCIe — UNI MCU layer.
//!
//! Sibling of [`crate::mt7921`]: the CONNAC2 bring-up (PCI probe,
//! BAR/L1 windows, WFDMA scaffolding, firmware transport) is shared,
//! and this module holds only what is CONNAC3-specific — the UNI
//! (unified) MCU command framing, per-link BSS info, EHT MLD TLVs and
//! per-link station add/assoc/remove builders.
//!
//! ## Implemented here
//!
//! - UNI command words (`MCU_UNI_CMD` / `MCU_WM_UNI_CMD` /
//!   `MCU_WM_UNI_CMD_QUERY`) and the `mt7925_mcu_rxd` event header.
//! - UNI station records: per-link TX/RX BA (`mt7925_mcu_uni_tx_ba` /
//!   `mt7925_mcu_uni_rx_ba`), the EHT MLD + MLD TLVs
//!   (`mt7925_mcu_sta_eht_mld_tlv`, `mt7925_mcu_sta_mld_tlv`), the
//!   station add/assoc builder and the station remove builder
//!   (`mt7925_mcu_sta_remove_tlv` + `STA_REC_MLD_OFF`).
//! - UNI BSS info (`mt7925_mcu_add_bss_info` /
//!   `mt7925_mcu_add_bss_info_sta`): the basic/SEC/rate/QoS/MLD/IFS
//!   TLVs, the HE + BSS-color TLVs, the RLM + MBSSID TLVs on enable,
//!   and the standalone EHT TLV (`mt7925_mcu_set_eht_pp`).
//! - EFUSE over UNI `EFUSE_CTRL` (`MCU_UNI_CMD(EFUSE_CTRL)` for
//!   `mt7925_mcu_set_eeprom`, `MCU_WM_UNI_CMD_QUERY(EFUSE_CTRL)` for
//!   `mt7925_mcu_read_eeprom`) — NOT the CONNAC2
//!   `MCU_EXT_CMD_EFUSE_ACCESS` that `mt7921::mcu` cites.
//!
//! ## Not here
//!
//! - EHT capability tables and the `eht_supported` advertisement —
//!   slice 7 owns `mt7921::he` + `iface.rs`. This module takes EHT
//!   capability values as plain inputs and lays out their bytes; it
//!   never computes them.
//! - DMA queue ids and the ring layout — #2499 owns them
//!   (`regs::MT7925_TXQ_MCU_WM` = 15, `regs::MT7925_RXQ_MCU_WM` = 0).
//!   UNI commands travel on TX MCU_WM (15) and their responses arrive
//!   on RX MCU_WM (0); the live send path will use the DMA `RingMap`.
//! - The chip-id gate (`pci.rs:441`) stays closed for MT7925 pending
//!   Q1 (#2494): what `MT_HW_CHIPID` reads on the 14c3:0717 card.
//!
//! ## Provenance
//!
//! All adaptation from Linux `drivers/net/wireless/mediatek/mt76/`
//! (GPL-2.0) at torvalds/linux `8d7fe9885c62`: `mt7925/mcu.c`,
//! `mt7925/mcu.h`, `mt7925/regs.h`, `mt7925/mt7925.h`,
//! `mt76_connac_mcu.h`, `mt76_connac_mcu.c`. NARF is GPL-2.0-or-later
//! since 2026-05-20; per-item provenance lives next to the constants
//! and code that consume it.

#![allow(dead_code)]

pub mod mcu;

#[cfg(feature = "builtin")]
mod mcu_tests;
