//! iwlwifi station table — Stage 5 STA_ADD / ADD_STA_KEY commands.
//!
//! Implements the firmware command encoders for:
//!
//! - `REPLY_ADD_STA` (0x18) — push a station context (MAC, AID,
//!   capability flags, queue mask) into the firmware's station table.
//!   References `iwl_mvm_add_sta_cmd` in `fw/api/sta.h`.
//!
//! - `REPLY_REMOVE_STA` (0x19) — remove a station entry.
//!   References `iwl_mvm_rm_sta_cmd` in `fw/api/sta.h`.
//!
//! - `REPLY_ADD_STA_KEY` (0x17) — install a Pairwise Temporal Key
//!   (PTK) or Group Temporal Key (GTK) into the firmware's CCMP
//!   engine. References `iwl_mvm_add_sta_key_cmd` in `fw/api/sta.h`.
//!
//! ## Station types
//!
//! | `IwlStaType` | Value | Use                              |
//! |--------------|-------|----------------------------------|
//! | Link         | 0     | Associated STA (normal data + RX) |
//! | Mcast        | 2     | Multicast/broadcast delivery      |
//!
//! ## References (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `drivers/net/wireless/intel/iwlwifi/fw/api/sta.h` —
//!   `iwl_mvm_add_sta_cmd`, `iwl_mvm_add_sta_key_cmd`,
//!   `iwl_sta_flags`, `iwl_sta_key_flag`, `iwl_mvm_rm_sta_cmd`.
//! - `drivers/net/wireless/intel/iwlwifi/mvm/sta.c` —
//!   `iwl_mvm_sta_add_internal`, `iwl_mvm_set_sta_key`.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── Command IDs ────────────────────────────────────────────────────

/// `REPLY_ADD_STA_KEY` host command ID.
pub const ADD_STA_KEY: u8 = 0x17;
/// `REPLY_ADD_STA` host command ID.
pub const ADD_STA: u8 = 0x18;
/// `REPLY_REMOVE_STA` host command ID.
pub const REMOVE_STA: u8 = 0x19;

// ── Station flags (from `enum iwl_sta_flags` in `fw/api/sta.h`) ───

pub mod sta_flags {
    /// Station is authenticated (class 2/3 traffic allowed).
    pub const STA_FLG_CLASS_AUTH: u32 = 1 << 14;
    /// Station is associated (class 3 traffic allowed).
    pub const STA_FLG_CLASS_ASSOC: u32 = 1 << 15;
    /// FAT (wide channel) support: 20 MHz only.
    pub const STA_FLG_FAT_EN_20MHZ: u32 = 0 << 26;
    /// FAT: 40 MHz.
    pub const STA_FLG_FAT_EN_40MHZ: u32 = 1 << 26;
    /// MIMO: single-stream (SISO).
    pub const STA_FLG_MIMO_EN_SISO: u32 = 0 << 28;
    /// MIMO: 2 streams.
    pub const STA_FLG_MIMO_EN_MIMO2: u32 = 1 << 28;
}

/// Station mode: ADD a new entry vs MODIFY an existing one.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StaMode {
    Add = 0,
    Modify = 1,
}

/// Station type sent in `iwl_mvm_add_sta_cmd::station_type`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IwlStaType {
    /// Normal link station (associated STA, data + management).
    Link = 0,
    /// General-purpose station (AP mode beacon / probe-resp).
    GeneralPurpose = 1,
    /// Multicast/broadcast delivery station.
    Multicast = 2,
}

// ── Response status (`enum iwl_mvm_add_sta_rsp_status`) ───────────

pub mod add_sta_status {
    pub const SUCCESS: u8 = 0x1;
    pub const STATIONS_OVERLOAD: u8 = 0x2;
    pub const IMMEDIATE_BA_FAILURE: u8 = 0x4;
    pub const MODIFY_NON_EXISTING: u8 = 0x8;
}

/// Mask to extract the status byte from the 4-byte ADD_STA response.
pub const IWL_ADD_STA_STATUS_MASK: u32 = 0xFF;

// ── ADD_STA command encoder ────────────────────────────────────────

/// Parameters for a `REPLY_ADD_STA` (ADD_STA) host command.
///
/// Matches `iwl_mvm_add_sta_cmd` v10 layout from `fw/api/sta.h`.
/// Fields not relevant to STA mode (BA tid, sleep, power save) are
/// zeroed; callers set only the identity + queue fields.
#[derive(Clone, Debug)]
pub struct AddStaParams {
    /// Index to place the station at in firmware's station table.
    /// Must be < `num_stations` (firmware-reported at ALIVE time).
    pub sta_id: u8,
    /// ADD or MODIFY.
    pub mode: StaMode,
    /// Station's MAC address (6 bytes).
    pub addr: [u8; 6],
    /// Association ID (bits 8:0; VHT PLCP AID). 0 for mcast/bcast.
    pub assoc_id: u16,
    /// Initial station flags (from `sta_flags::*`). Typically
    /// `STA_FLG_CLASS_AUTH | STA_FLG_CLASS_ASSOC`.
    pub station_flags: u32,
    /// Mask of which `station_flags` fields are valid this command.
    pub station_flags_msk: u32,
    /// TFD queue bitmask (queues 0-31). For a data station set the
    /// relevant AC queue bits. For management-only stations use 0.
    pub tfd_queue_msk: u32,
    /// Station type (`IwlStaType`).
    pub station_type: IwlStaType,
    /// MAC context id (MAC_ID / color) from the firmware context
    /// table. Use 0 for bring-up (single MAC context).
    pub mac_id_n_color: u32,
}

impl AddStaParams {
    /// Construct parameters for the AP station created after a
    /// successful 4-way handshake. `sta_id` = 0 (AP station
    /// convention per iwlwifi mvm/sta.c). Queue mask enables the
    /// four AC queues (AC_BK=1, AC_BE=2, AC_VI=3, AC_VO=4) for
    /// a simple data path.
    pub fn for_ap_station(sta_id: u8, mac_addr: [u8; 6], assoc_id: u16) -> Self {
        Self {
            sta_id,
            mode: StaMode::Add,
            addr: mac_addr,
            assoc_id,
            station_flags: sta_flags::STA_FLG_CLASS_AUTH | sta_flags::STA_FLG_CLASS_ASSOC,
            station_flags_msk: sta_flags::STA_FLG_CLASS_AUTH | sta_flags::STA_FLG_CLASS_ASSOC,
            tfd_queue_msk: 0b0001_1110, // queues 1-4
            station_type: IwlStaType::Link,
            mac_id_n_color: 0,
        }
    }

    /// Construct parameters for the multicast/broadcast station
    /// (used for group key CCMP decryption). Convention per
    /// `iwl_mvm_add_mcast_sta`: station_type=Multicast, AID=0.
    pub fn for_mcast_station(sta_id: u8) -> Self {
        Self {
            sta_id,
            mode: StaMode::Add,
            addr: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            assoc_id: 0,
            station_flags: 0,
            station_flags_msk: 0,
            tfd_queue_msk: 0,
            station_type: IwlStaType::Multicast,
            mac_id_n_color: 0,
        }
    }

    /// Encode into the `iwl_mvm_add_sta_cmd` v10 wire format.
    ///
    /// Layout (packed, all fields LE):
    /// ```text
    ///  0:    u8  add_modify
    ///  1:    u8  awake_acs (0)
    ///  2-3:  u16 tid_disable_tx (0)
    ///  4-7:  u32 mac_id_n_color
    ///  8-13: u8[6] addr
    ///  14-15: u16 reserved2 (0)
    ///  16:   u8  sta_id
    ///  17:   u8  modify_mask (0)
    ///  18-19: u16 reserved3 (0)
    ///  20-23: u32 station_flags
    ///  24-27: u32 station_flags_msk
    ///  28:   u8  add_immediate_ba_tid (0)
    ///  29:   u8  remove_immediate_ba_tid (0)
    ///  30-31: u16 add_immediate_ba_ssn (0)
    ///  32-33: u16 sleep_tx_count (0)
    ///  34:   u8  sleep_state_flags (0)
    ///  35:   u8  station_type
    ///  36-37: u16 assoc_id
    ///  38-39: u16 beamform_flags (0)
    ///  40-43: u32 tfd_queue_msk
    ///  44-45: u16 rx_ba_window (0)
    ///  46:   u8  sp_length (0)
    ///  47:   u8  uapsd_acs (0)
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.push(self.mode as u8);          // add_modify
        out.push(0u8);                       // awake_acs
        out.extend_from_slice(&0u16.to_le_bytes()); // tid_disable_tx
        out.extend_from_slice(&self.mac_id_n_color.to_le_bytes());
        out.extend_from_slice(&self.addr);
        out.extend_from_slice(&0u16.to_le_bytes()); // reserved2
        out.push(self.sta_id);
        out.push(0u8);                       // modify_mask
        out.extend_from_slice(&0u16.to_le_bytes()); // reserved3
        out.extend_from_slice(&self.station_flags.to_le_bytes());
        out.extend_from_slice(&self.station_flags_msk.to_le_bytes());
        out.push(0u8);                       // add_immediate_ba_tid
        out.push(0u8);                       // remove_immediate_ba_tid
        out.extend_from_slice(&0u16.to_le_bytes()); // add_immediate_ba_ssn
        out.extend_from_slice(&0u16.to_le_bytes()); // sleep_tx_count
        out.push(0u8);                       // sleep_state_flags
        out.push(self.station_type as u8);
        out.extend_from_slice(&self.assoc_id.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // beamform_flags
        out.extend_from_slice(&self.tfd_queue_msk.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // rx_ba_window
        out.push(0u8);                       // sp_length
        out.push(0u8);                       // uapsd_acs
        out
    }
}

// ── REMOVE_STA command encoder ─────────────────────────────────────

/// Encode a `REPLY_REMOVE_STA` command (4 bytes: sta_id + 3 reserved).
/// Reference: `iwl_mvm_rm_sta_cmd` in `fw/api/sta.h`.
pub fn encode_remove_sta(sta_id: u8) -> [u8; 4] {
    [sta_id, 0, 0, 0]
}

// ── Key flags (`enum iwl_sta_key_flag` in `fw/api/sta.h`) ─────────

pub mod key_flags {
    /// No encryption (remove key).
    pub const NO_ENC: u16 = 0;
    /// CCMP-128 encryption algorithm.
    pub const CCM: u16 = 2;
    /// TKIP encryption algorithm.
    pub const TKIP: u16 = 3;
    /// Mask for the encryption algorithm field (bits 2:0).
    pub const ENC_MSK: u16 = 0x07;
    /// Key index bit position (bits 9:8 = key_id 0-3).
    pub const KEYID_POS: u16 = 8;
    /// Key index mask.
    pub const KEYID_MSK: u16 = 3 << 8;
    /// Set for multicast (GTK) keys.
    pub const MULTICAST: u16 = 1 << 14;
    /// Key Not Valid — use to invalidate/remove an installed key.
    pub const NOT_VALID: u16 = 1 << 11;
    /// Management Frame Protection (IGTK).
    pub const MFP: u16 = 1 << 15;
}

/// Whether the key being installed is pairwise (PTK) or group (GTK).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyKind {
    /// Pairwise Temporal Key — unicast encryption (key_id = 0).
    Ptk,
    /// Group Temporal Key — multicast/broadcast (key_id 1-3).
    Gtk,
}

/// Parameters for `REPLY_ADD_STA_KEY` (0x17).
#[derive(Clone, Debug)]
pub struct AddStaKeyParams {
    /// Station index this key is bound to. PTK → AP station id.
    /// GTK → multicast station id.
    pub sta_id: u8,
    /// Slot in the firmware key store (0-3). PTK uses 0; GTK uses
    /// the key_id from the Group-Rekey message.
    pub key_offset: u8,
    /// Computed key_flags (use `build_key_flags`).
    pub key_flags: u16,
    /// Raw key material (16 bytes for CCMP-128).
    pub key: [u8; 32],
    /// RX sequence counter / PN (16 bytes; zero for initial install).
    pub rx_secur_seq_cnt: [u8; 16],
    /// For TKIP only: RX MIC key (8 bytes, rest zero).
    pub rx_mic_key: u64,
    /// For TKIP only: TX MIC key.
    pub tx_mic_key: u64,
    /// Transmit sequence count (TSC / PN) — zero for new keys.
    pub transmit_seq_cnt: u64,
}

/// Compute the `key_flags` field for `REPLY_ADD_STA_KEY`.
///
/// `kind` — PTK or GTK.
/// `key_id` — GTK key index (0-3); ignored for PTK (always 0).
/// `algo` — one of `key_flags::CCM` / `key_flags::TKIP`.
pub fn build_key_flags(kind: KeyKind, key_id: u8, algo: u16) -> u16 {
    let mut flags = algo & key_flags::ENC_MSK;
    let id = match kind {
        KeyKind::Ptk => 0u8,
        KeyKind::Gtk => key_id & 0x3,
    };
    flags |= (id as u16) << key_flags::KEYID_POS;
    if kind == KeyKind::Gtk {
        flags |= key_flags::MULTICAST;
    }
    flags
}

impl AddStaKeyParams {
    /// Create PTK (unicast) key parameters for a CCMP-128 session.
    pub fn ccmp_ptk(sta_id: u8, tk: &[u8]) -> Self {
        let mut key = [0u8; 32];
        let len = tk.len().min(16);
        key[..len].copy_from_slice(&tk[..len]);
        Self {
            sta_id,
            key_offset: 0,
            key_flags: build_key_flags(KeyKind::Ptk, 0, key_flags::CCM),
            key,
            rx_secur_seq_cnt: [0u8; 16],
            rx_mic_key: 0,
            tx_mic_key: 0,
            transmit_seq_cnt: 0,
        }
    }

    /// Create GTK (multicast) key parameters for a CCMP-128 session.
    pub fn ccmp_gtk(sta_id: u8, key_id: u8, gtk: &[u8]) -> Self {
        let mut key = [0u8; 32];
        let len = gtk.len().min(16);
        key[..len].copy_from_slice(&gtk[..len]);
        Self {
            sta_id,
            key_offset: key_id & 0x3,
            key_flags: build_key_flags(KeyKind::Gtk, key_id, key_flags::CCM),
            key,
            rx_secur_seq_cnt: [0u8; 16],
            rx_mic_key: 0,
            tx_mic_key: 0,
            transmit_seq_cnt: 0,
        }
    }

    /// Encode the `iwl_mvm_add_sta_key_cmd` v2 wire format.
    ///
    /// Layout (`struct iwl_mvm_add_sta_key_common` + v2 extras):
    /// ```text
    ///   0:    u8  sta_id
    ///   1:    u8  key_offset
    ///   2-3:  u16 key_flags (LE)
    ///   4-35: u8[32] key
    ///  36-51: u8[16] rx_secur_seq_cnt
    ///  52-59: u64 rx_mic_key (LE)
    ///  60-67: u64 tx_mic_key (LE)
    ///  68-75: u64 transmit_seq_cnt (LE)
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(76);
        out.push(self.sta_id);
        out.push(self.key_offset);
        out.extend_from_slice(&self.key_flags.to_le_bytes());
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.rx_secur_seq_cnt);
        out.extend_from_slice(&self.rx_mic_key.to_le_bytes());
        out.extend_from_slice(&self.tx_mic_key.to_le_bytes());
        out.extend_from_slice(&self.transmit_seq_cnt.to_le_bytes());
        out
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Smoke: ADD_STA command encode for AP station ───────────────

    fn smoke_iwlwifi_sta_add_ap_station_encode() -> TestResult {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let p = AddStaParams::for_ap_station(0, mac, 1);
        let cmd = p.encode();

        // Minimum 48 bytes for v10 layout.
        if cmd.len() != 48 {
            return TestResult::Fail("ADD_STA encode wrong length");
        }
        // Byte 0: add_modify = 0 (Add).
        if cmd[0] != StaMode::Add as u8 {
            return TestResult::Fail("add_modify wrong");
        }
        // Bytes 8-13: MAC address.
        if cmd[8..14] != mac {
            return TestResult::Fail("MAC address wrong in ADD_STA");
        }
        // Byte 16: sta_id = 0.
        if cmd[16] != 0 {
            return TestResult::Fail("sta_id wrong");
        }
        // Byte 35: station_type = Link (0).
        if cmd[35] != IwlStaType::Link as u8 {
            return TestResult::Fail("station_type wrong");
        }
        // Bytes 36-37: assoc_id = 1 (LE).
        let aid = u16::from_le_bytes([cmd[36], cmd[37]]);
        if aid != 1 {
            return TestResult::Fail("assoc_id wrong");
        }
        // Bytes 40-43: tfd_queue_msk.
        let qmsk = u32::from_le_bytes([cmd[40], cmd[41], cmd[42], cmd[43]]);
        if qmsk == 0 {
            return TestResult::Fail("tfd_queue_msk should be non-zero for AP station");
        }
        TestResult::Pass
    }

    // ── Smoke: ADD_STA for mcast station sets MULTICAST type ───────

    fn smoke_iwlwifi_sta_add_mcast_station_type() -> TestResult {
        let p = AddStaParams::for_mcast_station(1);
        let cmd = p.encode();
        if cmd[35] != IwlStaType::Multicast as u8 {
            return TestResult::Fail("mcast station_type should be Multicast(2)");
        }
        // tfd_queue_msk = 0 for mcast station.
        let qmsk = u32::from_le_bytes([cmd[40], cmd[41], cmd[42], cmd[43]]);
        if qmsk != 0 {
            return TestResult::Fail("mcast station tfd_queue_msk should be 0");
        }
        TestResult::Pass
    }

    // ── Smoke: REMOVE_STA command encode ──────────────────────────

    fn smoke_iwlwifi_sta_remove_encode() -> TestResult {
        let cmd = encode_remove_sta(5);
        if cmd[0] != 5 {
            return TestResult::Fail("sta_id wrong in REMOVE_STA");
        }
        if cmd[1..4] != [0, 0, 0] {
            return TestResult::Fail("reserved bytes not zero in REMOVE_STA");
        }
        TestResult::Pass
    }

    // ── Smoke: ADD_STA_KEY for PTK (CCMP-128) ─────────────────────

    fn smoke_iwlwifi_sta_add_ptk_key_encode() -> TestResult {
        let tk = [0x11u8; 16];
        let p = AddStaKeyParams::ccmp_ptk(0, &tk);
        let cmd = p.encode();

        // Wire format: 76 bytes.
        if cmd.len() != 76 {
            return TestResult::Fail("ADD_STA_KEY encode wrong length");
        }
        // Byte 0: sta_id = 0.
        if cmd[0] != 0 {
            return TestResult::Fail("sta_id wrong");
        }
        // Byte 1: key_offset = 0 (PTK).
        if cmd[1] != 0 {
            return TestResult::Fail("key_offset wrong for PTK");
        }
        // Bytes 2-3: key_flags — CCM(2), key_id=0, no MULTICAST.
        let kf = u16::from_le_bytes([cmd[2], cmd[3]]);
        if kf & key_flags::ENC_MSK != key_flags::CCM {
            return TestResult::Fail("key_flags algo should be CCM");
        }
        if kf & key_flags::MULTICAST != 0 {
            return TestResult::Fail("PTK should not have MULTICAST flag");
        }
        // Bytes 4-19: first 16 bytes of key = TK.
        if cmd[4..20] != tk {
            return TestResult::Fail("key bytes wrong");
        }
        TestResult::Pass
    }

    // ── Smoke: ADD_STA_KEY for GTK sets MULTICAST + key_id ────────

    fn smoke_iwlwifi_sta_add_gtk_key_flags() -> TestResult {
        let gtk = [0x22u8; 16];
        let p = AddStaKeyParams::ccmp_gtk(1, 2, &gtk);
        let cmd = p.encode();

        let kf = u16::from_le_bytes([cmd[2], cmd[3]]);
        // MULTICAST bit must be set.
        if kf & key_flags::MULTICAST == 0 {
            return TestResult::Fail("GTK should have MULTICAST flag");
        }
        // Key ID field (bits 9:8) must be 2.
        let kid = (kf >> key_flags::KEYID_POS) & 0x3;
        if kid != 2 {
            return TestResult::Fail("GTK key_id wrong");
        }
        // Byte 1: key_offset = 2.
        if cmd[1] != 2 {
            return TestResult::Fail("key_offset wrong for GTK key_id=2");
        }
        TestResult::Pass
    }

    // ── Smoke: build_key_flags encodes algo + id correctly ────────

    fn smoke_iwlwifi_sta_build_key_flags_ptk_gtk() -> TestResult {
        // PTK: algo=CCM, no MULTICAST, key_id=0.
        let ptk_flags = build_key_flags(KeyKind::Ptk, 0, key_flags::CCM);
        if ptk_flags & key_flags::MULTICAST != 0 {
            return TestResult::Fail("PTK flags should not have MULTICAST");
        }
        if ptk_flags & key_flags::ENC_MSK != key_flags::CCM {
            return TestResult::Fail("PTK flags algo wrong");
        }

        // GTK key_id=1: MULTICAST set, algo=CCM, key_id=1.
        let gtk_flags = build_key_flags(KeyKind::Gtk, 1, key_flags::CCM);
        if gtk_flags & key_flags::MULTICAST == 0 {
            return TestResult::Fail("GTK flags should have MULTICAST");
        }
        let kid = (gtk_flags >> key_flags::KEYID_POS) & 0x3;
        if kid != 1 {
            return TestResult::Fail("GTK key_id should be 1");
        }
        TestResult::Pass
    }

    kernel_test_in!(
        "drivers/wireless/iwlwifi/sta",
        smoke_iwlwifi_sta_add_ap_station_encode
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/sta",
        smoke_iwlwifi_sta_add_mcast_station_type
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/sta",
        smoke_iwlwifi_sta_remove_encode
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/sta",
        smoke_iwlwifi_sta_add_ptk_key_encode
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/sta",
        smoke_iwlwifi_sta_add_gtk_key_flags
    );
    kernel_test_in!(
        "drivers/wireless/iwlwifi/sta",
        smoke_iwlwifi_sta_build_key_flags_ptk_gtk
    );
}
