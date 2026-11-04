// SPDX-License-Identifier: GPL-2.0-or-later
//! Station hardware key offload for the RAW receive image (Linux ath10k
//! `rawmode=1 cryptmode=0`). The shared `station_security::Security` owner
//! stays the RSNA, PN and replay authority; it reports each committed
//! PTK/GTK and this unit programs it with `WMI_VDEV_INSTALL_KEY`, waiting
//! for the HTT security indication Linux uses as `install_key_done`
//! (htt_rx.c `HTT_T2H_MSG_TYPE_SEC_IND`). Until that confirmation the slot
//! stays software-only. IGTK/BIP is never programmed: Linux mac.c
//! `ath10k_set_key` returns 1 (software) for every BIP suite.
use super::*;
use narf_wireless::station_security::KeyInstall;

/// Linux `install_key_done` wait (mac.c `ath10k_install_key`, 3 * HZ).
pub(super) const INSTALL_TIMEOUT_MS: u64 = 3000;
/// HTT T2H `SEC_IND` in the main, 10.x, TLV and 10.4 maps (htt.h).
pub(super) const SECURITY_INDICATION: u8 = 0xb;
/// `IEEE80211_CCMP_MIC_LEN`: the device writes the MIC into this tail space
/// (htt_tx.c `ath10k_htt_tx_32`/`_64` RAW protected `skb_put`; wmi.c
/// `ath10k_wmi_op_gen_mgmt_tx` for protected action/deauth/disassoc), and
/// removes it before a device-decrypted MPDU's FCS on receive.
pub(super) const MIC_LEN: usize = 8;
/// `ATH10K_FW_FEATURE_MFP_SUPPORT` (core.h bit 12).
const FEATURE_MFP: u64 = 1 << 12;
/// `WMI_CIPHER_AES_CCM`, equal in `wmi_key_cipher_suites` and the TLV map.
const CIPHER_AES_CCM: u32 = 4;
/// `WMI_KEY_PAIRWISE` / `WMI_KEY_GROUP` (wmi.h).
const KEY_PAIRWISE: u32 = 0;
const KEY_GROUP: u32 = 1;
/// `struct wmi_vdev_install_key_cmd` without its flexible key array.
const INSTALL_BODY: usize = 92;

/// One outstanding install: Linux serializes `ath10k_install_key` under
/// `conf_mutex` with a single `install_key_done` completion.
#[derive(Debug, Clone, Copy)]
pub(super) struct InFlight {
    pub(super) token: u32,
    pub(super) pairwise: bool,
    pub(super) deadline: narf_time::Deadline,
}

/// `vdev_install_key_cmdid` per dialect: VDEV_UP + 4 in the main/TLV maps,
/// VDEV_UP + 6 in the 10.x/10.4 maps (STANDBY/RESUME_RESPONSE between).
fn install_command(dialect: Dialect) -> u32 {
    match dialect {
        Dialect::Main | Dialect::Tlv => 0x5009,
        Dialect::TenOne => 0x901b,
        Dialect::TenTwo | Dialect::TenTwoFour => 0x901a,
        Dialect::TenFour => 0x901d,
    }
}

/// `WMI_VDEV_INSTALL_KEY` for one CCMP-128 key of the station `vdev` peer
/// (Linux mac.c `ath10k_send_key`: `key_idx`, `WMI_KEY_PAIRWISE` or
/// `WMI_KEY_GROUP`, `WMI_CIPHER_AES_CCM`, the BSSID as peer address for both
/// in station mode). Like Linux, the RSC/TSC counters stay zero: the host
/// keeps PN generation and replay checking. Main/10.x carry the packed
/// struct with the key appended (wmi.c `ath10k_wmi_op_gen_vdev_install_key`);
/// TLV wraps the same struct in `VDEV_INSTALL_KEY_CMD` and the key in an
/// `ARRAY_BYTE` TLV (wmi-tlv.c `ath10k_wmi_tlv_op_gen_vdev_install_key`).
pub(super) fn install(
    dialect: Dialect,
    vdev: u8,
    bssid: [u8; 6],
    key: &KeyInstall,
) -> Result<Vec<u8>, Error> {
    if bssid == [0; 6] || bssid[0] & 1 != 0 || key.key_id > 3 || key.pairwise && key.key_id != 0 {
        return Err(Error::Malformed);
    }
    let tlv = dialect == Dialect::Tlv;
    // `wire::packet` sizes the body after the 4-octet command header.
    let size = if tlv {
        4 + INSTALL_BODY + 4 + 16
    } else {
        INSTALL_BODY + 16
    };
    let mut out = wire::packet(install_command(dialect), size)?;
    let at = if tlv {
        wire::put(&mut out, 4, (96 << 16) | INSTALL_BODY as u32);
        8
    } else {
        4
    };
    wire::put(&mut out, at, u32::from(vdev));
    out[at + 4..at + 10].copy_from_slice(&bssid);
    wire::put(&mut out, at + 12, u32::from(key.key_id));
    wire::put(
        &mut out,
        at + 16,
        if key.pairwise {
            KEY_PAIRWISE
        } else {
            KEY_GROUP
        },
    );
    wire::put(&mut out, at + 20, CIPHER_AES_CCM);
    wire::put(&mut out, at + 80, 16); // key_len; tx/rx MIC lengths stay 0.
    let data = if tlv {
        wire::put(&mut out, at + INSTALL_BODY, (17 << 16) | 16);
        at + INSTALL_BODY + 4
    } else {
        at + INSTALL_BODY
    };
    out[data..data + 16].copy_from_slice(&key.material[..]);
    Ok(out)
}

/// The PEER_ASSOC `peer_flags->pmf` bit (Linux mac.c
/// `ath10k_peer_assoc_h_crypto`): `WMI_PEER_PMF` in the main map,
/// `WMI_10_2_PEER_PMF` in the 10.2/10.4 map, `WMI_TLV_PEER_PMF` for TLV;
/// the 10.1 (`wmi_10x_peer_flags_map`) map has none.
pub(super) fn peer_pmf_flag(dialect: Dialect) -> Option<u32> {
    match dialect {
        Dialect::Main | Dialect::TenTwo | Dialect::TenTwoFour | Dialect::TenFour => {
            Some(0x1000_0000)
        }
        Dialect::Tlv => Some(0x0800_0000),
        Dialect::TenOne => None,
    }
}

/// Firmware decrypts PMF management for this peer only when Linux sets the
/// flag: a PMF association, `ATH10K_FW_FEATURE_MFP_SUPPORT` and a dialect
/// map entry. Otherwise robust management stays in host software.
pub(super) fn management_offload(dialect: Dialect, features: u64, pmf: bool) -> Option<u32> {
    peer_pmf_flag(dialect).filter(|_| pmf && features & FEATURE_MFP != 0)
}

/// OR the PMF flag into a built PEER_ASSOC command's `peer_flags` word.
pub(super) fn mark_peer_pmf(dialect: Dialect, command: &mut [u8], flag: u32) -> Result<(), Error> {
    let at = if dialect == Dialect::Tlv { 8 } else { 4 } + 20;
    let word = wire::word(command, at)?;
    wire::put(command, at, word | flag);
    Ok(())
}

/// `struct htt_security_indication` after the T2H type octet: the
/// `security_type:7, is_unicast:1` flags and the firmware peer ID. Returns
/// (peer, unicast) for an AES-CCMP (`HTT_SECURITY_AES_CCMP` = 6) indication.
pub(super) fn security_indication(bytes: &[u8]) -> Option<(u16, bool)> {
    if bytes.len() < 4 || bytes[0] != SECURITY_INDICATION || bytes[1] & 0x7f != 6 {
        return None;
    }
    Some((
        u16::from_le_bytes([bytes[2], bytes[3]]),
        bytes[1] & 0x80 != 0,
    ))
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "hw_keys_tests.rs"]
mod tests;
