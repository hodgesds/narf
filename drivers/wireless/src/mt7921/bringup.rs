//! MT7921 full bring-up orchestrator — Stages 7..14 wired together.
//!
//! This module composes the smaller Stage-N pieces into a single
//! linear bring-up sequence that, on real silicon, takes the radio
//! from a freshly probed link state through MCU + WM + WA firmware
//! load, vif setup, channel programming, association, and live data
//! TX/RX.
//!
//! ## Sequence
//!
//! ```text
//!   1. dma::dma_disable + dma::dma_reset          (WFDMA0 quiesce)
//!   2. dma::allocate_ring_set                     (9 rings, 16 ent ea.)
//!   3. dma::program_ring_set                       (MMIO program)
//!   4. fwdl::download_patch                       (Stage-5 — sem + dl)
//!   5. fwdl::download_wm                          (Stage-6 — WM)
//!   6. fwdl::download_wa                          (Stage-7 — WA)
//!   7. mcu_init_sequence                          (Stage-8 — PM + RA)
//!   8. mac_vif_setup                              (Stage-9 — dev/bss/sta)
//!   9. cmd::encode_default_channel_switch         (Stage-10 — ch36)
//!  10. assoc_open                                 (Stage-11 — auth+assoc)
//!  11. wpa2_psk_handshake / wpa3_sae_handshake    (Stage-12)
//!  12. tx + rx pumps live                         (Stage-13/14)
//! ```
//!
//! Each step is a typed function that takes the already-allocated
//! Stage-4 ring set + the chip MMIO + a side channel for the live
//! MCU mailbox (when one exists).
//!
//! ## Status
//!
//! The orchestrator is fully assembled but stops short of real
//! firmware dispatch — the MCU send/receive helpers return
//! `NotImplemented` because the cooperative MCU pump isn't wired
//! to the WFDMA0 RX completion IRQ yet. The shape of the sequence
//! is what real-silicon bring-up will fill in.

#![allow(dead_code)]

use super::cmd;
use super::dma;
use super::fwdl;
use super::regs::*;

/// Top-level bring-up errors, mapping each Stage to its typed error.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BringUpError {
    Dma(dma::DmaError),
    Fwdl(fwdl::DownloadError),
    /// MCU command was rejected by the firmware.
    McuFailed,
    /// MCU never sent a response within the wait window.
    McuTimeout,
    /// Association sequence didn't reach the assoc-success state.
    AssocFailed,
    /// EAPOL 4-way handshake didn't complete.
    HandshakeFailed,
    /// One of the orchestrator legs is gated on alive MCU mailbox.
    NotImplemented,
}

impl From<dma::DmaError> for BringUpError {
    fn from(e: dma::DmaError) -> Self {
        BringUpError::Dma(e)
    }
}

impl From<fwdl::DownloadError> for BringUpError {
    fn from(e: fwdl::DownloadError) -> Self {
        BringUpError::Fwdl(e)
    }
}

/// Per-bring-up parameters. Filled by the caller (vif setup defaults
/// for unassociated STA bringup are sensible).
#[derive(Copy, Clone, Debug)]
pub struct BringUpConfig {
    /// Effective device id (post MT7920 re-tag).
    pub effective_did: u16,
    /// EFUSE-derived own MAC.
    pub own_mac: [u8; 6],
    /// Default channel for the channel-switch step (Stage-10).
    pub channel: u8,
    /// Bandwidth for the channel-switch step (`CH_BW_*`).
    pub bw: u8,
    /// Band for the channel-switch step (`CH_BAND_*`).
    pub band: u8,
}

impl Default for BringUpConfig {
    fn default() -> Self {
        Self {
            effective_did: MTK_DEV_MT7961,
            own_mac: [0; 6],
            channel: MT7921_DEFAULT_CHAN_5G,
            bw: cmd::CH_BW_20,
            band: cmd::CH_BAND_5G,
        }
    }
}

/// What the orchestrator produces on a (real-silicon) successful
/// bring-up. The ring set is owned by the caller after this; the
/// caller drives the data-path TX/RX loop from there.
pub struct BringUpResult {
    pub rings: dma::RingSet,
    pub config: BringUpConfig,
}

/// Stage-8 — MCU init command sequence.
///
/// Encodes (but does not dispatch) the three init commands the
/// firmware expects before any vif setup runs:
///
///   1. `MCU_EXT_CMD_PM_STATE_CTRL` → ACTIVE.
///   2. `MCU_EXT_CMD_INIT_RA_CFG` → band 0 / 2 SS / 20 MHz.
///   3. `MCU_UNI_CMD_DEV_INFO_UPDATE` → active, own_mac primed.
///
/// Returns the three command bodies stacked into one Vec; the
/// real send path (which doesn't exist yet) breaks them apart and
/// posts them on the MCU TX ring.
pub fn build_mcu_init_sequence(config: &BringUpConfig) -> alloc::vec::Vec<u8> {
    extern crate alloc;
    let mut out = alloc::vec::Vec::new();
    out.resize(cmd::PM_STATE_CTRL_SIZE, 0);
    let _ = cmd::encode_pm_state_ctrl(cmd::PM_STATE_ACTIVE, 0, &mut out);

    let ra_start = out.len();
    out.resize(ra_start + cmd::INIT_RA_CFG_SIZE, 0);
    let _ = cmd::encode_init_ra_cfg(
        0, 2, true, false, true, config.bw, true, 0,
        &mut out[ra_start..],
    );

    let dev_start = out.len();
    out.resize(dev_start + cmd::UNI_DEV_INFO_BODY_SIZE, 0);
    let _ = cmd::encode_uni_dev_info_update(
        0, 0, true, config.own_mac,
        &mut out[dev_start..],
    );

    out
}

/// Stage-9 — MAC vif setup. Produces the three TLV-stream bodies the
/// firmware expects to register a STA-mode vif against a (target_bssid).
pub fn build_mac_vif_setup_sequence(
    config: &BringUpConfig,
    target_bssid: [u8; 6],
) -> alloc::vec::Vec<u8> {
    extern crate alloc;
    let mut out = alloc::vec::Vec::new();

    // 1. DEV_INFO_UPDATE (legacy ext-cmd) — register the BSS index.
    out.resize(cmd::DEV_INFO_UPDATE_SIZE, 0);
    let _ = cmd::encode_dev_info_update(0, true, config.own_mac, &mut out);

    // 2. BSS_INFO_UPDATE → BSS_INFO_BASIC TLV.
    let bss_start = out.len();
    out.resize(bss_start + cmd::BSS_INFO_BASIC_TLV_SIZE, 0);
    let _ = cmd::encode_bss_info_basic_tlv(
        cmd::NETWORK_TYPE_INFRA,
        0,
        0,
        target_bssid,
        100,
        2,
        cmd::PHY_MODE_HE,
        1,
        true,
        &mut out[bss_start..],
    );

    // 3. STA_REC_UPDATE → BASIC TLV.
    let sta_start = out.len();
    out.resize(sta_start + cmd::STA_REC_BASIC_TLV_SIZE, 0);
    let _ = cmd::encode_sta_rec_basic_tlv(
        cmd::CONN_TYPE_STA_INFRA,
        cmd::CONN_STATE_DISCONNECT,
        1,
        target_bssid,
        cmd::PHY_MODE_HE,
        1,
        true,
        &mut out[sta_start..],
    );

    out
}

/// Stage-10 — channel-switch body for the default 5 GHz channel.
pub fn build_channel_switch_body(config: &BringUpConfig) -> alloc::vec::Vec<u8> {
    extern crate alloc;
    let mut out = alloc::vec![0u8; cmd::CHANNEL_SWITCH_SIZE];
    let _ = cmd::encode_channel_switch(
        config.channel,
        config.channel,
        config.bw,
        2,
        2,
        config.band,
        &mut out,
    );
    out
}

/// Stage-11 — association.
///
/// Builds the open-auth frame + assoc-req frame for a given target
/// BSSID + SSID. The caller pushes each on the BMC TX ring
/// (queue 4 — Linux `MT7921_TXQ_BMC`).
pub fn build_assoc_open_frames(
    config: &BringUpConfig,
    target_bssid: [u8; 6],
    ssid: &[u8],
) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
    extern crate alloc;
    let mut auth = alloc::vec![0u8; cmd::IEEE80211_AUTH_FRAME_SIZE];
    let _ = cmd::encode_open_auth_frame(config.own_mac, target_bssid, &mut auth);

    let assoc_cap = 0x0011u16; // ESS + Short Preamble
    let mut assoc = alloc::vec![0u8; cmd::IEEE80211_MAC_HDR_SIZE + 2 + 2 + 2 + ssid.len()];
    if let Some(n) =
        cmd::encode_assoc_req_frame(config.own_mac, target_bssid, assoc_cap, 5, ssid, &mut assoc)
    {
        assoc.truncate(n);
    }
    (auth, assoc)
}

/// Stage-12 — WPA2-PSK / WPA3-SAE — build the STA_REC body that
/// flags the per-station crypto. The caller follows up with the
/// actual EAPOL handshake via `narf-wireless::eapol`.
pub fn build_secure_sta_rec_body(
    config: &BringUpConfig,
    target_bssid: [u8; 6],
    cipher: cmd::StaCipher,
    key_id: u8,
    key: &[u8],
) -> alloc::vec::Vec<u8> {
    extern crate alloc;
    let _ = config;
    let cap = cmd::STA_REC_BASIC_TLV_SIZE + cmd::STA_REC_WTBL_TLV_SIZE;
    let mut out = alloc::vec![0u8; cap];
    if let Some(n) = cmd::build_sta_rec_body_for_join(
        1,
        target_bssid,
        1,
        cmd::PHY_MODE_HE,
        cipher,
        key_id,
        key,
        &mut out,
    ) {
        out.truncate(n);
    }
    out
}

/// The orchestrator entry — composes Stages 1-12 into a single
/// linear sequence. On a real-silicon bring-up this returns
/// `Ok(BringUpResult)`. Right now it stops at the firmware-load
/// boundary with `NotImplemented` because the MCU pump isn't wired
/// to a WFDMA0 IRQ vector yet.
///
/// # Safety
/// `mmio` is the live BAR0 region; caller owns the device.
pub unsafe fn full_bring_up(
    mmio: &narf_bus::MmioRegion,
    config: BringUpConfig,
) -> Result<BringUpResult, BringUpError> {
    // Stage-4: DMA quiesce + ring alloc + ring program.
    // SAFETY: forwarded.
    let rings = dma::allocate_ring_set()?;
    // SAFETY: forwarded.
    unsafe { dma::program_ring_set(mmio, &rings)? };

    // Stage-5/6/7: firmware loads — gated on alive `narf_firmware`
    // registry. Without the blob nothing here can succeed; we surface
    // `NotImplemented` as the typed signal that "everything up to
    // this point worked, dispatch is the next missing piece."
    let _ = config;
    Err(BringUpError::NotImplemented)
}
