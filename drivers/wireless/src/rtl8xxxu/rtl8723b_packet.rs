//! RTL8723BU packet and gen2 rate-adaptation pieces that differ from the
//! RTL8192EU ones.
//!
//! Linux references (GPL-2.0-or-later, Linux 7.3-rc4):
//! - `rtl8xxxu/8723b.c::{rtl8723bu_fops, rtl8723b_cck_rssi}`
//! - `rtl8xxxu/core.c::{rtl8723au_rx_parse_phystats,
//!   rtl8xxxu_gen2_report_rssi, rtl8xxxu_ra_iter}`
//!
//! `rtl8723bu_fops` uses the same `tx_desc_size = sizeof(struct
//! rtl8xxxu_txdesc40)`, `rtl8xxxu_fill_txdesc_v2`, `rtl8xxxu_parse_rxdesc24`
//! and gen2 `update_rate_mask`/`report_connect` as the RTL8192EU; neither
//! `rtl8xxxu_tx`, `rtl8xxxu_fill_txdesc_v2` nor `rtl8xxxu_parse_rxdesc24`
//! has an RTL8723B branch. So the 8723BU reuses `rtl8192e_packet` (txdesc40
//! / rxdesc24 / gen2 C2H records), the gen2 `packet_transport` codec with its
//! own `rtl8xxxu_init_queue_priority` map, and `rtl8192e_ra` (`Ra` with
//! `tx_paths = 1`, so no 2SS mask is ever admitted). What differs is the CCK
//! signal (`rtl8723b_cck_rssi`, no report-type table) and the 4-byte
//! `RSSI_SETTING` (`rtl8xxxu_gen2_report_rssi` truncates for RTL8723B).

use super::firmware_transport::{ControlIo, Error, Owner};
use super::rate_adaptation::signal_to_snr;
use super::rtl8192e_ra::{Ra, H2C_RSSI_SETTING};

/// `rtl8723au_rx_parse_phystats` signal with `rtl8723b_cck_rssi`: CCK
/// (`rxmcs < DESC_RATE_6M`) maps the LNA index of `cck_agc_rpt_ofdm_cfosho_a`
/// (byte 5, `[7:5]`) and its VGA index (`[4:0]`); an LNA index outside
/// {0, 1, 4, 6} reports 0 dBm exactly as Linux does. OFDM/HT use
/// `(cck_sig_qual_ofdm_pwdb_all >> 1) - 110` (byte 4).
pub fn signal(phy: &[u8], rate: u8) -> Option<i8> {
    if rate < 4 {
        let agc = *phy.get(5)?;
        let lna = agc >> 5;
        let vga = (agc & 31) as i8;
        let base: i8 = match lna {
            6 => -34,
            4 => -14,
            1 => 6,
            0 => 16,
            _ => return Some(0),
        };
        Some(base.wrapping_sub(2 * vga))
    } else {
        Some(((*phy.get(4)? >> 1) as i8).wrapping_sub(110))
    }
}

/// `h2c.rssi_report` truncated to 4 bytes for RTL8723B.
pub fn rssi_setting(macid: u8, rssi: u8) -> [u8; 4] {
    [H2C_RSSI_SETTING, macid, 0, rssi]
}

impl<I: ControlIo> Owner<I> {
    /// `rtl8xxxu_ra_iter` for the RTL8723BU: the 4-byte RSSI report, then a
    /// mask refresh when the level changed. `signal` is `-ewma_rssi_read`.
    /// Association/disassociation reuse the gen2 `ra_connect_8192e` /
    /// `ra_disconnect_8192e` sequences, which have no chip branch in Linux.
    pub(super) async fn ra_watchdog_8723b(&self, ra: &mut Ra, signal: i32) -> Result<(), Error> {
        let cmd = rssi_setting(0, signal_to_snr(signal));
        super::rtl8192e_init::h2c(self, &cmd).await?;
        if let Some(request) = ra.refresh(signal) {
            self.update_rate_mask_8192e(request).await?;
        }
        Ok(())
    }
}
