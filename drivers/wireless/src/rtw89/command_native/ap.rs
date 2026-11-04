// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! AP-role adapters on the one retained Native: the `ApController` source,
//! the AP packet owner (ordinary rings plus the CH9 high queue) and the
//! per-peer MACID binding every AP transmission is re-proved against.
//!
//! Linux: core.c `rtw89_core_tx_get_mac_id` (peer link MACID, else the
//! vif MACID), `rtw89_core_tx_update_desc_info` (`hiq` from
//! `IEEE80211_TX_CTL_SEND_AFTER_DTIM`, `port` only for HIQ), core.c
//! `rtw89_core_get_mgmt_rate`/`rtw89_core_get_data_rate` (band floor),
//! pci.c `rtw89_pci_init_tx_ring` for `RTW89_TXCH_CH9`.
use super::*;
use crate::rtw89::{
    ap_control::ApController, packet_core as packet, packet_format as format, power,
};
use alloc::vec::Vec;

/// AP packet binding: the vif address/port and every peer MACID currently
/// held by the `ApController` (`rtw89_core_sta_link_add` .. `_remove`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::rtw89) struct ApBinding {
    own: [u8; 6],
    port: u8,
    peers: Vec<([u8; 6], u8)>,
}
impl ApBinding {
    fn mac_id(&self, a1: &[u8]) -> Option<u8> {
        if a1[0] & 1 != 0 {
            return Some(0);
        }
        self.peers
            .iter()
            .find(|(addr, _)| addr[..] == *a1)
            .map(|&(_, macid)| macid)
    }
    /// TX admission: own TA; unicast data and Null frames only to a bound
    /// peer; management may address an unbound peer (probe/auth/assoc
    /// responses before `add_peer`, vif MACID as in Linux).
    pub(super) fn admits(&self, bytes: &[u8]) -> Result<(), packet::Error> {
        if bytes.len() < 24 || bytes[10..16] != self.own {
            return Err(packet::Error::Packet);
        }
        let management = bytes[0] & 0x0c == 0;
        if !management && self.mac_id(&bytes[4..10]).is_none() {
            return Err(packet::Error::Packet);
        }
        Ok(())
    }
}

impl Native {
    pub(in crate::rtw89) fn tx_stop_all(&self) -> u32 {
        if self.station_runtime.ap.is_some() {
            format::AP_STOP_ALL
        } else {
            format::STOP_ALL
        }
    }
    /// A fresh AP control owner for the retained factory identity.
    pub(in crate::rtw89) fn ap_controller(&self) -> Result<ApController, power::Error> {
        // The AP role (CH9 HIQ, AP TXWD, AP CAM) is RTL8852B-only.
        if self.chip != ChipId::Rtl8852B {
            return Err(power::Error::Unsupported);
        }
        self.ordinary_current()?;
        ApController::new(self.factory.as_ref().ok_or(power::Error::Unsupported)?)
            .map_err(|_| power::Error::Unsupported)
    }
    pub(in crate::rtw89) fn ap_active(&self) -> bool {
        self.station_runtime.ap.is_some()
    }
    /// Publish the AP rings (ordinary + CH9) for the vif on MACID0/port0.
    /// Station and monitor owners are mutually exclusive with this role.
    pub(in crate::rtw89) fn prepare_ap_packets(
        &mut self,
        own: [u8; 6],
        port: u8,
    ) -> Result<(), packet::Error> {
        if self.station_runtime.monitor.is_some()
            || self.station_runtime.core.is_some()
            || self.station_runtime.peer.is_some()
            || self.station_runtime.ap.is_some()
            || port != 0
            || self.identity().is_none_or(|identity| identity.mac() != own)
        {
            return Err(packet::Error::State);
        }
        self.ordinary_current()?;
        let qos_all = self.station_qos_all_allowed().unwrap_or(false);
        let ht = self.station_ht_allowed().unwrap_or(false);
        let he = self.station_he_allowed().unwrap_or(false);
        let rx = packet::RxPhy::from_programs(ht, he);
        // The binding is in place before ring publication so `start`/`stop`
        // see the AP stop mask (CH9 included).
        self.station_runtime.ap = Some(ApBinding {
            own,
            port,
            peers: Vec::new(),
        });
        match packet::Core::prepare_ap(&mut self.station_access(), own, qos_all, rx) {
            Ok(core) => {
                self.station_runtime.core = Some(core);
                Ok(())
            }
            Err(error) => {
                self.fail();
                Err(error)
            }
        }
    }
    /// Mirror an `ApController::add_peer` MACID into the packet binding.
    pub(in crate::rtw89) fn ap_bind_peer(
        &mut self,
        addr: [u8; 6],
        mac_id: u8,
    ) -> Result<(), power::Error> {
        self.ordinary_current()?;
        let ap = self
            .station_runtime
            .ap
            .as_mut()
            .ok_or(power::Error::Terminal)?;
        if mac_id == 0
            || usize::from(mac_id) >= crate::rtw89::ap_control::MAX_MAC_ID
            || addr[0] & 1 != 0
            || addr == ap.own
            || ap.peers.iter().any(|&(a, m)| a == addr || m == mac_id)
        {
            return Err(power::Error::Unsupported);
        }
        ap.peers.push((addr, mac_id));
        Ok(())
    }
    /// Withdraw a peer before `ApController::remove_peer` releases its MACID.
    pub(in crate::rtw89) fn ap_unbind_peer(&mut self, addr: [u8; 6]) {
        if let Some(ap) = self.station_runtime.ap.as_mut() {
            ap.peers.retain(|&(a, _)| a != addr);
        }
    }
    /// One AP frame. MACID is resolved here (`rtw89_core_tx_get_mac_id`);
    /// management and Null frames use the band floor rate, group data the
    /// floor rate on the vif MACID, unicast data firmware RA (when the
    /// signed RA program is granted) or the floor.
    pub(in crate::rtw89) fn submit_ap_packet(
        &mut self,
        bytes: &[u8],
        after_dtim: bool,
        report: bool,
        rate: u8,
    ) -> Result<u64, packet::Error> {
        let ap = self
            .station_runtime
            .ap
            .as_ref()
            .ok_or(packet::Error::State)?;
        if bytes.len() < 24 {
            return Err(packet::Error::Packet);
        }
        ap.admits(bytes)?;
        let mac_id = ap.mac_id(&bytes[4..10]).unwrap_or(0);
        let port = if after_dtim { ap.port } else { 0 };
        let lowest = self.lowest_rate();
        let management = bytes[0] & 0x0c == 0 || matches!(bytes[0], 0x48 | 0xc8);
        let adaptive = rate & format::FIRMWARE_RA != 0;
        if adaptive {
            if management
                || bytes[4] & 1 != 0
                || rate != format::FIRMWARE_RA | lowest
                || !self.station_firmware_ra_allowed()?
            {
                return Err(packet::Error::Access);
            }
        } else if rate != lowest {
            return Err(packet::Error::Access);
        }
        self.station_tx_current()?;
        let tx = format::ApTx {
            mac_id,
            port,
            after_dtim,
            report,
            rate,
        };
        self.packet_operation(|core, port| core.submit_ap(port, bytes, tx))
    }
}
