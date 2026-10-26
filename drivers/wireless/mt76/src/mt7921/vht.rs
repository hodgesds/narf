//! Bounded5-GHz CONNAC2 VHT1SS implementation profile and native records.
//! Linux mt7921_init_work/mt76_init_sband register <=80-MHz VHT; the actual
//! NIC TLV must still report HT/VHT/5GHz/NSS. max_bw stays an opaque byte.
use super::{
    association::TxPermission,
    firmware_transport::{Error, RadioInfo},
};
use alloc::{vec, vec::Vec};
use narf_wireless::association::phy::{
    self, ApElements, HtGi, HtWidth, LocalHt, LocalPhy, LocalVht,
};

pub(crate) fn qualified(info: RadioInfo) -> bool {
    let caps = info.capabilities.phy;
    caps.ht && caps.vht && caps.bands & 2 != 0 && (1..=2).contains(&caps.spatial_streams)
}
pub(crate) fn local(info: RadioInfo) -> Result<LocalPhy, Error> {
    if !qualified(info) {
        return Err(Error::UnsupportedFirmware);
    }
    let ht = local_ht();
    let vht =
        LocalVht::new(0xfffc, 0xfffc, true, true, 0).map_err(|_| Error::UnsupportedFirmware)?;
    LocalPhy::vht80(ht, vht).map_err(|_| Error::UnsupportedFirmware)
}
fn local_ht() -> LocalHt {
    let mcs = [255, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    LocalHt::new(
        mcs,
        mcs,
        HtWidth::TwentyForty,
        HtGi {
            rx20: true,
            tx20: true,
            rx40: true,
            tx40: true,
        },
        0,
        7,
    )
    .expect("fixed implemented HT companion profile")
}
pub(crate) fn ht_capability() -> [u8; 26] {
    local_ht().capability_body()
}
pub(crate) fn ht_fallback(info: RadioInfo, wide: bool) -> Result<LocalPhy, Error> {
    if !info.capabilities.phy.ht || !(1..=2).contains(&info.capabilities.phy.spatial_streams) {
        return Err(Error::UnsupportedFirmware);
    }
    if wide {
        LocalPhy::ht40(local_ht()).map_err(|_| Error::UnsupportedFirmware)
    } else {
        let mcs = [255, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let ht = LocalHt::new(
            mcs,
            mcs,
            HtWidth::Twenty,
            HtGi {
                rx20: true,
                tx20: true,
                rx40: false,
                tx40: false,
            },
            0,
            7,
        )
        .map_err(|_| Error::UnsupportedFirmware)?;
        LocalPhy::ht20(ht).map_err(|_| Error::UnsupportedFirmware)
    }
}
pub(crate) fn capability(info: RadioInfo) -> Option<[u8; 12]> {
    qualified(info).then(|| {
        LocalVht::new(0xfffc, 0xfffc, true, true, 0)
            .unwrap()
            .capability_body()
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Profile {
    ap: ApElements,
    capability: u32,
    peer_rx: u16,
    peer_tx: u16,
    width: u8,
    center: u8,
}
impl Profile {
    pub(crate) fn negotiated(n: &phy::Negotiated, ies: &[u8]) -> Result<Self, Error> {
        let vht = n.vht().ok_or(Error::UnsupportedFirmware)?;
        if n.ht().operation().protection() != 0 {
            return Err(Error::UnsupportedFirmware);
        }
        let width = match n.width() {
            phy::Width::Twenty => 0,
            phy::Width::Forty => 1,
            phy::Width::Eighty => 2,
        };
        Ok(Self {
            ap: ApElements::parse(ies).map_err(|_| Error::Bounds)?,
            // Peer receive aggregation limit and transmit SGI intersection;
            // optional LDPC/STBC/beamforming/160 remain unimplemented.
            capability: (vht.peer_capability() & (7 << 23)) | (u32::from(vht.tx_sgi80()) << 5),
            peer_rx: vht.tx_mcs_map(),
            peer_tx: phy::intersect_maps(vht.rx_mcs_map(), vht.peer_tx_mcs_map()),
            width,
            center: n.center_channel(),
        })
    }
    pub(crate) fn width(self) -> u8 {
        self.width
    }
    pub(crate) fn center(self) -> u8 {
        self.center
    }
    pub(crate) fn ampdu_factor(self) -> u8 {
        ((self.capability >> 23) & 7) as u8
    }
    pub(crate) fn matches(self, ies: &[u8]) -> bool {
        ApElements::parse(ies).is_ok_and(|ap| ap == self.ap)
    }
    pub(crate) fn state(self) -> u8 {
        self.width
    } // RX NSS1 -> high nibble0.
    pub(crate) fn sta(self) -> Vec<u8> {
        let mut bytes = vec![10, 0, 16, 0]; // CONNAC2 retains the four-byte tail.
        bytes.extend_from_slice(&self.capability.to_le_bytes());
        bytes.extend_from_slice(&self.peer_rx.to_le_bytes());
        bytes.extend_from_slice(&self.peer_tx.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes
    }
    pub(crate) fn wtbl(self) -> [u8; 12] {
        [3, 0, 12, 0, 0, 0, 1, 0, 0, 0, 0, 0]
    }
    pub(crate) fn rlm(self, primary: u8, chains: u8) -> Vec<u8> {
        let mut bytes = vec![0; 20];
        bytes[4..8].copy_from_slice(&[2, 0, 16, 0]);
        bytes[8] = primary;
        bytes[9] = self.center;
        bytes[11] = self.width;
        bytes[12] = 1;
        bytes[13] = chains;
        bytes[14] = 1;
        bytes[15] = if self.width != 0 { 4 } else { 0 };
        bytes[16] = if primary < self.center {
            1
        } else if primary > self.center {
            3
        } else {
            0
        };
        bytes[17] = 1;
        bytes
    }
    pub(crate) fn permits(self, p: TxPermission) -> bool {
        self.width == p.native_width() && self.center == p.center_channel()
    }
    pub(crate) fn receive_allowed(self, phy: Option<u32>) -> bool {
        receive_allowed(self.width, phy, true)
    }
}
pub(crate) fn receive_allowed(selected_width: u8, phy: Option<u32>, vht: bool) -> bool {
    let Some(v) = phy else {
        return true;
    };
    let mode = (v >> 24) & 15;
    let width = (v >> 12) & 7;
    let rate = v & 127;
    let nsts = ((v >> 7) & 7) + 1;
    let stbc = (v >> 22) & 3;
    if v & (1 << 11) != 0 || stbc != 0 || width > u32::from(selected_width) {
        return false;
    }
    match mode {
        1 => width == 0 && (8..=15).contains(&rate) && (v >> 15) & 3 == 0,
        // Native OFDM hardware codes8..15; basic6Mbps is11.
        2 => nsts == 1 && rate <= 7 && width <= 1 && (v >> 15) & 3 <= 1,
        4 => vht && nsts == 1 && rate <= 7 && (v >> 15) & 3 <= 1,
        _ => false, // no CCK/greenfield/HE or unimplemented optional mode.
    }
}
