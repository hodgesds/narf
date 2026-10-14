//! MT7922 `WirelessNetIface` scaffold — compiling wiphy/netdev registration.
//!
//! This lands the control-plane skeleton the wireless stack needs: an
//! [`Mt76Iface`] that implements [`narf_net::Interface`] (so the netdev/TCP
//! stack sees the MAC + rings) and [`narf_wireless::WirelessNetIface`] (so the
//! nl80211 control plane sees a wiphy with bands + capabilities). Registration
//! goes through the same two calls iwlwifi uses:
//!
//!   * [`narf_net::iface::register`] — netdev identity.
//!   * [`narf_wireless::registry::register`] — wiphy registration.
//!
//! The datapath + MLME methods (`scan`/`associate`/`disassociate`/`set_config`)
//! return [`WirelessError::NotSupported`] for now: they depend on a live MCU
//! mailbox and the WFDMA data rings, which require real MediaTek silicon. QEMU
//! emulates no such device, so those paths are **hardware-gated** and cannot be
//! exercised here. See `PLAN.md` ("next steps for full association").

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use async_trait::async_trait;
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::iface::{HwCaps, WirelessBand, WirelessIfaceInfo, WirelessModes};
use narf_wireless::{
    AssociateRequest, ScanRequest, WirelessConfig, WirelessError, WirelessNetIface,
};
use narf_wireless::scan::BssInfo;

use crate::mt7921::name_for;

/// One control-plane interface for a bound MT7921/MT7922/MT7961 radio.
///
/// Holds the netdev identity (name + MAC + rings) and the static wiphy data
/// (bands + capabilities). The TX/RX rings are the `narf-net` frame rings; the
/// real device DMA rings live in the `mt7921::dma`/`txrx` path and are not yet
/// bridged to these (hardware-gated).
pub struct Mt76Iface {
    name: String,
    mac: [u8; 6],
    /// Matched (effective) PCI device id — determines the band set.
    effective_did: u16,
    rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

impl core::fmt::Debug for Mt76Iface {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mt76Iface")
            .field("name", &self.name)
            .field("mac", &self.mac)
            .field("effective_did", &format_args!("{:#06x}", self.effective_did))
            .finish_non_exhaustive()
    }
}

impl Mt76Iface {
    /// Build the iface for a bound radio. Allocates the netdev frame rings and
    /// seeds the static wiphy data from the matched device id.
    pub fn new(effective_did: u16, mac: [u8; 6]) -> Self {
        // Create the netdev frame-ring endpoints so the Interface contract is
        // satisfied. The device-side halves (the DMA-backed producer/consumer
        // bridge) land with the WFDMA datapath; the stack-facing halves are
        // held here.
        let (tx_prod, _tx_cons) = channel::<Frame, TX_RING_N>();
        let (_rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
        Self {
            name: String::from(name_for(effective_did)),
            mac,
            effective_did,
            rx_ring: IrqSafeSpinLock::new(Some(rx_cons)),
            tx_ring: IrqSafeSpinLock::new(Some(tx_prod)),
        }
    }

    /// Supported bands for the matched chip. All CONNAC2 parts here cover
    /// 2.4 GHz + 5 GHz; the Wi-Fi 6E parts (MT7922/MT7961/MT7920) add 6 GHz.
    pub fn bands(&self) -> Vec<WirelessBand> {
        use crate::mt7921::{MTK_DEV_MT7920, MTK_DEV_MT7922, MTK_DEV_MT7961};
        let mut bands = vec![
            WirelessBand {
                freq_mhz: 2400,
                channels: (1..=13).collect(),
            },
            WirelessBand {
                freq_mhz: 5000,
                channels: vec![
                    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132,
                    136, 140, 144, 149, 153, 157, 161, 165,
                ],
            },
        ];
        if matches!(
            self.effective_did,
            MTK_DEV_MT7922 | MTK_DEV_MT7961 | MTK_DEV_MT7920
        ) {
            bands.push(WirelessBand {
                freq_mhz: 6000,
                channels: (1..=233u32).step_by(4).collect(),
            });
        }
        bands
    }
}

impl Interface for Mt76Iface {
    fn name(&self) -> &str {
        &self.name
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        // No association yet (hardware-gated); the link comes up when the MLME
        // path completes a 4-way handshake on real silicon.
        false
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        &self.rx_ring
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        &self.tx_ring
    }
}

#[async_trait]
impl WirelessNetIface for Mt76Iface {
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        // The whole CONNAC2 family (Wi-Fi 6 MT7921 + Wi-Fi 6E MT7922/61/20) is
        // HE-capable; the 6E parts differ only in the extra 6 GHz band, which
        // `bands()` already reflects. No EHT/Wi-Fi 7 on this family.
        WirelessIfaceInfo {
            base_name: self.name.clone(),
            base_mac: self.mac,
            bands: self.bands(),
            modes: WirelessModes::STATION,
            hw_caps: HwCaps {
                ht_supported: true,
                vht_supported: true,
                // CONNAC2 is Wi-Fi 6 (HE); the 6E parts additionally open the
                // 6 GHz band but remain HE (no EHT/Wi-Fi 7 on this family).
                he_supported: true,
                eht_supported: false,
            },
        }
    }

    async fn scan(&self, _req: ScanRequest) -> Result<Vec<BssInfo>, WirelessError> {
        // Needs a live MCU mailbox (SCAN_REQ) + RX event path. Hardware-gated.
        Err(WirelessError::NotSupported)
    }

    async fn associate(&self, _req: AssociateRequest) -> Result<(), WirelessError> {
        // Needs MCU STA_REC_UPDATE + the WFDMA datapath. Hardware-gated.
        Err(WirelessError::NotSupported)
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        Err(WirelessError::NotSupported)
    }

    async fn set_config(&self, _cfg: WirelessConfig) -> Result<(), WirelessError> {
        // Channel/tx-power programming is an MCU command. Hardware-gated.
        Err(WirelessError::NotSupported)
    }
}

/// Register a bound radio's control-plane iface: the netdev identity with the
/// net stack and the wiphy with the wireless registry. Mirrors the iwlwifi
/// registration path. Returns the `Arc` so callers can retain it.
///
/// `send` is the net-stack TX hook (the `mt7921::pci::send_frame_unimpl`
/// placeholder until the DMA datapath lands).
pub fn register_iface(
    effective_did: u16,
    mac: [u8; 6],
    send: narf_net::iface::SendFn,
) -> Arc<Mt76Iface> {
    // Netdev identity so the kernel-side stack can see the MAC.
    let _name = narf_net::iface::register("wlan%d", mac, send);
    // Wiphy registration so the nl80211 control plane lists the radio.
    let iface = Arc::new(Mt76Iface::new(effective_did, mac));
    narf_wireless::registry::register(iface.clone());
    iface
}

#[cfg(any(test, feature = "builtin"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_mt76_iface_wiphy_bands_6ghz() -> TestResult {
        // MT7922 is Wi-Fi 6E → must advertise the 6 GHz band.
        let iface = Mt76Iface::new(crate::mt7921::MTK_DEV_MT7922, [0x00; 6]);
        let info = iface.get_wireless_info();
        if !info.modes.contains(WirelessModes::STATION) {
            return TestResult::Fail("mt76 wiphy missing STATION mode");
        }
        let has_6ghz = info.bands.iter().any(|b| b.freq_mhz == 6000);
        let has_24 = info.bands.iter().any(|b| b.freq_mhz == 2400);
        if has_6ghz && has_24 && info.hw_caps.he_supported {
            TestResult::Pass
        } else {
            TestResult::Fail("mt76 MT7922 wiphy missing 2.4/6 GHz band or HE cap")
        }
    }
    kernel_test_in!("drivers/wireless/mt76", smoke_mt76_iface_wiphy_bands_6ghz);

    fn smoke_mt76_iface_netdev_identity() -> TestResult {
        // The Interface MAC + name must round-trip from the bound radio.
        let mac = [0x02, 0x00, 0xde, 0xad, 0xbe, 0xef];
        let iface = Mt76Iface::new(crate::mt7921::MTK_DEV_MT7922, mac);
        if iface.mac() == mac && iface.mtu() == 1500 && !iface.name().is_empty() {
            TestResult::Pass
        } else {
            TestResult::Fail("mt76 netdev identity did not round-trip")
        }
    }
    kernel_test_in!("drivers/wireless/mt76", smoke_mt76_iface_netdev_identity);
}
