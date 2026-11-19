// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Distinct full ordinary packet/autonomous-response contract. No N22P/N22W
//! capability, calibrated-channel metadata or helper-generated bool upgrades.
use super::{
    be_qualification::Facts,
    calibration_policy::{Board, Calibration, Error},
    power,
};
const SCOPE: &[u8] = b"NARF RTL8922A N22O awake polled SCC ch1 legacy20 ordinary packet+response v1\0actual original checked reset/FW/System/TRX/CH12/rings/N22W complete DM/window/WONLY/init-late/channel-RFK owner; exact source/selected assets/current PCI+NORMAL/factory/CV/ACV/AID/GET_FEATURE; fresh original TX0/MGMT8 in-place ring indices0, same original RXQ/RPQ; no ring reset/replacement/reclaim; 512 never-repeated WP identities per queue, one ordinary MPDU in flight; actual BE fill_txdesc_v2 body/info/WP/address-info-v1, fixed1Mbps/20 nofallback/noRTS/noagg/noQoS/noHWhdr/security, ownTA and exact current BE MLME peer token; independent exact original4-byte BE RPQ plus actual TXBD RP required, neither is external AP/overair proof\0entire enabled calibration+TX+RX+WONLY+autonomous-response/protection/rate/power state and transitions measured jointly; complete source BE VIF/role/DMAC/CAM/CCTL/join/rate/crypto-off effects before actual packet enable; original qualified publication gates on register/DMA/RX/callbacks; host software Open/WPA2/CCMP, noAP/EHT/MLO/IRQ/DBCC/LPS\0";
/// Historical actual post-TRX response state. Its fields cannot be supplied
/// by a production caller, and it is never a current RF authority by itself.
#[derive(Clone, Copy)]
pub(super) struct Response {
    words: [u32; 3],
}
impl Response {
    #[cfg(any(test, feature = "kernel-test"))]
    pub(super) fn fixture() -> Self {
        Self { words: [0; 3] }
    }
    /// # Safety
    /// Same original exclusive supervisor/closed calibrated owner and BAR.
    /// No competing reset/host producer; current N22W and original PCI wrap
    /// the actual observations before ordinary-record lookup.
    pub(super) unsafe fn observe(
        radio: &super::native_radio_be::Radio,
        region: &narf_bus::MmioRegion,
        cap: &narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        cancel: &core::sync::atomic::AtomicBool,
    ) -> Result<Self, power::Error> {
        use core::sync::atomic::Ordering;
        radio.with_packet_preflight(|| {
            crate::rtw88::pci_park::invoke(cap, || {
                let mut words = [0u32; 3];
                for (slot, address) in words.iter_mut().zip([0x11008u64, 0x1008c, 0x10090]) {
                    closed(region)?;
                    if cancel.load(Ordering::Acquire) || address + 4 > region.len {
                        return Err(power::Error::Access);
                    }
                    // SAFETY: original current PCI+N22W scope and positive
                    // complete common MAC0 power before each actual word.
                    *slot = unsafe { region.read32(address) };
                    if *slot == u32::MAX {
                        return Err(power::Error::Gone);
                    }
                    closed(region)?;
                }
                if cancel.load(Ordering::Acquire) {
                    return Err(power::Error::Access);
                }
                Ok(Self { words })
            })
            .map_err(|_| power::Error::Access)?
        })
    }
    pub(super) fn check(&self, region: &narf_bus::MmioRegion) -> Result<(), power::Error> {
        for (address, value) in [0x11008u64, 0x1008c, 0x10090].into_iter().zip(self.words) {
            if address + 4 > region.len {
                return Err(power::Error::Access);
            }
            // SAFETY: native caller encloses this in actual current original
            // PCI+N22O invocation and first proves the common power tuple.
            if unsafe { region.read32(address) } != value {
                return Err(power::Error::Access);
            }
        }
        Ok(())
    }
}
pub(super) fn closed(region: &narf_bus::MmioRegion) -> Result<(), power::Error> {
    for (address, mask, value) in [
        (0x24u64, 0x1f00001f, 0x1f000000),
        (0x84, 0x03030300, 0x02010000),
        (0x10000, 0x30000000, 0),
        (0xb010, 0x80007fff, 0x80006fff),
        (0xb000, 0xb0, 0x30),
    ] {
        if address + 4 > region.len {
            return Err(power::Error::Access);
        }
        // SAFETY: only called inside original current PCI invocation; each
        // preceding complete common tuple proves the following bank readable.
        let seen = unsafe { region.read32(address) };
        if seen == u32::MAX || seen & mask != value {
            return Err(power::Error::Access);
        }
    }
    for (address, mask, value) in [(0xe348u64, u32::MAX, 0xd57ddf), (0xac, 0xffffff, 0x4003)] {
        if address + 4 > region.len {
            return Err(power::Error::Access);
        }
        // SAFETY: current original scope and full common power above.
        if unsafe { region.read32(address) } & mask != value {
            return Err(power::Error::Access);
        }
    }
    if region.len < 0x1087e {
        return Err(power::Error::Access);
    }
    // SAFETY: original current source and MAC0 power positively proved above.
    if unsafe { region.read16(0x1087c) } != 0x111 {
        return Err(power::Error::Access);
    }
    Ok(())
}
pub(super) fn identity(facts: &Facts<'_>, response: &Response) -> Result<[u8; 32], Error> {
    let mut hash = narf_crypto::sha256::Sha256::new();
    hash.update(SCOPE);
    hash.update(&super::be_wlan_qualification::identity(facts)?);
    hash.update(b"actual original post-TRX RESP1/RRSR0/RRSR1 words v1\0");
    for word in response.words {
        hash.update(&word.to_le_bytes());
    }
    for (name, bytes) in [
        (
            "ordinary-scope",
            include_bytes!("be_packet_qualification.rs").as_slice(),
        ),
        (
            "native-packet",
            include_bytes!("native_packet_be.rs").as_slice(),
        ),
        (
            "checked-packet",
            include_bytes!("checked_packet_8922a.rs").as_slice(),
        ),
        ("be-txwd", include_bytes!("txrx_be.rs").as_slice()),
        ("be-data", include_bytes!("tx_8922a.rs").as_slice()),
        (
            "be-completion",
            include_bytes!("completion_8922a.rs").as_slice(),
        ),
        ("be-link", include_bytes!("link_h2c_8922a.rs").as_slice()),
        ("be-station", include_bytes!("station_8922a.rs").as_slice()),
        ("be-cctl-g7", include_bytes!("cctl_g7.rs").as_slice()),
        ("be-mlme", include_bytes!("be_mlme.rs").as_slice()),
        (
            "be-native-mlme",
            include_bytes!("native_packet_be_mlme.rs").as_slice(),
        ),
        ("queue-state", include_bytes!("tx_transport.rs").as_slice()),
    ] {
        hash.update(&(name.len() as u32).to_le_bytes());
        hash.update(name.as_bytes());
        hash.update(&(bytes.len() as u32).to_le_bytes());
        hash.update(bytes);
    }
    Ok(hash.finalize())
}
pub(super) struct Ordinary {
    calibration: Calibration,
    response: Response,
}
impl Ordinary {
    pub(super) fn load(facts: &Facts<'_>, response: &Response) -> Result<Option<Self>, Error> {
        let board = Board::new_packet_be(facts, response)?;
        match Calibration::load_packet_be(board) {
            Ok(calibration) => {
                calibration.current()?;
                Ok(Some(Self {
                    calibration,
                    response: *response,
                }))
            }
            Err(Error::Firmware(narf_firmware::FirmwareError::NotFound)) => Ok(None),
            Err(e) => Err(e),
        }
    }
    pub(super) fn with_current<T, E: From<power::Error>>(
        &self,
        op: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.calibration.with_current_result(op)
    }
    pub(super) fn response(&self) -> Response {
        self.response
    }
}
#[cfg(any(test, feature = "kernel-test"))]
pub(super) mod tests {
    use super::*;
    pub(in crate::rtw89) fn revocable() -> (
        Ordinary,
        narf_capabilities::Cap<narf_firmware::FirmwareBlob, narf_capabilities::Read>,
    ) {
        let (factory, chip, assets, phycap, features) =
            super::super::be_qualification::tests::fixtures_version([0, 35, 8, 0]);
        let board = Board::new_packet_be(
            &Facts {
                device: super::super::be_qualification::tests::device(),
                factory: &factory,
                chip,
                assets: &assets,
                features,
                phycap: &phycap,
            },
            &Response { words: [0; 3] },
        )
        .unwrap();
        let (calibration, cap) =
            super::super::calibration_policy::tests::revocable_model_packet_be(board);
        (
            Ordinary {
                calibration,
                response: Response::fixture(),
            },
            cap,
        )
    }
}
