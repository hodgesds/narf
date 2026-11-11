//! rtlwifi PCIe transport — device-ID table, BAR mapping, probe.
//!
//! Linux per-chip `rtl_hal_cfg.bar_id` selects BAR2 for the supported PCIe
//! parts. It is mapped as Device memory for all control-register accesses.
//!
//! ## Linux reference
//!
//! - `rtlwifi/pci.c::rtl_pci_probe` — probe entry, per-chip BAR2 ioremap
//! - `rtlwifi/pci.c::rtl_pci_id_tbl` — `pci_device_id` table
//! - `rtlwifi/pci.h` — queue / descriptor constants

#![allow(dead_code)]

extern crate alloc;

use alloc::{boxed::Box, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};

use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_ipc::{channel, Consumer, Producer};
use narf_lib::sync::IrqSafeSpinLock;
use narf_net::{Frame, Interface, RX_RING_N, TX_RING_N};
use narf_wireless::{
    AssociateRequest, BssInfo, ScanRequest, WirelessConfig, WirelessError, WirelessIfaceInfo,
    WirelessNetIface,
};

use super::efuse;
use super::firmware_native::PciIo;
use super::firmware_transport::Owner as FirmwareOwner;
use super::irq;
use super::mac;
use super::power;
use super::regs::*;

/// A bound rtlwifi PCIe device.  Holds BAR2 + MAC + device-ID.
pub struct RtlwifiDevice {
    /// Retained bus identity; a repeat probe must not park the active owner.
    pub(crate) bus_addr: narf_bus::BusAddr,
    pub(super) name: &'static str,
    pub registers: MmioRegion,
    pub mac: [u8; MAC_ADDR_LEN],
    pub device_id: u16,
    /// One retained authenticated firmware attempt for the qualified 8188EE profile.
    pub(super) firmware: Option<Arc<FirmwareOwner<PciIo>>>,
    pub(super) prepared: Option<Arc<super::prepare_native::Retained>>,
    pub(super) factory: Option<Arc<super::efuse::Factory>>,
    pub(super) native: Option<Arc<super::interface::Native>>,
    pub link_up: AtomicBool,
    pub rx_ring: IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>,
    pub tx_ring: IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>,
}

impl RtlwifiDevice {
    fn current_firmware(&self) -> Option<Arc<FirmwareOwner<PciIo>>> {
        self.native
            .as_ref()
            .map(|native| native.native_firmware())
            .or_else(|| self.firmware.clone())
    }
    /// Provisioning metadata only; no measured gain or transmit permission.
    pub fn ht20_request(&self) -> Result<super::Ht20Request, super::channel_power::Error> {
        self.ht20_request_on_channel(1)
    }
    /// Per-channel provisioning metadata; this grants no RF permission.
    pub fn ht20_request_on_channel(
        &self,
        channel: u8,
    ) -> Result<super::Ht20Request, super::channel_power::Error> {
        if !(1..=11).contains(&channel) {
            return Err(super::channel_power::Error::Policy);
        }
        let factory = self
            .factory
            .as_ref()
            .ok_or(super::channel_power::Error::Identity)?;
        let base = super::channel_power::Calibration::load_registered(factory)?;
        let firmware = self
            .current_firmware()
            .and_then(|f| f.identity())
            .ok_or(super::channel_power::Error::Identity)?;
        firmware
            .invoke(|| Ok(()))
            .map_err(|_| super::channel_power::Error::Authority)?;
        Ok(if channel == 1 {
            super::ht::request(&base, firmware)
        } else {
            super::ht::request_on_channel(&base, firmware, channel)
        })
    }
    /// Exact selected automatic-diversity program qualification metadata.
    /// This request performs no radio I/O and supplies no antenna permission.
    pub fn antenna_diversity_request(
        &self,
    ) -> Result<super::AntennaDiversityRequest, super::channel_power::Error> {
        let firmware = self
            .current_firmware()
            .and_then(|f| f.identity())
            .ok_or(super::channel_power::Error::Identity)?;
        self.native
            .as_ref()
            .ok_or(super::channel_power::Error::Identity)?
            .antenna_diversity_request(firmware)
            .map_err(|_| super::channel_power::Error::Authority)
    }
    /// Exact retained full-program thermal qualification request. This is
    /// provisioning metadata and grants no gain, calibration or RF authority.
    pub fn thermal_tracking_request(
        &self,
    ) -> Result<super::ThermalTrackingRequest, super::channel_power::Error> {
        let firmware = self
            .current_firmware()
            .and_then(|f| f.identity())
            .ok_or(super::channel_power::Error::Identity)?;
        self.native
            .as_ref()
            .ok_or(super::channel_power::Error::Identity)?
            .thermal_tracking_request(firmware)
            .map_err(|_| super::channel_power::Error::Authority)
    }
    /// Pure request for the currently selected private NEPC/NEHT program.
    /// Provision in Passive after initial service selected its actual profile.
    pub fn rts_cts_request(&self) -> Result<super::ProtectionRequest, super::channel_power::Error> {
        let native = self
            .native
            .as_ref()
            .ok_or(super::channel_power::Error::Identity)?;
        let storage = native
            .prepared
            .try_lock()
            .ok_or(super::channel_power::Error::Authority)?;
        let owner = storage
            .as_ref()
            .ok_or(super::channel_power::Error::Identity)?;
        let firmware = self
            .current_firmware()
            .and_then(|f| f.identity())
            .ok_or(super::channel_power::Error::Identity)?;
        owner
            .station_protection_request(firmware)
            .map_err(|_| super::channel_power::Error::Authority)
    }
    /// Exact full20/40 qualification request; no radio I/O or permission.
    pub fn ht40_request(
        &self,
        primary: u8,
        secondary: u8,
    ) -> Result<super::Ht40Request, super::channel_power::Error> {
        let geometry = super::ht::Geometry::new(primary, secondary)
            .map_err(|_| super::channel_power::Error::Policy)?;
        let factory = self
            .factory
            .as_ref()
            .ok_or(super::channel_power::Error::Identity)?;
        let base = super::channel_power::Calibration::load_registered(factory)?;
        let firmware = self
            .current_firmware()
            .and_then(|f| f.identity())
            .ok_or(super::channel_power::Error::Identity)?;
        firmware
            .invoke(|| Ok(()))
            .map_err(|_| super::channel_power::Error::Authority)?;
        Ok(super::ht::wide_request(&base, firmware, geometry))
    }
    /// Exact-channel fallback provisioning metadata; grants no radio permission.
    pub fn rate_fallback_request(
        &self,
        channel: u8,
    ) -> Result<super::RateFallbackRequest, super::channel_power::Error> {
        if !(1..=11).contains(&channel) {
            return Err(super::channel_power::Error::Policy);
        }
        let factory = self
            .factory
            .as_ref()
            .ok_or(super::channel_power::Error::Identity)?;
        let base = super::channel_power::Calibration::load_registered(factory)?;
        let firmware = self
            .current_firmware()
            .and_then(|firmware| firmware.identity())
            .ok_or(super::channel_power::Error::Identity)?;
        firmware
            .invoke(|| Ok(()))
            .map_err(|_| super::channel_power::Error::Authority)?;
        Ok(if channel == 1 {
            super::fallback::request(&base, firmware)
        } else {
            super::fallback::request_on_channel(&base, firmware, channel)
        })
    }
    /// Firmware-ready is diagnostic CPU readiness, never station readiness.
    pub fn firmware_status(&self) -> Option<super::firmware_transport::Status> {
        self.current_firmware().map(|owner| owner.status())
    }
    /// Inactive descriptor/LLT readiness remains below RF and packet admission.
    /// None covers unallocated state or async preparation holding its guard.
    pub fn native_preparation_status(&self) -> Option<super::prepare::Phase> {
        let prepared = self.prepared.as_ref()?.try_lock()?;
        prepared.as_ref().map(|owner| owner.phase())
    }
}

impl Interface for RtlwifiDevice {
    fn name(&self) -> &str {
        self.native
            .as_ref()
            .map_or(self.name, |native| native.name())
    }
    fn mac(&self) -> [u8; 6] {
        self.mac
    }
    fn mtu(&self) -> u32 {
        1500
    }
    fn link_up(&self) -> bool {
        self.native.as_ref().map_or_else(
            || self.link_up.load(Ordering::Acquire),
            |native| native.link_up(),
        )
    }
    fn rx_ring(&self) -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>> {
        self.native
            .as_ref()
            .map_or(&self.rx_ring, |native| native.rx_ring())
    }
    fn tx_ring(&self) -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>> {
        self.native
            .as_ref()
            .map_or(&self.tx_ring, |native| native.tx_ring())
    }
}

#[async_trait::async_trait]
impl WirelessNetIface for RtlwifiDevice {
    fn rts_threshold(&self) -> Option<u32> {
        self.native.as_ref()?.rts_threshold()
    }
    fn set_rts_threshold(&self, threshold: u32) -> Result<(), i32> {
        self.native
            .as_ref()
            .ok_or(-95)?
            .set_rts_threshold(threshold)
    }
    fn supports_handshake_offload(&self) -> bool {
        self.native
            .as_ref()
            .is_some_and(|native| native.supports_handshake_offload())
    }
    fn reports_disconnect_events(&self) -> bool {
        self.native.is_some()
    }
    fn supports_scan_dwell(&self) -> bool {
        self.native.is_some()
    }
    fn connected_bssid(&self) -> Option<[u8; 6]> {
        self.native.as_ref()?.connected_bssid()
    }
    fn cipher_suites(&self) -> &'static [u32] {
        self.native
            .as_ref()
            .map_or(&[], |native| native.cipher_suites())
    }
    fn scan_information_elements(&self, bssid: [u8; 6]) -> Option<alloc::vec::Vec<u8>> {
        self.native.as_ref()?.scan_information_elements(bssid)
    }
    fn get_wireless_info(&self) -> WirelessIfaceInfo {
        if let Some(native) = &self.native {
            return native.get_wireless_info();
        }
        WirelessIfaceInfo {
            base_name: self.name().into(),
            base_mac: self.mac(),
            bands: alloc::vec![],
            modes: narf_wireless::iface::WirelessModes::STATION,
            hw_caps: narf_wireless::iface::HwCaps {
                ht_supported: false,
                vht_supported: false,
                he_supported: false,
                eht_supported: false,
            },
        }
    }

    async fn scan(&self, req: ScanRequest) -> Result<alloc::vec::Vec<BssInfo>, WirelessError> {
        match &self.native {
            Some(native) => native.scan(req).await,
            None => Err(WirelessError::NotSupported),
        }
    }

    async fn associate(&self, req: AssociateRequest) -> Result<(), WirelessError> {
        match &self.native {
            Some(native) => native.associate(req).await,
            None => Err(WirelessError::NotSupported),
        }
    }

    async fn disassociate(&self) -> Result<(), WirelessError> {
        if let Some(native) = &self.native {
            return native.disassociate().await;
        }
        self.link_up.store(false, Ordering::Release);
        Ok(())
    }

    async fn set_config(&self, cfg: WirelessConfig) -> Result<(), WirelessError> {
        match &self.native {
            Some(native) => native.set_config(cfg).await,
            None => Err(WirelessError::NotSupported),
        }
    }
}

impl core::fmt::Debug for RtlwifiDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RtlwifiDevice")
            .field("device_id", &self.device_id)
            .field("mac", &self.mac)
            .finish_non_exhaustive()
    }
}

/// Errors from the probe path.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProbeError {
    /// PCI access failed or bus mastering could not be verifiably parked.
    PciAccess,
    RegisterBarMapFailed,
    Efuse(efuse::EfuseError),
    PowerOn(power::PwrSeqError),
    MacInit(mac::MacInitError),
}

impl From<power::PwrSeqError> for ProbeError {
    fn from(e: power::PwrSeqError) -> Self {
        ProbeError::PowerOn(e)
    }
}

impl From<mac::MacInitError> for ProbeError {
    fn from(e: mac::MacInitError) -> Self {
        ProbeError::MacInit(e)
    }
}

/// Single-device static slot.
#[path = "pci_bindings.rs"]
mod pci_bindings;
static CONTROLLERS: IrqSafeSpinLock<pci_bindings::Bindings> =
    IrqSafeSpinLock::new(pci_bindings::Bindings::new());

/// Register one PCI-match entry per supported device ID.
pub fn register_pci_driver() {
    for &did in ALL_DEV_IDS {
        narf_bus::register_pci_driver(narf_bus::PciMatch {
            name: name_for(did),
            kind: narf_bus::MatchKind::VendorDevice {
                vendor: REALTEK_VENDOR,
                device: did,
            },
            probe,
        });
        narf_bus::register_pci_remove(name_for(did), remove);
    }
}

/// Linux v7.2 `pci.c::rtl_pci_remove`: `ieee80211_unregister_hw` (netdev
/// withdrawal, then `rtl_op_stop` → `rtl_pci_stop`: `disable_interrupt`
/// and `rtl88ee_card_disable`), `rtl_pci_deinit` (`free_irq` /
/// `pci_disable_msi`) and only then the DMA rings are freed. Here the
/// rings are released only after the card-disable quiescence proof;
/// unproven mappings stay pinned and the address is quarantined.
fn remove(device: BusDevice, _cap: Cap<BusDeviceCap, Write>) {
    let Some(owner) = detach(device.addr) else {
        return;
    };
    narf_scheduler::spawn(async move {
        let reclaimed = finish_removal(owner, device.addr).await;
        narf_console::klog!(
            "rtlwifi: removed; DMA {}\n",
            if reclaimed {
                "reclaimed"
            } else {
                "pinned, address quarantined"
            }
        );
    });
}
/// Take the bound owner for `address` out of the controller slot and
/// quarantine the address until its removal proves DMA idle.
fn detach(address: narf_bus::BusAddr) -> Option<RtlwifiDevice> {
    CONTROLLERS.lock().detach(address)
}
async fn finish_removal(owner: RtlwifiDevice, address: narf_bus::BusAddr) -> bool {
    let reclaimed = match &owner.native {
        Some(native) => native.remove().await,
        None => {
            // Diagnostic (non-native) profiles never publish DMA.
            let name = owner.name;
            if !name.is_empty() {
                narf_wireless::registry::unregister(name);
                narf_net::iface::unregister(name);
            }
            true
        }
    };
    drop(owner);
    if reclaimed {
        CONTROLLERS.lock().reclaimed(address);
    }
    reclaimed
}

/// PCI probe callback.
pub fn probe(device: BusDevice, cap: Cap<BusDeviceCap, Write>) -> Result<(), narf_bus::ProbeError> {
    match CONTROLLERS.lock().reserve(device.addr) {
        pci_bindings::Admission::Bound => return Ok(()),
        pci_bindings::Admission::Blocked => return Err(narf_bus::ProbeError::BadDevice),
        pci_bindings::Admission::Initialize => {}
    }
    // SAFETY: caller holds exclusive BusDeviceCap for this device.
    let result = unsafe { bring_up(&device, &cap) };
    let dev = match result {
        Ok(d) => d,
        Err(_) => {
            CONTROLLERS.lock().abandon(device.addr);
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };

    let name = dev.name;
    let address = dev.bus_addr;
    let mac = dev.mac;
    let did = dev.device_id;
    let native = dev.native.clone();
    if !CONTROLLERS.lock().commit(dev) {
        return Err(narf_bus::ProbeError::BadDevice);
    }

    narf_drivers::record_bound(narf_drivers::BoundDriver {
        name: alloc::string::String::from(name_for(did)),
        kind: narf_drivers::BoundKind::Net,
        pci_vid: Some(device.id.vendor),
        pci_did: Some(device.id.device),
        domain: narf_drivers::BoundKind::Net.default_domain(),
    });

    if let Some(native) = native.clone() {
        // The controller already retains the complete device before either
        // registry can expose it. Current net authority is required before
        // the station facade may open native DMA.
        super::interface::publish(native).map_err(|_| narf_bus::ProbeError::BadDevice)?;
    } else {
        narf_net::iface::register(name, mac, send_frame_unimpl);
    }
    if let Some(native) = native {
        // Initial boot and a later missing-input retry share the exact same
        // retained binding and async admission lock.
        narf_scheduler::spawn(async move {
            if let Err(error) = drive_scheduled(
                120,
                || {
                    with_controller_at(address, |dev| {
                        dev.native
                            .as_ref()
                            .is_some_and(|bound| Arc::ptr_eq(bound, &native))
                            && provisioning(Some(dev)).is_ok()
                    })
                    .unwrap_or(false)
                },
                || native.provision(),
                || narf_time::sleep_cycles(narf_time::wall::ns_to_cycles(500_000_000)),
            )
            .await
            {
                use core::fmt::Write;
                let _ = writeln!(
                    narf_console::Writer,
                    "rtlwifi-8188ee native preparation: {:?}",
                    error
                );
            }
        });
    }
    Ok(())
}

/// Park PCI DMA, map BAR2, apply the existing power table and read factory
/// EFUSE identity with device IRQs masked. Retains the qualified 8188EE
/// firmware owner; probe starts it asynchronously after publishing ownership.
/// Its one-shot continuation retains LLT/native rings and qualifies RF/BB/MAC.
/// Public native station control separately gates packet DMA and association
/// under signed board/current regulatory policy; device IRQs remain masked.
///
/// # Safety
/// Caller owns the device's PCI configuration and BARs exclusively.
pub unsafe fn bring_up(
    device: &BusDevice,
    cap: &Cap<BusDeviceCap, Write>,
) -> Result<RtlwifiDevice, ProbeError> {
    let did = device.id.device;
    // Retained native station profiles: RTL8188EE, (no BT coexistence)
    // RTL8821AE, (2.4 GHz, no BT coexistence, EFUSE TX power present)
    // RTL8192EE, (qualified RF_1T1R / RF_2T2R version, provisioned map,
    // no BT coexistence) RTL8192CE / RTL8188CE and (qualified version,
    // provisioned map, path-A TX power; BT-coexist boards included: the
    // coexistence owner runs) RTL8723BE and (non-test chip, autoloaded map,
    // a PROM MAC/PHY mode whose function bandset holds 2.4 GHz) RTL8192DE.
    // Every other matched chip stays diagnostic.
    let rtl8192ce = super::rtl8192ce::is_8192ce(did);
    let rtl8723be = did == RTL_DEV_8723BE;
    let rtl8192de = did == RTL_DEV_8192DE;
    let retained = matches!(
        did,
        RTL_DEV_8188EE | RTL_DEV_8821AE | RTL_DEV_8192EE | RTL_DEV_8723BE | RTL_DEV_8192DE
    ) || rtl8192ce;
    let (registers, factory) = crate::rtw88::pci_park::invoke(cap, || -> Result<_, ProbeError> {
        let registers = crate::rtw88::pci_park::map_bar_control(device, cap, 2)
            .map_err(|_| ProbeError::RegisterBarMapFailed)?;
        if registers.len < REG_EFUSE_ACCESS + 1
            || (device.id.device == RTL_DEV_8188EE && registers.len < 0x2000)
            || (device.id.device == RTL_DEV_8821AE
                && registers.len < super::rtl8821ae::MMIO_SIZE as u64)
            || (device.id.device == RTL_DEV_8192EE
                && registers.len < super::rtl8192ee::MMIO_SIZE as u64)
            || (rtl8192ce && registers.len < super::rtl8192ce::MMIO_SIZE as u64)
            || (rtl8723be && registers.len < super::rtl8723be::MMIO_SIZE as u64)
        {
            return Err(ProbeError::RegisterBarMapFailed);
        }

        if retained {
            // SAFETY: this exact exclusive function owns the validated BAR2;
            // its packet DMA is parked before any power/EFUSE access.
            let control = unsafe { PciIo::new(*device, *cap, registers) };
            control.disable_aspm().map_err(|_| ProbeError::PciAccess)?;
        }

        // Power-on (cardemu → active).  Optional — chips not in the table
        // are tolerated for forward compat; the rest fall through to MAC
        // init unchanged.
        if power::power_on_table_for(did).is_some() {
            // SAFETY: BAR2 mapped, no other thread holds the chip.
            unsafe { power::power_on(&registers, did) }?;
        }

        // The diagnostic identity stage does not own packet DMA or an IRQ
        // handler. Keep interrupt masks clear and defer MAC TX/RX/ring setup.
        // SAFETY: BAR2 mapped and owned.
        unsafe { irq::disable_interrupts_for(&registers, did) };

        let function = match device.addr {
            narf_bus::BusAddr::Pcie(addr) => addr.function,
            _ => return Err(ProbeError::Efuse(efuse::EfuseError::UnsupportedChip)),
        };
        // rtl8723ae/hw.c::rtl8723e_read_eeprom_info selects the Wi-Fi EFUSE
        // bank (REG_EFUSE_TEST[9:8] = EFUSE_WIFI_SEL_0) before reading it.
        if did == RTL_DEV_8723AE {
            use super::rtl8723ae::adapter::{efuse_test_wifi_sel, REG_EFUSE_TEST};
            // SAFETY: BAR2 mapped (length covers REG_EFUSE_ACCESS) and owned.
            unsafe {
                let value = registers.read32(u64::from(REG_EFUSE_TEST));
                registers.write32(u64::from(REG_EFUSE_TEST), efuse_test_wifi_sel(value));
            }
        }

        // SAFETY: BAR2 mapped and owned, with EFUSE read clocks configured by
        // the helper. PCI function selects the dual-MAC 8192DE factory address.
        let factory =
            unsafe { efuse::read_factory(&registers, did, function) }.map_err(ProbeError::Efuse)?;

        // RTL8192EE: the facts `configure_rtl8192ee` re-derives, checked
        // before the function is retained. A test chip, an unprovisioned
        // map, a BT-coexist board (`rtl92ee_read_bt_coexist_info_from_hwpg`
        // board type 1) or a map without TX power (`0x11 == 0xff`, Linux's
        // autoload-fail TX power branch) stays diagnostic.
        let admissible = did != RTL_DEV_8192EE || {
            use super::rtl8192ee::{adapter, txpower};
            // SAFETY: BAR2 mapped, length checked above, owned exclusively.
            let (sys_cfg1, cr9346) = unsafe {
                (
                    registers.read32(u64::from(adapter::REG_SYS_CFG1)),
                    registers.read8(u64::from(adapter::REG_9346CR)),
                )
            };
            adapter::Adapter::from_hardware(sys_cfg1, cr9346, &factory.logical)
                .is_ok_and(|facts| !facts.bt_coexist && facts.mac == factory.mac)
                && txpower::Efuse::from_logical(&factory.logical).is_ok()
        };

        // RTL8192CE / RTL8188CE: the facts `configure_rtl8192ce`
        // re-derives. `_rtl92ce_read_chip_version` must qualify (no
        // `TRP_VAUX_EN` test chip, no `CHIP_BONDING_92C_1T2R`, no unknown
        // cut, so the RF type is RF_1T1R or RF_2T2R), the map must be
        // provisioned (`REG_9346CR` EFUSE boot, autoload, `0x8129`), the
        // board must not be BT-coexist (`RF_OPTION1[7:5]`), the EFUSE MAC
        // must be the factory identity and the TX-power areas must decode.
        let admissible = admissible
            && (!rtl8192ce || {
                use super::rtl8192ce::{adapter, txpower, version};
                // SAFETY: BAR2 mapped, length checked above, owned exclusively.
                let (sys_cfg, cr9346) = unsafe {
                    (
                        registers.read32(u64::from(version::REG_SYS_CFG)),
                        registers.read8(u64::from(adapter::REG_9346CR)),
                    )
                };
                // SAFETY: as above (HPON_FSM is read only for 92C serials).
                let hpon = || unsafe { registers.read32(u64::from(version::REG_HPON_FSM)) };
                version::Version::from_registers(sys_cfg, hpon).is_ok_and(|qualified| {
                    adapter::Adapter::from_hardware(qualified, cr9346, &factory.logical).is_ok_and(
                        |facts| {
                            !facts.bt_coexistence()
                                && facts.mac == factory.mac
                                && txpower::Efuse::from_hwinfo(&facts.hwinfo).is_ok()
                        },
                    )
                })
            });

        // RTL8723BE: the facts `configure_rtl8723be` re-derives.
        // `_rtl8723be_read_chip_version` must carry `CHIP_8723B`, the map
        // must be provisioned (`REG_9346CR` EFUSE boot, autoload, `0x8129`;
        // `_rtl8723be_read_package_type` reads physical `0x1fb`, 0 after a
        // timeout), the EFUSE MAC must be the factory identity and the
        // path-A TX-power area must decode (`0x11 != 0xff`).
        let admissible = admissible
            && (!rtl8723be || {
                use super::rtl8723be::{adapter, txpower, version};
                // SAFETY: BAR2 mapped, length checked above, owned exclusively.
                let (sys_cfg1, sys_cfg, cr9346, multi_func_ctrl) = unsafe {
                    (
                        registers.read32(u64::from(version::REG_SYS_CFG1)),
                        registers.read32(u64::from(version::REG_SYS_CFG)),
                        registers.read8(u64::from(adapter::REG_9346CR)),
                        registers.read32(u64::from(adapter::REG_MULTI_FUNC_CTRL)),
                    )
                };
                // SAFETY: as above; only the EFUSE read registers are touched.
                let package =
                    unsafe { efuse::read_physical_byte(&registers, adapter::EFUSE_PACKAGE_ADDR) }
                        .unwrap_or(0);
                version::Version::from_registers(sys_cfg1, sys_cfg).is_ok_and(|qualified| {
                    adapter::Adapter::from_hardware(
                        qualified,
                        cr9346,
                        multi_func_ctrl,
                        &factory.logical,
                        package,
                    )
                    .is_ok_and(|facts| facts.mac == factory.mac)
                }) && txpower::Efuse::from_logical(&factory.logical).is_ok()
            });

        // RTL8192DE: the facts `configure_rtl8192de` / `prepare_rtl8192de`
        // re-derive. `_rtl92de_read_chip_version` must not be a test chip
        // (`REG_SYS_CFG` version bits), EFUSE autoload must have succeeded
        // (`REG_9346CR` BIT(5): an autoload-failed board has no power-group
        // store for the channel step) and the PROM mode
        // (`rtl92d_read_eeprom_info` `EEPROM_MAC_FUNCTION`) must give this
        // function a bandset holding the 2.4 GHz station plan (a dual-dual
        // MAC0 is 5 GHz only; the composed station is 2.4 GHz legacy).
        let admissible = admissible
            && (!rtl8192de || {
                use super::rtl8192de::{mode_from_prom, native_channel, version, Interface};
                // SAFETY: BAR2 mapped, length checked above, owned exclusively.
                let (sys_cfg, cr9346) = unsafe {
                    (
                        registers.read32(u64::from(version::REG_SYS_CFG)),
                        registers.read8(u64::from(version::REG_9346CR)),
                    )
                };
                sys_cfg != u32::MAX
                    && sys_cfg & version::SYS_CFG_VERSION_MASK != 0
                    && cr9346 & version::CR9346_AUTOLOAD_OK != 0
                    && mode_from_prom(Interface::Pci, &factory.logical)
                        .is_some_and(|mode| native_channel(1, mode, function))
            });

        Ok((registers, (factory, admissible)))
    })
    .map_err(|_| ProbeError::PciAccess)??;
    let (factory, admissible) = factory;
    let retained = retained && admissible;
    let mac = factory.mac;
    let factory = retained.then(|| Arc::new(factory));

    let (_rx_prod, rx_cons) = channel::<Frame, RX_RING_N>();
    let (tx_prod, _tx_cons) = channel::<Frame, TX_RING_N>();

    let firmware = if retained {
        // SAFETY: probe parked this exact function and exclusively owns BAR2.
        // PciIo rechecks current authority and parked BME at every access.
        let io = unsafe { PciIo::new(*device, *cap, registers) };
        Some(Arc::new(FirmwareOwner::new(io, did)))
    } else {
        None
    };
    let prepared = firmware
        .as_ref()
        .map(|_| Arc::new(super::prepare_native::Retained::new(None)));
    let name = narf_net::iface::reserve_name("wlan%d");
    let native = match (&firmware, &prepared, &factory) {
        (Some(firmware), Some(prepared), Some(factory)) => {
            Some(Arc::new(super::interface::Device::new(
                name,
                prepared.clone(),
                factory.clone(),
                super::interface::NativeEnvironment::new(firmware.clone()),
            )))
        }
        _ => None,
    };
    let device_arc = Arc::new(RtlwifiDevice {
        bus_addr: device.addr,
        name,
        registers,
        mac,
        device_id: device.id.device,
        firmware: firmware.clone(),
        prepared: prepared.clone(),
        factory: factory.clone(),
        native: native.clone(),
        link_up: AtomicBool::new(false),
        rx_ring: IrqSafeSpinLock::new(Some(rx_cons)),
        tx_ring: IrqSafeSpinLock::new(Some(tx_prod)),
    });
    if native.is_none() {
        narf_wireless::registry::register(device_arc);
    }

    Ok(RtlwifiDevice {
        bus_addr: device.addr,
        name,
        registers,
        mac,
        device_id: device.id.device,
        firmware,
        prepared,
        factory,
        native,
        link_up: AtomicBool::new(false),
        rx_ring: IrqSafeSpinLock::new(None),
        tx_ring: IrqSafeSpinLock::new(None),
    })
}

pub fn send_frame_unimpl(_frame: &[u8], _meta: narf_net::TxMeta) -> Result<(), ()> {
    Err(())
}

/// Human-readable driver name for a given device ID.
pub const fn name_for(did: u16) -> &'static str {
    match did {
        RTL_DEV_8188EE => "rtlwifi-8188ee",
        RTL_DEV_8192CE => "rtlwifi-8192ce",
        RTL_DEV_8192CE_ALT => "rtlwifi-8192ce-alt",
        RTL_DEV_8192CE_8177 => "rtlwifi-8192ce-8177",
        RTL_DEV_8192CE_8191 => "rtlwifi-8192ce-8191",
        RTL_DEV_8192DE => "rtlwifi-8192de",
        RTL_DEV_8192EE => "rtlwifi-8192ee",
        RTL_DEV_8723AE => "rtlwifi-8723ae",
        RTL_DEV_8723BE => "rtlwifi-8723be",
        RTL_DEV_8821AE => "rtlwifi-8821ae",
        _ => "rtlwifi",
    }
}

/// True if a device has been bound through probe.
pub fn is_probed() -> bool {
    CONTROLLERS.lock().first().is_some()
}

/// Borrow the bound controller.
pub fn with_controller<R>(f: impl FnOnce(&RtlwifiDevice) -> R) -> Option<R> {
    CONTROLLERS.lock().first().map(f)
}

/// Borrow the exact bound PCI function; no fallback to another radio.
pub fn with_controller_at<R>(
    address: narf_bus::BusAddr,
    f: impl FnOnce(&RtlwifiDevice) -> R,
) -> Option<R> {
    CONTROLLERS.lock().get(address).map(f)
}

struct Provisioning {
    firmware: Arc<FirmwareOwner<PciIo>>,
    prepared: Arc<super::prepare_native::Retained>,
    factory: Arc<efuse::Factory>,
}
fn provisioning(controller: Option<&RtlwifiDevice>) -> Result<Provisioning, super::prepare::Error> {
    let controller = controller.ok_or(super::prepare::Error::State)?;
    if controller.device_id != RTL_DEV_8188EE {
        return Err(super::prepare::Error::State);
    }
    let firmware = controller
        .current_firmware()
        .ok_or(super::prepare::Error::State)?;
    let stage = firmware.status().stage;
    if !matches!(
        stage,
        super::firmware_transport::Stage::Detected | super::firmware_transport::Stage::Ready
    ) {
        return Err(super::prepare::Error::State);
    }
    let prepared = controller
        .prepared
        .as_ref()
        .ok_or(super::prepare::Error::State)?
        .clone();
    if stage == super::firmware_transport::Stage::Ready {
        let Some(guard) = prepared.try_lock() else {
            return Err(super::prepare::Error::State);
        };
        let Some(owner) = guard.as_ref() else {
            return Err(super::prepare::Error::State);
        };
        if !matches!(
            owner.phase(),
            super::prepare::Phase::RadioConfigured
                | super::prepare::Phase::ChannelConfigured
                | super::prepare::Phase::MacConfigured
        ) {
            return Err(super::prepare::Error::State);
        }
    }
    Ok(Provisioning {
        firmware: firmware.clone(),
        prepared,
        factory: controller
            .factory
            .as_ref()
            .ok_or(super::prepare::Error::State)?
            .clone(),
    })
}
pub(crate) async fn drive_scheduled<Step, StepFut, Wait, WaitFut>(
    max_attempts: usize,
    mut retryable: impl FnMut() -> bool,
    mut step: Step,
    mut wait: Wait,
) -> Result<(), super::prepare::Error>
where
    Step: FnMut() -> StepFut,
    StepFut: core::future::Future<Output = Result<(), super::prepare::Error>>,
    Wait: FnMut() -> WaitFut,
    WaitFut: core::future::Future<Output = ()>,
{
    let mut last_err = super::prepare::Error::State;
    for attempt in 0..max_attempts {
        if attempt > 0 {
            wait().await;
        }
        match step().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = err;
                if !retryable() {
                    return Err(err);
                }
            }
        }
    }
    Err(last_err)
}
static PROVISIONING: narf_lib::mutex::Mutex<()> = narf_lib::mutex::Mutex::new(());
async fn provision_with(
    control: &narf_lib::mutex::Mutex<()>,
    binding: impl FnOnce() -> Result<Provisioning, super::prepare::Error>,
) -> Result<(), super::prepare::Error> {
    let _control = control.lock().await;
    let binding = binding()?;
    super::prepare_native::initialize_registered(
        binding.firmware,
        binding.prepared,
        binding.factory,
    )
    .await
}
/// Retry staged firmware only while the exact retained EE owner is Detected.
/// Started/failed firmware and existing preparation are never replayed/reset.
pub async fn provision() -> Result<(), super::prepare::Error> {
    let address = CONTROLLERS
        .lock()
        .first()
        .map(|controller| controller.bus_addr)
        .ok_or(super::prepare::Error::State)?;
    provision_at(address).await
}
/// Provision only the exact retained function selected by the caller.
pub async fn provision_at(address: narf_bus::BusAddr) -> Result<(), super::prepare::Error> {
    let native = with_controller_at(address, |controller| controller.native.clone())
        .ok_or(super::prepare::Error::State)?;
    if let Some(native) = native {
        return native.provision().await;
    }
    provision_with(&PROVISIONING, || {
        let controllers = CONTROLLERS.lock();
        provisioning(controllers.get(address))
    })
    .await
}

/// Test-only reset.
#[cfg(any(test, feature = "kernel-test"))]
pub fn __reset_for_test() {
    *CONTROLLERS.lock() = pci_bindings::Bindings::new();
}

#[cfg(feature = "kernel-test")]
mod provision_tests {
    use super::*;
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    use narf_kernel_test::{kernel_test_in, TestResult};
    fn fixture() -> RtlwifiDevice {
        let address = narf_bus::PcieAddr::new(0xfffe, 0xfd, 0x19, 0);
        let device = BusDevice {
            addr: narf_bus::BusAddr::Pcie(address),
            id: narf_bus::DeviceId {
                vendor: 0x10ec,
                device: RTL_DEV_8188EE,
                class: 0x028000,
                subsystem_vendor: 0x10ec,
                subsystem_id: 0xffff,
            },
            kind: narf_bus::BusKind::Pcie {
                addr: address,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        };
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        cap.revoke();
        let registers = MmioRegion {
            phys: narf_memory::PhysAddr::new(0),
            virt: 0,
            len: 0x2000,
            kind: narf_bus::BarKind::Mmio32 {
                prefetchable: false,
            },
        };
        // SAFETY: inert revoked-cap fixture; no admission test may access the
        // deliberately invalid config/BAR or present it as a live radio.
        let io = unsafe { PciIo::new(device, cap, registers) };
        RtlwifiDevice {
            bus_addr: device.addr,
            name: "ee-revoked-provision-fixture",
            registers,
            mac: [2, 1, 2, 3, 4, 5],
            device_id: RTL_DEV_8188EE,
            firmware: Some(Arc::new(FirmwareOwner::new(io, RTL_DEV_8188EE))),
            prepared: Some(Arc::new(narf_lib::mutex::Mutex::new(None))),
            factory: Some(Arc::new(efuse::Factory {
                mac: [2, 1, 2, 3, 4, 5],
                logical: [0xff; 512],
            })),
            native: None,
            link_up: AtomicBool::new(false),
            rx_ring: IrqSafeSpinLock::new(None),
            tx_ring: IrqSafeSpinLock::new(None),
        }
    }
    fn smoke_rtl8188ee_public_provision_admission_retains_exact_arcs_and_cancelled_wait(
    ) -> TestResult {
        if provisioning(None).is_ok() {
            return TestResult::Fail("EE retry admitted absent controller");
        }
        let controller = fixture();
        let admitted = provisioning(Some(&controller)).unwrap();
        if !Arc::ptr_eq(&admitted.firmware, controller.firmware.as_ref().unwrap())
            || !Arc::ptr_eq(&admitted.prepared, controller.prepared.as_ref().unwrap())
            || !Arc::ptr_eq(&admitted.factory, controller.factory.as_ref().unwrap())
        {
            return TestResult::Fail("EE retry cloned a new hardware/prepared/factory owner");
        }
        drop(admitted);
        let control = narf_lib::mutex::Mutex::new(());
        let guard = control.try_lock().unwrap();
        let entered = core::cell::Cell::new(false);
        {
            let mut future = core::pin::pin!(provision_with(&control, || {
                entered.set(true);
                provisioning(Some(&controller))
            }));
            if !matches!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ) {
                return TestResult::Fail("EE public retry bypassed retained async admission lock");
            }
        }
        drop(guard);
        if entered.get()
            || controller.firmware_status().unwrap().stage
                != super::super::firmware_transport::Stage::Detected
            || !Arc::ptr_eq(
                &provisioning(Some(&controller)).unwrap().firmware,
                controller.firmware.as_ref().unwrap(),
            )
        {
            return TestResult::Fail("cancelled EE pre-admission wait consumed or replaced owner");
        }
        let firmware = controller.firmware.as_ref().unwrap();
        // The supplied-byte diagnostic retains its original one-shot rule:
        // invalid input consumes that attempt before native I/O, making this
        // genuinely Failed owner ineligible for the public staging retry.
        if narf_scheduler::block_on(firmware.initialize(&[])).is_ok()
            || firmware.status().stage != super::super::firmware_transport::Stage::Failed
            || provisioning(Some(&controller)).is_ok()
        {
            return TestResult::Fail(
                "EE public retry admitted an owner whose attempt already began",
            );
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtlwifi/provision",
        smoke_rtl8188ee_public_provision_admission_retains_exact_arcs_and_cancelled_wait
    );
    /// `rtl_pci_remove` routing: only the bound address detaches, the
    /// address is quarantined against re-probe until removal proves DMA
    /// idle, and a reclaimed removal lifts the quarantine.
    fn smoke_rtl8188ee_pci_remove_detaches_and_quarantines_exact_owner() -> TestResult {
        __reset_for_test();
        let controller = fixture();
        let address = controller.bus_addr;
        let other = narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(0xfffe, 0xfd, 0x1a, 0));
        CONTROLLERS.lock().reserve(address);
        CONTROLLERS.lock().commit(controller);
        if detach(other).is_some() || !is_probed() || CONTROLLERS.lock().quarantined(address) {
            return TestResult::Fail("EE removal detached a different function");
        }
        let Some(owner) = detach(address) else {
            return TestResult::Fail("EE removal missed the bound function");
        };
        if is_probed() || !CONTROLLERS.lock().quarantined(address) {
            return TestResult::Fail("EE removal left the owner bound or unquarantined");
        }
        // A quarantined address is refused before any config/BAR access
        // (the fixture capability is revoked; any access would fail).
        let device = BusDevice {
            addr: address,
            id: narf_bus::DeviceId {
                vendor: 0x10ec,
                device: RTL_DEV_8188EE,
                class: 0x028000,
                subsystem_vendor: 0x10ec,
                subsystem_id: 0xffff,
            },
            kind: match address {
                narf_bus::BusAddr::Pcie(addr) => narf_bus::BusKind::Pcie {
                    addr,
                    cfg_phys: narf_memory::PhysAddr::new(0),
                },
                _ => unreachable!(),
            },
        };
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        cap.revoke();
        if probe(device, cap) != Err(narf_bus::ProbeError::BadDevice) || is_probed() {
            return TestResult::Fail("EE quarantined function was re-probed");
        }
        if !narf_scheduler::block_on(finish_removal(owner, address))
            || CONTROLLERS.lock().quarantined(address)
        {
            return TestResult::Fail("EE owner without published DMA kept its quarantine");
        }
        __reset_for_test();
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtlwifi/provision",
        smoke_rtl8188ee_pci_remove_detaches_and_quarantines_exact_owner
    );
    fn smoke_rtl8188ee_pci_bindings_reserve_and_quarantine_independent_functions() -> TestResult {
        use pci_bindings::Admission;
        let mut bindings = pci_bindings::Bindings::new();
        let a = fixture();
        let aa = a.bus_addr;
        let mut b = fixture();
        let ba = narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(0xfffe, 0xfd, 0x1a, 0));
        b.bus_addr = ba;
        let firmware_a = a.firmware.clone().unwrap();
        let firmware_b = b.firmware.clone().unwrap();
        if !matches!(bindings.reserve(aa), Admission::Initialize)
            || !matches!(bindings.reserve(aa), Admission::Blocked)
            || !matches!(bindings.reserve(ba), Admission::Initialize)
            || !bindings.commit(a)
            || !bindings.commit(b)
            || !matches!(bindings.reserve(aa), Admission::Bound)
            || !Arc::ptr_eq(
                bindings.get(aa).unwrap().firmware.as_ref().unwrap(),
                &firmware_a,
            )
            || !Arc::ptr_eq(
                bindings.get(ba).unwrap().firmware.as_ref().unwrap(),
                &firmware_b,
            )
        {
            return TestResult::Fail(
                "EE independent PCI reservations replaced or aliased a retained function",
            );
        }
        let retired = bindings.detach(aa).unwrap();
        bindings.reclaimed(ba); // A different completion cannot release aa.
        if bindings.get(ba).is_none()
            || !bindings.quarantined(aa)
            || !matches!(bindings.reserve(aa), Admission::Blocked)
            || bindings.detach(aa).is_some()
        {
            return TestResult::Fail(
                "EE retirement quarantined another radio or reopened unproven DMA",
            );
        }
        drop(retired);
        bindings.reclaimed(aa);
        if !matches!(bindings.reserve(aa), Admission::Initialize) || bindings.get(ba).is_none() {
            return TestResult::Fail("EE verified release did not lift only its own quarantine");
        }
        bindings.abandon(aa);
        if !matches!(bindings.reserve(aa), Admission::Initialize) {
            return TestResult::Fail("EE failed unstarted probe retained a false binding");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtlwifi/multi_radio",
        smoke_rtl8188ee_pci_bindings_reserve_and_quarantine_independent_functions
    );
}
