// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Retained one-shot native RTL8922AE closed bootstrap.
//!
//! The bus route requires an actual same-function PCIe FLR receipt. BME
//! parking, allocation and a clear reset-request bit are not reset proofs.
//! Every ring/RX/FWDL mapping is moved into the checked owner before its first
//! register publication. Failure/detach keeps the original owner, source
//! snapshots and uncertain mappings. Reprobe never reconstructs a new attempt.
//!
//! Success stops at ConfiguredClosed SCC/TRX with CMAC TX/RX closed, all ordinary TX
//! and WPDMA stopped, no IRQ/net registration, no channel/station or RF grant.
use super::{
    checked_fwdl_8922a as dma, cold_8922a as cold, download_plan, efuse_be, firmware_registry,
    fwdl_be, mac, mac_system_8922a, pci_reset,
    prepared_8922a::{self, checked::CheckedPrepared},
};
use alloc::{boxed::Box, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_io::{alloc_coherent_masked, DmaBuffer};
use narf_lib::{id::DomainId, mutex::Mutex, sync::IrqSafeSpinLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Error {
    Reset(pci_reset::Error),
    Identity,
    Removed,
    Bar,
    Memory,
    Power(cold::Error),
    Factory(efuse_be::checked::Error),
    Dma(dma::Error),
    Firmware(super::fw::FwError),
    Plan(download_plan::Error),
    System(mac_system_8922a::Error),
    Trx(super::trx_8922a::Error),
    Assets(super::radio_assets::Error),
    Radio(super::radio_be::Error),
    Variant,
    UnsolicitedRfk,
    PartialRadio(super::native_radio_be::Error),
    PacketPreflight(super::power::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum Stage {
    Reserved,
    Reset,
    ClosedPower,
    Factory,
    Rings,
    Download,
    SystemConfigured,
    TrxConfiguredClosed,
    PartialRadioConfigured,
    ClosedWlanCalibrated,
    Failed,
    Removed,
}
#[derive(Default)]
struct Runtime {
    fence: Option<pci_reset::Fence>,
    region: Option<MmioRegion>,
    cold: Option<cold::Cold>,
    prepared: Option<CheckedPrepared>,
    // Retain the actual selected/signature-verified source snapshots even
    // after failure; later qualification cannot substitute another image.
    plans: Option<(download_plan::DownloadPlan, download_plan::DownloadPlan)>,
    factory: Option<efuse_be::checked::Snapshot>,
    chip_version: Option<super::mac_pre_init_8922a::HalChipVer>,
    radio_assets: Option<super::radio_assets::Assets>,
    radio_tables: Option<super::radio_be::Tables>,
    firmware_events: Vec<super::completion_8922a::RoutedC2h>,
    rfk_features: Option<super::rfk::be_features::Features>,
    radio: Option<super::native_radio_be::Radio>,
    packet: Option<super::native_packet_be::Program>,
}
struct Supervisor {
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
    reset: Mutex<Option<pci_reset::Reset>>,
    runtime: Mutex<Runtime>,
    removed: Arc<AtomicBool>,
    stage: AtomicU8,
    error: IrqSafeSpinLock<Option<Error>>,
}
// A bounded lifetime reservation table. Entries intentionally survive detach
// and all errors; reaching the quota refuses a new function before access.
static OWNERS: IrqSafeSpinLock<Vec<Arc<Supervisor>>> = IrqSafeSpinLock::new(Vec::new());
const MAX_FUNCTIONS: usize = 16;

impl Supervisor {
    fn stage(&self, stage: Stage) {
        self.stage.store(stage as u8, Ordering::Release);
    }
    fn current(&self) -> Result<(), Error> {
        if self.removed.load(Ordering::Acquire) {
            return Err(Error::Removed);
        }
        crate::rtw88::pci_park::invoke(&self.authority, || ()).map_err(|_| Error::Identity)
    }
    fn command<T>(&self, op: impl FnOnce() -> Result<T, narf_bus::pci::PciError>) -> Result<T, ()> {
        self.current().map_err(|_| ())?;
        crate::rtw88::pci_park::invoke(&self.authority, op)
            .map_err(|_| ())?
            .map_err(|_| ())
    }
    fn fail(&self, error: Error) {
        *self.error.lock() = Some(error);
        self.stage(if self.removed.load(Ordering::Acquire) {
            Stage::Removed
        } else {
            Stage::Failed
        });
        narf_console::klog!(
            "rtw8922a: retained closed startup {:?}: {:?}\n",
            self.device.addr,
            error
        );
    }
    async fn drive(&self) -> Result<(), Error> {
        self.current()?;
        self.stage(Stage::Reset);
        // The retained reset owns cancellation/quarantine semantics; no second
        // config probe or replacement reset can occur while this is pending.
        let fence = {
            let mut reset = self.reset.lock().await;
            reset
                .as_mut()
                .ok_or(Error::Identity)?
                .run()
                .await
                .map_err(Error::Reset)?
        };
        let mut runtime = self.runtime.lock().await;
        if !fence.matches_function(&self.device, &self.authority) {
            return Err(Error::Identity);
        }
        runtime.fence = Some(fence);
        self.current()?;
        self.start_closed(&mut runtime)?;
        self.start_radio(&mut runtime).await?;
        self.prepare_packets(&mut runtime).await
    }
    async fn prepare_packets(&self, runtime: &mut Runtime) -> Result<(), Error> {
        self.current()?;
        let radio = runtime.radio.as_ref().ok_or(Error::Identity)?;
        if radio.state() != super::native_radio_be::State::ClosedWlanCalibrated {
            return Ok(());
        }
        if runtime.packet.is_some() {
            return Err(Error::Identity);
        }
        runtime.packet = Some(super::native_packet_be::Program::default());
        let packet = runtime.packet.as_mut().ok_or(Error::Identity)?;
        // SAFETY: all actual facts, original checked rings and completed
        // WLAN owner are still in this same retained supervisor. This call
        // can only preflight inactive transport; no packet publication.
        let ready = unsafe {
            packet.prepare(
                runtime.prepared.as_mut().ok_or(Error::Identity)?,
                radio,
                runtime.region.as_ref().ok_or(Error::Bar)?,
                &self.authority,
                &self.removed,
                super::native_packet_be::Sources {
                    device: self.device.id,
                    factory: runtime.factory.as_ref().ok_or(Error::Identity)?,
                    chip: runtime.chip_version.ok_or(Error::Identity)?,
                    assets: runtime.radio_assets.as_ref().ok_or(Error::Identity)?,
                    features: runtime.rfk_features.ok_or(Error::Identity)?,
                },
            )
        }
        .map_err(Error::PacketPreflight)?;
        if ready {
            // SAFETY: same original retained facts/rings/closed source radio;
            // this only programs BE port0/no-link, leaving packets closed.
            unsafe {
                packet.initialize(
                    runtime.prepared.as_mut().ok_or(Error::Identity)?,
                    radio,
                    runtime.region.as_ref().ok_or(Error::Bar)?,
                    &self.authority,
                    &self.removed,
                )
            }
            .await
            .map_err(Error::PacketPreflight)?;
        }
        self.current()?;
        narf_console::klog!("rtw8922a: {:?} separate packet measurement/preflight={}; ordinary gates remain closed\n",self.device.addr,ready);
        Ok(())
    }
    async fn start_radio(&self, runtime: &mut Runtime) -> Result<(), Error> {
        self.current()?;
        if runtime.radio.is_some() {
            return Err(Error::Identity);
        }
        if unsolicited_boot_rfk(&runtime.firmware_events) {
            return Err(Error::UnsolicitedRfk);
        }
        // Install before any radio future can publish, fail or be dropped.
        // The original one-shot owner is never reconstructed on reprobe.
        runtime.radio = Some(super::native_radio_be::Radio::default());
        let Runtime {
            region,
            prepared,
            factory,
            chip_version,
            radio_assets,
            radio_tables,
            rfk_features,
            radio,
            ..
        } = runtime;
        let owner = radio.as_mut().ok_or(Error::Identity)?;
        // SAFETY: every borrowed fact and checked DMA stage was produced
        // above by this exact retained original function under its original
        // authority. No Rtw89Device/IRQ/net source or replacement owns them.
        unsafe {
            owner
                .prepare_partial(
                    super::native_radio_be::NativeOwner {
                        prepared: prepared.as_mut().ok_or(Error::Identity)?,
                        region: region.as_ref().ok_or(Error::Bar)?,
                        authority: &self.authority,
                        cancelled: &self.removed,
                    },
                    super::native_radio_be::Sources {
                        device: self.device,
                        factory: factory.as_ref().ok_or(Error::Identity)?,
                        chip: chip_version.ok_or(Error::Identity)?,
                        assets: radio_assets.as_ref().ok_or(Error::Identity)?,
                        tables: radio_tables.as_ref().ok_or(Error::Identity)?,
                        features: rfk_features.ok_or(Error::Identity)?,
                    },
                )
                .await
        }
        .map_err(Error::PartialRadio)?;
        self.current()?;
        let wlan = owner.state() == super::native_radio_be::State::ClosedWlanCalibrated;
        self.stage(if wlan {
            Stage::ClosedWlanCalibrated
        } else {
            Stage::PartialRadioConfigured
        });
        narf_console::klog!(
            "rtw8922a: {:?} measured closed ch1/20MHz {:?}; ordinary HCI/IRQ/packet/station gates closed\n",
            self.device.addr, owner.state()
        );
        Ok(())
    }
    #[inline(never)]
    fn start_closed(&self, runtime: &mut Runtime) -> Result<(), Error> {
        self.current()?;
        if runtime.region.is_some()
            || runtime.prepared.is_some()
            || !runtime
                .fence
                .as_ref()
                .is_some_and(|f| f.matches_function(&self.device, &self.authority))
        {
            return Err(Error::Identity);
        }
        let region = crate::rtw88::pci_park::map_bar_control(&self.device, &self.authority, 2)
            .map_err(|_| Error::Bar)?;
        if region.len < 0x40000 {
            return Err(Error::Bar);
        }
        runtime.region = Some(region);
        let region = runtime.region.as_ref().ok_or(Error::Bar)?;
        let cv = crate::rtw88::pci_park::invoke(&self.authority, || {
            // SAFETY: original live exclusively reserved Device BAR; aligned
            // source R_AX_SYS_CFG1 lies inside the checked extent above.
            unsafe { region.read32(mac::R_AX_SYS_CFG1) }
        })
        .map_err(|_| Error::Identity)?;
        if cv == u32::MAX {
            return Err(Error::Identity);
        }
        let cv = ((cv & mac::B_AX_CHIP_VER_MASK) >> mac::B_AX_CHIP_VER_SHIFT) as u8;
        runtime.cold = Some(cold::Cold::default());
        let original = runtime.cold.as_mut().ok_or(Error::Identity)?;
        // SAFETY: retained successful exact-function temporal FLR above, BME
        // verified parked by mapping, exclusive original reservation; no DMA
        // mappings have been published and no IRQ/ordinary producer exists.
        let mut io =
            unsafe { cold::NativeRegs::new(region, &self.authority) }.cancel_with(&self.removed);
        // SAFETY: same actual FLR/parked-BME/no-published-DMA facts; actual CV
        // observed from the same original function under current authority.
        unsafe { original.power_on(&mut io, cv) }.map_err(Error::Power)?;
        self.stage(Stage::ClosedPower);
        let mut chip_version = original.chip_version(&mut io).map_err(Error::Power)?;
        runtime.chip_version = Some(chip_version);
        // SAFETY: checked original ClosedPower, both BBs/WCPU held, MAC0
        // power tuple on and packet gates closed, MAC1 complete power off.
        let mut factory_port = unsafe { efuse_be::checked::Native::new(region, &self.authority) }
            .cancel_with(&self.removed);
        runtime.factory =
            Some(efuse_be::checked::read_all(&mut factory_port, cv).map_err(Error::Factory)?);
        // Source ECV overrides only hal.cv; ACV/CID/AID remain the actual
        // original-function observations. Missing/erased ECV keeps raw CV.
        chip_version.cv = runtime
            .factory
            .as_ref()
            .ok_or(Error::Identity)?
            .factory
            .cv
            .unwrap_or(cv);
        runtime.chip_version = Some(chip_version);
        let cv = chip_version.cv;
        self.stage(Stage::Factory);
        original.prepare_bbmcu0(&mut io).map_err(Error::Power)?;
        self.current()?;
        // Still unpublished, so an allocation failure can normally drop these
        // fresh maps. After adopt, every path retains them through uncertainty.
        let storage = storage()?;
        let factory = runtime
            .factory
            .as_ref()
            .ok_or(Error::Identity)?
            .factory
            .clone();
        let mut base =
            Box::new(prepared_8922a::Prepared8922a::new(factory, cv).map_err(|_| Error::Memory)?);
        base.record_chip_ver(chip_version);
        let original = runtime.cold.take().ok_or(Error::Identity)?;
        // SAFETY: every ring/RX mapping is moved here exactly once; there is no
        // Rtw89Device storage alias, producer, IRQ or externally droppable copy.
        runtime.prepared = Some(unsafe {
            CheckedPrepared::adopt(
                base,
                original,
                storage,
                super::dma::DEFAULT_TXBD_NUM,
                super::dma::DEFAULT_RXBD_NUM,
                self.device,
                self.authority,
            )
        });
        let prepared = runtime.prepared.as_mut().ok_or(Error::Identity)?;
        // SAFETY: exact original live BAR/current authority, complete original
        // DMA owner retained above; no competing reset/removal/producer.
        let mut dma_port =
            unsafe { dma::Native::new(region, &self.authority) }.cancel_with(&self.removed);
        prepared.reset_program(&mut dma_port).map_err(Error::Dma)?;
        self.stage(Stage::Rings);
        // Select/authenticate both actual suits before granting PCI DMA.
        let image = firmware_registry::load(mac::ChipId::Rtl8922A, cv).map_err(Error::Firmware)?;
        let bb_image = image.bbmcu(cv, 0).map_err(Error::Firmware)?;
        let blacklist = super::secure::Blacklist::upstream(mac::ChipId::Rtl8922A);
        let fuses = prepared.secure_fuses();
        let normal =
            download_plan::DownloadPlan::new(image, fuses, blacklist).map_err(Error::Plan)?;
        let bb =
            download_plan::DownloadPlan::new(bb_image, fuses, blacklist).map_err(Error::Plan)?;
        // Pure preflight of the actual signed element region: no BB/RF effect
        // and no calibration qualification or emission authority is created.
        let assets = super::radio_assets::Assets::from_prepared_be(normal.firmware(), chip_version)
            .map_err(Error::Assets)?;
        let tables = super::radio_be::Tables::from_assets(
            &assets,
            runtime
                .factory
                .as_ref()
                .ok_or(Error::Identity)?
                .factory
                .rfe_type,
            cv,
        )
        .map_err(Error::Radio)?;
        runtime.radio_assets = Some(assets);
        runtime.radio_tables = Some(tables);
        let features =
            super::rfk::be_features::Features::from_plan(&normal).ok_or(Error::Identity)?;
        if !features.supports_device(self.device.id.device) {
            return Err(Error::Variant);
        }
        runtime.rfk_features = Some(features);
        runtime.plans = Some((normal, bb));
        let (normal, bb) = runtime.plans.as_ref().ok_or(Error::Identity)?;
        self.current()?;
        prepared
            .enable_ch12(&mut dma_port, &self.removed)
            .map_err(Error::Dma)?;
        self.stage(Stage::Download);
        // SAFETY: original signed/fuse-selected NORMAL+BBMCU0 snapshots,
        // checked preinit/BME/CH12 owner above, no retries or nested callback.
        unsafe {
            prepared.download(
                &mut dma_port,
                &fwdl_be::Suit {
                    plan: normal,
                    check: fwdl_be::CheckType::Wcpu,
                    malloc_info: true,
                },
                &fwdl_be::Suit {
                    plan: bb,
                    check: fwdl_be::CheckType::Bb0,
                    malloc_info: false,
                },
            )
        }
        .map_err(Error::Power)?;
        prepared
            .configure_system(region, &self.removed)
            .map_err(Error::System)?;
        self.current()?;
        self.stage(Stage::SystemConfigured);
        prepared
            .configure_trx(region, &self.removed)
            .map_err(Error::Trx)?;
        self.stage(Stage::TrxConfiguredClosed);
        prepared
            .query_phycap(region, &self.removed, features)
            .map_err(Error::Dma)?;
        // This initial bounded control poll is not an RFK completion: no
        // offload has been issued. Retain the actual messages for the later
        // typed single-outstanding control owner; ordinary packets are dropped.
        let events = prepared
            .poll_firmware(region, &self.removed, 256)
            .map_err(Error::Dma)?;
        runtime.firmware_events = events.c2h;
        narf_console::klog!(
            "rtw8922a: {:?} SCC/TRX configured; packet/RF/station gates closed\n",
            self.device.addr
        );
        Ok(())
    }
}
fn storage() -> Result<dma::Storage<DmaBuffer>, Error> {
    let allocate = |length| {
        alloc_coherent_masked(length, DomainId::DRIVER_0, super::tx_8922a::BUFFER_DMA_MASK)
            .map_err(|_| Error::Memory)
    };
    let mut tx = Vec::new();
    for _ in 0..super::dma::TXCH_NUM {
        tx.push(allocate(usize::from(super::dma::DEFAULT_TXBD_NUM) * 8)?);
    }
    let mut rx = Vec::new();
    let mut receive = [Vec::new(), Vec::new()];
    for packets in &mut receive {
        rx.push(allocate(usize::from(super::dma::DEFAULT_RXBD_NUM) * 8)?);
        for _ in 0..super::dma::DEFAULT_RXBD_NUM {
            packets.push(allocate(2048)?);
        }
    }
    Ok(dma::Storage {
        tx: tx.try_into().map_err(|_| Error::Memory)?,
        rx: rx.try_into().map_err(|_| Error::Memory)?,
        receive,
    })
}
pub(super) fn probe(
    device: BusDevice,
    authority: Cap<BusDeviceCap, Write>,
) -> Result<(), narf_bus::ProbeError> {
    if device.id.vendor != 0x10ec || !matches!(device.id.device, 0x8922 | 0x892b) {
        return Err(narf_bus::ProbeError::BadDevice);
    }
    let owner = {
        let mut owners = OWNERS.lock();
        if let Some(original) = owners.iter().find(|o| o.device.addr == device.addr) {
            return if original.device.id == device.id && same_config(original.device, device) {
                Ok(())
            } else {
                Err(narf_bus::ProbeError::BadDevice)
            };
        }
        if owners.len() >= MAX_FUNCTIONS {
            return Err(narf_bus::ProbeError::BadDevice);
        }
        let owner = Arc::new(Supervisor {
            device,
            authority,
            reset: Mutex::new(None),
            runtime: Mutex::new(Runtime::default()),
            removed: Arc::new(AtomicBool::new(false)),
            stage: AtomicU8::new(Stage::Reserved as u8),
            error: IrqSafeSpinLock::new(None),
        });
        owners.push(owner.clone());
        owner
    };
    // SAFETY: lifetime BDF reservation was published before any hardware
    // access. The same slot remains retained on refusal/cancel/detach.
    let reset = match unsafe { pci_reset::Reset::claim(device, authority) } {
        Ok(reset) => reset.cancel_with(owner.removed.clone()),
        Err(error) => {
            owner.fail(Error::Reset(error));
            return Err(narf_bus::ProbeError::BadDevice);
        }
    };
    // No async work has started, so this nonblocking uncontended installation
    // does not run a scheduler-dependent future or hold a lock across a wait.
    *owner
        .reset
        .try_lock()
        .ok_or(narf_bus::ProbeError::BadDevice)? = Some(reset);
    if crate::rtw88::pci_park::park_with(
        |bits| owner.command(|| narf_bus::pci::clear_command(&authority, &device, bits)),
        |bits| owner.command(|| narf_bus::pci::set_command(&authority, &device, bits)),
        || owner.command(|| narf_bus::pci::read_command(&authority, &device)),
    )
    .is_err()
    {
        owner.fail(Error::Identity);
        return Err(narf_bus::ProbeError::BadDevice);
    }
    narf_scheduler::spawn(async move {
        if let Err(error) = owner.drive().await {
            owner.fail(error);
        }
    });
    Ok(())
}
fn same_config(a: BusDevice, b: BusDevice) -> bool {
    match (a.kind, b.kind) {
        (
            narf_bus::BusKind::Pcie {
                addr: aa,
                cfg_phys: ac,
            },
            narf_bus::BusKind::Pcie {
                addr: ba,
                cfg_phys: bc,
            },
        ) => aa == ba && ac == bc,
        _ => false,
    }
}
fn unsolicited_boot_rfk(events: &[super::completion_8922a::RoutedC2h]) -> bool {
    events.iter().any(|event| {
        let c2h = &event.c2h;
        // Refuse even malformed/unknown-state report bodies: an initial
        // drain cannot hide a previous RFK producer from the exclusive
        // single-outstanding command/report owner about to be constructed.
        c2h.category == 2 && c2h.class == 9 && c2h.function == 0
    })
}
pub(super) fn remove(device: BusDevice, _authority: Cap<BusDeviceCap, Write>) {
    let owners = OWNERS.lock();
    let Some(owner) = owners.iter().find(|o| {
        o.device.addr == device.addr && o.device.id == device.id && same_config(o.device, device)
    }) else {
        return;
    };
    owner.removed.store(true, Ordering::Release);
    owner.stage(Stage::Removed);
    // A remove event is not proof that original DMA retired or a license to
    // access a replaced endpoint. Retain the whole owner and every mapping.
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};
    fn smoke_rtw8922a_native_refuses_preexisting_rfk_report_before_radio_owner() -> TestResult {
        use super::super::{
            completion_8922a::{Route, RoutedC2h},
            rx_packet::C2h,
        };
        let mut bytes = alloc::vec![0;10];
        bytes[..4].copy_from_slice(&0x26u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&10u32.to_le_bytes());
        bytes[8] = 1;
        bytes[9] = 7;
        let mut events = alloc::vec![RoutedC2h {
            route: Route::OutsrcPhy { class: 9, func: 0 },
            c2h: C2h::parse(bytes).unwrap(),
            ack: None,
        }];
        kt_assert!(unsolicited_boot_rfk(&events));
        events[0].c2h.bytes.truncate(8); // body shape cannot hide report header
        kt_assert!(unsolicited_boot_rfk(&events));
        events[0].c2h.function = 1;
        kt_assert!(!unsolicited_boot_rfk(&events));
        kt_assert!(!unsolicited_boot_rfk(&[]));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89",
        smoke_rtw8922a_native_refuses_preexisting_rfk_report_before_radio_owner
    );
    fn device() -> BusDevice {
        let addr = narf_bus::PcieAddr::new(0xfffe, 0xff, 31, 7);
        BusDevice {
            addr: narf_bus::BusAddr::Pcie(addr),
            id: narf_bus::DeviceId {
                vendor: 0x10ec,
                device: 0x8922,
                class: 0x028000,
                subsystem_vendor: 0x10ec,
                subsystem_id: 0x8922,
            },
            kind: narf_bus::BusKind::Pcie {
                addr,
                cfg_phys: narf_memory::PhysAddr::new(0),
            },
        }
    }
    fn smoke_rtw8922a_probe_retains_failed_original_and_refuses_replacement() -> TestResult {
        let device = device();
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        // Zero ECAM is refused by Binding before any config access/FLR/park.
        kt_assert!(probe(device, cap).is_err());
        let original = {
            let owners = OWNERS.lock();
            owners
                .iter()
                .find(|o| o.device.addr == device.addr)
                .cloned()
                .unwrap()
        };
        kt_assert_eq!(original.stage.load(Ordering::Acquire), Stage::Failed as u8);
        kt_assert_eq!(
            *original.error.lock(),
            Some(Error::Reset(pci_reset::Error::Unsupported))
        );
        kt_assert_eq!(probe(device, cap), Ok(()));
        let other = Cap::<BusDeviceCap, Write>::bootstrap();
        // The broker mints a fresh cap for reprobe/detach. It is observation
        // only: the original native/reset authority slot is never replaced.
        kt_assert_eq!(probe(device, other), Ok(()));
        kt_assert_eq!(original.authority.slot(), cap.slot());
        let mut moved = device;
        if let narf_bus::BusKind::Pcie { addr, .. } = device.kind {
            moved.kind = narf_bus::BusKind::Pcie {
                addr,
                cfg_phys: narf_memory::PhysAddr::new(0x4000),
            };
        }
        kt_assert!(probe(moved, cap).is_err());
        remove(device, other);
        kt_assert!(original.removed.load(Ordering::Acquire));
        kt_assert_eq!(probe(device, cap), Ok(()));
        kt_assert_eq!(original.stage.load(Ordering::Acquire), Stage::Removed as u8);
        let owners = OWNERS.lock();
        kt_assert_eq!(
            owners
                .iter()
                .filter(|o| o.device.addr == device.addr)
                .count(),
            1
        );
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89/8922a",
        smoke_rtw8922a_probe_retains_failed_original_and_refuses_replacement
    );
    fn smoke_rtw8922a_legacy_unfenced_direct_probe_is_refused_before_hardware() -> TestResult {
        let cap = Cap::<BusDeviceCap, Write>::bootstrap();
        // SAFETY: malformed inert zero-ECAM fixture; the BE refusal must run
        // before any bus/MMIO action and does not assume a real reset receipt.
        let result = unsafe { super::super::pci::bring_up(&device(), &cap) };
        kt_assert!(matches!(
            result,
            Err(super::super::pci::ProbeError::PciAccess)
        ));
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/rtw89/8922a",
        smoke_rtw8922a_legacy_unfenced_direct_probe_is_refused_before_hardware
    );
}
