// SPDX-License-Identifier: GPL-2.0-or-later
//! Retained RTL8822BE ("B22") native owner: one cold-power capability, its
//! single factory map and the shared native firmware lifecycle.
//!
//! Firmware follows Linux `main.c::rtw_load_firmware(rtw8822b_hw_spec.fw_name)`
//! and `mac.c::__rtw_download_firmware` (same 3081 WCPU section flow as
//! RTL8822C/RTL8821C) through the authenticated firmware registry. Later MAC,
//! PHY, calibration and station stages are separate continuations; holding this
//! owner grants no RF or transmit authority. RTL8821CE/RTL8822CE owners,
//! factory maps and signed records are distinct and never substitute.
use super::{
    efuse8822b::Factory8822b,
    firmware_lifecycle::{Lifecycle, Stage, Status},
    firmware_transport::{Error, Info},
    pci_firmware::{self, Transport},
};
use alloc::sync::Arc;
use narf_bus::{BusDevice, BusDeviceCap, MmioRegion};
use narf_capabilities::{Cap, Write};
use narf_lib::mutex::Mutex;

pub(super) struct Owner8822b {
    device: BusDevice,
    cap: Cap<BusDeviceCap, Write>,
    mmio: MmioRegion,
    factory: Factory8822b,
    lifecycle: Arc<Lifecycle<Transport>>,
    admission: Mutex<()>,
}
impl core::fmt::Debug for Owner8822b {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtw8822beNativeOwner")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}
impl Owner8822b {
    /// # Safety
    /// Exact exclusive RTL8822BE function immediately after its source-matched
    /// 8822B card-disable→enable power flow and its one factory EFUSE read,
    /// with BME/IRQs parked. No other native/firmware owner may exist.
    pub(super) unsafe fn new(
        device: BusDevice,
        cap: Cap<BusDeviceCap, Write>,
        mmio: MmioRegion,
        factory: Factory8822b,
    ) -> Self {
        Self {
            device,
            cap,
            mmio,
            factory,
            lifecycle: Arc::new(Lifecycle::new(device.id.device)),
            admission: Mutex::new(()),
        }
    }
    pub(super) fn status(&self) -> Status {
        self.lifecycle.status()
    }
    pub(super) fn lifecycle(&self) -> Arc<Lifecycle<Transport>> {
        self.lifecycle.clone()
    }
    pub(super) fn factory(&self) -> &Factory8822b {
        &self.factory
    }
    pub(super) async fn initialize_registered(&self) -> Result<Info, Error> {
        self.lifecycle
            .initialize_registered(|| {
                // SAFETY: the constructor retained the exact cold function;
                // Lifecycle consumes this allocator at most once.
                unsafe { pci_firmware::allocate(self.device, self.cap, self.mmio) }
            })
            .await
    }
    /// Drive every implemented B22 continuation in order. The chain currently
    /// ends at `Stage::Calibrated` (authenticated firmware, inactive
    /// `rtw_mac_init` + `rtw8822b_mac_init`, complete `rtw8822b_phy_set_param`,
    /// then the signed `N2BQ` ch1/20 firmware IQK; host DMA parked, TXPAUSE
    /// closed). An unprovisioned board stops at `PhyTablesPrepared`.
    pub(super) async fn provision(&self) -> Result<(), Error> {
        let _admission = self.admission.lock().await;
        loop {
            match self.status().stage {
                Stage::Detected => {
                    self.initialize_registered().await?;
                }
                Stage::Ready => {
                    self.lifecycle.prepare_mac().await?;
                }
                Stage::MacPrepared => {
                    self.lifecycle.prepare_phy8822b(&self.factory).await?;
                }
                Stage::PhyTablesPrepared => {
                    // A missing/unsigned/mismatched N2BQ record or refused
                    // policy is pure and keeps this checkpoint retryable.
                    self.lifecycle
                        .prepare_calibration8822b(&self.factory)
                        .await?;
                }
                Stage::Calibrated => return Ok(()),
                _ => return Err(Error::State),
            }
        }
    }
}
