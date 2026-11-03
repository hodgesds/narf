// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Receive-only role metadata and retained nonemitting capture controller.
//! Source Linux7.3-rc4 mac80211/core/mac/phy; no enum grants RF or capture.
use super::{monitor_wire, power, station_control::Admission};
use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use narf_lib::sync::IrqSafeSpinLock;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Selection {
    pub mode: u32,
    pub generation: u64,
}
/// Physical supervisor-owned selected role, retained across actual generation
/// rebind. Selection is metadata; only native receipts can open capture.
pub(super) struct Desired(IrqSafeSpinLock<Selection>, AtomicU32);
impl Desired {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self(
            IrqSafeSpinLock::new(Selection {
                mode: 2,
                generation: 1,
            }),
            AtomicU32::new(super::fragment_wire::DISABLED),
        ))
    }
    pub(super) fn fragment_threshold(&self) -> u32 {
        self.1.load(Ordering::Acquire)
    }
    /// A physical policy preference, not a new role/source generation or RF
    /// grant. Each new MSDU samples it; an already retained train is immutable.
    pub(super) fn set_fragment_threshold(&self, original: Selection, threshold: u32) -> bool {
        let selected = self.0.lock();
        if *selected != original || selected.mode != 2 {
            return false;
        }
        self.1.store(threshold, Ordering::Release);
        true
    }
    pub(super) fn snapshot(&self) -> Selection {
        *self.0.lock()
    }
    pub(super) fn select(&self, original: Selection, mode: u32) -> Option<Selection> {
        if !matches!(mode, 2 | 6) {
            return None;
        }
        let mut selected = self.0.lock();
        if *selected != original {
            return None;
        }
        if selected.mode == mode {
            return Some(*selected);
        }
        *selected = Selection {
            mode,
            generation: selected.generation.checked_add(1)?,
        };
        Some(*selected)
    }
    pub(super) fn current(&self, original: Selection) -> bool {
        self.snapshot() == original
    }
}
#[derive(Clone)]
pub(super) struct Epoch(Arc<AtomicBool>);
impl Epoch {
    fn closed() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }
    pub(super) fn current(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub(super) fn retire(&self) {
        self.0.store(false, Ordering::Release);
    }
}
/// # Safety
/// One actual Native/verified WCPU/physical source owns all MMIO/H2C/copies.
/// Source currentness invokes the existing actual device/base/full joint
/// base/full RFK program plus original role generation/admission; no callback/name
/// rebind occurs under native State. Program proves no ordinary peer/TX owner,
/// disabled CMAC TX/autoresponses and source sniffer/filter/crypto/PHYSTS
/// readbacks. Observe reads actual current RF channel A/B/legacy/direct.
/// Prefix consumes completed native RX including partial/drop progress; all
/// pre-active input is retired before current capture. Returned raw MPDUs
/// preserve original bytes and actual CRC/FCS/crypto/PHY admission.
pub(super) unsafe trait Io: Send {
    fn current(&mut self, admission: &Admission, selection: Selection) -> Result<(), power::Error>;
    fn program(
        &mut self,
        admission: &Admission,
        selection: Selection,
    ) -> impl core::future::Future<Output = Result<(), power::Error>> + Send;
    fn observed_channel(
        &mut self,
        admission: &Admission,
        selection: Selection,
    ) -> impl core::future::Future<Output = Result<[u32; 4], power::Error>> + Send;
    fn retire_prefix(
        &mut self,
        admission: &Admission,
        selection: Selection,
    ) -> Result<bool, power::Error>;
    fn receive(
        &mut self,
        admission: &Admission,
        selection: Selection,
        budget: usize,
    ) -> Result<Vec<Vec<u8>>, power::Error>;
    /// Nonemitting closure under actual device authority, never a TX wake.
    fn stop(&mut self) -> Result<(), power::Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    New,
    Starting,
    Active,
    Terminal,
}
pub(super) struct Controller {
    desired: Arc<Desired>,
    selection: Selection,
    admission: Admission,
    epoch: Epoch,
    phase: Phase,
}
impl Controller {
    pub(super) fn prepare(
        desired: Arc<Desired>,
        admission: Admission,
    ) -> Result<Self, power::Error> {
        let selection = desired.snapshot();
        if selection.mode != monitor_wire::IFTYPE {
            return Err(power::Error::Unsupported);
        }
        admission.check()?;
        Ok(Self {
            desired,
            selection,
            admission,
            epoch: Epoch::closed(),
            phase: Phase::New,
        })
    }
    pub(super) fn epoch(&self) -> Epoch {
        self.epoch.clone()
    }
    fn current(&self, io: &mut impl Io) -> Result<(), power::Error> {
        self.admission.check()?;
        if !self.desired.current(self.selection) {
            return Err(power::Error::Terminal);
        }
        io.current(&self.admission, self.selection)
    }
    pub(super) async fn start(&mut self, io: &mut impl Io) -> Result<(), power::Error> {
        if self.phase != Phase::New {
            return Err(power::Error::Terminal);
        }
        self.phase = Phase::Starting;
        self.current(io)?;
        io.program(&self.admission, self.selection).await?;
        self.current(io)?;
        let observed = io.observed_channel(&self.admission, self.selection).await?;
        if !monitor_wire::observed_channel(observed) {
            return Err(power::Error::Access);
        }
        self.current(io)?;
        if !io.retire_prefix(&self.admission, self.selection)? {
            return Err(power::Error::Busy);
        }
        self.current(io)?;
        self.epoch.0.store(true, Ordering::Release);
        self.phase = Phase::Active;
        Ok(())
    }
    pub(super) fn poll(&mut self, io: &mut impl Io) -> Result<Vec<Vec<u8>>, power::Error> {
        if self.phase != Phase::Active || !self.epoch.current() {
            return Err(power::Error::Terminal);
        }
        self.current(io)?;
        let frames = io.receive(&self.admission, self.selection, 64)?;
        self.current(io)?;
        Ok(frames)
    }
    pub(super) fn stop(&mut self, io: &mut impl Io) -> Result<(), power::Error> {
        self.epoch.retire();
        self.phase = Phase::Terminal;
        io.stop()
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.epoch.retire();
    }
}

/// Fixed original physical/source proof copied only after native monitor
/// configuration and RF observation. No registry/provider callback, name
/// lookup, retune or RF emission is added by this capture-only adjunct.
#[derive(Clone)]
pub(super) struct Source {
    device: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
    qualification: Arc<super::radio_policy::Qualification>,
    desired: Arc<Desired>,
    selection: Selection,
    admission: Admission,
    epoch: Epoch,
}
impl Source {
    pub(super) fn retire(&self) {
        self.epoch.retire();
    }
    /// # Safety
    /// Exact same retained Native completed full RFK/current base provenance,
    /// disabled TX/autoresponses, actual monitor receipts and actual channel
    /// reads before minting this original capture source. No input field may
    /// be recaptured from a name/new registration or unrelated Native.
    pub(super) unsafe fn new(
        device: narf_capabilities::Cap<narf_bus::BusDeviceCap, narf_capabilities::Write>,
        qualification: Arc<super::radio_policy::Qualification>,
        desired: Arc<Desired>,
        selection: Selection,
        admission: Admission,
        epoch: Epoch,
    ) -> Self {
        Self {
            device,
            qualification,
            desired,
            selection,
            admission,
            epoch,
        }
    }
    pub(super) fn with_current<T>(&self, publish: impl FnOnce() -> T) -> Result<T, power::Error> {
        self.admission.run(|| {
            if !self.epoch.current() || !self.desired.current(self.selection) {
                return Err(power::Error::Terminal);
            }
            crate::rtw88::pci_park::invoke(&self.device, || {
                self.qualification.with_current(|| {
                    if !self.epoch.current() || !self.desired.current(self.selection) {
                        return Err(power::Error::Terminal);
                    }
                    Ok(publish())
                })
            })
            .map_err(|_| power::Error::Access)?
        })
    }
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "monitor_tests.rs"]
mod tests;
