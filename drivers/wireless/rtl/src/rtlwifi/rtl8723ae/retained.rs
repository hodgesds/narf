// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact registered AE cold/factory/calibration capsule and lifetime retention.
use super::{cold_storage, factory};
use crate::platform::bus::BusAddr;
use crate::platform::lib::{
    mutex::Mutex,
    sync::{IrqSafeSpinLock, OnceLock},
};
use crate::rtlwifi::{
    efuse::Factory,
    firmware_native::PciIo,
    firmware_transport::{Error as AccessError, Identity, Io, Owner, PacketIo, Stage},
    pci::RtlwifiDevice,
    prepare::Error,
};
use alloc::sync::Arc;
use core::{
    mem::ManuallyDrop,
    sync::atomic::{AtomicBool, AtomicU8, Ordering},
};

/// Sealed to the rtlwifi package. Production implements only original PciIo;
/// fixtures implement it over native Rust capability-checked register actors.
/// current must enclose the ACTUAL operation, never return an unguarded future.
pub(in crate::rtlwifi) trait Backend: Io + 'static {
    fn address(&self) -> BusAddr;
    fn current<T>(
        &self,
        operation: impl FnOnce(&Self) -> Result<T, AccessError>,
    ) -> Result<T, AccessError>;
    fn identity(&self) -> Result<cold_storage::PciIdentity, AccessError>;
    /// Narrow native-only restrictive closure under CURRENT original PCI.
    /// Unsupported models retain uncertainty; this is no reset/reclaim proof.
    fn restrict_packets(&self) -> Result<(), AccessError> {
        Err(AccessError::Unsupported)
    }
}

const ALLOCATED: u8 = 0;
const REGISTERED: u8 = 1;
const RETIRED: u8 = 2;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::rtlwifi) enum Phase {
    Allocated,
    Claimed,
    ColdOwned,
    FactoryReading,
    InputsReady,
    Calibrating,
    Prepared,
    StationStarting,
    RingsReady,
    MacReady,
    ResetOnly,
}
pub(in crate::rtlwifi) struct State<I: Backend> {
    // Independently owned retention even before the handoff's first await.
    pub(in crate::rtlwifi) firmware: Arc<Owner<I>>,
    pub(super) expected: Arc<Factory>,
    pub(in crate::rtlwifi) cold: Arc<cold_storage::Storage>,
    pub(in crate::rtlwifi) port: Option<PacketIo<I>>,
    pub(in crate::rtlwifi) identity: Option<Identity>,
    pub(super) factory: factory::Owner,
    pub(in crate::rtlwifi) phase: Phase,
    pub(super) failure: Option<factory::Failure>,
    pub(super) work: Option<super::supervision::Work<I>>,
}

/// Allocated before native claim, retained by the real PCI Bindings slot.
/// No reset/reclaim API: state and a detached controller cannot be dropped,
/// even if the last public Arc disappears. Bindings separately reserves the
/// exact address forever on detach; ManuallyDrop supplies no reservation.
pub(in crate::rtlwifi) struct Retained<I: Backend = PciIo> {
    firmware: Arc<Owner<I>>,
    expected: Arc<Factory>,
    address: BusAddr,
    radio_name: OnceLock<&'static str>,
    registration: AtomicU8,
    parking: AtomicU8,
    pub(super) effect_gate: IrqSafeSpinLock<()>,
    pub(super) station_live: Arc<AtomicBool>,
    native: ManuallyDrop<OnceLock<Arc<crate::rtlwifi::interface::Native>>>,
    claim_intent: AtomicBool,
    factory_intent: AtomicBool,
    pub(super) station_intent: AtomicBool,
    pub(super) admission: Mutex<()>,
    pub(in crate::rtlwifi) cold: Arc<cold_storage::Storage>,
    pub(in crate::rtlwifi) state: ManuallyDrop<Mutex<State<I>>>,
    // Native controller retirement is handled only for default PciIo.
    quarantine_owner: ManuallyDrop<OnceLock<RtlwifiDevice>>,
    pub(super) transport: ManuallyDrop<OnceLock<Arc<crate::rtlwifi::prepare_native::Retained>>>,
}
impl<I: Backend> core::fmt::Debug for Retained<I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AeRetainedColdFactory")
            .field("address", &self.address)
            .field("registration", &self.registration.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}
impl<I: Backend> Retained<I> {
    /// Allocates metadata only. Only Bindings::commit may set REGISTERED;
    /// every access/claim checks it, original Arc identity and exact address.
    pub(in crate::rtlwifi) fn allocate(
        firmware: Arc<Owner<I>>,
        expected: Arc<Factory>,
    ) -> Result<Arc<Self>, AccessError> {
        if firmware.device_id() != super::DEV_ID {
            return Err(AccessError::Unsupported);
        }
        let address = firmware.native().address();
        let cold = Arc::new(cold_storage::Storage::default());
        let state = State {
            firmware: firmware.clone(),
            expected: expected.clone(),
            cold: cold.clone(),
            port: None,
            identity: None,
            factory: factory::Owner::default(),
            phase: Phase::Allocated,
            failure: None,
            work: None,
        };
        Ok(Arc::new(Self {
            firmware,
            expected,
            address,
            radio_name: OnceLock::new(),
            registration: AtomicU8::new(ALLOCATED),
            parking: AtomicU8::new(0),
            effect_gate: IrqSafeSpinLock::new(()),
            station_live: Arc::new(AtomicBool::new(false)),
            native: ManuallyDrop::new(OnceLock::new()),
            claim_intent: AtomicBool::new(false),
            factory_intent: AtomicBool::new(false),
            station_intent: AtomicBool::new(false),
            admission: Mutex::new(()),
            cold,
            state: ManuallyDrop::new(Mutex::new(state)),
            quarantine_owner: ManuallyDrop::new(OnceLock::new()),
            transport: ManuallyDrop::new(OnceLock::new()),
        }))
    }
    pub(in crate::rtlwifi) fn commit(&self, address: BusAddr, firmware: &Arc<Owner<I>>) -> bool {
        self.address == address
            && Arc::ptr_eq(&self.firmware, firmware)
            && self
                .registration
                .compare_exchange(ALLOCATED, REGISTERED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }
    pub(in crate::rtlwifi) fn attach_name(&self, name: &'static str) -> Result<(), AccessError> {
        if self.registration.load(Ordering::Acquire) != ALLOCATED {
            return Err(AccessError::Gate);
        }
        self.radio_name
            .set(name)
            .map_err(|_| AccessError::AlreadyStarted)
    }
    pub(super) fn radio_allowed(&self) -> bool {
        // Same stable default wiphy identity as WirelessNetIface::wiphy_id;
        // this single-netdev AE profile has no virtual-interface override.
        self.radio_name.get().is_some_and(|name| {
            let wiphy = name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| {
                (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
            });
            !crate::platform::wireless::rfkill::blocked(wiphy)
        })
    }
    pub(in crate::rtlwifi) fn registered_for(&self, firmware: &Arc<Owner<I>>) -> bool {
        self.registration.load(Ordering::Acquire) == REGISTERED
            && Arc::ptr_eq(&self.firmware, firmware)
            && self.address == firmware.native().address()
    }
    /// No lock, await, hardware access, or raw cleanup is needed to deny.
    pub(in crate::rtlwifi) fn retire(&self) {
        self.station_live.store(false, Ordering::Release);
        self.registration.store(RETIRED, Ordering::Release);
        self.firmware.retire_ae();
    }
    /// Terminal source/registration loss closes emission authority first.
    /// The current original PCI path may only restrict gates; every source,
    /// DMA allocation and calibration origin remains retained either way.
    pub(in crate::rtlwifi) fn terminal_park(&self) -> Result<(), AccessError> {
        self.retire();
        // All earlier admitted scalar enables complete BEFORE these closing
        // writes. Later effects recheck retirement only AFTER taking this gate.
        // No await, poll or outer descriptor callback may hold this lock.
        let _effects = self.effect_gate.lock();
        if let Some(mut state) = self.state.try_lock() {
            state.phase = Phase::ResetOnly;
        }
        match self
            .parking
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                let result = self.firmware.native().restrict_packets();
                if result.is_ok() {
                    self.parking.store(2, Ordering::Release);
                }
                result
            }
            Err(2) => Ok(()),
            Err(_) => Err(AccessError::Gate),
        }
    }
    pub(in crate::rtlwifi) fn claim_intent(&self) {
        self.claim_intent.store(true, Ordering::Release);
    }
    pub(super) fn firmware_backend(&self) -> &I {
        self.firmware.native()
    }
    pub(in crate::rtlwifi) fn same_firmware(&self, source: &Arc<Owner<I>>) -> bool {
        Arc::ptr_eq(&self.firmware, source) && self.address == source.native().address()
    }
    pub(in crate::rtlwifi) fn current<T>(
        &self,
        identity: Identity,
        operation: impl FnOnce(&I) -> Result<T, AccessError>,
    ) -> Result<T, AccessError> {
        if !self.registered_for(&self.firmware)
            || self.firmware.status().stage != Stage::Ready
            || self
                .firmware
                .identity()
                .is_none_or(|now| now.digest != identity.digest)
        {
            return Err(AccessError::Gate);
        }
        identity
            .invoke(|| {
                self.firmware
                    .native()
                    .current(|io| {
                        // Retirement can race the outer preflight, including
                        // on another CPU during a responsive hardware poll.
                        if !self.registered_for(&self.firmware)
                            || self.firmware.status().stage != Stage::Ready
                            || self
                                .firmware
                                .identity()
                                .is_none_or(|now| now.digest != identity.digest)
                        {
                            return Err(AccessError::Gate);
                        }
                        operation(io)
                    })
                    .map_err(Error::Access)
            })
            .map_err(|e| match e {
                Error::Access(e) => e,
                _ => AccessError::Gate,
            })
    }
    pub(super) fn firmware(&self) -> &Arc<Owner<I>> {
        &self.firmware
    }
    pub(super) fn expected(&self) -> &Arc<Factory> {
        &self.expected
    }
    /// Factory continuation before the separate signed calibration stages.
    /// Cancellation at either lock wait leaves the unique cold owner in its
    /// registered source/destination and permanently burns the claim/intent.
    pub(super) async fn acquire_factory(self: &Arc<Self>) -> Result<Arc<factory::Inputs>, Error> {
        self.factory_intent
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::State)?;
        self.firmware
            .claim_ae_cold(self)
            .await
            .map_err(Error::Access)?;
        let mut state = self.state.lock().await;
        if state.phase != Phase::ColdOwned || !self.registered_for(&self.firmware) {
            state.phase = Phase::ResetOnly;
            return Err(Error::State);
        }
        let identity = state.identity.ok_or(Error::State)?;
        state.phase = Phase::FactoryReading;
        let io = super::checked::FactoryIo::new(self.clone(), identity);
        // SAFETY: both the original source and destination are retained;
        // one-shot native claim excludes all other AE packet/radio writers.
        // A regular mutex owns the entire read. Cleanup still invokes the
        // same current PCI backend after source/registration retirement.
        let result = unsafe { state.factory.acquire(&io, self.expected.clone()) };
        match result {
            Ok(inputs) if self.registered_for(&self.firmware) => {
                state.phase = Phase::InputsReady;
                Ok(inputs)
            }
            result => {
                state.failure = result.err();
                state.phase = Phase::ResetOnly;
                Err(Error::State)
            }
        }
    }
    /// Metadata request only. Old NAPC alone cannot construct checked RF IO;
    /// the separately signed NAQR recipe and measured peak remain mandatory.
    pub(in crate::rtlwifi) async fn preparation_request(
        self: &Arc<Self>,
        op: super::envelope::Operating,
    ) -> Result<super::radio_policy::Request, Error> {
        let (inputs, identity, bound) = {
            let state = self.state.lock().await;
            if state.phase != Phase::InputsReady || !self.registered_for(&self.firmware) {
                return Err(Error::State);
            }
            (
                state.factory.inputs().ok_or(Error::State)?,
                state.identity.ok_or(Error::State)?,
                self.cold.bound()?,
            )
        };
        let base = Arc::new(
            super::envelope::Calibration::load_registered(&self.expected).map_err(Error::Power)?,
        );
        let cold = Arc::new(super::radio_policy::ColdBinding::from_native(bound));
        let program = super::radio_policy::Program::bind(inputs, base, identity, cold, op)?;
        self.current(identity, |_| Ok(())).map_err(Error::Access)?;
        Ok(program.request())
    }
    #[cfg(any(test, feature = "kernel-test"))]
    pub(in crate::rtlwifi) fn address(&self) -> BusAddr {
        self.address
    }
}
impl Retained<PciIo> {
    pub(in crate::rtlwifi) fn attach_native(
        &self,
        native: Arc<crate::rtlwifi::interface::Native>,
    ) -> Result<(), AccessError> {
        if self.registration.load(Ordering::Acquire) != ALLOCATED
            || !Arc::ptr_eq(&native.native_firmware(), &self.firmware)
            || self
                .transport
                .get()
                .is_none_or(|slot| !Arc::ptr_eq(slot, &native.prepared))
        {
            return Err(AccessError::Gate);
        }
        self.native
            .set(native)
            .map_err(|_| AccessError::AlreadyStarted)
    }
    pub(super) fn native_owner(&self) -> Result<Arc<crate::rtlwifi::interface::Native>, Error> {
        self.native.get().cloned().ok_or(Error::State)
    }
    pub(in crate::rtlwifi) fn same_native(
        &self,
        native: &Arc<crate::rtlwifi::interface::Native>,
    ) -> bool {
        self.native
            .get()
            .is_some_and(|held| Arc::ptr_eq(held, native))
    }

    pub(in crate::rtlwifi) fn attach_transport(
        &self,
        storage: Arc<crate::rtlwifi::prepare_native::Retained>,
    ) -> Result<(), AccessError> {
        if self.registration.load(Ordering::Acquire) != ALLOCATED {
            return Err(AccessError::Gate);
        }
        self.transport
            .set(storage)
            .map_err(|_| AccessError::AlreadyStarted)
    }
    /// Own the ENTIRE detached controller before its async removal could
    /// drop native/diagnostic resources. No reset fence -> never reclaimed.
    pub(in crate::rtlwifi) fn quarantine_controller(&self, owner: RtlwifiDevice) {
        self.retire();
        if let Err(owner) = self.quarantine_owner.set(owner) {
            // An impossible repeated detach still cannot release resources.
            // Bindings keeps the exact address quarantined on either path.
            core::mem::forget(owner);
        }
    }
}
