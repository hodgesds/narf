// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual native firmware/cold owner transfers and checked accesses.
//! This is a child of existing runtime_tests and reuses its full register/RF
//! actor and real firmware/cold trajectories, not an extracted algorithm.
use super::super::{
    checked::FactoryIo,
    cold_storage,
    retained::{Backend, Retained},
};
use super::*;
use crate::rtlwifi::firmware_transport::{Owner as FirmwareOwner, PacketIo};
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, Waker},
};
use narf_capabilities::{Cap, Write};

#[derive(Clone)]
struct CheckedPort {
    port: Port,
    cap: Cap<narf_bus::BusDeviceCap, Write>,
    master: Arc<core::sync::atomic::AtomicBool>,
    factory: Option<super::super::factory::tests::Port>,
}
impl CheckedPort {
    fn new() -> Self {
        let port = Port::new();
        port.set8(0x60, 2); // Independent AE GPIO input: radio-on, low-active.
        Self {
            port,
            cap: Cap::bootstrap(),
            master: Arc::new(core::sync::atomic::AtomicBool::new(false)),
            factory: None,
        }
    }
}
impl Backend for CheckedPort {
    fn restrict_packets(&self) -> Result<(), AccessError> {
        super::super::park::close(self, || {
            self.current(|s| {
                s.master.store(false, core::sync::atomic::Ordering::Release);
                s.port.0.lock().events.push(Event::Master(false));
                Ok(())
            })
        })
    }
    fn address(&self) -> narf_bus::BusAddr {
        narf_bus::BusAddr::Pcie(narf_bus::PcieAddr::new(0xfffd, 0, 1, 0))
    }
    fn current<T>(
        &self,
        f: impl FnOnce(&Self) -> Result<T, AccessError>,
    ) -> Result<T, AccessError> {
        crate::rtw88::pci_park::invoke(&self.cap, || f(self)).map_err(|_| AccessError::Access)?
    }
    fn identity(&self) -> Result<cold_storage::PciIdentity, AccessError> {
        self.current(|_| Ok(cold_storage::PciIdentity::fixture(self.address())))
    }
}
#[async_trait::async_trait]
impl Io for CheckedPort {
    fn read8(&self, r: u16) -> Result<u8, AccessError> {
        if matches!(r, 0x30..=0x37 | 0xcf) {
            if let Some(factory) = &self.factory {
                return self.current(|_| super::super::factory::Regs::read8(factory, r));
            }
        }
        self.current(|s| s.port.read8(r))
    }
    fn read16(&self, r: u16) -> Result<u16, AccessError> {
        if r & 1 != 0 {
            return Err(AccessError::Access);
        }
        self.current(|s| {
            let mut model = s.port.0.lock();
            model.events.push(Event::R16(r));
            let at = usize::from(r);
            Ok(u16::from_le_bytes(
                model.regs[at..at + 2].try_into().unwrap(),
            ))
        })
    }
    fn read32(&self, r: u16) -> Result<u32, AccessError> {
        if matches!(r, 0x30..=0x34) {
            if let Some(factory) = &self.factory {
                return self.current(|_| super::super::factory::Regs::read32(factory, r));
            }
        }
        self.current(|s| s.port.read32(r))
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), AccessError> {
        if matches!(r, 0x30..=0x37 | 0xcf) {
            if let Some(factory) = &self.factory {
                self.current(|_| super::super::factory::Regs::write8(factory, r, v))?;
            }
        }
        self.current(|s| s.port.write8(r, v))
    }
    fn write16(&self, r: u16, v: u16) -> Result<(), AccessError> {
        self.current(|s| s.port.write16(r, v))
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), AccessError> {
        if matches!(r, 0x30..=0x34) {
            if let Some(factory) = &self.factory {
                self.current(|_| super::super::factory::Regs::write32(factory, r, v))?;
            }
        }
        self.current(|s| s.port.write32(r, v))
    }
    fn write_bytes(&self, r: u16, b: &[u8]) -> Result<(), AccessError> {
        self.current(|s| s.port.write_bytes(r, b))
    }
    async fn delay_us(&self, us: u64) {
        self.port.delay_us(us).await;
    }
}
fn factory() -> Arc<crate::rtlwifi::efuse::Factory> {
    // Inert input identity only. These tests call no successful Factory
    // acquisition or signed native RF constructor with this synthetic map.
    Arc::new(crate::rtlwifi::efuse::Factory {
        mac: [2, 1, 2, 3, 4, 5],
        logical: [0xff; 512],
    })
}
fn ready() -> (
    CheckedPort,
    Arc<FirmwareOwner<CheckedPort>>,
    Arc<Retained<CheckedPort>>,
) {
    let port = CheckedPort::new();
    let owner = Arc::new(FirmwareOwner::new(port.clone(), DEV_ID));
    assert!(run(owner.initialize(&firmware_image())).is_ok());
    let retained = Retained::allocate(owner.clone(), factory()).unwrap();
    retained.attach_name("ae-retained-inert-model").unwrap();
    assert!(retained.commit(port.address(), &owner));
    (port, owner, retained)
}
fn poll<F: Future>(f: Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}
fn smoke_ae_exact_original_box_transfer_and_generic_refusal() -> TestResult {
    let (port, owner, root) = ready();
    let original =
        run(owner.ae_fixture_lock()).as_ref().unwrap().as_ref() as *const init::Owner as usize;
    // Rejected generic path must not consume the specialized native claim.
    kt_assert!(matches!(
        owner.claim_packet_io(),
        Err(AccessError::Unsupported)
    ));
    let writes = port.port.writes().len();
    let bound = run(owner.claim_ae_cold(&root)).unwrap();
    kt_assert_eq!(bound.original_address(), original);
    kt_assert!(run(owner.ae_fixture_lock()).is_none());
    kt_assert_eq!(
        bound.version(),
        version::Version::from_registers(0x10000, || 0, || 0).unwrap()
    );
    kt_assert_eq!(bound.ephy_retries(), 1);
    kt_assert_eq!(bound.chnlval()[0], 0xf401);
    kt_assert_eq!(port.port.writes().len(), writes); // no cold replay or IOCTL
    kt_assert!(matches!(
        run(owner.claim_ae_cold(&root)),
        Err(AccessError::AlreadyStarted)
    ));
    TestResult::Pass
}
fn smoke_ae_cold_claim_cancellation_and_post_lock_refusal_retain_box() -> TestResult {
    for fail_status in [false, true] {
        let (port, owner, root) = ready();
        let cold = run(owner.ae_fixture_lock());
        let original = cold.as_ref().unwrap().as_ref() as *const init::Owner as usize;
        let mut claim = Box::pin(owner.claim_ae_cold(&root));
        kt_assert!(poll(claim.as_mut()).is_pending()); // destination held, cold wait pending
        if fail_status {
            owner.ae_fixture_fail();
        } else {
            port.cap.revoke();
        }
        drop(cold);
        kt_assert!(matches!(poll(claim.as_mut()), Poll::Ready(Err(_))));
        drop(claim);
        let saved = run(owner.ae_fixture_lock());
        kt_assert_eq!(
            saved.as_ref().unwrap().as_ref() as *const init::Owner as usize,
            original
        );
        kt_assert!(root.cold.empty());
    }
    let (_, owner, root) = ready();
    let destination = run(root.state.lock());
    let mut claim = Box::pin(owner.claim_ae_cold(&root));
    kt_assert!(poll(claim.as_mut()).is_pending());
    drop(claim);
    drop(destination);
    kt_assert!(run(owner.ae_fixture_lock()).is_some());
    kt_assert!(matches!(
        run(owner.claim_ae_cold(&root)),
        Err(AccessError::AlreadyStarted)
    ));
    TestResult::Pass
}
fn smoke_ae_factory_io_current_source_and_independent_cleanup() -> TestResult {
    for revoke_pci in [false, true] {
        let (port, owner, root) = ready();
        run(owner.claim_ae_cold(&root)).unwrap();
        let io = FactoryIo::new(root.clone(), owner.identity().unwrap());
        kt_assert_eq!(io.write8(0xcf, 0x69), Ok(()));
        let writes = port.port.writes().len();
        root.retire();
        kt_assert_eq!(io.write16(2, 0x1234), Err(AccessError::Gate));
        kt_assert_eq!(port.port.writes().len(), writes);
        if revoke_pci {
            port.cap.revoke();
        }
        let closed = io.write8(0xcf, 0);
        if revoke_pci {
            kt_assert!(closed.is_err());
            kt_assert_eq!(port.port.writes().len(), writes); // no raw cleanup escape
        } else {
            kt_assert_eq!(closed, Ok(()));
            kt_assert_eq!(io.read8(0xcf), Ok(0)); // exact current PCI readback
            kt_assert_eq!(port.port.writes().last(), Some(&(1, 0xcf, 0)));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae/retained",
    smoke_ae_exact_original_box_transfer_and_generic_refusal
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae/retained",
    smoke_ae_cold_claim_cancellation_and_post_lock_refusal_retain_box
);
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8723ae/retained",
    smoke_ae_factory_io_current_source_and_independent_cleanup
);

#[path = "supervision_tests.rs"]
mod supervision_tests;

#[cfg(feature = "kernel-test")]
fn smoke_ae_original_firmware_source_revoked_during_cold_lock_wait() -> TestResult {
    let port = CheckedPort::new();
    let owner = Arc::new(FirmwareOwner::new(port.clone(), DEV_ID));
    let (write, read) = narf_firmware::bootstrap_authority();
    let name = "rtlwifi/ae-retained-original-source-lock-fixture.bin";
    crate::firmware_asset::tests::install(&write, name, &firmware_image(), true).unwrap();
    run(owner.initialize_registered_fixture(&read, name)).unwrap();
    let root = Retained::allocate(owner.clone(), factory()).unwrap();
    kt_assert!(root.commit(port.address(), &owner));
    let cold = run(owner.ae_fixture_lock());
    let address = cold.as_ref().unwrap().as_ref() as *const init::Owner as usize;
    let mut claim = Box::pin(owner.claim_ae_cold(&root));
    kt_assert!(poll(claim.as_mut()).is_pending());
    kt_assert!(owner.identity().unwrap().revoke_source());
    let at = port.port.writes().len();
    drop(cold);
    kt_assert!(matches!(poll(claim.as_mut()), Poll::Ready(Err(_))));
    drop(claim);
    kt_assert_eq!(port.port.writes().len(), at);
    kt_assert_eq!(
        run(owner.ae_fixture_lock()).as_ref().unwrap().as_ref() as *const init::Owner as usize,
        address
    );
    kt_assert!(root.cold.empty());
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae", smoke_ae_original_firmware_source_revoked_during_cold_lock_wait}

#[cfg(feature = "kernel-test")]
fn smoke_ae_pending_cold_retirement_and_image_revocation_stop_actual_polls() -> TestResult {
    for retired in [true, false] {
        let port = CheckedPort::new();
        port.port.0.lock().pause_delay = Some(50_000);
        let owner = Arc::new(FirmwareOwner::new(port.clone(), DEV_ID));
        let root = Retained::allocate(owner.clone(), factory()).unwrap();
        kt_assert!(root.commit(port.address(), &owner));
        let name = if retired {
            "rtlwifi/ae-original-cold-retire-fixture.bin"
        } else {
            "rtlwifi/ae-original-cold-image-revoke-fixture.bin"
        };
        let (write, read) = narf_firmware::bootstrap_authority();
        crate::firmware_asset::tests::install(&write, name, &firmware_image(), true).unwrap();
        let mut cold = Box::pin(owner.initialize_registered_fixture(&read, name));
        kt_assert!(poll(cold.as_mut()).is_pending());
        kt_assert_eq!(
            owner.status().stage,
            crate::rtlwifi::firmware_transport::Stage::Downloading
        );
        let writes = port.port.writes().len();
        if retired {
            root.retire();
        } else {
            kt_assert!(owner.ae_fixture_source().unwrap().revoke_source());
        }
        port.port.0.lock().pause_delay = None;
        kt_assert!(matches!(poll(cold.as_mut()), Poll::Ready(Err(_))));
        drop(cold);
        kt_assert_eq!(port.port.writes().len(), writes);
        kt_assert_eq!(
            owner.status().stage,
            crate::rtlwifi::firmware_transport::Stage::Failed
        );
        kt_assert_eq!(
            run(owner.ae_fixture_lock()).as_ref().unwrap().phase(),
            init::Phase::Failed
        );
        kt_assert!(run(owner.claim_ae_cold(&root)).is_err());
        kt_assert!(root.cold.empty());
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
kernel_test_in! {"drivers/wireless/rtlwifi/rtl8723ae",smoke_ae_pending_cold_retirement_and_image_revocation_stop_actual_polls}
