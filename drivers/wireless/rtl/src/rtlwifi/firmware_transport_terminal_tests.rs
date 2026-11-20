// SPDX-License-Identifier: GPL-2.0-or-later
//! Real PacketIo/source-cap/scalar/park closures over inert registers and
//! CURRENT BusDeviceCap operations. No physical PCI, reset, on-air or DMA-idle
//! receipt is simulated. The successful CPU-owner fixture bypasses download.
use super::*;
use alloc::{collections::BTreeMap, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    sync::atomic::AtomicUsize,
    task::{Context, Waker},
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, Read, Write};
use narf_firmware::FirmwareBlob;
use narf_kernel_test::{kernel_test_in, TestResult};
#[derive(Default)]
struct Model {
    regs: BTreeMap<u16, u8>,
    writes: Vec<(u8, u16, u32)>,
    deny: Option<u16>,
    master: bool,
    irq: bool,
}
#[derive(Clone)]
struct Original {
    cap: Cap<BusDeviceCap, Write>,
    model: Arc<IrqSafeSpinLock<Model>>,
}
impl Original {
    fn current<T>(&self, f: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        narf_drivers_wireless_rtw::rtw88::pci_park::invoke(&self.cap, f)
            .map_err(|_| Error::Access)?
    }
    fn put(&self, r: u16, v: u32, width: u8) -> Result<(), Error> {
        self.current(|| {
            let mut m = self.model.lock();
            if m.deny == Some(r) {
                return Err(Error::Access);
            }
            for i in 0..width {
                m.regs.insert(r + u16::from(i), (v >> (8 * i)) as u8);
            }
            m.writes.push((width, r, v));
            Ok(())
        })
    }
    fn get(&self, r: u16, width: u8) -> Result<u32, Error> {
        self.current(|| {
            let m = self.model.lock();
            Ok((0..width).fold(0, |v, i| {
                v | (u32::from(m.regs.get(&(r + u16::from(i))).copied().unwrap_or(0)) << (8 * i))
            }))
        })
    }
    fn master(&self, on: bool) -> Result<(), Error> {
        self.current(|| {
            let mut m = self.model.lock();
            m.master = on;
            m.writes.push((0, 0xfffe, u32::from(on)));
            Ok(())
        })
    }
}
#[async_trait::async_trait]
impl Io for Original {
    fn read8(&self, r: u16) -> Result<u8, Error> {
        self.get(r, 1).map(|v| v as u8)
    }
    fn read16(&self, r: u16) -> Result<u16, Error> {
        self.get(r, 2).map(|v| v as u16)
    }
    fn read32(&self, r: u16) -> Result<u32, Error> {
        self.get(r, 4)
    }
    fn write8(&self, r: u16, v: u8) -> Result<(), Error> {
        self.put(r, v.into(), 1)
    }
    fn write16(&self, r: u16, v: u16) -> Result<(), Error> {
        self.put(r, v.into(), 2)
    }
    fn write32(&self, r: u16, v: u32) -> Result<(), Error> {
        self.put(r, v, 4)
    }
    fn write_bytes(&self, r: u16, v: &[u8]) -> Result<(), Error> {
        for (i, b) in v.iter().enumerate() {
            self.write8(r + i as u16, *b)?;
        }
        Ok(())
    }
    fn restrict_8821_packets(&self) -> Result<(), Error> {
        let mac = crate::rtlwifi::rtl8821ae::park::close(self, || self.master(false));
        let irq = self.current(|| {
            let mut m = self.model.lock();
            m.irq = false;
            m.writes.push((0, 0xffff, 0));
            Ok(())
        });
        mac.and(irq)
    }
}
fn fixture() -> (
    Arc<Owner<Original>>,
    PacketIo<Original>,
    Original,
    Cap<FirmwareBlob, Read>,
) {
    let raw = Original {
        cap: Cap::bootstrap(),
        model: Arc::new(IrqSafeSpinLock::new(Model::default())),
    };
    raw.write16(0x100, 0x02ff).unwrap();
    raw.master(true).unwrap();
    raw.model.lock().irq = true;
    let image = Cap::bootstrap();
    let owner = Arc::new(Owner::new(
        raw.clone(),
        crate::rtlwifi::regs::RTL_DEV_8821AE,
    ));
    *owner.status.lock() = Status {
        stage: Stage::Ready,
        error: None,
    };
    *owner.identity.lock() = Some(Identity::fixture_with_source(&[0; 32], image));
    let io = owner.claim_packet_io().unwrap();
    (owner, io, raw, image)
}
fn require(ok: bool, message: &'static str) -> Result<(), &'static str> {
    if ok {
        Ok(())
    } else {
        Err(message)
    }
}
fn check(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    match f() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

struct RequestInputs {
    factory: super::super::efuse::Factory,
    base: super::super::rtl8821ae::envelope::Calibration,
    permission: super::super::rtl8821ae::envelope::Permission,
    source: Cap<FirmwareBlob, Read>,
}
fn request_inputs() -> Result<RequestInputs, &'static str> {
    use super::super::rtl8821ae::{envelope::Calibration, tests};
    let factory = super::super::efuse::Factory {
        // Never registered or delivered to physical PCI; this unique RAM
        // board name must be absent from the actual firmware registry.
        mac: [2, 0x21, 0x4e, 0x32, 0x31, 0x43],
        logical: tests::powered_logical(0xf2, 2),
    };
    let source = Cap::bootstrap();
    let base =
        Calibration::from_verified(&tests::napc(&factory, &[1], 30), Some([1; 32]), &factory)
            .map_err(|_| "8821 metadata NAPC fixture")?
            .with_fixture_source(source);
    let permission = base
        .permission(&super::super::channel_power::tests::domain(20), 1)
        .map_err(|_| "8821 metadata original permission")?;
    Ok(RequestInputs {
        factory,
        base,
        permission,
        source,
    })
}

fn smoke_8821_request_missing_asset_retains_original_metadata_without_retry() -> TestResult {
    check(|| {
        use super::super::rtl8821ae::coex_program::{self, BtIdentity};
        let (owner, io, raw, image_source) = fixture();
        let RequestInputs {
            factory,
            base,
            permission,
            source: napc_source,
        } = request_inputs()?;
        // The token is a framing-only test fixture. Production obtains it
        // solely from a complete actual original-RX GET_VERSION response.
        let bt = BtIdentity::observed(0x1234, 7).map_err(|_| "8821 metadata BT fixture")?;
        let image = owner.identity().ok_or("8821 metadata original image")?;
        let expected = coex_program::request(&base, image, &factory, permission, bt)
            .map_err(|_| "8821 metadata expected binding")?;
        let (_, registry) = narf_firmware::bootstrap_authority();
        let lookups = AtomicUsize::new(0);
        let before = raw.model.lock().writes.len();
        require(
            io.request_8821_program().is_none(),
            "8821 request existed before actual binding attempt",
        )?;
        let result = io.bind_8821_program_using(&base, &factory, permission, bt, |actual| {
            lookups.fetch_add(1, Ordering::AcqRel);
            if actual.digest != image.digest || io.request_8821_program() != Some(expected.clone())
            {
                return Err(super::super::prepare::Error::State);
            }
            // Real absent-asset lookup under a local revocable registry cap;
            // no process-global loader/trust state or record is installed.
            match crate::firmware_asset::load(&registry, &expected.name, 256, true) {
                Err(FirmwareError::NotFound) => Ok(None),
                _ => Err(super::super::prepare::Error::State),
            }
        });
        require(
            matches!(result, Ok(None))
                && io.request_8821_program() == Some(expected.clone())
                && io.1.program.get().is_none()
                && lookups.load(Ordering::Acquire) == 1
                && raw.model.lock().writes.len() == before,
            "8821 missing N21C lost exact prior request or performed device effects",
        )?;
        let changed = BtIdentity::observed(0x4321, 8).map_err(|_| "8821 changed BT fixture")?;
        require(
            io.bind_8821_program_using(&base, &factory, permission, changed, |_| {
                lookups.fetch_add(1, Ordering::AcqRel);
                Ok(None)
            })
            .is_err()
                && io.request_8821_program() == Some(expected.clone())
                && lookups.load(Ordering::Acquire) == 1
                && io.1.program.get().is_none(),
            "8821 retained request was replaced or retried for a late grant",
        )?;
        // The historical getter deliberately has no live-source admission.
        // Revocation/retirement cannot turn it into current RF authority.
        napc_source.revoke();
        image_source.revoke();
        io.1.retired.store(true, Ordering::Release);
        for _ in 0..2 {
            require(
                io.request_8821_program() == Some(expected.clone()),
                "8821 historical request changed after source revocation/retirement",
            )?;
        }
        require(
            raw.model.lock().writes.len() == before
                && io.1.program.get().is_none()
                && owner.native_claimed.load(Ordering::Acquire)
                && owner.claim_packet_io().is_err(),
            "8821 metadata getter emitted H2C, installed authority or reopened original claim",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_request_missing_asset_retains_original_metadata_without_retry
);

fn smoke_8821_request_retention_requires_current_original_image_and_napc() -> TestResult {
    check(|| {
        use super::super::rtl8821ae::coex_program::BtIdentity;
        for revoke_image in [false, true] {
            let (_owner, io, raw, image) = fixture();
            let RequestInputs {
                factory,
                base,
                permission,
                source: napc,
            } = request_inputs()?;
            let bt = BtIdentity::observed(0x1234, 7).map_err(|_| "8821 source BT fixture")?;
            if revoke_image {
                image.revoke();
            } else {
                napc.revoke();
            }
            let lookups = AtomicUsize::new(0);
            let before = raw.model.lock().writes.len();
            require(
                io.bind_8821_program_using(&base, &factory, permission, bt, |_| {
                    lookups.fetch_add(1, Ordering::AcqRel);
                    Ok(None)
                })
                .is_err()
                    && lookups.load(Ordering::Acquire) == 0
                    && io.request_8821_program().is_none()
                    && io.1.program.get().is_none()
                    && raw.model.lock().writes.len() == before,
                "8821 dead original source reached request retention or asset lookup",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_request_retention_requires_current_original_image_and_napc
);

fn smoke_8821_terminal_scalar_retirement_and_owned_publication_close_last() -> TestResult {
    check(|| {
        let (owner, io, raw, _image) = fixture();
        let terminal = io
            .terminal_8821()
            .ok_or("8821 original terminal callback absent")?;
        let pci = raw.cap;
        let publication =
            crate::rtlwifi::prepare::packet::Publication::model(Arc::new(move || {
                narf_drivers_wireless_rtw::rtw88::pci_park::invoke(&pci, || Ok(()))
                    .map_err(|_| crate::rtlwifi::prepare::Error::State)?
            }));
        let publication = io.guard_8821_publication(publication);
        let effects = AtomicUsize::new(0);
        publication
            .invoke(|| {
                effects.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
            .map_err(|_| "8821 live original publication")?;
        require(
            io.with_io(|_| io.write8(0x522, 0)).is_ok(),
            "8821 outer authority recursively held scalar lock",
        )?;
        require(
            io.with_effect_io(|original| {
                assert!(
                    io.1.scalar.try_lock().is_none(),
                    "actual8821 scalar missed shared park gate"
                );
                // Model retirement racing an already ADMITTED scalar; it completes
                // before park obtains this same gate. Never call park under the gate.
                io.1.retired.store(true, Ordering::Release);
                original.master(true)?;
                original.write16(0x100, 0x02ff)
            })
            .is_ok(),
            "8821 admitted scalar could not finish before restrictive park",
        )?;
        let before = raw.model.lock().writes.len();
        terminal
            .park()
            .map_err(|_| "8821 restrictive original-PCI park")?;
        let m = raw.model.lock();
        require(
            m.writes[before..]
                == [
                    (4, 0xb0, 0),
                    (4, 0xb8, 0),
                    (1, 0x522, 255),
                    (1, 0x301, 255),
                    (1, 0x100, 0x30),
                    (0, 0xfffe, 0),
                    (0, 0xffff, 0),
                ],
            "8821 source park scalar order/width/readback",
        )?;
        require(
            !m.master && !m.irq,
            "8821 independent BME/MSI withdrawal absent",
        )?;
        drop(m);
        let n = raw.model.lock().writes.len();
        require(
            io.write16(0x100, 0x02ff).is_err()
                && io.with_effect_io(|raw| raw.master(true)).is_err()
                && io.read32(0xb0).is_err(),
            "8821 retired scalar reopened/read hardware",
        )?;
        require(
            publication
                .invoke(|| {
                    effects.fetch_add(1, Ordering::AcqRel);
                    Ok(())
                })
                .is_err()
                && effects.load(Ordering::Acquire) == 1,
            "8821 captured pre-install publication escaped retired source",
        )?;
        require(
            raw.model.lock().writes.len() == n
                && owner.native_claimed.load(Ordering::Acquire)
                && owner.claim_packet_io().is_err(),
            "8821 terminal park replayed effects/reopened original claim",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_terminal_scalar_retirement_and_owned_publication_close_last
);
fn smoke_8821_terminal_firmware_loss_uses_only_current_original_pci() -> TestResult {
    check(|| {
        for revoke_pci in [false, true] {
            let (_owner, io, raw, image) = fixture();
            let terminal = io.terminal_8821().unwrap();
            image.revoke();
            let n = raw.model.lock().writes.len();
            require(
                io.write8(0x100, 0xff).is_err() && raw.model.lock().writes.len() == n,
                "8821 lost image emitted scalar",
            )?;
            if revoke_pci {
                raw.cap.revoke();
            }
            require(
                terminal.park().is_ok() != revoke_pci,
                "8821 cleanup borrowed dead image/PCI authority",
            )?;
            let m = raw.model.lock();
            require(
                if revoke_pci {
                    m.writes.len() == n && m.master && m.irq
                } else {
                    m.writes.len() > n && !m.master && !m.irq
                },
                "8821 revoked/current PCI park effects disagree",
            )?;
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_terminal_firmware_loss_uses_only_current_original_pci
);
fn smoke_8821_terminal_partial_park_attempts_independent_restrictive_gates() -> TestResult {
    check(|| {
        let (_owner, io, raw, _image) = fixture();
        raw.model.lock().deny = Some(0xb0);
        let before = raw.model.lock().writes.len();
        require(
            io.terminal_8821().unwrap().park().is_err(),
            "8821 partial gate was called a successful park",
        )?;
        let m = raw.model.lock();
        require(
            m.writes[before..]
                .iter()
                .any(|(_, r, v)| *r == 0xb8 && *v == 0)
                && m.writes[before..]
                    .iter()
                    .any(|(_, r, v)| *r == 0x301 && *v == 255)
                && !m.master
                && !m.irq,
            "8821 denied gate skipped independent stop/BME/MSI",
        )?;
        drop(m);
        require(
            io.write8(0x522, 0).is_err(),
            "8821 failed restrictive park unretired scalar admission",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_terminal_partial_park_attempts_independent_restrictive_gates
);
fn smoke_8821_terminal_owned_drop_callback_survives_cancelled_wait() -> TestResult {
    check(|| {
        struct OnDrop(Option<crate::rtlwifi::prepare::packet::TerminalPark>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                if let Some(park) = &self.0 {
                    let _ = park.park();
                }
            }
        }
        let (owner, io, raw, _image) = fixture();
        let terminal = io.terminal_8821().unwrap();
        {
            let future = async {
                let _guard = OnDrop(Some(terminal));
                io.write8(0x522, 0)?;
                core::future::pending::<()>().await;
                Ok::<(), Error>(())
            };
            let mut future = pin!(future);
            require(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending(),
                "8821 cancellation fixture did not hold source wait",
            )?;
        }
        let m = raw.model.lock();
        require(
            !m.master && !m.irq && m.regs.get(&0x522) == Some(&255),
            "8821 cancelled wait lost owned terminal closure",
        )?;
        drop(m);
        require(
            io.write8(0x100, 0xff).is_err() && owner.native_claimed.load(Ordering::Acquire),
            "8821 cancelled wait reopened native effect/claim",
        )
    })
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/rtl8821ae",
    smoke_8821_terminal_owned_drop_callback_survives_cancelled_wait
);
