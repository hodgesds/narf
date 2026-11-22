//! RAM register/record fixtures. Verified signer markers test the format
//! and real capability invocations; they are not measured board records.
use super::*;
use crate::ath9k::{
    admission::{Facts, Source},
    ar9003::{board, eeprom, phy, serdes, templates::AR9300_DEFAULT, Revision},
};
use alloc::{collections::BTreeMap, sync::Arc, vec, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};
use narf_firmware::FirmwareBlob;
use narf_kernel_test::{kernel_test_in, TestResult};

pub(in crate::ath9k) struct Fixture {
    pub(in crate::ath9k) power: Power,
    pub(in crate::ath9k) grant: Arc<Grant>,
    pub(in crate::ath9k) cap: Cap<FirmwareBlob, Read>,
    pub(in crate::ath9k) base: power::Plan,
}
pub(in crate::ath9k) fn fixture(device: u16, frequency: u16) -> Result<Fixture, &'static str> {
    let chip = match device {
        0x0034 => Chip::Ar9462,
        0x0036 => Chip::Ar9565,
        _ => return Err("MCI fixture device"),
    };
    let mask = if chip == Chip::Ar9462 { 3 } else { 1 };
    let id = narf_bus::DeviceId {
        vendor: 0x168c,
        device,
        class: 0x028000,
        subsystem_vendor: 0,
        subsystem_id: 0,
    };
    let mut image = AR9300_DEFAULT;
    image[eeprom::field::TXRX_MASK] = mask | (mask << 4);
    let identity = eeprom::Identity {
        mac: [2, 1, 2, 3, 4, 5],
        eeprom_version: image[0],
        template_version: image[1],
        regulatory_domains: [0x3a, 0],
        op_flags: 3,
        rx_chainmask: mask,
        tx_chainmask: mask,
        tx_gain: 0,
        rx_gain: 0,
    };
    let revision = Revision {
        chip,
        mac_rev: 2,
        pcie: true,
    };
    let ctl = if frequency < 4000 { 0x12 } else { 0x10 };
    let prepared = phy::expected_with_board(
        &revision,
        &identity,
        serdes::PllPwrsave::resolve(chip, 0, 0),
        &image,
        frequency,
        ctl,
        0,
        board::Config::for_pci(&id),
    )
    .map_err(|_| "MCI fixture preparation")?;
    let facts = Facts::new_ar9003(&id, &revision, &identity, &prepared, &image, frequency, ctl)
        .map_err(|_| "MCI fixture facts")?;
    let request = facts.request();
    let mut bytes = vec![0u8; 128];
    bytes[..4].copy_from_slice(if chip == Chip::Ar9462 {
        b"N46A"
    } else {
        b"N65A"
    });
    bytes[4..12].copy_from_slice(&[1, 0, 128, 0, 128, 0, 0, 0]);
    bytes[12..14].copy_from_slice(&id.vendor.to_le_bytes());
    bytes[14..16].copy_from_slice(&device.to_le_bytes());
    bytes[16..48].copy_from_slice(&request.identity);
    bytes[48..54].copy_from_slice(&request.mac);
    let channel = if frequency >= 4800 {
        ((frequency - 5000) / 5) as u8
    } else {
        ((frequency - 2407) / 5) as u8
    };
    let gain = image[eeprom::modal_base(frequency >= 4800) + eeprom::modal::ANTENNA_GAIN] as i8;
    bytes[54..60].copy_from_slice(&[channel, 20, mask, mask, gain.max(0) as u8, 40]);
    let cap = Cap::<FirmwareBlob, Read>::bootstrap();
    let grant = Source::Verified {
        bytes,
        signer: Some([0x46; 32]),
        cap,
    }
    .load(facts)
    .map_err(|_| "MCI fixture record")?;
    let base = power::plan(&image, frequency, ctl, grant.ceiling(40), mask)
        .map_err(|_| "MCI fixture base plan")?;
    Ok(Fixture {
        power: Power::new(device, &grant, base).ok_or("MCI fixture power binding")?,
        grant,
        cap,
        base,
    })
}
pub(in crate::ath9k) fn install(raw: &impl Raw, fixture: &Fixture) -> Result<(), Error> {
    let mut io = Qualified {
        raw,
        grant: &fixture.grant,
        error: None,
    };
    power::program(&mut io, fixture.power.chip, &fixture.base).map_err(|_| Error::Descriptor)?;
    check(&mut io, fixture.power.chip, &fixture.base)?;
    io.error.map_or(Ok(()), Err)
}

struct Current<F>(F);
impl<T, F: FnOnce() -> Result<T, Error>> CapOp<narf_bus::BusDeviceCap, Write> for Current<F> {
    type Output = Result<T, Error>;
    fn execute(self, _: &Cap<narf_bus::BusDeviceCap, Write>) -> Result<Self::Output, CapError> {
        Ok((self.0)())
    }
}
struct Model {
    pci: Cap<narf_bus::BusDeviceCap, Write>,
    regs: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    corrupt: Cell<Option<u64>>,
    revoke_record_on_write: Cell<Option<Cap<FirmwareBlob, Read>>>,
    revoke_pci_on_write: Cell<bool>,
}
impl Model {
    fn new() -> Self {
        Self {
            pci: Cap::bootstrap(),
            regs: RefCell::new(BTreeMap::from([(0x7044, 2)])),
            writes: RefCell::new(Vec::new()),
            corrupt: Cell::new(None),
            revoke_record_on_write: Cell::new(None),
            revoke_pci_on_write: Cell::new(false),
        }
    }
}
impl Raw for Model {
    fn read(&self, register: u64) -> Result<u32, Error> {
        self.pci
            .invoke(Current(|| {
                Ok(self.regs.borrow().get(&register).copied().unwrap_or(0))
            }))
            .map_err(|_| Error::Access)?
    }
    fn write(&self, register: u64, value: u32) -> Result<(), Error> {
        self.pci
            .invoke(Current(|| {
                self.writes.borrow_mut().push((register, value));
                self.regs.borrow_mut().insert(
                    register,
                    if self.corrupt.get() == Some(register) {
                        value ^ 1
                    } else {
                        value
                    },
                );
                if let Some(cap) = self.revoke_record_on_write.take() {
                    cap.revoke();
                }
                if self.revoke_pci_on_write.replace(false) {
                    self.pci.revoke();
                }
                Ok(())
            }))
            .map_err(|_| Error::Access)?
    }
}

fn run_transition(device: u16) -> Result<(), &'static str> {
    let mut f = fixture(device, 2412)?;
    let model = Model::new();
    install(&model, &f).map_err(|_| "MCI power install")?;
    if f.base.targets[8..22].iter().all(|&v| v <= 20) {
        return Err("fixture has no calibrated cap transition");
    }
    let before = f.base;
    f.power
        .transition(&model, &f.grant, true)
        .map_err(|_| "MCI enable")?;
    let capped = plan(&before, true);
    if f.power.words().ok() != Some(power::rate_words(&capped.targets))
        || capped.targets[..8] != before.targets[..8]
        || capped.targets[22..] != before.targets[22..]
        || capped.targets[8..22].iter().any(|&v| v > 20)
        || capped.targets[8..22]
            .iter()
            .zip(&before.targets[8..22])
            .any(|(&actual, &original)| actual != original.min(0x14))
        || capped.correction != before.correction
        || capped.temperature != before.temperature
        || capped.voltage != before.voltage
        || capped.nf_cal != before.nf_cal
        || capped.nf_power != before.nf_power
        || capped.temp_slope != before.temp_slope
    {
        return Err("MCI cap changed original legacy/calibration program");
    }
    let writes = model.writes.borrow().len();
    f.power
        .transition(&model, &f.grant, true)
        .map_err(|_| "MCI repeated enable")?;
    if model.writes.borrow().len() != writes {
        return Err("MCI repeated state rewrote power");
    }
    f.power
        .transition(&model, &f.grant, false)
        .map_err(|_| "MCI disable")?;
    if f.power.words().ok() != Some(power::rate_words(&before.targets)) {
        return Err("MCI disable did not restore immutable calibrated plan");
    }
    let mut five = fixture(device, 5180)?;
    let five_model = Model::new();
    install(&five_model, &five).map_err(|_| "5G install")?;
    let count = five_model.writes.borrow().len();
    if five
        .power
        .transition(&five_model, &five.grant, true)
        .is_ok()
        || five_model.writes.borrow().len() != count
        || plan(&five.base, true) != five.base
    {
        return Err("5G MCI transition changed power");
    }
    Ok(())
}
fn smoke_ath9k_mci_concurrent_calibrated_power_plans() -> TestResult {
    for device in [0x0034, 0x0036] {
        if let Err(error) = run_transition(device) {
            return TestResult::Fail(error);
        }
    }
    TestResult::Pass
}
fn refusal() -> Result<(), &'static str> {
    for mode in 0..5 {
        let mut f = fixture(0x0034, 2412)?;
        let model = Model::new();
        install(&model, &f).map_err(|_| "refusal install")?;
        model.writes.borrow_mut().clear();
        match mode {
            0 => f.cap.revoke(),
            1 => model.pci.revoke(),
            2 => model.corrupt.set(Some(0xa3c0)),
            3 => model.revoke_record_on_write.set(Some(f.cap)),
            _ => model.revoke_pci_on_write.set(true),
        }
        if f.power.transition(&model, &f.grant, true).is_ok() || f.power.enabled {
            return Err("failed current-source/readback MCI transition committed");
        }
        let count = model.writes.borrow().len();
        if mode < 2 && count != 0 {
            return Err("revoked MCI source reached native write");
        }
        if mode >= 2 && (count == 0 || f.power.words().is_ok()) {
            return Err("ambiguous power mutation did not retain terminal uncertainty");
        }
        if f.power.transition(&model, &f.grant, false).is_ok()
            || model.writes.borrow().len() != count
        {
            return Err("failed MCI transition reopened native writes");
        }
        if mode == 2 {
            // A software reset does not recover wrong hardware. Only the
            // actual base program, while reset owns DMA, permits reset().
            if f.power.reset(&model, &f.grant, &f.base).is_ok() {
                return Err("wrong physical plan cleared MCI uncertainty");
            }
            model.corrupt.set(None);
            install(&model, &f).map_err(|_| "actual reset plan")?;
            f.power
                .reset(&model, &f.grant, &f.base)
                .map_err(|_| "qualified reset")?;
            if f.power.words().ok() != Some(power::rate_words(&f.base.targets)) {
                return Err("qualified reset did not restore base history");
            }
        }
    }
    let f = fixture(0x0034, 2412)?;
    let other = fixture(0x0036, 2412)?;
    if Power::new(0x0034, &other.grant, f.base).is_some() {
        return Err("MCI power bound a foreign part record");
    }
    Ok(())
}
fn smoke_ath9k_mci_concurrent_current_sources_and_failed_readbacks() -> TestResult {
    refusal().map_or_else(TestResult::Fail, |_| TestResult::Pass)
}
fn smoke_ath9k_mci_concurrent_literal_rssi_counter() -> TestResult {
    let mut rssi = Rssi::default();
    for value in [39, 39, 40, 40, 40, 40] {
        if rssi.period(value).is_some() {
            return TestResult::Fail("concurrent RSSI sign-reset/fifth boundary");
        }
    }
    if rssi.period(40) != Some(true) {
        return TestResult::Fail("RSSI40 did not enable on fifth strong period");
    }
    for value in [0, 0, 40, 39, 39, 39, 39] {
        if rssi.period(value).is_some() {
            return TestResult::Fail("weak RSSI sign-reset/fifth boundary");
        }
    }
    if rssi.period(39) != Some(false) {
        return TestResult::Fail("RSSI39 did not disable on fifth weak period");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_mci_concurrent_calibrated_power_plans
);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_mci_concurrent_current_sources_and_failed_readbacks
);
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_mci_concurrent_literal_rssi_counter
);
