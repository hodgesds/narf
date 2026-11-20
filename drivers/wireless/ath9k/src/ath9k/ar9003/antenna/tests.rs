//! RAM-only register/record fixtures. Source::Verified marks format-only
//! qualification; neither these markers nor the template are measured RF data.
use super::*;
use crate::ath9k::{
    admission::{Facts, Source},
    ar9003::{eeprom, phy, serdes, templates::AR9300_DEFAULT, Revision},
};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_capabilities::{Cap, CapError, CapOp, Read, Write};
use narf_firmware::FirmwareBlob;
use narf_kernel_test::{kernel_test_in, TestResult};

pub(in crate::ath9k) fn device() -> DeviceId {
    DeviceId {
        vendor: 0x168c,
        device: 0x0032,
        class: 0x028000,
        subsystem_vendor: 0,
        subsystem_id: 0,
    }
}
pub(in crate::ath9k) fn factory(raw: u8) -> (Image, eeprom::Identity) {
    let mut image = AR9300_DEFAULT;
    image[field::TXRX_MASK] = 0x11;
    image[field::OP_FLAGS] = 2;
    image[field::TXRX_GAIN] = 0;
    image[field::EXT1 + field::EXT1_ANT_DIV_CONTROL] = raw;
    let identity = eeprom::Identity {
        mac: [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        eeprom_version: image[0],
        template_version: image[1],
        regulatory_domains: [0x3a, 0],
        op_flags: 2,
        rx_chainmask: 1,
        tx_chainmask: 1,
        tx_gain: 0,
        rx_gain: 0,
    };
    (image, identity)
}

type QualifiedFixture = (Profile, Arc<Grant>, Cap<FirmwareBlob, Read>);
pub(in crate::ath9k) fn fixture(id: DeviceId, raw: u8) -> Result<QualifiedFixture, Error> {
    let (image, identity) = factory(raw);
    let chip = Chip::for_device(id.device).ok_or(Error::State)?;
    let revision = Revision {
        chip,
        mac_rev: 1,
        pcie: true,
    };
    let prepared = phy::expected_with_board(
        &revision,
        &identity,
        serdes::PllPwrsave::resolve(chip, id.subsystem_vendor, id.subsystem_id),
        &image,
        2412,
        0x12,
        0,
        super::super::board::Config::for_pci(&id),
    )
    .map_err(|_| Error::Descriptor)?;
    let facts = Facts::new_ar9003(&id, &revision, &identity, &prepared, &image, 2412, 0x12)
        .map_err(|_| Error::Descriptor)?;
    let request = facts.request();
    let mut bytes = vec![0u8; 128];
    bytes[..8].copy_from_slice(if chip == Chip::Ar9565 {
        b"N65A\x01\0\x80\0"
    } else {
        b"N48A\x01\0\x80\0"
    });
    bytes[8..12].copy_from_slice(&128u32.to_le_bytes());
    bytes[12..14].copy_from_slice(&id.vendor.to_le_bytes());
    bytes[14..16].copy_from_slice(&id.device.to_le_bytes());
    bytes[16..48].copy_from_slice(&request.identity);
    bytes[48..54].copy_from_slice(&request.mac);
    bytes[54..60].copy_from_slice(&[1, 20, 1, 1, 128, 30]);
    let cap = Cap::<FirmwareBlob, Read>::bootstrap();
    let grant = Source::Verified {
        bytes,
        signer: Some([0x48; 32]),
        cap,
    }
    .load(facts)
    .map_err(|_| Error::Access)?;
    Ok((
        Profile::for_device(&id, &image).ok_or(Error::State)?,
        grant,
        cap,
    ))
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::ath9k) struct History {
    scanner: Scanner,
    logical: u8,
    other: u8,
}
pub(in crate::ath9k) fn sampled_history(shared: &Shared) -> History {
    let state = shared.0.lock();
    History {
        scanner: state.scanner,
        logical: state.logical,
        other: state.other,
    }
}
pub(in crate::ath9k) fn history(shared: &Shared) -> (u8, u8, bool) {
    let state = shared.0.lock();
    (state.logical, state.other, state.active)
}
fn smoke_ath9k_ar9565_source_pci_capability_and_retained_default_owner() -> TestResult {
    for (subvendor, subdevice, capable) in [
        (0, 0, true), // Generic0036 has BT_ANT_DIV in the source table.
        (0x168c, 0x3028, true),
        (0x1a3b, 0x2176, true),
        (0x105b, 0xe068, false),
        (0x185f, 0xa119, false),
        (0x11ad, 0x0632, false),
        (0x11ad, 0x06b2, false),
        (0x11ad, 0x0842, false),
        (0x11ad, 0x1842, false),
        (0x11ad, 0x6671, false),
        (0x1b9a, 0x2811, false),
        (0x1b9a, 0x2812, false),
        (0x1b9a, 0x28a1, false),
        (0x1b9a, 0x28a3, false),
        (0x1a3b, 0x218a, false),
        (0x1a3b, 0x2f8a, false),
        (0x1a3b, 0x218b, true),
        (0x105b, 0xe069, true),
    ] {
        let id = DeviceId {
            device: 0x0036,
            subsystem_vendor: subvendor,
            subsystem_id: subdevice,
            ..device()
        };
        let (profile, grant, cap) = match fixture(id, 0) {
            Ok(fixture) => fixture,
            Err(_) => return TestResult::Fail("N65A default-antenna fixture"),
        };
        if profile.raw != 0xc9 || profile.capable() != capable || profile.scan() {
            return TestResult::Fail("AR9565 ignored fixed EEPROM/PCI no-manual-BT source gate");
        }
        let port = PortModel::new();
        port.registers.borrow_mut().insert(CONTROL, 0x126f0600);
        let shared = Shared::new(profile);
        let bound = match shared.bind(&port, grant, profile) {
            Ok(bound) => bound,
            Err(_) => return TestResult::Fail("N65A initial source MC/default readback"),
        };
        if bound.resume(&port).is_err() {
            return TestResult::Fail("N65A default-antenna resume");
        }
        for _ in 0..3 {
            if bound.observe(&port, observation(2)).is_err() {
                return TestResult::Fail("N65A actual default observation");
            }
        }
        if port.reg(DEFAULT) != if capable { 2 } else { 1 }
            || port.reg(CONTROL) != 0x126f0600
            || port.writes.borrow().iter().any(|&(r, _)| r != DEFAULT)
        {
            return TestResult::Fail(
                "N65A capability/default-count became group2 scan or BT request",
            );
        }
        cap.revoke();
        if capable {
            let count = port.writes.borrow().len();
            if bound.observe(&port, observation(3)).is_ok()
                || port.writes.borrow().len() != count
                || history(&shared).2
            {
                return TestResult::Fail("N65A revoked default source wrote or stayed active");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9003",
    smoke_ath9k_ar9565_source_pci_capability_and_retained_default_owner
);
fn observation(antenna: u8) -> Observation {
    Observation {
        ctl: [40, 20, 0x18],
        antenna,
        more_aggr: false,
    }
}
fn initial() -> u32 {
    Config {
        main: 2,
        alt: 1,
        bias: 1,
        main_gain: false,
        alt_gain: false,
    }
    .word(0x8181_8101)
}

struct PortModel {
    pci: Cap<narf_bus::BusDeviceCap, Write>,
    registers: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    reads: Cell<usize>,
    corrupt: Cell<bool>,
    corrupt_register: Cell<Option<u64>>,
    revoke_on_default_write: Cell<Option<Cap<FirmwareBlob, Read>>>,
    revoke_record_after_read: Cell<Option<Cap<FirmwareBlob, Read>>>,
    revoke_pci_after_read: Cell<bool>,
}
struct Live<F>(F);
impl<T, F: FnOnce() -> Result<T, Error>> CapOp<narf_bus::BusDeviceCap, Write> for Live<F> {
    type Output = Result<T, Error>;
    fn execute(self, _: &Cap<narf_bus::BusDeviceCap, Write>) -> Result<Self::Output, CapError> {
        Ok((self.0)())
    }
}
impl PortModel {
    fn new() -> Self {
        Self {
            pci: Cap::bootstrap(),
            registers: RefCell::new(BTreeMap::from([(CONTROL, initial()), (DEFAULT, 1)])),
            writes: RefCell::new(Vec::new()),
            reads: Cell::new(0),
            corrupt: Cell::new(false),
            corrupt_register: Cell::new(None),
            revoke_on_default_write: Cell::new(None),
            revoke_record_after_read: Cell::new(None),
            revoke_pci_after_read: Cell::new(false),
        }
    }
    fn current<T>(&self, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.pci.invoke(Live(op)).map_err(|_| Error::Access)?
    }
    fn reg(&self, reg: u64) -> u32 {
        self.registers.borrow().get(&reg).copied().unwrap_or(0)
    }
}
impl Port for PortModel {
    fn transmit_allowed(&self) -> Result<(), Error> {
        self.current(|| Ok(()))
    }
    fn access<T>(&self, _: bool, op: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        self.current(op)
    }
    fn read(&self, reg: u64) -> Result<u32, Error> {
        self.current(|| {
            self.reads.set(self.reads.get() + 1);
            let value = self.reg(reg);
            if let Some(cap) = self.revoke_record_after_read.take() {
                cap.revoke();
            }
            if self.revoke_pci_after_read.replace(false) {
                self.pci.revoke();
            }
            Ok(value)
        })
    }
    fn write(&self, reg: u64, value: u32) -> Result<(), Error> {
        self.current(|| {
            self.writes.borrow_mut().push((reg, value));
            self.registers.borrow_mut().insert(
                reg,
                if self.corrupt.get() || self.corrupt_register.get() == Some(reg) {
                    value ^ 1
                } else {
                    value
                },
            );
            if reg == DEFAULT {
                if let Some(cap) = self.revoke_on_default_write.take() {
                    cap.revoke();
                }
            }
            Ok(())
        })
    }
    fn allocate(&self, _: usize) -> Result<narf_io::DmaBuffer, Error> {
        Err(Error::Memory)
    }
    fn master(&self, _: bool) -> Result<(), Error> {
        Err(Error::State)
    }
    fn now_us(&self) -> u64 {
        0
    }
}
/// Same PCI-current RAM register file exposed through the actual parked
/// capture helper's production RegisterIo surface; no extra authority.
impl crate::ath9k::identity::RegisterIo for PortModel {
    fn read32(&mut self, reg: u64) -> u32 {
        <Self as Port>::read(self, reg).unwrap_or(u32::MAX)
    }
    fn write32(&mut self, reg: u64, value: u32) {
        let _ = <Self as Port>::write(self, reg, value);
    }
}
fn check(f: impl FnOnce() -> Result<(), &'static str>) -> TestResult {
    f().map_or_else(TestResult::Fail, |()| TestResult::Pass)
}
fn smoke_ath9k_ar9485_antenna_raw_factory_capability_and_exact_bt_boards() -> TestResult {
    check(|| {
        for high in 0..4 {
            let (profile, _, _) = fixture(device(), high << 6).map_err(|_| "raw fixture")?;
            if profile.capable() != (high == 3) || profile.scan() != (high == 3) {
                return Err("raw high bits did not exclusively gate hardware combining");
            }
        }
        for (sv, si, cus) in [
            (0x1a3b, 0x2086, true),
            (0x1a3b, 0x1237, true),
            (0x1a3b, 0x2126, true),
            (0x1a3b, 0x126a, true),
            (0x1a3b, 0x2152, true),
            (0x105b, 0xe075, true),
            (0x168c, 0x3119, false),
            (0x168c, 0x3122, false),
            (0x185f, 0x3119, false),
            (0x185f, 0x3027, false),
            (0x144d, 0x4105, false),
            (0x144d, 0x4106, false),
            (0x144d, 0x410d, false),
            (0x144d, 0x410e, false),
            (0x144d, 0x410f, false),
            (0x144d, 0xc706, false),
            (0x144d, 0xc680, false),
            (0x144d, 0xc708, false),
            (0x17aa, 0x3218, false),
            (0x17aa, 0x3219, false),
        ] {
            let id = DeviceId {
                subsystem_vendor: sv,
                subsystem_id: si,
                ..device()
            };
            let (profile, _, _) = fixture(id, 0xc0).map_err(|_| "board fixture")?;
            if !profile.capable()
                || !profile.bt_capable
                || profile.scan()
                || (profile.low, profile.bias) != if cus { (20, 3) } else { (0, 0) }
            {
                return Err("source board/manual-BT gate differs");
            }
            let (part, _, _) = fixture(
                DeviceId {
                    device: 0x0037,
                    ..id
                },
                0xc0,
            )
            .map_err(|_| "AR1111 fixture")?;
            if part.bt_capable || !part.scan() || part.low != 0 || part.bias != 0 {
                return Err("AR1111 inherited PCI0032 board quirks");
            }
        }
        for raw in [0, 0x40, 0x80] {
            let (profile, grant, _) = fixture(device(), raw).map_err(|_| "disabled fixture")?;
            let port = PortModel::new();
            port.registers
                .borrow_mut()
                .insert(CONTROL, profile.base().word(0x8181_8101));
            let shared = Shared::new(profile);
            let binding = shared
                .bind(&port, grant, profile)
                .map_err(|_| "disabled bind")?;
            binding.resume(&port).map_err(|_| "disabled resume")?;
            for ant in [1, 2, 3] {
                binding
                    .observe(&port, observation(ant))
                    .map_err(|_| "disabled observation")?;
            }
            if history(&shared) != (0, 0, true) || !port.writes.borrow().is_empty() {
                return Err("absent raw capability allowed default/scanner writes");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_antenna_raw_factory_capability_and_exact_bt_boards
);
fn smoke_ath9k_ar9485_antenna_default_tracking_bt_gate_and_lifecycle() -> TestResult {
    check(|| {
        let id = DeviceId {
            subsystem_vendor: 0x168c,
            subsystem_id: 0x3119,
            ..device()
        };
        let (profile, grant, _) = fixture(id, 0xc0).map_err(|_| "fixture")?;
        let port = PortModel::new();
        let shared = Shared::new(profile);
        let first = shared
            .bind(&port, grant.clone(), profile)
            .map_err(|_| "bind")?;
        first.resume(&port).map_err(|_| "resume")?;
        for ant in [1, 2] {
            first
                .observe(&port, observation(ant))
                .map_err(|_| "observe")?;
        }
        if history(&shared) != (0, 2, true) || !port.writes.borrow().is_empty() {
            return Err("default antenna changed before source third mismatch");
        }
        first.pause();
        let paused = *shared.0.lock();
        if first.observe(&port, observation(3)) != Err(Error::State)
            || !port.writes.borrow().is_empty()
        {
            return Err("paused owner admitted RX metadata");
        }
        let second = shared
            .bind(&port, grant, profile)
            .map_err(|_| "reset rebind")?;
        if first.resume(&port) != Err(Error::State)
            || first.observe(&port, observation(3)) != Err(Error::State)
        {
            return Err("old binding adopted new hardware generation");
        }
        second.resume(&port).map_err(|_| "rebound resume")?;
        second
            .observe(&port, observation(3))
            .map_err(|_| "third mismatch")?;
        if history(&shared) != (3, 0, true)
            || port.writes.borrow().as_slice() != [(DEFAULT, 3)]
            || shared.0.lock().scanner != paused.scanner
        {
            return Err("reset lost history, nonidentical mismatches or BT scanner closure");
        }
        second.pause();
        second.resume(&port).map_err(|_| "pause resume")?;
        if history(&shared) != (3, 0, true) {
            return Err("pause/resume reset source history");
        }
        second.pause();
        let (_, refused_grant, refused_cap) = fixture(id, 0xc0).map_err(|_| "rebind fixture")?;
        refused_cap.revoke();
        if shared.bind(&port, refused_grant, profile).is_ok()
            || second.resume(&port) != Err(Error::State)
            || second.observe(&port, observation(3)) != Err(Error::State)
        {
            return Err("failed reset rebind revived an older binding");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_antenna_default_tracking_bt_gate_and_lifecycle
);
fn smoke_ath9k_ar9485_antenna_revoked_sources_precede_native_effects() -> TestResult {
    check(|| {
        for (pci, during_read) in [(false, false), (true, false), (false, true), (true, true)] {
            let (profile, grant, cap) = fixture(device(), 0xc0).map_err(|_| "fixture")?;
            let port = PortModel::new();
            let shared = Shared::new(profile);
            let bound = shared.bind(&port, grant, profile).map_err(|_| "bind")?;
            bound.resume(&port).map_err(|_| "resume")?;
            for ant in [1, 2] {
                bound
                    .observe(&port, observation(ant))
                    .map_err(|_| "observe")?;
            }
            let reads = port.reads.get();
            if during_read {
                if pci {
                    port.revoke_pci_after_read.set(true);
                } else {
                    port.revoke_record_after_read.set(Some(cap));
                }
            } else if pci {
                port.pci.revoke();
            } else {
                cap.revoke();
            }
            if bound.observe(&port, observation(3)) != Err(Error::Access)
                || port.reads.get() != reads + usize::from(during_read)
                || !port.writes.borrow().is_empty()
                || history(&shared) != (0, 2, false)
            {
                return Err("revoked native source executed MMIO or committed history");
            }
            if bound.resume(&port) != Err(Error::State) {
                return Err("failed source resumed old hardware generation");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_antenna_revoked_sources_precede_native_effects
);
fn smoke_ath9k_ar9485_antenna_full_readback_preserves_bits_and_pins_uncertainty() -> TestResult {
    check(|| {
        for (register, value) in [(CONTROL, initial() ^ (1 << 27)), (DEFAULT, 0), (DEFAULT, 8)] {
            let (profile, grant, _) = fixture(device(), 0xc0).map_err(|_| "base fixture")?;
            let port = PortModel::new();
            port.registers.borrow_mut().insert(register, value);
            let shared = Shared::new(profile);
            if !matches!(shared.bind(&port, grant, profile), Err(Error::Descriptor))
                || !port.writes.borrow().is_empty()
            {
                return Err("unproved INI/board base or default antenna admitted a fresh owner");
            }
        }
        let (profile, grant, _) = fixture(device(), 0xc0).map_err(|_| "fixture")?;
        let port = PortModel::new();
        let shared = Shared::new(profile);
        let bound = shared.bind(&port, grant, profile).map_err(|_| "bind")?;
        bound.resume(&port).map_err(|_| "resume")?;
        for _ in 0..512 {
            bound.observe(&port, observation(0)).map_err(|_| "window")?;
        }
        let before = initial();
        let after = port.reg(CONTROL);
        if after & !OWNED != before & !OWNED
            || Config::read(after)
                != (Config {
                    main: 1,
                    alt: 2,
                    bias: 1,
                    main_gain: false,
                    alt_gain: false,
                })
        {
            return Err("source LNA/gain/bias fields or preserved-bit write differs");
        }
        for ant in [1, 2] {
            bound
                .observe(&port, observation(ant))
                .map_err(|_| "default observations")?;
        }
        let old = *shared.0.lock();
        port.corrupt.set(true);
        if bound.observe(&port, observation(3)) != Err(Error::Descriptor)
            || history(&shared) != (old.logical, old.other, false)
        {
            return Err("uncertain readback committed default/history or stayed active");
        }
        let writes = port.writes.borrow().len();
        if bound.observe(&port, observation(3)) != Err(Error::State)
            || port.writes.borrow().len() != writes
        {
            return Err("uncertain generation issued another write");
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_antenna_full_readback_preserves_bits_and_pins_uncertainty
);

fn parked_mac(port: &PortModel, default: u32) {
    let mut regs = port.registers.borrow_mut();
    regs.insert(0x8048, 0x0200_0020);
    regs.insert(0xa20c, 1);
    regs.insert(DEFAULT, default);
}
/// Execute the production saved-default MAC tail under the same current
/// record and PCI capabilities as the antenna model. No PHY calibration,
/// real bus reset or physical RF qualification is claimed by this fixture.
fn smoke_ath9k_ar9485_saved_default_mac_tail_and_refusal_preserve_history() -> TestResult {
    check(|| {
        let (image, identity) = factory(0xc0);
        for value in [0, 1, 3, 7, 8, u32::MAX] {
            let (_, grant, _) = fixture(device(), 0xc0).map_err(|_| "capture fixture")?;
            let mut port = PortModel::new();
            parked_mac(&port, value);
            let parked = capture_parked_default(&grant, &mut port);
            let native = Qualified::new(&port, &grant).capture_default();
            if value <= 7 {
                if parked != Ok(value) || native != Ok(value) {
                    return Err("production captures changed valid saved hardware value");
                }
            } else if parked.is_ok() || native.is_ok() {
                return Err("production capture admitted impossible/default dead-card value");
            }
            if !port.writes.borrow().is_empty() {
                return Err("capturing default mutated hardware");
            }
        }
        for pci in [false, true] {
            let (_, grant, cap) = fixture(device(), 0xc0).map_err(|_| "capture revoked fixture")?;
            let mut port = PortModel::new();
            parked_mac(&port, 3);
            if pci {
                port.pci.revoke();
            } else {
                cap.revoke();
            }
            if capture_parked_default(&grant, &mut port).is_ok()
                || Qualified::new(&port, &grant).capture_default().is_ok()
                || port.reads.get() != 0
                || !port.writes.borrow().is_empty()
            {
                return Err("production capture bypassed revoked record or current PCI invocation");
            }
        }
        for (saved, reset_value, expected) in [
            (Some(0), 7, 1),
            (Some(1), 7, 1),
            (Some(3), 7, 3),
            (Some(7), 2, 7),
            (None, 0, 1),
            (None, 5, 5),
        ] {
            let (profile, grant, _) = fixture(device(), 0xc0).map_err(|_| "saved fixture")?;
            let port = PortModel::new();
            let shared = Shared::new(profile);
            let old = shared
                .bind(&port, grant.clone(), profile)
                .map_err(|_| "saved bind")?;
            old.resume(&port).map_err(|_| "saved resume")?;
            for ant in [1, 2] {
                old.observe(&port, observation(ant))
                    .map_err(|_| "saved history")?;
            }
            old.pause();
            let before = *shared.0.lock();
            // The model reset changes the hardware default; its saved
            // value and the logical source history remain distinct facts.
            parked_mac(&port, reset_value);
            let qualified = Qualified::new(&port, &grant);
            qualified
                .prepare_mac(&identity, &image, identity.mac, false, saved)
                .map_err(|_| "saved MAC tail")?;
            if port.reg(DEFAULT) != expected
                || history(&shared) != (before.logical, before.other, false)
                || shared.0.lock().scanner != before.scanner
            {
                return Err("saved tail used post-reset value or changed logical antenna history");
            }
            let next = shared
                .bind(&port, grant, profile)
                .map_err(|_| "saved new generation")?;
            if old.resume(&port) != Err(Error::State) {
                return Err("saved tail revived old binding");
            }
            next.resume(&port).map_err(|_| "saved new resume")?;
            if history(&shared) != (0, 2, true) {
                return Err("saved rebind lost original mismatch history");
            }
        }
        for saved in [8, u32::MAX] {
            let (_, grant, _) = fixture(device(), 0xc0).map_err(|_| "invalid fixture")?;
            let port = PortModel::new();
            parked_mac(&port, 1);
            let qualified = Qualified::new(&port, &grant);
            if qualified.prepare_mac(&identity, &image, identity.mac, false, Some(saved))
                != Err(Error::Packet)
                || port.reads.get() != 0
                || !port.writes.borrow().is_empty()
            {
                return Err("out-of-range saved default reached native IO");
            }
        }
        for pci in [false, true] {
            let (_, grant, cap) = fixture(device(), 0xc0).map_err(|_| "revoked fixture")?;
            let port = PortModel::new();
            parked_mac(&port, 1);
            if pci {
                port.pci.revoke();
            } else {
                cap.revoke();
            }
            let qualified = Qualified::new(&port, &grant);
            if qualified.prepare_mac(&identity, &image, identity.mac, false, Some(3))
                != Err(Error::Access)
                || port.reads.get() != 0
                || !port.writes.borrow().is_empty()
            {
                return Err("dead saved-tail source reached register access");
            }
        }
        for revoke in [false, true] {
            let (profile, grant, cap) = fixture(device(), 0xc0).map_err(|_| "uncertain fixture")?;
            let port = PortModel::new();
            let shared = Shared::new(profile);
            let old = shared
                .bind(&port, grant.clone(), profile)
                .map_err(|_| "uncertain bind")?;
            old.resume(&port).map_err(|_| "uncertain resume")?;
            for ant in [1, 2] {
                old.observe(&port, observation(ant))
                    .map_err(|_| "uncertain history")?;
            }
            old.pause();
            let before = *shared.0.lock();
            parked_mac(&port, 0);
            if revoke {
                port.revoke_on_default_write.set(Some(cap));
            } else {
                port.corrupt_register.set(Some(DEFAULT));
            }
            let qualified = Qualified::new(&port, &grant);
            let result = qualified.prepare_mac(&identity, &image, identity.mac, false, Some(3));
            let expected = if revoke {
                Error::Access
            } else {
                Error::Descriptor
            };
            if result != Err(expected)
                || !port.writes.borrow().contains(&(DEFAULT, 3))
                || history(&shared) != (before.logical, before.other, false)
                || shared.0.lock().scanner != before.scanner
            {
                return Err("uncertain saved-default receipt committed history or resumed RX");
            }
            if old.resume(&port).is_ok()
                || history(&shared) != (before.logical, before.other, false)
                || shared.0.lock().scanner != before.scanner
            {
                return Err("failed tail adopted uncertain default antenna");
            }
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath9k/ar9485/antenna",
    smoke_ath9k_ar9485_saved_default_mac_tail_and_refusal_preserve_history
);
