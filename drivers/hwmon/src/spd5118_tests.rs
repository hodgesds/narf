//! spd5118 smokes: register codecs, probe against an SPD5118 hub
//! model, and the published sysfs attributes (shows, stores, errnos).

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_drivers_i2c::client::{self, I2cClient};
use narf_drivers_i2c::smbus::{I2cFunc, SmbusOp};
use narf_drivers_i2c::{I2cBus, I2cError, I2cOp};
use narf_filesystem::FsError;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::spd5118::{self, temp_from_reg, temp_to_reg, vendor_valid, ProbeError};

// ── SPD5118 hub model ────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Hub {
    addr: u8,
    regs: [u8; 128],
}

impl Hub {
    /// A hub as the 21ME's DIMMs report it: SPD5118, vendor 0x06:0x32
    /// (bank 0x86 with its parity bit), revision 1.6, sensor present,
    /// page 0 selected.
    fn ddr5(addr: u8) -> Self {
        let mut regs = [0u8; 128];
        regs[0x00] = 0x51;
        regs[0x01] = 0x18;
        regs[0x02] = 0x0a; // revision 1.6
        regs[0x03] = 0x86;
        regs[0x04] = 0x32;
        regs[0x05] = 0x02; // temperature sensor supported
        regs[0x31] = 0xe0; // 46.000 °C = 184 * 0.25 → 0x2e0
        regs[0x32] = 0x02;
        Self { addr, regs }
    }

    /// MR0..MR4 read as zero while a legacy page other than 0 is
    /// selected — the case `spd5118_i2c_init` repairs.
    fn read(&self, reg: u8) -> u8 {
        if self.regs[0x0b] & 0x07 != 0 && reg < 0x05 {
            0
        } else {
            self.regs[usize::from(reg & 0x7f)]
        }
    }
}

/// An SMBus-only host carrying hub models.
#[derive(Debug)]
struct HubBus {
    hubs: IrqSafeSpinLock<Vec<Hub>>,
    func: I2cFunc,
    nack: AtomicBool,
}

impl HubBus {
    fn new(hubs: Vec<Hub>) -> Arc<Self> {
        Self::with_func(
            hubs,
            I2cFunc::SMBUS_READ_BYTE | I2cFunc::SMBUS_BYTE_DATA | I2cFunc::SMBUS_WORD_DATA,
        )
    }

    fn with_func(hubs: Vec<Hub>, func: I2cFunc) -> Arc<Self> {
        Arc::new(Self {
            hubs: IrqSafeSpinLock::new(hubs),
            func,
            nack: AtomicBool::new(false),
        })
    }

    fn reg(&self, addr: u8, reg: u8) -> u8 {
        self.hubs
            .lock()
            .iter()
            .find(|h| h.addr == addr)
            .expect("hub")
            .regs[usize::from(reg)]
    }

    fn set(&self, addr: u8, reg: u8, value: u8) {
        if let Some(h) = self.hubs.lock().iter_mut().find(|h| h.addr == addr) {
            h.regs[usize::from(reg)] = value;
        }
    }
}

#[async_trait]
impl I2cBus for HubBus {
    async fn transfer(&self, _addr: u8, _ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
        Err(I2cError::Unsupported)
    }

    fn name(&self) -> &str {
        "spd5118-model"
    }

    fn functionality(&self) -> I2cFunc {
        self.func
    }

    async fn smbus_xfer(&self, addr: u8, op: SmbusOp<'_>) -> Result<(), I2cError> {
        if self.nack.load(Ordering::SeqCst) {
            return Err(I2cError::Nack);
        }
        let mut hubs = self.hubs.lock();
        let hub = hubs
            .iter_mut()
            .find(|h| h.addr == addr)
            .ok_or(I2cError::Nack)?;
        match op {
            SmbusOp::ReceiveByte { out } => *out = 0,
            SmbusOp::ReadByteData { cmd, out } => *out = hub.read(cmd),
            SmbusOp::ReadWordData { cmd, out } => {
                *out = u16::from(hub.read(cmd)) | (u16::from(hub.read(cmd + 1)) << 8)
            }
            // MR19 is write-1-to-clear for the MR51 status bits.
            SmbusOp::WriteByteData { cmd: 0x13, value } => hub.regs[0x33] &= !value,
            SmbusOp::WriteByteData { cmd, value } => hub.regs[usize::from(cmd & 0x7f)] = value,
            _ => return Err(I2cError::Unsupported),
        }
        Ok(())
    }
}

/// A named way to break a good hub.
type HubEdit = (&'static str, fn(&mut Hub));

fn client_on(bus: &Arc<HubBus>, addr: u8) -> Arc<I2cClient> {
    let dynbus: Arc<dyn I2cBus> = bus.clone();
    client::new_client_device(&dynbus, addr, "spd5118").expect("client")
}

fn run<F: core::future::Future>(f: F) -> F::Output {
    narf_scheduler::block_on_spin(f)
}

// ── Codecs ───────────────────────────────────────────────────────────

fn smoke_spd5118_temperature_codec() -> TestResult {
    let decode = [
        (0x0000u16, 0i64),
        (0x02e0, 46_000),
        (0x1ffc, -250),
        (0x1000, -256_000),
        (0x0ffc, 255_750),
        // Bits 1:0 and 15:13 are not part of the reading.
        (0xe2e3, 46_000),
    ];
    if decode.iter().any(|&(reg, mc)| temp_from_reg(reg) != mc) {
        return TestResult::Fail("temp_from_reg differs from sign_extend32(reg >> 2, 10) * 250");
    }
    let encode = [
        (46_100i64, 0x02e0u16),
        (46_125, 0x02e4),
        (-125, 0x1ffc),
        (0, 0x0000),
        (300_000, 0x0ffc),
        (-300_000, 0x1000),
    ];
    if encode.iter().any(|&(mc, reg)| temp_to_reg(mc) != reg) {
        return TestResult::Fail("temp_to_reg differs from Linux's clamp + DIV_ROUND_CLOSEST");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/spd5118", smoke_spd5118_temperature_codec);

fn smoke_spd5118_vendor_parity() -> TestResult {
    let cases = [
        (0x86u8, 0x32u8, true), // the 21ME's hubs: 0x06:0x32
        (0x06, 0x32, false),    // bank parity even
        (0x86, 0x33, false),    // id parity even
        (0x86, 0x80, false),    // id 0 with parity
        (0x86, 0x7f, false),    // id 0x7f (odd parity, still reserved)
    ];
    if cases.iter().any(|&(b, i, ok)| vendor_valid(b, i) != ok) {
        return TestResult::Fail("vendor_valid differs from spd5118_vendor_valid");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/hwmon/spd5118", smoke_spd5118_vendor_parity);

// ── Probe ────────────────────────────────────────────────────────────

fn smoke_spd5118_probe_binds_and_refuses() -> TestResult {
    client::__reset_for_test();
    let good = HubBus::new(alloc::vec![Hub::ddr5(0x50)]);
    if run(spd5118::probe(&client_on(&good, 0x50))).is_err() {
        client::__reset_for_test();
        return TestResult::Fail("a DDR5 hub must bind");
    }
    let refuse: [HubEdit; 5] = [
        ("wrong MR0:MR1", |h| h.regs[0x00] = 0x12),
        ("no temperature sensor", |h| h.regs[0x05] = 0x00),
        ("bank parity", |h| h.regs[0x03] = 0x06),
        ("16-bit addressing", |h| h.regs[0x0b] = 0x08),
        // The aux port reads every address back as zero.
        ("all-zero device", |h| h.regs = [0; 128]),
    ];
    for (i, (_why, edit)) in refuse.iter().enumerate() {
        let mut hub = Hub::ddr5(0x50 + i as u8);
        edit(&mut hub);
        let bus = HubBus::new(alloc::vec![hub]);
        if !matches!(
            run(spd5118::probe(&client_on(&bus, 0x50 + i as u8))),
            Err(ProbeError::NoDevice)
        ) {
            client::__reset_for_test();
            return TestResult::Fail("a hub Linux refuses must not bind (ENODEV)");
        }
    }
    // An adapter without word data cannot run the probe at all.
    let narrow = HubBus::with_func(alloc::vec![Hub::ddr5(0x58)], I2cFunc::SMBUS_BYTE_DATA);
    let r = run(spd5118::probe(&client_on(&narrow, 0x58)));
    client::__reset_for_test();
    if !matches!(r, Err(ProbeError::NoDevice)) {
        return TestResult::Fail("probe needs SMBUS_BYTE_DATA | SMBUS_WORD_DATA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/spd5118",
    smoke_spd5118_probe_binds_and_refuses
);

fn smoke_spd5118_probe_selects_page_zero() -> TestResult {
    client::__reset_for_test();
    let mut hub = Hub::ddr5(0x50);
    hub.regs[0x0b] = 0x03; // firmware left legacy page 3 selected
    let bus = HubBus::new(alloc::vec![hub]);
    let r = run(spd5118::probe(&client_on(&bus, 0x50)));
    client::__reset_for_test();
    if r.is_err() || bus.reg(0x50, 0x0b) != 0x00 {
        return TestResult::Fail("init must select page 0 through MR11 and then bind");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/spd5118",
    smoke_spd5118_probe_selects_page_zero
);

fn smoke_spd5118_bind_clients_registers_bound_hubs() -> TestResult {
    client::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    let mut empty = Hub::ddr5(0x51);
    empty.regs = [0; 128];
    let bus = HubBus::new(alloc::vec![Hub::ddr5(0x50), empty]);
    client_on(&bus, 0x50);
    client_on(&bus, 0x51);
    let bound = spd5118::bind_clients();
    let names: Vec<alloc::string::String> = crate::registry::devices()
        .iter()
        .map(|d| alloc::string::String::from(d.name()))
        .collect();
    let clients = client::clients_of_kind("spd5118").len();
    client::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    if bound != 1 || names != ["spd5118"] {
        return TestResult::Fail("exactly the hub that probes must become a hwmon device");
    }
    if clients != 2 {
        return TestResult::Fail("an unbound client stays registered, as in Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/spd5118",
    smoke_spd5118_bind_clients_registers_bound_hubs
);

// ── sysfs ────────────────────────────────────────────────────────────

fn hwmon0() -> Option<Arc<narf_filesystem::sysfs::Kobject>> {
    narf_filesystem::sysfs::sysfs_root()
        .get_child("class")
        .and_then(|c| c.get_child("hwmon"))
        .and_then(|h| h.get_child("hwmon0"))
}

/// Bind one hub, publish it as hwmon0, and hand back the pieces.
fn publish() -> Option<(Arc<HubBus>, Arc<narf_filesystem::sysfs::Kobject>)> {
    narf_filesystem::sysfs::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    client::__reset_for_test();
    let bus = HubBus::new(alloc::vec![Hub::ddr5(0x50)]);
    client_on(&bus, 0x50);
    if spd5118::bind_clients() != 1 {
        return None;
    }
    crate::sysfs_bridge::populate_hwmon_class();
    hwmon0().map(|k| (bus, k))
}

fn teardown() {
    client::__reset_for_test();
    crate::registry::__reset_devices_for_test();
    narf_filesystem::sysfs::__reset_for_test();
}

fn store(
    k: &narf_filesystem::sysfs::Kobject,
    name: &str,
    data: &[u8],
) -> Option<Result<(), FsError>> {
    k.attr_store(name, data)
}

fn smoke_spd5118_sysfs_attributes() -> TestResult {
    let Some((bus, k)) = publish() else {
        teardown();
        return TestResult::Fail("hub did not publish as hwmon0");
    };
    let result = (|| {
        if k.attr_show("name").as_deref() != Some("spd5118\n") {
            return Err("name must be spd5118");
        }
        if k.attr_show("temp1_input").as_deref() != Some("46000\n") {
            return Err("temp1_input must render MR49:MR50");
        }
        if k.attr_show("temp1_label").is_some() {
            return Err("spd5118 has no temp1_label");
        }
        for ro in ["temp1_input", "temp1_max_alarm", "temp1_lcrit_alarm"] {
            if store(&k, ro, b"1").is_some() {
                return Err("input and alarms are read-only (0444)");
            }
        }
        // Limits: write, then read back through the register pair.
        if store(&k, "temp1_max", b"50000\n") != Some(Ok(()))
            || (bus.reg(0x50, 0x1c), bus.reg(0x50, 0x1d)) != (0x20, 0x03)
            || k.attr_show("temp1_max").as_deref() != Some("50000\n")
        {
            return Err("temp1_max must store temp_to_reg(50000) = 0x320 low byte first");
        }
        if store(&k, "temp1_lcrit", b"-5000") != Some(Ok(()))
            || k.attr_show("temp1_lcrit").as_deref() != Some("-5000\n")
        {
            return Err("negative limits must round-trip");
        }
        // Enable: 0/1 only, inverted into MR26 bit 0.
        if store(&k, "temp1_enable", b"2") != Some(Err(FsError::InvalidData)) {
            return Err("temp1_enable outside 0/1 must be EINVAL");
        }
        if store(&k, "temp1_enable", b"0") != Some(Ok(()))
            || bus.reg(0x50, 0x1a) & 1 != 1
            || k.attr_show("temp1_enable").as_deref() != Some("0\n")
        {
            return Err("disabling must set MR26 bit 0");
        }
        if store(&k, "temp1_enable", b"1\n") != Some(Ok(())) || bus.reg(0x50, 0x1a) & 1 != 0 {
            return Err("enabling must clear MR26 bit 0");
        }
        // Alarms latch in MR51 and clear on read through MR19.
        bus.set(0x50, 0x33, 0x01 | 0x04);
        if k.attr_show("temp1_max_alarm").as_deref() != Some("1\n")
            || k.attr_show("temp1_max_alarm").as_deref() != Some("0\n")
            || k.attr_show("temp1_crit_alarm").as_deref() != Some("1\n")
            || k.attr_show("temp1_min_alarm").as_deref() != Some("0\n")
        {
            return Err("alarms must read MR51 and clear the bit they report");
        }
        // A device that stops answering: empty show, ENXIO store.
        bus.nack.store(true, Ordering::SeqCst);
        if k.attr_show("temp1_input").as_deref() != Some("")
            || store(&k, "temp1_max", b"40000") != Some(Err(FsError::NoDeviceAddress))
        {
            return Err("a NACKing hub must render empty and store ENXIO");
        }
        Ok(())
    })();
    teardown();
    match result {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!("drivers/hwmon/spd5118", smoke_spd5118_sysfs_attributes);

fn smoke_hwmon_store_parses_like_kstrtol() -> TestResult {
    use crate::sysfs_bridge::kstrtol;
    let cases: [(&[u8], Result<i64, FsError>); 12] = [
        (b"50000", Ok(50_000)),
        (b"50000\n", Ok(50_000)),
        (b"+7", Ok(7)),
        (b"-7\n", Ok(-7)),
        (b"9223372036854775807", Ok(i64::MAX)),
        (b"-9223372036854775808", Ok(i64::MIN)),
        (b"9223372036854775808", Err(FsError::OutOfRange)),
        (b"99999999999999999999", Err(FsError::OutOfRange)),
        (b"", Err(FsError::InvalidData)),
        (b"50000 ", Err(FsError::InvalidData)),
        (b"5\n\n", Err(FsError::InvalidData)),
        (b"-+5", Err(FsError::InvalidData)),
    ];
    if cases.iter().any(|(input, want)| kstrtol(input) != *want) {
        return TestResult::Fail("store parsing differs from kstrtol(buf, 10, &val)");
    }
    if kstrtol(b"12\0junk") != Ok(12) {
        return TestResult::Fail("a store buffer ends at its first NUL");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/hwmon/spd5118",
    smoke_hwmon_store_parses_like_kstrtol
);
