//! Smokes for the SMBus layer: `smbus::emulate`, the piix4 host driver
//! against a register model, client instantiation and SPD planning.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_firmware_smbios::SmbiosMemoryDevice;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use crate::piix4::{setup_kerncz, FchPm, PortIo, SetupAdapter};
use crate::smbus::{self, I2cFunc, SmbusOp, SMBUS_BLOCK_MAX};
use crate::spd::{plan, SpdPlan};
use crate::{client, I2cBus, I2cError, I2cOp};

fn run<F: core::future::Future>(f: F) -> F::Output {
    narf_scheduler::block_on_spin(f)
}

// ── PIIX4 register model ─────────────────────────────────────────────

const MAIN: u16 = 0x0b00;
const AUX: u16 = 0x0b20;

/// One SMBus transaction the model executed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Xfer {
    host: u16,
    /// PM port-select field (`PMx02 & 0x18`) on the main host.
    port: Option<u8>,
    addr: u8,
    read: bool,
    size: u8,
    cmd: u8,
    /// Whether the host semaphore was owned while it ran.
    semaphore: bool,
}

#[derive(Debug)]
struct Target {
    host: u16,
    port: Option<u8>,
    addr: u8,
    regs: [u8; 256],
    block: Vec<u8>,
}

#[derive(Debug)]
struct HostRegs {
    base: u16,
    regs: [u8; 0x11],
    blk: Vec<u8>,
    blk_ptr: usize,
    owned: bool,
    muxed: bool,
}

#[derive(Debug)]
struct State {
    pm: [u8; 256],
    pm_index: u8,
    hosts: Vec<HostRegs>,
    targets: Vec<Target>,
    grant_semaphore: bool,
    imc_responds: bool,
    imc_index: u8,
    imc: [u8; 256],
    imc_flags: Vec<u8>,
    log: Vec<Xfer>,
}

#[derive(Debug)]
struct Model {
    s: IrqSafeSpinLock<State>,
}

impl Model {
    /// A KERNCZ FCH with the main host at 0x0b00 (DecodeEn: enabled,
    /// base high byte 0x0b) and the aux host at 0x0b20.
    fn new() -> Arc<Self> {
        let mut pm = [0u8; 256];
        pm[0x00] = 0x10; // SMBus decode enabled
        pm[0x01] = 0x0b; // base 0x0b00
        let host = |base, muxed| HostRegs {
            base,
            regs: [0; 0x11],
            blk: Vec::new(),
            blk_ptr: 0,
            owned: false,
            muxed,
        };
        let mut main = host(MAIN, true);
        main.regs[0x10] = 0x01; // I2CCFG: IRQ, revision 0
        Arc::new(Self {
            s: IrqSafeSpinLock::new(State {
                pm,
                pm_index: 0,
                hosts: vec![main, host(AUX, false)],
                targets: Vec::new(),
                grant_semaphore: true,
                imc_responds: true,
                imc_index: 0,
                imc: [0; 256],
                imc_flags: Vec::new(),
                log: Vec::new(),
            }),
        })
    }

    fn add_target(&self, host: u16, port: Option<u8>, addr: u8) {
        self.s.lock().targets.push(Target {
            host,
            port,
            addr,
            regs: [0; 256],
            block: Vec::new(),
        });
    }

    fn with_target<R>(&self, host: u16, addr: u8, f: impl FnOnce(&mut Target) -> R) -> R {
        let mut s = self.s.lock();
        let t = s
            .targets
            .iter_mut()
            .find(|t| t.host == host && t.addr == addr)
            .expect("target");
        f(t)
    }

    fn log(&self) -> Vec<Xfer> {
        self.s.lock().log.clone()
    }

    fn execute(s: &mut State, h: usize) {
        let (base, muxed, owned) = (s.hosts[h].base, s.hosts[h].muxed, s.hosts[h].owned);
        let cnt = s.hosts[h].regs[0x02];
        let add = s.hosts[h].regs[0x04];
        let cmd = s.hosts[h].regs[0x03];
        let size = cnt & 0x1c;
        let read = add & 1 != 0;
        let addr = add >> 1;
        let port = muxed.then_some(s.pm[0x02] & 0x18);
        s.log.push(Xfer {
            host: base,
            port,
            addr,
            read,
            size,
            cmd,
            semaphore: owned,
        });
        let Some(t) = s
            .targets
            .iter_mut()
            .find(|t| t.host == base && t.port == port && t.addr == addr)
        else {
            s.hosts[h].regs[0x00] = 0x04; // DEV_ERR: no response
            return;
        };
        let hr = &mut s.hosts[h];
        match (size, read) {
            (0x00, _) => {}
            (0x04, true) => hr.regs[0x05] = t.regs[0],
            (0x04, false) => t.regs[0] = cmd,
            (0x08, true) => hr.regs[0x05] = t.regs[usize::from(cmd)],
            (0x08, false) => t.regs[usize::from(cmd)] = hr.regs[0x05],
            (0x0c, true) => {
                hr.regs[0x05] = t.regs[usize::from(cmd)];
                hr.regs[0x06] = t.regs[usize::from(cmd) + 1];
            }
            (0x0c, false) => {
                t.regs[usize::from(cmd)] = hr.regs[0x05];
                t.regs[usize::from(cmd) + 1] = hr.regs[0x06];
            }
            (0x14, true) => {
                hr.regs[0x05] = t.block.len() as u8;
                hr.blk = t.block.clone();
            }
            (0x14, false) => {
                let n = usize::from(hr.regs[0x05]);
                t.block = hr.blk.iter().copied().take(n).collect();
            }
            _ => {}
        }
        hr.regs[0x00] = 0x02; // INTR: done
    }
}

impl PortIo for Model {
    fn inb(&self, port: u16) -> u8 {
        let mut s = self.s.lock();
        match port {
            0xcd7 => s.pm[usize::from(s.pm_index)],
            0x3f => s.imc[usize::from(s.imc_index)],
            _ => {
                let Some(h) = s
                    .hosts
                    .iter()
                    .position(|h| (h.base..h.base + 0x11).contains(&port))
                else {
                    return 0xff;
                };
                let off = usize::from(port - s.hosts[h].base);
                let hr = &mut s.hosts[h];
                match off {
                    0x02 => {
                        hr.blk_ptr = 0;
                        hr.regs[0x02]
                    }
                    0x07 => {
                        let b = hr.blk.get(hr.blk_ptr).copied().unwrap_or(0);
                        hr.blk_ptr += 1;
                        b
                    }
                    0x08 => hr.regs[0x08] | if hr.owned { 0x10 } else { 0 },
                    _ => hr.regs[off],
                }
            }
        }
    }

    fn outb(&self, port: u16, value: u8) {
        let mut s = self.s.lock();
        match port {
            0xcd6 => s.pm_index = value,
            0xcd7 => {
                let i = usize::from(s.pm_index);
                s.pm[i] = value;
            }
            0x3e => s.imc_index = value,
            0x3f => {
                let i = s.imc_index;
                s.imc[usize::from(i)] = value;
                if i == 0x83 {
                    s.imc_flags.push(value);
                }
                if i == 0x80 && value == 0x96 && s.imc_responds {
                    s.imc[0x82] = 0xfa;
                }
            }
            _ => {
                let Some(h) = s
                    .hosts
                    .iter()
                    .position(|h| (h.base..h.base + 0x11).contains(&port))
                else {
                    return;
                };
                let off = usize::from(port - s.hosts[h].base);
                let grant = s.grant_semaphore;
                let hr = &mut s.hosts[h];
                let mut start = false;
                match off {
                    0x00 => hr.regs[0x00] &= !value, // W1C
                    0x02 => {
                        hr.regs[0x02] = value & !0x40;
                        start = value & 0x40 != 0;
                    }
                    0x07 => {
                        if hr.blk_ptr == 0 {
                            hr.blk.clear();
                        }
                        hr.blk.push(value);
                        hr.blk_ptr += 1;
                    }
                    0x08 => {
                        if value & 0x10 != 0 && grant {
                            hr.owned = true;
                        }
                        if value & 0x20 != 0 {
                            hr.owned = false;
                        }
                    }
                    _ => hr.regs[off] = value,
                }
                if start {
                    Self::execute(&mut s, h);
                }
            }
        }
    }
}

/// The MMIO view of the model's PM registers.
#[derive(Debug)]
struct ModelPm(Arc<Model>);

impl FchPm for ModelPm {
    fn read8(&self, reg: u8) -> u8 {
        self.0.s.lock().pm[usize::from(reg)]
    }
    fn write8(&self, reg: u8, value: u8) {
        self.0.s.lock().pm[usize::from(reg)] = value;
    }
}

fn setup(model: &Arc<Model>, revision: u8, notify_imc: bool, asf: bool) -> Vec<SetupAdapter> {
    let io: Arc<dyn PortIo> = model.clone();
    setup_kerncz(
        io,
        Box::new(ModelPm(model.clone())),
        revision,
        notify_imc,
        asf,
    )
    .expect("host enabled")
}

fn names(adapters: &[SetupAdapter]) -> Vec<(String, bool)> {
    adapters
        .iter()
        .map(|a| (String::from(a.adapter.name()), a.register_spd))
        .collect()
}

// ── piix4 setup ──────────────────────────────────────────────────────

fn smoke_piix4_kerncz_adapters_match_linux() -> TestResult {
    let model = Model::new();
    let got = names(&setup(&model, 0x71, false, false));
    let want = [
        ("SMBus PIIX4 adapter port 0 at 0b00", true),
        ("SMBus PIIX4 adapter port 2 at 0b00", false),
        ("SMBus PIIX4 adapter port 1 at 0b20", true),
    ];
    if got.len() != want.len()
        || got
            .iter()
            .zip(want.iter())
            .any(|(g, w)| g.0 != w.0 || g.1 != w.1)
    {
        return TestResult::Fail("KERNCZ adapters differ from Linux's names or SPD set");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_piix4_kerncz_adapters_match_linux);

fn smoke_piix4_pre_decodeen_revision_uses_smb_en() -> TestResult {
    let model = Model::new();
    {
        let mut s = model.s.lock();
        s.pm[0x00] = 0; // DecodeEn says nothing on this revision
        s.pm[0x2c] = 0x01; // SmBus0En enabled, base low byte 0x00
        s.pm[0x2d] = 0x0b;
        s.pm[0x28] = 0x21; // aux: enabled, low byte 0x20
        s.pm[0x29] = 0x0b;
    }
    let got = names(&setup(&model, 0x42, false, false));
    if got.len() != 3
        || got[0].0 != "SMBus PIIX4 adapter port 0 at 0b00"
        || got[2].0 != "SMBus PIIX4 adapter port 1 at 0b20"
    {
        return TestResult::Fail("revision < 0x49 must read the base from PMx2c/PMx28");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_piix4_pre_decodeen_revision_uses_smb_en);

fn smoke_piix4_disabled_host_and_asf() -> TestResult {
    let model = Model::new();
    model.s.lock().pm[0x00] = 0x00; // decode disabled
    let io: Arc<dyn PortIo> = model.clone();
    if setup_kerncz(io, Box::new(ModelPm(model.clone())), 0x71, false, false).is_some() {
        return TestResult::Fail("a disabled main host must not register adapters");
    }
    let model = Model::new();
    if setup(&model, 0x71, false, true).len() != 2 {
        return TestResult::Fail("\\_SB.ASFC must suppress the aux adapter");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_piix4_disabled_host_and_asf);

// ── piix4 transactions ──────────────────────────────────────────────

fn smoke_piix4_port_select_is_restored() -> TestResult {
    let model = Model::new();
    let adapters = setup(&model, 0x71, false, false);
    model.add_target(MAIN, Some(0x00), 0x50);
    model.add_target(MAIN, Some(0x08), 0x50);
    model.with_target(MAIN, 0x50, |t| t.regs[0x10] = 0xaa);
    // Firmware left port 2 selected, plus an unrelated PMx02 bit.
    model.s.lock().pm[0x02] = 0x08 | 0x01;
    let port0 = &adapters[0].adapter;
    let port2 = &adapters[1].adapter;
    let r0 = run(smbus::read_byte_data(port0.as_ref(), 0x50, 0x10));
    let r2 = run(smbus::read_byte_data(port2.as_ref(), 0x50, 0x10));
    let log = model.log();
    if r0 != Ok(0xaa) || r2.is_err() {
        return TestResult::Fail("port adapters did not reach their targets");
    }
    if log.len() != 2 || log[0].port != Some(0x00) || log[1].port != Some(0x08) {
        return TestResult::Fail("each main-host adapter must select its own port");
    }
    if model.s.lock().pm[0x02] != 0x09 {
        return TestResult::Fail("the previous port selection must be restored");
    }
    if !log.iter().all(|x| x.semaphore) || model.s.lock().hosts[0].owned {
        return TestResult::Fail("main-host transactions must hold, then drop, the semaphore");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_piix4_port_select_is_restored);

fn smoke_piix4_smbus_sizes() -> TestResult {
    let model = Model::new();
    let adapters = setup(&model, 0x71, false, false);
    let aux = adapters[2].adapter.clone();
    model.add_target(AUX, None, 0x18);
    model.with_target(AUX, 0x18, |t| {
        t.regs[0x05] = 0x34;
        t.regs[0x06] = 0x12;
    });
    if run(smbus::read_word_data(aux.as_ref(), 0x18, 0x05)) != Ok(0x1234) {
        return TestResult::Fail("word read must be little-endian DAT0|DAT1<<8");
    }
    if run(smbus::write_word_data(aux.as_ref(), 0x18, 0x20, 0xbeef)).is_err()
        || model.with_target(AUX, 0x18, |t| (t.regs[0x20], t.regs[0x21])) != (0xef, 0xbe)
    {
        return TestResult::Fail("word write did not land low byte first");
    }
    if run(smbus::write_byte_data(aux.as_ref(), 0x18, 0x30, 0x5a)).is_err()
        || model.with_target(AUX, 0x18, |t| t.regs[0x30]) != 0x5a
    {
        return TestResult::Fail("byte-data write did not land");
    }
    // Send byte is the BYTE size with the value in CMD — not a
    // byte-data write (the old driver's Write[1] bug).
    let _ = run(aux.smbus_xfer(0x18, SmbusOp::SendByte { value: 0x77 }));
    let last = model.log().pop().expect("send byte ran");
    if last.size != 0x04 || last.read || last.cmd != 0x77 {
        return TestResult::Fail("send byte must be PIIX4_BYTE with the value in SMBHSTCMD");
    }
    if model.log().iter().any(|x| x.port.is_some()) {
        return TestResult::Fail("the aux host has no port multiplexer");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_piix4_smbus_sizes);

fn smoke_piix4_absent_device_and_raw_i2c() -> TestResult {
    let model = Model::new();
    let adapters = setup(&model, 0x71, false, false);
    let port0 = adapters[0].adapter.clone();
    if run(smbus::read_byte_data(port0.as_ref(), 0x51, 0)) != Err(I2cError::Nack) {
        return TestResult::Fail("no response must be Nack (Linux -ENXIO)");
    }
    if model.s.lock().hosts[0].regs[0x00] != 0 {
        return TestResult::Fail("status must be cleared after a failed transaction");
    }
    let mut buf = [0u8; 1];
    if run(port0.transfer(0x50, &mut [I2cOp::Read(&mut buf)])) != Err(I2cError::Unsupported) {
        return TestResult::Fail("piix4 has no raw I2C (Linux: no master_xfer)");
    }
    if port0.functionality().contains(I2cFunc::I2C)
        || !port0
            .functionality()
            .contains(I2cFunc::SMBUS_BYTE_DATA | I2cFunc::SMBUS_WORD_DATA)
    {
        return TestResult::Fail("functionality must be piix4_func");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_piix4_absent_device_and_raw_i2c);

fn smoke_piix4_block_transfers() -> TestResult {
    let model = Model::new();
    let adapters = setup(&model, 0x71, true, false);
    let port0 = adapters[0].adapter.clone();
    model.add_target(MAIN, Some(0x00), 0x2c);
    let data = [1u8, 2, 3, 4, 5];
    if run(port0.smbus_xfer(
        0x2c,
        SmbusOp::WriteBlockData {
            cmd: 0x40,
            data: &data,
        },
    ))
    .is_err()
        || model.with_target(MAIN, 0x2c, |t| t.block.clone()) != data
    {
        return TestResult::Fail("block write did not deliver its bytes");
    }
    let mut out = [0u8; SMBUS_BLOCK_MAX];
    let mut len = 0usize;
    let r = run(port0.smbus_xfer(
        0x2c,
        SmbusOp::ReadBlockData {
            cmd: 0x40,
            out: &mut out,
            len: &mut len,
        },
    ));
    if r.is_err() || out[..len] != data {
        return TestResult::Fail("block read did not return the device's count and bytes");
    }
    if model.s.lock().imc_flags != [0xB4, 0xB5, 0xB4, 0xB5] {
        return TestResult::Fail("block transfers must ask the IMC to stand off, then release");
    }
    let _ = run(smbus::read_byte_data(port0.as_ref(), 0x2c, 0));
    if model.s.lock().imc_flags.len() != 4 {
        return TestResult::Fail("byte transfers must not involve the IMC");
    }
    model.with_target(MAIN, 0x2c, |t| t.block.clear());
    let r = run(port0.smbus_xfer(
        0x2c,
        SmbusOp::ReadBlockData {
            cmd: 0x40,
            out: &mut out,
            len: &mut len,
        },
    ));
    if r != Err(I2cError::Protocol) {
        return TestResult::Fail("a zero block count must be Protocol (Linux -EPROTO)");
    }
    let long = [0u8; SMBUS_BLOCK_MAX + 1];
    for bad in [&long[..], &[][..]] {
        if run(port0.smbus_xfer(0x2c, SmbusOp::WriteBlockData { cmd: 0, data: bad }))
            != Err(I2cError::InvalidArgs)
        {
            return TestResult::Fail("piix4 block write of 0 or 33 bytes must be InvalidArgs");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_piix4_block_transfers);

fn smoke_piix4_semaphore_held_by_imc_is_busy() -> TestResult {
    let model = Model::new();
    let adapters = setup(&model, 0x71, false, false);
    model.add_target(MAIN, Some(0x00), 0x50);
    model.s.lock().grant_semaphore = false;
    let r = run(smbus::read_byte_data(adapters[0].adapter.as_ref(), 0x50, 0));
    if r != Err(I2cError::Busy) {
        return TestResult::Fail("an unobtainable semaphore must be Busy (Linux -EBUSY)");
    }
    if !model.log().is_empty() {
        return TestResult::Fail("no transaction may run without the semaphore");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_piix4_semaphore_held_by_imc_is_busy);

// ── smbus::emulate ───────────────────────────────────────────────────

/// A raw-I2C bus that records the messages it was given and answers
/// reads from a fixed byte pattern.
/// One recorded `transfer`: each message as (is_read, bytes).
type Messages = Vec<(bool, Vec<u8>)>;

#[derive(Debug)]
struct Recorder {
    msgs: IrqSafeSpinLock<Vec<Messages>>,
}

impl Recorder {
    fn new() -> Self {
        Self {
            msgs: IrqSafeSpinLock::new(Vec::new()),
        }
    }
}

#[async_trait]
impl I2cBus for Recorder {
    async fn transfer(&self, _addr: u8, ops: &mut [I2cOp<'_>]) -> Result<(), I2cError> {
        let mut rec = Vec::new();
        for op in ops.iter_mut() {
            match op {
                I2cOp::Write(w) => rec.push((false, w.to_vec())),
                I2cOp::Read(r) => {
                    for (i, b) in r.iter_mut().enumerate() {
                        *b = 0x10 + i as u8;
                    }
                    rec.push((true, vec![0; r.len()]));
                }
            }
        }
        self.msgs.lock().push(rec);
        Ok(())
    }
    fn name(&self) -> &str {
        "recorder"
    }
}

fn smoke_smbus_emulation_builds_linux_messages() -> TestResult {
    let bus = Recorder::new();
    if run(smbus::read_word_data(&bus, 0x10, 0x05)) != Ok(0x1110) {
        return TestResult::Fail("emulated word read must be little-endian");
    }
    let _ = run(bus.smbus_xfer(0x10, SmbusOp::SendByte { value: 0x42 }));
    let _ = run(bus.smbus_xfer(
        0x10,
        SmbusOp::WriteBlockData {
            cmd: 0x07,
            data: &[9, 8],
        },
    ));
    let msgs = bus.msgs.lock().clone();
    let want: [&[(bool, &[u8])]; 3] = [
        &[(false, &[0x05]), (true, &[0, 0])],
        &[(false, &[0x42])],
        &[(false, &[0x07, 2, 9, 8])],
    ];
    if msgs.len() != 3
        || msgs.iter().zip(want.iter()).any(|(got, want)| {
            got.len() != want.len()
                || got
                    .iter()
                    .zip(want.iter())
                    .any(|(g, w)| g.0 != w.0 || g.1 != w.1)
        })
    {
        return TestResult::Fail("emulated messages differ from i2c_smbus_xfer_emulated");
    }
    if run(bus.smbus_xfer(0x10, SmbusOp::Quick { read: false })) != Err(I2cError::Unsupported) {
        return TestResult::Fail("Quick has no I2cOp encoding");
    }
    let long = [0u8; SMBUS_BLOCK_MAX + 1];
    if run(bus.smbus_xfer(
        0x10,
        SmbusOp::WriteBlockData {
            cmd: 0,
            data: &long,
        },
    )) != Err(I2cError::InvalidArgs)
    {
        return TestResult::Fail("an emulated block write over 32 bytes must be InvalidArgs");
    }
    if !bus.functionality().contains(I2cFunc::I2C)
        || bus.functionality().contains(I2cFunc::SMBUS_QUICK)
    {
        return TestResult::Fail("default functionality must be I2C plus the emulated sizes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_smbus_emulation_builds_linux_messages);

// ── Clients and SPD ──────────────────────────────────────────────────

fn mem(size_mb: u32, memory_type: u8) -> SmbiosMemoryDevice {
    SmbiosMemoryDevice {
        size_mb,
        memory_type,
        ..SmbiosMemoryDevice::ZERO
    }
}

fn smoke_spd_plan_follows_i2c_register_spd() -> TestResult {
    let ddr5 = [mem(16384, 0x22), mem(16384, 0x22)];
    let probe = |kind, slots, modules, instantiate| SpdPlan::Probe {
        kind,
        slots,
        modules,
        instantiate,
    };
    let cases: [(&[SmbiosMemoryDevice], bool, SpdPlan); 7] = [
        (&ddr5, false, probe("spd5118", 2, 2, true)),
        (&ddr5, true, probe("spd5118", 2, 2, false)),
        (
            &[mem(0, 0x22), mem(8192, 0x1a), mem(0, 0x02)],
            false,
            probe("ee1004", 3, 1, true),
        ),
        (
            &[mem(8192, 0x22), mem(8192, 0x1a)],
            false,
            SpdPlan::MixedTypes,
        ),
        (&[mem(0, 0x22), mem(4096, 0x02)], false, SpdPlan::NoModules),
        (&[mem(4096, 0x24)], false, SpdPlan::Unsupported(0x24)),
        (&[mem(4096, 0x18); 12], false, probe("spd", 8, 12, true)),
    ];
    for (devices, wd, want) in cases {
        if plan(devices, wd) != want {
            return TestResult::Fail("SPD plan differs from i2c_register_spd");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_spd_plan_follows_i2c_register_spd);

fn smoke_spd_scan_instantiates_answering_slots() -> TestResult {
    client::__reset_for_test();
    let model = Model::new();
    let adapters = setup(&model, 0x71, false, false);
    let port0: Arc<dyn I2cBus> = adapters[0].adapter.clone();
    // Four slots, two modules, fitted in slots 1 and 3.
    model.add_target(MAIN, Some(0x00), 0x51);
    model.add_target(MAIN, Some(0x00), 0x53);
    let devices = [
        mem(0, 0x22),
        mem(16384, 0x22),
        mem(0, 0x22),
        mem(16384, 0x22),
    ];
    let created = run(crate::spd::scan(&port0, &devices, false));
    let clients = client::clients_of_kind("spd5118");
    let addrs: Vec<u8> = clients.iter().map(|c| c.addr()).collect();
    let probes: Vec<(u8, u8, bool)> = model
        .log()
        .iter()
        .map(|x| (x.addr, x.size, x.read))
        .collect();
    client::__reset_for_test();
    if created != 2 || addrs != [0x51, 0x53] {
        return TestResult::Fail("SPD scan must instantiate exactly the answering slots");
    }
    // EEPROM range: probed with receive byte, never a quick write.
    if probes
        != [
            (0x50, 0x04, true),
            (0x51, 0x04, true),
            (0x52, 0x04, true),
            (0x53, 0x04, true),
        ]
    {
        return TestResult::Fail("SPD probes must be receive-byte reads in slot order");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_spd_scan_instantiates_answering_slots);

fn smoke_client_registry_validates_addresses() -> TestResult {
    client::__reset_for_test();
    let bus: Arc<dyn I2cBus> = Arc::new(Recorder::new());
    let first = client::new_client_device(&bus, 0x50, "spd5118");
    let dup = client::new_client_device(&bus, 0x50, "spd5118");
    let general_call = client::new_client_device(&bus, 0x00, "spd5118");
    let over_7_bits = client::new_client_device(&bus, 0x80, "spd5118");
    // Reserved for probing only: an explicit client may sit there.
    let cbus = client::new_client_device(&bus, 0x01, "spd5118");
    // Busy is per adapter: another adapter, even one reporting the same
    // name, has its own address space.
    let other: Arc<dyn I2cBus> = Arc::new(Recorder::new());
    let same_name = other.name() == bus.name();
    let elsewhere = client::new_client_device(&other, 0x50, "spd5118");
    let n = client::clients().len();
    client::__reset_for_test();
    if first.is_err() || dup.err() != Some(I2cError::Busy) {
        return TestResult::Fail("a second client at one address must be Busy (Linux -EBUSY)");
    }
    if !same_name || elsewhere.is_err() {
        return TestResult::Fail("an address is busy per adapter, not per adapter name");
    }
    if general_call.err() != Some(I2cError::InvalidArgs)
        || over_7_bits.err() != Some(I2cError::InvalidArgs)
    {
        return TestResult::Fail("0x00 and 8-bit addresses must be InvalidArgs (Linux -EINVAL)");
    }
    if cbus.is_err() || n != 3 {
        return TestResult::Fail("i2c_new_client_device accepts 0x01-0x7f; only probing is strict");
    }
    TestResult::Pass
}
kernel_test_in!("drivers-i2c", smoke_client_registry_validates_addresses);
