use super::*;
use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[allow(dead_code)]
mod firmware_metadata {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../verification/data/wifi-firmware/realtek/metadata.rs"
    ));
}

fn smoke_rtw8822ce_raw_source_metadata_parser_golden() -> TestResult {
    // Replays retain the 64-byte source header only; zero sections/checksums
    // are parser geometry, never executable/provisionable firmware.
    let source = &firmware_metadata::SOURCE_2;
    if filename(0xc822) != Ok(source.name)
        || source.sha256 != "3deecb31210986d98cdbfb000391e08d602a6eee4ffc883969faa2b907ab03ba"
    {
        return TestResult::Fail("RTL8822CE source identity/provenance changed");
    }
    let mut bytes =
        match narf_wifi_fixtures::firmware::metadata_replay(source.length, source.fragments) {
            Ok(bytes) => bytes,
            Err(_) => return TestResult::Fail("RTL8822CE metadata replay geometry"),
        };
    let image = match parse(0xc822, &bytes) {
        Ok(image) => image,
        Err(_) => return TestResult::Fail("RTL8822CE raw-source header rejected"),
    };
    if image.info
        != (Info {
            version: 9,
            subversion: 9,
            h2c: 15,
            sections: 3,
        })
    {
        return TestResult::Fail("RTL8822CE independently extracted header facts");
    }
    for (section, (kind, address, length, offset)) in image.sections.iter().zip([
        (Kind::Dmem, 0x200000, 19336, 64),
        (Kind::Imem, 0x30000, 54072, 19400),
        (Kind::Emem, 0x100000, 129128, 73472),
    ]) {
        let Some(section) = section else {
            return TestResult::Fail("RTL8822CE source section missing");
        };
        if section.kind != kind
            || section.address != address
            || section.bytes.len() != length
            || section.bytes.as_ptr() as usize - bytes.as_ptr() as usize != offset
            || section.bytes.iter().any(|&byte| byte != 0)
        {
            return TestResult::Fail("RTL8822CE source section/checksum boundaries");
        }
    }
    for end in [0, 63, 64, bytes.len() - 1] {
        if parse(0xc822, &bytes[..end]).is_ok() {
            return TestResult::Fail("RTL8822CE truncated source geometry admitted");
        }
    }
    bytes[0x20] ^= 1;
    if parse(0xc822, &bytes).is_ok() {
        return TestResult::Fail("RTL8822CE source memory profile ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/fw",
    smoke_rtw8822ce_raw_source_metadata_parser_golden
);
#[derive(Clone, Debug, PartialEq, Eq)]
enum Op {
    Claim,
    Read(u8, u16),
    Write(u8, u16, u32),
    Packet(Vec<u8>),
    LteRead,
    LteWrite(u32),
    Finish,
    Delay,
}
#[derive(Debug)]
struct Model {
    regs: Vec<u8>,
    trace: Vec<Op>,
    calls: usize,
    fail: Option<usize>,
    claim: bool,
    packet_pending: bool,
    ddma_stall: bool,
    bad_checksum: bool,
    no_ready: bool,
    packet_data: Vec<u8>,
}
impl Model {
    fn new() -> Self {
        let mut regs = vec![0; 0x1400];
        regs[3] = 0xff;
        regs[0x1d] = 0xa5;
        regs[0x10d] = 0x36;
        regs[0x100] = 0x30;
        regs[0x550] = 0x19;
        Self {
            regs,
            trace: Vec::new(),
            calls: 0,
            fail: None,
            claim: false,
            packet_pending: false,
            ddma_stall: false,
            bad_checksum: false,
            no_ready: false,
            packet_data: Vec::new(),
        }
    }
    fn access(&mut self, operation: Op) -> Result<(), Error> {
        self.trace.push(operation);
        let call = self.calls;
        self.calls += 1;
        if self.fail == Some(call) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn read(&mut self, width: u8, reg: u16) -> Result<u32, Error> {
        self.access(Op::Read(width, reg))?;
        let at = usize::from(reg);
        let mut bytes = [0; 4];
        bytes[..usize::from(width / 8)]
            .copy_from_slice(&self.regs[at..at + usize::from(width / 8)]);
        let mut value = u32::from_le_bytes(bytes);
        if reg == 0x1208 {
            if !self.ddma_stall {
                value &= !(1 << 31);
            }
            if self.bad_checksum {
                value |= 1 << 27;
            }
        }
        if reg == 0x80 && value & (1 << 14) != 0 && !self.no_ready {
            value |= 1 << 15;
        }
        Ok(value)
    }
    fn write(&mut self, width: u8, reg: u16, value: u32) -> Result<(), Error> {
        self.access(Op::Write(width, reg, value))?;
        let at = usize::from(reg);
        self.regs[at..at + usize::from(width / 8)]
            .copy_from_slice(&value.to_le_bytes()[..usize::from(width / 8)]);
        Ok(())
    }
}
#[async_trait::async_trait]
// SAFETY: Inert register/packet model. No address or byte reaches hardware;
// packets are copied before an intentionally cancellable publication point.
unsafe impl Io for Model {
    fn claim_pristine(&mut self) -> Result<(), Error> {
        self.access(Op::Claim)?;
        if self.claim {
            return Err(Error::Prerequisite);
        }
        self.claim = true;
        Ok(())
    }
    fn read8(&mut self, reg: u16) -> Result<u8, Error> {
        Ok(self.read(8, reg)? as u8)
    }
    fn read16(&mut self, reg: u16) -> Result<u16, Error> {
        Ok(self.read(16, reg)? as u16)
    }
    fn read32(&mut self, reg: u16) -> Result<u32, Error> {
        self.read(32, reg)
    }
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error> {
        self.write(8, reg, u32::from(value))
    }
    fn write16(&mut self, reg: u16, value: u16) -> Result<(), Error> {
        self.write(16, reg, u32::from(value))
    }
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        self.write(32, reg, value)
    }
    async fn reserved_page(&mut self, data: &[u8]) -> Result<(), Error> {
        self.access(Op::Packet(data.to_vec()))?;
        self.packet_data = data.to_vec();
        if self.packet_pending {
            core::future::pending::<()>().await;
        }
        Ok(())
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        self.access(Op::LteRead)?;
        Ok(0x12345678)
    }
    async fn lte_restore(&mut self, value: u32) -> Result<(), Error> {
        self.access(Op::LteWrite(value))
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        self.access(Op::Finish)
    }
    async fn delay_us(&mut self, _: u64) {
        self.trace.push(Op::Delay);
    }
}
fn image(dmem: usize, imem: usize, emem: usize) -> Vec<u8> {
    let mut bytes = vec![0; 64 + dmem + 8 + imem + 8 + if emem != 0 { emem + 8 } else { 0 }];
    bytes[..2].copy_from_slice(&[0x22, 0x88]);
    bytes[4..7].copy_from_slice(&[9, 0, 9]);
    bytes[0x1c] = 15;
    bytes[0x18] = if emem != 0 { 0x10 } else { 0 };
    for (offset, value) in [
        (0x20, 0x80200000u32),
        (0x24, dmem as u32),
        (0x30, imem as u32),
        (0x34, emem as u32),
        (0x38, 0x80100000),
        (0x3c, 0x80030000),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, byte) in bytes[64..].iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    bytes
}
fn smoke_rtw88_sections_checksum_extents_and_native_iddma_order() -> TestResult {
    let bytes = image(4093, 9, 5);
    let parsed = parse(0xc822, &bytes).unwrap();
    if parsed.info.sections != 3
        || parsed.sections[0].as_ref().unwrap().bytes.len() != 4101
        || parsed.sections[1].as_ref().unwrap().bytes.len() != 17
        || parsed.sections[2].as_ref().unwrap().bytes.len() != 13
    {
        return TestResult::Fail("firmware checksum trailers/section extents differ from Linux");
    }
    let mut owner = Owner::new(Model::new(), 0xc822);
    let info = narf_scheduler::block_on(owner.download(&bytes));
    if info.is_err() || owner.phase() != Phase::Ready {
        return TestResult::Fail("native reserved-page/IDDMA firmware owner failed");
    }
    let packets: Vec<_> = owner
        .io
        .trace
        .iter()
        .filter_map(|op| {
            if let Op::Packet(data) = op {
                Some(data.as_slice())
            } else {
                None
            }
        })
        .collect();
    if packets
        != vec![
            &bytes[64..4160],
            &bytes[4160..4165],
            &bytes[4165..4182],
            &bytes[4182..4195],
        ]
    {
        return TestResult::Fail("firmware sections were not transferred as exact4KiB chunks");
    }
    let writes: Vec<_> = owner
        .io
        .trace
        .iter()
        .filter_map(|op| {
            if let Op::Write(32, reg, value) = op {
                if *reg == 0x1204 {
                    Some(*value)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();
    if writes != [0x200000, 0x201000, 0x30000, 0x100000]
        || !owner.io.trace.contains(&Op::Write(32, 0x1208, 0xa1000005))
        || owner.io.trace.last() != Some(&Op::Finish)
    {
        return TestResult::Fail("IDDMA source/destination/continue/start ownership order wrong");
    }
    let calls = owner.io.calls;
    if narf_scheduler::block_on(owner.download(&bytes)) != Err(Error::State)
        || owner.io.calls != calls
    {
        return TestResult::Fail("ready firmware owner repeated reset/DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_sections_checksum_extents_and_native_iddma_order
);
fn smoke_rtw88_section_layout_rejected_before_any_hardware() -> TestResult {
    let good = image(9, 9, 9);
    for mutation in 0..11 {
        let mut bytes = good.clone();
        let did = if mutation == 0 { 0xb822 } else { 0xc822 };
        match mutation {
            0 => {}
            1 => {
                bytes[0] ^= 1;
            }
            2 => {
                bytes.truncate(63);
            }
            3 => {
                bytes.pop();
            }
            4 => bytes.push(0),
            5 => bytes[0x24..0x28].fill(255),
            6 => bytes[0x20..0x24].copy_from_slice(&0x80201000u32.to_le_bytes()),
            7 => bytes[0x30..0x34].fill(0),
            8 => bytes[0x18] = 0,
            9 => bytes[0x34..0x38].fill(255),
            _ => bytes[0x3c..0x40].copy_from_slice(&0x80400000u32.to_le_bytes()),
        }
        let mut owner = Owner::new(Model::new(), did);
        if narf_scheduler::block_on(owner.download(&bytes)).is_ok() || !owner.io.trace.is_empty() {
            return TestResult::Fail("malformed/unsupported firmware reached PCI/MCU operations");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_section_layout_rejected_before_any_hardware
);
fn smoke_rtw88_firmware_every_io_error_and_active_packet_cancel_terminal() -> TestResult {
    let bytes = image(9, 9, 9);
    let mut reference = Owner::new(Model::new(), 0xc822);
    narf_scheduler::block_on(reference.download(&bytes)).unwrap();
    for fail in 0..reference.io.calls {
        let mut io = Model::new();
        io.fail = Some(fail);
        let mut owner = Owner::new(io, 0xc822);
        if narf_scheduler::block_on(owner.download(&bytes)) != Err(Error::Access)
            || owner.phase() != Phase::Failed
        {
            return TestResult::Fail("failed firmware I/O continued or claimed ready");
        }
        let calls = owner.io.calls;
        if calls != fail + 1
            || narf_scheduler::block_on(owner.download(&bytes)) != Err(Error::State)
            || owner.io.calls != calls
        {
            return TestResult::Fail("ambiguous firmware failure attempted cleanup/reuse");
        }
    }
    let mut io = Model::new();
    io.packet_pending = true;
    let mut owner = Owner::new(io, 0xc822);
    let mut future = Box::pin(owner.download(&bytes));
    if future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
        != Poll::Pending
    {
        return TestResult::Fail("cancel fixture did not publish actual packet");
    }
    drop(future);
    let calls = owner.io.calls;
    let packet = owner.io.packet_data.clone();
    if packet.is_empty()
        || owner.phase() != Phase::Failed
        || narf_scheduler::block_on(owner.download(&bytes)) != Err(Error::State)
        || owner.io.calls != calls
        || owner.io.packet_data != packet
    {
        return TestResult::Fail("cancelled packet ownership was reset or reused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_firmware_every_io_error_and_active_packet_cancel_terminal
);
fn smoke_rtw88_firmware_checksum_iddma_busy_and_ready_failures() -> TestResult {
    for mode in 0..4 {
        let mut io = Model::new();
        match mode {
            0 => io.bad_checksum = true,
            1 => io.ddma_stall = true,
            2 => io.no_ready = true,
            _ => io.claim = true,
        }
        let mut owner = Owner::new(io, 0xc822);
        let wanted = match mode {
            0 => Error::Checksum,
            1 => Error::Timeout,
            2 => Error::Ready,
            _ => Error::Prerequisite,
        };
        if narf_scheduler::block_on(owner.download(&image(9, 9, 0))) != Err(wanted)
            || owner.phase() != Phase::Failed
            || owner.io.trace.contains(&Op::Finish)
        {
            return TestResult::Fail("bad/busy/unready firmware crossed readiness gate");
        }
        let count = owner.io.calls;
        if narf_scheduler::block_on(owner.download(&image(9, 9, 0))) != Err(Error::State)
            || owner.io.calls != count
        {
            return TestResult::Fail("terminal firmware failure retried hardware");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_firmware_checksum_iddma_busy_and_ready_failures
);
include!("firmware/golden.rs");
fn smoke_rtw88_firmware_registers_match_actual_linux_callbacks() -> TestResult {
    let mut owner = Owner::new(Model::new(), 0xc822);
    narf_scheduler::block_on(owner.download(&image(4093, 9, 5))).unwrap();
    let trace: Vec<_> = owner
        .io
        .trace
        .iter()
        .filter_map(|op| match op {
            Op::Read(width, reg) => Some((0, *width, *reg, 0)),
            Op::Write(width, reg, value) => Some((1, *width, *reg, *value)),
            Op::Packet(bytes) => Some((2, 0, 0, bytes.len() as u32)),
            Op::LteRead => Some((3, 0, 0, 0)),
            Op::LteWrite(value) => Some((4, 0, 0, *value)),
            Op::Finish => Some((5, 0, 0, 0)),
            Op::Claim | Op::Delay => None,
        })
        .collect();
    if trace != LINUX_FW {
        return TestResult::Fail(
            "FW CPU/reset/backup/chunk/DDMA/checksum/start differs from actual Linux C",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw88_firmware_registers_match_actual_linux_callbacks
);
