use super::*;
use alloc::vec;
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    edid: Vec<u8>,
    dpcd: [u8; 16],
    extended: [u8; 16],
    segment: usize,
    offset: usize,
    mot: bool,
    commands: Vec<(u8, u8, u32, Vec<u8>)>,
    defers: usize,
    delays: usize,
    fail: Option<dmub::Error>,
    stall: Option<usize>,
}
fn checksum(block: &mut [u8]) {
    block[127] = 0u8.wrapping_sub(block[..127].iter().fold(0u8, |s, b| s.wrapping_add(*b)));
}
fn fake(blocks: usize) -> Fake {
    let mut edid = vec![0; blocks * 128];
    edid[..8].copy_from_slice(&[0, 255, 255, 255, 255, 255, 255, 0]);
    edid[18] = 1;
    edid[19] = 4;
    edid[126] = (blocks - 1) as u8;
    for (i, block) in edid.chunks_exact_mut(128).enumerate() {
        if i != 0 {
            block[0] = 2;
            block[1] = i as u8;
        }
        checksum(block);
    }
    let mut dpcd = [0; 16];
    dpcd[..3].copy_from_slice(&[0x14, 30, 0x84]);
    dpcd[14] = 0x80;
    let mut extended = dpcd;
    extended[0] = 0x21;
    Fake {
        edid,
        dpcd,
        extended,
        segment: 9,
        offset: 0,
        mot: false,
        commands: Vec::new(),
        defers: 0,
        delays: 0,
        fail: None,
        stall: None,
    }
}
impl Aux for Fake {
    async fn transfer(
        &mut self,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), dmub::Error> {
        if self.stall == Some(self.commands.len()) {
            core::future::pending::<()>().await;
        }
        self.commands
            .push((instance, action, address, data.to_vec()));
        if let Some(error) = self.fail {
            return Err(error);
        }
        if self.defers != 0 {
            self.defers -= 1;
            return Err(dmub::Error::Aux(8));
        }
        if instance == 2 {
            return Err(dmub::Error::Aux(1));
        }
        assert_eq!(instance, 1, "connector/transmitter mistaken for AUX");
        match (action, address, data.len()) {
            (0x90, 0, 16) => data.copy_from_slice(&self.dpcd),
            (0x90, 0x2200, 16) => data.copy_from_slice(&self.extended),
            (0, 0x30, 1) => {
                assert!(!self.mot);
                self.segment = usize::from(data[0]);
            }
            (0x40, 0x50, 1) => {
                assert!(!self.mot);
                self.offset = self.segment * 256 + usize::from(data[0]);
                self.mot = true;
            }
            (0x10 | 0x50, 0x50, 16) => {
                assert!(self.mot);
                data.copy_from_slice(&self.edid[self.offset..self.offset + 16]);
                self.offset += 16;
                self.mot = action != 0x10;
            }
            (0x10, 0x50, 0) => self.mot = false,
            _ => panic!("incorrect AUX/EDID transaction"),
        }
        Ok(())
    }
    async fn delay(&mut self) {
        self.delays += 1;
    }
}
fn path(aux: u8, transmitter: u8) -> inventory::Path {
    inventory::Path {
        connector: inventory::Connector::DisplayPort,
        connector_instance: 4,
        transmitter,
        aux: Some(aux),
        hpd: 2,
        device_tag: 8,
    }
}
fn probe() -> Probe {
    Probe::new(vec![path(1, 3), path(2, 0)]).unwrap()
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

fn navi48_display_reads_extended_caps_segmented_edid_and_distinct_wires() -> TestResult {
    let mut p = probe();
    let mut io = fake(3);
    io.defers = 2;
    let ports = run(p.scan_with(&mut io)).unwrap();
    let connected = ports[0].sink.as_ref().unwrap();
    if ports.len() != 2
        || ports[0].path.transmitter != 3
        || connected.dpcd[0] != 0x21
        || connected.edid != io.edid
        || ports[1].sink != Err(Error::Transport(dmub::Error::Aux(1)))
        || p.state() != State::Ready
        || io.delays != 2
        || io.mot
    {
        return TestResult::Fail("routed sink discovery or complete EDID");
    }
    let segments: Vec<_> = io
        .commands
        .iter()
        .filter(|c| c.2 == 0x30)
        .map(|c| c.3[0])
        .collect();
    let offsets: Vec<_> = io
        .commands
        .iter()
        .filter(|c| c.1 == 0x40)
        .map(|c| c.3[0])
        .collect();
    let stops = io
        .commands
        .iter()
        .filter(|c| c.1 == 0x10 && c.3.len() == 16)
        .count();
    if segments != [0, 1] || offsets != [0, 128, 0] || stops != 3 {
        return TestResult::Fail("E-EDID segment/offset/STOP sequence");
    }
    io.extended[0] = 0x12;
    if run(p.scan_with(&mut io)).unwrap()[0]
        .sink
        .as_ref()
        .unwrap()
        .dpcd[0]
        != 0x14
    {
        return TestResult::Fail("older extended caps replaced base capabilities");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-display",
    navi48_display_reads_extended_caps_segmented_edid_and_distinct_wires
);

fn navi48_display_bounds_edid_defers_and_preserves_other_ports() -> TestResult {
    for case in 0..4 {
        let mut p = probe();
        let mut io = fake(2);
        let expected = match case {
            0 => {
                io.edid[130] ^= 1;
                Error::InvalidEdid
            }
            1 => {
                io.edid[0] = 1;
                checksum(&mut io.edid[..128]);
                Error::InvalidEdid
            }
            2 => {
                io.edid[126] = 32;
                checksum(&mut io.edid[..128]);
                Error::EdidTooLarge
            }
            _ => {
                io.dpcd[2] = 3;
                Error::InvalidDpcd
            }
        };
        let ports = run(p.scan_with(&mut io)).unwrap();
        if ports[0].sink != Err(expected) || ports.len() != 2 || io.mot || p.state() != State::Ready
        {
            return TestResult::Fail("malformed sink poisoned scan or EDID left I2C open");
        }
    }
    let mut p = Probe::new(vec![path(1, 3)]).unwrap();
    let mut io = fake(1);
    io.defers = 10;
    let ports = run(p.scan_with(&mut io)).unwrap();
    if io.commands.len() != 7
        || io.delays != 6
        || ports[0].sink != Err(Error::Transport(dmub::Error::Aux(8)))
    {
        return TestResult::Fail("AUX DEFER retries unbounded or wrong result");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-display",
    navi48_display_bounds_edid_defers_and_preserves_other_ports
);

fn navi48_display_cancellation_and_transport_failure_block_reuse() -> TestResult {
    let mut p = probe();
    let mut io = fake(1);
    io.stall = Some(5);
    {
        let mut future = core::pin::pin!(p.scan_with(&mut io));
        if !future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
        {
            return TestResult::Fail("cancellation fixture did not suspend");
        }
    }
    io.stall = None;
    let commands = io.commands.len();
    if p.state() != State::Scanning
        || !io.mot
        || run(p.scan_with(&mut io)) != Err(Error::Busy)
        || commands != io.commands.len()
    {
        return TestResult::Fail("cancelled I2C MOT sequence silently reused");
    }
    for error in [
        dmub::Error::Revoked,
        dmub::Error::DeviceGone,
        dmub::Error::Protocol,
        dmub::Error::CommandTimeout,
    ] {
        let mut p = probe();
        let mut io = fake(1);
        io.fail = Some(error);
        if run(p.scan_with(&mut io)) != Err(Error::Transport(error))
            || p.state() != State::Failed(Error::Transport(error))
            || run(p.scan_with(&mut io)) != Err(Error::Busy)
            || io.commands.len() != 1
        {
            return TestResult::Fail("failed transport reused or other ports accessed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-display",
    navi48_display_cancellation_and_transport_failure_block_reuse
);

fn navi48_display_refuses_ambiguous_or_unroutable_board_paths() -> TestResult {
    for case in 0..5 {
        let first = path(1, 3);
        let mut second = path(2, 0);
        match case {
            0 => second.aux = first.aux,
            1 => second.transmitter = first.transmitter,
            2 => second.aux = Some(4),
            3 => second.hpd = 5,
            _ => second.aux = None,
        }
        if Probe::new(vec![first, second]).is_ok() {
            return TestResult::Fail("ambiguous or nonexistent DCN4 channel admitted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48-display",
    navi48_display_refuses_ambiguous_or_unroutable_board_paths
);
