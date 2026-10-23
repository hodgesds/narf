use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
#[derive(Debug, PartialEq, Eq)]
enum Op {
    Read(u32),
    Write(u32, u32),
    Delay(u64),
}
struct Model {
    csr: BTreeMap<u32, u32>,
    prph: BTreeMap<u32, u32>,
    read_address: u32,
    write_address: u32,
    now: u64,
    trace: Vec<Op>,
    count: usize,
    fail: Option<usize>,
    pending: bool,
    clock: bool,
    ownership: bool,
}
impl Model {
    fn new() -> Self {
        Self {
            csr: BTreeMap::from([(0x24, 1 << 27)]),
            prph: BTreeMap::new(),
            read_address: 0,
            write_address: 0,
            now: 0,
            trace: Vec::new(),
            count: 0,
            fail: None,
            pending: false,
            clock: true,
            ownership: true,
        }
    }
    fn access(&mut self) -> Result<(), Error> {
        let n = self.count;
        self.count += 1;
        if self.fail == Some(n) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
}
impl Io for Model {
    fn read(&mut self, r: u32) -> Result<u32, Error> {
        self.access()?;
        self.trace.push(Op::Read(r));
        Ok(if r == 0x450 {
            *self.prph.get(&self.read_address).unwrap_or(&0)
        } else {
            let mut value = *self.csr.get(&r).unwrap_or(&0);
            if r == 0x24 && self.clock {
                value |= 1;
                value &= !(1 << 4);
            }
            if r == 0 && !self.ownership {
                value &= !(1 << 22)
            }
            value
        })
    }
    fn write(&mut self, r: u32, v: u32) -> Result<(), Error> {
        self.access()?;
        self.trace.push(Op::Write(r, v));
        match r {
            0x448 => self.read_address = v & 0xfffff,
            0x444 => self.write_address = v & 0xfffff,
            0x44c => {
                self.prph.insert(self.write_address, v);
            }
            _ => {
                self.csr.insert(r, v);
            }
        }
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        self.trace.push(Op::Delay(us));
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.now += us;
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn profile(integrated: bool) -> Profile {
    super::super::gen2_profile::select(
        if integrated { 0xa0f0 } else { 0x2723 },
        if integrated { 0x351 } else { 0x340 },
        0x10c000,
    )
    .unwrap()
}
fn prepare(owner: &mut Owner, io: &mut Model, integrated: bool) -> Option<Result<(), Error>> {
    // SAFETY: owned inert register model; no device/bus/DMA/IRQ producer.
    ready(unsafe { owner.prepare(io, profile(integrated), 0x352, 0x2d) })
}
fn smoke_iwl_gen2_prepare_discrete_and_integrated_native_contract() -> TestResult {
    for integrated in [false, true] {
        let mut owner = Owner::default();
        let mut io = Model::new();
        io.csr.insert(0, 0x1234ffcf);
        if prepare(&mut owner, &mut io, integrated) != Some(Ok(()))
            || owner.phase() != Phase::Prepared
        {
            return TestResult::Fail("22000 preparation failed");
        }
        // PHY=type1/step3/dash2 =>0xe400, MAC stepping2. Unrelated bits survive.
        if io.csr.get(&0) != Some(&0x127ce4c2)
            || io.csr.get(&0x3c) != Some(&2)
            || io.csr.get(&0xa8) != Some(&0x800fffff)
        {
            return TestResult::Fail("NIC PHY config/step masks, L0s or shadow programming");
        }
        let delays: Vec<_> = io
            .trace
            .iter()
            .filter_map(|op| {
                if let Op::Delay(us) = op {
                    Some(*us)
                } else {
                    None
                }
            })
            .collect();
        if delays
            != if integrated {
                vec![6000, 20, 20, 6000]
            } else {
                vec![6000, 2000, 200]
            }
        {
            return TestResult::Fail("integrated forced-gating or discrete BISR delay contract");
        }
        if integrated {
            if io.prph.get(&0x3458) != Some(&3) {
                return TestResult::Fail(
                    "CNVi forced power gating left FORCE_ACTIVE or omitted SLP/PG",
                );
            }
        } else if io.prph.contains_key(&0x3458) {
            return TestResult::Fail("AX200 received integrated-only power gating");
        }
        if Owner::rom_ltr(&mut io, profile(integrated)) != Ok(())
            || if integrated {
                io.prph.get(&0x348c) != Some(&15) || io.prph.get(&0x3480) != Some(&0x88fa88fa)
            } else {
                io.csr.get(&0xd4) != Some(&0x88fa88fa)
            }
        {
            return TestResult::Fail("ROM boot LTR address/format");
        }
        let count = io.count;
        if prepare(&mut owner, &mut io, integrated) != Some(Err(Error::Terminal))
            || io.count != count
        {
            return TestResult::Fail("prepared APM owner accepted a repeated reset");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_gen2_prepare_discrete_and_integrated_native_contract
);
fn smoke_iwl_gen2_prepare_every_access_failure_and_cancel_stays_terminal() -> TestResult {
    for integrated in [false, true] {
        let mut owner = Owner::default();
        let mut baseline = Model::new();
        assert_eq!(prepare(&mut owner, &mut baseline, integrated), Some(Ok(())));
        for failure in 0..baseline.count {
            let mut owner = Owner::default();
            let mut io = Model::new();
            io.fail = Some(failure);
            if prepare(&mut owner, &mut io, integrated) != Some(Err(Error::Access))
                || owner.phase() != Phase::Preparing
            {
                return TestResult::Fail("failed preparation did not retain terminal owner");
            }
            let count = io.count;
            if prepare(&mut owner, &mut io, integrated) != Some(Err(Error::Terminal))
                || io.count != count
            {
                return TestResult::Fail("failed register operation replayed after partial reset");
            }
        }
        let mut owner = Owner::default();
        let mut io = Model::new();
        io.pending = true;
        if prepare(&mut owner, &mut io, integrated).is_some() || owner.phase() != Phase::Preparing {
            return TestResult::Fail("dropped reset delay did not retain terminal phase");
        }
        let count = io.count;
        if prepare(&mut owner, &mut io, integrated) != Some(Err(Error::Terminal))
            || io.count != count
        {
            return TestResult::Fail("cancelled reset retried");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_gen2_prepare_every_access_failure_and_cancel_stays_terminal
);
fn smoke_iwl_gen2_prepare_timeout_rfkill_and_protected_persistence() -> TestResult {
    for kind in 0..5 {
        let mut owner = Owner::default();
        let mut io = Model::new();
        let expected = match kind {
            0 => {
                io.clock = false;
                Error::Timeout
            }
            1 => {
                io.ownership = false;
                Error::Timeout
            }
            2 => {
                io.csr.insert(0x24, 0);
                Error::RadioDisabled
            }
            3 => {
                io.prph.insert(0x3440, 1 << 12);
                io.prph.insert(0x4d00, 1 << 12);
                Error::Persistence
            }
            _ => {
                io.prph.insert(0x3440, u32::MAX);
                Error::Gone
            }
        };
        if prepare(&mut owner, &mut io, true) != Some(Err(expected))
            || owner.phase() != Phase::Preparing
        {
            return TestResult::Fail("timeout/RFkill/protected/gone preparation outcome");
        }
        let count = io.count;
        if prepare(&mut owner, &mut io, true) != Some(Err(Error::Terminal)) || io.count != count {
            return TestResult::Fail("unsafe preparation outcome reopened owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/iwlwifi/gen2",
    smoke_iwl_gen2_prepare_timeout_rfkill_and_protected_persistence
);
