use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
include!("golden.rs");
struct Model {
    words: Vec<u32>,
    trace: Vec<(u8, u32, u32)>,
    now: u64,
    operations: usize,
    fail: Option<usize>,
    pending: Option<usize>,
    delays: usize,
    hold: u8,
}
impl Model {
    fn new(seed: u8) -> Self {
        let mut words = vec![u32::from(seed) * 0x01010101; 0x20000 / 4];
        words[SWSI as usize / 4] = 0x45678;
        Self {
            words,
            trace: Vec::new(),
            now: 0,
            operations: 0,
            fail: None,
            pending: None,
            delays: 0,
            hold: 0,
        }
    }
    fn access(&mut self) -> Result<(), Error> {
        let op = self.operations;
        self.operations += 1;
        if self.fail == Some(op) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
}
impl Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, Error> {
        Err(Error::Access)
    }
    fn read16(&mut self, _: u32) -> Result<u16, Error> {
        Err(Error::Access)
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.access()?;
        let mut v = self.words[a as usize / 4];
        if a == SWSI {
            v |= match self.hold {
                1 => 1 << 24,
                2 => 1 << 25,
                _ => 0,
            };
        }
        self.trace.push((0, a, v));
        Ok(v)
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), Error> {
        Err(Error::Access)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), Error> {
        Err(Error::Access)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.access()?;
        self.words[a as usize / 4] = v;
        self.trace.push((4, a, v));
        if a == BASE + 0x378 && self.hold != 3 {
            self.words[SWSI as usize / 4] |= 1 << 26;
        }
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        let delay = self.delays;
        self.delays += 1;
        self.trace.push((8, us as u32, 0));
        if self.pending == Some(delay) {
            core::future::pending::<()>().await;
        }
        self.now += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Err(Error::Unsupported)
    }
}
fn ready<T>(f: impl Future<Output = T>) -> Option<T> {
    let mut f = pin!(f);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
async fn execute(
    rf: &mut Rf,
    io: &mut Model,
    write: bool,
    path: u8,
    address: u32,
    mask: u32,
) -> Result<u32, Error> {
    if write {
        // SAFETY: complete exclusively owned B register model; no hardware,
        // DMA, other PHY/reset producer or outstanding transaction exists.
        unsafe { rf.write(io, path, address, mask, 0x789abc).await }.map(|()| 1)
    } else {
        // SAFETY: same complete private B register model and serialization.
        unsafe { rf.read(io, path, address, mask).await }
    }
}
fn smoke_rtw89_b_rf_transactions_match_frozen_references() -> TestResult {
    for &(write, seed, path, address, mask, value, trace) in CASES {
        let mut rf = Rf::default();
        let mut io = Model::new(seed);
        if ready(execute(&mut rf, &mut io, write, path, address, mask)) != Some(Ok(value))
            || io.trace != trace
            || rf.state() != State::Idle
        {
            return TestResult::Fail(
                "actual B SWSI/direct RF access differs from the frozen reference",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_rf_transactions_match_frozen_references
);

fn smoke_rtw89_b_rf_error_deadline_and_cancellation_never_replay() -> TestResult {
    for &(write, seed, path, address, mask, _, _) in CASES {
        let mut baseline = Model::new(seed);
        let mut rf = Rf::default();
        if !matches!(
            ready(execute(&mut rf, &mut baseline, write, path, address, mask)),
            Some(Ok(_))
        ) {
            return TestResult::Fail("RF baseline");
        }
        for fail in 0..baseline.operations {
            let mut rf = Rf::default();
            let mut io = Model::new(seed);
            io.fail = Some(fail);
            if ready(execute(&mut rf, &mut io, write, path, address, mask))
                != Some(Err(Error::Access))
                || rf.state() != State::Terminal
            {
                return TestResult::Fail("RF bus failure ignored");
            }
            let before = io.trace.clone();
            if ready(execute(&mut rf, &mut io, write, path, address, mask))
                != Some(Err(Error::Terminal))
                || io.trace != before
            {
                return TestResult::Fail("failed RF transaction replayed");
            }
        }
        for pending in 0..baseline.delays {
            let mut rf = Rf::default();
            let mut io = Model::new(seed);
            io.pending = Some(pending);
            if ready(execute(&mut rf, &mut io, write, path, address, mask)).is_some()
                || rf.state() != State::Busy
            {
                return TestResult::Fail("RF cancellation did not retain its busy transaction");
            }
            let before = io.trace.clone();
            if ready(execute(&mut rf, &mut io, write, path, address, mask))
                != Some(Err(Error::Terminal))
                || io.trace != before
            {
                return TestResult::Fail("cancelled RF transaction was reused");
            }
        }
    }
    for hold in 1..=3 {
        let mut rf = Rf::default();
        let mut io = Model::new(0);
        io.hold = hold;
        if ready(execute(&mut rf, &mut io, false, 0, 0x55, RF_MASK)) != Some(Err(Error::Timeout))
            || rf.state() != State::Terminal
            || io.now != if hold == 3 { 32 } else { 30 }
        {
            return TestResult::Fail("SWSI busy/done deadline differs from bounded Linux budget");
        }
    }
    for (path, address, mask) in [(2, 0x55, RF_MASK), (0, 0x20055, RF_MASK), (0, 0x55, 0)] {
        let mut rf = Rf::default();
        let mut io = Model::new(0);
        if ready(execute(&mut rf, &mut io, false, path, address, mask))
            != Some(Err(Error::Unsupported))
            || !io.trace.is_empty()
        {
            return TestResult::Fail("unsupported RF path/address/zero-mask touched hardware");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_rf_error_deadline_and_cancellation_never_replay
);

fn smoke_rtw89_b_rf_native_window_and_current_authority() -> TestResult {
    use super::super::{mac::ChipId, power_native::NativeIo};
    use narf_bus::{BusDeviceCap, MmioRegion};
    use narf_capabilities::{object_table, Cap, CapKind, CapSlot, Rights, Write};
    let (index, generation) = object_table::register(CapKind::BusDevice);
    // SAFETY: exact fresh model BusDevice/Write object; no ambient production
    // authority or real device is created by this fixture.
    let authority = unsafe {
        Cap::<BusDeviceCap, Write>::mint(CapSlot::new(
            generation,
            index,
            Write::BITS,
            CapKind::BusDevice as u32,
        ))
    };
    let mut words = vec![0u32; 0x20000 / 4];
    let mut region = MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 0x10000,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    // SAFETY: complete private aligned register RAM; the short advertised BAR
    // must reject RF before touching even its existing MAC-sized window.
    let short = unsafe { NativeIo::new(region, authority, ChipId::Rtl8852B, 0) }.unwrap();
    if short.b_phy_window() != Err(Error::Access) {
        return TestResult::Fail("MAC-sized BAR became RF aperture authority");
    }
    region.len = 0x20000;
    // SAFETY: same actual allocation covers the full B direct RF window.
    let mut io = unsafe { NativeIo::new(region, authority, ChipId::Rtl8852B, 0) }.unwrap();
    if io.b_phy_window() != Ok(()) {
        return TestResult::Fail("complete current B PHY window rejected");
    }
    words[0x1f154 / 4] = 0xabcde;
    let mut rf = Rf::default();
    // SAFETY: full current native B window proved above, exclusive inert RAM.
    if ready(unsafe { rf.read(&mut io, 1, 0x10055, 0xff00) }) != Some(Ok(0xbc)) {
        return TestResult::Fail("native RF did not use AX base plus actual path aperture");
    }
    authority.revoke();
    if io.b_phy_window() != Err(Error::Access) {
        return TestResult::Fail("revoked B PHY window accepted");
    }
    let before = words.clone();
    // SAFETY: revoked native capability must reject before any real register
    // read/write even though this private RF owner was previously usable.
    if ready(unsafe { rf.write(&mut io, 1, 0x10055, RF_MASK, 0x12345) }) != Some(Err(Error::Access))
        || rf.state() != State::Terminal
        || words != before
    {
        return TestResult::Fail("revoked RF transaction changed native BAR state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_rf_native_window_and_current_authority
);
