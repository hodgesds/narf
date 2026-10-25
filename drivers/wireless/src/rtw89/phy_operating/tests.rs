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
    xtal: [u8; 256],
    hash: u64,
    count: u32,
    accesses: usize,
    admissions: usize,
    deny: Option<usize>,
    ignore: Option<u32>,
    ignore_xtal: Option<u8>,
    pending: bool,
    permitted: bool,
}
impl Model {
    fn new(seed: u8) -> Self {
        Self {
            words: vec![u32::from(seed) * 0x01010101; 0x20000 / 4],
            xtal: [seed; 256],
            hash: 14695981039346656037,
            count: 0,
            accesses: 0,
            admissions: 0,
            deny: None,
            ignore: None,
            ignore_xtal: None,
            pending: false,
            permitted: false,
        }
    }
    fn access(&mut self) {
        assert!(
            self.permitted,
            "static PHY access bypassed current qualification"
        );
        self.permitted = false;
        self.accesses += 1;
    }
    fn record(&mut self, k: u32, a: u32, v: u32) {
        self.count += 1;
        for word in [k, a, v] {
            for byte in word.to_le_bytes() {
                self.hash ^= u64::from(byte);
                self.hash = self.hash.wrapping_mul(1099511628211);
            }
        }
    }
}
impl Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Unsupported)
    }
    fn read16(&mut self, _: u32) -> Result<u16, power::Error> {
        Err(power::Error::Unsupported)
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access();
        Ok(self.words[a as usize / 4])
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn write16(&mut self, _: u32, _: u16) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access();
        self.record(4, a, v);
        if self.ignore != Some(a) {
            self.words[a as usize / 4] = v;
        }
        Ok(())
    }
    fn now_us(&self) -> u64 {
        0
    }
    async fn delay_us(&mut self, _: u64) {}
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Interface for Model {
    fn admit(&mut self) -> Result<(), Error> {
        let n = self.admissions;
        self.admissions += 1;
        if self.deny == Some(n) {
            return Err(Error::Policy);
        }
        self.permitted = true;
        Ok(())
    }
    async fn xtal_write(&mut self, a: u8, v: u8, m: u8) -> Result<(), Error> {
        if self.pending {
            core::future::pending::<()>().await;
        }
        self.access();
        self.record(8, u32::from(a), u32::from(v));
        if self.ignore_xtal != Some(a) {
            self.xtal[usize::from(a)] = (self.xtal[usize::from(a)] & !m) | (v & m);
        }
        Ok(())
    }
    async fn xtal_read(&mut self, a: u8) -> Result<u8, Error> {
        self.access();
        let value = self.xtal[usize::from(a)];
        self.record(9, u32::from(a), u32::from(value));
        Ok(value)
    }
}
fn ready<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}
fn identity(cut: u8, xtal: u8) -> Identity {
    crate::rtw89::station_control::tests::factory_with_profile(cut, xtal, 5, false)
        .identity()
        .unwrap()
}
fn smoke_rtw8852b_static_phy_operating_matches_frozen_references_cut_and_crystal() -> TestResult {
    for &(seed, cut, xtal, count, hash, caps) in CASES {
        let mut model = Model::new(seed);
        let mut operating = Operating::default();
        let id = identity(cut, xtal);
        // SAFETY: isolated exact B PHY0/channel1/20/no-link source model;
        // the identity was earned through real factory sparse-map decoding.
        if ready(unsafe { operating.prepare(&mut model, id) }) != Some(Ok(()))
            || model.count != count
            || model.hash != hash
        {
            return TestResult::Fail(
                "B static PHYSTS/DIG/CFO/EDCCA writes differ from the frozen reference",
            );
        }
        let Some(state) = operating.working() else {
            return TestResult::Fail("source static PHY preparation lacks retained state");
        };
        if [state.crystal_cap, state.crystal_lower, state.crystal_upper] != caps
            || state.cut != cut
            || state.rfe != 5
            || state.cck_pd != (cut > 0)
        {
            return TestResult::Fail("actual factory/cut/crystal static PHY state differs");
        }
        let before = model.accesses;
        // SAFETY: isolated model; a replay must be rejected before access.
        if ready(unsafe { operating.prepare(&mut model, id) }) != Some(Err(Error::Terminal))
            || before != model.accesses
        {
            return TestResult::Fail("prepared static PHY owner replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/radio",
    smoke_rtw8852b_static_phy_operating_matches_frozen_references_cut_and_crystal
);
fn smoke_rtw8852b_static_phy_current_policy_ignored_writes_and_cancel_fail_closed() -> TestResult {
    let id = identity(1, 0x33);
    let mut baseline = Model::new(0);
    let mut operating = Operating::default();
    // SAFETY: isolated baseline records real source access frontiers.
    ready(unsafe { operating.prepare(&mut baseline, id) })
        .unwrap()
        .unwrap();
    for frontier in 0..baseline.admissions {
        let mut model = Model::new(0);
        model.deny = Some(frontier);
        let mut operating = Operating::default();
        // SAFETY: same isolated profile denies current policy at this step.
        if ready(unsafe { operating.prepare(&mut model, id) }) != Some(Err(Error::Policy))
            || operating.state() != State::Failed
            || operating.working().is_some()
        {
            return TestResult::Fail("static PHY bypassed a current policy/authority restriction");
        }
    }
    for lost in [
        0x10000 + R_PLCP_HISTOGRAM,
        0x10000 + R_PHY_STS_BITMAP_ADDR_START + 6 * 4,
        0x10000 + R_DCFO_OPT,
        R_AX_PWR_UL_CTRL2,
        0x10000 + R_TX_COLLISION_T2R_ST,
    ] {
        let mut model = Model::new(0);
        model.ignore = Some(lost);
        let mut operating = Operating::default();
        // SAFETY: isolated model drops an actual required register write.
        if ready(unsafe { operating.prepare(&mut model, id) })
            .unwrap()
            .is_ok()
            || operating.working().is_some()
        {
            return TestResult::Fail("ignored static PHY write fabricated operating state");
        }
    }
    for lost in [4, 5] {
        let mut model = Model::new(0);
        model.ignore_xtal = Some(lost);
        let mut operating = Operating::default();
        // SAFETY: isolated analog model drops one real XO/XI request.
        if ready(unsafe { operating.prepare(&mut model, id) }) != Some(Err(Error::Terminal))
            || operating.working().is_some()
        {
            return TestResult::Fail("ignored actual crystal request fabricated operating state");
        }
    }
    let mut model = Model::new(0);
    model.pending = true;
    let mut operating = Operating::default();
    {
        // SAFETY: isolated analog mailbox suspends at a real awaited request.
        let mut future = pin!(unsafe { operating.prepare(&mut model, id) });
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("static PHY cancel fixture missed actual analog await");
        }
    }
    let before = model.accesses;
    // SAFETY: same inert owner; cancellation forbids replay/access.
    let replay = ready(unsafe { operating.prepare(&mut model, id) });
    if replay != Some(Err(Error::Terminal))
        || operating.state() != State::Failed
        || operating.working().is_some()
        || before != model.accesses
    {
        return TestResult::Fail("cancelled static PHY owner replayed/published state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89/radio",
    smoke_rtw8852b_static_phy_current_policy_ignored_writes_and_cancel_fail_closed
);
