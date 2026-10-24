use super::*;
use crate::rtw89::factory::{Factory, Source};
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
struct Case {
    seed: u8,
    cut: u8,
    trace: &'static [(u8, u32, u32)],
}
include!("golden.rs");
struct Model {
    regs: Vec<u8>,
    trace: Vec<(u8, u32, u32)>,
    cut: u8,
    operations: usize,
    fail: Option<usize>,
    delay_edge: usize,
    pending: Option<usize>,
    now: u64,
    late: bool,
    stuck: Option<u32>,
    ignore: Option<u32>,
    seen: [usize; 6],
    active: [bool; 6],
}
impl Model {
    fn new(seed: u8, cut: u8) -> Self {
        let mut m = Self {
            regs: vec![seed; 65536],
            trace: Vec::new(),
            cut,
            operations: 0,
            fail: None,
            delay_edge: 0,
            pending: None,
            now: 0,
            late: false,
            stuck: None,
            ignore: None,
            seen: [0; 6],
            active: [false; 6],
        };
        m.store(0xa, 2, 32);
        m.store(0x1e0, 1, 0xe0);
        m.store(0x1010, 4, 0xb0f00);
        m.store(0x1000, 4, 1 << 11);
        m.store(0x8380, 4, 1);
        m
    }
    fn access(&mut self) -> Result<(), Error> {
        let n = self.operations;
        self.operations += 1;
        if self.fail == Some(n) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn raw(&self, a: u32, width: usize) -> u32 {
        let mut v = [0; 4];
        v[..width].copy_from_slice(&self.regs[a as usize..a as usize + width]);
        u32::from_le_bytes(v)
    }
    fn store(&mut self, a: u32, width: usize, v: u32) {
        self.regs[a as usize..a as usize + width].copy_from_slice(&v.to_le_bytes()[..width]);
    }
    fn settled(&mut self, index: usize, address: u32) -> bool {
        self.seen[index] += 1;
        self.stuck != Some(address) && (!self.late || self.seen[index] > 1)
    }
    fn read(&mut self, a: u32, width: usize) -> Result<u32, Error> {
        self.access()?;
        let mut v = self.raw(a, width);
        if width == 4 {
            if a == R_AX_WLAN_XTAL_SI_CTRL && self.active[0] && self.settled(0, a) {
                v &= !(1 << 31);
                self.store(a, 4, v);
                self.active[0] = false;
            }
            if a == R_AX_WDE_INI_STATUS {
                v = if self.settled(1, a) {
                    WDE_MGN_INI_RDY
                } else {
                    0
                };
            }
            if a == R_AX_PLE_INI_STATUS {
                v = if self.settled(2, a) {
                    PLE_MGN_INI_RDY
                } else {
                    0
                };
            }
            if a == R_AX_SS_CTRL && self.settled(3, a) {
                v |= B_AX_SS_INIT_DONE_1;
            }
            if a == R_AX_RESPBA_CAM_CTRL && self.active[5] && self.settled(5, a) {
                v &= !B_AX_BACAM_RST_MASK;
                self.store(a, 4, v);
                self.active[5] = false;
            }
            if a == R_AX_PUB_PAGE_INFO1 {
                v = 0;
            }
            if a == R_AX_PUB_PAGE_INFO2 {
                v = field(B_AX_PUB_AVAL_PG_MASK, 446);
            }
        }
        if width == 2 && a == R_AX_ADDR_CAM_CTRL && self.active[4] && self.settled(4, a) {
            v &= !B_AX_ADDR_CAM_CLR;
            self.store(a, 2, v);
            self.active[4] = false;
        }
        Ok(v)
    }
    fn write(&mut self, a: u32, width: usize, v: u32) -> Result<(), Error> {
        self.access()?;
        self.trace.push((width as u8, a, v));
        if self.ignore == Some(a) {
            return Ok(());
        }
        self.store(a, width, v);
        for (index, address, mask) in [
            (0, R_AX_WLAN_XTAL_SI_CTRL, 1 << 31),
            (4, R_AX_ADDR_CAM_CTRL, B_AX_ADDR_CAM_CLR),
            (5, R_AX_RESPBA_CAM_CTRL, B_AX_BACAM_RST_MASK),
        ] {
            if a == address && width == 4 && v & mask != 0 {
                self.active[index] = true;
                self.seen[index] = 0;
            }
        }
        Ok(())
    }
    fn setup(seed: u8, cut: u8) -> (Self, Factory) {
        let mut m = Self::new(seed, cut);
        let mut factory = Factory::default();
        assert_eq!(ready(factory.read(&mut m)), Some(Ok(())));
        m.operations = 0;
        m.trace.clear();
        (m, factory)
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, Error> {
        self.read(a, 1).map(|v| v as u8)
    }
    fn read16(&mut self, a: u32) -> Result<u16, Error> {
        self.read(a, 2).map(|v| v as u16)
    }
    fn read32(&mut self, a: u32) -> Result<u32, Error> {
        self.read(a, 4)
    }
    fn write8(&mut self, a: u32, v: u8) -> Result<(), Error> {
        self.write(a, 1, u32::from(v))
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), Error> {
        self.write(a, 2, u32::from(v))
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), Error> {
        self.write(a, 4, v)
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        let edge = self.delay_edge;
        self.delay_edge += 1;
        if self.pending == Some(edge) {
            core::future::pending::<()>().await;
        }
        self.trace.push((0, 0, us as u32));
        self.now += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, Error> {
        Err(Error::Unsupported)
    }
}
impl Source for Model {
    fn profile(&self) -> (ChipId, u8) {
        (ChipId::Rtl8852B, self.cut)
    }
    async fn physical(&mut self, start: u16, out: &mut [u8]) -> Result<(), Error> {
        out.fill(255);
        match (start, out.len()) {
            (0, 1216) => {
                let mut cursor = 4;
                for (offset, bytes) in [
                    (0x400, [2, 4]),
                    (0x402, [6, 8]),
                    (0x404, [10, 12]),
                    (0x2ca, [5, b'U']),
                    (0x2cc, [b'S', 255]),
                ] {
                    let block = offset / 8;
                    out[cursor] = (block >> 4) as u8;
                    out[cursor + 1] = ((block & 15) << 4) as u8 | (15 ^ (1 << ((offset % 8) / 2)));
                    out[cursor + 2..cursor + 4].copy_from_slice(&bytes);
                    cursor += 4;
                }
            }
            (0x580, 128) => (),
            _ => return Err(Error::Access),
        }
        Ok(())
    }
}
fn ready<F: Future>(future: F) -> Option<F::Output> {
    let mut f = pin!(future);
    match f.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_b_post_wcpu_mac_matches_original_linux_c() -> TestResult {
    for case in CASES {
        let (mut io, factory) = Model::setup(case.seed, case.cut);
        let mut mac = Mac::default();
        // SAFETY: inert single-owner register model supplies WCPU7, closed
        // packet/RX DMA and actual factory-source bytes; no native DMA exists.
        let result = ready(unsafe { mac.prepare(&mut io, &factory) });
        if result != Some(Ok(())) || mac.state() != State::Ready {
            return TestResult::Fail("B post-WCPU MAC did not reach confirmed Ready");
        }
        if io.trace != case.trace {
            return TestResult::Fail("B post-WCPU MAC differs from original Linux C trace");
        }
        if io.raw(0x1010, 4) != 0xb0f00
            || io.raw(0x1000, 4) & (1 << 13) != 0
            || io.raw(0x8380, 4) & 2 != 0
        {
            return TestResult::Fail("B MAC init activated unowned packet/RX DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_post_wcpu_mac_matches_original_linux_c
);
fn smoke_rtw89_b_post_wcpu_mac_failures_and_cancel_never_replay() -> TestResult {
    let (mut baseline, factory) = Model::setup(0, 1);
    baseline.late = true;
    let mut mac = Mac::default();
    // SAFETY: same inert exclusive model, with late readiness edges.
    if ready(unsafe { mac.prepare(&mut baseline, &factory) }) != Some(Ok(())) {
        return TestResult::Fail("B late MAC readiness fixture failed");
    }
    for failure in 0..baseline.operations {
        let (mut io, factory) = Model::setup(0, 1);
        io.late = true;
        io.fail = Some(failure);
        let mut mac = Mac::default();
        // SAFETY: fixture injects failure inside the same unpublished MAC owner.
        if ready(unsafe { mac.prepare(&mut io, &factory) }) == Some(Ok(()))
            || mac.state() != State::Preparing
        {
            return TestResult::Fail("failed B MAC access published Ready");
        }
        let before = io.operations;
        // SAFETY: a failed owner must reject replay before touching the model.
        if ready(unsafe { mac.prepare(&mut io, &factory) }) != Some(Err(Error::Terminal))
            || io.operations != before
        {
            return TestResult::Fail("failed B MAC owner replayed hardware changes");
        }
    }
    for edge in 0..baseline.delay_edge {
        let (mut io, factory) = Model::setup(0, 1);
        io.late = true;
        io.pending = Some(edge);
        let mut mac = Mac::default();
        // SAFETY: inert model suspends precisely this serialized hardware wait.
        if ready(unsafe { mac.prepare(&mut io, &factory) }).is_some()
            || mac.state() != State::Preparing
        {
            return TestResult::Fail("B MAC cancellation edge was not retained");
        }
        let before = io.operations;
        // SAFETY: dropped initialization cannot be resumed by a new call.
        if ready(unsafe { mac.prepare(&mut io, &factory) }) != Some(Err(Error::Terminal))
            || io.operations != before
        {
            return TestResult::Fail("cancelled B MAC owner replayed hardware changes");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_post_wcpu_mac_failures_and_cancel_never_replay
);
fn smoke_rtw89_b_post_wcpu_mac_requires_status_and_real_readiness() -> TestResult {
    for address in [
        R_AX_WLAN_XTAL_SI_CTRL,
        R_AX_WDE_INI_STATUS,
        R_AX_PLE_INI_STATUS,
        R_AX_SS_CTRL,
        R_AX_ADDR_CAM_CTRL,
        R_AX_RESPBA_CAM_CTRL,
    ] {
        let (mut io, factory) = Model::setup(0, 1);
        io.late = true;
        io.stuck = Some(address);
        let mut mac = Mac::default();
        // SAFETY: inert exclusive model with one permanently incomplete engine.
        if ready(unsafe { mac.prepare(&mut io, &factory) }) != Some(Err(Error::Timeout))
            || mac.state() != State::Preparing
        {
            return TestResult::Fail("B incomplete MAC controller became Ready");
        }
    }
    for address in [
        R_AX_DMAC_FUNC_EN,
        R_AX_CMAC_FUNC_EN,
        R_AX_HCI_FC_CTRL,
        R_AX_WDE_PKTBUF_CFG,
        R_AX_PLE_PKTBUF_CFG,
    ] {
        let (mut io, factory) = Model::setup(0, 1);
        io.ignore = Some(address);
        let mut mac = Mac::default();
        // SAFETY: inert model ignores a required write, with ordinary readback.
        if ready(unsafe { mac.prepare(&mut io, &factory) }) == Some(Ok(())) {
            return TestResult::Fail("B ignored MAC configuration write became Ready");
        }
    }
    for (address, width, value) in [
        (0x1e0, 1, 6 << 5),
        (0x1e0, 1, 255),
        (0x8380, 4, 3),
        (0x1000, 4, (1 << 11) | (1 << 13)),
        (0x1010, 4, 0),
    ] {
        let (mut io, factory) = Model::setup(0, 1);
        io.store(address, width, value);
        let mut mac = Mac::default();
        // SAFETY: these invalid prerequisite inputs must reject before BB writes.
        if ready(unsafe { mac.prepare(&mut io, &factory) }) == Some(Ok(())) || !io.trace.is_empty()
        {
            return TestResult::Fail("B unready WCPU/unowned RX reached MAC initialization");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_post_wcpu_mac_requires_status_and_real_readiness
);

fn smoke_rtw89_b_mac_uses_current_native_authority_before_register_access() -> TestResult {
    use narf_capabilities::{object_table, Cap, CapKind, CapSlot, Rights, Write};
    let (_, factory) = Model::setup(0, 1);
    let mut words = vec![0u32; 16384];
    let before = words.clone();
    let (index, generation) = object_table::register(CapKind::BusDevice);
    // SAFETY: new fixture object has exact BusDevice/Write type and rights.
    let authority: Cap<narf_bus::BusDeviceCap, Write> = unsafe {
        Cap::mint(CapSlot::new(
            generation,
            index,
            Write::BITS,
            CapKind::BusDevice as u32,
        ))
    };
    let region = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0),
        virt: words.as_mut_ptr() as u64,
        len: 65536,
        kind: narf_bus::BarKind::Mmio32 {
            prefetchable: false,
        },
    };
    // SAFETY: exclusively owned aligned RAM spans the full AX BAR aperture.
    let mut io = unsafe {
        super::super::power_native::NativeIo::new(region, authority, ChipId::Rtl8852B, 1)
    }
    .unwrap();
    authority.revoke();
    let mut mac = Mac::default();
    // SAFETY: revoked access must terminate before consulting any RAM register;
    // no actual device, packet DMA or concurrent producer exists in this test.
    if ready(unsafe { mac.prepare(&mut io, &factory) }) != Some(Err(Error::Access))
        || mac.state() != State::Preparing
        || words != before
    {
        return TestResult::Fail("B MAC accessed native BAR after capability revocation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_mac_uses_current_native_authority_before_register_access
);
