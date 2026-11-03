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
    chip: ChipId,
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
            chip: ChipId::Rtl8852B,
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
            // C V1 page block (never read on B).
            if self.chip == ChipId::Rtl8852C && a == c::R_AX_PUB_PAGE_INFO1_V1 {
                v = 0;
            }
            if self.chip == ChipId::Rtl8852C && a == c::R_AX_PUB_PAGE_INFO2_V1 {
                v = field(B_AX_PUB_AVAL_PG_MASK, c::PUB_MAX);
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
        Self::setup_chip(seed, cut, ChipId::Rtl8852B)
    }
    /// RTL8852C after its own CH12-only download: HAXI stops 0xbff00, TX
    /// init bit 7 only, `R_AX_HCI_FUNC_EN_V1` TX-only.
    fn setup_c(seed: u8, cut: u8) -> (Self, Factory) {
        Self::setup_chip(seed, cut, ChipId::Rtl8852C)
    }
    fn setup_chip(seed: u8, cut: u8, chip: ChipId) -> (Self, Factory) {
        let mut m = Self::new(seed, cut);
        m.chip = chip;
        if chip == ChipId::Rtl8852C {
            m.store(0x1010, 4, 0xbff00);
            m.store(0x1000, 4, 1 << 7);
            m.store(0x7880, 4, 1);
        }
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
        (self.chip, self.cut)
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
            (0x580, 128) if self.chip == ChipId::Rtl8852B => (),
            (0x590, 0x60) if self.chip == ChipId::Rtl8852C => (),
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
fn smoke_rtw89_b_post_wcpu_mac_matches_frozen_references() -> TestResult {
    for case in CASES {
        let (mut io, factory) = Model::setup(case.seed, case.cut);
        let mut mac = Mac::default();
        // SAFETY: inert single-owner register model supplies WCPU7, closed
        // packet/RX DMA and actual factory-source bytes; no native DMA exists.
        let result = ready(unsafe { mac.prepare(&mut io, &factory) });
        if result != Some(Ok(())) || mac.state() != State::Ready {
            return TestResult::Fail("B post-WCPU MAC did not reach confirmed Ready");
        }
        // Deliberate initial-profile deviation: retain the complete original
        // C stream, with only the independently named global CMAC TX gate
        // parked on each CMAC enable write. No transient autonomous TX enable.
        let expected: Vec<_> = case
            .trace
            .iter()
            .map(|&(width, address, value)| {
                (
                    width,
                    address,
                    if address == R_AX_CMAC_FUNC_EN {
                        value & !B_AX_CMAC_TXEN
                    } else {
                        value
                    },
                )
            })
            .collect();
        if io.trace != expected {
            return TestResult::Fail("B post-WCPU MAC differs from the frozen reference trace");
        }
        if io.raw(0x1010, 4) != 0xb0f00
            || io.raw(0x1000, 4) & (1 << 13) != 0
            || io.raw(0x8380, 4) & 2 != 0
            || io.raw(R_AX_CMAC_FUNC_EN, 4) & B_AX_CMAC_TXEN != 0
            || io
                .trace
                .iter()
                .any(|&(_, a, v)| a == R_AX_CMAC_FUNC_EN && v & B_AX_CMAC_TXEN != 0)
        {
            return TestResult::Fail("B MAC init activated unowned packet/RX DMA");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_b_post_wcpu_mac_matches_frozen_references
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

fn c_writes(io: &Model, address: u32) -> Vec<u32> {
    io.trace
        .iter()
        .filter(|&&(width, a, _)| width != 0 && a == address)
        .map(|&(_, _, v)| v)
        .collect()
}
fn smoke_rtw8852c_post_wcpu_mac_follows_linux_c_branches() -> TestResult {
    let (mut io, factory) = Model::setup_c(0, 0);
    let mut mac = Mac::default();
    // SAFETY: inert single-owner C register model with WCPU7, the C HAXI
    // download geometry and actual factory-source bytes; no native DMA.
    if ready(unsafe { mac.prepare(&mut io, &factory) }) != Some(Ok(()))
        || mac.state() != State::Ready
    {
        return TestResult::Fail("C post-WCPU MAC did not reach confirmed Ready");
    }
    // rtw8852c_mac_enable_bb_rf: XTAL0 7, ANAPAR_WL 0x6c, RFC S0/S1 0xc7,
    // XTAL3 0xd, in order; LDO VSEL S0/S1 = 1; no 885xB PHYREG_SET/ZCDC.
    let xtal: Vec<_> = c_writes(&io, R_AX_WLAN_XTAL_SI_CTRL)
        .iter()
        .map(|v| v & 0xffff)
        .collect();
    if xtal != [0x0700, 0x6c90, 0xc780, 0xc781, 0x0d03]
        || io.raw(c::R_AX_AFE_OFF_CTRL1, 4)
            & (c::B_AX_S0_LDO_VSEL_F_MASK | c::B_AX_S1_LDO_VSEL_F_MASK)
            != field(c::B_AX_S0_LDO_VSEL_F_MASK, 1) | field(c::B_AX_S1_LDO_VSEL_F_MASK, 1)
        || !c_writes(&io, R_AX_PHYREG_SET).is_empty()
    {
        return TestResult::Fail("C enable_bb_rf differs from rtw8852c_mac_enable_bb_rf");
    }
    // dmac_func_en_ax C value with H_AXIDMA; CMAC TX parked.
    if c_writes(&io, R_AX_DMAC_FUNC_EN).first() != Some(&c::c_dmac_functions())
        || io.raw(R_AX_CMAC_FUNC_EN, 4) & B_AX_CMAC_TXEN != 0
        || io
            .trace
            .iter()
            .any(|&(_, a, v)| a == R_AX_CMAC_FUNC_EN && v & B_AX_CMAC_TXEN != 0)
    {
        return TestResult::Fail("C sys_init differs or published CMAC TX");
    }
    // rtw8852c_dle_mem_pcie SCC: WDE 3328 x 64B, PLE 1904 x 128B bound 26,
    // wde_qt18, ple_qt46/qt47 incl. the C-only tx_rpt quota 11.
    let get = |v: u32, m: u32| (v & m) >> m.trailing_zeros();
    let wde = io.raw(R_AX_WDE_PKTBUF_CFG, 4);
    let ple = io.raw(R_AX_PLE_PKTBUF_CFG, 4);
    if get(wde, B_AX_WDE_FREE_PAGE_NUM_MASK) != 3328
        || get(wde, B_AX_WDE_PAGE_SEL_MASK) != 0
        || get(ple, B_AX_PLE_FREE_PAGE_NUM_MASK) != 1904
        || get(ple, B_AX_PLE_START_BOUND_MASK) != 26
        || get(ple, B_AX_PLE_PAGE_SEL_MASK) != 1
        || io.raw(R_AX_WDE_QTA0_CFG, 4) != 3228 << 16 | 3228
        || io.raw(R_AX_WDE_QTA4_CFG, 4) != 40 << 16 | 40
        || io.raw(R_AX_PLE_QTA0_CFG + 6 * 4, 4) != 1199 << 16 | 178
        || io.raw(R_AX_PLE_QTA0_CFG + 11 * 4, 4) != 1037 << 16 | 16
    {
        return TestResult::Fail("C DLE quotas differ from rtw8852c_dle_mem_pcie");
    }
    // HFC on the V1 page block only; groups per rtw8852c_hfc_chcfg_pcie.
    for channel in 0..12u32 {
        let group = if [4, 5, 6, 7, 10, 11].contains(&channel) {
            c::B_AX_GRP
        } else {
            0
        };
        if c_writes(&io, c::R_AX_ACH0_PAGE_CTRL_V1 + channel * 4) != [1614 << 16 | 13 | group] {
            return TestResult::Fail("C HFC channel config differs from rtw8852c_hfc_chcfg_pcie");
        }
    }
    if io.raw(c::R_AX_PUB_PAGE_CTRL1_V1, 4) != 1614 << 16 | 1614
        || io.raw(c::R_AX_PUB_PAGE_CTRL2_V1, 4) != 3228
        || io.raw(c::R_AX_CH_PAGE_CTRL_V1, 4) != 40 << 16 | 2
        || io.raw(c::R_AX_HCI_FC_CTRL_V1, 4) & (B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN)
            != B_AX_HCI_FC_EN | B_AX_HCI_FC_CH12_EN
        || io
            .trace
            .iter()
            .any(|&(width, a, _)| width != 0 && (0x8a00..=0x8aa8).contains(&a))
    {
        return TestResult::Fail("C HFC touched the B page block or misprogrammed V1");
    }
    // Preload, SS2F path, security UC_MGNT + TX timeout, C SIFS/RRSR/RX len.
    if get(
        io.raw(c::R_AX_TXPKTCTL_B0_PRELD_CFG0, 4),
        c::B_AX_B0_PRELD_USEMAXSZ_MASK,
    ) != 520
        || io.raw(c::R_AX_TXPKTCTL_B0_PRELD_CFG0, 4) & c::B_AX_B0_PRELD_FEN == 0
        || io.raw(c::R_AX_TXPKTCTL_B0_PRELD_CFG1, 4) & 0xfff != 0x134
        || get(io.raw(c::R_AX_SS2FINFO_PATH, 4), c::B_AX_SS_DEST_QUEUE_MASK) != 0x0a
        || io.raw(R_AX_SEC_ENG_CTRL, 4) & c::B_AX_UC_MGNT_DEC == 0
        || get(io.raw(c::R_AX_SEC_DEBUG1, 4), c::B_AX_TX_TIMEOUT_SEL_MASK) != 2
        || get(io.raw(R_AX_PREBKF_CFG_1, 4), B_AX_SIFS_MACTXEN_T1_MASK) != 0x41
        || get(io.raw(c::R_AX_PTCL_RRSR1, 4), c::B_AX_RSC_MASK) != 2
        || get(io.raw(R_AX_RX_FLTR_OPT, 4), B_AX_RX_MPDU_MAX_LEN_MASK) != 23
        || !c_writes(&io, R_AX_AGG_LEN_VHT_0).is_empty()
        || !c_writes(&io, R_AX_SCH_EXT_CTRL).is_empty()
    {
        return TestResult::Fail("C DMAC/CMAC branches differ from mac.c");
    }
    // 8852C _patch_dis_resp_chk sets the checks; trx_init_ax then clears
    // the static RTS BW check last.
    let rsp = io.raw(R_AX_RSP_CHK_SIG, 4);
    if rsp & (B_AX_RSP_CHK_TXNAV | B_AX_RSP_CHK_INTRA_NAV | B_AX_RSP_CHK_BASIC_NAV)
        != B_AX_RSP_CHK_TXNAV | B_AX_RSP_CHK_INTRA_NAV | B_AX_RSP_CHK_BASIC_NAV
        || rsp & c::B_AX_RSP_STATIC_RTS_CHK_SERV_BW_EN != 0
        || io
            .trace
            .iter()
            .rev()
            .find(|&&(w, _, _)| w != 0)
            .map(|&(_, a, _)| a)
            != Some(R_AX_RSP_CHK_SIG)
    {
        return TestResult::Fail("C response checks differ from mac.c");
    }
    // rtw8852c_imr_info: V1 registers set, B-only IMR registers untouched.
    for (reg, set) in [
        (c::R_AX_SEC_ERROR_FLAG_IMR, 3),
        (R_AX_MPDU_TX_ERR_IMR, c::B_AX_MPDU_TX_IMR_SET_V1),
        (
            c::R_AX_TXPKTCTL_B1_ERRFLAG_IMR,
            c::B_AX_TXPKTCTL_IMR_B1_SET_V1,
        ),
        (R_AX_OTHER_DISPATCHER_ERR_IMR, c::B_AX_OTHER_DISP_IMR_SET_V1),
        (c::R_AX_TX_ERR_FLAG_IMR, c::B_AX_TX_ERR_IMR_SET_V1),
        (c::R_AX_TRXPTCL_ERROR_INDICA_MASK, c::B_AX_TMAC_IMR_SET_V1),
    ] {
        if io.raw(reg, 4) & set != set {
            return TestResult::Fail("C IMR differs from rtw8852c_imr_info");
        }
    }
    if io.raw(c::R_AX_TRXPTCL_ERROR_INDICA_MASK, 4)
        & (c::B_AX_TMAC_IMR_CLR_V1 & !c::B_AX_TMAC_IMR_SET_V1)
        != 0
        || [
            R_AX_TXPKTCTL_ERR_IMR_ISR,
            R_AX_DLE_CTRL,
            R_AX_RMAC_ERR_ISR,
            R_AX_TMAC_ERR_IMR_ISR,
        ]
        .iter()
        .any(|&reg| !c_writes(&io, reg).is_empty())
    {
        return TestResult::Fail("C IMR wrote a B-only register");
    }
    if io.raw(0x1010, 4) != 0xbff00
        || io.raw(0x1000, 4) & (1 << 15) != 0
        || io.raw(0x7880, 4) & 2 != 0
    {
        return TestResult::Fail("C MAC init activated unowned packet/RX DMA");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_post_wcpu_mac_follows_linux_c_branches
);
fn smoke_rtw8852c_post_wcpu_mac_requires_c_geometry_and_readiness() -> TestResult {
    // A C device presenting B's download geometry (RX init bit 15 set, or
    // the C HCI RX layer enabled) is refused before any write.
    for (address, value) in [
        (0x1000, (1 << 7) | (1 << 15)),
        (0x7880, 3),
        (0x1010, 0xb0f00),
    ] {
        let (mut io, factory) = Model::setup_c(0, 0);
        io.store(address, 4, value);
        let mut mac = Mac::default();
        // SAFETY: invalid prerequisite inputs must reject before BB writes.
        if ready(unsafe { mac.prepare(&mut io, &factory) }) == Some(Ok(())) || !io.trace.is_empty()
        {
            return TestResult::Fail("C unowned RX/stop geometry reached MAC initialization");
        }
    }
    for address in [
        R_AX_WLAN_XTAL_SI_CTRL,
        R_AX_WDE_INI_STATUS,
        R_AX_PLE_INI_STATUS,
        R_AX_SS_CTRL,
        R_AX_ADDR_CAM_CTRL,
        R_AX_RESPBA_CAM_CTRL,
    ] {
        let (mut io, factory) = Model::setup_c(0, 0);
        io.late = true;
        io.stuck = Some(address);
        let mut mac = Mac::default();
        // SAFETY: inert exclusive model with one permanently incomplete engine.
        if ready(unsafe { mac.prepare(&mut io, &factory) }) != Some(Err(Error::Timeout))
            || mac.state() != State::Preparing
        {
            return TestResult::Fail("C incomplete MAC controller became Ready");
        }
    }
    for address in [
        R_AX_DMAC_FUNC_EN,
        R_AX_CMAC_FUNC_EN,
        c::R_AX_HCI_FC_CTRL_V1,
        R_AX_WDE_PKTBUF_CFG,
        R_AX_PLE_PKTBUF_CFG,
    ] {
        let (mut io, factory) = Model::setup_c(0, 0);
        io.ignore = Some(address);
        let mut mac = Mac::default();
        // SAFETY: inert model ignores a required write, with ordinary readback.
        if ready(unsafe { mac.prepare(&mut io, &factory) }) == Some(Ok(())) {
            return TestResult::Fail("C ignored MAC configuration write became Ready");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_post_wcpu_mac_requires_c_geometry_and_readiness
);
