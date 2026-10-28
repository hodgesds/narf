//! HAL SRNG + DP descriptor-layout tests.
//!
//! Every expected value is hand-derived from Linux
//! `drivers/net/wireless/ath/ath11k/{hal.c,hal.h,hal_desc.h,rx_desc.h,hw.c}`
//! for WCN6855 (`wcn6855_regs`), not from the code under test. Register
//! programming is replayed against [`RecIo`], a recording [`ChipIo`].

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::mem::size_of;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::dp::*;
use super::hal::*;
use super::hw::*;
use super::power::ChipIo;

macro_rules! check {
    ($cond:expr, $msg:literal) => {
        if !($cond) {
            return TestResult::Fail($msg);
        }
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    R(u32),
    W(u32, u32),
}

/// Register file that records every access.
#[derive(Debug, Default)]
pub struct RecIo {
    pub regs: RefCell<BTreeMap<u32, u32>>,
    pub ops: RefCell<Vec<Op>>,
}

impl RecIo {
    pub fn ops(&self) -> Vec<Op> {
        self.ops.borrow().clone()
    }
    pub fn clear(&self) {
        self.ops.borrow_mut().clear();
    }
    pub fn reg(&self, off: u32) -> u32 {
        *self.regs.borrow().get(&off).unwrap_or(&0)
    }
}

impl ChipIo for RecIo {
    fn read32(&self, offset: u32) -> u32 {
        self.ops.borrow_mut().push(Op::R(offset));
        self.reg(offset)
    }
    fn write32(&self, offset: u32, value: u32) {
        self.ops.borrow_mut().push(Op::W(offset, value));
        self.regs.borrow_mut().insert(offset, value);
    }
    fn delay_ms(&self, _ms: u32) {}
    fn restore_window(&self) {}
}

pub fn wcn6855() -> HwParams {
    HwRev::Wcn6855Hw21.params().expect("WCN6855 HW2.1 params")
}

fn ring(entries: u32, entry_words: u32) -> DmaMem {
    DmaMem::alloc((entries * entry_words * 4) as usize, HAL_RING_BASE_ALIGN).expect("ring memory")
}

// ── hw_params ─────────────────────────────────────────────────────

fn smoke_ath11k_hal_hw_params_wcn6855() -> TestResult {
    let p = wcn6855();
    check!(
        p.regs == Some(&WCN6855_REGS),
        "WCN6855 must use wcn6855_regs"
    );
    check!(p.ce_count() == 9, "WCN6855 ce_count is 9");
    check!(
        p.supports_shadow_regs,
        "WCN6855 supports_shadow_regs = true"
    );
    check!(p.credit_flow, "WCN6855 credit_flow = true");
    check!(
        WCN6855_REGS.hal_shadow_base_addr == 0x8fc,
        "wcn6855 hal_shadow_base_addr is 0x8fc"
    );
    check!(
        WCN6855_REGS.hal_seq_wcss_umac_ce0_src_reg == 0x01b8_0000
            && WCN6855_REGS.hal_seq_wcss_umac_ce1_dst_reg == 0x01b8_3000,
        "wcn6855 CE register blocks"
    );
    // ath11k_hw_ring_mask_qca6390: designated initialisers.
    let m = p.ring_mask;
    check!(
        m.tx[0] == 1 && m.tx[1..].iter().all(|&v| v == 0),
        "ring_mask.tx"
    );
    check!(
        m.rx[7] == 1
            && m.rx[8] == 2
            && m.rx[9] == 4
            && m.rx[10] == 8
            && m.rx[..7].iter().all(|&v| v == 0),
        "ring_mask.rx"
    );
    check!(
        m.rx_mon_status[4..7] == [1, 2, 4],
        "ring_mask.rx_mon_status"
    );
    check!(m.rxdma2host[..3] == [1, 2, 4], "ring_mask.rxdma2host");
    check!(
        m.host2rxdma.iter().all(|&v| v == 0),
        "ring_mask.host2rxdma is empty"
    );
    for rev in [HwRev::Wcn6855Hw20, HwRev::Qca2066Hw21, HwRev::Qca6698aqHw21] {
        let q = rev.params().unwrap();
        check!(
            q.regs == Some(&WCN6855_REGS) && q.ce_count() == 9 && q.supports_shadow_regs,
            "WCN6855 family shares wcn6855_regs + qca6390 CE config"
        );
    }
    let qcn = HwRev::Qcn9074Hw10.params().unwrap();
    check!(
        qcn.regs.is_some() && !qcn.supports_shadow_regs && qcn.ce_count() == 6,
        "QCN9074: qcn9074_regs, no shadow regs, 6 CEs"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_hal_hw_params_wcn6855
);

// ── srng config ───────────────────────────────────────────────────

/// (type, start id, max rings, entry words, reg_start, reg_size, lmac,
/// dir, max_size)
type Golden = (
    HalRingType,
    u32,
    u16,
    u16,
    [u32; 2],
    [u16; 2],
    bool,
    SrngDir,
    u32,
);

fn smoke_ath11k_hal_srng_config_wcn6855() -> TestResult {
    use HalRingType as T;
    use SrngDir::{Dst, Src};
    let c = create_config(&WCN6855_REGS);
    // (type, start id, max rings, entry words, reg_start, reg_size, lmac, dir, max_size)
    // reg_start = UMAC block + wcn6855_regs offset; strides = ring2 - ring1.
    #[rustfmt::skip]
    let golden: [Golden; 21] = [
        (T::ReoDst,        0, 4,  16, [0x00a3_8244, 0x00a3_b030], [0x58, 8], false, Dst, 0xfffff),
        (T::ReoException,  4, 1,  16, [0x00a3_8454, 0x00a3_b060], [0, 0], false, Dst, 0xfffff),
        (T::ReoReinject,   5, 1,   8, [0x00a3_81ec, 0x00a3_b028], [0, 0], false, Src, 0xffff),
        (T::ReoCmd,        8, 1,  10, [0x00a3_8194, 0x00a3_b020], [0, 0], false, Src, 0xffff),
        (T::ReoStatus,     9, 1,  26, [0x00a3_855c, 0x00a3_b078], [0, 0], false, Dst, 0xffff),
        (T::TclData,      16, 3,   8, [0x00a4_4690, 0x00a4_6000], [0x58, 8], false, Src, 0xfffff),
        (T::TclCmd,       24, 1,   8, [0x00a4_4798, 0x00a4_6018], [0, 0], false, Src, 0xfffff),
        (T::TclStatus,    25, 1,   9, [0x00a4_48a0, 0x00a4_6030], [0, 0], false, Dst, 0xffff),
        (T::CeSrc,        32, 12,  4, [0x01b8_0000, 0x01b8_0400], [0x2000, 0x2000], false, Src, 0xffff),
        (T::CeDst,        56, 12,  2, [0x01b8_1000, 0x01b8_1400], [0x2000, 0x2000], false, Src, 0xffff),
        (T::CeDstStatus,  80, 12,  4, [0x01b8_1058, 0x01b8_1408], [0x2000, 0x2000], false, Dst, 0xffff),
        (T::WbmIdleLink, 104, 1,   2, [0x00a3_4870, 0x00a3_70b0], [0, 0], false, Src, 0xffff),
        (T::Sw2WbmRelease, 105, 1, 8, [0x00a3_41e8, 0x00a3_7018], [0, 0], false, Src, 0xffff),
        (T::Wbm2SwRelease, 106, 5, 8, [0x00a3_4920, 0x00a3_70c0], [0x58, 8], false, Dst, 0xfffff),
        (T::RxdmaBuf,          128, 2, 2, [0, 0], [0, 0], true, Src, 0xffff),
        (T::RxdmaDst,          133, 1, 8, [0, 0], [0, 0], true, Dst, 0xffff),
        (T::RxdmaMonitorBuf,   130, 1, 2, [0, 0], [0, 0], true, Src, 0xffff),
        (T::RxdmaMonitorStatus, 132, 1, 2, [0, 0], [0, 0], true, Src, 0xffff),
        (T::RxdmaMonitorDst,   134, 1, 8, [0, 0], [0, 0], true, Dst, 0xffff),
        (T::RxdmaMonitorDesc,  135, 1, 2, [0, 0], [0, 0], true, Src, 0xffff),
        (T::RxdmaDirBuf,       136, 2, 2, [0, 0], [0, 0], true, Src, 0xffff),
    ];
    for (ty, start, max_rings, es, rs, rz, lmac, dir, max_size) in golden {
        let s = &c[ty.idx()];
        if s.start_ring_id != start
            || s.max_rings != max_rings
            || s.entry_size != es
            || s.reg_start != rs
            || s.reg_size != rz
            || s.lmac_ring != lmac
            || s.ring_dir != dir
            || s.max_size != max_size
        {
            return TestResult::Fail("srng config differs from Linux create_config for WCN6855");
        }
    }
    check!(
        HAL_SRNG_RING_ID_MAX == 172,
        "HAL_SRNG_RING_ID_MAX = 127 + 3 * 15"
    );
    check!(
        HAL_SRNG_NUM_LMAC_RINGS == 45,
        "HAL_SRNG_NUM_LMAC_RINGS = 45"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_hal_srng_config_wcn6855
);

// ── shadow registers v2 ───────────────────────────────────────────

/// The WCN6855 shadow v2 list Linux sends in QMI WLAN_CFG, derived by
/// hand: `reg_start[1] + reg_size[1] * ring_num`, `+ 4` (TP) for DST
/// rings; non-CE rings first in enum order, then per CE src, dst,
/// dst-status for the CEs with entries.
#[rustfmt::skip]
pub const WCN6855_SHADOW_REG_V2: [u32; 30] = [
    // REO2SW1..4 TP (DST): 0xa3b030 + 8n + 4
    0x00a3_b034, 0x00a3_b03c, 0x00a3_b044, 0x00a3_b04c,
    // REO2TCL TP (DST): 0xa3b060 + 4
    0x00a3_b064,
    // SW2REO HP (SRC)
    0x00a3_b028,
    // REO_CMD HP (SRC)
    0x00a3_b020,
    // REO_STATUS TP (DST): 0xa3b078 + 4
    0x00a3_b07c,
    // SW2TCL1..3 HP (SRC): 0xa46000 + 8n
    0x00a4_6000, 0x00a4_6008, 0x00a4_6010,
    // SW2TCL_CMD HP
    0x00a4_6018,
    // TCL_STATUS TP: 0xa46030 + 4
    0x00a4_6034,
    // WBM_IDLE_LINK HP
    0x00a3_70b0,
    // SW2WBM_RELEASE HP
    0x00a3_7018,
    // WBM2SW0..4 TP: 0xa370c0 + 8n + 4
    0x00a3_70c4, 0x00a3_70cc, 0x00a3_70d4, 0x00a3_70dc, 0x00a3_70e4,
    // CE0 src HP: 0x1b80400
    0x01b8_0400,
    // CE1 dst HP (CE_DST is a SRC ring), dst-status TP: 0x1b81400/0x1b81408 + 0x2000, +4
    0x01b8_3400, 0x01b8_340c,
    // CE2
    0x01b8_5400, 0x01b8_540c,
    // CE3 src, CE4 src
    0x01b8_6400, 0x01b8_8400,
    // CE5 dst, dst-status
    0x01b8_b400, 0x01b8_b40c,
    // CE7 src (CE6 / CE8 have no rings)
    0x01b8_e400,
];

// Literal qca6390_regs shadow list from local Linux hal.c/hw.c.
pub const QCA6390_SHADOW_REG_V2: [u32; 30] = [
    // REO2SW1..4 TP (DST): 0xa3b030 + 8n + 4
    0x00a3_b034,
    0x00a3_b03c,
    0x00a3_b044,
    0x00a3_b04c,
    // REO2TCL TP (DST): 0xa3b050 + 4
    0x00a3_b054,
    // SW2REO HP (SRC)
    0x00a3_b028,
    // REO_CMD HP (SRC)
    0x00a3_b020,
    // REO_STATUS TP (DST): 0xa3b068 + 4
    0x00a3_b06c,
    // SW2TCL1..3 HP (SRC): 0xa46000 + 8n
    0x00a4_6000,
    0x00a4_6008,
    0x00a4_6010,
    // SW2TCL_CMD HP
    0x00a4_6018,
    // TCL_STATUS TP: 0xa46030 + 4
    0x00a4_6034,
    // WBM_IDLE_LINK HP
    0x00a3_70b0,
    // SW2WBM_RELEASE HP
    0x00a3_7018,
    // WBM2SW0..4 TP: 0xa370c0 + 8n + 4
    0x00a3_70c4,
    0x00a3_70cc,
    0x00a3_70d4,
    0x00a3_70dc,
    0x00a3_70e4,
    // CE0 src HP: 0xa00400
    0x00a0_0400,
    // CE1 dst HP (CE_DST is a SRC ring), dst-status TP: 0xa01400/0xa01408 + 0x2000, +4
    0x00a0_3400,
    0x00a0_340c,
    // CE2
    0x00a0_5400,
    0x00a0_540c,
    // CE3 src, CE4 src
    0x00a0_6400,
    0x00a0_8400,
    // CE5 dst, dst-status
    0x00a0_b400,
    0x00a0_b40c,
    // CE7 src (CE6 / CE8 have no rings)
    0x00a0_e400,
];

fn smoke_ath11k_hal_shadow_reg_v2_wcn6855_golden() -> TestResult {
    let hw = wcn6855();
    let s = match shadow_reg_v2(&hw) {
        Some(s) => s,
        None => return TestResult::Fail("WCN6855 must produce a shadow v2 list"),
    };
    check!(
        s.as_slice() == WCN6855_SHADOW_REG_V2,
        "shadow v2 list differs from Linux"
    );
    check!(
        s.len() <= HAL_SHADOW_NUM_REGS,
        "list fits QMI_WLANFW_MAX_NUM_SHADOW_REG_V2 (36)"
    );
    // Which ring each shadow register serves (update_hp_tp_addr).
    check!(
        s.ring_of(0) == Some((HalRingType::ReoDst, 0))
            && s.ring_of(20) == Some((HalRingType::CeSrc, 0))
            && s.ring_of(22) == Some((HalRingType::CeDstStatus, 1))
            && s.ring_of(29) == Some((HalRingType::CeSrc, 7))
            && s.ring_of(30).is_none(),
        "shadow slot → ring mapping"
    );
    check!(
        s.slot_of(HalRingType::CeSrc, 4) == Some(26) && s.slot_of(HalRingType::CeSrc, 6).is_none(),
        "CE4 src in slot 26, CE6 has none"
    );
    // HAL_SHADOW_REG(ab, x) = 0x8fc + 4x (direct BAR0, below the window).
    check!(shadow_reg(&WCN6855_REGS, 0) == 0x8fc, "shadow reg 0");
    check!(
        shadow_reg(&WCN6855_REGS, 20) == 0x94c,
        "shadow reg 20 (CE0 src)"
    );
    check!(
        shadow_reg(&WCN6855_REGS, 29) == 0x970,
        "shadow reg 29 (CE7 src)"
    );
    check!(
        shadow_reg(&WCN6855_REGS, 35) < ATH11K_PCI_WINDOW_START,
        "all shadow registers are direct BAR0"
    );
    // The HAL computes the same list at init.
    let hal = match Hal::new(&hw) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("Hal::new failed"),
    };
    check!(
        hal.shadow_reg_v2() == WCN6855_SHADOW_REG_V2,
        "Hal shadow list != shadow_reg_v2()"
    );
    // Same for the rest of the family and QCA6390 (same CE config,
    // regs differ only in TCL/REO2TCL/REO_STATUS offsets).
    for rev in [HwRev::Wcn6855Hw20, HwRev::Qca2066Hw21, HwRev::Qca6698aqHw21] {
        let q = shadow_reg_v2(&rev.params().unwrap()).unwrap();
        check!(
            q.as_slice() == WCN6855_SHADOW_REG_V2,
            "WCN6855 family shadow list"
        );
    }
    let q = shadow_reg_v2(&HwRev::Qca6390Hw20.params().unwrap()).unwrap();
    check!(
        q.len() == 30 && q.as_slice()[4] == 0x00a3_b054 && q.as_slice()[20] == 0x00a0_0400,
        "QCA6390: REO2TCL TP 0xa3b050+4, CE0 src HP 0xa00400"
    );
    // Negative: no shadow registers → no list (shadow_reg_v2_valid = 0).
    check!(
        shadow_reg_v2(&HwRev::Qcn9074Hw10.params().unwrap()).is_none(),
        "QCN9074 has no shadow v2 list"
    );
    let mut no_shadow = hw;
    no_shadow.supports_shadow_regs = false;
    check!(
        shadow_reg_v2(&no_shadow).is_none(),
        "supports_shadow_regs = false → None"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_hal_shadow_reg_v2_wcn6855_golden
);

fn smoke_ath11k_hal_shadow_table_full() -> TestResult {
    let c = create_config(&WCN6855_REGS);
    let mut s = ShadowConfig::default();
    for i in 0..HAL_SHADOW_NUM_REGS {
        if s.update(&c, HalRingType::CeSrc, (i % 12) as u32) != Ok(i) {
            return TestResult::Fail("first 36 shadow slots must be granted in order");
        }
    }
    match s.update(&c, HalRingType::TclData, 2) {
        Err(e) => {
            check!(e.step == step::SHADOW_FULL, "37th slot: SHADOW_FULL");
            check!(e.detail == (5 << 16) | 2, "detail = type << 16 | ring_num");
            check!(e.errno == errno::EINVAL, "-EINVAL like Linux");
        }
        Ok(_) => return TestResult::Fail("37th shadow slot must be refused"),
    }
    check!(
        s.len() == HAL_SHADOW_NUM_REGS,
        "a refused update must not grow the table"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_hal_shadow_table_full
);

// ── ring ids ──────────────────────────────────────────────────────

fn smoke_ath11k_hal_ring_ids() -> TestResult {
    let c = create_config(&WCN6855_REGS);
    check!(
        get_ring_id(&c, HalRingType::CeSrc, 11, 0) == Ok(43),
        "CE11 src = 43"
    );
    check!(
        get_ring_id(&c, HalRingType::CeDstStatus, 0, 0) == Ok(80),
        "CE0 status = 80"
    );
    check!(
        get_ring_id(&c, HalRingType::Wbm2SwRelease, 4, 0) == Ok(110),
        "WBM2SW4 = 110"
    );
    // LMAC rings: + mac_id * HAL_SRNG_RINGS_PER_LMAC (15).
    check!(
        get_ring_id(&c, HalRingType::RxdmaBuf, 0, 1) == Ok(143),
        "RXDMA_BUF mac1 = 143"
    );
    check!(
        get_ring_id(&c, HalRingType::RxdmaDirBuf, 1, 2) == Ok(167),
        "DIR_BUF ring1 mac2 = 167"
    );
    // UMAC rings ignore mac_id.
    check!(
        get_ring_id(&c, HalRingType::TclData, 1, 2) == Ok(17),
        "SW2TCL2 = 17"
    );
    match get_ring_id(&c, HalRingType::CeSrc, 12, 0) {
        Err(e) => check!(
            e.step == step::BAD_RING_NUM && e.detail == (8 << 16) | 12 && e.errno == errno::EINVAL,
            "ring_num >= max_rings: BAD_RING_NUM, -EINVAL"
        ),
        Ok(_) => return TestResult::Fail("CE ring 12 must be refused"),
    }
    match get_ring_id(&c, HalRingType::RxdmaDirBuf, 1, 3) {
        Err(e) => check!(
            e.step == step::RING_ID_RANGE && e.detail == 182,
            "ring id >= HAL_SRNG_RING_ID_MAX: RING_ID_RANGE"
        ),
        Ok(_) => return TestResult::Fail("ring id 182 must be refused"),
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_hal_ring_ids);

// ── srng_setup golden (DP rings) ──────────────────────────────────

fn smoke_ath11k_hal_srng_setup_dp_golden() -> TestResult {
    use Op::W;
    let mut hal = match Hal::new(&wcn6855()) {
        Ok(h) => h,
        Err(_) => return TestResult::Fail("Hal::new failed"),
    };
    let rdp = hal.rdp.paddr();
    let io = RecIo::default();

    // TCL_DATA ring 1 (SW2TCL2, SRC): R0 = 0xa44690 + 0x58, R2 = 0xa46000 + 8.
    let mut p = SrngParams::new(ring(16, 8), 16);
    p.msi_addr = 0x1_fee0_1000;
    p.msi_data = 0x33;
    p.flags = flags::MSI_INTR | flags::LOW_THRESH_INTR_EN;
    p.intr_batch_cntr_thres_entries = 2;
    p.intr_timer_thres_us = 1000;
    p.low_threshold = 4;
    let base = p.ring.paddr();
    let id = match hal.srng_setup(&io, HalRingType::TclData, 1, 0, p) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("TCL_DATA ring 1 setup failed"),
    };
    check!(id == ring_id::SW2TCL2, "SW2TCL2 ring id");
    let r0 = 0x00a4_46e8;
    let r2 = 0x00a4_6008;
    let golden = [
        W(r0 + 0x48, 0xfee0_1000),                      // MSI1_BASE_LSB
        W(r0 + 0x4c, 0x1 | (1 << 8)),                   // MSI1_BASE_MSB: addr[39:32] | MSI1_ENABLE
        W(r0 + 0x50, 0x33),                             // MSI1_DATA
        W(r0, base as u32),                             // BASE_LSB
        W(r0 + 0x04, (base >> 32) as u32 | (128 << 8)), // BASE_MSB: RING_SIZE = 8 * 16 words
        W(r0 + 0x08, 8),                                // RING_ID: ENTRY_SIZE only (SRC)
        W(r0 + 0x30, (1000 << 16) | (2 * 8)), // CONSR_INT_SETUP_IX0: timer µs | batch * entry
        W(r0 + 0x34, 4 * 8),                  // IX1: LOW_THOLD = low_threshold * entry_size
        W(r0 + 0x1c, (rdp + 17 * 4) as u32),  // TP_ADDR_LSB = rdp + ring_id
        W(r0 + 0x20, ((rdp + 17 * 4) >> 32) as u32),
        W(r2, 0),                          // HP
        W(r2 + 4, 0),                      // TP
        W(r0 + 0x10, (1 << 1) | (1 << 6)), // MISC: MSI_LOOPCNT_DISABLE | SRNG_ENABLE
    ];
    check!(
        io.ops() == golden,
        "TCL_DATA src_hw_init sequence differs from Linux"
    );
    check!(
        hal.srng(id).map(|s| s.sw_ptr) == Some(SwPtr::Reg(0x8fc + 9 * 4)),
        "SW2TCL2 HP lives in shadow register 9"
    );

    // REO_DST ring 2 (REO2SW3, DST), no MSI: R0 = 0xa38244 + 2*0x58,
    // R2 = 0xa3b030 + 2*8.
    io.clear();
    let mut p = SrngParams::new(ring(8, 16), 8);
    p.intr_batch_cntr_thres_entries = 1;
    p.intr_timer_thres_us = 500;
    let base = p.ring.paddr();
    let id = match hal.srng_setup(&io, HalRingType::ReoDst, 2, 0, p) {
        Ok(id) => id,
        Err(_) => return TestResult::Fail("REO_DST ring 2 setup failed"),
    };
    check!(id == ring_id::REO2SW3, "REO2SW3 ring id");
    let r0 = 0x00a3_82f4;
    let r2 = 0x00a3_b040;
    let golden = [
        W(r0, base as u32),
        W(r0 + 0x04, (base >> 32) as u32 | (128 << 8)),
        W(r0 + 0x08, (2 << 8) | 16), // RING_ID: ring id | entry size
        W(r0 + 0x24, ((500 >> 3) << 16) | 16), // PRODUCER_INT_SETUP: timer in 8 µs | batch
        W(r0 + 0x14, (rdp + 2 * 4) as u32), // HP_ADDR_LSB = rdp + ring_id
        W(r0 + 0x18, ((rdp + 2 * 4) >> 32) as u32),
        W(r2, 0),
        W(r2 + 4, 0),
        W(r0 + 0x10, 1 << 6), // MISC: SRNG_ENABLE
    ];
    check!(
        io.ops() == golden,
        "REO_DST dst_hw_init sequence differs from Linux"
    );
    check!(
        hal.srng(id).map(|s| s.sw_ptr) == Some(SwPtr::Reg(0x8fc + 2 * 4)),
        "REO2SW3 TP lives in shadow register 2"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_hal_srng_setup_dp_golden
);

fn smoke_ath11k_hal_no_shadow_and_lmac_pointers() -> TestResult {
    // Without shadow registers the SW pointer is the ring's own R2
    // register: HP for SRC, HP + (REO1_TP - REO1_HP) for DST.
    let mut hw = wcn6855();
    hw.supports_shadow_regs = false;
    let mut hal = Hal::new(&hw).expect("hal");
    check!(
        hal.shadow_reg_v2().is_empty(),
        "no shadow list without shadow registers"
    );
    let io = RecIo::default();
    let src = hal
        .srng_setup(
            &io,
            HalRingType::CeSrc,
            0,
            0,
            SrngParams::new(ring(4, 4), 4),
        )
        .expect("ce0 src");
    let dst = hal
        .srng_setup(
            &io,
            HalRingType::CeDstStatus,
            0,
            0,
            SrngParams::new(ring(4, 4), 4),
        )
        .expect("ce0 status");
    check!(
        hal.srng(src).unwrap().sw_ptr == SwPtr::Reg(0x01b8_0400),
        "SRC HP = R2 register"
    );
    check!(
        hal.srng(dst).unwrap().sw_ptr == SwPtr::Reg(0x01b8_140c),
        "DST TP = R2 + 4"
    );
    io.clear();
    let _ = hal.src_get_next_entry(src);
    hal.access_end(&io, src);
    check!(
        io.ops() == [Op::W(0x01b8_0400, 4)],
        "access_end writes the SRC HP register"
    );

    // LMAC ring: no register programming, pointers in rdp / wrp.
    let mut hal = Hal::new(&wcn6855()).expect("hal");
    io.clear();
    let id = hal
        .srng_setup(
            &io,
            HalRingType::RxdmaBuf,
            0,
            0,
            SrngParams::new(ring(8, 2), 8),
        )
        .expect("rxdma buf");
    check!(id == 128, "RXDMA_BUF mac0 = 128");
    check!(
        io.ops().is_empty(),
        "LMAC rings are not programmed by the host"
    );
    let s = hal.srng(id).unwrap();
    check!(s.flags & flags::LMAC_RING != 0, "LMAC flag set");
    check!(s.sw_ptr == SwPtr::Wrp(0), "LMAC HP in wrp[ring_id - 128]");
    check!(
        hal.get_hp_addr(id) == hal.wrp.paddr(),
        "get_hp_addr = wrp slot"
    );
    check!(
        hal.get_tp_addr(id) == hal.rdp.paddr() + 128 * 4,
        "get_tp_addr = rdp slot"
    );
    let _ = hal.src_get_next_entry(id);
    hal.access_end(&io, id);
    check!(
        io.ops().is_empty() && hal.wrp.rd32(0) == 2,
        "LMAC access_end writes wrp, no MMIO"
    );
    // Non-LMAC rings report no hp/tp address.
    let ce = hal
        .srng_setup(
            &io,
            HalRingType::CeSrc,
            0,
            0,
            SrngParams::new(ring(4, 4), 4),
        )
        .expect("ce0 src");
    check!(
        hal.get_hp_addr(ce) == 0 && hal.get_tp_addr(ce) == 0,
        "non-LMAC: 0"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_hal_no_shadow_and_lmac_pointers
);

// ── ring arithmetic ───────────────────────────────────────────────

fn smoke_ath11k_hal_src_ring_arithmetic_wraps() -> TestResult {
    let mut hal = Hal::new(&wcn6855()).expect("hal");
    let io = RecIo::default();
    // CE3 src, 4 entries of 4 words: ring_size = 16 words.
    let id = hal
        .srng_setup(
            &io,
            HalRingType::CeSrc,
            3,
            0,
            SrngParams::new(ring(4, 4), 4),
        )
        .expect("ce3 src");
    check!(id == 35, "CE3 src = 35");
    let s = hal.srng(id).unwrap();
    check!(
        s.ring_size == 16 && s.hp == 0 && s.reap_hp == 12 && s.cached_tp == 0,
        "fresh SRC ring: hp 0, reap_hp = ring_size - entry_size"
    );
    // One slot always stays empty: 3 free of 4.
    check!(
        hal.src_num_free(id, false) == 3,
        "3 free on an empty 4-entry ring"
    );
    check!(hal.src_get_next_entry(id) == Some(0), "entry 0");
    check!(hal.src_get_next_entry(id) == Some(4), "entry 1");
    check!(hal.src_get_next_entry(id) == Some(8), "entry 2");
    check!(
        hal.src_get_next_entry(id).is_none(),
        "full: next_hp == cached_tp"
    );
    check!(hal.src_num_free(id, false) == 0, "0 free when full");
    check!(
        hal.src_peek(id).is_none() && hal.src_next_peek(id).is_none(),
        "peek on full ring"
    );
    io.clear();
    hal.access_end(&io, id);
    // CE3 src HP shadow = slot 25 → 0x8fc + 100.
    check!(
        io.ops() == [Op::W(0x960, 12)],
        "HP published through shadow register 25"
    );

    // Hardware consumed two entries: TP = 8 in rdp[ring_id].
    hal.rdp.wr32(id as usize, 8);
    check!(
        hal.src_num_free(id, false) == 0,
        "cached TP not refreshed without sync"
    );
    hal.access_begin(id);
    check!(
        hal.srng(id).unwrap().cached_tp == 8,
        "access_begin caches TP"
    );
    check!(
        hal.src_num_free(id, false) == 2,
        "(16 - 12 + 8) / 4 - 1 = 2 free"
    );
    check!(hal.src_get_next_entry(id) == Some(12), "entry 3");
    check!(hal.src_get_next_entry(id) == Some(0), "wraps to entry 0");
    check!(
        hal.src_get_next_entry(id).is_none(),
        "full again at hp 4, tp 8"
    );
    hal.rdp.wr32(id as usize, 4);
    check!(hal.src_num_free(id, true) == 3, "sync: tp == hp → 3 free");

    // reap path (ath11k_ce_send / completed_send_next) on CE7 src.
    let id = hal
        .srng_setup(
            &io,
            HalRingType::CeSrc,
            7,
            0,
            SrngParams::new(ring(4, 4), 4),
        )
        .expect("ce7 src");
    check!(hal.src_get_next_reaped(id) == Some(0), "reaped 0");
    check!(hal.src_get_next_reaped(id) == Some(4), "reaped 1");
    check!(hal.src_get_next_reaped(id) == Some(8), "reaped 2");
    check!(hal.src_get_next_reaped(id).is_none(), "hp reached reap_hp");
    hal.access_begin(id);
    check!(hal.src_reap_next(id).is_none(), "nothing consumed yet");
    hal.rdp.wr32(id as usize, 8);
    hal.access_begin(id);
    check!(hal.src_reap_next(id) == Some(0), "reap entry 0");
    check!(hal.src_reap_next(id) == Some(4), "reap entry 1");
    check!(hal.src_reap_next(id).is_none(), "reap stops at TP");
    check!(
        hal.src_get_next_reaped(id) == Some(12),
        "entry 3 free again"
    );
    check!(hal.src_get_next_reaped(id) == Some(0), "wraps to 0");
    check!(hal.src_get_next_reaped(id).is_none(), "stops at reap_hp 4");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_hal_src_ring_arithmetic_wraps
);

fn smoke_ath11k_hal_dst_ring_arithmetic_wraps() -> TestResult {
    let mut hal = Hal::new(&wcn6855()).expect("hal");
    let io = RecIo::default();
    // CE2 dst status, 4 entries of 4 words.
    let id = hal
        .srng_setup(
            &io,
            HalRingType::CeDstStatus,
            2,
            0,
            SrngParams::new(ring(4, 4), 4),
        )
        .expect("ce2 status");
    check!(id == 82, "CE2 status = 82");
    check!(hal.srng(id).unwrap().loop_cnt == 1, "loop_cnt starts at 1");
    check!(hal.dst_num_free(id, true) == 0, "empty");
    hal.access_begin(id);
    check!(hal.dst_get_next_entry(id).is_none(), "nothing to consume");
    // Hardware produced three entries: HP = 12.
    hal.rdp.wr32(id as usize, 12);
    check!(
        hal.dst_num_free(id, false) == 0,
        "cached HP stale without sync"
    );
    check!(hal.dst_num_free(id, true) == 3, "sync: 3 ready");
    hal.access_begin(id);
    check!(hal.dst_peek(id) == Some(0), "peek 0");
    check!(hal.dst_get_next_entry(id) == Some(0), "entry 0");
    check!(hal.dst_get_next_entry(id) == Some(4), "entry 1");
    check!(hal.dst_get_next_entry(id) == Some(8), "entry 2");
    check!(hal.dst_get_next_entry(id).is_none(), "tp == cached_hp");
    io.clear();
    hal.access_end(&io, id);
    // CE2 dst-status TP shadow = slot 24 → 0x8fc + 96.
    check!(
        io.ops() == [Op::W(0x95c, 12)],
        "TP published through shadow register 24"
    );
    // HP wraps 12 → 0 → 4: entries at 12 and 0.
    hal.rdp.wr32(id as usize, 4);
    check!(
        hal.dst_num_free(id, true) == 2,
        "(16 - 12 + 4) / 4 = 2 across the wrap"
    );
    hal.access_begin(id);
    check!(hal.dst_get_next_entry(id) == Some(12), "entry 3");
    check!(hal.srng(id).unwrap().tp == 0, "tp wraps to 0 at ring_size");
    check!(hal.dst_get_next_entry(id) == Some(0), "entry 0 again");
    check!(
        hal.dst_get_next_entry(id).is_none() && hal.dst_peek(id).is_none(),
        "drained"
    );
    // shadow_update_hp_tp only acts on SRC rings.
    io.clear();
    hal.shadow_update_hp_tp(&io, id);
    check!(io.ops().is_empty(), "shadow_update_hp_tp ignores DST rings");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_hal_dst_ring_arithmetic_wraps
);

fn smoke_ath11k_hal_setup_negatives() -> TestResult {
    let mut hal = Hal::new(&wcn6855()).expect("hal");
    let io = RecIo::default();
    let e = hal
        .srng_setup(
            &io,
            HalRingType::CeSrc,
            12,
            0,
            SrngParams::new(ring(4, 4), 4),
        )
        .unwrap_err();
    check!(e.step == step::BAD_RING_NUM, "CE ring 12: BAD_RING_NUM");
    let e = hal
        .srng_setup(
            &io,
            HalRingType::CeSrc,
            0,
            0,
            SrngParams::new(ring(1, 4), 0),
        )
        .unwrap_err();
    check!(e.step == step::BAD_RING_SIZE, "0 entries: BAD_RING_SIZE");
    // 0x4000 entries * 4 words = 0x10000 > HAL_CE_SRC_RING_BASE_MSB_RING_SIZE.
    let e = hal
        .srng_setup(
            &io,
            HalRingType::CeSrc,
            0,
            0,
            SrngParams::new(ring(1, 4), 0x4000),
        )
        .unwrap_err();
    check!(
        e.step == step::BAD_RING_SIZE && e.detail == (8 << 16) | 0x4000,
        "ring larger than max_size: BAD_RING_SIZE"
    );
    let e = hal
        .srng_setup(
            &io,
            HalRingType::CeSrc,
            0,
            0,
            SrngParams::new(ring(2, 4), 4),
        )
        .unwrap_err();
    check!(
        e.step == step::RING_MEM_SIZE && e.detail == 32,
        "short ring memory: RING_MEM_SIZE"
    );
    check!(io.ops().is_empty(), "rejected setups touch no register");
    hal.srng_setup(
        &io,
        HalRingType::CeSrc,
        0,
        0,
        SrngParams::new(ring(4, 4), 4),
    )
    .expect("ce0 src");
    let e = hal
        .srng_setup(
            &io,
            HalRingType::CeSrc,
            0,
            0,
            SrngParams::new(ring(4, 4), 4),
        )
        .unwrap_err();
    check!(
        e.step == step::RING_IN_USE && e.detail == 32,
        "second setup: RING_IN_USE"
    );

    // A shadow-register part whose CE ring got no shadow slot.
    let mut hw = wcn6855();
    hw.host_ce_config = &[];
    let mut hal = Hal::new(&hw).expect("hal");
    check!(
        hal.shadow_reg_v2().len() == 20,
        "only the 20 DP rings without CEs"
    );
    let e = hal
        .srng_setup(
            &io,
            HalRingType::CeSrc,
            0,
            0,
            SrngParams::new(ring(4, 4), 4),
        )
        .unwrap_err();
    check!(
        e.step == step::NO_SHADOW_REG && e.detail == 32,
        "no shadow slot: NO_SHADOW_REG"
    );

    // No register map.
    let mut noregs = HwRev::Qcn9074Hw10.params().unwrap();
    noregs.regs = None;
    let e = Hal::new(&noregs).unwrap_err();
    check!(
        e.step == step::NO_REGS && e.errno == errno::EINVAL,
        "no register map: NO_REGS"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_hal_setup_negatives);

// ── descriptors ───────────────────────────────────────────────────

fn smoke_ath11k_hal_ce_descriptor_bits() -> TestResult {
    check!(
        ce_get_desc_size(HalCeDesc::Src) == 16,
        "hal_ce_srng_src_desc = 16 B"
    );
    check!(
        ce_get_desc_size(HalCeDesc::Dst) == 8,
        "hal_ce_srng_dest_desc = 8 B"
    );
    check!(
        ce_get_desc_size(HalCeDesc::DstStatus) == 16,
        "dst status desc = 16 B"
    );
    // ath11k_hal_ce_src_set_desc: addr[39:32] in bits 7:0, byte swap
    // bit 9, gather bit 11 = 0, len in 31:16; meta in 15:0.
    let w = ce_src_desc_words(0xab_1234_5678, 0x7ff, 0xbeef, 0);
    check!(w == [0x1234_5678, 0x07ff_00ab, 0xbeef], "src desc words");
    let w = ce_src_desc_words(0x1000, 4, 1, 1);
    check!(w[1] == (4 << 16) | (1 << 9), "byte swap bit 9");
    // FIELD_PREP truncates: a 16-bit length field and 16-bit metadata.
    let w = ce_src_desc_words(0x1000, 0x1_0004, 0x1_0002, 0);
    check!(
        w[1] == 4 << 16 && w[2] == 2,
        "len / meta truncated to their fields"
    );
    check!(
        ce_dst_desc_words(0x7f_8000_0040) == [0x8000_0040, 0x7f],
        "dst desc words"
    );
    check!(
        HAL_CE_SRC_DESC_FLAGS_RING_ID == 0x0ff0_0000 && HAL_SRNG_DESC_LOOP_CNT == 0xf000_0000,
        "ring id 27:20, loop count 31:28"
    );
    // ath11k_hal_ce_dst_status_get_length reads and clears the length.
    let mut hal = Hal::new(&wcn6855()).expect("hal");
    let io = RecIo::default();
    let id = hal
        .srng_setup(
            &io,
            HalRingType::CeDstStatus,
            1,
            0,
            SrngParams::new(ring(4, 4), 4),
        )
        .expect("ce1 status");
    // flags: len 0x123 in 31:16, gather (bit 11) + byte swap (bit 9).
    hal.desc_wr(id, 4, &[(0x0123 << 16) | 0x0a00, 0, 0, 0x55]);
    check!(
        hal.ce_dst_status_get_length(id, 4) == 0x0123,
        "length = flags[31:16]"
    );
    check!(
        hal.desc_rd(id, 4, 0) == 0x0a00,
        "length cleared, other bits kept"
    );
    check!(hal.desc_rd(id, 4, 3) == 0x55, "meta_info untouched");
    check!(
        hal.ce_dst_status_get_length(id, 4) == 0,
        "second read sees 0"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_hal_ce_descriptor_bits
);

fn smoke_ath11k_dp_descriptor_layouts() -> TestResult {
    // sizeof() of the Linux structs (compiled from hal_desc.h / rx_desc.h).
    check!(size_of::<BufferAddr>() == 8, "ath11k_buffer_addr");
    check!(size_of::<HalTlvHdr>() == 4, "hal_tlv_hdr");
    check!(size_of::<HalReoDestRing>() == 64, "hal_reo_dest_ring");
    check!(
        size_of::<HalReoEntranceRing>() == 32,
        "hal_reo_entrance_ring"
    );
    check!(
        size_of::<HalTclDataCmd>() == 28 && HAL_TCL_DESC_LEN == 28,
        "hal_tcl_data_cmd"
    );
    check!(size_of::<HalTclStatusRing>() == 32, "hal_tcl_status_ring");
    check!(size_of::<HalWbmReleaseRing>() == 32, "hal_wbm_release_ring");
    check!(
        size_of::<HalWbmLinkDesc>() == 8 && size_of::<HalWbmBufferRing>() == 8,
        "wbm link/buffer"
    );
    check!(
        size_of::<HalRxDescWcn6855>() == 392,
        "hal_rx_desc_wcn6855 (hal_desc_sz)"
    );
    // Entry sizes the SRNG template derives from them (words).
    let t = &SRNG_CONFIG_TEMPLATE;
    check!(
        t[HalRingType::ReoDst.idx()].entry_size == 16,
        "REO_DST 16 words"
    );
    check!(
        t[HalRingType::TclData.idx()].entry_size == 8,
        "TCL_DATA (tlv + 28 B) 8 words"
    );
    check!(
        t[HalRingType::TclStatus.idx()].entry_size == 9,
        "TCL_STATUS (tlv + 32 B) 9 words"
    );
    check!(
        t[HalRingType::ReoCmd.idx()].entry_size == 10,
        "REO_CMD (tlv + 36 B) 10 words"
    );
    check!(
        t[HalRingType::ReoStatus.idx()].entry_size == 26,
        "REO_STATUS (tlv + 100 B) 26 words"
    );
    check!(
        t[HalRingType::Wbm2SwRelease.idx()].entry_size == 8,
        "WBM2SW 8 words"
    );
    check!(
        t[HalRingType::RxdmaBuf.idx()].entry_size == 2,
        "RXDMA_BUF 2 words"
    );

    // ath11k_hal_rx_buf_addr_info_set / _get.
    let b = BufferAddr::new(0xab_1234_5678, 0x1f_ffff, rbm::SW1_BM);
    let (i0, i1) = (b.info0, b.info1);
    check!(i0 == 0x1234_5678, "info0 = addr[31:0]");
    check!(
        i1 == 0xab | (4 << 8) | (0x1f_ffff << 11),
        "info1 = addr hi | rbm | cookie"
    );
    check!(b.get() == (0xab_1234_5678, 0x1f_ffff, 4), "round trip");
    check!(
        HalTlvHdr::new(tlv_tag::HAL_TCL_DATA_CMD, 28).tl == (0x144 << 1) | (28 << 10),
        "TLV header"
    );

    // hal_rx_desc_wcn6855 accessors at the Linux offsets.
    let mut raw = [0u8; HalRxDescWcn6855::SIZE];
    let put =
        |raw: &mut [u8], off: usize, v: u32| raw[off..off + 4].copy_from_slice(&v.to_le_bytes());
    put(&mut raw, 44, (1 << 28) | (1 << 29) | (2 << 26)); // msdu_end.info2
    put(&mut raw, 104, 0x5dc); // msdu_start.info1: msdu_len 1500
    put(&mut raw, 108, 2 << 8); // msdu_start.info2: decap format
    put(&mut raw, 128, 5180); // msdu_start.phy_meta_data
    put(&mut raw, 92, 1 << 31); // attention.info2: msdu_done
    put(&mut raw, 188, (0x123 << 20) | (1 << 9)); // mpdu_start.info1: seq | encrypt valid
    put(&mut raw, 172, (6 << 15) | (4 << 2)); // mpdu_start.info2: TID (wcn6855) | enc type
    raw[186..188].copy_from_slice(&0x0042u16.to_le_bytes()); // sw_peer_id
    put(&mut raw, 140, 0x4c << 1); // mpdu_start_tag TLV tag
    let d = match HalRxDescWcn6855::from_bytes(&raw) {
        Some(d) => d,
        None => return TestResult::Fail("from_bytes on a full descriptor"),
    };
    check!(
        d.first_msdu() && d.last_msdu(),
        "first/last msdu are bits 28/29 on WCN6855"
    );
    check!(d.l3_pad_bytes() == 2, "l3 pad bits 27:26");
    check!(d.msdu_len() == 1500, "msdu_len");
    check!(d.decap_type() == 2, "decap type");
    check!(d.msdu_freq() == 5180, "phy_meta_data");
    check!(d.msdu_done(), "msdu_done");
    check!(
        d.mpdu_start_seq_no() == 0x123 && d.encrypt_valid(),
        "seq / encrypt valid"
    );
    check!(
        d.mpdu_tid() == 6 && d.encrypt_type() == 4,
        "TID bits 18:15 on WCN6855"
    );
    check!(d.mpdu_peer_id() == 0x42, "sw_peer_id");
    check!(d.mpdu_start_tag() == 0x4c, "mpdu_start tag");
    check!(
        HalRxDescWcn6855::from_bytes(&raw[..HalRxDescWcn6855::SIZE - 1]).is_none(),
        "short buffer refused"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_descriptor_layouts
);

fn smoke_ath11k_dp_ring_sizes_match_linux() -> TestResult {
    check!(
        DP_TCL_DATA_RING_SIZE == 512 && DP_TCL_NUM_RING_MAX == 3,
        "TCL data"
    );
    check!(
        DP_REO_DST_RING_SIZE == 2048 && DP_REO_DST_RING_MAX == 4,
        "REO dst"
    );
    check!(
        DP_WBM_RELEASE_RING_SIZE == 64 && DP_TX_COMP_RING_SIZE == 32768,
        "WBM / TX comp"
    );
    check!(
        DP_RXDMA_BUF_RING_SIZE == 4096 && DP_RX_BUFFER_SIZE == 2048,
        "RXDMA"
    );
    // Every DP ring fits its type's max_size.
    let c = create_config(&WCN6855_REGS);
    for (ty, n) in [
        (HalRingType::TclData, DP_TCL_DATA_RING_SIZE),
        (HalRingType::Wbm2SwRelease, DP_TX_COMP_RING_SIZE),
        (HalRingType::ReoDst, DP_REO_DST_RING_SIZE),
        (HalRingType::ReoStatus, DP_REO_STATUS_RING_SIZE),
        (HalRingType::RxdmaBuf, DP_RXDMA_BUF_RING_SIZE),
    ] {
        if c[ty.idx()].entry_size as u32 * n > c[ty.idx()].max_size {
            return TestResult::Fail("DP ring larger than its type's max_size");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_ring_sizes_match_linux
);
