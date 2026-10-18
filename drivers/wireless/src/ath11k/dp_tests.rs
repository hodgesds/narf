//! Data-path ring runtime tests.
//!
//! The device side is a model that knows only what the host programmed:
//! UMAC rings (TCL, WBM, REO) from the ring base / size / entry-size /
//! pointer-address registers in [`RecIo`] and the QMI shadow-register
//! list (`WCN6855_SHADOW_REG_V2`) for the host's HP / TP, LMAC rings
//! (RXDMA) from the HTT SRING_SETUP messages. It moves descriptors and
//! buffers through the host's real DMA32 memory by physical address
//! (kernel direct map), as the hardware would.
//!
//! Expected values are hand-derived from Linux
//! `drivers/net/wireless/ath/ath11k/{dp.c,dp_tx.c,dp_rx.c,hal.c,hal_tx.c,
//! hal_rx.c,hw.c,dp.h,hal_desc.h,rx_desc.h}` for WCN6855 (`wcn6855_regs`,
//! `ath11k_hw_ring_mask_qca6390`, `ath11k_hw_hal_params_qca6390`), not
//! from the code under test.

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use super::ce::CeMsi;
use super::dp_ring::step;
use super::dp_ring::*;
use super::hal::*;
use super::hal_tests::{Op, RecIo, WCN6855_SHADOW_REG_V2};
use super::htt;
use super::hw::*;

macro_rules! check {
    ($cond:expr, $msg:literal) => {
        if !($cond) {
            return TestResult::Fail($msg);
        }
    };
}

// ── physical memory (the device side of DMA) ──────────────────────

fn phys_rd32(pa: u64) -> u32 {
    // SAFETY: `pa` lies inside a live DMA32 coherent buffer the DP / HAL
    // under test allocated and owns (ring, pointer area or posted buffer);
    // the kernel direct map covers it and it is 4-byte aligned.
    unsafe { core::ptr::read_volatile(narf_memory::PhysAddr::new(pa).kernel_ptr::<u32>()) }
}

fn phys_wr32(pa: u64, v: u32) {
    // SAFETY: as `phys_rd32`; the model only writes words the hardware
    // owns (ring entries it produces, its pointer, posted buffers).
    unsafe { core::ptr::write_volatile(narf_memory::PhysAddr::new(pa).kernel_mut_ptr::<u32>(), v) }
}

fn phys_read(pa: u64, out: &mut [u8]) {
    // SAFETY: `pa..pa + out.len()` is inside one live DMA buffer (a TX
    // bounce buffer of at least that length).
    unsafe {
        core::ptr::copy_nonoverlapping(
            narf_memory::PhysAddr::new(pa).kernel_ptr::<u8>(),
            out.as_mut_ptr(),
            out.len(),
        )
    }
}

fn phys_write(pa: u64, src: &[u8]) {
    // SAFETY: `pa` is a posted RX buffer (2048 bytes, callers write at
    // most that) or a link descriptor the model took from the idle list.
    unsafe {
        core::ptr::copy_nonoverlapping(
            src.as_ptr(),
            narf_memory::PhysAddr::new(pa).kernel_mut_ptr::<u8>(),
            src.len(),
        )
    }
}

// ── the device model ──────────────────────────────────────────────

const SHADOW_BASE: u32 = 0x8fc;

/// Shadow register that mirrors ring pointer register `target`.
fn shadow_of(target: u32) -> u32 {
    let i = WCN6855_SHADOW_REG_V2
        .iter()
        .position(|&t| t == target)
        .expect("ring pointer register in the shadow list");
    SHADOW_BASE + 4 * i as u32
}

#[derive(Copy, Clone, Debug)]
enum HostPtr {
    Reg(u32),
    Mem(u64),
}

/// One ring as the hardware sees it. `idx` is the device's pointer
/// (TP of a SRC ring, HP of a DST ring), in words.
#[derive(Copy, Clone, Debug)]
struct DevRing {
    base: u64,
    size: u32,
    esz: u32,
    hw_ptr: u64,
    host: HostPtr,
    idx: u32,
}

impl DevRing {
    fn host(&self, io: &RecIo) -> u32 {
        match self.host {
            HostPtr::Reg(o) => io.reg(o),
            HostPtr::Mem(pa) => phys_rd32(pa),
        }
    }

    fn publish(&self) {
        if self.hw_ptr != 0 {
            phys_wr32(self.hw_ptr, self.idx);
        }
    }

    /// DST ring: write one entry (fails when the ring is full).
    fn produce(&mut self, io: &RecIo, w: &[u32]) -> bool {
        let tp = self.host(io);
        if (self.idx + self.esz) % self.size == tp {
            return false;
        }
        for (i, &v) in w.iter().enumerate() {
            phys_wr32(self.base + (self.idx as u64 + i as u64) * 4, v);
        }
        self.idx = (self.idx + self.esz) % self.size;
        self.publish();
        true
    }

    /// SRC ring: take one entry the host posted.
    fn consume(&mut self, io: &RecIo) -> Option<Vec<u32>> {
        if self.idx == self.host(io) {
            return None;
        }
        let w = (0..self.esz)
            .map(|i| phys_rd32(self.base + (self.idx as u64 + i as u64) * 4))
            .collect();
        self.idx = (self.idx + self.esz) % self.size;
        self.publish();
        Some(w)
    }

    /// Entries the host posted that the device has not consumed.
    fn pending(&self, io: &RecIo) -> u32 {
        (self.host(io) + self.size - self.idx) % self.size / self.esz
    }

    fn entry(&self, i: u32) -> Vec<u32> {
        (0..self.esz)
            .map(|k| phys_rd32(self.base + ((i * self.esz + k) as u64) * 4))
            .collect()
    }
}

fn reg64(io: &RecIo, lo: u32) -> u64 {
    io.reg(lo) as u64 | ((io.reg(lo + 4) as u64 & 0xff) << 32)
}

/// A UMAC DST ring from its R0 registers (REO-style layout: base_msb +4,
/// id +8, hp_addr +0x14 / +0x18) and the TP register the host's shadow
/// mirrors.
fn umac_dst(io: &RecIo, r0: u32, tp_reg: u32) -> DevRing {
    DevRing {
        base: reg64(io, r0),
        size: (io.reg(r0 + 4) >> 8) & 0xf_ffff,
        esz: io.reg(r0 + 8) & 0xff,
        hw_ptr: io.reg(r0 + 0x14) as u64 | ((io.reg(r0 + 0x18) as u64) << 32),
        host: HostPtr::Reg(shadow_of(tp_reg)),
        idx: 0,
    }
}

/// A UMAC SRC ring (TCL-style layout: tp_addr +0x1c / +0x20).
fn umac_src(io: &RecIo, r0: u32, hp_reg: u32) -> DevRing {
    DevRing {
        base: reg64(io, r0),
        size: (io.reg(r0 + 4) >> 8) & 0xf_ffff,
        esz: io.reg(r0 + 8) & 0xff,
        hw_ptr: io.reg(r0 + 0x1c) as u64 | ((io.reg(r0 + 0x20) as u64) << 32),
        host: HostPtr::Reg(shadow_of(hp_reg)),
        idx: 0,
    }
}

fn msg_word(m: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([m[i * 4], m[i * 4 + 1], m[i * 4 + 2], m[i * 4 + 3]])
}

/// An LMAC ring from its HTT SRING_SETUP message: SW→HW rings have the
/// host HP at `ring_head_off32_remote_addr`, HW→SW rings the host TP at
/// `ring_tail_off32_remote_addr`.
fn lmac(m: &[u8]) -> DevRing {
    let info0 = msg_word(m, 0);
    let info1 = msg_word(m, 3);
    let hp = msg_word(m, 4) as u64 | ((msg_word(m, 5) as u64) << 32);
    let tp = msg_word(m, 6) as u64 | ((msg_word(m, 7) as u64) << 32);
    let hw_to_sw = (info0 >> 24) == 0;
    DevRing {
        base: msg_word(m, 1) as u64 | ((msg_word(m, 2) as u64) << 32),
        size: info1 & 0xffff,
        esz: (info1 >> 16) & 0xff,
        hw_ptr: if hw_to_sw { hp } else { tp },
        host: HostPtr::Mem(if hw_to_sw { tp } else { hp }),
        idx: 0,
    }
}

// WCN6855 UMAC ring R0 / pointer registers (HAL_SEQ_WCSS_UMAC_*_REG +
// wcn6855_regs offsets).
const REO2SW1_R0: u32 = 0x00a3_8244;
const REO_DST_STRIDE: u32 = 0x58;
const REO2SW1_TP: u32 = 0x00a3_b034;
const REO2TCL_R0: u32 = 0x00a3_8454;
const REO2TCL_TP: u32 = 0x00a3_b064;
const REO_STATUS_R0: u32 = 0x00a3_855c;
const REO_STATUS_TP: u32 = 0x00a3_b07c;
const TCL1_R0: u32 = 0x00a4_4690;
const TCL1_HP: u32 = 0x00a4_6000;
const WBM2SW0_R0: u32 = 0x00a3_4920;
const WBM2SW0_TP: u32 = 0x00a3_70c4;
const WBM2SW3_R0: u32 = 0x00a3_4920 + 3 * 0x58;
const WBM2SW3_TP: u32 = 0x00a3_70c4 + 3 * 8;
const SW2WBM_R0: u32 = 0x00a3_41e8;
const SW2WBM_HP: u32 = 0x00a3_7018;
const WBM_IDLE_R0: u32 = 0x00a3_4870;
const WBM_IDLE_HP: u32 = 0x00a3_70b0;

const MSI_ADDR: u64 = 0xfee0_0000;

fn msi() -> CeMsi {
    CeMsi {
        addr: MSI_ADDR,
        ep_base_data: 0,
        config: &MSI_CONFIG_QCA6390,
    }
}

pub(super) const SMALL: DpRingSizes = DpRingSizes {
    wbm_release: 16,
    tcl_cmd: 8,
    tcl_status: 8,
    tcl_data: Some(8),
    tx_comp: 16,
    reo_reinject: 8,
    rx_release: 16,
    reo_exception: 16,
    reo_cmd: 8,
    reo_status: 16,
    reo_dst: 16,
    rxdma_buf: 16,
    rx_mac_buf: 16,
    rxdma_err_dst: 16,
    rxdma_mon_status: 8,
    tx_status_fifo: 8,
    n_link_desc: Some(64),
};

struct Rig {
    hal: Hal,
    io: RecIo,
    dp: Dp,
    msgs: Vec<Vec<u8>>,
}

fn rig(sizes: DpRingSizes) -> Rig {
    let cfg = DpHwParams::for_rev(HwRev::Wcn6855Hw21).expect("WCN6855 DP params");
    let mut hal = Hal::new(&cfg.hw).expect("hal");
    let io = RecIo::default();
    let mut dp = Dp::alloc(&mut hal, &io, &cfg, sizes, Some(msi())).expect("dp alloc");
    dp.pdev_reo_setup(&mut hal, &io).expect("reo setup");
    let msgs = dp.pdev_alloc(&mut hal, &io, 0).expect("pdev alloc");
    Rig { hal, io, dp, msgs }
}

// ── RX descriptor / frame builders ────────────────────────────────

pub(super) const DESC_SZ: usize = 392;

#[derive(Clone, Default)]
pub(super) struct Rxd {
    pub(super) first: bool,
    pub(super) last: bool,
    pub(super) l3pad: u32,
    pub(super) attn1: u32,
    pub(super) not_done: bool,
    pub(super) decrypt_status: u32,
    pub(super) msdu_len: u32,
    pub(super) decap: u32,
    pub(super) freq: u32,
    pub(super) enc_valid: bool,
    pub(super) enc_type: u32,
    pub(super) tid: u32,
    pub(super) seq: u32,
    pub(super) sw_peer_id: u16,
    pub(super) addr2: Option<[u8; 6]>,
}

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// `struct hal_rx_desc_wcn6855` by byte offset (rx_desc.h).
pub(super) fn rx_desc_bytes(d: &Rxd) -> Vec<u8> {
    let mut b = vec![0u8; DESC_SZ];
    // msdu_end.info2 @ 4 + 40: FIRST_MSDU bit 28, LAST_MSDU bit 29, L3 pad 27:26
    put32(
        &mut b,
        44,
        (d.first as u32) << 28 | (d.last as u32) << 29 | (d.l3pad & 3) << 26,
    );
    // attention.info1 @ 84 + 4, info2 @ 84 + 8 (MSDU_DONE bit 31, decrypt status 12:10)
    put32(&mut b, 88, d.attn1);
    put32(
        &mut b,
        92,
        ((!d.not_done) as u32) << 31 | (d.decrypt_status & 7) << 10,
    );
    // msdu_start.info1 @ 100 + 4 (len 13:0), info2 @ 100 + 8 (decap 9:8),
    // phy_meta_data @ 100 + 28
    put32(&mut b, 104, d.msdu_len & 0x3fff);
    put32(&mut b, 108, (d.decap & 3) << 8);
    put32(&mut b, 128, d.freq);
    // mpdu_start @ 144: info2 @ +28 (enc 5:2, tid 18:15), sw_peer_id @ +42,
    // info1 @ +44 (ENCRYPT_INFO_VALID 9, MAC_ADDR2_VALID 3, seq 31:20),
    // addr2 @ +66
    put32(&mut b, 172, (d.enc_type & 0xf) << 2 | (d.tid & 0xf) << 15);
    b[186..188].copy_from_slice(&d.sw_peer_id.to_le_bytes());
    put32(
        &mut b,
        188,
        (d.enc_valid as u32) << 9 | (d.addr2.is_some() as u32) << 3 | (d.seq & 0xfff) << 20,
    );
    if let Some(a) = d.addr2 {
        b[210..216].copy_from_slice(&a);
    }
    b
}

const STA: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
const BSSID: [u8; 6] = [0x02, 0, 0, 0, 0, 0xaa];
const SRC: [u8; 6] = [0x02, 0, 0, 0, 0, 0xbb];

/// A native-wifi decapped MSDU from the AP (FromDS): 802.11 header
/// (no QoS, no IV) + RFC 1042 SNAP + payload.
fn nwifi_msdu(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x08, 0x02, 0, 0]; // fc = data | FromDS, duration
    f.extend_from_slice(&STA); // addr1 = DA
    f.extend_from_slice(&BSSID); // addr2 = BSSID
    f.extend_from_slice(&SRC); // addr3 = SA
    f.extend_from_slice(&[0x10, 0x00]); // seq ctrl
    f.extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0]);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn eth_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&STA);
    f.extend_from_slice(&SRC);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// REO destination entry (`struct hal_reo_dest_ring`, 16 words).
pub(super) fn reo_dest(
    paddr: u64,
    cookie: u32,
    msdu_info: u32,
    push: u32,
    tid: u32,
    peer: u32,
) -> [u32; 16] {
    let mut w = [0u32; 16];
    w[0] = paddr as u32;
    w[1] = ((paddr >> 32) as u32 & 0xff) | (4 << 8) | (cookie << 11); // rbm SW1
    w[2] = 0x5 << 8; // seq num 5
    w[3] = peer;
    w[4] = msdu_info;
    w[7] = (push << 9) | (tid << 16);
    w
}

pub(super) const FIRST: u32 = 1 << 0;
pub(super) const LAST: u32 = 1 << 1;
const CONT: u32 = 1 << 2;

/// Firmware side of the refill ring: take the next posted buffer.
fn fw_take(io: &RecIo, refill: &mut DevRing) -> (u64, u32) {
    let w = refill.consume(io).expect("posted RX buffer");
    let (pa, cookie, rbm_v) = buf_addr_get(w[0], w[1]);
    assert_eq!(rbm_v, rbm::SW1_BM);
    (pa, cookie)
}

/// Deliver one single-buffer MSDU through REO2SW`ring`.
fn deliver(io: &RecIo, refill: &mut DevRing, reo: &mut DevRing, d: &Rxd, msdu: &[u8]) -> u32 {
    let (pa, cookie) = fw_take(io, refill);
    let mut buf = rx_desc_bytes(d);
    buf.resize(DESC_SZ + d.l3pad as usize, 0);
    buf.extend_from_slice(msdu);
    phys_write(pa, &buf);
    assert!(reo.produce(
        io,
        &reo_dest(pa, cookie, FIRST | LAST | (msdu.len() as u32) << 3, 1, 0, 3)
    ));
    cookie
}

pub(super) fn good_rxd(len: usize, decap_ty: u32) -> Rxd {
    Rxd {
        first: true,
        last: true,
        msdu_len: len as u32,
        decap: decap_ty,
        freq: 5180,
        ..Rxd::default()
    }
}

// ── parameters ────────────────────────────────────────────────────

fn smoke_ath11k_dp_hw_params_wcn6855() -> TestResult {
    for rev in [
        HwRev::Wcn6855Hw20,
        HwRev::Wcn6855Hw21,
        HwRev::Qca2066Hw21,
        HwRev::Qca6698aqHw21,
    ] {
        let p = DpHwParams::for_rev(rev).unwrap();
        check!(
            p.num_rxdma_per_pdev == 2
                && p.rx_mac_buf_ring
                && !p.rxdma1_enable
                && !p.supports_monitor
                && !p.htt_peer_map_v2
                && p.tcl_ring_retry
                && p.tx_ring_size == 512
                && p.hal_desc_sz == 392
                && p.single_pdev_only,
            "WCN6855 family DP hw_params"
        );
        check!(
            p.num_tx_rings() == 1,
            "ath11k_hw_tcl2wbm_rbm_map_ipq5018: one TX ring"
        );
        check!(
            p.hal_params.rx_buf_rbm == rbm::SW1_BM
                && p.hal_params.tcl2wbm_rbm_map[0].rbm_id == rbm::SW0_BM,
            "rx_buf_rbm SW1, TX rbm SW0"
        );
    }
    check!(
        DpHwParams::for_rev(HwRev::Qcn9074Hw10).is_none()
            && DpHwParams::for_rev(HwRev::Qca6390Hw20).is_none(),
        "DP not ported for other parts"
    );
    // 2730 + 227 + 4681 + 10922 = 18560 → 1 << fls(18560) = 32768
    check!(wbm_idle_n_link_desc() == 32768, "n_link_desc");
    // 32768 * 128 + 128 = 4194432 over 0x200000 - 128 per bank: 2 full + 384
    check!(link_desc_banks(32768) == (3, 384), "bank split for WCN6855");
    check!(link_desc_banks(64) == (1, 64 * 128 + 128), "single bank");
    check!(
        link_desc_banks(1 << 17).0 > DP_LINK_DESC_BANKS_MAX,
        "too many banks"
    );
    check!(
        TCL_DATA_TLV_HDR == (0x144 << 1) | (28 << 10),
        "TCL data TLV header (HAL_TCL_DATA_CMD, 28 bytes)"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_hw_params_wcn6855);

fn smoke_ath11k_dp_msi_groups_wcn6855() -> TestResult {
    use HalRingType as T;
    let m = &RING_MASK_QCA6390;
    let cases: &[(T, u32, Option<usize>)] = &[
        (T::Wbm2SwRelease, 0, Some(0)), // tx[0] = 1
        (T::Wbm2SwRelease, 1, None),
        (T::Wbm2SwRelease, DP_RX_RELEASE_RING_NUM, Some(0)), // rx_wbm_rel[0]
        (T::ReoException, 0, Some(0)),
        (T::ReoDst, 0, Some(7)),
        (T::ReoDst, 1, Some(8)),
        (T::ReoDst, 2, Some(9)),
        (T::ReoDst, 3, Some(10)),
        (T::ReoDst, 4, None),
        (T::ReoStatus, 0, Some(0)),
        (T::RxdmaDst, 0, Some(0)),
        (T::RxdmaDst, 1, Some(1)),
        (T::RxdmaMonitorStatus, 0, Some(4)),
        (T::RxdmaMonitorStatus, 1, Some(5)),
        (T::RxdmaBuf, 0, None), // host2rxdma is empty
        (T::TclData, 0, None),
        (T::TclCmd, 0, None),
        (T::Sw2WbmRelease, 0, None),
        (T::WbmIdleLink, 0, None),
        (T::ReoCmd, 0, None),
        (T::ReoReinject, 0, None),
    ];
    for &(ty, n, g) in cases {
        check!(calculate_msi_group(m, ty, n) == g, "ext IRQ group");
    }
    let x = msi();
    // msi_data = (group % 18) + 14 (DP user base vector 14)
    check!(
        srng_msi(m, Some(&x), T::ReoDst, 2) == Some((MSI_ADDR, 23)),
        "REO2SW3 MSI data"
    );
    check!(
        srng_msi(m, Some(&x), T::RxdmaMonitorStatus, 1) == Some((MSI_ADDR, 19)),
        "mon status mac 1"
    );
    check!(
        srng_msi(m, Some(&x), T::TclData, 0).is_none(),
        "no group, no MSI"
    );
    check!(srng_msi(m, None, T::ReoDst, 0).is_none(), "no MSI at all");
    let one = CeMsi {
        addr: MSI_ADDR,
        ep_base_data: 3,
        config: &MSI_CONFIG_ONE,
    };
    // single MSI: DP user has 1 vector at base 0 → data = ep_base_data
    check!(
        srng_msi(m, Some(&one), T::ReoDst, 3) == Some((MSI_ADDR, 3)),
        "one-MSI fallback"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_msi_groups_wcn6855
);

// ── golden register sequences ─────────────────────────────────────

fn smoke_ath11k_dp_reo_setup_golden() -> TestResult {
    let io = RecIo::default();
    io.regs.borrow_mut().insert(0x00a3_8000, 0x1); // GEN_ENABLE
    io.regs.borrow_mut().insert(0x00a3_8630, 0xffff_ffff); // MISC_CTL (wcn6855 0x630)
    let r = &WCN6855_REGS;
    wcn6855_reo_setup(
        &io,
        r.hal_reo1_misc_ctl,
        [
            r.hal_reo1_aging_thresh_ix_0,
            r.hal_reo1_aging_thresh_ix_1,
            r.hal_reo1_aging_thresh_ix_2,
            r.hal_reo1_aging_thresh_ix_3,
        ],
    );
    // map = SW1 | SW2 << 4 | SW3 << 8 | SW4 << 12, twice
    let map = 0x4321_4321;
    let want = [
        Op::R(0x00a3_8000),
        Op::W(0x00a3_8000, 0x1 | 0x4 | 0x8),
        Op::R(0x00a3_8630),
        // FRAGMENT_DST_RING (20:17) = REO2SW1 (0)
        Op::W(0x00a3_8630, 0xffe1_ffff),
        Op::W(0x00a3_85bc, 40_000),
        Op::W(0x00a3_85c0, 40_000),
        Op::W(0x00a3_85c4, 40_000),
        Op::W(0x00a3_85c8, 40_000),
        Op::W(0x00a3_800c, map),
        Op::W(0x00a3_8010, map),
    ];
    check!(
        io.ops() == want,
        "ath11k_hw_wcn6855_reo_setup register sequence"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_reo_setup_golden);

fn smoke_ath11k_dp_dscp_tid_map_golden() -> TestResult {
    let io = RecIo::default();
    io.regs.borrow_mut().insert(0x00a4_4014, 0x0000_0101);
    hal_tx_set_dscp_tid_map(&io, 47);
    // dscp >> 3 in eight 3-bit fields per 8 DSCPs (t * 0x249249), packed 3
    // bytes per group: 00 00 00 49 92 24 92 24 49 db b6 6d 24 49 92 6d db
    // b6 b6 6d db ff ff ff.
    let tbl = 0x00a4_402c + 24 * 47;
    let want = [
        Op::R(0x00a4_4014),
        Op::W(0x00a4_4014, 0x0002_0101),
        Op::W(tbl, 0x4900_0000),
        Op::W(tbl + 4, 0x2492_2492),
        Op::W(tbl + 8, 0x6db6_db49),
        Op::W(tbl + 12, 0x6d92_4924),
        Op::W(tbl + 16, 0x6db6_b6db),
        Op::W(tbl + 20, 0xffff_ffdb),
        Op::R(0x00a4_4014),
        Op::W(0x00a4_4014, 0x0000_0101),
    ];
    check!(io.ops() == want, "ath11k_hal_tx_set_dscp_tid_map(47)");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_dscp_tid_map_golden
);

/// The bring-up configuration (Linux sizes): ring registers, the idle
/// list, the REO rings, RX buffer posting and the HTT messages of every
/// ring `ath11k_dp_rx_pdev_alloc` configures.
fn smoke_ath11k_dp_alloc_golden_linux_sizes() -> TestResult {
    let Rig { hal, io, dp, msgs } = rig(DpRingSizes::LINUX);

    // ring ids (enum hal_srng_ring_id)
    check!(
        dp.wbm_idle_ring.ring_id == 104
            && dp.wbm_desc_rel_ring.ring_id == 105
            && dp.tcl_cmd_ring.ring_id == 24
            && dp.tcl_status_ring.ring_id == 25
            && dp.tx_ring[0].tcl_data_ring.ring_id == 16
            && dp.tx_ring[0].tcl_comp_ring.ring_id == 106
            && dp.reo_reinject_ring.ring_id == 5
            && dp.rx_rel_ring.ring_id == 109
            && dp.reo_except_ring.ring_id == 4
            && dp.reo_cmd_ring.ring_id == 8
            && dp.reo_status_ring.ring_id == 9,
        "SOC ring ids"
    );
    check!(
        dp.reo_dst_ring
            .iter()
            .map(|r| r.ring_id)
            .collect::<Vec<_>>()
            == [0, 1, 2, 3],
        "REO2SW1..4"
    );

    // WBM idle list: 32768 requested, clamped to max_entries 0xffff / 2.
    check!(
        dp.wbm_idle_ring.num_entries == 32767,
        "idle ring clamped to 32767"
    );
    check!(dp.wbm_idle_ring.size == 32767 * 8 + 7, "ring->size");
    let banks: Vec<u32> = dp.link_desc_banks.iter().map(|b| b.size).collect();
    check!(
        banks == [0x20_0000, 0x20_0000, 384],
        "link descriptor banks"
    );
    check!(
        dp.link_desc_banks
            .iter()
            .all(|b| b.align_bytes == 0 && b.paddr % 128 == 0),
        "banks 128-byte aligned"
    );
    // 16384 from bank 0, 16382 from bank 1 (ring holds 32766), none from bank 2
    check!(dp.link_desc_posted == 32766, "idle entries posted");
    let idle = umac_src(&io, WBM_IDLE_R0, WBM_IDLE_HP);
    check!(idle.esz == 2 && idle.size == 65534, "idle ring registers");
    check!(
        io.reg(shadow_of(WBM_IDLE_HP)) == 32766 * 2,
        "idle HP published"
    );
    let b0 = dp.link_desc_banks[0].paddr;
    let b1 = dp.link_desc_banks[1].paddr;
    // ath11k_hal_set_link_desc_addr: rbm 1 (WBM_IDLE_DESC_LIST) << 8, bank << 11
    check!(idle.entry(0) == [b0 as u32, 0x100], "idle entry 0 → bank 0");
    check!(
        idle.entry(16383) == [(b0 + 16383 * 128) as u32, 0x100],
        "last bank-0 descriptor"
    );
    check!(
        idle.entry(16384) == [b1 as u32, 0x900],
        "first bank-1 descriptor"
    );
    check!(
        idle.entry(32765) == [(b1 + 16381 * 128) as u32, 0x900],
        "last posted descriptor"
    );
    // WBM idle: SRC init without tp addr; ix0 = OTHER timer 256 | batch 1*2
    check!(
        io.reg(WBM_IDLE_R0 + 0x30) == 0x0100_0002
            && io.reg(WBM_IDLE_R0 + 0x10) == 0x42
            && io.reg(WBM_IDLE_R0 + 0x1c) == 0,
        "idle ring interrupt / misc / no TP address"
    );

    // TX completion ring WBM2SW0 (DST, MSI group 0 → data 14)
    let rdp = hal.rdp.paddr();
    let wrp = hal.wrp.paddr();
    let comp = hal.srng(106).unwrap().ring_base_paddr;
    check!(io.reg(WBM2SW0_R0) == comp as u32, "comp ring base");
    check!(
        io.reg(WBM2SW0_R0 + 4) == (32768 * 8) << 8,
        "comp ring size (words)"
    );
    check!(
        io.reg(WBM2SW0_R0 + 8) == (106 << 8) | 8,
        "comp ring id / entry size"
    );
    // producer int: TX timer 1000 >> 3 = 125, batch 256 * 8
    check!(
        io.reg(WBM2SW0_R0 + 0x24) == 0x007d_0800,
        "comp ring interrupt setup"
    );
    check!(
        io.reg(WBM2SW0_R0 + 0x48) == MSI_ADDR as u32
            && io.reg(WBM2SW0_R0 + 0x4c) == 0x100
            && io.reg(WBM2SW0_R0 + 0x50) == 14,
        "comp ring MSI"
    );
    check!(
        io.reg(WBM2SW0_R0 + 0x14) == (rdp + 106 * 4) as u32 && io.reg(WBM2SW0_R0 + 0x10) == 0x40,
        "comp ring HP address / enable"
    );
    // RX release WBM2SW3: OTHER thresholds (ring_num >= 3), group 0
    check!(
        io.reg(WBM2SW3_R0 + 0x24) == (32 << 16) | 8 && io.reg(WBM2SW3_R0 + 0x50) == 14,
        "rx release ring"
    );

    // TCL data ring (SRC, no MSI): size 512 * 8 words, OTHER thresholds
    let tcl = hal.srng(16).unwrap().ring_base_paddr;
    check!(io.reg(TCL1_R0) == tcl as u32, "tcl base");
    check!(io.reg(TCL1_R0 + 4) == (512 * 8) << 8, "tcl size");
    check!(io.reg(TCL1_R0 + 8) == 8, "tcl entry size");
    check!(io.reg(TCL1_R0 + 0x30) == 0x0100_0008, "tcl ix0");
    check!(io.reg(TCL1_R0 + 0x34) == 0, "tcl ix1");
    check!(
        io.reg(TCL1_R0 + 0x1c) == (rdp + 16 * 4) as u32,
        "tcl TP address"
    );
    check!(io.reg(TCL1_R0 + 0x10) == 0x42, "tcl misc");
    check!(io.reg(TCL1_R0 + 0x48) == 0, "tcl has no MSI");
    let tcl_dev = umac_src(&io, TCL1_R0, TCL1_HP);
    check!(
        (0..512).all(|i| tcl_dev.entry(i)[0] == 0x7288),
        "ath11k_hal_tx_init_data_ring TLV headers"
    );

    // REO command ring: cmd numbers from 1 in word 1
    let cmd = hal.srng(8).unwrap();
    check!(cmd.entry_size == 10, "REO cmd entry 4 + 36 bytes");
    let cmd_base = cmd.ring_base_paddr;
    check!(
        (0..256u64).all(|i| phys_rd32(cmd_base + (i * 10 + 1) * 4) == i as u32 + 1),
        "ath11k_hal_reo_init_cmd_ring"
    );

    // REO destination rings: RX thresholds, groups 7..10 → data 21..24
    for i in 0..4u32 {
        let r0 = REO2SW1_R0 + i * REO_DST_STRIDE;
        check!(io.reg(r0 + 4) == (2048 * 16) << 8, "reo dst size");
        check!(io.reg(r0 + 8) == (i << 8) | 16, "reo dst id");
        check!(io.reg(r0 + 0x24) == 0x003e_0800, "reo dst interrupt setup");
        check!(io.reg(r0 + 0x50) == 21 + i, "reo dst MSI data");
    }
    // REO hw setup + DSCP tables
    check!(
        io.reg(0x00a3_800c) == 0x4321_4321 && io.reg(0x00a3_8010) == 0x4321_4321,
        "REO destination remap"
    );
    check!(
        io.reg(0x00a4_402c) == 0x4900_0000 && io.reg(0x00a4_402c + 24 * 47 + 20) == 0xffff_ffdb,
        "48 DSCP-TID tables"
    );

    // RX buffers: 4095 on the refill ring (cookie = buf id, pdev 0, rbm SW1)
    let pdev = dp.pdev.as_ref().unwrap();
    check!(
        pdev.rx_refill_buf_ring.bufs_max == 4096 && pdev.rx_refill_buf_ring.bufs.len() == 4095,
        "refill ring buffers"
    );
    let refill = lmac(&msgs[0]);
    check!(phys_rd32(wrp) == 4095 * 2, "refill HP in wrp");
    let p1 = dp.rx_buf(1).unwrap().paddr;
    check!(
        refill.entry(0) == [p1 as u32, 0x0c00],
        "refill entry 0: cookie 1"
    );
    let plast = dp.rx_buf(4095).unwrap().paddr;
    check!(
        refill.entry(4094) == [plast as u32, (4095 << 11) | 0x400],
        "refill entry 4094: cookie 4095"
    );
    check!(
        (1..=4095).all(|i| dp.rx_buf(i).unwrap().paddr % 128 == 0),
        "RX buffers 128-byte aligned"
    );
    for (k, m) in pdev.rx_mon_status_refill_ring.iter().enumerate() {
        check!(
            m.bufs_max == 1024 && m.bufs.len() == 1023,
            "mon status buffers"
        );
        let dev = lmac(&msgs[5 + k]);
        // rxdma_ring_buf_setup uses dp->mac_id (0) for both rings' cookies
        check!(dev.entry(0)[1] == 0x0c00, "mon status cookie pdev 0");
    }

    // HTT SRING_SETUP goldens
    let base = |id: u32| hal.srng(id).unwrap().ring_base_paddr as u32;
    let gold: [[u32; 13]; 7] = [
        // refill ring 128: HOST1_TO_FW_RXBUF (5), SW_TO_SW (2), pdev 0
        [
            0x0205_000b,
            base(128),
            0,
            0x0002_2000,
            wrp as u32,
            0,
            (rdp + 128 * 4) as u32,
            0,
            0,
            0,
            0,
            0x003e_0000,
            0x400,
        ],
        // rx_mac_buf ring 129 (mac 0): RXDMA_HOST_BUF (0), SW_TO_HW, pdev 1
        [
            0x0100_010b,
            base(129),
            0,
            0x0202_0800,
            (wrp + 4) as u32,
            0,
            (rdp + 129 * 4) as u32,
            0,
            0,
            0,
            0,
            0x003e_0000,
            0x100,
        ],
        // rx_mac_buf ring 144 (mac 1): pdev 2
        [
            0x0100_020b,
            base(144),
            0,
            0x0202_0800,
            (wrp + 16 * 4) as u32,
            0,
            (rdp + 144 * 4) as u32,
            0,
            0,
            0,
            0,
            0x003e_0000,
            0x100,
        ],
        // rxdma err dst 133: NON_MONITOR_DEST (7), HW_TO_SW, pdev 1, group 0
        [
            0x0007_010b,
            base(133),
            0,
            0x0008_2000,
            (rdp + 133 * 4) as u32,
            0,
            (wrp + 5 * 4) as u32,
            0,
            MSI_ADDR as u32,
            0,
            14,
            0x0020_0008,
            0,
        ],
        // rxdma err dst 148 (mac 1): group 1
        [
            0x0007_020b,
            base(148),
            0,
            0x0008_2000,
            (rdp + 148 * 4) as u32,
            0,
            (wrp + 20 * 4) as u32,
            0,
            MSI_ADDR as u32,
            0,
            15,
            0x0020_0008,
            0,
        ],
        // mon status 132 (start WMAC1_SW2RXDMA1_STATBUF): MONITOR_STATUS (1), SW_TO_HW, pdev 1, group 4
        [
            0x0101_010b,
            base(132),
            0,
            0x0202_0800,
            (wrp + 4 * 4) as u32,
            0,
            (rdp + 132 * 4) as u32,
            0,
            MSI_ADDR as u32,
            0,
            18,
            0x003e_0000,
            0x100,
        ],
        // mon status 147 (mac 1): group 5
        [
            0x0101_020b,
            base(147),
            0,
            0x0202_0800,
            (wrp + 19 * 4) as u32,
            0,
            (rdp + 147 * 4) as u32,
            0,
            MSI_ADDR as u32,
            0,
            19,
            0x003e_0000,
            0x100,
        ],
    ];
    check!(msgs.len() == 7, "seven SRING_SETUP messages");
    for (m, g) in msgs.iter().zip(gold.iter()) {
        let w: Vec<u8> = g.iter().flat_map(|v| v.to_le_bytes()).collect();
        check!(*m == w, "HTT SRING_SETUP golden");
    }

    // ath11k_mac_config_mon_status_default
    let on = dp.mon_status_default_msgs(&hal, true).unwrap();
    let off = dp.mon_status_default_msgs(&hal, false).unwrap();
    let g = |pdev: u32, f: [u32; 5]| -> Vec<u8> {
        [
            0x0001_000c | (pdev << 8),
            2048,
            f[0],
            f[1],
            f[2],
            f[3],
            f[4],
        ]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect()
    };
    let deflt = [0x0904_9249, 0x1249, 0x0920_0000, 0x0124_9249, 0x1201];
    check!(
        on == [g(1, deflt), g(2, deflt)],
        "RX_RING_SELECTION_CFG default filter"
    );
    check!(
        off == [g(1, [0; 5]), g(2, [0; 5])],
        "filter cleared on stop"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_alloc_golden_linux_sizes
);

fn smoke_ath11k_dp_setup_rejects() -> TestResult {
    let mut r = rig(SMALL);
    let e = r.dp.pdev_reo_setup(&mut r.hal, &r.io).unwrap_err();
    check!(
        e.step == step::ALREADY_SET_UP && e.detail == 1,
        "second REO setup"
    );
    let e = r.dp.pdev_alloc(&mut r.hal, &r.io, 0).unwrap_err();
    check!(
        e.step == step::ALREADY_SET_UP && e.detail == 2,
        "second pdev alloc"
    );
    // A second Dp on the same HAL hits RING_IN_USE (HAL step 88) first.
    let cfg = DpHwParams::for_rev(HwRev::Wcn6855Hw21).unwrap();
    let e = Dp::alloc(&mut r.hal, &r.io, &cfg, SMALL, None).unwrap_err();
    check!(
        e.step == step::SRNG_SETUP
            && e.detail == ((HalRingType::WbmIdleLink as u32) << 24) | 88
            && e.errno == errno::EINVAL,
        "ring already set up"
    );
    // The idle list would need the scatter path (> 2 MiB of entries).
    let mut hal = Hal::new(&cfg.hw).unwrap();
    let io = RecIo::default();
    let big = DpRingSizes {
        n_link_desc: Some(DP_LINK_DESC_ALLOC_SIZE_THRESH / 8 + 1),
        ..SMALL
    };
    let e = Dp::alloc(&mut hal, &io, &cfg, big, None).unwrap_err();
    check!(
        e.step == step::LINK_DESC_BANKS || e.step == step::SCATTER_UNSUPPORTED,
        "scatter idle list not ported"
    );
    // Without MSI the data rings carry no MSI.
    let mut hal = Hal::new(&cfg.hw).unwrap();
    let io = RecIo::default();
    let dp = Dp::alloc(&mut hal, &io, &cfg, SMALL, None).unwrap();
    check!(
        io.reg(WBM2SW0_R0 + 0x48) == 0
            && hal.srng(dp.tx_ring[0].tcl_comp_ring.ring_id).unwrap().flags & flags::MSI_INTR == 0,
        "no MSI programmed"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_setup_rejects);

// ── RX ────────────────────────────────────────────────────────────

fn smoke_ath11k_dp_rx_replenish_cookies() -> TestResult {
    let mut r = rig(SMALL);
    let mut refill = lmac(&r.msgs[0]);
    check!(refill.pending(&r.io) == 15, "15 of 16 entries posted");
    for i in 0..15u32 {
        let w = refill.entry(i);
        let (pa, cookie, mgr) = buf_addr_get(w[0], w[1]);
        check!(
            cookie == i + 1
                && mgr == rbm::SW1_BM
                && Some(pa) == r.dp.rx_buf(i + 1).map(|b| b.paddr),
            "cookie = pdev 0 | buf id, rbm SW1, buffer address"
        );
    }
    // Ring full: nothing more fits.
    check!(
        {
            r.dp.replenish_refill(&mut r.hal, &r.io, 4);
            r.dp.pdev.as_ref().unwrap().rx_refill_buf_ring.bufs.len() == 15
        },
        "full refill ring takes nothing"
    );
    // Firmware takes 3; the host tops up with fresh ids 16..18 (IDR range
    // [1, 3 * 16 + 1)).
    for _ in 0..3 {
        fw_take(&r.io, &mut refill);
    }
    r.dp.replenish_refill(&mut r.hal, &r.io, 3);
    check!(refill.pending(&r.io) == 15, "three reposted");
    let ids: Vec<u32> = (15..18)
        .map(|i| {
            let w = refill.entry(i % 16);
            buf_addr_get(w[0], w[1]).1
        })
        .collect();
    check!(
        ids == [16, 17, 18],
        "new buffer ids continue after the posted ones"
    );
    // req_entries = 0 tops up only when more than 3/4 is free.
    for _ in 0..4 {
        fw_take(&r.io, &mut refill);
    }
    r.dp.replenish_refill(&mut r.hal, &r.io, 0);
    check!(refill.pending(&r.io) == 11, "0 = no top-up at 4/15 free");
    for _ in 0..9 {
        fw_take(&r.io, &mut refill);
    }
    r.dp.replenish_refill(&mut r.hal, &r.io, 0);
    check!(
        refill.pending(&r.io) == 15,
        "0 = refill everything when > 3/4 free"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_rx_replenish_cookies
);

fn smoke_ath11k_dp_rx_reap_nwifi_and_eth() -> TestResult {
    let mut r = rig(SMALL);
    let mut refill = lmac(&r.msgs[0]);
    let mut reo = umac_dst(&r.io, REO2SW1_R0, REO2SW1_TP);
    check!(
        reo.esz == 16 && reo.size == 16 * 16,
        "REO2SW1 from registers"
    );

    let payload = [0x45u8, 0x00, 0x00, 0x14, 1, 2, 3, 4];
    let msdu = nwifi_msdu(0x0800, &payload);
    let mut d = good_rxd(msdu.len(), 1);
    d.l3pad = 2;
    d.seq = 77;
    deliver(&r.io, &mut refill, &mut reo, &d, &msdu);
    let eapol = eth_frame(0x888e, &[1, 3, 0, 0x5f]);
    deliver(
        &r.io,
        &mut refill,
        &mut reo,
        &good_rxd(eapol.len(), 2),
        &eapol,
    );

    let (n, rx) = r.dp.process_rx(&mut r.hal, &r.io, 0, 64);
    check!(n == 2 && rx.len() == 2, "two MSDUs reaped");
    check!(
        rx[0].frame == eth_frame(0x0800, &payload),
        "native wifi → Ethernet II (DA = addr1, SA = addr3, SNAP type)"
    );
    check!(
        rx[0].peer_id == 3 && rx[0].seq_no == 5 && rx[0].tid == 0 && rx[0].freq == 5180,
        "REO metadata + rx_desc freq"
    );
    check!(
        rx[0].decap == 1 && !rx[0].decrypted && rx[0].csum_ok && !rx[0].is_mcbc && !rx[0].is_eapol,
        "flags"
    );
    check!(
        rx[1].frame == eapol && rx[1].is_eapol,
        "Ethernet II passthrough, EAPOL flagged"
    );
    // TP published through the REO2SW1 shadow register, buffers reposted.
    check!(
        r.io.reg(shadow_of(REO2SW1_TP)) == 2 * 16,
        "REO TP published"
    );
    check!(refill.pending(&r.io) == 15, "two buffers replenished");
    // idr_alloc hands out the lowest free ids: 1 and 2 again, in the two
    // slots after the old HP (15, 0).
    let c15 = buf_addr_get(refill.entry(15)[0], refill.entry(15)[1]).1;
    let c0 = buf_addr_get(refill.entry(0)[0], refill.entry(0)[1]).1;
    check!(c15 == 1 && c0 == 2, "reaped ids reposted");
    check!(
        r.dp.pdev.as_ref().unwrap().rx_refill_buf_ring.bufs.len() == 15,
        "no buffer leak"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_rx_reap_nwifi_and_eth
);

fn smoke_ath11k_dp_rx_decrypted_mcbc_peer() -> TestResult {
    let mut r = rig(SMALL);
    // PEER_MAP v1 for the AP: vdev 0, peer 3
    let m = [0x0003_0003u32, 0x0000_0002, 0x0000_aa00];
    let mb: Vec<u8> = m.iter().flat_map(|v| v.to_le_bytes()).collect();
    check!(
        matches!(
            r.dp.htt_t2h_msg_handler(&mb),
            Ok(htt::HttT2h::PeerMap { peer_id: 3, .. })
        ),
        "peer map"
    );
    check!(
        r.dp.peer_by_id(3).map(|p| p.addr) == Some(BSSID),
        "peer table"
    );
    check!(r.dp.set_peer_sec_type(3, 6, 6), "CCMP-128 keys");
    let mut refill = lmac(&r.msgs[0]);
    let mut reo = umac_dst(&r.io, REO2SW1_R0, REO2SW1_TP);
    let msdu = nwifi_msdu(0x0806, &[0; 28]);
    let mut d = good_rxd(msdu.len(), 1);
    d.attn1 = 1 << 2; // MCAST_BCAST
    d.sw_peer_id = 3;
    d.seq = 0x123;
    deliver(&r.io, &mut refill, &mut reo, &d, &msdu);
    let (_, rx) = r.dp.process_rx(&mut r.hal, &r.io, 0, 64);
    check!(rx.len() == 1, "delivered");
    check!(
        rx[0].is_mcbc && rx[0].decrypted && rx[0].peer_id == 3 && rx[0].seq_no == 0x123,
        "mcbc: peer / seq from mpdu_start, group cipher, decrypt status OK"
    );
    // Unmap; an unknown unmap is counted.
    let u: Vec<u8> = [0x0003_0004u32]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    r.dp.htt_t2h_msg_handler(&u).unwrap();
    r.dp.htt_t2h_msg_handler(&u).unwrap();
    check!(
        r.dp.peers.is_empty() && r.dp.stats.htt_peer_unmap_unknown == 1,
        "peer unmap"
    );
    let v: Vec<u8> = [0x0003_0000u32]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    r.dp.htt_t2h_msg_handler(&v).unwrap();
    check!(r.dp.htt.version_ok() == Ok(true), "VERSION_CONF recorded");
    let x: Vec<u8> = [0x0000_0042u32]
        .iter()
        .flat_map(|v| v.to_le_bytes())
        .collect();
    check!(
        r.dp.htt_t2h_msg_handler(&x) == Ok(htt::HttT2h::Unhandled(0x42))
            && r.dp.stats.htt_unhandled == 1,
        "unknown T2H counted"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_rx_decrypted_mcbc_peer
);

fn smoke_ath11k_dp_rx_continuation_coalesce() -> TestResult {
    let mut r = rig(SMALL);
    let mut refill = lmac(&r.msgs[0]);
    let mut reo = umac_dst(&r.io, REO2SW1_R0, REO2SW1_TP);
    // 3000-byte Ethernet MSDU over two buffers: 1656 (2048 - 392) + 1344.
    let frame: Vec<u8> = {
        let p: Vec<u8> = (0..3000 - 14).map(|i| i as u8).collect();
        eth_frame(0x0800, &p)
    };
    let (pa1, c1) = fw_take(&r.io, &mut refill);
    let (pa2, c2) = fw_take(&r.io, &mut refill);
    let mut d1 = good_rxd(3000, 2);
    d1.last = false;
    let mut b1 = rx_desc_bytes(&d1);
    b1.extend_from_slice(&frame[..1656]);
    phys_write(pa1, &b1);
    // Only the last buffer's attention / msdu_end are valid.
    let mut d2 = good_rxd(0, 2);
    d2.first = false;
    let mut b2 = rx_desc_bytes(&d2);
    b2.extend_from_slice(&frame[1656..]);
    phys_write(pa2, &b2);
    check!(
        reo.produce(
            &r.io,
            &reo_dest(pa1, c1, FIRST | CONT | (2048 << 3), 1, 0, 3)
        ) && reo.produce(&r.io, &reo_dest(pa2, c2, LAST | (1344 << 3), 1, 0, 3)),
        "two REO entries"
    );
    let (n, rx) = r.dp.process_rx(&mut r.hal, &r.io, 0, 64);
    check!(n == 1 && rx.len() == 1, "one MSDU from two buffers");
    check!(rx[0].frame == frame, "coalesced payload");
    check!(refill.pending(&r.io) == 15, "both buffers replenished");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_rx_continuation_coalesce
);

fn smoke_ath11k_dp_rx_negatives() -> TestResult {
    let mut r = rig(SMALL);
    let mut refill = lmac(&r.msgs[0]);
    let mut reo = umac_dst(&r.io, REO2SW1_R0, REO2SW1_TP);
    let msdu = nwifi_msdu(0x0800, &[0; 20]);

    // Unknown cookie (buffer id never posted) and buffer id 0: skipped.
    check!(
        reo.produce(&r.io, &reo_dest(0x1000, 300, FIRST | LAST, 1, 0, 3))
            && reo.produce(&r.io, &reo_dest(0x1000, 0, FIRST | LAST, 1, 0, 3)),
        "bad cookies"
    );
    // Push reason ERR_DETECTED on a REO destination ring: dropped.
    let (pa, c) = fw_take(&r.io, &mut refill);
    check!(
        reo.produce(&r.io, &reo_dest(pa, c, FIRST | LAST, 0, 0, 3)),
        "err push"
    );
    // msdu_done clear.
    let mut nd = good_rxd(msdu.len(), 1);
    nd.not_done = true;
    deliver(&r.io, &mut refill, &mut reo, &nd, &msdu);
    // MSDU_LEN error in attention.
    let mut le = good_rxd(msdu.len(), 1);
    le.attn1 = 1 << 17;
    deliver(&r.io, &mut refill, &mut reo, &le, &msdu);
    // Length past the buffer without continuation.
    let mut big = good_rxd(1700, 1);
    big.msdu_len = 1700;
    deliver(&r.io, &mut refill, &mut reo, &big, &msdu);
    // FCS error, TKIP MIC error: dropped as mac80211 would.
    let mut fcs = good_rxd(msdu.len(), 1);
    fcs.attn1 = 1 << 31;
    deliver(&r.io, &mut refill, &mut reo, &fcs, &msdu);
    let mut mic = good_rxd(msdu.len(), 1);
    mic.attn1 = 1 << 28;
    deliver(&r.io, &mut refill, &mut reo, &mic, &msdu);
    // Raw decap (only reassembled fragments arrive raw on a station):
    // ath11k_dp_rx_h_undecap_raw drops the FCS, then 802.11 → 802.3.
    deliver(
        &r.io,
        &mut refill,
        &mut reo,
        &good_rxd(msdu.len(), 0),
        &msdu,
    );
    // Native wifi frame shorter than its 802.11 header.
    deliver(&r.io, &mut refill, &mut reo, &good_rxd(10, 1), &msdu[..10]);

    let (n, rx) = r.dp.process_rx(&mut r.hal, &r.io, 0, 64);
    let s = &r.dp.stats;
    check!(
        rx.len() == 1 && rx[0].decap == 0 && rx[0].frame.len() == ETH_HLEN + 20 - 4,
        "only the raw MPDU delivered, FCS trimmed"
    );
    // Entries skipped for their cookie or push reason are not counted.
    check!(n == 7, "seven MSDUs reaped");
    check!(
        s.rx_invalid_cookie == 1,
        "invalid buf_id counted (buf_id 0 silently)"
    );
    check!(s.hal_reo_error[0] == 1, "hal_reo_error[ring]");
    check!(s.rx_msdu_not_done == 1, "msdu_done");
    check!(s.rx_msdu_len_err == 1, "msdu len err");
    check!(s.rx_invalid_len == 1, "invalid msdu len");
    check!(s.rx_fcs_err == 1 && s.rx_mic_err == 1, "FCS / MIC");
    check!(s.rx_decap_unsupported == 1, "short header");
    check!(
        refill.pending(&r.io) == 15,
        "every reaped buffer replenished"
    );

    // A continuation with no last buffer in the reaped list (the ring
    // ends mid-MPDU after a complete MSDU): -EIO for the chain.
    let good = nwifi_msdu(0x0800, &[1; 4]);
    deliver(
        &r.io,
        &mut refill,
        &mut reo,
        &good_rxd(good.len(), 1),
        &good,
    );
    let (pa, c) = fw_take(&r.io, &mut refill);
    let mut d = good_rxd(3000, 2);
    d.last = false;
    phys_write(pa, &rx_desc_bytes(&d));
    check!(
        reo.produce(&r.io, &reo_dest(pa, c, FIRST | CONT, 1, 0, 3)),
        "lone continuation"
    );
    let (n, rx) = r.dp.process_rx(&mut r.hal, &r.io, 0, 64);
    check!(n == 1 && rx.len() == 1, "the complete MSDU is delivered");
    check!(
        r.dp.stats.rx_no_last_buf == 1,
        "\"No valid Rx buffer\" (-EIO)"
    );

    // Coalesce overflow: a last buffer carrying more than 2048 - 392.
    let (pa1, c1) = fw_take(&r.io, &mut refill);
    let (pa2, c2) = fw_take(&r.io, &mut refill);
    let mut d1 = good_rxd(3400, 2);
    d1.last = false;
    phys_write(pa1, &rx_desc_bytes(&d1));
    phys_write(pa2, &rx_desc_bytes(&good_rxd(0, 2)));
    check!(
        reo.produce(&r.io, &reo_dest(pa1, c1, FIRST | CONT, 1, 0, 3))
            && reo.produce(&r.io, &reo_dest(pa2, c2, LAST, 1, 0, 3)),
        "overflowing chain"
    );
    let (n, rx) = r.dp.process_rx(&mut r.hal, &r.io, 0, 64);
    check!(n == 1 && rx.is_empty(), "nothing delivered");
    check!(
        r.dp.stats.rx_coalesce_err == 1,
        "rem 1744 > 1656 is -EINVAL"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_rx_negatives);

fn smoke_ath11k_dp_rx_ring_wraparound() -> TestResult {
    let mut r = rig(SMALL);
    let mut refill = lmac(&r.msgs[0]);
    let mut reo = umac_dst(&r.io, REO2SW1_R0, REO2SW1_TP);
    let mut seen = 0u32;
    for round in 0..12u8 {
        for k in 0..5u8 {
            let p = [round, k, 0xee, 0xff];
            let msdu = nwifi_msdu(0x88b5, &p);
            deliver(
                &r.io,
                &mut refill,
                &mut reo,
                &good_rxd(msdu.len(), 1),
                &msdu,
            );
        }
        let (n, rx) = r.dp.process_rx(&mut r.hal, &r.io, 0, 3);
        let (n2, rx2) = r.dp.process_rx(&mut r.hal, &r.io, 0, 64);
        check!(n == 3 && n2 == 2, "budget honoured");
        for (k, m) in rx.iter().chain(rx2.iter()).enumerate() {
            check!(
                m.frame == eth_frame(0x88b5, &[round, k as u8, 0xee, 0xff]),
                "in-order payload"
            );
            seen += 1;
        }
    }
    check!(
        seen == 60,
        "60 frames through a 16-entry REO ring and refill ring"
    );
    check!(refill.pending(&r.io) == 15, "refill ring topped up");
    check!(
        r.dp.pdev.as_ref().unwrap().rx_refill_buf_ring.bufs.len() == 15,
        "no buffer leak"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_rx_ring_wraparound
);

/// WBM release entry for an RX error (`struct hal_wbm_release_ring`).
fn wbm_rx_err(pa: u64, cookie: u32, mgr: u32, src: u32, push: u32, code: u32) -> [u32; 8] {
    let mut w = [0u32; 8];
    w[0] = pa as u32;
    w[1] = (mgr << 8) | (cookie << 11);
    w[2] = src
        | if src == 2 {
            (push << 24) | (code << 26)
        } else {
            (push << 17) | (code << 19)
        };
    w
}

fn smoke_ath11k_dp_rx_wbm_err_null_q_desc() -> TestResult {
    let mut r = rig(SMALL);
    let mut refill = lmac(&r.msgs[0]);
    let mut rel = umac_dst(&r.io, WBM2SW3_R0, WBM2SW3_TP);
    let msdu = nwifi_msdu(0x0800, &[9; 12]);
    let mut put =
        |r: &Rig, refill: &mut DevRing, d: &Rxd, mgr: u32, src: u32, push: u32, code: u32| {
            let (pa, c) = fw_take(&r.io, refill);
            let mut b = rx_desc_bytes(d);
            b.extend_from_slice(&msdu);
            phys_write(pa, &b);
            assert!(rel.produce(&r.io, &wbm_rx_err(pa, c, mgr, src, push, code)));
        };
    let mut d = good_rxd(msdu.len(), 1);
    d.tid = 6;
    // REO, ERR_DETECTED, DESC_ADDR_ZERO (no TID queue): delivered.
    put(&r, &mut refill, &d, 4, 2, 0, 0);
    // PN check failed: dropped.
    put(&r, &mut refill, &d, 4, 2, 0, 11);
    // RXDMA TKIP MIC: dropped (no countermeasures).
    put(&r, &mut refill, &d, 4, 1, 0, 4);
    // RXDMA FCS error: dropped.
    put(&r, &mut refill, &d, 4, 1, 0, 2);
    // Wrong return buffer manager (SW0): parse error, buffer not taken.
    put(&r, &mut refill, &d, 3, 2, 0, 0);
    // Routing push reason on the error ring: buffer freed, not processed.
    put(&r, &mut refill, &d, 4, 2, 1, 0);

    let (n, rx) = r.dp.rx_process_wbm_err(&mut r.hal, &r.io, 64);
    let s = &r.dp.stats;
    check!(n == 5, "five buffers reaped (the bad-rbm one is not)");
    check!(rx.len() == 1, "one MSDU delivered");
    check!(
        rx[0].frame == eth_frame(0x0800, &[9; 12]) && rx[0].from_err_path && rx[0].tid == 6,
        "null-queue MSDU: Ethernet, TID from mpdu_start"
    );
    check!(s.reo_error[0] == 1 && s.reo_error[11] == 1, "reo_error[]");
    check!(
        s.rxdma_error[4] == 1 && s.rxdma_error[2] == 1,
        "rxdma_error[]"
    );
    check!(s.rx_mic_err == 1, "TKIP MIC dropped");
    check!(s.invalid_rbm == 1 && s.wbm_err_parse == 1, "bad rbm");
    check!(
        r.io.reg(shadow_of(WBM2SW3_TP)) == 6 * 8,
        "release ring TP published"
    );
    check!(
        refill.pending(&r.io) == 15 - 1,
        "5 replenished (the stranded buffer stays out)"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_rx_wbm_err_null_q_desc
);

/// Firmware side: take a link descriptor from the WBM idle list and fill
/// it as an MSDU link (`struct hal_rx_msdu_link`) naming `cookies`.
fn fill_link_desc(io: &RecIo, idle: &mut DevRing, cookies: &[u32], mgr: u32) -> [u32; 2] {
    let w = idle.consume(io).expect("idle link descriptor");
    let (pa, _bank, _) = buf_addr_get(w[0], w[1]);
    let mut b = vec![0u8; 128];
    for (i, &c) in cookies.iter().enumerate() {
        let o = 32 + 16 * i;
        put32(&mut b, o, 0x1000 + i as u32);
        put32(&mut b, o + 4, (mgr << 8) | (c << 11));
    }
    if cookies.is_empty() {
        put32(&mut b, 36, mgr << 8);
    }
    phys_write(pa, &b);
    [w[0], w[1]]
}

fn smoke_ath11k_dp_rxdma_err_link_desc_return() -> TestResult {
    let mut r = rig(SMALL);
    let mut refill = lmac(&r.msgs[0]);
    let mut idle = umac_src(&r.io, WBM_IDLE_R0, WBM_IDLE_HP);
    let mut err = lmac(&r.msgs[3]);
    let mut sw2wbm = umac_src(&r.io, SW2WBM_R0, SW2WBM_HP);
    check!(err.esz == 8 && sw2wbm.esz == 8, "rings from programming");
    let (_, c1) = fw_take(&r.io, &mut refill);
    let (_, c2) = fw_take(&r.io, &mut refill);
    let link = fill_link_desc(&r.io, &mut idle, &[c1, c2], 4);
    // hal_reo_entrance_ring: buf_addr_info = the link descriptor, info1
    // RXDMA error code 3 (DECRYPT) in bits 6:2.
    let mut e = [0u32; 8];
    e[0] = link[0];
    e[1] = link[1];
    e[6] = 3 << 2;
    check!(err.produce(&r.io, &e), "rxdma err entry");
    let n = r.dp.process_rxdma_err(&mut r.hal, &r.io, 0, 64);
    check!(
        n == 2,
        "Linux returns processed + 1 (quota-- post-decrement)"
    );
    check!(r.dp.stats.rxdma_error[3] == 1, "rxdma_error[DECRYPT]");
    // Freed ids are the lowest free ones, so the replenish reposts them
    // in the two slots after the old HP (15, 0).
    let cook = |i: u32| buf_addr_get(refill.entry(i)[0], refill.entry(i)[1]).1;
    check!(
        cook(15) == c1 && cook(0) == c2,
        "both MSDU buffers freed and their ids reposted"
    );
    check!(refill.pending(&r.io) == 15, "and replenished");
    let ret = sw2wbm.consume(&r.io).expect("link descriptor returned");
    // info0 = REL_SRC SW (4) | BM_ACTION PUT_IN_IDLE (0) << 3 | DESC_TYPE MSDU_LINK (1) << 6
    check!(
        ret[0] == link[0] && ret[1] == link[1] && ret[2] == 0x44,
        "ath11k_hal_rx_msdu_link_desc_set words"
    );
    // TP of the err ring (wrp) moved.
    check!(err.host(&r.io) == 8, "err ring TP published");

    // A link descriptor outside every bank: counted, still returned.
    let mut e2 = [0u32; 8];
    e2[0] = 0x10;
    e2[1] = 7 << 11; // bank 7
    check!(err.produce(&r.io, &e2), "bad bank");
    r.dp.process_rxdma_err(&mut r.hal, &r.io, 0, 64);
    check!(
        r.dp.stats.link_desc_lookup_fail == 1,
        "lookup failure counted"
    );
    check!(sw2wbm.consume(&r.io).is_some(), "returned anyway");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_rxdma_err_link_desc_return
);

fn smoke_ath11k_dp_reo_exception_drop() -> TestResult {
    let mut r = rig(SMALL);
    let mut refill = lmac(&r.msgs[0]);
    let mut idle = umac_src(&r.io, WBM_IDLE_R0, WBM_IDLE_HP);
    let mut exc = umac_dst(&r.io, REO2TCL_R0, REO2TCL_TP);
    let mut sw2wbm = umac_src(&r.io, SW2WBM_R0, SW2WBM_HP);
    let ent = |link: [u32; 2], push: u32, btype: u32, frag: bool| -> [u32; 16] {
        let mut w = [0u32; 16];
        w[0] = link[0];
        w[1] = link[1];
        w[2] = (frag as u32) << 20;
        w[7] = (btype << 8) | (push << 9) | (5 << 11); // error code 5 (2K jump)
        w
    };
    let (_, c1) = fw_take(&r.io, &mut refill);
    let l1 = fill_link_desc(&r.io, &mut idle, &[c1], 4);
    check!(exc.produce(&r.io, &ent(l1, 0, 1, false)), "exception entry");
    // Invalid rbm in the link descriptor (SW0): returned REL_MSDU.
    let (_, c2) = fw_take(&r.io, &mut refill);
    let l2 = fill_link_desc(&r.io, &mut idle, &[c2], 3);
    check!(exc.produce(&r.io, &ent(l2, 0, 1, false)), "bad rbm entry");
    // Buffer type MSDU: parse error.
    check!(
        exc.produce(&r.io, &ent(l1, 0, 0, false)),
        "msdu buffer type"
    );
    // A single-MSDU fragment after a dropped entry: Linux's `drop` stays
    // set for the rest of the pass, so it is freed and its link
    // descriptor not returned (quirk kept).
    let (_, c3) = fw_take(&r.io, &mut refill);
    let l3 = fill_link_desc(&r.io, &mut idle, &[c3], 4);
    check!(exc.produce(&r.io, &ent(l3, 0, 1, true)), "fragment");

    let n = r.dp.process_rx_err(&mut r.hal, &r.io, 64);
    let s = &r.dp.stats;
    check!(n == 2, "two buffers reaped");
    check!(
        s.err_ring_pkts == 4 && s.reo_error[5] == 4,
        "every entry counted"
    );
    check!(
        s.reo_err_parse == 1 && s.invalid_rbm == 1,
        "parse / rbm errors"
    );
    check!(
        s.rx_err_frags_dropped == 0,
        "the fragment never reached reassembly"
    );
    let cook = |i: u32| buf_addr_get(refill.entry(i)[0], refill.entry(i)[1]).1;
    check!(cook(15) == c1 && cook(0) == c3, "freed MSDU ids reposted");
    check!(r.dp.rx_buf(c2).is_some(), "bad-rbm MSDU not touched");
    let a = sw2wbm.consume(&r.io).unwrap();
    let b = sw2wbm.consume(&r.io).unwrap();
    check!(
        a[..2] == l1 && a[2] == 0x44 && b[..2] == l2 && b[2] == 0x4c,
        "PUT_IN_IDLE, REL_MSDU (0x4c)"
    );
    check!(sw2wbm.consume(&r.io).is_none(), "two returns");

    // A lone fragment in a new pass reaches ath11k_dp_rx_frag_h_mpdu,
    // which refuses it (no descriptor of a known peer): freed, link
    // descriptor returned PUT_IN_IDLE.
    let (pa4, c4) = fw_take(&r.io, &mut refill);
    phys_write(pa4, &rx_desc_bytes(&good_rxd(30, 0)));
    let l4 = fill_link_desc(&r.io, &mut idle, &[c4], 4);
    check!(exc.produce(&r.io, &ent(l4, 0, 1, true)), "lone fragment");
    check!(r.dp.process_rx_err(&mut r.hal, &r.io, 64) == 1, "reaped");
    check!(
        r.dp.stats.rx_err_frags_dropped == 1,
        "refused by frag_h_mpdu"
    );
    let c = sw2wbm.consume(&r.io).unwrap();
    check!(c[..2] == l4 && c[2] == 0x44, "returned PUT_IN_IDLE");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_reo_exception_drop
);

fn smoke_ath11k_dp_link_desc_return_full() -> TestResult {
    let mut r = rig(SMALL);
    // SW2WBM ring of 16 takes 15 without the hardware consuming.
    for i in 0..15 {
        check!(
            r.dp.link_desc_return(&mut r.hal, &r.io, [i, 0], 0).is_ok(),
            "link desc return"
        );
    }
    let e =
        r.dp.link_desc_return(&mut r.hal, &r.io, [99, 0], 0)
            .unwrap_err();
    check!(
        e.step == step::LINK_DESC_RETURN
            && e.errno == errno::ENOBUFS
            && r.dp.stats.link_desc_return_fail == 1,
        "full SW2WBM ring is -ENOBUFS"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_link_desc_return_full
);

fn smoke_ath11k_dp_reo_status() -> TestResult {
    let mut r = rig(SMALL);
    let mut st = umac_dst(&r.io, REO_STATUS_R0, REO_STATUS_TP);
    check!(st.esz == 26, "REO status entry: TLV + 100 bytes");
    let ent = |tag: u32, num: u32, status: u32| -> Vec<u32> {
        let mut w = vec![0u32; 26];
        w[0] = tag << 1;
        w[1] = num | (status << 26);
        w
    };
    check!(
        st.produce(&r.io, &ent(0x137, 5, 1))
            && st.produce(&r.io, &ent(0x123, 6, 0))
            && st.produce(&r.io, &ent(0x99, 7, 2)),
        "status entries"
    );
    let out = r.dp.process_reo_status(&mut r.hal, &r.io);
    check!(
        out == [
            ReoStatus {
                tag: 0x137,
                cmd_num: 5,
                cmd_status: 1
            },
            ReoStatus {
                tag: 0x99,
                cmd_num: 7,
                cmd_status: 2
            },
        ],
        "uniform headers"
    );
    check!(r.dp.stats.reo_status_unknown == 1, "unknown tag skipped");
    check!(r.io.reg(shadow_of(REO_STATUS_TP)) == 3 * 26, "TP published");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_reo_status);

fn smoke_ath11k_dp_mon_status_reap() -> TestResult {
    let mut r = rig(SMALL);
    let mut mon = lmac(&r.msgs[5]);
    check!(mon.pending(&r.io) == 7, "7 of 8 status buffers posted");
    // The hardware fills two status buffers: the first DONE, the second
    // not yet.
    let a = mon.consume(&r.io).unwrap();
    let b = mon.consume(&r.io).unwrap();
    phys_wr32(buf_addr_get(a[0], a[1]).0, 0x140 << 1); // HAL_RX_STATUS_BUFFER_DONE
    phys_wr32(buf_addr_get(b[0], b[1]).0, 0);
    let mut budget = 8;
    let n = r.dp.reap_mon_status(&mut r.hal, &r.io, 0, &mut budget);
    // HP slot (never filled) refilled, then slot 0 DONE reaped + refilled,
    // then slot 1: next peek would hit TP → stop.
    check!(n == 2, "two slots refilled");
    check!(r.dp.stats.mon_status_reaped == 1, "one DONE buffer");
    let ring = &r.dp.pdev.as_ref().unwrap().rx_mon_status_refill_ring[0];
    check!(ring.bufs.len() == 8, "7 posted + 1 new - 1 reaped + 1 new");
    check!(mon.pending(&r.io) == 7, "HP advanced over both slots");
    let e = mon.entry(0);
    let (pa, cookie, mgr) = buf_addr_get(e[0], e[1]);
    // HP slot 7 got id 0 (IDR range [0, bufs_max)), slot 0 the reaped id 1.
    let e7 = mon.entry(7);
    check!(
        cookie == 1
            && mgr == rbm::SW1_BM
            && ring.bufs.find(1).map(|b| b.paddr) == Some(pa)
            && buf_addr_get(e7[0], e7[1]).1 == 0,
        "refilled slots"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_mon_status_reap);

// ── TX ────────────────────────────────────────────────────────────

fn eth_meta() -> TxMeta {
    TxMeta {
        encap: TxEncap::Ethernet,
        priority: 5,
        queue: 1,
        ring_selector: 0,
        csum_partial: true,
        pdev_idx: 0,
        lmac_id: 0,
    }
}

fn smoke_ath11k_dp_tx_desc_golden() -> TestResult {
    let mut r = rig(SMALL);
    let mut vif = VifTx::attach(0, 0, false);
    check!(
        vif.tcl_metadata == 1 && vif.hal_addr_search_flags == 2 && vif.search_type == 0,
        "STA vif: TYPE 1, ADDRY_EN, SEARCH_DEFAULT"
    );
    check!(
        VifTx::attach(3, 1, true).tcl_metadata == (1 | 3 << 2 | 1 << 10),
        "vdev / pdev in TCL metadata"
    );
    vif.ast_hash = 0x5;
    vif.ast_idx = 0x123;
    let frame = eth_frame(0x0800, &[0x5a; 46]);
    let id =
        r.dp.tx(&mut r.hal, &r.io, &vif, &eth_meta(), &frame, 0)
            .expect("tx");
    // desc_id = MAC 0 | MSDU 0 << 2 | POOL (queue 1 & 3) << 19
    check!(id == 0x8_0000, "TX descriptor id");
    let mut tcl = umac_src(&r.io, TCL1_R0, TCL1_HP);
    check!(
        r.io.reg(shadow_of(TCL1_HP)) == 8,
        "TCL HP published through the shadow register"
    );
    let w = tcl.consume(&r.io).expect("TCL entry");
    let pa = buf_addr_get(w[1], w[2]).0;
    let want = [
        0x7288,
        pa as u32,
        // rbm SW0 (3) << 8 | desc_id << 11
        0x300 | (0x8_0000 << 11),
        // DESC_TYPE 0 | ENCAP ETHERNET (2) << 2 | ENCRYPT 0 | SEARCH 0 |
        // ADDR_EN ADDRY (2) << 14 | CMD_NUM (tcl_metadata 1) << 16
        0x0001_8008,
        // checksum offload bits 16..20 | data_len 60
        0x001f_003c,
        // TID_OVERWRITE (21) | TID 5 << 22 | LMAC 0
        0x0160_0000,
        // SEARCH_INDEX 0x123 << 6 | CACHE_SET_NUM (hash 5) << 26
        0x1400_48c0,
        0,
    ];
    check!(w == want, "hal_tcl_data_cmd golden");
    let mut got = vec![0u8; frame.len()];
    phys_read(pa, &mut got);
    check!(got == frame, "bounce buffer holds the frame");
    check!(
        r.dp.pdev.as_ref().unwrap().num_tx_pending == 1,
        "num_tx_pending"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_tx_desc_golden);

fn smoke_ath11k_dp_tx_native_wifi() -> TestResult {
    let mut r = rig(SMALL);
    let vif = VifTx::attach(0, 0, false);
    let meta = TxMeta {
        encap: TxEncap::NativeWifi,
        csum_partial: false,
        priority: 0x16,
        ..eth_meta()
    };
    // QoS data, ToDS: fc 0x0188, 24-byte header + QoS ctl (tid 6) + body
    let mut f = vec![0x88, 0x01, 0, 0];
    f.extend_from_slice(&BSSID);
    f.extend_from_slice(&STA);
    f.extend_from_slice(&SRC);
    f.extend_from_slice(&[0x20, 0x00, 0x06, 0x00]);
    f.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x00, 1, 2, 3]);
    r.dp.tx(&mut r.hal, &r.io, &vif, &meta, &f, 0).unwrap();
    // non-QoS data frame: TID HAL_DESC_REO_NON_QOS_TID (16)
    let mut g = f.clone();
    g[0] = 0x08;
    g.drain(24..26);
    r.dp.tx(&mut r.hal, &r.io, &vif, &meta, &g, 0).unwrap();
    let mut tcl = umac_src(&r.io, TCL1_R0, TCL1_HP);
    let w = tcl.consume(&r.io).unwrap();
    check!(w[3] & 0xc == 1 << 2, "encap NATIVE_WIFI");
    check!(
        w[4] == (f.len() as u32 - 2),
        "QoS control stripped from data_len, no csum"
    );
    check!(
        (w[5] >> 22) & 0xf == 6 && w[5] & (1 << 21) != 0,
        "TID = priority & 0xf"
    );
    let mut got = vec![0u8; f.len() - 2];
    phys_read(buf_addr_get(w[1], w[2]).0, &mut got);
    let mut want = g.clone();
    want[0] = 0x08; // QoS subtype bit cleared
    check!(got == want, "ath11k_dp_tx_encap_nwifi");
    let w2 = tcl.consume(&r.io).unwrap();
    // HAL_DESC_REO_NON_QOS_TID (16) through FIELD_PREP(GENMASK(25, 22))
    // is truncated to 0, exactly as Linux programs it.
    check!(
        (w2[5] >> 22) & 0xf == 0 && w2[5] & (1 << 21) != 0,
        "non-QoS TID 16 truncated by FIELD_PREP"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_tx_native_wifi);

fn smoke_ath11k_dp_tx_negatives() -> TestResult {
    let mut r = rig(SMALL);
    let vif = VifTx::attach(0, 0, false);
    let nw = TxMeta {
        encap: TxEncap::NativeWifi,
        ..eth_meta()
    };
    // A management frame without HW encap: -EOPNOTSUPP.
    let mgmt = [
        0x40u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let e = r.dp.tx(&mut r.hal, &r.io, &vif, &nw, &mgmt, 0).unwrap_err();
    check!(e.step == step::TX_NOT_DATA && e.errno == 95, "not data");
    // Shorter than its header / than an Ethernet header.
    let e =
        r.dp.tx(&mut r.hal, &r.io, &vif, &nw, &[0x08, 0x02, 0, 0], 0)
            .unwrap_err();
    check!(e.step == step::TX_FRAME_LEN, "short 802.11");
    let e =
        r.dp.tx(&mut r.hal, &r.io, &vif, &eth_meta(), &[0; 10], 0)
            .unwrap_err();
    check!(e.step == step::TX_FRAME_LEN, "short Ethernet");
    // TCL ring of 8: 7 frames fit, the 8th is -ENOMEM and frees its id.
    let frame = eth_frame(0x0800, &[0; 50]);
    for _ in 0..7 {
        check!(
            r.dp.tx(&mut r.hal, &r.io, &vif, &eth_meta(), &frame, 0)
                .is_ok(),
            "fits"
        );
    }
    let e =
        r.dp.tx(&mut r.hal, &r.io, &vif, &eth_meta(), &frame, 0)
            .unwrap_err();
    check!(
        e.step == step::TX_RING_FULL && e.errno == errno::ENOMEM && r.dp.stats.tx_desc_na[0] == 1,
        "ring full"
    );
    check!(r.dp.tx_ring[0].txbuf.len() == 7, "id released on ring full");
    r.dp.crash_flush = true;
    let e =
        r.dp.tx(&mut r.hal, &r.io, &vif, &eth_meta(), &frame, 0)
            .unwrap_err();
    check!(
        e.step == step::TX_SHUTDOWN && e.errno == errno::ESHUTDOWN,
        "crash flush"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_tx_negatives);

/// TQM release entry for TX descriptor `desc_id`.
pub(super) fn wbm_tqm(
    desc_id: u32,
    reason: u32,
    ppdu: u32,
    tries: u32,
    rssi: u32,
    peer: u32,
    tid: u32,
) -> [u32; 8] {
    let mut w = [0u32; 8];
    w[1] = (3 << 8) | (desc_id << 11);
    w[2] = reason << 13; // REL_SRC TQM (0)
    w[3] = ppdu | (tries << 24);
    w[4] = rssi | (1 << 9); // FIRST_MSDU
    w[5] = 0x1234_5671; // rate stats, VALID
    w[7] = peer | (tid << 16);
    w
}

/// FW (HTT) release entry: status in info0 12:9, ack rssi in info1
/// 31:24, peer id + VALID in info2.
pub(super) fn wbm_htt(desc_id: u32, status: u32, rssi: u32, peer: Option<u32>) -> [u32; 8] {
    let mut w = [0u32; 8];
    w[1] = (3 << 8) | (desc_id << 11);
    w[2] = 3 | (status << 9);
    w[3] = rssi << 24;
    w[4] = peer.map_or(0, |p| p | (1 << 21));
    w
}

fn smoke_ath11k_dp_tx_completion_decode() -> TestResult {
    let mut r = rig(SMALL);
    let vif = VifTx::attach(0, 0, false);
    let frame = eth_frame(0x0800, &[0; 50]);
    let mut ids = Vec::new();
    for _ in 0..6 {
        ids.push(
            r.dp.tx(&mut r.hal, &r.io, &vif, &eth_meta(), &frame, 0)
                .unwrap(),
        );
    }
    let mut tcl = umac_src(&r.io, TCL1_R0, TCL1_HP);
    while tcl.consume(&r.io).is_some() {}
    let mut comp = umac_dst(&r.io, WBM2SW0_R0, WBM2SW0_TP);
    check!(comp.esz == 8, "completion ring from registers");
    let ents = [
        wbm_tqm(ids[0], 0, 0x77, 2, 0x30, 3, 5),         // acked
        wbm_tqm(ids[1], 2, 0x78, 4, 0, 3, 5),            // CMD_REMOVE_TX: not acked
        wbm_htt(ids[2], 0, 0x22, Some(3)),               // HTT OK
        wbm_htt(ids[3], 1, 0, None),                     // HTT DROP
        wbm_htt(ids[4], 2, 0, Some(9)),                  // HTT TTL
        wbm_htt(ids[5], 3, 0, None),                     // HTT REINJ: freed silently
        wbm_tqm(0x8_0000 | (40 << 2), 0, 0, 1, 0, 0, 0), // unknown msdu
    ];
    for e in ents {
        check!(comp.produce(&r.io, &e), "completion");
    }
    let c = r.dp.tx_completion_handler(&mut r.hal, &r.io, 0);
    check!(c.len() == 5, "two TQM + three HTT completions reported");
    check!(
        c[0].acked
            && c[0].status == 0
            && c[0].ppdu_id == 0x77
            && c[0].try_cnt == 2
            && c[0].ack_rssi == 0x30
            && c[0].peer_id == 3
            && c[0].tid == 5
            && c[0].flags == 1
            && c[0].rate_stats == 0x1234_5671
            && c[0].len == 64
            && c[0].msdu_id == 0,
        "TQM acked decode"
    );
    check!(
        !c[1].acked && c[1].status == 2 && c[1].try_cnt == 4,
        "TQM remove-tx"
    );
    check!(
        c[2].acked && c[2].buf_rel_source == 3 && c[2].ack_rssi == 0x22 && c[2].peer_id == 3,
        "HTT OK"
    );
    check!(
        !c[3].acked && c[3].status == 1 && c[3].peer_id == 0xffff,
        "HTT DROP, no peer"
    );
    check!(
        !c[4].acked && c[4].status == 2 && c[4].peer_id == 9,
        "HTT TTL"
    );
    // A FIFO of 8 (head 0, tail 7) takes 6 per pass; the 7th waits.
    check!(
        r.dp.stats.tx_unknown_msdu == 0 && r.dp.stats.tx_status_fifo_full == 1,
        "seventh descriptor left on the ring"
    );
    let c2 = r.dp.tx_completion_handler(&mut r.hal, &r.io, 0);
    check!(
        c2.is_empty() && r.dp.stats.tx_unknown_msdu == 1,
        "unknown msdu id counted on the next pass"
    );
    check!(
        r.dp.tx_ring[0].txbuf.is_empty() && r.dp.pdev.as_ref().unwrap().num_tx_pending == 0,
        "every TX buffer released"
    );
    check!(
        r.io.reg(shadow_of(WBM2SW0_TP)) == 7 * 8,
        "completion TP published"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_tx_completion_decode
);

fn smoke_ath11k_dp_tx_status_fifo_full() -> TestResult {
    let mut r = rig(DpRingSizes {
        tx_status_fifo: 4,
        ..SMALL
    });
    let vif = VifTx::attach(0, 0, false);
    let frame = eth_frame(0x0800, &[0; 50]);
    let mut comp = umac_dst(&r.io, WBM2SW0_R0, WBM2SW0_TP);
    let mut tcl = umac_src(&r.io, TCL1_R0, TCL1_HP);
    for _ in 0..5 {
        let id =
            r.dp.tx(&mut r.hal, &r.io, &vif, &eth_meta(), &frame, 0)
                .unwrap();
        tcl.consume(&r.io).unwrap();
        check!(
            comp.produce(&r.io, &wbm_tqm(id, 0, 0, 1, 0, 1, 0)),
            "completion"
        );
    }
    // FIFO of 4 (head 0, tail 3): two descriptors per pass.
    let c = r.dp.tx_completion_handler(&mut r.hal, &r.io, 0);
    check!(
        c.len() == 2 && r.dp.stats.tx_status_fifo_full == 1,
        "fifo full warned"
    );
    let c2 = r.dp.tx_completion_handler(&mut r.hal, &r.io, 0);
    let c3 = r.dp.tx_completion_handler(&mut r.hal, &r.io, 0);
    check!(c2.len() + c3.len() == 3, "the rest on later passes");
    check!(r.dp.tx_ring[0].txbuf.is_empty(), "all released");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_tx_status_fifo_full
);

fn smoke_ath11k_dp_tx_ring_wraparound() -> TestResult {
    let mut r = rig(SMALL);
    let vif = VifTx::attach(0, 0, false);
    let mut comp = umac_dst(&r.io, WBM2SW0_R0, WBM2SW0_TP);
    let mut tcl = umac_src(&r.io, TCL1_R0, TCL1_HP);
    let mut done = 0;
    for round in 0..10u8 {
        for k in 0..5u8 {
            let frame = eth_frame(0x0800, &[round, k, 0, 0, 0, 0, 0, 0]);
            r.dp.tx(&mut r.hal, &r.io, &vif, &eth_meta(), &frame, 0)
                .unwrap();
        }
        while let Some(w) = tcl.consume(&r.io) {
            let pa = buf_addr_get(w[1], w[2]).0;
            let mut got = vec![0u8; 22];
            phys_read(pa, &mut got);
            if got[14] != round {
                return TestResult::Fail("TCL entries in order across the wrap");
            }
            let desc_id = (w[2] >> 11) & 0x1f_ffff;
            assert!(comp.produce(&r.io, &wbm_tqm(desc_id, 0, 0, 1, 0, 1, 0)));
        }
        done += r.dp.tx_completion_handler(&mut r.hal, &r.io, 0).len();
    }
    check!(
        done == 50,
        "50 frames through an 8-entry TCL and 16-entry completion ring"
    );
    check!(r.dp.tx_ring[0].txbuf.is_empty(), "ids recycled");
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_tx_ring_wraparound
);

fn smoke_ath11k_dp_tx_shadow_timer() -> TestResult {
    let mut r = rig(SMALL);
    let vif = VifTx::attach(0, 0, false);
    let frame = eth_frame(0x0800, &[0; 50]);
    r.dp.tx(&mut r.hal, &r.io, &vif, &eth_meta(), &frame, 100)
        .unwrap();
    check!(
        r.dp.tx_ring_timer[0].started && r.dp.tx_ring_timer[0].interval_ms == 20,
        "ATH11K_SHADOW_DP_TIMER_INTERVAL armed"
    );
    let sh = shadow_of(TCL1_HP);
    r.io.clear();
    r.dp.service_shadow_timers(&mut r.hal, &r.io, 119);
    check!(r.io.ops().is_empty(), "not due");
    r.dp.tx(&mut r.hal, &r.io, &vif, &eth_meta(), &frame, 110)
        .unwrap();
    r.io.clear();
    r.dp.service_shadow_timers(&mut r.hal, &r.io, 120);
    check!(
        r.io.ops().is_empty(),
        "TX in the interval: re-armed, HP untouched"
    );
    r.dp.service_shadow_timers(&mut r.hal, &r.io, 140);
    // Hardware has not consumed (rdp TP 0 != HP 16): HP re-published.
    check!(
        r.io.ops() == [Op::W(sh, 16)],
        "HP re-published through the shadow"
    );
    check!(!r.dp.tx_ring_timer[0].started, "timer stopped");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_tx_shadow_timer);

fn smoke_ath11k_dp_service_srng_groups() -> TestResult {
    let mut r = rig(SMALL);
    let mut refill = lmac(&r.msgs[0]);
    let mut reo2 = umac_dst(&r.io, REO2SW1_R0 + REO_DST_STRIDE, REO2SW1_TP + 8);
    let msdu = nwifi_msdu(0x0800, &[7; 8]);
    deliver(
        &r.io,
        &mut refill,
        &mut reo2,
        &good_rxd(msdu.len(), 1),
        &msdu,
    );
    // Group 7 services REO2SW1 only; group 8 (rx mask 2) REO2SW2.
    let o7 = r.dp.service_srng(&mut r.hal, &r.io, 7, 64);
    check!(o7.rx.is_empty() && o7.work_done == 0, "group 7 = ring 0");
    let o8 = r.dp.service_srng(&mut r.hal, &r.io, 8, 64);
    check!(o8.rx.len() == 1 && o8.work_done == 1, "group 8 = REO2SW2");
    // Group 0: TX completion + REO exception + WBM release + REO status +
    // RXDMA err of mac 0.
    let vif = VifTx::attach(0, 0, false);
    let id =
        r.dp.tx(
            &mut r.hal,
            &r.io,
            &vif,
            &eth_meta(),
            &eth_frame(0x0800, &[0; 50]),
            0,
        )
        .unwrap();
    let mut comp = umac_dst(&r.io, WBM2SW0_R0, WBM2SW0_TP);
    check!(
        comp.produce(&r.io, &wbm_tqm(id, 0, 0, 1, 0, 1, 0)),
        "completion"
    );
    let mut st = umac_dst(&r.io, REO_STATUS_R0, REO_STATUS_TP);
    let mut s = vec![0u32; 26];
    s[0] = 0x138 << 1;
    s[1] = 9;
    check!(st.produce(&r.io, &s), "status");
    let o0 = r.dp.service_srng(&mut r.hal, &r.io, 0, 64);
    check!(
        o0.tx_done.len() == 1 && o0.reo_status.len() == 1 && o0.reo_status[0].cmd_num == 9,
        "group 0 services TX completion and REO status"
    );
    // Group 1 = RXDMA err of mac 1 (rxdma2host[1] = 2); group 11 out of range.
    let o1 = r.dp.service_srng(&mut r.hal, &r.io, 1, 64);
    check!(
        o1.work_done == 1,
        "mac 1 rxdma err ring polled (Linux's +1)"
    );
    check!(
        r.dp.service_srng(&mut r.hal, &r.io, 11, 64) == DpServiceOutput::default(),
        "no group 11"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_service_srng_groups
);

fn smoke_ath11k_dp_idr_lowest_free() -> TestResult {
    let mut idr: Idr<u32> = Idr::default();
    check!(idr.alloc(10, 1, 5) == Ok(1), "first id is start");
    check!(idr.alloc(11, 1, 5) == Ok(2), "next");
    check!(idr.alloc(12, 0, 5) == Ok(0), "lower start finds 0");
    check!(
        idr.alloc(13, 1, 5) == Ok(3) && idr.alloc(14, 1, 5) == Ok(4),
        "fill"
    );
    check!(idr.alloc(15, 1, 5) == Err(15), "-ENOSPC returns the value");
    check!(
        idr.remove(2) == Some(11) && idr.remove(2).is_none(),
        "remove once"
    );
    check!(idr.alloc(16, 1, 5) == Ok(2), "lowest free reused");
    check!(idr.len() == 5 && idr.find(2) == Some(&16), "find");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_idr_lowest_free);

fn smoke_ath11k_dp_decap_helpers() -> TestResult {
    // ieee80211_hdrlen
    check!(ieee80211_hdrlen(0x0008) == 24, "data");
    check!(ieee80211_hdrlen(0x0088) == 26, "QoS data");
    check!(ieee80211_hdrlen(0x0388) == 32, "4-addr QoS");
    check!(ieee80211_hdrlen(0x8088) == 30, "QoS + HT control");
    // ToDS: DA = addr3, SA = addr2
    let mut h = vec![0x08, 0x01, 0, 0];
    h.extend_from_slice(&BSSID);
    h.extend_from_slice(&STA);
    h.extend_from_slice(&SRC);
    h.extend_from_slice(&[0, 0]);
    check!(ieee80211_da_sa(&h) == Some((SRC, STA)), "ToDS addresses");
    // nwifi without SNAP → 802.3 length frame
    let mut n = nwifi_msdu(0, &[]);
    n.truncate(24);
    n.extend_from_slice(&[0x42, 0x42, 3, 1, 2]);
    let e = nwifi_to_eth(&n).unwrap();
    check!(
        e[12..14] == [0, 5] && e[14..] == [0x42, 0x42, 3, 1, 2],
        "802.3 length frame"
    );
    // Bridge-tunnel SNAP
    let mut bt = nwifi_msdu(0x80f3, &[1]);
    bt[29] = 0xf8;
    check!(
        nwifi_to_eth(&bt).unwrap() == eth_frame(0x80f3, &[1]),
        "bridge tunnel"
    );
    // 802.3 + RFC1042 → Ethernet II
    let mut l = Vec::new();
    l.extend_from_slice(&STA);
    l.extend_from_slice(&SRC);
    l.extend_from_slice(&[0, 10]);
    l.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x08, 0x06, 9, 9]);
    check!(
        ieee8023_to_eth(&l).unwrap() == eth_frame(0x0806, &[9, 9]),
        "802.3 SNAP"
    );
    check!(
        nwifi_to_eth(&[0x08]).is_none() && ieee8023_to_eth(&[0; 13]).is_none(),
        "short"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_decap_helpers);

// ── RX fragment reassembly (dp_frag) ──────────────────────────────

const SW2REO_R0: u32 = 0x00a3_81ec;
const SW2REO_HP: u32 = 0x00a3_b028;
/// The AP's peer id for the reassembly tests.
const FRAG_PEER: u16 = 3;
const FRAG_SEQ: u32 = 5;
/// `queue_addr_lo` / `queue_addr_hi` of the exception entries.
const FRAG_QLO: u32 = 0xabcd_0000;
const FRAG_QHI: u32 = 0x01;
/// REO destination indication in the MSDU link entry.
const FRAG_DEST: u32 = 2;

/// A rig with the AP mapped (HTT PEER_MAP) and its REO queues set up
/// (`ath11k_dp_peer_setup`, so `dp_setup_done`), CCMP on the peer.
fn frag_rig() -> Rig {
    let mut r = rig(SMALL);
    let mut m = Vec::new();
    m.extend_from_slice(&(3u32 | (FRAG_PEER as u32) << 16).to_le_bytes());
    m.extend_from_slice(&[BSSID[0], BSSID[1], BSSID[2], BSSID[3]]);
    m.extend_from_slice(&[BSSID[4], BSSID[5], 0, 0]);
    r.dp.htt_t2h_msg_handler(&m).expect("peer map");
    let (mut op, _) = r.dp.peer_setup_begin(0, BSSID, 0);
    while r
        .dp
        .peer_setup_next(&mut r.hal, &r.io, &mut op, 0)
        .expect("peer setup")
        .is_some()
    {}
    r.dp.set_peer_sec_type(FRAG_PEER, enc::CCMP_128, enc::CCMP_128);
    r
}

/// Fragment `frag` of sequence `seq` as the hardware hands it over raw
/// and decrypted: 802.11 header (data | FromDS | Protected, More
/// Fragments unless `last`), CCMP header with PN `pn`, `body`, the 8-byte
/// MIC, the FCS.
fn raw_frag(seq: u32, frag: u8, last: bool, pn: u8, body: &[u8]) -> Vec<u8> {
    let mut f = vec![0x08, if last { 0x42 } else { 0x46 }, 0, 0];
    f.extend_from_slice(&STA);
    f.extend_from_slice(&BSSID);
    f.extend_from_slice(&SRC);
    f.extend_from_slice(&((seq << 4) as u16 | frag as u16).to_le_bytes());
    f.extend_from_slice(&[pn, 0, 0, 0x20, 0, 0, 0, 0]);
    f.extend_from_slice(body);
    f.extend_from_slice(&[0x4d; 8]); // MIC
    f.extend_from_slice(&[0xfc, 0xfc, 0xfc, 0xfc]); // FCS
    f
}

/// The fragment's RX descriptor: raw decap, CCMP decrypted OK, TID 0,
/// sequence `seq`, peer `FRAG_PEER`, MPDU sequence / frame-control valid.
fn frag_desc(len: usize, seq: u32, mcbc: bool) -> Vec<u8> {
    let mut b = rx_desc_bytes(&Rxd {
        first: true,
        last: true,
        msdu_len: len as u32,
        decap: 0,
        enc_valid: true,
        enc_type: enc::CCMP_128,
        seq,
        sw_peer_id: FRAG_PEER,
        attn1: if mcbc { 1 << 2 } else { 0 },
        ..Rxd::default()
    });
    // mpdu_start.info1 @ 188: MPDU_FCTRL_VALID (0) | MPDU_SEQ_CTRL_VALID (6)
    let v = u32::from_le_bytes([b[188], b[189], b[190], b[191]]) | 1 | 1 << 6;
    put32(&mut b, 188, v);
    b
}

/// Firmware side: a fragment in the next refill buffer, its MSDU link
/// descriptor (REO destination `FRAG_DEST`) from the idle list, and the
/// REO exception entry (FRAG_FLAG, error detected, link buffer type).
fn frag_entry(
    r: &Rig,
    refill: &mut DevRing,
    idle: &mut DevRing,
    exc: &mut DevRing,
    mpdu: &[u8],
    seq: u32,
    mcbc: bool,
) -> [u32; 2] {
    let (pa, cookie) = fw_take(&r.io, refill);
    let mut buf = frag_desc(mpdu.len(), seq, mcbc);
    buf.extend_from_slice(mpdu);
    phys_write(pa, &buf);
    let w = idle.consume(&r.io).expect("idle link descriptor");
    let (lpa, _, _) = buf_addr_get(w[0], w[1]);
    let mut b = vec![0u8; 128];
    put32(&mut b, 32, pa as u32);
    put32(
        &mut b,
        36,
        ((pa >> 32) as u32 & 0xff) | (4 << 8) | (cookie << 11),
    );
    put32(&mut b, 40, FRAG_DEST << 17);
    phys_write(lpa, &b);
    let mut e = [0u32; 16];
    e[0] = w[0];
    e[1] = w[1];
    e[2] = 1 << 20 | FRAG_SEQ << 8;
    e[3] = FRAG_PEER as u32;
    e[6] = FRAG_QLO;
    e[7] = FRAG_QHI | (1 << 8); // buffer type link desc, push ERR_DETECTED
    assert!(exc.produce(&r.io, &e));
    [w[0], w[1]]
}

fn body0() -> Vec<u8> {
    vec![0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00, 1, 2, 3, 4]
}

/// The reassembled MPDU (`ath11k_dp_rx_h_defrag`, CCMP): fragment 0's
/// header (More Fragments cleared) + IV, both bodies, the last
/// fragment's MIC + FCS.
fn defragged() -> Vec<u8> {
    let mut f = raw_frag(FRAG_SEQ, 0, true, 0x10, &body0());
    f.truncate(24 + 8 + 12);
    f.extend_from_slice(&[5, 6, 7, 8]);
    f.extend_from_slice(&[0x4d; 8]);
    f.extend_from_slice(&[0xfc; 4]);
    f
}

fn smoke_ath11k_dp_defrag_reinject_golden() -> TestResult {
    let mut r = frag_rig();
    let mut refill = lmac(&r.msgs[0]);
    let mut idle = umac_src(&r.io, WBM_IDLE_R0, WBM_IDLE_HP);
    let mut exc = umac_dst(&r.io, REO2TCL_R0, REO2TCL_TP);
    let mut sw2wbm = umac_src(&r.io, SW2WBM_R0, SW2WBM_HP);
    let mut reinj = umac_src(&r.io, SW2REO_R0, SW2REO_HP);
    let mut reo = umac_dst(&r.io, REO2SW1_R0, REO2SW1_TP);
    r.dp.now_ms = 1000;
    let f0 = raw_frag(FRAG_SEQ, 0, false, 0x10, &body0());
    let f1 = raw_frag(FRAG_SEQ, 1, true, 0x11, &[5, 6, 7, 8]);
    let l0 = frag_entry(&r, &mut refill, &mut idle, &mut exc, &f0, FRAG_SEQ, false);
    check!(
        r.dp.process_rx_err(&mut r.hal, &r.io, 64) == 1,
        "frag 0 reaped"
    );
    let t = &r.dp.peer_rx.peer(0, &BSSID).unwrap().rx_tid[0];
    check!(
        t.rx_frag_bitmap == 1 && t.cur_sn == FRAG_SEQ as u16 && t.frag_timer == Some(3000),
        "frag 0 held, 2 s timer armed"
    );
    check!(
        sw2wbm.consume(&r.io).is_none(),
        "frag 0's link descriptor kept"
    );
    let l1 = frag_entry(&r, &mut refill, &mut idle, &mut exc, &f1, FRAG_SEQ, false);
    check!(
        r.dp.process_rx_err(&mut r.hal, &r.io, 64) == 1,
        "frag 1 reaped"
    );
    let ret = sw2wbm.consume(&r.io).expect("frag 1's link descriptor");
    check!(
        ret[..2] == l1 && ret[2] == 0x44,
        "frag 1 returned PUT_IN_IDLE"
    );
    check!(
        sw2wbm.consume(&r.io).is_none(),
        "frag 0's link descriptor reused"
    );
    check!(r.dp.stats.rx_defrag_reinjected == 1, "reinjected");
    let t = &r.dp.peer_rx.peer(0, &BSSID).unwrap().rx_tid[0];
    check!(
        t.rx_frags.is_empty() && t.rx_frag_bitmap == 0 && t.dst_ring_desc.is_none(),
        "state cleared"
    );
    // hal_reo_entrance_ring: frag 0's link descriptor (rbm
    // WBM_IDLE_DESC_LIST = 1, cookie = bank), MSDU count 1 | seq 5 |
    // VALID_PN (24) | VALID_SA (25) | VALID_DA (27) | RAW_MPDU (30),
    // meta data + queue address from the exception entry, dest ind 2.
    let e = reinj.consume(&r.io).expect("reinject entry");
    let link = [l0[0], (l0[1] & !(7 << 8)) | (1 << 8)];
    check!(
        e[..2] == link
            && e[2] == 1 | FRAG_SEQ << 8 | 1 << 24 | 1 << 25 | 1 << 27 | 1 << 30
            && e[3] == FRAG_PEER as u32
            && e[4] == FRAG_QLO
            && e[5] == FRAG_QHI | FRAG_DEST << 22
            && e[6] == 0
            && e[7] == 0,
        "reinject entry golden"
    );
    // The MSDU link entry now names the reassembled buffer: FIRST | LAST
    // | length << 3 | dest << 17 | VALID_SA (23) | VALID_DA (25).
    let want = defragged();
    let (lpa, _, _) = buf_addr_get(l0[0], l0[1]);
    let mut ld = [0u8; 48];
    phys_read(lpa, &mut ld);
    let w = |i: usize| u32::from_le_bytes([ld[i * 4], ld[i * 4 + 1], ld[i * 4 + 2], ld[i * 4 + 3]]);
    check!(
        w(10) == 1 | 2 | (want.len() as u32) << 3 | FRAG_DEST << 17 | 1 << 23 | 1 << 25
            && w(11) == 0,
        "MSDU link entry golden"
    );
    let (bpa, cookie, mgr) = buf_addr_get(w(8), w(9));
    check!(
        mgr == rbm::SW1_BM && cookie >> 18 == 0,
        "rx_buf_rbm, pdev 0"
    );
    let mut buf = vec![0u8; DESC_SZ + want.len()];
    phys_read(bpa, &mut buf);
    let mut desc = frag_desc(want.len(), FRAG_SEQ, false);
    check!(buf[DESC_SZ..] == want[..], "reassembled MPDU golden");
    desc[104..108].copy_from_slice(&(want.len() as u32).to_le_bytes());
    check!(
        buf[..DESC_SZ] == desc[..],
        "descriptor with the MSDU length rewritten"
    );

    // The REO delivers it on REO2SW1 (routing): a raw, decrypted MPDU →
    // FCS, MIC, IV stripped (ath11k_dp_rx_h_undecap_raw) → Ethernet II.
    check!(
        reo.produce(
            &r.io,
            &reo_dest(
                bpa,
                cookie,
                FIRST | LAST | (want.len() as u32) << 3,
                1,
                0,
                FRAG_PEER as u32
            )
        ),
        "REO dest entry"
    );
    let (n, out) = r.dp.process_rx(&mut r.hal, &r.io, 0, 64);
    check!(n == 1 && out.len() == 1, "delivered");
    let mut eth = STA.to_vec();
    eth.extend_from_slice(&SRC);
    eth.extend_from_slice(&[0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]);
    check!(
        out[0].frame == eth && out[0].decrypted && out[0].decap == 0,
        "Ethernet II golden"
    );
    check!(
        r.dp.rx_buf(cookie).is_none(),
        "the reinjected buffer left the IDR"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_defrag_reinject_golden
);

fn smoke_ath11k_dp_defrag_negatives() -> TestResult {
    let mut r = frag_rig();
    let mut refill = lmac(&r.msgs[0]);
    let mut idle = umac_src(&r.io, WBM_IDLE_R0, WBM_IDLE_HP);
    let mut exc = umac_dst(&r.io, REO2TCL_R0, REO2TCL_TP);
    let mut sw2wbm = umac_src(&r.io, SW2WBM_R0, SW2WBM_HP);
    let mut reinj = umac_src(&r.io, SW2REO_R0, SW2REO_HP);
    let f0 = raw_frag(FRAG_SEQ, 0, false, 0x10, &body0());
    let f1 = raw_frag(FRAG_SEQ, 1, true, 0x11, &[5, 6, 7, 8]);
    macro_rules! feed {
        ($f:expr, $seq:expr, $mc:expr) => {{
            let l = frag_entry(&r, &mut refill, &mut idle, &mut exc, &$f, $seq, $mc);
            r.dp.process_rx_err(&mut r.hal, &r.io, 64);
            l
        }};
    }

    // Out of order: frag 1 first, then 0 → sorted, reinjected as the
    // in-order golden.
    let l1 = feed!(f1, FRAG_SEQ, false);
    let ret = sw2wbm.consume(&r.io).unwrap();
    check!(ret[..2] == l1, "frag 1's link descriptor returned at once");
    feed!(f0, FRAG_SEQ, false);
    check!(
        r.dp.stats.rx_defrag_reinjected == 1,
        "out-of-order set reinjected"
    );
    let e = reinj.consume(&r.io).expect("reinject entry");
    let (lpa, _, _) = buf_addr_get(e[0], e[1]);
    let mut ld = [0u8; 40];
    phys_read(lpa, &mut ld);
    let (bpa, _, _) = buf_addr_get(
        u32::from_le_bytes([ld[32], ld[33], ld[34], ld[35]]),
        u32::from_le_bytes([ld[36], ld[37], ld[38], ld[39]]),
    );
    let want = defragged();
    let mut buf = vec![0u8; want.len()];
    phys_read(bpa + DESC_SZ as u64, &mut buf);
    check!(buf == want, "sorted reassembly");

    // A PN gap (0x10 → 0x12): the set is dropped, both link descriptors
    // returned, nothing reinjected.
    let l0 = feed!(f0, FRAG_SEQ, false);
    let l1 = feed!(
        raw_frag(FRAG_SEQ, 1, true, 0x12, &[5, 6, 7, 8]),
        FRAG_SEQ,
        false
    );
    let a = sw2wbm.consume(&r.io).unwrap();
    let b = sw2wbm.consume(&r.io).unwrap();
    check!(a[..2] == l1 && b[..2] == l0, "frag 1 then frag 0 returned");
    check!(
        r.dp.stats.rx_defrag_dropped == 1 && reinj.consume(&r.io).is_none(),
        "PN gap: dropped, not reinjected"
    );

    // A duplicate fragment: refused, its own link descriptor returned.
    let l0 = feed!(f0, FRAG_SEQ, false);
    let d0 = feed!(f0, FRAG_SEQ, false);
    let a = sw2wbm.consume(&r.io).unwrap();
    check!(
        a[..2] == d0 && r.dp.stats.rx_err_frags_dropped == 1,
        "duplicate refused"
    );
    // A new sequence number flushes the held set (frag 0 returned).
    let l0b = feed!(raw_frag(6, 0, false, 0x20, &body0()), 6, false);
    let a = sw2wbm.consume(&r.io).unwrap();
    check!(a[..2] == l0, "old set flushed on a new sequence");
    check!(
        r.dp.peer_rx.peer(0, &BSSID).unwrap().rx_tid[0].cur_sn == 6,
        "new cur_sn"
    );
    // The fragment timer: nothing before 2 s, the set dropped at 2 s.
    let armed = r.dp.peer_rx.peer(0, &BSSID).unwrap().rx_tid[0]
        .frag_timer
        .unwrap();
    r.dp.service_frag_timers(&mut r.hal, &r.io, armed - 1);
    check!(sw2wbm.consume(&r.io).is_none(), "not yet");
    r.dp.service_frag_timers(&mut r.hal, &r.io, armed);
    let a = sw2wbm.consume(&r.io).unwrap();
    check!(
        a[..2] == l0b && r.dp.stats.rx_defrag_timeout == 1,
        "timer expiry drops the set"
    );

    // Group-addressed and unfragmented MPDUs are refused.
    let m = feed!(f0, FRAG_SEQ, true);
    let a = sw2wbm.consume(&r.io).unwrap();
    check!(a[..2] == m, "multicast fragment refused");
    let mut whole = raw_frag(FRAG_SEQ, 0, true, 0x10, &body0());
    whole[1] = 0x42;
    let w = feed!(whole, FRAG_SEQ, false);
    let a = sw2wbm.consume(&r.io).unwrap();
    check!(a[..2] == w, "unfragmented MPDU refused");

    // ath11k_peer_frags_flush (pairwise key install): held set dropped.
    let l0 = feed!(f0, FRAG_SEQ, false);
    r.dp.peer_frags_flush(&mut r.hal, &r.io, 0, &BSSID);
    let a = sw2wbm.consume(&r.io).unwrap();
    let t = &r.dp.peer_rx.peer(0, &BSSID).unwrap().rx_tid[0];
    check!(
        a[..2] == l0 && t.rx_frags.is_empty() && t.frag_timer.is_none(),
        "flush returns frag 0, timer stopped"
    );

    // A mapped peer without its data path set up: refused.
    let mut m = Vec::new();
    m.extend_from_slice(&(3u32 | 7u32 << 16).to_le_bytes());
    m.extend_from_slice(&[SRC[0], SRC[1], SRC[2], SRC[3], SRC[4], SRC[5], 0, 0]);
    r.dp.htt_t2h_msg_handler(&m).expect("peer map");
    let (pa, cookie) = fw_take(&r.io, &mut refill);
    let mut buf = frag_desc(f0.len(), FRAG_SEQ, false);
    buf[186..188].copy_from_slice(&7u16.to_le_bytes());
    buf.extend_from_slice(&f0);
    phys_write(pa, &buf);
    let before = r.dp.stats.rx_err_frags_dropped;
    let _ = cookie;
    // (no peer_rx entry exists for peer 7: ENOENT)
    let w = idle.consume(&r.io).unwrap();
    let (lpa, _, _) = buf_addr_get(w[0], w[1]);
    let mut b = vec![0u8; 128];
    put32(&mut b, 32, pa as u32);
    put32(&mut b, 36, (4 << 8) | (cookie << 11));
    phys_write(lpa, &b);
    let mut e = [0u32; 16];
    e[0] = w[0];
    e[1] = w[1];
    e[2] = 1 << 20;
    e[7] = 1 << 8;
    check!(exc.produce(&r.io, &e), "entry");
    r.dp.process_rx_err(&mut r.hal, &r.io, 64);
    let a = sw2wbm.consume(&r.io).unwrap();
    check!(
        a[..2] == [w[0], w[1]] && r.dp.stats.rx_err_frags_dropped == before + 1,
        "peer without a data path refused"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_defrag_negatives);

/// `ath11k_dp_rx_h_undecap_raw` + the crypto lengths, against literals.
fn smoke_ath11k_dp_undecap_raw() -> TestResult {
    use super::dp_frag::{crypto_icv_len, crypto_mic_len, crypto_param_len, undecap_raw};
    check!(
        crypto_mic_len(enc::CCMP_128) == 8
            && crypto_mic_len(enc::GCMP_128) == 16
            && crypto_mic_len(enc::TKIP_MIC) == 0
            && crypto_param_len(enc::CCMP_128) == 8
            && crypto_param_len(enc::TKIP_MIC) == 8
            && crypto_param_len(enc::OPEN) == 0
            && crypto_icv_len(enc::TKIP_MIC) == 4
            && crypto_icv_len(enc::CCMP_128) == 0,
        "ath11k_dp_rx_crypto_*_len"
    );
    let f = raw_frag(1, 0, true, 9, &[1, 2]);
    let mut hdr = f[..24].to_vec();
    hdr.extend_from_slice(&[1, 2]);
    check!(
        undecap_raw(&f, enc::CCMP_128, true, false).as_deref() == Some(&hdr[..]),
        "decrypted unicast: FCS, MIC, IV stripped"
    );
    check!(
        undecap_raw(&f, enc::OPEN, false, false).as_deref() == Some(&f[..f.len() - 4]),
        "not decrypted: FCS only"
    );
    check!(
        undecap_raw(&f, enc::CCMP_128, true, true).is_none(),
        "decrypted group frame keeps its IV for mac80211"
    );
    check!(
        undecap_raw(&f[..3], enc::OPEN, false, false).is_none(),
        "short"
    );
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_undecap_raw);

/// Occupy one ring of `ty` / `ring_num` / `mac_id` in the HAL (a ring
/// some other owner already set up).
fn occupy(hal: &mut Hal, io: &RecIo, ty: HalRingType, ring_num: u32, mac_id: u32) -> u32 {
    let n = 8;
    let mem = DmaMem::alloc((hal.entry_size_bytes(ty) * n) as usize, 8).expect("ring memory");
    hal.srng_setup(io, ty, ring_num, mac_id, SrngParams::new(mem, n))
        .expect("occupying ring")
}

/// `Hal::srng_free` / `srng_clear` (`ath11k_dp_srng_cleanup`,
/// `ath11k_hal_srng_clear`).
fn smoke_ath11k_hal_srng_free_and_clear() -> TestResult {
    let cfg = DpHwParams::for_rev(HwRev::Wcn6855Hw21).unwrap();
    let mut hal = Hal::new(&cfg.hw).unwrap();
    let io = RecIo::default();
    let id = occupy(&mut hal, &io, HalRingType::TclCmd, 0, 0);
    let pa = hal.ring_mem(id).map(|m| m.paddr());
    check!(hal.srng_ids() == [id], "one ring listed");
    let mem = hal.srng_free(id);
    check!(mem.as_ref().map(|m| m.paddr()) == pa, "memory handed back");
    check!(
        hal.srng(id).is_none() && hal.srng_free(id).is_none(),
        "gone, once"
    );
    // The same ring id can be set up again (over the returned memory).
    let again = hal
        .srng_setup(
            &io,
            HalRingType::TclCmd,
            0,
            0,
            SrngParams::new(mem.unwrap(), 8),
        )
        .map_err(|e| e.step);
    check!(again == Ok(id), "set up again");
    let _ = occupy(&mut hal, &io, HalRingType::ReoStatus, 0, 0);
    check!(hal.srng_clear() == 2, "srng_clear forgets both");
    check!(hal.srng_ids().is_empty(), "HAL empty");
    check!(
        occupy(&mut hal, &io, HalRingType::TclCmd, 0, 0) == id,
        "usable after clear"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_hal_srng_free_and_clear
);

/// `ath11k_dp_pdev_free` → `ath11k_dp_pdev_reo_cleanup` →
/// `ath11k_dp_free`: every DP ring leaves the HAL, and the same HAL takes
/// a second DP (the crash-recovery rebuild).
fn smoke_ath11k_dp_free_and_realloc() -> TestResult {
    let cfg = DpHwParams::for_rev(HwRev::Wcn6855Hw21).unwrap();
    let mut r = rig(SMALL);
    let all = r.hal.srng_ids();
    let p = r.dp.pdev.as_ref().unwrap();
    let mut pdev_ids = vec![p.rx_refill_buf_ring.refill_buf_ring.ring_id];
    pdev_ids.extend(p.rx_mac_buf_ring.iter().map(|s| s.ring_id));
    pdev_ids.extend(p.rxdma_err_dst_ring.iter().map(|s| s.ring_id));
    pdev_ids.extend(
        p.rx_mon_status_refill_ring
            .iter()
            .map(|s| s.refill_buf_ring.ring_id),
    );
    check!(pdev_ids.len() == 7, "seven pdev rings");
    check!(
        !p.rx_refill_buf_ring.bufs.is_empty(),
        "RX buffers posted on the refill ring"
    );
    r.dp.pdev_free(&mut r.hal);
    check!(r.dp.pdev.is_none(), "pdev gone");
    let left = r.hal.srng_ids();
    check!(
        pdev_ids.iter().all(|id| !left.contains(id)) && left.len() == all.len() - 7,
        "the pdev's rings left the HAL"
    );
    r.dp.pdev_free(&mut r.hal);
    check!(r.hal.srng_ids() == left, "second pdev_free is a no-op");
    let reo: Vec<u32> = r.dp.reo_dst_ring.iter().map(|s| s.ring_id).collect();
    check!(reo.len() == 4, "four REO destination rings");
    r.dp.pdev_reo_cleanup(&mut r.hal);
    check!(
        r.dp.reo_dst_ring.is_empty() && reo.iter().all(|id| r.hal.srng(*id).is_none()),
        "REO destination rings released"
    );
    r.dp.free(&mut r.hal);
    check!(r.hal.srng_ids().is_empty(), "DP free empties the HAL");

    // The same HAL takes a new DP (a failed or recovered device does not
    // need a new Hal).
    let mut dp = match Dp::alloc(&mut r.hal, &r.io, &cfg, SMALL, Some(msi())) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail("realloc on the same HAL"),
    };
    check!(
        dp.pdev_reo_setup(&mut r.hal, &r.io).is_ok(),
        "REO setup again"
    );
    let msgs = dp.pdev_alloc(&mut r.hal, &r.io, 0);
    check!(
        msgs.as_ref().map(|m| m.len()) == Ok(7),
        "pdev alloc again: seven SRING_SETUPs"
    );
    check!(r.hal.srng_ids() == all, "the same ring ids");
    check!(dp.msi().is_some(), "MSI kept for a rebuild");
    // ath11k_dp_free with the pdev still set up releases it as well.
    dp.free(&mut r.hal);
    check!(r.hal.srng_ids().is_empty(), "free releases the pdev too");
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_ath11k_dp_free_and_realloc);

/// A failed `ath11k_dp_alloc` / `ath11k_dp_pdev_reo_setup` /
/// `ath11k_dp_pdev_alloc` releases what it set up (and only that), so a
/// retry on the same HAL works.
fn smoke_ath11k_dp_failed_alloc_unwinds() -> TestResult {
    let cfg = DpHwParams::for_rev(HwRev::Wcn6855Hw21).unwrap();
    let mut hal = Hal::new(&cfg.hw).unwrap();
    let io = RecIo::default();
    // TCL_CMD taken: the WBM idle and SW2WBM rings set up before it are
    // released, the occupying ring stays.
    let busy = occupy(&mut hal, &io, HalRingType::TclCmd, 0, 0);
    let e = Dp::alloc(&mut hal, &io, &cfg, SMALL, Some(msi())).unwrap_err();
    check!(
        e.step == step::SRNG_SETUP && e.detail >> 24 == HalRingType::TclCmd as u32,
        "fails at TCL_CMD"
    );
    check!(
        hal.srng_ids() == [busy],
        "fail_cmn_srng_cleanup + link desc cleanup"
    );
    hal.srng_free(busy);
    // Fails after the WBM idle ring (scatter idle list): released too.
    let big = DpRingSizes {
        n_link_desc: Some(DP_LINK_DESC_ALLOC_SIZE_THRESH / 8 + 1),
        ..SMALL
    };
    check!(
        Dp::alloc(&mut hal, &io, &cfg, big, None).is_err(),
        "scatter refused"
    );
    check!(hal.srng_ids().is_empty(), "WBM idle ring released");
    // Retry on the same HAL.
    let mut dp = match Dp::alloc(&mut hal, &io, &cfg, SMALL, Some(msi())) {
        Ok(d) => d,
        Err(_) => return TestResult::Fail("retry on the same HAL"),
    };
    let after_alloc = hal.srng_ids();
    // REO2SW3 taken: err_reo_cleanup releases REO2SW1 / 2.
    let reo3 = occupy(&mut hal, &io, HalRingType::ReoDst, 2, 0);
    check!(
        dp.pdev_reo_setup(&mut hal, &io).is_err(),
        "REO setup fails at ring 2"
    );
    check!(dp.reo_dst_ring.is_empty(), "no REO destination ring kept");
    let mut want = after_alloc.clone();
    want.push(reo3);
    want.sort();
    check!(hal.srng_ids() == want, "REO rings 0 / 1 released");
    hal.srng_free(reo3);
    check!(
        dp.pdev_reo_setup(&mut hal, &io).is_ok(),
        "REO setup retried"
    );
    // RXDMA error ring taken: the refill / MAC buffer rings set up first
    // are released.
    let before = hal.srng_ids();
    let err = occupy(&mut hal, &io, HalRingType::RxdmaDst, 0, 0);
    check!(dp.pdev_alloc(&mut hal, &io, 0).is_err(), "pdev alloc fails");
    check!(dp.pdev.is_none(), "no pdev");
    let mut want = before.clone();
    want.push(err);
    want.sort();
    check!(
        hal.srng_ids() == want,
        "ath11k_dp_pdev_free on the error path"
    );
    hal.srng_free(err);
    check!(
        dp.pdev_alloc(&mut hal, &io, 0).is_ok(),
        "pdev alloc retried"
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_ath11k_dp_failed_alloc_unwinds
);
