//! RAM/MMIO fixtures for the Qualcomm SoC layer (kernel-test only).
//!
//! Shared with consumers' tests (ath11k AHB): an FDT builder, a
//! recording register file, a deterministic clock, a scripted secure
//! monitor, a split-firmware store, an MDT image builder and an SMEM
//! region builder. Nothing here models silicon timing; every expected
//! value in the tests is derived from the Linux sources.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use narf_lib::sync::IrqSafeSpinLock;

use crate::io::{Delay, RegIo};
use crate::mdt::SegmentSource;
use crate::scm::{ScmAlloc, ScmBuffer, SmcConduit};

// ── executor ───────────────────────────────────────────────────────

/// Drive a future whose waits are all [`FakeDelay`] (always ready).
pub fn run<F: Future>(f: F) -> Option<F::Output> {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1_000_000 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Some(v);
        }
    }
    None
}

// ── clock ──────────────────────────────────────────────────────────

/// A clock that advances only when slept on.
#[derive(Debug, Default)]
pub struct FakeDelay {
    now: AtomicU64,
    pub slept_us: AtomicU64,
}

impl FakeDelay {
    pub const fn new() -> Self {
        Self {
            now: AtomicU64::new(0),
            slept_us: AtomicU64::new(0),
        }
    }
}

impl Delay for FakeDelay {
    fn sleep_us(&self, us: u32) -> impl Future<Output = ()> + Send {
        self.now.fetch_add(us as u64, Ordering::Relaxed);
        self.slept_us.fetch_add(us as u64, Ordering::Relaxed);
        core::future::ready(())
    }
    fn now_us(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }
}

// ── registers ──────────────────────────────────────────────────────

/// One register access.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Op {
    R(u32, u32),
    W(u32, u32),
}

/// A sparse recording register file. Unwritten registers read 0 unless
/// preset; `forced` registers always read their forced value.
pub struct FakeRegs {
    regs: IrqSafeSpinLock<BTreeMap<u32, u32>>,
    forced: IrqSafeSpinLock<BTreeMap<u32, u32>>,
    log: IrqSafeSpinLock<Vec<Op>>,
    record: bool,
}

impl core::fmt::Debug for FakeRegs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FakeRegs")
    }
}

impl Default for FakeRegs {
    fn default() -> Self {
        Self::quiet()
    }
}

impl FakeRegs {
    pub fn new() -> Self {
        Self {
            record: true,
            ..Self::quiet()
        }
    }
    /// A register file that does not log (large RAM fixtures).
    pub fn quiet() -> Self {
        Self {
            regs: IrqSafeSpinLock::new(BTreeMap::new()),
            forced: IrqSafeSpinLock::new(BTreeMap::new()),
            log: IrqSafeSpinLock::new(Vec::new()),
            record: false,
        }
    }
    pub fn set(&self, off: u32, v: u32) {
        self.regs.lock().insert(off, v);
    }
    pub fn get(&self, off: u32) -> u32 {
        *self.regs.lock().get(&off).unwrap_or(&0)
    }
    pub fn force(&self, off: u32, v: u32) {
        self.forced.lock().insert(off, v);
    }
    pub fn unforce(&self, off: u32) {
        self.forced.lock().remove(&off);
    }
    pub fn log(&self) -> Vec<Op> {
        self.log.lock().clone()
    }
    pub fn writes(&self) -> Vec<(u32, u32)> {
        self.log
            .lock()
            .iter()
            .filter_map(|o| match *o {
                Op::W(a, v) => Some((a, v)),
                _ => None,
            })
            .collect()
    }
    pub fn writes_to(&self, off: u32) -> Vec<u32> {
        self.writes()
            .into_iter()
            .filter(|(a, _)| *a == off)
            .map(|(_, v)| v)
            .collect()
    }
    pub fn clear_log(&self) {
        self.log.lock().clear();
    }
}

impl RegIo for FakeRegs {
    fn read32(&self, off: u32) -> u32 {
        let v = match self.forced.lock().get(&off) {
            Some(v) => *v,
            None => self.get(off),
        };
        if self.record {
            self.log.lock().push(Op::R(off, v));
        }
        v
    }
    fn write32(&self, off: u32, value: u32) {
        self.regs.lock().insert(off, value);
        if self.record {
            self.log.lock().push(Op::W(off, value));
        }
    }
}

// ── secure monitor ─────────────────────────────────────────────────

type Responder = Box<dyn Fn(&[u64; 8], usize) -> [u64; 8] + Send + Sync>;

/// A scripted secure monitor: records every trap and answers through a
/// closure given (regs, call index).
pub struct FakeSmc {
    pub calls: IrqSafeSpinLock<Vec<[u64; 8]>>,
    respond: Responder,
}

impl core::fmt::Debug for FakeSmc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FakeSmc")
    }
}

impl FakeSmc {
    pub fn new(respond: impl Fn(&[u64; 8], usize) -> [u64; 8] + Send + Sync + 'static) -> Self {
        Self {
            calls: IrqSafeSpinLock::new(Vec::new()),
            respond: Box::new(respond),
        }
    }
    /// A monitor that implements SMC64, answers `IS_CALL_AVAIL` and
    /// `PAS_IS_SUPPORTED` with 1 and every other call with status 0 / result 0.
    pub fn ok() -> Self {
        Self::new(|r, _| {
            let mut o = [0u64; 8];
            let f = r[0] as u32 & 0xffff;
            if f == crate::scm::smc_fnid(crate::scm::SVC_INFO, crate::scm::INFO_IS_CALL_AVAIL)
                || f == crate::scm::smc_fnid(crate::scm::SVC_PIL, crate::scm::PIL_PAS_IS_SUPPORTED)
            {
                o[1] = 1;
            }
            o
        })
    }
    pub fn calls(&self) -> Vec<[u64; 8]> {
        self.calls.lock().clone()
    }
    /// `(svc, cmd)` of each trap, in order.
    pub fn fnids(&self) -> Vec<(u32, u32)> {
        self.calls()
            .iter()
            .map(|r| (((r[0] >> 8) & 0xff) as u32, (r[0] & 0xff) as u32))
            .collect()
    }
}

impl SmcConduit for FakeSmc {
    fn smc(&self, regs: &mut [u64; 8]) {
        let n = {
            let mut c = self.calls.lock();
            c.push(*regs);
            c.len() - 1
        };
        *regs = (self.respond)(regs, n);
    }
}

impl SmcConduit for &FakeSmc {
    fn smc(&self, regs: &mut [u64; 8]) {
        (**self).smc(regs)
    }
}

/// A heap buffer posing as DMA memory at a fake physical address.
#[derive(Debug)]
pub struct FakeBuf {
    pub phys: u64,
    pub data: Vec<u8>,
}

impl ScmBuffer for FakeBuf {
    fn phys(&self) -> u64 {
        self.phys
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

/// Allocates [`FakeBuf`]s at increasing fake addresses; keeps copies of
/// every allocation's final contents is not possible after drop, so it
/// records the sizes.
#[derive(Debug, Default)]
pub struct FakeAlloc {
    pub next: u64,
    pub sizes: Vec<usize>,
    pub fail: bool,
}

impl ScmAlloc for FakeAlloc {
    type Buf = FakeBuf;
    fn alloc(&mut self, len: usize) -> Option<FakeBuf> {
        if self.fail {
            return None;
        }
        self.sizes.push(len);
        let phys = 0x8000_0000 + self.next;
        self.next += ((len as u64) + 0xfff) & !0xfff;
        Some(FakeBuf {
            phys,
            data: vec![0; len],
        })
    }
}

// ── firmware ───────────────────────────────────────────────────────

/// Split-firmware files by name.
#[derive(Debug, Default)]
pub struct FwStore(pub BTreeMap<String, Vec<u8>>);

impl FwStore {
    pub fn insert(&mut self, name: &str, data: Vec<u8>) {
        self.0.insert(String::from(name), data);
    }
}

impl SegmentSource for FwStore {
    fn read_into(&self, name: &str, dst: &mut [u8]) -> Option<usize> {
        let f = self.0.get(name)?;
        if f.len() > dst.len() {
            return None;
        }
        dst[..f.len()].copy_from_slice(f);
        Some(f.len())
    }
}

/// One program header for [`build_mdt`].
#[derive(Copy, Clone, Debug)]
pub struct Seg {
    pub p_type: u32,
    pub flags: u32,
    pub paddr: u32,
    pub filesz: u32,
    pub memsz: u32,
    /// Fill byte of the segment's file data.
    pub fill: u8,
}

/// Build an MDT image: ELF32 header, phdrs, and (when `inline`) every
/// segment's data at its `p_offset`. Returns (mdt bytes, per-segment file
/// data). Phdr 0 should be the non-`PT_LOAD` ELF-header segment.
pub fn build_mdt(entry: u32, segs: &[Seg], inline: bool) -> (Vec<u8>, Vec<Vec<u8>>) {
    let phoff = 52usize;
    let hdr_len = phoff + segs.len() * 32;
    let mut data_off = (hdr_len + 0xf) & !0xf;
    let mut offsets = Vec::new();
    let mut files = Vec::new();
    for (i, s) in segs.iter().enumerate() {
        let d = if i == 0 {
            Vec::new()
        } else {
            vec![s.fill; s.filesz as usize]
        };
        offsets.push(if i == 0 { 0 } else { data_off as u32 });
        if i != 0 {
            data_off += s.filesz as usize;
        }
        files.push(d);
    }
    let mut out = vec![0u8; hdr_len];
    out[..4].copy_from_slice(b"\x7fELF");
    out[4] = 1; // ELFCLASS32
    out[5] = 1; // little-endian
    out[6] = 1;
    out[16..18].copy_from_slice(&2u16.to_le_bytes());
    out[18..20].copy_from_slice(&164u16.to_le_bytes()); // EM_QDSP6
    out[24..28].copy_from_slice(&entry.to_le_bytes());
    out[28..32].copy_from_slice(&(phoff as u32).to_le_bytes());
    out[40..42].copy_from_slice(&52u16.to_le_bytes());
    out[42..44].copy_from_slice(&32u16.to_le_bytes());
    out[44..46].copy_from_slice(&(segs.len() as u16).to_le_bytes());
    for (i, s) in segs.iter().enumerate() {
        let o = phoff + i * 32;
        let filesz = if i == 0 { hdr_len as u32 } else { s.filesz };
        let f = [
            s.p_type, offsets[i], s.paddr, s.paddr, filesz, s.memsz, s.flags, 0x1000,
        ];
        for (j, v) in f.iter().enumerate() {
            out[o + j * 4..o + j * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
    }
    if inline {
        for (i, d) in files.iter().enumerate().skip(1) {
            let o = offsets[i] as usize;
            if out.len() < o + d.len() {
                out.resize(o + d.len(), 0);
            }
            out[o..o + d.len()].copy_from_slice(d);
        }
    }
    (out, files)
}

// ── SMEM ───────────────────────────────────────────────────────────

/// Build a version-12 SMEM region of `size` bytes in `regs`: header,
/// `$TOC` with a global partition and an APPS↔`remote` private
/// partition, and a `SIII` info block (`item_count` items).
/// Returns (global partition base, private partition base).
pub fn build_smem_v12(regs: &FakeRegs, size: u32, remote: u16, item_count: u16) -> (u32, u32) {
    build_smem_v12_sized(regs, size, remote, item_count, 0x4000)
}

/// [`build_smem_v12`] with a `priv_size`-byte private partition at
/// 0x3000 (GLINK needs two 16 KiB FIFOs).
pub fn build_smem_v12_sized(
    regs: &FakeRegs,
    size: u32,
    remote: u16,
    item_count: u16,
    priv_size: u32,
) -> (u32, u32) {
    use crate::smem::*;
    regs.set(
        HDR_VERSION + SMEM_MASTER_SBL_VERSION_INDEX * 4,
        SMEM_GLOBAL_PART_VERSION << 16,
    );
    let ptable = size - PTABLE_SIZE;
    let glob = 0x1000;
    let glob_size = 0x2000;
    let priv_base = 0x3000;
    regs.set(ptable, u32::from_le_bytes(PTABLE_MAGIC));
    regs.set(ptable + 4, 1);
    regs.set(ptable + 8, 2);
    let entry = |i: u32, off: u32, sz: u32, h0: u16, h1: u16, cl: u32| {
        let e = ptable + PTABLE_HDR + i * PTABLE_ENTRY;
        regs.set(e, off);
        regs.set(e + 4, sz);
        regs.set(e + 12, h0 as u32 | ((h1 as u32) << 16));
        regs.set(e + 16, cl);
    };
    entry(0, glob, glob_size, SMEM_GLOBAL_HOST, SMEM_GLOBAL_HOST, 64);
    entry(1, priv_base, priv_size, SMEM_HOST_APPS, remote, 64);
    let info = ptable + PTABLE_HDR + 2 * PTABLE_ENTRY;
    regs.set(info, u32::from_le_bytes(INFO_MAGIC));
    regs.set(info + 4, size);
    regs.set(info + 16, item_count as u32);
    let part = |base: u32, sz: u32, h0: u16, h1: u16| {
        regs.set(base, u32::from_le_bytes(PART_MAGIC));
        regs.set(base + 4, h0 as u32 | ((h1 as u32) << 16));
        regs.set(base + 8, sz);
        regs.set(base + 12, PART_HDR);
        regs.set(base + 16, sz);
    };
    part(glob, glob_size, SMEM_GLOBAL_HOST, SMEM_GLOBAL_HOST);
    part(priv_base, priv_size, SMEM_HOST_APPS, remote);
    (glob, priv_base)
}

// ── FDT ────────────────────────────────────────────────────────────

/// A devicetree node for [`build_fdt`].
#[derive(Clone, Debug, Default)]
pub struct Node {
    pub name: String,
    pub props: Vec<(String, Vec<u8>)>,
    pub children: Vec<Node>,
}

impl Node {
    pub fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            ..Default::default()
        }
    }
    pub fn prop(mut self, name: &str, v: Vec<u8>) -> Self {
        self.props.push((String::from(name), v));
        self
    }
    pub fn u32s(self, name: &str, v: &[u32]) -> Self {
        self.prop(name, be32s(v))
    }
    pub fn strs(self, name: &str, v: &[&str]) -> Self {
        self.prop(name, strlist(v))
    }
    pub fn child(mut self, c: Node) -> Self {
        self.children.push(c);
        self
    }
}

pub fn be32s(v: &[u32]) -> Vec<u8> {
    v.iter().flat_map(|x| x.to_be_bytes()).collect()
}

pub fn strlist(v: &[&str]) -> Vec<u8> {
    let mut o = Vec::new();
    for s in v {
        o.extend_from_slice(s.as_bytes());
        o.push(0);
    }
    o
}

fn emit(s: &mut Vec<u8>, strings: &mut Vec<u8>, n: &Node) {
    s.extend_from_slice(&1u32.to_be_bytes());
    s.extend_from_slice(n.name.as_bytes());
    s.push(0);
    while s.len() % 4 != 0 {
        s.push(0);
    }
    for (name, value) in &n.props {
        let off = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        s.extend_from_slice(&3u32.to_be_bytes());
        s.extend_from_slice(&(value.len() as u32).to_be_bytes());
        s.extend_from_slice(&off.to_be_bytes());
        s.extend_from_slice(value);
        while s.len() % 4 != 0 {
            s.push(0);
        }
    }
    for c in &n.children {
        emit(s, strings, c);
    }
    s.extend_from_slice(&2u32.to_be_bytes());
}

/// Serialise `root` (its name is ignored; it is the `/` node).
pub fn build_fdt(root: &Node) -> Vec<u8> {
    let mut s = Vec::new();
    let mut strings = Vec::new();
    let mut r = root.clone();
    r.name = String::new();
    emit(&mut s, &mut strings, &r);
    s.extend_from_slice(&9u32.to_be_bytes());
    let off_struct = 40u32 + 16;
    let off_strings = off_struct + s.len() as u32;
    let total = off_strings + strings.len() as u32;
    let mut out = Vec::new();
    for v in [
        0xd00d_feedu32,
        total,
        off_struct,
        off_strings,
        40,
        17,
        16,
        0,
        strings.len() as u32,
        s.len() as u32,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&s);
    out.extend_from_slice(&strings);
    out
}

/// GIC SPI specifier cells `<0 n 1>` (edge rising).
pub fn spi(n: u32) -> [u32; 3] {
    [0, n, 1]
}

/// Phandles used by [`ipq6018_wifi_dt`] / [`sc7280_wifi_dt`].
pub mod ph {
    pub const INTC: u32 = 1;
    pub const GCC: u32 = 2;
    pub const TCSR: u32 = 3;
    pub const TCSR_MUTEX: u32 = 4;
    pub const APCS: u32 = 5;
    pub const SMEM_REGION: u32 = 6;
    pub const Q6_REGION: u32 = 7;
    pub const SMP2P_OUT: u32 = 8;
    pub const SMP2P_IN: u32 = 9;
    pub const RPROC: u32 = 10;
    pub const IPCC: u32 = 11;
    pub const WPSS_MEM: u32 = 12;
    pub const WLAN_OUT: u32 = 13;
    pub const WLAN_IN: u32 = 14;
    pub const WLAN_FW_MEM: u32 = 15;
    pub const WLAN_CE_MEM: u32 = 16;
}

fn reserved(name: &str, phandle: u32, base: u64, size: u64) -> Node {
    Node::new(name)
        .u32s(
            "reg",
            &[
                (base >> 32) as u32,
                base as u32,
                (size >> 32) as u32,
                size as u32,
            ],
        )
        .u32s("phandle", &[phandle])
}

fn reg2(base: u64, size: u64) -> Vec<u32> {
    vec![
        (base >> 32) as u32,
        base as u32,
        (size >> 32) as u32,
        size as u32,
    ]
}

/// The IPQ6018 tree pieces ath11k AHB touches, transcribed from Linux
/// `arch/arm64/boot/dts/qcom/ipq6018.dtsi` (`q6v5_wcss`, `wcss-smp2p`,
/// `smem`, `tcsr`, `tcsr_mutex`, `apcs_glb`, `gcc`) plus a `wifi@c000000`
/// node per the `qcom,ath11k.yaml` example with `compat` as compatible.
pub fn ipq6018_wifi_dt(compat: &str, wifi_irqs: &[u32]) -> Vec<u8> {
    let mut wifi_cells = Vec::new();
    for n in wifi_irqs {
        wifi_cells.extend_from_slice(&spi(*n));
    }
    let names: Vec<&str> = crate::fixtures::AHB_IRQ_NAMES[..wifi_irqs.len()].to_vec();
    let root = Node::new("")
        .u32s("#address-cells", &[2])
        .u32s("#size-cells", &[2])
        .u32s("interrupt-parent", &[ph::INTC])
        .child(
            Node::new("reserved-memory")
                .u32s("#address-cells", &[2])
                .u32s("#size-cells", &[2])
                .prop("ranges", Vec::new())
                .child(reserved(
                    "memory@4aa00000",
                    ph::SMEM_REGION,
                    0x4aa0_0000,
                    0x10_0000,
                ))
                .child(reserved(
                    "memory@4ab00000",
                    ph::Q6_REGION,
                    0x4ab0_0000,
                    0x550_0000,
                )),
        )
        .child(
            Node::new("smem")
                .strs("compatible", &["qcom,smem"])
                .u32s("memory-region", &[ph::SMEM_REGION])
                .u32s("hwlocks", &[ph::TCSR_MUTEX, 3]),
        )
        .child(
            Node::new("soc@0")
                .u32s("#address-cells", &[2])
                .u32s("#size-cells", &[2])
                .u32s("ranges", &[0, 0, 0, 0, 0, 0xffff_ffff])
                .child(
                    Node::new("interrupt-controller@b000000")
                        .strs("compatible", &["qcom,msm-qgic2"])
                        .prop("interrupt-controller", Vec::new())
                        .u32s("#interrupt-cells", &[3])
                        .u32s("reg", &reg2(0x0b00_0000, 0x1000))
                        .u32s("phandle", &[ph::INTC]),
                )
                .child(
                    Node::new("clock-controller@1800000")
                        .strs("compatible", &["qcom,gcc-ipq6018"])
                        .u32s("reg", &reg2(0x0180_0000, 0x8_0000))
                        .u32s("#clock-cells", &[1])
                        .u32s("#reset-cells", &[1])
                        .u32s("phandle", &[ph::GCC]),
                )
                .child(
                    Node::new("hwlock@1905000")
                        .strs(
                            "compatible",
                            &["qcom,ipq6018-tcsr-mutex", "qcom,tcsr-mutex"],
                        )
                        .u32s("reg", &reg2(0x0190_5000, 0x2_0000))
                        .u32s("#hwlock-cells", &[1])
                        .u32s("phandle", &[ph::TCSR_MUTEX]),
                )
                .child(
                    Node::new("syscon@1937000")
                        .strs("compatible", &["qcom,tcsr-ipq6018", "syscon"])
                        .u32s("reg", &reg2(0x0193_7000, 0x2_1000))
                        .u32s("phandle", &[ph::TCSR]),
                )
                .child(
                    Node::new("mailbox@b111000")
                        .strs("compatible", &["qcom,ipq6018-apcs-apps-global"])
                        .u32s("reg", &reg2(0x0b11_1000, 0x1000))
                        .u32s("#mbox-cells", &[1])
                        .u32s("phandle", &[ph::APCS]),
                )
                .child(
                    Node::new("remoteproc@cd00000")
                        .strs("compatible", &["qcom,ipq6018-wcss-pil"])
                        .u32s("reg", &[0, 0x0cd0_0000, 0, 0x4040, 0, 0x004a_b000, 0, 0x20])
                        .strs("reg-names", &["qdsp6", "rmb"])
                        .u32s(
                            "interrupts-extended",
                            &[
                                ph::INTC,
                                0,
                                325,
                                1,
                                ph::SMP2P_IN,
                                0,
                                0,
                                ph::SMP2P_IN,
                                1,
                                0,
                                ph::SMP2P_IN,
                                2,
                                0,
                                ph::SMP2P_IN,
                                3,
                                0,
                            ],
                        )
                        .strs(
                            "interrupt-names",
                            &["wdog", "fatal", "ready", "handover", "stop-ack"],
                        )
                        .u32s("resets", &[ph::GCC, 127, ph::GCC, 22, ph::GCC, 23])
                        .strs(
                            "reset-names",
                            &["wcss_aon_reset", "wcss_reset", "wcss_q6_reset"],
                        )
                        .u32s("clocks", &[ph::GCC, 136])
                        .strs("clock-names", &["prng"])
                        .u32s("qcom,halt-regs", &[ph::TCSR, 0x18000, 0x1b000, 0xe000])
                        .u32s("qcom,smem-states", &[ph::SMP2P_OUT, 0, ph::SMP2P_OUT, 1])
                        .strs("qcom,smem-state-names", &["shutdown", "stop"])
                        .u32s("memory-region", &[ph::Q6_REGION])
                        .u32s("phandle", &[ph::RPROC]),
                )
                .child(
                    Node::new("wifi@c000000")
                        .strs("compatible", &[compat])
                        .u32s("reg", &reg2(0x0c00_0000, 0x200_0000))
                        .prop("interrupts", be32s(&wifi_cells))
                        .strs("interrupt-names", &names)
                        .u32s("qcom,rproc", &[ph::RPROC]),
                ),
        )
        .child(
            Node::new("wcss-smp2p")
                .strs("compatible", &["qcom,smp2p"])
                .u32s("qcom,smem", &[435, 428])
                .u32s("interrupt-parent", &[ph::INTC])
                .u32s("interrupts", &spi(322))
                .u32s("mboxes", &[ph::APCS, 9])
                .u32s("qcom,local-pid", &[0])
                .u32s("qcom,remote-pid", &[1])
                .child(
                    Node::new("master-kernel")
                        .strs("qcom,entry-name", &["master-kernel"])
                        .u32s("#qcom,smem-state-cells", &[1])
                        .u32s("phandle", &[ph::SMP2P_OUT]),
                )
                .child(
                    Node::new("slave-kernel")
                        .strs("qcom,entry-name", &["slave-kernel"])
                        .prop("interrupt-controller", Vec::new())
                        .u32s("#interrupt-cells", &[2])
                        .u32s("phandle", &[ph::SMP2P_IN]),
                ),
        );
    build_fdt(&root)
}

/// The SC7280 pieces WCN6750 touches, from Linux `sc7280.dtsi`
/// (`remoteproc_wpss`, `smp2p-wpss`, `wifi@17a10040`, `ipcc`,
/// `wpss_mem`/`wlan_fw_mem`/`wlan_ce_mem`).
pub fn sc7280_wifi_dt() -> Vec<u8> {
    let mut wifi = Vec::new();
    for n in 768..800 {
        wifi.extend_from_slice(&spi(n));
    }
    let root = Node::new("")
        .u32s("#address-cells", &[2])
        .u32s("#size-cells", &[2])
        .u32s("interrupt-parent", &[ph::INTC])
        .child(
            Node::new("reserved-memory")
                .u32s("#address-cells", &[2])
                .u32s("#size-cells", &[2])
                .prop("ranges", Vec::new())
                .child(reserved(
                    "memory@80900000",
                    ph::SMEM_REGION,
                    0x8090_0000,
                    0x20_0000,
                ))
                .child(reserved(
                    "wpss@9ae00000",
                    ph::WPSS_MEM,
                    0x9ae0_0000,
                    0x190_0000,
                ))
                .child(reserved(
                    "wlan-fw@80c00000",
                    ph::WLAN_FW_MEM,
                    0x80c0_0000,
                    0xc0_0000,
                ))
                .child(reserved(
                    "wlan-ce@4cd000",
                    ph::WLAN_CE_MEM,
                    0x004c_d000,
                    0x1000,
                )),
        )
        .child(
            Node::new("smem")
                .strs("compatible", &["qcom,smem"])
                .u32s("memory-region", &[ph::SMEM_REGION])
                .u32s("hwlocks", &[ph::TCSR_MUTEX, 3]),
        )
        .child(
            Node::new("soc@0")
                .u32s("#address-cells", &[2])
                .u32s("#size-cells", &[2])
                .u32s("ranges", &[0, 0, 0, 0, 0, 0xffff_ffff])
                .child(
                    Node::new("interrupt-controller@17a00000")
                        .strs("compatible", &["arm,gic-v3"])
                        .prop("interrupt-controller", Vec::new())
                        .u32s("#interrupt-cells", &[3])
                        .u32s("reg", &reg2(0x17a0_0000, 0x1_0000))
                        .u32s("phandle", &[ph::INTC]),
                )
                .child(
                    Node::new("mailbox@408000")
                        .strs("compatible", &["qcom,sc7280-ipcc", "qcom,ipcc"])
                        .u32s("reg", &reg2(0x0040_8000, 0x1000))
                        .prop("interrupt-controller", Vec::new())
                        .u32s("#interrupt-cells", &[3])
                        .u32s("#mbox-cells", &[2])
                        .u32s("phandle", &[ph::IPCC]),
                )
                .child(
                    Node::new("hwlock@1f40000")
                        .strs("compatible", &["qcom,tcsr-mutex"])
                        .u32s("reg", &reg2(0x01f4_0000, 0x2_0000))
                        .u32s("#hwlock-cells", &[1])
                        .u32s("phandle", &[ph::TCSR_MUTEX]),
                )
                .child(
                    Node::new("remoteproc@8a00000")
                        .strs("compatible", &["qcom,sc7280-wpss-pas"])
                        .u32s("reg", &reg2(0x08a0_0000, 0x1_0000))
                        .u32s(
                            "interrupts-extended",
                            &[
                                ph::INTC,
                                0,
                                587,
                                1,
                                ph::SMP2P_IN,
                                0,
                                1,
                                ph::SMP2P_IN,
                                1,
                                1,
                                ph::SMP2P_IN,
                                2,
                                1,
                                ph::SMP2P_IN,
                                3,
                                1,
                                ph::SMP2P_IN,
                                7,
                                1,
                            ],
                        )
                        .strs(
                            "interrupt-names",
                            &[
                                "wdog",
                                "fatal",
                                "ready",
                                "handover",
                                "stop-ack",
                                "shutdown-ack",
                            ],
                        )
                        .u32s("memory-region", &[ph::WPSS_MEM])
                        .u32s("qcom,smem-states", &[ph::SMP2P_OUT, 0])
                        .strs("qcom,smem-state-names", &["stop"])
                        .u32s("phandle", &[ph::RPROC]),
                )
                .child(
                    Node::new("wifi@17a10040")
                        .strs("compatible", &["qcom,wcn6750-wifi"])
                        .u32s("reg", &reg2(0x17a1_0040, 0))
                        .prop("interrupts", be32s(&wifi))
                        .u32s("qcom,rproc", &[ph::RPROC])
                        .u32s("memory-region", &[ph::WLAN_FW_MEM, ph::WLAN_CE_MEM])
                        .u32s("qcom,smem-states", &[ph::WLAN_OUT, 0])
                        .strs("qcom,smem-state-names", &["wlan-smp2p-out"]),
                ),
        )
        .child(
            Node::new("smp2p-wpss")
                .strs("compatible", &["qcom,smp2p"])
                .u32s("qcom,smem", &[617, 616])
                .u32s("interrupts-extended", &[ph::IPCC, 24, 2, 1])
                .u32s("mboxes", &[ph::IPCC, 24, 2])
                .u32s("qcom,local-pid", &[0])
                .u32s("qcom,remote-pid", &[13])
                .child(
                    Node::new("master-kernel")
                        .strs("qcom,entry-name", &["master-kernel"])
                        .u32s("#qcom,smem-state-cells", &[1])
                        .u32s("phandle", &[ph::SMP2P_OUT]),
                )
                .child(
                    Node::new("slave-kernel")
                        .strs("qcom,entry-name", &["slave-kernel"])
                        .prop("interrupt-controller", Vec::new())
                        .u32s("#interrupt-cells", &[2])
                        .u32s("phandle", &[ph::SMP2P_IN]),
                )
                .child(
                    Node::new("wlan-ap-to-wpss")
                        .strs("qcom,entry-name", &["wlan"])
                        .u32s("#qcom,smem-state-cells", &[1])
                        .u32s("phandle", &[ph::WLAN_OUT]),
                )
                .child(
                    Node::new("wlan-wpss-to-ap")
                        .strs("qcom,entry-name", &["wlan"])
                        .prop("interrupt-controller", Vec::new())
                        .u32s("#interrupt-cells", &[2])
                        .u32s("phandle", &[ph::WLAN_IN]),
                ),
        );
    build_fdt(&root)
}

/// Linux `ath11k/ahb.c` `irq_name[]` order (the `qcom,ath11k.yaml`
/// `interrupt-names` order), used to label fixture `wifi@` nodes.
pub const AHB_IRQ_NAMES: [&str; 52] = [
    "misc-pulse1",
    "misc-latch",
    "sw-exception",
    "watchdog",
    "ce0",
    "ce1",
    "ce2",
    "ce3",
    "ce4",
    "ce5",
    "ce6",
    "ce7",
    "ce8",
    "ce9",
    "ce10",
    "ce11",
    "host2wbm-desc-feed",
    "host2reo-re-injection",
    "host2reo-command",
    "host2rxdma-monitor-ring3",
    "host2rxdma-monitor-ring2",
    "host2rxdma-monitor-ring1",
    "reo2ost-exception",
    "wbm2host-rx-release",
    "reo2host-status",
    "reo2host-destination-ring4",
    "reo2host-destination-ring3",
    "reo2host-destination-ring2",
    "reo2host-destination-ring1",
    "rxdma2host-monitor-destination-mac3",
    "rxdma2host-monitor-destination-mac2",
    "rxdma2host-monitor-destination-mac1",
    "ppdu-end-interrupts-mac3",
    "ppdu-end-interrupts-mac2",
    "ppdu-end-interrupts-mac1",
    "rxdma2host-monitor-status-ring-mac3",
    "rxdma2host-monitor-status-ring-mac2",
    "rxdma2host-monitor-status-ring-mac1",
    "host2rxdma-host-buf-ring-mac3",
    "host2rxdma-host-buf-ring-mac2",
    "host2rxdma-host-buf-ring-mac1",
    "rxdma2host-destination-ring-mac3",
    "rxdma2host-destination-ring-mac2",
    "rxdma2host-destination-ring-mac1",
    "host2tcl-input-ring4",
    "host2tcl-input-ring3",
    "host2tcl-input-ring2",
    "host2tcl-input-ring1",
    "wbm2host-tx-completions-ring3",
    "wbm2host-tx-completions-ring2",
    "wbm2host-tx-completions-ring1",
    "tcl2host-status-ring",
];

// ── GLINK remote ───────────────────────────────────────────────────

/// The remote end of a GLINK-SMEM edge over a [`FakeRegs`] SMEM region:
/// it fills the host's RX FIFO (item 480) and drains the host's TX FIFO
/// (item 479), keeping the shared descriptor indices as the Q6 would.
#[derive(Debug)]
pub struct GlinkRemote<'a> {
    pub regs: &'a FakeRegs,
    /// Descriptor: host tx tail, tx head, rx tail, rx head.
    pub desc: u32,
    /// Host TX FIFO (offset, len) — what the remote reads.
    pub host_tx: (u32, u32),
    /// Host RX FIFO (offset, len) — what the remote writes.
    pub host_rx: (u32, u32),
}

impl<'a> GlinkRemote<'a> {
    fn rd_bytes(&self, off: u32, n: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(n);
        for i in 0..n as u32 {
            let a = off + i;
            v.push(self.regs.get(a & !3).to_le_bytes()[(a & 3) as usize]);
        }
        v
    }
    fn wr_byte(&self, a: u32, b: u8) {
        let mut w = self.regs.get(a & !3).to_le_bytes();
        w[(a & 3) as usize] = b;
        self.regs.set(a & !3, u32::from_le_bytes(w));
    }

    /// Append raw bytes (one or more commands, each 8-aligned) to the
    /// host's RX FIFO and publish the new head.
    pub fn push(&self, bytes: &[u8]) {
        let (fifo, len) = self.host_rx;
        let mut head = self.regs.get(self.desc + 12);
        for b in bytes {
            self.wr_byte(fifo + head, *b);
            head += 1;
            if head >= len {
                head = 0;
            }
        }
        let mut h = (head + 7) & !7;
        if h >= len {
            h -= len;
        }
        self.regs.set(self.desc + 12, h);
    }

    /// Bytes the host has written and the remote not yet consumed.
    pub fn tx_pending(&self) -> usize {
        let (_, len) = self.host_tx;
        let tail = self.regs.get(self.desc);
        let head = self.regs.get(self.desc + 4);
        if head >= tail {
            (head - tail) as usize
        } else {
            (len - tail + head) as usize
        }
    }

    /// Drain the host's TX FIFO into whole commands: each element is
    /// (cmd, param1, param2, trailing bytes of that command).
    pub fn pop(&self) -> Vec<(u16, u16, u32, Vec<u8>)> {
        use crate::glink::*;
        let (fifo, len) = self.host_tx;
        let mut out = Vec::new();
        let read = |t: u32, n: usize| -> Vec<u8> {
            let first = (n as u32).min(len - t) as usize;
            let mut v = self.rd_bytes(fifo + t, first);
            if first < n {
                v.extend(self.rd_bytes(fifo, n - first));
            }
            v
        };
        while self.tx_pending() > 0 {
            let tail = self.regs.get(self.desc);
            let h = read(tail, 8);
            let cmd = u16::from_le_bytes([h[0], h[1]]);
            let p1 = u16::from_le_bytes([h[2], h[3]]);
            let p2 = u32::from_le_bytes([h[4], h[5], h[6], h[7]]);
            let t2 = (tail + 8) % len;
            let extra = match cmd {
                GLINK_CMD_OPEN => p2 as usize,
                GLINK_CMD_INTENT => p2 as usize * 8,
                GLINK_CMD_TX_DATA | GLINK_CMD_TX_DATA_CONT => {
                    let c = read(t2, 4);
                    8 + u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as usize
                }
                _ => 0,
            };
            let body = read(t2, extra);
            out.push((cmd, p1, p2, body));
            let next = (tail as usize + ((8 + extra + 7) & !7)) % len as usize;
            self.regs.set(self.desc, next as u32);
        }
        out
    }
}

/// Encode one GLINK command (header + body, padded to 8).
pub fn glink_cmd(cmd: u16, p1: u16, p2: u32, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&cmd.to_le_bytes());
    v.extend_from_slice(&p1.to_le_bytes());
    v.extend_from_slice(&p2.to_le_bytes());
    v.extend_from_slice(body);
    while v.len() % 8 != 0 {
        v.push(0);
    }
    v
}

/// Encode a remote `TX_DATA`/`TX_DATA_CONT` chunk.
pub fn glink_data(cont: bool, rcid: u16, liid: u32, chunk: &[u8], left: u32) -> Vec<u8> {
    use crate::glink::*;
    let mut body = Vec::new();
    body.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
    body.extend_from_slice(&left.to_le_bytes());
    body.extend_from_slice(chunk);
    let cmd = if cont {
        GLINK_CMD_TX_DATA_CONT
    } else {
        GLINK_CMD_TX_DATA
    };
    glink_cmd(cmd, rcid, liid, &body)
}

/// A counting [`Kick`](crate::ipc::Kick).
#[derive(Debug, Default)]
pub struct CountingKick(pub core::sync::atomic::AtomicUsize);
impl crate::ipc::Kick for &CountingKick {
    fn kick(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}
impl CountingKick {
    pub fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// A GLINK-SMEM edge over a fresh RAM SMEM with the remote's RX FIFO
/// allocated: returns the edge (VERSION already queued and flushed)
/// and its [`GlinkRemote`]. `regs` must outlive both.
pub fn glink_smem_edge<'a>(
    regs: &'a FakeRegs,
    lock_regs: &'a FakeRegs,
    delay: &'a FakeDelay,
    kick: &'a CountingKick,
    remote_pid: u16,
) -> (
    crate::glink::Glink<crate::glink::GlinkSmem<&'a FakeRegs, &'a CountingKick>>,
    GlinkRemote<'a>,
) {
    use crate::glink::*;
    use crate::hwlock::TcsrMutex;
    use crate::smem::Smem;
    const SIZE: u32 = 0x20000;
    build_smem_v12_sized(regs, SIZE, remote_pid, 512, 0x10000);
    let lock = TcsrMutex::new(lock_regs, delay, 3).expect("tcsr");
    let smem = Smem::probe(regs, SIZE).expect("smem");
    // The remote allocates its own TX FIFO (our RX) before it starts.
    run(smem.alloc(&lock, remote_pid, SMEM_GLINK_NATIVE_XPRT_FIFO_1, 0x4000))
        .expect("pending")
        .expect("alloc rx fifo");
    let rx = smem
        .get(remote_pid, SMEM_GLINK_NATIVE_XPRT_FIFO_1)
        .expect("rx");
    let pipe = run(GlinkSmem::register(smem, &lock, remote_pid, kick))
        .expect("pending")
        .expect("register");
    let remote = GlinkRemote {
        regs,
        desc: pipe.descriptor(),
        host_tx: pipe.tx_fifo(),
        host_rx: (rx.offset, rx.len),
    };
    (Glink::new(pipe, GLINK_FEATURE_INTENT_REUSE), remote)
}

/// Play the remote through version negotiation and a remote-initiated
/// open of `name` (remote cid `rcid`), offering `intents` (size, iid)
/// once the host's OPEN arrives. Returns the host lcid.
pub fn glink_remote_open<P: crate::glink::GlinkPipe>(
    g: &mut crate::glink::Glink<P>,
    r: &GlinkRemote<'_>,
    name: &str,
    rcid: u16,
    intents: &[(u32, u32)],
) -> Option<u16> {
    use crate::glink::*;
    r.pop();
    r.push(&glink_cmd(
        GLINK_CMD_VERSION,
        1,
        GLINK_FEATURE_INTENT_REUSE,
        &[],
    ));
    let mut nm = Vec::from(name.as_bytes());
    nm.push(0);
    r.push(&glink_cmd(GLINK_CMD_OPEN, rcid, nm.len() as u32, &nm));
    g.process_rx();
    let out = r.pop();
    let lcid = out.iter().find(|m| m.0 == GLINK_CMD_OPEN)?.1;
    let mut body = Vec::new();
    for (size, iid) in intents {
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&iid.to_le_bytes());
    }
    r.push(&glink_cmd(GLINK_CMD_OPEN_ACK, lcid, 0, &[]));
    if !intents.is_empty() {
        r.push(&glink_cmd(
            GLINK_CMD_INTENT,
            rcid,
            intents.len() as u32,
            &body,
        ));
    }
    g.process_rx();
    Some(lcid)
}
