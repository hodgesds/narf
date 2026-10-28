//! Kernel-test smokes for the Qualcomm SoC layer.
//!
//! Expected values are hand-derived from the Linux sources named in each
//! module (`qcom_scm*.c`, `mdt_loader.c`, `smem.c`, `smp2p.c`,
//! `reset.c`/`clk-branch.c`/`gcc-ipq*.c`, `qcom_q6v5{,_wcss,_pas}.c`, and
//! the `ipq6018.dtsi`/`sc7280.dtsi` nodes), not from the code under test.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use narf_kernel_test::{kernel_test_in, kt_assert, kt_assert_eq, TestResult};

use crate::fixtures::*;
use crate::gcc::{self, Gcc, GccError, ResetLine};
use crate::hwlock::{HwLockError, HwSpinlock, TcsrMutex};
use crate::io::{Delay, RegIo};
use crate::ipc::{ApcsIpc, Ipcc, Kick};
use crate::mdt::{self, Mdt, MdtError, PT_LOAD, QCOM_MDT_RELOCATABLE, QCOM_MDT_TYPE_HASH};
use crate::pas::PasRproc;
use crate::platform::{self, IrqSource, KickDt, RprocKind};
use crate::q6v5::{Q6Error, Q6Event, Q6v5};
use crate::rproc::{Carveout, RprocError, RprocState, StopState};
use crate::scm::{self, Convention, Scm, ScmError};
use crate::smem::{Smem, SmemError};
use crate::smp2p::{Smp2p, Smp2pConfig, ITEM_SIZE, SMP2P_MAGIC};
use crate::wcss::{self, Q6Wcss, WcssRegs, WcssResets};

const SUB: &str = "drivers/soc/qcom";

// ── SCM ────────────────────────────────────────────────────────────

fn smoke_qcom_scm_pas_encoding_and_probe() -> TestResult {
    let smc = FakeSmc::ok();
    let d = FakeDelay::new();
    let mut s = Scm::new(&smc);
    kt_assert_eq!(s.probe_convention(), Convention::Arm64);
    // Probe: fast SMC64 SiP IS_CALL_AVAIL(0x0601), arginfo 1, arg = own fnid | SIP<<24.
    let c = smc.calls();
    kt_assert_eq!(c[0][0], 0xC200_0601);
    kt_assert_eq!(c[0][1], 1);
    kt_assert_eq!(c[0][2], 0x0200_0601);
    kt_assert!(run(s.pas_init_image(6, 0x8000_0000, &d)).unwrap().is_ok());
    kt_assert!(run(s.pas_mem_setup(6, 0x9ae0_0000, 0x190_0000, &d))
        .unwrap()
        .is_ok());
    kt_assert!(run(s.pas_auth_and_reset(6, &d)).unwrap().is_ok());
    kt_assert!(run(s.pas_shutdown(6, &d)).unwrap().is_ok());
    let c = smc.calls();
    // Yielding (std) SMC64 SiP calls: 0x4200_02cc.
    kt_assert_eq!(c[1][0], 0x4200_0201);
    kt_assert_eq!(c[1][1], 0x82, "QCOM_SCM_ARGS(2, VAL, RW)");
    kt_assert_eq!((c[1][2], c[1][3]), (6, 0x8000_0000));
    kt_assert_eq!(c[2][0], 0x4200_0202);
    kt_assert_eq!(c[2][1], 3);
    kt_assert_eq!((c[2][2], c[2][3], c[2][4]), (6, 0x9ae0_0000, 0x190_0000));
    kt_assert_eq!(c[3][0], 0x4200_0205);
    kt_assert_eq!(c[4][0], 0x4200_0206);
    kt_assert!(c.iter().all(|r| r[6] == 0), "x6 session word starts 0");
    // pas_supported = IS_CALL_AVAIL(PIL, 7) then PAS_IS_SUPPORTED.
    kt_assert!(run(s.pas_supported(6, &d)).unwrap());
    let f = smc.fnids();
    kt_assert_eq!(&f[f.len() - 2..], &[(6, 1), (2, 7)]);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_scm_pas_encoding_and_probe);

fn smoke_qcom_scm_retry_and_errors() -> TestResult {
    let d = FakeDelay::new();
    // ARM64 probe fails → ARM32 answers.
    let smc = FakeSmc::new(|r, _| {
        let mut o = [0u64; 8];
        if r[0] & (1 << 30) != 0 {
            o[0] = u64::MAX; // SMCCC NOT_SUPPORTED on SMC64
        } else if r[0] as u32 & 0xffff == 0x0601 {
            o[1] = 1;
        }
        o
    });
    let mut s = Scm::new(&smc);
    kt_assert_eq!(s.probe_convention(), Convention::Arm32);
    kt_assert_eq!(smc.calls()[1][0], 0x8200_0601);
    // Nobody answers → legacy, refused.
    let dead = FakeSmc::new(|_, _| [u64::MAX, 0, 0, 0, 0, 0, 0, 0]);
    let mut s = Scm::new(&dead);
    kt_assert_eq!(
        run(s.pas_auth_and_reset(6, &d)).unwrap(),
        Err(ScmError::LegacyConvention)
    );
    // INTERRUPTED twice: re-issue with x0 = 1 and the returned x6.
    let smc = FakeSmc::new(|r, n| {
        let mut o = [0u64; 8];
        if r[0] as u32 & 0xffff == 0x0601 {
            o[1] = 1;
        } else if n < 3 {
            o[0] = 1;
            o[6] = 0x77 + n as u64;
        }
        o
    });
    let mut s = Scm::new(&smc);
    kt_assert!(run(s.pas_auth_and_reset(6, &d)).unwrap().is_ok());
    let c = smc.calls();
    kt_assert_eq!(c.len(), 4);
    kt_assert_eq!((c[2][0], c[2][6]), (1, 0x78));
    kt_assert_eq!((c[3][0], c[3][6]), (1, 0x79));
    // EBUSY: 20 sleeps of 30 ms then -EBUSY.
    let busy = FakeSmc::new(|r, _| {
        let mut o = [0u64; 8];
        if r[0] as u32 & 0xffff == 0x0601 {
            o[1] = 1;
        } else {
            o[0] = scm::SCM_V2_EBUSY as u64;
        }
        o
    });
    let d2 = FakeDelay::new();
    let mut s = Scm::new(&busy);
    kt_assert_eq!(run(s.pas_shutdown(6, &d2)).unwrap(), Err(ScmError::Busy));
    kt_assert_eq!(d2.slept_us.load(Ordering::Relaxed), 20 * 30_000);
    kt_assert_eq!(busy.calls().len(), 1 + 21);
    // Status remap and non-zero result[0].
    for (code, want) in [
        (-1i64, ScmError::Io),
        (-2, ScmError::Invalid),
        (-3, ScmError::Invalid),
        (-4, ScmError::NotSupported),
        (-5, ScmError::NoMem),
        (-99, ScmError::Invalid),
    ] {
        kt_assert_eq!(scm::remap_error(code), want);
    }
    let res = FakeSmc::new(|r, _| {
        let mut o = [0u64; 8];
        o[1] = if r[0] as u32 & 0xffff == 0x0601 {
            1
        } else {
            0x2a
        };
        o
    });
    let mut s = Scm::new(&res);
    kt_assert_eq!(
        run(s.pas_auth_and_reset(6, &d)).unwrap(),
        Err(ScmError::Result(0x2a))
    );
    let wq = FakeSmc::new(|r, _| {
        let mut o = [0u64; 8];
        if r[0] as u32 & 0xffff == 0x0601 {
            o[1] = 1;
        } else {
            o[0] = scm::SCM_WAITQ_SLEEP as u64;
        }
        o
    });
    let mut s = Scm::new(&wq);
    kt_assert_eq!(
        run(s.pas_auth_and_reset(6, &d)).unwrap(),
        Err(ScmError::WaitQueue)
    );
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_scm_retry_and_errors);

// ── MDT ────────────────────────────────────────────────────────────

fn segs(reloc: bool) -> [Seg; 4] {
    let rf = if reloc { QCOM_MDT_RELOCATABLE } else { 0 };
    [
        Seg {
            p_type: 0,
            flags: 0x0700_0000,
            paddr: 0,
            filesz: 0,
            memsz: 0,
            fill: 0,
        },
        Seg {
            p_type: 0,
            flags: QCOM_MDT_TYPE_HASH,
            paddr: 0x4ab0_0000,
            filesz: 0x40,
            memsz: 0x1000,
            fill: 0xaa,
        },
        Seg {
            p_type: PT_LOAD,
            flags: rf,
            paddr: 0x4ab0_0000,
            filesz: 0x100,
            memsz: 0x200,
            fill: 0x11,
        },
        Seg {
            p_type: PT_LOAD,
            flags: rf,
            paddr: 0x4ab0_2000,
            filesz: 0x80,
            memsz: 0x80,
            fill: 0x22,
        },
    ]
}

fn smoke_qcom_mdt_inline_and_split_load() -> TestResult {
    let (img, files) = build_mdt(0x4ab0_0000, &segs(false), true);
    let m = Mdt::parse(&img).unwrap();
    kt_assert_eq!(m.entry(), 0x4ab0_0000);
    kt_assert_eq!(
        m.size().unwrap(),
        0x3000,
        "min 0x4ab00000 .. ALIGN(0x4ab02080, 4K)"
    );
    kt_assert!(!m.is_split());
    let store = FwStore::default();
    let mut meta = Vec::new();
    m.read_metadata("q6_fw.mdt", &store, &mut meta).unwrap();
    let hdr = 52 + 4 * 32;
    kt_assert_eq!(meta.len(), hdr + 0x40);
    kt_assert!(meta[hdr..].iter().all(|&b| b == 0xaa));
    let mut mem = vec![0xffu8; 0x3000];
    let reloc = m.load("q6_fw.mdt", &store, &mut mem, 0x4ab0_0000).unwrap();
    kt_assert_eq!(reloc, 0x4ab0_0000);
    kt_assert!(mem[..0x100].iter().all(|&b| b == 0x11));
    kt_assert!(
        mem[0x100..0x200].iter().all(|&b| b == 0),
        "memsz tail zeroed"
    );
    kt_assert!(mem[0x2000..0x2080].iter().all(|&b| b == 0x22));
    kt_assert_eq!(mem[0x1000], 0xff, "hash segment not loaded");

    // Split: header-only .mdt (hash packed after the header), .b02/.b03.
    let (mut hdr_only, _) = build_mdt(0x4ab0_0000, &segs(true), false);
    hdr_only.extend_from_slice(&files[1]);
    let m = Mdt::parse(&hdr_only).unwrap();
    kt_assert!(m.is_split());
    let mut store = FwStore::default();
    store.insert("q6_fw.b02", files[2].clone());
    store.insert("q6_fw.b03", files[3].clone());
    let mut meta = Vec::new();
    m.read_metadata("q6_fw.mdt", &store, &mut meta).unwrap();
    kt_assert!(meta[hdr..].iter().all(|&b| b == 0xaa));
    let mut mem = vec![0u8; 0x3000];
    let reloc = m.load("q6_fw.mdt", &store, &mut mem, 0x5000_0000).unwrap();
    kt_assert_eq!(reloc, 0x4ab0_0000, "relocatable: base = lowest segment");
    kt_assert!(mem[0x2000..0x2080].iter().all(|&b| b == 0x22));
    kt_assert_eq!(mdt::segment_name("wpss.mdt", 12).unwrap(), "wpss.b12");
    // Missing split segment, out-of-range carve-out, filesz > memsz.
    store.0.remove("q6_fw.b03");
    kt_assert_eq!(
        m.load("q6_fw.mdt", &store, &mut mem, 0x5000_0000),
        Err(MdtError::SplitSegment(3))
    );
    let mut small = vec![0u8; 0x1000];
    kt_assert_eq!(
        Mdt::parse(&img)
            .unwrap()
            .load("q6_fw.mdt", &store, &mut small, 0x4ab0_0000),
        Err(MdtError::SegmentOutOfRange(3))
    );
    let mut bad = segs(false);
    bad[3].filesz = 0x100;
    let (bimg, _) = build_mdt(0, &bad, true);
    kt_assert_eq!(
        Mdt::parse(&bimg)
            .unwrap()
            .load("x.mdt", &store, &mut mem, 0x4ab0_0000),
        Err(MdtError::FileszExceedsMemsz(3))
    );
    kt_assert_eq!(Mdt::parse(b"\x7fELF\x02").err(), Some(MdtError::BadHeader));
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_mdt_inline_and_split_load);

fn smoke_qcom_mdt_pas_init() -> TestResult {
    let d = FakeDelay::new();
    for reloc in [false, true] {
        let (img, _) = build_mdt(0x9ae0_0000, &segs(reloc), true);
        let m = Mdt::parse(&img).unwrap();
        let smc = FakeSmc::ok();
        let mut s = Scm::new(&smc);
        let mut a = FakeAlloc::default();
        let buf = run(m.pas_init(
            "wpss.mdt",
            &FwStore::default(),
            &mut s,
            &mut a,
            6,
            0x9ae0_0000,
            &d,
        ))
        .unwrap()
        .unwrap();
        kt_assert_eq!(a.sizes, vec![52 + 4 * 32 + 0x40]);
        kt_assert!(buf.data[..4] == *b"\x7fELF");
        let f = smc.fnids();
        if reloc {
            kt_assert_eq!(&f[1..], &[(2, 1), (2, 2)]);
            kt_assert_eq!(smc.calls()[2][4], 0x3000, "mem_setup size = max - min");
        } else {
            kt_assert_eq!(&f[1..], &[(2, 1)]);
        }
    }
    // Allocation failure and a TZ rejection.
    let (img, _) = build_mdt(0, &segs(true), true);
    let m = Mdt::parse(&img).unwrap();
    let smc = FakeSmc::ok();
    let mut s = Scm::new(&smc);
    let mut a = FakeAlloc {
        fail: true,
        ..Default::default()
    };
    kt_assert_eq!(
        run(m.pas_init("w.mdt", &FwStore::default(), &mut s, &mut a, 6, 1, &d))
            .unwrap()
            .err(),
        Some(MdtError::Scm(ScmError::Alloc))
    );
    let rej = FakeSmc::new(|r, _| {
        let mut o = [0u64; 8];
        if r[0] as u32 & 0xffff == 0x0601 {
            o[1] = 1;
        } else {
            o[0] = (-2i64) as u64;
        }
        o
    });
    let mut s = Scm::new(&rej);
    let mut a = FakeAlloc::default();
    kt_assert_eq!(
        run(m.pas_init("w.mdt", &FwStore::default(), &mut s, &mut a, 6, 1, &d))
            .unwrap()
            .err(),
        Some(MdtError::Scm(ScmError::Invalid))
    );
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_mdt_pas_init);

// ── SMEM / hwlock ──────────────────────────────────────────────────

const SMEM_SIZE: u32 = 0x10000;

fn smoke_qcom_smem_v12_partitions() -> TestResult {
    let regs = FakeRegs::quiet();
    let (glob, priv_base) = build_smem_v12(&regs, SMEM_SIZE, 1, 512);
    let lock_regs = FakeRegs::new();
    let d = FakeDelay::new();
    let lock = TcsrMutex::new(&lock_regs, &d, 3).unwrap();
    let smem = Smem::probe(&regs, SMEM_SIZE).unwrap();
    kt_assert_eq!(smem.version(), 12);
    kt_assert_eq!(smem.item_count(), 512);
    kt_assert_eq!(smem.get(1, 435), Err(SmemError::NotFound));
    run(smem.alloc(&lock, 1, 435, 340)).unwrap().unwrap();
    let it = smem.get(1, 435).unwrap();
    kt_assert_eq!(
        it,
        crate::smem::SmemItem {
            offset: priv_base + 32 + 16,
            len: 340
        }
    );
    kt_assert_eq!(
        regs.get(priv_base + 12),
        32 + 16 + 344,
        "free_uncached advanced by hdr + ALIGN(340, 8)"
    );
    kt_assert_eq!(regs.get(priv_base + 32), 0xa5a5 | (435 << 16));
    kt_assert_eq!(
        run(smem.alloc(&lock, 1, 435, 8)).unwrap(),
        Err(SmemError::Exists)
    );
    // Lock 3 at offset 3 * 0x1000: written 1 (taken) then 0 (released).
    kt_assert_eq!(
        lock_regs.writes_to(0x3000),
        vec![1, 0, 1, 0],
        "taken and released per alloc"
    );
    // A host without a private partition falls back to the global one.
    run(smem.alloc(&lock, 5, 100, 4)).unwrap().unwrap();
    kt_assert_eq!(smem.get(5, 100).unwrap().offset, glob + 32 + 16);
    kt_assert_eq!(smem.get(5, 100).unwrap().len, 4);
    kt_assert_eq!(
        run(smem.alloc(&lock, 1, 3, 8)).unwrap(),
        Err(SmemError::BadItem),
        "fixed item"
    );
    kt_assert_eq!(smem.get(1, 600), Err(SmemError::BadItem));
    // Cached-list item written by the remote, found from the top.
    let top = priv_base + 0x4000;
    let e = top - 64; // ALIGN(16, cacheline 64)
    regs.set(e, 0xa5a5 | (500 << 16));
    regs.set(e + 4, 0x20);
    regs.set(priv_base + 16, 0x4000 - 64 - 0x20);
    let smem2 = Smem::probe(&regs, SMEM_SIZE).unwrap();
    kt_assert_eq!(
        smem2.get(1, 500),
        Ok(crate::smem::SmemItem {
            offset: e - 0x20,
            len: 0x20
        })
    );
    // Corrupt canary.
    regs.set(priv_base + 32, 0x1234 | (435 << 16));
    kt_assert_eq!(smem.get(1, 435), Err(SmemError::BadCanary));
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_smem_v12_partitions);

fn smoke_qcom_smem_v11_heap_and_lock_timeout() -> TestResult {
    let regs = FakeRegs::quiet();
    regs.set(crate::smem::HDR_VERSION + 7 * 4, 11 << 16);
    regs.set(crate::smem::HDR_FREE_OFFSET, 0x2000);
    regs.set(crate::smem::HDR_AVAILABLE, 0x100);
    let lock_regs = FakeRegs::quiet();
    let d = FakeDelay::new();
    let lock = TcsrMutex::new(&lock_regs, &d, 3).unwrap();
    let smem = Smem::probe(&regs, SMEM_SIZE).unwrap();
    run(smem.alloc(&lock, crate::smem::SMEM_HOST_ANY, 421, 13))
        .unwrap()
        .unwrap();
    kt_assert_eq!(
        smem.get(0xffff, 421).unwrap(),
        crate::smem::SmemItem {
            offset: 0x2000,
            len: 16
        }
    );
    kt_assert_eq!(regs.get(crate::smem::HDR_AVAILABLE), 0xf0);
    kt_assert_eq!(
        run(smem.alloc(&lock, 0xffff, 422, 0x200)).unwrap(),
        Err(SmemError::NoSpace)
    );
    // Remote holds the mutex: read-back is its id, never ours.
    lock_regs.force(0x3000, 2);
    kt_assert_eq!(
        run(smem.alloc(&lock, 0xffff, 423, 8)).unwrap(),
        Err(SmemError::Lock(HwLockError::Timeout))
    );
    kt_assert!(
        d.now_us() >= 1_000_000,
        "slept the full 1 s HWSPINLOCK_TIMEOUT"
    );
    kt_assert_eq!(lock.unlock(), Err(HwLockError::NotOwner(2)));
    regs.set(crate::smem::HDR_VERSION + 7 * 4, 13 << 16);
    kt_assert_eq!(
        Smem::probe(&regs, SMEM_SIZE).err(),
        Some(SmemError::UnsupportedVersion(13))
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/soc/qcom",
    smoke_qcom_smem_v11_heap_and_lock_timeout
);

// ── SMP2P ──────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct CountKick(AtomicUsize);
impl Kick for &CountKick {
    fn kick(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

/// Play the remote: allocate and fill its outbound (our inbound) item.
fn remote_item(
    smem: &Smem<&FakeRegs>,
    lock: &impl HwSpinlock,
    cfg: Smp2pConfig,
    entries: &[(&str, u32)],
    ssr: bool,
) -> u32 {
    run(smem.alloc(lock, cfg.remote_pid, cfg.smem_in, ITEM_SIZE))
        .unwrap()
        .unwrap();
    let it = smem.get(cfg.remote_pid, cfg.smem_in).unwrap();
    let m = smem.mem();
    m.write32(it.offset, SMP2P_MAGIC);
    m.write32(it.offset + 4, 1 | (1 << 8));
    m.write32(
        it.offset + 8,
        cfg.remote_pid as u32 | ((cfg.local_pid as u32) << 16),
    );
    m.write32(it.offset + 12, 16 | ((entries.len() as u32) << 16));
    m.write32(it.offset + 16, ssr as u32);
    for (i, (name, v)) in entries.iter().enumerate() {
        let e = it.offset + 20 + i as u32 * 20;
        let mut raw = [0u8; 16];
        raw[..name.len()].copy_from_slice(name.as_bytes());
        for w in 0..4 {
            m.write32(
                e + w * 4,
                u32::from_le_bytes([
                    raw[w as usize * 4],
                    raw[w as usize * 4 + 1],
                    raw[w as usize * 4 + 2],
                    raw[w as usize * 4 + 3],
                ]),
            );
        }
        m.write32(e + 16, *v);
    }
    it.offset
}

fn smoke_qcom_smp2p_edge() -> TestResult {
    let regs = FakeRegs::quiet();
    build_smem_v12(&regs, SMEM_SIZE, 1, 512);
    let lr = FakeRegs::new();
    let d = FakeDelay::new();
    let lock = TcsrMutex::new(&lr, &d, 3).unwrap();
    let smem = Smem::probe(&regs, SMEM_SIZE).unwrap();
    let cfg = Smp2pConfig {
        smem_in: 435,
        smem_out: 428,
        local_pid: 0,
        remote_pid: 1,
    };
    let k = CountKick::default();
    let mut e = run(Smp2p::new(&smem, &lock, cfg, &k)).unwrap().unwrap();
    let out = e.outbound_item();
    kt_assert_eq!(regs.get(out.offset), SMP2P_MAGIC);
    kt_assert_eq!(
        regs.get(out.offset + 4),
        1 | (1 << 8),
        "version 1, SSR_ACK feature"
    );
    kt_assert_eq!(regs.get(out.offset + 8), 1 << 16, "local 0, remote 1");
    kt_assert_eq!(k.0.load(Ordering::Relaxed), 1);
    let h = e.add_outbound(&smem, "master-kernel").unwrap();
    kt_assert_eq!(regs.get(out.offset + 12), 16 | (1 << 16));
    kt_assert_eq!(regs.get(out.offset + 20), u32::from_le_bytes(*b"mast"));
    e.update_bits(&smem, h, 1, 1).unwrap();
    e.update_bits(&smem, h, 1, 1).unwrap();
    kt_assert_eq!(k.0.load(Ordering::Relaxed), 2, "no kick when unchanged");
    kt_assert_eq!(e.outbound_value(&smem, h), Some(1));
    kt_assert_eq!(
        e.add_outbound(&smem, "a-name-too-long!"),
        Err(crate::smp2p::Smp2pError::BadName)
    );
    // Inbound: nothing until the remote publishes.
    let slave = e.add_inbound("slave-kernel").unwrap();
    for b in 0..4 {
        e.enable_irq(slave, b, true, false).unwrap();
    }
    kt_assert!(e.handle_interrupt(&smem).is_empty());
    let ri = remote_item(&smem, &lock, cfg, &[("slave-kernel", 0)], false);
    kt_assert!(
        e.handle_interrupt(&smem).is_empty(),
        "entry matched at value 0"
    );
    kt_assert!(e.negotiated() && e.ssr_ack_enabled());
    regs.set(ri + 36, 1 << 1); // ready
    let f = e.handle_interrupt(&smem);
    kt_assert_eq!(f.len(), 1);
    kt_assert_eq!((f[0].bit, f[0].high), (1, true));
    regs.set(ri + 36, 0); // falling edge: not enabled for falling
    kt_assert!(e.handle_interrupt(&smem).is_empty());
    regs.set(ri + 36, (1 << 1) | (1 << 3) | (1 << 9));
    let bits: Vec<u32> = e.handle_interrupt(&smem).iter().map(|i| i.bit).collect();
    kt_assert_eq!(bits, vec![1, 3], "bit 9 masked");
    // SSR: remote sets RESTART_DONE → we toggle RESTART_ACK and kick.
    let before = k.0.load(Ordering::Relaxed);
    regs.set(ri + 16, 1);
    e.handle_interrupt(&smem);
    kt_assert_eq!(regs.get(out.offset + 16) & 2, 2);
    kt_assert_eq!(k.0.load(Ordering::Relaxed), before + 1);
    // Kick encodings.
    let ap = FakeRegs::new();
    ApcsIpc::new(&ap, 8, 9).kick();
    kt_assert_eq!(ap.writes(), vec![(8, 1 << 9)]);
    let ip = FakeRegs::new();
    Ipcc::new(&ip, 24, 2).kick();
    kt_assert_eq!(ip.writes(), vec![(0x0c, (24 << 16) | 2)]);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_smp2p_edge);

// ── GCC ────────────────────────────────────────────────────────────

fn smoke_qcom_gcc_resets_and_branch() -> TestResult {
    let r = FakeRegs::new();
    let g = Gcc::new(&r, &gcc::IPQ6018);
    g.set_reset(127, true).unwrap();
    kt_assert_eq!(r.get(0x59010), 1);
    g.set_reset(127, false).unwrap();
    kt_assert_eq!(r.get(0x59010), 0);
    g.reset_line(23).unwrap().assert();
    kt_assert_eq!(r.get(0x18100), 1);
    kt_assert_eq!(g.set_reset(99, true), Err(GccError::UnknownIndex(99)));
    kt_assert!(
        Gcc::new(&r, &gcc::IPQ8074).reset_line(127).is_err(),
        "no AON reset on IPQ8074"
    );
    kt_assert_eq!(gcc::IPQ5018.resets[1].reg, 0x18004);
    let d = FakeDelay::new();
    run(g.enable_branch(136, &d)).unwrap().unwrap();
    kt_assert_eq!(r.get(0x0b004), 1 << 8);
    run(g.disable_branch(136, &d)).unwrap().unwrap();
    kt_assert_eq!(r.get(0x0b004), 0);
    r.force(0x13004, 1 << 31);
    kt_assert_eq!(
        run(g.enable_branch(136, &d)).unwrap(),
        Err(GccError::BranchStuckOff {
            halt_reg: 0x13004,
            value: 1 << 31
        })
    );
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_gcc_resets_and_branch);

// ── WCSS ───────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct RecReset {
    asserted: AtomicU32,
    deasserted: AtomicU32,
    level: AtomicU32,
}
impl ResetLine for RecReset {
    fn assert(&self) {
        self.asserted.fetch_add(1, Ordering::Relaxed);
        self.level.store(1, Ordering::Relaxed);
    }
    fn deassert(&self) {
        self.deasserted.fetch_add(1, Ordering::Relaxed);
        self.level.store(0, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct RecStop(IrqLog);
impl Default for RecStop {
    fn default() -> Self {
        Self(IrqLog::new(Vec::new()))
    }
}
type IrqLog = narf_lib::sync::IrqSafeSpinLock<Vec<bool>>;
impl StopState for RecStop {
    fn set_stop(&self, on: bool) {
        self.0.lock().push(on);
    }
}

fn wcss_fixture<'a>(q: &'a FakeRegs, rmb: &'a FakeRegs, t: &'a FakeRegs) -> Q6Wcss<&'a FakeRegs> {
    rmb.set(wcss::SSCAON_STATUS, 0x400);
    t.set(0x1b000 + wcss::AXI_HALTACK_REG, 1);
    t.set(0x1b000 + wcss::AXI_IDLE_REG, 0);
    t.set(0x18000 + wcss::AXI_IDLE_REG, 1);
    Q6Wcss::new(WcssRegs {
        qdsp6: q,
        rmb,
        tcsr: t,
        halt_q6: 0x18000,
        halt_wcss: 0x1b000,
        halt_nc: 0xe000,
    })
}

fn smoke_qcom_wcss_start_stop_sequence() -> TestResult {
    let (q, rmb, t) = (FakeRegs::new(), FakeRegs::new(), FakeRegs::new());
    let mut w = wcss_fixture(&q, &rmb, &t);
    let (aon, wr, q6r) = (
        RecReset::default(),
        RecReset::default(),
        RecReset::default(),
    );
    let resets = WcssResets {
        aon: &aon,
        wcss: &wr,
        q6: &q6r,
    };
    let d = FakeDelay::new();
    // start before load is refused.
    kt_assert_eq!(
        run(w.start(resets, &d, &mut |_| {})).unwrap(),
        Err(RprocError::BadState(RprocState::Offline))
    );
    let (img, _) = build_mdt(0x4ab0_1230, &segs(false), true);
    let mut mem = vec![0u8; 0x3000];
    let mut co = Carveout {
        phys: 0x4ab0_0000,
        mem: &mut mem,
    };
    w.load("IPQ8074/q6_fw.mdt", &img, &FwStore::default(), &mut co)
        .unwrap();
    kt_assert_eq!(w.boot_addr(), Some(0x4ab0_1230));
    t.set(0xe000, 0xffff_ffe0 | 0x3);
    t.set(0xe004, 0x3);
    let polls = AtomicU32::new(0);
    run(w.start(resets, &d, &mut |q6: &Q6v5| {
        if polls.fetch_add(1, Ordering::Relaxed) == 2 {
            q6.signal(Q6Event::Ready);
        }
    }))
    .unwrap()
    .unwrap();
    kt_assert_eq!(w.state(), RprocState::Running);
    kt_assert_eq!(
        (
            wr.deasserted.load(Ordering::Relaxed),
            q6r.deasserted.load(Ordering::Relaxed)
        ),
        (1, 1)
    );
    kt_assert_eq!(
        t.get(0xe000),
        0xffff_ffe0 | 0x14,
        "TCSR_GLOBAL_CFG0 clk mask/enable"
    );
    kt_assert_eq!(t.get(0xe004), 0x2, "TCSR_GLOBAL_CFG1 bit0 cleared");
    kt_assert_eq!(q.writes_to(wcss::Q6SS_RST_EVB), vec![0x4ab0_1230 >> 4]);
    // Q6SS_RESET: assert all, then clear CORE_ARES, then clear STOP_CORE.
    kt_assert_eq!(q.writes_to(wcss::Q6SS_RESET_REG), vec![0x7, 0x5, 0x4]);
    kt_assert_eq!(q.writes_to(wcss::Q6SS_XO_CBCR), vec![1]);
    let pwr = q.writes_to(wcss::Q6SS_PWR_CTL_REG);
    let bhs = 1 << 24;
    let ldo = 1 << 25;
    let stby = (1 << 18) | (1 << 19);
    kt_assert_eq!(
        pwr,
        vec![
            bhs,
            bhs | ldo,
            bhs | ldo,
            bhs | ldo | stby,
            bhs | ldo | stby,
            bhs | ldo | stby
        ]
    );
    let mem_w = q.writes_to(wcss::Q6SS_MEM_PWR_CTL);
    kt_assert_eq!(mem_w.len(), 20, "banks 19..=0 one at a time");
    kt_assert_eq!(mem_w[0], 1 << 19);
    kt_assert_eq!(*mem_w.last().unwrap(), 0xf_ffff);
    kt_assert_eq!(q.writes_to(wcss::Q6SS_GFMUX_CTL_REG), vec![1 << 1]);
    // Stop: stop bit set then cleared around the stop-ack wait.
    let stop = RecStop::default();
    q.clear_log();
    run(w.stop(resets, &stop, &d, &mut |q6: &Q6v5| {
        q6.signal(Q6Event::StopAck)
    }))
    .unwrap()
    .unwrap();
    kt_assert_eq!(*stop.0.lock(), vec![true, false]);
    kt_assert_eq!(w.state(), RprocState::Offline);
    kt_assert_eq!(aon.level.load(Ordering::Relaxed), 1);
    kt_assert_eq!(
        (
            wr.level.load(Ordering::Relaxed),
            q6r.level.load(Ordering::Relaxed)
        ),
        (1, 1)
    );
    // WCSS port was busy → HALTREQ 1 then 0; Q6 port already idle → untouched.
    kt_assert_eq!(t.writes_to(0x1b000), vec![1, 0]);
    kt_assert!(t.writes_to(0x18000).is_empty());
    let sscaon = rmb.writes_to(wcss::SSCAON_CONFIG);
    kt_assert_eq!(
        sscaon,
        vec![
            1 << 13,
            (1 << 13) | (1 << 15),
            (1 << 13) | (1 << 15) | 2,
            (1 << 15) | 2
        ]
    );
    kt_assert_eq!(q.writes_to(wcss::Q6SS_MEM_PWR_CTL).len(), 20);
    kt_assert_eq!(q.get(wcss::Q6SS_MEM_PWR_CTL), 0);
    kt_assert_eq!(
        run(w.stop(resets, &stop, &d, &mut |_| {})).unwrap(),
        Err(RprocError::BadState(RprocState::Offline))
    );
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_wcss_start_stop_sequence);

fn smoke_qcom_wcss_failures() -> TestResult {
    let (q, rmb, t) = (FakeRegs::new(), FakeRegs::new(), FakeRegs::new());
    let mut w = wcss_fixture(&q, &rmb, &t);
    let (aon, wr, q6r) = (
        RecReset::default(),
        RecReset::default(),
        RecReset::default(),
    );
    let resets = WcssResets {
        aon: &aon,
        wcss: &wr,
        q6: &q6r,
    };
    let d = FakeDelay::new();
    let (img, _) = build_mdt(0x4ab0_0000, &segs(false), true);
    let mut mem = vec![0u8; 0x3000];
    let mut co = Carveout {
        phys: 0x4ab0_0000,
        mem: &mut mem,
    };
    w.load("q6.mdt", &img, &FwStore::default(), &mut co)
        .unwrap();
    // XO CBCR never clears CLKOFF.
    q.force(wcss::Q6SS_XO_CBCR, 1 << 31);
    kt_assert_eq!(
        run(w.start(resets, &d, &mut |_| {})).unwrap(),
        Err(RprocError::XoClockTimeout)
    );
    kt_assert_eq!(
        (
            wr.level.load(Ordering::Relaxed),
            q6r.level.load(Ordering::Relaxed)
        ),
        (1, 1),
        "resets re-asserted"
    );
    q.unforce(wcss::Q6SS_XO_CBCR);
    q.set(wcss::Q6SS_XO_CBCR, 0); // the RMW latched CLKOFF from the forced read
                                  // Ready never arrives: 5 s timeout.
    let t0 = d.now_us();
    kt_assert_eq!(
        run(w.start(resets, &d, &mut |_| {})).unwrap(),
        Err(RprocError::Handshake(Q6Error::Timeout))
    );
    kt_assert!(d.now_us() - t0 >= 5_000_000);
    kt_assert_eq!(w.state(), RprocState::Offline);
    // Fatal during start.
    kt_assert_eq!(
        run(w.start(resets, &d, &mut |q6: &Q6v5| q6.signal(Q6Event::Fatal))).unwrap(),
        Err(RprocError::Handshake(Q6Error::Crashed(
            crate::q6v5::Crash::Fatal
        )))
    );
    // Running, then a watchdog bite marks it crashed.
    run(w.start(resets, &d, &mut |q6: &Q6v5| q6.signal(Q6Event::Ready)))
        .unwrap()
        .unwrap();
    w.q6.signal(Q6Event::Wdog);
    w.note_crash();
    kt_assert_eq!(w.state(), RprocState::Crashed);
    // Stop from Crashed skips the SMP2P dance; SSCAON stuck fails.
    let stop = RecStop::default();
    rmb.force(wcss::SSCAON_STATUS, 0x401);
    kt_assert_eq!(
        run(w.stop(resets, &stop, &d, &mut |_| {})).unwrap(),
        Err(RprocError::SscaonTimeout(0x401))
    );
    kt_assert!(stop.0.lock().is_empty());
    rmb.unforce(wcss::SSCAON_STATUS);
    q.force(wcss::Q6SS_BHS_STATUS, 1);
    kt_assert_eq!(
        run(w.stop(resets, &stop, &d, &mut |_| {})).unwrap(),
        Err(RprocError::BhsTimeout(1))
    );
    q.unforce(wcss::Q6SS_BHS_STATUS);
    run(w.stop(resets, &stop, &d, &mut |_| {}))
        .unwrap()
        .unwrap();
    // Stop-ack timeout from Running is an error.
    run(w.start(resets, &d, &mut |q6: &Q6v5| q6.signal(Q6Event::Ready)))
        .unwrap()
        .unwrap();
    kt_assert_eq!(
        run(w.stop(resets, &stop, &d, &mut |_| {})).unwrap(),
        Err(RprocError::Handshake(Q6Error::Timeout))
    );
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_wcss_failures);

// ── PAS ────────────────────────────────────────────────────────────

fn smoke_qcom_pas_wpss_start_stop() -> TestResult {
    let d = FakeDelay::new();
    let (img, _) = build_mdt(0x9ae0_0000, &segs(true), true);
    let smc = FakeSmc::ok();
    let mut s = Scm::new(&smc);
    let mut a = FakeAlloc::default();
    let mut mem = vec![0u8; 0x3000];
    let mut co = Carveout {
        phys: 0x9ae0_0000,
        mem: &mut mem,
    };
    let mut p = PasRproc::new(crate::pas::WPSS_PAS_ID);
    run(p.start(
        &mut s,
        &mut a,
        "wpss.mdt",
        &img,
        &FwStore::default(),
        &mut co,
        &d,
        &mut |q6: &Q6v5| q6.signal(Q6Event::Ready),
    ))
    .unwrap()
    .unwrap();
    kt_assert_eq!(p.state(), RprocState::Running);
    kt_assert_eq!(
        p.mem_reloc(),
        0x4ab0_0000,
        "relocatable image keeps its own base"
    );
    kt_assert_eq!(
        &smc.fnids()[1..],
        &[(2, 1), (2, 2), (2, 5)],
        "init, mem_setup, auth_and_reset"
    );
    kt_assert!(smc.calls()[1..].iter().all(|r| r[2] == 6), "pas_id 6");
    let stop = RecStop::default();
    run(p.stop(&mut s, &stop, &d, &mut |q6: &Q6v5| {
        q6.signal(Q6Event::ShutdownAck)
    }))
    .unwrap()
    .unwrap();
    kt_assert_eq!(*stop.0.lock(), vec![true, false]);
    kt_assert_eq!(*smc.fnids().last().unwrap(), (2, 6));
    kt_assert_eq!(p.state(), RprocState::Offline);
    // Ready timeout → PAS_SHUTDOWN, Offline.
    let smc = FakeSmc::ok();
    let mut s = Scm::new(&smc);
    let mut co = Carveout {
        phys: 0x9ae0_0000,
        mem: &mut mem,
    };
    kt_assert_eq!(
        run(p.start(
            &mut s,
            &mut a,
            "wpss.mdt",
            &img,
            &FwStore::default(),
            &mut co,
            &d,
            &mut |_| {}
        ))
        .unwrap(),
        Err(RprocError::Handshake(Q6Error::Timeout))
    );
    kt_assert_eq!(*smc.fnids().last().unwrap(), (2, 6));
    kt_assert_eq!(p.state(), RprocState::Offline);
    // TZ refuses authentication.
    let rej = FakeSmc::new(|r, _| {
        let mut o = [0u64; 8];
        match r[0] as u32 & 0xffff {
            0x0601 => o[1] = 1,
            0x0205 => o[0] = (-1i64) as u64,
            _ => {}
        }
        o
    });
    let mut s = Scm::new(&rej);
    let mut co = Carveout {
        phys: 0x9ae0_0000,
        mem: &mut mem,
    };
    kt_assert_eq!(
        run(p.start(
            &mut s,
            &mut a,
            "wpss.mdt",
            &img,
            &FwStore::default(),
            &mut co,
            &d,
            &mut |_| {}
        ))
        .unwrap(),
        Err(RprocError::Scm(ScmError::Io))
    );
    kt_assert!(!p.q6.running() || p.state() == RprocState::Offline);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_pas_wpss_start_stop);

// ── devicetree ─────────────────────────────────────────────────────

fn smoke_qcom_platform_ipq6018_dt() -> TestResult {
    let blob = ipq6018_wifi_dt("qcom,ipq6018-wifi", &[320, 319]);
    let p = platform::q6_platform(&blob, ph::RPROC).unwrap();
    kt_assert_eq!(p.kind, RprocKind::Wcss);
    kt_assert_eq!(p.firmware, "IPQ8074/q6_fw.mdt");
    kt_assert_eq!(p.crash_reason_item, 421);
    kt_assert_eq!(p.carveout, (0x4ab0_0000, 0x550_0000));
    kt_assert_eq!(p.qdsp6, (0x0cd0_0000, 0x4040));
    kt_assert_eq!(p.rmb, Some((0x004a_b000, 0x20)));
    let h = p.halt.clone().unwrap();
    kt_assert_eq!(
        (h.tcsr, h.q6, h.wcss, h.nc),
        ((0x0193_7000, 0x2_1000), 0x18000, 0x1b000, 0xe000)
    );
    let aon = p.reset("wcss_aon_reset").unwrap();
    kt_assert_eq!(
        (aon.index, aon.gcc_base.0, aon.gcc.compatible),
        (127, 0x0180_0000, "qcom,gcc-ipq6018")
    );
    kt_assert_eq!(p.reset("wcss_q6_reset").unwrap().index, 23);
    kt_assert_eq!(p.irq(Q6Event::Wdog), Some(&IrqSource::Gic(325 + 32)));
    let want = |bit| IrqSource::Smp2p {
        edge: "/wcss-smp2p".into(),
        entry: "slave-kernel".into(),
        bit,
    };
    kt_assert_eq!(p.irq(Q6Event::Fatal), Some(&want(0)));
    kt_assert_eq!(p.irq(Q6Event::StopAck), Some(&want(3)));
    kt_assert_eq!(
        p.stop,
        Some(("/wcss-smp2p".into(), "master-kernel".into(), 1)),
        "stop = 2nd smem-state"
    );
    kt_assert_eq!(p.edges.len(), 1);
    let e = &p.edges[0];
    kt_assert_eq!(
        e.cfg,
        Smp2pConfig {
            smem_in: 435,
            smem_out: 428,
            local_pid: 0,
            remote_pid: 1
        }
    );
    kt_assert_eq!(
        e.kick,
        KickDt::Apcs {
            base: (0x0b11_1000, 0x1000),
            offset: 8,
            channel: 9
        }
    );
    kt_assert_eq!(e.irq.gic_hwirq(), Some(322 + 32));
    let sm = p.smem.clone().unwrap();
    kt_assert_eq!(
        (sm.region, sm.hwlock_base.0, sm.hwlock_id),
        ((0x4aa0_0000, 0x10_0000), 0x0190_5000, 3)
    );
    let wifi = crate::dt::find_compatible(&blob, "qcom,ipq6018-wifi");
    kt_assert_eq!(wifi.len(), 1);
    kt_assert_eq!(wifi[0].reg(0).unwrap(), (0x0c00_0000, 0x200_0000));
    kt_assert_eq!(
        wifi[0].irq_by_name("misc-latch").unwrap().gic_hwirq(),
        Some(319 + 32)
    );
    kt_assert!(platform::q6_platform(&blob, 0x999).is_err());
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_platform_ipq6018_dt);

fn smoke_qcom_platform_sc7280_dt() -> TestResult {
    let blob = sc7280_wifi_dt();
    let p = platform::q6_platform(&blob, ph::RPROC).unwrap();
    kt_assert_eq!(p.kind, RprocKind::Pas { pas_id: 6 });
    kt_assert_eq!(p.firmware, "wpss.mdt");
    kt_assert_eq!(p.carveout, (0x9ae0_0000, 0x190_0000));
    kt_assert_eq!(p.qdsp6, (0x08a0_0000, 0x1_0000));
    kt_assert!(p.rmb.is_none() && p.halt.is_none() && p.resets.is_empty());
    kt_assert_eq!(
        p.irq(Q6Event::ShutdownAck),
        Some(&IrqSource::Smp2p {
            edge: "/smp2p-wpss".into(),
            entry: "slave-kernel".into(),
            bit: 7
        })
    );
    let e = &p.edges[0];
    kt_assert_eq!(
        e.cfg,
        Smp2pConfig {
            smem_in: 617,
            smem_out: 616,
            local_pid: 0,
            remote_pid: 13
        }
    );
    kt_assert_eq!(
        e.kick,
        KickDt::Ipcc {
            base: (0x0040_8000, 0x1000),
            client: 24,
            signal: 2
        }
    );
    kt_assert_eq!(
        p.stop,
        Some(("/smp2p-wpss".into(), "master-kernel".into(), 0))
    );
    // The wlan entries resolve on the same edge.
    kt_assert_eq!(
        platform::smp2p_entry(&blob, ph::WLAN_OUT),
        Some(("/smp2p-wpss".into(), "wlan".into()))
    );
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_platform_sc7280_dt);

// ── composed: DT → SMEM/SMP2P/GCC → WCSS boot and stop ────────────

struct Smp2pStop<'a> {
    edge: &'a Smp2p<&'a CountKick>,
    smem: &'a Smem<&'a FakeRegs>,
    h: crate::smp2p::OutHandle,
    bit: u32,
}
impl StopState for Smp2pStop<'_> {
    fn set_stop(&self, on: bool) {
        let b = 1 << self.bit;
        let _ = self
            .edge
            .update_bits(self.smem, self.h, b, if on { b } else { 0 });
    }
}

fn smoke_qcom_composed_ipq6018_wcss_boot() -> TestResult {
    let blob = ipq6018_wifi_dt("qcom,ipq6018-wifi", &[]);
    let p = platform::q6_platform(&blob, ph::RPROC).unwrap();
    let d = FakeDelay::new();
    // SMEM + hwlock from the DT description.
    let smem_regs = FakeRegs::quiet();
    let edge_dt = &p.edges[0];
    build_smem_v12(&smem_regs, SMEM_SIZE, edge_dt.cfg.remote_pid, 512);
    let lock_regs = FakeRegs::new();
    let lock = TcsrMutex::new(&lock_regs, &d, p.smem.as_ref().unwrap().hwlock_id).unwrap();
    let smem = Smem::probe(&smem_regs, SMEM_SIZE).unwrap();
    let k = CountKick::default();
    let mut edge = run(Smp2p::new(&smem, &lock, edge_dt.cfg, &k))
        .unwrap()
        .unwrap();
    let (stop_edge, stop_entry, stop_bit) = p.stop.clone().unwrap();
    kt_assert_eq!(stop_edge.as_str(), edge_dt.path.as_str());
    let out_h = edge.add_outbound(&smem, &stop_entry).unwrap();
    let in_h = edge.add_inbound("slave-kernel").unwrap();
    let mut ev_bits = Vec::new();
    for (ev, src) in &p.irqs {
        if let IrqSource::Smp2p { bit, .. } = src {
            edge.enable_irq(in_h, *bit, true, false).unwrap();
            ev_bits.push((*bit, *ev));
        }
    }
    // Remote side publishes its item.
    let ri = remote_item(&smem, &lock, edge_dt.cfg, &[("slave-kernel", 0)], false);
    // GCC resets from the DT.
    let gcc_regs = FakeRegs::new();
    let gcc = Gcc::new(&gcc_regs, p.reset("wcss_reset").unwrap().gcc);
    let aon = gcc
        .reset_line(p.reset("wcss_aon_reset").unwrap().index)
        .unwrap();
    let wr = gcc
        .reset_line(p.reset("wcss_reset").unwrap().index)
        .unwrap();
    let q6r = gcc
        .reset_line(p.reset("wcss_q6_reset").unwrap().index)
        .unwrap();
    let resets = WcssResets {
        aon: &aon,
        wcss: &wr,
        q6: &q6r,
    };
    let h = p.halt.clone().unwrap();
    let (q, rmb, t) = (FakeRegs::new(), FakeRegs::new(), FakeRegs::new());
    rmb.set(wcss::SSCAON_STATUS, 0x400);
    t.set(h.wcss + wcss::AXI_IDLE_REG, 1);
    t.set(h.q6 + wcss::AXI_IDLE_REG, 1);
    let mut w = Q6Wcss::new(WcssRegs {
        qdsp6: &q,
        rmb: &rmb,
        tcsr: &t,
        halt_q6: h.q6,
        halt_wcss: h.wcss,
        halt_nc: h.nc,
    });
    let (img, _) = build_mdt(0x4ab0_0000, &segs(false), true);
    let mut mem = vec![0u8; 0x3000];
    let mut co = Carveout {
        phys: p.carveout.0,
        mem: &mut mem,
    };
    w.load(p.firmware, &img, &FwStore::default(), &mut co)
        .unwrap();
    // The pump plays the Q6: after start, raise `ready` in SMEM, then
    // service our SMP2P interrupt and route fired bits to Q6v5.
    let step = AtomicU32::new(0);
    let edge_cell = narf_lib::sync::IrqSafeSpinLock::new(edge);
    let mut pump = |q6: &Q6v5| {
        if step.fetch_add(1, Ordering::Relaxed) == 1 {
            smem_regs.set(ri + 36, 1 << 1 | 1 << 2);
        }
        for irq in edge_cell.lock().handle_interrupt(&smem) {
            if let Some((_, ev)) = ev_bits.iter().find(|(b, _)| *b == irq.bit) {
                q6.signal(*ev);
            }
        }
    };
    run(w.start(resets, &d, &mut pump)).unwrap().unwrap();
    kt_assert_eq!(w.state(), RprocState::Running);
    kt_assert!(w.q6.handover_issued(), "handover bit routed");
    kt_assert_eq!(gcc_regs.get(0x18000), 0, "WCSS_BCR deasserted");
    kt_assert_eq!(gcc_regs.get(0x18100), 0, "WCSS_Q6_BCR deasserted");
    // Stop: the outbound stop bit is visible to the remote; it acks.
    let edge = edge_cell.into_inner();
    let stopper = Smp2pStop {
        edge: &edge,
        smem: &smem,
        h: out_h,
        bit: stop_bit,
    };
    let seen = AtomicU32::new(0);
    let mut stop_pump = |q6: &Q6v5| {
        let v = edge.outbound_value(&smem, out_h).unwrap_or(0);
        seen.fetch_or(v, Ordering::Relaxed);
        if v & (1 << stop_bit) != 0 {
            q6.signal(Q6Event::StopAck);
        }
    };
    run(w.stop(resets, &stopper, &d, &mut stop_pump))
        .unwrap()
        .unwrap();
    kt_assert_eq!(seen.load(Ordering::Relaxed), 1 << stop_bit);
    kt_assert_eq!(
        edge.outbound_value(&smem, out_h),
        Some(0),
        "stop bit cleared"
    );
    kt_assert_eq!(gcc_regs.get(0x59010), 1, "WCSSAON asserted");
    kt_assert_eq!((gcc_regs.get(0x18000), gcc_regs.get(0x18100)), (1, 1));
    kt_assert_eq!(w.state(), RprocState::Offline);
    TestResult::Pass
}
kernel_test_in!("drivers/soc/qcom", smoke_qcom_composed_ipq6018_wcss_boot);

#[allow(dead_code)]
const _SUB: &str = SUB;
