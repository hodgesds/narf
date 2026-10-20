//! GICv3 ITS model tests: `GITS_BASER<n>` negotiation, LPI tables, ITT
//! sizing, command encodings and the command queue against a register
//! model; firmware parsing against synthetic DTB / MADT / IORT blobs; and
//! (aarch64) the live ITS on QEMU end to end.
//!
//! Expected encodings are written out from Arm IHI 0069H and Linux
//! `include/linux/irqchip/arm-gic-v3.h` / `its_encode_*`, not computed by
//! the code under test.

use alloc::vec;
use alloc::vec::Vec;

use narf_kernel_test::{kernel_test_in, TestResult};

use crate::its_core::{self as c, reg, Cmd, CmdHw, Mmio64, Poll, TableMem};
use crate::its_fw::{self as fw, GicFirmware};

macro_rules! check {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            return TestResult::Fail($msg);
        }
    };
}

// ── Register model ──────────────────────────────────────────────────

#[derive(Copy, Clone)]
struct BaserCfg {
    kind: u64,
    esz: u64,
    /// Accepted page sizes: 4K, 16K, 64K.
    psz_ok: [bool; 3],
    shr_ok: bool,
    /// Corrupt address bit 20 on write (a table that never sticks).
    broken: bool,
}

struct FakeIts {
    typer: u64,
    cfg: [Option<BaserCfg>; 8],
    baser: [u64; 8],
    cbaser: u64,
    cbaser_shr_ok: bool,
    cwriter: u64,
    creadr: u64,
    queue: Vec<Cmd>,
    size: u64,
    /// Commands consumed per `GITS_CREADR` read (models a slow ITS).
    budget: usize,
    stall_op: Option<u8>,
    stalled: bool,
    log: Vec<Cmd>,
    spins: usize,
}

impl FakeIts {
    fn new(typer: u64, size: u64) -> Self {
        Self {
            typer,
            cfg: [None; 8],
            baser: [0; 8],
            cbaser: 0,
            cbaser_shr_ok: true,
            cwriter: 0,
            creadr: 0,
            queue: vec![[0; 4]; (size / 32) as usize],
            size,
            budget: usize::MAX,
            stall_op: None,
            stalled: false,
            log: Vec::new(),
            spins: 1000,
        }
    }
    fn with_baser(mut self, idx: usize, cfg: BaserCfg) -> Self {
        self.cfg[idx] = Some(cfg);
        self.baser[idx] = (cfg.kind << 56) | ((cfg.esz - 1) << 48);
        self
    }
    fn process(&mut self) {
        for _ in 0..self.budget {
            if self.stalled || self.creadr == self.cwriter {
                break;
            }
            let cmd = self.queue[(self.creadr / 32) as usize];
            if self.stall_op == Some(cmd[0] as u8) {
                self.stalled = true;
                break;
            }
            self.log.push(cmd);
            self.creadr = (self.creadr + 32) % self.size;
        }
    }
}

impl Mmio64 for FakeIts {
    fn read32(&mut self, _off: usize) -> u32 {
        0
    }
    fn write32(&mut self, _off: usize, _v: u32) {}
    fn read64(&mut self, off: usize) -> u64 {
        match off {
            reg::GITS_TYPER => self.typer,
            reg::GITS_CBASER => self.cbaser,
            reg::GITS_CWRITER => self.cwriter,
            reg::GITS_CREADR => {
                self.process();
                self.creadr | self.stalled as u64
            }
            o if (reg::GITS_BASER0..reg::GITS_BASER0 + 64).contains(&o) => {
                self.baser[(o - reg::GITS_BASER0) / 8]
            }
            _ => 0,
        }
    }
    fn write64(&mut self, off: usize, v: u64) {
        match off {
            reg::GITS_CBASER => {
                let mut v = v;
                if !self.cbaser_shr_ok {
                    v &= !(3 << 10);
                }
                self.cbaser = v;
                self.creadr = 0;
            }
            reg::GITS_CWRITER => self.cwriter = v & 0xF_FFE0,
            o if (reg::GITS_BASER0..reg::GITS_BASER0 + 64).contains(&o) => {
                let i = (o - reg::GITS_BASER0) / 8;
                let Some(cfg) = self.cfg[i] else {
                    return;
                };
                let ro = (cfg.kind << 56) | ((cfg.esz - 1) << 48);
                let mut v = (v & !((7 << 56) | (0x1F << 48))) | ro;
                let psz = ((v >> 8) & 3) as usize;
                if psz > 2 || !cfg.psz_ok[psz] {
                    let first = cfg.psz_ok.iter().position(|ok| *ok).unwrap_or(0) as u64;
                    v = (v & !(3 << 8)) | (first << 8);
                }
                if !cfg.shr_ok {
                    v &= !(3 << 10);
                }
                if cfg.broken {
                    v ^= 1 << 20;
                }
                self.baser[i] = v;
            }
            _ => {}
        }
    }
}

impl CmdHw for FakeIts {
    fn write_cmd(&mut self, off: u64, cmd: &Cmd) {
        self.queue[(off / 32) as usize] = *cmd;
    }
    fn spin(&mut self, poll: &mut dyn FnMut(&mut Self) -> Poll) -> Poll {
        for _ in 0..self.spins {
            let r = poll(self);
            if r != Poll::Pending {
                return r;
            }
        }
        Poll::Pending
    }
}

#[derive(Default)]
struct FakeMem {
    next: u64,
    allocs: Vec<(u64, u64)>,
    frees: Vec<(u64, u64)>,
    flushes: Vec<(u64, u64)>,
}

impl TableMem for FakeMem {
    fn alloc(&mut self, bytes: u64, align: u64) -> Option<u64> {
        let base = if self.next == 0 {
            0x4000_0000
        } else {
            self.next
        };
        let pa = base.div_ceil(align) * align;
        self.next = pa + bytes;
        self.allocs.push((pa, bytes));
        Some(pa)
    }
    fn free(&mut self, pa: u64, bytes: u64) {
        self.frees.push((pa, bytes));
    }
    fn flush(&mut self, pa: u64, bytes: u64) {
        self.flushes.push((pa, bytes));
    }
}

/// GITS_TYPER: Physical, ITT_entry_size field `itt-1`, IDbits field
/// `ev-1`, Devbits field `dev-1`.
const fn typer(itt: u64, ev: u64, dev: u64) -> u64 {
    1 | ((itt - 1) << 4) | ((ev - 1) << 8) | ((dev - 1) << 13)
}

fn its_typer_fields_match_linux_masks() -> TestResult {
    // Linux: ITT_ENTRY_SIZE GENMASK(7,4), IDBITS GENMASK(12,8),
    // DEVBITS GENMASK(17,13), PTA BIT(19), HCC [31:24].
    let t = c::ItsTyper((7 << 4) | (15 << 8) | (19 << 13) | (1 << 19) | (3 << 24) | 1);
    check!(t.physical(), "Physical bit");
    check!(t.itt_entry_size() == 8, "ITT_entry_size + 1");
    check!(t.event_id_bits() == 16, "IDbits + 1");
    check!(t.device_id_bits() == 20, "Devbits + 1");
    check!(t.pta(), "PTA bit 19");
    check!(t.hcc() == 3, "HCC");
    check!(t.collection_id_bits() == 16, "no CIL ⇒ 16-bit ICIDs");
    let cil = c::ItsTyper((1 << 36) | (7 << 32));
    check!(cil.collection_id_bits() == 8, "CIL ⇒ CIDbits + 1");
    TestResult::Pass
}
kernel_test_in!("interrupts/its", its_typer_fields_match_linux_masks);

fn its_baser_negotiates_type_entry_size_page_size_and_shareability() -> TestResult {
    let mut its = FakeIts::new(typer(8, 16, 16), 0x1_0000)
        // Device table: no 64K pages, non-shareable implementation.
        .with_baser(
            0,
            BaserCfg {
                kind: 1,
                esz: 8,
                psz_ok: [true, true, false],
                shr_ok: false,
                broken: false,
            },
        )
        // vPE table: must be left alone.
        .with_baser(
            1,
            BaserCfg {
                kind: 2,
                esz: 32,
                psz_ok: [true, true, true],
                shr_ok: true,
                broken: false,
            },
        )
        // Collection table: only 64K pages, 16-byte entries.
        .with_baser(
            3,
            BaserCfg {
                kind: 4,
                esz: 16,
                psz_ok: [false, false, true],
                shr_ok: true,
                broken: false,
            },
        );
    let vpe_before = its.baser[1];
    let mut mem = FakeMem::default();
    let typer = c::ItsTyper(its.read64(reg::GITS_TYPER));
    let Ok(t) = c::alloc_tables(&mut its, typer, 64, &mut mem) else {
        return TestResult::Fail("alloc_tables failed");
    };
    let (Some(dev), Some(col)) = (t.device, t.collection) else {
        return TestResult::Fail("device/collection table missing");
    };
    // Device: 16K pages (64K refused), 8 << 16 = 512 KiB = 32 pages.
    check!(dev.idx == 0 && dev.plan.psz == c::SZ_16K, "device psz 16K");
    check!(
        dev.plan.bytes == 512 << 10 && dev.plan.ids == 1 << 16,
        "device sizing"
    );
    let v = its.baser[0];
    check!(v >> 63 == 1, "device Valid");
    check!(
        (v >> 56) & 7 == 1 && (v >> 48) & 0x1F == 7,
        "type/esz preserved"
    );
    check!((v >> 8) & 3 == 1, "16K page-size field");
    check!(v & 0xFF == 31, "Size = pages - 1");
    check!(
        (v >> 10) & 3 == 0 && (v >> 59) & 7 == 1,
        "non-shareable ⇒ nC"
    );
    check!(v & 0xFFFF_FFFF_F000 == dev.pa, "device address field");
    check!(
        mem.flushes.contains(&(dev.pa, dev.plan.bytes)),
        "non-shareable table flushed"
    );
    // Collection: 64K pages, inherits the device table's attributes.
    check!(
        col.idx == 3 && col.plan.psz == c::SZ_64K,
        "collection psz 64K"
    );
    check!(
        col.plan.bytes == c::SZ_64K && col.pa % c::SZ_64K == 0,
        "collection sizing"
    );
    let v = its.baser[3];
    check!((v >> 8) & 3 == 2 && v & 0xFF == 0, "collection page fields");
    check!(
        col.baser.shr == 0 && col.baser.cache == c::CACHE_NC,
        "attributes inherited"
    );
    check!(its.baser[1] == vpe_before, "vPE BASER untouched");
    TestResult::Pass
}
kernel_test_in!(
    "interrupts/its",
    its_baser_negotiates_type_entry_size_page_size_and_shareability
);

fn its_baser_failures_and_caps() -> TestResult {
    let mut its = FakeIts::new(typer(8, 16, 16), 0x1_0000).with_baser(
        0,
        BaserCfg {
            kind: 1,
            esz: 8,
            psz_ok: [true, false, false],
            shr_ok: true,
            broken: true,
        },
    );
    let mut mem = FakeMem::default();
    let t = c::ItsTyper(its.typer);
    let r = c::alloc_tables(&mut its, t, 8, &mut mem);
    check!(
        matches!(r, Err(c::SetupError::NotSticky { .. })),
        "a BASER that drops address bits must be refused"
    );
    check!(
        mem.frees.len() == 1 && its.baser[0] >> 63 == 0,
        "refused table freed + invalid"
    );

    // Devbits 32 with 8-byte entries is capped to the flat-table budget.
    let p = c::plan_table(
        c::TableType::Device,
        8,
        c::SZ_64K,
        c::ItsTyper(typer(8, 16, 32)),
        8,
    )
    .unwrap();
    check!(
        p.bytes == c::MAX_FLAT_TABLE_BYTES,
        "flat device table capped"
    );
    check!(
        p.ids == c::MAX_FLAT_TABLE_BYTES / 8,
        "IDs covered shrink with the cap"
    );
    // 4K pages: 256-page Size limit (1 MiB) bites first.
    let p = c::plan_table(
        c::TableType::Device,
        8,
        c::SZ_4K,
        c::ItsTyper(typer(8, 16, 24)),
        8,
    )
    .unwrap();
    check!(p.bytes == 256 * c::SZ_4K, "GITS_BASER.Size cap");
    // 52-bit PA with 64K pages: PA[51:48] lands in bits [15:12].
    check!(
        c::baser_addr_field(0x000F_0000_0001_0000, c::SZ_64K) == Some(0xF000 | 0x1_0000),
        "52-bit address encoding"
    );
    check!(
        c::baser_addr_field(0x1_1000, c::SZ_64K).is_none(),
        "misaligned refused"
    );
    check!(
        c::baser_addr_field(1 << 48, c::SZ_4K).is_none(),
        "4K pages cannot hold 52-bit PAs"
    );
    TestResult::Pass
}
kernel_test_in!("interrupts/its", its_baser_failures_and_caps);

fn its_cbaser_falls_back_to_non_shareable() -> TestResult {
    let mut its = FakeIts::new(typer(8, 16, 16), 0x1_0000);
    let Ok((v, flush)) = c::setup_cbaser(&mut its, 0x4123_0000, c::CMD_QUEUE_BYTES) else {
        return TestResult::Fail("coherent CBASER");
    };
    check!(
        !flush && (v >> 10) & 3 == 1 && (v >> 59) & 7 == 7,
        "InnerShareable RaWaWb"
    );
    check!(v & 0xFF == 15 && v >> 63 == 1, "16 × 4K pages, Valid");
    its.cbaser_shr_ok = false;
    let Ok((v, flush)) = c::setup_cbaser(&mut its, 0x4123_0000, c::CMD_QUEUE_BYTES) else {
        return TestResult::Fail("non-shareable CBASER");
    };
    check!(
        flush && (v >> 10) & 3 == 0 && (v >> 59) & 7 == 1,
        "nC + flushing"
    );
    TestResult::Pass
}
kernel_test_in!("interrupts/its", its_cbaser_falls_back_to_non_shareable);

// ── LPI tables ──────────────────────────────────────────────────────

#[derive(Default)]
struct FakeRd {
    ctlr: u32,
    typer: u64,
    prop: u64,
    pend: u64,
    shr_ok: bool,
}

impl Mmio64 for FakeRd {
    fn read32(&mut self, off: usize) -> u32 {
        if off == reg::GICR_CTLR {
            self.ctlr
        } else {
            0
        }
    }
    fn write32(&mut self, off: usize, v: u32) {
        if off == reg::GICR_CTLR {
            self.ctlr = v;
        }
    }
    fn read64(&mut self, off: usize) -> u64 {
        match off {
            reg::GICR_TYPER => self.typer,
            reg::GICR_PROPBASER => self.prop,
            reg::GICR_PENDBASER => self.pend,
            _ => 0,
        }
    }
    fn write64(&mut self, off: usize, v: u64) {
        let v = if self.shr_ok { v } else { v & !(3 << 10) };
        match off {
            reg::GICR_PROPBASER => self.prop = v,
            reg::GICR_PENDBASER => self.pend = v,
            _ => {}
        }
    }
}

fn its_lpi_tables_sizes_alignment_and_attributes() -> TestResult {
    // GICD_TYPER: LPIS (bit 17), IDbits [23:19].
    let gicd = |idbits: u32| (1 << 17) | ((idbits - 1) << 19);
    check!(
        c::lpi_id_bits(gicd(16), 256) == Some(14),
        "14 bits cover 8192+256"
    );
    check!(
        c::lpi_id_bits(gicd(16), 8193) == Some(15),
        "wider range needs 15"
    );
    check!(c::lpi_id_bits(gicd(13), 256).is_none(), "IDbits too small");
    check!(
        c::lpi_id_bits(gicd(16) & !(1 << 17), 256).is_none(),
        "no LPIS"
    );
    check!(c::prop_table_bytes(14) == 8192, "one byte per LPI");
    check!(
        c::pend_table_bytes(14) == 0x1_0000,
        "pending rounded to 64 KiB"
    );
    check!(c::pend_table_bytes(20) == 0x2_0000, "1 bit per INTID");
    check!(
        c::lpi_prop_byte(true) == 0xA3 && c::lpi_prop_byte(false) == 0xA2,
        "prop byte"
    );

    let mut rd = FakeRd {
        typer: c::GICR_TYPER_PLPIS,
        shr_ok: true,
        ..FakeRd::default()
    };
    check!(
        c::init_lpis(&mut rd, 0x4000_0000, 0x4001_8000, 14) == Err(c::SetupError::Address),
        "pending table must be 64 KiB aligned"
    );
    let Ok(t) = c::init_lpis(&mut rd, 0x4000_2000, 0x4003_0000, 14) else {
        return TestResult::Fail("coherent redistributor");
    };
    check!(rd.ctlr & 1 == 1, "EnableLPIs");
    check!(t.propbaser & 0x1F == 13, "IDbits - 1");
    check!(
        t.propbaser & 0xF_FFFF_FFFF_F000 == 0x4000_2000,
        "PROPBASER PA[51:12]"
    );
    check!(
        (t.propbaser >> 10) & 3 == 1 && (t.propbaser >> 7) & 7 == 7,
        "PROPBASER attrs"
    );
    check!(
        t.pendbaser & 0xF_FFFF_FFFF_0000 == 0x4003_0000,
        "PENDBASER PA[51:16]"
    );
    check!(!t.prop_flush, "coherent property table");
    // Re-init with the same tables is accepted; other tables are refused.
    check!(
        c::init_lpis(&mut rd, 0x4000_2000, 0x4003_0000, 14).is_ok(),
        "re-init"
    );
    check!(
        c::init_lpis(&mut rd, 0x5000_0000, 0x5001_0000, 14)
            == Err(c::SetupError::LpisAlreadyEnabled),
        "live LPIs not reprogrammed"
    );
    let mut rd = FakeRd {
        typer: c::GICR_TYPER_PLPIS,
        shr_ok: false,
        ..FakeRd::default()
    };
    let Ok(t) = c::init_lpis(&mut rd, 0x4000_2000, 0x4003_0000, 14) else {
        return TestResult::Fail("non-shareable redistributor");
    };
    check!(t.prop_flush, "non-shareable ⇒ property flushing");
    check!(
        (t.propbaser >> 7) & 7 == 1 && (t.pendbaser >> 7) & 7 == 1,
        "nC fallback"
    );
    let mut rd = FakeRd::default();
    check!(
        c::init_lpis(&mut rd, 0x4000_2000, 0x4003_0000, 14) == Err(c::SetupError::NoLpis),
        "GICR_TYPER.PLPIS required"
    );
    TestResult::Pass
}
kernel_test_in!(
    "interrupts/its",
    its_lpi_tables_sizes_alignment_and_attributes
);

// ── ITTs and commands ───────────────────────────────────────────────

fn its_itt_sizing_and_alignment() -> TestResult {
    let t8 = c::ItsTyper(typer(8, 16, 16));
    let t12 = c::ItsTyper(typer(12, 16, 16));
    let p = c::plan_itt(1, t8);
    check!(
        p.nr_ites == 2 && p.bytes == 256 && p.size_field == 0,
        "1 vector ⇒ 2 ITEs"
    );
    let p = c::plan_itt(256, t8);
    check!(
        p.nr_ites == 256 && p.bytes == 2048 && p.size_field == 7,
        "256 vectors"
    );
    let p = c::plan_itt(3, t12);
    check!(p.nr_ites == 4 && p.bytes == 256, "rounded to ITS_ITT_ALIGN");
    let p = c::plan_itt(64, t12);
    check!(
        p.bytes == 768 && p.bytes % c::ITS_ITT_ALIGN == 0,
        "12-byte ITEs"
    );
    let p = c::plan_itt(1000, c::ItsTyper(typer(8, 5, 16)));
    check!(
        p.nr_ites == 32 && p.size_field == 4,
        "capped by EventID bits"
    );
    TestResult::Pass
}
kernel_test_in!("interrupts/its", its_itt_sizing_and_alignment);

fn its_command_encodings_match_linux() -> TestResult {
    // its_build_mapd_cmd: devid [63:32] DW0, size [4:0] DW1,
    // itt >> 8 at [51:8] DW2, valid [63] DW2.
    check!(
        c::cmd_mapd(0x1234, 0x8765_43FF, 7, true)
            == [0x08 | (0x1234 << 32), 7, 0x8765_4300 | (1 << 63), 0],
        "MAPD"
    );
    check!(
        c::cmd_mapd(0x1234, 0x8765_4300, 7, false)[2] == 0x8765_4300,
        "MAPD V=0"
    );
    // its_build_mapc_cmd: col [15:0], target >> 16 at [51:16], valid.
    check!(
        c::cmd_mapc(3, 0x2_0000, true) == [0x09, 0, 3 | 0x2_0000 | (1 << 63), 0],
        "MAPC"
    );
    // its_build_mapti_cmd: event [31:0] DW1, phys_id [63:32] DW1, col DW2.
    check!(
        c::cmd_mapti(0x10, 5, 8200, 2) == [0x0A | (0x10 << 32), 5 | (8200 << 32), 2, 0],
        "MAPTI"
    );
    check!(c::cmd_inv(7, 9) == [0x0C | (7 << 32), 9, 0, 0], "INV");
    check!(
        c::cmd_discard(7, 9) == [0x0F | (7 << 32), 9, 0, 0],
        "DISCARD"
    );
    check!(c::cmd_int(7, 9) == [0x03 | (7 << 32), 9, 0, 0], "INT");
    check!(c::cmd_invall(4) == [0x0D, 0, 4, 0], "INVALL");
    check!(
        c::cmd_sync(0x080A_0000) == [0x05, 0, 0x080A_0000, 0],
        "SYNC target"
    );
    // RDbase: PTA ⇒ physical address; else processor number << 16.
    let gicr_typer = 5 << 8;
    check!(
        c::rd_target(c::ItsTyper(typer(8, 16, 16)), 0x080E_0000, gicr_typer) == 5 << 16,
        "processor-number target"
    );
    check!(
        c::rd_target(
            c::ItsTyper(typer(8, 16, 16) | (1 << 19)),
            0x080E_0000,
            gicr_typer
        ) == 0x080E_0000,
        "PTA target"
    );
    TestResult::Pass
}
kernel_test_in!("interrupts/its", its_command_encodings_match_linux);

fn its_command_queue_wraps_and_reports_stall_and_timeout() -> TestResult {
    // 8-slot queue, an ITS that consumes one command per CREADR read.
    let mut its = FakeIts::new(typer(8, 16, 16), 256);
    its.budget = 1;
    let mut q = c::CmdQueue::new(256);
    let cmds: Vec<Cmd> = (0..20).map(|i| c::cmd_int(1, i)).collect();
    check!(
        c::submit(&mut its, &mut q, &cmds).is_ok(),
        "wrapping batch completes"
    );
    check!(its.log == cmds, "every command consumed once, in order");
    check!(
        q.write == (20 * 32) % 256 && its.cwriter == q.write,
        "CWRITER wrapped"
    );

    let mut w = c::RangeWait::new(0xE0, 0x20, 0x100);
    check!(
        !w.update(0xE0) && !w.update(0x00) && w.update(0x20),
        "wrap-aware completion"
    );

    // Stalled on MAPTI: the error names the offset of the bad command.
    let mut its = FakeIts::new(typer(8, 16, 16), 256);
    its.stall_op = Some(c::CMD_MAPTI);
    let mut q = c::CmdQueue::new(256);
    let r = c::submit(
        &mut its,
        &mut q,
        &[
            c::cmd_inv(1, 1),
            c::cmd_mapti(1, 1, 8192, 0),
            c::cmd_sync(0),
        ],
    );
    check!(
        r == Err(c::CmdError::Stalled { offset: 32 }),
        "Stalled reported"
    );

    // An ITS that never moves times out instead of spinning forever.
    let mut its = FakeIts::new(typer(8, 16, 16), 256);
    its.budget = 0;
    let mut q = c::CmdQueue::new(256);
    check!(
        c::submit(&mut its, &mut q, &[c::cmd_sync(0)]) == Err(c::CmdError::Timeout),
        "bounded CREADR poll"
    );
    TestResult::Pass
}
kernel_test_in!(
    "interrupts/its",
    its_command_queue_wraps_and_reports_stall_and_timeout
);

// ── Firmware ────────────────────────────────────────────────────────

/// Minimal FDT writer for the parser tests.
struct Fdt {
    st: Vec<u8>,
    strings: Vec<u8>,
}

impl Fdt {
    fn new() -> Self {
        Self {
            st: Vec::new(),
            strings: Vec::new(),
        }
    }
    fn tok(&mut self, t: u32) {
        self.st.extend_from_slice(&t.to_be_bytes());
    }
    fn begin(&mut self, name: &str) -> &mut Self {
        self.tok(1);
        self.st.extend_from_slice(name.as_bytes());
        self.st.push(0);
        while self.st.len() % 4 != 0 {
            self.st.push(0);
        }
        self
    }
    fn end(&mut self) -> &mut Self {
        self.tok(2);
        self
    }
    fn prop(&mut self, name: &str, data: &[u8]) -> &mut Self {
        let off = match self
            .strings
            .windows(name.len() + 1)
            .position(|w| &w[..name.len()] == name.as_bytes() && w[name.len()] == 0)
        {
            Some(o) => o,
            None => {
                let o = self.strings.len();
                self.strings.extend_from_slice(name.as_bytes());
                self.strings.push(0);
                o
            }
        };
        self.tok(3);
        self.st
            .extend_from_slice(&(data.len() as u32).to_be_bytes());
        self.st.extend_from_slice(&(off as u32).to_be_bytes());
        self.st.extend_from_slice(data);
        while self.st.len() % 4 != 0 {
            self.st.push(0);
        }
        self
    }
    fn cells(&mut self, name: &str, v: &[u32]) -> &mut Self {
        let b: Vec<u8> = v.iter().flat_map(|x| x.to_be_bytes()).collect();
        self.prop(name, &b)
    }
    fn finish(&mut self) -> Vec<u8> {
        self.tok(9);
        let off_struct = 40u32;
        let off_strings = off_struct + self.st.len() as u32;
        let total = off_strings + self.strings.len() as u32;
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
            self.strings.len() as u32,
            self.st.len() as u32,
        ] {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out.extend_from_slice(&self.st);
        out.extend_from_slice(&self.strings);
        out
    }
}

fn qemu_like_dtb(msi_map: bool) -> Vec<u8> {
    let mut f = Fdt::new();
    f.begin("")
        .cells("#address-cells", &[2])
        .cells("#size-cells", &[2]);
    f.begin("intc@8000000")
        .prop("compatible", b"arm,gic-v3\0")
        .cells("#address-cells", &[2])
        .cells("#size-cells", &[2])
        .cells("#redistributor-regions", &[1])
        .cells(
            "reg",
            &[0, 0x0800_0000, 0, 0x1_0000, 0, 0x080A_0000, 0, 0x00F6_0000],
        );
    f.begin("its@8080000")
        .prop("compatible", b"arm,gic-v3-its\0")
        .prop("msi-controller", b"")
        .cells("phandle", &[0x8])
        .cells("reg", &[0, 0x0808_0000, 0, 0x2_0000])
        .end();
    f.end();
    f.begin("pcie@10000000")
        .prop("compatible", b"pci-host-ecam-generic\0")
        .prop("device_type", b"pci\0")
        .cells("#address-cells", &[3])
        .cells("#size-cells", &[2])
        .cells("reg", &[0x40, 0x1000_0000, 0, 0x1000_0000]);
    if msi_map {
        f.cells(
            "msi-map",
            &[0x0000, 0x8, 0x1_0000, 0x100, 0x0100, 0x8, 0x2_0000, 0x100],
        )
        .cells("msi-map-mask", &[0xFFFF]);
    }
    // A PCI-PCI bridge node underneath: not a host bridge.
    f.begin("pci@1,0")
        .prop("device_type", b"pci\0")
        .cells("reg", &[0x800, 0, 0, 0, 0])
        .end();
    f.end();
    f.end();
    f.finish()
}

fn its_fdt_discovers_its_redistributors_and_msi_map() -> TestResult {
    let mut g = GicFirmware::default();
    check!(fw::parse_fdt(&qemu_like_dtb(true), &mut g), "DTB parses");
    check!(g.source == fw::Source::Devicetree, "DT source");
    check!(
        g.its
            == [fw::ItsNode {
                base: 0x0808_0000,
                id: 8
            }],
        "ITS base + phandle"
    );
    check!(g.rd_regions == [(0x080A_0000, 0x00F6_0000)], "GICR region");
    check!(
        g.pci_hosts.len() == 1 && g.pci_hosts[0].segment == 0,
        "one host bridge"
    );
    check!(
        g.pci_device_id(0, 0x0008) == Some(0x1_0008),
        "first msi-map range"
    );
    check!(
        g.pci_device_id(0, 0x0108) == Some(0x2_0008),
        "second msi-map range"
    );
    check!(
        g.pci_device_id(0, 0x0300).is_none(),
        "RID outside msi-map refused"
    );

    let mut g = GicFirmware::default();
    check!(fw::parse_fdt(&qemu_like_dtb(false), &mut g), "DTB parses");
    check!(
        g.pci_device_id(0, 0x0300) == Some(0x0300),
        "no msi-map ⇒ identity"
    );

    let mut bad = qemu_like_dtb(true);
    bad[0] = 0;
    check!(
        !fw::parse_fdt(&bad, &mut GicFirmware::default()),
        "bad magic"
    );
    TestResult::Pass
}
kernel_test_in!(
    "interrupts/its",
    its_fdt_discovers_its_redistributors_and_msi_map
);

fn sdt(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(sig);
    t.extend_from_slice(&((36 + body.len()) as u32).to_le_bytes());
    t.extend_from_slice(&[0; 28]);
    t.extend_from_slice(body);
    t
}

fn its_madt_gicc_gicr_and_its_structures() -> TestResult {
    let mut b = Vec::new();
    b.extend_from_slice(&[0; 8]); // local controller address + flags
    for (uid, mpidr, rd) in [
        (0u32, 0x0u64, 0x3000_0000u64),
        (1, 0x1_0000_0101, 0x3002_0000),
    ] {
        let mut e = vec![0u8; 80];
        e[0] = 0x0B;
        e[1] = 80;
        e[8..12].copy_from_slice(&uid.to_le_bytes());
        e[12..16].copy_from_slice(&1u32.to_le_bytes()); // enabled
        e[60..68].copy_from_slice(&rd.to_le_bytes());
        e[68..76].copy_from_slice(&mpidr.to_le_bytes());
        b.extend_from_slice(&e);
    }
    let mut gicr = vec![0u8; 16];
    gicr[0] = 0x0E;
    gicr[1] = 16;
    gicr[4..12].copy_from_slice(&0x3000_0000u64.to_le_bytes());
    gicr[12..16].copy_from_slice(&0x40_0000u32.to_le_bytes());
    b.extend_from_slice(&gicr);
    let mut its = vec![0u8; 20];
    its[0] = 0x0F;
    its[1] = 20;
    its[4..8].copy_from_slice(&7u32.to_le_bytes());
    its[8..16].copy_from_slice(&0x2F02_0000u64.to_le_bytes());
    b.extend_from_slice(&its);
    let mut g = GicFirmware::default();
    check!(
        fw::parse_madt(&sdt(b"APIC", &b), &mut g) == 4,
        "four GIC structures"
    );
    check!(g.source == fw::Source::Acpi, "ACPI source");
    check!(
        g.its
            == [fw::ItsNode {
                base: 0x2F02_0000,
                id: 7
            }],
        "GIC ITS"
    );
    check!(g.rd_regions == [(0x3000_0000, 0x40_0000)], "GICR range");
    // Aff3 from MPIDR[39:32] packs into bits [31:24].
    check!(
        g.gicc_rd == [(0, 0x3000_0000), (0x0100_0101, 0x3002_0000)],
        "GICC redistributor + MPIDR"
    );
    TestResult::Pass
}
kernel_test_in!("interrupts/its", its_madt_gicc_gicr_and_its_structures);

/// IORT with: ITS group (id 7), SMMUv3 mapping 0..=0xFFFF → 0x1_0000+,
/// root complex segment 1 mapping 0..=0xFFFF → SMMU, root complex segment
/// 2 with a single mapping to DeviceID 0x55.
fn synthetic_iort() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&4u32.to_le_bytes()); // nodes
    body.extend_from_slice(&48u32.to_le_bytes()); // node array offset
    body.extend_from_slice(&0u32.to_le_bytes());
    let its_off = 48u32;
    let mut its = vec![0u8; 24];
    its[0] = 0;
    its[1..3].copy_from_slice(&24u16.to_le_bytes());
    its[16..20].copy_from_slice(&1u32.to_le_bytes());
    its[20..24].copy_from_slice(&7u32.to_le_bytes());
    let smmu_off = its_off + 24;
    let map = |in_base: u32, count: u32, out: u32, to: u32, flags: u32| {
        let mut m = Vec::new();
        for v in [in_base, count, out, to, flags] {
            m.extend_from_slice(&v.to_le_bytes());
        }
        m
    };
    let mut smmu = vec![0u8; 68];
    smmu[0] = 4;
    smmu[3] = 0; // revision 0: no ID-mapping index
    smmu[8..12].copy_from_slice(&1u32.to_le_bytes());
    smmu[12..16].copy_from_slice(&68u32.to_le_bytes());
    smmu.extend_from_slice(&map(0, 0xFFFF, 0x1_0000, its_off, 0));
    let slen = smmu.len() as u16;
    smmu[1..3].copy_from_slice(&slen.to_le_bytes());
    let rc1_off = smmu_off + smmu.len() as u32;
    let rc = |segment: u32, m: Vec<u8>| {
        let mut n = vec![0u8; 36];
        n[0] = 2;
        n[8..12].copy_from_slice(&1u32.to_le_bytes());
        n[12..16].copy_from_slice(&36u32.to_le_bytes());
        n[28..32].copy_from_slice(&segment.to_le_bytes());
        n.extend_from_slice(&m);
        let l = n.len() as u16;
        n[1..3].copy_from_slice(&l.to_le_bytes());
        n
    };
    let rc1 = rc(1, map(0, 0xFFFF, 0, smmu_off, 0));
    let rc2 = rc(2, map(0, 0, 0x55, its_off, 1));
    let _ = rc1_off;
    body.extend_from_slice(&its);
    body.extend_from_slice(&smmu);
    body.extend_from_slice(&rc1);
    body.extend_from_slice(&rc2);
    sdt(b"IORT", &body)
}

fn its_iort_maps_rid_through_smmu_to_its_group() -> TestResult {
    let t = synthetic_iort();
    check!(
        fw::iort_map_rid(&t, 1, 0x0300) == Some(0x1_0300),
        "RC → SMMUv3 → ITS group"
    );
    check!(
        fw::iort_map_rid(&t, 2, 0x0123) == Some(0x55),
        "single mapping ignores the input ID"
    );
    check!(fw::iort_map_rid(&t, 9, 0x0300).is_none(), "unknown segment");
    let g = GicFirmware {
        iort: Some(t),
        ..GicFirmware::default()
    };
    check!(g.pci_device_id(1, 0x0010) == Some(0x1_0010), "IORT wins");
    check!(
        g.pci_device_id(9, 0x0010) == Some(0x0010),
        "unmapped ⇒ input ID (Linux)"
    );
    TestResult::Pass
}
kernel_test_in!(
    "interrupts/its",
    its_iort_maps_rid_through_smmu_to_its_group
);

fn its_redistributor_walk_follows_typer() -> TestResult {
    // Frame 0: aff 0, GICv4 (VLPIS) ⇒ next frame 256 KiB on;
    // frame 1: aff 0x100, GICv3 ⇒ 128 KiB; frame 2: aff 0x200, Last.
    let frames = [
        (0x1000_0000u64, c::GICR_TYPER_VLPIS),
        (0x1004_0000, 0x100u64 << 32),
        (0x1006_0000, (0x200u64 << 32) | c::GICR_TYPER_LAST),
    ];
    let read = |pa: u64| frames.iter().find(|f| f.0 == pa).map(|f| f.1);
    let region = (0x1000_0000, 0x100_0000);
    check!(
        fw::find_rd_frame(region, None, 0x200, read).map(|h| h.0) == Some(0x1006_0000),
        "stride follows VLPIS"
    );
    check!(
        fw::find_rd_frame(region, None, 0x300, read).is_none(),
        "stops at Last"
    );
    let read2 = |pa: u64| (pa == 0x1008_0000).then_some(0x300u64 << 32).or(Some(0));
    check!(
        fw::find_rd_frame(region, Some(0x4_0000), 0x300, read2).map(|h| h.0) == Some(0x1008_0000),
        "explicit redistributor-stride"
    );
    TestResult::Pass
}
kernel_test_in!("interrupts/its", its_redistributor_walk_follows_typer);

// ── Live ITS (QEMU virt) ────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
fn its_live_tables_and_lpi_delivery() -> TestResult {
    use crate::aarch64::its;
    let Some(s) = its::status() else {
        return TestResult::Skip("ITS not initialised on this machine");
    };
    check!(
        s.pend_pa % c::PEND_ALIGN == 0,
        "pending table 64 KiB aligned"
    );
    check!(
        s.pendbaser & 0xF_FFFF_FFFF_0000 == s.pend_pa,
        "PENDBASER holds the pending table"
    );
    check!(
        s.propbaser & 0x1F == (s.id_bits - 1) as u64,
        "PROPBASER IDbits"
    );
    check!(
        s.prop_bytes == c::prop_table_bytes(s.id_bits),
        "property table covers IDbits"
    );
    check!(s.tables.device.is_some(), "device table provisioned");
    check!(
        s.device_ids >= (1u64 << 16).min(1u64 << s.typer.device_id_bits()),
        "device table covers the PCI RID space"
    );

    // A DeviceID no PCI function on segment 0 maps to.
    let dev = (s.device_ids.min(1 << 20) - 1) as u32;
    let Ok(vector) = crate::vector::alloc() else {
        return TestResult::Skip("no free vector");
    };
    let lpi = its::lpi_for_vector(vector);
    crate::install_handler_named(vector, "its-selftest", 0, |_| {
        crate::dispatch::IrqStatus::Handled
    });
    let finish = |r: TestResult| {
        crate::remove_handler(vector, "its-selftest", 0);
        let _ = crate::vector::free(vector);
        r
    };
    // SAFETY: test-owned DeviceID with no hardware behind it.
    let Ok(info) = (unsafe { its::create_device(dev, 1) }) else {
        return finish(TestResult::Fail("create_device"));
    };
    if info.itt_pa % c::ITS_ITT_ALIGN != 0 || info.nr_ites != 2 {
        return finish(TestResult::Fail("ITT aligned + sized for one vector"));
    }
    // SAFETY: as above.
    if unsafe { its::map_event(dev, 0, lpi, 0) }.is_err() {
        return finish(TestResult::Fail("map_event"));
    }
    if its::lpi_config(lpi) != Some(c::lpi_prop_byte(true)) {
        return finish(TestResult::Fail("mapped LPI enabled in the property table"));
    }
    // Second map on the same device reuses its ITT.
    // SAFETY: as above.
    if unsafe { its::create_device(dev, 1) }.map(|i| i.itt_pa) != Ok(info.itt_pa) {
        return finish(TestResult::Fail("ITT reused"));
    }
    let before = crate::fire_count(vector);
    let was_on = narf_arch::interrupts_enabled();
    // SAFETY: test context; restored below.
    unsafe { narf_arch::enable_interrupts() };
    // SAFETY: event mapped, handler installed.
    let injected = unsafe { its::__test_inject(dev, 0) };
    let fired = narf_scheduler::responsive_spin_until(
        || crate::fire_count(vector) > before,
        narf_time::Deadline::after_ms(200),
    );
    if !was_on {
        // SAFETY: restoring the caller's state.
        unsafe { narf_arch::disable_interrupts() };
    }
    // SAFETY: nothing raises the test DeviceID any more.
    let freed = unsafe { its::free_device(dev) };
    if injected.is_err() {
        return finish(TestResult::Fail("INT command"));
    }
    if !fired {
        return finish(TestResult::Fail("LPI did not reach the BSP"));
    }
    if freed.is_err() || its::device_info(dev).is_some() {
        return finish(TestResult::Fail("free_device"));
    }
    if its::lpi_config(lpi) != Some(c::lpi_prop_byte(false)) {
        return finish(TestResult::Fail("freed LPI disabled"));
    }
    finish(TestResult::Pass)
}
#[cfg(target_arch = "aarch64")]
kernel_test_in!("interrupts/its", its_live_tables_and_lpi_delivery);
