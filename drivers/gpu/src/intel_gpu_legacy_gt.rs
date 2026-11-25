//! Gen9 / Gen11 GT setup for the execlists owner: the cache policy Linux's
//! `intel_gt_init_hw` programs before any engine runs.
//!
//! Gen9 (Skylake through Comet Lake) and Gen11 (Ice, Elkhart and Jasper
//! Lake) submit through execlists: i915 has no GuC submission below
//! graphics 11 and does not enable it by default below graphics 12
//! (`uc_expand_default_options`). Their cache model also predates Gen12's
//! global MOCS and PAT index: a private PPAT selects the leaf cacheability a
//! PPGTT PTE's PAT bits name, and every engine owns its own 64-entry MOCS
//! bank, with the render engine also loading the shared L3 control table.
//!
//! MIT Linux v6.12 `gt/intel_gtt.c` (`setup_private_pat`,
//! `bdw_setup_private_ppat`, `icl_setup_private_ppat`), `gt/intel_mocs.c`
//! (`skl_mocs_table`, `icl_mocs_table`, `get_mocs_settings`,
//! `intel_mocs_init_engine`) and `gt/intel_gt_regs.h`. Every value here is a
//! transcription; the tests pin them against hand-expanded macro values.

use crate::intel_gpu_engine::Engine;
use crate::intel_gpu_gt::GtPlatform;

/// The execlists generations this module covers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum LegacyGt {
    /// Graphics 9, big-core (`IS_GEN9_BC`: SKL/KBL/CFL/WHL/CML).
    Gen9,
    /// Graphics 11 (ICL/EHL/JSL).
    Gen11,
}

impl LegacyGt {
    pub(crate) const fn for_platform(platform: GtPlatform) -> Option<Self> {
        match platform {
            // Gen9 LP needs its own cache, workaround and power profile.
            GtPlatform::Gen9(p) if p.is_lp() => None,
            GtPlatform::Gen9(_) => Some(Self::Gen9),
            GtPlatform::Gen11(_) => Some(Self::Gen11),
            _ => None,
        }
    }
}

// ── Private PPAT (`setup_private_pat`) ──────────────────────────────

/// `GEN8_PRIVATE_PAT_LO`; `_HI` is +4. Gen11's `GEN10_PAT_INDEX(i)` are the
/// same registers addressed per entry (0x40e0 + 4i).
const GEN8_PRIVATE_PAT_LO: u64 = 0x40e0;

const PPAT_UC: u8 = 0;
const PPAT_WC: u8 = 1;
const PPAT_WB: u8 = 3;
/// `GEN8_PPAT_ELLC_OVERRIDE` is the zero target-cache field.
const PPAT_ELLC_OVERRIDE: u8 = 0;
const PPAT_LLC: u8 = 1 << 2;
const PPAT_LLCELLC: u8 = 2 << 2;
const fn ppat_age(age: u8) -> u8 {
    age << 4
}

/// The eight private PPAT entries, index order, the same on both: Gen9
/// big-core is `bdw_setup_private_ppat` (entry 2 the graphics-9 eLLC
/// scanout entry, not the pre-9 WT one), Gen11 `icl_setup_private_ppat`.
/// Only the register layout differs ([`ppat_writes`]).
pub(crate) const PPAT_ENTRIES: [u8; 8] = [
    PPAT_WB | PPAT_LLC,
    PPAT_WC | PPAT_LLCELLC,
    PPAT_WB | PPAT_ELLC_OVERRIDE,
    PPAT_UC,
    PPAT_WB | PPAT_LLCELLC | ppat_age(0),
    PPAT_WB | PPAT_LLCELLC | ppat_age(1),
    PPAT_WB | PPAT_LLCELLC | ppat_age(2),
    PPAT_WB | PPAT_LLCELLC | ppat_age(3),
];

/// The PPAT register writes in Linux's order: Gen9 the 64-bit
/// `GEN8_PPAT(i, x)` pair (LO then HI), Gen11 `GEN10_PAT_INDEX(0..8)`.
pub(crate) fn ppat_writes(gt: LegacyGt) -> alloc::vec::Vec<(u64, u32)> {
    let entries = PPAT_ENTRIES;
    match gt {
        LegacyGt::Gen9 => {
            let pat = entries
                .iter()
                .enumerate()
                .fold(0u64, |pat, (i, &x)| pat | (u64::from(x) << (i * 8)));
            alloc::vec![
                (GEN8_PRIVATE_PAT_LO, pat as u32),
                (GEN8_PRIVATE_PAT_LO + 4, (pat >> 32) as u32),
            ]
        }
        LegacyGt::Gen11 => entries
            .iter()
            .enumerate()
            .map(|(i, &x)| (GEN8_PRIVATE_PAT_LO + 4 * i as u64, u32::from(x)))
            .collect(),
    }
}

// ── MOCS (`intel_mocs_init_engine`) ─────────────────────────────────

/// `GEN9_NUM_MOCS_ENTRIES`: entries 63-64 are reserved but configured.
pub(crate) const MOCS_ENTRIES: usize = 64;

const fn le_cacheability(v: u32) -> u32 {
    v
}
const fn le_tgt_cache(v: u32) -> u32 {
    v << 2
}
const fn le_lrum(v: u32) -> u32 {
    v << 4
}
const fn le_aom(v: u32) -> u32 {
    v << 6
}
const fn le_rsc(v: u32) -> u32 {
    v << 7
}
const fn le_scc(v: u32) -> u32 {
    v << 8
}
const fn le_scf(v: u32) -> u32 {
    v << 14
}
const fn le_sse(v: u32) -> u32 {
    v << 17
}
const LE_0_PAGETABLE: u32 = le_cacheability(0);
const LE_1_UC: u32 = le_cacheability(1);
const LE_3_WB: u32 = le_cacheability(3);
const LE_TC_0_PAGETABLE: u32 = le_tgt_cache(0);
const LE_TC_1_LLC: u32 = le_tgt_cache(1);
const LE_TC_2_LLC_ELLC: u32 = le_tgt_cache(2);
const L3_1_UC: u16 = 1 << 4;
const L3_3_WB: u16 = 3 << 4;

/// One `MOCS_ENTRY(index, control, l3cc)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct MocsEntry {
    index: u8,
    control: u32,
    l3cc: u16,
}

const fn entry(index: u8, control: u32, l3cc: u16) -> MocsEntry {
    MocsEntry {
        index,
        control,
        l3cc,
    }
}

/// `skl_mocs_table`: `GEN9_MOCS_ENTRIES` (uncached, PTE), cached, and 63
/// (the L3's eviction / forced-uncacheable entry).
const SKL_MOCS: [MocsEntry; 4] = [
    entry(0, LE_1_UC | LE_TC_2_LLC_ELLC, L3_1_UC),
    entry(1, LE_0_PAGETABLE | LE_TC_0_PAGETABLE | le_lrum(3), L3_3_WB),
    entry(2, LE_3_WB | LE_TC_2_LLC_ELLC | le_lrum(3), L3_3_WB),
    entry(63, LE_3_WB | LE_TC_1_LLC | le_lrum(3), L3_1_UC),
];

/// `icl_mocs_table`: per-platform 0/1, then `GEN11_MOCS_ENTRIES`.
const ICL_MOCS: [MocsEntry; 26] = [
    entry(0, LE_1_UC | LE_TC_1_LLC, L3_1_UC),
    entry(1, LE_0_PAGETABLE | LE_TC_0_PAGETABLE, L3_3_WB),
    entry(2, LE_3_WB | LE_TC_1_LLC | le_lrum(3), L3_3_WB),
    entry(3, LE_1_UC | LE_TC_1_LLC, L3_1_UC),
    entry(4, LE_1_UC | LE_TC_1_LLC, L3_3_WB),
    entry(5, LE_3_WB | LE_TC_1_LLC | le_lrum(3), L3_1_UC),
    entry(6, LE_3_WB | LE_TC_1_LLC | le_lrum(1), L3_1_UC),
    entry(7, LE_3_WB | LE_TC_1_LLC | le_lrum(1), L3_3_WB),
    entry(8, LE_3_WB | LE_TC_1_LLC | le_lrum(2), L3_1_UC),
    entry(9, LE_3_WB | LE_TC_1_LLC | le_lrum(2), L3_3_WB),
    entry(10, LE_3_WB | LE_TC_1_LLC | le_lrum(3) | le_aom(1), L3_1_UC),
    entry(11, LE_3_WB | LE_TC_1_LLC | le_lrum(3) | le_aom(1), L3_3_WB),
    entry(12, LE_3_WB | LE_TC_1_LLC | le_lrum(1) | le_aom(1), L3_1_UC),
    entry(13, LE_3_WB | LE_TC_1_LLC | le_lrum(1) | le_aom(1), L3_3_WB),
    entry(14, LE_3_WB | LE_TC_1_LLC | le_lrum(2) | le_aom(1), L3_1_UC),
    entry(15, LE_3_WB | LE_TC_1_LLC | le_lrum(2) | le_aom(1), L3_3_WB),
    entry(16, LE_1_UC | LE_TC_1_LLC | le_scf(1), L3_1_UC),
    entry(17, LE_1_UC | LE_TC_1_LLC | le_scf(1), L3_3_WB),
    entry(18, LE_3_WB | LE_TC_1_LLC | le_lrum(3) | le_sse(3), L3_3_WB),
    entry(19, LE_3_WB | LE_TC_1_LLC | le_lrum(3) | le_scc(7), L3_3_WB),
    entry(20, LE_3_WB | LE_TC_1_LLC | le_lrum(3) | le_scc(3), L3_3_WB),
    entry(21, LE_3_WB | LE_TC_1_LLC | le_lrum(3) | le_scc(1), L3_3_WB),
    entry(
        22,
        LE_3_WB | LE_TC_1_LLC | le_lrum(3) | le_rsc(1) | le_scc(3),
        L3_3_WB,
    ),
    entry(
        23,
        LE_3_WB | LE_TC_1_LLC | le_lrum(3) | le_rsc(1) | le_scc(7),
        L3_3_WB,
    ),
    entry(62, LE_3_WB | LE_TC_1_LLC | le_lrum(3), L3_1_UC),
    entry(63, LE_3_WB | LE_TC_1_LLC | le_lrum(3), L3_1_UC),
];

const fn table(gt: LegacyGt) -> &'static [MocsEntry] {
    match gt {
        LegacyGt::Gen9 => &SKL_MOCS,
        LegacyGt::Gen11 => &ICL_MOCS,
    }
}

/// `get_mocs_settings`' `unused_entries_index`: `I915_MOCS_PTE` (1) on
/// both, the default neither table overrides.
const UNUSED_ENTRIES_INDEX: u8 = 1;

const fn lookup(gt: LegacyGt, index: u8) -> MocsEntry {
    let t = table(gt);
    let mut i = 0;
    let mut unused = t[0];
    while i < t.len() {
        if t[i].index == index {
            return t[i];
        }
        if t[i].index == UNUSED_ENTRIES_INDEX {
            unused = t[i];
        }
        i += 1;
    }
    unused
}

/// `get_entry_control`: the entry's control value, or the unused-entries
/// index's for an undefined one.
pub(crate) const fn mocs_control(gt: LegacyGt, index: u8) -> u32 {
    lookup(gt, index).control
}

/// `get_entry_l3cc`, likewise.
pub(crate) const fn mocs_l3cc(gt: LegacyGt, index: u8) -> u16 {
    lookup(gt, index).l3cc
}

/// The engine's MOCS bank (`mocs_offset`): `__GEN9_RCS0_MOCS0` and its
/// siblings, `__GEN11_VCS2_MOCS0` for the third video engine. `None` for an
/// engine these generations do not have.
pub(crate) const fn mocs_bank(engine: Engine) -> Option<u64> {
    match engine {
        Engine::Rcs0 => Some(0xc800),
        Engine::Vcs0 => Some(0xc900),
        Engine::Vcs1 => Some(0xca00),
        Engine::Vecs0 => Some(0xcb00),
        Engine::Bcs0 => Some(0xcc00),
        Engine::Vcs2 => Some(0x1_0000),
        _ => None,
    }
}

/// `init_mocs_table` for `engine`: all 64 control values, index order.
pub(crate) fn engine_mocs_writes(
    gt: LegacyGt,
    engine: Engine,
) -> Option<[(u64, u32); MOCS_ENTRIES]> {
    let base = mocs_bank(engine)?;
    Some(core::array::from_fn(|i| {
        (base + 4 * i as u64, mocs_control(gt, i as u8))
    }))
}

/// `GEN9_LNCFCMOCS(i)`: the render L3 control table, two 16-bit entries
/// per register.
const LNCFCMOCS: u64 = 0xb020;

/// `init_l3cc_table` (`HAS_RENDER_L3CC`, render engine only): 32 registers,
/// entry 2i in the low half and 2i + 1 in the high half.
pub(crate) fn l3cc_writes(gt: LegacyGt) -> [(u64, u32); MOCS_ENTRIES / 2] {
    core::array::from_fn(|i| {
        let low = u32::from(mocs_l3cc(gt, (2 * i) as u8));
        let high = u32::from(mocs_l3cc(gt, (2 * i + 1) as u8));
        (LNCFCMOCS + 4 * i as u64, low | high << 16)
    })
}

/// `WaDisableSkipCaching:skl,bxt,kbl,glk`: no Gen9 L3 entry may set the
/// skip-caching or eviction-control bits (`L3_ESC(1) | L3_SCC(0x7)`);
/// Linux refuses the whole table otherwise.
pub(crate) const fn skip_caching_clear(gt: LegacyGt) -> bool {
    let t = table(gt);
    let mut i = 0;
    while i < t.len() {
        if matches!(gt, LegacyGt::Gen9) && t[i].l3cc & 0xf != 0 {
            return false;
        }
        i += 1;
    }
    true
}

// get_mocs_settings refuses a Gen9 table that sets these bits; ours never does.
const _: () = assert!(skip_caching_clear(LegacyGt::Gen9));

// ── Workarounds (`intel_workarounds.c`) ─────────────────────────────

/// The sub-platform split Linux's workaround dispatch keys on. `IS_COFFEELAKE`
/// covers Whiskey Lake and Amber Lake's Coffee Lake IDs, `IS_KABYLAKE` Amber
/// Lake's Kaby Lake IDs; the PCI table's codenames follow the same grouping.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Gen9Kind {
    Skylake,
    KabyLake,
    CoffeeLake,
    CometLake,
}

/// The workaround identity of one GT: generation, sub-platform and the
/// PCI revision Linux maps to a graphics stepping.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum WaPlatform {
    Gen9 {
        kind: Gen9Kind,
        revision: u8,
    },
    /// `jsl_ehl` is Elkhart or Jasper Lake (one stepping table).
    Gen11 {
        jsl_ehl: bool,
        revision: u8,
    },
}

impl WaPlatform {
    pub(crate) fn for_device(device: u16, revision: u8) -> Option<Self> {
        let entry = crate::intel_gpu::DEVICE_TABLE
            .iter()
            .find(|entry| entry.did == device)?;
        let kind = match entry.asic {
            "skylake" => Gen9Kind::Skylake,
            "kabylake" => Gen9Kind::KabyLake,
            "coffeelake" | "whiskeylake" => Gen9Kind::CoffeeLake,
            "cometlake" => Gen9Kind::CometLake,
            "icelake" => {
                return Some(Self::Gen11 {
                    jsl_ehl: false,
                    revision,
                })
            }
            "elkhartlake" | "jasperlake" => {
                return Some(Self::Gen11 {
                    jsl_ehl: true,
                    revision,
                })
            }
            _ => return None,
        };
        Some(Self::Gen9 { kind, revision })
    }

    pub(crate) const fn gt(self) -> LegacyGt {
        match self {
            Self::Gen9 { .. } => LegacyGt::Gen9,
            Self::Gen11 { .. } => LegacyGt::Gen11,
        }
    }

    /// `IS_SKYLAKE && IS_GRAPHICS_STEP(A0, H0)`: `skl_revids` puts H0 at 7.
    const fn skl_before_h0(self) -> bool {
        matches!(self, Self::Gen9 { kind: Gen9Kind::Skylake, revision } if revision < 7)
    }

    /// `IS_KABYLAKE` with a stepping below C0: `kbl_revids` 0 and 1 (A0,
    /// B0); every later entry, including revision 5's second C0, is C0+.
    const fn kbl_before_c0(self) -> bool {
        matches!(self, Self::Gen9 { kind: Gen9Kind::KabyLake, revision } if revision < 2)
    }

    /// `IS_COFFEELAKE || IS_COMETLAKE`.
    const fn cfl_or_cml(self) -> bool {
        matches!(
            self,
            Self::Gen9 {
                kind: Gen9Kind::CoffeeLake | Gen9Kind::CometLake,
                ..
            }
        )
    }
}

/// One `struct i915_wa`: `clear` is the RMW's cleared bits (zero for a masked
/// or blind write), `read` the bits verification compares.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Wa {
    pub(crate) reg: u64,
    pub(crate) clear: u32,
    pub(crate) set: u32,
    pub(crate) read: u32,
    pub(crate) masked: bool,
}

const fn masked_enable(bits: u32) -> u32 {
    bits << 16 | bits
}

/// A workaround list with `_wa_add`'s semantics: kept sorted by register,
/// and a second entry for a register merges into the first. Its set, clear
/// and read bits are ORed in; only when its clear bits all fall inside the
/// earlier ones (Linux's "Discarding overwritten w/a") do they first drop
/// the earlier set bits.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct WaList(alloc::vec::Vec<Wa>);

impl WaList {
    fn add(&mut self, reg: u64, clear: u32, set: u32, read: u32, masked: bool) {
        match self.0.binary_search_by_key(&reg, |wa| wa.reg) {
            Ok(i) => {
                let wa = &mut self.0[i];
                if (clear | wa.clear) != 0 && clear & !wa.clear == 0 {
                    wa.set &= !clear;
                }
                wa.set |= set;
                wa.clear |= clear;
                wa.read |= read;
            }
            Err(i) => self.0.insert(
                i,
                Wa {
                    reg,
                    clear,
                    set,
                    read,
                    masked,
                },
            ),
        }
    }
    /// `wa_write_clr_set`.
    fn clear_set(&mut self, reg: u64, clear: u32, set: u32) {
        self.add(reg, clear, set, clear | set, false);
    }
    /// `wa_write_or`.
    fn or(&mut self, reg: u64, set: u32) {
        self.clear_set(reg, set, set);
    }
    /// `wa_write`: a blind full-register write.
    fn write(&mut self, reg: u64, set: u32) {
        self.clear_set(reg, !0, set);
    }
    /// `wa_masked_en`.
    fn masked_en(&mut self, reg: u64, bits: u32) {
        self.add(reg, 0, masked_enable(bits), bits, true);
    }
    /// `wa_masked_dis`.
    fn masked_dis(&mut self, reg: u64, bits: u32) {
        self.add(reg, 0, bits << 16, bits, true);
    }
    /// `wa_masked_field_set`.
    fn masked_field(&mut self, reg: u64, mask: u32, value: u32) {
        self.add(reg, 0, mask << 16 | value, mask, true);
    }

    #[cfg(any(test, feature = "kernel-test"))]
    pub(crate) fn entries(&self) -> &[Wa] {
        &self.0
    }

    /// `wa_list_apply`: an RMW reads first only when it clears bits, and
    /// skips the write when the value already matches. `read` performs the
    /// (possibly steered) read for a register.
    pub(crate) fn apply(&self, mut read: impl FnMut(u64) -> u32, mut write: impl FnMut(u64, u32)) {
        for wa in &self.0 {
            let old = if wa.clear != 0 { read(wa.reg) } else { 0 };
            let value = (old & !wa.clear) | wa.set;
            if value != old || wa.clear == 0 {
                write(wa.reg, value);
            }
        }
    }

    /// `wa_list_verify`: the first entry whose `read` bits did not stick.
    pub(crate) fn verify(&self, mut read: impl FnMut(u64) -> u32) -> Result<(), u64> {
        for wa in self.0.iter().filter(|wa| wa.read != 0) {
            if (read(wa.reg) ^ wa.set) & wa.read != 0 {
                return Err(wa.reg);
            }
        }
        Ok(())
    }

    /// `intel_engine_emit_ctx_wa`'s `MI_LOAD_REGISTER_IMM` body: masked
    /// and full-register entries load their set value; nothing in the
    /// Gen9/Gen11 context lists needs the RMW read the general form allows.
    pub(crate) fn load_register_imm(&self) -> alloc::vec::Vec<u32> {
        let mut words = alloc::vec::Vec::with_capacity(2 + 2 * self.0.len());
        if self.0.is_empty() {
            return words;
        }
        // MI_LOAD_REGISTER_IMM(n): opcode 0x22, length 2n - 1.
        words.push(0x2200_0000 | (2 * self.0.len() as u32 - 1));
        for wa in &self.0 {
            debug_assert!(wa.masked || wa.clear | wa.set == !0);
            words.push(wa.reg as u32);
            words.push(wa.set);
        }
        words.push(0); // MI_NOOP
        words
    }
}

/// The steering `gen9_wa_init_mcr` / `icl_wa_init_mcr` program: the lowest
/// enabled slice and subslice, read from the fuses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Steering {
    pub(crate) slice: u32,
    pub(crate) subslice: u32,
    /// Gen11 `l3bank_mask` (`~MIRROR_FUSE3 & L3BANK_MASK`); zero on Gen9.
    pub(crate) l3_banks: u32,
    /// Gen9 `skl_tune_iz_hashing` values per slice (3 - the one 7-EU
    /// subslice), zero where a slice has no single 7-EU subslice.
    pub(crate) iz_hashing: [u8; 3],
}

const GEN8_FUSE2: u64 = 0x9120;
const GEN9_EU_DISABLE: u64 = 0x9134;
const GEN10_MIRROR_FUSE3: u64 = 0x9118;
const GEN11_GT_SLICE_ENABLE: u64 = 0x9138;
const GEN11_GT_SUBSLICE_DISABLE: u64 = 0x913c;

impl Steering {
    /// `gen9_sseu_info_init` (big-core: three slices of four subslices) or
    /// `gen11_sseu_info_init` (one slice, eight subslices on Ice Lake, four
    /// on Elkhart/Jasper Lake). `None` when no slice or subslice is on.
    pub(crate) fn read(platform: WaPlatform, mut read: impl FnMut(u64) -> u32) -> Option<Self> {
        match platform {
            WaPlatform::Gen9 { .. } => {
                let fuse2 = read(GEN8_FUSE2);
                let slices = (fuse2 >> 25) & 0x7;
                let subslices = 0xf & !((fuse2 >> 20) & 0xf);
                if slices == 0 || subslices == 0 {
                    return None;
                }
                let mut iz_hashing = [0; 3];
                for (s, value) in iz_hashing.iter_mut().enumerate() {
                    if slices & 1 << s == 0 {
                        continue;
                    }
                    let disable = read(GEN9_EU_DISABLE + 4 * s as u64);
                    let seven = (0..4)
                        .filter(|ss| subslices & 1 << ss != 0)
                        .filter(|ss| 8 - ((disable >> (ss * 8)) & 0xff).count_ones() == 7)
                        .fold(0u32, |mask, ss| mask | 1 << ss);
                    if seven.is_power_of_two() {
                        *value = 3 - seven.trailing_zeros() as u8;
                    }
                }
                Some(Self {
                    slice: slices.trailing_zeros(),
                    subslice: subslices.trailing_zeros(),
                    l3_banks: 0,
                    iz_hashing,
                })
            }
            WaPlatform::Gen11 { jsl_ehl, .. } => {
                if read(GEN11_GT_SLICE_ENABLE) & 0xff & 1 == 0 {
                    return None;
                }
                let valid = if jsl_ehl { 0xf } else { 0xff };
                let subslices = !read(GEN11_GT_SUBSLICE_DISABLE) & valid;
                if subslices == 0 {
                    return None;
                }
                Some(Self {
                    slice: 0,
                    subslice: subslices.trailing_zeros(),
                    l3_banks: !read(GEN10_MIRROR_FUSE3) & 0xf,
                    iz_hashing: [0; 3],
                })
            }
        }
    }

    /// The `GEN8_MCR_SELECTOR` value an ICL read of an L3BANK register
    /// (`icl_l3bank_steering_table`, 0xb100..=0xb3ff) needs, when the default
    /// subslice steering does not already land on a live bank
    /// (`get_nonterminated_steering`: group 0, the lowest live bank).
    pub(crate) fn l3bank_read_selector(self, reg: u64) -> Option<u32> {
        if self.l3_banks == 0
            || !(0xb100..=0xb3ff).contains(&reg)
            || self.l3_banks & 1 << self.subslice != 0
        {
            return None;
        }
        Some(gen11_mcr(0, self.l3_banks.trailing_zeros()))
    }
}

/// `GEN8_MCR_SELECTOR`.
pub(crate) const MCR_SELECTOR: u64 = 0xfdc;

const fn gen11_mcr(slice: u32, subslice: u32) -> u32 {
    (slice & 0xf) << 27 | (subslice & 0x7) << 24
}

/// `gt_init_workarounds` for these generations.
pub(crate) fn gt_workarounds(platform: WaPlatform, steering: Steering) -> WaList {
    let mut w = WaList::default();
    match platform {
        WaPlatform::Gen9 { .. } => {
            // WaProgramMgsrForCorrectSliceSpecificMmioReads (GEN8_MCR_* fields).
            w.clear_set(
                MCR_SELECTOR,
                3 << 26 | 3 << 24,
                (steering.slice & 3) << 26 | (steering.subslice & 3) << 24,
            );
            // WaDisableKillLogic:bxt,skl,kbl (GAM_ECOCHK ECOCHK_DIS_TLB).
            if !platform.cfl_or_cml() {
                w.or(0x4090, 1 << 8);
            }
            // WaCompressedResourceSamplerPbeMediaNewHashMode (HAS_LLC):
            // MMCD_MISC_CTRL MMCD_PCLA | MMCD_HOTSPOT_EN.
            w.or(0x4ddc, 1 << 31 | 1 << 27);
            // WaDisableHDCInvalidation (BDW_DISABLE_HDC_INVALIDATION).
            w.or(0x4090, 1 << 25);
            // WaDisableDynamicCreditSharing:kbl (GAMT_CHKN_BIT_REG).
            if platform.kbl_before_c0() {
                w.or(0x4ab8, 1 << 28);
            }
            // WaDisableGafsUnitClkGating (GEN7_UCGCTL4).
            w.or(0x940c, 1 << 14);
            // WaInPlaceDecompressionHang (GEN9_GAMT_ECO_REG_RW_IA): every
            // KBL/CFL/CML, Skylake only before H0.
            if !matches!(
                platform,
                WaPlatform::Gen9 {
                    kind: Gen9Kind::Skylake,
                    ..
                }
            ) || platform.skl_before_h0()
            {
                w.or(0x4ab0, 1 << 18);
            }
        }
        WaPlatform::Gen11 { jsl_ehl, revision } => {
            w.clear_set(
                MCR_SELECTOR,
                gen11_mcr(0xf, 0x7),
                gen11_mcr(0, steering.subslice),
            );
            // WaModifyGamTlbPartitioning: GEN11_GACB_PERF_CTRL hash control.
            w.clear_set(0x4b80, 0x3 << 12 | 0xf, 1 | 1 << 12);
            // Wa_1405766107: GEN11_LSN_UNSLCVC half SF / CL2 max alloc.
            w.or(0xb43c, 1 << 7 | 1 << 9);
            // Wa_220166154: GAMW_ECO_DEV_CTX_RELOAD_DISABLE.
            w.or(0x4080, 1 << 7);
            // Wa_1406463099: GAMT_CHKN_DISABLE_L3_COH_PIPE.
            w.or(0x4ab8, 1 << 31);
            // Wa_1408615072 / Wa_1407596294: VSUNIT / HSUNIT clock gating.
            w.or(0x9434, 1 << 3 | 1 << 8);
            // Wa_1407352427: PSDUNIT clock gating.
            w.or(0x94e4, 1 << 5);
            // Wa_1406680159: GWUNIT clock gating.
            w.or(0x9524, 1 << 16);
            // Wa_1607087056: Ice Lake always, EHL/JSL before B0 (revision 0).
            if !jsl_ehl || revision == 0 {
                w.or(0x94d4, 1 << 16 | 1 << 17);
            }
            // Sampler power: GEN10_DFR_RATIO_EN_AND_CHICKEN clears DFR_DISABLE.
            w.clear_set(0x9550, 1 << 9, 0);
        }
    }
    w
}

/// `__intel_engine_init_ctx_wa` for the render engine. Emitted once into
/// each new context as an `MI_LOAD_REGISTER_IMM` (Linux records it into the
/// default context image every user context is cloned from).
pub(crate) fn ctx_workarounds(platform: WaPlatform, steering: Steering) -> WaList {
    let mut w = WaList::default();
    match platform {
        WaPlatform::Gen9 { kind, .. } => {
            // HAS_LLC: PBE / sampler compressed hash selection.
            w.masked_en(0x7014, 1 << 13);
            w.masked_en(0xe194, 1 << 8);
            // WaClearFlowControlGpgpuContextSave, WaDisablePartialInstShootdown.
            w.masked_en(0xe4f0, 1 << 15 | 1 << 8);
            // WaEnableYV12BugFixInHalfSliceChicken7,
            // WaEnableSamplerGPGPUPreemptionSupport.
            w.masked_en(0xe194, 1 << 4 | 1 << 2);
            // Wa4x4STCOptimizationDisable, WaDisablePartialResolveInVc.
            w.masked_en(0x7004, 1 << 6 | 1 << 1);
            // WaCcsTlbPrefetchDisable.
            w.masked_dis(0xe188, 1 << 3);
            // WaForceContextSaveRestoreNonCoherent, WaForceEnableNonCoherent.
            w.masked_en(0x7300, 1 << 5 | 1 << 15);
            w.masked_en(0x7300, 1 << 4);
            // WaDisableSamplerPowerBypassForSOPingPong (every Gen9 big core).
            w.masked_en(0xe184, 1 << 1);
            // WaDisableSTUnitPowerOptimization.
            w.masked_en(0xe180, 1 << 13);
            // WaDisable3DMidCmdPreemption, WaDisableGPGPUMidCmdPreemption:
            // GEN8_CS_CHICKEN1 3D object level off, GPGPU command level.
            w.masked_dis(0x2580, 1);
            w.masked_field(0x2580, 0x6, 0x4);
            match kind {
                Gen9Kind::Skylake => {
                    // skl_tune_iz_hashing: GEN7_GT_MODE.
                    let [a, b, c] = steering.iz_hashing;
                    if a | b | c != 0 {
                        w.masked_field(
                            0x7008,
                            0x3f,
                            u32::from(c) << 4 | u32::from(b) << 2 | u32::from(a),
                        );
                    }
                }
                Gen9Kind::KabyLake | Gen9Kind::CoffeeLake | Gen9Kind::CometLake => {
                    // WaToEnableHwFixForPushConstHWBug: KBL from C0, CFL/CML.
                    if !platform.kbl_before_c0() {
                        w.masked_en(0x7014, 1 << 8);
                    }
                    // WaDisableSbeCacheDispatchPortSharing.
                    w.masked_en(0xe100, 1 << 4);
                }
            }
        }
        WaPlatform::Gen11 { .. } => {
            // Wa_1406697149: GEN8_L3CNTLREG ERRDETBCTRL, a full write.
            w.write(0x7034, 1 << 9);
            // WaForceEnableNonCoherent: ICL_HDC_MODE.
            w.masked_en(0xe5f4, 1 << 4);
            // WaEnableFloatBlendOptimization: write-only, never verified.
            w.add(0xe420, 0, masked_enable(1 << 4), 0, true);
            // WaDisableGPGPUMidThreadPreemption: thread-group level.
            w.masked_field(0x2580, 0x6, 0x2);
            // Headerless messages for preemptible GPGPU contexts.
            w.masked_en(0xe18c, 1 << 5);
            // Wa_1604278689: IVB_FBC_RT_BASE(_UPPER).
            w.write(0x7020, !1);
            w.clear_set(0x7024, 0, !0);
            // Wa_1406306137: GEN9_ROW_CHICKEN4 GEN11_DIS_PICK_2ND_EU.
            w.masked_en(0xe48c, 1 << 7);
        }
    }
    w
}

/// `engine_init_workarounds` for RCS0: `general_render_compute_wa_init`
/// (the first render engine) and `rcs_engine_wa_init`.
pub(crate) fn rcs_workarounds(platform: WaPlatform) -> WaList {
    let mut w = WaList::default();
    match platform {
        WaPlatform::Gen11 { .. } => {
            // WaSetInidrectStateOverride: GEN10_SAMPLER_MODE.
            w.masked_en(0xe18c, 1 << 0);
            // _3D_CHICKEN3 AA line quality.
            w.masked_en(0x2090, 1 << 5);
            // GEN8_GARBCNTL arbitration priority order, then hash exclusion.
            w.or(0xb004, 0x3f << 22);
            w.clear_set(0xb004, 0x7f, 1);
            // GEN11_GLBLINVL bank hash address exclusion.
            w.clear_set(0xb404, 0x7f << 5, 1 << 5);
            // GEN8_L3SQCREG4 GEN11_LQSC_CLEAN_EVICT_DISABLE.
            w.or(0xb118, 1 << 6);
            // Wa_1606682166: GEN7_SARCHKMD sampler prefetch off.
            w.or(0xb000, 1 << 30);
            // Wa_1409178092: GEN11_SCRATCH2 partial-write merge off.
            w.clear_set(0xb140, 1 << 19, 0);
            // WaEnable32PlaneMode: GEN9_CSFE_CHICKEN1_RCS.
            w.masked_en(0x20d4, 1 << 7);
            // GEN7_FF_THREAD_MODE tessellation DOP gate.
            w.or(0x20a0, 1 << 19);
            // Wa_22010271021: GEN9_CS_DEBUG_MODE1 FF DOP clock gating.
            w.masked_en(0x20ec, 1 << 1);
        }
        WaPlatform::Gen9 { .. } => {
            // WaEnableGapsTsvCreditFix (GEN8_GARBCNTL).
            w.or(0xb004, 1 << 7);
            // WaContextSwitchWithConcurrentTLBInvalidate.
            w.masked_en(0x20d4, 1 << 2);
            // WaEnableLbsSlaRetryTimerDecrement (BDW_SCRATCH1).
            w.or(0xb11c, 1 << 2);
            // WaOCLCoherentLineFlush (GEN8_L3SQCREG4).
            w.or(0xb118, 1 << 21);
            // L3 atomics off: GEN9_SCRATCH_LNCF1, L3SQCREG4, GEN9_SCRATCH1
            // (the same register as BDW_SCRATCH1, so the entries merge).
            w.clear_set(0xb008, 1 << 0, 0);
            w.clear_set(0xb118, 1 << 22, 0);
            w.clear_set(0xb11c, 1 << 8, 0);
        }
    }
    // GRAPHICS_VER >= 9: GEN7_FF_SLICE_CS_CHICKEN1 per-context preemption.
    w.masked_en(0x20e0, 1 << 14);
    w
}

/// `RING_MAX_NONPRIV_SLOTS`.
pub(crate) const NONPRIV_SLOTS: usize = 12;
const NONPRIV_RD: u32 = 1 << 28;
const NONPRIV_RANGE_4: u32 = 1 << 0;

/// `intel_engine_init_whitelist` for RCS0, in `_wa_add`'s sorted order
/// (the access flags are part of the sort key).
pub(crate) fn rcs_whitelist(platform: WaPlatform) -> alloc::vec::Vec<u32> {
    let mut regs = match platform {
        WaPlatform::Gen9 { kind, .. } => {
            // gen9_whitelist_build: CTX_PREEMPT, CS_CHICKEN1, HDC_CHICKEN1,
            // COMMON_SLICE_CHICKEN2.
            let mut regs = alloc::vec![0x2248, 0x2580, 0x7304, 0x7014];
            match kind {
                // WaDisableLSQCROPERFforOCL (GEN8_L3SQCREG4).
                Gen9Kind::Skylake | Gen9Kind::KabyLake => regs.push(0xb118),
                // cfl/cml_whitelist_build: PS_INVOCATION_COUNT, RD, RANGE_4.
                Gen9Kind::CoffeeLake | Gen9Kind::CometLake => {
                    regs.push(0x2348 | NONPRIV_RD | NONPRIV_RANGE_4)
                }
            }
            regs
        }
        // icl_whitelist_build RENDER_CLASS: HALF_SLICE_CHICKEN7, SAMPLER_MODE,
        // SLICE_COMMON_ECO_CHICKEN1, PS_INVOCATION_COUNT.
        WaPlatform::Gen11 { .. } => alloc::vec![
            0xe194,
            0xe18c,
            0x731c,
            0x2348 | NONPRIV_RD | NONPRIV_RANGE_4
        ],
    };
    regs.sort_unstable();
    regs
}

/// `intel_engine_apply_whitelist`: each slot of the engine at `base` takes
/// a whitelisted register, the rest `RING_NOPID`.
pub(crate) fn whitelist_writes(base: u64, regs: &[u32]) -> [(u64, u32); NONPRIV_SLOTS] {
    core::array::from_fn(|i| {
        let value = regs.get(i).copied().unwrap_or(base as u32 + 0x94);
        (base + 0x4d0 + 4 * i as u64, value)
    })
}

/// `gtt_write_workarounds` and the GTT cache policy, in Linux's order.
pub(crate) fn gtt_workarounds(gt: LegacyGt) -> WaList {
    let mut w = WaList::default();
    // WaIncreaseDefaultTLBEntries: GEN8_L3_LRA_1_GPGPU, graphics 9..=11.
    w.write(0x4dd4, 0x67f1_427f);
    if gt == LegacyGt::Gen9 {
        // 64K pages (graphics <= 10): GAMW_ECO_ENABLE_64K_IPS_FIELD.
        w.or(0x4080, 0xf);
    }
    // WaGttCachingOffByDefault: HSW_GTT_CACHE_EN, off where 2M pages exist.
    w.write(0x4024, if gt == LegacyGt::Gen9 { 0xf000_7fff } else { 0 });
    w
}

// ── Topology (`gen9_sseu_info_init` / `gen11_sseu_info_init`) ──────

/// The slice / subslice / EU layout i915 records for these generations and
/// reports through `DRM_I915_QUERY_TOPOLOGY_INFO` and the SSEU GETPARAMs.
/// Gen9 big core is three slices of four subslices of eight EUs, each slice
/// with its own EU fuses; Gen11 one slice of eight (Ice Lake) or four
/// (Elkhart/Jasper Lake) subslices sharing one EU fuse byte.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LegacyTopology {
    max_slices: u8,
    max_subslices: u8,
    slices: u8,
    /// Enabled subslices of each slice.
    subslices: [u8; 3],
    /// Enabled EUs of each (slice, subslice).
    eus: [[u8; 8]; 3],
}

impl LegacyTopology {
    pub(crate) fn read(platform: WaPlatform, mut read: impl FnMut(u64) -> u32) -> Option<Self> {
        let mut topology = Self {
            max_slices: 1,
            max_subslices: 8,
            slices: 0,
            subslices: [0; 3],
            eus: [[0; 8]; 3],
        };
        match platform {
            WaPlatform::Gen9 { .. } => {
                topology.max_slices = 3;
                topology.max_subslices = 4;
                let fuse2 = read(GEN8_FUSE2);
                topology.slices = ((fuse2 >> 25) & 0x7) as u8;
                let subslices = (0xf & !((fuse2 >> 20) & 0xf)) as u8;
                for s in 0..3 {
                    if topology.slices & 1 << s == 0 {
                        continue;
                    }
                    topology.subslices[s] = subslices;
                    let disable = read(GEN9_EU_DISABLE + 4 * s as u64);
                    for ss in 0..4 {
                        if subslices & 1 << ss != 0 {
                            topology.eus[s][ss] = !(disable >> (8 * ss)) as u8;
                        }
                    }
                }
            }
            WaPlatform::Gen11 { jsl_ehl, .. } => {
                topology.max_subslices = if jsl_ehl { 4 } else { 8 };
                // gen11_compute_sseu_info: slice 0 regardless of the
                // enable fuse, which i915 only warns about.
                topology.slices = 1;
                let valid = (1u32 << topology.max_subslices) - 1;
                let subslices = (!read(GEN11_GT_SUBSLICE_DISABLE) & valid) as u8;
                topology.subslices[0] = subslices;
                let eus = !(read(GEN9_EU_DISABLE) & 0xff) as u8;
                for ss in 0..usize::from(topology.max_subslices) {
                    if subslices & 1 << ss != 0 {
                        topology.eus[0][ss] = eus;
                    }
                }
            }
        }
        (topology.slices != 0 && topology.subslices.iter().any(|&m| m != 0)).then_some(topology)
    }

    /// `I915_PARAM_SLICE_MASK`.
    pub fn slice_mask(&self) -> u32 {
        u32::from(self.slices)
    }
    /// `I915_PARAM_SUBSLICE_MASK`: the first slice's subslices only.
    pub fn subslice_mask(&self) -> u32 {
        u32::from(self.subslices[0])
    }
    /// `I915_PARAM_SUBSLICE_TOTAL` (`intel_sseu_subslice_total`).
    pub fn subslice_total(&self) -> u32 {
        self.subslices.iter().map(|m| m.count_ones()).sum()
    }
    /// `I915_PARAM_EU_TOTAL` (`compute_eu_total`).
    pub fn eu_total(&self) -> u32 {
        self.eus.iter().flatten().map(|m| m.count_ones()).sum()
    }

    /// `fill_topology_info`: the 16-byte header, the slice mask byte, one
    /// subslice byte per slice and one EU byte per (slice, subslice).
    pub fn i915_bytes(&self) -> alloc::vec::Vec<u8> {
        let slices = usize::from(self.max_slices);
        let subslices = usize::from(self.max_subslices);
        let eu_offset = 1 + slices;
        let mut bytes = alloc::vec![0; 16 + eu_offset + slices * subslices];
        for (i, value) in [
            0u16,
            u16::from(self.max_slices),
            u16::from(self.max_subslices),
            8,
            1,
            1,
            eu_offset as u16,
            1,
        ]
        .into_iter()
        .enumerate()
        {
            bytes[i * 2..i * 2 + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[16] = self.slices;
        for s in 0..slices {
            bytes[17 + s] = self.subslices[s];
            for ss in 0..subslices {
                bytes[16 + eu_offset + s * subslices + ss] = self.eus[s][ss];
            }
        }
        bytes
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// The PPAT bytes and their register image, from the macros by hand:
    /// WB|LLC 0x07, WC|LLCELLC 0x09, WB|ELLC_OVERRIDE 0x03, UC 0x00, then
    /// WB|LLCELLC at ages 0..3: 0x0b, 0x1b, 0x2b, 0x3b.
    fn smoke_legacy_gt_ppat_follows_setup_private_pat() -> TestResult {
        let want = [0x07, 0x09, 0x03, 0x00, 0x0b, 0x1b, 0x2b, 0x3b];
        if PPAT_ENTRIES != want {
            return TestResult::Fail("PPAT entries must match bdw/icl_setup_private_ppat");
        }
        if ppat_writes(LegacyGt::Gen9) != alloc::vec![(0x40e0, 0x0003_0907), (0x40e4, 0x3b2b_1b0b)]
        {
            return TestResult::Fail("Gen9 PPAT is the GEN8_PRIVATE_PAT LO/HI pair");
        }
        let gen11 = ppat_writes(LegacyGt::Gen11);
        if gen11.len() != 8
            || gen11[0] != (0x40e0, 0x07)
            || gen11[3] != (0x40ec, 0x00)
            || gen11[7] != (0x40fc, 0x3b)
        {
            return TestResult::Fail("Gen11 PPAT is GEN10_PAT_INDEX(0..8)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_gt",
        smoke_legacy_gt_ppat_follows_setup_private_pat
    );

    /// MOCS control and L3CC values, expanded by hand: SKL 0 = UC|LLC_ELLC
    /// 0x09 (L3 UC 0x10), 1 = PTE|LRUM(3) 0x30 (L3 WB 0x30), 2 = WB|LLC_ELLC|
    /// LRUM(3) 0x3b, 63 = WB|LLC|LRUM(3) 0x37 (L3 UC); unused entries take
    /// the PTE entry. ICL 0 = UC|LLC 0x05, 1 = PTE 0x00, 18 = 0x37|SSE(3)
    /// 0x60037, 23 = 0x37|RSC|SCC(7) 0x7b7; unused take entry 1.
    fn smoke_legacy_gt_mocs_follows_skl_icl_tables() -> TestResult {
        let skl = LegacyGt::Gen9;
        if mocs_control(skl, 0) != 0x09
            || mocs_control(skl, 1) != 0x30
            || mocs_control(skl, 2) != 0x3b
            || mocs_control(skl, 63) != 0x37
            || mocs_control(skl, 40) != 0x30
            || mocs_l3cc(skl, 0) != 0x10
            || mocs_l3cc(skl, 63) != 0x10
            || mocs_l3cc(skl, 40) != 0x30
            || !skip_caching_clear(skl)
        {
            return TestResult::Fail("Gen9 MOCS must match skl_mocs_table");
        }
        let icl = LegacyGt::Gen11;
        if mocs_control(icl, 0) != 0x05
            || mocs_control(icl, 1) != 0x00
            || mocs_control(icl, 16) != 0x4005
            || mocs_control(icl, 18) != 0x6_0037
            || mocs_control(icl, 23) != 0x7b7
            || mocs_control(icl, 40) != 0x00
            || mocs_l3cc(icl, 4) != 0x30
            || mocs_l3cc(icl, 62) != 0x10
        {
            return TestResult::Fail("Gen11 MOCS must match icl_mocs_table");
        }
        let rcs = engine_mocs_writes(skl, Engine::Rcs0).unwrap();
        let bcs = engine_mocs_writes(icl, Engine::Bcs0).unwrap();
        if rcs[0] != (0xc800, 0x09)
            || rcs[63] != (0xc8fc, 0x37)
            || bcs[2] != (0xcc08, 0x37)
            || engine_mocs_writes(icl, Engine::Ccs0).is_some()
            || mocs_bank(Engine::Vcs2) != Some(0x1_0000)
        {
            return TestResult::Fail("each engine programs its own 64-entry bank");
        }
        let l3 = l3cc_writes(skl);
        if l3[0] != (0xb020, 0x0030_0010) || l3[31] != (0xb09c, 0x0010_0030) {
            return TestResult::Fail("LNCFCMOCS packs entry 2i low and 2i+1 high");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_gt",
        smoke_legacy_gt_mocs_follows_skl_icl_tables
    );

    fn wa(reg: u64, clear: u32, set: u32, read: u32, masked: bool) -> Wa {
        Wa {
            reg,
            clear,
            set,
            read,
            masked,
        }
    }
    fn gen9(kind: Gen9Kind, revision: u8) -> WaPlatform {
        WaPlatform::Gen9 { kind, revision }
    }
    const STEER: Steering = Steering {
        slice: 0,
        subslice: 1,
        l3_banks: 0,
        iz_hashing: [0; 3],
    };

    /// The PCI codename picks the Linux dispatch arm: Whiskey Lake rides
    /// Coffee Lake, Amber Lake's 0x591C Kaby Lake, EHL/JSL one stepping table.
    fn smoke_legacy_gt_platform_follows_linux_dispatch() -> TestResult {
        use crate::intel_gpu as ids;
        let rows = [
            (ids::SKL_1912, Some(gen9(Gen9Kind::Skylake, 6))),
            (ids::KBL_5916, Some(gen9(Gen9Kind::KabyLake, 6))),
            (ids::KBL_591C, Some(gen9(Gen9Kind::KabyLake, 6))),
            (ids::CFL_3E92, Some(gen9(Gen9Kind::CoffeeLake, 6))),
            (ids::WHL_3EA0, Some(gen9(Gen9Kind::CoffeeLake, 6))),
            (ids::CML_9BC4, Some(gen9(Gen9Kind::CometLake, 6))),
            (
                ids::ICL_8A52,
                Some(WaPlatform::Gen11 {
                    jsl_ehl: false,
                    revision: 6,
                }),
            ),
            (
                ids::JSL_4E71,
                Some(WaPlatform::Gen11 {
                    jsl_ehl: true,
                    revision: 6,
                }),
            ),
            (
                ids::EHL_4571,
                Some(WaPlatform::Gen11 {
                    jsl_ehl: true,
                    revision: 6,
                }),
            ),
            (0x9a49, None),
        ];
        for (device, want) in rows {
            if WaPlatform::for_device(device, 6) != want {
                return TestResult::Fail("device must map to Linux's workaround dispatch arm");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_gt",
        smoke_legacy_gt_platform_follows_linux_dispatch
    );

    /// gt_init_workarounds, hand-expanded: the MCR selector first (lowest
    /// address), GAM_ECOCHK's two ORs merged, the stepping gates.
    fn smoke_legacy_gt_gt_workarounds_follow_linux() -> TestResult {
        let skl = gt_workarounds(gen9(Gen9Kind::Skylake, 6), STEER);
        let want = [
            wa(0xfdc, 0x0f00_0000, 0x0100_0000, 0x0f00_0000, false),
            wa(0x4090, 0x0200_0100, 0x0200_0100, 0x0200_0100, false),
            wa(0x4ab0, 1 << 18, 1 << 18, 1 << 18, false),
            wa(0x4ddc, 0x8800_0000, 0x8800_0000, 0x8800_0000, false),
            wa(0x940c, 1 << 14, 1 << 14, 1 << 14, false),
        ];
        if skl.entries() != want {
            return TestResult::Fail("Skylake GT workarounds");
        }
        let skl_h0 = gt_workarounds(gen9(Gen9Kind::Skylake, 7), STEER);
        let kbl_b0 = gt_workarounds(gen9(Gen9Kind::KabyLake, 1), STEER);
        let cfl = gt_workarounds(gen9(Gen9Kind::CoffeeLake, 0), STEER);
        if skl_h0.entries().iter().any(|w| w.reg == 0x4ab0)
            || !kbl_b0.entries().iter().any(|w| w.reg == 0x4ab8)
            || gt_workarounds(gen9(Gen9Kind::KabyLake, 2), STEER)
                .entries()
                .iter()
                .any(|w| w.reg == 0x4ab8)
            || cfl
                .entries()
                .iter()
                .find(|w| w.reg == 0x4090)
                .map(|w| w.set)
                != Some(1 << 25)
        {
            return TestResult::Fail("Gen9 stepping and CFL/CML gates");
        }
        let icl = gt_workarounds(
            WaPlatform::Gen11 {
                jsl_ehl: false,
                revision: 3,
            },
            Steering {
                subslice: 2,
                ..STEER
            },
        );
        let regs: alloc::vec::Vec<u64> = icl.entries().iter().map(|w| w.reg).collect();
        if regs
            != [
                0xfdc, 0x4080, 0x4ab8, 0x4b80, 0x9434, 0x94d4, 0x94e4, 0x9524, 0x9550, 0xb43c,
            ]
            || icl.entries()[0] != wa(0xfdc, 0x7f00_0000, 0x0200_0000, 0x7f00_0000, false)
            || icl.entries()[3] != wa(0x4b80, 0x300f, 0x1001, 0x300f, false)
            || icl.entries()[8] != wa(0x9550, 1 << 9, 0, 1 << 9, false)
        {
            return TestResult::Fail("Ice Lake GT workarounds");
        }
        let jsl_b0 = gt_workarounds(
            WaPlatform::Gen11 {
                jsl_ehl: true,
                revision: 1,
            },
            STEER,
        );
        if jsl_b0.entries().iter().any(|w| w.reg == 0x94d4) {
            return TestResult::Fail("Wa_1607087056 stops at EHL/JSL B0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_gt",
        smoke_legacy_gt_gt_workarounds_follow_linux
    );

    /// The context lists and their LRI image: masked entries merge their
    /// halves, the Gen11 blind writes load their value without a read.
    fn smoke_legacy_gt_ctx_workarounds_follow_linux() -> TestResult {
        let cfl = ctx_workarounds(gen9(Gen9Kind::CoffeeLake, 0), STEER);
        let want = [
            (0x2580, 0x0007_0004, 0x7),
            (0x7004, 0x0042_0042, 0x42),
            (0x7014, 0x2100_2100, 0x2100),
            (0x7300, 0x8030_8030, 0x8030),
            (0xe100, 0x0010_0010, 0x10),
            (0xe180, 0x2000_2000, 0x2000),
            (0xe184, 0x0002_0002, 0x2),
            (0xe188, 0x0008_0000, 0x8),
            (0xe194, 0x0114_0114, 0x114),
            (0xe4f0, 0x8100_8100, 0x8100),
        ];
        let got: alloc::vec::Vec<(u64, u32, u32)> = cfl
            .entries()
            .iter()
            .map(|w| (w.reg, w.set, w.read))
            .collect();
        if got != want || cfl.entries().iter().any(|w| !w.masked) {
            return TestResult::Fail("Coffee Lake context workarounds");
        }
        let lri = cfl.load_register_imm();
        if lri.len() != 22
            || lri[0] != 0x2200_0013
            || lri[1..3] != [0x2580, 0x0007_0004]
            || lri[21] != 0
        {
            return TestResult::Fail("LRI image: header, pairs, MI_NOOP");
        }
        let skl = ctx_workarounds(
            gen9(Gen9Kind::Skylake, 6),
            Steering {
                iz_hashing: [2, 0, 1],
                ..STEER
            },
        );
        if skl
            .entries()
            .iter()
            .find(|w| w.reg == 0x7008)
            .map(|w| w.set)
            != Some(0x003f_0012)
            || ctx_workarounds(gen9(Gen9Kind::Skylake, 6), STEER)
                .entries()
                .iter()
                .any(|w| w.reg == 0x7008 || w.reg == 0xe100)
            || ctx_workarounds(gen9(Gen9Kind::KabyLake, 1), STEER)
                .entries()
                .iter()
                .find(|w| w.reg == 0x7014)
                .map(|w| w.set)
                != Some(0x2000_2000)
        {
            return TestResult::Fail("SKL IZ hashing and KBL pre-C0 push-constant gate");
        }
        let icl = ctx_workarounds(
            WaPlatform::Gen11 {
                jsl_ehl: false,
                revision: 0,
            },
            STEER,
        );
        let got: alloc::vec::Vec<(u64, u32, u32)> = icl
            .entries()
            .iter()
            .map(|w| (w.reg, w.set, w.read))
            .collect();
        let want = [
            (0x2580, 0x0006_0002, 0x6),
            (0x7020, 0xffff_fffe, !0),
            (0x7024, 0xffff_ffff, !0),
            (0x7034, 0x0000_0200, !0),
            (0xe18c, 0x0020_0020, 0x20),
            (0xe420, 0x0010_0010, 0),
            (0xe48c, 0x0080_0080, 0x80),
            (0xe5f4, 0x0010_0010, 0x10),
        ];
        if got != want || icl.load_register_imm()[0] != 0x2200_000f {
            return TestResult::Fail("Ice Lake context workarounds");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_gt",
        smoke_legacy_gt_ctx_workarounds_follow_linux
    );

    /// rcs_engine_wa_init: Gen9's L3 atomics entries merge into the
    /// WaOCLCoherentLineFlush / BDW_SCRATCH1 entries without dropping their
    /// set bits; Gen11's GARBCNTL pair likewise.
    fn smoke_legacy_gt_rcs_workarounds_follow_linux() -> TestResult {
        let skl = rcs_workarounds(gen9(Gen9Kind::Skylake, 6));
        let want = [
            wa(0x20d4, 0, 0x0004_0004, 0x4, true),
            wa(0x20e0, 0, 0x4000_4000, 0x4000, true),
            wa(0xb004, 0x80, 0x80, 0x80, false),
            wa(0xb008, 1, 0, 1, false),
            wa(0xb118, 0x0060_0000, 0x0020_0000, 0x0060_0000, false),
            wa(0xb11c, 0x104, 0x4, 0x104, false),
        ];
        if skl.entries() != want {
            return TestResult::Fail("Gen9 RCS workarounds");
        }
        let icl = rcs_workarounds(WaPlatform::Gen11 {
            jsl_ehl: false,
            revision: 0,
        });
        let regs: alloc::vec::Vec<u64> = icl.entries().iter().map(|w| w.reg).collect();
        if regs
            != [
                0x2090, 0x20a0, 0x20d4, 0x20e0, 0x20ec, 0xb000, 0xb004, 0xb118, 0xb140, 0xb404,
                0xe18c,
            ]
            || icl.entries()[6] != wa(0xb004, 0x0fc0_007f, 0x0fc0_0001, 0x0fc0_007f, false)
            || icl.entries()[9] != wa(0xb404, 0xfe0, 0x20, 0xfe0, false)
        {
            return TestResult::Fail("Ice Lake RCS workarounds");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_gt",
        smoke_legacy_gt_rcs_workarounds_follow_linux
    );

    /// Whitelists sort with their access flags, and unused slots name
    /// RING_NOPID.
    fn smoke_legacy_gt_whitelist_follows_linux() -> TestResult {
        let skl = rcs_whitelist(gen9(Gen9Kind::Skylake, 6));
        let cml = rcs_whitelist(gen9(Gen9Kind::CometLake, 0));
        let icl = rcs_whitelist(WaPlatform::Gen11 {
            jsl_ehl: true,
            revision: 0,
        });
        if skl != [0x2248, 0x2580, 0x7014, 0x7304, 0xb118]
            || cml != [0x2248, 0x2580, 0x7014, 0x7304, 0x1000_2349]
            || icl != [0x731c, 0xe18c, 0xe194, 0x1000_2349]
        {
            return TestResult::Fail("RCS whitelist contents and order");
        }
        let writes = whitelist_writes(0x2000, &icl);
        if writes[0] != (0x24d0, 0x731c)
            || writes[3] != (0x24dc, 0x1000_2349)
            || writes[4] != (0x24e0, 0x2094)
            || writes[11] != (0x24fc, 0x2094)
        {
            return TestResult::Fail("FORCE_TO_NONPRIV slots then RING_NOPID");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_gt",
        smoke_legacy_gt_whitelist_follows_linux
    );

    /// Fuse decoding: Gen9 big core's FUSE2 slice/subslice fields and a lone
    /// 7-EU subslice's IZ hash; Gen11's subslice disable and L3 bank mask.
    fn smoke_legacy_gt_steering_follows_sseu_fuses() -> TestResult {
        let regs = |map: &'static [(u64, u32)]| {
            move |reg: u64| map.iter().find(|(r, _)| *r == reg).map_or(0, |(_, v)| *v)
        };
        // Slice 0 only, subslice 0 fused off, subslice 1 one EU short.
        let skl = Steering::read(
            gen9(Gen9Kind::Skylake, 6),
            regs(&[(0x9120, 1 << 25 | 1 << 20), (0x9134, 0x0000_0100)]),
        );
        if skl
            != Some(Steering {
                slice: 0,
                subslice: 1,
                l3_banks: 0,
                iz_hashing: [2, 0, 0],
            })
        {
            return TestResult::Fail("Gen9 FUSE2 steering and IZ hashing");
        }
        // Two 7-EU subslices: no single one, no hashing tune.
        let two = Steering::read(
            gen9(Gen9Kind::Skylake, 6),
            regs(&[(0x9120, 1 << 25), (0x9134, 0x0000_0101)]),
        );
        if two.map(|s| s.iz_hashing) != Some([0; 3])
            || Steering::read(gen9(Gen9Kind::KabyLake, 6), regs(&[(0x9120, 0)])).is_some()
        {
            return TestResult::Fail("IZ hashing needs exactly one 7-EU subslice per slice");
        }
        let icl = WaPlatform::Gen11 {
            jsl_ehl: false,
            revision: 0,
        };
        let on_bank =
            Steering::read(icl, regs(&[(0x9138, 1), (0x913c, 0x03), (0x9118, 0x0b)])).unwrap();
        let off_bank =
            Steering::read(icl, regs(&[(0x9138, 1), (0x913c, 0x03), (0x9118, 0x05)])).unwrap();
        if on_bank.subslice != 2
            || on_bank.l3_banks != 0x4
            || on_bank.l3bank_read_selector(0xb118).is_some()
            || off_bank.l3bank_read_selector(0xb118) != Some(1 << 24)
            || off_bank.l3bank_read_selector(0xb43c).is_some()
        {
            return TestResult::Fail("Gen11 subslice and L3 bank steering");
        }
        let jsl = WaPlatform::Gen11 {
            jsl_ehl: true,
            revision: 0,
        };
        if Steering::read(jsl, regs(&[(0x9138, 1), (0x913c, 0x0f)])).is_some() {
            return TestResult::Fail("EHL/JSL only have four subslices");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_gt",
        smoke_legacy_gt_steering_follows_sseu_fuses
    );

    /// wa_list_apply: reads only for RMW entries, skips unchanged values,
    /// always writes masked entries; verify reports the first unstuck one.
    fn smoke_legacy_gt_apply_and_verify() -> TestResult {
        use core::cell::RefCell;
        let list = gtt_workarounds(LegacyGt::Gen9);
        let regs = RefCell::new(alloc::collections::BTreeMap::from([
            (0x4024u64, 0xf000_7fffu32),
            (0x4080, 0x10),
            (0x4dd4, 0),
        ]));
        let reads = RefCell::new(alloc::vec::Vec::new());
        let writes = RefCell::new(alloc::vec::Vec::new());
        list.apply(
            |reg| {
                reads.borrow_mut().push(reg);
                regs.borrow()[&reg]
            },
            |reg, value| {
                writes.borrow_mut().push((reg, value));
                regs.borrow_mut().insert(reg, value);
            },
        );
        if *writes.borrow() != [(0x4080, 0x1f), (0x4dd4, 0x67f1_427f)]
            || *reads.borrow() != [0x4024, 0x4080, 0x4dd4]
            || list.verify(|reg| regs.borrow()[&reg]).is_err()
        {
            return TestResult::Fail("GTT workarounds apply as RMWs");
        }
        let masked = rcs_workarounds(gen9(Gen9Kind::Skylake, 6));
        let writes = RefCell::new(alloc::vec::Vec::new());
        masked.apply(|_| 0, |reg, value| writes.borrow_mut().push((reg, value)));
        // Masked entries always write; the SCRATCH_LNCF1 clear already holds
        // against a zero read, so wa_list_apply skips it.
        if writes.borrow()[0] != (0x20d4, 0x0004_0004)
            || writes.borrow().len() != 5
            || writes.borrow().iter().any(|(reg, _)| *reg == 0xb008)
        {
            return TestResult::Fail("masked entries write without reading");
        }
        if masked.verify(|reg| if reg == 0xb118 { 1 << 22 } else { !0 }) != Err(0xb008) {
            return TestResult::Fail("verify names the first entry that did not stick");
        }
        if gtt_workarounds(LegacyGt::Gen11).entries()
            != [
                wa(0x4024, !0, 0, !0, false),
                wa(0x4dd4, !0, 0x67f1_427f, !0, false),
            ]
        {
            return TestResult::Fail("Gen11 has 2M pages: GTT cache off, no 64K IPS");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_gt",
        smoke_legacy_gt_apply_and_verify
    );

    /// The SSEU decode and i915's topology blob, hand-built: a two-slice
    /// Gen9 GT3 with subslice 0 fused off and one 7-EU subslice, and an Ice
    /// Lake with subslices 6/7 fused off and one EU pair disabled.
    fn smoke_legacy_topology_follows_sseu_info_init() -> TestResult {
        let regs = |map: &'static [(u64, u32)]| {
            move |reg: u64| map.iter().find(|(r, _)| *r == reg).map_or(0, |(_, v)| *v)
        };
        let gt3 = LegacyTopology::read(
            gen9(Gen9Kind::Skylake, 6),
            regs(&[
                (0x9120, 0x3 << 25 | 1 << 20),
                (0x9134, 0x0000_8000),
                (0x9138, 0),
            ]),
        )
        .unwrap();
        if gt3.slice_mask() != 3
            || gt3.subslice_mask() != 0xe
            || gt3.subslice_total() != 6
            || gt3.eu_total() != 47
        {
            return TestResult::Fail("Gen9 slice / subslice / EU counts");
        }
        let blob = gt3.i915_bytes();
        let header: alloc::vec::Vec<u16> = blob[..16]
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        if header != [0, 3, 4, 8, 1, 1, 4, 1]
            || blob.len() != 32
            || blob[16..20] != [3, 0xe, 0xe, 0]
            || blob[20..24] != [0, 0x7f, 0xff, 0xff]
            || blob[24..28] != [0, 0xff, 0xff, 0xff]
            || blob[28..32] != [0; 4]
        {
            return TestResult::Fail("Gen9 topology blob");
        }
        let icl = LegacyTopology::read(
            WaPlatform::Gen11 {
                jsl_ehl: false,
                revision: 0,
            },
            regs(&[(0x913c, 0xc0), (0x9134, 0x03)]),
        )
        .unwrap();
        let blob = icl.i915_bytes();
        if icl.subslice_total() != 6
            || icl.eu_total() != 36
            || blob.len() != 16 + 2 + 8
            || blob[2..4] != [1, 0]
            || blob[4..6] != [8, 0]
            || blob[16..18] != [1, 0x3f]
            || blob[18..24] != [0xfc; 6]
            || blob[24..26] != [0, 0]
        {
            return TestResult::Fail("Ice Lake topology blob");
        }
        let jsl = LegacyTopology::read(
            WaPlatform::Gen11 {
                jsl_ehl: true,
                revision: 0,
            },
            regs(&[(0x913c, 0xf0)]),
        )
        .unwrap();
        if jsl.subslice_mask() != 0xf || jsl.i915_bytes().len() != 16 + 2 + 4 {
            return TestResult::Fail("EHL/JSL carry four subslices");
        }
        if LegacyTopology::read(gen9(Gen9Kind::Skylake, 6), regs(&[(0x9120, 0)])).is_some() {
            return TestResult::Fail("no enabled slice means no topology");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_legacy_gt",
        smoke_legacy_topology_follows_sseu_info_init
    );
}
