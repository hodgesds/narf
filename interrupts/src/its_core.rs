//! GICv3 ITS + redistributor LPI programming model.
//!
//! Arch-neutral and MMIO-free: register layouts, `GITS_BASERn`
//! negotiation, LPI table sizing, ITS command encodings and the command
//! queue's wrap / completion bookkeeping. `aarch64::its` drives real
//! hardware through these helpers; the kernel tests drive them against a
//! register model. Keeping the decisions here means the model and the
//! hardware path cannot disagree about an encoding.
//!
//! Field positions follow Arm IHI 0069H (GICv3/v4 architecture
//! specification) §12.19 (ITS registers), §12.11 (redistributor
//! registers) and §5.3 (ITS commands), cross-checked against Linux
//! `include/linux/irqchip/arm-gic-v3.h` and the `its_encode_*` helpers in
//! `drivers/irqchip/irq-gic-v3-its.c`.

/// ITS control-frame register offsets (Arm IHI 0069H §12.19).
pub mod reg {
    pub const GITS_CTLR: usize = 0x0000;
    pub const GITS_IIDR: usize = 0x0004;
    pub const GITS_TYPER: usize = 0x0008;
    pub const GITS_CBASER: usize = 0x0080;
    pub const GITS_CWRITER: usize = 0x0088;
    pub const GITS_CREADR: usize = 0x0090;
    pub const GITS_BASER0: usize = 0x0100;
    /// Number of `GITS_BASER<n>` registers.
    pub const GITS_BASER_NR: usize = 8;
    /// MSI doorbell, in the translation frame (second 64 KiB page).
    pub const GITS_TRANSLATER: u64 = 0x1_0040;
    /// ITS control frame + translation frame.
    pub const ITS_FRAME_LEN: u64 = 0x2_0000;

    pub const GICR_CTLR: usize = 0x0000;
    pub const GICR_TYPER: usize = 0x0008;
    pub const GICR_PROPBASER: usize = 0x0070;
    pub const GICR_PENDBASER: usize = 0x0078;
    /// One redistributor's RD_base frame.
    pub const GICR_RD_FRAME: u64 = 0x1_0000;
    /// RD_base + SGI_base.
    pub const GICR_STRIDE_V3: u64 = 0x2_0000;
    /// GICv4 adds VLPI_base + a reserved frame.
    pub const GICR_STRIDE_V4: u64 = 0x4_0000;
}

pub const GITS_CTLR_ENABLE: u32 = 1 << 0;
pub const GITS_CTLR_QUIESCENT: u32 = 1 << 31;
pub const GICR_CTLR_ENABLE_LPIS: u32 = 1 << 0;
pub const GICR_TYPER_PLPIS: u64 = 1 << 0;
pub const GICR_TYPER_VLPIS: u64 = 1 << 1;
pub const GICR_TYPER_LAST: u64 = 1 << 4;

/// Shareability encodings shared by every GIC table base register.
pub const SHR_NON: u64 = 0;
pub const SHR_INNER: u64 = 1;
/// Inner-cacheability encodings shared by every GIC table base register.
pub const CACHE_NC: u64 = 1;
pub const CACHE_RAWAWB: u64 = 7;

pub const SZ_4K: u64 = 0x1000;
pub const SZ_16K: u64 = 0x4000;
pub const SZ_64K: u64 = 0x1_0000;

/// Bits [51:12] / [51:16] / [51:8] masks used by the address fields.
const fn genmask(hi: u32, lo: u32) -> u64 {
    (u64::MAX >> (63 - hi)) & !((1u64 << lo) - 1)
}

// ── GITS_TYPER ──────────────────────────────────────────────────────

/// Decoded `GITS_TYPER` (Arm IHI 0069H §12.19.17).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ItsTyper(pub u64);

impl ItsTyper {
    /// Physical LPIs supported.
    pub fn physical(self) -> bool {
        self.0 & 1 != 0
    }
    /// Bytes per ITT entry (`ITT_entry_size + 1`, bits [7:4]).
    pub fn itt_entry_size(self) -> u64 {
        ((self.0 >> 4) & 0xF) + 1
    }
    /// EventID width (`IDbits + 1`, bits [12:8]).
    pub fn event_id_bits(self) -> u32 {
        ((self.0 >> 8) & 0x1F) as u32 + 1
    }
    /// DeviceID width (`Devbits + 1`, bits [17:13]).
    pub fn device_id_bits(self) -> u32 {
        ((self.0 >> 13) & 0x1F) as u32 + 1
    }
    /// `PTA` (bit 19): RDbase in commands is a physical address rather
    /// than a processor number.
    pub fn pta(self) -> bool {
        self.0 & (1 << 19) != 0
    }
    /// Hardware collection count (bits [31:24]).
    pub fn hcc(self) -> u32 {
        ((self.0 >> 24) & 0xFF) as u32
    }
    /// Collection-ID width: `CIDbits + 1` when `CIL` (bit 36), else 16.
    pub fn collection_id_bits(self) -> u32 {
        if self.0 & (1 << 36) != 0 {
            ((self.0 >> 32) & 0xF) as u32 + 1
        } else {
            16
        }
    }
}

// ── GITS_BASER<n> ───────────────────────────────────────────────────

pub const BASER_VALID: u64 = 1 << 63;
pub const BASER_INDIRECT: u64 = 1 << 62;
const BASER_INNER_CACHE_SHIFT: u32 = 59;
const BASER_TYPE_SHIFT: u32 = 56;
const BASER_ESZ_SHIFT: u32 = 48;
const BASER_SHR_SHIFT: u32 = 10;
const BASER_PSZ_SHIFT: u32 = 8;
pub const BASER_SHR_MASK: u64 = 3 << BASER_SHR_SHIFT;
pub const BASER_PSZ_MASK: u64 = 3 << BASER_PSZ_SHIFT;
/// `GITS_BASER.Size` is 8 bits: at most 256 pages.
pub const BASER_PAGES_MAX: u64 = 256;

/// Table kind in `GITS_BASER<n>.Type` (bits [58:56]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TableType {
    None,
    Device,
    Vcpu,
    Collection,
    Reserved(u8),
}

pub fn baser_type(v: u64) -> TableType {
    match (v >> BASER_TYPE_SHIFT) & 7 {
        0 => TableType::None,
        1 => TableType::Device,
        2 => TableType::Vcpu,
        4 => TableType::Collection,
        t => TableType::Reserved(t as u8),
    }
}

/// Bytes per table entry (`Entry_Size + 1`, bits [52:48]).
pub fn baser_entry_size(v: u64) -> u64 {
    ((v >> BASER_ESZ_SHIFT) & 0x1F) + 1
}

/// Page-size field encoding (bits [9:8]).
pub fn psz_field(psz: u64) -> Option<u64> {
    match psz {
        SZ_4K => Some(0),
        SZ_16K => Some(1),
        SZ_64K => Some(2),
        _ => None,
    }
}

/// Physical-address field of `GITS_BASER<n>` for page size `psz`.
///
/// 4K/16K pages hold PA[47:12]; with 64K pages the field holds PA[47:16]
/// and PA[51:48] moves to bits [15:12] (Linux `GITS_BASER_PHYS_52_to_48`).
pub fn baser_addr_field(pa: u64, psz: u64) -> Option<u64> {
    if pa & (psz - 1) != 0 {
        return None;
    }
    if psz == SZ_64K {
        if pa >> 52 != 0 {
            return None;
        }
        Some((pa & genmask(47, 16)) | (((pa >> 48) & 0xF) << 12))
    } else {
        if pa >> 48 != 0 {
            return None;
        }
        Some(pa & genmask(47, 12))
    }
}

/// Minimal register window. Both the ITS control frame and a
/// redistributor's RD_base frame are driven through it. 32-bit registers
/// (`GITS_CTLR`, `GICR_CTLR`) must use the 32-bit accessors.
pub trait Mmio64 {
    fn read32(&mut self, off: usize) -> u32;
    fn write32(&mut self, off: usize, v: u32);
    fn read64(&mut self, off: usize) -> u64;
    fn write64(&mut self, off: usize, v: u64);
}

/// `its_probe_baser_psz`: try 64K, then 16K, then 4K, and keep the
/// first page size that reads back.
pub fn probe_baser_psz(r: &mut impl Mmio64, idx: usize) -> Option<u64> {
    let off = reg::GITS_BASER0 + idx * 8;
    for psz in [SZ_64K, SZ_16K, SZ_4K] {
        let field = psz_field(psz)?;
        let v = (r.read64(off) & !BASER_PSZ_MASK) | (field << BASER_PSZ_SHIFT);
        r.write64(off, v);
        if (r.read64(off) & BASER_PSZ_MASK) >> BASER_PSZ_SHIFT == field {
            return Some(psz);
        }
    }
    None
}

/// Cap on one flat table. Indirect (two-level) tables are not used, so a
/// wide DeviceID space is truncated to what this much memory covers; the
/// IDs beyond it are refused at `MAPD` time instead of corrupting memory.
pub const MAX_FLAT_TABLE_BYTES: u64 = 2 << 20;

/// Sizing decision for one `GITS_BASER<n>` table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TablePlan {
    pub kind: TableType,
    pub esz: u64,
    pub psz: u64,
    pub bytes: u64,
    /// IDs the table covers (`bytes / esz`, capped at the ID space).
    pub ids: u64,
}

/// Size a flat table the way `its_alloc_tables` / `its_parse_indirect_baser`
/// do when indirection is unavailable: enough entries for the whole
/// DeviceID space (`esz << Devbits`), or for `collections` ICIDs, rounded
/// up to whole ITS pages and capped by `GITS_BASER.Size` and
/// [`MAX_FLAT_TABLE_BYTES`]. Returns `None` for kinds this driver leaves
/// unprovisioned (vPE tables, reserved types).
pub fn plan_table(
    kind: TableType,
    esz: u64,
    psz: u64,
    typer: ItsTyper,
    collections: u64,
) -> Option<TablePlan> {
    let space = match kind {
        TableType::Device => 1u64 << typer.device_id_bits().min(40),
        TableType::Collection => collections.clamp(1, 1u64 << typer.collection_id_bits().min(40)),
        _ => return None,
    };
    let want = esz.checked_mul(space)?;
    let cap = (psz * BASER_PAGES_MAX).min(MAX_FLAT_TABLE_BYTES.max(psz));
    let bytes = want.div_ceil(psz).max(1).saturating_mul(psz).min(cap);
    let bytes = bytes - bytes % psz;
    Some(TablePlan {
        kind,
        esz,
        psz,
        bytes,
        ids: (bytes / esz).min(space),
    })
}

/// Full `GITS_BASER<n>` value (`its_setup_baser`). `type_raw` and the
/// entry size are written back unchanged — they are read-only.
pub fn encode_baser(pa_field: u64, cur: u64, pages: u64, psz: u64, cache: u64, shr: u64) -> u64 {
    pa_field
        | (cur & (7 << BASER_TYPE_SHIFT))
        | (cur & (0x1F << BASER_ESZ_SHIFT))
        | ((pages - 1) & 0xFF)
        | (cache << BASER_INNER_CACHE_SHIFT)
        | (shr << BASER_SHR_SHIFT)
        | (psz_field(psz).unwrap_or(0) << BASER_PSZ_SHIFT)
        | BASER_VALID
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SetupError {
    /// No page size of 4K/16K/64K stuck in `GITS_BASER<n>`.
    PageSize,
    /// Table address not representable at the negotiated page size.
    Address,
    /// The register did not hold the programmed value.
    NotSticky { wrote: u64, read: u64 },
    /// Table memory could not be allocated.
    NoMemory,
    /// The redistributor already has LPIs enabled with tables we did not
    /// program (GICR_PROPBASER is then UNPREDICTABLE to change).
    LpisAlreadyEnabled,
    /// GICD_TYPER / GICR_TYPER / GITS_TYPER do not advertise physical LPIs
    /// wide enough for the LPI range used here.
    NoLpis,
}

/// Programmed table attributes after readback.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BaserResult {
    pub value: u64,
    pub cache: u64,
    pub shr: u64,
}

/// `its_setup_baser`: program, read back, and if the shareability did not
/// stick adopt what the ITS reported (dropping to non-cacheable when it
/// reports non-shareable) and retry. Any other difference is fatal.
pub fn setup_baser(
    r: &mut impl Mmio64,
    idx: usize,
    pa: u64,
    plan: &TablePlan,
    mut cache: u64,
    mut shr: u64,
) -> Result<BaserResult, SetupError> {
    let off = reg::GITS_BASER0 + idx * 8;
    let cur = r.read64(off);
    let field = baser_addr_field(pa, plan.psz).ok_or(SetupError::Address)?;
    let pages = plan.bytes / plan.psz;
    if !(1..=BASER_PAGES_MAX).contains(&pages) {
        return Err(SetupError::Address);
    }
    let mut last = (0, 0);
    for _ in 0..3 {
        let val = encode_baser(field, cur, pages, plan.psz, cache, shr);
        r.write64(off, val);
        let tmp = r.read64(off);
        if (val ^ tmp) & BASER_SHR_MASK != 0 {
            shr = (tmp & BASER_SHR_MASK) >> BASER_SHR_SHIFT;
            if shr == SHR_NON {
                cache = CACHE_NC;
            }
            last = (val, tmp);
            continue;
        }
        if val != tmp {
            return Err(SetupError::NotSticky {
                wrote: val,
                read: tmp,
            });
        }
        return Ok(BaserResult {
            value: val,
            cache,
            shr,
        });
    }
    Err(SetupError::NotSticky {
        wrote: last.0,
        read: last.1,
    })
}

/// Memory provider for ITS tables. The kernel backs it with the frame
/// allocator + cache maintenance; tests hand out synthetic addresses.
pub trait TableMem {
    /// Zeroed, physically contiguous, `align`-aligned memory.
    fn alloc(&mut self, bytes: u64, align: u64) -> Option<u64>;
    fn free(&mut self, pa: u64, bytes: u64);
    /// Clean + invalidate to the point of coherency.
    fn flush(&mut self, pa: u64, bytes: u64);
}

/// One provisioned `GITS_BASER<n>` table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TableInfo {
    pub idx: usize,
    pub plan: TablePlan,
    pub pa: u64,
    pub baser: BaserResult,
}

/// Provisioned device + collection tables.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Tables {
    pub device: Option<TableInfo>,
    pub collection: Option<TableInfo>,
}

impl Tables {
    /// DeviceIDs the flat device table covers. With no device table the
    /// ITS holds device state internally and the full `Devbits` space is
    /// usable.
    pub fn device_ids(&self, typer: ItsTyper) -> u64 {
        self.device
            .map(|t| t.plan.ids)
            .unwrap_or(1u64 << typer.device_id_bits().min(40))
    }
}

/// `its_alloc_tables` restricted to flat tables: walk every
/// `GITS_BASER<n>`, provision device and collection tables, leave
/// unknown / vPE tables invalid. The first table starts with
/// Inner-Shareable / RaWaWb and later tables inherit what the previous
/// one settled on.
pub fn alloc_tables(
    r: &mut impl Mmio64,
    typer: ItsTyper,
    collections: u64,
    mem: &mut impl TableMem,
) -> Result<Tables, SetupError> {
    let mut cache = CACHE_RAWAWB;
    let mut shr = SHR_INNER;
    let mut out = Tables::default();
    for idx in 0..reg::GITS_BASER_NR {
        let off = reg::GITS_BASER0 + idx * 8;
        let val = r.read64(off);
        let kind = baser_type(val);
        if !matches!(kind, TableType::Device | TableType::Collection) {
            continue;
        }
        let psz = match probe_baser_psz(r, idx) {
            Some(p) => p,
            None => {
                free_tables(&out, mem);
                return Err(SetupError::PageSize);
            }
        };
        let esz = baser_entry_size(r.read64(off));
        let Some(plan) = plan_table(kind, esz, psz, typer, collections) else {
            continue;
        };
        let Some(pa) = mem.alloc(plan.bytes, plan.psz) else {
            free_tables(&out, mem);
            return Err(SetupError::NoMemory);
        };
        let res = match setup_baser(r, idx, pa, &plan, cache, shr) {
            Ok(res) => res,
            Err(e) => {
                mem.free(pa, plan.bytes);
                r.write64(off, 0);
                free_tables(&out, mem);
                return Err(e);
            }
        };
        if res.shr == SHR_NON {
            mem.flush(pa, plan.bytes);
        }
        cache = res.cache;
        shr = res.shr;
        let info = TableInfo {
            idx,
            plan,
            pa,
            baser: res,
        };
        match kind {
            TableType::Device => out.device = Some(info),
            _ => out.collection = Some(info),
        }
    }
    Ok(out)
}

fn free_tables(t: &Tables, mem: &mut impl TableMem) {
    for info in [t.device, t.collection].into_iter().flatten() {
        mem.free(info.pa, info.plan.bytes);
    }
}

// ── GITS_CBASER ─────────────────────────────────────────────────────

/// Command queue size (Linux `ITS_CMD_QUEUE_SZ`).
pub const CMD_QUEUE_BYTES: u64 = SZ_64K;
pub const CMD_BYTES: u64 = 32;
const CBASER_INNER_CACHE_SHIFT: u32 = 59;
const CBASER_SHR_SHIFT: u32 = 10;
const CBASER_SHR_MASK: u64 = 3 << CBASER_SHR_SHIFT;
const CBASER_CACHE_MASK: u64 = 7 << CBASER_INNER_CACHE_SHIFT;

pub fn encode_cbaser(pa: u64, bytes: u64, cache: u64, shr: u64) -> u64 {
    (pa & genmask(51, 12))
        | (cache << CBASER_INNER_CACHE_SHIFT)
        | (shr << CBASER_SHR_SHIFT)
        | ((bytes / SZ_4K - 1) & 0xFF)
        | (1 << 63)
}

/// Program `GITS_CBASER` like `its_probe_one`. Returns the final value and
/// whether command writes need explicit cache cleaning (non-shareable).
pub fn setup_cbaser(r: &mut impl Mmio64, pa: u64, bytes: u64) -> Result<(u64, bool), SetupError> {
    let mut val = encode_cbaser(pa, bytes, CACHE_RAWAWB, SHR_INNER);
    r.write64(reg::GITS_CBASER, val);
    let tmp = r.read64(reg::GITS_CBASER);
    let mut flush = false;
    if (tmp ^ val) & CBASER_SHR_MASK != 0 {
        if tmp & CBASER_SHR_MASK == 0 {
            val &= !(CBASER_SHR_MASK | CBASER_CACHE_MASK);
            val |= CACHE_NC << CBASER_INNER_CACHE_SHIFT;
            r.write64(reg::GITS_CBASER, val);
        }
        flush = true;
    }
    let back = r.read64(reg::GITS_CBASER);
    if back & genmask(51, 12) != pa & genmask(51, 12) || back & (1 << 63) == 0 {
        return Err(SetupError::NotSticky {
            wrote: val,
            read: back,
        });
    }
    Ok((back, flush))
}

// ── LPI property / pending tables ───────────────────────────────────

/// First LPI INTID (architectural).
pub const LPI_BASE: u32 = 8192;
/// Pending tables must be 64 KiB aligned (GICR_PENDBASER bits [51:16]).
pub const PEND_ALIGN: u64 = SZ_64K;
/// LPI property byte: priority [7:2], bit 1 RES1 (Linux `LPI_PROP_GROUP1`),
/// bit 0 enable. Priority matches the SPI/PPI default (0xA0).
pub const LPI_PROP_PRIO: u8 = 0xA0;
pub const LPI_PROP_GROUP1: u8 = 1 << 1;
pub const LPI_PROP_ENABLED: u8 = 1 << 0;

pub const fn lpi_prop_byte(enabled: bool) -> u8 {
    LPI_PROP_PRIO | LPI_PROP_GROUP1 | if enabled { LPI_PROP_ENABLED } else { 0 }
}

/// Smallest INTID width covering `LPI_BASE + nr_lpis`, provided the
/// distributor implements LPIs (`GICD_TYPER.LPIS`, bit 17) with at least
/// that many ID bits (`GICD_TYPER.IDbits`, bits [23:19]).
pub fn lpi_id_bits(gicd_typer: u32, nr_lpis: u32) -> Option<u32> {
    if gicd_typer & (1 << 17) == 0 {
        return None;
    }
    let supported = ((gicd_typer >> 19) & 0x1F) + 1;
    let top = LPI_BASE.checked_add(nr_lpis)?;
    let need = (32 - (top - 1).leading_zeros()).max(14);
    (need <= supported).then_some(need)
}

/// Property-table bytes: one per LPI INTID below `2^id_bits`.
pub const fn prop_table_bytes(id_bits: u32) -> u64 {
    (1u64 << id_bits) - LPI_BASE as u64
}

/// Pending-table bytes: one bit per INTID (including the 1 KiB that
/// covers INTIDs < 8192), rounded to the 64 KiB alignment unit.
pub const fn pend_table_bytes(id_bits: u32) -> u64 {
    let raw = (1u64 << id_bits) / 8;
    raw.div_ceil(PEND_ALIGN) * PEND_ALIGN
}

const XBASER_SHR_SHIFT: u32 = 10;
const XBASER_SHR_MASK: u64 = 3 << XBASER_SHR_SHIFT;
const XBASER_INNER_CACHE_SHIFT: u32 = 7;
const XBASER_CACHE_MASK: u64 = 7 << XBASER_INNER_CACHE_SHIFT;

pub fn encode_propbaser(pa: u64, id_bits: u32, cache: u64, shr: u64) -> u64 {
    (pa & genmask(51, 12))
        | (shr << XBASER_SHR_SHIFT)
        | (cache << XBASER_INNER_CACHE_SHIFT)
        | ((id_bits as u64 - 1) & 0x1F)
}

pub fn encode_pendbaser(pa: u64, cache: u64, shr: u64) -> u64 {
    (pa & genmask(51, 16)) | (shr << XBASER_SHR_SHIFT) | (cache << XBASER_INNER_CACHE_SHIFT)
}

/// Outcome of `its_cpu_init_lpis`-style programming.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LpiTables {
    pub propbaser: u64,
    pub pendbaser: u64,
    /// Property-table updates need cache cleaning before INV.
    pub prop_flush: bool,
}

/// `its_cpu_init_lpis`: program PROPBASER then PENDBASER with
/// Inner-Shareable / RaWaWb, fall back to non-shareable non-cacheable
/// when the redistributor reports non-shareable, then set
/// `GICR_CTLR.EnableLPIs`. Refuses a redistributor whose LPIs are already
/// on (programming the bases is then UNPREDICTABLE).
pub fn init_lpis(
    rd: &mut impl Mmio64,
    prop_pa: u64,
    pend_pa: u64,
    id_bits: u32,
) -> Result<LpiTables, SetupError> {
    if pend_pa & (PEND_ALIGN - 1) != 0 || prop_pa & (SZ_4K - 1) != 0 {
        return Err(SetupError::Address);
    }
    let typer = rd.read64(reg::GICR_TYPER);
    if typer & GICR_TYPER_PLPIS == 0 {
        return Err(SetupError::NoLpis);
    }
    if rd.read32(reg::GICR_CTLR) & GICR_CTLR_ENABLE_LPIS != 0 {
        // Already live: only accept our own tables (re-init), never
        // reprogram them underneath the redistributor.
        let propbaser = rd.read64(reg::GICR_PROPBASER);
        let pendbaser = rd.read64(reg::GICR_PENDBASER);
        if propbaser & genmask(51, 12) != prop_pa & genmask(51, 12)
            || pendbaser & genmask(51, 16) != pend_pa & genmask(51, 16)
        {
            return Err(SetupError::LpisAlreadyEnabled);
        }
        return Ok(LpiTables {
            propbaser,
            pendbaser,
            prop_flush: propbaser & XBASER_SHR_MASK == 0,
        });
    }

    let mut prop = encode_propbaser(prop_pa, id_bits, CACHE_RAWAWB, SHR_INNER);
    rd.write64(reg::GICR_PROPBASER, prop);
    let tmp = rd.read64(reg::GICR_PROPBASER);
    let mut prop_flush = false;
    if (tmp ^ prop) & XBASER_SHR_MASK != 0 {
        if tmp & XBASER_SHR_MASK == 0 {
            prop &= !(XBASER_SHR_MASK | XBASER_CACHE_MASK);
            prop |= CACHE_NC << XBASER_INNER_CACHE_SHIFT;
            rd.write64(reg::GICR_PROPBASER, prop);
        }
        prop_flush = true;
    }
    let back = rd.read64(reg::GICR_PROPBASER);
    if back & genmask(51, 12) != prop_pa & genmask(51, 12) || back & 0x1F != (id_bits as u64 - 1) {
        return Err(SetupError::NotSticky {
            wrote: prop,
            read: back,
        });
    }

    let mut pend = encode_pendbaser(pend_pa, CACHE_RAWAWB, SHR_INNER);
    rd.write64(reg::GICR_PENDBASER, pend);
    let tmp = rd.read64(reg::GICR_PENDBASER);
    if tmp & XBASER_SHR_MASK == 0 {
        pend &= !(XBASER_SHR_MASK | XBASER_CACHE_MASK);
        pend |= CACHE_NC << XBASER_INNER_CACHE_SHIFT;
        rd.write64(reg::GICR_PENDBASER, pend);
    }
    let pend_back = rd.read64(reg::GICR_PENDBASER);
    if pend_back & genmask(51, 16) != pend_pa & genmask(51, 16) {
        return Err(SetupError::NotSticky {
            wrote: pend,
            read: pend_back,
        });
    }

    let ctlr = rd.read32(reg::GICR_CTLR);
    rd.write32(reg::GICR_CTLR, ctlr | GICR_CTLR_ENABLE_LPIS);
    Ok(LpiTables {
        propbaser: back,
        pendbaser: pend_back,
        prop_flush,
    })
}

// ── ITTs ────────────────────────────────────────────────────────────

/// ITT alignment (Linux `ITS_ITT_ALIGN`; MAPD ITT_addr holds PA[51:8]).
pub const ITS_ITT_ALIGN: u64 = 256;

/// `its_create_device` ITT sizing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IttPlan {
    /// Power-of-two ITE count (at least 2).
    pub nr_ites: u32,
    pub bytes: u64,
    /// MAPD `Size` field: `ilog2(nr_ites) - 1`.
    pub size_field: u8,
}

pub fn plan_itt(nvecs: u32, typer: ItsTyper) -> IttPlan {
    let ev_bits = typer.event_id_bits().min(31);
    let nv = nvecs.max(1).checked_next_power_of_two().unwrap_or(1 << 31);
    let nv = nv.min(1u32 << ev_bits);
    let nr_ites = nv.max(2);
    let bytes = (nr_ites as u64 * typer.itt_entry_size()).max(ITS_ITT_ALIGN);
    IttPlan {
        nr_ites,
        bytes: bytes.div_ceil(ITS_ITT_ALIGN) * ITS_ITT_ALIGN,
        size_field: (nr_ites.ilog2() - 1) as u8,
    }
}

/// `RDbase` operand of MAPC / SYNC: the redistributor's physical address
/// when `GITS_TYPER.PTA`, else its processor number (`GICR_TYPER[23:8]`)
/// shifted to bit 16, which is what `its_encode_target` expects.
pub fn rd_target(typer: ItsTyper, rd_pa: u64, gicr_typer: u64) -> u64 {
    if typer.pta() {
        rd_pa
    } else {
        ((gicr_typer >> 8) & 0xFFFF) << 16
    }
}

// ── Commands (Arm IHI 0069H §5.3) ───────────────────────────────────

pub type Cmd = [u64; 4];

pub const CMD_MOVI: u8 = 0x01;
pub const CMD_INT: u8 = 0x03;
pub const CMD_CLEAR: u8 = 0x04;
pub const CMD_SYNC: u8 = 0x05;
pub const CMD_MAPD: u8 = 0x08;
pub const CMD_MAPC: u8 = 0x09;
pub const CMD_MAPTI: u8 = 0x0A;
pub const CMD_MAPI: u8 = 0x0B;
pub const CMD_INV: u8 = 0x0C;
pub const CMD_INVALL: u8 = 0x0D;
pub const CMD_DISCARD: u8 = 0x0F;

const fn dev_cmd(op: u8, devid: u32) -> u64 {
    op as u64 | ((devid as u64) << 32)
}

/// MAPD: DeviceID [63:32] of DW0, Size [4:0] of DW1, ITT_addr PA[51:8]
/// in DW2 [51:8], V in DW2 [63].
pub fn cmd_mapd(devid: u32, itt_pa: u64, size_field: u8, valid: bool) -> Cmd {
    [
        dev_cmd(CMD_MAPD, devid),
        (size_field & 0x1F) as u64,
        (itt_pa & genmask(51, 8)) | ((valid as u64) << 63),
        0,
    ]
}

/// MAPC: ICID DW2 [15:0], RDbase DW2 [51:16], V DW2 [63].
pub fn cmd_mapc(icid: u16, target: u64, valid: bool) -> Cmd {
    [
        CMD_MAPC as u64,
        0,
        icid as u64 | (target & genmask(51, 16)) | ((valid as u64) << 63),
        0,
    ]
}

/// MAPTI: EventID DW1 [31:0], pINTID DW1 [63:32], ICID DW2 [15:0].
pub fn cmd_mapti(devid: u32, event: u32, lpi: u32, icid: u16) -> Cmd {
    [
        dev_cmd(CMD_MAPTI, devid),
        event as u64 | ((lpi as u64) << 32),
        icid as u64,
        0,
    ]
}

pub fn cmd_inv(devid: u32, event: u32) -> Cmd {
    [dev_cmd(CMD_INV, devid), event as u64, 0, 0]
}

pub fn cmd_int(devid: u32, event: u32) -> Cmd {
    [dev_cmd(CMD_INT, devid), event as u64, 0, 0]
}

pub fn cmd_discard(devid: u32, event: u32) -> Cmd {
    [dev_cmd(CMD_DISCARD, devid), event as u64, 0, 0]
}

pub fn cmd_invall(icid: u16) -> Cmd {
    [CMD_INVALL as u64, 0, icid as u64, 0]
}

/// SYNC: RDbase DW2 [51:16].
pub fn cmd_sync(target: u64) -> Cmd {
    [CMD_SYNC as u64, 0, target & genmask(51, 16), 0]
}

// ── Command queue ───────────────────────────────────────────────────

/// `GITS_CREADR.Offset` (bits [19:5]).
pub const fn creadr_offset(v: u64) -> u64 {
    v & genmask(19, 5)
}

/// `GITS_CREADR.Stalled` (bit 0): a command error stopped processing.
pub const fn creadr_stalled(v: u64) -> bool {
    v & 1 != 0
}

/// Software view of the circular command queue.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CmdQueue {
    pub size: u64,
    pub write: u64,
}

impl CmdQueue {
    pub const fn new(size: u64) -> Self {
        Self { size, write: 0 }
    }
    /// Linux `its_queue_full`: one slot always stays empty.
    pub fn is_full(&self, read: u64) -> bool {
        (self.write + CMD_BYTES) % self.size == read
    }
    /// Claim the next slot, wrapping at the end of the queue.
    pub fn push(&mut self) -> u64 {
        let at = self.write;
        self.write = (at + CMD_BYTES) % self.size;
        at
    }
}

/// Wrap-aware completion tracker (`its_wait_for_range_completion`).
#[derive(Copy, Clone, Debug)]
pub struct RangeWait {
    prev: u64,
    linear: u64,
    to: u64,
    size: u64,
}

impl RangeWait {
    pub fn new(from: u64, to: u64, size: u64) -> Self {
        let to = if to < from { to + size } else { to };
        Self {
            prev: from,
            linear: from,
            to,
            size,
        }
    }
    /// Feed a `GITS_CREADR` offset; true once the range has drained.
    pub fn update(&mut self, rd: u64) -> bool {
        let delta = if rd < self.prev {
            rd + self.size - self.prev
        } else {
            rd - self.prev
        };
        self.linear += delta;
        self.prev = rd;
        self.linear >= self.to
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Poll {
    Pending,
    Ready,
    Stalled,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CmdError {
    /// `GITS_CREADR` did not reach the posted commands in time.
    Timeout,
    /// `GITS_CREADR.Stalled`: the ITS stopped at the command at `offset`.
    Stalled { offset: u64 },
}

/// Command-queue backend: register access, command memory and a bounded
/// wait.
pub trait CmdHw: Mmio64 {
    /// Store one command at `off` and make it visible to the ITS.
    fn write_cmd(&mut self, off: u64, cmd: &Cmd);
    /// Re-run `poll` until it is not `Pending` or the bound expires; return
    /// the last result.
    fn spin(&mut self, poll: &mut dyn FnMut(&mut Self) -> Poll) -> Poll
    where
        Self: Sized;
}

/// Most commands linearised in one completion window (well under the
/// 2048-slot queue so the wrap arithmetic stays unambiguous).
const CMD_BATCH: usize = 64;

/// Post `cmds` and wait for the ITS to consume them, handling the queue
/// wrap and reporting `GITS_CREADR.Stalled`.
pub fn submit<H: CmdHw>(hw: &mut H, q: &mut CmdQueue, cmds: &[Cmd]) -> Result<(), CmdError> {
    // Never linearise more than the queue holds (one slot stays empty).
    let batch = CMD_BATCH.min((q.size / CMD_BYTES) as usize - 1).max(1);
    for chunk in cmds.chunks(batch) {
        let start = q.write;
        for cmd in chunk {
            let probe = *q;
            let mut stalled_at = 0;
            let state = hw.spin(&mut |h| {
                let rd = h.read64(reg::GITS_CREADR);
                if creadr_stalled(rd) {
                    stalled_at = creadr_offset(rd);
                    Poll::Stalled
                } else if probe.is_full(creadr_offset(rd)) {
                    Poll::Pending
                } else {
                    Poll::Ready
                }
            });
            match state {
                Poll::Ready => {}
                Poll::Stalled => return Err(CmdError::Stalled { offset: stalled_at }),
                Poll::Pending => return Err(CmdError::Timeout),
            }
            let at = q.push();
            hw.write_cmd(at, cmd);
            hw.write64(reg::GITS_CWRITER, q.write);
        }
        let mut wait = RangeWait::new(start, q.write, q.size);
        let mut stalled_at = 0;
        let state = hw.spin(&mut |h| {
            let rd = h.read64(reg::GITS_CREADR);
            if wait.update(creadr_offset(rd)) {
                Poll::Ready
            } else if creadr_stalled(rd) {
                stalled_at = creadr_offset(rd);
                Poll::Stalled
            } else {
                Poll::Pending
            }
        });
        match state {
            Poll::Ready => {}
            Poll::Stalled => return Err(CmdError::Stalled { offset: stalled_at }),
            Poll::Pending => return Err(CmdError::Timeout),
        }
    }
    Ok(())
}
