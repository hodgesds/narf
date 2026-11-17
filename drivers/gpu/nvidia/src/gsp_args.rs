//! GSP boot arguments — the RM args (`GSP_ARGUMENTS_CACHED`), the
//! shared message-queue init, and the libos memory-region list.
//!
//! These are the host-built descriptors the GSP firmware reads at boot
//! (their physical address is handed to the GSP Falcon via mailboxes):
//!
//! - `GSP_ARGUMENTS_CACHED` (the `rmargs` page) — carries
//!   `MESSAGE_QUEUE_INIT_ARGUMENTS`, telling GSP where the cmdq/msgq
//!   rings live. Cite `rm/r535/nvrm/gsp.h:578,593` +
//!   `rm/r535/gsp.c::r535_gsp_set_rmargs`.
//! - `LibosMemoryRegionInitArgument[]` (the `libos` page) — names the
//!   log buffers + the rmargs region for libos. Cite `gsp.h:612` +
//!   `gsp.c::r535_gsp_libos_init`.
//!
//! All pure CPU work (no hardware), unit-tested. The physical
//! addresses passed in come from the live allocator (a later lane).

#![allow(dead_code)]

/// GSP page / queue granularity.
pub const GSP_PAGE_SIZE: u64 = 4096;

// ── Shared RPC region geometry (A5) ──────────────────────────────
//
// One DMA-coherent region holds a self-mapping PTE array, then the
// cmdq (host→GSP), then the msgq (GSP→host), each 256 KiB. Cite
// `rm/r535/gsp.c::r535_gsp_shared_init`.

/// Byte size of each queue (cmdq, msgq).
pub const GSP_QUEUE_SIZE: u64 = 0x40000;
/// Entries per queue: `(size - entryOff) / msgSize`, entryOff =
/// msgSize = GSP_PAGE_SIZE → `(0x40000 - 0x1000) / 0x1000` = 63.
pub const GSP_QUEUE_MSG_COUNT: u32 = ((GSP_QUEUE_SIZE - GSP_PAGE_SIZE) / GSP_PAGE_SIZE) as u32;

/// PTE count for the shared region's self-map: the two queues plus the
/// pages the PTE array itself occupies. Cite `gsp.c:1137`
/// (`nr = (0x40000+0x40000)>>12; nr += DIV_ROUND_UP(nr*8, 4096)`).
pub const fn shared_region_pte_count() -> u32 {
    let data = ((GSP_QUEUE_SIZE + GSP_QUEUE_SIZE) / GSP_PAGE_SIZE) as u32;
    data + (data * 8).div_ceil(GSP_PAGE_SIZE as u32)
}

// ── MESSAGE_QUEUE_INIT_ARGUMENTS (48 bytes) ──────────────────────

/// Size of `MESSAGE_QUEUE_INIT_ARGUMENTS` (u64 + u32 + 4 pad + 4×u64).
pub const MSGQ_INIT_ARGS_SIZE: usize = 48;

/// Size of `GSP_ARGUMENTS_CACHED` (48 + 12 + 4 gpuInstance + 16
/// profilerArgs = 80 bytes), before page padding.
pub const GSP_ARGS_CACHED_SIZE: usize = 80;

/// Build the one-page `rmargs` buffer (`GSP_ARGUMENTS_CACHED` padded to
/// `GSP_PAGE_SIZE`). `shared_phys` is the DMA base of the shared RPC
/// region; `cmdq_off`/`statq_off` are the byte offsets of the two
/// queues within it; `pte_count` is [`shared_region_pte_count`].
/// Suspend/resume (`srInitArguments`), `gpuInstance`, and
/// `profilerArgs` are left zero for a fresh boot. Cite
/// `r535_gsp_set_rmargs`.
pub fn build_rmargs(
    shared_phys: u64,
    pte_count: u32,
    cmdq_off: u64,
    statq_off: u64,
) -> [u8; GSP_PAGE_SIZE as usize] {
    let mut b = [0u8; GSP_PAGE_SIZE as usize];
    let put64 = |b: &mut [u8], o: usize, v: u64| b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    let put32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    // MESSAGE_QUEUE_INIT_ARGUMENTS @ 0.
    put64(&mut b, 0x00, shared_phys); // sharedMemPhysAddr
    put32(&mut b, 0x08, pte_count); // pageTableEntryCount (+4 pad to 0x10)
    put64(&mut b, 0x10, cmdq_off); // cmdQueueOffset
    put64(&mut b, 0x18, statq_off); // statQueueOffset
    put64(&mut b, 0x20, 0); // locklessCmdQueueOffset
    put64(&mut b, 0x28, 0); // locklessStatQueueOffset
                            // srInitArguments @ 0x30 (12 bytes) — zero for fresh boot.
                            // gpuInstance @ 0x3C — zero. profilerArgs @ 0x40 — zero.
    b
}

// ── libos memory regions (A7) ────────────────────────────────────

/// `LibosMemoryRegionKind::CONTIGUOUS`.
pub const LIBOS_KIND_CONTIGUOUS: u8 = 1;
/// `LibosMemoryRegionLoc::SYSMEM`.
pub const LIBOS_LOC_SYSMEM: u8 = 1;

/// Size of one `LibosMemoryRegionInitArgument` (3×u64 + 2×u8 + 6 pad).
pub const LIBOS_REGION_ARG_SIZE: usize = 32;
/// Number of libos regions for a Turing boot (LOGINIT, LOGINTR, LOGRM,
/// RMARGS).
pub const LIBOS_REGION_COUNT: usize = 4;

/// Size of each log buffer (LOGINIT/LOGINTR/LOGRM).
pub const LIBOS_LOG_SIZE: u64 = 0x10000;

/// Pack the first ≤8 bytes of `name` big-endian into a libos `id8`.
/// Cite `gsp.c:1435 r535_gsp_libos_id8` (`id = (id<<8) | *name`).
pub fn libos_id8(name: &str) -> u64 {
    let mut id = 0u64;
    for &c in name.as_bytes().iter().take(8) {
        id = (id << 8) | c as u64;
    }
    id
}

/// One libos region descriptor.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LibosRegion {
    pub id8: u64,
    pub pa: u64,
    pub size: u64,
    pub kind: u8,
    pub loc: u8,
}

impl LibosRegion {
    fn write(&self, out: &mut [u8]) {
        out[0..8].copy_from_slice(&self.id8.to_le_bytes());
        out[8..16].copy_from_slice(&self.pa.to_le_bytes());
        out[16..24].copy_from_slice(&self.size.to_le_bytes());
        out[24] = self.kind;
        out[25] = self.loc;
        // bytes 26..32 are padding (stay zero).
    }
}

/// Build the one-page `libos` buffer: the four
/// `LibosMemoryRegionInitArgument` entries (LOGINIT, LOGINTR, LOGRM,
/// RMARGS), all CONTIGUOUS / SYSMEM. Cite `r535_gsp_libos_init`.
pub fn build_libos_args(
    loginit_pa: u64,
    logintr_pa: u64,
    logrm_pa: u64,
    rmargs_pa: u64,
) -> [u8; GSP_PAGE_SIZE as usize] {
    let regions = [
        LibosRegion {
            id8: libos_id8("LOGINIT"),
            pa: loginit_pa,
            size: LIBOS_LOG_SIZE,
            kind: LIBOS_KIND_CONTIGUOUS,
            loc: LIBOS_LOC_SYSMEM,
        },
        LibosRegion {
            id8: libos_id8("LOGINTR"),
            pa: logintr_pa,
            size: LIBOS_LOG_SIZE,
            kind: LIBOS_KIND_CONTIGUOUS,
            loc: LIBOS_LOC_SYSMEM,
        },
        LibosRegion {
            id8: libos_id8("LOGRM"),
            pa: logrm_pa,
            size: LIBOS_LOG_SIZE,
            kind: LIBOS_KIND_CONTIGUOUS,
            loc: LIBOS_LOC_SYSMEM,
        },
        LibosRegion {
            id8: libos_id8("RMARGS"),
            pa: rmargs_pa,
            size: GSP_PAGE_SIZE,
            kind: LIBOS_KIND_CONTIGUOUS,
            loc: LIBOS_LOC_SYSMEM,
        },
    ];
    let mut b = [0u8; GSP_PAGE_SIZE as usize];
    for (i, r) in regions.iter().enumerate() {
        r.write(&mut b[i * LIBOS_REGION_ARG_SIZE..(i + 1) * LIBOS_REGION_ARG_SIZE]);
    }
    b
}

/// Fill a contiguous page-table array in place: `ptes[i] = base_pa +
/// i*GSP_PAGE_SIZE` for `ceil(size/GSP_PAGE_SIZE)` entries. Used both
/// for the log buffers' embedded PTE arrays and the shared region's
/// self-map. Cite `gsp.c:1463 create_pte_array`.
pub fn create_pte_array(ptes: &mut [u64], base_pa: u64, size: u64) {
    let num_pages = size.div_ceil(GSP_PAGE_SIZE) as usize;
    for (i, pte) in ptes.iter_mut().take(num_pages).enumerate() {
        *pte = base_pa + (i as u64) * GSP_PAGE_SIZE;
    }
}
