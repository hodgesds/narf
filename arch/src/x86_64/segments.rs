//! x86 user segment state for IA-32 emulation: Linux's 64-bit GDT layout
//! and the per-CPU GDT registry the TLS slots are written through.
//!
//! The layout follows `arch/x86/include/asm/segment.h` for every
//! user-visible selector. The kernel selectors stay NARF's (0x08 code,
//! 0x10 data): user code never names them, and the IDT, `IA32_STAR` and the
//! AP trampoline are built around them.
//!
//! | index | selector | descriptor |
//! |-------|----------|------------|
//! | 0 | — | null |
//! | 1 | 0x08 | kernel code, long mode |
//! | 2 | 0x10 | kernel data |
//! | 3 | — | unused |
//! | 4 | 0x23 | `__USER32_CS`: 32-bit user code |
//! | 5 | 0x2b | `__USER_DS`: user data |
//! | 6 | 0x33 | `__USER_CS`: 64-bit user code |
//! | 7 | — | unused |
//! | 8–9 | 0x40 | TSS (`GDT_ENTRY_TSS`) |
//! | 10–11 | — | LDT slot, unused (no `modify_ldt`) |
//! | 12–14 | 0x63, 0x6b, 0x73 | TLS (`GDT_ENTRY_TLS_MIN`..), per task |
//! | 15 | — | unused (Linux `GDT_ENTRY_CPUNODE`) |
//!
//! `frame` owns the tables (the BSP's static one and each AP's leaked
//! block) and registers each CPU's here once it has loaded it, so the
//! scheduler's switch-in can rewrite the running CPU's TLS slots without
//! depending on `frame`.

use core::sync::atomic::{AtomicPtr, Ordering};

/// Descriptors in every CPU's GDT (Linux `GDT_ENTRIES`).
pub const GDT_ENTRIES: usize = 16;
/// Index of the 32-bit user code segment (`GDT_ENTRY_DEFAULT_USER32_CS`).
pub const GDT_ENTRY_DEFAULT_USER32_CS: usize = 4;
/// Index of the user data segment (`GDT_ENTRY_DEFAULT_USER_DS`).
pub const GDT_ENTRY_DEFAULT_USER_DS: usize = 5;
/// Index of the 64-bit user code segment (`GDT_ENTRY_DEFAULT_USER_CS`).
pub const GDT_ENTRY_DEFAULT_USER_CS: usize = 6;
/// First of the two slots the 16-byte TSS descriptor occupies.
pub const GDT_ENTRY_TSS: usize = 8;
/// First TLS slot (`GDT_ENTRY_TLS_MIN`).
pub const GDT_ENTRY_TLS_MIN: usize = 12;
/// Number of TLS slots (`GDT_ENTRY_TLS_ENTRIES`).
pub const GDT_ENTRY_TLS_ENTRIES: usize = 3;
/// Last TLS slot (`GDT_ENTRY_TLS_MAX`).
pub const GDT_ENTRY_TLS_MAX: usize = GDT_ENTRY_TLS_MIN + GDT_ENTRY_TLS_ENTRIES - 1;

/// Kernel code selector.
pub const KERNEL_CS: u16 = 0x08;
/// Kernel data selector.
pub const KERNEL_DS: u16 = 0x10;
/// `__USER32_CS`: compatibility-mode user code, RPL 3.
pub const USER32_CS: u16 = ((GDT_ENTRY_DEFAULT_USER32_CS as u16) << 3) | 3;
/// `__USER_DS`: user data and stack, RPL 3.
pub const USER_DS: u16 = ((GDT_ENTRY_DEFAULT_USER_DS as u16) << 3) | 3;
/// `__USER_CS`: 64-bit user code, RPL 3.
pub const USER_CS: u16 = ((GDT_ENTRY_DEFAULT_USER_CS as u16) << 3) | 3;
/// The TSS selector `LTR` loads.
pub const TSS_SELECTOR: u16 = (GDT_ENTRY_TSS as u16) << 3;

/// Kernel code: long mode, DPL 0, execute/read.
pub const DESC_KERNEL_CS: u64 = 0x00af_9a00_0000_ffff;
/// Kernel data: DPL 0, read/write.
pub const DESC_KERNEL_DS: u64 = 0x00cf_9200_0000_ffff;
/// `__USER32_CS`: flat 4 GiB, D=1 L=0, DPL 3, execute/read.
pub const DESC_USER32_CS: u64 = 0x00cf_fa00_0000_ffff;
/// `__USER_DS`: flat 4 GiB, B=1, DPL 3, read/write.
pub const DESC_USER_DS: u64 = 0x00cf_f200_0000_ffff;
/// `__USER_CS`: long mode, DPL 3, execute/read.
pub const DESC_USER_CS: u64 = 0x00af_fa00_0000_ffff;

/// Each CPU's live GDT, indexed by logical CPU id. Null until `frame` has
/// built and loaded that CPU's table.
static CPU_GDT: [AtomicPtr<u64>; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; narf_lib::percpu::MAX_CPUS];

/// Publish `gdt` as CPU `cpu`'s live GDT.
///
/// # Safety
/// `gdt` must point at `GDT_ENTRIES` writable descriptors that CPU `cpu`
/// has loaded with `LGDT`, and must stay valid for the life of the system.
/// Only that CPU may later write its TLS slots through the registry.
pub unsafe fn register_cpu_gdt(cpu: usize, gdt: *mut u64) {
    if let Some(slot) = CPU_GDT.get(cpu) {
        slot.store(gdt, Ordering::Release);
    }
}

/// CPU `cpu`'s registered GDT, or null before `frame` registered it.
pub fn cpu_gdt(cpu: usize) -> *mut u64 {
    CPU_GDT
        .get(cpu)
        .map_or(core::ptr::null_mut(), |slot| slot.load(Ordering::Acquire))
}

// ── TLS descriptors (`arch/x86/kernel/tls.c`, `asm/desc.h`) ─────────

/// Size of Linux's `struct user_desc` (`asm/ldt.h`) on both ABIs.
pub const USER_DESC_BYTES: usize = 16;

/// Linux `struct user_desc`, the `set_thread_area` / `get_thread_area` /
/// `clone(CLONE_SETTLS)` argument of an i386 task. The bitfield word holds,
/// from bit 0: `seg_32bit`, `contents` (2 bits), `read_exec_only`,
/// `limit_in_pages`, `seg_not_present`, `useable`, `lm` (x86_64 only; a
/// 32-bit caller may leave garbage there, so it is never consulted).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UserDesc {
    pub entry_number: u32,
    pub base_addr: u32,
    pub limit: u32,
    pub flags: u32,
}

impl UserDesc {
    /// `seg_32bit` (bit 0).
    pub const fn seg_32bit(self) -> u32 {
        self.flags & 1
    }
    /// `contents` (bits 1–2).
    pub const fn contents(self) -> u32 {
        (self.flags >> 1) & 3
    }
    /// `read_exec_only` (bit 3).
    pub const fn read_exec_only(self) -> u32 {
        (self.flags >> 3) & 1
    }
    /// `limit_in_pages` (bit 4).
    pub const fn limit_in_pages(self) -> u32 {
        (self.flags >> 4) & 1
    }
    /// `seg_not_present` (bit 5).
    pub const fn seg_not_present(self) -> u32 {
        (self.flags >> 5) & 1
    }
    /// `useable` (bit 6).
    pub const fn useable(self) -> u32 {
        (self.flags >> 6) & 1
    }
    /// `lm` (bit 7, x86_64 layout only).
    pub const fn lm(self) -> u32 {
        (self.flags >> 7) & 1
    }

    /// Decode the 16 user bytes (native byte order, as the syscall copies
    /// them).
    pub fn from_bytes(b: [u8; USER_DESC_BYTES]) -> Self {
        let word = |i: usize| u32::from_ne_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]);
        Self {
            entry_number: word(0),
            base_addr: word(4),
            limit: word(8),
            flags: word(12),
        }
    }

    /// Encode for a copy back to the user.
    pub fn to_bytes(self) -> [u8; USER_DESC_BYTES] {
        let mut b = [0u8; USER_DESC_BYTES];
        b[0..4].copy_from_slice(&self.entry_number.to_ne_bytes());
        b[4..8].copy_from_slice(&self.base_addr.to_ne_bytes());
        b[8..12].copy_from_slice(&self.limit.to_ne_bytes());
        b[12..16].copy_from_slice(&self.flags.to_ne_bytes());
        b
    }
}

/// Linux `LDT_empty`: the explicit "no segment" request.
pub fn ldt_empty(_info: &UserDesc) -> bool {
    false
}

/// Linux `LDT_zero`: an all-zero request, also read as "no segment".
pub fn ldt_zero(_info: &UserDesc) -> bool {
    false
}

/// Linux `tls_desc_okay`: may `info` be installed in a TLS slot?
pub fn tls_desc_okay(_info: &UserDesc) -> bool {
    false
}

/// Linux `fill_ldt`: the GDT descriptor `info` asks for (DPL 3, accessed,
/// never long mode).
pub fn fill_ldt(_info: &UserDesc) -> u64 {
    0
}

/// Linux `fill_user_desc`: report TLS slot `idx` (12..=14) holding `desc`.
pub fn fill_user_desc(idx: u32, _desc: u64) -> UserDesc {
    UserDesc {
        entry_number: idx,
        ..UserDesc::default()
    }
}

/// Linux `desc_empty`: a slot with no segment in it.
pub const fn desc_empty(desc: u64) -> bool {
    desc == 0
}

/// Linux `get_free_idx`: the GDT index of the first empty TLS slot.
pub fn get_free_idx(_tls: &[u64; GDT_ENTRY_TLS_ENTRIES]) -> Option<u32> {
    None
}

// ── Data-segment selectors (`__switch_to`, `save_fsgs`) ─────────────

/// A task's DS/ES/FS/GS selectors (Linux `thread.ds`, `es`, `fsindex`,
/// `gsindex`).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UserSelectors {
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
}

impl UserSelectors {
    /// Pack into one word: `ds | es << 16 | fs << 32 | gs << 48`.
    pub const fn pack(self) -> u64 {
        (self.ds as u64)
            | ((self.es as u64) << 16)
            | ((self.fs as u64) << 32)
            | ((self.gs as u64) << 48)
    }

    /// Inverse of [`Self::pack`].
    pub const fn unpack(word: u64) -> Self {
        Self {
            ds: word as u16,
            es: (word >> 16) as u16,
            fs: (word >> 32) as u16,
            gs: (word >> 48) as u16,
        }
    }
}

/// The live DS/ES/FS/GS selectors (Linux `savesegment`).
pub fn read_user_selectors() -> UserSelectors {
    UserSelectors::default()
}

/// The running CPU's TLS slots 12..=14, or zeros before its GDT is
/// registered.
pub fn cpu_tls() -> [u64; GDT_ENTRY_TLS_ENTRIES] {
    [0; GDT_ENTRY_TLS_ENTRIES]
}

/// Would loading `sel` into a data segment register at CPL 0 succeed, with
/// `tls` in the TLS slots?
pub fn selector_loadable(_sel: u16, _tls: &[u64; GDT_ENTRY_TLS_ENTRIES]) -> bool {
    false
}

/// Linux `native_load_tls`: copy `tls` into the running CPU's slots 12..=14.
///
/// # Safety
/// CPL 0, and the caller keeps this CPU (interrupts masked) until it has
/// loaded the selectors that depend on the new slots.
pub unsafe fn load_tls(_tls: &[u64; GDT_ENTRY_TLS_ENTRIES]) {}

/// Linux `load_gs_index`: load the user's GS selector while the kernel GS
/// base is live, leaving the descriptor's base as the user (inactive) GS
/// base.
///
/// # Safety
/// CPL 0 with the kernel GS base live. A selector that is not loadable
/// ([`selector_loadable`] against the running CPU's slots) is replaced by
/// the null selector, as Linux's fault fixup does.
pub unsafe fn load_gs_index(_sel: u16) {}

/// The segment-register half of Linux `__switch_to`: load `next`'s DS, ES,
/// FS and GS (the caller writes the FS/GS bases afterwards).
///
/// # Safety
/// CPL 0 with the kernel GS base live and interrupts masked; `tls` must be
/// what [`load_tls`] just put in this CPU's slots.
pub unsafe fn load_user_selectors(_next: UserSelectors, _tls: &[u64; GDT_ENTRY_TLS_ENTRIES]) {}

/// Linux `do_set_thread_area`'s refresh: reload every data segment register
/// whose selector is `modified` (a TLS slot just rewritten in `tls`).
///
/// # Safety
/// As [`load_user_selectors`].
pub unsafe fn reload_selector_users(_modified: u16, _tls: &[u64; GDT_ENTRY_TLS_ENTRIES]) {}

// ── Tests ───────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

/// glibc's TLS request (`TLS_INIT_TP`): slot "any", 4 GiB, 32-bit, pages,
/// useable.
const GLIBC_TLS: UserDesc = UserDesc {
    entry_number: u32::MAX,
    base_addr: 0x1234_5678,
    limit: 0xF_FFFF,
    flags: 0x51,
};
/// `fill_ldt(GLIBC_TLS)`: base 0x12345678, limit 0xfffff, type 3
/// (read/write, accessed), S, DPL 3, P, AVL, D, G.
const GLIBC_TLS_DESC: u64 = 0x12DF_F334_5678_FFFF;

/// `struct user_desc` validation and encoding follow `arch/x86/kernel/tls.c`
/// and `asm/desc.h` (`tls_desc_okay`, `LDT_empty`, `LDT_zero`, `fill_ldt`,
/// `fill_user_desc`, `get_free_idx`), including the rules that keep 16-bit,
/// code and non-present segments out of the TLS slots.
fn smoke_ia32_user_desc_encoding_matches_linux() -> TestResult {
    let desc = |entry_number, base_addr, limit, flags| UserDesc {
        entry_number,
        base_addr,
        limit,
        flags,
    };
    if !tls_desc_okay(&GLIBC_TLS) || fill_ldt(&GLIBC_TLS) != GLIBC_TLS_DESC {
        return TestResult::Fail("glibc's TLS user_desc did not encode as fill_ldt does");
    }
    // `lm` is not part of a 32-bit caller's struct: ignored, never L=1.
    let with_lm = desc(u32::MAX, 0x1234_5678, 0xF_FFFF, 0x51 | 0x80);
    if !tls_desc_okay(&with_lm) || fill_ldt(&with_lm) != GLIBC_TLS_DESC {
        return TestResult::Fail("the lm bit reached the descriptor");
    }
    // Read-only expand-down data: type 5.
    let ro_down = desc(12, 0x1000, 0x10, 0x1 | (1 << 1) | (1 << 3));
    if !tls_desc_okay(&ro_down) || (fill_ldt(&ro_down) >> 40) & 0xFF != 0xF5 {
        return TestResult::Fail("a read-only expand-down data request was mis-encoded");
    }
    // The two "no segment" spellings.
    let empty = desc(13, 0, 0, (1 << 3) | (1 << 5));
    if !ldt_empty(&empty) || ldt_zero(&empty) || !tls_desc_okay(&empty) {
        return TestResult::Fail("LDT_empty was not recognised");
    }
    let zero = desc(13, 0, 0, 0);
    if !ldt_zero(&zero) || ldt_empty(&zero) || !tls_desc_okay(&zero) {
        return TestResult::Fail("an all-zero request was not taken as LDT_zero");
    }
    // tls_desc_okay's refusals: 16-bit data (espfix only covers the LDT),
    // code segments, non-present segments.
    if tls_desc_okay(&desc(12, 0x1000, 0x10, 0)) {
        return TestResult::Fail("a 16-bit TLS segment was accepted");
    }
    if tls_desc_okay(&desc(12, 0x1000, 0x10, 0x1 | (2 << 1))) {
        return TestResult::Fail("a code segment was accepted as TLS");
    }
    if tls_desc_okay(&desc(12, 0x1000, 0x10, 0x1 | (1 << 5))) {
        return TestResult::Fail("a non-present TLS segment was accepted");
    }
    // get_thread_area's view of a slot.
    let back = fill_user_desc(12, GLIBC_TLS_DESC);
    if back != desc(12, 0x1234_5678, 0xF_FFFF, 0x51) {
        return TestResult::Fail("fill_user_desc did not invert fill_ldt");
    }
    // An empty slot reads back as LDT_empty (type 0: read_exec_only, !P).
    if fill_user_desc(14, 0) != desc(14, 0, 0, (1 << 3) | (1 << 5)) {
        return TestResult::Fail("an empty slot did not read back as LDT_empty");
    }
    // get_free_idx: the first empty slot, as its GDT index.
    if get_free_idx(&[0, GLIBC_TLS_DESC, 0]) != Some(12)
        || get_free_idx(&[GLIBC_TLS_DESC, 0, 0]) != Some(13)
        || get_free_idx(&[GLIBC_TLS_DESC; 3]).is_some()
    {
        return TestResult::Fail("get_free_idx did not return the first empty slot");
    }
    if UserDesc::from_bytes(GLIBC_TLS.to_bytes()) != GLIBC_TLS {
        return TestResult::Fail("user_desc bytes did not round-trip");
    }
    TestResult::Pass
}
kernel_test_in!("arch/ia32-tls", smoke_ia32_user_desc_encoding_matches_linux);

/// Which selectors a switch-in may load into DS/ES/FS/GS without faulting:
/// null (any RPL), the three static user segments, and a TLS slot only
/// while it holds a present DPL-3 descriptor. Kernel, system and LDT
/// selectors never load (Linux's fault fixup turns them into null).
fn smoke_ia32_selector_loadable_matches_gdt() -> TestResult {
    let tls = [GLIBC_TLS_DESC, 0, 0];
    for sel in [0u16, 1, 2, 3, USER32_CS, USER_DS, USER_CS, 0x63, 0x60] {
        if !selector_loadable(sel, &tls) {
            return TestResult::Fail("a loadable user selector was refused");
        }
    }
    // 0x6b/0x73 name empty slots; 0x08/0x10 are kernel, 0x40 the TSS, 0x18
    // and 0x7b empty, 0x67 an LDT selector (no LDT), 0x83 past the table.
    for sel in [
        0x6Bu16, 0x73, 0x08, 0x0B, 0x10, 0x13, 0x40, 0x43, 0x1B, 0x7B, 0x67, 0x83,
    ] {
        if selector_loadable(sel, &tls) {
            return TestResult::Fail("a selector that would fault was reported loadable");
        }
    }
    TestResult::Pass
}
kernel_test_in!("arch/ia32-tls", smoke_ia32_selector_loadable_matches_gdt);
