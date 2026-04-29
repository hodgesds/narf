//! Win32 process / thread personality: PEB + TEB.
//!
//! On Win32 amd64 the segment register `gs` is programmed to point at
//! the TEB, and the PEB pointer lives at TEB+0x60. On Win32 ARM64 the
//! same TEB layout is reached through `TPIDR_EL0` instead of `gs`.
//! A PE binary's CRT (`__scrt_*`) reaches `gs:[0x60]` (or
//! `[TPIDR_EL0+0x60]`) before it does much else, so the loader must
//! produce both pages before user-mode entry or the first PE
//! instruction faults.
//!
//! This module is intentionally byte-level: we do not declare full
//! Rust structs for PEB / TEB. Microsoft's structures have hundreds
//! of fields whose layout has drifted across kernels we don't care
//! about; reproducing them would just add maintenance load. Instead
//! we expose the *offsets* of the fields the M0 surface needs and
//! write into them with `put_u64` / `put_u32` / `put_u16`.
//!
//! All field offsets are stable across every Windows 10 / 11 build
//! the M0 thunk surface targets — they're the original NT layout.

pub const PAGE: usize = 4096;

// ── PEB field offsets (Win32 amd64 / ARM64) ──────────────────────
//
// Source: Microsoft public symbols + ReactOS' `pebteb.h`. Stable
// since NT 6.0; the trailing tail past 0x140-ish has churned but
// nothing M0 reads has moved.

pub const PEB_INHERITED_ADDRESS_SPACE: usize = 0x000; // u8
pub const PEB_BEING_DEBUGGED:          usize = 0x002; // u8
pub const PEB_IMAGE_BASE_ADDRESS:      usize = 0x010; // u64
pub const PEB_LDR:                     usize = 0x018; // u64 (PEB_LDR_DATA*)
pub const PEB_PROCESS_PARAMETERS:      usize = 0x020; // u64 (RTL_USER_PROCESS_PARAMETERS*)
pub const PEB_PROCESS_HEAP:            usize = 0x030; // u64 (HANDLE)
pub const PEB_OS_MAJOR_VERSION:        usize = 0x118; // u32
pub const PEB_OS_MINOR_VERSION:        usize = 0x11C; // u32
pub const PEB_OS_BUILD_NUMBER:         usize = 0x120; // u16

// ── TEB field offsets (Win32 amd64 / ARM64) ──────────────────────
//
// The first 0x38 bytes are the NT_TIB; the PEB pointer is at 0x60.

pub const TEB_TIB_EXCEPTION_LIST: usize = 0x000; // u64 (legacy SEH chain head)
pub const TEB_TIB_STACK_BASE:     usize = 0x008; // u64 (HIGH address of user stack)
pub const TEB_TIB_STACK_LIMIT:    usize = 0x010; // u64 (LOW address of user stack)
pub const TEB_TIB_SUBSYSTEM_TIB:  usize = 0x018; // u64 (unused on NT)
pub const TEB_TIB_FIBER_DATA:     usize = 0x020; // u64
pub const TEB_TIB_USER_POINTER:   usize = 0x028; // u64
pub const TEB_TIB_SELF:           usize = 0x030; // u64 (== &TEB)
pub const TEB_CLIENT_ID_PROCESS:  usize = 0x040; // u64
pub const TEB_CLIENT_ID_THREAD:   usize = 0x048; // u64
pub const TEB_PEB:                usize = 0x060; // u64 (== &PEB)

// ── Default Win32 VAs ────────────────────────────────────────────
//
// Win32 historically places PEB / TEB high in user space. The
// addresses below are below the canonical-low-half boundary
// (0x0000_8000_0000_0000) and well above any plausible image base
// (typically 0x0000_0001_4000_0000 for /HIGHENTROPYVA executables).
//
// M1 will randomise these — Windows ASLR puts both PEB and TEB at
// per-process random VAs — but a fixed pair is fine for M0.

pub const DEFAULT_PEB_VA:    u64 = 0x0000_7FFE_0000_0000;
pub const DEFAULT_TEB_VA:    u64 = 0x0000_7FFD_F000_0000;
pub const DEFAULT_STACK_TOP: u64 = 0x0000_7FFD_E000_0000; // high — RSP starts here
pub const DEFAULT_STACK_LEN: u64 = 0x100_000;             // 1 MiB — Win32 default
pub const DEFAULT_STACK_BASE: u64 = DEFAULT_STACK_TOP - DEFAULT_STACK_LEN;

/// Bundle of VAs the loader picks for a fresh `WinProcess`. The
/// stack VAs are populated into `TEB.NT_TIB.StackBase / StackLimit`
/// at TEB-init time so a Win32 caller's `__chkstk` sees the right
/// range; the loader does not allocate the stack itself (the
/// spawner does, mirroring `narf_userspace`'s split between
/// `load_user_process` and the executor's first-entry stack
/// allocation).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    pub peb_va:     u64,
    pub teb_va:     u64,
    pub image_base: u64,
    pub stack_base: u64, // LOW address — TEB.NT_TIB.StackLimit
    pub stack_top:  u64, // HIGH address — TEB.NT_TIB.StackBase
    pub pid:        u64,
    pub tid:        u64,
}

impl Layout {
    pub const fn defaults(image_base: u64, pid: u64, tid: u64) -> Self {
        Self {
            peb_va:     DEFAULT_PEB_VA,
            teb_va:     DEFAULT_TEB_VA,
            image_base,
            stack_base: DEFAULT_STACK_BASE,
            stack_top:  DEFAULT_STACK_TOP,
            pid,
            tid,
        }
    }
}

#[inline]
fn put_u64(buf: &mut [u8], off: usize, val: u64) {
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

#[inline]
fn put_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

#[inline]
fn put_u16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

/// Populate a freshly-zeroed PEB page. M0 fills the bare minimum:
/// `ImageBaseAddress` (so a CRT that walks the image headers from
/// PEB knows where to look) and a synthetic OS version high enough
/// to satisfy modern PE binaries that gate on `OSMajorVersion >= 6`.
///
/// `Ldr`, `ProcessParameters`, and `ProcessHeap` stay zero. Any PE
/// that dereferences them faults — that is intentional. The M1
/// surface fills them in once the loader-data, environment-block,
/// and HeapAlloc thunks land; until then we want to fail loudly
/// rather than make up zero-pointers.
pub fn init_peb(peb: &mut [u8; PAGE], layout: Layout) {
    put_u64(peb, PEB_IMAGE_BASE_ADDRESS, layout.image_base);
    // Win10 1809+ (build 17763) is the floor for any modern toolchain;
    // we report a concrete late-Win10 build to satisfy version checks
    // without claiming Win11 (which gates on a different
    // ProcessorFeatureSet field we haven't filled in).
    put_u32(peb, PEB_OS_MAJOR_VERSION, 10);
    put_u32(peb, PEB_OS_MINOR_VERSION, 0);
    put_u16(peb, PEB_OS_BUILD_NUMBER, 19045);
}

/// Populate a freshly-zeroed TEB page. M0 fills the NT_TIB stack
/// fields, the self-pointer (Win32 code does
/// `mov rax, gs:[0x30]` to materialise its own TEB pointer), the
/// ClientId pair, and the PEB pointer that sits at gs:[0x60].
pub fn init_teb(teb: &mut [u8; PAGE], layout: Layout) {
    put_u64(teb, TEB_TIB_STACK_BASE,    layout.stack_top);
    put_u64(teb, TEB_TIB_STACK_LIMIT,   layout.stack_base);
    put_u64(teb, TEB_TIB_SELF,          layout.teb_va);
    put_u64(teb, TEB_CLIENT_ID_PROCESS, layout.pid);
    put_u64(teb, TEB_CLIENT_ID_THREAD,  layout.tid);
    put_u64(teb, TEB_PEB,               layout.peb_va);
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn read_u64(buf: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
    }
    fn read_u32(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }
    fn read_u16(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
    }

    fn layout_for_test() -> Layout {
        Layout {
            peb_va:     0x7FFE_0000,
            teb_va:     0x7FFD_F000,
            image_base: 0x1_4000_0000,
            stack_base: 0x7FF7_0000,
            stack_top:  0x7FF8_0000,
            pid:        0xCAFE,
            tid:        0xBABE,
        }
    }

    #[test]
    fn peb_image_base_at_offset_0x10() {
        let mut peb = [0u8; PAGE];
        init_peb(&mut peb, layout_for_test());
        assert_eq!(read_u64(&peb, PEB_IMAGE_BASE_ADDRESS), 0x1_4000_0000);
        assert_eq!(read_u32(&peb, PEB_OS_MAJOR_VERSION), 10);
        assert_eq!(read_u32(&peb, PEB_OS_MINOR_VERSION), 0);
        assert_eq!(read_u16(&peb, PEB_OS_BUILD_NUMBER), 19045);
    }

    #[test]
    fn teb_self_pointer_matches_va() {
        let mut teb = [0u8; PAGE];
        init_teb(&mut teb, layout_for_test());
        // The defining invariant of the TEB self-pointer: gs:[0x30]
        // must equal &TEB. Win32 code does `mov rax, gs:[0x30]` to
        // materialise its own TEB pointer — if this offset doesn't
        // hold the TEB VA, every Win32 thread breaks immediately.
        assert_eq!(read_u64(&teb, TEB_TIB_SELF), 0x7FFD_F000);
    }

    #[test]
    fn teb_peb_pointer_at_gs_60() {
        let mut teb = [0u8; PAGE];
        init_teb(&mut teb, layout_for_test());
        assert_eq!(read_u64(&teb, TEB_PEB), 0x7FFE_0000);
    }

    #[test]
    fn teb_stack_range_high_low_order() {
        let mut teb = [0u8; PAGE];
        init_teb(&mut teb, layout_for_test());
        // Win32 invariant: StackBase is the HIGH address (where RSP
        // starts), StackLimit is the LOW address. Crossing these
        // would make __chkstk think the stack grows the wrong
        // direction.
        let base  = read_u64(&teb, TEB_TIB_STACK_BASE);
        let limit = read_u64(&teb, TEB_TIB_STACK_LIMIT);
        assert!(base > limit);
        assert_eq!(base,  0x7FF8_0000);
        assert_eq!(limit, 0x7FF7_0000);
    }

    #[test]
    fn teb_client_id() {
        let mut teb = [0u8; PAGE];
        init_teb(&mut teb, layout_for_test());
        assert_eq!(read_u64(&teb, TEB_CLIENT_ID_PROCESS), 0xCAFE);
        assert_eq!(read_u64(&teb, TEB_CLIENT_ID_THREAD),  0xBABE);
    }

    #[test]
    fn untouched_fields_stay_zero() {
        let mut peb = [0u8; PAGE];
        init_peb(&mut peb, layout_for_test());
        // Ldr / ProcessParameters / ProcessHeap deliberately not
        // populated (M1 territory). Verify they stayed zero so a
        // future change that quietly fills them isn't masked.
        assert_eq!(read_u64(&peb, PEB_LDR), 0);
        assert_eq!(read_u64(&peb, PEB_PROCESS_PARAMETERS), 0);
        assert_eq!(read_u64(&peb, PEB_PROCESS_HEAP), 0);
    }

    #[test]
    fn defaults_make_sense() {
        let l = Layout::defaults(0x1_4000_0000, 1, 1);
        // Stack range must not overlap PEB / TEB — sanity check on
        // the constants chosen above.
        assert!(l.stack_top <= l.teb_va);
        assert!(l.teb_va < l.peb_va);
        // Stack is the documented Win32 default 1 MiB.
        assert_eq!(l.stack_top - l.stack_base, 0x100_000);
    }
}
