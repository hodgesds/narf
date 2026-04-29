//! Per-process user-mode trampoline page.
//!
//! Closes the Ring-3 → kernel call gap documented in
//! `specification/spec.md` §8 option (1):
//!
//! - The PE loader allocates one user-RX page in the WinProcess AS.
//! - The page contains one fixed-size stub per registered Win32
//!   thunk, indexed by stable thunk id. Each stub is 16 bytes —
//!   small enough that 256 thunks fit in one page (currently we
//!   ship 4, so the rest of the page is NOP padding).
//! - IAT slots get patched with `trampoline_va + id * 16` instead
//!   of a kernel function address. A PE caller's
//!   `call qword ptr [iat]` lands inside its own user-RX page,
//!   the stub fires `syscall` / `svc`, the kernel-side
//!   `SYS_WIN_THUNK` handler dispatches by id, and the stub's
//!   `ret` returns control to the PE caller.
//!
//! ## amd64 stub (16 bytes)
//!
//! ```text
//! mov r10, rcx     ; 49 89 ca         (3) — preserve MS-x64 arg0
//!                  ;                       across syscall (rcx is
//!                  ;                       clobbered with rip).
//! mov eax, <id>    ; b8 XX XX XX XX  (5)
//! syscall          ; 0f 05            (2)
//! ret              ; c3               (1)
//! nop x 5          ; 90 90 90 90 90  (5) — pad to 16 B.
//! ```
//!
//! The kernel-side handler reads the thunk id from `rax`, the
//! Win32 first arg from `r10` (because amd64 `syscall` clobbers
//! `rcx`), and the rest of the MS-x64 args from `rdx` / `r8` /
//! `r9` / `[rsp + 0x28..]` — same shape Linux uses for syscall
//! args, mirroring the trick `r10 = arg4`.
//!
//! ## aarch64 stub (16 bytes)
//!
//! ```text
//! movz w8, #<id>   ; XX XX 80 52     (4) — syscall number in w8
//!                  ;                       (Linux convention; Win
//!                  ;                       on ARM64 has no native
//!                  ;                       syscall convention so
//!                  ;                       we pick one for parity).
//! svc #0           ; 01 00 00 d4     (4)
//! ret              ; c0 03 5f d6     (4)
//! nop              ; 1f 20 03 d5     (4) — alignment padding.
//! ```
//!
//! AAPCS64's `x0..x3` (the first 4 Win32 ARM64 args) are not
//! clobbered by `svc`, so no register-shuffle prologue is needed.
//! The handler reads `x8` for the id and `x0..x3` for args.

use alloc::vec::Vec;

/// Bytes per trampoline stub. Same on both arches by design — keeps
/// `trampoline_offset(id) = id * STUB_BYTES` arch-independent.
pub const STUB_BYTES: usize = 16;

/// Maximum thunk-id this trampoline scheme can address. 4 KiB page
/// / 16 B per stub = 256 stubs. M0 ships 4 thunks; an entire kernel32
/// surface comfortably fits.
pub const MAX_THUNKS: usize = 4096 / STUB_BYTES;

/// Offset within the trampoline page of the stub for thunk id `id`.
#[inline]
pub const fn trampoline_offset(id: u16) -> usize {
    (id as usize) * STUB_BYTES
}

/// Build a trampoline page worth of stubs for the first `num_thunks`
/// ids. Returns a `Vec<u8>` of exactly 4 KiB so the loader can
/// `copy_nonoverlapping` it into the freshly-allocated user-RX
/// frame.
///
/// Panics if `num_thunks > MAX_THUNKS`.
pub fn build_amd64(num_thunks: usize) -> Vec<u8> {
    assert!(num_thunks <= MAX_THUNKS, "too many thunks for one trampoline page");
    let mut page = alloc::vec![0x90u8; 4096]; // NOP fill so any
                                              // mis-targeted call
                                              // lands on a NOP slide
                                              // until the next stub.
    for id in 0..num_thunks {
        let off = trampoline_offset(id as u16);
        emit_stub_amd64(&mut page[off..off + STUB_BYTES], id as u32);
    }
    page
}

/// Same as [`build_amd64`] but for aarch64.
pub fn build_aarch64(num_thunks: usize) -> Vec<u8> {
    assert!(num_thunks <= MAX_THUNKS, "too many thunks for one trampoline page");
    let mut page = alloc::vec![0u8; 4096];
    // Pre-fill with `nop` (0xd503201f, little-endian) so off-by-one
    // landings hit a NOP slide rather than 0x00000000 (UDF on ARM64).
    for chunk in page.chunks_exact_mut(4) {
        chunk.copy_from_slice(&0xd503_201fu32.to_le_bytes());
    }
    for id in 0..num_thunks {
        let off = trampoline_offset(id as u16);
        emit_stub_aarch64(&mut page[off..off + STUB_BYTES], id as u16);
    }
    page
}

fn emit_stub_amd64(stub: &mut [u8], id: u32) {
    debug_assert_eq!(stub.len(), STUB_BYTES);
    // mov r10, rcx
    stub[0] = 0x49;
    stub[1] = 0x89;
    stub[2] = 0xCA;
    // mov eax, imm32 (id)
    stub[3] = 0xB8;
    stub[4..8].copy_from_slice(&id.to_le_bytes());
    // syscall
    stub[8] = 0x0F;
    stub[9] = 0x05;
    // ret
    stub[10] = 0xC3;
    // nop x 5
    for b in &mut stub[11..16] {
        *b = 0x90;
    }
}

fn emit_stub_aarch64(stub: &mut [u8], id: u16) {
    debug_assert_eq!(stub.len(), STUB_BYTES);
    // movz w8, #<id>  →  0x52800008 | (id << 5)
    //   sf=0, opc=10 (movz), hw=00, imm16=id, Rd=8 (w8)
    let movz: u32 = 0x52_80_00_08 | ((id as u32) << 5);
    stub[0..4].copy_from_slice(&movz.to_le_bytes());
    // svc #0  →  0xd4000001
    stub[4..8].copy_from_slice(&0xd400_0001u32.to_le_bytes());
    // ret  →  0xd65f03c0
    stub[8..12].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
    // nop  →  0xd503201f
    stub[12..16].copy_from_slice(&0xd503_201fu32.to_le_bytes());
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn amd64_stub_byte_layout() {
        let page = build_amd64(2);
        assert_eq!(page.len(), 4096);
        // Stub #0 with id 0.
        let s0 = &page[..STUB_BYTES];
        // mov r10, rcx
        assert_eq!(&s0[0..3], &[0x49, 0x89, 0xCA]);
        // mov eax, 0
        assert_eq!(s0[3], 0xB8);
        assert_eq!(&s0[4..8], &[0, 0, 0, 0]);
        // syscall
        assert_eq!(&s0[8..10], &[0x0F, 0x05]);
        // ret
        assert_eq!(s0[10], 0xC3);
        // nop x 5
        assert_eq!(&s0[11..16], &[0x90; 5]);

        // Stub #1 with id 1.
        let s1 = &page[STUB_BYTES..STUB_BYTES * 2];
        assert_eq!(&s1[0..3], &[0x49, 0x89, 0xCA]);
        assert_eq!(s1[3], 0xB8);
        assert_eq!(&s1[4..8], &[1, 0, 0, 0]);
    }

    #[test]
    fn amd64_unused_slots_are_nop_filled() {
        let page = build_amd64(1);
        // Bytes past the one stub are 0x90 (NOP) so a mis-targeted
        // call lands on a NOP slide instead of arbitrary data.
        for &b in &page[STUB_BYTES..] {
            assert_eq!(b, 0x90);
        }
    }

    #[test]
    fn aarch64_stub_decodes_to_movz_svc_ret_nop() {
        let page = build_aarch64(3);
        assert_eq!(page.len(), 4096);
        for id in 0..3u16 {
            let off = trampoline_offset(id);
            let stub = &page[off..off + STUB_BYTES];
            let movz = u32::from_le_bytes(stub[0..4].try_into().unwrap());
            // movz w8, #id  →  base 0x52800008 with imm16 in bits 5..21.
            assert_eq!(movz & 0xFFE0_001F, 0x5280_0008);
            assert_eq!((movz >> 5) & 0xFFFF, id as u32);
            // svc #0
            let svc = u32::from_le_bytes(stub[4..8].try_into().unwrap());
            assert_eq!(svc, 0xd400_0001);
            // ret
            let ret = u32::from_le_bytes(stub[8..12].try_into().unwrap());
            assert_eq!(ret, 0xd65f_03c0);
            // nop
            let nop = u32::from_le_bytes(stub[12..16].try_into().unwrap());
            assert_eq!(nop, 0xd503_201f);
        }
    }

    #[test]
    fn aarch64_unused_slots_are_nop_filled() {
        let page = build_aarch64(0);
        for chunk in page.chunks_exact(4) {
            let w = u32::from_le_bytes(chunk.try_into().unwrap());
            assert_eq!(w, 0xd503_201f);
        }
    }

    #[test]
    fn offset_is_id_times_stub_bytes() {
        assert_eq!(trampoline_offset(0), 0);
        assert_eq!(trampoline_offset(1), 16);
        assert_eq!(trampoline_offset(255), 4080);
    }
}
