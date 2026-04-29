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
//! NARF's amd64 syscall gate is `int 0x80` (see
//! `frame/src/x86_64/trap.rs`). Convention: `rax` = syscall number,
//! `rdi/rsi/rdx/r10/r8/r9` = args 0..5. The MS-x64 caller put its
//! first arg in `rcx`, so we shuffle `rcx → rsi` (SysV arg1) and put
//! the thunk id in `rdi` (SysV arg0). The other MS-x64 arg regs
//! (`rdx`, `r8`, `r9`) already align with SysV positions so we
//! leave them alone.
//!
//! ```text
//! mov rsi, rcx     ; 48 89 ce         (3) — MS arg0 → SysV arg1
//! mov edi, <id>    ; bf XX XX XX XX  (5) — thunk id → SysV arg0
//! mov eax, SYS_WIN_THUNK ; b8 XX XX XX XX (5) — syscall number
//! int 0x80         ; cd 80            (2)
//! ret              ; c3               (1)
//! ```
//!
//! Total 16 bytes. The kernel handler then sees
//! `args.{arg0..arg5} = {thunk_id, MS arg0, MS arg1, _, MS arg2, MS arg3}`
//! and dispatches via [`crate::syscall::WinThunkHandler`].
//!
//! ## aarch64 stub (16 bytes)
//!
//! NARF's aarch64 syscall gate is `svc #0`. Convention: `x8` =
//! syscall number, `x0..x5` = args 0..5. AAPCS64 (= Win32 ARM64
//! ABI) puts the first 4 args in `x0..x3` natively, so we leave
//! them in place and put the thunk id in `x4` (SysV arg4 in NARF's
//! mapping).
//!
//! ```text
//! movz x4, #<id>           ; thunk id → SysV arg4
//! movz x8, SYS_WIN_THUNK   ; syscall number
//! svc #0
//! ret
//! ```
//!
//! Total 16 bytes (one 4-byte instruction each). The kernel handler
//! reads `args.{arg0..arg3} = Win32 args 0..3` and `args.arg4 = id`.

use alloc::vec::Vec;

use crate::syscall::SYS_WIN_THUNK;

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
    // mov rsi, rcx  →  48 89 ce
    stub[0] = 0x48;
    stub[1] = 0x89;
    stub[2] = 0xCE;
    // mov edi, imm32 (thunk id)  →  bf XX XX XX XX
    stub[3] = 0xBF;
    stub[4..8].copy_from_slice(&id.to_le_bytes());
    // mov eax, imm32 (SYS_WIN_THUNK)  →  b8 XX XX XX XX
    stub[8]  = 0xB8;
    stub[9..13].copy_from_slice(&SYS_WIN_THUNK.to_le_bytes());
    // int 0x80  →  cd 80
    stub[13] = 0xCD;
    stub[14] = 0x80;
    // ret  →  c3
    stub[15] = 0xC3;
}

fn emit_stub_aarch64(stub: &mut [u8], id: u16) {
    debug_assert_eq!(stub.len(), STUB_BYTES);
    // movz x4, #<id>  →  0xd2800004 | (id << 5)
    //   sf=1, opc=10 (movz), hw=00, imm16=id, Rd=4
    let movz_id: u32 = 0xD2_80_00_04 | ((id as u32) << 5);
    stub[0..4].copy_from_slice(&movz_id.to_le_bytes());
    // movz x8, #SYS_WIN_THUNK  →  0xd2800008 | (SYS_WIN_THUNK << 5)
    let movz_no: u32 = 0xD2_80_00_08 | ((SYS_WIN_THUNK as u32) << 5);
    stub[4..8].copy_from_slice(&movz_no.to_le_bytes());
    // svc #0  →  0xd4000001
    stub[8..12].copy_from_slice(&0xd400_0001u32.to_le_bytes());
    // ret  →  0xd65f03c0
    stub[12..16].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
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
        // mov rsi, rcx
        assert_eq!(&s0[0..3], &[0x48, 0x89, 0xCE]);
        // mov edi, 0
        assert_eq!(s0[3], 0xBF);
        assert_eq!(&s0[4..8], &[0, 0, 0, 0]);
        // mov eax, SYS_WIN_THUNK
        assert_eq!(s0[8], 0xB8);
        assert_eq!(&s0[9..13], &SYS_WIN_THUNK.to_le_bytes());
        // int 0x80
        assert_eq!(&s0[13..15], &[0xCD, 0x80]);
        // ret
        assert_eq!(s0[15], 0xC3);

        // Stub #1 with id 1: only the imm32 in the `mov edi, ...`
        // instruction differs.
        let s1 = &page[STUB_BYTES..STUB_BYTES * 2];
        assert_eq!(&s1[0..3], &[0x48, 0x89, 0xCE]);
        assert_eq!(s1[3], 0xBF);
        assert_eq!(&s1[4..8], &[1, 0, 0, 0]);
        assert_eq!(&s1[9..13], &SYS_WIN_THUNK.to_le_bytes());
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
    fn aarch64_stub_decodes_to_movz_movz_svc_ret() {
        let page = build_aarch64(3);
        assert_eq!(page.len(), 4096);
        for id in 0..3u16 {
            let off = trampoline_offset(id);
            let stub = &page[off..off + STUB_BYTES];
            // movz x4, #id  →  base 0xd2800004 with imm16 in bits 5..21.
            let movz_id = u32::from_le_bytes(stub[0..4].try_into().unwrap());
            assert_eq!(movz_id & 0xFFE0_001F, 0xD280_0004);
            assert_eq!((movz_id >> 5) & 0xFFFF, id as u32);
            // movz x8, SYS_WIN_THUNK
            let movz_no = u32::from_le_bytes(stub[4..8].try_into().unwrap());
            assert_eq!(movz_no & 0xFFE0_001F, 0xD280_0008);
            assert_eq!((movz_no >> 5) & 0xFFFF, SYS_WIN_THUNK);
            // svc #0
            let svc = u32::from_le_bytes(stub[8..12].try_into().unwrap());
            assert_eq!(svc, 0xd400_0001);
            // ret
            let ret = u32::from_le_bytes(stub[12..16].try_into().unwrap());
            assert_eq!(ret, 0xd65f_03c0);
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
