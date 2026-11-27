//! The i386 System V IPC control structures (`include/asm-generic/compat.h`
//! `struct compat_ipc64_perm` / `compat_semid64_ds` / `compat_msqid64_ds` /
//! `compat_shmid64_ds`, `ipc/shm.c` `struct compat_shminfo64` /
//! `compat_shm_info`), converted to and from the native x86_64 layouts that
//! `sysvipc` and `sys_shmctl` encode and decode.
//!
//! The compat structures keep the native field order with every `long`
//! narrowed to 32 bits and each 64-bit time split into a low and a high
//! word, so a conversion is a list of field moves. Linux builds them the
//! same way (`copy_compat_semid_to_user` and friends): times as
//! `lower_32_bits`/`upper_32_bits`, counts truncated, `shmmax` clamped to
//! `INT_MAX`.

use alloc::vec::Vec;

use super::conv;
use crate::sysvipc::IpcDs;

/// Copy `len` bytes from offset `native` of the native structure to offset
/// `compat` of the compat one (or back). Little-endian, so the low bytes of
/// a wider native field are its compat value, and a native 64-bit time is
/// the compat `{time, time_high}` pair.
type Move = (usize, usize, usize);

/// `struct ipc64_perm` (48 bytes) ↔ `struct compat_ipc64_perm` (36): key,
/// uid, gid, cuid and cgid as they are; the 16-bit `compat_mode_t` and
/// `seq` from the low halves of the native fields; the unused words zero.
const PERM: [Move; 3] = [(0, 0, 20), (20, 20, 2), (24, 24, 2)];

/// `semid64_ds` (104) → `compat_semid64_ds` (64): `sem_otime`,
/// `sem_ctime` (with their high words) and `sem_nsems`.
const SEM: [Move; 3] = [(48, 36, 8), (64, 44, 8), (80, 52, 4)];

/// `msqid64_ds` (120) → `compat_msqid64_ds` (88): the three times, then
/// `msg_cbytes`, `msg_qnum`, `msg_qbytes`, `msg_lspid`, `msg_lrpid`.
const MSG: [Move; 8] = [
    (48, 36, 8),
    (56, 44, 8),
    (64, 52, 8),
    (72, 60, 4),
    (80, 64, 4),
    (88, 68, 4),
    (96, 72, 4),
    (100, 76, 4),
];

/// `shmid64_ds` (112) → `compat_shmid64_ds` (84): `shm_segsz`, the three
/// times, `shm_cpid`, `shm_lpid`, `shm_nattch`.
const SHM: [Move; 7] = [
    (48, 36, 4),
    (56, 40, 8),
    (64, 48, 8),
    (72, 56, 8),
    (80, 64, 4),
    (84, 68, 4),
    (88, 72, 4),
];

/// `shminfo64` (9 × `unsigned long`) → `compat_shminfo64` (9 × u32).
const SHM_INFO64: [Move; 9] = [
    (0, 0, 4),
    (8, 4, 4),
    (16, 8, 4),
    (24, 12, 4),
    (32, 16, 4),
    (40, 20, 4),
    (48, 24, 4),
    (56, 28, 4),
    (64, 32, 4),
];

/// `shm_info` (48) → `compat_shm_info` (24): `used_ids`, then the five
/// `unsigned long` counters.
const SHM_USAGE: [Move; 6] = [
    (0, 0, 4),
    (8, 4, 4),
    (16, 8, 4),
    (24, 12, 4),
    (32, 16, 4),
    (40, 20, 4),
];

/// The compat size, the native size, whether the structure starts with an
/// `ipc64_perm`, and its field moves.
fn layout(kind: IpcDs) -> (usize, usize, bool, &'static [Move]) {
    match kind {
        IpcDs::Sem => (64, 104, true, &SEM[..]),
        IpcDs::Msg => (88, 120, true, &MSG[..]),
        IpcDs::Shm => (84, 112, true, &SHM[..]),
        IpcDs::ShmInfo => (36, 72, false, &SHM_INFO64[..]),
        IpcDs::ShmUsage => (24, 48, false, &SHM_USAGE[..]),
    }
}

/// The compat form of the native `kind` structure `native`.
pub(crate) fn to_compat(kind: IpcDs, native: &[u8]) -> Vec<u8> {
    let (compat_len, native_len, perm, moves) = layout(kind);
    let mut out = alloc::vec![0u8; compat_len];
    if native.len() < native_len {
        return out;
    }
    let perm_moves: &[Move] = if perm { &PERM[..] } else { &[] };
    for &(from, to, len) in perm_moves.iter().chain(moves) {
        out[to..to + len].copy_from_slice(&native[from..from + len]);
    }
    if kind == IpcDs::ShmInfo {
        // `copy_compat_shminfo_to_user`: `if (in->shmmax > INT_MAX)
        // in->shmmax = INT_MAX;` before the narrowing copy.
        let shmmax = u64::from_le_bytes(native[0..8].try_into().unwrap_or([0; 8]));
        let clamped = core::cmp::min(shmmax, i32::MAX as u64) as u32;
        out[0..4].copy_from_slice(&clamped.to_le_bytes());
    }
    out
}

/// The native form of the compat `kind` structure `compat` (IPC_SET input).
pub(crate) fn from_compat(kind: IpcDs, compat: &[u8]) -> Vec<u8> {
    let (compat_len, native_len, perm, moves) = layout(kind);
    let mut out = alloc::vec![0u8; native_len];
    if compat.len() < compat_len {
        return out;
    }
    let perm_moves: &[Move] = if perm { &PERM[..] } else { &[] };
    for &(from, to, len) in perm_moves.iter().chain(moves) {
        out[from..from + len].copy_from_slice(&compat[to..to + len]);
    }
    out
}

/// Write the native `kind` structure `native` to the i386 caller's `uptr`
/// in its compat layout.
pub(crate) fn ds_to_user(kind: IpcDs, uptr: u64, native: &[u8]) -> Result<(), ()> {
    conv::write_user(uptr, &to_compat(kind, native)).map_err(|_| ())
}

/// Read the i386 caller's compat `kind` structure at `uptr`, widened to the
/// native layout.
pub(crate) fn ds_from_user(kind: IpcDs, uptr: u64) -> Result<Vec<u8>, ()> {
    let (compat_len, _, _, _) = layout(kind);
    let mut raw = alloc::vec![0u8; compat_len];
    conv::read_user(uptr, &mut raw).map_err(|_| ())?;
    Ok(from_compat(kind, &raw))
}
