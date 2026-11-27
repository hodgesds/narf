//! AES-XTS (IEEE 1619) on AES-NI, for the dm-crypt `aes-xts-plain64` data
//! path.
//!
//! Sources: Intel SDM vol. 2 (`AESENC`, `AESENCLAST`, `AESDEC`,
//! `AESDECLAST`, `AESIMC`, `AESKEYGENASSIST`); FIPS 197 §5.2 (key
//! expansion) and §5.3.5 (the equivalent inverse cipher); IEEE 1619-2018
//! §5.2 (XTS, the tweak multiplication by α).
//!
//! Each data unit (one encryption sector) uses the tweak
//! `T = AES-Enc(K2, sector)`, with the sector number as a little-endian 128-bit
//! integer (`plain64`). Block `j` of the unit is `C = AES(K1, P ^ T_j) ^ T_j`,
//! with `T_{j+1} = T_j · α` in GF(2^128). Units here are always whole
//! blocks (the callers' sectors are powers of two of at least 16 bytes), so
//! there is no ciphertext stealing. A buffer that is not a whole number of
//! blocks goes to the portable path ([`xts`] returns false).
//!
//! The work runs in [`crate::simd::section`]s of at most [`CHUNK`] bytes.
//! The keys are expanded on every call, so no expanded key outlives the
//! call; the stack copies are zeroed when it returns.

use zeroize::Zeroize;

use crate::simd::section;

/// Bytes per SIMD section. At about 1 cycle per byte, 16 KiB keeps
/// interrupts masked for a few microseconds at a time.
const CHUNK: usize = 16 * 1024;

/// Up to 15 round keys (AES-256), 16-byte aligned for the m128 operands.
#[repr(C, align(16))]
struct RoundKeys([u8; 240]);

impl Drop for RoundKeys {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `[0x87, 0, 1, 0]` as dwords: where the carries of the doubling land
/// (see `gf_double` in [`xts_unit`]).
#[repr(C, align(16))]
struct Align16([u32; 4]);
static GF_MASK: Align16 = Align16([0x87, 0, 1, 0]);

/// One step of the shift-xor cascade of FIPS 197 KeyExpansion:
/// `$r ^= $r << 32; $r ^= $r << 64; $r ^= $r << 96` (each dword picks up
/// every dword below it), with `$t` as scratch.
#[rustfmt::skip]
macro_rules! cascade {
    ($r:literal, $t:literal) => {
        concat!(
            "movdqa ", $t, ", ", $r, "\n",
            "pslldq ", $t, ", 4\n",
            "pxor ", $r, ", ", $t, "\n",
            "pslldq ", $t, ", 4\n",
            "pxor ", $r, ", ", $t, "\n",
            "pslldq ", $t, ", 4\n",
            "pxor ", $r, ", ", $t, "\n",
        )
    };
}

/// AES-128 key expansion step: round key `$off/16` from the previous one in
/// xmm1. `AESKEYGENASSIST`'s dword 3 is `RotWord(SubWord(w3)) ^ rcon`.
#[rustfmt::skip]
macro_rules! expand128 {
    ($rcon:literal, $off:literal) => {
        concat!(
            "aeskeygenassist xmm2, xmm1, ", $rcon, "\n",
            "pshufd xmm2, xmm2, 0xFF\n",
            cascade!("xmm1", "xmm3"),
            "pxor xmm1, xmm2\n",
            "movdqa [{rk} + ", $off, "], xmm1\n",
        )
    };
}

/// AES-256 even step: `w[i..i+4]` from `w[i-8..i-4]` (xmm1) and
/// `RotWord(SubWord(w[i-1])) ^ rcon` of the previous key (xmm3).
#[rustfmt::skip]
macro_rules! expand256_even {
    ($rcon:literal, $off:literal) => {
        concat!(
            "aeskeygenassist xmm2, xmm3, ", $rcon, "\n",
            "pshufd xmm2, xmm2, 0xFF\n",
            cascade!("xmm1", "xmm4"),
            "pxor xmm1, xmm2\n",
            "movdqa [{rk} + ", $off, "], xmm1\n",
        )
    };
}

/// AES-256 odd step: `SubWord(w[i-1])` with no rotation or rcon
/// (`AESKEYGENASSIST`'s dword 2) (FIPS 197 §5.2, Nk > 6, i mod Nk = 4).
#[rustfmt::skip]
macro_rules! expand256_odd {
    ($off:literal) => {
        concat!(
            "aeskeygenassist xmm2, xmm1, 0\n",
            "pshufd xmm2, xmm2, 0xAA\n",
            cascade!("xmm3", "xmm4"),
            "pxor xmm3, xmm2\n",
            "movdqa [{rk} + ", $off, "], xmm3\n",
        )
    };
}

/// Expand a 16- or 32-byte key into `rk`; returns the round count.
///
/// # Safety
/// Inside a section, with AES-NI.
unsafe fn expand(key: &[u8], rk: &mut RoundKeys) -> usize {
    match key.len() {
        16 => {
            // SAFETY: `key` is 16 readable bytes; `rk` has room for 11
            // aligned round keys. Clobbers xmm1-xmm3.
            unsafe {
                core::arch::asm!(
                    "movdqu xmm1, [{key}]",
                    "movdqa [{rk}], xmm1",
                    expand128!("0x01", "16"),
                    expand128!("0x02", "32"),
                    expand128!("0x04", "48"),
                    expand128!("0x08", "64"),
                    expand128!("0x10", "80"),
                    expand128!("0x20", "96"),
                    expand128!("0x40", "112"),
                    expand128!("0x80", "128"),
                    expand128!("0x1B", "144"),
                    expand128!("0x36", "160"),
                    key = in(reg) key.as_ptr(),
                    rk = in(reg) rk.0.as_mut_ptr(),
                    out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    options(nostack, preserves_flags),
                );
            }
            10
        }
        32 => {
            // SAFETY: `key` is 32 readable bytes; `rk` has room for 15
            // aligned round keys. Clobbers xmm1-xmm4.
            unsafe {
                core::arch::asm!(
                    "movdqu xmm1, [{key}]",
                    "movdqu xmm3, [{key} + 16]",
                    "movdqa [{rk}], xmm1",
                    "movdqa [{rk} + 16], xmm3",
                    expand256_even!("0x01", "32"),
                    expand256_odd!("48"),
                    expand256_even!("0x02", "64"),
                    expand256_odd!("80"),
                    expand256_even!("0x04", "96"),
                    expand256_odd!("112"),
                    expand256_even!("0x08", "128"),
                    expand256_odd!("144"),
                    expand256_even!("0x10", "160"),
                    expand256_odd!("176"),
                    expand256_even!("0x20", "192"),
                    expand256_odd!("208"),
                    expand256_even!("0x40", "224"),
                    key = in(reg) key.as_ptr(),
                    rk = in(reg) rk.0.as_mut_ptr(),
                    out("xmm1") _, out("xmm2") _, out("xmm3") _, out("xmm4") _,
                    options(nostack, preserves_flags),
                );
            }
            14
        }
        _ => unreachable!("AES-XTS key halves are 16 or 32 bytes"),
    }
}

/// The decryption schedule of the equivalent inverse cipher (FIPS 197
/// §5.3.5): the encryption keys in reverse order, with `InvMixColumns`
/// (`AESIMC`) applied to all but the first and last.
///
/// # Safety
/// Inside a section, with AES-NI.
unsafe fn invert(rk: &RoundKeys, rounds: usize, dk: &mut RoundKeys) {
    for i in 0..=rounds {
        let src = rk.0[(rounds - i) * 16..].as_ptr();
        let dst = dk.0[i * 16..].as_mut_ptr();
        if i == 0 || i == rounds {
            // SAFETY: both name 16 bytes inside their 240-byte arrays.
            unsafe { core::ptr::copy_nonoverlapping(src, dst, 16) };
        } else {
            // SAFETY: as above; both 16-byte aligned. Clobbers xmm1.
            unsafe {
                core::arch::asm!(
                    "aesimc xmm1, [{s}]",
                    "movdqa [{d}], xmm1",
                    s = in(reg) src,
                    d = in(reg) dst,
                    out("xmm1") _,
                    options(nostack, preserves_flags),
                );
            }
        }
    }
}

/// `xts_unit_enc` / `xts_unit_dec`: one data unit of `n` blocks at `data`.
///
/// Registers: xmm0-xmm3 four data blocks, xmm4-xmm7 their tweaks, xmm8
/// the next tweak, xmm9 scratch, xmm10 the round key, xmm11 [`GF_MASK`].
///
/// Doubling `T` (`gf_double`): `paddq` shifts each 64-bit half left by
/// one. The bit that left the low half (bit 63) must enter the high half
/// at bit 64, and the bit that left the top (bit 127) is reduced as `^=
/// 0x87` into byte 0. `psrad 31` turns each dword's top bit into a mask,
/// `pshufd 0x93` moves the mask of dword 3 to dword 0 and that of dword 1
/// to dword 2, and the AND with `[0x87, 0, 1, 0]` keeps exactly those two
/// corrections.
macro_rules! xts_unit {
    ($name:ident, $round:literal, $last:literal) => {
        /// # Safety
        /// Inside a section, with AES-NI. `data` holds `n >= 1` blocks;
        /// `k1` and `k2` hold `rounds + 1` round keys (`k1` the decryption
        /// schedule for the decrypting variant, `k2` always the encryption
        /// schedule).
        unsafe fn $name(
            k1: &RoundKeys,
            k2: &RoundKeys,
            rounds: usize,
            sector: u64,
            data: *mut u8,
            n: usize,
        ) {
            // SAFETY: the caller's contract; every m128 operand is a
            // 16-byte aligned round key or GF_MASK.
            unsafe {
                core::arch::asm!(
                    // T = AES-Enc(K2, sector).
                    "movq xmm8, {sector}",
                    "pxor xmm8, [{k2}]",
                    "lea {p}, [{k2} + 16]",
                    "lea {c}, [{rounds} - 1]",
                    "2:",
                    "aesenc xmm8, [{p}]",
                    "add {p}, 16",
                    "dec {c}",
                    "jnz 2b",
                    "aesenclast xmm8, [{p}]",
                    "movdqa xmm11, [{mask}]",
                    "cmp {n}, 4",
                    "jb 5f",
                    // Four blocks at a time.
                    "3:",
                    "movdqa xmm4, xmm8",
                    "movdqa xmm5, xmm4",
                    "movdqa xmm9, xmm5", "psrad xmm9, 31", "pshufd xmm9, xmm9, 0x93",
                    "pand xmm9, xmm11", "paddq xmm5, xmm5", "pxor xmm5, xmm9",
                    "movdqa xmm6, xmm5",
                    "movdqa xmm9, xmm6", "psrad xmm9, 31", "pshufd xmm9, xmm9, 0x93",
                    "pand xmm9, xmm11", "paddq xmm6, xmm6", "pxor xmm6, xmm9",
                    "movdqa xmm7, xmm6",
                    "movdqa xmm9, xmm7", "psrad xmm9, 31", "pshufd xmm9, xmm9, 0x93",
                    "pand xmm9, xmm11", "paddq xmm7, xmm7", "pxor xmm7, xmm9",
                    "movdqa xmm8, xmm7",
                    "movdqa xmm9, xmm8", "psrad xmm9, 31", "pshufd xmm9, xmm9, 0x93",
                    "pand xmm9, xmm11", "paddq xmm8, xmm8", "pxor xmm8, xmm9",
                    "movdqu xmm0, [{d}]",
                    "movdqu xmm1, [{d} + 16]",
                    "movdqu xmm2, [{d} + 32]",
                    "movdqu xmm3, [{d} + 48]",
                    "pxor xmm0, xmm4",
                    "pxor xmm1, xmm5",
                    "pxor xmm2, xmm6",
                    "pxor xmm3, xmm7",
                    "movdqa xmm10, [{k1}]",
                    "pxor xmm0, xmm10",
                    "pxor xmm1, xmm10",
                    "pxor xmm2, xmm10",
                    "pxor xmm3, xmm10",
                    "lea {p}, [{k1} + 16]",
                    "lea {c}, [{rounds} - 1]",
                    "4:",
                    "movdqa xmm10, [{p}]",
                    concat!($round, " xmm0, xmm10"),
                    concat!($round, " xmm1, xmm10"),
                    concat!($round, " xmm2, xmm10"),
                    concat!($round, " xmm3, xmm10"),
                    "add {p}, 16",
                    "dec {c}",
                    "jnz 4b",
                    "movdqa xmm10, [{p}]",
                    concat!($last, " xmm0, xmm10"),
                    concat!($last, " xmm1, xmm10"),
                    concat!($last, " xmm2, xmm10"),
                    concat!($last, " xmm3, xmm10"),
                    "pxor xmm0, xmm4",
                    "pxor xmm1, xmm5",
                    "pxor xmm2, xmm6",
                    "pxor xmm3, xmm7",
                    "movdqu [{d}], xmm0",
                    "movdqu [{d} + 16], xmm1",
                    "movdqu [{d} + 32], xmm2",
                    "movdqu [{d} + 48], xmm3",
                    "add {d}, 64",
                    "sub {n}, 4",
                    "cmp {n}, 4",
                    "jae 3b",
                    // One block at a time.
                    "5:",
                    "test {n}, {n}",
                    "jz 8f",
                    "6:",
                    "movdqu xmm0, [{d}]",
                    "pxor xmm0, xmm8",
                    "pxor xmm0, [{k1}]",
                    "lea {p}, [{k1} + 16]",
                    "lea {c}, [{rounds} - 1]",
                    "7:",
                    concat!($round, " xmm0, [{p}]"),
                    "add {p}, 16",
                    "dec {c}",
                    "jnz 7b",
                    concat!($last, " xmm0, [{p}]"),
                    "pxor xmm0, xmm8",
                    "movdqu [{d}], xmm0",
                    "movdqa xmm9, xmm8", "psrad xmm9, 31", "pshufd xmm9, xmm9, 0x93",
                    "pand xmm9, xmm11", "paddq xmm8, xmm8", "pxor xmm8, xmm9",
                    "add {d}, 16",
                    "dec {n}",
                    "jnz 6b",
                    "8:",
                    sector = in(reg) sector,
                    k1 = in(reg) k1.0.as_ptr(),
                    k2 = in(reg) k2.0.as_ptr(),
                    rounds = in(reg) rounds,
                    mask = in(reg) GF_MASK.0.as_ptr(),
                    d = inout(reg) data => _,
                    n = inout(reg) n => _,
                    p = out(reg) _,
                    c = out(reg) _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                    out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                    options(nostack),
                );
            }
        }
    };
}

xts_unit!(xts_unit_enc, "aesenc", "aesenclast");
xts_unit!(xts_unit_dec, "aesdec", "aesdeclast");

/// AES-XTS over `data` on AES-NI: `keys` is K1 || K2 (32 bytes for
/// AES-128-XTS, 64 for AES-256-XTS), the first data unit of `unit` bytes
/// is sector `first_sector`, and each later unit is the next sector.
///
/// Returns false, touching nothing, when this path cannot take the request:
/// no AES-NI (or no section in this build), or `data` not a whole number of
/// blocks. The caller then uses the portable path.
pub(crate) fn xts(
    encrypt: bool,
    keys: &[u8],
    first_sector: u64,
    unit: usize,
    data: &mut [u8],
) -> bool {
    if !crate::simd::caps().aes
        || !matches!(keys.len(), 32 | 64)
        || unit < 16
        || !unit.is_power_of_two()
        || data.is_empty()
        || data.len() % 16 != 0
    {
        return false;
    }
    let (k1_bytes, k2_bytes) = keys.split_at(keys.len() / 2);
    let mut k1 = RoundKeys([0; 240]);
    let mut k2 = RoundKeys([0; 240]);
    let mut dk = RoundKeys([0; 240]);
    let mut rounds = 0;
    let chunk = CHUNK.max(unit);
    let mut sector = first_sector;
    for (index, piece) in data.chunks_mut(chunk).enumerate() {
        section(|| {
            if index == 0 {
                // SAFETY: inside a section, AES-NI present.
                unsafe {
                    rounds = expand(k1_bytes, &mut k1);
                    expand(k2_bytes, &mut k2);
                    if !encrypt {
                        invert(&k1, rounds, &mut dk);
                    }
                }
            }
            for block in piece.chunks_mut(unit) {
                let n = block.len() / 16;
                // SAFETY: inside a section with AES-NI; `block` is `n`
                // whole blocks; the schedules hold `rounds + 1` keys.
                unsafe {
                    if encrypt {
                        xts_unit_enc(&k1, &k2, rounds, sector, block.as_mut_ptr(), n);
                    } else {
                        xts_unit_dec(&dk, &k2, rounds, sector, block.as_mut_ptr(), n);
                    }
                }
                sector = sector.wrapping_add(1);
            }
        });
    }
    true
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use aes::cipher::KeyInit;
    use alloc::vec::Vec;
    use xts_mode::{get_tweak_default, Xts128};

    fn bytes(seed: u64, n: usize) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    fn reference(encrypt: bool, keys: &[u8], sector: u64, unit: usize, data: &mut [u8]) {
        let (a, b) = keys.split_at(keys.len() / 2);
        if keys.len() == 32 {
            let x = Xts128::new(
                aes::Aes128::new_from_slice(a).unwrap(),
                aes::Aes128::new_from_slice(b).unwrap(),
            );
            if encrypt {
                x.encrypt_area(data, unit, sector.into(), get_tweak_default);
            } else {
                x.decrypt_area(data, unit, sector.into(), get_tweak_default);
            }
        } else {
            let x = Xts128::new(
                aes::Aes256::new_from_slice(a).unwrap(),
                aes::Aes256::new_from_slice(b).unwrap(),
            );
            if encrypt {
                x.encrypt_area(data, unit, sector.into(), get_tweak_default);
            } else {
                x.decrypt_area(data, unit, sector.into(), get_tweak_default);
            }
        }
    }

    /// Both directions, both key sizes, against the RustCrypto
    /// implementation: unit sizes 512-4096; lengths with 1-3 trailing
    /// blocks past a multiple of four, a short final unit, and more than
    /// one section; sector numbers that carry past 2^32.
    #[test]
    fn xts_ni_matches_reference() {
        if !crate::simd::caps().aes {
            std::eprintln!("no AES-NI on this CPU; skipped");
            return;
        }
        let lens = [16usize, 48, 112, 512, 528, 4096, 4096 + 80, 3 * CHUNK + 512];
        for key_len in [32usize, 64] {
            let keys = bytes(key_len as u64, key_len);
            for unit in [512usize, 1024, 4096] {
                for (i, &len) in lens.iter().enumerate() {
                    for sector in [0u64, 7, 0xffff_ffff, 0x1234_5678_9abc] {
                        let plain = bytes(len as u64 ^ sector, len);
                        let mut want = plain.clone();
                        reference(true, &keys, sector, unit, &mut want);
                        let mut got = plain.clone();
                        assert!(xts(true, &keys, sector, unit, &mut got));
                        assert_eq!(
                            got, want,
                            "enc key={key_len} unit={unit} len#{i} sector={sector}"
                        );
                        assert!(xts(false, &keys, sector, unit, &mut got));
                        assert_eq!(
                            got, plain,
                            "dec key={key_len} unit={unit} len#{i} sector={sector}"
                        );
                    }
                }
            }
        }
    }

    /// IEEE 1619-2007 Annex B, vector 10: AES-256-XTS, data unit sequence
    /// number 0xff, 512 bytes of 00..ff twice. Checks the first and last
    /// 16 bytes of the ciphertext.
    #[test]
    fn xts_ni_ieee1619_vector10() {
        if !crate::simd::caps().aes {
            return;
        }
        let mut keys = Vec::new();
        keys.extend_from_slice(&[
            0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45, 0x23, 0x53, 0x60, 0x28, 0x74, 0x71,
            0x35, 0x26, 0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93, 0x69, 0x99, 0x59, 0x57, 0x49,
            0x66, 0x96, 0x76, 0x27,
        ]);
        keys.extend_from_slice(&[
            0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x23, 0x84, 0x62, 0x64, 0x33, 0x83,
            0x27, 0x95, 0x02, 0x88, 0x41, 0x97, 0x16, 0x93, 0x99, 0x37, 0x51, 0x05, 0x82, 0x09,
            0x74, 0x94, 0x45, 0x92,
        ]);
        let mut data: Vec<u8> = (0..512).map(|i| i as u8).collect();
        let mut want = data.clone();
        reference(true, &keys, 0xff, 512, &mut want);
        assert!(xts(true, &keys, 0xff, 512, &mut data));
        assert_eq!(data, want);
        assert_eq!(
            &data[..16],
            &[
                0x1c, 0x3b, 0x3a, 0x10, 0x2f, 0x77, 0x03, 0x86, 0xe4, 0x83, 0x6c, 0x99, 0xe3, 0x70,
                0xcf, 0x9b
            ]
        );
    }

    #[test]
    fn xts_ni_declines_partial_blocks() {
        let keys = [1u8; 64];
        let mut data = [0u8; 40];
        assert!(!xts(true, &keys, 0, 512, &mut data));
        assert_eq!(data, [0u8; 40]);
    }
}
