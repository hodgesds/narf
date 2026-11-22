// SPDX-License-Identifier: GPL-2.0-or-later
//! Transport-agnostic physical-EFUSE decode, shared by the builtin driver and
//! the loadable `.ko`. The sparse physical stream (per-word-group headers +
//! enables + later overrides) decodes into the dense logical map both the
//! factory field accessors and the `.ko`'s field extraction read.
//!
//! The physical read itself (the EFUSE-controller register loop) stays in the
//! consuming crate — it is a register sequence over that crate's transport.

/// Decode one-/two-byte headers, sparse word enables, and later word overrides
/// of `physical` into the dense `logical` map (filled with `0xff` first).
/// `Err(())` on a malformed record. Protected physical bytes must be excluded
/// by the caller (`physical` is the readable programming area only).
pub fn decode_map(physical: &[u8], logical: &mut [u8]) -> Result<(), ()> {
    logical.fill(0xff);
    let mut cursor = 0;
    while cursor < physical.len() {
        let first = physical[cursor];
        cursor += 1;
        if first == 0xff {
            break;
        }
        let (block, word_enable) = if first & 0x1f == 0x0f {
            let second = *physical.get(cursor).ok_or(())?;
            cursor += 1;
            if second == 0xff {
                break;
            }
            (
                (((second & 0xf0) >> 1) | (first >> 5)) as usize,
                second & 0x0f,
            )
        } else {
            ((first >> 4) as usize, first & 0x0f)
        };

        for word in 0..4 {
            if word_enable & (1 << word) != 0 {
                continue;
            }
            let target = block * 8 + word * 2;
            let source = physical.get(cursor..cursor + 2).ok_or(())?;
            logical
                .get_mut(target..target + 2)
                .ok_or(())?
                .copy_from_slice(source);
            cursor += 2;
        }
    }
    Ok(())
}
