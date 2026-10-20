//! Board metadata from atomfirmware, with no SKU-based memory guesses.

fn word(bytes: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_le_bytes(bytes.get(at..at.checked_add(2)?)?.try_into().ok()?) as usize)
}

/// `amdgpu_atomfirmware_get_vram_info`: VRAM_INFO 2.3/2.4/2.5/2.6,
/// selecting the variable-length module from BIOS_SCRATCH_4[23:16].
/// Returns ATOM memory type and bus width in bits. Unlike the C reader,
/// malformed sizes and a module id equal to the count are rejected.
pub fn vram(table: &[u8], module: u8) -> Option<(u8, u32)> {
    let table = table.get(..word(table, 0)?)?;
    let (size_at, type_at, channels_at, width_at) = match table.get(2..4)? {
        [2, 3 | 4 | 6] => (20, 23, 24, 25),
        [2, 5] => (10, 13, 14, 15),
        _ => return None,
    };
    let count = *table.get(20)?;
    if count == 0 {
        return None;
    }
    // Linux falls back to the first module for an out-of-range strap.
    let module = if module >= count { 0 } else { module };
    let mut at: usize = 24;
    for index in 0..=module {
        let size = word(table, at.checked_add(size_at)?)?;
        if size <= width_at {
            return None;
        }
        let end = at.checked_add(size)?;
        let entry = table.get(at..end)?;
        if index == module {
            let channels = u32::from(*entry.get(channels_at)?);
            let width =
                channels.checked_mul(1u32.checked_shl(u32::from(*entry.get(width_at)?))?)?;
            if channels == 0 || width == 0 {
                return None;
            }
            return Some((*entry.get(type_at)?, width));
        }
        at = end;
    }
    None
}

/// Maximum common endpoint/slot link, as AMDGPU_INFO reports. Inputs are
/// PCI Express Link Capabilities, not the negotiated low-power Link Status.
pub fn pcie(endpoint: u32, partner: u32) -> Option<(u32, u32)> {
    let generation = (endpoint & 15).min(partner & 15);
    let lanes = ((endpoint >> 4) & 63).min((partner >> 4) & 63);
    if !(1..=6).contains(&generation) || !matches!(lanes, 1 | 2 | 4 | 8 | 12 | 16 | 32) {
        return None;
    }
    Some((generation, lanes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn variable_memory_modules_and_bad_tables() {
        for rev in [3, 4, 5, 6] {
            let mut bytes = [0u8; 160];
            bytes[..2].copy_from_slice(&160u16.to_le_bytes());
            bytes[2..4].copy_from_slice(&[2, rev]);
            bytes[20] = 2;
            let (s, t, c, w) = if rev == 5 {
                (10, 13, 14, 15)
            } else {
                (20, 23, 24, 25)
            };
            for (at, size, channels) in [(24, 56u16, 8), (80, 80, 6)] {
                bytes[at + s..at + s + 2].copy_from_slice(&size.to_le_bytes());
                bytes[at + t] = 0x70;
                bytes[at + c] = channels;
                bytes[at + w] = 5;
            }
            assert_eq!(vram(&bytes, 0), Some((0x70, 256)));
            assert_eq!(vram(&bytes, 1), Some((0x70, 192)));
            assert_eq!(vram(&bytes, 2), Some((0x70, 256)));
            assert_eq!(vram(&bytes, 255), Some((0x70, 256)));
            bytes[80 + w] = 32;
            assert_eq!(vram(&bytes, 1), None);
            bytes[80 + w] = 5;
            for len in 0..160 {
                assert_eq!(vram(&bytes[..len], 1), None);
            }
            bytes[24 + s..24 + s + 2].copy_from_slice(&0u16.to_le_bytes());
            assert_eq!(vram(&bytes, 1), None);
        }
    }
    #[test]
    fn pcie_uses_common_capabilities() {
        assert_eq!(pcie(4 | 16 << 4, 3 | 8 << 4), Some((3, 8)));
        assert_eq!(pcie(4 | 4 << 4, 5 | 16 << 4), Some((4, 4)));
        assert_eq!(pcie(0, u32::MAX), None);
        assert_eq!(pcie(u32::MAX, u32::MAX), None);
    }
}
