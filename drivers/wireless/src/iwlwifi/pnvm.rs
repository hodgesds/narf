//! PNVM selection from an embedded TLV 74 or a standalone .pnvm file.
//! Match all three ALIVE SKU words and the actual MAC/RF types before
//! exposing calibration payloads to the device.

use alloc::vec::Vec;

pub fn select(
    bytes: &[u8],
    sku: [u32; 3],
    mac_type: u16,
    rf_type: u16,
) -> Result<Vec<&[u8]>, &'static str> {
    let mut pos = 0;
    let mut selected = false;
    let mut matched_hw = false;
    let mut chunks = Vec::new();
    while pos < bytes.len() {
        if bytes.len() - pos < 8 {
            return Err("truncated PNVM TLV");
        }
        let tag = u32::from_le_bytes(bytes[pos..pos + 4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[pos + 4..pos + 8].try_into().unwrap()) as usize;
        pos += 8;
        let aligned = len.checked_add(3).ok_or("PNVM length overflow")? & !3;
        if aligned > bytes.len() - pos {
            return Err("truncated PNVM payload");
        }
        let data = &bytes[pos..pos + len];
        pos += aligned;
        if tag == 64 {
            if selected && matched_hw && !chunks.is_empty() {
                return Ok(chunks);
            }
            if len != 12 {
                return Err("invalid PNVM SKU");
            }
            selected = (0..3)
                .all(|i| u32::from_le_bytes(data[i * 4..i * 4 + 4].try_into().unwrap()) == sku[i]);
            matched_hw = false;
            chunks.clear();
            continue;
        }
        if !selected {
            continue;
        }
        match tag {
            58 => {
                if len < 4 {
                    return Err("invalid PNVM hardware selector");
                }
                matched_hw |= u16::from_le_bytes(data[..2].try_into().unwrap()) == mac_type
                    && u16::from_le_bytes(data[2..4].try_into().unwrap()) == rf_type;
            }
            19 => {
                if len < 4 {
                    return Err("truncated PNVM section");
                }
                if data[..4] != 0xdddd_eeeeu32.to_le_bytes() {
                    if len == 4 {
                        return Err("empty PNVM section");
                    }
                    chunks.push(&data[4..]);
                }
            }
            7 => {
                // iwl_uefi_pnvm_mem_desc: address(u32), size(u32), data.
                if len < 8 || u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize != len - 8
                {
                    return Err("invalid PNVM memory descriptor");
                }
                chunks.push(&data[8..]);
            }
            _ => {}
        }
        if chunks.len() > 64 {
            return Err("too many PNVM payloads");
        }
    }
    if selected && matched_hw && !chunks.is_empty() {
        Ok(chunks)
    } else {
        Err("PNVM has no matching SKU and hardware")
    }
}
