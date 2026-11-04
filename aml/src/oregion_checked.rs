//! Plain byte-access Fields with propagated hardware errors. The legacy
//! OpRegion accessors retain their existing compatibility behavior.

use core::sync::atomic::{compiler_fence, Ordering};

use super::{FieldAccessError, FieldInfo, OpRegionInfo, RegionSpace};

fn field(path: &str) -> Result<(FieldInfo, OpRegionInfo, u64, usize), FieldAccessError> {
    let field = super::field_for(path).ok_or(FieldAccessError::NoField)?;
    if field.bit_length == 0 || field.bit_length > 64 {
        return Err(FieldAccessError::TooWide);
    }
    if field.lock_rule
        || !matches!(field.access_kind, 0 | 1)
        || field.update_rule > 2
        || field.index_field.is_some()
        || field.bank_field.is_some()
    {
        return Err(FieldAccessError::Unsupported);
    }
    let region = super::region_for(&field.region_path).ok_or(FieldAccessError::NoRegion)?;
    let end = field
        .bit_offset
        .checked_add(field.bit_length)
        .ok_or(FieldAccessError::Unsupported)?;
    if region.length == 0
        || region
            .length
            .checked_mul(8)
            .is_none_or(|length| end > length)
    {
        return Err(FieldAccessError::Unsupported);
    }
    let first = field.bit_offset / 8;
    let bytes = (field.bit_offset % 8 + field.bit_length).div_ceil(8) as usize;
    let address = region
        .offset
        .checked_add(first)
        .ok_or(FieldAccessError::Unsupported)?;
    let address_end = address
        .checked_add(bytes as u64)
        .ok_or(FieldAccessError::Unsupported)?;
    match region.space {
        RegionSpace::SystemMemory => {}
        RegionSpace::SystemIO if cfg!(target_arch = "x86_64") && address_end <= 0x1_0000 => {}
        RegionSpace::EmbeddedCtl if cfg!(target_arch = "x86_64") && address_end <= 256 => {}
        _ => return Err(FieldAccessError::Unsupported),
    }
    Ok((field, region, address, bytes))
}

fn read_byte(region: &OpRegionInfo, address: u64) -> Result<u8, FieldAccessError> {
    compiler_fence(Ordering::SeqCst);
    let result = match region.space {
        RegionSpace::SystemMemory => {
            let pointer = super::sysmem_ptr(address, 1).ok_or(FieldAccessError::Unsupported)?;
            // SAFETY: actual firmware region, extent checked by field();
            // sysmem_ptr returned a live Device-attribute mapping.
            Ok(unsafe { pointer.read_volatile() })
        }
        RegionSpace::SystemIO => {
            // SAFETY: checked x86 byte port inside the declared region.
            Ok(unsafe { super::io_in(address as u16, 1) } as u8)
        }
        RegionSpace::EmbeddedCtl => super::ec_checked::read_byte(address as u8),
        _ => Err(FieldAccessError::Unsupported),
    };
    compiler_fence(Ordering::SeqCst);
    result
}

fn write_byte(region: &OpRegionInfo, address: u64, value: u8) -> Result<(), FieldAccessError> {
    compiler_fence(Ordering::SeqCst);
    let result = match region.space {
        RegionSpace::SystemMemory => {
            let pointer = super::sysmem_ptr(address, 1).ok_or(FieldAccessError::Unsupported)?;
            // SAFETY: checked extent and live Device mapping as above.
            unsafe { pointer.write_volatile(value) };
            Ok(())
        }
        RegionSpace::SystemIO => {
            // SAFETY: checked x86 byte port inside the declared region.
            unsafe { super::io_out(address as u16, 1, u64::from(value)) };
            Ok(())
        }
        RegionSpace::EmbeddedCtl => super::ec_checked::write_byte(address as u8, value),
        _ => Err(FieldAccessError::Unsupported),
    };
    compiler_fence(Ordering::SeqCst);
    result
}

/// Strict plain-Field read. Unsupported/stub spaces, lock/index/bank rules,
/// invalid extents, mapping failures and EC transaction errors propagate.
pub fn read_field_checked(path: &str) -> Result<u64, FieldAccessError> {
    let (field, region, address, bytes) = field(path)?;
    let mut raw = 0u128;
    for index in 0..bytes {
        raw |= u128::from(read_byte(&region, address + index as u64)?) << (index * 8);
    }
    let mask = (1u128 << field.bit_length) - 1;
    Ok(((raw >> (field.bit_offset % 8)) & mask) as u64)
}

/// Strict plain-Field write. No unsupported operation can become a success
/// receipt. A failed multi-byte write may be partial and requires the caller's
/// retained firmware-operation rollback; it never claims atomicity.
pub fn write_field_checked(path: &str, value: u64) -> Result<(), FieldAccessError> {
    let (field, region, address, bytes) = field(path)?;
    let mask = ((1u128 << field.bit_length) - 1) << (field.bit_offset % 8);
    let value = u128::from(value) << (field.bit_offset % 8);
    for index in 0..bytes {
        let byte_mask = (mask >> (index * 8)) as u8;
        let old = match field.update_rule {
            _ if byte_mask == u8::MAX => 0,
            0 => read_byte(&region, address + index as u64)?,
            1 => u8::MAX,
            2 => 0,
            _ => return Err(FieldAccessError::Unsupported),
        };
        let next = (old & !byte_mask) | (((value >> (index * 8)) as u8) & byte_mask);
        write_byte(&region, address + index as u64, next)?;
    }
    Ok(())
}
