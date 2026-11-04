//! Nonblocking EC gate admission for strict firmware receipts. The actual
//! transaction body remains the same bounded EC command/address/data path.

#[cfg(target_arch = "x86_64")]
pub(super) fn read_byte(offset: u8) -> Result<u8, super::FieldAccessError> {
    let _gate = super::try_acquire_ec_txn_gate().ok_or(super::FieldAccessError::Unsupported)?;
    super::ec_read_byte_under_gate(offset)
}

#[cfg(target_arch = "x86_64")]
pub(super) fn write_byte(offset: u8, value: u8) -> Result<(), super::FieldAccessError> {
    let _gate = super::try_acquire_ec_txn_gate().ok_or(super::FieldAccessError::Unsupported)?;
    super::ec_write_byte_under_gate(offset, value)
}

#[cfg(not(target_arch = "x86_64"))]
pub(super) fn read_byte(_offset: u8) -> Result<u8, super::FieldAccessError> {
    Err(super::FieldAccessError::Unsupported)
}

#[cfg(not(target_arch = "x86_64"))]
pub(super) fn write_byte(_offset: u8, _value: u8) -> Result<(), super::FieldAccessError> {
    Err(super::FieldAccessError::Unsupported)
}
