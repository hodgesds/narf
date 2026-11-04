//! MT76 copy-mode service protocol v1. Integers in payloads are little endian;
//! no Rust layouts, callbacks or kernel addresses appear in these records.
pub const FAMILY: u32 = 0x6d74_3736; // "mt76"
pub const VERSION: u32 = 1;
pub const INITIALIZE: u32 = 1;
pub const SCAN: u32 = 2;
pub const ASSOCIATE: u32 = 3;
pub const DISASSOCIATE: u32 = 4;
pub const TRANSMIT: u32 = 5;
pub const RECEIVE: u32 = 6;
pub const FIRMWARE_CHUNK: u32 = 7;
pub const INIT_FIXED: usize = 58;
pub const MAX_FRAME: usize = 2304;
pub const MAX_FIRMWARE_CHUNK: usize = 4096;

pub fn read_u16(bytes: &[u8], at: usize) -> Result<u16, i32> {
    let value = bytes.get(at..at.checked_add(2).ok_or(-22)?).ok_or(-22)?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}
pub fn read_u32(bytes: &[u8], at: usize) -> Result<u32, i32> {
    let value = bytes.get(at..at.checked_add(4).ok_or(-22)?).ok_or(-22)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

/// Check the actual admitted interface's INIT reply in the `.ko` without
/// needing the kernel's RadioInfo/Wiphy/Interface Rust types.
pub fn initialized(bytes: &[u8]) -> bool {
    bytes.len() >= INIT_FIXED
        && read_u32(bytes, 0) == Ok(VERSION)
        && read_u32(bytes, 4) == Ok(FAMILY)
        && bytes[12..18] != [0; 6]
        && bytes[12] & 1 == 0
        && read_u32(bytes, 20).is_ok_and(|index| index != 0)
        && bytes[57] != 0
        && bytes.len() == INIT_FIXED + usize::from(bytes[57])
}

/// Scan: active/count-frequencies/count-SSIDs/reserved, IE length u16,
/// reserved u16, frequencies u32[], length-prefixed SSIDs, then IE bytes.
pub fn validate_scan(bytes: &[u8]) -> Result<(), i32> {
    if bytes.len() < 8
        || bytes[0] > 1
        || bytes[1] > 64
        || bytes[2] > 4
        || bytes[3] != 0
        || read_u16(bytes, 6)? != 0
    {
        return Err(-22);
    }
    let ies = usize::from(read_u16(bytes, 4)?);
    if ies > 512 || (bytes[0] == 0 && bytes[2] != 0) {
        return Err(-22);
    }
    let mut cursor = 8 + usize::from(bytes[1]) * 4;
    if cursor > bytes.len() {
        return Err(-22);
    }
    for _ in 0..bytes[2] {
        let len = usize::from(*bytes.get(cursor).ok_or(-22)?);
        if len > 32 {
            return Err(-22);
        }
        cursor = cursor.checked_add(1 + len).ok_or(-22)?;
        if cursor > bytes.len() {
            return Err(-22);
        }
    }
    if cursor.checked_add(ies) != Some(bytes.len()) {
        return Err(-22);
    }
    Ok(())
}

/// Associate: BSSID[6], channel u8, security u8 (open/PSK/SAE), frequency
/// u32, SSID/IE/secret lengths u16, reserved u16, then those byte strings.
pub fn validate_associate(bytes: &[u8]) -> Result<(), i32> {
    if bytes.len() < 20
        || bytes[..6] == [0; 6]
        || bytes[0] & 1 != 0
        || bytes[6] == 0
        || bytes[6] > 233
        || bytes[7] > 2
        || read_u16(bytes, 18)? != 0
    {
        return Err(-22);
    }
    let ssid = usize::from(read_u16(bytes, 12)?);
    let ies = usize::from(read_u16(bytes, 14)?);
    let secret = usize::from(read_u16(bytes, 16)?);
    let valid_secret = match bytes[7] {
        0 => secret == 0,
        1 => secret == 32,
        2 => (1..=63).contains(&secret),
        _ => false,
    };
    if ssid == 0
        || ssid > 32
        || ies > 512
        || !valid_secret
        || 20 + ssid + ies + secret != bytes.len()
    {
        return Err(-22);
    }
    Ok(())
}

pub fn validate(opcode: u32, bytes: &[u8]) -> Result<(), i32> {
    match opcode {
        INITIALIZE | DISASSOCIATE | RECEIVE if bytes.is_empty() => Ok(()),
        SCAN => validate_scan(bytes),
        ASSOCIATE => validate_associate(bytes),
        TRANSMIT if (14..=MAX_FRAME).contains(&bytes.len()) => Ok(()),
        FIRMWARE_CHUNK
            if bytes.len() == 8
                && bytes[0] <= 1
                && bytes[1] == 0
                && (1..=MAX_FIRMWARE_CHUNK).contains(&usize::from(read_u16(bytes, 2)?)) =>
        {
            Ok(())
        }
        INITIALIZE | DISASSOCIATE | RECEIVE | TRANSMIT | FIRMWARE_CHUNK => Err(-22),
        _ => Err(-95),
    }
}
