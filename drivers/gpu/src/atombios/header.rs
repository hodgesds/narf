//! ATOM_ROM_HEADER structures and signature validation.
//!
//! The VBIOS image uses this layout:
//!
//! ```text
//! +0x00  PCI option ROM header (optional; some images start directly
//!        with the ATOM_ROM_HEADER)
//! +0x48  u16  pointer to ATOM_ROM_HEADER (relative to VBIOS image base)
//! ```
//!
//! At the pointer target:
//! ```text
//! ATOM_ROM_HEADER (per atombios.h lines 338-366):
//! +0x00  atom_signature[4]           "ATOM"
//! +0x04  bios_runtime_segment_address  u16
//! +0x06  protected_mode_info_offset    u16
//! +0x08  config_filename_offset        u16
//! +0x0A  crc_block_offset              u16
//! +0x0C  bios_bootup_message_offset    u16  ← version string
//! +0x0E  int10_offset                  u16
//! +0x10  pci_bus_dev_init_code         u16
//! +0x12  io_base_address               u16
//! +0x14  subsystem_vendor_id           u16
//! +0x16  subsystem_id                  u16
//! +0x18  pci_info_offset               u16
//! +0x1A  master_command_table_offset   u16
//! +0x1C  master_data_table_offset      u16
//! +0x1E  extended_function_code        u8
//! +0x1F  reserved                      u8
//! ```
//!
//! ## Linux references
//!
//! - `linux/drivers/gpu/drm/amd/include/atombios.h` lines 338-366
//!   (`ATOM_ROM_HEADER` / `ATOM_ROM_HEADER_V2_1`).
//! - `linux/drivers/gpu/drm/amd/amdgpu/amdgpu_atombios.c` lines 73-100
//!   (`amdgpu_atombios_get_bios_version`).

/// Byte offset of the u16 pointer to ATOM_ROM_HEADER within the VBIOS image.
///
/// Linux ref: atombios.h `OFFSET_TO_POINTER_TO_ATOM_ROM_HEADER = 0x48`.
pub const ROM_HEADER_PTR_OFFSET: usize = 0x48;

/// Size of the ROM_HEADER_PTR_OFFSET field (u16, 2 bytes).
pub const ROM_HEADER_PTR_SIZE: usize = 2;

/// Minimum image size to safely read the ROM header pointer.
pub const MIN_IMAGE_LEN: usize = ROM_HEADER_PTR_OFFSET + ROM_HEADER_PTR_SIZE;

/// Minimum size of the ATOM_ROM_HEADER struct itself (32 bytes, 0x20).
const ROM_HEADER_MIN_SIZE: usize = 0x20;

/// ASCII signature expected at the start of every ATOM_ROM_HEADER.
///
/// Linux ref: atombios.h `ATOM_ROM_HEADER.uaAtomSignature = "ATOM"`.
pub const ATOM_SIGNATURE: &[u8; 4] = b"ATOM";

/// Parsed ATOM_ROM_HEADER — all fields decoded from the VBIOS image.
///
/// Field order and sizes match `ATOM_ROM_HEADER` in atombios.h.
#[derive(Copy, Clone, Debug)]
pub struct AtomRomHeader {
    /// "ATOM" ASCII signature (validated on parse).
    pub atom_signature: [u8; 4],
    /// BIOS runtime segment address (CS:IP for the BIOS ROM stub).
    pub bios_runtime_segment_address: u16,
    /// Offset to protected-mode info struct (optional; 0 = absent).
    pub protected_mode_info_offset: u16,
    /// Offset to NUL-terminated config filename string.
    pub config_filename_offset: u16,
    /// Offset to the CRC block.
    pub crc_block_offset: u16,
    /// Offset to the NUL-terminated bootup message string.
    /// This is the VBIOS version string (e.g.
    /// `"BK-AMD ATOMBIOSBK-AMD VER015.040.000.000.014546\0"`).
    ///
    /// Linux ref: `amdgpu_atombios_get_bios_version` reads this offset.
    pub bios_bootup_message_offset: u16,
    /// Offset to INT 10h handler.
    pub int10_offset: u16,
    /// PCI bus/device init code offset.
    pub pci_bus_dev_init_code: u16,
    /// IO base address for register access.
    pub io_base_address: u16,
    /// PCI subsystem vendor ID.
    pub subsystem_vendor_id: u16,
    /// PCI subsystem device ID.
    pub subsystem_id: u16,
    /// Offset to PCI info struct.
    pub pci_info_offset: u16,
    /// Offset to the master command table directory.
    pub master_command_table_offset: u16,
    /// Offset to the master data table directory.
    pub master_data_table_offset: u16,
    /// Extended function code (rarely non-zero in modern VBIOSes).
    pub extended_function_code: u8,
    /// Reserved.
    pub reserved: u8,
}

/// Errors from ATOM_ROM_HEADER parsing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// Image is too short to hold even the ROM header pointer at 0x48.
    InvalidVbios,
    /// ROM header pointer points outside the image bounds.
    InvalidVbios2,
    /// The 4-byte ATOM signature is not "ATOM".
    BadAtomSignature,
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HeaderError::InvalidVbios => write!(f, "image too short"),
            HeaderError::InvalidVbios2 => write!(f, "ROM header pointer out of bounds"),
            HeaderError::BadAtomSignature => write!(f, "bad ATOM signature"),
        }
    }
}

/// Read a little-endian `u16` from `image[offset..]`.
///
/// Does **not** bounds-check: callers must ensure the image is long enough.
#[inline]
fn read_u16(image: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([image[offset], image[offset + 1]])
}

/// Parse the `ATOM_ROM_HEADER` from a VBIOS image.
///
/// Steps:
/// 1. Check `image.len() >= MIN_IMAGE_LEN` (at least 0x4A bytes).
/// 2. Read the little-endian `u16` pointer at offset 0x48 → `hdr_off`.
/// 3. Check `hdr_off + ROM_HEADER_MIN_SIZE <= image.len()`.
/// 4. Validate `image[hdr_off..hdr_off+4] == "ATOM"`.
/// 5. Decode all fields.
///
/// Linux ref: `amdgpu_atombios.c::amdgpu_atombios_get_bios_version`
/// uses this same two-step indirection:
///   `bios[0x48..0x4A]` → pointer → header fields.
pub fn parse_rom_header(image: &[u8]) -> Result<AtomRomHeader, HeaderError> {
    if image.len() < MIN_IMAGE_LEN {
        return Err(HeaderError::InvalidVbios);
    }

    let hdr_off = read_u16(image, ROM_HEADER_PTR_OFFSET) as usize;
    let end = hdr_off
        .checked_add(ROM_HEADER_MIN_SIZE)
        .ok_or(HeaderError::InvalidVbios2)?;
    if end > image.len() {
        return Err(HeaderError::InvalidVbios2);
    }

    // Validate the ATOM signature.
    let sig = [
        image[hdr_off],
        image[hdr_off + 1],
        image[hdr_off + 2],
        image[hdr_off + 3],
    ];
    if &sig != ATOM_SIGNATURE {
        return Err(HeaderError::BadAtomSignature);
    }

    Ok(AtomRomHeader {
        atom_signature: sig,
        bios_runtime_segment_address: read_u16(image, hdr_off + 0x04),
        protected_mode_info_offset: read_u16(image, hdr_off + 0x06),
        config_filename_offset: read_u16(image, hdr_off + 0x08),
        crc_block_offset: read_u16(image, hdr_off + 0x0A),
        bios_bootup_message_offset: read_u16(image, hdr_off + 0x0C),
        int10_offset: read_u16(image, hdr_off + 0x0E),
        pci_bus_dev_init_code: read_u16(image, hdr_off + 0x10),
        io_base_address: read_u16(image, hdr_off + 0x12),
        subsystem_vendor_id: read_u16(image, hdr_off + 0x14),
        subsystem_id: read_u16(image, hdr_off + 0x16),
        pci_info_offset: read_u16(image, hdr_off + 0x18),
        master_command_table_offset: read_u16(image, hdr_off + 0x1A),
        master_data_table_offset: read_u16(image, hdr_off + 0x1C),
        extended_function_code: image[hdr_off + 0x1E],
        reserved: image[hdr_off + 0x1F],
    })
}
