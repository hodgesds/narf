//! ATOM ROM header, following Linux `atombios.h` and `atom.h`.
//!
//! The PCI signature is 55 AA. A u16 at image offset 0x48 points to
//! a common table header (size, format revision, content revision).
//! Relative to that header: signature +4, boot message +0x10,
//! command directory +0x1e, data directory +0x20. V2.1 appends a
//! PSP directory pointer after the 36-byte legacy header.

/// Byte offset of the u16 pointer to ATOM_ROM_HEADER within the VBIOS image.
///
/// Linux ref: atombios.h `OFFSET_TO_POINTER_TO_ATOM_ROM_HEADER = 0x48`.
pub const ROM_HEADER_PTR_OFFSET: usize = 0x48;

/// Size of the ROM_HEADER_PTR_OFFSET field (u16, 2 bytes).
pub const ROM_HEADER_PTR_SIZE: usize = 2;

/// Minimum image size to safely read the ROM header pointer.
pub const MIN_IMAGE_LEN: usize = ROM_HEADER_PTR_OFFSET + ROM_HEADER_PTR_SIZE;

/// Minimum size of the ATOM_ROM_HEADER struct itself (36 bytes, 0x24).
const ROM_HEADER_MIN_SIZE: usize = 0x24;

/// ASCII signature expected after the common header of every ATOM_ROM_HEADER.
///
/// Linux ref: atombios.h `ATOM_ROM_HEADER.uaAtomSignature = "ATOM"`.
pub const ATOM_SIGNATURE: &[u8; 4] = b"ATOM";

/// Parsed ATOM_ROM_HEADER — all fields decoded from the VBIOS image.
///
/// Decoded fields from `ATOM_ROM_HEADER`; this Rust struct is not a wire overlay.
#[derive(Copy, Clone, Debug)]
pub struct AtomRomHeader {
    pub structure_size: u16,
    pub format_revision: u8,
    pub content_revision: u8,
    /// "ATOM" or legacy "MOTA" signature (validated on parse).
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
    /// Image is too short or lacks the 55 AA PCI ROM signature.
    InvalidVbios,
    /// ROM header pointer or declared structure size is invalid.
    InvalidVbios2,
    /// The signature is neither "ATOM" nor its legacy "MOTA" spelling.
    BadAtomSignature,
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HeaderError::InvalidVbios => write!(f, "invalid PCI ROM image"),
            HeaderError::InvalidVbios2 => write!(f, "invalid ROM header bounds"),
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
/// 4. Bound the declared header size and validate its signature at +4.
/// 5. Decode all fields.
///
/// Linux ref: `amdgpu_atombios.c::amdgpu_atombios_get_bios_version`
/// uses this same two-step indirection:
///   `bios[0x48..0x4A]` → pointer → header fields.
pub fn parse_rom_header(image: &[u8]) -> Result<AtomRomHeader, HeaderError> {
    if image.len() < MIN_IMAGE_LEN || image[..2] != [0x55, 0xaa] {
        return Err(HeaderError::InvalidVbios);
    }

    let hdr_off = read_u16(image, ROM_HEADER_PTR_OFFSET) as usize;
    let end = hdr_off
        .checked_add(ROM_HEADER_MIN_SIZE)
        .ok_or(HeaderError::InvalidVbios2)?;
    if hdr_off == 0 || end > image.len() {
        return Err(HeaderError::InvalidVbios2);
    }

    let structure_size = read_u16(image, hdr_off);
    if (structure_size as usize) < ROM_HEADER_MIN_SIZE
        || hdr_off + structure_size as usize > image.len()
    {
        return Err(HeaderError::InvalidVbios2);
    }
    let sig: [u8; 4] = image[hdr_off + 4..hdr_off + 8].try_into().unwrap();
    if &sig != ATOM_SIGNATURE && &sig != b"MOTA" {
        return Err(HeaderError::BadAtomSignature);
    }

    Ok(AtomRomHeader {
        structure_size,
        format_revision: image[hdr_off + 2],
        content_revision: image[hdr_off + 3],
        atom_signature: sig,
        bios_runtime_segment_address: read_u16(image, hdr_off + 0x08),
        protected_mode_info_offset: read_u16(image, hdr_off + 0x0A),
        config_filename_offset: read_u16(image, hdr_off + 0x0C),
        crc_block_offset: read_u16(image, hdr_off + 0x0E),
        bios_bootup_message_offset: read_u16(image, hdr_off + 0x10),
        int10_offset: read_u16(image, hdr_off + 0x12),
        pci_bus_dev_init_code: read_u16(image, hdr_off + 0x14),
        io_base_address: read_u16(image, hdr_off + 0x16),
        subsystem_vendor_id: read_u16(image, hdr_off + 0x18),
        subsystem_id: read_u16(image, hdr_off + 0x1A),
        pci_info_offset: read_u16(image, hdr_off + 0x1C),
        master_command_table_offset: read_u16(image, hdr_off + 0x1E),
        master_data_table_offset: read_u16(image, hdr_off + 0x20),
        extended_function_code: image[hdr_off + 0x22],
        reserved: image[hdr_off + 0x23],
    })
}
