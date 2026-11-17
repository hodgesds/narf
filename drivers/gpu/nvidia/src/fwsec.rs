//! FWSEC-FRTS — patch the VBIOS FWSEC microcode to carve WPR2.
//!
//! Before the booter ([`crate::gsp_boot`]) can run, the WPR2 region
//! must be created in the framebuffer by the **FWSEC** microcode,
//! which lives inside the card's VBIOS. The host locates it, patches
//! in the "FRTS" command (region addr/size) + the RSA signature, and
//! runs it on the GSP Falcon.
//!
//! ## This module (the ABI-critical core)
//!
//! The pure, unit-tested transform: given the extracted FWSEC ucode
//! image + its descriptor, patch the DMEMMAPPER command and the FRTS
//! parameters, and locate/patch the signature. Grounded against
//! `/usr/src/linux` `nvkm/subdev/gsp/fwsec.c` + the Rust nova-core
//! `firmware/fwsec.rs` / `firmware.rs`.
//!
//! Turing FWSEC is a **v3** (PKC-signed) descriptor; that is the path
//! implemented here. Locating the ucode in the VBIOS (BIT → PMU table
//! → FWSEC_PROD entry) and the hardware run (Falcon PIO load + boot +
//! WPR2/mailbox check) are separate sub-lanes; the run reuses
//! [`crate::falcon::Falcon::load_imem_v1`] and the completion checks
//! in [`crate::gsp_boot`].

#![allow(dead_code)]

// ── Constants (verified vs fwsec.c / nova-core fwsec.rs) ──────────

/// VBIOS PMU-table application id for the production FWSEC ucode.
pub const APPID_FWSEC_PROD: u8 = 0x85;
/// …and the debug build.
pub const APPID_FWSEC_DBG: u8 = 0x45;

/// `NVFW_FALCON_APPIF_ID_DMEMMAPPER` — the application-interface entry
/// that carries the command slot.
pub const APPIF_ID_DMEMMAPPER: u32 = 0x4;
/// `init_cmd` value selecting the FRTS (carve WPR2) command.
pub const DMEMMAPPER_CMD_FRTS: u32 = 0x15;
/// …and the SB (pre-OS scrub) command.
pub const DMEMMAPPER_CMD_SB: u32 = 0x19;
/// FRTS region type: framebuffer.
pub const FRTS_REGION_TYPE_FB: u32 = 2;
/// Offset of `init_cmd` within the DMEMMAPPER v3 block.
pub const DMEMMAPPER_INIT_CMD_OFF: usize = 0x2c;
/// Offset of `cmd_in_buffer_offset` within the DMEMMAPPER v3 block.
pub const DMEMMAPPER_CMD_IN_BUF_OFF: usize = 0x08;
/// Size of a BCRT3.0 RSA-3K signature.
pub const RSA3K_SIG_SIZE: usize = 384;
/// Size of the 44-byte `FrtsCmd` (ReadVbios[24] + FrtsRegion[20]).
pub const FRTS_CMD_SIZE: usize = 44;

// ── FalconUCodeDescV3 (Turing) ───────────────────────────────────

/// Error parsing/patching a FWSEC ucode.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwsecError {
    /// Descriptor buffer too small, or a declared offset ran past the
    /// ucode image.
    OutOfBounds(&'static str),
    /// The descriptor's valid bit was clear or the version was not 3.
    BadDescriptor,
    /// The application-interface header version was not 1.
    BadAppifHeader,
    /// No DMEMMAPPER (`id == 0x4`) entry was found in the interface.
    NoDmemMapper,
    /// The fuse version is not among the descriptor's signature
    /// versions.
    NoMatchingSignature,
    /// No BIT table (`\xff\xb8BIT`) was found in the VBIOS.
    VbiosNoBit,
    /// No falcon-data (`0x70`) token was found in the BIT table.
    VbiosNoFalconData,
    /// No production FWSEC (`0x85`) entry was found in the PMU table.
    VbiosNoFwsec,
}

/// The v3 Falcon ucode descriptor (44 bytes). Cite
/// `nvkm_falcon_ucode_desc_v3` / nova-core `FalconUCodeDescV3`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FalconUcodeDescV3 {
    pub hdr: u32,
    pub stored_size: u32,
    pub pkc_data_offset: u32,
    pub interface_offset: u32,
    pub imem_phys_base: u32,
    pub imem_load_size: u32,
    pub imem_virt_base: u32,
    pub dmem_phys_base: u32,
    pub dmem_load_size: u32,
    pub engine_id_mask: u16,
    pub ucode_id: u8,
    pub signature_count: u8,
    pub signature_versions: u16,
}

impl FalconUcodeDescV3 {
    pub const SIZE: usize = 0x2c;

    /// Header size encoded in `Hdr` bits[31:16] — the ucode payload
    /// begins this many bytes after the descriptor.
    pub const fn header_size(&self) -> usize {
        ((self.hdr & 0xffff_0000) >> 16) as usize
    }

    /// Descriptor version from `Hdr` bits[15:8].
    pub const fn version(&self) -> u8 {
        ((self.hdr & 0x0000_ff00) >> 8) as u8
    }

    /// Valid bit (`Hdr` bit 0).
    pub const fn valid(&self) -> bool {
        self.hdr & 1 != 0
    }

    /// Parse a v3 descriptor from the first [`Self::SIZE`] bytes.
    pub fn parse(buf: &[u8]) -> Result<Self, FwsecError> {
        if buf.len() < Self::SIZE {
            return Err(FwsecError::OutOfBounds("desc"));
        }
        let rd32 = |o: usize| u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        let rd16 = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]);
        let d = Self {
            hdr: rd32(0x00),
            stored_size: rd32(0x04),
            pkc_data_offset: rd32(0x08),
            interface_offset: rd32(0x0c),
            imem_phys_base: rd32(0x10),
            imem_load_size: rd32(0x14),
            imem_virt_base: rd32(0x18),
            dmem_phys_base: rd32(0x1c),
            dmem_load_size: rd32(0x20),
            engine_id_mask: rd16(0x24),
            ucode_id: buf[0x26],
            signature_count: buf[0x27],
            signature_versions: rd16(0x28),
        };
        if !d.valid() || d.version() != 3 {
            return Err(FwsecError::BadDescriptor);
        }
        Ok(d)
    }

    /// Byte offset of the DMEM image within the flat ucode (v3 packs
    /// DMEM immediately after IMEM).
    pub const fn dmem_base_img(&self) -> usize {
        self.imem_load_size as usize
    }

    /// Byte offset in the flat ucode where the signature is patched.
    pub const fn sig_base_img(&self) -> usize {
        self.dmem_base_img() + self.pkc_data_offset as usize
    }
}

// ── FRTS command + DMEMMAPPER patch (pure) ───────────────────────

/// Build the 44-byte `FrtsCmd` (ReadVbios + FrtsRegion). `frts_addr`
/// and `frts_size` are byte addresses; the firmware wants them
/// page-granular (`>> 12`). Cite `fwsec.c:70` / nova-core
/// `FrtsCmd`.
pub fn frts_cmd_bytes(frts_addr: u64, frts_size: u64) -> [u8; FRTS_CMD_SIZE] {
    let mut b = [0u8; FRTS_CMD_SIZE];
    let p32 = |b: &mut [u8], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    // read_vbios (24 bytes): ver=1, hdr=24, addr=0 (u64), size=0, flags=2.
    p32(&mut b, 0x00, 1);
    p32(&mut b, 0x04, 24);
    // addr @0x08 (u64) = 0, size @0x10 = 0.
    p32(&mut b, 0x14, 2); // flags
                          // frts_region (20 bytes): ver=1, hdr=20, addr, size, type=FB.
    p32(&mut b, 0x18, 1);
    p32(&mut b, 0x1c, 20);
    p32(&mut b, 0x20, (frts_addr >> 12) as u32);
    p32(&mut b, 0x24, (frts_size >> 12) as u32);
    p32(&mut b, 0x28, FRTS_REGION_TYPE_FB);
    b
}

/// Patch the FWSEC ucode in place for the FRTS command: walk the
/// application-interface table to the DMEMMAPPER block, set its
/// `init_cmd` to FRTS, and write the `FrtsCmd` into the command-input
/// buffer. Returns the absolute offset of the command buffer within
/// `ucode`. Mirrors `fwsec.c::nvkm_gsp_fwsec_patch` / nova-core
/// `new_fwsec`.
pub fn patch_frts(
    ucode: &mut [u8],
    desc: &FalconUcodeDescV3,
    frts_addr: u64,
    frts_size: u64,
) -> Result<usize, FwsecError> {
    let dmem = desc.dmem_base_img();
    // Application-interface header at dmem + interface_offset.
    let hdr_off = dmem
        .checked_add(desc.interface_offset as usize)
        .ok_or(FwsecError::OutOfBounds("appif_hdr"))?;
    let hdr = ucode
        .get(hdr_off..hdr_off + 4)
        .ok_or(FwsecError::OutOfBounds("appif_hdr"))?;
    if hdr[0] != 1 {
        return Err(FwsecError::BadAppifHeader);
    }
    let (ent_hdr, ent_len, ent_cnt) = (hdr[1] as usize, hdr[2] as usize, hdr[3] as usize);
    // Find the DMEMMAPPER entry (id == 0x4).
    let mut dmem_base = None;
    for i in 0..ent_cnt {
        let e = hdr_off + ent_hdr + i * ent_len;
        let s = ucode
            .get(e..e + 8)
            .ok_or(FwsecError::OutOfBounds("appif_entry"))?;
        let id = u32::from_le_bytes([s[0], s[1], s[2], s[3]]);
        if id == APPIF_ID_DMEMMAPPER {
            dmem_base = Some(u32::from_le_bytes([s[4], s[5], s[6], s[7]]) as usize);
            break;
        }
    }
    let dmem_base = dmem_base.ok_or(FwsecError::NoDmemMapper)?;
    // DMEMMAPPER block at dmem + dmem_base.
    let map_off = dmem
        .checked_add(dmem_base)
        .ok_or(FwsecError::OutOfBounds("dmemmapper"))?;
    // cmd_in_buffer_offset is at +0x08.
    let cmd_buf_rel = {
        let o = map_off + DMEMMAPPER_CMD_IN_BUF_OFF;
        let s = ucode
            .get(o..o + 4)
            .ok_or(FwsecError::OutOfBounds("dmemmapper"))?;
        u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize
    };
    // Patch init_cmd = FRTS at +0x2c.
    let init_off = map_off + DMEMMAPPER_INIT_CMD_OFF;
    ucode
        .get_mut(init_off..init_off + 4)
        .ok_or(FwsecError::OutOfBounds("init_cmd"))?
        .copy_from_slice(&DMEMMAPPER_CMD_FRTS.to_le_bytes());
    // Write the FrtsCmd into dmem + cmd_in_buffer_offset.
    let cmd_off = dmem
        .checked_add(cmd_buf_rel)
        .ok_or(FwsecError::OutOfBounds("frts_cmd"))?;
    let cmd = frts_cmd_bytes(frts_addr, frts_size);
    ucode
        .get_mut(cmd_off..cmd_off + FRTS_CMD_SIZE)
        .ok_or(FwsecError::OutOfBounds("frts_cmd"))?
        .copy_from_slice(&cmd);
    Ok(cmd_off)
}

// ── Signature selection + patch (pure) ───────────────────────────

/// Select which of the descriptor's signatures to use for a given
/// fuse version: the index is the popcount of set signature-version
/// bits *below* the fuse-version bit. On Turing the fuse version is 0
/// (no fuse read), giving index 0. Mirrors nova-core
/// `FwsecFirmware::new` / `fwsec.c` (which has no `.signature`
/// callback for tu102). Returns an error if the fuse version is not
/// present in `signature_versions`.
pub fn select_signature_index(
    signature_versions: u16,
    fuse_version: u8,
) -> Result<usize, FwsecError> {
    let bit = 1u32 << fuse_version;
    if signature_versions as u32 & bit == 0 {
        return Err(FwsecError::NoMatchingSignature);
    }
    Ok((signature_versions as u32 & (bit - 1)).count_ones() as usize)
}

/// Patch the selected RSA signature into the ucode at
/// [`FalconUcodeDescV3::sig_base_img`]. `sig` is one 384-byte
/// signature.
pub fn patch_signature(
    ucode: &mut [u8],
    desc: &FalconUcodeDescV3,
    sig: &[u8],
) -> Result<(), FwsecError> {
    if sig.len() != RSA3K_SIG_SIZE {
        return Err(FwsecError::OutOfBounds("sig_len"));
    }
    let off = desc.sig_base_img();
    ucode
        .get_mut(off..off + RSA3K_SIG_SIZE)
        .ok_or(FwsecError::OutOfBounds("sig_dst"))?
        .copy_from_slice(sig);
    Ok(())
}

// ── F2: locate FWSEC in the VBIOS (BIT → PMU → desc) ─────────────
//
// On a raw ROM read the chain uses absolute byte offsets (the nvkm
// flat-ROM model): scan for the BIT table, follow its falcon-data
// (0x70) token to the PMU lookup table, find the production FWSEC
// (0x85) entry, and read the FalconUCodeDesc offset from it. Cite
// `nvkm/subdev/bios/{bit,pmu}.c` + nova-core `vbios.rs`.

/// BIT table signature (`0xff 0xb8 "BIT"`).
pub const BIT_MAGIC: [u8; 5] = [0xff, 0xb8, b'B', b'I', b'T'];
/// BIT token id for the falcon/PMU data pointer.
pub const BIT_TOKEN_FALCON_DATA: u8 = 0x70;

/// Where the FWSEC ucode lives within the VBIOS image.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FwsecLocation {
    /// Offset of the `FalconUCodeDesc`.
    pub desc_offset: usize,
    /// Offset of the ucode image (`desc + header_size`).
    pub ucode_offset: usize,
    /// Length of the ucode image (`imem_load_size + dmem_load_size`).
    pub ucode_len: usize,
    /// Offset of the first RSA signature (`desc + descriptor size`).
    pub sig_offset: usize,
}

fn rom_rd16(rom: &[u8], o: usize) -> Option<u16> {
    rom.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn rom_rd32(rom: &[u8], o: usize) -> Option<u32> {
    rom.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Scan the VBIOS for the BIT table, returning the offset of its
/// signature.
pub fn find_bit_offset(rom: &[u8]) -> Option<usize> {
    rom.windows(BIT_MAGIC.len()).position(|w| w == BIT_MAGIC)
}

/// Follow the BIT table's falcon-data (`0x70`) token to the location
/// that holds the PMU-table pointer. The BIT header carries the entry
/// stride at `+9` and the entry count at `+10`; entries start at
/// `+12`, each `{id@0, version@1, length@2 (u16), offset@4 (u16)}`.
pub fn find_falcon_data_ptr(rom: &[u8], bit_off: usize) -> Option<usize> {
    let stride = *rom.get(bit_off + 9)? as usize;
    let count = *rom.get(bit_off + 10)? as usize;
    let base = bit_off + 12;
    for i in 0..count {
        let e = base + i * stride;
        if *rom.get(e)? == BIT_TOKEN_FALCON_DATA {
            return Some(rom_rd16(rom, e + 4)? as usize);
        }
    }
    None
}

/// Locate the production FWSEC ucode in a raw VBIOS image. Walks
/// BIT → falcon-data pointer → PMU lookup table → the `0x85`
/// (FWSEC_PROD) entry → the `FalconUCodeDesc`, then reads the
/// descriptor to bound the ucode + signature regions. All offsets are
/// absolute within `rom` and bounds-checked.
pub fn locate_fwsec(rom: &[u8]) -> Result<FwsecLocation, FwsecError> {
    let bit = find_bit_offset(rom).ok_or(FwsecError::VbiosNoBit)?;
    let fdp = find_falcon_data_ptr(rom, bit).ok_or(FwsecError::VbiosNoFalconData)?;
    // The PMU lookup table pointer is a u32 at the falcon-data location.
    let pmu = rom_rd32(rom, fdp).ok_or(FwsecError::VbiosNoFalconData)? as usize;
    // PMU header: ver@0, hdr@1, entry-len@2, count@3.
    let hdr = *rom.get(pmu + 1).ok_or(FwsecError::VbiosNoFwsec)? as usize;
    let len = *rom.get(pmu + 2).ok_or(FwsecError::VbiosNoFwsec)? as usize;
    let cnt = *rom.get(pmu + 3).ok_or(FwsecError::VbiosNoFwsec)? as usize;
    // Entries: {application_id@0 (u8), target_id@1 (u8), data@2 (u32)}.
    let mut desc_offset = None;
    for i in 0..cnt {
        let e = pmu + hdr + i * len;
        if *rom.get(e).ok_or(FwsecError::VbiosNoFwsec)? == APPID_FWSEC_PROD {
            desc_offset = Some(rom_rd32(rom, e + 2).ok_or(FwsecError::VbiosNoFwsec)? as usize);
            break;
        }
    }
    let desc_offset = desc_offset.ok_or(FwsecError::VbiosNoFwsec)?;
    // Read the descriptor to size the ucode + signature regions.
    let desc_bytes = rom
        .get(desc_offset..desc_offset + FalconUcodeDescV3::SIZE)
        .ok_or(FwsecError::OutOfBounds("vbios_desc"))?;
    let desc = FalconUcodeDescV3::parse(desc_bytes)?;
    let ucode_offset = desc_offset + desc.header_size();
    let ucode_len = desc.imem_load_size as usize + desc.dmem_load_size as usize;
    // The ucode image must lie within the ROM.
    if ucode_offset
        .checked_add(ucode_len)
        .is_none_or(|end| end > rom.len())
    {
        return Err(FwsecError::OutOfBounds("vbios_ucode"));
    }
    Ok(FwsecLocation {
        desc_offset,
        ucode_offset,
        ucode_len,
        sig_offset: desc_offset + FalconUcodeDescV3::SIZE,
    })
}
