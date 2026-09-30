//! DMCUB firmware preparation, before any GPU memory or registers are written.
//!
//! Wire references: Linux `amdgpu_ucode.h`, `amdgpu_dm_dmub.c`,
//! `dmub_srv.c::dmub_srv_get_fw_meta_info_from_raw_fw` and `dmub_cmd.h`.
//! The PSP receives the signed instruction payload; a direct-load path uses
//! instructions with the PSP header/footer removed. Neither is the whole file.
//! Authentication belongs to the firmware registry, not this format parser.

use core::ops::Range;

pub const DCN314_FIRMWARE: &str = "amdgpu/dcn_3_1_4_dmcub.bin";
const HEADER_SIZE: usize = 40;
const PSP_HEADER_SIZE: usize = 256;
const META_SIZE: usize = 64;
const META_MAGIC: u32 = 0x444d_5542;
const MAX_WINDOW_SIZE: usize = 16 * 1024 * 1024;
const MAX_IMAGE_SIZE: usize = MAX_WINDOW_SIZE + 4096;
const MAX_VBIOS_SIZE: usize = 1024 * 1024;
pub const RING_SIZE: u32 = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Truncated,
    UnsupportedHeader,
    InvalidSize,
    MetadataMissing,
    InvalidMetadata,
    /// DCN314's window setup has no separate BSS or shared-state mapping.
    UnsupportedLayout,
    BufferTooSmall,
    InvalidAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub version: u32,
    pub state_size: u32,
    pub trace_size: u32,
    pub shared_state_size: u32,
    pub shared_state_features: u16,
    pub feature_bits: u32,
}

/// A validated, borrowed AMD DMCUB container. No allocation or hardware access.
#[derive(Clone, Debug)]
pub struct Image<'a> {
    bytes: &'a [u8],
    signed: Range<usize>,
    instructions: Range<usize>,
    data: Range<usize>,
    version: u32,
    metadata: Metadata,
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn metadata(bytes: &[u8], tail: usize) -> Option<&[u8]> {
    let start = bytes.len().checked_sub(tail.checked_add(META_SIZE)?)?;
    let meta = &bytes[start..start + META_SIZE];
    (u32_at(meta, 0) == META_MAGIC).then_some(meta)
}

impl<'a> Image<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::Truncated);
        }
        if u32_at(bytes, 4) as usize != HEADER_SIZE
            || (u16_at(bytes, 8), u16_at(bytes, 10)) != (1, 0)
        {
            return Err(Error::UnsupportedHeader);
        }
        let size = u32_at(bytes, 0) as usize;
        let payload_size = u32_at(bytes, 20) as usize;
        let payload_start = u32_at(bytes, 24) as usize;
        let inst_size = u32_at(bytes, 32) as usize;
        let data_size = u32_at(bytes, 36) as usize;
        if size != bytes.len()
            || size > MAX_IMAGE_SIZE
            || payload_start < HEADER_SIZE
            || payload_start.checked_add(payload_size) != Some(size)
            || inst_size.checked_add(data_size) != Some(payload_size)
            || inst_size <= PSP_HEADER_SIZE + 256 + META_SIZE
        {
            return Err(Error::InvalidSize);
        }
        // The sums above prove all three ranges fit within the input.
        let signed = payload_start..payload_start + inst_size;
        let data = signed.end..size;
        let inst_start = signed.start + PSP_HEADER_SIZE;

        // Linux tries 256- then 512-byte PSP footers. In the legacy format
        // metadata lives 0x24 bytes before the end of BSS/data; in the combined
        // format it precedes the footer, with up to 15 bytes of alignment.
        let mut found = None;
        for footer in [256, 512] {
            let Some(end) = signed
                .end
                .checked_sub(footer)
                .filter(|end| *end > inst_start)
            else {
                continue;
            };
            let meta = if data.is_empty() {
                (0..16).find_map(|tail| metadata(&bytes[inst_start..end], tail))
            } else {
                metadata(&bytes[data.clone()], 0x24)
            };
            if let Some(meta) = meta {
                found = Some((end, meta));
                break;
            }
        }
        let (inst_end, meta) = found.ok_or(Error::MetadataMissing)?;
        let metadata = Metadata {
            state_size: u32_at(meta, 4),
            trace_size: u32_at(meta, 8),
            version: u32_at(meta, 12),
            shared_state_size: u32_at(meta, 20),
            shared_state_features: u16_at(meta, 24),
            feature_bits: u32_at(meta, 28),
        };
        if meta[16] != 1
            || metadata.state_size == 0
            || metadata.trace_size < 64
            || metadata.state_size as usize > MAX_WINDOW_SIZE
            || metadata.trace_size as usize > MAX_WINDOW_SIZE
            || metadata.shared_state_size as usize > MAX_WINDOW_SIZE
        {
            return Err(Error::InvalidMetadata);
        }
        Ok(Self {
            bytes,
            signed,
            instructions: inst_start..inst_end,
            data,
            version: u32_at(bytes, 16),
            metadata,
        })
    }

    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn metadata(&self) -> Metadata {
        self.metadata
    }
    /// PSP's DMCUB LOAD_IP_FW payload, including PSP packaging.
    pub fn signed_instructions(&self) -> &'a [u8] {
        &self.bytes[self.signed.clone()]
    }
    pub fn signed_offset(&self) -> usize {
        self.signed.start
    }
    /// Instruction bytes for the direct-load path, excluding PSP packaging.
    pub fn instructions(&self) -> &'a [u8] {
        &self.bytes[self.instructions.clone()]
    }
    pub fn bss_data(&self) -> &'a [u8] {
        &self.bytes[self.data.clone()]
    }

    /// Prepare the seven DCN314 cache-window regions. The supplied VBIOS must
    /// belong to this GPU; this method bounds its storage, but does not parse
    /// ATOM tables or authenticate it. No VRAM reservation is implied.
    pub fn prepare_dcn314(self, vbios: &'a [u8]) -> Result<Prepared<'a>, Error> {
        if !self.data.is_empty()
            || self.metadata.shared_state_size != 0
            || self.metadata.shared_state_features != 0
        {
            return Err(Error::UnsupportedLayout);
        }
        if vbios.is_empty() || vbios.len() > MAX_VBIOS_SIZE {
            return Err(Error::InvalidSize);
        }
        let sizes = [
            self.instructions.len(),
            (128 + 512) * 1024, // Linux DMUB_STACK_SIZE + DMUB_CONTEXT_SIZE.
            0,                  // DCN31 setup_windows does not program CW2.
            vbios.len(),
            RING_SIZE as usize * 2,
            self.metadata.trace_size as usize,
            self.metadata.state_size as usize,
        ];
        let mut regions = [Region { offset: 0, size: 0 }; 7];
        let mut end = 0;
        for (region, size) in regions.iter_mut().zip(sizes) {
            if size > MAX_WINDOW_SIZE {
                return Err(Error::InvalidSize);
            }
            region.offset = align(end, 256)?;
            region.size = align(size as u32, 64)?;
            end = region
                .offset
                .checked_add(region.size)
                .ok_or(Error::InvalidSize)?;
        }
        let layout = Layout {
            regions,
            size: align(end, 4096)?,
        };
        Ok(Prepared {
            image: self,
            vbios,
            layout,
        })
    }
}

fn align(value: u32, alignment: u32) -> Result<u32, Error> {
    value
        .checked_add(alignment - 1)
        .map(|n| n & !(alignment - 1))
        .ok_or(Error::InvalidSize)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum Window {
    Instructions,
    Stack,
    BssData,
    Vbios,
    Mailbox,
    Trace,
    State,
}

/// Byte offsets into a caller-owned allocation, not physical GPU addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub offset: u32,
    pub size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    regions: [Region; 7],
    size: u32,
}
impl Layout {
    pub fn size(&self) -> u32 {
        self.size
    }
    pub fn region(&self, window: Window) -> Region {
        self.regions[window as usize]
    }
    /// Validate an allocation's placement in a GPU-visible VRAM aperture.
    /// All addresses are GPU addresses (not PCI BAR physical addresses).
    /// The caller still must reserve and retain this range exclusively.
    /// This only computes addresses; it neither allocates nor touches memory.
    pub fn place(&self, address: u64, aperture: Range<u64>) -> Result<Placement, Error> {
        let end = address
            .checked_add(self.size as u64)
            .ok_or(Error::InvalidAddress)?;
        if address % 4096 != 0
            || aperture.start >= aperture.end
            || address < aperture.start
            || end > aperture.end
            || end > (1u64 << 48)
        {
            return Err(Error::InvalidAddress);
        }
        Ok(Placement {
            layout: *self,
            address,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    layout: Layout,
    address: u64,
}
impl Placement {
    pub fn address(&self, window: Window) -> u64 {
        self.address + self.layout.region(window).offset as u64
    }
    pub fn inbox(&self) -> u64 {
        self.address(Window::Mailbox)
    }
    pub fn outbox(&self) -> u64 {
        self.inbox() + RING_SIZE as u64
    }
}

/// A complete CPU-side image for a future DCN314 loader. Creating or staging
/// this object never implies that firmware has been loaded or booted.
#[derive(Debug)]
pub struct Prepared<'a> {
    image: Image<'a>,
    vbios: &'a [u8],
    layout: Layout,
}
impl Prepared<'_> {
    pub fn layout(&self) -> Layout {
        self.layout
    }
    /// Populate ordinary writable RAM, including zeroed padding, stack,
    /// mailbox, trace and state. Do not pass an MMIO mapping as a Rust slice;
    /// uploading to WC VRAM additionally requires volatile writes/readback.
    /// Rejects a short destination before changing any bytes, and leaves bytes
    /// beyond `layout().size()` untouched.
    pub fn stage(&self, dst: &mut [u8]) -> Result<(), Error> {
        let dst = dst
            .get_mut(..self.layout.size as usize)
            .ok_or(Error::BufferTooSmall)?;
        dst.fill(0);
        for (window, bytes) in [
            (Window::Instructions, self.image.instructions()),
            (Window::Vbios, self.vbios),
        ] {
            let offset = self.layout.region(window).offset as usize;
            dst[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dmub_firmware_tests.rs"]
mod tests;
