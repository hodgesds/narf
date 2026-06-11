//! `brcmfmac` PCIe shared-memory map — TCM ("BAR2 / dongle RAM")
//! protocol the firmware publishes at the address written into the
//! last 4 bytes of the firmware blob's RAM region.
//!
//! ## Discovery sequence (Linux pcie.c)
//!
//! After the host downloads the firmware blob to `ci->rambase` and
//! releases the ARM CM3 from reset, the firmware boots and writes the
//! address of its shared-info block into the last 4 bytes of RAM. The
//! host polls those 4 bytes (`brcmf_pcie_download_fw_nvram` ~L1758)
//! until they flip from the prior sentinel to a non-zero value, then
//! treats that value as a TCM address pointing at a
//! [`SharedInfoLayout`] struct.
//!
//! The host reads:
//!   - `flags`        @ +0   → 32-bit; low 8 bits are the version,
//!     upper bits are feature flags
//!     (DMA_INDEX / HOSTRDY_DB1 / etc).
//!   - `console_addr` @ +20  → pointer to the firmware-side console
//!     ring (debug; not required for assoc).
//!   - `max_rxbufpost`@ +34  → 16-bit; cap on how many RX buffers the
//!     host pre-posts.
//!   - `rx_dataoffset`@ +36  → 32-bit; bytes from start of an RX DMA
//!     buffer to the 802.11 payload.
//!   - `htod_mb_data` @ +40  → 32-bit; host→dongle mailbox-data slot.
//!   - `dtoh_mb_data` @ +44  → 32-bit; dongle→host mailbox-data slot.
//!   - `ring_info`    @ +48  → 32-bit; pointer to the
//!     `RingInfoLayout` block.
//!   - `scratch_len`  @ +52  → 32-bit; scratch DMA buffer length.
//!   - `scratch_addr` @ +56  → 64-bit; host phys of scratch buffer.
//!   - `ringupd_len`  @ +64  → 32-bit; ring-update DMA buffer length.
//!   - `ringupd_addr` @ +68  → 64-bit; host phys of ringupd buffer.
//!
//! The `RingInfoLayout` block at `ring_info` then describes where each
//! of the five common rings lives in TCM (`ringmem` field) and where
//! the read/write index slots are (either in TCM or in host-side DMA).
//!
//! ## References
//!
//! - Linux `drivers/net/wireless/broadcom/brcm80211/brcmfmac/pcie.c`
//!     - `brcmf_pcie_init_share_ram_info`        (~L1617..L1670)
//!     - `BRCMF_SHARED_*` offset constants       (~L227..L237)
//!     - `struct brcmf_pcie_shared_info`         (~L299..L318)
//!     - `struct brcmf_pcie_dhi_ringinfo`        (~L393..L406)

#![allow(dead_code)]

use core::convert::TryInto;

// ── Shared-info offset constants (Linux pcie.c ~L227..L237) ────────

/// Offset of the 16-bit `max_rxbufpost` field.
/// `BRCMF_SHARED_MAX_RXBUFPOST_OFFSET`.
pub const SHARED_MAX_RXBUFPOST_OFFSET: u32 = 34;

/// Offset of the 32-bit `rx_dataoffset` field. The 802.11 payload of
/// an RX-complete DMA buffer starts this many bytes from the buffer's
/// base. Firmware-provided to allow extra metadata in front.
pub const SHARED_RX_DATAOFFSET_OFFSET: u32 = 36;

/// Offset of the firmware-side console base pointer. Debug-only.
pub const SHARED_CONSOLE_ADDR_OFFSET: u32 = 20;

/// Offset of the H2D mailbox-data TCM address.
pub const SHARED_HTOD_MB_DATA_ADDR_OFFSET: u32 = 40;

/// Offset of the D2H mailbox-data TCM address.
pub const SHARED_DTOH_MB_DATA_ADDR_OFFSET: u32 = 44;

/// Offset of the ringinfo TCM address. The host follows this pointer
/// to find the per-ring memory map.
pub const SHARED_RING_INFO_ADDR_OFFSET: u32 = 48;

/// Offset of the scratch-buffer length (`BRCMF_SHARED_DMA_SCRATCH_LEN_OFFSET`).
pub const SHARED_DMA_SCRATCH_LEN_OFFSET: u32 = 52;
/// Offset of the 64-bit scratch-buffer host phys
/// (`BRCMF_SHARED_DMA_SCRATCH_ADDR_OFFSET`).
pub const SHARED_DMA_SCRATCH_ADDR_OFFSET: u32 = 56;
/// Offset of the ring-update DMA-buffer length
/// (`BRCMF_SHARED_DMA_RINGUPD_LEN_OFFSET`).
pub const SHARED_DMA_RINGUPD_LEN_OFFSET: u32 = 64;
/// Offset of the 64-bit ring-update host phys
/// (`BRCMF_SHARED_DMA_RINGUPD_ADDR_OFFSET`).
pub const SHARED_DMA_RINGUPD_ADDR_OFFSET: u32 = 68;

// ── Shared-info `flags` field (Linux pcie.c ~L216..L222) ───────────

/// Mask for the protocol version in the `flags` field.
pub const SHARED_VERSION_MASK: u32 = 0x0000_00FF;
/// Minimum shared-mem protocol version this driver supports
/// (`BRCMF_PCIE_MIN_SHARED_VERSION`).
pub const SHARED_VERSION_MIN: u8 = 5;
/// Maximum shared-mem protocol version this driver supports
/// (`BRCMF_PCIE_SHARED_VERSION_7`). v7 introduces 24-byte TX status
/// and 40-byte RX complete.
pub const SHARED_VERSION_MAX: u8 = 7;

/// Set if the firmware can DMA the ring read/write indices into a host
/// memory region instead of into TCM. Driver prefers this when set.
pub const SHARED_FLAG_DMA_INDEX: u32 = 0x0001_0000;
/// Set with `DMA_INDEX` when the indices are 2-byte (vs. 4-byte) per
/// slot. The driver picks the read/write helper accordingly.
pub const SHARED_FLAG_DMA_2B_IDX: u32 = 0x0010_0000;
/// Set if the firmware wants HOSTRDY signalled via DB1 (the second
/// mailbox doorbell). Older firmware signals via DB0.
pub const SHARED_FLAG_HOSTRDY_DB1: u32 = 0x1000_0000;

/// Split-mode H2D flag — the firmware supports separate submission /
/// completion ring layouts (`BRCMF_PCIE_FLAGS_HTOD_SPLIT`).
pub const SHARED_FLAG_HTOD_SPLIT: u32 = 0x0000_4000;
/// Split-mode D2H counterpart (`BRCMF_PCIE_FLAGS_DTOH_SPLIT`).
pub const SHARED_FLAG_DTOH_SPLIT: u32 = 0x0000_8000;

/// Default cap on pre-posted RX buffers when the firmware's
/// `max_rxbufpost` field is 0 (`BRCMF_DEF_MAX_RXBUFPOST`).
pub const DEF_MAX_RXBUFPOST: u16 = 255;

// ── SharedInfoLayout ───────────────────────────────────────────────

/// Decoded view of the firmware-published shared-RAM block.
///
/// The block lives in TCM (BAR2) at the address the firmware reports
/// via the last 4 bytes of RAM. Field offsets match Linux's
/// `BRCMF_SHARED_*` macros (pcie.c ~L227..L237).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SharedInfo {
    /// Raw `flags` value — low byte is version, upper bits are feature
    /// flags (DMA_INDEX / HOSTRDY_DB1 / etc).
    pub flags: u32,
    /// Per-protocol-version byte (= `flags & SHARED_VERSION_MASK`).
    pub version: u8,
    /// Cap on number of pre-posted RX buffers. Saturated to
    /// `DEF_MAX_RXBUFPOST` (255) by Linux when the firmware reports 0.
    pub max_rxbufpost: u16,
    /// Bytes from start of an RX DMA buffer to the 802.11 payload.
    pub rx_dataoffset: u32,
    /// TCM address of the H2D mailbox-data slot.
    pub htod_mb_data_addr: u32,
    /// TCM address of the D2H mailbox-data slot.
    pub dtoh_mb_data_addr: u32,
    /// TCM address of the [`RingInfo`] block.
    pub ring_info_addr: u32,
    /// Firmware-side console base. Debug; safe to ignore for assoc.
    pub console_addr: u32,
}

impl SharedInfo {
    /// Parse a snapshot of the shared-info block. `bytes` is the
    /// host-side copy that the caller `memcpy_fromio()`'d out of TCM.
    /// Returns `None` on a too-short buffer or an out-of-range version.
    ///
    /// Mirrors Linux `brcmf_pcie_init_share_ram_info` (pcie.c
    /// ~L1617..L1670).
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        // We need everything through `RING_INFO_ADDR_OFFSET + 4` to
        // safely produce a `SharedInfo`. Offsets are 0, 20, 34, 36,
        // 40, 44, 48; the last one needs 4 bytes for the u32 read, so
        // 52 bytes minimum.
        if bytes.len() < 52 {
            return None;
        }
        let flags = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        let version = (flags & SHARED_VERSION_MASK) as u8;
        if !(SHARED_VERSION_MIN..=SHARED_VERSION_MAX).contains(&version) {
            return None;
        }
        let console_addr = u32::from_le_bytes(
            bytes[SHARED_CONSOLE_ADDR_OFFSET as usize..SHARED_CONSOLE_ADDR_OFFSET as usize + 4]
                .try_into()
                .ok()?,
        );
        let mut max_rxbufpost = u16::from_le_bytes(
            bytes[SHARED_MAX_RXBUFPOST_OFFSET as usize..SHARED_MAX_RXBUFPOST_OFFSET as usize + 2]
                .try_into()
                .ok()?,
        );
        if max_rxbufpost == 0 {
            max_rxbufpost = DEF_MAX_RXBUFPOST;
        }
        let rx_dataoffset = u32::from_le_bytes(
            bytes[SHARED_RX_DATAOFFSET_OFFSET as usize..SHARED_RX_DATAOFFSET_OFFSET as usize + 4]
                .try_into()
                .ok()?,
        );
        let htod_mb_data_addr = u32::from_le_bytes(
            bytes[SHARED_HTOD_MB_DATA_ADDR_OFFSET as usize
                ..SHARED_HTOD_MB_DATA_ADDR_OFFSET as usize + 4]
                .try_into()
                .ok()?,
        );
        let dtoh_mb_data_addr = u32::from_le_bytes(
            bytes[SHARED_DTOH_MB_DATA_ADDR_OFFSET as usize
                ..SHARED_DTOH_MB_DATA_ADDR_OFFSET as usize + 4]
                .try_into()
                .ok()?,
        );
        let ring_info_addr = u32::from_le_bytes(
            bytes[SHARED_RING_INFO_ADDR_OFFSET as usize..SHARED_RING_INFO_ADDR_OFFSET as usize + 4]
                .try_into()
                .ok()?,
        );
        Some(Self {
            flags,
            version,
            max_rxbufpost,
            rx_dataoffset,
            htod_mb_data_addr,
            dtoh_mb_data_addr,
            ring_info_addr,
            console_addr,
        })
    }

    /// True iff the firmware advertises a 2-byte DMA-indices layout
    /// (host-memory indices, half the slot size).
    pub const fn uses_dma_2b_indices(&self) -> bool {
        (self.flags & SHARED_FLAG_DMA_INDEX) != 0 && (self.flags & SHARED_FLAG_DMA_2B_IDX) != 0
    }

    /// True iff the firmware DMAs indices to host memory at all (vs.
    /// keeping them in TCM where the host has to do MMIO reads).
    pub const fn uses_dma_indices(&self) -> bool {
        (self.flags & SHARED_FLAG_DMA_INDEX) != 0
    }

    /// True iff HOSTRDY is signalled via the DB1 mailbox (newer
    /// firmware). Older firmware uses DB0.
    pub const fn hostrdy_db1(&self) -> bool {
        (self.flags & SHARED_FLAG_HOSTRDY_DB1) != 0
    }

    /// True iff this is a pre-v7 firmware (different TX/RX complete
    /// item sizes — the msgbuf layer's `pre_v7` flag).
    pub const fn pre_v7(&self) -> bool {
        self.version < 7
    }
}

// ── RingInfoLayout (Linux pcie.c ~L393..L406, ~L239..L248) ─────────
//
// The ringinfo block at `shared.ring_info_addr` describes where the
// five common rings live and where their read/write indices are. Wire
// layout (little-endian, packed):
//
//   ringmem            u32  @ 0   (TCM base of the ring-memory table)
//   h2d_w_idx_ptr      u32  @ 4
//   h2d_r_idx_ptr      u32  @ 8
//   d2h_w_idx_ptr      u32  @ 12
//   d2h_r_idx_ptr      u32  @ 16
//   h2d_w_idx_hostaddr u64  @ 20..28
//   h2d_r_idx_hostaddr u64  @ 28..36
//   d2h_w_idx_hostaddr u64  @ 36..44
//   d2h_r_idx_hostaddr u64  @ 44..52
//   max_flowrings      u16  @ 52
//   max_submissionrings u16 @ 54  (>=v6 only; falls back to flowrings)
//   max_completionrings u16 @ 56  (>=v6 only; falls back to 3)
//
// Reference: Linux `brcmf_pcie_dhi_ringinfo` (pcie.c ~L393).

/// Wire size of `brcmf_pcie_dhi_ringinfo` (pcie.c ~L393).
pub const RINGINFO_SIZE: usize = 58;

/// Decoded ringinfo block.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RingInfo {
    /// TCM base of the per-ring memory descriptor table. Each per-ring
    /// entry occupies `BRCMF_RING_MEM_SZ = 16` bytes starting from
    /// here (Linux pcie.c ~L1316).
    pub ringmem: u32,
    pub h2d_w_idx_ptr: u32,
    pub h2d_r_idx_ptr: u32,
    pub d2h_w_idx_ptr: u32,
    pub d2h_r_idx_ptr: u32,
    pub h2d_w_idx_hostaddr: u64,
    pub h2d_r_idx_hostaddr: u64,
    pub d2h_w_idx_hostaddr: u64,
    pub d2h_r_idx_hostaddr: u64,
    pub max_flowrings: u16,
    pub max_submissionrings: u16,
    pub max_completionrings: u16,
}

impl RingInfo {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < RINGINFO_SIZE {
            return None;
        }
        Some(Self {
            ringmem: u32::from_le_bytes(bytes[0..4].try_into().ok()?),
            h2d_w_idx_ptr: u32::from_le_bytes(bytes[4..8].try_into().ok()?),
            h2d_r_idx_ptr: u32::from_le_bytes(bytes[8..12].try_into().ok()?),
            d2h_w_idx_ptr: u32::from_le_bytes(bytes[12..16].try_into().ok()?),
            d2h_r_idx_ptr: u32::from_le_bytes(bytes[16..20].try_into().ok()?),
            h2d_w_idx_hostaddr: u64::from_le_bytes(bytes[20..28].try_into().ok()?),
            h2d_r_idx_hostaddr: u64::from_le_bytes(bytes[28..36].try_into().ok()?),
            d2h_w_idx_hostaddr: u64::from_le_bytes(bytes[36..44].try_into().ok()?),
            d2h_r_idx_hostaddr: u64::from_le_bytes(bytes[44..52].try_into().ok()?),
            max_flowrings: u16::from_le_bytes(bytes[52..54].try_into().ok()?),
            max_submissionrings: u16::from_le_bytes(bytes[54..56].try_into().ok()?),
            max_completionrings: u16::from_le_bytes(bytes[56..58].try_into().ok()?),
        })
    }
}

/// Per-ring memory descriptor in the ring-memory table at
/// `ringinfo.ringmem`. Each entry is 16 bytes:
///
///   max_item   u16 LE @ 4
///   len_items  u16 LE @ 6  (= depth of usable items; bookkeeping)
///   base_addr  u64 LE @ 8..16 (TCM base of the ring's slot storage)
///
/// Reference: Linux pcie.c ~L244..L247 (`BRCMF_RING_*_OFFSET`,
/// `BRCMF_RING_MEM_SZ = 16`).
pub const RING_MEM_SZ: u32 = 16;
pub const RING_MEM_MAX_ITEM_OFFSET: u32 = 4;
pub const RING_MEM_LEN_ITEMS_OFFSET: u32 = 6;
pub const RING_MEM_BASE_ADDR_OFFSET: u32 = 8;

/// One entry from the `ringmem` table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RingMemEntry {
    pub max_item: u16,
    pub len_items: u16,
    pub base_addr: u64,
}

impl RingMemEntry {
    /// Parse one 16-byte entry from the ring-memory table.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < RING_MEM_SZ as usize {
            return None;
        }
        let max_item = u16::from_le_bytes(
            bytes[RING_MEM_MAX_ITEM_OFFSET as usize..RING_MEM_MAX_ITEM_OFFSET as usize + 2]
                .try_into()
                .ok()?,
        );
        let len_items = u16::from_le_bytes(
            bytes[RING_MEM_LEN_ITEMS_OFFSET as usize..RING_MEM_LEN_ITEMS_OFFSET as usize + 2]
                .try_into()
                .ok()?,
        );
        let base_addr = u64::from_le_bytes(
            bytes[RING_MEM_BASE_ADDR_OFFSET as usize..RING_MEM_BASE_ADDR_OFFSET as usize + 8]
                .try_into()
                .ok()?,
        );
        Some(Self {
            max_item,
            len_items,
            base_addr,
        })
    }
}
