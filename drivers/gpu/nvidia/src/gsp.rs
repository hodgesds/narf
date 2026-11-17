//! GSP — GPU System Processor (Turing+).
//!
//! ## Reference
//!
//! - **`/home/daniel/git/linux/drivers/gpu/drm/nouveau/nvkm/subdev/gsp/base.c`**
//!   — generic `nvkm_gsp_*`. The host driver stages a signed
//!   bootloader ("booter load"), waits for WPR2 to assert, then
//!   feeds the GSP firmware blob and the RM (Resource Manager)
//!   message-queue config.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/gsp/tu102.c`** — Turing
//!   GSP bring-up (cited above): WPR2_HI scratch readback +
//!   booter_load + booter_unload Falcons.
//! - **`drivers/gpu/drm/nouveau/nvkm/subdev/gsp/ga102.c`** /
//!   **`ad102.c`** — Ampere / Ada additions; RISC-V mode bits on
//!   the boot Falcon.
//!
//! ## Overview
//!
//! On Turing+ the GPU has a dedicated processor ("GSP") that
//! takes over almost every register write the host driver used
//! to do directly. The host:
//!
//! 1. Stages signed bootloader code into the boot Falcon's IMEM.
//! 2. Releases the boot Falcon; it sets up WPR2 (Window of
//!    Protected Regions 2) in VRAM and runs FWSEC.
//! 3. The GSP firmware runs inside WPR2 and exposes an RPC
//!    message queue.
//! 4. Host writes RPC messages into a ring (`MsgQ`) the firmware
//!    polls; firmware reports completion + events back through a
//!    separate ring.
//!
//! After GSP comes up, the host driver is basically a thin
//! message-pump for RPCs.

#![allow(dead_code)]

use crate::chip::ChipFamily;
use crate::falcon::{Falcon, FalconError, FALCON_BASE_GSP};

/// Per-engine `NV_PFALCON_FBIF_*` (FB interface) base offset
/// inside the GSP Falcon block. The host writes the WPR2 region
/// descriptor here. Cite `nvkm/subdev/gsp/tu102.c` &
/// `nvkm/falcon/v1.c::*_fbif`.
pub const FBIF_OFFSET: u64 = 0x0000_0600;

/// `NV_PGC6_AON_SECURE_SCRATCH_GROUP_05` — WPR2 hi address
/// scratch. Used to detect whether WPR2 is set up.
/// Cite `tu102.c::tu102_gsp_booter_unload` line "0x1fa828".
pub const WPR2_HI_SCRATCH: u64 = 0x001F_A828;

// ── Function + event ids (verified vs /usr/src/linux) ────────────
//
// `NV_VGPU_MSG_FUNCTION_*` are host→GSP commands; `NV_VGPU_MSG_EVENT_*`
// are GSP→host notifications. Grounded against
// `rm/r535/nvrm/{rpcfn,msgfn}.h` and `rm/r535/gsp.c`. (An earlier
// `GspRpcFn` placeholder enum carried wrong values — e.g. NOP=1 — and
// is removed; use [`GspRpcCmd`] for commands and these for events.)

/// `NV_VGPU_MSG_FUNCTION_NOP` — link-test ping.
pub const NV_VGPU_MSG_FUNCTION_NOP: u32 = 0;
/// `NV_VGPU_MSG_FUNCTION_GET_GSP_STATIC_INFO`.
pub const NV_VGPU_MSG_FUNCTION_GET_GSP_STATIC_INFO: u32 = 65;
/// `NV_VGPU_MSG_FUNCTION_GSP_SET_SYSTEM_INFO`.
pub const NV_VGPU_MSG_FUNCTION_GSP_SET_SYSTEM_INFO: u32 = 72;
/// `NV_VGPU_MSG_FUNCTION_SET_REGISTRY`.
pub const NV_VGPU_MSG_FUNCTION_SET_REGISTRY: u32 = 73;

/// `NV_VGPU_MSG_EVENT_GSP_INIT_DONE` — firmware reports init done.
pub const NV_VGPU_MSG_EVENT_GSP_INIT_DONE: u32 = 0x1001;
/// `NV_VGPU_MSG_EVENT_GSP_RUN_CPU_SEQUENCER`.
pub const NV_VGPU_MSG_EVENT_GSP_RUN_CPU_SEQUENCER: u32 = 0x1002;
/// `NV_VGPU_MSG_EVENT_POST_EVENT`.
pub const NV_VGPU_MSG_EVENT_POST_EVENT: u32 = 0x1003;

/// Full RPC function table — every command the host sends to GSP
/// during normal-mode driver operation. Numbers match
/// `nvkm/subdev/gsp/rm/r535/nvrm/rpcfn.h`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum GspRpcCmd {
    Nop = 0,
    SetGuestSystemInfo = 1,
    AllocRoot = 2,
    AllocMemory = 4,
    AllocCtxDma = 5,
    AllocChannelDma = 6,
    MapMemory = 7,
    AllocObject = 9,
    Free = 10,
    Log = 11,
    AllocVidmem = 12,
    UnmapMemory = 13,
    MapMemoryDma = 14,
    UnmapMemoryDma = 15,
    GetEdid = 16,
    AllocDispChannel = 17,
    AllocDispObject = 18,
    AllocSubdevice = 19,
    AllocDynamicMemory = 20,
    DupObject = 21,
    IdleChannels = 22,
    AllocEvent = 23,
    SendEvent = 24,
    DmaControl = 26,
    DmaFillPteMem = 27,
    ManageHwResource = 28,
    UnloadingGuestDriver = 47,
    GpuExecRegOps = 50,
    GetStaticInfo = 51,
    UpdatePde2 = 53,
    SetPageDirectory = 54,
    UpdateGpuPdes = 61,
    GetGspStaticInfo = 65,
    GspSetSystemInfo = 72,
    SetRegistry = 73,
    GspRmControl = 76,
    GetStaticInfo2 = 77,
    UnsetPageDirectory = 79,
}

/// The inner RPC header (`struct nvfw_gsp_rpc` / `rpc_message_header_
/// v03_00`) — 8 × u32 = 32 bytes, followed by the per-RPC payload.
/// Verified verbatim against `rm/r535/rpc.c:94` and
/// `rm/r535/nvrm/gsp.h:793`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GspRpcHeader {
    /// `0x03000000`.
    pub header_version: u32,
    /// `0x43505256` ('C','P','R','V').
    pub signature: u32,
    /// `sizeof(header) + payload_len` (i.e. includes these 32 bytes).
    pub length: u32,
    /// Function / event id (`GspRpcCmd::*` / `NV_VGPU_MSG_EVENT_*`).
    pub function: u32,
    /// `0xffffffff` on send; result code on the GSP's reply.
    pub rpc_result: u32,
    /// `0xffffffff` on send.
    pub rpc_result_private: u32,
    /// Monotonic sequence, or 0 for a fire-and-forget (NOSEQ) RPC.
    pub sequence: u32,
    /// `spare` / `cpuRmGfid` — 0.
    pub spare: u32,
}

/// `header_version` constant. Cite `rpc.c:622`.
pub const GSP_RPC_HEADER_VERSION: u32 = 0x0300_0000;
/// RPC signature `'C','P','R','V'`. Cite `rpc.c:623`
/// (`('C'<<24)|('P'<<16)|('R'<<8)|'V'`).
pub const GSP_RPC_SIGNATURE: u32 = 0x4350_5256;
/// Size of the inner RPC header on the wire.
pub const GSP_RPC_HDR_SIZE: usize = 32;

impl GspRpcHeader {
    /// Build a header for an outbound RPC. `payload_len` excludes the
    /// header; `length` is set to the full `32 + payload_len`. Send-
    /// side result fields are the `0xffffffff` sentinels.
    pub const fn new(function: u32, payload_len: u32, sequence: u32) -> Self {
        Self {
            header_version: GSP_RPC_HEADER_VERSION,
            signature: GSP_RPC_SIGNATURE,
            length: GSP_RPC_HDR_SIZE as u32 + payload_len,
            function,
            rpc_result: 0xFFFF_FFFF,
            rpc_result_private: 0xFFFF_FFFF,
            sequence,
            spare: 0,
        }
    }

    /// Pack into 32 little-endian bytes (the wire layout).
    pub fn to_bytes(&self) -> [u8; GSP_RPC_HDR_SIZE] {
        let mut b = [0u8; GSP_RPC_HDR_SIZE];
        b[0..4].copy_from_slice(&self.header_version.to_le_bytes());
        b[4..8].copy_from_slice(&self.signature.to_le_bytes());
        b[8..12].copy_from_slice(&self.length.to_le_bytes());
        b[12..16].copy_from_slice(&self.function.to_le_bytes());
        b[16..20].copy_from_slice(&self.rpc_result.to_le_bytes());
        b[20..24].copy_from_slice(&self.rpc_result_private.to_le_bytes());
        b[24..28].copy_from_slice(&self.sequence.to_le_bytes());
        b[28..32].copy_from_slice(&self.spare.to_le_bytes());
        b
    }

    /// Decode 32 bytes back into a header.
    pub fn from_bytes(b: &[u8; GSP_RPC_HDR_SIZE]) -> Self {
        let rd = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        Self {
            header_version: rd(0),
            signature: rd(4),
            length: rd(8),
            function: rd(12),
            rpc_result: rd(16),
            rpc_result_private: rd(20),
            sequence: rd(24),
            spare: rd(28),
        }
    }

    /// True if the signature matches.
    pub const fn signature_ok(&self) -> bool {
        self.signature == GSP_RPC_SIGNATURE
    }
}

// ── Outer message element + queue headers ────────────────────────

/// Outer message-queue element header (`struct r535_gsp_msg` /
/// `GSP_MSG_QUEUE_ELEMENT`) — 48 bytes, wrapping the inner
/// [`GspRpcHeader`] + payload. Cite `rm/r535/rpc.c:94`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GspMsgElement {
    pub auth_tag_buffer: [u8; 16],
    pub aad_buffer: [u8; 16],
    /// Set so the XOR checksum over the whole (page-aligned) message
    /// is zero.
    pub checksum: u32,
    /// Per-cmdq sequence number.
    pub sequence: u32,
    /// Number of `GSP_PAGE_SIZE` slots this message occupies.
    pub elem_count: u32,
    pub pad: u32,
}

/// Size of the outer element header (`GSP_MSG_HDR_SIZE`).
pub const GSP_MSG_HDR_SIZE: usize = 48;
/// Message-queue slot / page size.
pub const GSP_PAGE_SIZE: usize = 4096;
/// GSP cmdq doorbell: write 0 to the GSP Falcon's channel-ring
/// register to tell the firmware a new cmdq entry is ready. Cite
/// `rpc.c:411` (`nvkm_falcon_wr32(&gsp->falcon, 0xc00, 0)`); absolute
/// BAR0 offset = GSP Falcon base + 0xc00.
pub const GSP_DOORBELL_OFFSET: u64 = crate::falcon::FALCON_BASE_GSP + 0x0C00;

impl GspMsgElement {
    pub fn to_bytes(&self) -> [u8; GSP_MSG_HDR_SIZE] {
        let mut b = [0u8; GSP_MSG_HDR_SIZE];
        b[0..16].copy_from_slice(&self.auth_tag_buffer);
        b[16..32].copy_from_slice(&self.aad_buffer);
        b[32..36].copy_from_slice(&self.checksum.to_le_bytes());
        b[36..40].copy_from_slice(&self.sequence.to_le_bytes());
        b[40..44].copy_from_slice(&self.elem_count.to_le_bytes());
        b[44..48].copy_from_slice(&self.pad.to_le_bytes());
        b
    }
}

/// `msgqTxHeader` — the producer side of a queue (32 bytes). Cite
/// `rm/r535/nvrm/gsp.h:561`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct MsgqTxHeader {
    pub version: u32,
    pub size: u32,
    pub msg_size: u32,
    pub msg_count: u32,
    pub write_ptr: u32,
    pub flags: u32,
    pub rx_hdr_off: u32,
    pub entry_off: u32,
}

/// `msgqRxHeader` — the consumer side (4 bytes): `readPtr`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct MsgqRxHeader {
    pub read_ptr: u32,
}

/// XOR checksum over `buf` as 64-bit little-endian words: the element
/// `checksum` field is set so this folds to zero. Returns
/// `upper_32 ^ lower_32` of the running XOR. `buf` must be a whole
/// number of 8-byte words (the message is page-aligned in practice).
/// Cite `rpc.c:363` (`r535_gsp_msgq_checksum`).
pub fn rpc_checksum(buf: &[u8]) -> u32 {
    let mut acc: u64 = 0;
    for chunk in buf.chunks_exact(8) {
        acc ^= u64::from_le_bytes(chunk.try_into().unwrap());
    }
    ((acc >> 32) as u32) ^ (acc as u32)
}

/// GSP RPC message-queue ring. Cite
/// `rm/r535/rpc.c::r535_gsp_cmdq_push` / `..._msgq_peek`.
///
/// The firmware shares two queues — host→GSP (cmdq) and GSP→host
/// (msgq) — in a DMA-coherent buffer. The read/write pointers are
/// **message (page) indices**, not byte offsets: entry `n` lives at
/// `entry_off + n * GSP_PAGE_SIZE`. This matches `msgqTxHeader.
/// {writePtr,msgCount}` whose units are "message id".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GspRpcRing {
    /// Phys address of the queue region base.
    pub base_phys: u64,
    /// Number of page-sized entry slots (`msgqTxHeader.msgCount`).
    pub msg_count: u32,
    /// Read pointer — message index (consumer side advances it).
    pub rptr: u32,
    /// Write pointer — message index (producer side advances it).
    pub wptr: u32,
}

impl GspRpcRing {
    pub const fn new(base_phys: u64, msg_count: u32) -> Self {
        Self {
            base_phys,
            msg_count,
            rptr: 0,
            wptr: 0,
        }
    }

    /// True when there is nothing to consume.
    pub const fn is_empty(&self) -> bool {
        self.rptr == self.wptr
    }

    /// Slots currently occupied: `(wptr + count - rptr) % count`.
    /// Cite `rpc.c` `used = wptr + cnt - rptr; if (used >= cnt) used -= cnt`.
    pub const fn used(&self) -> u32 {
        let u = self
            .wptr
            .wrapping_add(self.msg_count)
            .wrapping_sub(self.rptr);
        if u >= self.msg_count {
            u - self.msg_count
        } else {
            u
        }
    }

    /// Free slots, keeping one empty to disambiguate full from empty.
    pub const fn free(&self) -> u32 {
        self.msg_count - 1 - self.used()
    }

    /// True if `slots` consecutive entries will not fit.
    pub const fn is_full(&self, slots: u32) -> bool {
        self.free() < slots
    }

    /// Byte offset of entry `idx` from the queue region base. The
    /// header page occupies slot 0's worth of space, so entries start
    /// one page in. Cite `msgqTxHeader.entryOff = GSP_PAGE_SIZE`.
    pub const fn entry_offset(idx: u32) -> u64 {
        GSP_PAGE_SIZE as u64 + (idx as u64) * GSP_PAGE_SIZE as u64
    }
}

/// Number of page slots a message of `payload_len` bytes occupies
/// (outer element + inner header + payload, page-aligned).
pub const fn rpc_message_slots(payload_len: usize) -> u32 {
    let total = GSP_MSG_HDR_SIZE + GSP_RPC_HDR_SIZE + payload_len;
    (total.div_ceil(GSP_PAGE_SIZE)) as u32
}

/// Assemble a complete GSP RPC message into `out`: the 48-byte outer
/// element, the 32-byte inner header, then the payload — and set the
/// element checksum so the XOR over the page-aligned message folds to
/// zero. `out` must be at least `rpc_message_slots(payload) *
/// GSP_PAGE_SIZE` bytes and is zeroed by the caller. Returns the
/// aligned message length. Cite `rpc.c::r535_gsp_cmdq_push`.
pub fn build_rpc_message(
    function: u32,
    sequence: u32,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, GspRpcError> {
    let slots = rpc_message_slots(payload.len());
    let aligned = slots as usize * GSP_PAGE_SIZE;
    if out.len() < aligned {
        return Err(GspRpcError::Overflow);
    }
    out[..aligned].fill(0);
    // Outer element (checksum left 0 for now).
    let elem = GspMsgElement {
        auth_tag_buffer: [0; 16],
        aad_buffer: [0; 16],
        checksum: 0,
        sequence,
        elem_count: slots,
        pad: 0,
    };
    out[..GSP_MSG_HDR_SIZE].copy_from_slice(&elem.to_bytes());
    // Inner RPC header.
    let hdr = GspRpcHeader::new(function, payload.len() as u32, sequence);
    out[GSP_MSG_HDR_SIZE..GSP_MSG_HDR_SIZE + GSP_RPC_HDR_SIZE].copy_from_slice(&hdr.to_bytes());
    // Payload.
    let body = GSP_MSG_HDR_SIZE + GSP_RPC_HDR_SIZE;
    out[body..body + payload.len()].copy_from_slice(payload);
    // Checksum so the fold is zero: store upper^lower into the field.
    let csum = rpc_checksum(&out[..aligned]);
    out[32..36].copy_from_slice(&csum.to_le_bytes());
    Ok(aligned)
}

/// Parse a GSP RPC message from `buf`: verify the checksum folds to
/// zero and the inner signature matches, then return the inner header
/// and the payload slice. Cite `rpc.c::r535_gsp_msg_recv`.
pub fn parse_rpc_message(buf: &[u8]) -> Result<(GspRpcHeader, &[u8]), GspRpcError> {
    if buf.len() < GSP_MSG_HDR_SIZE + GSP_RPC_HDR_SIZE {
        return Err(GspRpcError::Overflow);
    }
    let elem_count = u32::from_le_bytes([buf[40], buf[41], buf[42], buf[43]]).max(1) as usize;
    let aligned = (elem_count * GSP_PAGE_SIZE).min(buf.len());
    if rpc_checksum(&buf[..aligned]) != 0 {
        return Err(GspRpcError::BadChecksum);
    }
    let mut hb = [0u8; GSP_RPC_HDR_SIZE];
    hb.copy_from_slice(&buf[GSP_MSG_HDR_SIZE..GSP_MSG_HDR_SIZE + GSP_RPC_HDR_SIZE]);
    let hdr = GspRpcHeader::from_bytes(&hb);
    if !hdr.signature_ok() {
        return Err(GspRpcError::BadSignature);
    }
    let payload_len = (hdr.length as usize).saturating_sub(GSP_RPC_HDR_SIZE);
    let body = GSP_MSG_HDR_SIZE + GSP_RPC_HDR_SIZE;
    if body + payload_len > buf.len() {
        return Err(GspRpcError::Overflow);
    }
    Ok((hdr, &buf[body..body + payload_len]))
}

/// GSP handle. Wraps a Falcon at the GSP base + ring descriptors.
pub struct Gsp<'a> {
    pub falcon: Falcon<'a>,
    pub cmdq: GspRpcRing,
    pub msgq: GspRpcRing,
}

impl<'a> core::fmt::Debug for Gsp<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Gsp")
            .field("falcon_base", &FALCON_BASE_GSP)
            .field("cmdq", &self.cmdq)
            .field("msgq", &self.msgq)
            .finish()
    }
}

impl<'a> Gsp<'a> {
    pub const fn new(
        bar0: &'a narf_driver_runtime::MmioRegion,
        cmdq: GspRpcRing,
        msgq: GspRpcRing,
    ) -> Self {
        Self {
            falcon: Falcon::new(bar0, FALCON_BASE_GSP, "gsp"),
            cmdq,
            msgq,
        }
    }

    /// Pre-flight check: family must be Turing+ to have a GSP.
    pub fn family_has_gsp(family: ChipFamily) -> bool {
        family.has_gsp()
    }

    /// Read WPR2_HI scratch — non-zero means WPR2 is set up,
    /// i.e. the booter Falcon has run. Cite tu102.c line
    /// "0x1fa828".
    ///
    /// # Safety
    /// `bar0` is mapped and covers offset WPR2_HI_SCRATCH.
    pub unsafe fn wpr2_active(&self) -> bool {
        // SAFETY: caller's responsibility.
        unsafe { self.falcon.bar0.read32(WPR2_HI_SCRATCH) != 0 }
    }

    /// Wait for `wpr2_active` to flip true.
    ///
    /// # Safety
    /// Same.
    pub unsafe fn wait_wpr2(&self, max_polls: u32) -> Result<(), FalconError> {
        for _ in 0..max_polls {
            // SAFETY: caller's responsibility.
            if unsafe { self.wpr2_active() } {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(FalconError::IdleTimeout)
    }

    /// Ring the cmdq doorbell: tell the GSP firmware a new command
    /// entry is ready. Cite `rpc.c:411`
    /// (`nvkm_falcon_wr32(&gsp->falcon, 0xc00, 0)`).
    ///
    /// # Safety
    /// `bar0` is mapped and the cmdq entry + updated write pointer are
    /// already visible to the device (a write barrier precedes this).
    pub unsafe fn ring_doorbell(&self) {
        // SAFETY: GSP_DOORBELL_OFFSET is within the BAR0 window.
        unsafe { self.falcon.bar0.write32(GSP_DOORBELL_OFFSET, 0) };
    }
}

/// Errors from the live GSP RPC layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GspRpcError {
    /// Message wouldn't fit in the destination buffer.
    Overflow,
    /// Reply header had a wrong signature — torn write or bad fw.
    BadSignature,
    /// The element checksum did not fold to zero (torn/corrupt).
    BadChecksum,
    /// Firmware reported a non-zero `rpc_result`.
    FirmwareError(u32),
}

/// The GSP init handshake, in order, after the message rings are up.
/// Steps 1–2 are fire-and-forget (NOSEQ); step 3 is an event the GSP
/// posts that the host polls for. Cite `rm/r535/gsp.c::r535_gsp_init`
/// / `r535_gsp_rpc_set_system_info` / `..._set_registry`.
pub const GSP_INIT_SEQUENCE: &[u32] = &[
    NV_VGPU_MSG_FUNCTION_GSP_SET_SYSTEM_INFO,
    NV_VGPU_MSG_FUNCTION_SET_REGISTRY,
    NV_VGPU_MSG_EVENT_GSP_INIT_DONE,
];

/// Build a NOP RPC body (empty). Cite
/// `nvkm/subdev/gsp/r535.c::r535_rpc_nop`.
pub const fn nop_body() -> [u8; 0] {
    []
}

/// Build a SET_GUEST_SYSTEM_INFO body. Stage 1 carries the
/// canonical fields the GSP firmware reads: OS major / minor,
/// driver version, GPU emulation flag. Layout per
/// `nvkm/subdev/gsp/r535.c::r535_rpc_set_system_info`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GspSetSystemInfo {
    pub os_major: u32,
    pub os_minor: u32,
    pub driver_version: u32,
    /// Bit 0 = host_powers_gpu, bit 1 = emulated.
    pub flags: u32,
}

impl GspSetSystemInfo {
    pub const fn new(os_major: u32, os_minor: u32, driver_version: u32) -> Self {
        Self {
            os_major,
            os_minor,
            driver_version,
            flags: 0,
        }
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&self.os_major.to_le_bytes());
        b[4..8].copy_from_slice(&self.os_minor.to_le_bytes());
        b[8..12].copy_from_slice(&self.driver_version.to_le_bytes());
        b[12..16].copy_from_slice(&self.flags.to_le_bytes());
        b
    }
}

/// Build a SET_REGISTRY body. The firmware reads up to N (key, value)
/// pairs from this; Stage 1 supports a single key.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GspSetRegistryKey {
    pub key_hash: u32,
    pub value: u32,
}

impl GspSetRegistryKey {
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[0..4].copy_from_slice(&self.key_hash.to_le_bytes());
        b[4..8].copy_from_slice(&self.value.to_le_bytes());
        b
    }
}
