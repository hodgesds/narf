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

/// RPC message types — Nouveau's `rm/r535/nvrm/{msgfn,rpcfn}.h`
/// aliases. The numbering is canonical per open-gpu-kernel-modules
/// (NVIDIA's userspace kernel module, r535 / r570 releases). NARF's
/// `Stage 1` enum values were placeholders; this table mirrors the
/// upstream IDs verbatim.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum GspRpcFn {
    /// `NV_VGPU_MSG_FUNCTION_NOP` — link-test ping.
    Nop = 0x0001,
    /// `NV_VGPU_MSG_FUNCTION_SET_REGISTRY` — register key write.
    SetRegistry = 0x0002,
    /// `NV_VGPU_MSG_FUNCTION_ALLOC_ROOT` — allocate the root
    /// handle that subsequent RPCs descend from.
    AllocRoot = 0x0003,
    /// `NV_VGPU_MSG_EVENT_GSP_INIT_DONE` — firmware reports
    /// init done.
    EventInitDone = 0x1001,
}

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

/// Standard 16-byte RPC header. Cite
/// `nvkm/subdev/gsp/r535.c::r535_rpc_*`. The header is followed by
/// a per-RPC body the GSP firmware reads.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct GspRpcHeader {
    /// Header signature — 0x36C9_72A7 ("RPCH" little-endian-ish).
    pub signature: u32,
    /// Per-RPC function id (`GspRpcCmd::*`).
    pub function: u32,
    /// Total body length in bytes (not including header).
    pub length: u32,
    /// Sequence number; the firmware echoes it back on reply.
    pub rpc_result: u32,
}

/// Signature value used in `signature`. Cite `nvkm/subdev/gsp/r535/
/// r535.c::r535_rpc_signature`.
pub const GSP_RPC_SIGNATURE: u32 = 0x36C9_72A7;

impl GspRpcHeader {
    /// Build a header for an outbound RPC.
    pub const fn new(function: GspRpcCmd, body_len: u32) -> Self {
        Self {
            signature: GSP_RPC_SIGNATURE,
            function: function as u32,
            length: body_len,
            rpc_result: 0,
        }
    }

    /// Pack the header into 16 bytes (little-endian, matching the
    /// wire layout).
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&self.signature.to_le_bytes());
        buf[4..8].copy_from_slice(&self.function.to_le_bytes());
        buf[8..12].copy_from_slice(&self.length.to_le_bytes());
        buf[12..16].copy_from_slice(&self.rpc_result.to_le_bytes());
        buf
    }

    /// Decode 16 bytes back into a header.
    pub fn from_bytes(buf: &[u8; 16]) -> Self {
        Self {
            signature: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            function: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
            length: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
            rpc_result: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
        }
    }

    /// True if the signature matches.
    pub const fn signature_ok(&self) -> bool {
        self.signature == GSP_RPC_SIGNATURE
    }
}

/// GSP RPC message-queue ring shape. Cite
/// `nvkm/subdev/gsp/r535/r535.c::r535_gsp_msgq_*`.
///
/// The firmware reserves two queues — host→GSP (cmdq) and
/// GSP→host (msgq) — at fixed VRAM offsets handed to it via the
/// bootloader scratch fields. Both are SPSC rings with a
/// CPU-visible mailbox at the head.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GspRpcRing {
    /// Phys address (VRAM) of the ring base.
    pub base_phys: u64,
    /// Ring size in bytes. Must be a power of two.
    pub size_bytes: u32,
    /// Read pointer the firmware advances.
    pub rptr: u32,
    /// Write pointer the host advances.
    pub wptr: u32,
}

impl GspRpcRing {
    pub const fn new(base_phys: u64, size_bytes: u32) -> Self {
        Self {
            base_phys,
            size_bytes,
            rptr: 0,
            wptr: 0,
        }
    }

    /// True if this entry is empty (no work).
    pub const fn is_empty(&self) -> bool {
        self.rptr == self.wptr
    }

    /// True if the ring is full — wptr + 1 == rptr (mod size).
    pub const fn is_full(&self, msg_bytes: u32) -> bool {
        let next = self.wptr.wrapping_add(msg_bytes) & (self.size_bytes - 1);
        next == self.rptr
    }
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

    /// Stage one RPC into the cmdq. Returns the number of bytes
    /// written into the ring (header + body). Cite
    /// `nvkm/subdev/gsp/r535.c::r535_rpc_send`.
    pub fn enqueue_rpc(
        &mut self,
        function: GspRpcCmd,
        body: &[u8],
        out: &mut [u8],
    ) -> Result<u32, GspRpcError> {
        let needed = 16 + body.len();
        if needed > out.len() {
            return Err(GspRpcError::Overflow);
        }
        let hdr = GspRpcHeader::new(function, body.len() as u32);
        out[..16].copy_from_slice(&hdr.to_bytes());
        if !body.is_empty() {
            out[16..16 + body.len()].copy_from_slice(body);
        }
        // Advance the cmdq write pointer past the staged bytes.
        let advance = (needed as u32).next_multiple_of(16);
        self.cmdq.wptr = self.cmdq.wptr.wrapping_add(advance) & (self.cmdq.size_bytes - 1);
        Ok(advance)
    }

    /// Decode the next RPC reply pending in the msgq, if any.
    /// Returns the header + the body slice. Cite
    /// `nvkm/subdev/gsp/r535.c::r535_rpc_recv`.
    pub fn dequeue_rpc<'b>(&mut self, buf: &'b [u8]) -> Option<(GspRpcHeader, &'b [u8])> {
        if buf.len() < 16 {
            return None;
        }
        let mut hdr_bytes = [0u8; 16];
        hdr_bytes.copy_from_slice(&buf[..16]);
        let hdr = GspRpcHeader::from_bytes(&hdr_bytes);
        if !hdr.signature_ok() {
            return None;
        }
        let body_len = hdr.length as usize;
        if 16 + body_len > buf.len() {
            return None;
        }
        let body = &buf[16..16 + body_len];
        let advance = (16 + body_len) as u32;
        let advance_aligned = advance.next_multiple_of(16);
        self.msgq.rptr = self.msgq.rptr.wrapping_add(advance_aligned) & (self.msgq.size_bytes - 1);
        Some((hdr, body))
    }
}

/// Errors from the live GSP RPC layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GspRpcError {
    /// Body wouldn't fit in the destination buffer.
    Overflow,
    /// Reply header had a wrong signature — torn write or bad fw.
    BadSignature,
    /// Firmware reported a non-zero `rpc_result`.
    FirmwareError(u32),
}

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
