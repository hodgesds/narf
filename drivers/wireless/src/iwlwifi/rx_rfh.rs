//! iwlwifi receive descriptors for the Receive Flow Handler (RFH).
//!
//! From 9000-series silicon onward the receive path is the RFH, not
//! the FH that [`super::rx`] models. The difference is structural
//! rather than a matter of moved registers:
//!
//! The FH has one ring. The host posts buffers into it and the device
//! writes packets back into the same slots, so a single write-back
//! pointer says how far the device has got.
//!
//! The RFH has **two** rings per queue. The host posts empty buffers
//! onto a *free* list (FRBD) and the device returns filled ones on a
//! *used* list (URBD), each with its own index register. A buffer is
//! identified by an `rbid` tag that travels on both lists, so the
//! device is free to complete buffers in an order the host did not
//! post them in. Draining the RFH by walking one ring and assuming
//! slot order — which is all the FH ever needed — hands back the
//! wrong buffer as soon as the device reorders anything.
//!
//! The completion descriptor also shrank twice. AX210 uses a
//! 32-byte one; Bz and later — which includes Scorpius Peak, the
//! MS-03's part — use a 4-byte one. Both carry `rbid` and `flags`,
//! at different offsets, so reading one as the other yields a
//! plausible tag pointing at the wrong buffer.
//!
//! ## References (GPL-2.0-or-later, post 2026-05-20 relicense)
//!
//! - `pcie/gen1_2/internal.h` — `iwl_rx_transfer_desc`,
//!   `iwl_rx_completion_desc`, `iwl_rx_completion_desc_bz`,
//!   `IWL_RX_CD_FLAGS_FRAGMENTED`.
//! - `iwl-fh.h` — the `RFH_Q*` register block.
//! - `pcie/gen1_2/rx.c` — `iwl_pcie_rx_handle`, the completion-size
//!   selection at `IWL_DEVICE_FAMILY_BZ`, and the
//!   `HBUS_TARG_WRPTR` RX doorbell.
//!
//! The AX210+ runtime uses this wire/ownership layer for both firmware
//! startup responses and data packets. Gen2 retains its older path.

#![allow(dead_code)]

// ── Free-list (FRBD) descriptor ─────────────────────────────────────

/// `iwl_rx_transfer_desc` — one empty buffer offered to the device.
///
/// The tag comes first and the address last, with six bytes of
/// reserved space between them; 16 bytes packed.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxTransferDesc {
    /// Unique tag for this buffer, returned on the used list.
    pub rbid: u16,
    /// Reserved.
    pub reserved: [u16; 3],
    /// Host physical address of the buffer.
    pub addr: u64,
}

impl RxTransferDesc {
    /// Encode a nonzero buffer tag and DMA address in wire byte order.
    /// The caller must provide a suitably aligned, live DMA allocation.
    pub const fn new(rbid: u16, addr: u64) -> Option<Self> {
        if rbid == 0 {
            return None;
        }
        Some(Self {
            rbid: rbid.to_le(),
            reserved: [0; 3],
            addr: addr.to_le(),
        })
    }
}

// ── Used-list (URBD) descriptors ────────────────────────────────────

/// `IWL_RX_CD_FLAGS_FRAGMENTED` — the buffer holds a fragment.
pub const RX_CD_FLAGS_FRAGMENTED: u8 = 1 << 0;

/// `iwl_rx_completion_desc` — the AX210 completion descriptor.
///
/// 32 bytes, with `rbid` four bytes in behind a reserved word.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxCompletionDesc {
    /// Reserved.
    pub reserved1: u32,
    /// Tag of the buffer being returned.
    pub rbid: u16,
    /// `RX_CD_FLAGS_*`.
    pub flags: u8,
    /// Reserved.
    pub reserved2: [u8; 25],
}

/// `iwl_rx_completion_desc_bz` — the Bz-and-later descriptor, used by
/// Scorpius Peak.
///
/// Four bytes, with `rbid` at offset 0. Reading an AX210 descriptor
/// with this layout picks up the reserved word as the tag.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxCompletionDescBz {
    /// Tag of the buffer being returned.
    pub rbid: u16,
    /// `RX_CD_FLAGS_*`.
    pub flags: u8,
    /// Reserved.
    pub reserved: [u8; 1],
}

/// Which completion-descriptor layout a device family uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompletionFormat {
    /// 32-byte `iwl_rx_completion_desc`, AX210.
    Ax210,
    /// 4-byte `iwl_rx_completion_desc_bz`, Bz and later.
    Bz,
}

impl CompletionFormat {
    /// Select by MAC family, not firmware-loader generation: Sc is
    /// Bz-class, while Qu uses an older RFH transfer format that this
    /// module deliberately does not encode as an AX210 descriptor.
    pub const fn for_mac(mac: super::MacFamily) -> Option<Self> {
        use super::MacFamily;
        match mac {
            MacFamily::QuB0 | MacFamily::QuC0 | MacFamily::QuZA0 => None,
            MacFamily::TyA0 | MacFamily::SoA0 | MacFamily::MaA0 | MacFamily::MaB0 => {
                Some(Self::Ax210)
            }
            MacFamily::BzA0 | MacFamily::ScA0 => Some(Self::Bz),
        }
    }

    /// Bytes one completion descriptor occupies in the used list.
    ///
    /// This is the used ring's stride, so getting it wrong
    /// desynchronises every entry after the first.
    pub const fn size(self) -> usize {
        match self {
            CompletionFormat::Ax210 => core::mem::size_of::<RxCompletionDesc>(),
            CompletionFormat::Bz => core::mem::size_of::<RxCompletionDescBz>(),
        }
    }

    /// Decode one completion descriptor into `(rbid, fragmented)`.
    ///
    /// Returns `None` when `bytes` is shorter than this format's
    /// descriptor, rather than reading past the end of the ring.
    pub fn decode(self, bytes: &[u8]) -> Option<(u16, bool)> {
        if bytes.len() < self.size() {
            return None;
        }
        let (rbid, flags) = match self {
            CompletionFormat::Ax210 => (u16::from_le_bytes([bytes[4], bytes[5]]), bytes[6]),
            CompletionFormat::Bz => (u16::from_le_bytes([bytes[0], bytes[1]]), bytes[2]),
        };
        Some((rbid, flags & RX_CD_FLAGS_FRAGMENTED != 0))
    }

    /// Direct CSR and value for advertising posted free-list entries.
    /// Hardware consumes write indices in groups of eight. AX210 uses
    /// the RFH shadow CSR; Bz/Sc use the shared HBUS doorbell.
    /// `write_ptr` is already wrapped to the configured ring depth.
    pub const fn doorbell(self, queue: u16, write_ptr: u16) -> (u32, u32) {
        let write_actual = (write_ptr & !7) as u32;
        match self {
            Self::Ax210 => (rfh_frbdcb_widx_trg(queue as u32), write_actual),
            Self::Bz => (
                super::tx_gen2::HBUS_TARG_WRPTR,
                super::tx_gen2::rx_doorbell(queue as u32, write_actual),
            ),
        }
    }
}

/// An invalid completion must stop the drain before any buffer access.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CompletionError {
    /// The snapshot does not contain a complete descriptor.
    Truncated,
    /// Zero or a tag outside this queue's buffer pool.
    InvalidTag,
    /// The buffer was never posted, or has already been returned.
    NotPosted,
    /// An attempt to post a buffer that is still owned by hardware.
    AlreadyPosted,
}

/// One validated return, referring to a buffer rather than a ring slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ReturnedBuffer {
    /// Zero-based pool index, decoded from the one-based hardware tag.
    pub buffer_index: usize,
    /// Drop all buffers in a fragmented packet, including its final
    /// buffer (whose own fragmented flag is clear).
    pub discard: bool,
}

/// Buffer ownership and fragment-chain state for one RFH queue.
///
/// `N` is the buffer-pool size, not the used-ring stride/depth. Call
/// `post` only when publishing a free descriptor to hardware, then
/// `complete` on a snapshot from the used ring after observing the DMA
/// status write-back with the appropriate DMA read barrier. The caller
/// must finish consuming the returned buffer before posting it again.
///
/// This layer performs no MMIO or DMA access. Keeping ownership until
/// an explicit repost also detects duplicate completions within a
/// drain batch. On an error, stop the queue and recover/reset; do not
/// guess a buffer index or advance past the corrupt completion.
#[derive(Debug)]
pub struct CompletionTracker<const N: usize> {
    format: CompletionFormat,
    posted: [bool; N],
    next_is_fragment: bool,
}

impl<const N: usize> CompletionTracker<N> {
    /// Create an empty pool. Hardware tags are nonzero 16-bit values.
    pub const fn new(format: CompletionFormat) -> Self {
        assert!(N > 0 && N <= u16::MAX as usize);
        Self {
            format,
            posted: [false; N],
            next_is_fragment: false,
        }
    }

    fn index(rbid: u16) -> Result<usize, CompletionError> {
        if rbid == 0 || rbid as usize > N {
            return Err(CompletionError::InvalidTag);
        }
        Ok(rbid as usize - 1)
    }

    /// Mark a tag as published to the device. Reject double-posts.
    pub fn post(&mut self, rbid: u16) -> Result<(), CompletionError> {
        let index = Self::index(rbid)?;
        if self.posted[index] {
            return Err(CompletionError::AlreadyPosted);
        }
        self.posted[index] = true;
        Ok(())
    }

    /// Validate a used descriptor and return ownership to the host.
    /// Invalid input leaves ownership and fragment state unchanged.
    pub fn complete(&mut self, bytes: &[u8]) -> Result<ReturnedBuffer, CompletionError> {
        let (rbid, fragmented) = self
            .format
            .decode(bytes)
            .ok_or(CompletionError::Truncated)?;
        let index = Self::index(rbid)?;
        if !self.posted[index] {
            return Err(CompletionError::NotPosted);
        }
        self.posted[index] = false;
        let discard = fragmented || self.next_is_fragment;
        self.next_is_fragment = fragmented;
        Ok(ReturnedBuffer {
            buffer_index: index,
            discard,
        })
    }
}

// ── RFH registers ───────────────────────────────────────────────────
//
// These are PRPH addresses, reached through the HBUS window — not
// offsets into BAR0. The one exception is the write-index shadow at
// 0x1C80, which is a direct CSR.

/// `RFH_Q0_FRBDCB_BA_LSB` — free-list base address, 64-bit, per queue.
pub const RFH_Q0_FRBDCB_BA_LSB: u32 = 0x00A0_8000;
/// `RFH_Q0_FRBDCB_WIDX` — free-list write index.
pub const RFH_Q0_FRBDCB_WIDX: u32 = 0x00A0_8080;
/// `RFH_Q0_FRBDCB_RIDX` — free-list read index, written by the device.
pub const RFH_Q0_FRBDCB_RIDX: u32 = 0x00A0_80C0;
/// `RFH_Q0_URBDCB_BA_LSB` — used-list base address, 64-bit, per queue.
pub const RFH_Q0_URBDCB_BA_LSB: u32 = 0x00A0_8100;
/// `RFH_Q0_URBDCB_WIDX` — used-list write index.
pub const RFH_Q0_URBDCB_WIDX: u32 = 0x00A0_8180;
/// `RFH_Q0_URBDCB_VAID` — used-list valid count.
pub const RFH_Q0_URBDCB_VAID: u32 = 0x00A0_81C0;
/// `RFH_Q0_URBD_STTS_WPTR_LSB` — where the device writes the used
/// list's write pointer back into host memory, 64-bit, per queue.
pub const RFH_Q0_URBD_STTS_WPTR_LSB: u32 = 0x00A0_8200;

/// `RFH_Q0_FRBDCB_WIDX_TRG` — the shadow of the free-list write index.
///
/// Unlike every other register here this one is a *CSR offset*, not a
/// PRPH address: it lives inside BAR0 at 0x1C80 and is written
/// directly. Treating it as a PRPH address would send the index
/// through the HBUS window to an address the device does not decode.
pub const RFH_Q0_FRBDCB_WIDX_TRG: u32 = 0x1C80;

/// Base-address register for queue `q`'s free list. 64-bit
/// registers are eight bytes apart.
pub const fn rfh_frbdcb_ba_lsb(q: u32) -> u32 {
    RFH_Q0_FRBDCB_BA_LSB + q * 8
}

/// Write-index register for queue `q`'s free list.
pub const fn rfh_frbdcb_widx(q: u32) -> u32 {
    RFH_Q0_FRBDCB_WIDX + q * 4
}

/// Shadow write-index CSR for queue `q`'s free list.
pub const fn rfh_frbdcb_widx_trg(q: u32) -> u32 {
    RFH_Q0_FRBDCB_WIDX_TRG + q * 4
}

/// Read-index register for queue `q`'s free list.
pub const fn rfh_frbdcb_ridx(q: u32) -> u32 {
    RFH_Q0_FRBDCB_RIDX + q * 4
}

/// Base-address register for queue `q`'s used list.
pub const fn rfh_urbdcb_ba_lsb(q: u32) -> u32 {
    RFH_Q0_URBDCB_BA_LSB + q * 8
}

/// Write-index register for queue `q`'s used list.
pub const fn rfh_urbdcb_widx(q: u32) -> u32 {
    RFH_Q0_URBDCB_WIDX + q * 4
}

/// Used-list valid-count register for queue `q` (upstream spelling).
pub const fn rfh_urbdcb_vaid(q: u32) -> u32 {
    RFH_Q0_URBDCB_VAID + q * 4
}

/// Write-pointer write-back register for queue `q`'s used list.
pub const fn rfh_urbd_stts_wptr_lsb(q: u32) -> u32 {
    RFH_Q0_URBD_STTS_WPTR_LSB + q * 8
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use crate::iwlwifi::MacFamily;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_rfh_family_and_doorbell() -> TestResult {
        for mac in [MacFamily::BzA0, MacFamily::ScA0] {
            if CompletionFormat::for_mac(mac) != Some(CompletionFormat::Bz) {
                return TestResult::Fail("Bz and Sc use the four-byte completion format");
            }
        }
        for mac in [
            MacFamily::TyA0,
            MacFamily::SoA0,
            MacFamily::MaA0,
            MacFamily::MaB0,
        ] {
            if CompletionFormat::for_mac(mac) != Some(CompletionFormat::Ax210) {
                return TestResult::Fail("Ty/So/Ma use the 32-byte completion format");
            }
        }
        for mac in [MacFamily::QuB0, MacFamily::QuC0, MacFamily::QuZA0] {
            if CompletionFormat::for_mac(mac).is_some() {
                return TestResult::Fail("Qu requires the older RFH transfer format");
            }
        }
        for (write, actual) in [(0, 0), (7, 0), (8, 8), (15, 8), (255, 248)] {
            if CompletionFormat::Ax210.doorbell(3, write) != (0x1C8C, actual) {
                return TestResult::Fail("AX210 shadow doorbell must round down by eight");
            }
            if CompletionFormat::Bz.doorbell(3, write) != (0x460, 0x0203_0000 | actual) {
                return TestResult::Fail("Bz doorbell must encode RX queue id plus 512");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/iwlwifi/rx", smoke_rfh_family_and_doorbell);

    fn smoke_rfh_transfer_wire_bytes() -> TestResult {
        let desc = RxTransferDesc::new(0x1234, 0x1234_5678_9ABC_D000).unwrap();
        // SAFETY: repr(C, packed) has no padding, all fields were
        // initialized, and this borrow stays within the descriptor.
        let bytes = unsafe {
            core::slice::from_raw_parts((&desc as *const RxTransferDesc).cast::<u8>(), 16)
        };
        if bytes
            != [
                0x34, 0x12, 0, 0, 0, 0, 0, 0, 0, 0xD0, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12,
            ]
        {
            return TestResult::Fail("transfer descriptor tag/address must be little-endian");
        }
        if RxTransferDesc::new(0, 0x1000).is_some() {
            return TestResult::Fail("zero is not a hardware buffer tag");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/iwlwifi/rx", smoke_rfh_transfer_wire_bytes);

    fn completion(format: CompletionFormat, tag: u16, flags: u8) -> [u8; 32] {
        let mut bytes = [0; 32];
        let offset = match format {
            CompletionFormat::Ax210 => 4,
            CompletionFormat::Bz => 0,
        };
        bytes[offset..offset + 2].copy_from_slice(&tag.to_le_bytes());
        bytes[offset + 2] = flags;
        bytes
    }

    fn smoke_rfh_out_of_order_returns() -> TestResult {
        for format in [CompletionFormat::Ax210, CompletionFormat::Bz] {
            let mut tracker = CompletionTracker::<4>::new(format);
            for tag in 1..=4 {
                tracker.post(tag).unwrap();
            }
            if tracker.post(2) != Err(CompletionError::AlreadyPosted) {
                return TestResult::Fail("posting the same buffer twice must fail");
            }
            // Complete in a different order than the free descriptors.
            for tag in [3, 1, 4, 2] {
                let bytes = completion(format, tag, 0x80); // reserved flag is not fragmented
                let expected = ReturnedBuffer {
                    buffer_index: tag as usize - 1,
                    discard: false,
                };
                if tracker.complete(&bytes[..format.size()]) != Ok(expected) {
                    return TestResult::Fail(
                        "completion must select the tagged buffer, not the slot",
                    );
                }
                if tracker.complete(&bytes) != Err(CompletionError::NotPosted) {
                    return TestResult::Fail("a duplicate return must not grant ownership twice");
                }
            }
            // Tags may be reused only after the host explicitly reposts.
            tracker.post(3).unwrap();
            if tracker.complete(&completion(format, 3, 0)).is_err() {
                return TestResult::Fail("a reposted buffer must be returnable again");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/rx",
        smoke_rfh_out_of_order_returns
    );

    fn smoke_rfh_invalid_completion_preserves_state() -> TestResult {
        for format in [CompletionFormat::Ax210, CompletionFormat::Bz] {
            let mut tracker = CompletionTracker::<4>::new(format);
            tracker.post(2).unwrap();
            for tag in [0, 5, u16::MAX] {
                if tracker.post(tag) != Err(CompletionError::InvalidTag)
                    || tracker.complete(&completion(format, tag, 1))
                        != Err(CompletionError::InvalidTag)
                {
                    return TestResult::Fail("out-of-pool tags must fail before indexing");
                }
            }
            if tracker.complete(&completion(format, 1, 1)) != Err(CompletionError::NotPosted) {
                return TestResult::Fail("a valid but unpublished tag is not owned by hardware");
            }
            let bytes = completion(format, 2, 1);
            for len in 0..format.size() {
                if tracker.complete(&bytes[..len]) != Err(CompletionError::Truncated) {
                    return TestResult::Fail("short descriptors must not change ownership");
                }
            }
            if tracker.complete(&completion(format, 2, 0))
                != Ok(ReturnedBuffer {
                    buffer_index: 1,
                    discard: false,
                })
            {
                return TestResult::Fail(
                    "invalid descriptors must preserve ownership and fragment state",
                );
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/rx",
        smoke_rfh_invalid_completion_preserves_state
    );

    fn smoke_rfh_drops_entire_fragment_chain() -> TestResult {
        for format in [CompletionFormat::Ax210, CompletionFormat::Bz] {
            let mut tracker = CompletionTracker::<4>::new(format);
            for tag in 1..=4 {
                tracker.post(tag).unwrap();
            }
            // These calls can straddle drain batches/IRQs. The final
            // fragment has its own flag clear but is still discarded.
            for (tag, flags, discard) in [(3, 1, true), (1, 1, true), (4, 0, true), (2, 0, false)] {
                if tracker.complete(&completion(format, tag, flags))
                    != Ok(ReturnedBuffer {
                        buffer_index: tag as usize - 1,
                        discard,
                    })
                {
                    return TestResult::Fail(
                        "fragment tail must be dropped before normal delivery resumes",
                    );
                }
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/iwlwifi/rx",
        smoke_rfh_drops_entire_fragment_chain
    );
}
