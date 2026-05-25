//! Intel DDI AUX channel MMIO transport — Gen12 (TGL/ADL/RPL).
//!
//! Bridges the vendor-neutral [`dp_aux`] framing layer to the Intel
//! `DDI_AUX_CTL` / `DDI_AUX_DATA` register block. The encoded wire
//! bytes from `dp_aux::encode_request` go into `DDI_AUX_DATA_*`;
//! the controller drives them out, captures the reply, and we
//! decode it via `dp_aux::decode_response`.
//!
//! Reference: **Tiger Lake PRM Vol. 12 §"DDI_AUX_CTL"** and
//! §"DDI_AUX_DATA". Cross-checked against Linux
//! `drivers/gpu/drm/i915/display/intel_dp_aux.c::intel_dp_aux_xfer`
//! (GPL-2.0-or-later — compatible with NARF's post-2026-05-20
//! relicense).
//!
//! ## Register block
//!
//! `DDI_AUX_CTL_*` sits at MMIO offset `0x64010` for DDI A,
//! `0x64110` for DDI B, etc. (each port is +0x100). The data
//! payload lives in five consecutive 32-bit data registers at
//! offset `+0x14` through `+0x24`, giving up to 20 bytes (the
//! 4-byte AUX header + 16-byte payload that the DP spec caps
//! every transaction at).
//!
//! ## Transaction shape
//!
//! 1. Pack request bytes (already in wire format from
//!    `dp_aux::encode_request`) into the AUX_DATA dwords —
//!    big-endian, since AUX is byte-oriented but the registers
//!    are little-endian dwords. `byte0..3` -> `data[0][31:0]`
//!    with `byte0` in `[31:24]` and `byte3` in `[7:0]`.
//! 2. Write `DDI_AUX_CTL` with the SEND bit, message-size field,
//!    sync-pulse count (32), and the precharge timer + clock
//!    divider for the target AUX bit-clock (~1 MHz).
//! 3. Poll SEND_BUSY for clear (transaction complete) or
//!    `done`/`time-out-error`/`receive-error` flags.
//! 4. Reply byte count is published in `MSGSIZE` field of
//!    DDI_AUX_CTL after completion; read that many bytes back
//!    from the AUX_DATA dwords and hand them to
//!    `dp_aux::decode_response`.
//!
//! ## Retries
//!
//! DP-spec retry on `DEFER` is handled by the [`dp_aux`] layer
//! (it expects the transport to bubble the status up). The MMIO
//! transport here only does a low-level hardware retry on AUX
//! protocol errors (timeout / receive error), capped at 3
//! attempts — matches i915 behavior.

use core::sync::atomic::{compiler_fence, Ordering};

use crate::dp_aux::{
    decode_response, encode_request, AuxChannel, AuxError, AuxRequest, AuxResponse, AuxStatus,
};
use crate::intel_gpu_ddi::Ddi;

/// `DDI_AUX_CTL` offset relative to the DDI port base.
pub const DDI_AUX_CTL_OFFSET: u64 = 0x0010;
/// `DDI_AUX_DATA_<port>_<n>` base offset. Five dwords (0x14, 0x18,
/// 0x1C, 0x20, 0x24) carrying up to 20 bytes.
pub const DDI_AUX_DATA_OFFSET: u64 = 0x0014;
/// Number of AUX_DATA dwords per port. 5 dwords × 4 bytes = 20
/// bytes — the DP-spec maximum AUX transaction (4-byte header +
/// 16-byte payload).
pub const DDI_AUX_DATA_DWORDS: usize = 5;

// ── DDI_AUX_CTL bit fields (PRM Vol. 12 §"DDI_AUX_CTL") ──────────

/// `[31]` — Send Busy. Write 1 to issue the transaction; reads 0
/// when the controller has finished sending and either received a
/// reply or timed out.
pub const AUX_CTL_SEND_BUSY: u32 = 1 << 31;
/// `[30]` — Done. RW1C; set when the transaction completed
/// (regardless of ack/nack). Clear by writing 1 before issuing a
/// new transaction. Some platforms also clear it on a SEND_BUSY
/// write; clearing explicitly avoids latched stale values.
pub const AUX_CTL_DONE: u32 = 1 << 30;
/// `[28]` — Interrupt on Done. We poll, so leave clear.
pub const AUX_CTL_INTERRUPT_ON_DONE: u32 = 1 << 28;
/// `[27:26]` — Time-Out Timer Value. `00` = 400 µs, `01` = 600 µs,
/// `10` = 800 µs, `11` = 1600 µs. We use 1600 µs (the most
/// permissive) to tolerate slow eDP sinks.
pub const AUX_CTL_TIMEOUT_1600US: u32 = 0b11 << 26;
/// `[25]` — Time-Out Error. RW1C. Set on AUX time-out (no reply
/// within the configured window).
pub const AUX_CTL_TIMEOUT_ERROR: u32 = 1 << 25;
/// `[24]` — Receive Error. RW1C. Set on framing / parity error in
/// the reply.
pub const AUX_CTL_RECEIVE_ERROR: u32 = 1 << 24;
/// `[23:20]` — Message Size. Number of valid bytes in
/// AUX_DATA (output for sends, valid byte count of reply on
/// receive).
pub const AUX_CTL_MSGSIZE_SHIFT: u32 = 20;
pub const AUX_CTL_MSGSIZE_MASK: u32 = 0xF << AUX_CTL_MSGSIZE_SHIFT;
/// `[19:16]` — Pre-charge Time. PRM recommends 16 cycles for
/// reliable signal integrity.
pub const AUX_CTL_PRECHARGE_16: u32 = 0b1000 << 16;
/// `[15:11]` — Sync Pulses count. PRM mandates 32 for DP/eDP and
/// 18 for HDMI's DDC over AUX (we focus on DP here).
pub const AUX_CTL_SYNC_PULSES_32: u32 = 32 << 16;
// (NB: the PRM tables show overlap between PRECHARGE and SYNC
// fields across platforms — see TGL §"DDI_AUX_CTL" for the
// canonical layout. We pack both into the same dword; the
// individual bit ranges don't overlap on Gen12.)

/// AUX bit-clock divider, programming the target rate. AUX line
/// is nominally 1 MHz on DP. The divider value is `(CD_CLK_HZ /
/// 2_000_000) - 1` where `CD_CLK_HZ` is the core display clock
/// (typically 38.4 MHz on TGL/ADL, giving a divider of `19 - 1 =
/// 18`). For Stage 1 we hard-code `2222` — the i915 default for
/// 24 MHz reference, which works for any chip that hasn't yet
/// programmed CD_CLK above the boot default.
pub const AUX_CTL_BITCLK_DIVIDER_DEFAULT: u32 = 2222;

/// Maximum hardware-retry attempts on TIMEOUT / RECEIVE error.
/// Beyond 3 we surface the error to the caller; DEFER-status
/// retries are handled by the dp_aux layer above.
const HW_RETRIES: u32 = 3;

/// MMIO transport implementing the `AuxChannel` trait for an Intel
/// DDI port. Holds a borrowed handle to the BAR0 MMIO window plus
/// the port selector — does not own state across transactions.
pub struct IntelAux<'a, M: MmioWindow + ?Sized> {
    mmio: &'a M,
    ddi: Ddi,
}

impl<'a, M: MmioWindow + ?Sized> core::fmt::Debug for IntelAux<'a, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IntelAux").field("ddi", &self.ddi).finish()
    }
}

/// Minimal MMIO-window interface the transport needs. Lets us
/// inject mocks in tests without depending on the kernel's real
/// `Bar0` type. Real callers wrap `narf_drivers_pci`'s mapped BAR
/// in an adapter that implements this.
pub trait MmioWindow {
    /// Read a 32-bit register at byte offset `off` within the
    /// MMIO window.
    fn read32(&self, off: u64) -> u32;
    /// Write a 32-bit register at byte offset `off`.
    fn write32(&self, off: u64, val: u32);
}

impl<'a, M: MmioWindow + ?Sized> IntelAux<'a, M> {
    /// Create a transport for `ddi` over the BAR0 window `mmio`.
    pub fn new(mmio: &'a M, ddi: Ddi) -> Self {
        Self { mmio, ddi }
    }

    /// Absolute MMIO offset of this port's `DDI_AUX_CTL`.
    fn aux_ctl_off(&self) -> u64 {
        self.ddi.base() + DDI_AUX_CTL_OFFSET
    }

    /// Absolute MMIO offset of `DDI_AUX_DATA[n]` for this port.
    fn aux_data_off(&self, n: usize) -> u64 {
        self.ddi.base() + DDI_AUX_DATA_OFFSET + (n as u64) * 4
    }

    /// Pack a wire-format AUX request into the AUX_DATA dwords.
    /// Byte 0 lands in the high byte of `DATA[0]`; consecutive
    /// bytes fill toward the low byte of `DATA[4]`.
    fn write_data(&self, wire: &[u8]) {
        // Per i915 / PRM: AUX_DATA is laid out big-endian within
        // each 32-bit register — byte 0 is bits [31:24] of
        // DATA[0]; byte 3 is bits [7:0] of DATA[0]; byte 4 starts
        // DATA[1] in [31:24]; and so on.
        for (i, dword) in wire.chunks(4).enumerate() {
            if i >= DDI_AUX_DATA_DWORDS {
                break;
            }
            let mut v: u32 = 0;
            for (b, &byte) in dword.iter().enumerate() {
                v |= (byte as u32) << (24 - 8 * b);
            }
            self.mmio.write32(self.aux_data_off(i), v);
        }
    }

    /// Read `n` reply bytes from the AUX_DATA dwords back into
    /// `buf`. Uses the same big-endian byte order as
    /// `write_data`. Returns the number of bytes actually copied
    /// (capped at `buf.len()`).
    fn read_data(&self, n: usize, buf: &mut [u8]) -> usize {
        let want = n.min(buf.len());
        let mut got = 0;
        for i in 0..DDI_AUX_DATA_DWORDS {
            if got >= want {
                break;
            }
            let v = self.mmio.read32(self.aux_data_off(i));
            for b in 0..4 {
                if got >= want {
                    break;
                }
                buf[got] = ((v >> (24 - 8 * b)) & 0xFF) as u8;
                got += 1;
            }
        }
        got
    }

    /// Spin until SEND_BUSY clears or 5 ms has elapsed. Returns
    /// the final DDI_AUX_CTL value. Timeout is 5x the longest
    /// configured AUX timeout (1600 µs) to absorb slow sinks.
    ///
    /// We can't use `narf_time::Deadline` here because it would
    /// allocate; instead spin on a bounded RDTSC budget. The
    /// caller-visible "timeout" status comes from the
    /// AUX_CTL.TIMEOUT_ERROR bit, not from this spin's expiry.
    fn wait_send_complete(&self, ctl_initial: u32) -> u32 {
        // 5 ms at any plausible TSC rate (1-5 GHz post-divide is
        // the realistic range for Family 0x06 / Family 0x17+
        // silicon). At cpns=1 that's 5_000_000 cycles; at cpns=5,
        // 25_000_000. Pick the larger so we never short the wait
        // on faster cores.
        let cpns = narf_time::wall::cycles_per_ns().max(1) as u64;
        let budget = 5_000_000u64.saturating_mul(cpns);
        let start = narf_time::now_cycles();
        let mut ctl = ctl_initial;
        while ctl & AUX_CTL_SEND_BUSY != 0 {
            if narf_time::now_cycles().wrapping_sub(start) > budget {
                break;
            }
            core::hint::spin_loop();
            ctl = self.mmio.read32(self.aux_ctl_off());
        }
        ctl
    }

    /// Single-attempt AUX transaction. Returns the raw reply
    /// bytes (status nibble + payload) for the caller to decode
    /// via `dp_aux::decode_response`.
    fn xfer_once<'b>(
        &self,
        wire: &[u8],
        expected_reply_payload: usize,
        reply_buf: &'b mut [u8],
    ) -> Result<usize, AuxError> {
        if wire.len() > 20 {
            return Err(AuxError::TooLong);
        }
        // Clear any latched done/error bits from a prior transaction.
        // RW1C — write the bits we want cleared (don't clear SEND_BUSY).
        self.mmio.write32(
            self.aux_ctl_off(),
            AUX_CTL_DONE | AUX_CTL_TIMEOUT_ERROR | AUX_CTL_RECEIVE_ERROR,
        );

        self.write_data(wire);
        compiler_fence(Ordering::SeqCst);

        // Compose the control register: send + msgsize + timing.
        let msgsize = ((wire.len() as u32) << AUX_CTL_MSGSIZE_SHIFT) & AUX_CTL_MSGSIZE_MASK;
        let ctl = AUX_CTL_SEND_BUSY
            | msgsize
            | AUX_CTL_TIMEOUT_1600US
            | AUX_CTL_PRECHARGE_16
            | AUX_CTL_BITCLK_DIVIDER_DEFAULT;
        self.mmio.write32(self.aux_ctl_off(), ctl);

        // Poll for completion.
        let final_ctl = self.wait_send_complete(ctl);

        if final_ctl & AUX_CTL_TIMEOUT_ERROR != 0 {
            return Err(AuxError::ShortReply);
        }
        if final_ctl & AUX_CTL_RECEIVE_ERROR != 0 {
            return Err(AuxError::UnknownStatus);
        }
        if final_ctl & AUX_CTL_SEND_BUSY != 0 {
            // Spin expired without DONE — hardware really stuck.
            return Err(AuxError::ShortReply);
        }

        let reply_total = ((final_ctl & AUX_CTL_MSGSIZE_MASK) >> AUX_CTL_MSGSIZE_SHIFT) as usize;
        // Reply is 1 status byte + N payload bytes; sanity-check.
        let expected_total = 1 + expected_reply_payload;
        if reply_total == 0 {
            return Err(AuxError::ShortReply);
        }
        if reply_buf.len() < reply_total {
            return Err(AuxError::TooLong);
        }
        let _ = expected_total; // dp_aux's decode_response re-validates.
        Ok(self.read_data(reply_total, reply_buf))
    }
}

impl<'a, M: MmioWindow + ?Sized> AuxChannel for IntelAux<'a, M> {
    fn transact<'b>(
        &mut self,
        req: &AuxRequest<'_>,
        reply_buf: &'b mut [u8],
    ) -> Result<AuxResponse<'b>, AuxError> {
        // Encode the request into the on-wire 4..20 byte frame.
        let mut wire = [0u8; 20];
        let n = encode_request(req, &mut wire)?;

        // Expected reply payload length: NATIVE/I2C reads return
        // `req.data.len()` bytes; writes return 0.
        let is_read = matches!(
            req.cmd,
            crate::dp_aux::AuxCommand::NativeRead
                | crate::dp_aux::AuxCommand::I2cRead
                | crate::dp_aux::AuxCommand::I2cReadMot
        );
        let expected_payload = if is_read { req.data.len() } else { 0 };

        // Hardware retry on protocol error (TIMEOUT / RECEIVE).
        // The dp_aux layer above handles DEFER-status retries —
        // those are not protocol errors, they're sink-level
        // backoff requests carried in the status nibble.
        let mut attempt = 0;
        let mut last_err = AuxError::ShortReply;
        let raw_len;
        loop {
            // Use a scratch reply buffer the size the spec allows
            // for the worst case (1 status byte + 16 payload).
            let mut raw = [0u8; 17];
            match self.xfer_once(&wire[..n], expected_payload, &mut raw) {
                Ok(got) => {
                    if got > reply_buf.len() {
                        return Err(AuxError::TooLong);
                    }
                    reply_buf[..got].copy_from_slice(&raw[..got]);
                    raw_len = got;
                    break;
                }
                Err(e) => {
                    last_err = e;
                    attempt += 1;
                    if attempt >= HW_RETRIES {
                        return Err(last_err);
                    }
                }
            }
        }
        // Hand the raw reply (status nibble in high half of byte 0,
        // then payload) to the dp_aux decoder. The decoder enforces
        // length + status invariants.
        decode_response(&reply_buf[..raw_len], expected_payload)
    }
}

// Tests live in `crate::tests` and follow the `kernel_test_in!`
// macro convention so they run on the actual kernel test harness
// rather than `cargo test`. Smokes for the AUX transport (wire
// packing + control-register composition with a mock MmioWindow)
// live there.
