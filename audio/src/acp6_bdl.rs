//! ACP6 Stage-2 — Buffer Descriptor List (BDL) ring, stream-control
//! bit-position constants, IRQ-status decode, FakeMmio test scaffold,
//! and codec-tree wiring for the I2S0 TX playback path.
//!
//! ## Why "BDL" here?
//!
//! AMD ACP does not use an Intel HDA-style linked list of buffer
//! descriptors stored in DRAM. Instead the ACP I2S TX engine is
//! programmed with a contiguous ring-buffer (base + size) and fires
//! an interrupt when it has consumed `INTR_WATERMARK_SIZE` bytes past
//! the last ack point. Linux calls the period boundary a "watermark"
//! rather than a "BDL entry"; we expose the same concept as a BDL
//! descriptor so the higher-level mixer/period logic can use the same
//! idiom it uses for Intel HDA and virtio-sound.
//!
//! A `BdlDescriptor` describes one period (sub-division of the ring).
//! For ACP the only fields that matter are `byte_offset` and
//! `byte_len` — there are no IOC bits because the watermark register
//! fires once per `byte_len` bytes unconditionally. The round-trip
//! encode/decode test verifies field packing.
//!
//! ## References (GPL-2.0-or-later; NARF is GPL-2.0-or-later since
//!  2026-05-20)
//!
//! - Linux `sound/soc/amd/raven/acp3x-pcm-dma.c`:
//!     * `acp3x_dma_hw_params()` — watermark = period_bytes / 2 of
//!       the ring; confirmed that INTR_WATERMARK_SIZE is the only
//!       per-period knob. Our `BdlDescriptor` directly encodes this.
//! - Linux `sound/soc/amd/acp/acp_pcm.c` (ACP6-specific):
//!     * `acp_pcm_hw_params()` programs `ACP_EXTERNAL_INTR_ENB` bit 17
//!       (= `ACP_I2S_TX_THRESHOLD`) then starts via `ACP_BTTDM_ITER`.
//! - AMD Renoir PPR §13.7 "I2S DMA" — register layout + interrupt
//!   routing.

extern crate alloc;

use core::cell::RefCell;
use core::sync::atomic::{compiler_fence, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::acp6::regs;
use crate::codec::CodecTree;
use crate::realtek_alc;

// ── BDL descriptor ────────────────────────────────────────────────────

/// One period entry in the ACP I2S TX ring.
///
/// The ACP's DMA model is a flat ring-buffer with one hardware
/// watermark interrupt per programmed `byte_len`. We represent it as a
/// list of `BdlDescriptor`s so the higher-level period-advance logic
/// has a uniform shape regardless of which DMA engine sits below.
///
/// Field packing (32-bit host word, not written to MMIO — the ACP
/// has no DMA descriptor list in memory):
///
/// ```text
///   bits 31:16  byte_offset within the ring (must be period-aligned)
///   bits 15:0   byte_len of this period
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct BdlDescriptor {
    /// Byte offset of this period from the start of the ring.
    pub byte_offset: u16,
    /// Length of this period in bytes.
    pub byte_len: u16,
}

impl BdlDescriptor {
    /// Encode into a 32-bit host word (not written to MMIO).
    ///
    /// Field layout:
    /// ```text
    ///   [31:16] = byte_offset
    ///   [15:0]  = byte_len
    /// ```
    pub const fn encode(self) -> u32 {
        ((self.byte_offset as u32) << 16) | (self.byte_len as u32)
    }

    /// Decode a 32-bit word back into a `BdlDescriptor`.
    pub const fn decode(word: u32) -> Self {
        Self {
            byte_offset: ((word >> 16) & 0xFFFF) as u16,
            byte_len: (word & 0xFFFF) as u16,
        }
    }
}

// ── BDL ring ─────────────────────────────────────────────────────────

/// Maximum number of periods in the ring. Two periods = double-buffer
/// (front + back); the higher-level mixer writes the back buffer while
/// the engine drains the front. Linux ACP defaults to 2–4 periods;
/// we use 2 as the minimum for a working double-buffer playback loop.
pub const MAX_PERIODS: usize = 8;

/// A BDL ring: up to `MAX_PERIODS` descriptors uniformly dividing
/// `ring_bytes`.
#[derive(Clone, Debug)]
pub struct BdlRing {
    descs: [BdlDescriptor; MAX_PERIODS],
    count: usize,
    /// Total ring size in bytes.
    pub ring_bytes: u32,
    /// Period size in bytes (= ring_bytes / count).
    pub period_bytes: u32,
    /// Descriptor the engine is currently consuming (0-indexed,
    /// wraps modulo `count`). Advances on each watermark IRQ.
    pub head: usize,
}

impl Default for BdlRing {
    fn default() -> Self {
        Self {
            descs: [BdlDescriptor::default(); MAX_PERIODS],
            count: 0,
            ring_bytes: 0,
            period_bytes: 0,
            head: 0,
        }
    }
}

impl BdlRing {
    /// Build a uniform ring with `n_periods` descriptors spanning
    /// `ring_bytes`. `ring_bytes` must be divisible by `n_periods`.
    /// Returns `None` if either constraint is violated or `n_periods`
    /// exceeds `MAX_PERIODS`.
    pub fn build(ring_bytes: u32, n_periods: usize) -> Option<Self> {
        if n_periods == 0 || n_periods > MAX_PERIODS {
            return None;
        }
        if ring_bytes % n_periods as u32 != 0 {
            return None;
        }
        let period_bytes = ring_bytes / n_periods as u32;
        if period_bytes > 0xFFFF {
            return None;
        }
        let mut descs = [BdlDescriptor::default(); MAX_PERIODS];
        for i in 0..n_periods {
            descs[i] = BdlDescriptor {
                byte_offset: (i as u32 * period_bytes) as u16,
                byte_len: period_bytes as u16,
            };
        }
        Some(Self {
            descs,
            count: n_periods,
            ring_bytes,
            period_bytes,
            head: 0,
        })
    }

    /// Number of valid descriptors.
    pub fn len(&self) -> usize {
        self.count
    }

    /// `true` iff `count == 0`.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The descriptor at absolute index `i` (panics if out-of-range).
    pub fn get(&self, i: usize) -> BdlDescriptor {
        assert!(i < self.count, "BdlRing::get out of range");
        self.descs[i]
    }

    /// Advance `head` to the next descriptor (wrapping).
    pub fn advance(&mut self) -> BdlDescriptor {
        self.head = (self.head + 1) % self.count;
        self.descs[self.head]
    }

    /// Current head descriptor.
    pub fn current(&self) -> BdlDescriptor {
        if self.count == 0 {
            return BdlDescriptor::default();
        }
        self.descs[self.head]
    }

    /// Watermark register value: half the ring for a 2-period ring,
    /// or exactly `period_bytes` for longer rings. Mirrors Linux
    /// `acp3x_dma_hw_params` convention.
    pub fn watermark_bytes(&self) -> u32 {
        if self.count <= 2 {
            self.ring_bytes / 2
        } else {
            self.period_bytes
        }
    }
}

// ── ACP stream-control bit-positions ──────────────────────────────────
//
// Named bit positions within the ACP6 MMIO registers relevant to the
// I2S TX playback path.

/// `ACP_EXTERNAL_INTR_STAT` bit 17: I2S TX DMA-complete. Read by the
/// IRQ dispatcher to detect a period-end interrupt on the I2S0 TX
/// engine.
///
/// References:
/// - Renoir PPR §13.7.5 "Interrupt Source Bits".
/// - Linux `sound/soc/amd/acp/acp_pcm.c::acp_pcm_irq_handler` confirms
///   the same bit for ACP6.
pub const IRQ_BIT_I2STX_DONE: u32 = 1 << 17;

/// `ACP_BTTDM_ITER` bit 0: I2S link enable.
pub const ITER_BIT_ENABLE: u32 = regs::TDM_ITER_ENABLE;

/// `ACP_BTTDM_IER` bit 0: TX interrupt enable.
pub const IER_BIT_TX_ENABLE: u32 = regs::TDM_TX_ENABLE;

/// `ACP_CONTROL` bit 0: clock enable.
pub const CTRL_BIT_CLKEN: u32 = regs::CONTROL_CLKEN;

/// `ACP_CONTROL` bit 1: run.
pub const CTRL_BIT_RUN: u32 = regs::CONTROL_RUN;

// ── IRQ-status decode ─────────────────────────────────────────────────

/// Decoded `ACP_EXTERNAL_INTR_STAT` register word.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IntrStatus(pub u32);

impl IntrStatus {
    /// Build from a raw MMIO read of `ACP_EXTERNAL_INTR_STAT`.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// `true` iff the I2S TX DMA-complete bit is set.
    pub const fn i2s_tx_done(self) -> bool {
        self.0 & IRQ_BIT_I2STX_DONE != 0
    }

    /// Raw interrupt-status word.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Return the mask of active bits to write back to clear the
    /// I2S TX done interrupt (write-1-to-clear style on ACP6).
    pub const fn ack_i2s_tx(self) -> u32 {
        self.0 & IRQ_BIT_I2STX_DONE
    }
}

// ── Per-period callback state ─────────────────────────────────────────

/// IRQ-driven period advance state. One instance lives in the global
/// `PERIOD_STATE`; the IRQ handler updates it and the playback pump
/// consults it.
#[derive(Debug, Default)]
pub struct PeriodState {
    /// Number of IRQs (period completions) received since the last
    /// `prepare`. Wraps on overflow.
    pub irq_count: u32,
    /// Index (0-indexed, wraps mod `n_periods`) of the period the
    /// software should fill next.
    pub sw_period: usize,
    /// Total period count the ring was built with.
    pub n_periods: usize,
    /// `true` once `advance_period` has been called at least once.
    pub started: bool,
}

impl PeriodState {
    /// Acknowledge one period-done IRQ.
    pub fn advance_period(&mut self) {
        self.irq_count = self.irq_count.wrapping_add(1);
        if self.n_periods > 0 {
            self.sw_period = (self.sw_period + 1) % self.n_periods;
        }
        self.started = true;
    }

    /// Reset — called from `prepare` when starting a new stream.
    pub fn reset(&mut self, n_periods: usize) {
        self.irq_count = 0;
        self.sw_period = 0;
        self.n_periods = n_periods;
        self.started = false;
    }
}

// ── Global period-state singleton ─────────────────────────────────────

static PERIOD_STATE: IrqSafeSpinLock<PeriodState> = IrqSafeSpinLock::new(PeriodState {
    irq_count: 0,
    sw_period: 0,
    n_periods: 0,
    started: false,
});

/// Called from the ACP IRQ dispatch path: acknowledge the I2S TX
/// DMA-done interrupt and advance the software period pointer.
///
/// Returns `true` iff the I2S TX done bit was set (i.e. this IRQ was
/// ours).
pub fn on_i2s_tx_irq(raw_intr_stat: u32) -> bool {
    let status = IntrStatus::from_raw(raw_intr_stat);
    if !status.i2s_tx_done() {
        return false;
    }
    PERIOD_STATE.lock().advance_period();
    true
}

/// Read the current software period index.
pub fn sw_period() -> usize {
    PERIOD_STATE.lock().sw_period
}

/// How many period-complete IRQs have fired since the last `prepare`.
pub fn irq_count() -> u32 {
    PERIOD_STATE.lock().irq_count
}

/// `true` iff at least one IRQ has fired.
pub fn is_running() -> bool {
    PERIOD_STATE.lock().started
}

/// Reset the period state. Called by `acp6_pcm::prepare_i2s0_tx`.
pub fn reset_period_state(n_periods: usize) {
    PERIOD_STATE.lock().reset(n_periods);
}

// ── Codec-tree wiring ─────────────────────────────────────────────────

/// Errors from wiring an ACP6 I2S stream to a codec tree.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CodecWireError {
    /// No Realtek codec found in the tree.
    NoRealtekCodec,
    /// Codec not supported by this bring-up path.
    UnsupportedCodec,
    /// HDA transport error during bring-up.
    BringUpFailed,
}

/// Wire an ACP I2S TX stream to the audio function group in `tree`.
///
/// Supports Realtek ALC-family codecs. Calls
/// `realtek_alc::bring_up_alc295_with` (the canonical Renoir/Phoenix
/// baseline) to set Pin Widget Control + Amp Gain/Mute + EAPD on the
/// speaker / headphone pins.
///
/// The `send` closure has the same `(cad, nid, verb_id, payload) ->
/// Result<u32, CodecError>` shape used by the rest of the codec module.
pub fn wire_i2s_to_codec_tree(
    tree: &CodecTree,
    send: realtek_alc::SendVerb<'_>,
) -> Result<(), CodecWireError> {
    let chip = match realtek_alc::detect_from_tree(tree) {
        Some(c) => c,
        None => return Err(CodecWireError::NoRealtekCodec),
    };
    if !realtek_alc::is_supported(chip) {
        return Err(CodecWireError::UnsupportedCodec);
    }
    realtek_alc::bring_up_alc295_with(tree.cad, send)
        .map_err(|_| CodecWireError::BringUpFailed)
}

// ── FakeMmio test scaffold ────────────────────────────────────────────
//
// Recording/replaying MMIO mock. Shape follows the backlight and
// intel_gpu_modeset FakeMmio precedent (drivers/gpu/src/backlight.rs).

/// Recording MMIO mock — serves canned reads, captures writes.
#[derive(Debug, Default)]
pub struct FakeMmio {
    pub reads: RefCell<alloc::collections::BTreeMap<u64, u32>>,
    pub writes: RefCell<alloc::vec::Vec<(u64, u32)>>,
}

impl FakeMmio {
    /// Create a new empty mock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-program a canned read response for `offset`.
    pub fn set_read(&self, offset: u64, value: u32) {
        self.reads.borrow_mut().insert(offset, value);
    }

    /// Return the most recent value written to `offset`.
    pub fn last_write(&self, offset: u64) -> Option<u32> {
        self.writes
            .borrow()
            .iter()
            .rev()
            .find_map(|(o, v)| if *o == offset { Some(*v) } else { None })
    }

    /// `true` if a write to `offset` with value `val` was recorded.
    pub fn saw_write(&self, offset: u64, val: u32) -> bool {
        self.writes
            .borrow()
            .iter()
            .any(|(o, v)| *o == offset && *v == val)
    }

    /// Number of writes to `offset`.
    pub fn write_count(&self, offset: u64) -> usize {
        self.writes.borrow().iter().filter(|(o, _)| *o == offset).count()
    }

    /// Read a 32-bit register at `offset`.
    ///
    /// # Safety
    /// Safe in tests (no real MMIO).
    pub unsafe fn read32(&self, offset: u64) -> u32 {
        *self.reads.borrow().get(&offset).unwrap_or(&0)
    }

    /// Write a 32-bit register at `offset`.
    ///
    /// # Safety
    /// Safe in tests (no real MMIO).
    pub unsafe fn write32(&self, offset: u64, value: u32) {
        self.writes.borrow_mut().push((offset, value));
    }
}

/// Program the I2S TX DMA registers into a `FakeMmio`. Used by round-
/// trip smokes to verify the register-programming sequence without a
/// real `AcpDevice`.
///
/// Mirrors the production sequence in `acp6_pcm::program_dma_registers`
/// but accepts a `&FakeMmio` instead of `&AcpDevice`.
pub fn fake_program_dma_registers(
    mmio: &FakeMmio,
    ring_phys: u64,
    ring_bytes: u32,
    bdl: &BdlRing,
) {
    // SAFETY: FakeMmio::write32 is no-op MMIO — safe in tests.
    unsafe {
        mmio.write32(regs::ACP_I2STX_RINGBUFADDR, ring_phys as u32);
        mmio.write32(regs::ACP_I2STX_RINGBUFSIZE, ring_bytes);
        mmio.write32(regs::ACP_I2STX_FIFOADDR, regs::I2STX_FIFO_SCRATCH_OFFSET);
        mmio.write32(regs::ACP_I2STX_FIFOSIZE, regs::I2STX_FIFO_BYTES);
        // BYTES_PER_FRAME for S16LE stereo = 4.
        mmio.write32(regs::ACP_I2STX_DMA_SIZE, 4);
        mmio.write32(regs::ACP_I2STX_INTR_WATERMARK_SIZE, bdl.watermark_bytes());
        mmio.write32(regs::ACP_I2STX_LINEARPOSITION_CNTR_LOW, 0);
        mmio.write32(regs::ACP_I2STX_LINEARPOSITION_CNTR_HIGH, 0);
    }
    compiler_fence(Ordering::SeqCst);
}

// ── Tests ─────────────────────────────────────────────────────────────
//
// All smokes use `kernel_test_in!` which embeds them in the `narf.tests`
// ELF section — the kernel-test runner finds them at boot. No
// `#[cfg(test)]` because the framework runs in the kernel binary, not
// in a host std environment.

mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// BdlDescriptor encode/decode round-trip: field packing is stable
    /// across the full 16-bit range for both fields.
    fn smoke_acp6_bdl_descriptor_encode_decode() -> TestResult {
        // Nominal descriptor: offset 4096, len 2048.
        let d = BdlDescriptor { byte_offset: 4096, byte_len: 2048 };
        if BdlDescriptor::decode(d.encode()) != d {
            return TestResult::Fail("nominal round-trip failed");
        }

        // Zero descriptor.
        let zero = BdlDescriptor { byte_offset: 0, byte_len: 0 };
        if BdlDescriptor::decode(zero.encode()) != zero {
            return TestResult::Fail("zero descriptor round-trip");
        }

        // Max-value descriptor (both fields at 0xFFFF).
        let max = BdlDescriptor { byte_offset: 0xFFFF, byte_len: 0xFFFF };
        if BdlDescriptor::decode(max.encode()) != max {
            return TestResult::Fail("max descriptor round-trip");
        }

        // Bit independence: offset 0, len 1.
        let one_len = BdlDescriptor { byte_offset: 0, byte_len: 1 };
        if BdlDescriptor::decode(one_len.encode()) != one_len {
            return TestResult::Fail("single-bit len round-trip");
        }

        // Bit independence: offset 1, len 0.
        let one_off = BdlDescriptor { byte_offset: 1, byte_len: 0 };
        if BdlDescriptor::decode(one_off.encode()) != one_off {
            return TestResult::Fail("single-bit offset round-trip");
        }

        TestResult::Pass
    }
    kernel_test_in!("audio/acp6", smoke_acp6_bdl_descriptor_encode_decode);

    /// BdlRing construction + descriptor layout: 2-period ring over a
    /// 4 KiB buffer, verifying period layout + watermark.
    fn smoke_acp6_bdl_ring_two_period_layout() -> TestResult {
        let ring = match BdlRing::build(4096, 2) {
            Some(r) => r,
            None => return TestResult::Fail("BdlRing::build returned None"),
        };

        if ring.len() != 2 {
            return TestResult::Fail("period count wrong");
        }
        if ring.period_bytes != 2048 {
            return TestResult::Fail("period_bytes wrong");
        }
        let d0 = ring.get(0);
        if d0.byte_offset != 0 || d0.byte_len != 2048 {
            return TestResult::Fail("descriptor 0 layout wrong");
        }
        let d1 = ring.get(1);
        if d1.byte_offset != 2048 || d1.byte_len != 2048 {
            return TestResult::Fail("descriptor 1 layout wrong");
        }
        // 2-period watermark = ring / 2 = 2048.
        if ring.watermark_bytes() != 2048 {
            return TestResult::Fail("watermark wrong for 2-period ring");
        }

        // Reject misaligned ring.
        if BdlRing::build(4097, 2).is_some() {
            return TestResult::Fail("misaligned ring should be rejected");
        }
        // Reject 0 periods.
        if BdlRing::build(4096, 0).is_some() {
            return TestResult::Fail("zero periods should be rejected");
        }
        // Reject > MAX_PERIODS.
        if BdlRing::build(4096, MAX_PERIODS + 1).is_some() {
            return TestResult::Fail("too many periods should be rejected");
        }

        TestResult::Pass
    }
    kernel_test_in!("audio/acp6", smoke_acp6_bdl_ring_two_period_layout);

    /// Stream-control bit-position constants match the register-level
    /// values documented in the Renoir PPR §13.7 and Linux ACP source.
    fn smoke_acp6_stream_ctrl_bit_positions() -> TestResult {
        // IRQ_BIT_I2STX_DONE = bit 17 of ACP_EXTERNAL_INTR_STAT.
        if IRQ_BIT_I2STX_DONE != (1 << 17) {
            return TestResult::Fail("IRQ_BIT_I2STX_DONE wrong");
        }
        // ITER_BIT_ENABLE = bit 0 of ACP_BTTDM_ITER.
        if ITER_BIT_ENABLE != (1 << 0) {
            return TestResult::Fail("ITER_BIT_ENABLE wrong");
        }
        // IER_BIT_TX_ENABLE = bit 0 of ACP_BTTDM_IER.
        if IER_BIT_TX_ENABLE != (1 << 0) {
            return TestResult::Fail("IER_BIT_TX_ENABLE wrong");
        }
        // CTRL_BIT_CLKEN = bit 0 of ACP_CONTROL.
        if CTRL_BIT_CLKEN != (1 << 0) {
            return TestResult::Fail("CTRL_BIT_CLKEN wrong");
        }
        // CTRL_BIT_RUN = bit 1 of ACP_CONTROL.
        if CTRL_BIT_RUN != (1 << 1) {
            return TestResult::Fail("CTRL_BIT_RUN wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("audio/acp6", smoke_acp6_stream_ctrl_bit_positions);

    /// IRQ-status decode: `IntrStatus` correctly identifies the I2S TX
    /// done bit, and `ack_i2s_tx` returns only that bit for write-back.
    fn smoke_acp6_irq_status_decode() -> TestResult {
        // Raw with only bit 17 set.
        let s = IntrStatus::from_raw(1 << 17);
        if !s.i2s_tx_done() {
            return TestResult::Fail("i2s_tx_done not detected");
        }
        if s.ack_i2s_tx() != (1 << 17) {
            return TestResult::Fail("ack_i2s_tx wrong value");
        }

        // Bits 0..16 set but not bit 17 — not a TX-done.
        let other = IntrStatus::from_raw(0x0001_FFFF);
        if other.i2s_tx_done() {
            return TestResult::Fail("spurious i2s_tx_done");
        }

        // Zero.
        let zero = IntrStatus::from_raw(0);
        if zero.i2s_tx_done() {
            return TestResult::Fail("zero status shows done");
        }
        if zero.ack_i2s_tx() != 0 {
            return TestResult::Fail("ack on zero nonzero");
        }

        // Multiple sources including bit 17.
        let multi = IntrStatus::from_raw((1 << 17) | (1 << 3) | (1 << 0));
        if !multi.i2s_tx_done() {
            return TestResult::Fail("multi-source: i2s_tx_done not detected");
        }
        // ack should only return bit 17.
        if multi.ack_i2s_tx() != (1 << 17) {
            return TestResult::Fail("multi-source ack wrong");
        }

        TestResult::Pass
    }
    kernel_test_in!("audio/acp6", smoke_acp6_irq_status_decode);

    /// Ring-pointer round-trip on FakeMmio: `fake_program_dma_registers`
    /// writes the expected register sequence to a `FakeMmio`, then we
    /// read the captured writes back to confirm correct values.
    fn smoke_acp6_ring_ptr_round_trip_fake_mmio() -> TestResult {
        let mmio = FakeMmio::new();
        let ring = match BdlRing::build(4096, 2) {
            Some(r) => r,
            None => return TestResult::Fail("BdlRing::build failed"),
        };

        let ring_phys: u64 = 0x0001_8000; // below 4 GiB as ACP expects
        fake_program_dma_registers(&mmio, ring_phys, 4096, &ring);

        match mmio.last_write(regs::ACP_I2STX_RINGBUFADDR) {
            Some(v) if v == ring_phys as u32 => {}
            _ => return TestResult::Fail("RINGBUFADDR wrong"),
        }
        match mmio.last_write(regs::ACP_I2STX_RINGBUFSIZE) {
            Some(4096) => {}
            _ => return TestResult::Fail("RINGBUFSIZE wrong"),
        }
        let want_wm = ring.watermark_bytes();
        match mmio.last_write(regs::ACP_I2STX_INTR_WATERMARK_SIZE) {
            Some(v) if v == want_wm => {}
            _ => return TestResult::Fail("INTR_WATERMARK_SIZE wrong"),
        }
        match mmio.last_write(regs::ACP_I2STX_LINEARPOSITION_CNTR_LOW) {
            Some(0) => {}
            _ => return TestResult::Fail("LINPOS_LO not zeroed"),
        }
        match mmio.last_write(regs::ACP_I2STX_LINEARPOSITION_CNTR_HIGH) {
            Some(0) => {}
            _ => return TestResult::Fail("LINPOS_HI not zeroed"),
        }

        TestResult::Pass
    }
    kernel_test_in!("audio/acp6", smoke_acp6_ring_ptr_round_trip_fake_mmio);

    /// End-to-end mock: speaker amp on + buffer queued + period-advance
    /// fires. Verifies the three-step playback sequence:
    ///   1. `wire_i2s_to_codec_tree` drives the speaker-amp on verbs.
    ///   2. `fake_program_dma_registers` queues the ring.
    ///   3. `on_i2s_tx_irq` advances the software period pointer.
    fn smoke_acp6_e2e_speaker_amp_buffer_advance() -> TestResult {
        use crate::codec::FakeCorb;
        use crate::realtek_alc::{arm_fake_alc295, SPEAKER_PIN_PAYLOAD};
        use crate::codec::VERB_SET_PIN_WIDGET_CONTROL;

        let cad: u8 = 0;

        // 1. Build a fake ALC295 codec tree.
        let mut enum_corb = FakeCorb::new();
        arm_fake_alc295(&mut enum_corb, cad);
        let tree = crate::codec::enumerate_with(cad, |c, n, v, p| {
            Ok(enum_corb.send(c, n, v, p))
        })
        .expect("enumerate_with");

        // Wire the I2S stream to the codec tree via a second FakeCorb.
        let mut wire_corb = FakeCorb::new();
        arm_fake_alc295(&mut wire_corb, cad);
        let result = wire_i2s_to_codec_tree(
            &tree,
            &mut |c, n, v, p| Ok(wire_corb.send(c, n, v, p)),
        );
        if result.is_err() {
            return TestResult::Fail("wire_i2s_to_codec_tree failed");
        }

        // Confirm speaker amp was enabled: speaker pin (NID 4) saw
        // Set Pin Widget Control with SPEAKER_PIN_PAYLOAD.
        if !wire_corb.saw(cad, 4, VERB_SET_PIN_WIDGET_CONTROL, SPEAKER_PIN_PAYLOAD) {
            return TestResult::Fail("speaker amp not enabled");
        }

        // 2. Queue the ring buffer via FakeMmio.
        let mmio = FakeMmio::new();
        let ring = BdlRing::build(4096, 2).expect("BdlRing::build");
        fake_program_dma_registers(&mmio, 0x0001_0000, 4096, &ring);
        if mmio.last_write(regs::ACP_I2STX_RINGBUFADDR).is_none() {
            return TestResult::Fail("ring not queued");
        }

        // 3. Simulate IRQs and verify period-pointer advance.
        reset_period_state(2);
        if is_running() {
            return TestResult::Fail("is_running should be false before first IRQ");
        }

        let acked = on_i2s_tx_irq(IRQ_BIT_I2STX_DONE);
        if !acked {
            return TestResult::Fail("first IRQ not acked");
        }
        if !is_running() {
            return TestResult::Fail("is_running false after first IRQ");
        }
        if sw_period() != 1 {
            return TestResult::Fail("sw_period wrong after first IRQ");
        }
        if irq_count() != 1 {
            return TestResult::Fail("irq_count wrong after first IRQ");
        }

        // Second IRQ wraps back to period 0.
        on_i2s_tx_irq(IRQ_BIT_I2STX_DONE);
        if sw_period() != 0 {
            return TestResult::Fail("sw_period wrong after second IRQ (expected wrap)");
        }
        if irq_count() != 2 {
            return TestResult::Fail("irq_count wrong after second IRQ");
        }

        // Non-I2S-TX interrupt must not advance.
        let prev_count = irq_count();
        let acked = on_i2s_tx_irq(0x0000_0001); // bit 0, not bit 17
        if acked {
            return TestResult::Fail("non-I2S-TX IRQ should not be acked");
        }
        if irq_count() != prev_count {
            return TestResult::Fail("irq_count changed on non-I2S-TX IRQ");
        }

        TestResult::Pass
    }
    kernel_test_in!("audio/acp6", smoke_acp6_e2e_speaker_amp_buffer_advance);
}
