//! APU SMU telemetry owner (Renoir/Phoenix, SMU 12/13) — #1698, the #1186
//! remainder.
//!
//! The discrete owners (`amdgpu_smu_navi22`, `amdgpu_smu_navi48`) refresh
//! PMFW metrics through a retained VRAM transfer buffer and publish the
//! last sample on a 1 s cadence. APU-only machines had no equivalent: the
//! v13.0.4 metrics decode existed (`amdgpu_smu::parse_metrics`) but the DMA
//! transfer handshake that would refresh it was unwired. This module is
//! that owner, for both APU generations:
//!
//!   - a DMA-coherent transfer buffer, owned by this owner and published
//!     to the SMU with `PPSMC_MSG_SetDriverDramAddrHigh`/`Low`
//!     (High then Low, as Linux `smu_v13_0_set_driver_table_location`
//!     and the discrete `upload` path do it);
//!   - a transfer + decode step (`PPSMC_MSG_TransferTableSmu2Dram` with
//!     `TABLE_SMU_METRICS`, then `parse_metrics` / `parse_metrics_v12`)
//!     on a 1 s cadence, publishing the last [`ApuMetrics`] the way the
//!     discrete owners publish their `Snapshot` — retained across a
//!     rejected refresh, never fabricated;
//!   - the last sample exposed through [`snapshot()`] for diagnostics and
//!     for the `gpu_temp_mc` provider.
//!
//! Grounded in the Linux amdgpu driver (yocto mirror of mainline, fetched
//! 2026-11-06; the NARF in-tree v13 decode was re-checked against the
//! fetched header and matches field for field):
//!
//!   - `smu_v13_0_4_ppt.c::smu_v13_0_4_get_smu_metrics_data` →
//!     `smu_cmn_get_metrics_table` → `smu_cmn_update_table`: the metrics
//!     table is transferred with `TransferTableSmu2Dram`, argument
//!     `((0 & 0xFFFF) << 16) | (table_id & 0xffff)`, where `table_id` is
//!     the ASIC-side id from the generation's table map. The v13.0.4
//!     table map (`TAB_MAP_VALID(SMU_METRICS)`) resolves to
//!     `TABLE_SMU_METRICS` in `smu13_driver_if_v13_0_4.h` ("Table
//!     types"); the Renoir map resolves to `TABLE_SMU_METRICS` in
//!     `smu12_driver_if.h`. Both are **7**. The v13.0.4 and Renoir
//!     `SmuMetrics_t` layouts in those same headers are the source of
//!     `parse_metrics` / `parse_metrics_v12`.
//!   - `smu_v13_0_4_init_smc_tables`: the metrics table is a
//!     `sizeof(SmuMetrics_t)`, `PAGE_SIZE` allocation. The buffer here
//!     is one page ([`APU_METRICS_BUFFER_BYTES`]); the struct occupies
//!     the first 160 (v13) / 148 (v12) bytes of it.
//!   - `smu_cmn_get_metrics_table` serves a 1 ms cache; the 1 s NARF
//!     cadence ([`POLL_MS`], as in `amdgpu_navi22_power`) is well
//!     inside Linux's own refresh behaviour.
//!
//! What this module deliberately does NOT do:
//!
//!   - It does not wire into `AmdGpu::initialize` or any APU platform
//!     task: no APU platform singleton exists on main to attach it to,
//!     and the mailbox adapter there borrows the register window. The
//!     attach site owns that step: allocate the owner (or
//!     [`ApuTelemetryOwner::with_coherent_buffer`]), call
//!     [`ApuTelemetryOwner::publish_dram_addr`] once, then
//!     `let epoch = begin_epoch(); narf_scheduler::spawn(monitor(owner,
//!     mmio, epoch))` once the owner and mailbox live somewhere
//!     `'static` (cf. `amdgpu_navi22_power::start`, which spawns
//!     against the discrete platform singleton).
//!   - It does not register the `gpu_temp_mc` provider. That half lives
//!     in `amdgpu_smu_temp` (PR #1697 wired the discrete arms; the APU
//!     arm in `gpu_temp_mc_from` reads `snapshot()`'s
//!     [`ApuSnapshot::edge_temperature_milli_c`], consulted after the
//!     discrete owners).
//!
//! # Lifetime
//!
//! The SMU retains `DriverDramAddr` after acknowledgement, so the
//! buffer must stay alive as long as the SMU is live: dropping the
//! owner frees its frames while the SMU may still DMA into them. Keep
//! the owner retained for the device lifetime (a `'static` slot at the
//! attach site); [`stop`] only stops the monitor, it does not
//! unpublish the address.

use core::sync::atomic::{AtomicU64, Ordering};

use narf_driver_runtime::{alloc_coherent, DmaBuffer, DomainId};
use narf_io::DmaDirection;
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_smu::{
    parse_metrics, parse_metrics_v12, send_msg, PpsmcMsg, SmuError, SmuMetrics, SmuMetricsV12,
    SmuMmio, SmuVersion, SMU_METRICS_V13_0_4_BYTES,
};

/// `TABLE_SMU_METRICS` — the `TransferTableSmu2Dram` argument for the
/// metrics table on both APU generations: 7 in `smu12_driver_if.h` and
/// 7 in `smu13_driver_if_v13_0_4.h` ("Table types", "Called by Driver").
/// (For comparison the discrete SMU11/SMU14 value is 5 — the table
/// numbering is per-generation firmware interface, not the driver's
/// generic `SMU_TABLE_*` enum; do not "unify" them.)
pub const APU_METRICS_TABLE: u32 = 7;

/// Transfer-buffer size in bytes: one page, as Linux allocates the SMU
/// tables (`SMU_TABLE_INIT(..., PAGE_SIZE, ...)`). The metrics struct
/// occupies the first 160 (v13) / 148 (v12) bytes.
pub const APU_METRICS_BUFFER_BYTES: usize = 4096;

/// Refresh period; also hwmon's natural update granularity. Same value
/// as the discrete owners (`amdgpu_navi22_power::POLL_MS`).
pub const POLL_MS: u64 = 1000; // linux: n/a (NARF refresh period)

/// The DMA transfer buffer the SMU writes the metrics table into.
///
/// Production buffers are [`DmaBuffer`]s (DMA-coherent system RAM whose
/// physical address the SMU's DMA engine dereferences — on APUs the
/// "VRAM" Linux allocates the table from is itself carved system RAM,
/// so the physical address is the address the SMU wants). Tests use a
/// plain-array fake behind the same trait, so the handshake + decode
/// are exercised end-to-end without real silicon.
pub trait MetricsBuffer {
    /// Device-side address to program with `SetDriverDramAddr{High,Low}`.
    fn dma_addr(&self) -> u64;
    /// CPU view of the staged table bytes.
    fn as_slice(&self) -> &[u8];
    /// Mutable CPU view, for zeroing the staging area before a transfer.
    fn as_mut_slice(&mut self) -> &mut [u8];
    /// Cache maintenance before the CPU reads what the device wrote
    /// (Linux `dma_sync_single_for_cpu`, `FROM_DEVICE`). Takes `&mut`
    /// so a test fake can land its staged DMA write at exactly this
    /// point in the sequence; the production implementation only
    /// performs cache maintenance.
    fn sync_after_transfer(&mut self);
    /// Buffer length in bytes.
    fn len(&self) -> usize;
    /// Whether the buffer holds no bytes.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl MetricsBuffer for DmaBuffer {
    fn dma_addr(&self) -> u64 {
        self.dma_addr().raw()
    }
    fn as_slice(&self) -> &[u8] {
        self.as_slice()
    }
    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
    fn sync_after_transfer(&mut self) {
        self.sync_for_cpu(0, self.len(), DmaDirection::FromDevice);
    }
    fn len(&self) -> usize {
        self.len()
    }
}

/// One decoded APU metrics sample. The two generations decode to
/// different structs (different layouts, and watts vs milliwatts on
/// the power fields), so the version travels with the sample.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ApuMetrics {
    /// Renoir (SMU 12.0), decoded by `parse_metrics_v12`.
    V12(SmuMetricsV12),
    /// Phoenix / HawkPoint1 (SMU 13.0.4), decoded by `parse_metrics`.
    V13(SmuMetrics),
}

impl ApuMetrics {
    /// Which SMU generation produced this sample.
    pub fn version(&self) -> SmuVersion {
        match self {
            ApuMetrics::V12(_) => SmuVersion::V12,
            ApuMetrics::V13(_) => SmuVersion::V13,
        }
    }

    /// Edge temperature in milli-Celsius, the unit the OS thermal
    /// surface wants. Both generations report `GfxTemperature` in
    /// centi-Celsius, so this is centi-Celsius times ten either way.
    pub fn edge_temperature_milli_c(&self) -> i32 {
        match self {
            ApuMetrics::V12(m) => m.edge_temperature_milli_c(),
            ApuMetrics::V13(m) => m.edge_temperature_milli_c(),
        }
    }

    /// Hotspot temperature in milli-Celsius (`SocTemperature`).
    pub fn hotspot_temperature_milli_c(&self) -> i32 {
        match self {
            ApuMetrics::V12(m) => m.hotspot_temperature_milli_c(),
            ApuMetrics::V13(m) => m.hotspot_temperature_milli_c(),
        }
    }
}

/// APU telemetry owner failures.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ApuError {
    /// Mailbox-level failure from the SMU.
    Smu(SmuError),
    /// `refresh` called before `publish_dram_addr`: the SMU has no
    /// address to DMA the table to.
    NotPublished,
    /// Transfer acknowledged but the staged table did not decode (the
    /// buffer is shorter than the generation's struct, or the SMU
    /// wrote a truncated table).
    DecodeFailed,
    /// The transfer buffer is smaller than the metrics struct.
    BufferTooSmall,
    /// DMA-coherent allocation failed.
    Allocation,
}

impl From<SmuError> for ApuError {
    fn from(e: SmuError) -> Self {
        ApuError::Smu(e)
    }
}

impl ApuError {
    /// Terminal for the cadence monitor: a clean rejection leaves the
    /// owner reusable and the last sample standing, exactly as the
    /// discrete monitor treats `smu::Error::Rejected`; timeout,
    /// revocation and device loss end the loop.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, ApuError::Smu(SmuError::Rejected(_)))
    }
}

/// The APU SMU telemetry owner: a retained DMA transfer buffer, the
/// mailbox it is published through, and the last decoded sample.
///
/// The mailbox (`M: SmuMmio`) is supplied per call — the same shape as
/// `amdgpu_smu::bring_up` / `send_msg` — because the register window
/// is borrowed by the APU bring-up path and has no `'static` handle
/// on main. The buffer (`B: MetricsBuffer`) is owned: the SMU retains
/// `DriverDramAddr` after acknowledgement, so the owner must be kept
/// alive for the device lifetime (see the module docs).
#[derive(Debug)]
pub struct ApuTelemetryOwner<B: MetricsBuffer> {
    version: SmuVersion,
    mp1_base: u32,
    buffer: B,
    published: bool,
    last: Option<ApuMetrics>,
    samples: u64,
    error: Option<ApuError>,
}

impl<B: MetricsBuffer> ApuTelemetryOwner<B> {
    /// Build an owner around a caller-supplied transfer buffer. The
    /// buffer must hold at least the larger metrics struct (160 bytes);
    /// production buffers are one page.
    pub fn new(version: SmuVersion, mp1_base: u32, buffer: B) -> Result<Self, ApuError> {
        if buffer.len() < SMU_METRICS_V13_0_4_BYTES {
            return Err(ApuError::BufferTooSmall);
        }
        Ok(Self {
            version,
            mp1_base,
            buffer,
            published: false,
            last: None,
            samples: 0,
            error: None,
        })
    }

    /// SMU generation this owner talks to.
    pub fn version(&self) -> SmuVersion {
        self.version
    }

    /// MP1 mailbox base the owner sends through.
    pub fn mp1_base(&self) -> u32 {
        self.mp1_base
    }

    /// Whether `publish_dram_addr` has succeeded (the SMU knows where
    /// to DMA the table).
    pub fn is_published(&self) -> bool {
        self.published
    }

    /// Device-side address programmed into the SMU.
    pub fn dma_addr(&self) -> u64 {
        self.buffer.dma_addr()
    }

    /// Last successfully decoded sample, retained across a rejected
    /// refresh; `None` before the first success.
    pub fn last(&self) -> Option<ApuMetrics> {
        self.last
    }

    /// Successful refreshes so far.
    pub fn samples(&self) -> u64 {
        self.samples
    }

    /// Error of the latest refresh, cleared by the next success.
    pub fn error(&self) -> Option<ApuError> {
        self.error
    }

    /// Publish the transfer buffer to the SMU: `SetDriverDramAddrHigh`
    /// then `SetDriverDramAddrLow` with the buffer's DMA address
    /// (Linux `smu_v13_0_set_driver_table_location`; same High-then-Low
    /// order as the discrete owner's `upload`). Must succeed before
    /// the first `refresh`; re-publishing after a device reset is the
    /// caller's job. A failure here leaves `published` false.
    pub fn publish_dram_addr<M: SmuMmio>(&mut self, mmio: &mut M) -> Result<(), ApuError> {
        let addr = self.buffer.dma_addr();
        send_msg(
            mmio,
            self.mp1_base,
            self.version,
            PpsmcMsg::SetDriverDramAddrHigh,
            (addr >> 32) as u32,
        )?;
        send_msg(
            mmio,
            self.mp1_base,
            self.version,
            PpsmcMsg::SetDriverDramAddrLow,
            addr as u32,
        )?;
        self.published = true;
        Ok(())
    }

    /// One metrics refresh: Linux `smu_cmn_get_metrics_table` for the
    /// APU generations. The staging area is zeroed first (an
    /// acknowledged but unwritten table reads as zeros, never as stale
    /// data — as in the discrete `read_telemetry`), then
    /// `TransferTableSmu2Dram` asks the SMU to DMA `TABLE_SMU_METRICS`
    /// into it, and the staged bytes are decoded for this generation.
    ///
    /// A clean rejection returns the error and leaves the last sample
    /// standing; any other failure is terminal for the monitor (see
    /// [`ApuError::is_terminal`]).
    pub fn refresh<M: SmuMmio>(&mut self, mmio: &mut M) -> Result<ApuMetrics, ApuError> {
        if !self.published {
            return Err(ApuError::NotPublished);
        }
        // Zeroed staging: an acknowledged but unwritten table reads as
        // zeros, never as the previous sample.
        self.buffer.as_mut_slice().fill(0);
        send_msg(
            mmio,
            self.mp1_base,
            self.version,
            PpsmcMsg::TransferTableSmu2Dram,
            APU_METRICS_TABLE,
        )
        .map_err(|e| self.record_err(e.into()))?;
        self.buffer.sync_after_transfer();
        let decoded = match self.version {
            SmuVersion::V12 => parse_metrics_v12(self.buffer.as_slice()).map(ApuMetrics::V12),
            SmuVersion::V13 => parse_metrics(self.buffer.as_slice()).map(ApuMetrics::V13),
        };
        match decoded {
            Some(metrics) => {
                self.last = Some(metrics);
                self.samples += 1;
                self.error = None;
                Ok(metrics)
            }
            None => Err(self.record_err(ApuError::DecodeFailed)),
        }
    }

    fn record_err(&mut self, e: ApuError) -> ApuError {
        self.error = Some(e);
        e
    }
}

impl ApuTelemetryOwner<DmaBuffer> {
    /// Build an owner with its own DMA-coherent transfer buffer
    /// (`alloc_coherent`, one page, `DomainId::DRIVER_0` — the same
    /// allocation the GFX rings use). This is the production
    /// constructor; tests use [`ApuTelemetryOwner::new`] with a fake
    /// buffer.
    pub fn with_coherent_buffer(version: SmuVersion, mp1_base: u32) -> Result<Self, ApuError> {
        let buffer = alloc_coherent(APU_METRICS_BUFFER_BYTES, DomainId::DRIVER_0)
            .map_err(|_| ApuError::Allocation)?;
        Self::new(version, mp1_base, buffer)
    }
}

/// Last telemetry state, published to diagnostics and to the power
/// service's `gpu_temp_mc` provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApuSnapshot {
    /// Most recent successful sample; retained across a rejected refresh.
    pub metrics: Option<ApuMetrics>,
    /// Error of the latest refresh, cleared by the next success.
    pub error: Option<ApuError>,
    /// Successful refreshes so far.
    pub samples: u64,
}

impl ApuSnapshot {
    /// Edge temperature in milli-degrees Celsius from the last
    /// published sample. `None` when the owner never published — the
    /// field stays unknown rather than reporting a fabricated zero
    /// (the hwmon class rule). This is the value the `gpu_temp_mc`
    /// arm reads (`amdgpu_smu_temp::gpu_temp_mc_from`, after the
    /// discrete owners).
    pub fn edge_temperature_milli_c(&self) -> Option<i32> {
        self.metrics.map(|m| m.edge_temperature_milli_c())
    }
}

static SNAPSHOT: IrqSafeSpinLock<Option<ApuSnapshot>> = IrqSafeSpinLock::new(None);
/// Bumped by `begin_epoch` / `stop`, so a monitor of a replaced owner exits.
static EPOCH: AtomicU64 = AtomicU64::new(0);

/// Last published APU telemetry state. `None` before the first
/// `publish_sample` (the monitor seeds it via `begin_epoch` + refresh,
/// as the discrete `start` does).
pub fn snapshot() -> Option<ApuSnapshot> {
    *SNAPSHOT.lock()
}

/// Fold one refresh into the published state: a success replaces the
/// sample and clears the error; a failure keeps the last sample and
/// records the error. A failed refresh proves nothing new about the
/// last good reading.
fn update(previous: Option<ApuSnapshot>, sample: Result<ApuMetrics, ApuError>) -> ApuSnapshot {
    let (metrics, error) = match sample {
        Ok(m) => (Some(m), None),
        Err(e) => (previous.and_then(|p| p.metrics), Some(e)),
    };
    ApuSnapshot {
        metrics,
        error,
        samples: previous.map_or(0, |p| p.samples) + u64::from(error.is_none()),
    }
}

/// Fold one sample into the published snapshot. The monitor calls
/// this after every refresh, success or failure.
fn publish_sample(sample: Result<ApuMetrics, ApuError>) -> ApuSnapshot {
    let snapshot = {
        let mut published = SNAPSHOT.lock();
        let snapshot = update(*published, sample);
        *published = Some(snapshot);
        snapshot
    };
    snapshot
}

/// Start a monitor epoch: bumps the epoch counter and returns the new
/// value. The attach site spawns `monitor(owner, mmio, epoch)` with
/// it; a later `begin_epoch` / `stop` makes that monitor exit.
pub fn begin_epoch() -> u64 {
    EPOCH.fetch_add(1, Ordering::AcqRel) + 1
}

/// Stop the current monitor (recovery quiesce or device loss). The
/// published snapshot keeps whatever it last held. Does not unpublish
/// the DMA address — the SMU retains it (see the module docs).
pub fn stop() {
    EPOCH.fetch_add(1, Ordering::AcqRel);
}

/// Poll until a terminal SMU failure or a restart. Each refresh holds
/// the mailbox only for its own messages; a clean rejection is
/// published and retried after [`POLL_MS`], a terminal failure ends
/// the loop. Mirrors `amdgpu_navi22_power::monitor`, minus the
/// platform-owner lookup (the APU attach site owns the owner and the
/// mailbox and passes both in).
pub async fn monitor<M: SmuMmio, B: MetricsBuffer>(
    owner: &mut ApuTelemetryOwner<B>,
    mmio: &mut M,
    epoch: u64,
) {
    loop {
        if EPOCH.load(Ordering::Acquire) != epoch {
            return;
        }
        let sample = owner.refresh(mmio);
        if EPOCH.load(Ordering::Acquire) != epoch {
            return;
        }
        let terminal = sample.as_ref().err().is_some_and(ApuError::is_terminal);
        publish_sample(sample);
        if terminal {
            return;
        }
        narf_time::SleepUntil::new(narf_time::Deadline::after_ms(POLL_MS).as_instant()).await;
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_smu_apu_telemetry_tests.rs"]
mod tests;
