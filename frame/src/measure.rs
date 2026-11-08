//! Measured Boot Support — hardware-anchored TCB integrity.
//!
//! Spec: `security-model/specification/spec.md` §9. Anchors the NARF security
//! model by measuring the boot chain into the TPM's PCRs (Platform
//! Configuration Registers).
//!
//! ## PCR usage
//!
//! Follows the TCG PC Client Platform Firmware Profile Specification
//! (rev 1.05 r23):
//!
//! | PCR | Use                                                             |
//! |-----|-----------------------------------------------------------------|
//! |  0  | SRTM, BIOS, Host Platform Extensions, Embedded Option ROMs       |
//! |  1  | Host Platform Configuration                                      |
//! |  2  | UEFI driver and application code                                 |
//! |  3  | UEFI driver and application configuration and data               |
//! |  4  | UEFI Boot Manager Code (and Boot Attempts)                       |
//! |  5  | Boot Manager Code Configuration and Data + boot cmdline (NARF)   |
//! |  6  | Initramfs / Host Platform Manufacturer Specific (NARF: initrd)   |
//! |  7  | Secure Boot Policy (PK / KEK / db / dbx)                          |
//! |  8  | (reserved)                                                       |
//! |  9  | Kernel module / driver-firmware blobs (NARF: per-blob log entry) |
//! | 10  | IMA (userspace binary measurement, NARF: /sbin/init etc.)        |
//! | 11+ | (reserved / application)                                         |
//!
//! ## PCR-extend formula
//!
//! Per TCG TPM 2.0 Library Spec Part 1 §17.10, a PCR-extend with
//! digest D over bank H is:
//!
//! ```text
//!     PCR_new := H(PCR_old || D)
//! ```
//!
//! The NARF software shadow log mirrors the same operation on the
//! local replay state so it can be cross-checked against the hardware
//! PCR after the TPM responds. SHA-256 is used both for the digest
//! and the extend bank — this matches PC Client 1.5 mandatory minimum
//! (PC Client 1.0 was SHA-1 only; we don't support that).
//!
//! Adapted from Linux `security/integrity/ima/ima_crypto.c` (PCR-extend
//! semantics) and `drivers/char/tpm/tpm-chip.c` (extend dispatch).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use narf_crypto::sha256::Sha256;
use narf_lib::sync::IrqSafeSpinLock;
use narf_tpm::TpmError;

// ── TCG event types ────────────────────────────────────────────────
//
// From the TCG PC Client Platform Firmware Profile Spec §10.4.1
// (table 9: "Events"). Only the ones we actually emit are listed —
// the spec defines ~30 of these, but firmware-measurement consumers
// only care about a small set.

/// `EV_NO_ACTION` — informational; ignored by PCR computation but
/// recorded in the event log. The PC Client Spec uses this for the
/// "spec ID" event that anchors the log header.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
pub const EV_NO_ACTION: u32 = 0x0000_0003;
/// `EV_SEPARATOR` — written by firmware at the end of pre-OS to
/// terminate a PCR's measurement sequence.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
pub const EV_SEPARATOR: u32 = 0x0000_0004;
/// `EV_S_CRTM_VERSION` — Static Root of Trust for Measurement version.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
pub const EV_S_CRTM_VERSION: u32 = 0x0000_0008;
/// `EV_PLATFORM_CONFIG_FLAGS` — generic platform config event.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
pub const EV_PLATFORM_CONFIG_FLAGS: u32 = 0x0000_000A;
/// `EV_EFI_VARIABLE_BOOT` — measurement of `BootXXXX`/`BootOrder` for
/// the bootloader-config PCR.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
pub const EV_EFI_VARIABLE_BOOT: u32 = 0x8000_000C;
/// `EV_EFI_BOOT_SERVICES_APPLICATION` — measurement of a PE/COFF
/// image the firmware launched.
pub const EV_EFI_BOOT_SERVICES_APPLICATION: u32 = 0x8000_0003;
/// `EV_IPL` — Initial Program Loader. Used for bootloader payloads.
pub const EV_IPL: u32 = 0x0000_000D;
/// `EV_IPL_PARTITION_DATA` — bootloader config; we use this for the
/// kernel command line (PC Client Spec §10.4.4 explicitly allows IPL
/// events for boot config strings).
pub const EV_IPL_PARTITION_DATA: u32 = 0x0000_000E;

// ── TPM_ALG identifiers (TCG Algorithm Registry) ──────────────────

/// `TPM_ALG_SHA256` — the digest algorithm used in the SHA-256 bank.
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// `TPM_ALG_SHA384` — alternative bank required by PC Client 1.5.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
pub const TPM_ALG_SHA384: u16 = 0x000C;

/// Digest size in bytes for `TPM_ALG_SHA256`.
pub const SHA256_DIGEST_SIZE: usize = 32;

// ── Measurement log ───────────────────────────────────────────────

/// One entry in the software shadow of the TCG Event Log.
///
/// On the wire (TCG PC Client Spec §10.4.2, `TCG_PCR_EVENT2`):
///
/// ```text
///     UINT32      pcrIndex
///     UINT32      eventType
///     TPML_DIGEST_VALUES digests       // count + per-bank (algId, digest)
///     UINT32      eventSize
///     BYTE        event[eventSize]
/// ```
///
/// We keep the on-wire layout decoupled from the in-memory `Measurement`
/// — the encoder in `tcg_event_log_encode` produces the wire bytes.
#[derive(Debug, Clone)]
pub struct Measurement {
    /// PCR this measurement was extended into.
    pub pcr: u32,
    /// TCG event-type tag (see `EV_*` constants).
    pub event_type: u32,
    /// SHA-256 of the measured data (the value that was extended).
    pub digest: [u8; SHA256_DIGEST_SIZE],
    /// Length of the measured data in bytes (zero for synthetic events).
    pub data_len: u64,
    /// Human-readable label (kept owned so the log can carry per-path
    /// strings from firmware-measurement events).
    pub label: String,
    /// The raw event bytes as logged by firmware, when this entry
    /// came from a firmware event log (#1071). `None` for NARF's own
    /// measurements, whose event bytes are the `label` (the encoder's
    /// historical layout). `Some` — even when empty — for replayed
    /// firmware events, whose event bytes are arbitrary binary and
    /// must round-trip byte-for-byte so a verifier replaying the
    /// published log reproduces the firmware prefix.
    pub event_data: Option<Vec<u8>>,
}

/// Software shadow of the hardware event log. Each successful
/// `measure()` call appends here.
///
/// `IrqSafeSpinLock` so a measurement triggered from an IRQ context
/// (TPM interrupts, ACPI events) can safely append without racing the
/// boot-path appender.
static LOG: IrqSafeSpinLock<Vec<Measurement>> = IrqSafeSpinLock::new(Vec::new());

/// Software replay of the hardware PCRs. Indexed by PCR number.
/// Boot starts with all zeros, matching the TPM's reset state.
const PCR_COUNT: usize = 24;
static PCR_SHADOW: IrqSafeSpinLock<[[u8; SHA256_DIGEST_SIZE]; PCR_COUNT]> =
    IrqSafeSpinLock::new([[0u8; SHA256_DIGEST_SIZE]; PCR_COUNT]);

/// Set true once at least one extend has been issued — used by the
/// remote-attestation surface to refuse to produce a quote against an
/// untouched PCR set (which would otherwise look "clean" by accident).
static EXTEND_OBSERVED: AtomicBool = AtomicBool::new(false);

// ── Public API ─────────────────────────────────────────────────────

/// SHA-256 of `data`. Equivalent to one-shot `Sha256::new().update().finalize()`.
pub fn sha256(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// Apply the PCR-extend formula in software:
///
/// ```text
///     PCR_new := SHA-256(PCR_old || digest)
/// ```
///
/// Returns the post-extend value without touching the shadow — callers
/// who want to mutate the shadow should go through `extend_shadow`.
pub fn pcr_extend_value(
    pcr_old: &[u8; SHA256_DIGEST_SIZE],
    digest: &[u8; SHA256_DIGEST_SIZE],
) -> [u8; SHA256_DIGEST_SIZE] {
    let mut h = Sha256::new();
    h.update(pcr_old);
    h.update(digest);
    h.finalize()
}

/// Apply `pcr_extend_value` to the software-shadow PCR and return the
/// resulting value. Returns `None` if `pcr` is out of range.
pub fn extend_shadow(
    pcr: u32,
    digest: &[u8; SHA256_DIGEST_SIZE],
) -> Option<[u8; SHA256_DIGEST_SIZE]> {
    if pcr as usize >= PCR_COUNT {
        return None;
    }
    let mut g = PCR_SHADOW.lock();
    let pcr_old = g[pcr as usize];
    let pcr_new = pcr_extend_value(&pcr_old, digest);
    g[pcr as usize] = pcr_new;
    EXTEND_OBSERVED.store(true, Ordering::Release);
    Some(pcr_new)
}

/// Read a software-shadow PCR. Used by the attestation path when the
/// hardware TPM is absent (or for cross-checking the hardware reading
/// against the replay).
pub fn pcr_shadow(pcr: u32) -> Option<[u8; SHA256_DIGEST_SIZE]> {
    if pcr as usize >= PCR_COUNT {
        return None;
    }
    Some(PCR_SHADOW.lock()[pcr as usize])
}

/// `true` once at least one extend has been recorded.
pub fn any_extend_observed() -> bool {
    EXTEND_OBSERVED.load(Ordering::Acquire)
}

/// Install the measurement hooks the TPM attestation surface
/// (`narf_tpm::attest`) consults: this module's TCG event-log
/// encoder (served to userspace as the sysfs
/// `binary_bios_measurements` node), [`any_extend_observed`]
/// (the flag the quote composition refuses on when no extend has
/// been recorded this boot), and [`firmware_replay_mismatch`]
/// (the flag the quote composition refuses on when the firmware
/// replay disagrees with the hardware PCRs 0–7).
///
/// Called once from the measured-boot initcall in `bare_main`,
/// after the firmware event-log ingest and before that pass's own
/// extends run, so the first published log already carries the
/// firmware prefix. The hooks are plain function pointers to the
/// pure readers above — installing them changes no measurement
/// semantics; it only publishes, to the crates that cannot name
/// `frame` (the dependency runs the other way), state this module
/// already maintains.
pub fn install_attestation_hooks() {
    narf_tpm::attest::install_measurement_hooks(narf_tpm::attest::MeasurementHooks {
        event_log: tcg_event_log_encode,
        extends_observed: any_extend_observed,
        firmware_replay_mismatch,
    });
}

/// Whether measured-boot extends dispatch to a hardware TPM.
///
/// `true` when at least one device is registered in
/// `narf_tpm::registry` — the platform probe registers the device it
/// probed at Stage::Subsys, before the Stage::Late measured-boot
/// pass runs. When `false`, the `measure*` functions still record
/// into the software log and shadow, but nothing reaches silicon;
/// reporting surfaces (the boot console summary in `bare_main`) use
/// this predicate so they never claim hardware anchoring that did
/// not happen.
pub fn hardware_dispatch_active() -> bool {
    !narf_tpm::registry::list().is_empty()
}

// ── Firmware TCG event-log ingest (#1071) ──────────────────────────
//
// The firmware's own measurements (SRTM, UEFI drivers, boot
// attempts, Secure Boot policy — PCRs 0–7) happened before NARF
// ran, so the shadow starts at zero while the hardware PCRs do
// not. Ingesting the firmware TCG2 event log replays those events
// into the shadow with the same extend formula, and records them
// at the head of the published log, so the full chain — firmware
// prefix + NARF events — is what a verifier replays. Without this,
// quotes over the boot PCRs attest NARF's extends only.
//
// The handoff is the EFI configuration table
// (`narf_boot::firmware::tcg2_log_tables`, multiboot2 tag 12's
// system-table pointer); the wire decoding is pure
// (`narf_efi::tcg2`), so both are tested against synthetic,
// spec-built bytes. Ingest runs once, first, in the measured-boot
// initcall — before `install_attestation_hooks` publishes the log
// and before any NARF extend. The read-back cross-check
// (`cross_check_pcrs_0_7`) arbitrates afterwards: it compares the
// replayed shadow against the hardware PCRs 0–7 and refuses quotes
// over them on a proven mismatch.
//
// Design invariants (security-model §4, §9 — the TCB is
// `frame/`; this module is inside it):
// - Ingest is two-phase: parse everything first, then apply. A
//   malformed tail leaves no half-replayed shadow or log.
// - `EV_NO_ACTION` records are recorded, never extended
//   (PC Client Table 13: "MUST NOT extend any PCR").
// - The replay never touches the hardware TPM: firmware already
//   extended those digests; re-extending would double-extend.
// - A mismatch is sticky and surfaces (quote refusal), never
//   papered over by re-seeding the shadow from hardware.

/// Whether the firmware event log has been ingested this boot.
/// Exactly-once: a second ingest is refused, and ingest after any
/// NARF extend is refused (the firmware prefix must be the head
/// of the log, and the shadow must start from it).
static FIRMWARE_INGESTED: AtomicBool = AtomicBool::new(false);

/// The outcome of the firmware ingest, once it has run.
static FIRMWARE_INGEST: IrqSafeSpinLock<Option<FirmwareIngest>> = IrqSafeSpinLock::new(None);

/// Sticky: the last PCR 0–7 read-back cross-check proved the
/// replayed shadow disagrees with hardware. Set only by
/// [`cross_check_pcrs_0_7`] on a proven mismatch; never cleared
/// except by [`__reset_for_test`]. The quote composition consults
/// this through the attestation hooks and refuses quotes over
/// PCRs 0–7 while it is set.
static FIRMWARE_REPLAY_MISMATCH: AtomicBool = AtomicBool::new(false);

/// The outcome of a firmware event-log ingest.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FirmwareIngest {
    /// Records replayed from the main log (Spec ID event included).
    pub main_events: usize,
    /// Records replayed from the final-events table (after the
    /// preboot dedup skip — records already in the main log are
    /// not counted twice).
    pub final_events: usize,
    /// True when a main log was present and parsed cleanly end to
    /// end. The final-events table's absence does not clear this:
    /// the read-back cross-check arbitrates whether the chain is
    /// actually complete.
    pub full_chain: bool,
}

/// Why a firmware event-log ingest failed. Every variant fails
/// closed: a failed ingest replays nothing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FirmwareIngestError {
    /// Ingest already ran this boot.
    AlreadyIngested,
    /// The log already holds NARF events, or an extend was already
    /// recorded — the firmware prefix can no longer be its head.
    TooLate,
    /// No EFI system table, or neither TCG2 log table published.
    NoFirmwareLog,
    /// A firmware table's bytes could not be read (out of range,
    /// above the identity-map limit, or aarch64 where no identity
    /// map read exists yet).
    UnreadableFirmwareMemory,
    /// The main log's declared size exceeds
    /// [`narf_efi::tcg2::MAX_TCG2_LOG_BYTES`].
    MainLogTooLarge,
    /// The final-events table declares more than
    /// [`narf_efi::tcg2::MAX_TCG2_LOG_EVENTS`] events.
    FinalTableTooLarge,
    /// The main log failed to parse.
    BadMainLog(narf_efi::tcg2::Tcg2LogError),
    /// The final-events table failed to parse.
    BadFinalTable(narf_efi::tcg2::Tcg2LogError),
}

/// The outcome of one PCR 0–7 read-back cross-check.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PcrCrossCheck {
    /// True when every PCR 0–7 was read back and compared. False
    /// when no registry TPM exists (nothing to compare against)
    /// or a read failed (inconclusive, not a mismatch).
    pub checked: bool,
    /// Per-PCR (index = PCR number) mismatch against the replayed
    /// shadow. Meaningful only when `checked` is true.
    pub mismatched: [bool; 8],
    /// True when at least one `read_pcr` failed. A transport
    /// failure proves nothing about the replay, so it neither
    /// sets the sticky mismatch nor counts as a check.
    pub read_failed: bool,
}

/// The firmware ingest outcome, once ingest has run.
pub fn firmware_ingest() -> Option<FirmwareIngest> {
    *FIRMWARE_INGEST.lock()
}

/// Whether the firmware replay has been proven to disagree with
/// the hardware PCRs 0–7. Consulted by the quote composition
/// through the attestation hooks.
pub fn firmware_replay_mismatch() -> bool {
    FIRMWARE_REPLAY_MISMATCH.load(Ordering::Acquire)
}

/// Read firmware-table bytes out of physical memory through the
/// boot identity map. Mirrors the guards in
/// `firmware/smbios`'s `KernelPhys`: the address must be non-zero
/// and the range must end at or below the direct map's first slot
/// (`LOW_IDENTITY_LIMIT`, 512 GiB); on aarch64 there is no such
/// read yet and every read fails closed.
fn read_firmware_phys(phys: u64, out: &mut [u8]) -> bool {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (phys, out);
        false
    }
    #[cfg(target_arch = "x86_64")]
    {
        let Some(end) = phys.checked_add(out.len() as u64) else {
            return false;
        };
        if phys == 0 || end > narf_memory::addr::LOW_IDENTITY_LIMIT {
            return false;
        }
        let src = narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>();
        // SAFETY: same argument as `KernelPhys` in
        // `firmware/smbios`'s discover.rs: `[phys, end)` is below
        // 512 GiB, all of which the direct map's first slot maps;
        // before the map is live `kernel_ptr` is the boot identity
        // map. Firmware tables are plain RAM / ROM.
        unsafe {
            core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), out.len());
        }
        true
    }
}

/// One firmware event, parsed and ready to apply to the shadow and
/// the log. The digest is the SHA-256 bank's (the parser
/// guarantees it for every non-`EV_NO_ACTION` record); `extend`
/// is false exactly for `EV_NO_ACTION` records.
struct ParsedFirmwareEvent {
    pcr: u32,
    event_type: u32,
    digest: [u8; SHA256_DIGEST_SIZE],
    event: Vec<u8>,
    extend: bool,
}

impl ParsedFirmwareEvent {
    fn from_tcg2(ev: narf_efi::tcg2::Tcg2Event<'_>) -> Self {
        ParsedFirmwareEvent {
            pcr: ev.pcr,
            event_type: ev.event_type,
            digest: ev.sha256_digest.unwrap_or([0u8; SHA256_DIGEST_SIZE]),
            event: ev.event.to_vec(),
            extend: ev.event_type != EV_NO_ACTION,
        }
    }
}

/// Ingest the firmware TCG2 event log: locate it through the EFI
/// configuration table, parse it, and replay it into the shadow
/// and the head of the log. Runs once, first, in the measured-boot
/// initcall; a retry after a failure is allowed (the
/// exactly-once flag is set only on success), but a retry after
/// success — or after any NARF extend — is refused.
pub fn ingest_firmware_event_log() -> Result<FirmwareIngest, FirmwareIngestError> {
    if FIRMWARE_INGESTED.load(Ordering::Acquire) {
        return Err(FirmwareIngestError::AlreadyIngested);
    }
    if !LOG.lock().is_empty() || EXTEND_OBSERVED.load(Ordering::Acquire) {
        return Err(FirmwareIngestError::TooLate);
    }
    let outcome = ingest_firmware_event_log_inner()?;
    FIRMWARE_INGESTED.store(true, Ordering::Release);
    *FIRMWARE_INGEST.lock() = Some(outcome);
    Ok(outcome)
}

fn ingest_firmware_event_log_inner() -> Result<FirmwareIngest, FirmwareIngestError> {
    use narf_efi::tcg2;
    let handoff = narf_boot::firmware::firmware_handoff();
    let systab = handoff
        .efi_system_table
        .ok_or(FirmwareIngestError::NoFirmwareLog)?;
    let tables = narf_boot::firmware::tcg2_log_tables(systab, &read_firmware_phys);
    if tables.main_log.is_none() && tables.final_events.is_none() {
        return Err(FirmwareIngestError::NoFirmwareLog);
    }

    // Phase 1 — parse everything before touching the shadow or the
    // log, so a malformed tail cannot leave a half-replayed prefix.
    let mut events: Vec<ParsedFirmwareEvent> = Vec::new();
    let mut main_events = 0usize;
    let mut final_events = 0usize;
    let mut full_chain = false;
    let mut expected_digest_count: Option<u32> = None;
    let mut preboot_size = 0usize;
    if let Some(addr) = tables.main_log {
        let mut header = [0u8; 9];
        if !read_firmware_phys(addr, &mut header) {
            return Err(FirmwareIngestError::UnreadableFirmwareMemory);
        }
        let log_header = tcg2::decode_linux_tpm_event_log_header(&header).ok_or(
            FirmwareIngestError::BadMainLog(tcg2::Tcg2LogError::UnsupportedLogVersion),
        )?;
        if log_header.size as usize > tcg2::MAX_TCG2_LOG_BYTES {
            return Err(FirmwareIngestError::MainLogTooLarge);
        }
        let size = log_header.size as usize;
        let mut log_bytes = alloc::vec![0u8; size];
        if size > 0 {
            let Some(log_addr) = addr.checked_add(9) else {
                return Err(FirmwareIngestError::UnreadableFirmwareMemory);
            };
            if !read_firmware_phys(log_addr, &mut log_bytes) {
                return Err(FirmwareIngestError::UnreadableFirmwareMemory);
            }
        }
        let (spec, parsed) =
            tcg2::parse_tcg2_log(&log_bytes).map_err(FirmwareIngestError::BadMainLog)?;
        expected_digest_count = Some(spec.number_of_algorithms);
        preboot_size = log_header.final_events_preboot_size as usize;
        main_events = parsed.len();
        full_chain = true;
        events.extend(parsed.into_iter().map(ParsedFirmwareEvent::from_tcg2));
    }
    if let Some(addr) = tables.final_events {
        let mut header = [0u8; 16];
        if !read_firmware_phys(addr, &mut header) {
            return Err(FirmwareIngestError::UnreadableFirmwareMemory);
        }
        let table_header = tcg2::decode_final_events_table_header(&header).ok_or(
            FirmwareIngestError::BadFinalTable(tcg2::Tcg2LogError::UnsupportedLogVersion),
        )?;
        if table_header.number_of_events > tcg2::MAX_TCG2_LOG_EVENTS as u64 {
            return Err(FirmwareIngestError::FinalTableTooLarge);
        }
        // The table has no total length: copy a bounded window
        // sized by the event count (4 KiB per event is far above
        // any real firmware record) and walk exactly
        // `number_of_events` records out of it.
        let window_len =
            ((table_header.number_of_events as usize) * 4096).min(tcg2::MAX_TCG2_LOG_BYTES);
        let mut window = alloc::vec![0u8; window_len];
        if window_len > 0 {
            let Some(events_addr) = addr.checked_add(16) else {
                return Err(FirmwareIngestError::UnreadableFirmwareMemory);
            };
            if !read_firmware_phys(events_addr, &mut window) {
                return Err(FirmwareIngestError::UnreadableFirmwareMemory);
            }
        }
        let parsed = tcg2::parse_final_events(
            &window,
            table_header.number_of_events,
            expected_digest_count,
            preboot_size,
        )
        .map_err(FirmwareIngestError::BadFinalTable)?;
        final_events = parsed.len();
        events.extend(parsed.into_iter().map(ParsedFirmwareEvent::from_tcg2));
    }

    // Phase 2 — apply in stream order. The guards in
    // `ingest_firmware_event_log` guarantee the log is empty and
    // nothing was extended yet, so these land at the head of the
    // log and the shadow starts from them.
    apply_firmware_replay(&events, main_events, final_events, full_chain)
}

/// Apply already-parsed firmware events to the shadow and the head
/// of the log, in stream order. The caller guarantees the guards
/// (`ingest_firmware_event_log` checks them); the smokes call this
/// directly with spec-built logs, since the full ingest path reads
/// physical firmware memory.
fn apply_firmware_replay(
    events: &[ParsedFirmwareEvent],
    main_events: usize,
    final_events: usize,
    full_chain: bool,
) -> Result<FirmwareIngest, FirmwareIngestError> {
    if FIRMWARE_INGESTED.load(Ordering::Acquire) {
        return Err(FirmwareIngestError::AlreadyIngested);
    }
    if !LOG.lock().is_empty() || EXTEND_OBSERVED.load(Ordering::Acquire) {
        return Err(FirmwareIngestError::TooLate);
    }
    for ev in events {
        if ev.extend {
            // The parser guarantees `ev.pcr < 24`; the shadow
            // extend cannot fail here. The hardware TPM is never
            // touched: firmware already extended these digests.
            let _ = extend_shadow(ev.pcr, &ev.digest);
        }
        record_firmware(
            ev.pcr,
            ev.event_type,
            alloc::format!("firmware:{:#010x}", ev.event_type),
            &ev.digest,
            ev.event.clone(),
        );
    }
    let outcome = FirmwareIngest {
        main_events,
        final_events,
        full_chain,
    };
    FIRMWARE_INGESTED.store(true, Ordering::Release);
    *FIRMWARE_INGEST.lock() = Some(outcome);
    Ok(outcome)
}

/// Read hardware PCRs 0–7 back and compare them against the
/// replayed shadow (#1071 cross-check).
///
/// Runs whenever a registry TPM exists, regardless of whether a
/// firmware log was ingested: the comparison is meaningful either
/// way (on QEMU/swtpm with no firmware extends, both sides are
/// zero plus NARF's extends; on real UEFI without a published log
/// it correctly reports mismatch). Per-PCR 0–7 `read_pcr` must
/// return 32 bytes equal to the shadow. Any read failure makes
/// the outcome inconclusive (`checked = false`, `read_failed =
/// true`) — it proves nothing about the replay, so it neither
/// sets the sticky mismatch nor refuses quotes. Any proven
/// mismatch sets the sticky [`FIRMWARE_REPLAY_MISMATCH`] flag,
/// which the quote composition refuses on.
///
/// Callers run this before the measured-boot completion summary,
/// so the boot console reports the outcome.
pub async fn cross_check_pcrs_0_7() -> PcrCrossCheck {
    let mut out = PcrCrossCheck {
        checked: false,
        mismatched: [false; 8],
        read_failed: false,
    };
    let Some(tpm) = narf_tpm::registry::list().first().cloned() else {
        return out;
    };
    for pcr in 0..8u32 {
        let want = pcr_shadow(pcr).unwrap_or([0u8; SHA256_DIGEST_SIZE]);
        match tpm.read_pcr(pcr).await {
            Ok(v) if v.len() == SHA256_DIGEST_SIZE && v.as_slice() == want.as_slice() => {}
            Ok(_) => {
                out.mismatched[pcr as usize] = true;
            }
            Err(_) => {
                out.read_failed = true;
            }
        }
    }
    if out.read_failed {
        return out;
    }
    out.checked = true;
    if out.mismatched.iter().any(|&m| m) {
        FIRMWARE_REPLAY_MISMATCH.store(true, Ordering::Release);
    }
    out
}

/// Record a measurement in the software log and extend it into both
/// the software shadow PCR and the hardware TPM (if one is present).
///
/// Equivalent to `measure_with_type` with `event_type = EV_IPL`. Kept
/// as the historical entry-point so existing callers don't change.
pub async fn measure(pcr: u32, label: &'static str, data: &[u8]) -> Result<(), TpmError> {
    measure_with_type(pcr, EV_IPL, label, data).await
}

/// Record a measurement with an explicit TCG event-type tag. Use this
/// when the measured object has a specific tag (firmware blob →
/// `EV_IPL`; boot cmdline → `EV_IPL_PARTITION_DATA`; etc.).
pub async fn measure_with_type(
    pcr: u32,
    event_type: u32,
    label: &'static str,
    data: &[u8],
) -> Result<(), TpmError> {
    let digest = sha256(data);
    record(pcr, event_type, label, &digest, data.len() as u64);

    // Shadow first, hardware second. This way a panic between the two
    // leaves the shadow consistent (the hw TPM will catch up on retry),
    // which is the more useful failure mode for forensics.
    let _ = extend_shadow(pcr, &digest);

    if let Some(tpm) = narf_tpm::registry::list().first() {
        tpm.extend_pcr(pcr, &digest).await?;
    }

    Ok(())
}

/// Record a measurement with an externally-computed digest. Used by
/// the firmware-blob measurement path (the blob's SHA-256 is already
/// in `BlobIdentity`) and by the SPDM device-attestation path.
///
/// The data is not re-hashed; the caller asserts `digest` is the
/// SHA-256 of the underlying bytes.
pub async fn measure_precomputed(
    pcr: u32,
    event_type: u32,
    label: String,
    digest: &[u8; SHA256_DIGEST_SIZE],
    data_len: u64,
) -> Result<(), TpmError> {
    record_owned(pcr, event_type, label, digest, data_len);
    let _ = extend_shadow(pcr, digest);
    if let Some(tpm) = narf_tpm::registry::list().first() {
        tpm.extend_pcr(pcr, digest).await?;
    }
    Ok(())
}

/// Measure a physical memory range. Caller asserts the range is
/// identity-mapped readable.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
pub async fn measure_phys(
    pcr: u32,
    label: &'static str,
    phys: u64,
    len: u64,
) -> Result<(), TpmError> {
    // SAFETY: caller asserts range is identity-mapped readable.
    let slice = unsafe {
        core::slice::from_raw_parts(
            narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>(),
            len as usize,
        )
    };
    measure(pcr, label, slice).await
}

/// Measure an SPDM device's firmware and state.
pub async fn measure_device(
    pcr: u32,
    label: &'static str,
    device: &dyn narf_spdm::AttestationDevice,
) -> Result<(), TpmError> {
    let mut session = narf_spdm::SpdmSession::new(device);
    if let Ok(_caps) = session.establish().await {
        if let Ok(measurements) = session.collect_measurements().await {
            for m in measurements {
                measure(pcr, label, &m.data).await?;
            }
        }
    }
    Ok(())
}

/// Measure the bootloader's command-line string into PCR 5 with event
/// type `EV_IPL_PARTITION_DATA`. The string is measured verbatim —
/// trailing NUL not stripped, leading/trailing whitespace preserved —
/// so userspace attestation tools can byte-match against the kernel's
/// own self-report of its cmdline.
pub async fn measure_cmdline(cmdline: &str) -> Result<(), TpmError> {
    measure_with_type(5, EV_IPL_PARTITION_DATA, "boot-cmdline", cmdline.as_bytes()).await
}

/// Measure the initramfs blob into PCR 6 (TCG PC Client Spec recommends
/// PCR 6 for OEM-specific boot artifacts; the Linux IMA + measurement
/// convention also lands the initramfs there).
///
/// SAFETY: `phys` + `len` must be identity-mapped readable for the
/// entire range. The bootloader contract guarantees this when the
/// initramfs is staged via the BootInfo handoff.
pub async unsafe fn measure_initramfs(phys: u64, len: u64) -> Result<(), TpmError> {
    if len == 0 {
        return Ok(());
    }
    // SAFETY: forwarded from caller.
    let slice = unsafe {
        core::slice::from_raw_parts(
            narf_memory::PhysAddr::new(phys).kernel_ptr::<u8>(),
            len as usize,
        )
    };
    measure_with_type(6, EV_IPL, "initramfs", slice).await
}

/// Measure a kernel-module / driver-firmware blob into PCR 9 with the
/// blob's path encoded into the event-data so remote attestation can
/// distinguish which firmware was loaded where.
///
/// The event-data format is `path \0` — a NUL-terminated path. The
/// digest is over the firmware bytes themselves (no path mixed in)
/// because PC Client Spec §10.4.3 separates the binary measurement
/// from the path-binding event.
pub async fn measure_firmware_blob(
    path: &str,
    digest: &[u8; SHA256_DIGEST_SIZE],
    length: u64,
) -> Result<(), TpmError> {
    let mut label = String::with_capacity(9 + path.len());
    label.push_str("firmware:");
    label.push_str(path);
    measure_precomputed(9, EV_IPL, label, digest, length).await
}

/// Returns a copy of the measurement log.
pub fn get_log() -> Vec<Measurement> {
    LOG.lock().clone()
}

/// Public alias for the userspace attestation surface. Matches the
/// spec's `narf_measure::event_log()` name.
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
pub fn event_log() -> Vec<Measurement> {
    get_log()
}

/// Number of recorded measurements. O(1).
#[allow(dead_code)] // TODO(narf): unused — reserved for a not-yet-wired path
pub fn event_count() -> usize {
    LOG.lock().len()
}

/// Encode the event log as a TCG PC Client Spec §10.4.2 byte stream
/// (`TCG_PCR_EVENT2` records, SHA-256 bank only).
///
/// Returns the encoded bytes ready for hand-off to a userspace
/// attestation agent. Each event is:
///
/// ```text
///     UINT32 pcrIndex
///     UINT32 eventType
///     UINT32 digestCount  = 1
///     UINT16 algId        = TPM_ALG_SHA256
///     BYTE   digest[32]
///     UINT32 eventSize    = event bytes length
///     BYTE   event[eventSize]
/// ```
///
/// The event bytes are the `label` for NARF's own measurements and
/// the verbatim firmware event bytes (`event_data`) for replayed
/// firmware events (#1071) — so a verifier replaying the published
/// log reproduces the firmware prefix exactly.
pub fn tcg_event_log_encode() -> Vec<u8> {
    let log = LOG.lock();
    let mut out = Vec::with_capacity(log.len() * (4 + 4 + 4 + 2 + 32 + 4 + 16));
    for e in log.iter() {
        out.extend_from_slice(&e.pcr.to_le_bytes());
        out.extend_from_slice(&e.event_type.to_le_bytes());
        // digestCount = 1
        out.extend_from_slice(&1u32.to_le_bytes());
        // algId = SHA256
        out.extend_from_slice(&TPM_ALG_SHA256.to_le_bytes());
        out.extend_from_slice(&e.digest);
        let event_bytes = match &e.event_data {
            Some(data) => data.as_slice(),
            None => e.label.as_bytes(),
        };
        out.extend_from_slice(&(event_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(event_bytes);
    }
    out
}

/// Parse the first `TCG_PCR_EVENT2` record from `buf`. Returns the
/// decoded `Measurement` (without `data_len`, since the wire format
/// records the event-data length, not the measured-data length) and
/// the number of bytes consumed. Used by the round-trip smoke and by
/// userspace tools verifying a log against the hardware PCR state.
pub fn tcg_event_log_decode_one(buf: &[u8]) -> Option<(Measurement, usize)> {
    if buf.len() < 4 + 4 + 4 + 2 + SHA256_DIGEST_SIZE + 4 {
        return None;
    }
    let pcr = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let event_type = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let digest_count = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    if digest_count != 1 {
        return None;
    }
    let alg_id = u16::from_le_bytes([buf[12], buf[13]]);
    if alg_id != TPM_ALG_SHA256 {
        return None;
    }
    let mut digest = [0u8; SHA256_DIGEST_SIZE];
    digest.copy_from_slice(&buf[14..14 + SHA256_DIGEST_SIZE]);
    let off = 14 + SHA256_DIGEST_SIZE;
    let event_size =
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]]) as usize;
    let off = off + 4;
    if off + event_size > buf.len() {
        return None;
    }
    // Firmware event bytes are arbitrary binary, not necessarily
    // text: keep them verbatim in `event_data` and recover a label
    // lossily. A decode that refused non-UTF-8 bytes would make the
    // published log unloadable on logs whose firmware events carry
    // binary payloads.
    let event_data = buf[off..off + event_size].to_vec();
    let label = String::from_utf8_lossy(&event_data).into_owned();
    Some((
        Measurement {
            pcr,
            event_type,
            digest,
            data_len: 0,
            label,
            event_data: Some(event_data),
        },
        off + event_size,
    ))
}

/// Reset the log + shadow + firmware-ingest state. Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    LOG.lock().clear();
    *PCR_SHADOW.lock() = [[0u8; SHA256_DIGEST_SIZE]; PCR_COUNT];
    EXTEND_OBSERVED.store(false, Ordering::Release);
    FIRMWARE_INGESTED.store(false, Ordering::Release);
    *FIRMWARE_INGEST.lock() = None;
    FIRMWARE_REPLAY_MISMATCH.store(false, Ordering::Release);
}

fn record(
    pcr: u32,
    event_type: u32,
    label: &'static str,
    digest: &[u8; SHA256_DIGEST_SIZE],
    data_len: u64,
) {
    LOG.lock().push(Measurement {
        pcr,
        event_type,
        digest: *digest,
        data_len,
        label: alloc::string::ToString::to_string(label),
        event_data: None,
    });
}

fn record_owned(
    pcr: u32,
    event_type: u32,
    label: String,
    digest: &[u8; SHA256_DIGEST_SIZE],
    data_len: u64,
) {
    LOG.lock().push(Measurement {
        pcr,
        event_type,
        digest: *digest,
        data_len,
        label,
        event_data: None,
    });
}

/// Record a replayed firmware event (#1071): same log entry as
/// [`record_owned`], but the event bytes are kept verbatim in
/// `event_data` (the measured-data length is unknowable for
/// firmware events — the digest is authoritative — so `data_len`
/// is 0).
fn record_firmware(
    pcr: u32,
    event_type: u32,
    label: String,
    digest: &[u8; SHA256_DIGEST_SIZE],
    event: Vec<u8>,
) {
    LOG.lock().push(Measurement {
        pcr,
        event_type,
        digest: *digest,
        data_len: 0,
        label,
        event_data: Some(event),
    });
}

// ── Smokes ─────────────────────────────────────────────────────────

use alloc::boxed::Box;
use alloc::sync::Arc;
use async_trait::async_trait;
use core::sync::atomic::AtomicU32;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_tpm::{TpmDevice, TpmInfo};

fn smoke_measure_sha256_known_vector() -> TestResult {
    // FIPS 180-4 vector: SHA-256("abc") =
    //   BA7816BF 8F01CFEA 414140DE 5DAE2223 B00361A3 96177A9C B410FF61 F20015AD
    let want: [u8; 32] = [
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22,
        0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00,
        0x15, 0xAD,
    ];
    if sha256(b"abc") != want {
        return TestResult::Fail("SHA-256(\"abc\") mismatch");
    }
    TestResult::Pass
}
kernel_test_in!("frame/measure", smoke_measure_sha256_known_vector);

fn smoke_measure_pcr_extend_chain() -> TestResult {
    // Two extends starting from zero: PCR_1 := SHA(0^32 || D1);
    // PCR_2 := SHA(PCR_1 || D2). Independently compute and compare.
    let d1 = [0x11u8; 32];
    let d2 = [0x22u8; 32];
    let zero = [0u8; 32];
    let expected_after_first = pcr_extend_value(&zero, &d1);
    let expected_after_second = pcr_extend_value(&expected_after_first, &d2);

    __reset_for_test();
    let v1 = extend_shadow(15, &d1).expect("range");
    let v2 = extend_shadow(15, &d2).expect("range");
    if v1 != expected_after_first {
        return TestResult::Fail("first extend mismatch");
    }
    if v2 != expected_after_second {
        return TestResult::Fail("second extend mismatch");
    }
    if pcr_shadow(15).unwrap() != expected_after_second {
        return TestResult::Fail("shadow PCR not updated");
    }
    if !any_extend_observed() {
        return TestResult::Fail("EXTEND_OBSERVED not set");
    }
    __reset_for_test();
    if any_extend_observed() {
        return TestResult::Fail("reset didn't clear EXTEND_OBSERVED");
    }
    TestResult::Pass
}
kernel_test_in!("frame/measure", smoke_measure_pcr_extend_chain);

fn smoke_measure_pcr_out_of_range_rejected() -> TestResult {
    __reset_for_test();
    let d = [0u8; 32];
    if extend_shadow(24, &d).is_some() {
        return TestResult::Fail("PCR 24 should be out of range");
    }
    if pcr_shadow(u32::MAX).is_some() {
        return TestResult::Fail("PCR u32::MAX should be out of range");
    }
    TestResult::Pass
}
kernel_test_in!("frame/measure", smoke_measure_pcr_out_of_range_rejected);

fn smoke_measure_tcg_event_log_round_trip() -> TestResult {
    __reset_for_test();
    let d = [0xABu8; 32];
    record_owned(
        7,
        EV_IPL,
        alloc::string::ToString::to_string("test-event"),
        &d,
        42,
    );
    let bytes = tcg_event_log_encode();
    let (m, n) = match tcg_event_log_decode_one(&bytes) {
        Some(p) => p,
        None => return TestResult::Fail("decode returned None"),
    };
    if n != bytes.len() {
        return TestResult::Fail("decoder didn't consume full record");
    }
    if m.pcr != 7 || m.event_type != EV_IPL || m.digest != d || m.label != "test-event" {
        return TestResult::Fail("round-trip mismatch");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("frame/measure", smoke_measure_tcg_event_log_round_trip);

fn smoke_measure_attestation_hooks_publish_state() -> TestResult {
    __reset_for_test();
    narf_tpm::attest::__reset_measurement_hooks_for_test();
    install_attestation_hooks();
    // Before any extend: the guard hook reports the untouched
    // state (the quote composition refuses on exactly this), and
    // the log hook serves the encoder's (empty) output.
    if narf_tpm::attest::extends_observed() {
        return TestResult::Fail("extends observed before any extend");
    }
    if narf_tpm::attest::event_log_bytes() != tcg_event_log_encode() {
        return TestResult::Fail("event log hook != tcg_event_log_encode (empty)");
    }
    let d = [0xCDu8; 32];
    record_owned(
        7,
        EV_IPL,
        alloc::string::ToString::to_string("hook-event"),
        &d,
        7,
    );
    if narf_tpm::attest::event_log_bytes() != tcg_event_log_encode()
        || narf_tpm::attest::event_log_bytes().is_empty()
    {
        return TestResult::Fail("event log hook does not serve the recorded log");
    }
    if extend_shadow(4, &d).is_none() {
        return TestResult::Fail("extend_shadow(4) rejected");
    }
    if !narf_tpm::attest::extends_observed() {
        return TestResult::Fail("extend not observed through the installed hook");
    }
    narf_tpm::attest::__reset_measurement_hooks_for_test();
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "frame/measure",
    smoke_measure_attestation_hooks_publish_state
);

fn smoke_measure_initramfs_event_records_pcr_6() -> TestResult {
    __reset_for_test();
    // We can't call the async fn without a runtime here, so test the
    // synchronous building blocks: a recorded entry under PCR 6 must
    // have the SHA-256 of the data we'd have passed in.
    let payload: &[u8] = b"CPIO archive contents go here";
    let want = sha256(payload);
    record(6, EV_IPL, "initramfs", &want, payload.len() as u64);
    let log = get_log();
    if log.len() != 1 {
        return TestResult::Fail("expected one log entry");
    }
    if log[0].pcr != 6 {
        return TestResult::Fail("expected PCR 6");
    }
    if log[0].digest != want {
        return TestResult::Fail("digest mismatch");
    }
    if log[0].data_len != payload.len() as u64 {
        return TestResult::Fail("data_len mismatch");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("frame/measure", smoke_measure_initramfs_event_records_pcr_6);

fn smoke_measure_event_log_encoder_layout() -> TestResult {
    __reset_for_test();
    let d = [0x55u8; 32];
    record_owned(
        4,
        EV_EFI_BOOT_SERVICES_APPLICATION,
        alloc::string::ToString::to_string("kernel"),
        &d,
        100,
    );
    let bytes = tcg_event_log_encode();
    // Minimum record length = 4 (pcr) + 4 (et) + 4 (count) + 2 (alg)
    // + 32 (digest) + 4 (size) + label.
    let want = 4 + 4 + 4 + 2 + 32 + 4 + "kernel".len();
    if bytes.len() != want {
        return TestResult::Fail("encoded length wrong");
    }
    // pcr at offset 0 little-endian.
    if u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) != 4 {
        return TestResult::Fail("pcr field wrong");
    }
    if u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
        != EV_EFI_BOOT_SERVICES_APPLICATION
    {
        return TestResult::Fail("event-type field wrong");
    }
    if u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) != 1 {
        return TestResult::Fail("digestCount != 1");
    }
    if u16::from_le_bytes([bytes[12], bytes[13]]) != TPM_ALG_SHA256 {
        return TestResult::Fail("algId != SHA256");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("frame/measure", smoke_measure_event_log_encoder_layout);

/// Recording `TpmDevice` for the dispatch smoke: counts extends and
/// keeps the last (PCR, digest) pair it was handed.
struct RecordingTpm {
    extends: AtomicU32,
    last: IrqSafeSpinLock<Option<(u32, [u8; SHA256_DIGEST_SIZE])>>,
}

#[async_trait]
impl TpmDevice for RecordingTpm {
    fn get_info(&self) -> TpmInfo {
        TpmInfo {
            manufacturer: 0x4D4F434B, // "MOCK"
            version: 1,
            spec_level: 2,
        }
    }

    async fn submit_raw(&self, _cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
        Ok(alloc::vec![0; 10])
    }

    async fn get_random(&self, bytes: u16) -> Result<Vec<u8>, TpmError> {
        Ok(alloc::vec![0xAA; bytes as usize])
    }

    async fn extend_pcr(&self, pcr: u32, digest: &[u8]) -> Result<(), TpmError> {
        self.extends.fetch_add(1, Ordering::SeqCst);
        let mut d = [0u8; SHA256_DIGEST_SIZE];
        let n = digest.len().min(SHA256_DIGEST_SIZE);
        d[..n].copy_from_slice(&digest[..n]);
        *self.last.lock() = Some((pcr, d));
        Ok(())
    }

    async fn read_pcr(&self, _pcr: u32) -> Result<Vec<u8>, TpmError> {
        Ok(alloc::vec![0; SHA256_DIGEST_SIZE])
    }
}

fn smoke_measure_dispatches_extend_to_registered_device() -> TestResult {
    // The keystone seam (#943, covering #934's registry core): with
    // a device in `narf_tpm::registry`, `measure` must dispatch the
    // extend to it — until the platform probe learned to register,
    // this branch could not execute anywhere, fixtures included.
    // Hygiene: the registry and the measure state are globals, so
    // reset on entry AND exit; a leaked mock would silently become
    // the dispatch target for unrelated smokes later in the boot.
    narf_tpm::registry::__reset_for_test();
    __reset_for_test();
    narf_scheduler::__reset_queues_for_test();

    let mock = Arc::new(RecordingTpm {
        extends: AtomicU32::new(0),
        last: IrqSafeSpinLock::new(None),
    });
    narf_tpm::registry::register(mock.clone());
    if !hardware_dispatch_active() {
        narf_tpm::registry::__reset_for_test();
        return TestResult::Fail("registered device invisible to dispatch check");
    }

    let payload: &'static [u8] = b"narf measured-boot dispatch smoke";
    narf_scheduler::spawn(async move {
        let _ = measure(4, "dispatch-smoke", payload).await;
    });
    narf_scheduler::run_until_empty();

    let want_digest = sha256(payload);
    let observed = *mock.last.lock();
    let count = mock.extends.load(Ordering::SeqCst);
    let shadow_ok =
        pcr_shadow(4) == Some(pcr_extend_value(&[0u8; SHA256_DIGEST_SIZE], &want_digest));
    let log_ok = get_log().len() == 1;
    narf_tpm::registry::__reset_for_test();
    __reset_for_test();

    if count != 1 {
        return TestResult::Fail("registered device did not receive exactly one extend");
    }
    match observed {
        Some((pcr, digest)) if pcr == 4 && digest == want_digest => {}
        _ => return TestResult::Fail("dispatched extend carried wrong PCR or digest"),
    }
    if !shadow_ok {
        return TestResult::Fail("shadow PCR did not advance alongside hardware dispatch");
    }
    if !log_ok {
        return TestResult::Fail("measurement log did not record the dispatched event");
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/measure",
    smoke_measure_dispatches_extend_to_registered_device
);

/// Stateful `TpmDevice` for the reconciliation smoke: a real PCR
/// bank (the production extend formula applied per extend), not
/// a recording mock — so the fixture can compare *device PCR
/// state* against the software shadow, the reconciliation the
/// audit noted the production design needs (#946).
struct StatefulTpm {
    bank: IrqSafeSpinLock<[[u8; SHA256_DIGEST_SIZE]; PCR_COUNT]>,
    extends: AtomicU32,
    fail_extends: AtomicBool,
}

impl StatefulTpm {
    fn new() -> Self {
        Self {
            bank: IrqSafeSpinLock::new([[0; SHA256_DIGEST_SIZE]; PCR_COUNT]),
            extends: AtomicU32::new(0),
            fail_extends: AtomicBool::new(false),
        }
    }

    fn bank_snapshot(&self, pcr: u32) -> [u8; SHA256_DIGEST_SIZE] {
        self.bank.lock()[pcr as usize]
    }

    /// Test-only: set one bank PCR outright (what real firmware
    /// left in silicon), without extending — the firmware replay
    /// never extends hardware, so the cross-check smoke seeds the
    /// device bank to the replayed shadow this way.
    fn seed_pcr(&self, pcr: u32, value: [u8; SHA256_DIGEST_SIZE]) {
        self.bank.lock()[pcr as usize] = value;
    }
}

#[async_trait]
impl TpmDevice for StatefulTpm {
    fn get_info(&self) -> TpmInfo {
        TpmInfo {
            manufacturer: 0x53544154, // "STAT"
            version: 1,
            spec_level: 2,
        }
    }

    async fn submit_raw(&self, _cmd: &[u8]) -> Result<Vec<u8>, TpmError> {
        // `measure` never submits raw frames; the register-level
        // command conversation is covered at the platform seam
        // (drivers/platform/src/tpm_fixture.rs). Fail honestly
        // rather than fabricate a success response.
        Err(TpmError::BadResponse)
    }

    async fn get_random(&self, bytes: u16) -> Result<Vec<u8>, TpmError> {
        Ok(alloc::vec![0x5A; bytes as usize])
    }

    async fn extend_pcr(&self, pcr: u32, digest: &[u8]) -> Result<(), TpmError> {
        if self.fail_extends.load(Ordering::SeqCst) {
            return Err(TpmError::HardwareError);
        }
        let mut d = [0u8; SHA256_DIGEST_SIZE];
        let n = digest.len().min(SHA256_DIGEST_SIZE);
        d[..n].copy_from_slice(&digest[..n]);
        let mut bank = self.bank.lock();
        bank[pcr as usize] = pcr_extend_value(&bank[pcr as usize], &d);
        self.extends.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn read_pcr(&self, pcr: u32) -> Result<Vec<u8>, TpmError> {
        Ok(self.bank_snapshot(pcr).to_vec())
    }
}

fn smoke_measure_hardware_pcr_state_matches_shadow() -> TestResult {
    // #946: with a *stateful* device registered, a sequence of
    // production measurements must leave the device's PCR state
    // identical to the software shadow for every measured PCR —
    // the end-to-end property measured boot exists to provide,
    // previously unexecutable anywhere (the dispatch smoke's
    // recording mock has no PCR state to reconcile).
    // Hygiene: registry + measure state are globals; reset on
    // entry and exit (see the dispatch smoke).
    narf_tpm::registry::__reset_for_test();
    __reset_for_test();
    narf_scheduler::__reset_queues_for_test();

    let dev = Arc::new(StatefulTpm::new());
    narf_tpm::registry::register(dev.clone());
    let errs = Arc::new(AtomicU32::new(0));
    let errs_in = errs.clone();
    narf_scheduler::spawn(async move {
        let bump = |r: Result<(), TpmError>| {
            if r.is_err() {
                errs_in.fetch_add(1, Ordering::SeqCst);
            }
        };
        bump(measure(4, "boot-info", b"stage5 boot info payload").await);
        bump(measure(4, "boot-info-2", b"second measurement, same PCR").await);
        bump(measure(5, "cmdline", b"root=/dev/nvme0n1p2 quiet").await);
        let blob_digest = sha256(b"firmware blob bytes");
        bump(measure_precomputed(9, EV_IPL, String::from("fw-blob"), &blob_digest, 19).await);
    });
    narf_scheduler::run_until_empty();

    let mut ok = errs.load(Ordering::SeqCst) == 0 && dev.extends.load(Ordering::SeqCst) == 4;
    for pcr in [4u32, 5, 9] {
        if dev.bank_snapshot(pcr) != pcr_shadow(pcr).unwrap_or([0u8; SHA256_DIGEST_SIZE]) {
            ok = false;
        }
    }
    // An unmeasured PCR stays at the reset value on both sides.
    if dev.bank_snapshot(0) != [0u8; SHA256_DIGEST_SIZE]
        || pcr_shadow(0) != Some([0u8; SHA256_DIGEST_SIZE])
    {
        ok = false;
    }
    let log_ok = get_log().len() == 4;
    narf_tpm::registry::__reset_for_test();
    __reset_for_test();
    if !ok {
        return TestResult::Fail("device PCR state diverged from the shadow");
    }
    if !log_ok {
        return TestResult::Fail("measurement log did not record all four events");
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/measure",
    smoke_measure_hardware_pcr_state_matches_shadow
);

fn smoke_measure_hardware_failure_propagates() -> TestResult {
    // The hardware branch of `measure_with_type` propagates
    // device errors with `?` (measure.rs) — pin that a failing
    // device makes the measurement fail, and that the documented
    // shadow-first order still leaves the shadow advanced (the
    // forensic property the code comment promises) while the
    // device bank is untouched.
    narf_tpm::registry::__reset_for_test();
    __reset_for_test();
    narf_scheduler::__reset_queues_for_test();

    let dev = Arc::new(StatefulTpm::new());
    dev.fail_extends.store(true, Ordering::SeqCst);
    narf_tpm::registry::register(dev.clone());
    let outcome = Arc::new(IrqSafeSpinLock::new(None::<bool>));
    let outcome_in = outcome.clone();
    narf_scheduler::spawn(async move {
        let r = measure(6, "initramfs", b"initramfs bytes").await;
        *outcome_in.lock() = Some(r.is_err());
    });
    narf_scheduler::run_until_empty();

    let propagated = *outcome.lock() == Some(true);
    let want_shadow = pcr_extend_value(&[0u8; SHA256_DIGEST_SIZE], &sha256(b"initramfs bytes"));
    let shadow_ok = pcr_shadow(6) == Some(want_shadow);
    let bank_ok = dev.bank_snapshot(6) == [0u8; SHA256_DIGEST_SIZE];
    narf_tpm::registry::__reset_for_test();
    __reset_for_test();
    if !propagated {
        return TestResult::Fail("device extend failure did not propagate out of measure");
    }
    if !shadow_ok {
        return TestResult::Fail("shadow did not advance ahead of the failing device");
    }
    if !bank_ok {
        return TestResult::Fail("failing device mutated its PCR bank");
    }
    TestResult::Pass
}
kernel_test_in!("frame/measure", smoke_measure_hardware_failure_propagates);

/// Synthetic TCG2 log builders for the firmware-ingest smokes
/// (#1071). Hand-built from the TCG PC Client spec layouts (same
/// shapes as `efi/src/tests.rs`'s builders, duplicated here
/// because a kernel-test crate cannot import another crate's test
/// helpers): a Spec ID event, then EVENT2 records.
fn fw_push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn fw_push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn fw_spec_id_record() -> Vec<u8> {
    // TCG_PCR_EVENT: PCR 0, EV_NO_ACTION, 20 zero digest bytes,
    // event = TCG_EfiSpecIdEventStruct ("Spec ID Event03" + NUL,
    // platformClass 0, specVersion 2.0, errata 0, uintnSize 2,
    // numberOfAlgorithms 2: SHA-1/20 + SHA-256/32, vendorInfo "").
    // The signature is 16 bytes: the 15 ASCII bytes plus the NUL
    // terminator the TCG spec counts in TCG_SPECID_SIG. A 15-byte
    // signature shifts every later field one byte early and the
    // parser rejects the log (BadSpecIdVersion at the major byte).
    let mut body = Vec::new();
    body.extend_from_slice(b"Spec ID Event03\0");
    fw_push_u32(&mut body, 0);
    body.push(0);
    body.push(2);
    body.push(0);
    body.push(2);
    fw_push_u32(&mut body, 2);
    fw_push_u16(&mut body, 0x0004);
    fw_push_u16(&mut body, 20);
    fw_push_u16(&mut body, 0x000B);
    fw_push_u16(&mut body, 32);
    body.push(0);
    let mut rec = Vec::new();
    fw_push_u32(&mut rec, 0);
    fw_push_u32(&mut rec, EV_NO_ACTION);
    rec.extend_from_slice(&[0u8; 20]);
    fw_push_u32(&mut rec, body.len() as u32);
    rec.extend_from_slice(&body);
    rec
}

fn fw_event2_record(pcr: u32, event_type: u32, sha256: [u8; 32], event: &[u8]) -> Vec<u8> {
    // EVENT2 with two digests (SHA-1 + SHA-256), matching the Spec
    // ID anchor above — every record's digest count SHALL equal
    // numberOfAlgorithms (PC Client §9.1).
    let mut rec = Vec::new();
    fw_push_u32(&mut rec, pcr);
    fw_push_u32(&mut rec, event_type);
    fw_push_u32(&mut rec, 2);
    fw_push_u16(&mut rec, 0x0004);
    rec.extend_from_slice(&[0x11u8; 20]);
    fw_push_u16(&mut rec, 0x000B);
    rec.extend_from_slice(&sha256);
    fw_push_u32(&mut rec, event.len() as u32);
    rec.extend_from_slice(event);
    rec
}

fn fw_synthetic_log() -> Vec<u8> {
    let mut log = fw_spec_id_record();
    // CRTM measurement into PCR 0.
    log.extend_from_slice(&fw_event2_record(
        0,
        0x0000_0008,
        [0x21u8; 32],
        b"CRTM version",
    ));
    // Separator into PCR 0.
    log.extend_from_slice(&fw_event2_record(
        0,
        EV_SEPARATOR,
        [0x22u8; 32],
        b"separator",
    ));
    // Informational NO_ACTION event on PCR 7 — recorded, never extended.
    log.extend_from_slice(&fw_event2_record(
        7,
        EV_NO_ACTION,
        [0x23u8; 32],
        b"informational",
    ));
    log
}

fn smoke_measure_firmware_ingest_replays_spec_log() -> TestResult {
    __reset_for_test();
    let log = fw_synthetic_log();
    let (info, parsed) = match narf_efi::tcg2::parse_tcg2_log(&log) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("synthetic TCG2 log rejected"),
    };
    if info.number_of_algorithms != 2 || parsed.len() != 4 {
        return TestResult::Fail("synthetic log parsed wrong");
    }
    let events: Vec<ParsedFirmwareEvent> = parsed
        .into_iter()
        .map(ParsedFirmwareEvent::from_tcg2)
        .collect();
    let outcome = match apply_firmware_replay(&events, 4, 0, true) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("firmware replay refused"),
    };
    if outcome.main_events != 4 || outcome.final_events != 0 || !outcome.full_chain {
        return TestResult::Fail("ingest outcome wrong");
    }
    // The firmware prefix is the head of the log, in stream order.
    let entries = get_log();
    if entries.len() != 4 {
        return TestResult::Fail("log length after replay wrong");
    }
    if entries[0].event_type != EV_NO_ACTION || entries[1].event_type != 0x0000_0008 {
        return TestResult::Fail("replayed log order wrong");
    }
    // The Spec ID record's digest is the all-zero legacy digest.
    if entries[0].digest != [0u8; SHA256_DIGEST_SIZE] {
        return TestResult::Fail("Spec ID digest not zero");
    }
    // Shadow math: PCR 0 = H(H(0 || 0x21..) || 0x22..); the
    // NO_ACTION event on PCR 7 extended nothing.
    let want_pcr0 = pcr_extend_value(
        &pcr_extend_value(&[0u8; SHA256_DIGEST_SIZE], &[0x21u8; 32]),
        &[0x22u8; 32],
    );
    if pcr_shadow(0) != Some(want_pcr0) {
        return TestResult::Fail("PCR 0 shadow after replay wrong");
    }
    if pcr_shadow(7) != Some([0u8; SHA256_DIGEST_SIZE]) {
        return TestResult::Fail("NO_ACTION event extended PCR 7");
    }
    // Firmware event bytes round-trip through the encoder: a
    // verifier replaying the published log sees the firmware
    // prefix verbatim.
    let encoded = tcg_event_log_encode();
    let mut off = 0usize;
    let mut decoded: Vec<Measurement> = Vec::new();
    while off < encoded.len() {
        let Some((m, n)) = tcg_event_log_decode_one(&encoded[off..]) else {
            return TestResult::Fail("published log undecodable");
        };
        off += n;
        decoded.push(m);
    }
    if decoded.len() != 4 || decoded[1].digest != [0x21u8; 32] {
        return TestResult::Fail("published log round-trip wrong");
    }
    if decoded[1].event_data.as_deref() != Some(b"CRTM version".as_slice()) {
        return TestResult::Fail("firmware event bytes not preserved");
    }
    // Guards: a second replay is refused, and the state is untouched.
    match apply_firmware_replay(&events, 4, 0, true) {
        Err(FirmwareIngestError::AlreadyIngested) => {}
        _ => return TestResult::Fail("second replay not refused"),
    }
    if get_log().len() != 4 || pcr_shadow(0) != Some(want_pcr0) {
        return TestResult::Fail("refused replay mutated state");
    }
    // TooLate: after any NARF extend, a replay is refused.
    __reset_for_test();
    let _ = extend_shadow(4, &[0xCDu8; 32]);
    match apply_firmware_replay(&events, 4, 0, true) {
        Err(FirmwareIngestError::TooLate) => {}
        _ => return TestResult::Fail("replay after extend not refused"),
    }
    if !get_log().is_empty() {
        return TestResult::Fail("refused replay recorded events");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "frame/measure",
    smoke_measure_firmware_ingest_replays_spec_log
);

fn smoke_measure_firmware_ingest_absent_without_efi() -> TestResult {
    // The kernel-test environment has no EFI system table
    // (`firmware_handoff` is EMPTY: parse_raw never ran), so the
    // full ingest path must report the absence, not a log.
    __reset_for_test();
    match ingest_firmware_event_log() {
        Err(FirmwareIngestError::NoFirmwareLog) => {}
        _ => return TestResult::Fail("ingest without EFI did not report NoFirmwareLog"),
    }
    if firmware_ingest().is_some() || !get_log().is_empty() {
        return TestResult::Fail("failed ingest left state behind");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!(
    "frame/measure",
    smoke_measure_firmware_ingest_absent_without_efi
);

fn smoke_measure_firmware_cross_check_matches_and_mismatches() -> TestResult {
    narf_tpm::registry::__reset_for_test();
    __reset_for_test();
    narf_scheduler::__reset_queues_for_test();

    let tpm = Arc::new(StatefulTpm::new());
    narf_tpm::registry::register(tpm.clone());

    // Replay the synthetic firmware log: the shadow PCR 0
    // advances; the device bank does not (replay never touches
    // hardware).
    let log = fw_synthetic_log();
    let Ok((_, parsed)) = narf_efi::tcg2::parse_tcg2_log(&log) else {
        narf_tpm::registry::__reset_for_test();
        __reset_for_test();
        return TestResult::Fail("synthetic TCG2 log rejected");
    };
    let events: Vec<ParsedFirmwareEvent> = parsed
        .into_iter()
        .map(ParsedFirmwareEvent::from_tcg2)
        .collect();
    if apply_firmware_replay(&events, 4, 0, true).is_err() {
        narf_tpm::registry::__reset_for_test();
        __reset_for_test();
        return TestResult::Fail("firmware replay refused");
    }
    // Seed the device bank with the replayed shadow for PCRs 0–7
    // (what real firmware left in silicon): the check matches.
    for pcr in 0..8u32 {
        tpm.seed_pcr(pcr, pcr_shadow(pcr).unwrap_or([0u8; SHA256_DIGEST_SIZE]));
    }
    let outcome = Arc::new(IrqSafeSpinLock::new(None));
    let outcome2 = outcome.clone();
    narf_scheduler::spawn(async move {
        *outcome2.lock() = Some(cross_check_pcrs_0_7().await);
    });
    narf_scheduler::run_until_empty();
    let check = match *outcome.lock() {
        Some(c) => c,
        None => {
            narf_tpm::registry::__reset_for_test();
            __reset_for_test();
            return TestResult::Fail("cross-check task never ran");
        }
    };
    if !check.checked || check.mismatched.iter().any(|&m| m) || firmware_replay_mismatch() {
        narf_tpm::registry::__reset_for_test();
        __reset_for_test();
        return TestResult::Fail("matching replay reported mismatch");
    }
    // Now corrupt one hardware PCR: the check must prove the
    // mismatch and set the sticky flag.
    tpm.seed_pcr(1, [0xFFu8; 32]);
    let outcome = Arc::new(IrqSafeSpinLock::new(None));
    let outcome2 = outcome.clone();
    narf_scheduler::spawn(async move {
        *outcome2.lock() = Some(cross_check_pcrs_0_7().await);
    });
    narf_scheduler::run_until_empty();
    let check = match *outcome.lock() {
        Some(c) => c,
        None => {
            narf_tpm::registry::__reset_for_test();
            __reset_for_test();
            return TestResult::Fail("mismatch cross-check task never ran");
        }
    };
    let checked = check.checked;
    let m0 = check.mismatched[0];
    let m1 = check.mismatched[1];
    let sticky = firmware_replay_mismatch();
    narf_tpm::registry::__reset_for_test();
    __reset_for_test();
    if !checked || !m1 || m0 {
        return TestResult::Fail("mismatch not proven on PCR 1");
    }
    if !sticky {
        return TestResult::Fail("sticky mismatch flag not set");
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/measure",
    smoke_measure_firmware_cross_check_matches_and_mismatches
);
