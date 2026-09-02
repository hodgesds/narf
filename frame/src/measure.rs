//! Measured Boot Support — hardware-anchored TCB integrity.
//!
//! Spec: `frame/specification/spec.md` §3.7. Anchors the NARF security
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
///     UINT32 eventSize    = label.len()
///     BYTE   event[eventSize]
/// ```
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
        let label_bytes = e.label.as_bytes();
        out.extend_from_slice(&(label_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(label_bytes);
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
    let label = match core::str::from_utf8(&buf[off..off + event_size]) {
        Ok(s) => alloc::string::ToString::to_string(s),
        Err(_) => return None,
    };
    Some((
        Measurement {
            pcr,
            event_type,
            digest,
            data_len: 0,
            label,
        },
        off + event_size,
    ))
}

/// Reset the log + shadow. Test-only.
#[doc(hidden)]
pub fn __reset_for_test() {
    LOG.lock().clear();
    *PCR_SHADOW.lock() = [[0u8; SHA256_DIGEST_SIZE]; PCR_COUNT];
    EXTEND_OBSERVED.store(false, Ordering::Release);
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
    });
}

// ── Smokes ─────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

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
