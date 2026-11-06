//! TCG2 event-log codecs — the firmware side of measured boot.
//!
//! Sources (public only):
//!
//! - **TCG EFI Protocol Specification, TPM Family 2.0** (TCG):
//!   `EFI_TCG2_PROTOCOL_GUID`, `EFI_TCG2_FINAL_EVENTS_TABLE_GUID`,
//!   `EFI_TCG2_FINAL_EVENTS_TABLE_VERSION`, and the
//!   `EFI_TCG2_FINAL_EVENTS_TABLE` layout (`Version`/`NumberOfEvents`
//!   are `UINT64`; events follow as `TCG_PCR_EVENT2` records with no
//!   Spec ID header of their own).
//! - **TCG PC Client Platform Firmware Profile §9.1, §9.4.5.1, §10.4**:
//!   the TCG2 log opens with a legacy `TCG_PCR_EVENT` carrying the
//!   `TCG_EfiSpecIdEvent` ("Spec ID Event03"); every `TCG_PCR_EVENT2`
//!   record's digest count SHALL equal the Spec ID event's
//!   `numberOfAlgorithms` (including `EV_NO_ACTION` events, which do
//!   not extend any PCR); `numberOfAlgorithms` MUST be ≥ 1.
//! - **TCG Guidance on Integrity Measurements and Event Log
//!   Processing v1.0 §4.3.4**: the first (`EV_NO_ACTION`) event is
//!   completely unauthenticated — no PCR is extended — and a verifier
//!   must ignore its content. (PC Client Implementation Spec, Table
//!   13: `EV_NO_ACTION` "MUST NOT extend any PCR"; `EV_SEPARATOR`
//!   "MUST extend the PCRs 0 through 7 inclusive".)
//! - **Linux** `drivers/firmware/efi/libstub/tpm.c`
//!   (`efi_retrieve_tcg2_eventlog`) and `drivers/char/tpm/eventlog/efi.c`
//!   (`tpm_read_log_efi`): the `linux_efi_tpm_eventlog` wrapper
//!   (`size`/`final_events_preboot_size`/`version`/`log[]`) the EFI
//!   stub installs under `LINUX_EFI_TPM_EVENT_LOG_GUID`, the
//!   `final_events_preboot_size` de-duplication (the final table's
//!   leading bytes already present in the main log are skipped, never
//!   replayed twice), and the zero-record terminator (an all-zero
//!   record header ends a zero-padded log area).
//!
//! What this crate does NOT do: read physical memory, walk the EFI
//! configuration table, or replay anything into a PCR shadow. Those
//! are the boot handoff's (`narf_boot::firmware`) and
//! `frame::measure`'s jobs; this module is pure wire decoding so
//! both can be tested against synthetic, spec-built bytes.

extern crate alloc;

use alloc::vec::Vec;

use crate::variable::Guid;

/// `EFI_TCG2_FINAL_EVENTS_TABLE_GUID`
/// (`{1e2ed096-30e2-4254-bd89-863bbef82325}`) — the EFI configuration
/// table entry carrying the final-events table (events logged after
/// the last `GetEventLog` call, notably `ExitBootServices`).
pub const EFI_TCG2_FINAL_EVENTS_TABLE_GUID: Guid = Guid::new(
    0x1e2e_d096,
    0x30e2,
    0x4254,
    [0xbd, 0x89, 0x86, 0x3b, 0xbe, 0xf8, 0x23, 0x25],
);

/// `LINUX_EFI_TPM_EVENT_LOG_GUID`
/// (`{b7799cb0-eca2-4943-9667-1fae07b747fa}`) — the Linux-specific
/// EFI configuration table entry under which an EFI stub (or a
/// bootloader following the same convention, e.g. Limine's Linux
/// boot-protocol path) publishes the main TCG2 event log wrapped in
/// [`LinuxTpmEventLogHeader`].
pub const LINUX_EFI_TPM_EVENT_LOG_GUID: Guid = Guid::new(
    0xb779_9cb0,
    0xeca2,
    0x4943,
    [0x96, 0x67, 0x1f, 0xae, 0x07, 0xb7, 0x47, 0xfa],
);

/// `EFI_TCG2_FINAL_EVENTS_TABLE_VERSION` — the only defined version
/// of the final-events table. Anything else is a future format this
/// decoder does not understand; [`decode_final_events_table_header`]
/// rejects it rather than guessing at the layout.
pub const EFI_TCG2_FINAL_EVENTS_TABLE_VERSION: u64 = 1;

/// `EFI_TCG2_EVENT_LOG_FORMAT_TCG_2` — the `version` byte of a
/// [`LinuxTpmEventLogHeader`] holding a crypto-agile (TCG2) log.
/// Version 1 (`TCG_1_2`, SHA-1 only) has no SHA-256 bank to replay
/// into a SHA-256 shadow and is rejected by
/// [`decode_linux_tpm_event_log_header`].
pub const EFI_TCG2_EVENT_LOG_FORMAT_TCG_2: u8 = 2;

/// `TPM_ALG_SHA1` (TCG Algorithm Registry) — digest size 20.
pub const TPM_ALG_SHA1: u16 = 0x0004;
/// `TPM_ALG_SHA256` (TCG Algorithm Registry) — digest size 32.
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// `TPM_ALG_SHA384` (TCG Algorithm Registry) — digest size 48.
pub const TPM_ALG_SHA384: u16 = 0x000C;
/// `TPM_ALG_SHA512` (TCG Algorithm Registry) — digest size 64.
pub const TPM_ALG_SHA512: u16 = 0x000D;
/// `TPM_ALG_SM3_256` (TCG Algorithm Registry) — digest size 32.
pub const TPM_ALG_SM3_256: u16 = 0x0012;

/// `EV_NO_ACTION` — informational; MUST NOT extend any PCR
/// (PC Client Implementation Spec, Table 13).
pub const EV_NO_ACTION: u32 = 0x0000_0003;

/// Largest PCR index a TCG2 log may name (`MAX_PCR_INDEX`).
pub const MAX_PCR_INDEX: u32 = 23;

/// Signature opening every TCG2 log's Spec ID event
/// (`TCG_SPECID_SIG`).
pub const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03";

/// The Spec ID event's `specVersionMajor` for a TPM 2.0 log.
pub const SPEC_ID_VERSION_MAJOR: u8 = 2;

/// NARF bound on the algorithms a Spec ID event may declare.
/// Real firmware declares 1–3; anything above this is treated as
/// malformed rather than walked (each declared algorithm costs a
/// digest slot in every record).
pub const MAX_SPEC_ID_ALGORITHMS: u32 = 8;

/// NARF bound on events parsed from one log (DoS bound: a corrupt
/// `NumberOfEvents` must not make the parser loop forever).
pub const MAX_TCG2_LOG_EVENTS: usize = 16384;

/// NARF bound on one event's `eventSize` (DoS bound; real firmware
/// events are bytes to low KiB — the largest, an `EV_EFI_VARIABLE`
/// authority blob, stays well under this).
pub const MAX_TCG2_EVENT_SIZE: usize = 1 << 20;

/// NARF bound on a whole firmware log copied out of physical memory
/// (mirrors the SMBIOS `MAX_TABLE_LEN` bound; real logs are < 128 KiB).
pub const MAX_TCG2_LOG_BYTES: usize = 1 << 20;

/// `EFI_TCG2_FINAL_EVENTS_TABLE` header — 16 bytes:
///
/// ```text
///   0..8:   Version        (UINT64, must be 1)
///   8..16:  NumberOfEvents (UINT64)
///   16..:   TCG_PCR_EVENT2 Event[NumberOfEvents] (no Spec ID header)
/// ```
///
/// The table carries no total length: the caller walks exactly
/// `number_of_events` records (see [`parse_final_events`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FinalEventsTableHeader {
    pub version: u64,
    pub number_of_events: u64,
}

/// Decode an `EFI_TCG2_FINAL_EVENTS_TABLE` header. `None` when the
/// buffer is short or the version is not
/// [`EFI_TCG2_FINAL_EVENTS_TABLE_VERSION`] (fail closed: a future
/// version may lay the events out differently).
pub fn decode_final_events_table_header(buf: &[u8]) -> Option<FinalEventsTableHeader> {
    if buf.len() < 16 {
        return None;
    }
    let version = u64::from_le_bytes(buf[0..8].try_into().ok()?);
    if version != EFI_TCG2_FINAL_EVENTS_TABLE_VERSION {
        return None;
    }
    let number_of_events = u64::from_le_bytes(buf[8..16].try_into().ok()?);
    Some(FinalEventsTableHeader {
        version,
        number_of_events,
    })
}

/// `struct linux_efi_tpm_eventlog` header — 9 bytes:
///
/// ```text
///   0..4:  size                     (u32, bytes of `log[]`)
///   4..8:  final_events_preboot_size (u32, leading bytes of the
///          final-events table already present in `log[]` — skip
///          that many bytes when appending the final table)
///   8:     version                  (u8, 2 = TCG2 crypto-agile)
///   9..:   log[]                    (the TCG2 event log itself)
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LinuxTpmEventLogHeader {
    pub size: u32,
    pub final_events_preboot_size: u32,
    pub version: u8,
}

/// Decode a `linux_efi_tpm_eventlog` header. `None` when the buffer
/// is short or `version` is not
/// [`EFI_TCG2_EVENT_LOG_FORMAT_TCG_2`] (a SHA-1-only log has no
/// SHA-256 bank to replay).
pub fn decode_linux_tpm_event_log_header(buf: &[u8]) -> Option<LinuxTpmEventLogHeader> {
    if buf.len() < 9 {
        return None;
    }
    let version = buf[8];
    if version != EFI_TCG2_EVENT_LOG_FORMAT_TCG_2 {
        return None;
    }
    Some(LinuxTpmEventLogHeader {
        size: u32::from_le_bytes(buf[0..4].try_into().ok()?),
        final_events_preboot_size: u32::from_le_bytes(buf[4..8].try_into().ok()?),
        version,
    })
}

/// What the Spec ID event declares: how many digests every
/// `TCG_PCR_EVENT2` record must carry (PC Client §9.1), and whether
/// SHA-256 is among them.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SpecIdInfo {
    pub number_of_algorithms: u32,
    pub has_sha256: bool,
}

/// One parsed log record.
///
/// `sha256_digest` is the record's SHA-256-bank digest. It is
/// `None` only for the legacy Spec ID event (a `TCG_PCR_EVENT`
/// whose single digest is 20 zero bytes of SHA-1) — every
/// `TCG_PCR_EVENT2` record that is not `EV_NO_ACTION` must carry a
/// SHA-256 digest or parsing fails with [`Tcg2LogError::NoSha256Bank`]
/// (`EV_NO_ACTION` records are never extended, so a missing SHA-256
/// digest there is harmless and recorded as `None`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tcg2Event<'a> {
    pub pcr: u32,
    pub event_type: u32,
    pub sha256_digest: Option<[u8; 32]>,
    pub event: &'a [u8],
}

/// Why a TCG2 log (or final-events table) failed to parse.
/// Every variant fails closed: a malformed log replays nothing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tcg2LogError {
    /// Buffer ended mid-record (or an empty buffer).
    Short,
    /// First record is not the Spec ID event (wrong type, non-zero
    /// digest, bad signature, or an event body that does not add up).
    BadSpecIdSignature,
    /// Spec ID `specVersionMajor` is not 2.
    BadSpecIdVersion,
    /// The `linux_efi_tpm_eventlog` header's `version` is not 2, or
    /// a final-events table's `Version` is not 1: not a TCG2 log.
    UnsupportedLogVersion,
    /// `final_events_preboot_size` does not land on a final-table
    /// record boundary (or overruns the table): the dedup prefix is
    /// corrupt and the table cannot be replayed without risking a
    /// double- or half-replayed event.
    BadPrebootSize,
    /// Spec ID declares no SHA-256 bank, or a SHA-256 bank whose
    /// digest size is not 32.
    NoSha256Bank,
    /// A record's digest count does not match the Spec ID event's
    /// `numberOfAlgorithms` (PC Client §9.1), is zero, or names an
    /// algorithm this decoder cannot size.
    BadDigestCount,
    /// A record names a PCR above [`MAX_PCR_INDEX`].
    BadPcrIndex,
    /// An event's `eventSize` exceeds [`MAX_TCG2_EVENT_SIZE`].
    EventTooLarge,
    /// The Spec ID event declares more than
    /// [`MAX_SPEC_ID_ALGORITHMS`] algorithms.
    TooManyAlgorithms,
    /// More than [`MAX_TCG2_LOG_EVENTS`] events in one log.
    TooManyEvents,
}

/// Fixed digest size for a TCG algorithm ID (TCG Algorithm
/// Registry). `None` for algorithms this decoder does not know —
/// their digests cannot be sized, so a record naming one cannot be
/// walked.
fn digest_size(alg: u16) -> Option<usize> {
    match alg {
        TPM_ALG_SHA1 => Some(20),
        TPM_ALG_SHA256 => Some(32),
        TPM_ALG_SHA384 => Some(48),
        TPM_ALG_SHA512 => Some(64),
        TPM_ALG_SM3_256 => Some(32),
        _ => None,
    }
}

/// The Spec ID event, decoded from the head of `buf`.
///
/// Layout (`TCG_PCR_EVENT`, then `TCG_EfiSpecIdEventStruct`):
///
/// ```text
///   0..4:   pcrIndex
///   4..8:   eventType            (must be EV_NO_ACTION)
///   8..28:  digest[20]           (must be all zero)
///   28..32: eventSize
///   32..:   event:
///     0..16:  signature          ("Spec ID Event03")
///     16..20: platformClass
///     20:     specVersionMinor
///     21:     specVersionMajor   (must be 2)
///     22:     specErrata
///     23:     uintnSize
///     24..28: numberOfAlgorithms (must be >= 1)
///     28..:   digestSizes[numberOfAlgorithms] { algId u16, digestSize u16 }
///     ...:    vendorInfoSize u8, vendorInfo[]
/// ```
///
/// Returns the Spec ID info, the record's PCR, the event bytes, and
/// the total bytes consumed (32 + `eventSize`).
fn parse_spec_id_event(buf: &[u8]) -> Result<(SpecIdInfo, u32, &[u8], usize), Tcg2LogError> {
    if buf.len() < 32 {
        return Err(Tcg2LogError::Short);
    }
    let pcr = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let event_type = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    if event_type != EV_NO_ACTION || buf[8..28].iter().any(|&b| b != 0) {
        return Err(Tcg2LogError::BadSpecIdSignature);
    }
    let event_size = u32::from_le_bytes(buf[28..32].try_into().unwrap()) as usize;
    // event_size is capped at 1 MiB just above, so 32 + event_size
    // cannot overflow.
    if event_size > MAX_TCG2_EVENT_SIZE || 32 + event_size > buf.len() {
        return Err(Tcg2LogError::Short);
    }
    let event = &buf[32..32 + event_size];
    // Minimum Spec ID body: 16 (sig) + 4 (class) + 4 (versions) +
    // 4 (num_algs) + 1 (vendorInfoSize) = 29 bytes.
    if event.len() < 29 || &event[0..16] != SPEC_ID_SIGNATURE {
        return Err(Tcg2LogError::BadSpecIdSignature);
    }
    if event[21] != SPEC_ID_VERSION_MAJOR {
        return Err(Tcg2LogError::BadSpecIdVersion);
    }
    let number_of_algorithms = u32::from_le_bytes(event[24..28].try_into().unwrap());
    if number_of_algorithms == 0 {
        return Err(Tcg2LogError::BadDigestCount);
    }
    if number_of_algorithms > MAX_SPEC_ID_ALGORITHMS {
        return Err(Tcg2LogError::TooManyAlgorithms);
    }
    let n = number_of_algorithms as usize;
    // 28 + 4n (algorithm table) + 1 (vendorInfoSize) + vendorInfo.
    if event.len() < 29 + 4 * n {
        return Err(Tcg2LogError::BadSpecIdSignature);
    }
    let mut has_sha256 = false;
    for i in 0..n {
        let off = 28 + 4 * i;
        let alg = u16::from_le_bytes(event[off..off + 2].try_into().unwrap());
        let size = u16::from_le_bytes(event[off + 2..off + 4].try_into().unwrap());
        // Every declared algorithm must be one this decoder can size,
        // with the registry size — otherwise no record naming it can
        // be walked (its digest length is unknowable here).
        match digest_size(alg) {
            Some(want) if want == size as usize => {}
            _ => return Err(Tcg2LogError::BadDigestCount),
        }
        if alg == TPM_ALG_SHA256 {
            if size != 32 {
                return Err(Tcg2LogError::NoSha256Bank);
            }
            has_sha256 = true;
        }
    }
    if !has_sha256 {
        return Err(Tcg2LogError::NoSha256Bank);
    }
    let vendor_info_size = event[28 + 4 * n] as usize;
    if event.len() != 29 + 4 * n + vendor_info_size {
        return Err(Tcg2LogError::BadSpecIdSignature);
    }
    Ok((
        SpecIdInfo {
            number_of_algorithms,
            has_sha256,
        },
        pcr,
        event,
        32 + event_size,
    ))
}

/// True when `buf` opens with an all-zero 12-byte record header —
/// Linux's `__calc_tpm2_event_size` terminator: a zero-padded tail
/// ends the log rather than parsing as a (bogus) record.
fn is_zero_record_header(buf: &[u8]) -> bool {
    buf.len() >= 12 && buf[..12].iter().all(|&b| b == 0)
}

/// Parse one `TCG_PCR_EVENT2` record:
///
/// ```text
///   0..4:   pcrIndex
///   4..8:   eventType
///   8..12:  digestCount (must equal `expected_digest_count` when given)
///   12..:   digests[digestCount] { algId u16, digest[digestSize] }
///   ...:    eventSize u32, event[eventSize]
/// ```
///
/// Returns the record and the bytes consumed. `EV_NO_ACTION`
/// records may omit the SHA-256 digest (they are never extended);
/// any other record without one fails with
/// [`Tcg2LogError::NoSha256Bank`].
fn parse_event2_record(
    buf: &[u8],
    expected_digest_count: Option<u32>,
) -> Result<(Tcg2Event<'_>, usize), Tcg2LogError> {
    if buf.len() < 12 {
        return Err(Tcg2LogError::Short);
    }
    let pcr = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    if pcr > MAX_PCR_INDEX {
        return Err(Tcg2LogError::BadPcrIndex);
    }
    let event_type = u32::from_le_bytes(buf[4..8].try_into().unwrap());
    let digest_count = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    match expected_digest_count {
        Some(want) if digest_count != want => return Err(Tcg2LogError::BadDigestCount),
        None if digest_count == 0 => return Err(Tcg2LogError::BadDigestCount),
        _ => {}
    }
    let mut off = 12usize;
    let mut sha256_digest = None;
    for _ in 0..digest_count {
        if buf.len() < off + 2 {
            return Err(Tcg2LogError::Short);
        }
        let alg = u16::from_le_bytes(buf[off..off + 2].try_into().unwrap());
        let size = digest_size(alg).ok_or(Tcg2LogError::BadDigestCount)?;
        off += 2;
        if buf.len() < off + size {
            return Err(Tcg2LogError::Short);
        }
        if alg == TPM_ALG_SHA256 {
            let mut d = [0u8; 32];
            d.copy_from_slice(&buf[off..off + 32]);
            sha256_digest = Some(d);
        }
        off += size;
    }
    if sha256_digest.is_none() && event_type != EV_NO_ACTION {
        return Err(Tcg2LogError::NoSha256Bank);
    }
    if buf.len() < off + 4 {
        return Err(Tcg2LogError::Short);
    }
    let event_size = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
    if event_size > MAX_TCG2_EVENT_SIZE {
        return Err(Tcg2LogError::EventTooLarge);
    }
    off += 4;
    if buf.len() < off + event_size {
        return Err(Tcg2LogError::Short);
    }
    let event = &buf[off..off + event_size];
    Ok((
        Tcg2Event {
            pcr,
            event_type,
            sha256_digest,
            event,
        },
        off + event_size,
    ))
}

/// Parse a whole TCG2 event log: the Spec ID event first, then
/// `TCG_PCR_EVENT2` records to the end of the buffer. Returns the
/// Spec ID info and every record, the Spec ID event first (it is
/// recorded, never extended — see [`EV_NO_ACTION`]).
///
/// An all-zero record header terminates the parse successfully
/// (zero-padded log tail, per Linux); any other trailing bytes
/// that do not form a complete record fail with
/// [`Tcg2LogError::Short`].
pub fn parse_tcg2_log(buf: &[u8]) -> Result<(SpecIdInfo, Vec<Tcg2Event<'_>>), Tcg2LogError> {
    let (info, pcr, event, mut off) = parse_spec_id_event(buf)?;
    let mut events = Vec::new();
    events.push(Tcg2Event {
        pcr,
        event_type: EV_NO_ACTION,
        sha256_digest: None,
        event,
    });
    while off < buf.len() {
        if is_zero_record_header(&buf[off..]) {
            break;
        }
        if events.len() >= MAX_TCG2_LOG_EVENTS {
            return Err(Tcg2LogError::TooManyEvents);
        }
        let (ev, n) =
            parse_event2_record(&buf[off..], Some(info.number_of_algorithms))?;
        events.push(ev);
        off += n;
    }
    Ok((info, events))
}

/// Parse exactly `number_of_events` `TCG_PCR_EVENT2` records from
/// the body of an `EFI_TCG2_FINAL_EVENTS_TABLE` (the 16-byte header
/// already consumed by the caller). The final table carries no Spec
/// ID event of its own: `expected_digest_count` is the main log's
/// `numberOfAlgorithms` when the main log was parsed (`Some`), and
/// `None` when only the final table is available (each record is
/// then only required to carry at least one digest, and a SHA-256
/// one unless it is `EV_NO_ACTION`).
///
/// `skip_prefix_bytes` is the main log's
/// `final_events_preboot_size` (Linux `tpm_read_log_efi`): the
/// table's leading bytes already present in the main log, skipped
/// whole-record by whole-record and never replayed twice. The
/// prefix must end exactly on a record boundary, else
/// [`Tcg2LogError::BadPrebootSize`].
pub fn parse_final_events(
    buf: &[u8],
    number_of_events: u64,
    expected_digest_count: Option<u32>,
    skip_prefix_bytes: usize,
) -> Result<Vec<Tcg2Event<'_>>, Tcg2LogError> {
    let mut events = Vec::new();
    let mut off = 0usize;
    let mut parsed: u64 = 0;
    let mut skipped_bytes = 0usize;
    while parsed < number_of_events {
        if parsed as usize >= MAX_TCG2_LOG_EVENTS {
            return Err(Tcg2LogError::TooManyEvents);
        }
        if off >= buf.len() {
            return Err(Tcg2LogError::Short);
        }
        let (ev, n) = parse_event2_record(&buf[off..], expected_digest_count)?;
        off += n;
        parsed += 1;
        if skipped_bytes < skip_prefix_bytes {
            if off > skip_prefix_bytes {
                return Err(Tcg2LogError::BadPrebootSize);
            }
            skipped_bytes = off;
            continue;
        }
        events.push(ev);
    }
    if skipped_bytes != skip_prefix_bytes {
        return Err(Tcg2LogError::BadPrebootSize);
    }
    Ok(events)
}
