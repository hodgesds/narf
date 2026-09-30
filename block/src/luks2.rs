//! Read-only LUKS2 metadata parsing and passphrase-based keyslot unlock.
//!
//! Metadata is treated as hostile: both redundant headers are independently
//! bounds-checked and authenticated, JSON-controlled allocations and KDF work
//! are capped, and unknown mandatory requirements prevent activation. The
//! implementation intentionally never repairs or mutates metadata.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use argon2::{Algorithm, Argon2, Block, Params, Version};
use narf_capabilities::{Cap, Grant};
use narf_crypto::sha256::Sha256;
use narf_crypto::sha512::Sha512;
use narf_crypto::{
    aes_xts_128_decrypt, aes_xts_256_decrypt_with_sector_size, AesXts128, AesXts256, CryptoError,
    Key,
};
use serde::de::{Error as DeError, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use zeroize::Zeroizing;

use crate::encrypted::VkBytes;
use crate::luks1::{af_merge, constant_time_eq, pbkdf2, Luks1Hash};
use crate::registry::{BlockDeviceSync, BlockIoError};

const MAGIC_PRIMARY: &[u8; 6] = b"LUKS\xba\xbe";
const MAGIC_SECONDARY: &[u8; 6] = b"SKUL\xba\xbe";
const BINARY_HEADER_BYTES: usize = 4096;
const CHECKSUM_OFFSET: usize = 448;
const CHECKSUM_BYTES: usize = 64;
const MAX_KEYSLOT_BYTES: usize = 16 * 1024 * 1024;
const SECONDARY_OFFSETS: [u64; 9] = [
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
    1024 * 1024,
    2048 * 1024,
    4096 * 1024,
];

/// Which authenticated metadata copy supplied the selected LUKS2 view.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Luks2HeaderCopy {
    /// Header at byte offset zero.
    Primary,
    /// Redundant header at byte offset `hdr_size`.
    Secondary,
}

/// Validated LUKS2 binary header and activation-relevant JSON metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Luks2Header {
    /// Metadata sequence number. The newest valid copy wins.
    pub sequence_id: u64,
    /// Size of one binary-header plus JSON metadata area.
    pub header_size: u64,
    /// Canonical volume UUID.
    pub uuid: String,
    /// Optional user-visible label.
    pub label: String,
    /// Optional subsystem owner string.
    pub subsystem: String,
    /// Copy selected after checksum and JSON validation.
    pub source: Luks2HeaderCopy,
    metadata: Metadata,
}

/// Bounded resource policy for a LUKS2 unlock attempt.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Luks2UnlockPolicy {
    /// Maximum PBKDF2 iterations for one keyslot or volume-key digest.
    pub max_pbkdf2_iterations: u32,
    /// Maximum accumulated PBKDF2 iterations across attempted keyslots.
    pub max_total_pbkdf2_iterations: u64,
    /// Maximum Argon2 memory parameter, in KiB.
    pub max_argon2_memory_kib: u32,
    /// Maximum Argon2 passes.
    pub max_argon2_time: u32,
    /// Maximum Argon2 lane count.
    pub max_argon2_cpus: u32,
    /// Maximum aggregate `memory_kib * time` across attempted Argon2 slots.
    pub max_total_argon2_kib_passes: u64,
    /// Maximum keyslots tried by an automatic unlock.
    pub max_keyslot_attempts: u32,
}

impl Default for Luks2UnlockPolicy {
    fn default() -> Self {
        Self {
            max_pbkdf2_iterations: 10_000_000,
            max_total_pbkdf2_iterations: 25_000_000,
            max_argon2_memory_kib: 1024 * 1024,
            max_argon2_time: 16,
            max_argon2_cpus: 64,
            max_total_argon2_kib_passes: 8 * 1024 * 1024,
            max_keyslot_attempts: 8,
        }
    }
}

/// Failures while loading or unlocking a LUKS2 volume.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Luks2Error {
    /// Underlying block I/O failed.
    Io(BlockIoError),
    /// Logical block geometry cannot address LUKS2 metadata exactly.
    UnsupportedLogicalBlockSize,
    /// No authenticated primary or secondary LUKS2 header was found.
    NoValidHeader,
    /// The binary header, JSON padding, or mandatory JSON shape is invalid.
    InvalidMetadata,
    /// The header names an unsupported checksum, cipher, KDF, hash, or object.
    UnsupportedFeature,
    /// A mandatory `requirements` feature prevents safe activation.
    UnsupportedRequirement,
    /// An offset, length, or allocation falls outside its permitted region.
    OutOfBounds,
    /// A metadata-controlled CPU or memory cost exceeds policy.
    WorkFactorTooLarge,
    /// No automatic-priority LUKS2 keyslot can be tried.
    NoActiveKeyslot,
    /// No eligible keyslot authenticated with the supplied passphrase.
    WrongPassphrase,
    /// Cryptographic primitive failed.
    Crypto(CryptoError),
    /// Argon2 parameters or execution failed.
    Argon2,
    /// Memory reservation for metadata-controlled work failed.
    OutOfMemory,
}

impl From<BlockIoError> for Luks2Error {
    fn from(value: BlockIoError) -> Self {
        Self::Io(value)
    }
}

impl From<CryptoError> for Luks2Error {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct Metadata {
    keyslots: BTreeMap<String, Keyslot>,
    tokens: BTreeMap<String, serde_json::Value>,
    segments: BTreeMap<String, Segment>,
    digests: BTreeMap<String, Digest>,
    config: Config,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct Keyslot {
    #[serde(rename = "type")]
    kind: String,
    key_size: u32,
    #[serde(default = "normal_priority")]
    priority: u32,
    area: Area,
    kdf: Kdf,
    af: Af,
}

const fn normal_priority() -> u32 {
    1
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct Area {
    #[serde(rename = "type")]
    kind: String,
    encryption: String,
    key_size: u32,
    offset: String,
    size: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct Kdf {
    #[serde(rename = "type")]
    kind: String,
    salt: String,
    #[serde(default)]
    hash: Option<String>,
    #[serde(default)]
    iterations: Option<u32>,
    #[serde(default)]
    time: Option<u32>,
    #[serde(default)]
    memory: Option<u32>,
    #[serde(default)]
    cpus: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct Af {
    #[serde(rename = "type")]
    kind: String,
    stripes: u32,
    hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct Segment {
    #[serde(rename = "type")]
    kind: String,
    offset: String,
    size: String,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    iv_tweak: Option<String>,
    #[serde(default)]
    encryption: Option<String>,
    #[serde(default)]
    sector_size: Option<u32>,
    #[serde(default)]
    integrity: Option<serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct Digest {
    #[serde(rename = "type")]
    kind: String,
    keyslots: Vec<String>,
    segments: Vec<String>,
    hash: String,
    iterations: u32,
    salt: String,
    digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
struct Config {
    json_size: String,
    keyslots_size: String,
    #[serde(default)]
    flags: Vec<String>,
    #[serde(default)]
    requirements: Vec<String>,
}

struct Candidate {
    header: Luks2Header,
    offset: u64,
}

struct StrictJsonValue(serde_json::Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJsonValue;

    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        let number = serde_json::Number::from_f64(value)
            .ok_or_else(|| E::custom("non-finite JSON number"))?;
        Ok(StrictJsonValue(serde_json::Value::Number(number)))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: DeError,
    {
        self.visit_string(value.into())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJsonValue(serde_json::Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(StrictJsonValue(serde_json::Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = serde_json::Map::new();
        while let Some((key, value)) = object.next_entry::<String, StrictJsonValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(A::Error::custom("duplicate JSON object key"));
            }
        }
        Ok(StrictJsonValue(serde_json::Value::Object(values)))
    }
}

/// Mapping parameters and authenticated key material returned to the adapter.
pub(crate) struct UnlockedLuks2 {
    pub(crate) header: Luks2Header,
    pub(crate) volume_key: VkBytes,
    pub(crate) data_offset_bytes: u64,
    pub(crate) data_size_bytes: Option<u64>,
    pub(crate) iv_tweak: u64,
    pub(crate) sector_size: usize,
}

/// Probe a LUKS2 UUID from the fixed binary header without activating it.
pub(crate) fn probe_uuid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 208 || &bytes[..6] != MAGIC_PRIMARY || be_u16(bytes, 6)? != 2 {
        return None;
    }
    let uuid = fixed_cstr(bytes, 168, 40)?;
    if valid_uuid(uuid) {
        Some(uuid.to_string())
    } else {
        None
    }
}

/// Load, authenticate, and select the newest valid LUKS2 metadata copy.
pub fn load_header(inner: &dyn BlockDeviceSync) -> Result<Luks2Header, Luks2Error> {
    validate_geometry(inner)?;
    let mut best: Option<Candidate> = None;
    for offset in core::iter::once(0).chain(SECONDARY_OFFSETS) {
        let candidate = match load_candidate(inner, offset) {
            Ok(candidate) => candidate,
            Err(_) => continue,
        };
        let replace = best.as_ref().is_none_or(|current| {
            candidate.header.sequence_id > current.header.sequence_id
                || (candidate.header.sequence_id == current.header.sequence_id
                    && candidate.offset == 0
                    && current.offset != 0)
        });
        if replace {
            best = Some(candidate);
        }
    }
    best.map(|candidate| candidate.header)
        .ok_or(Luks2Error::NoValidHeader)
}

pub(crate) fn unlock(
    inner: Arc<dyn BlockDeviceSync>,
    passphrase: &[u8],
    policy: Luks2UnlockPolicy,
) -> Result<UnlockedLuks2, Luks2Error> {
    let header = load_header(inner.as_ref())?;
    let segment_id = normal_segment_id(&header.metadata)?;
    let segment = header
        .metadata
        .segments
        .get(segment_id)
        .ok_or(Luks2Error::InvalidMetadata)?;
    let mapping = validate_segment(inner.as_ref(), segment)?;

    let mut slots: Vec<(&String, &Keyslot)> = header
        .metadata
        .keyslots
        .iter()
        .filter(|(_, slot)| slot.kind == "luks2" && slot.priority != 0)
        .collect();
    slots.sort_by_key(|(id, slot)| (core::cmp::Reverse(slot.priority), numeric_name(id).ok()));
    if slots.is_empty() {
        return Err(Luks2Error::NoActiveKeyslot);
    }

    let mut pbkdf2_work = 0u64;
    let mut argon2_work = 0u64;
    let mut attempts = 0u32;
    for (slot_id, slot) in slots {
        attempts = attempts
            .checked_add(1)
            .ok_or(Luks2Error::WorkFactorTooLarge)?;
        if attempts > policy.max_keyslot_attempts {
            return Err(Luks2Error::WorkFactorTooLarge);
        }
        let digest = digest_for_slot(&header.metadata, slot_id, segment_id)?;
        let required_pbkdf2 =
            u64::from(digest.iterations) + slot.kdf.iterations.map(u64::from).unwrap_or_default();
        pbkdf2_work = pbkdf2_work
            .checked_add(required_pbkdf2)
            .ok_or(Luks2Error::WorkFactorTooLarge)?;
        if pbkdf2_work > policy.max_total_pbkdf2_iterations {
            return Err(Luks2Error::WorkFactorTooLarge);
        }
        if matches!(slot.kdf.kind.as_str(), "argon2i" | "argon2id") {
            let slot_work = u64::from(slot.kdf.memory.unwrap_or(0))
                .checked_mul(u64::from(slot.kdf.time.unwrap_or(0)))
                .ok_or(Luks2Error::WorkFactorTooLarge)?;
            argon2_work = argon2_work
                .checked_add(slot_work)
                .ok_or(Luks2Error::WorkFactorTooLarge)?;
            if argon2_work > policy.max_total_argon2_kib_passes {
                return Err(Luks2Error::WorkFactorTooLarge);
            }
        }

        match unlock_slot(inner.as_ref(), passphrase, slot, digest, policy) {
            Ok(volume_key) => {
                return Ok(UnlockedLuks2 {
                    header,
                    volume_key,
                    data_offset_bytes: mapping.0,
                    data_size_bytes: mapping.1,
                    iv_tweak: mapping.2,
                    sector_size: mapping.3,
                });
            }
            Err(Luks2Error::WrongPassphrase) => {}
            Err(error) => return Err(error),
        }
    }
    Err(Luks2Error::WrongPassphrase)
}

fn validate_geometry(inner: &dyn BlockDeviceSync) -> Result<(), Luks2Error> {
    let block = inner.lba_size() as usize;
    if !(512..=BINARY_HEADER_BYTES).contains(&block) || BINARY_HEADER_BYTES % block != 0 {
        return Err(Luks2Error::UnsupportedLogicalBlockSize);
    }
    Ok(())
}

fn load_candidate(inner: &dyn BlockDeviceSync, offset: u64) -> Result<Candidate, Luks2Error> {
    let prefix = read_aligned(inner, offset, BINARY_HEADER_BYTES)?;
    let expected_magic = if offset == 0 {
        MAGIC_PRIMARY
    } else {
        MAGIC_SECONDARY
    };
    if &prefix[..6] != expected_magic || be_u16(&prefix, 6) != Some(2) {
        return Err(Luks2Error::InvalidMetadata);
    }
    let header_size = be_u64(&prefix, 8).ok_or(Luks2Error::InvalidMetadata)?;
    if !SECONDARY_OFFSETS.contains(&header_size) || (offset != 0 && offset != header_size) {
        return Err(Luks2Error::InvalidMetadata);
    }
    if be_u64(&prefix, 256) != Some(offset) {
        return Err(Luks2Error::InvalidMetadata);
    }
    let serialized = read_aligned(
        inner,
        offset,
        usize::try_from(header_size).map_err(|_| Luks2Error::OutOfBounds)?,
    )?;
    validate_binary_padding(&serialized)?;

    let checksum_alg = fixed_cstr(&serialized, 72, 32).ok_or(Luks2Error::InvalidMetadata)?;
    validate_checksum(&serialized, checksum_alg)?;
    let json = json_bytes(&serialized)?;
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    let value =
        StrictJsonValue::deserialize(&mut deserializer).map_err(|_| Luks2Error::InvalidMetadata)?;
    deserializer
        .end()
        .map_err(|_| Luks2Error::InvalidMetadata)?;
    let metadata = Metadata::deserialize(value.0).map_err(|_| Luks2Error::InvalidMetadata)?;
    validate_metadata(&metadata, header_size, inner)?;

    let uuid = fixed_cstr(&serialized, 168, 40).ok_or(Luks2Error::InvalidMetadata)?;
    if !valid_uuid(uuid) {
        return Err(Luks2Error::InvalidMetadata);
    }
    Ok(Candidate {
        header: Luks2Header {
            sequence_id: be_u64(&serialized, 16).ok_or(Luks2Error::InvalidMetadata)?,
            header_size,
            uuid: uuid.to_string(),
            label: fixed_cstr(&serialized, 24, 48)
                .ok_or(Luks2Error::InvalidMetadata)?
                .to_string(),
            subsystem: fixed_cstr(&serialized, 208, 48)
                .ok_or(Luks2Error::InvalidMetadata)?
                .to_string(),
            source: if offset == 0 {
                Luks2HeaderCopy::Primary
            } else {
                Luks2HeaderCopy::Secondary
            },
            metadata,
        },
        offset,
    })
}

fn validate_binary_padding(bytes: &[u8]) -> Result<(), Luks2Error> {
    if bytes.len() < BINARY_HEADER_BYTES
        || bytes[264..448].iter().any(|&byte| byte != 0)
        || bytes[512..BINARY_HEADER_BYTES]
            .iter()
            .any(|&byte| byte != 0)
    {
        return Err(Luks2Error::InvalidMetadata);
    }
    Ok(())
}

fn validate_checksum(bytes: &[u8], algorithm: &str) -> Result<(), Luks2Error> {
    let mut input = bytes.to_vec();
    input[CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_BYTES].fill(0);
    let expected = &bytes[CHECKSUM_OFFSET..CHECKSUM_OFFSET + CHECKSUM_BYTES];
    let (digest, digest_len) = match algorithm {
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(&input);
            let digest = hasher.finalize();
            let mut padded = [0u8; CHECKSUM_BYTES];
            padded[..digest.len()].copy_from_slice(&digest);
            (padded, digest.len())
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            hasher.update(&input);
            let digest = hasher.finalize();
            (digest, digest.len())
        }
        _ => return Err(Luks2Error::UnsupportedFeature),
    };
    if !constant_time_eq(&digest[..digest_len], &expected[..digest_len])
        || expected[digest_len..].iter().any(|&byte| byte != 0)
    {
        return Err(Luks2Error::InvalidMetadata);
    }
    Ok(())
}

fn json_bytes(bytes: &[u8]) -> Result<&[u8], Luks2Error> {
    let area = &bytes[BINARY_HEADER_BYTES..];
    let end = area
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(Luks2Error::InvalidMetadata)?;
    if end == 0 || area[end..].iter().any(|&byte| byte != 0) {
        return Err(Luks2Error::InvalidMetadata);
    }
    Ok(&area[..end])
}

fn validate_metadata(
    metadata: &Metadata,
    header_size: u64,
    inner: &dyn BlockDeviceSync,
) -> Result<(), Luks2Error> {
    for name in metadata
        .keyslots
        .keys()
        .chain(metadata.tokens.keys())
        .chain(metadata.segments.keys())
        .chain(metadata.digests.keys())
    {
        numeric_name(name)?;
    }
    let json_size = decimal_u64(&metadata.config.json_size)?;
    let keyslots_size = decimal_u64(&metadata.config.keyslots_size)?;
    if json_size != header_size - BINARY_HEADER_BYTES as u64
        || keyslots_size == 0
        || keyslots_size % BINARY_HEADER_BYTES as u64 != 0
    {
        return Err(Luks2Error::InvalidMetadata);
    }
    if !metadata.config.requirements.is_empty() {
        return Err(Luks2Error::UnsupportedRequirement);
    }
    let keyslots_start = header_size.checked_mul(2).ok_or(Luks2Error::OutOfBounds)?;
    let keyslots_end = keyslots_start
        .checked_add(keyslots_size)
        .ok_or(Luks2Error::OutOfBounds)?;
    if keyslots_end > device_bytes(inner)? {
        return Err(Luks2Error::OutOfBounds);
    }

    for slot in metadata.keyslots.values() {
        if slot.kind != "luks2" {
            continue;
        }
        if !matches!(slot.priority, 0..=2)
            || !matches!(slot.key_size, 32 | 64)
            || slot.area.kind != "raw"
            || slot.area.encryption != "aes-xts-plain64"
            || slot.area.key_size != slot.key_size
            || slot.af.kind != "luks1"
            || slot.af.stripes != 4000
        {
            return Err(Luks2Error::UnsupportedFeature);
        }
        parse_hash(&slot.af.hash)?;
        validate_kdf_shape(&slot.kdf)?;
        let offset = decimal_u64(&slot.area.offset)?;
        let size = decimal_u64(&slot.area.size)?;
        let material_bytes = u64::from(slot.key_size)
            .checked_mul(u64::from(slot.af.stripes))
            .ok_or(Luks2Error::OutOfBounds)?;
        let end = offset.checked_add(size).ok_or(Luks2Error::OutOfBounds)?;
        if offset < keyslots_start
            || end > keyslots_end
            || offset % 4096 != 0
            || size % 4096 != 0
            || material_bytes > size
            || size > MAX_KEYSLOT_BYTES as u64
        {
            return Err(Luks2Error::OutOfBounds);
        }
    }

    for digest in metadata.digests.values() {
        if digest.kind != "pbkdf2" || digest.iterations == 0 {
            return Err(Luks2Error::UnsupportedFeature);
        }
        parse_hash(&digest.hash)?;
        let hash = parse_hash(&digest.hash)?;
        if decode_base64(&digest.salt)?.is_empty()
            || decode_base64(&digest.digest)?.len() != hash.digest_len()
        {
            return Err(Luks2Error::InvalidMetadata);
        }
        for slot in &digest.keyslots {
            if !metadata.keyslots.contains_key(slot) {
                return Err(Luks2Error::InvalidMetadata);
            }
        }
        for segment in &digest.segments {
            if !metadata.segments.contains_key(segment) {
                return Err(Luks2Error::InvalidMetadata);
            }
        }
    }
    for (slot_id, slot) in &metadata.keyslots {
        if slot.kind == "luks2"
            && metadata
                .digests
                .values()
                .filter(|digest| digest.keyslots.iter().any(|id| id == slot_id))
                .count()
                != 1
        {
            return Err(Luks2Error::InvalidMetadata);
        }
    }
    normal_segment_id(metadata)?;
    Ok(())
}

fn validate_kdf_shape(kdf: &Kdf) -> Result<(), Luks2Error> {
    if decode_base64(&kdf.salt)?.is_empty() {
        return Err(Luks2Error::InvalidMetadata);
    }
    match kdf.kind.as_str() {
        "pbkdf2" => {
            parse_hash(kdf.hash.as_deref().ok_or(Luks2Error::InvalidMetadata)?)?;
            if kdf.iterations.unwrap_or(0) == 0 {
                return Err(Luks2Error::InvalidMetadata);
            }
        }
        "argon2i" | "argon2id" => {
            if kdf.time.unwrap_or(0) == 0
                || kdf.memory.unwrap_or(0) == 0
                || kdf.cpus.unwrap_or(0) == 0
            {
                return Err(Luks2Error::InvalidMetadata);
            }
        }
        _ => return Err(Luks2Error::UnsupportedFeature),
    }
    Ok(())
}

fn normal_segment_id(metadata: &Metadata) -> Result<&String, Luks2Error> {
    if metadata.segments.len() != 1 {
        return Err(Luks2Error::UnsupportedFeature);
    }
    let mut normal = metadata.segments.iter().filter(|(_, segment)| {
        segment.kind == "crypt"
            && !segment
                .flags
                .iter()
                .any(|flag| flag == "in-reencryption" || flag.starts_with("backup-"))
    });
    let (id, segment) = normal.next().ok_or(Luks2Error::UnsupportedFeature)?;
    if normal.next().is_some()
        || segment.integrity.is_some()
        || segment.encryption.as_deref() != Some("aes-xts-plain64")
        || !matches!(segment.sector_size, Some(512 | 1024 | 2048 | 4096))
    {
        return Err(Luks2Error::UnsupportedFeature);
    }
    Ok(id)
}

fn validate_segment(
    inner: &dyn BlockDeviceSync,
    segment: &Segment,
) -> Result<(u64, Option<u64>, u64, usize), Luks2Error> {
    let offset = decimal_u64(&segment.offset)?;
    let size = if segment.size == "dynamic" {
        None
    } else {
        Some(decimal_u64(&segment.size)?)
    };
    let iv_tweak = decimal_u64(
        segment
            .iv_tweak
            .as_deref()
            .ok_or(Luks2Error::InvalidMetadata)?,
    )?;
    let sector_size = segment.sector_size.ok_or(Luks2Error::InvalidMetadata)? as usize;
    let sector_scale = sector_size as u64 / 512;
    let block_size = inner.lba_size() as u64;
    let device_size = device_bytes(inner)?;
    if (block_size % sector_size as u64 != 0 && sector_size as u64 % block_size != 0)
        || offset % block_size != 0
        || offset % sector_size as u64 != 0
        || iv_tweak % sector_scale != 0
        || offset >= device_size
        || size.is_some_and(|length| {
            length == 0
                || length % block_size != 0
                || length % sector_size as u64 != 0
                || offset
                    .checked_add(length)
                    .is_none_or(|end| end > device_size)
        })
    {
        return Err(Luks2Error::OutOfBounds);
    }
    Ok((offset, size, iv_tweak, sector_size))
}

fn digest_for_slot<'a>(
    metadata: &'a Metadata,
    slot_id: &str,
    segment_id: &str,
) -> Result<&'a Digest, Luks2Error> {
    let mut matches = metadata.digests.values().filter(|digest| {
        digest.keyslots.iter().any(|id| id == slot_id)
            && digest.segments.iter().any(|id| id == segment_id)
    });
    let digest = matches.next().ok_or(Luks2Error::InvalidMetadata)?;
    if matches.next().is_some() {
        return Err(Luks2Error::InvalidMetadata);
    }
    Ok(digest)
}

fn unlock_slot(
    inner: &dyn BlockDeviceSync,
    passphrase: &[u8],
    slot: &Keyslot,
    digest: &Digest,
    policy: Luks2UnlockPolicy,
) -> Result<VkBytes, Luks2Error> {
    let key_bytes = slot.key_size as usize;
    let area_offset = decimal_u64(&slot.area.offset)?;
    let area_size = decimal_u64(&slot.area.size)?;
    let material_bytes = key_bytes
        .checked_mul(slot.af.stripes as usize)
        .ok_or(Luks2Error::OutOfBounds)?;
    if area_size > MAX_KEYSLOT_BYTES as u64 || material_bytes > area_size as usize {
        return Err(Luks2Error::OutOfBounds);
    }
    let salt = decode_base64(&slot.kdf.salt)?;
    let derived = derive_key(passphrase, &salt, key_bytes, &slot.kdf, policy)?;
    let mut material = Zeroizing::new(read_aligned(inner, area_offset, area_size as usize)?);
    decrypt_keyslot(&derived, &mut material)?;
    let volume_key = af_merge(
        parse_hash(&slot.af.hash)?,
        &material[..material_bytes],
        key_bytes,
        slot.af.stripes as usize,
    )
    .map_err(|_| Luks2Error::InvalidMetadata)?;

    if digest.iterations > policy.max_pbkdf2_iterations {
        return Err(Luks2Error::WorkFactorTooLarge);
    }
    let digest_salt = decode_base64(&digest.salt)?;
    let expected = decode_base64(&digest.digest)?;
    let actual = pbkdf2(
        parse_hash(&digest.hash)?,
        &volume_key,
        &digest_salt,
        digest.iterations,
        expected.len(),
    );
    if !constant_time_eq(&actual, &expected) {
        return Err(Luks2Error::WrongPassphrase);
    }
    VkBytes::from_slice(&volume_key).map_err(|_| Luks2Error::InvalidMetadata)
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    output_len: usize,
    kdf: &Kdf,
    policy: Luks2UnlockPolicy,
) -> Result<Zeroizing<Vec<u8>>, Luks2Error> {
    match kdf.kind.as_str() {
        "pbkdf2" => {
            let iterations = kdf.iterations.ok_or(Luks2Error::InvalidMetadata)?;
            if iterations == 0 || iterations > policy.max_pbkdf2_iterations {
                return Err(Luks2Error::WorkFactorTooLarge);
            }
            Ok(pbkdf2(
                parse_hash(kdf.hash.as_deref().ok_or(Luks2Error::InvalidMetadata)?)?,
                passphrase,
                salt,
                iterations,
                output_len,
            ))
        }
        "argon2i" | "argon2id" => {
            let time = kdf.time.ok_or(Luks2Error::InvalidMetadata)?;
            let memory = kdf.memory.ok_or(Luks2Error::InvalidMetadata)?;
            let cpus = kdf.cpus.ok_or(Luks2Error::InvalidMetadata)?;
            if memory > policy.max_argon2_memory_kib
                || time > policy.max_argon2_time
                || cpus > policy.max_argon2_cpus
            {
                return Err(Luks2Error::WorkFactorTooLarge);
            }
            let params = Params::new(memory, time, cpus, Some(output_len))
                .map_err(|_| Luks2Error::Argon2)?;
            let algorithm = if kdf.kind == "argon2i" {
                Algorithm::Argon2i
            } else {
                Algorithm::Argon2id
            };
            let blocks = params.block_count();
            let mut memory_blocks = Vec::new();
            memory_blocks
                .try_reserve_exact(blocks)
                .map_err(|_| Luks2Error::OutOfMemory)?;
            memory_blocks.resize(blocks, Block::default());
            let mut memory_blocks = Zeroizing::new(memory_blocks);
            let mut output = Zeroizing::new(alloc::vec![0u8; output_len]);
            Argon2::new(algorithm, Version::V0x13, params)
                .hash_password_into_with_memory(
                    passphrase,
                    salt,
                    &mut output,
                    memory_blocks.as_mut_slice(),
                )
                .map_err(|_| Luks2Error::Argon2)?;
            Ok(output)
        }
        _ => Err(Luks2Error::UnsupportedFeature),
    }
}

fn decrypt_keyslot(key: &[u8], material: &mut [u8]) -> Result<(), Luks2Error> {
    match key.len() {
        32 => {
            let key: &[u8; 32] = key.try_into().map_err(|_| Luks2Error::InvalidMetadata)?;
            aes_xts_128_decrypt(
                &Cap::<Key<AesXts128>, Grant>::bootstrap(),
                key,
                0,
                512,
                material,
            )?;
        }
        64 => {
            let key: &[u8; 64] = key.try_into().map_err(|_| Luks2Error::InvalidMetadata)?;
            aes_xts_256_decrypt_with_sector_size(
                &Cap::<Key<AesXts256>, Grant>::bootstrap(),
                key,
                0,
                512,
                material,
            )?;
        }
        _ => return Err(Luks2Error::UnsupportedFeature),
    }
    Ok(())
}

fn parse_hash(name: &str) -> Result<Luks1Hash, Luks2Error> {
    match name {
        "sha1" => Ok(Luks1Hash::Sha1),
        "sha256" => Ok(Luks1Hash::Sha256),
        "sha512" => Ok(Luks1Hash::Sha512),
        _ => Err(Luks2Error::UnsupportedFeature),
    }
}

fn read_aligned(
    inner: &dyn BlockDeviceSync,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, Luks2Error> {
    let block = inner.lba_size() as usize;
    if offset % block as u64 != 0 || length == 0 || length % block != 0 {
        return Err(Luks2Error::OutOfBounds);
    }
    let blocks = length / block;
    if blocks > u16::MAX as usize
        || offset
            .checked_add(length as u64)
            .is_none_or(|end| end > device_bytes(inner).unwrap_or(0))
    {
        return Err(Luks2Error::OutOfBounds);
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| Luks2Error::OutOfMemory)?;
    output.resize(length, 0);
    inner.read(offset / block as u64, blocks as u16, &mut output)?;
    Ok(output)
}

fn device_bytes(inner: &dyn BlockDeviceSync) -> Result<u64, Luks2Error> {
    inner
        .capacity()
        .checked_mul(u64::from(inner.lba_size()))
        .ok_or(Luks2Error::OutOfBounds)
}

fn decimal_u64(value: &str) -> Result<u64, Luks2Error> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || value.bytes().any(|byte| !byte.is_ascii_digit())
    {
        return Err(Luks2Error::InvalidMetadata);
    }
    value.parse().map_err(|_| Luks2Error::InvalidMetadata)
}

fn numeric_name(value: &str) -> Result<u32, Luks2Error> {
    let number = decimal_u64(value)?;
    let number = u32::try_from(number).map_err(|_| Luks2Error::InvalidMetadata)?;
    if number.to_string() != value {
        return Err(Luks2Error::InvalidMetadata);
    }
    Ok(number)
}

fn fixed_cstr(bytes: &[u8], offset: usize, length: usize) -> Option<&str> {
    let field = bytes.get(offset..offset.checked_add(length)?)?;
    let end = field.iter().position(|&byte| byte == 0)?;
    if field[end..].iter().any(|&byte| byte != 0) {
        return None;
    }
    core::str::from_utf8(&field[..end]).ok()
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn be_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn be_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_be_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

fn decode_base64(input: &str) -> Result<Zeroizing<Vec<u8>>, Luks2Error> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 {
        return Err(Luks2Error::InvalidMetadata);
    }
    let padding = usize::from(bytes.ends_with(b"=")) + usize::from(bytes.ends_with(b"=="));
    let output_len = bytes.len() / 4 * 3 - padding;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(output_len)
        .map_err(|_| Luks2Error::OutOfMemory)?;

    for (chunk_index, chunk) in bytes.chunks_exact(4).enumerate() {
        let last = chunk_index + 1 == bytes.len() / 4;
        if chunk[0] == b'='
            || chunk[1] == b'='
            || (!last && chunk[3] == b'=')
            || (chunk[2] == b'=' && chunk[3] != b'=')
        {
            return Err(Luks2Error::InvalidMetadata);
        }
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if chunk[2] == b'=' {
            0
        } else {
            base64_value(chunk[2])?
        };
        let d = if chunk[3] == b'=' {
            0
        } else {
            base64_value(chunk[3])?
        };
        if (chunk[2] == b'=' && b & 0x0f != 0) || (chunk[3] == b'=' && c & 0x03 != 0) {
            return Err(Luks2Error::InvalidMetadata);
        }
        output.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            output.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            output.push((c << 6) | d);
        }
    }
    if output.len() != output_len {
        return Err(Luks2Error::InvalidMetadata);
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, Luks2Error> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Luks2Error::InvalidMetadata),
    }
}

pub(crate) mod tests {
    use super::*;
    use alloc::format;
    use narf_crypto::aes_xts_128_encrypt;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    const HEADER_SIZE: usize = 16 * 1024;
    const KEYSLOT_OFFSET: usize = 32 * 1024;
    const KEYSLOT_SIZE: usize = 131_072;
    const DATA_OFFSET: usize = KEYSLOT_OFFSET + KEYSLOT_SIZE;

    struct ImageDevice {
        bytes: IrqSafeSpinLock<Vec<u8>>,
    }

    impl BlockDeviceSync for ImageDevice {
        fn lba_size(&self) -> u32 {
            512
        }

        fn capacity(&self) -> u64 {
            self.bytes.lock().len() as u64 / 512
        }

        fn read(&self, lba: u64, blocks: u16, out: &mut [u8]) -> Result<(), BlockIoError> {
            let offset = lba as usize * 512;
            let length = usize::from(blocks) * 512;
            let bytes = self.bytes.lock();
            if offset
                .checked_add(length)
                .is_none_or(|end| end > bytes.len())
                || out.len() < length
            {
                return Err(BlockIoError::OutOfRange);
            }
            out[..length].copy_from_slice(&bytes[offset..offset + length]);
            Ok(())
        }

        fn write(&self, lba: u64, blocks: u16, data: &[u8]) -> Result<(), BlockIoError> {
            let offset = lba as usize * 512;
            let length = usize::from(blocks) * 512;
            let mut bytes = self.bytes.lock();
            if offset
                .checked_add(length)
                .is_none_or(|end| end > bytes.len())
                || data.len() < length
            {
                return Err(BlockIoError::OutOfRange);
            }
            bytes[offset..offset + length].copy_from_slice(&data[..length]);
            Ok(())
        }
    }

    fn encode_base64(input: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::new();
        for chunk in input.chunks(3) {
            let a = chunk[0];
            let b = chunk.get(1).copied().unwrap_or(0);
            let c = chunk.get(2).copied().unwrap_or(0);
            output.push(TABLE[(a >> 2) as usize] as char);
            output.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
            if chunk.len() > 1 {
                output.push(TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char);
            } else {
                output.push('=');
            }
            if chunk.len() > 2 {
                output.push(TABLE[(c & 0x3f) as usize] as char);
            } else {
                output.push('=');
            }
        }
        output
    }

    fn serialized_header(magic: &[u8; 6], offset: u64, sequence: u64, json: &str) -> Vec<u8> {
        let mut header = alloc::vec![0u8; HEADER_SIZE];
        header[..6].copy_from_slice(magic);
        header[6..8].copy_from_slice(&2u16.to_be_bytes());
        header[8..16].copy_from_slice(&(HEADER_SIZE as u64).to_be_bytes());
        header[16..24].copy_from_slice(&sequence.to_be_bytes());
        header[24..33].copy_from_slice(b"narf-test");
        header[72..78].copy_from_slice(b"sha256");
        header[104..168].fill(0x5a);
        header[168..204].copy_from_slice(b"01234567-89ab-cdef-0123-456789abcdef");
        header[256..264].copy_from_slice(&offset.to_be_bytes());
        header[BINARY_HEADER_BYTES..BINARY_HEADER_BYTES + json.len()]
            .copy_from_slice(json.as_bytes());

        let mut hasher = Sha256::new();
        hasher.update(&header);
        header[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 32].copy_from_slice(&hasher.finalize());
        header
    }

    fn luks2_fixture() -> (Arc<dyn BlockDeviceSync>, [u8; 4096]) {
        let passphrase = b"correct horse battery staple";
        let slot_salt = [0x22u8; 32];
        let digest_salt = [0x33u8; 32];
        let mut volume_key = [0u8; 32];
        for (index, byte) in volume_key.iter_mut().enumerate() {
            *byte = index as u8;
        }

        let material_bytes = volume_key.len() * 4000;
        let mut keyslot = alloc::vec![0u8; KEYSLOT_SIZE];
        // First 3999 stripes are zero. This final stripe is the precomputed
        // SHA-256 AF state XOR the 0x00..0x1f volume key. Production unlock
        // still performs and verifies all 4000 merge rounds.
        const LAST_STRIPE: [u8; 32] = [
            0x82, 0x57, 0x6d, 0xea, 0x2b, 0x91, 0x29, 0x7c, 0x38, 0xd0, 0x4c, 0x88, 0xc8, 0x5c,
            0x1e, 0x30, 0xa7, 0xc6, 0xce, 0xed, 0x6c, 0x9f, 0x6c, 0xdc, 0x86, 0x83, 0x94, 0xe7,
            0x5d, 0x56, 0x79, 0xd7,
        ];
        let last = material_bytes - volume_key.len();
        keyslot[last..material_bytes].copy_from_slice(&LAST_STRIPE);
        let slot_key = pbkdf2(
            Luks1Hash::Sha256,
            passphrase,
            &slot_salt,
            2,
            volume_key.len(),
        );
        let slot_key: &[u8; 32] = slot_key.as_slice().try_into().expect("32-byte key");
        aes_xts_128_encrypt(
            &Cap::<Key<AesXts128>, Grant>::bootstrap(),
            slot_key,
            0,
            512,
            &mut keyslot,
        )
        .expect("keyslot encryption");

        let digest = pbkdf2(Luks1Hash::Sha256, &volume_key, &digest_salt, 3, 32);
        let json = format!(
            concat!(
                "{{\"keyslots\":{{\"0\":{{\"type\":\"luks2\",\"key_size\":32,",
                "\"af\":{{\"type\":\"luks1\",\"stripes\":4000,\"hash\":\"sha256\"}},",
                "\"area\":{{\"type\":\"raw\",\"offset\":\"32768\",\"size\":\"131072\",",
                "\"encryption\":\"aes-xts-plain64\",\"key_size\":32}},",
                "\"kdf\":{{\"type\":\"pbkdf2\",\"hash\":\"sha256\",\"iterations\":2,",
                "\"salt\":\"{}\"}}}}}},\"tokens\":{{}},",
                "\"segments\":{{\"0\":{{\"type\":\"crypt\",\"offset\":\"163840\",",
                "\"size\":\"dynamic\",\"iv_tweak\":\"0\",",
                "\"encryption\":\"aes-xts-plain64\",\"sector_size\":4096}}}},",
                "\"digests\":{{\"0\":{{\"type\":\"pbkdf2\",\"keyslots\":[\"0\"],",
                "\"segments\":[\"0\"],\"hash\":\"sha256\",\"iterations\":3,",
                "\"salt\":\"{}\",\"digest\":\"{}\"}}}},",
                "\"config\":{{\"json_size\":\"12288\",\"keyslots_size\":\"131072\"}}}}"
            ),
            encode_base64(&slot_salt),
            encode_base64(&digest_salt),
            encode_base64(&digest),
        );

        let mut plaintext = [0u8; 4096];
        for (index, byte) in plaintext.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17);
        }
        let mut ciphertext = plaintext;
        aes_xts_128_encrypt(
            &Cap::<Key<AesXts128>, Grant>::bootstrap(),
            &volume_key,
            0,
            4096,
            &mut ciphertext,
        )
        .expect("payload encryption");

        let mut image = alloc::vec![0u8; DATA_OFFSET + 4096];
        image[KEYSLOT_OFFSET..KEYSLOT_OFFSET + KEYSLOT_SIZE].copy_from_slice(&keyslot);
        image[DATA_OFFSET..DATA_OFFSET + ciphertext.len()].copy_from_slice(&ciphertext);
        let primary = serialized_header(MAGIC_PRIMARY, 0, 7, &json);
        let secondary = serialized_header(MAGIC_SECONDARY, HEADER_SIZE as u64, 8, &json);
        image[..HEADER_SIZE].copy_from_slice(&primary);
        image[HEADER_SIZE..2 * HEADER_SIZE].copy_from_slice(&secondary);
        // Ensure redundant-metadata selection really tolerates a corrupt copy.
        image[CHECKSUM_OFFSET] ^= 0x80;

        (
            Arc::new(ImageDevice {
                bytes: IrqSafeSpinLock::new(image),
            }),
            plaintext,
        )
    }

    fn smoke_luks2_redundant_header_and_unlock() -> TestResult {
        use crate::encrypted::{
            clear_luks_passphrase_provider, install_luks_passphrase_provider,
            open_luks_with_provider, EncryptedBlockDevice, LuksVersion,
        };

        fn fixture_provider(
            volume: &crate::encrypted::LuksVolumeInfo,
        ) -> Result<Zeroizing<Vec<u8>>, crate::encrypted::LuksCredentialError> {
            if volume.version != LuksVersion::Luks2
                || volume.uuid != "01234567-89ab-cdef-0123-456789abcdef"
            {
                return Err(crate::encrypted::LuksCredentialError::Declined);
            }
            Ok(Zeroizing::new(b"correct horse battery staple".to_vec()))
        }

        let (device, plaintext) = luks2_fixture();
        let header = match load_header(device.as_ref()) {
            Ok(header) => header,
            Err(_) => return TestResult::Fail("valid secondary LUKS2 header rejected"),
        };
        if header.source != Luks2HeaderCopy::Secondary
            || header.sequence_id != 8
            || header.uuid != "01234567-89ab-cdef-0123-456789abcdef"
        {
            return TestResult::Fail("LUKS2 redundant-header selection mismatch");
        }

        clear_luks_passphrase_provider();
        install_luks_passphrase_provider(fixture_provider);
        let opened = open_luks_with_provider(device.clone());
        clear_luks_passphrase_provider();
        let unlocked = match opened {
            Ok(device) => device,
            Err(_) => return TestResult::Fail("provider-routed LUKS2 keyslot rejected"),
        };
        if unlocked.lba_size() != 4096 || unlocked.capacity() != 1 {
            return TestResult::Fail("LUKS2 encryption-sector geometry mismatch");
        }
        let mut actual = [0u8; 4096];
        if unlocked.read(0, 1, &mut actual).is_err() || actual != plaintext {
            return TestResult::Fail("LUKS2 payload mapping/decryption mismatch");
        }
        let mut replacement = plaintext;
        replacement.reverse();
        if unlocked.write(0, 1, &replacement).is_err()
            || unlocked.read(0, 1, &mut actual).is_err()
            || actual != replacement
        {
            return TestResult::Fail("LUKS2 payload mapping/encryption mismatch");
        }
        if unlocked.read(1, 1, &mut actual) != Err(BlockIoError::OutOfRange) {
            return TestResult::Fail("LUKS2 fixed segment capacity was not enforced");
        }
        match EncryptedBlockDevice::open_luks2(device, b"wrong passphrase") {
            Err(Luks2Error::WrongPassphrase) => TestResult::Pass,
            _ => TestResult::Fail("LUKS2 wrong passphrase was not rejected"),
        }
    }
    kernel_test_in!("block/luks2", smoke_luks2_redundant_header_and_unlock);

    fn smoke_luks2_resource_policy_rejects_kdf() -> TestResult {
        let (device, _) = luks2_fixture();
        let policy = Luks2UnlockPolicy {
            max_pbkdf2_iterations: 1,
            ..Luks2UnlockPolicy::default()
        };
        match crate::encrypted::EncryptedBlockDevice::open_luks2_with_policy(
            device,
            b"correct horse battery staple",
            policy,
        ) {
            Err(Luks2Error::WorkFactorTooLarge) => TestResult::Pass,
            _ => TestResult::Fail("LUKS2 PBKDF policy was not enforced"),
        }
    }
    kernel_test_in!("block/luks2", smoke_luks2_resource_policy_rejects_kdf);

    fn smoke_luks2_argon2id_known_answer() -> TestResult {
        // PHC reference implementation vector: Argon2id v1.3, m=256 KiB,
        // t=2, p=1, password="password", salt="somesalt".
        let kdf = Kdf {
            kind: "argon2id".into(),
            salt: encode_base64(b"somesalt"),
            hash: None,
            iterations: None,
            time: Some(2),
            memory: Some(256),
            cpus: Some(1),
        };
        let actual = match derive_key(
            b"password",
            b"somesalt",
            32,
            &kdf,
            Luks2UnlockPolicy::default(),
        ) {
            Ok(actual) => actual,
            Err(_) => return TestResult::Fail("Argon2id KDF returned an error"),
        };
        let expected = [
            0x9d, 0xfe, 0xb9, 0x10, 0xe8, 0x0b, 0xad, 0x03, 0x11, 0xfe, 0xe2, 0x0f, 0x9c, 0x0e,
            0x2b, 0x12, 0xc1, 0x79, 0x87, 0xb4, 0xca, 0xc9, 0x0c, 0x2e, 0xf5, 0x4d, 0x5b, 0x30,
            0x21, 0xc6, 0x8b, 0xfe,
        ];
        if actual.as_slice() == expected {
            TestResult::Pass
        } else {
            TestResult::Fail("Argon2id known-answer mismatch")
        }
    }
    kernel_test_in!("block/luks2", smoke_luks2_argon2id_known_answer);
}

#[cfg(test)]
mod host_tests {
    use super::*;

    // The block test binary links the real memory crate without the kernel
    // linker script. Supply inert host-only anchors for code paths these tests
    // never execute so pure metadata/KDF tests can run under `cargo test`.
    #[no_mangle]
    static __kernel_phys_bounds: [u64; 2] = [0; 2];
    #[no_mangle]
    static __text_start: u8 = 0;

    #[test]
    fn base64_vectors_and_rejections() {
        assert_eq!(&*decode_base64("TWFu").unwrap(), b"Man");
        assert_eq!(&*decode_base64("TWE=").unwrap(), b"Ma");
        assert_eq!(&*decode_base64("TQ==").unwrap(), b"M");
        assert!(decode_base64("T===").is_err());
        assert!(decode_base64("TQ==AAAA").is_err());
    }

    #[test]
    fn canonical_decimal_only() {
        assert_eq!(decimal_u64("0"), Ok(0));
        assert_eq!(decimal_u64("4194304"), Ok(4_194_304));
        assert!(decimal_u64("01").is_err());
        assert!(decimal_u64("-1").is_err());
    }

    #[test]
    fn duplicate_json_keys_are_rejected() {
        let mut deserializer = serde_json::Deserializer::from_slice(br#"{"0":1,"0":2}"#);
        assert!(StrictJsonValue::deserialize(&mut deserializer).is_err());
    }

    #[test]
    fn synthetic_af_merge_vector() {
        const LAST_STRIPE: [u8; 32] = [
            0x82, 0x57, 0x6d, 0xea, 0x2b, 0x91, 0x29, 0x7c, 0x38, 0xd0, 0x4c, 0x88, 0xc8, 0x5c,
            0x1e, 0x30, 0xa7, 0xc6, 0xce, 0xed, 0x6c, 0x9f, 0x6c, 0xdc, 0x86, 0x83, 0x94, 0xe7,
            0x5d, 0x56, 0x79, 0xd7,
        ];
        let mut material = alloc::vec![0u8; 32 * 4000];
        material[32 * 3999..].copy_from_slice(&LAST_STRIPE);
        let actual = af_merge(Luks1Hash::Sha256, &material, 32, 4000).unwrap();
        assert_eq!(&*actual, &(0u8..32).collect::<Vec<_>>());
    }
}
