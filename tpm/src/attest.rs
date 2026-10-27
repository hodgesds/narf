//! TPM 2.0 attestation structures, the remote-party verifier, and
//! the measurement-hooks seam (#945).
//!
//! Before this module, NARF could extend and read PCRs but could
//! not *attest*: there was no TPM2_Quote, no attestation key, and
//! the TCG event log `frame::measure` maintains never left the
//! kernel, so no remote party could ever check a NARF machine's
//! measurement state. This module is the canonical surface for
//! that: the `TPMS_ATTEST` / `TPMT_SIGNATURE` structures (Part 2
//! §10.12 / §11.4), a verifier that checks a quote the way a
//! relying party does, and the hooks through which `frame::measure`
//! publishes its event log and its extend-observed flag to the
//! quote composition and the sysfs publication.
//!
//! ## Reference
//!
//! TCG TPM Library Specification, Family 2.0, Rev 1.59 (public):
//! Part 1 §16 (Names), Part 2 §10.12 (TPMS_ATTEST), §11.4
//! (TPMT_SIGNATURE), Part 3 §18 (attestation commands: Quote).
//! <https://trustedcomputinggroup.org/resource/tpm-library-specification/>

extern crate alloc;

use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

use crate::tpm2::{
    TPM_ALG_AES, TPM_ALG_ECC, TPM_ALG_ECDSA, TPM_ALG_RSAPSS, TPM_ALG_RSASSA, TPM_ALG_SHA256,
    TPM_ECC_NIST_P256, TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE,
};
use crate::types::TpmError;

// ── Wire cursor ─────────────────────────────────────────────────────
//
// Same discipline as the canonical parsers in `commands`: every
// read is bounds-checked, counts are never trusted for allocation,
// and a structure parse must consume its buffer exactly.

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], TpmError> {
        if self.pos + n > self.buf.len() {
            return Err(TpmError::BadResponse);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, TpmError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, TpmError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, TpmError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, TpmError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Read a TPM2B (u16 size + bytes), returning the inner bytes.
    fn tpm2b(&mut self) -> Result<&'a [u8], TpmError> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = narf_crypto::sha256::Sha256::new();
    h.update(data);
    h.finalize()
}

// ── TPMS_ATTEST (Part 2 §10.12.8) ───────────────────────────────────

/// `TPMS_CLOCK_INFO` — the clock snapshot inside every TPMS_ATTEST.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClockInfo {
    /// Milliseconds since the TPM's clock epoch (TPM2_Startup).
    pub clock: u64,
    /// Number of TPM resets since manufacture.
    pub reset_count: u32,
    /// Number of TPM resumes (Startup(STATE)) since the last reset.
    pub restart_count: u32,
    /// The clock is in a "safe" state (no uncertainty about its
    /// source) — `TPM_YES` on the wire.
    pub safe: bool,
}

/// `TPMS_QUOTE_INFO` — the attested union member for
/// `TPM_ST_ATTEST_QUOTE`: the PCR selection that was quoted and
/// the composite digest over the selected PCRs' values,
/// `H(PCR[sel₁] || PCR[sel₂] || …)` in selection order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteInfo {
    /// `pcrSelect` as `(TPM_ALG_ID, pcrSelect bytes)` pairs.
    pub pcr_select: Vec<(u16, Vec<u8>)>,
    /// `pcrDigest` — the composite digest.
    pub pcr_digest: Vec<u8>,
}

/// A parsed `TPMS_ATTEST`. Only the quote union member is
/// interpreted; for other attestation types the union bytes are
/// the (uninterpreted) remainder of the structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestInfo {
    /// `magic` — must be [`TPM_GENERATED_VALUE`] for a structure
    /// a TPM produced.
    pub magic: u32,
    /// `type` — `TPMI_ST_ATTEST` (e.g. `TPM_ST_ATTEST_QUOTE`).
    pub attest_type: u16,
    /// `qualifiedSigner` — the signing key's qualified name.
    pub qualified_signer: Vec<u8>,
    /// `extraData` — the caller-supplied qualifying data (nonce).
    pub extra_data: Vec<u8>,
    /// `clockInfo`.
    pub clock_info: ClockInfo,
    /// `firmwareVersion`.
    pub firmware_version: u64,
    /// The quote union, when `attest_type == TPM_ST_ATTEST_QUOTE`.
    pub quote: Option<QuoteInfo>,
}

impl AttestInfo {
    /// Parse a `TPMS_ATTEST` from its marshaled bytes (the inner
    /// bytes of the response's `TPM2B_ATTEST`). Structural walk;
    /// for a quote the walk must consume the buffer exactly.
    pub fn parse(bytes: &[u8]) -> Result<Self, TpmError> {
        let mut r = Reader::new(bytes);
        let magic = r.u32()?;
        let attest_type = r.u16()?;
        let qualified_signer = r.tpm2b()?.to_vec();
        let extra_data = r.tpm2b()?.to_vec();
        let clock_info = ClockInfo {
            clock: r.u64()?,
            reset_count: r.u32()?,
            restart_count: r.u32()?,
            safe: r.u8()? != 0,
        };
        let firmware_version = r.u64()?;
        let quote = if attest_type == TPM_ST_ATTEST_QUOTE {
            // TPML_PCR_SELECTION, then TPM2B_DIGEST.
            let count = r.u32()? as usize;
            let mut pcr_select = Vec::new();
            for _ in 0..count {
                let alg = r.u16()?;
                let size = r.u8()? as usize;
                let mask = r.take(size)?.to_vec();
                pcr_select.push((alg, mask));
            }
            let pcr_digest = r.tpm2b()?.to_vec();
            if !r.at_end() {
                return Err(TpmError::BadResponse);
            }
            Some(QuoteInfo {
                pcr_select,
                pcr_digest,
            })
        } else {
            None
        };
        Ok(Self {
            magic,
            attest_type,
            qualified_signer,
            extra_data,
            clock_info,
            firmware_version,
            quote,
        })
    }
}

// ── TPMT_SIGNATURE (Part 2 §11.4.2) ─────────────────────────────────

/// A parsed `TPMT_SIGNATURE`. The ECDSA form is the attestation
/// key's; the RSA forms parse (a relying party may meet them from
/// other TPMs) but this crate's verifier does not check them —
/// `narf-crypto` has no RSASSA verify, and the in-tree AK is ECC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    /// `TPM_ALG_ECDSA`: hash + TPMS_SIGNATURE_ECC (r, s as
    /// TPM2B_ECC_PARAMETERs).
    Ecdsa { hash: u16, r: Vec<u8>, s: Vec<u8> },
    /// `TPM_ALG_RSASSA`: hash + TPM2B_PUBLIC_KEY_RSA.
    Rsassa { hash: u16, sig: Vec<u8> },
    /// `TPM_ALG_RSAPSS`: hash + TPM2B_PUBLIC_KEY_RSA.
    Rsapss { hash: u16, sig: Vec<u8> },
}

impl Signature {
    /// Parse a `TPMT_SIGNATURE`, consuming the buffer exactly.
    pub fn parse(bytes: &[u8]) -> Result<Self, TpmError> {
        let mut r = Reader::new(bytes);
        let alg = r.u16()?;
        let sig = match alg {
            TPM_ALG_ECDSA => {
                let hash = r.u16()?;
                let r_bytes = r.tpm2b()?.to_vec();
                let s_bytes = r.tpm2b()?.to_vec();
                Signature::Ecdsa {
                    hash,
                    r: r_bytes,
                    s: s_bytes,
                }
            }
            TPM_ALG_RSASSA => Signature::Rsassa {
                hash: r.u16()?,
                sig: r.tpm2b()?.to_vec(),
            },
            TPM_ALG_RSAPSS => Signature::Rsapss {
                hash: r.u16()?,
                sig: r.tpm2b()?.to_vec(),
            },
            _ => return Err(TpmError::BadResponse),
        };
        if !r.at_end() {
            return Err(TpmError::BadResponse);
        }
        Ok(sig)
    }
}

/// A parsed `TPM2_Quote` response: the raw attestation bytes (the
/// exact bytes the signature covers), their parsed form, and the
/// signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteResponse {
    pub attest_bytes: Vec<u8>,
    pub info: AttestInfo,
    pub signature: Signature,
}

// ── Names (Part 1 §16) ──────────────────────────────────────────────

/// The Name of an object: `nameAlg || H(publicArea)` (Part 1
/// §16.4). Only the SHA-256 nameAlg is computed — the only bank
/// this tree implements; any other nameAlg returns `None`.
pub fn object_name(public_area: &[u8]) -> Option<Vec<u8>> {
    if public_area.len() < 4 {
        return None;
    }
    let name_alg = u16::from_be_bytes([public_area[2], public_area[3]]);
    if name_alg != TPM_ALG_SHA256 {
        return None;
    }
    let mut name = Vec::with_capacity(34);
    name.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    name.extend_from_slice(&sha256(public_area));
    Some(name)
}

/// The qualified name of a *primary* object (Part 1 §16.5):
/// `nameAlg || H(hierarchyHandle || Name)`, where the hierarchy's
/// own qualified name is its handle value. This is the name a
/// quote's `qualifiedSigner` carries for a primary AK, and the
/// value `TPM2_ReadPublic` reports as `qualifiedName`.
pub fn primary_qualified_name(hierarchy: u32, name: &[u8]) -> Option<Vec<u8>> {
    if name.len() < 2 {
        return None;
    }
    let name_alg = u16::from_be_bytes([name[0], name[1]]);
    if name_alg != TPM_ALG_SHA256 {
        return None;
    }
    let mut input = Vec::with_capacity(4 + name.len());
    input.extend_from_slice(&hierarchy.to_be_bytes());
    input.extend_from_slice(name);
    let mut qn = Vec::with_capacity(34);
    qn.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
    qn.extend_from_slice(&sha256(&input));
    Some(qn)
}

// ── The remote-party verifier ───────────────────────────────────────

/// Why a quote failed verification. The checks run in the order a
/// relying party performs them — structure, provenance, binding,
/// state, signature — so the variant names the *first* broken
/// link in the attestation chain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AttestError {
    /// The attestation or signature bytes do not parse.
    BadStructure,
    /// `magic` is not TPM_GENERATED: the structure did not come
    /// out of a TPM.
    BadMagic,
    /// `type` is not TPM_ST_ATTEST_QUOTE.
    NotAQuote,
    /// `extraData` is not the qualifying data the verifier
    /// supplied (stale or replayed quote).
    ExtraDataMismatch,
    /// `qualifiedSigner` is not the AK's qualified name.
    SignerMismatch,
    /// The composite PCR digest does not recompute from the
    /// verifier's own PCR values (the quoted state is not the
    /// state the verifier measured).
    PcrDigestMismatch,
    /// The signature does not verify over the attestation with
    /// the AK public area.
    BadSignature,
    /// A key type, curve, scheme, or PCR bank this verifier does
    /// not implement (in-tree: ECC P-256 AKs, ECDSA signatures,
    /// the SHA-256 bank).
    Unsupported,
}

/// Walk a marshaled `TPMT_PUBLIC` for an ECC key and return its
/// `(x, y)` affine coordinates. Only the shape the AK template
/// uses is accepted: SHA-256 nameAlg, NIST P-256, NULL-or-AES
/// symmetric (restricted signing keys carry NULL), an optional
/// signing scheme, NULL-or-MGF1 KDF.
fn ecc_public_point(public_area: &[u8]) -> Result<([u8; 32], [u8; 32]), AttestError> {
    let mut r = Reader::new(public_area);
    let bad = |_: TpmError| AttestError::Unsupported;
    if r.u16().map_err(bad)? != TPM_ALG_ECC {
        return Err(AttestError::Unsupported);
    }
    if r.u16().map_err(bad)? != TPM_ALG_SHA256 {
        return Err(AttestError::Unsupported);
    }
    let _attrs = r.u32().map_err(bad)?;
    let _auth_policy = r.tpm2b().map_err(bad)?;
    // TPMT_SYM_DEF_OBJECT: NULL, or AES + keyBits + mode.
    match r.u16().map_err(bad)? {
        crate::tpm2::TPM_ALG_NULL => {}
        TPM_ALG_AES => {
            let _ = r.u16().map_err(bad)?;
            let _ = r.u16().map_err(bad)?;
        }
        _ => return Err(AttestError::Unsupported),
    }
    // TPMT_ECC_SCHEME: a signing scheme carries a hash; NULL does not.
    match r.u16().map_err(bad)? {
        crate::tpm2::TPM_ALG_NULL => {}
        TPM_ALG_ECDSA | TPM_ALG_RSASSA | TPM_ALG_RSAPSS => {
            let _ = r.u16().map_err(bad)?;
        }
        _ => return Err(AttestError::Unsupported),
    }
    if r.u16().map_err(bad)? != TPM_ECC_NIST_P256 {
        return Err(AttestError::Unsupported);
    }
    // TPMT_KDF_SCHEME: NULL, or MGF1 + hash.
    match r.u16().map_err(bad)? {
        crate::tpm2::TPM_ALG_NULL => {}
        0x0007 => {
            let _ = r.u16().map_err(bad)?;
        }
        _ => return Err(AttestError::Unsupported),
    }
    let x = r.tpm2b().map_err(bad)?;
    let y = r.tpm2b().map_err(bad)?;
    if x.len() != 32 || y.len() != 32 || !r.at_end() {
        return Err(AttestError::Unsupported);
    }
    let mut point = ([0u8; 32], [0u8; 32]);
    point.0.copy_from_slice(x);
    point.1.copy_from_slice(y);
    Ok(point)
}

/// Verify a quote the way a remote party does (TCG attestation
/// architecture, EK Credential Profile relying-party flow):
///
/// 1. Parse the attestation; require the TPM_GENERATED magic and
///    the quote type.
/// 2. Require `extraData` to be exactly the qualifying data
///    (nonce) this verifier issued — a quote answering a different
///    challenge is stale or replayed.
/// 3. Require `qualifiedSigner` to be the AK's qualified name,
///    pinned by the verifier from a trusted `TPM2_ReadPublic` at
///    enrollment time.
/// 4. Recompute the composite PCR digest from the verifier's own
///    PCR values (read independently, e.g. via `TPM2_PCR_Read`)
///    and require it to match the quoted `pcrDigest`.
/// 5. Verify the ECDSA signature over the exact attestation bytes
///    with the AK public area.
///
/// `ak_public` is the AK's marshaled `TPMT_PUBLIC` (the inner
/// bytes of the `TPM2B_PUBLIC` ReadPublic returns); `pcrs` carries
/// the verifier's PCR values as `(index, value)` pairs for the
/// SHA-256 bank — every PCR the quote selects must be present.
pub fn verify_quote(
    attest_bytes: &[u8],
    signature: &Signature,
    ak_public: &[u8],
    ak_qualified_name: &[u8],
    expected_extra_data: &[u8],
    pcrs: &[(u32, [u8; 32])],
) -> Result<AttestInfo, AttestError> {
    let info = AttestInfo::parse(attest_bytes).map_err(|_| AttestError::BadStructure)?;
    if info.magic != TPM_GENERATED_VALUE {
        return Err(AttestError::BadMagic);
    }
    if info.attest_type != TPM_ST_ATTEST_QUOTE {
        return Err(AttestError::NotAQuote);
    }
    if info.extra_data != expected_extra_data {
        return Err(AttestError::ExtraDataMismatch);
    }
    if info.qualified_signer != ak_qualified_name {
        return Err(AttestError::SignerMismatch);
    }
    let quote = info.quote.as_ref().ok_or(AttestError::NotAQuote)?;
    // Composite digest: concatenate the selected PCRs' values in
    // selection order and hash (Part 3, TPM2_Quote: pcrDigest is
    // the hash of the concatenation of the selected PCR values).
    let mut concat = Vec::new();
    for (alg, mask) in &quote.pcr_select {
        if *alg != TPM_ALG_SHA256 {
            return Err(AttestError::Unsupported);
        }
        for (byte_idx, byte) in mask.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0 {
                    let idx = (byte_idx * 8 + bit) as u32;
                    let value = pcrs
                        .iter()
                        .find(|(i, _)| *i == idx)
                        .map(|(_, v)| v)
                        .ok_or(AttestError::PcrDigestMismatch)?;
                    concat.extend_from_slice(value);
                }
            }
        }
    }
    if sha256(&concat).as_slice() != quote.pcr_digest.as_slice() {
        return Err(AttestError::PcrDigestMismatch);
    }
    // Signature over the attestation structure's marshaled bytes.
    let (x, y) = ecc_public_point(ak_public)?;
    let (hash_alg, r, s) = match signature {
        Signature::Ecdsa { hash, r, s } => (*hash, r, s),
        _ => return Err(AttestError::Unsupported),
    };
    if hash_alg != TPM_ALG_SHA256 || r.len() != 32 || s.len() != 32 {
        return Err(AttestError::BadSignature);
    }
    let mut pubkey = [0u8; 65];
    pubkey[0] = 0x04;
    pubkey[1..33].copy_from_slice(&x);
    pubkey[33..65].copy_from_slice(&y);
    let mut r32 = [0u8; 32];
    let mut s32 = [0u8; 32];
    r32.copy_from_slice(r);
    s32.copy_from_slice(s);
    let digest = sha256(attest_bytes);
    if !narf_crypto::p256::ecdsa::verify_p256(&pubkey, &digest, &r32, &s32) {
        return Err(AttestError::BadSignature);
    }
    Ok(info)
}

// ── Measurement hooks ───────────────────────────────────────────────
//
// The seam between `frame::measure` and the attestation surface.
// `frame` cannot be named by the composition crates that consume
// these hooks (the platform probe publishes the event log through
// the sysfs bridge; the quote composition checks the guard), and
// this crate cannot name `frame` either (frame dispatches through
// this crate's registry). So frame *installs* two pure probes at
// measured boot, and consumers consult them here:
//
// - `event_log` — the TCG_PCR_EVENT2 encoding of the measurement
//   log, for the `binary_bios_measurements` publication.
// - `extends_observed` — `frame::measure`'s EXTEND_OBSERVED flag:
//   has any measurement been extended this boot? The quote
//   composition refuses to quote an untouched PCR set — an empty
//   history signed as if it were a measured boot.
//
// Uninstalled hooks fail closed: no extends observed, empty log.

/// The measurement probes `frame::measure` installs at measured
/// boot (plain function pointers: the probes are pure reads of
/// frame's measurement state and capture nothing).
#[derive(Copy, Clone)]
pub struct MeasurementHooks {
    pub event_log: fn() -> Vec<u8>,
    pub extends_observed: fn() -> bool,
}

static MEASUREMENT_HOOKS: IrqSafeSpinLock<Option<MeasurementHooks>> = IrqSafeSpinLock::new(None);

/// Install the measurement hooks. Called once, from frame's
/// measured-boot initcall; a second install replaces the first
/// (fixtures re-install stubs).
pub fn install_measurement_hooks(hooks: MeasurementHooks) {
    *MEASUREMENT_HOOKS.lock() = Some(hooks);
}

/// The TCG event log bytes from the installed hook, or an empty
/// log when no hook is installed (no measured boot has run).
pub fn event_log_bytes() -> Vec<u8> {
    match *MEASUREMENT_HOOKS.lock() {
        Some(hooks) => (hooks.event_log)(),
        None => Vec::new(),
    }
}

/// Whether any PCR extend has been observed this boot, per the
/// installed hook. Fails closed: `false` when uninstalled.
pub fn extends_observed() -> bool {
    match *MEASUREMENT_HOOKS.lock() {
        Some(hooks) => (hooks.extends_observed)(),
        None => false,
    }
}

/// Test-only: drop the installed hooks, restoring the fail-closed
/// uninstalled state.
#[doc(hidden)]
pub fn __reset_measurement_hooks_for_test() {
    *MEASUREMENT_HOOKS.lock() = None;
}
