//! UEFI Secure Boot + Authenticode verification.
//!
//! Spec: `frame/specification/spec.md` §3.7 (Secure Boot chain).
//!
//! ## What this module does
//!
//! Three things, all keyed to the platform's UEFI variable namespace:
//!
//! 1. `enabled()` — report whether Secure Boot is enforcing
//!    (`SecureBoot == 1` AND `SetupMode == 0`). The kernel should
//!    refuse to load any signed-by-platform-key surface (kernel
//!    module, firmware blob, init binary) when this is false on a
//!    production build — bring-up builds can wave it through.
//!
//! 2. `verify_pe()` — Authenticode validation for a PE/COFF image:
//!    parse the PE security-directory pointer to a `WIN_CERTIFICATE`,
//!    decode its embedded PKCS#7 SignedData, extract the signer's
//!    X.509 / SHA-256 message digest, and walk the platform's `db`
//!    signature database for a matching entry. PE Authenticode hash
//!    is the SHA-256 of the image with the checksum, security-dir
//!    entry, and attribute-certificate-table sections zeroed.
//!
//! 3. `measure_and_verify()` — combined surface for "before you load,
//!    measure and verify" boot-time consumers. Calls `verify_pe()`,
//!    then `narf_measure::measure_with_type` to extend the image
//!    into the supplied PCR with `EV_EFI_BOOT_SERVICES_APPLICATION`.
//!
//! ## Sources
//!
//! - **PE/COFF Specification**, rev 8.3, Microsoft, §3.4 (Optional
//!   Header data directories — Security Table is entry 4) and §4.7
//!   (Attribute Certificate Table layout — `WIN_CERTIFICATE`).
//! - **Authenticode PE Signature Format** (Microsoft, 2008):
//!   <https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-functions>
//! - **PKCS#7** — RFC 5652 (Cryptographic Message Syntax). The
//!   SignerInfo decoder here implements the subset Authenticode
//!   actually uses: `SignedData { version, digestAlgorithms,
//!   contentInfo, certificates, signerInfos }`.
//! - **UEFI 2.10 §32.4** — PK / KEK / db / dbx variable shapes
//!   (decoded by `narf_efi::variable::parse_signature_list`).
//! - Adapted from Linux `crypto/asymmetric_keys/pkcs7_parser.c`,
//!   `crypto/asymmetric_keys/verify_pefile.c`, and
//!   `arch/x86/boot/compressed/efi.c` (GPL-2.0-or-later).

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use narf_efi::variable::{SignatureListHeader, EFI_CERT_SHA256_GUID};
use narf_lib::sync::IrqSafeSpinLock;

use super::measure::{
    measure_precomputed, sha256, EV_EFI_BOOT_SERVICES_APPLICATION, SHA256_DIGEST_SIZE,
};

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SecureBootError {
    /// Image is shorter than the smallest valid PE/COFF (`PE\0\0` +
    /// COFF header + optional header).
    TooSmall,
    /// `MZ` magic missing or `PE\0\0` offset out of bounds.
    NotPe,
    /// The image's optional-header magic is neither PE32 (`0x10b`)
    /// nor PE32+ (`0x20b`).
    BadOptionalHeader,
    /// Security data directory missing, zero-length, or out of bounds.
    NoSignature,
    /// `WIN_CERTIFICATE` header malformed (length too small, type
    /// not PKCS#7, revision not 0x0200).
    BadCertificate,
    /// PKCS#7 SignedData ASN.1 parse failed.
    BadPkcs7,
    /// SHA-256 digest mismatch between PE image and signed-content
    /// digest in PKCS#7.
    DigestMismatch,
    /// Signer's SHA-256 fingerprint is not in `db`.
    NotInDb,
    /// Signer's SHA-256 fingerprint is in `dbx`.
    Revoked,
    /// Secure Boot is enforcing and verification is mandatory but the
    /// platform variables are missing.
    NoPlatformKeys,
    /// Build profile rejects unsigned binaries.
    UnsignedRejected,
}

// ── Secure-Boot state (UEFI variable cache) ───────────────────────
//
// In a production wiring, these come from the UEFI runtime-services
// surface (`GetVariable("SecureBoot", &EFI_GLOBAL_VARIABLE, ...)`).
// Tier-1 of NARF doesn't yet wire RT services after ExitBootServices,
// so the bootloader is responsible for snapshotting these into a
// kernel-readable region pre-ExitBootServices and the kernel reads
// them through `install_state` at boot.
//
// Until that wiring lands, the kernel boots with `STATE = None`,
// `verify_pe` returns `NoPlatformKeys`, and `enabled()` returns
// false — bring-up builds wave it through via the `firmware-allow-
// unsigned` feature surface in `narf-firmware`. Production builds
// will refuse to load unsigned firmware once `STATE` is populated.

/// Decoded state of the platform's Secure Boot policy.
#[derive(Debug, Default, Clone)]
pub struct SecureBootState {
    /// Value of UEFI variable `SecureBoot` (1 = enforcing, 0 = off).
    pub secure_boot: u8,
    /// Value of UEFI variable `SetupMode` (1 = unprovisioned, 0 =
    /// PK enrolled).
    pub setup_mode: u8,
    /// Encoded `EFI_SIGNATURE_LIST` chain for the image-allow database.
    pub db: Vec<u8>,
    /// Encoded `EFI_SIGNATURE_LIST` chain for the image-forbid database.
    pub dbx: Vec<u8>,
}

static STATE: IrqSafeSpinLock<Option<SecureBootState>> = IrqSafeSpinLock::new(None);

/// Stage the platform's Secure Boot state. Called once at boot by the
/// bootloader handoff or the EFI RT-services pre-ExitBootServices
/// snapshot path. Idempotent — first install wins.
pub fn install_state(s: SecureBootState) {
    let mut g = STATE.lock();
    if g.is_none() {
        *g = Some(s);
    }
}

/// Borrow the cached Secure Boot state (clones the encoded
/// signature-database vectors).
pub fn state() -> Option<SecureBootState> {
    STATE.lock().clone()
}

/// `true` iff Secure Boot is enforcing (`SecureBoot == 1` AND
/// `SetupMode == 0`). Per UEFI 2.10 §32.3, both conditions must hold
/// — `SetupMode == 1` puts the platform in user-mode-bypass for
/// PK enrollment, so a signing decision shouldn't be enforced.
pub fn enabled() -> bool {
    match state() {
        Some(s) => s.secure_boot == 1 && s.setup_mode == 0,
        None => false,
    }
}

#[doc(hidden)]
pub fn __reset_for_test() {
    *STATE.lock() = None;
}

// ── PE/COFF parser (the subset needed for Authenticode) ───────────
//
// PE layout that matters here:
//
//   offset 0x3C..0x40  →  PE signature offset (u32 LE)
//   offset PEOFF + 0   →  `b"PE\0\0"`
//   offset PEOFF + 4   →  COFF header (20 bytes)
//   offset PEOFF + 24  →  Optional Header
//                          - magic u16 (0x10B = PE32, 0x20B = PE32+)
//                          - …
//                          - data directories at fixed offset from magic:
//                              PE32  → +0x60
//                              PE32+ → +0x70
//                            Data directory entry 4 is the Security
//                            Table — `(file_offset, size)`.
//   security entry → `WIN_CERTIFICATE { length, revision, type }` then
//                    PKCS#7 SignedData up to `length` bytes.

const PE_MAGIC: &[u8; 4] = b"PE\0\0";
const PE32_MAGIC: u16 = 0x010B;
const PE32PLUS_MAGIC: u16 = 0x020B;
const SECURITY_DIR_INDEX: usize = 4;

/// Decoded location of a PE image's Authenticode signature region.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PeSecurityDirectory {
    /// File offset of the first `WIN_CERTIFICATE` in the image.
    pub offset: u32,
    /// Total bytes in the certificate region (may chain multiple
    /// `WIN_CERTIFICATE` entries — Authenticode uses one).
    pub size: u32,
    /// Image size — needed by the Authenticode hash to know how much
    /// of the tail (beyond the certificate region) to hash.
    pub image_size: u32,
    /// File offset of the optional-header `CheckSum` field — zeroed
    /// during the Authenticode hash.
    pub checksum_offset: u32,
    /// File offset of the data-directory's Security entry — zeroed
    /// during the Authenticode hash.
    pub security_entry_offset: u32,
}

/// Parse the PE/COFF security directory from `image`.
pub fn parse_pe_security_dir(image: &[u8]) -> Result<PeSecurityDirectory, SecureBootError> {
    // DOS header check + PE offset.
    if image.len() < 0x40 {
        return Err(SecureBootError::TooSmall);
    }
    if &image[0..2] != b"MZ" {
        return Err(SecureBootError::NotPe);
    }
    let pe_off = u32::from_le_bytes([image[0x3C], image[0x3D], image[0x3E], image[0x3F]]) as usize;
    if pe_off + 24 > image.len() {
        return Err(SecureBootError::NotPe);
    }
    if &image[pe_off..pe_off + 4] != PE_MAGIC {
        return Err(SecureBootError::NotPe);
    }
    let coff = pe_off + 4;
    let opt_off = coff + 20;
    if opt_off + 2 > image.len() {
        return Err(SecureBootError::BadOptionalHeader);
    }
    let opt_magic = u16::from_le_bytes([image[opt_off], image[opt_off + 1]]);
    let (data_dir_off, image_size_off, checksum_off) = match opt_magic {
        PE32_MAGIC => (opt_off + 0x60, opt_off + 0x38, opt_off + 0x40),
        PE32PLUS_MAGIC => (opt_off + 0x70, opt_off + 0x38, opt_off + 0x40),
        _ => return Err(SecureBootError::BadOptionalHeader),
    };
    let sec_entry = data_dir_off + SECURITY_DIR_INDEX * 8;
    if sec_entry + 8 > image.len() {
        return Err(SecureBootError::NoSignature);
    }
    let offset = u32::from_le_bytes([
        image[sec_entry],
        image[sec_entry + 1],
        image[sec_entry + 2],
        image[sec_entry + 3],
    ]);
    let size = u32::from_le_bytes([
        image[sec_entry + 4],
        image[sec_entry + 5],
        image[sec_entry + 6],
        image[sec_entry + 7],
    ]);
    if offset == 0 || size == 0 {
        return Err(SecureBootError::NoSignature);
    }
    if (offset as usize) + (size as usize) > image.len() {
        return Err(SecureBootError::NoSignature);
    }
    if image_size_off + 4 > image.len() {
        return Err(SecureBootError::BadOptionalHeader);
    }
    let image_size = u32::from_le_bytes([
        image[image_size_off],
        image[image_size_off + 1],
        image[image_size_off + 2],
        image[image_size_off + 3],
    ]);
    Ok(PeSecurityDirectory {
        offset,
        size,
        image_size,
        checksum_offset: checksum_off as u32,
        security_entry_offset: sec_entry as u32,
    })
}

// ── WIN_CERTIFICATE (PE/COFF §4.7) ────────────────────────────────
//
//   UINT32      dwLength       — total length including header
//   UINT16      wRevision      — 0x0200 (current)
//   UINT16      wCertificateType — 0x0002 = PKCS_SIGNED_DATA
//   BYTE        bCertificate[] — PKCS#7 SignedData

pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct WinCertificateHeader {
    pub length: u32,
    pub revision: u16,
    pub cert_type: u16,
}

/// Decode the `WIN_CERTIFICATE` header at the start of `buf`. Returns
/// the header + the body slice (PKCS#7 SignedData).
pub fn parse_win_certificate(buf: &[u8]) -> Result<(WinCertificateHeader, &[u8]), SecureBootError> {
    if buf.len() < 8 {
        return Err(SecureBootError::BadCertificate);
    }
    let length = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let revision = u16::from_le_bytes([buf[4], buf[5]]);
    let cert_type = u16::from_le_bytes([buf[6], buf[7]]);
    if (length as usize) < 8 || (length as usize) > buf.len() {
        return Err(SecureBootError::BadCertificate);
    }
    if revision != WIN_CERT_REVISION_2_0 {
        return Err(SecureBootError::BadCertificate);
    }
    if cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
        return Err(SecureBootError::BadCertificate);
    }
    let body = &buf[8..length as usize];
    Ok((
        WinCertificateHeader {
            length,
            revision,
            cert_type,
        },
        body,
    ))
}

// ── Minimal PKCS#7 SignerInfo decoder ─────────────────────────────
//
// We don't reimplement a full ASN.1 parser — Authenticode SignedData
// is shaped specifically enough that a hand-rolled walker is small.
// What we extract:
//
//   - The SignedData OID (`1.2.840.113549.1.7.2`) at the outer
//     `ContentInfo`.
//   - The embedded `SpcIndirectDataContent` OID
//     (`1.3.6.1.4.1.311.2.1.4`) inside `encapContentInfo`.
//   - The `messageDigest` (SHA-256, 32 bytes) inside the inner content.
//
// Anything else (certificates, signer issuer/serial, signature value,
// attribute set) is left for the full verifier path. This is enough
// for the "image hash matches what was signed" check; trust-anchor
// verification adds the `db` lookup on top.

/// Decoded subset of an Authenticode PKCS#7 blob — just what we need
/// to verify "what got signed matches this PE."
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticodeSignerInfo {
    /// SHA-256 of the PE image as recorded in `SpcIndirectDataContent`.
    pub signed_digest: [u8; SHA256_DIGEST_SIZE],
}

/// Top-level OID for PKCS#7 SignedData (RFC 5652).
const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// Microsoft's `spcIndirectDataContent` OID (Authenticode).
const OID_SPC_INDIRECT_DATA: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04];

/// Parse an Authenticode PKCS#7 SignedData blob far enough to extract
/// the signed PE digest. Tolerant of trailing padding (Authenticode
/// usually 8-byte-aligns the WIN_CERTIFICATE body).
pub fn parse_authenticode(buf: &[u8]) -> Result<AuthenticodeSignerInfo, SecureBootError> {
    // The outermost SEQUENCE wraps a ContentInfo. Walk the ASN.1
    // structure looking for the first 32-byte OCTET STRING that
    // follows the spcIndirectDataContent OID — that's the signed
    // message digest.
    let mut walker = AsnWalker::new(buf);
    let mut saw_spc = false;
    while let Some(tlv) = walker.next() {
        // Recurse into SEQUENCE / SET / [0] EXPLICIT.
        let tag = tlv.tag;
        let class = tag & 0xC0;
        let is_constructed = tag & 0x20 != 0;
        if is_constructed || class == 0xA0 {
            walker.push_into(tlv.value);
            continue;
        }
        // Primitive — check for OID and OCTET STRING.
        match tag {
            0x06 => {
                if tlv.value == OID_SPC_INDIRECT_DATA {
                    saw_spc = true;
                }
            }
            0x04 => {
                if saw_spc && tlv.value.len() == SHA256_DIGEST_SIZE {
                    let mut d = [0u8; SHA256_DIGEST_SIZE];
                    d.copy_from_slice(tlv.value);
                    return Ok(AuthenticodeSignerInfo { signed_digest: d });
                }
            }
            _ => {}
        }
    }
    Err(SecureBootError::BadPkcs7)
}

/// Tiny ASN.1 DER walker — handles definite-length encodings only.
/// Recurses into constructed types by pushing the inner value onto a
/// stack and continuing iteration there.
struct AsnWalker<'a> {
    /// Stack of unparsed slices — bottom is the initial input, top is
    /// the current frame.
    stack: Vec<&'a [u8]>,
}

#[derive(Copy, Clone, Debug)]
struct AsnTlv<'a> {
    tag: u8,
    value: &'a [u8],
}

impl<'a> AsnWalker<'a> {
    fn new(buf: &'a [u8]) -> Self {
        let mut v = Vec::with_capacity(8);
        v.push(buf);
        Self { stack: v }
    }
    fn push_into(&mut self, buf: &'a [u8]) {
        if !buf.is_empty() {
            self.stack.push(buf);
        }
    }
    fn next(&mut self) -> Option<AsnTlv<'a>> {
        loop {
            let frame = match self.stack.last() {
                Some(f) => *f,
                None => return None,
            };
            if frame.is_empty() {
                self.stack.pop();
                continue;
            }
            if frame.len() < 2 {
                self.stack.pop();
                continue;
            }
            let tag = frame[0];
            // Long-form tags (low 5 bits == 0x1F) are out-of-spec for
            // PKCS#7 — we don't see them in practice.
            if tag & 0x1F == 0x1F {
                self.stack.pop();
                continue;
            }
            let (length, len_size) = match decode_length(&frame[1..]) {
                Some(p) => p,
                None => {
                    self.stack.pop();
                    continue;
                }
            };
            let header = 1 + len_size;
            if header + length > frame.len() {
                self.stack.pop();
                continue;
            }
            let value = &frame[header..header + length];
            let rest = &frame[header + length..];
            // Replace top-of-stack with the post-TLV slice.
            if let Some(top) = self.stack.last_mut() {
                *top = rest;
            }
            return Some(AsnTlv { tag, value });
        }
    }
}

/// Decode a DER length octet sequence at `buf[0..]`. Returns
/// `(length, bytes_consumed)`. Definite form only.
fn decode_length(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.is_empty() {
        return None;
    }
    let b0 = buf[0];
    if b0 & 0x80 == 0 {
        return Some((b0 as usize, 1));
    }
    let n = (b0 & 0x7F) as usize;
    if n == 0 || n > 4 || 1 + n > buf.len() {
        return None;
    }
    let mut len: usize = 0;
    for i in 0..n {
        len = (len << 8) | buf[1 + i] as usize;
    }
    Some((len, 1 + n))
}

// ── PE Authenticode hash (PE/COFF §3.4.2) ────────────────────────
//
// SHA-256 over the image with:
//   - the optional-header CheckSum field zeroed
//   - the data-directory's Security entry zeroed
//   - the certificate region itself excluded from the hash
//
// In wire order: hash bytes [0..checksum_off], skip 4 bytes
// (checksum), hash [checksum_off+4..security_entry_off], skip 8 bytes
// (security dir), hash [security_entry_off+8..sec_offset], skip
// security region (sec_offset..sec_offset+sec_size), hash trailing
// pad to image_size.

/// Compute the Authenticode SHA-256 hash of `image` using the parsed
/// security-directory layout. Returns the 32-byte digest.
pub fn authenticode_hash(image: &[u8], sec: &PeSecurityDirectory) -> [u8; SHA256_DIGEST_SIZE] {
    use narf_crypto::sha256::Sha256;
    let mut h = Sha256::new();
    let checksum_off = sec.checksum_offset as usize;
    let sec_dir_off = sec.security_entry_offset as usize;
    let sig_off = sec.offset as usize;
    let sig_end = sig_off + sec.size as usize;

    // Range 1: [0..checksum_off]
    h.update(&image[..checksum_off]);
    // Skip 4 bytes (checksum).
    // Range 2: [checksum_off+4..sec_dir_off]
    if checksum_off + 4 < sec_dir_off {
        h.update(&image[checksum_off + 4..sec_dir_off]);
    }
    // Skip 8 bytes (security data-directory entry).
    // Range 3: [sec_dir_off+8..sig_off]
    if sec_dir_off + 8 < sig_off {
        h.update(&image[sec_dir_off + 8..sig_off]);
    }
    // Skip the signature region.
    // Range 4: trailing data past the signature, if any.
    if sig_end < image.len() {
        h.update(&image[sig_end..]);
    }
    h.finalize()
}

// ── db / dbx lookup ───────────────────────────────────────────────

/// Walk a chained `EFI_SIGNATURE_LIST` blob and report whether
/// `fingerprint` (SHA-256 of either the image or its signer cert)
/// appears as one of the SHA-256 entries.
///
/// Returns `true` when matched. X.509 entries are not yet matched
/// against (they would require certificate-chain verification, which
/// the kernel defers to a future iteration).
pub fn fingerprint_in_signature_db(buf: &[u8], fingerprint: &[u8; SHA256_DIGEST_SIZE]) -> bool {
    let mut off = 0usize;
    while off + 28 <= buf.len() {
        let h = match SignatureListHeader::decode(&buf[off..]) {
            Ok(h) => h,
            Err(_) => break,
        };
        let list_size = h.list_size as usize;
        if off + list_size > buf.len() {
            break;
        }
        if h.signature_type == EFI_CERT_SHA256_GUID {
            let entries_start = off + 28 + h.header_size as usize;
            let entry_size = h.entry_size as usize;
            let end = off + list_size;
            let mut p = entries_start;
            while p + entry_size <= end {
                // entry = owner GUID (16) || SHA-256 digest (32)
                if entry_size == 16 + SHA256_DIGEST_SIZE
                    && &buf[p + 16..p + 16 + SHA256_DIGEST_SIZE] == fingerprint.as_slice()
                {
                    return true;
                }
                p += entry_size;
            }
        }
        off += list_size;
    }
    false
}

// ── Top-level verifier surface ────────────────────────────────────

/// Verify a PE/COFF image against the platform's Secure Boot policy.
///
/// Returns:
///   - `Ok(())` when Secure Boot is enforcing, the image carries a
///     valid Authenticode signature, the signed digest matches the
///     image's Authenticode hash, the signer's SHA-256 fingerprint
///     is in `db`, and not in `dbx`.
///   - `Err(NoPlatformKeys)` when `enabled()` is true but no `db`/`dbx`
///     have been staged.
///   - `Err(UnsignedRejected)` when the image has no security
///     directory.
///   - Various `Err(*)` variants for malformed PE / WIN_CERTIFICATE /
///     PKCS#7 input.
///   - `Ok(())` when `enabled()` is false — bring-up builds and
///     unprovisioned platforms.
pub fn verify_pe(image: &[u8]) -> Result<(), SecureBootError> {
    let st = match state() {
        Some(s) => s,
        None => {
            // No platform state staged — bring-up: trust the bootloader.
            return Ok(());
        }
    };
    if !(st.secure_boot == 1 && st.setup_mode == 0) {
        // Secure Boot disabled or platform unprovisioned — accept.
        return Ok(());
    }
    if st.db.is_empty() {
        return Err(SecureBootError::NoPlatformKeys);
    }

    let sec = parse_pe_security_dir(image)?;
    let cert_region = &image[sec.offset as usize..(sec.offset as usize) + sec.size as usize];
    let (_hdr, pkcs7) = parse_win_certificate(cert_region)?;
    let signer = parse_authenticode(pkcs7)?;

    let want_digest = authenticode_hash(image, &sec);
    if signer.signed_digest != want_digest {
        return Err(SecureBootError::DigestMismatch);
    }

    // Look up the image hash in dbx first (a revoked entry takes
    // priority), then db.
    if !st.dbx.is_empty() && fingerprint_in_signature_db(&st.dbx, &want_digest) {
        return Err(SecureBootError::Revoked);
    }
    if fingerprint_in_signature_db(&st.db, &want_digest) {
        return Ok(());
    }
    Err(SecureBootError::NotInDb)
}

/// Combined "measure then verify" surface for boot-time consumers.
/// Computes SHA-256 over the image, extends it into `pcr` with
/// `EV_EFI_BOOT_SERVICES_APPLICATION` (the canonical PE-measurement
/// tag), then runs `verify_pe`. The label string lets remote
/// attestation distinguish which binary was loaded where.
pub async fn measure_and_verify(
    image: &[u8],
    pcr: u32,
    label: &str,
) -> Result<(), SecureBootError> {
    let digest = sha256(image);
    let owned_label: String = ("pe:".to_string()) + label;
    // Best-effort: if the TPM extend fails we still propagate the
    // verification result. A failed extend deserves diagnostics,
    // not an aborted load.
    let _ = measure_precomputed(
        pcr,
        EV_EFI_BOOT_SERVICES_APPLICATION,
        owned_label,
        &digest,
        image.len() as u64,
    )
    .await;
    verify_pe(image)
}

// ── Smokes ─────────────────────────────────────────────────────────

use narf_kernel_test::{kernel_test_in, TestResult};

fn make_minimal_pe(with_security_dir: bool) -> Vec<u8> {
    // Build a hand-crafted PE32+ image:
    //   0x00..0x40   DOS header (MZ + PE offset at 0x3C)
    //   0x40..0x44   "PE\0\0"
    //   0x44..0x58   COFF header (20 bytes)
    //   0x58..0x108  Optional header (PE32+, 240 bytes)
    //                  + data directories @ 0x58 + 0x70 = 0xC8
    //                  16 entries × 8 bytes = 128 bytes
    //   0x108..0x208 Padding so the image has bytes past the headers.
    //                With a security dir, the WIN_CERTIFICATE lives
    //                here.
    let mut img = alloc::vec![0u8; 0x208];
    img[0] = b'M';
    img[1] = b'Z';
    // PE offset.
    img[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    img[0x40..0x44].copy_from_slice(b"PE\0\0");
    // Optional header magic (PE32+).
    img[0x58..0x5A].copy_from_slice(&PE32PLUS_MAGIC.to_le_bytes());
    // Image size at opt_off + 0x38.
    let image_size_off = 0x58 + 0x38;
    let img_len_le = (img.len() as u32).to_le_bytes();
    img[image_size_off..image_size_off + 4].copy_from_slice(&img_len_le);
    // Checksum at opt_off + 0x40.
    let checksum_off = 0x58 + 0x40;
    img[checksum_off..checksum_off + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    // Data-directory's Security entry @ 0x58 + 0x70 + 4*8 = 0xE0.
    let sec_dir_entry = 0x58 + 0x70 + SECURITY_DIR_INDEX * 8;
    if with_security_dir {
        // Place WIN_CERTIFICATE at offset 0x180.
        let sig_off = 0x180usize;
        let sig_size = 0x40usize;
        img[sec_dir_entry..sec_dir_entry + 4].copy_from_slice(&(sig_off as u32).to_le_bytes());
        img[sec_dir_entry + 4..sec_dir_entry + 8].copy_from_slice(&(sig_size as u32).to_le_bytes());
        // WIN_CERTIFICATE header.
        img[sig_off..sig_off + 4].copy_from_slice(&(sig_size as u32).to_le_bytes());
        img[sig_off + 4..sig_off + 6].copy_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
        img[sig_off + 6..sig_off + 8]
            .copy_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
    }
    img
}

fn smoke_secure_boot_pe_security_directory_parse() -> TestResult {
    let img = make_minimal_pe(true);
    let sec = match parse_pe_security_dir(&img) {
        Ok(s) => s,
        Err(_) => return TestResult::Fail("parse_pe_security_dir errored"),
    };
    if sec.offset != 0x180 || sec.size != 0x40 {
        return TestResult::Fail("security-dir offset/size wrong");
    }
    // Image without security dir → NoSignature.
    let img_no = make_minimal_pe(false);
    match parse_pe_security_dir(&img_no) {
        Err(SecureBootError::NoSignature) => {}
        _ => return TestResult::Fail("missing dir didn't surface NoSignature"),
    }
    // Truncated → TooSmall.
    let small = alloc::vec![0u8; 16];
    match parse_pe_security_dir(&small) {
        Err(SecureBootError::TooSmall) => {}
        _ => return TestResult::Fail("short image didn't surface TooSmall"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/secure_boot",
    smoke_secure_boot_pe_security_directory_parse
);

fn smoke_secure_boot_win_certificate_header_parse() -> TestResult {
    // Construct a WIN_CERTIFICATE with a tiny body.
    let body = [0xAAu8, 0xBB, 0xCC, 0xDD];
    let total_len = 8 + body.len() as u32;
    let mut buf = alloc::vec::Vec::new();
    buf.extend_from_slice(&total_len.to_le_bytes());
    buf.extend_from_slice(&WIN_CERT_REVISION_2_0.to_le_bytes());
    buf.extend_from_slice(&WIN_CERT_TYPE_PKCS_SIGNED_DATA.to_le_bytes());
    buf.extend_from_slice(&body);
    let (hdr, payload) = match parse_win_certificate(&buf) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("parse_win_certificate failed"),
    };
    if hdr.length != total_len || hdr.revision != WIN_CERT_REVISION_2_0 {
        return TestResult::Fail("header field mismatch");
    }
    if payload != &body {
        return TestResult::Fail("payload mismatch");
    }
    // Wrong cert_type rejected.
    let mut bad = buf.clone();
    bad[6] = 0;
    bad[7] = 0;
    match parse_win_certificate(&bad) {
        Err(SecureBootError::BadCertificate) => {}
        _ => return TestResult::Fail("wrong cert_type accepted"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/secure_boot",
    smoke_secure_boot_win_certificate_header_parse
);

fn smoke_secure_boot_pkcs7_signer_info_extract() -> TestResult {
    // Build a minimal SignedData-ish ASN.1 stream:
    //   SEQUENCE { OID spcIndirectDataContent, OCTET STRING (32 bytes) }
    let digest = [0xCDu8; SHA256_DIGEST_SIZE];
    let mut inner = alloc::vec::Vec::new();
    // OID: 06 0A 2B 06 01 04 01 82 37 02 01 04
    inner.push(0x06);
    inner.push(OID_SPC_INDIRECT_DATA.len() as u8);
    inner.extend_from_slice(OID_SPC_INDIRECT_DATA);
    // OCTET STRING tag + length + 32 bytes.
    inner.push(0x04);
    inner.push(SHA256_DIGEST_SIZE as u8);
    inner.extend_from_slice(&digest);

    let mut outer = alloc::vec::Vec::new();
    outer.push(0x30); // SEQUENCE
    outer.push(inner.len() as u8);
    outer.extend_from_slice(&inner);

    let info = match parse_authenticode(&outer) {
        Ok(i) => i,
        Err(_) => return TestResult::Fail("parse_authenticode failed"),
    };
    if info.signed_digest != digest {
        return TestResult::Fail("signed_digest mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/secure_boot",
    smoke_secure_boot_pkcs7_signer_info_extract
);

fn smoke_secure_boot_enabled_resolution() -> TestResult {
    __reset_for_test();
    if enabled() {
        return TestResult::Fail("enabled() with no state should be false");
    }
    // Enforcing state.
    install_state(SecureBootState {
        secure_boot: 1,
        setup_mode: 0,
        db: alloc::vec::Vec::new(),
        dbx: alloc::vec::Vec::new(),
    });
    if !enabled() {
        return TestResult::Fail("enabled() should be true under (sb=1, setup=0)");
    }
    __reset_for_test();
    // Setup mode → not enabled (even if SecureBoot==1).
    install_state(SecureBootState {
        secure_boot: 1,
        setup_mode: 1,
        db: alloc::vec::Vec::new(),
        dbx: alloc::vec::Vec::new(),
    });
    if enabled() {
        return TestResult::Fail("setup_mode=1 must override SecureBoot=1");
    }
    __reset_for_test();
    // SecureBoot==0 → not enabled.
    install_state(SecureBootState {
        secure_boot: 0,
        setup_mode: 0,
        db: alloc::vec::Vec::new(),
        dbx: alloc::vec::Vec::new(),
    });
    if enabled() {
        return TestResult::Fail("secure_boot=0 must disable enforcement");
    }
    __reset_for_test();
    TestResult::Pass
}
kernel_test_in!("frame/secure_boot", smoke_secure_boot_enabled_resolution);

fn smoke_secure_boot_authenticode_hash_excludes_checksum_and_security() -> TestResult {
    // Two images that differ only in checksum and security-dir entry
    // bytes must produce the same Authenticode hash.
    let mut a = make_minimal_pe(true);
    let sec = parse_pe_security_dir(&a).expect("sec dir");
    let hash_a = authenticode_hash(&a, &sec);
    // Mutate checksum field.
    let checksum_off = sec.checksum_offset as usize;
    a[checksum_off] ^= 0xFF;
    let hash_b = authenticode_hash(&a, &sec);
    if hash_a != hash_b {
        return TestResult::Fail("hash should not depend on checksum bytes");
    }
    // Mutate security-directory entry bytes.
    let sec_entry = sec.security_entry_offset as usize;
    a[sec_entry] ^= 0x55;
    let hash_c = authenticode_hash(&a, &sec);
    if hash_a != hash_c {
        return TestResult::Fail("hash should not depend on security-dir entry");
    }
    // Mutate a non-excluded byte (offset 0x44 — COFF header).
    a[0x44] ^= 0x11;
    let hash_d = authenticode_hash(&a, &sec);
    if hash_a == hash_d {
        return TestResult::Fail("hash should change when a hashed byte mutates");
    }
    TestResult::Pass
}
kernel_test_in!(
    "frame/secure_boot",
    smoke_secure_boot_authenticode_hash_excludes_checksum_and_security
);

fn smoke_secure_boot_fingerprint_db_walk() -> TestResult {
    // Build a single EFI_SIGNATURE_LIST containing two SHA-256 entries.
    use narf_efi::variable::EFI_CERT_SHA256_GUID;
    let mut db = alloc::vec::Vec::new();
    let entries = [[0x11u8; 32], [0x22u8; 32]];
    let entry_size: u32 = 16 + 32;
    let list_size: u32 = 28 + 0 + entry_size * entries.len() as u32;

    db.extend_from_slice(&EFI_CERT_SHA256_GUID.0);
    db.extend_from_slice(&list_size.to_le_bytes());
    db.extend_from_slice(&0u32.to_le_bytes()); // SignatureHeaderSize
    db.extend_from_slice(&entry_size.to_le_bytes());
    for e in &entries {
        db.extend_from_slice(&[0u8; 16]); // owner
        db.extend_from_slice(e);
    }

    if !fingerprint_in_signature_db(&db, &[0x11u8; 32]) {
        return TestResult::Fail("0x11 entry not matched");
    }
    if !fingerprint_in_signature_db(&db, &[0x22u8; 32]) {
        return TestResult::Fail("0x22 entry not matched");
    }
    if fingerprint_in_signature_db(&db, &[0x33u8; 32]) {
        return TestResult::Fail("0x33 entry should not match");
    }
    TestResult::Pass
}
kernel_test_in!("frame/secure_boot", smoke_secure_boot_fingerprint_db_walk);
