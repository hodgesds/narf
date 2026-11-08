//! X.509 certificate parsing and chain verification (RFC 5280).
//!
//! Minimal, purpose-built for TLS 1.3 server authentication (RFC 8446
//! §4.4.2): DER parsing of the fields the chain check needs, signature
//! verification, validity windows, and hostname matching.
//!
//! Supported signature algorithms (all SHA-256; the TLS client only
//! advertises SHA-256 schemes, so a chain needing anything else fails
//! closed with [`X509Error::UnsupportedAlgorithm`]):
//! - RSA PKCS#1 v1.5 with SHA-256 (RFC 8017 §8.2) — variable-length
//!   bignum below; the public exponent is small, so square-and-multiply
//!   with bitwise long-division reduction is fast enough for verification.
//! - RSASSA-PSS with SHA-256 (RFC 8017 §8.1), salt length taken from
//!   the algorithm parameters when present, else the digest length.
//! - ECDSA with P-256 and SHA-256, via `narf_crypto::p256::ecdsa`.
//! - Ed25519, via `narf_crypto::ed25519`.
//!
//! Deliberately NOT supported: P-384 / SHA-384, RSA with SHA-384/512,
//! DSA, MD5/SHA-1. A server chain using them is rejected, not silently
//! accepted. Self-consistent fixtures cannot mask a wrong constant
//! here: the chain unit tests verify against openssl-generated certs
//! (see `net/src/tls_fixtures/`) whose signatures openssl itself
//! validates.
//!
//! References (public-only):
//! - RFC 5280 §4.1 — certificate structure, validity, extensions.
//! - RFC 5280 §4.2.1.6 / §4.2.1.9 — basicConstraints, subjectAltName.
//! - RFC 6125 §6.4 — hostname matching (single-label wildcard).
//! - RFC 8017 §8.1/§8.2 — RSASSA-PSS / PKCS#1 v1.5 verification.
//! - RFC 8446 §4.4.2 — the TLS Certificate message and its chain.

use alloc::vec::Vec;
use core::cmp::Ordering;

use narf_crypto::ed25519::{ed25519_verify, PublicKey as EdPublicKey, Signature as EdSignature};
use narf_crypto::p256::ecdsa::verify_p256;
use narf_crypto::rsaes_oaep::mgf1_sha256;
use narf_crypto::sha256::Sha256;

/// Errors from parsing or chain verification. `InvalidSignature`,
/// `Expired`, `NotYetValid`, `UnknownIssuer`, `NotCa` and
/// `HostnameMismatch` are the ones a TLS client surfaces as
/// `bad_certificate` / `certificate_expired` / `unknown_ca` alerts
/// (RFC 8446 §6.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509Error {
    /// Truncated input (length exceeds the remaining bytes).
    Truncated,
    /// Well-formed DER was expected but the structure did not match.
    Malformed,
    /// A signature / public-key algorithm this module does not support.
    UnsupportedAlgorithm,
    /// A signature did not verify, or the signature value is malformed.
    InvalidSignature,
    /// `now` is after the certificate's `notAfter`.
    Expired,
    /// `now` is before the certificate's `notBefore`.
    NotYetValid,
    /// No issuer for the certificate was found in the chain or store.
    UnknownIssuer,
    /// An issuer in the chain is not a CA (`basicConstraints cA` false).
    NotCa,
    /// The leaf is a CA certificate and is not itself a trusted root.
    LeafIsCa,
    /// The chain has no certificates.
    EmptyChain,
    /// The chain walk exceeded the depth bound (cross-issued loop).
    ChainTooLong,
    /// The leaf does not match the expected hostname.
    HostnameMismatch,
}

/// A parsed X.509 certificate. All slices borrow the DER input.
#[derive(Debug, Clone)]
pub struct Certificate<'a> {
    /// The whole DER encoding (used for root pinning by byte equality).
    pub raw: &'a [u8],
    /// The raw `tbsCertificate` TLV (tag + length + content) — exactly
    /// the bytes a signature covers.
    pub tbs: &'a [u8],
    /// The signature value (BIT STRING contents, unused-bits byte
    /// stripped).
    pub signature: &'a [u8],
    /// The certificate's signature algorithm.
    pub signature_alg: SigAlg,
    /// The raw issuer `Name` TLV, for chaining by DER equality.
    pub issuer: &'a [u8],
    /// The raw subject `Name` TLV, for chaining by DER equality.
    pub subject: &'a [u8],
    /// `notBefore`, Unix seconds.
    pub not_before: u64,
    /// `notAfter`, Unix seconds.
    pub not_after: u64,
    /// The subject public key.
    pub spki: Spki<'a>,
    /// `basicConstraints cA` (absent extension means "not a CA").
    pub is_ca: bool,
    /// `subjectAltName` dNSName entries (IA5 bytes).
    pub san_dns: Vec<&'a [u8]>,
    /// The subject commonName, if any (string content bytes).
    pub cn: Option<&'a [u8]>,
}

/// The subject public key of a certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Spki<'a> {
    /// RSA: modulus and public exponent. Modulus bytes are big-endian
    /// with any leading zero stripped.
    Rsa {
        /// Modulus, big-endian.
        n: &'a [u8],
        /// Public exponent.
        e: u32,
    },
    /// ECDSA P-256: the uncompressed point (`0x04 || X || Y`, 65 bytes).
    EcP256 {
        /// Uncompressed point.
        point: &'a [u8],
    },
    /// Ed25519: the 32-byte public key.
    Ed25519 {
        /// Public key.
        point: &'a [u8],
    },
}

/// Signature algorithms this module verifies (SHA-256 only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlg {
    /// `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
    RsaPkcs1Sha256,
    /// `rsassaPss` (1.2.840.113549.1.1.10) with SHA-256.
    RsaPssSha256 {
        /// Salt length from the algorithm parameters.
        salt_len: usize,
    },
    /// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
    EcdsaP256Sha256,
    /// Ed25519 (1.3.101.112).
    Ed25519,
    /// Anything else — rejected, never verified.
    Unsupported,
}

// ─── DER ────────────────────────────────────────────────────────────────────

const TAG_BOOLEAN: u8 = 0x01;
const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_UTF8_STRING: u8 = 0x0c;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_SET: u8 = 0x31;
const TAG_PRINTABLE_STRING: u8 = 0x13;
const TAG_IA5_STRING: u8 = 0x16;
const TAG_UTCTIME: u8 = 0x17;
const TAG_GENERALIZED_TIME: u8 = 0x18;
const TAG_CONTEXT_0: u8 = 0xa0;
const TAG_CONTEXT_2: u8 = 0xa2;
const TAG_CONTEXT_3: u8 = 0xa3;
const TAG_DNS_NAME: u8 = 0x82;

/// A cursor over DER bytes.
struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn read_byte(&mut self) -> Result<u8, X509Error> {
        if self.pos >= self.buf.len() {
            return Err(X509Error::Truncated);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_len(&mut self) -> Result<usize, X509Error> {
        let b = self.read_byte()?;
        if b & 0x80 == 0 {
            return Ok(b as usize);
        }
        let n = (b & 0x7f) as usize;
        // Indefinite length (0x80) is forbidden in DER; lengths over
        // 64 KiB cannot occur in a certificate we accept.
        if n == 0 || n > 2 {
            return Err(X509Error::Malformed);
        }
        let mut len = 0usize;
        for _ in 0..n {
            len = (len << 8) | self.read_byte()? as usize;
        }
        Ok(len)
    }

    /// Read one TLV, returning (tag, content). The raw TLV span is
    /// `&buf[start..self.pos]`; callers that need it (tbsCertificate,
    /// issuer/subject Name) record `pos` before the call.
    fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), X509Error> {
        let tag = self.read_byte()?;
        let len = self.read_len()?;
        if len > self.remaining() {
            return Err(X509Error::Truncated);
        }
        let content = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok((tag, content))
    }

    fn expect(&mut self, tag: u8) -> Result<&'a [u8], X509Error> {
        let (t, c) = self.read_tlv()?;
        if t != tag {
            return Err(X509Error::Malformed);
        }
        Ok(c)
    }

    fn expect_sequence(&mut self) -> Result<Der<'a>, X509Error> {
        Ok(Der::new(self.expect(TAG_SEQUENCE)?))
    }

    /// Skip one TLV of any tag.
    fn skip(&mut self) -> Result<(), X509Error> {
        let _ = self.read_tlv()?;
        Ok(())
    }

    fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }
}

// OID contents (tag and length stripped) for the algorithms and
// extensions this module recognises.
const OID_SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const OID_RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];

/// Parse an algorithm identifier SEQUENCE into (OID, params content).
/// Params are returned as the raw content of the second element, or
/// `None` when absent.
fn parse_alg_id(content: &[u8]) -> Result<(&[u8], Option<&[u8]>), X509Error> {
    let mut d = Der::new(content);
    let oid = d.expect(TAG_OID)?;
    let params = if d.at_end() {
        None
    } else {
        let (tag, c) = d.read_tlv()?;
        if tag == TAG_NULL {
            None
        } else {
            Some(c)
        }
    };
    Ok((oid, params))
}

/// Extract the salt length from RSASSA-PSS parameters
/// (RFC 4055 §3.1): `SEQUENCE { [0] hashAlg, [1] mgf, [2] saltLength,
/// [3] trailerField }`. Absent or unparsable parameters default to the
/// digest length (32), which is what TLS 1.3 mandates for
/// CertificateVerify (RFC 8446 §4.4.3) and what openssl emits.
fn pss_salt_len(params: Option<&[u8]>) -> usize {
    let Some(p) = params else {
        return 32;
    };
    let mut d = Der::new(p);
    while !d.at_end() {
        let Ok((tag, content)) = d.read_tlv() else {
            return 32;
        };
        if tag == TAG_CONTEXT_2 {
            // [2] EXPLICIT INTEGER saltLength.
            let mut inner = Der::new(content);
            if let Ok(i) = inner.expect(TAG_INTEGER) {
                if let Some(v) = int_to_u32(i) {
                    return v as usize;
                }
            }
            return 32;
        }
    }
    32
}

/// A DER INTEGER's value as u32, or `None` when it does not fit / is
/// negative. A leading 0x00 (sign padding) is stripped.
fn int_to_u32(bytes: &[u8]) -> Option<u32> {
    let mut b = bytes;
    while !b.is_empty() && b[0] == 0 {
        b = &b[1..];
    }
    if b.is_empty() || b.len() > 4 {
        return None;
    }
    let mut v: u32 = 0;
    for &x in b {
        v = (v << 8) | x as u32;
    }
    Some(v)
}

/// A DER INTEGER's value as big-endian bytes with sign padding
/// stripped.
fn int_bytes(bytes: &[u8]) -> &[u8] {
    let mut b = bytes;
    while b.len() > 1 && b[0] == 0 {
        b = &b[1..];
    }
    b
}

/// Days from civil date (Howard Hinnant's algorithm), days since
/// 1970-01-01.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = ((m + 9) % 12) as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse a UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime
/// (`YYYYMMDDHHMMSSZ`) into Unix seconds. RFC 5280 §4.1.2.5.1: UTCTime
/// years 00–49 are 20YY, 50–99 are 19YY.
fn parse_time(tag: u8, content: &[u8]) -> Result<u64, X509Error> {
    let digits = |b: u8| -> Result<u32, X509Error> {
        if !b.is_ascii_digit() {
            return Err(X509Error::Malformed);
        }
        Ok((b - b'0') as u32)
    };
    let (year, rest): (i64, &[u8]) = match tag {
        TAG_UTCTIME => {
            if content.len() != 13 || content[12] != b'Z' {
                return Err(X509Error::Malformed);
            }
            let yy = digits(content[0])? * 10 + digits(content[1])?;
            let year = if yy < 50 { 2000 + yy } else { 1900 + yy } as i64;
            (year, &content[2..12])
        }
        TAG_GENERALIZED_TIME => {
            if content.len() != 15 || content[14] != b'Z' {
                return Err(X509Error::Malformed);
            }
            let mut year: i64 = 0;
            for &b in &content[0..4] {
                year = year * 10 + digits(b)? as i64;
            }
            (year, &content[4..14])
        }
        _ => return Err(X509Error::Malformed),
    };
    let num =
        |i: usize| -> Result<u32, X509Error> { Ok(digits(rest[i])? * 10 + digits(rest[i + 1])?) };
    let month = num(0)?;
    let day = num(2)?;
    let hour = num(4)?;
    let min = num(6)?;
    let sec = num(8)?;
    if !(1..=12).contains(&month) || day == 0 || day > 31 || hour > 23 || min > 59 || sec > 60 {
        return Err(X509Error::Malformed);
    }
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour as i64 * 3_600 + min as i64 * 60 + sec as i64;
    if secs < 0 {
        return Err(X509Error::Malformed);
    }
    Ok(secs as u64)
}

/// Parse the subjectPublicKeyInfo SEQUENCE content.
fn parse_spki(content: &[u8]) -> Result<Spki<'_>, X509Error> {
    let mut d = Der::new(content);
    let alg = d.expect_sequence()?;
    let (oid, params) = parse_alg_id(alg.buf)?;
    let key_bits = d.expect(TAG_BIT_STRING)?;
    if key_bits.is_empty() || key_bits[0] != 0 {
        return Err(X509Error::Malformed);
    }
    let key = &key_bits[1..];
    match oid {
        OID_RSA_ENCRYPTION => {
            let mut kd = Der::new(key);
            let mut seq = kd.expect_sequence()?;
            let n = int_bytes(seq.expect(TAG_INTEGER)?);
            let e = int_to_u32(seq.expect(TAG_INTEGER)?).ok_or(X509Error::Malformed)?;
            if n.is_empty() || e == 0 {
                return Err(X509Error::Malformed);
            }
            Ok(Spki::Rsa { n, e })
        }
        OID_EC_PUBLIC_KEY => {
            let Some(curve) = params else {
                return Err(X509Error::UnsupportedAlgorithm);
            };
            if curve != OID_PRIME256V1 {
                return Err(X509Error::UnsupportedAlgorithm);
            }
            if key.len() != 65 || key[0] != 0x04 {
                return Err(X509Error::Malformed);
            }
            Ok(Spki::EcP256 { point: key })
        }
        OID_ED25519 => {
            if key.len() != 32 {
                return Err(X509Error::Malformed);
            }
            Ok(Spki::Ed25519 { point: key })
        }
        _ => Err(X509Error::UnsupportedAlgorithm),
    }
}

/// Parse the extensions `[3] EXPLICIT SEQUENCE OF Extension`, filling
/// in `is_ca` and `san_dns` on the certificate under construction.
fn parse_extensions<'a>(
    content: &'a [u8],
    is_ca: &mut bool,
    san_dns: &mut Vec<&'a [u8]>,
) -> Result<(), X509Error> {
    // content is the [3] value: a SEQUENCE of extensions.
    let mut d = Der::new(content);
    let mut exts = d.expect_sequence()?;
    while !exts.at_end() {
        let mut e = exts.expect_sequence()?;
        let oid = e.expect(TAG_OID)?;
        // Optional BOOLEAN critical.
        let value_tag;
        let value;
        let (t, c) = e.read_tlv()?;
        if t == TAG_BOOLEAN {
            let (t2, c2) = e.read_tlv()?;
            value_tag = t2;
            value = c2;
        } else {
            value_tag = t;
            value = c;
        }
        if value_tag != TAG_OCTET_STRING {
            return Err(X509Error::Malformed);
        }
        if oid == OID_BASIC_CONSTRAINTS {
            let mut v = Der::new(value);
            let mut b = v.expect_sequence()?;
            if !b.at_end() {
                let (t, c) = b.read_tlv()?;
                if t == TAG_BOOLEAN && !c.is_empty() && c[0] != 0 {
                    *is_ca = true;
                }
            }
        } else if oid == OID_SUBJECT_ALT_NAME {
            let mut v = Der::new(value);
            let mut n = v.expect_sequence()?;
            while !n.at_end() {
                let (t, c) = n.read_tlv()?;
                if t == TAG_DNS_NAME {
                    san_dns.push(c);
                }
            }
        }
        // All other extensions are ignored.
    }
    Ok(())
}

/// Find the commonName in a subject Name: RDNSequence is a SEQUENCE of
/// SETs of SEQUENCEs { OID, value }.
fn find_cn(name: &[u8]) -> Option<&[u8]> {
    let mut d = Der::new(name);
    let mut rdns = d.expect_sequence().ok()?;
    while !rdns.at_end() {
        let set = rdns.expect(TAG_SET).ok()?;
        let mut atvs = Der::new(set);
        while !atvs.at_end() {
            let mut a = atvs.expect_sequence().ok()?;
            let oid = a.expect(TAG_OID).ok()?;
            let (tag, value) = a.read_tlv().ok()?;
            if oid == OID_COMMON_NAME
                && (tag == TAG_UTF8_STRING || tag == TAG_PRINTABLE_STRING || tag == TAG_IA5_STRING)
            {
                return Some(value);
            }
        }
    }
    None
}

/// Parse one DER certificate.
pub fn parse_certificate(der: &[u8]) -> Result<Certificate<'_>, X509Error> {
    let mut d = Der::new(der);
    let cert = d.expect(TAG_SEQUENCE)?;
    if !d.at_end() {
        return Err(X509Error::Malformed);
    }
    let mut c = Der::new(cert);

    // tbsCertificate — record the raw TLV span: the signature covers
    // exactly these bytes.
    let tbs_start = c.pos;
    let (tbs_tag, tbs_content) = c.read_tlv()?;
    let tbs = &cert[tbs_start..c.pos];
    if tbs_tag != TAG_SEQUENCE {
        return Err(X509Error::Malformed);
    }
    let mut t = Der::new(tbs_content);

    // Optional [0] EXPLICIT version.
    if !t.at_end() {
        let save = t.pos;
        if let Ok((tag, _)) = t.read_tlv() {
            if tag != TAG_CONTEXT_0 {
                t.pos = save;
            }
        } else {
            return Err(X509Error::Malformed);
        }
    }
    t.skip()?; // serialNumber
    let sig_alg_seq = t.expect_sequence()?;
    let (sig_oid, sig_params) = parse_alg_id(sig_alg_seq.buf)?;
    let signature_alg = match sig_oid {
        OID_SHA256_WITH_RSA => SigAlg::RsaPkcs1Sha256,
        OID_RSASSA_PSS => SigAlg::RsaPssSha256 {
            salt_len: pss_salt_len(sig_params),
        },
        OID_ECDSA_WITH_SHA256 => SigAlg::EcdsaP256Sha256,
        OID_ED25519 => SigAlg::Ed25519,
        _ => SigAlg::Unsupported,
    };
    let issuer_start = t.pos;
    let _ = t.read_tlv()?; // issuer Name
    let issuer = &tbs_content[issuer_start..t.pos];
    // Validity.
    let mut v = t.expect_sequence()?;
    let (t1_tag, t1) = v.read_tlv()?;
    let not_before = parse_time(t1_tag, t1)?;
    let (t2_tag, t2) = v.read_tlv()?;
    let not_after = parse_time(t2_tag, t2)?;
    let subject_start = t.pos;
    let _ = t.read_tlv()?; // subject Name
    let subject = &tbs_content[subject_start..t.pos];
    let spki_seq = t.expect_sequence()?;
    let spki = parse_spki(spki_seq.buf)?;

    // Optional [1] issuerUniqueID, [2] subjectUniqueID, [3] extensions.
    let mut is_ca = false;
    let mut san_dns: Vec<&[u8]> = Vec::new();
    while !t.at_end() {
        let (tag, content) = t.read_tlv()?;
        match tag {
            TAG_CONTEXT_3 => parse_extensions(content, &mut is_ca, &mut san_dns)?,
            TAG_CONTEXT_0 | TAG_CONTEXT_2 => {}
            _ => return Err(X509Error::Malformed),
        }
    }

    // Outer signatureAlgorithm must match the one inside tbs (RFC 5280
    // §4.1.1.2); a mismatch means the cert is malformed.
    let outer_alg = c.expect_sequence()?;
    let (outer_oid, _) = parse_alg_id(outer_alg.buf)?;
    if outer_oid != sig_oid {
        return Err(X509Error::Malformed);
    }
    let sig_bits = c.expect(TAG_BIT_STRING)?;
    if sig_bits.is_empty() || sig_bits[0] != 0 {
        return Err(X509Error::Malformed);
    }
    let signature = &sig_bits[1..];

    let cn = find_cn(subject);

    Ok(Certificate {
        raw: der,
        tbs,
        signature,
        signature_alg,
        issuer,
        subject,
        not_before,
        not_after,
        spki,
        is_ca,
        san_dns,
        cn,
    })
}

// ─── RSA bignum (verification only; public exponent is small) ───────────────

/// Big-endian bytes → little-endian u64 limbs, trailing zero limbs
/// stripped.
fn be_to_limbs(bytes: &[u8]) -> Vec<u64> {
    let mut limbs = Vec::with_capacity(bytes.len().div_ceil(8));
    let mut i = bytes.len();
    while i > 0 {
        let take = i.min(8);
        let start = i - take;
        let mut limb: u64 = 0;
        for &b in &bytes[start..i] {
            limb = (limb << 8) | b as u64;
        }
        limbs.push(limb);
        i = start;
    }
    while limbs.len() > 1 && limbs[limbs.len() - 1] == 0 {
        limbs.pop();
    }
    limbs
}

/// Little-endian limbs → big-endian bytes of exactly `len` bytes.
fn limbs_to_be(limbs: &[u64], len: usize) -> Vec<u8> {
    let mut out = alloc::vec![0u8; len];
    for (i, &limb) in limbs.iter().enumerate() {
        for j in 0..8 {
            let idx = i * 8 + j;
            if idx >= len {
                break;
            }
            out[len - 1 - idx] = (limb >> (8 * j)) as u8;
        }
    }
    out
}

fn cmp_limbs(a: &[u64], b: &[u64]) -> Ordering {
    let mut alen = a.len();
    while alen > 1 && a[alen - 1] == 0 {
        alen -= 1;
    }
    let mut blen = b.len();
    while blen > 1 && b[blen - 1] == 0 {
        blen -= 1;
    }
    if alen != blen {
        return alen.cmp(&blen);
    }
    for i in (0..alen).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    Ordering::Equal
}

/// `a - b`, requires `a >= b`. Result has `a.len()` limbs.
fn sub_limbs(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow: u64 = 0;
    for i in 0..a.len() {
        let bi = if i < b.len() { b[i] } else { 0 };
        let (r1, b1) = a[i].overflowing_sub(bi);
        let (r2, b2) = r1.overflowing_sub(borrow);
        borrow = (b1 || b2) as u64;
        out.push(r2);
    }
    out
}

/// Schoolbook multiplication.
fn mul_limbs(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = alloc::vec![0u64; a.len() + b.len()];
    for (i, &ai) in a.iter().enumerate() {
        let mut carry: u64 = 0;
        for (j, &bj) in b.iter().enumerate() {
            let prod = (ai as u128) * (bj as u128) + (out[i + j] as u128) + (carry as u128);
            out[i + j] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        let mut k = i + b.len();
        while carry != 0 {
            let sum = (out[k] as u128) + (carry as u128);
            out[k] = sum as u64;
            carry = (sum >> 64) as u64;
            k += 1;
        }
    }
    while out.len() > 1 && out[out.len() - 1] == 0 {
        out.pop();
    }
    out
}

/// `prod mod n` by bitwise long division: shift the remainder left one
/// bit at a time and subtract `n` whenever the remainder reaches it.
/// `prod` has at most twice the limbs of `n`.
fn mod_reduce(prod: &[u64], n: &[u64]) -> Vec<u64> {
    let mut rem = alloc::vec![0u64; n.len() + 1];
    let total_bits = prod.len() * 64;
    for bit in (0..total_bits).rev() {
        // rem <<= 1
        let mut carry: u64 = 0;
        for limb in rem.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        // rem |= bit
        rem[0] |= (prod[bit / 64] >> (bit % 64)) & 1;
        if cmp_limbs(&rem, n) != Ordering::Less {
            rem = sub_limbs(&rem, n);
            // sub_limbs returns a.len() limbs; rem was n.len()+1, and
            // the subtraction cannot borrow past the top, so the extra
            // limb stays 0. Pad back to n.len()+1 for the next round.
            rem.resize(n.len() + 1, 0);
        }
    }
    while rem.len() > 1 && rem[rem.len() - 1] == 0 {
        rem.pop();
    }
    rem
}

fn mod_mul(a: &[u64], b: &[u64], n: &[u64]) -> Vec<u64> {
    mod_reduce(&mul_limbs(a, b), n)
}

/// RSA public operation: `sig^e mod n`, returned as big-endian bytes
/// of the modulus length. `None` when the signature is `>= n` or the
/// inputs are empty.
fn rsa_public_op(n_bytes: &[u8], e: u32, sig: &[u8]) -> Option<Vec<u8>> {
    if n_bytes.is_empty() || sig.is_empty() || sig.len() > n_bytes.len() {
        return None;
    }
    let n = be_to_limbs(n_bytes);
    let base = be_to_limbs(sig);
    if cmp_limbs(&base, &n) != Ordering::Less {
        return None;
    }
    let mut result = alloc::vec![1u64];
    for bit in (0..32).rev() {
        result = mod_mul(&result, &result, &n);
        if (e >> bit) & 1 == 1 {
            result = mod_mul(&result, &base, &n);
        }
    }
    Some(limbs_to_be(&result, n_bytes.len()))
}

/// DigestInfo prefix for SHA-256 (RFC 8017 §9.2, note 1):
/// `DigestInfo ::= SEQUENCE { digestAlgorithm SHA-256, digest OCTET
/// STRING }` with the digest value stripped.
const SHA256_DIGESTINFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// PKCS#1 v1.5 verification (RFC 8017 §8.2.2): `EM = 00 || 01 ||
/// PS(FF…) || 00 || DigestInfo(SHA-256, digest)`, `PS` at least 8 bytes.
pub(crate) fn pkcs1_v15_verify_sha256(n: &[u8], e: u32, sig: &[u8], digest: &[u8; 32]) -> bool {
    let Some(em) = rsa_public_op(n, e, sig) else {
        return false;
    };
    if em.len() < SHA256_DIGESTINFO_PREFIX.len() + 32 + 11 {
        return false;
    }
    if em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }
    let mut i = 2;
    while i < em.len() && em[i] == 0xff {
        i += 1;
    }
    if i - 2 < 8 || i >= em.len() || em[i] != 0x00 {
        return false;
    }
    i += 1;
    if em.len() - i != SHA256_DIGESTINFO_PREFIX.len() + 32 {
        return false;
    }
    em[i..i + SHA256_DIGESTINFO_PREFIX.len()] == SHA256_DIGESTINFO_PREFIX
        && em[i + SHA256_DIGESTINFO_PREFIX.len()..] == *digest
}

/// RSASSA-PSS verification (RFC 8017 §9.1.2) with SHA-256, MGF1-SHA-256
/// and the given salt length. `emBits = modBits - 1`.
pub(crate) fn pss_verify_sha256(
    n: &[u8],
    e: u32,
    sig: &[u8],
    digest: &[u8; 32],
    salt_len: usize,
) -> bool {
    let Some(em_full) = rsa_public_op(n, e, sig) else {
        return false;
    };
    // Modulus bit length.
    let mod_bits = (n.len() - 1) * 8 + (8 - n[0].leading_zeros() as usize);
    let em_bits = mod_bits - 1;
    let em_len = em_bits.div_ceil(8);
    let h_len = 32usize;
    if em_len < h_len + salt_len + 2 || em_full.len() < em_len {
        return false;
    }
    // The encoded message is the last em_len bytes; any leading bytes
    // of the modulus-length buffer must be zero.
    let em = &em_full[em_full.len() - em_len..];
    if em_full[..em_full.len() - em_len].iter().any(|&b| b != 0) {
        return false;
    }
    // The leftmost (8*em_len - em_bits) bits of EM must be zero.
    let top_bits = 8 * em_len - em_bits;
    if top_bits > 0 && (em[0] >> (8 - top_bits)) != 0 {
        return false;
    }
    if em[em_len - 1] != 0xbc {
        return false;
    }
    let masked_db = &em[..em_len - h_len - 1];
    let h = &em[em_len - h_len - 1..em_len - 1];
    let db_mask = mgf1_sha256(h, em_len - h_len - 1);
    let mut db = Vec::with_capacity(masked_db.len());
    for (i, &b) in masked_db.iter().enumerate() {
        db.push(b ^ db_mask[i]);
    }
    if top_bits > 0 && (db[0] >> (8 - top_bits)) != 0 {
        return false;
    }
    // DB = PS(00…) || 0x01 || salt.
    let db_len = em_len - h_len - 1;
    if db_len < salt_len + 1 {
        return false;
    }
    let sep = db_len - salt_len - 1;
    if db[..sep].iter().any(|&b| b != 0) || db[sep] != 0x01 {
        return false;
    }
    let salt = &db[sep + 1..];
    let mut hasher = Sha256::new();
    hasher.update(&[0u8; 8]);
    hasher.update(digest);
    hasher.update(salt);
    let h_prime = hasher.finalize();
    h_prime[..] == h[..]
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}

/// Verify `subject`'s signature with `issuer`'s public key. Returns
/// `false` for unsupported algorithms, malformed signatures and key
/// mismatches alike — the caller maps all of these to
/// `bad_certificate`.
pub fn verify_cert_signature(issuer: &Certificate, subject: &Certificate) -> bool {
    let digest = sha256(subject.tbs);
    match subject.signature_alg {
        SigAlg::RsaPkcs1Sha256 => match &issuer.spki {
            Spki::Rsa { n, e } => pkcs1_v15_verify_sha256(n, *e, subject.signature, &digest),
            _ => false,
        },
        SigAlg::RsaPssSha256 { salt_len } => match &issuer.spki {
            Spki::Rsa { n, e } => pss_verify_sha256(n, *e, subject.signature, &digest, salt_len),
            _ => false,
        },
        SigAlg::EcdsaP256Sha256 => match &issuer.spki {
            Spki::EcP256 { point } => {
                // Signature is DER SEQUENCE { INTEGER r, INTEGER s }.
                let mut d = Der::new(subject.signature);
                let Ok(mut s) = d.expect_sequence() else {
                    return false;
                };
                let Ok(r) = s.expect(TAG_INTEGER) else {
                    return false;
                };
                let Ok(sv) = s.expect(TAG_INTEGER) else {
                    return false;
                };
                let Some(r32) = int_to_fixed32(r) else {
                    return false;
                };
                let Some(s32) = int_to_fixed32(sv) else {
                    return false;
                };
                verify_p256(point, &digest, &r32, &s32)
            }
            _ => false,
        },
        SigAlg::Ed25519 => match &issuer.spki {
            Spki::Ed25519 { point } => {
                let Ok(pk): Result<EdPublicKey, _> = (*point).try_into() else {
                    return false;
                };
                let Ok(sig): Result<EdSignature, _> = subject.signature.try_into() else {
                    return false;
                };
                ed25519_verify(&pk, subject.tbs, &sig)
            }
            _ => false,
        },
        SigAlg::Unsupported => false,
    }
}

/// A DER INTEGER as a fixed 32-byte big-endian value (for ECDSA r/s).
/// Leading sign padding is stripped; values longer than 32 bytes are
/// rejected.
pub(crate) fn int_to_fixed32(bytes: &[u8]) -> Option<[u8; 32]> {
    let b = int_bytes(bytes);
    if b.is_empty() || b.len() > 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Some(out)
}

// ─── Chain verification ─────────────────────────────────────────────────────

/// Check a certificate's validity window against `now` (Unix seconds).
fn check_validity(cert: &Certificate, now: u64) -> Result<(), X509Error> {
    if now < cert.not_before {
        return Err(X509Error::NotYetValid);
    }
    if now > cert.not_after {
        return Err(X509Error::Expired);
    }
    Ok(())
}

/// Case-insensitive DNS-name match; a `*.` prefix matches exactly one
/// left-hand label (RFC 6125 §6.4.3). Patterns and hosts are ASCII
/// (dNSName is IA5; IDNA hosts are out of scope).
fn dns_matches(pattern: &[u8], host: &str) -> bool {
    let host_b = host.as_bytes();
    if pattern.len() == host_b.len() && pattern.eq_ignore_ascii_case(host_b) {
        return true;
    }
    if pattern.len() > 2 && pattern[0] == b'*' && pattern[1] == b'.' {
        let suffix = &pattern[1..];
        if host_b.len() > suffix.len()
            && host_b[host_b.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        {
            let left = &host_b[..host_b.len() - suffix.len()];
            if !left.is_empty() && !left.contains(&b'.') {
                return true;
            }
        }
    }
    false
}

/// Hostname check against the leaf: SAN dNSNames win when present;
/// otherwise the subject CN is used (RFC 6125 §6.4.4 fallback).
fn verify_hostname(leaf: &Certificate, hostname: &str) -> Result<(), X509Error> {
    if !leaf.san_dns.is_empty() {
        for san in &leaf.san_dns {
            if dns_matches(san, hostname) {
                return Ok(());
            }
        }
        return Err(X509Error::HostnameMismatch);
    }
    match leaf.cn {
        Some(cn) if dns_matches(cn, hostname) => Ok(()),
        _ => Err(X509Error::HostnameMismatch),
    }
}

/// A trust store: a set of DER root certificates, provisioned at
/// runtime. The store starts empty — there are no baked-in public
/// roots; callers add roots via [`RootStore::add_root_der`] (for
/// example from a provisioned Mozilla bundle or an enterprise CA).
/// Fixtures build a store from a baked-in test CA.
#[derive(Debug, Default)]
pub struct RootStore<'a> {
    roots: Vec<Certificate<'a>>,
}

impl<'a> RootStore<'a> {
    /// An empty store, trusting nothing.
    pub fn new() -> Self {
        Self { roots: Vec::new() }
    }

    /// Add a DER root certificate to the store. The certificate must
    /// parse; its DER bytes must outlive the store. Any parseable
    /// certificate may be pinned — the pin itself is the trust
    /// decision (this is what lets a self-signed server certificate,
    /// such as the RFC 8448 test cert with `CA:FALSE`, serve as a
    /// trust anchor). The `CA` bit is still enforced where it matters:
    /// [`RootStore::verify_chain`] rejects a parent that is not a CA,
    /// so a pinned non-CA certificate can authenticate only itself
    /// as a leaf, never as an issuer.
    pub fn add_root_der(&mut self, der: &'a [u8]) -> Result<(), X509Error> {
        let cert = parse_certificate(der)?;
        self.roots.push(cert);
        Ok(())
    }

    /// Verify a certificate chain ending at a trusted root.
    ///
    /// `chain[0]` is the leaf; the remaining entries are intermediates
    /// in any order. Each certificate's signature must verify with its
    /// issuer's key, every issuer must be a CA, every certificate must
    /// be within its validity window at `now`, and the chain must
    /// terminate at a self-signed certificate present in the store.
    /// When `hostname` is `Some`, the leaf must match it.
    pub fn verify_chain(
        &self,
        chain: &[Certificate],
        hostname: Option<&str>,
        now_unix: u64,
    ) -> Result<(), X509Error> {
        if chain.is_empty() {
            return Err(X509Error::EmptyChain);
        }
        let leaf = &chain[0];
        // A CA certificate presented as the leaf is a misissuance —
        // unless the leaf IS a pinned root (a trust-store pin overrides
        // the shape check).
        let leaf_is_root = self.roots.iter().any(|r| r.raw == leaf.raw);
        if leaf.is_ca && !leaf_is_root {
            return Err(X509Error::LeafIsCa);
        }
        for cert in chain {
            check_validity(cert, now_unix)?;
        }
        if let Some(host) = hostname {
            verify_hostname(leaf, host)?;
        }

        let mut current = leaf;
        for _ in 0..8 {
            // A self-signed certificate terminates the chain — but
            // only at a pinned root. This is how a pinned
            // self-signed leaf authenticates (e.g. the RFC 8448
            // test cert, whose CA bit is FALSE): the pin is the
            // trust decision, and the CA bit is irrelevant because
            // the cert issues nothing — it IS the endpoint. A
            // self-signed cert that is not pinned is untrusted.
            if current.subject == current.issuer {
                if self.roots.iter().any(|r| r.raw == current.raw) {
                    if !verify_cert_signature(current, current) {
                        return Err(X509Error::InvalidSignature);
                    }
                    return Ok(());
                }
                return Err(X509Error::UnknownIssuer);
            }
            // Find the parent: any chain entry whose subject matches
            // the current issuer, else a store root.
            let parent: &Certificate = match chain.iter().find(|c| c.subject == current.issuer) {
                Some(p) => p,
                None => match self.roots.iter().find(|r| r.subject == current.issuer) {
                    Some(r) => r,
                    None => return Err(X509Error::UnknownIssuer),
                },
            };
            if !parent.is_ca {
                return Err(X509Error::NotCa);
            }
            check_validity(parent, now_unix)?;
            if !verify_cert_signature(parent, current) {
                return Err(X509Error::InvalidSignature);
            }
            current = parent;
        }
        Err(X509Error::ChainTooLong)
    }
}
