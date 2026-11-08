//! TLS 1.3 client (RFC 8446) over the in-tree software crypto.
//!
//! A transport-agnostic, synchronous client: handshake + HKDF key
//! schedule + AEAD record protection + server certificate-chain
//! verification. No PSK, no 0-RTT, no early data, no resumption —
//! those are remainders, documented at the bottom of this file.
//!
//! Ciphersuites: `TLS_AES_128_GCM_SHA256` (0x1301) and
//! `TLS_CHACHA20_POLY1305_SHA256` (0x1302) only — the in-tree HKDF is
//! SHA-256 only, so there is no SHA-384 suite and no P-384. Key
//! exchange is X25519 only; the signature schemes offered are
//! `rsa_pkcs1_sha256`, `ecdsa_secp256r1_sha256`,
//! `rsa_pss_rsae_sha256` and `ed25519` (all SHA-256).
//!
//! The root store starts empty: there are no baked-in public roots.
//! Callers provision roots with [`RootStore::add_root_der`] (for
//! example from a provisioned Mozilla bundle or an enterprise CA).
//! Fixtures build a store from a baked-in test CA. The client never
//! accepts a chain it cannot verify against the provisioned store.
//!
//! Certificate validity needs a correct clock: the caller passes
//! `now_unix` (production callers pass the wall clock). There is no
//! SNTP/NTP client in the tree yet, so the clock's accuracy is the
//! caller's responsibility — a wrong clock fails closed (expired /
//! not-yet-valid) rather than silently accepting.
//!
//! References (public-only):
//! - RFC 8446 — the TLS 1.3 protocol (handshake §4, record layer §5,
//!   key schedule §7, alerts §6).
//! - RFC 8448 §3 — the full-handshake trace the fixture reproduces
//!   byte-exactly (see `tls_client_tests.rs`).
//! - RFC 7748 §5 — X25519.
//!
//! Remainders (not implemented, fail closed where a peer offers them):
//! - PSK / session resumption / 0-RTT / early data: the client offers
//!   no PSK modes, so a server cannot negotiate them.
//! - Client authentication: the client has no certificate to offer;
//!   a `CertificateRequest` is answered with an empty `Certificate`
//!   (and no `CertificateVerify`), per RFC 8446 §4.4.2/§4.4.3.
//! - `NewSessionTicket` messages are parsed and discarded.
//! - P-384 / SHA-384: no SHA-384 HKDF in tree.

use alloc::vec::Vec;
use core::fmt::{Debug, Formatter};

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Key as GcmKey, Nonce as GcmNonce,
};
use narf_crypto::aead::{chacha20_poly1305_open, chacha20_poly1305_seal};
use narf_crypto::ed25519::{ed25519_verify, PublicKey as EdPublicKey, Signature as EdSignature};
use narf_crypto::hkdf::{hkdf_expand, hkdf_extract, hmac_sha256};
use narf_crypto::p256::ecdsa::verify_p256;
use narf_crypto::try_fill_random_bytes;

use crate::tls::{
    ALERT_BAD_CERTIFICATE, ALERT_BAD_RECORD_MAC, ALERT_CERTIFICATE_EXPIRED, ALERT_CLOSE_NOTIFY,
    ALERT_DECODE_ERROR, ALERT_DECRYPT_ERROR, ALERT_HANDSHAKE_FAILURE, ALERT_ILLEGAL_PARAMETER,
    ALERT_PROTOCOL_VERSION, ALERT_UNEXPECTED_MESSAGE, ALERT_UNKNOWN_CA,
    ALERT_UNSUPPORTED_CERTIFICATE, CIPHER_TLS_AES_128_GCM_SHA256,
    CIPHER_TLS_CHACHA20_POLY1305_SHA256, CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA,
    CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_HANDSHAKE, EXT_COOKIE, EXT_EARLY_DATA,
    EXT_EXTENDED_MASTER_SECRET, EXT_KEY_SHARE, EXT_PSK_KEY_EXCHANGE_MODES, EXT_RECORD_SIZE_LIMIT,
    EXT_RENEGOTIATION_INFO, EXT_SERVER_NAME, EXT_SIGNATURE_ALGORITHMS, EXT_SUPPORTED_GROUPS,
    EXT_SUPPORTED_VERSIONS, GROUP_X25519, HRR_RANDOM, HS_CERTIFICATE, HS_CERTIFICATE_REQUEST,
    HS_CERTIFICATE_VERIFY, HS_ENCRYPTED_EXTENSIONS, HS_FINISHED, HS_KEY_UPDATE, HS_MESSAGE_HASH,
    HS_NEW_SESSION_TICKET, HS_SERVER_HELLO, MAX_PLAINTEXT_LEN, SIG_ECDSA_SECP256R1_SHA256,
    SIG_ED25519, SIG_RSA_PKCS1_SHA256, SIG_RSA_PSS_RSAE_SHA256, TLS_VERSION_TLS_1_0,
    TLS_VERSION_TLS_1_2, TLS_VERSION_TLS_1_3,
};
use crate::tls_x25519::{x25519, x25519_public};
use crate::tls_x509::{
    int_to_fixed32, parse_certificate, pkcs1_v15_verify_sha256, pss_verify_sha256, sha256,
    Certificate, RootStore, Spki, X509Error,
};

// ─── Errors ─────────────────────────────────────────────────────────────────

/// Errors from the TLS client. Fatal handshake errors are reported to
/// the peer with the alert in parentheses (RFC 8446 §6.2) before the
/// function returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    /// The transport failed (read/write error, or a read deadline).
    Transport,
    /// The peer sent an alert; the value is the alert description.
    AlertReceived(u8),
    /// The peer closed cleanly (`close_notify`).
    Closed,
    /// A handshake message arrived out of order, or a record arrived
    /// in the wrong state (`unexpected_message`).
    UnexpectedMessage,
    /// The server did not negotiate TLS 1.3 (`protocol_version`).
    UnsupportedVersion,
    /// The server negotiated a ciphersuite we do not implement
    /// (`handshake_failure`).
    UnsupportedCipher,
    /// A HelloRetryRequest asked for a group we do not implement
    /// (`handshake_failure`).
    UnsupportedGroup,
    /// A second HelloRetryRequest arrived (`illegal_parameter`).
    TooManyHrr,
    /// A record or handshake message was malformed (`decode_error`).
    DecodeError,
    /// AEAD authentication failed (`bad_record_mac`).
    BadRecordMac,
    /// The server Finished MAC did not verify (`decrypt_error`).
    BadFinished,
    /// Certificate chain verification failed; the inner error selects
    /// the alert (`bad_certificate` / `certificate_expired` /
    /// `unknown_ca` / `unsupported_certificate`).
    CertError(X509Error),
    /// The peer's key share was missing or malformed
    /// (`illegal_parameter`).
    BadKeyShare,
    /// X25519 failed (all-zero shared secret).
    KeyExchangeFailed,
    /// No entropy was available for the client random / ephemeral key.
    NoEntropy,
    /// An internal inconsistency (should not happen).
    Internal,
}

impl TlsError {
    /// The fatal alert description to send for this error, if any.
    fn alert(self) -> Option<u8> {
        match self {
            TlsError::Transport
            | TlsError::AlertReceived(_)
            | TlsError::Closed
            | TlsError::NoEntropy
            | TlsError::Internal => None,
            TlsError::UnexpectedMessage => Some(ALERT_UNEXPECTED_MESSAGE),
            TlsError::UnsupportedVersion => Some(ALERT_PROTOCOL_VERSION),
            TlsError::UnsupportedCipher | TlsError::UnsupportedGroup => {
                Some(ALERT_HANDSHAKE_FAILURE)
            }
            TlsError::TooManyHrr | TlsError::BadKeyShare => Some(ALERT_ILLEGAL_PARAMETER),
            TlsError::DecodeError => Some(ALERT_DECODE_ERROR),
            TlsError::BadRecordMac => Some(ALERT_BAD_RECORD_MAC),
            TlsError::BadFinished => Some(ALERT_DECRYPT_ERROR),
            TlsError::CertError(X509Error::Expired) => Some(ALERT_CERTIFICATE_EXPIRED),
            TlsError::CertError(X509Error::UnknownIssuer) => Some(ALERT_UNKNOWN_CA),
            TlsError::CertError(X509Error::UnsupportedAlgorithm) => {
                Some(ALERT_UNSUPPORTED_CERTIFICATE)
            }
            TlsError::CertError(_) => Some(ALERT_BAD_CERTIFICATE),
            TlsError::KeyExchangeFailed => Some(ALERT_HANDSHAKE_FAILURE),
        }
    }
}

impl From<X509Error> for TlsError {
    fn from(e: X509Error) -> Self {
        TlsError::CertError(e)
    }
}

// ─── Transport ──────────────────────────────────────────────────────────────

/// A byte stream the TLS client runs over. `read_exact` must loop
/// internally until the buffer is full or the transport fails; short
/// reads are the transport's problem, not the client's.
pub trait Transport {
    /// Read exactly `buf.len()` bytes, or fail.
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), TlsError>;
    /// Write all of `buf`, or fail.
    fn write_all(&mut self, buf: &[u8]) -> Result<(), TlsError>;
}

/// An in-memory transport for fixtures: reads from a fixed input
/// slice, appends writes to an output buffer the test inspects.
#[derive(Debug)]
pub struct SliceTransport<'a> {
    input: &'a [u8],
    pos: usize,
    /// Everything the client wrote, in order.
    pub output: Vec<u8>,
}

impl<'a> SliceTransport<'a> {
    /// A transport over the given input bytes.
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            output: Vec::new(),
        }
    }

    /// Bytes the client has written so far.
    pub fn written(&self) -> &[u8] {
        &self.output
    }

    /// Bytes of input not yet consumed.
    pub fn remaining_input(&self) -> &[u8] {
        &self.input[self.pos..]
    }
}

impl Transport for SliceTransport<'_> {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), TlsError> {
        if self.input.len() - self.pos < buf.len() {
            return Err(TlsError::Transport);
        }
        buf.copy_from_slice(&self.input[self.pos..self.pos + buf.len()]);
        self.pos += buf.len();
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), TlsError> {
        self.output.extend_from_slice(buf);
        Ok(())
    }
}

/// A transport over a `net::tcp::core` socket id. Reads pump the
/// interface while waiting (the `connect_wait` pattern): `recv` is
/// non-blocking, so an empty read spins the pump until data arrives
/// or the 30-second deadline passes. Must be called from sync context,
/// not from inside an executor poll (same rule as `connect_wait`).
#[derive(Debug)]
pub struct TcpTransport {
    id: u32,
}

impl TcpTransport {
    /// Open a TCP connection to `ip:port` and wait for establishment.
    pub fn connect(ip: [u8; 4], port: u16) -> Result<Self, TlsError> {
        let id = crate::tcp::core::connect(ip, port).map_err(|_| TlsError::Transport)?;
        crate::tcp::core::connect_wait(id, crate::tcp::core::ConnectOptions::default())
            .map_err(|_| TlsError::Transport)?;
        Ok(Self { id })
    }

    /// The underlying socket id.
    pub fn socket_id(&self) -> u32 {
        self.id
    }
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        let _ = crate::tcp::core::close(self.id);
    }
}

impl Transport for TcpTransport {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), TlsError> {
        let mut filled = 0;
        while filled < buf.len() {
            match crate::tcp::core::recv(self.id, &mut buf[filled..]) {
                Ok(n) if n > 0 => filled += n,
                Ok(_) => {
                    // No data yet: pump until some arrives or the
                    // deadline passes.
                    let deadline = narf_scheduler::narf_time::Deadline::after_ns(30_000_000_000);
                    let mut got = 0usize;
                    let arrived = narf_scheduler::responsive_spin_until(
                        || {
                            while crate::iface::drain_pump() {}
                            crate::tcp_stack::neigh_tick();
                            match crate::tcp::core::recv(self.id, &mut buf[filled..]) {
                                Ok(n) if n > 0 => {
                                    got = n;
                                    true
                                }
                                _ => false,
                            }
                        },
                        deadline,
                    );
                    if !arrived {
                        return Err(TlsError::Transport);
                    }
                    filled += got;
                }
                Err(()) => return Err(TlsError::Transport),
            }
        }
        Ok(())
    }

    fn write_all(&mut self, buf: &[u8]) -> Result<(), TlsError> {
        let mut sent = 0;
        while sent < buf.len() {
            match crate::tcp::core::send(self.id, &buf[sent..]) {
                Ok(n) if n > 0 => sent += n,
                Ok(_) => {
                    // Send window full: pump once and retry; a
                    // persistently-zero send is a dead peer.
                    while crate::iface::drain_pump() {}
                    match crate::tcp::core::send(self.id, &buf[sent..]) {
                        Ok(n) if n > 0 => sent += n,
                        _ => return Err(TlsError::Transport),
                    }
                }
                Err(()) => return Err(TlsError::Transport),
            }
        }
        Ok(())
    }
}

// ─── Configuration ──────────────────────────────────────────────────────────

/// Client configuration. The random and ephemeral key are injected by
/// fixtures (the RFC 8448 trace pins them); production callers leave
/// them `None` and the client fills them from the entropy source.
#[derive(Debug)]
pub struct ClientConfig<'a> {
    /// Server hostname: sent as SNI and verified against the leaf.
    /// `None` disables SNI and hostname verification (the RFC 8448
    /// fixture uses `Some("server")` for SNI with verification off —
    /// the trace cert's CN is `rsa`, not `server`).
    pub server_name: Option<&'a str>,
    /// Verify the leaf hostname (default `true`). When `false`, the
    /// chain is still fully verified — only the name check is skipped.
    pub verify_hostname: bool,
    /// Trust store for chain verification.
    pub roots: &'a RootStore<'a>,
    /// Unix time for certificate validity. Production callers pass the
    /// wall clock (`narf_time::now_wall().secs`).
    pub now_unix: u64,
    /// Injected client random (fixtures). `None` → entropy.
    pub client_random: Option<[u8; 32]>,
    /// Injected ephemeral X25519 private key (fixtures). `None` →
    /// entropy.
    pub ephemeral_private: Option<[u8; 32]>,
    /// Ciphersuites offered, in preference order. Default: the two
    /// implemented suites, AES-128-GCM first.
    pub offered_suites: &'a [u16],
    /// Named groups offered for key_share. Default: X25519 only.
    pub offered_groups: &'a [u16],
    /// Signature schemes offered. Default: the four SHA-256 schemes.
    pub offered_sig_algs: &'a [u16],
    /// Offer `psk_key_exchange_modes` (fixture seam only — the RFC
    /// 8448 trace includes it). Production: `false`; this client
    /// offers no PSK.
    pub offer_psk_modes: bool,
    /// Offer `record_size_limit` with this value (fixture seam only).
    /// Production: `None`.
    pub record_size_limit: Option<u16>,
    /// Offer `renegotiation_info` (fixture seam only). Production:
    /// `false`.
    pub offer_renegotiation_info: bool,
    /// Offer `extended_master_secret` (fixture seam only). Production:
    /// `false`.
    pub offer_extended_master_secret: bool,
}

impl<'a> ClientConfig<'a> {
    /// A config verifying against `roots` at `now_unix`, with hostname
    /// verification on.
    pub fn new(roots: &'a RootStore<'a>, now_unix: u64) -> Self {
        Self {
            server_name: None,
            verify_hostname: true,
            roots,
            now_unix,
            client_random: None,
            ephemeral_private: None,
            offered_suites: &[
                CIPHER_TLS_AES_128_GCM_SHA256,
                CIPHER_TLS_CHACHA20_POLY1305_SHA256,
            ],
            offered_groups: &[GROUP_X25519],
            offered_sig_algs: &[
                SIG_RSA_PKCS1_SHA256,
                SIG_ECDSA_SECP256R1_SHA256,
                SIG_RSA_PSS_RSAE_SHA256,
                SIG_ED25519,
            ],
            offer_psk_modes: false,
            record_size_limit: None,
            offer_renegotiation_info: false,
            offer_extended_master_secret: false,
        }
    }
}

// ─── Key schedule (RFC 8446 §7.1) ───────────────────────────────────────────

/// HKDF-Expand-Label(Secret, Label, Context, Length) — RFC 8446 §7.1.
/// The label is prefixed with `"tls13 "`.
pub(crate) fn hkdf_expand_label(
    secret: &[u8; 32],
    label: &str,
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let mut full_label = Vec::with_capacity(6 + label.len());
    full_label.extend_from_slice(b"tls13 ");
    full_label.extend_from_slice(label.as_bytes());
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(&full_label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(secret, &info, len)
}

/// Derive-Secret(Secret, Label, Messages) — RFC 8446 §7.1:
/// `HKDF-Expand-Label(Secret, Label, Hash(Messages), 32)`. The caller
/// passes the already-hashed transcript.
pub(crate) fn derive_secret(
    secret: &[u8; 32],
    label: &str,
    transcript_hash: &[u8; 32],
) -> [u8; 32] {
    let out = hkdf_expand_label(secret, label, transcript_hash, 32);
    out.try_into()
        .expect("hkdf_expand_label(32) returns 32 bytes")
}

/// The traffic keys for one direction: AEAD key + per-record IV.
#[derive(Debug, Clone)]
pub(crate) struct TrafficKeys {
    /// AEAD key; only the first `key_len` bytes are used.
    pub(crate) key: [u8; 32],
    /// Key length in bytes (16 for AES-128-GCM, 32 for ChaCha20).
    pub(crate) key_len: usize,
    /// Per-record IV (12 bytes).
    pub(crate) iv: [u8; 12],
}

pub(crate) fn traffic_keys(cipher: Cipher, secret: &[u8; 32]) -> TrafficKeys {
    let key_len = match cipher {
        Cipher::Aes128Gcm => 16,
        Cipher::ChaCha20Poly1305 => 32,
    };
    let key_bytes = hkdf_expand_label(secret, "key", b"", key_len);
    let iv_bytes = hkdf_expand_label(secret, "iv", b"", 12);
    let mut key = [0u8; 32];
    key[..key_len].copy_from_slice(&key_bytes);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_bytes);
    TrafficKeys { key, key_len, iv }
}

/// The negotiated ciphersuite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    /// `TLS_AES_128_GCM_SHA256` (0x1301).
    Aes128Gcm,
    /// `TLS_CHACHA20_POLY1305_SHA256` (0x1302).
    ChaCha20Poly1305,
}

impl Cipher {
    fn from_u16(v: u16) -> Option<Self> {
        match v {
            CIPHER_TLS_AES_128_GCM_SHA256 => Some(Cipher::Aes128Gcm),
            CIPHER_TLS_CHACHA20_POLY1305_SHA256 => Some(Cipher::ChaCha20Poly1305),
            _ => None,
        }
    }
}

// ─── Record protection (RFC 8446 §5.2, §5.3) ────────────────────────────────

/// The per-record nonce: `IV XOR seq_num` (RFC 8446 §5.3), the
/// sequence number as a 64-bit big-endian integer in the low bytes.
fn record_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

/// Encrypt `plaintext` in place under `keys`/`seq`, returning the
/// 16-byte tag. `aad` is the 5-byte record header that will be sent
/// (RFC 8446 §5.2: the additional data is the record header itself).
pub(crate) fn aead_seal(
    cipher: Cipher,
    keys: &TrafficKeys,
    seq: u64,
    aad: &[u8],
    plaintext: &mut [u8],
) -> [u8; 16] {
    let nonce = record_nonce(&keys.iv, seq);
    match cipher {
        Cipher::Aes128Gcm => {
            let cipher = Aes128Gcm::new(GcmKey::<Aes128Gcm>::from_slice(&keys.key[..keys.key_len]));
            cipher
                .encrypt_in_place_detached(GcmNonce::from_slice(&nonce), aad, plaintext)
                .expect("aes-gcm seal cannot fail on valid inputs")
                .into()
        }
        Cipher::ChaCha20Poly1305 => chacha20_poly1305_seal(&keys.key, &nonce, aad, plaintext),
    }
}

/// Decrypt `ciphertext` in place under `keys`/`seq`; returns `false`
/// when the tag does not verify (nothing is decrypted then).
pub(crate) fn aead_open(
    cipher: Cipher,
    keys: &TrafficKeys,
    seq: u64,
    aad: &[u8],
    ciphertext: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    let nonce = record_nonce(&keys.iv, seq);
    match cipher {
        Cipher::Aes128Gcm => {
            let cipher = Aes128Gcm::new(GcmKey::<Aes128Gcm>::from_slice(&keys.key[..keys.key_len]));
            cipher
                .decrypt_in_place_detached(
                    GcmNonce::from_slice(&nonce),
                    aad,
                    ciphertext,
                    tag.into(),
                )
                .is_ok()
        }
        Cipher::ChaCha20Poly1305 => chacha20_poly1305_open(&keys.key, &nonce, aad, ciphertext, tag),
    }
}

/// Split a decrypted inner plaintext into (fragment, content type)
/// (RFC 8446 §5.4): the content type is the last non-zero byte;
/// everything after the fragment is zero padding.
fn split_inner_plaintext(plaintext: &[u8]) -> Option<(&[u8], u8)> {
    let mut i = plaintext.len();
    while i > 0 {
        i -= 1;
        if plaintext[i] != 0 {
            return Some((&plaintext[..i], plaintext[i]));
        }
    }
    None
}

// ─── ClientHello ────────────────────────────────────────────────────────────

/// The extension set a ClientHello offers. Production callers use the
/// defaults (only what this client implements); the fixture seam is
/// the RFC 8448 trace's exact set, which the test constructs via the
/// `ClientConfig` fields below. The difference is deliberate and
/// documented: the production hello advertises only implemented
/// features, so a real server can never negotiate something this
/// client cannot do.
pub(crate) fn build_client_hello(
    config: &ClientConfig,
    random: &[u8; 32],
    key_share_pub: &[u8; 32],
) -> Vec<u8> {
    build_client_hello_inner(config, random, key_share_pub, None)
}

/// A ClientHello answering a HelloRetryRequest: identical to
/// [`build_client_hello`] but with the server's cookie as the FIRST
/// extension (RFC 8446 §4.2.2).
pub(crate) fn build_client_hello_with_cookie(
    config: &ClientConfig,
    random: &[u8; 32],
    key_share_pub: &[u8; 32],
    cookie: Option<&[u8]>,
) -> Vec<u8> {
    build_client_hello_inner(config, random, key_share_pub, cookie)
}

fn build_client_hello_inner(
    config: &ClientConfig,
    random: &[u8; 32],
    key_share_pub: &[u8; 32],
    cookie: Option<&[u8]>,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(256);
    // legacy_version: TLS 1.2.
    body.extend_from_slice(&TLS_VERSION_TLS_1_2.to_be_bytes());
    body.extend_from_slice(random);
    // legacy_session_id: empty.
    body.push(0);
    // cipher_suites.
    body.extend_from_slice(&((config.offered_suites.len() * 2) as u16).to_be_bytes());
    for suite in config.offered_suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    // legacy_compression_methods: null only.
    body.extend_from_slice(&[1, 0]);

    let mut exts = Vec::with_capacity(128);
    // cookie (HelloRetryRequest response only): the first extension.
    if let Some(cookie) = cookie {
        let mut v = Vec::with_capacity(2 + cookie.len());
        v.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        v.extend_from_slice(cookie);
        push_ext(&mut exts, EXT_COOKIE, &v);
    }
    // server_name (SNI).
    if let Some(name) = config.server_name {
        let mut v = Vec::with_capacity(name.len() + 5);
        v.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        v.push(0); // host_name
        v.extend_from_slice(&(name.len() as u16).to_be_bytes());
        v.extend_from_slice(name.as_bytes());
        push_ext(&mut exts, EXT_SERVER_NAME, &v);
    }
    // Extension order follows the RFC 8448 §3 trace (server_name,
    // renegotiation_info, supported_groups, extended_master_secret,
    // key_share, supported_versions, signature_algorithms,
    // psk_key_exchange_modes, record_size_limit) so the fixture
    // ClientHello reproduces the trace byte-exactly. Extension order
    // is semantically irrelevant, so the production hello (no fixture
    // flags) uses the same order.
    // renegotiation_info (fixture seam only; empty, middlebox compat).
    if config.offer_renegotiation_info {
        push_ext(&mut exts, EXT_RENEGOTIATION_INFO, &[0]);
    }
    // supported_groups.
    {
        let mut v = Vec::with_capacity(2 + config.offered_groups.len() * 2);
        v.extend_from_slice(&((config.offered_groups.len() * 2) as u16).to_be_bytes());
        for g in config.offered_groups {
            v.extend_from_slice(&g.to_be_bytes());
        }
        push_ext(&mut exts, EXT_SUPPORTED_GROUPS, &v);
    }
    // extended_master_secret (fixture seam only; empty).
    if config.offer_extended_master_secret {
        push_ext(&mut exts, EXT_EXTENDED_MASTER_SECRET, &[]);
    }
    // key_share: one X25519 entry.
    {
        let mut v = Vec::with_capacity(2 + 2 + 2 + 32);
        v.extend_from_slice(&((2 + 2 + 32) as u16).to_be_bytes());
        v.extend_from_slice(&GROUP_X25519.to_be_bytes());
        v.extend_from_slice(&32u16.to_be_bytes());
        v.extend_from_slice(key_share_pub);
        push_ext(&mut exts, EXT_KEY_SHARE, &v);
    }
    // supported_versions: TLS 1.3 only. The data is a u8 length (2
    // bytes of versions) + 0x0304 — NOT length 1.
    push_ext(&mut exts, EXT_SUPPORTED_VERSIONS, &[2, 0x03, 0x04]);
    // signature_algorithms.
    {
        let mut v = Vec::with_capacity(2 + config.offered_sig_algs.len() * 2);
        v.extend_from_slice(&((config.offered_sig_algs.len() * 2) as u16).to_be_bytes());
        for a in config.offered_sig_algs {
            v.extend_from_slice(&a.to_be_bytes());
        }
        push_ext(&mut exts, EXT_SIGNATURE_ALGORITHMS, &v);
    }
    // psk_key_exchange_modes (fixture seam only; never in production —
    // this client offers no PSK).
    if config.offer_psk_modes {
        push_ext(&mut exts, EXT_PSK_KEY_EXCHANGE_MODES, &[1, 1]);
    }
    // record_size_limit (fixture seam only).
    if let Some(limit) = config.record_size_limit {
        push_ext(&mut exts, EXT_RECORD_SIZE_LIMIT, &limit.to_be_bytes());
    }

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    // Handshake message: type 1 (client_hello) + 24-bit length.
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(1);
    msg.extend_from_slice(&((body.len() as u32) & 0xff_ffff).to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    msg
}

fn push_ext(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    out.extend_from_slice(&ext_type.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Parse an extensions block (`u16 length` + entries) with a
/// callback per extension. Returns `Err` on truncation or overrun.
fn walk_extensions<F: FnMut(u16, &[u8]) -> Result<(), TlsError>>(
    buf: &[u8],
    mut f: F,
) -> Result<(), TlsError> {
    if buf.len() < 2 {
        return Err(TlsError::DecodeError);
    }
    let total = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if total != buf.len() - 2 {
        return Err(TlsError::DecodeError);
    }
    let mut rest = &buf[2..];
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err(TlsError::DecodeError);
        }
        let ext_type = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if rest.len() < 4 + len {
            return Err(TlsError::DecodeError);
        }
        f(ext_type, &rest[4..4 + len])?;
        rest = &rest[4 + len..];
    }
    Ok(())
}

// ─── The client ─────────────────────────────────────────────────────────────

/// Which keys protect records in each direction right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protection {
    /// No encryption yet (ClientHello / ServerHello).
    Plaintext,
    /// Handshake traffic secrets (server flight, client Finished).
    Handshake,
    /// Application traffic secrets (post-handshake).
    Application,
}

/// The leaf public key, copied out of the parsed Certificate so the
/// chain's borrowed data can be dropped before CertificateVerify.
#[derive(Debug, Clone)]
enum LeafKey {
    Rsa { n: Vec<u8>, e: u32 },
    EcP256 { point: [u8; 65] },
    Ed25519 { point: [u8; 32] },
}

/// A TLS 1.3 client connection. Created by [`TlsClient::connect`]
/// (which runs the handshake); afterwards `send_app_data` /
/// `recv_app_data` move application data.
pub struct TlsClient<'a, T: Transport> {
    transport: T,
    config: ClientConfig<'a>,
    cipher: Option<Cipher>,
    /// Concatenated handshake messages (type + length + body).
    transcript: Vec<u8>,
    /// Decrypted handshake bytes not yet consumed as messages.
    pending: Vec<u8>,
    hs_client: Option<TrafficKeys>,
    hs_server: Option<TrafficKeys>,
    /// Handshake traffic secrets (needed for Finished keys; the
    /// `TrafficKeys` hold only the derived key/iv).
    hs_client_secret: Option<[u8; 32]>,
    hs_server_secret: Option<[u8; 32]>,
    /// Handshake secret (needed for the application-traffic secrets
    /// derived after the server Finished).
    handshake_secret: Option<[u8; 32]>,
    ap_client: Option<TrafficKeys>,
    ap_server: Option<TrafficKeys>,
    client_ap_secret: Option<[u8; 32]>,
    server_ap_secret: Option<[u8; 32]>,
    client_seq: u64,
    server_seq: u64,
    client_protection: Protection,
    server_protection: Protection,
    client_random: [u8; 32],
    ephemeral_private: [u8; 32],
    /// The `CertificateRequest` context to echo, if the server asked
    /// for client authentication.
    cert_request_context: Option<Vec<u8>>,
    received_close_notify: bool,
}

/// `Debug` is manual on purpose: the struct holds traffic secrets,
/// the transcript, and the transport, none of which may be printed
/// into logs. Only the negotiated state is shown.
impl<'a, T: Transport> Debug for TlsClient<'a, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlsClient")
            .field("cipher", &self.cipher)
            .field("client_protection", &self.client_protection)
            .field("server_protection", &self.server_protection)
            .field("client_seq", &self.client_seq)
            .field("server_seq", &self.server_seq)
            .finish_non_exhaustive()
    }
}

impl<'a, T: Transport> TlsClient<'a, T> {
    /// Run the handshake over `transport` and return the established
    /// connection. On failure a fatal alert is sent best-effort before
    /// returning the error.
    pub fn connect(transport: T, config: ClientConfig<'a>) -> Result<Self, TlsError> {
        let mut client = Self {
            transport,
            config,
            cipher: None,
            transcript: Vec::new(),
            pending: Vec::new(),
            hs_client: None,
            hs_server: None,
            hs_client_secret: None,
            hs_server_secret: None,
            handshake_secret: None,
            ap_client: None,
            ap_server: None,
            client_ap_secret: None,
            server_ap_secret: None,
            client_seq: 0,
            server_seq: 0,
            client_protection: Protection::Plaintext,
            server_protection: Protection::Plaintext,
            client_random: [0; 32],
            ephemeral_private: [0; 32],
            cert_request_context: None,
            received_close_notify: false,
        };
        match client.handshake() {
            Ok(()) => Ok(client),
            Err(e) => {
                if let Some(desc) = e.alert() {
                    client.send_fatal_alert(desc);
                }
                Err(e)
            }
        }
    }

    // ── handshake driver ───────────────────────────────────────────────

    fn handshake(&mut self) -> Result<(), TlsError> {
        // Client random + ephemeral key: injected by fixtures, else
        // entropy. The per-task RNG is the keygen source; the suspend
        // design's P0 (per_task_rng lacks secure keygen entropy) is a
        // known caveat — `try_fill_random_bytes` is the health-checked
        // hardware-seeded path, and its failure fails the handshake
        // rather than falling back to weak randomness.
        self.client_random = match self.config.client_random {
            Some(r) => r,
            None => {
                let mut r = [0u8; 32];
                try_fill_random_bytes(&mut r).map_err(|_| TlsError::NoEntropy)?;
                r
            }
        };
        self.ephemeral_private = match self.config.ephemeral_private {
            Some(k) => k,
            None => {
                let mut k = [0u8; 32];
                try_fill_random_bytes(&mut k).map_err(|_| TlsError::NoEntropy)?;
                k
            }
        };
        let pub_key = x25519_public(&self.ephemeral_private).ok_or(TlsError::KeyExchangeFailed)?;

        // ClientHello (record version 0x0301 for the initial hello;
        // RFC 8446 §5.1 allows 0x0303 too, but the RFC 8448 trace
        // uses 0x0301 and the fixture asserts byte-exactness).
        let hello = build_client_hello(&self.config, &self.client_random, &pub_key);
        self.write_record_plaintext(CONTENT_TYPE_HANDSHAKE, TLS_VERSION_TLS_1_0, &hello)?;
        self.transcript.extend_from_slice(&hello);

        // ServerHello (or HelloRetryRequest).
        let (msg_type, body) = self.read_handshake_message()?;
        if msg_type != HS_SERVER_HELLO {
            return Err(TlsError::UnexpectedMessage);
        }
        let mut server_hello = body;
        if is_hrr(&server_hello) {
            let (group, cookie) = parse_hrr(&server_hello)?;
            if group != GROUP_X25519 {
                return Err(TlsError::UnsupportedGroup);
            }
            // RFC 8446 §4.4.1: the transcript becomes
            // message_hash(ClientHello1) || HRR, then ClientHello2.
            let ch1_hash = sha256(&self.transcript);
            let mut new_transcript = Vec::with_capacity(4 + 32 + server_hello.len() + 4);
            new_transcript.push(HS_MESSAGE_HASH);
            new_transcript.extend_from_slice(&[0, 0, 32]);
            new_transcript.extend_from_slice(&ch1_hash);
            new_transcript.push(HS_SERVER_HELLO);
            new_transcript
                .extend_from_slice(&((server_hello.len() as u32) & 0xff_ffff).to_be_bytes()[1..]);
            new_transcript.extend_from_slice(&server_hello);
            self.transcript = new_transcript;
            // Fresh ephemeral key for the second hello.
            let mut k = [0u8; 32];
            try_fill_random_bytes(&mut k).map_err(|_| TlsError::NoEntropy)?;
            self.ephemeral_private = k;
            let pub2 = x25519_public(&self.ephemeral_private).ok_or(TlsError::KeyExchangeFailed)?;
            let hello2 = build_client_hello_with_cookie(
                &self.config,
                &self.client_random,
                &pub2,
                cookie.as_deref(),
            );
            // A hello after HRR uses record version 0x0303.
            self.write_record_plaintext(CONTENT_TYPE_HANDSHAKE, TLS_VERSION_TLS_1_2, &hello2)?;
            self.transcript.extend_from_slice(&hello2);
            let (t2, b2) = self.read_handshake_message()?;
            if t2 != HS_SERVER_HELLO {
                return Err(TlsError::UnexpectedMessage);
            }
            if is_hrr(&b2) {
                return Err(TlsError::TooManyHrr);
            }
            server_hello = b2;
        }

        // Parse the (real) ServerHello and derive handshake secrets.
        let (suite, server_pub) = parse_server_hello(&server_hello)?;
        let cipher = Cipher::from_u16(suite).ok_or(TlsError::UnsupportedCipher)?;
        self.cipher = Some(cipher);
        let shared =
            x25519(&self.ephemeral_private, &server_pub).ok_or(TlsError::KeyExchangeFailed)?;
        self.transcript
            .extend_from_slice(&handshake_message_bytes(HS_SERVER_HELLO, &server_hello));
        let (hs_client, hs_server, hs_client_secret, hs_server_secret, handshake_secret) =
            derive_handshake_secrets(cipher, &shared, &self.transcript);
        self.hs_client = Some(hs_client);
        self.hs_server = Some(hs_server);
        self.hs_client_secret = Some(hs_client_secret);
        self.hs_server_secret = Some(hs_server_secret);
        self.handshake_secret = Some(handshake_secret);
        self.client_protection = Protection::Handshake;
        self.server_protection = Protection::Handshake;

        // Server flight: EncryptedExtensions, [CertificateRequest],
        // Certificate, CertificateVerify, Finished.
        let mut leaf_key: Option<LeafKey> = None;
        let mut saw_certificate = false;
        let mut saw_cert_verify = false;
        loop {
            let (msg_type, body) = self.read_handshake_message()?;
            match msg_type {
                HS_ENCRYPTED_EXTENSIONS => {
                    parse_encrypted_extensions(&body)?;
                }
                HS_CERTIFICATE_REQUEST => {
                    self.cert_request_context = Some(parse_cert_request(&body)?);
                }
                HS_CERTIFICATE => {
                    let (chain, leaf) = parse_certificate_message(&body)?;
                    let hostname = if self.config.verify_hostname {
                        self.config.server_name
                    } else {
                        None
                    };
                    self.config
                        .roots
                        .verify_chain(&chain, hostname, self.config.now_unix)?;
                    leaf_key = Some(leaf);
                    saw_certificate = true;
                }
                HS_CERTIFICATE_VERIFY => {
                    let Some(leaf) = &leaf_key else {
                        return Err(TlsError::UnexpectedMessage);
                    };
                    if !saw_certificate {
                        return Err(TlsError::UnexpectedMessage);
                    }
                    verify_certificate_verify(leaf, &body, &self.transcript)?;
                    self.transcript
                        .extend_from_slice(&handshake_message_bytes(msg_type, &body));
                    saw_cert_verify = true;
                }
                HS_FINISHED => {
                    if !saw_certificate || !saw_cert_verify {
                        return Err(TlsError::UnexpectedMessage);
                    }
                    let Some(hs_server_secret) = self.hs_server_secret else {
                        return Err(TlsError::Internal);
                    };
                    let finished_key = hkdf_expand_label(&hs_server_secret, "finished", b"", 32);
                    verify_finished(&finished_key, &body, &self.transcript)?;
                    self.transcript
                        .extend_from_slice(&handshake_message_bytes(msg_type, &body));
                    break;
                }
                _ => return Err(TlsError::UnexpectedMessage),
            }
            // Transcript appends for the messages handled above that
            // did not append inline (EE / CertificateRequest /
            // Certificate): the Certificate message is appended after
            // verification, so a failed chain never pollutes it.
            match msg_type {
                HS_ENCRYPTED_EXTENSIONS | HS_CERTIFICATE_REQUEST | HS_CERTIFICATE => {
                    self.transcript
                        .extend_from_slice(&handshake_message_bytes(msg_type, &body));
                }
                _ => {}
            }
        }

        // Application secrets (RFC 8446 §7.1).
        let Some(handshake_secret) = self.handshake_secret else {
            return Err(TlsError::Internal);
        };
        let derived = derive_secret(&handshake_secret, "derived", &sha256(b""));
        let master_secret = hkdf_extract(Some(&derived), &[0u8; 32]);
        let th = sha256(&self.transcript);
        let cipher = self.cipher.ok_or(TlsError::Internal)?;
        let c_ap = derive_secret(&master_secret, "c ap traffic", &th);
        let s_ap = derive_secret(&master_secret, "s ap traffic", &th);
        self.ap_client = Some(traffic_keys(cipher, &c_ap));
        self.ap_server = Some(traffic_keys(cipher, &s_ap));
        self.client_ap_secret = Some(c_ap);
        self.server_ap_secret = Some(s_ap);
        self.server_protection = Protection::Application;

        // Client flight: [Certificate] + Finished, under the client
        // handshake traffic secret.
        if let Some(context) = self.cert_request_context.take() {
            // Empty Certificate echoing the request context; no
            // CertificateVerify follows (RFC 8446 §4.4.3).
            let mut body = Vec::with_capacity(1 + context.len() + 3);
            body.push(context.len() as u8);
            body.extend_from_slice(&context);
            body.extend_from_slice(&[0, 0, 0]); // empty certificate_list
            let msg = handshake_message_bytes(HS_CERTIFICATE, &body);
            self.write_protected_handshake(&msg)?;
            self.transcript.extend_from_slice(&msg);
        }
        let Some(hs_client_secret) = self.hs_client_secret else {
            return Err(TlsError::Internal);
        };
        let finished_key = hkdf_expand_label(&hs_client_secret, "finished", b"", 32);
        let finished = compute_finished(&finished_key, &self.transcript);
        let msg = handshake_message_bytes(HS_FINISHED, &finished);
        self.write_protected_handshake(&msg)?;
        self.transcript.extend_from_slice(&msg);
        self.client_protection = Protection::Application;
        Ok(())
    }

    // ── record I/O ───────────────────────────────────────────────────────

    /// Write one plaintext record (ClientHello / alerts before keys).
    fn write_record_plaintext(
        &mut self,
        content_type: u8,
        version: u16,
        fragment: &[u8],
    ) -> Result<(), TlsError> {
        let mut out = Vec::with_capacity(5 + fragment.len());
        out.push(content_type);
        out.extend_from_slice(&version.to_be_bytes());
        out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        out.extend_from_slice(fragment);
        self.transport.write_all(&out)
    }

    /// Write one protected record: `fragment || inner_type`, AEAD
    /// sealed under the current client keys (handshake or application).
    fn write_protected_record(&mut self, inner_type: u8, fragment: &[u8]) -> Result<(), TlsError> {
        let (cipher, keys, seq) = match self.client_protection {
            Protection::Plaintext => return Err(TlsError::Internal),
            Protection::Handshake => (
                self.cipher.ok_or(TlsError::Internal)?,
                self.hs_client.as_ref().ok_or(TlsError::Internal)?,
                self.client_seq,
            ),
            Protection::Application => (
                self.cipher.ok_or(TlsError::Internal)?,
                self.ap_client.as_ref().ok_or(TlsError::Internal)?,
                self.client_seq,
            ),
        };
        let mut plaintext = Vec::with_capacity(fragment.len() + 1);
        plaintext.extend_from_slice(fragment);
        plaintext.push(inner_type);
        // AAD is the record header that will be sent.
        let total = plaintext.len() + 16;
        let mut header = [0u8; 5];
        header[0] = CONTENT_TYPE_APPLICATION_DATA;
        header[1..3].copy_from_slice(&TLS_VERSION_TLS_1_2.to_be_bytes());
        header[3..5].copy_from_slice(&(total as u16).to_be_bytes());
        let tag = aead_seal(cipher, keys, seq, &header, &mut plaintext);
        let mut out = Vec::with_capacity(5 + total);
        out.extend_from_slice(&header);
        out.extend_from_slice(&plaintext);
        out.extend_from_slice(&tag);
        self.transport.write_all(&out)?;
        self.client_seq = self.client_seq.wrapping_add(1);
        Ok(())
    }

    /// Write a handshake message under the current client protection.
    fn write_protected_handshake(&mut self, msg: &[u8]) -> Result<(), TlsError> {
        self.write_protected_record(CONTENT_TYPE_HANDSHAKE, msg)
    }

    /// Send a fatal alert, best-effort, under whatever protection is
    /// current (plaintext before keys, else the client keys).
    fn send_fatal_alert(&mut self, desc: u8) {
        let _ = self.send_alert(2, desc);
    }

    fn send_alert(&mut self, level: u8, desc: u8) -> Result<(), TlsError> {
        match self.client_protection {
            Protection::Plaintext => {
                self.write_record_plaintext(CONTENT_TYPE_ALERT, TLS_VERSION_TLS_1_2, &[level, desc])
            }
            _ => self.write_protected_record(CONTENT_TYPE_ALERT, &[level, desc]),
        }
    }

    /// Read one record. Returns (inner content type, fragment).
    /// Plaintext records return their outer type; protected records
    /// are decrypted and return the inner type. `change_cipher_spec`
    /// records with a single 0x01 byte are ignored (RFC 8446 §5.4).
    fn read_record(&mut self) -> Result<(u8, Vec<u8>), TlsError> {
        loop {
            let mut header = [0u8; 5];
            self.transport.read_exact(&mut header)?;
            let content_type = header[0];
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            if length > (1 << 14) + 256 {
                return Err(TlsError::DecodeError);
            }
            let mut fragment = alloc::vec![0u8; length];
            self.transport.read_exact(&mut fragment)?;
            match content_type {
                CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                    if fragment == [0x01] {
                        continue;
                    }
                    return Err(TlsError::UnexpectedMessage);
                }
                CONTENT_TYPE_ALERT => {
                    if self.server_protection != Protection::Plaintext {
                        return Err(TlsError::DecodeError);
                    }
                    if fragment.len() != 2 {
                        return Err(TlsError::DecodeError);
                    }
                    return Err(match fragment[1] {
                        ALERT_CLOSE_NOTIFY => TlsError::Closed,
                        desc => TlsError::AlertReceived(desc),
                    });
                }
                CONTENT_TYPE_HANDSHAKE => {
                    if self.server_protection == Protection::Plaintext {
                        return Ok((CONTENT_TYPE_HANDSHAKE, fragment));
                    }
                    return self.decrypt_record(&header, fragment);
                }
                CONTENT_TYPE_APPLICATION_DATA => {
                    if self.server_protection == Protection::Plaintext {
                        return Err(TlsError::UnexpectedMessage);
                    }
                    return self.decrypt_record(&header, fragment);
                }
                _ => return Err(TlsError::UnexpectedMessage),
            }
        }
    }

    /// Decrypt an application-data record under the current server
    /// keys; returns (inner content type, fragment).
    fn decrypt_record(
        &mut self,
        header: &[u8; 5],
        fragment: Vec<u8>,
    ) -> Result<(u8, Vec<u8>), TlsError> {
        if fragment.len() < 17 {
            return Err(TlsError::BadRecordMac);
        }
        let (cipher, keys, seq) = match self.server_protection {
            Protection::Plaintext => return Err(TlsError::Internal),
            Protection::Handshake => (
                self.cipher.ok_or(TlsError::Internal)?,
                self.hs_server.as_ref().ok_or(TlsError::Internal)?,
                self.server_seq,
            ),
            Protection::Application => (
                self.cipher.ok_or(TlsError::Internal)?,
                self.ap_server.as_ref().ok_or(TlsError::Internal)?,
                self.server_seq,
            ),
        };
        let split = fragment.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&fragment[split..]);
        let mut body = fragment[..split].to_vec();
        if !aead_open(cipher, keys, seq, header, &mut body, &tag) {
            return Err(TlsError::BadRecordMac);
        }
        self.server_seq = self.server_seq.wrapping_add(1);
        match split_inner_plaintext(&body) {
            Some((frag, inner)) => Ok((inner, frag.to_vec())),
            None => Err(TlsError::DecodeError),
        }
    }

    /// Read one handshake message, buffering across records. Returns
    /// (message type, body) without the 4-byte header.
    fn read_handshake_message(&mut self) -> Result<(u8, Vec<u8>), TlsError> {
        loop {
            if self.pending.len() >= 4 {
                let len = ((self.pending[1] as usize) << 16)
                    | ((self.pending[2] as usize) << 8)
                    | (self.pending[3] as usize);
                if self.pending.len() >= 4 + len {
                    let msg_type = self.pending[0];
                    let body = self.pending[4..4 + len].to_vec();
                    self.pending.drain(..4 + len);
                    return Ok((msg_type, body));
                }
            }
            let (inner, fragment) = self.read_record()?;
            match inner {
                CONTENT_TYPE_HANDSHAKE => {
                    self.pending.extend_from_slice(&fragment);
                }
                CONTENT_TYPE_ALERT => {
                    // An encrypted alert during the handshake.
                    if fragment.len() != 2 {
                        return Err(TlsError::DecodeError);
                    }
                    return Err(match fragment[1] {
                        ALERT_CLOSE_NOTIFY => TlsError::Closed,
                        desc => TlsError::AlertReceived(desc),
                    });
                }
                _ => return Err(TlsError::UnexpectedMessage),
            }
        }
    }

    // ── application data ───────────────────────────────────────────────

    /// Send application data, chunked into ≤16384-byte records.
    pub fn send_app_data(&mut self, data: &[u8]) -> Result<(), TlsError> {
        if self.client_protection != Protection::Application {
            return Err(TlsError::Internal);
        }
        for chunk in data.chunks(MAX_PLAINTEXT_LEN) {
            self.write_protected_record(CONTENT_TYPE_APPLICATION_DATA, chunk)?;
        }
        Ok(())
    }

    /// Receive one application-data payload. Post-handshake messages
    /// (NewSessionTicket, KeyUpdate, CertificateRequest) are handled
    /// inline and the read retries.
    pub fn recv_app_data(&mut self) -> Result<Vec<u8>, TlsError> {
        if self.received_close_notify {
            return Err(TlsError::Closed);
        }
        loop {
            let (inner, fragment) = self.read_record()?;
            match inner {
                CONTENT_TYPE_APPLICATION_DATA => return Ok(fragment),
                CONTENT_TYPE_HANDSHAKE => {
                    self.handle_post_handshake(&fragment)?;
                }
                CONTENT_TYPE_ALERT => {
                    if fragment.len() == 2 {
                        return Err(match fragment[1] {
                            ALERT_CLOSE_NOTIFY => {
                                self.received_close_notify = true;
                                TlsError::Closed
                            }
                            desc => TlsError::AlertReceived(desc),
                        });
                    }
                    return Err(TlsError::DecodeError);
                }
                _ => return Err(TlsError::UnexpectedMessage),
            }
        }
    }

    /// Handle one post-handshake handshake message (already decrypted).
    fn handle_post_handshake(&mut self, msg: &[u8]) -> Result<(), TlsError> {
        if msg.len() < 4 {
            return Err(TlsError::DecodeError);
        }
        let msg_type = msg[0];
        let len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
        if msg.len() != 4 + len {
            return Err(TlsError::DecodeError);
        }
        let body = &msg[4..];
        match msg_type {
            HS_NEW_SESSION_TICKET => {
                // Parsed and discarded: no resumption in this client.
                parse_new_session_ticket(body)?;
                Ok(())
            }
            HS_KEY_UPDATE => {
                if body.len() != 1 || body[0] > 1 {
                    return Err(TlsError::DecodeError);
                }
                self.ratchet_server_keys();
                if body[0] == 1 {
                    // Peer requested an update of our keys too.
                    self.send_key_update(false)?;
                }
                Ok(())
            }
            HS_CERTIFICATE_REQUEST => {
                let context = parse_cert_request(body)?;
                // Empty Certificate only (no CertificateVerify, no
                // Finished — RFC 8446 §4.4.2/§4.4.3).
                let mut cert_body = Vec::with_capacity(1 + context.len() + 3);
                cert_body.push(context.len() as u8);
                cert_body.extend_from_slice(&context);
                cert_body.extend_from_slice(&[0, 0, 0]);
                let msg = handshake_message_bytes(HS_CERTIFICATE, &cert_body);
                self.write_protected_record(CONTENT_TYPE_HANDSHAKE, &msg)
            }
            _ => Err(TlsError::UnexpectedMessage),
        }
    }

    /// Send a KeyUpdate message and ratchet our own traffic secret.
    pub fn update_keys(&mut self, request_peer_update: bool) -> Result<(), TlsError> {
        self.send_key_update(request_peer_update)
    }

    fn send_key_update(&mut self, request: bool) -> Result<(), TlsError> {
        let msg = handshake_message_bytes(HS_KEY_UPDATE, &[request as u8]);
        self.write_protected_record(CONTENT_TYPE_HANDSHAKE, &msg)?;
        self.ratchet_client_keys();
        Ok(())
    }

    fn ratchet_client_keys(&mut self) {
        if let (Some(cipher), Some(secret)) = (self.cipher, self.client_ap_secret) {
            // RFC 8446 §7.2: the next secret is
            // HKDF-Expand-Label(secret, "traffic upd", "", 32) — the
            // context is EMPTY, not the empty transcript hash (that
            // is what Derive-Secret uses; KeyUpdate does not use
            // Derive-Secret).
            let next_bytes = hkdf_expand_label(&secret, "traffic upd", b"", 32);
            let mut next = [0u8; 32];
            next.copy_from_slice(&next_bytes);
            self.client_ap_secret = Some(next);
            self.ap_client = Some(traffic_keys(cipher, &next));
            self.client_seq = 0;
        }
    }

    fn ratchet_server_keys(&mut self) {
        if let (Some(cipher), Some(secret)) = (self.cipher, self.server_ap_secret) {
            let next_bytes = hkdf_expand_label(&secret, "traffic upd", b"", 32);
            let mut next = [0u8; 32];
            next.copy_from_slice(&next_bytes);
            self.server_ap_secret = Some(next);
            self.ap_server = Some(traffic_keys(cipher, &next));
            self.server_seq = 0;
        }
    }

    /// Send `close_notify` and drop the connection (dropping the
    /// transport closes the socket for `TcpTransport`).
    pub fn close(&mut self) {
        let _ = self.send_alert(1, ALERT_CLOSE_NOTIFY);
    }

    /// The negotiated ciphersuite, if the handshake completed.
    pub fn negotiated_cipher(&self) -> Option<Cipher> {
        self.cipher
    }

    /// The underlying transport (e.g. to inspect bytes written).
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

// ─── Handshake message parsing ──────────────────────────────────────────────

fn handshake_message_bytes(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    out.extend_from_slice(&((body.len() as u32) & 0xff_ffff).to_be_bytes()[1..]);
    out.extend_from_slice(body);
    out
}

// ─── Handshake message parsing (continued) ──────────────────────────────

/// True when a ServerHello body carries the HelloRetryRequest magic
/// random (RFC 8446 §4.1.3).
fn is_hrr(body: &[u8]) -> bool {
    body.len() >= 34 && body[2..34] == HRR_RANDOM
}

/// Parse a HelloRetryRequest body. Returns (selected group, cookie).
/// The cipher suite must be one we offered; the supported_versions
/// extension must select TLS 1.3.
fn parse_hrr(body: &[u8]) -> Result<(u16, Option<Vec<u8>>), TlsError> {
    if body.len() < 34 + 1 + 2 + 1 + 2 {
        return Err(TlsError::DecodeError);
    }
    if u16::from_be_bytes([body[0], body[1]]) != TLS_VERSION_TLS_1_2 {
        return Err(TlsError::DecodeError);
    }
    let mut pos = 34;
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    if pos + 2 + 1 > body.len() {
        return Err(TlsError::DecodeError);
    }
    let suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
    if Cipher::from_u16(suite).is_none() {
        return Err(TlsError::UnsupportedCipher);
    }
    pos += 2;
    if body[pos] != 0 {
        return Err(TlsError::DecodeError);
    }
    pos += 1;
    if pos + 2 > body.len() {
        return Err(TlsError::DecodeError);
    }
    let exts = &body[pos..];
    let mut group: Option<u16> = None;
    let mut cookie: Option<Vec<u8>> = None;
    let mut saw_versions = false;
    walk_extensions(exts, |ext_type, data| {
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                if data.len() != 2 || u16::from_be_bytes([data[0], data[1]]) != TLS_VERSION_TLS_1_3
                {
                    return Err(TlsError::UnsupportedVersion);
                }
                saw_versions = true;
            }
            EXT_KEY_SHARE => {
                if data.len() != 4 {
                    return Err(TlsError::DecodeError);
                }
                let g = u16::from_be_bytes([data[0], data[1]]);
                let len = u16::from_be_bytes([data[2], data[3]]);
                if len != 0 {
                    return Err(TlsError::DecodeError);
                }
                group = Some(g);
            }
            EXT_COOKIE => {
                if data.len() < 2 {
                    return Err(TlsError::DecodeError);
                }
                let len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() != 2 + len {
                    return Err(TlsError::DecodeError);
                }
                cookie = Some(data[2..].to_vec());
            }
            _ => {}
        }
        Ok(())
    })?;
    if !saw_versions {
        return Err(TlsError::DecodeError);
    }
    let Some(group) = group else {
        return Err(TlsError::DecodeError);
    };
    Ok((group, cookie))
}

/// Parse a ServerHello body. Returns (negotiated ciphersuite,
/// server key_share public key).
fn parse_server_hello(body: &[u8]) -> Result<(u16, [u8; 32]), TlsError> {
    if body.len() < 34 + 1 + 2 + 1 + 2 {
        return Err(TlsError::DecodeError);
    }
    if u16::from_be_bytes([body[0], body[1]]) != TLS_VERSION_TLS_1_2 {
        return Err(TlsError::DecodeError);
    }
    let mut pos = 34;
    // legacy_session_id: the server echoes ours (empty).
    let sid_len = body[pos] as usize;
    if sid_len != 0 {
        return Err(TlsError::DecodeError);
    }
    pos += 1 + sid_len;
    if pos + 2 + 1 > body.len() {
        return Err(TlsError::DecodeError);
    }
    let suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 2;
    if body[pos] != 0 {
        return Err(TlsError::DecodeError);
    }
    pos += 1;
    if pos + 2 > body.len() {
        return Err(TlsError::DecodeError);
    }
    let exts = &body[pos..];
    let mut saw_versions = false;
    let mut server_pub: Option<[u8; 32]> = None;
    walk_extensions(exts, |ext_type, data| {
        match ext_type {
            EXT_SUPPORTED_VERSIONS => {
                if data.len() != 2 || u16::from_be_bytes([data[0], data[1]]) != TLS_VERSION_TLS_1_3
                {
                    return Err(TlsError::UnsupportedVersion);
                }
                saw_versions = true;
            }
            EXT_KEY_SHARE => {
                if data.len() < 4 {
                    return Err(TlsError::DecodeError);
                }
                let group = u16::from_be_bytes([data[0], data[1]]);
                let len = u16::from_be_bytes([data[2], data[3]]) as usize;
                if group != GROUP_X25519 || len != 32 || data.len() != 4 + 32 {
                    return Err(TlsError::BadKeyShare);
                }
                let mut pub_key = [0u8; 32];
                pub_key.copy_from_slice(&data[4..36]);
                server_pub = Some(pub_key);
            }
            _ => {}
        }
        Ok(())
    })?;
    if !saw_versions {
        return Err(TlsError::DecodeError);
    }
    let Some(server_pub) = server_pub else {
        return Err(TlsError::BadKeyShare);
    };
    Ok((suite, server_pub))
}

/// Parse EncryptedExtensions: only structure is checked, plus a
/// rejection of `early_data` (never offered, so never acceptable).
fn parse_encrypted_extensions(body: &[u8]) -> Result<(), TlsError> {
    walk_extensions(body, |ext_type, _data| {
        if ext_type == EXT_EARLY_DATA {
            return Err(TlsError::DecodeError);
        }
        Ok(())
    })
}

/// Parse a CertificateRequest body. Returns the request context the
/// client's Certificate message must echo.
fn parse_cert_request(body: &[u8]) -> Result<Vec<u8>, TlsError> {
    if body.is_empty() {
        return Err(TlsError::DecodeError);
    }
    let ctx_len = body[0] as usize;
    if body.len() < 1 + ctx_len + 2 {
        return Err(TlsError::DecodeError);
    }
    let context = body[1..1 + ctx_len].to_vec();
    let exts = &body[1 + ctx_len..];
    walk_extensions(exts, |_, _| Ok(()))?;
    Ok(context)
}

/// Parse a Certificate message body. Returns the parsed chain and the
/// leaf's public key (copied out, so the borrowed chain can drop).
/// The server's `certificate_request_context` must be empty
/// (RFC 8446 §4.4.2).
fn parse_certificate_message(body: &[u8]) -> Result<(Vec<Certificate<'_>>, LeafKey), TlsError> {
    if body.is_empty() || body[0] != 0 {
        return Err(TlsError::DecodeError);
    }
    if body.len() < 4 {
        return Err(TlsError::DecodeError);
    }
    let list_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | (body[3] as usize);
    if body.len() != 4 + list_len {
        return Err(TlsError::DecodeError);
    }
    let mut chain: Vec<Certificate> = Vec::new();
    let mut pos = 4;
    while pos < body.len() {
        if pos + 3 > body.len() {
            return Err(TlsError::DecodeError);
        }
        let cert_len = ((body[pos] as usize) << 16)
            | ((body[pos + 1] as usize) << 8)
            | (body[pos + 2] as usize);
        pos += 3;
        if cert_len == 0 || pos + cert_len + 2 > body.len() {
            return Err(TlsError::DecodeError);
        }
        let cert = parse_certificate(&body[pos..pos + cert_len])?;
        pos += cert_len;
        let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2;
        if pos + ext_len > body.len() {
            return Err(TlsError::DecodeError);
        }
        pos += ext_len; // per-certificate extensions are ignored
        chain.push(cert);
    }
    if chain.is_empty() {
        return Err(TlsError::DecodeError);
    }
    let leaf = match &chain[0].spki {
        Spki::Rsa { n, e } => LeafKey::Rsa {
            n: n.to_vec(),
            e: *e,
        },
        Spki::EcP256 { point } => {
            let mut p = [0u8; 65];
            p.copy_from_slice(point);
            LeafKey::EcP256 { point: p }
        }
        Spki::Ed25519 { point } => {
            let mut p = [0u8; 32];
            p.copy_from_slice(point);
            LeafKey::Ed25519 { point: p }
        }
    };
    Ok((chain, leaf))
}

/// Verify a CertificateVerify message (RFC 8446 §4.4.3) against the
/// leaf key and the transcript hash (which excludes this message).
/// The signature is over `0x20×64 || "TLS 1.3, server
/// CertificateVerify" || 0x00 || Hash(transcript)`. The scheme must be
/// one we offered; anything else is a protocol violation.
fn verify_certificate_verify(
    leaf: &LeafKey,
    body: &[u8],
    transcript: &[u8],
) -> Result<(), TlsError> {
    if body.len() < 4 {
        return Err(TlsError::DecodeError);
    }
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
    if body.len() != 4 + sig_len {
        return Err(TlsError::DecodeError);
    }
    let sig = &body[4..];
    let mut context = Vec::with_capacity(64 + 33 + 1 + 32);
    context.extend_from_slice(&[0x20u8; 64]);
    context.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    context.push(0);
    context.extend_from_slice(&sha256(transcript));
    let digest = sha256(&context);
    let ok = match (scheme, leaf) {
        (SIG_RSA_PKCS1_SHA256, LeafKey::Rsa { n, e }) => {
            pkcs1_v15_verify_sha256(n, *e, sig, &digest)
        }
        (SIG_RSA_PSS_RSAE_SHA256, LeafKey::Rsa { n, e }) => {
            // TLS mandates salt length == hash length (RFC 8446
            // §4.4.3).
            pss_verify_sha256(n, *e, sig, &digest, 32)
        }
        (SIG_ECDSA_SECP256R1_SHA256, LeafKey::EcP256 { point }) => {
            let Some((r, s)) = parse_ecdsa_sig(sig) else {
                return Err(TlsError::DecodeError);
            };
            verify_p256(point, &digest, &r, &s)
        }
        (SIG_ED25519, LeafKey::Ed25519 { point }) => {
            // EdPublicKey is [u8; 32]: the conversion is infallible.
            let pk: EdPublicKey = *point;
            let Ok(s): Result<EdSignature, _> = sig.try_into() else {
                return Err(TlsError::DecodeError);
            };
            ed25519_verify(&pk, &context, &s)
        }
        _ => return Err(TlsError::DecodeError),
    };
    if ok {
        Ok(())
    } else {
        Err(TlsError::CertError(X509Error::InvalidSignature))
    }
}

/// Parse a DER ECDSA signature `SEQUENCE { INTEGER r, INTEGER s }`
/// into fixed 32-byte values.
fn parse_ecdsa_sig(sig: &[u8]) -> Option<([u8; 32], [u8; 32])> {
    if sig.len() < 2 || sig[0] != 0x30 {
        return None;
    }
    // Short-form length only (r/s are ≤33 bytes each).
    let len = sig[1] as usize;
    if sig.len() != 2 + len || len < 4 {
        return None;
    }
    let mut pos = 2;
    if sig[pos] != 0x02 {
        return None;
    }
    let r_len = sig[pos + 1] as usize;
    pos += 2;
    if pos + r_len > sig.len() {
        return None;
    }
    let r = int_to_fixed32(&sig[pos..pos + r_len])?;
    pos += r_len;
    if pos + 2 > sig.len() || sig[pos] != 0x02 {
        return None;
    }
    let s_len = sig[pos + 1] as usize;
    pos += 2;
    if pos + s_len != sig.len() {
        return None;
    }
    let s = int_to_fixed32(&sig[pos..pos + s_len])?;
    Some((r, s))
}

/// Verify a Finished message body: `HMAC(finished_key,
/// Hash(transcript))` (RFC 8446 §4.4.4).
fn verify_finished(finished_key: &[u8], body: &[u8], transcript: &[u8]) -> Result<(), TlsError> {
    if body.len() != 32 {
        return Err(TlsError::DecodeError);
    }
    let expected = hmac_sha256(finished_key, &sha256(transcript));
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= body[i] ^ expected[i];
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(TlsError::BadFinished)
    }
}

/// Compute our Finished `verify_data` for the current transcript.
fn compute_finished(finished_key: &[u8], transcript: &[u8]) -> Vec<u8> {
    hmac_sha256(finished_key, &sha256(transcript)).to_vec()
}

/// The handshake key schedule (RFC 8446 §7.1) for a negotiated
/// ciphersuite: early secret (no PSK) → handshake secret → client/
/// server handshake traffic secrets + keys. Returns (client keys,
/// server keys, client secret, server secret, handshake secret).
pub(crate) fn derive_handshake_secrets(
    cipher: Cipher,
    shared_secret: &[u8; 32],
    transcript: &[u8],
) -> (TrafficKeys, TrafficKeys, [u8; 32], [u8; 32], [u8; 32]) {
    let early_secret = hkdf_extract(None, &[0u8; 32]);
    let derived = derive_secret(&early_secret, "derived", &sha256(b""));
    let handshake_secret = hkdf_extract(Some(&derived), shared_secret);
    let th = sha256(transcript);
    let c_hs = derive_secret(&handshake_secret, "c hs traffic", &th);
    let s_hs = derive_secret(&handshake_secret, "s hs traffic", &th);
    (
        traffic_keys(cipher, &c_hs),
        traffic_keys(cipher, &s_hs),
        c_hs,
        s_hs,
        handshake_secret,
    )
}

/// Validate a NewSessionTicket body structurally (lifetime, age_add,
/// nonce, ticket, extensions). The ticket is discarded — no
/// resumption in this client.
fn parse_new_session_ticket(body: &[u8]) -> Result<(), TlsError> {
    if body.len() < 4 + 4 + 1 + 2 + 2 {
        return Err(TlsError::DecodeError);
    }
    let mut pos = 8;
    let nonce_len = body[pos] as usize;
    pos += 1 + nonce_len;
    if pos + 2 > body.len() {
        return Err(TlsError::DecodeError);
    }
    let ticket_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + ticket_len;
    if pos + 2 > body.len() {
        return Err(TlsError::DecodeError);
    }
    let exts = &body[pos..];
    walk_extensions(exts, |_, _| Ok(()))
}
