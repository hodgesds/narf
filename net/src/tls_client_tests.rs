//! TLS 1.3 client fixtures (RFC 8448 §3) and chain tests.
//!
//! The handshake fixture reproduces the RFC 8448 §3 simple 1-RTT
//! handshake against the trace's published values. The server flight
//! is built by encrypting the trace's published plaintext with the
//! trace's published server handshake keys (AES-128-GCM, seq 0) —
//! the first 21 bytes of the built record are asserted against the
//! trace's published ciphertext, which anchors the construction
//! (key, nonce, AAD, plaintext) to the real RFC bytes; AES-GCM is
//! deterministic, so a matching prefix plus the published plaintext
//! means the built record IS the trace record. The same construction
//! builds the NewSessionTicket (server ap keys, seq 0) and server
//! application data (server ap keys, seq 1) records.
//!
//! The client side is fully asserted: the ClientHello record must be
//! byte-identical to the trace, the client Finished record must be
//! byte-identical, and the client application-data record must be
//! byte-identical. Any error in the key schedule, record protection,
//! or handshake transcript breaks one of those equalities.
//!
//! Chain tests use openssl-generated DER fixtures in
//! `net/src/tls_fixtures/` (ECDSA P-256, Ed25519, RSA-2048 CAs and
//! leaves; wrong-CA, expired, CN-only, wildcard leaves). The fixture
//! clock for those is 2027-01-01 (leaves are valid 2026-11-08 to
//! 2036-11-05; the expired leaf lapsed 2026-11-09).
//!
//! References (public-only):
//! - RFC 8448 §3 — the trace (all hex below is transcribed from it).
//! - RFC 8446 — the protocol.

use alloc::boxed::Box;
use alloc::vec::Vec;

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm, Key as GcmKey, Nonce as GcmNonce,
};
use narf_crypto::hkdf::{hkdf_extract, hmac_sha256};

use crate::tls_client::{
    aead_open, aead_seal, build_client_hello, derive_handshake_secrets, derive_secret,
    hkdf_expand_label, traffic_keys, Cipher, ClientConfig, SliceTransport, TlsClient, TlsError,
};
use crate::tls_x509::{parse_certificate, sha256, RootStore, X509Error};

/// Hex decoder for the trace constants.
fn hex(s: &str) -> Vec<u8> {
    let s = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
        let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
        out.push((hi << 4) | lo);
    }
    out
}

fn arr32(s: &str) -> [u8; 32] {
    hex(s).try_into().unwrap()
}

fn arr16(s: &str) -> [u8; 16] {
    hex(s).try_into().unwrap()
}

fn arr12(s: &str) -> [u8; 12] {
    hex(s).try_into().unwrap()
}

// ─── RFC 8448 §3 inputs ────────────────────────────────────────────────────

/// Client random (RFC 8448 §3, ClientHello).
const CLIENT_RANDOM: &str = "cb34ecb1e78163ba1c38c6dacb196a6dff\
    a21a8d9912ec18a2ef6283024dece7";
/// Client ephemeral private key (RFC 8448 §3).
const CLIENT_PRIV: &str = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";
/// Shared secret (RFC 8448 §3, handshake Extract IKM).
const SHARED_SECRET: &str = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";

/// The full ClientHello record (201 bytes), RFC 8448 §3.
const CLIENT_HELLO_RECORD: &str = "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dff\
    a21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572\
    ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d00\
    2099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020\
    001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002\
    4001";

/// The full ServerHello record (95 bytes), RFC 8448 §3.
const SERVER_HELLO_RECORD: &str = "160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5\
    cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6\
    cc253b833df1dd69b1b04e751f0f002b00020304";

/// EncryptedExtensions (40 bytes), RFC 8448 §3.
const ENCRYPTED_EXTENSIONS: &str = "080000240022000a00140012001d00170018001901000101010201030104\
    001c0002400100000000";

/// Certificate message (445 bytes), RFC 8448 §3. The certificate DER
/// (432 bytes) is the `CERT_DER` constant below.
const CERTIFICATE_MESSAGE: &str = "0b0001b9000001b50001b0";

/// The server certificate DER (432 bytes), RFC 8448 §3: 1024-bit RSA,
/// self-signed, CN `rsa`, validity 2016-07-30 → 2026-07-30, no SAN,
/// `sha256WithRSAEncryption`.
const CERT_DER: &str = "308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a\
    06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a\
    300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d003081890281\
    8100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95\
    137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda43084\
    6748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203\
    010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b\
    05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c\
    8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99b\
    e5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4d\
    e1";

/// CertificateVerify (136 bytes), RFC 8448 §3: scheme 0x0804
/// (rsa_pss_rsae_sha256), 128-byte signature.
const CERTIFICATE_VERIFY: &str = "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145\
    ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d\
    4859ee511f602957b15411ac027671459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e\
    063dda65cdf5aea20d53dfacd42f74f3";

/// Server Finished (36 bytes), RFC 8448 §3.
const SERVER_FINISHED: &str = "140000209b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454\
    b78f0718";

/// NewSessionTicket plaintext (205 bytes), RFC 8448 §3.
const NEW_SESSION_TICKET: &str = "040000c90000001efad6aac502000000b22c035d829359ee5ff7af4ec90000\
    0000262a6494dc486d2c8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097a3a9821172\
    83f82a03a143efd3ff5dd36d64e861be7fd61d2827db279cce145077d454a3664d4e6da4d29ee03725a6a4da\
    fcd0fc67d2aea70529513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5aea617646fac5c\
    03272e970727c621a79141ef5f7de6505e5bfbc388e93343694093934ae4d3570008002a000400000400";

/// The client's Finished record (58 bytes), RFC 8448 §3 — the exact
/// bytes our client must emit.
const EXPECTED_CLIENT_FINISHED_RECORD: &str =
    "170303003575ec4dc238cce60b298044a71e219c56cc77b0517f\
    e9b93c7a4bfc44d87f38f80338ac98fc46deb384bd1caeacab6867d726c40546";

/// The client's application-data record (72 bytes), RFC 8448 §3 —
/// the exact bytes our client must emit for payload `00..31`.
const EXPECTED_CLIENT_APP_RECORD: &str = "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa\
    66bcab3f2b9819a8a5b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4";

/// The server's close_notify record (24 bytes), RFC 8448 §3.
const SERVER_CLOSE_NOTIFY_RECORD: &str = "1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9";

/// First 21 bytes of the trace's encrypted server-flight record
/// (header + 16 ciphertext bytes) — the anchor for the constructed
/// flight record.
const FLIGHT_RECORD_PREFIX: &str = "17030302a2d1ff334a56f5bff6594a077869fcf40aa4";
/// First 21 bytes of the trace's NewSessionTicket record.
const NST_RECORD_PREFIX: &str = "17030300de3a6b8f90414a97d6959c3487680de513";
/// First 21 bytes of the trace's server application-data record.
const SERVER_APP_RECORD_PREFIX: &str = "17030300432e937e11ef4ac740e538ad36005fc4a469";

/// The application-data payload both sides send, RFC 8448 §3.
fn app_payload() -> Vec<u8> {
    (0u8..50).collect()
}

// ─── Key-schedule values (RFC 8448 §3) ─────────────────────────────────────

const EARLY_SECRET: &str = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
const DERIVED_SECRET: &str = "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba";
const HANDSHAKE_SECRET: &str = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
const C_HS_TRAFFIC: &str = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
const S_HS_TRAFFIC: &str = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
const C_HS_KEY: &str = "dbfaa693d1762c5b666af5d950258d01";
const C_HS_IV: &str = "5bd3c71b836e0b76bb73265f";
const S_HS_KEY: &str = "3fce516009c21727d0f2e4e86ee403bc";
const S_HS_IV: &str = "5d313eb2671276ee13000b30";
const MASTER_SECRET: &str = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
const C_AP_TRAFFIC: &str = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
const S_AP_TRAFFIC: &str = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
const C_AP_KEY: &str = "17422dda596ed5d9acd890e3c63f5051";
const C_AP_IV: &str = "5b78923dee08579033e523d9";
const S_AP_KEY: &str = "9f02283b6c9c07efc26bb9f2ac92e356";
const S_AP_IV: &str = "cf782b88dd83549aadf1e984";
const EXP_MASTER: &str = "fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50";
const RES_MASTER: &str = "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c";
const SERVER_FINISHED_VERIFY: &str =
    "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718";
const CLIENT_FINISHED_VERIFY: &str =
    "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61";

/// The RFC 8448 trace's fixture clock: 2020-01-01T00:00:00Z, inside
/// the trace cert's validity (2016-07-30 → 2026-07-30).
const RFC_NOW: u64 = 1_577_836_800;
/// The openssl-fixture clock: 2027-01-01T00:00:00Z.
const OPENSSL_NOW: u64 = 1_798_761_600;

// ─── Helpers ────────────────────────────────────────────────────────────────

/// The RFC 8448 extension set (the fixture seam): suites 1301/1303/
/// 1302, groups 001d/0017/0018/0019/0100/0101/0102/0103/0104, the
/// trace's 15 signature schemes, psk modes, record_size_limit 16385,
/// renegotiation_info, extended_master_secret.
fn rfc_config<'a>(roots: &'a RootStore<'a>) -> ClientConfig<'a> {
    let mut config = ClientConfig::new(roots, RFC_NOW);
    config.server_name = Some("server");
    // The trace cert's CN is `rsa`, not `server`, and it has no SAN —
    // the name check is off for this fixture (hostname checking is
    // covered by the openssl-cert tests).
    config.verify_hostname = false;
    config.client_random = Some(arr32(CLIENT_RANDOM));
    config.ephemeral_private = Some(arr32(CLIENT_PRIV));
    config.offered_suites = &[0x1301, 0x1303, 0x1302];
    config.offered_groups = &[
        0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
    ];
    config.offered_sig_algs = &[
        0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0201,
        0x0402, 0x0502, 0x0602, 0x0202,
    ];
    config.offer_psk_modes = true;
    config.record_size_limit = Some(0x4001);
    config.offer_renegotiation_info = true;
    config.offer_extended_master_secret = true;
    config
}

/// The server-flight plaintext: EE + Certificate + CertificateVerify
/// + Finished (657 bytes).
fn flight_plaintext() -> Vec<u8> {
    let mut out = Vec::with_capacity(657);
    out.extend_from_slice(&hex(ENCRYPTED_EXTENSIONS));
    out.extend_from_slice(&hex(CERTIFICATE_MESSAGE));
    out.extend_from_slice(&hex(CERT_DER));
    out.extend_from_slice(&hex("0000")); // per-certificate extensions: empty
    out.extend_from_slice(&hex(CERTIFICATE_VERIFY));
    out.extend_from_slice(&hex(SERVER_FINISHED));
    out
}

/// Seal `plaintext` (already including its inner content-type byte)
/// as one AES-128-GCM application-data record under `key`/`iv`/`seq`.
fn seal_aes_record(key: &[u8; 16], iv: &[u8; 12], seq: u64, plaintext: &[u8]) -> Vec<u8> {
    let total = plaintext.len() + 16;
    let mut header = [0u8; 5];
    header[0] = 0x17;
    header[1] = 0x03;
    header[2] = 0x03;
    header[3..5].copy_from_slice(&(total as u16).to_be_bytes());
    let mut nonce = *iv;
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let mut buf = plaintext.to_vec();
    let cipher = Aes128Gcm::new(GcmKey::<Aes128Gcm>::from_slice(key));
    let tag = cipher
        .encrypt_in_place_detached(GcmNonce::from_slice(&nonce), &header, &mut buf)
        .expect("aes-gcm seal");
    let mut out = Vec::with_capacity(5 + total);
    out.extend_from_slice(&header);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    out
}

/// The server-flight record, built by encrypting the trace plaintext
/// with the trace server handshake keys (seq 0).
fn flight_record() -> Vec<u8> {
    let mut inner = flight_plaintext();
    inner.push(0x16); // inner content type: handshake
    let record = seal_aes_record(&arr16(S_HS_KEY), &arr12(S_HS_IV), 0, &inner);
    assert_eq!(record.len(), 679, "flight record length");
    assert_eq!(
        &record[..21],
        hex(FLIGHT_RECORD_PREFIX).as_slice(),
        "flight record prefix must match the RFC ciphertext"
    );
    record
}

/// The NewSessionTicket record (server ap keys, seq 0).
fn nst_record() -> Vec<u8> {
    let mut inner = hex(NEW_SESSION_TICKET);
    inner.push(0x16);
    let record = seal_aes_record(&arr16(S_AP_KEY), &arr12(S_AP_IV), 0, &inner);
    assert_eq!(record.len(), 227, "NST record length");
    assert_eq!(
        &record[..21],
        hex(NST_RECORD_PREFIX).as_slice(),
        "NST record prefix must match the RFC ciphertext"
    );
    record
}

/// The server application-data record (server ap keys, seq 1).
fn server_app_record() -> Vec<u8> {
    let mut inner = app_payload();
    inner.push(0x17); // inner content type: application_data
    let record = seal_aes_record(&arr16(S_AP_KEY), &arr12(S_AP_IV), 1, &inner);
    assert_eq!(record.len(), 72, "server app record length");
    assert_eq!(
        &record[..21],
        hex(SERVER_APP_RECORD_PREFIX).as_slice(),
        "server app record prefix must match the RFC ciphertext"
    );
    record
}

/// A store trusting the RFC 8448 trace certificate (self-signed,
/// pinned by the test).
fn rfc_store() -> RootStore<'static> {
    let mut store = RootStore::new();
    store
        .add_root_der(Box::leak(hex(CERT_DER).into_boxed_slice()))
        .expect("RFC cert parses");
    store
}

// ─── Tests ──────────────────────────────────────────────────────────────────

/// The key schedule against every intermediate value in RFC 8448 §3.
#[test]
fn key_schedule_matches_rfc8448() {
    let ch = &hex(CLIENT_HELLO_RECORD)[5..];
    let sh = &hex(SERVER_HELLO_RECORD)[5..];
    let mut transcript = Vec::with_capacity(ch.len() + sh.len());
    transcript.extend_from_slice(ch);
    transcript.extend_from_slice(sh);

    // Early secret + derived (empty transcript hash).
    let early = hkdf_extract(None, &[0u8; 32]);
    assert_eq!(early, arr32(EARLY_SECRET));
    let derived = derive_secret(&early, "derived", &sha256(b""));
    assert_eq!(derived, arr32(DERIVED_SECRET));

    // Handshake secret + traffic secrets/keys.
    let (c_keys, s_keys, c_hs, s_hs, hs_secret) =
        derive_handshake_secrets(Cipher::Aes128Gcm, &arr32(SHARED_SECRET), &transcript);
    assert_eq!(hs_secret, arr32(HANDSHAKE_SECRET));
    assert_eq!(c_hs, arr32(C_HS_TRAFFIC));
    assert_eq!(s_hs, arr32(S_HS_TRAFFIC));
    assert_eq!(&c_keys.key[..16], arr16(C_HS_KEY).as_slice());
    assert_eq!(c_keys.iv, arr12(C_HS_IV));
    assert_eq!(&s_keys.key[..16], arr16(S_HS_KEY).as_slice());
    assert_eq!(s_keys.iv, arr12(S_HS_IV));

    // Master secret + application traffic secrets/keys. The transcript
    // is now CH || SH || EE || Cert || CV || server Finished.
    let mut full = transcript.clone();
    full.extend_from_slice(&flight_plaintext());
    let derived2 = derive_secret(&hs_secret, "derived", &sha256(b""));
    let master = hkdf_extract(Some(&derived2), &[0u8; 32]);
    assert_eq!(master, arr32(MASTER_SECRET));
    let th = sha256(&full);
    let c_ap = derive_secret(&master, "c ap traffic", &th);
    let s_ap = derive_secret(&master, "s ap traffic", &th);
    assert_eq!(c_ap, arr32(C_AP_TRAFFIC));
    assert_eq!(s_ap, arr32(S_AP_TRAFFIC));
    let c_ap_keys = traffic_keys(Cipher::Aes128Gcm, &c_ap);
    let s_ap_keys = traffic_keys(Cipher::Aes128Gcm, &s_ap);
    assert_eq!(&c_ap_keys.key[..16], arr16(C_AP_KEY).as_slice());
    assert_eq!(c_ap_keys.iv, arr12(C_AP_IV));
    assert_eq!(&s_ap_keys.key[..16], arr16(S_AP_KEY).as_slice());
    assert_eq!(s_ap_keys.iv, arr12(S_AP_IV));

    // Exporter + resumption masters.
    let exp = derive_secret(&master, "exp master", &th);
    assert_eq!(exp, arr32(EXP_MASTER));
    let mut with_client_finished = full.clone();
    with_client_finished.extend_from_slice(&hex(
        "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61",
    ));
    let res = derive_secret(&master, "res master", &sha256(&with_client_finished));
    assert_eq!(res, arr32(RES_MASTER));

    // Finished verify_data values.
    let s_finished_key = hkdf_expand_label(&s_hs, "finished", b"", 32);
    assert_eq!(
        hmac_sha256(&s_finished_key, &sha256(&full)).as_slice(),
        hex(SERVER_FINISHED_VERIFY).as_slice()
    );
    let c_finished_key = hkdf_expand_label(&c_hs, "finished", b"", 32);
    assert_eq!(
        hmac_sha256(&c_finished_key, &sha256(&full)).as_slice(),
        hex(CLIENT_FINISHED_VERIFY).as_slice()
    );
}

/// The ClientHello builder reproduces the RFC 8448 §3 record
/// byte-exactly (same random, same ephemeral key, same extension set).
#[test]
fn client_hello_matches_rfc8448_record() {
    let store = rfc_store();
    let config = rfc_config(&store);
    let pub_key = crate::tls_x25519::x25519_public(&arr32(CLIENT_PRIV)).unwrap();
    let hello = build_client_hello(&config, &arr32(CLIENT_RANDOM), &pub_key);
    let mut expected = Vec::with_capacity(201);
    expected.push(0x16);
    expected.extend_from_slice(&[0x03, 0x01]);
    expected.extend_from_slice(&(196u16).to_be_bytes());
    expected.extend_from_slice(&hello);
    assert_eq!(expected.len(), 201);
    assert_eq!(expected, hex(CLIENT_HELLO_RECORD));
}

/// The client's close_notify record (24 bytes), RFC 8448 §3.
const EXPECTED_CLIENT_CLOSE_NOTIFY_RECORD: &str =
    "1703030013c9872760655666b74d7ff1153efd6db6d0b0e3";

/// The full RFC 8448 §3 handshake, end to end: the client must emit
/// the trace's ClientHello and Finished records byte-exactly, exchange
/// the trace's application data, and handle the NewSessionTicket and
/// close_notify.
#[test]
fn full_handshake_matches_rfc8448() {
    let store = rfc_store();
    let config = rfc_config(&store);
    let mut input = Vec::new();
    input.extend_from_slice(&hex(SERVER_HELLO_RECORD));
    input.extend_from_slice(&flight_record());
    input.extend_from_slice(&nst_record());
    input.extend_from_slice(&server_app_record());
    input.extend_from_slice(&hex(SERVER_CLOSE_NOTIFY_RECORD));
    let transport = SliceTransport::new(Box::leak(input.into_boxed_slice()));
    let mut client = TlsClient::connect(transport, config).expect("handshake succeeds");
    assert_eq!(client.negotiated_cipher(), Some(Cipher::Aes128Gcm));

    // ClientHello + Finished, byte-exact.
    let mut expected = hex(CLIENT_HELLO_RECORD);
    expected.extend_from_slice(&hex(EXPECTED_CLIENT_FINISHED_RECORD));
    assert_eq!(client.transport().written(), expected.as_slice());

    // Application data out: byte-exact record.
    client.send_app_data(&app_payload()).expect("send app data");
    expected.extend_from_slice(&hex(EXPECTED_CLIENT_APP_RECORD));
    assert_eq!(client.transport().written(), expected.as_slice());

    // Application data in (the NewSessionTicket is consumed inline).
    let got = client.recv_app_data().expect("recv app data");
    assert_eq!(got, app_payload());

    // The server's close_notify ends the connection.
    assert_eq!(
        client.recv_app_data(),
        Err(TlsError::Closed),
        "server close_notify"
    );

    // Our close_notify is the trace's record.
    client.close();
    expected.extend_from_slice(&hex(EXPECTED_CLIENT_CLOSE_NOTIFY_RECORD));
    assert_eq!(client.transport().written(), expected.as_slice());
}

/// ChaCha20-Poly1305 at the record layer: key derivation (32-byte
/// keys), seal/open round-trip, cross-check of the seal against the
/// in-tree AEAD directly (same nonce/AAD), and tag failure.
///
/// A full ChaCha handshake against the trace is not possible without
/// re-signing CertificateVerify for a different transcript (the trace
/// server's private key is published in RFC 8448 §2, but this lane
/// does not implement RSA signing); the record layer and derivation
/// are the client-specific ChaCha logic, and they are covered here.
#[test]
fn chacha_record_layer() {
    use narf_crypto::aead::chacha20_poly1305_seal;

    let secret = [7u8; 32];
    let keys = traffic_keys(Cipher::ChaCha20Poly1305, &secret);
    assert_eq!(keys.key_len, 32);
    assert_eq!(
        keys.key,
        hkdf_expand_label(&secret, "key", b"", 32).as_slice()
    );
    assert_eq!(
        keys.iv,
        hkdf_expand_label(&secret, "iv", b"", 12).as_slice()
    );

    let aad = [0x17u8, 0x03, 0x03, 0x00, 0x1a];
    let mut plaintext = b"hello tls".to_vec();
    let tag = aead_seal(Cipher::ChaCha20Poly1305, &keys, 5, &aad, &mut plaintext);

    // Independent seal with the same nonce (IV XOR seq 5).
    let mut nonce = keys.iv;
    for (i, b) in 5u64.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let mut expected = b"hello tls".to_vec();
    let tag2 = chacha20_poly1305_seal(&keys.key, &nonce, &aad, &mut expected);
    assert_eq!(tag, tag2);
    assert_eq!(plaintext, expected);

    // Open round-trips; a flipped tag fails.
    let mut ct = plaintext.clone();
    assert!(aead_open(
        Cipher::ChaCha20Poly1305,
        &keys,
        5,
        &aad,
        &mut ct,
        &tag
    ));
    assert_eq!(ct, b"hello tls");
    let mut bad_tag = tag;
    bad_tag[0] ^= 1;
    let mut ct2 = plaintext.clone();
    assert!(!aead_open(
        Cipher::ChaCha20Poly1305,
        &keys,
        5,
        &aad,
        &mut ct2,
        &bad_tag
    ));

    // The AES path round-trips too (16-byte keys).
    let aes_keys = traffic_keys(Cipher::Aes128Gcm, &secret);
    assert_eq!(aes_keys.key_len, 16);
    let mut pt = b"aes test".to_vec();
    let tag = aead_seal(Cipher::Aes128Gcm, &aes_keys, 0, &aad, &mut pt);
    let mut ct = pt.clone();
    assert!(aead_open(
        Cipher::Aes128Gcm,
        &aes_keys,
        0,
        &aad,
        &mut ct,
        &tag
    ));
    assert_eq!(ct, b"aes test");
}

// ─── Chain tests (openssl fixtures) ─────────────────────────────────────────

fn fixture_store(ca: &[u8]) -> RootStore<'static> {
    let mut store = RootStore::new();
    store
        .add_root_der(Box::leak(ca.to_vec().into_boxed_slice()))
        .expect("fixture CA parses");
    store
}

fn leaf(der: &[u8]) -> crate::tls_x509::Certificate<'_> {
    parse_certificate(der).expect("fixture leaf parses")
}

#[test]
fn chain_ec_valid() {
    let store = fixture_store(include_bytes!("tls_fixtures/ca_ec.der"));
    let chain = [leaf(include_bytes!("tls_fixtures/leaf_ec.der"))];
    assert!(store
        .verify_chain(&chain, Some("example.com"), OPENSSL_NOW)
        .is_ok());
}

#[test]
fn chain_ed25519_valid() {
    let store = fixture_store(include_bytes!("tls_fixtures/ca_ed.der"));
    let chain = [leaf(include_bytes!("tls_fixtures/leaf_ed.der"))];
    assert!(store
        .verify_chain(&chain, Some("example.com"), OPENSSL_NOW)
        .is_ok());
}

#[test]
fn chain_rsa_valid() {
    let store = fixture_store(include_bytes!("tls_fixtures/ca_rsa.der"));
    let chain = [leaf(include_bytes!("tls_fixtures/leaf_rsa.der"))];
    assert!(store
        .verify_chain(&chain, Some("example.com"), OPENSSL_NOW)
        .is_ok());
}

#[test]
fn chain_wrong_ca_rejected() {
    let store = fixture_store(include_bytes!("tls_fixtures/ca_ec.der"));
    let chain = [leaf(include_bytes!("tls_fixtures/leaf_wrongca.der"))];
    assert_eq!(
        store.verify_chain(&chain, Some("example.com"), OPENSSL_NOW),
        Err(X509Error::UnknownIssuer)
    );
}

#[test]
fn chain_expired_rejected() {
    let store = fixture_store(include_bytes!("tls_fixtures/ca_ec.der"));
    let chain = [leaf(include_bytes!("tls_fixtures/leaf_expired.der"))];
    assert_eq!(
        store.verify_chain(&chain, Some("example.com"), OPENSSL_NOW),
        Err(X509Error::Expired)
    );
}

#[test]
fn chain_not_yet_valid_rejected() {
    let store = fixture_store(include_bytes!("tls_fixtures/ca_ec.der"));
    let chain = [leaf(include_bytes!("tls_fixtures/leaf_ec.der"))];
    assert_eq!(
        store.verify_chain(&chain, Some("example.com"), 1_700_000_000),
        Err(X509Error::NotYetValid)
    );
}

#[test]
fn chain_hostname_mismatch_rejected() {
    let store = fixture_store(include_bytes!("tls_fixtures/ca_ec.der"));
    let chain = [leaf(include_bytes!("tls_fixtures/leaf_ec.der"))];
    assert_eq!(
        store.verify_chain(&chain, Some("other.com"), OPENSSL_NOW),
        Err(X509Error::HostnameMismatch)
    );
}

#[test]
fn chain_cn_fallback_matches() {
    let store = fixture_store(include_bytes!("tls_fixtures/ca_ec.der"));
    let chain = [leaf(include_bytes!("tls_fixtures/leaf_cn.der"))];
    assert!(store
        .verify_chain(&chain, Some("example.com"), OPENSSL_NOW)
        .is_ok());
    assert_eq!(
        store.verify_chain(&chain, Some("other.com"), OPENSSL_NOW),
        Err(X509Error::HostnameMismatch)
    );
}

#[test]
fn chain_wildcard_matches_one_label() {
    let store = fixture_store(include_bytes!("tls_fixtures/ca_ec.der"));
    let chain = [leaf(include_bytes!("tls_fixtures/leaf_wild.der"))];
    assert!(store
        .verify_chain(&chain, Some("foo.example.com"), OPENSSL_NOW)
        .is_ok());
    assert_eq!(
        store.verify_chain(&chain, Some("a.b.example.com"), OPENSSL_NOW),
        Err(X509Error::HostnameMismatch)
    );
    assert_eq!(
        store.verify_chain(&chain, Some("example.com"), OPENSSL_NOW),
        Err(X509Error::HostnameMismatch)
    );
}

#[test]
fn rfc_cert_parses_and_self_verifies() {
    let der = hex(CERT_DER);
    let cert = parse_certificate(&der).expect("RFC cert parses");
    assert_eq!(cert.cn, Some(b"rsa".as_slice()));
    assert!(cert.san_dns.is_empty());
    assert!(!cert.is_ca);
    assert_eq!(cert.not_before, 1_469_829_039); // 2016-07-30T01:23:59Z
    assert_eq!(cert.not_after, 1_785_452_239); // 2026-07-30T01:23:59Z
    assert!(matches!(
        cert.spki,
        crate::tls_x509::Spki::Rsa { e: 65537, .. }
    ));
    // Self-signed: verifies with its own key, and chains to itself
    // as a pinned root.
    assert!(crate::tls_x509::verify_cert_signature(&cert, &cert));
    let store = rfc_store();
    assert!(store.verify_chain(&[cert], None, RFC_NOW).is_ok());
}

// ─── Negative handshake fixtures ────────────────────────────────────────────

fn handshake_input_with_flight(flight: &[u8]) -> Vec<u8> {
    let mut input = Vec::new();
    input.extend_from_slice(&hex(SERVER_HELLO_RECORD));
    input.extend_from_slice(flight);
    input
}

fn run_handshake<'a>(
    input: Vec<u8>,
    store: &'a RootStore<'a>,
) -> Result<TlsClient<'a, SliceTransport<'a>>, TlsError> {
    let config = rfc_config(store);
    let transport = SliceTransport::new(Box::leak(input.into_boxed_slice()));
    TlsClient::connect(transport, config)
}

#[test]
fn handshake_bad_finished_mac_rejected() {
    let store = rfc_store();
    // Flip a byte in the server Finished verify_data, then seal.
    let mut plaintext = flight_plaintext();
    let last = plaintext.len() - 1;
    plaintext[last] ^= 0x01;
    let mut inner = plaintext;
    inner.push(0x16);
    let flight = seal_aes_record(&arr16(S_HS_KEY), &arr12(S_HS_IV), 0, &inner);
    let err = run_handshake(handshake_input_with_flight(&flight), &store).unwrap_err();
    assert_eq!(err, TlsError::BadFinished);
}

#[test]
fn handshake_bad_chain_rejected() {
    let store = rfc_store();
    // Flip a byte inside the certificate signature, then seal.
    let mut plaintext = flight_plaintext();
    // The cert DER starts at offset 51; the signature is near its end.
    plaintext[51 + 400] ^= 0x01;
    let mut inner = plaintext;
    inner.push(0x16);
    let flight = seal_aes_record(&arr16(S_HS_KEY), &arr12(S_HS_IV), 0, &inner);
    let err = run_handshake(handshake_input_with_flight(&flight), &store).unwrap_err();
    assert!(matches!(err, TlsError::CertError(_)), "got {err:?}");
}

#[test]
fn handshake_wrong_version_rejected() {
    let store = rfc_store();
    // ServerHello supported_versions 0x0304 -> 0x0303.
    let mut sh = hex(SERVER_HELLO_RECORD);
    let n = sh.len();
    assert_eq!(&sh[n - 2..], &[0x03, 0x04]);
    sh[n - 1] = 0x03;
    let mut input = sh;
    input.extend_from_slice(&flight_record());
    let err = run_handshake(input, &store).unwrap_err();
    assert_eq!(err, TlsError::UnsupportedVersion);
}

#[test]
fn handshake_unknown_ca_rejected() {
    let store = RootStore::new();
    let err = run_handshake(handshake_input_with_flight(&flight_record()), &store).unwrap_err();
    assert_eq!(err, TlsError::CertError(X509Error::UnknownIssuer));
}
