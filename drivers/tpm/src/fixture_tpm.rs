//! `FixtureTpm` — a spec-shaped TPM 2.0 command core for test
//! fixtures (#1002), in the spirit of the #946 keystone model:
//! it answers through the production [`TpmTransport`] seam with
//! command/response framing taken from the TPM 2.0 Library
//! specification, and it *computes* the state transitions the
//! sealing conversation depends on — it never pattern-matches
//! a canned transcript.
//!
//! Modelled, with real semantics:
//!
//! - **Sessions with real policyDigest chaining.** A policy or
//!   trial session's digest evolves exactly per Part 3 §23.7
//!   (`policyDigestnew = H(policyDigestold ‖ TPM_CC_PolicyPCR ‖
//!   marshaled TPML_PCR_SELECTION ‖ digest)`); `PolicyPCR` on a
//!   non-trial session checks the digest TPM-side (Part 1
//!   "PolicyPCR": digestTPM = H(selected PCR values)) and a
//!   mismatch fails the command and invalidates the session
//!   without touching its digest; on a trial session the
//!   caller-provided digest is used (equation 20).
//!   `PolicyGetDigest` returns the digest verbatim, which is
//!   what makes a seal-time `authPolicy` independently
//!   computable by a fixture.
//! - **Sealed objects.** `Create` under a primary stores the
//!   public area, private blob, and sensitive data;
//!   `Load` re-derives the object's identity from the blob
//!   (a tampered public area fails the load, the integrity
//!   property the anchor's tamper fixture relies on);
//!   `Unseal` releases the data only when some supplied policy
//!   session's digest equals the stored `authPolicy` —
//!   otherwise `TPM_RC_POLICY_FAIL` (the §8.3 PCR binding).
//! - **PCR bank** with extend semantics (`H(old ‖ digest)`).
//! - **NV indices** with the counter discipline of Part 3
//!   §31.13: a `TPMA_NV_COUNTER` index changes only via
//!   `NV_Increment`; a defined-but-never-written index reads
//!   back `TPM_RC_NV_UNINITIALIZED`, even at size zero.
//! - **Startup gating:** every command before `TPM2_Startup`
//!   fails with `TPM_RC_INITIALIZE`.
//!
//! Deliberately *not* modelled (outside the sealing
//! conversation; wrong answers here cannot mask an anchor
//! defect): HMAC / parameter-encryption sessions, dictionary
//! attack lockout accounting, EK/AK hierarchies beyond template
//! echo, persistence (EvictControl), DA-protected auth retries.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_lib::sync::IrqSafeSpinLock;

use crate::devfs_bridge::TpmTransport;
use crate::tpm2::{
    TPM_ALG_NULL, TPM_ALG_SHA256, TPM_CC_CLEAR, TPM_CC_CREATE, TPM_CC_CREATE_PRIMARY,
    TPM_CC_FLUSH_CONTEXT, TPM_CC_GET_CAPABILITY, TPM_CC_GET_RANDOM, TPM_CC_LOAD,
    TPM_CC_NV_DEFINE_SPACE, TPM_CC_NV_INCREMENT, TPM_CC_NV_READ, TPM_CC_NV_UNDEFINE_SPACE,
    TPM_CC_NV_WRITE, TPM_CC_PCR_EXTEND, TPM_CC_PCR_READ, TPM_CC_POLICY_GET_DIGEST,
    TPM_CC_POLICY_PCR, TPM_CC_SHUTDOWN, TPM_CC_STARTUP, TPM_CC_START_AUTH_SESSION, TPM_CC_UNSEAL,
    TPM_RC_COMMAND_CODE, TPM_RC_FAILURE, TPM_RC_HANDLE, TPM_RC_INITIALIZE, TPM_RC_NV_DEFINED,
    TPM_RC_NV_UNINITIALIZED, TPM_RC_POLICY_FAIL, TPM_RC_SUCCESS, TPM_RC_VALUE, TPM_SE_TRIAL,
    TPM_ST_SESSIONS,
};

// ── SHA-256 (FIPS 180-4), one-shot ───────────────────────────────
//
// The fixture hashes policy digests and PCR composites itself
// rather than taking a crypto dependency: fixture code that
// shares an implementation with the code under test can agree
// with it on a wrong answer (the #1068 failure species). This
// copy follows the e2e keystone model's dependency-minimal
// precedent; fixtures that pin the anchor's policy digest
// compute it from the spec formula through *this* function or
// their own — never by asking the anchor.

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// One-shot SHA-256 (FIPS 180-4 §6.2).
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = Vec::with_capacity(data.len() + 72);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// ── Command cursor ───────────────────────────────────────────────

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ()> {
        let end = self.pos.checked_add(n).ok_or(())?;
        if end > self.buf.len() {
            return Err(());
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ()> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ()> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, ()> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn tpm2b(&mut self) -> Result<&'a [u8], ()> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    /// Skip an authorization area (u32 size + bytes).
    fn skip_auth_area(&mut self) -> Result<(), ()> {
        let n = self.u32()? as usize;
        self.take(n).map(|_| ())
    }
    /// Parse the first session of an authorization area this
    /// cursor is positioned at: `(sessionHandle, sessionAttributes)`.
    fn first_session(&mut self) -> Result<(u32, u8), ()> {
        let size = self.u32()? as usize;
        let area = self.take(size)?;
        let mut c = Cursor::new(area);
        let handle = c.u32()?;
        let _nonce = c.tpm2b()?;
        let attrs = c.u8()?;
        let _hmac = c.tpm2b()?;
        Ok((handle, attrs))
    }
}

// ── Response framing ─────────────────────────────────────────────

fn response(tag: u16, rc: u32, handles: &[u8], params: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tag.to_be_bytes());
    // Failure responses carry no parameter block at all; success
    // responses under TPM_ST_SESSIONS carry parameterSize +
    // params + one empty response session.
    let payload = if rc != TPM_RC_SUCCESS {
        handles.len()
    } else if tag == TPM_ST_SESSIONS {
        handles.len() + 4 + params.len() + 5
    } else {
        handles.len() + params.len()
    };
    v.extend_from_slice(&((10 + payload) as u32).to_be_bytes());
    v.extend_from_slice(&rc.to_be_bytes());
    v.extend_from_slice(handles);
    if rc == TPM_RC_SUCCESS {
        if tag == TPM_ST_SESSIONS {
            v.extend_from_slice(&(params.len() as u32).to_be_bytes());
            v.extend_from_slice(params);
            // One response session: empty nonce, attrs 0, empty HMAC.
            v.extend_from_slice(&0u16.to_be_bytes());
            v.push(0);
            v.extend_from_slice(&0u16.to_be_bytes());
        } else {
            v.extend_from_slice(params);
        }
    }
    v
}

fn ok(tag: u16, params: &[u8]) -> Vec<u8> {
    response(tag, TPM_RC_SUCCESS, &[], params)
}

fn ok_handle(tag: u16, handle: u32, params: &[u8]) -> Vec<u8> {
    response(tag, TPM_RC_SUCCESS, &handle.to_be_bytes(), params)
}

fn fail(tag: u16, rc: u32) -> Vec<u8> {
    response(tag, rc, &[], &[])
}

fn tpm2b(data: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + data.len());
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    v
}

// ── Fixture state ────────────────────────────────────────────────

#[derive(Clone)]
struct Session {
    kind: u8,
    policy_digest: [u8; 32],
}

#[derive(Clone)]
struct Created {
    /// The private blob as minted at Create (a fixture-internal
    /// encoding); Load keys on these exact bytes.
    blob: Vec<u8>,
    /// TPMT_PUBLIC inner bytes as created.
    public: Vec<u8>,
    /// authPolicy parsed out of the public area at Create.
    policy: Vec<u8>,
    /// The sealed sensitive data.
    data: Vec<u8>,
}

#[derive(Clone)]
struct NvEntry {
    attributes: u32,
    data: Vec<u8>,
    written: bool,
}

struct State {
    started: bool,
    pcrs: [[u8; 32]; 24],
    sessions: BTreeMap<u32, Session>,
    next_session: u32,
    /// Primaries keyed by their exact inPublic template bytes —
    /// a primary is a derivation, so the same template always
    /// yields the same handle, across and within boots.
    primaries: BTreeMap<Vec<u8>, u32>,
    next_object: u32,
    created: BTreeMap<Vec<u8>, Created>,
    loaded: BTreeMap<u32, Vec<u8>>,
    nv: BTreeMap<u32, NvEntry>,
    nonce_counter: u64,
    create_counter: u64,
}

impl State {
    fn new() -> Self {
        Self {
            started: false,
            pcrs: [[0u8; 32]; 24],
            sessions: BTreeMap::new(),
            next_session: 0x0200_0000,
            primaries: BTreeMap::new(),
            next_object: 0x8000_1000,
            created: BTreeMap::new(),
            loaded: BTreeMap::new(),
            nv: BTreeMap::new(),
            nonce_counter: 0,
            create_counter: 0,
        }
    }

    fn alloc_session(&mut self) -> u32 {
        let h = self.next_session;
        self.next_session += 1;
        h
    }

    fn alloc_object(&mut self) -> u32 {
        let h = self.next_object;
        self.next_object += 1;
        h
    }
}

/// A fixture TPM 2.0 for the sealing conversation — see the
/// module documentation for what is and is not modelled.
pub struct FixtureTpm {
    state: IrqSafeSpinLock<State>,
}

impl core::fmt::Debug for FixtureTpm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FixtureTpm")
    }
}

impl Default for FixtureTpm {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureTpm {
    pub fn new() -> Self {
        Self {
            state: IrqSafeSpinLock::new(State::new()),
        }
    }

    /// Current value of a SHA-256-bank PCR (test introspection;
    /// production code reads PCRs through TPM2_PCR_Read).
    pub fn pcr(&self, pcr: u32) -> [u8; 32] {
        self.state.lock().pcrs[pcr as usize]
    }

    /// Whether TPM2_Startup has been issued.
    pub fn is_started(&self) -> bool {
        self.state.lock().started
    }

    fn dispatch(&self, cmd: &[u8]) -> Vec<u8> {
        if cmd.len() < 10 {
            return fail(TPM_ST_SESSIONS, TPM_RC_FAILURE);
        }
        let tag = u16::from_be_bytes([cmd[0], cmd[1]]);
        let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
        let body = &cmd[10..];
        let mut st = self.state.lock();
        if cc != TPM_CC_STARTUP && !st.started {
            return fail(tag, TPM_RC_INITIALIZE);
        }
        match cc {
            TPM_CC_STARTUP => {
                st.started = true;
                // Startup does not reset locality-0 PCRs on the
                // fixture's power model (PCR reset belongs to
                // TPM Reset / Clear as modelled here); sessions
                // and volatile objects never survive it.
                st.sessions.clear();
                st.loaded.clear();
                ok(tag, &[])
            }
            TPM_CC_SHUTDOWN => {
                st.sessions.clear();
                st.loaded.clear();
                ok(tag, &[])
            }
            TPM_CC_CLEAR => {
                st.pcrs = [[0u8; 32]; 24];
                st.sessions.clear();
                st.loaded.clear();
                ok(tag, &[])
            }
            TPM_CC_GET_RANDOM => Self::get_random(&mut st, tag, body),
            TPM_CC_GET_CAPABILITY => Self::get_capability(tag, body),
            TPM_CC_START_AUTH_SESSION => Self::start_auth_session(&mut st, tag, body),
            TPM_CC_POLICY_PCR => Self::policy_pcr(&mut st, tag, body),
            TPM_CC_POLICY_GET_DIGEST => Self::policy_get_digest(&st, tag, body),
            TPM_CC_FLUSH_CONTEXT => Self::flush_context(&mut st, tag, body),
            TPM_CC_CREATE_PRIMARY => Self::create_primary(&mut st, tag, body),
            TPM_CC_CREATE => Self::create(&mut st, tag, body),
            TPM_CC_LOAD => Self::load(&mut st, tag, body),
            TPM_CC_UNSEAL => Self::unseal(&mut st, tag, body),
            TPM_CC_PCR_READ => Self::pcr_read(&st, tag, body),
            TPM_CC_PCR_EXTEND => Self::pcr_extend(&mut st, tag, body),
            TPM_CC_NV_DEFINE_SPACE => Self::nv_define(&mut st, tag, body),
            TPM_CC_NV_UNDEFINE_SPACE => Self::nv_undefine(&mut st, tag, body),
            TPM_CC_NV_READ => Self::nv_read(&st, tag, body),
            TPM_CC_NV_WRITE => Self::nv_write(&mut st, tag, body),
            TPM_CC_NV_INCREMENT => Self::nv_increment(&mut st, tag, body),
            _ => fail(tag, TPM_RC_COMMAND_CODE),
        }
    }

    fn get_random(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let n = match c.u16() {
            Ok(v) => v as usize,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            st.nonce_counter += 1;
            let block = sha256(&st.nonce_counter.to_be_bytes());
            let take = (n - out.len()).min(32);
            out.extend_from_slice(&block[..take]);
        }
        ok(tag, &tpm2b(&out))
    }

    fn get_capability(tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let (cap, property, _count) = match (c.u32(), c.u32(), c.u32()) {
            (Ok(a), Ok(b), Ok(d)) => (a, b, d),
            _ => return fail(tag, TPM_RC_FAILURE),
        };
        // TPM_CAP_TPM_PROPERTIES (6): one property — manufacturer
        // "NARF" — enough for identity probes; TPM_CAP_PCRS (5):
        // the SHA-256 bank, all 24 PCRs.
        let mut params = Vec::new();
        params.push(0u8); // moreData = NO
        params.extend_from_slice(&cap.to_be_bytes());
        match cap {
            6 => {
                params.extend_from_slice(&1u32.to_be_bytes());
                params.extend_from_slice(&property.max(0x100).to_be_bytes());
                params.extend_from_slice(&0x4E41_5246u32.to_be_bytes()); // "NARF"
            }
            5 => {
                params.extend_from_slice(&1u32.to_be_bytes());
                params.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
                params.push(3u8);
                params.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
            }
            _ => {
                params.extend_from_slice(&0u32.to_be_bytes());
            }
        }
        ok(tag, &params)
    }

    fn start_auth_session(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let _tpm_key = c.u32()?;
            let _bind = c.u32()?;
            let _nonce_caller = c.tpm2b()?;
            let _salt = c.tpm2b()?;
            let kind = c.u8()?;
            let symmetric = c.u16()?;
            if symmetric != TPM_ALG_NULL {
                return Err(());
            }
            let _auth_hash = c.u16()?;
            Ok(kind)
        })();
        let kind = match parsed {
            Ok(k) => k,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        let handle = st.alloc_session();
        st.sessions.insert(
            handle,
            Session {
                kind,
                policy_digest: [0u8; 32],
            },
        );
        st.nonce_counter += 1;
        let mut seed = Vec::with_capacity(16);
        seed.extend_from_slice(&handle.to_be_bytes());
        seed.extend_from_slice(&st.nonce_counter.to_be_bytes());
        let nonce = sha256(&seed);
        let mut params = Vec::new();
        params.extend_from_slice(&tpm2b(&nonce));
        ok_handle(tag, handle, &params)
    }

    fn policy_pcr(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let session = c.u32()?;
            c.skip_auth_area()?;
            let digest = c.tpm2b()?.to_vec();
            let raw_from = c.pos;
            let count = c.u32()?;
            let mut entries: Vec<(u16, Vec<u8>)> = Vec::new();
            for _ in 0..count {
                let alg = c.u16()?;
                let size = c.u8()? as usize;
                let mask = c.take(size)?.to_vec();
                entries.push((alg, mask));
            }
            let raw = body[raw_from..c.pos].to_vec();
            Ok((session, digest, entries, raw))
        })();
        let (handle, digest_arg, entries, selection_raw) = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        let session = match st.sessions.get(&handle) {
            Some(s) => s.clone(),
            None => return fail(tag, TPM_RC_HANDLE),
        };
        // Part 1 "PolicyPCR": for a non-trial session the TPM
        // computes digestTPM itself and, when the caller supplied
        // a non-empty pcrDigest, requires equality (mismatch:
        // TPM_RC_VALUE, session digest unchanged, session
        // invalidated). For a trial session the supplied digest
        // is used as-is (equation 20).
        let effective = if session.kind == TPM_SE_TRIAL {
            digest_arg.clone()
        } else {
            let mut concat = Vec::new();
            for (alg, mask) in &entries {
                if *alg != TPM_ALG_SHA256 {
                    continue;
                }
                for (pcr, byte) in mask.iter().enumerate() {
                    for bit in 0..8 {
                        if byte & (1 << bit) != 0 {
                            let idx = pcr * 8 + bit;
                            if idx < 24 {
                                concat.extend_from_slice(&st.pcrs[idx]);
                            }
                        }
                    }
                }
            }
            let computed = sha256(&concat).to_vec();
            if !digest_arg.is_empty() && digest_arg != computed {
                st.sessions.remove(&handle);
                return fail(tag, TPM_RC_VALUE);
            }
            computed
        };
        // Equation 19/20: policyDigestnew =
        // H(policyDigestold ‖ TPM_CC_PolicyPCR ‖ args), args =
        // marshaled TPML_PCR_SELECTION ‖ digest.
        let mut input = Vec::new();
        input.extend_from_slice(&session.policy_digest);
        input.extend_from_slice(&TPM_CC_POLICY_PCR.to_be_bytes());
        input.extend_from_slice(&selection_raw);
        input.extend_from_slice(&effective);
        let new_digest = sha256(&input);
        if let Some(s) = st.sessions.get_mut(&handle) {
            s.policy_digest = new_digest;
        }
        ok(tag, &[])
    }

    fn policy_get_digest(st: &State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let handle = match c.u32() {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        match st.sessions.get(&handle) {
            Some(s) => ok(tag, &tpm2b(&s.policy_digest)),
            None => fail(tag, TPM_RC_HANDLE),
        }
    }

    fn flush_context(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let handle = match c.u32() {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        st.sessions.remove(&handle);
        st.loaded.remove(&handle);
        // Primaries are derivations: flushing one forgets its
        // handle assignment; the template re-derives on demand.
        st.primaries.retain(|_, h| *h != handle);
        ok(tag, &[])
    }

    fn create_primary(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let hierarchy = c.u32()?;
            c.skip_auth_area()?;
            let _in_sensitive = c.tpm2b()?;
            let in_public = c.tpm2b()?.to_vec();
            Ok((hierarchy, in_public))
        })();
        let (hierarchy, in_public) = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        let handle = match st.primaries.get(&in_public) {
            Some(h) => *h,
            None => {
                let h = st.alloc_object();
                st.primaries.insert(in_public.clone(), h);
                h
            }
        };
        // Part 3 §12.2 response layout — outPublic, creationData,
        // creationHash, ticket; NO outPrivate.
        let mut params = Vec::new();
        params.extend_from_slice(&tpm2b(&in_public));
        params.extend_from_slice(&tpm2b(&[])); // creationData
        params.extend_from_slice(&tpm2b(&sha256(&in_public))); // creationHash
        params.extend_from_slice(&0x8021u16.to_be_bytes()); // TPM_ST_CREATION
        params.extend_from_slice(&hierarchy.to_be_bytes());
        params.extend_from_slice(&tpm2b(&[])); // ticket digest
        ok_handle(tag, handle, &params)
    }

    fn create(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let parent = c.u32()?;
            c.skip_auth_area()?;
            let in_sensitive = c.tpm2b()?.to_vec();
            let in_public = c.tpm2b()?.to_vec();
            Ok((parent, in_sensitive, in_public))
        })();
        let (parent, in_sensitive, in_public) = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        if !st.primaries.values().any(|h| *h == parent) {
            return fail(tag, TPM_RC_HANDLE);
        }
        // inSensitive inner: userAuth TPM2B ‖ data TPM2B.
        let mut sc = Cursor::new(&in_sensitive);
        let data = match (|| {
            let _auth = sc.tpm2b()?;
            sc.tpm2b().map(|d| d.to_vec())
        })() {
            Ok(d) => d,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        // TPMT_PUBLIC: type(2) ‖ nameAlg(2) ‖ attributes(4) ‖
        // authPolicy TPM2B ‖ …
        let policy = {
            let mut pc = Cursor::new(&in_public);
            match (|| {
                let _ty = pc.u16()?;
                let _name_alg = pc.u16()?;
                let _attrs = pc.u32()?;
                pc.tpm2b().map(|p| p.to_vec())
            })() {
                Ok(p) => p,
                Err(()) => return fail(tag, TPM_RC_FAILURE),
            }
        };
        st.create_counter += 1;
        let mut blob_seed = Vec::new();
        blob_seed.extend_from_slice(&in_public);
        blob_seed.extend_from_slice(&data);
        blob_seed.extend_from_slice(&st.create_counter.to_be_bytes());
        let blob = sha256(&blob_seed).to_vec();
        st.created.insert(
            blob.clone(),
            Created {
                blob: blob.clone(),
                public: in_public.clone(),
                policy,
                data,
            },
        );
        let mut params = Vec::new();
        params.extend_from_slice(&tpm2b(&blob)); // outPrivate
        params.extend_from_slice(&tpm2b(&in_public)); // outPublic
        params.extend_from_slice(&tpm2b(&[])); // creationData
        params.extend_from_slice(&tpm2b(&sha256(&in_public))); // creationHash
        params.extend_from_slice(&0x8021u16.to_be_bytes());
        params.extend_from_slice(&crate::tpm2::TPM_RH_OWNER.to_be_bytes());
        params.extend_from_slice(&tpm2b(&[]));
        ok(tag, &params)
    }

    fn load(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let parent = c.u32()?;
            c.skip_auth_area()?;
            let in_private = c.tpm2b()?.to_vec();
            let in_public = c.tpm2b()?.to_vec();
            Ok((parent, in_private, in_public))
        })();
        let (parent, in_private, in_public) = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        if !st.primaries.values().any(|h| *h == parent) {
            return fail(tag, TPM_RC_HANDLE);
        }
        // The private blob is integrity-bound to the public area
        // it was created with: a mismatch is a load failure,
        // never a load of attacker-chosen parts.
        let created = match st.created.get(&in_private) {
            Some(cr) if cr.public == in_public => cr.clone(),
            _ => return fail(tag, TPM_RC_FAILURE),
        };
        let handle = st.alloc_object();
        st.loaded.insert(handle, created.blob.clone());
        // Name: nameAlg ‖ H(public) (Part 1, keyedhash form).
        let mut name = Vec::new();
        name.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        name.extend_from_slice(&sha256(&created.public));
        ok_handle(tag, handle, &tpm2b(&name))
    }

    fn unseal(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let item = c.u32()?;
            let (session, attrs) = c.first_session()?;
            Ok((item, session, attrs))
        })();
        let (item, session_handle, attrs) = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        let blob = match st.loaded.get(&item) {
            Some(b) => b.clone(),
            None => return fail(tag, TPM_RC_HANDLE),
        };
        let created = match st.created.get(&blob) {
            Some(cr) => cr.clone(),
            None => return fail(tag, TPM_RC_FAILURE),
        };
        // Authorization: the password session (TPM_RS_PW) reaches
        // only objects with an empty authPolicy; an object with a
        // policy requires a policy session whose digest equals
        // it. Anything else is TPM_RC_POLICY_FAIL.
        let authorized = if created.policy.is_empty() {
            session_handle == crate::tpm2::TPM_RS_PW
        } else {
            match st.sessions.get(&session_handle) {
                Some(s) => s.policy_digest[..] == created.policy[..],
                None => false,
            }
        };
        // continueSession clear ⇒ the session dies with the
        // command, success or failure (Part 1 session rules).
        if attrs & 0x01 == 0 {
            st.sessions.remove(&session_handle);
        }
        if !authorized {
            return fail(tag, TPM_RC_POLICY_FAIL);
        }
        ok(tag, &tpm2b(&created.data))
    }

    fn pcr_read(st: &State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let count = c.u32()?;
            let mut entries = Vec::new();
            for _ in 0..count {
                let alg = c.u16()?;
                let size = c.u8()? as usize;
                let mask = c.take(size)?.to_vec();
                entries.push((alg, mask));
            }
            Ok(entries)
        })();
        let entries: Vec<(u16, Vec<u8>)> = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        let mut params = Vec::new();
        params.extend_from_slice(&0u32.to_be_bytes()); // pcrUpdateCounter
        params.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        let mut digests: Vec<&[u8; 32]> = Vec::new();
        for (alg, mask) in &entries {
            params.extend_from_slice(&alg.to_be_bytes());
            params.push(mask.len() as u8);
            params.extend_from_slice(mask);
            if *alg == TPM_ALG_SHA256 {
                for (byte_idx, byte) in mask.iter().enumerate() {
                    for bit in 0..8 {
                        if byte & (1 << bit) != 0 {
                            let idx = byte_idx * 8 + bit;
                            if idx < 24 {
                                digests.push(&st.pcrs[idx]);
                            }
                        }
                    }
                }
            }
        }
        params.extend_from_slice(&(digests.len() as u32).to_be_bytes());
        for d in digests {
            params.extend_from_slice(&tpm2b(d));
        }
        ok(tag, &params)
    }

    fn pcr_extend(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let pcr = c.u32()?;
            c.skip_auth_area()?;
            let count = c.u32()?;
            let mut digests = Vec::new();
            for _ in 0..count {
                let alg = c.u16()?;
                let d = c.take(32)?.to_vec();
                digests.push((alg, d));
            }
            Ok((pcr, digests))
        })();
        let (pcr, digests) = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        if pcr >= 24 {
            return fail(tag, TPM_RC_HANDLE);
        }
        for (alg, digest) in digests {
            if alg == TPM_ALG_SHA256 {
                let mut input = Vec::with_capacity(64);
                input.extend_from_slice(&st.pcrs[pcr as usize]);
                input.extend_from_slice(&digest);
                st.pcrs[pcr as usize] = sha256(&input);
            }
        }
        ok(tag, &[])
    }

    fn nv_define(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let _auth_handle = c.u32()?;
            c.skip_auth_area()?;
            let _auth = c.tpm2b()?;
            let public = c.tpm2b()?.to_vec();
            Ok(public)
        })();
        let public = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        // TPMS_NV_PUBLIC: nvIndex(4) ‖ nameAlg(2) ‖ attributes(4)
        // ‖ authPolicy TPM2B ‖ dataSize(2).
        let mut pc = Cursor::new(&public);
        let parsed = (|| {
            let index = pc.u32()?;
            let _name_alg = pc.u16()?;
            let attrs = pc.u32()?;
            let _policy = pc.tpm2b()?;
            let size = pc.u16()?;
            Ok((index, attrs, size))
        })();
        let (index, attrs, size) = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        if st.nv.contains_key(&index) {
            return fail(tag, TPM_RC_NV_DEFINED);
        }
        st.nv.insert(
            index,
            NvEntry {
                attributes: attrs,
                data: alloc::vec![0u8; size as usize],
                written: false,
            },
        );
        ok(tag, &[])
    }

    fn nv_undefine(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let _auth_handle = c.u32()?;
            let index = c.u32()?;
            c.skip_auth_area()?;
            Ok(index)
        })();
        match parsed {
            Ok(index) => {
                st.nv.remove(&index);
                ok(tag, &[])
            }
            Err(()) => fail(tag, TPM_RC_FAILURE),
        }
    }

    fn nv_read(st: &State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let _auth_handle = c.u32()?;
            let index = c.u32()?;
            c.skip_auth_area()?;
            let size = c.u16()?;
            let offset = c.u16()?;
            Ok((index, size, offset))
        })();
        let (index, size, offset) = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        let entry = match st.nv.get(&index) {
            Some(e) => e,
            None => return fail(tag, TPM_RC_HANDLE),
        };
        // Part 3 §31.13: TPMA_NV_WRITTEN CLEAR ⇒ any data access
        // is TPM_RC_NV_UNINITIALIZED, even at size 0.
        if !entry.written {
            return fail(tag, TPM_RC_NV_UNINITIALIZED);
        }
        let start = offset as usize;
        let end = start + size as usize;
        if end > entry.data.len() {
            return fail(tag, TPM_RC_VALUE);
        }
        ok(tag, &tpm2b(&entry.data[start..end]))
    }

    fn nv_write(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        const TPMA_NV_NT_MASK: u32 = 0x0000_00F0;
        const TPMA_NV_NT_COUNTER: u32 = 0x0000_0010;
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let _auth_handle = c.u32()?;
            let index = c.u32()?;
            c.skip_auth_area()?;
            let data = c.tpm2b()?.to_vec();
            let offset = c.u16()?;
            Ok((index, data, offset))
        })();
        let (index, data, offset) = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        let entry = match st.nv.get_mut(&index) {
            Some(e) => e,
            None => return fail(tag, TPM_RC_HANDLE),
        };
        // A counter index changes only via NV_Increment.
        if entry.attributes & TPMA_NV_NT_MASK == TPMA_NV_NT_COUNTER {
            return fail(tag, TPM_RC_VALUE);
        }
        let start = offset as usize;
        let end = start + data.len();
        if end > entry.data.len() {
            return fail(tag, TPM_RC_VALUE);
        }
        entry.data[start..end].copy_from_slice(&data);
        entry.written = true;
        ok(tag, &[])
    }

    fn nv_increment(st: &mut State, tag: u16, body: &[u8]) -> Vec<u8> {
        let mut c = Cursor::new(body);
        let parsed = (|| {
            let _auth_handle = c.u32()?;
            let index = c.u32()?;
            c.skip_auth_area()?;
            Ok(index)
        })();
        let index = match parsed {
            Ok(v) => v,
            Err(()) => return fail(tag, TPM_RC_FAILURE),
        };
        let entry = match st.nv.get_mut(&index) {
            Some(e) => e,
            None => return fail(tag, TPM_RC_HANDLE),
        };
        if entry.data.len() < 8 {
            return fail(tag, TPM_RC_VALUE);
        }
        let mut cur = [0u8; 8];
        cur.copy_from_slice(&entry.data[..8]);
        let next = u64::from_be_bytes(cur).wrapping_add(1);
        entry.data[..8].copy_from_slice(&next.to_be_bytes());
        entry.written = true;
        ok(tag, &[])
    }
}

impl TpmTransport for FixtureTpm {
    fn submit(&self, cmd: &[u8]) -> Result<Vec<u8>, ()> {
        Ok(self.dispatch(cmd))
    }
}

/// Convenience for fixtures: a started fixture behind the
/// transport trait object the anchor consumes.
pub fn started_fixture() -> Arc<FixtureTpm> {
    let tpm = Arc::new(FixtureTpm::new());
    let resp = tpm
        .submit(&crate::tpm2::commands::startup_clear())
        .unwrap_or_default();
    debug_assert_eq!(
        crate::tpm2::commands::response_rc(&resp),
        Some(TPM_RC_SUCCESS)
    );
    tpm
}
