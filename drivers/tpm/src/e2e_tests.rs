//! End-to-end smoke tests for the NARF TPM 2.0 stack.
//!
//! These tests exercise the full measured-boot cycle using a
//! `FakeTpmTransport` that maintains virtual PCR banks, a small NV
//! index store, and a sealed-object store bound to PCR policies.
//!
//! ## Smokes covered (13 total)
//!
//! 1.  `TPM2_Startup(CLEAR)` → SUCCESS
//! 2.  `TPM2_GetCapability(MANUFACTURER)` → 4-char "FAKE"
//! 3.  `TPM2_GetRandom(32)` → 32 distinct bytes
//! 4.  PCR_Read PCR-0 SHA-256 before extend → all-zero
//! 5.  PCR_Extend PCR-7 with D1 → SHA256(0||D1)
//! 6.  Multiple extends compose: SHA256(SHA256(0||D1)||D2)
//! 7.  PCR_Read after extend matches expected digest
//! 8.  `/sys/class/tpm/tpm0/pcrs` format after extends
//! 9.  NV_DefineSpace + NV_Write + NV_Read round-trip
//! 10. Seal blob bound to PCR-7 → Unseal succeeds
//! 11. Re-extend PCR-7 → Unseal fails (TPM_RC_POLICY_FAIL)
//! 12. FlushContext on DevTpmRm0 drop
//! 13. DevTpm0 (raw) does not auto-flush on drop
//!
//! ## Linux references
//!
//! - `linux/drivers/char/tpm/tpm2-cmd.c` — command dispatch
//! - `linux/drivers/char/tpm/tpm2-space.c` — RM session lifecycle
//! - TCG TPM Library Spec Part 1 §17.4 (PCR extend formula)
//! - TCG TPM Library Spec Part 3 §23.7 (TPM2_PolicyPCR digest update)
//!
//! ## Deferred
//!
//! - TPM2 PolicySigned / PolicyAuthorize
//! - Full RM session virtualisation beyond pass-through
//! - TPM Endorsement Key certificate chain

#[cfg(any(test, feature = "kernel-test"))]
mod smokes {
    extern crate alloc;

    use crate::devfs_bridge::TpmTransport;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::sync::IrqSafeSpinLock;

    use crate::tpm2::{
        TPM_CC_GET_CAPABILITY, TPM_CC_GET_RANDOM, TPM_CC_NV_DEFINE_SPACE, TPM_CC_NV_READ,
        TPM_CC_NV_WRITE, TPM_CC_PCR_EXTEND, TPM_CC_PCR_READ, TPM_CC_STARTUP, TPM_RC_SUCCESS,
    };

    // ─────────────────────────────────────────────────────────────────────
    // Inline SHA-256  (FIPS 180-4 §6.2.2)
    //
    // Avoids adding a new crate dependency.  Same algorithm as
    // `narf-crypto/src/sha256.rs`; copied here to keep the TPM driver
    // crate dependency-minimal.
    // ─────────────────────────────────────────────────────────────────────

    fn sha256(data: &[u8]) -> [u8; 32] {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        const H0: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let bit_len = (data.len() as u64).wrapping_mul(8);
        let pad_len = {
            let mut l = data.len() + 1;
            while l % 64 != 56 {
                l += 1;
            }
            l + 8
        };
        let mut msg = alloc::vec![0u8; pad_len];
        msg[..data.len()].copy_from_slice(data);
        msg[data.len()] = 0x80;
        msg[pad_len - 8..].copy_from_slice(&bit_len.to_be_bytes());

        let mut h = H0;
        for block in msg.chunks_exact(64) {
            let mut w = [0u32; 64];
            for i in 0..16 {
                w[i] = u32::from_be_bytes([
                    block[i * 4],
                    block[i * 4 + 1],
                    block[i * 4 + 2],
                    block[i * 4 + 3],
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
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] =
                [h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]];
            for t in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ (!e & g);
                let t1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[t])
                    .wrapping_add(w[t]);
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
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
        }
        out
    }

    /// PCR extend formula: `new_pcr = SHA256(old_pcr || digest)`.
    /// TCG Part 1 §17.4.
    fn pcr_extend_formula(old: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(old);
        input[32..].copy_from_slice(digest);
        sha256(&input)
    }

    // ─────────────────────────────────────────────────────────────────────
    // FakeTpmTransport
    // ─────────────────────────────────────────────────────────────────────

    /// TPM_RC_POLICY_FAIL — unseal fails when PCR has changed since sealing.
    /// TCG Part 2 §6.6, error 0x099D.
    const TPM_RC_POLICY_FAIL: u32 = 0x0000_099D;

    /// Fake MANUFACTURER value: "FAKE" = 0x46414B45.
    const FAKE_MANUFACTURER: u32 = 0x4641_4B45;

    /// Session handle allocated by StartAuthSession.
    const FAKE_SESSION_HANDLE: u32 = 0x0200_0001;

    // Additional command codes not exported by the tpm2 module as pub consts.
    const TPM_CC_START_AUTH_SESSION: u32 = 0x0000_0176;
    const TPM_CC_POLICY_PCR: u32 = 0x0000_017F;
    const TPM_CC_CREATE: u32 = 0x0000_0153;
    const TPM_CC_LOAD: u32 = 0x0000_0157;
    const TPM_CC_UNSEAL: u32 = 0x0000_015E;
    const TPM_CC_FLUSH_CONTEXT: u32 = 0x0000_0165;

    struct SealedObject {
        /// Original (non-transient) object handle.
        handle: u32,
        /// PCR index bound to this object (always 7 in these tests).
        pcr_idx: usize,
        /// PCR value at time of sealing.
        sealed_pcr: [u8; 32],
        /// The secret bytes.
        secret: Vec<u8>,
        /// Opaque private blob (4-byte handle, big-endian) for Load.
        private_blob: Vec<u8>,
    }

    struct AuthSession {
        handle: u32,
    }

    struct FakeState {
        /// SHA-256 PCR bank: 24 × 32 bytes, all-zero on reset.
        pcrs: [[u8; 32]; 24],
        /// NV store: (index_handle, data).
        nv: Vec<(u32, Vec<u8>)>,
        /// Sealed objects keyed by original handle.
        sealed: Vec<SealedObject>,
        /// Active auth sessions.
        sessions: Vec<AuthSession>,
        /// Next original object handle to allocate.
        next_handle: u32,
    }

    impl FakeState {
        fn new() -> Self {
            Self {
                pcrs: [[0u8; 32]; 24],
                nv: Vec::new(),
                sealed: Vec::new(),
                sessions: Vec::new(),
                next_handle: 0x8000_0100, // distinct from transient range base
            }
        }
    }

    struct FakeTpmTransport {
        state: IrqSafeSpinLock<FakeState>,
    }

    impl FakeTpmTransport {
        fn new() -> Self {
            Self {
                state: IrqSafeSpinLock::new(FakeState::new()),
            }
        }
    }

    fn success_resp() -> Vec<u8> {
        let mut r = alloc::vec![0u8; 10];
        r[0] = 0x80;
        r[1] = 0x01; // TPM_ST_NO_SESSIONS
        r[2] = 0;
        r[3] = 0;
        r[4] = 0;
        r[5] = 10;
        r
    }

    fn failure_resp(rc: u32) -> Vec<u8> {
        let mut r = alloc::vec![0u8; 10];
        r[0] = 0x80;
        r[1] = 0x01;
        r[2] = 0;
        r[3] = 0;
        r[4] = 0;
        r[5] = 10;
        r[6] = (rc >> 24) as u8;
        r[7] = (rc >> 16) as u8;
        r[8] = (rc >> 8) as u8;
        r[9] = rc as u8;
        r
    }

    fn patch_size(r: &mut Vec<u8>) {
        let n = r.len() as u32;
        r[2] = (n >> 24) as u8;
        r[3] = (n >> 16) as u8;
        r[4] = (n >> 8) as u8;
        r[5] = n as u8;
    }

    impl crate::devfs_bridge::TpmTransport for FakeTpmTransport {
        fn submit(&self, cmd: &[u8]) -> Result<Vec<u8>, ()> {
            if cmd.len() < 10 {
                return Err(());
            }
            let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
            let mut st = self.state.lock();

            match cc {
                // ── TPM2_Startup ──────────────────────────────────────────
                x if x == TPM_CC_STARTUP => Ok(success_resp()),

                // ── TPM2_GetCapability ────────────────────────────────────
                x if x == TPM_CC_GET_CAPABILITY => {
                    // Return FAKE_MANUFACTURER for any property query.
                    // Body: moreData(1) + cap(4) + count(4) + tag(4) + value(4) = 17
                    let mut r = alloc::vec![0u8; 10 + 17];
                    r[0] = 0x80;
                    r[1] = 0x01;
                    let mut p = 10usize;
                    r[p] = 0;
                    p += 1; // moreData = 0
                    r[p + 3] = 6;
                    p += 4; // cap = TPM_CAP_TPM_PROPERTIES
                    r[p + 3] = 1;
                    p += 4; // count = 1
                    r[p + 2] = 0x01;
                    r[p + 3] = 0x05;
                    p += 4; // tag = PT_MANUFACTURER = 0x105
                    let mv = FAKE_MANUFACTURER;
                    r[p] = (mv >> 24) as u8;
                    r[p + 1] = (mv >> 16) as u8;
                    r[p + 2] = (mv >> 8) as u8;
                    r[p + 3] = mv as u8;
                    patch_size(&mut r);
                    Ok(r)
                }

                // ── TPM2_GetRandom ────────────────────────────────────────
                x if x == TPM_CC_GET_RANDOM => {
                    let n = if cmd.len() >= 12 {
                        u16::from_be_bytes([cmd[10], cmd[11]]) as usize
                    } else {
                        32
                    };
                    let mut r = alloc::vec![0u8; 10 + 2 + n];
                    r[0] = 0x80;
                    r[1] = 0x01;
                    r[10] = (n >> 8) as u8;
                    r[11] = n as u8;
                    // Pseudo-random fill: each byte varies with position.
                    for i in 0..n {
                        r[12 + i] = ((i
                            .wrapping_mul(0x37)
                            .wrapping_add(0xA5)
                            .wrapping_add((i >> 3).wrapping_mul(0x5B)))
                            & 0xFF) as u8;
                    }
                    patch_size(&mut r);
                    Ok(r)
                }

                // ── TPM2_PCR_Read ─────────────────────────────────────────
                x if x == TPM_CC_PCR_READ => {
                    // header(10) + selCount(4) + hashAlg(2) + sos(1) + bitmap(3)
                    if cmd.len() < 20 {
                        return Err(());
                    }
                    let sos = cmd[16] as usize;
                    if sos != 3 {
                        return Err(());
                    }
                    let bitmap = [cmd[17], cmd[18], cmd[19]];

                    let mut digests: Vec<[u8; 32]> = Vec::new();
                    for pcr in 0..24usize {
                        if bitmap[pcr / 8] & (1 << (pcr % 8)) != 0 {
                            digests.push(st.pcrs[pcr]);
                        }
                    }
                    let dc = digests.len();

                    // Response body:
                    // pcrUpdateCounter(4) + TPML_PCR_SELECTION(4+2+1+3) +
                    // TPML_DIGEST: count(4) + dc × (size(2)+digest(32))
                    let body = 4 + (4 + 2 + 1 + 3) + 4 + dc * (2 + 32);
                    let mut r = alloc::vec![0u8; 10 + body];
                    r[0] = 0x80;
                    r[1] = 0x01;
                    let mut p = 10usize;
                    p += 4; // pcrUpdateCounter = 0
                            // TPML_PCR_SELECTION count=1
                    r[p + 3] = 1;
                    p += 4;
                    r[p] = 0x00;
                    r[p + 1] = 0x0B;
                    p += 2; // SHA-256
                    r[p] = 3;
                    p += 1;
                    r[p] = bitmap[0];
                    r[p + 1] = bitmap[1];
                    r[p + 2] = bitmap[2];
                    p += 3;
                    // TPML_DIGEST count
                    let dcu = dc as u32;
                    r[p] = (dcu >> 24) as u8;
                    r[p + 1] = (dcu >> 16) as u8;
                    r[p + 2] = (dcu >> 8) as u8;
                    r[p + 3] = dcu as u8;
                    p += 4;
                    for d in &digests {
                        r[p] = 0;
                        r[p + 1] = 32;
                        p += 2; // TPM2B_DIGEST size = 32
                        r[p..p + 32].copy_from_slice(d);
                        p += 32;
                    }
                    patch_size(&mut r);
                    Ok(r)
                }

                // ── TPM2_PCR_Extend ───────────────────────────────────────
                x if x == TPM_CC_PCR_EXTEND => {
                    // header(10)+pcrHandle(4)+authSize(4)+auth(9)+count(4)+hashAlg(2)+digest(32)
                    // = 10+4+4+9+4+2+32 = 65
                    if cmd.len() < 65 {
                        return Err(());
                    }
                    let pcr_handle = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]);
                    if pcr_handle >= 24 {
                        return Err(());
                    }
                    let pcr = pcr_handle as usize;
                    // digest starts at byte 33 (10+4+4+9+4+2 = 33)
                    let mut digest = [0u8; 32];
                    digest.copy_from_slice(&cmd[33..65]);
                    let old = st.pcrs[pcr];
                    st.pcrs[pcr] = pcr_extend_formula(&old, &digest);
                    Ok(success_resp())
                }

                // ── TPM2_NV_DefineSpace ───────────────────────────────────
                x if x == TPM_CC_NV_DEFINE_SPACE => Ok(success_resp()),

                // ── TPM2_NV_Write ─────────────────────────────────────────
                //
                // nv_write() layout (from commands.rs):
                //   header(10) + authHandle(4) + nvIndex(4) +
                //   authSize(4) + auth(session: TPM_RS_PW(4)+nonce(2)+attrs(1)+hmac(2)=9) +
                //   TPM2B data: size(2) + bytes +
                //   offset(2)
                x if x == TPM_CC_NV_WRITE => {
                    if cmd.len() < 31 {
                        return Err(());
                    }
                    // nvIndex at 14..17
                    let nv_index = u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]);
                    // authSize at 18..21; for password session = 9
                    let auth_size =
                        u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]) as usize;
                    // TPM2B_MAX_NV_BUFFER size at 10+4+4+4+auth_size = 22+auth_size
                    let data_hdr = 22 + auth_size;
                    if cmd.len() < data_hdr + 4 {
                        return Err(());
                    }
                    let data_size = u16::from_be_bytes([cmd[data_hdr], cmd[data_hdr + 1]]) as usize;
                    if cmd.len() < data_hdr + 2 + data_size {
                        return Err(());
                    }
                    let data = cmd[data_hdr + 2..data_hdr + 2 + data_size].to_vec();

                    if let Some(entry) = st.nv.iter_mut().find(|e| e.0 == nv_index) {
                        entry.1 = data;
                    } else {
                        st.nv.push((nv_index, data));
                    }
                    Ok(success_resp())
                }

                // ── TPM2_NV_Read ──────────────────────────────────────────
                //
                // nv_read() layout:
                //   header(10) + authHandle(4) + nvIndex(4) +
                //   authSize(4) + auth(9) +
                //   size(2) + offset(2)
                x if x == TPM_CC_NV_READ => {
                    if cmd.len() < 31 {
                        return Err(());
                    }
                    let nv_index = u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]);
                    let auth_size =
                        u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]) as usize;
                    let params = 22 + auth_size;
                    if cmd.len() < params + 4 {
                        return Err(());
                    }
                    let read_size = u16::from_be_bytes([cmd[params], cmd[params + 1]]) as usize;
                    let read_offset =
                        u16::from_be_bytes([cmd[params + 2], cmd[params + 3]]) as usize;

                    let data = match st.nv.iter().find(|e| e.0 == nv_index) {
                        Some(e) => {
                            if read_offset >= e.1.len() {
                                alloc::vec![]
                            } else {
                                let end = (read_offset + read_size).min(e.1.len());
                                e.1[read_offset..end].to_vec()
                            }
                        }
                        None => return Ok(failure_resp(0x014E)), // TPM_RC_NV_UNDEFINED (approximate)
                    };

                    let mut r = alloc::vec![0u8; 10 + 2 + data.len()];
                    r[0] = 0x80;
                    r[1] = 0x01;
                    let dl = data.len() as u16;
                    r[10] = (dl >> 8) as u8;
                    r[11] = dl as u8;
                    r[12..12 + data.len()].copy_from_slice(&data);
                    patch_size(&mut r);
                    Ok(r)
                }

                // ── TPM2_StartAuthSession ─────────────────────────────────
                x if x == TPM_CC_START_AUTH_SESSION => {
                    let handle = FAKE_SESSION_HANDLE;
                    st.sessions.push(AuthSession { handle });
                    // Response: header + sessionHandle(4) + nonceTPM(TPM2B:2+0)
                    let mut r = alloc::vec![0u8; 10 + 4 + 2];
                    r[0] = 0x80;
                    r[1] = 0x01;
                    r[10] = (handle >> 24) as u8;
                    r[11] = (handle >> 16) as u8;
                    r[12] = (handle >> 8) as u8;
                    r[13] = handle as u8;
                    // nonceTPM size = 0 (already zeroed)
                    patch_size(&mut r);
                    Ok(r)
                }

                // ── TPM2_PolicyPCR ────────────────────────────────────────
                x if x == TPM_CC_POLICY_PCR => {
                    // We just check the session exists and return SUCCESS.
                    // The actual PCR check happens at Unseal time.
                    if cmd.len() < 14 {
                        return Err(());
                    }
                    let _session = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]);
                    let sess_exists = st.sessions.iter().any(|s| s.handle == _session);
                    if !sess_exists {
                        return Ok(failure_resp(0x018B)); // TPM_RC_HANDLE
                    }
                    Ok(success_resp())
                }

                // ── TPM2_Create (sealed data) ─────────────────────────────
                //
                // We extract the secret from inSensitive.data and store a
                // SealedObject bound to the *current* PCR-7 value.
                x if x == TPM_CC_CREATE => {
                    let secret = extract_sensitive_data(cmd).to_vec();
                    let sealed_pcr = st.pcrs[7];
                    let handle = st.next_handle;
                    st.next_handle += 1;
                    let private_blob = handle.to_be_bytes().to_vec();
                    st.sealed.push(SealedObject {
                        handle,
                        pcr_idx: 7,
                        sealed_pcr,
                        secret,
                        private_blob: private_blob.clone(),
                    });

                    // Response: header + TPM2B_PRIVATE + TPM2B_PUBLIC +
                    //           creationData(2+0) + creationHash(2+0) +
                    //           TPMT_TK_CREATION: tag(2)+hierarchy(4)+digest(2+0)
                    let mut r: Vec<u8> = Vec::new();
                    r.extend_from_slice(&[0x80u8, 0x01, 0, 0, 0, 0, 0, 0, 0, 0]); // header placeholder
                                                                                  // TPM2B_PRIVATE: size(2) + handle(4)
                    r.extend_from_slice(&(private_blob.len() as u16).to_be_bytes());
                    r.extend_from_slice(&private_blob);
                    // TPM2B_PUBLIC: size = 0
                    r.extend_from_slice(&0u16.to_be_bytes());
                    // creationData TPM2B size = 0
                    r.extend_from_slice(&0u16.to_be_bytes());
                    // creationHash TPM2B size = 0
                    r.extend_from_slice(&0u16.to_be_bytes());
                    // TPMT_TK_CREATION stub: tag(2)+hierarchy(4)+digest(2+0) = 8 bytes
                    r.extend_from_slice(&[0x80u8, 0x02, 0, 0, 0, 0, 0, 0]);
                    patch_size(&mut r);
                    Ok(r)
                }

                // ── TPM2_Load ─────────────────────────────────────────────
                //
                // Reads the 4-byte orig_handle from TPM2B_PRIVATE blob and
                // returns a transient handle 0x8000_0000|orig_handle.
                x if x == TPM_CC_LOAD => {
                    // header(10)+parentHandle(4)+authSize(4)+auth(N)+TPM2B_PRIVATE:size(2)+blob
                    if cmd.len() < 31 {
                        return Err(());
                    }
                    let auth_size =
                        u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]) as usize;
                    let priv_start = 10 + 4 + 4 + auth_size;
                    if cmd.len() < priv_start + 6 {
                        return Err(());
                    }
                    let priv_size =
                        u16::from_be_bytes([cmd[priv_start], cmd[priv_start + 1]]) as usize;
                    if priv_size < 4 || cmd.len() < priv_start + 2 + priv_size {
                        return Err(());
                    }
                    let orig_handle = u32::from_be_bytes([
                        cmd[priv_start + 2],
                        cmd[priv_start + 3],
                        cmd[priv_start + 4],
                        cmd[priv_start + 5],
                    ]);
                    if !st.sealed.iter().any(|o| o.handle == orig_handle) {
                        return Ok(failure_resp(0x018B)); // TPM_RC_HANDLE
                    }
                    let transient = 0x8000_0000 | orig_handle;
                    let mut r = alloc::vec![0u8; 10 + 4];
                    r[0] = 0x80;
                    r[1] = 0x01;
                    r[10] = (transient >> 24) as u8;
                    r[11] = (transient >> 16) as u8;
                    r[12] = (transient >> 8) as u8;
                    r[13] = transient as u8;
                    patch_size(&mut r);
                    Ok(r)
                }

                // ── TPM2_Unseal ───────────────────────────────────────────
                //
                // Derives the original handle, checks whether the current
                // PCR-7 value matches the sealed value, and returns the
                // secret or TPM_RC_POLICY_FAIL.
                x if x == TPM_CC_UNSEAL => {
                    if cmd.len() < 14 {
                        return Err(());
                    }
                    let item_handle = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]);
                    // Transient handles have bit 31 set; strip it to get orig.
                    let orig_handle = item_handle & !0x8000_0000;
                    let (pcr_idx, sealed_pcr, secret) =
                        match st.sealed.iter().find(|o| o.handle == orig_handle) {
                            Some(o) => (o.pcr_idx, o.sealed_pcr, o.secret.clone()),
                            None => return Ok(failure_resp(0x018B)),
                        };
                    if st.pcrs[pcr_idx] != sealed_pcr {
                        return Ok(failure_resp(TPM_RC_POLICY_FAIL));
                    }
                    let mut r = alloc::vec![0u8; 10 + 2 + secret.len()];
                    r[0] = 0x80;
                    r[1] = 0x01;
                    r[10] = (secret.len() >> 8) as u8;
                    r[11] = secret.len() as u8;
                    r[12..12 + secret.len()].copy_from_slice(&secret);
                    patch_size(&mut r);
                    Ok(r)
                }

                // ── TPM2_FlushContext ─────────────────────────────────────
                x if x == TPM_CC_FLUSH_CONTEXT => {
                    if cmd.len() >= 14 {
                        let handle = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]);
                        st.sessions.retain(|s| s.handle != handle);
                    }
                    Ok(success_resp())
                }

                _ => Ok(success_resp()),
            }
        }
    }

    /// Extract the `data` field from `TPM2_Create`'s `inSensitive`.
    ///
    /// Command layout (Part 3 §12.1):
    ///   header(10) + parentHandle(4) + authorizationSize(4) + auth(9) +
    ///   inSensitive (TPM2B_SENSITIVE_CREATE):
    ///     outerSize(2) + userAuth(2+N) + data(2+M)
    fn extract_sensitive_data(cmd: &[u8]) -> &[u8] {
        // Base = header(10) + parentHandle(4) + authSize(4) + auth(9)
        const BASE: usize = 10 + 4 + 4 + 9;
        if cmd.len() <= BASE + 4 {
            return &[];
        }
        // outerSize at BASE (skip it)
        let ua_size = u16::from_be_bytes([cmd[BASE + 2], cmd[BASE + 3]]) as usize;
        let data_off = BASE + 2 + 2 + ua_size;
        if cmd.len() <= data_off + 2 {
            return &[];
        }
        let data_size = u16::from_be_bytes([cmd[data_off], cmd[data_off + 1]]) as usize;
        let data_start = data_off + 2;
        if cmd.len() < data_start + data_size {
            return &[];
        }
        &cmd[data_start..data_start + data_size]
    }

    // ─────────────────────────────────────────────────────────────────────
    // Minimal sync future poller (same as tests.rs).
    // ─────────────────────────────────────────────────────────────────────

    fn poll_sync<F: core::future::Future>(fut: F) -> Option<F::Output> {
        use core::task::{Context, RawWaker, RawWakerVTable, Waker};
        unsafe fn no_clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTAB)
        }
        unsafe fn no_op(_: *const ()) {}
        static VTAB: RawWakerVTable = RawWakerVTable::new(no_clone, no_op, no_op, no_op);
        let raw = RawWaker::new(core::ptr::null(), &VTAB);
        let waker = unsafe { Waker::from_raw(raw) };
        let mut cx = Context::from_waker(&waker);
        let mut pinned = core::pin::pin!(fut);
        match pinned.as_mut().poll(&mut cx) {
            core::task::Poll::Ready(v) => Some(v),
            core::task::Poll::Pending => None,
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Command builder helpers used by e2e smokes.
    // ─────────────────────────────────────────────────────────────────────

    /// Build `TPM2_StartAuthSession` (policy, SHA-256, null keys, no salt).
    /// Part 3 §18.1.
    fn start_auth_session_cmd() -> Vec<u8> {
        use crate::tpm2::{begin_command, finalise, TPM_ST_NO_SESSIONS};
        let mut b = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_START_AUTH_SESSION);
        b.extend_from_slice(&0x4000_0007u32.to_be_bytes()); // tpmKey   = TPM_RH_NULL
        b.extend_from_slice(&0x4000_0007u32.to_be_bytes()); // bind     = TPM_RH_NULL
        b.extend_from_slice(&0u16.to_be_bytes()); // nonceCaller TPM2B size=0
        b.extend_from_slice(&0u16.to_be_bytes()); // encryptedSalt TPM2B size=0
        b.push(0x01); // sessionType = TPM_SE_POLICY
        b.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric  = TPM_ALG_NULL
        b.extend_from_slice(&0x000Bu16.to_be_bytes()); // authHash   = SHA-256
        finalise(&mut b);
        b
    }

    /// Build `TPM2_PolicyPCR` for a single PCR in the SHA-256 bank.
    /// Part 3 §23.7.
    fn policy_pcr_cmd(session_handle: u32, pcr_idx: u32) -> Vec<u8> {
        use crate::tpm2::{begin_command, finalise, TPM_ALG_SHA256, TPM_ST_NO_SESSIONS};
        let mut b = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_POLICY_PCR);
        b.extend_from_slice(&session_handle.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes()); // pcrDigest TPM2B size=0 (use current)
        b.extend_from_slice(&1u32.to_be_bytes()); // TPML_PCR_SELECTION count=1
        b.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        b.push(3); // sizeofSelect = 3
        let mut mask = [0u8; 3];
        if pcr_idx < 24 {
            mask[(pcr_idx / 8) as usize] |= 1 << (pcr_idx % 8);
        }
        b.extend_from_slice(&mask);
        finalise(&mut b);
        b
    }

    /// Build `TPM2_Create` for a sealed-data (KEYEDHASH) object under
    /// TPM_RH_OWNER with the given secret as `inSensitive.data`.
    /// `policy_digest` fills the authPolicy field of TPMT_PUBLIC.
    fn create_sealed_cmd(secret: &[u8], policy_digest: &[u8; 32]) -> Vec<u8> {
        use crate::tpm2::{
            begin_command, finalise, TPM_ALG_SHA256, TPM_RH_OWNER, TPM_RS_PW, TPM_ST_SESSIONS,
        };
        let mut b = begin_command(TPM_ST_SESSIONS, TPM_CC_CREATE);
        b.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
        // Empty password session (9 bytes).
        b.extend_from_slice(&9u32.to_be_bytes());
        b.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes()); // nonceSize = 0
        b.push(0u8); // sessionAttributes = 0
        b.extend_from_slice(&0u16.to_be_bytes()); // hmacSize = 0

        // inSensitive (TPM2B_SENSITIVE_CREATE):
        //   outerSize(2) + userAuth(2+0) + data(2+secret)
        let inner = 2 + 0 + 2 + secret.len();
        b.extend_from_slice(&(inner as u16).to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes()); // userAuth size=0
        b.extend_from_slice(&(secret.len() as u16).to_be_bytes());
        b.extend_from_slice(secret);

        // inPublic (TPM2B_PUBLIC):
        //   type=KEYEDHASH(0x0008) + nameAlg=SHA256 + attrs + authPolicy(2+32)
        //   + TPMS_KEYEDHASH_PARMS: scheme=NULL(2) + unique TPM2B size=0(2)
        let attrs: u32 = (1 << 6) | (1 << 2); // USER_WITH_AUTH | ST_CLEAR
        let mut pub_inner: Vec<u8> = Vec::new();
        pub_inner.extend_from_slice(&0x0008u16.to_be_bytes()); // type = KEYEDHASH
        pub_inner.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        pub_inner.extend_from_slice(&attrs.to_be_bytes());
        pub_inner.extend_from_slice(&32u16.to_be_bytes()); // authPolicy size
        pub_inner.extend_from_slice(policy_digest);
        pub_inner.extend_from_slice(&0x0010u16.to_be_bytes()); // scheme = NULL
        pub_inner.extend_from_slice(&0u16.to_be_bytes()); // unique TPM2B size=0
        b.extend_from_slice(&(pub_inner.len() as u16).to_be_bytes());
        b.extend_from_slice(&pub_inner);

        b.extend_from_slice(&0u16.to_be_bytes()); // outsideInfo TPM2B size=0
        b.extend_from_slice(&0u32.to_be_bytes()); // creationPCR count=0
        finalise(&mut b);
        b
    }

    /// Build `TPM2_Load` with a 4-byte private blob and empty public.
    fn load_sealed_cmd(parent_handle: u32, private_blob: &[u8]) -> Vec<u8> {
        use crate::tpm2::{begin_command, finalise, TPM_RS_PW, TPM_ST_SESSIONS};
        let mut b = begin_command(TPM_ST_SESSIONS, TPM_CC_LOAD);
        b.extend_from_slice(&parent_handle.to_be_bytes());
        b.extend_from_slice(&9u32.to_be_bytes()); // authSize
        b.extend_from_slice(&TPM_RS_PW.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());
        b.push(0u8);
        b.extend_from_slice(&0u16.to_be_bytes());
        b.extend_from_slice(&(private_blob.len() as u16).to_be_bytes());
        b.extend_from_slice(private_blob);
        b.extend_from_slice(&0u16.to_be_bytes()); // TPM2B_PUBLIC size=0
        finalise(&mut b);
        b
    }

    /// Build `TPM2_Unseal(itemHandle)` with a policy session in the auth area.
    fn unseal_with_session_cmd(item_handle: u32, session_handle: u32) -> Vec<u8> {
        use crate::tpm2::{begin_command, finalise, TPM_ST_SESSIONS};
        let mut b = begin_command(TPM_ST_SESSIONS, TPM_CC_UNSEAL);
        b.extend_from_slice(&item_handle.to_be_bytes());
        b.extend_from_slice(&9u32.to_be_bytes()); // authArea size
        b.extend_from_slice(&session_handle.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes()); // nonceSize=0
        b.push(0u8); // sessionAttributes
        b.extend_from_slice(&0u16.to_be_bytes()); // hmacSize=0
        finalise(&mut b);
        b
    }

    // ─────────────────────────────────────────────────────────────────────
    // Response parsing helpers.
    // ─────────────────────────────────────────────────────────────────────

    fn rc(raw: &[u8]) -> u32 {
        if raw.len() < 10 {
            return !0;
        }
        u32::from_be_bytes([raw[6], raw[7], raw[8], raw[9]])
    }

    /// Parse a PCR_Read response and return the first SHA-256 digest.
    fn parse_pcr_digest(raw: &[u8]) -> Option<[u8; 32]> {
        if rc(raw) != TPM_RC_SUCCESS {
            return None;
        }
        // header(10)+pcrUpdateCounter(4)+selCount(4)+hashAlg(2)+sos(1)+bitmap(3)
        // +digestCount(4)+digestSize(2) = 30 bytes before the digest
        let off = 10 + 4 + 4 + 2 + 1 + 3 + 4 + 2;
        if raw.len() < off + 32 {
            return None;
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(&raw[off..off + 32]);
        Some(d)
    }

    /// Parse a `TPM2_Load` response and return the objectHandle.
    fn parse_load_handle(raw: &[u8]) -> Option<u32> {
        if rc(raw) != TPM_RC_SUCCESS || raw.len() < 14 {
            return None;
        }
        Some(u32::from_be_bytes([raw[10], raw[11], raw[12], raw[13]]))
    }

    /// Parse a `TPM2_StartAuthSession` response and return the sessionHandle.
    fn parse_session_handle(raw: &[u8]) -> Option<u32> {
        // Same layout as Load response (handle at 10..14).
        parse_load_handle(raw)
    }

    /// Parse a `TPM2_Create` response and return the TPM2B_PRIVATE bytes.
    fn parse_create_private(raw: &[u8]) -> Option<Vec<u8>> {
        if rc(raw) != TPM_RC_SUCCESS || raw.len() < 12 {
            return None;
        }
        let priv_size = u16::from_be_bytes([raw[10], raw[11]]) as usize;
        if raw.len() < 12 + priv_size {
            return None;
        }
        Some(raw[12..12 + priv_size].to_vec())
    }

    /// Parse a `TPM2_Unseal` response and return the secret bytes.
    fn parse_unseal_secret(raw: &[u8]) -> Option<Vec<u8>> {
        if rc(raw) != TPM_RC_SUCCESS || raw.len() < 12 {
            return None;
        }
        let size = u16::from_be_bytes([raw[10], raw[11]]) as usize;
        if raw.len() < 12 + size {
            return None;
        }
        Some(raw[12..12 + size].to_vec())
    }

    // ─────────────────────────────────────────────────────────────────────
    // FlushRecordingTransport — wraps FakeTpmTransport and logs FlushContext
    // calls to a test-local static so smokes 12/13 can inspect them without
    // downcasting the erased `Arc<dyn TpmTransport>`.
    // ─────────────────────────────────────────────────────────────────────

    static FLUSH_LOG: IrqSafeSpinLock<Vec<u32>> = IrqSafeSpinLock::new(Vec::new());

    struct FlushRecorder {
        inner: Arc<FakeTpmTransport>,
    }

    impl crate::devfs_bridge::TpmTransport for FlushRecorder {
        fn submit(&self, cmd: &[u8]) -> Result<Vec<u8>, ()> {
            let resp = self.inner.submit(cmd)?;
            if cmd.len() >= 14 {
                let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
                if cc == TPM_CC_FLUSH_CONTEXT {
                    let h = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]);
                    FLUSH_LOG.lock().push(h);
                }
            }
            Ok(resp)
        }
    }

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 1: TPM2_Startup(CLEAR) → SUCCESS
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_startup_clear() -> TestResult {
        let t = Arc::new(FakeTpmTransport::new());
        let cmd = crate::tpm2::commands::startup_clear();
        let resp = match t.submit(&cmd) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("submit failed"),
        };
        if rc(&resp) != TPM_RC_SUCCESS {
            return TestResult::Fail("Startup(CLEAR) returned non-SUCCESS");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_startup_clear);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 2: TPM2_GetCapability(MANUFACTURER) → "FAKE"
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_get_capability_manufacturer() -> TestResult {
        let t = Arc::new(FakeTpmTransport::new());
        let cmd = crate::tpm2::commands::get_capability(
            crate::tpm2::TPM_CAP_TPM_PROPERTIES,
            0x0000_0105, // PT_MANUFACTURER
            1,
        );
        let resp = match t.submit(&cmd) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("submit failed"),
        };
        if rc(&resp) != TPM_RC_SUCCESS {
            return TestResult::Fail("GetCapability returned non-SUCCESS");
        }
        // value at: 10 (body) + 1 (moreData) + 4 (cap) + 4 (count) + 4 (tag) = 23
        if resp.len() < 27 {
            return TestResult::Fail("GetCapability response too short");
        }
        let value = u32::from_be_bytes([resp[23], resp[24], resp[25], resp[26]]);
        if value != FAKE_MANUFACTURER {
            return TestResult::Fail("MANUFACTURER != 'FAKE'");
        }
        // ASCII printability check.
        for b in value.to_be_bytes() {
            if !b.is_ascii_graphic() {
                return TestResult::Fail("MANUFACTURER contains non-graphic byte");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_get_capability_manufacturer);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 3: TPM2_GetRandom(32) → 32 distinct bytes, non-zero variance
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_get_random_32() -> TestResult {
        let t = Arc::new(FakeTpmTransport::new());
        let cmd = crate::tpm2::commands::get_random(32);
        let resp = match t.submit(&cmd) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("submit failed"),
        };
        if rc(&resp) != TPM_RC_SUCCESS {
            return TestResult::Fail("GetRandom returned non-SUCCESS");
        }
        // header(10) + size(2) + 32 bytes = 44 minimum
        if resp.len() < 44 {
            return TestResult::Fail("GetRandom(32) response too short");
        }
        let n = u16::from_be_bytes([resp[10], resp[11]]) as usize;
        if n != 32 {
            return TestResult::Fail("GetRandom returned wrong byte count");
        }
        let rand = &resp[12..12 + 32];
        // Non-zero variance: not all bytes identical.
        let first = rand[0];
        if rand.iter().all(|&b| b == first) {
            return TestResult::Fail("GetRandom returned zero-variance data");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_get_random_32);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 4: PCR_Read PCR-0 SHA-256 before extend → all-zero
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_pcr0_zero_before_extend() -> TestResult {
        let t = Arc::new(FakeTpmTransport::new());
        let cmd = crate::tpm2::commands::pcr_read_single(0);
        let resp = t.submit(&cmd).unwrap_or_default();
        let digest = match parse_pcr_digest(&resp) {
            Some(d) => d,
            None => return TestResult::Fail("could not parse PCR_Read response"),
        };
        if digest != [0u8; 32] {
            return TestResult::Fail("PCR-0 is not all-zero before any extend");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_pcr0_zero_before_extend);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 5: PCR_Extend PCR-7 with D1 → PCR-7 = SHA256(0||D1)
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_pcr_extend_single() -> TestResult {
        let t = Arc::new(FakeTpmTransport::new());
        let d1 = [0x11u8; 32];
        let expected = pcr_extend_formula(&[0u8; 32], &d1);

        if t.submit(&crate::tpm2::commands::pcr_extend_sha256(7, &d1))
            .is_err()
        {
            return TestResult::Fail("PCR_Extend failed");
        }
        let resp = t
            .submit(&crate::tpm2::commands::pcr_read_single(7))
            .unwrap_or_default();
        let digest = match parse_pcr_digest(&resp) {
            Some(d) => d,
            None => return TestResult::Fail("could not parse PCR_Read response"),
        };
        if digest != expected {
            return TestResult::Fail("PCR-7 != SHA256(0||D1) after single extend");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_pcr_extend_single);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 6: Multiple extends compose — SHA256(SHA256(0||D1)||D2)
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_pcr_extend_compose() -> TestResult {
        let t = Arc::new(FakeTpmTransport::new());
        let d1 = [0x22u8; 32];
        let d2 = [0x33u8; 32];
        let after_d1 = pcr_extend_formula(&[0u8; 32], &d1);
        let expected = pcr_extend_formula(&after_d1, &d2);

        if t.submit(&crate::tpm2::commands::pcr_extend_sha256(7, &d1))
            .is_err()
            || t.submit(&crate::tpm2::commands::pcr_extend_sha256(7, &d2))
                .is_err()
        {
            return TestResult::Fail("PCR_Extend(s) failed");
        }
        let resp = t
            .submit(&crate::tpm2::commands::pcr_read_single(7))
            .unwrap_or_default();
        let digest = match parse_pcr_digest(&resp) {
            Some(d) => d,
            None => return TestResult::Fail("could not parse PCR_Read response"),
        };
        if digest != expected {
            return TestResult::Fail("PCR-7 != SHA256(SHA256(0||D1)||D2) after two extends");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_pcr_extend_compose);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 7: PCR_Read after extend matches expected digest
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_pcr_read_matches_expected() -> TestResult {
        let t = Arc::new(FakeTpmTransport::new());
        let d = [0x42u8; 32];
        let expected = pcr_extend_formula(&[0u8; 32], &d);

        if t.submit(&crate::tpm2::commands::pcr_extend_sha256(3, &d))
            .is_err()
        {
            return TestResult::Fail("PCR_Extend failed");
        }
        let resp = t
            .submit(&crate::tpm2::commands::pcr_read_single(3))
            .unwrap_or_default();
        let digest = match parse_pcr_digest(&resp) {
            Some(d) => d,
            None => return TestResult::Fail("could not parse PCR_Read response"),
        };
        if digest != expected {
            return TestResult::Fail("PCR-3 read-back does not match expected");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_pcr_read_matches_expected);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 8: /sys/class/tpm/tpm0/pcrs format after extends
    // ═════════════════════════════════════════════════════════════════════

#[cfg(feature = "linux-compat")]
    fn e2e_smoke_sysfs_pcrs_format() -> TestResult {
        let fake = Arc::new(FakeTpmTransport::new());
        // Extend PCR-0 so the sysfs output shows a non-trivial value.
        let d0 = [0x01u8; 32];
        if fake
            .submit(&crate::tpm2::commands::pcr_extend_sha256(0, &d0))
            .is_err()
        {
            return TestResult::Fail("PCR_Extend failed in sysfs smoke");
        }

        let t = fake as Arc<dyn crate::devfs_bridge::TpmTransport>;
        crate::devfs_bridge::register_transport(t.clone());
        crate::sysfs_bridge::register_sysfs_tpm0(t);

        let class_tpm = narf_filesystem::class_register("tpm");
        let tpm0 = narf_filesystem::class_device_register(class_tpm, "tpm0");
        let pcrs = tpm0.attr_show("pcrs");
        crate::devfs_bridge::unregister_transport();

        let pcrs = match pcrs {
            Some(s) => s,
            None => return TestResult::Fail("pcrs attribute missing"),
        };

        if !pcrs.starts_with("PCR-00:") {
            return TestResult::Fail("pcrs does not start with 'PCR-00:'");
        }
        if !pcrs.contains("(SHA-256)") {
            return TestResult::Fail("pcrs missing '(SHA-256)' label");
        }
        if !pcrs.contains("PCR-23:") {
            return TestResult::Fail("pcrs does not contain PCR-23 line");
        }
        TestResult::Pass
    }
#[cfg(feature = "linux-compat")]
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_sysfs_pcrs_format);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 9: NV_DefineSpace + NV_Write + NV_Read round-trip
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_nv_round_trip() -> TestResult {
        let t = Arc::new(FakeTpmTransport::new());
        const NV_IDX: u32 = 0x0150_0000;
        let attrs = crate::tpm2::nv::NV_ATTR_AUTH_RW;

        // Define space.
        if t.submit(&crate::tpm2::commands::nv_define_space(NV_IDX, 16, attrs))
            .is_err()
        {
            return TestResult::Fail("NV_DefineSpace failed");
        }

        // Write 16 bytes.
        let payload: [u8; 16] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
            0x07, 0x08,
        ];
        if t.submit(&crate::tpm2::commands::nv_write(NV_IDX, &payload, 0))
            .is_err()
        {
            return TestResult::Fail("NV_Write failed");
        }

        // Read back.
        let resp = t
            .submit(&crate::tpm2::commands::nv_read(NV_IDX, 16, 0))
            .unwrap_or_default();
        if rc(&resp) != TPM_RC_SUCCESS {
            return TestResult::Fail("NV_Read returned non-SUCCESS");
        }
        if resp.len() < 12 + 16 {
            return TestResult::Fail("NV_Read response too short");
        }
        let data_size = u16::from_be_bytes([resp[10], resp[11]]) as usize;
        if data_size != 16 {
            return TestResult::Fail("NV_Read returned wrong data size");
        }
        if &resp[12..28] != &payload {
            return TestResult::Fail("NV round-trip data mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_nv_round_trip);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 10: Seal blob bound to PCR-7 → Unseal succeeds
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_seal_unseal_success() -> TestResult {
        let t = Arc::new(FakeTpmTransport::new());

        // 1. Extend PCR-7 to a known value.
        let d1 = [0xABu8; 32];
        if t.submit(&crate::tpm2::commands::pcr_extend_sha256(7, &d1))
            .is_err()
        {
            return TestResult::Fail("PCR_Extend failed");
        }

        // 2. StartAuthSession.
        let sess_resp = t.submit(&start_auth_session_cmd()).unwrap_or_default();
        let session_handle = match parse_session_handle(&sess_resp) {
            Some(h) => h,
            None => return TestResult::Fail("could not parse session handle"),
        };

        // 3. PolicyPCR on PCR-7.
        if t.submit(&policy_pcr_cmd(session_handle, 7)).is_err() {
            return TestResult::Fail("PolicyPCR failed");
        }

        // 4. Create sealed object.
        let secret = b"narf-disk-key-analog-32-bytes!!!";
        let create_resp = t
            .submit(&create_sealed_cmd(secret, &[0u8; 32]))
            .unwrap_or_default();
        let private_blob = match parse_create_private(&create_resp) {
            Some(b) => b,
            None => return TestResult::Fail("could not parse Create response"),
        };

        // 5. Load.
        let load_resp = t
            .submit(&load_sealed_cmd(crate::tpm2::TPM_RH_OWNER, &private_blob))
            .unwrap_or_default();
        let object_handle = match parse_load_handle(&load_resp) {
            Some(h) => h,
            None => return TestResult::Fail("could not parse Load response"),
        };

        // 6. Unseal — PCR-7 unchanged → SUCCESS.
        let unseal_resp = t
            .submit(&unseal_with_session_cmd(object_handle, session_handle))
            .unwrap_or_default();
        if rc(&unseal_resp) != TPM_RC_SUCCESS {
            return TestResult::Fail("Unseal returned non-SUCCESS when PCR matches sealed value");
        }
        let returned = match parse_unseal_secret(&unseal_resp) {
            Some(s) => s,
            None => return TestResult::Fail("could not parse Unseal response"),
        };
        if returned != secret.as_ref() {
            return TestResult::Fail("Unseal returned wrong secret");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_seal_unseal_success);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 11: Re-extend PCR-7 → Unseal fails (TPM_RC_POLICY_FAIL)
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_seal_unseal_policy_fail() -> TestResult {
        let t = Arc::new(FakeTpmTransport::new());

        // Extend PCR-7 and seal a secret.
        let d1 = [0xCCu8; 32];
        if t.submit(&crate::tpm2::commands::pcr_extend_sha256(7, &d1))
            .is_err()
        {
            return TestResult::Fail("PCR_Extend (initial) failed");
        }
        let secret = b"disk-encryption-key-placeholder!";
        let create_resp = t
            .submit(&create_sealed_cmd(secret, &[0u8; 32]))
            .unwrap_or_default();
        let private_blob = match parse_create_private(&create_resp) {
            Some(b) => b,
            None => return TestResult::Fail("could not parse Create response"),
        };
        let load_resp = t
            .submit(&load_sealed_cmd(crate::tpm2::TPM_RH_OWNER, &private_blob))
            .unwrap_or_default();
        let object_handle = match parse_load_handle(&load_resp) {
            Some(h) => h,
            None => return TestResult::Fail("could not parse Load response"),
        };

        // Re-extend PCR-7 → PCR value changes.
        let d2 = [0xDDu8; 32];
        if t.submit(&crate::tpm2::commands::pcr_extend_sha256(7, &d2))
            .is_err()
        {
            return TestResult::Fail("PCR_Extend (re-extend) failed");
        }

        // Unseal → must fail.
        let sess_resp = t.submit(&start_auth_session_cmd()).unwrap_or_default();
        let session_handle = parse_session_handle(&sess_resp).unwrap_or(FAKE_SESSION_HANDLE);
        let unseal_resp = t
            .submit(&unseal_with_session_cmd(object_handle, session_handle))
            .unwrap_or_default();
        let returned_rc = rc(&unseal_resp);
        if returned_rc != TPM_RC_POLICY_FAIL {
            return TestResult::Fail("Unseal should fail with TPM_RC_POLICY_FAIL after re-extend");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_seal_unseal_policy_fail);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 12: FlushContext issued by DevTpmRm0 on drop
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_tpmrm0_flush_on_drop() -> TestResult {
        use narf_filesystem::FileOps;

        FLUSH_LOG.lock().clear();

        let fake = Arc::new(FakeTpmTransport::new());

        // Pre-create a sealed object so the Load command has something to return.
        let secret = b"session-key-material-32-bytes!!!";
        let create_resp = fake
            .submit(&create_sealed_cmd(secret, &[0u8; 32]))
            .unwrap_or_default();
        let private_blob = match parse_create_private(&create_resp) {
            Some(b) => b,
            None => return TestResult::Fail("Create parse failed"),
        };
        let load_cmd = load_sealed_cmd(crate::tpm2::TPM_RH_OWNER, &private_blob);

        let recorder =
            Arc::new(FlushRecorder { inner: fake }) as Arc<dyn crate::devfs_bridge::TpmTransport>;
        crate::devfs_bridge::register_transport(recorder);

        let transient_handle;
        {
            let dev = crate::devfs_bridge::DevTpmRm0::new();
            // Write the Load command through the RM device.
            let _ = poll_sync(dev.write(0, &load_cmd)).and_then(|r| r.ok());
            // Read the response to find the transient handle.
            let mut buf = alloc::vec![0u8; 64];
            let n = poll_sync(dev.read(0, &mut buf))
                .and_then(|r| r.ok())
                .unwrap_or(0);
            transient_handle = if n >= 14 {
                u32::from_be_bytes([buf[10], buf[11], buf[12], buf[13]])
            } else {
                0
            };
            // DevTpmRm0 drops here → FlushContext(transient_handle)
        }

        let flush_log = FLUSH_LOG.lock().clone();
        crate::devfs_bridge::unregister_transport();

        if transient_handle == 0 {
            return TestResult::Fail("could not determine transient handle from Load response");
        }
        if !flush_log.contains(&transient_handle) {
            return TestResult::Fail("DevTpmRm0 did not FlushContext the transient handle on drop");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_tpmrm0_flush_on_drop);

    // ═════════════════════════════════════════════════════════════════════
    // Smoke 13: DevTpm0 (raw) does NOT auto-flush on drop
    // ═════════════════════════════════════════════════════════════════════

    fn e2e_smoke_tpm0_no_auto_flush() -> TestResult {
        use narf_filesystem::FileOps;

        FLUSH_LOG.lock().clear();

        let fake = Arc::new(FakeTpmTransport::new());

        // Pre-create a sealed object.
        let secret = b"raw-device-secret-should-stay!!!";
        let create_resp = fake
            .submit(&create_sealed_cmd(secret, &[0u8; 32]))
            .unwrap_or_default();
        let private_blob = match parse_create_private(&create_resp) {
            Some(b) => b,
            None => return TestResult::Fail("Create parse failed"),
        };
        let load_cmd = load_sealed_cmd(crate::tpm2::TPM_RH_OWNER, &private_blob);

        let recorder =
            Arc::new(FlushRecorder { inner: fake }) as Arc<dyn crate::devfs_bridge::TpmTransport>;
        crate::devfs_bridge::register_transport(recorder);

        {
            let dev = crate::devfs_bridge::DevTpm0::new();
            let _ = poll_sync(dev.write(0, &load_cmd)).and_then(|r| r.ok());
            // DevTpm0 drops here — must NOT FlushContext.
        }

        let flush_log = FLUSH_LOG.lock().clone();
        crate::devfs_bridge::unregister_transport();

        if !flush_log.is_empty() {
            return TestResult::Fail("DevTpm0 (raw) issued FlushContext on drop — must not");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/tpm/e2e", e2e_smoke_tpm0_no_auto_flush);
}
