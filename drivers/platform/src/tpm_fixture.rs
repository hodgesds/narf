//! Register-level TPM 2.0 device model + production-seam fixtures
//! (#946).
//!
//! The round-1 TPM audit found the fixture situation inverted: the
//! orphaned `drivers/tpm` stack had a stateful fake and a full
//! suite, while the seams that actually run — the production
//! transport in `crate::tpm`, the ACPI discovery decision, and the
//! registry dispatch `frame::measure` consults — had no
//! simulated-hardware coverage at all. The keystone chain
//! (#969/#970/#972/#973) closed the probe-core and wire-encoding
//! holes; this module closes the remaining ones:
//!
//! - [`FakeTpmDevice`]: a swtpm-shaped register-level model of a
//!   TPM 2.0 — a CRB control area (PTP rev 1.05 §6) or a TIS
//!   register block (TIS v1.21 §5.6) in front of a stateful
//!   command core (PCR banks applying the real extend formula,
//!   Startup gating, deterministic RNG). The production probe core
//!   and both production submit paths (`submit_crb_over` /
//!   `submit_tis_over`) drive it through the same `CrbRegs` seam
//!   they use against MMIO, so the conversation a fixture runs is
//!   the conversation silicon would see.
//! - Fixtures composing the full boot path end to end: synthetic
//!   TPM2 ACPI table → `parse_tpm2` → `discovered_base` →
//!   identify/acquire over the model → registry registration →
//!   dispatch → hardware PCR state.
//!
//! ## Model fidelity — what is modelled, what is not
//!
//! Modelled per spec: CRB locality grant on LOC_CTRL request,
//! host-programmed buffer registers fetched at GO time, CMD_READY
//! → GO → self-clearing START discipline, CANCEL of a wedged
//! command; TIS locality request/grant, EXPECT-gated FIFO writes,
//! GO execution, DATA_AVAIL drain, and the commandReady discipline
//! (the TPM clears commandReady when a command is taken; the host
//! must re-assert it before the next command — TIS §5.6, and the
//! behaviour Linux's `tpm_tis_ready` implements). Commands other
//! than TPM2_Startup are rejected with `TPM_RC_INITIALIZE` until
//! Startup, exactly as a powered-on TPM behaves. PCR_Extend
//! parses the sessions-tagged frame of Part 3 §22.2 (TPM_RS_PW
//! authorization area included) and applies
//! `PCR = SHA256(PCR || digest)` (Part 1 §17.4).
//!
//! Documented simplifications (each is a place the model is
//! *narrower* than silicon, never a place it excuses the driver):
//! - Only the SHA-256 PCR bank is implemented; a digest list or
//!   selection naming another bank is answered `TPM_RC_VALUE`, as
//!   a TPM without that bank allocated would.
//! - All 24 PCRs reset to zero on Startup(CLEAR). Silicon sets
//!   the DRTM PCRs (17–22) to their locality-defined reset values;
//!   no production path or fixture measures into them.
//! - Startup(STATE) is accepted like CLEAR (the model keeps no
//!   saved state to restore).
//! - GetRandom bytes come from a fixed-seed xorshift PRNG:
//!   determinism is a fixture requirement, and fixtures assert
//!   framing/length only, never entropy.
//! - GetCapability (#941) serves the capabilities the command
//!   core actually implements — TPM_PROPERTIES (the model's
//!   identity: manufacturer "NARF", vendor string "NARF fixture
//!   TPM", firmware 1.0, spec revision 159, TPMA_PERMANENT = 0 —
//!   no hierarchy auth is set), PCRS (the SHA-256 bank), ALGS
//!   (SHA-256 only), COMMANDS (the six implemented command
//!   codes), HANDLES (always empty: the model holds no loaded
//!   objects). Any other capability is answered `TPM_RC_VALUE`,
//!   as a TPM without it would.
//! - `CTRL_STS.error` is never set for ordinary command RCs (it
//!   signals a fatal device state on silicon, not a rejection).

#![cfg(target_arch = "x86_64")]

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use async_trait::async_trait;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;
use narf_tpm::{TpmDevice, TpmError as HighLevelTpmError, TpmInfo};

use crate::tpm::{self, CrbRegs};

// ── Device-side register bits ──────────────────────────────────────
// The model plays the TPM, so it defines the bits from the device
// side of the same documents the production register map cites
// (PTP rev 1.05 §6, TIS v1.21 §5.6).

const CRB_CTRL_REQ_CMD_READY: u32 = 1 << 0;
const CRB_CTRL_STS_TPM_IDLE: u32 = 1 << 1;
const CRB_CTRL_START_GO: u32 = 1 << 0;

const TIS_ACCESS_REQUEST_USE: u8 = 1 << 1;
const TIS_ACCESS_ACTIVE: u8 = 1 << 5;
const TIS_ACCESS_VALID: u8 = 1 << 7;
const TIS_STS_CMD_READY: u8 = 1 << 6;
const TIS_STS_GO: u8 = 1 << 5;
const TIS_STS_DATA_AVAIL: u8 = 1 << 4;
const TIS_STS_EXPECT: u8 = 1 << 3;
const TIS_STS_VALID: u8 = 1 << 7;

// ── TPM_RC values (Part 1 §39, Part 2 §6.6) ───────────────────────

const RC_INITIALIZE: u32 = 0x0000_0100;
const RC_FAILURE: u32 = 0x0000_0101;
const RC_COMMAND_CODE: u32 = 0x0000_0143;
const RC_AUTH_MISSING: u32 = 0x0000_012A;
const RC_VALUE: u32 = 0x0000_0184;
const RC_SIZE: u32 = 0x0000_0195;

const TPM_RS_PW: u32 = 0x4000_0009;

// ── SHA-256 (FIPS 180-4 §6.2.2) ────────────────────────────────────
//
// The model needs the real extend formula, which needs SHA-256.
// Same algorithm as `narf-crypto/src/sha256.rs`, copied here for
// the same reason `drivers/tpm`'s e2e fixtures copied it: the
// platform crate takes no crypto dependency for its test code.
// `smoke_tpm_fixture_sha256_fips_vectors` pins it to the FIPS
// vectors so a transcription error fails loudly, and the frame
// fixtures cross-check this model's PCR state against `frame`'s
// independent implementation.

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
fn pcr_extend_value(old: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(old);
    input[32..].copy_from_slice(digest);
    sha256(&input)
}

// ── The device model ───────────────────────────────────────────────

struct DeviceState {
    /// The register file: one locality-0 window, byte-addressed.
    regs: [u8; 0x1000],
    /// SHA-256 PCR bank.
    pcrs: [[u8; 32]; 24],
    started: bool,
    update_counter: u64,
    rng: u64,
    // Observations for fixture assertions.
    cancel_seen: bool,
    cmd_ready_seen: bool,
    go_count: u32,
    dropped_fifo_bytes: u32,
    bad_buffer_addr: bool,
    // TIS conversation state.
    tis_cmd_ready: bool,
    tis_locality: bool,
    tis_rx: Vec<u8>,
    tis_tx: Vec<u8>,
    tis_tx_pos: usize,
}

impl DeviceState {
    fn get32(&self, offset: u64) -> u32 {
        let o = offset as usize;
        u32::from_le_bytes([
            self.regs[o],
            self.regs[o + 1],
            self.regs[o + 2],
            self.regs[o + 3],
        ])
    }
    fn set32(&mut self, offset: u64, value: u32) {
        let o = offset as usize;
        self.regs[o..o + 4].copy_from_slice(&value.to_le_bytes());
    }
}

/// A register-level TPM 2.0 model. Construct with
/// [`FakeTpmDevice::crb`] or [`FakeTpmDevice::tis`], attach the
/// host buffers the fixture will program into the device, then
/// drive it with the production `CrbRegs` consumers (`identify`,
/// `crb_acquire_and_program`, `submit_crb_over`, `submit_tis_over`).
struct FakeTpmDevice {
    state: IrqSafeSpinLock<DeviceState>,
    tis: bool,
    wedge: core::sync::atomic::AtomicBool,
    /// Host command-buffer memory (fixture-owned). The device
    /// fetches commands from the address the host programmed into
    /// CMD_PA — in fixture space that address is this pointer,
    /// exactly as a DMA-capable device reads host RAM.
    cmd_mem: *mut u8,
    cmd_mem_len: usize,
    rsp_mem: *mut u8,
    rsp_mem_len: usize,
}

// SAFETY: all mutable state sits behind `IrqSafeSpinLock` or an
// atomic; the buffer pointers are set once by `attach_buffers`
// before the device is shared, and only read afterwards.
unsafe impl Send for FakeTpmDevice {}
unsafe impl Sync for FakeTpmDevice {}

impl FakeTpmDevice {
    fn new(tis: bool) -> Self {
        let mut st = DeviceState {
            regs: [0; 0x1000],
            pcrs: [[0; 32]; 24],
            started: false,
            update_counter: 0,
            rng: 0x9E37_79B9_7F4A_7C15,
            cancel_seen: false,
            cmd_ready_seen: false,
            go_count: 0,
            dropped_fifo_bytes: 0,
            bad_buffer_addr: false,
            tis_cmd_ready: true,
            tis_locality: false,
            tis_rx: Vec::new(),
            tis_tx: Vec::new(),
            tis_tx_pos: 0,
        };
        if tis {
            // INTF_ID: type 0xF (TIS-only), version 1. DID_VID:
            // a sane vendor/device pair (identify requires one).
            st.set32(tpm::REG_INTERFACE_ID, 0x1F);
            st.set32(tpm::REG_TIS_DID_VID, 0x15D1_0001);
        } else {
            // INTF_ID: type 0 (CRB), version 1 — the encoding is
            // type in bits[3:0], version in bits[7:4], i.e. 0x10.
            st.set32(tpm::REG_INTERFACE_ID, 0x10);
            // A powered-on CRB TPM sits in TPM_IDLE until the host
            // requests command-ready.
            st.set32(tpm::REG_CRB_CTRL_STS, CRB_CTRL_STS_TPM_IDLE);
        }
        Self {
            state: IrqSafeSpinLock::new(st),
            tis,
            wedge: core::sync::atomic::AtomicBool::new(false),
            cmd_mem: core::ptr::null_mut(),
            cmd_mem_len: 0,
            rsp_mem: core::ptr::null_mut(),
            rsp_mem_len: 0,
        }
    }

    fn crb() -> Self {
        Self::new(false)
    }

    fn tis() -> Self {
        Self::new(true)
    }

    /// Attach the fixture-owned host buffers. Must be called
    /// before any submit; the addresses are what the fixture
    /// programs into the CMD_PA / RSP_PA registers.
    fn attach_buffers(&mut self, cmd: *mut u8, cmd_len: usize, rsp: *mut u8, rsp_len: usize) {
        self.cmd_mem = cmd;
        self.cmd_mem_len = cmd_len;
        self.rsp_mem = rsp;
        self.rsp_mem_len = rsp_len;
    }

    /// Wedge the device: CTRL_START.GO never completes (the
    /// command is never executed), so the production poll runs to
    /// its timeout and must CANCEL.
    fn set_wedge(&self, wedge: bool) {
        self.wedge
            .store(wedge, core::sync::atomic::Ordering::SeqCst);
    }

    fn cancel_seen(&self) -> bool {
        self.state.lock().cancel_seen
    }
    fn cmd_ready_seen(&self) -> bool {
        self.state.lock().cmd_ready_seen
    }
    fn go_count(&self) -> u32 {
        self.state.lock().go_count
    }
    fn dropped_fifo_bytes(&self) -> u32 {
        self.state.lock().dropped_fifo_bytes
    }
    fn bad_buffer_addr(&self) -> bool {
        self.state.lock().bad_buffer_addr
    }
    fn pcr(&self, idx: u32) -> [u8; 32] {
        self.state.lock().pcrs[idx as usize]
    }
    fn is_started(&self) -> bool {
        self.state.lock().started
    }

    // ── Command core ─────────────────────────────────────────────

    /// Execute one command frame against the TPM core and return
    /// the response frame. Transport-independent: the CRB and TIS
    /// front ends both land here, as they do on silicon.
    fn execute(&self, cmd: &[u8]) -> Vec<u8> {
        // Error responses are always TPM_ST_NO_SESSIONS / 10 bytes
        // (Part 1 §18: error responses carry no session area).
        let err = |rc: u32| -> Vec<u8> {
            let mut out = alloc::vec![0u8; 10];
            out[0..2].copy_from_slice(&narf_tpm::tpm2::TPM_ST_NO_SESSIONS.to_be_bytes());
            out[2..6].copy_from_slice(&10u32.to_be_bytes());
            out[6..10].copy_from_slice(&rc.to_be_bytes());
            out
        };
        if cmd.len() < 10 {
            return err(RC_SIZE);
        }
        let tag = u16::from_be_bytes([cmd[0], cmd[1]]);
        let size = u32::from_be_bytes([cmd[2], cmd[3], cmd[4], cmd[5]]) as usize;
        let cc = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]);
        if size != cmd.len() {
            return err(RC_SIZE);
        }
        let ok = |body: &[u8]| -> Vec<u8> {
            let mut out = alloc::vec![0u8; 10 + body.len()];
            out[0..2].copy_from_slice(&tag.to_be_bytes());
            out[2..6].copy_from_slice(&((10 + body.len()) as u32).to_be_bytes());
            out[10..].copy_from_slice(body);
            out
        };

        // TPM2_Startup is the only command a powered-on TPM
        // accepts before it is started (Part 3 §9.3).
        if cc == narf_tpm::tpm2::TPM_CC_STARTUP {
            if cmd.len() != 12 {
                return err(RC_SIZE);
            }
            let mut st = self.state.lock();
            if st.started {
                return err(RC_VALUE);
            }
            st.started = true;
            // Startup(CLEAR) reset values (documented
            // simplification: all-zero, DRTM PCRs included).
            st.pcrs = [[0; 32]; 24];
            st.update_counter = 0;
            return ok(&[]);
        }
        if !self.state.lock().started {
            return err(RC_INITIALIZE);
        }

        match cc {
            x if x == narf_tpm::tpm2::TPM_CC_SHUTDOWN => {
                if cmd.len() != 12 {
                    return err(RC_SIZE);
                }
                self.state.lock().started = false;
                ok(&[])
            }
            x if x == narf_tpm::tpm2::TPM_CC_PCR_EXTEND => self.exec_pcr_extend(tag, cmd),
            x if x == narf_tpm::tpm2::TPM_CC_PCR_READ => self.exec_pcr_read(cmd),
            x if x == narf_tpm::tpm2::TPM_CC_GET_CAPABILITY => self.exec_get_capability(tag, cmd),
            x if x == narf_tpm::tpm2::TPM_CC_GET_RANDOM => {
                if cmd.len() != 12 {
                    return err(RC_SIZE);
                }
                let n = u16::from_be_bytes([cmd[10], cmd[11]]) as usize;
                let mut body = alloc::vec![0u8; 2 + n];
                body[0..2].copy_from_slice(&(n as u16).to_be_bytes());
                let mut st = self.state.lock();
                for chunk in body[2..].chunks_mut(8) {
                    // xorshift64* — deterministic fixture bytes.
                    let mut s = st.rng;
                    s ^= s >> 12;
                    s ^= s << 25;
                    s ^= s >> 27;
                    st.rng = s;
                    let v = s.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
                    chunk.copy_from_slice(&v[..chunk.len()]);
                }
                drop(st);
                ok(&body)
            }
            _ => err(RC_COMMAND_CODE),
        }
    }

    /// TPM2_PCR_Extend (Part 3 §22.2): sessions-tagged frame with
    /// a TPM_RS_PW authorization area, then a TPML_DIGEST_VALUES.
    fn exec_pcr_extend(&self, tag: u16, cmd: &[u8]) -> Vec<u8> {
        let err = |rc: u32| -> Vec<u8> {
            let mut out = alloc::vec![0u8; 10];
            out[0..2].copy_from_slice(&narf_tpm::tpm2::TPM_ST_NO_SESSIONS.to_be_bytes());
            out[2..6].copy_from_slice(&10u32.to_be_bytes());
            out[6..10].copy_from_slice(&rc.to_be_bytes());
            out
        };
        // The PCR handle is an authorization handle: a
        // NO_SESSIONS frame carries no authorization area and a
        // real TPM rejects it with TPM_RC_AUTH_MISSING.
        if tag != narf_tpm::tpm2::TPM_ST_SESSIONS {
            return err(RC_AUTH_MISSING);
        }
        if cmd.len() < 18 {
            return err(RC_SIZE);
        }
        let pcr = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]);
        if pcr >= 24 {
            return err(RC_VALUE);
        }
        let auth_size = u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]) as usize;
        let auth_end = 18 + auth_size;
        if auth_size < 9 || auth_end > cmd.len() {
            return err(RC_SIZE);
        }
        // Authorization area: sessionHandle(4) + nonce(TPM2B) +
        // sessionAttributes(1) + hmac(TPM2B). Only the password
        // session is modelled; anything else is a value error, as
        // an unopened session handle would be on silicon.
        let session = u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]);
        if session != TPM_RS_PW {
            return err(RC_VALUE);
        }
        let mut pos = 22;
        let read_tpm2b = |pos: &mut usize| -> Option<()> {
            if *pos + 2 > auth_end {
                return None;
            }
            let n = u16::from_be_bytes([cmd[*pos], cmd[*pos + 1]]) as usize;
            *pos += 2 + n;
            if *pos > auth_end {
                return None;
            }
            Some(())
        };
        if read_tpm2b(&mut pos).is_none() {
            return err(RC_SIZE);
        }
        if pos + 1 > auth_end {
            return err(RC_SIZE);
        }
        pos += 1; // sessionAttributes
        if read_tpm2b(&mut pos).is_none() || pos != auth_end {
            return err(RC_SIZE);
        }
        // TPML_DIGEST_VALUES: count(4), then per entry
        // hashAlg(2) + digest.
        if auth_end + 4 > cmd.len() {
            return err(RC_SIZE);
        }
        let count = u32::from_be_bytes([
            cmd[auth_end],
            cmd[auth_end + 1],
            cmd[auth_end + 2],
            cmd[auth_end + 3],
        ]);
        let mut p = auth_end + 4;
        let mut st = self.state.lock();
        for _ in 0..count {
            if p + 2 > cmd.len() {
                return err(RC_SIZE);
            }
            let alg = u16::from_be_bytes([cmd[p], cmd[p + 1]]);
            p += 2;
            if alg != narf_tpm::tpm2::TPM_ALG_SHA256 {
                // A bank this model does not implement is answered
                // as an unallocated bank would be.
                return err(RC_VALUE);
            }
            if p + 32 > cmd.len() {
                return err(RC_SIZE);
            }
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&cmd[p..p + 32]);
            p += 32;
            let idx = pcr as usize;
            st.pcrs[idx] = pcr_extend_value(&st.pcrs[idx], &digest);
        }
        st.update_counter += 1;
        drop(st);
        // Sessions success response: header + parameterSize(4) +
        // authorization area (empty nonce, attributes 0, empty
        // HMAC) = 19 bytes.
        let mut out = alloc::vec![0u8; 19];
        out[0..2].copy_from_slice(&narf_tpm::tpm2::TPM_ST_SESSIONS.to_be_bytes());
        out[2..6].copy_from_slice(&19u32.to_be_bytes());
        out[10..14].copy_from_slice(&5u32.to_be_bytes());
        out
    }

    /// TPM2_PCR_Read (Part 3 §22.6) over the SHA-256 bank.
    fn exec_pcr_read(&self, cmd: &[u8]) -> Vec<u8> {
        let err = |rc: u32| -> Vec<u8> {
            let mut out = alloc::vec![0u8; 10];
            out[0..2].copy_from_slice(&narf_tpm::tpm2::TPM_ST_NO_SESSIONS.to_be_bytes());
            out[2..6].copy_from_slice(&10u32.to_be_bytes());
            out[6..10].copy_from_slice(&rc.to_be_bytes());
            out
        };
        if cmd.len() < 14 {
            return err(RC_SIZE);
        }
        let sel_count = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]) as usize;
        let mut pos = 14;
        let st = self.state.lock();
        let mut selections: Vec<(u16, u8, [u8; 3])> = Vec::new();
        let mut digests: Vec<[u8; 32]> = Vec::new();
        for _ in 0..sel_count {
            if pos + 3 > cmd.len() {
                return err(RC_SIZE);
            }
            let alg = u16::from_be_bytes([cmd[pos], cmd[pos + 1]]);
            let size_of_select = cmd[pos + 2] as usize;
            pos += 3;
            if pos + size_of_select > cmd.len() || size_of_select > 3 {
                return err(RC_SIZE);
            }
            if alg != narf_tpm::tpm2::TPM_ALG_SHA256 {
                return err(RC_VALUE);
            }
            let mut mask = [0u8; 3];
            mask[..size_of_select].copy_from_slice(&cmd[pos..pos + size_of_select]);
            pos += size_of_select;
            for byte in 0..3 {
                for bit in 0..8 {
                    if mask[byte] & (1 << bit) != 0 {
                        digests.push(st.pcrs[byte * 8 + bit]);
                    }
                }
            }
            selections.push((alg, size_of_select as u8, mask));
        }
        let mut body = Vec::new();
        body.extend_from_slice(&st.update_counter.to_be_bytes());
        body.extend_from_slice(&(selections.len() as u32).to_be_bytes());
        for (alg, sos, mask) in &selections {
            body.extend_from_slice(&alg.to_be_bytes());
            body.push(*sos);
            body.extend_from_slice(&mask[..*sos as usize]);
        }
        body.extend_from_slice(&(digests.len() as u32).to_be_bytes());
        for d in &digests {
            body.extend_from_slice(d);
        }
        drop(st);
        let mut out = alloc::vec![0u8; 10 + body.len()];
        out[0..2].copy_from_slice(&narf_tpm::tpm2::TPM_ST_NO_SESSIONS.to_be_bytes());
        out[2..6].copy_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        out[10..].copy_from_slice(&body);
        out
    }

    /// The model's TPM_PT property table (Part 2 §6.12–§6.15),
    /// ascending by tag: the fixed group first, then
    /// TPM_PT_PERMANENT from the variable group. The identity is
    /// deliberately legible in fixtures — vendor string pieces
    /// concatenate to "NARF fixture TPM" through the sysfs
    /// `description` attribute.
    fn model_properties() -> &'static [(u32, u32)] {
        use narf_tpm::tpm2::*;
        &[
            (TPM_PT_FAMILY_INDICATOR, 0x322E_3000), // "2.0\0"
            (TPM_PT_LEVEL, 0),
            (TPM_PT_REVISION, 159),
            (TPM_PT_MANUFACTURER, 0x4E41_5246),    // "NARF"
            (TPM_PT_VENDOR_STRING_1, 0x4E41_5246), // "NARF"
            (TPM_PT_VENDOR_STRING_2, 0x2066_6978), // " fix"
            (TPM_PT_VENDOR_STRING_3, 0x7475_7265), // "ture"
            (TPM_PT_VENDOR_STRING_4, 0x2054_504D), // " TPM"
            (TPM_PT_VENDOR_TPM_TYPE, 0),
            (TPM_PT_FIRMWARE_VERSION_1, 0x0001_0000),
            (TPM_PT_FIRMWARE_VERSION_2, 0),
            (TPM_PT_INPUT_BUFFER, 1024),
            (TPM_PT_HR_TRANSIENT_MIN, 3),
            (TPM_PT_PCR_COUNT, 24),
            // TPMA_PERMANENT = 0: no hierarchy auth value is set,
            // dictionary-attack lockout is not engaged.
            (TPM_PT_PERMANENT, 0),
        ]
    }

    /// TPM2_GetCapability (Part 3 §30): no handles, no sessions;
    /// parameters are capability(4) + property(4) +
    /// propertyCount(4). The response mirrors the request tag and
    /// carries moreData(1) + capability(4) + capabilityData.
    fn exec_get_capability(&self, tag: u16, cmd: &[u8]) -> Vec<u8> {
        let err = |rc: u32| -> Vec<u8> {
            let mut out = alloc::vec![0u8; 10];
            out[0..2].copy_from_slice(&narf_tpm::tpm2::TPM_ST_NO_SESSIONS.to_be_bytes());
            out[2..6].copy_from_slice(&10u32.to_be_bytes());
            out[6..10].copy_from_slice(&rc.to_be_bytes());
            out
        };
        if cmd.len() != 22 {
            return err(RC_SIZE);
        }
        let capability = u32::from_be_bytes([cmd[10], cmd[11], cmd[12], cmd[13]]);
        let property = u32::from_be_bytes([cmd[14], cmd[15], cmd[16], cmd[17]]);
        let count = u32::from_be_bytes([cmd[18], cmd[19], cmd[20], cmd[21]]) as usize;

        let mut data = Vec::new();
        let more_data: u8 = match capability {
            x if x == narf_tpm::tpm2::TPM_CAP_TPM_PROPERTIES => {
                // TPML_TAGGED_TPM_PROPERTY, paged by tag: entries
                // at or after `property`, ascending, at most
                // `count` of them; moreData reports whether the
                // table continues past the page.
                let table = Self::model_properties();
                let eligible: Vec<&(u32, u32)> =
                    table.iter().filter(|(t, _)| *t >= property).collect();
                let page = &eligible[..eligible.len().min(count)];
                data.extend_from_slice(&(page.len() as u32).to_be_bytes());
                for (t, v) in page {
                    data.extend_from_slice(&t.to_be_bytes());
                    data.extend_from_slice(&v.to_be_bytes());
                }
                u8::from(eligible.len() > page.len())
            }
            x if x == narf_tpm::tpm2::TPM_CAP_PCRS => {
                // TPML_PCR_SELECTION: the one implemented bank,
                // all 24 PCRs allocated.
                data.extend_from_slice(&1u32.to_be_bytes());
                data.extend_from_slice(&narf_tpm::tpm2::TPM_ALG_SHA256.to_be_bytes());
                data.push(3u8);
                data.extend_from_slice(&[0xFF, 0xFF, 0xFF]);
                0
            }
            x if x == narf_tpm::tpm2::TPM_CAP_ALGS => {
                // TPML_ALG_PROPERTY: SHA-256, TPMA_ALGORITHM.hash
                // (bit 2) — the only algorithm the command core
                // implements.
                data.extend_from_slice(&1u32.to_be_bytes());
                data.extend_from_slice(&narf_tpm::tpm2::TPM_ALG_SHA256.to_be_bytes());
                data.extend_from_slice(&0x0000_0004u32.to_be_bytes());
                0
            }
            x if x == narf_tpm::tpm2::TPM_CAP_COMMANDS => {
                // TPML_CCA: one attribute word per 32 command
                // codes, indexed from TPM_CC_FIRST (0x11F). Four
                // words cover every code the core implements.
                const MODEL_COMMANDS: [u32; 6] = [
                    narf_tpm::tpm2::TPM_CC_STARTUP,
                    narf_tpm::tpm2::TPM_CC_SHUTDOWN,
                    narf_tpm::tpm2::TPM_CC_GET_CAPABILITY,
                    narf_tpm::tpm2::TPM_CC_GET_RANDOM,
                    narf_tpm::tpm2::TPM_CC_PCR_READ,
                    narf_tpm::tpm2::TPM_CC_PCR_EXTEND,
                ];
                let mut words = [0u32; 4];
                for cc in MODEL_COMMANDS {
                    let idx = (cc - 0x0000_011F) as usize;
                    words[idx / 32] |= 1 << (idx % 32);
                }
                data.extend_from_slice(&(words.len() as u32).to_be_bytes());
                for w in words {
                    data.extend_from_slice(&w.to_be_bytes());
                }
                0
            }
            x if x == narf_tpm::tpm2::TPM_CAP_HANDLES => {
                // TPML_HANDLE: the model holds no loaded,
                // persistent, or session handles.
                data.extend_from_slice(&0u32.to_be_bytes());
                0
            }
            _ => return err(RC_VALUE),
        };

        let mut body = Vec::new();
        body.push(more_data);
        body.extend_from_slice(&capability.to_be_bytes());
        body.extend_from_slice(&data);
        let mut out = alloc::vec![0u8; 10 + body.len()];
        out[0..2].copy_from_slice(&tag.to_be_bytes());
        out[2..6].copy_from_slice(&((10 + body.len()) as u32).to_be_bytes());
        out[10..].copy_from_slice(&body);
        out
    }

    // ── CRB front end ────────────────────────────────────────────

    /// Execute the command sitting in the host command buffer and
    /// leave the response in the host response buffer, fetching
    /// both through the addresses the host programmed — the CRB
    /// contract (PTP §6), not through fixture side channels.
    fn crb_execute_from_buffers(&self) {
        let (cmd_pa, cmd_size, rsp_pa, rsp_size) = {
            let st = self.state.lock();
            (
                ((st.get32(tpm::REG_CRB_CMD_HI) as u64) << 32)
                    | st.get32(tpm::REG_CRB_CMD_LO) as u64,
                st.get32(tpm::REG_CRB_CMD_SIZE) as usize,
                ((st.get32(tpm::REG_CRB_RSP_HI) as u64) << 32)
                    | st.get32(tpm::REG_CRB_RSP_LO) as u64,
                st.get32(tpm::REG_CRB_RSP_SIZE) as usize,
            )
        };
        if cmd_pa != self.cmd_mem as u64 || rsp_pa != self.rsp_mem as u64 {
            // The host programmed addresses this device cannot
            // resolve to its attached memory: a real device would
            // fetch from the wrong place and fail. Record it (the
            // fixture asserts this never happens) and answer
            // TPM_RC_FAILURE at the response address if that one
            // at least is ours.
            self.state.lock().bad_buffer_addr = true;
            if rsp_pa == self.rsp_mem as u64 {
                let mut resp = alloc::vec![0u8; 10];
                resp[0..2].copy_from_slice(&narf_tpm::tpm2::TPM_ST_NO_SESSIONS.to_be_bytes());
                resp[2..6].copy_from_slice(&10u32.to_be_bytes());
                resp[6..10].copy_from_slice(&RC_FAILURE.to_be_bytes());
                self.write_rsp(&resp, rsp_size);
            }
            return;
        }
        // The transfer length is the command's own header size,
        // bounded by the programmed buffer size.
        // SAFETY: `cmd_mem` is the fixture-owned buffer attached
        // at construction; reads stay inside the programmed size.
        let cmd = unsafe {
            let avail = cmd_size.min(self.cmd_mem_len);
            if avail < 10 {
                &[][..]
            } else {
                let declared = u32::from_be_bytes([
                    *self.cmd_mem.add(2),
                    *self.cmd_mem.add(3),
                    *self.cmd_mem.add(4),
                    *self.cmd_mem.add(5),
                ]) as usize;
                let n = declared.min(avail);
                core::slice::from_raw_parts(self.cmd_mem, n)
            }
        };
        let resp = self.execute(cmd);
        self.write_rsp(&resp, rsp_size);
    }

    fn write_rsp(&self, resp: &[u8], rsp_size: usize) {
        let n = resp.len().min(rsp_size).min(self.rsp_mem_len);
        // SAFETY: `rsp_mem` is the fixture-owned response buffer;
        // `n` is bounded by both the programmed size and its
        // allocation.
        unsafe {
            core::ptr::copy_nonoverlapping(resp.as_ptr(), self.rsp_mem, n);
        }
    }

    // ── TIS front end ────────────────────────────────────────────

    fn tis_sts(&self, st: &DeviceState) -> u8 {
        let mut s = TIS_STS_VALID;
        if st.tis_cmd_ready {
            s |= TIS_STS_CMD_READY;
            if st.tis_locality && st.tis_tx.is_empty() {
                s |= TIS_STS_EXPECT;
            }
        }
        if st.tis_tx_pos < st.tis_tx.len() {
            s |= TIS_STS_DATA_AVAIL;
        }
        s
    }
}

impl CrbRegs for FakeTpmDevice {
    fn rd32(&self, offset: u64) -> u32 {
        self.state.lock().get32(offset)
    }

    fn wr32(&self, offset: u64, value: u32) {
        let mut go = false;
        {
            let mut st = self.state.lock();
            st.set32(offset, value);
            match offset {
                x if x == tpm::REG_LOC_CTRL => {
                    // Locality grant: LOC_STATE.locAssigned follows
                    // a LOC_CTRL request (PTP §6.5).
                    if value & tpm::LOC_CTRL_REQ_ACCESS != 0 {
                        let cur = st.get32(tpm::REG_LOC_STATE);
                        st.set32(tpm::REG_LOC_STATE, cur | tpm::LOC_STATE_LOC_ASSIGNED);
                    }
                }
                x if x == tpm::REG_CRB_CTRL_REQ => {
                    if value & CRB_CTRL_REQ_CMD_READY != 0 {
                        st.cmd_ready_seen = true;
                        // The TPM leaves idle for command-ready.
                        let cur = st.get32(tpm::REG_CRB_CTRL_STS);
                        st.set32(tpm::REG_CRB_CTRL_STS, cur & !CRB_CTRL_STS_TPM_IDLE);
                    }
                }
                x if x == tpm::REG_CRB_CTRL_START => {
                    if value & CRB_CTRL_START_GO != 0 {
                        st.go_count += 1;
                        go = !self.wedge.load(core::sync::atomic::Ordering::SeqCst);
                    }
                }
                x if x == tpm::REG_CRB_CTRL_CANCEL => {
                    if value & 1 != 0 {
                        st.cancel_seen = true;
                        // The device aborts the in-flight command:
                        // START.GO clears without a response.
                        let cur = st.get32(tpm::REG_CRB_CTRL_START);
                        st.set32(tpm::REG_CRB_CTRL_START, cur & !CRB_CTRL_START_GO);
                    }
                }
                _ => {}
            }
        }
        if go {
            // Execute outside the state lock (execution takes the
            // lock itself), then clear GO — the self-clearing bit
            // is the completion signal the host polls.
            self.crb_execute_from_buffers();
            let mut st = self.state.lock();
            let cur = st.get32(tpm::REG_CRB_CTRL_START);
            st.set32(tpm::REG_CRB_CTRL_START, cur & !CRB_CTRL_START_GO);
        }
    }

    fn rd8(&self, offset: u64) -> u8 {
        let st = self.state.lock();
        if self.tis {
            match offset {
                x if x == tpm::REG_TIS_ACCESS => {
                    let mut v = TIS_ACCESS_VALID;
                    if st.tis_locality {
                        v |= TIS_ACCESS_ACTIVE;
                    }
                    return v;
                }
                x if x == tpm::REG_TIS_STS => return self.tis_sts(&st),
                x if x == tpm::REG_TIS_DATA_FIFO => {
                    // Served by `rd8_fifo`; see below.
                    drop(st);
                    return self.rd8_fifo();
                }
                _ => {}
            }
        }
        st.regs[offset as usize]
    }

    fn wr8(&self, offset: u64, value: u8) {
        let mut execute_tis = false;
        {
            let mut st = self.state.lock();
            if self.tis {
                match offset {
                    x if x == tpm::REG_TIS_ACCESS => {
                        if value & TIS_ACCESS_REQUEST_USE != 0 {
                            st.tis_locality = true;
                        }
                        return;
                    }
                    x if x == tpm::REG_TIS_STS => {
                        if value & TIS_STS_GO != 0 && st.tis_locality {
                            execute_tis = true;
                        }
                        if value & TIS_STS_CMD_READY != 0 {
                            // Host re-arms commandReady for the
                            // next command (and aborts any
                            // partially-written one).
                            st.tis_cmd_ready = true;
                            st.tis_rx.clear();
                        }
                        if execute_tis {
                            st.tis_cmd_ready = false;
                        }
                        // STS bits are device-owned; the write is
                        // not stored into the register file.
                        if !execute_tis {
                            return;
                        }
                    }
                    x if x == tpm::REG_TIS_DATA_FIFO => {
                        // Bytes are accepted only while the TPM is
                        // in commandReady with the locality granted
                        // (TIS §5.6); anything else is dropped by
                        // the device, and counted so the fixture
                        // can see the discipline failed.
                        if st.tis_locality && st.tis_cmd_ready && st.tis_tx.is_empty() {
                            st.tis_rx.push(value);
                        } else {
                            st.dropped_fifo_bytes += 1;
                        }
                        return;
                    }
                    _ => {}
                }
            }
            st.regs[offset as usize] = value;
        }
        if execute_tis {
            let cmd = {
                let mut st = self.state.lock();
                core::mem::take(&mut st.tis_rx)
            };
            let resp = self.execute(&cmd);
            let mut st = self.state.lock();
            st.tis_tx = resp;
            st.tis_tx_pos = 0;
        }
    }
}

impl FakeTpmDevice {
    fn rd8_fifo(&self) -> u8 {
        let mut st = self.state.lock();
        if st.tis_tx_pos < st.tis_tx.len() {
            let b = st.tis_tx[st.tis_tx_pos];
            st.tis_tx_pos += 1;
            b
        } else {
            0
        }
    }
}

// ── Fixtures ───────────────────────────────────────────────────────

fn smoke_tpm_fixture_sha256_fips_vectors() -> TestResult {
    // FIPS 180-4 vectors. This pins the model's copied SHA-256:
    // every PCR assertion below is only as good as this hash.
    let abc = sha256(b"abc");
    let want_abc: [u8; 32] = [
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22,
        0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00,
        0x15, 0xAD,
    ];
    if abc != want_abc {
        return TestResult::Fail("model sha256(\"abc\") != FIPS vector");
    }
    let empty = sha256(b"");
    let want_empty: [u8; 32] = [
        0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9,
        0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52,
        0xB8, 0x55,
    ];
    if empty != want_empty {
        return TestResult::Fail("model sha256(\"\") != FIPS vector");
    }
    // The 56-byte FIPS message — exercises the padding boundary.
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let want: [u8; 32] = [
        0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60,
        0x39, 0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB,
        0x06, 0xC1,
    ];
    if sha256(msg) != want {
        return TestResult::Fail("model sha256(56-byte) != FIPS vector");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-fixture",
    smoke_tpm_fixture_sha256_fips_vectors
);

/// Drive one CRB submit through the production seam against the
/// model, synchronously (the model is self-waking: it completes
/// inside the GO write, so the spin bridge never actually waits —
/// except in the wedge fixture, where the wait is the point).
fn submit_crb_sync(
    dev: &FakeTpmDevice,
    cmd_ptr: *mut u8,
    rsp_ptr: *mut u8,
    cmd: &[u8],
) -> Result<Vec<u8>, tpm::TpmError> {
    narf_scheduler::block_on_spin(tpm::submit_crb_over(dev, cmd_ptr, 4096, rsp_ptr, 4096, cmd))
}

fn smoke_tpm_crb_submit_conversation() -> TestResult {
    use narf_tpm::commands::ResponseParser;
    use narf_tpm::types::TpmRc;

    let mut dev = FakeTpmDevice::crb();
    let mut cmd_mem = alloc::vec![0u8; 4096];
    let mut rsp_mem = alloc::vec![0u8; 4096];
    let cmd_ptr = cmd_mem.as_mut_ptr();
    let rsp_ptr = rsp_mem.as_mut_ptr();
    dev.attach_buffers(cmd_ptr, 4096, rsp_ptr, 4096);

    // Probe core over the model: identify + locality + host
    // buffer programming (the #973 seam, reused as the setup for
    // the submit conversation).
    if tpm::identify(&dev) != Ok(tpm::TpmKind::Crb) {
        return TestResult::Fail("model control area not identified as CRB");
    }
    if tpm::crb_acquire_and_program(
        &dev,
        cmd_ptr as u64,
        4096,
        rsp_ptr as u64,
        4096,
        narf_time::Deadline::after_ms(750),
    )
    .is_err()
    {
        return TestResult::Fail("CRB bring-up failed against the model");
    }

    let d1: [u8; 32] = [0x11; 32];
    let d2: [u8; 32] = [0x22; 32];
    let d3: [u8; 32] = [0x33; 32];

    // (1) A powered-on TPM that has not seen TPM2_Startup rejects
    // the extend with TPM_RC_INITIALIZE — and the rejection must
    // surface through the production response validation, not be
    // swallowed (the pre-#970 transport discarded responses
    // unread).
    let req = tpm::build_pcr_extend_request(4, &d1);
    let resp = match submit_crb_sync(&dev, cmd_ptr, rsp_ptr, &req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("pre-startup extend submit failed at transport"),
    };
    match tpm::validate_pcr_extend_response(&resp) {
        Err(HighLevelTpmError::Rc(TpmRc::Initialize)) => {}
        _ => return TestResult::Fail("pre-startup extend not rejected with TPM_RC_INITIALIZE"),
    }
    if dev.pcr(4) != [0u8; 32] {
        return TestResult::Fail("rejected extend mutated PCR 4");
    }

    // (2) Startup(CLEAR) through the production submit path.
    let startup = narf_tpm::tpm2::startup(narf_tpm::tpm2::TPM_SU_CLEAR);
    let resp = match submit_crb_sync(&dev, cmd_ptr, rsp_ptr, &startup) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("startup submit failed at transport"),
    };
    if ResponseParser::new(&resp).is_err() {
        return TestResult::Fail("startup response not a success frame");
    }

    // (3) The measured-boot extend now lands; validate + read
    // back through PCR_Read, checking the device state both via
    // the wire and directly.
    let req = tpm::build_pcr_extend_request(4, &d1);
    let resp = match submit_crb_sync(&dev, cmd_ptr, rsp_ptr, &req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("extend submit failed at transport"),
    };
    if tpm::validate_pcr_extend_response(&resp).is_err() {
        return TestResult::Fail("post-startup extend response not success");
    }
    let want1 = pcr_extend_value(&[0u8; 32], &d1);
    if dev.pcr(4) != want1 {
        return TestResult::Fail("device PCR 4 != extend(0, d1)");
    }
    let mut mask = [0u8; 3];
    mask[0] = 1 << 4;
    let read_req = narf_tpm::tpm2::pcr_read(narf_tpm::tpm2::TPM_ALG_SHA256, &mask);
    let resp = match submit_crb_sync(&dev, cmd_ptr, rsp_ptr, &read_req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("pcr_read submit failed at transport"),
    };
    let parser = match ResponseParser::new(&resp) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("pcr_read response not a success frame"),
    };
    match parser.parse_pcr_read() {
        Ok(v) if v == want1.to_vec() => {}
        _ => return TestResult::Fail("pcr_read value != device PCR 4"),
    }

    // (4) Extend chain: a second extend to PCR 4 composes over
    // the first; PCR 9 extends independently.
    let req = tpm::build_pcr_extend_request(4, &d2);
    if submit_crb_sync(&dev, cmd_ptr, rsp_ptr, &req).is_err() {
        return TestResult::Fail("second extend submit failed");
    }
    let req = tpm::build_pcr_extend_request(9, &d3);
    if submit_crb_sync(&dev, cmd_ptr, rsp_ptr, &req).is_err() {
        return TestResult::Fail("pcr 9 extend submit failed");
    }
    let want_chain = pcr_extend_value(&want1, &d2);
    if dev.pcr(4) != want_chain {
        return TestResult::Fail("device PCR 4 != extend chain");
    }
    if dev.pcr(9) != pcr_extend_value(&[0u8; 32], &d3) {
        return TestResult::Fail("device PCR 9 != extend(0, d3)");
    }

    // (5) GetRandom round-trips with correct framing.
    let req = narf_tpm::tpm2::get_random(16);
    let resp = match submit_crb_sync(&dev, cmd_ptr, rsp_ptr, &req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("get_random submit failed at transport"),
    };
    let parser = match ResponseParser::new(&resp) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("get_random response not a success frame"),
    };
    match parser.parse_get_random() {
        Ok(v) if v.len() == 16 => {}
        _ => return TestResult::Fail("get_random did not return 16 framed bytes"),
    }

    // (6) Discipline observations: every submit requested
    // CMD_READY first, kicked GO exactly once per command, and
    // the device never saw a buffer address it could not resolve.
    if !dev.cmd_ready_seen() {
        return TestResult::Fail("submit never requested CMD_READY");
    }
    if dev.go_count() != 7 {
        return TestResult::Fail("GO count != number of submitted commands");
    }
    if dev.bad_buffer_addr() {
        return TestResult::Fail("device saw an unresolvable buffer address");
    }
    let _ = (cmd_mem, rsp_mem);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-crb-conversation",
    smoke_tpm_crb_submit_conversation
);

fn smoke_tpm_tis_submit_conversation() -> TestResult {
    use narf_tpm::commands::ResponseParser;

    let dev = FakeTpmDevice::tis();
    if tpm::identify(&dev) != Ok(tpm::TpmKind::Tis) {
        return TestResult::Fail("model register block not identified as TIS");
    }

    // The first-command conversation, end to end over the
    // production TIS path: locality request → FIFO bytes under
    // EXPECT → GO → DATA_AVAIL drain. A powered-on TPM presents
    // commandReady set, so this conversation is well-formed.
    //
    // The conversation deliberately stops at one command. The
    // model enforces the TIS commandReady discipline (TIS
    // v1.21 §5.6; the flow `drivers/tpm/src/tis.rs` documents as
    // step 2 of every command, and Linux's `tpm_tis_ready`
    // implements): the TPM clears commandReady when it takes a
    // command at GO, FIFO writes outside the ready state are
    // dropped, and the host must write STS.commandReady to
    // re-enter the ready state. The production submit path never
    // writes commandReady (audit §2.3 item 5), so from the second
    // command on, its bytes are dropped by a spec-shaped device
    // and the command cannot complete — the multi-command TIS
    // conversation is the lifecycle lane's acceptance test
    // (#942), and this model is ready to serve it unchanged.
    let startup = narf_tpm::tpm2::startup(narf_tpm::tpm2::TPM_SU_CLEAR);
    let resp = match narf_scheduler::block_on_spin(tpm::submit_tis_over(&dev, &startup)) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("TIS startup submit failed at transport"),
    };
    if ResponseParser::new(&resp).is_err() {
        return TestResult::Fail("TIS startup response not a success frame");
    }
    if !dev.is_started() {
        return TestResult::Fail("device did not execute the startup command");
    }

    // Locality discipline held for the whole conversation: the
    // device accepted every FIFO byte (none arrived without the
    // locality granted / commandReady state the model requires).
    if dev.dropped_fifo_bytes() != 0 {
        return TestResult::Fail("device dropped FIFO bytes during the conversation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-tis-conversation",
    smoke_tpm_tis_submit_conversation
);

fn smoke_tpm_crb_submit_wedged_device_cancels() -> TestResult {
    let mut dev = FakeTpmDevice::crb();
    let mut cmd_mem = alloc::vec![0u8; 4096];
    let mut rsp_mem = alloc::vec![0u8; 4096];
    let cmd_ptr = cmd_mem.as_mut_ptr();
    let rsp_ptr = rsp_mem.as_mut_ptr();
    dev.attach_buffers(cmd_ptr, 4096, rsp_ptr, 4096);
    if tpm::crb_acquire_and_program(
        &dev,
        cmd_ptr as u64,
        4096,
        rsp_ptr as u64,
        4096,
        narf_time::Deadline::after_ms(750),
    )
    .is_err()
    {
        return TestResult::Fail("CRB bring-up failed against the model");
    }
    // The device never completes the command: GO stays set. The
    // production poll must run to its 5 s budget, write CANCEL,
    // and report BusyTimeout — not hang the executor, not report
    // success.
    dev.set_wedge(true);
    let startup = narf_tpm::tpm2::startup(narf_tpm::tpm2::TPM_SU_CLEAR);
    match submit_crb_sync(&dev, cmd_ptr, rsp_ptr, &startup) {
        Err(tpm::TpmError::BusyTimeout) => {}
        _ => return TestResult::Fail("wedged device did not produce BusyTimeout"),
    }
    if !dev.cancel_seen() {
        return TestResult::Fail("production submit did not CANCEL the wedged command");
    }
    let _ = (cmd_mem, rsp_mem);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-crb-wedge",
    smoke_tpm_crb_submit_wedged_device_cancels
);

// ── Boot-path composition: discovery → probe → registry → PCR ──────

/// A `TpmDevice` over the model, composed from the same
/// production pieces `Tpm`'s trait implementation composes
/// (canonical frame builders, the register-level submit seam,
/// the production response validation) — the production struct
/// itself cannot be constructed over a register model, because
/// `Tpm::probe` owns an ioremap'd window. What this adapter
/// stands in for is exactly that ownership glue; everything below
/// it (frames, submit discipline, validation) is production code.
struct ModelDevice {
    dev: Arc<FakeTpmDevice>,
    cmd_ptr: *mut u8,
    rsp_ptr: *mut u8,
    /// Which production submit seam `submit_raw` drives: `false`
    /// for CRB (the buffer pointers are live), `true` for TIS (the
    /// pointers are unused — TIS moves bytes through the FIFO
    /// registers, not host buffers).
    tis: bool,
}

// SAFETY: `FakeTpmDevice` is Send + Sync; the buffer pointers
// address fixture-owned memory that outlives the adapter.
unsafe impl Send for ModelDevice {}
unsafe impl Sync for ModelDevice {}

fn map_transport_err(e: tpm::TpmError) -> HighLevelTpmError {
    // The same mapping `Tpm::submit_raw` applies.
    match e {
        tpm::TpmError::NotPresent => HighLevelTpmError::NotPresent,
        tpm::TpmError::LocalityTimeout => HighLevelTpmError::LocalityTimeout,
        tpm::TpmError::BusyTimeout => HighLevelTpmError::BusyTimeout,
        tpm::TpmError::NoCommandBuffer => HighLevelTpmError::NoCommandBuffer,
        tpm::TpmError::BufferAlloc => HighLevelTpmError::HardwareError,
        tpm::TpmError::BadResponse => HighLevelTpmError::BadResponse,
    }
}

#[async_trait]
impl TpmDevice for ModelDevice {
    fn get_info(&self) -> TpmInfo {
        // Mirrors the production transport's unqueried defaults
        // (#941): the adapter does not run the probe-time
        // `query_info` — fixtures that need the live identity call
        // `query_info` on the adapter explicitly.
        TpmInfo {
            manufacturer: 0,
            version: 2,
            spec_level: 159,
        }
    }

    async fn submit_raw(&self, cmd: &[u8]) -> Result<Vec<u8>, HighLevelTpmError> {
        if self.tis {
            return tpm::submit_tis_over(self.dev.as_ref(), cmd)
                .await
                .map_err(map_transport_err);
        }
        tpm::submit_crb_over(
            self.dev.as_ref(),
            self.cmd_ptr,
            4096,
            self.rsp_ptr,
            4096,
            cmd,
        )
        .await
        .map_err(map_transport_err)
    }

    async fn get_random(&self, bytes: u16) -> Result<Vec<u8>, HighLevelTpmError> {
        let req = narf_tpm::tpm2::get_random(bytes);
        let resp = self.submit_raw(&req).await?;
        if resp.len() < 12 {
            return Err(HighLevelTpmError::BadResponse);
        }
        let n = u16::from_be_bytes([resp[10], resp[11]]) as usize;
        if 12 + n > resp.len() {
            return Err(HighLevelTpmError::BadResponse);
        }
        Ok(resp[12..12 + n].to_vec())
    }

    async fn extend_pcr(&self, pcr: u32, digest: &[u8]) -> Result<(), HighLevelTpmError> {
        let req = tpm::build_pcr_extend_request(pcr, digest);
        let resp = self.submit_raw(&req).await?;
        tpm::validate_pcr_extend_response(&resp)
    }

    async fn read_pcr(&self, pcr: u32) -> Result<Vec<u8>, HighLevelTpmError> {
        let mut mask = [0u8; 3];
        if pcr < 24 {
            mask[(pcr / 8) as usize] |= 1 << (pcr % 8);
        }
        let req = narf_tpm::tpm2::pcr_read(narf_tpm::tpm2::TPM_ALG_SHA256, &mask);
        let resp = self.submit_raw(&req).await?;
        if resp.len() < 30 {
            return Err(HighLevelTpmError::BadResponse);
        }
        Ok(resp[resp.len() - 32..].to_vec())
    }
}

fn sdt_checksum(buf: &mut [u8]) {
    buf[9] = 0;
    let sum: u8 = buf.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    buf[9] = 0u8.wrapping_sub(sum);
}

/// A synthetic TPM2 ACPI table (SDT header + platform class,
/// control-area address, start method), per the TCG ACPI spec —
/// the table `discovered_base` reads through `narf_acpi`.
fn build_tpm2_table(control_addr: u64, start_method: u32) -> Vec<u8> {
    let mut t = alloc::vec![0u8; 52];
    t[0..4].copy_from_slice(b"TPM2");
    t[4..8].copy_from_slice(&52u32.to_le_bytes());
    t[8] = 1; // revision
    t[10..16].copy_from_slice(b"NARFCO");
    t[16..24].copy_from_slice(b"NARFTBL_");
    // platform_class (36..38) = 0 (client); reserved (38..40).
    t[40..48].copy_from_slice(&control_addr.to_le_bytes());
    t[48..52].copy_from_slice(&start_method.to_le_bytes());
    sdt_checksum(&mut t);
    t
}

fn build_xsdt(table_phys: u64) -> Vec<u8> {
    let mut x = alloc::vec![0u8; 44];
    x[0..4].copy_from_slice(b"XSDT");
    x[4..8].copy_from_slice(&44u32.to_le_bytes());
    x[8] = 1;
    x[10..16].copy_from_slice(b"NARFCO");
    x[16..24].copy_from_slice(b"NARFTBL_");
    x[36..44].copy_from_slice(&table_phys.to_le_bytes());
    sdt_checksum(&mut x);
    x
}

fn build_rsdp(xsdt_phys: u64) -> [u8; 36] {
    let mut r = [0u8; 36];
    r[0..8].copy_from_slice(b"RSD PTR ");
    r[15] = 2; // revision >= 2 → XSDT
    r[24..32].copy_from_slice(&xsdt_phys.to_le_bytes());
    let sum: u8 = r[..20].iter().fold(0u8, |a, b| a.wrapping_add(*b));
    r[8] = 0u8.wrapping_sub(sum);
    r
}

fn smoke_tpm_discovery_to_registry_conversation() -> TestResult {
    use narf_tpm::types::TpmRc;

    // Hygiene: ACPI TPM2 state and the registry are globals.
    // Reset on entry AND exit so no synthetic control-area
    // address or model device leaks into later fixtures.
    narf_acpi::__reset_tpm2_for_test();
    narf_tpm::registry::__reset_for_test();

    // The address firmware "publishes" for the model device.
    // (A token address: the fixture drives the model itself for
    // the window at that address, the same substitution the
    // probe-core fixtures make.)
    let model_addr: u64 = 0xD000_0000;
    let mut table = build_tpm2_table(model_addr, 7);
    let xsdt = build_xsdt(table.as_ptr() as u64);
    let rsdp = build_rsdp(xsdt.as_ptr() as u64);
    let rsdp_phys = narf_memory::PhysAddr::new(rsdp.as_ptr() as u64);

    let cleanup = |msg: &'static str| -> TestResult {
        narf_acpi::__reset_tpm2_for_test();
        narf_tpm::registry::__reset_for_test();
        TestResult::Fail(msg)
    };

    // Parser → info: the full RSDP → XSDT → TPM2 chain, driven
    // through the production parser (the composition the audit
    // found had no fixture: the parser had a body-decode smoke,
    // the chain and its consumer had none).
    // SAFETY: the chain lives in heap buffers kept alive for the
    // whole fixture; the parser reads through the phys map, the
    // same in-process pattern the acpi crate's own synthetic
    // fixtures use.
    if unsafe { narf_acpi::parse_tpm2(rsdp_phys) }.is_err() {
        return cleanup("synthetic TPM2 chain did not parse");
    }
    match narf_acpi::tpm2_info() {
        Some(info) if info.control_area_addr == model_addr && info.start_method == 7 => {}
        _ => return cleanup("tpm2_info does not reflect the synthetic table"),
    }

    // Discovery decision: start method 7 (CRB) publishes the
    // control area; method 11 (ARM SMC) has no transport in-tree
    // and must NOT be probed as MMIO.
    match tpm::discovered_base() {
        Some(a) if a == model_addr => {}
        _ => return cleanup("discovered_base did not return the table's control area"),
    }
    table[48..52].copy_from_slice(&11u32.to_le_bytes());
    sdt_checksum(&mut table);
    // SAFETY: as above; re-parse overwrites the TPM2 state.
    if unsafe { narf_acpi::parse_tpm2(rsdp_phys) }.is_err() {
        return cleanup("re-parse of the method-11 table failed");
    }
    if tpm::discovered_base().is_some() {
        return cleanup("start method 11 (ARM SMC) was offered as an MMIO base");
    }
    table[48..52].copy_from_slice(&7u32.to_le_bytes());
    sdt_checksum(&mut table);
    // SAFETY: as above.
    if unsafe { narf_acpi::parse_tpm2(rsdp_phys) }.is_err() {
        return cleanup("re-parse of the method-7 table failed");
    }
    if tpm::discovered_base() != Some(model_addr) {
        return cleanup("discovered_base lost the control area after re-parse");
    }

    // Probe core at the discovered base (the model stands in for
    // the window there), then the composition `try_init_default`
    // performs on success: register the device.
    let mut dev = FakeTpmDevice::crb();
    let mut cmd_mem = alloc::vec![0u8; 4096];
    let mut rsp_mem = alloc::vec![0u8; 4096];
    let cmd_ptr = cmd_mem.as_mut_ptr();
    let rsp_ptr = rsp_mem.as_mut_ptr();
    dev.attach_buffers(cmd_ptr, 4096, rsp_ptr, 4096);
    let dev = Arc::new(dev);
    if tpm::identify(dev.as_ref()) != Ok(tpm::TpmKind::Crb) {
        return cleanup("device at the discovered base not identified as CRB");
    }
    if tpm::crb_acquire_and_program(
        dev.as_ref(),
        cmd_ptr as u64,
        4096,
        rsp_ptr as u64,
        4096,
        narf_time::Deadline::after_ms(750),
    )
    .is_err()
    {
        return cleanup("CRB bring-up failed at the discovered base");
    }
    let adapter = Arc::new(ModelDevice {
        dev: dev.clone(),
        cmd_ptr,
        rsp_ptr,
        tis: false,
    });
    narf_tpm::registry::register(adapter.clone());
    if narf_tpm::registry::list().len() != 1 {
        return cleanup("registered device not visible in the registry");
    }

    // The measured-boot conversation, dispatched through the
    // registry exactly as `frame::measure` dispatches it
    // (registry::list().first() → extend_pcr):
    //   1. an extend before Startup is rejected TPM_RC_INITIALIZE
    //      and the rejection propagates to the caller;
    //   2. Startup through the registered device's raw path;
    //   3. the extend lands — PCR state advances by the formula;
    //   4. read-back through the registry handle matches.
    let digest: [u8; 32] = [0x42; 32];
    let stages = Arc::new(IrqSafeSpinLock::new([false; 4]));
    let stages_in = stages.clone();
    narf_scheduler::__reset_queues_for_test();
    narf_scheduler::spawn(async move {
        let mut s = [false; 4];
        let handle = narf_tpm::registry::list().first().cloned();
        if let Some(dev) = handle {
            s[0] = matches!(
                dev.extend_pcr(4, &digest).await,
                Err(HighLevelTpmError::Rc(TpmRc::Initialize))
            );
            let startup = narf_tpm::tpm2::startup(narf_tpm::tpm2::TPM_SU_CLEAR);
            s[1] = matches!(dev.submit_raw(&startup).await, Ok(resp) if resp.len() == 10);
            s[2] = dev.extend_pcr(4, &digest).await.is_ok();
            let want = pcr_extend_value(&[0u8; 32], &digest);
            s[3] = matches!(dev.read_pcr(4).await, Ok(v) if v == want.to_vec());
        }
        *stages_in.lock() = s;
    });
    narf_scheduler::run_until_empty();
    let stages = *stages.lock();
    let pcr_ok = dev.pcr(4) == pcr_extend_value(&[0u8; 32], &digest);
    narf_acpi::__reset_tpm2_for_test();
    narf_tpm::registry::__reset_for_test();
    let _ = (table, xsdt, rsdp, cmd_mem, rsp_mem);
    if stages != [true; 4] {
        return TestResult::Fail("boot conversation stage failed (see stage order in source)");
    }
    if !pcr_ok {
        return TestResult::Fail("device PCR 4 != extend(0, digest) after the conversation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-discovery",
    smoke_tpm_discovery_to_registry_conversation
);

// ── Lifecycle lane (#942): commandReady + probe→Startup→extend ────

fn smoke_tpm_tis_multi_command_conversation() -> TestResult {
    use narf_tpm::types::TpmRc;

    let dev = Arc::new(FakeTpmDevice::tis());
    if tpm::identify(dev.as_ref()) != Ok(tpm::TpmKind::Tis) {
        return TestResult::Fail("model register block not identified as TIS");
    }
    // The multi-command TIS conversation the keystone deferred,
    // run through the trait over the production TIS submit path.
    // Commands after the first are the acceptance test for the
    // commandReady assertion in `submit_tis_over`: the model
    // enforces the spec discipline (clears commandReady at GO,
    // drops FIFO bytes written outside the ready state), so a
    // missing re-assertion surfaces as dropped bytes and a stuck
    // command — TPM_RC_SIZE from executing an empty FIFO —
    // exactly as on spec-shaped silicon.
    let adapter: Arc<dyn TpmDevice> = Arc::new(ModelDevice {
        dev: dev.clone(),
        cmd_ptr: core::ptr::null_mut(),
        rsp_ptr: core::ptr::null_mut(),
        tis: true,
    });
    let digest1: [u8; 32] = [0x11; 32];
    let digest2: [u8; 32] = [0x22; 32];
    let stages = Arc::new(IrqSafeSpinLock::new([false; 6]));
    let stages_in = stages.clone();
    narf_scheduler::__reset_queues_for_test();
    narf_scheduler::spawn(async move {
        let mut s = [false; 6];
        // 1. Pre-Startup extend is rejected TPM_RC_INITIALIZE.
        s[0] = matches!(
            adapter.extend_pcr(4, &digest1).await,
            Err(HighLevelTpmError::Rc(TpmRc::Initialize))
        );
        // 2. The trait's lifecycle call starts the device.
        s[1] = adapter.startup(narf_tpm::StartupType::Clear).await.is_ok();
        // 3. A second Startup(CLEAR) — the call the production
        //    probe submits on a firmware-started machine — is
        //    folded to success by the already-started policy.
        s[2] = adapter.startup(narf_tpm::StartupType::Clear).await.is_ok();
        // 4. The extend lands; the device chain advances.
        s[3] = adapter.extend_pcr(4, &digest1).await.is_ok();
        // 5. Read-back matches the chain so far.
        let after1 = pcr_extend_value(&[0u8; 32], &digest1);
        s[4] = matches!(adapter.read_pcr(4).await, Ok(v) if v == after1.to_vec());
        // 6. A further extend composes the chain across the whole
        //    conversation (seven submits in total).
        s[5] = adapter.extend_pcr(4, &digest2).await.is_ok();
        *stages_in.lock() = s;
    });
    narf_scheduler::run_until_empty();
    let stages = *stages.lock();
    if stages != [true; 6] {
        return TestResult::Fail("multi-command TIS stage failed (see stage order in source)");
    }
    let after1 = pcr_extend_value(&[0u8; 32], &digest1);
    if dev.pcr(4) != pcr_extend_value(&after1, &digest2) {
        return TestResult::Fail("device PCR 4 chain does not match the conversation");
    }
    // The discipline held for every command: no FIFO byte was
    // dropped anywhere in the conversation.
    if dev.dropped_fifo_bytes() != 0 {
        return TestResult::Fail("device dropped FIFO bytes — commandReady discipline missing");
    }
    if !dev.is_started() {
        return TestResult::Fail("device not started after the conversation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-tis-multi",
    smoke_tpm_tis_multi_command_conversation
);

fn smoke_tpm_probe_startup_extend_conversation() -> TestResult {
    use narf_tpm::types::TpmRc;

    // The boot-path lifecycle conversation: the composition
    // `try_init_default` performs on real silicon — device,
    // registry publication, registry dispatch — with the
    // lifecycle edge this lane adds: the registered handle is
    // started through the trait's `startup`, the call the
    // production probe now makes between probe and registration,
    // before the first extend is dispatched. The keystone's
    // discovery fixture covers the same composition with Startup
    // submitted as a hand-built raw frame; this one pins the
    // trait surface production actually uses.
    let mut dev = FakeTpmDevice::crb();
    let mut cmd_mem = alloc::vec![0u8; 4096];
    let mut rsp_mem = alloc::vec![0u8; 4096];
    let cmd_ptr = cmd_mem.as_mut_ptr();
    let rsp_ptr = rsp_mem.as_mut_ptr();
    dev.attach_buffers(cmd_ptr, 4096, rsp_ptr, 4096);
    let dev = Arc::new(dev);
    if tpm::crb_acquire_and_program(
        dev.as_ref(),
        cmd_ptr as u64,
        4096,
        rsp_ptr as u64,
        4096,
        narf_time::Deadline::after_ms(750),
    )
    .is_err()
    {
        return TestResult::Fail("CRB bring-up failed against the model");
    }
    narf_tpm::registry::__reset_for_test();
    let adapter: Arc<dyn TpmDevice> = Arc::new(ModelDevice {
        dev: dev.clone(),
        cmd_ptr,
        rsp_ptr,
        tis: false,
    });
    narf_tpm::registry::register(adapter);
    let digest: [u8; 32] = [0x5A; 32];
    let stages = Arc::new(IrqSafeSpinLock::new([false; 4]));
    let stages_in = stages.clone();
    narf_scheduler::__reset_queues_for_test();
    narf_scheduler::spawn(async move {
        let mut s = [false; 4];
        if let Some(handle) = narf_tpm::registry::list().first().cloned() {
            // 1. Before Startup, the registry dispatch is
            //    rejected exactly as `frame::measure` observes it.
            s[0] = matches!(
                handle.extend_pcr(4, &digest).await,
                Err(HighLevelTpmError::Rc(TpmRc::Initialize))
            );
            // 2. The lifecycle call.
            s[1] = handle.startup(narf_tpm::StartupType::Clear).await.is_ok();
            // 3. The extend now lands.
            s[2] = handle.extend_pcr(4, &digest).await.is_ok();
            // 4. Read-back through the registry handle matches the
            //    device-side chain.
            let want = pcr_extend_value(&[0u8; 32], &digest);
            s[3] = matches!(handle.read_pcr(4).await, Ok(v) if v == want.to_vec());
        }
        *stages_in.lock() = s;
    });
    narf_scheduler::run_until_empty();
    let stages = *stages.lock();
    let started = dev.is_started();
    let pcr_ok = dev.pcr(4) == pcr_extend_value(&[0u8; 32], &digest);
    narf_tpm::registry::__reset_for_test();
    let _ = (cmd_mem, rsp_mem);
    if stages != [true; 4] {
        return TestResult::Fail("probe/startup/extend stage failed (see stage order in source)");
    }
    if !started || !pcr_ok {
        return TestResult::Fail("device state does not reflect the conversation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-startup",
    smoke_tpm_probe_startup_extend_conversation
);

// ── Userspace publication (#940): devfs + sysfs over the model ────

/// #941: TPM2_GetCapability against the model — the command the
/// keystone deliberately left unimplemented until the command-set
/// lane grew it. The conversation runs over the CRB register
/// front end through the production submit seam: the trait's
/// `query_info` maps the model's property page, and the raw
/// capability pages (PCRS / ALGS / COMMANDS / HANDLES, paging,
/// unknown-capability rejection) are checked against the
/// canonical parsers and the model's documented identity.
fn smoke_tpm_getcapability_conversation() -> TestResult {
    use narf_tpm::commands::ResponseParser;
    use narf_tpm::types::TpmRc;

    let mut dev = FakeTpmDevice::crb();
    let mut cmd_mem = alloc::vec![0u8; 4096];
    let mut rsp_mem = alloc::vec![0u8; 4096];
    let cmd_ptr = cmd_mem.as_mut_ptr();
    let rsp_ptr = rsp_mem.as_mut_ptr();
    dev.attach_buffers(cmd_ptr, 4096, rsp_ptr, 4096);
    let dev = Arc::new(dev);
    if tpm::crb_acquire_and_program(
        dev.as_ref(),
        cmd_ptr as u64,
        4096,
        rsp_ptr as u64,
        4096,
        narf_time::Deadline::after_ms(750),
    )
    .is_err()
    {
        return TestResult::Fail("CRB bring-up failed against the model");
    }
    let adapter: Arc<dyn TpmDevice> = Arc::new(ModelDevice {
        dev: dev.clone(),
        cmd_ptr,
        rsp_ptr,
        tis: false,
    });
    let submit = |req: &[u8]| submit_crb_sync(dev.as_ref(), cmd_ptr, rsp_ptr, req);

    // (1) Before Startup the model rejects GetCapability with
    // TPM_RC_INITIALIZE, like every other command.
    let req = narf_tpm::tpm2::get_capability(
        narf_tpm::tpm2::TPM_CAP_TPM_PROPERTIES,
        narf_tpm::tpm2::TPM_PT_FAMILY_INDICATOR,
        64,
    );
    let resp = match submit(&req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("pre-startup GetCapability submit failed at transport"),
    };
    match ResponseParser::new(&resp) {
        Err(HighLevelTpmError::Rc(TpmRc::Initialize)) => {}
        _ => return TestResult::Fail("pre-startup GetCapability not rejected with INITIALIZE"),
    }

    if narf_scheduler::block_on_spin(adapter.startup(narf_tpm::StartupType::Clear)).is_err() {
        return TestResult::Fail("Startup(CLEAR) failed against the model");
    }

    // (2) The trait's query_info maps the model's property page.
    match narf_scheduler::block_on_spin(adapter.query_info()) {
        Ok(info)
            if info.manufacturer == 0x4E41_5246
                && info.version == 0x0001_0000
                && info.spec_level == 159 => {}
        _ => return TestResult::Fail("query_info did not map the model's identity"),
    }

    // (3) PCRS: the one implemented bank, all 24 PCRs, parsed by
    // the canonical selection parser.
    let req = narf_tpm::tpm2::get_capability(narf_tpm::tpm2::TPM_CAP_PCRS, 0, 1);
    let resp = match submit(&req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("GetCapability(PCRS) submit failed at transport"),
    };
    let parser = match ResponseParser::new(&resp) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("GetCapability(PCRS) response not a success frame"),
    };
    match parser.parse_get_capability_pcr_selections() {
        Ok((false, sels))
            if sels.len() == 1
                && sels[0].0 == narf_tpm::tpm2::TPM_ALG_SHA256
                && sels[0].1 == alloc::vec![0xFF, 0xFF, 0xFF] => {}
        _ => return TestResult::Fail("PCRS page != one SHA-256 bank with all PCRs"),
    }

    // (4) ALGS: SHA-256 only, TPMA_ALGORITHM.hash set. (No
    // canonical parser for this page yet — raw body walk.)
    let req = narf_tpm::tpm2::get_capability(narf_tpm::tpm2::TPM_CAP_ALGS, 0, 1);
    let resp = match submit(&req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("GetCapability(ALGS) submit failed at transport"),
    };
    let body = match ResponseParser::new(&resp) {
        Ok(p) => p.body().to_vec(),
        Err(_) => return TestResult::Fail("GetCapability(ALGS) response not a success frame"),
    };
    // moreData(1) + cap(4) + count(4) + alg(2) + properties(4)
    if body.len() != 15
        || body[0] != 0
        || u32::from_be_bytes([body[5], body[6], body[7], body[8]]) != 1
        || u16::from_be_bytes([body[9], body[10]]) != narf_tpm::tpm2::TPM_ALG_SHA256
        || u32::from_be_bytes([body[11], body[12], body[13], body[14]]) != 0x0000_0004
    {
        return TestResult::Fail("ALGS page != SHA-256 with the hash attribute");
    }

    // (5) COMMANDS: the TPML_CCA bitmap names exactly the six
    // commands the model's core implements.
    let req = narf_tpm::tpm2::get_capability(narf_tpm::tpm2::TPM_CAP_COMMANDS, 0, 0);
    let resp = match submit(&req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("GetCapability(COMMANDS) submit failed at transport"),
    };
    let body = match ResponseParser::new(&resp) {
        Ok(p) => p.body().to_vec(),
        Err(_) => return TestResult::Fail("GetCapability(COMMANDS) response not a success frame"),
    };
    if body.len() < 9 {
        return TestResult::Fail("COMMANDS page truncated");
    }
    let words = u32::from_be_bytes([body[5], body[6], body[7], body[8]]) as usize;
    if body.len() != 9 + words * 4 {
        return TestResult::Fail("COMMANDS page length disagrees with its word count");
    }
    let has = |cc: u32| -> bool {
        let idx = (cc - 0x0000_011F) as usize;
        let word = u32::from_be_bytes([
            body[9 + (idx / 32) * 4],
            body[10 + (idx / 32) * 4],
            body[11 + (idx / 32) * 4],
            body[12 + (idx / 32) * 4],
        ]);
        word & (1 << (idx % 32)) != 0
    };
    for cc in [
        narf_tpm::tpm2::TPM_CC_STARTUP,
        narf_tpm::tpm2::TPM_CC_SHUTDOWN,
        narf_tpm::tpm2::TPM_CC_GET_CAPABILITY,
        narf_tpm::tpm2::TPM_CC_GET_RANDOM,
        narf_tpm::tpm2::TPM_CC_PCR_READ,
        narf_tpm::tpm2::TPM_CC_PCR_EXTEND,
    ] {
        if !has(cc) {
            return TestResult::Fail("COMMANDS bitmap missing an implemented command");
        }
    }
    if has(0x0000_0153) {
        // TPM_CC_Create — the model does not implement it.
        return TestResult::Fail("COMMANDS bitmap claims TPM_CC_Create");
    }

    // (6) HANDLES: the model holds none.
    let req = narf_tpm::tpm2::get_capability(narf_tpm::tpm2::TPM_CAP_HANDLES, 0, 0);
    let resp = match submit(&req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("GetCapability(HANDLES) submit failed at transport"),
    };
    let body = match ResponseParser::new(&resp) {
        Ok(p) => p.body().to_vec(),
        Err(_) => return TestResult::Fail("GetCapability(HANDLES) response not a success frame"),
    };
    if body.len() != 9 || u32::from_be_bytes([body[5], body[6], body[7], body[8]]) != 0 {
        return TestResult::Fail("HANDLES page not empty");
    }

    // (7) Property paging: a two-entry page from the first tag
    // reports moreData; continuing from the next tag drains the
    // table (ending at TPM_PT_PERMANENT in the variable group).
    let req = narf_tpm::tpm2::get_capability(
        narf_tpm::tpm2::TPM_CAP_TPM_PROPERTIES,
        narf_tpm::tpm2::TPM_PT_FAMILY_INDICATOR,
        2,
    );
    let resp = match submit(&req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("GetCapability paging submit failed at transport"),
    };
    let parser = match ResponseParser::new(&resp) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("GetCapability paging response not a success frame"),
    };
    let next_tag = match parser.parse_get_capability_properties() {
        Ok((true, entries)) if entries.len() == 2 => entries[1].0 + 1,
        _ => return TestResult::Fail("first property page != 2 entries with moreData"),
    };
    let req = narf_tpm::tpm2::get_capability(narf_tpm::tpm2::TPM_CAP_TPM_PROPERTIES, next_tag, 64);
    let resp = match submit(&req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("GetCapability page-2 submit failed at transport"),
    };
    let parser = match ResponseParser::new(&resp) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("GetCapability page-2 response not a success frame"),
    };
    match parser.parse_get_capability_properties() {
        Ok((false, entries))
            if entries.last().map(|(t, _)| *t) == Some(narf_tpm::tpm2::TPM_PT_PERMANENT) => {}
        _ => return TestResult::Fail("second property page does not drain at TPM_PT_PERMANENT"),
    }

    // (8) An unknown capability is TPM_RC_VALUE, not a framed lie.
    let req = narf_tpm::tpm2::get_capability(0xFFFF_FFFF, 0, 1);
    let resp = match submit(&req) {
        Ok(r) => r,
        Err(_) => return TestResult::Fail("GetCapability(unknown) submit failed at transport"),
    };
    match ResponseParser::new(&resp) {
        Err(HighLevelTpmError::Rc(TpmRc::Value)) => {}
        _ => return TestResult::Fail("unknown capability not rejected with TPM_RC_VALUE"),
    }

    let _ = (cmd_mem, rsp_mem);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/platform/tpm-getcapability",
    smoke_tpm_getcapability_conversation
);

/// Fixture-cleanup transport: installed into the sysfs bridge on
/// fixture exit so the class attributes the publication registered
/// stop pointing at this fixture's model device (whose command
/// buffers are fixture-owned memory). Mirrors the hygiene the
/// `drivers/tpm` sysfs fixtures apply with their mock transports.
struct DeadTransport;

impl narf_drivers_tpm::devfs_bridge::TpmTransport for DeadTransport {
    fn submit(&self, _cmd: &[u8]) -> Result<Vec<u8>, ()> {
        Err(())
    }
}

fn smoke_tpm_userspace_publication_conversation() -> TestResult {
    use narf_filesystem::{DirOps, FileOps, FsInstance};

    // Hygiene in AND out: the registry, the bridge transport slot
    // and the devfs delegates are globals. The sysfs class is
    // boot-lifetime by design (production registers it once and
    // never removes it); on exit the fixture re-points its
    // attributes at `DeadTransport`, the same end-state the
    // `drivers/tpm` sysfs fixtures leave behind.
    let teardown = || {
        narf_drivers_tpm::devfs_bridge::unregister_dev_nodes();
        narf_drivers_tpm::devfs_bridge::unregister_transport();
        narf_drivers_tpm::sysfs_bridge::register_sysfs_tpm0(
            Arc::new(DeadTransport) as Arc<dyn narf_drivers_tpm::devfs_bridge::TpmTransport>
        );
        narf_tpm::registry::__reset_for_test();
    };
    teardown();

    // The composition `try_init_default` performs on real silicon,
    // over the model: bring the device up, start it, register it,
    // publish it. The production struct cannot be constructed over
    // a register model (`Tpm::probe` owns an ioremap'd window), so
    // the `ModelDevice` adapter stands in for that ownership glue —
    // the same substitution the #946/#942 fixtures make; everything
    // below the adapter is production code, including the
    // publication function itself.
    let mut dev = FakeTpmDevice::crb();
    let mut cmd_mem = alloc::vec![0u8; 4096];
    let mut rsp_mem = alloc::vec![0u8; 4096];
    let cmd_ptr = cmd_mem.as_mut_ptr();
    let rsp_ptr = rsp_mem.as_mut_ptr();
    dev.attach_buffers(cmd_ptr, 4096, rsp_ptr, 4096);
    let dev = Arc::new(dev);

    let run = || -> Result<(), &'static str> {
        if tpm::crb_acquire_and_program(
            dev.as_ref(),
            cmd_ptr as u64,
            4096,
            rsp_ptr as u64,
            4096,
            narf_time::Deadline::after_ms(750),
        )
        .is_err()
        {
            return Err("CRB bring-up failed against the model");
        }
        let adapter: Arc<dyn TpmDevice> = Arc::new(ModelDevice {
            dev: dev.clone(),
            cmd_ptr,
            rsp_ptr,
            tis: false,
        });
        // The production order: Startup, registry, publication.
        // `block_on_spin` from the fixture body is the same bridge
        // the Stage::Subsys initcall uses (not an executor poll;
        // the submit futures are self-waking register polls).
        if narf_scheduler::block_on_spin(adapter.startup(narf_tpm::StartupType::Clear)).is_err() {
            return Err("Startup(CLEAR) failed against the model");
        }
        narf_tpm::registry::register(adapter.clone());
        if narf_tpm::registry::list().len() != 1 {
            return Err("registered device not visible in the registry");
        }

        // Before publication the devfs nodes do not exist (the
        // entries' visibility is the delegate slot).
        let dev_root = narf_filesystem::devfs::DevFs::new().root();
        if dev_root.lookup("tpm0").is_some() || dev_root.lookup("tpmrm0").is_some() {
            return Err("TPM devfs nodes visible before publication");
        }

        tpm::publish_userspace_surface(adapter.clone());

        let node = dev_root
            .lookup("tpm0")
            .ok_or("/dev/tpm0 missing after publication")?;
        if dev_root.lookup("tpmrm0").is_none() {
            return Err("/dev/tpmrm0 missing after publication");
        }

        // Open both nodes the way `sys_open` does: the looked-up
        // node is the prototype; the fd is its per-open clone.
        let open = |node: &Arc<dyn FileOps>| -> Result<Arc<dyn FileOps>, &'static str> {
            match node.open_instance_checked(false) {
                Ok(Some(instance)) => Ok(instance),
                Ok(None) => Ok(node.clone()),
                Err(_) => Err("open_instance_checked errored on the TPM node"),
            }
        };
        let fd_a = open(&node)?;
        let fd_b = open(&node)?;
        if Arc::ptr_eq(&fd_a, &fd_b) {
            return Err("two opens of /dev/tpm0 share one instance (per-fd state broken)");
        }

        // Command round-trip through the published node:
        // TPM2_GetRandom(8) against the model, via the production
        // transport (registry device → register-level submit).
        let cmd = narf_tpm::tpm2::get_random(8);
        match narf_scheduler::block_on(fd_a.write(0, &cmd)) {
            Ok(n) if n == cmd.len() => {}
            _ => return Err("GetRandom write through /dev/tpm0 failed"),
        }
        let mut resp = [0u8; 64];
        let n = match narf_scheduler::block_on(fd_a.read(0, &mut resp)) {
            Ok(n) => n,
            Err(_) => return Err("GetRandom read through /dev/tpm0 failed"),
        };
        if n != 20 || resp[6..10] != [0, 0, 0, 0] || resp[10..12] != [0, 8] {
            return Err("GetRandom response through /dev/tpm0 malformed");
        }
        // The second fd has no pending response of its own: its
        // read is EOF, not fd A's response.
        let mut other = [0u8; 64];
        match narf_scheduler::block_on(fd_b.read(0, &mut other)) {
            Ok(0) => {}
            _ => return Err("second /dev/tpm0 fd observed the first fd's response"),
        }

        // A PCR extend through the published node lands on the
        // device (production frame builder, production transport).
        let digest: [u8; 32] = [0x77; 32];
        let ext = tpm::build_pcr_extend_request(4, &digest);
        match narf_scheduler::block_on(fd_a.write(0, &ext)) {
            Ok(n) if n == ext.len() => {}
            _ => return Err("PCR_Extend write through /dev/tpm0 failed"),
        }
        let mut rsp = [0u8; 16];
        match narf_scheduler::block_on(fd_a.read(0, &mut rsp)) {
            Ok(10) if rsp[6..10] == [0, 0, 0, 0] => {}
            _ => return Err("PCR_Extend response through /dev/tpm0 malformed"),
        }
        let want_pcr = pcr_extend_value(&[0u8; 32], &digest);
        if dev.pcr(4) != want_pcr {
            return Err("device PCR 4 does not reflect the /dev/tpm0 extend");
        }

        // The RM node is live too: a GetRandom round-trip through
        // its own per-open instance.
        let rm_node = dev_root
            .lookup("tpmrm0")
            .ok_or("/dev/tpmrm0 vanished after publication")?;
        let fd_rm = open(&rm_node)?;
        match narf_scheduler::block_on(fd_rm.write(0, &cmd)) {
            Ok(n) if n == cmd.len() => {}
            _ => return Err("GetRandom write through /dev/tpmrm0 failed"),
        }
        let mut rm_resp = [0u8; 64];
        match narf_scheduler::block_on(fd_rm.read(0, &mut rm_resp)) {
            Ok(20) if rm_resp[6..10] == [0, 0, 0, 0] => {}
            _ => return Err("GetRandom response through /dev/tpmrm0 malformed"),
        }

        // The sysfs surface: navigate the published class tree
        // (not the registration API — presence is the assertion).
        let sysfs = narf_filesystem::sysfs::sysfs_root();
        let tpm0 = sysfs
            .get_child("class")
            .and_then(|c| c.get_child("tpm"))
            .and_then(|c| c.get_child("tpm0"))
            .ok_or("/sys/class/tpm/tpm0 missing after publication")?;
        if tpm0.attr_show("tpm_version_major").as_deref() != Some("2\n") {
            return Err("tpm_version_major != '2\\n' on the published class");
        }
        // `pcrs` reads back the extend through the published
        // surface: PCR 4's SHA-256 bank shows the chain value, in
        // the bridge's uppercase space-separated format. (The
        // SHA-1 bank is not implemented by the model, so its field
        // is the bridge's "??" — not asserted.)
        let pcrs = tpm0
            .attr_show("pcrs")
            .ok_or("pcrs attribute missing on the published class")?;
        let mut want_hex = alloc::string::String::new();
        for (i, b) in want_pcr.iter().enumerate() {
            if i > 0 {
                want_hex.push(' ');
            }
            want_hex.push_str(&alloc::format!("{b:02X}"));
        }
        if !pcrs.contains("PCR-04:") || !pcrs.contains(&want_hex) {
            return Err("pcrs does not show the /dev/tpm0 extend on PCR 4");
        }
        // `owned` is live since #941: the model serves
        // TPM_PT_PERMANENT = 0 (no hierarchy auth is set), so the
        // attribute reads a real property value. (Before #941 the
        // model did not implement GetCapability and this assertion
        // pinned the bridge's failure default instead; the bit
        // semantics over nonzero values are pinned separately by
        // the drivers/tpm fixture against a crafted response.)
        if tpm0.attr_show("owned").as_deref() != Some("0\n") {
            return Err("owned != '0\\n' against the model");
        }
        // The remaining GetCapability-backed attributes read the
        // model's identity live through the published surface:
        // manufacturer "NARF", vendor string "NARF fixture TPM",
        // spec revision 159 → "1.59".
        if tpm0.attr_show("manufacturer").as_deref() != Some("NARF\n") {
            return Err("manufacturer does not read the model's identity");
        }
        if tpm0.attr_show("description").as_deref() != Some("NARF fixture TPM\n") {
            return Err("description does not concatenate the model's vendor strings");
        }
        match tpm0.attr_show("caps") {
            Some(caps)
                if caps.contains("manufacturer: NARF") && caps.contains("revision: 1.59") => {}
            _ => return Err("caps does not report the model's identity"),
        }
        Ok(())
    };

    let result = run();
    teardown();
    let _ = (cmd_mem, rsp_mem);
    match result {
        Ok(()) => TestResult::Pass,
        Err(msg) => TestResult::Fail(msg),
    }
}
kernel_test_in!(
    "drivers/platform/tpm-publication",
    smoke_tpm_userspace_publication_conversation
);
