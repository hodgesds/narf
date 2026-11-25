//! Native HDCP fixtures (`drivers/gpu/intel_hdcp`).
//!
//! Every expected value is laid out by hand from the Linux sources
//! (`intel_hdcp_regs.h`, `drm_hdcp.h`, `drm_dp.h`,
//! `i915_hdcp_interface.h`, `intel_gsc_mtl_header`) or derived step by
//! step from `intel_hdcp_validate_v_prime`; none is recorded from the code
//! under test. The models: a transcoder HDCP register block (key load, An,
//! R0/Ri match, the SHA-1 text engine, HDCP 2.2 link status), a scripted
//! DP sink (DPCD 0x68000 / 0x69000), a scripted HDMI sink (DDC 0x3A), an
//! MEI-client model of the HDCP firmware that checks every
//! `wired_cmd_*_in` and answers with its `_out`, and a GSC model that
//! checks the `intel_gsc_mtl_header` framing around the same commands.

extern crate alloc;

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::mst;
use super::*;
use crate::intel_hdcp_live as live;
use crate::intel_hdcp_msg::{self as msg, GscFraming, GscPacketPort, HdcpPortData};
use crate::intel_hdcp_shim::{self as shim, Ddc, DpShim, Dpcd, HdmiShim};

// ── Driving ──────────────────────────────────────────────────────────

fn noop_waker() -> Waker {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(|_| RAW, |_| {}, |_| {}, |_| {});
    const RAW: RawWaker = RawWaker::new(core::ptr::null(), &VTABLE);
    // SAFETY: every vtable entry ignores the null data pointer.
    unsafe { Waker::from_raw(RAW) }
}

/// Run `f` to completion: every model answers at once and every delay is
/// virtual, so a few polls always finish it.
fn drive<F: Future>(f: F) -> Option<F::Output> {
    let mut f = core::pin::pin!(f);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    for _ in 0..64 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return Some(v);
        }
    }
    None
}

// ── The transcoder register model ────────────────────────────────────

#[derive(Debug, Default)]
struct RegState {
    regs: BTreeMap<u64, u32>,
    t: u8,
    an: [u32; 2],
    /// The R0 / Ri the "hardware" computed.
    r0: u16,
    key_fails: bool,
    sha: Vec<(u32, u32)>,
    expect_sha: Vec<(u32, u32)>,
    expect_v: [u32; 5],
    sha_done: bool,
    writes: Vec<(u64, u32)>,
    /// An MST stream transcoder whose encryption never confirms.
    stuck_stream: Option<u8>,
}

struct Regs(IrqSafeSpinLock<RegState>);

impl Regs {
    fn new(t: u8) -> Self {
        let r = Self(IrqSafeSpinLock::new(RegState::default()));
        {
            let mut s = r.0.lock();
            s.t = t;
            s.an = [0x0403_0201, 0x0807_0605];
            s.r0 = 0x1234;
            s.regs.insert(HSW_PWR_WELL_CTL2, 0b11);
        }
        r
    }
    fn get(&self, off: u64) -> u32 {
        *self.0.lock().regs.get(&off).unwrap_or(&0)
    }
    fn set_bits(&self, off: u64, bits: u32) {
        *self.0.lock().regs.entry(off).or_insert(0) |= bits;
    }
    fn clear_bits(&self, off: u64, bits: u32) {
        *self.0.lock().regs.entry(off).or_insert(0) &= !bits;
    }
    fn wrote(&self, off: u64) -> Vec<u32> {
        self.0
            .lock()
            .writes
            .iter()
            .filter(|w| w.0 == off)
            .map(|w| w.1)
            .collect()
    }
}

impl MmioWindow for Regs {
    fn read32(&self, off: u64) -> u32 {
        let s = self.0.lock();
        let t = s.t;
        if off == trans_hdcp_anlo(t) {
            return s.an[0];
        }
        if off == trans_hdcp_anhi(t) {
            return s.an[1];
        }
        let v = *s.regs.get(&off).unwrap_or(&0);
        // DP MST: a stream is encrypted while its TRANS_DDI_FUNC_CTL HDCP
        // select is set on an encrypted link (the master's
        // LINK_ENCRYPTION_STATUS, or its HDCP 1.4 ENC).
        for x in 0..4u8 {
            let select = s.regs.get(&trans_ddi_func_ctl(x)).copied().unwrap_or(0)
                & mst::TRANS_DDI_HDCP_SELECT
                != 0
                && s.stuck_stream != Some(x);
            if off == mst::trans_hdcp2_stream_status(x) {
                let link = s.regs.get(&trans_hdcp2_status(t)).copied().unwrap_or(0)
                    & LINK_ENCRYPTION_STATUS
                    != 0;
                return v | if select && link {
                    mst::STREAM_ENCRYPTION_STATUS
                } else {
                    0
                };
            }
            if off == trans_hdcp_status(x) {
                let enc =
                    s.regs.get(&trans_hdcp_status(t)).copied().unwrap_or(0) & HDCP_STATUS_ENC != 0;
                return v | if select && enc {
                    mst::hdcp_status_stream_enc(x)
                } else {
                    0
                };
            }
        }
        if off == HDCP_REP_CTL {
            let mut v = v | HDCP_SHA1_READY;
            if s.sha_done {
                v |= HDCP_SHA1_COMPLETE;
                let vprime: Vec<u32> = (0..5)
                    .map(|i| *s.regs.get(&hdcp_sha_v_prime(i)).unwrap_or(&0))
                    .collect();
                if s.sha == s.expect_sha && vprime[..] == s.expect_v[..] {
                    v |= HDCP_SHA1_V_MATCH;
                }
            }
            return v;
        }
        v
    }

    fn write32(&self, off: u64, val: u32) {
        let mut s = self.0.lock();
        s.writes.push((off, val));
        let t = s.t;
        let status = trans_hdcp_status(t);
        let st = |s: &mut RegState| -> u32 { *s.regs.get(&status).unwrap_or(&0) };
        if off == HDCP_KEY_CONF {
            if val & HDCP_KEY_LOAD_TRIGGER != 0 {
                let bits = if s.key_fails {
                    HDCP_KEY_LOAD_DONE
                } else {
                    HDCP_KEY_LOAD_DONE | HDCP_KEY_LOAD_STATUS
                };
                s.regs.insert(HDCP_KEY_STATUS, bits);
            }
        } else if off == HDCP_KEY_STATUS {
            // Write one to clear.
            let v = *s.regs.get(&off).unwrap_or(&0);
            s.regs.insert(off, v & !val);
        } else if off == trans_hdcp_conf(t) {
            let v = match val {
                HDCP_CONF_CAPTURE_AN => st(&mut s) | HDCP_STATUS_AN_READY,
                HDCP_CONF_AUTH_AND_ENC => st(&mut s) | HDCP_STATUS_R0_READY,
                _ => 0,
            };
            s.regs.insert(status, v);
            s.regs.insert(off, val);
        } else if off == trans_hdcp_rprime(t) {
            if val == u32::from(s.r0) {
                let v = st(&mut s) | HDCP_STATUS_RI_MATCH | HDCP_STATUS_ENC;
                s.regs.insert(status, v);
            }
        } else if off == HDCP_REP_CTL {
            if val & 0xe == HDCP_SHA1_COMPLETE_HASH {
                s.sha_done = true;
            }
            s.regs.insert(off, val);
        } else if off == HDCP_SHA_TEXT {
            let mode = *s.regs.get(&HDCP_REP_CTL).unwrap_or(&0) & 0xe;
            s.sha.push((mode, val));
        } else if off == trans_hdcp2_ctl(t) {
            let st2 = trans_hdcp2_status(t);
            let mut v = *s.regs.get(&st2).unwrap_or(&0);
            if val & CTL_LINK_ENCRYPTION_REQ != 0 && v & LINK_AUTH_STATUS != 0 {
                v |= LINK_ENCRYPTION_STATUS;
            } else if val & CTL_LINK_ENCRYPTION_REQ == 0 {
                v &= !LINK_ENCRYPTION_STATUS;
            }
            s.regs.insert(st2, v);
            s.regs.insert(off, val);
        } else {
            s.regs.insert(off, val);
        }
    }
}

// ── The environment ──────────────────────────────────────────────────

#[derive(Debug, Default)]
struct Env {
    now: u64,
    rnd: u32,
    srm: Option<Srm>,
    delays: Vec<u64>,
}

impl HdcpEnv for Env {
    fn now_us(&mut self) -> u64 {
        self.now += 1;
        self.now
    }
    fn delay_ms(&mut self, ms: u64) -> msg::HdcpFuture<'_, ()> {
        self.now += ms * 1000;
        self.delays.push(ms);
        Box::pin(core::future::ready(()))
    }
    fn udelay(&mut self, us: u64) {
        self.now += us;
    }
    fn random_u32(&mut self) -> u32 {
        self.rnd = self.rnd.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        self.rnd
    }
    fn revoked(&mut self, ksvs: &[u8]) -> usize {
        self.srm.as_ref().map_or(0, |s| s.revoked_count(ksvs))
    }
}

// ── Pinned sink values ───────────────────────────────────────────────

/// A valid KSV (20 ones) and an invalid one (19).
const BKSV: [u8; 5] = [0x0f, 0x0f, 0x0f, 0x0f, 0x0f];
const BAD_KSV: [u8; 5] = [0x0f, 0x0f, 0x0f, 0x0f, 0x0e];
const KSV0: [u8; 5] = [0x55; 5];
const KSV1: [u8; 5] = [0x33; 5];
/// R0' as the sink sends it (little endian 0x1234, the register model's
/// R0).
const RI: [u8; 2] = [0x34, 0x12];

fn pattern(base: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| base.wrapping_add(i as u8)).collect()
}

/// The HDCP 2.2 values the sink and the firmware exchange.
struct Hdcp2Data {
    r_tx: Vec<u8>,
    cert: Vec<u8>,
    ekm: Vec<u8>,
    hprime: Vec<u8>,
    pairing: Vec<u8>,
    r_n: Vec<u8>,
    lprime: Vec<u8>,
    eks: Vec<u8>,
    riv: Vec<u8>,
    v: Vec<u8>,
    vprime: Vec<u8>,
    mprime: Vec<u8>,
}

impl Hdcp2Data {
    fn new(repeater: bool) -> Self {
        // hdcp2_cert_rx (receiver_id, kpub_rx, reserved, signature), r_rx,
        // rx_caps {HDCP_2_2_RX_CAPS_VERSION_VAL, 0, DP_HDCP_CAPABLE |
        // REPEATER}.
        let mut cert = BKSV.to_vec();
        cert.extend(pattern(0x20, 131));
        cert.extend([0, 0]);
        cert.extend(pattern(0x80, 384));
        cert.extend(pattern(0xb0, 8));
        cert.extend([0x02, 0x00, 0x02 | u8::from(repeater)]);
        Self {
            r_tx: pattern(0xa0, 8),
            cert,
            ekm: pattern(0x01, 128),
            hprime: pattern(0xc0, 32),
            pairing: pattern(0xd0, 16),
            r_n: pattern(0xe0, 8),
            lprime: pattern(0x40, 32),
            eks: pattern(0x60, 16),
            riv: pattern(0x70, 8),
            v: pattern(0x90, 16),
            vprime: pattern(0x11, 16),
            mprime: pattern(0x31, 32),
        }
    }
}

// ── The DP sink ──────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct DpSink {
    mem: BTreeMap<u32, u8>,
    writes: Vec<(u32, Vec<u8>)>,
    fifo: Vec<u8>,
    fifo_at: usize,
    rx_status: u8,
    reads: Vec<u32>,
    /// The CP_IRQs the sink raised so far; `None`: none delivered.
    cp_irq: Option<u32>,
    /// Announce H' (after AKE_No_Stored_km) and the pairing info (once H'
    /// is read) by RxStatus and CP_IRQ, as a sink computing them does.
    announce: bool,
}

impl DpSink {
    fn put(&mut self, addr: u32, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.mem.insert(addr + i as u32, b);
        }
    }
    fn got(&self, addr: u32, len: usize) -> Vec<u8> {
        (0..len as u32)
            .map(|i| self.mem.get(&(addr + i)).copied().unwrap_or(0))
            .collect()
    }
    /// An HDCP 1.4 sink: capable, Bksv, R0'.
    fn hdcp14(repeater: bool) -> Self {
        let mut s = Self::default();
        s.put(shim::DP_AUX_HDCP_BKSV, &BKSV);
        s.put(shim::DP_AUX_HDCP_RI_PRIME, &RI);
        let bcaps = shim::DP_BCAPS_HDCP_CAPABLE
            | if repeater {
                shim::DP_BCAPS_REPEATER_PRESENT
            } else {
                0
            };
        s.put(shim::DP_AUX_HDCP_BCAPS, &[bcaps]);
        s
    }
    /// An HDCP 2.2 sink: RxCaps, the certificate block, H', pairing and
    /// L' in place; H' and pairing announced.
    fn hdcp22(d: &Hdcp2Data) -> Self {
        let mut s = Self::default();
        s.put(shim::DP_HDCP_2_2_REG_CERT_RX_OFFSET, &d.cert);
        s.put(shim::DP_HDCP_2_2_REG_HPRIME_OFFSET, &d.hprime);
        s.put(shim::DP_HDCP_2_2_REG_EKH_KM_RD_OFFSET, &d.pairing);
        s.put(shim::DP_HDCP_2_2_REG_LPRIME_OFFSET, &d.lprime);
        s.rx_status = (1 << 1) | (1 << 2);
        s
    }
}

impl Dpcd for DpSink {
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), HdcpError> {
        self.reads.push(addr);
        if addr == shim::DP_AUX_HDCP_KSV_FIFO {
            for b in buf.iter_mut() {
                *b = self.fifo.get(self.fifo_at).copied().unwrap_or(0);
                self.fifo_at += 1;
            }
            return Ok(());
        }
        if addr == shim::DP_HDCP_2_2_REG_RXSTATUS_OFFSET {
            buf[0] = self.rx_status;
            return Ok(());
        }
        if self.announce && addr == shim::DP_HDCP_2_2_REG_HPRIME_OFFSET {
            self.rx_status |= 1 << 2;
            self.cp_irq = self.cp_irq.map(|n| n + 1);
        }
        let got = self.got(addr, buf.len());
        buf.copy_from_slice(&got);
        Ok(())
    }
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), HdcpError> {
        self.writes.push((addr, data.to_vec()));
        self.put(addr, data);
        // A new authentication (the Aksv write) restarts the repeater's
        // part 2: its KSV list is read from the first KSV again.
        // `intel_hdcp1_enable` retries `intel_hdcp_auth` three times and
        // each `intel_hdcp_auth_downstream` reads the whole list.
        if addr == shim::DP_AUX_HDCP_AKSV {
            self.fifo_at = 0;
        }
        if self.announce && addr + data.len() as u32 == shim::DP_HDCP_2_2_REG_EKPUB_KM_OFFSET + 128
        {
            self.rx_status |= 1 << 1;
            self.cp_irq = self.cp_irq.map(|n| n + 1);
        }
        Ok(())
    }
    fn cp_irq_count(&mut self) -> Option<u32> {
        self.cp_irq
    }
}

// ── The HDMI sink ────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct HdmiSink {
    regs: BTreeMap<u8, Vec<u8>>,
    an: Option<Vec<u8>>,
    aksv: u32,
    /// Messages the transmitter wrote.
    written: Vec<Vec<u8>>,
    /// Message id written → messages the sink then offers.
    script: Vec<(u8, Vec<Vec<u8>>)>,
    pending: VecDeque<Vec<u8>>,
    reauth: bool,
}

impl HdmiSink {
    fn hdcp14() -> Self {
        let mut s = Self::default();
        s.regs.insert(shim::DDC_BKSV, BKSV.to_vec());
        s.regs.insert(shim::DDC_RI_PRIME, RI.to_vec());
        s.regs.insert(shim::DDC_BCAPS, vec![0]);
        s
    }
}

impl Ddc for HdmiSink {
    fn read(&mut self, offset: u8, buf: &mut [u8]) -> Result<(), HdcpError> {
        match offset {
            shim::HDCP_2_2_HDMI_REG_RXSTATUS_OFFSET => {
                let size = self.pending.front().map_or(0, Vec::len);
                let ready = self
                    .pending
                    .front()
                    .is_some_and(|m| m[0] == msg::REP_SEND_RECVID_LIST);
                buf[0] = size as u8;
                buf[1] = (size >> 8) as u8 & 3 | u8::from(ready) << 2 | u8::from(self.reauth) << 3;
            }
            shim::HDCP_2_2_HDMI_REG_RD_MSG_OFFSET => {
                let m = self.pending.pop_front().ok_or(HdcpError::Sink(-5))?;
                if m.len() != buf.len() {
                    return Err(HdcpError::Sink(-5));
                }
                buf.copy_from_slice(&m);
            }
            _ => {
                let r = self.regs.get(&offset).cloned().unwrap_or_default();
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = r.get(i).copied().unwrap_or(0);
                }
            }
        }
        Ok(())
    }
    fn write(&mut self, offset: u8, data: &[u8]) -> Result<(), HdcpError> {
        match offset {
            shim::DDC_AN => self.an = Some(data.to_vec()),
            shim::HDCP_2_2_HDMI_REG_WR_MSG_OFFSET => {
                self.written.push(data.to_vec());
                if let Some((_, replies)) = self.script.iter().find(|(id, _)| *id == data[0]) {
                    self.pending.extend(replies.iter().cloned());
                }
            }
            _ => {
                self.regs.insert(offset, data.to_vec());
            }
        }
        Ok(())
    }
    fn output_aksv(&mut self) -> Result<(), HdcpError> {
        self.aksv += 1;
        Ok(())
    }
}

// ── The HDCP firmware model (MEI client) ─────────────────────────────

/// `WIRED_CMD_BUF_LEN_*_IN` from `i915_hdcp_interface.h`, by command.
fn buffer_len_in(id: u32, len: usize) -> Option<u32> {
    Some(match id {
        0x0003_1000 => 5,
        0x0003_1001 => 4 + 522 + 8 + 3,
        0x0003_1002 => 4 + 32,
        0x0003_1003 => 4 + 16,
        0x0003_1004 => 4,
        0x0003_1005 => 4 + 32,
        0x0003_1006 => 4,
        0x0003_1007 => 4 + 1,
        0x0003_1008 => 4 + 2 + 3 + 16 + 155,
        // REPEATER_AUTH_STREAM_REQ: struct_size(.., streams, k) less the header.
        0x0003_1009 => len as u32 - 16,
        0x0003_100a => 4,
        _ => return None,
    })
}

struct FwModel<'r> {
    regs: &'r Regs,
    t: u8,
    protocol: u8,
    d: Hdcp2Data,
    stored_km: bool,
    content_type: u8,
    /// (command, status) to fail with, and how many times.
    fail: Option<(u32, u32, u32)>,
    log: Vec<u32>,
    bad: Option<&'static str>,
    /// The (stream ID, type) pairs a DP MST port manages; `None` for SST
    /// and HDMI (stream 0 of the content type).
    mst_streams: Option<Vec<(u8, u8)>>,
}

impl core::fmt::Debug for FwModel<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FwModel").field("log", &self.log).finish()
    }
}

impl<'r> FwModel<'r> {
    fn new(regs: &'r Regs, t: u8, protocol: u8, d: Hdcp2Data) -> Self {
        Self {
            regs,
            t,
            protocol,
            d,
            stored_km: false,
            content_type: 0,
            fail: None,
            log: Vec::new(),
            bad: None,
            mst_streams: None,
        }
    }

    fn check(&mut self, ok: bool, what: &'static str) {
        if !ok && self.bad.is_none() {
            self.bad = Some(what);
        }
    }

    /// One `wired_cmd_*_in` and its `_out`.
    fn handle(&mut self, cmd: &[u8], reply: &mut [u8]) -> Result<usize, i32> {
        let le = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let id = le(&cmd[4..8]);
        self.log.push(id);
        self.check(le(&cmd[0..4]) == 0x0001_0000, "api_version");
        self.check(le(&cmd[8..12]) == 0, "request status");
        self.check(
            buffer_len_in(id, cmd.len()) == Some(le(&cmd[12..16]))
                && le(&cmd[12..16]) as usize == cmd.len() - 16,
            "buffer_len",
        );
        // INTEGRATED, physical port 0 (Gen12+), HDCP_TRANSCODER_A + t.
        self.check(cmd[16..20] == [1, 0, 0x10 + self.t, 0], "hdcp_port_id");
        let p = &cmd[20..];
        let mut status = 0;
        if let Some((fid, fstatus, n)) = self.fail {
            if fid == id && n > 0 {
                status = fstatus;
                self.fail = Some((fid, fstatus, n - 1));
            }
        }
        let mut out = Vec::new();
        match id {
            0x0003_1000 => {
                self.check(p == [self.protocol], "session protocol");
                out.extend(&self.d.r_tx);
                out.extend([0x02, 0x00, 0x00]);
            }
            0x0003_1001 => {
                self.check(p == &self.d.cert[..], "cert_rx, r_rx, rx_caps");
                out.push(u8::from(self.stored_km));
                out.extend([0, 0, 0]);
                out.extend(&self.d.ekm);
            }
            0x0003_1002 => self.check(p == &self.d.hprime[..], "h_prime"),
            0x0003_1003 => self.check(p == &self.d.pairing[..], "e_kh_km"),
            0x0003_1004 => out.extend(&self.d.r_n),
            0x0003_1005 => self.check(p == &self.d.lprime[..], "l_prime"),
            0x0003_1006 => {
                out.extend(&self.d.eks);
                out.extend(&self.d.riv);
            }
            0x0003_1007 => {
                let ty = self
                    .mst_streams
                    .as_ref()
                    .map_or(self.content_type, |s| s[0].1);
                self.check(p == [ty], "enable_auth stream_type");
                if status == 0 {
                    self.regs
                        .set_bits(trans_hdcp2_status(self.t), LINK_AUTH_STATUS);
                }
            }
            0x0003_1008 => {
                // rx_info {0, DEV_COUNT_LO 1}, seq_num_v 0, V', one ID and
                // the rest of HDCP_2_2_RECEIVER_IDS_MAX_LEN zero.
                let mut want = vec![0x00, 0x10, 0, 0, 0];
                want.extend(&self.d.vprime);
                want.extend(KSV0);
                want.resize(2 + 3 + 16 + 155, 0);
                self.check(p == &want[..], "verify_repeater payload");
                out.push(1);
                out.extend(&self.d.v);
            }
            0x0003_1009 => {
                // seq_num_m 0 (be24), M', k (be16), {stream ID, type}[k]:
                // stream 0 of the content type for SST and HDMI.
                let streams = self
                    .mst_streams
                    .clone()
                    .unwrap_or_else(|| vec![(0, self.content_type)]);
                let mut want = vec![0, 0, 0];
                want.extend(&self.d.mprime);
                want.extend((streams.len() as u16).to_be_bytes());
                for (id, ty) in streams {
                    want.extend([id, ty]);
                }
                self.check(p == &want[..], "repeater_auth_stream_req payload");
            }
            0x0003_100a => {}
            _ => self.check(false, "unknown command"),
        }
        let mut r = Vec::new();
        r.extend(0x0001_0000u32.to_le_bytes());
        r.extend(id.to_le_bytes());
        r.extend(status.to_le_bytes());
        r.extend(((out.len() + 4) as u32).to_le_bytes());
        r.extend(&cmd[16..20]);
        r.extend(out);
        let n = r.len().min(reply.len());
        reply[..n].copy_from_slice(&r[..n]);
        Ok(n)
    }
}

impl msg::HdcpTransport for FwModel<'_> {
    fn exchange<'a>(
        &'a mut self,
        command: &'a [u8],
        reply: &'a mut [u8],
    ) -> msg::HdcpFuture<'a, Result<usize, i32>> {
        let r = self.handle(command, reply);
        Box::pin(core::future::ready(r))
    }
}

// ── The GSC model ────────────────────────────────────────────────────

/// `struct intel_gsc_mtl_header`: validity_marker 0xA578875A at 0,
/// heci_client_id at 4, header_version (1) at 6, host_session_handle at 8,
/// gsc_message_handle at 16, message_size (header included) at 24, flags
/// (bit 0 pending) at 28, status at 32; 36 bytes.
struct GscModel<'r> {
    fw: FwModel<'r>,
    pending_once: bool,
    handles: Vec<u64>,
    sessions: Vec<u64>,
    bad: Option<&'static str>,
}

impl core::fmt::Debug for GscModel<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GscModel").finish_non_exhaustive()
    }
}

const GSC_HANDLE: u64 = 0x1122_3344_5566_7788;

impl GscModel<'_> {
    fn submit_now(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), i32> {
        let le32 = |b: &[u8]| u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let le64 = |b: &[u8]| u64::from_le_bytes(b[..8].try_into().unwrap());
        let ok = le32(&input[0..4]) == 0xA578_875A
            && input[4] == 18
            && input[6..8] == [1, 0]
            && le32(&input[24..28]) as usize == input.len()
            && le64(&input[8..16]) >> 56 == 18;
        if !ok && self.bad.is_none() {
            self.bad = Some("intel_gsc_mtl_header");
        }
        self.sessions.push(le64(&input[8..16]));
        self.handles.push(le64(&input[16..24]));
        output.fill(0);
        output[0..4].copy_from_slice(&0xA578_875Au32.to_le_bytes());
        output[4] = 18;
        output[6] = 1;
        if self.pending_once {
            self.pending_once = false;
            output[16..24].copy_from_slice(&GSC_HANDLE.to_le_bytes());
            output[24..28].copy_from_slice(&36u32.to_le_bytes());
            output[28..32].copy_from_slice(&1u32.to_le_bytes());
            return Ok(());
        }
        let n = self.fw.handle(&input[36..], &mut output[36..])?;
        output[24..28].copy_from_slice(&((36 + n) as u32).to_le_bytes());
        Ok(())
    }
}

impl GscPacketPort for GscModel<'_> {
    fn submit<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
    ) -> msg::HdcpFuture<'a, Result<(), i32>> {
        let r = self.submit_now(input, output);
        Box::pin(core::future::ready(r))
    }
    fn ready(&mut self) -> bool {
        true
    }
    fn delay_ms(&mut self, _: u64) -> msg::HdcpFuture<'_, ()> {
        Box::pin(core::future::ready(()))
    }
}

// ── Layouts ──────────────────────────────────────────────────────────

fn smoke_intel_hdcp_register_and_message_layouts() -> TestResult {
    // intel_hdcp_regs.h, transcoder B (the A block plus 0x100).
    let regs = [
        (trans_hdcp_conf(1), 0x66500),
        (trans_hdcp_aninit(1), 0x66504),
        (trans_hdcp_anlo(1), 0x66508),
        (trans_hdcp_anhi(1), 0x6650c),
        (trans_hdcp_bksvlo(1), 0x66510),
        (trans_hdcp_bksvhi(1), 0x66514),
        (trans_hdcp_rprime(1), 0x66518),
        (trans_hdcp_status(1), 0x6651c),
        (trans_hdcp2_auth(0), 0x66498),
        (trans_hdcp2_ctl(0), 0x664b0),
        (trans_hdcp2_status(1), 0x665b4),
        (hdcp_sha_v_prime(4), 0x66d14),
        (mtl_chicken_trans(1), 0x614e0),
        (trans_ddi_func_ctl(2), 0x62400),
    ];
    if regs.iter().any(|(a, b)| a != b) || HDCP_SHA_TEXT != 0x66d18 || HDCP_REP_CTL != 0x66d00 {
        return TestResult::Fail("HDCP register offsets differ from intel_hdcp_regs.h");
    }
    // HDCP_TRANS{A..D}_REP_PRESENT | HDCP_TRANS{A..D}_SHA1_M0.
    let rep = [
        (1 << 31) | (1 << 20),
        (1 << 30) | (2 << 20),
        (1 << 29) | (3 << 20),
        (1 << 28) | (4 << 20),
    ];
    if (0..4).any(|t| HdcpLink::repeater_ctl(t) != rep[t as usize]) {
        return TestResult::Fail("repeater control bits differ from intel_hdcp_get_repeater_ctl");
    }
    // sizeof(struct hdcp2_*), packed.
    let sizes = [
        (msg::AKE_INIT_SIZE, 12),
        (msg::AKE_SEND_CERT_SIZE, 534),
        (msg::AKE_NO_STORED_KM_SIZE, 129),
        (msg::AKE_STORED_KM_SIZE, 33),
        (msg::AKE_SEND_HPRIME_SIZE, 33),
        (msg::AKE_SEND_PAIRING_INFO_SIZE, 17),
        (msg::LC_INIT_SIZE, 9),
        (msg::LC_SEND_LPRIME_SIZE, 33),
        (msg::SKE_SEND_EKS_SIZE, 25),
        (msg::REP_SEND_RECVID_LIST_SIZE, 177),
        (msg::REP_SEND_ACK_SIZE, 17),
        (msg::REP_STREAM_MANAGE_SIZE, 14),
        (msg::REP_STREAM_READY_SIZE, 33),
        (msg::CERT_RXCAPS, 531),
    ];
    if sizes.iter().any(|(a, b)| a != b) {
        return TestResult::Fail("HDCP 2.2 message sizes differ from drm_hdcp.h");
    }
    // sizeof(struct wired_cmd_*_out).
    let outs = [
        (msg::INITIATE_SESSION_OUT, 31),
        (msg::VERIFY_RECEIVER_CERT_OUT, 152),
        (msg::STATUS_ONLY_OUT, 20),
        (msg::INIT_LOCALITY_CHECK_OUT, 28),
        (msg::GET_SESSION_KEY_OUT, 44),
        (msg::VERIFY_REPEATER_OUT, 37),
    ];
    if outs.iter().any(|(a, b)| a != b) {
        return TestResult::Fail("wired_cmd_*_out sizes differ from i915_hdcp_interface.h");
    }
    if msg::hdcp_transcoder(0) != 0x10
        || msg::hdcp_transcoder(3) != 0x13
        || msg::hdcp_transcoder(4) != 0
    {
        return TestResult::Fail("intel_get_hdcp_transcoder");
    }
    if msg::device_count([0x01, 0x30]) != 0x13 || msg::be24_to_cpu([1, 2, 3]) != 0x0001_0203 {
        return TestResult::Fail("rx_info device count / be24");
    }
    if !ksv_valid(&BKSV) || ksv_valid(&BAD_KSV) {
        return TestResult::Fail("intel_hdcp_is_ksv_valid");
    }
    // intel_hdcp_adjust_hdcp_line_rekeying's display/step table.
    let rekey = [
        ((12, 0, 0), LineRekey::None),
        ((14, 0, 8), LineRekey::None),
        ((14, 0, 12), LineRekey::ChickenTrans),
        ((14, 1, 0), LineRekey::None),
        ((14, 1, 4), LineRekey::TransDdi),
        ((20, 0, 4), LineRekey::TransDdi),
        ((30, 0, 0), LineRekey::Xe3TransDdi),
    ];
    if rekey
        .iter()
        .any(|((v, r, s), want)| LineRekey::for_display(*v, *r, *s) != *want)
    {
        return TestResult::Fail("line rekey table");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_hdcp",
    smoke_intel_hdcp_register_and_message_layouts
);

fn smoke_intel_hdcp_wired_commands() -> TestResult {
    let mut port = HdcpPortData::gen12(msg::HDCP_PROTOCOL_HDMI);
    port.hdcp_transcoder = msg::hdcp_transcoder(1);
    // wired_cmd_initiate_hdcp2_session_in.
    let want = [
        0x00, 0x00, 0x01, 0x00, 0x00, 0x10, 0x03, 0x00, 0, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0x11, 0, 1,
    ];
    if msg::wired::initiate_session(&port)[..] != want[..] {
        return TestResult::Fail("initiate-session command bytes");
    }
    // wired_cmd_enable_auth_in with a type-1 stream.
    port.k = 1;
    port.streams[0] = (0, 1);
    let e = msg::wired::enable_auth(&port);
    if e.len() != 21 || e[4..8] != 0x0003_1007u32.to_le_bytes() || e[20] != 1 {
        return TestResult::Fail("enable-auth command bytes");
    }
    // wired_cmd_repeater_auth_stream_req_in, k = 1, seq_num_m 0x010203.
    port.seq_num_m = 0x0001_0203;
    let mut ready = vec![msg::REP_STREAM_READY];
    ready.extend(pattern(0x31, 32));
    let Some(r) = msg::wired::repeater_auth_stream_req(&port, &ready) else {
        return TestResult::Fail("stream request refused");
    };
    let mut want = Vec::new();
    want.extend(0x0001_0000u32.to_le_bytes());
    want.extend(0x0003_1009u32.to_le_bytes());
    want.extend(0u32.to_le_bytes());
    want.extend(((4 + 3 + 32 + 2 + 2) as u32).to_le_bytes());
    want.extend([1, 0, 0x11, 0, 0x01, 0x02, 0x03]);
    want.extend(pattern(0x31, 32));
    want.extend([0x00, 0x01, 0x00, 0x01]);
    if r != want {
        return TestResult::Fail("stream request command bytes");
    }
    port.k = 5;
    if msg::wired::repeater_auth_stream_req(&port, &ready).is_some() {
        return TestResult::Fail("k beyond HDCP_2_2_MAX_CONTENT_STREAMS_CNT accepted");
    }
    // The GSC framing: header for HECI_MEADDRESS_HDCP, -ENOSPC beyond a page.
    let Ok(f) = msg::frame_gsc_command(&[0xaa; 20], 20, 0x0012_3456) else {
        return TestResult::Fail("GSC framing refused");
    };
    let mut want = vec![0x5a, 0x87, 0x78, 0xa5, 18, 0, 1, 0];
    want.extend((0x0012_3456u64 | 18 << 56).to_le_bytes());
    want.extend([0; 8]);
    want.extend(56u32.to_le_bytes());
    want.extend([0; 8]);
    want.extend([0xaa; 20]);
    if f != want {
        return TestResult::Fail("intel_gsc_mtl_header framing");
    }
    if msg::frame_gsc_command(&[0; 4061], 20, 1).is_ok()
        || msg::frame_gsc_command(&[0; 20], 4061, 1).is_ok()
    {
        return TestResult::Fail("oversize GSC message not -ENOSPC");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp_wired_commands);

// ── HDCP 1.4 ─────────────────────────────────────────────────────────

fn hdcp14_dp_sink() -> TestResult {
    let regs = Regs::new(1);
    let mut s = DpShim::new(DpSink::hdcp14(false));
    let mut env = Env::default();
    let mut link = HdcpLink::new(Protocol::Dp, 1, LineRekey::None, true);
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: None::<&mut FwModel>,
        env: &mut env,
    };
    if drive(link.enable(&mut cx, 0)) != Some(Ok(())) {
        return TestResult::Fail("HDCP 1.4 DP enable failed");
    }
    if link.value != CpValue::Enabled || !link.hdcp_encrypted || link.hdcp2_encrypted {
        return TestResult::Fail("not ENABLED with HDCP 1.4 encryption");
    }
    // Key load, An capture and AUTH_AND_ENC on transcoder B.
    if regs.wrote(HDCP_KEY_CONF) != [HDCP_KEY_LOAD_TRIGGER, HDCP_AKSV_SEND_TRIGGER]
        || regs.wrote(trans_hdcp_aninit(1)).len() != 2
        || regs.wrote(trans_hdcp_conf(1)) != [HDCP_CONF_CAPTURE_AN, HDCP_CONF_AUTH_AND_ENC]
        || regs.wrote(trans_hdcp_bksvlo(1)) != [0x0f0f_0f0f]
        || regs.wrote(trans_hdcp_bksvhi(1)) != [0x0f]
        || regs.wrote(trans_hdcp_rprime(1)) != [0x1234]
        || !regs.wrote(HDCP_REP_CTL).is_empty()
    {
        return TestResult::Fail("HDCP 1.4 register sequence");
    }
    // An (the two An registers, little endian) to 0x6800c, then five zero
    // bytes to the Aksv address for the hardware to fill.
    let w = &s.dpcd.writes;
    if w.len() != 2
        || w[0] != (shim::DP_AUX_HDCP_AN, vec![1, 2, 3, 4, 5, 6, 7, 8])
        || w[1] != (shim::DP_AUX_HDCP_AKSV, vec![0; 5])
    {
        return TestResult::Fail("An / Aksv DPCD writes");
    }
    // R0' is read only once 300 ms passed since Aksv.
    if !env.delays.iter().any(|&d| d > 290 && d <= 300) {
        return TestResult::Fail("no R0' wait");
    }
    // Link check: BSTATUS clean keeps it, a link failure re-authenticates.
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: None::<&mut FwModel>,
        env: &mut env,
    };
    if drive(link.check_link(&mut cx)) != Some(Ok(())) {
        return TestResult::Fail("clean link check failed");
    }
    cx.shim
        .dpcd
        .put(shim::DP_AUX_HDCP_BSTATUS, &[shim::DP_BSTATUS_LINK_FAILURE]);
    if drive(link.check_link(&mut cx)) != Some(Ok(())) || link.value != CpValue::Enabled {
        return TestResult::Fail("link failure did not re-authenticate");
    }
    // The sink stops answering with a valid Bksv: back to DESIRED.
    cx.shim.dpcd.put(shim::DP_AUX_HDCP_BKSV, &BAD_KSV);
    if drive(link.check_link(&mut cx)) != Some(Err(HdcpError::InvalidBksv))
        || link.value != CpValue::Desired
    {
        return TestResult::Fail("failed re-authentication not DESIRED");
    }
    // Encryption dropped under an enabled link: DESIRED at once.
    let mut link = HdcpLink::new(Protocol::Dp, 1, LineRekey::None, true);
    let mut s = DpShim::new(DpSink::hdcp14(false));
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: None::<&mut FwModel>,
        env: &mut env,
    };
    if drive(link.enable(&mut cx, 0)) != Some(Ok(())) {
        return TestResult::Fail("second enable failed");
    }
    regs.clear_bits(trans_hdcp_status(1), HDCP_STATUS_ENC);
    if drive(link.check_link(&mut cx)) != Some(Err(HdcpError::LinkStopped))
        || link.value != CpValue::Desired
    {
        return TestResult::Fail("stopped encryption not DESIRED");
    }
    TestResult::Pass
}

fn smoke_intel_hdcp14_dp_sink() -> TestResult {
    hdcp14_dp_sink()
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp14_dp_sink);

/// `intel_hdcp_validate_v_prime` for two KSVs: KSV0 fills one dword, its
/// last byte and three of KSV1 the next, two leftovers join BINFO in a
/// third; the leftover-2 case then writes 64 bits of M0, the terminator
/// by hand, zeros to byte 60 and the bit length (2 * 5 + 10) * 8.
fn expected_sha_two(binfo: [u8; 2]) -> Vec<(u32, u32)> {
    let mut v = vec![
        (HDCP_SHA1_TEXT_32, 0x5555_5555),
        (HDCP_SHA1_TEXT_32, 0x5533_3333),
        (
            HDCP_SHA1_TEXT_32,
            0x3333_0000 | u32::from(binfo[0]) << 8 | u32::from(binfo[1]),
        ),
        (HDCP_SHA1_TEXT_0, 0),
        (HDCP_SHA1_TEXT_0, 0),
        (HDCP_SHA1_TEXT_32, 0x8000_0000),
    ];
    v.extend(core::iter::repeat_n((HDCP_SHA1_TEXT_32, 0), 9));
    v.push((HDCP_SHA1_TEXT_32, 160));
    v
}

fn repeater_sink(binfo: [u8; 2]) -> DpSink {
    let mut sink = DpSink::hdcp14(true);
    sink.put(shim::DP_AUX_HDCP_BSTATUS, &[shim::DP_BSTATUS_READY]);
    sink.put(shim::DP_AUX_HDCP_BINFO, &binfo);
    sink.fifo = [KSV0, KSV1].concat();
    sink.put(shim::dp_aux_hdcp_v_prime(0), &pattern(0x10, 20));
    sink
}

fn hdcp14_dp_repeater() -> TestResult {
    let binfo = [0x02, 0x01];
    let regs = Regs::new(0);
    {
        let mut st = regs.0.lock();
        st.expect_sha = expected_sha_two(binfo);
        for i in 0..5 {
            let b = 0x10 + 4 * i as u8;
            st.expect_v[i] = u32::from_le_bytes([b, b + 1, b + 2, b + 3]);
        }
    }
    let mut s = DpShim::new(repeater_sink(binfo));
    let mut env = Env::default();
    let mut link = HdcpLink::new(Protocol::Dp, 0, LineRekey::None, true);
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: None::<&mut FwModel>,
        env: &mut env,
    };
    if drive(link.enable(&mut cx, 0)) != Some(Ok(())) {
        return TestResult::Fail("HDCP 1.4 repeater enable failed (KSV list or V')");
    }
    // HDCP_REP_CTL armed with the repeater bits before signalling.
    if regs.wrote(HDCP_REP_CTL).first() != Some(&HdcpLink::repeater_ctl(0)) {
        return TestResult::Fail("REP_CTL not armed for the repeater");
    }
    // The KSV FIFO through its 15-byte window: one read of 10 bytes.
    if s.dpcd.fifo_at != 10
        || s.dpcd
            .reads
            .iter()
            .filter(|&&a| a == shim::DP_AUX_HDCP_KSV_FIFO)
            .count()
            != 1
    {
        return TestResult::Fail("KSV FIFO not read once through its window");
    }
    // Topology limits and revocation.
    for (binfo, want) in [
        ([0x82, 0x01], HdcpError::TopologyExceeded),
        ([0x02, 0x09], HdcpError::TopologyExceeded),
        ([0x00, 0x01], HdcpError::NoDownstream),
    ] {
        let regs = Regs::new(0);
        let mut s = DpShim::new(repeater_sink(binfo));
        let mut link = HdcpLink::new(Protocol::Dp, 0, LineRekey::None, true);
        let mut cx = Ctx {
            io: &regs,
            shim: &mut s,
            fw: None::<&mut FwModel>,
            env: &mut env,
        };
        if drive(link.enable(&mut cx, 0)) != Some(Err(want)) {
            return TestResult::Fail("repeater topology limit not refused");
        }
    }
    let regs = Regs::new(0);
    let mut s = DpShim::new(repeater_sink(binfo));
    let mut srm = vec![0x80, 0x00, 0x00, 0x01, 0x01, 0, 0, 3 + 6 + 40, 1];
    srm.extend(KSV1);
    srm.extend([0; 40]);
    let mut env = Env {
        srm: Srm::parse(&srm),
        ..Env::default()
    };
    let mut link = HdcpLink::new(Protocol::Dp, 0, LineRekey::None, true);
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: None::<&mut FwModel>,
        env: &mut env,
    };
    if drive(link.enable(&mut cx, 0)) != Some(Err(HdcpError::Revoked)) {
        return TestResult::Fail("revoked downstream KSV accepted");
    }
    // intel_hdcp1_enable's three tries each read the whole list and stop
    // at drm_hdcp_check_ksvs_revoked, before any V' comparison.
    if s.dpcd
        .reads
        .iter()
        .filter(|&&a| a == shim::DP_AUX_HDCP_KSV_FIFO)
        .count()
        != 3
        || !regs.wrote(HDCP_SHA_TEXT).is_empty()
    {
        return TestResult::Fail("revoked KSV list not refused on every try before V'");
    }
    TestResult::Pass
}

fn smoke_intel_hdcp14_dp_repeater() -> TestResult {
    hdcp14_dp_repeater()
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp14_dp_repeater);

fn smoke_intel_hdcp14_hdmi() -> TestResult {
    let regs = Regs::new(2);
    let mut s = HdmiShim::new(HdmiSink::hdcp14());
    let mut env = Env::default();
    let mut link = HdcpLink::new(Protocol::Hdmi, 2, LineRekey::None, true);
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: None::<&mut FwModel>,
        env: &mut env,
    };
    if drive(link.enable(&mut cx, 0)) != Some(Ok(())) {
        return TestResult::Fail("HDCP 1.4 HDMI enable failed");
    }
    if cx.shim.ddc.an.as_deref() != Some(&[1, 2, 3, 4, 5, 6, 7, 8][..]) || cx.shim.ddc.aksv != 1 {
        return TestResult::Fail("An over DDC / hardware Aksv");
    }
    // TRANS_DDI_HDCP_SIGNALLING for HDMI.
    if regs.get(trans_ddi_func_ctl(2)) & TRANS_DDI_HDCP_SIGNALLING == 0 {
        return TestResult::Fail("HDMI HDCP signalling not set");
    }
    // Ri' check: RI_MATCH and ENC both, three tries.
    if drive(link.check_link(&mut cx)) != Some(Ok(())) {
        return TestResult::Fail("HDMI Ri' check failed");
    }
    // A wrong Ri' after encryption stopped: re-authentication fails, DESIRED.
    cx.shim.ddc.regs.insert(shim::DDC_RI_PRIME, vec![0, 0]);
    regs.clear_bits(trans_hdcp_status(2), HDCP_STATUS_RI_MATCH);
    if drive(link.check_link(&mut cx)).is_none_or(|r| r.is_ok()) || link.value != CpValue::Desired {
        return TestResult::Fail("Ri' mismatch not DESIRED");
    }
    // Disable clears signalling.
    let mut link = HdcpLink::new(Protocol::Hdmi, 2, LineRekey::None, true);
    let mut s = HdmiShim::new(HdmiSink::hdcp14());
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: None::<&mut FwModel>,
        env: &mut env,
    };
    if drive(link.enable(&mut cx, 0)) != Some(Ok(()))
        || drive(link.disable(&mut cx)) != Some(Ok(()))
        || link.value != CpValue::Undesired
        || regs.get(trans_ddi_func_ctl(2)) & TRANS_DDI_HDCP_SIGNALLING != 0
        || regs.get(trans_hdcp_conf(2)) != 0
    {
        return TestResult::Fail("HDMI disable left signalling or CONF");
    }
    // Keys that never load: -ENXIO after KEY_LOAD_TRIES, with clears.
    let regs = Regs::new(2);
    regs.0.lock().key_fails = true;
    let mut link = HdcpLink::new(Protocol::Hdmi, 2, LineRekey::None, true);
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: None::<&mut FwModel>,
        env: &mut env,
    };
    if drive(link.enable(&mut cx, 0)) != Some(Err(HdcpError::KeyLoad))
        || regs
            .wrote(HDCP_KEY_CONF)
            .iter()
            .filter(|&&v| v == HDCP_CLEAR_KEYS_TRIGGER)
            .count()
            != 5
    {
        return TestResult::Fail("failed key load not retried and cleared");
    }
    // PW_1 off in both request registers: hdcp_key_loadable refuses before
    // any key register is written; the BIOS request alone suffices.
    let regs = Regs::new(2);
    regs.0.lock().regs.insert(HSW_PWR_WELL_CTL2, 0);
    let mut link = HdcpLink::new(Protocol::Hdmi, 2, LineRekey::None, true);
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: None::<&mut FwModel>,
        env: &mut env,
    };
    if drive(link.enable(&mut cx, 0)) != Some(Err(HdcpError::KeyNotLoadable))
        || !regs.wrote(HDCP_KEY_CONF).is_empty()
    {
        return TestResult::Fail("key load with PW_1 off");
    }
    regs.0.lock().regs.insert(HSW_PWR_WELL_CTL1, 0b11);
    if drive(link.enable(&mut cx, 0)) != Some(Ok(())) {
        return TestResult::Fail("BIOS-requested PW_1 not accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp14_hdmi);

// ── HDCP 2.2 ─────────────────────────────────────────────────────────

fn hdcp22_dp_mei() -> TestResult {
    let regs = Regs::new(1);
    let d = Hdcp2Data::new(false);
    let mut s = DpShim::new(DpSink::hdcp22(&d));
    let mut fw = FwModel::new(&regs, 1, msg::HDCP_PROTOCOL_DP, Hdcp2Data::new(false));
    let mut env = Env::default();
    let mut link = HdcpLink::new(Protocol::Dp, 1, LineRekey::None, true);
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: Some(&mut fw),
        env: &mut env,
    };
    let r = drive(link.enable(&mut cx, 0));
    if let Some(bad) = fw.bad {
        return TestResult::Fail(bad);
    }
    if r != Some(Ok(())) || link.value != CpValue::Enabled || !link.hdcp2_encrypted {
        return TestResult::Fail("HDCP 2.2 DP enable failed");
    }
    // The firmware commands, in hdcp2_authenticate_and_encrypt's order.
    let want = [
        0x0003_1000,
        0x0003_1001,
        0x0003_1002,
        0x0003_1003,
        0x0003_1004,
        0x0003_1005,
        0x0003_1006,
        0x0003_1007,
    ];
    if fw.log != want {
        return TestResult::Fail("firmware command order");
    }
    // The sink's DPCD: AKE_Init, AKE_No_Stored_km, LC_Init, SKE_Send_Eks
    // and the errata stream type, no message ids.
    let sink = &s.dpcd;
    let mut ake = d.r_tx.clone();
    ake.extend([2, 0, 0]);
    let mut eks = d.eks.clone();
    eks.extend(&d.riv);
    if sink.got(shim::DP_HDCP_2_2_REG_RTX_OFFSET, 11) != ake
        || sink.got(shim::DP_HDCP_2_2_REG_EKPUB_KM_OFFSET, 128) != d.ekm
        || sink.got(shim::DP_HDCP_2_2_REG_RN_OFFSET, 8) != d.r_n
        || sink.got(shim::DP_HDCP_2_2_REG_EDKEY_KS_OFFSET, 24) != eks
        || sink.got(shim::DP_HDCP_2_2_REG_STREAM_TYPE_OFFSET, 1) != [0]
    {
        return TestResult::Fail("HDCP 2.2 DPCD writes");
    }
    // No write longer than one AUX transfer.
    if sink.writes.iter().any(|(_, b)| b.len() > 16) {
        return TestResult::Fail("DPCD write over 16 bytes");
    }
    // 200 ms between SKE and encryption, then CTL_LINK_ENCRYPTION_REQ.
    if !env.delays.contains(&DELAY_BEFORE_ENCRYPTION_MS)
        || regs.get(trans_hdcp2_ctl(1)) & CTL_LINK_ENCRYPTION_REQ == 0
    {
        return TestResult::Fail("encryption request");
    }
    // Link check: protected, then a reauth request disables (closing the
    // session) and goes back to DESIRED.
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: Some(&mut fw),
        env: &mut env,
    };
    if drive(link.check_link(&mut cx)) != Some(Ok(())) {
        return TestResult::Fail("protected HDCP 2.2 link check failed");
    }
    cx.shim.dpcd.rx_status |= 1 << 3;
    if drive(link.check_link(&mut cx)) != Some(Err(HdcpError::LinkStopped))
        || link.value != CpValue::Desired
        || link.hdcp2_encrypted
    {
        return TestResult::Fail("reauth request not DESIRED");
    }
    if fw.log.last() != Some(&0x0003_100a)
        || regs.get(trans_hdcp2_ctl(1)) & CTL_LINK_ENCRYPTION_REQ != 0
    {
        return TestResult::Fail("reauth did not close the session and stop encryption");
    }
    TestResult::Pass
}

fn smoke_intel_hdcp22_dp_mei() -> TestResult {
    hdcp22_dp_mei()
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp22_dp_mei);

/// A DP AUX model of the device service IRQ vectors for
/// [`shim::take_cp_irq`].
struct IrqAux {
    mem: BTreeMap<u32, u8>,
    writes: Vec<(u32, Vec<u8>)>,
}

impl crate::dp_aux::AuxChannel for IrqAux {
    fn transact<'a>(
        &mut self,
        req: &crate::dp_aux::AuxRequest<'_>,
        reply: &'a mut [u8],
    ) -> Result<crate::dp_aux::AuxResponse<'a>, crate::dp_aux::AuxError> {
        use crate::dp_aux::{AuxCommand, AuxResponse, AuxStatus};
        reply[0] = 0;
        let n = match req.cmd {
            AuxCommand::NativeRead => {
                let n = req.data.len();
                for (i, b) in reply[1..=n].iter_mut().enumerate() {
                    *b = self
                        .mem
                        .get(&(req.address + i as u32))
                        .copied()
                        .unwrap_or(0);
                }
                n
            }
            AuxCommand::NativeWrite => {
                self.writes.push((req.address, req.data.to_vec()));
                0
            }
            _ => return Err(crate::dp_aux::AuxError::Nacked),
        };
        Ok(AuxResponse {
            status: AuxStatus::Ack,
            data: &reply[1..1 + n],
        })
    }
}

/// `intel_dp_short_pulse` / `intel_dp_mst_hpd_irq`: CP_IRQ in
/// DP_DEVICE_SERVICE_IRQ_VECTOR (0x201) or ESI0 (0x2003) is acknowledged
/// alone; no CP_IRQ, no write.
fn smoke_intel_hdcp_cp_irq_vector() -> TestResult {
    // SST: CP_IRQ beside AUTOMATED_TEST_REQUEST (bit 1).
    let mut aux = IrqAux {
        mem: BTreeMap::from([(0x201, 0x06)]),
        writes: Vec::new(),
    };
    if shim::take_cp_irq(&mut aux, false) != Ok(true) || aux.writes != [(0x201, vec![0x04])] {
        return TestResult::Fail("SST CP_IRQ not acknowledged alone");
    }
    // MST: ESI0, and a vector without CP_IRQ leaves the sink alone.
    let mut aux = IrqAux {
        mem: BTreeMap::from([(0x201, 0x04), (0x2003, 0x10)]),
        writes: Vec::new(),
    };
    if shim::take_cp_irq(&mut aux, true) != Ok(false) || !aux.writes.is_empty() {
        return TestResult::Fail("MST ESI0 without CP_IRQ written");
    }
    aux.mem.insert(0x2003, 0x14);
    if shim::take_cp_irq(&mut aux, true) != Ok(true) || aux.writes != [(0x2003, vec![0x04])] {
        return TestResult::Fail("MST CP_IRQ not acknowledged in ESI0");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp_cp_irq_vector);

/// The count of the shim's CP_IRQ waits and RxStatus reads.
fn cp_irq_waits(env: &Env) -> usize {
    env.delays.iter().filter(|&&d| d == CP_IRQ_WAIT_MS).count()
}
fn rx_status_reads(sink: &DpSink) -> usize {
    sink.reads
        .iter()
        .filter(|&&a| a == shim::DP_HDCP_2_2_REG_RXSTATUS_OFFSET)
        .count()
}

/// HDCP 2.2 over DP with CP_IRQ delivery (`intel_dp_hdcp2_wait_for_msg`):
/// H' and the pairing info each end their wait at the sink's CP_IRQ and
/// read RxStatus once; a lost CP_IRQ waits out the message timeout and
/// then reads RxStatus once. A CP_IRQ that carries REAUTH_REQ runs the
/// link check at once (`intel_hdcp_handle_cp_irq`), which takes the link
/// to DESIRED; the next enable authenticates again.
fn hdcp22_dp_cp_irq() -> TestResult {
    let regs = Regs::new(1);
    let d = Hdcp2Data::new(false);
    let mut sink = DpSink::hdcp22(&d);
    sink.rx_status = 0;
    sink.cp_irq = Some(0);
    sink.announce = true;
    let mut s = DpShim::new(sink);
    let mut fw = FwModel::new(&regs, 1, msg::HDCP_PROTOCOL_DP, Hdcp2Data::new(false));
    let mut env = Env::default();
    let mut link = HdcpLink::new(Protocol::Dp, 1, LineRekey::None, true);
    let r = {
        let mut cx = Ctx {
            io: &regs,
            shim: &mut s,
            fw: Some(&mut fw),
            env: &mut env,
        };
        drive(link.enable(&mut cx, 0))
    };
    if let Some(bad) = fw.bad {
        return TestResult::Fail(bad);
    }
    if r != Some(Ok(())) || link.value != CpValue::Enabled || !link.hdcp2_encrypted {
        return TestResult::Fail("HDCP 2.2 enable over CP_IRQ failed");
    }
    if rx_status_reads(&s.dpcd) != 2
        || cp_irq_waits(&env) != 0
        || env.delays.contains(&shim::DP_POLL_MS)
    {
        return TestResult::Fail("H' / pairing not taken at their CP_IRQ");
    }
    // The sink asks for re-authentication and raises CP_IRQ.
    let mut card = crate::drm::card::Card::new("intel-gpu", "HDCP CP_IRQ", (1, 0, 0));
    card.connectors.push(crate::drm::card::Connector {
        id: 3,
        connector_type: crate::drm::card::ConnectorType::DisplayPort,
        connector_type_id: 1,
        status: crate::drm::card::ConnectorStatus::Connected,
        encoder_id: None,
        modes: Vec::new(),
    });
    let index = crate::drm_registry::register_drm_card_with_state(Arc::new(LiveCard), card);
    live::__attach_for_test(index);
    let key = live::xelpg_key(1, 1);
    let route = live::RouteDesc {
        key,
        protocol: Protocol::Dp,
        transcoder: 1,
        link: live::RouteLink::Dp(shim::AuxPort::XeLpdp {
            base: 0x16_4000,
            tbt_io: false,
        }),
        display_ver: 14,
        rekey: LineRekey::None,
        cp_irq: true,
        mst: live::MstStreams::default(),
    };
    live::__bind_for_test(index, 3, route, link.clone(), u64::MAX);
    s.dpcd.rx_status |= 1 << 3;
    if live::__cp_irq_for_test(key) != 1 || live::__next_check_for_test(index, 3) != Some(0) {
        return TestResult::Fail("CP_IRQ did not run the link check at once");
    }
    live::__reset_for_test();
    let r = {
        let mut cx = Ctx {
            io: &regs,
            shim: &mut s,
            fw: Some(&mut fw),
            env: &mut env,
        };
        drive(link.check_link(&mut cx))
    };
    if r != Some(Err(HdcpError::LinkStopped)) || link.value != CpValue::Desired {
        return TestResult::Fail("REAUTH_REQ did not take the link to DESIRED");
    }
    // Userspace commits DESIRED again: a fresh authentication, announced
    // by CP_IRQ as before.
    s.dpcd.rx_status = 0;
    let inits = fw.log.iter().filter(|&&c| c == 0x0003_1000).count();
    let reads = rx_status_reads(&s.dpcd);
    let r = {
        let mut cx = Ctx {
            io: &regs,
            shim: &mut s,
            fw: Some(&mut fw),
            env: &mut env,
        };
        drive(link.enable(&mut cx, 0))
    };
    if r != Some(Ok(()))
        || link.value != CpValue::Enabled
        || fw.log.iter().filter(|&&c| c == 0x0003_1000).count() != inits + 1
        || rx_status_reads(&s.dpcd) != reads + 2
        || cp_irq_waits(&env) != 0
    {
        return TestResult::Fail("re-authentication after the CP_IRQ failed");
    }
    // A lost CP_IRQ: H' (1 s unpaired) and pairing (200 ms) are waited out
    // in 1 ms steps, then RxStatus is read once each.
    let regs = Regs::new(1);
    let mut sink = DpSink::hdcp22(&d);
    sink.cp_irq = Some(0);
    let mut s = DpShim::new(sink);
    let mut fw = FwModel::new(&regs, 1, msg::HDCP_PROTOCOL_DP, Hdcp2Data::new(false));
    let mut env = Env::default();
    let mut link = HdcpLink::new(Protocol::Dp, 1, LineRekey::None, true);
    let r = {
        let mut cx = Ctx {
            io: &regs,
            shim: &mut s,
            fw: Some(&mut fw),
            env: &mut env,
        };
        drive(link.enable(&mut cx, 0))
    };
    if r != Some(Ok(())) || rx_status_reads(&s.dpcd) != 2 || cp_irq_waits(&env) < 1150 {
        return TestResult::Fail("a lost CP_IRQ did not wait out the timeouts");
    }
    TestResult::Pass
}

fn smoke_intel_hdcp22_dp_cp_irq() -> TestResult {
    hdcp22_dp_cp_irq()
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp22_dp_cp_irq);

/// An Intel card in the DRM registry for the live service's fixtures.
#[derive(Debug)]
struct LiveCard;
impl crate::drm_registry::DrmCard for LiveCard {
    fn name(&self) -> &str {
        "intel-hdcp-live-fixture"
    }
    fn driver(&self) -> &str {
        "intel-gpu"
    }
    fn vendor_id(&self) -> u16 {
        0xf00d
    }
    fn device_id(&self) -> u16 {
        0xcaff
    }
    fn subsystem_vendor(&self) -> u16 {
        0
    }
    fn subsystem_device(&self) -> u16 {
        0
    }
    fn vbios_version(&self) -> Option<&str> {
        None
    }
    fn gpu_busy_percent(&self) -> Option<u32> {
        None
    }
    fn power_state(&self) -> &str {
        "D0"
    }
}

/// The HDMI sink script for an HDCP 2.2 repeater with one device.
fn hdmi_repeater(d: &Hdcp2Data) -> HdmiSink {
    let mut s = HdmiSink::default();
    s.regs
        .insert(shim::HDCP_2_2_HDMI_REG_VER_OFFSET, vec![1 << 2]);
    let with_id = |id: u8, body: &[&[u8]]| {
        let mut m = vec![id];
        for b in body {
            m.extend_from_slice(b);
        }
        m
    };
    let mut recvid = vec![msg::REP_SEND_RECVID_LIST, 0x00, 0x10, 0, 0, 0];
    recvid.extend(&d.vprime);
    recvid.extend(KSV0);
    s.script = vec![
        (msg::AKE_INIT, vec![with_id(msg::AKE_SEND_CERT, &[&d.cert])]),
        (
            msg::AKE_NO_STORED_KM,
            vec![
                with_id(msg::AKE_SEND_HPRIME, &[&d.hprime]),
                with_id(msg::AKE_SEND_PAIRING_INFO, &[&d.pairing]),
            ],
        ),
        (
            msg::LC_INIT,
            vec![with_id(msg::LC_SEND_LPRIME, &[&d.lprime])],
        ),
        (msg::SKE_SEND_EKS, vec![recvid]),
        (
            msg::REP_STREAM_MANAGE,
            vec![with_id(msg::REP_STREAM_READY, &[&d.mprime])],
        ),
    ];
    s
}

fn hdcp22_hdmi_gsc() -> TestResult {
    let regs = Regs::new(1);
    let d = Hdcp2Data::new(true);
    let mut s = HdmiShim::new(hdmi_repeater(&d));
    let mut fw = FwModel::new(&regs, 1, msg::HDCP_PROTOCOL_HDMI, Hdcp2Data::new(true));
    fw.content_type = 1;
    let gsc = GscModel {
        fw,
        pending_once: true,
        handles: Vec::new(),
        sessions: Vec::new(),
        bad: None,
    };
    let mut framing = GscFraming::new(gsc, 0xffee_0000_1234_5678);
    let mut env = Env::default();
    let mut link = HdcpLink::new(Protocol::Hdmi, 1, LineRekey::TransDdi, true);
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: Some(&mut framing),
        env: &mut env,
    };
    let r = drive(link.enable(&mut cx, 1));
    let gsc = &framing.port;
    if let Some(bad) = gsc.bad.or(gsc.fw.bad) {
        return TestResult::Fail(bad);
    }
    if r != Some(Ok(())) || link.value != CpValue::Enabled || !link.hdcp2_encrypted {
        return TestResult::Fail("HDCP 2.2 HDMI repeater enable over the GSC failed");
    }
    // The first command came back pending: resubmitted with its handle.
    if gsc.handles.get(..2) != Some(&[0, GSC_HANDLE][..]) {
        return TestResult::Fail("pending GSC reply not resubmitted with its handle");
    }
    // One host session, client byte masked in (xe_gsc_create_host_session_id).
    if gsc
        .sessions
        .iter()
        .any(|&x| x != (0x00ee_0000_1234_5678 | 18 << 56))
    {
        return TestResult::Fail("host session id");
    }
    let want = [
        0x0003_1000,
        0x0003_1001,
        0x0003_1002,
        0x0003_1003,
        0x0003_1004,
        0x0003_1005,
        0x0003_1006,
        0x0003_1008,
        0x0003_1009,
        0x0003_1007,
    ];
    if gsc.fw.log != want {
        return TestResult::Fail("GSC firmware command order");
    }
    // HDMI messages whole, ids included: the ack and the stream manage.
    let w = &s.ddc.written;
    let mut ack = vec![msg::REP_SEND_ACK];
    ack.extend(&d.v);
    if w.len() != 6
        || w[4] != ack
        || w[5] != [msg::REP_STREAM_MANAGE, 0, 0, 0, 0, 1, 0, 1]
        || link.seq_num_m != 1
    {
        return TestResult::Fail("repeater ack / stream manage messages");
    }
    // HDCP 2.2 disables line rekeying (14.01 B0+ TRANS_DDI bit 12) and
    // signals on HDMI.
    let f = regs.get(trans_ddi_func_ctl(1));
    if f & TRANS_DDI_HDCP_LINE_REKEY_DISABLE == 0 || f & TRANS_DDI_HDCP_SIGNALLING == 0 {
        return TestResult::Fail("HDMI rekey / signalling bits");
    }
    TestResult::Pass
}

fn smoke_intel_hdcp22_hdmi_repeater_gsc() -> TestResult {
    hdcp22_hdmi_gsc()
}
kernel_test_in!(
    "drivers/gpu/intel_hdcp",
    smoke_intel_hdcp22_hdmi_repeater_gsc
);

fn hdcp22_fallback() -> TestResult {
    // No firmware: type 0 falls back to HDCP 1.4, type 1 is refused.
    let regs = Regs::new(0);
    let mut sink = DpSink::hdcp14(false);
    sink.put(shim::DP_HDCP_2_2_REG_RX_CAPS_OFFSET, &[2, 0, 2]);
    let mut s = DpShim::new(sink);
    let mut env = Env::default();
    let mut link = HdcpLink::new(Protocol::Dp, 0, LineRekey::None, true);
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: None::<&mut FwModel>,
        env: &mut env,
    };
    if drive(link.enable(&mut cx, 1)) != Some(Err(HdcpError::Type1Unavailable)) {
        return TestResult::Fail("type 1 without HDCP 2.2 not refused");
    }
    if drive(link.enable(&mut cx, 0)) != Some(Ok(())) || !link.hdcp_encrypted {
        return TestResult::Fail("type 0 did not fall back to HDCP 1.4");
    }
    // The firmware rejects H' every time: three tries, each closing its
    // session, then HDCP 1.4.
    let regs = Regs::new(0);
    let d = Hdcp2Data::new(false);
    let mut sink = DpSink::hdcp22(&d);
    sink.put(shim::DP_AUX_HDCP_BKSV, &BKSV);
    sink.put(shim::DP_AUX_HDCP_RI_PRIME, &RI);
    sink.put(shim::DP_AUX_HDCP_BCAPS, &[shim::DP_BCAPS_HDCP_CAPABLE]);
    let mut s = DpShim::new(sink);
    let mut fw = FwModel::new(&regs, 0, msg::HDCP_PROTOCOL_DP, Hdcp2Data::new(false));
    // FW_HDCP_H_VERIFICATION_FAILED.
    fw.fail = Some((0x0003_1002, 0x6008, 3));
    let mut link = HdcpLink::new(Protocol::Dp, 0, LineRekey::None, true);
    let mut cx = Ctx {
        io: &regs,
        shim: &mut s,
        fw: Some(&mut fw),
        env: &mut env,
    };
    let r = drive(link.enable(&mut cx, 0));
    let closes = fw.log.iter().filter(|&&c| c == 0x0003_100a).count();
    let hprimes = fw.log.iter().filter(|&&c| c == 0x0003_1002).count();
    if r != Some(Ok(())) || !link.hdcp_encrypted || link.hdcp2_encrypted {
        return TestResult::Fail("H' failure did not fall back to HDCP 1.4");
    }
    if hprimes != 3 || closes != 3 {
        return TestResult::Fail("H' failure not retried three times with session close");
    }
    if HdcpError::Fw(msg::FwError::Status(0x6008)).errno() != -5 {
        return TestResult::Fail("a firmware status is not -EIO");
    }
    TestResult::Pass
}

fn smoke_intel_hdcp22_fallback_and_type1() -> TestResult {
    hdcp22_fallback()
}
kernel_test_in!(
    "drivers/gpu/intel_hdcp",
    smoke_intel_hdcp22_fallback_and_type1
);

// ── The property state machine ───────────────────────────────────────

fn smoke_intel_hdcp_property_state_machine() -> TestResult {
    let mut link = HdcpLink::new(Protocol::Dp, 0, LineRekey::None, true);
    let u = |cp, content_type| Uapi { cp, content_type };
    // drm_atomic_connector_set_property: only drivers set ENABLED.
    if uapi_set(2).is_some() || uapi_set(3).is_some() || uapi_set(1) != Some(CpValue::Desired) {
        return TestResult::Fail("userspace may set ENABLED or out-of-range values");
    }
    // UNDESIRED -> DESIRED enables.
    if update_pipe(&link, u(CpValue::Desired, 0))
        != (Commit::Enable {
            disable_first: false,
        })
    {
        return TestResult::Fail("DESIRED does not enable");
    }
    // DESIRED -> ENABLED reported by the driver.
    let mut uapi = u(CpValue::Desired, 0);
    link.value = CpValue::Enabled;
    if !report(&mut uapi, link.value) || uapi.cp != CpValue::Enabled {
        return TestResult::Fail("ENABLED not reported");
    }
    // A DESIRED commit on an enabled link re-reports ENABLED.
    if update_pipe(&link, u(CpValue::Desired, 0)) != Commit::Report {
        return TestResult::Fail("DESIRED on ENABLED is not a report");
    }
    // A type change disables, then enables.
    if update_pipe(&link, u(CpValue::Desired, 1))
        != (Commit::Enable {
            disable_first: true,
        })
    {
        return TestResult::Fail("type change not disable + enable");
    }
    // Link loss: the driver says DESIRED, which reaches userspace.
    link.value = CpValue::Desired;
    if !report(&mut uapi, link.value) || uapi.cp != CpValue::Desired {
        return TestResult::Fail("ENABLED -> DESIRED not reported");
    }
    // UNDESIRED is userspace's own: never reported by the driver.
    link.value = CpValue::Undesired;
    if report(&mut uapi, link.value) {
        return TestResult::Fail("UNDESIRED reported");
    }
    // UNDESIRED disables an enabled link and keeps an idle one.
    link.value = CpValue::Enabled;
    if update_pipe(&link, u(CpValue::Undesired, 0)) != Commit::Disable {
        return TestResult::Fail("UNDESIRED does not disable");
    }
    link.value = CpValue::Undesired;
    if update_pipe(&link, u(CpValue::Undesired, 0)) != Commit::Keep {
        return TestResult::Fail("idle UNDESIRED not kept");
    }
    // A route that goes away turns ENABLED into DESIRED; a route that
    // comes back enables DESIRED (and ENABLED the driver did not enable).
    let mut uapi = u(CpValue::Enabled, 0);
    route_lost(&mut uapi);
    if uapi.cp != CpValue::Desired || !enable_on_route(&link, uapi) {
        return TestResult::Fail("route loss / return");
    }
    if !enable_on_route(&link, u(CpValue::Enabled, 0))
        || enable_on_route(&link, u(CpValue::Undesired, 0))
    {
        return TestResult::Fail("intel_hdcp_enable condition");
    }
    // force_off: registers off, DESIRED, session flagged.
    let regs = Regs::new(3);
    regs.set_bits(trans_hdcp2_ctl(3), CTL_LINK_ENCRYPTION_REQ);
    regs.set_bits(trans_ddi_func_ctl(3), TRANS_DDI_HDCP_SIGNALLING);
    let mut link = HdcpLink::new(Protocol::Hdmi, 3, LineRekey::None, true);
    link.value = CpValue::Enabled;
    link.hdcp2_encrypted = true;
    if !link.force_off(&regs)
        || link.value != CpValue::Desired
        || regs.get(trans_hdcp2_ctl(3)) & CTL_LINK_ENCRYPTION_REQ != 0
        || regs.get(trans_ddi_func_ctl(3)) & TRANS_DDI_HDCP_SIGNALLING != 0
        || regs.wrote(trans_hdcp_conf(3)) != [0]
    {
        return TestResult::Fail("force_off");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_hdcp",
    smoke_intel_hdcp_property_state_machine
);

fn smoke_intel_hdcp_srm() -> TestResult {
    // HDCP 1.x SRM: header, VRL length 3 + 11 + 40, one VRL of two KSVs.
    let mut v1 = vec![0x80, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 54, 2];
    v1.extend(KSV0);
    v1.extend(KSV1);
    v1.extend([0; 40]);
    let Some(srm) = Srm::parse(&v1) else {
        return TestResult::Fail("HDCP 1.x SRM refused");
    };
    if srm.revoked != [KSV0, KSV1] || srm.revoked_count(&[BKSV, KSV1].concat()) != 1 {
        return TestResult::Fail("HDCP 1.x SRM KSVs");
    }
    // A VRL count that overruns: the SRM's KSVs are discarded.
    let mut bad = v1.clone();
    bad[8] = 3;
    if Srm::parse(&bad).map(|s| s.revoked.len()) != Some(0) {
        return TestResult::Fail("invalid VRLs not discarded");
    }
    // HDCP 2.x SRM: id 0x91, one receiver ID (count 10 bits split 8 + 2).
    let mut v2 = vec![
        0x91, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x8c, 0x00, 0x40, 0, 0,
    ];
    v2.extend(KSV0);
    v2.extend([0; 384]);
    if Srm::parse(&v2).map(|s| s.revoked) != Some(vec![KSV0]) {
        return TestResult::Fail("HDCP 2.x SRM");
    }
    // Unknown id, short blob, nonzero 2.x reserved byte.
    let mut reserved = v2.clone();
    reserved[1] = 1;
    if Srm::parse(&[0x70; 60]).is_some()
        || Srm::parse(&v1[..20]).is_some()
        || Srm::parse(&reserved).is_some()
    {
        return TestResult::Fail("malformed SRM accepted");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp_srm);

// ── Transports ───────────────────────────────────────────────────────

fn smoke_intel_hdcp_aksv_transports() -> TestResult {
    use crate::dp_aux::AuxChannel;
    use crate::intel_gpu_aux::tests::MockMmio;
    use crate::intel_gpu_aux::{IntelAux, AUX_CTL_AKSV_SELECT, AUX_CTL_DONE, DDI_AUX_CTL_OFFSET};
    use crate::intel_gpu_ddi::Ddi;
    // DP: only a native write to DP_AUX_HDCP_AKSV carries AKSV_SELECT.
    let mmio = MockMmio::default();
    mmio.set_read(Ddi::B.base() + DDI_AUX_CTL_OFFSET, AUX_CTL_DONE | 1 << 20);
    let mut aux = IntelAux::new(&mmio, Ddi::B);
    if aux.dpcd_write(shim::DP_AUX_HDCP_AN, &[0; 8]).is_err()
        || aux.dpcd_write(shim::DP_AUX_HDCP_AKSV, &[0; 5]).is_err()
    {
        return TestResult::Fail("AUX writes failed against the mock");
    }
    let sends: Vec<u32> = mmio
        .writes_to(Ddi::B.base() + DDI_AUX_CTL_OFFSET)
        .into_iter()
        .filter(|v| v & (1 << 31) != 0)
        .collect();
    if sends.len() != 2
        || sends[0] & AUX_CTL_AKSV_SELECT != 0
        || sends[1] & AUX_CTL_AKSV_SELECT == 0
    {
        return TestResult::Fail("AKSV_SELECT not exactly on the Aksv write");
    }
    // HDMI: GMBUS index write of 0x10 to 0x3A, five bytes, AKSV source.
    use crate::intel_gpu_gmbus::*;
    struct Gm(IrqSafeSpinLock<Vec<(u64, u32)>>);
    impl MmioWindow for Gm {
        fn read32(&self, off: u64) -> u32 {
            if off == GMBUS2 {
                GMBUS2_HW_RDY | GMBUS2_HW_WAIT_PHASE
            } else {
                0
            }
        }
        fn write32(&self, off: u64, val: u32) {
            self.0.lock().push((off, val));
        }
    }
    let gm = Gm(IrqSafeSpinLock::new(Vec::new()));
    let bus = GmbusBus::new(&gm, PinPair::Pin2Bxt);
    if bus.output_aksv().is_err() {
        return TestResult::Fail("output_aksv failed against the mock");
    }
    let w = gm.0.lock().clone();
    let g0: Vec<u32> = w.iter().filter(|x| x.0 == GMBUS0).map(|x| x.1).collect();
    let g1: Vec<u32> = w.iter().filter(|x| x.0 == GMBUS1).map(|x| x.1).collect();
    if g0.first().map(|v| v & GMBUS0_AKSV_SELECT) != Some(GMBUS0_AKSV_SELECT)
        || g1.first()
            != Some(
                &(GMBUS1_SW_RDY
                    | GMBUS1_CYCLE_INDEX
                    | gmbus1_index_byte(0x10)
                    | GMBUS1_CYCLE_WAIT
                    | gmbus1_byte_count(5)
                    | gmbus1_slave_addr(0x3A)),
            )
    {
        return TestResult::Fail("GMBUS Aksv program");
    }
    // A 534-byte DDC read (AKE_Send_Cert) runs as 511 + 23 byte phases.
    gm.0.lock().clear();
    let mut cert = vec![0u8; 534];
    if bus.read_indexed(0x3A, 0x80, &mut cert).is_err() {
        return TestResult::Fail("long DDC read failed against the mock");
    }
    let counts: Vec<u32> =
        gm.0.lock()
            .iter()
            .filter(|x| x.0 == GMBUS1 && x.1 & GMBUS1_SW_RDY != 0 && x.1 & GMBUS1_DIR_READ != 0)
            .map(|x| (x.1 >> 16) & 0x1ff)
            .collect();
    if counts != [511, 23] {
        return TestResult::Fail("long GMBUS read not split at 511 bytes");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_hdcp", smoke_intel_hdcp_aksv_transports);

// ── Refusals ─────────────────────────────────────────────────────────

fn smoke_intel_hdcp_refusals_without_option() -> TestResult {
    // The fixture kernel boots without narf.intel.hdcp=1.
    if live::enabled() || opted_in() {
        return TestResult::Skip("narf.intel.hdcp=1 on the test command line");
    }
    live::__reset_for_test();
    let bar = narf_bus::MmioRegion {
        phys: narf_memory::PhysAddr::new(0x1000_0000),
        virt: 0x1000_0000,
        len: 16 << 20,
        kind: narf_bus::BarKind::Mmio64 {
            prefetchable: false,
        },
    };
    // Inert: nothing attached, no register touched on a route stop.
    live::service(&bar);
    let regs = Regs::new(0);
    live::route_stopping(&regs, live::gen12_key(crate::intel_gpu_ddi::Ddi::B));
    if live::__connector_count() != 0 || !regs.0.lock().writes.is_empty() {
        return TestResult::Fail("HDCP acted without its option");
    }
    // A request for a connector without the property changes nothing.
    live::request(0, 3, 1, 0);
    if live::last_error(0, 3).is_some() || live::__connector_count() != 0 {
        return TestResult::Fail("request without an attached connector");
    }
    // The firmware-route readout: platform, MST, two outputs.
    use crate::intel_gpu_gt::Gen12Platform as P;
    let regs = Regs::new(0);
    let func = |sel: u32, mode: u32| (1u32 << 31) | (sel << 27) | (mode << 24);
    if live::inherited_gen12_route(&regs, P::RocketLake) != Err(HdcpError::Unsupported) {
        return TestResult::Fail("Rocket Lake readout not refused");
    }
    if live::inherited_gen12_route(&regs, P::AlderLakeP) != Ok(None) {
        return TestResult::Fail("dark display found a route");
    }
    regs.write32(trans_ddi_func_ctl(0), func(2, 3));
    if live::inherited_gen12_route(&regs, P::AlderLakeP) != Err(HdcpError::Unsupported) {
        return TestResult::Fail("MST route not refused");
    }
    // HDMI on DDI B (select 2), pin 2.
    regs.write32(trans_ddi_func_ctl(0), func(2, 0));
    let Ok(Some(r)) = live::inherited_gen12_route(&regs, P::AlderLakeP) else {
        return TestResult::Fail("firmware HDMI route not read back");
    };
    if r.protocol != Protocol::Hdmi
        || r.transcoder != 0
        || r.link != live::RouteLink::Hdmi(crate::intel_gpu_gmbus::PinPair::Pin2Bxt)
        || r.key != live::gen12_key(crate::intel_gpu_ddi::Ddi::B)
    {
        return TestResult::Fail("firmware HDMI route fields");
    }
    // DP on a Type-C DDI (TC1, select 4): refused before any AUX.
    regs.write32(trans_ddi_func_ctl(0), func(4, 2));
    if live::inherited_gen12_route(&regs, P::AlderLakeP) != Err(HdcpError::Unsupported) {
        return TestResult::Fail("Type-C DP readout not refused");
    }
    // Two lit transcoders: no single route.
    regs.write32(trans_ddi_func_ctl(0), func(2, 0));
    regs.write32(trans_ddi_func_ctl(1), func(4, 0));
    if live::inherited_gen12_route(&regs, P::AlderLakeP) != Err(HdcpError::NoRoute) {
        return TestResult::Fail("two firmware routes not refused");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_hdcp",
    smoke_intel_hdcp_refusals_without_option
);

#[path = "intel_hdcp_mst_tests.rs"]
mod mst_tests;
