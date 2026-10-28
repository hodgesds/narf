//! WLFW handshake tests: a scripted fake WCN6855 firmware behind a
//! fake QRTR/MHI pipe runs the whole of `ath11k_qmi_driver_event_work`
//! from the device's HELLO to FW_READY and `firmware_start`, and every
//! request the host sends is compared byte for byte.
//!
//! Oracles: the `qmi_wlfw` encoders (each pinned to output of Linux's
//! own `qmi_encdec.c` in `qmi_tests.rs`), two of those Linux goldens
//! inlined here (ind_register, host_cap), board-name strings written
//! out by hand from the `scnprintf` formats of
//! `__ath11k_core_create_board_name`, and QRTR frames from the
//! `af_qrtr.c` header layout.

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use narf_kernel_test::{kernel_test_in, TestResult};

use super::board::*;
use super::hw::HwRev;
use super::qmi::*;
use super::qmi_client::*;
use super::qmi_wlfw::*;
use super::qrtr::*;
use super::wlfw::*;

type R = Result<(), &'static str>;

fn run_test(f: impl FnOnce() -> R) -> TestResult {
    match f() {
        Ok(()) => TestResult::Pass,
        Err(m) => TestResult::Fail(m),
    }
}

macro_rules! ensure {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            return Err($msg);
        }
    };
}

/// Drive a future whose waits are all immediately ready.
fn block<F: Future>(f: F) -> F::Output {
    let mut f = pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..64 {
        if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
    panic!("handshake future did not complete");
}

// ── fake firmware ─────────────────────────────────────────────────

const DEV_NODE: u32 = 3;
const SRV_PORT: u32 = 1;
const HOST: QrtrAddr = QrtrAddr {
    node: 1,
    port: QRTR_MIN_EPH_SOCKET,
};
const SRV: QrtrAddr = QrtrAddr {
    node: DEV_NODE,
    port: SRV_PORT,
};
const DEV_CTRL: QrtrAddr = QrtrAddr {
    node: DEV_NODE,
    port: QRTR_PORT_CTRL,
};
const HOST_CTRL: QrtrAddr = QrtrAddr {
    node: 1,
    port: QRTR_PORT_CTRL,
};

/// How the firmware answers one request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Reply {
    /// The default reply (and its side effects).
    Normal,
    /// `{FAILURE, error}` response, no side effects.
    Fail(u16),
    /// Never answer.
    Silent,
    /// A response whose TLV stream does not decode.
    Garbage,
    /// Answer, then announce DEL_SERVER.
    ThenDelServer,
}

#[derive(Clone, Debug)]
struct Script {
    hello: bool,
    announce: bool,
    instance: u32,
    mem_rounds: Vec<Vec<MemSeg>>,
    cap: CapResp,
    /// `(msg_id, nth occurrence starting at 0, reply)`.
    overrides: Vec<(u16, usize, Reply)>,
    fw_ready: bool,
    init_done: bool,
    ack_flow: bool,
    /// Send REQUEST_MEM before the host_cap response.
    early_mem_ind: bool,
    /// Send a stray response (wrong txn) before each real one.
    stray_responses: bool,
}

fn seg(size: u32, mem_type: i32) -> MemSeg {
    MemSeg {
        size,
        mem_type,
        mem_cfg: Vec::new(),
    }
}

impl Script {
    fn wcn6855() -> Self {
        Self {
            hello: true,
            announce: true,
            instance: qmi_instance(1, 1),
            mem_rounds: vec![vec![
                seg(0x18_0000, QMI_WLANFW_MEM_TYPE_DDR_V01),
                seg(0x4_0000, QMI_WLANFW_MEM_CAL_V01),
                seg(0x2_0000, QMI_WLANFW_MEM_M3_V01),
            ]],
            cap: CapResp {
                resp: QmiResponse::default(),
                chip_info: Some(RfChipInfo {
                    chip_id: 2,
                    chip_family: 4,
                }),
                board_id: Some(0xff),
                soc_id: Some(0x400c_1211),
                fw_version_info: Some(FwVersionInfo {
                    fw_version: 0x1105_811b,
                    fw_build_timestamp: b"2024-01-01 00:00".to_vec(),
                }),
                fw_build_id: Some(b"QC_IMAGE_VERSION_STRING=WLAN.HSP.1.1-03125".to_vec()),
                num_macs: None,
                voltage_mv: None,
                time_freq_hz: None,
                otp_version: None,
                eeprom_read_timeout: None,
            },
            overrides: Vec::new(),
            fw_ready: true,
            init_done: false,
            ack_flow: true,
            early_mem_ind: false,
            stray_responses: false,
        }
    }
}

struct FakeFw {
    s: Script,
    out: VecDeque<Vec<u8>>,
    /// QMI messages the host sent to the server, in order.
    reqs: Vec<Vec<u8>>,
    /// Every UL frame.
    ul: Vec<Vec<u8>>,
    counts: BTreeMap<u16, usize>,
    mem_round: usize,
    host_hello: bool,
    /// Host frames sent before the device's HELLO.
    early_tx: usize,
    hello_sent: bool,
}

impl FakeFw {
    fn new(s: Script) -> Self {
        let mut f = Self {
            s,
            out: VecDeque::new(),
            reqs: Vec::new(),
            ul: Vec::new(),
            counts: BTreeMap::new(),
            mem_round: 0,
            host_hello: false,
            early_tx: 0,
            hello_sent: false,
        };
        if f.s.hello {
            f.ctrl(CtrlPkt::Hello);
            f.hello_sent = true;
        }
        f
    }

    fn ctrl(&mut self, pkt: CtrlPkt) {
        let f = encode_packet(pkt.cmd(), DEV_CTRL, HOST_CTRL, false, &pkt.to_bytes()).unwrap();
        self.out.push_back(f);
    }

    fn data(&mut self, qmi: Vec<u8>) {
        self.out
            .push_back(encode_packet(QRTR_TYPE_DATA, SRV, HOST, false, &qmi).unwrap());
    }

    fn resp(&mut self, msg_id: u16, txn: u16, payload: &[u8]) {
        if self.s.stray_responses {
            self.data(encode_message(
                QMI_RESPONSE,
                msg_id,
                txn.wrapping_add(7),
                &[0x02, 0x04, 0x00, 0x01, 0x00, 0x05, 0x00],
            ));
        }
        self.data(encode_message(QMI_RESPONSE, msg_id, txn, payload));
    }

    fn ind(&mut self, msg_id: u16, payload: &[u8]) {
        self.data(encode_message(QMI_INDICATION, msg_id, 0, payload));
    }

    fn mem_ind(&mut self) {
        let Some(round) = self.s.mem_rounds.get(self.mem_round).cloned() else {
            return;
        };
        let mut w = TlvWriter::new(QMI_WLANFW_REQUEST_MEM_IND_MSG_V01_MAX_LEN);
        RequestMemInd { mem_seg: round }.write(&mut w).unwrap();
        let p = w.finish().unwrap();
        self.ind(QMI_WLFW_REQUEST_MEM_IND_V01, &p);
    }

    fn host_frame(&mut self, frame: &[u8]) {
        self.ul.push(frame.to_vec());
        if !self.hello_sent {
            self.early_tx += 1;
        }
        let p = decode_packet(frame).expect("host sent an invalid QRTR frame");
        if p.dst_port == QRTR_PORT_CTRL {
            if let Ok(CtrlPkt::Hello) = CtrlPkt::parse(p.payload) {
                self.host_hello = true;
                if self.s.announce {
                    self.ctrl(CtrlPkt::NewServer {
                        service: ATH11K_QMI_WLFW_SERVICE_ID_V01,
                        instance: self.s.instance,
                        node: DEV_NODE,
                        port: SRV_PORT,
                    });
                }
            }
            return;
        }
        if p.pkt_type != QRTR_TYPE_DATA || p.dst_port != SRV_PORT {
            return;
        }
        if p.confirm_rx && self.s.ack_flow {
            // qrtr_recvmsg → qrtr_send_resume_tx from the server port.
            let r = CtrlPkt::ResumeTx {
                node: DEV_NODE,
                port: SRV_PORT,
            };
            self.out.push_back(
                encode_packet(
                    QRTR_TYPE_RESUME_TX,
                    SRV,
                    QrtrAddr {
                        node: p.src_node,
                        port: p.src_port,
                    },
                    false,
                    &r.to_bytes(),
                )
                .unwrap(),
            );
        }
        let qmi = p.payload.to_vec();
        self.reqs.push(qmi.clone());
        let (hdr, payload) = split_message(&qmi).unwrap();
        self.on_request(hdr.msg_id, hdr.txn_id, payload);
    }

    fn on_request(&mut self, msg_id: u16, txn: u16, payload: &[u8]) {
        let n = *self.counts.get(&msg_id).unwrap_or(&0);
        self.counts.insert(msg_id, n + 1);
        let reply = self
            .s
            .overrides
            .iter()
            .find(|(m, k, _)| *m == msg_id && *k == n)
            .map(|o| o.2)
            .unwrap_or(Reply::Normal);
        const OK: [u8; 7] = [0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];
        match reply {
            Reply::Silent => return,
            Reply::Fail(err) => {
                let e = err.to_le_bytes();
                self.resp(msg_id, txn, &[0x02, 0x04, 0x00, 0x01, 0x00, e[0], e[1]]);
                return;
            }
            Reply::Garbage => {
                // TLV 0x03 is unknown and below 0x10: qmi_decode -EINVAL.
                self.resp(msg_id, txn, &[0x03, 0x01, 0x00, 0x00]);
                return;
            }
            Reply::Normal | Reply::ThenDelServer => {}
        }
        match msg_id {
            QMI_WLANFW_HOST_CAP_REQ_V01 => {
                if self.s.early_mem_ind {
                    self.mem_ind();
                    self.resp(msg_id, txn, &OK);
                } else {
                    self.resp(msg_id, txn, &OK);
                    self.mem_ind();
                }
            }
            QMI_WLANFW_RESPOND_MEM_REQ_V01 => {
                // payload: 0x01, len, count, ...
                let delayed = payload.len() >= 4 && payload[3] == 0;
                if delayed {
                    // Firmware refuses an empty list with error 0.
                    self.resp(msg_id, txn, &[0x02, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00]);
                } else {
                    self.resp(msg_id, txn, &OK);
                }
                self.mem_round += 1;
                if self.mem_round < self.s.mem_rounds.len() {
                    self.mem_ind();
                } else {
                    self.ind(QMI_WLFW_FW_MEM_READY_IND_V01, &[]);
                }
            }
            QMI_WLANFW_CAP_REQ_V01 => {
                let mut w = TlvWriter::new(QMI_WLANFW_CAP_RESP_MSG_V01_MAX_LEN);
                self.s.cap.write(&mut w).unwrap();
                let p = w.finish().unwrap();
                self.resp(msg_id, txn, &p);
            }
            QMI_WLANFW_M3_INFO_REQ_V01 => {
                self.resp(msg_id, txn, &OK);
                if self.s.init_done {
                    self.ind(QMI_WLFW_FW_INIT_DONE_IND_V01, &[]);
                }
                if self.s.fw_ready {
                    self.ind(QMI_WLFW_FW_READY_IND_V01, &[]);
                }
            }
            _ => self.resp(msg_id, txn, &OK),
        }
        if reply == Reply::ThenDelServer {
            self.ctrl(CtrlPkt::DelServer {
                service: ATH11K_QMI_WLFW_SERVICE_ID_V01,
                instance: self.s.instance,
                node: DEV_NODE,
                port: SRV_PORT,
            });
        }
    }

    fn msg_ids(&self) -> Vec<u16> {
        self.reqs
            .iter()
            .map(|m| u16::from_le_bytes([m[3], m[4]]))
            .collect()
    }
}

struct FakePipe {
    fw: FakeFw,
    now: u64,
    logs: RefCell<Vec<String>>,
}

impl QrtrPipe for FakePipe {
    fn send(&mut self, frame: &[u8]) -> Result<(), i32> {
        self.fw.host_frame(frame);
        Ok(())
    }
    fn poll(&mut self) {}
    fn recv(&mut self) -> Option<Vec<u8>> {
        self.fw.out.pop_front()
    }
    fn wait(&mut self, ms: u32) -> impl Future<Output = ()> + Send {
        self.now += ms as u64;
        core::future::ready(())
    }
    fn now_ms(&self) -> u64 {
        self.now
    }
    fn log(&self, args: core::fmt::Arguments<'_>) {
        self.logs.borrow_mut().push(format!("{}", args));
    }
    fn power_cycle(
        &mut self,
    ) -> impl Future<Output = Result<(), super::mhi_host::MhiError>> + Send {
        // The device boots its firmware again and says HELLO.
        let s = self.fw.s.clone();
        self.fw = FakeFw::new(s);
        self.logs.borrow_mut().push(String::from("power cycle"));
        core::future::ready(Ok(()))
    }
}

#[derive(Default)]
struct FakeFiles {
    files: BTreeMap<String, Vec<u8>>,
    requested: Vec<String>,
}

impl FakeFiles {
    fn add(&mut self, file: &str, data: Vec<u8>) {
        self.files
            .insert(format!("ath11k/WCN6855/hw2.1/{}", file), data);
    }
}

impl FirmwareLoader for FakeFiles {
    type Blob = Vec<u8>;
    fn request(&mut self, path: &str) -> Result<Vec<u8>, i32> {
        self.requested.push(String::from(path));
        self.files.get(path).cloned().ok_or(ENOENT)
    }
}

#[derive(Debug)]
struct FakeMem {
    addr: u64,
    size: usize,
    data: Vec<u8>,
}

impl CoherentMem for FakeMem {
    fn dma_addr(&self) -> u64 {
        self.addr
    }
    fn size(&self) -> usize {
        self.size
    }
    fn write(&mut self, off: usize, data: &[u8]) {
        self.data[off..off + data.len()].copy_from_slice(data);
    }
    fn bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Buddy-like: power-of-two pages, aligned to their size, below 4 GiB.
struct FakeDma {
    next: u64,
    fail_above: usize,
    allocs: Vec<usize>,
}

impl FakeDma {
    fn new() -> Self {
        Self {
            next: 0x1000_0000,
            fail_above: 4 << 20,
            allocs: Vec::new(),
        }
    }
}

impl DmaAllocator for FakeDma {
    type Mem = FakeMem;
    fn alloc_coherent(&mut self, size: usize) -> Option<FakeMem> {
        self.allocs.push(size);
        if size == 0 || size > self.fail_above {
            return None;
        }
        let bytes = (size.div_ceil(4096).next_power_of_two() * 4096) as u64;
        let addr = (self.next + bytes - 1) & !(bytes - 1);
        self.next = addr + bytes;
        Some(FakeMem {
            addr,
            size: bytes as usize,
            data: vec![0; size],
        })
    }
}

// ── fixtures ──────────────────────────────────────────────────────

/// `bus=pci,vendor=17cb,device=1103,subsystem-vendor=17aa,
/// subsystem-device=9309,qmi-chip-id=2,qmi-board-id=255` — written out
/// from the `ATH11K_BDF_NAME_FULL` format string by hand.
const LAPTOP_NAME: &str = "bus=pci,vendor=17cb,device=1103,subsystem-vendor=17aa,\
subsystem-device=9309,qmi-chip-id=2,qmi-board-id=255";

fn elf_blob(len: usize, seed: u8) -> Vec<u8> {
    let mut v: Vec<u8> = (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect();
    v[..4].copy_from_slice(b"\x7fELF");
    v
}

fn bin_blob(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(seed) | 1)
        .collect()
}

fn board2(board: &[u8], regdb: &[u8]) -> Vec<u8> {
    build_board2(&[
        (
            ATH11K_BD_IE_BOARD,
            vec![
                (ATH11K_BD_IE_BOARD_NAME, b"bus=pci,qmi-chip-id=9".to_vec()),
                (ATH11K_BD_IE_BOARD_DATA, bin_blob(64, 9)),
            ],
        ),
        (
            ATH11K_BD_IE_BOARD,
            vec![
                (ATH11K_BD_IE_BOARD_NAME, LAPTOP_NAME.as_bytes().to_vec()),
                (ATH11K_BD_IE_BOARD_DATA, board.to_vec()),
            ],
        ),
        (
            ATH11K_BD_IE_REGDB,
            vec![
                (ATH11K_BD_IE_REGDB_NAME, b"bus=pci".to_vec()),
                (ATH11K_BD_IE_REGDB_DATA, regdb.to_vec()),
            ],
        ),
    ])
}

fn config() -> WlfwConfig {
    WlfwConfig::pci(
        HwRev::Wcn6855Hw21,
        0x17cb,
        0x1103,
        0x17aa,
        0x9309,
        String::from("0000:03:00.0"),
        Vec::new(),
    )
    .unwrap()
}

fn hw() -> WlfwHwParams {
    wlfw_hw_params(HwRev::Wcn6855Hw21).unwrap()
}

fn standard_files(board: &[u8], regdb: &[u8], m3: &[u8]) -> FakeFiles {
    let mut f = FakeFiles::default();
    f.add("board-2.bin", board2(board, regdb));
    f.add("m3.bin", m3.to_vec());
    f
}

type W<A> = Wlfw<FakePipe, FakeFiles, A>;

fn wlfw_with<A: DmaAllocator>(s: Script, files: FakeFiles, dma: A, cfg: WlfwConfig) -> W<A> {
    let pipe = FakePipe {
        fw: FakeFw::new(s),
        now: 0,
        logs: RefCell::new(Vec::new()),
    };
    Wlfw::new(pipe, files, dma, cfg).unwrap()
}

fn wlfw(s: Script, files: FakeFiles) -> W<FakeDma> {
    wlfw_with(s, files, FakeDma::new(), config())
}

fn enc<T: WlfwRequest>(m: &T, txn: u16) -> Vec<u8> {
    m.encode(txn).unwrap()
}

/// Linux golden (qmi_tests oracle E4) with the txn bytes set.
fn ind_register_golden(txn: u16) -> Vec<u8> {
    let t = txn.to_le_bytes();
    vec![
        0x00, t[0], t[1], 0x20, 0x00, 0x1b, 0x00, 0x10, 0x01, 0x00, 0x01, 0x15, 0x04, 0x00, 0x4c,
        0x45, 0x4e, 0x4b, 0x16, 0x01, 0x00, 0x01, 0x17, 0x01, 0x00, 0x01, 0x18, 0x01, 0x00, 0x01,
        0x1b, 0x01, 0x00, 0x01,
    ]
}

/// Linux golden (qmi_tests oracle E1): WCN6855 HW2.1 host_cap, txn 1,
/// `cal_done = 0`.
const HOST_CAP_TXN1: [u8; 38] = [
    0x00, 0x01, 0x00, 0x34, 0x00, 0x1f, 0x00, 0x10, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x01,
    0x00, 0x1e, 0x14, 0x01, 0x00, 0x01, 0x16, 0x01, 0x00, 0x01, 0x17, 0x01, 0x00, 0x01, 0x1a, 0x01,
    0x00, 0x00, 0x1c, 0x01, 0x00, 0x00,
];

/// The requests a full WCN6855 bring-up sends, from `txn` 0.
fn expected_sequence(
    mem: &[(u64, u32, i32)],
    regdb: &[u8],
    board: &[u8],
    board_id: u32,
    m3_addr: u64,
    m3_len: u32,
) -> Vec<Vec<u8>> {
    expected_sequence_from(0, 0, mem, regdb, board, board_id, m3_addr, m3_len)
}

/// [`expected_sequence`] from transaction `txn0` with host_cap's
/// `cal_done` (a recovery handshake runs with the handle's next ids and
/// `cal_done = 1`).
#[allow(clippy::too_many_arguments)]
fn expected_sequence_from(
    txn0: u16,
    cal_done: u8,
    mem: &[(u64, u32, i32)],
    regdb: &[u8],
    board: &[u8],
    board_id: u32,
    m3_addr: u64,
    m3_len: u32,
) -> Vec<Vec<u8>> {
    let hw = hw();
    let mut v = Vec::new();
    let mut txn = txn0;
    let push = |m: Vec<u8>, v: &mut Vec<Vec<u8>>| v.push(m);
    push(enc(&IndRegisterReq::ath11k(&hw), txn), &mut v);
    txn += 1;
    push(enc(&HostCapReq::ath11k(&hw, cal_done), txn), &mut v);
    txn += 1;
    let segs = mem
        .iter()
        .map(|&(addr, size, mem_type)| MemSegResp {
            addr,
            size,
            mem_type,
            restore: 0,
        })
        .collect();
    push(enc(&RespondMemReq { mem_seg: segs }, txn), &mut v);
    txn += 1;
    push(enc(&CapReq, txn), &mut v);
    txn += 1;
    for r in bdf_segments(regdb, board_id, ATH11K_QMI_BDF_TYPE_REGDB) {
        push(enc(&r, txn), &mut v);
        txn += 1;
    }
    let sent = &board[..board.len().min(256 * 1024)];
    for r in bdf_segments(sent, board_id, bdf_type_for(board, false)) {
        push(enc(&r, txn), &mut v);
        txn += 1;
    }
    push(
        enc(
            &M3InfoReq {
                addr: m3_addr,
                size: m3_len,
            },
            txn,
        ),
        &mut v,
    );
    v
}

// ══ the full handshake ═══════════════════════════════════════════

fn smoke_wlfw_handshake_wcn6855_full() -> TestResult {
    run_test(|| {
        let board = elf_blob(13_000, 1);
        let regdb = bin_blob(7_000, 2);
        let m3 = bin_blob(150_000, 3);
        let mut w = wlfw(Script::wcn6855(), standard_files(&board, &regdb, &m3));
        let info = block(w.run_to_fw_ready()).map_err(|_| "handshake must reach FW_READY")?;

        // QRTR: nothing before the device's HELLO; the first UL frame is
        // ns.c's say_hello reply to (remote node, CTRL).
        let fw = &w.client.pipe.fw;
        ensure!(
            fw.early_tx == 0,
            "host must not speak before the device HELLO"
        );
        let hello = encode_packet(
            QRTR_TYPE_HELLO,
            HOST_CTRL,
            DEV_CTRL,
            false,
            &CtrlPkt::Hello.to_bytes(),
        )
        .unwrap();
        ensure!(
            fw.ul.first() == Some(&hello),
            "first UL frame = HELLO reply"
        );
        ensure!(
            fw.ul
                .iter()
                .filter(|f| f[4] == QRTR_TYPE_HELLO as u8)
                .count()
                == 1,
            "exactly one HELLO"
        );
        ensure!(
            w.client.server()
                == Some(QrtrServer {
                    service: 0x45,
                    instance: 0x101,
                    node: DEV_NODE,
                    port: SRV_PORT
                }),
            "connected to WLFW 0x45 v1 ins 1"
        );

        // Every request, byte for byte.
        let mem = info.target_mem.clone();
        ensure!(mem.len() == 3, "three target memory chunks");
        let want = expected_sequence(&mem, &regdb, &board, 0xff, info.m3_addr, m3.len() as u32);
        let fw = &w.client.pipe.fw;
        ensure!(fw.reqs.len() == want.len(), "request count");
        for (i, (got, exp)) in fw.reqs.iter().zip(want.iter()).enumerate() {
            if got != exp {
                let _ = i;
                return Err("a request differs from Linux's bytes");
            }
        }
        ensure!(
            fw.reqs[0] == ind_register_golden(0),
            "ind_register = Linux golden, txn 0"
        );
        ensure!(
            fw.reqs[1] == HOST_CAP_TXN1,
            "host_cap = Linux golden, txn 1"
        );
        // regdb: 7000 → 6144 + 856; board: 13000 → 6144 + 6144 + 712.
        ensure!(fw.reqs.len() == 4 + 2 + 3 + 1, "10 requests to FW_READY");

        // DATA framing: client port 0x4000 → server, confirm_rx on the
        // packet that brings the pending count to QRTR_TX_FLOW_LOW.
        let data: Vec<_> = fw
            .ul
            .iter()
            .filter_map(|f| decode_packet(f).ok())
            .filter(|p| p.pkt_type == QRTR_TYPE_DATA)
            .collect();
        ensure!(data.len() == 10, "10 DATA frames");
        ensure!(
            data.iter().all(|p| p.src_node == 1
                && p.src_port == 0x4000
                && p.dst_node == 3
                && p.dst_port == 1),
            "DATA addressing"
        );
        let confirms: Vec<usize> = data
            .iter()
            .enumerate()
            .filter(|(_, p)| p.confirm_rx)
            .map(|(i, _)| i)
            .collect();
        ensure!(
            confirms == [4, 9],
            "confirm_rx on the 5th packet after each resume"
        );

        // Results.
        ensure!(
            info.target.chip_id == 2 && info.target.board_id == 0xff,
            "target ids"
        );
        ensure!(info.target.soc_id == 0x400c_1211, "soc id");
        ensure!(
            info.target.fw_build_id_display() == b"WLAN.HSP.1.1-03125",
            "build id prefix stripped"
        );
        let b = info.board.as_ref().ok_or("board chosen")?;
        ensure!(b.name == LAPTOP_NAME && b.api == 2, "board name match");
        ensure!(
            b.bdf_type == ATH11K_QMI_BDF_TYPE_ELF && b.sent == 13_000,
            "ELF board"
        );
        ensure!(info.regdb_sent == Some(7_000), "regdb sent");
        ensure!(info.mem_delayed_rounds == 0, "no delayed round");
        ensure!(w.cal_done == 1, "FW_READY sets cal_done");
        ensure!(w.registered, "registered");
        // M3 image copied into its own DMA buffer.
        let m3mem = w.m3.as_ref().ok_or("m3 memory")?;
        ensure!(m3mem.data == m3 && m3mem.addr == info.m3_addr, "m3 copy");
        ensure!(info.m3_size == 150_000, "m3 size");
        let logs = w.client.pipe.logs.borrow();
        ensure!(
            logs.iter()
                .any(|l| l == "chip_id 0x2 chip_family 0x4 board_id 0xff soc_id 0x400c1211"),
            "target_cap log line (ath11k_info format)"
        );
        ensure!(
            logs.iter().any(|l| l
                == "fw_version 0x1105811b fw_build_timestamp 2024-01-01 00:00 \
                    fw_build_id WLAN.HSP.1.1-03125"),
            "fw version log line"
        );
        drop(logs);

        // Firmware files, in Linux's request order: regdb then board
        // via board-2.bin (each api_n call requests it), ELF → no
        // caldata, then m3.bin.
        let files = &w.fw.requested;
        ensure!(
            files
                == &[
                    "ath11k/WCN6855/hw2.1/board-2.bin",
                    "ath11k/WCN6855/hw2.1/board-2.bin",
                    "ath11k/WCN6855/hw2.1/board-2.bin",
                    "ath11k/WCN6855/hw2.1/m3.bin",
                ],
            "firmware request order"
        );

        // firmware_start(NORMAL): wlan_ini(1), wlan_cfg, wlan_mode(0).
        let shadow: Vec<u32> = (0..40).map(|i| 0x0002_4000 + 4 * i).collect();
        block(w.firmware_start(ATH11K_FIRMWARE_MODE_NORMAL, &shadow))
            .map_err(|_| "firmware_start")?;
        let fw = &w.client.pipe.fw;
        let n = fw.reqs.len();
        ensure!(n == 13, "three more requests");
        ensure!(
            fw.reqs[10] == enc(&WlanIniReq::ath11k(true), 10),
            "wlan_ini bytes"
        );
        let cfg = WlanCfgReq::ath11k(
            &hw(),
            &TARGET_CE_CONFIG_WLAN_QCA6390,
            &TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390,
            &shadow,
        );
        ensure!(fw.reqs[11] == enc(&cfg, 11), "wlan_cfg bytes");
        // shadow list clamped to 36: TLV 0x14 count byte.
        let c = &fw.reqs[11];
        let pos = c.len() - (3 + 1 + 36 * 4);
        ensure!(
            c[pos] == 0x14 && c[pos + 3] == 36,
            "shadow v2 clamped to 36"
        );
        ensure!(
            fw.reqs[12] == enc(&WlanModeReq::ath11k(ATH11K_FIRMWARE_MODE_NORMAL), 12),
            "wlan_mode bytes"
        );
        ensure!(
            fw.reqs[12][7..] == [0x01, 0x04, 0x00, 0, 0, 0, 0, 0x10, 0x01, 0x00, 0x00],
            "mode 0 + hw_debug 0"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_handshake_wcn6855_full);

fn smoke_wlfw_handshake_real_dma32() -> TestResult {
    run_test(|| {
        // The same bring-up with real coherent memory: every chunk and
        // the M3 copy sit below 4 GiB, aligned to their power-of-two
        // allocation, as dma_alloc_coherent's contract promises.
        let board = elf_blob(7_000, 4);
        let m3 = bin_blob(100_000, 5);
        let mut w = wlfw_with(
            Script::wcn6855(),
            standard_files(&board, &bin_blob(100, 6), &m3),
            Dma32,
            config(),
        );
        let info = block(w.run_to_fw_ready()).map_err(|_| "handshake with Dma32")?;
        for (i, &(addr, size, _)) in info.target_mem.iter().enumerate() {
            let alloc = (size as u64).div_ceil(4096).next_power_of_two() * 4096;
            ensure!(addr != 0, "chunk allocated");
            ensure!(addr % alloc == 0, "chunk aligned to its allocation order");
            ensure!(addr + size as u64 - 1 <= 0xffff_ffff, "chunk within DMA32");
            let mem = w.target_mem[i].mem.as_ref().ok_or("chunk mem")?;
            ensure!(mem.size() as u64 == alloc, "power-of-two pages");
        }
        let m3mem = w.m3.as_ref().ok_or("m3")?;
        ensure!(
            m3mem.as_slice()[..m3.len()] == m3[..],
            "m3 copied to DMA memory"
        );
        ensure!(
            info.m3_addr + m3.len() as u64 - 1 <= 0xffff_ffff,
            "m3 within DMA32"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_handshake_real_dma32);

fn smoke_wlfw_dma32_alloc_sizes() -> TestResult {
    run_test(|| {
        let mut d = Dma32;
        for size in [1usize, 4096, 4097, 0x2_0000, 0x18_0000, 0x40_0000] {
            let m = d.alloc_coherent(size).ok_or("Dma32 allocation")?;
            let want = size.div_ceil(4096).next_power_of_two() * 4096;
            ensure!(m.size() == want, "size rounded to power-of-two pages");
            let addr = CoherentMem::dma_addr(&m);
            ensure!(addr % want as u64 == 0, "aligned to the order");
            ensure!(
                addr + want as u64 - 1 <= 0xffff_ffff,
                "below ATH11K_PCI_COHERENT_DMA_MASK"
            );
            ensure!(m.as_slice().iter().all(|&b| b == 0), "zeroed");
        }
        ensure!(d.alloc_coherent(0).is_none(), "0 bytes fails");
        ensure!(
            d.alloc_coherent((4 << 20) + 1).is_none(),
            "over the 4 MiB contiguous ceiling fails"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_dma32_alloc_sizes);

// ══ target memory ════════════════════════════════════════════════

fn smoke_wlfw_mem_request_delayed_path() -> TestResult {
    run_test(|| {
        // QCA6390-style: first one ~8 MiB block (cannot be allocated,
        // ≤ 5 segments → empty "delayed" answer, firmware refuses it
        // with error 0), then 6 smaller chunks.
        let mut s = Script::wcn6855();
        s.mem_rounds = vec![
            vec![seg(0x80_0000, QMI_WLANFW_MEM_TYPE_DDR_V01)],
            (0..6)
                .map(|_| seg(0x10_0000, QMI_WLANFW_MEM_TYPE_DDR_V01))
                .collect(),
        ];
        let board = elf_blob(100, 7);
        let mut w = wlfw(s, standard_files(&board, &[1, 2, 3], &[9; 64]));
        let info = block(w.run_to_fw_ready()).map_err(|_| "delayed path must recover")?;
        ensure!(info.mem_delayed_rounds == 1, "one delayed round");
        ensure!(info.target_mem.len() == 6, "six chunks");
        let fw = &w.client.pipe.fw;
        ensure!(
            fw.reqs[2] == enc(&RespondMemReq::default(), 2),
            "delayed respond_mem = empty list (Linux golden shape)"
        );
        ensure!(
            fw.reqs[2] == [0x00, 0x02, 0x00, 0x36, 0x00, 0x04, 0x00, 0x01, 0x01, 0x00, 0x00],
            "empty list bytes"
        );
        let segs = info
            .target_mem
            .iter()
            .map(|&(addr, size, mem_type)| MemSegResp {
                addr,
                size,
                mem_type,
                restore: 0,
            })
            .collect();
        ensure!(
            fw.reqs[3] == enc(&RespondMemReq { mem_seg: segs }, 3),
            "second respond_mem lists the six chunks"
        );
        ensure!(
            w.dma.allocs[0] == 0x80_0000 && w.dma.allocs.len() == 1 + 6 + 1,
            "one failed big alloc, six chunks, m3"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_wlfw_mem_request_delayed_path
);

fn smoke_wlfw_mem_alloc_rules() -> TestResult {
    run_test(|| {
        let mut w = wlfw(Script::wcn6855(), FakeFiles::default());
        // Two chunks allocate.
        w.mem_seg_count = 2;
        w.target_mem[0].size = 0x1000;
        w.target_mem[0].mem_type = 1;
        w.target_mem[1].size = 0x3000;
        w.target_mem[1].mem_type = 4;
        w.alloc_target_mem_chunk().map_err(|_| "alloc")?;
        ensure!(
            !w.target_mem_delayed && w.dma.allocs == [0x1000, 0x3000],
            "fresh"
        );
        let first = w.target_mem[0].mem.as_ref().unwrap().addr;
        // Same size/type: reused (firmware reload), no new allocation.
        w.alloc_target_mem_chunk().map_err(|_| "realloc")?;
        ensure!(w.dma.allocs.len() == 2, "reuse unchanged chunks");
        ensure!(
            w.target_mem[0].mem.as_ref().unwrap().addr == first,
            "same buffer"
        );
        // A size change with ≤ 5 segments: delayed, nothing freed.
        w.target_mem[1].size = 0x5000;
        w.alloc_target_mem_chunk().map_err(|_| "mismatch")?;
        ensure!(w.target_mem_delayed, "size mismatch → delayed");
        ensure!(w.target_mem[1].mem.is_some(), "kept for later");
        // Six segments with a mismatch: freed and re-allocated.
        w.mem_seg_count = 6;
        for i in 2..6 {
            w.target_mem[i].size = 0x1000;
        }
        w.alloc_target_mem_chunk().map_err(|_| "six")?;
        ensure!(
            !w.target_mem_delayed,
            "> 5 segments never delays a mismatch"
        );
        ensure!(w.dma.allocs[2] == 0x5000, "re-allocated at the new size");
        // > 5 segments and an allocation failure: hard error.
        w.dma.fail_above = 0x800;
        w.target_mem[3].size = 0x2000;
        let e = w.alloc_target_mem_chunk().err().ok_or("must fail")?;
        ensure!(
            e.step == step::TARGET_MEM_ALLOC && e.detail == 0x2000,
            "TARGET_MEM_ALLOC"
        );
        // ≤ 5 segments and a failure: delayed, every chunk freed.
        w.mem_seg_count = 2;
        w.target_mem[0].mem = None;
        w.target_mem[0].size = 0x9000;
        w.alloc_target_mem_chunk().map_err(|_| "small fail")?;
        ensure!(w.target_mem_delayed, "≤ 5 → delayed");
        ensure!(
            w.target_mem[0].mem.is_none() && w.target_mem[1].mem.is_none(),
            "ath11k_qmi_free_target_mem_chunk"
        );
        // The boundary: exactly ATH11K_QMI_FW_MEM_REQ_SEGMENT_CNT (5)
        // segments still delays; 6 fails hard.
        w.mem_seg_count = 5;
        w.alloc_target_mem_chunk()
            .map_err(|_| "5 segments must delay, not fail")?;
        ensure!(w.target_mem_delayed, "5 → delayed");
        w.mem_seg_count = 6;
        ensure!(
            w.alloc_target_mem_chunk().is_err(),
            "6 segments with a failure → error"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_mem_alloc_rules);

fn smoke_wlfw_mem_alloc_failure_many_segments() -> TestResult {
    run_test(|| {
        let mut s = Script::wcn6855();
        s.mem_rounds = vec![(0..6)
            .map(|_| seg(0x80_0000, QMI_WLANFW_MEM_TYPE_DDR_V01))
            .collect()];
        let mut w = wlfw(s, standard_files(&[1], &[1], &[1]));
        let e = block(w.run_to_fw_ready()).err().ok_or("must fail")?;
        ensure!(
            e.step == step::TARGET_MEM_ALLOC && e.detail == 0x80_0000,
            "6 unallocatable segments: TARGET_MEM_ALLOC (Linux stalls)"
        );
        ensure!(
            w.client.pipe.fw.reqs.len() == 2,
            "no respond_mem after the failed callback"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_wlfw_mem_alloc_failure_many_segments
);

fn smoke_wlfw_delayed_response_error() -> TestResult {
    run_test(|| {
        // A delayed (empty) answer refused with a non-zero error is a
        // real failure.
        let mut s = Script::wcn6855();
        s.mem_rounds = vec![vec![seg(0x80_0000, 1)]];
        s.overrides = vec![(QMI_WLANFW_RESPOND_MEM_REQ_V01, 0, Reply::Fail(3))];
        let mut w = wlfw(s, standard_files(&[1], &[1], &[1]));
        let e = block(w.run_to_fw_ready()).err().ok_or("must fail")?;
        ensure!(
            e.step == step::RESPOND_MEM && e.detail == (2 << 16 | 3) && e.errno == 22,
            "RESPOND_MEM, QMI error 3, -EINVAL"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_delayed_response_error);

// ══ board data ═══════════════════════════════════════════════════

fn id(variant: &[u8]) -> BoardId {
    BoardId {
        search_bus_and_board: true,
        vendor: 0x17cb,
        device: 0x1103,
        subsystem_vendor: 0x17aa,
        subsystem_device: 0x9309,
        chip_id: 2,
        board_id: 255,
        bdf_ext: variant.to_vec(),
    }
}

fn smoke_wlfw_board_names() -> TestResult {
    run_test(|| {
        let i = id(b"");
        ensure!(
            board_name(&i, true, BdfNameType::Full) == LAPTOP_NAME,
            "full"
        );
        ensure!(
            board_name(&i, false, BdfNameType::Full) == LAPTOP_NAME,
            "fallback = full without variant"
        );
        ensure!(
            board_name(&i, false, BdfNameType::ChipId) == "bus=pci,qmi-chip-id=2",
            "chip id"
        );
        ensure!(
            board_name(&i, false, BdfNameType::BusName) == "bus=pci",
            "bus"
        );
        let v = id(b"LE_X13s");
        ensure!(
            board_name(&v, true, BdfNameType::Full)
                == "bus=pci,vendor=17cb,device=1103,subsystem-vendor=17aa,subsystem-device=9309,\
                    qmi-chip-id=2,qmi-board-id=255,variant=LE_X13s",
            "variant appended"
        );
        ensure!(
            board_name(&v, false, BdfNameType::Full) == LAPTOP_NAME,
            "fallback drops variant"
        );
        ensure!(
            board_name(&v, true, BdfNameType::ChipId) == "bus=pci,qmi-chip-id=2",
            "chip-id never has a variant"
        );
        // %d: ids print signed.
        let mut neg = id(b"");
        neg.chip_id = 0xffff_ffff;
        neg.board_id = 0x8000_0000;
        ensure!(
            board_name(&neg, false, BdfNameType::ChipId) == "bus=pci,qmi-chip-id=-1",
            "chip_id %d"
        );
        ensure!(
            board_name(&neg, false, BdfNameType::Full)
                .ends_with("qmi-chip-id=-1,qmi-board-id=-2147483648"),
            "board_id %d"
        );
        // %04x pads.
        let mut small = id(b"");
        small.subsystem_vendor = 0x1a;
        ensure!(
            board_name(&small, false, BdfNameType::Full).contains("subsystem-vendor=001a,"),
            "%04x"
        );
        // Non-WCN6855 (bdf_search default): one format for every type.
        let mut q = id(b"V");
        q.search_bus_and_board = false;
        ensure!(
            board_name(&q, true, BdfNameType::Full)
                == "bus=pci,qmi-chip-id=2,qmi-board-id=255,variant=V",
            "default + variant"
        );
        ensure!(
            board_name(&q, false, BdfNameType::ChipId) == "bus=pci,qmi-chip-id=2,qmi-board-id=255",
            "default ignores name_type"
        );
        // scnprintf: 199 bytes max; variant field 40 max.
        let long = id(&[b'A'; 60]);
        let n = board_name(&long, true, BdfNameType::Full);
        ensure!(
            n.len() == LAPTOP_NAME.len() + 40,
            "variant truncated to 40 bytes"
        );
        // Search orders.
        let s = bdf_search(&i);
        ensure!(
            s[0] == BoardSearch::Api2 {
                name: String::from(LAPTOP_NAME),
                ie_id: ATH11K_BD_IE_BOARD
            } && s[1] == s[0]
                && s[2]
                    == BoardSearch::Api2 {
                        name: String::from("bus=pci,qmi-chip-id=2"),
                        ie_id: ATH11K_BD_IE_BOARD
                    }
                && s[3] == BoardSearch::Api1 { file: "board.bin" },
            "fetch_bdf order"
        );
        let r = regdb_search(&i);
        ensure!(
            r[1] == BoardSearch::Api2 {
                name: String::from("bus=pci"),
                ie_id: ATH11K_BD_IE_REGDB
            } && r[2] == BoardSearch::Api1 { file: "regdb.bin" },
            "fetch_regdb order"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_board_names);

fn smoke_wlfw_board2_parser() -> TestResult {
    run_test(|| {
        let a = bin_blob(33, 1);
        let b = bin_blob(1000, 2);
        let file = build_board2(&[
            (
                ATH11K_BD_IE_BOARD,
                vec![
                    (ATH11K_BD_IE_BOARD_NAME, b"bus=pci,qmi-chip-id=1".to_vec()),
                    (ATH11K_BD_IE_BOARD_NAME, b"bus=pci,qmi-chip-id=3".to_vec()),
                    (ATH11K_BD_IE_BOARD_DATA, a.clone()),
                ],
            ),
            (7, vec![(0, b"junk".to_vec())]),
            (
                ATH11K_BD_IE_BOARD,
                vec![
                    (ATH11K_BD_IE_BOARD_NAME, LAPTOP_NAME.as_bytes().to_vec()),
                    (ATH11K_BD_IE_BOARD_DATA, b.clone()),
                ],
            ),
            (
                ATH11K_BD_IE_REGDB,
                vec![
                    (ATH11K_BD_IE_REGDB_NAME, b"bus=pci".to_vec()),
                    (ATH11K_BD_IE_REGDB_DATA, vec![5; 12]),
                ],
            ),
        ]);
        let get = |name: &[u8], ie: u32| {
            fetch_board_data_api_n(&file, name, ie, 0, 1).map(|(o, l)| file[o..o + l].to_vec())
        };
        ensure!(
            get(LAPTOP_NAME.as_bytes(), ATH11K_BD_IE_BOARD) == Ok(b.clone()),
            "second board"
        );
        ensure!(
            get(b"bus=pci,qmi-chip-id=1", ATH11K_BD_IE_BOARD) == Ok(a.clone()),
            "first name of a group"
        );
        ensure!(
            get(b"bus=pci,qmi-chip-id=3", ATH11K_BD_IE_BOARD) == Ok(a.clone()),
            "second name of a group"
        );
        ensure!(
            get(b"bus=pci", ATH11K_BD_IE_REGDB) == Ok(vec![5; 12]),
            "regdb IE"
        );
        ensure!(
            get(b"bus=pci", ATH11K_BD_IE_BOARD) == Err(BoardError::NoData),
            "regdb names are not boards"
        );
        ensure!(
            get(b"bus=pci,qmi-chip-id", ATH11K_BD_IE_BOARD) == Err(BoardError::NoData),
            "prefix is no match"
        );
        ensure!(
            get(b"bus=pci,qmi-chip-id=11", ATH11K_BD_IE_BOARD) == Err(BoardError::NoData),
            "longer is no match"
        );

        // Linux quirk: a match is never reset by a later non-matching
        // name, so the data after it is taken.
        let quirk = build_board2(&[(
            ATH11K_BD_IE_BOARD,
            vec![(0, b"X".to_vec()), (0, b"Y".to_vec()), (1, vec![7; 4])],
        )]);
        ensure!(
            fetch_board_data_api_n(&quirk, b"X", 0, 0, 1).is_ok(),
            "match then other name"
        );
        // A data IE before any name match is skipped; the next one after
        // a match is taken.
        let skip = build_board2(&[(
            ATH11K_BD_IE_BOARD,
            vec![(1, vec![1; 4]), (0, b"X".to_vec()), (1, vec![2; 8])],
        )]);
        let (o, l) = fetch_board_data_api_n(&skip, b"X", 0, 0, 1).map_err(|_| "skip")?;
        ensure!(skip[o..o + l] == [2; 8], "data after the match");
        // Zero-length data → -ENODATA.
        let empty = build_board2(&[(
            ATH11K_BD_IE_BOARD,
            vec![(0, b"X".to_vec()), (1, Vec::new())],
        )]);
        ensure!(
            fetch_board_data_api_n(&empty, b"X", 0, 0, 1) == Err(BoardError::NoData),
            "empty data"
        );

        // Magic.
        ensure!(
            fetch_board_data_api_n(b"QCA-ATH11K-BOAR", b"X", 0, 0, 1)
                == Err(BoardError::ShortMagic),
            "short magic"
        );
        let mut bad = file.clone();
        bad[3] = b'X';
        ensure!(
            fetch_board_data_api_n(&bad, b"X", 0, 0, 1) == Err(BoardError::BadMagic),
            "bad magic"
        );
        let mut nonul = file.clone();
        nonul[16] = b'!';
        ensure!(
            fetch_board_data_api_n(&nonul, b"X", 0, 0, 1) == Err(BoardError::BadMagic),
            "magic NUL is compared"
        );
        ensure!(
            fetch_board_data_api_n(b"QCA-ATH11K-BOARD\0\0\0", b"X", 0, 0, 1)
                == Err(BoardError::NoRoomAfterMagic),
            "19 bytes: no room for the padded magic"
        );
        ensure!(
            fetch_board_data_api_n(&file[..20], b"X", 0, 0, 1) == Err(BoardError::NoData),
            "magic alone: no data"
        );
        // Truncated top-level IE.
        let cut = &file[..file.len() - 4];
        ensure!(
            matches!(
                fetch_board_data_api_n(cut, b"bus=pci", 1, 0, 1),
                Err(BoardError::BadIeLength { ie_id: 1, .. })
            ),
            "truncated IE → -EINVAL"
        );
        // A matching board found before the truncation still wins
        // (Linux stops at the first match).
        ensure!(
            fetch_board_data_api_n(cut, b"bus=pci,qmi-chip-id=1", 0, 0, 1).is_ok(),
            "early match"
        );
        // Oversize sub-IE inside a well-formed top-level IE.
        let mut over = build_board2(&[(
            ATH11K_BD_IE_BOARD,
            vec![(0, b"X".to_vec()), (1, vec![1; 8])],
        )]);
        // sub-IE #2 header at 20 + 8 + 8 + 4: patch its len to 64.
        let p = 20 + 8 + 12 + 4;
        over[p..p + 4].copy_from_slice(&64u32.to_le_bytes());
        ensure!(
            matches!(
                fetch_board_data_api_n(&over, b"X", 0, 0, 1),
                Err(BoardError::BadSubIeLength { .. })
            ),
            "oversize sub-IE → -EINVAL"
        );
        // An IE header with exactly 8 bytes left is not parsed
        // (`while (len > sizeof(*hdr))`).
        let mut tail = build_board2(&[]);
        tail.extend_from_slice(&0u32.to_le_bytes());
        tail.extend_from_slice(&0u32.to_le_bytes());
        ensure!(
            fetch_board_data_api_n(&tail, b"X", 0, 0, 1) == Err(BoardError::NoData),
            "8-byte tail ignored"
        );
        // Errnos.
        ensure!(
            BoardError::NoData.errno() == 61 && BoardError::BadMagic.errno() == 22,
            "errnos"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_board2_parser);

fn smoke_wlfw_smbios_variant() -> TestResult {
    run_test(|| {
        // type 0xF8, length 9, handle, features, cc flag, cc code, bdf_enabled, strings.
        let rec = |len: u8, flag: u8, cc: u16, en: u8, s: &[u8]| {
            let mut v = vec![0xF8, len, 0x34, 0x12, 0x00, flag];
            v.extend_from_slice(&cc.to_le_bytes());
            v.push(en);
            v.extend_from_slice(s);
            v.extend_from_slice(&[0, 0]);
            v
        };
        let mut st = SmbiosBdf::default();
        smbios_bdf_ext(&rec(9, 1, 0x5553, 1, b"BDF_LE_X13s"), &mut st);
        ensure!(
            st.bdf_ext == b"LE_X13s" && st.alpha2 == Some(*b"US"),
            "variant + ISO cc"
        );
        // First variant wins.
        smbios_bdf_ext(&rec(9, 2, 0, 1, b"BDF_OTHER"), &mut st);
        ensure!(
            st.bdf_ext == b"LE_X13s" && st.alpha2 == Some(*b"US"),
            "ignored once set"
        );
        let mut st = SmbiosBdf::default();
        smbios_bdf_ext(&rec(10, 1, 0x5553, 1, b"BDF_X"), &mut st);
        ensure!(st == SmbiosBdf::default(), "wrong length ignored entirely");
        smbios_bdf_ext(&rec(9, 2, 0, 0, b"BDF_X"), &mut st);
        ensure!(
            st.bdf_ext.is_empty() && st.alpha2 == Some(*b"00"),
            "WW cc, bdf disabled"
        );
        smbios_bdf_ext(&rec(9, 0, 0, 1, b"XDF_X"), &mut st);
        ensure!(st.bdf_ext.is_empty(), "bad magic");
        smbios_bdf_ext(&rec(9, 0, 0, 1, b"BDF_\x01x"), &mut st);
        ensure!(st.bdf_ext.is_empty(), "non-printable refused");
        let mut a = vec![0xF7, 9, 0, 0, 0, 0, 0, 0, 1];
        a.extend_from_slice(b"BDF_Y\0\0");
        smbios_bdf_ext(&a, &mut st);
        ensure!(st.bdf_ext.is_empty(), "other types ignored");
        // 40-char string: the 32-char window is checked, the copy keeps 31.
        let long: Vec<u8> = b"BDF_"
            .iter()
            .copied()
            .chain(core::iter::repeat_n(b'Z', 36))
            .collect();
        smbios_bdf_ext(&rec(9, 0, 0, 1, &long), &mut st);
        ensure!(st.bdf_ext.len() == 31, "strscpy truncation kept");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_smbios_variant);

/// A structure table: `(type, formatted tail after the header, strings)`
/// per structure, then end-of-table (SMBIOS 3: `num = 0`).
/// `(type, formatted tail after the header, strings)`.
type DmiRec<'a> = (u8, &'a [u8], &'a [&'a [u8]]);

fn dmi_table(recs: &[DmiRec<'_>]) -> narf_firmware_smbios::RawTable {
    let mut t = Vec::new();
    for (i, (kind, tail, strings)) in recs.iter().enumerate() {
        t.push(*kind);
        t.push(4 + tail.len() as u8);
        t.extend_from_slice(&(i as u16).to_le_bytes());
        t.extend_from_slice(tail);
        if strings.is_empty() {
            t.push(0);
        }
        for s in *strings {
            t.extend_from_slice(s);
            t.push(0);
        }
        t.push(0);
    }
    t.extend_from_slice(&[127, 4, 0xFF, 0xFE, 0, 0]);
    narf_firmware_smbios::RawTable::from_bytes(t, 0)
}

/// `ath11k_core_check_smbios` over a whole DMI table, the way
/// `dmi_walk` feeds it: the variant reaches the board name, invalid
/// 0xF8 structures are skipped without stopping the walk.
fn smoke_wlfw_smbios_table_variant() -> TestResult {
    run_test(|| {
        let sys: &[u8] = &[
            1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        // features_disabled, cc flag, cc code (LE), bdf_enabled.
        let f8 = |flag: u8, en: u8| -> [u8; 5] { [0, flag, 0x53, 0x55, en] };
        let (iso, off) = (f8(1, 1), f8(0, 0));
        let (on, ww) = (f8(0, 1), f8(2, 1));

        // ThinkPad P14s Gen 5 AMD (17aa:9309): `le_lfr-1`.
        let t = dmi_table(&[
            (1, sys, &[b"LENOVO", b"21ME"]),
            (0xF8, &iso, &[b"BDF_le_lfr-1"]),
        ]);
        let st = check_smbios_in(&t);
        ensure!(
            st.bdf_ext == b"le_lfr-1" && st.alpha2 == Some(*b"US"),
            "variant + ISO cc"
        );
        let mut id = BoardId {
            search_bus_and_board: true,
            vendor: 0x17cb,
            device: 0x1103,
            subsystem_vendor: 0x17aa,
            subsystem_device: 0x9309,
            chip_id: 2,
            board_id: 255,
            bdf_ext: st.bdf_ext,
        };
        ensure!(
            board_name(&id, true, BdfNameType::Full)
                == "bus=pci,vendor=17cb,device=1103,subsystem-vendor=17aa,\
                    subsystem-device=9309,qmi-chip-id=2,qmi-board-id=255,variant=le_lfr-1",
            "P14s full board name carries the variant"
        );
        id.bdf_ext.clear();
        ensure!(
            !board_name(&id, true, BdfNameType::Full).contains("variant"),
            "no variant without SMBIOS"
        );

        // No 0xF8 structure at all → -ENODATA (empty).
        let t = dmi_table(&[(1, sys, &[b"LENOVO", b"21ME"])]);
        ensure!(check_smbios_in(&t) == SmbiosBdf::default(), "no type 0xF8");

        // Disabled / bad magic / wrong length first: the walk goes on
        // and the later valid structure wins; its WW cc overrides the
        // earlier ISO one (new_alpha2 is rewritten per structure).
        let wrong_len: &[u8] = &[0, 1, 0x53, 0x55, 1, 0];
        let t = dmi_table(&[
            (0xF8, &off, &[b"BDF_disabled"]),
            (0xF8, &on, &[b"XDF_bad"]),
            (0xF8, wrong_len, &[b"BDF_len10"]),
            (0xF8, &ww, &[b"BDF_LE_NDA-M"]),
            (0xF8, &on, &[b"BDF_LE"]),
        ]);
        let st = check_smbios_in(&t);
        ensure!(
            st.bdf_ext == b"LE_NDA-M" && st.alpha2 == Some(*b"00"),
            "first valid variant after rejected ones"
        );

        // bdf_enabled = 0 everywhere → nothing.
        let t = dmi_table(&[(0xF8, &off, &[b"BDF_LE"])]);
        ensure!(check_smbios_in(&t).bdf_ext.is_empty(), "bdf disabled");
        // Magic wrong → nothing.
        let t = dmi_table(&[(0xF8, &on, &[b"bdf_LE"])]);
        ensure!(
            check_smbios_in(&t).bdf_ext.is_empty(),
            "magic is case-sensitive"
        );
        // No string set → nothing.
        let t = dmi_table(&[(0xF8, &on, &[])]);
        ensure!(check_smbios_in(&t).bdf_ext.is_empty(), "empty string set");
        // "BDF_" alone leaves bdf_ext empty, so a later one still counts.
        let t = dmi_table(&[(0xF8, &on, &[b"BDF_"]), (0xF8, &on, &[b"BDF_LE"])]);
        ensure!(
            check_smbios_in(&t).bdf_ext == b"LE",
            "empty variant is no variant"
        );
        // Only the first string is the variant (`bdf_ext[]` = string 1).
        let t = dmi_table(&[(0xF8, &on, &[b"junk", b"BDF_LE"])]);
        ensure!(check_smbios_in(&t).bdf_ext.is_empty(), "string 2 ignored");
        // Over-long: strscpy truncates to 31 and Linux keeps the copy.
        let long = [b"BDF_".as_slice(), &[b'Q'; 32]].concat();
        let t = dmi_table(&[(0xF8, &on, &[&long])]);
        ensure!(
            check_smbios_in(&t).bdf_ext == [b'Q'; 31],
            "over-long variant truncated to 31"
        );
        // A non-printable byte inside the 32-char window → refused;
        // past it (index ≥ 32) Linux does not look.
        let mut bad = long.clone();
        bad[31] = 0x7F;
        let t = dmi_table(&[(0xF8, &on, &[&bad])]);
        ensure!(check_smbios_in(&t).bdf_ext.is_empty(), "DEL in window");
        let mut late = long.clone();
        late[33] = 0x7F;
        let t = dmi_table(&[(0xF8, &on, &[&late])]);
        ensure!(check_smbios_in(&t).bdf_ext.len() == 31, "byte 33 unchecked");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_smbios_table_variant);

/// The boot path: `check_smbios` reads the table the DMI scan kept.
/// Skips when the firmware gave none.
fn smoke_wlfw_smbios_boot_table() -> TestResult {
    let Some(t) = narf_firmware_smbios::boot_table() else {
        return TestResult::Skip("no SMBIOS table at boot");
    };
    if check_smbios() != check_smbios_in(t) {
        return TestResult::Fail("check_smbios must read the boot table");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_smbios_boot_table);

fn smoke_wlfw_board_fallbacks() -> TestResult {
    run_test(|| {
        // Only a chip-id entry: third name wins.
        let mut f = FakeFiles::default();
        f.add(
            "board-2.bin",
            build_board2(&[(
                0,
                vec![(0, b"bus=pci,qmi-chip-id=2".to_vec()), (1, elf_blob(40, 8))],
            )]),
        );
        f.add("m3.bin", vec![1; 16]);
        let mut w = wlfw(Script::wcn6855(), f);
        let info = block(w.run_to_fw_ready()).map_err(|_| "chip-id fallback")?;
        let b = info.board.ok_or("board")?;
        ensure!(
            b.name == "bus=pci,qmi-chip-id=2" && b.api == 2,
            "chip-id board used"
        );
        ensure!(info.regdb_sent.is_none(), "no regdb anywhere: ignored");
        ensure!(
            w.fw.requested
                == [
                    // regdb: full, bus=pci, regdb.bin
                    "ath11k/WCN6855/hw2.1/board-2.bin",
                    "ath11k/WCN6855/hw2.1/board-2.bin",
                    "ath11k/WCN6855/hw2.1/regdb.bin",
                    // board: full, fallback, chip-id
                    "ath11k/WCN6855/hw2.1/board-2.bin",
                    "ath11k/WCN6855/hw2.1/board-2.bin",
                    "ath11k/WCN6855/hw2.1/board-2.bin",
                    "ath11k/WCN6855/hw2.1/m3.bin",
                ],
            "lookup order"
        );

        // No board-2.bin: API-1 board.bin (BIN → caldata.bin next) and
        // regdb.bin.
        let mut f = FakeFiles::default();
        f.add("board.bin", bin_blob(300, 1));
        f.add("regdb.bin", bin_blob(20, 1));
        f.add("caldata.bin", bin_blob(10, 2));
        f.add("m3.bin", vec![1; 16]);
        let mut w = wlfw(Script::wcn6855(), f);
        let info = block(w.run_to_fw_ready()).map_err(|_| "board.bin fallback")?;
        let b = info.board.ok_or("board")?;
        ensure!(
            b.name == "board.bin" && b.api == 1 && b.bdf_type == ATH11K_QMI_BDF_TYPE_BIN,
            "api 1 BIN"
        );
        ensure!(info.regdb_sent == Some(20), "regdb.bin");
        let fw = &w.client.pipe.fw;
        // ind, host, mem, cap, regdb(1), board(1), caldata(1), m3.
        ensure!(fw.reqs.len() == 8, "caldata download added");
        let cal = &fw.reqs[6];
        let cal_data = bin_blob(10, 2);
        let want = bdf_segments(&cal_data, 0xff, ATH11K_QMI_FILE_TYPE_CALDATA)
            .next()
            .ok_or("seg")?;
        ensure!(*cal == enc(&want, 6), "caldata segment, bdf_type CALDATA");
        ensure!(
            w.fw.requested
                .iter()
                .position(|p| p == "ath11k/WCN6855/hw2.1/cal-pci-0000:03:00.0.bin")
                < w.fw
                    .requested
                    .iter()
                    .position(|p| p == "ath11k/WCN6855/hw2.1/caldata.bin"),
            "cal-pci-<dev>.bin is tried before caldata.bin"
        );

        // Nothing at all: BDF_FETCH (-ENOENT).
        let mut f = FakeFiles::default();
        f.add("m3.bin", vec![1; 16]);
        let mut w = wlfw(Script::wcn6855(), f);
        let e = block(w.run_to_fw_ready()).err().ok_or("must fail")?;
        ensure!(
            e.step == step::BDF_FETCH && e.errno == ENOENT,
            "missing board → BDF_FETCH"
        );
        ensure!(
            w.client.pipe.fw.msg_ids().last() == Some(&QMI_WLANFW_CAP_REQ_V01),
            "stops after target_cap"
        );

        // board-2.bin present, no matching name, no board.bin:
        // the last error is board.bin's -ENOENT, as Linux returns.
        let mut f = FakeFiles::default();
        f.add(
            "board-2.bin",
            build_board2(&[(
                0,
                vec![(0, b"bus=pci,qmi-chip-id=7".to_vec()), (1, vec![1; 4])],
            )]),
        );
        f.add("m3.bin", vec![1; 16]);
        let mut w = wlfw(Script::wcn6855(), f);
        let e = block(w.run_to_fw_ready()).err().ok_or("must fail")?;
        ensure!(
            e.step == step::BDF_FETCH && e.errno == ENOENT,
            "no match, no board.bin"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_board_fallbacks);

fn smoke_wlfw_board_truncation_and_caldata() -> TestResult {
    run_test(|| {
        // 300 KiB ELF board: only board_size (256 KiB) is sent, as 43
        // segments; ELF skips caldata.
        let board = elf_blob(300 * 1024, 3);
        let mut w = wlfw(Script::wcn6855(), standard_files(&board, &[], &[1; 8]));
        let info = block(w.run_to_fw_ready()).map_err(|_| "big board")?;
        ensure!(
            info.board.as_ref().map(|b| b.sent) == Some(256 * 1024),
            "truncated to board_size"
        );
        let fw = &w.client.pipe.fw;
        let bdf: Vec<&Vec<u8>> = fw.reqs.iter().filter(|m| m[3] == 0x25).collect();
        ensure!(bdf.len() == 43, "43 segments of ≤ 6144");
        let want_last = bdf_segments(&board[..256 * 1024], 0xff, ATH11K_QMI_BDF_TYPE_ELF)
            .last()
            .ok_or("last")?;
        ensure!(
            want_last.end == Some(1)
                && want_last.seg_id == Some(42)
                && want_last.total_size == Some(4096),
            "last segment"
        );
        ensure!(
            **bdf.last().unwrap() == enc(&want_last, (4 + 42) as u16),
            "last segment bytes"
        );
        ensure!(
            info.regdb_sent.is_none(),
            "empty regdb data: -ENODATA, ignored"
        );

        // BIN board, eeprom caldata advertised: one EEPROM request, no
        // caldata file lookup.
        let mut s = Script::wcn6855();
        s.cap.eeprom_read_timeout = Some(5);
        let mut w = wlfw(s, standard_files(&bin_blob(100, 1), &[2; 4], &[1; 8]));
        block(w.run_to_fw_ready()).map_err(|_| "eeprom")?;
        let fw = &w.client.pipe.fw;
        ensure!(
            fw.reqs[6] == enc(&bdf_eeprom_request(0xff), 6),
            "EEPROM caldata request"
        );
        ensure!(
            fw.msg_ids()[7] == QMI_WLANFW_M3_INFO_REQ_V01,
            "then m3_info"
        );
        ensure!(
            !w.fw.requested.iter().any(|p| p.contains("cal")),
            "no caldata file"
        );

        // BIN board, no caldata files: CALDATA_FETCH.
        let mut w = wlfw(
            Script::wcn6855(),
            standard_files(&bin_blob(100, 1), &[2; 4], &[1; 8]),
        );
        let e = block(w.run_to_fw_ready()).err().ok_or("must fail")?;
        ensure!(
            e.step == step::CALDATA_FETCH && e.errno == ENOENT,
            "missing caldata"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_wlfw_board_truncation_and_caldata
);

// ══ negatives ════════════════════════════════════════════════════

fn fail_with(s: Script) -> Result<(WlfwError, W<FakeDma>), &'static str> {
    let mut w = wlfw(s, standard_files(&elf_blob(100, 1), &[3; 9], &[1; 8]));
    let e = block(w.run_to_fw_ready())
        .err()
        .ok_or("handshake must fail")?;
    Ok((e, w))
}

fn smoke_wlfw_server_never_appears() -> TestResult {
    run_test(|| {
        let mut s = Script::wcn6855();
        s.hello = false;
        let (e, w) = fail_with(s)?;
        ensure!(
            e.step == step::SERVER_TIMEOUT && e.detail == 0 && e.errno == ETIMEDOUT,
            "no HELLO"
        );
        ensure!(
            w.client.pipe.now >= ATH11K_NARF_IND_TIMEOUT_MS as u64,
            "waited the full bound"
        );
        ensure!(
            w.client.pipe.fw.ul.is_empty(),
            "host stays silent without a HELLO"
        );

        let mut s = Script::wcn6855();
        s.announce = false;
        let (e, w) = fail_with(s)?;
        ensure!(
            e.step == step::SERVER_TIMEOUT && e.detail == 1,
            "HELLO but no NEW_SERVER"
        );
        ensure!(w.client.pipe.fw.host_hello, "HELLO answered");

        // A server with the wrong instance (0x45 v1 ins 2) is not ours.
        let mut s = Script::wcn6855();
        s.instance = qmi_instance(1, 2);
        let (e, _) = fail_with(s)?;
        ensure!(e.step == step::SERVER_TIMEOUT, "instance must be 0x101");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_server_never_appears);

fn smoke_wlfw_qmi_error_results() -> TestResult {
    run_test(|| {
        for (msg, step_code) in [
            (QMI_WLANFW_IND_REGISTER_REQ_V01, step::IND_REGISTER),
            (QMI_WLANFW_HOST_CAP_REQ_V01, step::HOST_CAP),
            (QMI_WLANFW_RESPOND_MEM_REQ_V01, step::RESPOND_MEM),
            (QMI_WLANFW_CAP_REQ_V01, step::TARGET_CAP),
            (QMI_WLANFW_M3_INFO_REQ_V01, step::M3_INFO),
        ] {
            let mut s = Script::wcn6855();
            s.overrides = vec![(msg, 0, Reply::Fail(0x5a))];
            let (e, w) = fail_with(s)?;
            ensure!(e.step == step_code, "failure lands on its own step");
            ensure!(
                e.detail == (2 << 16 | 0x5a) && e.errno == 22,
                "result failure: -EINVAL + QMI error"
            );
            ensure!(
                w.client.pipe.fw.msg_ids().last() == Some(&msg),
                "nothing sent after the failure"
            );
        }
        // BDF segment failure (second board segment).
        let mut s = Script::wcn6855();
        s.overrides = vec![(QMI_WLANFW_BDF_DOWNLOAD_REQ_V01, 2, Reply::Fail(1))];
        let mut w = wlfw(s, standard_files(&elf_blob(10_000, 1), &[3; 9], &[1; 8]));
        let e = block(w.run_to_fw_ready()).err().ok_or("must fail")?;
        ensure!(e.step == step::BDF_DOWNLOAD, "BDF_DOWNLOAD");
        // A failing regdb segment is ignored (Linux discards the
        // regdb load result).
        let mut s = Script::wcn6855();
        s.overrides = vec![(QMI_WLANFW_BDF_DOWNLOAD_REQ_V01, 0, Reply::Fail(1))];
        let mut w = wlfw(s, standard_files(&elf_blob(100, 1), &[3; 9], &[1; 8]));
        let info = block(w.run_to_fw_ready()).map_err(|_| "regdb failure is not fatal")?;
        ensure!(
            info.regdb_sent.is_none() && info.board.is_some(),
            "board still sent"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_qmi_error_results);

fn smoke_wlfw_timeouts_and_decode() -> TestResult {
    run_test(|| {
        // No response to target_cap: -ETIMEDOUT after
        // ATH11K_QMI_WLANFW_TIMEOUT_MS.
        let mut s = Script::wcn6855();
        s.overrides = vec![(QMI_WLANFW_CAP_REQ_V01, 0, Reply::Silent)];
        let (e, w) = fail_with(s)?;
        ensure!(
            e.step == step::TARGET_CAP && e.detail == 1 << 16 && e.errno == ETIMEDOUT,
            "cap timeout"
        );
        ensure!(w.client.pipe.now >= 10_000, "10 s transaction timeout");
        // Undecodable response.
        let mut s = Script::wcn6855();
        s.overrides = vec![(QMI_WLANFW_HOST_CAP_REQ_V01, 0, Reply::Garbage)];
        let (e, _) = fail_with(s)?;
        ensure!(
            e.step == step::HOST_CAP && e.detail >> 16 == 3 && e.errno == 22,
            "decode failure"
        );
        // No FW_MEM_READY / FW_READY / REQUEST_MEM.
        let mut s = Script::wcn6855();
        s.fw_ready = false;
        let (e, _) = fail_with(s)?;
        ensure!(e.step == step::FW_READY_TIMEOUT, "FW_READY never comes");
        let mut s = Script::wcn6855();
        s.mem_rounds = Vec::new();
        let (e, _) = fail_with(s)?;
        ensure!(
            e.step == step::MEM_REQUEST_TIMEOUT,
            "REQUEST_MEM never comes"
        );
        // Flow control never resumed: the 11th DATA packet blocks.
        let mut s = Script::wcn6855();
        s.ack_flow = false;
        let mut w = wlfw(
            s,
            standard_files(&elf_blob(13_000, 1), &bin_blob(7_000, 2), &[1; 8]),
        );
        block(w.run_to_fw_ready()).map_err(|_| "10 packets fit the window")?;
        let e = block(w.firmware_start(0, &[]))
            .err()
            .ok_or("11th must block")?;
        ensure!(
            e.step == step::WLAN_INI && e.detail >> 16 == 7,
            "QRTR flow timeout"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_timeouts_and_decode);

fn smoke_wlfw_m3_and_server_exit() -> TestResult {
    run_test(|| {
        let mut f = standard_files(&elf_blob(100, 1), &[3; 9], &[1; 8]);
        f.files.remove("ath11k/WCN6855/hw2.1/m3.bin");
        let mut w = wlfw(Script::wcn6855(), f);
        let e = block(w.run_to_fw_ready()).err().ok_or("must fail")?;
        ensure!(
            e.step == step::M3_LOAD && e.errno == ENOENT,
            "missing m3.bin"
        );
        ensure!(
            w.client.pipe.fw.msg_ids().last() == Some(&QMI_WLANFW_BDF_DOWNLOAD_REQ_V01),
            "no m3_info sent"
        );
        // M3 allocation failure.
        let mut w = wlfw(
            Script::wcn6855(),
            standard_files(&elf_blob(100, 1), &[3; 9], &vec![1; 0x50_0000]),
        );
        let e = block(w.run_to_fw_ready()).err().ok_or("must fail")?;
        ensure!(
            e.step == step::M3_ALLOC && e.detail == 0x50_0000 && e.errno == ENOMEM,
            "M3_ALLOC"
        );
        // Server goes away after host_cap.
        let mut s = Script::wcn6855();
        s.overrides = vec![(QMI_WLANFW_HOST_CAP_REQ_V01, 0, Reply::ThenDelServer)];
        let (e, _) = fail_with(s)?;
        ensure!(e.step == step::SERVER_EXIT, "DEL_SERVER → SERVER_EXIT");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_m3_and_server_exit);

fn smoke_wlfw_event_ordering() -> TestResult {
    run_test(|| {
        // REQUEST_MEM before the host_cap response, and stray responses
        // with wrong txn ids: same requests, same result.
        let mut s = Script::wcn6855();
        s.early_mem_ind = true;
        s.stray_responses = true;
        let board = elf_blob(100, 1);
        let mut w = wlfw(s, standard_files(&board, &[3; 9], &[1; 8]));
        let info = block(w.run_to_fw_ready()).map_err(|_| "early indication")?;
        let want = expected_sequence(&info.target_mem, &[3; 9], &board, 0xff, info.m3_addr, 8);
        ensure!(w.client.pipe.fw.reqs == want, "identical requests");
        ensure!(
            w.client.stats.unexpected_responses as usize == want.len(),
            "strays dropped"
        );
        // FW_INIT_DONE alone also completes (cold-boot cal unsupported).
        let mut s = Script::wcn6855();
        s.fw_ready = false;
        s.init_done = true;
        let mut w = wlfw(s, standard_files(&board, &[3; 9], &[1; 8]));
        block(w.run_to_fw_ready()).map_err(|_| "FW_INIT_DONE")?;
        ensure!(
            w.registered && w.cal_done == 0,
            "init done: registered, cal_done untouched"
        );
        // Cold-boot calibration (a part with coldboot_cal_mm): mode
        // COLD_BOOT first, then FW_READY completes.
        let mut cfg = config();
        cfg.hw.coldboot_cal_mm = true;
        let mut s = Script::wcn6855();
        s.init_done = true;
        s.fw_ready = false;
        s.overrides = vec![];
        let mut w = wlfw_with(
            s,
            standard_files(&board, &[3; 9], &[1; 8]),
            FakeDma::new(),
            cfg,
        );
        // Firmware answers the COLD_BOOT mode request; then sends FW_READY.
        w.client.pipe.fw.s.fw_ready = false;
        let r = block(w.run_to_fw_ready());
        let ids = w.client.pipe.fw.msg_ids();
        ensure!(
            ids.last() == Some(&QMI_WLANFW_WLAN_MODE_REQ_V01),
            "COLD_BOOT mode sent"
        );
        let last = w.client.pipe.fw.reqs.last().unwrap().clone();
        ensure!(
            last[7..14] == [0x01, 0x04, 0x00, 0x07, 0, 0, 0],
            "mode = ATH11K_FIRMWARE_MODE_COLD_BOOT"
        );
        ensure!(
            r.is_err_and(|e| e.step == step::FW_READY_TIMEOUT),
            "no FW_READY after calibration"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_event_ordering);

fn smoke_wlfw_txn_ids_and_lookup() -> TestResult {
    run_test(|| {
        // idr_alloc_cyclic(.., 0, U16_MAX): 65534 then 0.
        let mut w = wlfw(
            Script::wcn6855(),
            standard_files(&elf_blob(100, 1), &[3; 9], &[1; 8]),
        );
        w.client.set_next_txn_id(65534);
        block(w.run_to_fw_ready()).map_err(|_| "wrap")?;
        let fw = &w.client.pipe.fw;
        let txns: Vec<u16> = fw
            .reqs
            .iter()
            .map(|m| u16::from_le_bytes([m[1], m[2]]))
            .collect();
        ensure!(
            txns[0] == 65534 && txns[1] == 0 && txns[2] == 1,
            "cyclic wrap skips 65535"
        );
        // The lookup is local: NEW_LOOKUP payload Linux would hand its
        // own name service.
        ensure!(
            QrtrLink::new_lookup_payload(0x45, 1, 1)
                == [10, 0, 0, 0, 0x45, 0, 0, 0, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "NEW_LOOKUP 0x45 / 0x101"
        );
        ensure!(
            !fw.ul.iter().any(|f| f[4] == QRTR_TYPE_NEW_LOOKUP as u8),
            "NEW_LOOKUP never goes on the wire"
        );
        // The pci glue's dev_name.
        ensure!(
            super::pci::pci_dev_name((0, 3, 0, 0)) == "0000:03:00.0"
                && super::pci::pci_dev_name((0x1, 0xab, 0x1f, 7)) == "0001:ab:1f.7",
            "dev_name format"
        );
        ensure!(
            w.fw_path("m3.bin") == "ath11k/WCN6855/hw2.1/m3.bin",
            "firmware path"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_txn_ids_and_lookup);

/// `firmware-2.bin` with `(id, data)` IEs, written out from `fw.h`.
fn firmware_n(ies: &[(u32, &[u8])]) -> Vec<u8> {
    let mut v = b"QCOM-ATH11K-FW\0\0".to_vec();
    for (id, data) in ies {
        v.extend_from_slice(&id.to_le_bytes());
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(data);
        while v.len() % 4 != 0 {
            v.push(0);
        }
    }
    v
}

fn smoke_wlfw_m3_from_firmware_n() -> TestResult {
    run_test(|| {
        // ath11k_qmi_m3_load: the M3 IE of firmware-2.bin, no m3.bin.
        let m3 = bin_blob(3_000, 7);
        let file = firmware_n(&[(super::fw::ie::AMSS_IMAGE, &[1, 2, 3]), (3, &m3)]);
        let (api, refused) = super::fw::FwApi::pre_init(|_| Ok(file.clone()));
        ensure!(refused.is_none() && api.api_version == 2, "fw api 2");
        let mut f = standard_files(&elf_blob(100, 1), &[3; 9], &[1; 8]);
        f.files.remove("ath11k/WCN6855/hw2.1/m3.bin");
        let mut w = wlfw(Script::wcn6855(), f);
        w.fw_api = api;
        let info = block(w.run_to_fw_ready()).map_err(|_| "FW_READY with the M3 IE")?;
        let mem = w.m3.as_ref().ok_or("m3 memory")?;
        ensure!(mem.data == m3, "DMA copy of the M3 IE");
        ensure!(
            info.m3_size == 3_000 && info.m3_addr == mem.addr,
            "m3 size / address"
        );
        ensure!(
            !w.fw.requested.iter().any(|p| p.ends_with("m3.bin")),
            "m3.bin not requested"
        );
        let fw = &w.client.pipe.fw;
        let i = fw
            .msg_ids()
            .iter()
            .position(|&id| id == QMI_WLANFW_M3_INFO_REQ_V01)
            .ok_or("m3_info sent")?;
        let txn = u16::from_le_bytes([fw.reqs[i][1], fw.reqs[i][2]]);
        ensure!(
            fw.reqs[i]
                == enc(
                    &M3InfoReq {
                        addr: mem.addr,
                        size: 3_000
                    },
                    txn
                ),
            "m3_info names the IE copy"
        );

        // An empty M3 IE is not used: m3.bin is requested (and missing).
        let file = firmware_n(&[(3, &[])]);
        let (api, _) = super::fw::FwApi::pre_init(|_| Ok(file.clone()));
        let mut f = standard_files(&elf_blob(100, 1), &[3; 9], &[1; 8]);
        f.files.remove("ath11k/WCN6855/hw2.1/m3.bin");
        let mut w = wlfw(Script::wcn6855(), f);
        w.fw_api = api;
        let e = block(w.run_to_fw_ready()).err().ok_or("must fail")?;
        ensure!(
            e.step == step::M3_LOAD && e.errno == ENOENT,
            "empty M3 IE falls back to m3.bin"
        );
        ensure!(
            w.fw.requested.last().map(String::as_str) == Some("ath11k/WCN6855/hw2.1/m3.bin"),
            "m3.bin requested"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_m3_from_firmware_n);

// ══ after FW_READY: late events, restart handshake ════════════════

const WLFW_SRV: CtrlPkt = CtrlPkt::DelServer {
    service: ATH11K_QMI_WLFW_SERVICE_ID_V01,
    instance: 0x101,
    node: DEV_NODE,
    port: SRV_PORT,
};

/// The firmware restarts on its own: DEL_SERVER, then the server is
/// announced again and the handshake script runs from the start.
fn fw_restarts(fw: &mut FakeFw) {
    fw.ctrl(WLFW_SRV);
    fw.mem_round = 0;
    fw.counts.clear();
    fw.ctrl(CtrlPkt::NewServer {
        service: ATH11K_QMI_WLFW_SERVICE_ID_V01,
        instance: fw.s.instance,
        node: DEV_NODE,
        port: SRV_PORT,
    });
}

fn ready_wlfw(
    board: &[u8],
    regdb: &[u8],
    m3: &[u8],
) -> Result<(W<FakeDma>, FwReadyInfo), &'static str> {
    let mut w = wlfw(Script::wcn6855(), standard_files(board, regdb, m3));
    let info = block(w.run_to_fw_ready()).map_err(|_| "FW_READY")?;
    Ok((w, info))
}

fn smoke_wlfw_late_indications() -> TestResult {
    run_test(|| {
        let (board, regdb, m3) = (elf_blob(100, 1), [3u8; 9], [1u8; 8]);
        let (mut w, _) = ready_wlfw(&board, &regdb, &m3)?;
        ensure!(w.late_event().is_none(), "quiet firmware: nothing");

        // COLD_BOOT_CAL_DONE: cal_done = 1, no event (Linux's event case
        // is a no-op).
        w.cal_done = 0;
        w.client
            .pipe
            .fw
            .ind(QMI_WLFW_COLD_BOOT_CAL_DONE_IND_V01, &[]);
        ensure!(w.late_event().is_none(), "COLD_BOOT_CAL_DONE: no event");
        ensure!(w.cal_done == 1, "cal_done set");

        // FW_INIT_DONE with REGISTERED: restart_work; the restart
        // handshake has nothing left to send.
        w.client.pipe.fw.ind(QMI_WLFW_FW_INIT_DONE_IND_V01, &[]);
        ensure!(
            w.late_event() == Some(LateEvent::Restart),
            "FW_INIT_DONE → restart"
        );
        let n = w.client.pipe.fw.reqs.len();
        block(w.run_to_fw_restart()).map_err(|_| "restart consumes FW_INIT_DONE")?;
        ensure!(w.client.pipe.fw.reqs.len() == n, "no request");
        ensure!(w.late_event().is_none(), "event consumed");

        // FW_READY again on WCN6855 (no cbcal_restart_fw): the restart
        // path too.
        w.client.pipe.fw.ind(QMI_WLFW_FW_READY_IND_V01, &[]);
        ensure!(
            w.late_event() == Some(LateEvent::Restart),
            "FW_READY → restart"
        );
        block(w.run_to_fw_restart()).map_err(|_| "restart consumes FW_READY")?;
        // A part with cbcal_restart_fw ignores FW_READY ("no need to
        // process FW ready").
        w.cfg.hw.cbcal_restart_fw = true;
        w.client.pipe.fw.ind(QMI_WLFW_FW_READY_IND_V01, &[]);
        ensure!(
            w.late_event().is_none(),
            "cbcal_restart_fw: FW_READY dropped"
        );
        w.cfg.hw.cbcal_restart_fw = false;

        // A REQUEST_MEM with no SERVER_EXIT before it: the firmware
        // restarted; the chunks are already allocated by the callback.
        w.client.pipe.fw.mem_round = 0;
        w.client.pipe.fw.mem_ind();
        ensure!(
            w.late_event() == Some(LateEvent::ServerExit),
            "handshake event without SERVER_EXIT"
        );
        ensure!(
            w.client
                .pipe
                .logs
                .borrow()
                .iter()
                .any(|l| l.contains("firmware restarted without SERVER_EXIT")),
            "logged"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_late_indications);

fn smoke_wlfw_server_exit_restart_handshake() -> TestResult {
    run_test(|| {
        let (board, regdb, m3) = (elf_blob(100, 1), [3u8; 9], [1u8; 8]);
        let (mut w, info) = ready_wlfw(&board, &regdb, &m3)?;
        let allocs = w.dma.allocs.len();
        let first = w.client.pipe.fw.reqs.len();
        // SERVER_EXIT, then the firmware's own restart.
        fw_restarts(&mut w.client.pipe.fw);
        ensure!(
            w.late_event() == Some(LateEvent::ServerExit),
            "SERVER_EXIT reported"
        );
        block(w.run_to_fw_restart()).map_err(|_| "restart handshake")?;
        // The same requests, with the handle's next transaction ids and
        // cal_done = 1; the target memory and the M3 copy are reused.
        ensure!(
            w.target_mem_list() == info.target_mem,
            "chunks of the same size / type reused"
        );
        ensure!(w.dma.allocs.len() == allocs, "nothing reallocated");
        let want = expected_sequence_from(
            first as u16,
            1,
            &info.target_mem,
            &regdb,
            &board,
            0xff,
            info.m3_addr,
            8,
        );
        ensure!(
            w.client.pipe.fw.reqs[first..] == want[..],
            "restart handshake = Linux's requests"
        );
        ensure!(
            w.fw.requested
                .iter()
                .filter(|p| p.ends_with("m3.bin"))
                .count()
                == 1,
            "M3 loaded once"
        );
        ensure!(w.registered, "still registered");

        // FW_INIT_DONE ends it too (a firmware that sends that).
        w.client.pipe.fw.s.fw_ready = false;
        w.client.pipe.fw.s.init_done = true;
        fw_restarts(&mut w.client.pipe.fw);
        ensure!(w.late_event() == Some(LateEvent::ServerExit), "again");
        block(w.run_to_fw_restart()).map_err(|_| "FW_INIT_DONE restart")?;

        // The server never comes back: SERVER_TIMEOUT.
        w.client.pipe.fw.ctrl(WLFW_SRV);
        ensure!(w.late_event() == Some(LateEvent::ServerExit), "exit");
        let e = block(w.run_to_fw_restart()).err().ok_or("must time out")?;
        ensure!(e.step == step::SERVER_TIMEOUT, "SERVER_TIMEOUT");

        // Back, but no FW_INIT_DONE / FW_READY after m3_info.
        w.client.pipe.fw.s.init_done = false;
        w.client.pipe.fw.mem_round = 0;
        w.client.pipe.fw.counts.clear();
        w.client.pipe.fw.ctrl(CtrlPkt::NewServer {
            service: ATH11K_QMI_WLFW_SERVICE_ID_V01,
            instance: 0x101,
            node: DEV_NODE,
            port: SRV_PORT,
        });
        let e = block(w.run_to_fw_restart()).err().ok_or("must time out")?;
        ensure!(e.step == step::FW_READY_TIMEOUT, "FW_READY_TIMEOUT");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_wlfw_server_exit_restart_handshake
);

fn smoke_wlfw_endpoint_reset_restart_handshake() -> TestResult {
    run_test(|| {
        // ath11k_core_reset's power cycle: the MHI endpoint goes away
        // (its server is reported gone), the device boots again and says
        // HELLO, the handshake reruns on the new link.
        let (board, regdb, m3) = (elf_blob(100, 1), [3u8; 9], [1u8; 8]);
        let (mut w, info) = ready_wlfw(&board, &regdb, &m3)?;
        let next = w.client.next_txn_id();
        // A stale FW_INIT_DONE from the dead firmware is dropped.
        w.client.pipe.fw.ind(QMI_WLFW_FW_INIT_DONE_IND_V01, &[]);
        w.client.pump();
        w.endpoint_reset();
        ensure!(w.client.server().is_none(), "server gone");
        ensure!(!w.client.link().hello_seen(), "link waits for HELLO");
        w.client.pipe.fw = FakeFw::new(Script::wcn6855());
        block(w.run_to_fw_restart()).map_err(|_| "handshake on the new endpoint")?;
        let fw = &w.client.pipe.fw;
        let hello = encode_packet(
            QRTR_TYPE_HELLO,
            HOST_CTRL,
            DEV_CTRL,
            false,
            &CtrlPkt::Hello.to_bytes(),
        )
        .unwrap();
        ensure!(fw.ul.first() == Some(&hello), "HELLO answered first");
        let want = expected_sequence_from(
            next,
            1,
            &info.target_mem,
            &regdb,
            &board,
            0xff,
            info.m3_addr,
            8,
        );
        ensure!(fw.reqs == want, "full handshake, next txn ids, cal_done 1");
        ensure!(
            w.client.server().map(|s| s.node) == Some(DEV_NODE),
            "reconnected"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_wlfw_endpoint_reset_restart_handshake
);

fn smoke_wlfw_service_reports_notices() -> TestResult {
    run_test(|| {
        use super::core::{FwNotice, QmiFw};
        let (board, regdb, m3) = (elf_blob(100, 1), [3u8; 9], [1u8; 8]);
        let (mut w, _) = ready_wlfw(&board, &regdb, &m3)?;
        ensure!(QmiFw::service(&mut w).is_none(), "nothing to report");
        w.client.pipe.fw.ind(QMI_WLFW_FW_INIT_DONE_IND_V01, &[]);
        ensure!(
            QmiFw::service(&mut w) == Some(FwNotice::Restart),
            "FW_INIT_DONE → Restart"
        );
        block(w.run_to_fw_restart()).map_err(|_| "consume")?;
        w.client.pipe.fw.ctrl(WLFW_SRV);
        ensure!(
            QmiFw::service(&mut w) == Some(FwNotice::ServerExit),
            "DEL_SERVER → ServerExit"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_wlfw_service_reports_notices
);

fn smoke_wlfw_recover_with_power_cycle() -> TestResult {
    run_test(|| {
        use super::core::QmiFw;
        let (board, regdb, m3) = (elf_blob(100, 1), [3u8; 9], [1u8; 8]);
        let (mut w, info) = ready_wlfw(&board, &regdb, &m3)?;
        let next = w.client.next_txn_id();
        // ath11k_core_reset: power cycle, endpoint reset, handshake.
        block(QmiFw::recover(&mut w, true)).map_err(|_| "recover(power_cycle)")?;
        ensure!(
            w.client
                .pipe
                .logs
                .borrow()
                .iter()
                .any(|l| l == "power cycle"),
            "pipe power-cycled"
        );
        let want = expected_sequence_from(
            next,
            1,
            &info.target_mem,
            &regdb,
            &board,
            0xff,
            info.m3_addr,
            8,
        );
        ensure!(w.client.pipe.fw.reqs == want, "handshake on the new boot");
        // Without a power cycle (SERVER_EXIT seen): the firmware restarts
        // itself.
        fw_restarts(&mut w.client.pipe.fw);
        ensure!(
            QmiFw::service(&mut w) == Some(super::core::FwNotice::ServerExit),
            "notice"
        );
        block(QmiFw::recover(&mut w, false)).map_err(|_| "recover()")?;
        // The handshake fails: the error comes back with its step.
        w.client.pipe.fw.s.overrides = vec![(QMI_WLANFW_HOST_CAP_REQ_V01, 0, Reply::Fail(3))];
        let e = block(QmiFw::recover(&mut w, true))
            .err()
            .ok_or("host_cap refused")?;
        ensure!(e.step == step::HOST_CAP, "HOST_CAP step");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_wlfw_recover_with_power_cycle
);

// ── Devicetree board variant / fixed memory region ────────────────

/// A DTB: `/reserved-memory/wlan` (phandle 7) and a host bridge (domain
/// 0) → root port (devfn 0) → WCN6855 (devfn 0) with `props`.
fn wcn6855_dtb(props: &[(&str, &[u8])]) -> Vec<u8> {
    let mut strings = Vec::new();
    let mut s = Vec::new();
    let mut prop = |s: &mut Vec<u8>, name: &str, value: &[u8]| {
        let off = strings.len() as u32;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
        s.extend_from_slice(&3u32.to_be_bytes());
        s.extend_from_slice(&(value.len() as u32).to_be_bytes());
        s.extend_from_slice(&off.to_be_bytes());
        s.extend_from_slice(value);
        while s.len() % 4 != 0 {
            s.push(0);
        }
    };
    let begin = |s: &mut Vec<u8>, name: &str| {
        s.extend_from_slice(&1u32.to_be_bytes());
        s.extend_from_slice(name.as_bytes());
        s.push(0);
        while s.len() % 4 != 0 {
            s.push(0);
        }
    };
    let end = |s: &mut Vec<u8>| s.extend_from_slice(&2u32.to_be_bytes());
    begin(&mut s, "");
    begin(&mut s, "reserved-memory");
    prop(&mut s, "#address-cells", &[0, 0, 0, 2]);
    prop(&mut s, "#size-cells", &[0, 0, 0, 2]);
    begin(&mut s, "wlan@8c400000");
    prop(
        &mut s,
        "reg",
        &[0, 0, 0, 0, 0x8c, 0x40, 0, 0, 0, 0, 0, 0, 0, 0x30, 0, 0],
    );
    prop(&mut s, "phandle", &[0, 0, 0, 7]);
    end(&mut s);
    end(&mut s);
    begin(&mut s, "pcie@1c08000");
    prop(&mut s, "device_type", b"pci\0");
    prop(&mut s, "linux,pci-domain", &[0, 0, 0, 0]);
    begin(&mut s, "pcie@0");
    prop(&mut s, "device_type", b"pci\0");
    prop(&mut s, "reg", &[0; 20]);
    begin(&mut s, "wifi@0");
    prop(&mut s, "reg", &[0; 20]);
    for (name, value) in props {
        prop(&mut s, name, value);
    }
    end(&mut s);
    end(&mut s);
    end(&mut s);
    end(&mut s);
    s.extend_from_slice(&9u32.to_be_bytes());
    let off_struct = 40u32 + 16;
    let off_strings = off_struct + s.len() as u32;
    let mut out = Vec::new();
    for v in [
        0xd00d_feedu32,
        off_strings + strings.len() as u32,
        off_struct,
        off_strings,
        40,
        17,
        16,
        0,
        strings.len() as u32,
        s.len() as u32,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&[0; 16]);
    out.extend_from_slice(&s);
    out.extend_from_slice(&strings);
    out
}

/// `ath11k_core_check_dt`: `qcom,calibration-variant` before the legacy
/// `qcom,ath11k-calibration-variant`, `strscpy` truncation, the DT value
/// replacing an SMBIOS one, `memory-region` → `ATH11K_FLAG_FIXED_MEM_RGN`
/// with its `/reserved-memory` resource, and no node / no DTB facts.
fn smoke_wlfw_dt_board_variant() -> TestResult {
    run_test(|| {
        let both = wcn6855_dtb(&[
            ("qcom,ath11k-calibration-variant", b"LEGACY\0"),
            ("qcom,calibration-variant", b"LE_X13S\0"),
            ("memory-region", &[0, 0, 0, 7]),
        ]);
        let facts = dt_facts_in(&both, 0, &[0, 0]).ok_or("node not associated")?;
        ensure!(
            facts.variant.as_deref() == Some(&b"LE_X13S"[..])
                && facts.memory_region
                && facts.reserved == Some((0x8c40_0000, 0x30_0000)),
            "variant / memory-region facts"
        );
        let legacy = wcn6855_dtb(&[("qcom,ath11k-calibration-variant", b"LEGACY\0")]);
        let facts = dt_facts_in(&legacy, 0, &[0, 0]).ok_or("legacy node")?;
        ensure!(
            facts.variant.as_deref() == Some(&b"LEGACY"[..]) && !facts.memory_region,
            "legacy property fallback"
        );
        let long = wcn6855_dtb(&[(
            "qcom,calibration-variant",
            b"0123456789abcdef0123456789abcdefXYZ\0",
        )]);
        ensure!(
            dt_facts_in(&long, 0, &[0, 0])
                .and_then(|f| f.variant)
                .is_some_and(|v| v.len() == ATH11K_QMI_BDF_EXT_STR_LENGTH - 1),
            "strscpy truncation"
        );
        let unterminated = wcn6855_dtb(&[("qcom,calibration-variant", b"NONUL")]);
        ensure!(
            dt_facts_in(&unterminated, 0, &[0, 0]).is_some_and(|f| f.variant.is_none()),
            "unterminated string accepted"
        );
        ensure!(
            dt_facts_in(&both, 0, &[0, 8]).is_none() && dt_facts_in(&both, 1, &[0, 0]).is_none(),
            "foreign function / domain associated"
        );
        let dt = dt_facts_in(&both, 0, &[0, 0]);
        ensure!(
            bdf_ext(b"SMBIOS".to_vec(), dt.as_ref()) == b"LE_X13S"
                && bdf_ext(b"SMBIOS".to_vec(), None) == b"SMBIOS"
                && bdf_ext(
                    b"SMBIOS".to_vec(),
                    dt_facts_in(&wcn6855_dtb(&[]), 0, &[0, 0]).as_ref()
                ) == b"SMBIOS",
            "SMBIOS then DT order"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_dt_board_variant);

/// `ATH11K_FLAG_FIXED_MEM_RGN`: `ath11k_qmi_assign_target_mem_chunk` puts
/// HOST_DDR at the reserved region, BDF at `bdf_addr`, CALDB after HOST_DDR
/// (cold-boot calibration) or at 0, drops other types, never allocates DMA
/// and never answers "delayed"; a missing/small region or oversized CALDB
/// fails.
fn smoke_wlfw_fixed_mem_region() -> TestResult {
    run_test(|| {
        let segs = [
            (QMI_WLANFW_MEM_TYPE_DDR_V01, 0x10_0000),
            (QMI_WLANFW_MEM_CAL_V01, 0x1000),
            (QMI_WLANFW_MEM_BDF_V01, 0x2000),
            (QMI_WLANFW_MEM_M3_V01, 0x3000),
        ];
        let region = Some((0x8c40_0000, 0x30_0000));
        ensure!(
            assign_fixed_target_mem(&segs, region, 0, true)
                == Ok(vec![
                    (0x8c40_0000, 0x10_0000, 1),
                    (0x8c50_0000, 0x1000, 4),
                    (0, 0x2000, 2),
                ]),
            "cold-boot CALDB after HOST_DDR"
        );
        ensure!(
            assign_fixed_target_mem(&segs[1..2], None, 0, true)
                == Ok(vec![(ATH11K_QMI_CALDB_ADDRESS, 0x1000, 4)])
                && assign_fixed_target_mem(&segs[1..2], None, 0, false) == Ok(vec![(0, 0x1000, 4)]),
            "CALDB without HOST_DDR"
        );
        ensure!(
            assign_fixed_target_mem(&segs, None, 0, true) == Err(ENOENT)
                && assign_fixed_target_mem(&segs, Some((0x8c40_0000, 0x1000)), 0, true)
                    == Err(EINVAL)
                && assign_fixed_target_mem(
                    &[(QMI_WLANFW_MEM_CAL_V01, ATH11K_QMI_CALDB_SIZE + 1)],
                    region,
                    0,
                    true
                ) == Err(EINVAL),
            "assignment failures"
        );
        // Full handshake: one round, fixed addresses, only M3 allocated.
        let mut s = Script::wcn6855();
        s.mem_rounds = vec![vec![
            seg(0x10_0000, QMI_WLANFW_MEM_TYPE_DDR_V01),
            seg(0x1000, QMI_WLANFW_MEM_CAL_V01),
        ]];
        let board = elf_blob(100, 7);
        let cfg = config().with_fixed_mem_region(region);
        let caldb = if cfg.coldboot_cal_support() {
            0x8c50_0000
        } else {
            0
        };
        let mut w = wlfw_with(
            s,
            standard_files(&board, &[1, 2, 3], &[9; 64]),
            FakeDma::new(),
            cfg,
        );
        let info = block(w.run_to_fw_ready()).map_err(|_| "fixed-memory handshake")?;
        ensure!(
            info.mem_delayed_rounds == 0
                && info.target_mem == [(0x8c40_0000, 0x10_0000, 1), (caldb, 0x1000, 4)]
                && w.dma.allocs.len() == 1,
            "fixed region answered without DMA chunks"
        );
        // A memory-region whose resource cannot be resolved stalls Linux;
        // here the handshake fails with TARGET_MEM_ALLOC.
        let mut s = Script::wcn6855();
        s.mem_rounds = vec![vec![seg(0x10_0000, QMI_WLANFW_MEM_TYPE_DDR_V01)]];
        let mut w = wlfw_with(
            s,
            standard_files(&board, &[1, 2, 3], &[9; 64]),
            FakeDma::new(),
            config().with_fixed_mem_region(None),
        );
        let e = block(w.run_to_fw_ready())
            .err()
            .ok_or("unresolved region")?;
        ensure!(e.step == step::TARGET_MEM_ALLOC, "TARGET_MEM_ALLOC");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_fixed_mem_region);
