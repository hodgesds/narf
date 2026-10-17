//! Offline tests for the QMI codec ([`super::qmi`]), the WLFW message
//! set ([`super::qmi_wlfw`]) and QRTR framing ([`super::qrtr`]).
//!
//! Golden vectors: every WLFW byte array below is what Linux's own
//! `drivers/soc/qcom/qmi_encdec.c::qmi_encode_message`, run on the
//! `*_ei[]` tables of `drivers/net/wireless/ath/ath11k/qmi.c` with
//! the struct filled exactly as the named `ath11k_qmi_*_send`
//! function fills it, produced (the two sources compiled unmodified
//! into a host program). The short ones are annotated TLV by TLV
//! with the ei entry each byte comes from; long ones are checked by
//! length + FNV-1a-64 of the whole message, also taken from that
//! run. Decode cases record what `qmi_decode_message` returned for
//! the same bytes, and say where this codec deliberately differs.
//! QRTR vectors are derived by hand from `qrtr_node_enqueue` /
//! `struct qrtr_hdr_v1` / `struct qrtr_ctrl_pkt`.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

use super::hw::HwRev;
use super::qmi::*;
use super::qmi_wlfw::*;
use super::qrtr::*;

type R = Result<(), &'static str>;

fn run(f: impl FnOnce() -> R) -> TestResult {
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

/// FNV-1a 64 — same function the oracle printed.
fn fnv(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &x in b {
        h ^= x as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn wcn6855() -> WlfwHwParams {
    wlfw_hw_params(HwRev::Wcn6855Hw21).expect("wcn6855 hw2.1 params")
}

fn enc<T: WlfwRequest>(m: &T, txn: u16) -> Result<Vec<u8>, &'static str> {
    m.encode(txn).map_err(|_| "encode failed")
}

/// Prefix `payload` with a response/indication header for decode tests.
fn msg(msg_type: u8, msg_id: u16, payload: &[u8]) -> Vec<u8> {
    encode_message(msg_type, msg_id, 0, payload)
}

/// TLV 0x02 `qmi_response_type_v01` = {SUCCESS, NONE}.
const RESP_OK: [u8; 7] = [0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00];

// ══ QMI codec ═══════════════════════════════════════════════════════

fn smoke_qmi_header_roundtrip() -> TestResult {
    run(|| {
        let h = QmiHeader {
            msg_type: QMI_RESPONSE,
            txn_id: 0xBEEF,
            msg_id: 0x0024,
            msg_len: 0x0102,
        };
        // struct qmi_header: u8 type, __le16 txn_id, msg_id, msg_len; packed.
        ensure!(
            h.to_bytes() == [0x02, 0xEF, 0xBE, 0x24, 0x00, 0x02, 0x01],
            "qmi_header byte layout"
        );
        ensure!(
            QmiHeader::parse(&h.to_bytes()) == Ok(h),
            "header parse roundtrip"
        );
        ensure!(
            QmiHeader::parse(&[0u8; 6]) == Err(QmiError::ShortHeader),
            "6-byte message must be refused (qmi_handle_message)"
        );
        // Decoding ignores msg_len, as qmi_decode_message does.
        let m = [0x02, 0, 0, 0x34, 0, 0xFF, 0xFF, 0x02, 0x04, 0, 0, 0, 0, 0];
        let (_, r) = HostCapResp::decode(&m).map_err(|_| "msg_len must not be consulted")?;
        ensure!(r.resp.is_success(), "resp decoded");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_qmi_header_roundtrip);

fn smoke_qmi_writer_limits() -> TestResult {
    run(|| {
        // Payload larger than *_MAX_LEN → -ETOOSMALL.
        let mut w = TlvWriter::new(6);
        w.u32(0x10, 1);
        ensure!(
            w.finish() == Err(QmiError::BufferTooSmall { needed: 7, max: 6 }),
            "7-byte payload over a 6-byte max must fail"
        );
        let mut w = TlvWriter::new(7);
        w.u32(0x10, 1);
        ensure!(w.finish().is_ok(), "exactly max_len is allowed");
        // Top-level string: strlen > elem_len → -EINVAL; == elem_len ok.
        let mut w = TlvWriter::new(64);
        ensure!(
            w.string(0x10, b"abcd", 4).is_ok(),
            "strlen == elem_len encodes"
        );
        ensure!(
            w.string(0x10, b"abcde", 4).is_err(),
            "strlen > elem_len must fail"
        );
        // strlen stops at the first NUL.
        let mut w = TlvWriter::new(64);
        w.string(0x10, b"WIN\0junk", 17).map_err(|_| "string")?;
        ensure!(
            w.finish() == Ok(vec![0x10, 0x03, 0x00, b'W', b'I', b'N']),
            "string encodes strlen bytes, no NUL, no count"
        );
        // Nested string: u8 count when elem_len <= 255, u16 above.
        let mut w = TlvWriter::new(600);
        w.struct_tlv(0x11, |s| {
            s.string(b"ab", 33)?;
            s.string(b"cd", 256)?;
            Ok(())
        })
        .map_err(|_| "nested")?;
        ensure!(
            w.finish()
                == Ok(vec![
                    0x11, 0x07, 0x00, 0x02, b'a', b'b', 0x02, 0x00, b'c', b'd'
                ]),
            "nested string count width"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_qmi_writer_limits);

fn smoke_qmi_decode_unknown_tlvs() -> TestResult {
    run(|| {
        // Oracle D1: unknown optional TLV 0x30 between known ones is
        // skipped (qmi_decode: !temp_ei && type >= 0x10).
        let p = [
            0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x02, 0x00, 0xAA, 0xBB, 0x15, 0x01,
            0x00, 0x03,
        ];
        let c = CapResp::decode_payload(&p).map_err(|_| "unknown optional TLV must be skipped")?;
        ensure!(c.num_macs == Some(3), "TLV after the skipped one decoded");
        // Oracle D12: an unknown optional TLV whose length runs past
        // the end is stepped over and the message accepted.
        let p = [
            0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0xFF, 0x00, 0x01,
        ];
        ensure!(
            CapResp::decode_payload(&p).is_ok(),
            "overrunning unknown optional TLV is accepted like Linux"
        );
        // Oracle D2: unknown TLV type 0x05 (< 0x10) → -EINVAL.
        let p = [
            0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00,
        ];
        ensure!(
            CapResp::decode_payload(&p) == Err(QmiError::UnknownMandatoryTlv(0x05)),
            "unknown mandatory TLV must be refused"
        );
        // Oracle D14/D14b: an empty-ei indication skips 0x10, refuses 0x01.
        ensure!(
            FwReadyInd::decode_payload(&[0x10, 0x01, 0x00, 0x00]).is_ok(),
            "fw_ready with optional TLV"
        );
        ensure!(
            FwReadyInd::decode_payload(&[0x01, 0x01, 0x00, 0x00])
                == Err(QmiError::UnknownMandatoryTlv(0x01)),
            "fw_ready with mandatory TLV"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_qmi_decode_unknown_tlvs);

fn smoke_qmi_decode_truncated_and_bad_lengths() -> TestResult {
    run(|| {
        // TLV header cut short (2 of 3 bytes).
        ensure!(
            HostCapResp::decode_payload(&[0x02, 0x04]) == Err(QmiError::Truncated { tlv: 0x02 }),
            "truncated TLV header"
        );
        // Known TLV value runs past the payload.
        ensure!(
            HostCapResp::decode_payload(&[0x02, 0x04, 0x00, 0x00, 0x00])
                == Err(QmiError::Truncated { tlv: 0x02 }),
            "truncated TLV value"
        );
        // Basic-element TLV with the wrong length (u8 num_macs, len 2).
        let mut p = RESP_OK.to_vec();
        p.extend_from_slice(&[0x15, 0x02, 0x00, 0x03, 0x00]);
        ensure!(
            CapResp::decode_payload(&p)
                == Err(QmiError::LengthMismatch {
                    tlv: 0x15,
                    expected: 1,
                    got: 2
                }),
            "basic TLV length must equal the element size"
        );
        // Oracle D4: resp struct cut mid-member (3 bytes) → -EFAULT.
        ensure!(
            HostCapResp::decode_payload(&[0x02, 0x03, 0x00, 0x01, 0x00, 0x00]).is_err(),
            "resp struct of 3 bytes"
        );
        // Oracle D4b: resp struct with a trailing byte → -EFAULT.
        ensure!(
            HostCapResp::decode_payload(&[0x02, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00])
                == Err(QmiError::StructLengthMismatch { tlv: 0x02 }),
            "resp struct of 5 bytes"
        );
        // Oracle D3: resp struct of 2 bytes ends on a member boundary;
        // Linux accepts it with error = 0. So do we.
        let r = HostCapResp::decode_payload(&[0x02, 0x02, 0x00, 0x01, 0x00])
            .map_err(|_| "2-byte resp struct is accepted by Linux")?;
        ensure!(
            r.resp
                == QmiResponse {
                    result: 1,
                    error: 0
                },
            "short resp leaves error zero"
        );
        // Oracle D15: chip_info with only chip_id (4 of 8 bytes).
        let mut p = RESP_OK.to_vec();
        p.extend_from_slice(&[0x10, 0x04, 0x00, 0x12, 0x00, 0x00, 0x00]);
        let c = CapResp::decode_payload(&p).map_err(|_| "short chip_info accepted")?;
        ensure!(
            c.chip_info
                == Some(RfChipInfo {
                    chip_id: 0x12,
                    chip_family: 0
                }),
            "short chip_info zero-fills chip_family"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_qmi_decode_truncated_and_bad_lengths
);

fn smoke_qmi_decode_missing_mandatory_and_duplicates() -> TestResult {
    run(|| {
        // Oracle D10: Linux decodes a response without TLV 0x02 as
        // result = 0 (SUCCESS). Deliberate deviation: refuse it.
        ensure!(
            CapResp::decode_payload(&[0x15, 0x01, 0x00, 0x03])
                == Err(QmiError::MissingMandatoryTlv(0x02)),
            "response without TLV 0x02"
        );
        ensure!(
            HostCapResp::decode_payload(&[]) == Err(QmiError::MissingMandatoryTlv(0x02)),
            "empty response"
        );
        ensure!(
            RequestMemInd::decode_payload(&[]) == Err(QmiError::MissingMandatoryTlv(0x01)),
            "request_mem without mem_seg"
        );
        // Oracle D13: a repeated TLV — the last copy wins.
        let mut p = RESP_OK.to_vec();
        p.extend_from_slice(&[0x15, 0x01, 0x00, 0x03, 0x15, 0x01, 0x00, 0x09]);
        let c = CapResp::decode_payload(&p).map_err(|_| "dup")?;
        ensure!(c.num_macs == Some(9), "last duplicate wins");
        // Raw iterator: same TLVs, then stops on a truncated tail.
        let mut it = TlvReader::new(&[0x10, 0x01, 0x00, 0x07, 0x11, 0x05, 0x00, 0x01]);
        ensure!(
            it.next()
                == Some(Ok(Tlv {
                    ty: 0x10,
                    value: &[0x07]
                })),
            "first TLV"
        );
        ensure!(
            it.next() == Some(Err(QmiError::Truncated { tlv: 0x11 })),
            "truncated second TLV"
        );
        ensure!(it.next().is_none(), "iterator stops after an error");
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_qmi_decode_missing_mandatory_and_duplicates
);

// ══ WLFW requests ═══════════════════════════════════════════════════

fn smoke_wlfw_service_constants() -> TestResult {
    run(|| {
        ensure!(ATH11K_QMI_WLFW_SERVICE_ID_V01 == 0x45, "WLFW service id");
        ensure!(ATH11K_QMI_WLFW_SERVICE_VERS_V01 == 0x01, "WLFW version");
        let p = wcn6855();
        ensure!(
            p.qmi_service_ins_id == ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_QCA6390
                && p.qmi_service_ins_id == 1,
            "WCN6855 uses the QCA6390 instance id 1"
        );
        let q = wlfw_hw_params(HwRev::Qcn9074Hw10).ok_or("qcn9074")?;
        ensure!(q.qmi_service_ins_id == 0x07, "QCN9074 instance id");
        ensure!(
            !wlfw_hw_params(HwRev::Qca6390Hw20)
                .ok_or("qca6390")?
                .supports_regdb,
            "QCA6390 has no regdb"
        );
        ensure!(wlfw_hw_params(HwRev::Unknown).is_none(), "unknown rev");
        ensure!(QMI_WLANFW_CLIENT_ID.to_le_bytes() == *b"LENK", "client id");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_service_constants);

/// Oracle E1 — `ath11k_qmi_host_cap_send` on WCN6855 HW2.1 (first
/// boot, `cal_done = 0`), txn 1.
const HOST_CAP_WCN6855: [u8; 38] = [
    0x00, 0x01, 0x00, 0x34, 0x00, 0x1f, 0x00, // header: REQUEST, txn 1, 0x0034, len 31
    0x10, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, // 0x10 num_clients (UNSIGNED_4_BYTE) = 1
    0x13, 0x01, 0x00, 0x1e, // 0x13 nm_modem (UNSIGNED_1_BYTE), see below
    0x14, 0x01, 0x00, 0x01, // 0x14 bdf_support = 1
    0x16, 0x01, 0x00, 0x01, // 0x16 m3_support = 1 (m3_fw_support)
    0x17, 0x01, 0x00, 0x01, // 0x17 m3_cache_support = 1
    0x1a, 0x01, 0x00, 0x00, // 0x1A cal_done = qmi.cal_done (0)
    0x1c, 0x01, 0x00, 0x00, // 0x1C mem_cfg_mode = hw_params.fw_mem_mode (0)
];
// nm_modem 0x1e = HOST_CSTATE_BIT 0x04 | SLEEP_CLOCK_SELECT_INTERNAL_BIT
// 0x02 (both: internal_sleep_clock) | PLATFORM_CAP_PCIE_GLOBAL_RESET 0x08
// (global_reset) | PLATFORM_CAP_PCIE_PME_D3COLD 0x10 (always).

fn smoke_wlfw_host_cap_wcn6855_golden() -> TestResult {
    run(|| {
        let req = HostCapReq::ath11k(&wcn6855(), 0);
        ensure!(
            enc(&req, 1)? == HOST_CAP_WCN6855,
            "host_cap WCN6855 bytes differ from Linux"
        );
        // Oracle E1b: cal_done = 1 after FW_READY, txn 0x0102 —
        // only the txn and the 0x1A value byte change.
        let mut want = HOST_CAP_WCN6855;
        want[1] = 0x02;
        want[2] = 0x01;
        want[33] = 0x01;
        let got = enc(&HostCapReq::ath11k(&wcn6855(), 1), 0x0102)?;
        ensure!(got == want, "host_cap cal_done=1");
        ensure!(
            fnv(&got) == 0x6491_7814_3083_fea0,
            "host_cap cal_done=1 fnv"
        );
        // Every WCN6855-family stepping sends the same request.
        for rev in [
            HwRev::Wcn6855Hw20,
            HwRev::Qca2066Hw21,
            HwRev::Qca6698aqHw21,
            HwRev::Qca6390Hw20,
        ] {
            let p = wlfw_hw_params(rev).ok_or("rev")?;
            ensure!(
                enc(&HostCapReq::ath11k(&p, 0), 1)? == HOST_CAP_WCN6855,
                "WCN6855-family host_cap"
            );
        }
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_wlfw_host_cap_wcn6855_golden
);

fn smoke_wlfw_host_cap_variants() -> TestResult {
    run(|| {
        // Oracle E2 — QCN9074: no internal_sleep_clock → no 0x13 at all
        // (nm_modem_valid stays 0 although PME_D3COLD is ORed in);
        // mem_cfg_mode = fw_mem_mode 2.
        const QCN9074: [u8; 34] = [
            0x00, 0x01, 0x00, 0x34, 0x00, 0x1b, 0x00, // header, msg_len 27
            0x10, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, // num_clients 1
            0x14, 0x01, 0x00, 0x01, // bdf_support
            0x16, 0x01, 0x00, 0x01, // m3_support
            0x17, 0x01, 0x00, 0x01, // m3_cache_support
            0x1a, 0x01, 0x00, 0x00, // cal_done
            0x1c, 0x01, 0x00, 0x02, // mem_cfg_mode 2
        ];
        let p = wlfw_hw_params(HwRev::Qcn9074Hw10).ok_or("qcn9074")?;
        ensure!(
            enc(&HostCapReq::ath11k(&p, 0), 1)? == QCN9074,
            "host_cap QCN9074"
        );

        // Oracle E3 — every field, gpios {7, 0x11223344}: the 0x12
        // TLV is DATA_LEN (u8) + VAR_LEN_ARRAY of u32.
        const ALL: [u8; 76] = [
            0x00, 0x34, 0x12, 0x34, 0x00, 0x45, 0x00, 0x10, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x11, 0x04, 0x00, 0xcd, 0xab, 0x00, 0x00, 0x12, 0x09, 0x00, 0x02, 0x07, 0x00, 0x00,
            0x00, 0x44, 0x33, 0x22, 0x11, 0x13, 0x01, 0x00, 0x1e, 0x14, 0x01, 0x00, 0x01, 0x15,
            0x01, 0x00, 0x02, 0x16, 0x01, 0x00, 0x03, 0x17, 0x01, 0x00, 0x04, 0x18, 0x01, 0x00,
            0x05, 0x19, 0x01, 0x00, 0x06, 0x1a, 0x01, 0x00, 0x07, 0x1b, 0x04, 0x00, 0x04, 0x03,
            0x02, 0x01, 0x1c, 0x01, 0x00, 0x09,
        ];
        let mut all = HostCapReq {
            num_clients: Some(2),
            wake_msi: Some(0xabcd),
            gpios: Some(vec![7, 0x1122_3344]),
            nm_modem: Some(0x1e),
            bdf_support: Some(1),
            bdf_cache_support: Some(2),
            m3_support: Some(3),
            m3_cache_support: Some(4),
            cal_filesys_support: Some(5),
            cal_cache_support: Some(6),
            cal_done: Some(7),
            mem_bucket: Some(0x0102_0304),
            mem_cfg_mode: Some(9),
        };
        ensure!(enc(&all, 0x1234)? == ALL, "host_cap all fields");
        ensure!(
            ALL[21..30] == [0x12, 0x09, 0x00, 0x02, 0x07, 0x00, 0x00, 0x00, 0x44],
            "gpios TLV head"
        );
        // Oracle E3b — gpios_valid with gpios_len 0: TLV of just the count.
        const NO_GPIO: [u8; 68] = [
            0x00, 0x34, 0x12, 0x34, 0x00, 0x3d, 0x00, 0x10, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x11, 0x04, 0x00, 0xcd, 0xab, 0x00, 0x00, 0x12, 0x01, 0x00, 0x00, 0x13, 0x01, 0x00,
            0x1e, 0x14, 0x01, 0x00, 0x01, 0x15, 0x01, 0x00, 0x02, 0x16, 0x01, 0x00, 0x03, 0x17,
            0x01, 0x00, 0x04, 0x18, 0x01, 0x00, 0x05, 0x19, 0x01, 0x00, 0x06, 0x1a, 0x01, 0x00,
            0x07, 0x1b, 0x04, 0x00, 0x04, 0x03, 0x02, 0x01, 0x1c, 0x01, 0x00, 0x09,
        ];
        all.gpios = Some(Vec::new());
        ensure!(enc(&all, 0x1234)? == NO_GPIO, "host_cap empty gpios");
        ensure!(
            NO_GPIO[21..25] == [0x12, 0x01, 0x00, 0x00],
            "empty var array TLV"
        );
        // Oracle E3c — gpios_len 33 > QMI_WLFW_MAX_NUM_GPIO_V01 → -EINVAL.
        all.gpios = Some(vec![0; 33]);
        ensure!(
            all.encode(0)
                == Err(QmiError::ArrayTooLong {
                    tlv: 0x12,
                    len: 33,
                    max: 32
                }),
            "33 gpios must fail"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_host_cap_variants);

fn smoke_wlfw_ind_register_golden() -> TestResult {
    run(|| {
        // Oracle E4 — ath11k_qmi_fw_ind_register_send, !fixed_fw_mem, txn 2.
        const IND: [u8; 34] = [
            0x00, 0x02, 0x00, 0x20, 0x00, 0x1b, 0x00, // header: msg 0x0020, len 27
            0x10, 0x01, 0x00, 0x01, // fw_ready_enable
            0x15, 0x04, 0x00, 0x4c, 0x45, 0x4e, 0x4b, // client_id QMI_WLANFW_CLIENT_ID
            0x16, 0x01, 0x00, 0x01, // request_mem_enable
            0x17, 0x01, 0x00, 0x01, // fw_mem_ready_enable
            0x18, 0x01, 0x00, 0x01, // fw_init_done_enable
            0x1b, 0x01, 0x00, 0x01, // cal_done_enable
        ];
        let req = IndRegisterReq::ath11k(&wcn6855());
        ensure!(enc(&req, 2)? == IND, "ind_register bytes differ from Linux");
        // Oracle E4b — rejuvenate_enable is a u32 field with a 1-byte ei
        // entry: Linux sends only the low byte (0x01020305 → 0x05).
        const IND_REJ: [u8; 38] = [
            0x00, 0x02, 0x00, 0x20, 0x00, 0x1f, 0x00, 0x10, 0x01, 0x00, 0x01, 0x15, 0x04, 0x00,
            0x4c, 0x45, 0x4e, 0x4b, 0x16, 0x01, 0x00, 0x01, 0x17, 0x01, 0x00, 0x01, 0x18, 0x01,
            0x00, 0x01, 0x19, 0x01, 0x00, 0x05, 0x1b, 0x01, 0x00, 0x01,
        ];
        let rej = IndRegisterReq {
            rejuvenate_enable: Some(0x05),
            ..req
        };
        ensure!(enc(&rej, 2)? == IND_REJ, "ind_register rejuvenate byte");
        // fixed_fw_mem (WCN6750) drops 0x16/0x17.
        let fixed = WlfwHwParams {
            fixed_fw_mem: true,
            ..wcn6855()
        };
        let p = IndRegisterReq::ath11k(&fixed)
            .payload()
            .map_err(|_| "enc")?;
        ensure!(
            !p.windows(3).any(|w| w == [0x16, 0x01, 0x00]),
            "fixed_fw_mem must not register request_mem"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_ind_register_golden);

fn smoke_wlfw_respond_mem_golden() -> TestResult {
    run(|| {
        // Oracle E5 — the "delayed" answer: mandatory 0x01 with count 0.
        const DELAYED: [u8; 11] = [
            0x00, 0x03, 0x00, 0x36, 0x00, 0x04, 0x00, // header: msg 0x0036, len 4
            0x01, 0x01, 0x00, 0x00, // mem_seg_len (u8) = 0, no mem_seg
        ];
        ensure!(
            enc(&RespondMemReq::default(), 3)? == DELAYED,
            "respond_mem delayed"
        );
        // Oracle E6 — two chunks: 0x01 = u8 count + 17-byte
        // qmi_wlanfw_mem_seg_resp_s_v01 {u64 addr, u32 size, i32 type, u8 restore}.
        const TWO: [u8; 45] = [
            0x00, 0x04, 0x00, 0x36, 0x00, 0x26, 0x00, // header, len 38
            0x01, 0x23, 0x00, 0x02, // TLV len 35, mem_seg_len 2
            0x00, 0x60, 0x45, 0x23, 0x01, 0x00, 0x00, 0x00, // addr 0x1_2345_6000
            0x00, 0x00, 0x18, 0x00, // size 0x180000
            0x01, 0x00, 0x00, 0x00, // type DDR
            0x00, // restore
            0x00, 0xb0, 0xdc, 0xfe, 0x00, 0x00, 0x00, 0x00, // addr 0xfedc_b000
            0x00, 0x00, 0x04, 0x00, // size 0x40000
            0x04, 0x00, 0x00, 0x00, // type CAL
            0x00, // restore
        ];
        let two = RespondMemReq {
            mem_seg: vec![
                MemSegResp {
                    addr: 0x1_2345_6000,
                    size: 0x18_0000,
                    mem_type: QMI_WLANFW_MEM_TYPE_DDR_V01,
                    restore: 0,
                },
                MemSegResp {
                    addr: 0xfedc_b000,
                    size: 0x4_0000,
                    mem_type: QMI_WLANFW_MEM_CAL_V01,
                    restore: 0,
                },
            ],
        };
        ensure!(enc(&two, 4)? == TWO, "respond_mem two segments");
        // Oracle E6b — 52 segments fills QMI_WLANFW_RESPOND_MEM_REQ_MSG_V01_MAX_LEN.
        let mut full = RespondMemReq::default();
        for i in 0..52u64 {
            full.mem_seg.push(MemSegResp {
                addr: 0x1000 * i,
                size: 0x8000,
                mem_type: 1,
                restore: 0,
            });
        }
        let b = enc(&full, 4)?;
        ensure!(
            b.len() == 895 && b.len() - QMI_HEADER_SIZE == 888,
            "52 segments = max len"
        );
        ensure!(fnv(&b) == 0xdb74_581a_37f4_9909, "respond_mem 52 fnv");
        // Oracle E6c — 53 segments → -EINVAL.
        full.mem_seg.push(MemSegResp::default());
        ensure!(full.encode(4).is_err(), "53 segments must fail");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_respond_mem_golden);

fn smoke_wlfw_empty_requests() -> TestResult {
    run(|| {
        // Oracle E7 — cap request: empty ei, header only, msg_len 0.
        ensure!(
            enc(&CapReq, 5)? == [0x00, 0x05, 0x00, 0x24, 0x00, 0x00, 0x00],
            "cap request"
        );
        ensure!(
            enc(&DeviceInfoReq, 6)? == [0x00, 0x06, 0x00, 0x4c, 0x00, 0x00, 0x00],
            "device_info request"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_empty_requests);

/// Oracle E8 — one-segment ELF board file (6 bytes), board_id 0xff, txn 6.
const BDF_SINGLE: [u8; 51] = [
    0x00, 0x06, 0x00, 0x25, 0x00, 0x2c, 0x00, // header: msg 0x0025, msg_len 44
    0x01, 0x01, 0x00, 0x01, // 0x01 valid (UNSIGNED_1_BYTE, mandatory) = 1
    0x10, 0x04, 0x00, 0xff, 0x00, 0x00, 0x00, // 0x10 file_id (SIGNED_4_BYTE_ENUM) = board_id
    0x11, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, // 0x11 total_size = remaining = 6
    0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x12 seg_id = 0
    0x13, 0x08, 0x00, 0x06, 0x00, // 0x13 data: DATA_LEN elem_size u16 → count 6
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, //    ...the 6 data bytes
    0x14, 0x01, 0x00, 0x01, // 0x14 end = 1 (remaining <= 6144)
    0x15, 0x01, 0x00, 0x01, // 0x15 bdf_type = ATH11K_QMI_BDF_TYPE_ELF
];

fn smoke_wlfw_bdf_download_golden() -> TestResult {
    run(|| {
        let elf = [0x7f, b'E', b'L', b'F', 0x02, 0x01];
        let t = bdf_type_for(&elf, false);
        ensure!(t == ATH11K_QMI_BDF_TYPE_ELF, "ELF magic → BDF_TYPE_ELF");
        ensure!(
            bdf_type_for(b"bin", false) == ATH11K_QMI_BDF_TYPE_BIN,
            "BIN"
        );
        ensure!(
            bdf_type_for(&elf, true) == ATH11K_QMI_BDF_TYPE_REGDB,
            "regdb wins"
        );
        let segs: Vec<_> = bdf_segments(&elf, 0xff, t).collect();
        ensure!(segs.len() == 1, "6 bytes = one segment");
        ensure!(enc(&segs[0], 6)? == BDF_SINGLE, "bdf single segment bytes");

        // Oracle E9 — 6150-byte BIN file, board_id 0x8c: segment 0 is
        // 6144 bytes (end 0, total 6150), segment 1 is 6 (end 1, total 6).
        let file: Vec<u8> = (0..6150u32).map(|i| (i * 7 + 3) as u8).collect();
        let segs: Vec<_> = bdf_segments(&file, 0x8c, ATH11K_QMI_BDF_TYPE_BIN).collect();
        ensure!(segs.len() == 2, "6150 bytes = two segments");
        let s0 = enc(&segs[0], 0x40)?;
        ensure!(s0.len() == 6189, "segment 0 length");
        ensure!(
            s0[5..7] == [0x26, 0x18],
            "segment 0 msg_len 6182 = QMI_WLANFW_BDF_DOWNLOAD_REQ_MSG_V01_MAX_LEN"
        );
        ensure!(fnv(&s0) == 0xcfaf_e29a_a1f3_9ed4, "segment 0 fnv");
        const SEG1: [u8; 51] = [
            0x00, 0x41, 0x00, 0x25, 0x00, 0x2c, 0x00, 0x01, 0x01, 0x00, 0x01, 0x10, 0x04, 0x00,
            0x8c, 0x00, 0x00, 0x00, 0x11, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x12, 0x04, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x13, 0x08, 0x00, 0x06, 0x00, 0x03, 0x0a, 0x11, 0x18, 0x1f,
            0x26, 0x14, 0x01, 0x00, 0x01, 0x15, 0x01, 0x00, 0x00,
        ];
        ensure!(enc(&segs[1], 0x41)? == SEG1, "segment 1 bytes");

        // Oracle E10 — EEPROM caldata: no 0x13 (data_valid 0), end 1,
        // total_size 64, bdf_type ATH11K_QMI_FILE_TYPE_EEPROM.
        const EEPROM: [u8; 40] = [
            0x00, 0x07, 0x00, 0x25, 0x00, 0x21, 0x00, // header, len 33
            0x01, 0x01, 0x00, 0x01, // valid
            0x10, 0x04, 0x00, 0x34, 0x12, 0x00, 0x00, // file_id 0x1234
            0x11, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00, // total_size 64
            0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // seg_id 0
            0x14, 0x01, 0x00, 0x01, // end
            0x15, 0x01, 0x00, 0x03, // bdf_type EEPROM
        ];
        ensure!(
            enc(&bdf_eeprom_request(0x1234), 7)? == EEPROM,
            "bdf eeprom bytes"
        );

        // Oracle E11 — data_len 6145 → -EINVAL.
        let big = vec![0u8; QMI_WLANFW_MAX_DATA_SIZE_V01 + 1];
        let over = BdfDownloadReq {
            valid: 1,
            data: Some(&big),
            ..BdfDownloadReq::default()
        };
        ensure!(over.encode(7).is_err(), "6145-byte segment must fail");
        // Empty file: Linux's while (remaining) sends nothing.
        ensure!(bdf_segments(&[], 0xff, 0).next().is_none(), "empty file");
        // Exactly 6144 bytes: one segment with end = 1.
        let exact = vec![0u8; QMI_WLANFW_MAX_DATA_SIZE_V01];
        let s: Vec<_> = bdf_segments(&exact, 0, 0).collect();
        ensure!(
            s.len() == 1 && s[0].end == Some(1),
            "6144 bytes = one final segment"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_bdf_download_golden);

fn smoke_wlfw_m3_ini_mode_golden() -> TestResult {
    run(|| {
        // Oracle E12 — m3_info: two mandatory TLVs.
        const M3: [u8; 25] = [
            0x00, 0x07, 0x00, 0x3c, 0x00, 0x12, 0x00, // header: msg 0x003C, len 18
            0x01, 0x08, 0x00, 0x00, 0x00, 0xde, 0xc0, 0x01, 0x00, 0x00, 0x00, // 0x01 addr u64
            0x02, 0x04, 0x00, 0x00, 0xb0, 0x04, 0x00, // 0x02 size u32 0x4b000
        ];
        let m3 = M3InfoReq {
            addr: 0x1_c0de_0000,
            size: 0x4_b000,
        };
        ensure!(enc(&m3, 7)? == M3, "m3_info bytes");
        // Oracle E13 — wlan_ini enablefwlog = 1.
        ensure!(
            enc(&WlanIniReq::ath11k(true), 8)?
                == [0x00, 0x08, 0x00, 0x2f, 0x00, 0x04, 0x00, 0x10, 0x01, 0x00, 0x01],
            "wlan_ini bytes"
        );
        // Oracle E15/E16 — wlan_mode NORMAL and OFF, hw_debug_valid 1 / 0.
        ensure!(
            enc(&WlanModeReq::ath11k(ATH11K_FIRMWARE_MODE_NORMAL), 10)?
                == [
                    0x00, 0x0a, 0x00, 0x22, 0x00, 0x0b, 0x00, // header, len 11
                    0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // 0x01 mode u32
                    0x10, 0x01, 0x00, 0x00, // 0x10 hw_debug
                ],
            "wlan_mode normal bytes"
        );
        let off = enc(&WlanModeReq::ath11k(ATH11K_FIRMWARE_MODE_OFF), 11)?;
        ensure!(
            fnv(&off) == 0xfd01_22aa_38d0_a197 && off[10] == 4,
            "wlan_mode off"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_m3_ini_mode_golden);

fn smoke_wlfw_wlan_cfg_golden() -> TestResult {
    run(|| {
        // Oracle E14 — ath11k_qmi_wlanfw_wlan_cfg_send for WCN6855:
        // 0x10 "WIN", 0x11 9 × ce_tgt_pipe_cfg (20 B), 0x12 14 ×
        // ce_svc_pipe_cfg (12 B), no 0x13, 0x14 3 shadow v2 addrs.
        const CFG: [u8; 385] = [
            0x00, 0x09, 0x00, 0x23, 0x00, 0x7a, 0x01, 0x10, 0x03, 0x00, 0x57, 0x49, 0x4e, 0x11,
            0xb5, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00,
            0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x08, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20,
            0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
            0x00, 0x03, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x12, 0xa9, 0x00, 0x0e, 0x04, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x02, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x02,
            0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x14, 0x0d, 0x00, 0x03, 0x08, 0x30, 0x00, 0x00, 0x0c,
            0x30, 0x00, 0x00, 0x10, 0x4c, 0x02, 0x00,
        ];
        let shadow = [0x3008, 0x300c, 0x24c10];
        let req = WlanCfgReq::ath11k(
            &wcn6855(),
            &TARGET_CE_CONFIG_WLAN_QCA6390,
            &TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390,
            &shadow,
        );
        let got = enc(&req, 9)?;
        ensure!(got == CFG, "wlan_cfg bytes differ from Linux");
        ensure!(fnv(&got) == 0xadb7_6983_7638_d40b, "wlan_cfg fnv");
        // Spot checks: host_version TLV, CE4 flags = CE_ATTR_DIS_INTR,
        // tgt TLV length 1 + 9*20, svc TLV length 1 + 14*12.
        ensure!(
            CFG[7..13] == [0x10, 0x03, 0x00, b'W', b'I', b'N'],
            "host_version"
        );
        ensure!(CFG[13..17] == [0x11, 0xb5, 0x00, 0x09], "tgt_cfg TLV head");
        ensure!(
            CFG[197..201] == [0x12, 0xa9, 0x00, 0x0e],
            "svc_cfg TLV head"
        );
        // Oracle E14b — 40 shadow addresses clamp to 36 (min_t in Linux).
        let many: Vec<u32> = (0..40).map(|i| 0x3000 + 4 * i).collect();
        let req = WlanCfgReq::ath11k(
            &wcn6855(),
            &TARGET_CE_CONFIG_WLAN_QCA6390,
            &TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390,
            &many,
        );
        let got = enc(&req, 9)?;
        ensure!(
            got.len() == 517 && fnv(&got) == 0x7f45_e9ea_384b_1e14,
            "wlan_cfg with 36 shadow regs"
        );
        // Oracle E14c — shadow v1 instead of v2.
        let v1 = [ShadowRegCfg {
            id: 0x0102,
            offset: 0x0304,
        }];
        let req = WlanCfgReq {
            shadow_reg: Some(&v1),
            shadow_reg_v2: None,
            ..WlanCfgReq::ath11k(
                &wcn6855(),
                &TARGET_CE_CONFIG_WLAN_QCA6390,
                &TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390,
                &[],
            )
        };
        let got = enc(&req, 9)?;
        ensure!(
            got.len() == 377 && fnv(&got) == 0xf2b4_3d9a_34f6_e33c,
            "wlan_cfg with shadow v1"
        );
        // !supports_shadow_regs → no 0x14 TLV.
        let no_shadow = WlfwHwParams {
            supports_shadow_regs: false,
            ..wcn6855()
        };
        let req = WlanCfgReq::ath11k(
            &no_shadow,
            &TARGET_CE_CONFIG_WLAN_QCA6390,
            &TARGET_SERVICE_TO_CE_MAP_WLAN_QCA6390,
            &shadow,
        );
        ensure!(enc(&req, 9)?.len() == CFG.len() - 16, "no shadow TLV");
        // 13 CE configs exceed QMI_WLANFW_MAX_NUM_CE_V01.
        let ce13 = [CeTgtPipeCfg::default(); 13];
        let req = WlanCfgReq {
            tgt_cfg: Some(&ce13),
            ..WlanCfgReq::default()
        };
        ensure!(req.encode(0).is_err(), "13 CE configs must fail");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_wlan_cfg_golden);

// ══ WLFW responses / indications ════════════════════════════════════

/// Oracle E19 — a cap response as WCN6855 HW2.1 firmware sends it
/// (values typical of `ath11k_pci` boot logs), encoded by Linux's
/// `qmi_encode_message` on `qmi_wlanfw_cap_resp_msg_v01_ei`.
const CAP_RESP: [u8; 174] = [
    0x02, 0x05, 0x00, 0x24, 0x00, 0xa7, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x08,
    0x00, 0x12, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x11, 0x04, 0x00, 0xff, 0x00, 0x00, 0x00,
    0x12, 0x04, 0x00, 0x11, 0x12, 0x0c, 0x40, 0x13, 0x15, 0x00, 0x35, 0x8c, 0x08, 0x11, 0x10, 0x32,
    0x30, 0x32, 0x34, 0x2d, 0x30, 0x34, 0x2d, 0x31, 0x37, 0x20, 0x30, 0x38, 0x3a, 0x33, 0x34, 0x14,
    0x53, 0x00, 0x51, 0x43, 0x5f, 0x49, 0x4d, 0x41, 0x47, 0x45, 0x5f, 0x56, 0x45, 0x52, 0x53, 0x49,
    0x4f, 0x4e, 0x5f, 0x53, 0x54, 0x52, 0x49, 0x4e, 0x47, 0x3d, 0x57, 0x4c, 0x41, 0x4e, 0x2e, 0x48,
    0x53, 0x50, 0x2e, 0x31, 0x2e, 0x31, 0x2d, 0x30, 0x33, 0x31, 0x32, 0x35, 0x2d, 0x51, 0x43, 0x41,
    0x48, 0x53, 0x50, 0x53, 0x57, 0x50, 0x4c, 0x5f, 0x56, 0x31, 0x5f, 0x56, 0x32, 0x5f, 0x53, 0x49,
    0x4c, 0x49, 0x43, 0x4f, 0x4e, 0x5a, 0x5f, 0x4c, 0x49, 0x54, 0x45, 0x2d, 0x33, 0x2e, 0x36, 0x35,
    0x31, 0x30, 0x2e, 0x34, 0x31, 0x15, 0x01, 0x00, 0x02, 0x16, 0x04, 0x00, 0xe4, 0x0c, 0x00, 0x00,
    0x17, 0x04, 0x00, 0x00, 0xf8, 0x24, 0x01, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn smoke_wlfw_cap_resp_decode() -> TestResult {
    run(|| {
        let (hdr, c) = CapResp::decode(&CAP_RESP).map_err(|_| "cap resp decode")?;
        ensure!(hdr.msg_type == QMI_RESPONSE && hdr.txn_id == 5, "header");
        ensure!(c.resp.is_success(), "result SUCCESS");
        ensure!(
            c.chip_info
                == Some(RfChipInfo {
                    chip_id: 0x12,
                    chip_family: 0xb
                }),
            "chip_info"
        );
        ensure!(c.board_id == Some(0xff), "board_id");
        ensure!(c.soc_id == Some(0x400c_1211), "soc_id");
        let fv = c.fw_version_info.as_ref().ok_or("fw_version_info")?;
        ensure!(fv.fw_version == 0x1108_8c35, "fw_version");
        ensure!(fv.fw_build_timestamp == b"2024-04-17 08:34", "timestamp");
        ensure!(
            c.fw_build_id.as_deref()
                == Some(&b"QC_IMAGE_VERSION_STRING=WLAN.HSP.1.1-03125-QCAHSPSWPL_V1_V2_SILICONZ_LITE-3.6510.41"[..]),
            "fw_build_id"
        );
        ensure!(c.num_macs == Some(2), "num_macs");
        ensure!(c.voltage_mv == Some(3300), "voltage_mv");
        ensure!(c.time_freq_hz == Some(19_200_000), "time_freq_hz");
        ensure!(c.otp_version == Some(0), "otp_version");
        ensure!(c.eeprom_read_timeout.is_none(), "no eeprom");
        let t = TargetInfo::from_cap(&c);
        ensure!(
            t.board_id == 0xff && t.chip_id == 0x12 && t.eeprom_caldata == 0,
            "target info"
        );
        ensure!(
            t.fw_build_id_display()
                == b"WLAN.HSP.1.1-03125-QCAHSPSWPL_V1_V2_SILICONZ_LITE-3.6510.41",
            "FW_BUILD_ID_MASK stripped"
        );
        // Our firmware-side encoder reproduces Linux's bytes.
        let mut w = TlvWriter::new(QMI_WLANFW_CAP_RESP_MSG_V01_MAX_LEN);
        c.write(&mut w).map_err(|_| "write")?;
        let p = w.finish().map_err(|_| "finish")?;
        ensure!(
            encode_message(QMI_RESPONSE, QMI_WLANFW_CAP_RESP_V01, 5, &p) == CAP_RESP,
            "CapResp::write matches Linux"
        );

        // Oracle E19b — failure result, only eeprom_read_timeout.
        const FAIL: [u8; 21] = [
            0x02, 0x05, 0x00, 0x24, 0x00, 0x0e, 0x00, // QMI_RESPONSE, len 14
            0x02, 0x04, 0x00, 0x01, 0x00, 0x5a, 0x00, // result FAILURE, error 0x5a
            0x19, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00, // eeprom_read_timeout 0x10
        ];
        let (_, f) = CapResp::decode(&FAIL).map_err(|_| "fail decode")?;
        ensure!(
            !f.resp.is_success() && f.resp.error == QMI_ERR_INCOMPATIBLE_STATE_V01,
            "failure resp"
        );
        let t = TargetInfo::from_cap(&f);
        ensure!(
            t.board_id == 0xff && t.eeprom_caldata == 0x10,
            "default board_id 0xFF"
        );
        // Wrong message for the type.
        ensure!(
            HostCapResp::decode(&CAP_RESP)
                == Err(QmiError::UnexpectedMessage {
                    msg_type: QMI_RESPONSE,
                    msg_id: 0x24
                }),
            "msg_id checked"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_cap_resp_decode);

fn smoke_wlfw_cap_resp_string_limits() -> TestResult {
    run(|| {
        // Oracle D5a/D5b — fw_build_id: 128 bytes OK, 129 (= elem_len) → -ETOOSMALL.
        let mut p = RESP_OK.to_vec();
        p.extend_from_slice(&[0x14, 128, 0x00]);
        p.extend_from_slice(&[b'A'; 128]);
        let c = CapResp::decode_payload(&p).map_err(|_| "128-char build id")?;
        ensure!(
            c.fw_build_id.map(|v| v.len()) == Some(128),
            "build id length"
        );
        let mut p = RESP_OK.to_vec();
        p.extend_from_slice(&[0x14, 129, 0x00]);
        p.extend_from_slice(&[b'A'; 129]);
        ensure!(
            matches!(
                CapResp::decode_payload(&p),
                Err(QmiError::StringTooLong { tlv: 0x14, .. })
            ),
            "129-char build id must fail"
        );
        // Oracle D9/D9b — nested fw_build_timestamp: count 33 fails, 32 ok.
        let ts = |n: u8| {
            let mut p = RESP_OK.to_vec();
            p.extend_from_slice(&[0x13, 4 + 1 + n, 0x00, 0x01, 0x00, 0x00, 0x00, n]);
            p.extend_from_slice(&vec![b'T'; n as usize]);
            p
        };
        ensure!(
            CapResp::decode_payload(&ts(33)).is_err(),
            "33-char timestamp must fail"
        );
        let c = CapResp::decode_payload(&ts(32)).map_err(|_| "32-char timestamp")?;
        let fv = c.fw_version_info.ok_or("fw_version_info")?;
        ensure!(
            fv.fw_version == 1 && fv.fw_build_timestamp.len() == 32,
            "timestamp 32"
        );
        // Nested count larger than the bytes present.
        let mut p = RESP_OK.to_vec();
        p.extend_from_slice(&[0x13, 4 + 1 + 2, 0x00, 0x01, 0x00, 0x00, 0x00, 5, b'a', b'b']);
        ensure!(
            CapResp::decode_payload(&p).is_err(),
            "timestamp count past the struct"
        );
        // A string decodes up to its first NUL, as a C consumer sees it.
        let mut p = RESP_OK.to_vec();
        p.extend_from_slice(&[0x14, 0x04, 0x00, b'a', b'b', 0x00, b'c']);
        let c = CapResp::decode_payload(&p).map_err(|_| "nul")?;
        ensure!(
            c.fw_build_id.as_deref() == Some(&b"ab"[..]),
            "string cut at NUL"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_cap_resp_string_limits);

/// Oracle E18 — a request_mem indication as firmware encodes it: two
/// segments, the second with one mem_cfg.
const REQUEST_MEM_IND: [u8; 42] = [
    0x04, 0x00, 0x00, 0x35, 0x00, 0x23, 0x00, // INDICATION, txn 0, msg 0x0035, len 35
    0x01, 0x20, 0x00, 0x02, // 0x01: TLV len 32, mem_seg_len (u8) 2
    0x00, 0x00, 0x20, 0x00, // mem_seg[0].size 0x200000
    0x01, 0x00, 0x00, 0x00, // mem_seg[0].type DDR (SIGNED_4_BYTE_ENUM)
    0x00, // mem_seg[0].mem_cfg_len (u8) 0
    0x00, 0x00, 0x01, 0x00, // mem_seg[1].size 0x10000
    0x04, 0x00, 0x00, 0x00, // mem_seg[1].type CAL
    0x01, // mem_seg[1].mem_cfg_len 1
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mem_cfg[0].offset u64 0x1000
    0x00, 0x08, 0x00, 0x00, // mem_cfg[0].size 0x800
    0x01, // mem_cfg[0].secure_flag
];

fn smoke_wlfw_request_mem_ind() -> TestResult {
    run(|| {
        let want = RequestMemInd {
            mem_seg: vec![
                MemSeg {
                    size: 0x20_0000,
                    mem_type: QMI_WLANFW_MEM_TYPE_DDR_V01,
                    mem_cfg: Vec::new(),
                },
                MemSeg {
                    size: 0x1_0000,
                    mem_type: QMI_WLANFW_MEM_CAL_V01,
                    mem_cfg: vec![MemCfg {
                        offset: 0x1000,
                        size: 0x800,
                        secure_flag: 1,
                    }],
                },
            ],
        };
        let (_, got) = RequestMemInd::decode(&REQUEST_MEM_IND).map_err(|_| "decode")?;
        ensure!(got == want, "request_mem decode");
        ensure!(
            decode_indication(&REQUEST_MEM_IND)
                == Ok(Some(WlfwIndication::RequestMem(want.clone()))),
            "indication dispatch"
        );
        let mut w = TlvWriter::new(QMI_WLANFW_REQUEST_MEM_IND_MSG_V01_MAX_LEN);
        want.write(&mut w).map_err(|_| "write")?;
        let p = w.finish().map_err(|_| "finish")?;
        ensure!(
            msg(QMI_INDICATION, QMI_WLFW_REQUEST_MEM_IND_V01, &p) == REQUEST_MEM_IND,
            "RequestMemInd::write matches Linux"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_request_mem_ind);

fn smoke_wlfw_request_mem_ind_negative() -> TestResult {
    run(|| {
        // Oracle D6 — mem_seg_len 53 > 52 → -ETOOSMALL.
        ensure!(
            matches!(
                RequestMemInd::decode_payload(&[0x01, 0x01, 0x00, 53]),
                Err(QmiError::ArrayTooLong {
                    len: 53,
                    max: 52,
                    ..
                })
            ),
            "53 segments must fail"
        );
        // Oracle D7 — mem_seg_len 2 but one segment present: Linux
        // stops at the end of the TLV and leaves segment 1 zeroed.
        let p = [
            0x01, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        let m = RequestMemInd::decode_payload(&p).map_err(|_| "short array accepted by Linux")?;
        ensure!(m.mem_seg.len() == 2, "count kept");
        ensure!(
            m.mem_seg[0].size == 0x20_0000 && m.mem_seg[0].mem_type == 1,
            "seg 0"
        );
        ensure!(m.mem_seg[1] == MemSeg::default(), "seg 1 zeroed");
        // Oracle D8 — mem_cfg_len 3 > 2 → -ETOOSMALL.
        let p = [
            0x01, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03,
        ];
        ensure!(
            matches!(
                RequestMemInd::decode_payload(&p),
                Err(QmiError::ArrayTooLong { len: 3, max: 2, .. })
            ),
            "3 mem_cfg must fail"
        );
        // Oracle D8b — mem_cfg_len 1 with no mem_cfg bytes: a nested
        // array must be complete → -EFAULT.
        let p = [
            0x01, 0x0a, 0x00, 0x01, 0x00, 0x00, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ];
        ensure!(
            RequestMemInd::decode_payload(&p) == Err(QmiError::StructLengthMismatch { tlv: 0x01 }),
            "missing nested mem_cfg must fail"
        );
        // A segment cut mid-member.
        let p = [0x01, 0x03, 0x00, 0x01, 0x00, 0x00];
        ensure!(
            RequestMemInd::decode_payload(&p).is_err(),
            "half a size field"
        );
        // TLV 0x01 too short for its count byte.
        ensure!(
            RequestMemInd::decode_payload(&[0x01, 0x00, 0x00])
                == Err(QmiError::Truncated { tlv: 0x01 }),
            "empty 0x01"
        );
        Ok(())
    })
}
kernel_test_in!(
    "drivers/wireless/ath11k",
    smoke_wlfw_request_mem_ind_negative
);

fn smoke_wlfw_simple_responses() -> TestResult {
    run(|| {
        // Oracle D11 — ind_register response with fw_status (u64).
        let b = [
            0x02, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x10, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let (h, r) = IndRegisterResp::decode(&b).map_err(|_| "ind_register resp")?;
        ensure!(h.txn_id == 2 && r.resp.is_success(), "ind_register header");
        ensure!(r.fw_status == Some(0x0807_0605_0403_0201), "fw_status");
        // Each resp-only message decodes its own id only.
        let ok = |id| msg(QMI_RESPONSE, id, &RESP_OK);
        ensure!(HostCapResp::decode(&ok(0x34)).is_ok(), "host_cap resp");
        ensure!(
            RespondMemResp::decode(&ok(0x36)).is_ok(),
            "respond_mem resp"
        );
        ensure!(BdfDownloadResp::decode(&ok(0x25)).is_ok(), "bdf resp");
        ensure!(M3InfoResp::decode(&ok(0x3c)).is_ok(), "m3 resp");
        ensure!(WlanCfgResp::decode(&ok(0x23)).is_ok(), "wlan_cfg resp");
        ensure!(WlanModeResp::decode(&ok(0x22)).is_ok(), "wlan_mode resp");
        ensure!(WlanIniResp::decode(&ok(0x2f)).is_ok(), "wlan_ini resp");
        ensure!(WlanIniResp::decode(&ok(0x22)).is_err(), "wrong id refused");
        ensure!(
            WlanIniResp::decode(&msg(QMI_INDICATION, 0x2f, &RESP_OK)).is_err(),
            "wrong type refused"
        );
        // The delayed respond_mem answer: FAILURE with error 0.
        let (_, d) = RespondMemResp::decode(&msg(
            QMI_RESPONSE,
            0x36,
            &[0x02, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00],
        ))
        .map_err(|_| "delayed resp")?;
        ensure!(!d.resp.is_success() && d.resp.error == 0, "delayed failure");
        // device_info (hybrid bus only).
        let mut p = RESP_OK.to_vec();
        p.extend_from_slice(&[0x10, 0x08, 0x00, 0, 0, 0x20, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&[0x11, 0x04, 0x00, 0, 0, 0x20, 0]);
        let di = DeviceInfoResp::decode_payload(&p).map_err(|_| "device_info")?;
        ensure!(
            di.bar_addr == Some(0x20_0000) && di.bar_size == Some(0x20_0000),
            "device_info fields"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_simple_responses);

fn smoke_wlfw_indication_dispatch() -> TestResult {
    run(|| {
        let ind = |id| msg(QMI_INDICATION, id, &[]);
        ensure!(
            decode_indication(&ind(0x37)) == Ok(Some(WlfwIndication::FwMemReady)),
            "mem ready"
        );
        ensure!(
            decode_indication(&ind(0x21)) == Ok(Some(WlfwIndication::FwReady)),
            "fw ready"
        );
        ensure!(
            decode_indication(&ind(0x3e)) == Ok(Some(WlfwIndication::ColdBootCalDone)),
            "cal done"
        );
        ensure!(
            decode_indication(&ind(0x38)) == Ok(Some(WlfwIndication::FwInitDone)),
            "init done"
        );
        // No handler: dropped (qmi_invoke_handler finds none).
        ensure!(
            decode_indication(&ind(0x99)) == Ok(None),
            "unknown indication"
        );
        ensure!(
            decode_indication(&msg(QMI_RESPONSE, 0x21, &[])) == Ok(None),
            "response is not an indication"
        );
        // Handler found but decode fails.
        ensure!(
            decode_indication(&msg(QMI_INDICATION, 0x21, &[0x01, 0x00, 0x00])).is_err(),
            "fw_ready with a mandatory TLV"
        );
        ensure!(
            decode_indication(&[0x04, 0x00]) == Err(QmiError::ShortHeader),
            "short"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_wlfw_indication_dispatch);

// ══ QRTR ════════════════════════════════════════════════════════════

/// `qmi_send_new_lookup` for WLFW on WCN6855: cmd NEW_LOOKUP,
/// service 0x45, instance = version 1 | instance 1 << 8.
const NEW_LOOKUP_WLFW: [u8; 20] = [
    0x0a, 0x00, 0x00, 0x00, // cmd QRTR_TYPE_NEW_LOOKUP
    0x45, 0x00, 0x00, 0x00, // server.service ATH11K_QMI_WLFW_SERVICE_ID_V01
    0x01, 0x01, 0x00, 0x00, // server.instance 0x0101
    0x00, 0x00, 0x00, 0x00, // server.node (memset 0)
    0x00, 0x00, 0x00, 0x00, // server.port (memset 0)
];

/// HELLO from local node 1 to remote node 3 (`qrtr_node_enqueue`).
const HELLO_1_TO_3: [u8; 52] = [
    0x01, 0x00, 0x00, 0x00, // version QRTR_PROTO_VER_1
    0x02, 0x00, 0x00, 0x00, // type QRTR_TYPE_HELLO
    0x01, 0x00, 0x00, 0x00, // src_node = qrtr_local_nid 1
    0xfe, 0xff, 0xff, 0xff, // src_port QRTR_PORT_CTRL
    0x00, 0x00, 0x00, 0x00, // confirm_rx (never on non-DATA)
    0x14, 0x00, 0x00, 0x00, // size 20
    0x03, 0x00, 0x00, 0x00, // dst_node = node->nid
    0xfe, 0xff, 0xff, 0xff, // dst_port QRTR_PORT_CTRL
    0x02, 0x00, 0x00, 0x00, // qrtr_ctrl_pkt.cmd HELLO
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // union zeroed
];

fn ctrl_from(node: u32, pkt: CtrlPkt) -> Vec<u8> {
    encode_packet(
        pkt.cmd(),
        QrtrAddr {
            node,
            port: QRTR_PORT_CTRL,
        },
        QrtrAddr {
            node: 1,
            port: QRTR_PORT_CTRL,
        },
        false,
        &pkt.to_bytes(),
    )
    .unwrap_or_default()
}

fn smoke_qrtr_ctrl_packet_golden() -> TestResult {
    run(|| {
        ensure!(
            QrtrLink::new_lookup_payload(
                ATH11K_QMI_WLFW_SERVICE_ID_V01,
                ATH11K_QMI_WLFW_SERVICE_VERS_V01,
                ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_QCA6390
            ) == NEW_LOOKUP_WLFW,
            "NEW_LOOKUP bytes"
        );
        ensure!(
            CtrlPkt::parse(&NEW_LOOKUP_WLFW)
                == Ok(CtrlPkt::NewLookup {
                    service: 0x45,
                    instance: 0x101
                }),
            "NEW_LOOKUP parse"
        );
        // Every type round-trips through the 20-byte layout.
        for p in [
            CtrlPkt::Hello,
            CtrlPkt::Bye { node: 3 },
            CtrlPkt::NewServer {
                service: 0x45,
                instance: 0x101,
                node: 3,
                port: 0x10,
            },
            CtrlPkt::DelServer {
                service: 1,
                instance: 2,
                node: 3,
                port: 4,
            },
            CtrlPkt::DelClient { node: 3, port: 9 },
            CtrlPkt::ResumeTx {
                node: 1,
                port: 0x4000,
            },
            CtrlPkt::Exit,
            CtrlPkt::Ping,
            CtrlPkt::DelLookup {
                service: 0x45,
                instance: 0,
            },
            CtrlPkt::Other { cmd: 0x77 },
        ] {
            ensure!(CtrlPkt::parse(&p.to_bytes()) == Ok(p), "ctrl roundtrip");
        }
        ensure!(
            CtrlPkt::parse(&NEW_LOOKUP_WLFW[..19]) == Err(QrtrError::ShortControlPayload),
            "19-byte control packet"
        );
        // Full v1 frame.
        let f = encode_packet(
            QRTR_TYPE_HELLO,
            QrtrAddr {
                node: 1,
                port: QRTR_PORT_CTRL,
            },
            QrtrAddr {
                node: 3,
                port: QRTR_PORT_CTRL,
            },
            false,
            &CtrlPkt::Hello.to_bytes(),
        )
        .map_err(|_| "encode")?;
        ensure!(f == HELLO_1_TO_3, "HELLO frame bytes");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_qrtr_ctrl_packet_golden);

fn smoke_qrtr_data_framing() -> TestResult {
    run(|| {
        // 5-byte payload → size 5, padded with 3 zero bytes.
        let src = QrtrAddr {
            node: 1,
            port: 0x4000,
        };
        let dst = QrtrAddr { node: 3, port: 0x1 };
        let f =
            encode_packet(QRTR_TYPE_DATA, src, dst, true, &[1, 2, 3, 4, 5]).map_err(|_| "enc")?;
        ensure!(f.len() == 32 + 8, "padded length");
        ensure!(f[16..20] == [1, 0, 0, 0], "confirm_rx = 1");
        ensure!(f[20..24] == [5, 0, 0, 0], "size excludes padding");
        ensure!(f[37..40] == [0, 0, 0], "zero padding");
        let p = decode_packet(&f).map_err(|_| "decode")?;
        ensure!(
            p.pkt_type == QRTR_TYPE_DATA
                && p.src_node == 1
                && p.src_port == 0x4000
                && p.dst_node == 3
                && p.dst_port == 1
                && p.confirm_rx
                && p.payload == [1, 2, 3, 4, 5],
            "decode fields"
        );
        ensure!(
            encode_packet(QRTR_TYPE_DATA, src, dst, false, &vec![0; 65536])
                == Err(QrtrError::PayloadTooLarge),
            "65536-byte payload"
        );
        // v2 header: u8 type/flags/optlen, __le16 nodes/ports, 0xfffe → CTRL.
        let v2 = [
            0x03, 0x01, 0x01, 0x04, // version 3, DATA, CONFIRM_RX, optlen 4
            0x03, 0x00, 0x00, 0x00, // size 3
            0x03, 0x00, 0xfe, 0xff, // src node 3, port 0xfffe
            0x01, 0x00, 0x00, 0x40, // dst node 1, port 0x4000
            0xaa, 0xaa, 0xaa, 0xaa, // optional header
            0x07, 0x08, 0x09, 0x00, // payload + pad
        ];
        let p = decode_packet(&v2).map_err(|_| "v2 decode")?;
        ensure!(
            p.version == 3 && p.src_port == QRTR_PORT_CTRL && p.dst_port == 0x4000 && p.confirm_rx,
            "v2 fields"
        );
        ensure!(p.payload == [7, 8, 9], "v2 payload after optlen");
        // Legacy control port 0xffff is rewritten to QRTR_PORT_CTRL.
        let mut legacy = ctrl_from(3, CtrlPkt::Hello);
        legacy[28..32].copy_from_slice(&0xffffu32.to_le_bytes());
        ensure!(
            decode_packet(&legacy).map(|p| p.dst_port) == Ok(QRTR_PORT_CTRL),
            "legacy ctrl port"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_qrtr_data_framing);

fn smoke_qrtr_decode_rejects() -> TestResult {
    run(|| {
        let good = ctrl_from(3, CtrlPkt::Hello);
        ensure!(decode_packet(&good).is_ok(), "baseline");
        ensure!(decode_packet(&[]) == Err(QrtrError::BadLength), "len 0");
        ensure!(
            decode_packet(&good[..51]) == Err(QrtrError::BadLength),
            "len & 3"
        );
        let mut bad = good.clone();
        bad[0] = 2;
        ensure!(
            decode_packet(&bad) == Err(QrtrError::BadVersion(2)),
            "version 2"
        );
        // Linux reads only the low byte of the v1 version word.
        let mut hi = good.clone();
        hi[1] = 0x01;
        ensure!(decode_packet(&hi).is_ok(), "v1 version upper bytes ignored");
        ensure!(
            decode_packet(&good[..28]) == Err(QrtrError::ShortHeader),
            "short v1 header"
        );
        ensure!(
            decode_packet(&[3, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]) == Err(QrtrError::ShortHeader),
            "short v2"
        );
        // size 0.
        let mut s = good.clone();
        s[20..24].copy_from_slice(&0u32.to_le_bytes());
        ensure!(decode_packet(&s) == Err(QrtrError::SizeMismatch), "size 0");
        // size disagrees with the frame (16 vs 20 payload bytes).
        s[20..24].copy_from_slice(&16u32.to_le_bytes());
        ensure!(
            decode_packet(&s) == Err(QrtrError::SizeMismatch),
            "size short"
        );
        // size overflow: 0xffffffff aligns to 2^32, never equals len.
        s[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        ensure!(
            decode_packet(&s) == Err(QrtrError::SizeMismatch),
            "size overflow"
        );
        // 19 ≡ 20 after ALIGN: accepted by framing, payload 19 bytes.
        s[20..24].copy_from_slice(&19u32.to_le_bytes());
        ensure!(
            decode_packet(&s).map(|p| p.payload.len()) == Ok(19),
            "size 19 aligned"
        );
        // ...but NEW_SERVER / RESUME_TX need a full ctrl packet.
        let mut ns = ctrl_from(
            3,
            CtrlPkt::NewServer {
                service: 0x45,
                instance: 0x101,
                node: 3,
                port: 1,
            },
        );
        ns[20..24].copy_from_slice(&19u32.to_le_bytes());
        ensure!(
            decode_packet(&ns) == Err(QrtrError::ShortControl),
            "short NEW_SERVER"
        );
        // A control type to a non-control port.
        let mut np = good.clone();
        np[28..32].copy_from_slice(&0x4000u32.to_le_bytes());
        ensure!(
            decode_packet(&np) == Err(QrtrError::NotToControlPort),
            "HELLO to a data port"
        );
        // RESUME_TX to a data port is allowed.
        let rt = encode_packet(
            QRTR_TYPE_RESUME_TX,
            QrtrAddr { node: 3, port: 1 },
            QrtrAddr {
                node: 1,
                port: 0x4000,
            },
            false,
            &CtrlPkt::ResumeTx { node: 3, port: 1 }.to_bytes(),
        )
        .map_err(|_| "rt")?;
        ensure!(decode_packet(&rt).is_ok(), "RESUME_TX to a data port");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_qrtr_decode_rejects);

fn smoke_qrtr_hello_and_lookup() -> TestResult {
    run(|| {
        let mut link = QrtrLink::new(QRTR_DEFAULT_LOCAL_NODE);
        ensure!(link.remote_node() == QRTR_EP_NID_AUTO, "node id unassigned");
        // Before the remote speaks, the broadcast HELLO goes to node AUTO.
        let h0 = link.hello_frame();
        ensure!(h0[24..28] == [0xff; 4], "initial HELLO to QRTR_EP_NID_AUTO");
        // Register the WLFW lookup first (ath11k_qmi_init_service).
        let early = link.add_lookup(
            ATH11K_QMI_WLFW_SERVICE_ID_V01,
            qmi_instance(
                ATH11K_QMI_WLFW_SERVICE_VERS_V01,
                ATH11K_QMI_WLFW_SERVICE_INS_ID_V01_QCA6390,
            ),
        );
        ensure!(early.is_empty(), "no servers yet");
        // Remote HELLO → we answer HELLO to its node.
        let rx = link
            .receive(&ctrl_from(3, CtrlPkt::Hello))
            .map_err(|_| "hello rx")?;
        ensure!(
            link.remote_node() == 3 && link.hello_seen(),
            "node 3 learned"
        );
        ensure!(
            rx.tx.len() == 1 && rx.tx[0] == HELLO_1_TO_3,
            "HELLO reply bytes"
        );
        ensure!(rx.events.is_empty(), "no events for HELLO");
        // A non-matching server (other service) is learned silently.
        let other = CtrlPkt::NewServer {
            service: 0x42,
            instance: 0x101,
            node: 3,
            port: 0x20,
        };
        let rx = link.receive(&ctrl_from(3, other)).map_err(|_| "other")?;
        ensure!(
            rx.events.is_empty() && rx.tx.is_empty(),
            "other service: no event"
        );
        // WLFW with a different instance (QCN9074's 7) does not match.
        let wrong = CtrlPkt::NewServer {
            service: 0x45,
            instance: qmi_instance(1, 7),
            node: 3,
            port: 0x21,
        };
        ensure!(
            link.receive(&ctrl_from(3, wrong))
                .map_err(|_| "wrong")?
                .events
                .is_empty(),
            "instance filter"
        );
        // service 0 / port 0 are refused by server_add.
        let zero = CtrlPkt::NewServer {
            service: 0x45,
            instance: 0x101,
            node: 3,
            port: 0,
        };
        ensure!(
            link.receive(&ctrl_from(3, zero))
                .map_err(|_| "zero")?
                .events
                .is_empty(),
            "port 0 ignored"
        );
        // The real WLFW server.
        let wlfw = QrtrServer {
            service: 0x45,
            instance: 0x101,
            node: 3,
            port: 0x1,
        };
        let rx = link
            .receive(&ctrl_from(
                3,
                CtrlPkt::NewServer {
                    service: 0x45,
                    instance: 0x101,
                    node: 3,
                    port: 0x1,
                },
            ))
            .map_err(|_| "wlfw")?;
        ensure!(
            rx.events == vec![QrtrEvent::NewServer(wlfw)],
            "WLFW NEW_SERVER event"
        );
        ensure!(
            wlfw.qmi_version() == 1 && wlfw.qmi_instance() == 1,
            "instance split"
        );
        ensure!(link.servers().len() == 3, "three servers known");
        // A lookup added after the fact reports the known server.
        let mut late = QrtrLink::new(1);
        late.receive(&ctrl_from(
            3,
            CtrlPkt::NewServer {
                service: 0x45,
                instance: 0x101,
                node: 3,
                port: 0x1,
            },
        ))
        .map_err(|_| "late rx")?;
        ensure!(
            late.add_lookup(0x45, 0x101) == vec![QrtrEvent::NewServer(wlfw)],
            "late lookup"
        );
        ensure!(late.add_lookup(0, 0).len() == 1, "wildcard lookup");
        // Spoofed DEL_CLIENT (client.node != sender) is ignored.
        let spoof = link
            .receive(&ctrl_from(5, CtrlPkt::DelClient { node: 3, port: 1 }))
            .map_err(|_| "spoof")?;
        ensure!(
            spoof.events.is_empty() && link.servers().len() == 3,
            "spoof ignored"
        );
        // DEL_SERVER removes and notifies.
        let rx = link
            .receive(&ctrl_from(
                3,
                CtrlPkt::DelServer {
                    service: 0x45,
                    instance: 0x101,
                    node: 3,
                    port: 1,
                },
            ))
            .map_err(|_| "del")?;
        ensure!(
            rx.events == vec![QrtrEvent::DelServer(wlfw)],
            "DEL_SERVER event"
        );
        // Re-announce, then BYE from node 3 drops every node-3 server.
        link.receive(&ctrl_from(
            3,
            CtrlPkt::NewServer {
                service: 0x45,
                instance: 0x101,
                node: 3,
                port: 0x1,
            },
        ))
        .map_err(|_| "re")?;
        let rx = link
            .receive(&ctrl_from(3, CtrlPkt::Bye { node: 3 }))
            .map_err(|_| "bye")?;
        ensure!(
            rx.events == vec![QrtrEvent::DelServer(wlfw)],
            "BYE notifies the WLFW lookup only"
        );
        ensure!(link.servers().is_empty(), "BYE dropped all node-3 servers");
        // A bad frame changes nothing.
        let before = link.remote_node();
        ensure!(link.receive(&[0u8; 8]).is_err(), "bad frame");
        ensure!(link.remote_node() == before, "no state change on error");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_qrtr_hello_and_lookup);

fn smoke_qrtr_short_control_payload() -> TestResult {
    run(|| {
        let src = QrtrAddr {
            node: 3,
            port: QRTR_PORT_CTRL,
        };
        let dst = QrtrAddr {
            node: 1,
            port: QRTR_PORT_CTRL,
        };
        // qrtr_ns_worker switches on cmd alone: a 4-byte HELLO is answered.
        let mut link = QrtrLink::new(1);
        let hello4 = encode_packet(
            QRTR_TYPE_HELLO,
            src,
            dst,
            false,
            &QRTR_TYPE_HELLO.to_le_bytes(),
        )
        .map_err(|_| "enc")?;
        ensure!(hello4.len() == 36, "4-byte payload frame");
        let rx = link.receive(&hello4).map_err(|_| "4-byte HELLO refused")?;
        ensure!(
            rx.tx == vec![HELLO_1_TO_3.to_vec()],
            "4-byte HELLO answered"
        );
        // A command that reads the union needs all 20 bytes.
        let mut del = CtrlPkt::DelServer {
            service: 0x45,
            instance: 0x101,
            node: 3,
            port: 1,
        }
        .to_bytes()
        .to_vec();
        del.truncate(8);
        let f = encode_packet(QRTR_TYPE_DEL_SERVER, src, dst, false, &del).map_err(|_| "enc")?;
        ensure!(
            link.receive(&f) == Err(QrtrError::ShortControlPayload),
            "8-byte DEL_SERVER"
        );
        // Under 4 bytes there is no cmd at all.
        let f = encode_packet(QRTR_TYPE_HELLO, src, dst, false, &[2, 0]).map_err(|_| "enc")?;
        ensure!(
            link.receive(&f) == Err(QrtrError::ShortControlPayload),
            "2-byte control payload"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_qrtr_short_control_payload);

fn smoke_qrtr_flow_control_and_data() -> TestResult {
    run(|| {
        let mut link = QrtrLink::new(1);
        link.receive(&ctrl_from(3, CtrlPkt::Hello))
            .map_err(|_| "hello")?;
        let wlfw = QrtrAddr { node: 3, port: 1 };
        // qrtr_tx_wait: confirm_rx on the packet making pending == 5;
        // block once 10 are pending.
        for i in 1..=10u32 {
            let f = link.data_frame(0x4000, wlfw, &[0xAB]).map_err(|_| "send")?;
            let confirm = f[16] == 1;
            ensure!(
                confirm == (i == QRTR_TX_FLOW_LOW),
                "confirm_rx only on the 5th"
            );
        }
        ensure!(link.pending(wlfw) == 10, "10 pending");
        ensure!(
            link.data_frame(0x4000, wlfw, &[0]) == Err(QrtrError::FlowBlocked),
            "11th blocks"
        );
        // Remote RESUME_TX for (node 3, port 1) resets the flow.
        let rt = encode_packet(
            QRTR_TYPE_RESUME_TX,
            QrtrAddr { node: 3, port: 1 },
            QrtrAddr {
                node: 1,
                port: 0x4000,
            },
            false,
            &CtrlPkt::ResumeTx { node: 3, port: 1 }.to_bytes(),
        )
        .map_err(|_| "rt")?;
        let rx = link.receive(&rt).map_err(|_| "rt rx")?;
        ensure!(
            rx.events == vec![QrtrEvent::ResumeTx { node: 3, port: 1 }],
            "resume event"
        );
        ensure!(link.pending(wlfw) == 0, "flow reset");
        ensure!(link.data_frame(0x4000, wlfw, &[0]).is_ok(), "sending again");
        // Incoming DATA with confirm_rx → RESUME_TX back to the sender,
        // from the receiving port (qrtr_send_resume_tx).
        let qmi = HOST_CAP_WCN6855;
        let data = encode_packet(
            QRTR_TYPE_DATA,
            wlfw,
            QrtrAddr {
                node: 1,
                port: 0x4000,
            },
            true,
            &qmi,
        )
        .map_err(|_| "data")?;
        let rx = link.receive(&data).map_err(|_| "data rx")?;
        const RESUME: [u8; 52] = [
            0x01, 0x00, 0x00, 0x00, // version 1
            0x07, 0x00, 0x00, 0x00, // RESUME_TX
            0x01, 0x00, 0x00, 0x00, // src node = cb->dst_node 1
            0x00, 0x40, 0x00, 0x00, // src port = cb->dst_port 0x4000
            0x00, 0x00, 0x00, 0x00, // confirm_rx 0
            0x14, 0x00, 0x00, 0x00, // size 20
            0x03, 0x00, 0x00, 0x00, // dst node = cb->src_node
            0x01, 0x00, 0x00, 0x00, // dst port = cb->src_port
            0x07, 0x00, 0x00, 0x00, // cmd RESUME_TX
            0x01, 0x00, 0x00, 0x00, // client.node
            0x00, 0x40, 0x00, 0x00, // client.port
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
        ];
        ensure!(rx.tx == vec![RESUME.to_vec()], "RESUME_TX reply bytes");
        ensure!(
            rx.events
                == vec![QrtrEvent::Data {
                    src: wlfw,
                    dst_port: 0x4000,
                    payload: qmi.to_vec()
                }],
            "DATA event"
        );
        // Without confirm_rx: no reply.
        let data = encode_packet(
            QRTR_TYPE_DATA,
            wlfw,
            QrtrAddr {
                node: 1,
                port: 0x4000,
            },
            false,
            &qmi,
        )
        .map_err(|_| "data2")?;
        ensure!(
            link.receive(&data).map_err(|_| "rx2")?.tx.is_empty(),
            "no RESUME_TX"
        );
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_qrtr_flow_control_and_data);

fn smoke_qrtr_qmi_end_to_end() -> TestResult {
    run(|| {
        // host_cap over QRTR: QMI message in a DATA frame, back out.
        let mut link = QrtrLink::new(1);
        link.receive(&ctrl_from(3, CtrlPkt::Hello))
            .map_err(|_| "hello")?;
        let req = enc(&HostCapReq::ath11k(&wcn6855(), 0), 1)?;
        let frame = link
            .data_frame(QRTR_MIN_EPH_SOCKET, QrtrAddr { node: 3, port: 1 }, &req)
            .map_err(|_| "frame")?;
        ensure!(frame.len() == 32 + 40, "38-byte QMI message padded to 40");
        let p = decode_packet(&frame).map_err(|_| "decode")?;
        let (hdr, payload) = split_message(p.payload).map_err(|_| "split")?;
        ensure!(
            hdr.msg_id == QMI_WLANFW_HOST_CAP_REQ_V01 && hdr.txn_id == 1,
            "QMI header"
        );
        ensure!(payload.len() == hdr.msg_len as usize, "msg_len");
        // And a firmware response coming back.
        let resp = msg(QMI_RESPONSE, QMI_WLFW_HOST_CAP_RESP_V01, &RESP_OK);
        let dl = encode_packet(
            QRTR_TYPE_DATA,
            QrtrAddr { node: 3, port: 1 },
            QrtrAddr {
                node: 1,
                port: QRTR_MIN_EPH_SOCKET,
            },
            false,
            &resp,
        )
        .map_err(|_| "dl")?;
        let rx = link.receive(&dl).map_err(|_| "rx")?;
        let Some(QrtrEvent::Data { payload, .. }) = rx.events.first() else {
            return Err("expected DATA");
        };
        let (_, r) = HostCapResp::decode(payload).map_err(|_| "resp")?;
        ensure!(r.resp.is_success(), "host_cap response success");
        Ok(())
    })
}
kernel_test_in!("drivers/wireless/ath11k", smoke_qrtr_qmi_end_to_end);
