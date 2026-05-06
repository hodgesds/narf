//! virtio-scsi-pci smokes — clean-room, sourced from VirtIO 1.2 §5.6.

#![cfg(target_arch = "x86_64")]

use narf_kernel_test::{kernel_test_in, TestResult};

use super::{VIRTIO_SCSI_PCI_DEVICE, VIRTIO_SCSI_PCI_VENDOR};

// ── Stage 1: PCI match table ───────────────────────────────────────

fn smoke_virtio_scsi_pci_match_table() -> TestResult {
    use narf_bus::driver_match::__reset_for_test;
    use narf_bus::{registered_pci_drivers, MatchKind};
    __reset_for_test();
    super::register_pci_driver();
    let registered = registered_pci_drivers();
    let matched = registered.iter().any(|m| {
        matches!(
            m.kind,
            MatchKind::VendorDevice {
                vendor: VIRTIO_SCSI_PCI_VENDOR,
                device: VIRTIO_SCSI_PCI_DEVICE,
            }
        )
    });
    if !matched {
        return TestResult::Fail("virtio-scsi PCI match table missing 1AF4:1048");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/virtio/scsi_pci", smoke_virtio_scsi_pci_match_table);

// ── Stage 2: wire-format round-trip (REPORT LUNS) ──────────────────

fn smoke_virtio_scsi_pci_report_luns_roundtrip() -> TestResult {
    use super::wire::{
        build_lun, build_report_luns_cdb, decode_cmd_resp, encode_cmd_req, encode_tmf_req,
        VirtioScsiCmdResp, CDB_SIZE, SCSI_OP_REPORT_LUNS, SENSE_SIZE, VIRTIO_SCSI_S_OK,
        VIRTIO_SCSI_S_SIMPLE, VIRTIO_SCSI_T_TMF, VIRTIO_SCSI_T_TMF_ABORT_TASK,
    };
    // Encode a REPORT LUNS for target 0, LUN 0, allocation length 256.
    let cdb = build_report_luns_cdb(256);
    if cdb[0] != SCSI_OP_REPORT_LUNS {
        return TestResult::Fail("REPORT LUNS opcode wrong");
    }
    if cdb[2] != 0 {
        return TestResult::Fail("SELECT REPORT must be 0");
    }
    // alloc_len 256 = 0x00000100, big-endian at bytes 6..10.
    if cdb[6] != 0 || cdb[7] != 0 || cdb[8] != 0x01 || cdb[9] != 0x00 {
        return TestResult::Fail("alloc_len BE encoding wrong");
    }
    // CDB pads to CDB_SIZE.
    if cdb.len() != CDB_SIZE {
        return TestResult::Fail("CDB pad size wrong");
    }

    let req = encode_cmd_req(
        /*target*/ 0,
        /*lun*/ 0,
        /*id*/ 0xDEAD_BEEF,
        VIRTIO_SCSI_S_SIMPLE,
        cdb,
    );
    let lun = req.lun;
    if lun != build_lun(0, 0) {
        return TestResult::Fail("LUN field mismatch");
    }
    if lun[0] != 1 {
        return TestResult::Fail("virtio-scsi LUN[0] must be 1");
    }
    let id = req.id;
    if id != 0xDEAD_BEEF {
        return TestResult::Fail("id round-trip failed");
    }
    let ta = req.task_attr;
    if ta != VIRTIO_SCSI_S_SIMPLE {
        return TestResult::Fail("task_attr lost");
    }

    // Synthesize a successful response: status=GOOD (0), response=OK,
    // residual=0 (full alloc_len consumed by an empty LUN list).
    let resp = VirtioScsiCmdResp {
        sense_len: 0,
        residual: 0,
        status_qualifier: 0,
        status: 0,
        response: VIRTIO_SCSI_S_OK,
        sense: [0u8; SENSE_SIZE],
    };
    let dec = decode_cmd_resp(&resp);
    if dec.response != VIRTIO_SCSI_S_OK {
        return TestResult::Fail("response decode wrong");
    }
    if dec.status != 0 {
        return TestResult::Fail("status decode wrong");
    }
    if dec.sense_len != 0 || dec.residual != 0 || dec.status_qualifier != 0 {
        return TestResult::Fail("zero-init resp decode mismatch");
    }

    // Synthesize a failure path: CHECK CONDITION (0x02), with
    // residual = full alloc_len (device returned no data) and a sense
    // length of 18 bytes.
    let mut resp_fail = VirtioScsiCmdResp {
        sense_len: 18,
        residual: 256,
        status_qualifier: 0,
        status: 0x02,
        response: VIRTIO_SCSI_S_OK,
        sense: [0u8; SENSE_SIZE],
    };
    resp_fail.sense[0] = 0x70; // current error, fixed-format sense
    resp_fail.sense[2] = 0x05; // ILLEGAL REQUEST
    resp_fail.sense[12] = 0x24; // ASC = INVALID FIELD IN CDB
    let df = decode_cmd_resp(&resp_fail);
    if df.status != 0x02 || df.sense_len != 18 || df.residual != 256 {
        return TestResult::Fail("CHECK CONDITION decode mismatch");
    }

    // Build a TMF (ABORT_TASK targeting our REPORT LUNS id).
    let tmf = encode_tmf_req(VIRTIO_SCSI_T_TMF_ABORT_TASK, 0, 0, 0xDEAD_BEEF);
    let ty = tmf.r#type;
    let sub = tmf.subtype;
    let tid = tmf.id;
    if ty != VIRTIO_SCSI_T_TMF {
        return TestResult::Fail("TMF type wrong");
    }
    if sub != VIRTIO_SCSI_T_TMF_ABORT_TASK {
        return TestResult::Fail("TMF subtype wrong");
    }
    if tid != 0xDEAD_BEEF {
        return TestResult::Fail("TMF id round-trip failed");
    }

    TestResult::Pass
}
kernel_test_in!(
    "drivers/virtio/scsi_pci",
    smoke_virtio_scsi_pci_report_luns_roundtrip
);

fn smoke_virtio_scsi_pci_live_report_luns() -> TestResult {
    use crate::scsi_pci;
    if !scsi_pci::is_probed() {
        return TestResult::Skip("no virtio-scsi-pci device on this run");
    }
    let r = scsi_pci::with_controller(|c| c.report_luns(0, 256));
    match r {
        Some(Ok((resp, _data))) => {
            // CHECK CONDITION (status=0x02) is acceptable when no
            // disk is attached at target 0; we just want a response.
            let _ = resp;
            TestResult::Pass
        }
        Some(Err(_)) => TestResult::Fail("submit_cmd returned err"),
        None => TestResult::Skip("controller missing"),
    }
}
kernel_test_in!(
    "drivers/virtio/scsi_pci",
    smoke_virtio_scsi_pci_live_report_luns
);
