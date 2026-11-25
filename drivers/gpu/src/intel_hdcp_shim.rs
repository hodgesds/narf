//! The HDCP sink shims: DP over AUX (`intel_dp_hdcp.c`'s
//! `intel_dp_hdcp_shim`) and HDMI over DDC (`intel_hdmi.c`'s
//! `intel_hdmi_hdcp_shim`).
//!
//! ## DP (DPCD 0x68000 and 0x69000, `include/drm/display/drm_dp.h`)
//!
//! HDCP 1.4 registers at `DP_AUX_HDCP_*`; HDCP 2.2 messages at the
//! `DP_HDCP_2_2_*_OFFSET`s without their message-id byte, in 16-byte AUX
//! transfers; availability from `DP_HDCP_2_2_REG_RXSTATUS_OFFSET`. Linux
//! waits for the sink's `CP_IRQ` before checking a detectable message;
//! NARF does not route the short-pulse `CP_IRQ` to HDCP and polls RxStatus
//! every [`DP_POLL_MS`] up to the same timeout instead. The Aksv write is a
//! five-zero-byte native write to `DP_AUX_HDCP_AKSV`, which the AUX
//! transport marks `DP_AUX_CH_CTL_AUX_AKSV_SELECT`.
//!
//! ## HDMI (DDC slave 0x3A, `DRM_HDCP_DDC_*`)
//!
//! HDCP 1.4 registers by index read/write; HDCP 2.2 messages whole
//! (message id included) to `HDCP_2_2_HDMI_REG_WR_MSG_OFFSET` and from
//! `HDCP_2_2_HDMI_REG_RD_MSG_OFFSET`, sized by RxStatus. The Aksv goes
//! out as an index write with `GMBUS_AKSV_SELECT`.

use crate::dp_aux::{AuxChannel, AuxError};
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gmbus::{GmbusBus, GmbusError, I2cMsg, PinPair};
use crate::intel_hdcp::{HdcpError, HdcpShim, LinkCheck, MsgTiming, Protocol};
use crate::intel_hdcp_msg as msg;

/// Native DPCD access for the DP shim.
pub trait Dpcd: Send {
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), HdcpError>;
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), HdcpError>;
}

/// The HDCP DDC slave (0x3A) for the HDMI shim.
pub trait Ddc: Send {
    /// Read `buf.len()` bytes at `offset` (index write, then read).
    fn read(&mut self, offset: u8, buf: &mut [u8]) -> Result<(), HdcpError>;
    /// Write `data` at `offset` (one message: offset, then data).
    fn write(&mut self, offset: u8, data: &[u8]) -> Result<(), HdcpError>;
    /// `intel_gmbus_output_aksv`.
    fn output_aksv(&mut self) -> Result<(), HdcpError>;
}

// ── DP ───────────────────────────────────────────────────────────────

pub const DP_AUX_HDCP_BKSV: u32 = 0x68000;
pub const DP_AUX_HDCP_RI_PRIME: u32 = 0x68005;
pub const DP_AUX_HDCP_AKSV: u32 = 0x68007;
pub const DP_AUX_HDCP_AN: u32 = 0x6800c;
pub const fn dp_aux_hdcp_v_prime(h: usize) -> u32 {
    0x68014 + h as u32 * 4
}
pub const DP_AUX_HDCP_BCAPS: u32 = 0x68028;
pub const DP_BCAPS_REPEATER_PRESENT: u8 = 1 << 1;
pub const DP_BCAPS_HDCP_CAPABLE: u8 = 1 << 0;
pub const DP_AUX_HDCP_BSTATUS: u32 = 0x68029;
pub const DP_BSTATUS_REAUTH_REQ: u8 = 1 << 3;
pub const DP_BSTATUS_LINK_FAILURE: u8 = 1 << 2;
pub const DP_BSTATUS_R0_PRIME_READY: u8 = 1 << 1;
pub const DP_BSTATUS_READY: u8 = 1 << 0;
pub const DP_AUX_HDCP_BINFO: u32 = 0x6802a;
pub const DP_AUX_HDCP_KSV_FIFO: u32 = 0x6802c;

pub const DP_HDCP_2_2_REG_RTX_OFFSET: u32 = 0x69000;
pub const DP_HDCP_2_2_REG_CERT_RX_OFFSET: u32 = 0x6900b;
pub const DP_HDCP_2_2_REG_RX_CAPS_OFFSET: u32 = 0x6921d;
pub const DP_HDCP_2_2_REG_EKPUB_KM_OFFSET: u32 = 0x69220;
pub const DP_HDCP_2_2_REG_EKH_KM_WR_OFFSET: u32 = 0x692a0;
pub const DP_HDCP_2_2_REG_HPRIME_OFFSET: u32 = 0x692c0;
pub const DP_HDCP_2_2_REG_EKH_KM_RD_OFFSET: u32 = 0x692e0;
pub const DP_HDCP_2_2_REG_RN_OFFSET: u32 = 0x692f0;
pub const DP_HDCP_2_2_REG_LPRIME_OFFSET: u32 = 0x692f8;
pub const DP_HDCP_2_2_REG_EDKEY_KS_OFFSET: u32 = 0x69318;
pub const DP_HDCP_2_2_REG_RXINFO_OFFSET: u32 = 0x69330;
pub const DP_HDCP_2_2_REG_V_OFFSET: u32 = 0x693e0;
pub const DP_HDCP_2_2_REG_SEQ_NUM_M_OFFSET: u32 = 0x693f0;
pub const DP_HDCP_2_2_REG_MPRIME_OFFSET: u32 = 0x69473;
pub const DP_HDCP_2_2_REG_RXSTATUS_OFFSET: u32 = 0x69493;
pub const DP_HDCP_2_2_REG_STREAM_TYPE_OFFSET: u32 = 0x69494;

/// `HDCP_2_2_DP_RXSTATUS_*`.
const RXSTATUS_READY: u8 = 1 << 0;
const RXSTATUS_H_PRIME: u8 = 1 << 1;
const RXSTATUS_PAIRING: u8 = 1 << 2;
const RXSTATUS_REAUTH_REQ: u8 = 1 << 3;
const RXSTATUS_LINK_FAILED: u8 = 1 << 4;

/// The RxStatus poll that stands in for `intel_dp_hdcp_wait_for_cp_irq`.
pub const DP_POLL_MS: u64 = 10;
/// `DP_AUX_MAX_PAYLOAD_BYTES`.
const AUX_MAX: usize = 16;

/// `hdcp2_dp_msg_data`: (msg_id, offset, detectable, timeout,
/// timeout2 for a non-paired H', whole-message read timeout).
const DP_MSGS: [(u8, u32, bool, u64, u64, u64); 14] = [
    (msg::AKE_INIT, DP_HDCP_2_2_REG_RTX_OFFSET, false, 0, 0, 0),
    (
        msg::AKE_SEND_CERT,
        DP_HDCP_2_2_REG_CERT_RX_OFFSET,
        false,
        100,
        0,
        110,
    ),
    (
        msg::AKE_NO_STORED_KM,
        DP_HDCP_2_2_REG_EKPUB_KM_OFFSET,
        false,
        0,
        0,
        0,
    ),
    (
        msg::AKE_STORED_KM,
        DP_HDCP_2_2_REG_EKH_KM_WR_OFFSET,
        false,
        0,
        0,
        0,
    ),
    (
        msg::AKE_SEND_HPRIME,
        DP_HDCP_2_2_REG_HPRIME_OFFSET,
        true,
        200,
        1000,
        7,
    ),
    (
        msg::AKE_SEND_PAIRING_INFO,
        DP_HDCP_2_2_REG_EKH_KM_RD_OFFSET,
        true,
        200,
        0,
        5,
    ),
    (msg::LC_INIT, DP_HDCP_2_2_REG_RN_OFFSET, false, 0, 0, 0),
    (
        msg::LC_SEND_LPRIME,
        DP_HDCP_2_2_REG_LPRIME_OFFSET,
        false,
        16,
        0,
        0,
    ),
    (
        msg::SKE_SEND_EKS,
        DP_HDCP_2_2_REG_EDKEY_KS_OFFSET,
        false,
        0,
        0,
        0,
    ),
    (
        msg::REP_SEND_RECVID_LIST,
        DP_HDCP_2_2_REG_RXINFO_OFFSET,
        true,
        3000,
        0,
        0,
    ),
    (msg::REP_SEND_ACK, DP_HDCP_2_2_REG_V_OFFSET, false, 0, 0, 0),
    (
        msg::REP_STREAM_MANAGE,
        DP_HDCP_2_2_REG_SEQ_NUM_M_OFFSET,
        false,
        0,
        0,
        0,
    ),
    (
        msg::REP_STREAM_READY,
        DP_HDCP_2_2_REG_MPRIME_OFFSET,
        false,
        100,
        0,
        0,
    ),
    (
        msg::ERRATA_DP_STREAM_TYPE,
        DP_HDCP_2_2_REG_STREAM_TYPE_OFFSET,
        false,
        0,
        0,
        0,
    ),
];

fn dp_msg(id: u8) -> Result<(u8, u32, bool, u64, u64, u64), HdcpError> {
    DP_MSGS
        .iter()
        .copied()
        .find(|m| m.0 == id)
        .ok_or(HdcpError::MsgSize)
}

/// `intel_dp_hdcp_shim` (single stream).
#[derive(Debug)]
pub struct DpShim<D> {
    pub dpcd: D,
}

impl<D: Dpcd> DpShim<D> {
    pub fn new(dpcd: D) -> Self {
        Self { dpcd }
    }

    fn byte(&mut self, addr: u32) -> Result<u8, HdcpError> {
        let mut b = [0u8; 1];
        self.dpcd.read(addr, &mut b)?;
        Ok(b[0])
    }

    /// Chunked DPCD read (`drm_dp_dpcd_read` in ≤ 16-byte transfers).
    fn read_long(&mut self, mut addr: u32, buf: &mut [u8]) -> Result<(), HdcpError> {
        for chunk in buf.chunks_mut(AUX_MAX) {
            self.dpcd.read(addr, chunk)?;
            addr += chunk.len() as u32;
        }
        Ok(())
    }
}

impl<D: Dpcd> HdcpShim for DpShim<D> {
    fn protocol(&self) -> Protocol {
        Protocol::Dp
    }

    /// `intel_dp_hdcp_write_an_aksv`.
    fn write_an_aksv(&mut self, an: &[u8; 8]) -> Result<(), HdcpError> {
        self.dpcd.write(DP_AUX_HDCP_AN, an)?;
        self.dpcd.write(DP_AUX_HDCP_AKSV, &[0; msg::KSV_LEN])
    }

    fn read_bksv(&mut self) -> Result<[u8; 5], HdcpError> {
        let mut b = [0u8; 5];
        self.dpcd.read(DP_AUX_HDCP_BKSV, &mut b)?;
        Ok(b)
    }

    /// BINFO.
    fn read_bstatus(&mut self) -> Result<[u8; 2], HdcpError> {
        let mut b = [0u8; 2];
        self.dpcd.read(DP_AUX_HDCP_BINFO, &mut b)?;
        Ok(b)
    }

    fn repeater_present(&mut self) -> Result<bool, HdcpError> {
        Ok(self.byte(DP_AUX_HDCP_BCAPS)? & DP_BCAPS_REPEATER_PRESENT != 0)
    }

    fn read_ri_prime(&mut self) -> Result<[u8; 2], HdcpError> {
        let mut b = [0u8; 2];
        self.dpcd.read(DP_AUX_HDCP_RI_PRIME, &mut b)?;
        Ok(b)
    }

    fn read_ksv_ready(&mut self) -> Result<bool, HdcpError> {
        Ok(self.byte(DP_AUX_HDCP_BSTATUS)? & DP_BSTATUS_READY != 0)
    }

    /// The 15-byte window: three KSVs per read.
    fn read_ksv_fifo(&mut self, num: usize, out: &mut [u8]) -> Result<(), HdcpError> {
        let mut i = 0;
        while i < num {
            let n = (num - i).min(3) * msg::KSV_LEN;
            self.dpcd
                .read(DP_AUX_HDCP_KSV_FIFO, &mut out[i * msg::KSV_LEN..][..n])?;
            i += 3;
        }
        Ok(())
    }

    fn read_v_prime_part(&mut self, i: usize) -> Result<u32, HdcpError> {
        if i >= 5 {
            return Err(HdcpError::MsgSize);
        }
        let mut b = [0u8; 4];
        self.dpcd.read(dp_aux_hdcp_v_prime(i), &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn hdcp_capable(&mut self) -> Option<Result<bool, HdcpError>> {
        Some(
            self.byte(DP_AUX_HDCP_BCAPS)
                .map(|b| b & DP_BCAPS_HDCP_CAPABLE != 0),
        )
    }

    /// `intel_dp_hdcp_check_link`.
    fn check_link_status(&mut self) -> Option<bool> {
        Some(
            self.byte(DP_AUX_HDCP_BSTATUS)
                .is_ok_and(|b| b & (DP_BSTATUS_LINK_FAILURE | DP_BSTATUS_REAUTH_REQ) == 0),
        )
    }

    /// `_intel_dp_hdcp2_get_capability`: three reads of RxCaps.
    fn hdcp2_capable(&mut self) -> Result<bool, HdcpError> {
        for _ in 0..3 {
            let mut caps = [0u8; msg::RXCAPS_LEN];
            self.dpcd.read(DP_HDCP_2_2_REG_RX_CAPS_OFFSET, &mut caps)?;
            if caps[0] == msg::RX_CAPS_VERSION_VAL && msg::dp_hdcp_capable(caps[2]) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `intel_dp_hdcp2_write_msg`: no message id on DP.
    fn write_2_2_msg(&mut self, m: &[u8]) -> Result<(), HdcpError> {
        let (_, mut offset, ..) = dp_msg(*m.first().ok_or(HdcpError::MsgSize)?)?;
        for chunk in m[1..].chunks(AUX_MAX) {
            self.dpcd.write(offset, chunk)?;
            offset += chunk.len() as u32;
        }
        Ok(())
    }

    fn msg_timing(&self, msg_id: u8, paired: bool) -> Result<MsgTiming, HdcpError> {
        let (id, _, detectable, timeout, timeout2, read_timeout) = dp_msg(msg_id)?;
        Ok(MsgTiming {
            detectable,
            timeout_ms: if id == msg::AKE_SEND_HPRIME && !paired {
                timeout2
            } else {
                timeout
            },
            read_timeout_ms: read_timeout,
            poll_ms: DP_POLL_MS,
        })
    }

    /// `hdcp2_detect_msg_availability`.
    fn msg_available(&mut self, msg_id: u8) -> Result<Option<usize>, HdcpError> {
        let rx = self.byte(DP_HDCP_2_2_REG_RXSTATUS_OFFSET)?;
        let ready = match msg_id {
            msg::AKE_SEND_HPRIME => rx & RXSTATUS_H_PRIME != 0,
            msg::AKE_SEND_PAIRING_INFO => rx & RXSTATUS_PAIRING != 0,
            msg::REP_SEND_RECVID_LIST => rx & RXSTATUS_READY != 0,
            _ => return Err(HdcpError::MsgSize),
        };
        Ok(ready.then_some(0))
    }

    /// `intel_dp_hdcp2_read_msg`: the receiver ID list is sized by its
    /// RxInfo device count (at most 31).
    fn read_2_2_msg(&mut self, msg_id: u8, _: usize, buf: &mut [u8]) -> Result<usize, HdcpError> {
        let (_, offset, ..) = dp_msg(msg_id)?;
        if buf.is_empty() {
            return Err(HdcpError::MsgSize);
        }
        buf[0] = msg_id;
        if msg_id == msg::REP_SEND_RECVID_LIST {
            if buf.len() < msg::REP_SEND_RECVID_LIST_SIZE {
                return Err(HdcpError::MsgSize);
            }
            let mut rx_info = [0u8; msg::RXINFO_LEN];
            self.dpcd
                .read(DP_HDCP_2_2_REG_RXINFO_OFFSET, &mut rx_info)?;
            buf[1..3].copy_from_slice(&rx_info);
            let devices = (msg::device_count(rx_info) as usize).min(msg::MAX_DEVICE_COUNT);
            let rest = msg::SEQ_NUM_LEN + msg::V_PRIME_HALF_LEN + devices * msg::KSV_LEN;
            self.read_long(offset + msg::RXINFO_LEN as u32, &mut buf[3..3 + rest])?;
            return Ok(3 + rest);
        }
        let size = buf.len();
        self.read_long(offset, &mut buf[1..size])?;
        Ok(size)
    }

    /// `intel_dp_hdcp2_config_stream_type`: the DP errata write, sinks
    /// only (a repeater learns the type from stream management).
    fn config_stream_type(&mut self, is_repeater: bool, content_type: u8) -> Result<(), HdcpError> {
        if is_repeater {
            return Ok(());
        }
        self.write_2_2_msg(&[msg::ERRATA_DP_STREAM_TYPE, content_type])
    }

    /// `intel_dp_hdcp2_check_link`.
    fn check_2_2_link(&mut self) -> Result<LinkCheck, HdcpError> {
        let rx = self.byte(DP_HDCP_2_2_REG_RXSTATUS_OFFSET)?;
        Ok(if rx & RXSTATUS_REAUTH_REQ != 0 {
            LinkCheck::ReauthRequest
        } else if rx & RXSTATUS_LINK_FAILED != 0 {
            LinkCheck::IntegrityFailure
        } else if rx & RXSTATUS_READY != 0 {
            LinkCheck::TopologyChange
        } else {
            LinkCheck::Protected
        })
    }
}

// ── HDMI ─────────────────────────────────────────────────────────────

/// `DRM_HDCP_DDC_ADDR`.
pub const DRM_HDCP_DDC_ADDR: u8 = 0x3A;
pub const DDC_BKSV: u8 = 0x00;
pub const DDC_RI_PRIME: u8 = 0x08;
pub const DDC_AKSV: u8 = 0x10;
pub const DDC_AN: u8 = 0x18;
pub const fn ddc_v_prime(h: usize) -> u8 {
    0x20 + h as u8 * 4
}
pub const DDC_BCAPS: u8 = 0x40;
pub const DDC_BCAPS_REPEATER_PRESENT: u8 = 1 << 6;
pub const DDC_BCAPS_KSV_FIFO_READY: u8 = 1 << 5;
pub const DDC_BSTATUS: u8 = 0x41;
pub const DDC_KSV_FIFO: u8 = 0x43;
pub const HDCP_2_2_HDMI_REG_VER_OFFSET: u8 = 0x50;
pub const HDCP_2_2_HDMI_REG_WR_MSG_OFFSET: u8 = 0x60;
pub const HDCP_2_2_HDMI_REG_RXSTATUS_OFFSET: u8 = 0x70;
pub const HDCP_2_2_HDMI_REG_RD_MSG_OFFSET: u8 = 0x80;
/// `HDCP_2_2_HDMI_SUPPORT_MASK`.
pub const HDCP_2_2_HDMI_SUPPORT: u8 = 1 << 2;
/// The `poll_timeout_us` interval of `intel_hdmi_hdcp2_wait_for_msg`.
pub const HDMI_POLL_MS: u64 = 4;

/// `intel_hdmi_hdcp_shim`.
#[derive(Debug)]
pub struct HdmiShim<D> {
    pub ddc: D,
}

impl<D: Ddc> HdmiShim<D> {
    pub fn new(ddc: D) -> Self {
        Self { ddc }
    }

    fn byte(&mut self, offset: u8) -> Result<u8, HdcpError> {
        let mut b = [0u8; 1];
        self.ddc.read(offset, &mut b)?;
        Ok(b[0])
    }

    fn rx_status(&mut self) -> Result<[u8; 2], HdcpError> {
        let mut b = [0u8; 2];
        self.ddc.read(HDCP_2_2_HDMI_REG_RXSTATUS_OFFSET, &mut b)?;
        Ok(b)
    }
}

impl<D: Ddc> HdcpShim for HdmiShim<D> {
    fn protocol(&self) -> Protocol {
        Protocol::Hdmi
    }

    fn write_an_aksv(&mut self, an: &[u8; 8]) -> Result<(), HdcpError> {
        self.ddc.write(DDC_AN, an)?;
        self.ddc.output_aksv()
    }

    fn read_bksv(&mut self) -> Result<[u8; 5], HdcpError> {
        let mut b = [0u8; 5];
        self.ddc.read(DDC_BKSV, &mut b)?;
        Ok(b)
    }

    fn read_bstatus(&mut self) -> Result<[u8; 2], HdcpError> {
        let mut b = [0u8; 2];
        self.ddc.read(DDC_BSTATUS, &mut b)?;
        Ok(b)
    }

    fn repeater_present(&mut self) -> Result<bool, HdcpError> {
        Ok(self.byte(DDC_BCAPS)? & DDC_BCAPS_REPEATER_PRESENT != 0)
    }

    fn read_ri_prime(&mut self) -> Result<[u8; 2], HdcpError> {
        let mut b = [0u8; 2];
        self.ddc.read(DDC_RI_PRIME, &mut b)?;
        Ok(b)
    }

    fn read_ksv_ready(&mut self) -> Result<bool, HdcpError> {
        Ok(self.byte(DDC_BCAPS)? & DDC_BCAPS_KSV_FIFO_READY != 0)
    }

    fn read_ksv_fifo(&mut self, num: usize, out: &mut [u8]) -> Result<(), HdcpError> {
        self.ddc.read(DDC_KSV_FIFO, &mut out[..num * msg::KSV_LEN])
    }

    fn read_v_prime_part(&mut self, i: usize) -> Result<u32, HdcpError> {
        if i >= 5 {
            return Err(HdcpError::MsgSize);
        }
        let mut b = [0u8; 4];
        self.ddc.read(ddc_v_prime(i), &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn hdcp_capable(&mut self) -> Option<Result<bool, HdcpError>> {
        None
    }

    fn check_link_status(&mut self) -> Option<bool> {
        None
    }

    /// `intel_hdmi_hdcp2_get_capability`.
    fn hdcp2_capable(&mut self) -> Result<bool, HdcpError> {
        Ok(self.byte(HDCP_2_2_HDMI_REG_VER_OFFSET)? & HDCP_2_2_HDMI_SUPPORT != 0)
    }

    fn write_2_2_msg(&mut self, m: &[u8]) -> Result<(), HdcpError> {
        self.ddc.write(HDCP_2_2_HDMI_REG_WR_MSG_OFFSET, m)
    }

    /// `get_hdcp2_msg_timeout`; every HDMI message is detected by its
    /// RxStatus size, polled every 4 ms.
    fn msg_timing(&self, msg_id: u8, paired: bool) -> Result<MsgTiming, HdcpError> {
        let timeout_ms = match msg_id {
            msg::AKE_SEND_HPRIME if paired => 200,
            msg::AKE_SEND_HPRIME => 1000,
            msg::AKE_SEND_CERT => 100,
            msg::AKE_SEND_PAIRING_INFO => 200,
            msg::LC_SEND_LPRIME => 20,
            msg::REP_SEND_RECVID_LIST => 3000,
            msg::REP_STREAM_READY => 100,
            _ => return Err(HdcpError::MsgSize),
        };
        Ok(MsgTiming {
            detectable: true,
            timeout_ms,
            read_timeout_ms: 0,
            poll_ms: HDMI_POLL_MS,
        })
    }

    /// `hdcp2_detect_msg_availability`: the size in RxStatus, and the
    /// READY bit for the receiver ID list.
    fn msg_available(&mut self, msg_id: u8) -> Result<Option<usize>, HdcpError> {
        let rx = self.rx_status()?;
        let size = usize::from(rx[1] & 0x3) << 8 | usize::from(rx[0]);
        let ready = if msg_id == msg::REP_SEND_RECVID_LIST {
            rx[1] & (1 << 2) != 0 && size != 0
        } else {
            size != 0
        };
        Ok(ready.then_some(size))
    }

    /// `intel_hdmi_hdcp2_read_msg`: the available size must fit.
    fn read_2_2_msg(
        &mut self,
        _: u8,
        available: usize,
        buf: &mut [u8],
    ) -> Result<usize, HdcpError> {
        if available == 0 || available > buf.len() {
            return Err(HdcpError::MsgSize);
        }
        self.ddc
            .read(HDCP_2_2_HDMI_REG_RD_MSG_OFFSET, &mut buf[..available])?;
        Ok(available)
    }

    fn config_stream_type(&mut self, _: bool, _: u8) -> Result<(), HdcpError> {
        Ok(())
    }

    /// `intel_hdmi_hdcp2_check_link`: reauth and link-integrity failure
    /// share REAUTH_REQ.
    fn check_2_2_link(&mut self) -> Result<LinkCheck, HdcpError> {
        let rx = self.rx_status()?;
        Ok(if rx[1] & (1 << 3) != 0 {
            LinkCheck::ReauthRequest
        } else if rx[1] & (1 << 2) != 0 {
            LinkCheck::TopologyChange
        } else {
            LinkCheck::Protected
        })
    }
}

// ── Production transports ────────────────────────────────────────────

/// Which AUX register block and control word a DP route uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuxPort {
    /// Gen12 DDI AUX (`IntelAux::new`).
    Gen12(crate::intel_gpu_ddi::Ddi),
    /// Display 14+ AUX at `base` (`IntelAux::xelpdp`).
    XeLpdp { base: u64, tbt_io: bool },
}

/// `drm_dp_dpcd_access`'s retries: 32 attempts on anything but a NACK.
const DPCD_TRIES: u32 = 32;

fn aux_errno(e: AuxError) -> HdcpError {
    use narf_lib::errno as e_;
    HdcpError::Sink(
        -(match e {
            AuxError::Nacked => e_::EIO,
            AuxError::Deferred => e_::EBUSY,
            AuxError::TooLong => e_::E2BIG,
            _ => e_::EPROTO,
        } as i32),
    )
}

/// Native DPCD over the route's AUX channel, one `IntelAux` per transfer.
pub struct AuxDpcd<'a, M: ?Sized> {
    pub io: &'a M,
    pub port: AuxPort,
}

impl<M: ?Sized> core::fmt::Debug for AuxDpcd<'_, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AuxDpcd")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl<M: MmioWindow + Sync + ?Sized> AuxDpcd<'_, M> {
    fn transfer(
        &self,
        mut op: impl FnMut(&mut dyn AuxChannel) -> Result<(), AuxError>,
    ) -> Result<(), HdcpError> {
        let mut last = AuxError::Deferred;
        for _ in 0..DPCD_TRIES {
            let result = match self.port {
                AuxPort::Gen12(ddi) => op(&mut crate::intel_gpu_aux::IntelAux::new(self.io, ddi)),
                AuxPort::XeLpdp { base, tbt_io } => op(
                    &mut crate::intel_gpu_aux::IntelAux::xelpdp(self.io, base, tbt_io),
                ),
            };
            match result {
                Ok(()) => return Ok(()),
                Err(AuxError::Nacked) => return Err(aux_errno(AuxError::Nacked)),
                Err(e) => last = e,
            }
            // intel_dp_aux_xfer's DEFER back-off (400-500 µs).
            let budget = narf_time::wall::ns_to_cycles(500_000);
            let start = narf_time::now_cycles();
            while narf_time::now_cycles().wrapping_sub(start) < budget {
                core::hint::spin_loop();
            }
        }
        Err(aux_errno(last))
    }
}

impl<M: MmioWindow + Sync + ?Sized> Dpcd for AuxDpcd<'_, M> {
    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), HdcpError> {
        self.transfer(|aux| aux.dpcd_read(addr, buf))
    }
    fn write(&mut self, addr: u32, data: &[u8]) -> Result<(), HdcpError> {
        self.transfer(|aux| aux.dpcd_write(addr, data))
    }
}

fn gmbus_errno(e: GmbusError) -> HdcpError {
    use narf_lib::errno as e_;
    HdcpError::Sink(
        -(match e {
            GmbusError::SlaveNack => e_::ENXIO,
            GmbusError::Timeout | GmbusError::HardwareTimeout => e_::ETIMEDOUT,
            _ => e_::EIO,
        } as i32),
    )
}

/// The HDCP slave over the route's GMBUS pin.
pub struct GmbusDdc<'a, M: ?Sized> {
    pub io: &'a M,
    pub pin: PinPair,
}

impl<M: ?Sized> core::fmt::Debug for GmbusDdc<'_, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GmbusDdc")
            .field("pin", &self.pin)
            .finish_non_exhaustive()
    }
}

impl<M: MmioWindow + Sync + ?Sized> Ddc for GmbusDdc<'_, M> {
    /// `intel_hdmi_hdcp_read`.
    fn read(&mut self, offset: u8, buf: &mut [u8]) -> Result<(), HdcpError> {
        GmbusBus::new(self.io, self.pin)
            .xfer(&mut [
                I2cMsg::Write {
                    addr: DRM_HDCP_DDC_ADDR,
                    data: &[offset],
                },
                I2cMsg::Read {
                    addr: DRM_HDCP_DDC_ADDR,
                    buf,
                },
            ])
            .map_err(gmbus_errno)
    }

    /// `intel_hdmi_hdcp_write`: one message, the offset then the data.
    fn write(&mut self, offset: u8, data: &[u8]) -> Result<(), HdcpError> {
        let mut m = alloc::vec::Vec::with_capacity(data.len() + 1);
        m.push(offset);
        m.extend_from_slice(data);
        GmbusBus::new(self.io, self.pin)
            .write(DRM_HDCP_DDC_ADDR, &m)
            .map_err(gmbus_errno)
    }

    fn output_aksv(&mut self) -> Result<(), HdcpError> {
        GmbusBus::new(self.io, self.pin)
            .output_aksv()
            .map_err(gmbus_errno)
    }
}
