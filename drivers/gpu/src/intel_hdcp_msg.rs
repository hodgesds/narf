//! HDCP 2.2 message layouts and the HDCP firmware command set.
//!
//! ## References
//!
//! - `include/drm/display/drm_hdcp.h`: the HDCP 2.2 message ids, field
//!   lengths and the packed `struct hdcp2_*` messages the transmitter
//!   exchanges with the sink.
//! - `include/drm/intel/i915_hdcp_interface.h`: `struct hdcp_port_data`,
//!   the `enum hdcp_*` port/protocol/transcoder indices, `enum
//!   fw_hdcp_status`, `enum hdcp_command_id`, the
//!   `WIRED_CMD_BUF_LEN_*` payload lengths and the packed
//!   `struct wired_cmd_*_{in,out}` commands of the CSME/GSC HDCP client.
//! - `drivers/misc/mei/hdcp/mei_hdcp.c` and
//!   `drivers/gpu/drm/i915/display/intel_hdcp_gsc_message.c`: the eleven
//!   `i915_hdcp_ops`, each one command and its reply. The two files are
//!   the same translation over two transports; [`Fw`] is that translation
//!   once, over a [`HdcpTransport`].
//! - `drivers/gpu/drm/xe/display/xe_hdcp_gsc.c`: the GSC transport's
//!   framing (`intel_hdcp_gsc_msg_send`), [`frame_gsc_command`] and
//!   [`GscFraming`].
//!
//! ## Secrets
//!
//! The firmware returns km encrypted under the receiver's public key, ks
//! encrypted under the derived key, and the topology; none of it is
//! secret in the clear, but none of it is logged either: this module
//! never prints a message, and [`FwError`] carries only the firmware
//! status code.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;

// ── drm_hdcp.h ───────────────────────────────────────────────────────

/// `DRM_HDCP_KSV_LEN`: a KSV / receiver ID.
pub const KSV_LEN: usize = 5;
/// `HDCP_STREAM_TYPE0` / `HDCP_STREAM_TYPE1`.
pub const STREAM_TYPE0: u8 = 0;
pub const STREAM_TYPE1: u8 = 1;

/// HDCP 2.2 message ids.
pub const AKE_INIT: u8 = 2;
pub const AKE_SEND_CERT: u8 = 3;
pub const AKE_NO_STORED_KM: u8 = 4;
pub const AKE_STORED_KM: u8 = 5;
pub const AKE_SEND_HPRIME: u8 = 7;
pub const AKE_SEND_PAIRING_INFO: u8 = 8;
pub const LC_INIT: u8 = 9;
pub const LC_SEND_LPRIME: u8 = 10;
pub const SKE_SEND_EKS: u8 = 11;
pub const REP_SEND_RECVID_LIST: u8 = 12;
pub const REP_SEND_ACK: u8 = 15;
pub const REP_STREAM_MANAGE: u8 = 16;
pub const REP_STREAM_READY: u8 = 17;
/// `intel_dp_hdcp.c`'s local `HDCP_2_2_ERRATA_DP_STREAM_TYPE` (the DP
/// errata stream-type write shovelled through `write_2_2_msg`).
pub const ERRATA_DP_STREAM_TYPE: u8 = 50;

pub const RTX_LEN: usize = 8;
pub const RRX_LEN: usize = 8;
pub const TXCAPS_LEN: usize = 3;
pub const RXCAPS_LEN: usize = 3;
/// `HDCP_2_2_K_PUB_RX_LEN` (modulus 128 + exponent 3).
pub const K_PUB_RX_LEN: usize = 131;
pub const DCP_LLC_SIG_LEN: usize = 384;
/// `sizeof(struct hdcp2_cert_rx)`: receiver_id, kpub_rx, reserved[2],
/// dcp_signature.
pub const CERT_RX_LEN: usize = KSV_LEN + K_PUB_RX_LEN + 2 + DCP_LLC_SIG_LEN;
pub const E_KPUB_KM_LEN: usize = 128;
pub const E_KH_KM_M_LEN: usize = 32;
pub const H_PRIME_LEN: usize = 32;
pub const E_KH_KM_LEN: usize = 16;
pub const RN_LEN: usize = 8;
pub const L_PRIME_LEN: usize = 32;
pub const E_DKEY_KS_LEN: usize = 16;
pub const RIV_LEN: usize = 8;
pub const SEQ_NUM_LEN: usize = 3;
pub const V_PRIME_HALF_LEN: usize = 16;
pub const RXINFO_LEN: usize = 2;
pub const MAX_DEVICE_COUNT: usize = 31;
pub const RECEIVER_IDS_MAX_LEN: usize = KSV_LEN * MAX_DEVICE_COUNT;
pub const MPRIME_LEN: usize = 32;
/// `HDCP_2_2_MAX_CONTENT_STREAMS_CNT`.
pub const MAX_CONTENT_STREAMS: usize = 4;
/// `HDCP_2_2_RX_CAPS_VERSION_VAL`.
pub const RX_CAPS_VERSION_VAL: u8 = 0x02;
/// `HDCP_2_2_SEQ_NUM_MAX`.
pub const SEQ_NUM_MAX: u32 = 0x00FF_FFFF;

/// `sizeof(struct hdcp2_*)` for each message, the msg_id byte included.
pub const AKE_INIT_SIZE: usize = 1 + RTX_LEN + TXCAPS_LEN;
pub const AKE_SEND_CERT_SIZE: usize = 1 + CERT_RX_LEN + RRX_LEN + RXCAPS_LEN;
pub const AKE_NO_STORED_KM_SIZE: usize = 1 + E_KPUB_KM_LEN;
pub const AKE_STORED_KM_SIZE: usize = 1 + E_KH_KM_M_LEN;
pub const AKE_SEND_HPRIME_SIZE: usize = 1 + H_PRIME_LEN;
pub const AKE_SEND_PAIRING_INFO_SIZE: usize = 1 + E_KH_KM_LEN;
pub const LC_INIT_SIZE: usize = 1 + RN_LEN;
pub const LC_SEND_LPRIME_SIZE: usize = 1 + L_PRIME_LEN;
pub const SKE_SEND_EKS_SIZE: usize = 1 + E_DKEY_KS_LEN + RIV_LEN;
pub const REP_SEND_RECVID_LIST_SIZE: usize =
    1 + RXINFO_LEN + SEQ_NUM_LEN + V_PRIME_HALF_LEN + RECEIVER_IDS_MAX_LEN;
pub const REP_SEND_ACK_SIZE: usize = 1 + V_PRIME_HALF_LEN;
/// With all four streams; the transmitter sends
/// `size - (MAX_CONTENT_STREAMS - k) * 2`.
pub const REP_STREAM_MANAGE_SIZE: usize = 1 + SEQ_NUM_LEN + 2 + MAX_CONTENT_STREAMS * 2;
pub const REP_STREAM_READY_SIZE: usize = 1 + MPRIME_LEN;

/// Offsets inside `struct hdcp2_ake_send_cert`.
pub const CERT_RECEIVER_ID: usize = 1;
pub const CERT_RRX: usize = 1 + CERT_RX_LEN;
pub const CERT_RXCAPS: usize = CERT_RRX + RRX_LEN;
/// Offsets inside `struct hdcp2_rep_send_receiverid_list`.
pub const RECVID_RXINFO: usize = 1;
pub const RECVID_SEQ_NUM_V: usize = RECVID_RXINFO + RXINFO_LEN;
pub const RECVID_V_PRIME: usize = RECVID_SEQ_NUM_V + SEQ_NUM_LEN;
pub const RECVID_IDS: usize = RECVID_V_PRIME + V_PRIME_HALF_LEN;

/// `HDCP_2_2_RX_REPEATER(rx_caps[2])`.
pub const fn rx_repeater(byte: u8) -> bool {
    byte & 1 != 0
}
/// `HDCP_2_2_DP_HDCP_CAPABLE(rx_caps[2])`.
pub const fn dp_hdcp_capable(byte: u8) -> bool {
    byte & 2 != 0
}
/// `HDCP_2_2_HDCP1_DEVICE_CONNECTED(rx_info[1])`.
pub const fn hdcp1_device_connected(byte: u8) -> bool {
    byte & 1 != 0
}
/// `HDCP_2_2_HDCP_2_0_REP_CONNECTED(rx_info[1])`.
pub const fn hdcp_2_0_rep_connected(byte: u8) -> bool {
    byte & 2 != 0
}
/// `HDCP_2_2_MAX_CASCADE_EXCEEDED(rx_info[1])`.
pub const fn max_cascade_exceeded(byte: u8) -> bool {
    byte & 4 != 0
}
/// `HDCP_2_2_MAX_DEVS_EXCEEDED(rx_info[1])`.
pub const fn max_devs_exceeded(byte: u8) -> bool {
    byte & 8 != 0
}
/// `HDCP_2_2_DEV_COUNT_HI(rx_info[0]) << 4 | HDCP_2_2_DEV_COUNT_LO(rx_info[1])`.
pub const fn device_count(rx_info: [u8; 2]) -> u32 {
    ((rx_info[0] & 1) as u32) << 4 | ((rx_info[1] & 0xF0) >> 4) as u32
}
/// `drm_hdcp_be24_to_cpu`.
pub const fn be24_to_cpu(b: [u8; 3]) -> u32 {
    (b[2] as u32) | (b[1] as u32) << 8 | (b[0] as u32) << 16
}
/// `drm_hdcp_cpu_to_be24`.
pub const fn cpu_to_be24(v: u32) -> [u8; 3] {
    [(v >> 16) as u8, (v >> 8) as u8, v as u8]
}

// ── i915_hdcp_interface.h ────────────────────────────────────────────

/// `enum hdcp_port_type`.
pub const HDCP_PORT_TYPE_INTEGRATED: u8 = 1;
/// `enum hdcp_wired_protocol`.
pub const HDCP_PROTOCOL_HDMI: u8 = 1;
pub const HDCP_PROTOCOL_DP: u8 = 2;
/// `HDCP_DDI_INVALID_PORT`: what Gen12+ puts in `physical_port`.
pub const HDCP_DDI_INVALID_PORT: u8 = 0;
/// `HDCP_INVALID_TRANSCODER`.
pub const HDCP_INVALID_TRANSCODER: u8 = 0;

/// `intel_hdcp.c::intel_get_hdcp_transcoder`: transcoders A..D map to
/// `HDCP_TRANSCODER_A..D` (0x10..0x13); eDP and DSI are not HDCP
/// capable.
pub const fn hdcp_transcoder(cpu_transcoder: u8) -> u8 {
    if cpu_transcoder < 4 {
        cpu_transcoder | 0x10
    } else {
        HDCP_INVALID_TRANSCODER
    }
}

/// `struct hdcp_port_data`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HdcpPortData {
    pub hdcp_ddi: u8,
    pub hdcp_transcoder: u8,
    pub port_type: u8,
    pub protocol: u8,
    /// Streams on the port (1 for SST and HDMI).
    pub k: u16,
    /// RepeaterAuth_Stream_Manage messages sent with this seq_num_m.
    pub seq_num_m: u32,
    /// `struct hdcp2_streamid_type[k]`: (stream_id, stream_type).
    pub streams: [(u8, u8); MAX_CONTENT_STREAMS],
}

impl HdcpPortData {
    /// `intel_hdcp.c::initialize_hdcp_port_data` for a Gen12+ port: no
    /// DDI index, the transcoder filled in at enable, integrated port.
    pub const fn gen12(protocol: u8) -> Self {
        Self {
            hdcp_ddi: HDCP_DDI_INVALID_PORT,
            hdcp_transcoder: HDCP_INVALID_TRANSCODER,
            port_type: HDCP_PORT_TYPE_INTEGRATED,
            protocol,
            k: 0,
            seq_num_m: 0,
            streams: [(0, 0); MAX_CONTENT_STREAMS],
        }
    }

    /// `struct hdcp_port_id` as every command carries it.
    pub const fn port_id(&self) -> [u8; 4] {
        [self.port_type, self.hdcp_ddi, self.hdcp_transcoder, 0]
    }
}

/// `HDCP_API_VERSION`.
pub const HDCP_API_VERSION: u32 = 0x0001_0000;
/// `FW_HDCP_STATUS_SUCCESS`.
pub const FW_HDCP_STATUS_SUCCESS: u32 = 0;

/// `enum hdcp_command_id`, the wired Tx commands.
pub const WIRED_INITIATE_HDCP2_SESSION: u32 = 0x0003_1000;
pub const WIRED_VERIFY_RECEIVER_CERT: u32 = 0x0003_1001;
pub const WIRED_AKE_SEND_HPRIME: u32 = 0x0003_1002;
pub const WIRED_AKE_SEND_PAIRING_INFO: u32 = 0x0003_1003;
pub const WIRED_INIT_LOCALITY_CHECK: u32 = 0x0003_1004;
pub const WIRED_VALIDATE_LOCALITY: u32 = 0x0003_1005;
pub const WIRED_GET_SESSION_KEY: u32 = 0x0003_1006;
pub const WIRED_ENABLE_AUTH: u32 = 0x0003_1007;
pub const WIRED_VERIFY_REPEATER: u32 = 0x0003_1008;
pub const WIRED_REPEATER_AUTH_STREAM_REQ: u32 = 0x0003_1009;
pub const WIRED_CLOSE_SESSION: u32 = 0x0003_100A;

/// `sizeof(struct hdcp_cmd_header)`.
pub const CMD_HEADER_LEN: usize = 16;
/// Header plus `struct hdcp_port_id`.
const CMD_PORT_END: usize = CMD_HEADER_LEN + 4;

/// `WIRED_CMD_BUF_LEN_*_IN`: header.buffer_len of each command.
pub const BUF_LEN_INITIATE_HDCP2_SESSION_IN: u32 = 4 + 1;
pub const BUF_LEN_VERIFY_RECEIVER_CERT_IN: u32 = 4 + 522 + 8 + 3;
pub const BUF_LEN_AKE_SEND_HPRIME_IN: u32 = 4 + 32;
pub const BUF_LEN_SEND_PAIRING_INFO_IN: u32 = 4 + 16;
pub const BUF_LEN_CLOSE_SESSION_IN: u32 = 4;
pub const BUF_LEN_INIT_LOCALITY_CHECK_IN: u32 = 4;
pub const BUF_LEN_VALIDATE_LOCALITY_IN: u32 = 4 + 32;
pub const BUF_LEN_GET_SESSION_KEY_IN: u32 = 4;
pub const BUF_LEN_ENABLE_AUTH_IN: u32 = 4 + 1;
pub const BUF_LEN_VERIFY_REPEATER_IN: u32 = 4 + 2 + 3 + 16 + 155;

/// `sizeof(struct wired_cmd_*_out)` of each reply.
pub const INITIATE_SESSION_OUT: usize = CMD_PORT_END + RTX_LEN + TXCAPS_LEN;
pub const VERIFY_RECEIVER_CERT_OUT: usize = CMD_PORT_END + 1 + 3 + E_KPUB_KM_LEN;
pub const STATUS_ONLY_OUT: usize = CMD_PORT_END;
pub const INIT_LOCALITY_CHECK_OUT: usize = CMD_PORT_END + RN_LEN;
pub const GET_SESSION_KEY_OUT: usize = CMD_PORT_END + E_DKEY_KS_LEN + RIV_LEN;
pub const VERIFY_REPEATER_OUT: usize = CMD_PORT_END + 1 + V_PRIME_HALF_LEN;

/// A failed firmware command.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FwError {
    /// The transport failed with this negative errno
    /// (`mei_cldev_send`/`recv`, or the GSC submission).
    Transport(i32),
    /// The reply's `header.status` was not `FW_HDCP_STATUS_SUCCESS`
    /// (the ops return `-EIO`).
    Status(u32),
    /// The reply was shorter than its `wired_cmd_*_out`.
    Short,
    /// The arguments cannot form a command (`-EINVAL`), e.g. k > 4.
    Invalid,
}

impl FwError {
    /// The errno the Linux op returns.
    pub const fn errno(self) -> i32 {
        match self {
            Self::Transport(e) => e,
            Self::Status(_) | Self::Short => -(narf_lib::errno::EIO as i32),
            Self::Invalid => -(narf_lib::errno::EINVAL as i32),
        }
    }
}

/// A boxed, sendable future.
pub type HdcpFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// One command and its reply to the HDCP firmware client: the arbiter's
/// `hdcp_dev` (MEI) or the GSC HECI client `HECI_MEADDRESS_HDCP`.
pub trait HdcpTransport: Send {
    /// Send `command`, receive its reply into `reply`; returns the reply
    /// length or a negative errno.
    fn exchange<'a>(
        &'a mut self,
        command: &'a [u8],
        reply: &'a mut [u8],
    ) -> HdcpFuture<'a, Result<usize, i32>>;
}

fn command(id: u32, buffer_len: u32, data: &HdcpPortData, payload: usize) -> Vec<u8> {
    let mut c = vec![0u8; CMD_PORT_END + payload];
    c[0..4].copy_from_slice(&HDCP_API_VERSION.to_le_bytes());
    c[4..8].copy_from_slice(&id.to_le_bytes());
    c[8..12].copy_from_slice(&FW_HDCP_STATUS_SUCCESS.to_le_bytes());
    c[12..16].copy_from_slice(&buffer_len.to_le_bytes());
    c[16..20].copy_from_slice(&data.port_id());
    c
}

/// The command builders, one per `i915_hdcp_ops` member, laid out as the
/// `wired_cmd_*_in` structs.
pub mod wired {
    use super::*;

    /// `wired_cmd_initiate_hdcp2_session_in`.
    pub fn initiate_session(data: &HdcpPortData) -> Vec<u8> {
        let mut c = command(
            WIRED_INITIATE_HDCP2_SESSION,
            BUF_LEN_INITIATE_HDCP2_SESSION_IN,
            data,
            1,
        );
        c[CMD_PORT_END] = data.protocol;
        c
    }

    /// `wired_cmd_verify_receiver_cert_in` from AKE_Send_Cert: cert_rx,
    /// r_rx and rx_caps.
    pub fn verify_receiver_cert(data: &HdcpPortData, send_cert: &[u8]) -> Option<Vec<u8>> {
        if send_cert.len() < AKE_SEND_CERT_SIZE {
            return None;
        }
        let mut c = command(
            WIRED_VERIFY_RECEIVER_CERT,
            BUF_LEN_VERIFY_RECEIVER_CERT_IN,
            data,
            CERT_RX_LEN + RRX_LEN + RXCAPS_LEN,
        );
        c[CMD_PORT_END..].copy_from_slice(&send_cert[1..AKE_SEND_CERT_SIZE]);
        Some(c)
    }

    /// `wired_cmd_ake_send_hprime_in`.
    pub fn send_hprime(data: &HdcpPortData, h_prime: &[u8]) -> Option<Vec<u8>> {
        tail(
            WIRED_AKE_SEND_HPRIME,
            BUF_LEN_AKE_SEND_HPRIME_IN,
            data,
            h_prime,
            AKE_SEND_HPRIME_SIZE,
        )
    }

    /// `wired_cmd_ake_send_pairing_info_in`.
    pub fn send_pairing_info(data: &HdcpPortData, pairing: &[u8]) -> Option<Vec<u8>> {
        tail(
            WIRED_AKE_SEND_PAIRING_INFO,
            BUF_LEN_SEND_PAIRING_INFO_IN,
            data,
            pairing,
            AKE_SEND_PAIRING_INFO_SIZE,
        )
    }

    /// `wired_cmd_init_locality_check_in`.
    pub fn init_locality_check(data: &HdcpPortData) -> Vec<u8> {
        command(
            WIRED_INIT_LOCALITY_CHECK,
            BUF_LEN_INIT_LOCALITY_CHECK_IN,
            data,
            0,
        )
    }

    /// `wired_cmd_validate_locality_in`.
    pub fn validate_locality(data: &HdcpPortData, send_lprime: &[u8]) -> Option<Vec<u8>> {
        tail(
            WIRED_VALIDATE_LOCALITY,
            BUF_LEN_VALIDATE_LOCALITY_IN,
            data,
            send_lprime,
            LC_SEND_LPRIME_SIZE,
        )
    }

    /// `wired_cmd_get_session_key_in`.
    pub fn get_session_key(data: &HdcpPortData) -> Vec<u8> {
        command(WIRED_GET_SESSION_KEY, BUF_LEN_GET_SESSION_KEY_IN, data, 0)
    }

    /// `wired_cmd_verify_repeater_in`: rx_info, seq_num_v, v_prime and the
    /// whole receiver_ids array (`HDCP_2_2_RECEIVER_IDS_MAX_LEN`).
    pub fn verify_repeater(data: &HdcpPortData, recvid_list: &[u8]) -> Option<Vec<u8>> {
        if recvid_list.len() < REP_SEND_RECVID_LIST_SIZE {
            return None;
        }
        let mut c = command(
            WIRED_VERIFY_REPEATER,
            BUF_LEN_VERIFY_REPEATER_IN,
            data,
            REP_SEND_RECVID_LIST_SIZE - 1,
        );
        c[CMD_PORT_END..].copy_from_slice(&recvid_list[1..REP_SEND_RECVID_LIST_SIZE]);
        Some(c)
    }

    /// `wired_cmd_repeater_auth_stream_req_in` with `data.k` streams:
    /// seq_num_m (big-endian 24 bit), m_prime, k (big-endian 16 bit),
    /// streams; `buffer_len` is the command size less the header.
    pub fn repeater_auth_stream_req(data: &HdcpPortData, stream_ready: &[u8]) -> Option<Vec<u8>> {
        let k = usize::from(data.k);
        if stream_ready.len() < REP_STREAM_READY_SIZE || k > MAX_CONTENT_STREAMS {
            return None;
        }
        let payload = SEQ_NUM_LEN + MPRIME_LEN + 2 + 2 * k;
        let size = CMD_PORT_END + payload;
        let mut c = command(
            WIRED_REPEATER_AUTH_STREAM_REQ,
            (size - CMD_HEADER_LEN) as u32,
            data,
            payload,
        );
        let mut at = CMD_PORT_END;
        c[at..at + SEQ_NUM_LEN].copy_from_slice(&cpu_to_be24(data.seq_num_m));
        at += SEQ_NUM_LEN;
        c[at..at + MPRIME_LEN].copy_from_slice(&stream_ready[1..REP_STREAM_READY_SIZE]);
        at += MPRIME_LEN;
        c[at..at + 2].copy_from_slice(&data.k.to_be_bytes());
        at += 2;
        for (id, ty) in &data.streams[..k] {
            c[at] = *id;
            c[at + 1] = *ty;
            at += 2;
        }
        Some(c)
    }

    /// `wired_cmd_enable_auth_in`: the first stream's type.
    pub fn enable_auth(data: &HdcpPortData) -> Vec<u8> {
        let mut c = command(WIRED_ENABLE_AUTH, BUF_LEN_ENABLE_AUTH_IN, data, 1);
        c[CMD_PORT_END] = data.streams[0].1;
        c
    }

    /// `wired_cmd_close_session_in`.
    pub fn close_session(data: &HdcpPortData) -> Vec<u8> {
        command(WIRED_CLOSE_SESSION, BUF_LEN_CLOSE_SESSION_IN, data, 0)
    }

    fn tail(
        id: u32,
        buffer_len: u32,
        data: &HdcpPortData,
        msg: &[u8],
        size: usize,
    ) -> Option<Vec<u8>> {
        if msg.len() < size {
            return None;
        }
        let mut c = command(id, buffer_len, data, size - 1);
        c[CMD_PORT_END..].copy_from_slice(&msg[1..size]);
        Some(c)
    }
}

/// The reply's `header.status`, after its length check.
fn reply_ok(reply: &[u8], len: usize, expected: usize) -> Result<(), FwError> {
    if len < CMD_HEADER_LEN {
        return Err(FwError::Short);
    }
    let status = u32::from_le_bytes([reply[8], reply[9], reply[10], reply[11]]);
    if status != FW_HDCP_STATUS_SUCCESS {
        return Err(FwError::Status(status));
    }
    if len < expected {
        return Err(FwError::Short);
    }
    Ok(())
}

/// `struct i915_hdcp_ops` over a transport: each op sends its
/// `wired_cmd_*_in` and checks the reply as `mei_hdcp.c` and
/// `intel_hdcp_gsc_message.c` do (a non-success `header.status` fails
/// with `-EIO`), and builds the HDCP 2.2 message the transmitter sends
/// next.
#[derive(Debug)]
pub struct Fw<'t, T: HdcpTransport + ?Sized>(pub &'t mut T);

impl<T: HdcpTransport + ?Sized> Fw<'_, T> {
    async fn call(&mut self, command: &[u8], out: usize) -> Result<Vec<u8>, FwError> {
        let mut reply = vec![0u8; out];
        let len = self
            .0
            .exchange(command, &mut reply)
            .await
            .map_err(FwError::Transport)?;
        reply_ok(&reply, len, out)?;
        Ok(reply)
    }

    /// `initiate_hdcp2_session`: AKE_Init (msg_id, r_tx, tx_caps).
    pub async fn initiate_session(
        &mut self,
        data: &HdcpPortData,
    ) -> Result<[u8; AKE_INIT_SIZE], FwError> {
        let r = self
            .call(&wired::initiate_session(data), INITIATE_SESSION_OUT)
            .await?;
        let mut msg = [0u8; AKE_INIT_SIZE];
        msg[0] = AKE_INIT;
        msg[1..].copy_from_slice(&r[CMD_PORT_END..INITIATE_SESSION_OUT]);
        Ok(msg)
    }

    /// `verify_receiver_cert_prepare_km`: whether km is stored, and the
    /// AKE_Stored_Km or AKE_No_Stored_Km message to send (its size is the
    /// message's).
    pub async fn verify_receiver_cert(
        &mut self,
        data: &HdcpPortData,
        send_cert: &[u8],
    ) -> Result<(bool, Vec<u8>), FwError> {
        let command = wired::verify_receiver_cert(data, send_cert).ok_or(FwError::Invalid)?;
        let r = self.call(&command, VERIFY_RECEIVER_CERT_OUT).await?;
        let stored = r[CMD_PORT_END] != 0;
        let ekm = &r[CMD_PORT_END + 4..VERIFY_RECEIVER_CERT_OUT];
        let msg = if stored {
            let mut m = vec![AKE_STORED_KM];
            m.extend_from_slice(&ekm[..E_KH_KM_M_LEN]);
            m
        } else {
            let mut m = vec![AKE_NO_STORED_KM];
            m.extend_from_slice(ekm);
            m
        };
        Ok((stored, msg))
    }

    /// `verify_hprime`.
    pub async fn verify_hprime(&mut self, data: &HdcpPortData, msg: &[u8]) -> Result<(), FwError> {
        let command = wired::send_hprime(data, msg).ok_or(FwError::Invalid)?;
        self.call(&command, STATUS_ONLY_OUT).await.map(drop)
    }

    /// `store_pairing_info`.
    pub async fn store_pairing_info(
        &mut self,
        data: &HdcpPortData,
        msg: &[u8],
    ) -> Result<(), FwError> {
        let command = wired::send_pairing_info(data, msg).ok_or(FwError::Invalid)?;
        self.call(&command, STATUS_ONLY_OUT).await.map(drop)
    }

    /// `initiate_locality_check`: LC_Init (msg_id, r_n).
    pub async fn initiate_locality_check(
        &mut self,
        data: &HdcpPortData,
    ) -> Result<[u8; LC_INIT_SIZE], FwError> {
        let r = self
            .call(&wired::init_locality_check(data), INIT_LOCALITY_CHECK_OUT)
            .await?;
        let mut msg = [0u8; LC_INIT_SIZE];
        msg[0] = LC_INIT;
        msg[1..].copy_from_slice(&r[CMD_PORT_END..INIT_LOCALITY_CHECK_OUT]);
        Ok(msg)
    }

    /// `verify_lprime`.
    pub async fn verify_lprime(&mut self, data: &HdcpPortData, msg: &[u8]) -> Result<(), FwError> {
        let command = wired::validate_locality(data, msg).ok_or(FwError::Invalid)?;
        self.call(&command, STATUS_ONLY_OUT).await.map(drop)
    }

    /// `get_session_key`: SKE_Send_Eks (msg_id, e_dkey_ks, riv).
    pub async fn get_session_key(
        &mut self,
        data: &HdcpPortData,
    ) -> Result<[u8; SKE_SEND_EKS_SIZE], FwError> {
        let r = self
            .call(&wired::get_session_key(data), GET_SESSION_KEY_OUT)
            .await?;
        let mut msg = [0u8; SKE_SEND_EKS_SIZE];
        msg[0] = SKE_SEND_EKS;
        msg[1..].copy_from_slice(&r[CMD_PORT_END..GET_SESSION_KEY_OUT]);
        Ok(msg)
    }

    /// `repeater_check_flow_prepare_ack`: RepeaterAuth_Send_Ack (msg_id,
    /// V).
    pub async fn repeater_check_flow_prepare_ack(
        &mut self,
        data: &HdcpPortData,
        recvid_list: &[u8],
    ) -> Result<[u8; REP_SEND_ACK_SIZE], FwError> {
        let command = wired::verify_repeater(data, recvid_list).ok_or(FwError::Invalid)?;
        let r = self.call(&command, VERIFY_REPEATER_OUT).await?;
        let mut msg = [0u8; REP_SEND_ACK_SIZE];
        msg[0] = REP_SEND_ACK;
        msg[1..].copy_from_slice(&r[CMD_PORT_END + 1..VERIFY_REPEATER_OUT]);
        Ok(msg)
    }

    /// `verify_mprime`.
    pub async fn verify_mprime(&mut self, data: &HdcpPortData, msg: &[u8]) -> Result<(), FwError> {
        let command = wired::repeater_auth_stream_req(data, msg).ok_or(FwError::Invalid)?;
        self.call(&command, STATUS_ONLY_OUT).await.map(drop)
    }

    /// `enable_hdcp_authentication`.
    pub async fn enable_authentication(&mut self, data: &HdcpPortData) -> Result<(), FwError> {
        self.call(&wired::enable_auth(data), STATUS_ONLY_OUT)
            .await
            .map(drop)
    }

    /// `close_hdcp_session`.
    pub async fn close_session(&mut self, data: &HdcpPortData) -> Result<(), FwError> {
        self.call(&wired::close_session(data), STATUS_ONLY_OUT)
            .await
            .map(drop)
    }
}

// ── MEI transport ────────────────────────────────────────────────────

/// The MEI HDCP client (`narf_drivers_platform::mei_hdcp`) as a
/// transport: `mei_cldev_send` + `mei_cldev_recv` on the bound component.
#[derive(Debug)]
pub struct MeiTransport(pub narf_drivers::hdcp_component::HdcpBinding);

impl HdcpTransport for MeiTransport {
    fn exchange<'a>(
        &'a mut self,
        command: &'a [u8],
        reply: &'a mut [u8],
    ) -> HdcpFuture<'a, Result<usize, i32>> {
        Box::pin(core::future::ready(self.0.exchange(command, reply)))
    }
}

// ── GSC transport framing (xe_hdcp_gsc.c) ────────────────────────────

/// `HECI_MEADDRESS_HDCP`.
pub const HECI_MEADDRESS_HDCP: u8 = 18;
/// `sizeof(struct intel_gsc_mtl_header)`.
pub const GSC_HEADER: usize = 36;
/// `PAGE_SIZE`: each of the input and output halves.
pub const GSC_PAGE: usize = 4096;
/// `intel_hdcp_gsc_msg_send`: the GSC said pending; resubmit 50 ms later,
/// 20 submissions in all.
pub const GSC_PENDING_TRIES: u32 = 20;
pub const GSC_PENDING_RETRY_MS: u64 = 50;

/// `xe_gsc_emit_header` + the message, for `HECI_MEADDRESS_HDCP` with
/// `host_session_id` (bits 63:56 must be clear: the client goes there).
/// `-ENOSPC` when the command or its reply would not fit its page.
pub fn frame_gsc_command(
    command: &[u8],
    reply_len: usize,
    host_session_id: u64,
) -> Result<Vec<u8>, i32> {
    let max = GSC_PAGE - GSC_HEADER;
    if command.len() > max || reply_len > max {
        return Err(-(narf_lib::errno::ENOSPC as i32));
    }
    let mut packet = vec![0u8; GSC_HEADER + command.len()];
    crate::intel_gpu_gt::media::gsc::emit_header(
        &mut packet,
        HECI_MEADDRESS_HDCP,
        host_session_id,
        command.len() as u32,
    )
    .map_err(|_| -(narf_lib::errno::EINVAL as i32))?;
    packet[GSC_HEADER..].copy_from_slice(command);
    Ok(packet)
}

/// One `GSC_HECI_CMD_PKT` submission of a framed command, waiting for its
/// job: `xe_gsc_pkt_submit_kernel` (input, `input.len()`; output,
/// `output.len()`). The output holds the GSC header and the reply.
pub trait GscPacketPort: Send {
    fn submit<'a>(
        &'a mut self,
        input: &'a [u8],
        output: &'a mut [u8],
    ) -> HdcpFuture<'a, Result<(), i32>>;
    /// `intel_hdcp_gsc_check_status`: the media GT runs, its GSC firmware
    /// is loaded and `xe_gsc_proxy_init_done`.
    fn ready(&mut self) -> bool;
    /// Wait `ms` before resubmitting a pending message (`msleep(50)`).
    fn delay_ms(&mut self, ms: u64) -> HdcpFuture<'_, ()>;
}

/// The GSC transport: `intel_hdcp_gsc_msg_send` over a [`GscPacketPort`],
/// with one host session id for the transport's life
/// (`xe_gsc_create_host_session_id` per message in xe; the GSC accepts
/// either).
#[derive(Debug)]
pub struct GscFraming<P> {
    pub port: P,
    pub host_session_id: u64,
}

impl<P: GscPacketPort> GscFraming<P> {
    /// `xe_gsc_create_host_session_id`: random, bits 56-63 masked.
    pub fn new(port: P, random: u64) -> Self {
        Self {
            port,
            host_session_id: random & !(0xFFu64 << 56),
        }
    }

    async fn send(&mut self, command: &[u8], reply: &mut [u8]) -> Result<usize, i32> {
        let mut input = frame_gsc_command(command, reply.len(), self.host_session_id)?;
        let mut output = vec![0u8; GSC_HEADER + reply.len()];
        let mut tries = 0;
        loop {
            output.fill(0);
            self.port.submit(&input, &mut output).await?;
            // xe_gsc_check_and_update_pending: -EAGAIN, the handle goes
            // back into the next submission's header.
            if crate::intel_gpu_gt::media::gsc::check_and_update_pending(&mut input, &output) {
                tries += 1;
                if tries >= GSC_PENDING_TRIES {
                    return Err(-(narf_lib::errno::EAGAIN as i32));
                }
                self.port.delay_ms(GSC_PENDING_RETRY_MS).await;
                continue;
            }
            break;
        }
        // xe_gsc_read_out_header(.., sizeof(struct hdcp_cmd_header)).
        crate::intel_gpu_gt::media::gsc::read_out_header(&output, CMD_HEADER_LEN as u32)
            .map_err(|_| -(narf_lib::errno::EPROTO as i32))?;
        reply.copy_from_slice(&output[GSC_HEADER..]);
        Ok(reply.len())
    }
}

impl<P: GscPacketPort> HdcpTransport for GscFraming<P> {
    fn exchange<'a>(
        &'a mut self,
        command: &'a [u8],
        reply: &'a mut [u8],
    ) -> HdcpFuture<'a, Result<usize, i32>> {
        Box::pin(self.send(command, reply))
    }
}
