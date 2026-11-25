//! HDCP over DP MST, behind `narf.intel.hdcp=1`: the stream side of
//! `intel_dp_mst_hdcp_shim` (`intel_dp_mst_toggle_hdcp_stream_select`,
//! `intel_dp_mst_hdcp_stream_encryption`,
//! `intel_dp_mst_hdcp2_stream_encryption`, `intel_dp_hdcp.c`) and Linux's
//! per-connector operations over one MST port (`intel_hdcp.c`).
//!
//! ## Linux's shape
//!
//! Every MST stream has its own connector (`struct intel_hdcp`: the value,
//! the encryption flags, the HDCP 2.2 session counters and
//! `stream_transcoder`), all over one port (`intel_digital_port.hdcp`:
//! `auth_status`, `num_streams`, `mst_type1_capable`, `port_data`). The
//! link authenticates on the master transcoder (`mst_master_transcoder`,
//! `hdcp->cpu_transcoder`); a stream is encrypted by
//! `TRANS_DDI_HDCP_SELECT` in its own transcoder's `TRANS_DDI_FUNC_CTL`,
//! confirmed by `HDCP_STATUS_STREAM_x_ENC` (HDCP 1.4) or
//! `TRANS_HDCP2_STREAM_STATUS` (HDCP 2.2). The first HDCP 2.2 connector
//! authenticates the port and manages every stream of the commit
//! (`intel_hdcp_required_content_stream`: RepeaterAuth_Stream_Manage with
//! k streams, all type 1 when the topology allows it, else all type 0);
//! later connectors find `auth_status` set and only select their stream.
//! A disable leaves the link encrypted while other streams are ENABLED
//! (`num_streams`), except for link recovery.
//!
//! ## NARF's shape
//!
//! The Intel card has one DRM connector for the whole route, so
//! [`MstHdcp`] runs those per-connector operations for every stream of the
//! route, in stream order, as one commit enabling (or disabling) all of
//! them would. The connector is ENABLED only when every stream is. Two
//! fail-closed deviations:
//! - a stream that fails takes the streams already enabled by the same
//!   request back down, and its own HDCP select off, so the connector is
//!   never partly protected;
//! - the streams after the first use only the first stream's HDCP version
//!   (Linux would try HDCP 1.4 part 1 on the master transcoder for a later
//!   connector whose HDCP 2.2 stream select failed, under a link that is
//!   HDCP 2.2 encrypted).
//!
//! The stream type cross-checks of `intel_dp_mst_hdcp2_stream_encryption`
//! (`HDCP2_AUTH_STREAM` before display 30, `STREAM_TYPE_STATUS` after) are
//! `drm_WARN_ON`s in Linux and are not made here.

extern crate alloc;

use alloc::vec::Vec;

use super::{
    trans_ddi_func_ctl, trans_hdcp_status, CpValue, Ctx, HdcpEnv, HdcpError, HdcpLink, HdcpShim,
    LineRekey, Protocol, Versions, ENCRYPT_STATUS_CHANGE_TIMEOUT_MS,
};
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_hdcp_msg::HdcpTransport;

/// `TRANS_DDI_HDCP_SELECT` in `TRANS_DDI_FUNC_CTL`.
pub const TRANS_DDI_HDCP_SELECT: u32 = 1 << 5;
/// `transcoder_to_stream_enc_status`: `HDCP_STATUS_STREAM_{A,B,C,D}_ENC`;
/// 0 for any other transcoder.
pub const fn hdcp_status_stream_enc(t: u8) -> u32 {
    match t {
        0..=3 => 1 << (31 - t as u32),
        _ => 0,
    }
}
/// `TRANS_HDCP2_STREAM_STATUS(trans)` (display 12+).
pub const fn trans_hdcp2_stream_status(t: u8) -> u64 {
    0x664c0 + t as u64 * 0x100
}
pub const STREAM_ENCRYPTION_STATUS: u32 = 1 << 31;
/// `STREAM_TYPE_STATUS_MASK`.
pub const STREAM_TYPE_STATUS: u32 = 1 << 30;
/// `TRANS_HDCP2_AUTH_STREAM(trans)`: the A block at 0x66F00, B 4 bytes on.
pub const fn trans_hdcp2_auth_stream(t: u8) -> u64 {
    0x66f00 + t as u64 * 4
}
/// `AUTH_STREAM_TYPE_MASK`.
pub const AUTH_STREAM_TYPE: u32 = 1 << 31;

// ── The stream side of intel_dp_mst_hdcp_shim ────────────────────────

impl HdcpLink {
    /// `intel_dp_mst_toggle_hdcp_stream_select`
    /// (`intel_ddi_toggle_hdcp_bits(..., TRANS_DDI_HDCP_SELECT)`) on the
    /// stream's own transcoder.
    fn toggle_stream_select<M, S, T, E>(&self, cx: &Ctx<'_, M, S, T, E>, stream: u8, enable: bool)
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        cx.rmw(
            trans_ddi_func_ctl(stream),
            TRANS_DDI_HDCP_SELECT,
            if enable { TRANS_DDI_HDCP_SELECT } else { 0 },
        );
    }

    /// `intel_dp_mst_hdcp_stream_encryption`: the stream select, then its
    /// `HDCP_STATUS_STREAM_x_ENC` bit in the stream transcoder's
    /// `HDCP_STATUS` within 50 ms.
    pub(super) fn mst_stream_encryption<M, S, T, E>(
        &self,
        cx: &mut Ctx<'_, M, S, T, E>,
        stream: u8,
        enable: bool,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        self.toggle_stream_select(cx, stream, enable);
        let bit = hdcp_status_stream_enc(stream);
        if bit == 0 {
            return Err(HdcpError::Unsupported);
        }
        cx.wait(
            trans_hdcp_status(stream),
            bit,
            if enable { bit } else { 0 },
            ENCRYPT_STATUS_CHANGE_TIMEOUT_MS,
        )
        .map(drop)
    }

    /// `intel_dp_mst_hdcp2_stream_encryption`: the stream select, then
    /// `STREAM_ENCRYPTION_STATUS` in `TRANS_HDCP2_STREAM_STATUS` within
    /// 50 ms.
    pub(super) fn mst_stream_2_2_encryption<M, S, T, E>(
        &self,
        cx: &mut Ctx<'_, M, S, T, E>,
        stream: u8,
        enable: bool,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        self.toggle_stream_select(cx, stream, enable);
        cx.wait(
            trans_hdcp2_stream_status(stream),
            STREAM_ENCRYPTION_STATUS,
            if enable { STREAM_ENCRYPTION_STATUS } else { 0 },
            ENCRYPT_STATUS_CHANGE_TIMEOUT_MS,
        )
        .map(drop)
    }
}

// ── The connectors over one port ─────────────────────────────────────

/// The connector half of `struct intel_hdcp` for one MST stream.
#[derive(Clone, Debug, Default)]
struct Conn {
    value: CpValue,
    content_type: u8,
    hdcp_encrypted: bool,
    hdcp2_encrypted: bool,
    is_paired: bool,
    is_repeater: bool,
    seq_num_v: u32,
    seq_num_m: u32,
}

impl Conn {
    /// Exchange this connector's state with the one `link` carries.
    fn swap(&mut self, link: &mut HdcpLink) {
        use core::mem::swap;
        swap(&mut self.value, &mut link.value);
        swap(&mut self.content_type, &mut link.content_type);
        swap(&mut self.hdcp_encrypted, &mut link.hdcp_encrypted);
        swap(&mut self.hdcp2_encrypted, &mut link.hdcp2_encrypted);
        swap(&mut self.is_paired, &mut link.is_paired);
        swap(&mut self.is_repeater, &mut link.is_repeater);
        swap(&mut self.seq_num_v, &mut link.seq_num_v);
        swap(&mut self.seq_num_m, &mut link.seq_num_m);
    }
}

/// One stream of the route: its transcoder and payload ID (the stream ID
/// of RepeaterAuth_Stream_Manage, `intel_conn_to_vcpi`).
#[derive(Clone, Debug)]
pub struct MstStream {
    pub transcoder: u8,
    pub vcpi: u8,
    conn: Conn,
}

impl MstStream {
    pub fn value(&self) -> CpValue {
        self.conn.value
    }
    pub fn hdcp2_encrypted(&self) -> bool {
        self.conn.hdcp2_encrypted
    }
    pub fn hdcp_encrypted(&self) -> bool {
        self.conn.hdcp_encrypted
    }
}

/// HDCP for every stream of one DP MST route: the port (and the master
/// transcoder's registers) in `link`, the connectors in `streams`.
#[derive(Clone, Debug)]
pub struct MstHdcp {
    pub link: HdcpLink,
    pub streams: Vec<MstStream>,
}

impl MstHdcp {
    /// `intel_hdcp_init` for the route's connectors: the link on
    /// `master` (the first stream's transcoder), the streams as
    /// (transcoder, VCPI) in their enable order.
    pub fn new(master: u8, streams: &[(u8, u8)], rekey: LineRekey, hdcp2: bool) -> Self {
        let mut link = HdcpLink::new(Protocol::Dp, master, rekey, hdcp2);
        link.mst_vcpis = streams.iter().map(|&(_, vcpi)| vcpi).collect();
        Self {
            link,
            streams: streams
                .iter()
                .map(|&(transcoder, vcpi)| MstStream {
                    transcoder,
                    vcpi,
                    conn: Conn::default(),
                })
                .collect(),
        }
    }

    /// The route's one connector: ENABLED when every stream is, UNDESIRED
    /// when none wants protection, else DESIRED.
    pub fn value(&self) -> CpValue {
        if !self.streams.is_empty() && self.streams.iter().all(|s| s.conn.value == CpValue::Enabled)
        {
            CpValue::Enabled
        } else if self
            .streams
            .iter()
            .any(|s| s.conn.value != CpValue::Undesired)
        {
            CpValue::Desired
        } else {
            CpValue::Undesired
        }
    }

    /// `intel_hdcp_update_pipe`'s type change: after the disable, every
    /// stream wants protection again (DESIRED).
    pub fn mark_desired(&mut self) {
        for s in &mut self.streams {
            if s.conn.value == CpValue::Undesired {
                s.conn.value = CpValue::Desired;
            }
        }
    }

    /// The content type the streams were enabled with.
    pub fn content_type(&self) -> u8 {
        self.streams.first().map_or(0, |s| s.conn.content_type)
    }

    /// The check interval of the version the first stream runs.
    pub fn check_period_ms(&self) -> u64 {
        if self.streams.first().is_some_and(|s| s.conn.hdcp2_encrypted) {
            super::HDCP2_CHECK_PERIOD_MS
        } else {
            super::HDCP_CHECK_PERIOD_MS
        }
    }

    fn enter(&mut self, i: usize) {
        self.streams[i].conn.swap(&mut self.link);
        self.link.stream_transcoder = Some(self.streams[i].transcoder);
    }

    fn leave(&mut self, i: usize) {
        self.link.stream_transcoder = None;
        self.streams[i].conn.swap(&mut self.link);
    }

    /// `intel_hdcp_disable` for stream `i`.
    async fn disable_stream<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
        i: usize,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        self.enter(i);
        let r = self.link.disable(cx).await;
        self.leave(i);
        r
    }

    /// `intel_hdcp_enable` for each stream not yet ENABLED, in stream
    /// order. On a failure the streams this call enabled go back down and
    /// the error is returned.
    pub async fn enable<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
        content_type: u8,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        if self.streams.is_empty() {
            return Err(HdcpError::NoRoute);
        }
        let mut enabled = Vec::new();
        for i in 0..self.streams.len() {
            if self.streams[i].conn.value == CpValue::Enabled {
                continue;
            }
            // The streams after the first run the first stream's version.
            let versions = match self.streams[..i]
                .iter()
                .find(|s| s.conn.value == CpValue::Enabled)
            {
                Some(s) if s.conn.hdcp2_encrypted => Versions::HDCP2,
                Some(_) => Versions::HDCP1,
                None => Versions::ANY,
            };
            self.enter(i);
            let r = self.link.enable_with(cx, content_type, versions).await;
            self.leave(i);
            match r {
                Ok(()) => enabled.push(i),
                Err(e) => {
                    // A select whose confirmation timed out stays set in
                    // Linux; here it goes off with the rest.
                    self.link
                        .toggle_stream_select(cx, self.streams[i].transcoder, false);
                    for &j in enabled.iter().rev() {
                        let _ = self.disable_stream(cx, j).await;
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// `intel_hdcp_disable` for every stream, last first: the link goes
    /// down with the last ENABLED stream.
    pub async fn disable<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        let mut ret = Ok(());
        for i in (0..self.streams.len()).rev() {
            let r = self.disable_stream(cx, i).await;
            if ret.is_ok() {
                ret = r;
            }
        }
        ret
    }

    /// `intel_hdcp_check_work` for every ENABLED stream. A failed link
    /// check on one stream recovers the link for all (its
    /// `_intel_hdcp2_disable(connector, true)`), so every stream then
    /// reports DESIRED.
    pub async fn check_link<M, S, T, E>(
        &mut self,
        cx: &mut Ctx<'_, M, S, T, E>,
    ) -> Result<(), HdcpError>
    where
        M: MmioWindow + Sync + ?Sized,
        S: HdcpShim,
        T: HdcpTransport + ?Sized,
        E: HdcpEnv,
    {
        let mut ret = Ok(());
        for i in 0..self.streams.len() {
            if self.streams[i].conn.value != CpValue::Enabled {
                continue;
            }
            self.enter(i);
            let r = self.link.check_link(cx).await;
            self.leave(i);
            if ret.is_ok() {
                ret = r;
            }
        }
        ret
    }

    /// [`HdcpLink::force_off`] for the route: every stream's select off,
    /// then the link's registers on the master transcoder. Returns `true`
    /// when the firmware session may still be open.
    pub fn force_off<M: MmioWindow + ?Sized>(&mut self, io: &M) -> bool {
        let mut session = false;
        for s in &mut self.streams {
            let t = s.transcoder;
            let f = io.read32(trans_ddi_func_ctl(t));
            io.write32(trans_ddi_func_ctl(t), f & !TRANS_DDI_HDCP_SELECT);
            session |= s.conn.hdcp2_encrypted;
            s.conn.hdcp_encrypted = false;
            s.conn.hdcp2_encrypted = false;
            if s.conn.value == CpValue::Enabled {
                s.conn.value = CpValue::Desired;
            }
        }
        session |= self.link.force_off(io);
        self.link.num_streams = 0;
        session
    }
}
