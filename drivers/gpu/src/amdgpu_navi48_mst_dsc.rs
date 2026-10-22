//! DSC on DP MST, as DRM and amdgpu_dm decide and enable it:
//!
//! - `dsc_aux_for_port` is drm_dp_mst_dsc_aux_for_port: where an end
//!   device's DSC decoder is reached (its own DPCD through its branch, a
//!   DP-to-DP or DP-to-HDMI peer's virtual DPCD, or a Synaptics/Realtek hub
//!   without virtual DPCD), and the passthrough port for an end device that
//!   decodes behind a virtual-DPCD peer;
//! - `read_dsc` is validate_dsc_caps_on_connector (dc_dsc_parse_dsc_dpcd on
//!   the decoder's 0x060 and 0x0A0 caps), with dp_get_link_current_set_bw's
//!   last-link bandwidth and the immediate upstream branch's OUI that
//!   dm_dp_mst_is_port_support_mode reads;
//! - `port_supports_mode` is dm_dp_mst_is_port_support_mode;
//! - `compute` is compute_mst_dsc_configs_for_link (`crate::amdgpu_mst_dsc`)
//!   for streams the display pipeline can run compressed;
//! - `set_rx` is dm_helpers_dp_write_dsc_enable for an MST stream.
//!
//! Synaptics AUX routing and shared non-virtual decoder/FIFO ownership follow
//! amdgpu_dm_mst_types.c and amdgpu_dm_helpers.c. DP-to-HDMI PCON FRL DSC
//! (build_frl_mst_dsc_params) is a separate downstream-link policy.
use super::*;
use crate::amdgpu_dsc::{self, DscConfig, DscSinkCaps};
pub use crate::amdgpu_mst_dsc::*;
use dp_mst_mgr::Sink;
#[path = "amdgpu_navi48_mst_pcon.rs"]
pub mod pcon;

/// DP_DSC_SUPPORT, DP_FEC_CAPABILITY, DP_DSC_ENABLE, DP_LINK_BW_SET,
/// DP_BRANCH_OUI and DP_DSC_BRANCH_OVERALL_THROUGHPUT_0.
const DSC_SUPPORT: u32 = 0x60;
const FEC_CAPABILITY: u32 = 0x90;
const DSC_ENABLE: u32 = 0x160;
const LINK_BW_SET: u32 = 0x100;
const BRANCH_OUI: u32 = 0x500;
const DSC_BRANCH_CAPS: u32 = 0xa0;
/// DP_DSC_DECOMPRESSION_IS_SUPPORTED, DP_DSC_PASSTHROUGH_IS_SUPPORTED.
const DECOMPRESSION: u8 = 1;
const PASSTHROUGH: u8 = 2;
/// The Synaptics branch OUI (DP_BRANCH_DEVICE_ID_90CC24).
pub const OUI_SYNAPTICS: u32 = 0x90cc24;

/// A DPCD an MST end device's DSC is reached through: an output port's own
/// (drm_dp_mst_port's `aux`, remote DPCD through its branch) or the
/// root's (the manager's `aux`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DscAux {
    Port(Sink),
    Root,
}

/// An MST endpoint's decoder and downstream converter admission state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MstDsc {
    /// Decoder caps; None retains a raw-only HDMI converter's limits.
    pub caps: Option<DscSinkCaps>,
    /// Where DP_DSC_ENABLE goes (aconnector->dsc_aux).
    pub aux: DscAux,
    /// The virtual-DPCD peer told to pass the stream through
    /// (port->passthrough_aux), when the end device decodes it.
    pub passthrough: Option<Sink>,
    /// dp_get_link_current_set_bw of the end device's DPCD: the last link's
    /// bandwidth (0 unread or for a legacy converter).
    pub end_link_kbps: u32,
    /// The immediate upstream branch's OUI (retrieve_branch_specific_data).
    pub branch_oui: u32,
    /// Root Synaptics non-virtual decoder policy, retained with the route.
    /// `Some(true)` additionally needs the first-stream SYNA FIFO reset.
    pub synaptics: Option<bool>,
    /// Retained even for a raw-only HDMI converter with no DSC decoder.
    pub pcon: Option<pcon::Pcon>,
}

async fn read<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    at: DscAux,
    address: u32,
    len: u8,
) -> Result<Vec<u8>, MstError<A::Error>> {
    match at {
        DscAux::Port(port) => {
            manager
                .remote_dpcd_read(aux, topology, port, address, len)
                .await
        }
        DscAux::Root => {
            let mut buf = alloc::vec![0; usize::from(len)];
            aux.read(address, &mut buf).await.map_err(MstError::Aux)?;
            Ok(buf)
        }
    }
}

/// drm_dp_mst_is_virtual_dpcd.
pub fn is_virtual_dpcd(topology: &Topology, port: Sink) -> bool {
    let Some(p) = topology.port(port) else {
        return false;
    };
    let i = &p.info;
    if i.dpcd_revision < 0x14 {
        return false;
    }
    // drm_dp_mst_port_is_logical: a virtual DP sink.
    if i.port >= 8 {
        return true;
    }
    if i.peer_device_type == dp_mst::PEER_DP_LEGACY_CONV && !i.mcs && i.legacy_plug {
        return true;
    }
    // A DP-to-DP peer: a two-port branch with an SST sink output.
    i.peer_device_type == dp_mst::PEER_MST_BRANCHING
        && p.branch
            .and_then(|b| topology.branches.get(b))
            .is_some_and(|b| {
                b.ports.len() == 2
                    && b.ports
                        .iter()
                        .any(|q| q.info.peer_device_type == dp_mst::PEER_SST_SINK && !q.info.input)
            })
}

/// drm_dp_has_quirk(DP_DPCD_QUIRK_DSC_WITHOUT_VIRTUAL_DPCD) for a branch's
/// 0x500 identification: any Synaptics hub, Realtek's "Dp1.4".
fn dsc_without_virtual_dpcd(ident: &[u8]) -> bool {
    let oui = ident.get(..3);
    let device = ident.get(3..9);
    oui == Some(&[0x90, 0xcc, 0x24][..])
        || oui == Some(&[0x00, 0xe0, 0x4c][..]) && device == Some(&b"Dp1.4\0"[..])
}

/// drm_dp_read_dpcd_caps: the receiver caps, replaced by the extended caps
/// (0x2200) when present and not older.
async fn dpcd_caps<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    at: DscAux,
) -> Result<Vec<u8>, MstError<A::Error>> {
    let dpcd = read(manager, aux, topology, at, 0, 15).await?;
    if dpcd[0xe] & 0x80 == 0 {
        return Ok(dpcd);
    }
    let ext = read(manager, aux, topology, at, 0x2200, 15).await?;
    Ok(if dpcd[0] > ext[0] { dpcd } else { ext })
}

/// drm_dp_mst_dsc_aux_for_port for end device `port`: the DPCD its DSC
/// is enabled through, and a passthrough port. None when its route or the
/// device cannot carry DSC; a failed read is None, as in DRM.
async fn drm_dsc_aux_for_port<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    port: Sink,
) -> Option<(DscAux, Option<Sink>)> {
    let path = topology.path(port)?;
    let upstream = path.get(1).copied();
    // Each physical link between the output and the primary branch carries FEC.
    for &hop in &path[1..] {
        if !is_virtual_dpcd(topology, hop) && !topology.port(hop)?.fec {
            return None;
        }
    }
    let one = |r: Result<Vec<u8>, _>| r.ok().map(|b: Vec<u8>| b[0]);
    if let Some(up) = upstream.filter(|&u| is_virtual_dpcd(topology, u)) {
        // A DP-to-DP peer: the end device decodes behind a passthrough
        // peer, else the peer's virtual DPCD does.
        let dsc = one(read(manager, aux, topology, DscAux::Port(port), DSC_SUPPORT, 1).await)?;
        let fec = one(read(
            manager,
            aux,
            topology,
            DscAux::Port(port),
            FEC_CAPABILITY,
            1,
        )
        .await)?;
        let up_dsc = one(read(manager, aux, topology, DscAux::Port(up), DSC_SUPPORT, 1).await)?;
        if dsc & DECOMPRESSION != 0 && fec & 1 != 0 && up_dsc & PASSTHROUGH != 0 {
            return Some((DscAux::Port(port), Some(up)));
        }
        return Some((DscAux::Port(up), None));
    }
    // A DP-to-HDMI converter or virtual DP sink decodes in its own DPCD.
    if is_virtual_dpcd(topology, port) {
        return Some((DscAux::Port(port), None));
    }
    let up_aux = upstream.map_or(DscAux::Root, DscAux::Port);
    let ident = read(manager, aux, topology, up_aux, BRANCH_OUI, 12)
        .await
        .ok()?;
    if dsc_without_virtual_dpcd(&ident) {
        let up_dsc = one(read(manager, aux, topology, up_aux, DSC_SUPPORT, 1).await)?;
        if up_dsc & DECOMPRESSION == 0 {
            return None;
        }
        let dpcd = dpcd_caps(manager, aux, topology, up_aux).await.ok()?;
        // DPCD 1.4 with a downstream port that is not VGA.
        if dpcd[0] >= 0x14 && dpcd[5] & 1 != 0 && dpcd[5] & 6 != 2 {
            return Some((up_aux, None));
        }
    }
    // The MST sink itself decodes, with FEC.
    let dsc = one(read(manager, aux, topology, DscAux::Port(port), DSC_SUPPORT, 1).await)?;
    let fec = one(read(
        manager,
        aux,
        topology,
        DscAux::Port(port),
        FEC_CAPABILITY,
        1,
    )
    .await)?;
    (dsc & DECOMPRESSION != 0 && fec & 1 != 0).then_some((DscAux::Port(port), None))
}

/// amdgpu_dm needs_dsc_aux_workaround: only these exact root revisions.
pub fn needs_dsc_aux_workaround(oui: u32, revision: u8, sink_count: u8) -> bool {
    oui == OUI_SYNAPTICS && matches!(revision, 0x12 | 0x14) && sink_count & 0x3f >= 2
}
#[derive(Default)]
struct RootDsc {
    workaround: bool,
    cascaded: bool,
    reset_fifo: bool,
}
async fn root_dsc<A: MstAux>(aux: &mut A) -> RootDsc {
    let mut ident = [0; 12];
    if aux.read(BRANCH_OUI, &mut ident).await.is_err() || ident[..3] != [0x90, 0xcc, 0x24] {
        return RootDsc::default();
    }
    let mut revision = [0];
    let mut sink_count = [0];
    let workaround = aux.read(0, &mut revision).await.is_ok()
        && aux.read(0x200, &mut sink_count).await.is_ok()
        && needs_dsc_aux_workaround(OUI_SYNAPTICS, revision[0], sink_count[0]);
    let mut vendor = [0; 4];
    let cascaded =
        ident[7] & 0xf0 == 0x50 && aux.read(0x50c, &mut vendor).await.is_ok() && vendor[2] == 0x5a;
    RootDsc {
        workaround,
        cascaded,
        reset_fifo: &ident[3..7] == b"SYNA",
    }
}
async fn select_dsc_aux<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    port: Sink,
    root: &RootDsc,
) -> Option<(DscAux, Option<Sink>)> {
    // Validate the route even when a root quirk overrides DRM's answer.
    let path = topology.path(port)?;
    let mut selected = drm_dsc_aux_for_port(manager, aux, topology, port).await;
    if selected.is_none() && path.len() == 1 && root.workaround {
        selected = Some((DscAux::Root, None));
    }
    // Cascaded Panamera overrides even a successful end-device route.
    if root.cascaded {
        selected = Some((DscAux::Root, None));
    }
    selected
}
/// DRM DSC routing plus amdgpu's immediate-child fallback and cascaded
/// Panamera root-AUX override. Missing identification grants no workaround.
#[cfg(feature = "kernel-test")]
pub async fn dsc_aux_for_port<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    port: Sink,
) -> Option<(DscAux, Option<Sink>)> {
    let root = root_dsc(aux).await;
    select_dsc_aux(manager, aux, topology, port, &root).await
}

/// dp_get_link_current_set_bw: the trained link of a DPCD's
/// DP_LINK_BW_SET/LANE_COUNT_SET/MAIN_LINK_CHANNEL_CODING_SET, in kbps.
pub fn link_set_kbps(set: &[u8]) -> Option<u32> {
    let (bw, lanes, coding) = (*set.first()?, u32::from(*set.get(1)? & 0x1f), *set.get(8)?);
    let (per_lane, efficiency) = match coding {
        // 8b/10b at FEC's efficiency.
        1 => (u32::from(bw) * 27_000 * 10, 8000 / 100 * 97),
        2 => (
            match bw {
                0x01 => 1000,
                0x04 => 1350,
                0x02 => 2000,
                _ => return None,
            } * 10_000,
            9641,
        ),
        _ => return None,
    };
    Some(per_lane * lanes / 10_000 * efficiency)
}

/// validate_dsc_caps_on_connector for end device `port`, and what
/// dm_dp_mst_is_port_support_mode reads beside it. None without a
/// decoder or with caps Linux rejects.
#[cfg(feature = "kernel-test")]
pub async fn read_dsc<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    port: Sink,
) -> Option<MstDsc> {
    read_endpoint(manager, aux, topology, port, &[]).await
}
/// Test compatibility view; production discovery uses the checked owner path.
#[cfg(feature = "kernel-test")]
pub async fn read_endpoint<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    port: Sink,
    edid: &[u8],
) -> Option<MstDsc> {
    read_endpoint_checked(manager, aux, topology, port, edid)
        .await
        .ok()
        .flatten()
}
/// Propagate uncertain PCON reads so discovery retains its AUX journal.
pub async fn read_endpoint_checked<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    port: Sink,
    edid: &[u8],
) -> Result<Option<MstDsc>, MstError<A::Error>> {
    let root = root_dsc(aux).await;
    let Some((at, passthrough)) = select_dsc_aux(manager, aux, topology, port, &root).await else {
        return Ok(None);
    };
    let synaptics = if root.workaround {
        let downstream = read(manager, aux, topology, at, 5, 1).await?;
        (downstream[0] & 7 != 3).then_some(root.reset_fifo)
    } else {
        None
    };
    let basic = match read(manager, aux, topology, at, DSC_SUPPORT, 16).await {
        Ok(v) => v,
        Err(MstError::Nak(_)) => alloc::vec![0; 16],
        Err(e) => return Err(e),
    };
    let branch = match read(manager, aux, topology, at, DSC_BRANCH_CAPS, 3).await {
        Ok(v) => v,
        Err(MstError::Nak(_)) => alloc::vec![0; 3],
        Err(e) => return Err(e),
    };
    let pcon = if at == DscAux::Port(port) && is_virtual_dpcd(topology, port) {
        pcon::probe(manager, aux, topology, at, edid, basic[0]).await?
    } else {
        None
    };
    let caps = if let Some(p) = pcon.filter(|p| p.passthrough) {
        p.hdmi.dsc.as_ref().map(DscSinkCaps::from_hdmi)
    } else {
        DscSinkCaps::parse(
            basic
                .as_slice()
                .try_into()
                .map_err(|_| MstError::Malformed)?,
            branch
                .as_slice()
                .try_into()
                .map_err(|_| MstError::Malformed)?,
        )
    };
    if caps.is_none() && pcon.is_none() {
        return Ok(None);
    }
    let info = topology.port(port).ok_or(MstError::Malformed)?.info;
    let end_link_kbps = if info.peer_device_type == dp_mst::PEER_DP_LEGACY_CONV {
        0
    } else {
        read(manager, aux, topology, DscAux::Port(port), LINK_BW_SET, 16)
            .await
            .ok()
            .and_then(|set| link_set_kbps(&set))
            .unwrap_or(0)
    };
    let upstream = topology
        .path(port)
        .ok_or(MstError::Malformed)?
        .get(1)
        .copied();
    let up_aux = upstream.map_or(DscAux::Root, DscAux::Port);
    let branch_oui = read(manager, aux, topology, up_aux, BRANCH_OUI, 3)
        .await
        .map_or(0, |o| {
            u32::from(o[0]) << 16 | u32::from(o[1]) << 8 | u32::from(o[2])
        });
    Ok(Some(MstDsc {
        caps,
        aux: at,
        passthrough,
        end_link_kbps,
        branch_oui,
        synaptics: synaptics.filter(|_| pcon.is_none()),
        pcon,
    }))
}

/// dm_helpers_dp_write_dsc_enable for an MST stream: on enable the
/// passthrough peer (DP_DSC_ENABLE 2) before the decoder (1); on disable
/// the decoder (0) before the peer.
pub async fn set_rx<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    dsc: &MstDsc,
    enable: bool,
    link_active: bool,
) -> Result<(), MstError<A::Error>> {
    if let Some(reset_fifo) = dsc.synaptics {
        if enable {
            if !link_active && reset_fifo {
                synaptics_fifo_reset(manager, aux, topology, dsc.aux).await?;
            }
            return write_enable(manager, aux, topology, dsc.aux, 1).await;
        }
        // Shared non-virtual decoder must stay enabled for every sibling.
        return if link_active {
            Ok(())
        } else {
            write_enable(manager, aux, topology, dsc.aux, 0).await
        };
    }
    if enable {
        if let Some(peer) = dsc.passthrough {
            write_enable(manager, aux, topology, DscAux::Port(peer), 2).await?;
        }
        write_enable(
            manager,
            aux,
            topology,
            dsc.aux,
            if dsc.pcon.is_some_and(|p| p.passthrough) {
                2
            } else {
                1
            },
        )
        .await
    } else {
        let decoder = write_enable(manager, aux, topology, dsc.aux, 0).await;
        if let Some(peer) = dsc.passthrough {
            write_enable(manager, aux, topology, DscAux::Port(peer), 0).await?;
        }
        decoder
    }
}

/// The decoder reports DP_DSC_ENABLE's decompression bit.
pub async fn rx_enabled<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    dsc: &MstDsc,
) -> Result<bool, MstError<A::Error>> {
    let bit = if dsc.pcon.is_some_and(|p| p.passthrough) {
        2
    } else {
        1
    };
    Ok(read(manager, aux, topology, dsc.aux, DSC_ENABLE, 1).await?[0] & bit == bit)
}

/// DP_DSC_ENABLE through `at`.
async fn write_enable<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    at: DscAux,
    value: u8,
) -> Result<(), MstError<A::Error>> {
    write(manager, aux, topology, at, DSC_ENABLE, &[value]).await
}
async fn write<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    at: DscAux,
    address: u32,
    data: &[u8],
) -> Result<(), MstError<A::Error>> {
    match at {
        DscAux::Port(port) => {
            manager
                .remote_dpcd_write(aux, topology, port, address, data)
                .await
        }
        DscAux::Root => aux.write(address, data).await.map_err(MstError::Aux),
    }
}
/// amdgpu_dm_helpers execute_synaptics_rc_command. The whole sequence is
/// serialized by its retained MstLink operation marker; cancellation must
/// never be treated as a completed vendor transaction.
#[allow(clippy::too_many_arguments)]
async fn synaptics_command<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    at: DscAux,
    command: u8,
    offset: u32,
    data: &mut [u8],
    is_write: bool,
) -> Result<(), MstError<A::Error>> {
    if data.len() > 16 {
        return Err(MstError::Malformed);
    }
    if is_write {
        let mut padded = [0; 16];
        padded[..data.len()].copy_from_slice(data);
        write(manager, aux, topology, at, 0x4c0, &padded).await?;
    }
    write(manager, aux, topology, at, 0x4bc, &offset.to_le_bytes()).await?;
    write(
        manager,
        aux,
        topology,
        at,
        0x4b8,
        &(data.len() as u16).to_le_bytes(),
    )
    .await?;
    write(manager, aux, topology, at, 0x4b2, &[command | 0x80]).await?;
    let mut complete = false;
    for _ in 0..10 {
        if read(manager, aux, topology, at, 0x4b2, 1).await?[0] == command {
            complete = true;
            break;
        }
        aux.delay(10_000).await;
    }
    // A stale success result is not proof that an active command ended.
    if !complete {
        return Err(MstError::Timeout);
    }
    if read(manager, aux, topology, at, 0x4b3, 1).await?[0] != 0 {
        return Err(MstError::Malformed);
    }
    if !is_write {
        data.copy_from_slice(&read(manager, aux, topology, at, 0x4c0, data.len() as u8).await?);
    }
    Ok(())
}
/// GPU reset does not reset a remote RC controller. Before a successor
/// starts PRIUS, require the command observed on entry to become exactly
/// its inactive command byte, as the Linux RC command poll does. Another
/// command appearing during that wait is not our completion witness.
async fn synaptics_idle<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    at: DscAux,
) -> Result<(), MstError<A::Error>> {
    let mut status = read(manager, aux, topology, at, 0x4b2, 1).await?[0];
    let command = status & 0x7f;
    for attempt in 0..10 {
        if status == command {
            return Ok(());
        }
        if status & 0x7f != command {
            return Err(MstError::Malformed);
        }
        aux.delay(10_000).await;
        if attempt != 9 {
            status = read(manager, aux, topology, at, 0x4b2, 1).await?[0];
        }
    }
    Err(MstError::Timeout)
}
async fn synaptics_fifo_reset<A: MstAux>(
    manager: &mut Manager,
    aux: &mut A,
    topology: &Topology,
    at: DscAux,
) -> Result<(), MstError<A::Error>> {
    synaptics_idle(manager, aux, topology, at).await?;
    let mut unlock = *b"PRIUS";
    synaptics_command(manager, aux, topology, at, 1, 0, &mut unlock, true).await?;
    let mut data = [0; 4];
    for offset in [0x220998, 0x220d98, 0x221198] {
        synaptics_command(manager, aux, topology, at, 0x31, offset, &mut data, false).await?;
        data[0] &= !2;
        synaptics_command(manager, aux, topology, at, 0x21, offset, &mut data, true).await?;
    }
    for offset in [0x220998, 0x220d98, 0x221198] {
        synaptics_command(manager, aux, topology, at, 0x31, offset, &mut data, false).await?;
        data[0] |= 2;
        // Preserve Linux's exact sequence: the middle register is read
        // here, but only the first and last receive the restore write.
        if offset != 0x220d98 {
            synaptics_command(manager, aux, topology, at, 0x21, offset, &mut data, true).await?;
        }
    }
    synaptics_command(manager, aux, topology, at, 2, 0, &mut [], true).await
}

/// A provisional decoder configuration. Native shape is checked after
/// whole-link fairness and full-configuration admission choose Plan.pipes.
pub fn native_config(s: &DscStream, link: &DscLink) -> Option<DscConfig> {
    let cfg = config(s, link)?;
    Some(cfg)
}

/// `compute_link` with provisional decoder configurations; final native
/// shape and bandwidth acceptance belong to the complete configuration.
#[cfg(feature = "kernel-test")]
pub fn compute(streams: &[DscStream], link: &DscLink, fits: &Fits<'_>) -> Option<Vec<DscPayload>> {
    compute_link(streams, link, fits, &|s| native_config(s, link))
}

/// A compressed alternative inside an already reserved DP payload. The
/// converter's own bpp/rate contract applies before native plane admission.
pub fn config_in_payload(
    t: &Timing,
    bpc: u8,
    decoder: &MstDsc,
    link: &DscLink,
    pbn: u16,
) -> Option<DscConfig> {
    let caps = decoder.caps?;
    if let Some(pcon) = decoder.pcon {
        let stream = DscStream {
            sink: Sink { branch: 0, port: 0 },
            timing: *t,
            dsc: Some(caps),
            bpc,
        };
        let (constraint, cfg) = pcon.profile(&stream, link);
        let range = constraint.dsc_range?;
        let mut cfg = cfg?;
        let dt = mst_dsc_timing(t, bpc);
        let step = (16 / caps.bpp_increment_div.max(1)).max(1);
        cfg.bpp_x16 = (range.min_bpp_x16..=range.max_bpp_x16).rev().find(|&bpp| {
            bpp % step == 0
                && peak_pbn(amdgpu_dsc::dsc_kbps(&dt, bpp, cfg.slices_h), link.encoding)
                    <= i32::from(pbn)
                && pcon.allows(
                    t,
                    bpc,
                    Some(&DscConfig {
                        bpp_x16: bpp,
                        ..cfg
                    }),
                )
        })?;
        Some(cfg)
    } else {
        amdgpu_dsc::compute_config(
            &caps,
            link.max_dispclk_khz,
            (u64::from(pbn) * 994 * 8 * 54 / 64) as u32,
            &mst_dsc_timing(t, bpc),
            link.encoding,
            false,
        )
    }
}

/// Fairness with each stream's owned converter output. Cached constraints
/// apply equally to joining, running, offered and final configurations.
pub fn compute_endpoints(
    streams: &[DscStream],
    link: &DscLink,
    fits: &Fits<'_>,
    endpoint: &dyn Fn(Sink) -> Option<MstDsc>,
) -> Option<Vec<DscPayload>> {
    let profiles: Vec<_> = streams
        .iter()
        .map(|s| {
            let pcon = endpoint(s.sink).and_then(|e| e.pcon);
            let (constraint, cfg) = match pcon {
                Some(p) => {
                    let (c, cfg) = p.profile(s, link);
                    (Some(c), cfg)
                }
                None => (None, native_config(s, link)),
            };
            (s.sink, pcon, constraint, cfg)
        })
        .collect();
    let find = |sink| profiles.iter().find(|p| p.0 == sink);
    let result = compute_link_constrained(
        streams,
        link,
        fits,
        &|s| find(s.sink).and_then(|p| p.3),
        &|s| find(s.sink).and_then(|p| p.2),
    )?;
    if streams.iter().zip(&result).any(|(s, r)| {
        find(s.sink)
            .and_then(|p| p.1)
            .is_some_and(|p| !p.allows(&s.timing, s.bpc, r.dsc.as_ref()))
    }) {
        return None;
    }
    Some(result)
}

/// dm_dp_mst_is_port_support_mode's "DSC unnecessary case": `t` in RGB at
/// `bpc` (dc_bandwidth_in_kbps_from_timing) within the end-to-end
/// bandwidth, the root link's and the port's `full_pbn`'s.
pub fn raw_supported(t: &Timing, bpc: u8, full_pbn: u16, link: &DscLink) -> bool {
    let stream = amdgpu_dsc::stream_kbps(&mst_dsc_timing(t, bpc), link.encoding);
    stream <= link.kbps.min(kbps_from_pbn(u32::from(full_pbn)))
}

/// dm_dp_mst_is_port_support_mode for `t` on end device `port` (RGB at
/// `bpc`, the stream's display_color_depth):
/// carried uncompressed within the end-to-end bandwidth (the root link and
/// the port's full PBN), or compressible within the path the compressed
/// stream crosses: the whole route for a passthrough decoder; otherwise the
/// last link must carry the stream raw (unless the hub is Synaptics) and
/// the link before it the compressed minimum, dc_dsc_compute_config must
/// find a configuration for the end-to-end bandwidth, and the branch's
/// throughput must hold the pixel rate.
pub fn port_supports_mode(
    t: &Timing,
    bpc: u8,
    topology: &Topology,
    port: Sink,
    dsc: Option<&MstDsc>,
    link: &DscLink,
) -> bool {
    let dt = mst_dsc_timing(t, bpc);
    let stream = amdgpu_dsc::stream_kbps(&dt, link.encoding);
    let Some(p) = topology.port(port) else {
        return false;
    };
    let end_to_end = link.kbps.min(kbps_from_pbn(u32::from(p.full_pbn)));
    let converter = dsc.and_then(|d| d.pcon);
    let raw_allowed = converter.is_none_or(|p| p.raw_allowed(t, bpc));
    if raw_allowed && raw_supported(t, bpc, p.full_pbn, link) {
        return true;
    }
    let Some(d) = dsc else {
        return false;
    };
    let Some(caps) = d.caps else {
        return false;
    };
    let (min, max) = amdgpu_dsc::policy_bpp_x16(&dt, link.encoding);
    let (constraint, config) = converter
        .map(|p| {
            p.profile(
                &DscStream {
                    sink: port,
                    timing: *t,
                    dsc: Some(caps),
                    bpc,
                },
                link,
            )
        })
        .map_or((None, None), |(c, cfg)| (Some(c), cfg));
    let Some(range) = constraint.and_then(|c| c.dsc_range).or_else(|| {
        constraint.is_none().then_some(()).and_then(|_| {
            amdgpu_dsc::bandwidth_range(&caps, link.max_dispclk_khz, min, max, &dt, link.encoding)
        })
    }) else {
        return false;
    };
    if d.passthrough.is_some() {
        if range.min_kbps > end_to_end {
            return false;
        }
    } else {
        let pdt = p.info.peer_device_type;
        if pdt != dp_mst::PEER_DP_LEGACY_CONV
            && pdt != 0
            && d.end_link_kbps > 0
            && stream > d.end_link_kbps
            && d.branch_oui != OUI_SYNAPTICS
        {
            return false;
        }
        let upstream = topology.path(port).and_then(|h| h.get(1).copied());
        let channel = match upstream.and_then(|u| topology.port(u)) {
            Some(u) => link.kbps.min(kbps_from_pbn(u32::from(u.full_pbn))),
            None => link.kbps,
        };
        if range.min_kbps > channel {
            return false;
        }
    }
    if (if converter.is_some() {
        config
    } else {
        amdgpu_dsc::compute_config(
            &caps,
            link.max_dispclk_khz,
            end_to_end,
            &dt,
            link.encoding,
            false,
        )
    })
    .is_none()
    {
        return false;
    }
    let branch_mps = caps.branch_throughput_0_mps;
    branch_mps == 0 || t.pixel_clock_khz <= branch_mps * 1000
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi48_mst_dsc_tests.rs"]
mod tests;
