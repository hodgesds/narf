//! USB Attached SCSI (UAS / UASP) — detection + streams negotiation.
//!
//! Slice 1 of #833. This module identifies UAS interfaces in a
//! Configuration Descriptor blob and negotiates the bulk-stream count
//! the host controller and the device can both support. It does NOT
//! move SCSI commands: the Command/Status Information Units, the
//! tag↔stream-ID queueing, and the attach-cascade wiring are slice 2.
//! Until then the attach cascade stays BOT-only, so a UAS device keeps
//! working through its BOT alternate setting — just without queueing.
//!
//! ## References
//!
//! - "Universal Serial Bus Mass Storage Class — USB Attached SCSI
//!   Protocol (UASP)", USB-IF rev 1.0, and T10 "USB Attached SCSI"
//!   (INCITS 471 / ISO/IEC 14776-251): the interface triple
//!   (class 0x08, subclass 0x06, protocol 0x62), the four pipes, and
//!   the Pipe Usage descriptor that names them.
//! - Linux `drivers/usb/storage/uas.c` + `uas-detect.h` (upstream):
//!   `uas_is_interface` (the triple above), `uas_find_uas_alt_setting`
//!   (first UAS alternate setting of the interface wins),
//!   `uas_find_endpoints` (pipes are assigned by Pipe Usage
//!   descriptors, `pipe_id` 1..=4, never by endpoint number or
//!   descriptor order), `uas_configure_endpoints` (streams are
//!   allocated on the status + data-IN + data-OUT pipes only —
//!   `usb_alloc_streams(intf, eps + 1, 3, ...)` — the command pipe
//!   never carries a stream ID; the UAS tag *is* the stream ID,
//!   1-based, stream 0 reserved), and `MAX_CMNDS` (256) as the
//!   stream count UAS asks for. On a SuperSpeed device whose host
//!   controller cannot do streams, Linux declines UAS outright
//!   (`uas_use_uas_driver` returns 0 when `!hcd->can_do_streams`);
//!   [`prefer_uas`] mirrors that gate.
//! - USB 3.0 §4.4.6.4, §8.12.1.4 (bulk streams) and §9.6.7
//!   (SuperSpeed Endpoint Companion descriptor): `bmAttributes`
//!   bits 4:0 carry the stream count as a power of two
//!   (`usb_ss_max_streams`: 0 if the field is 0, else `1 << field`).
//!   Linux `Documentation/driver-api/usb/bulk-streams.rst`: stream
//!   ID 0 is reserved, usable IDs are 1..=N, and fewer than two
//!   streams must not be requested.
//! - xHCI 1.2 §5.3.6 Table 5-13 (HCCPARAMS1 `MaxPSASize`: the
//!   Primary Stream Array holds `2^(MaxPSASize+1)` entries; 0 means
//!   streams are not supported) and §6.2.3 Table 6-8 (Endpoint
//!   Context `MaxPStreams`, bits 14:10: 0 means no streams and the TR
//!   Dequeue Pointer references a Transfer Ring; 1..=15 means the
//!   Primary Stream Array holds `2^(MaxPStreams+1)` entries and the
//!   TR Dequeue Pointer must reference a Primary Stream Context
//!   Array).
//!
//! ## Deliberate deviations from Linux
//!
//! - Two endpoints claiming the same pipe ID, a pipe whose endpoint
//!   direction contradicts the UAS pipe table, or a non-bulk endpoint
//!   inside a UAS alternate setting are all rejected here
//!   ([`UasError::DuplicatePipe`], [`UasError::PipeDirectionMismatch`],
//!   [`UasError::NonBulkEndpoint`]). Linux's `uas_find_endpoints`
//!   last-wins a duplicate pipe ID, never checks direction, and never
//!   checks transfer type, so a lying device could make it build a
//!   nonsense pipe that only fails later, on the wire. Failing at
//!   detection is cheaper and the device falls back to BOT.
//! - [`find_uas_endpoints`] requires exactly the four pipes to be
//!   bound; it does not require the interface's `bNumEndpoints` to
//!   be 4, so an extra endpoint in the alternate setting is ignored
//!   rather than fatal. The four pipes are what the transport needs.

use crate::xhci::{cap, EndpointConfig, EndpointKind};

/// Interface class for USB Mass Storage (USB 2.0 §9.6.5;
/// Linux `USB_CLASS_MASS_STORAGE`).
pub const UAS_INTERFACE_CLASS: u8 = 0x08;
/// Interface subclass: SCSI transparent command set
/// (Linux `USB_SC_SCSI`).
pub const UAS_INTERFACE_SUBCLASS: u8 = 0x06;
/// Interface protocol: USB Attached SCSI (Linux `USB_PR_UAS`;
/// `lsusb` shows this as `bInterfaceProtocol 98`).
pub const UAS_INTERFACE_PROTOCOL: u8 = 0x62;

/// Pipe Usage descriptor type (Linux `USB_DT_PIPE_USAGE`,
/// "From the T10 UAS specification", `include/uapi/linux/usb/ch9.h`).
pub const USB_DT_PIPE_USAGE: u8 = 0x24;
/// SuperSpeed Endpoint Companion descriptor type (Linux
/// `USB_DT_SS_ENDPOINT_COMP`, `include/uapi/linux/usb/ch9.h`).
pub const USB_DT_SS_ENDPOINT_COMP: u8 = 0x30;

/// Pipe IDs (UASP pipe table; Linux `uas_configure_endpoints`
/// assigns `eps[0]`..`eps[3]` to these in order).
pub const UAS_PIPE_COMMAND: u8 = 1;
pub const UAS_PIPE_STATUS: u8 = 2;
pub const UAS_PIPE_DATA_IN: u8 = 3;
pub const UAS_PIPE_DATA_OUT: u8 = 4;

/// Stream count UAS asks the host controller for (Linux `MAX_CMNDS`:
/// 256 tags; `can_queue` is the negotiated depth minus the two
/// reserved tags).
pub const UAS_REQUESTED_STREAMS: u32 = 256;

/// True iff `(class, subclass, protocol)` is the UAS triple.
/// Mirrors Linux `uas_is_interface` in `uas-detect.h`.
pub const fn is_uas_interface(class: u8, subclass: u8, protocol: u8) -> bool {
    class == UAS_INTERFACE_CLASS
        && subclass == UAS_INTERFACE_SUBCLASS
        && protocol == UAS_INTERFACE_PROTOCOL
}

/// Detection failure. Every variant degrades to the same outcome the
/// tree already has: the device binds BOT (or is left unbound) — a
/// UAS detection failure must never take storage offline.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UasError {
    /// No `(0x08, 0x06, 0x62)` interface anywhere in the blob.
    NoUasInterface,
    /// A UAS alternate setting was found but not all four pipes
    /// (command / status / data-in / data-out) could be bound from
    /// its Pipe Usage descriptors.
    EndpointsMissing,
    /// An endpoint inside a UAS alternate setting is not bulk.
    NonBulkEndpoint,
    /// A pipe's endpoint direction contradicts the UAS pipe table
    /// (command and data-out must be OUT; status and data-in IN).
    PipeDirectionMismatch,
    /// Two endpoints claim the same pipe ID.
    DuplicatePipe,
    /// A SuperSpeed companion or Pipe Usage descriptor is too short
    /// to read the field it exists to carry.
    MalformedDescriptor,
}

/// A complete UAS alternate setting: the four bulk pipes, identified
/// by their Pipe Usage IDs (never by endpoint number or descriptor
/// order — Linux `uas_find_endpoints`), plus each pipe's stream
/// capacity from its SuperSpeed Endpoint Companion descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UasEndpointSet {
    /// `bInterfaceNumber` of the matched interface.
    pub interface: u8,
    /// `bAlternateSetting` of the matched setting. This is the value
    /// a bind must pass to SET_INTERFACE (USB 2.0 §9.4.10) — the
    /// BOT path never selects an alternate setting explicitly, so a
    /// UAS bind must not inherit its default.
    pub alt_setting: u8,
    /// Pipe 1: bulk OUT, carries Command IUs.
    pub command_out: EndpointConfig,
    /// Pipe 2: bulk IN, carries Sense / Response / Status IUs.
    pub status_in: EndpointConfig,
    /// Pipe 3: bulk IN, carries read data.
    pub data_in: EndpointConfig,
    /// Pipe 4: bulk OUT, carries write data.
    pub data_out: EndpointConfig,
    /// Maximum streams per pipe, pipe order
    /// `[command, status, data-in, data-out]`: `2^bmAttributes`
    /// from each endpoint's SuperSpeed companion (`usb_ss_max_streams`),
    /// 0 when the endpoint has no companion or reports no streams.
    /// The command pipe's entry is recorded but never negotiated:
    /// Linux allocates streams on the other three pipes only.
    pub max_streams: [u32; 4],
}

/// Device-side stream capacity from one SuperSpeed companion
/// `bmAttributes` byte. Mirrors Linux `usb_ss_max_streams`
/// (`include/uapi/linux/usb/ch9.h`): the low five bits are the
/// exponent; 0 means the endpoint does not support streams.
pub const fn device_max_streams(bm_attributes: u8) -> u32 {
    let field = bm_attributes & 0x1f;
    if field == 0 {
        0
    } else {
        1u32 << field
    }
}

/// Negotiated usable stream count: the most the host controller, the
/// device, and the request can all agree on, rounded down to a power
/// of two. Returns `None` when fewer than two streams survive — stream
/// ID 0 is reserved, so a single usable stream cannot carry a tag
/// (Linux bulk-streams: do not request fewer than two streams).
pub fn negotiate_stream_count(hc_max: u32, dev_max: u32, requested: u32) -> Option<u32> {
    let min = hc_max.min(dev_max).min(requested);
    if min < 2 {
        return None;
    }
    // Largest power of two <= min.
    Some(1u32 << (u32::BITS - 1 - min.leading_zeros()))
}

/// Endpoint Context `MaxPStreams` value for a negotiated stream count
/// (xHCI 1.2 §6.2.3 Table 6-8: the Primary Stream Array holds
/// `2^(MaxPStreams+1)` entries, so `MaxPStreams = log2(count) - 1`).
/// `None` unless `count` is a power of two in `2..=65536`
/// (`MaxPStreams` is only valid at 1..=15). The caller must pass a
/// count already clamped to the host controller's `MaxPSASize`, so
/// the result never exceeds what the HC advertises.
pub const fn max_pstreams_encode(stream_count: u32) -> Option<u8> {
    if !stream_count.is_power_of_two() || stream_count < 2 {
        return None;
    }
    let exponent = stream_count.trailing_zeros();
    if exponent > 16 {
        return None;
    }
    Some((exponent - 1) as u8)
}

/// The negotiated stream configuration for a [`UasEndpointSet`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct UasStreams {
    /// Usable stream IDs are 1..=`count` (stream 0 is reserved).
    pub count: u32,
    /// Endpoint Context `MaxPStreams` value for `count`.
    pub max_pstreams: u8,
}

/// Negotiate streams for a detected UAS setting against the host
/// controller's `MaxPSASize` (HCCPARAMS1, already decoded by
/// [`cap::HccParams1::decode`]). The device side is the minimum over
/// the three streamed pipes — status, data-in, data-out — because
/// Linux allocates one stream array shared by exactly those three
/// (`usb_alloc_streams(intf, eps + 1, 3, ...)`); the command pipe
/// takes no streams, so its companion capacity is ignored here.
/// Returns `None` when no usable stream count survives, in which case
/// the caller must not prefer UAS on a SuperSpeed link (Linux
/// `uas_use_uas_driver`: no streams ⇒ no UAS).
pub fn negotiate_streams(
    max_psa_size: u8,
    set: &UasEndpointSet,
    requested: u32,
) -> Option<UasStreams> {
    let hc_max = cap::hc_max_streams(max_psa_size);
    // Pipes [command, status, data-in, data-out]: stream the last three.
    let dev_max = set.max_streams[1]
        .min(set.max_streams[2])
        .min(set.max_streams[3]);
    let count = negotiate_stream_count(hc_max, dev_max, requested)?;
    let max_pstreams = max_pstreams_encode(count)?;
    Some(UasStreams {
        count,
        max_pstreams,
    })
}

/// Binding preference: `Some((set, streams))` when the configuration
/// blob carries a complete UAS alternate setting *and* the host
/// controller and the device can negotiate at least two streams for
/// it, `None` otherwise. `None` means "stay on BOT" — the current
/// attach behaviour — never "fail the bind". The attach cascade does
/// not call this yet: slice 2 wires it in alongside the Command /
/// Status IU transport, which is what makes a UAS bind usable.
/// `requested` is the stream count to ask for; pass
/// [`UAS_REQUESTED_STREAMS`] (Linux's 256) unless a caller has a
/// reason to ask for fewer.
pub fn prefer_uas(
    cfg: &[u8],
    max_psa_size: u8,
    requested: u32,
) -> Option<(UasEndpointSet, UasStreams)> {
    let set = find_uas_endpoints(cfg).ok()?;
    let streams = negotiate_streams(max_psa_size, &set, requested)?;
    Some((set, streams))
}

/// Walk a Configuration Descriptor (§9.6.3) blob looking for the
/// first interface whose `bInterfaceClass:SubClass:Protocol` is the
/// UAS triple, plus its four bulk pipes. Pipe roles come only from
/// the Pipe Usage descriptors that follow each endpoint descriptor
/// (Linux `uas_find_endpoints`); endpoint numbers and descriptor
/// order are never consulted. The first UAS alternate setting wins
/// (Linux `uas_find_uas_alt_setting`); if its pipes are incomplete
/// the search fails rather than falling through to a later setting.
///
/// `cfg` is the descriptor blob fetched via
/// `Xhci::get_config_descriptor`, the same blob
/// [`crate::msc::find_bot_endpoints`] walks for BOT.
pub fn find_uas_endpoints(cfg: &[u8]) -> Result<UasEndpointSet, UasError> {
    let mut i = 0usize;
    let mut in_uas = false;
    let mut iface = 0u8;
    let mut alt = 0u8;
    // Pipes in pipe-ID order: [command, status, data-in, data-out].
    let mut pipes: [Option<EndpointConfig>; 4] = [None; 4];
    let mut pipe_streams: [u32; 4] = [0; 4];
    // Endpoint descriptor most recently seen inside the UAS alternate
    // setting, awaiting its companion / pipe-usage descriptors.
    let mut pending: Option<PendingEndpoint> = None;

    while i + 2 <= cfg.len() {
        let len = cfg[i] as usize;
        if len < 2 || i + len > cfg.len() {
            break;
        }
        let dtype = cfg[i + 1];
        match dtype {
            // Interface Descriptor (§9.6.5) — bLength 9, dtype 4.
            //   +2 bInterfaceNumber, +3 bAlternateSetting,
            //   +5 bInterfaceClass, +6 bInterfaceSubClass,
            //   +7 bInterfaceProtocol.
            // Any interface descriptor ends the alternate setting in
            // progress: finalize it (first UAS setting wins).
            4 => {
                if in_uas {
                    return finish_uas(iface, alt, pipes, pipe_streams);
                }
                if len >= 9 && is_uas_interface(cfg[i + 5], cfg[i + 6], cfg[i + 7]) {
                    in_uas = true;
                    iface = cfg[i + 2];
                    alt = cfg[i + 3];
                    pipes = [None; 4];
                    pipe_streams = [0; 4];
                }
                pending = None;
            }
            // Endpoint Descriptor (§9.6.6) — bLength 7, dtype 5.
            //   +2 bEndpointAddress (bit 7 = IN)
            //   +3 bmAttributes (bits[1:0] = transfer type; 2 = bulk)
            //   +4..=5 wMaxPacketSize.
            // A UAS alternate setting carries bulk endpoints only.
            5 => {
                if !in_uas {
                    pending = None;
                } else if len < 7 {
                    return Err(UasError::MalformedDescriptor);
                } else {
                    let ep_addr = cfg[i + 2];
                    let attr = cfg[i + 3];
                    let mps = u16::from_le_bytes([cfg[i + 4], cfg[i + 5]]);
                    if attr & 0x03 != 2 {
                        return Err(UasError::NonBulkEndpoint);
                    }
                    let kind = if ep_addr & 0x80 != 0 {
                        EndpointKind::BulkIn
                    } else {
                        EndpointKind::BulkOut
                    };
                    pending = Some(PendingEndpoint {
                        ep: EndpointConfig {
                            ep_addr,
                            max_packet: mps,
                            kind,
                            interval: 0,
                        },
                        max_streams: 0,
                        pipe_usage_seen: false,
                        bound_slot: None,
                    });
                }
            }
            // SuperSpeed Endpoint Companion (§9.6.7) — bLength 6,
            // dtype 0x30: +2 bMaxBurst, +3 bmAttributes,
            // +4..=5 wBytesPerInterval. Belongs to the pending
            // endpoint; ignored when there is none to attach to.
            // It may follow the endpoint's Pipe Usage descriptor
            // instead of preceding it, so when this endpoint has
            // already bound a pipe the recorded capacity is updated
            // in place rather than lost.
            USB_DT_SS_ENDPOINT_COMP => {
                if in_uas {
                    if len < 6 {
                        return Err(UasError::MalformedDescriptor);
                    }
                    if let Some(p) = pending.as_mut() {
                        p.max_streams = device_max_streams(cfg[i + 3]);
                        if let Some(slot) = p.bound_slot {
                            pipe_streams[slot] = p.max_streams;
                        }
                    }
                }
            }
            // Pipe Usage (T10 UAS) — bLength 4, dtype 0x24:
            // +2 bPipeID (1..=4). Belongs to the pending endpoint.
            // Only the first Pipe Usage descriptor per endpoint is
            // honoured (Linux breaks out of the extra-descriptor
            // walk at the first one); an out-of-range pipe ID is
            // ignored, as in Linux.
            USB_DT_PIPE_USAGE => {
                if in_uas {
                    if len < 3 {
                        return Err(UasError::MalformedDescriptor);
                    }
                    if let Some(p) = pending.as_mut() {
                        if !p.pipe_usage_seen {
                            p.pipe_usage_seen = true;
                            let pipe_id = cfg[i + 2];
                            if (1..=4).contains(&pipe_id) {
                                let slot = (pipe_id - 1) as usize;
                                if pipes[slot].is_some() {
                                    return Err(UasError::DuplicatePipe);
                                }
                                if !pipe_direction_ok(pipe_id, p.ep.ep_addr) {
                                    return Err(UasError::PipeDirectionMismatch);
                                }
                                pipes[slot] = Some(p.ep);
                                pipe_streams[slot] = p.max_streams;
                                p.bound_slot = Some(slot);
                            }
                        }
                    }
                }
            }
            // Anything else ends the pending endpoint's descriptor
            // run (configuration, class-specific, ...).
            _ => {
                pending = None;
            }
        }
        i += len;
    }
    if in_uas {
        return finish_uas(iface, alt, pipes, pipe_streams);
    }
    Err(UasError::NoUasInterface)
}

/// The UAS pipe table's direction for a pipe ID: command (1) and
/// data-out (4) are OUT, status (2) and data-in (3) are IN.
const fn pipe_direction_ok(pipe_id: u8, ep_addr: u8) -> bool {
    let is_in = ep_addr & 0x80 != 0;
    match pipe_id {
        UAS_PIPE_COMMAND | UAS_PIPE_DATA_OUT => !is_in,
        UAS_PIPE_STATUS | UAS_PIPE_DATA_IN => is_in,
        _ => false,
    }
}

/// One endpoint descriptor seen inside a UAS alternate setting,
/// waiting for the companion / pipe-usage descriptors that follow it
/// in the blob.
#[derive(Copy, Clone, Debug)]
struct PendingEndpoint {
    ep: EndpointConfig,
    /// Streams from this endpoint's SuperSpeed companion (0 if none).
    max_streams: u32,
    /// A Pipe Usage descriptor was already seen for this endpoint.
    pipe_usage_seen: bool,
    /// Pipe slot this endpoint bound (if its Pipe Usage descriptor
    /// already arrived), so a later companion can update the
    /// recorded stream capacity in place.
    bound_slot: Option<usize>,
}

fn finish_uas(
    interface: u8,
    alt_setting: u8,
    pipes: [Option<EndpointConfig>; 4],
    pipe_streams: [u32; 4],
) -> Result<UasEndpointSet, UasError> {
    match pipes {
        [Some(command_out), Some(status_in), Some(data_in), Some(data_out)] => Ok(UasEndpointSet {
            interface,
            alt_setting,
            command_out,
            status_in,
            data_in,
            data_out,
            max_streams: pipe_streams,
        }),
        _ => Err(UasError::EndpointsMissing),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    // ── Fixture builders: byte-exact descriptor shapes ──────────
    // Layouts follow the USB 2.0 §9.6 / USB 3.0 §9.6.7 descriptor
    // tables and the Linux gadget UAS function (endpoint, companion,
    // pipe-usage per endpoint). Values are the spec's, not the code's:
    // the assertions below check the finder against these bytes.

    fn config(total_len: u16) -> Vec<u8> {
        let mut v = alloc::vec![9, 0x02];
        v.extend_from_slice(&total_len.to_le_bytes());
        v.extend_from_slice(&[1, 1, 0, 0x80, 250]);
        v
    }

    /// Wrap an interface/body blob in a configuration descriptor
    /// whose `wTotalLength` is the real blob length.
    fn wrap(body: &[u8]) -> Vec<u8> {
        let total = (9 + body.len()) as u16;
        let mut v = config(total);
        v.extend_from_slice(body);
        v
    }

    fn iface(num: u8, alt: u8, n_eps: u8, class: u8, sub: u8, proto: u8) -> Vec<u8> {
        alloc::vec![9, 0x04, num, alt, n_eps, class, sub, proto, 0]
    }

    fn ep(addr: u8, mps: u16) -> Vec<u8> {
        let mut v = alloc::vec![7, 0x05, addr, 0x02];
        v.extend_from_slice(&mps.to_le_bytes());
        v.push(0);
        v
    }

    fn ep_with_type(addr: u8, attr: u8, mps: u16) -> Vec<u8> {
        let mut v = alloc::vec![7, 0x05, addr, attr];
        v.extend_from_slice(&mps.to_le_bytes());
        v.push(0);
        v
    }

    /// SuperSpeed companion: bLength 6, dtype 0x30, bMaxBurst 0,
    /// bmAttributes, wBytesPerInterval 0.
    fn ss_comp(bm_attributes: u8) -> Vec<u8> {
        alloc::vec![6, USB_DT_SS_ENDPOINT_COMP, 0, bm_attributes, 0, 0]
    }

    /// Pipe Usage: bLength 4, dtype 0x24, bPipeID, reserved 0.
    fn pipe_usage(id: u8) -> Vec<u8> {
        alloc::vec![4, USB_DT_PIPE_USAGE, id, 0]
    }

    /// One UAS endpoint in blob order: endpoint + companion +
    /// pipe-usage. `streams` is the companion bmAttributes field.
    fn uas_ep(addr: u8, streams: u8, pipe: u8) -> Vec<u8> {
        let mut v = ep(addr, 1024);
        v.extend_from_slice(&ss_comp(streams));
        v.extend_from_slice(&pipe_usage(pipe));
        v
    }

    /// Dual-alternate-setting enclosure (the shape Linux's
    /// `uas_find_uas_alt_setting` exists for): interface 0 alt 0 is
    /// BOT, alt 1 is UAS. The UAS endpoints are deliberately listed
    /// in shuffled descriptor order — data-out first, command third —
    /// so any finder that assigns roles by endpoint number or by
    /// descriptor order answers differently from the Pipe Usage
    /// assignment and fails this test.
    fn dual_alt_blob() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 2, 0x08, 0x06, 0x50));
        v.extend_from_slice(&ep(0x81, 1024));
        v.extend_from_slice(&ss_comp(0));
        v.extend_from_slice(&ep(0x02, 1024));
        v.extend_from_slice(&ss_comp(0));
        v.extend_from_slice(&iface(0, 1, 4, 0x08, 0x06, 0x62));
        v.extend_from_slice(&uas_ep(0x04, 5, UAS_PIPE_DATA_OUT));
        v.extend_from_slice(&uas_ep(0x82, 5, UAS_PIPE_STATUS));
        v.extend_from_slice(&uas_ep(0x01, 5, UAS_PIPE_COMMAND));
        v.extend_from_slice(&uas_ep(0x83, 5, UAS_PIPE_DATA_IN));
        wrap(&v)
    }

    /// UAS-only device: one alternate setting, alt 0, no companions
    /// (a USB 2.0-speed UAS device reports no stream capacity).
    fn uas_only_blob() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 4, 0x08, 0x06, 0x62));
        for (addr, pipe) in [
            (0x01, UAS_PIPE_COMMAND),
            (0x82, UAS_PIPE_STATUS),
            (0x83, UAS_PIPE_DATA_IN),
            (0x04, UAS_PIPE_DATA_OUT),
        ] {
            v.extend_from_slice(&ep(addr, 512));
            v.extend_from_slice(&pipe_usage(pipe));
        }
        wrap(&v)
    }

    #[test]
    fn dual_alt_finds_uas_setting_by_pipe_usage() {
        let set = find_uas_endpoints(&dual_alt_blob()).unwrap();
        assert_eq!(set.interface, 0);
        assert_eq!(set.alt_setting, 1);
        // Roles come from the Pipe Usage descriptors, not from the
        // shuffled descriptor order (data-out was listed first).
        assert_eq!(set.command_out.ep_addr, 0x01);
        assert_eq!(set.status_in.ep_addr, 0x82);
        assert_eq!(set.data_in.ep_addr, 0x83);
        assert_eq!(set.data_out.ep_addr, 0x04);
        assert_eq!(set.command_out.kind, EndpointKind::BulkOut);
        assert_eq!(set.status_in.kind, EndpointKind::BulkIn);
        assert_eq!(set.data_in.kind, EndpointKind::BulkIn);
        assert_eq!(set.data_out.kind, EndpointKind::BulkOut);
        // bmAttributes 5 on every companion => 2^5 = 32 streams.
        assert_eq!(set.max_streams, [32, 32, 32, 32]);
        // The BOT alternate's endpoints must not leak into the set.
        assert_ne!(set.command_out.ep_addr, 0x02);
        assert_ne!(set.status_in.ep_addr, 0x81);
    }

    #[test]
    fn pipe_usage_before_companion_still_records_streams() {
        // Same endpoint run, descriptors in the other order:
        // endpoint, pipe-usage, then companion. The capacity must
        // still land on the bound pipe.
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 4, 0x08, 0x06, 0x62));
        for (addr, pipe) in [
            (0x01, UAS_PIPE_COMMAND),
            (0x82, UAS_PIPE_STATUS),
            (0x83, UAS_PIPE_DATA_IN),
            (0x04, UAS_PIPE_DATA_OUT),
        ] {
            v.extend_from_slice(&ep(addr, 1024));
            v.extend_from_slice(&pipe_usage(pipe));
            v.extend_from_slice(&ss_comp(5));
        }
        let v = wrap(&v);
        let set = find_uas_endpoints(&v).unwrap();
        assert_eq!(set.max_streams, [32, 32, 32, 32]);
    }

    #[test]
    fn uas_only_alt_zero_binds_without_companions() {
        let set = find_uas_endpoints(&uas_only_blob()).unwrap();
        assert_eq!((set.interface, set.alt_setting), (0, 0));
        assert_eq!(set.max_streams, [0, 0, 0, 0]);
    }

    #[test]
    fn bot_only_blob_is_not_uas() {
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 2, 0x08, 0x06, 0x50));
        v.extend_from_slice(&ep(0x81, 512));
        v.extend_from_slice(&ep(0x02, 512));
        let v = wrap(&v);
        assert_eq!(find_uas_endpoints(&v), Err(UasError::NoUasInterface));
    }

    #[test]
    fn empty_and_truncated_blobs_fail_cleanly() {
        assert_eq!(find_uas_endpoints(&[]), Err(UasError::NoUasInterface));
        // Cut the dual-alt blob off inside the UAS setting, after
        // only two pipes have been bound.
        let mut v = dual_alt_blob();
        v.truncate(9 + 9 + 7 + 6 + 7 + 6 + 9 + 7 + 6 + 4 + 7 + 6 + 4);
        assert_eq!(find_uas_endpoints(&v), Err(UasError::EndpointsMissing));
    }

    #[test]
    fn missing_pipe_usage_is_endpoints_missing() {
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 4, 0x08, 0x06, 0x62));
        // Three pipes only: data-out has no Pipe Usage descriptor,
        // so it stays unbound even though the endpoint is present.
        v.extend_from_slice(&uas_ep(0x01, 5, UAS_PIPE_COMMAND));
        v.extend_from_slice(&uas_ep(0x82, 5, UAS_PIPE_STATUS));
        v.extend_from_slice(&uas_ep(0x83, 5, UAS_PIPE_DATA_IN));
        v.extend_from_slice(&ep(0x04, 1024));
        v.extend_from_slice(&ss_comp(5));
        let v = wrap(&v);
        assert_eq!(find_uas_endpoints(&v), Err(UasError::EndpointsMissing));
    }

    #[test]
    fn out_of_range_pipe_id_is_ignored_like_linux() {
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 4, 0x08, 0x06, 0x62));
        v.extend_from_slice(&uas_ep(0x01, 5, UAS_PIPE_COMMAND));
        v.extend_from_slice(&uas_ep(0x82, 5, UAS_PIPE_STATUS));
        v.extend_from_slice(&uas_ep(0x83, 5, UAS_PIPE_DATA_IN));
        // Pipe ID 5 is outside 1..=4: ignored, data-out unbound.
        v.extend_from_slice(&uas_ep(0x04, 5, 5));
        let v = wrap(&v);
        assert_eq!(find_uas_endpoints(&v), Err(UasError::EndpointsMissing));
    }

    #[test]
    fn duplicate_pipe_id_fails() {
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 4, 0x08, 0x06, 0x62));
        v.extend_from_slice(&uas_ep(0x01, 5, UAS_PIPE_COMMAND));
        v.extend_from_slice(&uas_ep(0x82, 5, UAS_PIPE_STATUS));
        v.extend_from_slice(&uas_ep(0x83, 5, UAS_PIPE_DATA_IN));
        // Second endpoint claiming pipe 1 (command).
        v.extend_from_slice(&uas_ep(0x04, 5, UAS_PIPE_COMMAND));
        let v = wrap(&v);
        assert_eq!(find_uas_endpoints(&v), Err(UasError::DuplicatePipe));
    }

    #[test]
    fn pipe_direction_mismatch_fails() {
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 4, 0x08, 0x06, 0x62));
        // Command pipe (1) on an IN endpoint: contradicts the table.
        v.extend_from_slice(&uas_ep(0x81, 5, UAS_PIPE_COMMAND));
        v.extend_from_slice(&uas_ep(0x82, 5, UAS_PIPE_STATUS));
        v.extend_from_slice(&uas_ep(0x83, 5, UAS_PIPE_DATA_IN));
        v.extend_from_slice(&uas_ep(0x04, 5, UAS_PIPE_DATA_OUT));
        let v = wrap(&v);
        assert_eq!(find_uas_endpoints(&v), Err(UasError::PipeDirectionMismatch));
    }

    #[test]
    fn non_bulk_endpoint_in_uas_setting_fails() {
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 4, 0x08, 0x06, 0x62));
        v.extend_from_slice(&uas_ep(0x01, 5, UAS_PIPE_COMMAND));
        v.extend_from_slice(&uas_ep(0x82, 5, UAS_PIPE_STATUS));
        v.extend_from_slice(&uas_ep(0x83, 5, UAS_PIPE_DATA_IN));
        // Interrupt endpoint (bmAttributes 0x03) as data-out.
        v.extend_from_slice(&ep_with_type(0x04, 0x03, 1024));
        v.extend_from_slice(&ss_comp(5));
        v.extend_from_slice(&pipe_usage(UAS_PIPE_DATA_OUT));
        let v = wrap(&v);
        assert_eq!(find_uas_endpoints(&v), Err(UasError::NonBulkEndpoint));
    }

    #[test]
    fn truncated_companion_and_pipe_usage_fail() {
        // Companion claiming dtype 0x30 with bLength 4 (< 6).
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 4, 0x08, 0x06, 0x62));
        v.extend_from_slice(&ep(0x01, 1024));
        v.extend_from_slice(&[4, USB_DT_SS_ENDPOINT_COMP, 0, 5]);
        v.extend_from_slice(&pipe_usage(UAS_PIPE_COMMAND));
        let v = wrap(&v);
        assert_eq!(find_uas_endpoints(&v), Err(UasError::MalformedDescriptor));
        // Pipe Usage claiming dtype 0x24 with bLength 2 (< 3).
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 4, 0x08, 0x06, 0x62));
        v.extend_from_slice(&ep(0x01, 1024));
        v.extend_from_slice(&[2, USB_DT_PIPE_USAGE]);
        let v = wrap(&v);
        assert_eq!(find_uas_endpoints(&v), Err(UasError::MalformedDescriptor));
    }

    #[test]
    fn second_interface_after_uas_does_not_disturb_the_set() {
        // A composite device: UAS on interface 0, then a BOT
        // interface 1. The finder finalizes at interface 1 and
        // still returns the UAS set (first UAS setting wins).
        let mut v = dual_alt_blob();
        v.extend_from_slice(&iface(1, 0, 2, 0x08, 0x06, 0x50));
        v.extend_from_slice(&ep(0x85, 512));
        v.extend_from_slice(&ep(0x06, 512));
        // The appended interface changes the real total length.
        let total = v.len() as u16;
        v[2..4].copy_from_slice(&total.to_le_bytes());
        let set = find_uas_endpoints(&v).unwrap();
        assert_eq!((set.interface, set.alt_setting), (0, 1));
        // And a UAS interface that is NOT first still wins over an
        // earlier non-storage interface.
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 1, 0x03, 0x01, 0x02));
        v.extend_from_slice(&ep_with_type(0x81, 0x03, 8));
        v.extend_from_slice(&iface(1, 0, 4, 0x08, 0x06, 0x62));
        v.extend_from_slice(&uas_ep(0x01, 5, UAS_PIPE_COMMAND));
        v.extend_from_slice(&uas_ep(0x82, 5, UAS_PIPE_STATUS));
        v.extend_from_slice(&uas_ep(0x83, 5, UAS_PIPE_DATA_IN));
        v.extend_from_slice(&uas_ep(0x04, 5, UAS_PIPE_DATA_OUT));
        let v = wrap(&v);
        let set = find_uas_endpoints(&v).unwrap();
        assert_eq!((set.interface, set.alt_setting), (1, 0));
    }

    #[test]
    fn first_uas_setting_wins_even_when_incomplete() {
        // Two UAS interfaces: the first is incomplete. Linux takes
        // the first UAS alternate setting, so detection fails rather
        // than falling through to the complete second one.
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 2, 0x08, 0x06, 0x62));
        v.extend_from_slice(&uas_ep(0x01, 5, UAS_PIPE_COMMAND));
        v.extend_from_slice(&uas_ep(0x82, 5, UAS_PIPE_STATUS));
        v.extend_from_slice(&iface(1, 0, 4, 0x08, 0x06, 0x62));
        v.extend_from_slice(&uas_ep(0x01, 5, UAS_PIPE_COMMAND));
        v.extend_from_slice(&uas_ep(0x82, 5, UAS_PIPE_STATUS));
        v.extend_from_slice(&uas_ep(0x83, 5, UAS_PIPE_DATA_IN));
        v.extend_from_slice(&uas_ep(0x04, 5, UAS_PIPE_DATA_OUT));
        let v = wrap(&v);
        assert_eq!(find_uas_endpoints(&v), Err(UasError::EndpointsMissing));
    }

    #[test]
    fn stream_counts_follow_the_spec_encodings() {
        // Device side: usb_ss_max_streams — 0 stays 0, else 1<<field.
        assert_eq!(device_max_streams(0), 0);
        assert_eq!(device_max_streams(1), 2);
        assert_eq!(device_max_streams(5), 32);
        assert_eq!(device_max_streams(16), 65536);
        // Host side: HCCPARAMS1 MaxPSASize — 0 means no streams,
        // else the PSA holds 2^(n+1) entries (xHCI §5.3.6).
        assert_eq!(cap::hc_max_streams(0), 0);
        assert_eq!(cap::hc_max_streams(1), 4);
        assert_eq!(cap::hc_max_streams(5), 64);
        assert_eq!(cap::hc_max_streams(15), 65536);
        // Negotiation: min of the three, rounded down to a power
        // of two, at least two streams.
        assert_eq!(negotiate_stream_count(65536, 32, 256), Some(32));
        assert_eq!(negotiate_stream_count(64, 32, 256), Some(32));
        assert_eq!(negotiate_stream_count(32, 64, 256), Some(32));
        assert_eq!(negotiate_stream_count(65536, 32, 16), Some(16));
        assert_eq!(negotiate_stream_count(65536, 32, 20), Some(16));
        assert_eq!(negotiate_stream_count(4, 4, 4), Some(4));
        assert_eq!(negotiate_stream_count(3, 3, 3), Some(2));
        assert_eq!(negotiate_stream_count(0, 32, 256), None);
        assert_eq!(negotiate_stream_count(65536, 0, 256), None);
        assert_eq!(negotiate_stream_count(65536, 1, 256), None);
        assert_eq!(negotiate_stream_count(65536, 32, 1), None);
        // MaxPStreams encode: PSA entries 2^(v+1) = count.
        assert_eq!(max_pstreams_encode(2), Some(0));
        assert_eq!(max_pstreams_encode(4), Some(1));
        assert_eq!(max_pstreams_encode(32), Some(4));
        assert_eq!(max_pstreams_encode(65536), Some(15));
        assert_eq!(max_pstreams_encode(0), None);
        assert_eq!(max_pstreams_encode(1), None);
        assert_eq!(max_pstreams_encode(3), None);
        assert_eq!(max_pstreams_encode(131072), None);
        // EP Context dword-0 field: MaxPStreams at bits 14:10
        // (Linux EP_MAXPSTREAMS macro; xHCI §6.2.3 Table 6-8).
        assert_eq!(crate::xhci::ep_context_max_pstreams_field(0), 0);
        assert_eq!(crate::xhci::ep_context_max_pstreams_field(1), 0x400);
        assert_eq!(crate::xhci::ep_context_max_pstreams_field(4), 0x1000);
        assert_eq!(crate::xhci::ep_context_max_pstreams_field(15), 0x3c00);
    }

    #[test]
    fn negotiate_streams_uses_the_three_streamed_pipes() {
        let set = find_uas_endpoints(&dual_alt_blob()).unwrap();
        // HC MaxPSASize 5 => 64 streams; device 32 on every pipe;
        // request 256 => 32 streams, MaxPStreams 4.
        let streams = negotiate_streams(5, &set, UAS_REQUESTED_STREAMS).unwrap();
        assert_eq!(
            streams,
            UasStreams {
                count: 32,
                max_pstreams: 4,
            }
        );
        // HC without streams => no negotiation.
        assert_eq!(negotiate_streams(0, &set, UAS_REQUESTED_STREAMS), None);
        // A setting whose status pipe reports no streams caps the
        // negotiation at zero even if the data pipes offer 32: the
        // shared stream array needs all three streamed pipes.
        let mut limited = set.clone();
        limited.max_streams[1] = 0;
        assert_eq!(negotiate_streams(5, &limited, UAS_REQUESTED_STREAMS), None);
        // The command pipe's capacity is irrelevant: it takes no
        // streams, so zeroing it changes nothing.
        let mut cmd_zero = set.clone();
        cmd_zero.max_streams[0] = 0;
        assert_eq!(
            negotiate_streams(5, &cmd_zero, UAS_REQUESTED_STREAMS),
            Some(UasStreams {
                count: 32,
                max_pstreams: 4,
            })
        );
    }

    #[test]
    fn prefer_uas_is_the_binding_decision() {
        // Dual-alt enclosure + a stream-capable HC: prefer UAS.
        let (set, streams) = prefer_uas(&dual_alt_blob(), 5, UAS_REQUESTED_STREAMS)
            .expect("dual-alt enclosure should prefer UAS");
        assert_eq!((set.interface, set.alt_setting), (0, 1));
        assert_eq!(streams.count, 32);
        // Same blob, HC without streams: stay on BOT.
        assert_eq!(prefer_uas(&dual_alt_blob(), 0, UAS_REQUESTED_STREAMS), None);
        // BOT-only blob: stay on BOT.
        let mut v = Vec::new();
        v.extend_from_slice(&iface(0, 0, 2, 0x08, 0x06, 0x50));
        v.extend_from_slice(&ep(0x81, 512));
        v.extend_from_slice(&ep(0x02, 512));
        let v = wrap(&v);
        assert_eq!(prefer_uas(&v, 5, UAS_REQUESTED_STREAMS), None);
        // UAS-only device with no stream capacity: no UAS preference
        // (SuperSpeed UAS without streams is not attempted; the
        // device keeps its BOT path if it has one).
        assert_eq!(prefer_uas(&uas_only_blob(), 5, UAS_REQUESTED_STREAMS), None);
    }
}
