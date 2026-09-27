//! Linux `NETLINK_SOCK_DIAG` responder for IPv4 and IPv6 TCP/UDP sockets.
//!
//! `ss` sends `SOCK_DIAG_BY_FAMILY` / `inet_diag_req_v2` dump requests.
//! Replies are standard `inet_diag_msg` records sourced from the same TCP
//! and UDP snapshots that back `/proc/net/{tcp,udp}`.

extern crate alloc;

use alloc::vec::Vec;

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_MULTI: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;

pub const SOCK_DIAG_BY_FAMILY: u16 = 20;
/// `linux/inet_diag.h`: legacy `inet_diag_req` query type.
pub const TCPDIAG_GETSOCK: u16 = 18;
/// `linux/sock_diag.h`: socket-destroy request.
pub const SOCK_DESTROY: u16 = 21;
/// `linux/socket.h` `AF_MAX` (one past `AF_MCTP`).
const AF_MAX: u8 = 46;
pub const AF_INET: u8 = 2;
pub const AF_INET6: u8 = 10;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

const EINVAL: i32 = 22;
const ENOENT: i32 = 2;
const EOPNOTSUPP: i32 = 95;
const INET_DIAG_NOCOOKIE: u32 = u32::MAX;

#[derive(Copy, Clone)]
struct DiagRecord {
    family: u8,
    state: u8,
    local_addr: [u8; 16],
    local_port: u16,
    remote_addr: [u8; 16],
    remote_port: u16,
    tx_queue: u32,
    rx_queue: u32,
    retransmits: u32,
}

/// UDP6 state is owned by the Linux socket compatibility layer, so callers
/// provide its namespace-filtered snapshot when building diagnostic replies.
#[derive(Copy, Clone, Debug)]
pub struct Udp6DiagRecord {
    pub state: u8,
    pub local_addr: [u8; 16],
    pub local_port: u16,
    pub remote_addr: [u8; 16],
    pub remote_port: u16,
    pub tx_queue: u32,
    pub rx_queue: u32,
}

#[inline]
fn align(len: usize) -> usize {
    (len + 3) & !3
}

fn frame(kind: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = NLMSG_HDRLEN + payload.len();
    let mut out = Vec::with_capacity(align(len));
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&seq.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align(len), 0);
    out
}

fn error(errno: i32, seq: u32, request: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + request.len());
    payload.extend_from_slice(&(-errno).to_ne_bytes());
    payload.extend_from_slice(request);
    frame(NLMSG_ERROR, 0, seq, &payload)
}

fn encode_record(record: DiagRecord, seq: u32, multipart: bool) -> Vec<u8> {
    // struct inet_diag_msg: family/state/timer/retrans + inet_diag_sockid,
    // then expires/rqueue/wqueue/uid/inode.
    let mut body = Vec::with_capacity(72);
    body.extend_from_slice(&[
        record.family,
        record.state,
        0,
        record.retransmits.min(255) as u8,
    ]);
    body.extend_from_slice(&record.local_port.to_be_bytes());
    body.extend_from_slice(&record.remote_port.to_be_bytes());
    body.extend_from_slice(&record.local_addr);
    body.extend_from_slice(&record.remote_addr);
    body.extend_from_slice(&0u32.to_ne_bytes()); // idiag_if
    body.extend_from_slice(&INET_DIAG_NOCOOKIE.to_ne_bytes());
    body.extend_from_slice(&INET_DIAG_NOCOOKIE.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes()); // idiag_expires
    body.extend_from_slice(&record.rx_queue.to_ne_bytes());
    body.extend_from_slice(&record.tx_queue.to_ne_bytes());
    body.extend_from_slice(&0u32.to_ne_bytes()); // uid: NARF has no root identity
    body.extend_from_slice(&0u32.to_ne_bytes()); // inode unavailable
    frame(
        SOCK_DIAG_BY_FAMILY,
        if multipart { NLM_F_MULTI } else { 0 },
        seq,
        &body,
    )
}

fn records(net_ns_id: u64, family: u8, protocol: u8, udp6: &[Udp6DiagRecord]) -> Vec<DiagRecord> {
    match (family, protocol) {
        (AF_INET, IPPROTO_TCP) => crate::tcp::core::snapshot_in(net_ns_id)
            .into_iter()
            .map(|socket| DiagRecord {
                family,
                state: socket.state_code,
                local_addr: v4_addr(socket.local_addr),
                local_port: socket.local_port,
                remote_addr: v4_addr(socket.remote_addr),
                remote_port: socket.remote_port,
                tx_queue: socket.tx_queue,
                rx_queue: socket.rx_queue,
                retransmits: socket.retrnsmt,
            })
            .collect(),
        (AF_INET, IPPROTO_UDP) => crate::udp_sock::snapshot_in(net_ns_id)
            .into_iter()
            .map(|socket| DiagRecord {
                family,
                state: socket.state_code,
                local_addr: v4_addr(socket.local_addr),
                local_port: socket.local_port,
                remote_addr: v4_addr(socket.remote_addr),
                remote_port: socket.remote_port,
                tx_queue: socket.tx_queue,
                rx_queue: socket.rx_queue,
                retransmits: 0,
            })
            .collect(),
        (AF_INET6, IPPROTO_TCP) => crate::tcp::core::snapshot6_in(net_ns_id)
            .into_iter()
            .map(|socket| DiagRecord {
                family,
                state: socket.state_code,
                local_addr: socket.local_addr,
                local_port: socket.local_port,
                remote_addr: socket.remote_addr,
                remote_port: socket.remote_port,
                tx_queue: socket.tx_queue,
                rx_queue: socket.rx_queue,
                retransmits: socket.retrnsmt,
            })
            .collect(),
        (AF_INET6, IPPROTO_UDP) => udp6
            .iter()
            .map(|socket| DiagRecord {
                family,
                state: socket.state,
                local_addr: socket.local_addr,
                local_port: socket.local_port,
                remote_addr: socket.remote_addr,
                remote_port: socket.remote_port,
                tx_queue: socket.tx_queue,
                rx_queue: socket.rx_queue,
                retransmits: 0,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn v4_addr(addr: [u8; 4]) -> [u8; 16] {
    let mut out = [0; 16];
    out[..4].copy_from_slice(&addr);
    out
}

fn build_one(net_ns_id: u64, request: &[u8], udp6: &[Udp6DiagRecord]) -> Result<Vec<Vec<u8>>, ()> {
    if request.len() < NLMSG_HDRLEN {
        return Err(());
    }
    let declared = u32::from_ne_bytes(request[0..4].try_into().map_err(|_| ())?) as usize;
    if declared < NLMSG_HDRLEN || declared > request.len() {
        return Err(());
    }
    let kind = u16::from_ne_bytes(request[4..6].try_into().map_err(|_| ())?);
    let flags = u16::from_ne_bytes(request[6..8].try_into().map_err(|_| ())?);
    let seq = u32::from_ne_bytes(request[8..12].try_into().map_err(|_| ())?);
    let request = &request[..declared];
    if flags & NLM_F_REQUEST == 0 {
        return Ok(alloc::vec![error(EINVAL, seq, request)]);
    }
    // `sock_diag_rcv_msg` (net/core/sock_diag.c): TCPDIAG_GETSOCK needs the
    // legacy inet compat hook (-EOPNOTSUPP when absent, as here), and
    // SOCK_DESTROY needs a handler `destroy` op (-EOPNOTSUPP). Every other
    // type is a bad message: -EINVAL.
    match kind {
        SOCK_DIAG_BY_FAMILY => {}
        TCPDIAG_GETSOCK | SOCK_DESTROY => {
            return Ok(alloc::vec![error(EOPNOTSUPP, seq, request)]);
        }
        _ => return Ok(alloc::vec![error(EINVAL, seq, request)]),
    }
    // `__sock_diag_cmd`: a truncated `sock_diag_req` or a family >= AF_MAX
    // is -EINVAL; a family with no registered handler is -ENOENT.
    if request.len() < NLMSG_HDRLEN + 4 {
        return Ok(alloc::vec![error(EINVAL, seq, request)]);
    }
    let family = request[NLMSG_HDRLEN];
    let protocol = request[NLMSG_HDRLEN + 1];
    if family >= AF_MAX {
        return Ok(alloc::vec![error(EINVAL, seq, request)]);
    }
    if !matches!(family, AF_INET | AF_INET6) {
        return Ok(alloc::vec![error(ENOENT, seq, request)]);
    }
    // `inet_diag_handler_cmd`: short `inet_diag_req_v2` → -EINVAL.
    if request.len() < NLMSG_HDRLEN + 56 {
        return Ok(alloc::vec![error(EINVAL, seq, request)]);
    }
    // `inet_diag_lock_handler`: no `inet_diag_table[protocol]` → -ENOENT.
    if !matches!(protocol, IPPROTO_TCP | IPPROTO_UDP) {
        return Ok(alloc::vec![error(ENOENT, seq, request)]);
    }

    let requested_states = u32::from_ne_bytes(
        request[NLMSG_HDRLEN + 4..NLMSG_HDRLEN + 8]
            .try_into()
            .map_err(|_| ())?,
    );
    let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
    let requested_local_port = u16::from_be_bytes(
        request[NLMSG_HDRLEN + 8..NLMSG_HDRLEN + 10]
            .try_into()
            .unwrap(),
    );
    let requested_remote_port = u16::from_be_bytes(
        request[NLMSG_HDRLEN + 10..NLMSG_HDRLEN + 12]
            .try_into()
            .unwrap(),
    );
    let requested_local_addr: [u8; 16] = request[NLMSG_HDRLEN + 12..NLMSG_HDRLEN + 28]
        .try_into()
        .unwrap();
    let requested_remote_addr: [u8; 16] = request[NLMSG_HDRLEN + 28..NLMSG_HDRLEN + 44]
        .try_into()
        .unwrap();
    let mut out = Vec::new();
    for record in records(net_ns_id, family, protocol, udp6) {
        let state_bit = 1u32.checked_shl(record.state as u32).unwrap_or(0);
        let state_matches = requested_states == 0 || requested_states & state_bit != 0;
        let id_matches = dump
            || (record.local_port == requested_local_port
                && record.remote_port == requested_remote_port
                && record.local_addr == requested_local_addr
                && record.remote_addr == requested_remote_addr);
        if state_matches && id_matches {
            out.push(encode_record(record, seq, dump));
        }
    }
    if dump {
        out.push(frame(NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_ne_bytes()));
    } else if out.is_empty() {
        out.push(error(ENOENT, seq, request));
    }
    if flags & NLM_F_ACK != 0
        && !out.iter().any(|message| {
            message.get(4..6) == Some(&NLMSG_ERROR.to_ne_bytes())
                && message
                    .get(NLMSG_HDRLEN..NLMSG_HDRLEN + 4)
                    .is_some_and(|raw| i32::from_ne_bytes(raw.try_into().unwrap_or([0; 4])) < 0)
        })
    {
        out.push(error(0, seq, request));
    }
    Ok(out)
}

/// Build ordered replies for every aligned `inet_diag_req_v2` message.
pub fn build_replies(datagram: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    build_replies_in(0, datagram)
}

pub fn build_replies_in(net_ns_id: u64, datagram: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    build_replies_in_with_udp6(net_ns_id, datagram, &[])
}

pub fn build_replies_in_with_udp6(
    net_ns_id: u64,
    datagram: &[u8],
    udp6: &[Udp6DiagRecord],
) -> Result<Vec<Vec<u8>>, ()> {
    let mut offset = 0;
    let mut replies = Vec::new();
    while offset < datagram.len() {
        let remaining = &datagram[offset..];
        if remaining.len() < NLMSG_HDRLEN {
            return Err(());
        }
        let len = u32::from_ne_bytes(remaining[0..4].try_into().map_err(|_| ())?) as usize;
        if len < NLMSG_HDRLEN || len > remaining.len() {
            return Err(());
        }
        replies.extend(build_one(net_ns_id, &remaining[..len], udp6)?);
        let step = align(len);
        if step > remaining.len() {
            if len == remaining.len() {
                break;
            }
            return Err(());
        }
        offset += step;
    }
    Ok(replies)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(protocol: u8) -> Vec<u8> {
        request_for(AF_INET, protocol)
    }

    fn request_for(family: u8, protocol: u8) -> Vec<u8> {
        let mut body = alloc::vec![0u8; 56];
        body[0] = family;
        body[1] = protocol;
        body[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
        frame(SOCK_DIAG_BY_FAMILY, 1 | NLM_F_DUMP, 91, &body)
    }

    #[test]
    fn empty_tcp_dump_is_completed() {
        crate::tcp::core::__reset_for_test();
        let replies = build_replies(&request(IPPROTO_TCP)).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            u16::from_ne_bytes(replies[0][4..6].try_into().unwrap()),
            NLMSG_DONE
        );
    }

    #[test]
    fn diag_record_uses_network_order_ports_and_linux_layout() {
        let message = encode_record(
            DiagRecord {
                family: AF_INET,
                state: 10,
                local_addr: v4_addr([127, 0, 0, 1]),
                local_port: 8080,
                remote_addr: [0; 16],
                remote_port: 0,
                tx_queue: 3,
                rx_queue: 4,
                retransmits: 2,
            },
            7,
            true,
        );
        assert_eq!(message.len(), NLMSG_HDRLEN + 72);
        assert_eq!(&message[20..22], &8080u16.to_be_bytes());
        assert_eq!(&message[24..28], &[127, 0, 0, 1]);
        assert_eq!(
            u32::from_ne_bytes(
                message[NLMSG_HDRLEN + 56..NLMSG_HDRLEN + 60]
                    .try_into()
                    .unwrap()
            ),
            4
        );
    }

    #[test]
    fn udp6_dump_encodes_family_and_full_addresses() {
        let local_addr = [0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let rows = [Udp6DiagRecord {
            state: 7,
            local_addr,
            local_port: 5353,
            remote_addr: [0; 16],
            remote_port: 0,
            tx_queue: 0,
            rx_queue: 12,
        }];
        let replies =
            build_replies_in_with_udp6(4, &request_for(AF_INET6, IPPROTO_UDP), &rows).unwrap();
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0][NLMSG_HDRLEN], AF_INET6);
        assert_eq!(
            &replies[0][NLMSG_HDRLEN + 8..NLMSG_HDRLEN + 24],
            &local_addr
        );
    }

    #[test]
    fn unsupported_protocol_returns_enoent() {
        // `inet_diag_lock_handler`: no handler for the protocol → -ENOENT.
        let replies = build_replies(&request(132)).unwrap();
        assert_eq!(
            i32::from_ne_bytes(
                replies[0][NLMSG_HDRLEN..NLMSG_HDRLEN + 4]
                    .try_into()
                    .unwrap()
            ),
            -ENOENT
        );
    }

    #[test]
    fn batched_dumps_preserve_sequences_and_ack() {
        crate::tcp::core::__reset_for_test();
        let mut first = request(IPPROTO_TCP);
        let mut second = request(IPPROTO_TCP);
        first[8..12].copy_from_slice(&101u32.to_ne_bytes());
        second[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK).to_ne_bytes());
        second[8..12].copy_from_slice(&102u32.to_ne_bytes());
        first.extend_from_slice(&second);

        let replies = build_replies(&first).unwrap();
        assert_eq!(replies.len(), 3);
        assert_eq!(
            u32::from_ne_bytes(replies[0][8..12].try_into().unwrap()),
            101
        );
        assert_eq!(
            u32::from_ne_bytes(replies[1][8..12].try_into().unwrap()),
            102
        );
        assert_eq!(
            i32::from_ne_bytes(
                replies[2][NLMSG_HDRLEN..NLMSG_HDRLEN + 4]
                    .try_into()
                    .unwrap()
            ),
            0
        );
    }

    #[test]
    fn request_flag_is_required() {
        let mut message = request(IPPROTO_TCP);
        message[6..8].copy_from_slice(&NLM_F_DUMP.to_ne_bytes());
        let replies = build_replies(&message).unwrap();
        assert_eq!(
            i32::from_ne_bytes(
                replies[0][NLMSG_HDRLEN..NLMSG_HDRLEN + 4]
                    .try_into()
                    .unwrap()
            ),
            -EINVAL
        );
    }
}
