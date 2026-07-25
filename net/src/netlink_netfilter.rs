//! Read-only Linux nfnetlink conntrack responder.
//!
//! `conntrack -L` sends an `IPCTNL_MSG_CT_GET` dump to
//! `NETLINK_NETFILTER`. Replies are `IPCTNL_MSG_CT_NEW` records sourced from
//! the canonical conntrack snapshot, followed by `NLMSG_DONE`.

extern crate alloc;

use alloc::vec::Vec;

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_MULTI: u16 = 2;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;
const NLA_F_NESTED: u16 = 1 << 15;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_NEW: u16 = 0;
const IPCTNL_MSG_CT_GET: u16 = 1;
const AF_INET: u8 = 2;
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_STATUS: u16 = 3;
const CTA_TIMEOUT: u16 = 7;
const CTA_ID: u16 = 12;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const IPS_SEEN_REPLY: u32 = 1 << 1;
const IPS_ASSURED: u32 = 1 << 2;
const IPS_CONFIRMED: u32 = 1 << 3;
const EINVAL: i32 = 22;
const EOPNOTSUPP: i32 = 95;

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
    let mut payload = Vec::new();
    payload.extend_from_slice(&(-errno).to_ne_bytes());
    payload.extend_from_slice(request);
    frame(NLMSG_ERROR, 0, seq, &payload)
}

fn push_attr(body: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = (4 + payload.len()) as u16;
    body.extend_from_slice(&len.to_ne_bytes());
    body.extend_from_slice(&kind.to_ne_bytes());
    body.extend_from_slice(payload);
    body.resize(align(body.len()), 0);
}

fn tuple(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, proto_num: u8) -> Vec<u8> {
    let mut ip = Vec::new();
    push_attr(&mut ip, CTA_IP_V4_SRC, &src);
    push_attr(&mut ip, CTA_IP_V4_DST, &dst);
    let mut proto = Vec::new();
    push_attr(&mut proto, CTA_PROTO_NUM, &[proto_num]);
    push_attr(&mut proto, CTA_PROTO_SRC_PORT, &sport.to_be_bytes());
    push_attr(&mut proto, CTA_PROTO_DST_PORT, &dport.to_be_bytes());
    let mut out = Vec::new();
    push_attr(&mut out, CTA_TUPLE_IP | NLA_F_NESTED, &ip);
    push_attr(&mut out, CTA_TUPLE_PROTO | NLA_F_NESTED, &proto);
    out
}

fn encode_entry(entry: &crate::netfilter::conntrack::ConntrackSnapshot, seq: u32) -> Vec<u8> {
    let mut body = alloc::vec![AF_INET, 0, 0, 0]; // struct nfgenmsg
    let original = tuple(
        entry.orig_src,
        entry.orig_dst,
        entry.orig_sport,
        entry.orig_dport,
        entry.l4proto_num,
    );
    push_attr(&mut body, CTA_TUPLE_ORIG | NLA_F_NESTED, &original);
    let reply = tuple(
        entry.reply_src,
        entry.reply_dst,
        entry.reply_sport,
        entry.reply_dport,
        entry.l4proto_num,
    );
    push_attr(&mut body, CTA_TUPLE_REPLY | NLA_F_NESTED, &reply);
    let mut status = IPS_CONFIRMED;
    if entry.state != "NEW" {
        status |= IPS_SEEN_REPLY;
    }
    if entry.assured {
        status |= IPS_ASSURED;
    }
    push_attr(&mut body, CTA_STATUS, &status.to_be_bytes());
    push_attr(&mut body, CTA_TIMEOUT, &entry.timeout.to_be_bytes());
    push_attr(&mut body, CTA_ID, &(entry.id as u32).to_be_bytes());
    frame(
        (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW,
        NLM_F_MULTI,
        seq,
        &body,
    )
}

fn build_one(request: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
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
    if kind >> 8 != NFNL_SUBSYS_CTNETLINK || kind & 0xff != IPCTNL_MSG_CT_GET {
        return Ok(alloc::vec![error(EOPNOTSUPP, seq, request)]);
    }
    if request.len() < NLMSG_HDRLEN + 4 || request[NLMSG_HDRLEN] != AF_INET {
        return Ok(alloc::vec![error(EINVAL, seq, request)]);
    }
    if flags & NLM_F_DUMP != NLM_F_DUMP {
        return Ok(alloc::vec![error(EOPNOTSUPP, seq, request)]);
    }
    let mut out = crate::netfilter::conntrack::snapshot()
        .iter()
        .map(|entry| encode_entry(entry, seq))
        .collect::<Vec<_>>();
    out.push(frame(NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_ne_bytes()));
    if flags & NLM_F_ACK != 0 {
        out.push(error(0, seq, request));
    }
    Ok(out)
}

/// Build replies for every aligned nfnetlink request in one datagram.
pub fn build_replies(datagram: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    let mut offset = 0usize;
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
        replies.extend(build_one(&remaining[..len])?);
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

    fn request() -> Vec<u8> {
        frame(
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
            1 | NLM_F_DUMP,
            55,
            &[AF_INET, 0, 0, 0],
        )
    }

    #[test]
    fn empty_conntrack_dump_terminates() {
        crate::netfilter::conntrack::__reset_for_test();
        let replies = build_replies(&request()).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            u16::from_ne_bytes(replies[0][4..6].try_into().unwrap()),
            NLMSG_DONE
        );
    }

    #[test]
    fn unsupported_subsystem_returns_error() {
        let mut request = request();
        request[4..6].copy_from_slice(&0x0201u16.to_ne_bytes());
        let replies = build_replies(&request).unwrap();
        assert_eq!(
            i32::from_ne_bytes(
                replies[0][NLMSG_HDRLEN..NLMSG_HDRLEN + 4]
                    .try_into()
                    .unwrap()
            ),
            -EOPNOTSUPP
        );
    }

    #[test]
    fn batched_requests_preserve_sequences_and_ack() {
        crate::netfilter::conntrack::__reset_for_test();
        let first = request();
        let mut second = request();
        second[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK).to_ne_bytes());
        second[8..12].copy_from_slice(&56u32.to_ne_bytes());
        let mut batch = first;
        batch.extend_from_slice(&second);
        let replies = build_replies(&batch).unwrap();
        assert_eq!(replies.len(), 3);
        assert_eq!(
            u32::from_ne_bytes(replies[0][8..12].try_into().unwrap()),
            55
        );
        assert_eq!(
            u32::from_ne_bytes(replies[1][8..12].try_into().unwrap()),
            56
        );
        assert_eq!(
            u16::from_ne_bytes(replies[2][4..6].try_into().unwrap()),
            NLMSG_ERROR
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
}
