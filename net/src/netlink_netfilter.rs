//! Linux nfnetlink conntrack and nftables responder.
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
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const IPCTNL_MSG_CT_NEW: u16 = 0;
const IPCTNL_MSG_CT_GET: u16 = 1;
const AF_INET: u8 = 2;
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_GETTABLE: u16 = 1;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_GETCHAIN: u16 = 4;
const NFT_MSG_DELCHAIN: u16 = 5;
const NFTA_TABLE_NAME: u16 = 1;
const NFTA_TABLE_FLAGS: u16 = 2;
const NFTA_TABLE_USE: u16 = 3;
const NFTA_TABLE_HANDLE: u16 = 4;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_HANDLE: u16 = 2;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_USE: u16 = 6;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_CHAIN_FLAGS: u16 = 10;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFT_CHAIN_BASE: u32 = 1;
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
const ENOENT: i32 = 2;
const EPERM: i32 = 1;
const EEXIST: i32 = 17;
const EBUSY: i32 = 16;
const EOPNOTSUPP: i32 = 95;
const NLA_TYPE_MASK: u16 = !(3 << 14);

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

fn push_string_attr(body: &mut Vec<u8>, kind: u16, value: &str) {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    push_attr(body, kind, &bytes);
}

fn push_be_u32_attr(body: &mut Vec<u8>, kind: u16, value: u32) {
    push_attr(body, kind | NLA_F_NET_BYTEORDER, &value.to_be_bytes());
}

fn push_be_u64_attr(body: &mut Vec<u8>, kind: u16, value: u64) {
    push_attr(body, kind | NLA_F_NET_BYTEORDER, &value.to_be_bytes());
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

fn encode_entry(
    entry: &crate::netfilter::conntrack::ConntrackSnapshot,
    seq: u32,
    multipart: bool,
) -> Vec<u8> {
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
        if multipart { NLM_F_MULTI } else { 0 },
        seq,
        &body,
    )
}

fn find_attr(attrs: &[u8], requested_kind: u16) -> Option<&[u8]> {
    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let len = u16::from_ne_bytes(attrs[offset..offset + 2].try_into().ok()?) as usize;
        let kind =
            u16::from_ne_bytes(attrs[offset + 2..offset + 4].try_into().ok()?) & NLA_TYPE_MASK;
        if len < 4 || offset + len > attrs.len() {
            return None;
        }
        if kind == requested_kind {
            return Some(&attrs[offset + 4..offset + len]);
        }
        offset += align(len);
    }
    None
}

fn requested_tuple(attrs: &[u8]) -> Option<crate::netfilter::Tuple> {
    let tuple = find_attr(attrs, CTA_TUPLE_ORIG)?;
    let ip = find_attr(tuple, CTA_TUPLE_IP)?;
    let proto = find_attr(tuple, CTA_TUPLE_PROTO)?;
    let src_ip = find_attr(ip, CTA_IP_V4_SRC)?.try_into().ok()?;
    let dst_ip = find_attr(ip, CTA_IP_V4_DST)?.try_into().ok()?;
    let proto_num = *find_attr(proto, CTA_PROTO_NUM)?.first()?;
    let src_port = u16::from_be_bytes(find_attr(proto, CTA_PROTO_SRC_PORT)?.try_into().ok()?);
    let dst_port = u16::from_be_bytes(find_attr(proto, CTA_PROTO_DST_PORT)?.try_into().ok()?);
    Some(crate::netfilter::Tuple {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        proto: proto_num,
    })
}

fn nft_table_record(
    table: &crate::netfilter::rules::Table,
    handle: u64,
    seq: u32,
    multipart: bool,
) -> Vec<u8> {
    let mut body = alloc::vec![AF_INET, 0, 0, 0];
    push_string_attr(&mut body, NFTA_TABLE_NAME, &table.name);
    push_be_u32_attr(&mut body, NFTA_TABLE_FLAGS, 0);
    push_be_u32_attr(&mut body, NFTA_TABLE_USE, table.chains.len() as u32);
    push_be_u64_attr(&mut body, NFTA_TABLE_HANDLE, handle);
    frame(
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWTABLE,
        if multipart { NLM_F_MULTI } else { 0 },
        seq,
        &body,
    )
}

fn nft_chain_record(
    table: &crate::netfilter::rules::Table,
    chain: &crate::netfilter::rules::Chain,
    handle: u64,
    seq: u32,
    multipart: bool,
) -> Vec<u8> {
    let mut body = alloc::vec![AF_INET, 0, 0, 0];
    push_string_attr(&mut body, NFTA_CHAIN_TABLE, &table.name);
    push_be_u64_attr(&mut body, NFTA_CHAIN_HANDLE, handle);
    push_string_attr(&mut body, NFTA_CHAIN_NAME, &chain.name);
    let mut hook = Vec::new();
    push_be_u32_attr(&mut hook, NFTA_HOOK_HOOKNUM, chain.hook as u32);
    push_be_u32_attr(&mut hook, NFTA_HOOK_PRIORITY, 0);
    push_attr(&mut body, NFTA_CHAIN_HOOK | NLA_F_NESTED, &hook);
    push_be_u32_attr(
        &mut body,
        NFTA_CHAIN_POLICY,
        match chain.policy {
            crate::netfilter::Verdict::Drop => 0,
            _ => 1,
        },
    );
    push_be_u32_attr(&mut body, NFTA_CHAIN_USE, chain.rules.len() as u32);
    push_string_attr(&mut body, NFTA_CHAIN_TYPE, "filter");
    push_be_u32_attr(&mut body, NFTA_CHAIN_FLAGS, NFT_CHAIN_BASE);
    frame(
        (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWCHAIN,
        if multipart { NLM_F_MULTI } else { 0 },
        seq,
        &body,
    )
}

fn attr_string(attrs: &[u8], kind: u16) -> Option<&str> {
    let bytes = find_attr(attrs, kind)?;
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    core::str::from_utf8(bytes).ok()
}

fn build_nft_get(net_ns_id: u64, kind: u16, flags: u16, seq: u32, request: &[u8]) -> Vec<Vec<u8>> {
    let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
    let attrs = &request[NLMSG_HDRLEN + 4..];
    let requested_table = attr_string(attrs, NFTA_TABLE_NAME);
    let requested_chain = attr_string(attrs, NFTA_CHAIN_NAME);
    let ruleset = if net_ns_id == 0 {
        crate::netfilter::filter::filter().snapshot()
    } else {
        crate::netfilter::namespace::get(net_ns_id)
            .filter
            .snapshot()
    };
    let mut out = Vec::new();
    match kind {
        NFT_MSG_GETTABLE => {
            for (table_index, table) in ruleset.iter().enumerate() {
                if requested_table.is_none_or(|name| name == table.name) {
                    out.push(nft_table_record(table, table_index as u64 + 1, seq, dump));
                }
            }
        }
        NFT_MSG_GETCHAIN => {
            for (table_index, table) in ruleset.iter().enumerate() {
                if requested_table.is_some_and(|name| name != table.name) {
                    continue;
                }
                for (chain_index, chain) in table.chains.iter().enumerate() {
                    if requested_chain.is_none_or(|name| name == chain.name) {
                        let handle = ((table_index as u64 + 1) << 32) | (chain_index as u64 + 1);
                        out.push(nft_chain_record(table, chain, handle, seq, dump));
                    }
                }
            }
        }
        _ => {}
    }
    if dump {
        out.push(frame(NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_ne_bytes()));
    } else if out.is_empty() {
        out.push(error(ENOENT, seq, request));
    }
    out
}

fn mutation_error(error: crate::netfilter::filter::RulesetError) -> i32 {
    match error {
        crate::netfilter::filter::RulesetError::AlreadyExists => EEXIST,
        crate::netfilter::filter::RulesetError::NotFound => ENOENT,
        crate::netfilter::filter::RulesetError::NotEmpty => EBUSY,
    }
}

fn mutate_nft(
    net_ns_id: u64,
    message: u16,
    request: &[u8],
    admin: Option<&crate::netfilter::NetfilterAdminHandle>,
) -> i32 {
    let Some(admin) = admin else {
        return EPERM;
    };
    if admin.net_ns_id() != net_ns_id
        || admin
            .check(crate::netfilter::NetfilterRights::RULESET)
            .is_err()
    {
        return EPERM;
    }
    let attrs = &request[NLMSG_HDRLEN + 4..];
    let table_name = match message {
        NFT_MSG_NEWTABLE | NFT_MSG_DELTABLE => attr_string(attrs, NFTA_TABLE_NAME),
        NFT_MSG_NEWCHAIN | NFT_MSG_DELCHAIN => attr_string(attrs, NFTA_CHAIN_TABLE),
        _ => None,
    };
    let Some(table_name) = table_name.filter(|name| !name.is_empty()) else {
        return EINVAL;
    };
    let namespace = (net_ns_id != 0).then(|| crate::netfilter::namespace::get(net_ns_id));
    let filter = namespace
        .as_ref()
        .map(|namespace| &namespace.filter)
        .unwrap_or_else(|| crate::netfilter::filter::filter());
    let result = match message {
        NFT_MSG_NEWTABLE => filter.create_table(table_name),
        NFT_MSG_DELTABLE => filter.delete_table(table_name),
        NFT_MSG_NEWCHAIN | NFT_MSG_DELCHAIN => {
            let Some(chain_name) =
                attr_string(attrs, NFTA_CHAIN_NAME).filter(|name| !name.is_empty())
            else {
                return EINVAL;
            };
            if message == NFT_MSG_NEWCHAIN {
                filter.create_chain(table_name, chain_name)
            } else {
                filter.delete_chain(table_name, chain_name)
            }
        }
        _ => return EOPNOTSUPP,
    };
    result.err().map(mutation_error).unwrap_or(0)
}

fn build_one(
    net_ns_id: u64,
    request: &[u8],
    admin: Option<&crate::netfilter::NetfilterAdminHandle>,
) -> Result<Vec<Vec<u8>>, ()> {
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
    let subsystem = kind >> 8;
    let message = kind & 0xff;
    if subsystem != NFNL_SUBSYS_CTNETLINK && subsystem != NFNL_SUBSYS_NFTABLES {
        return Ok(alloc::vec![error(EOPNOTSUPP, seq, request)]);
    }
    if request.len() < NLMSG_HDRLEN + 4 || request[NLMSG_HDRLEN] != AF_INET {
        return Ok(alloc::vec![error(EINVAL, seq, request)]);
    }
    if subsystem == NFNL_SUBSYS_NFTABLES {
        if matches!(
            message,
            NFT_MSG_NEWTABLE | NFT_MSG_DELTABLE | NFT_MSG_NEWCHAIN | NFT_MSG_DELCHAIN
        ) {
            let errno = mutate_nft(net_ns_id, message, request, admin);
            return Ok(if errno != 0 || flags & NLM_F_ACK != 0 {
                alloc::vec![error(errno, seq, request)]
            } else {
                Vec::new()
            });
        }
        if !matches!(message, NFT_MSG_GETTABLE | NFT_MSG_GETCHAIN) {
            return Ok(alloc::vec![error(EOPNOTSUPP, seq, request)]);
        }
        let mut out = build_nft_get(net_ns_id, message, flags, seq, request);
        if flags & NLM_F_ACK != 0 {
            out.push(error(0, seq, request));
        }
        return Ok(out);
    }
    if message != IPCTNL_MSG_CT_GET {
        return Ok(alloc::vec![error(EOPNOTSUPP, seq, request)]);
    }
    let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
    let snapshot = crate::netfilter::conntrack::snapshot_in(net_ns_id);
    let mut out = if dump {
        let mut replies = snapshot
            .iter()
            .map(|entry| encode_entry(entry, seq, true))
            .collect::<Vec<_>>();
        replies.push(frame(NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_ne_bytes()));
        replies
    } else {
        let attrs = &request[NLMSG_HDRLEN + 4..];
        let requested_id = find_attr(attrs, CTA_ID)
            .filter(|raw| raw.len() == 4)
            .map(|raw| u32::from_be_bytes(raw.try_into().unwrap_or([0; 4])) as u64);
        let requested_tuple = requested_tuple(attrs);
        if requested_id.is_none() && requested_tuple.is_none() {
            return Ok(alloc::vec![error(EINVAL, seq, request)]);
        }
        let found = snapshot.iter().find(|entry| {
            requested_id == Some(entry.id)
                || requested_tuple.is_some_and(|tuple| {
                    tuple.src_ip == entry.orig_src
                        && tuple.dst_ip == entry.orig_dst
                        && tuple.src_port == entry.orig_sport
                        && tuple.dst_port == entry.orig_dport
                        && tuple.proto == entry.l4proto_num
                })
        });
        match found {
            Some(entry) => alloc::vec![encode_entry(entry, seq, false)],
            None => alloc::vec![error(ENOENT, seq, request)],
        }
    };
    if flags & NLM_F_ACK != 0 {
        out.push(error(0, seq, request));
    }
    Ok(out)
}

/// Build replies for every aligned nfnetlink request in one datagram.
pub fn build_replies(datagram: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    build_replies_in(0, datagram)
}

pub fn build_replies_in(net_ns_id: u64, datagram: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    build_replies_authorized(net_ns_id, datagram, None)
}

pub fn build_replies_authorized(
    net_ns_id: u64,
    datagram: &[u8],
    admin: Option<&crate::netfilter::NetfilterAdminHandle>,
) -> Result<Vec<Vec<u8>>, ()> {
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
        replies.extend(build_one(net_ns_id, &remaining[..len], admin)?);
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

    #[test]
    fn point_query_finds_canonical_tuple_and_omits_multi_flag() {
        crate::netfilter::conntrack::__reset_for_test();
        let tracked = crate::netfilter::Tuple {
            src_ip: [192, 0, 2, 1],
            dst_ip: [198, 51, 100, 2],
            src_port: 4242,
            dst_port: 443,
            proto: 6,
        };
        crate::netfilter::conntrack::ct().insert_new(tracked, 0);

        let mut body = alloc::vec![AF_INET, 0, 0, 0];
        let attrs = tuple(
            tracked.src_ip,
            tracked.dst_ip,
            tracked.src_port,
            tracked.dst_port,
            tracked.proto,
        );
        push_attr(&mut body, CTA_TUPLE_ORIG | NLA_F_NESTED, &attrs);
        let query = frame(
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
            NLM_F_REQUEST,
            77,
            &body,
        );
        let replies = build_replies(&query).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            u16::from_ne_bytes(replies[0][4..6].try_into().unwrap()),
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_NEW
        );
        assert_eq!(
            u16::from_ne_bytes(replies[0][6..8].try_into().unwrap()) & NLM_F_MULTI,
            0
        );
    }

    #[test]
    fn missing_point_query_returns_enoent() {
        crate::netfilter::conntrack::__reset_for_test();
        let mut body = alloc::vec![AF_INET, 0, 0, 0];
        push_attr(&mut body, CTA_ID, &99u32.to_be_bytes());
        let query = frame(
            (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET,
            NLM_F_REQUEST,
            78,
            &body,
        );
        let replies = build_replies(&query).unwrap();
        assert_eq!(
            i32::from_ne_bytes(
                replies[0][NLMSG_HDRLEN..NLMSG_HDRLEN + 4]
                    .try_into()
                    .unwrap()
            ),
            -ENOENT
        );
    }
}
