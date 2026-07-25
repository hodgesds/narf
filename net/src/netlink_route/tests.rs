//! Wire-format smokes for the rtnetlink dump responder.

use super::*;
extern crate alloc;
use alloc::vec::Vec;

/// Build a `struct nlmsghdr` request buffer: len is filled to header size,
/// type/flags/seq/pid as given.
fn req(msg_type: u16, seq: u32, pid: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&(NLMSG_HDRLEN as u32).to_le_bytes());
    b.extend_from_slice(&msg_type.to_le_bytes());
    b.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_le_bytes());
    b.extend_from_slice(&seq.to_le_bytes());
    b.extend_from_slice(&pid.to_le_bytes());
    b
}

/// Read the `nlmsghdr` fields off the front of a framed message.
fn hdr_of(msg: &[u8]) -> (u32, u16, u16, u32, u32) {
    let h = parse_hdr(msg).expect("message shorter than a header");
    (h.len, h.msg_type, h.flags, h.seq, h.pid)
}

/// Walk a message's rtattrs (starting after `ifhdr_len` bytes of fixed
/// header) and return the payload of the first attribute of `want_type`.
fn find_rtattr(msg: &[u8], ifhdr_len: usize, want_type: u16) -> Option<Vec<u8>> {
    let mut off = NLMSG_HDRLEN + ifhdr_len;
    let end = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]) as usize;
    while off + 4 <= end {
        let rta_len = u16::from_le_bytes([msg[off], msg[off + 1]]) as usize;
        let rta_type = u16::from_le_bytes([msg[off + 2], msg[off + 3]]);
        if rta_len < 4 || off + rta_len > end {
            break;
        }
        if rta_type == want_type {
            return Some(msg[off + 4..off + rta_len].to_vec());
        }
        off += rta_align(rta_len);
    }
    None
}

#[test]
fn align_helpers_round_to_four() {
    assert_eq!(nlmsg_align(0), 0);
    assert_eq!(nlmsg_align(1), 4);
    assert_eq!(nlmsg_align(4), 4);
    assert_eq!(nlmsg_align(5), 8);
    assert_eq!(rta_align(6), 8);
    // Every framed message length is 4-byte aligned.
    let msgs = build_dump(&req(RTM_GETLINK, 7, 99));
    for m in &msgs {
        assert_eq!(m.len() % NLMSG_ALIGNTO, 0, "message not NLMSG_ALIGN-padded");
    }
}

#[test]
fn getlink_dump_has_loopback_and_terminates() {
    let msgs = build_dump(&req(RTM_GETLINK, 42, 1234));
    assert!(msgs.len() >= 2, "expected >=1 NEWLINK + a DONE");

    // First message is an RTM_NEWLINK with echoed seq/pid and NLM_F_MULTI.
    let (_len, mtype, flags, seq, pid) = hdr_of(&msgs[0]);
    assert_eq!(mtype, RTM_NEWLINK);
    assert_eq!(seq, 42);
    assert_eq!(pid, 0, "reply sender is the kernel netlink endpoint");
    assert_ne!(
        flags & NLM_F_MULTI,
        0,
        "dump entries must carry NLM_F_MULTI"
    );

    // The loopback entry names itself "lo" via IFLA_IFNAME. ifinfomsg is
    // 16 bytes: family/pad/type(2)/index(4)/flags(4)/change(4).
    let name = find_rtattr(&msgs[0], 16, IFLA_IFNAME).expect("first link has IFLA_IFNAME");
    assert_eq!(&name, b"lo\0", "ifindex-1 link is the loopback");
    assert_eq!(
        find_rtattr(&msgs[0], 16, IFLA_OPERSTATE).as_deref(),
        Some(&[IF_OPER_UP][..])
    );
    assert_eq!(
        find_rtattr(&msgs[0], 16, IFLA_QDISC).as_deref(),
        Some(&b"noqueue\0"[..])
    );
    assert_eq!(
        find_rtattr(&msgs[0], 16, IFLA_STATS64)
            .expect("link has IFLA_STATS64")
            .len(),
        25 * 8
    );

    // Last message is NLMSG_DONE.
    let (_l, dtype, _f, dseq, _p) = hdr_of(msgs.last().unwrap());
    assert_eq!(dtype, NLMSG_DONE);
    assert_eq!(dseq, 42, "DONE echoes the request seq");
}

#[test]
fn getaddr_dump_is_well_formed() {
    let msgs = build_dump(&req(RTM_GETADDR, 5, 77));
    assert!(msgs.len() >= 2, "expected >=1 NEWADDR + a DONE");

    // First address is loopback 127.0.0.1/8 with an IFA_LOCAL attribute.
    let (_len, mtype, _flags, seq, _pid) = hdr_of(&msgs[0]);
    assert_eq!(mtype, RTM_NEWADDR);
    assert_eq!(seq, 5);
    // ifaddrmsg is 8 bytes: family/prefixlen/flags/scope/index(4).
    assert_eq!(msgs[0][NLMSG_HDRLEN], AF_INET, "ifa_family = AF_INET");
    assert_eq!(msgs[0][NLMSG_HDRLEN + 1], 8, "loopback prefixlen /8");
    let local = find_rtattr(&msgs[0], 8, IFA_LOCAL).expect("addr has IFA_LOCAL");
    assert_eq!(&local, &[127, 0, 0, 1], "first addr is 127.0.0.1");

    let (_l, dtype, _f, _s, _p) = hdr_of(msgs.last().unwrap());
    assert_eq!(dtype, NLMSG_DONE);
}

#[test]
fn getroute_dump_has_loopback_and_terminates() {
    let msgs = build_dump(&req(RTM_GETROUTE, 19, 88));
    assert!(msgs.len() >= 2, "expected >=1 NEWROUTE + a DONE");

    let (_len, mtype, flags, seq, pid) = hdr_of(&msgs[0]);
    assert_eq!(mtype, RTM_NEWROUTE);
    assert_eq!(flags & NLM_F_MULTI, NLM_F_MULTI);
    assert_eq!(seq, 19);
    assert_eq!(pid, 0);

    // struct rtmsg is 12 bytes. The always-present synthetic loopback route
    // is AF_INET 127.0.0.0/8, local-table, host-scope, with oif=1.
    assert_eq!(msgs[0][NLMSG_HDRLEN], AF_INET);
    assert_eq!(msgs[0][NLMSG_HDRLEN + 1], 8);
    assert_eq!(msgs[0][NLMSG_HDRLEN + 4], crate::route::TABLE_LOCAL);
    assert_eq!(msgs[0][NLMSG_HDRLEN + 6], crate::route::Scope::Host as u8);
    assert_eq!(msgs[0][NLMSG_HDRLEN + 7], RTN_LOCAL);
    assert_eq!(
        find_rtattr(&msgs[0], 12, RTA_DST).as_deref(),
        Some(&[127, 0, 0, 0][..])
    );
    assert_eq!(
        find_rtattr(&msgs[0], 12, RTA_OIF).as_deref(),
        Some(&1u32.to_le_bytes()[..])
    );
    assert_eq!(
        find_rtattr(&msgs[0], 12, RTA_PREFSRC).as_deref(),
        Some(&[127, 0, 0, 1][..])
    );

    let (_l, dtype, _f, dseq, _p) = hdr_of(msgs.last().unwrap());
    assert_eq!(dtype, NLMSG_DONE);
    assert_eq!(dseq, 19);
}

#[test]
fn newneigh_wire_layout_carries_ipv4_destination_and_mac() {
    let msg = build_newneigh(
        &NeighInfo {
            family: AF_INET,
            dst: &[192, 0, 2, 1],
            mac: Some([0x02, 0, 0, 0, 0, 1]),
            ifindex: 3,
            state: NUD_STALE,
            flags: 0,
        },
        31,
        0,
    );
    let (_len, mtype, flags, seq, pid) = hdr_of(&msg);
    assert_eq!(mtype, RTM_NEWNEIGH);
    assert_eq!(flags, NLM_F_MULTI);
    assert_eq!(seq, 31);
    assert_eq!(pid, 0);
    assert_eq!(msg[NLMSG_HDRLEN], AF_INET);
    assert_eq!(
        i32::from_ne_bytes(msg[NLMSG_HDRLEN + 4..NLMSG_HDRLEN + 8].try_into().unwrap()),
        3
    );
    assert_eq!(
        u16::from_ne_bytes(msg[NLMSG_HDRLEN + 8..NLMSG_HDRLEN + 10].try_into().unwrap()),
        NUD_STALE
    );
    assert_eq!(
        find_rtattr(&msg, 12, NDA_DST).as_deref(),
        Some(&[192, 0, 2, 1][..])
    );
    assert_eq!(
        find_rtattr(&msg, 12, NDA_LLADDR).as_deref(),
        Some(&[0x02, 0, 0, 0, 0, 1][..])
    );
}

#[test]
fn getneigh_dump_terminates() {
    let msgs = build_dump(&req(RTM_GETNEIGH, 44, 12));
    assert_eq!(hdr_of(msgs.last().unwrap()).1, NLMSG_DONE);
    assert!(msgs
        .iter()
        .all(|msg| matches!(hdr_of(msg).1, RTM_NEWNEIGH | NLMSG_DONE)));
}

#[test]
fn getrule_dump_has_linux_default_ipv4_rules() {
    let msgs = build_dump(&req(RTM_GETRULE, 52, 9));
    assert_eq!(msgs.len(), 4);
    let expected = [
        (crate::route::TABLE_LOCAL, 0u32),
        (crate::route::TABLE_MAIN, 32_766u32),
        (crate::route::TABLE_DEFAULT, 32_767u32),
    ];
    for (msg, (table, priority)) in msgs.iter().zip(expected) {
        assert_eq!(hdr_of(msg).1, RTM_NEWRULE);
        assert_eq!(msg[NLMSG_HDRLEN], AF_INET);
        assert_eq!(msg[NLMSG_HDRLEN + 4], table);
        assert_eq!(
            find_rtattr(msg, 12, FRA_PRIORITY).as_deref(),
            Some(&priority.to_ne_bytes()[..])
        );
        assert_eq!(
            find_rtattr(msg, 12, FRA_TABLE).as_deref(),
            Some(&(table as u32).to_ne_bytes()[..])
        );
    }
    assert_eq!(hdr_of(msgs.last().unwrap()).1, NLMSG_DONE);
}

#[test]
fn getqdisc_reports_noqueue_for_loopback() {
    let msgs = build_dump(&req(RTM_GETQDISC, 61, 4));
    assert!(msgs.len() >= 2);
    assert_eq!(hdr_of(&msgs[0]).1, RTM_NEWQDISC);
    assert_eq!(
        i32::from_ne_bytes(
            msgs[0][NLMSG_HDRLEN + 4..NLMSG_HDRLEN + 8]
                .try_into()
                .unwrap()
        ),
        1
    );
    assert_eq!(
        find_rtattr(&msgs[0], 20, TCA_KIND).as_deref(),
        Some(&b"noqueue\0"[..])
    );
    assert_eq!(hdr_of(msgs.last().unwrap()).1, NLMSG_DONE);
}

#[test]
fn absent_optional_collections_return_empty_completed_dumps() {
    for msg_type in [
        RTM_GETTCLASS,
        RTM_GETTFILTER,
        RTM_GETACTION,
        RTM_GETADDRLABEL,
        RTM_GETMDB,
        RTM_GETNEXTHOP,
    ] {
        let msgs = build_dump(&req(msg_type, msg_type as u32, 0));
        assert_eq!(msgs.len(), 1, "type {msg_type} was not an empty dump");
        let hdr = parse_hdr(&msgs[0]).unwrap();
        assert_eq!(hdr.msg_type, NLMSG_DONE);
        assert_eq!(hdr.seq, msg_type as u32);
    }
}

#[test]
fn unsupported_request_yields_eopnotsupp_error() {
    // RTM_GETLINK is 18; use a bogus type the responder doesn't handle.
    let bogus: u16 = 999;
    let msgs = build_dump(&req(bogus, 8, 55));
    assert_eq!(msgs.len(), 1, "error dump is a single message");
    let (_len, mtype, _flags, seq, pid) = hdr_of(&msgs[0]);
    assert_eq!(mtype, NLMSG_ERROR);
    assert_eq!(seq, 8);
    assert_eq!(pid, 0);
    // nlmsgerr.error is the first i32 of the payload: -EOPNOTSUPP.
    let err = i32::from_le_bytes([
        msgs[0][NLMSG_HDRLEN],
        msgs[0][NLMSG_HDRLEN + 1],
        msgs[0][NLMSG_HDRLEN + 2],
        msgs[0][NLMSG_HDRLEN + 3],
    ]);
    assert_eq!(err, -EOPNOTSUPP, "error payload carries -EOPNOTSUPP");
}

#[test]
fn batched_requests_keep_sequence_and_ack_independent() {
    let mut first = req(RTM_GETLINK, 101, 77);
    first[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK).to_le_bytes());
    let second = req(RTM_GETADDR, 202, 77);
    first.extend_from_slice(&second);

    let replies = build_replies(&first).expect("valid batched datagram");
    assert!(replies.iter().any(|m| {
        let h = parse_hdr(m).unwrap();
        h.msg_type == RTM_NEWLINK && h.seq == 101
    }));
    assert!(replies.iter().any(|m| {
        let h = parse_hdr(m).unwrap();
        h.msg_type == NLMSG_ERROR
            && h.seq == 101
            && i32::from_le_bytes(m[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap()) == 0
    }));
    assert!(replies.iter().any(|m| {
        let h = parse_hdr(m).unwrap();
        h.msg_type == RTM_NEWADDR && h.seq == 202
    }));
}

#[test]
fn malformed_batched_message_length_is_rejected() {
    let mut message = req(RTM_GETLINK, 1, 0);
    message[0..4].copy_from_slice(&15u32.to_le_bytes());
    assert!(build_replies(&message).is_err());

    message[0..4].copy_from_slice(&1024u32.to_le_bytes());
    assert!(build_replies(&message).is_err());
}
