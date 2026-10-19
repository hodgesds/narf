//! nl80211 command permissions through the generic-netlink layer, as Linux
//! `genl_family_rcv_msg` applies each `nl80211_ops` entry's `.flags`.

use super::*;
use narf_net::netlink_generic::{build_replies_with_context, ReplyOptions};

const PERM_NAME: &str = "wlan-perm";
const REQUEST_ACK: u16 = 5; // NLM_F_REQUEST | NLM_F_ACK

fn request(command: u8, flags: u16, attrs: &[u8]) -> Vec<u8> {
    let mut body = alloc::vec![command, 1, 0, 0];
    body.extend_from_slice(attrs);
    let len = 16 + body.len();
    let mut out = Vec::new();
    out.extend_from_slice(&(len as u32).to_ne_bytes());
    out.extend_from_slice(&NL80211_FAMILY_ID.to_ne_bytes());
    out.extend_from_slice(&flags.to_ne_bytes());
    out.extend_from_slice(&7u32.to_ne_bytes());
    out.extend_from_slice(&0u32.to_ne_bytes());
    out.extend_from_slice(&body);
    out
}

/// The first reply's errno (0 for an ACK or a data reply).
fn errno(command: u8, ifindex: u32, context: RequestContext<'_>) -> i32 {
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 3, &ifindex.to_ne_bytes());
    let replies = build_replies_with_context(
        &request(command, REQUEST_ACK, &attrs),
        ReplyOptions::default(),
        context,
    )
    .unwrap();
    let first = &replies[0];
    if u16::from_ne_bytes(first[4..6].try_into().unwrap()) == 2 {
        -i32::from_ne_bytes(first[16..20].try_into().unwrap())
    } else {
        0
    }
}

/// `CTRL_ATTR_OP_FLAGS` of `command` in the nl80211 family description.
fn advertised_flags(command: u8) -> Option<u32> {
    let mut name = b"nl80211".to_vec();
    name.push(0);
    let mut attrs = Vec::new();
    push_attr(&mut attrs, 2, &name);
    let mut msg = request(3, 1, &attrs);
    msg[4..6].copy_from_slice(&0x10u16.to_ne_bytes()); // GENL_ID_CTRL
    let replies =
        build_replies_with_context(&msg, ReplyOptions::default(), RequestContext::default())
            .ok()?;
    let ops = find_attr(&replies[0][20..], 6 | NLA_F_NESTED)?;
    let mut off = 0;
    while off + 4 <= ops.len() {
        let len = u16::from_ne_bytes(ops[off..off + 2].try_into().ok()?) as usize;
        if len < 4 || off + len > ops.len() {
            return None;
        }
        let op = &ops[off + 4..off + len];
        let id = find_attr(op, 1).map(|b| u32::from_ne_bytes(b.try_into().unwrap_or([0; 4])));
        if id == Some(u32::from(command)) {
            return find_attr(op, 2).map(|b| u32::from_ne_bytes(b.try_into().unwrap_or([0; 4])));
        }
        off += align(len);
    }
    None
}

fn smoke_nl80211_command_permissions() -> TestResult {
    register();
    let iface: Arc<dyn crate::WirelessNetIface> = Arc::new(super::InterfaceStub {
        name: PERM_NAME,
        rx: IrqSafeSpinLock::new(None),
        tx: IrqSafeSpinLock::new(None),
    });
    narf_net::iface::register(PERM_NAME, iface.mac(), |_, _| Ok(()));
    crate::registry::register(iface);
    let Some(ifindex) = narf_net::netlink_route::ifindex_for_name(PERM_NAME) else {
        return TestResult::Fail("permission stub has no ifindex");
    };
    const MISSING: u32 = 0x7fff_0000;

    // The family advertises Linux's flags: TRIGGER_SCAN / STOP_AP are
    // GENL_UNS_ADMIN_PERM (0x10), EXTERNAL_AUTH GENL_ADMIN_PERM (0x01),
    // GET_SCAN / GET_INTERFACE carry neither.
    for (command, want) in [(33u8, 0x10u32), (16, 0x10), (127, 0x01), (32, 0), (5, 0)] {
        if advertised_flags(command).map(|f| f & 0x11) != Some(want) {
            return TestResult::Fail("CTRL_ATTR_OP_FLAGS permission bits differ from Linux");
        }
    }

    let nobody = RequestContext::default();
    let root = RequestContext {
        init_net_admin: true,
        net_admin: true,
        ..RequestContext::default()
    };
    // CAP_NET_ADMIN over the netns's owning user namespace only.
    let child_ns_root = RequestContext {
        net_admin: true,
        ..RequestContext::default()
    };
    let own = narf_net::kernel_admin(PERM_NAME).unwrap();
    let delegated = RequestContext {
        admin: Some(&own),
        ..RequestContext::default()
    };
    let other = narf_net::initial_loopback_admin();
    let delegated_elsewhere = RequestContext {
        admin: Some(&other),
        ..RequestContext::default()
    };
    // STOP_AP and EXTERNAL_AUTH stop at -EOPNOTSUPP on a station-only,
    // offload-SME stub *after* the permission check, so that errno proves
    // the request was allowed; -EPERM proves it was refused.
    const STOP_AP: u8 = 16;
    let cases: &[(&'static str, u8, u32, RequestContext<'_>, i32)] = &[
        ("UNS op, no capability", STOP_AP, ifindex, nobody, EPERM),
        ("UNS op, CAP_NET_ADMIN", STOP_AP, ifindex, root, EOPNOTSUPP),
        (
            "UNS op, child-userns capability",
            STOP_AP,
            ifindex,
            child_ns_root,
            EOPNOTSUPP,
        ),
        (
            "UNS op, delegated handle",
            STOP_AP,
            ifindex,
            delegated,
            EOPNOTSUPP,
        ),
        (
            "UNS op, handle for another iface",
            STOP_AP,
            ifindex,
            delegated_elsewhere,
            EPERM,
        ),
        (
            "ADMIN op, no capability",
            EXTERNAL_AUTH,
            ifindex,
            nobody,
            EPERM,
        ),
        (
            "ADMIN op, CAP_NET_ADMIN",
            EXTERNAL_AUTH,
            ifindex,
            root,
            EOPNOTSUPP,
        ),
        (
            "ADMIN op, child-userns capability",
            EXTERNAL_AUTH,
            ifindex,
            child_ns_root,
            EPERM,
        ),
        (
            "ADMIN op, delegated handle",
            EXTERNAL_AUTH,
            ifindex,
            delegated,
            EOPNOTSUPP,
        ),
        // genl_family_rcv_msg orders op lookup → permission → pre_doit.
        (
            "missing device, no capability",
            STOP_AP,
            MISSING,
            nobody,
            EPERM,
        ),
        (
            "missing device, CAP_NET_ADMIN",
            STOP_AP,
            MISSING,
            root,
            ENODEV,
        ),
        (
            "unknown command, no capability",
            0xfe,
            ifindex,
            nobody,
            EOPNOTSUPP,
        ),
        // GET_SCAN is dump-only: a do request is -EOPNOTSUPP from the op table.
        (
            "GET_SCAN as do, no capability",
            GET_SCAN,
            ifindex,
            nobody,
            EOPNOTSUPP,
        ),
        // Flagless ops need nothing.
        (
            "GET_INTERFACE, no capability",
            NL80211_CMD_GET_INTERFACE,
            ifindex,
            nobody,
            0,
        ),
    ];
    for (what, command, index, context, want) in cases {
        if errno(*command, *index, *context) != *want {
            return TestResult::Fail(what);
        }
    }
    // A CAP_NET_ADMIN sender without any delegated handle runs a real scan
    // request through to its ACK.
    if errno(SCAN, ifindex, root) != 0 {
        return TestResult::Fail("CAP_NET_ADMIN TRIGGER_SCAN was not accepted");
    }
    TestResult::Pass
}
kernel_test_in!("wireless/nl80211", smoke_nl80211_command_permissions);
