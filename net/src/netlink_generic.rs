//! Linux generic-netlink control-family responder.
//!
//! `libnl` and tools such as `iw` discover generic-netlink families by
//! sending `CTRL_CMD_GETFAMILY` to `GENL_ID_CTRL`. NARF currently publishes
//! only the mandatory `nlctrl` family; unknown names receive `ENOENT`.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use narf_lib::sync::IrqSafeSpinLock;

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_MULTI: u16 = 2;
const NLM_F_ACK: u16 = 4;
const NLM_F_CAPPED: u16 = 0x100;
const NLM_F_ACK_TLVS: u16 = 0x200;
const NLM_F_DUMP: u16 = 0x300;

pub const GENL_ID_CTRL: u16 = 0x10;
pub const CTRL_CMD_NEWFAMILY: u8 = 1;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_VERSION: u8 = 2;

const CTRL_ATTR_FAMILY_ID: u16 = 1;
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
const CTRL_ATTR_VERSION: u16 = 3;
const CTRL_ATTR_HDRSIZE: u16 = 4;
const CTRL_ATTR_MAXATTR: u16 = 5;
const CTRL_ATTR_OPS: u16 = 6;
const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
const CTRL_ATTR_OP_ID: u16 = 1;
const CTRL_ATTR_OP_FLAGS: u16 = 2;
const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !(3 << 14);
const GENL_CMD_CAP_DO: u32 = 1 << 1;
const GENL_CMD_CAP_DUMP: u32 = 1 << 2;
const CTRL_MCAST_GRP_NOTIFY: u32 = 16;
const ENOENT: i32 = 2;
const EINVAL: i32 = 22;
const EOPNOTSUPP: i32 = 95;
const NLMSGERR_ATTR_MSG: u16 = 1;

/// One command advertised by a registered generic-netlink family.
#[derive(Copy, Clone, Debug)]
pub struct GenlOperation {
    pub command: u8,
    pub flags: u32,
}

/// One multicast group advertised by a registered generic-netlink family.
#[derive(Copy, Clone, Debug)]
pub struct GenlMulticastGroup {
    pub name: &'static str,
    pub id: u32,
}

/// One family response before generic-netlink framing.
#[derive(Clone, Debug)]
pub struct GenlReply {
    pub command: u8,
    pub attrs: Vec<u8>,
}

/// Family callback. The generic-netlink layer adds the version header and
/// netlink framing to each returned response.
pub type GenlHandler = fn(command: u8, attrs: &[u8], dump: bool) -> Result<Vec<GenlReply>, i32>;

/// Static description of a generic-netlink family supplied by a subsystem.
#[derive(Copy, Clone, Debug)]
pub struct GenlFamily {
    pub id: u16,
    pub name: &'static str,
    pub version: u8,
    pub max_attr: u32,
    pub operations: &'static [GenlOperation],
    pub groups: &'static [GenlMulticastGroup],
    pub handler: GenlHandler,
}

static FAMILIES: IrqSafeSpinLock<Vec<GenlFamily>> = IrqSafeSpinLock::new(Vec::new());

/// Register a non-control generic-netlink family. Duplicate names or IDs are
/// rejected, making repeated init calls harmless and family routing unambiguous.
pub fn register_family(family: GenlFamily) -> bool {
    if family.id <= GENL_ID_CTRL || family.name.is_empty() {
        return false;
    }
    let mut families = FAMILIES.lock();
    if families
        .iter()
        .any(|known| known.id == family.id || known.name == family.name)
    {
        return false;
    }
    families.push(family);
    true
}

fn align(len: usize) -> usize {
    (len + 3) & !3
}

fn push_attr(body: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = (4 + payload.len()) as u16;
    body.extend_from_slice(&len.to_ne_bytes());
    body.extend_from_slice(&kind.to_ne_bytes());
    body.extend_from_slice(payload);
    body.resize(align(body.len()), 0);
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
    let mut body = Vec::new();
    body.extend_from_slice(&(-errno).to_ne_bytes());
    body.extend_from_slice(request);
    if request.len() < NLMSG_HDRLEN {
        body.resize(4 + NLMSG_HDRLEN, 0);
    }
    frame(NLMSG_ERROR, 0, seq, &body)
}

fn family_description(family: &GenlFamily, seq: u32, multipart: bool) -> Vec<u8> {
    let mut body = vec![CTRL_CMD_NEWFAMILY, CTRL_VERSION, 0, 0];
    push_attr(&mut body, CTRL_ATTR_FAMILY_ID, &family.id.to_ne_bytes());
    let mut name = family.name.as_bytes().to_vec();
    name.push(0);
    push_attr(&mut body, CTRL_ATTR_FAMILY_NAME, &name);
    push_attr(
        &mut body,
        CTRL_ATTR_VERSION,
        &(family.version as u32).to_ne_bytes(),
    );
    push_attr(&mut body, CTRL_ATTR_HDRSIZE, &0u32.to_ne_bytes());
    push_attr(&mut body, CTRL_ATTR_MAXATTR, &family.max_attr.to_ne_bytes());

    let mut operations = Vec::new();
    for (index, descriptor) in family.operations.iter().enumerate() {
        let mut operation = Vec::new();
        push_attr(
            &mut operation,
            CTRL_ATTR_OP_ID,
            &(descriptor.command as u32).to_ne_bytes(),
        );
        push_attr(
            &mut operation,
            CTRL_ATTR_OP_FLAGS,
            &descriptor.flags.to_ne_bytes(),
        );
        push_attr(
            &mut operations,
            (index as u16 + 1) | NLA_F_NESTED,
            &operation,
        );
    }
    push_attr(&mut body, CTRL_ATTR_OPS | NLA_F_NESTED, &operations);

    let mut groups = Vec::new();
    for (index, descriptor) in family.groups.iter().enumerate() {
        let mut group = Vec::new();
        let mut name = descriptor.name.as_bytes().to_vec();
        name.push(0);
        push_attr(&mut group, CTRL_ATTR_MCAST_GRP_NAME, &name);
        push_attr(
            &mut group,
            CTRL_ATTR_MCAST_GRP_ID,
            &descriptor.id.to_ne_bytes(),
        );
        push_attr(&mut groups, (index as u16 + 1) | NLA_F_NESTED, &group);
    }
    push_attr(&mut body, CTRL_ATTR_MCAST_GROUPS | NLA_F_NESTED, &groups);
    frame(
        GENL_ID_CTRL,
        if multipart { NLM_F_MULTI } else { 0 },
        seq,
        &body,
    )
}

fn unsupported_control(_: u8, _: &[u8], _: bool) -> Result<Vec<GenlReply>, i32> {
    Err(EOPNOTSUPP)
}

const CONTROL_OPERATIONS: &[GenlOperation] = &[GenlOperation {
    command: CTRL_CMD_GETFAMILY,
    flags: GENL_CMD_CAP_DO | GENL_CMD_CAP_DUMP,
}];
const CONTROL_GROUPS: &[GenlMulticastGroup] = &[GenlMulticastGroup {
    name: "notify",
    id: CTRL_MCAST_GRP_NOTIFY,
}];
const CONTROL_FAMILY: GenlFamily = GenlFamily {
    id: GENL_ID_CTRL,
    name: "nlctrl",
    version: CTRL_VERSION,
    max_attr: CTRL_ATTR_MAXATTR as u32,
    operations: CONTROL_OPERATIONS,
    groups: CONTROL_GROUPS,
    handler: unsupported_control,
};

fn requested_attr(request: &[u8], requested_kind: u16) -> Option<&[u8]> {
    let mut off = NLMSG_HDRLEN + 4;
    while off + 4 <= request.len() {
        let len = u16::from_ne_bytes(request[off..off + 2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(request[off + 2..off + 4].try_into().ok()?) & NLA_TYPE_MASK;
        if len < 4 || off + len > request.len() {
            return None;
        }
        if kind == requested_kind {
            return Some(&request[off + 4..off + len]);
        }
        off += align(len);
    }
    None
}

fn build_one(request: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    if request.len() < NLMSG_HDRLEN + 4 {
        return Err(());
    }
    let len = u32::from_ne_bytes(request[0..4].try_into().map_err(|_| ())?) as usize;
    if len < NLMSG_HDRLEN + 4 || len > request.len() {
        return Err(());
    }
    let kind = u16::from_ne_bytes(request[4..6].try_into().map_err(|_| ())?);
    let flags = u16::from_ne_bytes(request[6..8].try_into().map_err(|_| ())?);
    let seq = u32::from_ne_bytes(request[8..12].try_into().map_err(|_| ())?);
    let command = request[NLMSG_HDRLEN];
    let request = &request[..len];
    if kind != GENL_ID_CTRL {
        let family = FAMILIES
            .lock()
            .iter()
            .find(|family| family.id == kind)
            .copied();
        let Some(family) = family else {
            return Ok(vec![error(EOPNOTSUPP, seq, request)]);
        };
        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        let mut out = match (family.handler)(command, &request[NLMSG_HDRLEN + 4..], dump) {
            Ok(payloads) => payloads
                .into_iter()
                .map(|reply| {
                    let mut body = vec![reply.command, family.version, 0, 0];
                    body.extend_from_slice(&reply.attrs);
                    frame(family.id, if dump { NLM_F_MULTI } else { 0 }, seq, &body)
                })
                .collect::<Vec<_>>(),
            Err(errno) => vec![error(errno, seq, request)],
        };
        if dump
            && !matches!(out.first(), Some(message) if message.get(4..6) == Some(&NLMSG_ERROR.to_ne_bytes()))
        {
            out.push(frame(NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_ne_bytes()));
        }
        if flags & NLM_F_ACK != 0
            && !out
                .iter()
                .any(|message| message.get(4..6) == Some(&NLMSG_ERROR.to_ne_bytes()))
        {
            out.push(error(0, seq, request));
        }
        return Ok(out);
    }
    if command != CTRL_CMD_GETFAMILY {
        return Ok(vec![error(EOPNOTSUPP, seq, request)]);
    }

    let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
    let mut out = Vec::new();
    if dump {
        out.push(family_description(&CONTROL_FAMILY, seq, true));
        for family in FAMILIES.lock().iter() {
            out.push(family_description(family, seq, true));
        }
        out.push(frame(NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_ne_bytes()));
    } else {
        let name = requested_attr(request, CTRL_ATTR_FAMILY_NAME);
        let family_id = requested_attr(request, CTRL_ATTR_FAMILY_ID)
            .filter(|raw| raw.len() == 2)
            .map(|raw| u16::from_ne_bytes(raw.try_into().unwrap_or([0; 2])));
        let registered = FAMILIES
            .lock()
            .iter()
            .find(|family| {
                family_id == Some(family.id)
                    || name.is_some_and(|requested| {
                        requested.strip_suffix(&[0]).unwrap_or(requested) == family.name.as_bytes()
                    })
            })
            .copied();
        if name.is_none() && family_id.is_none() {
            out.push(error(EINVAL, seq, request));
            return Ok(out);
        }
        if name.is_some_and(|name| name == b"nlctrl" || name == b"nlctrl\0")
            || family_id == Some(GENL_ID_CTRL)
        {
            out.push(family_description(&CONTROL_FAMILY, seq, false));
        } else if let Some(family) = registered {
            out.push(family_description(&family, seq, false));
        } else {
            out.push(error(ENOENT, seq, request));
        }
    }
    if flags & NLM_F_ACK != 0
        && !out
            .iter()
            .any(|message| message.get(4..6) == Some(&NLMSG_ERROR.to_ne_bytes()))
    {
        out.push(error(0, seq, request));
    }
    Ok(out)
}

/// Handle every aligned generic-netlink request in one datagram.
pub fn build_replies(datagram: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    build_replies_with_options(datagram, ReplyOptions::default())
}

#[derive(Copy, Clone, Debug, Default)]
pub struct ReplyOptions {
    pub ext_ack: bool,
    pub cap_ack: bool,
}

pub fn build_replies_with_options(
    datagram: &[u8],
    options: ReplyOptions,
) -> Result<Vec<Vec<u8>>, ()> {
    let mut offset = 0usize;
    let mut replies = Vec::new();
    while offset < datagram.len() {
        let remaining = &datagram[offset..];
        if remaining.len() < NLMSG_HDRLEN {
            return Err(());
        }
        let len = u32::from_ne_bytes(remaining[0..4].try_into().map_err(|_| ())?) as usize;
        if len < NLMSG_HDRLEN + 4 || len > remaining.len() {
            return Err(());
        }
        replies.extend(build_one(&remaining[..len])?);
        let step = align(len);
        if step > remaining.len() {
            if len == remaining.len() {
                offset = datagram.len();
            } else {
                return Err(());
            }
        } else {
            offset += step;
        }
    }
    for reply in &mut replies {
        if options.cap_ack {
            cap_acknowledgement(reply);
        }
        if options.ext_ack {
            append_extended_ack(reply);
        }
    }
    Ok(replies)
}

fn cap_acknowledgement(message: &mut Vec<u8>) {
    if message.len() < NLMSG_HDRLEN + 4 + NLMSG_HDRLEN {
        return;
    }
    let kind = u16::from_ne_bytes(message[4..6].try_into().unwrap_or([0; 2]));
    if kind != NLMSG_ERROR {
        return;
    }
    let len = NLMSG_HDRLEN + 4 + NLMSG_HDRLEN;
    message.truncate(len);
    message[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
    let flags = u16::from_ne_bytes(message[6..8].try_into().unwrap_or([0; 2])) | NLM_F_CAPPED;
    message[6..8].copy_from_slice(&flags.to_ne_bytes());
}

fn append_extended_ack(message: &mut Vec<u8>) {
    if message.len() < NLMSG_HDRLEN + 4 {
        return;
    }
    let kind = u16::from_ne_bytes(message[4..6].try_into().unwrap_or([0; 2]));
    let errno = i32::from_ne_bytes(
        message[NLMSG_HDRLEN..NLMSG_HDRLEN + 4]
            .try_into()
            .unwrap_or([0; 4]),
    );
    if kind != NLMSG_ERROR || errno >= 0 {
        return;
    }
    let text: &[u8] = match -errno {
        ENOENT => b"generic-netlink family does not exist\0",
        EOPNOTSUPP => b"generic-netlink command not supported\0",
        _ => b"generic-netlink request failed\0",
    };
    let declared = u32::from_ne_bytes(message[0..4].try_into().unwrap_or([0; 4])) as usize;
    message.truncate(declared);
    message.resize(align(message.len()), 0);
    push_attr(message, NLMSGERR_ATTR_MSG, text);
    let new_len = message.len() as u32;
    message[0..4].copy_from_slice(&new_len.to_ne_bytes());
    let flags = u16::from_ne_bytes(message[6..8].try_into().unwrap_or([0; 2])) | NLM_F_ACK_TLVS;
    message[6..8].copy_from_slice(&flags.to_ne_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: Option<&[u8]>, flags: u16) -> Vec<u8> {
        let mut body = vec![CTRL_CMD_GETFAMILY, CTRL_VERSION, 0, 0];
        if let Some(name) = name {
            push_attr(&mut body, CTRL_ATTR_FAMILY_NAME, name);
        }
        let mut msg = frame(GENL_ID_CTRL, flags, 77, &body);
        let exact = u32::from_ne_bytes(msg[0..4].try_into().unwrap()) as usize;
        msg.truncate(exact);
        msg
    }

    #[test]
    fn resolves_control_family_by_name() {
        let replies = build_replies(&request(Some(b"nlctrl\0"), 1)).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            u16::from_ne_bytes(replies[0][4..6].try_into().unwrap()),
            GENL_ID_CTRL
        );
        assert!(replies[0].windows(7).any(|w| w == b"nlctrl\0"));
    }

    #[test]
    fn unknown_family_returns_enoent() {
        let replies = build_replies(&request(Some(b"nl80211\0"), 1)).unwrap();
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
    fn resolves_control_family_by_id() {
        let mut body = vec![CTRL_CMD_GETFAMILY, CTRL_VERSION, 0, 0];
        push_attr(&mut body, CTRL_ATTR_FAMILY_ID, &GENL_ID_CTRL.to_ne_bytes());
        let request = frame(GENL_ID_CTRL, 1, 78, &body);
        let replies = build_replies(&request).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            u16::from_ne_bytes(replies[0][4..6].try_into().unwrap()),
            GENL_ID_CTRL
        );
        assert!(replies[0].windows(7).any(|window| window == b"nlctrl\0"));
    }

    #[test]
    fn family_description_advertises_ops_and_notify_group() {
        let replies = build_replies(&request(Some(b"nlctrl\0"), 1)).unwrap();
        let reply = &replies[0];
        assert!(reply.windows(7).any(|window| window == b"notify\0"));

        let attrs = &reply[NLMSG_HDRLEN + 4..];
        let mut off = 0;
        let mut saw_ops = false;
        let mut saw_groups = false;
        while off + 4 <= attrs.len() {
            let len = u16::from_ne_bytes(attrs[off..off + 2].try_into().unwrap()) as usize;
            if len < 4 || off + len > attrs.len() {
                break;
            }
            let kind = u16::from_ne_bytes(attrs[off + 2..off + 4].try_into().unwrap());
            saw_ops |= kind == CTRL_ATTR_OPS | NLA_F_NESTED;
            saw_groups |= kind == CTRL_ATTR_MCAST_GROUPS | NLA_F_NESTED;
            off += align(len);
        }
        assert!(saw_ops);
        assert!(saw_groups);
    }

    #[test]
    fn unknown_family_supports_capped_extended_ack() {
        let request = request(Some(b"nl80211\0"), 1);
        let replies = build_replies_with_options(
            &request,
            ReplyOptions {
                ext_ack: true,
                cap_ack: true,
            },
        )
        .unwrap();
        let flags = u16::from_ne_bytes(replies[0][6..8].try_into().unwrap());
        assert_ne!(flags & NLM_F_CAPPED, 0);
        assert_ne!(flags & NLM_F_ACK_TLVS, 0);
        assert!(replies[0]
            .windows(b"generic-netlink family does not exist\0".len())
            .any(|window| window == b"generic-netlink family does not exist\0"));
    }

    #[test]
    fn dump_terminates() {
        let replies = build_replies(&request(None, 1 | NLM_F_DUMP)).unwrap();
        assert_eq!(replies.len(), 2);
        assert_eq!(
            u16::from_ne_bytes(replies[1][4..6].try_into().unwrap()),
            NLMSG_DONE
        );
    }

    #[test]
    fn batched_requests_preserve_sequences() {
        let mut first = request(Some(b"nlctrl\0"), 1);
        first[8..12].copy_from_slice(&101u32.to_ne_bytes());
        first.resize(align(first.len()), 0);
        let mut second = request(Some(b"nlctrl\0"), 1);
        second[8..12].copy_from_slice(&202u32.to_ne_bytes());
        first.extend_from_slice(&second);

        let replies = build_replies(&first).unwrap();
        assert_eq!(replies.len(), 2);
        assert_eq!(
            u32::from_ne_bytes(replies[0][8..12].try_into().unwrap()),
            101
        );
        assert_eq!(
            u32::from_ne_bytes(replies[1][8..12].try_into().unwrap()),
            202
        );
    }

    #[test]
    fn malformed_batch_length_is_rejected() {
        let mut request = request(Some(b"nlctrl\0"), 1);
        request[0..4].copy_from_slice(&15u32.to_ne_bytes());
        assert!(build_replies(&request).is_err());
    }

    #[test]
    fn registered_family_is_discoverable_and_dispatched() {
        fn handler(command: u8, _: &[u8], _: bool) -> Result<Vec<GenlReply>, i32> {
            Ok(vec![GenlReply {
                command: command + 1,
                attrs: vec![8, 0, 1, 0, 42, 0, 0, 0],
            }])
        }
        static OPS: &[GenlOperation] = &[GenlOperation {
            command: 9,
            flags: GENL_CMD_CAP_DO,
        }];
        let _ = register_family(GenlFamily {
            id: 0x30,
            name: "narf-test",
            version: 1,
            max_attr: 1,
            operations: OPS,
            groups: &[],
            handler,
        });

        let lookup = request(Some(b"narf-test\0"), 1);
        let replies = build_replies(&lookup).unwrap();
        assert!(replies[0]
            .windows(10)
            .any(|window| window == b"narf-test\0"));

        let mut body = vec![9, 1, 0, 0];
        push_attr(&mut body, 1, &7u32.to_ne_bytes());
        let family_request = frame(0x30, 1, 303, &body);
        let replies = build_replies(&family_request).unwrap();
        assert_eq!(
            u16::from_ne_bytes(replies[0][4..6].try_into().unwrap()),
            0x30
        );
        assert_eq!(replies[0][NLMSG_HDRLEN], 10);
        assert_eq!(
            u32::from_ne_bytes(replies[0][8..12].try_into().unwrap()),
            303
        );
    }
}
