//! Linux generic-netlink control-family responder.
//!
//! `libnl` and tools such as `iw` discover generic-netlink families by
//! sending `CTRL_CMD_GETFAMILY` to `GENL_ID_CTRL`. NARF currently publishes
//! only the mandatory `nlctrl` family; unknown names receive `ENOENT`.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_MULTI: u16 = 2;
const NLM_F_ACK: u16 = 4;
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
const ENOENT: i32 = 2;
const EOPNOTSUPP: i32 = 95;

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
    let echoed = request.len().min(NLMSG_HDRLEN);
    body.extend_from_slice(&request[..echoed]);
    body.resize(4 + NLMSG_HDRLEN, 0);
    frame(NLMSG_ERROR, 0, seq, &body)
}

fn family(seq: u32, multipart: bool) -> Vec<u8> {
    let mut body = vec![CTRL_CMD_NEWFAMILY, CTRL_VERSION, 0, 0];
    push_attr(&mut body, CTRL_ATTR_FAMILY_ID, &GENL_ID_CTRL.to_ne_bytes());
    push_attr(&mut body, CTRL_ATTR_FAMILY_NAME, b"nlctrl\0");
    push_attr(
        &mut body,
        CTRL_ATTR_VERSION,
        &(CTRL_VERSION as u32).to_ne_bytes(),
    );
    push_attr(&mut body, CTRL_ATTR_HDRSIZE, &0u32.to_ne_bytes());
    push_attr(
        &mut body,
        CTRL_ATTR_MAXATTR,
        &(CTRL_ATTR_MAXATTR as u32).to_ne_bytes(),
    );
    frame(
        GENL_ID_CTRL,
        if multipart { NLM_F_MULTI } else { 0 },
        seq,
        &body,
    )
}

fn requested_name(request: &[u8]) -> Option<&[u8]> {
    let mut off = NLMSG_HDRLEN + 4;
    while off + 4 <= request.len() {
        let len = u16::from_ne_bytes(request[off..off + 2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(request[off + 2..off + 4].try_into().ok()?);
        if len < 4 || off + len > request.len() {
            return None;
        }
        if kind == CTRL_ATTR_FAMILY_NAME {
            return Some(&request[off + 4..off + len]);
        }
        off += align(len);
    }
    None
}

/// Handle one generic-netlink datagram.
pub fn build_replies(request: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
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
    if kind != GENL_ID_CTRL || command != CTRL_CMD_GETFAMILY {
        return Ok(vec![error(EOPNOTSUPP, seq, request)]);
    }

    let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
    let mut out = Vec::new();
    if flags & NLM_F_ACK != 0 {
        out.push(error(0, seq, request));
    }
    if dump {
        out.push(family(seq, true));
        out.push(frame(NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_ne_bytes()));
    } else {
        let name = requested_name(request).unwrap_or_default();
        if name == b"nlctrl" || name == b"nlctrl\0" {
            out.push(family(seq, false));
        } else {
            out.push(error(ENOENT, seq, request));
        }
    }
    Ok(out)
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
    fn dump_terminates() {
        let replies = build_replies(&request(None, 1 | NLM_F_DUMP)).unwrap();
        assert_eq!(replies.len(), 2);
        assert_eq!(
            u16::from_ne_bytes(replies[1][4..6].try_into().unwrap()),
            NLMSG_DONE
        );
    }
}
