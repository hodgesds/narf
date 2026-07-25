//! Minimal Linux `NETLINK_AUDIT` control-plane responder.
//!
//! Audit configuration is authority-bearing state, so the compatibility
//! socket exposes status and empty rule enumeration but never treats a Linux
//! uid as permission to mutate it.

extern crate alloc;

use alloc::vec::Vec;

const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_MULTI: u16 = 2;
const NLM_F_ACK: u16 = 4;
const NLM_F_DUMP: u16 = 0x300;

pub const AUDIT_GET: u16 = 1000;
pub const AUDIT_SET: u16 = 1001;
pub const AUDIT_LIST_RULES: u16 = 1013;

const EINVAL: i32 = 22;
const EPERM: i32 = 1;
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
    let mut payload = Vec::with_capacity(4 + request.len());
    payload.extend_from_slice(&(-errno).to_ne_bytes());
    payload.extend_from_slice(request);
    frame(NLMSG_ERROR, 0, seq, &payload)
}

fn status(seq: u32) -> Vec<u8> {
    // Linux struct audit_status. NARF has no global audit collector enabled,
    // so all counters and configuration fields truthfully report zero.
    frame(AUDIT_GET, 0, seq, &[0u8; 44])
}

fn build_one(request: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
    if request.len() < NLMSG_HDRLEN {
        return Err(());
    }
    let declared = u32::from_ne_bytes(request[0..4].try_into().map_err(|_| ())?) as usize;
    if declared < NLMSG_HDRLEN || declared > request.len() {
        return Err(());
    }
    let request = &request[..declared];
    let kind = u16::from_ne_bytes(request[4..6].try_into().map_err(|_| ())?);
    let flags = u16::from_ne_bytes(request[6..8].try_into().map_err(|_| ())?);
    let seq = u32::from_ne_bytes(request[8..12].try_into().map_err(|_| ())?);
    if flags & NLM_F_REQUEST == 0 {
        return Ok(alloc::vec![error(EINVAL, seq, request)]);
    }
    let mut replies = match kind {
        AUDIT_GET => alloc::vec![status(seq)],
        AUDIT_LIST_RULES if flags & NLM_F_DUMP == NLM_F_DUMP => {
            alloc::vec![frame(NLMSG_DONE, NLM_F_MULTI, seq, &0i32.to_ne_bytes())]
        }
        AUDIT_SET => alloc::vec![error(EPERM, seq, request)],
        _ => alloc::vec![error(EOPNOTSUPP, seq, request)],
    };
    if flags & NLM_F_ACK != 0
        && !replies
            .iter()
            .any(|message| message.get(4..6) == Some(&NLMSG_ERROR.to_ne_bytes()))
    {
        replies.push(error(0, seq, request));
    }
    Ok(replies)
}

/// Handle every aligned audit-netlink message in one datagram.
pub fn build_replies(datagram: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
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

    fn request(kind: u16, flags: u16, seq: u32) -> Vec<u8> {
        frame(kind, flags | NLM_F_REQUEST, seq, &[])
    }

    #[test]
    fn get_returns_disabled_status() {
        let replies = build_replies(&request(AUDIT_GET, 0, 7)).unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(
            u16::from_ne_bytes(replies[0][4..6].try_into().unwrap()),
            AUDIT_GET
        );
        assert_eq!(replies[0].len(), align(NLMSG_HDRLEN + 44));
        assert!(replies[0][NLMSG_HDRLEN..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn set_requires_native_authority() {
        let replies = build_replies(&request(AUDIT_SET, 0, 8)).unwrap();
        assert_eq!(
            i32::from_ne_bytes(
                replies[0][NLMSG_HDRLEN..NLMSG_HDRLEN + 4]
                    .try_into()
                    .unwrap()
            ),
            -EPERM
        );
    }
}
