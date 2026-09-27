//! Cross-family UDP port reservations.
//!
//! IPv4 and IPv6 retain separate receive-demux tables, but Linux allocates
//! their ports from one effective bind space whenever an IPv6 socket can
//! also receive IPv4. In Linux both `udp_v4_get_port` and
//! `udp_v6_get_port` enter `udp_lib_get_port` (`net/ipv4/udp.c`), which holds
//! the common primary `udp_hslot::lock` across conflict scan and RCU hash
//! insertion, then briefly nests the secondary `hslot2->lock` in that fixed
//! order. NARF mirrors the atomic cross-family decision with this one
//! reservation lock. Family demux locks may call into it, but this module
//! never enters a family table, establishing the fixed order
//! `family table -> RESERVATIONS` and excluding an IPv4/IPv6 ABBA cycle.

use super::*;

#[derive(Clone, Copy)]
pub(super) enum BindAddr {
    V4(u32),
    V6 { addr: [u8; 16], v6only: bool },
}

struct Reservation {
    net_ns_id: u64,
    port: u16,
    addr: BindAddr,
    reuseaddr: bool,
    reuseport: bool,
    uid: u32,
    owner: Weak<SocketFile>,
}

static RESERVATIONS: IrqSafeSpinLock<Vec<Reservation>> = IrqSafeSpinLock::new(Vec::new());

fn mapped_v4(addr: &[u8; 16]) -> Option<u32> {
    (addr[..10] == [0; 10] && addr[10..12] == [0xff, 0xff])
        .then(|| u32::from_be_bytes([addr[12], addr[13], addr[14], addr[15]]))
}

fn cross_family_overlap(a: BindAddr, b: BindAddr) -> bool {
    let (v4, v6) = match (a, b) {
        (BindAddr::V4(v4), BindAddr::V6 { addr, v6only })
        | (BindAddr::V6 { addr, v6only }, BindAddr::V4(v4)) => {
            if v6only {
                return false;
            }
            (v4, addr)
        }
        // Same-family conflicts remain owned by the existing family table.
        _ => return false,
    };
    if v6 == [0; 16] {
        return true;
    }
    mapped_v4(&v6).is_some_and(|mapped| v4 == 0 || mapped == 0 || mapped == v4)
}

pub(super) fn reserve(sock: &Arc<SocketFile>, port: u16, addr: BindAddr) -> Result<(), SockError> {
    let ns = sock.net_ns_id();
    let (reuseaddr, reuseport) = {
        let options = sock.options.lock();
        (options.reuseaddr, options.reuseport)
    };
    let uid = sock.local_cred.lock().uid;
    let mut reservations = RESERVATIONS.lock();
    reservations.retain(|entry| entry.owner.strong_count() != 0);
    let conflict = reservations.iter().any(|entry| {
        entry.net_ns_id == ns
            && entry.port == port
            && cross_family_overlap(entry.addr, addr)
            && !(entry.reuseaddr && reuseaddr)
            && !(entry.reuseport && reuseport && entry.uid == uid)
    });
    if conflict {
        return Err(SockError::AddrInUse);
    }
    reservations.push(Reservation {
        net_ns_id: ns,
        port,
        addr,
        reuseaddr,
        reuseport,
        uid,
        owner: Arc::downgrade(sock),
    });
    Ok(())
}

pub(super) fn release(sock: &SocketFile, port: u16) {
    RESERVATIONS.lock().retain(|entry| {
        !(entry.port == port
            && entry
                .owner
                .upgrade()
                .is_some_and(|owner| core::ptr::eq(Arc::as_ptr(&owner), sock)))
    });
}
