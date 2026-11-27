//! Steam identifies its webhelper by joining /proc/net/tcp with sockfs inodes.
//! Exercise the production procfs hooks, including connections that use rings.

use alloc::{string::String, sync::Arc, vec::Vec};
use narf_filesystem::procfs::{net, poll_once, ProcFs};
use narf_filesystem::{FileOps, FsInstance};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::socket::{
    make_sockaddr_in, make_sockaddr_in6, SockAddr, SocketFile, SocketOp, SocketOpResult, AF_INET,
    AF_INET6, SOCK_STREAM,
};

struct Socket(Arc<SocketFile>);

impl Socket {
    fn new(family: u16) -> Self {
        Self(SocketFile::new(family, SOCK_STREAM))
    }
}

impl Drop for Socket {
    fn drop(&mut self) {
        self.0.unregister();
    }
}

fn address(family: u16, wildcard: bool, port: u16) -> SockAddr {
    if family == AF_INET {
        make_sockaddr_in(if wildcard { 0 } else { 0x7f00_0001 }, port)
    } else {
        let mut ip = [0; 16];
        if !wildcard {
            ip[15] = 1;
        }
        make_sockaddr_in6(ip, port)
    }
}

fn ok(result: SocketOpResult) -> Result<(), &'static str> {
    match result {
        SocketOpResult::Ok(_) => Ok(()),
        _ => Err("socket operation failed"),
    }
}

fn listen(socket: &Socket, family: u16, wildcard: bool) -> Result<SockAddr, &'static str> {
    ok(socket.0.dispatch_op(SocketOp::Bind {
        addr: address(family, wildcard, 0),
    }))?;
    ok(socket.0.dispatch_op(SocketOp::Listen { backlog: 4 }))?;
    let bound = socket.0.local_addr().ok_or("missing local address")?;
    // SockAddr::body begins with the network-order port, after sa_family.
    let port = u16::from_be_bytes([bound.body[0], bound.body[1]]);
    Ok(address(family, false, port))
}

fn accept(listener: &Socket) -> Result<Socket, &'static str> {
    match listener.0.dispatch_op(SocketOp::Accept) {
        SocketOpResult::Accepted { socket, .. } => Ok(Socket(socket)),
        _ => Err("accept failed"),
    }
}

fn table(name: &str) -> Result<String, &'static str> {
    net::register_all();
    let file = ProcFs
        .root()
        .lookup_dir("net")
        .and_then(|dir| dir.lookup(name))
        .ok_or("missing proc net table")?;
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0; 512];
        let n = match poll_once(file.read(bytes.len() as u64, &mut chunk)) {
            Some(Ok(n)) => n,
            _ => return Err("proc net table read failed"),
        };
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > 256 * 1024 {
            return Err("proc net table did not terminate");
        }
    }
    String::from_utf8(bytes).map_err(|_| "invalid proc net text")
}

fn row(text: &str, inode: u64) -> Result<Vec<&str>, &'static str> {
    let mut rows = text.lines().skip(1).filter_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.get(9).and_then(|s| s.parse::<u64>().ok()) == Some(inode)).then_some(fields)
    });
    let result = rows
        .next()
        .ok_or("live socket inode missing from TCP table")?;
    if rows.next().is_some() {
        return Err("socket duplicated between ring and stack snapshots");
    }
    Ok(result)
}

fn identity_case(family: u16, wildcard: bool) -> Result<(), &'static str> {
    let name = if family == AF_INET { "tcp" } else { "tcp6" };
    let listener = Socket::new(family);
    let client = Socket::new(family);
    let destination = listen(&listener, family, wildcard)?;
    let text = table(name)?;
    if row(&text, listener.0.ino())?[3] != "0A" {
        return Err("listener missing LISTEN state");
    }
    if row(&text, client.0.ino()).is_ok() {
        return Err("unconnected socket should not be in TCP table");
    }
    ok(client
        .0
        .dispatch_op(SocketOp::Connect { addr: destination }))?;
    let server = accept(&listener)?;
    ok(client.0.dispatch_op(SocketOp::Send {
        buf: b"steam",
        flags: 0,
        addr: None,
    }))?;

    let text = table(name)?;
    let outgoing = row(&text, client.0.ino())?;
    let incoming = row(&text, server.0.ino())?;
    if outgoing[1] != incoming[2] || outgoing[2] != incoming[1] {
        return Err("TCP connection endpoint names do not match");
    }
    for socket in [&listener, &client, &server] {
        if row(&text, socket.0.ino())?[7] != "4242" {
            return Err("TCP table lost the socket creator UID");
        }
    }
    if outgoing[3] != "01" || incoming[3] != "01" || incoming[4] != "00000000:00000005" {
        return Err("TCP table lost established state or receive queue");
    }
    let client_inode = client.0.ino();
    let server_inode = server.0.ino();
    let listener_inode = listener.0.ino();
    drop(server);
    drop(client);
    drop(listener);
    let text = table(name)?;
    for inode in [client_inode, server_inode, listener_inode] {
        if row(&text, inode).is_ok() {
            return Err("closed socket retained its procfs inode");
        }
    }
    Ok(())
}

pub fn __test_proc_tcp_loopback_identity() -> TestResult {
    crate::abi_test_support::with_setup(|| {
        let task = crate::handlers::current_task_id();
        let previous = crate::handlers::current_fsuid();
        crate::handlers::__test_set_fsids(task, 4242, 4242);
        let result = (|| {
            for family in [AF_INET, AF_INET6] {
                for wildcard in [false, true] {
                    identity_case(family, wildcard)?;
                }
            }
            Ok(())
        })();
        crate::handlers::__test_set_fsids(task, previous, previous);
        result
    })
}

fn smoke_proc_ipv6_headers_match_lsof() -> TestResult {
    crate::abi_test_support::with_setup(|| {
        for name in ["tcp6", "udp6", "raw6"] {
            let text = table(name)?;
            let header: Vec<_> = text
                .lines()
                .next()
                .ok_or("missing header")?
                .split_whitespace()
                .collect();
            if header.len() != 12 || header[2] != "remote_address" || header[11] != "inode" {
                return Err("IPv6 table header rejected by lsof");
            }
        }
        Ok(())
    })
}
kernel_test_in!("userspace/proc_tcp", smoke_proc_ipv6_headers_match_lsof);

#[cfg(feature = "container")]
fn smoke_proc_tcp_loopback_namespace() -> TestResult {
    use crate::socket::{tcp4_loopback_snapshot_in, tcp6_loopback_snapshot_in};
    crate::abi_test_support::with_setup(|| {
        for family in [AF_INET, AF_INET6] {
            let namespace = crate::namespaces::NetNamespace::new_with_loopback();
            let listener = Socket::new(family);
            listener.0.set_net_namespace(namespace.clone());
            let client = Socket::new(family);
            client.0.set_net_namespace(namespace.clone());
            let destination = listen(&listener, family, false)?;
            ok(client
                .0
                .dispatch_op(SocketOp::Connect { addr: destination }))?;
            let server = accept(&listener)?;
            // IPv6 listeners may be stack-backed even for ::1; the local
            // snapshot must contain the two ring-backed connected endpoints.
            let inodes = [client.0.ino(), server.0.ino()];
            let snapshot = |ns| -> Vec<u64> {
                if family == AF_INET {
                    tcp4_loopback_snapshot_in(ns)
                        .iter()
                        .map(|r| r.inode)
                        .collect()
                } else {
                    tcp6_loopback_snapshot_in(ns)
                        .iter()
                        .map(|r| r.inode)
                        .collect()
                }
            };
            let selected = snapshot(namespace.id());
            let initial = snapshot(0);
            if inodes
                .iter()
                .any(|ino| !selected.contains(ino) || initial.contains(ino))
            {
                return Err("loopback TCP snapshot crossed network namespaces");
            }
        }
        Ok(())
    })
}
#[cfg(feature = "container")]
kernel_test_in!("userspace/proc_tcp", smoke_proc_tcp_loopback_namespace);
