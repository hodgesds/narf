use super::*;
use alloc::vec;
use narf_net::netlink_generic::DeferredReplySink;

fn deferred_ack_is_bound_to_the_exact_socket_across_close_and_port_reuse() -> TestResult {
    let socket = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if !matches!(
        socket.dispatch_op(SocketOp::Bind {
            addr: SocketFile::netlink_sockaddr(0, 0),
        }),
        SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("deferred socket binding");
    }
    let portid = socket.netlink_portid.load(Ordering::Acquire);
    let endpoint = GenericReplyEndpoint::capture(&socket, portid);
    let mut ack = vec![0; 36];
    ack[..4].copy_from_slice(&36u32.to_ne_bytes());
    ack[4..6].copy_from_slice(&2u16.to_ne_bytes());
    ack[8..12].copy_from_slice(&0x1234_5678u32.to_ne_bytes());
    if !endpoint.current() || endpoint.deliver(ack.clone()) != Ok(()) {
        return TestResult::Fail("live exact socket refused actual completion");
    }
    let mut bytes = [0; 64];
    if !matches!(
        socket.dispatch_op(SocketOp::Recv {
            buf: &mut bytes,
            flags: 0,
        }),
        SocketOpResult::Received { n: 36, .. }
    ) || bytes[8..12] != 0x1234_5678u32.to_ne_bytes()
        || bytes[12..16] != portid.to_ne_bytes()
        || socket
            .netlink_recv_groups
            .lock()
            .values()
            .any(|group| *group != 0)
    {
        return TestResult::Fail("deferred ACK lost sequence, sender port or unicast group");
    }
    socket.set_net_ns_id(endpoint.namespace.wrapping_add(77));
    if endpoint.current() || endpoint.deliver(ack.clone()) != Err(111) {
        return TestResult::Fail("deferred endpoint ignored socket namespace identity");
    }
    drop(socket);
    let replacement = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if !matches!(
        replacement.dispatch_op(SocketOp::Bind {
            addr: SocketFile::netlink_sockaddr(portid, 0),
        }),
        SocketOpResult::Ok(_)
    ) {
        return TestResult::Fail("closed deferred socket retained its port binding");
    }
    if endpoint.current()
        || endpoint.deliver(ack.clone()) != Err(111)
        || !matches!(
            replacement.dispatch_op(SocketOp::Recv {
                buf: &mut bytes,
                flags: 0,
            }),
            SocketOpResult::Err(SockError::WouldBlock)
        )
    {
        return TestResult::Fail("old completion reached a rebound port's new file");
    }
    let current = GenericReplyEndpoint::capture(&replacement, portid);
    if !current.current()
        || current.deliver(ack) != Ok(())
        || !matches!(
            replacement.dispatch_op(SocketOp::Recv {
                buf: &mut bytes,
                flags: 0,
            }),
            SocketOpResult::Received { n: 36, .. }
        )
    {
        return TestResult::Fail("replacement's own exact completion was suppressed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    deferred_ack_is_bound_to_the_exact_socket_across_close_and_port_reuse
);

fn native_socket_source_is_weak_lock_free_and_cannot_survive_namespace_aba_or_port_reuse(
) -> TestResult {
    let socket = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    let portid = socket.ensure_netlink_portid();
    let endpoint = GenericReplyEndpoint::capture(&socket, portid);
    let Some(first) = endpoint.native_source() else {
        return TestResult::Fail("actual generic socket did not supply a native source");
    };
    {
        let _state = socket.state.lock();
        if !first.current() {
            return TestResult::Fail(
                "concrete native source touched socket state or lost liveness",
            );
        }
    }
    socket.set_net_ns_id(77);
    socket.set_net_ns_id(0);
    if first.current() || endpoint.current() || endpoint.native_source().is_some() {
        return TestResult::Fail("namespace ABA revived old native source/request endpoint");
    }
    let fresh = GenericReplyEndpoint::capture(&socket, portid);
    let Some(second) = fresh.native_source() else {
        return TestResult::Fail(
            "fresh actual source could not be captured after namespace return",
        );
    };
    // A live bound source cannot be retargeted by a bind to another port.
    if !matches!(
        socket.bind_netlink(&SocketFile::netlink_sockaddr(portid.wrapping_add(1), 0)),
        SocketOpResult::Err(SockError::InvalidArg)
    ) || !second.current()
    {
        return TestResult::Fail("generic socket source rebind changed an already-bound source");
    }
    drop(socket);
    let replacement = SocketFile::with_protocol(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if !matches!(
        replacement.bind_netlink(&SocketFile::netlink_sockaddr(portid, 0)),
        SocketOpResult::Ok(_)
    ) || first.current()
        || second.current()
        || endpoint.native_source().is_some()
    {
        return TestResult::Fail("old native source retained its socket or followed port reuse");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/socket",
    native_socket_source_is_weak_lock_free_and_cannot_survive_namespace_aba_or_port_reuse
);
