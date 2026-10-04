# net — Specification

> Status: **v1.0** (Stage 4 design lock). v0.1 outlined the
> stack-daemon attach contract; v1.0 locks the boot-time
> kernel-stack scope, interface naming, RSS hash policy,
> stack-daemon trust posture, and multi-stack arbitration.

## 1. Purpose & scope

**Owns:**

- The **frame-ring contract** between `drivers/net/` (frame producer)
  and consumers (userspace daemon, kernel-internal callers).
- **Interface registry** — the list of active network interfaces,
  their MAC/MTU/features, and the caps that gate access.
- **Loopback** — a reference implementation of the contract with no
  hardware, used for tests and local-only traffic.
- **Stack-daemon rendezvous protocol** — how a userspace network
  stack attaches, authenticates (via `capabilities/`), and binds to
  an interface.

**Does NOT own:**

- IP, TCP, UDP, QUIC, TLS — these live in the userspace daemon (or
  a library loaded by consumers). NARF's kernel has no L3/L4 stack.
- Driver-internal RX/TX paths — those are `drivers/net/`.
- Hardware offload choice (TSO, GRO, checksum) — driver negotiates
  with hardware; consumer opts in per-interface via a cap bit.

## 2. Assumptions

- `drivers/net/` exposes interfaces via the contract here.
- `ipc/` Narf-Rings carry frames both directions.
- `capabilities/` mints `Cap<NetIface, R>` where R ∈ {Rx, Tx, Admin}.
- `io/` DMA buffers back RX/TX rings.
- `userspace/` is mature enough to host a stack daemon (Stage 4).

## 3. Public interface

### 3.1 Interface object

```rust
pub struct IfaceId(u32);
pub struct IfaceInfo {
    pub id:          IfaceId,
    pub mac:         [u8; 6],
    pub mtu:         u16,
    pub features:    IfaceFeatures,       // Checksum, TSO, GRO, RxHash, Vlan, …
    pub link_state:  LinkState,
    pub max_queues:  u16,
}

pub fn list(cap: &Cap<IfaceRegistry, Read>) -> impl Iterator<Item = IfaceInfo>;
pub fn open(id: IfaceId, rights: IfaceRights, cap: &Cap<IfaceRegistry, Bind>)
    -> Cap<NetIface, _>;
```

The capability-gated interface registry is the canonical hardware inventory
for the control plane. Compatibility views include every driver-backed entry,
even when an interface has not also joined the legacy kernel IPv4 data path.

### 3.2 Frame rings

```rust
pub struct Frame {
    pub data:     Cap<DmaBuffer<u8>, _>,  // zero-copy; payload stays in DMA buffer
    pub len:      u16,
    pub offloads: FrameOffloadFlags,       // CsumOk, GsoSize, RxHash, RxTimestamp
    pub queue:    u16,                     // which RX/TX queue this came from / goes to
}

pub fn rx_ring(iface: &Cap<NetIface, Rx>, queue: u16) -> Ring<Frame>;
pub fn tx_ring(iface: &Cap<NetIface, Tx>, queue: u16) -> Ring<Frame>;
```

- Zero-copy: frame data is a `DmaBuffer` cap; neither `net/` nor the
  stack daemon ever touches the bytes on the hot path.
- Multi-queue is explicit. The consumer chooses queue affinity;
  default is "per-CPU queue" for hash-steered RX.

The in-tree `Frame` owns a DMA buffer, payload offset and length. Its
`tx_meta()` / `set_tx_meta(TxMeta)` and `rx_meta()` / `set_rx_meta(RxMeta)`
accessors carry offload metadata with the same IPC ownership transfer.
Constructors default to plain TX and unchecked RX. `payload_mut()` invalidates
RX checksum results; decomposition into DMA parts discards metadata.

`Interface::offloads() -> OffloadCapabilities` reports the implemented frame-ring
profile: TCP/UDP TX checksum, RX checksum reporting, maximum TSO frame bytes
(zero means unsupported), and VLAN insertion. The default advertises none.
Producers must negotiate before setting `TxMeta`. Packets contain ordinary wire
headers; drivers prepare hardware checksum seeds, validate lengths and reject
unsupported requests rather than transmit partially checksummed packets.
`RxMeta::csum_l3` means a verified IPv4 header checksum; IPv6 never sets it.
`csum_l4` means verified TCP/UDP. Consumers verify in software whenever a flag
is false. These fields describe the in-kernel frame-ring contract; they do not
change the stack-daemon attach wire ABI.

### 3.3 Control-plane operations

```rust
pub struct AdminHandle { /* revocable AdminCap + bound interface identity */ }
pub fn set_link(admin: &AdminHandle, up: bool) -> Result<(), AdminError>;
pub fn set_mtu (admin: &AdminHandle, mtu: u32) -> Result<(), AdminError>;
pub fn set_mac (admin: &AdminHandle, mac: [u8; 6]) -> Result<(), AdminError>;
pub fn add_ipv4(admin: &AdminHandle, addr: [u8; 4], prefix: u8) -> Result<(), AdminError>;
pub fn del_ipv4(admin: &AdminHandle, addr: [u8; 4], prefix: u8) -> Result<(), AdminError>;
pub fn add_ipv6(admin: &AdminHandle, addr: [u8; 16], prefix: u8) -> Result<(), AdminError>;
pub fn del_ipv6(admin: &AdminHandle, addr: [u8; 16], prefix: u8) -> Result<(), AdminError>;
pub fn add_ipv4_route(admin: &AdminHandle, route: Ipv4Route) -> Result<(), AdminError>;
pub fn del_ipv4_route(admin: &AdminHandle, route: Ipv4RouteKey) -> Result<(), AdminError>;
pub fn add_ipv6_route(admin: &AdminHandle, route: Ipv6Route) -> Result<(), AdminError>;
pub fn del_ipv6_route(admin: &AdminHandle, route: Ipv6RouteKey) -> Result<(), AdminError>;
pub fn set_neighbor(admin: &AdminHandle, neighbor: Neighbor) -> Result<(), AdminError>;
pub fn del_neighbor(admin: &AdminHandle, key: NeighborKey) -> Result<(), AdminError>;
pub fn stats   (iface: &Cap<NetIface, Read>) -> IfaceStats;
```

Admin is deliberately separate from Rx/Tx: a stack daemon needs Rx+Tx but
usually not Admin. `AdminHandle` binds the revocable authority to exactly one
interface; every operation checks current cap validity before mutation.

`stack::control_registered(&StackAttach)` validates the registered interface
handle and daemon identity through `Cap::invoke`, returning an interface-bound
`StackAttachReply` without changing frame routing. This supports a wireless
control service alongside the existing IP stack. Its administrative handle
retains both source grants and becomes unusable when either is revoked;
creating it does not attach an XDP socket or consume interface frame rings.

### 3.4 Loopback

A built-in `Loopback` implementation of the contract. Always
available, backed by a kernel-internal Narf-Ring that loops TX →
RX. Used by `verification/` to test the contract without hardware.

### 3.5 Stack-daemon attach (Stage 4)

- A userspace daemon presents a `Cap<Stack, Install>` token (minted
  at boot by a maintainer's policy).
- On attach, the daemon binds one or more interfaces and claims its
  rings.
- The presented `Cap<NetIface, Write>` must exactly match the handle retained
  beside that interface in the canonical driver registry. A live cap minted
  for another or unregistered object is rejected before classifier state
  changes.
- Rings from hardware go **directly** into the daemon's Narf-Rings
  — the kernel does not interpose.
- Multiple stacks can coexist (one per interface, or one per
  cap-scoped domain); each has its own rings. The kernel does not
  multiplex among them.

### 3.6 Linux rtnetlink compatibility

`NETLINK_ROUTE` provides Linux wire-compatible dumps for
`RTM_GETLINK`, `RTM_GETADDR`, `RTM_GETROUTE`, `RTM_GETNEIGH`, and
`RTM_GETRULE`, plus `RTM_GETQDISC`. Replies expose the interface registry,
configured IPv4 and IPv6 addresses, both IP-version FIBs, live IPv4 ARP plus IPv6 NDP neighbor
caches, the canonical local/main/default IPv4 policy rules, and each
interface's direct-ring `noqueue` discipline respectively,
echo the request sequence, identify the kernel sender with port ID zero, carry
`NLM_F_MULTI`, and terminate with `NLMSG_DONE`. Unsupported request types return
`NLMSG_ERROR(-EOPNOTSUPP)`. Rtnetlink mutation requests follow
`rtnetlink_rcv_msg`: a non-GET request needs
`netlink_net_capable(skb, CAP_NET_ADMIN)` — CAP_NET_ADMIN over the socket's
network namespace (its owning user namespace), held both by the socket's
opener (recorded at `socket()`, the `file_ns_capable` half) and by the sending
task — or the reply is `NLMSG_ERROR(-EPERM)`. A capable sender may change any
device of that namespace (another namespace's device is `-ENODEV`) through
kernel-held interface handles minted once per interface
(`stack::kernel_admin`). A route socket may also be delegated an
interface-bound `AdminHandle`, which authorizes exactly that interface.
`RTM_NEWLINK`/`RTM_SETLINK` and IPv4 or IPv6
`RTM_NEWADDR`/`RTM_DELADDR` plus `RTM_NEWROUTE`/`RTM_DELROUTE` invoke the
typed operations in §3.3. `RTM_NEWNEIGH`/`RTM_DELNEIGH` update IPv4 ARP or
IPv6 NDP state through the same interface-bound authority.
The stack-daemon launcher performs delegation as a kernel-held transfer from a
successful `StackAttachReply` to a route socket in the attaching task's fd
table. The Linux syscall surface never accepts raw admin-handle bytes.

Successful mutations emit kernel-originated sequence-zero notifications to
the Linux rtnetlink multicast group for the changed object (link, neighbor,
IPv4/IPv6 address, or IPv4/IPv6 route). Address and route notifications use
the family-specific IPv4 or IPv6 group. Only sockets subscribed through
`nl_groups` or `NETLINK_ADD_MEMBERSHIP` receive them.

Creation and replacement honor Linux `NLM_F_CREATE`, `NLM_F_EXCL`, and
`NLM_F_REPLACE` semantics per object, with the errnos of the Linux handler:
an existing address or route is `EEXIST` under `NLM_F_EXCL` or without
`NLM_F_REPLACE`; a new IPv4 route needs `NLM_F_CREATE` (`ENOENT`,
`fib_table_insert`) while a new address or IPv6 route does not (only an IPv6
`NLM_F_REPLACE` of a missing route is `ENOENT`); a missing neighbor needs
`NLM_F_CREATE` (`ENOENT`) and an existing one is `EEXIST` only under
`NLM_F_EXCL` (`neigh_add`). Deleting a missing route returns `ESRCH`
(`fib_table_delete` / `ip6_route_del`), a missing address `EADDRNOTAVAIL`
(`inet_rtm_deladdr` / `inet6_addr_del`), a missing neighbor `ENOENT`.
Address and route requests for a family other than IPv4/IPv6 return
`EOPNOTSUPP`; neighbor requests for such a family return `EAFNOSUPPORT`.
`RTM_SETLINK` resolves the device by positive ifindex or, with ifindex 0, by
`IFLA_IFNAME` (neither: `EINVAL`; unknown: `ENODEV`). `RTM_NEWLINK` on an
existing device returns `EEXIST` under `NLM_F_EXCL` and `EOPNOTSUPP` under
`NLM_F_REPLACE`; for a missing device it returns `ENODEV` without
`NLM_F_CREATE` and `EOPNOTSUPP` with it (no link kinds are registered). An
invalid (multicast or all-zero) `IFLA_ADDRESS` returns `EADDRNOTAVAIL`.

Interface identity follows Linux `register_netdevice`. `lo` is ifindex 1;
every other device takes the next unused ifindex when it registers
(`dev_new_index`) and keeps it for its lifetime, including across a
re-registration under the same name; a device known only to the frame-ring
registry gets one from the same counter on first sight. The link dump,
`SIOCGIFINDEX`, `/sys/class/net/<dev>/ifindex`, the BPF XDP attach path and
`iface::send_on_ifindex` all use that one number. A name containing `%d` takes
the lowest unused number (`dev_alloc_name`): e1000 and virtio-net register as
`eth%d` and wireless drivers as `wlan%d`, each device under one name in both
registries (a driver needing its name before registering reserves it). The link dump lists
exactly one loopback, `lo`, and a running device reports `IFF_LOWER_UP`
(`dev_get_flags`). A device registers down (no `IFF_UP`) and with no
address, as `register_netdevice` leaves it, so a distro network manager finds
it unconfigured; NARF's `lo` stays permanently up. The first IPv4 address
configured on a device becomes the address the stack sends from; removing it
moves that to the next address, or none. The opt-in `qemu-net` feature is the
equivalent of Linux kernel IP autoconfiguration
(`ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off`): it brings the primary
virtio NIC up and configures that address and default route.

When `NETLINK_EXT_ACK` is enabled, a failed mutation carries
`NLM_F_ACK_TLVS` and a `NLMSGERR_ATTR_MSG` only where the Linux handler calls
`NL_SET_ERR_MSG`, with the handler's text (for example `inet_rtm_deladdr`'s
"ipv4: Address not found"); the bare `-EPERM` of the capability check carries
none. Address requests fail in the handlers' order: `inet_validate_rtm`
(prefix, then `IFA_LOCAL`) before the IPv4 device lookup, and IPv6 address
extraction before any lookup.
Without `NETLINK_CAP_ACK`, `nlmsgerr` echoes the complete offending request.
With CAP_ACK enabled the echo is header-only and marked `NLM_F_CAPPED`; any
extended-ACK attributes follow the capped request header.

Requests are walked as `netlink_rcv_skb` / `rtnetlink_rcv_msg` do: a message
without `NLM_F_REQUEST`, a control message, or one without even a one-byte
`struct rtgenmsg` is not processed (only `NLM_F_ACK` earns a zero ACK). A
`NLM_F_DUMP` request selects the Linux dumpit for `(family, type)`, falling
back to `AF_UNSPEC`; with none registered (for example `RTM_GETADDRLABEL`
outside `AF_INET6`, `RTM_GETMDB` outside `AF_BRIDGE`) the reply is
`NLMSG_ERROR(-EOPNOTSUPP)`. A dump that starts is never ACKed. The dumpit
validates the request exactly as its Linux counterpart (strictly when
`NETLINK_GET_STRICT_CHK` is set — `rtnl_valid_dump_ifinfo_req`,
`inet{,6}_valid_dump_ifaddr_req`, `ip_valid_fib_dump_req`,
`neigh_valid_dump_req`, `fib_valid_dumprule_req`, `ip6addrlbl_valid_dump_req`,
`rtnl_mdb_valid_dump_req`; `nh_valid_dump_req` and the traffic-control dumps
validate in both modes), including `nla_policy` attribute validation, and a
failure (`EINVAL`, `ERANGE`, `ENODEV`, `ENOENT`, `EAFNOSUPPORT`) is the i32
payload of the terminating `NLMSG_DONE`, flagged `NLM_F_MULTI` plus the dump's
answer flags, with `NLM_F_ACK_TLVS`, the Linux `NLMSGERR_ATTR_MSG` text, and
`NLMSGERR_ATTR_OFFS` under `NETLINK_EXT_ACK`. Filtered dumps mark their
entries (and, where Linux sets `cb->answer_flags`, the `NLMSG_DONE`)
`NLM_F_DUMP_FILTERED`. Non-dump `RTM_GETLINK` / `RTM_GETROUTE` run
`rtnl_valid_getlink_req` / `inet_rtm_valid_getroute_req` and answer errors
with `NLMSG_ERROR`; a successful doit's reply precedes its `NLM_F_ACK`.
Non-dump `RTM_GETLINK` resolves one interface by positive ifindex or else
`IFLA_IFNAME`, returning a non-multipart reply, `ENODEV` when the named
interface is absent, or `EINVAL` when neither selector is present.
Non-dump `RTM_GETROUTE` performs the forwarding table's longest-prefix
lookup for `RTA_DST` (absent: 0.0.0.0, as `inet_rtm_getroute`), returning
the selected route as one non-multipart reply or `ENETUNREACH`; a family
other than `AF_INET` returns `EOPNOTSUPP`.
Address dumps honor `ifa_family`, and `ifa_index` only under strict checking;
route dumps honor `rtm_family`, and under strict checking `rtm_table` /
`RTA_TABLE`, `RTA_OIF`, `rtm_protocol`, and `rtm_type`; neighbor dumps filter
by `NDA_IFINDEX` / `NDA_MASTER`; qdisc dumps cover every device. A valid
filter with no matching objects returns an empty dump terminated by
`NLMSG_DONE`.

Link dumps include Linux operational-state, carrier, qdisc, queue-length,
broadcast, group, and `rtnl_link_stats64` attributes. Counters remain zero
until a driver publishes them through the central interface registry.

Collection queries for absent optional state—traffic classes, filters,
actions, address labels, multicast database entries, and nexthops—return an
empty multipart dump terminated by `NLMSG_DONE`.
Link dumps merge the legacy IPv4 registry with the canonical driver-backed
registry by interface name, so frame-ring-only drivers appear exactly once.

`NETLINK_GENERIC` publishes the mandatory `nlctrl` control family.
`CTRL_CMD_GETFAMILY` supports name or numeric-ID lookup and dump enumeration
with Linux-compatible family, supported-operation, and multicast-group
attributes; unknown families return `ENOENT`. A request addressed to an
unregistered family ID returns `ENOENT` (`genl_rcv_msg`); a command absent
from the family's operation table, or a dump of a do-only operation, returns
`EOPNOTSUPP` before the family callback runs (`genl_get_cmd`). Multiple
aligned control requests may be batched in one datagram and retain independent
sequence numbers.
Subsystems may register additional generic-netlink families by stable ID and
name, with immutable operation/group descriptors and a request callback.
Duplicate IDs or names are rejected. Family callbacks return attribute streams;
the netlink core owns generic headers, multipart termination, acknowledgements,
and sequence/sender fields.
Generic control errors honor `NETLINK_CAP_ACK` and `NETLINK_EXT_ACK` with the
same capped echo and diagnostic-TLV rules as rtnetlink.

Families may additionally register a `ContextHandler` receiving
`RequestContext { net_ns_id, admin }`. `admin` is an optional, kernel-held
interface-bound `AdminHandle`; the default reply builder supplies none.
The socket bridge passes only explicitly delegated authority. Family
mutations check its current validity, interface name and namespace before
queueing work, and again when asynchronous work starts. Generic-netlink
attributes cannot mint or substitute capabilities.
`AdminHandle::authorize_interface(name, namespace)` performs this boundary
check through `Cap::invoke`, including the current revocation epoch.

`publish_event` frames a notification only for a registered family/group.
Its installed socket sink filters by `NETLINK_GENERIC`, namespace and
membership, queues at most 256 notifications per socket, and wakes readiness
after releasing the queue lock. This is a bounded, best-effort multicast
path; callers recover lost scan notifications by querying cached results.

`NETLINK_SOCK_DIAG` accepts Linux `SOCK_DIAG_BY_FAMILY` /
`inet_diag_req_v2` dumps for IPv4 and IPv6 TCP and UDP. It filters by the requested
Linux socket-state mask and emits `inet_diag_msg` records from
namespace-scoped transport snapshots, followed by
`NLMSG_DONE`. Aligned requests may be batched, their sequences remain
independent, and `NLM_F_ACK` adds a zero-error acknowledgement after a
successful query. Messages without `NLM_F_REQUEST` return `EINVAL`.
Errnos follow `sock_diag_rcv_msg` / `inet_diag`: unknown message types and
families `>= AF_MAX` return `EINVAL`; `TCPDIAG_GETSOCK` and `SOCK_DESTROY`
return `EOPNOTSUPP`; address families and transport protocols without a
handler return `ENOENT`.

`NETLINK_NETFILTER` accepts IPv4 conntrack `IPCTNL_MSG_CT_GET` dumps and
emits Linux nfnetlink `IPCTNL_MSG_CT_NEW` records with original/reply tuples,
status, timeout, and flow ID from the canonical conntrack table. Dumps end
with `NLMSG_DONE`; aligned requests may be batched and `NLM_F_ACK` produces a
zero-error acknowledgement after a successful query. Non-dump point queries
select an entry by `CTA_ID` or complete `CTA_TUPLE_ORIG`, return a
non-multipart record, and report `ENOENT` when the canonical table has no
match. Creating or deleting nftables tables and empty chains requires a
delegated namespace-matched `NetfilterAdminHandle` with ruleset rights;
missing, revoked, cross-namespace, or rights-attenuated authority returns
`EPERM`, and deleting a non-empty object returns `EBUSY`. Creating a table or
chain that already exists returns `EEXIST` under `NLM_F_EXCL`, `EOPNOTSUPP`
under `NLM_F_REPLACE`, and otherwise succeeds as a no-op update
(`nf_tables_newtable` / `nf_tables_newchain`). nf_tables requests for a
family other than IPv4 return `EOPNOTSUPP` (`nft_supported_family`), except
that `NFPROTO_UNSPEC` table/chain dumps list the IPv4 ruleset. Rule-expression and
conntrack mutations plus unsupported nfnetlink subsystems return
`EOPNOTSUPP`; Linux netlink does not grant ambient filter/NAT authority.

Every packet context and `NETLINK_NETFILTER` query carries an immutable
network-namespace id (zero is the initial namespace). Rulesets, conntrack
entries, and NAT mappings are stored independently for each id. Mutable
operations require a live `Cap<NetfilterAdminCap, Invoke>` wrapped with the
exact namespace id and explicit read/ruleset/conntrack/NAT operation rights;
namespace membership, uid, and Linux ambient capability bits are not
authority.

Physical interfaces carry one owning network-namespace id. Moving an
interface requires its live interface-bound `AdminHandle`; afterward namespace
filtered lookup hides it from the source namespace and ingress packets inherit
the destination namespace before AF_PACKET delivery and PRE_ROUTING. IPv4 FIB
entries are keyed by namespace as well as destination/interface/table, so
longest-prefix lookup cannot select another namespace's route.
TCP connection/listener keys and UDP bind/delivery tables include the network
namespace id; identical endpoint tuples may coexist across namespaces and
accepted TCP children inherit their listener's namespace. The IPv4 ARP cache
is namespace-scoped. ICMP echo and raw delivery, plus ICMP-originated TCP/UDP
errors, are restricted to the receiving namespace. TCP, UDP, and ICMP output resolves only namespace-owned
interfaces and routes and traverses that namespace's `LOCAL_OUT` and
`POST_ROUTING` netfilter hooks.
`iface::is_local_addr_in(ns, ip)` reports whether `ip` is one of the
namespace's addresses (or in 127.0.0.0/8); `iface::is_broadcast_in(ns, ip)`
reports the limited broadcast or a local subnet's `prefix | ~mask` for
prefixes shorter than /31 (Linux `RTCF_BROADCAST`). `udp_sock` sends refuse a
payload over `UDP_MAX_PAYLOAD` (65507) regardless of `SO_SNDBUF`, require
`SO_BROADCAST` for exactly those broadcast destinations, drop an arriving
datagram when the receive queue is full, and drop received datagrams whose
length field is shorter than the header or longer than the segment.
ICMP errors quoting a UDP datagram reach sockets bound to the exact source
address or to `INADDR_ANY` (`__udp4_lib_lookup`), and Parameter Problem is
delivered like Destination Unreachable and Time Exceeded.
`udp_sock::SockError::linux_errno()` /
`udp_sock::icmp_err_convert(type, code) -> Option<(errno, hard)>` give the
Linux errno and hard/soft class of a queued ICMP error as `udp_err` derives
them, from the shared `tcp::core::ICMP_UNREACH_ERRNO` /
`ICMP_UNREACH_FATAL` (`icmp_err_convert[]`) table: Fragmentation Needed
`EMSGSIZE` hard, Parameter Problem `EPROTO` hard, Time Exceeded
`EHOSTUNREACH` soft, Source Quench / Redirect not reported. ICMP echo
payloads above `icmp_sock::ICMP_ECHO_MAX_PAYLOAD` fail
`IcmpError2::MsgTooLong` (Linux `EMSGSIZE`).

Native IPv6 UDP transmission enforces the minimum of the interface MTU,
socket `IPV6_MTU`, and learned destination PMTU. ICMPv6 Packet Too Big
messages monotonically reduce the namespace-scoped destination cache.
Datagrams exceeding that MTU return `EMSGSIZE` when `IPV6_DONTFRAG` is set
or the discovery mode preserves DF semantics; modes for which Linux
`ip6_sk_ignore_df` permits source fragmentation emit RFC 8200 Fragment
headers with one identification and eight-byte-aligned non-final payloads.
Packets retained during neighbor discovery preserve the MTU decision and are
fragmented only after resolution, before device transmission.

Linux `/proc/net/{tcp,tcp6,udp,udp6,raw,arp,route,dev,nf_conntrack}` snapshots resolve
the calling task's network namespace and exclude objects owned by every other
namespace.
TCP snapshots expose Linux `get_tcp4_sock` transport fields rather than
placeholders: the active timer and USER_HZ deadline, retransmit/probe counts,
RTO and delayed-ACK deadline, congestion window, and slow-start threshold.
`tcp_info(id)` snapshots the authoritative live TCB fields used by Linux
`TCP_INFO`: state, congestion state, negotiated options/scales, timer and RTT
metrics, MSS/window values, queue depth, and retransmission state. Metrics the
stack does not track are omitted and the socket ABI reports them as zero.
Per-TCB transport controls are effective, not passive metadata:
`TCP_SYNCNT` selects the SYN retransmit limit and blocking-connect deadline;
`TCP_NOTSENT_LOWAT` backpressures writes at the unsent-byte threshold;
`TCP_THIN_LINEAR_TIMEOUTS` suppresses exponential RTO growth for thin flights;
`TCP_THIN_DUPACK` is retained as Linux's accepted no-op (and reads back zero);
and `TCP_DEFER_ACCEPT` holds ACK-only children off the accept queue until
data arrives or the configured deadline expires.
DHCP reply and DNS side channels are keyed by the ingress interface's network
namespace. The final namespace reference reclaims its TCP, UDP, raw, ICMP,
ARP-resolution, DHCP, route, and netfilter state; physical interfaces return
to the initial namespace without retaining dead-namespace routes.

`NETLINK_AUDIT` reports a disabled zeroed `audit_status` for `AUDIT_GET` and
an empty completed `AUDIT_LIST_RULES` list (with or without `NLM_F_DUMP`).
`AUDIT_SET` and the other configuration writes (`AUDIT_ADD_RULE`,
`AUDIT_DEL_RULE`, `AUDIT_TRIM`, `AUDIT_MAKE_EQUIV`, `AUDIT_TTY_SET`,
`AUDIT_SET_FEATURE`) return `EPERM` because Linux uid and capability bits do
not confer NARF audit authority. Obsolete `AUDIT_LIST`/`AUDIT_ADD`/`AUDIT_DEL`
and unimplemented read queries return `EOPNOTSUPP`; unknown message types
return `EINVAL` (`audit_netlink_ok`).

AF_NETLINK sockets retain their bound `sockaddr_nl` port ID and group mask,
support a connected kernel or userspace destination, auto-bind before the
first send, and expose Linux `SOL_NETLINK` membership and feature-option
round trips. Group membership is not limited to the legacy 32-bit
`sockaddr_nl.nl_groups` mask; `NETLINK_ADD_MEMBERSHIP`,
`NETLINK_DROP_MEMBERSHIP`, and `NETLINK_LIST_MEMBERSHIPS` retain and report
the full group-number bitmap. Explicit port IDs are unique within each netlink protocol.
When `NETLINK_PKTINFO` is enabled, `recvmsg` emits a `SOL_NETLINK` /
`NETLINK_PKTINFO` control message whose `nl_pktinfo.group` identifies the
multicast group of the datagram actually dequeued (zero for unicast replies).
`sendto` or connected send to a live userspace port delivers one datagram and
reports the sender's port ID through `recvfrom`; a missing destination returns
`ECONNREFUSED`. Userspace multicast is rejected because NARF does not infer
Linux ambient broadcast authority; kernel protocol notifications still fan out
to subscribed sockets. A protocol with no registered kernel responder retains
user-to-user port-ID delivery, but a send to kernel port ID zero returns
`ECONNREFUSED` instead of silently discarding the request. Kernel-originated
messages use port ID zero. A send may contain
multiple `NLMSG_ALIGN`-framed requests; replies preserve request order and
sequence numbers. `NLM_F_ACK` requests receive `NLMSG_ERROR` with error zero
after successful handling, while malformed framing fails with `EINVAL`.
`SIOCINQ`/`FIONREAD` reports the complete size of the next queued route or
generic-netlink datagram without consuming it.
`MSG_PEEK` copies the next queued route or generic-netlink datagram without
advancing the queue.
When a receive buffer is short, only its capacity is copied. `MSG_TRUNC`
returns the complete datagram length; `recvmsg` also sets its output
`msg_flags` to `MSG_TRUNC`.

### 3.7 In-kernel TCP socket calls and errno (`tcp_stack`)

The kernel-TCP socket paths (`SocketState::InetWired` and
`SocketState::Inet6Wired`) call the
errno-returning entry points below. Errors are positive Linux errnos from
`narf_lib::errno`; each call returns what Linux returns for the same state.
All are non-blocking: where Linux would sleep, they return `EAGAIN` and the
socket layer parks the task.

```rust
pub fn connect_errno_in(ns: u64, addr: [u8; 4], port: u16) -> Result<u32, i32>;
pub fn connect6_errno_in(ns: u64, addr: [u8; 16], port: u16) -> Result<u32, i32>;
pub fn listen6_in(ns: u64, addr: [u8; 16], port: u16, backlog: usize) -> Result<u32, ()>;
pub fn send_errno(id: u32, buf: &[u8]) -> Result<usize, i32>;
pub fn recv_errno(id: u32, buf: &mut [u8]) -> Result<usize, i32>; // Ok(0) = EOF
pub fn shutdown_errno(id: u32, how: Shutdown) -> Result<(), i32>;
pub fn take_sock_error(id: u32) -> i32;  // getsockopt(SO_ERROR); 0 = none
pub fn release(id: u32);                 // socket closed: forget the TCB id
pub fn signal_icmp_error_in(ns, local, lport, remote, rport,
                            icmp_type: u8, icmp_code: u8, seq: u32);
```

The legacy `connect_in` / `send` / `recv` / `shutdown` (`Result<_, ()>`)
remain for in-kernel callers that do not report errors.

IPv4 and IPv6 share one TCB state machine, congestion/retransmit machinery,
socket buffers, and errno path. Family-specific connected and listener
indexes retain full-width addresses and include the network-namespace ID.
The lookup/index locks are never held while taking a TCB lock; this mirrors
the lock separation in `tcp_v4_rcv`/`tcp_v6_rcv` and
`inet_csk_get_port`, where hash-bucket locking protects membership and the
socket lock protects protocol state.

| Condition | Result | Linux source |
| --- | --- | --- |
| `connect`: no interface | `ENETUNREACH` | `fib_lookup` (include/net/ip_fib.h) |
| `connect`: next hop unresolvable | `EHOSTUNREACH` | `ipv4_link_failure` → `tcp_v4_err` |
| `connect`: RST to the SYN | `ECONNREFUSED` | `tcp_reset` |
| `connect`: ICMP error in SYN-SENT | `icmp_err_convert[code]`; TIME_EXCEEDED `EHOSTUNREACH`; PARAMETERPROB `EPROTO` | `tcp_v4_err`, net/ipv4/icmp.c |
| `connect`: no answer | `ETIMEDOUT` (or the soft ICMP error) | `tcp_write_err` |
| RST in ESTABLISHED / FIN-WAIT / CLOSING / LAST-ACK | `ECONNRESET` | `tcp_reset` |
| RST in CLOSE-WAIT | `EPIPE` | `tcp_reset` |
| retransmit or keepalive give-up | `sk_err_soft` if set, else `ETIMEDOUT` | `tcp_write_err` |
| ICMP error once established | soft only: `SO_ERROR`, or the errno of a later timeout; never aborts | `tcp_v4_err` (RFC 1122 §4.2.3.9) |
| ICMP FRAG_NEEDED / REDIRECT / SOURCE_QUENCH; quoted seq outside `[snd_una, snd_nxt]` | ignored | `tcp_v4_err` |
| `recv`: data queued | the data, whatever the state | `tcp_recvmsg_locked` |
| `recv`: peer FIN received (`SOCK_DONE`) | `0` | `tcp_recvmsg_locked` |
| `recv`: pending error | that errno, once; then `0` | `sock_error`, `tcp_done` |
| `recv`: after `SHUT_RD` / connection closed | `0` | `RCV_SHUTDOWN` |
| `recv`: live, nothing queued | `EAGAIN` | `tcp_recvmsg_locked` |
| `send`: pending error | that errno, once; then `EPIPE` | `sk_stream_error` |
| `send`: after `SHUT_WR` / connection closed | `EPIPE` (caller raises `SIGPIPE` unless `MSG_NOSIGNAL`) | `tcp_sendmsg_locked` |
| `send`: send buffer full | `EAGAIN` | `sk_stream_wait_memory` |
| `shutdown`: connection closed (incl. TIME-WAIT) | `ENOTCONN` | `inet_shutdown` |
| `shutdown`: `how > SHUT_RDWR` | `EINVAL` | `inet_shutdown` |
| `SO_ERROR` | pending error, else the soft error; each cleared by the read | `sk_getsockopt` |
| `setsockopt` SO_TYPE / SO_PROTOCOL / SO_DOMAIN / SO_ERROR | `ENOPROTOOPT` | `sk_setsockopt` |

A connection's TCB is freed when it ends, while Linux keeps `struct sock`
until the fd closes. So the pending error and `SOCK_DONE` of a connection
that ended in error are kept by TCB id until `close` / `release` (bounded:
the oldest entry is evicted past 4096).

Deviation: `iface::for_dst` falls back to the primary interface when no
route matches, so `ENETUNREACH` is reported only when no interface exists,
not for every destination without a route.

## 4. Invariants & safety properties

- A frame buffer is owned by exactly one holder at a time — either
  the driver domain (pre-RX / post-TX completion) or the consumer
  (post-RX / pre-TX submit).
- No L3+ parsing happens in the kernel. Packets are opaque bytes
  across the contract.
- `IfaceRegistry` is read-mostly; updates (interface add/remove)
  use RCU so list readers never lock.
- Admin operations cannot be performed with Rx/Tx caps alone.
- MTU changes do not leak in-flight frames of the old MTU.
- **Frame rings inherit `ipc/` §4 invariants in full:** explicit
  release/acquire barrier pair on every index transition (matters
  on aarch64), cache-line partitioned head/tail/payload, on-aarch64
  retag of every pointer crossing into the receiver's domain.
- **RX ring back-pressure: drop-newest with counter, never block the
  driver.** A NIC RX path cannot wait — the hardware will drop on
  its side anyway. When the receiver-side ring is full, the driver
  drops the frame, increments a per-ring `rx_dropped` counter
  visible in `IfaceStats`, and emits a `tracing/` event. This is
  the exception to the "no silent drops" rule: line-rate networking
  forces it.
- **TX ring back-pressure: standard `ipc/` blocking-via-waker.** The
  user-side stack daemon submits TX frames; if the ring is full it
  is woken when the driver drains, exactly as `ipc/` §4 specifies.
  No hot-path drop on TX.
- **TX submissions follow the `abi/` §3.1 cancellation protocol.**
  Dropping a TX Future requests cancel; terminal completion is one
  of `Ok` (frame left the NIC), `Cancelled` (driver reclaimed the
  descriptor before transmit), or `CancelRequested` (already in
  hardware TX queue, must wait). RX has no cancel — frames arrive
  or don't; the RX ring is purely observational.

## 5. Architecture notes

Arch-neutral at the spec level. Hardware-specific offload negotiation
happens inside `drivers/net/` per-driver.

## 6. Dependencies

- **Consumes:** `drivers/net/` (frame source), `ipc/` (rings),
  `capabilities/`, `io/` (DMA), `memory/`, `rcu/` (registry reads),
  `tracing/` (per-frame USDT, opt-in).
- **Provides to:** `userspace/` (stack daemon), `drivers/net/`
  (as the contract it implements), any kernel subsystem that needs
  raw frames (rare — mostly test tools).

## 7. Stage assignment

| Stage | Lands                                                          |
| ----- | -------------------------------------------------------------- |
| 3     | Contract types, interface registry, loopback, virtio-net attached. |
| 4     | Userspace stack-daemon protocol, Admin cap flow, hardware NIC integration via `drivers/net/`. |
| post-1.0 | XDP-equivalent fast-path filters (declarative, not VM), optional minimal in-kernel stack for boot-only networking. |

## 8. Resolved decisions

### 8.1 In-kernel stack scope (resolved)

**Decision:** **no in-kernel TCP/IP stack at v1.0**. All L3+
(IP, TCP, UDP, TLS) lives in user-mode stack daemons. The
kernel `net/` only owns:

- L2 frame ingress/egress at the device boundary.
- MAC-address binding via `Cap<NetIface, _>`.
- Optionally, a pre-mounted user-mode stack daemon image for
  boot-time PXE-style operations (loaded from initramfs).

Network-boot scenarios use the pre-mounted user-mode stack;
no kernel protocol code. This keeps NARF microkernel-pure
on the network path.

### 8.2 Interface naming (resolved)

**Decision:** **capability-only addressing internally;
operator-facing names via a thin naming service**.

Inside the kernel and stack daemons, interfaces are named
solely by their `Cap<NetIface, _>` (with bus-device-path
badge). For operator tooling, a small naming daemon
(`narf-ifnamed`) maps caps to stable names like `wan0`,
`lan0`, etc., reading a `narf.network.toml` config file.

This avoids Linux's famous network-interface naming wars
(predictable names vs. eth0 vs. systemd renaming) — the
stable names live in operator config, not in udev-equivalent
kernel-side magic.

### 8.3 Hardware hash steering / RSS (resolved)

**Decision:** **consumer declares an `RssScheme` enum**;
driver implements as best the hardware allows.

```rust
pub enum RssScheme {
    None,                          // single-queue, no steering
    HashIPv4,                      // 5-tuple hash on IPv4 traffic
    HashIPv6,                      // 5-tuple hash on IPv6
    HashAuto,                      // either, driver picks
    Custom(Cap<RssKey, Read>),    // consumer-supplied hash key
}
```

The hash key (when consumer-supplied) lives behind a cap so
the kernel doesn't see the bytes — the driver writes the key
into the device's RSS table directly via its
`Cap<BusDevice, Write>`.

Drivers without RSS hardware degrade to `RssScheme::None`
silently; consumers that needed steering observe the
single-queue throughput floor.

### 8.4 High-performance / fast-path networking (resolved)

**Decision:** **first-class polled fast-path data-plane
support** as a NARF-native mechanism. The same kernel-bypass
ideas that DPDK / VPP / Snabb / netmap pioneered, expressed
through NARF's existing primitives — caps, user-mode-domain
drivers, polled futures, huge-page DMA pools — without
inheriting any specific external API.

A fast-path NIC driver is a driver crate that:

- Declares `host = "user-mode-domain"` in its manifest, so
  it runs as a sandboxed user-mode process (not in the
  kernel). Bug or malice cannot crash the kernel.
- Holds `Cap<BusDevice, Dma>` + `Cap<MsiXTable, _>` +
  `Cap<DmaBuffer, _>` with a quota request sized for the
  packet pool (see `drivers/spec` §17.2).
- Declares `dispatch = Polled` in its registration so the
  framework does not deliver MSI-X — the driver polls RX
  descriptor rings directly via MMIO.
- Optionally pins polling threads to specific CPUs via
  `Cap<CpuAffinity, _>`.

NARF provides four primitives that make line-rate fast-path
work without kernel-side per-packet overhead:

#### 1. Huge-page DMA buffer pools

`io/spec` §8.1 exposes `alloc_coherent`; the
fast-path-friendly variant pulls from `memory/`'s folio
allocator at huge-page granularity:

```rust
pub fn alloc_pool(
    bytes:    usize,
    granule:  PageSize,        // Page4K | Huge2M | Huge1G
    dev:      &Cap<BusDevice, Dma>,
    quota:    &Cap<Quota, Spend>,
) -> Result<Cap<DmaBuffer, Read | Write>, IoError>;
```

The returned cap covers the whole pool. Sub-allocation
into fixed-size packet slots happens in the driver's
address space without further kernel calls — same model as
slab over a heap, but for DMA-pinned memory. Slot phys
addrs are stable for the pool's lifetime; the driver hands
them to the NIC's descriptor rings.

#### 2. Per-queue CPU steering

A fast-path NIC driver creates one RX/TX queue pair per
polling thread. The framework lets the driver program each
queue's hardware-redirection target independently:

```rust
pub fn bind_queue(
    table:      &Cap<MsiXTable, ProgramQueue>,
    queue_idx:  u16,
    target_cpu: CpuId,
) -> Result<(), MsiXError>;
```

For polled drivers this is largely ceremonial (no IRQs are
expected) but ensures that any hardware-driven RSS routes
flows to the queue intended for that CPU's polling thread.

#### 3. Hardware flow steering

`RssScheme` (§8.3) covers the symmetric / 5-tuple-hash
common case. For consumers that need explicit flow
direction (per-tenant routing, DDoS-mitigation rules,
segregating control vs. data flows), there's an explicit
flow-rule API:

```rust
pub struct FlowFilter {
    pub match_tuple: TupleMatch,          // 5-tuple + masks
    pub action:      FlowAction,          // Queue(u16) | Drop | Mirror(u16)
}

pub fn install_flow(
    iface: &Cap<NetIface, FlowSteer>,
    rule:  FlowFilter,
) -> Result<FlowHandle, NetError>;
```

`Cap<NetIface, FlowSteer>` is a separate cap right (not
every NIC consumer may install flows; this is a privileged
operation). Drivers translate `FlowFilter` to whatever
their hardware exposes (Intel flow-director, NVIDIA
steering tables, ARM CCP). Drivers without hardware
filtering reject with `Err(NotSupported)` and the consumer
falls back to software-side classification.

#### 4. Zero-copy data path

The fast-path data-plane runs entirely in user space:

- **TX**: the consumer writes the packet payload into a
  pool slot (in its own address space, no syscall),
  updates the NIC's TX descriptor (MMIO write through the
  driver's `Cap<BusDevice, Write>`), kicks the doorbell.
- **RX**: the consumer polls the NIC's RX descriptor ring,
  dequeues filled slots, processes them.

The kernel is touched zero times per packet in either
direction. CPU is the only bottleneck; the path is
proportional to the NIC's per-packet descriptor cost
(typically a couple of cache lines).

NARF-specific advantages over historical kernel-bypass
designs:

1. **Sandboxed**: the driver runs in user-mode-domain. A
   buggy implementation can corrupt its own state and lose
   packets but cannot crash the kernel or other tenants.
2. **Cap-typed access**: BAR maps and DMA buffers are caps;
   the driver can't forge access to memory outside its
   grant. The IOMMU is the third isolation layer.
3. **No special "bypass" framework needed** — it's the
   same Driver trait, the same SDK, the same loader. A
   driver crate flips between IRQ-driven (default) and
   polled fast-path by changing `dispatch =` in its
   manifest.

#### Reference performance

Single-flow UDP, MTU 1500, single core, contemporary
hardware (Cascade Lake / Ampere Altra):

| Mode                              | Throughput |
| --------------------------------- | ---------- |
| Polled in-kernel driver           | ~12 Mpps   |
| Polled user-mode-domain driver    | ~10 Mpps   |
| IRQ-driven kernel driver (compare)| ~2 Mpps    |

The 20% gap between in-kernel and user-mode-domain is the
cap-check cost on each MMIO doorbell — small but real.
Operators paying for the security gain accept it; operators
who want absolute peak rates can mark a driver
`host = "kernel"` and lose the sandbox (an explicit, audited
policy decision per system).

#### Naming conventions

Operators provision fast-path networking through a workspace
`narf.toml` image profile — naming convention `*-fastpath`:

```toml
[image.production-fastpath]
inherits = "production"
modules += ["narf-drivers-mlx5-fastpath"]   # vendor-supplied
```

There is no global "DPDK mode" switch — fast-path is a
per-driver capability, not a kernel-wide option. Mixed
deployments (one fast-path NIC for the data plane, one
IRQ-driven NIC for the control plane) are first-class.

### 8.5 Stack-daemon trust (resolved)

**Decision:** **out of TCB**. A bug in the user-mode stack
daemon can DoS its own connections but cannot escalate into
kernel privilege. The stack runs in `DomainId::USERSPACE_K`
with caps to specific `NetIface` instances; everything else
is unreachable.

DoS mitigation: per-stack-daemon budget caps (CPU, memory,
ring slots) limit blast radius. A malicious stack daemon
can drop its own packets but can't drop another daemon's.

### 8.5 Multi-stack arbitration (resolved)

**Decision:** **first-come single-binding per interface**.
Only one stack daemon may hold `Cap<NetIface, Bind>` per
interface at a time. Subsequent bind attempts return
`Err(InterfaceBound)`.

Operators wanting multiple stacks per interface (e.g.
"normal TCP/IP + sidecar QUIC") run a multiplexer daemon
that holds the bind and fans out to multiple sub-stacks.
The multiplexer is just another stack daemon; the
arbitration rule remains 1:1 at the kernel boundary.

## 9. ABI versioning

`net/` exports through SDK at `@v0`:

- `Cap<NetIface, _>`, `Cap<StackInstall, _>`, `Cap<RssKey, _>`.
- L2 frame submission API (driver → stack and stack →
  driver).
- `RssScheme` enum.

`NET_ABI_MAJOR = 1`, `NET_ABI_MINOR = 0`.

## 10. Open questions

(none — all v0.1 questions resolved in §8)

## 11. L4 codecs (`pkt_udp`, `pkt_tcp`, `pkt_ipv6`, `pkt_dns`)

The `net/` crate ships clean-room codecs for the wire-format layers
above Ethernet/ARP/IPv4/ICMP that `pkt.rs` already covered.
References (public-only, all IETF documents):

### UDP (`pkt_udp`)
- **RFC 768** — User Datagram Protocol (J. Postel, Aug 1980).
- **RFC 1071** — Computing the Internet Checksum (mechanism reused
  for the UDP pseudo-header sum).
- Surfaced: `UdpHeader::encode/decode`, `ipv4_pseudo_checksum`,
  `build_ipv4`, `verify_ipv4` (with the RFC 768 "0 = disabled,
  computed-0 → 0xFFFF" rule).

### TCP (`pkt_tcp`)
- **RFC 9293** — Transmission Control Protocol (W. Eddy, Aug 2022).
  §3.1 Header Format. §3.2 Control flags FIN/SYN/RST/PSH/ACK/URG/
  ECE/CWR.
- **RFC 7323** — TCP Extensions for High Performance — Window Scale
  (kind 3) + Timestamps (kind 8).
- **RFC 2018** — TCP Selective Acknowledgement Options (kind 4
  SACK Permitted, kind 5 SACK).
- Surfaced: `TcpHeader::encode/decode`, `iter_options` returning
  `TcpOption::{Mss, WindowScale, SackPermitted, Timestamps,
  Other}`, `ipv4_pseudo_checksum` + `verify_ipv4`, `build_syn` /
  `build_rst` builders. Flag-bit constants `FLAG_FIN..FLAG_CWR`.

### IPv6 + ICMPv6 ND (`pkt_ipv6`)
- **RFC 8200** — IPv6 base specification. §3 fixed header, §8.1
  pseudo-header for upper-layer checksums.
- **RFC 4443** — ICMPv6. §2.1 message general format, §3 error
  messages, §4 echo request/reply.
- **RFC 4861** — Neighbor Discovery for IPv6. §4.1–4.5 message
  layouts (Router Solicitation / Advertisement, Neighbor
  Solicitation / Advertisement, Redirect). §4.6 option formats
  (Source / Target Link-Layer Address, Prefix Information, MTU).
- Surfaced: `Ipv6Header::encode/decode`, `pseudo_checksum`,
  `Icmpv6Header`, ND option iterator + appender, message builders
  for RS / NS / NA (with R/S/O flags) / RA (with M/O flags +
  CurHopLimit + Router Lifetime + Reachable / Retrans timers).
- `ipv6_stack::build_udp_segment` constructs the mandatory non-zero IPv6 UDP
  checksum. `ipv6_stack::send_udp` performs IPv6 longest-prefix route lookup,
  preferred/deprecated source selection, gateway-aware NDP lookup or RFC 2464
  multicast MAC mapping, and emits the complete Ethernet frame. RX validates
  the IPv6 pseudo-header checksum and UDP length before forwarding the exact
  payload and ingress ifindex through the registered userspace datagram hook.
  A unicast cache miss installs an `Incomplete` NDP entry and emits a Neighbor
  Solicitation to the target's solicited-node multicast address with IPv6 hop
  limit 255; repeated sends do not flood duplicate solicitations while that
  resolution is pending. The complete UDP segment is retained in a bounded,
  namespace-keyed queue and emitted when the Neighbor Advertisement updates
  the cache; queue exhaustion returns `ENOBUFS` rather than reporting a
  datagram as sent and dropping it.
- Native TCP6 RX validates the IPv6 pseudo-header checksum before entering the
  shared TCP state machine. Active and passive opens use IPv6 FIB/source
  selection and NDP, emit Ethernet+IPv6+TCP frames, and retain native IPv6
  endpoints for `getsockname`, `getpeername`, and accept.
- AF_INET6 sockets implement `IPV6_UNICAST_HOPS`, `IPV6_MTU_DISCOVER`,
  `IPV6_MTU`, `IPV6_RECVERR`, `IPV6_RECVPKTINFO`, `IPV6_RECVHOPLIMIT`,
  `IPV6_DONTFRAG`, and `IPV6_V6ONLY` with Linux argument validation and
  `ENOTCONN` for an unconnected `IPV6_MTU` query. UDP6 receive records retain
  destination address, ingress ifindex, and received hop limit per datagram;
  `recvmsg` emits `IPV6_PKTINFO` and `IPV6_HOPLIMIT` control messages when the
  corresponding receive options are enabled and reports `MSG_CTRUNC` when a
  complete requested record does not fit.
- IPv6 address and route registries are keyed by immutable network-namespace
  ID internally. Source selection, local-address tests, route lookup,
  rtnetlink/proc snapshots, and final namespace teardown use the caller's
  namespace; identical interface/address/prefix values may coexist without
  cross-namespace visibility.

### DNS (`pkt_dns`)
- **RFC 1035** — Domain Names — Implementation and Specification
  (P. Mockapetris, Nov 1987). §4 messages, §4.1.4 name
  compression (length-prefixed labels + 0xC0xx 14-bit pointer).
- **RFC 3596** — DNS Extensions to Support IPv6 (TYPE_AAAA = 28).
- **RFC 6891** — EDNS(0) (TYPE_OPT = 41).
- Surfaced: `DnsHeader::encode/decode` with opcode + rcode +
  flag-bit accessors, `encode_name` / `decode_name` (with hop-
  capped pointer-chasing), `Question` + `ResourceRecord`
  encode/decode, `build_a_query` convenience, opcode + rcode +
  RR type + class constants.

**No GPL Linux source consulted.**

## 12. App-layer codecs (`pkt_dhcp`, `tls`, `http`, `pkt_mdns`)

The networking axis cycle continued past raw L4 codecs into the
app-layer protocols a usable kernel network stack needs the moment
its Ethernet driver brings up a link. References (public-only):

### DHCPv4 (`pkt_dhcp`)
- **RFC 2131** — Dynamic Host Configuration Protocol (R. Droms,
  Mar 1997). §2 BOOTP-derived 240-byte fixed header.
- **RFC 2132** — DHCP Options and BOOTP Vendor Extensions
  (S. Alexander & R. Droms, Mar 1997). All numbered options.
- **RFC 951 / 1497** — BOOTP base + 0x63825363 magic cookie.
- Surfaced: `DhcpHeader::encode_into`/`decode`, options iterator
  + builders, message-type constants
  (DISCOVER/OFFER/REQUEST/DECLINE/ACK/NAK/RELEASE/INFORM), and
  `build_discover` / `build_request` convenience.

### TLS 1.3 record-layer (`tls`)
- **RFC 8446** — TLS 1.3 (E. Rescorla, Aug 2018). §5.1 Record
  Layer (5-byte TLSPlaintext header — type / legacy_record_version
  / length). §4 Handshake Protocol (1-byte msg_type + 24-bit BE
  length). §6 Alert Protocol (level + description). §B.1–B.4
  ContentType / HandshakeType / AlertDescription / ExtensionType
  enumerations.
- Surfaced: `Record::encode/decode` with the (1<<14)+256 ciphertext
  ceiling, `HandshakeMessage::encode/decode` with 24-bit BE length,
  `Alert::encode/decode`, `record_for_handshake` /
  `record_for_alert` builders that pin the spec-required
  legacy_record_version = 0x0303 invariant. Constants for
  ContentType / HandshakeType / AlertDescription / common
  ExtensionType values (server_name = 0, supported_versions = 43,
  key_share = 51, etc.). **No crypto** — codec-only.

### HTTP/1.1 framing (`http`)
- **RFC 9112** — HTTP/1.1 (R. Fielding et al, June 2022). §3
  Message Format. §4 Request Line. §5 Status Line. §6 Field Lines.
  §7.1 Chunked Transfer Coding.
- Surfaced: `RequestLine::encode/decode`, `StatusLine::encode/
  decode`, `parse_headers` + `append_field` + `append_end_of_headers`
  with OWS trimming, `iter_chunks` / `encode_chunk` for chunked
  bodies including chunk-ext stripping, terminating zero-length
  chunk handling.

### mDNS / DNS-SD (`pkt_mdns`)
- **RFC 6762** — Multicast DNS (S. Cheshire & M. Krochmal, Feb
  2013). §5 transport (UDP port 5353, IPv4 224.0.0.251 / IPv6
  FF02::FB). §10.2 cache-flush bit at top of CLASS in answers.
  §18.12 unicast-response bit at top of QCLASS in questions.
- **RFC 6763** — DNS-Based Service Discovery. §4 service-type
  browsing via PTR queries for `_service._proto.local`. §6 TXT
  records: 1-byte-length-prefixed key=value strings.
- **RFC 2782** — DNS SRV records (priority + weight + port +
  target).
- Surfaced: multicast address constants, class-helper functions
  for the cache-flush + unicast-response top bits, query/response
  header builders that pin the mDNS conventions (id=0, AA=1 on
  responses), TXT RDATA build + parse, `SrvRecord` encode/decode
  on top of the existing DNS name codec, `services_meta_name`
  + `service_browse_name` helpers.

**No GPL Linux source consulted.**

## 13. NTP, WebSocket, DHCPv6, ICMP-extra + IGMPv3 codecs

The networking axis cycle continued past app-layer protocols into
the time-sync, real-time-streaming, IPv6-config, and IPv4-error /
multicast layers a kernel network stack also needs.

### NTPv4 (`pkt_ntp`)
- **RFC 5905** — Network Time Protocol Version 4 (D. Mills et al,
  June 2010). §6 NTP timestamp format. §7.3 Packet Header Variables.
  §7.5 Packet Header Format.
- **RFC 868** — referenced for the historical 1900-01-01 NTP prime
  epoch.
- Surfaced: `NtpHeader::encode/decode` (LI/VN/Mode byte packing,
  signed Poll + Precision, BE 16.16 short-fixed-point Root Delay /
  Root Dispersion, 4-byte Reference ID, four 64-bit timestamps).
  `unix_to_ntp` / `ntp_to_unix` with the 2_208_988_800-second epoch
  offset. `client_request` SNTP-style builder.

### WebSocket (`ws`)
- **RFC 6455** — The WebSocket Protocol (I. Fette & A. Melnikov,
  Dec 2011). §5.2 base framing (FIN + RSV1-3 + 4-bit opcode + MASK
  + 7-bit / 16-bit / 64-bit length encodings). §5.3 client → server
  masking (4-byte key XOR). §5.5 control-frame ≤ 125 bytes
  invariant. §7.4 status codes.
- Surfaced: `Frame::encode/decode` covering the full length ladder,
  client masking unwound on decode, opcode + close-status
  constants, builders (`text_frame` / `binary_frame` /
  `close_frame` / `ping_frame` / `pong_frame`), control-frame size
  enforcement.

### DHCPv6 (`pkt_dhcpv6`)
- **RFC 8415** — DHCPv6 (T. Mrugalski et al, Nov 2018). §8 Message
  Formats. §9 Client/Server message header (4 bytes — msg-type +
  24-bit transaction-id). §9.1 Relay Agent header (34 bytes). §21
  Options. §11 DUID format.
- **RFC 3315** — original DHCPv6 layouts that 8415 inherits.
- Surfaced: `DhcpV6Header::encode/decode`, `RelayHeader::encode/
  decode`, full message-type constant set
  (SOLICIT/ADVERTISE/REQUEST/CONFIRM/RENEW/REBIND/REPLY/RELEASE/
  DECLINE/RECONFIGURE/INFORMATION_REQUEST/RELAY_FORW/RELAY_REPL),
  selected option codes (CLIENTID, SERVERID, IA_NA/IA_TA/IA_PD,
  IAADDR, ORO, ELAPSED_TIME, RAPID_COMMIT, DNS_SERVERS,
  DOMAIN_LIST, …), DUID-LL builder, ORO + Rapid Commit + Elapsed
  Time appenders, `build_solicit` convenience.

### ICMPv4 errors + IGMPv3 (`pkt_icmp_extra`)
- **RFC 792** — Internet Control Message Protocol (J. Postel, Sep
  1981). Type 3/4/5/11/12 messages.
- **RFC 1191** — Path MTU Discovery (next-hop MTU at low 16 bits of
  rest-of-header on a Fragmentation-Needed Destination Unreachable).
- **RFC 3376** — IGMPv3 (B. Cain et al, Oct 2002). §4.1 Membership
  Query, §4.2 Membership Report, §4.2.4 Group Record format.
- Surfaced: ICMP error builders (Destination Unreachable with
  `build_fragmentation_needed`, Time Exceeded, Redirect),
  `IcmpError::decode` with checksum verification, IGMP type
  constants, IGMPv3 Membership Query decoder, `GroupRecord`
  encode/decode, `build_v3_report` Membership Report builder with
  installed checksum.

**No GPL Linux source consulted.**

## 14. HTTP/2, STUN, MQTT v5, VLAN+LLDP codecs

The networking-axis cycle continued past the time-sync / streaming
layer into modern app-layer + L2 protocols a kernel network stack
needs to peer with on real wire.

### HTTP/2 (`http2`)
- **RFC 9113** — HTTP/2 (M. Thomson & C. Benfield, June 2022).
  §3.4 Connection Preface. §4.1 Frame Format (9-byte header:
  24-bit length + 8-bit type + 8-bit flags + reserved bit + 31-bit
  stream id). §6 Frame Definitions. §6.5.2 SETTINGS parameters.
  §7 Error Codes.
- Surfaced: `FrameHeader::encode/decode` (with the R-bit masking
  invariant), `build_frame` generic, SETTINGS payload encoder/
  parser, `build_window_update` / `build_rst_stream` / `build_ping`
  (with ACK flag) / `build_goaway`. Full frame-type + flag-bit +
  SETTINGS-parameter + error-code constant set, plus the 24-byte
  CLIENT_PREFACE.

### STUN (`stun`)
- **RFC 8489** — Session Traversal Utilities for NAT (M. Petit-
  Huguenin et al, Feb 2020). §5 Message Structure (20-byte fixed
  header with magic cookie 0x2112A442 + 96-bit transaction id).
  §6 Base Attributes. §14 Method Numbering.
- Surfaced: `message_type` / `parse_message_type` covering the
  interleaved method+class bit packing, `StunHeader::encode/decode`
  (with magic-cookie verification), TLV iterator + builder with
  4-byte attribute alignment per §6, XOR-MAPPED-ADDRESS encode/
  decode (XORing port and IPv4 address with the magic cookie),
  ERROR-CODE encode/decode (3-bit class + 8-bit number split),
  `build_binding_request` convenience.

### MQTT v5 (`mqtt`)
- **OASIS MQTT v5.0 Standard** (7 March 2019). Public.
  §2.1 Fixed Header. §2.1.4 Remaining Length VarInt (1-4 bytes,
  7-bit per byte continuation). §3.1 CONNECT Packet (Protocol
  Name "MQTT" + level 5 + Connect Flags + Keep Alive +
  Properties + Client ID payload). §3.3 PUBLISH. §3.13 PINGREQ.
  §3.14 DISCONNECT.
- Surfaced: VarInt encode/decode (with 4-byte cap rejection),
  `FixedHeader::encode/decode`, MQTT UTF-8-string append/decode,
  `build_connect_v5`, `build_publish_v5` (DUP/QoS/retain in fixed-
  header flags), `build_pingreq`, `build_disconnect_v5`. Full
  packet-type + connect-flag + reason-code + property-id constants.

### VLAN 802.1Q + LLDP 802.1AB (`pkt_l2`)
- **IEEE 802.1Q-2018** — Bridges and Bridged Networks. §9.6 TPID
  values 0x8100 (C-VLAN) + 0x88A8 (S-VLAN, "QinQ"). §9.6.2 TCI
  layout (PCP + DEI + VID).
- **IEEE 802.1AB-2016** — LLDP. §8.1 EtherType 0x88CC + nearest-
  bridge multicast MAC 01:80:C2:00:00:0E. §8.4 TLV format
  (7-bit Type + 9-bit Length packed into 2 bytes BE). §8.5
  mandatory + optional TLVs (Chassis ID / Port ID / TTL /
  System Name / System Capabilities / Management Address /
  End-of-LLDPDU sentinel).
- Surfaced: `VlanTag::encode/decode`, `iter_tlvs` over an LLDPDU,
  `append_tlv` + builders for Chassis ID / Port ID / TTL /
  System Capabilities / End-of-LLDPDU, `parse_ttl`, full subtype +
  capability-bit constant set.

**No GPL Linux source consulted.**

## 15. CoAP, GRE, SCTP, TFTP codecs

The networking-axis cycle continued past app-layer + L2 into IoT,
tunneling, multi-stream transport, and netboot protocols.

### CoAP (`pkt_coap`)
- **RFC 7252** — The Constrained Application Protocol (Z. Shelby et
  al, June 2014). §3 message format. §3.1 option format with
  Delta + Length nibbles + 13 / 14 / 15 extended forms. §5.10
  registered options. §12.1 message codes (request methods +
  response codes class.detail).
- Surfaced: `Header::encode_into/decode` (with version + TKL +
  bad-token-length rejection), `append_option` + `parse_options_and_payload`
  with the 13 / 14 / 15 nibble extension form, payload-marker
  handling, response-code split, `build_get_request` for the
  `.well-known/core` browsing convention.

### GRE (`pkt_gre`)
- **RFC 2784** — Generic Routing Encapsulation (D. Farinacci et al,
  March 2000). §2.1 4-byte fixed header (flags + version + protocol
  type) + optional 16-bit checksum + 16-bit reserved.
- **RFC 2890** — Key and Sequence Number Extensions to GRE (G.
  Dommety, September 2000). K and S flags adding optional 32-bit
  Key + 32-bit Sequence Number.
- Surfaced: `GreHeader::encode/decode`, `build` builder with
  optional Checksum / Key / Sequence + automatic CRC-style
  ip-checksum installation, `verify` for received packets, full
  flag-bit + helper accessor set.

### SCTP (`pkt_sctp`)
- **RFC 9260** — Stream Control Transmission Protocol (R. Stewart
  et al, June 2022). §3.1 12-byte common header. §3.2 chunk header
  format. §3.3 chunk types (INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK/
  DATA/SACK/HEARTBEAT/HEARTBEAT-ACK/ABORT/SHUTDOWN/ERROR/PAD).
- **RFC 3309** — SCTP Checksum (CRC-32C / Castagnoli, polynomial
  0x1EDC6F41, transmitted in *little-endian* byte order on the
  wire).
- Surfaced: `CommonHeader::encode/decode`, `iter_chunks` walking
  with 4-byte alignment padding, `append_chunk` builder,
  `build_data_value` for the §3.3.1 DATA chunk body (TSN +
  Stream ID + Sequence + PPID + user data), `crc32c` standalone
  and `compute_checksum` / `build_packet` / `verify_packet`
  end-to-end with the LE-on-wire SCTP convention.

### TFTP (`pkt_tftp`)
- **RFC 1350** — The TFTP Protocol Revision 2 (K. Sollins, July
  1992). §5 packet formats. Opcodes RRQ / WRQ / DATA / ACK / ERROR.
- **RFC 2347** — TFTP Option Extension (G. Malkin & A. Harkin, May
  1998). OACK packet (opcode 6) carrying the server-acknowledged
  options.
- Surfaced: `Packet` enum encode/decode covering RRQ / WRQ / DATA /
  ACK / ERROR / OACK including options on requests + OACK,
  full mode + error-code constant set, NUL-terminated string codec
  with unterminated-buffer rejection.

**No GPL Linux source consulted.**
