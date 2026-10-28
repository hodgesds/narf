# USB4 NHI and connection manager — specification

## 1. Purpose & scope

Discover Intel and AMD USB4 NHIs, run a native connection manager, enumerate
USB4 routers and establish USB3, DisplayPort and PCIe tunnels. The legacy pure
configuration/topology helpers remain available for callers and tests.

## 2. Assumptions

ACPI `_SB._OSC` must confirm native USB4 support and grant the corresponding
control bits (USB4 `_OSC` capabilities DWORD 2: bit 0 USB3 tunnelling,
bit 1 DisplayPort tunnelling, bit 2 PCIe tunnelling, bit 3 XDomain). The CM
requests USB3, DisplayPort, PCIe and XDomain and proceeds per protocol on
the bits actually granted: a platform that grants USB3/DP but not PCIe
still gets USB3/DP tunnels, and PCIe paths are never programmed without
the PCIe grant. XDomain (host-to-host) services likewise run only under
the XDomain grant.
A controller needs an accessible BAR0 and coherent DMA.
PCI class `0x0c0340` identifies a USB4 NHI, including AMD Pink Sardine. The
number of NHI functions does not determine the number of physical USB-C ports.

A controller whose NHI firmware status (`REG_FW_STS`, bit 0 `ICM_EN`) reports
the legacy firmware connection manager (ICM) enabled is not a native-CM
target: the firmware owns that fabric. Detection samples the status until it
settles (two consecutive equal reads) and any state that will not settle, or
cannot be read, is treated as firmware-owned. The native CM stands down for
such controllers; it never starts, resets, or speaks to the ICM firmware.

## 3. Public interface

- `nhi::matches_controller(vendor, device, class)` accepts the USB4 class and
  known Intel NHI IDs; xHCI and PCIe tunnel bridges are separate drivers.
- `topology::domains() -> Vec<Domain>` snapshots live per-NHI router/adapter
  state. Router route strings are meaningful only within their domain.
- `tunnel::displays()`, `tunnel::usb3_tunnels()` and `tunnel::pcie_tunnels()`
  return `TunnelInfo` snapshots with domain, protocol and input/output
  `(route, port)` endpoints. A DP `dprx_done` flag is reported separately from
  tunnel creation. Neither is proof that the GPU has trained an external
  monitor or enabled scanout. A PCIe `TunnelInfo`'s input is the PCIe
  downstream adapter on the nearest ancestor router carrying one; its
  output is the device router's PCIe upstream adapter. Publication of a
  PCIe tunnel is the handoff surface for the tunnelled hierarchy: devices
  behind the device router's PCIe switch enumerate under the NHI's
  companion PCIe bridge through the normal PCI driver path once the bus
  subsystem scans that bridge (runtime rescan of the companion bridge is
  bus-subsystem work, §8).
- `tunnel::granted_controls()` returns the `_OSC` control mask the CM is
  operating under and `tunnel::pcie_tunnelling_granted()` its PCIe bit, so
  "firmware did not grant PCIe control" is observable state, never inferred
  from an empty tunnel list.
- `tunnel::live_tunnel_count()` reports the published live-tunnel count
  across domains, and `tunnel::orphaned_path_domains()` the domains whose
  CM exited with tunnel writes unrolled-back. Together they are the
  state the CM's device-PM handler gates system suspend on (§4).
- `tunnel::suspended_tunnels()` returns the tunnels currently quiesced
  for system suspend (recorded by identity, awaiting replay), and
  `tunnel::replay_failures()` the tunnels whose resume replay failed
  and rolled back. The device-PM handlers only latch requests in this
  state; the per-domain CM task performs the quiesce (journaled
  teardown, hop drain before credit release) and the replay
  (re-activation of the recorded endpoints against the re-scanned
  topology) from its own loop. A peer that vanished across the sleep
  is torn down, not replayed; a failed replay is never published
  live and stays named in `replay_failures()` until a resume retry
  restores it.
- `xdomain::peers()` returns `PeerInfo` snapshots of the discovered
  peer hosts (domain, route, XDomain UUID, advertised identity and
  services, ThunderboltIP login state, link state, peer MAC and
  transmit path). A peer host appears here once its depth-1 router has
  been probed and its property block fetched and validated; it is
  removed when its router leaves the topology.
- Each peer advertising the Thunderbolt networking service gets a
  netdev named `tbnet<domain>-<n>` registered with the net registry,
  carrying Ethernet frames over ThunderboltIP data frames once the
  mutual login completes (see §8 for the data-transport binding).
- `register_initcalls()` registers PCI discovery at Device and starts one
  task per natively managed controller at Late. MSI-X wakes the task, with bounded timed
  polling when MSI-X is unavailable. No config transaction holds a spinlock
  across an await.
- `icm::domain_statuses() -> Vec<DomainStatus>` snapshots the per-controller
  firmware-CM detection verdict recorded at CM start: `Native`,
  `FirmwareManaged`, `Unsettled`, or `Unreadable`, with the settled
  `REG_FW_STS` value when one was observed; `icm::firmware_managed_count()`
  reports how many controllers the firmware manages. Detection
  (`icm::classify` over sampled `REG_FW_STS` reads) gates CM start per
  controller, before ring 0 and — when no controller is native — before the
  `_OSC` request is made at all. Stood-down controllers get no ring, no
  config traffic, and no device-PM registration.

The implementation supports USB4 routers with buffer-allocation parameters,
USB3 tunneling between parent/child routers, PCIe tunnelling between an
ancestor router's PCIe downstream adapter and a device router's PCIe
upstream adapter (path hops in both directions, adapters enabled last via
ADP_PCIE_CS_0 PE), and multiple host-to-device DP tunnels per domain. DP
tunnels run at the negotiated envelope — RBR through HBR3 at the adapters'
common lane count — programmed into both adapters' DP_REMOTE_CAP. A DP IN
adapter advertising bandwidth-allocation mode with a decodable granularity
(250/500/1000 Mb/s) is allocated against: the CM publishes its bandwidth
group — tunnels sharing a first fabric link, charged together with the
USB3 tunnels over that link against the link's raw bandwidth less a 10%
guard band — as GROUP_ID/CM_ID/ESTIMATED_BW in ADP_DP_CS_2, grants the
tunnel its payload in DP_STATUS ALLOCATED_BW, and services later
allocation requests (ADP_DP_CS_8 DR/REQUESTED_BW) through the CM
Acknowledge handshake, granting at most what the group has free. Adapters
without allocation mode are programmed in legacy mode at the full
negotiated envelope. `TunnelInfo` publishes each DP tunnel's negotiated
envelope and live grant (`dp`) and every tunnel's fabric consumption in
Mb/s (`consumed_mbps`), so suspend/resume replay rebuilds a DP tunnel at
its recorded rate. Existing enabled
firmware tunnels are preserved and are not represented as newly owned paths.

## 4. Invariants

Ring-zero descriptors and frames stay allocated until DMA is stopped. Failed
bus-master revocation quarantines the controller's DMA/IRQ ownership. Config
submission and receive/repost operations run through the PCI capability's
`invoke` epoch check; revocation stops new work while teardown still quiesces
the owned hardware. A malformed terminal reply poisons the channel. Config
replies must match route, port, space, offset, length and sequence; a timeout
or cancelled transaction poisons the channel so a late reply cannot satisfy a
new command. Wire packets carry big-endian DWORDs and CRC32C.

Capability chains, topology depth, event queues and packet lengths are
bounded. Detach removes the affected subtree before rediscovery, including
replacement hardware at the same route. Tunnel writes are journaled before
submission, rolled back in reverse order, and never replace enabled paths.
Hop pending is read from DWORD 1 and must clear before credits are released.
USB3 bandwidth ownership uses the CMR/HCA handshake in both directions.
Protocol adapters retain vendor-defined ingress credit/flow-control fields.


DP bandwidth groups are never overcommitted: a tunnel's envelope is fitted
under its group's free budget — the first link's budget less every live
tunnel charged to the group, USB3 tunnels included — by stepping the rate
down, then halving the lanes and restarting the rate ladder, before any
path is programmed, and a tunnel that cannot fit even at RBR x1 is refused
unprogrammed. Allocation requests are granted at most the group's free
remainder and never silently dropped; a grant below the request is the
renegotiation signal to the source. DP allocation writes (DP_REMOTE_CAP,
the ADP_DP_CS_2 group/estimate fields, the DP_STATUS grant) are journaled
like every other tunnel write and roll back with the tunnel. A reduced
grant does not reprogram the programmed envelope: the source re-trains
within the granted envelope, conveyed by ALLOCATED_BW and ESTIMATED_BW.
The published tunnel set is the allocation ledger — a tunnel is published
when its activation completes and removed when its teardown completes, so
accounting never charges a half-programmed tunnel and never misses a live
one.

The CM does not request XDomain control. PCIe tunnelling is gated on the
PCIe bit of the `_OSC` grant at both layers: without it, router
configuration never sets ROUTER_CS_5 PTO and `reconcile` never programs a
PCIe path; with it, a device router's PTO is set only when its parent
router carries a PCIe downstream adapter. A PCIe downstream adapter
serves at most one live PCIe tunnel, and a tunnel's origin is the
nearest ancestor router carrying one. The native CM joins the
device-PM fan-out with a state-checked handler: system suspend is refused
(`Busy`) while tunnels are live and unquiesced, while a host-to-host
XDomain link is logged in, while a domain's CM has exited with tunnel
writes unrolled-back, or while a replay failure is outstanding. The
first tunnel refusal latches a quiesce request; the CM task
drains each live path (hop drain before credit release, via the
journaled teardown) and records it, after which the handler reports
ready — an idle, stopped, cleanly-exited, or fully-quiesced CM with no
logged-in XDomain link never vetoes suspend. On resume the CM re-scans
the topology and replays
each recorded tunnel through its original activation path; endpoints
missing from the re-scan are dropped, and a replay that fails rolls
back through its own journal and is named in the replay-failure
registry (the resume handler reports it as `DriverError`, and the
suspend handler keeps refusing until a retry restores it). While a
domain is quiescing or quiesced, its CM does not scan or reconcile —
rediscovery never reprograms paths suspend drained.

Host-to-host XDomain runs inside the CM task under the XDomain `_OSC`
grant: the engine probes each depth-1 router (a peer host) by UUID
exchange, fetches and validates its property block (fail-closed: strict
per-message lengths, bounded block size, root/directory structure and
payload bounds all checked before any state is taken from it), and
answers inbound requests from the same rules — an unknown destination
UUID draws an error response, an out-of-range properties offset draws
silence, and malformed frames are dropped. A peer whose generation
advances restarts its ThunderboltIP session; a properties-changed
notification at the same generation revalidates the view without
dropping the session. Peer errors are absorbed into per-peer state and
never fail the CM loop. The ThunderboltIP login is mutual: the link is
up only once both directions have logged in, after which Ethernet
frames cross fragmented into 4 KiB data frames and are reassembled
under the reference validation rules (strict index order, first
fragment's count and id, any failure discarding the packet in
progress). Suspend composition: a logged-in XDomain link vetoes
suspend outright — it is not quiesced the way live tunnels are, and
the veto is checked before any tunnel quiesce is latched; after resume
the engine re-reads peer properties and re-logs in, which is the
XDomain half of the replay world (tunnel replay restores paths; XDomain
replay re-establishes sessions). Transport failure
clears public snapshots and attempts owned-path
teardown; a poisoned channel can prevent that teardown, and the orphaned
domain's refusal persists until a CM for it tears the paths down.

The native CM never touches a firmware-managed controller. ICM detection
reads `REG_FW_STS` and nothing else: the register's host-writable ICM
control bits and the ICM mailbox registers are never written, ring 0 is
never started for a stood-down controller, and a controller whose firmware
status will not settle or cannot be read is stood down from rather than
fought over. Detection is per controller — one firmware-managed controller
neither blocks nor is endangered by a native CM on another.

## 5. Architecture notes

The transport is shared across x86_64 and aarch64 and uses the bus/DMA/IRQ
abstractions. Intel MSI-X uses automatic interrupt clearing; AMD uses explicit
W1C for the TX/RX ring-zero bits. Physical AMD hardware remains unvalidated.

## 6. Dependencies and references

`bus`, `io`, `interrupts`, `capabilities`, `aml`, `scheduler`, `time`, `power`.
Register fields and protocol behavior were checked against local Linux
`/usr/src/linux/drivers/thunderbolt/{pci,nhi,ctl,usb4,path,tunnel,switch,cap}.c`,
`nhi_regs.h`, `tb_regs.h`, `tb_msgs.h`, and `drivers/acpi/bus.c`.

## 7. Stage assignment

Stage 5 Silicon. QEMU executes memory-backed ring and config-device models;
it does not emulate an AMD USB4 dock or prove physical monitor output.

## 8. Open work

Hardware validation; firmware tunnel adoption; controller reset recovery after resume
(tunnel replay assumes the control channel survives the sleep or is
re-established by that recovery);
link bonding and retimer policy.
Legacy ICM is closed by detect-and-defer (§3): firmware-managed hosts are
stood aside from, and implementing the ICM protocol itself — or adopting
the firmware's tunnels — is out of scope by design, not pending work.
XDomain remainders: the NHI data-ring binding for the ThunderboltIP
netdev — `drivers/thunderbolt/src/ring.rs` implements only ring 0, so
no production `DataLink` exists yet; the binding is a TX ring with
`RING_FLAG_FRAME` and an RX ring with `RING_FLAG_FRAME |
RING_FLAG_E2E`, frame-start/end PDF masks, HopID `0xf`
(`TBNET_LOCAL_PATH`), plus the in-router XDomain path programming
that approves the peer's transmit path — until it lands, logins
complete but the netdev reports link down and no frames flow. The
local XDomain UUID is a deterministic derivation from the domain and
router identity (enumeration surfaces no firmware UUID); it is a
stable placeholder, not a provisioned identity.
DP remainders: UHBR (128b/132b) tunnel envelopes, Gen 4 asymmetric link
transitions, and renegotiating the programmed REMOTE_CAP envelope itself
in response to allocation changes (today the source re-trains within the
granted envelope).
PCIe remainders: a pre-activation wait for the PCIe adapters' LTSSM
Detect state, and a runtime PCI rescan of the NHI's companion bridge so
tunnelled devices enumerate without a reboot (the CM publishes tunnels;
registering newly appeared PCI devices is a bus-subsystem surface).
AMD source encoder setup, firmware loading and link training belong to GPU.
