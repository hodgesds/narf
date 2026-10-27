# USB4 NHI and connection manager — specification

## 1. Purpose & scope

Discover Intel and AMD USB4 NHIs, run a native connection manager, enumerate
USB4 routers and establish USB3, DisplayPort and PCIe tunnels. The legacy pure
configuration/topology helpers remain available for callers and tests.

## 2. Assumptions

ACPI `_SB._OSC` must confirm native USB4 support and grant the corresponding
control bits (USB4 `_OSC` capabilities DWORD 2: bit 0 USB3 tunnelling,
bit 1 DisplayPort tunnelling, bit 2 PCIe tunnelling, bit 3 XDomain). The CM
requests USB3, DisplayPort and PCIe and proceeds per protocol on the bits
actually granted: a platform that grants USB3/DP but not PCIe still gets
USB3/DP tunnels, and PCIe paths are never programmed without the PCIe grant.
A controller needs an accessible BAR0 and coherent DMA.
PCI class `0x0c0340` identifies a USB4 NHI, including AMD Pink Sardine. The
number of NHI functions does not determine the number of physical USB-C ports.

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
- `register_initcalls()` registers PCI discovery at Device and starts one
  task per controller at Late. MSI-X wakes the task, with bounded timed
  polling when MSI-X is unavailable. No config transaction holds a spinlock
  across an await.

The implementation supports USB4 routers with buffer-allocation parameters,
USB3 tunneling between parent/child routers, PCIe tunnelling between an
ancestor router's PCIe downstream adapter and a device router's PCIe
upstream adapter (path hops in both directions, adapters enabled last via
ADP_PCIE_CS_0 PE), and one host-to-device DP tunnel per domain. DP
capabilities are limited to RBR and the common lane count;
higher-rate bandwidth allocation is not implemented. Existing enabled
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

The CM does not request XDomain control. PCIe tunnelling is gated on the
PCIe bit of the `_OSC` grant at both layers: without it, router
configuration never sets ROUTER_CS_5 PTO and `reconcile` never programs a
PCIe path; with it, a device router's PTO is set only when its parent
router carries a PCIe downstream adapter. A PCIe downstream adapter
serves at most one live PCIe tunnel, and a tunnel's origin is the
nearest ancestor router carrying one. The native CM joins the
device-PM fan-out with a state-checked handler: system suspend is refused
(`Busy`) only while tunnels are live, or while a domain's CM has exited
with tunnel writes unrolled-back. With no live paths the handler reports
ready — an idle, stopped, or cleanly-exited CM never vetoes suspend.
Tunnel suspend/replay remains unsupported, so live tunnels still block
sleep. Transport failure clears public snapshots and attempts owned-path
teardown; a poisoned channel can prevent that teardown, and the orphaned
domain's refusal persists until a CM for it tears the paths down.

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

Hardware validation; full DP bandwidth allocation and multiple DP tunnels;
firmware tunnel adoption; tunnel suspend/replay (live tunnels still veto
system suspend); controller reset recovery after resume;
legacy Thunderbolt/ICM, XDomain tunnels, link bonding and retimer policy.
PCIe remainders: a pre-activation wait for the PCIe adapters' LTSSM
Detect state, and a runtime PCI rescan of the NHI's companion bridge so
tunnelled devices enumerate without a reboot (the CM publishes tunnels;
registering newly appeared PCI devices is a bus-subsystem surface).
AMD source encoder setup, firmware loading and link training belong to GPU.
