# USB4 NHI and connection manager — specification

## 1. Purpose & scope

Discover Intel and AMD USB4 NHIs, run a native connection manager, enumerate
USB4 routers and establish USB3 and DisplayPort tunnels. The legacy pure
configuration/topology helpers remain available for callers and tests.

## 2. Assumptions

ACPI `_SB._OSC` must confirm native USB4 support and grant the corresponding
USB3/DP control bits. A controller needs an accessible BAR0 and coherent DMA.
PCI class `0x0c0340` identifies a USB4 NHI, including AMD Pink Sardine. The
number of NHI functions does not determine the number of physical USB-C ports.

## 3. Public interface

- `nhi::matches_controller(vendor, device, class)` accepts the USB4 class and
  known Intel NHI IDs; xHCI and PCIe tunnel bridges are separate drivers.
- `topology::domains() -> Vec<Domain>` snapshots live per-NHI router/adapter
  state. Router route strings are meaningful only within their domain.
- `tunnel::displays()` and `tunnel::usb3_tunnels()` return `TunnelInfo` snapshots
  with domain, protocol and input/output `(route, port)` endpoints. A DP
  `dprx_done` flag is reported separately from tunnel creation. Neither is
  proof that the GPU has trained an external monitor or enabled scanout.
- `register_initcalls()` registers PCI discovery at Device and starts one
  task per controller at Late. MSI-X wakes the task, with bounded timed
  polling when MSI-X is unavailable. No config transaction holds a spinlock
  across an await.

The implementation supports USB4 routers with buffer-allocation parameters,
USB3 tunneling between parent/child routers, and one host-to-device DP tunnel
per domain. DP capabilities are limited to RBR and the common lane count;
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

The CM does not request PCIe or XDomain control. System suspend is refused
while a native CM has been started: tunnel suspend/replay remains unsupported.
Transport failure clears public snapshots and attempts owned-path teardown;
a poisoned channel can prevent that teardown, so the suspend refusal remains.

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
firmware tunnel adoption; native suspend/resume and controller reset recovery;
legacy Thunderbolt/ICM, PCIe/XDomain tunnels, link bonding and retimer policy.
AMD source encoder setup, firmware loading and link training belong to GPU.
