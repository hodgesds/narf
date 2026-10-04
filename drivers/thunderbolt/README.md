# drivers/thunderbolt — USB4 Host Interface and Connection Manager

This crate drives Thunderbolt/USB4 controllers: it discovers the USB4
Native Host Interface (NHI), runs a native connection manager (CM) in
software, enumerates the USB4 router topology behind the host, and
establishes tunnels through it. USB4 (and its Thunderbolt predecessor)
multiplexes several protocols — USB 3, DisplayPort, and PCIe — over a
single high-speed link by wrapping them in a packet-switched fabric of
routers connected by a route-string tree; the connection manager is the
entity that walks that tree, allocates path resources, and sets up the
per-protocol tunnels. NARF implements the native (host-software) CM
rather than delegating to a firmware CM, so this crate owns the fabric.

Controllers are found by PCI discovery, matching the USB4 NHI class and
known Intel NHI device IDs and covering AMD's Pink Sardine NHI. Before
the controller's DMA ring can be started, ACPI `_SB._OSC` must confirm
native USB4 support and hand the OS the USB3/DisplayPort control bits;
the crate honors that firmware handshake. One actor task per NHI owns
that controller's DMA rings, its control/configuration transaction
channel, its topology view, and its tunnels, so there is a single
serialization point per domain and no configuration transaction holds a
lock across an await. MSI-X wakes the actor, with bounded timed polling
as a fallback where MSI-X is unavailable.

Conceptually the crate is layered from the NHI and its DMA ring, through
a control channel that issues and matches configuration read/write
transactions (big-endian DWORDs with CRC32C, strict route/port/offset/
sequence matching, and channel poisoning on malformed or late replies),
up through switch/router and adapter modelling, a live topology
snapshot, and a tunnel manager. The tunnel manager supports USB3
tunneling between parent and child routers using the bandwidth-ownership
handshake in both directions, and a host-to-device DisplayPort tunnel
per domain at base link rate. Tunnel writes are journaled before
submission and rolled back in reverse on failure, and existing
firmware-enabled tunnels are preserved rather than claimed. Reporting a
tunnel is not a claim that a monitor has trained or that scanout is live.

Out of scope: PCIe and XDomain tunneling, legacy ICM (firmware CM)
operation, and tunnel suspend/replay — consequently system suspend is
refused while a native CM is running. Detach removes the affected
router subtree before rediscovery. Discovery registers at Device-stage
init and the per-controller CM task starts at Late-stage init. The crate
is `no_std`.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Stage: 5 (silicon)
