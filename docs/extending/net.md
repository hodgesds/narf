# Extending NARF: Network (NIC) Drivers

Prereq: [drivers.md](drivers.md). This doc covers publishing a NIC into the
network stack after your PCI probe has brought the device up.

Source: `net/src/lib.rs`. Reference driver: `drivers/net/src/rtl8139.rs`
(smallest real NIC), plus the loopback in `net/src/lib.rs` itself.

The seam is cleanly out-of-tree: implement `Interface`, then
`narf_net::registry().register(&authority, your_iface)`.

---

## 1. The `Interface` trait — implement this

`Interface` (`net/src/lib.rs:285`) is the netdev seam. All six methods are
required (no defaults); the type must be `Send + Sync + 'static`:

```rust
pub trait Interface: Send + Sync {                          // net/src/lib.rs:285
    fn name(&self) -> &str;                                  // :288  "eth0", "lo0"
    fn mac(&self) -> [u8; 6];                                // :291  48-bit HW addr
    fn mtu(&self) -> u32;                                    // :293  1500 by convention
    fn link_up(&self) -> bool;                               // :295  sample the PHY
    fn rx_ring(&self)                                        // :299
        -> &IrqSafeSpinLock<Option<Consumer<Frame, RX_RING_N>>>;
    fn tx_ring(&self)                                        // :302
        -> &IrqSafeSpinLock<Option<Producer<Frame, TX_RING_N>>>;
}
```

The last two are the crux. NARF moves packets over **Narf-Ring** IPC
(`narf_ipc::Producer`/`Consumer`), not callback DMA:

- `rx_ring()` exposes the **consumer** half of an inbound-frame ring. The stack
  `lock().take()`s the consumer to drain frames your driver produced.
- `tx_ring()` exposes the **producer** half of an outbound-frame ring. The stack
  `lock().take()`s the producer to push frames for your driver to transmit.

`Frame` is `net/src/lib.rs:132`; ring depth is `RX_RING_N = 64`
(`net/src/lib.rs:115`) and `TX_RING_N = 64` (`net/src/lib.rs:117`). The
`Option<...>` is so ownership can be `take`n exactly once (Stage-3 drivers hand
it out and don't take it back).

---

## 2. The registration entry point

```rust
pub fn registry() -> &'static Registry;                     // net/src/lib.rs:352

impl Registry {
    pub fn register<I: Interface + 'static>(                 // net/src/lib.rs:361
        &self,
        authority: &Cap<NetIface, Grant>,
        iface: I,
    ) -> Result<Cap<NetIface, Write>, RegisterError>;
}
```

- **Cap-gated.** You need a `Cap<NetIface, Grant>` authority. Get it from
  `narf_net::trusted_net_authority() -> Option<Cap<NetIface, Grant>>`
  (`net/src/lib.rs:437`) and `derive()` a fresh one — the TCB bootstraps this.
- On success you get back a `Cap<NetIface, Write>` handle to reference your
  interface in (Stage-4) cap-gated ops.
- `RegisterError` (`net/src/lib.rs:312`) — `DuplicateName` (names must be
  unique, `net/src/lib.rs:369`) and `AuthorityRevoked`.

---

## 3. The packet path

**RX (device → stack):** your driver's RX pump reads inbound bytes from the
hardware FIFO/DMA rings, allocates a `Frame` (from a coherent DMA buffer), and
pushes it into the RX ring's **producer** half. The stack drains via the
consumer that `Interface::rx_ring` exposes.

**TX (stack → device):** the stack pushes a `Frame` into the TX ring's
producer; your driver's TX pump reads from the consumer half and DMAs the bytes
out to the hardware TX buffer.

You own both pumps. They are async tasks spawned with
`narf_scheduler::spawn(...)` from your probe; they `await` device IRQs via
`wait_for_irq` (see [drivers.md](drivers.md) §4) rather than spinning.

---

## 4. Worked reference: RTL8139

Probe (`drivers/net/src/rtl8139.rs:455`) — the tail after bring-up:

```rust
// … bring the controller up, create the RX/TX Frame rings …

let auth = match narf_net::trusted_net_authority() {        // :487
    Some(a) => a.derive().ok(),
    None => None,
};
if let Some(auth) = auth {
    let _ = narf_net::registry().register(&auth, Rtl8139Nic);  // :492
}
spawn_pumps(dev, rx_prod, tx_cons);                         // :496  RX/TX async tasks
```

- `impl narf_net::Interface for Rtl8139Nic` — `drivers/net/src/rtl8139.rs:384`.
- `spawn_pumps` (`drivers/net/src/rtl8139.rs:501`) spawns the RX and TX pump
  tasks via `narf_scheduler::spawn` (`:507`, `:512`).
- PCI registration (`drivers/net/src/rtl8139.rs:537`) is the ordinary
  `narf_bus::register_pci_driver(PciMatch { .. VendorDevice .. , probe })`,
  wired from a `Stage::Subsys` initcall in `drivers/net/src/lib.rs:96`.

### Simpler still: loopback

`net/src/lib.rs` ships a `Loopback` that implements `Interface`
(`net/src/lib.rs:511`) and a `register_loopback(&Cap<NetIface, Grant>)`
(`net/src/lib.rs:541`) / `register_loopback_named` (`net/src/lib.rs:549`) helper
that shows the minimal register-then-spawn-forwarder shape with no hardware.
Read it as the "hello world" of a NARF NIC.

---

## 5. Gotchas

- **Authority first.** If `trusted_net_authority()` returns `None` (TCB not
  bootstrapped yet), skip registration — don't panic. RTL8139 gracefully
  degrades (`drivers/net/src/rtl8139.rs:487`).
- **Unique names.** A second interface with the same `name()` gets
  `RegisterError::DuplicateName`.
- **Frames carry cap-referenced DMA, not raw pointers** — allocate them from
  `alloc_coherent` so the payload survives crossing the ring and MTE retag works
  (see [drivers.md](drivers.md) §4).
- **Ring ownership is `take`-once.** Don't assume you can re-`take` the
  producer/consumer; Stage-3 hands it to the stack and keeps it there.
- **Pumps await IRQs.** Don't busy-poll the device from a pump task; block on
  the IRQ waiter so the executor can halt.
