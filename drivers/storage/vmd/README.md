# drivers/storage/vmd — Intel Volume Management Device

`narf-drivers-storage-vmd` handles the Intel Volume Management Device:
a PCIe bridge that hides a subtree of NVMe/storage functions behind
itself, so the driver must re-root that subtree before the ordinary
PCI walk can bind drivers to the children. It identifies the VMD bridge
by Intel device-ID, maps BAR0 (the VMD-private config-space window),
and walks it as if it were a standard PCIe ECAM region, using the
standard `(bus << 20) | (devfn << 12) | reg` offset math.

Every discovered function is pushed into the global `narf-bus`
registry tagged with a synthetic `segment`, so its (bus, device,
function) key cannot collide with the host PCIe domain, and from there
existing drivers (NVMe and others) bind to the children through the
same `probe_all_pci` walk that probed the bridge. Two pieces make the
children actually usable: the MEMBAR windows (BAR2/BAR4 apertures child
BARs must decode inside, registered before the children are installed)
and MSI remapping (issue #933 items 3 and 4). The implementation is
`src/vmd.rs` (`Vmd`, `probe()`, `register_pci_driver_vmd()`), and the
crate is dual-build (built-in or loadable `.ko`).

- Spec: [`../specification/spec.md`](../specification/spec.md)
