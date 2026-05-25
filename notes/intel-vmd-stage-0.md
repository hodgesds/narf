# Intel VMD bridge — Stage-0 enumeration

Date: 2026-05-25. Companion to `drivers/storage/src/vmd.rs` and the
small extensions to `bus/src/{registry,pcie,lib}.rs`.

## What landed in Stage-0

Three edits, one new module:

1. **`bus::registry::append_devices`** — new public API that pushes
   additional `BusDevice`s onto the registry instead of replacing
   it. The host PCIe walk still owns the initial `install`; VMD is
   the first caller that needs to grow the registry post-init.

2. **`bus::pcie::enumerate_segment`** — variant of `enumerate_n`
   that takes a synthetic `segment` so children behind a VMD bridge
   don't collide with `segment=0` host PCIe devices. The walk
   itself is byte-for-byte the same — VMD's BAR0 is a standard ECAM
   region; only the addressing context changes.

3. **`drivers/storage/src/vmd.rs`** — the actual driver:
   - **PCI ID table** — eight Intel device IDs from Linux
     `drivers/pci/controller/vmd.c` `vmd_pci_tbl[]`: `8086:201D`
     (original), `28C0` (Skylake-X), `467F` (Comet Lake), `4C3D`
     (Rocket Lake / Alder Lake-P), `7D0B` (Raptor Lake), `9A0B`
     (Tiger Lake), `A77F` (Meteor Lake), `AD0B` (Tiger Lake-H).
     All eight register as `MatchKind::VendorDevice` so the
     bus tie-breaker prefers them over any class backstop.
   - **`Vmd::bring_up`** — maps BAR0 (`VMD_CFGBAR`), derives the
     child-bus count from BAR size (`size >> 20`), allocates a
     unique segment per bridge (`VMD_SEGMENT_BASE | instance`,
     mirroring Linux's `pci_bus_find_emul_domain_nr` choice of
     0x10000+), walks the BAR0 ECAM via `enumerate_segment`, and
     hands the children to `append_devices`.
   - **Probe log** — `vmd: detected DID=$did BAR0=$base $N child
     devices found (segment=$seg, buses=$nbuses)` follows the same
     shape as the i915 / NVMe probe-announce lines.

4. **Stage::Device initcall** — registered alongside the existing
   AHCI / SDHCI Stage::Subsys calls in
   `drivers/storage/src/lib.rs::register_initcalls`. VMD itself is
   discovered by the host PCIe walk at boot; this initcall is what
   gets the match table populated so `probe_all_pci` finds it.

## What Stage-0 does NOT do (deferred)

- **No child probe re-trigger.** Children land in the registry
  with a non-zero segment, but Stage-0 stops at "log how many we
  found." A follow-up needs to teach `read_bar` /
  `assign_unprogrammed_bars` to consult the VMD-private cfg window
  for `segment != 0` devices, then re-run `probe_all_pci` so NVMe
  can claim them. The plumbing is the gnarly bit because the BAR
  windows for VMD children live inside `VMD_MEMBAR1/2`, not the
  host MMIO pool.

- **No MSI remapping.** VMD owns its own MSI and forwards children's
  MSIs through a remapped table. That's the follow-up that touches
  `interrupts/` and is explicitly out of scope for this stage.

- **No `VMD_FEAT_HAS_MEMBAR_SHADOW` / `_VSCAP` / `BUS_RESTRICTIONS`
  handling.** These only matter once children's MMIO is being
  re-driven from outside the bridge; Stage-0's enumerate-only path
  reads cfg space through BAR0, which is unaffected.

## Source citation

Direct adaptation of `drivers/pci/controller/vmd.c` is fine under
the post-2026-05-20 relicense (GPL-2.0-or-later). The PCI ID table,
`VMD_CFGBAR`/`MEMBAR1`/`MEMBAR2` indices, and the
`PCIE_ECAM_OFFSET(bus, devfn, reg)` cfg-window math come from
there.
