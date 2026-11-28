# drivers/usb/storage — USB mass storage (Bulk-Only Transport)

Dual-build crate (`narf-drivers-usb-storage`):

- **Built-in** (default): the BOT/SCSI wire codec only (`src/codec.rs`).
  The built-in binder stays in `narf-drivers-usb::msc`, which takes its
  interface triple and CBW/CSW signatures from this codec. A
  `drivers/usb/msc` smoke checks its encoders against the codec byte for
  byte.
- **Module** (`usb-storage.ko`): `cargo narf build build-module --package
  narf-drivers-usb-storage --no-default-features --features module`. It
  matches BOT interfaces (08/06/50) and drives the stick through the
  `narf_usb_*` exports. Configure and `SET_CONFIGURATION` run from
  completions; SCSI then runs synchronously over callback-less bulk
  requests waited with `narf_usb_wait`. The stick is published as
  `usb-msc<N>` through `narf_blk_*`.

The module handles LUN 0 and READ/WRITE(10) only, at most 4 KiB per
command, with no BOT reset recovery: a stall or phase error takes the
device offline. Build the kernel with `narf-drivers-usb/msc-module-only`
so the built-in binder leaves the stick to the module. The proof is
`cargo narf smoke usb-storage-module-block-smoke`.

Design: `modules/DATAPATH_ABI_DESIGN.md` ("USB transfer datapath",
"Block datapath").
