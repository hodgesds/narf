# drivers/usb/ftdi — FTDI USB-serial (dual-build)

`narf-drivers-usb-ftdi` is NARF's first USB driver that works as a
loadable module, and the reference consumer of the USB transfer datapath
(`narf_usb_*` kernel-ABI exports, `modules/DATAPATH_ABI_DESIGN.md`).

- **`codec`** (both builds): FTDI request codes, the BM/R and H-series baud
  divisors, modem-control encoding, and bulk-IN status framing. Pure
  arithmetic, `const` where the module needs it at compile time. The
  built-in driver in `narf-drivers-usb` (`serial::ftdi`) re-exports it, so
  built-in and module program identical values.
- **built-in build** (default): the codec only. FTDI parts bind through the
  USB stack's serial cascade, which owns `/dev/ttyUSB<N>` and termios for
  every vendor serial family.
- **module build**: a working driver for single-interface parts — FT232BM/R
  (0403:6001, QEMU's `usb-serial`), FT-X (0403:6015), FT232H (0403:6014).
  It is a state machine driven entirely by completion callbacks:

  1. probe reads the probed configuration descriptor, picks the first
     interface's bulk pair, and reads the device descriptor (control IN);
  2. endpoint configuration, SET_CONFIGURATION, FTDI reset, 115200 baud,
     8N1, DTR/RTS, no flow control (control OUT, one per completion);
  3. publishes a module-backed `/dev/ttyUSB<N>`, keeps one bulk-IN posted
     (stripping FTDI's two status bytes) and moves writers' bytes to
     bulk-OUT on every kick.

  It links nothing but KSYMTAB imports: no allocator, no slice copies, no
  indexing that could panic (cargo narf's `nm -u` gate).

```
cargo narf build build-module --package narf-drivers-usb-ftdi \
  --no-default-features --features module
cargo narf ftdi-module-serial-smoke --arch=x86_64   # end-to-end proof
```

Not yet: termios changes on the module node are cached, not programmed
(baud stays 115200); multi-port FT2232H/FT4232H stay built-in; there is no
modem-status reporting through TIOCMGET for module ports.
