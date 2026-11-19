# drivers/bluetooth/btusb — USB Bluetooth HCI controllers

Driver for USB Bluetooth controllers (interface class 0xE0 / subclass 0x01 /
protocol 0x01). `btusb.rs` covers endpoint discovery, the HCI transport over
the bulk, interrupt and isochronous (SCO) endpoints, hub autosuspend and
remote wakeup, and detach; `btusb_{intel,rtl,bcm,mtk,qca}.rs` the vendor
firmware/setup sequences. The controller registers with the `narf-bluetooth`
host stack as an `HciTransport`. The USB host stack (`narf-drivers-usb`)
reaches this crate only through its `bluetooth_hooks` slots (attach-cascade
binder, wake watch), installed by `register_initcalls`.

Dual-build: the built-in build compiles the real driver; the `.ko` build
registers the Bluetooth interface match through the `narf_register_usb_driver`
KSYMTAB export and is registration-only: the USB transfer datapath exists
(`narf_usb_*`), but no HCI-transport export lets a module hand the host
stack its events and ACL data yet.

```
cargo xtask build-module --package narf-drivers-bluetooth-btusb \
  --no-default-features --features module
```

- Host stack spec: [bluetooth specification](../../../bluetooth/specification/spec.md)
- USB stack spec: [drivers/usb specification](../../usb/specification/spec.md)
