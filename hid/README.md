# hid — HID Protocol & Report Codec

`narf-hid` is a transport-neutral implementation of the USB-IF Human
Interface Device protocol (HID 1.11). Its job is to understand what a
HID device is saying, independent of how the bytes arrived. The crate
contains two symmetric codecs plus a set of profile decoders built on
top of them, all derived clean-room from the public HID 1.11 class
definition and the USB-IF HID Usage Tables 1.4 — no GPL Linux source
was consulted.

The first codec is the report-descriptor parser. A HID device, when
asked, returns a report descriptor: an opaque byte stream describing
the structure of every report the device can send or receive. The
parser walks HID's Main / Global / Local item state machine (the same
format whether it came from a USB `GET_DESCRIPTOR(Report)` request, an
i2c-HID device, or Bluetooth HoGP) and produces an ordered list of
fields, each carrying its bit position and size within a report along
with the static metadata — usage page, usage list, logical range —
needed to interpret runtime data. The second codec is the report
value layer: given a parsed descriptor and a wire-format report, it
extracts each field's value with correct sign-extension, and
symmetrically packs values back into an Output or Feature report for
sending to the device.

Transport is explicitly out of scope. USB control and interrupt
endpoints, i2c, Bluetooth L2CAP, and GATT all live in other crates;
they feed raw bytes into this one and read decoded values back out.

On top of the two codecs sit profile decoders that recognize the
common HID application collections and turn generic field values into
meaningful device state: keyboard (including the boot-protocol
reference descriptor used as a test fixture), a Precision Touchpad
decoder, pen/stylus digitizer, touchscreen, and HID sensor profiles.
A usage submodule provides the named page and usage-ID constants from
the Usage Tables.

The crate is `no_std` and standalone — its only build dependency is
the kernel test harness. A `kernel-test` feature flag gates in-kernel
smoke tests. The concrete hardware drivers in `drivers/input` consume
this crate to interpret the devices they bind, and the decoded output
is ultimately expressed as the event shapes defined in `input`.

- Spec: [`specification/spec.md`](./specification/spec.md)
