# drivers/nfc — NFC Controller Interface Scaffold

`narf-drivers-nfc` is NARF's Near Field Communication subsystem in an
early, scaffold state. It provides the core types of the NFC Forum's
NFC Controller Interface (NCI) 1.0 protocol — the standard host-to-
controller command/response/notification framing used to drive an NFC
controller (NFCC) — together with a transport abstraction and one
concrete vendor driver.

The crate models the NCI 1.0 packet layer: the message-type, group-ID,
opcode, and connection-ID fields that make up the NCI packet header, the
CORE and RF-management command groups, and the status codes a controller
reports back. On top of this sits a transport trait that abstracts the
physical link to the controller (byte framing plus an interrupt/data-
ready signal), and the `nxp_pn553` module, an NXP PN553 I2C vendor
driver that implements that transport — including the active-high IRQ
GPIO convention the part uses.

Scope is deliberately narrow (Stage 0). Higher NFC layers are
explicitly deferred: the HCI/PN544 gate model, NDEF record handling,
peer-to-peer modes, and secure-element access are all out of scope for
now. The crate depends only on `narf-lib`, the console, and init
registration, reflecting that it is currently protocol types plus a
single I2C driver rather than a wired-up end-to-end stack. The design
is `no_std`, and types such as the NCI message kinds are kept exhaustive
so future additions force the handling code to be updated.
