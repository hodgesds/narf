# narf-drivers-usbpd — Type-C Port Controller drivers

Clean-room implementations of TCPC chips that implement
`narf_usbpd::tcpc::Tcpc`.

## References (public-only)

All driver code is derived strictly from public silicon datasheets.
No GPL or Linux kernel source consulted.

### FUSB302B (ON Semiconductor)

- **FUSB302B Programmable USB Type-C Controller w/ PD** —
  ON Semi document FUSB302B/D, Rev. 6 (Sept 2017).
  https://www.onsemi.com/download/data-sheet/pdf/fusb302b-d.pdf
  - §"Register Description" — register map (0x01..0x43).
  - §"BMC PHY" — TX/RX FIFO token encoding for SOP framing.
  - §"Functional Description" — CC sense, role programming, IRQ
    causes, hard/soft reset.
- **USB Type-C Cable and Connector Specification 2.2** (USB-IF) —
  CC pin sense thresholds (Rd/Rp termination meanings).
- **USB Power Delivery 3.1** (USB-IF) — PD frame layout the FIFO
  consumes. The protocol layer lives in `narf-usbpd`; this driver
  only handles physical-layer framing.

## Cap surface

Drivers register `Arc<dyn Tcpc>` with `narf_usbpd::tcpc` at probe
time; the TCPM polls `cc_status()` and drives `transmit/receive`.
Production-bound TCPCs hold an `Cap<I2cBus, Write>` they were
handed at probe; the test fakes route through an in-memory mock
register file.
