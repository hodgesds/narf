# ixgbe — Specification

> Status: **v0.1** (Stages 1-6 — PCI match, MAC reset / EEPROM, TX
> ring, RX ring, MSI-X, `HwNic` impl).
>
> Clean-room driver for the Intel 82599 / X540 / X550 10 GbE
> controller family. Reference material: the public
> *Intel 82599 10 GbE Controller Datasheet* (rev. 3.3) plus the
> matching X540 / X550 datasheets. No GPL Linux `ixgbe` source
> consulted.

## 1. Scope

Owns the full bring-up of an 82599-class NIC: PCIe BAR0 mapping,
documented `CTRL.RST` reset, EEPROM-backed MAC read, TX descriptor
ring (advanced layout), RX descriptor ring (legacy layout for
simplicity), one MSI-X vector for link / RX completion, and a
`HwNic` adapter exposing the same surface the e1000/mlx5 drivers
do.

Does NOT own: DCB, FCoE, SR-IOV, RSS, FlowDirector, EEE, VMDq.

## 2. PCI match

| device     | vid    | did    |
|------------|--------|--------|
| 82599EB    | 0x8086 | 0x10FB |
| X540-AT2   | 0x8086 | 0x1528 |
| X550       | 0x8086 | 0x1563 |
| X550EM_x   | 0x8086 | 0x15AB |

## 3. Register surface (BAR0)

All registers are 4-byte little-endian (host order). Offsets per
82599 §8.2.

| offset    | name      | notes                                |
|-----------|-----------|--------------------------------------|
| 0x00000   | CTRL      | Device Control (RST = bit 26)        |
| 0x00008   | STATUS    | LAN_ID + LINK_UP                     |
| 0x00018   | CTRL_EXT  | Extended Control (DRV_LOAD = bit 28) |
| 0x00800   | EICR      | Extended Interrupt Cause             |
| 0x00808   | EICS      | Extended Interrupt Cause Set         |
| 0x00880   | EIMS      | Extended Interrupt Mask Set/Read     |
| 0x00888   | EIMC      | Extended Interrupt Mask Clear        |
| 0x00900   | EIAC      | Extended Interrupt Auto-Clear        |
| 0x00A50   | GPIE      | General-Purpose Interrupt Enable     |
| 0x00A90   | EIAM      | Extended Interrupt Auto-Mask         |
| 0x01000+  | IVAR      | Interrupt-vector allocation          |
| 0x01014   | EIMC_EX0  | extra IMC bits                       |
| 0x01400   | EIMS_EX0  | extra IMS bits                       |
| 0x01580   | EIAC_EX0  | extra EIAC bits                      |
| 0x02100+  | RDBAL[n]  | RX desc base low (per-queue)         |
| 0x02104+  | RDBAH[n]  | RX desc base high                    |
| 0x02108+  | RDLEN[n]  | RX desc length                       |
| 0x02110+  | RDH[n]    | RX desc head                         |
| 0x02118+  | RDT[n]    | RX desc tail                         |
| 0x0282C+  | RXDCTL[n] | RX queue Enable + thresholds         |
| 0x03000   | RXCTRL    | RX master enable (bit 0 = RXEN)      |
| 0x05080   | FCTRL     | Filter Control (BAM/MPE/UPE)         |
| 0x05400   | RAL[0]    | Receive Address Low                  |
| 0x05404   | RAH[0]    | Receive Address High (AV = bit 31)   |
| 0x06000+  | TDBAL[n]  | TX desc base low                     |
| 0x06004+  | TDBAH[n]  | TX desc base high                    |
| 0x06008+  | TDLEN[n]  | TX desc length                       |
| 0x06010+  | TDH[n]    | TX desc head                         |
| 0x06018+  | TDT[n]    | TX desc tail                         |
| 0x06028+  | TXDCTL[n] | TX queue enable + thresholds         |
| 0x04200   | LINKS     | LINK_UP = bit 30                     |
| 0x10010   | EERD      | EEPROM Read (legacy 82599 path)      |

Per-queue stride is 0x40 bytes for queues 0..63.

## 4. EEPROM read (82599 §10.2.4.2)

```
EERD = (addr << 2) | START(1<<0)
poll EERD.DONE (bit 1) up to ~10 ms
data = EERD >> 16
```

MAC bytes 0..2 live at EEPROM word 0; bytes 2..4 at word 1; bytes
4..6 at word 2 (byte-swapped per word — low byte = even index).

## 5. TX descriptor format (advanced TX, §7.2.3.2.4)

```
struct AdvTxDesc {
    addr:        u64,    // buffer phys
    cmd_type_len:u32,    // [29:24]=DTYP, [27]=DEXT, [25]=RS, [24]=EOP, [23:0]=DTALEN
    olinfo:      u32,    // [13:0]=PAYLEN, [3:0]=CC, [16]=IXSM, [13:0]
}
```

Stage 3 cut: legacy descriptor isn't supported on 82599 — we use
the advanced (DEXT=1) layout with `DTYP = 0x3` (Advanced Data
Descriptor).

## 6. RX descriptor format (legacy, §7.1.5)

Same 16-byte legacy layout as e1000:

```
struct RxDesc {
    addr:    u64,
    length:  u16,
    csum:    u16,
    status:  u8,
    errors:  u8,
    special: u16,
}
```

## 7. MSI-X (Stage 5)

82599 supports up to 64 MSI-X vectors. We allocate one shared
"misc" vector (link/RX/TX collapsed) for Stage 5. IVAR[0] maps
queue 0's RX/TX onto that vector; OTHER_CAUSES_IVAR routes
link-state changes to it as well. The bus-side `enable_msix`
helper does the table programming.

## 8. Smokes

Per project rule, smokes live in `drivers/net/src/ixgbe/tests.rs`
and register via `kernel_test_in!("drivers/net/ixgbe", …)`.
Coverage:

- PCI match table includes all four documented IDs.
- `eeprom_decode` round-trips a synthetic EEPROM word.
- `AdvTxDesc::ctrl_word` packs `EOP|RS|DEXT|DTYP=3|len`.
- `RxDesc` size + alignment.
- (live) `bring_up` against an attached 82599 — `Skip` if absent.
