# RTW89 fixed reference data

The native driver, register/recipe tables and kernel tests are Rust. The stored
`golden.rs` arrays and digests are frozen regression inputs from the Linux source
snapshots cited below. Tests compare Rust results with those checked-in values;
they do not compile Linux or prove continuing equivalence with a current Linux
checkout. No Python, C compiler, temporary `rustc` comparison harness or
source-to-Rust generator is part of this family’s build or validation workflow.

The former extraction/compiler scripts have been removed. Source SHA256 comments
remain attached to captured fixtures, register constants and recipes. They record
provenance, not a regeneration dependency. Fixture changes require source/hardware
contract review and an explanation of the changed expected behavior; deriving new
expected values from the implementation under test would defeat the regression.
The retained `firmware_fixture_sha256.json` is vendor-image metadata.

Except for the PCI FLR reference, source paths are relative to
`drivers/net/wireless/realtek/rtw89/`. The native modules also cite the individual
source helper names used by their hardware contracts.

| Stored reference area | Linux source contract | Native Rust coverage retained |
|---|---|---|
| `pci_reset` | `drivers/pci/pci.c` pending/FLR timing and reset protocol | Actual config-state ordering, minimum silence, capability epochs, identity/BAR readbacks, cancellation and retained ownership |
| `power`, `firmware_boot`, `fifo` | `mac.c`, `mac.h`, `reg.h`, per-chip power/FIFO definitions | Power/WCPU/DLE/HFC register traces, bounded waits, inherited fields, faults and cancellation |
| `pci_basic`, `pcie`, `bdram`, `phy_access` | `pci.c`, `pci.h`, `reg.h` | AX profile geometry, MDIO/DBI, clock/link modes, BDRAM/indices and complete failure/retention boundaries |
| `factory`, `secure`, `download_dma` | `efuse.c`, chip EFUSE headers, `fw.c`, `fw.h`, `pci.h` | Packed factory layout, physical secure selections, section/download geometry and malformed/absent input rejection |
| `command`, `firmware_phycap`, `scheduler_mailbox` | `fw.c`, `fw.h`, `mac.c` firmware request/response contracts | Exact serialized identities, automatic ACKs, topology decoding, current authority and consumed/executed receipt separation |
| `rf_access`, `radio_table`, `radio_assets` | `phy.c`, `phy.h`, `fw.c`, `fw.h`, `rtw8852b_table.c` | RF transactions, 160 headline/condition cases, full selected-table digests and bounded firmware override parsing |
| `radio_init`, `radio_gain`, `radio_trim`, `radio_power`, `phy_operating` | `rtw8852b.c`, `rtw8852b_table.c`, `phy.c` | BB/gain/reset/power tables, signed factory arithmetic, RF uploads and guarded measured radio prerequisites |
| `rfk`, `iqk`, `tssi`, `dpk` | `rtw8852b_rfk.c`, `rtw8852b_rfk_table.c`, `phy.c` | Calibration sequencing/measurements, signed mapping domains, current qualification, bounded NCTL/PMAC waits, restore/fault/cancel behavior |
| `channel_bb`, `channel_rf`, `channel_transition`, `coex_native` | `rtw8852b.c`, `rtw8852b_rfk.c`, `phy.c`, `coex.c` | Channel/gain/coexistence fields, exact state transitions and retained current-policy ownership |
| `radio_stop`, `radio_shutdown`, `radio_full` | `rtw8852b.c`, `rtw8852b_rfk.c`, `mac.c` and the composed source recipes | Independent emission-engine closure, clock shutdown, recipe binding and uncertain-DMA retention |
| `station_control`, `packet_format`, `rx_packet`, `rx_dma` | `cam.c`, `mac.c`, `fw.c`, `txrx.h`, `pci.c`, `pci.h` | Literal command/descriptor/reference traces, native ring/DMA receipts, peer/key admission, wrap/exhaustion and actual-capability revocation |

Production tables and recipe digests remain part of the hardware programming and
signed qualification contracts. They are not measured board data. The existing
Rust models retain native DMA/command ownership, Open/WPA2 and kernel DHCP/IP
composition coverage. They establish software regressions within the documented
profile; physical calibration, firmware and radio acceptance remain separate.
