# RTW88 fixed reference data

The driver, hardware tables and kernel tests are Rust. The checked-in reference
arrays and digests are frozen regression inputs from the Linux source snapshots
listed below. Tests compare native Rust behavior with those stored inputs; they
do not compile Linux, run a second implementation or establish continuing
equivalence with a current Linux checkout. No Python, C compiler, temporary
`rustc` harness or source-to-Rust generator is required to build or test RTW88.

The former extraction/comparison scripts have been removed. Changing a fixture
requires review of the cited hardware/source contract and an explanation of the
changed expected behavior. Expected values must not be regenerated from the
implementation being tested. Existing source fingerprints and firmware metadata
remain provenance for the captured data, not a regeneration recipe.

All Linux paths below are relative to
`drivers/net/wireless/realtek/rtw88/`, except the mac80211 reference.

| Stored data | Source contract | Native Rust coverage retained |
|---|---|---|
| `factory/*golden.rs`, `factory/power_values.rs` | `rtw8821c.h`, `rtw8822c.h`, `main.h`, `efuse.h`; power groups and regulatory-limit records in `phy.c`/`rtw8822c_table.c` | Sparse EFUSE decoding, exact packed offsets, raw factory bytes, gain/power bounds and erased-data rejection |
| `firmware/golden.rs`, `firmware/rtl8821c_metadata.rs` | `mac.c` firmware callbacks; the named installed NIC firmware header and its recorded digest | Header/section bounds, same-owner page/IDDMA flow, checksum/ready receipts, faults and cancellation |
| `mac/*golden.rs`, `mac/*values.rs` | `mac.c`, `rtw8821c.c`, `rtw8822c.c`, `reg.h` | Chip-specific FIFO/LLT/H2C setup, inactive register traces, access failures, stale receipts and replay refusal |
| `phy/*golden.rs`, `phy/*tables.rs` | `phy.c`, `rtw8821c_table.c`, `rtw8822c_table.c`, chip PHY callbacks | 56 C21 cut/package/RFE and 49 C22 cut/RFE profiles, table/callback digests, retained MAC/PHY ownership and closed gates |
| `radio/golden.rs` | `rtw8822c.c` fresh DACK, channel/trim and IQK command paths | Bounded measurements, distinct-path restoration, signed/current power admission, native transport faults and cancellation |
| `station_control/*golden.rs` | `fw.c`, `mac80211.c`; Linux `net/mac80211/wme.c` non-QoS defaults | Mailbox fields/receipts, source DCF defaults, peer/teardown/cancellation ownership |
| `packet_format/golden.rs`, `packet_format/provenance.json` | `pci.c`, `pci.h`, `tx.c`, `tx.h`, `rx.c`, `rx.h`, `fw.h`, `main.h`, `mac.h` | Literal TXD/TXBD, RX and CCX vectors, malformed descriptors, separate DMA/security completion and current-capability publication |

The packet references have additional captured source/function SHA256 records
in `packet_format/provenance.json`. Production tables are hardware programming
data, not test results or measured board calibration. They cannot authorize RF
emission or substitute for signed deployment qualification.

The existing kernel models also cover real capability epochs, retained DMA,
Open/WPA2 station ownership and kernel DHCP/IP composition. Removing external
compiler pipelines does not remove those tests. These checks remain software
regressions; firmware acceptance, measured RF behavior and physical DMA safety
still require hardware testing.
