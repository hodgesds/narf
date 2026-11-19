# RTL8822CE packet reference vectors

`golden.rs` contains fixed reference inputs for 96 complete PCI TXD/TXBD cases,
48 RX metadata cases and 512 CCX results. Their captured source provenance is
Linux `drivers/net/wireless/realtek/rtw88/{pci,tx,rx}.{c,h}`, `fw.h`, `main.h`
and `mac.h`; `provenance.json` preserves source and extracted-function SHA256
records. The compiler/extraction pipeline has been removed. These are stored
regression data, not an ongoing C-equivalence check or a regeneration target.

Native Rust kernel tests compare the driver with those literal vectors. They
require no Python, C compiler or external Linux source checkout. Fixture changes
need source-contract review and must not derive expected values from the code
being tested. The 40-byte source TX layout occupies the first 40 bytes of this
chip's 48-byte descriptor; its final eight bytes remain zero. PCI does not use
the USB/SDIO host checksum callback.

The Rust raw profile additionally rejects hardware plaintext, CRC/ICV errors,
nonlegacy rates/bandwidths and incomplete extents. C2H retains its bounded
envelope without incorrectly stripping a Wi-Fi FCS. CCX acknowledgement and
PCI TXBD consumption remain separate receipts.

The packet core uses one outstanding contiguous payload, retained MGMT/BE rings
and a tagged RX ring. Rust models check both completion orders, report/index
wrap, consumed bad CRC versus genuine RX idle, current policy/authority loss,
terminal ownership and bytes reread from actual DMA. Actual capability
revocation is checked before CPU/config/MMIO/allocation access. These are
software checks; RF, firmware and physical DMA acceptance remain separate.

See `../REFERENCE_FIXTURES.md` for the family's source and coverage inventory.
