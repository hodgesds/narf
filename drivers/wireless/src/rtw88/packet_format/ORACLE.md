# RTL8822CE packet formats

Run `python3 make_linux_oracle.py --check` to compile the original local Linux
PCI transmit and receive functions against an inert bus. `--linux` selects an
explicit rtw88 source directory; no network access or source mutation occurs.
Without `--check`, the script regenerates `golden.rs` and `provenance.json`.

The source functions produce 96 complete PCI TXD/TXBD cases, 48 RX metadata
cases and 512 CCX report-macro results. Wire types, bitfields, queue selection,
descriptor clearing and both PCI DMA segments come from the original C.
`provenance.json` records complete source and extracted-function SHA256 hashes.
The 40-byte source TX struct occupies the first 40 bytes of this chip's actual
48-byte packet descriptor; the final eight bytes remain zero. PCI does not
call the USB/SDIO host checksum callback.

The Rust raw profile additionally rejects hardware plaintext, CRC/ICV errors,
nonlegacy rates/bandwidths and incomplete extents. C2H has its own bounded
envelope and never loses four bytes as though it carried a Wi-Fi FCS.
CCX acknowledgement and PCI TXBD consumption are separate receipts.

The packet core uses one outstanding contiguous payload, the original retained
MGMT/BE rings and tagged RX ring. Kernel models check both completion orders,
report/index wrap, consumed bad CRC versus genuine RX idle, current policy and
authority loss, terminal ownership and bytes reread from actual DMA. A real
object-table revocation test precedes native CPU/config/MMIO/allocation access.
These are software checks; RF, firmware and physical DMA acceptance are separate.
