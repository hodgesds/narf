# Native ath10k terminal teardown oracle

Run `python3 make_linux_oracle.py /usr/src/linux` from any directory. It compiles
the complete unmodified Linux legacy/TLV VDEV_DOWN, PEER_DELETE and VDEV_STOP
generators, command/event enums and packed event structures. Host allocation,
debug and endian glue supply the only replacements. None of the expected bytes
come from Rust encoders. MAIN, 10.1, 10.2/10.2.4, 10.4 and TLV have exact command
fixtures; STOPPED and TLV peer-delete replies preserve their actual event IDs
and layouts. The TLV synchronous-delete service number is also independently
obtained from Linux's native enum.

`--write` explicitly regenerates `golden.rs` and `provenance.json`.
`--artifacts DIR` retains extracted C, the host executable, raw output and
provenance. The source hashes identify the unpacked Linux reference tree.
Ordinary runs compare both output bytes and source provenance.

The composed kernel tests send these commands over production CE/HTC/WMI and
receive HTT UNMAP plus correlated firmware events through native destination
CEs. They keep all DMA retained. Successful peer/vdev retirement does not prove
whole-device reset, allow rejoin, qualify board calibration or establish RF
interoperability.
