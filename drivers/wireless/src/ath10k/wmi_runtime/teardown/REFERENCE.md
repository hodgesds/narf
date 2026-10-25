# ath10k terminal teardown reference fixtures

Fixed Rust fixtures retain VDEV_DOWN, PEER_DELETE and VDEV_STOP commands plus
STOPPED/peer-delete event layouts for MAIN, 10.1, 10.2/10.2.4, 10.4 and TLV.
Native Rust regressions send commands through the production CE/HTC/WMI owner
and receive HTT UNMAP plus correlated events through destination CEs. They check
stale/foreign events, deadlines, cancellation and continued DMA ownership.

Provenance JSON preserves historical source hashes. There is no source extraction,
C compilation or Python comparison workflow. Review changes to literal wire data
against the documented firmware ABI independently of the encoder under test.
Run the `drivers/wireless/ath10k` scope on both architectures. Successful peer/vdev
retirement does not prove whole-device reset, permit rejoin or qualify RF behavior.
