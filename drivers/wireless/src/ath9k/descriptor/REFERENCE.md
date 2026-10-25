# AR9285 descriptor reference fixtures

`golden.rs` contains fixed Rust TX descriptor and RX status vectors. Native Rust
tests exercise the production descriptor encoder/parser directly: 72 transmit
cases cover twelve legacy rates, three frame lengths and unicast/group receiver
addresses; ten RX vectors cover CRC, decryption, key-index and completion states.
DMA extent, ownership and frame-admission tests remain separate assertions.

The adjacent provenance JSON records the historical layout sources and hashes.
It is provenance for fixed data, not a build or regeneration dependency. There is
no external compiler, source extraction or generated Rust comparison harness.
Review literal values against documented descriptor fields when updating cases;
do not regenerate expected bytes by calling the implementation under test.

Run `cargo xtask test --arch=x86_64 --subsystem drivers/wireless/ath9k` (and the
same command with `--arch=aarch64`). These model checks do not establish physical
DMA behavior, firmware execution or RF acceptance.
