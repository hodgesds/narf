# AR9285 MAC reference fixtures

The fixed Rust vectors in `golden.rs` cover ten MAC/PCU/queue/DMA scenarios.
Native Rust tests execute the production register owner over a bounded model,
checking retained ownership, closed packet engines, register widths, access
failures and cancellation. No source is extracted or compiled for comparison.

`provenance.json` retains historical reference-source hashes. Maintain these
vectors as reviewed input/output data alongside register-contract assertions;
never derive expected traces from the implementation under test. Run the
`drivers/wireless/ath9k` kernel-test scope on both architectures. Physical radio,
interrupt and DMA qualification remain separate acceptance work.
