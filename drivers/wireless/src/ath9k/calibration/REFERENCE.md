# AR9285 calibration reference fixtures

The retained Rust data contains 32 traces covering XE2 identity, board gain,
carrier-leakage retry and inherited register state, plus 35 IQ arithmetic vectors
covering signed division, clipping and wrapping intermediate values. Native Rust
tests run the real calibration owner and inspect its register/delay model, access
failures, missing completion, dropped waits and retained closed packet gates.

Source/function hashes remain in the adjacent provenance JSON as historical
reference metadata. They require no source checkout, C compiler, Python helper
or generated Rust harness. Fixture changes require review against the documented
arithmetic and hardware fields; do not obtain expected results from the tested
implementation. The `drivers/wireless/ath9k` scope runs these tests on both arches.
Software fixtures cannot supply physical calibration measurements or RF evidence.
