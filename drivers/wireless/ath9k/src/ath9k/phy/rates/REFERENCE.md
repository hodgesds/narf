# AR9285 rate and regulatory reference fixtures

The fixed Rust data in `golden.rs` covers exact, interpolated and clamped target
power; specific/world CTL groups; antenna-gain subtraction; and zero ceilings.
Nine rate cases preserve their packed EEPROM inputs and seven register writes.
Native Rust tests also exercise saturating subtraction and all 65,536 EEPROM
identities through the shared factory/regulatory resolver, including rejection.

The provenance JSON retains historical source hashes, not executable generators.
No Python, C compiler, source checkout or extracted-code harness is needed to
build or run these tests. Expected values must be reviewed against the numeric
and hardware contracts; do not regenerate them from the production rate builder.
Run the `drivers/wireless/ath9k` kernel-test scope on both architectures. Neither
these data nor a structurally valid EEPROM establishes measured board power or
physical RF readiness.
