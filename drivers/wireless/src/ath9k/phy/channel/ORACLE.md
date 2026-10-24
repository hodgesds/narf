# AR9285 channel oracle

`make_linux_oracle.py` extracts the complete original Linux override, channel
mode, chain-mask, RF-mode, synth, delta-slope and both spur-mask functions.
The native C wrapper supplies an AR9285 single-chain 2GHz/full-rate/20MHz
hardware identity and records every register write. It does not call Rust.
Packed EEPROM types, field offsets and register masks come from Linux headers.
The source and extracted-function hashes are in `linux_oracle_provenance.json`.

The 48 cases combine channels 1, 6 and 13; signed spur offsets -10, -9, -3,
0, 3, 9, 10 and 100 MHz; and zero/nonzero inherited registers. They preserve
Linux's strict spur edges, signed division, and its irregular/repeated Viterbi
mask indices. `golden.rs` contains ordered-write counts and FNV-1a hashes over
each `(register,value)` pair in little-endian u32 form. These are trace
comparisons, with no performance claim or assertion of RF calibration.

To reproduce without modifying checked-in expectations:

```sh
python3 drivers/wireless/src/ath9k/phy/channel/make_linux_oracle.py --out /tmp/ath9k-channel-oracle
```

The private production path currently uses only the inactive 2412MHz reference
after full INI preparation. This is neither a fast channel-switch API nor
transmit authorization. Calibration, authenticated live power/channel policy
and retained packet/IRQ owners must precede radio operation.
