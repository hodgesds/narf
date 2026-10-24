# AR9285 calibration oracle

The generator extracts the complete original Linux SerDes/PCIe initialization,
PHY settling, AGC/carrier leakage retry, PA calibration, noise-floor load/start,
and IQ setup/collection/correction functions. Header constants and the actual
selected SerDes array come from the local Linux tree. Generated C and source/
function SHA256 provenance are saved in a temporary or selected output folder;
checked-in expectations are never rewritten automatically.

```sh
python3 drivers/wireless/src/ath9k/calibration/make_linux_oracle.py --out /tmp/ath9k-calibration-oracle
```

The 32 traces vary XE2 identity, normal/high-power board gain, carrier-leakage
retry, inherited register values and correlation sign. The model represents
the read-only silicon bits and fast self-clearing completion semantics. Every
native register write and requested microsecond delay contributes a tagged
little-endian `(kind,address,value)` FNV-1a record; delays use `(1,us,0)`.
The existing independent rate-power fixtures cover the preceding factory/CTL
power writes. A separate set of original C IQ vectors covers signed correlation,
clipping, unsigned intermediate wrap and the legal full-width `-1` sample.

Native tests also cover access loss, withheld AGC/NF/IQ completion, dropped
waits, actual capability revocation and overlapping regulatory limits. An
invalid zero-denominator sample is refused rather than qualifying an old
factory coefficient. Cancellation records failure without MMIO cleanup or a
new attempt. Successful calibration keeps MAC RX, TX queues, IRQ and BME
closed; PHY activation alone is not packet or RF acceptance. The measured
noise floor and Linux-sanitized diagnostic value are reported separately.
