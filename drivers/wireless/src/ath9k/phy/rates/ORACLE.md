# Independent Linux rate and regulatory fixtures

These generators read a local Linux source tree and execute its C algorithms.
They never call a Rust rate builder or write checked-in goldens. Python 3 and a
host C compiler are required. Run from the repository root:

```sh
python3 drivers/wireless/src/ath9k/phy/rates/make_linux_oracle.py --linux /usr/src/linux --out /tmp/narf-ath9k-rate-oracle
python3 drivers/wireless/src/ath9k/phy/rates/make_regulatory_oracle.py --linux /usr/src/linux --out /tmp/narf-ath9k-regulatory-oracle
```

Omit `--out` to use an automatically removed temporary directory. `--cc` selects
the host compiler. With `--out`, generated C, executable, output and provenance
remain available for inspection. Existing Rust literals are compared as tokens,
allowing formatting/comments; an output mismatch fails without updating them.
Source or extracted-function SHA256 changes also fail against the checked-in
`*_provenance.json`. Review a changed Linux reference before updating either the
provenance or literal outputs.

`make_linux_oracle.py` extracts complete functions from `ath9k/eeprom.c`,
`eeprom_4k.c` and `eeprom.h`, including target interpolation, max-edge limiting,
4K per-rate selection and the full 4K TX-power writer. Native packed EEPROM
structs and dependent register macros are extracted from Linux headers. Comment
removal is mechanical; algorithm bodies are retained. MMIO is replaced by a
private register array. The fixed family is one-chain AR9285, legacy 20 MHz,
with per-packet TPC disabled. Only the seven rate-register writes are printed;
the complete native detector/TX-power functions still execute.

The nine `RATE_*` cases are:

| Case | MHz | Config CTL | Ceiling (half-dBm) | Antenna gain | Coverage |
| --- | --- | --- | --- | --- | --- |
| 0 | 2412 | FCC/11G | 40 | 0 | exact first pier |
| 1 | 2422 | FCC/11G | 40 | 0 | interpolated target, flagged edge |
| 2 | 2437 | FCC/11G | 40 | 0 | exact middle pier |
| 3 | 2442 | FCC/11G | 40 | 0 | interpolation after unflagged edge |
| 4 | 2462 | FCC/11G | 40 | 0 | exact final pier |
| 5 | 2467 | SD_NO_CTL/11G | 32 | 0 | upper clamp, all-group minimum |
| 6 | 2412 | FCC/11G | 0 | 0 | native inactive-probe ceiling |
| 7 | 2407 | SD_NO_CTL/11G | 40 | 0 | lower clamp, world-group handling |
| 8 | 2442 | FCC/11G | 40 | 6 | antenna-gain reduction |

CCK, OFDM and HT20 groups use different target powers. ETSI-group edges are
deliberately lower than FCC edges, making world-minimum versus specific-first
selection observable. The generated packed EEPROM image is retained beside
each register trace in `golden.rs`. Native `offsetof` output checks the byte
positions independently of Rust. A separate Rust test covers conservative
saturating antenna subtraction below gain; Linux's unsigned underflow is not
used as its expected result.

`make_regulatory_oracle.py` compiles unmodified `ath/regd.c` initialization and
lookup/sanitization helpers, actual pair/country tables, and
`ath_regd_get_band_ctl`. Every 16-bit EEPROM value is evaluated with the initial
DFS region unset. FNV-1a identity hash `ec8104beec6e96fc` and initial 2GHz/11G CTL
hash `6ddb71ef849e3ba2` both cover all 65,536 inputs, including rejection bytes;
611 values resolve successfully. This independently verifies the shared Factory
resolver, ath10k reexport and ath9k initial selector.

These are software ABI/algorithm fixtures. They do not validate RF behavior,
calibration on a physical board, PHY activation or packet operation.
