# Wi-Fi firmware metadata and provisioning inventory

These fixtures retain independently extracted structural metadata from 36
SHA256-pinned installed raw vendor files. They contain headers, TLV/section
geometry, API/version facts and board names. Executable instructions, board
calibration, cryptographic signatures and opaque payloads are omitted. A replay
with zero-filled gaps is a parser input, never a loadable or qualified firmware
image. Full-image authentication and hardware acceptance remain separate.

Each vendor directory contains an independent Python extractor and provenance
with complete raw-source hashes. Regeneration requires those exact originals;
the scripts do not download or silently update their pins:

```sh
python3 verification/data/wifi-firmware/intel/regen.py --check
python3 verification/data/wifi-firmware/mediatek/regen.py --check
python3 verification/data/wifi-firmware/realtek/regenerate.py --check
python3 verification/data/wifi-firmware/qualcomm/regen.py --check
python3 verification/data/wifi-firmware/broadcom/regen.py --check
```

The kernel tests decode actual captured layouts and compare independently
observed section extents, versions, API tables, firmware suits and board-name
selection. MediaTek metadata slices intentionally fail whole-image preparation.
The installed BCM43602 original has no RAM-size marker; its golden records that
absence. No installed ath11k API2 container, exact CYW43439 set or qualified
BCM43602 board NVRAM was available. Synthetic tests for unsupported/unavailable
formats remain distinct from real-source evidence. Intel cc77 and bz-b0 images
exercise parsers without enabling differently named QuZ/bz-a0 device profiles.

`profiles.json` inventories 44 currently named payload profiles across all 11
driver families. It is a provisioning catalog, not a declaration that every
listed chip has a complete station driver. In particular, Realtek preparation
profiles retain their station/TX admission gates, and ath9k uses on-device
EEPROM rather than external executable firmware. Physical Intel MAC/RF/step,
Qualcomm board-name/QMI identity and Broadcom board selection remain essential.

```sh
cargo xtask wifi-firmware --report /tmp/wifi-inventory.json
cargo xtask wifi-firmware --profile mt7920,rtl8188ee --require-assets
cargo xtask import-firmware --vendor iwlwifi --out target/wifi-firmware-intel
```

The audit reads local raw or zstd assets, follows only contained file aliases,
and reports decompressed SHA256/length and NARF registry keys. An existing
invalid candidate stops fallback. The report must be a new file outside the
source tree. `--require-assets` checks fixed required payloads only: conditional
PNVM, signed deployment policy, exact board calibration and hardware remain
manual gates. SHA256 identifies the local bytes; it is not vendor attestation.
Audit and import use the same source order: canonical raw, canonical zstd,
then flat Intel raw/zstd aliases. When creating a fresh output, duplicate source
names cannot change the selected bytes through traversal or `--skip-existing`.

The importer maps flat Intel source names into `iwlwifi/` registry keys and
preserves board NVRAM `.txt` files. It produces unsigned developer NRFW wrappers.
Production provisioning uses the existing externally signed `pack-firmware`
command and build-time trusted public keys. RTL8188EU additionally requires the
signed, measured per-factory-MAC board-power artifact; neither these fixtures
nor unsigned developer firmware can satisfy that requirement. Keep proprietary
originals and deployment calibration outside git and apply their distribution
terms when packaging them.
