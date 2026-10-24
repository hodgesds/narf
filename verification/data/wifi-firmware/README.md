# Wi-Fi firmware metadata and provisioning inventory

These fixtures retain independently extracted structural metadata from 36
SHA256-pinned installed raw vendor files. They contain headers, TLV/section
geometry, API/version facts and board names. Executable instructions, board
calibration, cryptographic signatures and opaque payloads are omitted. A replay
with zero-filled gaps is a parser input, never a loadable or qualified firmware
image. Full-image authentication and hardware acceptance remain separate.

**Checkout state (issue #739):** the intel and mediatek `*.metadata.bin`
extracts are committed. The qualcomm and broadcom extracts are **not** in
git: the root `*.bin` gitignore rule silently excluded them when the tables
landed (intel/mediatek carry a nested `!*.metadata.bin` negation; qualcomm
and broadcom now carry one too, so regenerated extracts are committable).
Until they are regenerated from the pinned originals and committed, a clean
checkout has no qualcomm/broadcom extracts: `narf-drivers-wireless` builds
regardless — its `build.rs` detects the absence and the affected golden
replay tests report `Skip` — and the build prints a warning naming the
regen command below.

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
command and build-time trusted public keys. RTL8188EU, RTL8188EE and RTL8822CE
additionally require signed, measured per-factory-MAC board-power artifacts;
neither these fixtures nor unsigned developer firmware can satisfy that
requirement. EE uses `rtlwifi/rtl8188ee-cal-v1-<12 lowercase MAC hex digits>.bin`;
8822CE uses `rtw88/rtw8822ce-cal-v2-<12 lowercase MAC hex digits>.bin`. Its v2
qualification binds both calibration emission and the complete reachable
autonomous response-rate envelope; a fixed1Mbps host data rate does not narrow
hardware ACK/CTS power. The older v1 artifact cannot grant this station profile.
The family specifications describe the exact factory, firmware and profile binding.

RTL8852B's initial2T2R profile requires both the current basic
`rtw89/rtw8852b-cal-v1-<12 lowercase MAC hex digits>.bin` and full
`rtw89/rtw8852b-radio-v2-<12 lowercase MAC hex digits>.bin`. Full N52B v2 binds
actual firmware PHY capability, the complete channel/calibration/operating and
power recipes, measured calibration/ordinary/autonomous-response maxima, and
signed maximum antenna gain. Its old basic artifact cannot grant ordinary RF.
The worker prints the exact requested filename and actual board digest when
staging is incomplete. These are provisioning facts; the measurement/signing
authority must supply the real peaks. Static source WW power tables supply no
country authority or measured dBm conversion.

Generic RTL8852B attachment requires a real advertised and completed PCIe FLR.
For a platform that instead proves an actual function/slot power reset and
posted-traffic drainage, the unsafe `rtw89::pci::attach_cold` entry must be
called before generic binding. A board flag, a claimed cold boot and BME-off
do not supply that temporal proof. Published DMA remains retained on terminal
failure; the first fixed1Mbps profile is bounded to512 packets per queue and
does not implement automatic reset/rejoin.

BCM43602 and CYW43439 require an explicit board selection before firmware
upload. The signed `brcm/wifi-board-selection-v1.bin` manifest binds the actual
PCI or SDIO host/card identity, chip revisions and exact canonical asset keys,
lengths and SHA256 digests. NVRAM and CLM must be signed even in an unsigned
developer build. Executable-image development policy remains separate. Encode
verified deployment records with
`drivers/wireless/src/brcmfmac/provision/make_manifest.py`, then use the existing
`pack-firmware` workflow to sign the manifest and selected board assets. The
generator takes explicit host, board and file facts; it does not discover
wiring, select a board by filename or create measured calibration. A trusted
platform must still supply CYW power, clock and reset wiring.

Registry staging may happen after device detection. Intel, BCM43602 and CYW
retain parked startup owners; RTL8188EE exposes a bounded `pci::provision`
continuation for its existing detected owner. RTL8822CE's `rtw88::pci::provision`
continues that same owner at completed firmware/MAC/PHY/calibration boundaries;
MT76's `mt7921::firmware_transport::provision_boot_radio` resumes its parked
binding after firmware preflight was missing or invalid. Intel Sc selects only
the actual CSR MAC/RF/step's firmware ladder, even if other Sc images are present.
Missing assets before the first hardware attempt remain retryable. A consumed
or failed native attempt cannot be replaced by reopening an asset name or
reconstructing an owner. MT76 keeps its started future across caller cancellation;
other drivers retain their documented one-shot cancellation behavior.
Keep proprietary
originals and deployment calibration outside git and apply their distribution
terms when packaging them.
