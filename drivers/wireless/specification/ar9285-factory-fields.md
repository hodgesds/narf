# AR9285 factory map and field byte order

The admitted AR9285 revision2 factory lane is source-complete, including
little-endian fields, big-endian fields, and magic-driven word-swapped storage.
Five new native cases are written; release compilation and native execution
are pending. No new physical measurements or signed board assets are supplied.
The gain, calibration, policy and exact source qualification limits remain.

Linux7.2 `eeprom.c::ath9k_hw_eeprom_init` selects `eep_4k_ops` for AR9285;
the AR9287, AR9300 and default maps belong to separately tracked chip rows.
The map is the existing376-byte packed `ar5416_eeprom_4k` at EEPROM word64,
major14/minor>=1. There is no additional unspecified AR9285 map to invent.
All four `ar9002_hw.c::ar9002_hw_init_mode_gain_regs` AR9285 branches already
exist: original/high power and XE2 original/high power. The selection uses
actual `SYNTH9 & 7 == 1` and factory `txGainType == 1`; a silicon revision
nibble does not stand in for the XE2 RF identity. Existing source-native tests
independently hash every655 INI writes for all four selections.

The remaining concrete same-map input gap was that identity decoded big-endian
base scalars, while several later consumers read the raw bytes as little
endian. Linux distinguishes two transformations: `ath9k_hw_nvram_swap_data`
normalizes EEPROM words according to magic, then checks `EEPMISC_BIG_ENDIAN`;
`eeprom_4k.c::ath9k_hw_4k_check_eeprom` validates the raw checksum and converts
specific multibyte fields. Its `EEPROM_FIELD_SWAB16/32` macros explicitly
leave MAC/U8 calibration, target and CTL tables as byte arrays.

NARF retains the complete raw factory image after magic-driven word
normalization, including its original EEPMISC flag and checksum. Private
`identity::eeprom_word/eeprom_dword` readers interpret an actual EEPROM
multibyte field according to that flag. They do not mutate the image, its
checksum, Identity provenance or the bytes hashed by signed qualification.
Live consumers now consistently use them for:

- Modal version, antenna-chain/common switch controls and minor-version gates.
- Detector overlap selection (minor1 uses native INI overlap; minor>=2 uses
  the EEPROM overlap).
- Narrow/wide factory regulatory domain resolution and current CTL/rate plan.
- HT40 PDADC compensation (minor1 uses source2; minor>=2 uses the actual
  modal increment).
- Five16-bit EEPROM spur-channel entries, including the0x8000 sentinel.

The existing MAC and native RF-silent paths already honor field byte order.
Derived PDADC byte packing, native MAC address bytes, air headers and all
signed N85H/B/T/Q bodies remain in their own required byte order. They are not
EEPROM fields and are not globally swapped. Old little-endian images retain
the same source selection and hardware writes. Every accepted qualification
format/request recipe remains unchanged. A big-field image has distinct raw
bytes and therefore requires the exact corresponding H1/2/3 body; an LE body
cannot authorize it even when the actual semantic hardware/report is equal.
Magic-word-swapped storage that decodes to the same raw field image retains
that same factual identity.

The full program still validates magic, bounded even length, raw checksum,
major/minor, MAC, chain masks, detector/target/CTL/rate facts and factory domain
before packet publication. A falsely changed endian flag, corrupted checksum,
foreign version or unknown domain fails before the native owner exists. The
current host occupied-span rule and external signed measured program remain
mandatory. Full40 additionally needs actual fresh40 NF/ADC/IQ and the exact
signer-supplied expected receipt, with real20 fallback and terminal generation,
key/BA/capture/DMA ownership unchanged. Revocation at an actual copied-packet
boundary still closes delivery and the host link.

Five new cases in `calibration/factory_tests.rs` and
`interface_factory_tests.rs` cover actual reset/EEPROM reads, all four gains,
minor1/2/3, asymmetric modal/spur values, paired LE/BE and word-swapped BE
hardware/register/report equivalence, narrow1/6/13 and both40 extensions,
Open/WPA2 Device/kernel DHCP/IP, full40 signed child composition, foreign LE
body rejection, checksum/endian/version/domain negatives and current source
revocation after actual DMA copy. The tests use synthetic model-only images
and signatures; production data is external. No native pass or physical RF,
interoperability or performance result is claimed.
