# AR9285 legacy descriptors

`python3 make_linux_oracle.py --linux /usr/src/linux --out /tmp/ar9285-desc`
compiles complete original Linux `ar9002_set_txdesc`, RX descriptor setup and
`ath9k_hw_computetxtime` and `ath9k_hw_rxprocdesc`, using the original native descriptor structs, macros
and legacy rate table. It writes only to the selected output directory.

The 72 cases cover twelve legacy rates, three MPDU lengths and acknowledged
or group receiver addresses. All 24 words and native status offsets are
compared in kernel smokes. The source/function SHA256 hashes are recorded in
`provenance.json`. These codec checks establish neither DMA ownership nor an
operational station; those require the retained packet/MAC owner.

Ten native RX status vectors independently classify CRC, decrypt, key-index,
key-miss and busy results. Protected software-CCMP key misses may clear the
hardware FrameOK bit; the invalid key-cache index and original ciphertext are
retained for software authentication. This exception grants no plaintext or
unprotected-management admission without FrameOK.
