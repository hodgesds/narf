# Native ath10k MLME oracle

Run `python3 make_linux_oracle.py /path/to/linux` from any directory. The script
extracts full native WMI enum/packed struct declarations, legacy/TLV management
serializers, PEER_ASSOC fill/validation/generators and VDEV_UP generators from
Linux `drivers/net/wireless/ath/ath10k/wmi{,-tlv}.{c,h}`. It compiles and runs
those C functions with host allocation/debug/endian/kernel glue, then compares
all 40 complete command fixtures against `golden.rs`. No Rust encoder supplies
expected bytes. The host glue requires a little-endian host and a C compiler.

`--artifacts DIR` retains the extracted C, binary, raw output and provenance.
`--write` explicitly regenerates the selected golden file. `provenance.json`
records Linux 7.3-rc4 source hashes, generated C hash, fixture sizes and hashes.
The original source tree is an unpacked local release without a Git revision;
the four source hashes identify precisely which native code was compiled.

Fixtures cover Open/WPA2 management in MAIN, 10.1, 10.2, 10.2.4, 10.4 and TLV
(TenTwoFour shares 10.2 serializers); all six PEER_ASSOC/VDEV_UP profiles;
full twelve-rate sets and single 1/6 Mbps rate sets (11B/11G and TLV padding).
Raw air requests are fixed protocol inputs; shared JoinPlan produces them in
the composed runtime test before native CE/HTC/WMI submission. They do not
establish firmware acceptance, RF calibration or physical interoperability.
