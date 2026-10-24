# AR9285 MAC prerequisites

`python3 make_linux_oracle.py --linux /usr/src/linux --out /tmp/ar9285-mac`
compiles complete original Linux queue reset and its interrupt helpers,
DMA/FIFO setup, QoS defaults, station operating mode and MFP setup. All native
register definitions are extracted from the original headers. Ten cases
compare complete ordered write hashes for zero and inherited nonzero seeds.
`provenance.json` pins the source and extracted function hashes.

Separate retained-CPU models exercise full factory-bound preparation,
key-cache clearing, RF-silent input selection, peer/AID/timing writes and each
access failure. MAC preparation keeps packet DMA and IRQs off. These checks
grant no RF acceptance, physical key authority or station admission.
