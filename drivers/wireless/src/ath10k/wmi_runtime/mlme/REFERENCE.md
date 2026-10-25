# ath10k management reference fixtures

Checked-in Rust vectors describe the supported WMI dialects' management command
IDs, packed layouts and event fields. Native Rust tests exercise the production
CE/HTC/WMI management path, peer/channel/address binding, bounded command waits,
actual terminal receipts and cancellation ownership. They consume fixed vectors;
no original source or external compiler is used as an executable oracle.

Historical source hashes remain in provenance metadata. Maintain expected bytes
by reviewing the documented firmware wire contract, not by running the encoder
under test to obtain its own expectations. Run the `drivers/wireless/ath10k`
QEMU scope on both architectures. These checks do not establish firmware or
physical air-interface conformance.
