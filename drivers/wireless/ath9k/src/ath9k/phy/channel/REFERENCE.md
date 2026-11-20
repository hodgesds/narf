# AR9285 channel reference fixtures

Fixed Rust vectors cover 48 inactive channel-programming cases: channels 1/6/13,
eight signed spur offsets including both boundaries, and zero/nonzero inherited
register state. Native Rust tests exercise production programming, exact legacy
Viterbi packing, invalid-channel refusal, lost access and retained ownership.

Historical source/function hashes remain in the adjacent provenance JSON. The
Python/C extraction and comparison pipeline has been retired; ordinary tests and
builds use Rust only. Review expected values against hardware-field documentation
when updating them, independently of the implementation under test. Execute the
`drivers/wireless/ath9k` scope on both architectures. These fixtures do not prove
fast retuning, physical channel calibration or radio interoperability.
