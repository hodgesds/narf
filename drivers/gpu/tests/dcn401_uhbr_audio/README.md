# UHBR LPCM reference checks

`python3 check.py [linux-tree]` compiles the actual static bandwidth routines
extracted from Linux `dc/dce/dce_audio.c` with Linux's `fixpt31_32.c`, using the
existing DSC host header shims. It checks 1701 vectors. `--generate` prints a
replacement vector file; kernel tests consume the checked-in file. Inputs are
pixel clock in kHz, horizontal active/total, bpc, UHBR rate (10-Mbps units),
lane count and channel count; output is the supported LPCM sample-rate mask.

The harness supplies NARF's programmed `HBLANK_MIN_SYMBOL_WIDTH`, including
pixel padding. It deliberately does not use the differently scaled field in
Linux `populate_audio_dp_link_info`. This verifies `check_audio_bandwidth_dp`
for that explicit hardware-width input, not all of Linux's audio policy.
NARF uses stereo layout for mono and the eight-channel layout for 3..8 channels.
The vectors cover Linux's defined 2/6/8-channel layouts, all UHBR rates/lane
counts and RGB 8/10/12 bpc, including narrow blanking and rate-filter boundaries.
DSC and MST audio are outside this contract.

`registers.c` checks all four native APG/stream register offsets and masks
against Linux DCN401 headers. Its compile command is in the file. These checks
and the register/ownership models provide no physical playback evidence.
