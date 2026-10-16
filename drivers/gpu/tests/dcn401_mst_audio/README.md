# Legacy MST LPCM reference checks

Run `python3 ../dcn401_uhbr_audio/check.py --mst [linux-tree]` here to compile
the actual static `check_audio_bandwidth_dp` routines from Linux `dce_audio.c`
with Linux's `fixpt31_32.c` and the existing DSC host header shims. `--generate`
prints replacement vectors. The kernel tests consume the checked-in file.

The 2268 cases cover RBR/HBR/HBR2/HBR3, 1/2/4 physical lanes, RGB 8/10/12 bpc,
2/6/8-channel layouts and seven sample rates, with normal and narrow blanking.
Inputs are pixel clock (kHz), horizontal active/total, bpc, DPCD rate code,
lane count and channel count; output is the supported LPCM rate mask.

The link budget excludes FEC overhead, as Linux's
`populate_audio_dp_link_info` does for legacy MST audio; minimum blank width
is zero. AV mapping always uses four lanes. NARF conservatively treats mono
as stereo and 3..8 channels as the eight-channel layout. The vectors test
arithmetic independently of video link admission, including over-link modes.
Native startup separately requires the completed manager payload and fresh
SAT/VC/transport witnesses. These checks provide no physical playback evidence.
