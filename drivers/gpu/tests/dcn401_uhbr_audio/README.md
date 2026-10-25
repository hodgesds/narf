# UHBR LPCM regression vectors

The retained 1701 vectors use pixel clock(kHz), horizontal active/total, bpc,
UHBR rate(10-Mbps units), lane count and channel count; output is the supported
LPCM sample-rate mask. The 4536 DSC cases additionally specify compressed
bits-per-pixel in1/16, slice count and encoder minimum blank width.

These static fixtures originated from Linux `dc/dce/dce_audio.c` bandwidth
arithmetic using the programmed `HBLANK_MIN_SYMBOL_WIDTH`, including pixel
padding, rather than the differently scaled derived link-info field. Native
Rust tests call the production bandwidth function. Mono uses stereo layout,
and 3..8 channels use the eight-channel layout. Fixture agreement establishes
an internal regression contract, not current Linux conformance or physical
playback. The source extraction/compiler pipeline and register C shims are
removed.
