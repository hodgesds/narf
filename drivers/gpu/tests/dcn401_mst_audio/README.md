# Legacy MST LPCM regression vectors

Native Rust tests consume 2268 static uncompressed cases and 1512 DSC cases.
Inputs cover RBR/HBR/HBR2/HBR3,1/2/4 lanes, RGB8/10/12bpc,2/6/8-channel
layouts and seven sample rates, including narrow blanking. They originated
from Linux `dce_audio.c` bandwidth arithmetic; the former compiler comparison
pipeline is removed. Native tests exercise production Rust functions directly.

Legacy MST audio excludes FEC overhead and uses zero minimum blank width.
AV mapping uses four lanes; NARF conservatively treats mono as stereo and
3..8 channels as the eight-channel layout. Link admission separately requires
completed manager payload and fresh SAT/VC/transport witnesses. These fixtures
and internal tests do not establish external conformance or physical playback.
