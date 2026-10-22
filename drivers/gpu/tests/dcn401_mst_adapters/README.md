# MST adapter primary-source checks

Run `bash check.sh /path/to/linux` with a Linux source tree. The extractor
compiles the actual Synaptics remote-command/FIFO-reset helpers and the
actual converter FRL intersection helpers, with host shims for AUX and the
surrounding display structures. It checks the 13-command reset transcript,
converter/EDID limits, autonomous post-training rate decoding and the
upstream PCON policy gate.

The native Rust tests under `drivers/gpu/navi48` exercise adapter discovery,
owned AUX transactions, bandwidth admission, cancellation and quarantine.
This host check compares primary helper behavior; it does not emulate a hub
or prove physical link training. A source archive run does not verify a Git
revision: use the repository's revision-pinned reference gate for that.
