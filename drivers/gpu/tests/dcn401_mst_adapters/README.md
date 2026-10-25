# MST adapter Rust coverage

Native Rust tests under `drivers/gpu/navi48` exercise adapter discovery, owned
AUX transactions, bandwidth admission, cancellation and quarantine. Source
references are Linux's Synaptics remote-command/FIFO-reset helpers and converter
FRL intersection policy. The former extraction/C-shim comparison is removed.
Internal tests do not establish hub behavior or physical link training.
