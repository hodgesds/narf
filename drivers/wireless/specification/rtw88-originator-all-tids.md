# RTW88 originator Block Ack on non-VO TIDs

This is a source-complete software contract for retained RTL8821CE and
RTL8822CE, channel1/HT20/one stream. New release/native execution and physical
acceptance are pending. It supplies no production measurements or board asset.

`Rtw88Device::tx_ba_request()` retains the original v1 `identity`, `filename`
and `mac`, and additionally returns `all_tids_identity` and
`all_tids_filename`. The new filename has `tx-ba-v2` in place of `tx-ba-v1`.
The new identity hashes the unchanged complete v1 H or R-over-H identity plus
the actual per-TID, ring, receipt and complete mixed-queue program. Metadata
does not authorize DATA. Native loading tries optional v2 first; only an absent
v2 name permits v1 lookup. A present bad v2 cannot borrow the v1 permission.
The v1 recipe,192-byte input, zero-reserved admission and BE/TID0 behavior
remain available. Neither Q alone nor a v1 T record enables the new bursts.

The separately signed N21T/N22T **version2** record remains192 bytes, with
the same exact chip, MAC, channel1/width20, antenna, EIRP, full thermal0..63,
batch2..4, peer-window1..64,8191-byte/factor0 and2500..4000us bounds as v1.
Its version/header is `[2,0,192,0]`; bytes16..48 contain
`all_tids_identity`; bytes108..110 are exactly `[0x3f,3]`, denoting TIDs0..5
and the additional BK/VI rings. Bytes110..192 are zero. All four transition/
automatic-response/control/retry-burst peaks and16 LGI/SGI MCS peaks now bound
the maximum across the complete BE/BK/VI program, including transitions and
mixed-TID duty, supply, antenna, coexistence and retries. A TID subset, VO bit,
missing ring, different identity or shorter thermal envelope is refused.
These are externally measured maxima, not values inferred from single-MPDU
power or produced by this implementation. Current host/factory ceilings and
every earlier H/R peak still intersect the complete new program.

N2xQ remains independently mandatory for actual nonzero-TID classification,
WMM admission-control downgrade and the extra ACs. Absence or observed loss of
Q preserves its existing legitimate BE/TID0 fallback. It cannot reclassify a
queued ciphertext or silently activate another TID's agreement. Each actual
burst samples the original current Q/T/base/PCI profile before descriptors
and final WP. The physical adapter encloses the complete batch publication in
the original Q capability invocation and the current T/base gate. A cut after
partial native BD publication stops publication and pins the original mappings;
no stale doorbell, new ticket or reconstructed original is admitted.

Linux7.2 `tx.c::rtw_txq_check_agg` (576..605) starts BA per demanded TXQ TID,
excluding VO and EAPOL. `rtw_tx_pkt_info_update` assigns QSEL from the actual
priority; `rtw_tx_queue_mapping` and `rtw_tx_ac_to_hwq` map the canonical AC to
the physical queue. `mac80211.c::rtw_ops_ampdu_action` owns host TX_START/
TX_OPERATIONAL eligibility rather than a fictitious firmware-session ACK.
The implementation retains the existing genuine on-air ADDBA request/response,
requested native CCX, actual RX-idle and MAC-FIFO proof before activation.

There is one independent agreement, window, SSN, timeout and pending control
state for each TID. TID0 preserves the original initial negotiation. Other
non-VO TIDs are requested only after real classified DATA demand. Dialog tokens
are unique across the original station and never wrap; a wrong-TID response
with the original token cancels that proposal. A late or different token cannot
activate another agreement. Open stations use independent per-TID counters;
WPA2 uses the existing actual shared Security per-TID producer before crypto.
Non-QoS management/EAPOL retain their distinct sequence and key behavior.

All agreements share the same exclusive retained native owner, four original
parked allocations, management slot and CCX namespace. Only one burst/control
owns this physical continuation at a time. Public IPC consumes a same-TID FIFO
prefix, bounded before encryption, and leaves the next TID's plaintext queued.
TID0/3 use BE0x3a8/depth256, TID1/2 use BK0x3ac/depth128, and TID4/5 use
VI0x3a4/depth128. VO6/7 remains ordinary single-MPDU on0x3a0 and EAPOL never
enters a burst. Each descriptor keeps the original TID/QSEL, protected body,
fixed measured MCS/GI and AGGEN/density/MAXAGG fields. No TX A-MSDU, protected
header rewrite, firmware BA bitmap or fabricated ACK is used.

Completion observes the submitted physical ring's own host/device indices and
depth, with wrap-safe actual consumed-prefix checks and a positive matching
CCX for every immutable original. A receipt reads the retained mapped body.
Another ring's progress, reverse CCX, PCI consumption alone or a partial prefix
cannot release the remaining originals. The exact existing1s timeout, negative
or duplicate-report and terminal quarantine rules remain mandatory.

Source `mac.c::get_priority_queues/__rtw_mac_flush_prio_queue` follows each
AC's actual RQPN map. T2 checks the retained0xc5a0 map's VI6/BE8/BK10 and
management12 shifts against exact-chip16-bit reserved/available counters.
Actual empty priority FIFOs, RX-idle and no pending native/control originals
are required before another burst, peer/key transfer or current-SSN BAR.
The BAR belongs to the TID whose completed burst was drained, rather than
whichever agreement happened to negotiate most recently. v1 retains its
original BE/management proof. RTS single-MPDU drains do not invent a BA BAR.

Peer DELBA and TU expiry retire only the named TID. All old agreements retire
before a real key/close/source transition; submitted controls and DATA still
drain through their original CCX/PCI ownership. After an actual terminal key
receipt, demanded TIDs can negotiate fresh globally unique dialogs without
resetting PN/replay or the independent sequence producers. Existing opaque
recipient BA, original receive/copy epochs and publication fences stay intact.

Sixteen new native registrations are written: seven compositions per chip and
two actual packet-Core cases. They cover Open/WPA2 with real kernel DHCP and
all six independent non-VO agreements, actual per-ring WP/QSEL and four-buffer
bursts, VO singles, public mixed-TID prefix order without SN/PN gaps, malformed
v2/v1 identity isolation, TU/DELBA and genuine key replacement, held actual
control CCX and wrong-TID response, current-Q fallback/partial-BD loss, and
per-ring wrap/ordered consumed-prefix receipts. Fixture records are private
synthetic measurements and the reactive AP reads real published DMA originals.
All earlier native registrations and assertions remain. These new cases have
not run; no over-air, RF, power or throughput result is claimed.
