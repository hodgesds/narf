# AR9285 N85T4 bounded larger sender aggregates

This is a software contract for external board qualification. The complete
source and seven native cases are written; release compilation and native
execution of this continuation are pending. No measured peak, signature,
physical RF/interoperability result or performance claim is supplied.

The admitted radio remains AR9285 revision2, one chain, with current exact
N85H1/H2 HT20 or N85H3 full20/40 qualification and its actual calibration,
factory, country, occupied-span and native readback proofs. AR2427 and every
other chip remain excluded. Old N85T1/T2/T3 identities, record bytes, two-map
allocation and maximum4095-air-byte recovery recipe remain unchanged.
A larger program requires a separate signed **N85T4** record. Its measured
whole-program peak covers every admitted member count, rate, width/GI,
normal-ACK retry, RTS/protection, automatic response, BAR/DELBA and transient
through the full fixed temperature/supply/antenna/BT/posture envelope.
Tracking and a TX A-MSDU program are not implied.

`Ath9k::tx_aggregate_qualification_request()` returns a factual identity/MAC/
filename after an actual current packet owner exists. It grants neither an
agreement nor emission. The distinct SHA-256 recipe binds the complete H1/2/3
identity and signed-body digest, base version, actual geometry, full source
program, limits, publication, readback, retry, epoch and terminal ownership.
The filename is `ath9k/ar9285-txba-v4-ch<P>-ext<S>-<MAC>.bin`, with decimal
primary/secondary (S=0 for20) and twelve lowercase hex MAC digits. Registered
loading probes v4 first; an absent file retains the accepted old request.
A present malformed v4 record is refused rather than decoded as an old format.
An installed v4 source cannot be replaced after revocation or policy loss.

All fields are little endian. The record is exactly128 bytes:

| Offset | Field |
| ---: | --- |
|0| `N85T`, version:u16=4, header:u16=128 |
|8| length:u32=128 |
|12| vendor:u16=0x168c/device:u16=0x002b |
|16| request SHA-256[32] |
|48| MAC[6] |
|54| primary:u8, width:u8 (20/40), secondary:u8 (0 for20), direction:u8 (0 for20,1 above,3 below) |
|58| measured maximum complete-program conducted peak:i16 half-dBm |
|60| maximum BA window:u8=4..64 |
|61| software retries per original:u8=3 |
|62| board ceiling:i16 half-dBm |
|64| maximum members:u8=3..8 |
|65| exact current base N85H version:u8=1/2/3 |
|66| maximum complete aggregate air bytes:u16=1..65535 |
|68| complete current H1/2/3 signed-body SHA-256[32] |
|100| reserved[28]=0 |

Peak/ceiling are known values in−512..256. Every invoke nests both immutable
source caps, and the peak plus current base antenna upper bound must fit this
ceiling, the base ceiling and all current rules overlapping the complete
occupied span. The base still proves the actual selected power program and
all current PCI/RF-silent/calibration readbacks. A small signed air bound or
window may admit only singles or pairs; that grants no larger transmission.
No private key or synthetic production measurement is supplied.

The sender retains one actual ADDBA agreement for BE/TID0, with its current
shared QoS sequence as SSN, exact native request receipt, bound response,
TU inactivity and real DELBA. One chain is bounded by the signed member
limit, **half the accepted BA window**, min offered/response/current-beacon
A-MPDU factor, signed air ceiling, hardware65535 limit, and actual **4ms**
HT PPDU duration. The software bound is eight original MPDUs; it does not
claim a64-member sender. Individual originals remain34..1550 bytes before
FCS. Each owns a separate original QoS SC and, for WPA2, a distinct shared
CCMP PN/ciphertext. Management, EAPOL, other TIDs, keys and control traffic
never enter this chain. N85Q normal-ACK singles on other TIDs use their own
SC/QCU and never advance or recover this TID0 sender BA window.

The public Device sizes a maximal already-queued TID0 prefix before consuming
any sequence number or PN. Lengths include QoS26/SNAP8 and the actual CCMP
ExtIV/MIC, excluding Ethernet14. Unfitting suffixes stay in their IPC-owned
software queues; a lone/unfitting head uses ordinary single-MPDU transmission.
The actual publication lock and current source/readback checks enclose
encoding and DMA publication. After any partial encoder failure the owner is
terminal; consumed PNs/SCs are never reused. A current accepted beacon may
only narrow the sender: lower the byte limit, raise density, or drop TX SGI40
in step with the installed packet profile. Admission never keeps stale SGI
4ms timing after the actual TX descriptor mode becomes long GI.

Only a larger source grows storage. With every TX queue proven idle, it
allocates a checked128-byte-stride descriptor ring and enough separate DMA
payload maps for the signed count. Existing maps are retained; the old ring,
which QTXDP may still name, is retained too. All new addresses are aligned,
32-bit and disjoint from every old/fresh extent. A failed expansion publishes
nothing. Neither ring nor any payload map is released until the existing
full RX/all-QCU/IRQ/BME-off/PCIe-order proof succeeds. Failed stop retains all
published storage, including the original ring, for the boot lifetime.

The physical chain follows Linux `ar9002_set_txdesc`: FIRST owns rates, tries,
whole-PPDU duration and16-bit AggrLen, with IsAggr|MoreAggr. Each MIDDLE has
IsAggr|MoreAggr, its own PadDelim and actual next descriptor DMA link, with
zero rate/tries/duration words. LAST has IsAggr, NULL link, and no following
alignment/delimiter padding. Per-member length includes FCS, while DMA
payload length includes transport pad2 after the original QoS header. The
original authenticated header/ciphertext is never transformed. A preceding
member adds a4-byte delimiter, FCS, alignment and max(source256-byte minimum,
actual negotiated density) padding. Software CCMP installs no hardware key,
so the hardware-key encryption-delimiter quirk does not apply; AR9285
ent_mode0 has no later OTP first60-delimiter quirk.

Only actual LAST TxDone **and** QCU idle permit a receipt. Before consuming
any BA bitmap, the owner verifies every immutable descriptor control word,
every original padded payload and each bound sequence. The actual native
BAflag/TID/SSN/64-bit bitmap resolves every member, including4095 wrap. A
wrong returned TID retries all; TxOK without BA is terminal. Under v4 every
missing original independently gets at most three normal-ACK retries, same
SC/PN/ciphertext and Retry bit only. Exhausted holes retire CPU retry
authority; remaining originals finish their own bounded retry ownership.
Only then does an actual BAR, with exact target=end of the full chain,
native BAflag/TID/SSN/ACK/idle plus RX-idle proof, advance the window. No hole
is skipped on enqueue or by dropping a future. Rekey/source/cancel/retune
closure invalidates retry and copy authority while retaining still-published
DMA until terminal proof; old packet/name/key/BA tokens cannot reopen it.

Pinned Linux7.2 source chain: `xmit.c::ath_lookup_rate` intersects peer and
4ms/65535 bounds; `ath_compute_num_delims` supplies minimum and density;
`ath_tx_form_aggr` enforces half-BAW, actual predecessor padding and links;
`ath_pkt_duration` supplies20/40/SGI arithmetic; `ath_tx_fill_desc` chooses
FIRST/MIDDLE/LAST; `ar9002_mac.c::ar9002_set_txdesc` encodes each descriptor,
`ar9002_hw_proc_txdesc` parses actual tail BA status; `mac.h` gives the16-bit
AggrLen and8-bit PadDelim fields. Exact file hashes/line anchors are persisted
with the implementation evidence.

Seven written native cases cover distinct/unknown/unsigned v4 and unchanged
legacy2; all3..8 counts/MCS/CCMP PNs and actual separate maps, padding and
queue/tail fences; half-BAW/factor/signed air/4ms prefix limits before SC
consumption and actual >8191-air chains; all eight bitmap positions and
immutable hole retries/BAR/wrap; middle-control/payload/source corruption,
rekey and pinned failure ownership; public IPC eight-original Open/WPA2
kernel DHCP/IP with recipient BA and an independent nonzero-TID single
between two eight-frame chains; and actual freshly calibrated H3 both
extensions, LGI/SGI40,16us density, current SGI loss and DHCP. They have not
run. Hardware qualification remains an external requirement.
