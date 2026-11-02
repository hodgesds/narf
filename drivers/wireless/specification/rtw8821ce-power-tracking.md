# RTL8821CE qualified thermal tracking

This continuation implements `rf_power_tracking` for the admitted RTL8821CE
type0, RF-A, channel1/HT20 station. It adds actual TXAGC/txscale compensation
and segmented associated IQK to the retained firmware/packet owner. RTL8822C
keeps its existing N22D mechanism. All existing N21Q/P/S/L/H/R/T/X and N21D
formats and identity recipes keep their original meaning. N21X is RTS;
the distinct tracking asset is **N21W**. No physical board measurements or
deployment qualification asset are supplied.

## Source and native program

The pinned Linux7.2 sources are
`drivers/net/wireless/realtek/rtw88/rtw8821c.c`:
`rtw8821c_pwrtrack_init`, `rtw8821c_pwr_track`,
`rtw8821c_phy_pwrtrack`, `rtw8821c_pwrtrack_set`,
`rtw8821c_txagc_swing_offset`, `rtw8821c_do_iqk`, and the four
2GHz CCK/OFDM positive/negative tables; `phy.c`'s thermal EWMA/delta/IQK
threshold; `fw.c::rtw_fw_do_iqk`; and `fw.h::IQK_SET_SEGMENT_IQK`.
The 37-entry TX-scale table and four delta tables are hashed into N21W's
recipe. C21 does not read C22's efuse power-track selector; its source
zero-initialized type0 is retained. An erased factory meter refuses tracking.

The watchdog triggers RF42[17:16]=3, waits until a following period at least
2seconds later, and reads the actual RF42[15:10]. Thermal EWMA uses precision10
and weight4. Delta magnitude is bounded29. Fixed DATA uses its actual known
TX rate. Firmware fallback requires a native C2H0c RA report; absence defers
tracking. The source CCK or OFDM table selects the signed delta.

The source signed TXAGC offset at c94[6:1] is global. Its source bounds
±15 are intersected with **every** programmed CCK, OFDM and MCS0..7 factory
limit, including automatic responses and rates other than current DATA.
The RFE2/4 path-B factory substitution for physical RF-A remains intact.
Remaining compensation uses c1c[31:21], constrained to the source initial
index+10, lower0 and table bound36. Both the actual signed AGC and table
value must read back. Index arithmetic never substitutes for RF measurement.

An actual quiet continuation is required before changing either power field
or running IQK: no software DATA/control/security/BA submission; every
original packet Core terminal retired; genuine RX-idle and current original
RX pointer; all seven native TX ring RP=WP; and all four source priority
FIFO reserved/available counters equal the programmed values. Every ring,
key, PN, replay floor, TID agreement and allocator owner is retained.
The driver closes publication, retires copied receive admission, pauses TX,
sets RXPKT_NUM.RW_RELEASE, obtains actual RXDMA_IDLE, and rechecks the original
RX pointer before mutation. Frames arriving before that receipt cannot cross
the newly admitted program. No old native mapping is freed or reconstructed.

IQK runs when the averaged meter differs from the last completed calibration
meter by8. The existing H2C ring and80-byte retained command buffer are reused
only after their actual previous terminal, with a nonwrapping sequence and
the literal associated command (clear0, segment1). Cold startup's segment0
encoder is unchanged. A preexisting RF08 completion refuses the operation.
After real H2C consumption, a new RF08=abcde and zero IQKFAIL low8/reload16
are mandatory; the driver then clears and reads back RF08. DMA retirement
alone never acknowledges applied IQK. Missing, failed, revoked or cancelled
receipts leave publication closed and published DMA pinned.

The new program is committed only after power/HT geometry/IQK readbacks,
current original qualification and PCI invokes, and actual RX unpark/TX
unpause receipts. Copies from before either mutation boundary remain denied.
The original H/R/T/RTS dispatch is a distinct non-dispatching base invoker,
so the tracking wrapper cannot create generic invocation recursion.

## Signed N21W v1

Filename: `rtw88/rtw8821ce-power-track-v1-<12 lowercase MAC hex>.bin`.
The existing trusted firmware loader and nonempty authenticated signer are
required. The public `Rtw88Device::rtl8821c_power_tracking_request()` returns
measurement metadata for the exact already-bound C21 HT session; it grants
no writes. Install the externally measured asset before a fresh association
to enable the continuation. An absent asset preserves the static station.
An invalid asset refuses the new continuation and preserves the original
static station without thermal mutations.

The identity binds factory MAC/thermal, initial actual TX scale, C21 H recipe
and signed bytes (including the original factory image/calibration chain),
all three actual factory ceilings, optional R and T1/T2 signed bytes, optional
RTS N21X signed bytes, optional C/Q/F signed bytes, optional D signed bytes,
and this complete source program. It cannot be reused across a narrower
H-only recipe, another T version, different all-AC qualification, or changed
power indices. Dynamic RTS settings are inside the measured whole program.

| Bytes | Meaning |
|---|---|
| 0..4 | `N21W` |
| 4..8 | `[1,0,192,0]` |
| 8..12 | 192 LE u32 |
| 12..16 | PCI vendor/device `[ec,10,21,c8]` |
| 16..48 | Exact request identity |
| 48..54 | Factory MAC |
| 54..56 | `[1,20]`, channel1/HT20 |
| 56..58 | Antenna gain in quarter-dBi, signed LE i16, 0..128 |
| 58..60 | Qualified regulatory ceiling in quarter-dBm, signed LE i16 |
| 60..62 | Inclusive measured thermal interval, containing the factory meter, within0..63 |
| 62..64 | Signed i8 AGC interval, containing0, within−15..15 |
| 64..66 | Inclusive TX-scale index interval containing the actual initial index, within0..36 |
| 66..98 | Sixteen signed LE i16 conducted maxima, in quarter-dBm |
| 98..192 | Zero |

Peak0 is the maximum of the whole admitted program; peaks1..15 must not
exceed it. The sixteen maxima cover whole program, CCK, OFDM, HT LGI/SGI,
automatic responses, retries, power-program transitions, associated IQK,
coexistence, mixed QCU/T2 bursts, coding, fallback, DIG/CCK-PD/RA composition,
supply and antenna/environment variation. Each value must lie within−512..256
quarter-dBm; each plus antenna gain must remain within the current signed
H/static-policy, optional R/T/RTS signed-prefix ceilings and the W ceiling.
Every operation also invokes that exact current original prefix; a child
qualification cannot be bypassed by a wider W envelope. These are measured maxima across
the full admitted AGC/swing/thermal range and source combinations, not
measurements at a single nominal index. No per-rate or analog calibration
value is inferred from these bounds.

## Restore and terminal ownership

Losing W or a composed source, or leaving its thermal/power envelope, can
restore zero AGC and the exact original TX scale only when no periodic IQK
has changed firmware coefficients. That restore uses the current original
static qualification, actual quiet/RX-park proof and complete readbacks; it
does not invoke a revoked W. Keys, PN floors and existing BA ownership are
preserved. If native work is not terminal, restoration defers; it never
invents a completion. An ordinary caller hitting an invalid source before
maintenance may instead terminally close the device.

After any periodic IQK, static coefficient restoration has no source-backed
receipt. Qualification loss therefore closes the station and requires a
fresh lifecycle. The driver does not pretend that resetting AGC/swing restores
the startup IQK image. Failed restore, cancellation, current base/PCI loss,
ambiguous command ownership and physical readback failure also remain closed;
only the existing stopped-DMA proof can release published allocations.

## Written native cases

Eight cases use the actual C21 reserved firmware → IQK → power → awake →
L/H → native Core → registered Device stack, real DMA/CCX and AP actor:
Open with kernel DHCP and applied IQK; WPA2 negative AGC/swing and retained
keys; T2/Q/RTS with a nonselected MCS at its factory ceiling and copied-epoch
retirement; invalid distinct assets/static H; held native DATA and power-only
restore; failed writes/RX park/H2C/applied IQK; cancellation at a real await;
and coding/actual RA fallback/D composition. These cases are written and
remain unexecuted until the coordinated release/native validation. Physical
radio, board power and antenna acceptance remain separate.
