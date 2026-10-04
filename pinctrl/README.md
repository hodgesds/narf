# pinctrl — Pin Control, GPIO, and SPMI/PMIC Codecs

`narf-pinctrl` is NARF's transport-neutral collection of codecs for the
low-level control-plane plumbing of ARM-class SoCs: pin multiplexing, GPIO
register layouts, and the serial protocol that connects a SoC to its companion
power-management IC. On these platforms a single physical pin can serve many
functions (a UART line, an I²C line, a plain GPIO), with its function, drive
strength, and pull resistors selected by a pin-mux register block; GPIO banks
have their own register conventions; and the PMIC that supplies power, GPIOs,
and regulators is reached over a dedicated two-wire bus. This crate encodes and
decodes the register and message formats for all three, so that controller
drivers do not each reinvent the bit-twiddling.

The crate is explicitly a set of codecs, not a driver stack: it produces and
consumes the words that cross a bus or a register, and stays neutral about how
those words are actually transported. It comprises four modules. The pin-mux
codec encodes the 32-bit configuration word — function select, drive strength,
pull up/down — shared in form by pin-mux blocks such as Qualcomm TLMM,
MediaTek pinmux, and Rockchip GRF. The SPMI codec builds and parses MIPI SPMI
2.0 master-to-slave command words, the protocol Qualcomm PMICs and similar
power-management ICs speak. The DesignWare APB GPIO module models the
Synopsys DW_apb_gpio register bank — data, direction, and the interrupt
enable/mask/type/polarity registers. The Qualcomm PMIC module handles that
family's peripheral GPIO type registers (mode select, drive control, output
value).

The implementation is clean-room, built only from public documentation: the
MIPI SPMI 2.0 specification, the publicly available DesignWare APB GPIO
databook material, and the Qualcomm PMIC peripheral register reference as it
appears in public device headers. Those constants describe the device-side
reality of the silicon, not any particular OS's interpretation of it; no GPL
or Linux source was consulted.

`narf-pinctrl` is `no_std`, `alloc`-backed, and carries strict lints
(`forbid(unsafe_op_in_unsafe_fn)`, `deny(missing_debug_implementations)`). It
has essentially no NARF dependencies beyond the kernel test harness, reflecting
its role as a pure encoding layer other subsystems link against. The
`kernel-test` feature compiles the in-kernel smoke suite that exercises the
four codecs.
