# drivers/psp — AMD Platform Security Processor Driver

`drivers/psp` is the host-side driver for the AMD Platform Security
Processor, the separate Arm Cortex-A5 security microcontroller embedded in
AMD SoCs (Family 0x17 Renoir, Family 0x19 Phoenix HawkPoint1, and
relatives). From the main CPU's point of view the PSP is reached through
the CCP subsystem's PCI function (vendor 0x1022), and this driver speaks
the platform-level mailbox protocol that the PSP exposes there.

A key distinction the crate draws is that AMD hardware carries *two*
separate mailbox protocols, and this driver implements only one of them.
The platform mailbox lives in the CCP's C2PMSG_17–19 registers (and
associated capability/bootloader/TEE-version registers) and is used for
TEE ring initialization, platform status, and firmware-version queries.
The other mailbox — the GFX/MP0 firmware-load path used to load
DCN/SMU/GFX/VCN firmware — is handled elsewhere, in the GPU driver's
PSP code, and is explicitly out of scope here.

The driver encodes the register layout for both silicon generations:
Renoir and Cezanne (pspv3/pspv4) place the command/response and
command-buffer-address registers in the 0x105xx window, while Phoenix
HawkPoint1 (pspv5/pspv7) uses a shifted 0x109xx window; the
capability, bootloader-info, and TEE-version registers sit at the same
absolute offsets on both. The command/response register itself is a
packed word carrying a response-ready bit, a recovery-mode bit, the
host-written command id, and a 16-bit status field that reads back zero
on success — so a command is issued by writing the physical address of a
command buffer, triggering the command id, and polling for the
response bit. This mirrors Linux's `psp-dev.c` / `sp-pci.c` register
definitions, cited under NARF's relicensing record.

The crate is `no_std` with `alloc`, forbids unchecked `unsafe`, and
depends only on `narf-lib` and the kernel test harness. It is a pure
hardware driver — it talks to the PSP so that higher layers (TEE clients,
attestation, firmware queries) have a transport, and does not itself
define security policy.
