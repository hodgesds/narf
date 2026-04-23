# frame — Research

## Primary sources

- **Intel SDM Vol. 3A — Chapters 6 (Interrupt and Exception Handling) and
  7 (Task Management)**. <https://www.intel.com/sdm>
- **Arm ARM — D1 ("The AArch64 System Level Programmers' Model"),
  especially exception entry, VBAR_EL1, SPSR_EL1.**
  <https://developer.arm.com/documentation/ddi0487/latest/>

## Secondary sources

- **Phil Oppermann, "Writing an OS in Rust" — Interrupts and Exceptions.**
  <https://os.phil-opp.com/cpu-exceptions/>
- **Redox `kernel/src/arch/x86_64/interrupt`.**
- **Hubris kernel supervisor.**
- **`x86_64` crate (rust-osdev).** <https://docs.rs/x86_64>
- **`aarch64-cpu` crate.** <https://docs.rs/aarch64-cpu>

## Distilled summaries

- None specifically — primary source chapters are the go-to.

## Open research questions

- TSS IST usage: reserve how many stacks for which exceptions?
- aarch64 stack pointer alignment for trap entry under MTE.
