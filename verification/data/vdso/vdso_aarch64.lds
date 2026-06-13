/* vDSO layout + version script (aarch64). Mirrors the Linux kernel's
 * arch/arm64/kernel/vdso/vdso.lds.S: one RX PT_LOAD including the ELF
 * header + program headers, a PT_DYNAMIC, and the __kernel_* symbols under
 * the LINUX_2.6.39 version node that glibc/musl look up on arm64. */
SECTIONS {
  . = SIZEOF_HEADERS;

  .hash           : { *(.hash) }
  .gnu.hash       : { *(.gnu.hash) }
  .dynsym         : { *(.dynsym) }
  .dynstr         : { *(.dynstr) }
  .gnu.version    : { *(.gnu.version) }
  .gnu.version_d  : { *(.gnu.version_d) }
  .gnu.version_r  : { *(.gnu.version_r) }

  .dynamic        : { *(.dynamic) }                       :text :dynamic

  .rodata         : { *(.rodata*) *(.data*) *(.bss*)
                      *(.got*) *(.igot*) *(.plt*) }        :text
  .text           : { *(.text*) }                         :text

  /DISCARD/       : { *(.note*) *(.eh_frame*) *(.comment) *(.gnu.lto*) }
}

PHDRS {
  text    PT_LOAD    FLAGS(5) FILEHDR PHDRS;   /* R+X, includes ehdr+phdrs */
  dynamic PT_DYNAMIC;
}

VERSION {
  LINUX_2.6.39 {
    global:
      __kernel_clock_gettime;
      __kernel_gettimeofday;
      __kernel_clock_getres;
      __kernel_getcpu;
    local: *;
  };
}
