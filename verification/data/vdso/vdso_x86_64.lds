/* vDSO layout + version script (x86_64). Models the Linux kernel's
 * arch/x86/entry/vdso/vdso.lds.S: one RX PT_LOAD that includes the ELF
 * header + program headers (so __ehdr_start == the mapped base), plus a
 * PT_DYNAMIC for the symbol/version tables libc parses. */
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
  LINUX_2.6 {
    global:
      __vdso_clock_gettime;
      __vdso_gettimeofday;
      __vdso_clock_getres;
      __vdso_getcpu;
      __vdso_time;
    local: *;
  };
}
