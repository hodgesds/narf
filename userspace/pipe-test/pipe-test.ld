ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0x0000008000001000;
    .text : ALIGN(4096) { *(.text .text.*) *(.ltext .ltext.*) *(.rodata .rodata.*) *(.lrodata .lrodata.*) } :text
    .data : ALIGN(4096) { *(.data .data.*) *(.ldata .ldata.*) *(.bss .bss.*) *(.lbss .lbss.*) } :data
    /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note.*) }
}
