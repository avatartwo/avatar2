ENTRY(main)

SECTIONS
{
  . = 0x80100000;
  .text : { *(.text) }
  .data : { *(.data) }
  .bss : { *(.bss) }
}

