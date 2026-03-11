MEMORY
{
    ITCM (xr) : ORIGIN = 0x00000000, LENGTH = 64K
    SRAM (rw) : ORIGIN = 0x20400000, LENGTH = 768K
}

ENTRY(_start)

/* SECTIONS directive defines the memory regions of the program */
SECTIONS
{
    /* text section (code)*/
    .text : {
        *(.text*)
    } > ITCM

    /* data section, initialized variables */
    .data : {
        *(.data)
    } > SRAM

    /* bss section, uninitialized variables */
    .bss : {
        *(.bss*)
        end = .;
        PROVIDE(end = end);
    } > SRAM

    /* stack section */
    /* The stack is placed at the end of the RAM */
    stack_top = ORIGIN(SRAM) + LENGTH(SRAM);

    _end = .;
    PROVIDE(end = .);
}

/* this should be changed..*/
