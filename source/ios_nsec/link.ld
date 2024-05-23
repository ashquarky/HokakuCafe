OUTPUT_ARCH(arm)

INCLUDE "imports.ld"

SECTIONS {
    . = 0xe10a0000;

    .text : {
        _text_start = .;
        *(.text*);
        *(.rodata*);
        *(.data*);
    }
    _text_end = .;
    PROVIDE(_system_version = .);

    . = 0xe12e9000;

    .bss : {
        *(.bss*);
    }

    /DISCARD/ : {
        *(*);
    }
}

ASSERT(SIZEOF(.text) < 0x6000, "ios_nsec text is too big");
ASSERT(SIZEOF(.bss) < 0x6000, "ios_nsec bss is too big");
