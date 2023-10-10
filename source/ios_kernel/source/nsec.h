#pragma once

#define NSEC_TEXT_VADDR 0xe10a0000
#define NSEC_BSS_VADDR  0xe12e9000
#define NSEC_PADDR(vaddr) (vaddr - 0xE1000000 + 0x12BC0000)
void run_ios_nsec_patches(void);
