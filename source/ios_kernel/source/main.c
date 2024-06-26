#include "imports.h"
#include "net.h"
#include "fpd.h"
#include "nsec.h"

#define USB_PHYS_CODE_BASE      0x101312D0
#define NET_PHYS_CODE_BASE      0x12432000
#define NET_PHYS_BSS_BASE       0x1288e000
#define FPD_PHYS_CODE_BASE      (0xe316c000 - 0xe3000000 + 0x13640000)
#define FPD_PHYS_BSS_BASE       (0xe32fd000 - 0xe31af000 + 0x137ef000)

typedef struct {
    uint32_t size;
    uint8_t data[0];
} payload_info_t;

static const char repairData_set_fault_behavior[] = {
    0xE1,0x2F,0xFF,0x1E,0xE9,0x2D,0x40,0x30,0xE5,0x93,0x20,0x00,0xE1,0xA0,0x40,0x00,
    0xE5,0x92,0x30,0x54,0xE1,0xA0,0x50,0x01,0xE3,0x53,0x00,0x01,0x0A,0x00,0x00,0x02,
    0xE1,0x53,0x00,0x00,0xE3,0xE0,0x00,0x00,0x18,0xBD,0x80,0x30,0xE3,0x54,0x00,0x0D,
};

static const char repairData_set_panic_behavior[] = {
    0x08,0x16,0x6C,0x00,0x00,0x00,0x18,0x0C,0x08,0x14,0x40,0x00,0x00,0x00,0x9D,0x70,
    0x08,0x16,0x84,0x0C,0x00,0x00,0xB4,0x0C,0x00,0x00,0x01,0x01,0x08,0x14,0x40,0x00,
    0x08,0x15,0x00,0x00,0x08,0x17,0x21,0x80,0x08,0x17,0x38,0x00,0x08,0x14,0x30,0xD4,
    0x08,0x14,0x12,0x50,0x08,0x14,0x12,0x94,0xE3,0xA0,0x35,0x36,0xE5,0x93,0x21,0x94,
    0xE3,0xC2,0x2E,0x21,0xE5,0x83,0x21,0x94,0xE5,0x93,0x11,0x94,0xE1,0x2F,0xFF,0x1E,
    0xE5,0x9F,0x30,0x1C,0xE5,0x9F,0xC0,0x1C,0xE5,0x93,0x20,0x00,0xE1,0xA0,0x10,0x00,
    0xE5,0x92,0x30,0x54,0xE5,0x9C,0x00,0x00,
};

static const char repairData_usb_root_thread[] = {
    0xE5,0x8D,0xE0,0x04,0xE5,0x8D,0xC0,0x08,0xE5,0x8D,0x40,0x0C,0xE5,0x8D,0x60,0x10,
    0xEB,0x00,0xB2,0xFD,0xEA,0xFF,0xFF,0xC9,0x10,0x14,0x03,0xF8,0x10,0x62,0x4D,0xD3,
    0x10,0x14,0x50,0x00,0x10,0x14,0x50,0x20,0x10,0x14,0x00,0x00,0x10,0x14,0x00,0x90,
    0x10,0x14,0x00,0x70,0x10,0x14,0x00,0x98,0x10,0x14,0x00,0x84,0x10,0x14,0x03,0xE8,
    0x10,0x14,0x00,0x3C,0x00,0x00,0x01,0x73,0x00,0x00,0x01,0x76,0xE9,0x2D,0x4F,0xF0,
    0xE2,0x4D,0xDE,0x17,0xEB,0x00,0xB9,0x92,0xE3,0xA0,0x10,0x00,0xE3,0xA0,0x20,0x03,
    0xE5,0x9F,0x0E,0x68,0xEB,0x00,0xB3,0x20,
};

int _main()
{
    void(*invalidate_icache)() = (void(*)())0x0812DCF0;
    void(*invalidate_dcache)(unsigned int, unsigned int) = (void(*)())0x08120164;
    void(*flush_dcache)(unsigned int, unsigned int) = (void(*)())0x08120160;

    flush_dcache(0x081200F0, 0x4001); // giving a size >= 0x4000 flushes all cache

    int level = disable_interrupts();

    unsigned int control_register = disable_mmu();

    /* Save the request handle so we can reply later */
    *(volatile uint32_t*) 0x0012F000 = *(volatile uint32_t*)0x1016AD18;

    /* Patch kernel_error_handler to BX LR immediately */
    *(volatile uint32_t*) 0x08129A24 = 0xE12FFF1E;

    void * pset_fault_behavior = (void*)0x081298BC;
    kernel_memcpy(pset_fault_behavior, (void*)repairData_set_fault_behavior, sizeof(repairData_set_fault_behavior));

    void * pset_panic_behavior = (void*)0x081296E4;
    kernel_memcpy(pset_panic_behavior, (void*)repairData_set_panic_behavior, sizeof(repairData_set_panic_behavior));

    void * pusb_root_thread = (void*)0x10100174;
    kernel_memcpy(pusb_root_thread, (void*)repairData_usb_root_thread, sizeof(repairData_usb_root_thread));

    // copy ios_usb
    payload_info_t *payloads = (payload_info_t *) 0x00148000;
    kernel_memcpy((void *) USB_PHYS_CODE_BASE, payloads->data, payloads->size);

    // copy ios_net
    payloads = (payload_info_t *) 0x00149000;
    kernel_memcpy((void *) NET_PHYS_CODE_BASE, payloads->data, payloads->size);

    // memset ios-net bss
    kernel_memset((void *) NET_PHYS_BSS_BASE, 0, 0x6000);

    // apply ios_net patches
    run_ios_net_patches();

    // copy ios_fpd
    payloads = (payload_info_t *) 0x00150000;
    kernel_memcpy((void *) FPD_PHYS_CODE_BASE, payloads->data, payloads->size);

    // memset ios_fpd bss
    kernel_memset((void *) FPD_PHYS_BSS_BASE, 0, 0x6000);

    // apply ios_fpd patches
    run_ios_fpd_patches();

    // copy ios_nsec
    payloads = (payload_info_t *) 0x00160000;
    kernel_memcpy((void *) NSEC_PADDR(NSEC_TEXT_VADDR), payloads->data, payloads->size);

    // memset ios_nsec bss
    kernel_memset((void *) NSEC_PADDR(NSEC_BSS_VADDR), 0, 0x6000);

    // apply ios_nsec patches
    run_ios_nsec_patches();

    *(volatile uint32_t*) (0x1555500) = 0;

    /* REENABLE MMU */
    restore_mmu(control_register);

    invalidate_dcache(0x081298BC, 0x4001); // giving a size >= 0x4000 invalidates all cache
    invalidate_icache();

    enable_interrupts(level);

	int (*setClientCapability)(int pid, int fid, uint64_t mask) = (int(*)(int, int, uint64_t)) 0x081260a8;
    // give IOS-NET full access to FS
    setClientCapability(7, 11, 0xFFFFFFFFFFFFFFFF);
    // give IOS-FPD full access to FS
	setClientCapability(12, 11, 0xFFFFFFFFFFFFFFFF);
    // give IOS-NSEC full access to FS
    setClientCapability(9, 11, 0xFFFFFFFFFFFFFFFF);

    return 0;
}
