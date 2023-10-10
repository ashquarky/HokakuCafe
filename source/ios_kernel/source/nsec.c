#include "nsec.h"
#include "imports.h"
#include "../../common/interface.h"
#include "../../common/config.h"
#include "../../ios_nsec/ios_nsec_syms.h"

void run_ios_nsec_patches(void) {
    // map memory for the custom ios-net code
    // custom ios-net text
    ios_map_shared_info_t map_info;
    map_info.paddr = NSEC_PADDR(NSEC_TEXT_VADDR);
    map_info.vaddr = NSEC_TEXT_VADDR;
    map_info.size = 0x6000;
    map_info.domain = 9;            // NSEC
    map_info.type = 3;              // 0 = undefined, 1 = kernel only, 2 = read only, 3 = read/write
    map_info.cached = 0xFFFFFFFF;
    _iosMapSharedUserExecution(&map_info);

    // custom ios-net bss
    map_info.paddr = NSEC_PADDR(NSEC_BSS_VADDR);
    map_info.vaddr = NSEC_BSS_VADDR;
    map_info.size = 0x6000;
    map_info.domain = 9;            // NET
    map_info.type = 3;              // 0 = undefined, 1 = kernel only, 2 = read only, 3 = read write
    map_info.cached = 0xFFFFFFFF;
    _iosMapSharedUserExecution(&map_info);

    *(volatile uint32_t *) NSEC_PADDR(0xe1008918) = ARM_BL(0xe1008918, SSL_do_handshake_hook);

    *(volatile uint32_t *) NSEC_PADDR(0xe1007620) = ARM_BL(0xe1007620, SSL_read_hook);
    *(volatile uint32_t *) NSEC_PADDR(0xe10105c4) = ARM_BL(0xe10105c4, SSL_read_hook);

    *(volatile uint32_t *) NSEC_PADDR(0xe10074a0) = ARM_BL(0xe10074a0, SSL_write_hook);
    *(volatile uint32_t *) NSEC_PADDR(0xe10104a4) = ARM_BL(0xe10104a4, SSL_write_hook);
}
