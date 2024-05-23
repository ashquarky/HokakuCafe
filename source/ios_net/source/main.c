#include <stdio.h>
#include <string.h>

#include "ios.h"
#include "fsa.h"
#include "utils.h"
#include "../../common/interface.h"
#include "../../common/config.h"

#define ETHERTYPE_IPV4 0x0800
#define PROTO_TCP 0x06
#define PROTO_UDP 0x11

#define LINKTYPE_ETHERNET 1

typedef struct pcapng_opt_s {
    uint16_t option_type;
    uint16_t option_length;
    uint8_t  option_data[]; /* pad to 4 bytes */
} pcapng_opt_t;

typedef struct pcapng_shb_s {
    uint32_t block_type;     /* magic number */
    uint32_t block_length;   /* length of this SHB */
    uint32_t byte_order;     /* place your bets if BE works */
    uint16_t version_major;
    uint16_t version_minor;
    int64_t  section_length; /* usually -1 (unknown) */
    /* pcapng_opt_s options[] */
    /* uint32_t block_length; */
} pcapng_shb_t;

typedef struct pcapng_idb_s {
    uint32_t block_type;   /* magic number */
    uint32_t block_length; /* length of this IDB */
    uint16_t link_type;    /* data link type */
    uint16_t reserved;
    uint32_t snap_length;  /* max packet length before truncation */
    /* pcapng_opt_s options[] */
    /* uint32_t block_length; */
} pcapng_idb_t;

typedef struct __attribute__((packed)) pcapng_epb_s {
    uint32_t block_type;   /* magic number */
    uint32_t block_length; /* length of this EPB */
    uint32_t interface_id; /* zero-based IDB index */
    uint64_t timestamp;    /* milliseconds since 1970, assuming BE here */
    uint32_t captured_len; /* bytes saved to file (e.g. truncation) */
    uint32_t actual_len;   /* actual packet size */
    /* uint8_t data[] */
    /* pcapng_opt_s options[] */
    /* uint32_t block_length; */
} pcapng_epb_t;

typedef struct pcapng_dsb_s {
    uint32_t block_type;   /* magic number */
    uint32_t block_length; /* length of this DSB */
    uint32_t secrets_type; /* type of secret */
    uint32_t secrets_len;  /* size of secret */
    /* uint8_t data[] */
    /* pcapng_opt_s options[] */
    /* uint32_t block_length; */
} pcapng_dsb_t;

extern Configuration_t _configuration;

int semaphore = -1;
int fileHandle = -1;
void* writeBuffer = NULL;
int fsaHandle = -1;

int matchData(uint8_t *data)
{
    if (_configuration.mode == MODE_ALL) {
        return 1;
    }

    uint16_t ether_type = (data[12] << 8) | data[13];
    if (ether_type == ETHERTYPE_IPV4) {
        if (_configuration.mode == MODE_IPV4) {
            return 1;
        }

        if (data[23] == PROTO_TCP) {
            if (_configuration.mode == MODE_TCP) {
                return 1;
            }
        } else if (data[23] == PROTO_UDP) {
            if (_configuration.mode == MODE_UDP) {
                return 1;
            }

            if (_configuration.mode == MODE_PRUDP &&
                // PRUDPv1
                ((data[42] == 0xea && data[43] == 0xd0) ||
                // PRUDPv0 (Nintendo)
                (data[42] == 0xaf && data[43] == 0xa1))) {
                return 1;
            }
        }
    }

    return 0;
}

void writeData(void* data, uint32_t size, const char* interface)
{
    if (semaphore < 0) {
        semaphore = IOS_CreateSemaphore(1, 1);
        if (semaphore < 0) {
            printf("Failed to create semaphore\n");
        }
    }

    IOS_WaitSemaphore(semaphore, 0);

    if (fsaHandle < 0) {
        fsaHandle = IOS_Open("/dev/fsa", 0);
        if (fsaHandle < 0) {
            printf("Failed to open FSA\n");
            IOS_SignalSemaphore(semaphore);
            return;
        }
    }

    if (!writeBuffer) {
        writeBuffer = IOS_AllocAligned(0xcaff, _configuration.maxPacketSize + 0x2000, 0x40);
        if (!writeBuffer) {
            printf("Failed to allocate write buffer\n");
            IOS_SignalSemaphore(semaphore);
            return;
        }
    }

    if (fileHandle < 0) {
        int res = FSA_Mount(fsaHandle, "/dev/sdcard01", "/vol/storage_framedump", 2, NULL, 0);
        if (res >= 0) {
            FSA_MakeDir(fsaHandle, "/vol/storage_framedump/HokakuCafe", 0x600);

            CalendarTime_t ctime;
            IOS_GetAbsTimeCalendar(&ctime);

            char name[512];
            snprintf(name, sizeof(name), "/vol/storage_framedump/HokakuCafe/%04ld-%02ld-%02ld_%02ld-%02ld-%02ld.pcapng",
                ctime.year, ctime.month, ctime.day, ctime.hour, ctime.minute, ctime.second);

            res = FSA_OpenFile(fsaHandle, name, "w", &fileHandle);
            if (res < 0) {
                printf("Failed to open file\n");
                FSA_Unmount(fsaHandle, "/vol/storage_framedump", 2);
                fileHandle = -1;
                IOS_SignalSemaphore(semaphore);
                return;
            }

            // write pcapng header

            pcapng_shb_t hdr = { 0 };
            hdr.block_type = 0x0a0d0d0a;
            hdr.byte_order = 0x1a2b3c4d;
            hdr.version_major = 1;
            hdr.version_minor = 0;
            hdr.section_length = -1;

            const char app[] = "HokakuCafe v2.0";
            pcapng_opt_t app_opt = { 0 };
            app_opt.option_type = 4;
            app_opt.option_length = sizeof(app) - 1;
            // padding
            const int app_size = ALIGN(app_opt.option_length, 4);

            hdr.block_length = sizeof(hdr) + sizeof(app_opt) + app_size + 4 /* opt_endofopt */ + 4 /* block_length_2 */;

            int offset = 0;
            memcpy(writeBuffer + offset, &hdr, sizeof(hdr));
            offset += sizeof(hdr);
            memcpy(writeBuffer + offset, &app_opt, sizeof(app_opt));
            offset += sizeof(app_opt);
            memcpy(writeBuffer + offset, app, sizeof(app) - 1);
            offset += app_size;

            uint32_t opt_endofopt = 0;
            memcpy(writeBuffer + offset, &opt_endofopt, sizeof(opt_endofopt));
            offset += sizeof(opt_endofopt);

            memcpy(writeBuffer + offset, &hdr.block_length, sizeof(hdr.block_length));
            offset += sizeof(hdr.block_length);

            FSA_WriteFile(fsaHandle, writeBuffer, 1, offset, fileHandle, 0);

            // write interface descriptors
            pcapng_idb_t idb_usb = { 0 };
            idb_usb.block_type = 1;
            idb_usb.link_type = LINKTYPE_ETHERNET;
            idb_usb.snap_length = _configuration.maxPacketSize;

            const char ifname_usb[] = "USB";
            pcapng_opt_t ifname_usb_opt = { 0 };
            ifname_usb_opt.option_type = 2;
            ifname_usb_opt.option_length = sizeof(ifname_usb) - 1;
            const int ifname_usb_size = ALIGN(sizeof(ifname_usb), 4);

            pcapng_opt_t filter_opt = { 0 };
            filter_opt.option_type = 0xb;

            const char* filter;
            int filter_size;
            if (_configuration.mode == MODE_ALL) {
                filter = "\0";
                filter_size = 1;
            } else if (_configuration.mode == MODE_IPV4) {
                filter = "\0ip";
                filter_size = 3;
            } else if (_configuration.mode == MODE_TCP) {
                filter = "\0tcp";
                filter_size = 4;
            } else if (_configuration.mode == MODE_UDP) {
                filter = "\0udp";
                filter_size = 4;
            } else { //if (_configuration.mode == MODE_PRUDP) {
                filter = "\0prudpv0 || prudpv1";
                filter_size = 19;
            }
            filter_opt.option_length = filter_size;
            filter_size = ALIGN(filter_opt.option_length, 4);

            idb_usb.block_length = sizeof(idb_usb) + sizeof(ifname_usb_opt) + ifname_usb_size
                    + sizeof(filter_opt) + filter_size + 4 /* opt_endofopt */ + 4 /* block_length_2 */;

            offset = 0;
            memcpy(writeBuffer + offset, &idb_usb, sizeof(idb_usb));
            offset += sizeof(idb_usb);
            memcpy(writeBuffer + offset, &ifname_usb_opt, sizeof(ifname_usb_opt));
            offset += sizeof(ifname_usb_opt);
            memcpy(writeBuffer + offset, ifname_usb, ifname_usb_opt.option_length);
            offset += ifname_usb_size;
            memcpy(writeBuffer + offset, &filter_opt, sizeof(filter_opt));
            offset += sizeof(filter_opt);
            memcpy(writeBuffer + offset, filter, filter_opt.option_length);
            offset += filter_size;

            opt_endofopt = 0;
            memcpy(writeBuffer + offset, &opt_endofopt, sizeof(opt_endofopt));
            offset += sizeof(opt_endofopt);

            memcpy(writeBuffer + offset, &idb_usb.block_length, sizeof(idb_usb.block_length));
            offset += sizeof(idb_usb.block_length);

            FSA_WriteFile(fsaHandle, writeBuffer, 1, offset, fileHandle, 0);

            // write wl interface descriptor
            // write interface descriptors
            pcapng_idb_t idb_wl = { 0 };
            idb_wl.block_type = 1;
            idb_wl.link_type = LINKTYPE_ETHERNET;
            idb_wl.snap_length = _configuration.maxPacketSize;

            const char ifname_wl[] = "wl";
            pcapng_opt_t ifname_wl_opt = { 0 };
            ifname_wl_opt.option_type = 2;
            ifname_wl_opt.option_length = sizeof(ifname_wl) - 1;
            const int ifname_wl_size = ALIGN(sizeof(ifname_wl), 4);

            idb_wl.block_length = sizeof(idb_wl) + sizeof(ifname_wl_opt) + ifname_wl_size
                    + sizeof(filter_opt) + filter_size + 4 /* opt_endofopt */ + 4 /* block_length_2 */;

            offset = 0;
            memcpy(writeBuffer + offset, &idb_wl, sizeof(idb_wl));
            offset += sizeof(idb_wl);
            memcpy(writeBuffer + offset, &ifname_wl_opt, sizeof(ifname_wl_opt));
            offset += sizeof(ifname_wl_opt);
            memcpy(writeBuffer + offset, ifname_wl, ifname_wl_opt.option_length);
            offset += ifname_wl_size;
            memcpy(writeBuffer + offset, &filter_opt, sizeof(filter_opt));
            offset += sizeof(filter_opt);
            memcpy(writeBuffer + offset, filter, filter_opt.option_length);
            offset += filter_size;

            opt_endofopt = 0;
            memcpy(writeBuffer + offset, &opt_endofopt, sizeof(opt_endofopt));
            offset += sizeof(opt_endofopt);

            memcpy(writeBuffer + offset, &idb_wl.block_length, sizeof(idb_wl.block_length));
            offset += sizeof(idb_wl.block_length);

            FSA_WriteFile(fsaHandle, writeBuffer, 1, offset, fileHandle, 0);

            FSA_FlushFile(fsaHandle, fileHandle);
        }
        else {
            printf("Failed to mount sdcard\n");
            IOS_SignalSemaphore(semaphore);
            return;
        }
    }

    int interface_id;
    if (interface[0] == 'U' && interface[1] == 'S' && interface[2] == 'B') {
        interface_id = 0;
    }
    else { //if (interface[0] == 'w' && interface[1] == 'l') {
        interface_id = 1;
    }

    uint64_t time;
    IOS_GetAbsTime64(&time);

    pcapng_epb_t ebp_hdr = { 0 };
    ebp_hdr.block_type = 6;
    ebp_hdr.interface_id = interface_id;
    ebp_hdr.timestamp = time; // this is wrong, but I don't think I care
    ebp_hdr.captured_len = (size >= _configuration.maxPacketSize) ? _configuration.maxPacketSize : size;
    ebp_hdr.actual_len = size;

    const int data_len = ALIGN(ebp_hdr.captured_len, 4);
    ebp_hdr.block_length = sizeof(ebp_hdr) + data_len + 4 /* opt_endofopt */ + 4 /* block_length_2 */;

    int offset = 0;
    memcpy(writeBuffer + offset, &ebp_hdr, sizeof(ebp_hdr));
    offset += sizeof(ebp_hdr);
    memcpy(writeBuffer + offset, data, ebp_hdr.captured_len);
    offset += data_len;

    uint32_t opt_endofopt = 0;
    memcpy(writeBuffer + offset, &opt_endofopt, sizeof(opt_endofopt));
    offset += sizeof(opt_endofopt);

    memcpy(writeBuffer + offset, &ebp_hdr.block_length, sizeof(ebp_hdr.block_length));
    offset += sizeof(ebp_hdr.block_length);

    if (FSA_WriteFile(fsaHandle, writeBuffer, 1, offset, fileHandle, 0) < 0) {
        FSA_CloseFile(fsaHandle, fileHandle);
        fileHandle = -1;
    } else {
        FSA_FlushFile(fsaHandle, fileHandle);
    }

    IOS_SignalSemaphore(semaphore);
}

void netSuspendHook(void)
{
    IOS_Free(IOS_HEAP_SHARED, writeBuffer);
    writeBuffer = NULL;

    if (fsaHandle < 0) {
        return;
    }

    FSA_CloseFile(fsaHandle, fileHandle);
    IOS_Close(fsaHandle);

    fileHandle = -1;
    fsaHandle = -1;
}

typedef struct {
    uint32_t free;
    uint8_t* data;
    uint32_t max_data_size;
    uint32_t unk0;
    uint32_t packet_size;
    uint32_t unk1;
    InterfaceCtx_t* iface;
} Packet_t;

void queuePush(void* queue, Packet_t* packet);

void queuePushHook(void* queue, Packet_t* packet)
{
    uint8_t* data = packet->data + 2;
    // packet_size doesn't include the size of the frame header
    uint32_t size = packet->packet_size + 0xe;

    if (matchData(data)) {
        writeData(data, size, packet->iface->id);
    }

    queuePush(queue, packet);
}

int __UsbEthSendFrame(InterfaceCtx_t* ctx, uint8_t* data, uint32_t size);
int __WlSendFrame(InterfaceCtx_t* ctx, uint8_t* data, uint32_t size);

int sendFrameHook(InterfaceCtx_t* ctx, uint8_t* data, uint32_t size)
{
    // Only write packets which match to the pcap file
    if (matchData(data)) {
        writeData(data, size, ctx->id);
    }

    if (ctx->id[0] == 'U' && ctx->id[1] == 'S' && ctx->id[2] == 'B') {
        return __UsbEthSendFrame(ctx, data, size);
    }
    else if (ctx->id[0] == 'w' && ctx->id[1] == 'l') {
        return __WlSendFrame(ctx, data, size);
    }

    printf("sendFrameHook: unknown interface %s\n", ctx->id);
    return 0;
}
