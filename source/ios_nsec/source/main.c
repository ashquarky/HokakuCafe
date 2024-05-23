#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "ios.h"
#include "fsa.h"
#include "../../common/interface.h"
#include "../../common/config.h"

int semaphore = -1;
int fsa_handle = -1;
int file_handle = -1;
char *line_buffer = NULL;
#define LINE_BUFFER_SIZE 1024

extern const int _system_version;
#include "openssl.h"

static int open_file() {
    if (semaphore < 0) {
        semaphore = IOS_CreateSemaphore(1, 1);
        if (semaphore < 0) {
            printf("Failed to create semaphore\n");
        }
    }

    IOS_WaitSemaphore(semaphore, 0);

    if (fsa_handle < 0) {
        fsa_handle = IOS_Open("/dev/fsa", 0);
        if (fsa_handle < 0) {
            printf("Failed to open FSA\n");
            IOS_SignalSemaphore(semaphore);
            return -1;
        }
    }

    if (!line_buffer) {
        line_buffer = IOS_AllocAligned(0xcaff, LINE_BUFFER_SIZE, 0x40);
        if (!line_buffer) {
            printf("Failed to allocate write buffer\n");
            IOS_SignalSemaphore(semaphore);
            return -1;
        }
    }

    if (file_handle < 0) {
        int res = FSA_Mount(fsa_handle, "/dev/sdcard01", "/vol/storage_ssldump", 2, NULL, 0);
        if (res >= 0) {
            FSA_MakeDir(fsa_handle, "/vol/storage_ssldump/HokakuCafe", 0x600);

            CalendarTime_t ctime;
            IOS_GetAbsTimeCalendar(&ctime);

            char name[512];
            snprintf(name, sizeof(name), "/vol/storage_ssldump/HokakuCafe/%04ld-%02ld-%02ld_%02ld-%02ld-%02ld.ssl",
                     ctime.year, ctime.month, ctime.day, ctime.hour, ctime.minute, ctime.second);

            res = FSA_OpenFile(fsa_handle, name, "w", &file_handle);
            if (res < 0) {
                printf("Failed to open file\n");
                FSA_Unmount(fsa_handle, "/vol/storage_ssldump", 2);
                file_handle = -1;
                IOS_SignalSemaphore(semaphore);
                return -1;
            }

            const char header[] = "# HokakuCafe SSL keys\n";
            memcpy(line_buffer, header, sizeof(header));

            FSA_WriteFile(fsa_handle, line_buffer, 1, sizeof(header)-1, file_handle, 0);
            FSA_FlushFile(fsa_handle, file_handle);
        } else {
            printf("Failed to mount sdcard\n");
            IOS_SignalSemaphore(semaphore);
            return -1;
        }
    }

    return file_handle;
}

#define CLIENT_RANDOM_LENGTH 32

static const uint8_t *get_client_random(const SSL *ssl) {
    const ssl3_state_st *s3 = *(ssl3_state_st **) (ssl + 0x58);
    const uint8_t *client_random = s3 + 0xc0;

    return client_random;
}

static bool save_ssl_keys(const SSL *ssl) {
    const SSL_SESSION *session = *(SSL_SESSION **) (ssl + 0xc0);
    if (!session) {
        printf("[HokakuCafeSSL] No session yet, won't save keys\n");
        return false;
    }
    const int master_key_length = *(int *) (session + 0x10);
    const uint8_t *master_key = session + 0x14;

    if (master_key_length <= 0 || master_key_length > 48) {
        printf("[HokakuCafeSSL] session has no keys (%d)...\n", master_key_length);
        return false;
    }

    const uint8_t *client_random = get_client_random(ssl);

    int fd = open_file();
    if (fd < 0) return false;

    // bounds checks omitted for brevity ;)
    int offset = 0;
    offset += snprintf(&line_buffer[offset], LINE_BUFFER_SIZE - offset, "CLIENT_RANDOM ");

    for (int i = 0; i < CLIENT_RANDOM_LENGTH; i++) {
        offset += snprintf(&line_buffer[offset], LINE_BUFFER_SIZE - offset, "%02x", client_random[i]);
    }

    line_buffer[offset++] = ' ';
    //line_buffer[offset++] = '\0';

    for (int i = 0; i < master_key_length; i++) {
        offset += snprintf(&line_buffer[offset], LINE_BUFFER_SIZE - offset, "%02x", master_key[i]);
    }
    printf("[HokakuCafeSSL] %s\n", line_buffer);

    line_buffer[offset++] = '\n';
    line_buffer[offset++] = '\0';

    if (FSA_WriteFile(fsa_handle, line_buffer, 1, offset-1, fd, 0) < 0) {
        FSA_CloseFile(fsa_handle, file_handle);
        file_handle = -1;
    } else {
        FSA_FlushFile(fsa_handle, file_handle);
    }

    IOS_SignalSemaphore(semaphore);

    return true;
}

int SSL_do_handshake_hook(SSL *ssl) {
    int result = SSL_do_handshake(ssl);
    save_ssl_keys(ssl);
    return result;
}

uint8_t last_seen_client_random[CLIENT_RANDOM_LENGTH];
int SSL_read_hook(SSL *s, void *buf, int num) {
    const int result = SSL_read(s, buf, num);

    // see if the random changed (we re-negotiated)
    if (memcmp(last_seen_client_random, get_client_random(s), sizeof(last_seen_client_random)) != 0) {
        if (save_ssl_keys(s)) {
            // only cache this if the keys were actually saved correctly
            memcpy(last_seen_client_random, get_client_random(s), sizeof(last_seen_client_random));
        }
    }

    return result;
}

int SSL_write_hook(SSL *s, void *buf, int num) {
    const int result = SSL_write(s, buf, num);

    // see if the random changed (we re-negotiated)
    if (memcmp(last_seen_client_random, get_client_random(s), sizeof(last_seen_client_random)) != 0) {
        if (save_ssl_keys(s)) {
            // only cache this if the keys were actually saved correctly
            memcpy(last_seen_client_random, get_client_random(s), sizeof(last_seen_client_random));
        }
    }

    return result;
}
