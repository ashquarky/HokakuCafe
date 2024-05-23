#pragma once

//todo
typedef void SSL;
typedef void SSL_SESSION;
typedef void ssl3_state_st;

int SSL_do_handshake_15702(SSL *s);
int SSL_do_handshake_15848(SSL *s);

static inline int SSL_do_handshake(SSL *s) {
    if (_system_version == 15848) {
        return SSL_do_handshake_15848(s);
    } else {
        return SSL_do_handshake_15702(s);
    }
}

int SSL_read_15702(SSL *s, void *buf, int num);
int SSL_read_15848(SSL *s, void *buf, int num);

static inline int SSL_read(SSL *s, void *buf, int num) {
    if (_system_version == 15848) {
        return SSL_read_15848(s, buf, num);
    } else {
        return SSL_read_15702(s, buf, num);
    }
}

int SSL_write_15702(SSL *s, void *buf, int num);
int SSL_write_15848(SSL *s, void *buf, int num);

static inline int SSL_write(SSL *s, void *buf, int num) {
    if (_system_version == 15848) {
        return SSL_write_15848(s, buf, num);
    } else {
        return SSL_write_15702(s, buf, num);
    }
}