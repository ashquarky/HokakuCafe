#pragma once

//todo
typedef void SSL;
typedef void SSL_SESSION;
typedef void ssl3_state_st;

int SSL_do_handshake(SSL *s);

int SSL_read(SSL *s, void *buf, int num);

int SSL_write(SSL *s, void *buf, int num);