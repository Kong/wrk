// Copyright (C) 2013 - Will Glozer.  All rights reserved.

#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "ssl.h"

SSL_CTX *ssl_init(const char *ca, const char *cert, const char *key) {
    SSL_CTX *ctx = NULL;

    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    if ((ctx = SSL_CTX_new(SSLv23_client_method()))) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_verify_depth(ctx, 0);
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT);

        if (ca) {
            if (SSL_CTX_load_verify_locations(ctx, ca, NULL) < 1) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        }
        if (cert) {
            if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
        }
        if (key) {
            if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(EXIT_FAILURE);
            }
            if (SSL_CTX_check_private_key(ctx) == 0) {
                fprintf(stderr, "Private key does not match the certificate public key\n");
                exit(EXIT_FAILURE);
            }
        }
    }

    return ctx;
}

status ssl_connect(connection *c, char *host) {
    int r;
    SSL_set_fd(c->ssl, c->fd);
    SSL_set_tlsext_host_name(c->ssl, host);
    if ((r = SSL_connect(c->ssl)) != 1) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    return OK;
}

status ssl_close(connection *c) {
    SSL_shutdown(c->ssl);
    SSL_clear(c->ssl);
    return OK;
}

status ssl_read(connection *c, size_t *n) {
    int r;
    if ((r = SSL_read(c->ssl, c->buf, sizeof(c->buf))) <= 0) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    *n = (size_t) r;
    return OK;
}

status ssl_write(connection *c, char *buf, size_t len, size_t *n) {
    int r;
    if ((r = SSL_write(c->ssl, buf, len)) <= 0) {
        switch (SSL_get_error(c->ssl, r)) {
            case SSL_ERROR_WANT_READ:  return RETRY;
            case SSL_ERROR_WANT_WRITE: return RETRY;
            default:                   return ERROR;
        }
    }
    *n = (size_t) r;
    return OK;
}

size_t ssl_readable(connection *c) {
    return SSL_pending(c->ssl);
}
