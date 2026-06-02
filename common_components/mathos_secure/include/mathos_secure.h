#pragma once

#include <stdint.h>
#include "mathos_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum
{
    MATHOS_SECURE_STATUS_OK = 0,
    MATHOS_SECURE_STATUS_BAD_ARGUMENT,
    MATHOS_SECURE_STATUS_BAD_LENGTH,
    MATHOS_SECURE_STATUS_CRYPTO_FAILED,
    MATHOS_SECURE_STATUS_AUTH_FAILED
} mathos_secure_status_t;

const char *mathos_secure_status_to_string(mathos_secure_status_t status);

/*
    Encrypts packet->payload in-place.
    Writes real 16-byte Poly1305 authentication tag into packet->auth_tag.
*/
mathos_secure_status_t mathos_secure_encrypt_packet(mathos_secure_packet_t *packet);

/*
    Verifies packet->auth_tag.
    If valid, decrypts packet->payload in-place.
    If invalid, payload must be discarded.
*/
mathos_secure_status_t mathos_secure_decrypt_packet(mathos_secure_packet_t *packet);

#ifdef __cplusplus
}
#endif