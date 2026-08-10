#pragma once

#include <stdint.h>
#include "mathos_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MATHOS_SECURE_KEY_LEN 32U

typedef enum
{
    MATHOS_SECURE_STATUS_OK = 0,
    MATHOS_SECURE_STATUS_BAD_ARGUMENT,
    MATHOS_SECURE_STATUS_BAD_LENGTH,
    MATHOS_SECURE_STATUS_KEY_NOT_SET,
    MATHOS_SECURE_STATUS_CRYPTO_FAILED,
    MATHOS_SECURE_STATUS_AUTH_FAILED
} mathos_secure_status_t;
const char *mathos_secure_status_to_string(mathos_secure_status_t status);

/*
    Encrypts packet->payload in-place.
    Writes real 16-byte Poly1305 authentication tag into packet->auth_tag.
*/
/*
    Installs the 256-bit operational root key.

    This must be called during boot before operational
    control/status/telemetry tasks are started.
*/
mathos_secure_status_t mathos_secure_set_key(
    const uint8_t *key,
    uint32_t key_len);

/*
    Removes the currently installed operational key.
*/
void mathos_secure_clear_key(void);

/*
    Returns nonzero when an operational key is installed.
*/
int mathos_secure_key_is_set(void);
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