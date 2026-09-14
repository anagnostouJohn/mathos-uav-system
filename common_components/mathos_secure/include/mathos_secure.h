#pragma once

#include <stdint.h>
#include "mathos_protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MATHOS_SECURE_KEY_LEN 32U

typedef enum
{
    MATHOS_SECURE_ROLE_RC = 1,
    MATHOS_SECURE_ROLE_GATEWAY = 2
    
} mathos_secure_role_t;

typedef enum
{
    MATHOS_SECURE_STATUS_OK = 0,
    MATHOS_SECURE_STATUS_BAD_ARGUMENT,
    MATHOS_SECURE_STATUS_BAD_LENGTH,
    MATHOS_SECURE_STATUS_KEY_NOT_SET,
    MATHOS_SECURE_STATUS_CRYPTO_FAILED,
    MATHOS_SECURE_STATUS_AUTH_FAILED,
    MATHOS_SECURE_STATUS_STORAGE_FAILED,
    MATHOS_SECURE_STATUS_SESSION_NOT_SET
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
    Reserve a persistent nonzero transmit session ID.

    The value is incremented and committed to NVS before
    being returned to the caller.

    partition_name == NULL uses the default NVS partition.

    A skipped value after power loss is harmless.
    Reusing an old value is not.
*/
mathos_secure_status_t mathos_secure_reserve_session_id(
    const char *partition_name,
    uint32_t *session_id_out);


/*
    Derive independent operational keys for:

        RC -> Gateway
        Gateway -> RC

    Both devices use the same Pair Key and the same pair
    of persistent session IDs.

    The local role decides which derived key is TX and
    which is RX.
*/
mathos_secure_status_t mathos_secure_derive_session_keys(
    uint32_t rc_session_id,
    uint32_t gateway_session_id,
    mathos_secure_role_t local_role);

void mathos_secure_clear_session_keys(void);

int mathos_secure_session_keys_are_set(void);

/*
    Operational traffic uses the derived directional
    session keys.

    Pairing/session-establishment traffic will continue
    to use the persistent Pair Key separately.
*/
mathos_secure_status_t mathos_secure_encrypt_session_packet(
    mathos_secure_packet_t *packet);

mathos_secure_status_t mathos_secure_decrypt_session_packet(
    mathos_secure_packet_t *packet);

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