#include "mathos_secure.h"

#include <string.h>

#include "nvs.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/md.h"

/*
    Persistent operational Pair Key installed at boot.

    There is deliberately NO fallback development key.

    No installed key means no operational encryption or
    decryption authority.

    Direction-specific session keys are derived from this
    persistent Pair Key after session establishment.
*/
static uint8_t mathos_runtime_key[MATHOS_SECURE_KEY_LEN];
static int mathos_runtime_key_set = 0;

/*
    Direction-specific operational session keys.

    TX is used for packets sent by this device.
    RX is used for packets received by this device.
*/
static uint8_t mathos_session_tx_key[MATHOS_SECURE_KEY_LEN];
static uint8_t mathos_session_rx_key[MATHOS_SECURE_KEY_LEN];

static int mathos_session_keys_set = 0;

/*
    Persistent transmit-session counter storage.
*/
#define MATHOS_SECURE_SESSION_NAMESPACE "mathos_sec"
#define MATHOS_SECURE_SESSION_KEY "tx_session"

mathos_secure_status_t mathos_secure_set_key(
    const uint8_t *key,
    uint32_t key_len)
{
    if (key == NULL)
    {
        return MATHOS_SECURE_STATUS_BAD_ARGUMENT;
    }

    if (key_len != MATHOS_SECURE_KEY_LEN)
    {
        return MATHOS_SECURE_STATUS_BAD_LENGTH;
    }
    mathos_secure_clear_session_keys();
    /*
        Clear any previous key before installing
        the new validated key.
    */
    mbedtls_platform_zeroize(
        mathos_runtime_key,
        sizeof(mathos_runtime_key));

    memcpy(
        mathos_runtime_key,
        key,
        MATHOS_SECURE_KEY_LEN);

    mathos_runtime_key_set = 1;

    return MATHOS_SECURE_STATUS_OK;
}

void mathos_secure_clear_key(void)
{
    mathos_secure_clear_session_keys();
    mbedtls_platform_zeroize(
        mathos_runtime_key,
        sizeof(mathos_runtime_key));

    mathos_runtime_key_set = 0;
}

int mathos_secure_key_is_set(void)
{
    return mathos_runtime_key_set;
}
void mathos_secure_clear_session_keys(void)
{
    mbedtls_platform_zeroize(
        mathos_session_tx_key,
        sizeof(mathos_session_tx_key));

    mbedtls_platform_zeroize(
        mathos_session_rx_key,
        sizeof(mathos_session_rx_key));

    mathos_session_keys_set = 0;
}
static void mathos_secure_put_u32_le(
    uint8_t *buffer,
    size_t *index,
    uint32_t value)
{
    buffer[(*index)++] =
        (uint8_t)((value >> 0) & 0xFFU);

    buffer[(*index)++] =
        (uint8_t)((value >> 8) & 0xFFU);

    buffer[(*index)++] =
        (uint8_t)((value >> 16) & 0xFFU);

    buffer[(*index)++] =
        (uint8_t)((value >> 24) & 0xFFU);
}

static mathos_secure_status_t
mathos_secure_derive_direction_key(
    uint32_t rc_session_id,
    uint32_t gateway_session_id,
    uint8_t direction,
    uint8_t output_key[MATHOS_SECURE_KEY_LEN])
{
    static const uint8_t label[] =
        "MATHOS-OP-V1";

    uint8_t info[(sizeof(label) - 1U) +
                 sizeof(uint32_t) +
                 sizeof(uint32_t) +
                 1U];

    size_t index = 0;

    memcpy(
        &info[index],
        label,
        sizeof(label) - 1U);

    index += sizeof(label) - 1U;

    mathos_secure_put_u32_le(
        info,
        &index,
        rc_session_id);

    mathos_secure_put_u32_le(
        info,
        &index,
        gateway_session_id);

    info[index++] = direction;

    const mbedtls_md_info_t *sha256_info =
        mbedtls_md_info_from_type(
            MBEDTLS_MD_SHA256);

    if (sha256_info == NULL)
    {
        return MATHOS_SECURE_STATUS_CRYPTO_FAILED;
    }

    int result =
        mbedtls_md_hmac(
            sha256_info,
            mathos_runtime_key,
            MATHOS_SECURE_KEY_LEN,
            info,
            sizeof(info),
            output_key);

    mbedtls_platform_zeroize(
        info,
        sizeof(info));

    if (result != 0)
    {
        return MATHOS_SECURE_STATUS_CRYPTO_FAILED;
    }

    return MATHOS_SECURE_STATUS_OK;
}
mathos_secure_status_t mathos_secure_derive_session_keys(
    uint32_t rc_session_id,
    uint32_t gateway_session_id,
    mathos_secure_role_t local_role)
{
    /*
    Fail closed before attempting to establish a new
    operational session.

    Any derivation attempt invalidates previously derived
    directional session keys. A validation or cryptographic
    failure must never leave old session authority active.
*/
    mathos_secure_clear_session_keys();
    if (!mathos_runtime_key_set)
    {
        return MATHOS_SECURE_STATUS_KEY_NOT_SET;
    }

    if (rc_session_id == 0 ||
        gateway_session_id == 0)
    {
        return MATHOS_SECURE_STATUS_BAD_ARGUMENT;
    }

    if (local_role != MATHOS_SECURE_ROLE_RC &&
        local_role != MATHOS_SECURE_ROLE_GATEWAY)
    {
        return MATHOS_SECURE_STATUS_BAD_ARGUMENT;
    }

    uint8_t rc_to_gateway[MATHOS_SECURE_KEY_LEN] = {0};
    uint8_t gateway_to_rc[MATHOS_SECURE_KEY_LEN] = {0};

    mathos_secure_status_t status =
        mathos_secure_derive_direction_key(
            rc_session_id,
            gateway_session_id,
            1U,
            rc_to_gateway);

    if (status != MATHOS_SECURE_STATUS_OK)
    {
        goto cleanup;
    }

    status =
        mathos_secure_derive_direction_key(
            rc_session_id,
            gateway_session_id,
            2U,
            gateway_to_rc);

    if (status != MATHOS_SECURE_STATUS_OK)
    {
        goto cleanup;
    }

    if (local_role == MATHOS_SECURE_ROLE_RC)
    {
        memcpy(
            mathos_session_tx_key,
            rc_to_gateway,
            MATHOS_SECURE_KEY_LEN);

        memcpy(
            mathos_session_rx_key,
            gateway_to_rc,
            MATHOS_SECURE_KEY_LEN);
    }
    else
    {
        memcpy(
            mathos_session_tx_key,
            gateway_to_rc,
            MATHOS_SECURE_KEY_LEN);

        memcpy(
            mathos_session_rx_key,
            rc_to_gateway,
            MATHOS_SECURE_KEY_LEN);
    }

    mathos_session_keys_set = 1;

cleanup:

    mbedtls_platform_zeroize(
        rc_to_gateway,
        sizeof(rc_to_gateway));

    mbedtls_platform_zeroize(
        gateway_to_rc,
        sizeof(gateway_to_rc));

    return status;
}
int mathos_secure_session_keys_are_set(void)
{
    return mathos_session_keys_set;
}
mathos_secure_status_t mathos_secure_reserve_session_id(
    const char *partition_name,
    uint32_t *session_id_out)
{
    if (session_id_out == NULL)
    {
        return MATHOS_SECURE_STATUS_BAD_ARGUMENT;
    }

    *session_id_out = 0;

    nvs_handle_t handle;

    esp_err_t err;

    if (partition_name == NULL ||
        partition_name[0] == '\0')
    {
        err = nvs_open(
            MATHOS_SECURE_SESSION_NAMESPACE,
            NVS_READWRITE,
            &handle);
    }
    else
    {
        err = nvs_open_from_partition(
            partition_name,
            MATHOS_SECURE_SESSION_NAMESPACE,
            NVS_READWRITE,
            &handle);
    }

    if (err != ESP_OK)
    {
        return MATHOS_SECURE_STATUS_STORAGE_FAILED;
    }

    uint32_t stored_session = 0;

    err = nvs_get_u32(
        handle,
        MATHOS_SECURE_SESSION_KEY,
        &stored_session);

    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        stored_session = 0;
    }
    else if (err != ESP_OK)
    {
        nvs_close(handle);
        return MATHOS_SECURE_STATUS_STORAGE_FAILED;
    }

    /*
        Never wrap back to zero while the same persistent
        operational key may still exist.
    */
    if (stored_session == UINT32_MAX)
    {
        nvs_close(handle);
        return MATHOS_SECURE_STATUS_STORAGE_FAILED;
    }

    uint32_t reserved_session =
        stored_session + 1U;

    err = nvs_set_u32(
        handle,
        MATHOS_SECURE_SESSION_KEY,
        reserved_session);

    if (err == ESP_OK)
    {
        /*
            Commit BEFORE publishing the session ID.

            If power disappears after this commit but before
            transmission begins, one value is merely skipped.
        */
        err = nvs_commit(handle);
    }

    nvs_close(handle);

    if (err != ESP_OK)
    {
        return MATHOS_SECURE_STATUS_STORAGE_FAILED;
    }

    *session_id_out =
        reserved_session;

    return MATHOS_SECURE_STATUS_OK;
}

static void put_u32_le(uint8_t *buffer, int *index, uint32_t value)
{
    buffer[(*index)++] = (uint8_t)((value >> 0) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 8) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 16) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 24) & 0xFF);
}

const char *mathos_secure_status_to_string(mathos_secure_status_t status)
{
    switch (status)
    {
    case MATHOS_SECURE_STATUS_OK:
        return "OK";

    case MATHOS_SECURE_STATUS_BAD_ARGUMENT:
        return "BAD_ARGUMENT";

    case MATHOS_SECURE_STATUS_BAD_LENGTH:
        return "BAD_LENGTH";

    case MATHOS_SECURE_STATUS_KEY_NOT_SET:
        return "KEY_NOT_SET";

    case MATHOS_SECURE_STATUS_CRYPTO_FAILED:
        return "CRYPTO_FAILED";

    case MATHOS_SECURE_STATUS_AUTH_FAILED:
        return "AUTH_FAILED";

    case MATHOS_SECURE_STATUS_STORAGE_FAILED:
        return "STORAGE_FAILED";

    case MATHOS_SECURE_STATUS_SESSION_NOT_SET:
        return "SESSION_NOT_SET";

    default:
        return "UNKNOWN";
    }
}

/*
    Nonce layout, 12 bytes:

    0..3   session_id currently stored in packet->timestamp_ms
    4..7   sequence
    8      controller_id
    9      link_id
    10     payload_type
    11     constant domain byte

    Rule:
    same key + same nonce must never repeat.

    For this engineering test, timestamp_ms is used as a boot session ID.
    Later we should rename it properly to session_id and make it 64-bit.
*/
static void build_nonce(const mathos_secure_packet_t *packet, uint8_t nonce[12])
{
    int i = 0;

    put_u32_le(nonce, &i, packet->timestamp_ms);
    put_u32_le(nonce, &i, packet->sequence);

    nonce[i++] = packet->controller_id;
    nonce[i++] = packet->link_id;
    nonce[i++] = packet->payload_type;
    nonce[i++] = 0xA1;
}

/*
    AAD = authenticated but not encrypted header fields.

    If an attacker changes any of these fields, decrypt fails.
*/
static void build_aad(const mathos_secure_packet_t *packet, uint8_t aad[12])
{
    int i = 0;

    put_u32_le(aad, &i, packet->sequence);
    put_u32_le(aad, &i, packet->timestamp_ms);

    aad[i++] = packet->controller_id;
    aad[i++] = packet->link_id;
    aad[i++] = packet->payload_type;
    aad[i++] = packet->payload_len;
}
static mathos_secure_status_t
mathos_secure_encrypt_with_key(
    mathos_secure_packet_t *packet,
    const uint8_t key[MATHOS_SECURE_KEY_LEN])
{
    if (packet == NULL ||
        key == NULL)
    {
        return MATHOS_SECURE_STATUS_BAD_ARGUMENT;
    }

    if (packet->payload_len >
        MATHOS_PAYLOAD_MAX_LEN)
    {
        return MATHOS_SECURE_STATUS_BAD_LENGTH;
    }

    uint8_t nonce[12];
    uint8_t aad[12];
    uint8_t encrypted[MATHOS_PAYLOAD_MAX_LEN];

    build_nonce(packet, nonce);
    build_aad(packet, aad);

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);

    int rc =
        mbedtls_chachapoly_setkey(
            &ctx,
            key);

    if (rc == 0)
    {
        rc =
            mbedtls_chachapoly_encrypt_and_tag(
                &ctx,
                packet->payload_len,
                nonce,
                aad,
                sizeof(aad),
                packet->payload,
                encrypted,
                packet->auth_tag);
    }

    mbedtls_chachapoly_free(&ctx);

    if (rc != 0)
    {
        return MATHOS_SECURE_STATUS_CRYPTO_FAILED;
    }

    memcpy(
        packet->payload,
        encrypted,
        packet->payload_len);

    mbedtls_platform_zeroize(
        encrypted,
        sizeof(encrypted));

    return MATHOS_SECURE_STATUS_OK;
}
mathos_secure_status_t mathos_secure_encrypt_packet(mathos_secure_packet_t *packet)

{
    if (!mathos_runtime_key_set)
    {
        return MATHOS_SECURE_STATUS_KEY_NOT_SET;
    }

    return mathos_secure_encrypt_with_key(
        packet,
        mathos_runtime_key);
}
mathos_secure_status_t
mathos_secure_encrypt_session_packet(
    mathos_secure_packet_t *packet)
{
    if (!mathos_session_keys_set)
    {
        return MATHOS_SECURE_STATUS_SESSION_NOT_SET;
    }

    return mathos_secure_encrypt_with_key(
        packet,
        mathos_session_tx_key);
}

static mathos_secure_status_t
mathos_secure_decrypt_with_key(
    mathos_secure_packet_t *packet,
    const uint8_t key[MATHOS_SECURE_KEY_LEN])
{
    if (packet == NULL ||
        key == NULL)
    {
        return MATHOS_SECURE_STATUS_BAD_ARGUMENT;
    }

    if (packet->payload_len >
        MATHOS_PAYLOAD_MAX_LEN)
    {
        return MATHOS_SECURE_STATUS_BAD_LENGTH;
    }

    uint8_t nonce[12];
    uint8_t aad[12];
    uint8_t decrypted[MATHOS_PAYLOAD_MAX_LEN];

    memset(
        decrypted,
        0,
        sizeof(decrypted));

    build_nonce(
        packet,
        nonce);

    build_aad(
        packet,
        aad);

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);

    int rc =
        mbedtls_chachapoly_setkey(
            &ctx,
            key);

    if (rc == 0)
    {
        rc =
            mbedtls_chachapoly_auth_decrypt(
                &ctx,
                packet->payload_len,
                nonce,
                aad,
                sizeof(aad),
                packet->auth_tag,
                packet->payload,
                decrypted);
    }

    mbedtls_chachapoly_free(&ctx);

    if (rc != 0)
    {
        mbedtls_platform_zeroize(
            decrypted,
            sizeof(decrypted));

        return MATHOS_SECURE_STATUS_AUTH_FAILED;
    }

    memcpy(
        packet->payload,
        decrypted,
        packet->payload_len);

    mbedtls_platform_zeroize(
        decrypted,
        sizeof(decrypted));

    return MATHOS_SECURE_STATUS_OK;
}

mathos_secure_status_t
mathos_secure_decrypt_packet(
    mathos_secure_packet_t *packet)
{
    if (!mathos_runtime_key_set)
    {
        return MATHOS_SECURE_STATUS_KEY_NOT_SET;
    }

    return mathos_secure_decrypt_with_key(
        packet,
        mathos_runtime_key);
}

mathos_secure_status_t
mathos_secure_decrypt_session_packet(
    mathos_secure_packet_t *packet)
{
    if (!mathos_session_keys_set)
    {
        return MATHOS_SECURE_STATUS_SESSION_NOT_SET;
    }

    return mathos_secure_decrypt_with_key(
        packet,
        mathos_session_rx_key);
}