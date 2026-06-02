#include "mathos_secure.h"

#include <string.h>

#include "mbedtls/chachapoly.h"

/*
    DEVELOPMENT KEY ONLY.

    Later this must come from maintenance mode / NVS / secure provisioning.
    Do not treat this hardcoded key as production security.
*/
static const uint8_t MATHOS_DEV_KEY[32] = {
    0x31, 0x4D, 0x61, 0x74, 0x68, 0x6F, 0x73, 0x2D,
    0x55, 0x41, 0x56, 0x2D, 0x44, 0x45, 0x56, 0x31,
    0x90, 0xA4, 0x11, 0x29, 0x7C, 0xE2, 0x5D, 0x83,
    0x19, 0xB6, 0xCC, 0x42, 0xD0, 0x6E, 0x51, 0xA8
};

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

    case MATHOS_SECURE_STATUS_CRYPTO_FAILED:
        return "CRYPTO_FAILED";

    case MATHOS_SECURE_STATUS_AUTH_FAILED:
        return "AUTH_FAILED";

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

mathos_secure_status_t mathos_secure_encrypt_packet(mathos_secure_packet_t *packet)
{
    if (packet == NULL)
    {
        return MATHOS_SECURE_STATUS_BAD_ARGUMENT;
    }

    if (packet->payload_len > MATHOS_PAYLOAD_MAX_LEN)
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

    int rc = mbedtls_chachapoly_setkey(&ctx, MATHOS_DEV_KEY);

    if (rc != 0)
    {
        mbedtls_chachapoly_free(&ctx);
        return MATHOS_SECURE_STATUS_CRYPTO_FAILED;
    }

    rc = mbedtls_chachapoly_encrypt_and_tag(
        &ctx,
        packet->payload_len,
        nonce,
        aad,
        sizeof(aad),
        packet->payload,
        encrypted,
        packet->auth_tag);

    mbedtls_chachapoly_free(&ctx);

    if (rc != 0)
    {
        return MATHOS_SECURE_STATUS_CRYPTO_FAILED;
    }

    memcpy(packet->payload, encrypted, packet->payload_len);

    return MATHOS_SECURE_STATUS_OK;
}

mathos_secure_status_t mathos_secure_decrypt_packet(mathos_secure_packet_t *packet)
{
    if (packet == NULL)
    {
        return MATHOS_SECURE_STATUS_BAD_ARGUMENT;
    }

    if (packet->payload_len > MATHOS_PAYLOAD_MAX_LEN)
    {
        return MATHOS_SECURE_STATUS_BAD_LENGTH;
    }

    uint8_t nonce[12];
    uint8_t aad[12];
    uint8_t decrypted[MATHOS_PAYLOAD_MAX_LEN];

    build_nonce(packet, nonce);
    build_aad(packet, aad);

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);

    int rc = mbedtls_chachapoly_setkey(&ctx, MATHOS_DEV_KEY);

    if (rc != 0)
    {
        mbedtls_chachapoly_free(&ctx);
        return MATHOS_SECURE_STATUS_CRYPTO_FAILED;
    }

    rc = mbedtls_chachapoly_auth_decrypt(
        &ctx,
        packet->payload_len,
        nonce,
        aad,
        sizeof(aad),
        packet->auth_tag,
        packet->payload,
        decrypted);

    mbedtls_chachapoly_free(&ctx);

    if (rc != 0)
    {
        return MATHOS_SECURE_STATUS_AUTH_FAILED;
    }

    memcpy(packet->payload, decrypted, packet->payload_len);

    return MATHOS_SECURE_STATUS_OK;
}