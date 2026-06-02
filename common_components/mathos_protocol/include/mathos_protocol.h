#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define MATHOS_WIRE_MAGIC_0 0x4D /* 'M' */
#define MATHOS_WIRE_MAGIC_1 0x54 /* 'T' */

#define MATHOS_WIRE_VERSION 1

#define MATHOS_FRAME_TYPE_SECURE_RC 1

#define MATHOS_PAYLOAD_MAX_LEN 64
#define MATHOS_AUTH_TAG_LEN 16

    /*
        Frame layout:

        byte 0      magic 0 = 'M'
        byte 1      magic 1 = 'T'
        byte 2      version
        byte 3      frame_type
        byte 4-5    total frame length, little endian, including CRC
        byte 6-9    sequence, little endian
        byte 10-13  timestamp_ms, little endian
        byte 14     controller_id
        byte 15     link_id
        byte 16     payload_type
        byte 17     payload_len
        byte 18..   payload
        next 16     auth_tag
        last 2      crc16 over all previous bytes
    */

#define MATHOS_WIRE_HEADER_LEN 18
#define MATHOS_WIRE_CRC_LEN 2
#define MATHOS_WIRE_MAX_FRAME_LEN \
    (MATHOS_WIRE_HEADER_LEN + MATHOS_PAYLOAD_MAX_LEN + MATHOS_AUTH_TAG_LEN + MATHOS_WIRE_CRC_LEN)

    typedef enum
    {
        MATHOS_STATUS_OK = 0,
        MATHOS_STATUS_BAD_ARGUMENT,
        MATHOS_STATUS_BUFFER_TOO_SMALL,
        MATHOS_STATUS_BAD_MAGIC,
        MATHOS_STATUS_BAD_VERSION,
        MATHOS_STATUS_BAD_TYPE,
        MATHOS_STATUS_BAD_LENGTH,
        MATHOS_STATUS_BAD_CRC
    } mathos_status_t;

    typedef struct
    {
        uint32_t sequence;
        uint32_t timestamp_ms;

        uint8_t controller_id;
        uint8_t link_id;
        uint8_t payload_type;
        uint8_t payload_len;

        uint8_t payload[MATHOS_PAYLOAD_MAX_LEN];
        uint8_t auth_tag[MATHOS_AUTH_TAG_LEN];

    } mathos_secure_packet_t;

    const char *mathos_status_to_string(mathos_status_t status);

    uint16_t mathos_crc16_ccitt(const uint8_t *data, size_t len);

    mathos_status_t mathos_wire_encode(
        const mathos_secure_packet_t *packet,
        uint8_t *out_frame,
        size_t out_frame_max_len,
        size_t *out_frame_len);

    mathos_status_t mathos_wire_decode(
        const uint8_t *frame,
        size_t frame_len,
        mathos_secure_packet_t *out_packet);

#ifdef __cplusplus
}
#endif