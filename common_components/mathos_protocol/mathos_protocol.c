#include "mathos_protocol.h"

#include <string.h>

static void mathos_put_u16_le(uint8_t *buffer, size_t *index, uint16_t value)
{
    buffer[(*index)++] = (uint8_t)((value >> 0) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 8) & 0xFF);
}

static void mathos_put_u32_le(uint8_t *buffer, size_t *index, uint32_t value)
{
    buffer[(*index)++] = (uint8_t)((value >> 0) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 8) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 16) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 24) & 0xFF);
}

static uint16_t mathos_get_u16_le(const uint8_t *buffer)
{
    return ((uint16_t)buffer[0] << 0) |
           ((uint16_t)buffer[1] << 8);
}

static uint32_t mathos_get_u32_le(const uint8_t *buffer)
{
    return ((uint32_t)buffer[0] << 0) |
           ((uint32_t)buffer[1] << 8) |
           ((uint32_t)buffer[2] << 16) |
           ((uint32_t)buffer[3] << 24);
}

const char *mathos_status_to_string(mathos_status_t status)
{
    switch (status)
    {
    case MATHOS_STATUS_OK:
        return "OK";

    case MATHOS_STATUS_BAD_ARGUMENT:
        return "BAD_ARGUMENT";

    case MATHOS_STATUS_BUFFER_TOO_SMALL:
        return "BUFFER_TOO_SMALL";

    case MATHOS_STATUS_BAD_MAGIC:
        return "BAD_MAGIC";

    case MATHOS_STATUS_BAD_VERSION:
        return "BAD_VERSION";

    case MATHOS_STATUS_BAD_TYPE:
        return "BAD_TYPE";

    case MATHOS_STATUS_BAD_LENGTH:
        return "BAD_LENGTH";

    case MATHOS_STATUS_BAD_CRC:
        return "BAD_CRC";

    default:
        return "UNKNOWN";
    }
}

/*
    CRC16-CCITT-FALSE
    poly: 0x1021
    init: 0xFFFF
*/
uint16_t mathos_crc16_ccitt(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;

    if (data == NULL && len > 0)
    {
        return 0;
    }

    for (size_t i = 0; i < len; i++)
    {
        crc ^= ((uint16_t)data[i] << 8);

        for (int bit = 0; bit < 8; bit++)
        {
            if (crc & 0x8000)
            {
                crc = (uint16_t)((crc << 1) ^ 0x1021);
            }
            else
            {
                crc = (uint16_t)(crc << 1);
            }
        }
    }

    return crc;
}

mathos_status_t mathos_wire_encode(
    const mathos_secure_packet_t *packet,
    uint8_t *out_frame,
    size_t out_frame_max_len,
    size_t *out_frame_len)
{
    if (packet == NULL || out_frame == NULL || out_frame_len == NULL)
    {
        return MATHOS_STATUS_BAD_ARGUMENT;
    }

    if (packet->payload_len > MATHOS_PAYLOAD_MAX_LEN)
    {
        return MATHOS_STATUS_BAD_LENGTH;
    }

    size_t frame_len =
        MATHOS_WIRE_HEADER_LEN +
        packet->payload_len +
        MATHOS_AUTH_TAG_LEN +
        MATHOS_WIRE_CRC_LEN;

    if (frame_len > out_frame_max_len)
    {
        return MATHOS_STATUS_BUFFER_TOO_SMALL;
    }

    size_t i = 0;

    out_frame[i++] = MATHOS_WIRE_MAGIC_0;
    out_frame[i++] = MATHOS_WIRE_MAGIC_1;
    out_frame[i++] = MATHOS_WIRE_VERSION;
    out_frame[i++] = MATHOS_FRAME_TYPE_SECURE_RC;

    mathos_put_u16_le(out_frame, &i, (uint16_t)frame_len);

    mathos_put_u32_le(out_frame, &i, packet->sequence);
    mathos_put_u32_le(out_frame, &i, packet->timestamp_ms);

    out_frame[i++] = packet->controller_id;
    out_frame[i++] = packet->link_id;
    out_frame[i++] = packet->payload_type;
    out_frame[i++] = packet->payload_len;

    if (packet->payload_len > 0)
    {
        memcpy(&out_frame[i], packet->payload, packet->payload_len);
        i += packet->payload_len;
    }

    memcpy(&out_frame[i], packet->auth_tag, MATHOS_AUTH_TAG_LEN);
    i += MATHOS_AUTH_TAG_LEN;

    uint16_t crc = mathos_crc16_ccitt(out_frame, i);

    mathos_put_u16_le(out_frame, &i, crc);

    if (i != frame_len)
    {
        return MATHOS_STATUS_BAD_LENGTH;
    }

    *out_frame_len = frame_len;

    return MATHOS_STATUS_OK;
}

mathos_status_t mathos_wire_decode(
    const uint8_t *frame,
    size_t frame_len,
    mathos_secure_packet_t *out_packet)
{
    if (frame == NULL || out_packet == NULL)
    {
        return MATHOS_STATUS_BAD_ARGUMENT;
    }

    if (frame_len < (MATHOS_WIRE_HEADER_LEN + MATHOS_AUTH_TAG_LEN + MATHOS_WIRE_CRC_LEN))
    {
        return MATHOS_STATUS_BAD_LENGTH;
    }

    if (frame[0] != MATHOS_WIRE_MAGIC_0 || frame[1] != MATHOS_WIRE_MAGIC_1)
    {
        return MATHOS_STATUS_BAD_MAGIC;
    }

    if (frame[2] != MATHOS_WIRE_VERSION)
    {
        return MATHOS_STATUS_BAD_VERSION;
    }

    if (frame[3] != MATHOS_FRAME_TYPE_SECURE_RC)
    {
        return MATHOS_STATUS_BAD_TYPE;
    }

    uint16_t declared_len = mathos_get_u16_le(&frame[4]);

    if (declared_len != frame_len)
    {
        return MATHOS_STATUS_BAD_LENGTH;
    }

    uint8_t payload_len = frame[17];

    if (payload_len > MATHOS_PAYLOAD_MAX_LEN)
    {
        return MATHOS_STATUS_BAD_LENGTH;
    }

    size_t expected_len =
        MATHOS_WIRE_HEADER_LEN +
        payload_len +
        MATHOS_AUTH_TAG_LEN +
        MATHOS_WIRE_CRC_LEN;

    if (expected_len != frame_len)
    {
        return MATHOS_STATUS_BAD_LENGTH;
    }

    uint16_t received_crc = mathos_get_u16_le(&frame[frame_len - 2]);
    uint16_t calculated_crc = mathos_crc16_ccitt(frame, frame_len - 2);

    if (received_crc != calculated_crc)
    {
        return MATHOS_STATUS_BAD_CRC;
    }

    memset(out_packet, 0, sizeof(mathos_secure_packet_t));

    out_packet->sequence = mathos_get_u32_le(&frame[6]);
    out_packet->timestamp_ms = mathos_get_u32_le(&frame[10]);

    out_packet->controller_id = frame[14];
    out_packet->link_id = frame[15];
    out_packet->payload_type = frame[16];
    out_packet->payload_len = payload_len;

    if (payload_len > 0)
    {
        memcpy(out_packet->payload, &frame[18], payload_len);
    }

    memcpy(out_packet->auth_tag, &frame[18 + payload_len], MATHOS_AUTH_TAG_LEN);

    return MATHOS_STATUS_OK;
}