#include "mathos_fleet.h"

#include "esp_log.h"
#include "nvs.h"
#include <string.h>
#include "nvs_flash.h"
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "MATHOS_FLEET";

/*
    Compare credential bytes without returning early
    when a mismatch is found.
*/
static int fleet_secret_matches(
    const uint8_t *left,
    const uint8_t *right,
    size_t length)
{
    if (left == NULL ||
        right == NULL)
    {
        return 0;
    }

    uint8_t difference = 0U;

    for (size_t index = 0;
         index < length;
         index++)
    {
        difference |=
            left[index] ^ right[index];
    }

    return difference == 0U;
}

static esp_err_t fleet_make_slot_key(
    uint16_t slot,
    char *buffer,
    size_t buffer_size)
{
    if (buffer == NULL ||
        buffer_size < 5U)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (slot >= MATHOS_FLEET_MAX_AIRCRAFT)
    {
        return ESP_ERR_INVALID_ARG;
    }

    int written =
        snprintf(
            buffer,
            buffer_size,
            "a%03u",
            (unsigned int)slot);

    if (written <= 0 ||
        (size_t)written >= buffer_size)
    {
        return ESP_FAIL;
    }

    return ESP_OK;
}

static void fleet_put_u16_le(
    uint8_t *buffer,
    size_t *index,
    uint16_t value)
{
    buffer[(*index)++] =
        (uint8_t)(value & 0xFFU);

    buffer[(*index)++] =
        (uint8_t)((value >> 8) & 0xFFU);
}

static void fleet_put_u32_le(
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

static uint16_t fleet_get_u16_le(
    const uint8_t *buffer,
    size_t *index)
{
    uint16_t value =
        ((uint16_t)buffer[*index + 0] << 0) |
        ((uint16_t)buffer[*index + 1] << 8);

    *index += 2;

    return value;
}

static uint32_t fleet_get_u32_le(
    const uint8_t *buffer,
    size_t *index)
{
    uint32_t value =
        ((uint32_t)buffer[*index + 0] << 0) |
        ((uint32_t)buffer[*index + 1] << 8) |
        ((uint32_t)buffer[*index + 2] << 16) |
        ((uint32_t)buffer[*index + 3] << 24);

    *index += 4;

    return value;
}

static uint32_t fleet_crc32_bytes(
    const uint8_t *data,
    size_t len)
{
    if (data == NULL)
    {
        return 0;
    }

    uint32_t crc =
        0xFFFFFFFFU;

    for (size_t i = 0;
         i < len;
         i++)
    {
        crc ^= data[i];

        for (int bit = 0;
             bit < 8;
             bit++)
        {
            if (crc & 1U)
            {
                crc =
                    (crc >> 1) ^
                    0xEDB88320U;
            }
            else
            {
                crc >>= 1;
            }
        }
    }

    return ~crc;
}

void mathos_fleet_record_set_defaults(
    mathos_fleet_record_t *record)
{
    if (record == NULL)
    {
        return;
    }

    memset(
        record,
        0,
        sizeof(*record));

    record->magic =
        MATHOS_FLEET_RECORD_MAGIC;

    record->version =
        MATHOS_FLEET_RECORD_VERSION;

    record->record_size =
        MATHOS_FLEET_RECORD_WIRE_LEN;

    record->state =
        MATHOS_FLEET_STATE_EMPTY;

    record->secret_format =
        MATHOS_FLEET_SECRET_FORMAT_NONE;
}

uint32_t mathos_fleet_record_calculate_crc32(
    const mathos_fleet_record_t *record)
{
    if (record == NULL)
    {
        return 0;
    }

    /*
        Canonical Fleet Record excluding the final
        4-byte CRC field.
    */
    uint8_t buffer[MATHOS_FLEET_RECORD_WIRE_LEN - 4U];

    memset(
        buffer,
        0,
        sizeof(buffer));

    size_t index = 0;

    fleet_put_u32_le(
        buffer,
        &index,
        record->magic);

    fleet_put_u16_le(
        buffer,
        &index,
        record->version);

    fleet_put_u16_le(
        buffer,
        &index,
        record->record_size);

    memcpy(
        &buffer[index],
        record->gateway_uid.bytes,
        MATHOS_DEVICE_UID_LEN);

    index +=
        MATHOS_DEVICE_UID_LEN;

    buffer[index++] =
        record->state;

    buffer[index++] =
        record->secret_format;

    memcpy(
        &buffer[index],
        record->friendly_name,
        MATHOS_FLEET_FRIENDLY_NAME_LEN);

    index +=
        MATHOS_FLEET_FRIENDLY_NAME_LEN;

    fleet_put_u32_le(
        buffer,
        &index,
        record->key_generation);

    fleet_put_u32_le(
        buffer,
        &index,
        record->security_counter);

    fleet_put_u16_le(
        buffer,
        &index,
        record->secret_blob_len);

    fleet_put_u16_le(
        buffer,
        &index,
        record->reserved0);

    memcpy(
        &buffer[index],
        record->secret_blob,
        MATHOS_FLEET_SECRET_BLOB_MAX_LEN);

    index +=
        MATHOS_FLEET_SECRET_BLOB_MAX_LEN;

    fleet_put_u32_le(
        buffer,
        &index,
        record->record_counter);

    /*
        Must be exactly:
            132 - 4 = 128 bytes
    */
    if (index != sizeof(buffer))
    {
        return 0;
    }

    return fleet_crc32_bytes(
        buffer,
        sizeof(buffer));
}

int mathos_fleet_record_is_valid(
    const mathos_fleet_record_t *record)
{
    if (record == NULL)
    {
        return 0;
    }

    if (record->magic !=
        MATHOS_FLEET_RECORD_MAGIC)
    {
        return 0;
    }

    if (record->version !=
        MATHOS_FLEET_RECORD_VERSION)
    {
        return 0;
    }

    if (record->record_size !=
        MATHOS_FLEET_RECORD_WIRE_LEN)
    {
        return 0;
    }

    if (record->state !=
            MATHOS_FLEET_STATE_ACTIVE &&
        record->state !=
            MATHOS_FLEET_STATE_REVOKED)
    {
        /*
            EMPTY is an internal blank-record state,
            not a valid stored aircraft.
        */
        return 0;
    }

    if (!mathos_device_uid_is_valid(
            &record->gateway_uid))
    {
        return 0;
    }

    /*
        A stored aircraft must have a non-empty,
        null-terminated friendly name.
    */
    if (record->friendly_name[0] == '\0')
    {
        return 0;
    }

    if (memchr(
            record->friendly_name,
            '\0',
            MATHOS_FLEET_FRIENDLY_NAME_LEN) == NULL)
    {
        return 0;
    }

    if (record->key_generation == 0)
    {
        return 0;
    }

    if (record->secret_format ==
        MATHOS_FLEET_SECRET_FORMAT_NONE)
    {
        return 0;
    }

    if (record->secret_blob_len == 0 ||
        record->secret_blob_len >
            MATHOS_FLEET_SECRET_BLOB_MAX_LEN)
    {
        return 0;
    }

    /*
        Development raw Pair Key must always be
        exactly 32 bytes.
    */
    if (record->secret_format ==
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY &&
        record->secret_blob_len !=
            MATHOS_FLEET_PAIR_KEY_LEN)
    {
        return 0;
    }

    /*
        Only known secret formats are accepted.
    */
    if (record->secret_format !=
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY &&
        record->secret_format !=
            MATHOS_FLEET_SECRET_FORMAT_WRAPPED_PAIR_KEY_V1)
    {
        return 0;
    }

    /*
        Version 1 requires reserved fields to remain zero.
    */
    if (record->reserved0 != 0)
    {
        return 0;
    }

    uint32_t expected_crc =
        mathos_fleet_record_calculate_crc32(
            record);

    if (record->crc32 != expected_crc)
    {
        return 0;
    }

    return 1;
}

esp_err_t mathos_fleet_record_encode(
    const mathos_fleet_record_t *record,
    uint8_t *output,
    size_t output_size)
{
    if (record == NULL ||
        output == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (output_size <
        MATHOS_FLEET_RECORD_WIRE_LEN)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    if (!mathos_fleet_record_is_valid(
            record))
    {
        return ESP_ERR_INVALID_STATE;
    }

    memset(
        output,
        0,
        MATHOS_FLEET_RECORD_WIRE_LEN);

    size_t index = 0;

    fleet_put_u32_le(
        output,
        &index,
        record->magic);

    fleet_put_u16_le(
        output,
        &index,
        record->version);

    fleet_put_u16_le(
        output,
        &index,
        record->record_size);

    memcpy(
        &output[index],
        record->gateway_uid.bytes,
        MATHOS_DEVICE_UID_LEN);

    index +=
        MATHOS_DEVICE_UID_LEN;

    output[index++] =
        record->state;

    output[index++] =
        record->secret_format;

    memcpy(
        &output[index],
        record->friendly_name,
        MATHOS_FLEET_FRIENDLY_NAME_LEN);

    index +=
        MATHOS_FLEET_FRIENDLY_NAME_LEN;

    fleet_put_u32_le(
        output,
        &index,
        record->key_generation);

    fleet_put_u32_le(
        output,
        &index,
        record->security_counter);

    fleet_put_u16_le(
        output,
        &index,
        record->secret_blob_len);

    fleet_put_u16_le(
        output,
        &index,
        record->reserved0);

    memcpy(
        &output[index],
        record->secret_blob,
        MATHOS_FLEET_SECRET_BLOB_MAX_LEN);

    index +=
        MATHOS_FLEET_SECRET_BLOB_MAX_LEN;

    fleet_put_u32_le(
        output,
        &index,
        record->record_counter);

    fleet_put_u32_le(
        output,
        &index,
        record->crc32);

    if (index !=
        MATHOS_FLEET_RECORD_WIRE_LEN)
    {
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t mathos_fleet_record_decode(
    const uint8_t *input,
    size_t input_size,
    mathos_fleet_record_t *record)
{
    if (input == NULL ||
        record == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (input_size !=
        MATHOS_FLEET_RECORD_WIRE_LEN)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    mathos_fleet_record_t candidate;

    memset(
        &candidate,
        0,
        sizeof(candidate));

    size_t index = 0;

    candidate.magic =
        fleet_get_u32_le(
            input,
            &index);

    candidate.version =
        fleet_get_u16_le(
            input,
            &index);

    candidate.record_size =
        fleet_get_u16_le(
            input,
            &index);

    memcpy(
        candidate.gateway_uid.bytes,
        &input[index],
        MATHOS_DEVICE_UID_LEN);

    index +=
        MATHOS_DEVICE_UID_LEN;

    candidate.state =
        input[index++];

    candidate.secret_format =
        input[index++];

    memcpy(
        candidate.friendly_name,
        &input[index],
        MATHOS_FLEET_FRIENDLY_NAME_LEN);

    index +=
        MATHOS_FLEET_FRIENDLY_NAME_LEN;

    candidate.key_generation =
        fleet_get_u32_le(
            input,
            &index);

    candidate.security_counter =
        fleet_get_u32_le(
            input,
            &index);

    candidate.secret_blob_len =
        fleet_get_u16_le(
            input,
            &index);

    candidate.reserved0 =
        fleet_get_u16_le(
            input,
            &index);

    memcpy(
        candidate.secret_blob,
        &input[index],
        MATHOS_FLEET_SECRET_BLOB_MAX_LEN);

    index +=
        MATHOS_FLEET_SECRET_BLOB_MAX_LEN;

    candidate.record_counter =
        fleet_get_u32_le(
            input,
            &index);

    candidate.crc32 =
        fleet_get_u32_le(
            input,
            &index);

    if (index !=
        MATHOS_FLEET_RECORD_WIRE_LEN)
    {
        return ESP_FAIL;
    }

    if (!mathos_fleet_record_is_valid(
            &candidate))
    {
        return ESP_ERR_INVALID_STATE;
    }

    /*
        Publish only after complete validation.
    */
    *record =
        candidate;

    return ESP_OK;
}
esp_err_t mathos_fleet_record_self_test(void)
{
    mathos_fleet_record_t source;

    mathos_fleet_record_set_defaults(
        &source);

    /*
        Synthetic test Gateway UID.
    */
    const uint8_t test_uid[MATHOS_DEVICE_UID_LEN] =
        {
            0x10,
            0x20,
            0x30,
            0x40,
            0x50,
            0x60};

    memcpy(
        source.gateway_uid.bytes,
        test_uid,
        sizeof(test_uid));

    source.state =
        MATHOS_FLEET_STATE_ACTIVE;

    source.secret_format =
        MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY;

    strncpy(
        source.friendly_name,
        "Fleet Self Test",
        sizeof(source.friendly_name) - 1U);

    source.key_generation = 1U;

    source.security_counter = 0U;

    source.secret_blob_len =
        MATHOS_FLEET_PAIR_KEY_LEN;

    for (size_t i = 0;
         i < MATHOS_FLEET_PAIR_KEY_LEN;
         i++)
    {
        source.secret_blob[i] =
            (uint8_t)(0xA0U + i);
    }

    source.record_counter = 1U;

    source.crc32 =
        mathos_fleet_record_calculate_crc32(
            &source);

    if (!mathos_fleet_record_is_valid(
            &source))
    {
        ESP_LOGE(
            TAG,
            "Fleet record self-test FAILED: "
            "source invalid");

        return ESP_FAIL;
    }

    uint8_t encoded[MATHOS_FLEET_RECORD_WIRE_LEN];

    memset(
        encoded,
        0,
        sizeof(encoded));

    esp_err_t err =
        mathos_fleet_record_encode(
            &source,
            encoded,
            sizeof(encoded));

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet record self-test FAILED: "
            "encode error=%s",
            esp_err_to_name(err));

        return err;
    }

    mathos_fleet_record_t decoded;

    memset(
        &decoded,
        0,
        sizeof(decoded));

    err =
        mathos_fleet_record_decode(
            encoded,
            sizeof(encoded),
            &decoded);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet record self-test FAILED: "
            "decode error=%s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Re-encode the decoded record and compare the
        canonical representation, rather than comparing
        raw C structures.
    */
    uint8_t reencoded[MATHOS_FLEET_RECORD_WIRE_LEN];

    memset(
        reencoded,
        0,
        sizeof(reencoded));

    err =
        mathos_fleet_record_encode(
            &decoded,
            reencoded,
            sizeof(reencoded));

    if (err != ESP_OK)
    {
        return err;
    }

    if (memcmp(
            encoded,
            reencoded,
            sizeof(encoded)) != 0)
    {
        ESP_LOGE(
            TAG,
            "Fleet record self-test FAILED: "
            "round-trip mismatch");

        return ESP_FAIL;
    }

    /*
        Tamper with one byte of the secret.

        The stored CRC is unchanged, so decode must fail.
    */
    encoded[80] ^= 0x01U;

    mathos_fleet_record_t tampered;

    memset(
        &tampered,
        0,
        sizeof(tampered));

    err =
        mathos_fleet_record_decode(
            encoded,
            sizeof(encoded),
            &tampered);

    if (err == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet record self-test FAILED: "
            "tampered record accepted");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Fleet record self-test PASSED "
        "wire_len=%u crc=0x%08lx",
        (unsigned int)
            MATHOS_FLEET_RECORD_WIRE_LEN,
        (unsigned long)
            source.crc32);

    return ESP_OK;
}
esp_err_t mathos_fleet_record_save_slot(
    uint16_t slot,
    mathos_fleet_record_t *record)
{
    if (record == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    char key[8];

    esp_err_t err =
        fleet_make_slot_key(
            slot,
            key,
            sizeof(key));

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        Work on a candidate.

        The caller's record changes only after the
        complete flash write/read-back succeeds.
    */
    mathos_fleet_record_t candidate =
        *record;

    candidate.record_counter++;

    /*
        Counter zero is reserved.

        This also catches uint32 overflow.
    */
    if (candidate.record_counter == 0U)
    {
        return ESP_ERR_INVALID_STATE;
    }

    candidate.crc32 =
        mathos_fleet_record_calculate_crc32(
            &candidate);

    if (!mathos_fleet_record_is_valid(
            &candidate))
    {
        ESP_LOGE(
            TAG,
            "Fleet save rejected: invalid record slot=%u",
            (unsigned int)slot);

        return ESP_ERR_INVALID_STATE;
    }

    uint8_t encoded[MATHOS_FLEET_RECORD_WIRE_LEN];

    memset(
        encoded,
        0,
        sizeof(encoded));

    err =
        mathos_fleet_record_encode(
            &candidate,
            encoded,
            sizeof(encoded));

    if (err != ESP_OK)
    {
        return err;
    }

    nvs_handle_t handle;

    err =
        nvs_open_from_partition(
            MATHOS_FLEET_PARTITION_NAME,
            MATHOS_FLEET_NAMESPACE,
            NVS_READWRITE,
            &handle);

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        nvs_set_blob(
            handle,
            key,
            encoded,
            sizeof(encoded));

    if (err != ESP_OK)
    {
        nvs_close(handle);
        return err;
    }

    err =
        nvs_commit(handle);

    if (err != ESP_OK)
    {
        nvs_close(handle);
        return err;
    }

    /*
        Read committed bytes back before trusting them.
    */
    uint8_t verified[MATHOS_FLEET_RECORD_WIRE_LEN];

    memset(
        verified,
        0,
        sizeof(verified));

    size_t verified_size =
        sizeof(verified);

    err =
        nvs_get_blob(
            handle,
            key,
            verified,
            &verified_size);

    nvs_close(handle);

    if (err != ESP_OK)
    {
        return err;
    }

    if (verified_size !=
        MATHOS_FLEET_RECORD_WIRE_LEN)
    {
        ESP_LOGE(
            TAG,
            "Fleet save verification size mismatch "
            "slot=%u size=%u",
            (unsigned int)slot,
            (unsigned int)verified_size);

        return ESP_FAIL;
    }

    if (memcmp(
            encoded,
            verified,
            sizeof(encoded)) != 0)
    {
        ESP_LOGE(
            TAG,
            "Fleet save verification mismatch slot=%u",
            (unsigned int)slot);

        return ESP_FAIL;
    }

    /*
        Also prove that the stored canonical bytes
        decode into a valid record.
    */
    mathos_fleet_record_t decoded;

    memset(
        &decoded,
        0,
        sizeof(decoded));

    err =
        mathos_fleet_record_decode(
            verified,
            verified_size,
            &decoded);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet save read-back decode failed slot=%u",
            (unsigned int)slot);

        return err;
    }

    /*
        Publish updated counter/CRC only now.
    */
    *record =
        candidate;

    ESP_LOGI(
        TAG,
        "Fleet record saved slot=%u key=%s "
        "state=%s generation=%lu counter=%lu",
        (unsigned int)slot,
        key,
        mathos_fleet_state_to_string(
            (mathos_fleet_state_t)candidate.state),
        (unsigned long)candidate.key_generation,
        (unsigned long)candidate.record_counter);

    return ESP_OK;
}

esp_err_t mathos_fleet_record_load_slot(
    uint16_t slot,
    mathos_fleet_record_t *record)
{
    if (record == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    char key[8];

    esp_err_t err =
        fleet_make_slot_key(
            slot,
            key,
            sizeof(key));

    if (err != ESP_OK)
    {
        return err;
    }

    nvs_handle_t handle;

    err =
        nvs_open_from_partition(
            MATHOS_FLEET_PARTITION_NAME,
            MATHOS_FLEET_NAMESPACE,
            NVS_READONLY,
            &handle);

    if (err != ESP_OK)
    {
        return err;
    }

    size_t stored_size = 0;

    err =
        nvs_get_blob(
            handle,
            key,
            NULL,
            &stored_size);

    if (err != ESP_OK)
    {
        nvs_close(handle);
        return err;
    }

    if (stored_size !=
        MATHOS_FLEET_RECORD_WIRE_LEN)
    {
        ESP_LOGE(
            TAG,
            "Fleet record bad stored size "
            "slot=%u size=%u expected=%u",
            (unsigned int)slot,
            (unsigned int)stored_size,
            (unsigned int)
                MATHOS_FLEET_RECORD_WIRE_LEN);

        nvs_close(handle);

        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t encoded[MATHOS_FLEET_RECORD_WIRE_LEN];

    memset(
        encoded,
        0,
        sizeof(encoded));

    err =
        nvs_get_blob(
            handle,
            key,
            encoded,
            &stored_size);

    nvs_close(handle);

    if (err != ESP_OK)
    {
        return err;
    }

    mathos_fleet_record_t candidate;

    memset(
        &candidate,
        0,
        sizeof(candidate));

    err =
        mathos_fleet_record_decode(
            encoded,
            stored_size,
            &candidate);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet record validation failed slot=%u",
            (unsigned int)slot);

        return err;
    }

    /*
        Publish only after complete validation.
    */
    *record =
        candidate;

    return ESP_OK;
}

esp_err_t mathos_fleet_find_by_uid(
    const mathos_device_uid_t *gateway_uid,
    uint16_t *slot_out,
    mathos_fleet_record_t *record_out)
{
    if (gateway_uid == NULL ||
        slot_out == NULL ||
        record_out == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (!mathos_device_uid_is_valid(
            gateway_uid))
    {
        return ESP_ERR_INVALID_ARG;
    }

    *slot_out =
        0xFFFFU;

    memset(
        record_out,
        0,
        sizeof(*record_out));

    bool match_found =
        false;

    uint16_t matched_slot =
        0xFFFFU;

    mathos_fleet_record_t matched_record;

    memset(
        &matched_record,
        0,
        sizeof(matched_record));

    for (uint16_t slot = 0;
         slot < MATHOS_FLEET_MAX_AIRCRAFT;
         slot++)
    {
        mathos_fleet_record_t record;

        memset(
            &record,
            0,
            sizeof(record));

        esp_err_t err =
            mathos_fleet_record_load_slot(
                slot,
                &record);

        if (err == ESP_ERR_NVS_NOT_FOUND)
        {
            continue;
        }

        /*
            Any persistent-record problem must abort
            the lookup.

            We never silently skip corrupted Fleet data.
        */
        if (err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "Fleet UID lookup aborted "
                "slot=%u error=%s",
                (unsigned int)slot,
                esp_err_to_name(err));

            return err;
        }

        if (memcmp(
                record.gateway_uid.bytes,
                gateway_uid->bytes,
                MATHOS_DEVICE_UID_LEN) != 0)
        {
            continue;
        }

        /*
            First match:
            remember it, but KEEP SCANNING.

            Returning immediately would allow a second
            duplicate UID to remain undetected.
        */
        if (!match_found)
        {
            match_found =
                true;

            matched_slot =
                slot;

            matched_record =
                record;

            continue;
        }

        /*
            Second match for the same physical Gateway.

            Fleet identity is now ambiguous.
        */
        ESP_LOGE(
            TAG,
            "Fleet UID lookup FAILED: "
            "duplicate Gateway UID "
            "slots=%u,%u",
            (unsigned int)matched_slot,
            (unsigned int)slot);

        return ESP_ERR_INVALID_STATE;
    }

    if (!match_found)
    {
        return ESP_ERR_NOT_FOUND;
    }

    *slot_out =
        matched_slot;

    *record_out =
        matched_record;

    ESP_LOGI(
        TAG,
        "Fleet UID match slot=%u "
        "name=%s state=%s generation=%lu",
        (unsigned int)matched_slot,
        matched_record.friendly_name,
        mathos_fleet_state_to_string(
            (mathos_fleet_state_t)
                matched_record.state),
        (unsigned long)
            matched_record.key_generation);

    return ESP_OK;
}
esp_err_t mathos_fleet_duplicate_uid_lookup_self_test(void)
{
    mathos_device_uid_t test_uid =
        {
            .bytes =
                {
                    0xE1, 0xE2, 0xE3,
                    0xE4, 0xE5, 0xE6}};

    /*
        Make sure the synthetic UID does not already exist.
    */
    uint16_t existing_slot =
        0xFFFFU;

    mathos_fleet_record_t existing_record;

    memset(
        &existing_record,
        0,
        sizeof(existing_record));

    esp_err_t err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &existing_slot,
            &existing_record);

    if (err == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Duplicate UID lookup self-test REFUSED: "
            "test UID already exists slot=%u",
            (unsigned int)existing_slot);

        return ESP_ERR_INVALID_STATE;
    }

    if (err != ESP_ERR_NOT_FOUND)
    {
        return err;
    }

    uint8_t test_key[MATHOS_FLEET_PAIR_KEY_LEN];

    for (size_t i = 0;
         i < sizeof(test_key);
         i++)
    {
        test_key[i] =
            (uint8_t)(0x20U + i);
    }

    /*
        Find first free slot.
    */
    uint16_t slot_one =
        0xFFFFU;

    err =
        mathos_fleet_find_free_slot(
            &slot_one);

    if (err != ESP_OK)
    {
        return err;
    }

    mathos_fleet_record_t record_one;

    mathos_fleet_record_set_defaults(
        &record_one);

    record_one.gateway_uid =
        test_uid;

    record_one.state =
        MATHOS_FLEET_STATE_ACTIVE;

    record_one.secret_format =
        MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY;

    memcpy(
        record_one.friendly_name,
        "Duplicate Lookup One",
        sizeof("Duplicate Lookup One"));

    record_one.key_generation =
        1U;

    record_one.secret_blob_len =
        MATHOS_FLEET_PAIR_KEY_LEN;

    memcpy(
        record_one.secret_blob,
        test_key,
        sizeof(test_key));

    err =
        mathos_fleet_record_save_slot(
            slot_one,
            &record_one);

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        One matching record must still be a normal,
        successful lookup.
    */
    uint16_t found_slot =
        0xFFFFU;

    mathos_fleet_record_t found_record;

    memset(
        &found_record,
        0,
        sizeof(found_record));

    err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &found_slot,
            &found_record);

    if (err != ESP_OK ||
        found_slot != slot_one)
    {
        ESP_LOGE(
            TAG,
            "Duplicate UID lookup self-test FAILED: "
            "single UID lookup failed");

        mathos_fleet_record_delete_slot(
            slot_one);

        return ESP_FAIL;
    }

    /*
        Find another free slot.
    */
    uint16_t slot_two =
        0xFFFFU;

    err =
        mathos_fleet_find_free_slot(
            &slot_two);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            slot_one);

        return err;
    }

    /*
        Inject another individually valid record with
        exactly the SAME Gateway UID.
    */
    mathos_fleet_record_t record_two;

    mathos_fleet_record_set_defaults(
        &record_two);

    record_two.gateway_uid =
        test_uid;

    record_two.state =
        MATHOS_FLEET_STATE_REVOKED;

    record_two.secret_format =
        MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY;

    memcpy(
        record_two.friendly_name,
        "Duplicate Lookup Two",
        sizeof("Duplicate Lookup Two"));

    record_two.key_generation =
        1U;

    record_two.secret_blob_len =
        MATHOS_FLEET_PAIR_KEY_LEN;

    memcpy(
        record_two.secret_blob,
        test_key,
        sizeof(test_key));

    err =
        mathos_fleet_record_save_slot(
            slot_two,
            &record_two);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            slot_one);

        return err;
    }

    /*
        Now lookup MUST fail closed.

        It must not simply return whichever duplicate
        record happens to appear first.
    */
    found_slot =
        0xFFFFU;

    memset(
        &found_record,
        0,
        sizeof(found_record));

    err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &found_slot,
            &found_record);

    if (err != ESP_ERR_INVALID_STATE)
    {
        ESP_LOGE(
            TAG,
            "Duplicate UID lookup self-test FAILED: "
            "ambiguous UID not rejected error=%s",
            esp_err_to_name(err));

        mathos_fleet_record_delete_slot(
            slot_one);

        mathos_fleet_record_delete_slot(
            slot_two);

        return ESP_FAIL;
    }

    /*
        On ambiguity, no selected record may escape.
    */
    if (found_slot != 0xFFFFU)
    {
        ESP_LOGE(
            TAG,
            "Duplicate UID lookup self-test FAILED: "
            "ambiguous lookup exposed slot=%u",
            (unsigned int)found_slot);

        mathos_fleet_record_delete_slot(
            slot_one);

        mathos_fleet_record_delete_slot(
            slot_two);

        return ESP_FAIL;
    }

    /*
        Cleanup deliberate duplicate records.
    */
    err =
        mathos_fleet_record_delete_slot(
            slot_one);

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        mathos_fleet_record_delete_slot(
            slot_two);

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        Final proof:
        after cleanup the UID must disappear completely.
    */
    found_slot =
        0xFFFFU;

    memset(
        &found_record,
        0,
        sizeof(found_record));

    err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &found_slot,
            &found_record);

    if (err != ESP_ERR_NOT_FOUND)
    {
        ESP_LOGE(
            TAG,
            "Duplicate UID lookup self-test FAILED: "
            "test UID remains after cleanup");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Duplicate UID lookup self-test PASSED "
        "single->duplicate-rejected->removed "
        "slots=%u,%u",
        (unsigned int)slot_one,
        (unsigned int)slot_two);

    return ESP_OK;
}

esp_err_t mathos_fleet_find_free_slot(
    uint16_t *slot_out)
{
    if (slot_out == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    for (uint16_t slot = 0;
         slot < MATHOS_FLEET_MAX_AIRCRAFT;
         slot++)
    {
        mathos_fleet_record_t record;

        memset(
            &record,
            0,
            sizeof(record));

        esp_err_t err =
            mathos_fleet_record_load_slot(
                slot,
                &record);

        /*
            No NVS key means this slot is free.
        */
        if (err == ESP_ERR_NVS_NOT_FOUND)
        {
            *slot_out =
                slot;

            return ESP_OK;
        }

        /*
            Valid occupied slot.
        */
        if (err == ESP_OK)
        {
            continue;
        }

        /*
            Existing but corrupted/unreadable Fleet
            data must never be treated as free space.
        */
        ESP_LOGE(
            TAG,
            "Fleet free-slot search aborted "
            "slot=%u error=%s",
            (unsigned int)slot,
            esp_err_to_name(err));

        return err;
    }

    /*
        All 200 slots are occupied.
    */
    return ESP_ERR_NO_MEM;
}

esp_err_t mathos_fleet_get_counts(
    mathos_fleet_counts_t *counts)
{
    if (counts == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    memset(
        counts,
        0,
        sizeof(*counts));

    for (uint16_t slot = 0;
         slot < MATHOS_FLEET_MAX_AIRCRAFT;
         slot++)
    {
        mathos_fleet_record_t record;

        memset(
            &record,
            0,
            sizeof(record));

        esp_err_t err =
            mathos_fleet_record_load_slot(
                slot,
                &record);

        /*
            No record stored in this slot.
        */
        if (err == ESP_ERR_NVS_NOT_FOUND)
        {
            counts->free_slots++;
            continue;
        }

        /*
            Any other load problem is security relevant.
            Do not silently skip corrupted records.
        */
        if (err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "Fleet count aborted "
                "slot=%u error=%s",
                (unsigned int)slot,
                esp_err_to_name(err));

            memset(
                counts,
                0,
                sizeof(*counts));

            return err;
        }

        counts->total++;

        switch ((mathos_fleet_state_t)
                    record.state)
        {
        case MATHOS_FLEET_STATE_ACTIVE:
            counts->active++;
            break;

        case MATHOS_FLEET_STATE_REVOKED:
            counts->revoked++;
            break;

        default:
            /*
                load_slot() should already reject this,
                but keep this defensive check.
            */
            ESP_LOGE(
                TAG,
                "Fleet count found invalid state "
                "slot=%u state=%u",
                (unsigned int)slot,
                (unsigned int)record.state);

            memset(
                counts,
                0,
                sizeof(*counts));

            return ESP_ERR_INVALID_STATE;
        }
    }

    /*
        Internal consistency check.
    */
    if (counts->total !=
        (uint16_t)(counts->active +
                   counts->revoked))
    {
        memset(
            counts,
            0,
            sizeof(*counts));

        return ESP_FAIL;
    }

    if ((uint16_t)(counts->total +
                   counts->free_slots) !=
        MATHOS_FLEET_MAX_AIRCRAFT)
    {
        memset(
            counts,
            0,
            sizeof(*counts));

        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t mathos_fleet_get_active_status(
    mathos_fleet_active_status_t *status_out,
    uint16_t *slot_out,
    mathos_fleet_record_t *record_out)
{
    if (status_out == NULL ||
        slot_out == NULL ||
        record_out == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    *status_out =
        MATHOS_FLEET_ACTIVE_NONE;

    *slot_out =
        0xFFFFU;

    memset(
        record_out,
        0,
        sizeof(*record_out));

    uint16_t active_count = 0U;

    uint16_t first_active_slot =
        0xFFFFU;

    mathos_fleet_record_t first_active_record;

    memset(
        &first_active_record,
        0,
        sizeof(first_active_record));

    for (uint16_t slot = 0;
         slot < MATHOS_FLEET_MAX_AIRCRAFT;
         slot++)
    {
        mathos_fleet_record_t record;

        memset(
            &record,
            0,
            sizeof(record));

        esp_err_t err =
            mathos_fleet_record_load_slot(
                slot,
                &record);

        /*
            Empty slot.
        */
        if (err == ESP_ERR_NVS_NOT_FOUND)
        {
            continue;
        }

        /*
            Corrupted/unreadable Fleet data is
            security-relevant.

            Fail closed rather than pretending the
            aircraft does not exist.
        */
        if (err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "Fleet active-status scan aborted "
                "slot=%u error=%s",
                (unsigned int)slot,
                esp_err_to_name(err));

            return err;
        }

        if (record.state !=
            MATHOS_FLEET_STATE_ACTIVE)
        {
            continue;
        }

        active_count++;

        /*
            Remember the first ACTIVE record.

            We only publish it if it turns out to be
            the ONLY ACTIVE aircraft.
        */
        if (active_count == 1U)
        {
            first_active_slot =
                slot;

            first_active_record =
                record;
        }

        /*
            We already know the answer is MULTIPLE.

            No need to scan the remaining slots.
        */
        if (active_count >= 2U)
        {
            *status_out =
                MATHOS_FLEET_ACTIVE_MULTIPLE;

            return ESP_OK;
        }
    }

    if (active_count == 0U)
    {
        *status_out =
            MATHOS_FLEET_ACTIVE_NONE;

        return ESP_OK;
    }

    /*
        Exactly one ACTIVE aircraft.
    */
    *status_out =
        MATHOS_FLEET_ACTIVE_ONE;

    *slot_out =
        first_active_slot;

    *record_out =
        first_active_record;

    return ESP_OK;
}

esp_err_t mathos_fleet_get_operation_status(
    mathos_fleet_operation_status_t *status_out,
    uint16_t *slot_out,
    mathos_fleet_record_t *record_out)
{
    if (status_out == NULL ||
        slot_out == NULL ||
        record_out == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    *status_out =
        MATHOS_FLEET_OPERATION_NO_AIRCRAFT;

    *slot_out =
        0xFFFFU;

    memset(
        record_out,
        0,
        sizeof(*record_out));

    mathos_fleet_active_status_t active_status =
        MATHOS_FLEET_ACTIVE_NONE;

    uint16_t active_slot =
        0xFFFFU;

    mathos_fleet_record_t active_record;

    memset(
        &active_record,
        0,
        sizeof(active_record));

    esp_err_t err =
        mathos_fleet_get_active_status(
            &active_status,
            &active_slot,
            &active_record);

    if (err != ESP_OK)
    {
        /*
            Fleet corruption/read failure propagates.

            Normal operation must not continue using
            an incomplete Fleet view.
        */
        return err;
    }

    switch (active_status)
    {
    case MATHOS_FLEET_ACTIVE_NONE:

        *status_out =
            MATHOS_FLEET_OPERATION_NO_AIRCRAFT;

        return ESP_OK;

    case MATHOS_FLEET_ACTIVE_ONE:

        *status_out =
            MATHOS_FLEET_OPERATION_READY;

        *slot_out =
            active_slot;

        *record_out =
            active_record;

        return ESP_OK;

    case MATHOS_FLEET_ACTIVE_MULTIPLE:

        *status_out =
            MATHOS_FLEET_OPERATION_SELECTION_REQUIRED;

        /*
            Deliberately do not expose a selected record.
        */
        return ESP_OK;

    default:

        return ESP_ERR_INVALID_STATE;
    }
}

esp_err_t mathos_fleet_boot_validate(
    mathos_fleet_operation_status_t *status_out,
    uint16_t *slot_out,
    mathos_fleet_record_t *record_out)
{
    if (status_out == NULL ||
        slot_out == NULL ||
        record_out == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Clear outputs before doing any persistent
        Fleet inspection.

        Nothing is considered selected unless the
        complete validation sequence succeeds.
    */
    *status_out =
        MATHOS_FLEET_OPERATION_NO_AIRCRAFT;

    *slot_out =
        0xFFFFU;

    memset(
        record_out,
        0,
        sizeof(*record_out));

    /*
        First validate the Fleet database as a whole.

        This detects:
            malformed records
            CRC failures
            unsupported versions/formats
            duplicate Gateway UIDs
            storage read failures

        Any failure is fatal for Fleet-based operation.
    */
    esp_err_t err =
        mathos_fleet_validate_store();

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet boot validation FAILED "
            "store_integrity error=%s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Only after the complete Fleet passes integrity
        validation do we derive the operational state.
    */
    err =
        mathos_fleet_get_operation_status(
            status_out,
            slot_out,
            record_out);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet boot validation FAILED "
            "operation_status error=%s",
            esp_err_to_name(err));

        /*
            Fail closed outputs.
        */
        *status_out =
            MATHOS_FLEET_OPERATION_NO_AIRCRAFT;

        *slot_out =
            0xFFFFU;

        memset(
            record_out,
            0,
            sizeof(*record_out));

        return err;
    }

    ESP_LOGI(
        TAG,
        "Fleet boot validation PASSED status=%s",
        mathos_fleet_operation_status_to_string(
            *status_out));

    if (*status_out ==
        MATHOS_FLEET_OPERATION_READY)
    {
        ESP_LOGI(
            TAG,
            "Fleet boot candidate slot=%u "
            "name=%s generation=%lu",
            (unsigned int)*slot_out,
            record_out->friendly_name,
            (unsigned long)
                record_out->key_generation);
    }

    return ESP_OK;
}

const char *mathos_fleet_operation_status_to_string(
    mathos_fleet_operation_status_t status)
{
    switch (status)
    {
    case MATHOS_FLEET_OPERATION_NO_AIRCRAFT:
        return "NO_AIRCRAFT";

    case MATHOS_FLEET_OPERATION_READY:
        return "READY";

    case MATHOS_FLEET_OPERATION_SELECTION_REQUIRED:
        return "SELECTION_REQUIRED";

    default:
        return "INVALID";
    }
}

esp_err_t mathos_fleet_operation_status_self_test(void)
{
    mathos_fleet_operation_status_t status =
        MATHOS_FLEET_OPERATION_NO_AIRCRAFT;

    uint16_t slot =
        0xFFFFU;

    mathos_fleet_record_t record;

    memset(
        &record,
        0,
        sizeof(record));

    /*
        TEST 1:
        Empty Fleet -> NO_AIRCRAFT
    */
    esp_err_t err =
        mathos_fleet_get_operation_status(
            &status,
            &slot,
            &record);

    if (err != ESP_OK ||
        status !=
            MATHOS_FLEET_OPERATION_NO_AIRCRAFT)
    {
        ESP_LOGE(
            TAG,
            "Fleet operation-status self-test FAILED: "
            "expected NO_AIRCRAFT");

        return ESP_FAIL;
    }

    if (slot != 0xFFFFU)
    {
        ESP_LOGE(
            TAG,
            "Fleet operation-status self-test FAILED: "
            "NO_AIRCRAFT exposed slot=%u",
            (unsigned int)slot);

        return ESP_FAIL;
    }

    uint8_t test_key[MATHOS_FLEET_PAIR_KEY_LEN];

    for (size_t i = 0;
         i < sizeof(test_key);
         i++)
    {
        test_key[i] =
            (uint8_t)(0xE0U + i);
    }

    mathos_device_uid_t uid_one =
        {
            .bytes =
                {
                    0xB1, 0xB2, 0xB3,
                    0xB4, 0xB5, 0xB6}};

    mathos_device_uid_t uid_two =
        {
            .bytes =
                {
                    0xC1, 0xC2, 0xC3,
                    0xC4, 0xC5, 0xC6}};

    uint16_t slot_one =
        0xFFFFU;

    /*
        TEST 2:
        One ACTIVE aircraft -> READY
    */
    err =
        mathos_fleet_add_aircraft(
            &uid_one,
            "Operation One",
            1U,
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY,
            test_key,
            sizeof(test_key),
            &slot_one);

    if (err != ESP_OK)
    {
        return err;
    }

    memset(
        &record,
        0,
        sizeof(record));

    slot =
        0xFFFFU;

    err =
        mathos_fleet_get_operation_status(
            &status,
            &slot,
            &record);

    if (err != ESP_OK ||
        status !=
            MATHOS_FLEET_OPERATION_READY ||
        slot != slot_one)
    {
        ESP_LOGE(
            TAG,
            "Fleet operation-status self-test FAILED: "
            "expected READY");

        mathos_fleet_record_delete_slot(
            slot_one);

        return ESP_FAIL;
    }

    uint16_t slot_two =
        0xFFFFU;

    /*
        TEST 3:
        Two ACTIVE aircraft -> SELECTION_REQUIRED
    */
    err =
        mathos_fleet_add_aircraft(
            &uid_two,
            "Operation Two",
            1U,
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY,
            test_key,
            sizeof(test_key),
            &slot_two);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            slot_one);

        return err;
    }

    memset(
        &record,
        0,
        sizeof(record));

    slot =
        0xFFFFU;

    err =
        mathos_fleet_get_operation_status(
            &status,
            &slot,
            &record);

    if (err != ESP_OK ||
        status !=
            MATHOS_FLEET_OPERATION_SELECTION_REQUIRED)
    {
        ESP_LOGE(
            TAG,
            "Fleet operation-status self-test FAILED: "
            "expected SELECTION_REQUIRED");

        mathos_fleet_record_delete_slot(
            slot_one);

        mathos_fleet_record_delete_slot(
            slot_two);

        return ESP_FAIL;
    }

    /*
        MULTIPLE aircraft must not expose
        an automatically selected slot.
    */
    if (slot != 0xFFFFU)
    {
        ESP_LOGE(
            TAG,
            "Fleet operation-status self-test FAILED: "
            "SELECTION_REQUIRED exposed slot=%u",
            (unsigned int)slot);

        mathos_fleet_record_delete_slot(
            slot_one);

        mathos_fleet_record_delete_slot(
            slot_two);

        return ESP_FAIL;
    }

    /*
        TEST 4:
        Revoke second aircraft -> READY again
    */
    err =
        mathos_fleet_revoke_aircraft(
            &uid_two);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            slot_one);

        mathos_fleet_record_delete_slot(
            slot_two);

        return err;
    }

    memset(
        &record,
        0,
        sizeof(record));

    slot =
        0xFFFFU;

    err =
        mathos_fleet_get_operation_status(
            &status,
            &slot,
            &record);

    if (err != ESP_OK ||
        status !=
            MATHOS_FLEET_OPERATION_READY ||
        slot != slot_one)
    {
        ESP_LOGE(
            TAG,
            "Fleet operation-status self-test FAILED: "
            "expected READY after revoke");

        mathos_fleet_record_delete_slot(
            slot_one);

        mathos_fleet_record_delete_slot(
            slot_two);

        return ESP_FAIL;
    }

    /*
        Cleanup.
    */
    err =
        mathos_fleet_record_delete_slot(
            slot_one);

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        mathos_fleet_record_delete_slot(
            slot_two);

    if (err != ESP_OK)
    {
        return err;
    }

    ESP_LOGI(
        TAG,
        "Fleet operation-status self-test PASSED "
        "NO_AIRCRAFT->READY->SELECTION_REQUIRED->READY");

    return ESP_OK;
}
esp_err_t mathos_fleet_validate_store(void)
{
    /*
        Do not place the 200-entry UID table on the
        main task stack.

        Allocate it temporarily from the heap instead.
    */
    mathos_device_uid_t *seen_uids =
        calloc(
            MATHOS_FLEET_MAX_AIRCRAFT,
            sizeof(mathos_device_uid_t));

    if (seen_uids == NULL)
    {
        ESP_LOGE(
            TAG,
            "Fleet validation FAILED: "
            "cannot allocate UID table");

        return ESP_ERR_NO_MEM;
    }

    uint16_t seen_count = 0U;

    for (uint16_t slot = 0;
         slot < MATHOS_FLEET_MAX_AIRCRAFT;
         slot++)
    {
        mathos_fleet_record_t record;

        memset(
            &record,
            0,
            sizeof(record));

        esp_err_t err =
            mathos_fleet_record_load_slot(
                slot,
                &record);

        /*
            Empty slot is normal.
        */
        if (err == ESP_ERR_NVS_NOT_FOUND)
        {
            continue;
        }

        /*
            CRC/version/format/storage failures
            must fail closed.
        */
        if (err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "Fleet validation FAILED "
                "slot=%u error=%s",
                (unsigned int)slot,
                esp_err_to_name(err));

            free(seen_uids);

            return err;
        }

        /*
            Detect duplicate physical Gateway UIDs.
        */
        for (uint16_t i = 0;
             i < seen_count;
             i++)
        {
            if (memcmp(
                    seen_uids[i].bytes,
                    record.gateway_uid.bytes,
                    MATHOS_DEVICE_UID_LEN) == 0)
            {
                ESP_LOGE(
                    TAG,
                    "Fleet validation FAILED: "
                    "duplicate Gateway UID "
                    "slot=%u earlier_record=%u",
                    (unsigned int)slot,
                    (unsigned int)i);

                free(seen_uids);

                return ESP_ERR_INVALID_STATE;
            }
        }

        if (seen_count >=
            MATHOS_FLEET_MAX_AIRCRAFT)
        {
            free(seen_uids);

            return ESP_ERR_INVALID_STATE;
        }

        seen_uids[seen_count] =
            record.gateway_uid;

        seen_count++;
    }

    free(seen_uids);

    ESP_LOGI(
        TAG,
        "Fleet validation PASSED "
        "records=%u capacity=%u",
        (unsigned int)seen_count,
        (unsigned int)
            MATHOS_FLEET_MAX_AIRCRAFT);

    return ESP_OK;
}

esp_err_t mathos_fleet_validate_store_self_test(void)
{
    /*
        First prove that the current Fleet Store itself
        is internally valid.
    */
    esp_err_t err =
        mathos_fleet_validate_store();

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet validation self-test REFUSED: "
            "existing Fleet is not valid error=%s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Synthetic UID used only for deliberate
        duplicate-record injection.
    */
    mathos_device_uid_t test_uid =
        {
            .bytes =
                {
                    0xD1, 0xD2, 0xD3,
                    0xD4, 0xD5, 0xD6}};

    /*
        Make sure the synthetic UID is not already
        present.
    */
    uint16_t existing_slot = 0xFFFFU;

    mathos_fleet_record_t existing_record;

    memset(
        &existing_record,
        0,
        sizeof(existing_record));

    err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &existing_slot,
            &existing_record);

    if (err == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet validation self-test REFUSED: "
            "test UID already exists slot=%u",
            (unsigned int)existing_slot);

        return ESP_ERR_INVALID_STATE;
    }

    if (err != ESP_ERR_NOT_FOUND)
    {
        return err;
    }

    /*
        We need two free slots so that we can inject
        two valid records with the SAME UID.
    */
    uint16_t slot_one = 0xFFFFU;

    err =
        mathos_fleet_find_free_slot(
            &slot_one);

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        Construct first valid record directly.
    */
    uint8_t test_key[MATHOS_FLEET_PAIR_KEY_LEN];

    for (size_t i = 0;
         i < sizeof(test_key);
         i++)
    {
        test_key[i] =
            (uint8_t)(0xF0U + i);
    }

    mathos_fleet_record_t record_one;

    mathos_fleet_record_set_defaults(
        &record_one);

    record_one.gateway_uid =
        test_uid;

    record_one.state =
        MATHOS_FLEET_STATE_ACTIVE;

    record_one.secret_format =
        MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY;

    memcpy(
        record_one.friendly_name,
        "Validation One",
        sizeof("Validation One"));

    record_one.key_generation =
        1U;

    record_one.secret_blob_len =
        MATHOS_FLEET_PAIR_KEY_LEN;

    memcpy(
        record_one.secret_blob,
        test_key,
        sizeof(test_key));

    err =
        mathos_fleet_record_save_slot(
            slot_one,
            &record_one);

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        With only one injected record, validation
        must still succeed.
    */
    err =
        mathos_fleet_validate_store();

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet validation self-test FAILED: "
            "valid single record rejected");

        mathos_fleet_record_delete_slot(
            slot_one);

        return err;
    }

    /*
        Find the next free slot.
    */
    uint16_t slot_two = 0xFFFFU;

    err =
        mathos_fleet_find_free_slot(
            &slot_two);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            slot_one);

        return err;
    }

    /*
        Construct another individually valid record,
        but intentionally reuse the SAME Gateway UID.

        This simulates an ambiguous/corrupted Fleet Store.
    */
    mathos_fleet_record_t record_two;

    mathos_fleet_record_set_defaults(
        &record_two);

    record_two.gateway_uid =
        test_uid;

    record_two.state =
        MATHOS_FLEET_STATE_REVOKED;

    record_two.secret_format =
        MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY;

    memcpy(
        record_two.friendly_name,
        "Validation Duplicate",
        sizeof("Validation Duplicate"));

    record_two.key_generation =
        1U;

    record_two.secret_blob_len =
        MATHOS_FLEET_PAIR_KEY_LEN;

    memcpy(
        record_two.secret_blob,
        test_key,
        sizeof(test_key));

    err =
        mathos_fleet_record_save_slot(
            slot_two,
            &record_two);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            slot_one);

        return err;
    }

    /*
        The integrity scan MUST now reject the Fleet.
    */
    err =
        mathos_fleet_validate_store();

    if (err != ESP_ERR_INVALID_STATE)
    {
        ESP_LOGE(
            TAG,
            "Fleet validation self-test FAILED: "
            "duplicate UID was not detected error=%s",
            esp_err_to_name(err));

        mathos_fleet_record_delete_slot(
            slot_one);

        mathos_fleet_record_delete_slot(
            slot_two);

        return ESP_FAIL;
    }

    /*
        Remove the deliberately corrupted test data.
    */
    err =
        mathos_fleet_record_delete_slot(
            slot_one);

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        mathos_fleet_record_delete_slot(
            slot_two);

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        Final proof that cleanup restored a valid Fleet.
    */
    err =
        mathos_fleet_validate_store();

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet validation self-test FAILED: "
            "Fleet invalid after cleanup error=%s",
            esp_err_to_name(err));

        return err;
    }

    ESP_LOGI(
        TAG,
        "Fleet validation self-test PASSED "
        "valid->duplicate-detected->valid "
        "slots=%u,%u",
        (unsigned int)slot_one,
        (unsigned int)slot_two);

    return ESP_OK;
}

const char *mathos_fleet_active_status_to_string(
    mathos_fleet_active_status_t status)
{
    switch (status)
    {
    case MATHOS_FLEET_ACTIVE_NONE:
        return "NONE";

    case MATHOS_FLEET_ACTIVE_ONE:
        return "ONE";

    case MATHOS_FLEET_ACTIVE_MULTIPLE:
        return "MULTIPLE";

    default:
        return "UNKNOWN";
    }
}
esp_err_t mathos_fleet_active_status_self_test(void)
{
    mathos_fleet_active_status_t status;

    uint16_t slot = 0xFFFFU;

    mathos_fleet_record_t record;

    memset(
        &record,
        0,
        sizeof(record));

    /*
        TEST 1:
        Current Fleet should have zero ACTIVE aircraft.
    */
    esp_err_t err =
        mathos_fleet_get_active_status(
            &status,
            &slot,
            &record);

    if (err != ESP_OK)
    {
        return err;
    }

    if (status !=
        MATHOS_FLEET_ACTIVE_NONE)
    {
        ESP_LOGE(
            TAG,
            "Fleet active-status self-test FAILED: "
            "expected NONE got=%s",
            mathos_fleet_active_status_to_string(
                status));

        return ESP_FAIL;
    }

    /*
        Synthetic Pair Key.
    */
    uint8_t test_key[MATHOS_FLEET_PAIR_KEY_LEN];

    for (size_t i = 0;
         i < sizeof(test_key);
         i++)
    {
        test_key[i] =
            (uint8_t)(0xC0U + i);
    }

    mathos_device_uid_t uid_one =
        {
            .bytes =
                {
                    0x81, 0x82, 0x83,
                    0x84, 0x85, 0x86}};

    mathos_device_uid_t uid_two =
        {
            .bytes =
                {
                    0x91, 0x92, 0x93,
                    0x94, 0x95, 0x96}};

    uint16_t slot_one =
        0xFFFFU;

    /*
        Add first ACTIVE aircraft.
    */
    err =
        mathos_fleet_add_aircraft(
            &uid_one,
            "Active One",
            1U,
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY,
            test_key,
            sizeof(test_key),
            &slot_one);

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        TEST 2:
        Exactly one ACTIVE aircraft.
    */
    memset(
        &record,
        0,
        sizeof(record));

    slot = 0xFFFFU;

    err =
        mathos_fleet_get_active_status(
            &status,
            &slot,
            &record);

    if (err != ESP_OK ||
        status !=
            MATHOS_FLEET_ACTIVE_ONE ||
        slot != slot_one)
    {
        ESP_LOGE(
            TAG,
            "Fleet active-status self-test FAILED: "
            "ONE state incorrect");

        mathos_fleet_record_delete_slot(
            slot_one);

        return ESP_FAIL;
    }

    uint16_t slot_two =
        0xFFFFU;

    /*
        Add second ACTIVE aircraft.
    */
    err =
        mathos_fleet_add_aircraft(
            &uid_two,
            "Active Two",
            1U,
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY,
            test_key,
            sizeof(test_key),
            &slot_two);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            slot_one);

        return err;
    }

    /*
        TEST 3:
        Two ACTIVE aircraft must report MULTIPLE.

        No aircraft must be auto-selected.
    */
    memset(
        &record,
        0,
        sizeof(record));

    slot = 0xFFFFU;

    err =
        mathos_fleet_get_active_status(
            &status,
            &slot,
            &record);

    if (err != ESP_OK ||
        status !=
            MATHOS_FLEET_ACTIVE_MULTIPLE)
    {
        ESP_LOGE(
            TAG,
            "Fleet active-status self-test FAILED: "
            "expected MULTIPLE");

        mathos_fleet_record_delete_slot(
            slot_one);

        mathos_fleet_record_delete_slot(
            slot_two);

        return ESP_FAIL;
    }

    /*
        MULTIPLE must not expose a selected slot.
    */
    if (slot != 0xFFFFU)
    {
        ESP_LOGE(
            TAG,
            "Fleet active-status self-test FAILED: "
            "MULTIPLE exposed slot=%u",
            (unsigned int)slot);

        mathos_fleet_record_delete_slot(
            slot_one);

        mathos_fleet_record_delete_slot(
            slot_two);

        return ESP_FAIL;
    }

    /*
        Revoke second aircraft.

        We should return to exactly ONE ACTIVE aircraft.
    */
    err =
        mathos_fleet_revoke_aircraft(
            &uid_two);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            slot_one);

        mathos_fleet_record_delete_slot(
            slot_two);

        return err;
    }

    memset(
        &record,
        0,
        sizeof(record));

    slot = 0xFFFFU;

    err =
        mathos_fleet_get_active_status(
            &status,
            &slot,
            &record);

    if (err != ESP_OK ||
        status !=
            MATHOS_FLEET_ACTIVE_ONE ||
        slot != slot_one)
    {
        ESP_LOGE(
            TAG,
            "Fleet active-status self-test FAILED: "
            "REVOKE did not return Fleet to ONE");

        mathos_fleet_record_delete_slot(
            slot_one);

        mathos_fleet_record_delete_slot(
            slot_two);

        return ESP_FAIL;
    }

    /*
        Cleanup.
    */
    err =
        mathos_fleet_record_delete_slot(
            slot_one);

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        mathos_fleet_record_delete_slot(
            slot_two);

    if (err != ESP_OK)
    {
        return err;
    }

    ESP_LOGI(
        TAG,
        "Fleet active-status self-test PASSED "
        "NONE->ONE->MULTIPLE->ONE");

    return ESP_OK;
}
esp_err_t mathos_fleet_add_aircraft_self_test(void)
{
    /*
        Determine which slot should be allocated before
        we add anything.
    */
    uint16_t expected_slot = 0xFFFFU;

    esp_err_t err =
        mathos_fleet_find_free_slot(
            &expected_slot);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet add-aircraft self-test FAILED: "
            "cannot find free slot error=%s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Synthetic Gateway UID used only by this test.
    */
    mathos_device_uid_t test_uid =
        {
            .bytes =
                {
                    0x41,
                    0x42,
                    0x43,
                    0x44,
                    0x45,
                    0x46}};

    /*
        Make sure this synthetic UID is not already
        enrolled from an interrupted previous test.
    */
    uint16_t existing_slot = 0;

    mathos_fleet_record_t existing_record;

    memset(
        &existing_record,
        0,
        sizeof(existing_record));

    err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &existing_slot,
            &existing_record);

    if (err == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet add-aircraft self-test REFUSED: "
            "test UID already exists slot=%u",
            (unsigned int)existing_slot);

        return ESP_ERR_INVALID_STATE;
    }

    if (err != ESP_ERR_NOT_FOUND)
    {
        ESP_LOGE(
            TAG,
            "Fleet add-aircraft self-test FAILED: "
            "UID pre-check error=%s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Synthetic development Pair Key.
    */
    uint8_t test_pair_key[MATHOS_FLEET_PAIR_KEY_LEN];

    for (size_t i = 0;
         i < sizeof(test_pair_key);
         i++)
    {
        test_pair_key[i] =
            (uint8_t)(0x80U + i);
    }

    /*
        ADD first aircraft.
    */
    uint16_t assigned_slot = 0xFFFFU;

    err =
        mathos_fleet_add_aircraft(
            &test_uid,
            "Enrollment Test",
            1U,
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY,
            test_pair_key,
            sizeof(test_pair_key),
            &assigned_slot);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet add-aircraft self-test FAILED: "
            "initial ADD error=%s",
            esp_err_to_name(err));

        return err;
    }

    /*
        It must use the first free slot we saw before
        enrollment.
    */
    if (assigned_slot != expected_slot)
    {
        ESP_LOGE(
            TAG,
            "Fleet add-aircraft self-test FAILED: "
            "expected slot=%u assigned=%u",
            (unsigned int)expected_slot,
            (unsigned int)assigned_slot);

        mathos_fleet_record_delete_slot(
            assigned_slot);

        return ESP_FAIL;
    }

    /*
        Find it again using only the Gateway UID.
    */
    uint16_t found_slot = 0xFFFFU;

    mathos_fleet_record_t found_record;

    memset(
        &found_record,
        0,
        sizeof(found_record));

    err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &found_slot,
            &found_record);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet add-aircraft self-test FAILED: "
            "enrolled UID not found");

        mathos_fleet_record_delete_slot(
            assigned_slot);

        return err;
    }

    if (found_slot != assigned_slot)
    {
        ESP_LOGE(
            TAG,
            "Fleet add-aircraft self-test FAILED: "
            "lookup slot mismatch");

        mathos_fleet_record_delete_slot(
            assigned_slot);

        return ESP_FAIL;
    }

    if (found_record.state !=
        MATHOS_FLEET_STATE_ACTIVE)
    {
        ESP_LOGE(
            TAG,
            "Fleet add-aircraft self-test FAILED: "
            "record is not ACTIVE");

        mathos_fleet_record_delete_slot(
            assigned_slot);

        return ESP_FAIL;
    }

    /*
        Attempt to enroll the SAME physical Gateway again.

        This MUST fail.
    */
    uint16_t duplicate_slot = 0xFFFFU;

    err =
        mathos_fleet_add_aircraft(
            &test_uid,
            "Duplicate Test",
            1U,
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY,
            test_pair_key,
            sizeof(test_pair_key),
            &duplicate_slot);

    if (err != ESP_ERR_INVALID_STATE)
    {
        ESP_LOGE(
            TAG,
            "Fleet add-aircraft self-test FAILED: "
            "duplicate UID was not rejected "
            "error=%s",
            esp_err_to_name(err));

        mathos_fleet_record_delete_slot(
            assigned_slot);

        return ESP_FAIL;
    }

    /*
        Delete the enrolled aircraft.
    */
    err =
        mathos_fleet_record_delete_slot(
            assigned_slot);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet add-aircraft self-test FAILED: "
            "delete error=%s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Final proof:
        after DELETE, this UID must no longer exist.
    */
    memset(
        &found_record,
        0,
        sizeof(found_record));

    found_slot = 0xFFFFU;

    err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &found_slot,
            &found_record);

    if (err != ESP_ERR_NOT_FOUND)
    {
        ESP_LOGE(
            TAG,
            "Fleet add-aircraft self-test FAILED: "
            "deleted UID still exists");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Fleet add-aircraft self-test PASSED "
        "slot=%u add/find/duplicate-reject/delete OK",
        (unsigned int)assigned_slot);

    return ESP_OK;
}

esp_err_t mathos_fleet_store_verified_pairing(
    const mathos_device_uid_t *gateway_uid,
    const char *friendly_name,
    uint32_t key_generation,
    mathos_fleet_secret_format_t secret_format,
    const uint8_t *secret_blob,
    uint16_t secret_blob_len,
    mathos_fleet_pairing_store_result_t *result_out,
    uint16_t *slot_out)
{
    if (gateway_uid == NULL ||
        friendly_name == NULL ||
        secret_blob == NULL ||
        result_out == NULL ||
        slot_out == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    *result_out =
        MATHOS_FLEET_PAIRING_STORE_NONE;

    *slot_out =
        0xFFFFU;

    if (!mathos_device_uid_is_valid(
            gateway_uid))
    {
        return ESP_ERR_INVALID_ARG;
    }

    size_t name_len =
        strnlen(
            friendly_name,
            MATHOS_FLEET_FRIENDLY_NAME_LEN);

    if (name_len == 0U ||
        name_len >= MATHOS_FLEET_FRIENDLY_NAME_LEN ||
        key_generation == 0U ||
        secret_blob_len == 0U ||
        secret_blob_len >
            MATHOS_FLEET_SECRET_BLOB_MAX_LEN)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (secret_format ==
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY &&
        secret_blob_len !=
            MATHOS_FLEET_PAIR_KEY_LEN)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (secret_format !=
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY &&
        secret_format !=
            MATHOS_FLEET_SECRET_FORMAT_WRAPPED_PAIR_KEY_V1)
    {
        return ESP_ERR_INVALID_ARG;
    }

    uint16_t existing_slot =
        0xFFFFU;

    mathos_fleet_record_t existing_record;

    memset(
        &existing_record,
        0,
        sizeof(existing_record));

    esp_err_t err =
        mathos_fleet_find_by_uid(
            gateway_uid,
            &existing_slot,
            &existing_record);

    /*
        Unknown UID: create a new ACTIVE aircraft.
    */
    if (err == ESP_ERR_NOT_FOUND)
    {
        err =
            mathos_fleet_add_aircraft(
                gateway_uid,
                friendly_name,
                key_generation,
                secret_format,
                secret_blob,
                secret_blob_len,
                slot_out);

        if (err != ESP_OK)
        {
            return err;
        }

        *result_out =
            MATHOS_FLEET_PAIRING_STORE_ENROLLED;

        return ESP_OK;
    }

    /*
        Corruption or storage errors must propagate.
    */
    if (err != ESP_OK)
    {
        return err;
    }

    /*
        Pairing must never silently restore an aircraft
        that the owner explicitly revoked.
    */
    if (existing_record.state ==
        MATHOS_FLEET_STATE_REVOKED)
    {
        ESP_LOGW(
            TAG,
            "Fleet pairing commit rejected: "
            "Gateway UID is revoked slot=%u",
            (unsigned int)existing_slot);

        return ESP_ERR_INVALID_STATE;
    }

    if (existing_record.state !=
        MATHOS_FLEET_STATE_ACTIVE)
    {
        return ESP_ERR_INVALID_STATE;
    }

    /*
        Never replace a newer stored relationship with
        an older pairing generation.
    */
    if (key_generation <
        existing_record.key_generation)
    {
        ESP_LOGW(
            TAG,
            "Fleet pairing rollback rejected "
            "slot=%u stored=%lu received=%lu",
            (unsigned int)existing_slot,
            (unsigned long)
                existing_record.key_generation,
            (unsigned long)
                key_generation);

        return ESP_ERR_INVALID_STATE;
    }

    /*
        Same generation is accepted only when the stored
        credential matches exactly. This makes retries
        idempotent without permitting key replacement.
    */
    if (key_generation ==
        existing_record.key_generation)
    {
        int same_credential =
            existing_record.secret_format ==
                (uint8_t)secret_format &&

            existing_record.secret_blob_len ==
                secret_blob_len &&

            fleet_secret_matches(
                existing_record.secret_blob,
                secret_blob,
                secret_blob_len);

        if (!same_credential)
        {
            ESP_LOGW(
                TAG,
                "Fleet pairing conflict rejected "
                "slot=%u generation=%lu",
                (unsigned int)existing_slot,
                (unsigned long)key_generation);

            return ESP_ERR_INVALID_STATE;
        }

        *slot_out =
            existing_slot;

        *result_out =
            MATHOS_FLEET_PAIRING_STORE_UNCHANGED;

        ESP_LOGI(
            TAG,
            "Fleet pairing already current "
            "slot=%u generation=%lu",
            (unsigned int)existing_slot,
            (unsigned long)key_generation);

        return ESP_OK;
    }

    /*
        A higher authenticated generation rotates the
        credential in the existing Fleet slot.

        Preserve the owner's friendly name and state.
    */
    uint32_t previous_generation =
        existing_record.key_generation;

    existing_record.key_generation =
        key_generation;

    existing_record.secret_format =
        (uint8_t)secret_format;

    memset(
        existing_record.secret_blob,
        0,
        sizeof(existing_record.secret_blob));

    memcpy(
        existing_record.secret_blob,
        secret_blob,
        secret_blob_len);

    existing_record.secret_blob_len =
        secret_blob_len;

    err =
        mathos_fleet_record_save_slot(
            existing_slot,
            &existing_record);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet pairing rotation failed "
            "slot=%u error=%s",
            (unsigned int)existing_slot,
            esp_err_to_name(err));

        return err;
    }

    /*
        Verify the authoritative UID lookup after writing.
    */
    uint16_t verified_slot =
        0xFFFFU;

    mathos_fleet_record_t verified_record;

    memset(
        &verified_record,
        0,
        sizeof(verified_record));

    err =
        mathos_fleet_find_by_uid(
            gateway_uid,
            &verified_slot,
            &verified_record);

    if (err != ESP_OK)
    {
        return err;
    }

    if (verified_slot != existing_slot ||
        verified_record.state !=
            MATHOS_FLEET_STATE_ACTIVE ||
        verified_record.key_generation !=
            key_generation ||
        verified_record.secret_format !=
            (uint8_t)secret_format ||
        verified_record.secret_blob_len !=
            secret_blob_len ||
        !fleet_secret_matches(
            verified_record.secret_blob,
            secret_blob,
            secret_blob_len))
    {
        ESP_LOGE(
            TAG,
            "Fleet pairing rotation verification failed "
            "slot=%u",
            (unsigned int)existing_slot);

        return ESP_FAIL;
    }

    *slot_out =
        existing_slot;

    *result_out =
        MATHOS_FLEET_PAIRING_STORE_ROTATED;

    ESP_LOGI(
        TAG,
        "Fleet pairing credential rotated "
        "slot=%u generation=%lu->%lu",
        (unsigned int)existing_slot,
        (unsigned long)previous_generation,
        (unsigned long)key_generation);

    return ESP_OK;
}

esp_err_t mathos_fleet_get_authorization(
    const mathos_device_uid_t *gateway_uid,
    mathos_fleet_auth_status_t *status_out,
    uint16_t *slot_out,
    mathos_fleet_record_t *record_out)
{
    if (gateway_uid == NULL ||
        status_out == NULL ||
        slot_out == NULL ||
        record_out == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    *status_out =
        MATHOS_FLEET_AUTH_UNKNOWN;

    *slot_out =
        0xFFFFU;

    memset(
        record_out,
        0,
        sizeof(*record_out));

    uint16_t slot = 0xFFFFU;

    mathos_fleet_record_t record;

    memset(
        &record,
        0,
        sizeof(record));

    esp_err_t err =
        mathos_fleet_find_by_uid(
            gateway_uid,
            &slot,
            &record);

    /*
        Unknown Gateway is not a storage error.

        It is simply not enrolled.
    */
    if (err == ESP_ERR_NOT_FOUND)
    {
        *status_out =
            MATHOS_FLEET_AUTH_UNKNOWN;

        return ESP_OK;
    }

    /*
        Corruption/read failure must propagate.
    */
    if (err != ESP_OK)
    {
        return err;
    }

    switch ((mathos_fleet_state_t)
                record.state)
    {
    case MATHOS_FLEET_STATE_ACTIVE:

        *status_out =
            MATHOS_FLEET_AUTH_ACTIVE;
        break;

    case MATHOS_FLEET_STATE_REVOKED:

        *status_out =
            MATHOS_FLEET_AUTH_REVOKED;
        break;

    default:

        return ESP_ERR_INVALID_STATE;
    }

    *slot_out =
        slot;

    *record_out =
        record;

    return ESP_OK;
}

const char *mathos_fleet_auth_status_to_string(
    mathos_fleet_auth_status_t status)
{
    switch (status)
    {
    case MATHOS_FLEET_AUTH_UNKNOWN:
        return "UNKNOWN";

    case MATHOS_FLEET_AUTH_ACTIVE:
        return "ACTIVE";

    case MATHOS_FLEET_AUTH_REVOKED:
        return "REVOKED";

    default:
        return "INVALID";
    }
}
esp_err_t mathos_fleet_authorization_self_test(void)
{
    mathos_device_uid_t test_uid =
        {
            .bytes =
                {
                    0xA1, 0xA2, 0xA3,
                    0xA4, 0xA5, 0xA6}};

    mathos_fleet_auth_status_t status =
        MATHOS_FLEET_AUTH_UNKNOWN;

    uint16_t slot =
        0xFFFFU;

    mathos_fleet_record_t record;

    memset(
        &record,
        0,
        sizeof(record));

    /*
        1. Unknown UID.
    */
    esp_err_t err =
        mathos_fleet_get_authorization(
            &test_uid,
            &status,
            &slot,
            &record);

    if (err != ESP_OK ||
        status != MATHOS_FLEET_AUTH_UNKNOWN)
    {
        ESP_LOGE(
            TAG,
            "Fleet authorization self-test FAILED: "
            "expected UNKNOWN");

        return ESP_FAIL;
    }

    /*
        UNKNOWN must not expose a Fleet slot.
    */
    if (slot != 0xFFFFU)
    {
        ESP_LOGE(
            TAG,
            "Fleet authorization self-test FAILED: "
            "UNKNOWN exposed slot=%u",
            (unsigned int)slot);

        return ESP_FAIL;
    }

    uint8_t test_key[MATHOS_FLEET_PAIR_KEY_LEN];

    for (size_t i = 0;
         i < sizeof(test_key);
         i++)
    {
        test_key[i] =
            (uint8_t)(0xD0U + i);
    }

    uint16_t enrolled_slot =
        0xFFFFU;

    /*
        2. Enroll aircraft.
    */
    err =
        mathos_fleet_add_aircraft(
            &test_uid,
            "Authorization Test",
            1U,
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY,
            test_key,
            sizeof(test_key),
            &enrolled_slot);

    if (err != ESP_OK)
    {
        return err;
    }

    memset(
        &record,
        0,
        sizeof(record));

    slot =
        0xFFFFU;

    err =
        mathos_fleet_get_authorization(
            &test_uid,
            &status,
            &slot,
            &record);

    if (err != ESP_OK ||
        status != MATHOS_FLEET_AUTH_ACTIVE ||
        slot != enrolled_slot)
    {
        ESP_LOGE(
            TAG,
            "Fleet authorization self-test FAILED: "
            "expected ACTIVE");

        mathos_fleet_record_delete_slot(
            enrolled_slot);

        return ESP_FAIL;
    }

    /*
        3. Revoke aircraft.
    */
    err =
        mathos_fleet_revoke_aircraft(
            &test_uid);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            enrolled_slot);

        return err;
    }

    memset(
        &record,
        0,
        sizeof(record));

    slot =
        0xFFFFU;

    err =
        mathos_fleet_get_authorization(
            &test_uid,
            &status,
            &slot,
            &record);

    if (err != ESP_OK ||
        status != MATHOS_FLEET_AUTH_REVOKED ||
        slot != enrolled_slot)
    {
        ESP_LOGE(
            TAG,
            "Fleet authorization self-test FAILED: "
            "expected REVOKED");

        mathos_fleet_record_delete_slot(
            enrolled_slot);

        return ESP_FAIL;
    }

    /*
        Cleanup.
    */
    err =
        mathos_fleet_record_delete_slot(
            enrolled_slot);

    if (err != ESP_OK)
    {
        return err;
    }

    ESP_LOGI(
        TAG,
        "Fleet authorization self-test PASSED "
        "UNKNOWN->ACTIVE->REVOKED");

    return ESP_OK;
}
esp_err_t mathos_fleet_counts_self_test(void)
{
    /*
        Test assumes its synthetic UIDs are not already
        enrolled.
    */
    mathos_device_uid_t uid_active =
        {
            .bytes =
                {
                    0x61, 0x62, 0x63,
                    0x64, 0x65, 0x66}};

    mathos_device_uid_t uid_revoked =
        {
            .bytes =
                {
                    0x71, 0x72, 0x73,
                    0x74, 0x75, 0x76}};

    mathos_fleet_counts_t before;

    esp_err_t err =
        mathos_fleet_get_counts(
            &before);

    if (err != ESP_OK)
    {
        return err;
    }

    uint8_t test_key[MATHOS_FLEET_PAIR_KEY_LEN];

    for (size_t i = 0;
         i < sizeof(test_key);
         i++)
    {
        test_key[i] =
            (uint8_t)(0xB0U + i);
    }

    uint16_t slot_active = 0xFFFFU;

    err =
        mathos_fleet_add_aircraft(
            &uid_active,
            "Count Active",
            1U,
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY,
            test_key,
            sizeof(test_key),
            &slot_active);

    if (err != ESP_OK)
    {
        return err;
    }

    uint16_t slot_revoked = 0xFFFFU;

    err =
        mathos_fleet_add_aircraft(
            &uid_revoked,
            "Count Revoked",
            1U,
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY,
            test_key,
            sizeof(test_key),
            &slot_revoked);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            slot_active);

        return err;
    }

    err =
        mathos_fleet_revoke_aircraft(
            &uid_revoked);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            slot_active);

        mathos_fleet_record_delete_slot(
            slot_revoked);

        return err;
    }

    mathos_fleet_counts_t after;

    err =
        mathos_fleet_get_counts(
            &after);

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            slot_active);

        mathos_fleet_record_delete_slot(
            slot_revoked);

        return err;
    }

    /*
        We added:
            +2 total
            +1 active
            +1 revoked
            -2 free
    */
    if (after.total !=
            (uint16_t)(before.total + 2U) ||
        after.active !=
            (uint16_t)(before.active + 1U) ||
        after.revoked !=
            (uint16_t)(before.revoked + 1U) ||
        after.free_slots !=
            (uint16_t)(before.free_slots - 2U))
    {
        ESP_LOGE(
            TAG,
            "Fleet count self-test FAILED "
            "before=%u/%u/%u/%u "
            "after=%u/%u/%u/%u",
            (unsigned int)before.total,
            (unsigned int)before.active,
            (unsigned int)before.revoked,
            (unsigned int)before.free_slots,
            (unsigned int)after.total,
            (unsigned int)after.active,
            (unsigned int)after.revoked,
            (unsigned int)after.free_slots);

        mathos_fleet_record_delete_slot(
            slot_active);

        mathos_fleet_record_delete_slot(
            slot_revoked);

        return ESP_FAIL;
    }

    err =
        mathos_fleet_record_delete_slot(
            slot_active);

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        mathos_fleet_record_delete_slot(
            slot_revoked);

    if (err != ESP_OK)
    {
        return err;
    }

    ESP_LOGI(
        TAG,
        "Fleet count self-test PASSED "
        "total=%u active=%u revoked=%u free=%u",
        (unsigned int)after.total,
        (unsigned int)after.active,
        (unsigned int)after.revoked,
        (unsigned int)after.free_slots);

    return ESP_OK;
}

esp_err_t mathos_fleet_add_aircraft(
    const mathos_device_uid_t *gateway_uid,
    const char *friendly_name,
    uint32_t key_generation,
    mathos_fleet_secret_format_t secret_format,
    const uint8_t *secret_blob,
    uint16_t secret_blob_len,
    uint16_t *slot_out)
{
    if (gateway_uid == NULL ||
        friendly_name == NULL ||
        secret_blob == NULL ||
        slot_out == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (!mathos_device_uid_is_valid(
            gateway_uid))
    {
        return ESP_ERR_INVALID_ARG;
    }

    size_t name_len =
        strnlen(
            friendly_name,
            MATHOS_FLEET_FRIENDLY_NAME_LEN);

    /*
        Name must be non-empty and fit completely
        inside the Fleet record.
    */
    if (name_len == 0U ||
        name_len >= MATHOS_FLEET_FRIENDLY_NAME_LEN)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (key_generation == 0U)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (secret_blob_len == 0U ||
        secret_blob_len >
            MATHOS_FLEET_SECRET_BLOB_MAX_LEN)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Development raw Pair Key must be exactly
        32 bytes.
    */
    if (secret_format ==
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY &&
        secret_blob_len !=
            MATHOS_FLEET_PAIR_KEY_LEN)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (secret_format !=
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY &&
        secret_format !=
            MATHOS_FLEET_SECRET_FORMAT_WRAPPED_PAIR_KEY_V1)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Reject duplicate Gateway UID.

        We do not allow the same physical Gateway
        to silently occupy multiple Fleet slots.
    */
    uint16_t existing_slot = 0;

    mathos_fleet_record_t existing_record;

    memset(
        &existing_record,
        0,
        sizeof(existing_record));

    esp_err_t err =
        mathos_fleet_find_by_uid(
            gateway_uid,
            &existing_slot,
            &existing_record);

    if (err == ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "Fleet add rejected: Gateway UID "
            "already enrolled slot=%u state=%s",
            (unsigned int)existing_slot,
            mathos_fleet_state_to_string(
                (mathos_fleet_state_t)
                    existing_record.state));

        return ESP_ERR_INVALID_STATE;
    }

    if (err != ESP_ERR_NOT_FOUND)
    {
        /*
            Search failure/corruption must propagate.
        */
        return err;
    }

    /*
        Find storage location.
    */
    uint16_t free_slot = 0;

    err =
        mathos_fleet_find_free_slot(
            &free_slot);

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        Construct the new ACTIVE aircraft record.
    */
    mathos_fleet_record_t record;

    mathos_fleet_record_set_defaults(
        &record);

    record.gateway_uid =
        *gateway_uid;

    record.state =
        MATHOS_FLEET_STATE_ACTIVE;

    record.secret_format =
        (uint8_t)secret_format;

    memcpy(
        record.friendly_name,
        friendly_name,
        name_len);

    record.friendly_name[name_len] =
        '\0';

    record.key_generation =
        key_generation;

    record.security_counter =
        0U;

    record.secret_blob_len =
        secret_blob_len;

    memcpy(
        record.secret_blob,
        secret_blob,
        secret_blob_len);

    /*
        save_slot() will increment:
            record_counter 0 -> 1

        and calculate the CRC before committing.
    */
    record.record_counter =
        0U;

    err =
        mathos_fleet_record_save_slot(
            free_slot,
            &record);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet add failed slot=%u error=%s",
            (unsigned int)free_slot,
            esp_err_to_name(err));

        return err;
    }

    /*
        Final lookup proof using the authoritative UID.
    */
    uint16_t verified_slot = 0;

    mathos_fleet_record_t verified_record;

    memset(
        &verified_record,
        0,
        sizeof(verified_record));

    err =
        mathos_fleet_find_by_uid(
            gateway_uid,
            &verified_slot,
            &verified_record);

    if (err != ESP_OK ||
        verified_slot != free_slot)
    {
        ESP_LOGE(
            TAG,
            "Fleet add verification failed "
            "expected_slot=%u",
            (unsigned int)free_slot);

        return ESP_FAIL;
    }

    *slot_out =
        free_slot;

    ESP_LOGI(
        TAG,
        "Aircraft enrolled slot=%u "
        "name=%s generation=%lu state=ACTIVE",
        (unsigned int)free_slot,
        record.friendly_name,
        (unsigned long)record.key_generation);

    return ESP_OK;
}

esp_err_t mathos_fleet_revoke_aircraft(
    const mathos_device_uid_t *gateway_uid)
{
    if (gateway_uid == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    uint16_t slot = 0;

    mathos_fleet_record_t record;

    memset(
        &record,
        0,
        sizeof(record));

    esp_err_t err =
        mathos_fleet_find_by_uid(
            gateway_uid,
            &slot,
            &record);

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        Already revoked.
    */
    if (record.state ==
        MATHOS_FLEET_STATE_REVOKED)
    {
        return ESP_ERR_INVALID_STATE;
    }

    if (record.state !=
        MATHOS_FLEET_STATE_ACTIVE)
    {
        return ESP_ERR_INVALID_STATE;
    }

    record.state =
        MATHOS_FLEET_STATE_REVOKED;

    /*
        save_slot() increments record_counter
        and recalculates CRC.
    */
    err =
        mathos_fleet_record_save_slot(
            slot,
            &record);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke failed slot=%u error=%s",
            (unsigned int)slot,
            esp_err_to_name(err));

        return err;
    }

    ESP_LOGW(
        TAG,
        "Aircraft REVOKED slot=%u name=%s",
        (unsigned int)slot,
        record.friendly_name);

    return ESP_OK;
}
esp_err_t mathos_fleet_restore_aircraft(
    const mathos_device_uid_t *gateway_uid)
{
    if (gateway_uid == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    uint16_t slot = 0;

    mathos_fleet_record_t record;

    memset(
        &record,
        0,
        sizeof(record));

    esp_err_t err =
        mathos_fleet_find_by_uid(
            gateway_uid,
            &slot,
            &record);

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        Only REVOKED aircraft may be restored.
    */
    if (record.state !=
        MATHOS_FLEET_STATE_REVOKED)
    {
        return ESP_ERR_INVALID_STATE;
    }

    record.state =
        MATHOS_FLEET_STATE_ACTIVE;

    err =
        mathos_fleet_record_save_slot(
            slot,
            &record);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet restore failed slot=%u error=%s",
            (unsigned int)slot,
            esp_err_to_name(err));

        return err;
    }

    ESP_LOGI(
        TAG,
        "Aircraft RESTORED slot=%u name=%s",
        (unsigned int)slot,
        record.friendly_name);

    return ESP_OK;
}

esp_err_t mathos_fleet_revoke_restore_self_test(void)
{
    /*
        Synthetic Gateway used only by this test.
    */
    mathos_device_uid_t test_uid =
        {
            .bytes =
                {
                    0x51,
                    0x52,
                    0x53,
                    0x54,
                    0x55,
                    0x56}};

    /*
        Ensure this test UID is not already enrolled.
    */
    uint16_t existing_slot = 0;

    mathos_fleet_record_t existing_record;

    memset(
        &existing_record,
        0,
        sizeof(existing_record));

    esp_err_t err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &existing_slot,
            &existing_record);

    if (err == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test REFUSED: "
            "test UID already exists slot=%u",
            (unsigned int)existing_slot);

        return ESP_ERR_INVALID_STATE;
    }

    if (err != ESP_ERR_NOT_FOUND)
    {
        return err;
    }

    /*
        Synthetic development Pair Key.
    */
    uint8_t test_pair_key[MATHOS_FLEET_PAIR_KEY_LEN];

    for (size_t i = 0;
         i < sizeof(test_pair_key);
         i++)
    {
        test_pair_key[i] =
            (uint8_t)(0x90U + i);
    }

    /*
        1. ADD
    */
    uint16_t slot = 0xFFFFU;

    err =
        mathos_fleet_add_aircraft(
            &test_uid,
            "Lifecycle Test",
            1U,
            MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY,
            test_pair_key,
            sizeof(test_pair_key),
            &slot);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test "
            "ADD FAILED: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        2. REVOKE
    */
    err =
        mathos_fleet_revoke_aircraft(
            &test_uid);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test "
            "REVOKE FAILED: %s",
            esp_err_to_name(err));

        mathos_fleet_record_delete_slot(slot);

        return err;
    }

    /*
        Verify persistent REVOKED state.
    */
    uint16_t found_slot = 0;

    mathos_fleet_record_t record;

    memset(
        &record,
        0,
        sizeof(record));

    err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &found_slot,
            &record);

    if (err != ESP_OK ||
        found_slot != slot ||
        record.state !=
            MATHOS_FLEET_STATE_REVOKED)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test FAILED: "
            "REVOKED state not persisted");

        mathos_fleet_record_delete_slot(slot);

        return ESP_FAIL;
    }

    /*
        ADD initially stored counter=1.
        REVOKE must have advanced it to 2.
    */
    if (record.record_counter != 2U)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test FAILED: "
            "revoke counter=%lu expected=2",
            (unsigned long)record.record_counter);

        mathos_fleet_record_delete_slot(slot);

        return ESP_FAIL;
    }

    /*
        3. Duplicate REVOKE must fail.
    */
    err =
        mathos_fleet_revoke_aircraft(
            &test_uid);

    if (err != ESP_ERR_INVALID_STATE)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test FAILED: "
            "duplicate REVOKE accepted");

        mathos_fleet_record_delete_slot(slot);

        return ESP_FAIL;
    }

    /*
        4. RESTORE
    */
    err =
        mathos_fleet_restore_aircraft(
            &test_uid);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test "
            "RESTORE FAILED: %s",
            esp_err_to_name(err));

        mathos_fleet_record_delete_slot(slot);

        return err;
    }

    /*
        Verify persistent ACTIVE state.
    */
    memset(
        &record,
        0,
        sizeof(record));

    err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &found_slot,
            &record);

    if (err != ESP_OK ||
        record.state !=
            MATHOS_FLEET_STATE_ACTIVE)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test FAILED: "
            "ACTIVE state not restored");

        mathos_fleet_record_delete_slot(slot);

        return ESP_FAIL;
    }

    /*
        RESTORE must advance counter:
            ADD     = 1
            REVOKE  = 2
            RESTORE = 3
    */
    if (record.record_counter != 3U)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test FAILED: "
            "restore counter=%lu expected=3",
            (unsigned long)record.record_counter);

        mathos_fleet_record_delete_slot(slot);

        return ESP_FAIL;
    }

    /*
        5. Duplicate RESTORE must fail.
    */
    err =
        mathos_fleet_restore_aircraft(
            &test_uid);

    if (err != ESP_ERR_INVALID_STATE)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test FAILED: "
            "duplicate RESTORE accepted");

        mathos_fleet_record_delete_slot(slot);

        return ESP_FAIL;
    }

    /*
        6. DELETE test aircraft.
    */
    err =
        mathos_fleet_record_delete_slot(
            slot);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test "
            "DELETE FAILED: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Final proof that the UID disappeared.
    */
    memset(
        &record,
        0,
        sizeof(record));

    err =
        mathos_fleet_find_by_uid(
            &test_uid,
            &found_slot,
            &record);

    if (err != ESP_ERR_NOT_FOUND)
    {
        ESP_LOGE(
            TAG,
            "Fleet revoke/restore self-test FAILED: "
            "deleted UID still exists");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Fleet revoke/restore self-test PASSED "
        "slot=%u ACTIVE->REVOKED->ACTIVE "
        "counter=1->2->3",
        (unsigned int)slot);

    return ESP_OK;
}

esp_err_t mathos_fleet_free_slot_self_test(void)
{
    uint16_t slot = 0xFFFFU;

    esp_err_t err =
        mathos_fleet_find_free_slot(
            &slot);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet free-slot self-test FAILED: %s",
            esp_err_to_name(err));

        return err;
    }

    if (slot >= MATHOS_FLEET_MAX_AIRCRAFT)
    {
        ESP_LOGE(
            TAG,
            "Fleet free-slot self-test FAILED: "
            "invalid slot=%u",
            (unsigned int)slot);

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Fleet free-slot self-test PASSED "
        "first_free_slot=%u",
        (unsigned int)slot);

    return ESP_OK;
}

esp_err_t mathos_fleet_uid_lookup_self_test(void)
{
    const uint16_t test_slot =
        MATHOS_FLEET_MAX_AIRCRAFT - 1U;

    /*
        First prove our temporary slot is empty.
    */
    mathos_fleet_record_t existing;

    memset(
        &existing,
        0,
        sizeof(existing));

    esp_err_t err =
        mathos_fleet_record_load_slot(
            test_slot,
            &existing);

    if (err == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet UID lookup self-test REFUSED: "
            "slot=%u already occupied",
            (unsigned int)test_slot);

        return ESP_ERR_INVALID_STATE;
    }

    if (err != ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGE(
            TAG,
            "Fleet UID lookup self-test cannot inspect "
            "slot=%u error=%s",
            (unsigned int)test_slot,
            esp_err_to_name(err));

        return err;
    }

    /*
        Create synthetic enrolled aircraft.
    */
    mathos_fleet_record_t source;

    mathos_fleet_record_set_defaults(
        &source);

    const uint8_t known_uid[MATHOS_DEVICE_UID_LEN] =
        {
            0x21,
            0x22,
            0x23,
            0x24,
            0x25,
            0x26};

    memcpy(
        source.gateway_uid.bytes,
        known_uid,
        sizeof(known_uid));

    source.state =
        MATHOS_FLEET_STATE_ACTIVE;

    source.secret_format =
        MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY;

    strncpy(
        source.friendly_name,
        "UID Lookup Test",
        sizeof(source.friendly_name) - 1U);

    source.key_generation = 1U;

    source.secret_blob_len =
        MATHOS_FLEET_PAIR_KEY_LEN;

    for (size_t i = 0;
         i < MATHOS_FLEET_PAIR_KEY_LEN;
         i++)
    {
        source.secret_blob[i] =
            (uint8_t)(0x60U + i);
    }

    source.record_counter = 0U;

    /*
        save_slot() calculates the final CRC and
        increments record_counter.
    */
    err =
        mathos_fleet_record_save_slot(
            test_slot,
            &source);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet UID lookup self-test SAVE FAILED: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Search using ONLY the Gateway UID.
    */
    uint16_t found_slot = 0;

    mathos_fleet_record_t found;

    memset(
        &found,
        0,
        sizeof(found));

    err =
        mathos_fleet_find_by_uid(
            &source.gateway_uid,
            &found_slot,
            &found);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet UID lookup self-test FAILED: "
            "known UID not found error=%s",
            esp_err_to_name(err));

        mathos_fleet_record_delete_slot(
            test_slot);

        return err;
    }

    if (found_slot != test_slot)
    {
        ESP_LOGE(
            TAG,
            "Fleet UID lookup self-test FAILED: "
            "expected slot=%u found=%u",
            (unsigned int)test_slot,
            (unsigned int)found_slot);

        mathos_fleet_record_delete_slot(
            test_slot);

        return ESP_FAIL;
    }

    /*
        Verify returned record matches what was stored.
    */
    uint8_t source_wire[MATHOS_FLEET_RECORD_WIRE_LEN];

    uint8_t found_wire[MATHOS_FLEET_RECORD_WIRE_LEN];

    err =
        mathos_fleet_record_encode(
            &source,
            source_wire,
            sizeof(source_wire));

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            test_slot);

        return err;
    }

    err =
        mathos_fleet_record_encode(
            &found,
            found_wire,
            sizeof(found_wire));

    if (err != ESP_OK)
    {
        mathos_fleet_record_delete_slot(
            test_slot);

        return err;
    }

    if (memcmp(
            source_wire,
            found_wire,
            sizeof(source_wire)) != 0)
    {
        ESP_LOGE(
            TAG,
            "Fleet UID lookup self-test FAILED: "
            "returned record mismatch");

        mathos_fleet_record_delete_slot(
            test_slot);

        return ESP_FAIL;
    }

    /*
        Now search for a UID that is NOT enrolled.
    */
    mathos_device_uid_t unknown_uid =
        {
            .bytes =
                {
                    0x31,
                    0x32,
                    0x33,
                    0x34,
                    0x35,
                    0x36}};

    memset(
        &found,
        0,
        sizeof(found));

    found_slot = 0;

    err =
        mathos_fleet_find_by_uid(
            &unknown_uid,
            &found_slot,
            &found);

    if (err != ESP_ERR_NOT_FOUND)
    {
        ESP_LOGE(
            TAG,
            "Fleet UID lookup self-test FAILED: "
            "unknown UID was not rejected");

        mathos_fleet_record_delete_slot(
            test_slot);

        return ESP_FAIL;
    }

    /*
        Remove temporary aircraft.
    */
    err =
        mathos_fleet_record_delete_slot(
            test_slot);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet UID lookup self-test DELETE FAILED: %s",
            esp_err_to_name(err));

        return err;
    }

    ESP_LOGI(
        TAG,
        "Fleet UID lookup self-test PASSED "
        "known_uid->slot=%u unknown_uid->NOT_FOUND",
        (unsigned int)test_slot);

    return ESP_OK;
}

esp_err_t mathos_fleet_record_delete_slot(
    uint16_t slot)
{
    char key[8];

    esp_err_t err =
        fleet_make_slot_key(
            slot,
            key,
            sizeof(key));

    if (err != ESP_OK)
    {
        return err;
    }

    nvs_handle_t handle;

    err =
        nvs_open_from_partition(
            MATHOS_FLEET_PARTITION_NAME,
            MATHOS_FLEET_NAMESPACE,
            NVS_READWRITE,
            &handle);

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        nvs_erase_key(
            handle,
            key);

    if (err != ESP_OK)
    {
        nvs_close(handle);
        return err;
    }

    err =
        nvs_commit(handle);

    nvs_close(handle);

    if (err == ESP_OK)
    {
        ESP_LOGI(
            TAG,
            "Fleet record deleted slot=%u",
            (unsigned int)slot);
    }

    return err;
}
esp_err_t mathos_fleet_persistence_self_test(void)
{
    /*
        Temporary development slot.

        We first ensure it is EMPTY so this test
        can never erase a legitimate aircraft.
    */
    const uint16_t test_slot =
        MATHOS_FLEET_MAX_AIRCRAFT - 1U;

    mathos_fleet_record_t existing;

    memset(
        &existing,
        0,
        sizeof(existing));

    esp_err_t err =
        mathos_fleet_record_load_slot(
            test_slot,
            &existing);

    if (err == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet persistence self-test REFUSED: "
            "test slot %u already occupied",
            (unsigned int)test_slot);

        return ESP_ERR_INVALID_STATE;
    }

    if (err != ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGE(
            TAG,
            "Fleet persistence self-test cannot inspect "
            "test slot error=%s",
            esp_err_to_name(err));

        return err;
    }

    mathos_fleet_record_t source;

    mathos_fleet_record_set_defaults(
        &source);

    const uint8_t uid[MATHOS_DEVICE_UID_LEN] =
        {
            0x91,
            0x92,
            0x93,
            0x94,
            0x95,
            0x96};

    memcpy(
        source.gateway_uid.bytes,
        uid,
        sizeof(uid));

    source.state =
        MATHOS_FLEET_STATE_ACTIVE;

    source.secret_format =
        MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY;

    strncpy(
        source.friendly_name,
        "Persistence Test",
        sizeof(source.friendly_name) - 1U);

    source.key_generation = 1U;

    source.secret_blob_len =
        MATHOS_FLEET_PAIR_KEY_LEN;

    for (size_t i = 0;
         i < MATHOS_FLEET_PAIR_KEY_LEN;
         i++)
    {
        source.secret_blob[i] =
            (uint8_t)(0x40U + i);
    }

    /*
        save_slot() will change this:
            0 -> 1
    */
    source.record_counter = 0U;

    err =
        mathos_fleet_record_save_slot(
            test_slot,
            &source);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet persistence self-test SAVE FAILED: %s",
            esp_err_to_name(err));

        return err;
    }

    mathos_fleet_record_t loaded;

    memset(
        &loaded,
        0,
        sizeof(loaded));

    err =
        mathos_fleet_record_load_slot(
            test_slot,
            &loaded);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet persistence self-test LOAD FAILED: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Compare canonical bytes, never raw C structs.
    */
    uint8_t source_wire[MATHOS_FLEET_RECORD_WIRE_LEN];

    uint8_t loaded_wire[MATHOS_FLEET_RECORD_WIRE_LEN];

    err =
        mathos_fleet_record_encode(
            &source,
            source_wire,
            sizeof(source_wire));

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        mathos_fleet_record_encode(
            &loaded,
            loaded_wire,
            sizeof(loaded_wire));

    if (err != ESP_OK)
    {
        return err;
    }

    if (memcmp(
            source_wire,
            loaded_wire,
            sizeof(source_wire)) != 0)
    {
        ESP_LOGE(
            TAG,
            "Fleet persistence self-test FAILED: "
            "loaded record differs");

        return ESP_FAIL;
    }

    err =
        mathos_fleet_record_delete_slot(
            test_slot);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet persistence self-test DELETE FAILED: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Final proof that deletion really persisted.
    */
    memset(
        &loaded,
        0,
        sizeof(loaded));

    err =
        mathos_fleet_record_load_slot(
            test_slot,
            &loaded);

    if (err != ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGE(
            TAG,
            "Fleet persistence self-test FAILED: "
            "deleted slot still readable");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Fleet persistence self-test PASSED "
        "slot=%u write/read/verify/delete OK",
        (unsigned int)test_slot);

    return ESP_OK;
}
const char *mathos_fleet_state_to_string(
    mathos_fleet_state_t state)
{
    switch (state)
    {
    case MATHOS_FLEET_STATE_EMPTY:
        return "EMPTY";

    case MATHOS_FLEET_STATE_ACTIVE:
        return "ACTIVE";

    case MATHOS_FLEET_STATE_REVOKED:
        return "REVOKED";

    default:
        return "UNKNOWN";
    }
}

esp_err_t mathos_fleet_init(void)
{
    /*
        Initialize only the dedicated "fleet" partition.

        This is independent from the normal default NVS
        partition already initialized by the RC.
    */
    esp_err_t err =
        nvs_flash_init_partition(
            MATHOS_FLEET_PARTITION_NAME);

    /*
        Never erase the Fleet partition automatically.

        It contains aircraft identities, Pair Keys and
        revocation state. Recovery must require an explicit
        physical maintenance action.
    */
    if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
        err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_LOGE(
            TAG,
            "Fleet partition requires explicit recovery "
            "error=%s. Automatic erase is forbidden.",
            esp_err_to_name(err));

        return err;
    }

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet partition initialization failed: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Smoke-test that the dedicated namespace can
        actually be opened.
    */
    nvs_handle_t handle;

    err =
        nvs_open_from_partition(
            MATHOS_FLEET_PARTITION_NAME,
            MATHOS_FLEET_NAMESPACE,
            NVS_READWRITE,
            &handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet namespace open failed: %s",
            esp_err_to_name(err));

        return err;
    }

    nvs_close(handle);
    err =
        mathos_fleet_record_self_test();

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Fleet record format self-test FAILED: %s",
            esp_err_to_name(err));

        return err;
    }
    ESP_LOGI(
        TAG,
        "Fleet Store ready partition=%s namespace=%s",
        MATHOS_FLEET_PARTITION_NAME,
        MATHOS_FLEET_NAMESPACE);

    return ESP_OK;
}