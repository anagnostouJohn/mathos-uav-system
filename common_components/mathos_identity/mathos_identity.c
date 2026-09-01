#include "mathos_identity.h"

#include <stdio.h>
#include <string.h>

#include "esp_mac.h"

int mathos_device_uid_is_valid(
    const mathos_device_uid_t *uid)
{
    if (uid == NULL)
    {
        return 0;
    }

    int all_zero = 1;
    int all_ff = 1;

    for (size_t i = 0;
         i < MATHOS_DEVICE_UID_LEN;
         i++)
    {
        if (uid->bytes[i] != 0x00U)
        {
            all_zero = 0;
        }

        if (uid->bytes[i] != 0xFFU)
        {
            all_ff = 0;
        }
    }

    return !all_zero && !all_ff;
}

esp_err_t mathos_device_uid_read(
    mathos_device_uid_t *uid)
{
    if (uid == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    memset(
        uid,
        0,
        sizeof(*uid));

    esp_err_t err =
        esp_efuse_mac_get_default(
            uid->bytes);

    if (err != ESP_OK)
    {
        memset(
            uid,
            0,
            sizeof(*uid));

        return err;
    }

    if (!mathos_device_uid_is_valid(uid))
    {
        memset(
            uid,
            0,
            sizeof(*uid));

        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t mathos_device_uid_format(
    const mathos_device_uid_t *uid,
    char *buffer,
    size_t buffer_size)
{
    if (uid == NULL ||
        buffer == NULL ||
        buffer_size <
            MATHOS_DEVICE_UID_TEXT_LEN)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (!mathos_device_uid_is_valid(uid))
    {
        return ESP_ERR_INVALID_STATE;
    }

    int written =
        snprintf(
            buffer,
            buffer_size,
            "%02X:%02X:%02X:%02X:%02X:%02X",
            uid->bytes[0],
            uid->bytes[1],
            uid->bytes[2],
            uid->bytes[3],
            uid->bytes[4],
            uid->bytes[5]);

    if (written !=
        (MATHOS_DEVICE_UID_TEXT_LEN - 1))
    {
        buffer[0] = '\0';
        return ESP_FAIL;
    }

    return ESP_OK;
}