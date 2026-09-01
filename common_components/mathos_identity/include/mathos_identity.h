#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MATHOS_DEVICE_UID_LEN 6U
#define MATHOS_DEVICE_UID_TEXT_LEN 18U

typedef struct
{
    uint8_t bytes[MATHOS_DEVICE_UID_LEN];
} mathos_device_uid_t;

/*
    Read the immutable factory-programmed ESP32 identity.

    For now this is the Espressif factory base MAC
    stored in eFuse.

    IMPORTANT:
    This UID identifies the board.
    It is NOT authentication by itself.
*/
esp_err_t mathos_device_uid_read(
    mathos_device_uid_t *uid);

/*
    Basic structural validity check.

    Rejects all-zero and all-0xFF values.
*/
int mathos_device_uid_is_valid(
    const mathos_device_uid_t *uid);

/*
    Convert UID to:

        AA:BB:CC:DD:EE:FF
*/
esp_err_t mathos_device_uid_format(
    const mathos_device_uid_t *uid,
    char *buffer,
    size_t buffer_size);

#ifdef __cplusplus
}
#endif