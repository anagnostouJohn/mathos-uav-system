#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MATHOS_MAINTENANCE_CONFIG_MAGIC 0x4D434647U
#define MATHOS_MAINTENANCE_CONFIG_VERSION 1U

#define MATHOS_MAINTENANCE_WIFI_SSID_MAX_LEN 33
#define MATHOS_MAINTENANCE_SERVER_HOST_MAX_LEN 64

typedef enum
{
    MATHOS_MAINTENANCE_ROLE_RC = 0,
    MATHOS_MAINTENANCE_ROLE_GATEWAY
} mathos_maintenance_role_t;

typedef struct
{
    uint32_t magic;
    uint16_t version;
    uint16_t record_size;

    /*
        0 = telemetry forwarding disabled
        1 = telemetry forwarding enabled
    */
    uint8_t telemetry_enabled;

    /*
        Reserved bytes maintain alignment and leave
        space for small future additions.
    */
    uint8_t reserved[3];

    /*
        Null-terminated Wi-Fi SSID.
    */
    char wifi_ssid[
        MATHOS_MAINTENANCE_WIFI_SSID_MAX_LEN];

    /*
        Null-terminated hostname or IPv4 address.

        Examples:
            telemetry.example.com
            192.168.1.50
    */
    char server_host[
        MATHOS_MAINTENANCE_SERVER_HOST_MAX_LEN];

    uint16_t server_port;
    uint16_t reserved2;

    /*
        CRC protects the stored record against
        corruption or incomplete writes.
    */
    uint32_t crc32;

} mathos_maintenance_config_t;

void mathos_maintenance_config_set_defaults(
    mathos_maintenance_config_t *config);

int mathos_maintenance_config_is_valid(
    const mathos_maintenance_config_t *config);

esp_err_t mathos_maintenance_softap_start(
    mathos_maintenance_role_t role);

esp_err_t mathos_maintenance_get_ap_ip(
    char *buffer,
    size_t buffer_size);

#ifdef __cplusplus
}
#endif