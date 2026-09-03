#include "mathos_maintenance.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_server.h"
#include "nvs.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_task_wdt.h"
#include "freertos/FreeRTOS.h"

#define MATHOS_MAINTENANCE_RC_SSID "MATHOS-RC-SETUP"
#define MATHOS_MAINTENANCE_GATEWAY_SSID "MATHOS-GW-SETUP"

/*
    Temporary bench password.

    Later this will be replaced by a device-specific
    maintenance password stored securely in NVS.
*/
#define MATHOS_MAINTENANCE_TEST_PASSWORD "MathosSetup26!"

#define MATHOS_MAINTENANCE_WIFI_CHANNEL 1
#define MATHOS_MAINTENANCE_MAX_CLIENTS 4
#define MATHOS_MAINTENANCE_NVS_NAMESPACE "mathos_cfg"
#define MATHOS_MAINTENANCE_NVS_KEY "config_v1"
#define MATHOS_GATEWAY_NVS_KEY "gateway_v2"
#define MATHOS_RC_PAIRING_NVS_KEY "rc_pair_v1"
#define MATHOS_MAINTENANCE_PAGE_BUFFER_SIZE 16384
#define MATHOS_MAINTENANCE_ROLE_SECTION_BUFFER_SIZE 8192
#define MATHOS_MAINTENANCE_FORM_BODY_MAX 2048
/*
    Temporary bench-only pairing self-test.

    Set to 0 after the runtime test passes.
*/
/*
    PBKDF2 currently takes approximately eight seconds
    on the RC.

    Maintenance mode is exclusive: flight and control
    tasks are not running. Give maintenance operations
    enough time while retaining watchdog protection.
*/
#define MATHOS_MAINTENANCE_TASK_WDT_TIMEOUT_MS 15000U
#define MATHOS_PAIRING_BENCH_SELF_TEST_ENABLED 0

static const char *TAG = "MATHOS_MAINT";

static bool maintenance_softap_started = false;

static httpd_handle_t maintenance_http_server = NULL;
static esp_netif_t *maintenance_ap_netif = NULL;
static mathos_maintenance_rc_pairing_callback_t
    maintenance_rc_pairing_callback = NULL;
/*
    Protect the display-only pairing status because it
    is written by both HTTP and pairing transport tasks.
*/
static portMUX_TYPE
    maintenance_rc_pairing_status_lock =
        portMUX_INITIALIZER_UNLOCKED;

static mathos_maintenance_rc_pairing_status_t
    maintenance_rc_pairing_status =
        MATHOS_MAINTENANCE_RC_PAIRING_IDLE;
static mathos_maintenance_rc_pairing_status_t
maintenance_get_rc_pairing_status(void);

static mathos_maintenance_role_t maintenance_active_role =
    MATHOS_MAINTENANCE_ROLE_RC;
static mathos_maintenance_config_t
    maintenance_active_config;
static mathos_gateway_config_t
    maintenance_active_gateway_config;

static mathos_rc_pairing_config_t
    maintenance_active_rc_pairing_config;

static int
    maintenance_config_loaded_from_nvs = 0;

static int
    maintenance_gateway_config_loaded_from_nvs = 0;

static int
    maintenance_rc_pairing_config_loaded_from_nvs = 0;

static esp_err_t maintenance_form_get_value(
    const char *body,
    const char *key,
    char *output,
    size_t output_size);

static esp_err_t maintenance_send_text_response(
    httpd_req_t *request,
    const char *status,
    const char *text);

static esp_err_t
maintenance_send_rc_pairing_progress_page(
    httpd_req_t *request);

static void maintenance_clear_sensitive_memory(
    void *buffer,
    size_t buffer_size);

static esp_err_t maintenance_rc_pairing_post_handler(
    httpd_req_t *request)
{
    if (request == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        This endpoint exists only on the RC.
    */
    if (maintenance_active_role !=
        MATHOS_MAINTENANCE_ROLE_RC)
    {
        return maintenance_send_text_response(
            request,
            "403 Forbidden",
            "RC pairing is unavailable on this device.\n");
    }

    /*
        The RC application enables this callback only
        after the maintenance pairing UART is ready.
    */
    if (maintenance_rc_pairing_callback == NULL)
    {
        ESP_LOGW(
            TAG,
            "RC pairing POST rejected: "
            "pairing callback not ready");

        return maintenance_send_text_response(
            request,
            "503 Service Unavailable",
            "RC pairing transport is not ready.\n");
    }

    size_t content_length =
        request->content_len;

    if (content_length == 0 ||
        content_length >
            MATHOS_MAINTENANCE_FORM_BODY_MAX)
    {
        return maintenance_send_text_response(
            request,
            "413 Payload Too Large",
            "Invalid RC pairing form size.\n");
    }

    char *body =
        malloc(
            content_length + 1U);

    if (body == NULL)
    {
        return maintenance_send_text_response(
            request,
            "500 Internal Server Error",
            "Insufficient memory.\n");
    }

    char pairing_passphrase[MATHOS_PAIRING_PASSPHRASE_MAX_LEN + 1U] = "";

    char pairing_passphrase_confirm[MATHOS_PAIRING_PASSPHRASE_MAX_LEN + 1U] = "";

    size_t total_received = 0;
    int timeout_count = 0;

    /*
        Read the complete application/x-www-form-urlencoded
        request body.
    */
    while (total_received <
           content_length)
    {
        int received =
            httpd_req_recv(
                request,
                body + total_received,
                content_length -
                    total_received);

        if (received ==
            HTTPD_SOCK_ERR_TIMEOUT)
        {
            timeout_count++;

            if (timeout_count > 2)
            {
                goto request_timeout;
            }

            continue;
        }

        if (received <= 0)
        {
            goto invalid_request;
        }

        total_received +=
            (size_t)received;
    }

    body[total_received] = '\0';

    esp_err_t field_err =
        maintenance_form_get_value(
            body,
            "pairing_passphrase",
            pairing_passphrase,
            sizeof(pairing_passphrase));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_form_get_value(
            body,
            "pairing_passphrase_confirm",
            pairing_passphrase_confirm,
            sizeof(pairing_passphrase_confirm));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    /*
        The raw HTTP body also contains the passphrase.

        Erase it as soon as both decoded fields have
        been extracted.
    */
    maintenance_clear_sensitive_memory(
        body,
        content_length + 1U);

    free(body);
    body = NULL;

    size_t passphrase_len =
        strlen(
            pairing_passphrase);

    if (passphrase_len <
            MATHOS_PAIRING_PASSPHRASE_MIN_LEN ||
        passphrase_len >
            MATHOS_PAIRING_PASSPHRASE_MAX_LEN)
    {
        goto invalid_form;
    }

    /*
        Version 1 pairing passphrases are printable ASCII.
    */
    for (size_t i = 0;
         i < passphrase_len;
         i++)
    {
        unsigned char c =
            (unsigned char)
                pairing_passphrase[i];

        if (c < 0x20U ||
            c > 0x7EU)
        {
            goto invalid_form;
        }
    }

    if (strcmp(
            pairing_passphrase,
            pairing_passphrase_confirm) != 0)
    {
        goto invalid_form;
    }

    /*
        Confirmation is no longer required.
    */
    maintenance_clear_sensitive_memory(
        pairing_passphrase_confirm,
        sizeof(pairing_passphrase_confirm));

    /*
        The callback derives the candidate root key,
        creates RC_PROOF and writes the 78-byte frame
        to the maintenance UART.

        It must not retain this passphrase pointer.
    */
    /*
        Publish IN_PROGRESS before invoking the transport.

        The Gateway response may arrive on another task
        immediately after RC_PROOF is transmitted.
    */
    mathos_maintenance_set_rc_pairing_status(
        MATHOS_MAINTENANCE_RC_PAIRING_IN_PROGRESS);

    esp_err_t pairing_err =
        maintenance_rc_pairing_callback(
            pairing_passphrase);

    /*
        The passphrase must disappear from this HTTP
        task immediately after the callback returns.
    */
    maintenance_clear_sensitive_memory(
        pairing_passphrase,
        sizeof(pairing_passphrase));

    if (pairing_err != ESP_OK)
    {
        mathos_maintenance_set_rc_pairing_status(
            MATHOS_MAINTENANCE_RC_PAIRING_FAILED);

        ESP_LOGW(
            TAG,
            "RC pairing proof request failed: %s",
            esp_err_to_name(
                pairing_err));

        return maintenance_send_text_response(
            request,
            "409 Conflict",
            "RC pairing proof could not be generated. "
            "Ensure PACKAGE and CHALLENGE were received "
            "and retry pairing.\n");
    }

    ESP_LOGI(
        TAG,
        "RC pairing proof submitted to pairing transport");

    return maintenance_send_rc_pairing_progress_page(
        request);

invalid_form:

    if (body != NULL)
    {
        maintenance_clear_sensitive_memory(
            body,
            content_length + 1U);

        free(body);
        body = NULL;
    }

    maintenance_clear_sensitive_memory(
        pairing_passphrase,
        sizeof(pairing_passphrase));

    maintenance_clear_sensitive_memory(
        pairing_passphrase_confirm,
        sizeof(pairing_passphrase_confirm));

    return maintenance_send_text_response(
        request,
        "400 Bad Request",
        "Pairing passphrases are invalid or do not match.\n");

request_timeout:

    maintenance_clear_sensitive_memory(
        body,
        content_length + 1U);

    free(body);
    body = NULL;

    maintenance_clear_sensitive_memory(
        pairing_passphrase,
        sizeof(pairing_passphrase));

    maintenance_clear_sensitive_memory(
        pairing_passphrase_confirm,
        sizeof(pairing_passphrase_confirm));

    return maintenance_send_text_response(
        request,
        "408 Request Timeout",
        "Pairing request timed out.\n");

invalid_request:

    maintenance_clear_sensitive_memory(
        body,
        content_length + 1U);

    free(body);
    body = NULL;

    maintenance_clear_sensitive_memory(
        pairing_passphrase,
        sizeof(pairing_passphrase));

    maintenance_clear_sensitive_memory(
        pairing_passphrase_confirm,
        sizeof(pairing_passphrase_confirm));

    return maintenance_send_text_response(
        request,
        "400 Bad Request",
        "Could not read RC pairing form.\n");
}

static esp_err_t
maintenance_rc_pairing_status_get_handler(
    httpd_req_t *request)
{
    if (request == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        This status exists only on the RC maintenance
        interface.
    */
    if (maintenance_active_role !=
        MATHOS_MAINTENANCE_ROLE_RC)
    {
        return maintenance_send_text_response(
            request,
            "403 Forbidden",
            "RC pairing status is unavailable "
            "on this device.\n");
    }

    const char *response = NULL;

    switch (maintenance_get_rc_pairing_status())
    {
    case MATHOS_MAINTENANCE_RC_PAIRING_IDLE:
        response =
            "{\"status\":\"idle\"}\n";
        break;

    case MATHOS_MAINTENANCE_RC_PAIRING_IN_PROGRESS:
        response =
            "{\"status\":\"in_progress\"}\n";
        break;

    case MATHOS_MAINTENANCE_RC_PAIRING_SUCCESS:
        response =
            "{\"status\":\"success\"}\n";
        break;

    case MATHOS_MAINTENANCE_RC_PAIRING_FAILED:
    default:
        response =
            "{\"status\":\"failed\"}\n";
        break;
    }

    esp_err_t err =
        httpd_resp_set_status(
            request,
            "200 OK");

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        httpd_resp_set_type(
            request,
            "application/json; charset=utf-8");

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        Pairing status is live RAM state and must never
        be served from a browser or intermediary cache.
    */
    err =
        httpd_resp_set_hdr(
            request,
            "Cache-Control",
            "no-store");

    if (err != ESP_OK)
    {
        return err;
    }

    return httpd_resp_send(
        request,
        response,
        HTTPD_RESP_USE_STRLEN);
}

static esp_err_t
maintenance_send_rc_pairing_progress_page(
    httpd_req_t *request)
{
    if (request == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    static const char page[] =
        "<!doctype html>"
        "<html lang=\"en\">"
        "<head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"viewport\" "
        "content=\"width=device-width,initial-scale=1\">"
        "<title>MATHOS Pairing</title>"

        "<style>"
        "body{margin:0;background:#0f172a;color:#e2e8f0;"
        "font-family:Arial,sans-serif;display:flex;"
        "min-height:100vh;align-items:center;"
        "justify-content:center;}"

        ".card{width:min(88%,480px);background:#1e293b;"
        "padding:28px;border-radius:16px;"
        "box-shadow:0 12px 35px #0008;}"

        "h1{margin-top:0;font-size:24px;}"

        "#status{font-size:20px;font-weight:bold;"
        "color:#fbbf24;margin:22px 0 12px;}"

        ".success{color:#4ade80!important;}"
        ".failed{color:#f87171!important;}"

        "p{line-height:1.5;color:#cbd5e1;}"

        "a{display:inline-block;margin-top:18px;"
        "padding:12px 16px;background:#2563eb;"
        "color:white;text-decoration:none;"
        "border-radius:9px;}"

        "</style>"
        "</head>"

        "<body>"
        "<main class=\"card\">"
        "<h1>Secure Gateway Pairing</h1>"

        "<div id=\"status\">"
        "Authenticating Gateway..."
        "</div>"

        "<p id=\"detail\">"
        "RC_PROOF was sent. Waiting for the authenticated "
        "Gateway response."
        "</p>"

        "<a id=\"back\" href=\"/\" hidden>"
        "Return to maintenance page"
        "</a>"

        "</main>"

        "<script>"
        "const statusElement="
        "document.getElementById('status');"

        "const detailElement="
        "document.getElementById('detail');"

        "const backElement="
        "document.getElementById('back');"

        "let checks=0;"

        "async function checkPairingStatus(){"
        "try{"
        "const response=await fetch("
        "'/pair/rc/status',{cache:'no-store'});"

        "if(!response.ok){"
        "throw new Error('status request failed');"
        "}"

        "const result=await response.json();"

        "if(result.status==='success'){"
        "statusElement.textContent='Pairing successful';"
        "statusElement.className='success';"

        "detailElement.textContent="
        "'Gateway authenticated and the pairing key was "
        "saved. Reboot both devices into normal mode.';"

        "backElement.hidden=false;"
        "return;"
        "}"

        "if(result.status==='failed'){"
        "statusElement.textContent='Pairing failed';"
        "statusElement.className='failed';"

        "detailElement.textContent="
        "'Gateway authentication or secure pairing commit "
        "failed. Check the device connection before retrying.';"

        "backElement.hidden=false;"
        "return;"
        "}"

        "if(result.status==='idle'){"
        "statusElement.textContent='Pairing session is idle';"
        "statusElement.className='failed';"

        "detailElement.textContent="
        "'No active pairing result is available.';"

        "backElement.hidden=false;"
        "return;"
        "}"
        "}catch(error){"
        "/* Temporary Wi-Fi or HTTP errors are retried. */"
        "}"

        "checks++;"

        "if(checks>=60){"
        "statusElement.textContent="
        "'Still waiting for final status';"

        "detailElement.textContent="
        "'No final result was received within 30 seconds. "
        "Pairing may still finish; check the device "
        "connection before retrying.';"

        "backElement.hidden=false;"
        "return;"
        "}"

        "setTimeout(checkPairingStatus,500);"
        "}"

        "checkPairingStatus();"
        "</script>"
        "</body>"
        "</html>";

    esp_err_t err =
        httpd_resp_set_status(
            request,
            "200 OK");

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        httpd_resp_set_type(
            request,
            "text/html; charset=utf-8");

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        httpd_resp_set_hdr(
            request,
            "Cache-Control",
            "no-store");

    if (err != ESP_OK)
    {
        return err;
    }

    return httpd_resp_send(
        request,
        page,
        HTTPD_RESP_USE_STRLEN);
}

static esp_err_t maintenance_rc_config_post_handler(
    httpd_req_t *request);

static esp_err_t maintenance_gateway_config_post_handler(
    httpd_req_t *request);

static esp_err_t maintenance_rc_pairing_post_handler(
    httpd_req_t *request);

static esp_err_t maintenance_run_pairing_bench_self_test(
    void);
static esp_err_t mathos_pairing_package_wire_self_test(void);
static esp_err_t mathos_pairing_challenge_wire_self_test(void);
static esp_err_t mathos_pairing_proof_wire_self_test(void);
static esp_err_t mathos_pairing_complete_frame_self_test(void);

static uint32_t mathos_maintenance_config_calculate_crc32(
    const mathos_maintenance_config_t *config)
{
    if (config == NULL)
    {
        return 0;
    }

    /*
        Work on a copy so the stored CRC field is
        excluded from its own calculation.
    */
    mathos_maintenance_config_t copy =
        *config;

    copy.crc32 = 0;

    const uint8_t *data =
        (const uint8_t *)&copy;

    uint32_t crc =
        0xFFFFFFFFU;

    for (size_t i = 0;
         i < sizeof(copy);
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

static uint32_t mathos_gateway_config_calculate_crc32(
    const mathos_gateway_config_t *config)
{
    if (config == NULL)
    {
        return 0;
    }

    /*
        Calculate the CRC using a copy with the
        crc32 field cleared.

        This prevents the checksum from including itself.
    */
    mathos_gateway_config_t copy =
        *config;

    copy.crc32 = 0;

    const uint8_t *data =
        (const uint8_t *)&copy;

    uint32_t crc =
        0xFFFFFFFFU;

    for (size_t i = 0;
         i < sizeof(copy);
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
static uint32_t mathos_rc_pairing_config_calculate_crc32(
    const mathos_rc_pairing_config_t *config)
{
    if (config == NULL)
    {
        return 0;
    }

    /*
        Work on a copy so the CRC field is excluded
        from its own calculation.
    */
    mathos_rc_pairing_config_t copy =
        *config;

    copy.crc32 = 0;

    const uint8_t *data =
        (const uint8_t *)&copy;

    uint32_t crc =
        0xFFFFFFFFU;

    for (size_t i = 0;
         i < sizeof(copy);
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

static uint32_t mathos_pairing_package_calculate_crc32(
    const mathos_pairing_package_t *package)
{
    if (package == NULL)
    {
        return 0;
    }

    /*
        Calculate the CRC using a copy with the
        crc32 field cleared.
    */
    mathos_pairing_package_t copy =
        *package;

    copy.crc32 = 0;

    const uint8_t *data =
        (const uint8_t *)&copy;

    uint32_t crc =
        0xFFFFFFFFU;

    for (size_t i = 0;
         i < sizeof(copy);
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

static uint32_t mathos_pairing_challenge_calculate_crc32(
    const mathos_pairing_challenge_t *challenge)
{
    if (challenge == NULL)
    {
        return 0;
    }

    /*
        Calculate the CRC using a copy with its CRC
        field cleared.
    */
    mathos_pairing_challenge_t copy =
        *challenge;

    copy.crc32 = 0;

    const uint8_t *data =
        (const uint8_t *)&copy;

    uint32_t crc =
        0xFFFFFFFFU;

    for (size_t i = 0;
         i < sizeof(copy);
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

static uint32_t mathos_pairing_proof_calculate_crc32(
    const mathos_pairing_proof_t *proof)
{
    if (proof == NULL)
    {
        return 0;
    }

    /*
        Calculate the CRC using a copy with its
        crc32 field cleared.
    */
    mathos_pairing_proof_t copy =
        *proof;

    copy.crc32 = 0;

    const uint8_t *data =
        (const uint8_t *)&copy;

    uint32_t crc =
        0xFFFFFFFFU;

    for (size_t i = 0;
         i < sizeof(copy);
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

esp_err_t mathos_pairing_wire_encode_header(
    const mathos_pairing_wire_header_t *header,
    uint8_t output[MATHOS_PAIRING_WIRE_HEADER_LEN])
{
    if (header == NULL ||
        output == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Reject anything that is not a valid Mathos
        pairing header before serializing it.
    */
    if (header->magic_0 !=
            MATHOS_PAIRING_WIRE_MAGIC_0 ||
        header->magic_1 !=
            MATHOS_PAIRING_WIRE_MAGIC_1 ||
        header->version !=
            MATHOS_PAIRING_WIRE_VERSION)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (header->message_type <=
            MATHOS_PAIRING_MSG_INVALID ||
        header->message_type >
            MATHOS_PAIRING_MSG_RESULT)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Pairing sequence zero is reserved as invalid.
    */
    if (header->sequence == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Canonical 10-byte wire representation.

        Multi-byte integers are always little-endian.
    */
    output[0] =
        MATHOS_PAIRING_WIRE_MAGIC_0;

    output[1] =
        MATHOS_PAIRING_WIRE_MAGIC_1;

    output[2] =
        MATHOS_PAIRING_WIRE_VERSION;

    output[3] =
        header->message_type;

    output[4] =
        (uint8_t)(header->payload_len & 0xFFU);

    output[5] =
        (uint8_t)((header->payload_len >> 8) &
                  0xFFU);

    output[6] =
        (uint8_t)(header->sequence & 0xFFU);

    output[7] =
        (uint8_t)((header->sequence >> 8) &
                  0xFFU);

    output[8] =
        (uint8_t)((header->sequence >> 16) &
                  0xFFU);

    output[9] =
        (uint8_t)((header->sequence >> 24) &
                  0xFFU);

    return ESP_OK;
}

esp_err_t mathos_pairing_wire_decode_header(
    const uint8_t input[MATHOS_PAIRING_WIRE_HEADER_LEN],
    mathos_pairing_wire_header_t *header)
{
    if (input == NULL ||
        header == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Reject frames that do not begin with the
        Mathos Pairing magic bytes.
    */
    if (input[0] !=
            MATHOS_PAIRING_WIRE_MAGIC_0 ||
        input[1] !=
            MATHOS_PAIRING_WIRE_MAGIC_1)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Reject unsupported protocol versions.
    */
    if (input[2] !=
        MATHOS_PAIRING_WIRE_VERSION)
    {
        return ESP_ERR_INVALID_VERSION;
    }

    uint8_t message_type =
        input[3];

    if (message_type <=
            MATHOS_PAIRING_MSG_INVALID ||
        message_type >
            MATHOS_PAIRING_MSG_RESULT)
    {
        return ESP_ERR_INVALID_ARG;
    }

    uint16_t payload_len =
        (uint16_t)input[4] |
        ((uint16_t)input[5] << 8);

    uint32_t sequence =
        (uint32_t)input[6] |
        ((uint32_t)input[7] << 8) |
        ((uint32_t)input[8] << 16) |
        ((uint32_t)input[9] << 24);

    /*
        Pairing sequence zero is reserved.
    */
    if (sequence == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    memset(
        header,
        0,
        sizeof(*header));

    header->magic_0 =
        MATHOS_PAIRING_WIRE_MAGIC_0;

    header->magic_1 =
        MATHOS_PAIRING_WIRE_MAGIC_1;

    header->version =
        MATHOS_PAIRING_WIRE_VERSION;

    header->message_type =
        message_type;

    header->payload_len =
        payload_len;

    header->sequence =
        sequence;

    return ESP_OK;
}

esp_err_t mathos_pairing_wire_encode_frame(
    const mathos_pairing_wire_header_t *header,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *output,
    size_t output_size,
    size_t *output_len)
{
    if (header == NULL ||
        payload == NULL ||
        output == NULL ||
        output_len == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Always clear the caller-visible length first.

        If anything fails below, the caller cannot
        accidentally transmit an old frame length.
    */
    *output_len = 0;

    /*
        Pairing payloads must be non-empty and must fit
        inside the current version-1 transport limit.
    */
    if (payload_len == 0 ||
        payload_len >
            MATHOS_PAIRING_WIRE_MAX_PAYLOAD_LEN)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    /*
        The length stored in the header must describe
        exactly the supplied serialized payload.

        Never allow:

            header says 44 bytes
            caller supplies 36 bytes
    */
    if ((size_t)header->payload_len !=
        payload_len)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    size_t required_size =
        MATHOS_PAIRING_WIRE_HEADER_LEN +
        payload_len;

    if (required_size >
        MATHOS_PAIRING_WIRE_MAX_FRAME_LEN)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    if (output_size <
        required_size)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    /*
        Serialize and validate the canonical 10-byte
        pairing header directly into the output frame.
    */
    esp_err_t err =
        mathos_pairing_wire_encode_header(
            header,
            output);

    if (err != ESP_OK)
    {
        return err;
    }

    /*
        Append the already serialized pairing payload
        immediately after the header.
    */
    memcpy(
        &output[MATHOS_PAIRING_WIRE_HEADER_LEN],
        payload,
        payload_len);

    *output_len =
        required_size;

    return ESP_OK;
}

esp_err_t mathos_pairing_wire_decode_frame(
    const uint8_t *input,
    size_t input_len,
    mathos_pairing_wire_header_t *header,
    uint8_t *payload,
    size_t payload_capacity,
    size_t *payload_len)
{
    if (input == NULL ||
        header == NULL ||
        payload == NULL ||
        payload_len == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Never expose a stale length after a failed decode.
    */
    *payload_len = 0;

    /*
        At minimum, a complete frame must contain
        the canonical 10-byte pairing header.
    */
    if (input_len <
        MATHOS_PAIRING_WIRE_HEADER_LEN)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    /*
        Decode and validate the header first.
    */
    esp_err_t err =
        mathos_pairing_wire_decode_header(
            input,
            header);

    if (err != ESP_OK)
    {
        memset(
            header,
            0,
            sizeof(*header));

        return err;
    }

    /*
        Version 1 does not permit payloads larger than
        the current maximum pairing payload.
    */
    if (header->payload_len == 0 ||
        header->payload_len >
            MATHOS_PAIRING_WIRE_MAX_PAYLOAD_LEN)
    {
        memset(
            header,
            0,
            sizeof(*header));

        return ESP_ERR_INVALID_SIZE;
    }

    size_t required_frame_len =
        MATHOS_PAIRING_WIRE_HEADER_LEN +
        (size_t)header->payload_len;

    /*
        The supplied frame must contain exactly the
        number of bytes declared by the header.

        Reject both:

            truncated frames
            extra trailing bytes
    */
    if (input_len !=
        required_frame_len)
    {
        memset(
            header,
            0,
            sizeof(*header));

        return ESP_ERR_INVALID_SIZE;
    }

    /*
        The caller must provide enough room for the
        decoded payload.
    */
    if (payload_capacity <
        header->payload_len)
    {
        memset(
            header,
            0,
            sizeof(*header));

        return ESP_ERR_INVALID_SIZE;
    }

    /*
        Copy only the payload.

        Header bytes are already represented by
        the decoded header structure.
    */
    memcpy(
        payload,
        &input[MATHOS_PAIRING_WIRE_HEADER_LEN],
        header->payload_len);

    *payload_len =
        header->payload_len;

    return ESP_OK;
}

esp_err_t mathos_pairing_package_encode_payload(
    const mathos_pairing_package_t *package,
    uint8_t *output,
    size_t output_size)
{
    if (package == NULL ||
        output == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (output_size <
        MATHOS_PAIRING_PACKAGE_WIRE_LEN)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    /*
        Only serialize a pairing package that already
        passes its structural and CRC validation.
    */
    if (!mathos_pairing_package_is_valid(
            package))
    {
        return ESP_ERR_INVALID_ARG;
    }

    size_t i = 0;

    /*
        magic uint32 little-endian
    */
    output[i++] =
        (uint8_t)(package->magic & 0xFFU);

    output[i++] =
        (uint8_t)((package->magic >> 8) & 0xFFU);

    output[i++] =
        (uint8_t)((package->magic >> 16) & 0xFFU);

    output[i++] =
        (uint8_t)((package->magic >> 24) & 0xFFU);

    /*
        version uint16 little-endian
    */
    output[i++] =
        (uint8_t)(package->version & 0xFFU);

    output[i++] =
        (uint8_t)((package->version >> 8) & 0xFFU);

    /*
        record_size uint16 little-endian
    */
    output[i++] =
        (uint8_t)(package->record_size & 0xFFU);

    output[i++] =
        (uint8_t)((package->record_size >> 8) & 0xFFU);

    /*
        Device identities and KDF selector.
    */
    output[i++] =
        package->rc_id;

    output[i++] =
        package->gateway_id;

    /*
        Permanent Gateway hardware UID.

        Canonical byte order is exactly the six bytes
        returned by mathos_identity.
    */
    for (size_t uid_index = 0;
         uid_index < MATHOS_DEVICE_UID_LEN;
         uid_index++)
    {
        output[i++] =
            package->gateway_uid.bytes[uid_index];
    }

    output[i++] =
        package->key_derivation_method;

    output[i++] =
        package->reserved0;

    /*
        key_generation uint32 little-endian
    */
    output[i++] =
        (uint8_t)(package->key_generation & 0xFFU);

    output[i++] =
        (uint8_t)((package->key_generation >> 8) & 0xFFU);

    output[i++] =
        (uint8_t)((package->key_generation >> 16) & 0xFFU);

    output[i++] =
        (uint8_t)((package->key_generation >> 24) & 0xFFU);

    /*
        PBKDF2 iteration count uint32 little-endian.
    */
    output[i++] =
        (uint8_t)(package->kdf_iteration_count & 0xFFU);

    output[i++] =
        (uint8_t)((package->kdf_iteration_count >> 8) & 0xFFU);

    output[i++] =
        (uint8_t)((package->kdf_iteration_count >> 16) & 0xFFU);

    output[i++] =
        (uint8_t)((package->kdf_iteration_count >> 24) & 0xFFU);

    /*
        Public pairing salt.
    */
    for (size_t salt_index = 0;
         salt_index < MATHOS_PAIRING_SALT_LEN;
         salt_index++)
    {
        output[i++] =
            package->pairing_salt[salt_index];
    }

    /*
        Reserved version-1 bytes.
    */
    for (size_t reserved_index = 0;
         reserved_index <
         sizeof(package->reserved1);
         reserved_index++)
    {
        output[i++] =
            package->reserved1[reserved_index];
    }

    /*
        Package CRC uint32 little-endian.
    */
    output[i++] =
        (uint8_t)(package->crc32 & 0xFFU);

    output[i++] =
        (uint8_t)((package->crc32 >> 8) & 0xFFU);

    output[i++] =
        (uint8_t)((package->crc32 >> 16) & 0xFFU);

    output[i++] =
        (uint8_t)((package->crc32 >> 24) & 0xFFU);

    /*
        Defensive programming check.

        If the wire layout is edited incorrectly later,
        fail instead of silently producing a malformed
        package.
    */
    if (i !=
        MATHOS_PAIRING_PACKAGE_WIRE_LEN)
    {
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t mathos_pairing_package_decode_payload(
    const uint8_t *input,
    size_t input_size,
    mathos_pairing_package_t *package)
{
    if (input == NULL ||
        package == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (input_size !=
        MATHOS_PAIRING_PACKAGE_WIRE_LEN)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    memset(
        package,
        0,
        sizeof(*package));

    size_t i = 0;

    /*
        magic uint32 little-endian
    */
    package->magic =
        (uint32_t)input[i] |
        ((uint32_t)input[i + 1] << 8) |
        ((uint32_t)input[i + 2] << 16) |
        ((uint32_t)input[i + 3] << 24);

    i += 4;

    /*
        version uint16 little-endian
    */
    package->version =
        (uint16_t)input[i] |
        ((uint16_t)input[i + 1] << 8);

    i += 2;

    /*
        record_size uint16 little-endian
    */
    package->record_size =
        (uint16_t)input[i] |
        ((uint16_t)input[i + 1] << 8);

    i += 2;

    package->rc_id =
        input[i++];

    package->gateway_id =
        input[i++];

    /*
        Decode the permanent Gateway hardware UID.
    */
    for (size_t uid_index = 0;
         uid_index < MATHOS_DEVICE_UID_LEN;
         uid_index++)
    {
        package->gateway_uid.bytes[uid_index] =
            input[i++];
    }

    package->key_derivation_method =
        input[i++];

    package->reserved0 =
        input[i++];

    /*
        key_generation uint32 little-endian
    */
    package->key_generation =
        (uint32_t)input[i] |
        ((uint32_t)input[i + 1] << 8) |
        ((uint32_t)input[i + 2] << 16) |
        ((uint32_t)input[i + 3] << 24);

    i += 4;

    /*
        PBKDF2 iteration count uint32 little-endian
    */
    package->kdf_iteration_count =
        (uint32_t)input[i] |
        ((uint32_t)input[i + 1] << 8) |
        ((uint32_t)input[i + 2] << 16) |
        ((uint32_t)input[i + 3] << 24);

    i += 4;

    /*
        Public pairing salt.
    */
    for (size_t salt_index = 0;
         salt_index < MATHOS_PAIRING_SALT_LEN;
         salt_index++)
    {
        package->pairing_salt[salt_index] =
            input[i++];
    }

    /*
        Reserved version-1 bytes.
    */
    for (size_t reserved_index = 0;
         reserved_index <
         sizeof(package->reserved1);
         reserved_index++)
    {
        package->reserved1[reserved_index] =
            input[i++];
    }

    /*
        CRC uint32 little-endian
    */
    package->crc32 =
        (uint32_t)input[i] |
        ((uint32_t)input[i + 1] << 8) |
        ((uint32_t)input[i + 2] << 16) |
        ((uint32_t)input[i + 3] << 24);

    i += 4;

    /*
        Defensive layout check.
    */
    if (i !=
        MATHOS_PAIRING_PACKAGE_WIRE_LEN)
    {
        memset(
            package,
            0,
            sizeof(*package));

        return ESP_FAIL;
    }

    /*
        Validate magic, version, KDF parameters,
        generation and CRC using the existing
        pairing package validator.
    */
    if (!mathos_pairing_package_is_valid(
            package))
    {
        memset(
            package,
            0,
            sizeof(*package));

        return ESP_ERR_INVALID_CRC;
    }

    return ESP_OK;
}

esp_err_t mathos_pairing_proof_encode_payload(
    const mathos_pairing_proof_t *proof,
    uint8_t *output,
    size_t output_size)
{
    if (proof == NULL ||
        output == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (output_size <
        MATHOS_PAIRING_PROOF_WIRE_LEN)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    /*
        Only an active and fully validated proof may
        enter the pairing transport.

        Generation zero represents an empty/default
        proof and must never be transmitted.
    */
    if (!mathos_pairing_proof_is_valid(
            proof) ||
        proof->key_generation == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    size_t i = 0;

    /*
        magic uint32 little-endian
    */
    output[i++] =
        (uint8_t)(proof->magic & 0xFFU);

    output[i++] =
        (uint8_t)((proof->magic >> 8) & 0xFFU);

    output[i++] =
        (uint8_t)((proof->magic >> 16) & 0xFFU);

    output[i++] =
        (uint8_t)((proof->magic >> 24) & 0xFFU);

    /*
        version uint16 little-endian
    */
    output[i++] =
        (uint8_t)(proof->version & 0xFFU);

    output[i++] =
        (uint8_t)((proof->version >> 8) & 0xFFU);

    /*
        record_size uint16 little-endian
    */
    output[i++] =
        (uint8_t)(proof->record_size & 0xFFU);

    output[i++] =
        (uint8_t)((proof->record_size >> 8) & 0xFFU);

    /*
        Pairing identities and role.
    */
    output[i++] =
        proof->rc_id;

    output[i++] =
        proof->gateway_id;

    output[i++] =
        proof->proof_role;

    output[i++] =
        proof->reserved0;

    /*
        key_generation uint32 little-endian
    */
    output[i++] =
        (uint8_t)(proof->key_generation & 0xFFU);

    output[i++] =
        (uint8_t)((proof->key_generation >> 8) & 0xFFU);

    output[i++] =
        (uint8_t)((proof->key_generation >> 16) & 0xFFU);

    output[i++] =
        (uint8_t)((proof->key_generation >> 24) & 0xFFU);

    /*
        Copy the exact challenge nonce.
    */
    for (size_t nonce_index = 0;
         nonce_index < MATHOS_PAIRING_NONCE_LEN;
         nonce_index++)
    {
        output[i++] =
            proof->nonce[nonce_index];
    }

    /*
        Copy the 32-byte HMAC proof.

        This is authentication material, not the
        root key itself.
    */
    for (size_t proof_index = 0;
         proof_index < MATHOS_PAIRING_PROOF_LEN;
         proof_index++)
    {
        output[i++] =
            proof->proof[proof_index];
    }

    /*
        CRC uint32 little-endian
    */
    output[i++] =
        (uint8_t)(proof->crc32 & 0xFFU);

    output[i++] =
        (uint8_t)((proof->crc32 >> 8) & 0xFFU);

    output[i++] =
        (uint8_t)((proof->crc32 >> 16) & 0xFFU);

    output[i++] =
        (uint8_t)((proof->crc32 >> 24) & 0xFFU);

    /*
        Defensive layout check.
    */
    if (i !=
        MATHOS_PAIRING_PROOF_WIRE_LEN)
    {
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t mathos_pairing_proof_decode_payload(
    const uint8_t *input,
    size_t input_size,
    mathos_pairing_proof_t *proof)
{
    if (input == NULL ||
        proof == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (input_size !=
        MATHOS_PAIRING_PROOF_WIRE_LEN)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    memset(
        proof,
        0,
        sizeof(*proof));

    size_t i = 0;

    /*
        magic uint32 little-endian
    */
    proof->magic =
        (uint32_t)input[i] |
        ((uint32_t)input[i + 1] << 8) |
        ((uint32_t)input[i + 2] << 16) |
        ((uint32_t)input[i + 3] << 24);

    i += 4;

    /*
        version uint16 little-endian
    */
    proof->version =
        (uint16_t)input[i] |
        ((uint16_t)input[i + 1] << 8);

    i += 2;

    /*
        record_size uint16 little-endian
    */
    proof->record_size =
        (uint16_t)input[i] |
        ((uint16_t)input[i + 1] << 8);

    i += 2;

    /*
        Device identities and proof role.
    */
    proof->rc_id =
        input[i++];

    proof->gateway_id =
        input[i++];

    proof->proof_role =
        input[i++];

    proof->reserved0 =
        input[i++];

    /*
        key_generation uint32 little-endian
    */
    proof->key_generation =
        (uint32_t)input[i] |
        ((uint32_t)input[i + 1] << 8) |
        ((uint32_t)input[i + 2] << 16) |
        ((uint32_t)input[i + 3] << 24);

    i += 4;

    /*
        Challenge nonce.
    */
    for (size_t nonce_index = 0;
         nonce_index < MATHOS_PAIRING_NONCE_LEN;
         nonce_index++)
    {
        proof->nonce[nonce_index] =
            input[i++];
    }

    /*
        HMAC proof.
    */
    for (size_t proof_index = 0;
         proof_index < MATHOS_PAIRING_PROOF_LEN;
         proof_index++)
    {
        proof->proof[proof_index] =
            input[i++];
    }

    /*
        CRC uint32 little-endian
    */
    proof->crc32 =
        (uint32_t)input[i] |
        ((uint32_t)input[i + 1] << 8) |
        ((uint32_t)input[i + 2] << 16) |
        ((uint32_t)input[i + 3] << 24);

    i += 4;

    /*
        Defensive wire-layout check.
    */
    if (i !=
        MATHOS_PAIRING_PROOF_WIRE_LEN)
    {
        memset(
            proof,
            0,
            sizeof(*proof));

        return ESP_FAIL;
    }

    /*
        Only a real active proof may be accepted from
        the pairing transport.

        This validator already checks:
        - magic
        - version
        - record size
        - identities
        - proof role
        - generation
        - nonce
        - proof bytes
        - CRC
    */
    if (!mathos_pairing_proof_is_valid(
            proof) ||
        proof->key_generation == 0)
    {
        memset(
            proof,
            0,
            sizeof(*proof));

        return ESP_ERR_INVALID_CRC;
    }

    return ESP_OK;
}
static esp_err_t
mathos_pairing_wire_header_self_test(void)
{
    mathos_pairing_wire_header_t original = {
        .magic_0 =
            MATHOS_PAIRING_WIRE_MAGIC_0,

        .magic_1 =
            MATHOS_PAIRING_WIRE_MAGIC_1,

        .version =
            MATHOS_PAIRING_WIRE_VERSION,

        .message_type =
            MATHOS_PAIRING_MSG_PACKAGE,

        .payload_len = 64,

        .sequence = 0x12345678U};

    uint8_t encoded[MATHOS_PAIRING_WIRE_HEADER_LEN];

    memset(
        encoded,
        0,
        sizeof(encoded));

    esp_err_t err =
        mathos_pairing_wire_encode_header(
            &original,
            encoded);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing header self-test encode failed: %s",
            esp_err_to_name(err));

        return err;
    }

    mathos_pairing_wire_header_t decoded;

    memset(
        &decoded,
        0,
        sizeof(decoded));

    err =
        mathos_pairing_wire_decode_header(
            encoded,
            &decoded);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing header self-test decode failed: %s",
            esp_err_to_name(err));

        return err;
    }

    if (decoded.magic_0 != original.magic_0 ||
        decoded.magic_1 != original.magic_1 ||
        decoded.version != original.version ||
        decoded.message_type != original.message_type ||
        decoded.payload_len != original.payload_len ||
        decoded.sequence != original.sequence)
    {
        ESP_LOGE(
            TAG,
            "Pairing header self-test mismatch");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Pairing header self-test PASSED "
        "type=%u payload_len=%u sequence=0x%08" PRIx32,
        decoded.message_type,
        decoded.payload_len,
        decoded.sequence);

    return ESP_OK;
}
void mathos_maintenance_set_rc_pairing_callback(
    mathos_maintenance_rc_pairing_callback_t callback)
{
    maintenance_rc_pairing_callback =
        callback;
}

void mathos_maintenance_set_rc_pairing_status(
    mathos_maintenance_rc_pairing_status_t status)
{
    switch (status)
    {
    case MATHOS_MAINTENANCE_RC_PAIRING_IDLE:
    case MATHOS_MAINTENANCE_RC_PAIRING_IN_PROGRESS:
    case MATHOS_MAINTENANCE_RC_PAIRING_SUCCESS:
    case MATHOS_MAINTENANCE_RC_PAIRING_FAILED:
        break;

    default:
        ESP_LOGW(
            TAG,
            "invalid RC pairing web status=%u",
            (unsigned int)status);

        return;
    }

    portENTER_CRITICAL(
        &maintenance_rc_pairing_status_lock);

    maintenance_rc_pairing_status =
        status;

    portEXIT_CRITICAL(
        &maintenance_rc_pairing_status_lock);

    ESP_LOGI(
        TAG,
        "RC pairing web status=%u",
        (unsigned int)status);
}

static mathos_maintenance_rc_pairing_status_t
maintenance_get_rc_pairing_status(void)
{
    mathos_maintenance_rc_pairing_status_t status;

    portENTER_CRITICAL(
        &maintenance_rc_pairing_status_lock);

    status =
        maintenance_rc_pairing_status;

    portEXIT_CRITICAL(
        &maintenance_rc_pairing_status_lock);

    return status;
}

void mathos_gateway_config_set_defaults(
    mathos_gateway_config_t *config)
{
    if (config == NULL)
    {
        return;
    }
    memset(
        config,
        0,
        sizeof(*config));
    config->magic =
        MATHOS_GATEWAY_CONFIG_MAGIC;
    config->version =
        MATHOS_GATEWAY_CONFIG_VERSION;
    config->record_size =
        sizeof(mathos_gateway_config_t);
    config->gateway_id = 2;
    config->authorised_rc_id = 1;
    config->failsafe_policy =
        MATHOS_GATEWAY_FAILSAFE_FC_NATIVE;

    config->key_derivation_method =
        MATHOS_GATEWAY_KEY_DERIVATION_NONE;

    config->key_generation = 0;
    config->kdf_iteration_count = 0;
    config->link_uart_baud = 115200;
    config->fc_uart_baud = 115200;
    config->rc_packet_timeout_ms = 250;
    config->fc_heartbeat_timeout_ms = 1500;
    config->status_tx_period_ms = 200;
    config->telemetry_tx_period_ms = 200;
    memset(
        config->pairing_salt,
        0,
        sizeof(config->pairing_salt));

    memset(
        config->reserved1,
        0,
        sizeof(config->reserved1));
    config->configuration_counter = 0;

    config->crc32 = 0;

    config->crc32 =
        mathos_gateway_config_calculate_crc32(
            config);
}
void mathos_rc_pairing_config_set_defaults(
    mathos_rc_pairing_config_t *config)
{
    if (config == NULL)
    {
        return;
    }

    /*
        Begin with a completely cleared record.

        An all-zero root key and salt represent the
        unpaired state.
    */
    memset(
        config,
        0,
        sizeof(*config));

    config->magic =
        MATHOS_RC_PAIRING_CONFIG_MAGIC;

    config->version =
        MATHOS_RC_PAIRING_CONFIG_VERSION;

    config->record_size =
        sizeof(mathos_rc_pairing_config_t);

    /*
        Current default device identities.

        These will later be editable from the RC
        maintenance interface.
    */
    config->rc_id = 1;

    config->authorised_gateway_id = 2;

    config->key_derivation_method =
        MATHOS_GATEWAY_KEY_DERIVATION_NONE;

    config->key_generation = 0;

    config->kdf_iteration_count = 0;

    /*
        Reserved fields and pairing material are already
        zero because the complete structure was cleared.
    */
    config->configuration_counter = 0;

    config->crc32 = 0;

    config->crc32 =
        mathos_rc_pairing_config_calculate_crc32(
            config);
}

void mathos_pairing_package_set_defaults(
    mathos_pairing_package_t *package)
{
    if (package == NULL)
    {
        return;
    }

    /*
        A completely cleared package represents
        no active pairing offer.
    */
    memset(
        package,
        0,
        sizeof(*package));

    package->magic =
        MATHOS_PAIRING_PACKAGE_MAGIC;

    package->version =
        MATHOS_PAIRING_PACKAGE_VERSION;

    package->record_size =
        sizeof(mathos_pairing_package_t);

    package->rc_id = 1;
    package->gateway_id = 2;

    /*
        No salt, generation or derivation method exists
        until the Gateway creates a real pairing package.
    */
    package->key_derivation_method =
        MATHOS_GATEWAY_KEY_DERIVATION_NONE;

    package->key_generation = 0;
    package->kdf_iteration_count = 0;

    package->reserved0 = 0;

    memset(
        package->reserved1,
        0,
        sizeof(package->reserved1));

    package->crc32 = 0;

    package->crc32 =
        mathos_pairing_package_calculate_crc32(
            package);
}

void mathos_pairing_challenge_set_defaults(
    mathos_pairing_challenge_t *challenge)
{
    if (challenge == NULL)
    {
        return;
    }

    /*
        A cleared nonce represents no active challenge.
    */
    memset(
        challenge,
        0,
        sizeof(*challenge));

    challenge->magic =
        MATHOS_PAIRING_CHALLENGE_MAGIC;

    challenge->version =
        MATHOS_PAIRING_CHALLENGE_VERSION;

    challenge->record_size =
        sizeof(mathos_pairing_challenge_t);

    challenge->rc_id = 1;
    challenge->gateway_id = 2;

    challenge->key_generation = 0;

    challenge->crc32 = 0;

    challenge->crc32 =
        mathos_pairing_challenge_calculate_crc32(
            challenge);
}
void mathos_pairing_proof_set_defaults(
    mathos_pairing_proof_t *proof)
{
    if (proof == NULL)
    {
        return;
    }

    /*
        A completely cleared proof represents
        no active authenticated response.
    */
    memset(
        proof,
        0,
        sizeof(*proof));

    proof->magic =
        MATHOS_PAIRING_PROOF_MAGIC;

    proof->version =
        MATHOS_PAIRING_PROOF_VERSION;

    proof->record_size =
        sizeof(mathos_pairing_proof_t);

    proof->rc_id = 1;
    proof->gateway_id = 2;

    proof->proof_role = 0;
    proof->reserved0 = 0;

    proof->key_generation = 0;

    proof->crc32 = 0;

    proof->crc32 =
        mathos_pairing_proof_calculate_crc32(
            proof);
}

void mathos_pairing_session_set_defaults(
    mathos_pairing_session_t *session)
{
    if (session == NULL)
    {
        return;
    }

    /*
        Clear the entire session first because it may
        contain a candidate root key.
    */
    maintenance_clear_sensitive_memory(
        session,
        sizeof(*session));

    session->state =
        MATHOS_PAIRING_SESSION_IDLE;

    session->active = 0;
    session->retry_count = 0;
    session->key_generation = 0;
    session->started_at_us = 0;

    mathos_pairing_package_set_defaults(
        &session->package);

    mathos_pairing_challenge_set_defaults(
        &session->challenge);

    mathos_rc_pairing_config_set_defaults(
        &session->rc_candidate);

    mathos_pairing_proof_set_defaults(
        &session->rc_proof);

    mathos_pairing_proof_set_defaults(
        &session->gateway_proof);
}

void mathos_pairing_session_reset(
    mathos_pairing_session_t *session)
{
    if (session == NULL)
    {
        return;
    }

    /*
        mathos_pairing_session_set_defaults() securely
        clears the complete session before rebuilding
        the safe inactive state.

        This wipes the candidate root key, nonce,
        package parameters and both proof records.
    */
    mathos_pairing_session_set_defaults(
        session);

    ESP_LOGI(
        TAG,
        "pairing session securely reset to IDLE");
}

int mathos_pairing_session_has_timed_out(
    const mathos_pairing_session_t *session)
{
    if (session == NULL)
    {
        return 0;
    }

    /*
        An inactive session cannot expire.
    */
    if (!session->active)
    {
        return 0;
    }

    /*
        Every active session must have a valid start time.

        Treat a missing timestamp as expired so sensitive
        session material cannot remain active indefinitely.
    */
    if (session->started_at_us <= 0)
    {
        return 1;
    }

    int64_t now_us =
        esp_timer_get_time();

    /*
        A backwards timestamp should not normally occur,
        but reject the session rather than trusting an
        invalid elapsed-time calculation.
    */
    if (now_us < session->started_at_us)
    {
        return 1;
    }

    int64_t elapsed_us =
        now_us -
        session->started_at_us;

    int64_t timeout_us =
        (int64_t)
            MATHOS_PAIRING_SESSION_TIMEOUT_MS *
        1000LL;

    return elapsed_us >= timeout_us
               ? 1
               : 0;
}

static esp_err_t
mathos_pairing_proof_wire_self_test(void)
{
    /*
        Test both legitimate pairing proof roles:

        1 = RC_PROOF
        2 = GATEWAY_PROOF
    */
    const uint8_t roles[] = {
        MATHOS_PAIRING_PROOF_ROLE_RC,
        MATHOS_PAIRING_PROOF_ROLE_GATEWAY};

    for (size_t role_index = 0;
         role_index < sizeof(roles);
         role_index++)
    {
        mathos_pairing_proof_t original;

        mathos_pairing_proof_set_defaults(
            &original);

        original.rc_id = 1;
        original.gateway_id = 2;

        original.proof_role =
            roles[role_index];

        original.reserved0 = 0;

        original.key_generation = 7;

        /*
            Deterministic nonzero challenge nonce.

            This is only serialization-test data.
        */
        for (size_t i = 0;
             i < MATHOS_PAIRING_NONCE_LEN;
             i++)
        {
            original.nonce[i] =
                (uint8_t)(0x40U + i);
        }

        /*
            Deterministic nonzero pseudo-proof bytes.

            These are NOT real HMAC bytes.
            Real cryptographic proof generation is already
            tested separately by the pairing bench test.
        */
        for (size_t i = 0;
             i < MATHOS_PAIRING_PROOF_LEN;
             i++)
        {
            original.proof[i] =
                (uint8_t)(0x80U + i);
        }

        original.crc32 = 0;

        original.crc32 =
            mathos_pairing_proof_calculate_crc32(
                &original);

        if (!mathos_pairing_proof_is_valid(
                &original))
        {
            ESP_LOGE(
                TAG,
                "Pairing PROOF wire self-test "
                "could not create valid source proof "
                "role=%u",
                original.proof_role);

            return ESP_FAIL;
        }

        uint8_t encoded[MATHOS_PAIRING_PROOF_WIRE_LEN];

        memset(
            encoded,
            0,
            sizeof(encoded));

        esp_err_t err =
            mathos_pairing_proof_encode_payload(
                &original,
                encoded,
                sizeof(encoded));

        if (err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "Pairing PROOF wire self-test "
                "encode failed role=%u error=%s",
                original.proof_role,
                esp_err_to_name(err));

            return err;
        }

        mathos_pairing_proof_t decoded;

        memset(
            &decoded,
            0,
            sizeof(decoded));

        err =
            mathos_pairing_proof_decode_payload(
                encoded,
                sizeof(encoded),
                &decoded);

        if (err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "Pairing PROOF wire self-test "
                "decode failed role=%u error=%s",
                original.proof_role,
                esp_err_to_name(err));

            return err;
        }

        /*
            Compare every meaningful field explicitly.

            Do not compare raw structures because compiler
            padding must never define the wire protocol.
        */
        if (decoded.magic != original.magic ||
            decoded.version != original.version ||
            decoded.record_size != original.record_size ||
            decoded.rc_id != original.rc_id ||
            decoded.gateway_id != original.gateway_id ||
            decoded.proof_role != original.proof_role ||
            decoded.reserved0 != original.reserved0 ||
            decoded.key_generation !=
                original.key_generation ||
            memcmp(
                decoded.nonce,
                original.nonce,
                MATHOS_PAIRING_NONCE_LEN) != 0 ||
            memcmp(
                decoded.proof,
                original.proof,
                MATHOS_PAIRING_PROOF_LEN) != 0 ||
            decoded.crc32 != original.crc32)
        {
            ESP_LOGE(
                TAG,
                "Pairing PROOF wire self-test "
                "mismatch role=%u",
                original.proof_role);

            return ESP_FAIL;
        }

        ESP_LOGI(
            TAG,
            "Pairing PROOF wire round-trip PASSED "
            "role=%u len=%u generation=%lu",
            decoded.proof_role,
            (unsigned int)
                MATHOS_PAIRING_PROOF_WIRE_LEN,
            (unsigned long)
                decoded.key_generation);
    }

    /*
        ------------------------------------------------
        Corruption test
        ------------------------------------------------

        Build one valid RC proof again and then alter
        one serialized HMAC byte without changing CRC.

        The decoder must reject it.
    */
    mathos_pairing_proof_t tamper_source;

    mathos_pairing_proof_set_defaults(
        &tamper_source);

    tamper_source.rc_id = 1;
    tamper_source.gateway_id = 2;

    tamper_source.proof_role =
        MATHOS_PAIRING_PROOF_ROLE_RC;

    tamper_source.key_generation = 7;

    for (size_t i = 0;
         i < MATHOS_PAIRING_NONCE_LEN;
         i++)
    {
        tamper_source.nonce[i] =
            (uint8_t)(0x40U + i);
    }

    for (size_t i = 0;
         i < MATHOS_PAIRING_PROOF_LEN;
         i++)
    {
        tamper_source.proof[i] =
            (uint8_t)(0x80U + i);
    }

    tamper_source.crc32 = 0;

    tamper_source.crc32 =
        mathos_pairing_proof_calculate_crc32(
            &tamper_source);

    uint8_t tampered_encoded[MATHOS_PAIRING_PROOF_WIRE_LEN];

    esp_err_t err =
        mathos_pairing_proof_encode_payload(
            &tamper_source,
            tampered_encoded,
            sizeof(tampered_encoded));

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing PROOF tamper test "
            "source encode failed");

        return err;
    }

    /*
        Wire layout:

        0..15   metadata
        16..31  nonce
        32..63  HMAC proof
        64..67  CRC

        Change the first HMAC byte.
    */
    tampered_encoded[32] ^= 0x01U;

    mathos_pairing_proof_t tampered_decoded;

    memset(
        &tampered_decoded,
        0,
        sizeof(tampered_decoded));

    err =
        mathos_pairing_proof_decode_payload(
            tampered_encoded,
            sizeof(tampered_encoded),
            &tampered_decoded);

    if (err == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing PROOF tamper test FAILED: "
            "corrupted proof was accepted");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Pairing PROOF tamper test PASSED: "
        "corrupted proof rejected");

    return ESP_OK;
}

static esp_err_t
mathos_pairing_complete_frame_self_test(void)
{
    /*
        ------------------------------------------------
        1. Create one valid pairing PACKAGE
        ------------------------------------------------
    */
    mathos_pairing_package_t original;

    mathos_pairing_package_set_defaults(
        &original);

    original.rc_id = 1;
    original.gateway_id = 2;

    /*
        Deterministic synthetic Gateway UID used only by
        this complete-frame self-test.
    */
    const mathos_device_uid_t test_gateway_uid = {
        .bytes = {
            0x02U,
            0x00U,
            0x00U,
            0x00U,
            0x00U,
            0x04U}};

    original.gateway_uid =
        test_gateway_uid;

    original.key_derivation_method =
        MATHOS_GATEWAY_KEY_DERIVATION_PBKDF2_SHA256;

    original.key_generation = 7;

    original.kdf_iteration_count =
        MATHOS_PAIRING_KDF_DEFAULT_ITERATIONS;

    for (size_t i = 0;
         i < MATHOS_PAIRING_SALT_LEN;
         i++)
    {
        original.pairing_salt[i] =
            (uint8_t)(i + 1U);
    }

    original.reserved0 = 0;

    memset(
        original.reserved1,
        0,
        sizeof(original.reserved1));

    original.crc32 = 0;

    original.crc32 =
        mathos_pairing_package_calculate_crc32(
            &original);

    if (!mathos_pairing_package_is_valid(
            &original))
    {
        ESP_LOGE(
            TAG,
            "Pairing complete-frame self-test "
            "source PACKAGE is invalid");

        return ESP_FAIL;
    }

    /*
        ------------------------------------------------
        2. Serialize PACKAGE payload
        ------------------------------------------------
    */
    uint8_t package_payload[MATHOS_PAIRING_PACKAGE_WIRE_LEN];

    memset(
        package_payload,
        0,
        sizeof(package_payload));

    esp_err_t err =
        mathos_pairing_package_encode_payload(
            &original,
            package_payload,
            sizeof(package_payload));

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing complete-frame self-test "
            "PACKAGE encode failed: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        ------------------------------------------------
        3. Build pairing header
        ------------------------------------------------
    */
    mathos_pairing_wire_header_t tx_header = {
        .magic_0 =
            MATHOS_PAIRING_WIRE_MAGIC_0,

        .magic_1 =
            MATHOS_PAIRING_WIRE_MAGIC_1,

        .version =
            MATHOS_PAIRING_WIRE_VERSION,

        .message_type =
            MATHOS_PAIRING_MSG_PACKAGE,

        .payload_len =
            MATHOS_PAIRING_PACKAGE_WIRE_LEN,

        .sequence = 1U};

    /*
        ------------------------------------------------
        4. Build complete frame
        ------------------------------------------------
    */
    uint8_t frame[MATHOS_PAIRING_WIRE_MAX_FRAME_LEN];

    memset(
        frame,
        0,
        sizeof(frame));

    size_t frame_len = 0;

    err =
        mathos_pairing_wire_encode_frame(
            &tx_header,
            package_payload,
            sizeof(package_payload),
            frame,
            sizeof(frame),
            &frame_len);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing complete-frame self-test "
            "frame encode failed: %s",
            esp_err_to_name(err));

        return err;
    }

    if (frame_len !=
        (MATHOS_PAIRING_WIRE_HEADER_LEN +
         MATHOS_PAIRING_PACKAGE_WIRE_LEN))
    {
        ESP_LOGE(
            TAG,
            "Pairing complete-frame self-test "
            "unexpected frame length=%u",
            (unsigned int)frame_len);

        return ESP_FAIL;
    }

    /*
        ------------------------------------------------
        5. Decode complete frame
        ------------------------------------------------
    */
    mathos_pairing_wire_header_t rx_header;

    memset(
        &rx_header,
        0,
        sizeof(rx_header));

    uint8_t decoded_payload[MATHOS_PAIRING_WIRE_MAX_PAYLOAD_LEN];

    memset(
        decoded_payload,
        0,
        sizeof(decoded_payload));

    size_t decoded_payload_len = 0;

    err =
        mathos_pairing_wire_decode_frame(
            frame,
            frame_len,
            &rx_header,
            decoded_payload,
            sizeof(decoded_payload),
            &decoded_payload_len);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing complete-frame self-test "
            "frame decode failed: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        ------------------------------------------------
        6. Validate decoded header
        ------------------------------------------------
    */
    if (rx_header.message_type !=
            MATHOS_PAIRING_MSG_PACKAGE ||
        rx_header.payload_len !=
            MATHOS_PAIRING_PACKAGE_WIRE_LEN ||
        rx_header.sequence != 1U ||
        decoded_payload_len !=
            MATHOS_PAIRING_PACKAGE_WIRE_LEN)
    {
        ESP_LOGE(
            TAG,
            "Pairing complete-frame self-test "
            "decoded header mismatch");

        return ESP_FAIL;
    }

    /*
        ------------------------------------------------
        7. Decode PACKAGE payload
        ------------------------------------------------
    */
    mathos_pairing_package_t decoded_package;

    memset(
        &decoded_package,
        0,
        sizeof(decoded_package));

    err =
        mathos_pairing_package_decode_payload(
            decoded_payload,
            decoded_payload_len,
            &decoded_package);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing complete-frame self-test "
            "PACKAGE decode failed: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        ------------------------------------------------
        8. Compare final PACKAGE
        ------------------------------------------------
    */
    if (decoded_package.rc_id !=
            original.rc_id ||
        decoded_package.gateway_id !=
            original.gateway_id ||
        memcmp(
            decoded_package.gateway_uid.bytes,
            original.gateway_uid.bytes,
            MATHOS_DEVICE_UID_LEN) != 0 ||
        decoded_package.key_generation !=
            original.key_generation ||
        decoded_package.kdf_iteration_count !=
            original.kdf_iteration_count ||
        memcmp(
            decoded_package.pairing_salt,
            original.pairing_salt,
            MATHOS_PAIRING_SALT_LEN) != 0 ||
        decoded_package.crc32 !=
            original.crc32)
    {
        ESP_LOGE(
            TAG,
            "Pairing complete-frame self-test "
            "final PACKAGE mismatch");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Pairing COMPLETE FRAME self-test PASSED "
        "type=PACKAGE frame_len=%u payload_len=%u "
        "sequence=%lu",
        (unsigned int)frame_len,
        (unsigned int)decoded_payload_len,
        (unsigned long)rx_header.sequence);

    return ESP_OK;
}

int mathos_pairing_session_register_failure(
    mathos_pairing_session_t *session)
{
    if (session == NULL)
    {
        return 0;
    }

    /*
        A failure can belong only to an active pairing
        attempt.

        An inactive or inconsistent session is reset
        immediately.
    */
    if (!session->active)
    {
        ESP_LOGW(
            TAG,
            "pairing failure received for inactive session");

        mathos_pairing_session_reset(
            session);

        return 0;
    }

    /*
        A timed-out session must never be retried using
        its old challenge, nonce or candidate key.
    */
    if (mathos_pairing_session_has_timed_out(
            session))
    {
        ESP_LOGW(
            TAG,
            "pairing session failure caused by timeout");

        mathos_pairing_session_reset(
            session);

        return 0;
    }

    /*
        Increase the retry counter safely.

        The configured limit is far below UINT8_MAX,
        but avoid integer wrap-around anyway.
    */
    if (session->retry_count < UINT8_MAX)
    {
        session->retry_count++;
    }

    /*
        Reaching the retry limit terminates the complete
        pairing attempt.

        Resetting wipes the candidate root key, nonce,
        package parameters and proof records.
    */
    if (session->retry_count >=
        MATHOS_PAIRING_SESSION_MAX_RETRIES)
    {
        ESP_LOGW(
            TAG,
            "pairing retry limit reached retries=%u; "
            "session will be securely reset",
            session->retry_count);

        mathos_pairing_session_reset(
            session);

        return 0;
    }

    /*
        Preserve the active session for a controlled retry.

        The caller must explicitly decide which previous
        valid state should be recreated next.
    */
    session->state =
        MATHOS_PAIRING_SESSION_FAILED;

    ESP_LOGW(
        TAG,
        "pairing attempt failed retry=%u/%u",
        session->retry_count,
        (unsigned int)
            MATHOS_PAIRING_SESSION_MAX_RETRIES);

    /*
        Return one while another retry is permitted.
    */
    return 1;
}

esp_err_t mathos_pairing_session_start(
    mathos_pairing_session_t *session,
    const mathos_pairing_package_t *package)
{
    if (session == NULL ||
        package == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        A new pairing attempt may begin only from the
        safe inactive state.

        An existing session must be cancelled, completed
        or timed out before another one begins.
    */
    if (session->active ||
        session->state !=
            MATHOS_PAIRING_SESSION_IDLE)
    {
        ESP_LOGW(
            TAG,
            "pairing session start rejected: "
            "another session is already active");

        return ESP_ERR_INVALID_STATE;
    }

    /*
        Reject corrupted, empty or incompatible packages
        before allocating any active session state.
    */
    if (!mathos_pairing_package_is_valid(
            package))
    {
        ESP_LOGW(
            TAG,
            "pairing session start rejected: "
            "invalid pairing package");

        return ESP_ERR_INVALID_ARG;
    }

    if (package->key_generation == 0)
    {
        ESP_LOGW(
            TAG,
            "pairing session start rejected: "
            "pairing package is empty");

        return ESP_ERR_INVALID_STATE;
    }

    /*
        Construct the complete new session locally.

        The caller's session remains unchanged unless
        every initialization step succeeds.
    */
    mathos_pairing_session_t candidate;

    mathos_pairing_session_set_defaults(
        &candidate);

    candidate.package =
        *package;

    candidate.state =
        MATHOS_PAIRING_SESSION_PACKAGE_READY;

    candidate.key_generation =
        package->key_generation;

    candidate.retry_count = 0;

    candidate.started_at_us =
        esp_timer_get_time();

    /*
        The timeout logic treats a missing or invalid
        timestamp as expired.
    */
    if (candidate.started_at_us <= 0)
    {
        ESP_LOGE(
            TAG,
            "pairing session start failed: "
            "invalid start timestamp");

        maintenance_clear_sensitive_memory(
            &candidate,
            sizeof(candidate));

        return ESP_ERR_INVALID_STATE;
    }

    /*
        Generate a fresh random challenge for this
        particular pairing attempt.
    */
    esp_err_t challenge_err =
        mathos_pairing_challenge_from_package(
            &candidate.package,
            &candidate.challenge);

    if (challenge_err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "pairing session start failed: "
            "challenge generation error=%s",
            esp_err_to_name(challenge_err));

        maintenance_clear_sensitive_memory(
            &candidate,
            sizeof(candidate));

        return challenge_err;
    }

    candidate.state =
        MATHOS_PAIRING_SESSION_CHALLENGE_READY;

    candidate.active = 1;

    /*
        Publish the complete session only after the
        challenge has been generated and validated.
    */
    *session =
        candidate;

    ESP_LOGI(
        TAG,
        "pairing session started "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu state=%u",
        session->package.rc_id,
        session->package.gateway_id,
        (unsigned long)
            session->key_generation,
        (unsigned int)
            session->state);

    /*
        The active session now owns the required copy.
        Clear the temporary stack copy.
    */
    maintenance_clear_sensitive_memory(
        &candidate,
        sizeof(candidate));

    return ESP_OK;
}

esp_err_t mathos_pairing_session_accept_remote_challenge(
    mathos_pairing_session_t *session,
    const mathos_pairing_package_t *package,
    const mathos_pairing_challenge_t *challenge)
{
    if (session == NULL ||
        package == NULL ||
        challenge == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Never overwrite an active pairing attempt.
    */
    if (session->active ||
        session->state !=
            MATHOS_PAIRING_SESSION_IDLE)
    {
        ESP_LOGW(
            TAG,
            "remote pairing session rejected: "
            "session already active state=%u",
            (unsigned int)session->state);

        return ESP_ERR_INVALID_STATE;
    }

    /*
        Both received records must independently pass
        their normal validation.
    */
    if (!mathos_pairing_package_is_valid(
            package) ||
        !mathos_pairing_challenge_is_valid(
            challenge))
    {
        ESP_LOGW(
            TAG,
            "remote pairing session rejected: "
            "invalid package or challenge");

        return ESP_ERR_INVALID_ARG;
    }

    if (package->key_generation == 0 ||
        challenge->key_generation == 0)
    {
        return ESP_ERR_INVALID_STATE;
    }

    /*
        PACKAGE and CHALLENGE must describe exactly
        the same pairing attempt.
    */
    if (package->rc_id !=
            challenge->rc_id ||
        package->gateway_id !=
            challenge->gateway_id ||
        memcmp(
            package->gateway_uid.bytes,
            challenge->gateway_uid.bytes,
            MATHOS_DEVICE_UID_LEN) != 0 ||
        package->key_generation !=
            challenge->key_generation)
    {
        ESP_LOGW(
            TAG,
            "remote pairing session rejected: "
            "metadata or Gateway UID mismatch");

        return ESP_ERR_INVALID_STATE;
    }

    /*
        Construct locally first.

        The caller's session remains unchanged if
        initialization fails.
    */
    mathos_pairing_session_t candidate;

    mathos_pairing_session_set_defaults(
        &candidate);

    candidate.package =
        *package;

    candidate.challenge =
        *challenge;

    candidate.key_generation =
        package->key_generation;

    candidate.retry_count = 0;

    candidate.started_at_us =
        esp_timer_get_time();

    if (candidate.started_at_us <= 0)
    {
        return ESP_ERR_INVALID_STATE;
    }

    candidate.state =
        MATHOS_PAIRING_SESSION_CHALLENGE_READY;

    candidate.active = 1;

    /*
        Publish only the completely validated session.
    */
    *session =
        candidate;

    ESP_LOGI(
        TAG,
        "remote pairing session accepted "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu state=%u",
        session->package.rc_id,
        session->package.gateway_id,
        (unsigned long)
            session->key_generation,
        (unsigned int)
            session->state);

    /*
        The session now owns the copies.
    */
    memset(
        &candidate,
        0,
        sizeof(candidate));

    return ESP_OK;
}

esp_err_t mathos_pairing_session_prepare_rc_response(
    mathos_pairing_session_t *session,
    const mathos_rc_pairing_config_t *current_config,
    const char *passphrase)
{
    if (session == NULL ||
        current_config == NULL ||
        passphrase == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Build the candidate configuration and proof in
        temporary storage.

        Nothing sensitive is published into the active
        session until every operation succeeds.
    */
    mathos_rc_pairing_config_t candidate_config = {0};
    mathos_pairing_proof_t candidate_proof = {0};

    esp_err_t result = ESP_OK;

    /*
        RC response generation is allowed only while an
        active challenge is waiting for a response.
    */
    if (!session->active ||
        session->state !=
            MATHOS_PAIRING_SESSION_CHALLENGE_READY)
    {
        ESP_LOGW(
            TAG,
            "RC pairing response rejected: "
            "invalid session state=%u active=%u",
            (unsigned int)session->state,
            session->active);

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        Never use an expired challenge or candidate-key
        derivation session.
    */
    if (mathos_pairing_session_has_timed_out(
            session))
    {
        ESP_LOGW(
            TAG,
            "RC pairing response rejected: "
            "session timed out");

        mathos_pairing_session_reset(
            session);

        result = ESP_ERR_TIMEOUT;
        goto cleanup;
    }

    /*
        The package and challenge must still be complete
        and valid.
    */
    if (!mathos_pairing_package_is_valid(
            &session->package) ||
        !mathos_pairing_challenge_is_valid(
            &session->challenge))
    {
        ESP_LOGE(
            TAG,
            "RC pairing response rejected: "
            "session records are invalid");

        mathos_pairing_session_reset(
            session);

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        Confirm that all session metadata belongs to the
        same pairing attempt.
    */
    if (session->key_generation !=
            session->package.key_generation ||
        session->key_generation !=
            session->challenge.key_generation ||
        session->package.rc_id !=
            session->challenge.rc_id ||
        session->package.gateway_id !=
            session->challenge.gateway_id ||
        memcmp(
            session->package.gateway_uid.bytes,
            session->challenge.gateway_uid.bytes,
            MATHOS_DEVICE_UID_LEN) != 0)
    {
        ESP_LOGE(
            TAG,
            "RC pairing response rejected: "
            "session metadata or Gateway UID mismatch");

        mathos_pairing_session_reset(
            session);

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        Derive and validate the RC candidate configuration.

        This does not save anything to NVS.
    */
    result =
        mathos_rc_pairing_config_prepare_from_package(
            current_config,
            &session->package,
            passphrase,
            &candidate_config);

    if (result != ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "RC pairing response rejected: "
            "candidate preparation failed");

        goto attempt_failed;
    }

    /*
        The candidate must describe the exact identities
        and generation from the active challenge.
    */
    if (candidate_config.rc_id !=
            session->challenge.rc_id ||
        candidate_config.authorised_gateway_id !=
            session->challenge.gateway_id ||
        candidate_config.key_generation !=
            session->challenge.key_generation)
    {
        ESP_LOGE(
            TAG,
            "RC pairing response rejected: "
            "candidate metadata mismatch");

        result = ESP_ERR_INVALID_STATE;
        goto attempt_failed;
    }

    /*
        Create the role-1 proof using the candidate
        root key.

        This proves that the RC derived the same key
        expected by the Gateway.
    */
    result =
        mathos_pairing_proof_create(
            candidate_config.root_key,
            &session->challenge,
            MATHOS_PAIRING_PROOF_ROLE_RC,
            &candidate_proof);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "RC pairing response failed: "
            "proof generation error=%s",
            esp_err_to_name(result));

        goto attempt_failed;
    }

    /*
        Validate the finished proof before publishing it.
    */
    if (!mathos_pairing_proof_is_valid(
            &candidate_proof))
    {
        ESP_LOGE(
            TAG,
            "RC pairing response failed: "
            "generated proof is invalid");

        result = ESP_FAIL;
        goto attempt_failed;
    }

    /*
        Publish both sensitive records only after the
        complete operation succeeds.
    */
    session->rc_candidate =
        candidate_config;

    session->rc_proof =
        candidate_proof;

    session->state =
        MATHOS_PAIRING_SESSION_RC_PROOF_READY;

    ESP_LOGI(
        TAG,
        "RC pairing response prepared "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu retry=%u "
        "state=%u",
        session->rc_candidate.rc_id,
        session->rc_candidate.authorised_gateway_id,
        (unsigned long)
            session->rc_candidate.key_generation,
        session->retry_count,
        (unsigned int)
            session->state);

    result = ESP_OK;
    goto cleanup;

attempt_failed:
    /*
        Count unsuccessful derivation or proof attempts.

        After the first two failures, return to the same
        challenge so the operator may correct the
        passphrase.

        The third failure securely resets the session.
    */
    if (mathos_pairing_session_register_failure(
            session))
    {
        session->state =
            MATHOS_PAIRING_SESSION_CHALLENGE_READY;

        ESP_LOGI(
            TAG,
            "pairing session returned to "
            "CHALLENGE_READY for retry");
    }

cleanup:
    /*
        These temporary structures may contain a derived
        root key and HMAC proof.
    */
    maintenance_clear_sensitive_memory(
        &candidate_config,
        sizeof(candidate_config));

    maintenance_clear_sensitive_memory(
        &candidate_proof,
        sizeof(candidate_proof));

    return result;
}

esp_err_t mathos_pairing_session_prepare_gateway_response(
    mathos_pairing_session_t *session,
    const mathos_gateway_config_t *gateway_config)
{
    if (session == NULL ||
        gateway_config == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Build the Gateway confirmation proof in temporary
        storage.

        It is published into the active session only after
        RC proof verification succeeds.
    */
    mathos_pairing_proof_t candidate_gateway_proof = {0};

    esp_err_t result = ESP_OK;

    /*
        The Gateway may process a response only when an
        active RC proof is waiting for verification.
    */
    if (!session->active ||
        session->state !=
            MATHOS_PAIRING_SESSION_RC_PROOF_READY)
    {
        ESP_LOGW(
            TAG,
            "Gateway pairing response rejected: "
            "invalid session state=%u active=%u",
            (unsigned int)session->state,
            session->active);

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        Never verify a proof from an expired pairing
        attempt.
    */
    if (mathos_pairing_session_has_timed_out(
            session))
    {
        ESP_LOGW(
            TAG,
            "Gateway pairing response rejected: "
            "session timed out");

        mathos_pairing_session_reset(
            session);

        result = ESP_ERR_TIMEOUT;
        goto cleanup;
    }

    /*
        Only a fully validated and provisioned Gateway
        configuration may authenticate an RC.
    */
    if (!mathos_gateway_config_is_valid(
            gateway_config))
    {
        ESP_LOGE(
            TAG,
            "Gateway pairing response rejected: "
            "invalid Gateway configuration");

        mathos_pairing_session_reset(
            session);

        result = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }

    if (gateway_config->key_generation == 0)
    {
        ESP_LOGW(
            TAG,
            "Gateway pairing response rejected: "
            "Gateway key is not provisioned");

        mathos_pairing_session_reset(
            session);

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        Every record involved in the exchange must still
        pass its own structural and CRC validation.
    */
    if (!mathos_pairing_package_is_valid(
            &session->package) ||
        !mathos_pairing_challenge_is_valid(
            &session->challenge) ||
        !mathos_pairing_proof_is_valid(
            &session->rc_proof))
    {
        ESP_LOGE(
            TAG,
            "Gateway pairing response rejected: "
            "invalid session record");

        mathos_pairing_session_reset(
            session);

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        Confirm that the pairing package still describes
        this exact Gateway configuration.
    */
    if (session->package.rc_id !=
            gateway_config->authorised_rc_id ||
        session->package.gateway_id !=
            gateway_config->gateway_id ||
        session->package.key_generation !=
            gateway_config->key_generation ||
        session->package.key_derivation_method !=
            gateway_config->key_derivation_method ||
        session->package.kdf_iteration_count !=
            gateway_config->kdf_iteration_count ||
        memcmp(
            session->package.pairing_salt,
            gateway_config->pairing_salt,
            sizeof(session->package.pairing_salt)) != 0)
    {
        ESP_LOGE(
            TAG,
            "Gateway pairing response rejected: "
            "Gateway configuration does not match package");

        mathos_pairing_session_reset(
            session);

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        Confirm that the package, challenge and session
        all belong to the same generation and identities.
    */
    if (session->key_generation !=
            gateway_config->key_generation ||
        session->challenge.key_generation !=
            gateway_config->key_generation ||
        session->challenge.rc_id !=
            gateway_config->authorised_rc_id ||
        session->challenge.gateway_id !=
            gateway_config->gateway_id ||
        memcmp(
            session->package.gateway_uid.bytes,
            session->challenge.gateway_uid.bytes,
            MATHOS_DEVICE_UID_LEN) != 0)
    {
        ESP_LOGE(
            TAG,
            "Gateway pairing response rejected: "
            "session metadata or Gateway UID mismatch");

        mathos_pairing_session_reset(
            session);

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        Verify the role-1 proof using the Gateway's own
        root key.

        A successful result proves that the RC derived the
        same root key without transmitting that key.
    */
    result =
        mathos_pairing_proof_verify(
            gateway_config->root_key,
            &session->challenge,
            &session->rc_proof,
            MATHOS_PAIRING_PROOF_ROLE_RC);

    if (result != ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "Gateway rejected RC pairing proof");

        goto attempt_failed;
    }

    session->state =
        MATHOS_PAIRING_SESSION_RC_PROOF_VERIFIED;

    /*
        Create the role-2 Gateway confirmation proof.

        Role separation prevents the received RC proof
        from being reflected back as a valid confirmation.
    */
    result =
        mathos_pairing_proof_create(
            gateway_config->root_key,
            &session->challenge,
            MATHOS_PAIRING_PROOF_ROLE_GATEWAY,
            &candidate_gateway_proof);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Gateway confirmation proof generation failed: %s",
            esp_err_to_name(result));

        mathos_pairing_session_reset(
            session);

        goto cleanup;
    }

    if (!mathos_pairing_proof_is_valid(
            &candidate_gateway_proof))
    {
        ESP_LOGE(
            TAG,
            "Gateway confirmation proof failed validation");

        mathos_pairing_session_reset(
            session);

        result = ESP_FAIL;
        goto cleanup;
    }

    /*
        Publish the confirmation only after RC proof
        verification and Gateway proof generation succeed.
    */
    session->gateway_proof =
        candidate_gateway_proof;

    session->state =
        MATHOS_PAIRING_SESSION_GATEWAY_PROOF_READY;

    ESP_LOGI(
        TAG,
        "Gateway pairing response prepared "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu state=%u",
        session->gateway_proof.rc_id,
        session->gateway_proof.gateway_id,
        (unsigned long)
            session->gateway_proof.key_generation,
        (unsigned int)
            session->state);

    result = ESP_OK;
    goto cleanup;

attempt_failed:

    /*
        Remove the rejected candidate and RC proof before
        allowing another passphrase attempt.

        The public package and challenge remain available
        until the retry limit or session timeout is reached.
    */
    maintenance_clear_sensitive_memory(
        &session->rc_candidate,
        sizeof(session->rc_candidate));

    mathos_rc_pairing_config_set_defaults(
        &session->rc_candidate);

    maintenance_clear_sensitive_memory(
        &session->rc_proof,
        sizeof(session->rc_proof));

    mathos_pairing_proof_set_defaults(
        &session->rc_proof);

    if (mathos_pairing_session_register_failure(
            session))
    {
        session->state =
            MATHOS_PAIRING_SESSION_CHALLENGE_READY;

        ESP_LOGI(
            TAG,
            "pairing session returned to "
            "CHALLENGE_READY after rejected RC proof");
    }

cleanup:

    /*
        The temporary proof contains authentication
        material derived from the Gateway root key.
    */
    maintenance_clear_sensitive_memory(
        &candidate_gateway_proof,
        sizeof(candidate_gateway_proof));

    return result;
}

esp_err_t mathos_pairing_session_accept_gateway_proof(
    mathos_pairing_session_t *session,
    const mathos_pairing_proof_t *gateway_proof)
{
    if (session == NULL ||
        gateway_proof == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        The RC may accept a Gateway confirmation only
        after it has created and sent its own RC_PROOF.
    */
    if (!session->active ||
        session->state !=
            MATHOS_PAIRING_SESSION_RC_PROOF_READY)
    {
        ESP_LOGW(
            TAG,
            "Gateway proof rejected: "
            "pairing session not ready state=%u",
            (unsigned int)session->state);

        return ESP_ERR_INVALID_STATE;
    }

    /*
        Do not authenticate against a stale challenge.
    */
    if (mathos_pairing_session_has_timed_out(
            session))
    {
        ESP_LOGW(
            TAG,
            "Gateway proof rejected: "
            "pairing session timed out");

        mathos_pairing_session_reset(
            session);

        return ESP_ERR_TIMEOUT;
    }

    /*
        First reject malformed/corrupted proof records.
    */
    if (!mathos_pairing_proof_is_valid(
            gateway_proof))
    {
        ESP_LOGW(
            TAG,
            "Gateway proof rejected: "
            "invalid proof record");

        return ESP_ERR_INVALID_ARG;
    }

    /*
        CRITICAL AUTHENTICATION STEP.

        Verify the Gateway proof using the candidate root
        key derived locally on the RC.

        mathos_pairing_proof_verify() also checks:
            - proof role == GATEWAY
            - rc_id
            - gateway_id
            - key generation
            - exact challenge nonce
            - HMAC-SHA256
    */
    esp_err_t verify_err =
        mathos_pairing_proof_verify(
            session->rc_candidate.root_key,
            &session->challenge,
            gateway_proof,
            MATHOS_PAIRING_PROOF_ROLE_GATEWAY);

    if (verify_err != ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "Gateway proof authentication FAILED");

        /*
            Do not mutate the candidate/session here.

            A malformed injected proof must not destroy
            a legitimate pairing attempt.
        */
        return verify_err;
    }

    /*
        Publish the authenticated proof only after all
        cryptographic verification has succeeded.
    */
    session->gateway_proof =
        *gateway_proof;

    session->state =
        MATHOS_PAIRING_SESSION_GATEWAY_PROOF_VERIFIED;

    ESP_LOGI(
        TAG,
        "Gateway pairing proof verified "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu state=%u",
        gateway_proof->rc_id,
        gateway_proof->gateway_id,
        (unsigned long)
            gateway_proof->key_generation,
        (unsigned int)
            session->state);

    /*
        Mutual authentication is now complete.

        Persistence is deliberately a separate operation.
    */
    session->state =
        MATHOS_PAIRING_SESSION_COMMIT_READY;

    ESP_LOGI(
        TAG,
        "RC pairing session COMMIT_READY "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu state=%u",
        session->package.rc_id,
        session->package.gateway_id,
        (unsigned long)
            session->key_generation,
        (unsigned int)
            session->state);

    return ESP_OK;
}

static esp_err_t maintenance_run_pairing_bench_self_test(
    void)
{
    /*
        This passphrase exists only for the temporary
        bench self-test.

        It is never written to NVS or transmitted.
    */
    char test_passphrase[] =
        "MATHOS-BENCH-SELFTEST-2026";

    char wrong_test_passphrase[] =
        "MATHOS-WRONG-SELFTEST-2026";

    mathos_gateway_config_t gateway_config = {0};

    mathos_rc_pairing_config_t current_rc_config = {0};

    mathos_pairing_package_t package = {0};

    mathos_pairing_session_t session = {0};

    /*
        Deterministic synthetic Gateway UID used only by
        this in-memory pairing self-test.

        0x02 marks it as a locally administered identity,
        keeping it distinct from a real factory MAC.
    */
    mathos_device_uid_t test_gateway_uid = {
        .bytes = {
            0x02U,
            0x00U,
            0x00U,
            0x00U,
            0x00U,
            0x01U}};

    esp_err_t result = ESP_OK;

    ESP_LOGI(
        TAG,
        "PAIRING SELF-TEST START");

    /*
        Build a fresh, provisioned Gateway configuration
        entirely in RAM.
    */
    mathos_gateway_config_set_defaults(
        &gateway_config);

    result =
        mathos_maintenance_generate_pairing_salt(
            gateway_config.pairing_salt);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "salt generation");

        goto cleanup;
    }

    /*
        Use the minimum permitted iteration count for this
        temporary startup test.

        The production default of 100,000 iterations has
        already been measured separately.
    */
    gateway_config.kdf_iteration_count =
        MATHOS_PAIRING_KDF_MIN_ITERATIONS;

    result =
        mathos_maintenance_derive_root_key_from_passphrase(
            test_passphrase,
            gateway_config.pairing_salt,
            gateway_config.kdf_iteration_count,
            gateway_config.root_key);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "Gateway key derivation");

        goto cleanup;
    }

    gateway_config.key_derivation_method =
        MATHOS_GATEWAY_KEY_DERIVATION_PBKDF2_SHA256;

    gateway_config.key_generation = 1;

    gateway_config.crc32 = 0;

    gateway_config.crc32 =
        mathos_gateway_config_calculate_crc32(
            &gateway_config);

    if (!mathos_gateway_config_is_valid(
            &gateway_config))
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "Gateway configuration validation");

        result = ESP_FAIL;
        goto cleanup;
    }

    /*
        Begin with a valid unpaired RC configuration.
    */
    mathos_rc_pairing_config_set_defaults(
        &current_rc_config);

    /*
        Export the Gateway's public pairing parameters.

        The package contains no root key.
    */
    result =
        mathos_pairing_package_from_gateway_config(
            &gateway_config,
            &test_gateway_uid,
            &package);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "package creation");

        goto cleanup;
    }

    /*
        Create a fresh challenge and start the controlled
        pairing session.
    */
    mathos_pairing_session_set_defaults(
        &session);

    result =
        mathos_pairing_session_start(
            &session,
            &package);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "session start");

        goto cleanup;
    }
    /*
        First test the hostile path.

        The RC can derive a key and create a structurally
        valid proof using the wrong passphrase, but the
        Gateway must reject that proof because its HMAC
        will not match.
    */
    result =
        mathos_pairing_session_prepare_rc_response(
            &session,
            &current_rc_config,
            wrong_test_passphrase);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "wrong-passphrase RC proof preparation");

        goto cleanup;
    }

    /*
        Gateway verification must fail here.

        Returning ESP_OK would mean the wrong passphrase
        was incorrectly accepted.
    */
    result =
        mathos_pairing_session_prepare_gateway_response(
            &session,
            &gateway_config);

    if (result == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "wrong passphrase was accepted");

        result = ESP_FAIL;
        goto cleanup;
    }

    /*
        After the first rejected proof, the session should
        remain active and return to CHALLENGE_READY so the
        operator may retry.

        The retry counter must now equal one.
    */
    if (!session.active ||
        session.state !=
            MATHOS_PAIRING_SESSION_CHALLENGE_READY ||
        session.retry_count != 1U)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "wrong-passphrase recovery state "
            "active=%u state=%u retry=%u",
            session.active,
            (unsigned int)session.state,
            session.retry_count);

        result = ESP_FAIL;
        goto cleanup;
    }

    ESP_LOGI(
        TAG,
        "PAIRING WRONG-PASSPHRASE REJECTION PASSED "
        "retry=%u state=%u",
        session.retry_count,
        (unsigned int)session.state);

    /*
        The rejection above intentionally returned an error.

        Clear that expected result before continuing with
        the correct passphrase.
    */
    result = ESP_OK;
    /*
        The RC derives its candidate key from the same
        passphrase and creates the role-1 proof.
    */
    result =
        mathos_pairing_session_prepare_rc_response(
            &session,
            &current_rc_config,
            test_passphrase);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "RC response preparation");

        goto cleanup;
    }
    /*
    Prove that the Gateway hardware UID is part of the
    MPR2 authenticated transcript.

    Use a valid copy of the challenge with one UID byte
    changed and a freshly calculated CRC. Therefore,
    rejection must come from the HMAC mismatch rather
    than ordinary packet-corruption validation.
*/
    mathos_pairing_challenge_t uid_tampered_challenge =
        session.challenge;

    uid_tampered_challenge.gateway_uid.bytes[0] ^=
        0x01U;

    uid_tampered_challenge.crc32 = 0;

    uid_tampered_challenge.crc32 =
        mathos_pairing_challenge_calculate_crc32(
            &uid_tampered_challenge);

    if (!mathos_pairing_challenge_is_valid(
            &uid_tampered_challenge))
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "UID-tampered challenge is not structurally valid");

        result = ESP_FAIL;

        maintenance_clear_sensitive_memory(
            &uid_tampered_challenge,
            sizeof(uid_tampered_challenge));

        goto cleanup;
    }

    result =
        mathos_pairing_proof_verify(
            session.rc_candidate.root_key,
            &uid_tampered_challenge,
            &session.rc_proof,
            MATHOS_PAIRING_PROOF_ROLE_RC);

    maintenance_clear_sensitive_memory(
        &uid_tampered_challenge,
        sizeof(uid_tampered_challenge));

    if (result == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "proof accepted after Gateway UID modification");

        result = ESP_FAIL;
        goto cleanup;
    }

    ESP_LOGI(
        TAG,
        "PAIRING MPR2 UID-BINDING TEST PASSED: "
        "modified Gateway UID rejected");

    result = ESP_OK;
    /*
        Tamper with one HMAC byte after a completely valid
        RC proof has been created.

        Recalculate the CRC so the record remains
        structurally valid. The Gateway must reject it
        because the cryptographic HMAC is wrong.
    */
    session.rc_proof.proof[0] ^=
        0x01U;

    session.rc_proof.crc32 = 0;

    session.rc_proof.crc32 =
        mathos_pairing_proof_calculate_crc32(
            &session.rc_proof);

    /*
        Confirm that CRC and structural validation still pass.

        This ensures the following rejection is caused by
        HMAC authentication, not by packet corruption rules.
    */
    if (!mathos_pairing_proof_is_valid(
            &session.rc_proof))
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "tampered proof is not structurally valid");

        result = ESP_FAIL;
        goto cleanup;
    }

    /*
        The Gateway must reject the altered HMAC.
    */
    result =
        mathos_pairing_session_prepare_gateway_response(
            &session,
            &gateway_config);

    if (result == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "tampered proof was accepted");

        result = ESP_FAIL;
        goto cleanup;
    }

    /*
        This is the second expected failure:

            retry 1 = wrong passphrase
            retry 2 = tampered proof

        The session must remain available for one final
        correct attempt.
    */
    if (!session.active ||
        session.state !=
            MATHOS_PAIRING_SESSION_CHALLENGE_READY ||
        session.retry_count != 2U)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "tampered-proof recovery state "
            "active=%u state=%u retry=%u",
            session.active,
            (unsigned int)session.state,
            session.retry_count);

        result = ESP_FAIL;
        goto cleanup;
    }

    ESP_LOGI(
        TAG,
        "PAIRING TAMPERED-PROOF REJECTION PASSED "
        "retry=%u state=%u",
        session.retry_count,
        (unsigned int)session.state);

    /*
        The Gateway rejection was expected.
    */
    result = ESP_OK;
    /*
        The Gateway verifies the RC proof and creates its
        role-2 confirmation proof.
    */
    /*
     Recreate the RC candidate and proof after the
     deliberately tampered attempt was rejected.
 */
    result =
        mathos_pairing_session_prepare_rc_response(
            &session,
            &current_rc_config,
            test_passphrase);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "RC response recreation after tamper");

        goto cleanup;
    }
    result =
        mathos_pairing_session_prepare_gateway_response(
            &session,
            &gateway_config);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "Gateway response preparation");

        goto cleanup;
    }

    /*
        The RC verifies the Gateway confirmation using
        only its candidate key.
    */
    result =
        mathos_pairing_proof_verify(
            session.rc_candidate.root_key,
            &session.challenge,
            &session.gateway_proof,
            MATHOS_PAIRING_PROOF_ROLE_GATEWAY);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "Gateway confirmation verification");

        goto cleanup;
    }

    session.state =
        MATHOS_PAIRING_SESSION_GATEWAY_PROOF_VERIFIED;

    /*
        Confirm independently that both sides derived the
        same complete 256-bit root key.
    */
    uint8_t key_mismatch = 0;

    for (size_t i = 0;
         i < MATHOS_GATEWAY_ROOT_KEY_LEN;
         i++)
    {
        key_mismatch |=
            (uint8_t)(gateway_config.root_key[i] ^
                      session.rc_candidate.root_key[i]);
    }

    if (key_mismatch != 0)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FAIL: "
            "derived root keys differ");

        result = ESP_FAIL;
        goto cleanup;
    }

    session.state =
        MATHOS_PAIRING_SESSION_COMMIT_READY;

    ESP_LOGI(
        TAG,
        "PAIRING SELF-TEST PASSED "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu state=%u",
        session.rc_candidate.rc_id,
        session.rc_candidate.authorised_gateway_id,
        (unsigned long)
            session.rc_candidate.key_generation,
        (unsigned int)
            session.state);

    result = ESP_OK;

cleanup:

    /*
        The test deliberately persists nothing.

        Remove all passphrase, key, salt, challenge and
        proof material before returning.
    */
    maintenance_clear_sensitive_memory(
        test_passphrase,
        sizeof(test_passphrase));

    maintenance_clear_sensitive_memory(
        wrong_test_passphrase,
        sizeof(wrong_test_passphrase));

    maintenance_clear_sensitive_memory(
        &gateway_config,
        sizeof(gateway_config));

    maintenance_clear_sensitive_memory(
        &current_rc_config,
        sizeof(current_rc_config));

    maintenance_clear_sensitive_memory(
        &package,
        sizeof(package));

    maintenance_clear_sensitive_memory(
        &session,
        sizeof(session));

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "PAIRING SELF-TEST FINAL RESULT: FAILED");
    }

    return result;
}
static esp_err_t
mathos_pairing_package_wire_self_test(void)
{
    mathos_pairing_package_t original;

    mathos_pairing_package_set_defaults(
        &original);

    /*
        Turn the default empty package into a valid
        provisioned pairing offer.
    */
    original.rc_id = 1;
    original.gateway_id = 2;

    /*
        Deterministic synthetic Gateway UID used only by
        this wire-format self-test.
    */
    const mathos_device_uid_t test_gateway_uid = {
        .bytes = {
            0x02U,
            0x00U,
            0x00U,
            0x00U,
            0x00U,
            0x02U}};

    original.gateway_uid =
        test_gateway_uid;

    original.key_derivation_method =
        MATHOS_GATEWAY_KEY_DERIVATION_PBKDF2_SHA256;

    original.key_generation = 7;

    original.kdf_iteration_count =
        MATHOS_PAIRING_KDF_DEFAULT_ITERATIONS;

    /*
        Deterministic nonzero salt for this wire-format
        self-test only.

        This is NOT an operational pairing salt.
    */
    for (size_t i = 0;
         i < MATHOS_PAIRING_SALT_LEN;
         i++)
    {
        original.pairing_salt[i] =
            (uint8_t)(i + 1U);
    }

    original.reserved0 = 0;

    memset(
        original.reserved1,
        0,
        sizeof(original.reserved1));

    /*
        Recalculate the package CRC after modifying
        the pairing parameters.
    */
    original.crc32 = 0;

    original.crc32 =
        mathos_pairing_package_calculate_crc32(
            &original);

    if (!mathos_pairing_package_is_valid(
            &original))
    {
        ESP_LOGE(
            TAG,
            "Pairing PACKAGE wire self-test "
            "could not create valid source package");

        return ESP_FAIL;
    }

    uint8_t encoded[MATHOS_PAIRING_PACKAGE_WIRE_LEN];

    memset(
        encoded,
        0,
        sizeof(encoded));

    esp_err_t err =
        mathos_pairing_package_encode_payload(
            &original,
            encoded,
            sizeof(encoded));

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing PACKAGE wire self-test "
            "encode failed: %s",
            esp_err_to_name(err));

        return err;
    }

    mathos_pairing_package_t decoded;

    memset(
        &decoded,
        0,
        sizeof(decoded));

    err =
        mathos_pairing_package_decode_payload(
            encoded,
            sizeof(encoded),
            &decoded);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing PACKAGE wire self-test "
            "decode failed: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Compare every meaningful field explicitly.

        We intentionally do not compare the raw C
        structures because compiler padding must never
        become part of the wire protocol.
    */
    if (decoded.magic != original.magic ||
        decoded.version != original.version ||
        decoded.record_size != original.record_size ||
        decoded.rc_id != original.rc_id ||
        decoded.gateway_id != original.gateway_id ||
        memcmp(
            decoded.gateway_uid.bytes,
            original.gateway_uid.bytes,
            MATHOS_DEVICE_UID_LEN) != 0 ||
        decoded.key_derivation_method !=
            original.key_derivation_method ||
        decoded.reserved0 != original.reserved0 ||
        decoded.key_generation !=
            original.key_generation ||
        decoded.kdf_iteration_count !=
            original.kdf_iteration_count ||
        memcmp(
            decoded.pairing_salt,
            original.pairing_salt,
            MATHOS_PAIRING_SALT_LEN) != 0 ||
        memcmp(
            decoded.reserved1,
            original.reserved1,
            sizeof(original.reserved1)) != 0 ||
        decoded.crc32 != original.crc32)
    {
        ESP_LOGE(
            TAG,
            "Pairing PACKAGE wire self-test mismatch");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Pairing PACKAGE wire round-trip PASSED "
        "len=%u generation=%lu",
        (unsigned int)
            MATHOS_PAIRING_PACKAGE_WIRE_LEN,
        (unsigned long)
            decoded.key_generation);

    /*
        ----------------------------------------------------
        Gateway UID tamper test
        ----------------------------------------------------

        Byte 10 is the first Gateway hardware UID byte
        in the canonical version-2 PACKAGE payload.

        Modify it without changing the stored CRC.
        The decoder must reject the package.
    */
    encoded[10] ^= 0x01U;

    mathos_pairing_package_t tampered;

    memset(
        &tampered,
        0,
        sizeof(tampered));

    err =
        mathos_pairing_package_decode_payload(
            encoded,
            sizeof(encoded),
            &tampered);

    if (err == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing PACKAGE tamper test FAILED: "
            "corrupted payload was accepted");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Pairing PACKAGE tamper test PASSED: "
        "corrupted payload rejected");

    return ESP_OK;
}

static esp_err_t
mathos_pairing_challenge_wire_self_test(void)
{
    mathos_pairing_challenge_t original;

    mathos_pairing_challenge_set_defaults(
        &original);

    /*
        Build a deterministic valid challenge only
        for serialization testing.
    */
    original.rc_id = 1;
    original.gateway_id = 2;

    /*
        Deterministic synthetic Gateway UID used only by
        this challenge wire-format self-test.
    */
    const mathos_device_uid_t test_gateway_uid = {
        .bytes = {
            0x02U,
            0x00U,
            0x00U,
            0x00U,
            0x00U,
            0x03U}};

    original.gateway_uid =
        test_gateway_uid;

    original.key_generation = 7;

    original.reserved0[0] = 0;
    original.reserved0[1] = 0;

    /*
        Deterministic nonzero nonce.

        This is NOT an operational pairing challenge.
    */
    for (size_t i = 0;
         i < MATHOS_PAIRING_NONCE_LEN;
         i++)
    {
        original.nonce[i] =
            (uint8_t)(0xA0U + i);
    }

    original.crc32 = 0;

    original.crc32 =
        mathos_pairing_challenge_calculate_crc32(
            &original);

    if (!mathos_pairing_challenge_is_valid(
            &original))
    {
        ESP_LOGE(
            TAG,
            "Pairing CHALLENGE wire self-test "
            "could not create valid source challenge");

        return ESP_FAIL;
    }

    uint8_t encoded[MATHOS_PAIRING_CHALLENGE_WIRE_LEN];

    memset(
        encoded,
        0,
        sizeof(encoded));

    esp_err_t err =
        mathos_pairing_challenge_encode_payload(
            &original,
            encoded,
            sizeof(encoded));

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing CHALLENGE wire self-test "
            "encode failed: %s",
            esp_err_to_name(err));

        return err;
    }

    mathos_pairing_challenge_t decoded;

    memset(
        &decoded,
        0,
        sizeof(decoded));

    err =
        mathos_pairing_challenge_decode_payload(
            encoded,
            sizeof(encoded),
            &decoded);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing CHALLENGE wire self-test "
            "decode failed: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Compare fields explicitly.

        Never compare raw structures because compiler
        padding must not define the wire protocol.
    */
    if (decoded.magic != original.magic ||
        decoded.version != original.version ||
        decoded.record_size != original.record_size ||
        decoded.rc_id != original.rc_id ||
        decoded.gateway_id != original.gateway_id ||
        memcmp(
            decoded.gateway_uid.bytes,
            original.gateway_uid.bytes,
            MATHOS_DEVICE_UID_LEN) != 0 ||
        decoded.reserved0[0] != original.reserved0[0] ||
        decoded.reserved0[1] != original.reserved0[1] ||
        decoded.key_generation !=
            original.key_generation ||
        memcmp(
            decoded.nonce,
            original.nonce,
            MATHOS_PAIRING_NONCE_LEN) != 0 ||
        decoded.crc32 != original.crc32)
    {
        ESP_LOGE(
            TAG,
            "Pairing CHALLENGE wire self-test mismatch");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Pairing CHALLENGE wire round-trip PASSED "
        "len=%u generation=%lu",
        (unsigned int)
            MATHOS_PAIRING_CHALLENGE_WIRE_LEN,
        (unsigned long)
            decoded.key_generation);

    /*
        Gateway UID tamper test.

        Byte 10 is the first Gateway hardware UID byte
        in the canonical version-2 CHALLENGE payload.

        Change it without recalculating the CRC.
        The decoder must reject the challenge.
    */
    encoded[10] ^= 0x01U;

    mathos_pairing_challenge_t tampered;

    memset(
        &tampered,
        0,
        sizeof(tampered));

    err =
        mathos_pairing_challenge_decode_payload(
            encoded,
            sizeof(encoded),
            &tampered);

    if (err == ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing CHALLENGE tamper test FAILED: "
            "corrupted challenge was accepted");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "Pairing CHALLENGE tamper test PASSED: "
        "corrupted challenge rejected");

    return ESP_OK;
}

int mathos_pairing_proof_is_valid(
    const mathos_pairing_proof_t *proof)
{
    if (proof == NULL)
    {
        return 0;
    }

    if (proof->magic !=
        MATHOS_PAIRING_PROOF_MAGIC)
    {
        return 0;
    }

    if (proof->version !=
        MATHOS_PAIRING_PROOF_VERSION)
    {
        return 0;
    }

    if (proof->record_size !=
        sizeof(mathos_pairing_proof_t))
    {
        return 0;
    }

    /*
        Device identities must use values
        from 1 through 254.
    */
    if (proof->rc_id == 0 ||
        proof->rc_id == UINT8_MAX)
    {
        return 0;
    }

    if (proof->gateway_id == 0 ||
        proof->gateway_id == UINT8_MAX)
    {
        return 0;
    }

    if (proof->rc_id ==
        proof->gateway_id)
    {
        return 0;
    }

    /*
        Reserved version-1 fields must remain zero.
    */
    if (proof->reserved0 != 0)
    {
        return 0;
    }

    int nonce_is_set = 0;
    int proof_bytes_are_set = 0;

    for (size_t i = 0;
         i < sizeof(proof->nonce);
         i++)
    {
        if (proof->nonce[i] != 0)
        {
            nonce_is_set = 1;
            break;
        }
    }

    for (size_t i = 0;
         i < sizeof(proof->proof);
         i++)
    {
        if (proof->proof[i] != 0)
        {
            proof_bytes_are_set = 1;
            break;
        }
    }

    /*
        Generation zero represents an empty proof.

        No role, nonce or HMAC bytes may exist in this
        inactive state.
    */
    if (proof->key_generation == 0)
    {
        if (proof->proof_role != 0 ||
            nonce_is_set ||
            proof_bytes_are_set)
        {
            return 0;
        }
    }
    else
    {
        /*
            A real proof must identify which side
            generated it.
        */
        if (proof->proof_role !=
                MATHOS_PAIRING_PROOF_ROLE_RC &&
            proof->proof_role !=
                MATHOS_PAIRING_PROOF_ROLE_GATEWAY)
        {
            return 0;
        }

        if (!nonce_is_set ||
            !proof_bytes_are_set)
        {
            return 0;
        }
    }

    /*
        Verify accidental-corruption protection last.
    */
    uint32_t expected_crc =
        mathos_pairing_proof_calculate_crc32(
            proof);

    if (proof->crc32 != expected_crc)
    {
        return 0;
    }

    return 1;
}
esp_err_t mathos_pairing_proof_create(
    const uint8_t root_key[MATHOS_GATEWAY_ROOT_KEY_LEN],
    const mathos_pairing_challenge_t *challenge,
    uint8_t proof_role,
    mathos_pairing_proof_t *proof)
{
    if (root_key == NULL ||
        challenge == NULL ||
        proof == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Begin with a valid empty proof.

        If any operation fails, the caller will not receive
        stale or partially generated authentication data.
    */
    mathos_pairing_proof_set_defaults(
        proof);

    /*
        Only a complete, active challenge may be
        authenticated.
    */
    if (!mathos_pairing_challenge_is_valid(
            challenge))
    {
        ESP_LOGE(
            TAG,
            "pairing proof creation rejected: "
            "invalid challenge");

        return ESP_ERR_INVALID_ARG;
    }

    if (challenge->key_generation == 0)
    {
        ESP_LOGW(
            TAG,
            "pairing proof creation rejected: "
            "challenge is inactive");

        return ESP_ERR_INVALID_STATE;
    }

    /*
        The proof role prevents an RC proof from being
        reused as a Gateway confirmation, or vice versa.
    */
    if (proof_role !=
            MATHOS_PAIRING_PROOF_ROLE_RC &&
        proof_role !=
            MATHOS_PAIRING_PROOF_ROLE_GATEWAY)
    {
        ESP_LOGE(
            TAG,
            "pairing proof creation rejected: "
            "invalid proof role=%u",
            proof_role);

        return ESP_ERR_INVALID_ARG;
    }

    /*
        An all-zero root key represents the unprovisioned
        state and must never authenticate a challenge.
    */
    int root_key_is_set = 0;

    for (size_t i = 0;
         i < MATHOS_GATEWAY_ROOT_KEY_LEN;
         i++)
    {
        if (root_key[i] != 0)
        {
            root_key_is_set = 1;
            break;
        }
    }

    if (!root_key_is_set)
    {
        ESP_LOGW(
            TAG,
            "pairing proof creation rejected: "
            "root key is not provisioned");

        return ESP_ERR_INVALID_STATE;
    }

    /*
        Build a fixed byte sequence for HMAC.

        Do not authenticate a raw C structure because
        compiler padding and CPU byte order could differ
        between future implementations.
    */
    uint8_t authenticated_data[4U +
                               1U +
                               1U +
                               1U +
                               MATHOS_DEVICE_UID_LEN +
                               1U +
                               4U +
                               MATHOS_PAIRING_NONCE_LEN] = {0};

    size_t offset = 0;

    /*
        Domain separator: "MPR2"

        Pairing proof v2 cryptographically binds the
        permanent Gateway hardware UID into the transcript.

        Using a new domain separator prevents a v1 proof
        from ever being interpreted as a v2 proof.
    */
    authenticated_data[offset++] = 'M';
    authenticated_data[offset++] = 'P';
    authenticated_data[offset++] = 'R';
    authenticated_data[offset++] = '2';

    authenticated_data[offset++] =
        proof_role;

    authenticated_data[offset++] =
        challenge->rc_id;

    authenticated_data[offset++] =
        challenge->gateway_id;

    /*
        Cryptographically bind this proof to the exact
        physical Gateway identity.

        The UID itself is public, but changing even one UID
        byte now changes the HMAC and causes verification
        to fail.
    */
    for (size_t uid_index = 0;
         uid_index < MATHOS_DEVICE_UID_LEN;
         uid_index++)
    {
        authenticated_data[offset++] =
            challenge->gateway_uid.bytes[uid_index];
    }

    authenticated_data[offset++] =
        MATHOS_PAIRING_PROOF_VERSION;

    /*
        Encode the generation explicitly in big-endian
        byte order.
    */
    authenticated_data[offset++] =
        (uint8_t)(challenge->key_generation >> 24);

    authenticated_data[offset++] =
        (uint8_t)(challenge->key_generation >> 16);

    authenticated_data[offset++] =
        (uint8_t)(challenge->key_generation >> 8);

    authenticated_data[offset++] =
        (uint8_t)
            challenge->key_generation;

    memcpy(
        &authenticated_data[offset],
        challenge->nonce,
        MATHOS_PAIRING_NONCE_LEN);

    offset +=
        MATHOS_PAIRING_NONCE_LEN;

    if (offset != sizeof(authenticated_data))
    {
        ESP_LOGE(
            TAG,
            "pairing proof authenticated-data "
            "length mismatch");

        maintenance_clear_sensitive_memory(
            authenticated_data,
            sizeof(authenticated_data));

        return ESP_FAIL;
    }

    const mbedtls_md_info_t *sha256_info =
        mbedtls_md_info_from_type(
            MBEDTLS_MD_SHA256);

    if (sha256_info == NULL)
    {
        ESP_LOGE(
            TAG,
            "pairing proof SHA-256 implementation "
            "is unavailable");

        maintenance_clear_sensitive_memory(
            authenticated_data,
            sizeof(authenticated_data));

        return ESP_ERR_NOT_SUPPORTED;
    }

    proof->rc_id =
        challenge->rc_id;

    proof->gateway_id =
        challenge->gateway_id;

    proof->proof_role =
        proof_role;

    proof->reserved0 = 0;

    proof->key_generation =
        challenge->key_generation;

    memcpy(
        proof->nonce,
        challenge->nonce,
        sizeof(proof->nonce));

    int hmac_result =
        mbedtls_md_hmac(
            sha256_info,
            root_key,
            MATHOS_GATEWAY_ROOT_KEY_LEN,
            authenticated_data,
            sizeof(authenticated_data),
            proof->proof);

    maintenance_clear_sensitive_memory(
        authenticated_data,
        sizeof(authenticated_data));

    if (hmac_result != 0)
    {
        ESP_LOGE(
            TAG,
            "pairing proof HMAC generation failed: "
            "-0x%04X",
            (unsigned int)(-hmac_result));

        mathos_pairing_proof_set_defaults(
            proof);

        return ESP_FAIL;
    }

    /*
        An all-zero HMAC is treated as invalid even though
        a legitimate SHA-256 HMAC producing this value is
        practically impossible.
    */
    int proof_is_set = 0;

    for (size_t i = 0;
         i < sizeof(proof->proof);
         i++)
    {
        if (proof->proof[i] != 0)
        {
            proof_is_set = 1;
            break;
        }
    }

    if (!proof_is_set)
    {
        ESP_LOGE(
            TAG,
            "pairing proof HMAC is unexpectedly zero");

        mathos_pairing_proof_set_defaults(
            proof);

        return ESP_FAIL;
    }

    proof->crc32 = 0;

    proof->crc32 =
        mathos_pairing_proof_calculate_crc32(
            proof);

    if (!mathos_pairing_proof_is_valid(
            proof))
    {
        ESP_LOGE(
            TAG,
            "generated pairing proof failed validation");

        mathos_pairing_proof_set_defaults(
            proof);

        return ESP_FAIL;
    }

    /*
        Never log the HMAC, nonce or root key.
    */
    ESP_LOGI(
        TAG,
        "pairing proof created "
        "role=%u rc_id=%u gateway_id=%u "
        "key_generation=%lu crc=0x%08lx",
        proof->proof_role,
        proof->rc_id,
        proof->gateway_id,
        (unsigned long)
            proof->key_generation,
        (unsigned long)
            proof->crc32);

    return ESP_OK;
}

esp_err_t mathos_pairing_proof_verify(
    const uint8_t root_key[MATHOS_GATEWAY_ROOT_KEY_LEN],
    const mathos_pairing_challenge_t *challenge,
    const mathos_pairing_proof_t *proof,
    uint8_t expected_proof_role)
{
    if (root_key == NULL ||
        challenge == NULL ||
        proof == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    mathos_pairing_proof_t expected_proof = {0};

    esp_err_t result = ESP_OK;

    /*
        Only the two defined pairing-proof roles may
        be requested.
    */
    if (expected_proof_role !=
            MATHOS_PAIRING_PROOF_ROLE_RC &&
        expected_proof_role !=
            MATHOS_PAIRING_PROOF_ROLE_GATEWAY)
    {
        ESP_LOGE(
            TAG,
            "pairing proof verification rejected: "
            "invalid expected role=%u",
            expected_proof_role);

        result = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }

    /*
        Validate both records before comparing their
        identities, generation or nonce.
    */
    if (!mathos_pairing_challenge_is_valid(
            challenge))
    {
        ESP_LOGW(
            TAG,
            "pairing proof verification rejected: "
            "invalid challenge");

        result = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }

    if (challenge->key_generation == 0)
    {
        ESP_LOGW(
            TAG,
            "pairing proof verification rejected: "
            "challenge is inactive");

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    if (!mathos_pairing_proof_is_valid(
            proof))
    {
        ESP_LOGW(
            TAG,
            "pairing proof verification rejected: "
            "invalid proof record");

        result = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }

    /*
        An RC proof cannot be accepted as a Gateway
        confirmation, or vice versa.
    */
    if (proof->proof_role !=
        expected_proof_role)
    {
        ESP_LOGW(
            TAG,
            "pairing proof verification rejected: "
            "role mismatch expected=%u received=%u",
            expected_proof_role,
            proof->proof_role);

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        The proof must belong to the exact challenge
        identities and key generation.
    */
    if (proof->rc_id !=
            challenge->rc_id ||
        proof->gateway_id !=
            challenge->gateway_id ||
        proof->key_generation !=
            challenge->key_generation)
    {
        ESP_LOGW(
            TAG,
            "pairing proof verification rejected: "
            "challenge metadata mismatch");

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        The response must echo the exact random nonce
        generated for this pairing attempt.
    */
    if (memcmp(
            proof->nonce,
            challenge->nonce,
            sizeof(proof->nonce)) != 0)
    {
        ESP_LOGW(
            TAG,
            "pairing proof verification rejected: "
            "challenge nonce mismatch");

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        Recreate the expected HMAC using the supplied
        root key, challenge and expected role.
    */
    result =
        mathos_pairing_proof_create(
            root_key,
            challenge,
            expected_proof_role,
            &expected_proof);

    if (result != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "pairing proof verification failed: "
            "expected proof could not be generated");

        goto cleanup;
    }

    /*
        Compare every HMAC byte.

        Do not stop when the first mismatch is found.
    */
    uint8_t proof_mismatch = 0;

    for (size_t i = 0;
         i < MATHOS_PAIRING_PROOF_LEN;
         i++)
    {
        proof_mismatch |=
            (uint8_t)(proof->proof[i] ^
                      expected_proof.proof[i]);
    }

    if (proof_mismatch != 0)
    {
        ESP_LOGW(
            TAG,
            "pairing proof verification rejected: "
            "HMAC mismatch");

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        Never log the HMAC, nonce or root key.
    */
    ESP_LOGI(
        TAG,
        "pairing proof verified "
        "role=%u rc_id=%u gateway_id=%u "
        "key_generation=%lu",
        proof->proof_role,
        proof->rc_id,
        proof->gateway_id,
        (unsigned long)
            proof->key_generation);

    result = ESP_OK;

cleanup:

    /*
        The temporary record contains authentication
        material generated using the root key.
    */
    maintenance_clear_sensitive_memory(
        &expected_proof,
        sizeof(expected_proof));

    return result;
}

int mathos_pairing_challenge_is_valid(
    const mathos_pairing_challenge_t *challenge)
{
    if (challenge == NULL)
    {
        return 0;
    }

    if (challenge->magic !=
        MATHOS_PAIRING_CHALLENGE_MAGIC)
    {
        return 0;
    }

    if (challenge->version !=
        MATHOS_PAIRING_CHALLENGE_VERSION)
    {
        return 0;
    }

    if (challenge->record_size !=
        sizeof(mathos_pairing_challenge_t))
    {
        return 0;
    }

    /*
        Device identities must use values 1 through 254.
    */
    if (challenge->rc_id == 0 ||
        challenge->rc_id == UINT8_MAX)
    {
        return 0;
    }

    if (challenge->gateway_id == 0 ||
        challenge->gateway_id == UINT8_MAX)
    {
        return 0;
    }

    if (challenge->rc_id ==
        challenge->gateway_id)
    {
        return 0;
    }
    /*
        Gateway UID follows the same active/inactive rule
        as the pairing PACKAGE.

        generation == 0:
            empty challenge, UID must be all zero.

        generation > 0:
            active challenge, UID must be a valid
            permanent hardware identity.
    */
    if (challenge->key_generation == 0)
    {
        for (size_t i = 0;
             i < MATHOS_DEVICE_UID_LEN;
             i++)
        {
            if (challenge->gateway_uid.bytes[i] != 0)
            {
                return 0;
            }
        }
    }
    else
    {
        if (!mathos_device_uid_is_valid(
                &challenge->gateway_uid))
        {
            return 0;
        }
    }
    /*
        Reserved version-2 bytes must remain zero.
    */
    for (size_t i = 0;
         i < sizeof(challenge->reserved0);
         i++)
    {
        if (challenge->reserved0[i] != 0)
        {
            return 0;
        }
    }

    int nonce_is_set = 0;

    for (size_t i = 0;
         i < sizeof(challenge->nonce);
         i++)
    {
        if (challenge->nonce[i] != 0)
        {
            nonce_is_set = 1;
            break;
        }
    }

    /*
        Generation zero is the empty challenge state.

        A real challenge requires both a positive generation
        and a nonzero nonce.
    */
    if (challenge->key_generation == 0)
    {
        if (nonce_is_set)
        {
            return 0;
        }
    }
    else
    {
        if (!nonce_is_set)
        {
            return 0;
        }
    }

    uint32_t expected_crc =
        mathos_pairing_challenge_calculate_crc32(
            challenge);

    if (challenge->crc32 != expected_crc)
    {
        return 0;
    }

    return 1;
}

esp_err_t mathos_pairing_challenge_from_package(
    const mathos_pairing_package_t *package,
    mathos_pairing_challenge_t *challenge)
{
    if (package == NULL ||
        challenge == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Always begin with a valid empty challenge.

        If generation fails, no partial nonce or stale
        pairing information remains in the output.
    */
    mathos_pairing_challenge_set_defaults(
        challenge);

    /*
        Only a completely valid pairing package may
        create a challenge.
    */
    if (!mathos_pairing_package_is_valid(
            package))
    {
        ESP_LOGE(
            TAG,
            "pairing challenge creation rejected: "
            "invalid pairing package");

        return ESP_ERR_INVALID_ARG;
    }

    /*
        Generation zero represents an empty package,
        not an active pairing request.
    */
    if (package->key_generation == 0)
    {
        ESP_LOGW(
            TAG,
            "pairing challenge creation rejected: "
            "pairing package is empty");

        return ESP_ERR_INVALID_STATE;
    }

    challenge->rc_id =
        package->rc_id;

    challenge->gateway_id =
        package->gateway_id;

    /*
        Bind this challenge to the exact physical Gateway
        that created the PACKAGE.
    */
    challenge->gateway_uid =
        package->gateway_uid;

    challenge->key_generation =
        package->key_generation;

    memset(
        challenge->reserved0,
        0,
        sizeof(challenge->reserved0));

    /*
        An all-zero nonce is reserved for the inactive
        challenge state.

        Retry explicitly, even though sixteen random zero
        bytes are extraordinarily unlikely.
    */
    int nonce_generated = 0;

    for (uint32_t attempt = 0;
         attempt < 4U;
         attempt++)
    {
        esp_fill_random(
            challenge->nonce,
            sizeof(challenge->nonce));

        for (size_t i = 0;
             i < sizeof(challenge->nonce);
             i++)
        {
            if (challenge->nonce[i] != 0)
            {
                nonce_generated = 1;
                break;
            }
        }

        if (nonce_generated)
        {
            break;
        }
    }

    if (!nonce_generated)
    {
        ESP_LOGE(
            TAG,
            "pairing challenge nonce generation failed");

        mathos_pairing_challenge_set_defaults(
            challenge);

        return ESP_FAIL;
    }

    challenge->crc32 = 0;

    challenge->crc32 =
        mathos_pairing_challenge_calculate_crc32(
            challenge);

    /*
        Validate the finished challenge before exposing it
        to the caller or transport layer.
    */
    if (!mathos_pairing_challenge_is_valid(
            challenge))
    {
        ESP_LOGE(
            TAG,
            "generated pairing challenge failed validation");

        mathos_pairing_challenge_set_defaults(
            challenge);

        return ESP_FAIL;
    }

    /*
        The nonce is not secret, but it is deliberately not
        printed to keep security logs compact.
    */
    ESP_LOGI(
        TAG,
        "pairing challenge created "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu crc=0x%08lx",
        challenge->rc_id,
        challenge->gateway_id,
        (unsigned long)
            challenge->key_generation,
        (unsigned long)
            challenge->crc32);

    return ESP_OK;
}

int mathos_pairing_package_is_valid(
    const mathos_pairing_package_t *package)
{
    if (package == NULL)
    {
        return 0;
    }

    /*
        Confirm the expected pairing-package format.
    */
    if (package->magic !=
        MATHOS_PAIRING_PACKAGE_MAGIC)
    {
        return 0;
    }

    if (package->version !=
        MATHOS_PAIRING_PACKAGE_VERSION)
    {
        return 0;
    }

    if (package->record_size !=
        sizeof(mathos_pairing_package_t))
    {
        return 0;
    }

    /*
        Device identities must use the valid range
        1 through 254.
    */
    if (package->rc_id == 0 ||
        package->rc_id == UINT8_MAX)
    {
        return 0;
    }

    if (package->gateway_id == 0 ||
        package->gateway_id == UINT8_MAX)
    {
        return 0;
    }

    /*
        The two devices cannot share the same identity.
    */
    if (package->rc_id ==
        package->gateway_id)
    {
        return 0;
    }
    /*
        Gateway UID rules:

        Empty package:
            generation == 0
            UID must remain all-zero.

        Real pairing package:
            generation > 0
            UID must be a valid permanent hardware UID.

        This preserves a clean inactive/default state while
        preventing a real pairing offer from using an empty
        or invalid Fleet identity.
    */
    if (package->key_generation == 0)
    {
        for (size_t i = 0;
             i < MATHOS_DEVICE_UID_LEN;
             i++)
        {
            if (package->gateway_uid.bytes[i] != 0)
            {
                return 0;
            }
        }
    }
    else
    {
        if (!mathos_device_uid_is_valid(
                &package->gateway_uid))
        {
            return 0;
        }
    }
    /*
        Reserved version-2 fields must remain zero.
    */
    if (package->reserved0 != 0)
    {
        return 0;
    }

    for (size_t i = 0;
         i < sizeof(package->reserved1);
         i++)
    {
        if (package->reserved1[i] != 0)
        {
            return 0;
        }
    }

    /*
        Determine whether the package contains a
        nonzero pairing salt.
    */
    int pairing_salt_is_set = 0;

    for (size_t i = 0;
         i < sizeof(package->pairing_salt);
         i++)
    {
        if (package->pairing_salt[i] != 0)
        {
            pairing_salt_is_set = 1;
            break;
        }
    }

    /*
        Generation zero represents an empty package.

        No derivation method, salt or iteration count
        may exist in this state.
    */
    if (package->key_generation == 0)
    {
        if (package->key_derivation_method !=
                MATHOS_GATEWAY_KEY_DERIVATION_NONE ||
            package->kdf_iteration_count != 0 ||
            pairing_salt_is_set)
        {
            return 0;
        }
    }

    /*
        A real pairing package currently supports only
        PBKDF2-HMAC-SHA256.

        RAW_HEX is not allowed because this package never
        transports the root key itself.
    */
    else
    {
        if (package->key_derivation_method !=
            MATHOS_GATEWAY_KEY_DERIVATION_PBKDF2_SHA256)
        {
            return 0;
        }

        if (!pairing_salt_is_set)
        {
            return 0;
        }

        if (package->kdf_iteration_count <
                MATHOS_PAIRING_KDF_MIN_ITERATIONS ||
            package->kdf_iteration_count >
                MATHOS_PAIRING_KDF_MAX_ITERATIONS)
        {
            return 0;
        }
    }

    /*
        Verify package integrity last.
    */
    uint32_t expected_crc =
        mathos_pairing_package_calculate_crc32(
            package);

    if (package->crc32 != expected_crc)
    {
        return 0;
    }

    return 1;
}

esp_err_t mathos_pairing_package_from_gateway_config(
    const mathos_gateway_config_t *gateway_config,
    const mathos_device_uid_t *gateway_uid,
    mathos_pairing_package_t *package)
{
    if (gateway_config == NULL ||
        gateway_uid == NULL ||
        package == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (!mathos_device_uid_is_valid(
            gateway_uid))
    {
        ESP_LOGE(
            TAG,
            "pairing package creation rejected: "
            "invalid Gateway hardware UID");

        return ESP_ERR_INVALID_ARG;
    }

    /*
        Always begin with a valid empty package.

        If conversion fails, the caller will not receive
        stale or partially written pairing parameters.
    */
    mathos_pairing_package_set_defaults(
        package);

    /*
        Only a completely valid Gateway configuration may
        be used to create a pairing package.
    */
    if (!mathos_gateway_config_is_valid(
            gateway_config))
    {
        ESP_LOGE(
            TAG,
            "pairing package creation rejected: "
            "invalid Gateway configuration");

        return ESP_ERR_INVALID_ARG;
    }

    /*
        An unprovisioned Gateway has no real pairing offer.
    */
    if (gateway_config->key_generation == 0)
    {
        ESP_LOGW(
            TAG,
            "pairing package creation rejected: "
            "Gateway key is not provisioned");

        return ESP_ERR_INVALID_STATE;
    }

    /*
        A shared pairing package currently supports only
        passphrase-derived PBKDF2 keys.

        RAW_HEX cannot be exported because the package
        deliberately contains no root key.
    */
    if (gateway_config->key_derivation_method !=
        MATHOS_GATEWAY_KEY_DERIVATION_PBKDF2_SHA256)
    {
        ESP_LOGW(
            TAG,
            "pairing package creation rejected: "
            "unsupported derivation method=%u",
            gateway_config->key_derivation_method);

        return ESP_ERR_NOT_SUPPORTED;
    }

    /*
        Copy only the public pairing parameters required
        by the RC to derive the same root key.
    */
    package->rc_id =
        gateway_config->authorised_rc_id;

    package->gateway_id =
        gateway_config->gateway_id;

    package->gateway_uid =
        *gateway_uid;

    package->key_derivation_method =
        gateway_config->key_derivation_method;

    package->key_generation =
        gateway_config->key_generation;

    package->kdf_iteration_count =
        gateway_config->kdf_iteration_count;

    memcpy(
        package->pairing_salt,
        gateway_config->pairing_salt,
        sizeof(package->pairing_salt));

    /*
        The Gateway root key is intentionally not copied.
        mathos_pairing_package_t has no root-key field.
    */

    package->reserved0 = 0;

    memset(
        package->reserved1,
        0,
        sizeof(package->reserved1));

    package->crc32 = 0;

    package->crc32 =
        mathos_pairing_package_calculate_crc32(
            package);

    /*
        Validate the finished package before returning it
        to the caller.
    */
    if (!mathos_pairing_package_is_valid(
            package))
    {
        ESP_LOGE(
            TAG,
            "generated pairing package failed validation");

        mathos_pairing_package_set_defaults(
            package);

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "pairing package created "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu iterations=%lu "
        "crc=0x%08lx",
        package->rc_id,
        package->gateway_id,
        (unsigned long)
            package->key_generation,
        (unsigned long)
            package->kdf_iteration_count,
        (unsigned long)
            package->crc32);

    return ESP_OK;
}

esp_err_t mathos_rc_pairing_config_prepare_from_package(
    const mathos_rc_pairing_config_t *current_config,
    const mathos_pairing_package_t *package,
    const char *passphrase,
    mathos_rc_pairing_config_t *candidate_config)
{
    if (current_config == NULL ||
        package == NULL ||
        passphrase == NULL ||
        candidate_config == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Build everything in temporary storage.

        The caller's output configuration is modified only
        after the complete candidate passes validation.
    */
    uint8_t derived_root_key[MATHOS_GATEWAY_ROOT_KEY_LEN] = {0};

    mathos_rc_pairing_config_t candidate = {0};

    esp_err_t result = ESP_OK;

    /*
        The existing RC record must already be valid.

        This includes the safe unpaired default record.
    */
    if (!mathos_rc_pairing_config_is_valid(
            current_config))
    {
        ESP_LOGE(
            TAG,
            "RC pairing candidate rejected: "
            "current configuration is invalid");

        result = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }

    /*
        Never derive a key from an invalid or corrupted
        pairing package.
    */
    if (!mathos_pairing_package_is_valid(
            package))
    {
        ESP_LOGE(
            TAG,
            "RC pairing candidate rejected: "
            "pairing package is invalid");

        result = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }

    /*
        Generation zero represents an empty package and
        cannot create a provisioned RC configuration.
    */
    if (package->key_generation == 0)
    {
        ESP_LOGW(
            TAG,
            "RC pairing candidate rejected: "
            "pairing package is empty");

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        Real shared pairing packages currently support
        PBKDF2-HMAC-SHA256 only.
    */
    if (package->key_derivation_method !=
        MATHOS_GATEWAY_KEY_DERIVATION_PBKDF2_SHA256)
    {
        ESP_LOGW(
            TAG,
            "RC pairing candidate rejected: "
            "unsupported derivation method=%u",
            package->key_derivation_method);

        result = ESP_ERR_NOT_SUPPORTED;
        goto cleanup;
    }

    /*
        Reject an older key generation.

        This prevents a previously captured pairing package
        from rolling the RC back to an obsolete key.
    */
    if (current_config->key_generation != 0 &&
        package->key_generation <
            current_config->key_generation)
    {
        ESP_LOGW(
            TAG,
            "RC pairing candidate rejected: "
            "generation rollback current=%lu received=%lu",
            (unsigned long)
                current_config->key_generation,
            (unsigned long)
                package->key_generation);

        result = ESP_ERR_INVALID_STATE;
        goto cleanup;
    }

    /*
        The same generation number must always refer to the
        same identities, KDF parameters and salt.

        A difference would indicate a generation collision
        or a corrupted pairing workflow.
    */
    if (current_config->key_generation != 0 &&
        package->key_generation ==
            current_config->key_generation)
    {
        if (current_config->rc_id !=
                package->rc_id ||
            current_config->authorised_gateway_id !=
                package->gateway_id ||
            current_config->key_derivation_method !=
                package->key_derivation_method ||
            current_config->kdf_iteration_count !=
                package->kdf_iteration_count ||
            memcmp(
                current_config->pairing_salt,
                package->pairing_salt,
                sizeof(package->pairing_salt)) != 0)
        {
            ESP_LOGW(
                TAG,
                "RC pairing candidate rejected: "
                "same generation has different parameters");

            result = ESP_ERR_INVALID_STATE;
            goto cleanup;
        }
    }

    /*
        Derive the root key using exactly the salt and
        iteration count supplied by the Gateway package.
    */
    result =
        mathos_maintenance_derive_root_key_from_passphrase(
            passphrase,
            package->pairing_salt,
            package->kdf_iteration_count,
            derived_root_key);

    if (result != ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "RC pairing candidate rejected: "
            "root-key derivation failed");

        goto cleanup;
    }

    /*
        When reprocessing the same generation, the derived
        key must match the key already stored by the RC.

        Compare every byte before deciding, rather than
        returning at the first mismatch.
    */
    if (current_config->key_generation != 0 &&
        package->key_generation ==
            current_config->key_generation)
    {
        uint8_t key_mismatch = 0;

        for (size_t i = 0;
             i < sizeof(derived_root_key);
             i++)
        {
            key_mismatch |=
                (uint8_t)(derived_root_key[i] ^
                          current_config->root_key[i]);
        }

        if (key_mismatch != 0)
        {
            ESP_LOGW(
                TAG,
                "RC pairing candidate rejected: "
                "passphrase does not match current generation");

            result = ESP_ERR_INVALID_STATE;
            goto cleanup;
        }
    }

    /*
        Preserve the current configuration counter.

        mathos_rc_pairing_config_save() will increment it
        only after the candidate has been authenticated.
    */
    candidate =
        *current_config;

    candidate.magic =
        MATHOS_RC_PAIRING_CONFIG_MAGIC;

    candidate.version =
        MATHOS_RC_PAIRING_CONFIG_VERSION;

    candidate.record_size =
        sizeof(mathos_rc_pairing_config_t);

    candidate.rc_id =
        package->rc_id;

    candidate.authorised_gateway_id =
        package->gateway_id;

    candidate.key_derivation_method =
        package->key_derivation_method;

    candidate.reserved0 = 0;

    candidate.key_generation =
        package->key_generation;

    candidate.kdf_iteration_count =
        package->kdf_iteration_count;

    memcpy(
        candidate.root_key,
        derived_root_key,
        sizeof(candidate.root_key));

    memcpy(
        candidate.pairing_salt,
        package->pairing_salt,
        sizeof(candidate.pairing_salt));

    memset(
        candidate.reserved1,
        0,
        sizeof(candidate.reserved1));

    candidate.crc32 = 0;

    candidate.crc32 =
        mathos_rc_pairing_config_calculate_crc32(
            &candidate);

    if (!mathos_rc_pairing_config_is_valid(
            &candidate))
    {
        ESP_LOGE(
            TAG,
            "prepared RC pairing candidate "
            "failed validation");

        result = ESP_FAIL;
        goto cleanup;
    }

    /*
        Publish the candidate only after all checks pass.
    */
    *candidate_config =
        candidate;

    ESP_LOGI(
        TAG,
        "RC pairing candidate prepared "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu iterations=%lu",
        candidate.rc_id,
        candidate.authorised_gateway_id,
        (unsigned long)
            candidate.key_generation,
        (unsigned long)
            candidate.kdf_iteration_count);

    result = ESP_OK;

cleanup:

    /*
        Temporary structures contain derived key material.
    */
    maintenance_clear_sensitive_memory(
        derived_root_key,
        sizeof(derived_root_key));

    maintenance_clear_sensitive_memory(
        &candidate,
        sizeof(candidate));

    return result;
}

int mathos_rc_pairing_config_is_valid(
    const mathos_rc_pairing_config_t *config)
{
    if (config == NULL)
    {
        return 0;
    }

    /*
        Confirm that this is the expected RC pairing
        record version and exact structure size.
    */
    if (config->magic !=
        MATHOS_RC_PAIRING_CONFIG_MAGIC)
    {
        return 0;
    }

    if (config->version !=
        MATHOS_RC_PAIRING_CONFIG_VERSION)
    {
        return 0;
    }

    if (config->record_size !=
        sizeof(mathos_rc_pairing_config_t))
    {
        return 0;
    }

    /*
        Device IDs must be between 1 and 254.

        Zero and 255 remain reserved.
    */
    if (config->rc_id == 0 ||
        config->rc_id == UINT8_MAX)
    {
        return 0;
    }

    if (config->authorised_gateway_id == 0 ||
        config->authorised_gateway_id ==
            UINT8_MAX)
    {
        return 0;
    }

    /*
        The RC and Gateway must not use the same
        device identity.
    */
    if (config->rc_id ==
        config->authorised_gateway_id)
    {
        return 0;
    }

    /*
        Reserved version-1 fields must remain zero.
    */
    if (config->reserved0 != 0)
    {
        return 0;
    }

    for (size_t i = 0;
         i < sizeof(config->reserved1);
         i++)
    {
        if (config->reserved1[i] != 0)
        {
            return 0;
        }
    }

    /*
        Determine whether pairing material exists.
    */
    int root_key_is_provisioned = 0;
    int pairing_salt_is_set = 0;

    for (size_t i = 0;
         i < sizeof(config->root_key);
         i++)
    {
        if (config->root_key[i] != 0)
        {
            root_key_is_provisioned = 1;
            break;
        }
    }

    for (size_t i = 0;
         i < sizeof(config->pairing_salt);
         i++)
    {
        if (config->pairing_salt[i] != 0)
        {
            pairing_salt_is_set = 1;
            break;
        }
    }

    /*
        Generation zero represents a completely
        unpaired RC.
    */
    if (config->key_generation == 0)
    {
        if (root_key_is_provisioned ||
            pairing_salt_is_set ||
            config->key_derivation_method !=
                MATHOS_GATEWAY_KEY_DERIVATION_NONE ||
            config->kdf_iteration_count != 0)
        {
            return 0;
        }
    }

    /*
        Temporary compatibility with the older raw
        hexadecimal key workflow.
    */
    else if (config->key_derivation_method ==
             MATHOS_GATEWAY_KEY_DERIVATION_RAW_HEX)
    {
        if (!root_key_is_provisioned ||
            pairing_salt_is_set ||
            config->kdf_iteration_count != 0)
        {
            return 0;
        }
    }

    /*
        Normal passphrase-derived pairing record.
    */
    else if (config->key_derivation_method ==
             MATHOS_GATEWAY_KEY_DERIVATION_PBKDF2_SHA256)
    {
        if (!root_key_is_provisioned ||
            !pairing_salt_is_set)
        {
            return 0;
        }

        if (config->kdf_iteration_count <
                MATHOS_PAIRING_KDF_MIN_ITERATIONS ||
            config->kdf_iteration_count >
                MATHOS_PAIRING_KDF_MAX_ITERATIONS)
        {
            return 0;
        }
    }

    /*
        Any unknown derivation method is rejected.
    */
    else
    {
        return 0;
    }

    /*
        Validate record integrity last.
    */
    uint32_t expected_crc =
        mathos_rc_pairing_config_calculate_crc32(
            config);

    if (config->crc32 != expected_crc)
    {
        return 0;
    }

    return 1;
}

static int mathos_gateway_uart_baud_is_valid(
    uint32_t baud)
{
    switch (baud)
    {
    case 9600:
    case 19200:
    case 38400:
    case 57600:
    case 115200:
    case 230400:
    case 460800:
    case 921600:
        return 1;

    default:
        return 0;
    }
}
int mathos_gateway_config_is_valid(
    const mathos_gateway_config_t *config)
{
    if (config == NULL)
    {
        return 0;
    }

    /*
        Confirm record identity, version and exact size.
    */
    if (config->magic !=
        MATHOS_GATEWAY_CONFIG_MAGIC)
    {
        return 0;
    }

    if (config->version !=
        MATHOS_GATEWAY_CONFIG_VERSION)
    {
        return 0;
    }

    if (config->record_size !=
        sizeof(mathos_gateway_config_t))
    {
        return 0;
    }

    /*
        Device IDs must be between 1 and 254.

        Zero and 255 are reserved.
    */
    if (config->gateway_id == 0 ||
        config->gateway_id == UINT8_MAX)
    {
        return 0;
    }

    if (config->authorised_rc_id == 0 ||
        config->authorised_rc_id == UINT8_MAX)
    {
        return 0;
    }

    if (config->gateway_id ==
        config->authorised_rc_id)
    {
        return 0;
    }

    /*
        Only supported failsafe policies are accepted.
    */
    if (config->failsafe_policy !=
            MATHOS_GATEWAY_FAILSAFE_FC_NATIVE &&
        config->failsafe_policy !=
            MATHOS_GATEWAY_FAILSAFE_RTL)
    {
        return 0;
    }

    /*
        Reserved version-2 fields must remain zero.
    */
    for (size_t i = 0;
         i < sizeof(config->reserved1);
         i++)
    {
        if (config->reserved1[i] != 0)
        {
            return 0;
        }
    }

    /*
        Accept only known UART baud rates.
    */
    if (!mathos_gateway_uart_baud_is_valid(
            config->link_uart_baud))
    {
        return 0;
    }

    if (!mathos_gateway_uart_baud_is_valid(
            config->fc_uart_baud))
    {
        return 0;
    }

    /*
        RC packet timeout.

        Too short creates false link-loss events.
        Too long delays failsafe detection.
    */
    if (config->rc_packet_timeout_ms < 100 ||
        config->rc_packet_timeout_ms > 5000)
    {
        return 0;
    }

    /*
        ArduPilot normally sends HEARTBEAT at roughly
        one-second intervals.
    */
    if (config->fc_heartbeat_timeout_ms < 1000 ||
        config->fc_heartbeat_timeout_ms > 10000)
    {
        return 0;
    }

    /*
        Gateway status and telemetry reporting periods.
    */
    if (config->status_tx_period_ms < 50 ||
        config->status_tx_period_ms > 5000)
    {
        return 0;
    }

    if (config->telemetry_tx_period_ms < 50 ||
        config->telemetry_tx_period_ms > 5000)
    {
        return 0;
    }

    /*
        Determine whether the stored root key and pairing
        salt contain any nonzero bytes.
    */
    int root_key_is_provisioned = 0;
    int pairing_salt_is_set = 0;

    for (size_t i = 0;
         i < sizeof(config->root_key);
         i++)
    {
        if (config->root_key[i] != 0)
        {
            root_key_is_provisioned = 1;
            break;
        }
    }

    for (size_t i = 0;
         i < sizeof(config->pairing_salt);
         i++)
    {
        if (config->pairing_salt[i] != 0)
        {
            pairing_salt_is_set = 1;
            break;
        }
    }

    /*
        Completely unprovisioned state.

        No key, salt, derivation method, or KDF iteration
        count may exist while generation is zero.
    */
    if (config->key_generation == 0)
    {
        if (root_key_is_provisioned ||
            pairing_salt_is_set ||
            config->key_derivation_method !=
                MATHOS_GATEWAY_KEY_DERIVATION_NONE ||
            config->kdf_iteration_count != 0)
        {
            return 0;
        }
    }

    /*
        Provisioned using the temporary hexadecimal-key
        workflow.

        A root key must exist, but no salt or KDF iteration
        count is used.
    */
    else if (config->key_derivation_method ==
             MATHOS_GATEWAY_KEY_DERIVATION_RAW_HEX)
    {
        if (!root_key_is_provisioned ||
            pairing_salt_is_set ||
            config->kdf_iteration_count != 0)
        {
            return 0;
        }
    }

    /*
        Provisioned from a passphrase using
        PBKDF2-HMAC-SHA256.
    */
    else if (config->key_derivation_method ==
             MATHOS_GATEWAY_KEY_DERIVATION_PBKDF2_SHA256)
    {
        if (!root_key_is_provisioned ||
            !pairing_salt_is_set)
        {
            return 0;
        }

        if (config->kdf_iteration_count <
                MATHOS_PAIRING_KDF_MIN_ITERATIONS ||
            config->kdf_iteration_count >
                MATHOS_PAIRING_KDF_MAX_ITERATIONS)
        {
            return 0;
        }
    }

    /*
        A positive key generation with any unknown
        derivation method is invalid.
    */
    else
    {
        return 0;
    }

    /*
        Validate record integrity last.
    */
    uint32_t expected_crc =
        mathos_gateway_config_calculate_crc32(
            config);

    if (config->crc32 != expected_crc)
    {
        return 0;
    }

    return 1;
}

esp_err_t mathos_gateway_config_save(
    const mathos_gateway_config_t *config)
{
    if (config == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Work on a local copy so the caller's RAM
        configuration is not modified directly.
    */
    mathos_gateway_config_t record =
        *config;

    /*
        Refresh the fixed record metadata before saving.
    */
    record.magic =
        MATHOS_GATEWAY_CONFIG_MAGIC;

    record.version =
        MATHOS_GATEWAY_CONFIG_VERSION;

    record.record_size =
        sizeof(mathos_gateway_config_t);

    /*
        Version 2 requires the reserved byte to remain zero.
    */
    memset(
        record.reserved1,
        0,
        sizeof(record.reserved1));

    record.configuration_counter =
        config->configuration_counter + 1U;

    /*
        Protect against uint32_t wrap-around returning
        the counter to the reserved value zero.
    */
    if (record.configuration_counter == 0)
    {
        record.configuration_counter = 1U;
    }

    /*
        Recalculate the CRC after every stored field has
        reached its final value.
    */
    record.crc32 = 0;

    record.crc32 =
        mathos_gateway_config_calculate_crc32(
            &record);

    /*
        Never write an invalid Gateway configuration
        into NVS.
    */
    if (!mathos_gateway_config_is_valid(
            &record))
    {
        ESP_LOGE(
            TAG,
            "gateway configuration save rejected: "
            "invalid fields");

        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;

    esp_err_t err =
        nvs_open(
            MATHOS_MAINTENANCE_NVS_NAMESPACE,
            NVS_READWRITE,
            &handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to open gateway configuration NVS: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Store the Gateway configuration under its own key.

        RC configuration:
            config_v1

        Gateway configuration:
            gateway_v2
    */
    err =
        nvs_set_blob(
            handle,
            MATHOS_GATEWAY_NVS_KEY,
            &record,
            sizeof(record));

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to write gateway configuration: %s",
            esp_err_to_name(err));

        nvs_close(handle);
        return err;
    }

    err =
        nvs_commit(
            handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to commit gateway configuration: %s",
            esp_err_to_name(err));

        nvs_close(handle);
        return err;
    }

    /*
        Read the committed record back before declaring
        the save successful.
    */
    mathos_gateway_config_t verified = {0};

    size_t verified_size =
        sizeof(verified);

    err =
        nvs_get_blob(
            handle,
            MATHOS_GATEWAY_NVS_KEY,
            &verified,
            &verified_size);

    nvs_close(handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "gateway configuration read-back failed: %s",
            esp_err_to_name(err));

        return err;
    }

    if (verified_size != sizeof(verified))
    {
        ESP_LOGE(
            TAG,
            "gateway configuration read-back size mismatch "
            "stored=%u expected=%u",
            (unsigned int)verified_size,
            (unsigned int)sizeof(verified));

        return ESP_FAIL;
    }

    /*
        Validate the record read from flash independently.
    */
    if (!mathos_gateway_config_is_valid(
            &verified))
    {
        ESP_LOGE(
            TAG,
            "gateway configuration read-back "
            "validation failed");

        return ESP_FAIL;
    }

    /*
        The record in flash must exactly match the record
        that we attempted to save.
    */
    if (memcmp(
            &record,
            &verified,
            sizeof(record)) != 0)
    {
        ESP_LOGE(
            TAG,
            "gateway configuration read-back differs "
            "from written record");

        return ESP_FAIL;
    }

    /*
        Never print the root key.

        Only report whether a key generation exists.
    */
    ESP_LOGI(
        TAG,
        "gateway configuration saved and verified "
        "gateway_id=%u rc_id=%u "
        "key_generation=%lu counter=%lu "
        "key_provisioned=%u crc=0x%08lx",
        verified.gateway_id,
        verified.authorised_rc_id,
        (unsigned long)verified.key_generation,
        (unsigned long)verified.configuration_counter,
        verified.key_generation != 0 ? 1U : 0U,
        (unsigned long)verified.crc32);

    return ESP_OK;
}

esp_err_t mathos_gateway_config_load(
    mathos_gateway_config_t *config,
    int *loaded_from_nvs)
{
    if (config == NULL ||
        loaded_from_nvs == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Always begin with a complete and valid safe
        Gateway configuration.

        If NVS is empty, corrupted or incompatible,
        these defaults remain available to the caller.
    */
    mathos_gateway_config_set_defaults(
        config);

    *loaded_from_nvs = 0;

    nvs_handle_t handle;

    esp_err_t err =
        nvs_open(
            MATHOS_MAINTENANCE_NVS_NAMESPACE,
            NVS_READONLY,
            &handle);

    /*
        A new Gateway may not have an NVS namespace yet.
        This is normal and not a fatal condition.
    */
    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGI(
            TAG,
            "no saved gateway configuration; "
            "using defaults");

        return ESP_OK;
    }

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to open gateway configuration NVS: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Read the stored blob size first.

        This prevents an older or incompatible record
        from being read into the current structure.
    */
    size_t stored_size = 0;

    err =
        nvs_get_blob(
            handle,
            MATHOS_GATEWAY_NVS_KEY,
            NULL,
            &stored_size);

    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGI(
            TAG,
            "no saved gateway configuration; "
            "using defaults");

        nvs_close(handle);
        return ESP_OK;
    }

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to read gateway configuration size: %s",
            esp_err_to_name(err));

        nvs_close(handle);
        return err;
    }

    if (stored_size !=
        sizeof(mathos_gateway_config_t))
    {
        ESP_LOGE(
            TAG,
            "gateway configuration size mismatch "
            "stored=%u expected=%u; using defaults",
            (unsigned int)stored_size,
            (unsigned int)sizeof(mathos_gateway_config_t));

        nvs_close(handle);
        return ESP_ERR_INVALID_SIZE;
    }

    mathos_gateway_config_t stored = {0};

    size_t read_size =
        sizeof(stored);

    err =
        nvs_get_blob(
            handle,
            MATHOS_GATEWAY_NVS_KEY,
            &stored,
            &read_size);

    nvs_close(handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to read gateway configuration: %s",
            esp_err_to_name(err));

        return err;
    }

    if (read_size != sizeof(stored))
    {
        ESP_LOGE(
            TAG,
            "gateway configuration read size mismatch "
            "read=%u expected=%u; using defaults",
            (unsigned int)read_size,
            (unsigned int)sizeof(stored));

        return ESP_ERR_INVALID_SIZE;
    }

    /*
        This validates:

        - magic
        - version
        - structure size
        - device identities
        - failsafe policy
        - UART baud rates
        - timeout ranges
        - root-key generation rules
        - CRC32
    */
    if (!mathos_gateway_config_is_valid(
            &stored))
    {
        ESP_LOGE(
            TAG,
            "saved gateway configuration is invalid; "
            "using defaults");

        return ESP_FAIL;
    }

    /*
        Activate the saved configuration only after
        complete validation.
    */
    *config = stored;
    *loaded_from_nvs = 1;

    /*
        Never print the cryptographic root key.
    */
    ESP_LOGI(
        TAG,
        "gateway configuration loaded "
        "gateway_id=%u rc_id=%u "
        "key_generation=%lu "
        "key_provisioned=%u "
        "link_baud=%lu fc_baud=%lu "
        "rc_timeout=%u fc_timeout=%u "
        "status_period=%u telemetry_period=%u "
        "failsafe_policy=%u counter=%lu "
        "crc=0x%08lx",
        config->gateway_id,
        config->authorised_rc_id,
        (unsigned long)
            config->key_generation,
        config->key_generation != 0
            ? 1U
            : 0U,
        (unsigned long)
            config->link_uart_baud,
        (unsigned long)
            config->fc_uart_baud,
        config->rc_packet_timeout_ms,
        config->fc_heartbeat_timeout_ms,
        config->status_tx_period_ms,
        config->telemetry_tx_period_ms,
        config->failsafe_policy,
        (unsigned long)
            config->configuration_counter,
        (unsigned long)
            config->crc32);

    return ESP_OK;
}
void mathos_maintenance_config_set_defaults(
    mathos_maintenance_config_t *config)
{
    if (config == NULL)
    {
        return;
    }

    memset(
        config,
        0,
        sizeof(*config));

    config->magic =
        MATHOS_MAINTENANCE_CONFIG_MAGIC;

    config->version =
        MATHOS_MAINTENANCE_CONFIG_VERSION;

    config->record_size =
        sizeof(mathos_maintenance_config_t);

    /*
        Telemetry forwarding remains disabled until
        valid Wi-Fi and server settings are configured.
    */
    config->telemetry_enabled = 0;

    /*
        Empty strings mean no configuration exists yet.
    */
    config->wifi_ssid[0] = '\0';
    config->server_host[0] = '\0';

    config->server_port = 0;

    config->crc32 = mathos_maintenance_config_calculate_crc32(config);
}

int mathos_maintenance_config_is_valid(
    const mathos_maintenance_config_t *config)
{
    if (config == NULL)
    {
        return 0;
    }

    if (config->magic !=
        MATHOS_MAINTENANCE_CONFIG_MAGIC)
    {
        return 0;
    }

    if (config->version !=
        MATHOS_MAINTENANCE_CONFIG_VERSION)
    {
        return 0;
    }

    if (config->record_size !=
        sizeof(mathos_maintenance_config_t))
    {
        return 0;
    }

    if (config->telemetry_enabled > 1)
    {
        return 0;
    }

    /*
        Both character arrays must contain a null
        terminator inside their allocated storage.
    */
    if (memchr(
            config->wifi_ssid,
            '\0',
            sizeof(config->wifi_ssid)) == NULL)
    {
        return 0;
    }

    if (memchr(
            config->server_host,
            '\0',
            sizeof(config->server_host)) == NULL)
    {
        return 0;
    }

    /*
        Reserved fields must remain zero for version 1.
        This prevents undefined data from entering NVS.
    */
    for (size_t i = 0;
         i < sizeof(config->reserved);
         i++)
    {
        if (config->reserved[i] != 0)
        {
            return 0;
        }
    }

    if (config->reserved2 != 0)
    {
        return 0;
    }

    /*
        When telemetry forwarding is enabled, all
        required connection settings must exist.
    */
    if (config->telemetry_enabled)
    {
        if (config->wifi_ssid[0] == '\0')
        {
            return 0;
        }

        if (config->server_host[0] == '\0')
        {
            return 0;
        }

        if (config->server_port == 0)
        {
            return 0;
        }
    }

    uint32_t expected_crc =
        mathos_maintenance_config_calculate_crc32(
            config);

    if (config->crc32 != expected_crc)
    {
        return 0;
    }

    return 1;
}

esp_err_t mathos_maintenance_config_save(
    const mathos_maintenance_config_t *config)
{
    if (config == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Work on a local copy.

        This allows the save function to refresh the
        metadata and CRC without modifying the caller's
        configuration object.
    */
    mathos_maintenance_config_t record =
        *config;

    record.magic =
        MATHOS_MAINTENANCE_CONFIG_MAGIC;

    record.version =
        MATHOS_MAINTENANCE_CONFIG_VERSION;

    record.record_size =
        sizeof(mathos_maintenance_config_t);

    /*
        Reserved fields must remain zero in version 1.
    */
    memset(
        record.reserved,
        0,
        sizeof(record.reserved));

    record.reserved2 = 0;

    /*
        Recalculate CRC after all fields have reached
        their final stored values.
    */
    record.crc32 = 0;

    record.crc32 =
        mathos_maintenance_config_calculate_crc32(
            &record);

    if (!mathos_maintenance_config_is_valid(
            &record))
    {
        ESP_LOGE(
            TAG,
            "configuration save rejected: invalid fields");

        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t handle;

    esp_err_t err =
        nvs_open(
            MATHOS_MAINTENANCE_NVS_NAMESPACE,
            NVS_READWRITE,
            &handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to open maintenance NVS: %s",
            esp_err_to_name(err));

        return err;
    }

    err =
        nvs_set_blob(
            handle,
            MATHOS_MAINTENANCE_NVS_KEY,
            &record,
            sizeof(record));

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to write maintenance config: %s",
            esp_err_to_name(err));

        nvs_close(handle);
        return err;
    }

    err =
        nvs_commit(
            handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to commit maintenance config: %s",
            esp_err_to_name(err));

        nvs_close(handle);
        return err;
    }

    /*
        Read the committed record back before declaring
        the operation successful.
    */
    mathos_maintenance_config_t verified = {0};

    size_t verified_size =
        sizeof(verified);

    err =
        nvs_get_blob(
            handle,
            MATHOS_MAINTENANCE_NVS_KEY,
            &verified,
            &verified_size);

    nvs_close(handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "maintenance config read-back failed: %s",
            esp_err_to_name(err));

        return err;
    }

    if (verified_size != sizeof(verified))
    {
        ESP_LOGE(
            TAG,
            "maintenance config read-back size mismatch "
            "stored=%u expected=%u",
            (unsigned int)verified_size,
            (unsigned int)sizeof(verified));

        return ESP_FAIL;
    }

    if (!mathos_maintenance_config_is_valid(
            &verified))
    {
        ESP_LOGE(
            TAG,
            "maintenance config read-back validation failed");

        return ESP_FAIL;
    }

    if (memcmp(
            &record,
            &verified,
            sizeof(record)) != 0)
    {
        ESP_LOGE(
            TAG,
            "maintenance config read-back differs "
            "from written record");

        return ESP_FAIL;
    }

    ESP_LOGI(
        TAG,
        "maintenance configuration saved and verified "
        "telemetry=%u port=%u crc=0x%08lx",
        verified.telemetry_enabled,
        verified.server_port,
        (unsigned long)verified.crc32);

    return ESP_OK;
}

esp_err_t mathos_maintenance_config_load(
    mathos_maintenance_config_t *config,
    int *loaded_from_nvs)
{
    if (config == NULL ||
        loaded_from_nvs == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Always begin with a complete and valid safe
        configuration.

        If NVS is empty or invalid, the caller can still
        safely use this default record.
    */
    mathos_maintenance_config_set_defaults(
        config);

    *loaded_from_nvs = 0;

    nvs_handle_t handle;

    esp_err_t err =
        nvs_open(
            MATHOS_MAINTENANCE_NVS_NAMESPACE,
            NVS_READONLY,
            &handle);

    /*
        A new device may not have a maintenance
        namespace yet. This is not a fatal condition.
    */
    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGI(
            TAG,
            "no saved maintenance configuration; "
            "using defaults");

        return ESP_OK;
    }

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to open maintenance NVS: %s",
            esp_err_to_name(err));

        return err;
    }

    size_t stored_size = 0;

    err =
        nvs_get_blob(
            handle,
            MATHOS_MAINTENANCE_NVS_KEY,
            NULL,
            &stored_size);

    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGI(
            TAG,
            "no saved maintenance configuration; "
            "using defaults");

        nvs_close(handle);
        return ESP_OK;
    }

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to read maintenance config size: %s",
            esp_err_to_name(err));

        nvs_close(handle);
        return err;
    }

    if (stored_size !=
        sizeof(mathos_maintenance_config_t))
    {
        ESP_LOGE(
            TAG,
            "maintenance config size mismatch "
            "stored=%u expected=%u; using defaults",
            (unsigned int)stored_size,
            (unsigned int)sizeof(mathos_maintenance_config_t));

        nvs_close(handle);
        return ESP_ERR_INVALID_SIZE;
    }

    mathos_maintenance_config_t stored = {0};

    size_t read_size =
        sizeof(stored);

    err =
        nvs_get_blob(
            handle,
            MATHOS_MAINTENANCE_NVS_KEY,
            &stored,
            &read_size);

    nvs_close(handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to read maintenance configuration: %s",
            esp_err_to_name(err));

        return err;
    }

    if (read_size != sizeof(stored))
    {
        ESP_LOGE(
            TAG,
            "maintenance config read size mismatch "
            "read=%u expected=%u; using defaults",
            (unsigned int)read_size,
            (unsigned int)sizeof(stored));

        return ESP_ERR_INVALID_SIZE;
    }

    if (!mathos_maintenance_config_is_valid(
            &stored))
    {
        ESP_LOGE(
            TAG,
            "saved maintenance configuration is invalid; "
            "using defaults");

        return ESP_FAIL;
    }

    /*
        Activate the stored record only after all
        validation checks have passed.
    */
    *config = stored;
    *loaded_from_nvs = 1;

    ESP_LOGI(
        TAG,
        "maintenance configuration loaded "
        "telemetry=%u ssid_set=%u host_set=%u "
        "port=%u crc=0x%08lx",
        config->telemetry_enabled,
        config->wifi_ssid[0] != '\0' ? 1U : 0U,
        config->server_host[0] != '\0' ? 1U : 0U,
        config->server_port,
        (unsigned long)config->crc32);

    return ESP_OK;
}

static const char *maintenance_role_to_page_text(
    mathos_maintenance_role_t role)
{
    switch (role)
    {
    case MATHOS_MAINTENANCE_ROLE_RC:
        return "Remote Controller";

    case MATHOS_MAINTENANCE_ROLE_GATEWAY:
        return "Drone Gateway";

    default:
        return "Unknown Device";
    }
}

static esp_err_t maintenance_html_escape(
    const char *source,
    char *destination,
    size_t destination_size)
{
    if (source == NULL ||
        destination == NULL ||
        destination_size == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    size_t output_index = 0;

    for (size_t input_index = 0;
         source[input_index] != '\0';
         input_index++)
    {
        const char *replacement = NULL;

        switch (source[input_index])
        {
        case '&':
            replacement = "&amp;";
            break;

        case '<':
            replacement = "&lt;";
            break;

        case '>':
            replacement = "&gt;";
            break;

        case '"':
            replacement = "&quot;";
            break;

        case '\'':
            replacement = "&#39;";
            break;

        default:
            break;
        }

        if (replacement != NULL)
        {
            size_t replacement_length =
                strlen(replacement);

            if ((output_index +
                 replacement_length) >=
                destination_size)
            {
                destination[0] = '\0';
                return ESP_ERR_INVALID_SIZE;
            }

            memcpy(
                &destination[output_index],
                replacement,
                replacement_length);

            output_index +=
                replacement_length;
        }
        else
        {
            if ((output_index + 1) >=
                destination_size)
            {
                destination[0] = '\0';
                return ESP_ERR_INVALID_SIZE;
            }

            destination[output_index++] =
                source[input_index];
        }
    }

    destination[output_index] = '\0';

    return ESP_OK;
}
static int maintenance_hex_value(
    char character)
{
    if (character >= '0' &&
        character <= '9')
    {
        return character - '0';
    }

    if (character >= 'a' &&
        character <= 'f')
    {
        return 10 +
               (character - 'a');
    }

    if (character >= 'A' &&
        character <= 'F')
    {
        return 10 +
               (character - 'A');
    }

    return -1;
}

static esp_err_t maintenance_url_decode(
    const char *source,
    size_t source_length,
    char *destination,
    size_t destination_size)
{
    if (source == NULL ||
        destination == NULL ||
        destination_size == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    size_t output_index = 0;

    for (size_t input_index = 0;
         input_index < source_length;
         input_index++)
    {
        char decoded_character;

        /*
            HTML forms encode spaces as plus signs.
        */
        if (source[input_index] == '+')
        {
            decoded_character = ' ';
        }
        else if (source[input_index] == '%')
        {
            /*
                Percent encoding requires exactly
                two following hexadecimal digits.
            */
            if ((input_index + 2) >=
                source_length)
            {
                destination[0] = '\0';
                return ESP_ERR_INVALID_ARG;
            }

            int high =
                maintenance_hex_value(
                    source[input_index + 1]);

            int low =
                maintenance_hex_value(
                    source[input_index + 2]);

            if (high < 0 ||
                low < 0)
            {
                destination[0] = '\0';
                return ESP_ERR_INVALID_ARG;
            }

            decoded_character =
                (char)((high << 4) | low);

            input_index += 2;

            /*
                Reject encoded null bytes so strings
                cannot be silently truncated.
            */
            if (decoded_character == '\0')
            {
                destination[0] = '\0';
                return ESP_ERR_INVALID_ARG;
            }
        }
        else
        {
            decoded_character =
                source[input_index];
        }

        if ((output_index + 1) >=
            destination_size)
        {
            destination[0] = '\0';
            return ESP_ERR_INVALID_SIZE;
        }

        destination[output_index++] =
            decoded_character;
    }

    destination[output_index] = '\0';

    return ESP_OK;
}
static esp_err_t maintenance_form_get_value(
    const char *body,
    const char *field_name,
    char *destination,
    size_t destination_size)
{
    if (body == NULL ||
        field_name == NULL ||
        destination == NULL ||
        destination_size == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    destination[0] = '\0';

    size_t field_name_length =
        strlen(field_name);

    const char *field_start =
        body;

    while (*field_start != '\0')
    {
        const char *field_end =
            strchr(
                field_start,
                '&');

        if (field_end == NULL)
        {
            field_end =
                field_start +
                strlen(field_start);
        }

        const char *equals =
            memchr(
                field_start,
                '=',
                (size_t)(field_end -
                         field_start));

        if (equals != NULL)
        {
            size_t current_name_length =
                (size_t)(equals -
                         field_start);

            if (current_name_length ==
                    field_name_length &&
                memcmp(
                    field_start,
                    field_name,
                    field_name_length) == 0)
            {
                const char *encoded_value =
                    equals + 1;

                size_t encoded_length =
                    (size_t)(field_end -
                             encoded_value);

                return maintenance_url_decode(
                    encoded_value,
                    encoded_length,
                    destination,
                    destination_size);
            }
        }

        if (*field_end == '\0')
        {
            break;
        }

        field_start =
            field_end + 1;
    }

    return ESP_ERR_NOT_FOUND;
}

static esp_err_t maintenance_send_text_response(
    httpd_req_t *request,
    const char *status,
    const char *message)
{
    if (request == NULL ||
        status == NULL ||
        message == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err =
        httpd_resp_set_status(
            request,
            status);

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        httpd_resp_set_type(
            request,
            "text/plain; charset=utf-8");

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        httpd_resp_set_hdr(
            request,
            "Cache-Control",
            "no-store");

    if (err != ESP_OK)
    {
        return err;
    }

    return httpd_resp_send(
        request,
        message,
        HTTPD_RESP_USE_STRLEN);
}

static esp_err_t maintenance_build_role_section(
    mathos_maintenance_role_t role,
    const char *config_source_text,
    const char *telemetry_state_text,
    const char *telemetry_checked_text,
    const char *wifi_ssid_html,
    const char *server_host_html,
    const char *server_port_text,
    const char *server_port_form,
    char *destination,
    size_t destination_size)
{
    if (config_source_text == NULL ||
        telemetry_state_text == NULL ||
        telemetry_checked_text == NULL ||
        wifi_ssid_html == NULL ||
        server_host_html == NULL ||
        server_port_text == NULL ||
        server_port_form == NULL ||
        destination == NULL ||
        destination_size == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    int written = 0;

    switch (role)
    {
    case MATHOS_MAINTENANCE_ROLE_RC:
    {
        const char *pairing_source_text =
            maintenance_rc_pairing_config_loaded_from_nvs
                ? "Saved pairing"
                : "Unpaired defaults";

        const char *pairing_state_text =
            maintenance_active_rc_pairing_config
                        .key_generation != 0
                ? "Paired"
                : "Not paired";

        written = snprintf(
            destination,
            destination_size,

            "<div class=\"label\">Configuration source</div>"
            "<div class=\"value\">%s</div>"

            "<div class=\"label\">Pairing source</div>"
            "<div class=\"value\">%s</div>"

            "<div class=\"label\">Pairing status</div>"
            "<div class=\"value\">%s</div>"

            "<div class=\"label\">RC ID</div>"
            "<div class=\"value\">%u</div>"

            "<div class=\"label\">Authorised Gateway ID</div>"
            "<div class=\"value\">%u</div>"

            "<div class=\"label\">Key generation</div>"
            "<div class=\"value\">%lu</div>"

            "<div class=\"label\">Telemetry forwarding</div>"
            "<div class=\"value\">%s</div>"

            "<div class=\"label\">Telemetry Wi-Fi SSID</div>"
            "<div class=\"value\">%s</div>"

            "<div class=\"label\">Telemetry server</div>"
            "<div class=\"value\">%s</div>"

            "<div class=\"label\">Server port</div>"
            "<div class=\"value\">%s</div>"

            "<section class=\"editor\">"
            "<h2>Remote controller configuration</h2>"

            "<form method=\"post\" action=\"/config/rc\">"

            "<label class=\"toggle\">"
            "<input type=\"checkbox\" "
            "name=\"telemetry_enabled\" value=\"1\"%s>"
            "<span>Enable telemetry forwarding</span>"
            "</label>"

            "<label class=\"form-label\" "
            "for=\"wifi_ssid\">Telemetry Wi-Fi SSID</label>"

            "<input class=\"form-input\" "
            "id=\"wifi_ssid\" "
            "name=\"wifi_ssid\" "
            "type=\"text\" "
            "maxlength=\"32\" "
            "value=\"%s\" "
            "autocomplete=\"off\">"

            "<label class=\"form-label\" "
            "for=\"server_host\">Telemetry server</label>"

            "<input class=\"form-input\" "
            "id=\"server_host\" "
            "name=\"server_host\" "
            "type=\"text\" "
            "maxlength=\"63\" "
            "value=\"%s\" "
            "autocomplete=\"off\">"

            "<label class=\"form-label\" "
            "for=\"server_port\">Server port</label>"

            "<input class=\"form-input\" "
            "id=\"server_port\" "
            "name=\"server_port\" "
            "type=\"number\" "
            "min=\"1\" "
            "max=\"65535\" "
            "value=\"%s\">"

            "<button class=\"save-button\" "
            "type=\"submit\">Save RC configuration</button>"

            "<div class=\"warning\">"
            "Joystick calibration will be added as a separate "
            "RC-only maintenance section."
            "</div>"

            "</form>"
            "</section>"

            "<section class=\"editor\">"
            "<h2>Secure Gateway Pairing</h2>"

            "<div class=\"warning\">"
            "The Gateway must already be in maintenance pairing mode "
            "and the RC must have received its pairing challenge."
            "</div>"

            "<form method=\"post\" action=\"/pair/rc\">"

            "<label class=\"form-label\" "
            "for=\"pairing_passphrase\">Pairing passphrase</label>"

            "<input class=\"form-input\" "
            "id=\"pairing_passphrase\" "
            "name=\"pairing_passphrase\" "
            "type=\"password\" "
            "minlength=\"16\" "
            "maxlength=\"96\" "
            "autocomplete=\"new-password\" "
            "required>"

            "<label class=\"form-label\" "
            "for=\"pairing_passphrase_confirm\">Confirm passphrase</label>"

            "<input class=\"form-input\" "
            "id=\"pairing_passphrase_confirm\" "
            "name=\"pairing_passphrase_confirm\" "
            "type=\"password\" "
            "minlength=\"16\" "
            "maxlength=\"96\" "
            "autocomplete=\"new-password\" "
            "required>"

            "<button class=\"save-button\" "
            "type=\"submit\">Authenticate Pairing</button>"

            "<div class=\"warning\">"
            "The passphrase is used only to derive the temporary "
            "pairing key. It is not stored in NVS and is not "
            "transmitted to the Gateway."
            "</div>"

            "</form>"
            "</section>",

            config_source_text,
            pairing_source_text,
            pairing_state_text,

            maintenance_active_rc_pairing_config.rc_id,

            maintenance_active_rc_pairing_config
                .authorised_gateway_id,

            (unsigned long)
                maintenance_active_rc_pairing_config
                    .key_generation,

            telemetry_state_text,
            wifi_ssid_html,
            server_host_html,
            server_port_text,
            telemetry_checked_text,
            wifi_ssid_html,
            server_host_html,
            server_port_form);

        break;
    }
    case MATHOS_MAINTENANCE_ROLE_GATEWAY:
    {
        const char *key_state_text =
            maintenance_active_gateway_config.key_generation != 0
                ? "Provisioned"
                : "Not provisioned";

        const char *failsafe_text =
            maintenance_active_gateway_config.failsafe_policy ==
                    MATHOS_GATEWAY_FAILSAFE_RTL
                ? "Request RTL"
                : "Flight-controller native";

        const char *fc_native_selected =
            maintenance_active_gateway_config.failsafe_policy ==
                    MATHOS_GATEWAY_FAILSAFE_FC_NATIVE
                ? " selected"
                : "";

        const char *rtl_selected =
            maintenance_active_gateway_config.failsafe_policy ==
                    MATHOS_GATEWAY_FAILSAFE_RTL
                ? " selected"
                : "";

        written = snprintf(
            destination,
            destination_size,

            "<div class=\"label\">Configuration source</div>"
            "<div class=\"value\">%s</div>"

            "<div class=\"label\">Security key</div>"
            "<div class=\"value\">%s</div>"

            "<div class=\"label\">Key generation</div>"
            "<div class=\"value\">%lu</div>"

            "<div class=\"label\">Configuration counter</div>"
            "<div class=\"value\">%lu</div>"

            "<section class=\"editor\">"
            "<h2>Gateway configuration</h2>"

            "<form method=\"post\" action=\"/config/gateway\">"

            "<label class=\"form-label\" "
            "for=\"gateway_id\">Gateway ID</label>"

            "<input class=\"form-input\" "
            "id=\"gateway_id\" "
            "name=\"gateway_id\" "
            "type=\"number\" "
            "min=\"1\" "
            "max=\"254\" "
            "value=\"%u\" "
            "required>"

            "<label class=\"form-label\" "
            "for=\"authorised_rc_id\">Authorised RC ID</label>"

            "<input class=\"form-input\" "
            "id=\"authorised_rc_id\" "
            "name=\"authorised_rc_id\" "
            "type=\"number\" "
            "min=\"1\" "
            "max=\"254\" "
            "value=\"%u\" "
            "required>"

            "<label class=\"form-label\" "
            "for=\"pairing_passphrase\">"
            "New pairing passphrase"
            "</label>"

            "<input class=\"form-input\" "
            "id=\"pairing_passphrase\" "
            "name=\"pairing_passphrase\" "
            "type=\"password\" "
            "minlength=\"16\" "
            "maxlength=\"96\" "
            "placeholder=\"16 to 96 characters\" "
            "autocomplete=\"new-password\">"

            "<label class=\"form-label\" "
            "for=\"pairing_passphrase_confirm\">"
            "Confirm pairing passphrase"
            "</label>"

            "<input class=\"form-input\" "
            "id=\"pairing_passphrase_confirm\" "
            "name=\"pairing_passphrase_confirm\" "
            "type=\"password\" "
            "minlength=\"16\" "
            "maxlength=\"96\" "
            "placeholder=\"Enter the same passphrase again\" "
            "autocomplete=\"new-password\">"

            "<div class=\"warning\">"
            "Leave both fields empty to preserve the currently "
            "provisioned key. The passphrase and derived key are "
            "never displayed or logged."
            "</div>"

            "<label class=\"form-label\" "
            "for=\"link_uart_baud\">RC-link UART baud</label>"

            "<input class=\"form-input\" "
            "id=\"link_uart_baud\" "
            "name=\"link_uart_baud\" "
            "type=\"number\" "
            "list=\"gateway_baud_rates\" "
            "value=\"%lu\" "
            "required>"

            "<label class=\"form-label\" "
            "for=\"fc_uart_baud\">Flight-controller UART baud</label>"

            "<input class=\"form-input\" "
            "id=\"fc_uart_baud\" "
            "name=\"fc_uart_baud\" "
            "type=\"number\" "
            "list=\"gateway_baud_rates\" "
            "value=\"%lu\" "
            "required>"

            "<datalist id=\"gateway_baud_rates\">"
            "<option value=\"9600\">"
            "<option value=\"19200\">"
            "<option value=\"38400\">"
            "<option value=\"57600\">"
            "<option value=\"115200\">"
            "<option value=\"230400\">"
            "<option value=\"460800\">"
            "<option value=\"921600\">"
            "</datalist>"

            "<label class=\"form-label\" "
            "for=\"rc_packet_timeout_ms\">RC packet timeout</label>"

            "<input class=\"form-input\" "
            "id=\"rc_packet_timeout_ms\" "
            "name=\"rc_packet_timeout_ms\" "
            "type=\"number\" "
            "min=\"100\" "
            "max=\"5000\" "
            "value=\"%u\" "
            "required>"

            "<label class=\"form-label\" "
            "for=\"fc_heartbeat_timeout_ms\">"
            "FC heartbeat timeout"
            "</label>"

            "<input class=\"form-input\" "
            "id=\"fc_heartbeat_timeout_ms\" "
            "name=\"fc_heartbeat_timeout_ms\" "
            "type=\"number\" "
            "min=\"1000\" "
            "max=\"10000\" "
            "value=\"%u\" "
            "required>"

            "<label class=\"form-label\" "
            "for=\"status_tx_period_ms\">"
            "Status transmission period"
            "</label>"

            "<input class=\"form-input\" "
            "id=\"status_tx_period_ms\" "
            "name=\"status_tx_period_ms\" "
            "type=\"number\" "
            "min=\"50\" "
            "max=\"5000\" "
            "value=\"%u\" "
            "required>"

            "<label class=\"form-label\" "
            "for=\"telemetry_tx_period_ms\">"
            "Telemetry transmission period"
            "</label>"

            "<input class=\"form-input\" "
            "id=\"telemetry_tx_period_ms\" "
            "name=\"telemetry_tx_period_ms\" "
            "type=\"number\" "
            "min=\"50\" "
            "max=\"5000\" "
            "value=\"%u\" "
            "required>"

            "<label class=\"form-label\" "
            "for=\"failsafe_policy\">Failsafe policy</label>"

            "<select class=\"form-input\" "
            "id=\"failsafe_policy\" "
            "name=\"failsafe_policy\">"

            "<option value=\"0\"%s>"
            "Flight-controller native"
            "</option>"

            "<option value=\"1\"%s>"
            "Request RTL"
            "</option>"

            "</select>"
            "<button class=\"save-button\" "
            "type=\"submit\">"
            "Save Gateway configuration"
            "</button>"

            "<div class=\"warning\">"
            "Current failsafe policy: %s."
            "</div>"

            "<div class=\"warning\">"
            "Changes are validated, saved to NVS and activated "
            "after the Gateway restarts."
            "</div>"

            "</form>"
            "</section>",

            config_source_text,
            key_state_text,

            (unsigned long)
                maintenance_active_gateway_config.key_generation,

            (unsigned long)
                maintenance_active_gateway_config.configuration_counter,

            maintenance_active_gateway_config.gateway_id,
            maintenance_active_gateway_config.authorised_rc_id,

            (unsigned long)
                maintenance_active_gateway_config.link_uart_baud,

            (unsigned long)
                maintenance_active_gateway_config.fc_uart_baud,

            maintenance_active_gateway_config.rc_packet_timeout_ms,
            maintenance_active_gateway_config.fc_heartbeat_timeout_ms,
            maintenance_active_gateway_config.status_tx_period_ms,
            maintenance_active_gateway_config.telemetry_tx_period_ms,

            fc_native_selected,
            rtl_selected,
            failsafe_text);

        break;
    }

    default:

        destination[0] = '\0';
        return ESP_ERR_INVALID_ARG;
    }

    if (written < 0 ||
        (size_t)written >= destination_size)
    {
        destination[0] = '\0';
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}

static esp_err_t maintenance_root_get_handler(httpd_req_t *request)
{
    ESP_LOGI(
        TAG,
        "HTTP GET / received");

    if (request == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    const char *device_text =
        maintenance_role_to_page_text(
            maintenance_active_role);

    char ip_text[16] = "Unavailable";

    char wifi_ssid_html[193] =
        "Not configured";

    char server_host_html[384] =
        "Not configured";

    esp_err_t ip_err =
        mathos_maintenance_get_ap_ip(
            ip_text,
            sizeof(ip_text));

    if (ip_err != ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "failed to read maintenance AP IP: %s",
            esp_err_to_name(ip_err));
    }

    if (maintenance_active_config.wifi_ssid[0] != '\0')
    {
        esp_err_t escape_err =
            maintenance_html_escape(
                maintenance_active_config.wifi_ssid,
                wifi_ssid_html,
                sizeof(wifi_ssid_html));

        if (escape_err != ESP_OK)
        {
            ESP_LOGW(
                TAG,
                "failed to escape Wi-Fi SSID: %s",
                esp_err_to_name(escape_err));

            snprintf(
                wifi_ssid_html,
                sizeof(wifi_ssid_html),
                "Invalid value");
        }
    }

    if (maintenance_active_config.server_host[0] != '\0')
    {
        esp_err_t escape_err =
            maintenance_html_escape(
                maintenance_active_config.server_host,
                server_host_html,
                sizeof(server_host_html));

        if (escape_err != ESP_OK)
        {
            ESP_LOGW(
                TAG,
                "failed to escape server host: %s",
                esp_err_to_name(escape_err));

            snprintf(
                server_host_html,
                sizeof(server_host_html),
                "Invalid value");
        }
    }
    const char *config_source_text = "Safe defaults";

    if (maintenance_active_role ==
        MATHOS_MAINTENANCE_ROLE_RC)
    {
        config_source_text =
            maintenance_config_loaded_from_nvs
                ? "Saved configuration"
                : "Safe defaults";
    }
    else if (maintenance_active_role ==
             MATHOS_MAINTENANCE_ROLE_GATEWAY)
    {
        config_source_text =
            maintenance_gateway_config_loaded_from_nvs
                ? "Saved configuration"
                : "Safe defaults";
    }

    const char *telemetry_state_text =
        maintenance_active_config.telemetry_enabled
            ? "Enabled"
            : "Disabled";
    const char *telemetry_checked_text =
        maintenance_active_config.telemetry_enabled
            ? " checked"
            : "";

    char server_port_text[20] =
        "Not configured";

    char server_port_form[6] =
        "";

    if (maintenance_active_config.server_port != 0)
    {
        snprintf(
            server_port_text,
            sizeof(server_port_text),
            "%u",
            (unsigned int)
                maintenance_active_config.server_port);

        snprintf(
            server_port_form,
            sizeof(server_port_form),
            "%u",
            (unsigned int)
                maintenance_active_config.server_port);
    }
    char *role_section_html =
        malloc(
            MATHOS_MAINTENANCE_ROLE_SECTION_BUFFER_SIZE);

    if (role_section_html == NULL)
    {
        ESP_LOGE(
            TAG,
            "failed to allocate role-specific page section");

        return ESP_ERR_NO_MEM;
    }

    esp_err_t role_section_err =
        maintenance_build_role_section(
            maintenance_active_role,
            config_source_text,
            telemetry_state_text,
            telemetry_checked_text,
            wifi_ssid_html,
            server_host_html,
            server_port_text,
            server_port_form,
            role_section_html,
            MATHOS_MAINTENANCE_ROLE_SECTION_BUFFER_SIZE);

    if (role_section_err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to build role-specific page section: %s",
            esp_err_to_name(role_section_err));

        free(role_section_html);

        return role_section_err;
    }
    char *page =
        malloc(
            MATHOS_MAINTENANCE_PAGE_BUFFER_SIZE);

    if (page == NULL)
    {
        ESP_LOGE(
            TAG,
            "failed to allocate maintenance page buffer");

        free(role_section_html);

        return ESP_ERR_NO_MEM;
    }

    int written = snprintf(
        page,
        MATHOS_MAINTENANCE_PAGE_BUFFER_SIZE,
        "<!DOCTYPE html>"
        "<html lang=\"en\">"
        "<head>"
        "<meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" "
        "content=\"width=device-width, initial-scale=1\">"
        "<title>MATHOS Maintenance</title>"
        "<style>"
        "body{"
        "margin:0;"
        "min-height:100vh;"
        "display:flex;"
        "align-items:center;"
        "justify-content:center;"
        "background:#101820;"
        "color:#ffffff;"
        "font-family:Arial,sans-serif;"
        "}"
        ".card{"
        "width:min(88%%,520px);"
        "padding:32px;"
        "border:1px solid #3a5268;"
        "border-radius:14px;"
        "background:#182632;"
        "box-shadow:0 14px 40px rgba(0,0,0,.35);"
        "}"
        "h1{margin-top:0;font-size:25px;}"
        ".label{color:#9db4c7;margin-top:18px;}"
        ".value{font-size:19px;margin-top:5px;}"
        ".safe{color:#68d391;}"
        ".ip{font-family:monospace;color:#63b3ed;}"
        ".editor{"
        "margin-top:28px;"
        "padding-top:20px;"
        "border-top:1px solid #3a5268;"
        "}"

        ".editor h2{"
        "margin:0 0 18px 0;"
        "font-size:21px;"
        "}"

        ".form-label{"
        "display:block;"
        "margin-top:16px;"
        "margin-bottom:6px;"
        "color:#9db4c7;"
        "}"

        ".form-input{"
        "box-sizing:border-box;"
        "width:100%%;"
        "padding:11px;"
        "border:1px solid #52697d;"
        "border-radius:7px;"
        "background:#101820;"
        "color:#ffffff;"
        "font-size:16px;"
        "}"

        ".toggle{"
        "display:flex;"
        "align-items:center;"
        "gap:10px;"
        "margin-bottom:16px;"
        "}"

        ".save-button{"
        "width:100%%;"
        "margin-top:22px;"
        "padding:12px;"
        "border:0;"
        "border-radius:7px;"
        "background:#3182ce;"
        "color:#ffffff;"
        "font-size:17px;"
        "font-weight:bold;"
        "cursor:pointer;"
        "}"

        ".warning{"
        "margin-top:12px;"
        "font-size:13px;"
        "color:#f6ad55;"
        "}"
        "</style>"
        "</head>"
        "<body>"
        "<main class=\"card\">"
        "<h1>MATHOS UAV MAINTENANCE</h1>"
        "<div class=\"label\">Device</div>"
        "<div class=\"value\">%s</div>"
        "<div class=\"label\">Status</div>"
        "<div class=\"value safe\">Maintenance mode active</div>"
        "<div class=\"label\">Local address</div>"
        "<div class=\"value ip\">%s</div>"

        "%s"

        "<div class=\"label\">Safety state</div>"
        "<div class=\"value safe\">Control tasks disabled</div>"
        "</main>"
        "</body>"
        "</html>",
        device_text,
        ip_text,
        role_section_html);

    if (written < 0 ||
        written >=
            MATHOS_MAINTENANCE_PAGE_BUFFER_SIZE)
    {
        ESP_LOGE(
            TAG,
            "maintenance page buffer too small");

        free(page);
        free(role_section_html);

        return ESP_FAIL;
    }

    esp_err_t err =
        httpd_resp_set_type(
            request,
            "text/html; charset=utf-8");

    if (err != ESP_OK)
    {
        free(page);
        free(role_section_html);

        return err;
    }

    /*
        Do not let the browser show an old maintenance
        page after the device has changed state.
    */
    err =
        httpd_resp_set_hdr(
            request,
            "Cache-Control",
            "no-store");

    if (err != ESP_OK)
    {
        free(page);
        free(role_section_html);

        return err;
    }

    esp_err_t send_err =
        httpd_resp_send(
            request,
            page,
            HTTPD_RESP_USE_STRLEN);

    free(page);
    free(role_section_html);

    return send_err;
}

static esp_err_t maintenance_http_server_start(
    mathos_maintenance_role_t role)
{
    if (maintenance_http_server != NULL)
    {
        ESP_LOGW(
            TAG,
            "HTTP server already started");

        return ESP_OK;
    }

    maintenance_active_role = role;

    httpd_config_t config =
        HTTPD_DEFAULT_CONFIG();

    config.server_port = 80;
    config.lru_purge_enable = true;

    esp_err_t err =
        httpd_start(
            &maintenance_http_server,
            &config);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "HTTP server start failed: %s",
            esp_err_to_name(err));

        maintenance_http_server = NULL;
        return err;
    }

    httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = maintenance_root_get_handler,
        .user_ctx = NULL,
    };

    err =
        httpd_register_uri_handler(
            maintenance_http_server,
            &root_uri);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "root URI registration failed: %s",
            esp_err_to_name(err));

        httpd_stop(
            maintenance_http_server);

        maintenance_http_server = NULL;
        return err;
    }
    if (role ==
        MATHOS_MAINTENANCE_ROLE_RC)
    {
        httpd_uri_t rc_config_uri = {
            .uri = "/config/rc",
            .method = HTTP_POST,
            .handler =
                maintenance_rc_config_post_handler,
            .user_ctx = NULL,
        };

        err =
            httpd_register_uri_handler(
                maintenance_http_server,
                &rc_config_uri);

        if (err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "RC configuration URI registration failed: %s",
                esp_err_to_name(err));

            httpd_stop(
                maintenance_http_server);

            maintenance_http_server = NULL;

            return err;
        }

        ESP_LOGI(
            TAG,
            "RC configuration endpoint registered");
        httpd_uri_t rc_pairing_uri = {
            .uri = "/pair/rc",
            .method = HTTP_POST,
            .handler =
                maintenance_rc_pairing_post_handler,
            .user_ctx = NULL,
        };

        err =
            httpd_register_uri_handler(
                maintenance_http_server,
                &rc_pairing_uri);

        if (err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "RC pairing URI registration failed: %s",
                esp_err_to_name(err));

            httpd_stop(
                maintenance_http_server);

            maintenance_http_server = NULL;

            return err;
        }

        ESP_LOGI(
            TAG,
            "RC pairing endpoint registered");
        /*
Read-only endpoint polled by the phone after
RC_PROOF transmission.
*/
        httpd_uri_t rc_pairing_status_uri = {
            .uri = "/pair/rc/status",
            .method = HTTP_GET,
            .handler =
                maintenance_rc_pairing_status_get_handler,
            .user_ctx = NULL,
        };

        err =
            httpd_register_uri_handler(
                maintenance_http_server,
                &rc_pairing_status_uri);

        if (err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "RC pairing status URI "
                "registration failed: %s",
                esp_err_to_name(err));

            httpd_stop(
                maintenance_http_server);

            maintenance_http_server = NULL;

            return err;
        }

        ESP_LOGI(
            TAG,
            "RC pairing status endpoint registered");
    }
    else if (role ==
             MATHOS_MAINTENANCE_ROLE_GATEWAY)
    {
        httpd_uri_t gateway_config_uri = {
            .uri = "/config/gateway",
            .method = HTTP_POST,
            .handler =
                maintenance_gateway_config_post_handler,
            .user_ctx = NULL,
        };

        err =
            httpd_register_uri_handler(
                maintenance_http_server,
                &gateway_config_uri);

        if (err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "Gateway configuration URI "
                "registration failed: %s",
                esp_err_to_name(err));

            httpd_stop(
                maintenance_http_server);

            maintenance_http_server = NULL;

            return err;
        }

        ESP_LOGI(
            TAG,
            "Gateway configuration endpoint registered");
    }
    else
    {
        ESP_LOGE(
            TAG,
            "configuration endpoint rejected: "
            "invalid maintenance role=%d",
            (int)role);

        httpd_stop(
            maintenance_http_server);

        maintenance_http_server = NULL;

        return ESP_ERR_INVALID_ARG;
    }

    char ip_text[16] =
        "Unavailable";

    esp_err_t ip_err =
        mathos_maintenance_get_ap_ip(
            ip_text,
            sizeof(ip_text));

    if (ip_err != ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "failed to read AP IP for HTTP log: %s",
            esp_err_to_name(ip_err));
    }

    ESP_LOGI(
        TAG,
        "HTTP maintenance page active at http://%s",
        ip_text);

    return ESP_OK;
}

static esp_err_t maintenance_parse_server_port(
    const char *text,
    uint16_t *port)
{
    if (text == NULL ||
        port == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        An empty form field means no server port
        has been configured yet.
    */
    if (text[0] == '\0')
    {
        *port = 0;
        return ESP_OK;
    }

    uint32_t value = 0;

    for (size_t i = 0;
         text[i] != '\0';
         i++)
    {
        if (text[i] < '0' ||
            text[i] > '9')
        {
            return ESP_ERR_INVALID_ARG;
        }

        value =
            (value * 10U) +
            (uint32_t)(text[i] - '0');

        if (value > 65535U)
        {
            return ESP_ERR_INVALID_ARG;
        }
    }

    /*
        Port zero is represented only by an empty field.
        A submitted literal "0" is invalid.
    */
    if (value == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    *port =
        (uint16_t)value;

    return ESP_OK;
}

static esp_err_t maintenance_parse_u32_range(
    const char *text,
    uint32_t minimum,
    uint32_t maximum,
    uint32_t *value)
{
    if (text == NULL ||
        value == NULL ||
        minimum > maximum)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Gateway numeric fields are mandatory.

        Reject empty values, spaces, signs, decimal
        points and every other non-digit character.
    */
    if (text[0] == '\0')
    {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t parsed = 0;

    for (size_t i = 0;
         text[i] != '\0';
         i++)
    {
        if (text[i] < '0' ||
            text[i] > '9')
        {
            return ESP_ERR_INVALID_ARG;
        }

        uint32_t digit =
            (uint32_t)(text[i] - '0');

        /*
            Detect overflow and values above the allowed
            maximum before multiplying.
        */
        if (parsed > (maximum / 10U) ||
            (parsed == (maximum / 10U) &&
             digit > (maximum % 10U)))
        {
            return ESP_ERR_INVALID_ARG;
        }

        parsed =
            (parsed * 10U) +
            digit;
    }

    if (parsed < minimum ||
        parsed > maximum)
    {
        return ESP_ERR_INVALID_ARG;
    }

    *value = parsed;

    return ESP_OK;
}

static esp_err_t maintenance_parse_u16_range(
    const char *text,
    uint16_t minimum,
    uint16_t maximum,
    uint16_t *value)
{
    if (value == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t parsed = 0;

    esp_err_t err =
        maintenance_parse_u32_range(
            text,
            minimum,
            maximum,
            &parsed);

    if (err != ESP_OK)
    {
        return err;
    }

    *value =
        (uint16_t)parsed;

    return ESP_OK;
}

static void maintenance_clear_sensitive_memory(
    void *buffer,
    size_t buffer_size)
{
    if (buffer == NULL)
    {
        return;
    }

    /*
        Volatile prevents the compiler from removing this
        clear operation as an unnecessary write.
    */
    volatile uint8_t *bytes =
        (volatile uint8_t *)buffer;

    while (buffer_size > 0)
    {
        *bytes = 0;

        bytes++;
        buffer_size--;
    }
}

esp_err_t mathos_rc_pairing_config_save(
    const mathos_rc_pairing_config_t *config)
{
    if (config == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Work on a local copy because the save operation
        refreshes metadata, counter and CRC.
    */
    mathos_rc_pairing_config_t record =
        *config;

    mathos_rc_pairing_config_t verified = {0};

    esp_err_t result = ESP_OK;

    /*
        Restore the fixed record metadata.
    */
    record.magic =
        MATHOS_RC_PAIRING_CONFIG_MAGIC;

    record.version =
        MATHOS_RC_PAIRING_CONFIG_VERSION;

    record.record_size =
        sizeof(mathos_rc_pairing_config_t);

    /*
        Reserved version-1 fields must always remain zero.
    */
    record.reserved0 = 0;

    memset(
        record.reserved1,
        0,
        sizeof(record.reserved1));

    /*
        Increment the persistent configuration counter.

        Counter zero is reserved for the initial
        unsaved default record.
    */
    record.configuration_counter =
        config->configuration_counter + 1U;

    if (record.configuration_counter == 0)
    {
        record.configuration_counter = 1U;
    }

    /*
        Calculate the CRC only after every stored field
        has reached its final value.
    */
    record.crc32 = 0;

    record.crc32 =
        mathos_rc_pairing_config_calculate_crc32(
            &record);

    if (!mathos_rc_pairing_config_is_valid(
            &record))
    {
        ESP_LOGE(
            TAG,
            "RC pairing configuration save rejected: "
            "invalid fields");

        result = ESP_ERR_INVALID_ARG;
        goto cleanup;
    }

    nvs_handle_t handle;

    esp_err_t err =
        nvs_open(
            MATHOS_MAINTENANCE_NVS_NAMESPACE,
            NVS_READWRITE,
            &handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to open RC pairing NVS: %s",
            esp_err_to_name(err));

        result = err;
        goto cleanup;
    }

    err =
        nvs_set_blob(
            handle,
            MATHOS_RC_PAIRING_NVS_KEY,
            &record,
            sizeof(record));

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to write RC pairing configuration: %s",
            esp_err_to_name(err));

        nvs_close(handle);

        result = err;
        goto cleanup;
    }

    err =
        nvs_commit(
            handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to commit RC pairing configuration: %s",
            esp_err_to_name(err));

        nvs_close(handle);

        result = err;
        goto cleanup;
    }

    /*
        Read the committed record back from NVS before
        reporting success.
    */
    size_t verified_size =
        sizeof(verified);

    err =
        nvs_get_blob(
            handle,
            MATHOS_RC_PAIRING_NVS_KEY,
            &verified,
            &verified_size);

    nvs_close(handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "RC pairing configuration read-back failed: %s",
            esp_err_to_name(err));

        result = err;
        goto cleanup;
    }

    if (verified_size !=
        sizeof(verified))
    {
        ESP_LOGE(
            TAG,
            "RC pairing read-back size mismatch "
            "stored=%u expected=%u",
            (unsigned int)verified_size,
            (unsigned int)sizeof(verified));

        result = ESP_FAIL;
        goto cleanup;
    }

    if (!mathos_rc_pairing_config_is_valid(
            &verified))
    {
        ESP_LOGE(
            TAG,
            "RC pairing read-back validation failed");

        result = ESP_FAIL;
        goto cleanup;
    }

    if (memcmp(
            &record,
            &verified,
            sizeof(record)) != 0)
    {
        ESP_LOGE(
            TAG,
            "RC pairing read-back differs from "
            "written record");

        result = ESP_FAIL;
        goto cleanup;
    }

    /*
        Never log the root key or pairing salt.
    */
    ESP_LOGI(
        TAG,
        "RC pairing configuration saved and verified "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu counter=%lu "
        "key_provisioned=%u crc=0x%08lx",
        verified.rc_id,
        verified.authorised_gateway_id,
        (unsigned long)
            verified.key_generation,
        (unsigned long)
            verified.configuration_counter,
        verified.key_generation != 0
            ? 1U
            : 0U,
        (unsigned long)
            verified.crc32);

cleanup:

    /*
        Both local structures may contain the root key,
        so erase them before returning.
    */
    maintenance_clear_sensitive_memory(
        &record,
        sizeof(record));

    maintenance_clear_sensitive_memory(
        &verified,
        sizeof(verified));

    return result;
}

esp_err_t mathos_rc_pairing_config_load(
    mathos_rc_pairing_config_t *config,
    int *loaded_from_nvs)
{
    if (config == NULL ||
        loaded_from_nvs == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Always begin with a complete and valid unpaired
        RC record.

        If NVS is empty, corrupted or incompatible,
        these safe defaults remain active.
    */
    mathos_rc_pairing_config_set_defaults(
        config);

    *loaded_from_nvs = 0;

    nvs_handle_t handle;

    esp_err_t err =
        nvs_open(
            MATHOS_MAINTENANCE_NVS_NAMESPACE,
            NVS_READONLY,
            &handle);

    /*
        A new RC may not have created the shared
        maintenance namespace yet.
    */
    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGI(
            TAG,
            "no saved RC pairing configuration; "
            "using unpaired defaults");

        return ESP_OK;
    }

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to open RC pairing NVS: %s",
            esp_err_to_name(err));

        return err;
    }

    /*
        Query the stored blob size before reading it.

        This prevents an old or incompatible record from
        being copied into the current structure.
    */
    size_t stored_size = 0;

    err =
        nvs_get_blob(
            handle,
            MATHOS_RC_PAIRING_NVS_KEY,
            NULL,
            &stored_size);

    if (err == ESP_ERR_NVS_NOT_FOUND)
    {
        ESP_LOGI(
            TAG,
            "no saved RC pairing configuration; "
            "using unpaired defaults");

        nvs_close(handle);

        return ESP_OK;
    }

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to read RC pairing record size: %s",
            esp_err_to_name(err));

        nvs_close(handle);

        return err;
    }

    if (stored_size !=
        sizeof(mathos_rc_pairing_config_t))
    {
        ESP_LOGE(
            TAG,
            "RC pairing record size mismatch "
            "stored=%u expected=%u; "
            "using unpaired defaults",
            (unsigned int)stored_size,
            (unsigned int)sizeof(mathos_rc_pairing_config_t));

        nvs_close(handle);

        return ESP_ERR_INVALID_SIZE;
    }

    mathos_rc_pairing_config_t stored = {0};

    size_t read_size =
        sizeof(stored);

    err =
        nvs_get_blob(
            handle,
            MATHOS_RC_PAIRING_NVS_KEY,
            &stored,
            &read_size);

    nvs_close(handle);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "failed to read RC pairing configuration: %s",
            esp_err_to_name(err));

        maintenance_clear_sensitive_memory(
            &stored,
            sizeof(stored));

        return err;
    }

    if (read_size != sizeof(stored))
    {
        ESP_LOGE(
            TAG,
            "RC pairing read size mismatch "
            "read=%u expected=%u; "
            "using unpaired defaults",
            (unsigned int)read_size,
            (unsigned int)sizeof(stored));

        maintenance_clear_sensitive_memory(
            &stored,
            sizeof(stored));

        return ESP_ERR_INVALID_SIZE;
    }

    /*
        Validate the complete record before allowing its
        key material to become active.
    */
    if (!mathos_rc_pairing_config_is_valid(
            &stored))
    {
        ESP_LOGE(
            TAG,
            "saved RC pairing configuration is invalid; "
            "using unpaired defaults");

        maintenance_clear_sensitive_memory(
            &stored,
            sizeof(stored));

        return ESP_FAIL;
    }

    /*
        Activate the saved pairing record only after
        every validation check succeeds.
    */
    *config = stored;

    *loaded_from_nvs = 1;

    /*
        Never print the root key, salt or passphrase.
    */
    ESP_LOGI(
        TAG,
        "RC pairing configuration loaded "
        "rc_id=%u gateway_id=%u "
        "key_generation=%lu "
        "key_provisioned=%u "
        "counter=%lu crc=0x%08lx",
        config->rc_id,
        config->authorised_gateway_id,
        (unsigned long)
            config->key_generation,
        config->key_generation != 0
            ? 1U
            : 0U,
        (unsigned long)
            config->configuration_counter,
        (unsigned long)
            config->crc32);

    /*
        The active configuration now contains the needed
        copy. Erase the temporary stack copy.
    */
    maintenance_clear_sensitive_memory(
        &stored,
        sizeof(stored));

    return ESP_OK;
}

esp_err_t mathos_maintenance_generate_pairing_salt(
    uint8_t salt[MATHOS_PAIRING_SALT_LEN])
{
    if (salt == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Begin with a cleared output buffer.

        A failed generation must not leave previous
        salt material in the caller's buffer.
    */
    maintenance_clear_sensitive_memory(
        salt,
        MATHOS_PAIRING_SALT_LEN);

    /*
        An all-zero salt is reserved as the
        unprovisioned configuration state.

        It is astronomically unlikely for a secure random
        generator to produce sixteen zero bytes, but retry
        explicitly so the configuration rules remain exact.
    */
    for (uint32_t attempt = 0;
         attempt < 4U;
         attempt++)
    {
        esp_fill_random(
            salt,
            MATHOS_PAIRING_SALT_LEN);

        int contains_nonzero_byte = 0;

        for (size_t i = 0;
             i < MATHOS_PAIRING_SALT_LEN;
             i++)
        {
            if (salt[i] != 0)
            {
                contains_nonzero_byte = 1;
                break;
            }
        }

        if (contains_nonzero_byte)
        {
            return ESP_OK;
        }
    }

    maintenance_clear_sensitive_memory(
        salt,
        MATHOS_PAIRING_SALT_LEN);

    ESP_LOGE(
        TAG,
        "failed to generate a valid pairing salt");

    return ESP_FAIL;
}

esp_err_t mathos_maintenance_derive_root_key_from_passphrase(
    const char *passphrase,
    const uint8_t salt[MATHOS_PAIRING_SALT_LEN],
    uint32_t iteration_count,
    uint8_t root_key[MATHOS_GATEWAY_ROOT_KEY_LEN])
{
    if (passphrase == NULL ||
        salt == NULL ||
        root_key == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (iteration_count <
            MATHOS_PAIRING_KDF_MIN_ITERATIONS ||
        iteration_count >
            MATHOS_PAIRING_KDF_MAX_ITERATIONS)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Begin with a cleared output buffer.

        A failed derivation must never leave a partial or
        previously generated key in the caller's buffer.
    */
    maintenance_clear_sensitive_memory(
        root_key,
        MATHOS_GATEWAY_ROOT_KEY_LEN);

    /*
        strnlen prevents an unterminated or excessively long
        passphrase from causing an unbounded memory scan.
    */
    size_t passphrase_length =
        strnlen(
            passphrase,
            MATHOS_PAIRING_PASSPHRASE_MAX_LEN + 1U);

    if (passphrase_length <
            MATHOS_PAIRING_PASSPHRASE_MIN_LEN ||
        passphrase_length >
            MATHOS_PAIRING_PASSPHRASE_MAX_LEN)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Version 1 of the pairing interface accepts printable
        ASCII only.

        This avoids different Unicode encodings or
        normalization rules producing different keys on the
        RC and Gateway.
    */
    for (size_t i = 0;
         i < passphrase_length;
         i++)
    {
        unsigned char character =
            (unsigned char)passphrase[i];

        if (character < 0x20U ||
            character > 0x7EU)
        {
            return ESP_ERR_INVALID_ARG;
        }
    }

    /*
        Reject accidental leading or trailing spaces.

        Spaces inside the passphrase remain allowed.
    */
    if (passphrase[0] == ' ' ||
        passphrase[passphrase_length - 1U] == ' ')
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        A production pairing salt must not be the all-zero
        value.
    */
    int salt_contains_nonzero_byte = 0;

    for (size_t i = 0;
         i < MATHOS_PAIRING_SALT_LEN;
         i++)
    {
        if (salt[i] != 0)
        {
            salt_contains_nonzero_byte = 1;
            break;
        }
    }

    if (!salt_contains_nonzero_byte)
    {
        return ESP_ERR_INVALID_ARG;
    }
    int64_t derivation_start_us =
        esp_timer_get_time();
    int result =
        mbedtls_pkcs5_pbkdf2_hmac_ext(
            MBEDTLS_MD_SHA256,

            (const unsigned char *)passphrase,
            passphrase_length,

            salt,
            MATHOS_PAIRING_SALT_LEN,

            (unsigned int)iteration_count,

            MATHOS_GATEWAY_ROOT_KEY_LEN,
            root_key);
    int64_t derivation_duration_us =
        esp_timer_get_time() -
        derivation_start_us;
    if (result != 0)
    {
        maintenance_clear_sensitive_memory(
            root_key,
            MATHOS_GATEWAY_ROOT_KEY_LEN);

        /*
            Log only the Mbed TLS error code.

            Never log the passphrase, salt-derived key,
            or generated root key.
        */
        ESP_LOGE(
            TAG,
            "PBKDF2 root-key derivation failed: "
            "-0x%04X",
            (unsigned int)(-result));

        return ESP_FAIL;
    }

    /*
        PBKDF2 should not produce an all-zero result, but
        explicitly reject it because MATHOS reserves an
        all-zero root key for the unprovisioned state.
    */
    int key_contains_nonzero_byte = 0;

    for (size_t i = 0;
         i < MATHOS_GATEWAY_ROOT_KEY_LEN;
         i++)
    {
        if (root_key[i] != 0)
        {
            key_contains_nonzero_byte = 1;
            break;
        }
    }

    if (!key_contains_nonzero_byte)
    {
        maintenance_clear_sensitive_memory(
            root_key,
            MATHOS_GATEWAY_ROOT_KEY_LEN);

        ESP_LOGE(
            TAG,
            "PBKDF2 produced an invalid zero root key");

        return ESP_FAIL;
    }
    ESP_LOGI(
        TAG,
        "PBKDF2 root-key derivation completed "
        "iterations=%lu duration_ms=%lld",
        (unsigned long)iteration_count,
        (long long)(derivation_duration_us / 1000LL));
    return ESP_OK;
}

static esp_err_t maintenance_parse_u8_range(
    const char *text,
    uint8_t minimum,
    uint8_t maximum,
    uint8_t *value)
{
    if (value == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t parsed = 0;

    esp_err_t err =
        maintenance_parse_u32_range(
            text,
            minimum,
            maximum,
            &parsed);

    if (err != ESP_OK)
    {
        return err;
    }

    *value =
        (uint8_t)parsed;

    return ESP_OK;
}

static esp_err_t maintenance_prepare_gateway_passphrase_key(
    const char *passphrase,
    const char *passphrase_confirmation,
    uint8_t root_key[MATHOS_GATEWAY_ROOT_KEY_LEN],
    uint8_t pairing_salt[MATHOS_PAIRING_SALT_LEN],
    int *key_was_provided)
{
    if (passphrase == NULL ||
        passphrase_confirmation == NULL ||
        root_key == NULL ||
        pairing_salt == NULL ||
        key_was_provided == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    *key_was_provided = 0;

    /*
        Always clear the outputs first.

        A failed operation must never leave old key or
        salt material in the caller's buffers.
    */
    maintenance_clear_sensitive_memory(
        root_key,
        MATHOS_GATEWAY_ROOT_KEY_LEN);

    maintenance_clear_sensitive_memory(
        pairing_salt,
        MATHOS_PAIRING_SALT_LEN);

    /*
        Both empty fields mean:

        Preserve the currently provisioned key.
    */
    if (passphrase[0] == '\0' &&
        passphrase_confirmation[0] == '\0')
    {
        return ESP_OK;
    }

    /*
        Reject a submission where only one field
        contains a value.
    */
    if (passphrase[0] == '\0' ||
        passphrase_confirmation[0] == '\0')
    {
        return ESP_ERR_INVALID_ARG;
    }

    size_t passphrase_length =
        strnlen(
            passphrase,
            MATHOS_PAIRING_PASSPHRASE_MAX_LEN + 1U);

    size_t confirmation_length =
        strnlen(
            passphrase_confirmation,
            MATHOS_PAIRING_PASSPHRASE_MAX_LEN + 1U);

    if (passphrase_length <
            MATHOS_PAIRING_PASSPHRASE_MIN_LEN ||
        passphrase_length >
            MATHOS_PAIRING_PASSPHRASE_MAX_LEN ||
        confirmation_length !=
            passphrase_length)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Compare the complete passphrases without returning
        immediately at the first different character.
    */
    uint8_t mismatch = 0;

    for (size_t i = 0;
         i < passphrase_length;
         i++)
    {
        mismatch |=
            (uint8_t)((uint8_t)passphrase[i] ^
                      (uint8_t)passphrase_confirmation[i]);
    }

    if (mismatch != 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Create a fresh random salt whenever a new
        passphrase is provisioned.
    */
    esp_err_t salt_err =
        mathos_maintenance_generate_pairing_salt(
            pairing_salt);

    if (salt_err != ESP_OK)
    {
        maintenance_clear_sensitive_memory(
            pairing_salt,
            MATHOS_PAIRING_SALT_LEN);

        return salt_err;
    }

    /*
        Derive the existing 256-bit MATHOS root key using
        PBKDF2-HMAC-SHA256.
    */
    esp_err_t derive_err =
        mathos_maintenance_derive_root_key_from_passphrase(
            passphrase,
            pairing_salt,
            MATHOS_PAIRING_KDF_DEFAULT_ITERATIONS,
            root_key);

    if (derive_err != ESP_OK)
    {
        maintenance_clear_sensitive_memory(
            root_key,
            MATHOS_GATEWAY_ROOT_KEY_LEN);

        maintenance_clear_sensitive_memory(
            pairing_salt,
            MATHOS_PAIRING_SALT_LEN);

        return derive_err;
    }

    *key_was_provided = 1;

    return ESP_OK;
}

static esp_err_t maintenance_rc_config_post_handler(
    httpd_req_t *request)
{
    if (request == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (maintenance_active_role !=
        MATHOS_MAINTENANCE_ROLE_RC)
    {
        ESP_LOGW(
            TAG,
            "RC configuration POST rejected for role=%d",
            (int)maintenance_active_role);

        return maintenance_send_text_response(
            request,
            "403 Forbidden",
            "RC configuration is unavailable on this device.\n");
    }

    size_t content_length =
        request->content_len;

    if (content_length == 0 ||
        content_length >
            MATHOS_MAINTENANCE_FORM_BODY_MAX)
    {
        ESP_LOGW(
            TAG,
            "configuration POST rejected: body size=%u",
            (unsigned int)content_length);

        return maintenance_send_text_response(
            request,
            "413 Payload Too Large",
            "Invalid configuration form size.\n");
    }

    char *body =
        malloc(
            content_length + 1U);

    if (body == NULL)
    {
        ESP_LOGE(
            TAG,
            "failed to allocate configuration POST buffer");

        return maintenance_send_text_response(
            request,
            "500 Internal Server Error",
            "Insufficient memory.\n");
    }

    size_t total_received = 0;
    int timeout_count = 0;

    while (total_received <
           content_length)
    {
        int received =
            httpd_req_recv(
                request,
                body + total_received,
                content_length -
                    total_received);

        if (received ==
            HTTPD_SOCK_ERR_TIMEOUT)
        {
            timeout_count++;

            if (timeout_count > 2)
            {
                free(body);

                ESP_LOGW(
                    TAG,
                    "configuration POST receive timeout");

                return maintenance_send_text_response(
                    request,
                    "408 Request Timeout",
                    "Request timed out.\n");
            }

            continue;
        }

        if (received <= 0)
        {
            free(body);

            ESP_LOGW(
                TAG,
                "configuration POST receive failed");

            return maintenance_send_text_response(
                request,
                "400 Bad Request",
                "Could not read configuration form.\n");
        }

        total_received +=
            (size_t)received;
    }

    body[total_received] = '\0';

    char telemetry_value[8] = "";
    char wifi_ssid[MATHOS_MAINTENANCE_WIFI_SSID_MAX_LEN] = "";

    char server_host[MATHOS_MAINTENANCE_SERVER_HOST_MAX_LEN] = "";

    char server_port_text[6] = "";

    uint8_t telemetry_enabled = 0;
    uint16_t server_port = 0;

    /*
        An unchecked checkbox is omitted by the browser.
        That means telemetry remains disabled.
    */
    esp_err_t field_err =
        maintenance_form_get_value(
            body,
            "telemetry_enabled",
            telemetry_value,
            sizeof(telemetry_value));

    if (field_err == ESP_OK)
    {
        if (strcmp(
                telemetry_value,
                "1") != 0)
        {
            free(body);

            return maintenance_send_text_response(
                request,
                "400 Bad Request",
                "Invalid telemetry setting.\n");
        }

        telemetry_enabled = 1;
    }
    else if (field_err !=
             ESP_ERR_NOT_FOUND)
    {
        free(body);

        return maintenance_send_text_response(
            request,
            "400 Bad Request",
            "Invalid telemetry setting.\n");
    }

    field_err =
        maintenance_form_get_value(
            body,
            "wifi_ssid",
            wifi_ssid,
            sizeof(wifi_ssid));

    if (field_err != ESP_OK)
    {
        free(body);

        return maintenance_send_text_response(
            request,
            "400 Bad Request",
            "Invalid Wi-Fi SSID.\n");
    }

    field_err =
        maintenance_form_get_value(
            body,
            "server_host",
            server_host,
            sizeof(server_host));

    if (field_err != ESP_OK)
    {
        free(body);

        return maintenance_send_text_response(
            request,
            "400 Bad Request",
            "Invalid telemetry server.\n");
    }

    field_err =
        maintenance_form_get_value(
            body,
            "server_port",
            server_port_text,
            sizeof(server_port_text));

    if (field_err != ESP_OK)
    {
        free(body);

        return maintenance_send_text_response(
            request,
            "400 Bad Request",
            "Invalid server port.\n");
    }

    free(body);

    field_err =
        maintenance_parse_server_port(
            server_port_text,
            &server_port);

    if (field_err != ESP_OK)
    {
        return maintenance_send_text_response(
            request,
            "400 Bad Request",
            "Server port must be between 1 and 65535.\n");
    }

    /*
        Begin with the active configuration, then replace
        only fields controlled by this form.
    */
    mathos_maintenance_config_t candidate =
        maintenance_active_config;

    candidate.telemetry_enabled =
        telemetry_enabled;

    snprintf(
        candidate.wifi_ssid,
        sizeof(candidate.wifi_ssid),
        "%s",
        wifi_ssid);

    snprintf(
        candidate.server_host,
        sizeof(candidate.server_host),
        "%s",
        server_host);

    candidate.server_port =
        server_port;

    esp_err_t save_err =
        mathos_maintenance_config_save(
            &candidate);

    if (save_err != ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "configuration POST rejected during save: %s",
            esp_err_to_name(save_err));

        return maintenance_send_text_response(
            request,
            "400 Bad Request",
            "Configuration is incomplete or invalid.\n");
    }

    /*
        Reload the verified NVS record rather than trusting
        the submitted RAM copy.
    */
    int loaded_from_nvs = 0;

    esp_err_t load_err =
        mathos_maintenance_config_load(
            &maintenance_active_config,
            &loaded_from_nvs);

    if (load_err != ESP_OK ||
        !loaded_from_nvs)
    {
        ESP_LOGE(
            TAG,
            "saved configuration could not be reloaded: %s",
            esp_err_to_name(load_err));

        return maintenance_send_text_response(
            request,
            "500 Internal Server Error",
            "Configuration was written but verification failed.\n");
    }

    maintenance_config_loaded_from_nvs = 1;

    ESP_LOGI(
        TAG,
        "configuration updated from maintenance form "
        "telemetry=%u ssid_set=%u host_set=%u port=%u",
        maintenance_active_config.telemetry_enabled,
        maintenance_active_config.wifi_ssid[0] != '\0'
            ? 1U
            : 0U,
        maintenance_active_config.server_host[0] != '\0'
            ? 1U
            : 0U,
        maintenance_active_config.server_port);

    /*
        Redirect back to the main page using POST/Redirect/GET.
        Refreshing the page will not submit the form again.
    */
    esp_err_t err =
        httpd_resp_set_status(
            request,
            "303 See Other");

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        httpd_resp_set_hdr(
            request,
            "Location",
            "/");

    if (err != ESP_OK)
    {
        return err;
    }

    err =
        httpd_resp_set_hdr(
            request,
            "Cache-Control",
            "no-store");

    if (err != ESP_OK)
    {
        return err;
    }

    return httpd_resp_send(
        request,
        NULL,
        0);
}

static esp_err_t maintenance_gateway_config_post_handler(
    httpd_req_t *request)
{
    if (request == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    /*
        Never permit Gateway configuration through the
        RC maintenance role.
    */
    if (maintenance_active_role !=
        MATHOS_MAINTENANCE_ROLE_GATEWAY)
    {
        ESP_LOGW(
            TAG,
            "Gateway configuration POST rejected for role=%d",
            (int)maintenance_active_role);

        return maintenance_send_text_response(
            request,
            "403 Forbidden",
            "Gateway configuration is unavailable "
            "on this device.\n");
    }

    size_t content_length =
        request->content_len;

    if (content_length == 0 ||
        content_length >
            MATHOS_MAINTENANCE_FORM_BODY_MAX)
    {
        ESP_LOGW(
            TAG,
            "Gateway configuration POST rejected: "
            "body size=%u",
            (unsigned int)content_length);

        return maintenance_send_text_response(
            request,
            "413 Payload Too Large",
            "Invalid Gateway configuration form size.\n");
    }

    char *body =
        malloc(
            content_length + 1U);

    if (body == NULL)
    {
        ESP_LOGE(
            TAG,
            "failed to allocate Gateway POST buffer");

        return maintenance_send_text_response(
            request,
            "500 Internal Server Error",
            "Insufficient memory.\n");
    }

    char gateway_id_text[4] = "";
    char authorised_rc_id_text[4] = "";

    char pairing_passphrase[MATHOS_PAIRING_PASSPHRASE_MAX_LEN + 1U] = "";

    char pairing_passphrase_confirm[MATHOS_PAIRING_PASSPHRASE_MAX_LEN + 1U] = "";

    char link_uart_baud_text[11] = "";
    char fc_uart_baud_text[11] = "";

    char rc_packet_timeout_text[11] = "";
    char fc_heartbeat_timeout_text[11] = "";
    char status_tx_period_text[11] = "";
    char telemetry_tx_period_text[11] = "";

    char failsafe_policy_text[4] = "";

    uint8_t derived_root_key[MATHOS_GATEWAY_ROOT_KEY_LEN] = {0};

    uint8_t generated_pairing_salt[MATHOS_PAIRING_SALT_LEN] = {0};

    int key_was_provided = 0;

    mathos_gateway_config_t candidate = {0};

    size_t total_received = 0;
    int timeout_count = 0;

    while (total_received <
           content_length)
    {
        int received =
            httpd_req_recv(
                request,
                body + total_received,
                content_length -
                    total_received);

        if (received ==
            HTTPD_SOCK_ERR_TIMEOUT)
        {
            timeout_count++;

            if (timeout_count > 2)
            {
                ESP_LOGW(
                    TAG,
                    "Gateway configuration POST "
                    "receive timeout");

                goto request_timeout;
            }

            continue;
        }

        if (received <= 0)
        {
            ESP_LOGW(
                TAG,
                "Gateway configuration POST "
                "receive failed");

            goto invalid_request;
        }

        total_received +=
            (size_t)received;
    }

    body[total_received] = '\0';

    esp_err_t field_err =
        maintenance_form_get_value(
            body,
            "gateway_id",
            gateway_id_text,
            sizeof(gateway_id_text));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_form_get_value(
            body,
            "authorised_rc_id",
            authorised_rc_id_text,
            sizeof(authorised_rc_id_text));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_form_get_value(
            body,
            "pairing_passphrase",
            pairing_passphrase,
            sizeof(pairing_passphrase));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_form_get_value(
            body,
            "pairing_passphrase_confirm",
            pairing_passphrase_confirm,
            sizeof(pairing_passphrase_confirm));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_form_get_value(
            body,
            "link_uart_baud",
            link_uart_baud_text,
            sizeof(link_uart_baud_text));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_form_get_value(
            body,
            "fc_uart_baud",
            fc_uart_baud_text,
            sizeof(fc_uart_baud_text));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_form_get_value(
            body,
            "rc_packet_timeout_ms",
            rc_packet_timeout_text,
            sizeof(rc_packet_timeout_text));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_form_get_value(
            body,
            "fc_heartbeat_timeout_ms",
            fc_heartbeat_timeout_text,
            sizeof(fc_heartbeat_timeout_text));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_form_get_value(
            body,
            "status_tx_period_ms",
            status_tx_period_text,
            sizeof(status_tx_period_text));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_form_get_value(
            body,
            "telemetry_tx_period_ms",
            telemetry_tx_period_text,
            sizeof(telemetry_tx_period_text));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_form_get_value(
            body,
            "failsafe_policy",
            failsafe_policy_text,
            sizeof(failsafe_policy_text));

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    maintenance_clear_sensitive_memory(
        body,
        content_length + 1U);

    free(body);
    body = NULL;

    uint8_t gateway_id = 0;
    uint8_t authorised_rc_id = 0;
    uint8_t failsafe_policy = 0;

    uint32_t link_uart_baud = 0;
    uint32_t fc_uart_baud = 0;

    uint16_t rc_packet_timeout_ms = 0;
    uint16_t fc_heartbeat_timeout_ms = 0;
    uint16_t status_tx_period_ms = 0;
    uint16_t telemetry_tx_period_ms = 0;

    field_err =
        maintenance_parse_u8_range(
            gateway_id_text,
            1,
            254,
            &gateway_id);

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_parse_u8_range(
            authorised_rc_id_text,
            1,
            254,
            &authorised_rc_id);

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    if (gateway_id ==
        authorised_rc_id)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_parse_u32_range(
            link_uart_baud_text,
            9600,
            921600,
            &link_uart_baud);

    if (field_err != ESP_OK ||
        !mathos_gateway_uart_baud_is_valid(
            link_uart_baud))
    {
        goto invalid_form;
    }

    field_err =
        maintenance_parse_u32_range(
            fc_uart_baud_text,
            9600,
            921600,
            &fc_uart_baud);

    if (field_err != ESP_OK ||
        !mathos_gateway_uart_baud_is_valid(
            fc_uart_baud))
    {
        goto invalid_form;
    }

    field_err =
        maintenance_parse_u16_range(
            rc_packet_timeout_text,
            100,
            5000,
            &rc_packet_timeout_ms);

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_parse_u16_range(
            fc_heartbeat_timeout_text,
            1000,
            10000,
            &fc_heartbeat_timeout_ms);

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_parse_u16_range(
            status_tx_period_text,
            50,
            5000,
            &status_tx_period_ms);

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_parse_u16_range(
            telemetry_tx_period_text,
            50,
            5000,
            &telemetry_tx_period_ms);

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_parse_u8_range(
            failsafe_policy_text,
            MATHOS_GATEWAY_FAILSAFE_FC_NATIVE,
            MATHOS_GATEWAY_FAILSAFE_RTL,
            &failsafe_policy);

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    field_err =
        maintenance_prepare_gateway_passphrase_key(
            pairing_passphrase,
            pairing_passphrase_confirm,
            derived_root_key,
            generated_pairing_salt,
            &key_was_provided);

    if (field_err != ESP_OK)
    {
        goto invalid_form;
    }

    /*
        Start from the active verified configuration.

        Empty passphrase fields preserve the currently
        provisioned key, salt, derivation settings and
        key generation.
    */
    candidate =
        maintenance_active_gateway_config;

    candidate.gateway_id =
        gateway_id;

    candidate.authorised_rc_id =
        authorised_rc_id;

    candidate.link_uart_baud =
        link_uart_baud;

    candidate.fc_uart_baud =
        fc_uart_baud;

    candidate.rc_packet_timeout_ms =
        rc_packet_timeout_ms;

    candidate.fc_heartbeat_timeout_ms =
        fc_heartbeat_timeout_ms;

    candidate.status_tx_period_ms =
        status_tx_period_ms;

    candidate.telemetry_tx_period_ms =
        telemetry_tx_period_ms;

    candidate.failsafe_policy =
        failsafe_policy;

    if (key_was_provided)
    {
        memcpy(
            candidate.root_key,
            derived_root_key,
            sizeof(candidate.root_key));

        memcpy(
            candidate.pairing_salt,
            generated_pairing_salt,
            sizeof(candidate.pairing_salt));

        candidate.key_derivation_method =
            MATHOS_GATEWAY_KEY_DERIVATION_PBKDF2_SHA256;

        candidate.kdf_iteration_count =
            MATHOS_PAIRING_KDF_DEFAULT_ITERATIONS;

        candidate.key_generation =
            maintenance_active_gateway_config
                .key_generation +
            1U;

        /*
            Prevent wrap-around from creating generation
            zero, which represents an unprovisioned key.
        */
        if (candidate.key_generation == 0)
        {
            candidate.key_generation = 1U;
        }
    }

    esp_err_t save_err =
        mathos_gateway_config_save(
            &candidate);

    maintenance_clear_sensitive_memory(
        pairing_passphrase,
        sizeof(pairing_passphrase));

    maintenance_clear_sensitive_memory(
        pairing_passphrase_confirm,
        sizeof(pairing_passphrase_confirm));

    maintenance_clear_sensitive_memory(
        derived_root_key,
        sizeof(derived_root_key));

    maintenance_clear_sensitive_memory(
        generated_pairing_salt,
        sizeof(generated_pairing_salt));

    maintenance_clear_sensitive_memory(
        &candidate,
        sizeof(candidate));

    if (save_err != ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "Gateway configuration save rejected: %s",
            esp_err_to_name(save_err));

        return maintenance_send_text_response(
            request,
            "400 Bad Request",
            "Gateway configuration is incomplete "
            "or invalid.\n");
    }

    /*
        Reload the verified record instead of trusting
        the submitted RAM candidate.
    */
    int loaded_from_nvs = 0;

    esp_err_t load_err =
        mathos_gateway_config_load(
            &maintenance_active_gateway_config,
            &loaded_from_nvs);

    if (load_err != ESP_OK ||
        !loaded_from_nvs)
    {
        ESP_LOGE(
            TAG,
            "saved Gateway configuration could not "
            "be reloaded: %s",
            esp_err_to_name(load_err));

        return maintenance_send_text_response(
            request,
            "500 Internal Server Error",
            "Gateway configuration was written but "
            "verification failed.\n");
    }

    maintenance_gateway_config_loaded_from_nvs = 1;

    ESP_LOGI(
        TAG,
        "Gateway configuration updated "
        "gateway_id=%u rc_id=%u "
        "key_generation=%lu "
        "link_baud=%lu fc_baud=%lu "
        "failsafe_policy=%u counter=%lu",
        maintenance_active_gateway_config.gateway_id,
        maintenance_active_gateway_config.authorised_rc_id,
        (unsigned long)
            maintenance_active_gateway_config.key_generation,
        (unsigned long)
            maintenance_active_gateway_config.link_uart_baud,
        (unsigned long)
            maintenance_active_gateway_config.fc_uart_baud,
        maintenance_active_gateway_config.failsafe_policy,
        (unsigned long)
            maintenance_active_gateway_config
                .configuration_counter);

    /*
        POST/Redirect/GET prevents accidental resubmission
        when the browser refreshes the page.
    */
    esp_err_t response_err =
        httpd_resp_set_status(
            request,
            "303 See Other");

    if (response_err != ESP_OK)
    {
        return response_err;
    }

    response_err =
        httpd_resp_set_hdr(
            request,
            "Location",
            "/");

    if (response_err != ESP_OK)
    {
        return response_err;
    }

    response_err =
        httpd_resp_set_hdr(
            request,
            "Cache-Control",
            "no-store");

    if (response_err != ESP_OK)
    {
        return response_err;
    }

    return httpd_resp_send(
        request,
        NULL,
        0);

invalid_form:

    ESP_LOGW(
        TAG,
        "Gateway configuration form contains "
        "invalid or missing fields");

    if (body != NULL)
    {
        maintenance_clear_sensitive_memory(
            body,
            content_length + 1U);

        free(body);
        body = NULL;
    }

    maintenance_clear_sensitive_memory(
        pairing_passphrase,
        sizeof(pairing_passphrase));

    maintenance_clear_sensitive_memory(
        pairing_passphrase_confirm,
        sizeof(pairing_passphrase_confirm));

    maintenance_clear_sensitive_memory(
        derived_root_key,
        sizeof(derived_root_key));

    maintenance_clear_sensitive_memory(
        generated_pairing_salt,
        sizeof(generated_pairing_salt));

    maintenance_clear_sensitive_memory(
        &candidate,
        sizeof(candidate));

    return maintenance_send_text_response(
        request,
        "400 Bad Request",
        "Invalid Gateway configuration values.\n");

request_timeout:

    maintenance_clear_sensitive_memory(
        body,
        content_length + 1U);

    free(body);

    maintenance_clear_sensitive_memory(
        pairing_passphrase,
        sizeof(pairing_passphrase));

    maintenance_clear_sensitive_memory(
        pairing_passphrase_confirm,
        sizeof(pairing_passphrase_confirm));

    maintenance_clear_sensitive_memory(
        derived_root_key,
        sizeof(derived_root_key));

    maintenance_clear_sensitive_memory(
        generated_pairing_salt,
        sizeof(generated_pairing_salt));

    return maintenance_send_text_response(
        request,
        "408 Request Timeout",
        "Request timed out.\n");

invalid_request:

    maintenance_clear_sensitive_memory(
        body,
        content_length + 1U);

    free(body);

    maintenance_clear_sensitive_memory(
        pairing_passphrase,
        sizeof(pairing_passphrase));

    maintenance_clear_sensitive_memory(
        pairing_passphrase_confirm,
        sizeof(pairing_passphrase_confirm));

    maintenance_clear_sensitive_memory(
        derived_root_key,
        sizeof(derived_root_key));

    maintenance_clear_sensitive_memory(
        generated_pairing_salt,
        sizeof(generated_pairing_salt));

    return maintenance_send_text_response(
        request,
        "400 Bad Request",
        "Could not read Gateway configuration form.\n");
}

static void maintenance_wifi_event_handler(
    void *handler_argument,
    esp_event_base_t event_base,
    int32_t event_id,
    void *event_data)
{
    (void)handler_argument;
    (void)event_base;

    if (event_id == WIFI_EVENT_AP_STACONNECTED)
    {
        const wifi_event_ap_staconnected_t *event =
            (const wifi_event_ap_staconnected_t *)event_data;

        ESP_LOGI(
            TAG,
            "client connected mac=" MACSTR " aid=%d",
            MAC2STR(event->mac),
            event->aid);
    }
    else if (event_id == WIFI_EVENT_AP_STADISCONNECTED)
    {
        const wifi_event_ap_stadisconnected_t *event =
            (const wifi_event_ap_stadisconnected_t *)event_data;

        ESP_LOGI(
            TAG,
            "client disconnected mac=" MACSTR
            " aid=%d reason=%d",
            MAC2STR(event->mac),
            event->aid,
            event->reason);
    }
}

static const char *maintenance_role_to_ssid(
    mathos_maintenance_role_t role)
{
    switch (role)
    {
    case MATHOS_MAINTENANCE_ROLE_RC:
        return MATHOS_MAINTENANCE_RC_SSID;

    case MATHOS_MAINTENANCE_ROLE_GATEWAY:
        return MATHOS_MAINTENANCE_GATEWAY_SSID;

    default:
        return NULL;
    }
}

static const char *maintenance_role_to_text(
    mathos_maintenance_role_t role)
{
    switch (role)
    {
    case MATHOS_MAINTENANCE_ROLE_RC:
        return "RC";

    case MATHOS_MAINTENANCE_ROLE_GATEWAY:
        return "GATEWAY";

    default:
        return "UNKNOWN";
    }
}
static esp_err_t
maintenance_configure_task_watchdog(void)
{
#if defined(CONFIG_ESP_TASK_WDT_EN) && \
    defined(CONFIG_ESP_TASK_WDT_INIT)

    const esp_task_wdt_config_t task_wdt_config = {
        .timeout_ms =
            MATHOS_MAINTENANCE_TASK_WDT_TIMEOUT_MS,

        .idle_core_mask =
            (1U << CONFIG_FREERTOS_NUMBER_OF_CORES) -
            1U,

#if defined(CONFIG_ESP_TASK_WDT_PANIC)
        .trigger_panic = true
#else
        .trigger_panic = false
#endif
    };

    esp_err_t err =
        esp_task_wdt_reconfigure(
            &task_wdt_config);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "maintenance Task Watchdog "
            "reconfiguration failed: %s",
            esp_err_to_name(err));

        return err;
    }

    ESP_LOGI(
        TAG,
        "maintenance Task Watchdog timeout=%lu ms",
        (unsigned long)
            MATHOS_MAINTENANCE_TASK_WDT_TIMEOUT_MS);

#endif

    return ESP_OK;
}
esp_err_t mathos_maintenance_softap_start(
    mathos_maintenance_role_t role)
{

    if (maintenance_softap_started)
    {
        ESP_LOGW(
            TAG,
            "SoftAP already started");

        return ESP_OK;
    }
    esp_err_t pairing_header_test_err =
        mathos_pairing_wire_header_self_test();

    if (pairing_header_test_err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing wire header self-test FAILED");

        return pairing_header_test_err;
    }

    esp_err_t pairing_package_wire_test_err =
        mathos_pairing_package_wire_self_test();

    if (pairing_package_wire_test_err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing PACKAGE wire self-test FAILED");

        return pairing_package_wire_test_err;
    }

    esp_err_t pairing_challenge_wire_test_err =
        mathos_pairing_challenge_wire_self_test();

    if (pairing_challenge_wire_test_err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing CHALLENGE wire self-test FAILED");

        return pairing_challenge_wire_test_err;
    }

    esp_err_t pairing_proof_wire_test_err =
        mathos_pairing_proof_wire_self_test();

    if (pairing_proof_wire_test_err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing PROOF wire self-test FAILED");

        return pairing_proof_wire_test_err;
    }

    esp_err_t pairing_complete_frame_test_err =
        mathos_pairing_complete_frame_self_test();

    if (pairing_complete_frame_test_err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Pairing COMPLETE FRAME self-test FAILED");

        return pairing_complete_frame_test_err;
    }

    const char *ssid =
        maintenance_role_to_ssid(role);

    if (ssid == NULL)
    {
        ESP_LOGE(
            TAG,
            "invalid maintenance role=%d",
            (int)role);

        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t watchdog_err =
        maintenance_configure_task_watchdog();

    if (watchdog_err != ESP_OK)
    {
        return watchdog_err;
    }
    esp_err_t config_err = ESP_OK;

    if (role == MATHOS_MAINTENANCE_ROLE_RC)
    {
        /*
            The RC uses the telemetry-forwarding
            configuration stored under config_v1.
        */
        config_err =
            mathos_maintenance_config_load(
                &maintenance_active_config,
                &maintenance_config_loaded_from_nvs);

        if (config_err != ESP_OK)
        {
            ESP_LOGW(
                TAG,
                "RC maintenance configuration load failed: %s; "
                "safe defaults remain active",
                esp_err_to_name(config_err));

            maintenance_config_loaded_from_nvs = 0;
        }

        ESP_LOGI(
            TAG,
            "active RC configuration source=%s "
            "telemetry=%u ssid_set=%u host_set=%u port=%u",
            maintenance_config_loaded_from_nvs
                ? "NVS"
                : "DEFAULTS",
            maintenance_active_config.telemetry_enabled,
            maintenance_active_config.wifi_ssid[0] != '\0'
                ? 1U
                : 0U,
            maintenance_active_config.server_host[0] != '\0'
                ? 1U
                : 0U,
            maintenance_active_config.server_port);

        /*
            Load the RC cryptographic pairing record separately
            from telemetry and server configuration.
        */
        esp_err_t pairing_err =
            mathos_rc_pairing_config_load(
                &maintenance_active_rc_pairing_config,
                &maintenance_rc_pairing_config_loaded_from_nvs);

        if (pairing_err != ESP_OK)
        {
            ESP_LOGW(
                TAG,
                "RC pairing configuration load failed: %s; "
                "unpaired defaults remain active",
                esp_err_to_name(pairing_err));

            maintenance_rc_pairing_config_loaded_from_nvs = 0;
        }

        ESP_LOGI(
            TAG,
            "active RC pairing source=%s "
            "rc_id=%u gateway_id=%u "
            "key_generation=%lu key_provisioned=%u "
            "counter=%lu",
            maintenance_rc_pairing_config_loaded_from_nvs
                ? "NVS"
                : "DEFAULTS",
            maintenance_active_rc_pairing_config.rc_id,
            maintenance_active_rc_pairing_config
                .authorised_gateway_id,
            (unsigned long)
                maintenance_active_rc_pairing_config
                    .key_generation,
            maintenance_active_rc_pairing_config
                        .key_generation != 0
                ? 1U
                : 0U,
            (unsigned long)
                maintenance_active_rc_pairing_config
                    .configuration_counter);
    }
    else if (role == MATHOS_MAINTENANCE_ROLE_GATEWAY)
    {
        /*
            The airborne Gateway uses the separate
            configuration stored under gateway_v2.
        */
        config_err =
            mathos_gateway_config_load(
                &maintenance_active_gateway_config,
                &maintenance_gateway_config_loaded_from_nvs);

        if (config_err != ESP_OK)
        {
            ESP_LOGW(
                TAG,
                "Gateway configuration load failed: %s; "
                "safe defaults remain active",
                esp_err_to_name(config_err));

            maintenance_gateway_config_loaded_from_nvs = 0;
        }

        ESP_LOGI(
            TAG,
            "active Gateway configuration source=%s "
            "gateway_id=%u rc_id=%u "
            "key_generation=%lu key_provisioned=%u "
            "link_baud=%lu fc_baud=%lu "
            "rc_timeout=%u fc_timeout=%u "
            "status_period=%u telemetry_period=%u "
            "failsafe_policy=%u counter=%lu",
            maintenance_gateway_config_loaded_from_nvs
                ? "NVS"
                : "DEFAULTS",
            maintenance_active_gateway_config.gateway_id,
            maintenance_active_gateway_config.authorised_rc_id,
            (unsigned long)
                maintenance_active_gateway_config.key_generation,
            maintenance_active_gateway_config.key_generation != 0
                ? 1U
                : 0U,
            (unsigned long)
                maintenance_active_gateway_config.link_uart_baud,
            (unsigned long)
                maintenance_active_gateway_config.fc_uart_baud,
            maintenance_active_gateway_config.rc_packet_timeout_ms,
            maintenance_active_gateway_config.fc_heartbeat_timeout_ms,
            maintenance_active_gateway_config.status_tx_period_ms,
            maintenance_active_gateway_config.telemetry_tx_period_ms,
            maintenance_active_gateway_config.failsafe_policy,
            (unsigned long)
                maintenance_active_gateway_config.configuration_counter);
    }
    else
    {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err =
        esp_netif_init();

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "esp_netif_init failed: %s",
            esp_err_to_name(err));

        return err;
    }

    err =
        esp_event_loop_create_default();

    /*
        ESP_ERR_INVALID_STATE means another part of the
        application already created the default event loop.

        That is acceptable for the shared component.
    */
    if (err != ESP_OK &&
        err != ESP_ERR_INVALID_STATE)
    {
        ESP_LOGE(
            TAG,
            "event loop creation failed: %s",
            esp_err_to_name(err));

        return err;
    }

    maintenance_ap_netif = esp_netif_create_default_wifi_ap();

    if (maintenance_ap_netif == NULL)
    {
        ESP_LOGE(
            TAG,
            "failed to create default Wi-Fi AP interface");

        return ESP_FAIL;
    }

    wifi_init_config_t wifi_init_config =
        WIFI_INIT_CONFIG_DEFAULT();

    err =
        esp_wifi_init(&wifi_init_config);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "esp_wifi_init failed: %s",
            esp_err_to_name(err));

        return err;
    }

    err =
        esp_event_handler_instance_register(
            WIFI_EVENT,
            ESP_EVENT_ANY_ID,
            maintenance_wifi_event_handler,
            NULL,
            NULL);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "Wi-Fi event handler registration failed: %s",
            esp_err_to_name(err));

        return err;
    }

    wifi_config_t wifi_config = {0};

    snprintf(
        (char *)wifi_config.ap.ssid,
        sizeof(wifi_config.ap.ssid),
        "%s",
        ssid);

    wifi_config.ap.ssid_len =
        strlen(
            (const char *)wifi_config.ap.ssid);

    snprintf(
        (char *)wifi_config.ap.password,
        sizeof(wifi_config.ap.password),
        "%s",
        MATHOS_MAINTENANCE_TEST_PASSWORD);

    wifi_config.ap.channel =
        MATHOS_MAINTENANCE_WIFI_CHANNEL;

    wifi_config.ap.max_connection =
        MATHOS_MAINTENANCE_MAX_CLIENTS;

    wifi_config.ap.authmode =
        WIFI_AUTH_WPA2_PSK;

    wifi_config.ap.pmf_cfg.capable =
        true;

    wifi_config.ap.pmf_cfg.required =
        true;

    err =
        esp_wifi_set_mode(
            WIFI_MODE_AP);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "esp_wifi_set_mode failed: %s",
            esp_err_to_name(err));

        return err;
    }

    err =
        esp_wifi_set_config(
            WIFI_IF_AP,
            &wifi_config);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "esp_wifi_set_config failed: %s",
            esp_err_to_name(err));

        return err;
    }

    err =
        esp_wifi_start();

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "esp_wifi_start failed: %s",
            esp_err_to_name(err));

        return err;
    }

    maintenance_softap_started = true;

    err = maintenance_http_server_start(role);

    if (err != ESP_OK)
    {
        ESP_LOGE(
            TAG,
            "maintenance HTTP server failed: %s",
            esp_err_to_name(err));

        maintenance_softap_started = false;

        esp_wifi_stop();

        return err;
    }

    ESP_LOGI(
        TAG,
        "SoftAP started role=%s ssid=%s channel=%u max_clients=%u",
        maintenance_role_to_text(role),
        ssid,
        (unsigned int)MATHOS_MAINTENANCE_WIFI_CHANNEL,
        (unsigned int)MATHOS_MAINTENANCE_MAX_CLIENTS);

    ESP_LOGI(
        TAG,
        "maintenance control and flight tasks remain disabled");

#if MATHOS_PAIRING_BENCH_SELF_TEST_ENABLED

    if (role ==
        MATHOS_MAINTENANCE_ROLE_RC)
    {
        esp_err_t self_test_err =
            maintenance_run_pairing_bench_self_test();

        if (self_test_err != ESP_OK)
        {
            ESP_LOGE(
                TAG,
                "pairing bench self-test returned: %s",
                esp_err_to_name(self_test_err));
        }
    }

#endif

    return ESP_OK;
}

esp_err_t mathos_pairing_challenge_encode_payload(
    const mathos_pairing_challenge_t *challenge,
    uint8_t *output,
    size_t output_size)
{
    if (challenge == NULL ||
        output == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (output_size <
        MATHOS_PAIRING_CHALLENGE_WIRE_LEN)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    /*
        Only an active, completely valid challenge
        may be placed onto the pairing transport.
    */
    if (!mathos_pairing_challenge_is_valid(
            challenge) ||
        challenge->key_generation == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    size_t i = 0;

    /*
        magic uint32 little-endian
    */
    output[i++] =
        (uint8_t)(challenge->magic & 0xFFU);

    output[i++] =
        (uint8_t)((challenge->magic >> 8) & 0xFFU);

    output[i++] =
        (uint8_t)((challenge->magic >> 16) & 0xFFU);

    output[i++] =
        (uint8_t)((challenge->magic >> 24) & 0xFFU);

    /*
        version uint16 little-endian
    */
    output[i++] =
        (uint8_t)(challenge->version & 0xFFU);

    output[i++] =
        (uint8_t)((challenge->version >> 8) & 0xFFU);

    /*
        record_size uint16 little-endian
    */
    output[i++] =
        (uint8_t)(challenge->record_size & 0xFFU);

    output[i++] =
        (uint8_t)((challenge->record_size >> 8) & 0xFFU);

    /*
        Device identities.
    */
    output[i++] =
        challenge->rc_id;

    output[i++] =
        challenge->gateway_id;

    /*
        Permanent Gateway hardware UID.

        The byte order is exactly the canonical UID byte
        order used by mathos_identity.
    */
    for (size_t uid_index = 0;
         uid_index < MATHOS_DEVICE_UID_LEN;
         uid_index++)
    {
        output[i++] =
            challenge->gateway_uid.bytes[uid_index];
    }

    output[i++] =
        challenge->reserved0[0];

    output[i++] =
        challenge->reserved0[1];

    /*
        key_generation uint32 little-endian
    */
    output[i++] =
        (uint8_t)(challenge->key_generation & 0xFFU);

    output[i++] =
        (uint8_t)((challenge->key_generation >> 8) & 0xFFU);

    output[i++] =
        (uint8_t)((challenge->key_generation >> 16) & 0xFFU);

    output[i++] =
        (uint8_t)((challenge->key_generation >> 24) & 0xFFU);

    /*
        Fresh Gateway nonce.
    */
    for (size_t nonce_index = 0;
         nonce_index < MATHOS_PAIRING_NONCE_LEN;
         nonce_index++)
    {
        output[i++] =
            challenge->nonce[nonce_index];
    }

    /*
        CRC uint32 little-endian
    */
    output[i++] =
        (uint8_t)(challenge->crc32 & 0xFFU);

    output[i++] =
        (uint8_t)((challenge->crc32 >> 8) & 0xFFU);

    output[i++] =
        (uint8_t)((challenge->crc32 >> 16) & 0xFFU);

    output[i++] =
        (uint8_t)((challenge->crc32 >> 24) & 0xFFU);

    /*
        Detect accidental future wire-layout mistakes.
    */
    if (i !=
        MATHOS_PAIRING_CHALLENGE_WIRE_LEN)
    {
        return ESP_FAIL;
    }

    return ESP_OK;
}

esp_err_t mathos_pairing_challenge_decode_payload(
    const uint8_t *input,
    size_t input_size,
    mathos_pairing_challenge_t *challenge)
{
    if (input == NULL ||
        challenge == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    if (input_size !=
        MATHOS_PAIRING_CHALLENGE_WIRE_LEN)
    {
        return ESP_ERR_INVALID_SIZE;
    }

    memset(
        challenge,
        0,
        sizeof(*challenge));

    size_t i = 0;

    /*
        magic uint32 little-endian
    */
    challenge->magic =
        (uint32_t)input[i] |
        ((uint32_t)input[i + 1] << 8) |
        ((uint32_t)input[i + 2] << 16) |
        ((uint32_t)input[i + 3] << 24);

    i += 4;

    /*
        version uint16 little-endian
    */
    challenge->version =
        (uint16_t)input[i] |
        ((uint16_t)input[i + 1] << 8);

    i += 2;

    /*
        record_size uint16 little-endian
    */
    challenge->record_size =
        (uint16_t)input[i] |
        ((uint16_t)input[i + 1] << 8);

    i += 2;

    challenge->rc_id =
        input[i++];

    challenge->gateway_id =
        input[i++];

    /*
        Decode the permanent Gateway hardware UID.
    */
    for (size_t uid_index = 0;
         uid_index < MATHOS_DEVICE_UID_LEN;
         uid_index++)
    {
        challenge->gateway_uid.bytes[uid_index] =
            input[i++];
    }

    challenge->reserved0[0] =
        input[i++];

    challenge->reserved0[1] =
        input[i++];

    /*
        key_generation uint32 little-endian
    */
    challenge->key_generation =
        (uint32_t)input[i] |
        ((uint32_t)input[i + 1] << 8) |
        ((uint32_t)input[i + 2] << 16) |
        ((uint32_t)input[i + 3] << 24);

    i += 4;

    /*
        Fresh Gateway nonce.
    */
    for (size_t nonce_index = 0;
         nonce_index < MATHOS_PAIRING_NONCE_LEN;
         nonce_index++)
    {
        challenge->nonce[nonce_index] =
            input[i++];
    }

    /*
        CRC uint32 little-endian
    */
    challenge->crc32 =
        (uint32_t)input[i] |
        ((uint32_t)input[i + 1] << 8) |
        ((uint32_t)input[i + 2] << 16) |
        ((uint32_t)input[i + 3] << 24);

    i += 4;

    /*
        Defensive wire-layout check.
    */
    if (i !=
        MATHOS_PAIRING_CHALLENGE_WIRE_LEN)
    {
        memset(
            challenge,
            0,
            sizeof(*challenge));

        return ESP_FAIL;
    }

    /*
        Reject malformed, stale-format or corrupted
        challenge records.
    */
    if (!mathos_pairing_challenge_is_valid(
            challenge) ||
        challenge->key_generation == 0)
    {
        memset(
            challenge,
            0,
            sizeof(*challenge));

        return ESP_ERR_INVALID_CRC;
    }

    return ESP_OK;
}

esp_err_t mathos_maintenance_get_ap_ip(
    char *buffer,
    size_t buffer_size)
{
    if (buffer == NULL ||
        buffer_size == 0)
    {
        return ESP_ERR_INVALID_ARG;
    }

    buffer[0] = '\0';

    if (!maintenance_softap_started ||
        maintenance_ap_netif == NULL)
    {
        return ESP_ERR_INVALID_STATE;
    }

    esp_netif_ip_info_t ip_info = {0};

    esp_err_t err =
        esp_netif_get_ip_info(
            maintenance_ap_netif,
            &ip_info);

    if (err != ESP_OK)
    {
        return err;
    }

    int written = snprintf(
        buffer,
        buffer_size,
        IPSTR,
        IP2STR(&ip_info.ip));

    if (written < 0 ||
        written >= (int)buffer_size)
    {
        buffer[0] = '\0';
        return ESP_ERR_INVALID_SIZE;
    }

    return ESP_OK;
}