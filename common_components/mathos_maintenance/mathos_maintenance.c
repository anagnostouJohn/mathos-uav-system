#include "mathos_maintenance.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_server.h"
#include "nvs.h"

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
#define MATHOS_MAINTENANCE_PAGE_BUFFER_SIZE 8192
#define MATHOS_MAINTENANCE_ROLE_SECTION_BUFFER_SIZE 4096
#define MATHOS_MAINTENANCE_FORM_BODY_MAX 512

static const char *TAG = "MATHOS_MAINT";

static bool maintenance_softap_started = false;

static httpd_handle_t maintenance_http_server = NULL;
static esp_netif_t *maintenance_ap_netif = NULL;

static mathos_maintenance_role_t maintenance_active_role =
    MATHOS_MAINTENANCE_ROLE_RC;

static mathos_maintenance_config_t maintenance_active_config;

static int maintenance_config_loaded_from_nvs = 0;
static esp_err_t maintenance_rc_config_post_handler(
    httpd_req_t *request);

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

        written = snprintf(
            destination,
            destination_size,

            "<div class=\"label\">Configuration source</div>"
            "<div class=\"value\">%s</div>"

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
            "</section>",

            config_source_text,
            telemetry_state_text,
            wifi_ssid_html,
            server_host_html,
            server_port_text,
            telemetry_checked_text,
            wifi_ssid_html,
            server_host_html,
            server_port_form);

        break;

    case MATHOS_MAINTENANCE_ROLE_GATEWAY:

        written = snprintf(
            destination,
            destination_size,

            "<section class=\"editor\">"
            "<h2>Gateway configuration</h2>"

            "<div class=\"warning\">"
            "Gateway-specific flight-controller, MAVLink, "
            "radio-link and telemetry-routing settings "
            "will be configured here."
            "</div>"

            "<div class=\"warning\">"
            "RC joystick and calibration controls are "
            "intentionally unavailable on the gateway."
            "</div>"

            "</section>");

        break;

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
    const char *config_source_text =
        maintenance_config_loaded_from_nvs
            ? "Saved configuration"
            : "Safe defaults";

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
    }
    else
    {
        ESP_LOGI(
            TAG,
            "RC configuration endpoint not registered "
            "for gateway role");
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

    esp_err_t config_err =
        mathos_maintenance_config_load(
            &maintenance_active_config,
            &maintenance_config_loaded_from_nvs);

    if (config_err != ESP_OK)
    {
        ESP_LOGW(
            TAG,
            "maintenance configuration load failed: %s; "
            "safe defaults remain active",
            esp_err_to_name(config_err));

        maintenance_config_loaded_from_nvs = 0;
    }

    ESP_LOGI(
        TAG,
        "active maintenance configuration source=%s "
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