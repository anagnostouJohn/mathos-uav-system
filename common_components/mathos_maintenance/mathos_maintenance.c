#include "mathos_maintenance.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_http_server.h"

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

static const char *TAG = "MATHOS_MAINT";

static bool maintenance_softap_started = false;

static httpd_handle_t maintenance_http_server = NULL;
static esp_netif_t *maintenance_ap_netif = NULL;

static mathos_maintenance_role_t maintenance_active_role =
    MATHOS_MAINTENANCE_ROLE_RC;



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

static esp_err_t maintenance_root_get_handler(
    httpd_req_t *request)
{
    ESP_LOGI(
        TAG,
        "HTTP GET / received");

    if (request == NULL)
    {
        return ESP_ERR_INVALID_ARG;
    }

    char page[1536];

    const char *device_text =
        maintenance_role_to_page_text(
            maintenance_active_role);

    char ip_text[16] = "Unavailable";

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

    int written = snprintf(
        page,
        sizeof(page),
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
        "<div class=\"label\">Safety state</div>"
        "<div class=\"value\">Control tasks disabled</div>"
        "</main>"
        "</body>"
        "</html>",
        device_text,
        ip_text);

    if (written < 0 ||
        written >= (int)sizeof(page))
    {
        ESP_LOGE(
            TAG,
            "maintenance page buffer too small");

        return ESP_FAIL;
    }

    esp_err_t err =
        httpd_resp_set_type(
            request,
            "text/html; charset=utf-8");

    if (err != ESP_OK)
    {
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
        return err;
    }

    return httpd_resp_send(
        request,
        page,
        HTTPD_RESP_USE_STRLEN);
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