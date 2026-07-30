idf_component_register(
    SRCS
        "mathos_maintenance.c"

    INCLUDE_DIRS
        "include"

    REQUIRES
        esp_wifi
        esp_event
        esp_netif
        esp_http_server
        nvs_flash
)