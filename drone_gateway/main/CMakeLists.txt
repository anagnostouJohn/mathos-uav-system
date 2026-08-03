idf_component_register(
    SRCS "main.c"
    INCLUDE_DIRS "."
    REQUIRES
        driver
        esp_timer
        esp_system
        esp_hw_support
        log
        mathos_protocol
        mathos_secure
        mavlink
        mathos_messages
        mathos_flight_modes
        mathos_maintenance
        nvs_flash
)