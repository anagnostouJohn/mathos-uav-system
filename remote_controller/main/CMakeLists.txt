idf_component_register(
    SRCS
        "main.c"

    INCLUDE_DIRS
        "."

    REQUIRES
        driver
        esp_adc
        esp_timer
        espressif__led_strip
        mathos_protocol
        mathos_secure
        mathos_messages
        mathos_flight_modes
        nvs_flash
        mathos_maintenance
)