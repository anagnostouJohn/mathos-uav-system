idf_component_register(
    SRCS "drone_gateway_main.c"
    INCLUDE_DIRS "."
    REQUIRES
        esp_timer
        esp_driver_uart
        esp_driver_gpio
        log
        mathos_protocol
        mathos_secure
        mavlink
)