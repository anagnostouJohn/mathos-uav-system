idf_component_register(
    SRCS
        "mathos_fleet.c"

    INCLUDE_DIRS
        "include"

REQUIRES
    nvs_flash
    nvs_sec_provider
    efuse
    esp_security
    esp_partition
    esp_hw_support
    mbedtls
    mathos_identity
)