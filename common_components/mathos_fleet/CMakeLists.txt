idf_component_register(
    SRCS
        "mathos_fleet.c"

    INCLUDE_DIRS
        "include"

    REQUIRES
        nvs_flash
        mathos_identity
)