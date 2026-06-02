idf_component_register(
    SRCS "mathos_secure.c"
    INCLUDE_DIRS "include"
    REQUIRES mathos_protocol mbedtls
)