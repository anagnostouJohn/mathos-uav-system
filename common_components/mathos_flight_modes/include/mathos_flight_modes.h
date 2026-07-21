#pragma once

#include <stdint.h>
#include <stdbool.h>

/*
    Shared ArduPlane / QuadPlane mode helpers.

    Used by:
    - remote_controller
    - drone_gateway
*/

const char *mathos_plane_mode_to_string(uint32_t custom_mode);

bool mathos_plane_mode_is_rtl(uint32_t custom_mode);