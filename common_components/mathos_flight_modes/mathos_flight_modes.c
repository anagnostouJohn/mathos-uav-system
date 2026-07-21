#include "mathos_flight_modes.h"

const char *mathos_plane_mode_to_string(uint32_t custom_mode)
{
    switch (custom_mode)
    {
    case 0:
        return "MANUAL";

    case 1:
        return "CIRCLE";

    case 2:
        return "STABILIZE";

    case 3:
        return "TRAINING";

    case 4:
        return "ACRO";

    case 5:
        return "FBWA";

    case 6:
        return "FBWB";

    case 7:
        return "CRUISE";

    case 8:
        return "AUTOTUNE";

    case 10:
        return "AUTO";

    case 11:
        return "RTL";

    case 12:
        return "LOITER";

    case 13:
        return "TAKEOFF";

    case 14:
        return "AVOID ADSB";

    case 15:
        return "GUIDED";

    case 16:
        return "INITIALISING";

    case 17:
        return "QSTABILIZE";

    case 18:
        return "QHOVER";

    case 19:
        return "QLOITER";

    case 20:
        return "QLAND";

    case 21:
        return "QRTL";

    case 22:
        return "QAUTOTUNE";

    case 23:
        return "QACRO";

    case 24:
        return "THERMAL";

    case 25:
        return "LOITER QLAND";

    case 26:
        return "AUTOLAND";

    default:
        return "UNKNOWN";
    }
}

bool mathos_plane_mode_is_rtl(uint32_t custom_mode)
{
    return custom_mode == 11U ||
           custom_mode == 21U;
}