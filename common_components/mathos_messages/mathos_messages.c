#include "mathos_messages.h"
#include <stddef.h>

uint16_t mathos_get_u16_le(const uint8_t *buffer)
{
    if (buffer == NULL)
    {
        return 0;
    }

    return ((uint16_t)buffer[0] << 0) |
           ((uint16_t)buffer[1] << 8);
}

const char *mathos_rc_state_to_string(rc_state_t state)
{
    switch (state)
    {
    case RC_DISARMED:
        return "DISARMED";

    case RC_ARMED:
        return "ARMED";

    case RC_FAILSAFE:
        return "FAILSAFE";

    default:
        return "UNKNOWN";
    }
}


const char *mathos_gateway_action_to_string(
    gateway_action_t action
)
{
    switch (action)
    {
    case GATEWAY_ACTION_NONE:
        return "NONE";

    case GATEWAY_ACTION_ARM_DRY_RUN:
        return "ARM_DRY_RUN";

    case GATEWAY_ACTION_DISARM_DRY_RUN:
        return "DISARM_DRY_RUN";

    case GATEWAY_ACTION_FAILSAFE_DRY_RUN:
        return "FAILSAFE_DRY_RUN";

    case GATEWAY_ACTION_ARM_REAL_SENT:
        return "ARM_REAL_SENT";

    case GATEWAY_ACTION_DISARM_REAL_SENT:
        return "DISARM_REAL_SENT";

    case GATEWAY_ACTION_RTL_SENT:
        return "RTL_SENT";

    case GATEWAY_ACTION_RTL_CONFIRMED:
        return "RTL_CONFIRMED";

    case GATEWAY_ACTION_RTL_DENIED:
        return "RTL_DENIED";

    case GATEWAY_ACTION_RTL_TIMEOUT:
        return "RTL_TIMEOUT";

    case GATEWAY_ACTION_ARM_CONFIRMED:
        return "ARM_CONFIRMED";

    case GATEWAY_ACTION_DISARM_CONFIRMED:
        return "DISARM_CONFIRMED";

    case GATEWAY_ACTION_ARM_DENIED:
        return "ARM_DENIED";

    case GATEWAY_ACTION_DISARM_DENIED:
        return "DISARM_DENIED";

    case GATEWAY_ACTION_ARM_TIMEOUT:
        return "ARM_TIMEOUT";

    case GATEWAY_ACTION_DISARM_TIMEOUT:
        return "DISARM_TIMEOUT";

    case GATEWAY_ACTION_RECOVER_DRY_RUN:
        return "RECOVER_DRY_RUN";

    case GATEWAY_ACTION_RECOVER_CONFIRMED:
        return "RECOVER_CONFIRMED";

    default:
        return "UNKNOWN";
    }
}

const char *mathos_gps_fix_to_string(uint8_t fix_type)
{
    switch (fix_type)
    {
    case 0:
        return "NO_GPS";

    case 1:
        return "NO_FIX";

    case 2:
        return "2D";

    case 3:
        return "3D";

    case 4:
        return "DGPS";

    case 5:
        return "RTK_FLOAT";

    case 6:
        return "RTK_FIXED";

    default:
        return "UNKNOWN";
    }
}

const char *mathos_mav_result_to_string(uint8_t result)
{
    switch (result)
    {
    case 0:
        return "ACCEPTED";

    case 1:
        return "TEMPORARILY_REJECTED";

    case 2:
        return "DENIED";

    case 3:
        return "UNSUPPORTED";

    case 4:
        return "FAILED";

    case 5:
        return "IN_PROGRESS";

    case 6:
        return "CANCELLED";

    default:
        return "UNKNOWN";
    }
}