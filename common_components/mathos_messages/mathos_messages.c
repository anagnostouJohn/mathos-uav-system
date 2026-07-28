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
    gateway_action_t action)
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

mathos_ekf_health_t mathos_ekf_health_classify(
    uint16_t ekf_flags,
    int data_available,
    int data_fresh)
{
    /*
        No EKF_STATUS_REPORT has been received yet.
    */
    if (!data_available)
    {
        return MATHOS_EKF_HEALTH_NO_DATA;
    }

    /*
        An EKF report existed, but it is no longer fresh.
    */
    if (!data_fresh)
    {
        return MATHOS_EKF_HEALTH_STALE;
    }

    /*
        ArduPilot explicitly reports that the EKF
        has not completed initialization.
    */
    if (ekf_flags & MATHOS_EKF_FLAG_UNINITIALIZED)
    {
        return MATHOS_EKF_HEALTH_INITIALIZING;
    }

    /*
        A valid attitude estimate is the minimum condition
        we currently require for EKF OK.

        GPS position is deliberately not required here,
        because attitude can be valid without GPS.
    */
    if (ekf_flags & MATHOS_EKF_FLAG_ATTITUDE)
    {
        return MATHOS_EKF_HEALTH_OK;
    }

    return MATHOS_EKF_HEALTH_BAD;
}

const char *mathos_ekf_health_to_string(
    mathos_ekf_health_t health)
{
    switch (health)
    {
    case MATHOS_EKF_HEALTH_NO_DATA:
        return "NO_DATA";

    case MATHOS_EKF_HEALTH_STALE:
        return "STALE";

    case MATHOS_EKF_HEALTH_INITIALIZING:
        return "INITIALIZING";

    case MATHOS_EKF_HEALTH_OK:
        return "OK";

    case MATHOS_EKF_HEALTH_BAD:
        return "BAD";

    default:
        return "UNKNOWN";
    }
}

mathos_gps_health_t mathos_gps_health_classify(
    uint8_t fix_type,
    int data_available,
    int data_fresh)
{
    if (!data_available)
    {
        return MATHOS_GPS_HEALTH_NO_DATA;
    }

    if (!data_fresh)
    {
        return MATHOS_GPS_HEALTH_STALE;
    }

    switch (fix_type)
    {
    case 0:
        return MATHOS_GPS_HEALTH_NO_GPS;

    case 1:
        return MATHOS_GPS_HEALTH_NO_FIX;

    case 2:
        return MATHOS_GPS_HEALTH_2D;

    case 3:
        return MATHOS_GPS_HEALTH_3D;

    case 4:
        return MATHOS_GPS_HEALTH_DGPS;

    case 5:
        return MATHOS_GPS_HEALTH_RTK_FLOAT;

    case 6:
        return MATHOS_GPS_HEALTH_RTK_FIXED;

    default:
        return MATHOS_GPS_HEALTH_UNKNOWN;
    }
}

const char *mathos_gps_health_to_string(
    mathos_gps_health_t health)
{
    switch (health)
    {
    case MATHOS_GPS_HEALTH_NO_DATA:
        return "NO_DATA";

    case MATHOS_GPS_HEALTH_STALE:
        return "STALE";

    case MATHOS_GPS_HEALTH_NO_GPS:
        return "NO_GPS";

    case MATHOS_GPS_HEALTH_NO_FIX:
        return "NO_FIX";

    case MATHOS_GPS_HEALTH_2D:
        return "2D";

    case MATHOS_GPS_HEALTH_3D:
        return "3D";

    case MATHOS_GPS_HEALTH_DGPS:
        return "DGPS";

    case MATHOS_GPS_HEALTH_RTK_FLOAT:
        return "RTK_FLOAT";

    case MATHOS_GPS_HEALTH_RTK_FIXED:
        return "RTK_FIXED";

    case MATHOS_GPS_HEALTH_UNKNOWN:
        return "UNKNOWN";

    default:
        return "UNKNOWN";
    }
}

mathos_battery_health_t mathos_battery_health_classify(
    uint16_t voltage_mv,
    int8_t remaining_percent,
    int data_available,
    int data_fresh)
{
    if (!data_available)
    {
        return MATHOS_BATTERY_HEALTH_NO_DATA;
    }

    if (!data_fresh)
    {
        return MATHOS_BATTERY_HEALTH_STALE;
    }

    /*
        Zero and UINT16_MAX represent unusable voltage data.
    */
    if (voltage_mv == 0 ||
        voltage_mv == UINT16_MAX)
    {
        return MATHOS_BATTERY_HEALTH_INVALID;
    }

    /*
        MAVLink uses -1 when battery percentage
        is not available.
    */
    if (remaining_percent == -1)
    {
        return MATHOS_BATTERY_HEALTH_NO_PERCENT;
    }

    if (remaining_percent < -1 ||
        remaining_percent > 100)
    {
        return MATHOS_BATTERY_HEALTH_INVALID;
    }

    if (remaining_percent <= 10)
    {
        return MATHOS_BATTERY_HEALTH_CRITICAL;
    }

    if (remaining_percent <= 20)
    {
        return MATHOS_BATTERY_HEALTH_LOW;
    }

    return MATHOS_BATTERY_HEALTH_OK;
}

const char *mathos_battery_health_to_string(
    mathos_battery_health_t health)
{
    switch (health)
    {
    case MATHOS_BATTERY_HEALTH_NO_DATA:
        return "NO_DATA";

    case MATHOS_BATTERY_HEALTH_STALE:
        return "STALE";

    case MATHOS_BATTERY_HEALTH_INVALID:
        return "INVALID";

    case MATHOS_BATTERY_HEALTH_NO_PERCENT:
        return "NO_PERCENT";

    case MATHOS_BATTERY_HEALTH_OK:
        return "OK";

    case MATHOS_BATTERY_HEALTH_LOW:
        return "LOW";

    case MATHOS_BATTERY_HEALTH_CRITICAL:
        return "CRITICAL";

    default:
        return "UNKNOWN";
    }
}

mathos_altitude_health_t mathos_altitude_health_classify(
    int data_available,
    int data_fresh)
{
    if (!data_available)
    {
        return MATHOS_ALTITUDE_HEALTH_NO_DATA;
    }

    if (!data_fresh)
    {
        return MATHOS_ALTITUDE_HEALTH_STALE;
    }

    return MATHOS_ALTITUDE_HEALTH_VALID;
}

const char *mathos_altitude_health_to_string(
    mathos_altitude_health_t health)
{
    switch (health)
    {
    case MATHOS_ALTITUDE_HEALTH_NO_DATA:
        return "NO_DATA";

    case MATHOS_ALTITUDE_HEALTH_STALE:
        return "STALE";

    case MATHOS_ALTITUDE_HEALTH_VALID:
        return "VALID";

    default:
        return "UNKNOWN";
    }
}

mathos_attitude_health_t mathos_attitude_health_classify(
    int data_available,
    int data_fresh)
{
    if (!data_available)
    {
        return MATHOS_ATTITUDE_HEALTH_NO_DATA;
    }

    if (!data_fresh)
    {
        return MATHOS_ATTITUDE_HEALTH_STALE;
    }

    return MATHOS_ATTITUDE_HEALTH_VALID;
}

const char *mathos_attitude_health_to_string(
    mathos_attitude_health_t health)
{
    switch (health)
    {
    case MATHOS_ATTITUDE_HEALTH_NO_DATA:
        return "NO_DATA";

    case MATHOS_ATTITUDE_HEALTH_STALE:
        return "STALE";

    case MATHOS_ATTITUDE_HEALTH_VALID:
        return "VALID";

    default:
        return "UNKNOWN";
    }
}

mathos_airspeed_health_t mathos_airspeed_health_classify(
    int data_available,
    int data_fresh)
{
    if (!data_available)
    {
        return MATHOS_AIRSPEED_HEALTH_NO_DATA;
    }

    if (!data_fresh)
    {
        return MATHOS_AIRSPEED_HEALTH_STALE;
    }

    return MATHOS_AIRSPEED_HEALTH_VALID;
}

const char *mathos_airspeed_health_to_string(
    mathos_airspeed_health_t health)
{
    switch (health)
    {
    case MATHOS_AIRSPEED_HEALTH_NO_DATA:
        return "NO_DATA";

    case MATHOS_AIRSPEED_HEALTH_STALE:
        return "STALE";

    case MATHOS_AIRSPEED_HEALTH_VALID:
        return "VALID";

    default:
        return "UNKNOWN";
    }
}