#pragma once

#include <stdint.h>

/*
    Shared Mathos UAV wire-message definitions.

    Used by:
    - remote_controller
    - drone_gateway
*/

#define MATHOS_MESSAGES_VERSION 1U
/*
    Mathos link endpoint identities.

    Controller ID 1:
    Remote controller packets sent toward the gateway.

    Controller ID 2:
    Gateway status and telemetry packets sent toward the remote.
*/
#define SECURITY_CONTROLLER_ID 1U
#define SECURITY_GATEWAY_ID    2U
#define MATHOS_RC_PROTOCOL_VERSION 1u
/*
    Encrypted Mathos payload types.
*/
#define SECURITY_PAYLOAD_TYPE_RC                1U
#define SECURITY_PAYLOAD_TYPE_GATEWAY_STATUS    2U
#define SECURITY_PAYLOAD_TYPE_GATEWAY_TELEMETRY 3U
typedef enum
{
    RC_DISARMED = 0,
    RC_ARMED = 1,
    RC_FAILSAFE = 2
} rc_state_t;

const char *mathos_rc_state_to_string(rc_state_t state);
const char *mathos_gps_fix_to_string(uint8_t fix_type);
const char *mathos_mav_result_to_string(uint8_t result);
uint16_t mathos_get_u16_le(const uint8_t *buffer);

typedef struct
{
    uint32_t packet_id;
    rc_state_t state;

    int throttle;
    int yaw;
    int pitch;
    int roll;

    /*
       Identifies the RC control-packet layout.

       The gateway must reject packets using an unsupported
       version before processing state or joystick data.
    */
    uint8_t protocol_version;
    uint8_t reserved[3];
} rc_packet_t;


typedef enum
{
    GATEWAY_ACTION_NONE = 0,

    GATEWAY_ACTION_ARM_DRY_RUN,
    GATEWAY_ACTION_DISARM_DRY_RUN,
    GATEWAY_ACTION_FAILSAFE_DRY_RUN,

    GATEWAY_ACTION_ARM_REAL_SENT,
    GATEWAY_ACTION_DISARM_REAL_SENT,

    GATEWAY_ACTION_RTL_SENT,
    GATEWAY_ACTION_RTL_CONFIRMED,
    GATEWAY_ACTION_RTL_DENIED,
    GATEWAY_ACTION_RTL_TIMEOUT,

    GATEWAY_ACTION_ARM_CONFIRMED,
    GATEWAY_ACTION_DISARM_CONFIRMED,
    GATEWAY_ACTION_ARM_DENIED,
    GATEWAY_ACTION_DISARM_DENIED,
    GATEWAY_ACTION_ARM_TIMEOUT,
    GATEWAY_ACTION_DISARM_TIMEOUT,

    GATEWAY_ACTION_RECOVER_DRY_RUN,
    GATEWAY_ACTION_RECOVER_CONFIRMED
} gateway_action_t;


const char *mathos_gateway_action_to_string(
    gateway_action_t action
);

#define MATHOS_GATEWAY_PROTOCOL_VERSION 1u

typedef struct __attribute__((packed))
{
    uint32_t packet_id;
    uint32_t session_id;

    uint8_t fc_heartbeat_fresh;
    uint8_t fc_is_armed;
    uint8_t remote_state;
    uint8_t gateway_link_ok;
    uint8_t last_action;

    /*
        Version of the gateway-to-remote status protocol.

        Both devices must report the same version before
        ARM or FAILSAFE recovery is allowed.
    */
    uint8_t protocol_version;

    uint8_t reserved[2];

    uint32_t rx_ok_count;
    uint32_t rx_bad_count;
    uint32_t rx_replay_count;
} gateway_status_packet_t;

/*
    Gateway telemetry field-validity flags.
*/
#define GATEWAY_TELEMETRY_FLAG_BATTERY_FRESH  (1u << 0)
#define GATEWAY_TELEMETRY_FLAG_GPS_FRESH      (1u << 1)
#define GATEWAY_TELEMETRY_FLAG_POSITION_FRESH (1u << 2)
#define GATEWAY_TELEMETRY_FLAG_ATTITUDE_FRESH (1u << 3)
#define GATEWAY_TELEMETRY_FLAG_EKF_FRESH      (1u << 4)

typedef struct __attribute__((packed))
{
    uint32_t packet_id;
    uint32_t sample_time_ms;

    /*
        Raw ArduPilot HEARTBEAT.custom_mode.
    */
    uint32_t fc_custom_mode;

    uint16_t battery_voltage_mv;
    int16_t battery_current_ca;
    int8_t battery_remaining;

    uint8_t gps_fix_type;
    uint8_t satellites_visible;
    uint8_t telemetry_flags;

    int32_t latitude_e7;
    int32_t longitude_e7;
    int32_t altitude_mm;
    int32_t relative_altitude_mm;

    int16_t roll_cd;
    int16_t pitch_cd;
    int16_t yaw_cd;

    /*
        Raw MAVLink EKF_STATUS_REPORT.flags.
    */
    uint16_t ekf_flags;

    uint8_t fc_is_armed;
    uint8_t system_status;

    /*
        MAVLink HEARTBEAT.type.
    */
    uint8_t fc_vehicle_type;

    uint8_t reserved;
} gateway_telemetry_packet_t;

_Static_assert(
    sizeof(gateway_telemetry_packet_t) == 48,
    "gateway_telemetry_packet_t size mismatch"
);

_Static_assert(
    sizeof(gateway_status_packet_t) == 28,
    "gateway_status_packet_t size mismatch"
);


/*
    These assertions protect the current wire format.

    We are deliberately preserving the existing 24-byte packet
    during this cleanup.
*/
_Static_assert(
    sizeof(int) == 4,
    "Mathos wire protocol requires 32-bit int"
);

_Static_assert(
    sizeof(rc_state_t) == 4,
    "rc_state_t size changed"
);

_Static_assert(
    sizeof(rc_packet_t) == 28,
    "rc_packet_t size mismatch"
);