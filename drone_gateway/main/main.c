#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "driver/uart.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "mathos_protocol.h"
#include "mathos_secure.h"
#include "esp_random.h"

// Use the MAVLink headers you generated before.
// If your path is different, change this include.
#include "ardupilotmega/mavlink.h"

static const char *TAG = "DRONE_GATEWAY";

/*
   ============================================================
   CHANGE THESE PINS FOR YOUR ESP32-S3 DRONE GATEWAY BOARD
   ============================================================
*/

// UART from RC link: fiber/RFD receiver into drone ESP32
#define LINK_UART_NUM          UART_NUM_1
#define LINK_UART_TX_PIN       17
#define LINK_UART_RX_PIN       18
#define LINK_UART_BAUD         115200

// UART from drone ESP32 to Flight Controller TELEM port
#define FC_UART_NUM            UART_NUM_2
#define FC_UART_TX_PIN         38
#define FC_UART_RX_PIN         39
#define FC_UART_BAUD           115200

#define RC_PACKET_QUEUE_LEN    1

#define RC_PACKET_TIMEOUT_MS   250
#define MAVLINK_SEND_PERIOD_MS 50
#define HEARTBEAT_PERIOD_MS    1000
#define HEALTH_PERIOD_MS       1000

#define FC_TARGET_SYS_ID       0
#define FC_TARGET_COMP_ID      0

#define GATEWAY_MAV_SYS_ID     255
#define GATEWAY_MAV_COMP_ID    191   // onboard computer style component id

#define SECURITY_CONTROLLER_ID        1
#define SECURITY_PAYLOAD_TYPE_RC      1
#define LINK_RX_BUFFER_SIZE           128

#define GATEWAY_STATUS_TX_PERIOD_MS 200

#define SECURITY_GATEWAY_ID                 2
#define SECURITY_PAYLOAD_TYPE_GATEWAY_STATUS 2
#define GATEWAY_STATUS_LINK_ID              0

#define GATEWAY_ACTION_STATUS_REPEAT_COUNT  5

#define DEBUG_MAVLINK_OVERRIDE_TX      0
#define MAVLINK_OVERRIDE_PRINT_EVERY   100

#define DEBUG_MAVLINK_RELEASE_TX       0
#define MAVLINK_RELEASE_PRINT_EVERY    100

#define FEATURE_DRY_RUN_ARMING          1
#define FEATURE_REAL_MAVLINK_ARMING     1
/*
   ============================================================
   ARM/DISARM MODE

   FEATURE_REAL_MAVLINK_ARMING = 0:
       safe bench mode, gateway only reports dry-run actions.

   FEATURE_REAL_MAVLINK_ARMING = 1:
       gateway sends real MAV_CMD_COMPONENT_ARM_DISARM to FC.

   DO NOT enable real mode with props attached.
   ============================================================
*/

/*
   ============================================================
   BENCH FAILSAFE MODE

   This is for bench testing only.

   If the FC is ARMED and we lose RC / receive FAILSAFE,
   the gateway sends a real DISARM.

   Do NOT use this exact behavior for real flight yet.
   In flight, failsafe should become RTL / LAND / ArduPilot failsafe.
   ============================================================
*/
/*
   ============================================================
   FAILSAFE ACTION MODE

   BENCH_DISARM:
       For bench testing only.
       RC failsafe / RC timeout sends real DISARM.

   FLIGHT_RTL:
       For real flight later.
       RC failsafe / RC timeout requests RTL.
       It does NOT disarm.

   Keep BENCH_DISARM while props are off.
   Do not switch to FLIGHT_RTL until GPS/home/RTL behavior is tested.
   ============================================================
*/
#define GATEWAY_FAILSAFE_ACTION_BENCH_DISARM    1
#define GATEWAY_FAILSAFE_ACTION_FLIGHT_RTL      2

#define GATEWAY_FAILSAFE_ACTION_MODE            GATEWAY_FAILSAFE_ACTION_BENCH_DISARM

#define FEATURE_BENCH_FAILSAFE_REAL_DISARM \
    (GATEWAY_FAILSAFE_ACTION_MODE == GATEWAY_FAILSAFE_ACTION_BENCH_DISARM)

#define GATEWAY_RC_FAILSAFE_DISARM_TIMEOUT_MS   1000
#define GATEWAY_FC_FAILSAFE_DISARM_TIMEOUT_MS   3000

#define GATEWAY_ARM_THROTTLE_MAX        50
#define GATEWAY_ARM_TIMEOUT_MS          5000
#define GATEWAY_DISARM_TIMEOUT_MS       5000
#define GATEWAY_RTL_TIMEOUT_MS                  5000

/*
   RC override works reliably with broadcast target 0/0.
   Real COMMAND_LONG uses the FC sysid/compid learned from heartbeat.
*/
#define FC_COMMAND_TARGET_SYS_ID_FALLBACK   1
#define FC_COMMAND_TARGET_COMP_ID_FALLBACK  1

typedef enum {
    RC_DISARMED = 0,
    RC_ARMED    = 1,
    RC_FAILSAFE = 2,
} rc_state_t;


typedef enum {
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


typedef enum {
    LINK_ID_OPTIC = 0,
    LINK_ID_RF    = 1,
} link_id_t;


typedef struct {
    uint32_t packet_id;
    rc_state_t state;

    int throttle;
    int yaw;
    int pitch;
    int roll;
} rc_packet_t;

typedef struct __attribute__((packed))
{
    uint32_t packet_id;
    uint32_t session_id;

    uint8_t fc_heartbeat_fresh;
    uint8_t fc_is_armed;
    uint8_t remote_state;
    uint8_t gateway_link_ok;
    uint8_t last_action;

    uint8_t reserved[3];

    uint32_t rx_ok_count;
    uint32_t rx_bad_count;
    uint32_t rx_replay_count;
} gateway_status_packet_t;

static QueueHandle_t rc_packet_queue = NULL;

static volatile uint32_t rx_packets = 0;
static volatile uint32_t valid_packets = 0;
static volatile uint32_t bad_packets = 0;
static volatile uint32_t lost_packets = 0;

static volatile uint32_t last_good_packet_id = 0;
static volatile int64_t last_good_packet_time_us = 0;

static volatile int64_t last_fc_heartbeat_us = 0;

static volatile uint8_t fc_is_armed = 0;

static volatile rc_state_t gateway_last_remote_state = RC_DISARMED;
static volatile int64_t gateway_last_remote_packet_time_us = 0;

static volatile uint8_t gateway_last_action = GATEWAY_ACTION_NONE;
static volatile uint8_t gateway_last_action_repeat_remaining = 0;

static uint32_t gateway_status_tx_sequence = 1;
static uint32_t gateway_status_session_id = 1;

static volatile uint32_t replay_packets = 0;
static volatile bool gateway_arm_pending = false;
static volatile bool gateway_disarm_pending = false;
static volatile bool gateway_safety_disarm_latched = false;
static volatile bool gateway_rtl_pending = false;

static volatile int64_t gateway_rtl_command_time_us = 0;
static volatile int64_t gateway_arm_command_time_us = 0;
static volatile int64_t gateway_disarm_command_time_us = 0;

/*
   Learned from real FC heartbeat.
   This is safer than hardcoding command target forever.
*/
static volatile uint8_t fc_seen_sys_id = 0;
static volatile uint8_t fc_seen_comp_id = 0;
/*
   IMPORTANT:
   This checksum function must match the RC controller side.

   If your RC has a slightly different rc_packet_checksum(),
   copy the RC version here exactly.
*/



static int16_t clamp_i16(int16_t value, int16_t min, int16_t max)
{
    if (value < min) return min;
    if (value > max) return max;
    return value;
}

static uint16_t axis_to_pwm(int16_t axis)
{
    axis = clamp_i16(axis, -1000, 1000);

    // -1000 -> 1000 us
    //     0 -> 1500 us
    // +1000 -> 2000 us
    return (uint16_t)(1500 + (axis / 2));
}

static uint16_t throttle_to_pwm(int16_t throttle)
{
    throttle = clamp_i16(throttle, 0, 1000);

    // 0    -> 1000 us
    // 1000 -> 2000 us
    return (uint16_t)(1000 + throttle);
}

static void uart_init_port(
    uart_port_t uart_num,
    int tx_pin,
    int rx_pin,
    int baud_rate
)
{
    const uart_config_t uart_config = {
        .baud_rate = baud_rate,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_driver_install(uart_num, 4096, 4096, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(uart_num, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(uart_num, tx_pin, rx_pin, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
}


static void mavlink_send_message(const mavlink_message_t *msg)
{
    uint8_t buffer[MAVLINK_MAX_PACKET_LEN];
    uint16_t len = mavlink_msg_to_send_buffer(buffer, msg);

    uart_write_bytes(FC_UART_NUM, (const char *)buffer, len);
}

static void send_gateway_heartbeat(void)
{
    mavlink_message_t msg;

    mavlink_msg_heartbeat_pack(
        GATEWAY_MAV_SYS_ID,
        GATEWAY_MAV_COMP_ID,
        &msg,
        MAV_TYPE_ONBOARD_CONTROLLER,
        MAV_AUTOPILOT_INVALID,
        0,
        0,
        MAV_STATE_ACTIVE
    );

    mavlink_send_message(&msg);
}

static void send_rc_override_from_packet(const rc_packet_t *packet)
{
    mavlink_message_t msg;

    uint16_t ch1_roll     = axis_to_pwm(packet->roll);
    uint16_t ch2_pitch    = axis_to_pwm(packet->pitch);
    uint16_t ch3_throttle = throttle_to_pwm(packet->throttle);
    uint16_t ch4_yaw      = axis_to_pwm(packet->yaw);
#if DEBUG_MAVLINK_OVERRIDE_TX
    static uint32_t override_print_counter = 0;

    override_print_counter++;

    if (override_print_counter == 1 ||
        (override_print_counter % MAVLINK_OVERRIDE_PRINT_EVERY) == 0) {
        ESP_LOGI(
            TAG,
            "MAVLINK RC_OVERRIDE TX packet_id=%" PRIu32
            " state=%d raw: roll=%d pitch=%d throttle=%d yaw=%d"
            " pwm: ch1_roll=%u ch2_pitch=%u ch3_throttle=%u ch4_yaw=%u",
            packet->packet_id,
            packet->state,
            packet->roll,
            packet->pitch,
            packet->throttle,
            packet->yaw,
            ch1_roll,
            ch2_pitch,
            ch3_throttle,
            ch4_yaw
        );
    }
#endif
    /*
       For now we do NOT arm/disarm using MAVLink command.
       We only send stick channels.

       Channels 5-18 are ignored.
    */
    uint16_t ignore = UINT16_MAX;

    mavlink_msg_rc_channels_override_pack(
        GATEWAY_MAV_SYS_ID,
        GATEWAY_MAV_COMP_ID,
        &msg,
        FC_TARGET_SYS_ID,
        FC_TARGET_COMP_ID,

        ch1_roll,
        ch2_pitch,
        ch3_throttle,
        ch4_yaw,

        ignore,
        ignore,
        ignore,
        ignore,

        ignore,
        ignore,
        ignore,
        ignore,
        ignore,
        ignore,
        ignore,
        ignore,
        ignore,
        ignore
    );

    mavlink_send_message(&msg);
}

static void send_rc_release(void)
{
    mavlink_message_t msg;

    /*
       For channels 1-8:
       0 means release RC override.
    */
    uint16_t release = 0;
    uint16_t ignore = UINT16_MAX;

#if DEBUG_MAVLINK_RELEASE_TX
    static uint32_t release_print_counter = 0;

    release_print_counter++;

    if (release_print_counter == 1 ||
        (release_print_counter % MAVLINK_RELEASE_PRINT_EVERY) == 0) {
        ESP_LOGI(TAG, "MAVLINK RC_OVERRIDE RELEASE TX");
    }
#endif

    mavlink_msg_rc_channels_override_pack(
        GATEWAY_MAV_SYS_ID,
        GATEWAY_MAV_COMP_ID,
        &msg,
        FC_TARGET_SYS_ID,
        FC_TARGET_COMP_ID,

        release,
        release,
        release,
        release,

        release,
        release,
        release,
        release,

        ignore,
        ignore,
        ignore,
        ignore,
        ignore,
        ignore,
        ignore,
        ignore,
        ignore,
        ignore
    );

    mavlink_send_message(&msg);
}

static uint16_t link_get_u16_le(const uint8_t *buffer)
{
    return ((uint16_t)buffer[0] << 0) |
           ((uint16_t)buffer[1] << 8);
}

static int64_t gateway_remote_link_age_ms(void);
static int64_t gateway_fc_heartbeat_age_ms(void);
static bool gateway_start_real_disarm_for_safety(const char *reason);
static void gateway_failsafe_safety_check(void);
static bool gateway_send_arm_disarm_command(bool arm);
static void gateway_arm_disarm_timeout_check(void);
static const char *gateway_mav_result_to_string(uint8_t result);
static void gateway_process_rc_state_action(const rc_packet_t *packet);
static bool gateway_status_send_once(void);
static const char *rc_state_to_string(rc_state_t state);
static bool gateway_send_rtl_command(void);
static bool gateway_start_rtl_for_safety(const char *reason);
static void gateway_rtl_timeout_check(void);

static void handle_valid_rc_packet(const rc_packet_t *packet, bool new_session)
{
    static uint32_t previous_packet_id = 0;
    static bool have_previous_packet = false;

    if (packet == NULL) {
        return;
    }

    if (new_session) {
        previous_packet_id = 0;
        have_previous_packet = false;

        ESP_LOGI(TAG, "RC packet_id tracker reset for new session");
    }

    rx_packets++;

    if (have_previous_packet) {
        if (packet->packet_id <= previous_packet_id) {
            bad_packets++;

            ESP_LOGW(
                TAG,
                "Old/duplicate RC packet. got=%" PRIu32 ", last=%" PRIu32,
                packet->packet_id,
                previous_packet_id
            );

            return;
        }

        if (packet->packet_id > previous_packet_id + 1) {
            uint32_t missed = packet->packet_id - previous_packet_id - 1;
            lost_packets += missed;

            ESP_LOGW(
                TAG,
                "Lost RC packets: +%" PRIu32 " total=%" PRIu32,
                missed,
                lost_packets
            );
        }
    }

    previous_packet_id = packet->packet_id;
    have_previous_packet = true;

    valid_packets++;
    last_good_packet_id = packet->packet_id;
    last_good_packet_time_us = esp_timer_get_time();

    xQueueOverwrite(rc_packet_queue, packet);

    gateway_last_remote_state = packet->state;
    gateway_last_remote_packet_time_us = last_good_packet_time_us;
    static rc_state_t debug_last_state = RC_DISARMED;
    static bool debug_state_initialized = false;

    if (!debug_state_initialized || debug_last_state != packet->state) {
        ESP_LOGW(
            TAG,
            "RC PACKET STATE CHANGE packet_id=%" PRIu32
            " %s -> %s throttle=%d",
            packet->packet_id,
            debug_state_initialized ? rc_state_to_string(debug_last_state) : "INIT",
            rc_state_to_string(packet->state),
            packet->throttle
        );

        debug_last_state = packet->state;
        debug_state_initialized = true;
    }
    gateway_process_rc_state_action(packet);
}
static bool fc_heartbeat_is_fresh(void)
{
    if (last_fc_heartbeat_us <= 0) {
        return false;
    }

    int64_t now_us = esp_timer_get_time();
    int64_t age_ms = (now_us - last_fc_heartbeat_us) / 1000;

    return age_ms <= 1500;
}
static int64_t gateway_remote_link_age_ms(void)
{
    if (gateway_last_remote_packet_time_us <= 0) {
        return -1;
    }

    int64_t now_us = esp_timer_get_time();

    return (now_us - gateway_last_remote_packet_time_us) / 1000;
}

static int64_t gateway_fc_heartbeat_age_ms(void)
{
    if (last_fc_heartbeat_us <= 0) {
        return -1;
    }

    int64_t now_us = esp_timer_get_time();

    return (now_us - last_fc_heartbeat_us) / 1000;
}
static bool gateway_remote_link_is_fresh(void)
{
    if (gateway_last_remote_packet_time_us <= 0) {
        return false;
    }

    int64_t now_us = esp_timer_get_time();
    int64_t age_ms = (now_us - gateway_last_remote_packet_time_us) / 1000;

    return age_ms <= RC_PACKET_TIMEOUT_MS;
}

static void gateway_action_publish(gateway_action_t action)
{
    gateway_last_action = (uint8_t)action;

    if (action == GATEWAY_ACTION_NONE) {
        gateway_last_action_repeat_remaining = 0;
        return;
    }

    gateway_last_action_repeat_remaining = GATEWAY_ACTION_STATUS_REPEAT_COUNT;
}

static void gateway_action_tick_after_status_send(bool send_ok)
{
    if (!send_ok) {
        return;
    }

    if (gateway_last_action == GATEWAY_ACTION_NONE) {
        return;
    }

    if (gateway_last_action_repeat_remaining > 0) {
        gateway_last_action_repeat_remaining--;
    }

    if (gateway_last_action_repeat_remaining == 0) {
        gateway_last_action = GATEWAY_ACTION_NONE;
    }
}
static const char *gateway_mav_result_to_string(uint8_t result)
{
    switch (result) {
    case MAV_RESULT_ACCEPTED:
        return "ACCEPTED";

    case MAV_RESULT_TEMPORARILY_REJECTED:
        return "TEMPORARILY_REJECTED";

    case MAV_RESULT_DENIED:
        return "DENIED";

    case MAV_RESULT_UNSUPPORTED:
        return "UNSUPPORTED";

    case MAV_RESULT_FAILED:
        return "FAILED";

    case MAV_RESULT_IN_PROGRESS:
        return "IN_PROGRESS";

    case MAV_RESULT_CANCELLED:
        return "CANCELLED";

    default:
        return "UNKNOWN";
    }
}

static const char *gateway_action_to_string(uint8_t action)
{
    switch ((gateway_action_t)action) {
    case GATEWAY_ACTION_NONE:
        return "NONE";

    case GATEWAY_ACTION_ARM_DRY_RUN:
        return "ARM_DRY_RUN";

    case GATEWAY_ACTION_DISARM_DRY_RUN:
        return "DISARM_DRY_RUN";

    case GATEWAY_ACTION_FAILSAFE_DRY_RUN:
        return "FAILSAFE_DRY_RUN";

    case GATEWAY_ACTION_RECOVER_DRY_RUN:
        return "RECOVER_DRY_RUN";

    case GATEWAY_ACTION_ARM_REAL_SENT:
        return "ARM_REAL_SENT";

    case GATEWAY_ACTION_DISARM_REAL_SENT:
        return "DISARM_REAL_SENT";

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

    case GATEWAY_ACTION_RECOVER_CONFIRMED:
        return "RECOVER_CONFIRMED";

    case GATEWAY_ACTION_RTL_SENT:
        return "RTL_SENT";

    case GATEWAY_ACTION_RTL_CONFIRMED:
        return "RTL_CONFIRMED";

    case GATEWAY_ACTION_RTL_DENIED:
        return "RTL_DENIED";

    case GATEWAY_ACTION_RTL_TIMEOUT:
        return "RTL_TIMEOUT";

    default:
        return "UNKNOWN";
    }
}

static const char *rc_state_to_string(rc_state_t state)
{
    switch (state) {
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

static bool gateway_send_arm_disarm_command(bool arm)
{
    mavlink_message_t msg;

    uint8_t target_sys = fc_seen_sys_id;
    uint8_t target_comp = fc_seen_comp_id;

    if (target_sys == 0) {
        target_sys = FC_COMMAND_TARGET_SYS_ID_FALLBACK;
    }

    if (target_comp == 0) {
        target_comp = FC_COMMAND_TARGET_COMP_ID_FALLBACK;
    }

    /*
       MAV_CMD_COMPONENT_ARM_DISARM:
       param1 = 1.0 arm
       param1 = 0.0 disarm

       param2 remains 0.0.
       We are NOT using force-arm magic values.
    */
    mavlink_msg_command_long_pack(
        GATEWAY_MAV_SYS_ID,
        GATEWAY_MAV_COMP_ID,
        &msg,

        target_sys,
        target_comp,

        MAV_CMD_COMPONENT_ARM_DISARM,
        0,

        arm ? 1.0f : 0.0f,
        0.0f,
        0.0f,
        0.0f,
        0.0f,
        0.0f,
        0.0f
    );

    mavlink_send_message(&msg);

    ESP_LOGW(
        TAG,
        "REAL %s COMMAND_LONG sent target_sys=%u target_comp=%u",
        arm ? "ARM" : "DISARM",
        target_sys,
        target_comp
    );

    return true;
}

static bool gateway_send_rtl_command(void)
{
    mavlink_message_t msg;

    uint8_t target_sys = fc_seen_sys_id;
    uint8_t target_comp = fc_seen_comp_id;

    if (target_sys == 0) {
        target_sys = FC_COMMAND_TARGET_SYS_ID_FALLBACK;
    }

    if (target_comp == 0) {
        target_comp = FC_COMMAND_TARGET_COMP_ID_FALLBACK;
    }

    /*
       MAV_CMD_NAV_RETURN_TO_LAUNCH:
       Ask ArduPilot to switch to RTL.

       This is for FLIGHT failsafe mode later.
       Do not use it until RTL behavior is tested in Mission Planner.
    */
    mavlink_msg_command_long_pack(
        GATEWAY_MAV_SYS_ID,
        GATEWAY_MAV_COMP_ID,
        &msg,

        target_sys,
        target_comp,

        MAV_CMD_NAV_RETURN_TO_LAUNCH,
        0,

        0.0f,
        0.0f,
        0.0f,
        0.0f,
        0.0f,
        0.0f,
        0.0f
    );

    mavlink_send_message(&msg);

    ESP_LOGW(
        TAG,
        "REAL RTL COMMAND_LONG sent target_sys=%u target_comp=%u",
        target_sys,
        target_comp
    );

    return true;
}


static bool gateway_start_real_disarm_for_safety(const char *reason)
{
#if FEATURE_REAL_MAVLINK_ARMING && FEATURE_BENCH_FAILSAFE_REAL_DISARM
    if (reason == NULL) {
        reason = "unknown";
    }

    if (!fc_is_armed) {
        ESP_LOGW(
            TAG,
            "SAFETY DISARM skipped: FC already DISARMED reason=%s",
            reason
        );

        gateway_action_publish(GATEWAY_ACTION_DISARM_CONFIRMED);
        gateway_safety_disarm_latched = false;

        return false;
    }

    if (gateway_disarm_pending) {
        ESP_LOGW(
            TAG,
            "SAFETY DISARM already pending reason=%s",
            reason
        );

        return false;
    }

    /*
       Safety disarm has priority over any pending arm command.
    */
    gateway_arm_pending = false;

    gateway_send_arm_disarm_command(false);

    gateway_disarm_pending = true;
    gateway_disarm_command_time_us = esp_timer_get_time();

    gateway_action_publish(GATEWAY_ACTION_DISARM_REAL_SENT);

    ESP_LOGW(
        TAG,
        "SAFETY REAL DISARM requested reason=%s",
        reason
    );

    return true;
#else
    ESP_LOGW(
        TAG,
        "SAFETY DISARM dry/disabled reason=%s",
        reason ? reason : "unknown"
    );

    gateway_action_publish(GATEWAY_ACTION_FAILSAFE_DRY_RUN);

    return false;
#endif
}

static bool gateway_start_rtl_for_safety(const char *reason)
{
#if FEATURE_REAL_MAVLINK_ARMING
    if (reason == NULL) {
        reason = "unknown";
    }

    if (!fc_is_armed) {
        ESP_LOGW(
            TAG,
            "SAFETY RTL skipped: FC already DISARMED reason=%s",
            reason
        );

        gateway_action_publish(GATEWAY_ACTION_DISARM_CONFIRMED);
        gateway_safety_disarm_latched = false;

        return false;
    }

    if (gateway_rtl_pending) {
        ESP_LOGW(
            TAG,
            "SAFETY RTL already pending reason=%s",
            reason
        );

        return false;
    }

    /*
       RTL has priority over normal arm/disarm pending state.
    */
    gateway_arm_pending = false;
    gateway_disarm_pending = false;

    gateway_send_rtl_command();

    gateway_rtl_pending = true;
    gateway_rtl_command_time_us = esp_timer_get_time();

    gateway_action_publish(GATEWAY_ACTION_RTL_SENT);

    ESP_LOGW(
        TAG,
        "SAFETY RTL requested reason=%s",
        reason
    );

    return true;
#else
    ESP_LOGW(
        TAG,
        "SAFETY RTL disabled reason=%s",
        reason ? reason : "unknown"
    );

    gateway_action_publish(GATEWAY_ACTION_FAILSAFE_DRY_RUN);

    return false;
#endif
}


static void gateway_failsafe_safety_check(void)
{
#if FEATURE_REAL_MAVLINK_ARMING
    int64_t rc_age_ms = gateway_remote_link_age_ms();
    int64_t fc_age_ms = gateway_fc_heartbeat_age_ms();

    bool rc_link_lost = false;
    bool fc_heartbeat_lost = false;
    bool rc_requested_failsafe = false;

    if (rc_age_ms >= 0 &&
        rc_age_ms > GATEWAY_RC_FAILSAFE_DISARM_TIMEOUT_MS) {
        rc_link_lost = true;
    }

    if (fc_age_ms >= 0 &&
        fc_age_ms > GATEWAY_FC_FAILSAFE_DISARM_TIMEOUT_MS) {
        fc_heartbeat_lost = true;
    }

    if (gateway_last_remote_state == RC_FAILSAFE) {
        rc_requested_failsafe = true;
    }

    /*
       Once FC is confirmed disarmed, clear the latch.
    */
    if (!fc_is_armed) {
        gateway_safety_disarm_latched = false;
        return;
    }

    /*
       Avoid sending the same emergency disarm again and again.
    */
    if (gateway_safety_disarm_latched) {
        return;
    }

    if (rc_requested_failsafe) {
        gateway_safety_disarm_latched = true;

#if GATEWAY_FAILSAFE_ACTION_MODE == GATEWAY_FAILSAFE_ACTION_BENCH_DISARM
        gateway_start_real_disarm_for_safety(
            "RC state FAILSAFE"
        );
#elif GATEWAY_FAILSAFE_ACTION_MODE == GATEWAY_FAILSAFE_ACTION_FLIGHT_RTL
        gateway_start_rtl_for_safety(
            "FC heartbeat timeout"
        );
#endif

        return;
    }

    if (rc_link_lost) {
        gateway_last_remote_state = RC_FAILSAFE;
        gateway_safety_disarm_latched = true;

#if GATEWAY_FAILSAFE_ACTION_MODE == GATEWAY_FAILSAFE_ACTION_BENCH_DISARM
        gateway_start_real_disarm_for_safety(
            "RC link timeout"
        );
#elif GATEWAY_FAILSAFE_ACTION_MODE == GATEWAY_FAILSAFE_ACTION_FLIGHT_RTL
        gateway_start_rtl_for_safety(
            "RC state FAILSAFE"
        );
#endif

        return;
    }

    if (fc_heartbeat_lost) {
        gateway_safety_disarm_latched = true;

#if GATEWAY_FAILSAFE_ACTION_MODE == GATEWAY_FAILSAFE_ACTION_BENCH_DISARM
        gateway_start_real_disarm_for_safety(
            "RC link timeout"
        );
#elif GATEWAY_FAILSAFE_ACTION_MODE == GATEWAY_FAILSAFE_ACTION_FLIGHT_RTL
        gateway_start_rtl_for_safety(
            "RC state FAILSAFE"
        );
#endif

        return;
    }
#endif
}


static void gateway_rtl_timeout_check(void)
{
#if FEATURE_REAL_MAVLINK_ARMING
    if (!gateway_rtl_pending) {
        return;
    }

    int64_t now_us = esp_timer_get_time();
    int64_t age_ms = (now_us - gateway_rtl_command_time_us) / 1000;

    if (age_ms > GATEWAY_RTL_TIMEOUT_MS) {
        gateway_rtl_pending = false;

        gateway_action_publish(GATEWAY_ACTION_RTL_TIMEOUT);

        ESP_LOGW(
            TAG,
            "REAL RTL timeout after %" PRId64 "ms",
            age_ms
        );
    }
#endif
}


static void gateway_arm_disarm_timeout_check(void)
{
#if FEATURE_REAL_MAVLINK_ARMING
    int64_t now_us = esp_timer_get_time();

    if (gateway_arm_pending) {
        int64_t age_ms = (now_us - gateway_arm_command_time_us) / 1000;

        if (age_ms > GATEWAY_ARM_TIMEOUT_MS) {
            gateway_arm_pending = false;
            gateway_disarm_pending = false;

            gateway_action_publish(GATEWAY_ACTION_ARM_TIMEOUT);

            ESP_LOGW(
                TAG,
                "REAL ARM timeout after %" PRId64 "ms",
                age_ms
            );
        }
    }

    if (gateway_disarm_pending) {
        int64_t age_ms = (now_us - gateway_disarm_command_time_us) / 1000;

        if (age_ms > GATEWAY_DISARM_TIMEOUT_MS) {
            gateway_arm_pending = false;
            gateway_disarm_pending = false;

            gateway_action_publish(GATEWAY_ACTION_DISARM_TIMEOUT);

            ESP_LOGW(
                TAG,
                "REAL DISARM timeout after %" PRId64 "ms",
                age_ms
            );
        }
    }
#endif
}
static void gateway_process_rc_state_action(const rc_packet_t *packet)
{
    static bool initialized = false;
    static rc_state_t previous_state = RC_DISARMED;

    if (packet == NULL) {
        return;
    }

    if (!initialized) {
        previous_state = packet->state;
        initialized = true;
        return;
    }

    if (packet->state == previous_state) {
        return;
    }

    /*
       DISARMED -> ARMED
    */
    if (previous_state == RC_DISARMED && packet->state == RC_ARMED) {

#if FEATURE_REAL_MAVLINK_ARMING
        if (!fc_heartbeat_is_fresh()) {
            gateway_action_publish(GATEWAY_ACTION_ARM_DENIED);

            ESP_LOGW(
                TAG,
                "REAL ARM denied: FC heartbeat not fresh packet_id=%" PRIu32,
                packet->packet_id
            );
        }
        else if (packet->throttle > GATEWAY_ARM_THROTTLE_MAX) {
            gateway_action_publish(GATEWAY_ACTION_ARM_DENIED);

            ESP_LOGW(
                TAG,
                "REAL ARM denied: throttle=%d max=%d packet_id=%" PRIu32,
                packet->throttle,
                GATEWAY_ARM_THROTTLE_MAX,
                packet->packet_id
            );
        }
        else if (fc_is_armed) {
            gateway_action_publish(GATEWAY_ACTION_ARM_CONFIRMED);

            ESP_LOGW(
                TAG,
                "REAL ARM skipped: FC already ARMED packet_id=%" PRIu32,
                packet->packet_id
            );
        }
        else if (gateway_arm_pending || gateway_disarm_pending) {
            gateway_action_publish(GATEWAY_ACTION_ARM_DENIED);

            ESP_LOGW(
                TAG,
                "REAL ARM denied: command already pending packet_id=%" PRIu32,
                packet->packet_id
            );
        }
        else {
            gateway_send_arm_disarm_command(true);

            gateway_arm_pending = true;
            gateway_disarm_pending = false;
            gateway_arm_command_time_us = esp_timer_get_time();

            gateway_action_publish(GATEWAY_ACTION_ARM_REAL_SENT);

            ESP_LOGW(
                TAG,
                "REAL ARM requested: DISARMED -> ARMED packet_id=%" PRIu32,
                packet->packet_id
            );
        }
#else
        gateway_action_publish(GATEWAY_ACTION_ARM_DRY_RUN);

        ESP_LOGI(
            TAG,
            "ARM DRY RUN: DISARMED -> ARMED packet_id=%" PRIu32,
            packet->packet_id
        );
#endif
    }

    /*
       FAILSAFE -> ARMED means recover/resume pilot control.
       It is NOT a real ARM command.
    */
    else if (previous_state == RC_FAILSAFE && packet->state == RC_ARMED) {
        gateway_action_publish(GATEWAY_ACTION_RECOVER_DRY_RUN);

        ESP_LOGI(
            TAG,
            "RECOVER DRY RUN: FAILSAFE -> ARMED packet_id=%" PRIu32,
            packet->packet_id
        );
    }

    /*
       Anything -> DISARMED
    */
    else if (packet->state == RC_DISARMED) {

#if FEATURE_REAL_MAVLINK_ARMING
        if (!fc_heartbeat_is_fresh()) {
            gateway_action_publish(GATEWAY_ACTION_DISARM_DENIED);

            ESP_LOGW(
                TAG,
                "REAL DISARM denied: FC heartbeat not fresh packet_id=%" PRIu32,
                packet->packet_id
            );
        }
        else if (!fc_is_armed) {
            gateway_action_publish(GATEWAY_ACTION_DISARM_CONFIRMED);

            ESP_LOGW(
                TAG,
                "REAL DISARM skipped: FC already DISARMED packet_id=%" PRIu32,
                packet->packet_id
            );
        }
        else if (gateway_arm_pending || gateway_disarm_pending) {
            gateway_action_publish(GATEWAY_ACTION_DISARM_DENIED);

            ESP_LOGW(
                TAG,
                "REAL DISARM denied: command already pending packet_id=%" PRIu32,
                packet->packet_id
            );
        }
        else {
            gateway_send_arm_disarm_command(false);

            gateway_disarm_pending = true;
            gateway_arm_pending = false;
            gateway_disarm_command_time_us = esp_timer_get_time();

            gateway_action_publish(GATEWAY_ACTION_DISARM_REAL_SENT);

            ESP_LOGW(
                TAG,
                "REAL DISARM requested: %s -> DISARMED packet_id=%" PRIu32,
                rc_state_to_string(previous_state),
                packet->packet_id
            );
        }
#else
        gateway_action_publish(GATEWAY_ACTION_DISARM_DRY_RUN);

        ESP_LOGI(
            TAG,
            "DISARM DRY RUN: %s -> DISARMED packet_id=%" PRIu32,
            rc_state_to_string(previous_state),
            packet->packet_id
        );
#endif
    }


    /*
       Anything -> FAILSAFE
    */
    else if (packet->state == RC_FAILSAFE) {

#if FEATURE_REAL_MAVLINK_ARMING
        gateway_action_publish(GATEWAY_ACTION_FAILSAFE_DRY_RUN);

        ESP_LOGW(
            TAG,
            "FAILSAFE received: %s -> FAILSAFE packet_id=%" PRIu32,
            rc_state_to_string(previous_state),
            packet->packet_id
        );

        if (fc_is_armed) {
            gateway_safety_disarm_latched = true;

#if GATEWAY_FAILSAFE_ACTION_MODE == GATEWAY_FAILSAFE_ACTION_BENCH_DISARM
            gateway_start_real_disarm_for_safety(
                "RC state changed to FAILSAFE"
            );
#elif GATEWAY_FAILSAFE_ACTION_MODE == GATEWAY_FAILSAFE_ACTION_FLIGHT_RTL
            gateway_start_rtl_for_safety(
                "RC state changed to FAILSAFE"
            );
#endif
        }
#else
        gateway_action_publish(GATEWAY_ACTION_FAILSAFE_DRY_RUN);

        ESP_LOGI(
            TAG,
            "FAILSAFE DRY RUN: %s -> FAILSAFE packet_id=%" PRIu32,
            rc_state_to_string(previous_state),
            packet->packet_id
        );
#endif
    }

    previous_state = packet->state;
}

static void link_handle_mathos_frame(const uint8_t *frame, size_t frame_len)
{
    bool new_session = false;
    static uint32_t last_sequence = 0;
    static uint32_t last_session_id = 0;
    static bool has_session = false;

    if (frame == NULL || frame_len == 0) {
        return;
    }

    mathos_secure_packet_t packet;

    mathos_status_t decode_status = mathos_wire_decode(
        frame,
        frame_len,
        &packet
    );

    if (decode_status != MATHOS_STATUS_OK) {
        bad_packets++;

        ESP_LOGW(
            TAG,
            "Mathos wire BAD status=%s bad=%" PRIu32 " len=%u",
            mathos_status_to_string(decode_status),
            bad_packets,
            (unsigned int)frame_len
        );

        return;
    }

    mathos_secure_status_t crypto_status = mathos_secure_decrypt_packet(&packet);

    if (crypto_status != MATHOS_SECURE_STATUS_OK) {
        bad_packets++;

        ESP_LOGW(
            TAG,
            "Mathos crypto BAD status=%s bad=%" PRIu32,
            mathos_secure_status_to_string(crypto_status),
            bad_packets
        );

        return;
    }

    if (packet.controller_id != SECURITY_CONTROLLER_ID) {
        bad_packets++;

        ESP_LOGW(
            TAG,
            "Bad controller_id=%u expected=%u",
            packet.controller_id,
            SECURITY_CONTROLLER_ID
        );

        return;
    }

    if (packet.payload_type != SECURITY_PAYLOAD_TYPE_RC) {
        bad_packets++;

        ESP_LOGW(
            TAG,
            "Bad payload_type=%u expected=%u",
            packet.payload_type,
            SECURITY_PAYLOAD_TYPE_RC
        );

        return;
    }

    if (packet.payload_len != sizeof(rc_packet_t)) {
        bad_packets++;

        ESP_LOGW(
            TAG,
            "Bad RC payload_len=%u expected=%u",
            packet.payload_len,
            (unsigned int)sizeof(rc_packet_t)
        );

        return;
    }

    uint32_t session_id = packet.timestamp_ms;

if (!has_session || session_id != last_session_id) {
    ESP_LOGI(
        TAG,
        "New RC session old=0x%08" PRIx32 " new=0x%08" PRIx32,
        last_session_id,
        session_id
    );

    last_session_id = session_id;
    last_sequence = 0;
    has_session = true;
    new_session = true;
}

    if (packet.sequence <= last_sequence) {
        bad_packets++;
        replay_packets++;

        ESP_LOGW(
            TAG,
            "Replay/old secure packet seq=%" PRIu32 " last=%" PRIu32,
            packet.sequence,
            last_sequence
        );

        return;
    }

    last_sequence = packet.sequence;

    rc_packet_t rc_packet;
    memset(&rc_packet, 0, sizeof(rc_packet));
    memcpy(&rc_packet, packet.payload, sizeof(rc_packet));

    handle_valid_rc_packet(&rc_packet, new_session);
}

static void link_process_byte(uint8_t byte)
{
    static uint8_t frame[MATHOS_WIRE_MAX_FRAME_LEN];
    static size_t frame_index = 0;
    static size_t expected_frame_len = 0;

    if (frame_index == 0) {
        if (byte != MATHOS_WIRE_MAGIC_0) {
            return;
        }

        frame[frame_index++] = byte;
        expected_frame_len = 0;
        return;
    }

    if (frame_index == 1) {
        if (byte == MATHOS_WIRE_MAGIC_1) {
            frame[frame_index++] = byte;
            return;
        }

        if (byte == MATHOS_WIRE_MAGIC_0) {
            frame[0] = byte;
            frame_index = 1;
            expected_frame_len = 0;
            return;
        }

        frame_index = 0;
        expected_frame_len = 0;
        return;
    }

    if (frame_index >= sizeof(frame)) {
        frame_index = 0;
        expected_frame_len = 0;
        return;
    }

    frame[frame_index++] = byte;

    if (frame_index == 6) {
        expected_frame_len = link_get_u16_le(&frame[4]);

        if (expected_frame_len < (MATHOS_WIRE_HEADER_LEN + MATHOS_AUTH_TAG_LEN + MATHOS_WIRE_CRC_LEN) ||
            expected_frame_len > MATHOS_WIRE_MAX_FRAME_LEN) {
            ESP_LOGW(
                TAG,
                "Bad Mathos declared frame length=%u",
                (unsigned int)expected_frame_len
            );

            frame_index = 0;
            expected_frame_len = 0;
            return;
        }
    }

    if (expected_frame_len > 0 && frame_index >= expected_frame_len) {
        link_handle_mathos_frame(frame, expected_frame_len);

        frame_index = 0;
        expected_frame_len = 0;
    }
}

static void link_rx_task(void *arg)
{
    uint8_t rx_buffer[LINK_RX_BUFFER_SIZE];

    ESP_LOGI(TAG, "Mathos link RX task started");

    while (true) {
        int len = uart_read_bytes(
            LINK_UART_NUM,
            rx_buffer,
            sizeof(rx_buffer),
            pdMS_TO_TICKS(100)
        );

        if (len <= 0) {
            continue;
        }

        for (int i = 0; i < len; i++) {
            link_process_byte(rx_buffer[i]);
        }
    }
}

static void mavlink_tx_task(void *arg)
{
    rc_packet_t latest_packet;
    bool have_packet = false;
    bool released = true;

    while (true) {
        rc_packet_t packet;

        if (xQueueReceive(rc_packet_queue, &packet, 0) == pdTRUE) {
            latest_packet = packet;
            have_packet = true;
        }

        int64_t now_us = esp_timer_get_time();
        int64_t age_ms = 999999;

        if (last_good_packet_time_us > 0) {
            age_ms = (now_us - last_good_packet_time_us) / 1000;
        }

        if (have_packet &&
            age_ms <= RC_PACKET_TIMEOUT_MS &&
            latest_packet.state == RC_ARMED) {
            send_rc_override_from_packet(&latest_packet);
            released = false;
        } else {
            if (!released) {
                if (!have_packet) {
                    ESP_LOGW(TAG, "No RC packet yet. Releasing RC override.");
                }
                else if (age_ms > RC_PACKET_TIMEOUT_MS) {
                    ESP_LOGW(
                        TAG,
                        "RC packet timeout age=%" PRId64 "ms. Releasing RC override.",
                        (int64_t)age_ms
                    );
                }
                else if (latest_packet.state != RC_ARMED) {
                    ESP_LOGI(
                        TAG,
                        "RC state is %s. Releasing RC override.",
                        rc_state_to_string(latest_packet.state)
                    );
                }
                else {
                    ESP_LOGW(TAG, "RC override released for unknown reason.");
                }

                released = true;
            }

            send_rc_release();
        }

        vTaskDelay(pdMS_TO_TICKS(MAVLINK_SEND_PERIOD_MS));
    }
}

static void heartbeat_task(void *arg)
{
    while (true) {
        send_gateway_heartbeat();
        vTaskDelay(pdMS_TO_TICKS(HEARTBEAT_PERIOD_MS));
    }
}

static void mavlink_rx_task(void *arg)
{
    uint8_t byte;
    mavlink_message_t msg;
    mavlink_status_t status;

    memset(&msg, 0, sizeof(msg));
    memset(&status, 0, sizeof(status));

    while (true) {
        int len = uart_read_bytes(
            FC_UART_NUM,
            &byte,
            1,
            pdMS_TO_TICKS(20)
        );

        if (len <= 0) {
            continue;
        }

        if (!mavlink_parse_char(MAVLINK_COMM_0, byte, &msg, &status)) {
            continue;
        }

        if (msg.msgid == MAVLINK_MSG_ID_HEARTBEAT) {
            mavlink_heartbeat_t heartbeat;
            mavlink_msg_heartbeat_decode(&msg, &heartbeat);

            /*
               Ignore our own gateway heartbeat if it ever loops back.
               We only care about real FC/autopilot heartbeat.
            */
            if (msg.sysid == GATEWAY_MAV_SYS_ID &&
                msg.compid == GATEWAY_MAV_COMP_ID) {
                continue;
            }

            if (heartbeat.autopilot == MAV_AUTOPILOT_INVALID) {
                continue;
            }

            last_fc_heartbeat_us = esp_timer_get_time();

            fc_seen_sys_id = msg.sysid;
            fc_seen_comp_id = msg.compid;

            fc_is_armed = (heartbeat.base_mode & MAV_MODE_FLAG_SAFETY_ARMED) ? 1 : 0;

#if FEATURE_REAL_MAVLINK_ARMING
            if (fc_is_armed && gateway_arm_pending) {
                gateway_arm_pending = false;
                gateway_disarm_pending = false;

                gateway_action_publish(GATEWAY_ACTION_ARM_CONFIRMED);

                ESP_LOGW(TAG, "REAL ARM confirmed by FC heartbeat");
            }

            if (!fc_is_armed && gateway_disarm_pending) {
                gateway_arm_pending = false;
                gateway_disarm_pending = false;

                gateway_action_publish(GATEWAY_ACTION_DISARM_CONFIRMED);

                ESP_LOGW(TAG, "REAL DISARM confirmed by FC heartbeat");
            }
#endif
        }
        else if (msg.msgid == MAVLINK_MSG_ID_COMMAND_ACK) {
            mavlink_command_ack_t ack;
            mavlink_msg_command_ack_decode(&msg, &ack);

            if (ack.command == MAV_CMD_COMPONENT_ARM_DISARM) {
                ESP_LOGW(
                    TAG,
                    "FC COMMAND_ACK ARM_DISARM result=%s raw=%u",
                    gateway_mav_result_to_string(ack.result),
                    ack.result
                );

#if FEATURE_REAL_MAVLINK_ARMING
                if (ack.result == MAV_RESULT_ACCEPTED ||
                    ack.result == MAV_RESULT_IN_PROGRESS) {
                    /*
                       Do not mark confirmed from ACK alone.
                       We wait for FC heartbeat armed flag.
                    */
                }
                else {
                    if (gateway_arm_pending) {
                        gateway_action_publish(GATEWAY_ACTION_ARM_DENIED);
                    }
                    else if (gateway_disarm_pending) {
                        gateway_action_publish(GATEWAY_ACTION_DISARM_DENIED);
                    }

                    gateway_arm_pending = false;
                    gateway_disarm_pending = false;
                }
#endif
            }


            if (ack.command == MAV_CMD_NAV_RETURN_TO_LAUNCH) {
                ESP_LOGW(
                    TAG,
                    "FC COMMAND_ACK RTL result=%s raw=%u",
                    gateway_mav_result_to_string(ack.result),
                    ack.result
                );

            #if FEATURE_REAL_MAVLINK_ARMING
                if (ack.result == MAV_RESULT_ACCEPTED ||
                    ack.result == MAV_RESULT_IN_PROGRESS) {
                    gateway_action_publish(GATEWAY_ACTION_RTL_CONFIRMED);
                    gateway_rtl_pending = false;

                    ESP_LOGW(TAG, "REAL RTL accepted by FC");
                }
                else {
                    gateway_action_publish(GATEWAY_ACTION_RTL_DENIED);
                    gateway_rtl_pending = false;

                    ESP_LOGW(TAG, "REAL RTL denied by FC");
                }
            #endif
            }


        }
    }
}
static void gateway_status_tx_task(void *arg)
{
    uint32_t print_counter = 0;

    ESP_LOGI(TAG, "Gateway status TX task started");

    while (true) {
        bool ok = gateway_status_send_once();

        gateway_action_tick_after_status_send(ok);
        gateway_arm_disarm_timeout_check();
        gateway_rtl_timeout_check();
        gateway_failsafe_safety_check();
        print_counter++;

        if (print_counter == 1 || (print_counter % 10) == 0) {
            ESP_LOGI(
                TAG,
                "Gateway status TX %s fc_fresh=%u fc=%s remote=%s link=%u action=%s ok=%" PRIu32 " bad=%" PRIu32 " replay=%" PRIu32,
                ok ? "OK" : "FAILED",
                fc_heartbeat_is_fresh() ? 1 : 0,
                fc_is_armed ? "ARMED" : "DISARMED",
                rc_state_to_string(gateway_last_remote_state),
                gateway_remote_link_is_fresh() ? 1 : 0,
                gateway_action_to_string(gateway_last_action),
                valid_packets,
                bad_packets,
                replay_packets
            );
        }

        vTaskDelay(pdMS_TO_TICKS(GATEWAY_STATUS_TX_PERIOD_MS));
    }
}
static bool gateway_status_send_once(void)
{
    gateway_status_packet_t status;
    memset(&status, 0, sizeof(status));

    uint32_t seq = gateway_status_tx_sequence++;

    status.packet_id = seq;
    status.session_id = gateway_status_session_id;

    status.fc_heartbeat_fresh = fc_heartbeat_is_fresh() ? 1 : 0;
    status.fc_is_armed = fc_is_armed ? 1 : 0;
    status.remote_state = (uint8_t)gateway_last_remote_state;
    status.gateway_link_ok = gateway_remote_link_is_fresh() ? 1 : 0;
    status.last_action = gateway_last_action;

    status.rx_ok_count = valid_packets;
    status.rx_bad_count = bad_packets;
    status.rx_replay_count = replay_packets;

    mathos_secure_packet_t packet;
    memset(&packet, 0, sizeof(packet));

    packet.sequence = seq;
    packet.timestamp_ms = gateway_status_session_id;

    packet.controller_id = SECURITY_GATEWAY_ID;
    packet.link_id = GATEWAY_STATUS_LINK_ID;
    packet.payload_type = SECURITY_PAYLOAD_TYPE_GATEWAY_STATUS;
    packet.payload_len = sizeof(gateway_status_packet_t);

    if (packet.payload_len > MATHOS_PAYLOAD_MAX_LEN) {
        ESP_LOGE(
            TAG,
            "Gateway status payload too large: %u max=%u",
            packet.payload_len,
            MATHOS_PAYLOAD_MAX_LEN
        );
        return false;
    }

    memcpy(packet.payload, &status, sizeof(status));

    mathos_secure_status_t crypto_status = mathos_secure_encrypt_packet(&packet);

    if (crypto_status != MATHOS_SECURE_STATUS_OK) {
        ESP_LOGW(
            TAG,
            "Gateway status encrypt failed: %s",
            mathos_secure_status_to_string(crypto_status)
        );
        return false;
    }

    uint8_t wire_frame[MATHOS_WIRE_MAX_FRAME_LEN];
    size_t wire_frame_len = 0;

    mathos_status_t encode_status = mathos_wire_encode(
        &packet,
        wire_frame,
        sizeof(wire_frame),
        &wire_frame_len
    );

    if (encode_status != MATHOS_STATUS_OK) {
        ESP_LOGW(
            TAG,
            "Gateway status encode failed: %s",
            mathos_status_to_string(encode_status)
        );
        return false;
    }

    int written = uart_write_bytes(
        LINK_UART_NUM,
        (const char *)wire_frame,
        wire_frame_len
    );

    return written == wire_frame_len;
}
static void health_task(void *arg)
{
    while (true) {
        int64_t now_us = esp_timer_get_time();

        int64_t rc_age_ms = -1;
        if (last_good_packet_time_us > 0) {
            rc_age_ms = (now_us - last_good_packet_time_us) / 1000;
        }

        int64_t fc_hb_age_ms = -1;
        if (last_fc_heartbeat_us > 0) {
            fc_hb_age_ms = (now_us - last_fc_heartbeat_us) / 1000;
        }

        ESP_LOGI(
            TAG,
            "rx=%" PRIu32 " valid=%" PRIu32 " bad=%" PRIu32
            " lost=%" PRIu32 " last_id=%" PRIu32
            " rc_age=%lldms fc_hb_age=%lldms",
            rx_packets,
            valid_packets,
            bad_packets,
            lost_packets,
            last_good_packet_id,
            rc_age_ms,
            fc_hb_age_ms
        );

        vTaskDelay(pdMS_TO_TICKS(HEALTH_PERIOD_MS));
    }
}

void app_main(void)
{
    gateway_status_session_id = esp_random();
    if (gateway_status_session_id == 0) {
    gateway_status_session_id = 1;
}

ESP_LOGI(
    TAG,
    "Gateway status session_id=0x%08" PRIx32,
    gateway_status_session_id
);
    ESP_LOGI(TAG, "Starting drone-side gateway");

    rc_packet_queue = xQueueCreate(RC_PACKET_QUEUE_LEN, sizeof(rc_packet_t));

    if (rc_packet_queue == NULL) {
        ESP_LOGE(TAG, "Failed to create rc_packet_queue");
        return;
    }

    uart_init_port(
        LINK_UART_NUM,
        LINK_UART_TX_PIN,
        LINK_UART_RX_PIN,
        LINK_UART_BAUD
    );

    uart_init_port(
        FC_UART_NUM,
        FC_UART_TX_PIN,
        FC_UART_RX_PIN,
        FC_UART_BAUD
    );

    xTaskCreate(link_rx_task, "link_rx_task", 4096, NULL, 10, NULL);
    xTaskCreate(mavlink_tx_task, "mavlink_tx_task", 4096, NULL, 9, NULL);
    xTaskCreate(heartbeat_task, "heartbeat_task", 3072, NULL, 5, NULL);
    xTaskCreate(mavlink_rx_task, "mavlink_rx_task", 4096, NULL, 6, NULL);
    xTaskCreate(health_task, "health_task", 4096, NULL, 4, NULL);
    xTaskCreate(gateway_status_tx_task, "gateway_status_tx_task", 4096, NULL, 5, NULL);
    ESP_LOGI(TAG, "Drone gateway started");
}