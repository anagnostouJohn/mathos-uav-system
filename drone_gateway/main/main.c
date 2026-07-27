#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"

#include "driver/uart.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "mathos_protocol.h"
#include "mathos_secure.h"
#include "esp_random.h"


// Use the MAVLink headers you generated before.
// If your path is different, change this include.
#include "ardupilotmega/mavlink.h"
#include "mathos_messages.h"
#include "mathos_flight_modes.h"

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
/*
   ============================================================
   MAVLink telemetry stream requests

   Gateway asks ArduPilot to send useful telemetry messages.
   This does not affect ARM/DISARM/failsafe.
   ============================================================
*/
#define TELEMETRY_REQUEST_REPEAT_MS          10000
#define TELEMETRY_REQUEST_FAST_INTERVAL_US   200000    // 5 Hz
#define TELEMETRY_REQUEST_MED_INTERVAL_US    500000    // 2 Hz
#define TELEMETRY_REQUEST_SLOW_INTERVAL_US   1000000   // 1 Hz
#define TELEMETRY_REQUEST_ROUNDS             3
#define FC_TARGET_SYS_ID       0
#define FC_TARGET_COMP_ID      0

#define GATEWAY_MAV_SYS_ID     255
#define GATEWAY_MAV_COMP_ID    191   // onboard computer style component id

#define LINK_RX_BUFFER_SIZE           128

#define GATEWAY_STATUS_TX_PERIOD_MS 200
#define GATEWAY_TELEMETRY_TX_PERIOD_MS 200
#define GATEWAY_TELEMETRY_FRESH_MS 1500

#define GATEWAY_STATUS_LINK_ID              0

#define GATEWAY_ACTION_STATUS_REPEAT_COUNT  5

#define DEBUG_MAVLINK_OVERRIDE_TX      0
#define MAVLINK_OVERRIDE_PRINT_EVERY   100

#define DEBUG_MAVLINK_RELEASE_TX       0
#define MAVLINK_RELEASE_PRINT_EVERY    100

#define FEATURE_DRY_RUN_ARMING          1
#define FEATURE_REAL_MAVLINK_ARMING     1
#define GATEWAY_RC_SESSION_HISTORY_LEN 16
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
#define GATEWAY_RTL_TIMEOUT_MS          5000
#define GATEWAY_SESSION_RECOVERY_HOLD_MS 3000
/*
   ArduPlane / QuadPlane custom_mode values used for
   positive RTL confirmation.

   RTL  = fixed-wing return
   QRTL = QuadPlane VTOL return
*/
/*
   RC override works reliably with broadcast target 0/0.
   Real COMMAND_LONG uses the FC sysid/compid learned from heartbeat.
*/
#define FC_COMMAND_TARGET_SYS_ID_FALLBACK   1
#define FC_COMMAND_TARGET_COMP_ID_FALLBACK  1

static QueueHandle_t rc_packet_queue = NULL;
static SemaphoreHandle_t mavlink_tx_mutex = NULL;
static volatile uint32_t rx_packets = 0;
static volatile uint32_t valid_packets = 0;
static volatile uint32_t bad_packets = 0;
static volatile uint32_t lost_packets = 0;
static volatile uint32_t last_good_packet_id = 0;
static volatile int64_t last_good_packet_time_us = 0;
static volatile int64_t last_fc_heartbeat_us = 0;
static volatile uint8_t fc_is_armed = 0;

/*
   ArduPilot flight mode reported in HEARTBEAT.custom_mode.

   We will use this later to confirm that RTL was
   actually entered, rather than trusting COMMAND_ACK alone.
*/
static volatile uint32_t fc_custom_mode = 0;
static volatile uint8_t fc_vehicle_type = MAV_TYPE_GENERIC;
static volatile rc_state_t gateway_last_remote_state = RC_DISARMED;
static volatile int64_t gateway_last_remote_packet_time_us = 0;
static volatile uint8_t gateway_last_action = GATEWAY_ACTION_NONE;
static volatile uint8_t gateway_last_action_repeat_remaining = 0;
static portMUX_TYPE gateway_action_mux = portMUX_INITIALIZER_UNLOCKED;
static uint32_t gateway_status_tx_sequence = 1;
static uint32_t gateway_status_session_id = 1;
static volatile uint32_t replay_packets = 0;
static uint32_t gateway_rc_session_history[ GATEWAY_RC_SESSION_HISTORY_LEN ] = {0};

static uint8_t gateway_rc_session_history_count = 0;

static uint8_t gateway_rc_session_history_next = 0;
static portMUX_TYPE gateway_command_state_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile bool gateway_arm_pending = false;
static volatile bool gateway_disarm_pending = false;
static volatile bool gateway_safety_disarm_latched = false;
static volatile bool gateway_session_recovery_required = false;
static volatile bool gateway_rtl_pending = false;
static volatile int64_t gateway_session_recovery_disarmed_since_us = 0;
static volatile int64_t gateway_rtl_command_time_us = 0;
static volatile int64_t gateway_arm_command_time_us = 0;
static volatile int64_t gateway_disarm_command_time_us = 0;
static volatile uint8_t fc_seen_sys_id = 0;
static volatile uint8_t fc_seen_comp_id = 0;

static portMUX_TYPE fc_telemetry_mux =  portMUX_INITIALIZER_UNLOCKED;
static volatile bool fc_tel_sys_status_seen = false;
static volatile bool fc_tel_gps_seen = false;
static volatile bool fc_tel_position_seen = false;
static volatile bool fc_tel_attitude_seen = false;
static volatile bool fc_tel_vfr_hud_seen = false;

static volatile int64_t fc_tel_battery_update_us = 0;
static volatile int64_t fc_tel_gps_update_us = 0;
static volatile int64_t fc_tel_position_update_us = 0;
static volatile int64_t fc_tel_attitude_update_us = 0;
static volatile int64_t fc_tel_ekf_update_us = 0;
static volatile int64_t fc_tel_airspeed_update_us = 0;
static volatile uint8_t fc_tel_system_status = 0;

static volatile uint16_t fc_tel_battery_voltage_mv = 0;
static volatile int16_t fc_tel_battery_current_ca = -1;
static volatile int8_t fc_tel_battery_remaining = -1;

static volatile uint8_t fc_tel_gps_fix_type = 0;
static volatile uint8_t fc_tel_satellites_visible = 0;
static volatile int32_t fc_tel_lat = 0;
static volatile int32_t fc_tel_lon = 0;

static volatile int32_t fc_tel_gps_alt_mm = 0;
static volatile int32_t fc_tel_global_alt_mm = 0;

static volatile int32_t fc_tel_relative_alt_mm = 0;

static volatile float fc_tel_roll_rad = 0.0f;
static volatile float fc_tel_pitch_rad = 0.0f;
static volatile float fc_tel_yaw_rad = 0.0f;
static volatile float fc_tel_airspeed_mps = 0.0f;
static volatile uint16_t fc_tel_ekf_flags = 0;


typedef struct
{
    bool arm_pending;
    bool disarm_pending;
    bool rtl_pending;

    int64_t arm_command_time_us;
    int64_t disarm_command_time_us;
    int64_t rtl_command_time_us;
} gateway_command_state_snapshot_t;


static gateway_command_state_snapshot_t
gateway_command_state_get_snapshot(void)
{
    gateway_command_state_snapshot_t snapshot;

    taskENTER_CRITICAL(
        &gateway_command_state_mux);

    snapshot.arm_pending =
        gateway_arm_pending;

    snapshot.disarm_pending =
        gateway_disarm_pending;

    snapshot.rtl_pending =
        gateway_rtl_pending;

    snapshot.arm_command_time_us =
        gateway_arm_command_time_us;

    snapshot.disarm_command_time_us =
        gateway_disarm_command_time_us;

    snapshot.rtl_command_time_us =
        gateway_rtl_command_time_us;

    taskEXIT_CRITICAL(
        &gateway_command_state_mux);

    return snapshot;
}

static bool gateway_command_state_try_start_arm(void)
{
    bool started = false;
    int64_t now_us = esp_timer_get_time();

    taskENTER_CRITICAL(
        &gateway_command_state_mux);

    /*
       Only one FC command may be pending at a time.

       The check and state update happen under the same lock,
       preventing another task from starting DISARM or RTL
       between them.
    */
    if (!gateway_arm_pending &&
        !gateway_disarm_pending &&
        !gateway_rtl_pending) {

        gateway_arm_pending = true;
        gateway_arm_command_time_us = now_us;

        started = true;
    }

    taskEXIT_CRITICAL(
        &gateway_command_state_mux);

    return started;
}

static bool gateway_command_state_try_start_disarm(bool *cancelled_arm)
{
    bool started = false;
    bool arm_was_pending = false;
    int64_t now_us = esp_timer_get_time();

    taskENTER_CRITICAL(
        &gateway_command_state_mux);

    /*
       DISARM may cancel a pending ARM operation.

       It must not replace an existing DISARM or RTL
       operation.
    */
    if (!gateway_disarm_pending &&
        !gateway_rtl_pending) {

        arm_was_pending =
            gateway_arm_pending;

        gateway_arm_pending = false;
        gateway_disarm_pending = true;
        gateway_disarm_command_time_us =
            now_us;

        started = true;
    }

    taskEXIT_CRITICAL(
        &gateway_command_state_mux);

    if (cancelled_arm != NULL) {
        *cancelled_arm =
            arm_was_pending;
    }

    return started;
}
static bool gateway_command_state_try_start_rtl(
    bool *cancelled_arm,
    bool *cancelled_disarm)
{
    bool started = false;
    bool arm_was_pending = false;
    bool disarm_was_pending = false;

    int64_t now_us =
        esp_timer_get_time();

    taskENTER_CRITICAL(
        &gateway_command_state_mux);

    /*
       Safety RTL has priority over normal ARM and DISARM.

       All pending-state changes happen atomically.
    */
    if (!gateway_rtl_pending) {
        arm_was_pending =
            gateway_arm_pending;

        disarm_was_pending =
            gateway_disarm_pending;

        gateway_arm_pending = false;
        gateway_disarm_pending = false;

        gateway_rtl_pending = true;
        gateway_rtl_command_time_us =
            now_us;

        started = true;
    }

    taskEXIT_CRITICAL(
        &gateway_command_state_mux);

    if (cancelled_arm != NULL) {
        *cancelled_arm =
            arm_was_pending;
    }

    if (cancelled_disarm != NULL) {
        *cancelled_disarm =
            disarm_was_pending;
    }

    return started;
}

static bool gateway_command_state_confirm_arm(void)
{
    bool confirmed = false;

    taskENTER_CRITICAL(
        &gateway_command_state_mux);

    /*
       Confirm ARM only when ARM is still the active
       pending operation.
    */
    if (gateway_arm_pending &&
        !gateway_disarm_pending &&
        !gateway_rtl_pending) {

        gateway_arm_pending = false;
        gateway_arm_command_time_us = 0;

        confirmed = true;
    }

    taskEXIT_CRITICAL(
        &gateway_command_state_mux);

    return confirmed;
}

static bool gateway_command_state_confirm_disarm(void)
{
    bool confirmed = false;

    taskENTER_CRITICAL(
        &gateway_command_state_mux);

    if (gateway_disarm_pending) {
        gateway_arm_pending = false;
        gateway_disarm_pending = false;

        gateway_arm_command_time_us = 0;
        gateway_disarm_command_time_us = 0;

        confirmed = true;
    }

    taskEXIT_CRITICAL(
        &gateway_command_state_mux);

    return confirmed;
}

static bool gateway_command_state_confirm_rtl(void)
{
    bool confirmed = false;

    taskENTER_CRITICAL(
        &gateway_command_state_mux);

    if (gateway_rtl_pending) {
        gateway_rtl_pending = false;
        gateway_rtl_command_time_us = 0;

        confirmed = true;
    }

    taskEXIT_CRITICAL(
        &gateway_command_state_mux);

    return confirmed;
}
static bool gateway_command_state_reject_rtl(void)
{
    bool rejected = false;

    taskENTER_CRITICAL(
        &gateway_command_state_mux);

    if (gateway_rtl_pending) {
        gateway_rtl_pending = false;
        gateway_rtl_command_time_us = 0;

        rejected = true;
    }

    taskEXIT_CRITICAL(
        &gateway_command_state_mux);

    return rejected;
}

static bool gateway_command_state_timeout_arm(
    int64_t now_us,
    int64_t *age_ms_out)
{
    bool timed_out = false;
    int64_t age_ms = 0;

    taskENTER_CRITICAL(
        &gateway_command_state_mux);

    if (gateway_arm_pending &&
        gateway_arm_command_time_us > 0) {

        age_ms =
            (now_us -
             gateway_arm_command_time_us) /
            1000;

        if (age_ms >= GATEWAY_ARM_TIMEOUT_MS) {
            gateway_arm_pending = false;
            gateway_arm_command_time_us = 0;

            timed_out = true;
        }
    }

    taskEXIT_CRITICAL(
        &gateway_command_state_mux);

    if (age_ms_out != NULL) {
        *age_ms_out = age_ms;
    }

    return timed_out;
}

static bool gateway_command_state_timeout_disarm(
    int64_t now_us,
    int64_t *age_ms_out)
{
    bool timed_out = false;
    int64_t age_ms = 0;

    taskENTER_CRITICAL(
        &gateway_command_state_mux);

    if (gateway_disarm_pending &&
        gateway_disarm_command_time_us > 0) {

        age_ms =
            (now_us -
             gateway_disarm_command_time_us) /
            1000;

        if (age_ms >=
            GATEWAY_DISARM_TIMEOUT_MS) {

            gateway_disarm_pending = false;
            gateway_disarm_command_time_us = 0;

            timed_out = true;
        }
    }

    taskEXIT_CRITICAL(
        &gateway_command_state_mux);

    if (age_ms_out != NULL) {
        *age_ms_out = age_ms;
    }

    return timed_out;
}

static bool gateway_command_state_timeout_rtl(
    int64_t now_us,
    int64_t *age_ms_out)
{
    bool timed_out = false;
    int64_t age_ms = 0;

    taskENTER_CRITICAL(
        &gateway_command_state_mux);

    if (gateway_rtl_pending &&
        gateway_rtl_command_time_us > 0) {

        age_ms =
            (now_us -
             gateway_rtl_command_time_us) /
            1000;

        if (age_ms >= GATEWAY_RTL_TIMEOUT_MS) {
            gateway_rtl_pending = false;
            gateway_rtl_command_time_us = 0;

            timed_out = true;
        }
    }

    taskEXIT_CRITICAL(
        &gateway_command_state_mux);

    if (age_ms_out != NULL) {
        *age_ms_out = age_ms;
    }

    return timed_out;
}


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


static void mavlink_send_message(
    const mavlink_message_t *msg)
{
    if (msg == NULL) {
        return;
    }

    if (mavlink_tx_mutex == NULL) {
        ESP_LOGE(
            TAG,
            "MAVLink TX rejected: mutex not initialized"
        );

        return;
    }

    /*
       Only one gateway task may construct and queue a complete
       MAVLink frame at a time.
    */
    if (xSemaphoreTake(
            mavlink_tx_mutex,
            pdMS_TO_TICKS(100)) != pdTRUE) {

        ESP_LOGE(
            TAG,
            "MAVLink TX mutex timeout msgid=%" PRIu32,
            msg->msgid
        );

        return;
    }

    uint8_t buffer[MAVLINK_MAX_PACKET_LEN];

    uint16_t len =
        mavlink_msg_to_send_buffer(
            buffer,
            msg);

    int written =
        uart_write_bytes(
            FC_UART_NUM,
            (const char *)buffer,
            len);

    xSemaphoreGive(
        mavlink_tx_mutex);

    if (written != len) {
        ESP_LOGE(
            TAG,
            "MAVLink TX incomplete msgid=%" PRIu32
            " written=%d expected=%u",
            msg->msgid,
            written,
            len
        );
    }
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





static int64_t gateway_remote_link_age_ms(void);
static int64_t gateway_fc_heartbeat_age_ms(void);
static bool gateway_start_real_disarm_for_safety(const char *reason);
static void gateway_failsafe_safety_check(void);
static bool gateway_send_arm_disarm_command(bool arm);
static void gateway_arm_disarm_timeout_check(void);
static void gateway_process_rc_state_action(const rc_packet_t *packet,bool new_session);
static void gateway_session_recovery_check(const rc_packet_t *packet);
static bool gateway_status_send_once(void);
static bool gateway_telemetry_send_once(void);
static bool gateway_send_rtl_command(void);
static bool gateway_start_rtl_for_safety(const char *reason);
static void gateway_rtl_timeout_check(void);
static void gateway_print_fc_telemetry(void);
static bool gateway_send_message_interval_request(
    uint32_t message_id,
    int32_t interval_us,
    const char *name
);

static void gateway_request_telemetry_streams_once(void);
static void telemetry_request_task(void *arg);

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
            debug_state_initialized ? mathos_rc_state_to_string(debug_last_state) : "INIT",
            mathos_rc_state_to_string(packet->state),
            packet->throttle
        );

        debug_last_state = packet->state;
        debug_state_initialized = true;
    }

        gateway_process_rc_state_action(
            packet,
            new_session);

        gateway_session_recovery_check(
            packet);

        xQueueOverwrite(
            rc_packet_queue,
            packet);
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
static void gateway_session_recovery_check(
    const rc_packet_t *packet)
{
    if (packet == NULL) {
        return;
    }

    /*
       No recovery lock exists. Keep the timer reset.
    */
    if (!gateway_session_recovery_required) {
        gateway_session_recovery_disarmed_since_us = 0;
        return;
    }

    /*
       Every required safety condition must remain true
       continuously for the complete hold period.
    */
    bool safe_for_recovery =
        packet->state == RC_DISARMED &&
        packet->throttle <= GATEWAY_ARM_THROTTLE_MAX &&
        fc_heartbeat_is_fresh() &&
        !fc_is_armed &&
        !gateway_arm_pending &&
        !gateway_disarm_pending &&
        !gateway_rtl_pending;

    if (!safe_for_recovery) {
        if (gateway_session_recovery_disarmed_since_us != 0) {
            ESP_LOGW(
                TAG,
                "RC SESSION RECOVERY hold reset "
                "state=%s throttle=%d fc_fresh=%u "
                "fc=%s arm_pending=%u "
                "disarm_pending=%u rtl_pending=%u",
                mathos_rc_state_to_string(
                    packet->state),
                packet->throttle,
                fc_heartbeat_is_fresh() ? 1 : 0,
                fc_is_armed
                    ? "ARMED"
                    : "DISARMED",
                gateway_arm_pending ? 1 : 0,
                gateway_disarm_pending ? 1 : 0,
                gateway_rtl_pending ? 1 : 0
            );
        }

        gateway_session_recovery_disarmed_since_us = 0;
        return;
    }

    int64_t now_us = esp_timer_get_time();

    /*
       Start the continuous DISARMED observation period.
    */
    if (gateway_session_recovery_disarmed_since_us == 0) {
        gateway_session_recovery_disarmed_since_us =
            now_us;

        ESP_LOGW(
            TAG,
            "RC SESSION RECOVERY hold started "
            "required_ms=%u",
            (unsigned int)
                GATEWAY_SESSION_RECOVERY_HOLD_MS
        );

        return;
    }

    int64_t held_ms =
        (now_us -
         gateway_session_recovery_disarmed_since_us) /
        1000;

    if (held_ms <
        GATEWAY_SESSION_RECOVERY_HOLD_MS) {
        return;
    }

    /*
       Recovery conditions remained continuously valid for
       the complete hold period. Restore control authority.
    */
    gateway_session_recovery_required = false;
    gateway_session_recovery_disarmed_since_us = 0;

    ESP_LOGW(
        TAG,
        "RC SESSION RECOVERY CLEARED "
        "held_ms=%" PRId64
        " fc=DISARMED remote=DISARMED",
        held_ms
    );
}
static void gateway_action_publish(
    gateway_action_t action)
{
    taskENTER_CRITICAL(
        &gateway_action_mux);

    gateway_last_action =
        (uint8_t)action;

    if (action == GATEWAY_ACTION_NONE) {
        gateway_last_action_repeat_remaining = 0;
    }
    else {
        gateway_last_action_repeat_remaining =
            GATEWAY_ACTION_STATUS_REPEAT_COUNT;
    }

    taskEXIT_CRITICAL(
        &gateway_action_mux);
}

static void gateway_action_tick_after_status_send(
    bool send_ok)
{
    if (!send_ok) {
        return;
    }

    taskENTER_CRITICAL(
        &gateway_action_mux);

    if (gateway_last_action ==
        GATEWAY_ACTION_NONE) {

        taskEXIT_CRITICAL(
            &gateway_action_mux);

        return;
    }

    if (gateway_last_action_repeat_remaining > 0) {
        gateway_last_action_repeat_remaining--;
    }

    if (gateway_last_action_repeat_remaining == 0) {
        gateway_last_action =
            GATEWAY_ACTION_NONE;
    }

    taskEXIT_CRITICAL(
        &gateway_action_mux);
}

static gateway_action_t gateway_action_get(void)
{
    uint8_t action;

    taskENTER_CRITICAL(
        &gateway_action_mux);

    action = gateway_last_action;

    taskEXIT_CRITICAL(
        &gateway_action_mux);

    return (gateway_action_t)action;
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


static bool gateway_start_real_disarm_for_safety(
    const char *reason)
{
#if FEATURE_REAL_MAVLINK_ARMING && \
    FEATURE_BENCH_FAILSAFE_REAL_DISARM

    if (reason == NULL) {
        reason = "unknown";
    }

    gateway_command_state_snapshot_t command_state =
        gateway_command_state_get_snapshot();

    /*
       The FC is already DISARMED and no delayed ARM command
       exists. There is nothing left to cancel.
    */
    if (!fc_is_armed &&
        !command_state.arm_pending) {

        ESP_LOGW(
            TAG,
            "SAFETY DISARM skipped: FC already DISARMED "
            "reason=%s",
            reason
        );

        gateway_action_publish(
            GATEWAY_ACTION_DISARM_CONFIRMED);

        gateway_safety_disarm_latched = false;

        return false;
    }

    /*
       A safety DISARM is already waiting for heartbeat
       confirmation.
    */
    if (command_state.disarm_pending) {
        ESP_LOGW(
            TAG,
            "SAFETY DISARM already pending reason=%s",
            reason
        );

        return false;
    }

    bool cancelled_arm = false;

    /*
       Atomically cancel a pending ARM and reserve DISARM.

       This also handles the case where the latest heartbeat
       still reports DISARMED but an earlier ARM command may
       complete later.
    */
    if (!gateway_command_state_try_start_disarm(
            &cancelled_arm)) {

        command_state =
            gateway_command_state_get_snapshot();

        ESP_LOGW(
            TAG,
            "SAFETY DISARM denied: command conflict "
            "arm=%u disarm=%u rtl=%u reason=%s",
            command_state.arm_pending ? 1 : 0,
            command_state.disarm_pending ? 1 : 0,
            command_state.rtl_pending ? 1 : 0,
            reason
        );

        return false;
    }

    gateway_send_arm_disarm_command(false);

    gateway_action_publish(
        GATEWAY_ACTION_DISARM_REAL_SENT);

    ESP_LOGW(
        TAG,
        "SAFETY REAL DISARM requested "
        "cancelled_arm=%u reason=%s",
        cancelled_arm ? 1 : 0,
        reason
    );

    return true;

#else

    ESP_LOGW(
        TAG,
        "SAFETY DISARM dry/disabled reason=%s",
        reason ? reason : "unknown"
    );

    gateway_action_publish(
        GATEWAY_ACTION_FAILSAFE_DRY_RUN);

    return false;

#endif
}

static bool gateway_start_rtl_for_safety(
    const char *reason)
{
#if FEATURE_REAL_MAVLINK_ARMING

    if (reason == NULL) {
        reason = "unknown";
    }

    if (!fc_is_armed) {
        ESP_LOGW(
            TAG,
            "SAFETY RTL skipped: FC already DISARMED "
            "reason=%s",
            reason
        );

        gateway_action_publish(
            GATEWAY_ACTION_DISARM_CONFIRMED);

        gateway_safety_disarm_latched = false;

        return false;
    }

    gateway_command_state_snapshot_t command_state =
        gateway_command_state_get_snapshot();

    if (command_state.rtl_pending) {
        ESP_LOGW(
            TAG,
            "SAFETY RTL already pending reason=%s",
            reason
        );

        return false;
    }

    bool cancelled_arm = false;
    bool cancelled_disarm = false;

    /*
       Atomically cancel normal ARM/DISARM operations and
       reserve the safety RTL operation.
    */
    if (!gateway_command_state_try_start_rtl(
            &cancelled_arm,
            &cancelled_disarm)) {

        command_state =
            gateway_command_state_get_snapshot();

        ESP_LOGW(
            TAG,
            "SAFETY RTL denied: command conflict "
            "arm=%u disarm=%u rtl=%u reason=%s",
            command_state.arm_pending ? 1 : 0,
            command_state.disarm_pending ? 1 : 0,
            command_state.rtl_pending ? 1 : 0,
            reason
        );

        return false;
    }

    gateway_send_rtl_command();

    gateway_action_publish(
        GATEWAY_ACTION_RTL_SENT);

    ESP_LOGW(
        TAG,
        "SAFETY RTL requested "
        "cancelled_arm=%u cancelled_disarm=%u "
        "reason=%s",
        cancelled_arm ? 1 : 0,
        cancelled_disarm ? 1 : 0,
        reason
    );

    return true;

#else

    ESP_LOGW(
        TAG,
        "SAFETY RTL disabled reason=%s",
        reason ? reason : "unknown"
    );

    gateway_action_publish(
        GATEWAY_ACTION_FAILSAFE_DRY_RUN);

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
            "RC state FAILSAFE"
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
            "RC link timeout"
        );
#endif

        return;
    }

    if (fc_heartbeat_lost) {
        gateway_last_remote_state = RC_FAILSAFE;
        gateway_safety_disarm_latched = true;

#if GATEWAY_FAILSAFE_ACTION_MODE == GATEWAY_FAILSAFE_ACTION_BENCH_DISARM
        gateway_start_real_disarm_for_safety(
            "FC heartbeat timeout"
        );
#elif GATEWAY_FAILSAFE_ACTION_MODE == GATEWAY_FAILSAFE_ACTION_FLIGHT_RTL
        gateway_start_rtl_for_safety(
            "FC heartbeat timeout"
        );
#endif

        return;
    }

#endif
}


static void gateway_rtl_timeout_check(void)
{
#if FEATURE_REAL_MAVLINK_ARMING

    int64_t age_ms = 0;

    if (!gateway_command_state_timeout_rtl(
            esp_timer_get_time(),
            &age_ms)) {
        return;
    }

    gateway_action_publish(
        GATEWAY_ACTION_RTL_TIMEOUT);

    ESP_LOGW(
        TAG,
        "REAL RTL timeout after %" PRId64 "ms",
        age_ms
    );

#endif
}

static void gateway_arm_disarm_timeout_check(void)
{
#if FEATURE_REAL_MAVLINK_ARMING

    int64_t now_us =
        esp_timer_get_time();

    int64_t arm_age_ms = 0;
    int64_t disarm_age_ms = 0;

    if (gateway_command_state_timeout_arm(
            now_us,
            &arm_age_ms)) {

        gateway_action_publish(
            GATEWAY_ACTION_ARM_TIMEOUT);

        ESP_LOGW(
            TAG,
            "REAL ARM timeout after %" PRId64 "ms",
            arm_age_ms
        );
    }

    if (gateway_command_state_timeout_disarm(
            now_us,
            &disarm_age_ms)) {

        gateway_action_publish(
            GATEWAY_ACTION_DISARM_TIMEOUT);

        ESP_LOGW(
            TAG,
            "REAL DISARM timeout after %" PRId64 "ms",
            disarm_age_ms
        );
    }

#endif
}
static void gateway_process_rc_state_action(
    const rc_packet_t *packet,
    bool new_session)
{
    static bool initialized = false;
    static rc_state_t previous_state =
        RC_DISARMED;

    if (packet == NULL) {
        return;
    }

    /*
       The first authenticated packet from a new remote
       session establishes a new state-machine baseline.

       It must never be interpreted as an operator-requested
       ARM, DISARM, FAILSAFE, or RECOVER transition.
    */
    if (new_session) {
        gateway_command_state_snapshot_t command_state =
            gateway_command_state_get_snapshot();

        bool arm_was_pending =
            command_state.arm_pending;

        /*
        Establish the new remote session as the state-machine
        baseline. Its first packet is never treated as a normal
        operator transition.
        */
        previous_state = packet->state;
        initialized = true;

    #if FEATURE_REAL_MAVLINK_ARMING

        /*
        A remote reboot occurred while an ARM command was still
        pending.

        The FC may still process that old ARM command after the
        reboot, so explicitly cancel it with DISARM.
        */
        if (arm_was_pending) {
            gateway_session_recovery_required = true;

            bool cancelled_arm = false;

            if (gateway_command_state_try_start_disarm(
                    &cancelled_arm)) {

                gateway_send_arm_disarm_command(false);

                gateway_action_publish(
                    GATEWAY_ACTION_DISARM_REAL_SENT);

                ESP_LOGW(
                    TAG,
                    "RC SESSION SAFETY: pending ARM cancelled "
                    "with explicit DISARM packet_id=%" PRIu32
                    " state=%s",
                    packet->packet_id,
                    mathos_rc_state_to_string(
                        packet->state)
                );
            }
            else {
                command_state =
                    gateway_command_state_get_snapshot();

                ESP_LOGW(
                    TAG,
                    "RC SESSION SAFETY: DISARM not started "
                    "arm=%u disarm=%u rtl=%u "
                    "packet_id=%" PRIu32,
                    command_state.arm_pending ? 1 : 0,
                    command_state.disarm_pending ? 1 : 0,
                    command_state.rtl_pending ? 1 : 0,
                    packet->packet_id
                );
            }

            return;
        }

        /*
        The FC is already armed when a new remote session
        appears.

        Never trust the new session as continuous pilot control.
        Apply the configured safety action instead.
        */
        if (fc_is_armed) {
            gateway_session_recovery_required = true;
            gateway_safety_disarm_latched = true;

        #if GATEWAY_FAILSAFE_ACTION_MODE == \
            GATEWAY_FAILSAFE_ACTION_BENCH_DISARM

            gateway_start_real_disarm_for_safety(
                "RC new session while FC armed"
            );

        #elif GATEWAY_FAILSAFE_ACTION_MODE == \
            GATEWAY_FAILSAFE_ACTION_FLIGHT_RTL

            gateway_start_rtl_for_safety(
                "RC new session while FC armed"
            );

        #endif

            ESP_LOGW(
                TAG,
                "RC SESSION SAFETY: FC was ARMED "
                "packet_id=%" PRIu32
                " new_state=%s",
                packet->packet_id,
                mathos_rc_state_to_string(
                    packet->state)
            );

            return;
        }

        /*
        A new remote session must begin DISARMED.

        An initial ARMED or FAILSAFE state is not accepted as
        continuous pilot authority, even when the FC currently
        reports DISARMED.
        */
        if (packet->state != RC_DISARMED) {
            gateway_session_recovery_required = true;

            gateway_action_publish(
                GATEWAY_ACTION_ARM_DENIED);

            ESP_LOGW(
                TAG,
                "RC SESSION LOCKED packet_id=%" PRIu32
                " unsafe initial state=%s "
                "recovery required",
                packet->packet_id,
                mathos_rc_state_to_string(
                    packet->state)
            );

            return;
        }

    #endif

        /*
        Safe case: no ARM operation exists and the FC is
        confirmed disarmed. Only synchronize the baseline.
        */
        ESP_LOGW(
            TAG,
            "RC SESSION SYNC packet_id=%" PRIu32
            " state=%s fc=DISARMED "
            "no command executed",
            packet->packet_id,
            mathos_rc_state_to_string(
                packet->state)
        );

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
    if (gateway_session_recovery_required) {
        gateway_action_publish(GATEWAY_ACTION_ARM_DENIED);

        ESP_LOGW(
            TAG,
            "REAL ARM denied: session recovery "
            "required packet_id=%" PRIu32,
            packet->packet_id
        );
    }
    else if (!fc_heartbeat_is_fresh()) {
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
        else {
    /*
       Atomically reserve the ARM operation before sending
       anything to the flight controller.
    */
    if (!gateway_command_state_try_start_arm()) {
        gateway_command_state_snapshot_t command_state =
            gateway_command_state_get_snapshot();

        gateway_action_publish(
            GATEWAY_ACTION_ARM_DENIED);

        ESP_LOGW(
            TAG,
            "REAL ARM denied: command already pending "
            "arm=%u disarm=%u rtl=%u "
            "packet_id=%" PRIu32,
            command_state.arm_pending ? 1 : 0,
            command_state.disarm_pending ? 1 : 0,
            command_state.rtl_pending ? 1 : 0,
            packet->packet_id
        );
    }
    else {
        gateway_send_arm_disarm_command(true);

        gateway_action_publish(
            GATEWAY_ACTION_ARM_REAL_SENT);

        ESP_LOGW(
            TAG,
            "REAL ARM requested: DISARMED -> ARMED "
            "packet_id=%" PRIu32,
            packet->packet_id
        );
    }
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
        gateway_action_publish(
            GATEWAY_ACTION_DISARM_DENIED);

        ESP_LOGW(
            TAG,
            "REAL DISARM denied: FC heartbeat not fresh "
            "packet_id=%" PRIu32,
            packet->packet_id
        );
    }
    else {
        gateway_command_state_snapshot_t command_state =
            gateway_command_state_get_snapshot();

        /*
           A DISARM operation is already active.
        */
        if (command_state.disarm_pending) {
            gateway_action_publish(
                GATEWAY_ACTION_DISARM_REAL_SENT);

            ESP_LOGW(
                TAG,
                "REAL DISARM already pending "
                "packet_id=%" PRIu32,
                packet->packet_id
            );
        }

        /*
           No delayed ARM exists and the FC is already
           confirmed DISARMED.
        */
        else if (!fc_is_armed &&
                 !command_state.arm_pending) {

            gateway_action_publish(
                GATEWAY_ACTION_DISARM_CONFIRMED);

            ESP_LOGW(
                TAG,
                "REAL DISARM skipped: FC already DISARMED "
                "packet_id=%" PRIu32,
                packet->packet_id
            );
        }
        else {
            bool cancelled_arm = false;

            if (!gateway_command_state_try_start_disarm(
                    &cancelled_arm)) {

                command_state =
                    gateway_command_state_get_snapshot();

                if (command_state.disarm_pending) {
                    gateway_action_publish(
                        GATEWAY_ACTION_DISARM_REAL_SENT);

                    ESP_LOGW(
                        TAG,
                        "REAL DISARM already pending "
                        "packet_id=%" PRIu32,
                        packet->packet_id
                    );
                }
                else {
                    gateway_action_publish(
                        GATEWAY_ACTION_DISARM_DENIED);

                    ESP_LOGW(
                        TAG,
                        "REAL DISARM denied: command conflict "
                        "arm=%u disarm=%u rtl=%u "
                        "packet_id=%" PRIu32,
                        command_state.arm_pending ? 1 : 0,
                        command_state.disarm_pending ? 1 : 0,
                        command_state.rtl_pending ? 1 : 0,
                        packet->packet_id
                    );
                }
            }
            else {
                gateway_send_arm_disarm_command(false);

                gateway_action_publish(
                    GATEWAY_ACTION_DISARM_REAL_SENT);

                if (cancelled_arm) {
                    ESP_LOGW(
                        TAG,
                        "REAL ARM CANCELLED: explicit DISARM sent "
                        "packet_id=%" PRIu32,
                        packet->packet_id
                    );
                }
                else {
                    ESP_LOGW(
                        TAG,
                        "REAL DISARM requested: %s -> DISARMED "
                        "packet_id=%" PRIu32,
                        mathos_rc_state_to_string(
                            previous_state),
                        packet->packet_id
                    );
                }
            }
        }
    }

#else

    gateway_action_publish(
        GATEWAY_ACTION_DISARM_DRY_RUN);

    ESP_LOGI(
        TAG,
        "DISARM DRY RUN: %s -> DISARMED "
        "packet_id=%" PRIu32,
        mathos_rc_state_to_string(
            previous_state),
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
            mathos_rc_state_to_string(previous_state),
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
            mathos_rc_state_to_string(previous_state),
            packet->packet_id
        );
#endif
    }

    previous_state = packet->state;
}

static bool gateway_rc_session_seen_before(
    uint32_t session_id)
{
    for (uint8_t i = 0;
         i < gateway_rc_session_history_count;
         i++) {

        if (gateway_rc_session_history[i] ==
            session_id) {
            return true;
        }
    }

    return false;
}

static void gateway_rc_session_remember(
    uint32_t session_id)
{
    if (gateway_rc_session_seen_before(
            session_id)) {
        return;
    }

    gateway_rc_session_history[
        gateway_rc_session_history_next
    ] = session_id;

    gateway_rc_session_history_next =
        (uint8_t)(
            (gateway_rc_session_history_next + 1) %
            GATEWAY_RC_SESSION_HISTORY_LEN
        );

    if (gateway_rc_session_history_count <
        GATEWAY_RC_SESSION_HISTORY_LEN) {

        gateway_rc_session_history_count++;
    }
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

    rc_packet_t rc_packet;
    memset(&rc_packet, 0, sizeof(rc_packet));

    memcpy(
        &rc_packet,
        packet.payload,
        sizeof(rc_packet)
    );

    /*
    Validate the RC packet layout before changing session,
    replay, sequence, state-machine, or control-output state.
    */
    if (rc_packet.protocol_version !=
        MATHOS_RC_PROTOCOL_VERSION) {

        bad_packets++;

        ESP_LOGE(
            TAG,
            "RC PROTOCOL MISMATCH received=%u expected=%u "
            "packet_id=%" PRIu32
            " bad=%" PRIu32,
            rc_packet.protocol_version,
            MATHOS_RC_PROTOCOL_VERSION,
            rc_packet.packet_id,
            bad_packets
        );

        return;
    }


        /*
    The encrypted Mathos header sequence and the RC payload
    packet_id must identify the exact same control packet.

    A mismatch indicates corrupted construction, incompatible
    firmware, or an invalid authenticated payload.
    */
    if (rc_packet.packet_id != packet.sequence) {
        bad_packets++;

        ESP_LOGE(
            TAG,
            "RC PACKET ID MISMATCH "
            "payload_id=%" PRIu32
            " secure_seq=%" PRIu32
            " bad=%" PRIu32,
            rc_packet.packet_id,
            packet.sequence,
            bad_packets
        );

        return;
    }


uint32_t session_id =
    packet.timestamp_ms;

/*
   Session zero is never valid.

   The remote generates a nonzero random session identifier
   at boot.
*/
if (session_id == 0) {
    bad_packets++;
    replay_packets++;

    ESP_LOGE(
        TAG,
        "RC SESSION INVALID id=0 "
        "secure_seq=%" PRIu32
        " bad=%" PRIu32,
        packet.sequence,
        bad_packets
    );

    return;
}

/*
   Accept the first authenticated session.
*/
if (!has_session) {
    last_session_id = session_id;
    last_sequence = 0;
    has_session = true;
    new_session = true;

    gateway_rc_session_remember(
        session_id);

    ESP_LOGI(
        TAG,
        "Initial RC session accepted "
        "id=0x%08" PRIx32,
        session_id
    );
}

/*
   A different session may be a legitimate remote reboot.

   It is accepted only when it has never previously been
   accepted during this gateway uptime.
*/
else if (session_id != last_session_id) {
    if (gateway_rc_session_seen_before(
            session_id)) {

        bad_packets++;
        replay_packets++;

        ESP_LOGE(
            TAG,
            "RC SESSION ROLLBACK rejected "
            "current=0x%08" PRIx32
            " replayed=0x%08" PRIx32
            " secure_seq=%" PRIu32
            " replay=%" PRIu32,
            last_session_id,
            session_id,
            packet.sequence,
            replay_packets
        );

        return;
    }

    ESP_LOGW(
        TAG,
        "New RC session accepted "
        "old=0x%08" PRIx32
        " new=0x%08" PRIx32,
        last_session_id,
        session_id
    );

    last_session_id = session_id;
    last_sequence = 0;
    new_session = true;

    gateway_rc_session_remember(
        session_id);
}

    /*
    Sequence zero is never valid because the remote begins
    transmission from sequence one.
    */
    if (packet.sequence == 0 ||
        packet.sequence <= last_sequence) {

        bad_packets++;
        replay_packets++;

        ESP_LOGW(
            TAG,
            "Replay/old secure packet seq=%" PRIu32
            " last=%" PRIu32,
            packet.sequence,
            last_sequence
        );

        return;
    }

    last_sequence = packet.sequence;

    handle_valid_rc_packet(
        &rc_packet,
        new_session);
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
        expected_frame_len = mathos_get_u16_le(&frame[4]);

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
            latest_packet.state == RC_ARMED &&
            !gateway_session_recovery_required) {
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
                        mathos_rc_state_to_string(latest_packet.state)
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

static void gateway_print_fc_telemetry(void)
{
    float battery_v = fc_tel_battery_voltage_mv / 1000.0f;
    float battery_a = 0.0f;

    if (fc_tel_battery_current_ca >= 0) {
        battery_a = fc_tel_battery_current_ca / 100.0f;
    }

    double lat_deg = fc_tel_lat / 10000000.0;
    double lon_deg = fc_tel_lon / 10000000.0;



    int32_t selected_alt_mm;
    int32_t selected_rel_alt_mm;
    int64_t altitude_update_us;

    taskENTER_CRITICAL(&fc_telemetry_mux);

    selected_alt_mm =
        fc_tel_position_seen
            ? fc_tel_global_alt_mm
            : fc_tel_gps_alt_mm;

    selected_rel_alt_mm =
        fc_tel_relative_alt_mm;

    altitude_update_us =
        fc_tel_position_update_us;

    taskEXIT_CRITICAL(&fc_telemetry_mux);

    float alt_m =
        selected_alt_mm / 1000.0f;

    float rel_alt_m =
        selected_rel_alt_mm / 1000.0f;

    int altitude_data_available =
    altitude_update_us > 0;

    int altitude_data_fresh = 0;

    if (altitude_data_available)
    {
        int64_t altitude_age_ms =
            (esp_timer_get_time() -
            altitude_update_us) /
            1000;

        altitude_data_fresh =
            altitude_age_ms <=
            GATEWAY_TELEMETRY_FRESH_MS;
    }

    mathos_altitude_health_t altitude_health =
        mathos_altitude_health_classify(
            altitude_data_available,
            altitude_data_fresh);

    float roll_rad;
    float pitch_rad;
    float yaw_rad;
    int64_t attitude_update_us;

    taskENTER_CRITICAL(&fc_telemetry_mux);

    roll_rad = fc_tel_roll_rad;
    pitch_rad = fc_tel_pitch_rad;
    yaw_rad = fc_tel_yaw_rad;
    attitude_update_us = fc_tel_attitude_update_us;

    taskEXIT_CRITICAL(&fc_telemetry_mux);

    int attitude_data_available =
        attitude_update_us > 0;

    int attitude_data_fresh = 0;

    if (attitude_data_available)
    {
        int64_t attitude_age_ms =
            (esp_timer_get_time() -
            attitude_update_us) /
            1000;

        attitude_data_fresh =
            attitude_age_ms <=
            GATEWAY_TELEMETRY_FRESH_MS;
    }

    mathos_attitude_health_t attitude_health =
        mathos_attitude_health_classify(
            attitude_data_available,
            attitude_data_fresh);

    float roll_deg = roll_rad * 57.2957795f;
    float pitch_deg = pitch_rad * 57.2957795f;
    float yaw_deg = yaw_rad * 57.2957795f;

    int64_t gps_update_us;
    uint8_t gps_fix_type;

    taskENTER_CRITICAL(&fc_telemetry_mux);

    gps_update_us = fc_tel_gps_update_us;
    gps_fix_type = fc_tel_gps_fix_type;

    taskEXIT_CRITICAL(&fc_telemetry_mux);

    int gps_data_available =
        gps_update_us > 0;

    int gps_data_fresh = 0;

    if (gps_data_available)
    {
        int64_t gps_age_ms =
            (esp_timer_get_time() - gps_update_us) / 1000;

        gps_data_fresh =
            gps_age_ms <= GATEWAY_TELEMETRY_FRESH_MS;
    }

    mathos_gps_health_t gps_health =
        mathos_gps_health_classify(
            gps_fix_type,
            gps_data_available,
            gps_data_fresh);

            int64_t battery_update_us;
    uint16_t battery_voltage_mv;
    int8_t battery_remaining;

    taskENTER_CRITICAL(&fc_telemetry_mux);

    battery_update_us =
        fc_tel_battery_update_us;

    battery_voltage_mv =
        fc_tel_battery_voltage_mv;

    battery_remaining =
        fc_tel_battery_remaining;

    taskEXIT_CRITICAL(&fc_telemetry_mux);

    int battery_data_available =
        battery_update_us > 0;

    int battery_data_fresh = 0;

    if (battery_data_available)
    {
        int64_t battery_age_ms =
            (esp_timer_get_time() -
            battery_update_us) /
            1000;

        battery_data_fresh =
            battery_age_ms <=
            GATEWAY_TELEMETRY_FRESH_MS;
    }

    mathos_battery_health_t battery_health =
        mathos_battery_health_classify(
            battery_voltage_mv,
            battery_remaining,
            battery_data_available,
            battery_data_fresh);

    ESP_LOGI(
        TAG,
        "FC TELEMETRY batt=%.2fV current=%.2fA rem=%d%% "
        "battery_fresh=%u battery_health=%s "
        "gps=%s gps_health=%s sats=%u "
        "lat=%.7f lon=%.7f alt=%.1fm rel=%.1fm "
        "altitude_health=%s attitude_health=%s "
        "roll=%.1f pitch=%.1f yaw=%.1f",
        battery_v,
        battery_a,
        fc_tel_battery_remaining,
        battery_data_fresh ? 1U : 0U,
        mathos_battery_health_to_string(battery_health),
        mathos_gps_fix_to_string(fc_tel_gps_fix_type),
        mathos_gps_health_to_string(gps_health),
        fc_tel_satellites_visible,
        lat_deg,
        lon_deg,
        alt_m,
        rel_alt_m,
        mathos_altitude_health_to_string(altitude_health),
        mathos_attitude_health_to_string(attitude_health),
        roll_deg,
        pitch_deg,
        yaw_deg
    );
}
static bool gateway_send_message_interval_request(
    uint32_t message_id,
    int32_t interval_us,
    const char *name
)
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
       MAV_CMD_SET_MESSAGE_INTERVAL

       param1 = MAVLink message ID
       param2 = interval in microseconds
                -1 disables
                 0 restores default
                >0 requested interval
    */
    mavlink_msg_command_long_pack(
        GATEWAY_MAV_SYS_ID,
        GATEWAY_MAV_COMP_ID,
        &msg,

        target_sys,
        target_comp,

        MAV_CMD_SET_MESSAGE_INTERVAL,
        0,

        (float)message_id,
        (float)interval_us,
        0.0f,
        0.0f,
        0.0f,
        0.0f,
        0.0f
    );

    mavlink_send_message(&msg);

    ESP_LOGW(
        TAG,
        "TELEMETRY REQUEST %s msg_id=%" PRIu32
        " interval_us=%" PRId32
        " target_sys=%u target_comp=%u",
        name ? name : "UNKNOWN",
        message_id,
        interval_us,
        target_sys,
        target_comp
    );

    return true;
}

static void gateway_request_telemetry_streams_once(void)
{
    /*
       Core health / battery.
    */
    gateway_send_message_interval_request(
        MAVLINK_MSG_ID_SYS_STATUS,
        TELEMETRY_REQUEST_SLOW_INTERVAL_US,
        "SYS_STATUS"
    );

    gateway_send_message_interval_request(
        MAVLINK_MSG_ID_BATTERY_STATUS,
        TELEMETRY_REQUEST_SLOW_INTERVAL_US,
        "BATTERY_STATUS"
    );

    /*
       GPS / position.
    */
    gateway_send_message_interval_request(
        MAVLINK_MSG_ID_GPS_RAW_INT,
        TELEMETRY_REQUEST_SLOW_INTERVAL_US,
        "GPS_RAW_INT"
    );

    gateway_send_message_interval_request(
        MAVLINK_MSG_ID_GLOBAL_POSITION_INT,
        TELEMETRY_REQUEST_MED_INTERVAL_US,
        "GLOBAL_POSITION_INT"
    );

    /*
       Attitude and flight information.
    */
    gateway_send_message_interval_request(
        MAVLINK_MSG_ID_ATTITUDE,
        TELEMETRY_REQUEST_FAST_INTERVAL_US,
        "ATTITUDE"
    );

    gateway_send_message_interval_request(
        MAVLINK_MSG_ID_VFR_HUD,
        TELEMETRY_REQUEST_MED_INTERVAL_US,
        "VFR_HUD"
    );

    gateway_send_message_interval_request(
        MAVLINK_MSG_ID_EXTENDED_SYS_STATE,
        TELEMETRY_REQUEST_SLOW_INTERVAL_US,
        "EXTENDED_SYS_STATE"
    );
    /*
   EKF health and estimator variances.

   One update per second is enough for health monitoring.
*/
    gateway_send_message_interval_request(
        MAVLINK_MSG_ID_EKF_STATUS_REPORT,
        TELEMETRY_REQUEST_SLOW_INTERVAL_US,
        "EKF_STATUS_REPORT"
    );
}

static void telemetry_request_task(void *arg)
{
    int request_round = 0;

    /*
       Wait until the gateway has seen the FC heartbeat.
       That gives us real target sysid/compid.
    */
    while (!fc_heartbeat_is_fresh()) {
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    ESP_LOGW(TAG, "FC heartbeat fresh. Starting telemetry stream requests.");

    while (true) {
        gateway_request_telemetry_streams_once();

        request_round++;

        /*
           First few rounds repeat more often to make sure ArduPilot accepts
           the requested stream rates. After that, refresh once per minute.
        */
        if (request_round < TELEMETRY_REQUEST_ROUNDS) {
            vTaskDelay(pdMS_TO_TICKS(TELEMETRY_REQUEST_REPEAT_MS));
        }
        else {
            vTaskDelay(pdMS_TO_TICKS(60000));
        }
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
            /*
            Print only when the FC changes mode.

            This avoids printing one mode line every heartbeat.
            */
            static uint32_t previous_fc_mode = UINT32_MAX;

            if (heartbeat.custom_mode != previous_fc_mode)
            {
                ESP_LOGW(
                    TAG,
                    "FC MODE CHANGE old=%" PRIu32
                    " new=%" PRIu32 " name=%s",
                    previous_fc_mode,
                    heartbeat.custom_mode,
                    mathos_plane_mode_to_string(
                        heartbeat.custom_mode));

                previous_fc_mode = heartbeat.custom_mode;
            }
            last_fc_heartbeat_us = esp_timer_get_time();

            fc_seen_sys_id = msg.sysid;
            fc_seen_comp_id = msg.compid;

            taskENTER_CRITICAL(&fc_telemetry_mux);

            fc_is_armed =
                (heartbeat.base_mode & MAV_MODE_FLAG_SAFETY_ARMED) ? 1 : 0;

            fc_custom_mode =
                heartbeat.custom_mode;

            fc_vehicle_type =
                heartbeat.type;

            fc_tel_system_status =
                heartbeat.system_status;

            taskEXIT_CRITICAL(&fc_telemetry_mux);

#if FEATURE_REAL_MAVLINK_ARMING
            if (fc_is_armed &&
                gateway_command_state_confirm_arm()) {

                gateway_action_publish(
                    GATEWAY_ACTION_ARM_CONFIRMED);

                ESP_LOGW(
                    TAG,
                    "REAL ARM confirmed by FC heartbeat"
                );
            }

            if (!fc_is_armed &&
                gateway_command_state_confirm_disarm()) {

                gateway_action_publish(
                    GATEWAY_ACTION_DISARM_CONFIRMED);

                ESP_LOGW(
                    TAG,
                    "REAL DISARM confirmed by FC heartbeat"
                );
            }
            /*
   A command acknowledgement means the FC received and accepted
   the RTL request.

   Actual confirmation comes only when HEARTBEAT.custom_mode
   reports RTL or QRTL.
*/
        if (mathos_plane_mode_is_rtl(
                heartbeat.custom_mode) &&
            gateway_command_state_confirm_rtl()) {

            gateway_action_publish(
                GATEWAY_ACTION_RTL_CONFIRMED);

            ESP_LOGW(
                TAG,
                "REAL RTL confirmed by FC heartbeat "
                "mode=%s raw=%" PRIu32,
                mathos_plane_mode_to_string(
                    heartbeat.custom_mode),
                heartbeat.custom_mode
            );
        }
#endif
        }

        else if (msg.msgid == MAVLINK_MSG_ID_COMMAND_ACK) {
            mavlink_command_ack_t ack;
            mavlink_msg_command_ack_decode(&msg, &ack);

if (ack.command == MAV_CMD_COMPONENT_ARM_DISARM) {
    ESP_LOGW(
        TAG,
        "FC COMMAND_ACK ARM_DISARM result=%s raw=%u "
        "arm_pending=%u disarm_pending=%u",
        mathos_mav_result_to_string(
            ack.result),
        ack.result,
        gateway_arm_pending ? 1 : 0,
        gateway_disarm_pending ? 1 : 0
    );

#if FEATURE_REAL_MAVLINK_ARMING

    /*
       ARM and DISARM use the same MAVLink command ID.

       A delayed ACK cannot be reliably associated with the
       current operation after an ARM cancellation or a rapid
       state transition.

       Therefore, COMMAND_ACK is diagnostic only.

       Final operation results come from:
       - HEARTBEAT armed state
       - ARM/DISARM timeout handling
    */
    if (ack.result != MAV_RESULT_ACCEPTED &&
        ack.result != MAV_RESULT_IN_PROGRESS) {

        ESP_LOGW(
            TAG,
            "ARM_DISARM ACK rejection recorded only; "
            "waiting for heartbeat or timeout"
        );
    }

#endif
}

if (ack.command ==
    MAV_CMD_NAV_RETURN_TO_LAUNCH) {

    ESP_LOGW(
        TAG,
        "FC COMMAND_ACK RTL result=%s raw=%u",
        mathos_mav_result_to_string(
            ack.result),
        ack.result
    );

#if FEATURE_REAL_MAVLINK_ARMING

    if (ack.result == MAV_RESULT_ACCEPTED ||
        ack.result == MAV_RESULT_IN_PROGRESS) {

        gateway_command_state_snapshot_t command_state =
            gateway_command_state_get_snapshot();

        /*
           ACK confirms receipt only.

           Final RTL confirmation still comes from the
           FC heartbeat flight mode.
        */
        if (command_state.rtl_pending) {
            ESP_LOGW(
                TAG,
                "REAL RTL command accepted. "
                "Waiting for FC mode confirmation."
            );
        }
    }
    else {
        /*
           Clear RTL only when an RTL operation is still
           pending. A delayed ACK cannot overwrite a
           completed operation.
        */
        if (gateway_command_state_reject_rtl()) {
            gateway_action_publish(
                GATEWAY_ACTION_RTL_DENIED);

            ESP_LOGW(
                TAG,
                "REAL RTL denied by FC"
            );
        }
    }

#endif
}

            if (ack.command == MAV_CMD_SET_MESSAGE_INTERVAL) {
                ESP_LOGW(
                    TAG,
                    "FC COMMAND_ACK SET_MESSAGE_INTERVAL result=%s raw=%u",
                    mathos_mav_result_to_string(ack.result),
                    ack.result
                );
            }
        }

        else if (msg.msgid == MAVLINK_MSG_ID_SYS_STATUS) {
            mavlink_sys_status_t sys_status;
            mavlink_msg_sys_status_decode(&msg, &sys_status);

            int64_t update_us = esp_timer_get_time();

            taskENTER_CRITICAL(&fc_telemetry_mux);

            fc_tel_sys_status_seen = true;
            fc_tel_battery_voltage_mv = sys_status.voltage_battery;
            fc_tel_battery_current_ca = sys_status.current_battery;
            fc_tel_battery_remaining = sys_status.battery_remaining;
            fc_tel_battery_update_us = update_us;

            taskEXIT_CRITICAL(&fc_telemetry_mux);
        }

        else if (msg.msgid == MAVLINK_MSG_ID_BATTERY_STATUS)
        {
            mavlink_battery_status_t battery;
            mavlink_msg_battery_status_decode(&msg, &battery);

            /*
            BATTERY_STATUS updates current and remaining percentage.

            Do not refresh the battery voltage timestamp here because
            this handler does not currently update battery voltage.
            */
            taskENTER_CRITICAL(&fc_telemetry_mux);

            fc_tel_battery_current_ca = battery.current_battery;
            fc_tel_battery_remaining = battery.battery_remaining;

            taskEXIT_CRITICAL(&fc_telemetry_mux);
        }

        else if (msg.msgid == MAVLINK_MSG_ID_GPS_RAW_INT) {
            mavlink_gps_raw_int_t gps;
            mavlink_msg_gps_raw_int_decode(&msg, &gps);

            int64_t update_us = esp_timer_get_time();

            taskENTER_CRITICAL(&fc_telemetry_mux);

            fc_tel_gps_seen = true;
            fc_tel_gps_fix_type = gps.fix_type;
            fc_tel_satellites_visible = gps.satellites_visible;

            /*
            GPS_RAW_INT:
            lat/lon = degrees * 1E7
            alt     = millimeters MSL
            */
            fc_tel_lat = gps.lat;
            fc_tel_lon = gps.lon;
            fc_tel_gps_alt_mm = gps.alt;
            fc_tel_gps_update_us = update_us;

            taskEXIT_CRITICAL(&fc_telemetry_mux);
        }

        else if (msg.msgid == MAVLINK_MSG_ID_GLOBAL_POSITION_INT) {
            mavlink_global_position_int_t pos;
            mavlink_msg_global_position_int_decode(&msg, &pos);

            int64_t update_us = esp_timer_get_time();

            taskENTER_CRITICAL(&fc_telemetry_mux);

            fc_tel_position_seen = true;

            /*
            GLOBAL_POSITION_INT:
            lat/lon      = degrees * 1E7
            alt          = millimeters MSL
            relative_alt = millimeters above home
            */
            fc_tel_lat = pos.lat;
            fc_tel_lon = pos.lon;
            fc_tel_global_alt_mm = pos.alt;
            fc_tel_relative_alt_mm = pos.relative_alt;
            fc_tel_position_update_us = update_us;

            taskEXIT_CRITICAL(&fc_telemetry_mux);
        }

        else if (msg.msgid == MAVLINK_MSG_ID_ATTITUDE) {
            mavlink_attitude_t attitude;
            mavlink_msg_attitude_decode(&msg, &attitude);

            int64_t update_us = esp_timer_get_time();

            taskENTER_CRITICAL(&fc_telemetry_mux);

            fc_tel_attitude_seen = true;

            fc_tel_roll_rad = attitude.roll;
            fc_tel_pitch_rad = attitude.pitch;
            fc_tel_yaw_rad = attitude.yaw;
            fc_tel_attitude_update_us = update_us;

            taskEXIT_CRITICAL(&fc_telemetry_mux);
        }
        else if (msg.msgid == MAVLINK_MSG_ID_VFR_HUD)
        {
            mavlink_vfr_hud_t vfr_hud;

            mavlink_msg_vfr_hud_decode(
                &msg,
                &vfr_hud);

            int64_t update_us =
                esp_timer_get_time();

            taskENTER_CRITICAL(
                &fc_telemetry_mux);

            fc_tel_vfr_hud_seen = true;
            fc_tel_airspeed_mps =
                vfr_hud.airspeed;
            fc_tel_airspeed_update_us =
                update_us;

            taskEXIT_CRITICAL(
                &fc_telemetry_mux);
        }
        else if (msg.msgid == MAVLINK_MSG_ID_EKF_STATUS_REPORT){
    mavlink_ekf_status_report_t ekf;

    mavlink_msg_ekf_status_report_decode(
        &msg,
        &ekf);
    int64_t update_us = esp_timer_get_time();

    /*
    Store the latest EKF flags for encrypted telemetry TX.
    */
    taskENTER_CRITICAL(&fc_telemetry_mux);

    fc_tel_ekf_flags = ekf.flags;
    fc_tel_ekf_update_us = update_us;

    taskEXIT_CRITICAL(&fc_telemetry_mux);
    /*
       Print immediately when the EKF flags change.

       While the flags remain unchanged, print one diagnostic
       approximately every five received reports.
    */
    static uint16_t previous_ekf_flags = UINT16_MAX;
    static uint32_t ekf_print_counter = 0;

    ekf_print_counter++;
    mathos_ekf_health_t ekf_health =
    mathos_ekf_health_classify(
        ekf.flags,
        1,
        1);

    bool flags_changed =
        ekf.flags != previous_ekf_flags;

    if (flags_changed ||
        ekf_print_counter >= 5)
    {
        previous_ekf_flags = ekf.flags;
        ekf_print_counter = 0;

        ESP_LOGI(
            TAG,
            "FC EKF flags=0x%04X health=%s "
            "att=%u vel_h=%u vel_v=%u "
            "pos_rel=%u pos_abs=%u alt_abs=%u "
            "uninit=%u gps_glitch=%u "
            "variance[v=%.2f ph=%.2f pv=%.2f "
            "mag=%.2f terrain=%.2f air=%.2f]",
            ekf.flags,
            mathos_ekf_health_to_string(ekf_health),
            (ekf.flags & EKF_ATTITUDE) ? 1 : 0,
            (ekf.flags & EKF_VELOCITY_HORIZ) ? 1 : 0,
            (ekf.flags & EKF_VELOCITY_VERT) ? 1 : 0,

            (ekf.flags & EKF_POS_HORIZ_REL) ? 1 : 0,
            (ekf.flags & EKF_POS_HORIZ_ABS) ? 1 : 0,
            (ekf.flags & EKF_POS_VERT_ABS) ? 1 : 0,

            (ekf.flags & EKF_UNINITIALIZED) ? 1 : 0,
            (ekf.flags & EKF_GPS_GLITCHING) ? 1 : 0,

            ekf.velocity_variance,
            ekf.pos_horiz_variance,
            ekf.pos_vert_variance,
            ekf.compass_variance,
            ekf.terrain_alt_variance,
            ekf.airspeed_variance);
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
        bool telemetry_ok = gateway_telemetry_send_once();

        gateway_action_tick_after_status_send(ok);
        gateway_arm_disarm_timeout_check();
        gateway_rtl_timeout_check();
        gateway_failsafe_safety_check();
        print_counter++;

        if (print_counter == 1 || (print_counter % 10) == 0) {
            ESP_LOGI(
                TAG,
                "Gateway status TX %s telemetry=%s fc_fresh=%u fc=%s remote=%s link=%u action=%s ok=%" PRIu32 " bad=%" PRIu32 " replay=%" PRIu32,
                ok ? "OK" : "FAILED",
                telemetry_ok ? "OK" : "FAILED",
                fc_heartbeat_is_fresh() ? 1 : 0,
                fc_is_armed ? "ARMED" : "DISARMED",
                mathos_rc_state_to_string(gateway_last_remote_state),
                gateway_remote_link_is_fresh() ? 1 : 0,
                mathos_gateway_action_to_string(gateway_action_get()),
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
    status.last_action = (uint8_t)gateway_action_get();

    status.protocol_version =
        MATHOS_GATEWAY_PROTOCOL_VERSION;
    
/*
    Temporary protocol-mismatch bench test.
    Restore to MATHOS_GATEWAY_PROTOCOL_VERSION after testing.
*/

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
static int16_t gateway_radians_to_centidegrees(float radians)
{
    float degrees = radians * 57.2957795f;
    int32_t centidegrees = (int32_t)(degrees * 100.0f);

    if (centidegrees > INT16_MAX) {
        centidegrees = INT16_MAX;
    }
    else if (centidegrees < INT16_MIN) {
        centidegrees = INT16_MIN;
    }

    return (int16_t)centidegrees;
}

static bool gateway_telemetry_value_is_fresh(int64_t update_us, int64_t now_us)
{
    if (update_us <= 0) {
        return false;
    }

    return ((now_us - update_us) / 1000) <= GATEWAY_TELEMETRY_FRESH_MS;
}

static bool gateway_telemetry_send_once(void)
{
    gateway_telemetry_packet_t telemetry;
    memset(&telemetry, 0, sizeof(telemetry));

    uint32_t seq = gateway_status_tx_sequence++;

    /*
    Local copies of values that need conversion or freshness checks
    after the critical section has been released.
    */
    float roll_rad;
    float pitch_rad;
    float yaw_rad;
    float airspeed_mps;

    int64_t battery_update_us;
    int64_t gps_update_us;
    int64_t position_update_us;
    int64_t attitude_update_us;
    int64_t ekf_update_us;
    int64_t airspeed_update_us;

    /*
    Take one complete telemetry snapshot.

    MAVLink RX cannot modify these values while they are copied,
    so the outgoing packet represents one internally consistent state.
    */
    taskENTER_CRITICAL(&fc_telemetry_mux);

    telemetry.battery_voltage_mv = fc_tel_battery_voltage_mv;
    telemetry.battery_current_ca = fc_tel_battery_current_ca;
    telemetry.battery_remaining = fc_tel_battery_remaining;

    telemetry.gps_fix_type = fc_tel_gps_fix_type;
    telemetry.satellites_visible = fc_tel_satellites_visible;

    telemetry.latitude_e7 = fc_tel_lat;
    telemetry.longitude_e7 = fc_tel_lon;

    /*
    Prefer GLOBAL_POSITION_INT altitude.

    Only use GPS_RAW_INT altitude when global position
    has never been received.
    */
    if (fc_tel_position_seen) {
        telemetry.altitude_mm =
            fc_tel_global_alt_mm;
    }
    else {
        telemetry.altitude_mm =
            fc_tel_gps_alt_mm;
    }

    telemetry.relative_altitude_mm =
        fc_tel_relative_alt_mm;

    roll_rad = fc_tel_roll_rad;
    pitch_rad = fc_tel_pitch_rad;
    yaw_rad = fc_tel_yaw_rad;
    airspeed_mps = fc_tel_airspeed_mps;

    telemetry.fc_custom_mode = fc_custom_mode;
    telemetry.fc_vehicle_type = fc_vehicle_type;
    telemetry.ekf_flags = fc_tel_ekf_flags;

    telemetry.fc_is_armed = fc_is_armed ? 1 : 0;
    telemetry.system_status = fc_tel_system_status;

    battery_update_us = fc_tel_battery_update_us;
    gps_update_us = fc_tel_gps_update_us;
    position_update_us = fc_tel_position_update_us;
    attitude_update_us = fc_tel_attitude_update_us;
    ekf_update_us = fc_tel_ekf_update_us;
    airspeed_update_us = fc_tel_airspeed_update_us;
    taskEXIT_CRITICAL(&fc_telemetry_mux);
/*
   Capture time after the snapshot so it cannot be older
   than any copied telemetry update timestamp.
*/
    int64_t now_us = esp_timer_get_time();
    /*
    Everything below happens outside the lock.
    */
    telemetry.packet_id = seq;
    telemetry.sample_time_ms = (uint32_t)(now_us / 1000);

    telemetry.roll_cd =
        gateway_radians_to_centidegrees(roll_rad);

    telemetry.pitch_cd =
        gateway_radians_to_centidegrees(pitch_rad);

    telemetry.yaw_cd =
        gateway_radians_to_centidegrees(yaw_rad);

    float airspeed_kph =
        airspeed_mps * 3.6f;

    if (airspeed_kph < 0.0f)
    {
        airspeed_kph = 0.0f;
    }
    else if (airspeed_kph > 255.0f)
    {
        airspeed_kph = 255.0f;
    }

    telemetry.airspeed_kph =
        (uint8_t)(airspeed_kph + 0.5f);

    if (gateway_telemetry_value_is_fresh(
            battery_update_us,
            now_us)) {
        telemetry.telemetry_flags |=
            GATEWAY_TELEMETRY_FLAG_BATTERY_FRESH;
    }

    if (gateway_telemetry_value_is_fresh(
            airspeed_update_us,
            now_us))
    {
        telemetry.telemetry_flags |=
            GATEWAY_TELEMETRY_FLAG_AIRSPEED_FRESH;
    }

    if (gateway_telemetry_value_is_fresh(
            gps_update_us,
            now_us)) {
        telemetry.telemetry_flags |=
            GATEWAY_TELEMETRY_FLAG_GPS_FRESH;
    }

    if (gateway_telemetry_value_is_fresh(
            position_update_us,
            now_us)) {
        telemetry.telemetry_flags |=
            GATEWAY_TELEMETRY_FLAG_POSITION_FRESH;
    }

    if (gateway_telemetry_value_is_fresh(
            attitude_update_us,
            now_us)) {
        telemetry.telemetry_flags |=
            GATEWAY_TELEMETRY_FLAG_ATTITUDE_FRESH;
    }
    if (gateway_telemetry_value_is_fresh(
        ekf_update_us,
        now_us))
    {
        telemetry.telemetry_flags |=
            GATEWAY_TELEMETRY_FLAG_EKF_FRESH;
    }

    mathos_secure_packet_t packet;
    memset(&packet, 0, sizeof(packet));

    packet.sequence = seq;
    packet.timestamp_ms = gateway_status_session_id;
    packet.controller_id = SECURITY_GATEWAY_ID;
    packet.link_id = GATEWAY_STATUS_LINK_ID;
    packet.payload_type = SECURITY_PAYLOAD_TYPE_GATEWAY_TELEMETRY;
    packet.payload_len = sizeof(gateway_telemetry_packet_t);

    if (packet.payload_len > MATHOS_PAYLOAD_MAX_LEN) {
        ESP_LOGE(
            TAG,
            "Gateway telemetry payload too large: %u max=%u",
            packet.payload_len,
            MATHOS_PAYLOAD_MAX_LEN
        );
        return false;
    }

    memcpy(packet.payload, &telemetry, sizeof(telemetry));

    mathos_secure_status_t crypto_status = mathos_secure_encrypt_packet(&packet);

    if (crypto_status != MATHOS_SECURE_STATUS_OK) {
        ESP_LOGW(
            TAG,
            "Gateway telemetry encrypt failed: %s",
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
            "Gateway telemetry encode failed: %s",
            mathos_status_to_string(encode_status)
        );
        return false;
    }

    int written = uart_write_bytes(
        LINK_UART_NUM,
        (const char *)wire_frame,
        wire_frame_len
    );

    static uint32_t print_counter = 0;
    print_counter++;

    if (print_counter == 1 || (print_counter % 25) == 0) {
        ESP_LOGI(
            TAG,
            "GATEWAY TELEMETRY TX packet=%" PRIu32
            " mode=%" PRIu32 " vehicle_type=%u"
            " flags=0x%02X batt=%umV rem=%d%% gps=%u sats=%u"
            " rel_alt=%" PRId32 "mm roll=%dcd pitch=%dcd yaw=%dcd",
            telemetry.packet_id,
            telemetry.fc_custom_mode,
            telemetry.fc_vehicle_type,
            telemetry.telemetry_flags,
            telemetry.battery_voltage_mv,
            telemetry.battery_remaining,
            telemetry.gps_fix_type,
            telemetry.satellites_visible,
            telemetry.relative_altitude_mm,
            telemetry.roll_cd,
            telemetry.pitch_cd,
            telemetry.yaw_cd
        );
    }

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
            "rx=%" PRIu32 " valid=%" PRIu32
            " bad=%" PRIu32 " lost=%" PRIu32
            " last_id=%" PRIu32
            " rc_age=%" PRId64 "ms"
            " fc_hb_age=%" PRId64 "ms"
            " fc_mode=%" PRIu32 " fc_mode_name=%s",
            rx_packets,
            valid_packets,
            bad_packets,
            lost_packets,
            last_good_packet_id,
            rc_age_ms,
            fc_hb_age_ms,
            fc_custom_mode,
            mathos_plane_mode_to_string(fc_custom_mode)
        );
        static uint32_t telemetry_print_counter = 0;

        telemetry_print_counter++;

        if ((telemetry_print_counter % 5) == 0) {
            gateway_print_fc_telemetry();
        }
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

    mavlink_tx_mutex =
        xSemaphoreCreateMutex();

    if (mavlink_tx_mutex == NULL) {
        ESP_LOGE(
            TAG,
            "Failed to create mavlink_tx_mutex"
        );

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
    xTaskCreate(telemetry_request_task, "telemetry_request_task", 4096, NULL, 4, NULL);
    ESP_LOGI(TAG, "Drone gateway started");
}