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

#define FC_TARGET_SYS_ID       1
#define FC_TARGET_COMP_ID      1

#define GATEWAY_MAV_SYS_ID     42
#define GATEWAY_MAV_COMP_ID    191   // onboard computer style component id

#define SECURITY_CONTROLLER_ID        1
#define SECURITY_PAYLOAD_TYPE_RC      1
#define LINK_RX_BUFFER_SIZE           128


typedef enum {
    RC_DISARMED = 0,
    RC_ARMED    = 1,
    RC_FAILSAFE = 2,
} rc_state_t;

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



static QueueHandle_t rc_packet_queue = NULL;

static volatile uint32_t rx_packets = 0;
static volatile uint32_t valid_packets = 0;
static volatile uint32_t bad_packets = 0;
static volatile uint32_t lost_packets = 0;

static volatile uint32_t last_good_packet_id = 0;
static volatile int64_t last_good_packet_time_us = 0;

static volatile int64_t last_fc_heartbeat_us = 0;

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
static void handle_valid_rc_packet(const rc_packet_t *packet)
{
    static uint32_t previous_packet_id = 0;
    static bool have_previous_packet = false;

    if (packet == NULL) {
        return;
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
}

static void link_handle_mathos_frame(const uint8_t *frame, size_t frame_len)
{
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
    }

    if (packet.sequence <= last_sequence) {
        bad_packets++;

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

    handle_valid_rc_packet(&rc_packet);
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
                ESP_LOGW(TAG, "RC packet timeout. Releasing RC override.");
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

        if (mavlink_parse_char(MAVLINK_COMM_0, byte, &msg, &status)) {
            if (msg.msgid == MAVLINK_MSG_ID_HEARTBEAT) {
                last_fc_heartbeat_us = esp_timer_get_time();
            }
        }
    }
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

    ESP_LOGI(TAG, "Drone gateway started");
}