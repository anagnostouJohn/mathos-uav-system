#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/uart.h"
#include "esp_err.h"

#include "mathos_protocol.h"
#include "mathos_secure.h"
#include "esp_random.h"

#define GATEWAY_UART_PORT UART_NUM_1
#define GATEWAY_UART_TX_PIN 8
#define GATEWAY_UART_RX_PIN 9
#define GATEWAY_UART_BAUD 115200

#define GATEWAY_RX_BUFFER_SIZE 256
#define GATEWAY_PRINT_EVERY 50
#define DEBUG_GATEWAY_RX_BYTES 0
#define GATEWAY_MAVLINK_DRY_RUN 1
#define GATEWAY_DRY_RUN_PRINT_EVERY 50

#define GATEWAY_FC_UART_ENABLE 1

#define GATEWAY_FC_UART_PORT UART_NUM_2
#define GATEWAY_FC_UART_TX_PIN 38
#define GATEWAY_FC_UART_RX_PIN 39
#define GATEWAY_FC_UART_BAUD 115200

#define GATEWAY_MAVLINK_HEARTBEAT_ENABLE 1
#define GATEWAY_MAVLINK_MANUAL_CONTROL_ENABLE 0

#define MAVLINK2_STX 0xFD

#define GATEWAY_MAVLINK_SYS_ID 245
#define GATEWAY_MAVLINK_COMP_ID 190

#define MAVLINK_MSG_ID_HEARTBEAT 0
#define MAVLINK_MSG_HEARTBEAT_LEN 9
#define MAVLINK_MSG_HEARTBEAT_CRC_EXTRA 50

#define MAV_TYPE_GCS 6
#define MAV_AUTOPILOT_INVALID 8
#define MAV_MODE_FLAG_CUSTOM_MODE_ENABLED 1
#define MAV_STATE_ACTIVE 4
#define MAVLINK_VERSION_FIELD 3
#define MAVLINK1_STX 0xFE
#define MAVLINK_MAX_FRAME_LEN (10 + 255 + 2 + 13)

#define MAV_MODE_FLAG_SAFETY_ARMED 0x80
#define GATEWAY_FC_HEARTBEAT_PRINT_EVERY 1

#define GATEWAY_ARM_DISARM_DRY_RUN 1
#define GATEWAY_ARM_DISARM_REAL_ENABLE 0

#define GATEWAY_STATUS_TX_ENABLE 1
#define GATEWAY_STATUS_TX_PERIOD_MS 200

#define MATHOS_GATEWAY_ID 2
#define MATHOS_LINK_ID_STATUS 0
#define MATHOS_PAYLOAD_TYPE_GATEWAY_STATUS 2

#define GATEWAY_REMOTE_LINK_FRESH_MS 1000

static uint8_t gateway_mavlink_tx_seq = 0;

static uint32_t gateway_fc_heartbeat_count = 0;
static uint8_t gateway_fc_is_armed = 0;
static uint32_t gateway_status_session_id = 1;
static TickType_t gateway_fc_last_heartbeat_tick = 0;



typedef enum
{
    RC_DISARMED = 0,
    RC_ARMED = 1,
    RC_FAILSAFE = 2
} rc_state_t;

typedef struct
{
    uint32_t packet_id;
    rc_state_t state;

    int throttle;
    int yaw;
    int pitch;
    int roll;
} rc_packet_t;

typedef enum
{
    GATEWAY_ACTION_NONE = 0,
    GATEWAY_ACTION_ARM_DRY_RUN,
    GATEWAY_ACTION_DISARM_DRY_RUN,
    GATEWAY_ACTION_FAILSAFE_DRY_RUN
} gateway_action_t;

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

static uint32_t gateway_status_tx_sequence = 1;

static volatile uint32_t gateway_rx_ok_count = 0;
static volatile uint32_t gateway_rx_bad_count = 0;
static volatile uint32_t gateway_rx_replay_count = 0;

static volatile rc_state_t gateway_last_remote_state = RC_DISARMED;
static volatile uint8_t gateway_last_action = GATEWAY_ACTION_NONE;
static volatile TickType_t gateway_last_remote_packet_tick = 0;

static uint8_t gateway_fc_heartbeat_is_fresh(void)
{
    TickType_t now = xTaskGetTickCount();

    if (gateway_fc_last_heartbeat_tick != 0 &&
        (now - gateway_fc_last_heartbeat_tick) < pdMS_TO_TICKS(1500))
    {
        return 1;
    }

    return 0;
}

static const char *gateway_fc_arm_state_to_string(uint8_t armed)
{
    if (armed)
    {
        return "ARMED";
    }

    return "DISARMED";
}

static const char *state_to_string(rc_state_t state)
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

static uint16_t gateway_get_u16_le(const uint8_t *buffer)
{
    return ((uint16_t)buffer[0] << 0) |
           ((uint16_t)buffer[1] << 8);
}

static void gateway_uart_init(void)
{
    printf("[GATEWAY] Mathos Gateway UART init tx=%d rx=%d baud=%d\n",
           GATEWAY_UART_TX_PIN,
           GATEWAY_UART_RX_PIN,
           GATEWAY_UART_BAUD);

    uart_config_t uart_config = {
        .baud_rate = GATEWAY_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_driver_install(
        GATEWAY_UART_PORT,
        4096,
        2048,
        0,
        NULL,
        0));

    ESP_ERROR_CHECK(uart_param_config(GATEWAY_UART_PORT, &uart_config));

    ESP_ERROR_CHECK(uart_set_pin(
        GATEWAY_UART_PORT,
        GATEWAY_UART_TX_PIN,
        GATEWAY_UART_RX_PIN,
        UART_PIN_NO_CHANGE,
        UART_PIN_NO_CHANGE));
}
static int16_t gateway_clamp_i16(int value, int min, int max)
{
    if (value < min)
    {
        return min;
    }

    if (value > max)
    {
        return max;
    }

    return value;
}

static int gateway_rc_packet_is_valid(const rc_packet_t *packet)
{
    if (packet == NULL)
    {
        return 0;
    }

    if (packet->state != RC_DISARMED &&
        packet->state != RC_ARMED &&
        packet->state != RC_FAILSAFE)
    {
        return 0;
    }

    if (packet->throttle < 0 || packet->throttle > 1000)
    {
        return 0;
    }

    if (packet->yaw < -1000 || packet->yaw > 1000)
    {
        return 0;
    }

    if (packet->pitch < -1000 || packet->pitch > 1000)
    {
        return 0;
    }

    if (packet->roll < -1000 || packet->roll > 1000)
    {
        return 0;
    }

    return 1;
}

static void gateway_mavlink_dry_run(const rc_packet_t *packet)
{
#if GATEWAY_MAVLINK_DRY_RUN

    static uint32_t dry_run_count = 0;

    if (packet == NULL)
    {
        return;
    }

    int16_t x_pitch = gateway_clamp_i16(packet->pitch, -1000, 1000);
    int16_t y_roll = gateway_clamp_i16(packet->roll, -1000, 1000);
    int16_t z_throttle = gateway_clamp_i16(packet->throttle, 0, 1000);
    int16_t r_yaw = gateway_clamp_i16(packet->yaw, -1000, 1000);

    /*
        Safety rule:
        if remote is not ARMED, gateway would send neutral controls.
    */
    uint8_t fc_heartbeat_fresh = gateway_fc_heartbeat_is_fresh();

    if (packet->state != RC_ARMED ||
        !fc_heartbeat_fresh ||
        !gateway_fc_is_armed)
    {
        x_pitch = 0;
        y_roll = 0;
        z_throttle = 0;
        r_yaw = 0;
    }

    dry_run_count++;

    if (dry_run_count == 1 || (dry_run_count % GATEWAY_DRY_RUN_PRINT_EVERY) == 0)
    {
        printf("[GATEWAY MAVLINK DRY RUN] packet_id=%lu remote=%s fc=%s fc_fresh=%u x_pitch=%d y_roll=%d z_throttle=%d r_yaw=%d\n",
               (unsigned long)packet->packet_id,
               state_to_string(packet->state),
               gateway_fc_arm_state_to_string(gateway_fc_is_armed),
               fc_heartbeat_fresh,
               x_pitch,
               y_roll,
               z_throttle,
               r_yaw);
    }

#endif
}
static void gateway_arm_disarm_dry_run(const rc_packet_t *packet)
{
#if GATEWAY_ARM_DISARM_DRY_RUN

    static uint8_t initialized = 0;
    static rc_state_t last_remote_state = RC_DISARMED;

    if (packet == NULL)
    {
        return;
    }

    if (!initialized)
    {
        last_remote_state = packet->state;
        initialized = 1;
        return;
    }

    if (packet->state == last_remote_state)
    {
        return;
    }

    uint8_t fc_fresh = gateway_fc_heartbeat_is_fresh();

    if (packet->state == RC_ARMED)
    {
        gateway_last_action = GATEWAY_ACTION_ARM_DRY_RUN;

        printf("[GATEWAY ARM DRY RUN] remote changed to ARMED packet_id=%lu fc=%s fc_fresh=%u ACTION=PRINT_ONLY\n",
               (unsigned long)packet->packet_id,
               gateway_fc_arm_state_to_string(gateway_fc_is_armed),
               fc_fresh);
    }
    else if (packet->state == RC_DISARMED)
    {
        gateway_last_action = GATEWAY_ACTION_DISARM_DRY_RUN;

        printf("[GATEWAY DISARM DRY RUN] remote changed to DISARMED packet_id=%lu fc=%s fc_fresh=%u ACTION=PRINT_ONLY\n",
               (unsigned long)packet->packet_id,
               gateway_fc_arm_state_to_string(gateway_fc_is_armed),
               fc_fresh);
    }
    else if (packet->state == RC_FAILSAFE)
    {
        gateway_last_action = GATEWAY_ACTION_FAILSAFE_DRY_RUN;

        printf("[GATEWAY FAILSAFE DRY RUN] remote changed to FAILSAFE packet_id=%lu fc=%s fc_fresh=%u ACTION=PRINT_ONLY\n",
               (unsigned long)packet->packet_id,
               gateway_fc_arm_state_to_string(gateway_fc_is_armed),
               fc_fresh);
    }

    last_remote_state = packet->state;

#endif
}

static void gateway_handle_frame(const uint8_t *frame, size_t frame_len)
{
    static uint32_t ok_count = 0;
    static uint32_t bad_count = 0;
    static uint32_t replay_count = 0;

    static uint32_t last_sequence = 0;
    static uint32_t last_session_id = 0;
    static int has_session = 0;

    mathos_secure_packet_t packet;

    mathos_status_t status = mathos_wire_decode(
        frame,
        frame_len,
        &packet);

    if (status != MATHOS_STATUS_OK)
    {
        bad_count++;
        gateway_rx_bad_count = bad_count;

        if ((bad_count % 20) == 1)
        {
            printf("[GATEWAY] frame BAD status=%s bad_count=%lu len=%u\n",
                   mathos_status_to_string(status),
                   (unsigned long)bad_count,
                   (unsigned int)frame_len);
        }

        return;
    }

    /*
        Only decrypt AFTER wire decode succeeds.
        If wire decode failed, packet contents are not trusted.
    */
    mathos_secure_status_t crypto_status = mathos_secure_decrypt_packet(&packet);

    if (crypto_status != MATHOS_SECURE_STATUS_OK)
    {
        bad_count++;
gateway_rx_bad_count = bad_count;
        if ((bad_count % 20) == 1)
        {
            printf("[GATEWAY] crypto BAD status=%s bad_count=%lu len=%u\n",
                   mathos_secure_status_to_string(crypto_status),
                   (unsigned long)bad_count,
                   (unsigned int)frame_len);
        }

        return;
    }

    /*
        DEV MODE:
        packet.timestamp_ms is currently used as session_id.

        Same session:
            sequence must increase.

        New session:
            remote probably rebooted, so sequence can safely restart.
    */
    uint32_t session_id = packet.timestamp_ms;

    if (!has_session || session_id != last_session_id)
    {
        printf("[GATEWAY] NEW SESSION old=0x%08lx new=0x%08lx reset last_sequence\n",
               (unsigned long)last_session_id,
               (unsigned long)session_id);

        last_session_id = session_id;
        last_sequence = 0;
        has_session = 1;
    }

    if (packet.sequence <= last_sequence)
    {
        replay_count++;
gateway_rx_replay_count = replay_count;
        printf("[GATEWAY] REPLAY/OLD session=0x%08lx seq=%lu last=%lu replay_count=%lu\n",
               (unsigned long)session_id,
               (unsigned long)packet.sequence,
               (unsigned long)last_sequence,
               (unsigned long)replay_count);

        return;
    }

    last_sequence = packet.sequence;
    ok_count++;
gateway_rx_ok_count = ok_count;
gateway_last_remote_packet_tick = xTaskGetTickCount();
    rc_packet_t rc_packet;
    memset(&rc_packet, 0, sizeof(rc_packet));

    if (packet.payload_len == sizeof(rc_packet_t))
    {
        memcpy(&rc_packet, packet.payload, sizeof(rc_packet_t));
    }
    else
    {
        printf("[GATEWAY] invalid RC payload size. got=%u expected=%u seq=%lu\n",
               packet.payload_len,
               (unsigned int)sizeof(rc_packet_t),
               (unsigned long)packet.sequence);

        return;
    }

    if (!gateway_rc_packet_is_valid(&rc_packet))
    {
        printf("[GATEWAY] decrypted RC INVALID packet_id=%lu state=%d throttle=%d yaw=%d pitch=%d roll=%d seq=%lu\n",
               (unsigned long)rc_packet.packet_id,
               rc_packet.state,
               rc_packet.throttle,
               rc_packet.yaw,
               rc_packet.pitch,
               rc_packet.roll,
               (unsigned long)packet.sequence);

        return;
    }
gateway_last_remote_state = rc_packet.state;
    gateway_arm_disarm_dry_run(&rc_packet);
    gateway_mavlink_dry_run(&rc_packet);

    if (ok_count == 1 || (ok_count % GATEWAY_PRINT_EVERY) == 0)
    {
        printf("[GATEWAY] frame OK count=%lu len=%u session=0x%08lx seq=%lu controller=%u link=%u payload_type=%u payload_len=%u\n",
               (unsigned long)ok_count,
               (unsigned int)frame_len,
               (unsigned long)session_id,
               (unsigned long)packet.sequence,
               packet.controller_id,
               packet.link_id,
               packet.payload_type,
               packet.payload_len);

        if (packet.payload_len == sizeof(rc_packet_t))
        {
            printf("[GATEWAY] RC packet_id=%lu state=%s throttle=%d yaw=%d pitch=%d roll=%d\n",
                   (unsigned long)rc_packet.packet_id,
                   state_to_string(rc_packet.state),
                   rc_packet.throttle,
                   rc_packet.yaw,
                   rc_packet.pitch,
                   rc_packet.roll);
        }
        else
        {
            printf("[GATEWAY] unexpected RC payload size. got=%u expected=%u\n",
                   packet.payload_len,
                   (unsigned int)sizeof(rc_packet_t));
        }
    }
}

static void gateway_process_byte(uint8_t byte)
{
    static uint8_t frame[MATHOS_WIRE_MAX_FRAME_LEN];
    static size_t frame_index = 0;
    static size_t expected_frame_len = 0;

    if (frame_index == 0)
    {
        if (byte != MATHOS_WIRE_MAGIC_0)
        {
            return;
        }

        frame[frame_index++] = byte;
        expected_frame_len = 0;
        return;
    }

    if (frame_index == 1)
    {
        if (byte == MATHOS_WIRE_MAGIC_1)
        {
            frame[frame_index++] = byte;
            return;
        }

        if (byte == MATHOS_WIRE_MAGIC_0)
        {
            frame[0] = byte;
            frame_index = 1;
            expected_frame_len = 0;
            return;
        }

        frame_index = 0;
        expected_frame_len = 0;
        return;
    }

    if (frame_index >= sizeof(frame))
    {
        frame_index = 0;
        expected_frame_len = 0;
        return;
    }

    frame[frame_index++] = byte;

    if (frame_index == 6)
    {
        expected_frame_len = gateway_get_u16_le(&frame[4]);

        if (expected_frame_len < (MATHOS_WIRE_HEADER_LEN + MATHOS_AUTH_TAG_LEN + MATHOS_WIRE_CRC_LEN) ||
            expected_frame_len > MATHOS_WIRE_MAX_FRAME_LEN)
        {
            printf("[GATEWAY] bad declared frame length=%u\n",
                   (unsigned int)expected_frame_len);

            frame_index = 0;
            expected_frame_len = 0;
            return;
        }
    }

    if (expected_frame_len > 0 && frame_index >= expected_frame_len)
    {
        gateway_handle_frame(frame, expected_frame_len);

        frame_index = 0;
        expected_frame_len = 0;
    }
}

static void gateway_rx_task(void *pvParameters)
{
    uint8_t rx_buffer[GATEWAY_RX_BUFFER_SIZE];

    printf("[GATEWAY] RX task started. Waiting for Mathos frames...\n");

    while (1)
    {
        int len = uart_read_bytes(
            GATEWAY_UART_PORT,
            rx_buffer,
            sizeof(rx_buffer),
            pdMS_TO_TICKS(100));

        if (len > 0)
        {
#if DEBUG_GATEWAY_RX_BYTES
            static uint32_t rx_total = 0;
            rx_total += len;

            if ((rx_total % 500) < len)
            {
                printf("[GATEWAY] RX bytes total=%lu last_len=%d first=0x%02X\n",
                       (unsigned long)rx_total,
                       len,
                       rx_buffer[0]);
            }
#endif

            for (int i = 0; i < len; i++)
            {
                gateway_process_byte(rx_buffer[i]);
            }
        }
    }
}

static void gateway_mav_put_u32_le(uint8_t *buffer, int *index, uint32_t value)
{
    buffer[(*index)++] = (uint8_t)((value >> 0) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 8) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 16) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 24) & 0xFF);
}

static void gateway_mavlink_crc_accumulate(uint8_t data, uint16_t *crc)
{
    uint8_t tmp = data ^ (uint8_t)(*crc & 0xFF);
    tmp ^= (tmp << 4);

    *crc = (*crc >> 8) ^
           ((uint16_t)tmp << 8) ^
           ((uint16_t)tmp << 3) ^
           ((uint16_t)tmp >> 4);
}

static uint16_t gateway_mavlink_crc_calculate(
    const uint8_t *data,
    int len,
    uint8_t crc_extra)
{
    uint16_t crc = 0xFFFF;

    for (int i = 0; i < len; i++)
    {
        gateway_mavlink_crc_accumulate(data[i], &crc);
    }

    gateway_mavlink_crc_accumulate(crc_extra, &crc);

    return crc;
}

static void gateway_handle_fc_heartbeat(
    uint8_t sys_id,
    uint8_t comp_id,
    const uint8_t *payload,
    uint8_t payload_len)
{
    if (payload == NULL || payload_len < MAVLINK_MSG_HEARTBEAT_LEN)
    {
        return;
    }

    uint8_t type = payload[4];
    uint8_t autopilot = payload[5];
    uint8_t base_mode = payload[6];
    uint8_t system_status = payload[7];
/*
    Ignore our own GCS heartbeat.
    Trust only the real FC/autopilot heartbeat.
*/
if (sys_id == GATEWAY_MAVLINK_SYS_ID && comp_id == GATEWAY_MAVLINK_COMP_ID)
{
    return;
}

if (autopilot == MAV_AUTOPILOT_INVALID)
{
    return;
}
    uint8_t armed = (base_mode & MAV_MODE_FLAG_SAFETY_ARMED) != 0;

    gateway_fc_heartbeat_count++;
    gateway_fc_last_heartbeat_tick = xTaskGetTickCount();
    gateway_fc_is_armed = armed;

    if (gateway_fc_heartbeat_count == 1 ||
        (gateway_fc_heartbeat_count % GATEWAY_FC_HEARTBEAT_PRINT_EVERY) == 0)
    {
        printf("[GATEWAY FC HEARTBEAT] count=%lu sys=%u comp=%u type=%u autopilot=%u base_mode=0x%02X status=%u FC=%s\n",
               (unsigned long)gateway_fc_heartbeat_count,
               sys_id,
               comp_id,
               type,
               autopilot,
               base_mode,
               system_status,
               gateway_fc_arm_state_to_string(armed));
    }
}
static void gateway_handle_fc_mavlink2_frame(const uint8_t *frame, size_t frame_len)
{
    if (frame == NULL || frame_len < 12)
    {
        return;
    }

    uint8_t payload_len = frame[1];
    uint8_t incompat_flags = frame[2];

    size_t signature_len = 0;

    if ((incompat_flags & 0x01) != 0)
    {
        signature_len = 13;
    }

    size_t expected_len = 10 + payload_len + 2 + signature_len;

    if (frame_len != expected_len)
    {
        return;
    }

    uint8_t sys_id = frame[5];
    uint8_t comp_id = frame[6];

    uint32_t msg_id =
        ((uint32_t)frame[7] << 0) |
        ((uint32_t)frame[8] << 8) |
        ((uint32_t)frame[9] << 16);

    uint8_t crc_extra = 0;

    if (msg_id == MAVLINK_MSG_ID_HEARTBEAT)
    {
        crc_extra = MAVLINK_MSG_HEARTBEAT_CRC_EXTRA;
    }
    else
    {
        return;
    }

    uint16_t rx_crc =
        ((uint16_t)frame[10 + payload_len] << 0) |
        ((uint16_t)frame[10 + payload_len + 1] << 8);

    uint16_t calc_crc = gateway_mavlink_crc_calculate(
        &frame[1],
        9 + payload_len,
        crc_extra);

    if (rx_crc != calc_crc)
    {
        printf("[GATEWAY FC MAVLINK] BAD CRC msg=%lu rx=0x%04X calc=0x%04X\n",
               (unsigned long)msg_id,
               rx_crc,
               calc_crc);

        return;
    }

    gateway_handle_fc_heartbeat(
        sys_id,
        comp_id,
        &frame[10],
        payload_len);
}

static void gateway_handle_fc_mavlink1_frame(const uint8_t *frame, size_t frame_len)
{
    if (frame == NULL || frame_len < 8)
    {
        return;
    }

    uint8_t payload_len = frame[1];

    size_t expected_len = 6 + payload_len + 2;

    if (frame_len != expected_len)
    {
        return;
    }

    uint8_t sys_id = frame[3];
    uint8_t comp_id = frame[4];
    uint8_t msg_id = frame[5];

    uint8_t crc_extra = 0;

    if (msg_id == MAVLINK_MSG_ID_HEARTBEAT)
    {
        crc_extra = MAVLINK_MSG_HEARTBEAT_CRC_EXTRA;
    }
    else
    {
        return;
    }

    uint16_t rx_crc =
        ((uint16_t)frame[6 + payload_len] << 0) |
        ((uint16_t)frame[6 + payload_len + 1] << 8);

    uint16_t calc_crc = gateway_mavlink_crc_calculate(
        &frame[1],
        5 + payload_len,
        crc_extra);

    if (rx_crc != calc_crc)
    {
        printf("[GATEWAY FC MAVLINK] BAD CRC MAVLink1 msg=%u rx=0x%04X calc=0x%04X\n",
               msg_id,
               rx_crc,
               calc_crc);

        return;
    }

    gateway_handle_fc_heartbeat(
        sys_id,
        comp_id,
        &frame[6],
        payload_len);
}

static void gateway_fc_mavlink_process_byte(uint8_t byte)
{
    static uint8_t frame[MAVLINK_MAX_FRAME_LEN];
    static size_t frame_index = 0;
    static size_t expected_frame_len = 0;

    if (frame_index == 0)
    {
        if (byte != MAVLINK2_STX && byte != MAVLINK1_STX)
        {
            return;
        }

        frame[frame_index++] = byte;
        expected_frame_len = 0;
        return;
    }

    if (frame_index >= sizeof(frame))
    {
        frame_index = 0;
        expected_frame_len = 0;
        return;
    }

    frame[frame_index++] = byte;

    if (frame_index == 2)
    {
        uint8_t payload_len = frame[1];

        if (frame[0] == MAVLINK1_STX)
        {
            expected_frame_len = 6 + payload_len + 2;
        }
    }

    if (frame_index == 3)
    {
        uint8_t payload_len = frame[1];

        if (frame[0] == MAVLINK2_STX)
        {
            uint8_t incompat_flags = frame[2];
            size_t signature_len = 0;

            if ((incompat_flags & 0x01) != 0)
            {
                signature_len = 13;
            }

            expected_frame_len = 10 + payload_len + 2 + signature_len;
        }
    }

    if (expected_frame_len > sizeof(frame))
    {
        frame_index = 0;
        expected_frame_len = 0;
        return;
    }

    if (expected_frame_len > 0 && frame_index >= expected_frame_len)
    {
        if (frame[0] == MAVLINK2_STX)
        {
            gateway_handle_fc_mavlink2_frame(frame, expected_frame_len);
        }
        else if (frame[0] == MAVLINK1_STX)
        {
            gateway_handle_fc_mavlink1_frame(frame, expected_frame_len);
        }

        frame_index = 0;
        expected_frame_len = 0;
    }
}
static void gateway_fc_mavlink_rx_task(void *pvParameters)
{
    uint8_t rx_buffer[128];

    printf("[GATEWAY FC MAVLINK] RX task started\n");

    while (1)
    {
        int len = uart_read_bytes(
            GATEWAY_FC_UART_PORT,
            rx_buffer,
            sizeof(rx_buffer),
            pdMS_TO_TICKS(100));

        if (len > 0)
        {
            for (int i = 0; i < len; i++)
            {
                gateway_fc_mavlink_process_byte(rx_buffer[i]);
            }
        }
    }
}
static int gateway_fc_uart_init(void)
{
#if GATEWAY_FC_UART_ENABLE

    printf("[GATEWAY FC UART] MAVLink tx=%d rx=%d baud=%d\n",
           GATEWAY_FC_UART_TX_PIN,
           GATEWAY_FC_UART_RX_PIN,
           GATEWAY_FC_UART_BAUD);

    uart_config_t uart_config = {
        .baud_rate = GATEWAY_FC_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_driver_install(
        GATEWAY_FC_UART_PORT,
        4096,
        4096,
        0,
        NULL,
        0));

    ESP_ERROR_CHECK(uart_param_config(
        GATEWAY_FC_UART_PORT,
        &uart_config));

    ESP_ERROR_CHECK(uart_set_pin(
        GATEWAY_FC_UART_PORT,
        GATEWAY_FC_UART_TX_PIN,
        GATEWAY_FC_UART_RX_PIN,
        UART_PIN_NO_CHANGE,
        UART_PIN_NO_CHANGE));

#endif

    return 1;
}

static int gateway_mavlink_send_message(
    uint32_t msg_id,
    const uint8_t *payload,
    uint8_t payload_len,
    uint8_t crc_extra)
{
#if GATEWAY_FC_UART_ENABLE

    uint8_t frame[10 + 255 + 2];
    int index = 0;

    frame[index++] = MAVLINK2_STX;
    frame[index++] = payload_len;
    frame[index++] = 0x00;
    frame[index++] = 0x00;
    frame[index++] = gateway_mavlink_tx_seq++;
    frame[index++] = GATEWAY_MAVLINK_SYS_ID;
    frame[index++] = GATEWAY_MAVLINK_COMP_ID;

    frame[index++] = (uint8_t)((msg_id >> 0) & 0xFF);
    frame[index++] = (uint8_t)((msg_id >> 8) & 0xFF);
    frame[index++] = (uint8_t)((msg_id >> 16) & 0xFF);

    if (payload_len > 0 && payload != NULL)
    {
        memcpy(&frame[index], payload, payload_len);
        index += payload_len;
    }

    uint16_t crc = gateway_mavlink_crc_calculate(
        &frame[1],
        9 + payload_len,
        crc_extra);

    frame[index++] = (uint8_t)(crc & 0xFF);
    frame[index++] = (uint8_t)((crc >> 8) & 0xFF);

    int written = uart_write_bytes(
        GATEWAY_FC_UART_PORT,
        (const char *)frame,
        index);

    return written == index;

#else

    return 1;

#endif
}

static int gateway_mavlink_send_heartbeat(void)
{
#if GATEWAY_MAVLINK_HEARTBEAT_ENABLE

    uint8_t payload[MAVLINK_MSG_HEARTBEAT_LEN];
    int p = 0;

    gateway_mav_put_u32_le(payload, &p, 0);

    payload[p++] = MAV_TYPE_GCS;
    payload[p++] = MAV_AUTOPILOT_INVALID;
    payload[p++] = MAV_MODE_FLAG_CUSTOM_MODE_ENABLED;
    payload[p++] = MAV_STATE_ACTIVE;
    payload[p++] = MAVLINK_VERSION_FIELD;

    if (p != MAVLINK_MSG_HEARTBEAT_LEN)
    {
        return 0;
    }

    return gateway_mavlink_send_message(
        MAVLINK_MSG_ID_HEARTBEAT,
        payload,
        MAVLINK_MSG_HEARTBEAT_LEN,
        MAVLINK_MSG_HEARTBEAT_CRC_EXTRA);

#else

    return 1;

#endif
}

static void gateway_mavlink_heartbeat_task(void *pvParameters)
{
    while (1)
    {
        if (!gateway_mavlink_send_heartbeat())
        {
            printf("[GATEWAY MAVLINK] HEARTBEAT send FAILED\n");
        }
        else
        {
            printf("[GATEWAY MAVLINK] HEARTBEAT sent to FC\n");
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
static const char *gateway_action_to_string(uint8_t action)
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

    default:
        return "UNKNOWN";
    }
}

static int gateway_status_send_once(void)
{
#if GATEWAY_STATUS_TX_ENABLE

    gateway_status_packet_t status;
    memset(&status, 0, sizeof(status));

    TickType_t now = xTaskGetTickCount();

    uint8_t remote_link_ok = 0;

    if (gateway_last_remote_packet_tick != 0 &&
        (now - gateway_last_remote_packet_tick) < pdMS_TO_TICKS(GATEWAY_REMOTE_LINK_FRESH_MS))
    {
        remote_link_ok = 1;
    }

    uint32_t seq = gateway_status_tx_sequence++;

    status.packet_id = seq;
    status.session_id = gateway_status_session_id;

    status.fc_heartbeat_fresh = gateway_fc_heartbeat_is_fresh();
    status.fc_is_armed = gateway_fc_is_armed;
    status.remote_state = (uint8_t)gateway_last_remote_state;
    status.gateway_link_ok = remote_link_ok;
    status.last_action = gateway_last_action;

    status.rx_ok_count = gateway_rx_ok_count;
    status.rx_bad_count = gateway_rx_bad_count;
    status.rx_replay_count = gateway_rx_replay_count;

    mathos_secure_packet_t packet;
    memset(&packet, 0, sizeof(packet));

    packet.sequence = seq;
    packet.timestamp_ms = status.session_id;
    packet.controller_id = MATHOS_GATEWAY_ID;
    packet.link_id = MATHOS_LINK_ID_STATUS;
    packet.payload_type = MATHOS_PAYLOAD_TYPE_GATEWAY_STATUS;
    packet.payload_len = sizeof(gateway_status_packet_t);

    if (packet.payload_len > MATHOS_PAYLOAD_MAX_LEN)
    {
        printf("[GATEWAY STATUS TX] payload too large=%u max=%u\n",
               packet.payload_len,
               MATHOS_PAYLOAD_MAX_LEN);
        return 0;
    }

    memcpy(packet.payload, &status, sizeof(status));

    mathos_secure_status_t crypto_status = mathos_secure_encrypt_packet(&packet);

    if (crypto_status != MATHOS_SECURE_STATUS_OK)
    {
        printf("[GATEWAY STATUS TX] encrypt failed status=%s\n",
               mathos_secure_status_to_string(crypto_status));
        return 0;
    }

    uint8_t wire_frame[MATHOS_WIRE_MAX_FRAME_LEN];
    size_t wire_frame_len = 0;

    mathos_status_t encode_status = mathos_wire_encode(
        &packet,
        wire_frame,
        sizeof(wire_frame),
        &wire_frame_len);

    if (encode_status != MATHOS_STATUS_OK)
    {
        printf("[GATEWAY STATUS TX] encode failed status=%s\n",
               mathos_status_to_string(encode_status));
        return 0;
    }

    int written = uart_write_bytes(
        GATEWAY_UART_PORT,
        (const char *)wire_frame,
        wire_frame_len);

    return written == wire_frame_len;

#else

    return 1;

#endif
}

static void gateway_status_tx_task(void *pvParameters)
{
    uint32_t print_counter = 0;

    printf("[GATEWAY STATUS TX] task started\n");

    while (1)
    {
        int ok = gateway_status_send_once();

        print_counter++;

        if (print_counter == 1 || (print_counter % 10) == 0)
        {
            printf("[GATEWAY STATUS TX] %s fc=%s fc_fresh=%u remote=%s action=%s ok_count=%lu bad_count=%lu replay_count=%lu\n",
                   ok ? "OK" : "FAILED",
                   gateway_fc_arm_state_to_string(gateway_fc_is_armed),
                   gateway_fc_heartbeat_is_fresh(),
                   state_to_string(gateway_last_remote_state),
                   gateway_action_to_string(gateway_last_action),
                   (unsigned long)gateway_rx_ok_count,
                   (unsigned long)gateway_rx_bad_count,
                   (unsigned long)gateway_rx_replay_count);
        }

        vTaskDelay(pdMS_TO_TICKS(GATEWAY_STATUS_TX_PERIOD_MS));
    }
}
void app_main(void)
{
    if (!gateway_fc_uart_init())
    {
        printf("[FATAL] gateway FC UART init failed\n");
        return;
    }

    printf("\n");
    printf("========================================\n");
    printf(" MATHOS DRONE GATEWAY v0.2.0\n");
    printf(" UART RX=%d TX=%d BAUD=%d\n",
           GATEWAY_UART_RX_PIN,
           GATEWAY_UART_TX_PIN,
           GATEWAY_UART_BAUD);
    printf("========================================\n");

    gateway_uart_init();
gateway_status_session_id = esp_random();

if (gateway_status_session_id == 0)
{
    gateway_status_session_id = 1;
}

printf("[GATEWAY STATUS] session_id=0x%08lx\n",
       (unsigned long)gateway_status_session_id);
    xTaskCreate(gateway_rx_task, "gateway_rx_task", 4096, NULL, 5, NULL);
    xTaskCreate(gateway_mavlink_heartbeat_task, "gateway_mavlink_heartbeat_task", 4096, NULL, 3, NULL);
    xTaskCreate(gateway_fc_mavlink_rx_task, "gateway_fc_mavlink_rx_task", 4096, NULL, 4, NULL);
    xTaskCreate(gateway_status_tx_task, "gateway_status_tx_task", 4096, NULL, 3, NULL);
}