#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/uart.h"
#include "esp_err.h"

#include "mathos_protocol.h"
#include "mathos_secure.h"

#define GATEWAY_UART_PORT UART_NUM_1
#define GATEWAY_UART_TX_PIN 8
#define GATEWAY_UART_RX_PIN 9
#define GATEWAY_UART_BAUD 115200

#define GATEWAY_RX_BUFFER_SIZE 256
#define GATEWAY_PRINT_EVERY 50

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

        printf("[GATEWAY] REPLAY/OLD session=0x%08lx seq=%lu last=%lu replay_count=%lu\n",
               (unsigned long)session_id,
               (unsigned long)packet.sequence,
               (unsigned long)last_sequence,
               (unsigned long)replay_count);

        return;
    }

    last_sequence = packet.sequence;
    ok_count++;

    rc_packet_t rc_packet;
    memset(&rc_packet, 0, sizeof(rc_packet));

    if (packet.payload_len == sizeof(rc_packet_t))
    {
        memcpy(&rc_packet, packet.payload, sizeof(rc_packet_t));
    }

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
            static uint32_t rx_total = 0;
            rx_total += len;

            if ((rx_total % 500) < len)
            {
                printf("[GATEWAY] RX bytes total=%lu last_len=%d first=0x%02X\n",
                       (unsigned long)rx_total,
                       len,
                       rx_buffer[0]);
            }

            for (int i = 0; i < len; i++)
            {
                gateway_process_byte(rx_buffer[i]);
            }
        }
    }
}

void app_main(void)
{
    printf("\n");
    printf("========================================\n");
    printf(" MATHOS DRONE GATEWAY v0.2.0\n");
    printf(" UART RX=%d TX=%d BAUD=%d\n",
           GATEWAY_UART_RX_PIN,
           GATEWAY_UART_TX_PIN,
           GATEWAY_UART_BAUD);
    printf("========================================\n");

    gateway_uart_init();

    xTaskCreate(gateway_rx_task, "gateway_rx_task", 4096, NULL, 5, NULL);
}