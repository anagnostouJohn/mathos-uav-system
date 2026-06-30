#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "driver/gpio.h"
#include <stdint.h>
#include <stdlib.h>
#include "freertos/queue.h"
#include "esp_err.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_system.h"
#include "led_strip.h"
#include <string.h>
#include "driver/spi_master.h"
#include "esp_timer.h"
#include "driver/uart.h"
#include "mathos_protocol.h"
#include "mathos_secure.h"
#include "esp_random.h"
////////////////////////////////////////////////////////////////////////////////////
#define COMMAND_STATUS_MESSAGE_CLEAR_MS 3000

#define DEBUG_CRYPTO_TAMPER_TEST 0
#define CRYPTO_TAMPER_EVERY 200

#define BENCH_FAILSAFE_DISARM 1

#define FC_ARM_PENDING_TIMEOUT_MS 3000

#define ONE_JOYSTICK_TEST 1

#define TEST_FIXED_MANUAL_CONTROL 0
#define TEST_ALLOW_MANUAL_WHILE_DISARMED 0

#define TEST_FIXED_THROTTLE 0
#define TEST_FIXED_YAW 200
#define TEST_FIXED_PITCH 300
#define TEST_FIXED_ROLL -300

#define JOYSTICK_RAW_DIAGNOSTIC 0
#define JOYSTICK_DIAG_PRINT_EVERY 200

#define BUTTON_PIN_ARM 12
#define BUTTON_PIN_FAILSAFE 13 //<<<<<<<<<<<<<<<<<<<
#define BUTTON_PIN_DISARM 14

#define RGB_LED_PIN 48
#define RGB_LED_COUNT 1

#define SWITCH_OPTIC_PIN 21
#define SWITCH_RF_PIN 47
#define MASTER_ENABLE_PIN 10
#define ARM_PERMISSION_SWITCH_PIN 2

#define JOYSTICK_PERIOD_MS 10
#define RADIO_TX_PERIOD_MS 20

#define RADIO_TX_MAX_WORK_MS 10
#define JOYSTICK_MAX_WORK_MS 10

//////////////////// LCD / ST7789 HARDWARE SPI
#define LCD_HOST SPI3_HOST

#define LCD_SCK 16
#define LCD_MOSI 15
#define LCD_DC 17
#define LCD_RST 18

#define LCD_W 240
#define LCD_H 240

#define COLOR_BLUE 0x001F
#define COLOR_BLACK 0x0000
#define COLOR_WHITE 0xFFFF
#define COLOR_RED 0xF800
#define COLOR_YELLOW 0xFFE0
//////////////////// LCD

//////////////////// UART

#define CONTROL_UART_PORT UART_NUM_1
#define CONTROL_UART_TX_PIN 8
#define CONTROL_UART_RX_PIN 9
#define CONTROL_UART_BAUD 115200

#define LINK_UART_PORT UART_NUM_2
#define LINK_UART_TX_PIN 38
#define LINK_UART_RX_PIN 39
#define LINK_UART_BAUD 115200

#define FEATURE_LINK_UART_TX 1

//////////////////// UART
//////////////////// MAVLINK
#define MAVLINK2_STX 0xFD

#define MAVLINK_TARGET_COMP_ID 1

#define MAVLINK_MSG_ID_COMMAND_LONG 76
#define MAVLINK_MSG_COMMAND_LONG_LEN 33
#define MAVLINK_MSG_COMMAND_LONG_CRC_EXTRA 152

#define MAV_CMD_COMPONENT_ARM_DISARM 400

#define MAVLINK_SYS_ID 255
#define MAVLINK_COMP_ID 190

#define MAVLINK_TARGET_SYS_ID 1

#define MAVLINK_MSG_ID_HEARTBEAT 0
#define MAVLINK_MSG_HEARTBEAT_LEN 9
#define MAVLINK_MSG_HEARTBEAT_CRC_EXTRA 50

#define MAVLINK_MSG_ID_MANUAL_CONTROL 69
#define MAVLINK_MSG_MANUAL_CONTROL_LEN 11
#define MAVLINK_MSG_MANUAL_CONTROL_CRC_EXTRA 243

#define MAV_TYPE_GCS 6
#define MAV_AUTOPILOT_INVALID 8
#define MAV_MODE_FLAG_CUSTOM_MODE_ENABLED 1
#define MAV_STATE_ACTIVE 4
#define MAVLINK_VERSION_FIELD 3

#define MAV_MODE_FLAG_SAFETY_ARMED 128

#define MAVLINK2_SIGNATURE_LEN 13
#define MAVLINK_RX_FRAME_MAX_LEN (10 + 255 + 2 + MAVLINK2_SIGNATURE_LEN)

#define MAVLINK_MSG_ID_COMMAND_ACK 77
#define MAVLINK_MSG_COMMAND_ACK_CRC_EXTRA 143

#define MAV_RESULT_ACCEPTED 0
#define MAV_RESULT_TEMPORARILY_REJECTED 1
#define MAV_RESULT_DENIED 2
#define MAV_RESULT_UNSUPPORTED 3
#define MAV_RESULT_FAILED 4
#define MAV_RESULT_IN_PROGRESS 5
#define MAV_RESULT_CANCELLED 6
//////////////////// MAVLINK
#define JOY_X_ADC ADC_CHANNEL_5 // GPIO6
#define JOY_Y_ADC ADC_CHANNEL_6 // GPIO7

#define JOY2_X_ADC ADC_CHANNEL_3 // GPIO4
#define JOY2_Y_ADC ADC_CHANNEL_4 // GPIO5

#define ROLL_RAW_MIN 317
#define ROLL_RAW_CENTER 2000
#define ROLL_RAW_MAX 4095

#define PITCH_RAW_MIN 429
#define PITCH_RAW_CENTER 2300
#define PITCH_RAW_MAX 4095

#define AXIS_DEADZONE_RAW 120

#define ROLL_INVERT 0
#define PITCH_INVERT 1

#define MIN_FREE_HEAP_BYTES 30000
#define MIN_STACK_WATERMARK 512

#define ARM_THROTTLE_MAX 50
#define ARM_STICK_MAX 100

#define DEBUG_SERIAL 1

#define DEBUG_MAVLINK_TX 0
#define DEBUG_SECURITY_PACKET 0
#define DEBUG_SECURITY_TIMING 1
#define DEBUG_HEARTBEAT_TX 0
#define DEBUG_MAVLINK_RX_CRC 0
#define DEBUG_SECURE_WIRE_TEST 1
#define SECURE_WIRE_TEST_PRINT_EVERY 100
///////////////////FEATURE FLAGS//////////////////
#define FEATURE_SECURITY_SKELETON 1
#define FEATURE_WIFI_TELEMETRY 0
#define FEATURE_SECURE_GATEWAY_MODE 1
#define FEATURE_DIRECT_MAVLINK_MODE 0

#if FEATURE_DIRECT_MAVLINK_MODE && FEATURE_SECURE_GATEWAY_MODE
#error "Only one control mode can be enabled: DIRECT MAVLINK or SECURE GATEWAY"
#endif

#if !FEATURE_DIRECT_MAVLINK_MODE && !FEATURE_SECURE_GATEWAY_MODE
#error "One control mode must be enabled"
#endif

///////////////////FEATURE FLAGS//////////////////

//////////////////// SECURITY LAYER

#define SECURITY_SKELETON_DIAGNOSTIC FEATURE_SECURITY_SKELETON

#define SECURITY_CONTROLLER_ID 1
#define SECURITY_LINK_ID_LOCAL_TEST 0

#define SECURITY_PAYLOAD_TYPE_RC 1
#define SECURITY_GATEWAY_ID 2
#define SECURITY_PAYLOAD_TYPE_GATEWAY_STATUS 2

#define LINK_RX_BUFFER_SIZE 128
#define GATEWAY_STATUS_FRESH_MS 1000
#define SECURITY_PAYLOAD_MAX_LEN 64
#define SECURITY_AUTH_TAG_LEN 16
#define SECURITY_TIMING_DIAGNOSTIC DEBUG_SECURITY_TIMING
#define SECURITY_TIMING_PRINT_EVERY 100
#define SECURITY_TIMING_WARN_US 1000
//////////////////// SECURITY LAYER
#if DEBUG_SERIAL
#define DBG_PRINT(...) printf(__VA_ARGS__)
#else
#define DBG_PRINT(...) \
    do                 \
    {                  \
    } while (0)
#endif

typedef enum
{
    ARM_STATUS_READY = 0,
    ARM_STATUS_MASTER_OFF,
    ARM_STATUS_ARM_LOCKED,
    ARM_STATUS_BOOT_LOCK,
    ARM_STATUS_INPUT_STALE,
    ARM_STATUS_STICKS_NOT_CENTERED,
    ARM_STATUS_TELEMETRY_STALE,
    ARM_STATUS_LINK_BAD,
    ARM_STATUS_DRONE_FAILSAFE,
    ARM_STATUS_THROTTLE_HIGH,
    ARM_STATUS_SYSTEM_FAULT
} arm_status_t;

typedef enum
{
    FAULT_NONE = 0,
    FAULT_JOYSTICK_STALE = 1 << 0,
    FAULT_TELEMETRY_STALE = 1 << 1,
    FAULT_DRONE_LINK_BAD = 1 << 2,
    FAULT_DRONE_FAILSAFE = 1 << 3,
    FAULT_STACK_LOW = 1 << 4,
    FAULT_HEAP_LOW = 1 << 5,
    FAULT_BAD_PACKETS = 1 << 6,
    FAULT_ARM_SWITCH_OFF = 1 << 7,
    FAULT_TASK_STALLED = 1 << 8,
    FAULT_CONTROL_TIMING = 1 << 9,
    FAULT_OUTPUT_FAILED = 1 << 10,
    FAULT_MASTER_SWITCH_OFF = 1 << 11,
    FAULT_ARM_BOOT_LOCK = 1 << 12,
    FAULT_PACKET_SEQUENCE = 1 << 13
} system_fault_t;

typedef enum
{
    RC_DISARMED = 0,
    RC_ARMED = 1,
    RC_FAILSAFE = 2
} rc_state_t;

typedef enum
{
    COMMAND_STATUS_IDLE = 0,
    COMMAND_STATUS_ARMING,
    COMMAND_STATUS_DISARMING,
    COMMAND_STATUS_DENIED,
    COMMAND_STATUS_TIMEOUT
} command_status_t;

typedef enum
{
    EVENT_BUTTON_ARM_PRESS = 0,
    EVENT_BUTTON_DISARM_PRESS,
    EVENT_BUTTON_FAILSAFE_PRESS
} rc_event_type_t;

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
    GATEWAY_ACTION_FAILSAFE_DRY_RUN,

    GATEWAY_ACTION_ARM_REAL_SENT,
    GATEWAY_ACTION_DISARM_REAL_SENT,
    GATEWAY_ACTION_ARM_CONFIRMED,
    GATEWAY_ACTION_DISARM_CONFIRMED,
    GATEWAY_ACTION_ARM_DENIED,
    GATEWAY_ACTION_DISARM_DENIED,
    GATEWAY_ACTION_ARM_TIMEOUT,
    GATEWAY_ACTION_DISARM_TIMEOUT
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

typedef struct
{
    uint32_t sequence;
    uint32_t timestamp_ms;

    uint8_t controller_id;
    uint8_t link_id;
    uint8_t payload_type;
    uint8_t payload_len;

    uint8_t payload[SECURITY_PAYLOAD_MAX_LEN];
    uint8_t auth_tag[SECURITY_AUTH_TAG_LEN];

} secure_packet_t;

typedef enum
{
    SECURITY_STATUS_OK = 0,
    SECURITY_STATUS_BAD_ARGUMENT,
    SECURITY_STATUS_BAD_CONTROLLER,
    SECURITY_STATUS_BAD_PAYLOAD_TYPE,
    SECURITY_STATUS_BAD_LENGTH,
    SECURITY_STATUS_REPLAY,
    SECURITY_STATUS_BAD_TAG

} security_status_t;

typedef struct
{
    uint32_t count;
    uint32_t ok_count;
    uint32_t fail_count;

    int64_t last_us;
    int64_t max_us;
    int64_t total_us;

} security_timing_stats_t;

typedef struct
{
    rc_event_type_t type;
} rc_event_t;

typedef struct
{
    int throttle;
    int yaw;
    int pitch;
    int roll;
    int valid;
} rc_input_t;

typedef enum
{
    HB_LED = 0,
    HB_RADIO_TX,
    HB_JOYSTICK,
    HB_SYSTEM_HEALTH,
    HB_LINK_MODE,
    HB_ARM_SAFETY,
    HB_LCD,
    HB_MAVLINK_RX,
    HB_COUNT
} heartbeat_id_t;

typedef enum
{
    LINK_MODE_AUTO = 0,
    LINK_MODE_FORCE_OPTIC,
    LINK_MODE_FORCE_RF
} link_mode_t;

static adc_oneshot_unit_handle_t adc1_handle;

volatile uint32_t system_faults = FAULT_NONE;
volatile TickType_t task_heartbeat[HB_COUNT];
volatile TickType_t rc_input_last_update_tick = 0;
volatile TickType_t telemetry_last_update_tick = 0;
volatile TickType_t fc_arm_pending_start_tick = 0;
volatile TickType_t fc_disarm_pending_start_tick = 0;
volatile TickType_t gateway_status_last_update_tick = 0;
volatile rc_state_t drone_state = RC_DISARMED;
volatile rc_state_t drone_command_state = RC_DISARMED;
volatile command_status_t command_status = COMMAND_STATUS_IDLE;
volatile TickType_t command_status_last_change_tick = 0;

volatile int telemetry_valid = 0;
volatile int drone_link_ok = 0;
volatile int arm_boot_latch_active = 0;
volatile int fc_heartbeat_seen = 0;
volatile int fc_is_armed = 0;
volatile int fc_arm_pending = 0;
volatile int fc_disarm_pending = 0;

volatile int gateway_status_valid = 0;

volatile uint8_t fc_system_id = 0;
volatile uint8_t fc_component_id = 0;
volatile uint8_t fc_type = 0;
volatile uint8_t fc_autopilot = 0;
volatile uint8_t fc_base_mode = 0;
volatile uint8_t fc_system_status = 0;
volatile uint32_t fc_custom_mode = 0;
static uint32_t mathos_session_id = 1;
static gateway_status_packet_t gateway_status_snapshot = {0};
volatile rc_input_t rc_input = {
    .throttle = 0,
    .yaw = 0,
    .pitch = 0,
    .roll = 0,
    .valid = 0};

led_strip_handle_t strip;

portMUX_TYPE rc_input_mux = portMUX_INITIALIZER_UNLOCKED;
portMUX_TYPE fault_mux = portMUX_INITIALIZER_UNLOCKED;
portMUX_TYPE state_mux = portMUX_INITIALIZER_UNLOCKED;
portMUX_TYPE heartbeat_mux = portMUX_INITIALIZER_UNLOCKED;
portMUX_TYPE security_mux = portMUX_INITIALIZER_UNLOCKED;
portMUX_TYPE gateway_status_mux = portMUX_INITIALIZER_UNLOCKED;

SemaphoreHandle_t button_semaphore_arm = NULL;
SemaphoreHandle_t button_semaphore_failsafe = NULL;
SemaphoreHandle_t button_semaphore_disarm = NULL;

QueueHandle_t rc_event_queue = NULL;

TaskHandle_t status_led_task_handle = NULL;
TaskHandle_t button_task_arm_handle = NULL;
TaskHandle_t button_task_disarm_handle = NULL;
TaskHandle_t button_task_failsafe_handle = NULL;
TaskHandle_t controller_task_handle = NULL;
TaskHandle_t radio_tx_task_handle = NULL;
TaskHandle_t joystick_adc_task_handle = NULL;
TaskHandle_t system_health_task_handle = NULL;
TaskHandle_t link_mode_task_handle = NULL;
TaskHandle_t arm_safety_task_handle = NULL;
TaskHandle_t lcd_task_handle = NULL;
TaskHandle_t heartbeat_task_handle = NULL;
TaskHandle_t mavlink_heartbeat_task_handle = NULL;
TaskHandle_t mavlink_rx_task_handle = NULL;
TaskHandle_t gateway_status_rx_task_handle = NULL;
TaskHandle_t command_status_auto_clear_task_handle = NULL;

static spi_device_handle_t lcd_spi = NULL;
static uint8_t mavlink_tx_seq = 0;
static uint32_t security_tx_sequence = 1;
static security_timing_stats_t security_timing_stats = {0};
static const uint8_t font_5x7[37][7] = {
    // A
    {0b01110, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001},
    // B
    {0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110},
    // C
    {0b01110, 0b10001, 0b10000, 0b10000, 0b10000, 0b10001, 0b01110},
    // D
    {0b11110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b11110},
    // E
    {0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b11111},
    // F
    {0b11111, 0b10000, 0b10000, 0b11110, 0b10000, 0b10000, 0b10000},
    // G
    {0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01110},
    // H
    {0b10001, 0b10001, 0b10001, 0b11111, 0b10001, 0b10001, 0b10001},
    // I
    {0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b11111},
    // J
    {0b00111, 0b00010, 0b00010, 0b00010, 0b10010, 0b10010, 0b01100},
    // K
    {0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001},
    // L
    {0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b10000, 0b11111},
    // M
    {0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001},
    // N
    {0b10001, 0b11001, 0b10101, 0b10011, 0b10001, 0b10001, 0b10001},
    // O
    {0b01110, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110},
    // P
    {0b11110, 0b10001, 0b10001, 0b11110, 0b10000, 0b10000, 0b10000},
    // Q
    {0b01110, 0b10001, 0b10001, 0b10001, 0b10101, 0b10010, 0b01101},
    // R
    {0b11110, 0b10001, 0b10001, 0b11110, 0b10100, 0b10010, 0b10001},
    // S
    {0b01111, 0b10000, 0b10000, 0b01110, 0b00001, 0b00001, 0b11110},
    // T
    {0b11111, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100, 0b00100},
    // U
    {0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01110},
    // V
    {0b10001, 0b10001, 0b10001, 0b10001, 0b10001, 0b01010, 0b00100},
    // W
    {0b10001, 0b10001, 0b10001, 0b10101, 0b10101, 0b10101, 0b01010},
    // X
    {0b10001, 0b10001, 0b01010, 0b00100, 0b01010, 0b10001, 0b10001},
    // Y
    {0b10001, 0b10001, 0b01010, 0b00100, 0b00100, 0b00100, 0b00100},
    // Z
    {0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b10000, 0b11111},

    // 0
    {0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110},
    // 1
    {0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110},
    // 2
    {0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111},
    // 3
    {0b11110, 0b00001, 0b00001, 0b01110, 0b00001, 0b00001, 0b11110},
    // 4
    {0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010},
    // 5
    {0b11111, 0b10000, 0b10000, 0b11110, 0b00001, 0b00001, 0b11110},
    // 6
    {0b01110, 0b10000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110},
    // 7
    {0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000},
    // 8
    {0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110},
    // 9
    {0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00001, 0b01110},

    // SPACE
    {0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b00000}};

void heartbeat_init_all(void)
{
    TickType_t now = xTaskGetTickCount();
    taskENTER_CRITICAL(&heartbeat_mux);
    for (int i = 0; i < HB_COUNT; i++)
    {
        task_heartbeat[i] = now;
    }
    taskEXIT_CRITICAL(&heartbeat_mux);
}

void heartbeat_mark(heartbeat_id_t id)
{
    if (id >= HB_COUNT)
    {
        return;
    }
    TickType_t now = xTaskGetTickCount();
    taskENTER_CRITICAL(&heartbeat_mux);
    task_heartbeat[id] = now;
    taskEXIT_CRITICAL(&heartbeat_mux);
}

uint32_t heartbeat_age_ms(heartbeat_id_t id)
{
    if (id >= HB_COUNT)
    {
        return 0xFFFFFFFF;
    }
    TickType_t last;
    TickType_t now = xTaskGetTickCount();
    taskENTER_CRITICAL(&heartbeat_mux);
    last = task_heartbeat[id];
    taskEXIT_CRITICAL(&heartbeat_mux);
    return pdTICKS_TO_MS(now - last);
}

static void lcd_delay_ms(int ms)
{
    vTaskDelay(pdMS_TO_TICKS(ms));
}

static void lcd_spi_send_bytes(const uint8_t *data, int len)
{
    spi_transaction_t t;
    memset(&t, 0, sizeof(t));

    t.length = len * 8;
    t.tx_buffer = data;

    ESP_ERROR_CHECK(spi_device_transmit(lcd_spi, &t));
}

static void lcd_spi_send_byte(uint8_t data)
{
    lcd_spi_send_bytes(&data, 1);
}

static void lcd_cmd(uint8_t cmd)
{
    gpio_set_level(LCD_DC, 0);
    lcd_spi_send_byte(cmd);
}

static void lcd_data(uint8_t data)
{
    gpio_set_level(LCD_DC, 1);
    lcd_spi_send_byte(data);
}

static void lcd_data16(uint16_t data)
{
    uint8_t bytes[2];

    bytes[0] = data >> 8;
    bytes[1] = data & 0xFF;

    gpio_set_level(LCD_DC, 1);
    lcd_spi_send_bytes(bytes, 2);
}

static void lcd_reset(void)
{
    gpio_set_level(LCD_RST, 1);
    lcd_delay_ms(100);

    gpio_set_level(LCD_RST, 0);
    lcd_delay_ms(100);

    gpio_set_level(LCD_RST, 1);
    lcd_delay_ms(200);
}

static void lcd_spi_init(void)
{
    spi_bus_config_t buscfg = {
        .sclk_io_num = LCD_SCK,
        .mosi_io_num = LCD_MOSI,
        .miso_io_num = -1,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = LCD_W * 2,
    };

    ESP_ERROR_CHECK(spi_bus_initialize(
        LCD_HOST,
        &buscfg,
        SPI_DMA_CH_AUTO));

    spi_device_interface_config_t devcfg = {
        .clock_speed_hz = 10 * 1000 * 1000,
        .mode = 3,
        .spics_io_num = -1,
        .queue_size = 1,
    };

    ESP_ERROR_CHECK(spi_bus_add_device(
        LCD_HOST,
        &devcfg,
        &lcd_spi));
}

static void lcd_init(void)
{
    lcd_reset();

    lcd_cmd(0x01);
    lcd_delay_ms(150);

    lcd_cmd(0x11);
    lcd_delay_ms(150);

    lcd_cmd(0x3A);
    lcd_data(0x55);
    lcd_delay_ms(10);

    lcd_cmd(0x36);
    lcd_data(0x00);

    lcd_cmd(0x21);

    lcd_cmd(0x13);
    lcd_delay_ms(10);

    lcd_cmd(0x29);
    lcd_delay_ms(100);
}

static void lcd_set_window(uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1)
{
    lcd_cmd(0x2A);
    lcd_data16(x0);
    lcd_data16(x1);

    lcd_cmd(0x2B);
    lcd_data16(y0);
    lcd_data16(y1);

    lcd_cmd(0x2C);
}

static void lcd_send_color(uint16_t color)
{
    uint8_t bytes[2];

    bytes[0] = color >> 8;
    bytes[1] = color & 0xFF;

    lcd_spi_send_bytes(bytes, 2);
}

static void lcd_fill_color(uint16_t color)
{
    static uint8_t line[LCD_W * 2];

    uint8_t hi = color >> 8;
    uint8_t lo = color & 0xFF;

    for (int x = 0; x < LCD_W; x++)
    {
        line[x * 2] = hi;
        line[x * 2 + 1] = lo;
    }

    lcd_set_window(0, 0, LCD_W - 1, LCD_H - 1);

    gpio_set_level(LCD_DC, 1);

    for (int y = 0; y < LCD_H; y++)
    {
        lcd_spi_send_bytes(line, sizeof(line));
    }
}

static void lcd_draw_rect(int x, int y, int w, int h, uint16_t color)
{
    if (x < 0 || y < 0 || x + w > LCD_W || y + h > LCD_H)
    {
        return;
    }

    lcd_set_window(x, y, x + w - 1, y + h - 1);

    gpio_set_level(LCD_DC, 1);

    for (int i = 0; i < w * h; i++)
    {
        lcd_send_color(color);
    }
}

static const uint8_t *get_font(char c)
{
    if (c >= 'a' && c <= 'z')
    {
        c = c - 'a' + 'A';
    }

    if (c >= 'A' && c <= 'Z')
    {
        return font_5x7[c - 'A'];
    }

    if (c >= '0' && c <= '9')
    {
        return font_5x7[26 + (c - '0')];
    }

    return font_5x7[36];
}
static int gateway_status_is_fresh(void)
{
    int valid;
    TickType_t last_update;

    taskENTER_CRITICAL(&gateway_status_mux);
    valid = gateway_status_valid;
    last_update = gateway_status_last_update_tick;
    taskEXIT_CRITICAL(&gateway_status_mux);

    if (!valid)
    {
        return 0;
    }

    TickType_t now = xTaskGetTickCount();

    if ((now - last_update) > pdMS_TO_TICKS(GATEWAY_STATUS_FRESH_MS))
    {
        return 0;
    }

    return 1;
}

static void lcd_draw_char(int x, int y, char c, int scale, uint16_t text_color, uint16_t bg_color)
{
    const uint8_t *glyph = get_font(c);

    for (int row = 0; row < 7; row++)
    {
        for (int col = 0; col < 5; col++)
        {
            int bit = (glyph[row] >> (4 - col)) & 0x01;
            uint16_t color = bit ? text_color : bg_color;

            lcd_draw_rect(
                x + col * scale,
                y + row * scale,
                scale,
                scale,
                color);
        }
    }
}

static void lcd_draw_text(int x, int y, const char *text, int scale, uint16_t text_color, uint16_t bg_color)
{
    int cursor_x = x;

    for (int i = 0; text[i] != '\0'; i++)
    {
        lcd_draw_char(cursor_x, y, text[i], scale, text_color, bg_color);
        cursor_x += 6 * scale;
    }
}

static int lcd_text_width(const char *text, int scale)
{
    return strlen(text) * 6 * scale;
}

static void lcd_draw_text_centered(int y, const char *text, int scale, uint16_t text_color, uint16_t bg_color)
{
    int width = lcd_text_width(text, scale);
    int x = (LCD_W - width) / 2;

    if (x < 0)
    {
        x = 0;
    }

    lcd_draw_text(x, y, text, scale, text_color, bg_color);
}

void fault_set(system_fault_t fault)
{
    taskENTER_CRITICAL(&fault_mux);
    system_faults |= fault;
    taskEXIT_CRITICAL(&fault_mux);
}

void fault_clear(system_fault_t fault)
{
    taskENTER_CRITICAL(&fault_mux);
    system_faults &= ~fault;
    taskEXIT_CRITICAL(&fault_mux);
}

int arm_boot_latch_is_active(void)
{
    return arm_boot_latch_active;
}

void print_fault_names(uint32_t faults)
{
    if (faults == FAULT_NONE)
    {
        printf(" NONE");
        return;
    }

    if (faults & FAULT_JOYSTICK_STALE)
    {
        printf(" JOYSTICK_STALE");
    }

    if (faults & FAULT_TELEMETRY_STALE)
    {
        printf(" TELEMETRY_STALE");
    }

    if (faults & FAULT_DRONE_LINK_BAD)
    {
        printf(" DRONE_LINK_BAD");
    }

    if (faults & FAULT_DRONE_FAILSAFE)
    {
        printf(" DRONE_FAILSAFE");
    }

    if (faults & FAULT_STACK_LOW)
    {
        printf(" STACK_LOW");
    }

    if (faults & FAULT_HEAP_LOW)
    {
        printf(" HEAP_LOW");
    }

    if (faults & FAULT_BAD_PACKETS)
    {
        printf(" BAD_PACKETS");
    }

    if (faults & FAULT_ARM_SWITCH_OFF)
    {
        printf(" ARM_SWITCH_OFF");
    }

    if (faults & FAULT_TASK_STALLED)
    {
        printf(" TASK_STALLED");
    }

    if (faults & FAULT_CONTROL_TIMING)
    {
        printf(" CONTROL_TIMING");
    }

    if (faults & FAULT_OUTPUT_FAILED)
    {
        printf(" OUTPUT_FAILED");
    }

    if (faults & FAULT_MASTER_SWITCH_OFF)
    {
        printf(" MASTER_SWITCH_OFF");
    }

    if (faults & FAULT_ARM_BOOT_LOCK)
    {
        printf(" ARM_BOOT_LOCK");
    }
    if (faults & FAULT_PACKET_SEQUENCE)
    {
        printf(" PACKET_SEQUENCE");
    }
}

void print_fault_snapshot(const char *prefix, uint32_t faults)
{
    printf("%s0x%08lx", prefix ? prefix : "", (unsigned long)faults);
    print_fault_names(faults);
    printf("\n");
}
uint32_t fault_get_snapshot(void)
{
    uint32_t snapshot;

    taskENTER_CRITICAL(&fault_mux);
    snapshot = system_faults;
    taskEXIT_CRITICAL(&fault_mux);

    return snapshot;
}

void create_task_checked(
    TaskFunction_t task_function,
    const char *task_name,
    uint32_t stack_size,
    void *parameters,
    UBaseType_t priority,
    TaskHandle_t *task_handle)
{
    BaseType_t result = xTaskCreate(
        task_function,
        task_name,
        stack_size,
        parameters,
        priority,
        task_handle);

    if (result != pdPASS)
    {
        printf("[FATAL] Failed to create task: %s\n", task_name);

        drone_command_state = RC_FAILSAFE;
        drone_state = RC_FAILSAFE;

        while (1)
        {
            led_strip_set_pixel(strip, 0, 255, 0, 0);
            led_strip_refresh(strip);
            vTaskDelay(pdMS_TO_TICKS(100));

            led_strip_clear(strip);
            led_strip_refresh(strip);
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }

    printf("[BOOT] Task created: %s\n", task_name);
}

const char *state_to_string(rc_state_t state)
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
const char *arm_status_to_lcd_text(arm_status_t status)
{
    switch (status)
    {
    case ARM_STATUS_READY:
        return "READY";

    case ARM_STATUS_MASTER_OFF:
        return "MASTER OFF";

    case ARM_STATUS_ARM_LOCKED:
        return "ARM LOCK";

    case ARM_STATUS_BOOT_LOCK:
        return "BOOT LOCK";

    case ARM_STATUS_INPUT_STALE:
        return "INPUT BAD";

    case ARM_STATUS_STICKS_NOT_CENTERED:
        return "STICK BAD";

    case ARM_STATUS_TELEMETRY_STALE:
        return "TEL STALE";

    case ARM_STATUS_LINK_BAD:
        return "LINK BAD";

    case ARM_STATUS_DRONE_FAILSAFE:
        return "DRONE FS";

    case ARM_STATUS_THROTTLE_HIGH:
        return "THROTTLE";

    case ARM_STATUS_SYSTEM_FAULT:
        return "SYS FAULT";

    default:
        return "UNKNOWN";
    }
}
const char *arm_status_to_log_text(arm_status_t status)
{
    switch (status)
    {
    case ARM_STATUS_READY:
        return "READY";

    case ARM_STATUS_MASTER_OFF:
        return "MASTER_OFF";

    case ARM_STATUS_ARM_LOCKED:
        return "ARM_SWITCH_LOCKED";

    case ARM_STATUS_BOOT_LOCK:
        return "ARM_BOOT_LOCK";

    case ARM_STATUS_INPUT_STALE:
        return "INPUT_STALE";

    case ARM_STATUS_STICKS_NOT_CENTERED:
        return "STICKS_NOT_CENTERED";

    case ARM_STATUS_TELEMETRY_STALE:
        return "TELEMETRY_STALE";

    case ARM_STATUS_LINK_BAD:
        return "LINK_BAD";

    case ARM_STATUS_DRONE_FAILSAFE:
        return "DRONE_FAILSAFE";

    case ARM_STATUS_THROTTLE_HIGH:
        return "THROTTLE_HIGH";

    case ARM_STATUS_SYSTEM_FAULT:
        return "SYSTEM_FAULT";

    default:
        return "UNKNOWN";
    }
}
const char *link_mode_to_string(link_mode_t mode)
{
    switch (mode)
    {
    case LINK_MODE_AUTO:
        return "AUTO";
    case LINK_MODE_FORCE_OPTIC:
        return "FORCE_OPTIC";
    case LINK_MODE_FORCE_RF:
        return "FORCE_RF";
    default:
        return "UNKNOWN";
    }
}
const char *command_status_to_string(command_status_t status)
{
    switch (status)
    {
    case COMMAND_STATUS_IDLE:
        return "IDLE";

    case COMMAND_STATUS_ARMING:
        return "ARMING";

    case COMMAND_STATUS_DISARMING:
        return "DISARMING";

    case COMMAND_STATUS_DENIED:
        return "DENIED";

    case COMMAND_STATUS_TIMEOUT:
        return "TIMEOUT";

    default:
        return "UNKNOWN";
    }
}

void command_status_set(command_status_t new_status, const char *reason)
{
    command_status_t old_status;
    int changed = 0;

    taskENTER_CRITICAL(&state_mux);

    old_status = command_status;

    if (command_status != new_status)
    {
command_status = new_status;
command_status_last_change_tick = xTaskGetTickCount();
changed = 1;
    }

    taskEXIT_CRITICAL(&state_mux);

    if (changed)
    {
        printf("[COMMAND STATUS] %s -> %s reason=%s\n",
               command_status_to_string(old_status),
               command_status_to_string(new_status),
               reason ? reason : "none");
    }
}

command_status_t command_status_get(void)
{
    command_status_t snapshot;

    taskENTER_CRITICAL(&state_mux);
    snapshot = command_status;
    taskEXIT_CRITICAL(&state_mux);

    return snapshot;
}

static void command_status_auto_clear_task(void *pvParameters)
{
    while (1)
    {
        command_status_t status;
        TickType_t last_change;

        taskENTER_CRITICAL(&state_mux);
        status = command_status;
        last_change = command_status_last_change_tick;
        taskEXIT_CRITICAL(&state_mux);

        TickType_t now = xTaskGetTickCount();

        if ((status == COMMAND_STATUS_DENIED ||
             status == COMMAND_STATUS_TIMEOUT) &&
            (now - last_change) > pdMS_TO_TICKS(COMMAND_STATUS_MESSAGE_CLEAR_MS))
        {
            command_status_set(COMMAND_STATUS_IDLE, "temporary command status auto-cleared");
        }

        vTaskDelay(pdMS_TO_TICKS(250));
    }
}

rc_state_t drone_command_get(void)
{
    rc_state_t snapshot;

    taskENTER_CRITICAL(&state_mux);
    snapshot = drone_command_state;
    taskEXIT_CRITICAL(&state_mux);

    return snapshot;
}

rc_state_t drone_get_state(void)
{
    rc_state_t snapshot;

    taskENTER_CRITICAL(&state_mux);
    snapshot = drone_state;
    taskEXIT_CRITICAL(&state_mux);

    return snapshot;
}

static void frame_put_u32_le(uint8_t *buffer, int *index, uint32_t value)
{
    buffer[(*index)++] = (uint8_t)((value >> 0) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 8) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 16) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 24) & 0xFF);
}

static void mav_put_u16_le(uint8_t *buffer, int *index, uint16_t value)
{
    buffer[(*index)++] = (uint8_t)((value >> 0) & 0xFF);
    buffer[(*index)++] = (uint8_t)((value >> 8) & 0xFF);
}

static void mav_put_i16_le(uint8_t *buffer, int *index, int16_t value)
{
    mav_put_u16_le(buffer, index, (uint16_t)value);
}
static void mav_put_float_le(uint8_t *buffer, int *index, float value)
{
    uint32_t raw = 0;

    memcpy(&raw, &value, sizeof(raw));

    buffer[(*index)++] = (uint8_t)((raw >> 0) & 0xFF);
    buffer[(*index)++] = (uint8_t)((raw >> 8) & 0xFF);
    buffer[(*index)++] = (uint8_t)((raw >> 16) & 0xFF);
    buffer[(*index)++] = (uint8_t)((raw >> 24) & 0xFF);
}
static int16_t clamp_i16(int value, int min, int max)
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

static void mavlink_crc_accumulate(uint8_t data, uint16_t *crc)
{
    uint8_t tmp = data ^ (uint8_t)(*crc & 0xFF);
    tmp ^= (tmp << 4);

    *crc = (*crc >> 8) ^
           ((uint16_t)tmp << 8) ^
           ((uint16_t)tmp << 3) ^
           ((uint16_t)tmp >> 4);
}
static uint16_t mavlink_crc_calculate(const uint8_t *data, int len, uint8_t crc_extra)
{
    uint16_t crc = 0xFFFF;

    for (int i = 0; i < len; i++)
    {
        mavlink_crc_accumulate(data[i], &crc);
    }

    mavlink_crc_accumulate(crc_extra, &crc);

    return crc;
}
static int mavlink_send_message(uint32_t msg_id,
                                const uint8_t *payload,
                                uint8_t payload_len,
                                uint8_t crc_extra)
{
    if (payload == NULL && payload_len > 0)
    {
        return 0;
    }

    uint8_t frame[10 + 255 + 2];
    int index = 0;

    frame[index++] = MAVLINK2_STX;
    frame[index++] = payload_len;
    frame[index++] = 0x00; // incompat flags: unsigned
    frame[index++] = 0x00; // compat flags
    frame[index++] = mavlink_tx_seq++;
    frame[index++] = MAVLINK_SYS_ID;
    frame[index++] = MAVLINK_COMP_ID;

    frame[index++] = (uint8_t)((msg_id >> 0) & 0xFF);
    frame[index++] = (uint8_t)((msg_id >> 8) & 0xFF);
    frame[index++] = (uint8_t)((msg_id >> 16) & 0xFF);

    if (payload_len > 0)
    {
        memcpy(&frame[index], payload, payload_len);
        index += payload_len;
    }

    uint16_t crc = mavlink_crc_calculate(
        &frame[1],
        9 + payload_len,
        crc_extra);

    frame[index++] = (uint8_t)(crc & 0xFF);
    frame[index++] = (uint8_t)((crc >> 8) & 0xFF);

    int written = uart_write_bytes(
        CONTROL_UART_PORT,
        (const char *)frame,
        index);

    if (written != index)
    {
        return 0;
    }

    return 1;
}

static int control_mavlink_send_heartbeat(void)
{
    uint8_t payload[MAVLINK_MSG_HEARTBEAT_LEN];
    int p = 0;

    /*
        HEARTBEAT payload wire order:
        uint32 custom_mode
        uint8  type
        uint8  autopilot
        uint8  base_mode
        uint8  system_status
        uint8  mavlink_version
    */

    frame_put_u32_le(payload, &p, 0); // custom_mode

    payload[p++] = MAV_TYPE_GCS;
    payload[p++] = MAV_AUTOPILOT_INVALID;
    payload[p++] = MAV_MODE_FLAG_CUSTOM_MODE_ENABLED;
    payload[p++] = MAV_STATE_ACTIVE;
    payload[p++] = MAVLINK_VERSION_FIELD;

    if (p != MAVLINK_MSG_HEARTBEAT_LEN)
    {
        return 0;
    }

    return mavlink_send_message(
        MAVLINK_MSG_ID_HEARTBEAT,
        payload,
        MAVLINK_MSG_HEARTBEAT_LEN,
        MAVLINK_MSG_HEARTBEAT_CRC_EXTRA);
}
static int control_mavlink_send_arm_disarm(int arm)
{
    uint8_t payload[MAVLINK_MSG_COMMAND_LONG_LEN];
    int p = 0;

    uint8_t target_component = MAVLINK_TARGET_COMP_ID;

    if (fc_component_id != 0)
    {
        target_component = fc_component_id;
    }

    /*
        COMMAND_LONG payload order:

        float param1
        float param2
        float param3
        float param4
        float param5
        float param6
        float param7
        uint16 command
        uint8 target_system
        uint8 target_component
        uint8 confirmation

        MAV_CMD_COMPONENT_ARM_DISARM:
        param1 = 1.0 arm
        param1 = 0.0 disarm
    */

    mav_put_float_le(payload, &p, arm ? 1.0f : 0.0f); // param1
    mav_put_float_le(payload, &p, 0.0f);              // param2
    mav_put_float_le(payload, &p, 0.0f);              // param3
    mav_put_float_le(payload, &p, 0.0f);              // param4
    mav_put_float_le(payload, &p, 0.0f);              // param5
    mav_put_float_le(payload, &p, 0.0f);              // param6
    mav_put_float_le(payload, &p, 0.0f);              // param7

    mav_put_u16_le(payload, &p, MAV_CMD_COMPONENT_ARM_DISARM);

    payload[p++] = MAVLINK_TARGET_SYS_ID;
    payload[p++] = target_component;
    payload[p++] = 0; // confirmation

    if (p != MAVLINK_MSG_COMMAND_LONG_LEN)
    {
        return 0;
    }

    int ok = mavlink_send_message(
        MAVLINK_MSG_ID_COMMAND_LONG,
        payload,
        MAVLINK_MSG_COMMAND_LONG_LEN,
        MAVLINK_MSG_COMMAND_LONG_CRC_EXTRA);

    printf("[MAVLINK TX] COMMAND_LONG %s target_sys=%u target_comp=%u result=%s\n",
           arm ? "ARM" : "DISARM",
           MAVLINK_TARGET_SYS_ID,
           target_component,
           ok ? "OK" : "FAILED");

    return ok;
}

int control_output_init(void)
{
    printf("[OUTPUT] mode=MAVLINK2 MANUAL_CONTROL tx=%d rx=%d baud=%d\n",
           CONTROL_UART_TX_PIN,
           CONTROL_UART_RX_PIN,
           CONTROL_UART_BAUD);

    uart_config_t uart_config = {
        .baud_rate = CONTROL_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_driver_install(CONTROL_UART_PORT, 4096, 4096, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(CONTROL_UART_PORT, &uart_config));

    ESP_ERROR_CHECK(uart_set_pin(
        CONTROL_UART_PORT,
        CONTROL_UART_TX_PIN,
        CONTROL_UART_RX_PIN,
        UART_PIN_NO_CHANGE,
        UART_PIN_NO_CHANGE));

    return 1;
}
int link_uart_init(void)
{
#if FEATURE_LINK_UART_TX

    printf("[LINK UART] mode=MATHOS_WIRE tx=%d rx=%d baud=%d\n",
           LINK_UART_TX_PIN,
           LINK_UART_RX_PIN,
           LINK_UART_BAUD);

    uart_config_t uart_config = {
        .baud_rate = LINK_UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_driver_install(LINK_UART_PORT, 2048, 2048, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(LINK_UART_PORT, &uart_config));

    ESP_ERROR_CHECK(uart_set_pin(
        LINK_UART_PORT,
        LINK_UART_TX_PIN,
        LINK_UART_RX_PIN,
        UART_PIN_NO_CHANGE,
        UART_PIN_NO_CHANGE));

#endif

    return 1;
}

int link_uart_send_frame(const uint8_t *frame, size_t frame_len)
{
#if FEATURE_LINK_UART_TX

    if (frame == NULL || frame_len == 0)
    {
        return 0;
    }

    int written = uart_write_bytes(
        LINK_UART_PORT,
        (const char *)frame,
        frame_len);

    return written == frame_len;

#else

    return 1;

#endif
}
static int control_mavlink_send_manual_control(const rc_packet_t *packet)
{
    if (packet == NULL)
    {
        return 0;
    }

    /*
        MAVLink2 unsigned packet:

        0      STX = 0xFD
        1      payload length
        2      incompat flags
        3      compat flags
        4      sequence
        5      system id
        6      component id
        7-9    message id, little endian 24-bit
        10..   payload
        end    checksum low, checksum high
    */

    uint8_t frame[10 + MAVLINK_MSG_MANUAL_CONTROL_LEN + 2];
    uint8_t payload[MAVLINK_MSG_MANUAL_CONTROL_LEN];

    int p = 0;

    int16_t x_pitch = clamp_i16(packet->pitch, -1000, 1000);
    int16_t y_roll = clamp_i16(packet->roll, -1000, 1000);
    int16_t z_throttle = clamp_i16(packet->throttle, 0, 1000);
    int16_t r_yaw = clamp_i16(packet->yaw, -1000, 1000);

    uint16_t buttons = 0;

    /*
        If remote is not ARMED, send neutral controls.
    */
/*
    Normal safety rule:
    if remote is not ARMED, send neutral controls.

    Temporary bench-test exception:
    allow fixed non-throttle values while DISARMED so we can verify
    MAVLink MANUAL_CONTROL data in Mission Planner.
*/
#if !(TEST_FIXED_MANUAL_CONTROL && TEST_ALLOW_MANUAL_WHILE_DISARMED)

    if (packet->state != RC_ARMED || !fc_is_armed)
    {
        x_pitch = 0;
        y_roll = 0;
        z_throttle = 0;
        r_yaw = 0;
        buttons = 0;
    }

#endif

    /*
        MANUAL_CONTROL payload wire order:
        int16 x
        int16 y
        int16 z
        int16 r
        uint16 buttons
        uint8 target
    */
    static uint32_t mav_manual_print_counter = 0;

    if (++mav_manual_print_counter >= 50)
    {
        mav_manual_print_counter = 0;
#if DEBUG_MAVLINK_TX
        printf("[MAVLINK TX] MANUAL_CONTROL x_pitch=%d y_roll=%d z_throttle=%d r_yaw=%d state=%s\n",
               x_pitch,
               y_roll,
               z_throttle,
               r_yaw,
               state_to_string(packet->state));
#endif
    }
    mav_put_i16_le(payload, &p, x_pitch);
    mav_put_i16_le(payload, &p, y_roll);
    mav_put_i16_le(payload, &p, z_throttle);
    mav_put_i16_le(payload, &p, r_yaw);
    mav_put_u16_le(payload, &p, buttons);
    payload[p++] = MAVLINK_TARGET_SYS_ID;

    if (p != MAVLINK_MSG_MANUAL_CONTROL_LEN)
    {
        return 0;
    }

    int index = 0;

    frame[index++] = MAVLINK2_STX;
    frame[index++] = MAVLINK_MSG_MANUAL_CONTROL_LEN;
    frame[index++] = 0x00; // incompat flags: unsigned
    frame[index++] = 0x00; // compat flags
    frame[index++] = mavlink_tx_seq++;
    frame[index++] = MAVLINK_SYS_ID;
    frame[index++] = MAVLINK_COMP_ID;

    frame[index++] = (uint8_t)((MAVLINK_MSG_ID_MANUAL_CONTROL >> 0) & 0xFF);
    frame[index++] = (uint8_t)((MAVLINK_MSG_ID_MANUAL_CONTROL >> 8) & 0xFF);
    frame[index++] = (uint8_t)((MAVLINK_MSG_ID_MANUAL_CONTROL >> 16) & 0xFF);

    memcpy(&frame[index], payload, MAVLINK_MSG_MANUAL_CONTROL_LEN);
    index += MAVLINK_MSG_MANUAL_CONTROL_LEN;

    /*
        MAVLink checksum covers:
        payload length through payload,
        not the STX byte.
    */
    uint16_t crc = mavlink_crc_calculate(
        &frame[1],
        9 + MAVLINK_MSG_MANUAL_CONTROL_LEN,
        MAVLINK_MSG_MANUAL_CONTROL_CRC_EXTRA);

    frame[index++] = (uint8_t)(crc & 0xFF);
    frame[index++] = (uint8_t)((crc >> 8) & 0xFF);

    int written = uart_write_bytes(
        CONTROL_UART_PORT,
        (const char *)frame,
        index);

    if (written != index)
    {
        return 0;
    }

    return 1;
}
int control_output_send(const rc_packet_t *packet)
{
    if (packet == NULL)
    {
        return 0;
    }

    return control_mavlink_send_manual_control(packet);
}

void drone_command_set(rc_state_t new_state, const char *reason)
{
    rc_state_t old_state;
    int changed = 0;

    taskENTER_CRITICAL(&state_mux);

    old_state = drone_command_state;

    if (drone_command_state != new_state)
    {
        drone_command_state = new_state;
        changed = 1;
    }

    taskEXIT_CRITICAL(&state_mux);

    if (changed)
    {
        printf("[CMD] drone command %s -> %s reason=%s\n",
               state_to_string(old_state),
               state_to_string(new_state),
               reason ? reason : "none");
    }
}

void drone_set_state(rc_state_t new_state, const char *reason)
{
    rc_state_t old_state;
    int changed = 0;

    taskENTER_CRITICAL(&state_mux);

    old_state = drone_state;

    if (drone_state != new_state)
    {
        drone_state = new_state;
        changed = 1;
    }

    taskEXIT_CRITICAL(&state_mux);

    if (changed)
    {
        printf("[STATE] drone %s -> %s reason=%s\n",
               state_to_string(old_state),
               state_to_string(new_state),
               reason ? reason : "none");
    }
}

uint32_t security_next_tx_sequence(void)
{
    uint32_t sequence;

    taskENTER_CRITICAL(&security_mux);
    sequence = security_tx_sequence++;
    taskEXIT_CRITICAL(&security_mux);

    return sequence;
}

const char *security_status_to_string(security_status_t status)
{
    switch (status)
    {
    case SECURITY_STATUS_OK:
        return "OK";

    case SECURITY_STATUS_BAD_ARGUMENT:
        return "BAD_ARGUMENT";

    case SECURITY_STATUS_BAD_CONTROLLER:
        return "BAD_CONTROLLER";

    case SECURITY_STATUS_BAD_PAYLOAD_TYPE:
        return "BAD_PAYLOAD_TYPE";

    case SECURITY_STATUS_BAD_LENGTH:
        return "BAD_LENGTH";

    case SECURITY_STATUS_REPLAY:
        return "REPLAY";

    case SECURITY_STATUS_BAD_TAG:
        return "BAD_TAG";

    default:
        return "UNKNOWN";
    }
}
void security_timing_update(int64_t work_us, security_status_t status)
{
#if SECURITY_TIMING_DIAGNOSTIC

    security_timing_stats.count++;
    security_timing_stats.last_us = work_us;
    security_timing_stats.total_us += work_us;

    if (work_us > security_timing_stats.max_us)
    {
        security_timing_stats.max_us = work_us;
    }

    if (status == SECURITY_STATUS_OK)
    {
        security_timing_stats.ok_count++;
    }
    else
    {
        security_timing_stats.fail_count++;
    }

#endif
}

void security_timing_print_if_needed(void)
{
#if SECURITY_TIMING_DIAGNOSTIC

    if (security_timing_stats.count == 0)
    {
        return;
    }

    if ((security_timing_stats.count % SECURITY_TIMING_PRINT_EVERY) != 0)
    {
        return;
    }

    int64_t avg_us = security_timing_stats.total_us / security_timing_stats.count;

    printf("[SECURITY TIMING] count=%lu ok=%lu fail=%lu last_us=%lld avg_us=%lld max_us=%lld\n",
           (unsigned long)security_timing_stats.count,
           (unsigned long)security_timing_stats.ok_count,
           (unsigned long)security_timing_stats.fail_count,
           (long long)security_timing_stats.last_us,
           (long long)avg_us,
           (long long)security_timing_stats.max_us);

    if (security_timing_stats.last_us > SECURITY_TIMING_WARN_US)
    {
        printf("[SECURITY TIMING WARNING] last_us=%lld limit_us=%d\n",
               (long long)security_timing_stats.last_us,
               SECURITY_TIMING_WARN_US);
    }

#endif
}
static void security_mix_byte(uint32_t *acc, uint8_t value)
{
    *acc ^= value;
    *acc *= 16777619u;
}

static void security_mix_u32(uint32_t *acc, uint32_t value)
{
    security_mix_byte(acc, (uint8_t)((value >> 0) & 0xFF));
    security_mix_byte(acc, (uint8_t)((value >> 8) & 0xFF));
    security_mix_byte(acc, (uint8_t)((value >> 16) & 0xFF));
    security_mix_byte(acc, (uint8_t)((value >> 24) & 0xFF));
}

static void security_mix_bytes(uint32_t *acc, const uint8_t *data, uint8_t len)
{
    for (int i = 0; i < len; i++)
    {
        security_mix_byte(acc, data[i]);
    }
}

/*
    TEMPORARY TEST TAG.

    This is NOT cryptography.
    This only proves that our packet wrapping / checking structure works.

    Later this function will be replaced with real authenticated encryption:
    ChaCha20-Poly1305 or AES-GCM.
*/
void security_make_test_tag(const secure_packet_t *packet, uint8_t tag[SECURITY_AUTH_TAG_LEN])
{
    uint32_t acc = 2166136261u;

    security_mix_u32(&acc, packet->sequence);
    security_mix_u32(&acc, packet->timestamp_ms);

    security_mix_byte(&acc, packet->controller_id);
    security_mix_byte(&acc, packet->link_id);
    security_mix_byte(&acc, packet->payload_type);
    security_mix_byte(&acc, packet->payload_len);

    security_mix_bytes(&acc, packet->payload, packet->payload_len);

    for (int i = 0; i < SECURITY_AUTH_TAG_LEN; i++)
    {
        acc = (acc * 1664525u) + 1013904223u + (uint32_t)i;
        tag[i] = (uint8_t)((acc >> ((i % 4) * 8)) & 0xFF);
    }
}

int security_tag_equal(const uint8_t a[SECURITY_AUTH_TAG_LEN],
                       const uint8_t b[SECURITY_AUTH_TAG_LEN])
{
    uint8_t diff = 0;

    for (int i = 0; i < SECURITY_AUTH_TAG_LEN; i++)
    {
        diff |= a[i] ^ b[i];
    }

    return diff == 0;
}

int security_wrap_rc_packet(const rc_packet_t *rc_packet,
                            secure_packet_t *secure_packet,
                            link_mode_t link_mode)
{
    if (rc_packet == NULL || secure_packet == NULL)
    {
        return 0;
    }

    if (sizeof(rc_packet_t) > SECURITY_PAYLOAD_MAX_LEN)
    {
        return 0;
    }

    memset(secure_packet, 0, sizeof(secure_packet_t));

    secure_packet->sequence = security_next_tx_sequence();
    secure_packet->timestamp_ms = mathos_session_id;
    secure_packet->controller_id = SECURITY_CONTROLLER_ID;
    secure_packet->link_id = (uint8_t)link_mode;
    secure_packet->payload_type = SECURITY_PAYLOAD_TYPE_RC;
    secure_packet->payload_len = sizeof(rc_packet_t);

    memcpy(secure_packet->payload, rc_packet, sizeof(rc_packet_t));

    security_make_test_tag(secure_packet, secure_packet->auth_tag);

    return 1;
}

security_status_t security_verify_packet_basic(const secure_packet_t *packet, uint32_t *last_accepted_sequence)
{
    if (packet == NULL || last_accepted_sequence == NULL)
    {
        return SECURITY_STATUS_BAD_ARGUMENT;
    }

    if (packet->controller_id != SECURITY_CONTROLLER_ID)
    {
        return SECURITY_STATUS_BAD_CONTROLLER;
    }

    if (packet->payload_type != SECURITY_PAYLOAD_TYPE_RC)
    {
        return SECURITY_STATUS_BAD_PAYLOAD_TYPE;
    }

    if (packet->payload_len != sizeof(rc_packet_t))
    {
        return SECURITY_STATUS_BAD_LENGTH;
    }

    if (packet->sequence <= *last_accepted_sequence)
    {
        return SECURITY_STATUS_REPLAY;
    }

    uint8_t expected_tag[SECURITY_AUTH_TAG_LEN];

    security_make_test_tag(packet, expected_tag);

    if (!security_tag_equal(packet->auth_tag, expected_tag))
    {
        return SECURITY_STATUS_BAD_TAG;
    }

    *last_accepted_sequence = packet->sequence;

    return SECURITY_STATUS_OK;
}
static int mathos_from_local_secure_packet(
    const secure_packet_t *src,
    mathos_secure_packet_t *dst)
{
    if (src == NULL || dst == NULL)
    {
        return 0;
    }

    if (src->payload_len > MATHOS_PAYLOAD_MAX_LEN)
    {
        return 0;
    }

    memset(dst, 0, sizeof(mathos_secure_packet_t));

    dst->sequence = src->sequence;
    dst->timestamp_ms = src->timestamp_ms;

    dst->controller_id = src->controller_id;
    dst->link_id = src->link_id;
    dst->payload_type = src->payload_type;
    dst->payload_len = src->payload_len;

    memcpy(dst->payload, src->payload, src->payload_len);
    memcpy(dst->auth_tag, src->auth_tag, MATHOS_AUTH_TAG_LEN);

    return 1;
}

static int mathos_to_local_secure_packet(
    const mathos_secure_packet_t *src,
    secure_packet_t *dst)
{
    if (src == NULL || dst == NULL)
    {
        return 0;
    }

    if (src->payload_len > SECURITY_PAYLOAD_MAX_LEN)
    {
        return 0;
    }

    memset(dst, 0, sizeof(secure_packet_t));

    dst->sequence = src->sequence;
    dst->timestamp_ms = src->timestamp_ms;

    dst->controller_id = src->controller_id;
    dst->link_id = src->link_id;
    dst->payload_type = src->payload_type;
    dst->payload_len = src->payload_len;

    memcpy(dst->payload, src->payload, src->payload_len);
    memcpy(dst->auth_tag, src->auth_tag, SECURITY_AUTH_TAG_LEN);

    return 1;
}
void enter_failsafe(const char *reason)
{
    rc_state_t command_state = drone_command_get();

    if (command_state == RC_FAILSAFE)
    {
        return;
    }

#if BENCH_FAILSAFE_DISARM && FEATURE_DIRECT_MAVLINK_MODE
    if (fc_is_armed)
    {
        if (control_mavlink_send_arm_disarm(0))
        {
            fc_disarm_pending = 1;
            fc_arm_pending = 0;
            fc_disarm_pending_start_tick = xTaskGetTickCount();

            command_status_set(COMMAND_STATUS_DISARMING, "failsafe sent DISARM to FC");

            printf("[FAILSAFE] FC DISARM command sent\n");
        }
        else
        {
            fault_set(FAULT_OUTPUT_FAILED);
            command_status_set(COMMAND_STATUS_DENIED, "failsafe failed to send DISARM");
            printf("[FAILSAFE] WARNING: failed to send FC DISARM command\n");
        }
    }
#endif

    drone_command_set(RC_FAILSAFE, reason);

    printf("[FAILSAFE] ENTERED reason=%s\n",
           reason ? reason : "none");
}

void rc_input_update(int throttle, int yaw, int pitch, int roll, int valid)
{
    TickType_t now = xTaskGetTickCount();
    taskENTER_CRITICAL(&rc_input_mux);
    rc_input.throttle = throttle;
    rc_input.yaw = yaw;
    rc_input.pitch = pitch;
    rc_input.roll = roll;
    rc_input.valid = valid;
    rc_input_last_update_tick = now;
    taskEXIT_CRITICAL(&rc_input_mux);
}

void rc_input_get_snapshot(rc_input_t *snapshot, TickType_t *last_update_tick)
{
    taskENTER_CRITICAL(&rc_input_mux);
    *snapshot = rc_input;
    *last_update_tick = rc_input_last_update_tick;
    taskEXIT_CRITICAL(&rc_input_mux);
}
int master_switch_enabled(void)
{
    /*
        Pull-up logic:
        switch OFF = 1
        switch ON  = 0
    */
    return gpio_get_level(MASTER_ENABLE_PIN) == 0;
}

int arm_permission_enabled(void)
{
    /*
        Pull-up logic:
        switch OFF = 1
        switch ON  = 0
    */
    return gpio_get_level(ARM_PERMISSION_SWITCH_PIN) == 0;
}

static uint32_t mav_get_u32_le(const uint8_t *buffer)
{
    return ((uint32_t)buffer[0] << 0) |
           ((uint32_t)buffer[1] << 8) |
           ((uint32_t)buffer[2] << 16) |
           ((uint32_t)buffer[3] << 24);
}

static uint16_t mav_get_u16_le(const uint8_t *buffer)
{
    return ((uint16_t)buffer[0] << 0) |
           ((uint16_t)buffer[1] << 8);
}

static int32_t mav_get_i32_le(const uint8_t *buffer)
{
    return ((int32_t)((uint32_t)buffer[0] << 0) |
            (int32_t)((uint32_t)buffer[1] << 8) |
            (int32_t)((uint32_t)buffer[2] << 16) |
            (int32_t)((uint32_t)buffer[3] << 24));
}

static const char *mav_result_to_string(uint8_t result)
{
    switch (result)
    {
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

static const char *fc_arm_state_to_string(void)
{
    return fc_is_armed ? "ARMED" : "DISARMED";
}

static void handle_mavlink_heartbeat(
    uint8_t sysid,
    uint8_t compid,
    const uint8_t *payload,
    uint8_t payload_len)
{
    if (payload_len < MAVLINK_MSG_HEARTBEAT_LEN)
    {
        return;
    }

    /*
        HEARTBEAT payload order:

        uint32 custom_mode
        uint8  type
        uint8  autopilot
        uint8  base_mode
        uint8  system_status
        uint8  mavlink_version
    */

    uint32_t custom_mode = mav_get_u32_le(&payload[0]);
    uint8_t type = payload[4];
    uint8_t autopilot = payload[5];
    /*
    Ignore our own heartbeat or any GCS heartbeat.
    We only want the real flight controller/autopilot heartbeat.
*/
    if (sysid == MAVLINK_SYS_ID && compid == MAVLINK_COMP_ID)
    {
        return;
    }
    if (sysid != MAVLINK_TARGET_SYS_ID)
    {
        return;
    }
    if (autopilot == MAV_AUTOPILOT_INVALID)
    {
        return;
    }
    uint8_t base_mode = payload[6];
    uint8_t system_status = payload[7];

    int armed = (base_mode & MAV_MODE_FLAG_SAFETY_ARMED) != 0;

    int changed =
        (!fc_heartbeat_seen) ||
        (fc_is_armed != armed) ||
        (fc_system_status != system_status) ||
        (fc_base_mode != base_mode);

    fc_heartbeat_seen = 1;
    fc_is_armed = armed;

    fc_system_id = sysid;
    fc_component_id = compid;
    fc_type = type;
    fc_autopilot = autopilot;
    fc_base_mode = base_mode;
    fc_system_status = system_status;
    fc_custom_mode = custom_mode;

    telemetry_valid = 1;
    telemetry_last_update_tick = xTaskGetTickCount();
    drone_link_ok = 1;

    if (armed)
    {
        drone_set_state(RC_ARMED, "FC HEARTBEAT armed");

        if (fc_arm_pending || command_status_get() == COMMAND_STATUS_ARMING)
        {
            fc_arm_pending = 0;
            fc_disarm_pending = 0;

            drone_command_set(RC_ARMED, "FC heartbeat confirmed armed");
            command_status_set(COMMAND_STATUS_IDLE, "FC heartbeat confirmed armed");

            printf("[CONTROLLER] FC ARM CONFIRMED. Controller is now ARMED\n");
        }
    }
    else
    {
        drone_set_state(RC_DISARMED, "FC HEARTBEAT disarmed");

        if (fc_disarm_pending || command_status_get() == COMMAND_STATUS_DISARMING)
        {
            fc_disarm_pending = 0;
            fc_arm_pending = 0;

            command_status_set(COMMAND_STATUS_IDLE, "FC heartbeat confirmed disarmed");

            printf("[CONTROLLER] FC DISARM CONFIRMED. Controller is now DISARMED\n");
        }

        if (drone_command_get() == RC_ARMED)
        {
            drone_command_set(RC_DISARMED, "FC heartbeat confirmed disarmed");
            printf("[CONTROLLER] FC is DISARMED. Controller returned to DISARMED\n");
        }
    }

    if (changed)
    {
        printf("[FC HEARTBEAT] sys=%u comp=%u type=%u autopilot=%u base_mode=0x%02X custom_mode=%lu status=%u FC=%s\n",
               fc_system_id,
               fc_component_id,
               fc_type,
               fc_autopilot,
               fc_base_mode,
               (unsigned long)fc_custom_mode,
               fc_system_status,
               fc_arm_state_to_string());
    }
}
static void handle_mavlink_command_ack(
    uint8_t sysid,
    uint8_t compid,
    const uint8_t *payload,
    uint8_t payload_len)
{
    if (payload_len < 3)
    {
        return;
    }

    uint16_t command = mav_get_u16_le(&payload[0]);
    uint8_t result = payload[2];

    uint8_t progress = 0;
    int32_t result_param2 = 0;
    uint8_t target_system = 0;
    uint8_t target_component = 0;

    /*
        COMMAND_ACK has MAVLink2 extension fields.
        Some frames may only contain the first 3 bytes.
    */
    if (payload_len >= 4)
    {
        progress = payload[3];
    }

    if (payload_len >= 8)
    {
        result_param2 = mav_get_i32_le(&payload[4]);
    }

    if (payload_len >= 9)
    {
        target_system = payload[8];
    }

    if (payload_len >= 10)
    {
        target_component = payload[9];
    }

    printf("[FC COMMAND_ACK] sys=%u comp=%u command=%u result=%s progress=%u result_param2=%ld target_sys=%u target_comp=%u\n",
           sysid,
           compid,
           command,
           mav_result_to_string(result),
           progress,
           (long)result_param2,
           target_system,
           target_component);

    if (command == MAV_CMD_COMPONENT_ARM_DISARM)
    {
        if (result == MAV_RESULT_ACCEPTED)
        {
            printf("[FC ARM/DISARM ACK] ACCEPTED\n");
        }
        else
        {
            printf("[FC ARM/DISARM ACK] NOT ACCEPTED: %s\n",
                   mav_result_to_string(result));

            fc_arm_pending = 0;
            fc_disarm_pending = 0;

            command_status_set(COMMAND_STATUS_DENIED, "FC rejected ARM/DISARM command");

            if (!fc_is_armed)
            {
                drone_command_set(RC_DISARMED, "FC rejected ARM/DISARM command");
            }
        }
    }
}

static void mavlink_parse_frame(const uint8_t *frame, int frame_len)
{
    if (frame == NULL)
    {
        return;
    }

    if (frame_len < 12)
    {
        return;
    }

    if (frame[0] != MAVLINK2_STX)
    {
        return;
    }

    uint8_t payload_len = frame[1];
    uint8_t incompat_flags = frame[2];

    int signature_len = 0;

    /*
        MAVLink2 signed frame:
        incompat_flags bit 0 means a 13-byte signature exists
        AFTER the normal checksum.
    */
    if (incompat_flags & 0x01)
    {
        signature_len = MAVLINK2_SIGNATURE_LEN;
    }

    int expected_len = 10 + payload_len + 2 + signature_len;

    if (frame_len != expected_len)
    {
        return;
    }

    uint32_t msg_id =
        ((uint32_t)frame[7] << 0) |
        ((uint32_t)frame[8] << 8) |
        ((uint32_t)frame[9] << 16);

    uint8_t crc_extra = 0;

    if (msg_id == MAVLINK_MSG_ID_HEARTBEAT)
    {
        crc_extra = MAVLINK_MSG_HEARTBEAT_CRC_EXTRA;
    }
    else if (msg_id == MAVLINK_MSG_ID_COMMAND_ACK)
    {
        crc_extra = MAVLINK_MSG_COMMAND_ACK_CRC_EXTRA;
    }

    else
    {
        return;
    }

    /*
        CRC is before the optional signature.
        Signature is not part of normal MAVLink CRC.
    */
    uint16_t calculated_crc = mavlink_crc_calculate(
        &frame[1],
        9 + payload_len,
        crc_extra);

    uint16_t received_crc =
        ((uint16_t)frame[10 + payload_len] << 0) |
        ((uint16_t)frame[10 + payload_len + 1] << 8);

    if (calculated_crc != received_crc)
    {
#if DEBUG_MAVLINK_RX_CRC
        printf("[MAVLINK RX] CRC BAD msg_id=%lu calc=0x%04X recv=0x%04X\n",
               (unsigned long)msg_id,
               calculated_crc,
               received_crc);
#endif
        return;
    }

    uint8_t sysid = frame[5];
    uint8_t compid = frame[6];
    const uint8_t *payload = &frame[10];

    if (msg_id == MAVLINK_MSG_ID_HEARTBEAT)
    {
        handle_mavlink_heartbeat(sysid, compid, payload, payload_len);
    }
    else if (msg_id == MAVLINK_MSG_ID_COMMAND_ACK)
    {
        handle_mavlink_command_ack(sysid, compid, payload, payload_len);
    }
}
void mavlink_rx_task(void *pvParameters)
{
    uint8_t rx_buffer[128];

    uint8_t frame[MAVLINK_RX_FRAME_MAX_LEN];
    int frame_index = 0;
    int expected_frame_len = 0;

    while (1)
    {
        heartbeat_mark(HB_MAVLINK_RX);

        int len = uart_read_bytes(
            CONTROL_UART_PORT,
            rx_buffer,
            sizeof(rx_buffer),
            pdMS_TO_TICKS(100));

        if (len > 0)
        {
            for (int i = 0; i < len; i++)
            {
                uint8_t b = rx_buffer[i];

                /*
                    Wait for MAVLink2 start byte.
                */
                if (frame_index == 0)
                {
                    if (b != MAVLINK2_STX)
                    {
                        continue;
                    }

                    frame[frame_index++] = b;
                    expected_frame_len = 0;
                    continue;
                }

                frame[frame_index++] = b;

                /*
                    After byte 1, we know payload length.
                    MAVLink2 frame length:
                    10-byte header including STX + payload + 2-byte CRC.
                */
                if (frame_index == 3)
                {
                    uint8_t payload_len = frame[1];
                    uint8_t incompat_flags = frame[2];

                    int signature_len = 0;

                    if (incompat_flags & 0x01)
                    {
                        signature_len = MAVLINK2_SIGNATURE_LEN;
                    }

                    expected_frame_len = 10 + payload_len + 2 + signature_len;

                    if (expected_frame_len > MAVLINK_RX_FRAME_MAX_LEN)
                    {
                        frame_index = 0;
                        expected_frame_len = 0;
                        continue;
                    }
                }

                if (expected_frame_len > 0 && frame_index >= expected_frame_len)
                {
                    mavlink_parse_frame(frame, frame_index);

                    frame_index = 0;
                    expected_frame_len = 0;
                }

                /*
                    Safety reset if something goes wrong.
                */
                if (frame_index >= MAVLINK_RX_FRAME_MAX_LEN)
                {
                    frame_index = 0;
                    expected_frame_len = 0;
                }
            }
        }
    }
}
void arm_safety_task(void *pvParameters)
{
    int last_master = -1;
    int last_arm_permission = -1;

    while (1)
    {
        heartbeat_mark(HB_ARM_SAFETY);

        int master_enable = master_switch_enabled();
        int arm_permission = arm_permission_enabled();

        rc_state_t command_state = drone_command_get();

        if (master_enable != last_master)
        {
            last_master = master_enable;

            printf("[MASTER SWITCH] %s\n",
                   master_enable ? "ENABLE" : "OFF");
        }

        if (arm_permission != last_arm_permission)
        {
            last_arm_permission = arm_permission;

            printf("[ARM PERMISSION SWITCH] %s\n",
                   arm_permission ? "PERMITTED" : "LOCKED");
        }

        /*
            Boot safety latch.

            If ARM permission switch was ON during boot,
            arming stays blocked until the operator moves it OFF once.
        */
        if (arm_boot_latch_active)
        {
            fault_set(FAULT_ARM_BOOT_LOCK);

            if (!arm_permission)
            {
                arm_boot_latch_active = 0;
                fault_clear(FAULT_ARM_BOOT_LOCK);

                printf("[BOOT SAFETY] ARM boot lock cleared. ARM permission switch moved OFF\n");
            }
        }

        /*
            MASTER OFF:
            If controller is ARMED, enter centralized FAILSAFE.
            enter_failsafe() handles FC DISARM for bench mode.
        */
        if (!master_enable)
        {
            fault_set(FAULT_MASTER_SWITCH_OFF);

            if (command_state == RC_ARMED)
            {
                enter_failsafe("master switch OFF while armed");

                printf("[MASTER SWITCH] FAILSAFE: master turned OFF while ARMED\n");
            }
        }
        else
        {
            fault_clear(FAULT_MASTER_SWITCH_OFF);
        }

        /*
            ARM PERMISSION OFF:
            If controller is ARMED, enter centralized FAILSAFE.
            enter_failsafe() handles FC DISARM for bench mode.
        */
        command_state = drone_command_get();

        if (!arm_permission)
        {
            fault_set(FAULT_ARM_SWITCH_OFF);

            if (command_state == RC_ARMED)
            {
                enter_failsafe("arm permission removed while armed");

                printf("[ARM PERMISSION SWITCH] FAILSAFE: permission removed while ARMED\n");
            }
        }
        else
        {
            fault_clear(FAULT_ARM_SWITCH_OFF);
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

int map_axis_calibrated(
    int raw,
    int raw_min,
    int raw_center,
    int raw_max,
    int invert)
{
    int value = 0;

    if (abs(raw - raw_center) < AXIS_DEADZONE_RAW)
    {
        value = 0;
    }
    else if (raw > raw_center)
    {
        value = ((raw - raw_center) * 1000) / (raw_max - raw_center);
    }
    else
    {
        value = -((raw_center - raw) * 1000) / (raw_center - raw_min);
    }

    if (value > 1000)
        value = 1000;

    if (value < -1000)
        value = -1000;

    if (invert)
        value = -value;

    return value;
}

int telemetry_is_fresh(void)
{
    TickType_t now = xTaskGetTickCount();
    TickType_t age = now - telemetry_last_update_tick;

    if (!telemetry_valid)
    {
        return 0;
    }

    if (age > pdMS_TO_TICKS(1500))
    {
        return 0;
    }

    return 1;
}
int rc_input_is_fresh(void)
{
    rc_input_t snapshot;
    TickType_t last_update;
    rc_input_get_snapshot(&snapshot, &last_update);

    TickType_t now = xTaskGetTickCount();
    TickType_t age = now - last_update;

    if (!snapshot.valid)
    {
        return 0;
    }

    if (age > pdMS_TO_TICKS(200))
    {
        return 0;
    }

    return 1;
}
int print_stack_watermark(const char *name, TaskHandle_t handle)
{
    if (handle == NULL)
    {
        DBG_PRINT("[STACK] %s handle is NULL\n", name);
        return 1;
    }

    UBaseType_t watermark = uxTaskGetStackHighWaterMark(handle);

    DBG_PRINT("[STACK] %s free_stack=%lu\n",
              name,
              (unsigned long)watermark);

    if (watermark < MIN_STACK_WATERMARK)
    {
        DBG_PRINT("[STACK WARNING] %s stack is getting low!\n", name);
        return 1;
    }
    return 0;
}

link_mode_t read_link_mode_switch(void)
{
    int optic = gpio_get_level(SWITCH_OPTIC_PIN);
    int rf = gpio_get_level(SWITCH_RF_PIN);
    if (optic == 0 && rf == 1)
    {
        return LINK_MODE_FORCE_OPTIC;
    }
    if (optic == 1 && rf == 0)
    {
        return LINK_MODE_FORCE_RF;
    }
    return LINK_MODE_AUTO;
}

arm_status_t get_arm_status(void)
{
    if (!master_switch_enabled())
    {
        return ARM_STATUS_MASTER_OFF;
    }

    if (!arm_permission_enabled())
    {
        return ARM_STATUS_ARM_LOCKED;
    }

    if (arm_boot_latch_is_active())
    {
        return ARM_STATUS_BOOT_LOCK;
    }

    rc_input_t input_snapshot;
    TickType_t input_last_update;

    rc_input_get_snapshot(&input_snapshot, &input_last_update);

    if (!rc_input_is_fresh())
    {
        return ARM_STATUS_INPUT_STALE;
    }

    if (abs(input_snapshot.roll) > ARM_STICK_MAX ||
        abs(input_snapshot.pitch) > ARM_STICK_MAX ||
        abs(input_snapshot.yaw) > ARM_STICK_MAX)
    {
        return ARM_STATUS_STICKS_NOT_CENTERED;
    }
#if FEATURE_DIRECT_MAVLINK_MODE
    if (!telemetry_is_fresh())
    {
        return ARM_STATUS_TELEMETRY_STALE;
    }

    if (!drone_link_ok)
    {
        return ARM_STATUS_LINK_BAD;
    }

    if (drone_get_state() == RC_FAILSAFE)
    {
        return ARM_STATUS_DRONE_FAILSAFE;
    }
#endif
#if FEATURE_SECURE_GATEWAY_MODE
    if (!gateway_status_is_fresh())
    {
        return ARM_STATUS_LINK_BAD;
    }
#endif
    if (input_snapshot.throttle > ARM_THROTTLE_MAX)
    {
        return ARM_STATUS_THROTTLE_HIGH;
    }

    /*
        These faults are already represented by specific arm statuses above.
        Do not let them appear again as generic SYSTEM_FAULT.
    */
    uint32_t real_faults = fault_get_snapshot() &
                           ~(FAULT_MASTER_SWITCH_OFF |
                             FAULT_ARM_SWITCH_OFF |
                             FAULT_ARM_BOOT_LOCK |
                             FAULT_JOYSTICK_STALE |
                             FAULT_TELEMETRY_STALE |
                             FAULT_DRONE_LINK_BAD |
                             FAULT_DRONE_FAILSAFE);

    if (real_faults != FAULT_NONE)
    {
        return ARM_STATUS_SYSTEM_FAULT;
    }

    return ARM_STATUS_READY;
}

void system_health_task(void *pvParameters)
{
    static int stack_print_counter = 0;
    static uint32_t last_fault_snapshot = 0xFFFFFFFF;
    static arm_status_t last_arm_status = (arm_status_t)-1;
    while (1)
    {
        heartbeat_mark(HB_SYSTEM_HEALTH);
        rc_input_t input_snapshot;
        TickType_t input_last_update;

        rc_input_get_snapshot(&input_snapshot, &input_last_update);
        int input_fresh = rc_input_is_fresh();
        int telemetry_fresh = telemetry_is_fresh();
        TickType_t now = xTaskGetTickCount();
        TickType_t input_age_ticks = now - input_last_update;
        uint32_t input_age_ms = pdTICKS_TO_MS(input_age_ticks);

        uint32_t free_heap = esp_get_free_heap_size();
        rc_state_t command_state = drone_command_get();
        rc_state_t drone_state_snapshot = drone_get_state();

        if (free_heap < MIN_FREE_HEAP_BYTES)
        {
            fault_set(FAULT_HEAP_LOW);
        }
        else
        {
            fault_clear(FAULT_HEAP_LOW);
        }

#if FEATURE_DIRECT_MAVLINK_MODE

        if (command_state == RC_ARMED && !telemetry_fresh)
        {
            enter_failsafe("telemetry stale while armed");
            printf("[HEALTH] FAILSAFE: telemetry stale while ARMED\n");
        }
        else

#endif
            //     if (command_state == RC_ARMED && !input_fresh)
            // {
            //     enter_failsafe("joystick input stale while armed");
            //     printf("[HEALTH] FAILSAFE: joystick input stale while ARMED\n");
            // }
            if (command_state == RC_ARMED && !input_fresh)
            {
                enter_failsafe("joystick input stale while armed");
                printf("[HEALTH] FAILSAFE: joystick input stale while ARMED\n");
            }

        if (!input_fresh)
        {
            fault_set(FAULT_JOYSTICK_STALE);
        }
        else
        {
            fault_clear(FAULT_JOYSTICK_STALE);
        }
#if FEATURE_DIRECT_MAVLINK_MODE
        if (!telemetry_fresh)
        {
            fault_set(FAULT_TELEMETRY_STALE);
            drone_link_ok = 0;
        }
        else
        {
            fault_clear(FAULT_TELEMETRY_STALE);
        }

        if (!drone_link_ok)
        {
            fault_set(FAULT_DRONE_LINK_BAD);
        }
        else
        {
            fault_clear(FAULT_DRONE_LINK_BAD);
        }
#else

        fault_clear(FAULT_TELEMETRY_STALE);
        fault_clear(FAULT_DRONE_LINK_BAD);

        /*
            In secure gateway mode, remote link status comes from
            encrypted gateway status packets.
        */
        drone_link_ok = gateway_status_is_fresh();

#endif
        if (command_state == RC_FAILSAFE || drone_state_snapshot == RC_FAILSAFE)
        {
            fault_set(FAULT_DRONE_FAILSAFE);
        }
        else
        {
            fault_clear(FAULT_DRONE_FAILSAFE);
        }

        if (++stack_print_counter >= 5)
        {
            int stack_problem = 0;
            stack_print_counter = 0;

            stack_problem |= print_stack_watermark("led_task", status_led_task_handle);
            stack_problem |= print_stack_watermark("button_task_arm", button_task_arm_handle);
            stack_problem |= print_stack_watermark("button_task_disarm", button_task_disarm_handle);
            stack_problem |= print_stack_watermark("button_task_failsafe", button_task_failsafe_handle);
            stack_problem |= print_stack_watermark("controller_task", controller_task_handle);
            stack_problem |= print_stack_watermark("radio_tx_task", radio_tx_task_handle);
            stack_problem |= print_stack_watermark("gateway_status_rx_task", gateway_status_rx_task_handle);
            stack_problem |= print_stack_watermark("joystick_adc_task", joystick_adc_task_handle);
            stack_problem |= print_stack_watermark("link_mode_task", link_mode_task_handle);
            stack_problem |= print_stack_watermark("arm_safety_task", arm_safety_task_handle);
            stack_problem |= print_stack_watermark("lcd_task", lcd_task_handle);
            stack_problem |= print_stack_watermark("task_supervisor_task", heartbeat_task_handle);
#if FEATURE_DIRECT_MAVLINK_MODE
            stack_problem |= print_stack_watermark("mavlink_heartbeat_task", mavlink_heartbeat_task_handle);
            stack_problem |= print_stack_watermark("mavlink_rx_task", mavlink_rx_task_handle);
#endif

            if (stack_problem)
            {
                fault_set(FAULT_STACK_LOW);
            }
            else
            {
                fault_clear(FAULT_STACK_LOW);
            }
        }

        command_state = drone_command_get();
        drone_state_snapshot = drone_get_state();
        uint32_t fault_snapshot = fault_get_snapshot();
        const char *telemetry_text = telemetry_fresh ? "FRESH" : "STALE";

#if FEATURE_SECURE_GATEWAY_MODE
        telemetry_text = gateway_status_is_fresh() ? "GATEWAY" : "GW_STALE";
#endif
        DBG_PRINT("[HEALTH] command=%s drone=%s input=%s telemetry=%s faults=0x%08lx age=%lu ms heap=%lu link=%s\n",
                  state_to_string(command_state),
                  state_to_string(drone_state_snapshot),
                  input_fresh ? "FRESH" : "STALE",
                  telemetry_text,
                  (unsigned long)fault_snapshot,
                  (unsigned long)input_age_ms,
                  (unsigned long)free_heap,
                  drone_link_ok ? "OK" : "BAD");

        if (fault_snapshot != last_fault_snapshot)
        {
            last_fault_snapshot = fault_snapshot;
            print_fault_snapshot("[FAULTS] ", fault_snapshot);
        }
        arm_status_t arm_status = get_arm_status();

        if (arm_status != last_arm_status)
        {
            last_arm_status = arm_status;

            printf("[ARM STATUS] %s\n",
                   arm_status_to_log_text(arm_status));
        }
        if (fc_arm_pending)
        {
            TickType_t now = xTaskGetTickCount();
            uint32_t pending_ms = pdTICKS_TO_MS(now - fc_arm_pending_start_tick);

            if (pending_ms > FC_ARM_PENDING_TIMEOUT_MS)
            {
                fc_arm_pending = 0;

                command_status_set(COMMAND_STATUS_TIMEOUT, "FC did not confirm ARMED");

                printf("[ARM PENDING] TIMEOUT: FC did not confirm ARMED within %lu ms\n",
                       (unsigned long)pending_ms);
            }
        }

        if (fc_disarm_pending)
        {
            TickType_t now = xTaskGetTickCount();
            uint32_t pending_ms = pdTICKS_TO_MS(now - fc_disarm_pending_start_tick);

            if (pending_ms > FC_ARM_PENDING_TIMEOUT_MS)
            {
                fc_disarm_pending = 0;

                command_status_set(COMMAND_STATUS_TIMEOUT, "FC did not confirm DISARMED");

                printf("[DISARM PENDING] TIMEOUT: FC did not confirm DISARMED within %lu ms\n",
                       (unsigned long)pending_ms);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void IRAM_ATTR button_isr_handler(void *arg)
{
    SemaphoreHandle_t semaphore = (SemaphoreHandle_t)arg;

    if (semaphore == NULL)
    {
        return;
    }

    BaseType_t xHigherPriorityTaskWoken = pdFALSE;

    xSemaphoreGiveFromISR(semaphore, &xHigherPriorityTaskWoken);

    portYIELD_FROM_ISR(xHigherPriorityTaskWoken);
}
void mavlink_heartbeat_task(void *pvParameters)
{
    while (1)
    {
        if (!control_mavlink_send_heartbeat())
        {
            printf("[MAVLINK] HEARTBEAT send failed\n");
            fault_set(FAULT_OUTPUT_FAILED);
        }
        else
        {
            fault_clear(FAULT_OUTPUT_FAILED);
#if DEBUG_HEARTBEAT_TX
            printf("[MAVLINK] HEARTBEAT sent\n");
#endif
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void status_led_task(void *pvParameters)
{

    while (1)
    {
        heartbeat_mark(HB_LED);
        rc_state_t command_state = drone_command_get();
        if (command_state == RC_DISARMED)
        {
            led_strip_set_pixel(strip, 0, 255, 0, 0); // red
            led_strip_refresh(strip);
            vTaskDelay(pdMS_TO_TICKS(200));
        }
        else if (command_state == RC_ARMED)
        {
            led_strip_set_pixel(strip, 0, 0, 255, 0); // green
            led_strip_refresh(strip);
            vTaskDelay(pdMS_TO_TICKS(200));
        }
        else if (command_state == RC_FAILSAFE)
        {
            led_strip_set_pixel(strip, 0, 0, 0, 255); // blue
            led_strip_refresh(strip);
            vTaskDelay(pdMS_TO_TICKS(250));

            led_strip_clear(strip);
            led_strip_refresh(strip);
            vTaskDelay(pdMS_TO_TICKS(250));
        }
    }
}

void button_task_common(
    SemaphoreHandle_t semaphore,
    int button_pin,
    rc_event_type_t event_type,
    const char *button_name)
{
    while (1)
    {
        if (xSemaphoreTake(semaphore, portMAX_DELAY) == pdTRUE)
        {
            /*
                Simple debounce.
                Wait 50ms, then confirm the button is still pressed.
            */
            vTaskDelay(pdMS_TO_TICKS(50));

            /*
                Pull-up logic:
                pressed  = 0
                released = 1
            */
            if (gpio_get_level(button_pin) != 0)
            {
                continue;
            }

            printf("[BUTTON] %s pressed\n", button_name);

            rc_event_t event;
            event.type = event_type;
            xQueueSend(rc_event_queue, &event, portMAX_DELAY);

            /*
                Wait until the button is released.
                This prevents repeated events from one physical press.
            */
            while (gpio_get_level(button_pin) == 0)
            {
                vTaskDelay(pdMS_TO_TICKS(10));
            }
        }
    }
}
void button_task_arm(void *pvParameters)
{
    button_task_common(
        button_semaphore_arm,
        BUTTON_PIN_ARM,
        EVENT_BUTTON_ARM_PRESS,
        "ARM");
}
void button_task_disarm(void *pvParameters)
{
    button_task_common(
        button_semaphore_disarm,
        BUTTON_PIN_DISARM,
        EVENT_BUTTON_DISARM_PRESS,
        "DISARM");
}
void button_task_failsafe(void *pvParameters)
{
    button_task_common(
        button_semaphore_failsafe,
        BUTTON_PIN_FAILSAFE,
        EVENT_BUTTON_FAILSAFE_PRESS,
        "FAILSAFE");
}
int prearm_checks_pass(void)
{
    arm_status_t status = get_arm_status();

    if (status != ARM_STATUS_READY)
    {
        printf("[PREARM] FAIL: %s\n", arm_status_to_log_text(status));

        if (status == ARM_STATUS_SYSTEM_FAULT)
        {
            uint32_t fault_snapshot = fault_get_snapshot();
            print_fault_snapshot("[PREARM FAULTS] ", fault_snapshot);
        }

        return 0;
    }

    printf("[PREARM] PASS\n");
    return 1;
}
static uint16_t link_get_u16_le(const uint8_t *buffer)
{
    return ((uint16_t)buffer[0] << 0) |
           ((uint16_t)buffer[1] << 8);
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

    default:
        return "UNKNOWN";
    }
}

static void gateway_status_apply_to_remote(const gateway_status_packet_t *status)
{
    if (status == NULL)
    {
        return;
    }

    command_status_t op_status = command_status_get();
    rc_state_t command_state = drone_command_get();

    /*
        Track actual FC state from the gateway.
        This is the real aircraft state, not just the local button intent.
    */
    if (status->fc_is_armed)
    {
        drone_set_state(RC_ARMED, "gateway reports FC armed");
    }
    else
    {
        drone_set_state(RC_DISARMED, "gateway reports FC disarmed");
    }

    switch ((gateway_action_t)status->last_action)
    {
    case GATEWAY_ACTION_ARM_REAL_SENT:
        if (op_status == COMMAND_STATUS_ARMING)
        {
            command_status_set(COMMAND_STATUS_ARMING, "gateway sent real ARM command");
        }
        break;

case GATEWAY_ACTION_ARM_CONFIRMED:
    if (status->fc_is_armed &&
        op_status == COMMAND_STATUS_ARMING)
    {
        drone_command_set(RC_ARMED, "gateway confirmed FC armed");
        drone_set_state(RC_ARMED, "gateway confirmed FC armed");
        command_status_set(COMMAND_STATUS_IDLE, "gateway confirmed FC armed");

        printf("[REMOTE] ARM CONFIRMED by gateway/FC\n");
    }
    break;

    case GATEWAY_ACTION_ARM_DENIED:
        if (op_status == COMMAND_STATUS_ARMING)
        {
            drone_command_set(RC_DISARMED, "gateway denied ARM");
            drone_set_state(RC_DISARMED, "gateway denied ARM");
            command_status_set(COMMAND_STATUS_DENIED, "gateway denied ARM");

            printf("[REMOTE] ARM DENIED by gateway/FC\n");
        }
        break;

    case GATEWAY_ACTION_ARM_TIMEOUT:
        if (op_status == COMMAND_STATUS_ARMING)
        {
            drone_command_set(RC_DISARMED, "gateway ARM timeout");
            drone_set_state(RC_DISARMED, "gateway ARM timeout");
            command_status_set(COMMAND_STATUS_TIMEOUT, "gateway ARM timeout");

            printf("[REMOTE] ARM TIMEOUT from gateway/FC\n");
        }
        break;

    case GATEWAY_ACTION_DISARM_REAL_SENT:
        if (op_status == COMMAND_STATUS_DISARMING)
        {
            command_status_set(COMMAND_STATUS_DISARMING, "gateway sent real DISARM command");
        }
        break;

    case GATEWAY_ACTION_DISARM_CONFIRMED:
        /*
            Normal DISARM confirmation clears DISARMING.
            If the local command is FAILSAFE, keep FAILSAFE latched until
            the operator resets it intentionally.
        */
        if (op_status == COMMAND_STATUS_DISARMING &&
            command_state != RC_FAILSAFE)
        {
            drone_command_set(RC_DISARMED, "gateway confirmed FC disarmed");
            drone_set_state(RC_DISARMED, "gateway confirmed FC disarmed");
            command_status_set(COMMAND_STATUS_IDLE, "gateway confirmed FC disarmed");

            printf("[REMOTE] DISARM CONFIRMED by gateway/FC\n");
        }
        break;

    case GATEWAY_ACTION_DISARM_DENIED:
        if (op_status == COMMAND_STATUS_DISARMING)
        {
            drone_command_set(RC_DISARMED, "gateway denied DISARM, keeping output neutral");
            command_status_set(COMMAND_STATUS_DENIED, "gateway denied DISARM");

            if (status->fc_is_armed)
            {
                drone_set_state(RC_ARMED, "gateway says FC still armed after DISARM denied");
            }
            else
            {
                drone_set_state(RC_DISARMED, "gateway says FC disarmed after DISARM denied");
            }

            printf("[REMOTE] DISARM DENIED by gateway/FC\n");
        }
        break;

    case GATEWAY_ACTION_DISARM_TIMEOUT:
        if (op_status == COMMAND_STATUS_DISARMING)
        {
            drone_command_set(RC_DISARMED, "gateway DISARM timeout, keeping output neutral");
            command_status_set(COMMAND_STATUS_TIMEOUT, "gateway DISARM timeout");

            if (status->fc_is_armed)
            {
                drone_set_state(RC_ARMED, "gateway says FC still armed after DISARM timeout");
            }
            else
            {
                drone_set_state(RC_DISARMED, "gateway says FC disarmed after DISARM timeout");
            }

            printf("[REMOTE] DISARM TIMEOUT from gateway/FC\n");
        }
        break;

    default:
        break;
    }
}

static void gateway_status_update(const gateway_status_packet_t *status)
{
    if (status == NULL)
    {
        return;
    }

    taskENTER_CRITICAL(&gateway_status_mux);

    gateway_status_snapshot = *status;
    gateway_status_last_update_tick = xTaskGetTickCount();
    gateway_status_valid = 1;

    taskEXIT_CRITICAL(&gateway_status_mux);
}

static void gateway_status_handle_frame(const uint8_t *frame, size_t frame_len)
{
    static uint32_t last_sequence = 0;
    static uint32_t last_session_id = 0;
    static int has_session = 0;

    static uint32_t ok_count = 0;
    static uint32_t bad_count = 0;
    static uint32_t replay_count = 0;

    if (frame == NULL || frame_len == 0)
    {
        return;
    }

    mathos_secure_packet_t packet;

    mathos_status_t decode_status = mathos_wire_decode(
        frame,
        frame_len,
        &packet);

    if (decode_status != MATHOS_STATUS_OK)
    {
        bad_count++;

        if ((bad_count % 20) == 1)
        {
            printf("[GATEWAY STATUS RX] wire BAD status=%s bad_count=%lu len=%u\n",
                   mathos_status_to_string(decode_status),
                   (unsigned long)bad_count,
                   (unsigned int)frame_len);
        }

        return;
    }

    mathos_secure_status_t crypto_status = mathos_secure_decrypt_packet(&packet);

    if (crypto_status != MATHOS_SECURE_STATUS_OK)
    {
        bad_count++;

        if ((bad_count % 20) == 1)
        {
            printf("[GATEWAY STATUS RX] crypto BAD status=%s bad_count=%lu len=%u\n",
                   mathos_secure_status_to_string(crypto_status),
                   (unsigned long)bad_count,
                   (unsigned int)frame_len);
        }

        return;
    }

    if (packet.controller_id != SECURITY_GATEWAY_ID)
    {
        bad_count++;

        printf("[GATEWAY STATUS RX] bad controller_id=%u expected=%u\n",
               packet.controller_id,
               SECURITY_GATEWAY_ID);
        return;
    }

    if (packet.payload_type != SECURITY_PAYLOAD_TYPE_GATEWAY_STATUS)
    {
        bad_count++;

        printf("[GATEWAY STATUS RX] bad payload_type=%u expected=%u\n",
               packet.payload_type,
               SECURITY_PAYLOAD_TYPE_GATEWAY_STATUS);
        return;
    }

    if (packet.payload_len != sizeof(gateway_status_packet_t))
    {
        bad_count++;

        printf("[GATEWAY STATUS RX] bad payload_len=%u expected=%u\n",
               packet.payload_len,
               (unsigned int)sizeof(gateway_status_packet_t));
        return;
    }

    uint32_t session_id = packet.timestamp_ms;

    if (!has_session || session_id != last_session_id)
    {
        printf("[GATEWAY STATUS RX] NEW SESSION old=0x%08lx new=0x%08lx reset last_sequence\n",
               (unsigned long)last_session_id,
               (unsigned long)session_id);

        last_session_id = session_id;
        last_sequence = 0;
        has_session = 1;
    }

    if (packet.sequence <= last_sequence)
    {
        replay_count++;

        printf("[GATEWAY STATUS RX] REPLAY/OLD session=0x%08lx seq=%lu last=%lu replay_count=%lu\n",
               (unsigned long)session_id,
               (unsigned long)packet.sequence,
               (unsigned long)last_sequence,
               (unsigned long)replay_count);

        return;
    }

    last_sequence = packet.sequence;

    gateway_status_packet_t status;
    memset(&status, 0, sizeof(status));

    memcpy(&status, packet.payload, sizeof(status));

    gateway_status_update(&status);
    gateway_status_apply_to_remote(&status);

    ok_count++;

    static uint32_t print_counter = 0;
    static uint8_t last_fc_armed = 255;
    static uint8_t last_fc_fresh = 255;
    static uint8_t last_action = 255;

    print_counter++;

    int changed =
        (last_fc_armed != status.fc_is_armed) ||
        (last_fc_fresh != status.fc_heartbeat_fresh) ||
        (last_action != status.last_action);

    if (changed || print_counter == 1 || (print_counter % 10) == 0)
    {
        last_fc_armed = status.fc_is_armed;
        last_fc_fresh = status.fc_heartbeat_fresh;
        last_action = status.last_action;

        printf("[GATEWAY STATUS RX] packet_id=%lu fc=%s fc_fresh=%u remote=%s link=%u action=%s ok=%lu bad=%lu replay=%lu\n",
               (unsigned long)status.packet_id,
               status.fc_is_armed ? "ARMED" : "DISARMED",
               status.fc_heartbeat_fresh,
               state_to_string((rc_state_t)status.remote_state),
               status.gateway_link_ok,
               gateway_action_to_string(status.last_action),
               (unsigned long)status.rx_ok_count,
               (unsigned long)status.rx_bad_count,
               (unsigned long)status.rx_replay_count);
    }
}

static void gateway_status_process_byte(uint8_t byte)
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
        expected_frame_len = link_get_u16_le(&frame[4]);

        if (expected_frame_len < (MATHOS_WIRE_HEADER_LEN + MATHOS_AUTH_TAG_LEN + MATHOS_WIRE_CRC_LEN) ||
            expected_frame_len > MATHOS_WIRE_MAX_FRAME_LEN)
        {
            printf("[GATEWAY STATUS RX] bad declared frame length=%u\n",
                   (unsigned int)expected_frame_len);

            frame_index = 0;
            expected_frame_len = 0;
            return;
        }
    }

    if (expected_frame_len > 0 && frame_index >= expected_frame_len)
    {
        gateway_status_handle_frame(frame, expected_frame_len);

        frame_index = 0;
        expected_frame_len = 0;
    }
}

void gateway_status_rx_task(void *pvParameters)
{
    uint8_t rx_buffer[LINK_RX_BUFFER_SIZE];

    printf("[GATEWAY STATUS RX] task started. Waiting for encrypted gateway status...\n");

    while (1)
    {
        int len = uart_read_bytes(
            LINK_UART_PORT,
            rx_buffer,
            sizeof(rx_buffer),
            pdMS_TO_TICKS(100));

        if (len > 0)
        {
            for (int i = 0; i < len; i++)
            {
                gateway_status_process_byte(rx_buffer[i]);
            }
        }
    }
}

void task_supervisor_task(void *pvParameters)
{
    while (1)
    {
        int stalled = 0;

        uint32_t radio_age = heartbeat_age_ms(HB_RADIO_TX);
        uint32_t joystick_age = heartbeat_age_ms(HB_JOYSTICK);
        uint32_t arm_age = heartbeat_age_ms(HB_ARM_SAFETY);
        uint32_t mavlink_rx_age = heartbeat_age_ms(HB_MAVLINK_RX);
        uint32_t lcd_age = heartbeat_age_ms(HB_LCD);

        if (radio_age > 500)
        {
            printf("[SUPERVISOR] RADIO TX STALLED age=%lu ms\n",
                   (unsigned long)radio_age);
            stalled = 1;
        }

        if (joystick_age > 500)
        {
            printf("[SUPERVISOR] JOYSTICK TASK STALLED age=%lu ms\n",
                   (unsigned long)joystick_age);
            stalled = 1;
        }

        if (arm_age > 500)
        {
            printf("[SUPERVISOR] ARM SAFETY TASK STALLED age=%lu ms\n",
                   (unsigned long)arm_age);
            stalled = 1;
        }
#if FEATURE_DIRECT_MAVLINK_MODE
        if (mavlink_rx_age > 1000)
        {
            printf("[SUPERVISOR] MAVLINK RX TASK STALLED age=%lu ms\n",
                   (unsigned long)mavlink_rx_age);
            stalled = 1;
        }
#endif
        /*
            LCD is not flight-critical.
            We print warning only, but we do not enter FAILSAFE because of LCD.
        */
        if (lcd_age > 3000)
        {
            printf("[SUPERVISOR] LCD TASK SLOW/STALLED age=%lu ms\n",
                   (unsigned long)lcd_age);
        }

        if (stalled)
        {
            fault_set(FAULT_TASK_STALLED);

            if (drone_command_get() == RC_ARMED)
            {
                enter_failsafe("critical task stalled");
            }
        }
        else
        {
            fault_clear(FAULT_TASK_STALLED);
        }

        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

void controller_task(void *pvParameters)
{
    rc_event_t event;

    while (1)
    {
        if (xQueueReceive(rc_event_queue, &event, portMAX_DELAY) == pdTRUE)
        {
            rc_state_t command_state = drone_command_get();

            int master_enabled = master_switch_enabled();
            int arm_permission = arm_permission_enabled();

            /*
                MASTER OFF:
                Button does nothing.
                arm_safety_task handles emergency if it was armed.
            */
            if (!master_enabled)
            {
                printf("[CONTROLLER] Button ignored: MASTER switch is OFF\n");
                continue;
            }

            if (event.type == EVENT_BUTTON_ARM_PRESS)
            {
                if (fc_arm_pending)
                {
                    printf("[CONTROLLER] ARM ignored: FC ARM already pending\n");
                }
                else if (command_state == RC_DISARMED)
                {
                    if (!arm_permission)
                    {
                        printf("[CONTROLLER] ARM ignored: ARM permission switch is LOCKED\n");
                    }
                    else if (prearm_checks_pass())
                    {
#if FEATURE_DIRECT_MAVLINK_MODE

                        if (control_mavlink_send_arm_disarm(1))
                        {
                            fc_arm_pending = 1;
                            fc_disarm_pending = 0;
                            fc_arm_pending_start_tick = xTaskGetTickCount();

                            command_status_set(COMMAND_STATUS_ARMING, "ARM command sent to FC");

                            printf("[CONTROLLER] ARM COMMAND SENT TO FC\n");
                            printf("[CONTROLLER] Waiting for FC heartbeat to confirm ARMED\n");
                        }
                        else
                        {
                            fault_set(FAULT_OUTPUT_FAILED);
                            command_status_set(COMMAND_STATUS_DENIED, "failed to send ARM command");
                            printf("[CONTROLLER] ARM BLOCKED: failed to send FC ARM command\n");
                        }

#else

                        drone_command_set(RC_ARMED, "secure gateway mode ARM request");
                        command_status_set(COMMAND_STATUS_ARMING, "ARM request sent to gateway");

                        printf("[CONTROLLER] ARM REQUEST SENT TO GATEWAY\n");
                        printf("[CONTROLLER] Waiting for gateway/FC ARM confirmation\n");

#endif
                    }
                    else
                    {
                        printf("[CONTROLLER] ARM BLOCKED\n");
                    }
                }
                else if (command_state == RC_ARMED)
                {
                    printf("[CONTROLLER] ARM ignored: already ARMED\n");
                }
                else if (command_state == RC_FAILSAFE)
                {
                    printf("[CONTROLLER] ARM ignored: currently in FAILSAFE. Use DISARM with ARM permission OFF first\n");
                }

                printf("[CONTROLLER] ARM button complete, command=%s\n",
                       state_to_string(drone_command_get()));
            }
            else if (event.type == EVENT_BUTTON_FAILSAFE_PRESS)
            {
                if (command_state == RC_ARMED)
                {
                    enter_failsafe("manual failsafe button while armed");

                    printf("[CONTROLLER] FAILSAFE triggered by FAILSAFE button\n");
                }
                else if (command_state == RC_DISARMED)
                {
                    printf("[CONTROLLER] FAILSAFE ignored: drone command is DISARMED/BLOCKED\n");
                }
                else if (command_state == RC_FAILSAFE)
                {
                    printf("[CONTROLLER] Already in FAILSAFE\n");
                }

                printf("[CONTROLLER] FAILSAFE button complete,  command=%s\n",
                       state_to_string(drone_command_get()));
            }
            else if (event.type == EVENT_BUTTON_DISARM_PRESS)
            {
                if (fc_arm_pending)
                {
                    fc_arm_pending = 0;

#if FEATURE_DIRECT_MAVLINK_MODE

                    if (control_mavlink_send_arm_disarm(0))
                    {
                        fc_disarm_pending = 1;
                        fc_disarm_pending_start_tick = xTaskGetTickCount();

                        command_status_set(COMMAND_STATUS_DISARMING, "pending ARM cancelled, DISARM sent");

                        printf("[CONTROLLER] Pending ARM cancelled. DISARM sent to FC\n");
                    }
                    else
                    {
                        command_status_set(COMMAND_STATUS_DENIED, "failed to cancel pending ARM");
                        printf("[CONTROLLER] Pending ARM cancelled. Failed to send DISARM to FC\n");
                    }

#else

                    command_status_set(COMMAND_STATUS_IDLE, "pending ARM intent cancelled");
                    printf("[CONTROLLER] Pending ARM intent cancelled in gateway mode\n");

#endif

                    drone_command_set(RC_DISARMED, "DISARM pressed while ARM pending");
                }
                else if (command_state == RC_ARMED)
                {
#if FEATURE_DIRECT_MAVLINK_MODE
                    if (!control_mavlink_send_arm_disarm(0))
                    {
                        fault_set(FAULT_OUTPUT_FAILED);
                        command_status_set(COMMAND_STATUS_DENIED, "failed to send DISARM command");
                        printf("[CONTROLLER] WARNING: failed to send FC DISARM command\n");
                    }
                    else
                    {
                        fault_clear(FAULT_OUTPUT_FAILED);

                        fc_disarm_pending = 1;
                        fc_arm_pending = 0;
                        fc_disarm_pending_start_tick = xTaskGetTickCount();

                        command_status_set(COMMAND_STATUS_DISARMING, "DISARM command sent to FC");

                        printf("[CONTROLLER] DISARM COMMAND SENT TO FC\n");
                    }

                    /*
                        Local controller goes DISARMED immediately.
                        This forces MANUAL_CONTROL back to neutral even if FC disarm is delayed/refused.
                    */
                    drone_command_set(RC_DISARMED, "DISARM button pressed");
#else

                    drone_command_set(RC_DISARMED, "secure gateway mode DISARM request");
                    command_status_set(COMMAND_STATUS_DISARMING, "DISARM request sent to gateway");

                    printf("[CONTROLLER] DISARM REQUEST SENT TO GATEWAY\n");
                    printf("[CONTROLLER] Waiting for gateway/FC DISARM confirmation\n");

#endif
                }
                else if (command_state == RC_DISARMED)
                {
                    printf("[CONTROLLER] DISARM ignored: already DISARMED\n");
                }
                else if (command_state == RC_FAILSAFE)
                {
                    if (!arm_permission)
                    {
#if FEATURE_DIRECT_MAVLINK_MODE

                        if (control_mavlink_send_arm_disarm(0))
                        {
                            printf("[CONTROLLER] FAILSAFE RESET: DISARM command sent to FC\n");
                        }
                        else
                        {
                            fault_set(FAULT_OUTPUT_FAILED);
                            printf("[CONTROLLER] FAILSAFE RESET WARNING: failed to send FC DISARM command\n");
                        }

#else

                        printf("[CONTROLLER] FAILSAFE RESET: gateway mode, no direct FC command\n");

#endif

                        drone_command_set(RC_DISARMED, "failsafe reset with DISARM button and arm permission OFF");

                        printf("[CONTROLLER] FAILSAFE RESET TO DISARMED by DISARM button\n");
                    }
                    else
                    {
                        printf("[CONTROLLER] FAILSAFE reset blocked: turn ARM permission switch OFF first\n");
                    }
                }

                printf("[CONTROLLER] DISARM button complete, command=%s\n",
                       state_to_string(drone_command_get()));
            }
        }
    }
}

void radio_tx_task(void *pvParameters)
{
    uint32_t packet_id = 0;

    TickType_t last_wake = xTaskGetTickCount();
    const TickType_t period = pdMS_TO_TICKS(RADIO_TX_PERIOD_MS);

    while (1)
    {
        int64_t work_start_us = esp_timer_get_time();

        heartbeat_mark(HB_RADIO_TX);

        rc_input_t input_snapshot;
        TickType_t input_last_update;

        rc_input_get_snapshot(&input_snapshot, &input_last_update);

        int throttle_to_send = input_snapshot.throttle;
        int yaw_to_send = input_snapshot.yaw;
        int pitch_to_send = input_snapshot.pitch;
        int roll_to_send = input_snapshot.roll;

        rc_state_t command_state = drone_command_get();
        command_status_t op_status = command_status_get();

#if TEST_FIXED_MANUAL_CONTROL

        /*
            Bench test only.

            We force fixed control values so we can see what is being sent
            to the flight controller through MAVLink MANUAL_CONTROL.

            Keep throttle 0.
        */
        throttle_to_send = TEST_FIXED_THROTTLE;
        yaw_to_send = TEST_FIXED_YAW;
        pitch_to_send = TEST_FIXED_PITCH;
        roll_to_send = TEST_FIXED_ROLL;

#else

        if (command_state != RC_ARMED ||
            op_status == COMMAND_STATUS_ARMING ||
            op_status == COMMAND_STATUS_DISARMING ||
            !rc_input_is_fresh())
        {
            throttle_to_send = 0;
            yaw_to_send = 0;
            pitch_to_send = 0;
            roll_to_send = 0;
        }

#endif

        rc_packet_t packet = {
            .packet_id = packet_id++,
            .state = command_state,
            .throttle = throttle_to_send,
            .yaw = yaw_to_send,
            .pitch = pitch_to_send,
            .roll = roll_to_send,
        };
#if SECURITY_SKELETON_DIAGNOSTIC

        int64_t security_start_us = esp_timer_get_time();

        secure_packet_t secure_packet;
        security_status_t security_status = SECURITY_STATUS_BAD_ARGUMENT;

        if (security_wrap_rc_packet(&packet, &secure_packet, read_link_mode_switch()))
        {
            static uint32_t security_print_counter = 0;
            static uint32_t security_test_last_sequence = 0;

            security_status =
                security_verify_packet_basic(&secure_packet, &security_test_last_sequence);

            int64_t security_work_us = esp_timer_get_time() - security_start_us;
#if DEBUG_SECURE_WIRE_TEST
            static uint32_t wire_print_counter = 0;
            static uint32_t wire_last_accepted_sequence = 0;

            mathos_secure_packet_t wire_packet;
            mathos_secure_packet_t decoded_wire_packet;
            mathos_secure_status_t encrypt_status = MATHOS_SECURE_STATUS_BAD_ARGUMENT;
            mathos_secure_status_t decrypt_status = MATHOS_SECURE_STATUS_BAD_ARGUMENT;
            int payload_match = 0;
            secure_packet_t decoded_secure_packet;

            uint8_t wire_frame[MATHOS_WIRE_MAX_FRAME_LEN];
            size_t wire_frame_len = 0;

            mathos_status_t encode_status = MATHOS_STATUS_BAD_ARGUMENT;
            mathos_status_t decode_status = MATHOS_STATUS_BAD_ARGUMENT;
            security_status_t decoded_security_status = SECURITY_STATUS_BAD_ARGUMENT;
            if (mathos_from_local_secure_packet(&secure_packet, &wire_packet))
            {
                encrypt_status = mathos_secure_encrypt_packet(&wire_packet);

                if (encrypt_status == MATHOS_SECURE_STATUS_OK)
                {
                    mathos_secure_packet_t packet_to_send;
                    memcpy(&packet_to_send, &wire_packet, sizeof(packet_to_send));

#if DEBUG_CRYPTO_TAMPER_TEST
                    if ((packet_to_send.sequence % CRYPTO_TAMPER_EVERY) == 0 &&
                        packet_to_send.payload_len > 0)
                    {
                        packet_to_send.payload[0] ^= 0x01;

                        printf("[TAMPER TEST] damaged encrypted payload byte seq=%lu\n",
                               (unsigned long)packet_to_send.sequence);
                    }
#endif

                    encode_status = mathos_wire_encode(
                        &packet_to_send,
                        wire_frame,
                        sizeof(wire_frame),
                        &wire_frame_len);
                    // if (encrypt_status == MATHOS_SECURE_STATUS_OK)
                    // {
                    //     encode_status = mathos_wire_encode(
                    //         &wire_packet,
                    //         wire_frame,
                    //         sizeof(wire_frame),
                    //         &wire_frame_len);

                    if (encode_status == MATHOS_STATUS_OK)
                    {
#if FEATURE_LINK_UART_TX
                        if (!link_uart_send_frame(wire_frame, wire_frame_len))
                        {
                            static uint32_t link_uart_fail_count = 0;
                            link_uart_fail_count++;

                            if ((link_uart_fail_count % 50) == 1)
                            {
                                printf("[LINK UART] TX FAILED count=%lu\n",
                                       (unsigned long)link_uart_fail_count);
                            }
                        }
#endif

                        decode_status = mathos_wire_decode(
                            wire_frame,
                            wire_frame_len,
                            &decoded_wire_packet);

                        if (decode_status == MATHOS_STATUS_OK)
                        {
                            decrypt_status = mathos_secure_decrypt_packet(&decoded_wire_packet);

                            if (decrypt_status == MATHOS_SECURE_STATUS_OK &&
                                decoded_wire_packet.payload_len == secure_packet.payload_len &&
                                memcmp(decoded_wire_packet.payload,
                                       secure_packet.payload,
                                       secure_packet.payload_len) == 0)
                            {
                                payload_match = 1;
                            }
                        }
                    }
                }
            }

            if (++wire_print_counter >= SECURE_WIRE_TEST_PRINT_EVERY)
            {
                wire_print_counter = 0;

                printf("[WIRE TEST] len=%u encode=%s decode=%s verify=%s seq=%lu\n",
                       (unsigned int)wire_frame_len,
                       mathos_status_to_string(encode_status),
                       mathos_status_to_string(decode_status),
                       security_status_to_string(decoded_security_status),
                       (unsigned long)secure_packet.sequence);
            }
#endif
            security_timing_update(security_work_us, security_status);
            security_timing_print_if_needed();

            if (++security_print_counter >= 50)
            {
                security_print_counter = 0;

#if DEBUG_SECURITY_PACKET
                printf("[SECURITY] wrapped rc_packet id=%lu seq=%lu payload_len=%u status=%s tag=%02X%02X%02X%02X...\n",
                       (unsigned long)packet.packet_id,
                       (unsigned long)secure_packet.sequence,
                       secure_packet.payload_len,
                       security_status_to_string(security_status),
                       secure_packet.auth_tag[0],
                       secure_packet.auth_tag[1],
                       secure_packet.auth_tag[2],
                       secure_packet.auth_tag[3]);
#endif
            }
        }
        else
        {
            int64_t security_work_us = esp_timer_get_time() - security_start_us;

            security_timing_update(security_work_us, SECURITY_STATUS_BAD_ARGUMENT);
            security_timing_print_if_needed();

            printf("[SECURITY] failed to wrap rc_packet id=%lu\n",
                   (unsigned long)packet.packet_id);
        }

#endif

#if FEATURE_DIRECT_MAVLINK_MODE

        if (!control_output_send(&packet))
        {
            printf("[OUTPUT] FAILED to send control packet id=%lu\n",
                   (unsigned long)packet.packet_id);
            fault_set(FAULT_OUTPUT_FAILED);

            if (drone_command_get() == RC_ARMED)
            {
                enter_failsafe("control output failed");
            }
        }
        else
        {
            fault_clear(FAULT_OUTPUT_FAILED);
        }

#else

        /*
            Secure gateway mode:
            remote only sends encrypted Mathos packets to gateway.
            No direct MAVLink output from remote.
        */
        fault_clear(FAULT_OUTPUT_FAILED);

#endif
        int64_t work_us = esp_timer_get_time() - work_start_us;

        static int radio_slow_count = 0;

        if (work_us > (RADIO_TX_MAX_WORK_MS * 1000))
        {
            radio_slow_count++;

            printf("[TIMING] radio_tx_task slow work_us=%lld slow_count=%d\n",
                   (long long)work_us,
                   radio_slow_count);

            if (radio_slow_count >= 5)
            {
                fault_set(FAULT_CONTROL_TIMING);

                if (drone_command_get() == RC_ARMED)
                {
                    enter_failsafe("radio tx timing fault");
                }
            }
        }
        else
        {
            radio_slow_count = 0;
        }

        vTaskDelayUntil(&last_wake, period);
    }
}

void joystick_adc_task(void *pvParameters)
{
    static int print_counter = 0;

    static int roll_min = 4095;
    static int roll_max = 0;

    static int pitch_min = 4095;
    static int pitch_max = 0;

    static int yaw_min = 4095;
    static int yaw_max = 0;

    static int throttle_min = 4095;
    static int throttle_max = 0;

    TickType_t last_wake = xTaskGetTickCount();
    const TickType_t period = pdMS_TO_TICKS(JOYSTICK_PERIOD_MS);

    while (1)
    {
        int64_t work_start_us = esp_timer_get_time();

        heartbeat_mark(HB_JOYSTICK);

        int raw_roll = 0;
        int raw_pitch = 0;
        int raw_yaw = 0;
        int raw_throttle = 0;

        /*
            Diagnostic channel mapping:

            JOY_X_ADC   -> roll
            JOY_Y_ADC   -> pitch
            JOY2_X_ADC  -> yaw
            JOY2_Y_ADC  -> throttle
        */
        ESP_ERROR_CHECK(adc_oneshot_read(adc1_handle, JOY_X_ADC, &raw_roll));
        ESP_ERROR_CHECK(adc_oneshot_read(adc1_handle, JOY_Y_ADC, &raw_pitch));

#if !ONE_JOYSTICK_TEST
        ESP_ERROR_CHECK(adc_oneshot_read(adc1_handle, JOY2_X_ADC, &raw_yaw));
        ESP_ERROR_CHECK(adc_oneshot_read(adc1_handle, JOY2_Y_ADC, &raw_throttle));
#else
        raw_yaw = 0;
        raw_throttle = 0;
#endif
        /*
            Track min/max so we can see real physical joystick range.
        */
        if (raw_roll < roll_min)
            roll_min = raw_roll;
        if (raw_roll > roll_max)
            roll_max = raw_roll;

        if (raw_pitch < pitch_min)
            pitch_min = raw_pitch;
        if (raw_pitch > pitch_max)
            pitch_max = raw_pitch;

        if (raw_yaw < yaw_min)
            yaw_min = raw_yaw;
        if (raw_yaw > yaw_max)
            yaw_max = raw_yaw;

        if (raw_throttle < throttle_min)
            throttle_min = raw_throttle;
        if (raw_throttle > throttle_max)
            throttle_max = raw_throttle;

#if JOYSTICK_RAW_DIAGNOSTIC

        /*
            In raw diagnostic mode we do NOT send real joystick values.
            We only keep input fresh and neutral.
        */
        rc_input_update(0, 0, 0, 0, 1);

        if (++print_counter >= JOYSTICK_DIAG_PRINT_EVERY)
        {
            print_counter = 0;

            printf("\n[JOYSTICK RAW DIAG]\n");
            printf("ROLL     raw=%4d min=%4d max=%4d channel=JOY_X_ADC\n",
                   raw_roll, roll_min, roll_max);

            printf("PITCH    raw=%4d min=%4d max=%4d channel=JOY_Y_ADC\n",
                   raw_pitch, pitch_min, pitch_max);

            printf("YAW      raw=%4d min=%4d max=%4d channel=JOY2_X_ADC\n",
                   raw_yaw, yaw_min, yaw_max);

            printf("THROTTLE raw=%4d min=%4d max=%4d channel=JOY2_Y_ADC\n",
                   raw_throttle, throttle_min, throttle_max);
        }

#else

        /*
            Normal mode later.
            For now this keeps the old roll/pitch behavior.
        */
        int mapped_roll = map_axis_calibrated(
            raw_roll,
            ROLL_RAW_MIN,
            ROLL_RAW_CENTER,
            ROLL_RAW_MAX,
            ROLL_INVERT);

        int mapped_pitch = map_axis_calibrated(
            raw_pitch,
            PITCH_RAW_MIN,
            PITCH_RAW_CENTER,
            PITCH_RAW_MAX,
            PITCH_INVERT);

        /*
            ONE JOYSTICK TEST:
            throttle = 0
            yaw      = 0
            pitch    = joystick Y
            roll     = joystick X
        */
        rc_input_update(0, 0, mapped_pitch, mapped_roll, 1);

        if (++print_counter >= 100)
        {
            print_counter = 0;

            printf("[JOYSTICK] roll_raw=%d pitch_raw=%d roll=%d pitch=%d\n",
                   raw_roll,
                   raw_pitch,
                   mapped_roll,
                   mapped_pitch);
        }

#endif

        int64_t work_us = esp_timer_get_time() - work_start_us;
        static int joystick_slow_count = 0;

        if (work_us > (JOYSTICK_MAX_WORK_MS * 1000))
        {
            joystick_slow_count++;

            printf("[TIMING] joystick_adc_task slow work_us=%lld slow_count=%d\n",
                   (long long)work_us,
                   joystick_slow_count);

            if (joystick_slow_count >= 5)
            {
                fault_set(FAULT_CONTROL_TIMING);

                if (drone_command_get() == RC_ARMED)
                {
                    enter_failsafe("joystick timing fault");
                }
            }
        }
        else
        {
            joystick_slow_count = 0;
            fault_clear(FAULT_CONTROL_TIMING);
        }

        vTaskDelayUntil(&last_wake, period);
    }
}
void link_mode_task(void *pvParameters)
{
    link_mode_t last_mode = (link_mode_t)-1;

    while (1)
    {
        heartbeat_mark(HB_LINK_MODE);
        link_mode_t mode = read_link_mode_switch();
        if (mode != last_mode)
        {
            last_mode = mode;

            printf("[LINK MODE] %s\n", link_mode_to_string(mode));
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}

int ready_to_arm_for_display(void)
{
    return get_arm_status() == ARM_STATUS_READY;
}
void lcd_task(void *pvParameters)
{
    rc_state_t last_state = (rc_state_t)-1;
    link_mode_t last_link_mode = (link_mode_t)-1;
    arm_status_t last_arm_status = (arm_status_t)-1;
    command_status_t last_command_status = (command_status_t)-1;
    uint32_t last_faults = 0xFFFFFFFF;
    int last_link_ok = -1;
    int last_master_off = -1;
    int last_arm_locked = -1;
    int last_ready_to_arm = -1;
    int last_boot_lock = -1;
    lcd_fill_color(COLOR_BLACK);

    while (1)
    {
        heartbeat_mark(HB_LCD);

        rc_state_t state = drone_command_get();
        link_mode_t link_mode = read_link_mode_switch();
        uint32_t faults = fault_get_snapshot();
        command_status_t op_status = command_status_get();
        int link_ok = drone_link_ok;
        int master_off = !master_switch_enabled();
        int arm_locked = !arm_permission_enabled();
        int ready_to_arm = ready_to_arm_for_display();
        int boot_lock = arm_boot_latch_is_active();
        arm_status_t arm_status = get_arm_status();
        uint32_t real_faults = faults & ~(FAULT_ARM_SWITCH_OFF | FAULT_MASTER_SWITCH_OFF);

        if (state != last_state ||
            link_mode != last_link_mode ||
            op_status != last_command_status ||
            faults != last_faults ||
            link_ok != last_link_ok ||
            master_off != last_master_off ||
            arm_locked != last_arm_locked ||
            ready_to_arm != last_ready_to_arm || boot_lock != last_boot_lock || arm_status != last_arm_status)
        {
            last_state = state;
            last_link_mode = link_mode;
            last_command_status = op_status;
            last_faults = faults;
            last_link_ok = link_ok;
            last_master_off = master_off;
            last_arm_locked = arm_locked;
            last_ready_to_arm = ready_to_arm;
            last_boot_lock = boot_lock;
            last_arm_status = arm_status;
            lcd_fill_color(COLOR_BLACK);

            /*
                Title
            */
            lcd_draw_text_centered(15, "REMOTE", 3, COLOR_WHITE, COLOR_BLACK);

            /*
                Main state
            */
            if (master_off)
            {
                lcd_draw_text_centered(65, "CTRL OFF", 3, COLOR_WHITE, COLOR_BLACK);
            }
            else if (state == RC_FAILSAFE)
            {
                lcd_draw_text_centered(65, "FAILSAFE", 3, COLOR_RED, COLOR_BLACK);
            }
            else if (op_status == COMMAND_STATUS_ARMING)

            {
                lcd_draw_text_centered(65, "ARMING", 3, COLOR_YELLOW, COLOR_BLACK);
            }
            else if (op_status == COMMAND_STATUS_DISARMING)
            {
                lcd_draw_text_centered(65, "DISARMING", 3, COLOR_YELLOW, COLOR_BLACK);
            }
            else if (op_status == COMMAND_STATUS_DENIED)
            {
                lcd_draw_text_centered(65, "DENIED", 3, COLOR_RED, COLOR_BLACK);
            }
            else if (op_status == COMMAND_STATUS_TIMEOUT)
            {
                lcd_draw_text_centered(65, "TIMEOUT", 3, COLOR_RED, COLOR_BLACK);
            }
            else if (state == RC_ARMED)
            {
                lcd_draw_text_centered(65, "ARMED", 4, COLOR_BLUE, COLOR_BLACK);
            }
            else
            {
                lcd_draw_text_centered(65, "DISARMED", 3, COLOR_WHITE, COLOR_BLACK);
            }

            /*
                Link mode
            */
            if (link_mode == LINK_MODE_AUTO)
            {
                lcd_draw_text_centered(120, "LINK AUTO", 2, COLOR_WHITE, COLOR_BLACK);
            }
            else if (link_mode == LINK_MODE_FORCE_OPTIC)
            {
                lcd_draw_text_centered(120, "LINK OPTIC", 2, COLOR_BLUE, COLOR_BLACK);
            }
            else
            {
                lcd_draw_text_centered(120, "LINK RF", 2, COLOR_BLUE, COLOR_BLACK);
            }

            /*
                Drone link status
            */
            if (link_ok)
            {
                lcd_draw_text_centered(155, "DRONE LINK OK", 1, COLOR_BLUE, COLOR_BLACK);
            }
            else
            {
                lcd_draw_text_centered(155, "DRONE LINK BAD", 1, COLOR_RED, COLOR_BLACK);
            }

            /*
                Bottom status
            */
            if (master_off)
            {
                lcd_draw_text_centered(185, "MASTER OFF", 2, COLOR_WHITE, COLOR_BLACK);
            }
            else if (state == RC_FAILSAFE && arm_locked)
            {
                lcd_draw_text_centered(185, "ARM OFF", 3, COLOR_RED, COLOR_BLACK);
            }
            else if (state == RC_FAILSAFE)
            {
                lcd_draw_text_centered(185, "FAILSAFE", 3, COLOR_RED, COLOR_BLACK);
            }
            else if (op_status == COMMAND_STATUS_ARMING)
            {
                lcd_draw_text_centered(185, "WAIT FC", 2, COLOR_YELLOW, COLOR_BLACK);
            }
            else if (op_status == COMMAND_STATUS_DISARMING)
            {
                lcd_draw_text_centered(185, "WAIT FC", 2, COLOR_YELLOW, COLOR_BLACK);
            }
            else if (op_status == COMMAND_STATUS_DENIED)
            {
                lcd_draw_text_centered(185, "FC DENIED", 2, COLOR_RED, COLOR_BLACK);
            }
            else if (op_status == COMMAND_STATUS_TIMEOUT)
            {
                lcd_draw_text_centered(185, "FC TIMEOUT", 2, COLOR_RED, COLOR_BLACK);
            }
            else if (boot_lock)
            {
                lcd_draw_text_centered(185, "BOOT LOCK", 2, COLOR_RED, COLOR_BLACK);
            }
            else if (arm_locked)
            {
                lcd_draw_text_centered(185, "LOCKED", 3, COLOR_WHITE, COLOR_BLACK);
            }
            else if (state == RC_DISARMED && arm_status == ARM_STATUS_READY)
            {
                lcd_draw_text_centered(185, "READY", 3, COLOR_BLUE, COLOR_BLACK);
            }
            else if (state == RC_DISARMED)
            {
                lcd_draw_text_centered(185, arm_status_to_lcd_text(arm_status), 2, COLOR_RED, COLOR_BLACK);
            }
            else if (state == RC_ARMED && real_faults == FAULT_NONE)
            {
                lcd_draw_text_centered(185, "NO FAULT", 2, COLOR_BLUE, COLOR_BLACK);
            }
            else
            {
                lcd_draw_text_centered(185, "FAULT", 3, COLOR_RED, COLOR_BLACK);
            }
        }

        vTaskDelay(pdMS_TO_TICKS(250));
    }
}

void app_main(void)
{
    button_semaphore_arm = xSemaphoreCreateBinary();
    button_semaphore_failsafe = xSemaphoreCreateBinary();
    button_semaphore_disarm = xSemaphoreCreateBinary();
    if (button_semaphore_arm == NULL || button_semaphore_failsafe == NULL || button_semaphore_disarm == NULL)
    {
        printf("[FATAL] failed to create button semaphores\n");
        return;
    }

    rc_event_queue = xQueueCreate(10, sizeof(rc_event_t));
    if (rc_event_queue == NULL)
    {
        printf("failed to create queue");
        return;
    }

#if FEATURE_DIRECT_MAVLINK_MODE
    if (!control_output_init())
    {
        printf("[FATAL] control output init failed\n");
        return;
    }
#else
    printf("[OUTPUT] direct MAVLink disabled. Using secure gateway mode.\n");
#endif
    if (!link_uart_init())
    {
        printf("[FATAL] link UART init failed\n");
        return;
    }

    mathos_session_id = esp_random();

    if (mathos_session_id == 0)
    {
        mathos_session_id = 1;
    }

    printf("[SECURITY] session_id=0x%08lx\n",
           (unsigned long)mathos_session_id);

    led_strip_config_t strip_config = {
        .strip_gpio_num = RGB_LED_PIN,
        .max_leds = RGB_LED_COUNT,
    };

    led_strip_rmt_config_t rmt_config = {
        .resolution_hz = 10 * 1000 * 1000,
        .flags.with_dma = false,
    };

    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config, &strip));
    led_strip_clear(strip);
    led_strip_refresh(strip);

    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << BUTTON_PIN_ARM) | (1ULL << BUTTON_PIN_FAILSAFE) | (1ULL << BUTTON_PIN_DISARM),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_NEGEDGE};
    gpio_config(&io_conf);

    gpio_config_t switch_conf = {
        .pin_bit_mask = (1ULL << SWITCH_OPTIC_PIN) | (1ULL << SWITCH_RF_PIN) | (1ULL << ARM_PERMISSION_SWITCH_PIN) | (1ULL << MASTER_ENABLE_PIN),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE};
    gpio_config(&switch_conf);
    /*
    Boot safety latch.

    If ARM switch is already ON during boot,
    block arming until operator moves it OFF.
*/
    if (arm_permission_enabled())
    {
        arm_boot_latch_active = 1;
        fault_set(FAULT_ARM_BOOT_LOCK);

        printf("[BOOT SAFETY] ARM permission switch was ON at boot. Move it OFF to unlock\n");
    }
    else
    {
        arm_boot_latch_active = 0;
        fault_clear(FAULT_ARM_BOOT_LOCK);

        printf("[BOOT SAFETY] ARM permission switch was OFF at boot. Normal startup\n");
    }
    gpio_install_isr_service(0);
    gpio_isr_handler_add(BUTTON_PIN_ARM, button_isr_handler, button_semaphore_arm);
    gpio_isr_handler_add(BUTTON_PIN_DISARM, button_isr_handler, button_semaphore_disarm);
    gpio_isr_handler_add(BUTTON_PIN_FAILSAFE, button_isr_handler, button_semaphore_failsafe);
    adc_oneshot_unit_init_cfg_t init_config = {
        .unit_id = ADC_UNIT_1,
    };

    ESP_ERROR_CHECK(adc_oneshot_new_unit(&init_config, &adc1_handle));

    adc_oneshot_chan_cfg_t channel_config = {
        .atten = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };

    ESP_ERROR_CHECK(adc_oneshot_config_channel(adc1_handle, JOY_X_ADC, &channel_config));
    ESP_ERROR_CHECK(adc_oneshot_config_channel(adc1_handle, JOY_Y_ADC, &channel_config));
    ESP_ERROR_CHECK(adc_oneshot_config_channel(adc1_handle, JOY2_X_ADC, &channel_config));
    ESP_ERROR_CHECK(adc_oneshot_config_channel(adc1_handle, JOY2_Y_ADC, &channel_config));

    gpio_config_t lcd_gpio_conf = {
        .pin_bit_mask = (1ULL << LCD_DC) | (1ULL << LCD_RST),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE};

    gpio_config(&lcd_gpio_conf);

    gpio_set_level(LCD_DC, 0);
    gpio_set_level(LCD_RST, 1);

    lcd_spi_init();
    lcd_delay_ms(500);
    lcd_init();
    heartbeat_init_all();
    create_task_checked(status_led_task, "led_task", 4096, NULL, 4, &status_led_task_handle);
    create_task_checked(button_task_arm, "button_task_arm", 4096, NULL, 5, &button_task_arm_handle);
    create_task_checked(button_task_disarm, "button_task_disarm", 4096, NULL, 5, &button_task_disarm_handle);
    create_task_checked(button_task_failsafe, "button_task_failsafe", 4096, NULL, 5, &button_task_failsafe_handle);
    create_task_checked(controller_task, "controller_task", 4096, NULL, 5, &controller_task_handle);
    create_task_checked(radio_tx_task, "radio_tx_task", 4096, NULL, 3, &radio_tx_task_handle);
    create_task_checked(gateway_status_rx_task, "gateway_status_rx_task", 4096, NULL, 3, &gateway_status_rx_task_handle);
#if FEATURE_DIRECT_MAVLINK_MODE
    create_task_checked(mavlink_heartbeat_task, "mavlink_heartbeat_task", 4096, NULL, 3, &mavlink_heartbeat_task_handle);
    create_task_checked(mavlink_rx_task, "mavlink_rx_task", 4096, NULL, 3, &mavlink_rx_task_handle);
#else
    printf("[BOOT] Direct MAVLink tasks disabled in secure gateway mode\n");
#endif
    create_task_checked(system_health_task, "system_health_task", 4096, NULL, 2, &system_health_task_handle);
    create_task_checked(command_status_auto_clear_task, "command_status_auto_clear_task", 3072, NULL, 2, &command_status_auto_clear_task_handle);
    create_task_checked(link_mode_task, "link_mode_task", 4096, NULL, 3, &link_mode_task_handle);
    create_task_checked(arm_safety_task, "arm_safety_task", 4096, NULL, 5, &arm_safety_task_handle);
    create_task_checked(lcd_task, "lcd_task", 4096, NULL, 2, &lcd_task_handle);
    create_task_checked(task_supervisor_task, "task_supervisor_task", 4096, NULL, 6, &heartbeat_task_handle);
    create_task_checked(joystick_adc_task, "joystick_adc_task", 4096, NULL, 3, &joystick_adc_task_handle);
}
