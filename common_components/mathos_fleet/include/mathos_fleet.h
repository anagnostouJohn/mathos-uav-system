#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "mathos_identity.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MATHOS_FLEET_PARTITION_NAME "fleet"
#define MATHOS_FLEET_NAMESPACE      "fleetdb"

#define MATHOS_FLEET_MAX_AIRCRAFT      200U
#define MATHOS_FLEET_FRIENDLY_NAME_LEN 32U

/*
    64 bytes is intentionally larger than a 32-byte Pair Key.

    Later it can contain an encrypted/wrapped credential
    envelope such as:

        ciphertext
        nonce
        authentication tag

    without changing the whole Fleet record architecture.
*/
#define MATHOS_FLEET_SECRET_BLOB_MAX_LEN 64U

#define MATHOS_FLEET_RECORD_MAGIC   0x4D464C54U
#define MATHOS_FLEET_RECORD_VERSION 1U

#define MATHOS_FLEET_PAIR_KEY_LEN 32U

/*
    Canonical version-1 Fleet record size.

    Layout:
        magic             4
        version           2
        record_size       2
        gateway_uid       6
        state             1
        secret_format     1
        friendly_name    32
        key_generation    4
        security_counter  4
        secret_blob_len   2
        reserved0         2
        secret_blob      64
        record_counter    4
        crc32             4

    Total: 132 bytes.

    This is the persistent storage format.
    It is NOT sizeof(mathos_fleet_record_t).
*/
#define MATHOS_FLEET_RECORD_WIRE_LEN 132U


typedef enum
{
    MATHOS_FLEET_STATE_EMPTY = 0,
    MATHOS_FLEET_STATE_ACTIVE,
    MATHOS_FLEET_STATE_REVOKED

} mathos_fleet_state_t;


/*
    How the credential blob is encoded.

    DEV_RAW_PAIR_KEY exists only for development.

    Later the production record will use
    WRAPPED_PAIR_KEY_V1.
*/
typedef enum
{
    MATHOS_FLEET_SECRET_FORMAT_NONE = 0,

    MATHOS_FLEET_SECRET_FORMAT_DEV_RAW_PAIR_KEY,

    MATHOS_FLEET_SECRET_FORMAT_WRAPPED_PAIR_KEY_V1

} mathos_fleet_secret_format_t;


typedef struct
{
    uint32_t magic;
    uint16_t version;
    uint16_t record_size;

    /*
        Permanent Gateway hardware UID.

        This identifies the aircraft record.

        IMPORTANT:
        UID alone is NOT authentication.
    */
    mathos_device_uid_t gateway_uid;

    uint8_t state;
    uint8_t secret_format;

    /*
        Human-readable aircraft name.

        Example:
            Drone 17
    */
    char friendly_name[
        MATHOS_FLEET_FRIENDLY_NAME_LEN];

    /*
        Generation of this RC <-> Gateway
        permanent relationship key.
    */
    uint32_t key_generation;

    /*
        Reserved for future security lifecycle
        counters / metadata.
    */
    uint32_t security_counter;

    /*
        Number of valid bytes inside secret_blob.
    */
    uint16_t secret_blob_len;

    uint16_t reserved0;

    /*
        Opaque credential storage.

        DEVELOPMENT:
            may temporarily contain the raw
            32-byte Pair Key.

        FINAL:
            contains wrapped/encrypted Pair Key.
    */
    uint8_t secret_blob[
        MATHOS_FLEET_SECRET_BLOB_MAX_LEN];

    /*
        Increments whenever the record is rewritten.
    */
    uint32_t record_counter;

    /*
        Detects accidental corruption.

        CRC is NOT cryptographic authentication.
    */
    uint32_t crc32;

} mathos_fleet_record_t;


/*
    Initialize the dedicated Fleet Store NVS partition.
*/
esp_err_t mathos_fleet_init(void);
esp_err_t mathos_fleet_counts_self_test(void);

/*
    Revoke an enrolled aircraft.

    The record remains in the Fleet Store but can no
    longer be authorized for normal operation.
*/
esp_err_t mathos_fleet_revoke_aircraft(
    const mathos_device_uid_t *gateway_uid);
/*
    Development test for Fleet lifecycle.

    Tests:
        ADD
        ACTIVE
        REVOKE
        duplicate REVOKE rejected
        RESTORE
        duplicate RESTORE rejected
        DELETE
*/
esp_err_t mathos_fleet_revoke_restore_self_test(void);

/*
    Restore a previously revoked aircraft.
*/
esp_err_t mathos_fleet_restore_aircraft(
    const mathos_device_uid_t *gateway_uid);
/*
    Add one new aircraft to the Fleet Store.

    The Gateway UID must not already exist.

    On success:
        slot_out receives the allocated Fleet slot.

    Returns:
        ESP_OK
        ESP_ERR_INVALID_ARG
        ESP_ERR_INVALID_STATE   duplicate UID
        ESP_ERR_NO_MEM          Fleet full
        other error             storage/integrity failure
*/
esp_err_t mathos_fleet_add_aircraft(
    const mathos_device_uid_t *gateway_uid,
    const char *friendly_name,
    uint32_t key_generation,
    mathos_fleet_secret_format_t secret_format,
    const uint8_t *secret_blob,
    uint16_t secret_blob_len,
    uint16_t *slot_out);


    typedef struct
{
    uint16_t total;
    uint16_t active;
    uint16_t revoked;
    uint16_t free_slots;

} mathos_fleet_counts_t;


typedef enum
{
    MATHOS_FLEET_AUTH_UNKNOWN = 0,
    MATHOS_FLEET_AUTH_ACTIVE,
    MATHOS_FLEET_AUTH_REVOKED

} mathos_fleet_auth_status_t;

typedef enum
{
    MATHOS_FLEET_OPERATION_NO_AIRCRAFT = 0,
    MATHOS_FLEET_OPERATION_READY,
    MATHOS_FLEET_OPERATION_SELECTION_REQUIRED

} mathos_fleet_operation_status_t;

typedef enum
{
    MATHOS_FLEET_ACTIVE_NONE = 0,
    MATHOS_FLEET_ACTIVE_ONE,
    MATHOS_FLEET_ACTIVE_MULTIPLE

} mathos_fleet_active_status_t;

/*
    Determine whether the Fleet contains:

        0 ACTIVE aircraft
        exactly 1 ACTIVE aircraft
        more than 1 ACTIVE aircraft

    If exactly one ACTIVE aircraft exists:

        slot_out   receives its slot
        record_out receives its validated Fleet record

    For NONE or MULTIPLE:
        slot_out and record_out are cleared.
*/
esp_err_t mathos_fleet_get_active_status(
    mathos_fleet_active_status_t *status_out,
    uint16_t *slot_out,
    mathos_fleet_record_t *record_out);
/*
    Count Fleet Store records.

    Returns:
        ESP_OK       counts are valid
        other error  Fleet Store corruption/read failure

    Corrupted records are NOT ignored.
*/

esp_err_t mathos_fleet_get_operation_status(
    mathos_fleet_operation_status_t *status_out,
    uint16_t *slot_out,
    mathos_fleet_record_t *record_out);

const char *mathos_fleet_operation_status_to_string(
    mathos_fleet_operation_status_t status);

esp_err_t mathos_fleet_validate_store(void);
esp_err_t mathos_fleet_operation_status_self_test(void);
esp_err_t mathos_fleet_validate_store_self_test(void);
esp_err_t mathos_fleet_duplicate_uid_lookup_self_test(void);
esp_err_t mathos_fleet_boot_validate(
    mathos_fleet_operation_status_t *status_out,
    uint16_t *slot_out,
    mathos_fleet_record_t *record_out);
esp_err_t mathos_fleet_get_authorization(
    const mathos_device_uid_t *gateway_uid,
    mathos_fleet_auth_status_t *status_out,
    uint16_t *slot_out,
    mathos_fleet_record_t *record_out);

const char *mathos_fleet_auth_status_to_string(
    mathos_fleet_auth_status_t status);

esp_err_t mathos_fleet_authorization_self_test(void);
esp_err_t mathos_fleet_get_counts(
    mathos_fleet_counts_t *counts);
/*
    Development test for complete aircraft enrollment.

    Tests:
        add new aircraft
        find by UID
        reject duplicate UID
        delete aircraft
        confirm UID no longer exists
*/
esp_err_t mathos_fleet_add_aircraft_self_test(void);

/*
    Initialize one blank Fleet record.
*/
void mathos_fleet_record_set_defaults(
    mathos_fleet_record_t *record);


/*
    Validate one complete aircraft record.
*/
int mathos_fleet_record_is_valid(
    const mathos_fleet_record_t *record);


/*
    Calculate the CRC32 for one Fleet record.
*/
uint32_t mathos_fleet_record_calculate_crc32(
    const mathos_fleet_record_t *record);
/*
    Convert Fleet state to readable text.
*/
const char *mathos_fleet_state_to_string(
    mathos_fleet_state_t state);
esp_err_t mathos_fleet_active_status_self_test(void);
/*
    Encode one Fleet record into its canonical
    version-1 byte representation.
*/
esp_err_t mathos_fleet_record_encode(
    const mathos_fleet_record_t *record,
    uint8_t *output,
    size_t output_size);
const char *mathos_fleet_active_status_to_string(
    mathos_fleet_active_status_t status);

/*
    Decode and validate one canonical
    version-1 Fleet record.
*/
esp_err_t mathos_fleet_record_decode(
    const uint8_t *input,
    size_t input_size,
    mathos_fleet_record_t *record);


/*
    Development self-test for:

        encode
        decode
        CRC
        tamper rejection
*/

/*
    Find an aircraft by its permanent Gateway hardware UID.

    On success:
        slot_out   receives the Fleet slot
        record_out receives the validated record

    Returns:
        ESP_OK             record found
        ESP_ERR_NOT_FOUND  UID is not enrolled
        other error        Fleet Store problem/corruption
*/
esp_err_t mathos_fleet_find_by_uid(
    const mathos_device_uid_t *gateway_uid,
    uint16_t *slot_out,
    mathos_fleet_record_t *record_out);




/*
    Development test for Fleet UID lookup.

    Tests:
        known UID -> correct slot
        unknown UID -> NOT_FOUND
*/
esp_err_t mathos_fleet_uid_lookup_self_test(void);
/*
    Find the first unused Fleet slot.

    Returns:
        ESP_OK         free slot found
        ESP_ERR_NO_MEM Fleet Store contains 200 aircraft
        other error    Fleet Store problem
*/
esp_err_t mathos_fleet_find_free_slot(
    uint16_t *slot_out);

esp_err_t mathos_fleet_free_slot_self_test(void);
esp_err_t mathos_fleet_record_self_test(void);
/*
    Save one aircraft into a fixed Fleet slot.

    Slot range:
        0 .. 199

    On successful save:
        record_counter is incremented
        crc32 is recalculated
        flash contents are read back and verified
*/
esp_err_t mathos_fleet_record_save_slot(
    uint16_t slot,
    mathos_fleet_record_t *record);


/*
    Load and validate one aircraft from a Fleet slot.
*/
esp_err_t mathos_fleet_record_load_slot(
    uint16_t slot,
    mathos_fleet_record_t *record);


/*
    Permanently erase one Fleet slot.
*/
esp_err_t mathos_fleet_record_delete_slot(
    uint16_t slot);


/*
    Temporary development test.

    Writes a synthetic aircraft, reloads it,
    verifies it and deletes it again.
*/
esp_err_t mathos_fleet_persistence_self_test(void);
#ifdef __cplusplus
}
#endif