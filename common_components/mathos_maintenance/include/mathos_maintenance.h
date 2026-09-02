#pragma once

#include <stddef.h>
#include <stdint.h>
#include "mathos_identity.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define MATHOS_MAINTENANCE_CONFIG_MAGIC 0x4D434647U
#define MATHOS_MAINTENANCE_CONFIG_VERSION 1U
#define MATHOS_GATEWAY_ROOT_KEY_LEN 32U
#define MATHOS_GATEWAY_FAILSAFE_FC_NATIVE 0U
#define MATHOS_GATEWAY_FAILSAFE_RTL 1U

#define MATHOS_GATEWAY_CONFIG_MAGIC 0x4D475746U
#define MATHOS_GATEWAY_CONFIG_VERSION 2U

#define MATHOS_RC_PAIRING_CONFIG_MAGIC 0x4D525043U
#define MATHOS_RC_PAIRING_CONFIG_VERSION 1U
#define MATHOS_GATEWAY_KEY_DERIVATION_NONE 0U
#define MATHOS_GATEWAY_KEY_DERIVATION_RAW_HEX 1U
#define MATHOS_GATEWAY_KEY_DERIVATION_PBKDF2_SHA256 2U

#define MATHOS_PAIRING_KDF_DEFAULT_ITERATIONS 100000U
#define MATHOS_PAIRING_KDF_MIN_ITERATIONS 10000U
#define MATHOS_PAIRING_KDF_MAX_ITERATIONS 1000000U
#define MATHOS_MAINTENANCE_WIFI_SSID_MAX_LEN 33
#define MATHOS_MAINTENANCE_SERVER_HOST_MAX_LEN 64
#define MATHOS_PAIRING_PACKAGE_MAGIC 0x4D504B47U
#define MATHOS_PAIRING_PACKAGE_VERSION 2U
#define MATHOS_PAIRING_SALT_LEN 16U
#define MATHOS_PAIRING_PASSPHRASE_MIN_LEN 16U
#define MATHOS_PAIRING_PASSPHRASE_MAX_LEN 96U
#define MATHOS_PAIRING_CHALLENGE_MAGIC 0x4D43484CU
#define MATHOS_PAIRING_CHALLENGE_VERSION 2U
#define MATHOS_PAIRING_PROOF_MAGIC 0x4D505246U
#define MATHOS_PAIRING_PROOF_VERSION 2U
#define MATHOS_PAIRING_PROOF_ROLE_RC 1U
#define MATHOS_PAIRING_PROOF_ROLE_GATEWAY 2U
/*
    Pairing-session limits.

    The timeout will later be enforced using esp_timer.
*/
#define MATHOS_PAIRING_SESSION_TIMEOUT_MS 180000U
#define MATHOS_PAIRING_SESSION_MAX_RETRIES 3U

#define MATHOS_PAIRING_NONCE_LEN 16U
#define MATHOS_PAIRING_PROOF_LEN 32U

    typedef enum
    {
        MATHOS_MAINTENANCE_ROLE_RC = 0,
        MATHOS_MAINTENANCE_ROLE_GATEWAY
    } mathos_maintenance_role_t;

    typedef struct
    {
        uint32_t magic;
        uint16_t version;
        uint16_t record_size;

        /*
            0 = telemetry forwarding disabled
            1 = telemetry forwarding enabled
        */
        uint8_t telemetry_enabled;

        /*
            Reserved bytes maintain alignment and leave
            space for small future additions.
        */
        uint8_t reserved[3];

        /*
            Null-terminated Wi-Fi SSID.
        */
        char wifi_ssid[MATHOS_MAINTENANCE_WIFI_SSID_MAX_LEN];

        /*
            Null-terminated hostname or IPv4 address.

            Examples:
                telemetry.example.com
                192.168.1.50
        */
        char server_host[MATHOS_MAINTENANCE_SERVER_HOST_MAX_LEN];

        uint16_t server_port;
        uint16_t reserved2;
        uint32_t crc32;

    } mathos_maintenance_config_t;

    typedef struct
    {
        uint32_t magic;
        uint16_t version;
        uint16_t record_size;

        uint8_t gateway_id;
        uint8_t authorised_rc_id;
        uint8_t failsafe_policy;
        uint8_t key_derivation_method;

        uint32_t key_generation;
        uint32_t kdf_iteration_count;

        uint32_t link_uart_baud;
        uint32_t fc_uart_baud;

        uint16_t rc_packet_timeout_ms;
        uint16_t fc_heartbeat_timeout_ms;
        uint16_t status_tx_period_ms;
        uint16_t telemetry_tx_period_ms;

        uint8_t root_key[MATHOS_GATEWAY_ROOT_KEY_LEN];

        uint8_t pairing_salt[MATHOS_PAIRING_SALT_LEN];

        uint8_t reserved1[4];

        uint32_t configuration_counter;
        uint32_t crc32;
    } mathos_gateway_config_t;

    typedef struct
    {
        uint32_t magic;
        uint16_t version;
        uint16_t record_size;

        /*
            Identity of this RC and the only Gateway
            authorised to use this pairing record.
        */
        uint8_t rc_id;
        uint8_t authorised_gateway_id;

        uint8_t key_derivation_method;
        uint8_t reserved0;

        /*
            Zero means the RC is not paired.

            Every successful provisioning or key rotation
            increments this generation.
        */
        uint32_t key_generation;
        uint32_t kdf_iteration_count;

        /*
            The passphrase is never stored.

            Only its derived root key and the exact salt
            required to reproduce that key are retained.
        */
        uint8_t root_key[MATHOS_GATEWAY_ROOT_KEY_LEN];
        uint8_t pairing_salt[MATHOS_PAIRING_SALT_LEN];

        /*
            Reserved for a future compatible record version.
            Version 1 requires every byte to remain zero.
        */
        uint8_t reserved1[4];

        /*
            Increments whenever the RC pairing record is
            successfully saved.
        */
        uint32_t configuration_counter;

        /*
            Detects accidental corruption of the complete
            stored record.
        */
        uint32_t crc32;
    } mathos_rc_pairing_config_t;

    typedef struct
    {
        uint32_t magic;
        uint16_t version;
        uint16_t record_size;

        /*
            Identities of the two devices participating
            in this pairing.
        */
        uint8_t rc_id;
        uint8_t gateway_id;

        /*
            Permanent physical Gateway identity.

            Used as the Fleet lookup identity and authenticated
            by the Pairing-v2 challenge/proof transcript.

            UID identifies the Gateway.
            UID alone is NOT authentication.
        */
        mathos_device_uid_t gateway_uid;

        uint8_t key_derivation_method;
        uint8_t reserved0;
        uint32_t key_generation;
        uint32_t kdf_iteration_count;
        uint8_t pairing_salt[MATHOS_PAIRING_SALT_LEN];
        uint8_t reserved1[4];
        uint32_t crc32;
    } mathos_pairing_package_t;

    typedef struct
    {
        uint32_t magic;
        uint16_t version;
        uint16_t record_size;

        uint8_t rc_id;
        uint8_t gateway_id;

        /*
            Exact Gateway hardware UID from the pairing PACKAGE.

            This UID will become part of the authenticated
            pairing transcript.
        */
        mathos_device_uid_t gateway_uid;

        /*
            Reserved for future challenge types.
        */
        uint8_t reserved0[2];

        /*
            The proof is valid only for this key generation.
        */
        uint32_t key_generation;

        /*
            Generated randomly by the Gateway for every
            pairing attempt.
        */
        uint8_t nonce[MATHOS_PAIRING_NONCE_LEN];

        /*
            Detects accidental corruption.

            Authentication will later be provided by HMAC,
            not by this CRC.
        */
        uint32_t crc32;
    } mathos_pairing_challenge_t;

    typedef struct
    {
        uint32_t magic;
        uint16_t version;
        uint16_t record_size;
        uint8_t rc_id;
        uint8_t gateway_id;
        uint8_t proof_role;
        uint8_t reserved0;
        uint32_t key_generation;
        uint8_t nonce[MATHOS_PAIRING_NONCE_LEN];
        uint8_t proof[MATHOS_PAIRING_PROOF_LEN];

        uint32_t crc32;
    } mathos_pairing_proof_t;

    /*
    ============================================================
    Pairing transport message types
    ============================================================

    These messages travel only while both devices are in
    maintenance/pairing mode.

    They are NOT normal flight-control packets and they do
    NOT use the operational ChaCha20-Poly1305 session.

    Public package/challenge data may travel in plaintext.
    Authentication is provided by the pairing HMAC proofs.
*/
    typedef enum
    {
        MATHOS_PAIRING_MSG_INVALID = 0,

        /*
            Gateway -> RC

            Public pairing parameters:
            identities, generation, KDF parameters and salt.
        */
        MATHOS_PAIRING_MSG_PACKAGE = 1,

        /*
            Gateway -> RC

            Fresh random challenge nonce.
        */
        MATHOS_PAIRING_MSG_CHALLENGE = 2,

        /*
            RC -> Gateway

            HMAC proof demonstrating possession of the
            candidate root key.
        */
        MATHOS_PAIRING_MSG_RC_PROOF = 3,

        /*
            Gateway -> RC

            Mutual-authentication HMAC proof demonstrating
            possession of the same root key.
        */
        MATHOS_PAIRING_MSG_GATEWAY_PROOF = 4,

        /*
            Either direction.

            Used later for explicit success/failure result.
        */
        MATHOS_PAIRING_MSG_RESULT = 5

    } mathos_pairing_message_type_t;

    /*
        ============================================================
        Pairing wire protocol
        ============================================================

        Canonical frame layout:

        byte 0      magic 0
        byte 1      magic 1
        byte 2      protocol version
        byte 3      message type
        byte 4..5   payload length, little-endian
        byte 6..9   sequence number, little-endian
        byte 10..   payload

        IMPORTANT:
        mathos_pairing_wire_header_t is an in-memory
        representation only.

        Never send this C struct using memcpy().
        The serializer/deserializer will write each field
        explicitly so compiler padding cannot change the
        wire format.
    */

#define MATHOS_PAIRING_WIRE_MAGIC_0 0x4DU
#define MATHOS_PAIRING_WIRE_MAGIC_1 0x50U
#define MATHOS_PAIRING_WIRE_VERSION 1U
#define MATHOS_PAIRING_WIRE_HEADER_LEN 10U

/*
    Canonical version-1 pairing PACKAGE payload length.

    This is a wire-format size, not sizeof(struct).
*/
#define MATHOS_PAIRING_PACKAGE_WIRE_LEN \
    (4U + 2U + 2U +                     \
     1U + 1U +                          \
     MATHOS_DEVICE_UID_LEN +            \
     1U + 1U +                          \
     4U + 4U +                          \
     MATHOS_PAIRING_SALT_LEN +          \
     4U +                               \
     4U)

/*
    Canonical version-1 pairing CHALLENGE payload length.

    This is the wire-format size, not sizeof(struct).
*/
#define MATHOS_PAIRING_CHALLENGE_WIRE_LEN \
    (4U + 2U + 2U +                       \
     1U + 1U +                            \
     MATHOS_DEVICE_UID_LEN +              \
     2U +                                 \
     4U +                                 \
     MATHOS_PAIRING_NONCE_LEN +           \
     4U)

    /*
   Canonical version-1 pairing PROOF payload length.

   Layout:
       magic           4
       version         2
       record_size     2
       rc_id           1
       gateway_id      1
       proof_role      1
       reserved0       1
       key_generation  4
       nonce          16
       proof          32
       crc32           4

   Total: 68 bytes.
*/

#define MATHOS_PAIRING_PROOF_WIRE_LEN \
    (4U + 2U + 2U +                   \
     1U + 1U + 1U + 1U +              \
     4U +                             \
     MATHOS_PAIRING_NONCE_LEN +       \
     MATHOS_PAIRING_PROOF_LEN +       \
     4U)

    /*
   Largest version-1 pairing payload currently defined.

   PROOF is currently the largest at 68 bytes.
*/
#define MATHOS_PAIRING_WIRE_MAX_PAYLOAD_LEN \
    MATHOS_PAIRING_PROOF_WIRE_LEN

/*
    Maximum complete version-1 pairing frame:

        10-byte header
        +
        largest pairing payload
*/
#define MATHOS_PAIRING_WIRE_MAX_FRAME_LEN \
    (MATHOS_PAIRING_WIRE_HEADER_LEN +     \
     MATHOS_PAIRING_WIRE_MAX_PAYLOAD_LEN)
    typedef struct
    {
        uint8_t magic_0;
        uint8_t magic_1;

        uint8_t version;
        uint8_t message_type;

        uint16_t payload_len;
        uint32_t sequence;

    } mathos_pairing_wire_header_t;

    /*
    Encode one pairing wire header into its canonical
    10-byte representation.

    No raw struct memcpy is used.
*/
    esp_err_t mathos_pairing_wire_encode_header(
        const mathos_pairing_wire_header_t *header,
        uint8_t output[MATHOS_PAIRING_WIRE_HEADER_LEN]);

    /*
        Decode and validate one canonical 10-byte
        Mathos pairing wire header.
    */
    esp_err_t mathos_pairing_wire_decode_header(
        const uint8_t input[MATHOS_PAIRING_WIRE_HEADER_LEN],
        mathos_pairing_wire_header_t *header);
    /*
        Build one complete canonical pairing frame:

            header + payload

        The caller supplies the already serialized payload.

        output_len receives the exact number of bytes written.
    */
    esp_err_t mathos_pairing_wire_encode_frame(
        const mathos_pairing_wire_header_t *header,
        const uint8_t *payload,
        size_t payload_len,
        uint8_t *output,
        size_t output_size,
        size_t *output_len);
    /*
        Encode an authenticated pairing proof into the
        canonical version-1 wire payload.

        Supports both:
            MATHOS_PAIRING_PROOF_ROLE_RC
            MATHOS_PAIRING_PROOF_ROLE_GATEWAY
    */

    /*
    Decode one complete canonical pairing frame:

        header + payload

    The payload is copied into the caller-provided buffer.

    payload_len receives the exact decoded payload size.
*/
    esp_err_t mathos_pairing_wire_decode_frame(
        const uint8_t *input,
        size_t input_len,
        mathos_pairing_wire_header_t *header,
        uint8_t *payload,
        size_t payload_capacity,
        size_t *payload_len);

    esp_err_t mathos_pairing_proof_encode_payload(
        const mathos_pairing_proof_t *proof,
        uint8_t *output,
        size_t output_size);

    typedef enum
    {
        MATHOS_PAIRING_SESSION_IDLE = 0,
        MATHOS_PAIRING_SESSION_PACKAGE_READY,
        MATHOS_PAIRING_SESSION_CHALLENGE_READY,
        MATHOS_PAIRING_SESSION_RC_CANDIDATE_READY,
        MATHOS_PAIRING_SESSION_RC_PROOF_READY,
        MATHOS_PAIRING_SESSION_RC_PROOF_VERIFIED,
        MATHOS_PAIRING_SESSION_GATEWAY_PROOF_READY,
        MATHOS_PAIRING_SESSION_GATEWAY_PROOF_VERIFIED,
        MATHOS_PAIRING_SESSION_COMMIT_READY,
        MATHOS_PAIRING_SESSION_COMPLETE,
        MATHOS_PAIRING_SESSION_FAILED
    } mathos_pairing_session_state_t;

    typedef struct
    {
        mathos_pairing_session_state_t state;

        /*
            Identifies whether a pairing attempt is active.
        */
        uint8_t active;

        /*
            Number of failed or repeated message attempts.
        */
        uint8_t retry_count;

        uint8_t reserved0[2];

        /*
            Key generation involved in this session.

            This allows stale messages from an older session
            to be rejected quickly.
        */
        uint32_t key_generation;

        /*
            Session start time from esp_timer_get_time().

            The value is stored in microseconds.
        */
        int64_t started_at_us;

        /*
            Public pairing parameters supplied by the Gateway.
        */
        mathos_pairing_package_t package;

        /*
            Random Gateway challenge for this attempt.
        */
        mathos_pairing_challenge_t challenge;

        /*
            Candidate RC configuration.

            This contains derived key material but remains
            in RAM until mutual authentication succeeds.
        */
        mathos_rc_pairing_config_t rc_candidate;

        /*
            Proof sent by the RC.
        */
        mathos_pairing_proof_t rc_proof;

        /*
            Confirmation proof sent by the Gateway.
        */
        mathos_pairing_proof_t gateway_proof;
    } mathos_pairing_session_t;

    void mathos_maintenance_config_set_defaults(
        mathos_maintenance_config_t *config);

    int mathos_maintenance_config_is_valid(
        const mathos_maintenance_config_t *config);

    esp_err_t mathos_maintenance_config_save(
        const mathos_maintenance_config_t *config);

    esp_err_t mathos_maintenance_config_load(
        mathos_maintenance_config_t *config,
        int *loaded_from_nvs);

    esp_err_t mathos_maintenance_softap_start(
        mathos_maintenance_role_t role);

    esp_err_t mathos_maintenance_get_ap_ip(
        char *buffer,
        size_t buffer_size);

    void mathos_gateway_config_set_defaults(
        mathos_gateway_config_t *config);

    void mathos_rc_pairing_config_set_defaults(
        mathos_rc_pairing_config_t *config);

    void mathos_pairing_package_set_defaults(
        mathos_pairing_package_t *package);

    int mathos_pairing_package_is_valid(
        const mathos_pairing_package_t *package);

    int mathos_rc_pairing_config_is_valid(
        const mathos_rc_pairing_config_t *config);

    /*
        Encode the public pairing package into its canonical
        version-1 wire payload.

        The root key is never part of this payload.
    */
    /*
        Encode an active Gateway pairing challenge into
        its canonical version-1 wire payload.
    */
    esp_err_t mathos_pairing_challenge_encode_payload(
        const mathos_pairing_challenge_t *challenge,
        uint8_t *output,
        size_t output_size);

    /*
        Decode and validate one canonical version-1
        pairing CHALLENGE payload.
    */

    /*
        Decode and validate one canonical version-1
        pairing PROOF payload.
    */
    esp_err_t mathos_pairing_proof_decode_payload(
        const uint8_t *input,
        size_t input_size,
        mathos_pairing_proof_t *proof);
    esp_err_t mathos_pairing_challenge_decode_payload(
        const uint8_t *input,
        size_t input_size,
        mathos_pairing_challenge_t *challenge);

    esp_err_t mathos_pairing_package_encode_payload(
        const mathos_pairing_package_t *package,
        uint8_t *output,
        size_t output_size);

    /*
        Decode and validate one canonical version-1
        pairing PACKAGE payload.
    */
    esp_err_t mathos_pairing_package_decode_payload(
        const uint8_t *input,
        size_t input_size,
        mathos_pairing_package_t *package);

    /*
        RC pairing-passphrase callback.

        The maintenance HTTP layer supplies the passphrase
        only for the duration of the request.

        The callback must not retain the pointer.
    */
    typedef esp_err_t (*mathos_maintenance_rc_pairing_callback_t)(
        const char *passphrase);

    /*
        Register the RC application's pairing handler.

        Pass NULL to remove the callback.
    */
    void mathos_maintenance_set_rc_pairing_callback(
        mathos_maintenance_rc_pairing_callback_t callback);

    esp_err_t mathos_rc_pairing_config_save(
        const mathos_rc_pairing_config_t *config);

    esp_err_t mathos_rc_pairing_config_load(
        mathos_rc_pairing_config_t *config,
        int *loaded_from_nvs);

    esp_err_t mathos_pairing_package_from_gateway_config(
        const mathos_gateway_config_t *gateway_config,
        const mathos_device_uid_t *gateway_uid,
        mathos_pairing_package_t *package);

    void mathos_pairing_proof_set_defaults(
        mathos_pairing_proof_t *proof);

    void mathos_pairing_session_set_defaults(
        mathos_pairing_session_t *session);

    void mathos_pairing_session_reset(
        mathos_pairing_session_t *session);

    int mathos_pairing_session_has_timed_out(
        const mathos_pairing_session_t *session);

    esp_err_t mathos_pairing_session_start(
        mathos_pairing_session_t *session,
        const mathos_pairing_package_t *package);

    /*
        Initialize the RC side of a distributed pairing session
        using the PACKAGE and CHALLENGE actually received from
        the Gateway.

        Unlike mathos_pairing_session_start(), this function
        never generates a new challenge.
    */
    esp_err_t mathos_pairing_session_accept_remote_challenge(
        mathos_pairing_session_t *session,
        const mathos_pairing_package_t *package,
        const mathos_pairing_challenge_t *challenge);

    int mathos_pairing_session_register_failure(
        mathos_pairing_session_t *session);

    int mathos_pairing_proof_is_valid(
        const mathos_pairing_proof_t *proof);

    void mathos_pairing_challenge_set_defaults(
        mathos_pairing_challenge_t *challenge);

    int mathos_pairing_challenge_is_valid(
        const mathos_pairing_challenge_t *challenge);

    esp_err_t mathos_pairing_challenge_from_package(
        const mathos_pairing_package_t *package,
        mathos_pairing_challenge_t *challenge);

    esp_err_t mathos_rc_pairing_config_prepare_from_package(
        const mathos_rc_pairing_config_t *current_config,
        const mathos_pairing_package_t *package,
        const char *passphrase,
        mathos_rc_pairing_config_t *candidate_config);

    esp_err_t mathos_pairing_proof_create(
        const uint8_t root_key[MATHOS_GATEWAY_ROOT_KEY_LEN],
        const mathos_pairing_challenge_t *challenge,
        uint8_t proof_role,
        mathos_pairing_proof_t *proof);

    esp_err_t mathos_pairing_proof_verify(
        const uint8_t root_key[MATHOS_GATEWAY_ROOT_KEY_LEN],
        const mathos_pairing_challenge_t *challenge,
        const mathos_pairing_proof_t *proof,
        uint8_t expected_proof_role);

    int mathos_gateway_config_is_valid(
        const mathos_gateway_config_t *config);

    esp_err_t mathos_gateway_config_save(
        const mathos_gateway_config_t *config);

    esp_err_t mathos_pairing_session_prepare_rc_response(
        mathos_pairing_session_t *session,
        const mathos_rc_pairing_config_t *current_config,
        const char *passphrase);

    esp_err_t mathos_pairing_session_prepare_gateway_response(
        mathos_pairing_session_t *session,
        const mathos_gateway_config_t *gateway_config);

    /*
        RC-side completion of mutual authentication.

        Accepts the GATEWAY_PROOF received from the real
        Gateway and verifies it using the RC candidate key
        and the exact challenge already stored in the session.

        On success the session becomes COMMIT_READY.

        This function does NOT write NVS.
    */
    esp_err_t mathos_pairing_session_accept_gateway_proof(
        mathos_pairing_session_t *session,
        const mathos_pairing_proof_t *gateway_proof);

    esp_err_t mathos_gateway_config_load(
        mathos_gateway_config_t *config,
        int *loaded_from_nvs);
    esp_err_t mathos_maintenance_generate_pairing_salt(
        uint8_t salt[MATHOS_PAIRING_SALT_LEN]);

    esp_err_t mathos_maintenance_derive_root_key_from_passphrase(
        const char *passphrase,
        const uint8_t salt[MATHOS_PAIRING_SALT_LEN],
        uint32_t iteration_count,
        uint8_t root_key[MATHOS_GATEWAY_ROOT_KEY_LEN]);

#ifdef __cplusplus
}
#endif