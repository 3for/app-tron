#include <string.h>
#include "tlv_library.h"
#include "read.h"
#include "os_print.h"
#include "common_utils.h"
#include "tlv_apdu.h"
#include "gcs_memory.h"
#include "ui_utils.h"
#include "buffer.h"
#include "utils.h"
#include "challenge.h"
#include "chain_config.h"

static uint8_t *g_tlv_payload;
static uint16_t g_tlv_size;
static uint16_t g_tlv_pos;
static uint8_t g_tlv_owner;
static uint8_t g_tlv_owner_p2;
static f_tlv_payload_handler g_tlv_handler;

static void reset_state(void) {
    if (g_tlv_payload != NULL) {
        explicit_bzero(g_tlv_payload, g_tlv_size);
    }
    gcs_mem_free_and_null((void **) &g_tlv_payload);
    g_tlv_size = 0;
    g_tlv_pos = 0;
    g_tlv_owner = 0;
    g_tlv_owner_p2 = 0;
    g_tlv_handler = NULL;
}

void tlv_apdu_reset(void) {
    reset_state();
}

bool tlv_apdu_in_progress(void) {
    return g_tlv_payload != NULL;
}

bool tlv_apdu_owner_matches(uint8_t owner, uint8_t owner_p2) {
    return tlv_apdu_in_progress() && (g_tlv_owner == owner) &&
           (g_tlv_owner_p2 == owner_p2);
}

bool tlv_from_apdu(uint8_t owner,
                   uint8_t owner_p2,
                   bool first_chunk,
                   uint8_t lc,
                   const uint8_t *payload,
                   uint16_t max_payload_size,
                   f_tlv_payload_handler handler) {
    bool ret = true;
    uint8_t offset = 0;
    uint8_t chunk_length;

    if ((handler == NULL) || (max_payload_size == 0)) {
        reset_state();
        return false;
    }

    if (first_chunk) {
        if (g_tlv_payload != NULL) {
            PRINTF("Error: remnants from an incomplete TLV payload!\n");
            reset_state();
            return false;
        }
        if ((offset + sizeof(g_tlv_size)) > lc) {
            reset_state();
            return false;
        }
        g_tlv_size = read_u16_be(payload, offset);
        offset += sizeof(g_tlv_size);
        g_tlv_pos = 0;
        if ((g_tlv_size == 0) || (g_tlv_size > max_payload_size)) {
            PRINTF("TLV payload length out of bounds: %u\n", g_tlv_size);
            reset_state();
            return false;
        }

        if (g_tlv_size > (lc - offset)) {
            if ((g_tlv_payload = gcs_mem_alloc(g_tlv_size,
                                               GCS_MEM_DESCRIPTOR)) == NULL) {
                reset_state();
                return false;
            }
            g_tlv_owner = owner;
            g_tlv_owner_p2 = owner_p2;
            g_tlv_handler = handler;
        }
    } else if ((g_tlv_payload == NULL) || (g_tlv_owner != owner) ||
               (g_tlv_owner_p2 != owner_p2) ||
               (g_tlv_handler != handler) || (lc == 0)) {
        PRINTF("Invalid or non-progressing TLV continuation\n");
        reset_state();
        return false;
    }
    chunk_length = lc - offset;
    if ((g_tlv_pos + chunk_length) > g_tlv_size) {
        PRINTF("TLV payload bigger than expected!\n");
        reset_state();
        return false;
    }

    if (g_tlv_payload != NULL) {
        memcpy(g_tlv_payload + g_tlv_pos, payload + offset, chunk_length);
    }

    g_tlv_pos += chunk_length;

    if (g_tlv_pos == g_tlv_size) {
        // Create buffer_t for the complete payload
        buffer_t buf;
        if (g_tlv_payload != NULL) {
            // Multi-chunk case: use allocated buffer
            buf = (buffer_t){.ptr = g_tlv_payload, .size = g_tlv_size, .offset = 0};
        } else {
            // Single-chunk case: use APDU data directly
            buf = (buffer_t){.ptr = (uint8_t *) &payload[offset], .size = g_tlv_size, .offset = 0};
        }
        ret = (*handler)(&buf);
        reset_state();
    }
    return ret;
}

/**
 * @brief Parse and check the STRUCTURE_TYPE value.
 *
 * @param[in] data to handle
 * @param[in] expected value
 * @return whether the handling was successful
 */
bool tlv_check_struct_type(const tlv_data_t *data, uint8_t expected) {
    uint8_t value = 0;
    if (!get_uint8_t_from_tlv_data(data, &value)) {
        PRINTF("STRUCTURE_TYPE: failed to extract\n");
        return false;
    }
    CHECK_FIELD_VALUE("STRUCTURE_TYPE", value, expected);
    return true;
}

/**
 * @brief Parse and check the STRUCTURE_VERSION value.
 *
 * @param[in] data to handle
 * @param[in] expected value
 * @return whether the handling was successful
 */
bool tlv_check_struct_version(const tlv_data_t *data, uint8_t expected) {
    uint8_t value = 0;
    if (!get_uint8_t_from_tlv_data(data, &value)) {
        PRINTF("STRUCTURE_VERSION: failed to extract\n");
        return false;
    }
    CHECK_FIELD_VALUE("STRUCTURE_VERSION", value, expected);
    return true;
}

/**
 * @brief Parse and check the STRUCTURE_TYPE value.
 *
 * @param[in] data to handle
 * @return whether the handling was successful
 */
bool tlv_check_challenge(const tlv_data_t *data) {
    uint32_t challenge = 0;
    if (!get_uint32_t_from_tlv_data(data, &challenge)) {
        PRINTF("CHALLENGE: failed to extract\n");
        return false;
    }
    return check_challenge(challenge);
}

/**
 * @brief Parse and get the CHAIN_ID value.
 *
 * @param[in] data to handle
 * @param[out] chain_id extracted chain ID
 * @return whether the handling was successful
 *
 * @note The chain ID is expected to be in the range of valid Ethereum chain IDs
 * (1 to 2^48-1, excluding some reserved values).
 * See https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2294.md
 */
bool tlv_get_chain_id(const tlv_data_t *data, uint64_t *chain_id) {
    if (!chain_id) {
        PRINTF("CHAIN_ID: null pointer provided\n");
        return false;
    }
    if (!get_uint64_t_from_tlv_data(data, chain_id)) {
        PRINTF("CHAIN_ID: failed to extract\n");
        return false;
    }
    // Check if the chain ID is supported
    if ((*chain_id > MAX_VALID_CHAIN_ID) || (*chain_id == 0)) {
        PRINTF("Unsupported chain ID: %llu\n", *chain_id);
        return false;
    }
    return true;
}

/**
 * @brief Parse and get a HASH value.
 *
 * @param[in] data to handle
 * @param[out] out buffer to store the hash
 * @param[in] max_size of the hash
 * @return whether the handling was successful
 */
bool tlv_get_hash(const tlv_data_t *data, uint8_t *out, uint16_t max_size) {
    buffer_t hash = {0};
    if (!out) {
        PRINTF("HASH: null pointer provided\n");
        return false;
    }
    if (!max_size) {
        PRINTF("HASH: invalid size\n");
        return false;
    }
    if (!get_buffer_from_tlv_data(data, &hash, 0, max_size)) {
        PRINTF("HASH: failed to extract\n");
        return false;
    }
    memmove((void *) out, hash.ptr, hash.size);
    return true;
}

/**
 * @brief Parse and get a valid ADDRESS value.
 *
 * @param[in] data to handle
 * @param[out] out buffer to store the hash
 * @return whether the handling was successful
 */
bool tlv_get_address(const tlv_data_t *data, uint8_t *out) {
    buffer_t address = {0};
    if (!out) {
        PRINTF("ADDRESS: null pointer provided\n");
        return false;
    }
    // CAL descriptors carry the address as a 34-char TRON Base58Check string ("T...").
    // The signature is verified over these raw bytes (the field is hashed as-is); here
    // we decode + checksum-validate them down to the canonical 20-byte form kept
    // internally, so all downstream comparison/display is unchanged.
    if (!get_buffer_from_tlv_data(data,
                                  &address,
                                  TRON_BASE58CHECK_ADDRESS_SIZE,
                                  TRON_BASE58CHECK_ADDRESS_SIZE)) {
        PRINTF("ADDRESS: failed to extract\n");
        return false;
    }
    if (!tronBase58ToBinaryLen((const char *) address.ptr, address.size, out)) {
        PRINTF("ADDRESS: invalid TRON Base58 address\n");
        return false;
    }
    return true;
}

/**
 * @brief Parse and get an string.
 *
 * @param[in] data to handle
 * @param[out] out extracted string
 * @param[in] min_len minimum valid length
 * @param[in] max_len maximum valid length
 * @return whether the handling was successful
 */
bool tlv_get_printable_string(const tlv_data_t *data,
                              char *out,
                              uint32_t min_len,
                              uint32_t max_len) {
    if ((data == NULL) || (data->value.ptr == NULL) || (out == NULL)) {
        PRINTF("STRING: null pointer provided\n");
        return false;
    }
    if (min_len > max_len) {
        PRINTF("STRING: Invalid limits provided\n");
        return false;
    }
    /* Validate the complete signed wire value before converting it to a C string.
     * Otherwise an embedded NUL would hide an authenticated suffix from the UI. */
    if ((memchr(data->value.ptr, '\0', data->value.size) != NULL) ||
        !is_printable((const char *) data->value.ptr, data->value.size)) {
        PRINTF("STRING contains NUL or non-printable bytes!\n");
        return false;
    }
    // Extract the string (with null terminator added by get_string_from_tlv_data)
    // max_len is the buffer capacity including the null terminator
    if (!get_string_from_tlv_data(data, out, min_len, max_len)) {
        PRINTF("STRING: failed to extract\n");
        return false;
    }
    return true;
}

/**
 * @brief Parse and get an uint16_t value.
 *
 * @param[in] data to handle
 * @param[out] out extracted value
 * @param[in] min_val minimum valid value (inclusive)
 * @param[in] max_val maximum valid value (inclusive)
 * @return whether the handling was successful
 */
bool tlv_get_uint16_range(const tlv_data_t *data,
                          uint16_t *out,
                          uint16_t min_val,
                          uint16_t max_val) {
    uint16_t value = 0;
    if (!out) {
        PRINTF("UINT16: null pointer provided\n");
        return false;
    }
    if (min_val > max_val) {
        PRINTF("UINT16: Invalid limits provided\n");
        return false;
    }
    if (!get_uint16_t_from_tlv_data(data, &value)) {
        PRINTF("UINT16: failed to extract\n");
        return false;
    }
    if ((value < min_val) || (value > max_val)) {
        PRINTF("UINT16: not in range\n");
        return false;
    }
    *out = value;
    return true;
}

/**
 * @brief Parse and get an uint8_t value.
 *
 * @param[in] data to handle
 * @param[out] out extracted value
 * @param[in] min_val minimum valid value (inclusive)
 * @param[in] max_val maximum valid value (inclusive)
 * @return whether the handling was successful
 */
bool tlv_get_uint8_range(const tlv_data_t *data, uint8_t *out, uint8_t min_val, uint8_t max_val) {
    uint8_t value = 0;
    if (!out) {
        PRINTF("UINT8: null pointer provided\n");
        return false;
    }
    if (min_val > max_val) {
        PRINTF("UINT8: Invalid limits provided\n");
        return false;
    }
    if (!get_uint8_t_from_tlv_data(data, &value)) {
        PRINTF("UINT8: failed to extract\n");
        return false;
    }
    if ((value < min_val) || (value > max_val)) {
        PRINTF("UINT8: not in range\n");
        return false;
    }
    *out = value;
    return true;
}

/**
 * @brief Parse and check an uint8_t value.
 *
 * @param[in] data to handle
 * @param[out] out extracted value
 * @param[in] expected expected value
 * @return whether the handling was successful
 */
bool tlv_check_uint8(const tlv_data_t *data, uint8_t expected) {
    uint8_t value = 0;
    if (!get_uint8_t_from_tlv_data(data, &value)) {
        PRINTF("UINT8: failed to extract\n");
        return false;
    }
    if (value != expected) {
        PRINTF("UINT8: Value mismatch (%d /%d)!\n", value, expected);
        return false;
    }
    return true;
}
