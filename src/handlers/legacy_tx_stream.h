#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "core/Tron.pb.h"
#include "pb.h"

// java-tron rejects serialized transactions larger than 500 KiB. INS_SIGN
// receives raw_data rather than the complete Transaction, but applying the
// same ceiling provides a simple, protocol-aligned upper bound.
#define LEGACY_TX_MAX_RAW_SIZE       (500U * 1024U)
#define LEGACY_TX_MAX_PARAMETER_SIZE 4096U
#define LEGACY_TX_MAX_TYPE_URL_SIZE  64U
#define LEGACY_TX_STREAM_MAX_NESTING 3U

typedef enum {
    LEGACY_TX_CTX_RAW = 0,
    LEGACY_TX_CTX_CONTRACT,
    LEGACY_TX_CTX_ANY,
    LEGACY_TX_CTX_COUNT,
} legacy_tx_context_t;

typedef struct {
    legacy_tx_context_t context;
    size_t remaining;
    bool bounded;
} legacy_tx_frame_t;

typedef enum {
    LEGACY_TX_MODE_KEY = 0,
    LEGACY_TX_MODE_VARINT,
    LEGACY_TX_MODE_LENGTH,
    LEGACY_TX_MODE_BYTES,
} legacy_tx_mode_t;

typedef enum {
    LEGACY_TX_BYTES_SKIP = 0,
    LEGACY_TX_BYTES_TYPE_URL,
    LEGACY_TX_BYTES_PARAMETER,
} legacy_tx_bytes_action_t;

typedef struct {
    void (*on_begin)(void *ctx, size_t parameter_len);
    void (*on_chunk)(void *ctx, const uint8_t *data, size_t data_len);
    void (*on_end)(void *ctx);
    void *ctx;
} legacy_parameter_observer_t;

typedef struct {
    protocol_Transaction_Contract_ContractType contract_type;
    int32_t permission_id;
    int64_t fee_limit;
    uint64_t custom_data_len;
    size_t raw_data_size;
    const uint8_t *parameter;
    size_t parameter_len;
    bool parameter_overflow;
} legacy_tx_stream_result_t;

typedef struct {
    legacy_tx_frame_t frames[LEGACY_TX_STREAM_MAX_NESTING];
    size_t depth;
    size_t total_len;

    legacy_tx_mode_t mode;
    legacy_tx_bytes_action_t bytes_action;
    uint32_t pending_tag;
    pb_wire_type_t pending_wire;

    uint64_t varint_value;
    uint8_t varint_shift;
    uint8_t varint_count;
    size_t bytes_remaining;

    bool contract_seen;
    bool parameter_message_seen;
    bool contract_type_seen;
    bool permission_id_seen;
    bool fee_limit_seen;
    bool custom_data_seen;
    bool type_url_seen;
    bool parameter_seen;
    bool error;
    bool finished;

    protocol_Transaction_Contract_ContractType contract_type;
    int32_t permission_id;
    int64_t fee_limit;
    uint64_t custom_data_len;

    uint8_t type_url[LEGACY_TX_MAX_TYPE_URL_SIZE];
    size_t type_url_len;
    uint8_t parameter[LEGACY_TX_MAX_PARAMETER_SIZE];
    size_t parameter_len;
    size_t parameter_capture_len;
    size_t capture_offset;
    bool parameter_overflow;
    legacy_parameter_observer_t parameter_observer;

    // All accepted envelope fields are singular in the legacy signing model.
    // Track them per protobuf context so duplicate encodings fail closed.
    uint32_t seen_fields[LEGACY_TX_CTX_COUNT];
} legacy_tx_stream_t;

void legacy_tx_stream_init(legacy_tx_stream_t *stream,
                           const legacy_parameter_observer_t *observer);
bool legacy_tx_stream_feed(legacy_tx_stream_t *stream, const uint8_t *data, size_t len);
bool legacy_tx_stream_finish(legacy_tx_stream_t *stream, legacy_tx_stream_result_t *result);
