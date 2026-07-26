#pragma once

#include <stddef.h>

/*
 * Generic Clear Signing v1 limits. Raw data is streamed and follows
 * java-tron's 500 KiB transaction limit; retained calldata/descriptors use
 * separate, device-oriented caps below.
 */
#define GCS_MAX_RAW_DATA_SIZE            (500U * 1024U)
#define GCS_MAX_STORE_APDUS              2048U
#define GCS_MAX_ROOT_CALLDATA_TOTAL_SIZE 4096U
#define GCS_MAX_NESTED_CALLDATA_SIZE     4096U
#define GCS_MAX_DYNAMIC_VALUE_SIZE       4096U
#define GCS_MAX_CALLDATA_FOOTPRINT_BYTES (9U * 1024U)
#define GCS_MAX_TRACKED_LIVE_BYTES       (12U * 1024U)
#define GCS_HEAP_RESERVE_BYTES           (4U * 1024U)

#define GCS_MAX_DESCRIPTOR_SIZE             4096U
#define GCS_MAX_DESCRIPTOR_COUNT            64U
#define GCS_MAX_DESCRIPTOR_THROUGHPUT_BYTES (32U * 1024U)
#define GCS_MAX_RENDERED_FIELDS             64U
#define GCS_MAX_TX_CONTEXTS                 16U
#define GCS_MAX_BATCH_TRANSACTIONS_HARD_LIMIT 16U
#define GCS_MAX_UI_PAIRS                     82U

#define GCS_MAX_CONSTRAINTS_PER_FIELD 16U
#define GCS_MAX_CONSTRAINT_VALUE_SIZE 256U
