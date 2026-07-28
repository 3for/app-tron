#pragma once

/* Deterministic per-session limits for the heap-backed TIP-712 push parser.
 * They are deliberately below protocol-width maxima because the app has a
 * fixed 16 KiB heap and all type/UI nodes remain resident until approval. */
#define TIP712_MAX_STRUCTS              16U
#define TIP712_MAX_FIELDS               64U
#define TIP712_MAX_ARRAY_LEVELS         32U
#define TIP712_MAX_ARRAY_LEVELS_PER_FIELD 8U
#define TIP712_MAX_IDENTIFIER_LENGTH    64U
/* Existing BulkOrder schemas legitimately render more than 64 leaves once
 * the domain fields are included.  Keep the logical cap below the uint8_t
 * protocol/UI width while letting the tracked heap budget remain the actual
 * resident-memory guard. */
#define TIP712_MAX_UI_PAIRS             128U
#define TIP712_MAX_DYNAMIC_DISPLAY_BYTES 4096U
#define TIP712_MAX_CALLDATA_INFOS        16U
#define TIP712_MAX_FILTER_LABEL_LENGTH   64U
#define TIP712_MAX_AMOUNT_LABEL_LENGTH   25U
