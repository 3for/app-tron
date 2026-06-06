#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * Bridge between the TRON streaming protobuf decoder and the Generic Clear
 * Signing (generic_tx_parser) calldata store.
 *
 * The TRON decoder (transaction_trigger_decode) reports every byte of a
 * TriggerSmartContract.data field through a trigger-data observer, together with
 * its offset and the total data length. This module registers such an observer
 * to rebuild the full EVM calldata into `g_parked_calldata`, mirroring what
 * app-ethereum does while streaming the RLP `data` field (eth_ustream.c).
 */

/**
 * Reset the bridge accumulation state.
 *
 * Must be called before feeding a new TriggerSmartContract through the decoder.
 * Frees any half-built parked calldata left over from a previous (aborted) run.
 */
void gcs_bridge_reset(void);

/**
 * Trigger-data observer to register through
 * tron_stream_decoder_set_trigger_data_observer().
 *
 * Accumulates the first CALLDATA_SELECTOR_SIZE bytes as the selector, allocates
 * `g_parked_calldata` once the selector is complete, then appends the remaining
 * bytes (the ABI-encoded arguments) into it.
 *
 * @return whether the byte(s) were handled successfully
 */
bool gcs_bridge_feed_data_chunk(void *ctx,
                                const uint8_t *chunk,
                                size_t chunk_len,
                                size_t chunk_offset,
                                size_t total_len);

/**
 * Register the parked calldata as the root transaction context.
 *
 * @param[in] owner21 21-byte TRON owner address (0x41 + 20), or NULL
 * @param[in] contract21 21-byte TRON contract address (0x41 + 20), or NULL
 * @param[in] call_value the TriggerSmartContract call value (TRX, in SUN)
 * @param[in] chain_id the TRON chain id used by the GCS descriptors
 * @return whether the tx context was created successfully
 */
bool gcs_bridge_finalize(const uint8_t *owner21,
                         const uint8_t *contract21,
                         uint64_t call_value,
                         uint64_t chain_id);

/**
 * Free any parked calldata that was not handed over to a tx context (error
 * path). Safe to call when nothing is parked.
 */
void gcs_bridge_abort(void);
