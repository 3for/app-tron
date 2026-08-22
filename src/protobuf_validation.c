/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2026 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ********************************************************************************/

#include <stdbool.h>
#include <stdint.h>

#include "pb.h"
#include "pb_decode.h"
#include "core/Tron.pb.h"
#include "protobuf_validation.h"

/* Ledger apps process APDUs serially. Limit the permissive policy to an
 * explicit transaction decode call; signed token/exchange metadata remains
 * strict and cannot acquire alternate protobuf semantics.
 */
static bool *G_has_unreviewed_fields;

/* FT_IGNORE fields do not receive generated tag macros. Keep these values in
 * lockstep with protocol.Transaction.raw in proto/core/Tron.proto. */
enum transaction_raw_unmodeled_tag_e {
    TRANSACTION_RAW_REF_BLOCK_BYTES_TAG = 1,
    TRANSACTION_RAW_REF_BLOCK_NUM_TAG = 3,
    TRANSACTION_RAW_REF_BLOCK_HASH_TAG = 4,
    TRANSACTION_RAW_EXPIRATION_TAG = 8,
    TRANSACTION_RAW_TIMESTAMP_TAG = 14,
};

/*
 * Transaction.raw contains chain bookkeeping fields that are signed but do
 * not affect the action shown during clear signing. They were deliberately
 * generated with FT_IGNORE to save RAM, so nanopb otherwise sees them as
 * unknown. Admit these established fields without degrading the review.
 * Every other unmodeled transaction field is admitted only while decoding a
 * transaction and forces full-hash blind signing.
 */
bool pb_allow_unknown_field(const pb_msgdesc_t *fields, uint32_t tag, pb_wire_type_t wire_type) {
    if (fields == protocol_Transaction_raw_fields) {
        switch (tag) {
            case TRANSACTION_RAW_REF_BLOCK_BYTES_TAG:
            case TRANSACTION_RAW_REF_BLOCK_HASH_TAG:
                if (wire_type == PB_WT_STRING) {
                    return true;
                }
                break;

            case TRANSACTION_RAW_REF_BLOCK_NUM_TAG:
            case TRANSACTION_RAW_EXPIRATION_TAG:
            case TRANSACTION_RAW_TIMESTAMP_TAG:
                if (wire_type == PB_WT_VARINT) {
                    return true;
                }
                break;

            default:
                break;
        }
    }

    if (G_has_unreviewed_fields != NULL) {
        *G_has_unreviewed_fields = true;
        return true;
    }

    return false;
}

bool pb_decode_transaction(pb_istream_t *stream,
                           const pb_msgdesc_t *fields,
                           void *dest_struct,
                           bool *has_unreviewed_fields) {
    if ((has_unreviewed_fields == NULL) || (G_has_unreviewed_fields != NULL)) {
        return false;
    }

    G_has_unreviewed_fields = has_unreviewed_fields;
    bool result = pb_decode(stream, fields, dest_struct);
    G_has_unreviewed_fields = NULL;
    return result;
}
