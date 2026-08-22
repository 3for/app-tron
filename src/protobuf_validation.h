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

#ifndef PROTOBUF_VALIDATION_H
#define PROTOBUF_VALIDATION_H

#include <stdbool.h>

#include "pb_decode.h"

/* Decode chain transaction data under the application unknown-field policy.
 * Any field not represented by the generated Ledger schema is skipped for
 * java-tron wire compatibility and reported to the caller so clear signing can
 * be disabled for the complete transaction.
 */
bool pb_decode_transaction(pb_istream_t *stream,
                           const pb_msgdesc_t *fields,
                           void *dest_struct,
                           bool *has_unreviewed_fields);

#endif
