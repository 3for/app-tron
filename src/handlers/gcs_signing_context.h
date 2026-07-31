#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Lifecycle helpers owned by INS_SIGN_GCS. */
void gcs_signing_context_cleanup(void);
bool gcs_signing_in_progress(void);

/* Descriptor accounting is applied only to the GCS transaction flow. */
bool gcs_account_descriptor_apdu(void);
bool gcs_account_descriptor(size_t descriptor_size, bool rendered_field);

/* Append firmware-forced transaction fields after authenticated TX_INFO intent. */
bool gcs_add_forced_fields(void);
