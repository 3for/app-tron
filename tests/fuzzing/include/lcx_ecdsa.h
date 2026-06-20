#pragma once
// Host-side shim for the SDK <lcx_ecdsa.h>. The ECDSA/curve types and curve id
// (CX_CURVE_256K1) used by the GCS descriptor verification are provided by the
// existing cx.h mock; descriptor signature checks go through the public_keys.h
// mock (check_signature_with_pubkey).
#include "cx.h"

// Max DER/ASN.1 length of an ECDSA-secp256 signature, as the SDK defines it.
#ifndef CX_ECDSA_SHA256_SIG_MAX_ASN1_LENGTH
#define CX_ECDSA_SHA256_SIG_MAX_ASN1_LENGTH 72
#endif
#ifndef CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH
#define CX_ECDSA_SHA256_SIG_MIN_ASN1_LENGTH 8
#endif
