# TIP-712 filter signature V2

This firmware supports only version 2 of TIP-712 filter signatures. Hosts must
check bit `0x40` in the first byte returned by `GET_APP_CONFIGURATION` before
starting a filtered TIP-712 flow. A missing bit is an error; hosts must not
fall back to legacy filter signatures.

Filtering is activated with `INS=0x1e`, `P1=0x00`, `P2=0x02` and empty cdata.
The legacy activation value `P2=0x00` is rejected.

## Canonical signed preimage

Every filter descriptor is signed over the following exact byte sequence:

```text
ASCII "LEDGER/TRON/TIP712/FILTER"        # no trailing NUL
02                                       # signature format version
MM                                       # existing descriptor magic/kind
01 00 08 <chain_id:u64 big-endian>
02 00 14 <resolved_contract:20 bytes>
03 00 1c <schema_hash:28 bytes>
04 <path_length:u16 big-endian> <canonical ASCII path>
05 <body_length:u16 big-endian> <unsigned descriptor cdata>
```

The signature is ECDSA over `SHA256(preimage)`, using the existing coin-meta
CAL key. Each TLV is `tag:u8 || length:u16be || value`; all five TLVs are
present exactly once and in the order shown. Message-info and calldata-info
use an empty path encoded as `04 00 00`.

`body` is the descriptor APDU cdata from offset zero up to, but excluding, the
`sig_len` byte and DER signature. It therefore includes all existing string
lengths, array counts, indices and flags. The descriptor magic separates the
different body layouts.

The contract is the CAL-resolved implementation address when proxy metadata is
present, otherwise the typed-data `verifyingContract`. The firmware freezes
and revalidates chain ID, verifying contract, resolved contract and schema hash
for the complete review.

`P1` is not signed. For field descriptors it only distinguishes a normal path
from the same canonical path replayed for an empty array. The discarded path
is independently constrained to the schema path saved by the firmware.

## CAL deployment

V1 signatures are not compatible and must be regenerated. This remains a
static CAL scheme: chain ID, contract, schema, path and descriptor body are all
static policy data; transaction field values are not part of the preimage.

A reference test vector is pinned in `tests/ragger/test_tip712.py` by
`test_tip712_filter_v2_canonical_preimage_kat`.
