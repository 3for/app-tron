#include <string.h>
#include "apdu_constants.h"
#include "asset_info.h"
#include "network.h"
#include "public_keys.h"
#include "parse.h"
#include "common_utils.h"
#include "io.h"
#include "app_errors.h"
#include "os_pki.h"

#define TYPE_SIZE        1
#define VERSION_SIZE     1
#define NAME_LENGTH_SIZE 1
#define HEADER_SIZE      (TYPE_SIZE + VERSION_SIZE + NAME_LENGTH_SIZE)

#define CHAIN_ID_SIZE         8
#define KEY_ID_SIZE           1
#define ALGORITHM_ID_SIZE     1
#define SIGNATURE_LENGTH_SIZE 1
#define MIN_DER_SIG_SIZE      67
#define MAX_DER_SIG_SIZE      72

#define STAGING_NFT_METADATA_KEY 0
#define PROD_NFT_METADATA_KEY    1

#define ALGORITHM_ID_1 1
#define TYPE_1         1
#define VERSION_1      1

/**
 * Handle the APDU command that provides NFT collection metadata to the app.
 *
 * The flow mirrors app-ethereum's handle_provide_nft_information() (parse a
 * header, the collection name, the contract address, the chain id, the signer
 * key/algorithm identifiers, then verify a DER signature over the structured
 * payload with the Ledger NFT metadata key). The only TRON adaptations are:
 *  - the contract address is a 21-byte TRON address (0x41 + 20), of which only
 *    the canonical 20-byte EVM part is retained, exactly like the TRC-20 token
 *    information handler (cmd_provideTokenInfo.c);
 *  - the 1-byte asset-index response and error codes use TRON's io_send_* API.
 */
int handleProvideNFTInformation(uint8_t p1,
                                uint8_t p2,
                                const uint8_t *workBuffer,
                                uint8_t dataLength) {
    UNUSED(p1);
    UNUSED(p2);
    uint8_t hash[INT256_LENGTH];
    nftInfo_t *nft = NULL;
    size_t offset = 0;
    size_t payloadSize = 0;
    uint8_t collectionNameLength = 0;
    uint64_t chain_id = 0;
    uint8_t signatureLen = 0;
#ifdef HAVE_NFT_STAGING_KEY
    uint8_t valid_keyId = STAGING_NFT_METADATA_KEY;
#else
    uint8_t valid_keyId = PROD_NFT_METADATA_KEY;
#endif

    PRINTF("In handle provide NFTInformation\n");

    // Retrieve the NFT sub-structure from the current asset info slot.
    nft = &get_current_asset_info()->nft;

    PRINTF("Provisioning currentAssetIndex %d\n", tmpCtx.transactionContext.currentAssetIndex);

    // --- Header validation ---
    if (dataLength <= HEADER_SIZE) {
        PRINTF("Data too small for headers: expected at least %d, got %d\n",
               HEADER_SIZE,
               dataLength);
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (workBuffer[offset] != TYPE_1) {
        PRINTF("Unsupported type %d\n", workBuffer[offset]);
        return io_send_sw(E_INCORRECT_DATA);
    }
    offset += TYPE_SIZE;

    if (workBuffer[offset] != VERSION_1) {
        PRINTF("Unsupported version %d\n", workBuffer[offset]);
        return io_send_sw(E_INCORRECT_DATA);
    }
    offset += VERSION_SIZE;

    collectionNameLength = workBuffer[offset];
    offset += NAME_LENGTH_SIZE;

    // --- Payload size validation ---
    // TRON adaptation: the contract address is a 34-char TRON Base58Check string.
    payloadSize = HEADER_SIZE + collectionNameLength + TRON_BASE58CHECK_ADDRESS_SIZE +
                  CHAIN_ID_SIZE + KEY_ID_SIZE + ALGORITHM_ID_SIZE;
    if (dataLength < payloadSize) {
        PRINTF("Data too small for payload: expected at least %d, got %d\n",
               payloadSize,
               dataLength);
        return io_send_sw(E_INCORRECT_DATA);
    }

    if (collectionNameLength > COLLECTION_NAME_MAX_LEN) {
        PRINTF("CollectionName too big: expected max %d, got %d\n",
               COLLECTION_NAME_MAX_LEN,
               collectionNameLength);
        return io_send_sw(E_INCORRECT_DATA);
    }

    // --- Collection name parsing ---
    memcpy(nft->collectionName, workBuffer + offset, collectionNameLength);
    nft->collectionName[collectionNameLength] = '\0';
    PRINTF("Length: %d\n", collectionNameLength);
    PRINTF("CollectionName: %s\n", nft->collectionName);
    offset += collectionNameLength;

    // --- Contract address parsing (TRON adaptation) ---
    // The address is a 34-char TRON Base58Check string ("T..."); decode +
    // checksum-validate it to the canonical 20-byte (EVM) form retained internally,
    // matching cmd_provideTokenInfo.c.
    if (!tronBase58ToBinaryLen((const char *) (workBuffer + offset),
                               TRON_BASE58CHECK_ADDRESS_SIZE,
                               nft->contractAddress)) {
        return io_send_sw(E_INCORRECT_DATA);
    }
    PRINTF("Address: %.*s\n", TRON_BASE58CHECK_ADDRESS_SIZE, workBuffer + offset);
    offset += TRON_BASE58CHECK_ADDRESS_SIZE;

    // --- Chain ID parsing and compatibility check ---
    chain_id = u64_from_BE(workBuffer + offset, CHAIN_ID_SIZE);
    PRINTF("ChainID: %llu\n", chain_id);
    if (!app_compatible_with_chain_id(&chain_id)) {
        UNSUPPORTED_CHAIN_ID_MSG(chain_id);
        return io_send_sw(E_INCORRECT_DATA);
    }
    offset += CHAIN_ID_SIZE;

    // --- Key ID validation ---
    if (workBuffer[offset] != valid_keyId) {
        PRINTF("Unsupported KeyID %d\n", workBuffer[offset]);
        return io_send_sw(E_INCORRECT_DATA);
    }
    offset += KEY_ID_SIZE;

    // --- Algorithm ID validation ---
    if (workBuffer[offset] != ALGORITHM_ID_1) {
        PRINTF("Incorrect algorithmId %d\n", workBuffer[offset]);
        return io_send_sw(E_INCORRECT_DATA);
    }
    offset += ALGORITHM_ID_SIZE;

    // --- Payload hashing ---
    PRINTF("hashing: %.*H\n", payloadSize, workBuffer);
    cx_hash_sha256(workBuffer, payloadSize, hash, sizeof(hash));

    // --- Signature length parsing and validation ---
    if (dataLength < payloadSize + SIGNATURE_LENGTH_SIZE) {
        PRINTF("Data too short to hold signature length\n");
        return io_send_sw(E_INCORRECT_DATA);
    }

    signatureLen = workBuffer[offset];
    PRINTF("Signature len: %d\n", signatureLen);
    if (signatureLen < MIN_DER_SIG_SIZE || signatureLen > MAX_DER_SIG_SIZE) {
        PRINTF("SignatureLen too big or too small. Must be between %d and %d, got %d\n",
               MIN_DER_SIG_SIZE,
               MAX_DER_SIG_SIZE,
               signatureLen);
        return io_send_sw(E_INCORRECT_DATA);
    }
    offset += SIGNATURE_LENGTH_SIZE;

    if (dataLength < payloadSize + SIGNATURE_LENGTH_SIZE + signatureLen) {
        PRINTF("Signature could not fit in data\n");
        return io_send_sw(E_INCORRECT_DATA);
    }

    // --- Signature verification ---
    if (check_signature_with_pubkey(hash,
                                    sizeof(hash),
                                    LEDGER_NFT_METADATA_PUBLIC_KEY,
                                    sizeof(LEDGER_NFT_METADATA_PUBLIC_KEY),
                                    CERTIFICATE_PUBLIC_KEY_USAGE_NFT_METADATA,
                                    (uint8_t *) (workBuffer + offset),
                                    signatureLen) != true) {
#ifndef HAVE_BYPASS_SIGNATURES
        return io_send_sw(E_INCORRECT_DATA);
#endif
    }

    // --- Commit the validated metadata ---
    G_io_apdu_buffer[0] = tmpCtx.transactionContext.currentAssetIndex;
    validate_current_asset_info();
    return io_send_response_pointer(G_io_apdu_buffer, 1, E_OK);
}
