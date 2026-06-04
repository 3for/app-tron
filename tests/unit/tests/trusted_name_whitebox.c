#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <cmocka.h>

#include "cx.h"
#include "common_utils.h"
#include "parse.h"
#include "read.h"
#include "bip32_path_parser.h"
#include "../../../src/handlers/provideTrustedName/trusted_name.h"

#ifndef explicit_bzero
#define explicit_bzero(ptr, len) memset((ptr), 0, (len))
#endif

#define MAJOR_VERSION 1
#define MINOR_VERSION 0
#define PATCH_VERSION 0
#define ARRAYLEN(a) (sizeof(a) / sizeof((a)[0]))
#define PRINTF(...) ((void) 0)

typedef struct {
    uint8_t publicKey[65];
    char address58[35];
    uint8_t chainCode[32];
    bool getChaincode;
} publicKeyContext_t;

const uint8_t LEDGER_SIGNATURE_PUBLIC_KEY[65] = {0};
const uint8_t TRUSTED_NAME_PUB_KEY[65] = {0};

static uint32_t mock_challenge = 0x11223344U;
static uint8_t mock_owner_address[ADDRESS_LENGTH] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
};

uint32_t get_challenge(void) {
    return mock_challenge;
}

void hash_nbytes(const uint8_t *const bytes_ptr, size_t n, cx_hash_t *hash_ctx) {
    (void) cx_hash_no_throw(hash_ctx, 0U, bytes_ptr, n, NULL, 0U);
}

void buf_shrink_expand(const uint8_t *src, size_t src_size, uint8_t *dst, size_t dst_size) {
    memset(dst, 0, dst_size);
    if (src_size > dst_size) {
        memcpy(dst, src + (src_size - dst_size), dst_size);
    } else {
        memcpy(dst + (dst_size - src_size), src, src_size);
    }
}

uint64_t u64_from_BE(const uint8_t *in, uint8_t size) {
    uint64_t out = 0U;

    for (uint8_t i = 0; i < size; i++) {
        out = (out << 8) | in[i];
    }
    return out;
}

off_t read_bip32_path(const uint8_t *buffer, size_t length, bip32_path_t *path) {
    return read_bip32_path_words(buffer, length, &path->length, path->indices, MAX_BIP32_PATH);
}

int check_signature_with_pubkey(const char *tag,
                                uint8_t *buffer,
                                const uint8_t bufLen,
                                const uint8_t *PubKey,
                                const uint8_t keyLen,
                                const uint8_t keyUsageExp,
                                uint8_t *signature,
                                const uint8_t sigLen) {
    (void) tag;
    (void) buffer;
    (void) bufLen;
    (void) PubKey;
    (void) keyLen;
    (void) keyUsageExp;
    (void) signature;
    (void) sigLen;
    return CX_OK;
}

void getAddressFromPublicKey(const uint8_t *publicKey,
                             uint8_t address[static TRON_ADDRESS_SIZE]) {
    memset(address, 0, TRON_ADDRESS_SIZE);
    address[0] = 0x41;
    memcpy(address + 1, publicKey + 1, ADDRESS_LENGTH);
}

int initPublicKeyContext(bip32_path_t *bip32_path,
                         char *address58,
                         publicKeyContext_t *public_key_ctx) {
    (void) bip32_path;
    (void) address58;

    memset(public_key_ctx, 0, sizeof(*public_key_ctx));
    memcpy(public_key_ctx->publicKey + 1, mock_owner_address, ADDRESS_LENGTH);
    return 0;
}

#define static
#define inline
#include "../../../src/handlers/provideTrustedName/trusted_name.c"
#undef inline
#undef static

static void mark_received_tag(s_trusted_name_ctx *ctx, TLV_tag_t tag) {
    ctx->received_tags.tag_to_flag_function = parse_tlv_trusted_name_tag_to_flag;
    ctx->received_tags.flags |= parse_tlv_trusted_name_tag_to_flag(tag);
}

static void init_base_ctx(s_trusted_name_ctx *ctx) {
    memset(ctx, 0, sizeof(*ctx));
    cx_sha256_init(&ctx->hash_ctx);
    ctx->trusted_name.struct_version = 2U;
    memcpy(ctx->trusted_name.addr, mock_owner_address, ADDRESS_LENGTH);
    ctx->trusted_name.chain_id = 0x44AA55U;
    ctx->key_id = TN_KEY_ID_DOMAIN_SVC;
    static const uint8_t mock_signature[] = {0x01U};

    ctx->sig_size = sizeof(mock_signature);
    ctx->sig = mock_signature;
    mark_received_tag(ctx, TAG_STRUCTURE_TYPE);
    mark_received_tag(ctx, TAG_STRUCTURE_VERSION);
    mark_received_tag(ctx, TAG_SIGNER_KEY_ID);
    mark_received_tag(ctx, TAG_SIGNER_ALGO);
    mark_received_tag(ctx, TAG_DER_SIGNATURE);
    mark_received_tag(ctx, TAG_TRUSTED_NAME);
    mark_received_tag(ctx, TAG_ADDRESS);
    mark_received_tag(ctx, TAG_CHAIN_ID);
    mark_received_tag(ctx, TAG_TRUSTED_NAME_TYPE);
    mark_received_tag(ctx, TAG_TRUSTED_NAME_SOURCE);
}

static void test_validate_name_rules(void **state) {
    (void) state;

    s_trusted_name info = {0};

    info.struct_version = 1U;
    strcpy(info.name, "ledger.eth");
    assert_true(validate_trusted_name_value(&info));
    strcpy(info.name, "MyLedger");
    assert_false(validate_trusted_name_value(&info));

    info.struct_version = 2U;
    info.name_type = TN_TYPE_ACCOUNT;
    info.name_source = TN_SOURCE_ENS;
    strcpy(info.name, "ledger.eth");
    assert_true(validate_trusted_name_value(&info));
    strcpy(info.name, "MyLedger");
    assert_false(validate_trusted_name_value(&info));

    info.name_source = TN_SOURCE_MAB;
    strcpy(info.name, "MyLedger");
    assert_true(validate_trusted_name_value(&info));

    info.name_type = TN_TYPE_TOKEN;
    info.name_source = TN_SOURCE_CAL;
    strcpy(info.name, "Wrapped TRX");
    assert_true(validate_trusted_name_value(&info));
}

static void test_mab_missing_owner_metadata_is_rejected(void **state) {
    s_trusted_name_ctx ctx;

    (void) state;
    init_base_ctx(&ctx);
    ctx.trusted_name.name_type = TN_TYPE_ACCOUNT;
    ctx.trusted_name.name_source = TN_SOURCE_MAB;
    strcpy(ctx.trusted_name.name, "MyLedger");
    mark_received_tag(&ctx, TAG_CHALLENGE);

    assert_false(verify_trusted_name_struct(&ctx));
}

static void test_duplicate_tlv_tag_is_rejected(void **state) {
    static const uint8_t payload[] = {
        0x01U, 0x01U, 0x03U,
        0x01U, 0x01U, 0x03U,
    };
    s_trusted_name_ctx ctx = {0};
    const buffer_t buf = {.ptr = (uint8_t *) payload, .size = sizeof(payload), .offset = 0U};

    (void) state;
    cx_sha256_init(&ctx.hash_ctx);

    assert_false(handle_trusted_name_tlv_payload(&buf, &ctx));
}

static void test_mab_owner_metadata_is_accepted(void **state) {
    s_trusted_name_ctx ctx;

    (void) state;
    init_base_ctx(&ctx);
    ctx.trusted_name.name_type = TN_TYPE_ACCOUNT;
    ctx.trusted_name.name_source = TN_SOURCE_MAB;
    strcpy(ctx.trusted_name.name, "MyLedger");
    memcpy(ctx.owner, mock_owner_address, sizeof(ctx.owner));
    ctx.owner_deriv_path.length = 5U;
    ctx.owner_deriv_path.indices[0] = 0x8000002CU;
    ctx.owner_deriv_path.indices[1] = 0x800000C3U;
    ctx.owner_deriv_path.indices[2] = 0x80000000U;
    ctx.owner_deriv_path.indices[3] = 0U;
    ctx.owner_deriv_path.indices[4] = 0U;
    mark_received_tag(&ctx, TAG_CHALLENGE);
    mark_received_tag(&ctx, TAG_OWNER);
    mark_received_tag(&ctx, TAG_OWNER_DERIV_PATH);

    trusted_name_cleanup();
    assert_true(verify_trusted_name_struct(&ctx));
    assert_true(has_trusted_name());
}

static void test_lookup_is_non_destructive(void **state) {
    s_trusted_name_ctx ens_ctx;
    s_trusted_name_ctx token_ctx;
    const e_name_type account_type = TN_TYPE_ACCOUNT;
    const e_name_type token_type = TN_TYPE_TOKEN;
    const e_name_source ens_source = TN_SOURCE_ENS;
    const e_name_source cal_source = TN_SOURCE_CAL;
    const uint64_t chain_id = 0x44AA55U;
    const s_trusted_name *trusted_name;

    (void) state;

    trusted_name_cleanup();

    init_base_ctx(&ens_ctx);
    ens_ctx.trusted_name.name_type = TN_TYPE_ACCOUNT;
    ens_ctx.trusted_name.name_source = TN_SOURCE_ENS;
    strcpy(ens_ctx.trusted_name.name, "ledger.eth");
    mark_received_tag(&ens_ctx, TAG_CHALLENGE);
    assert_true(verify_trusted_name_struct(&ens_ctx));

    init_base_ctx(&token_ctx);
    token_ctx.trusted_name.name_type = TN_TYPE_TOKEN;
    token_ctx.trusted_name.name_source = TN_SOURCE_CAL;
    strcpy(token_ctx.trusted_name.name, "USDT");
    assert_true(verify_trusted_name_struct(&token_ctx));

    trusted_name = get_trusted_name(1,
                                    &account_type,
                                    1,
                                    &ens_source,
                                    &chain_id,
                                    mock_owner_address);
    assert_non_null(trusted_name);
    assert_string_equal(trusted_name->name, "ledger.eth");

    trusted_name = get_trusted_name(1,
                                    &account_type,
                                    1,
                                    &ens_source,
                                    &chain_id,
                                    mock_owner_address);
    assert_non_null(trusted_name);
    assert_string_equal(trusted_name->name, "ledger.eth");

    trusted_name = get_trusted_name(1, &token_type, 1, &cal_source, &chain_id, mock_owner_address);
    assert_non_null(trusted_name);
    assert_string_equal(trusted_name->name, "USDT");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_validate_name_rules),
        cmocka_unit_test(test_mab_missing_owner_metadata_is_rejected),
        cmocka_unit_test(test_duplicate_tlv_tag_is_rejected),
        cmocka_unit_test(test_mab_owner_metadata_is_accepted),
        cmocka_unit_test(test_lookup_is_non_destructive),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
