#*******************************************************************************
#   Ledger App
#   (c) 2018 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.target

APPNAME = Tron

splitVersion=$(word $2, $(subst ., , $1))

APPVERSION = $(file < VERSION)

APPVERSION_M=$(call splitVersion, $(APPVERSION), 1)
APPVERSION_N=$(call splitVersion, $(APPVERSION), 2)
APPVERSION_P=$(call splitVersion, $(APPVERSION), 3)

# - <VARIANT_PARAM> is the name of the parameter which should be set
#   to specify the variant that should be build.
# - <VARIANT_VALUES> a list of variant that can be build using this app code.
#   * It must at least contains one value.
#   * Values can be the app ticker or anything else but should be unique.
VARIANT_PARAM = COIN
VARIANT_VALUES = tron

CURVE_APP_LOAD_PARAMS = secp256k1
PATH_APP_LOAD_PARAMS = "44'/195'"  # purpose=coin(44) / coin_type=Tron(1)

ICON_NANOX = icons/nanox_app_tron.gif
ICON_NANOSP = icons/nanox_app_tron.gif
ICON_STAX = icons/stax_app_tron.gif
ICON_FLEX = icons/flex_app_tron.gif
ICON_APEX_P = icons/apex_app_tron.png

ENABLE_BLUETOOTH = 1
ENABLE_SWAP = 1
ENABLE_NBGL_FOR_NANO_DEVICES = 1
ENABLE_NBGL_QRCODE = 1
ENABLE_DYNAMIC_ALLOC = 1
ENABLE_PKI_LIBRARY = 1
ENABLE_TLV_LIBRARY = 1
# Linked-list library, used by the list-based TIP-712 typed-data model
ENABLE_LISTS_LIBRARY = 1
DEFINES += HAVE_SDK_LL_LIB

# Gated/"dated" signing (INS_PROVIDE_GATING 0x38), ported from app-ethereum.
DEFINES += HAVE_GATING_SUPPORT

# Enabling DEBUG flag will enable PRINTF and disable optimizations
DEBUG ?= 0

APP_SOURCE_PATH  += src
APP_SOURCE_FILES += $(filter-out ./tron-plugin-sdk/src/main.c, $(wildcard ./tron-plugin-sdk/src/*.c))
INCLUDES_PATH += ./tron-plugin-sdk/src

# Don't define plugin function in the plugin SDK
DEFINES += IS_NOT_A_PLUGIN

# ENS
TRUSTED_NAME_TEST_KEY ?= 0
ifneq ($(TRUSTED_NAME_TEST_KEY),0)
    DEFINES += HAVE_TRUSTED_NAME_TEST_KEY
endif

# Activate requested features
# ---------------------------
# Bypass the signature verification for provideTokenInfo calls
BYPASS_SIGNATURES ?= 0
ifneq ($(BYPASS_SIGNATURES),0)
    DEFINES += HAVE_BYPASS_SIGNATURES
endif

# Use a fixed challenge (0x12345678) and skip its verification, so trusted-name /
# proxy descriptors that embed a challenge can be pre-generated for tests/examples
# without a live GET_CHALLENGE round-trip. Mirrors app-ethereum's CHALLENGE_NO_CHECK.
CHALLENGE_NO_CHECK ?= 0
ifneq ($(CHALLENGE_NO_CHECK),0)
    DEFINES += HAVE_CHALLENGE_NO_CHECK
endif

# CryptoAssetsList key
CAL_TEST_KEY ?= 0
ifneq ($(CAL_TEST_KEY),0)
    # Key used in our test framework
    DEFINES += HAVE_CAL_TEST_KEY
endif
CAL_STAGING_KEY ?= 0
ifneq ($(CAL_STAGING_KEY),0)
    # Key used by the staging CAL
    DEFINES += HAVE_CAL_STAGING_KEY
endif

DEFINES += APP_TICKER=\"TRX\" APP_CHAIN_ID=728126428

.PHONY: proto
proto:
	$(MAKE) -C proto

cleanall : clean
	$(MAKE) -C proto clean

# nanopb
#include nanopb/extra/nanopb.mk
NANOPB_DIR = nanopb

CFLAGS += "-I$(NANOPB_DIR)" -Iproto
DEFINES   += PB_NO_ERRMSG=1
SOURCE_FILES += $(NANOPB_DIR)/pb_encode.c $(NANOPB_DIR)/pb_decode.c $(NANOPB_DIR)/pb_common.c
APP_SOURCE_PATH += proto

include $(BOLOS_SDK)/Makefile.standard_app

# CryptoAssetsList key
ifneq (,$(filter $(DEFINES),HAVE_CAL_TEST_KEY))
    ifneq (, $(filter $(DEFINES),HAVE_CAL_STAGING_KEY))
        # Can't use both the staging and testing keys
        $(error Multiple alternative CAL keys set at once)
    endif
endif
