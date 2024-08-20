/*******************************************************************************
 *   Tron Ledger Wallet
 *   (c) 2022 Ledger
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
#ifdef HAVE_NBGL

#include "os.h"
#include "ui_idle_menu.h"
#include "glyphs.h"
#include "ux.h"
#include "nbgl_use_case.h"
#include "ui_globals.h"
#include "settings.h"
#include "parse.h"

enum {
    SWITCH_ALLOW_TX_DATA_TOKEN = FIRST_USER_TOKEN,
    SWITCH_ALLOW_CSTM_CONTRACTS_TOKEN,
    SWITCH_ALLOW_HASH_TX_TOKEN,
    DOMAIN_NAME_VERBOSE_TOKEN,
    EIP712_VERBOSE_TOKEN
};

enum {
    TX_DATA_ID,
    CSTM_CONTRACTS_ID,
    HASH_TX_ID,
#ifdef HAVE_DOMAIN_NAME
    DOMAIN_NAME_VERBOSE_ID,
#endif
#ifdef HAVE_TIP712_FULL_SUPPORT
    EIP712_VERBOSE_ID,
#endif
    SETTINGS_SWITCHES_NB
};

#define NB_INFO_FIELDS SETTINGS_SWITCHES_NB
static const char* const infoTypes[] = {"Version", "Developer", "Copyright"};
static const char* const infoContents[] = {APPVERSION, "Klever", "(c) 2024 Ledger"};

#define NB_SETTINGS_SWITCHES SETTINGS_SWITCHES_NB
#define SETTING_IDX(token)   (token - SWITCH_ALLOW_TX_DATA_TOKEN)
static uint8_t settings[NB_SETTINGS_SWITCHES] = {S_DATA_ALLOWED, S_CUSTOM_CONTRACT, S_SIGN_BY_HASH};
static nbgl_layoutSwitch_t switches[NB_SETTINGS_SWITCHES] = {0};

void onQuitCallback(void) {
    os_sched_exit(-1);
}

static void settingsControlsCallback(int token, uint8_t index, int page) {
    UNUSED(index);
    UNUSED(page);
    bool value;
    switch (token) {
        case SWITCH_ALLOW_TX_DATA_TOKEN:
        case SWITCH_ALLOW_CSTM_CONTRACTS_TOKEN:
        case SWITCH_ALLOW_HASH_TX_TOKEN:
            SETTING_TOGGLE(settings[SETTING_IDX(token)]);
            switches[TX_DATA_ID].initState = (HAS_SETTING(S_DATA_ALLOWED)) ? ON_STATE : OFF_STATE;
            switches[CSTM_CONTRACTS_ID].initState = (HAS_SETTING(S_CUSTOM_CONTRACT)) ? ON_STATE : OFF_STATE;
            switches[HASH_TX_ID].initState = (HAS_SETTING(S_SIGN_BY_HASH)) ? ON_STATE : OFF_STATE;
            break;
#ifdef HAVE_TIP712_FULL_SUPPORT
        case EIP712_VERBOSE_TOKEN:
            value = !N_storage.verbose_tip712;
            switches[EIP712_VERBOSE_ID].initState = (nbgl_state_t) value;
            nvm_write((void *) &N_storage.verbose_tip712, (void *) &value, sizeof(uint8_t));
            break;
#endif  // HAVE_TIP712_FULL_SUPPORT
#ifdef HAVE_DOMAIN_NAME
        case DOMAIN_NAME_VERBOSE_TOKEN:
            value = !N_storage.verbose_domain_name;
            switches[DOMAIN_NAME_VERBOSE_ID].initState = (nbgl_state_t) value;
            nvm_write((void *) &N_storage.verbose_domain_name, (void *) &value, sizeof(uint8_t));
            break;
#endif  // HAVE_DOMAIN_NAME
        default:
            PRINTF("Should not happen !");
            break;
    }
}

// info menu definition
static const nbgl_contentInfoList_t infoList = {
    .nbInfos = NB_INFO_FIELDS,
    .infoTypes = infoTypes,
    .infoContents = infoContents,
};

// settings menu definition
#define SETTING_CONTENTS_NB 1
static const nbgl_content_t contents[SETTING_CONTENTS_NB] = {
    {.type = SWITCHES_LIST,
     .content.switchesList.nbSwitches = NB_SETTINGS_SWITCHES,
     .content.switchesList.switches = switches,
     .contentActionCallback = settingsControlsCallback}};

static const nbgl_genericContents_t settingContents = {.callbackCallNeeded = false,
                                                       .contentsList = contents,
                                                       .nbContents = SETTING_CONTENTS_NB};
void ui_idle(void) {
    switches[TX_DATA_ID].text = "Transactions data";
    switches[TX_DATA_ID].subText = "Allow extra data in\ntransactions";
    switches[TX_DATA_ID].token = SWITCH_ALLOW_TX_DATA_TOKEN;
    switches[TX_DATA_ID].tuneId = TUNE_TAP_CASUAL;
    switches[TX_DATA_ID].initState = (HAS_SETTING(S_DATA_ALLOWED)) ? ON_STATE : OFF_STATE;

    switches[CSTM_CONTRACTS_ID].text = "Custom contracts";
    switches[CSTM_CONTRACTS_ID].subText = "Allow unverified contracts";
    switches[CSTM_CONTRACTS_ID].token = SWITCH_ALLOW_CSTM_CONTRACTS_TOKEN;
    switches[CSTM_CONTRACTS_ID].tuneId = TUNE_TAP_CASUAL;
    switches[CSTM_CONTRACTS_ID].initState = (HAS_SETTING(S_CUSTOM_CONTRACT)) ? ON_STATE : OFF_STATE;

    switches[HASH_TX_ID].text = "Blind signing";
    switches[HASH_TX_ID].subText = "Allow transaction blind signing";
    switches[HASH_TX_ID].token = SWITCH_ALLOW_HASH_TX_TOKEN;
    switches[HASH_TX_ID].tuneId = TUNE_TAP_CASUAL;
    switches[HASH_TX_ID].initState = (HAS_SETTING(S_SIGN_BY_HASH)) ? ON_STATE : OFF_STATE;

#ifdef HAVE_DOMAIN_NAME
    switches[DOMAIN_NAME_VERBOSE_ID].initState =
        N_storage.verbose_domain_name ? ON_STATE : OFF_STATE;
    switches[DOMAIN_NAME_VERBOSE_ID].text = "ENS addresses";
    switches[DOMAIN_NAME_VERBOSE_ID].subText = "Display the resolved address of ENS domains.";
    switches[DOMAIN_NAME_VERBOSE_ID].token = DOMAIN_NAME_VERBOSE_TOKEN;
    switches[DOMAIN_NAME_VERBOSE_ID].tuneId = TUNE_TAP_CASUAL;
#endif  // HAVE_DOMAIN_NAME

#ifdef HAVE_TIP712_FULL_SUPPORT
    switches[EIP712_VERBOSE_ID].initState = N_storage.verbose_tip712 ? ON_STATE : OFF_STATE;
    switches[EIP712_VERBOSE_ID].text = "Raw messages";
    switches[EIP712_VERBOSE_ID].subText = "Display raw content from EIP712 messages.";
    switches[EIP712_VERBOSE_ID].token = EIP712_VERBOSE_TOKEN;
    switches[EIP712_VERBOSE_ID].tuneId = TUNE_TAP_CASUAL;
#endif  // HAVE_TIP712_FULL_SUPPORT

    nbgl_useCaseHomeAndSettings(APPNAME,
                                &APP_TRON_ICON,
                                NULL,
                                INIT_HOME_PAGE,
                                &settingContents,
                                &infoList,
                                NULL,
                                onQuitCallback);
}
#endif  // HAVE_NBGL
