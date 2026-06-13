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
#include <string.h>
#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "app_mem_utils.h"
#include "caller_api.h"
#include "ui_idle_menu.h"
#include "ui_globals.h"
#include "ui_nbgl.h"
#include "settings.h"
#include "parse.h"

// settings info definition
#define SETTING_INFO_NB 3

// settings menu definition
#define SETTING_CONTENTS_NB 1

// Tagline format for plugins / clones
#define FORMAT_PLUGIN "This app enables clear\nsigning transactions for\nthe %s dApp."

// Settings switch tokens (kept stable across device families).
enum {
    SWITCH_ALLOW_TX_DATA_TOKEN = FIRST_USER_TOKEN,
    SWITCH_ALLOW_CSTM_CONTRACTS_TOKEN,
#if !defined(SCREEN_SIZE_WALLET)
    SWITCH_TRUNCATE_ADDRESS_TOKEN,
#endif
    SWITCH_ALLOW_HASH_TX_TOKEN,
    SWITCH_TIP712_VERBOSE_TOKEN,
};

// Settings switch indices (same order as the tokens above and the settings[]
// table below, so SETTING_IDX(token) maps a token to both arrays).
enum {
    TX_DATA_ID,
    CSTM_CONTRACTS_ID,
#if !defined(SCREEN_SIZE_WALLET)
    TRUNCATE_ADDRESS_ID,
#endif
    HASH_TX_ID,
    TIP712_VERBOSE_ID,
    SETTINGS_SWITCHES_NB
};

// settings definition
static const char *const infoTypes[SETTING_INFO_NB] = {"Version", "Developer", "Copyright"};
static const char *const infoContents[SETTING_INFO_NB] = {APPVERSION, "Ledger", "Ledger (c) 2026"};

static nbgl_contentInfoList_t infoList = {0};
static nbgl_layoutSwitch_t switches[SETTINGS_SWITCHES_NB] = {0};
static nbgl_content_t contents[SETTING_CONTENTS_NB] = {0};
static nbgl_genericContents_t settingContents = {0};

// Buffer used for the plugin tagline (never deallocated, like app-ethereum)
static char *g_tag_line = NULL;

// Maps a switch token to its index in switches[] / settings[].
#define SETTING_IDX(token) (token - SWITCH_ALLOW_TX_DATA_TOKEN)

// Persisted setting bit backing each switch (TRON stores settings as a NVRAM
// bitfield toggled through SETTING_TOGGLE / HAS_SETTING, unlike app-ethereum's
// per-field N_storage entries).
static const uint8_t settings[SETTINGS_SWITCHES_NB] = {
    S_DATA_ALLOWED,
    S_CUSTOM_CONTRACT,
#if !defined(SCREEN_SIZE_WALLET)
    S_TRUNCATE_ADDRESS,
#endif
    S_SIGN_BY_HASH,
    S_VERBOSE_TIP712,
};

static void setting_toggle_callback(int token, uint8_t index, int page) {
    UNUSED(index);
    UNUSED(page);
    uint8_t id;

    switch (token) {
        case SWITCH_ALLOW_TX_DATA_TOKEN:
        case SWITCH_ALLOW_CSTM_CONTRACTS_TOKEN:
#if !defined(SCREEN_SIZE_WALLET)
        case SWITCH_TRUNCATE_ADDRESS_TOKEN:
#endif
        case SWITCH_ALLOW_HASH_TX_TOKEN:
        case SWITCH_TIP712_VERBOSE_TOKEN:
            id = SETTING_IDX(token);
            SETTING_TOGGLE(settings[id]);
            switches[id].initState = HAS_SETTING(settings[id]) ? ON_STATE : OFF_STATE;
            break;
        default:
            PRINTF("Should not happen !\n");
            break;
    }
}

/**
 * Get the home screen icon (the caller app's icon when launched as a
 * clone/plugin, the TRON icon otherwise)
 */
static const nbgl_icon_details_t *get_home_icon(void) {
    if (caller_app != NULL && caller_app->icon != NULL) {
        return caller_app->icon;
    }
    return &APP_TRON_HOME_ICON;
}

/**
 * Prepare settings, app infos and call the HomeAndSettings use case
 *
 * @param[in] appname given app name
 * @param[in] tagline given tagline (\ref NULL if default)
 * @param[in] page to start on
 */
static void prepare_and_display_home(const char *appname, const char *tagline, uint8_t page) {
    switches[TX_DATA_ID].text = "Transactions data";
    switches[TX_DATA_ID].subText = "Allow extra data in\ntransactions";
    switches[TX_DATA_ID].token = SWITCH_ALLOW_TX_DATA_TOKEN;
    switches[TX_DATA_ID].tuneId = TUNE_TAP_CASUAL;
    switches[TX_DATA_ID].initState = HAS_SETTING(S_DATA_ALLOWED) ? ON_STATE : OFF_STATE;

    switches[CSTM_CONTRACTS_ID].text = "Custom contracts";
    switches[CSTM_CONTRACTS_ID].subText = "Allow unverified contracts";
    switches[CSTM_CONTRACTS_ID].token = SWITCH_ALLOW_CSTM_CONTRACTS_TOKEN;
    switches[CSTM_CONTRACTS_ID].tuneId = TUNE_TAP_CASUAL;
    switches[CSTM_CONTRACTS_ID].initState = HAS_SETTING(S_CUSTOM_CONTRACT) ? ON_STATE : OFF_STATE;

#if !defined(SCREEN_SIZE_WALLET)
    switches[TRUNCATE_ADDRESS_ID].text = "Truncate Address";
    switches[TRUNCATE_ADDRESS_ID].subText = "Display truncated\naddresses";
    switches[TRUNCATE_ADDRESS_ID].token = SWITCH_TRUNCATE_ADDRESS_TOKEN;
    switches[TRUNCATE_ADDRESS_ID].tuneId = TUNE_TAP_CASUAL;
    switches[TRUNCATE_ADDRESS_ID].initState =
        HAS_SETTING(S_TRUNCATE_ADDRESS) ? ON_STATE : OFF_STATE;

    switches[HASH_TX_ID].text = "Sign by Hash";
    switches[HASH_TX_ID].subText = "Allow hash-only\ntransactions";
#else
    switches[HASH_TX_ID].text = "Blind signing";
    switches[HASH_TX_ID].subText = "Allow transaction blind signing";
#endif
    switches[HASH_TX_ID].token = SWITCH_ALLOW_HASH_TX_TOKEN;
    switches[HASH_TX_ID].tuneId = TUNE_TAP_CASUAL;
    switches[HASH_TX_ID].initState = HAS_SETTING(S_SIGN_BY_HASH) ? ON_STATE : OFF_STATE;

    switches[TIP712_VERBOSE_ID].text = "Raw messages";
    switches[TIP712_VERBOSE_ID].subText = "Displays raw content of TIP712 messages";
    switches[TIP712_VERBOSE_ID].token = SWITCH_TIP712_VERBOSE_TOKEN;
    switches[TIP712_VERBOSE_ID].tuneId = TUNE_TAP_CASUAL;
    switches[TIP712_VERBOSE_ID].initState = HAS_SETTING(S_VERBOSE_TIP712) ? ON_STATE : OFF_STATE;

    contents[0].type = SWITCHES_LIST;
    contents[0].content.switchesList.nbSwitches = SETTINGS_SWITCHES_NB;
    contents[0].content.switchesList.switches = switches;
    contents[0].contentActionCallback = setting_toggle_callback;

    settingContents.callbackCallNeeded = false;
    settingContents.contentsList = contents;
    settingContents.nbContents = SETTING_CONTENTS_NB;

    infoList.nbInfos = SETTING_INFO_NB;
    infoList.infoTypes = infoTypes;
    infoList.infoContents = infoContents;

    nbgl_useCaseHomeAndSettings(appname,
                                get_home_icon(),
                                tagline,
                                page,
                                &settingContents,
                                &infoList,
                                NULL,
                                app_quit);
}

/**
 * Get appname & tagline
 *
 * Prepares the app name & tagline depending on how the application was called
 * (standalone TRON app, or as a clone/plugin caller app).
 */
static void get_appname_and_tagline(const char **appname, const char **tagline) {
    uint8_t line_len = 1;  // Initialize length to 1 for the '\0' character

    if (caller_app != NULL) {
        *appname = caller_app->name;
        if (caller_app->type == CALLER_TYPE_PLUGIN) {
            line_len += strlen(FORMAT_PLUGIN);
            line_len += strlen(caller_app->name);
            // Allocate the buffer - will never be deallocated...
            if (APP_MEM_CALLOC((void **) &g_tag_line, line_len) == true) {
                snprintf(g_tag_line, line_len, FORMAT_PLUGIN, *appname);
                *tagline = g_tag_line;
            }
        }
    } else {  // standalone TRON app
        *appname = APPNAME;
    }
}

/**
 * Go to the requested start page
 */
static void ui_start_page(uint8_t page) {
    const char *appname = NULL;
    const char *tagline = NULL;

    get_appname_and_tagline(&appname, &tagline);
    prepare_and_display_home(appname, tagline, page);
}

/**
 * Go to home screen
 */
void ui_idle(void) {
    ui_start_page(INIT_HOME_PAGE);
}

/**
 * Go to settings screen
 */
void ui_settings(void) {
    ui_start_page(0);
}

#ifdef SCREEN_SIZE_WALLET
static void ui_error_blind_signing_choice(bool confirm) {
    if (confirm) {
        ui_settings();
    } else {
        ui_idle();
    }
}
#endif

void ui_error_blind_signing(void) {
#ifdef SCREEN_SIZE_WALLET
    nbgl_useCaseChoice(&ICON_APP_WARNING,
                       "This transaction cannot be clear-signed",
                       "Enable blind signing in the settings to sign this transaction.",
                       "Go to settings",
                       "Reject transaction",
                       ui_error_blind_signing_choice);
#else
    nbgl_useCaseAction(&C_Alert_circle_14px,
                       "Blind signing must\nbe enabled in\nsettings",
                       NULL,
                       ui_idle);
#endif
}
