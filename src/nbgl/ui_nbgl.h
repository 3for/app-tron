#define TEXT_MESSAGE "message"

#ifdef SCREEN_SIZE_WALLET
#define SIGN(msg) "Sign " msg "?"
#else
#define SIGN(msg) "Sign " msg
#endif
#define REVIEW(msg) "Review " msg

#define TEXT_TYPED_MESSAGE "typed " TEXT_MESSAGE
#define TEXT_REVIEW_TIP712 REVIEW(TEXT_TYPED_MESSAGE)
#define TEXT_SIGN_TIP712   SIGN(TEXT_TYPED_MESSAGE)

#define BLIND_SIGN(msg)        "Accept risk and sign " msg "?"
#define TEXT_BLIND_SIGN_TIP712 BLIND_SIGN(TEXT_TYPED_MESSAGE)
// ui_settings() is declared in ui_idle_menu.h (home/settings entry points).

#ifdef TARGET_APEX_P
#define ICON_APP_WARNING LARGE_WARNING_ICON
#define ICON_APP_REVIEW  LARGE_REVIEW_ICON
#define ICON_LEDGER      C_ledger_48px
#elifdef SCREEN_SIZE_WALLET  // for both flex and stax
#define ICON_APP_WARNING C_Warning_64px
#define ICON_APP_REVIEW  C_Review_64px
#define ICON_LEDGER      C_ledger_64px
#else
#define ICON_APP_WARNING C_icon_warning
#define ICON_APP_REVIEW  C_icon_certificate
#define ICON_LEDGER       C_ledger_14px
#endif

extern nbgl_warning_t warning;
