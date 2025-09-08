#ifndef _UI_NBGL_H_
#define _UI_NBGL_H_
#include "nbgl_use_case.h"

#define TEXT_MESSAGE "message"

#define SIGN(msg)   "Sign " msg "?"
#define REVIEW(msg) "Review " msg

#define TEXT_TYPED_MESSAGE "typed " TEXT_MESSAGE
#define TEXT_REVIEW_TIP712 REVIEW(TEXT_TYPED_MESSAGE)
#define TEXT_SIGN_TIP712   SIGN(TEXT_TYPED_MESSAGE)

#define BLIND_SIGN(msg)        "Accept risk and sign " msg "?"
#define TEXT_BLIND_SIGN_TIP712 BLIND_SIGN(TEXT_TYPED_MESSAGE)
void ui_settings(void);

#ifdef SCREEN_SIZE_WALLET
#define ICON_APP_WARNING C_Warning_64px
#define ICON_APP_REVIEW  C_Review_64px
#else
#define ICON_APP_WARNING C_icon_warning
#define ICON_APP_REVIEW  C_icon_certificate
#endif

extern char g_stax_shared_buffer[SHARED_BUFFER_SIZE];

#endif  // _UI_NBGL_H_