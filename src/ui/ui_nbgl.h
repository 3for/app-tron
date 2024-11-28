#ifdef HAVE_NBGL
#define TEXT_MESSAGE "message"

#define SIGN(msg)   "Sign " msg "?"
#define REVIEW(msg) "Review " msg

#define TEXT_TYPED_MESSAGE "typed " TEXT_MESSAGE
#define TEXT_REVIEW_TIP712 REVIEW(TEXT_TYPED_MESSAGE)
#define TEXT_SIGN_TIP712   SIGN(TEXT_TYPED_MESSAGE)
#define BLIND_SIGN(msg)       "Accept risk and sign " msg "?"
#define TEXT_BLIND_SIGN_TIP712 BLIND_SIGN(TEXT_TYPED_MESSAGE)
void ui_settings(void);
#endif