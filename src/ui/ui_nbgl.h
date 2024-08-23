#ifdef HAVE_NBGL
#define TEXT_MESSAGE "message"

#define SIGN(msg)   "Sign " msg "?"
#define REVIEW(msg) "Review " msg

#define TEXT_TYPED_MESSAGE "typed " TEXT_MESSAGE
#define TEXT_REVIEW_TIP712 REVIEW(TEXT_TYPED_MESSAGE)
#define TEXT_SIGN_TIP712   SIGN(TEXT_TYPED_MESSAGE)

#endif