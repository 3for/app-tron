#ifdef HAVE_TRUSTED_NAME

#include "ui_trusted_name_bagl.h"
#include "trusted_name.h"

#ifdef HAVE_BAGL
//////////////////////////////////////////////////////////////////////
// clang-format off
UX_STEP_NOCB(
    ux_trusted_name_step,
    bnnn_paging,
    {
      .title = "To (domain)",
      .text = g_trusted_name
    });
// clang-format on
#endif

#endif  // HAVE_TRUSTED_NAME
