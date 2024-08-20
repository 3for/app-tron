#ifdef HAVE_TIP712_FULL_SUPPORT
#ifdef HAVE_BAGL
#include "ui_logic.h"
#include "ui_globals.h"

enum { UI_712_POS_REVIEW, UI_712_POS_END };
static uint8_t ui_pos;

static void dummy_cb(void) {
    switch (ui_712_next_field()) {
        case TIP712_NO_MORE_FIELD:
            if (ui_pos == UI_712_POS_REVIEW) {
                ux_flow_next();
                ui_pos = UI_712_POS_END;
            } else {
                // Keep user at the end of the flow
                ux_flow_next();
            }
            break;
        case TIP712_FIELD_INCOMING:
            // temporarily disable button clicks, they will be re-enabled as soon as new data
            // is received and the page is redrawn with ux_flow_init()
            G_ux.stack[0].button_push_callback = NULL;
            break;
        case TIP712_FIELD_LATER:
        default:
            break;
    }
}

// clang-format off
UX_STEP_NOCB(
    ux_712_step_review,
    pnn,
    {
      &C_icon_eye,
      "Review",
      "typed message",
    });
UX_STEP_NOCB(
   ux_712_step_dynamic,
   bnnn_paging,
   {
      .title = strings.tmp.tmp2,
      .text = strings.tmp.tmp,
   }
);
UX_STEP_INIT(
   ux_712_step_dummy,
   NULL,
   NULL,
   {
    dummy_cb();
   }
);
UX_STEP_CB(
    ux_712_step_approve,
    pb,
    ui_712_approve(),
    {
      &C_icon_validate_14,
      "Approve",
    });
UX_STEP_CB(
    ux_712_step_reject,
    pb,
    ui_712_reject(),
    {
      &C_icon_crossmark,
      "Reject",
    });
// clang-format on

UX_FLOW(ux_712_flow,
        &ux_712_step_review,
        &ux_712_step_dynamic,
        &ux_712_step_dummy,
        &ux_712_step_approve,
        &ux_712_step_reject);

void ui_712_start(void) {
    ux_flow_init(0, ux_712_flow, NULL);
    ui_pos = UI_712_POS_REVIEW;
}

void ui_712_switch_to_message(void) {
    ux_flow_init(0, ux_712_flow, &ux_712_step_dynamic);
    ui_pos = UI_712_POS_REVIEW;
}

void ui_712_switch_to_sign(void) {
    ux_flow_init(0, ux_712_flow, &ux_712_step_approve);
    ui_pos = UI_712_POS_END;
}

#endif
#endif  // HAVE_TIP712_FULL_SUPPORT
