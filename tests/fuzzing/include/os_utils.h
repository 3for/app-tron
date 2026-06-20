#pragma once
// Host-side mock of the SDK <os_utils.h>. network.c uses u64_to_string, which
// the TRON common_utils provides; pull its declarations in here.
#include "common_utils.h"
