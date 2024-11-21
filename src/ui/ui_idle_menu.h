/*******************************************************************************
 *   TRON Ledger
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

#pragma once
#include "os_io_seproxyhal.h"
#include "ux.h"

void ui_idle(void);

extern const ux_flow_step_t* const ux_error_blind_signing_flow[];

extern const ux_flow_step_t* const ux_warning_blind_signing_flow[];

extern const ux_flow_step_t ux_warning_blind_signing_warn_step;