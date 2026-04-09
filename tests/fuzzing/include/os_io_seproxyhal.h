#pragma once

#include <setjmp.h>
#include <stdint.h>

extern int fuzz_os_lib_exception_code;
extern jmp_buf fuzz_os_lib_jmp_buf;

void os_lib_call(uintptr_t *params);

#define BEGIN_TRY if (1)
#define TRY if (setjmp(fuzz_os_lib_jmp_buf) == 0)
#define CATCH_OTHER(e) else for (int e = fuzz_os_lib_exception_code; e != 0; e = 0)
#define FINALLY if (1)
#define END_TRY
#define CLOSE_TRY ((void) 0)
