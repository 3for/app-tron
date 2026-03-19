cmake_minimum_required(VERSION 3.14)

project(transaction_trigger_decode_fuzzer
        VERSION 1.0
        DESCRIPTION "libFuzzer target for Tron trigger stream decoder"
        LANGUAGES C)

if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "Fuzzer needs to be built with Clang")
endif()

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

if (NOT DEFINED ENV{LIB_FUZZING_ENGINE})
  set(TARGET_COMPILE_FLAGS -g -O0 -Wall -Wextra)
  set(TARGET_LINK_FLAGS)
  set(TARGET_LINK_LIBS)
  if (SANITIZER MATCHES "address")
    list(APPEND TARGET_COMPILE_FLAGS -fsanitize=fuzzer,address,undefined)
    list(APPEND TARGET_LINK_FLAGS -fsanitize=fuzzer,address,undefined)
  elseif (SANITIZER MATCHES "memory")
    list(APPEND TARGET_COMPILE_FLAGS -fsanitize=fuzzer,memory,undefined
                                     -fsanitize-memory-track-origins)
    list(APPEND TARGET_LINK_FLAGS -fsanitize=fuzzer,memory,undefined
                                  -fsanitize-memory-track-origins)
  else()
    message(FATAL_ERROR "Unknown sanitizer type. It must be set to `address` or `memory`.")
  endif()
else()
  set(TARGET_COMPILE_FLAGS "$ENV{CFLAGS}")
  set(TARGET_LINK_FLAGS "$ENV{CFLAGS}")
  set(TARGET_LINK_LIBS "$ENV{LIB_FUZZING_ENGINE}")
  separate_arguments(TARGET_COMPILE_FLAGS)
  separate_arguments(TARGET_LINK_FLAGS)

  if (TARGET_LINK_LIBS AND NOT EXISTS "${TARGET_LINK_LIBS}")
    message(WARNING
            "LIB_FUZZING_ENGINE points to a missing file (${TARGET_LINK_LIBS}); "
            "falling back to -fsanitize=fuzzer for linking.")
    set(TARGET_LINK_LIBS)
    list(APPEND TARGET_COMPILE_FLAGS -fsanitize=fuzzer-no-link)
    list(APPEND TARGET_LINK_FLAGS -fsanitize=fuzzer)
  endif()
endif()

if (${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please use a separate build directory.")
endif()

add_compile_definitions(PB_SYSTEM_HEADER=\"pb_system_header.h\")

add_executable(transaction_trigger_decode_fuzzer
               src/transaction_trigger_decode_fuzzer.c
               ../../src/handlers/transaction_trigger_decode.c)

target_include_directories(transaction_trigger_decode_fuzzer
                           PRIVATE
                           .
                           ../../src/handlers
                           ../../proto
                           ../../nanopb)

target_compile_options(transaction_trigger_decode_fuzzer PRIVATE ${TARGET_COMPILE_FLAGS})
target_link_options(transaction_trigger_decode_fuzzer PRIVATE ${TARGET_LINK_FLAGS})
if (TARGET_LINK_LIBS)
  target_link_libraries(transaction_trigger_decode_fuzzer PRIVATE ${TARGET_LINK_LIBS})
endif()
