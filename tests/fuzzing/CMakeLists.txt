cmake_minimum_required(VERSION 3.14)

project(app_tron_fuzzers
        VERSION 1.0
        DESCRIPTION "libFuzzer targets for app-tron host-side fuzzing"
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
  set(STANDALONE_FUZZ_MODE OFF)
  if (APPLE)
    execute_process(COMMAND ${CMAKE_C_COMPILER} -print-resource-dir
                    OUTPUT_VARIABLE CLANG_RESOURCE_DIR
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    if (EXISTS "${CLANG_RESOURCE_DIR}/lib/darwin/libclang_rt.fuzzer_osx.a")
      set(FUZZER_LINK_FLAG -fsanitize=fuzzer)
    else()
      message(WARNING
              "libFuzzer runtime not found under ${CLANG_RESOURCE_DIR}; "
              "building standalone replay binaries instead.")
      set(FUZZER_LINK_FLAG)
      set(STANDALONE_FUZZ_MODE ON)
    endif()
  else()
    set(FUZZER_LINK_FLAG -fsanitize=fuzzer)
  endif()
  if (SANITIZER MATCHES "address")
    if (STANDALONE_FUZZ_MODE)
      list(APPEND TARGET_COMPILE_FLAGS -fsanitize=fuzzer-no-link,address,undefined)
      list(APPEND TARGET_LINK_FLAGS -fsanitize=address,undefined)
    else()
      list(APPEND TARGET_COMPILE_FLAGS -fsanitize=fuzzer,address,undefined)
      list(APPEND TARGET_LINK_FLAGS ${FUZZER_LINK_FLAG} -fsanitize=address,undefined)
    endif()
  elseif (SANITIZER MATCHES "memory")
    if (STANDALONE_FUZZ_MODE)
      list(APPEND TARGET_COMPILE_FLAGS -fsanitize=fuzzer-no-link,memory,undefined
                                       -fsanitize-memory-track-origins)
      list(APPEND TARGET_LINK_FLAGS -fsanitize=memory,undefined
                                    -fsanitize-memory-track-origins)
    else()
      list(APPEND TARGET_COMPILE_FLAGS -fsanitize=fuzzer,memory,undefined
                                       -fsanitize-memory-track-origins)
      list(APPEND TARGET_LINK_FLAGS ${FUZZER_LINK_FLAG}
                                    -fsanitize=memory,undefined
                                    -fsanitize-memory-track-origins)
    endif()
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
if (STANDALONE_FUZZ_MODE)
  target_sources(transaction_trigger_decode_fuzzer PRIVATE src/fuzz_standalone_main.c)
endif()

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

set(TIP712_FUZZ_SUPPORT_SOURCES
    src/tip712_fuzz_support.c
    src/tip712_fuzz_helpers_bridge.c
    ../../src/mem.c
    ../../src/mem_utils.c
    ../../src/hash_bytes.c
    ../../src/utils.c
    ../../src/uint_common.c
    ../../src/uint128.c
    ../../src/uint256.c
    ../../src/handlers/signMessageTIP712/commands_712.c
    ../../src/handlers/signMessageTIP712/context_712.c
    ../../src/handlers/signMessageTIP712/encode_field.c
    ../../src/handlers/signMessageTIP712/field_hash.c
    ../../src/handlers/signMessageTIP712/filtering.c
    ../../src/handlers/signMessageTIP712/format_hash_field_type.c
    ../../src/handlers/signMessageTIP712/path.c
    ../../src/handlers/signMessageTIP712/schema_hash.c
    ../../src/handlers/signMessageTIP712/sol_typenames.c
    ../../src/handlers/signMessageTIP712/type_hash.c
    ../../src/handlers/signMessageTIP712/typed_data.c
    ../../src/handlers/signMessageTIP712/ui_logic.c)

add_executable(fuzz_tip712
               src/fuzz_tip712.c
               ${TIP712_FUZZ_SUPPORT_SOURCES})
if (STANDALONE_FUZZ_MODE)
  target_sources(fuzz_tip712 PRIVATE src/fuzz_standalone_main.c)
endif()

target_include_directories(fuzz_tip712
                           PRIVATE
                           .
                           include
                           ../../src
                           ../../src/handlers/signMessageTIP712
                           ../../tron-plugin-sdk/src)

target_compile_options(fuzz_tip712 PRIVATE ${TARGET_COMPILE_FLAGS})
target_compile_options(fuzz_tip712 PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/include/fuzz_compat.h)
target_link_options(fuzz_tip712 PRIVATE ${TARGET_LINK_FLAGS})
if (TARGET_LINK_LIBS)
  target_link_libraries(fuzz_tip712 PRIVATE ${TARGET_LINK_LIBS})
endif()

add_executable(fuzz_tip712_wallet
               src/fuzz_tip712.c
               ${TIP712_FUZZ_SUPPORT_SOURCES})
if (STANDALONE_FUZZ_MODE)
  target_sources(fuzz_tip712_wallet PRIVATE src/fuzz_standalone_main.c)
endif()

target_include_directories(fuzz_tip712_wallet
                           PRIVATE
                           .
                           include
                           ../../src
                           ../../src/handlers/signMessageTIP712
                           ../../tron-plugin-sdk/src)

target_compile_definitions(fuzz_tip712_wallet PRIVATE SCREEN_SIZE_WALLET)
target_compile_options(fuzz_tip712_wallet PRIVATE ${TARGET_COMPILE_FLAGS})
target_compile_options(fuzz_tip712_wallet PRIVATE -include ${CMAKE_CURRENT_SOURCE_DIR}/include/fuzz_compat.h)
target_link_options(fuzz_tip712_wallet PRIVATE ${TARGET_LINK_FLAGS})
if (TARGET_LINK_LIBS)
  target_link_libraries(fuzz_tip712_wallet PRIVATE ${TARGET_LINK_LIBS})
endif()
