cmake_minimum_required(VERSION 3.10)

if(${CMAKE_VERSION} VERSION_LESS 3.10)
    cmake_policy(VERSION ${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION})
endif()

# project information
project(unit_tests
        VERSION 0.1
	      DESCRIPTION "Unit tests for C project"
        LANGUAGES C)


# guard against bad build-type strings
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
ENABLE_TESTING()

# specify C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
if(APPLE)
  foreach(FLAG_VAR
          CMAKE_C_FLAGS
          CMAKE_C_FLAGS_DEBUG
          CMAKE_C_FLAGS_RELEASE
          CMAKE_C_FLAGS_RELWITHDEBINFO
          CMAKE_C_FLAGS_MINSIZEREL)
    if(DEFINED ${FLAG_VAR})
      string(REPLACE "-fstack-clash-protection" "" ${FLAG_VAR} "${${FLAG_VAR}}")
    endif()
  endforeach()
endif()
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -g -O0 --coverage")

set(COVERAGE_LINK_FLAGS "--coverage")
if(NOT APPLE)
  string(APPEND COVERAGE_LINK_FLAGS " -lgcov")
endif()
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${COVERAGE_LINK_FLAGS}")

# guard against in-source builds
if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there. You may need to remove CMakeCache.txt. ")
endif()

# Fetch cmocka
find_package(cmocka QUIET)
include(FetchContent)
FetchContent_Declare(
    cmocka
    GIT_REPOSITORY https://git.cryptomilk.org/projects/cmocka.git
    GIT_TAG        cmocka-1.1.5
    GIT_SHALLOW    1
)
set(WITH_STATIC_LIB ON CACHE BOOL "CMocka: Build with a static library" FORCE)
set(WITH_CMOCKERY_SUPPORT OFF CACHE BOOL "CMocka: Install a cmockery header" FORCE)
set(WITH_EXAMPLES OFF CACHE BOOL "CMocka: Build examples" FORCE)
set(UNIT_TESTING OFF CACHE BOOL "CMocka: Build with unit testing" FORCE)
set(PICKY_DEVELOPER OFF CACHE BOOL "CMocka: Build with picky developer flags" FORCE)
FetchContent_MakeAvailable(cmocka)

if(APPLE)
  if(TARGET cmocka)
    target_compile_options(cmocka PRIVATE -Wno-unused-command-line-argument)
  endif()
  if(TARGET cmocka-static)
    target_compile_options(cmocka-static PRIVATE -Wno-unused-command-line-argument)
  endif()
endif()

add_compile_definitions(TEST DEBUG=0 SKIP_FOR_CMOCKA PB_SYSTEM_HEADER=\"pb_system_header.h\")

add_library(transaction_trigger_decode_lib STATIC ../../src/handlers/transaction_trigger_decode.c)
target_include_directories(transaction_trigger_decode_lib
                           PUBLIC
                           .
                           ../../src/handlers
                           ../../proto
                           ../../nanopb)

add_executable(test_transaction_trigger_decode_blackbox tests/transaction_trigger_decode_blackbox.c)
target_include_directories(test_transaction_trigger_decode_blackbox
                           PRIVATE
                           .
                           ../../src/handlers
                           ../../proto
                           ../../nanopb)
target_link_libraries(test_transaction_trigger_decode_blackbox
                      PUBLIC
                      cmocka
                      transaction_trigger_decode_lib)
if(NOT APPLE)
    target_link_libraries(test_transaction_trigger_decode_blackbox PUBLIC gcov)
endif()

add_test(test_transaction_trigger_decode_blackbox test_transaction_trigger_decode_blackbox)

add_executable(test_transaction_trigger_decode_whitebox tests/transaction_trigger_decode_whitebox.c)
target_include_directories(test_transaction_trigger_decode_whitebox
                           PRIVATE
                           .
                           ../../src/handlers
                           ../../proto
                           ../../nanopb)
target_link_libraries(test_transaction_trigger_decode_whitebox PUBLIC cmocka)
if(NOT APPLE)
    target_link_libraries(test_transaction_trigger_decode_whitebox PUBLIC gcov)
endif()

add_test(test_transaction_trigger_decode_whitebox test_transaction_trigger_decode_whitebox)

add_library(legacy_tx_stream_lib STATIC ../../src/handlers/legacy_tx_stream.c)
target_include_directories(legacy_tx_stream_lib
                           PUBLIC
                           .
                           ../../src/handlers
                           ../../proto
                           ../../nanopb)

add_executable(test_legacy_tx_stream
               tests/legacy_tx_stream.c
               ../../proto/core/Tron.pb.c
               ../../proto/google/protobuf/any.pb.c
               ../../nanopb/pb_decode.c
               ../../nanopb/pb_common.c)
target_include_directories(test_legacy_tx_stream
                           PRIVATE
                           .
                           ../../src/handlers
                           ../../proto
                           ../../nanopb)
target_link_libraries(test_legacy_tx_stream PUBLIC cmocka legacy_tx_stream_lib)
if(NOT APPLE)
    target_link_libraries(test_legacy_tx_stream PUBLIC gcov)
endif()

add_test(test_legacy_tx_stream test_legacy_tx_stream)

add_library(create_smart_contract_stream_lib STATIC
            ../../src/handlers/create_smart_contract_stream.c)
target_include_directories(create_smart_contract_stream_lib
                           PUBLIC
                           .
                           ../fuzzing/include
                           ../../src/handlers
                           ../../proto
                           ../../nanopb)

add_executable(test_create_smart_contract_stream
               tests/create_smart_contract_stream.c)
target_include_directories(test_create_smart_contract_stream
                           PRIVATE
                           .
                           ../fuzzing/include
                           ../../src/handlers
                           ../../proto
                           ../../nanopb)
target_link_libraries(test_create_smart_contract_stream
                      PUBLIC
                      cmocka
                      create_smart_contract_stream_lib)
if(NOT APPLE)
    target_link_libraries(test_create_smart_contract_stream PUBLIC gcov)
endif()

add_test(test_create_smart_contract_stream test_create_smart_contract_stream)
