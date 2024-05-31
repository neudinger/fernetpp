cmake_minimum_required(VERSION 3.25)

function(add_test_incl_memcheck name target)
  target_link_libraries(${target} PRIVATE Catch2::Catch2
    # Catch2::Catch2WithMain
  )

  # https://github.com/catchorg/Catch2/blob/devel/docs/cmake-integration.md#usage
  # catch_discover_tests(${target})
  add_test(NAME ${name}_main COMMAND ${target})

  # add_test(NAME ${name}_memchecked_test
  # COMMAND valgrind
  # -s
  # --error-exitcode=1
  # --tool=memcheck
  # --leak-check=full
  # --errors-for-leak-kinds=definite
  # --show-leak-kinds=definite $<TARGET_FILE:${target}>
  # WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})
endfunction()

# https://www.kitware.com/static-checks-with-cmake-cdash-iwyu-clang-tidy-lwyu-cpplint-and-cppcheck/
if("$ENV{Fernet_VERSION}" STREQUAL "")
  set(Fernet_VERSION 0.0.0.0)
  message(
    WARNING
    "Setup Fernet_VERSION in your environement variable default ${Fernet_VERSION} will bet set to Fernet_VERSION variable"
  )
else()
  set(Fernet_VERSION $ENV{Fernet_VERSION})
endif("$ENV{Fernet_VERSION}" STREQUAL "")

project(
  Fernet
  LANGUAGES CXX
  VERSION ${Fernet_VERSION}
  DESCRIPTION "C++ Fernet library"
  HOMEPAGE_URL "https://github.com/neudinger/fernetpp")

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED CMAKE_VISIBILITY_INLINES_HIDDEN)
  set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)
endif()


# target_include_directories(${PROJECT_NAME} PUBLIC ${date_INCLUDE_DIRS})

# message(FATAL_ERROR "${date_IMPORT_PREFIX}")
find_program(CCACHE_PROGRAM ccache)

if(CCACHE_PROGRAM)
  set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
  set(CMAKE_CUDA_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif()

get_filename_component(PARENT_DIR ${CMAKE_SOURCE_DIR} PATH)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(OpenSSL)
include(JSONParser)

file(READ ${CMAKE_SOURCE_DIR}/requirements.json requirementsJSON)
sbeparsejson(dependencies requirementsJSON)

set(OPENSSL_USE_STATIC_LIBS ON)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)
set(CMAKE_SHARED_LIBS OFF)

# -Weverything (Clang only)
# ASAN_OPTIONS=detect_leaks=1
# -static-libasan
# -fsanitize=leak
# -fsanitize-address-use-after-scope
# -fsanitize=address
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif(NOT CMAKE_BUILD_TYPE)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  remove_definitions(NDEBUG)
endif(CMAKE_BUILD_TYPE STREQUAL "Release")

if(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
  add_compile_definitions(NDEBUG=1)
  add_compile_options(
    -fstack-usage
    -fstack-protector-strong
    -fno-omit-frame-pointer
    -Wstack-usage=3000
  )
endif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_COMPILE_WARNING_AS_ERROR OFF)

  # add_compile_options(-fstack-usage -Wstack-usage=3000)
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

if(DEFINED EMSCRIPTEN)
  message("Build with EMSCRIPTEN")

  set(CMAKE_EXECUTABLE_SUFFIX ".wasm")
  add_executable(${PROJECT_NAME} ${SOURCES})
  set_target_properties(${PROJECT_NAME} PROPERTIES COMPILE_FLAGS
    "-Os -s SIDE_MODULE=1 ")
  set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES LINK_FLAGS
    "-Os -s WASM=1 -s SIDE_MODULE=1 -s STANDALONE_WASM --no-entry")
else()
  # list(APPEND LINK_TYPES SHARED)
endif()

if(NOT(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/crypto/hash/murmur3.hpp"))
  file(
    DOWNLOAD
    https://gist.githubusercontent.com/neudinger/97a75228381e12d4ba2b435c3b86ba9e/raw/8ad43fe606ed499102ffa8949cf531aeaa6473d7/murmur3.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/crypto/hash/murmur3.hpp)
else()
  message(INFO "murmur3.hpp already downloaded")
endif()

if(NOT(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/crypto/hash/FNV1a.hpp"))
  file(DOWNLOAD
    https://gist.githubusercontent.com/neudinger/4921e8cf323b2be544982e8b5968cd57/raw/5dc026a1e6ef45ed17dec17c6223025ee5ccc26f/FNV1a.hpp
    ${CMAKE_CURRENT_BINARY_DIR}/crypto/hash/FNV1a.hpp)
else()
  message(INFO "FNV1a.hpp already downloaded")
endif()

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include)

set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)

file(GLOB SOURCES_LIB ${SRC_DIR}/*.cc)
file(GLOB SOURCES_EXES ${SRC_DIR}/*.cpp)

set(TARGET_NAME_EXE ${PROJECT_NAME}.exe)

list(APPEND COMPILE_FEATURES
  cxx_std_${CMAKE_CXX_STANDARD}
  cxx_constexpr
  cxx_variable_templates
  cxx_return_type_deduction
  cxx_relaxed_constexpr
  cxx_generic_lambdas
  cxx_lambda_init_captures
  cxx_template_template_parameters
  cxx_unicode_literals
  cxx_unrestricted_unions
  cxx_uniform_initialization
  cxx_user_literals
  cxx_variadic_macros
  cxx_digit_separators
  cxx_variadic_templates
  cxx_attribute_deprecated
  cxx_binary_literals
  cxx_aggregate_default_initializers
  cxx_contextual_conversions
  cxx_decltype_auto
  cxx_trailing_return_types
  cxx_strong_enums
  cxx_thread_local
  cxx_sizeof_member
  cxx_static_assert
  cxx_rvalue_references
  cxx_reference_qualified_functions
  cxx_right_angle_brackets
  cxx_nonstatic_member_init
  cxx_raw_string_literals
  cxx_override
  cxx_nullptr
  cxx_range_for
  cxx_noexcept
  cxx_local_type_template_args
  cxx_long_long_type
  cxx_explicit_conversions
  cxx_extended_friend_declarations
  cxx_extern_templates
  cxx_lambdas
  cxx_final
  cxx_generalized_initializers
  cxx_inheriting_constructors
  cxx_func_identifier
  cxx_inline_namespaces
  cxx_deleted_functions
  cxx_enum_forward_declarations
  cxx_defaulted_move_initializers
  cxx_delegating_constructors
  cxx_constexpr
  cxx_decltype_incomplete_return_types
  cxx_decltype
  cxx_default_function_template_args
  cxx_defaulted_functions
  cxx_alignof
  cxx_attributes
  cxx_auto_type
  cxx_alias_templates
  cxx_alignas)

add_library(${PROJECT_NAME} ${SOURCES_LIB})
add_library(Fernet::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

target_compile_features(${PROJECT_NAME} PRIVATE ${COMPILE_FEATURES})

find_package(Catch2 REQUIRED)
include(Catch)

include(CTest)
enable_testing()

find_program(VALGRIND valgrind)

if(NOT VALGRIND)
  message(
    STATUS
    "Valgrind is required for memcheck wrapper but was not found! All corresponding tests are disabled."
  )
endif()

add_executable(${TARGET_NAME_EXE} ${SOURCES_LIB} ${SOURCES_EXES})
target_compile_features(${TARGET_NAME_EXE} PRIVATE ${COMPILE_FEATURES})

target_compile_options(${TARGET_NAME_EXE}
  PRIVATE
  -Wall
  -Wextra
  -Wfatal-errors
  -Wpedantic
  -Werror
  -Wshadow
  -Wdouble-promotion
  -Wformat=2
  -Wformat-truncation
  -Wundef
  -fno-common
  -Wconversion)

# Catch2::Catch2WithMain
target_link_libraries(${TARGET_NAME_EXE} PRIVATE OpenSSL::Crypto)
target_compile_features(${TARGET_NAME_EXE} PRIVATE ${COMPILE_FEATURES})

add_test_incl_memcheck(${PROJECT_NAME} ${TARGET_NAME_EXE})

include(IPO)
include(Packing)
include(Packaging)

set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssl (>= 3.0.0)")
include(CPack)

sbeclearjson(dependencies)
