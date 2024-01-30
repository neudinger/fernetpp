cmake_minimum_required(VERSION 3.27)
project(
  Fernet
  LANGUAGES CXX
  VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# https://www.kitware.com/import-cmake-c20-modules/
# https://libcxx.llvm.org/Modules.html Libc++ doesn't support compiler
# extensions for modules.

set(CMAKE_CXX_EXTENSIONS ON)

find_package(OpenSSL REQUIRED)
set(OPENSSL_USE_STATIC_LIBS ON)

# add_compile_definitions(MODULE=ON)
# add_compile_options("-fmodules-ts")

# if(NOT DEFINED CMAKE_VISIBILITY_INLINES_HIDDEN)
#   set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)
# endif()

# string(
#   CONCAT CMAKE_EXPERIMENTAL_CXX_SCANDEP_SOURCE
#          "<CMAKE_CXX_COMPILER> <DEFINES> <INCLUDES> <FLAGS> <SOURCE>"
#          " -MT <DYNDEP_FILE> -MD -MF <DEP_FILE>"
#          " ${flags_to_scan_deps} -fdep-file=<DYNDEP_FILE> -fdep-output=<OBJECT>"
# )

# set(CMAKE_EXPERIMENTAL_CXX_MODULE_MAP_FORMAT "gcc")
# set(CMAKE_EXPERIMENTAL_CXX_MODULE_MAP_FLAG
#     "${compiler_flags_for_module_map} -fmodule-mapper=<MODULE_MAP_FILE>")

# This is required to write your own modules in your project.
# if(CMAKE_VERSION VERSION_LESS "3.27.0")
#   set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API
#       "2182bf5c-ef0d-489a-91da-49dbc3090d2a")
# else()
#   set(CMAKE_EXPERIMENTAL_CXX_MODULE_CMAKE_API
#       "aa1f7df0-828a-4fcd-9afc-2dc80491aca7")
# endif()
# set(CMAKE_EXPERIMENTAL_CXX_MODULE_DYNDEP 1)

if(NOT CMAKE_BUILD_TYPE)
  # set(CMAKE_BUILD_TYPE RelWithDebInfo)
  set(CMAKE_BUILD_TYPE Debug)
  # remove_definitions(NDEBUG) add_compile_definitions(NDEBUG=1)
  # add_compile_options()
  # set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)

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
  # target_compile_features(${PROJECT_NAME} PRIVATE
  # cxx_std_${CMAKE_CXX_STANDARD})
else()
  # list(APPEND LINK_TYPES SHARED)
endif()

get_filename_component(PARENT_DIR ${CMAKE_CURRENT_LIST_DIR} PATH)
if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL
                                        "RelWithDebInfo")
  # include_directories(${PARENT_DIR}/mcauth/include)
  # link_directories(${PARENT_DIR}/mcauth-build-lib/)
  message("Include locale openssl")
elseif(NOT EXISTS ${PARENT_DIR}/openssl)
  include(ExternalProject)
  cmake_host_system_information(RESULT Ncpu QUERY NUMBER_OF_PHYSICAL_CORES)
  ExternalProject_Add(
    openssl
    DOWNLOAD_EXTRACT_TIMESTAMP true
    DOWNLOAD_DIR ${CMAKE_CURRENT_BINARY_DIR}
    URL ${PARENT_DIR}/openssl-3.1.1.tar.gz # URL
        https://github.com/openssl/openssl/releases/download/openssl-3.1.1/openssl-3.1.1.tar.gz
    URL_HASH
      SHA256=b3aa61334233b852b63ddb048df181177c2c659eb9d4376008118f9c08d07674
    SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/openssl-3.1.1
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ${CMAKE_CURRENT_BINARY_DIR}/openssl-3.1.1/Configure
                      linux-generic64 --prefix=${PARENT_DIR}/openssl
    BUILD_COMMAND make -f ${CMAKE_CURRENT_BINARY_DIR}/openssl-3.1.1/Makefile
                  -j${Ncpu}
    INSTALL_COMMAND make -f ${CMAKE_CURRENT_BINARY_DIR}/openssl-3.1.1/Makefile
                    install -j${Ncpu})
endif()
# include_directories(${PARENT_DIR}/openssl/include)
# link_directories(${PARENT_DIR}/openssl/lib)

# add_compile_options(-fpic)

set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
message(STATUS "SRC_DIR ${SRC_DIR}")
file(GLOB SOURCES ${SRC_DIR}/*.cc)
message(STATUS "SOURCES ${SOURCES}")
# add_library(${PROJECT_NAME} ${SOURCES})
# add_library(${PROJECT_NAME}::fernet ALIAS ${PROJECT_NAME})

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)

# set_target_properties(
#   ${PROJECT_NAME} PROPERTIES VERSION ${${PROJECT_NAME}_VERSION}
#                              SOVERSION ${${PROJECT_NAME}_VERSION_MAJOR})
# target_include_directories(
#   ${PROJECT_NAME}
#   PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_${CMAKE_CXX_STANDARD})
