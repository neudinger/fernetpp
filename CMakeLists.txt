cmake_minimum_required(VERSION 3.27)

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

get_filename_component(PARENT_DIR ${CMAKE_SOURCE_DIR} PATH)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake
     ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(OpenSSL)
include(JSONParser)

file(READ ${CMAKE_SOURCE_DIR}/requirements.json requirementsJSON)
sbeparsejson(dependencies requirementsJSON)

# find_package(OpenSSL REQUIRED)
set(OPENSSL_USE_STATIC_LIBS ON)
set(CMAKE_COMPILE_WARNING_AS_ERROR ON)
add_compile_options(
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

# -Weverything (Clang only)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif(NOT CMAKE_BUILD_TYPE)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  remove_definitions(NDEBUG)
  add_compile_options(-fstack-usage -Wstack-usage=400)
endif(CMAKE_BUILD_TYPE STREQUAL "Release")

if(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
  add_compile_definitions(NDEBUG=1)
endif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(CMAKE_COMPILE_WARNING_AS_ERROR OFF)
  add_compile_options(-fstack-usage -Wstack-usage=500)
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
  # target_compile_features(${PROJECT_NAME} PRIVATE
  # cxx_std_${CMAKE_CXX_STANDARD})
else()
  # list(APPEND LINK_TYPES SHARED)
endif()

# To be able to be used by python add_compile_options(-fPIC)
add_definitions(-fPIC)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)

file(GLOB SOURCES_LIB ${SRC_DIR}/*.cc)
file(GLOB SOURCES_EXES ${SRC_DIR}/*.cpp)

set(TARGET_NAME_EXE ${PROJECT_NAME}.exe)

add_executable(${TARGET_NAME_EXE} ${SOURCES_LIB} ${SOURCES_EXES})
target_link_libraries(${TARGET_NAME_EXE} PRIVATE OpenSSL::Crypto)
target_compile_features(${TARGET_NAME_EXE}
                        PRIVATE cxx_std_${CMAKE_CXX_STANDARD})

add_library(${PROJECT_NAME} ${SOURCES_LIB})
add_library(Fernet::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

include(IPO)

include(Packing)
include(Packaging)

set(CPACK_DEBIAN_PACKAGE_DEPENDS "openssl (>= 3.0.2)")
include(CPack)

sbeclearjson(dependencies)
