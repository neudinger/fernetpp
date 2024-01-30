get_filename_component(PROJECT_DIR ${CMAKE_SOURCE_DIR} PATH)

# https://cmake.org/cmake/help/latest/module/FindOpenSSL.html
find_program(
  OpenSSL
  NAMES openssl
  DOC "openssl tools")
if(OpenSSL)
  execute_process(
    COMMAND ${OpenSSL} version
    OUTPUT_VARIABLE openssl_output
    RESULT_VARIABLE openssl_result)

  string(REPLACE " " ";" openssl_output_list ${openssl_output})
  list(GET openssl_output_list 1 openssl_output_version)
else()
  set(openssl_output_version "")
endif(OpenSSL)
if(NOT ("${openssl_output_version}" STREQUAL "${dependencies.openssl.version}"))
  if(NOT (IS_DIRECTORY ${PROJECT_DIR}/built_dependencies/openssl/))
    make_directory(${PROJECT_DIR}/built_dependencies)

    # https://stackoverflow.com/questions/37845413/how-to-configure-externalproject-during-main-project-configuration
    execute_process(
      COMMAND
        ${CMAKE_COMMAND} -DINSTALL_NAME_DIR=${PROJECT_DIR}/built_dependencies
        -DOpenSSL_Version=${dependencies.openssl.version}
        -DOpenSSL_URL=${dependencies.openssl.url}
        -DOpenSSL_URL_HASH=${dependencies.openssl.hash} -S
        ${PROJECT_DIR}/BuildOpenSSL -B ${PROJECT_DIR}/build_dir-OpenSSL
      RESULT_VARIABLE PP)
    execute_process(COMMAND ${CMAKE_COMMAND} --build
                            ${PROJECT_DIR}/build_dir-OpenSSL RESULT_VARIABLE PP)
  endif(NOT (IS_DIRECTORY ${PROJECT_DIR}/built_dependencies/openssl/))

  set(OPENSSL_ROOT_DIR ${PROJECT_DIR}/built_dependencies/openssl/)
endif(NOT ("${openssl_output_version}" STREQUAL "${dependencies.openssl.version}"))

find_package(OpenSSL ${dependencies.openssl.version} REQUIRED)
set(OPENSSL_USE_STATIC_LIBS ON)
set(CMAKE_INCLUDE_PATH ${OPENSSL_INCLUDE_DIR}:${CMAKE_INCLUDE_PATH})
include_directories(${OPENSSL_INCLUDE_DIR})
link_directories(${OPENSSL_LIBRARIES})
