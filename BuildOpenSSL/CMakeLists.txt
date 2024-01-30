cmake_minimum_required(VERSION 3.27)
project(openssl)
# https://stackoverflow.com/questions/37845413/how-to-configure-externalproject-during-main-project-configuration
cmake_host_system_information(RESULT Ncpu QUERY NUMBER_OF_PHYSICAL_CORES)

include(ExternalProject)

if(NOT (IS_DIRECTORY ${INSTALL_NAME_DIR}))
  message(FATAL_ERROR "INSTALL_NAME_DIR IS NOT CORRECT")
endif(NOT (IS_DIRECTORY ${INSTALL_NAME_DIR}))

ExternalProject_Add(
  openssl
  DOWNLOAD_EXTRACT_TIMESTAMP true
  DOWNLOAD_DIR ${CMAKE_CURRENT_BINARY_DIR}
  UPDATE_DISCONNECTED True
  UPDATE_COMMAND ""
  URL ${OpenSSL_URL}
  URL_HASH ${OpenSSL_URL_HASH}
  SOURCE_DIR ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-${OpenSSL_Version}
  BUILD_IN_SOURCE 1
  # DEPENDS
  CONFIGURE_COMMAND
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-${OpenSSL_Version}/Configure
    linux-generic64 --prefix=${INSTALL_NAME_DIR}/${PROJECT_NAME}
  BUILD_COMMAND
    make -f ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-${OpenSSL_Version}/Makefile
    -j${Ncpu}
  INSTALL_COMMAND
    make -f ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-${OpenSSL_Version}/Makefile
    install -j${Ncpu})
