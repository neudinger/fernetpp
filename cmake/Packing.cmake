# these are cache variables, so they could be overwritten with -D,
# https://decovar.dev/blog/2021/09/23/cmake-cpack-package-deb-apt/
# https://refspecs.linuxfoundation.org/LSB_2.1.0/LSB-Core-generic/LSB-Core-generic/pkgnameconv.html
include(CPackComponent)

set(CPACK_PACKAGE_NAME
    Fernet-${PROJECT_NAME}
    CACHE STRING "${PROJECT_NAME} from neudinger in etherogenes projects")
# which is useful in case of packing only selected components instead of the
# whole thing
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "${PROJECT_NAME}"
    CACHE STRING "${PROJECT_NAME} ${PROJECT_DESCRIPTION}")
set(CPACK_PACKAGE_VENDOR "Etherogene")
set(CPACK_PACKAGE_HOMEPAGE_URL "${PROJECT_HOMEPAGE_URL}")
set(CPACK_PACKAGE_CONTACT "ikelive@hotmail.fr")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE.md")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")

set(CPACK_VERBATIM_VARIABLES YES)

set(CPACK_PACKAGE_INSTALL_DIRECTORY ${CPACK_PACKAGE_NAME})

if("${CPACK_OUTPUT_FILE_PREFIX}" STREQUAL "")
  set(CPACK_OUTPUT_FILE_PREFIX "${CMAKE_SOURCE_DIR}/dist") # /${CMAKE_PROJECT_VERSION}")
endif("${CPACK_OUTPUT_FILE_PREFIX}" STREQUAL "")

# that is if you want every group to have its own package, although the same
# will happen if this is not set (so it defaults to ONE_PER_GROUP) and
# CPACK_DEB_COMPONENT_INSTALL is set to YES
set(CPACK_COMPONENTS_GROUPING ONE_PER_GROUP)

# https://unix.stackexchange.com/a/11552/254512


if("${CPACK_PACKAGING_INSTALL_PREFIX}" STREQUAL "")
  set(CPACK_PACKAGING_INSTALL_PREFIX "/opt/") # /${CMAKE_PROJECT_VERSION}")
endif("${CPACK_PACKAGING_INSTALL_PREFIX}" STREQUAL "")


set(CPACK_PACKAGE_VERSION ${CMAKE_PROJECT_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${PROJECT_VERSION_PATCH})

set(CPACK_COMPONENT_Library_DISPLAY_NAME "${PROJECT_NAME} Library")
set(CPACK_COMPONENT_Library_DESCRIPTION "Fernet C++")
set(CPACK_COMPONENT_Library_REQUIRED 1)
set(CPACK_COMPONENT_Devel_DISPLAY_NAME "${PROJECT_NAME} Library")
set(CPACK_COMPONENT_Devel_DESCRIPTION
    "Development files for compiling ${PROJECT_NAME}.")
set(CPACK_COMPONENT_Devel_REQUIRED 0)
set(CPACK_PACKAGE_RELEASE 1)

set(CPACK_ARCHIVE_COMPONENT_INSTALL YES)
get_cmake_property(CPACK_COMPONENTS_ALL COMPONENTS)
list(REMOVE_ITEM CPACK_COMPONENTS_ALL "Unspecified")
set(CPACK_COMPONENT_UNSPECIFIED_HIDDEN TRUE)
set(CPACK_COMPONENT_UNSPECIFIED_REQUIRED TRUE)

# Debian
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_COMPRESSION_TYPE "xz")
# without this you won't be able to pack only specified component
set(CPACK_DEB_COMPONENT_INSTALL YES)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Barre Kevin")
if("${CPACK_PACKAGE_ARCHITECTURE}" STREQUAL "x86_64")
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64") # DEB doesn't always use the
                                                 # kernel's arch name
else()
  set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE ${CPACK_PACKAGE_ARCHITECTURE})
endif()
