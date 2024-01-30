include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(NOT DEFINED ${PROJECT_NAME}_INSTALL_CMAKEDIR)
  set(${PROJECT_NAME}_INSTALL_CMAKEDIR
      "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}"
      CACHE STRING "Path to ${PROJECT_NAME} CMake files")
endif()

install(
  TARGETS ${PROJECT_NAME}
  EXPORT ${PROJECT_NAME}_Targets
  COMPONENT ${PROJECT_NAME} # must be here, not any line lower
  RUNTIME COMPONENT ${PROJECT_NAME}_Runtime
  LIBRARY COMPONENT ${PROJECT_NAME}_Runtime
          NAMELINK_COMPONENT ${PROJECT_NAME}_Development
  ARCHIVE COMPONENT ${PROJECT_NAME}_Development
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} # bin
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} # lib
          # except for public headers, as we want them to be inside a library
          # folder
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
  INCLUDES
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(
  DIRECTORY "${${PROJECT_NAME}_SOURCE_DIR}/include/"
            "${${PROJECT_NAME}_BINARY_DIR}/include/"
  TYPE INCLUDE
  COMPONENT ${PROJECT_NAME}_Development)

if(BUILD_SHARED_LIBS)
  set(type shared)
else()
  set(type static)
endif()

install(
  EXPORT ${PROJECT_NAME}_Targets
  DESTINATION ${${PROJECT_NAME}_INSTALL_CMAKEDIR}
  NAMESPACE Fernet::
  FILE ${PROJECT_NAME}-${type}-targets.cmake
  COMPONENT ${PROJECT_NAME}_Development)

write_basic_package_version_file(${PROJECT_NAME}ConfigVersion.cmake
                                 COMPATIBILITY SameMajorVersion)

install(
  FILES "${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}Config.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
  DESTINATION "${${PROJECT_NAME}_INSTALL_CMAKEDIR}"
  COMPONENT ${PROJECT_NAME}_Development)
