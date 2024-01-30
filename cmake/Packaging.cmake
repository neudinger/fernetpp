include(GenerateExportHeader)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
file(GLOB INCLUDE_SOURCES ${INCLUDE_DIR}/fernet/*.h)
generate_export_header(${PROJECT_NAME} EXPORT_FILE_NAME include/fernet/export.h)
target_compile_definitions(
  ${PROJECT_NAME}
  PUBLIC "$<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:${PROJECT_NAME}_STATIC_DEFINE>")
target_include_directories(
  ${PROJECT_NAME}
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>")

string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}"
               is_top_level)
option(${PROJECT_NAME}_INCLUDE_PACKAGING
       "Include packaging rules for ${PROJECT_NAME}" "${is_top_level}")
if(${PROJECT_NAME}_INCLUDE_PACKAGING)
  add_subdirectory(packaging)
endif()

set_target_properties(
  ${PROJECT_NAME} PROPERTIES VERSION ${${PROJECT_NAME}_VERSION}
                             SOVERSION ${${PROJECT_NAME}_VERSION_MAJOR})
target_include_directories(
  ${PROJECT_NAME}
  PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_${CMAKE_CXX_STANDARD})

# Generate the export header for FERNET and attach it to the target
set(FERNET_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
message(STATUS "FERNET_INCLUDE_DIR in: ${FERNET_INCLUDE_DIR}")
include_directories(${FERNET_INCLUDE_DIR})
