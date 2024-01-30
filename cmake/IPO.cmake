option(LTO "Build With link table optimisation" OFF)
# https://cmake.org/cmake/help/latest/module/CheckIPOSupported.html
if(LTO)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT supported OUTPUT error)
  set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE) # It is -lto : link table
                                               # optimisation flag
endif(LTO)
if(supported)
  message(STATUS "IPO / LTO enabled")
  set_property(TARGET ${PROJECT_NAME} PROPERTY INTERPROCEDURAL_OPTIMIZATION
                                               TRUE)
elseif(LTO)
  message(FATAL_ERROR "IPO / LTO not supported: <${error}>")
else()
  message(WARNING "IPO / LTO not activated")
endif()