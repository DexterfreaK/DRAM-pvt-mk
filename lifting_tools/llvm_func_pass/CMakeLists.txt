cmake_minimum_required(VERSION 3.2)
project(func_pass)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake from ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_library(func_pass MODULE
  func_pass.cpp
)

# Must match library name above
set(LLVM_RUNTIME_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/bin)
set(LLVM_LIBRARY_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/lib)

set_target_properties(func_pass PROPERTIES
  COMPILE_FLAGS "-fno-rtti"
)

if(WIN32 OR CYGWIN)
  set(LLVM_LINK_COMPONENTS Core)
  llvm_config(func_pass USE_SHARED ${LLVM_LINK_COMPONENTS})
endif()
