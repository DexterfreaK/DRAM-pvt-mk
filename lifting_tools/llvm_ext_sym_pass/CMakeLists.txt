cmake_minimum_required(VERSION 3.2)
project(ext_sym_pass)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake from ${LLVM_DIR}")

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_library(ext_sym_pass MODULE
  ext_sym_pass.cpp
)

# Must match library name above
set(LLVM_RUNTIME_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/bin)
set(LLVM_LIBRARY_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/lib)

set_target_properties(ext_sym_pass PROPERTIES
  COMPILE_FLAGS "-fno-rtti"
)

if(WIN32 OR CYGWIN)
  set(LLVM_LINK_COMPONENTS Core)
  llvm_config(ext_sym_pass USE_SHARED ${LLVM_LINK_COMPONENTS})
endif()
