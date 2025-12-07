cmake_minimum_required(VERSION 3.10)

project(AiDA)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# User provided SDK path
if(NOT DEFINED IDASDK)
    set(IDASDK "/home/lotso/.idapro/idasdk91/")
endif()

if(NOT EXISTS "${IDASDK}")
    message(FATAL_ERROR "IDA SDK not found at ${IDASDK}. Please set IDASDK environment variable or CMake variable.")
endif()

# Constants
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(IDA_ARCH_64 ON)
    set(Generated64bitPlugin ON)
    add_definitions(-D__EA64__)
else()
    set(IDA_ARCH_64 OFF)
    set(Generated64bitPlugin OFF)
endif()

# IDA SDK includes
include_directories(
    "${IDASDK}/include"
    "${IDASDK}/module"
)

# OpenSSL
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# Source files
file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "src/*.hpp")

# Dependencies (httplib, json)
include_directories("libs/cpp-httplib")
include_directories("libs/nlohmann")

# Link directories for IDA SDK
if(UNIX)
    link_directories("${IDASDK}/lib/x64_linux_gcc_64")
endif()

# Define the plugin library
add_library(AiDA SHARED ${SOURCES} ${HEADERS})

# Compiler definitions
if(UNIX)
    target_compile_definitions(AiDA PRIVATE __LINUX__ __X64__)
    # Position Independent Code is required for shared libraries
    set_property(TARGET AiDA PROPERTY POSITION_INDEPENDENT_CODE ON)
elseif(WIN32)
    target_compile_definitions(AiDA PRIVATE __NT__)
endif()

# Link IDA lib
if(UNIX)
    target_link_libraries(AiDA PRIVATE ida)
endif()


# Link OpenSSL
target_link_libraries(AiDA PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Link phtread
if(UNIX)
    target_link_libraries(AiDA PRIVATE pthread)
endif()

# Extension for IDA plugins
set_target_properties(AiDA PROPERTIES SUFFIX ".so")
set_target_properties(AiDA PROPERTIES PREFIX "")
