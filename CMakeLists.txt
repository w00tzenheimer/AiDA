cmake_minimum_required(VERSION 3.10)

project(AiDA)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# User provided SDK path
if(NOT DEFINED IDASDK)
    set(IDASDK "~/.idapro/idasdk91/")
endif()

if(NOT EXISTS "${IDASDK}")
    set(LOCAL_SDK_PATH "${CMAKE_SOURCE_DIR}/.ida_sdk")
    message(STATUS "IDA SDK not found at ${IDASDK}. Checking local fallback ${LOCAL_SDK_PATH}...")
    
    if(NOT EXISTS "${LOCAL_SDK_PATH}")
        message(STATUS "Cloning IDA SDK from https://github.com/HexRaysSA/ida-sdk to ${LOCAL_SDK_PATH}...")
        find_package(Git REQUIRED)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} clone --depth 1 https://github.com/HexRaysSA/ida-sdk.git ${LOCAL_SDK_PATH}
            RESULT_VARIABLE git_result
        )
        if(NOT git_result EQUAL 0)
            message(FATAL_ERROR "Failed to clone IDA SDK")
        endif()
    endif()
    
    set(IDASDK "${LOCAL_SDK_PATH}")
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
if(APPLE)
    target_compile_definitions(AiDA PRIVATE __MAC__)
    set_property(TARGET AiDA PROPERTY POSITION_INDEPENDENT_CODE ON)
elseif(UNIX)
    target_compile_definitions(AiDA PRIVATE __LINUX__ __X64__)
    # Position Independent Code is required for shared libraries
    set_property(TARGET AiDA PROPERTY POSITION_INDEPENDENT_CODE ON)
elseif(WIN32)
    target_compile_definitions(AiDA PRIVATE __NT__)
    # Link IDA lib for Windows
    target_link_libraries(AiDA PRIVATE "${IDASDK}/lib/x64_win_vc_64/ida.lib")
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
if(WIN32)
    set_target_properties(AiDA PROPERTIES SUFFIX ".dll")
elseif(APPLE)
    set_target_properties(AiDA PROPERTIES SUFFIX ".dylib")
else()
    set_target_properties(AiDA PROPERTIES SUFFIX ".so")
endif()
set_target_properties(AiDA PROPERTIES PREFIX "")
