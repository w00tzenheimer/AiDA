cmake_minimum_required(VERSION 3.27)
project(aida)

set(CMAKE_CXX_STANDARD 17)

# Check for IDA SDK
if(NOT DEFINED IDASDK)
    if(DEFINED ENV{IDASDK})
        set(IDASDK "$ENV{IDASDK}")
    else()
        set(IDASDK "~/.idapro/idasdk91/")
    endif()
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
    # Force set environment variable for child processes/includes
    set(ENV{IDASDK} "${LOCAL_SDK_PATH}")
endif()

# Setup ida-cmake
set(IDA_SDK_ROOT "${IDASDK}")
if(NOT EXISTS "${IDA_SDK_ROOT}/ida-cmake/bootstrap.cmake")
    message(STATUS "Cloning ida-cmake into ${IDA_SDK_ROOT}/ida-cmake...")
    execute_process(
        COMMAND ${GIT_EXECUTABLE} clone --depth 1 https://github.com/allthingsida/ida-cmake.git "${IDA_SDK_ROOT}/ida-cmake"
        RESULT_VARIABLE git_result
    )
    if(NOT git_result EQUAL 0)
        message(FATAL_ERROR "Failed to clone ida-cmake")
    endif()
endif()

# Fix for GitHub SDK structure (src/include instead of include)
if(NOT EXISTS "${IDASDK}/include/pro.h" AND EXISTS "${IDASDK}/src/include/pro.h")
    message(STATUS "Detected GitHub SDK structure, updating IDASDK path to ${IDASDK}/src")
    set(IDASDK "${IDASDK}/src")
    set(ENV{IDASDK} "${IDASDK}")
endif()

include("${IDA_SDK_ROOT}/ida-cmake/bootstrap.cmake")
find_package(idasdk REQUIRED)

# Dependencies
include_directories("libs/cpp-httplib")
include_directories("libs/nlohmann")
find_package(OpenSSL REQUIRED)

# Plugin definition
file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "src/*.hpp")

add_ida_plugin(AiDA ${SOURCES} ${HEADERS})

# Link OpenSSL *AFTER* defining the target
target_link_libraries(AiDA PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(UNIX AND NOT APPLE)
    target_link_libraries(AiDA PRIVATE pthread)
endif()

# Platform specific defines
if(APPLE)
    target_compile_definitions(AiDA PRIVATE __MAC__)
elseif(UNIX)
    target_compile_definitions(AiDA PRIVATE __LINUX__)
elseif(WIN32)
    target_compile_definitions(AiDA PRIVATE __NT__)
    # Link Winsock2
    target_link_libraries(AiDA PRIVATE ws2_32)
endif()
