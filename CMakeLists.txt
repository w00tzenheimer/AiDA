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
    message(WARNING "IDA SDK not found at ${IDASDK}. Build may fail.")
endif()

# Check for ida-cmake
if(DEFINED ENV{IDA_CMAKE_DIR})
    set(IDA_CMAKE_DIR "$ENV{IDA_CMAKE_DIR}")
elseif(EXISTS "${CMAKE_SOURCE_DIR}/.ida_cmake")
    set(IDA_CMAKE_DIR "${CMAKE_SOURCE_DIR}/.ida_cmake")
else()
    # Fallback to FetchContent if not provided externally
    include(FetchContent)
    FetchContent_Declare(
      ida_cmake
      GIT_REPOSITORY https://github.com/allthingsida/ida-cmake.git
      GIT_TAG        main
    )
    FetchContent_MakeAvailable(ida_cmake)
    set(IDA_CMAKE_DIR "${ida_cmake_SOURCE_DIR}")
endif()

list(APPEND CMAKE_MODULE_PATH "${IDA_CMAKE_DIR}/cmake")
include("${IDA_CMAKE_DIR}/bootstrap.cmake")
find_package(idasdk REQUIRED)

# Dependencies
include_directories("libs/cpp-httplib")
include_directories("libs")
find_package(OpenSSL REQUIRED)

# Plugin definition
file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "src/*.hpp")

ida_add_plugin(AiDA SOURCES ${SOURCES} ${HEADERS})

# Link OpenSSL *AFTER* defining the target
target_link_libraries(AiDA PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(UNIX AND NOT APPLE)
    target_link_libraries(AiDA PRIVATE pthread)
endif()

# Platform specific defines
if(APPLE)
    target_compile_definitions(AiDA PRIVATE __MAC__)
    find_library(CORE_FOUNDATION_FRAMEWORK CoreFoundation)
    find_library(SECURITY_FRAMEWORK Security)
    find_library(CFNETWORK_FRAMEWORK CFNetwork)
    find_library(SYSTEM_CONFIGURATION_FRAMEWORK SystemConfiguration)
    target_link_libraries(AiDA PRIVATE ${CORE_FOUNDATION_FRAMEWORK} ${SECURITY_FRAMEWORK} ${CFNETWORK_FRAMEWORK} ${SYSTEM_CONFIGURATION_FRAMEWORK})
elseif(UNIX)
    target_compile_definitions(AiDA PRIVATE __LINUX__)
elseif(WIN32)
    target_compile_definitions(AiDA PRIVATE __NT__)
    # Link Winsock2
    target_link_libraries(AiDA PRIVATE ws2_32 crypt32)

    # Copy OpenSSL DLLs to output directory
    if(OPENSSL_FOUND)
        # Use include dir to find root, avoiding issues with optimized/debug keywords in library list
        # and quote paths to handle spaces
        list(GET OPENSSL_INCLUDE_DIR 0 OPENSSL_INC_DIR_SINGLE)
        
        get_filename_component(OPENSSL_ROOT_DIR "${OPENSSL_INC_DIR_SINGLE}" DIRECTORY)
        set(OPENSSL_BIN_DIR "${OPENSSL_ROOT_DIR}/bin")
        
        file(GLOB OPENSSL_DLLS "${OPENSSL_BIN_DIR}/*.dll")
        
        if(OPENSSL_DLLS)
            add_custom_command(TARGET AiDA POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${OPENSSL_DLLS}
                $<TARGET_FILE_DIR:AiDA>
                COMMENT "Copying OpenSSL DLLs to output directory"
            )
        else()
             message(WARNING "Could not find OpenSSL DLLs in ${OPENSSL_BIN_DIR} to bundle.")
        endif()
    endif()
endif()
