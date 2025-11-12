add_library(httplib INTERFACE)
target_include_directories(httplib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

# Find OpenSSL for HTTPS support
find_package(OpenSSL REQUIRED)

# Link OpenSSL libraries for SSL/TLS functionality
target_link_libraries(httplib INTERFACE OpenSSL::SSL OpenSSL::Crypto)
