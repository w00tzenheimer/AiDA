cmake_minimum_required(VERSION 3.27)
project(aida)

set(CMAKE_CXX_STANDARD 17)

include(cmake/ida-cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

add_subdirectory(libs)
add_subdirectory(src)
