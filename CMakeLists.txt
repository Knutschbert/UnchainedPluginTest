cmake_minimum_required(VERSION 3.5)

set(TARGET UnchainedPlugin)

set(VER_MAJOR 0 CACHE STRING "MAJOR.minor.patch.build")
set(VER_MINOR 4 CACHE STRING "major.MINOR.patch.build")
set(VER_PATCH 2 CACHE STRING "major.minor.PATCH.build")
set(VER_BUILD 0 CACHE STRING "major.minor.patch.BUILD")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

project(${TARGET} VERSION 1)

include_directories(${PROJECT_SOURCE_DIR}/${TARGET}/include)

add_subdirectory(${TARGET})

