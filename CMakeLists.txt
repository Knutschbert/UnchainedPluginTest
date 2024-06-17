cmake_minimum_required(VERSION 3.5)

set(TARGET UnchainedPlugin)
project(${TARGET} VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(${PROJECT_SOURCE_DIR}/${TARGET}/include)

add_subdirectory(${TARGET})

