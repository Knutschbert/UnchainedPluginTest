cmake_minimum_required(VERSION 3.5)

project(tiny-json)

add_library(tiny-json STATIC tiny-json.c tiny-json.h)

target_include_directories(tiny-json PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
