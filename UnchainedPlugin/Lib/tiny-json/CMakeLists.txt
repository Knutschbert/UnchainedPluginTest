cmake_minimum_required(VERSION 3.5)

project(tiny-json)

set(TINY_JSON_SOURCES
    tiny-json.c
)

set(TINY_JSON_HEADERS
    tiny-json.h
)

add_library(tiny-json STATIC ${TINY_JSON_SOURCES} ${TINY_JSON_HEADERS})

target_include_directories(tiny-json PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
