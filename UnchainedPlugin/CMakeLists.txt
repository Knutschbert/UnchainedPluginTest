cmake_minimum_required(VERSION 3.5)

project(${TARGET})

file(GLOB SOURCES "*.cpp" "include/*.cpp")
file(GLOB HEADERS "*.h" "include/*.h")

add_library(${TARGET} SHARED ${SOURCES} ${HEADERS})
target_include_directories(${TARGET} PUBLIC include "Lib/Sig")

add_subdirectory(Lib/MinHook)
add_subdirectory(Lib/tiny-json)

target_link_libraries(${TARGET} MinHook tiny-json winhttp)
