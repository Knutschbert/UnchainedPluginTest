cmake_minimum_required(VERSION 3.5)

project(${TARGET})

file(GLOB SOURCES "*.cpp" "include/*.cpp")
file(GLOB HEADERS "*.h" "include/*.h")

source_group("Source Files\\Utils" FILES
    logging.cpp
    include/commandline.cpp
    include/nettools.cpp
)

source_group("Header Files\\Utils" FILES
    include/commandline.h
    include/logging.h
    include/nettools.h
)

source_group("Header Files\\Hooks" FILES
    include/adminControl.h
    include/assetLoading.h
    include/backendHooks.h
    include/etcHooks.h
    include/ownershipOverrides.h
    include/sigs.h
    include/unchainedIntegration.h
)

add_library(${TARGET} SHARED ${SOURCES} ${HEADERS})
target_include_directories(${TARGET} PUBLIC include "Lib/Sig")

add_subdirectory(Lib/MinHook)
add_subdirectory(Lib/tiny-json)

target_link_libraries(${TARGET} MinHook tiny-json winhttp)
