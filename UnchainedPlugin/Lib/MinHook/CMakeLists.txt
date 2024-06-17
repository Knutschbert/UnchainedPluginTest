# Specify the minimum CMake version
cmake_minimum_required(VERSION 3.10)

# Set the project name
project(MinHook)

# Add sources
set(MINHOOK_SOURCES
    src/buffer.c
    src/hook.c
    src/trampoline.c
    src/hde/hde32.c
    src/hde/hde64.c
)

# Add headers
set(MINHOOK_HEADERS
    include/MinHook.h
    src/buffer.h
    src/trampoline.h
    src/hde/hde32.h
    src/hde/hde64.h
    src/hde/pstdint.h
    src/hde/table32.h
    src/hde/table64.h
)

# Create a static library
add_library(MinHook STATIC ${MINHOOK_SOURCES} ${MINHOOK_HEADERS})

# Include directories
target_include_directories(MinHook PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
