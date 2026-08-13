cmake_minimum_required(VERSION 3.20)

# ---------------------------------------------------------------------------
# Stellaris QuickJS Loader
# ---------------------------------------------------------------------------
# Builds the DLL injection loader executable.
# Usage:
#   mkdir build && cd build
#   cmake .. -G "Visual Studio 17 2022" -A x64
#   cmake --build . --config Release
#
# Or with Ninja:
#   cmake .. -G Ninja -DCMAKE_BUILD_TYPE=Release
#   cmake --build .
# ---------------------------------------------------------------------------

project(stellaris-loader
    VERSION 1.0.0
    LANGUAGES CXX
    DESCRIPTION "DLL injection loader for Stellaris QuickJS modding"
)

# Require C++17 (for std::filesystem)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Output executable name
set(LOADER_NAME "stellaris-loader")

# Sources
set(LOADER_SOURCES
    main.cpp
    inject.cpp
)

set(LOADER_HEADERS
    inject.h
)

# Build the loader executable (console app for status output)
add_executable(${LOADER_NAME}
    ${LOADER_SOURCES}
    ${LOADER_HEADERS}
)

# Windows-specific settings
if(WIN32)
    target_link_libraries(${LOADER_NAME} PRIVATE
        kernel32.lib    # OpenProcess, VirtualAllocEx, CreateRemoteThread, etc.
        advapi32.lib    # Process security functions
    )

    # Embed version info in the executable
    target_compile_definitions(${LOADER_NAME} PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        UNICODE
        _UNICODE
    )

    # MSVC-specific: enable warnings
    if(MSVC)
        target_compile_options(${LOADER_NAME} PRIVATE
            /W4         # Warning level 4
            /WX         # Treat warnings as errors (for strictness)
            /permissive- # Strict conformance mode
        )
    endif()
endif()

# Set output directory to project bin/
set_target_properties(${LOADER_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/bin/Release"
)

# Install target (optional)
install(TARGETS ${LOADER_NAME}
    RUNTIME DESTINATION bin
)
