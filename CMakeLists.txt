cmake_minimum_required(VERSION 3.20)
project(TCPView)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Download dependencies
include(FetchContent)

# GLFW for window creation
FetchContent_Declare(
    glfw
    GIT_REPOSITORY https://github.com/glfw/glfw.git
    GIT_TAG 3.3.8
)
FetchContent_MakeAvailable(glfw)

# Dear ImGui
FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.90.1
)
FetchContent_MakeAvailable(imgui)

# WinDivert - packet capture driver (автоматическая загрузка)
FetchContent_Declare(
    windivert
    URL https://github.com/basil00/Divert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(windivert)

# ImGui sources
set(IMGUI_DIR ${imgui_SOURCE_DIR})
set(IMGUI_SOURCES
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
)

# Main executable - console mode for now
add_executable(TCPView
    src/main.cpp
    src/net_engine.cpp
    src/pktmon_dialog.cpp
    ${IMGUI_SOURCES}
)

# Include directories
target_include_directories(TCPView PRIVATE
    ${IMGUI_DIR}
    ${IMGUI_DIR}/backends
    ${windivert_SOURCE_DIR}/include
)

# Link libraries
target_link_libraries(TCPView PRIVATE
    glfw
    opengl32
    ws2_32
    iphlpapi
    dwmapi
    shell32
    ole32
    ${windivert_SOURCE_DIR}/x64/WinDivert.lib
)

# Set output directories
set_target_properties(TCPView PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_RELEASE ${CMAKE_BINARY_DIR}/bin/Release
    RUNTIME_OUTPUT_DIRECTORY_DEBUG ${CMAKE_BINARY_DIR}/bin/Debug
)

# Copy WinDivert binaries to output directory (АВТОМАТИЧЕСКИ)
add_custom_command(TARGET TCPView POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${windivert_SOURCE_DIR}/x64/WinDivert64.sys
        $<TARGET_FILE_DIR:TCPView>/WinDivert64.sys
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${windivert_SOURCE_DIR}/x64/WinDivert.dll
        $<TARGET_FILE_DIR:TCPView>/WinDivert.dll
    COMMENT "Copying WinDivert binaries..."
)
