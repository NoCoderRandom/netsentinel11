add_library(netsentinel_installer STATIC
    src/installer_plan.cpp
)

target_include_directories(
    netsentinel_installer
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
