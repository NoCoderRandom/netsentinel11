add_library(netsentinel_hardening STATIC
    src/hardening.cpp
)

target_include_directories(
    netsentinel_hardening
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
