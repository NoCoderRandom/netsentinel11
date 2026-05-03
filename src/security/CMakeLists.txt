add_library(netsentinel_security INTERFACE)

target_include_directories(
    netsentinel_security
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

