add_library(netsentinel_service STATIC
    src/tray_service_stub.cpp
)

target_include_directories(
    netsentinel_service
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
