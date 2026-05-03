add_library(netsentinel_alerts STATIC
    src/alert_router_stub.cpp
)

target_include_directories(
    netsentinel_alerts
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
