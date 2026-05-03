add_library(netsentinel_reports STATIC
    src/report_generator.cpp
)

target_include_directories(
    netsentinel_reports
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    netsentinel_reports
    PUBLIC
        netsentinel_storage
        netsentinel_diagnostics
        netsentinel_engine
        netsentinel_bandwidth
)
