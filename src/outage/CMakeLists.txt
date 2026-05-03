add_library(netsentinel_outage STATIC
    src/outage_detector_stub.cpp
)

target_include_directories(
    netsentinel_outage
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(WIN32)
    target_link_libraries(
        netsentinel_outage
        PUBLIC
            iphlpapi
            ws2_32
    )
endif()
