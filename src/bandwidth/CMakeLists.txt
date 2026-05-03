add_library(netsentinel_bandwidth STATIC
    src/bandwidth_source.cpp
)

target_include_directories(
    netsentinel_bandwidth
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    netsentinel_bandwidth
    PRIVATE
        netsentinel_storage
        netsentinel_engine
)

if(WIN32)
    target_link_libraries(
        netsentinel_bandwidth
        PRIVATE
            Advapi32
            Iphlpapi
    )
endif()
