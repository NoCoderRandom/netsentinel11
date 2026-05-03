set(NETCORE_CORE_SOURCES
    src/version.c
    src/adapter_inventory.c
    src/netcore_boundary.c
    src/arp_discovery.c
)

add_library(netsentinel_netcore_c STATIC ${NETCORE_CORE_SOURCES})
set_target_properties(netsentinel_netcore_c PROPERTIES OUTPUT_NAME netsentinel_netcore_c)

target_include_directories(
    netsentinel_netcore_c
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(WIN32)
    target_link_libraries(netsentinel_netcore_c PRIVATE iphlpapi ws2_32)
endif()

if(NETSENTINEL_HAS_SQLITE)
    # Explicitly keep this module independent of optional runtime integrations for now.
endif()
