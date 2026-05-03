set(NETSENTINEL_ENGINE_SOURCES
    src/domain_model.cpp
    src/error_model.cpp
    src/scan_contract.cpp
    src/logger.cpp
    src/adapter_inventory.cpp
    src/scan_scope.cpp
    src/netcore_boundary.cpp
    src/arp_discovery.cpp
    src/icmp_discovery.cpp
    src/tcp_discovery.cpp
    src/device_merge.cpp
    src/oui_vendor.cpp
    src/hostname_resolution.cpp
    src/netbios_discovery.cpp
    src/mdns_discovery.cpp
    src/ssdp_discovery.cpp
    src/fingerprint_engine_v1.cpp
    src/snmp_read_only_discovery.cpp
)

add_library(netsentinel_engine STATIC ${NETSENTINEL_ENGINE_SOURCES})

target_link_libraries(
    netsentinel_engine
    PRIVATE
        netsentinel_netcore_c
)

if(NETSENTINEL_HAS_JSON)
    target_link_libraries(netsentinel_engine PRIVATE nlohmann_json::nlohmann_json)
    target_compile_definitions(netsentinel_engine PRIVATE NETSENTINEL_HAVE_NLOHMANN_JSON=1)
else()
    target_compile_definitions(netsentinel_engine PRIVATE NETSENTINEL_HAVE_NLOHMANN_JSON=0)
endif()
if(NETSENTINEL_HAS_SPDLOG)
    target_link_libraries(netsentinel_engine PRIVATE spdlog::spdlog)
    target_compile_definitions(netsentinel_engine PRIVATE NETSENTINEL_HAVE_SPDLOG=1)
else()
    target_compile_definitions(netsentinel_engine PRIVATE NETSENTINEL_HAVE_SPDLOG=0)
endif()

target_include_directories(
    netsentinel_engine
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
