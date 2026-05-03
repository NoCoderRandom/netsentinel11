add_executable(netsentinel11
    main.cpp
    safety_contract.cpp
)

target_include_directories(
    netsentinel11
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(
    netsentinel11
    PRIVATE
        netsentinel_netcore_c
        netsentinel_engine
        netsentinel_storage
        netsentinel_diagnostics
        netsentinel_security
        netsentinel_alerts
        netsentinel_speed_test
        netsentinel_outage
        netsentinel_service
        netsentinel_ui
        netsentinel_reports
        netsentinel_api
        netsentinel_installer
        netsentinel_bandwidth
        netsentinel_hardening
)

if(NETSENTINEL_HAS_SQLITE)
    target_compile_definitions(netsentinel11 PRIVATE NETSENTINEL_HAVE_SQLITE=1)
else()
    target_compile_definitions(netsentinel11 PRIVATE NETSENTINEL_HAVE_SQLITE=0)
endif()
if(NETSENTINEL_HAS_SPDLOG)
    target_compile_definitions(netsentinel11 PRIVATE NETSENTINEL_HAVE_SPDLOG=1)
else()
    target_compile_definitions(netsentinel11 PRIVATE NETSENTINEL_HAVE_SPDLOG=0)
endif()
if(NETSENTINEL_HAS_JSON)
    target_compile_definitions(netsentinel11 PRIVATE NETSENTINEL_HAVE_NLOHMANN_JSON=1)
else()
    target_compile_definitions(netsentinel11 PRIVATE NETSENTINEL_HAVE_NLOHMANN_JSON=0)
endif()

if(NETSENTINEL_HAS_SPDLOG)
    target_link_libraries(netsentinel11 PRIVATE spdlog::spdlog)
endif()
if(NETSENTINEL_HAS_JSON)
    target_link_libraries(netsentinel11 PRIVATE nlohmann_json::nlohmann_json)
endif()

set_target_properties(netsentinel11 PROPERTIES OUTPUT_NAME "netsentinel11")
