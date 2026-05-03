add_library(netsentinel_api STATIC
    src/acceptance_audit.cpp
    src/agent_collector_protocol.cpp
    src/local_rest_api.cpp
    src/privacy_policy.cpp
    src/professional_workspace.cpp
    src/simulation_suite.cpp
)

target_include_directories(
    netsentinel_api
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    netsentinel_api
    PUBLIC
        netsentinel_storage
        netsentinel_engine
)
