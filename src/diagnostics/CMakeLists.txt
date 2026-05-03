add_library(netsentinel_diagnostics STATIC
    src/diagnostic_tools_stub.cpp
)

target_include_directories(
    netsentinel_diagnostics
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(WIN32)
    target_link_libraries(netsentinel_diagnostics PRIVATE ws2_32 wlanapi iphlpapi)
endif()
