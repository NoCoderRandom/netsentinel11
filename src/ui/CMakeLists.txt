add_library(netsentinel_ui STATIC
    src/gui_shell.cpp
)

target_include_directories(
    netsentinel_ui
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(
    netsentinel_ui
    PUBLIC
        netsentinel_storage
        netsentinel_diagnostics
        netsentinel_reports
        netsentinel_alerts
        netsentinel_api
        netsentinel_service
        netsentinel_speed_test
        netsentinel_engine
        netsentinel_bandwidth
        netsentinel_outage
)

find_package(Qt6 QUIET COMPONENTS Widgets)

if(Qt6_FOUND)
    target_compile_definitions(netsentinel_ui PUBLIC NETSENTINEL_UI_HAS_QT=1)
    add_executable(netsentinel11_gui
        src/qt_gui_main.cpp
    )
    target_link_libraries(
        netsentinel11_gui
        PRIVATE
            netsentinel_ui
            Qt6::Widgets
    )
else()
    target_compile_definitions(netsentinel_ui PUBLIC NETSENTINEL_UI_HAS_QT=0)
    message(STATUS "Qt6 Widgets not found. GUI shell model will build; native Qt executable is skipped.")
endif()
