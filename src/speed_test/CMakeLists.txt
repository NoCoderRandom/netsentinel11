add_library(netsentinel_speed_test STATIC
    src/speed_test_stub.cpp
)

target_include_directories(
    netsentinel_speed_test
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
