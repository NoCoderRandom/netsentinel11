add_library(netsentinel_storage STATIC
    src/storage.cpp
)

target_include_directories(
    netsentinel_storage
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if (NETSENTINEL_HAS_SQLITE)
    target_compile_definitions(
        netsentinel_storage
        PRIVATE
            NETSENTINEL_HAVE_SQLITE=1
    )
else()
    target_compile_definitions(
        netsentinel_storage
        PRIVATE
            NETSENTINEL_HAVE_SQLITE=0
    )
endif()

target_link_libraries(
    netsentinel_storage
    PRIVATE
        netsentinel_engine
)
