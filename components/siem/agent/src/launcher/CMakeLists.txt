add_executable(tamsilcms
    main.cpp
    ${CMAKE_SOURCE_DIR}/agent_icon.rc
)

target_include_directories(tamsilcms PRIVATE ../../include)

target_link_libraries(tamsilcms PRIVATE advapi32)
