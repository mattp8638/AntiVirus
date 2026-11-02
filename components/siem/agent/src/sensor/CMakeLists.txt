add_executable(agent_sensor
    main.cpp
    service_entry.cpp
    etw_subscriber.cpp
    ipc_client.cpp
)

target_include_directories(agent_sensor PRIVATE ../../include)

target_link_libraries(agent_sensor PRIVATE ${AGENT_LIBS} advapi32 wevtapi agent_stubs agent_ipc)
