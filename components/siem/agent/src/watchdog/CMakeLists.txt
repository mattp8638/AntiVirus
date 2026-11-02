add_executable(agent_watchdog
    main.cpp
    service_entry.cpp
    RegisterService_stub.cpp
    WatchdogService_stub.cpp
)

target_include_directories(agent_watchdog PRIVATE ../../include)

target_link_libraries(agent_watchdog PRIVATE ${AGENT_LIBS} advapi32)
