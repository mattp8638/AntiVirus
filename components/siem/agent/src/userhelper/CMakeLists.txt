add_executable(agent_userhelper
    main.cpp
    service_entry.cpp
    RegisterService_stub.cpp
)

target_include_directories(agent_userhelper PRIVATE ../../include)

target_link_libraries(agent_userhelper PRIVATE ${AGENT_LIBS} advapi32)
