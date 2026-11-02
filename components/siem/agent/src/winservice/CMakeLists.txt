cmake_minimum_required(VERSION 3.20)

add_executable(agent_winservice
    main.cpp
    service_entry.cpp
    RegisterService_stub.cpp
)

target_include_directories(agent_winservice PRIVATE ../../include)
target_link_libraries(agent_winservice PRIVATE advapi32)
