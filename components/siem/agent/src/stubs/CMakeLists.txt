add_library(agent_stubs STATIC
    identity_stub.cpp
    core_stubs.cpp
    execution_stub.cpp
    module_registry_stub.cpp
    compliance_stub.cpp
    winservice_stub.cpp
    sensor_service_stub.cpp
)

target_include_directories(agent_stubs PRIVATE ../../include)

target_link_libraries(agent_stubs PRIVATE ${AGENT_LIBS})
