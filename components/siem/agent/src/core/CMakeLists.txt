# Core implementation library (shared between agent_core executable and tests)
add_library(agent_core_lib STATIC
    compliance.cpp
    evidence.cpp
    evidence_impl.cpp
    ../agent_rmm.cpp
    ../agent_config.cpp
    ../agent_system.cpp
    ipc_server.cpp
)

target_include_directories(agent_core_lib PRIVATE ../../include)
target_link_libraries(agent_core_lib PRIVATE ${AGENT_LIBS} OpenSSL::Crypto agent_stubs)

add_executable(agent_core
    main.cpp
    service_entry.cpp
)

target_include_directories(agent_core PRIVATE ../../include)
target_link_libraries(agent_core PRIVATE agent_core_lib agent_ipc advapi32)

add_executable(evidence_test
    evidence_test.cpp
)

target_include_directories(evidence_test PRIVATE ../../include)
target_link_libraries(evidence_test PRIVATE agent_core_lib)
