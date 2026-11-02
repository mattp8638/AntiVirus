add_library(agent_ipc STATIC
    named_pipe_ipc.cpp
)

target_include_directories(agent_ipc PRIVATE ../include ../../include)

target_link_libraries(agent_ipc PRIVATE ${AGENT_LIBS})
