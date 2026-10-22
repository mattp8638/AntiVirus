// agent_sensor.h
// Sensor Service interface and event types
#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

namespace agent_sensor {
    struct ProcessCreateEvent {
        std::string asset_id;
        uint32_t pid;
        uint32_t parent_pid;
        std::wstring image_path;
        std::wstring command_line;
        std::wstring user_sid;
        std::chrono::system_clock::time_point event_time;
    };

    struct FileEvent {
        std::string asset_id;
        std::wstring file_path;
        std::string action; // create, write, delete
        std::string hash;
        std::chrono::system_clock::time_point event_time;
    };

    struct NetworkEvent {
        std::string asset_id;
        std::string local_ip;
        std::string remote_ip;
        uint16_t remote_port;
        std::string protocol;
        std::chrono::system_clock::time_point event_time;
    };

    struct RegistryEvent {
        std::string asset_id;
        std::wstring key_path;
        std::string action;
        std::chrono::system_clock::time_point event_time;
    };

    class SensorService {
    public:
        void EmitProcessEvent(const ProcessCreateEvent& evt);
        void EmitFileEvent(const FileEvent& evt);
        void EmitNetworkEvent(const NetworkEvent& evt);
        void EmitRegistryEvent(const RegistryEvent& evt);
        // ... other event types
    };
}

// Declare SendTelemetryMessage for use in main.cpp
int SendTelemetryMessage();
