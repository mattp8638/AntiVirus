// Sensor Service
// Responsibilities: Event capture, telemetry, minimal local interpretation
#include <iostream>
#include "agent_sensor.h"
#include "../../include/agent_sensor_etw.h"

int main(int argc, char* argv[]) {
    agent_sensor::SensorService sensor;
    // Start ETW / Event Log subscriber (skeleton)
    agent_sensor::EtwSubscriber etw;
    if (etw.Start()) {
        std::cout << "ETW subscriber running." << std::endl;
    }

    // TODO: Initialize real event captures (ETW, Event Log, Kernel callbacks, WMI, file system, network hooks)

    // Example: Emit a process event
    agent_sensor::ProcessCreateEvent evt;
    evt.asset_id = "TODO: asset_id";
    evt.pid = 1234;
    evt.parent_pid = 567;
    evt.image_path = L"C:\\Windows\\System32\\notepad.exe";
    evt.command_line = L"notepad.exe test.txt";
    evt.user_sid = L"S-1-5-21-...";
    evt.event_time = std::chrono::system_clock::now();
    sensor.EmitProcessEvent(evt);
    std::cout << "Sensor Service started. Example event emitted." << std::endl;

    // IPC test: send a telemetry message to core (non-blocking test)
    SendTelemetryMessage();

    // Keep service running (placeholder)
    while (true) { Sleep(1000); }
    return 0;
}
