// Minimal stub for agent_sensor::SensorService implementation
#include "../../include/agent_sensor.h"
namespace agent_sensor {
void SensorService::EmitProcessEvent(const ProcessCreateEvent&) {}
void SensorService::EmitFileEvent(const FileEvent&) {}
void SensorService::EmitNetworkEvent(const NetworkEvent&) {}
void SensorService::EmitRegistryEvent(const RegistryEvent&) {}
}
