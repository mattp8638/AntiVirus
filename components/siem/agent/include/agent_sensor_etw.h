// agent_sensor_etw.h
// ETW / Windows Event Log subscriber skeleton for Sensor Service
#pragma once
#include <windows.h>
#include <winevt.h>
#include <string>

namespace agent_sensor {
    class EtwSubscriber {
    public:
        EtwSubscriber();
        ~EtwSubscriber();

        // Start subscribing to ETW or Windows Event Log
        bool Start();
        // Stop subscription
        void Stop();

    private:
        // Use correct callback type for ETW subscription
        EVT_SUBSCRIBE_CALLBACK callback_ = nullptr;
        EVT_HANDLE subscription_handle_ = nullptr;

        static DWORD WINAPI CallbackStub(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID userContext, EVT_HANDLE event);
    };
}
