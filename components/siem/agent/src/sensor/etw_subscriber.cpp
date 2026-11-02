// etw_subscriber.cpp
// Windows Event Log / ETW subscription implementation (basic)
#include "../../include/agent_sensor_etw.h"
#include <iostream>
#include <vector>

namespace agent_sensor {

    EtwSubscriber::EtwSubscriber() {
        subscription_handle_ = nullptr;
    }

    EtwSubscriber::~EtwSubscriber() {
        Stop();
    }

    // Callback invoked by the subscription for each event
    DWORD WINAPI EtwSubscriber::CallbackStub(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID userContext, EVT_HANDLE event) {
        (void)userContext;
        if (action == EvtSubscribeActionError) {
            std::cerr << "ETW subscription error callback." << std::endl;
            return ERROR_SUCCESS;
        }
        if (action == EvtSubscribeActionDeliver && event != nullptr) {
            // Render event as XML
            DWORD status = ERROR_SUCCESS;
            DWORD bufferUsed = 0;
            DWORD propertyCount = 0;

            // First call to determine buffer size
            if (!EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &bufferUsed, &propertyCount)) {
                status = GetLastError();
                if (status != ERROR_INSUFFICIENT_BUFFER) {
                    std::cerr << "EvtRender failed to get size: " << status << std::endl;
                    return ERROR_SUCCESS;
                }
            }

            std::vector<wchar_t> buffer(bufferUsed / sizeof(wchar_t));
            if (!EvtRender(nullptr, event, EvtRenderEventXml, bufferUsed, buffer.data(), &bufferUsed, &propertyCount)) {
                std::cerr << "EvtRender failed to render XML: " << GetLastError() << std::endl;
                return ERROR_SUCCESS;
            }

            // Convert wide string to narrow for logging/IPC purposes (simple conversion)
            std::wstring wxml(buffer.data());
            std::string xml;
            xml.reserve(wxml.size());
            for (wchar_t c : wxml) xml.push_back((char)(c & 0xFF));

            // For now, print the XML to stdout. In production, forward to telemetry router/IPC
            std::cout << "ETW Event XML: " << xml << std::endl;
        }
        return ERROR_SUCCESS;
    }

    bool EtwSubscriber::Start() {
        // Subscribe to the Application channel for future events. In production, make this configurable.
        // Note: EvtSubscribe returns a handle that must be closed with EvtClose.
        subscription_handle_ = EvtSubscribe(nullptr, nullptr, L"Application", nullptr, nullptr, nullptr,
            (EVT_SUBSCRIBE_CALLBACK)EtwSubscriber::CallbackStub, EvtSubscribeToFutureEvents);

        if (!subscription_handle_) {
            std::cerr << "EvtSubscribe failed: " << GetLastError() << std::endl;
            return false;
        }
        std::cout << "ETW subscriber started." << std::endl;
        return true;
    }

    void EtwSubscriber::Stop() {
        if (subscription_handle_) {
            EvtClose(subscription_handle_);
            subscription_handle_ = nullptr;
        }
        std::cout << "ETW subscriber stopped." << std::endl;
    }

}
