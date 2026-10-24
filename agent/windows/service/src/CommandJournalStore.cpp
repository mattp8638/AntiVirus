#include "CommandJournalStore.h"

#include "RuntimeDatabase.h"

namespace antivirus::agent {

CommandJournalStore::CommandJournalStore(std::filesystem::path databasePath) : databasePath_(std::move(databasePath)) {}

void CommandJournalStore::RecordPolled(const RemoteCommand& command) const {
  // Persist the in-flight marker BEFORE executing a side-effecting command.
  RuntimeDatabase(databasePath_).UpsertCommandJournal(command, L"started", L"{}", L"");
}

bool CommandJournalStore::LoadReceipt(const std::wstring& commandId, std::wstring& status,
                                      std::wstring& resultJson) const {
  return RuntimeDatabase(databasePath_).LoadCommandJournal(commandId, status, resultJson);
}

void CommandJournalStore::RecordCompleted(const RemoteCommand& command, const std::wstring& resultJson) const {
  RuntimeDatabase(databasePath_).UpsertCommandJournal(command, L"completed", resultJson, L"");
}

void CommandJournalStore::RecordFailed(const RemoteCommand& command, const std::wstring& failureJson,
                                       const std::wstring& errorMessage) const {
  RuntimeDatabase(databasePath_).UpsertCommandJournal(command, L"failed", failureJson, errorMessage);
}

}  // namespace antivirus::agent
