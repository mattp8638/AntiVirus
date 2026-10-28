#pragma once

#include <sqlite3.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

#include "StringUtils.h"

namespace antivirus::agent {

class DnsResolutionCache {
 public:
  explicit DnsResolutionCache(std::filesystem::path databasePath) : databasePath_(std::move(databasePath)) {}

  void UpsertResolution(const std::wstring& host,
                        const std::vector<std::wstring>& addresses,
                        const std::wstring& source = L"resolver") const {
    if (host.empty() || addresses.empty()) {
      return;
    }

    const auto db = OpenConnection();
    const auto observedAt = CurrentUtcTimestamp();
    auto statement = Prepare(db.get(),
                             "INSERT INTO dns_resolution_cache("
                             " normalized_ip, resolved_host, observed_at, source)"
                             " VALUES(?, ?, ?, ?)"
                             " ON CONFLICT(normalized_ip) DO UPDATE SET"
                             " resolved_host=excluded.resolved_host,"
                             " observed_at=excluded.observed_at,"
                             " source=excluded.source;");

    for (const auto& address : addresses) {
      if (address.empty()) {
        continue;
      }
      sqlite3_reset(statement.get());
      sqlite3_clear_bindings(statement.get());
      BindText(statement.get(), 1, address);
      BindText(statement.get(), 2, host);
      BindText(statement.get(), 3, observedAt);
      BindText(statement.get(), 4, source);
      StepDone(db.get(), statement.get());
    }
  }

  void CacheDomainVerdict(const std::wstring& domain,
                          const std::wstring& verdict,
                          const std::wstring& category = L"",
                          int ttlSeconds = 300) const {
    if (domain.empty()) {
      return;
    }

    const auto db = OpenConnection();
    const auto observedAt = CurrentUtcTimestamp();
    auto statement = Prepare(db.get(),
                             "INSERT INTO dns_verdict_cache("
                             " domain, verdict, category, observed_at, ttl_seconds)"
                             " VALUES(?, ?, ?, ?, ?)"
                             " ON CONFLICT(domain) DO UPDATE SET"
                             " verdict=excluded.verdict,"
                             " category=excluded.category,"
                             " observed_at=excluded.observed_at,"
                             " ttl_seconds=excluded.ttl_seconds;");

    BindText(statement.get(), 1, domain);
    BindText(statement.get(), 2, verdict);
    BindText(statement.get(), 3, category);
    BindText(statement.get(), 4, observedAt);
    sqlite3_bind_int(statement.get(), 5, ttlSeconds);
    StepDone(db.get(), statement.get());
  }

  std::wstring LookupDomainVerdict(const std::wstring& domain) const {
    if (domain.empty()) {
      return {};
    }

    const auto db = OpenConnection();
    auto statement = Prepare(db.get(),
                             "SELECT verdict, category FROM dns_verdict_cache"
                             " WHERE domain=?;");
    BindText(statement.get(), 1, domain);
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE || step != SQLITE_ROW) {
      return {};
    }
    return ColumnText(statement.get(), 0);
  }

  std::wstring LookupHostForIp(const std::wstring& address) const {
    if (address.empty()) {
      return {};
    }

    const auto db = OpenConnection();
    auto statement = Prepare(db.get(),
                             "SELECT resolved_host FROM dns_resolution_cache"
                             " WHERE normalized_ip=? ORDER BY observed_at DESC LIMIT 1;");
    BindText(statement.get(), 1, address);
    const auto step = sqlite3_step(statement.get());
    if (step == SQLITE_DONE) {
      return {};
    }
    if (step != SQLITE_ROW) {
      ThrowSqliteError(db.get(), "loading dns resolution cache failed");
    }
    return ColumnText(statement.get(), 0);
  }

 private:
  using ConnectionHandle = std::unique_ptr<sqlite3, decltype(&sqlite3_close)>;
  using StatementHandle = std::unique_ptr<sqlite3_stmt, decltype(&sqlite3_finalize)>;

  std::filesystem::path databasePath_;

  [[noreturn]] static void ThrowSqliteError(sqlite3* db, const char* message) {
    throw std::runtime_error(std::string(message) + ": " + (db == nullptr ? "sqlite unavailable" : sqlite3_errmsg(db)));
  }

  static void Exec(sqlite3* db, const char* sql) {
    char* errorMessage = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &errorMessage) != SQLITE_OK) {
      const auto combined = std::string("sqlite exec failed: ") + (errorMessage == nullptr ? sql : errorMessage);
      if (errorMessage != nullptr) {
        sqlite3_free(errorMessage);
      }
      throw std::runtime_error(combined);
    }
  }

  ConnectionHandle OpenConnection() const {
    if (databasePath_.has_parent_path()) {
      std::filesystem::create_directories(databasePath_.parent_path());
    }

    sqlite3* raw = nullptr;
    if (sqlite3_open_v2(WideToUtf8(databasePath_.wstring()).c_str(), &raw,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
      ThrowSqliteError(raw, "sqlite3_open_v2 failed");
    }

    ConnectionHandle connection(raw, sqlite3_close);
    Exec(connection.get(), "PRAGMA journal_mode=WAL;");
    Exec(connection.get(), "PRAGMA synchronous=FULL;");
    EnsureSchema(connection.get());
    return connection;
  }

  static void EnsureSchema(sqlite3* db) {
    Exec(db,
         "CREATE TABLE IF NOT EXISTS dns_resolution_cache ("
         " normalized_ip TEXT PRIMARY KEY,"
         " resolved_host TEXT NOT NULL,"
         " observed_at TEXT NOT NULL,"
         " source TEXT"
         ");"
         "CREATE INDEX IF NOT EXISTS idx_dns_resolution_host ON dns_resolution_cache(resolved_host, observed_at DESC);"
         "CREATE TABLE IF NOT EXISTS dns_verdict_cache ("
         " domain TEXT PRIMARY KEY,"
         " verdict TEXT NOT NULL,"
         " category TEXT,"
         " observed_at TEXT NOT NULL,"
         " ttl_seconds INTEGER NOT NULL DEFAULT 300"
         ");");
  }

  static StatementHandle Prepare(sqlite3* db, const char* sql) {
    sqlite3_stmt* raw = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &raw, nullptr) != SQLITE_OK) {
      ThrowSqliteError(db, "sqlite3_prepare_v2 failed");
    }
    return StatementHandle(raw, sqlite3_finalize);
  }

  static void StepDone(sqlite3* db, sqlite3_stmt* statement) {
    if (sqlite3_step(statement) != SQLITE_DONE) {
      ThrowSqliteError(db, "sqlite3_step did not finish");
    }
  }

  static void BindText(sqlite3_stmt* statement, int index, const std::wstring& value) {
    const auto utf8 = WideToUtf8(value);
    sqlite3_bind_text(statement, index, utf8.c_str(), -1, SQLITE_TRANSIENT);
  }

  static std::wstring ColumnText(sqlite3_stmt* statement, int column) {
    const auto* text = reinterpret_cast<const char*>(sqlite3_column_text(statement, column));
    return text == nullptr ? std::wstring{} : Utf8ToWide(reinterpret_cast<const char*>(text));
  }
};

}  // namespace antivirus::agent
