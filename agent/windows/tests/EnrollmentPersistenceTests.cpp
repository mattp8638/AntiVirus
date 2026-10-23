#include "EnrollmentPersistence.h"

#include <cassert>
#include <iostream>

int main() {
  using antivirus::agent::EnrollmentChangeRequiresMigration;
  const std::wstring server = L"https://fenrir.example";
  const std::wstring token = L"fet_current_token";
  // First setup is allowed to create an identity.
  assert(!EnrollmentChangeRequiresMigration(server, token, server, L"fet_new_token", false));
  assert(!EnrollmentChangeRequiresMigration(server, token, L"https://other.example", token, false));
  // Reinstall from the same deployment package must preserve identity.
  assert(!EnrollmentChangeRequiresMigration(server, token, server, token, true));
  assert(!EnrollmentChangeRequiresMigration(server, token, server + L"/", token, true));
  assert(!EnrollmentChangeRequiresMigration(server, token, L"", L"", true));
  // An enrolled device cannot silently move customer or server.
  assert(EnrollmentChangeRequiresMigration(server, token, server, L"fet_other_customer", true));
  assert(EnrollmentChangeRequiresMigration(server, token, L"https://other.example", token, true));
  assert(EnrollmentChangeRequiresMigration(server, token, L"https://other.example", L"fet_new_token", true));
  std::cout << "Enrollment persistence policy tests passed\n";
}
