// Unit tests for temporary admin account naming. Portable: g++ on Linux, or MinGW/MSVC.
#include <cstdio>
#include <string>

#include "TemporaryAdmin.h"

using namespace antivirus::agent::tempadmin;

static int failures = 0;
#define CHECK(cond)                                                    \
  do {                                                                 \
    if (!(cond)) {                                                     \
      std::printf("FAIL %s:%d %s\n", __FILE__, __LINE__, #cond);       \
      ++failures;                                                      \
    }                                                                  \
  } while (0)

int main() {
  // Named after the user it is for, unique per request, within Windows' 20 characters.
  CHECK(AccountName(L"PC1\\jo", L"elv_1a2b3c4d5e6f") == L"fadm-jo-5e6f");
  CHECK(AccountName(L"CONTOSO\\Matthew.Palmer", L"elv_00000000abcd") == L"fadm-matthewp-abcd");
  CHECK(AccountName(L"AzureAD\\matt@palmertech.co.uk", L"elv_x9") == L"fadm-matt-lvx9");  // the id's last 4 letters/digits
  CHECK(AccountName(L"élève", L"elv_ffff") == L"fadm-lve-ffff");  // non-ASCII letters are dropped
  CHECK(AccountName(L"éè", L"") == L"fadm-user-0000");
  for (const auto* user : {L"a", L"VeryLongDomainName\\AnExtremelyLongUserNameIndeed", L"x@y"}) {
    const auto name = AccountName(user, L"elv_0123456789abcdef");
    CHECK(name.size() <= 20 && IsTemporaryAccountName(name));
  }
  CHECK(AccountName(L"PC1\\jo", L"elv_aaaa1111") != AccountName(L"PC1\\jo", L"elv_aaaa2222"));
  // Only Fenrir's own accounts are ever treated as temporary ones.
  CHECK(!IsTemporaryAccountName(L"Administrator"));
  CHECK(!IsTemporaryAccountName(L"FenrirBreakGlass"));
  CHECK(!IsTemporaryAccountName(L"fadm-this-name-is-far-too-long"));
  if (failures == 0) std::printf("temporary admin naming tests passed\n");
  return failures == 0 ? 0 : 1;
}
