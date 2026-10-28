#include "RemoteSasRequest.h"

#include <iostream>
#include <stdexcept>

using antivirus::agent::remote::ValidateSasCaller;

void Check(bool condition, const char* reason) {
  if (!condition) throw std::runtime_error(reason);
}

int main() {
  try {
    Check(ValidateSasCaller(100, 100, 1, 1, true, true).empty(), "console helper was rejected");
    Check(ValidateSasCaller(100, 100, 7, 7, true, true).empty(), "RDP helper was rejected");
    Check(!ValidateSasCaller(100, 101, 1, 1, true, true).empty(), "a different process was accepted");
    Check(!ValidateSasCaller(0, 0, 1, 1, true, true).empty(), "an unidentified process was accepted");
    Check(!ValidateSasCaller(100, 100, 7, 1, true, true).empty(), "another Windows session was accepted");
    Check(!ValidateSasCaller(100, 100, 0, 0, true, true).empty(), "session 0 was accepted");
    Check(!ValidateSasCaller(100, 100, UINT32_MAX, UINT32_MAX, true, true).empty(), "an unknown session was accepted");
    Check(!ValidateSasCaller(100, 100, 1, 1, false, true).empty(), "a non-SYSTEM caller was accepted");
    Check(!ValidateSasCaller(100, 100, 1, 1, true, false).empty(), "an identification-only token was accepted");
    std::cout << "Remote SAS caller tests passed (console, RDP, PID, identity, impersonation, session isolation).\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
