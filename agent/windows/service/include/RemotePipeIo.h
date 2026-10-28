#pragma once

#include <windows.h>

namespace antivirus::agent::remote {

// Every pipe operation must finish (including cancellation) before its buffer,
// OVERLAPPED or event is destroyed. A hung peer must not freeze the remote UI.
inline bool FinishPipeIo(HANDLE pipe, OVERLAPPED& operation, BOOL completed, DWORD startError,
                         DWORD timeoutMs, HANDLE peerProcess, DWORD& transferred) {
  transferred = 0;
  if (!completed && startError != ERROR_IO_PENDING) {
    SetLastError(startError);
    return false;
  }
  if (!completed) {
    HANDLE waits[] = {operation.hEvent, peerProcess};
    const DWORD wait = WaitForMultipleObjects(peerProcess ? 2 : 1, waits, FALSE, timeoutMs);
    if (wait != WAIT_OBJECT_0) {
      const DWORD error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT
                          : wait == WAIT_OBJECT_0 + 1 ? ERROR_BROKEN_PIPE : GetLastError();
      CancelIoEx(pipe, &operation);
      DWORD ignored = 0;
      GetOverlappedResult(pipe, &operation, &ignored, TRUE);
      SetLastError(error);
      return false;
    }
  }
  return GetOverlappedResult(pipe, &operation, &transferred, FALSE) != FALSE;
}

}  // namespace antivirus::agent::remote
