/*
 * AntivirusMinifilter: Fenrir's file-system minifilter.
 *
 * What it does
 *   - Before Windows maps a file as executable code (starting a program, loading a DLL or driver image), it asks
 *     the Fenrir service (fenrir-agent-service.exe, connected on \AntiVirusRealtimePort) whether to allow it, and
 *     refuses the mapping with STATUS_ACCESS_DENIED when the service says block. This is pre-execution blocking.
 *   - When a handle that wrote to an executable, script or archive is closed, it sends the file for a scan
 *     (the service can quarantine it; the write itself has already happened).
 *   - A file found clean is remembered per stream until it is written to, the service reconnects, or ten minutes
 *     pass, so a program that starts often is not rescanned every time.
 *
 * Safety rules
 *   - Fail open: no service connected, a timeout, a malformed reply or a non-passive IRQL all mean "allow".
 *     After three failures in a row it stops asking for a minute (circuit breaker), so a hung service cannot
 *     stall every program start on the machine.
 *   - The service's own file activity is never sent back to it (it reads files to scan them; asking it about
 *     those reads would deadlock), nor is the System process's.
 *   - File names are resolved when a file is opened (post-create, PASSIVE_LEVEL) and kept in a stream-handle
 *     context; nothing queries names while section locks may be held.
 *   - The message layout is the shared, C-compatible RealtimeProtectionProtocol.h used by the service.
 */

#include <fltKernel.h>
#include <ntstrsafe.h>

#include "RealtimeProtectionProtocol.h"

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x1000000
#endif

#define AV_TAG_CONTEXT 'cfVA'
#define AV_TAG_MESSAGE 'mfVA'
#define AV_TAG_NAME 'nfVA'

#define AV_EXECUTE_TIMEOUT_MS 10000
#define AV_WRITE_TIMEOUT_MS 3000
#define AV_CLEAN_CACHE_100NS (600LL * 10000000LL) /* ten minutes */
#define AV_BREAKER_FAILURES 3
#define AV_BREAKER_100NS (60LL * 10000000LL) /* one minute */

typedef struct _AV_GLOBALS {
  PFLT_FILTER Filter;
  PFLT_PORT ServerPort;
  PFLT_PORT ClientPort;         /* the connected service; FltCloseClientPort clears it */
  HANDLE volatile ServicePid;   /* its process, whose I/O is never inspected */
  volatile LONG Generation;     /* bumped on every connect: clean results from before are not trusted */
  volatile LONG64 NextRequestId;
  volatile LONG ConsecutiveFailures;
  volatile LONG64 BreakerUntil; /* interrupt time; 0 = closed */
} AV_GLOBALS;

static AV_GLOBALS Globals;

/* Per volume: how to turn \Device\HarddiskVolumeN\... into C:\... (looked up lazily, outside mount paths). */
typedef struct _AV_INSTANCE_CONTEXT {
  PUNICODE_STRING volatile DosVolume;
  BOOLEAN Remote;
  BOOLEAN Removable;
} AV_INSTANCE_CONTEXT, *PAV_INSTANCE_CONTEXT;

/* Per open handle that may execute or that writes a risky file type. */
typedef struct _AV_HANDLE_CONTEXT {
  ULONG RequestFlags;
  ULONG PathRiskFlags;
  ULONG SignerTrust;
  ULONG DesiredAccess;
  ULONG CreateDisposition;
  ULONG64 FileSize;
  BOOLEAN WriteIntent;
  volatile BOOLEAN Written;
  USHORT PathChars;
  WCHAR Path[ANTIVIRUS_REALTIME_PATH_CAPACITY];
} AV_HANDLE_CONTEXT, *PAV_HANDLE_CONTEXT;

/* Per stream (file contents): the clean-result cache. */
typedef struct _AV_STREAM_CONTEXT {
  volatile LONG CleanGeneration; /* 0 = not known clean */
  volatile LONG WriteSequence;   /* bumped on every change, so a scan that raced a write is not cached */
  volatile LONG64 CleanAt;
} AV_STREAM_CONTEXT, *PAV_STREAM_CONTEXT;

DRIVER_INITIALIZE DriverEntry;
static NTSTATUS FLTAPI AvUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
static NTSTATUS FLTAPI AvInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags,
                                       DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType);
static NTSTATUS FLTAPI AvInstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects,
                                               FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);
static VOID FLTAPI AvInstanceContextCleanup(PFLT_CONTEXT Context, FLT_CONTEXT_TYPE ContextType);
static FLT_POSTOP_CALLBACK_STATUS FLTAPI AvPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                                      PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags);
static FLT_PREOP_CALLBACK_STATUS FLTAPI AvPreAcquireForSection(PFLT_CALLBACK_DATA Data,
                                                               PCFLT_RELATED_OBJECTS FltObjects,
                                                               PVOID* CompletionContext);
static FLT_PREOP_CALLBACK_STATUS FLTAPI AvPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                                   PVOID* CompletionContext);
static FLT_PREOP_CALLBACK_STATUS FLTAPI AvPreSetInformation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                                            PVOID* CompletionContext);
static FLT_PREOP_CALLBACK_STATUS FLTAPI AvPreCleanup(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                                     PVOID* CompletionContext);
static NTSTATUS FLTAPI AvPortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext,
                                     ULONG SizeOfContext, PVOID* ConnectionPortCookie);
static VOID FLTAPI AvPortDisconnect(PVOID ConnectionCookie);

static const FLT_OPERATION_REGISTRATION AvCallbacks[] = {
    {IRP_MJ_CREATE, 0, NULL, AvPostCreate},
    {IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, AvPreAcquireForSection, NULL},
    {IRP_MJ_WRITE, 0, AvPreWrite, NULL},
    {IRP_MJ_SET_INFORMATION, 0, AvPreSetInformation, NULL},
    {IRP_MJ_CLEANUP, 0, AvPreCleanup, NULL},
    {IRP_MJ_OPERATION_END}};

static const FLT_CONTEXT_REGISTRATION AvContexts[] = {
    {FLT_INSTANCE_CONTEXT, 0, AvInstanceContextCleanup, sizeof(AV_INSTANCE_CONTEXT), AV_TAG_CONTEXT},
    {FLT_STREAMHANDLE_CONTEXT, 0, NULL, sizeof(AV_HANDLE_CONTEXT), AV_TAG_CONTEXT},
    {FLT_STREAM_CONTEXT, 0, NULL, sizeof(AV_STREAM_CONTEXT), AV_TAG_CONTEXT},
    {FLT_CONTEXT_END}};

static const FLT_REGISTRATION AvRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    AvContexts,
    AvCallbacks,
    AvUnload,
    AvInstanceSetup,
    AvInstanceQueryTeardown,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL};

/* ------------------------------------------------------------------------------------------------------------ */
/* Small helpers                                                                                                 */

static BOOLEAN AvIsTrustedRequestor(VOID) {
  const HANDLE pid = PsGetCurrentProcessId();
  return pid == (HANDLE)4 || (Globals.ServicePid != NULL && pid == Globals.ServicePid);
}

static BOOLEAN AvBreakerOpen(VOID) {
  const LONG64 until = InterlockedCompareExchange64(&Globals.BreakerUntil, 0, 0);
  return until != 0 && (LONG64)KeQueryInterruptTime() < until;
}

static VOID AvRecordFailure(VOID) {
  if (InterlockedIncrement(&Globals.ConsecutiveFailures) >= AV_BREAKER_FAILURES) {
    InterlockedExchange(&Globals.ConsecutiveFailures, 0);
    InterlockedExchange64(&Globals.BreakerUntil, (LONG64)KeQueryInterruptTime() + AV_BREAKER_100NS);
  }
}

static BOOLEAN AvServiceAvailable(VOID) {
  return Globals.ClientPort != NULL && !AvBreakerOpen() && KeGetCurrentIrql() == PASSIVE_LEVEL;
}

static WCHAR AvUpper(WCHAR c) { return (c >= L'a' && c <= L'z') ? (WCHAR)(c - (L'a' - L'A')) : c; }

/* Case-insensitive search for an upper-case ASCII needle. */
static BOOLEAN AvContains(const WCHAR* text, USHORT textChars, const WCHAR* needle) {
  USHORT needleChars = 0;
  USHORT i, j;
  while (needle[needleChars] != L'\0') ++needleChars;
  if (needleChars == 0 || needleChars > textChars) return FALSE;
  for (i = 0; i + needleChars <= textChars; ++i) {
    for (j = 0; j < needleChars && AvUpper(text[i + j]) == needle[j]; ++j) {
    }
    if (j == needleChars) return TRUE;
  }
  return FALSE;
}

static BOOLEAN AvExtensionIn(const WCHAR* ext, USHORT extChars, const WCHAR* const* list) {
  USHORT i;
  for (; *list != NULL; ++list) {
    const WCHAR* candidate = *list;
    for (i = 0; i < extChars && candidate[i] != L'\0' && AvUpper(ext[i]) == candidate[i]; ++i) {
    }
    if (i == extChars && candidate[i] == L'\0') return TRUE;
  }
  return FALSE;
}

static const WCHAR* const AvExecutableExtensions[] = {L"EXE", L"DLL", L"SYS", L"SCR", L"COM", L"CPL", L"OCX",
                                                      L"MSI", L"MSP", L"DRV", L"EFI", L"PIF", NULL};
static const WCHAR* const AvScriptExtensions[] = {L"PS1", L"PSM1", L"PSD1", L"VBS", L"VBE", L"JS",  L"JSE", L"WSF",
                                                  L"WSH", L"HTA",  L"BAT",  L"CMD", L"LNK", L"REG", L"MSC", NULL};
static const WCHAR* const AvContainerExtensions[] = {L"ZIP", L"RAR", L"7Z",  L"ISO", L"IMG", L"VHD",
                                                     L"VHDX", L"CAB", L"JAR", L"GZ", L"TAR", NULL};

/* Extension, alternate data stream and location flags, as the service's protocol defines them. */
static VOID AvClassifyPath(PAV_HANDLE_CONTEXT ctx) {
  const WCHAR* path = ctx->Path;
  const USHORT chars = ctx->PathChars;
  USHORT lastSlash = 0, dot = 0, i;
  BOOLEAN hasStream = FALSE;
  for (i = 0; i < chars; ++i) {
    if (path[i] == L'\\') {
      lastSlash = i;
      dot = 0;
    } else if (path[i] == L'.') {
      dot = i;
    } else if (path[i] == L':' && i > 2) {
      hasStream = TRUE;
      break;
    }
  }
  if (dot > lastSlash) {
    const WCHAR* ext = path + dot + 1;
    const USHORT extChars = (USHORT)(i - dot - 1);
    if (AvExtensionIn(ext, extChars, AvExecutableExtensions)) ctx->PathRiskFlags |= ANTIVIRUS_REALTIME_PATH_RISK_EXECUTABLE_EXTENSION;
    if (AvExtensionIn(ext, extChars, AvScriptExtensions)) ctx->PathRiskFlags |= ANTIVIRUS_REALTIME_PATH_RISK_SCRIPT_EXTENSION;
    if (AvExtensionIn(ext, extChars, AvContainerExtensions)) ctx->PathRiskFlags |= ANTIVIRUS_REALTIME_PATH_RISK_CONTAINER_EXTENSION;
  }
  if (hasStream) {
    ctx->PathRiskFlags |= ANTIVIRUS_REALTIME_PATH_RISK_ADS_PATH;
    ctx->RequestFlags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_ADS_PATH;
  }
  if (AvContains(path, chars, L"\\USERS\\") || AvContains(path, chars, L"\\PROGRAMDATA\\")) {
    ctx->PathRiskFlags |= ANTIVIRUS_REALTIME_PATH_RISK_USER_CONTROLLED;
  }
  if (AvContains(path, chars, L"\\APPDATA\\LOCAL\\TEMP\\") || AvContains(path, chars, L"\\DOWNLOADS\\") ||
      AvContains(path, chars, L"\\WINDOWS\\TEMP\\") || AvContains(path, chars, L"\\$RECYCLE.BIN\\")) {
    ctx->PathRiskFlags |= ANTIVIRUS_REALTIME_PATH_RISK_HIGH_RISK_PATH;
  }
  if (AvContains(path, chars, L"\\..\\")) ctx->PathRiskFlags |= ANTIVIRUS_REALTIME_PATH_RISK_TRAVERSAL_SEQUENCE;
  if (chars > 3 && AvContains(path, chars < 12 ? chars : 12, L":\\WINDOWS\\")) {
    ctx->SignerTrust = ANTIVIRUS_REALTIME_SIGNER_TRUST_SYSTEM;
  } else if (AvContains(path, chars, L":\\PROGRAM FILES")) {
    ctx->SignerTrust = ANTIVIRUS_REALTIME_SIGNER_TRUST_PROGRAM_FILES;
  } else if (AvContains(path, chars, L"\\USERS\\")) {
    ctx->SignerTrust = ANTIVIRUS_REALTIME_SIGNER_TRUST_USER_PATH;
  } else {
    ctx->SignerTrust = ANTIVIRUS_REALTIME_SIGNER_TRUST_UNKNOWN;
  }
}

/* Cheap check on the name as opened, before any name query: does a write to this file need following? */
static BOOLEAN AvRiskyOpenedName(PCUNICODE_STRING name) {
  const USHORT chars = (USHORT)(name->Length / sizeof(WCHAR));
  USHORT i, dot = 0, end = chars;
  for (i = 0; i < chars; ++i) {
    if (name->Buffer[i] == L'\\') {
      dot = 0;
    } else if (name->Buffer[i] == L'.') {
      dot = i;
    } else if (name->Buffer[i] == L':' && i > 2) {
      end = i;
      break;
    }
  }
  if (dot == 0 || dot + 1 >= end) return FALSE;
  return AvExtensionIn(name->Buffer + dot + 1, (USHORT)(end - dot - 1), AvExecutableExtensions) ||
         AvExtensionIn(name->Buffer + dot + 1, (USHORT)(end - dot - 1), AvScriptExtensions) ||
         AvExtensionIn(name->Buffer + dot + 1, (USHORT)(end - dot - 1), AvContainerExtensions);
}

static VOID AvAppend(PAV_HANDLE_CONTEXT ctx, const WCHAR* text, USHORT chars) {
  const USHORT room = (USHORT)(ANTIVIRUS_REALTIME_PATH_CAPACITY - 1 - ctx->PathChars);
  const USHORT take = chars < room ? chars : room;
  RtlCopyMemory(ctx->Path + ctx->PathChars, text, take * sizeof(WCHAR));
  ctx->PathChars = (USHORT)(ctx->PathChars + take);
  ctx->Path[ctx->PathChars] = L'\0';
}

/* "C:" for a local volume, "\" for the network redirector (so \Device\Mup\server\share becomes \\server\share). */
static PUNICODE_STRING AvDosVolume(PCFLT_RELATED_OBJECTS FltObjects, PAV_INSTANCE_CONTEXT ictx) {
  PUNICODE_STRING existing = ictx->DosVolume;
  PUNICODE_STRING created;
  UNICODE_STRING dos = {0};
  PDEVICE_OBJECT disk = NULL;
  if (existing != NULL) return existing;
  if (ictx->Remote) {
    dos.Buffer = L"\\";
    dos.Length = sizeof(WCHAR);
  } else {
    NTSTATUS status = FltGetDiskDeviceObject(FltObjects->Volume, &disk);
    if (!NT_SUCCESS(status)) return NULL;
    status = IoVolumeDeviceToDosName(disk, &dos);
    ObDereferenceObject(disk);
    if (!NT_SUCCESS(status) || dos.Buffer == NULL) return NULL;
  }
  created = (PUNICODE_STRING)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(UNICODE_STRING) + dos.Length, AV_TAG_NAME);
  if (created != NULL) {
    created->Buffer = (PWCH)(created + 1);
    created->Length = created->MaximumLength = dos.Length;
    RtlCopyMemory(created->Buffer, dos.Buffer, dos.Length);
  }
  if (!ictx->Remote) ExFreePool(dos.Buffer);
  if (created == NULL) return NULL;
  existing = (PUNICODE_STRING)InterlockedCompareExchangePointer((PVOID volatile*)&ictx->DosVolume, created, NULL);
  if (existing != NULL) {
    ExFreePoolWithTag(created, AV_TAG_NAME);
    return existing;
  }
  return created;
}

/* Stream (contents) context: found or created; NULL when the file system does not support it. */
static PAV_STREAM_CONTEXT AvStreamContext(PCFLT_RELATED_OBJECTS FltObjects, BOOLEAN create) {
  PAV_STREAM_CONTEXT ctx = NULL;
  PAV_STREAM_CONTEXT old = NULL;
  NTSTATUS status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&ctx);
  if (NT_SUCCESS(status)) return ctx;
  if (!create) return NULL;
  status = FltAllocateContext(Globals.Filter, FLT_STREAM_CONTEXT, sizeof(AV_STREAM_CONTEXT), NonPagedPoolNx,
                              (PFLT_CONTEXT*)&ctx);
  if (!NT_SUCCESS(status)) return NULL;
  RtlZeroMemory(ctx, sizeof(*ctx));
  status = FltSetStreamContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx,
                               (PFLT_CONTEXT*)&old);
  if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
    FltReleaseContext(ctx);
    return old;
  }
  if (!NT_SUCCESS(status)) {
    FltReleaseContext(ctx);
    return NULL;
  }
  return ctx;
}

static VOID AvInvalidate(PCFLT_RELATED_OBJECTS FltObjects) {
  PAV_STREAM_CONTEXT ctx = AvStreamContext(FltObjects, FALSE);
  if (ctx == NULL) return;
  InterlockedIncrement(&ctx->WriteSequence);
  InterlockedExchange(&ctx->CleanGeneration, 0);
  FltReleaseContext(ctx);
}

static BOOLEAN AvKnownClean(PAV_STREAM_CONTEXT ctx) {
  const LONG generation = InterlockedCompareExchange(&ctx->CleanGeneration, 0, 0);
  const LONG64 at = InterlockedCompareExchange64(&ctx->CleanAt, 0, 0);
  return generation != 0 && generation == Globals.Generation &&
         (LONG64)KeQueryInterruptTime() - at < AV_CLEAN_CACHE_100NS;
}

/*
 * Ask the service. Returns TRUE to block. *clean is set when the service positively found the file clean.
 * Anything other than a well-formed, matching reply is treated as allow (fail open).
 */
static BOOLEAN AvAskService(PAV_HANDLE_CONTEXT handle, ULONG operation, ULONG extraFlags, ULONG timeoutMs,
                            PBOOLEAN clean) {
  ANTIVIRUS_REALTIME_SCAN_REQUEST* request;
  ANTIVIRUS_REALTIME_SCAN_REPLY* reply;
  ULONG replyLength = sizeof(ANTIVIRUS_REALTIME_SCAN_REPLY);
  LARGE_INTEGER timeout;
  NTSTATUS status;
  BOOLEAN block = FALSE;
  ULONG64 requestId;
  *clean = FALSE;

  request = (ANTIVIRUS_REALTIME_SCAN_REQUEST*)ExAllocatePool2(
      POOL_FLAG_NON_PAGED, sizeof(ANTIVIRUS_REALTIME_SCAN_REQUEST) + sizeof(ANTIVIRUS_REALTIME_SCAN_REPLY),
      AV_TAG_MESSAGE);
  if (request == NULL) return FALSE;
  reply = (ANTIVIRUS_REALTIME_SCAN_REPLY*)(request + 1);

  requestId = (ULONG64)InterlockedIncrement64(&Globals.NextRequestId);
  request->protocolVersion = ANTIVIRUS_REALTIME_PROTOCOL_VERSION;
  request->requestSize = sizeof(ANTIVIRUS_REALTIME_SCAN_REQUEST);
  request->requestId = requestId;
  request->operation = operation;
  request->processId = (uint32_t)(ULONG_PTR)PsGetCurrentProcessId();
  request->threadId = (uint32_t)(ULONG_PTR)PsGetCurrentThreadId();
  request->parentProcessId = 0; /* the service fills in the process context from the process id */
  request->desiredAccess = handle->DesiredAccess;
  request->createDisposition = handle->CreateDisposition;
  request->requestFlags = handle->RequestFlags | extraFlags;
  request->signerTrustLevel = handle->SignerTrust;
  request->pathRiskFlags = handle->PathRiskFlags;
  request->fileSizeBytes = handle->FileSize;
  RtlStringCchPrintfW(request->correlationId, ANTIVIRUS_REALTIME_CORRELATION_CAPACITY, L"kmf-%I64u", requestId);
  RtlCopyMemory(request->path, handle->Path, (handle->PathChars + 1) * sizeof(WCHAR));

  timeout.QuadPart = -(LONGLONG)timeoutMs * 10000LL;
  status = FltSendMessage(Globals.Filter, &Globals.ClientPort, request, sizeof(ANTIVIRUS_REALTIME_SCAN_REQUEST), reply,
                          &replyLength, &timeout);
  /* STATUS_TIMEOUT is a success code, so compare with STATUS_SUCCESS exactly. */
  if (status == STATUS_SUCCESS && reply->protocolVersion == ANTIVIRUS_REALTIME_PROTOCOL_VERSION &&
      reply->requestId == requestId) {
    InterlockedExchange(&Globals.ConsecutiveFailures, 0);
    block = reply->action == ANTIVIRUS_REALTIME_RESPONSE_ACTION_BLOCK;
    *clean = !block && reply->disposition == ANTIVIRUS_REALTIME_RESPONSE_DISPOSITION_CLEAN;
  } else if (status != STATUS_PORT_DISCONNECTED) {
    AvRecordFailure();
  }
  ExFreePoolWithTag(request, AV_TAG_MESSAGE);
  return block;
}

/* Ask about a stream, using and updating the clean cache. Returns TRUE to block. */
static BOOLEAN AvInspect(PCFLT_RELATED_OBJECTS FltObjects, PAV_HANDLE_CONTEXT handle, ULONG operation,
                         ULONG extraFlags, ULONG timeoutMs) {
  BOOLEAN clean = FALSE;
  BOOLEAN block;
  LONG sequence = 0;
  LONG generation = Globals.Generation;
  PAV_STREAM_CONTEXT stream = AvStreamContext(FltObjects, TRUE);
  if (stream != NULL) {
    if (AvKnownClean(stream)) {
      FltReleaseContext(stream);
      return FALSE;
    }
    sequence = InterlockedCompareExchange(&stream->WriteSequence, 0, 0);
  }
  block = AvAskService(handle, operation, extraFlags, timeoutMs, &clean);
  if (stream != NULL) {
    if (clean && sequence == InterlockedCompareExchange(&stream->WriteSequence, 0, 0)) {
      InterlockedExchange64(&stream->CleanAt, (LONG64)KeQueryInterruptTime());
      InterlockedExchange(&stream->CleanGeneration, generation);
    }
    FltReleaseContext(stream);
  }
  return block;
}

/* ------------------------------------------------------------------------------------------------------------ */
/* Registration, ports and instances                                                                             */

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
  NTSTATUS status;
  PSECURITY_DESCRIPTOR descriptor = NULL;
  OBJECT_ATTRIBUTES attributes;
  UNICODE_STRING portName;
  UNREFERENCED_PARAMETER(RegistryPath);

  RtlZeroMemory(&Globals, sizeof(Globals));
  Globals.Generation = 1;

  status = FltRegisterFilter(DriverObject, &AvRegistration, &Globals.Filter);
  if (!NT_SUCCESS(status)) return status;

  /* System and Administrators only. */
  status = FltBuildDefaultSecurityDescriptor(&descriptor, FLT_PORT_ALL_ACCESS);
  if (NT_SUCCESS(status)) {
    RtlInitUnicodeString(&portName, ANTIVIRUS_REALTIME_PORT_NAME);
    InitializeObjectAttributes(&attributes, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, descriptor);
    status = FltCreateCommunicationPort(Globals.Filter, &Globals.ServerPort, &attributes, NULL, AvPortConnect,
                                        AvPortDisconnect, NULL, 1);
    FltFreeSecurityDescriptor(descriptor);
  }
  if (NT_SUCCESS(status)) {
    status = FltStartFiltering(Globals.Filter);
    if (!NT_SUCCESS(status)) FltCloseCommunicationPort(Globals.ServerPort);
  }
  if (!NT_SUCCESS(status)) FltUnregisterFilter(Globals.Filter);
  return status;
}

static NTSTATUS FLTAPI AvUnload(FLT_FILTER_UNLOAD_FLAGS Flags) {
  UNREFERENCED_PARAMETER(Flags);
  /* Unloading is allowed so that setup can upgrade the driver (fltmc unload needs administrator rights). */
  FltCloseCommunicationPort(Globals.ServerPort);
  FltUnregisterFilter(Globals.Filter);
  return STATUS_SUCCESS;
}

static NTSTATUS FLTAPI AvPortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie, PVOID ConnectionContext,
                                     ULONG SizeOfContext, PVOID* ConnectionPortCookie) {
  UNREFERENCED_PARAMETER(ServerPortCookie);
  UNREFERENCED_PARAMETER(ConnectionContext);
  UNREFERENCED_PARAMETER(SizeOfContext);
  Globals.ClientPort = ClientPort;
  InterlockedExchangePointer((PVOID volatile*)&Globals.ServicePid, PsGetCurrentProcessId());
  if (InterlockedIncrement(&Globals.Generation) == 0) InterlockedIncrement(&Globals.Generation);
  InterlockedExchange(&Globals.ConsecutiveFailures, 0);
  InterlockedExchange64(&Globals.BreakerUntil, 0);
  *ConnectionPortCookie = NULL;
  return STATUS_SUCCESS;
}

static VOID FLTAPI AvPortDisconnect(PVOID ConnectionCookie) {
  UNREFERENCED_PARAMETER(ConnectionCookie);
  FltCloseClientPort(Globals.Filter, &Globals.ClientPort);
  InterlockedExchangePointer((PVOID volatile*)&Globals.ServicePid, NULL);
}

static NTSTATUS FLTAPI AvInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects, FLT_INSTANCE_SETUP_FLAGS Flags,
                                       DEVICE_TYPE VolumeDeviceType, FLT_FILESYSTEM_TYPE VolumeFilesystemType) {
  PAV_INSTANCE_CONTEXT ctx = NULL;
  PDEVICE_OBJECT disk = NULL;
  NTSTATUS status;
  UNREFERENCED_PARAMETER(Flags);

  if (VolumeFilesystemType == FLT_FSTYPE_RAW) return STATUS_FLT_DO_NOT_ATTACH;
  if (VolumeDeviceType != FILE_DEVICE_DISK_FILE_SYSTEM && VolumeDeviceType != FILE_DEVICE_NETWORK_FILE_SYSTEM &&
      VolumeDeviceType != FILE_DEVICE_CD_ROM_FILE_SYSTEM) {
    return STATUS_FLT_DO_NOT_ATTACH;
  }
  status = FltAllocateContext(Globals.Filter, FLT_INSTANCE_CONTEXT, sizeof(AV_INSTANCE_CONTEXT), NonPagedPoolNx,
                              (PFLT_CONTEXT*)&ctx);
  if (!NT_SUCCESS(status)) return STATUS_SUCCESS; /* attach anyway; paths stay in NT form */
  RtlZeroMemory(ctx, sizeof(*ctx));
  ctx->Remote = VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM;
  ctx->Removable = VolumeDeviceType == FILE_DEVICE_CD_ROM_FILE_SYSTEM;
  if (!ctx->Remote && NT_SUCCESS(FltGetDiskDeviceObject(FltObjects->Volume, &disk))) {
    if (FlagOn(disk->Characteristics, FILE_REMOVABLE_MEDIA)) ctx->Removable = TRUE;
    ObDereferenceObject(disk);
  }
  FltSetInstanceContext(FltObjects->Instance, FLT_SET_CONTEXT_KEEP_IF_EXISTS, ctx, NULL);
  FltReleaseContext(ctx);
  return STATUS_SUCCESS;
}

static NTSTATUS FLTAPI AvInstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects,
                                               FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags) {
  UNREFERENCED_PARAMETER(FltObjects);
  UNREFERENCED_PARAMETER(Flags);
  return STATUS_SUCCESS;
}

static VOID FLTAPI AvInstanceContextCleanup(PFLT_CONTEXT Context, FLT_CONTEXT_TYPE ContextType) {
  PAV_INSTANCE_CONTEXT ctx = (PAV_INSTANCE_CONTEXT)Context;
  UNREFERENCED_PARAMETER(ContextType);
  if (ctx->DosVolume != NULL) ExFreePoolWithTag(ctx->DosVolume, AV_TAG_NAME);
}

/* ------------------------------------------------------------------------------------------------------------ */
/* Operations                                                                                                    */

/* Remember the name and intent of handles that may execute or that write risky file types. */
static FLT_POSTOP_CALLBACK_STATUS FLTAPI AvPostCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                                      PVOID CompletionContext, FLT_POST_OPERATION_FLAGS Flags) {
  PFLT_FILE_NAME_INFORMATION name = NULL;
  PAV_INSTANCE_CONTEXT instance = NULL;
  PAV_HANDLE_CONTEXT handle = NULL;
  PUNICODE_STRING dosVolume = NULL;
  FILE_STANDARD_INFORMATION standard;
  BOOLEAN isDirectory = FALSE;
  ULONG desiredAccess, disposition;
  BOOLEAN executeIntent, writeIntent;
  NTSTATUS status;
  UNREFERENCED_PARAMETER(CompletionContext);

  if (FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING)) return FLT_POSTOP_FINISHED_PROCESSING;
  if (!NT_SUCCESS(Data->IoStatus.Status) || Data->IoStatus.Status == STATUS_REPARSE) return FLT_POSTOP_FINISHED_PROCESSING;
  if (FltObjects->FileObject == NULL || FlagOn(FltObjects->FileObject->Flags, FO_VOLUME_OPEN)) return FLT_POSTOP_FINISHED_PROCESSING;
  if (AvIsTrustedRequestor() || KeGetCurrentIrql() != PASSIVE_LEVEL) return FLT_POSTOP_FINISHED_PROCESSING;

  desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
  disposition = (Data->Iopb->Parameters.Create.Options >> 24) & 0xFF;
  executeIntent = FlagOn(desiredAccess, FILE_EXECUTE) != 0;
  writeIntent = FlagOn(desiredAccess, FILE_WRITE_DATA | FILE_APPEND_DATA) != 0 || disposition == FILE_SUPERSEDE ||
                disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF ||
                Data->IoStatus.Information == FILE_CREATED;
  if (!executeIntent && !writeIntent) return FLT_POSTOP_FINISHED_PROCESSING;
  if (NT_SUCCESS(FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDirectory)) && isDirectory) {
    return FLT_POSTOP_FINISHED_PROCESSING;
  }
  if (FsRtlIsPagingFile(FltObjects->FileObject)) return FLT_POSTOP_FINISHED_PROCESSING;
  if (writeIntent) AvInvalidate(FltObjects);
  if (!executeIntent && !AvRiskyOpenedName(&FltObjects->FileObject->FileName)) return FLT_POSTOP_FINISHED_PROCESSING;

  status = FltAllocateContext(Globals.Filter, FLT_STREAMHANDLE_CONTEXT, sizeof(AV_HANDLE_CONTEXT), PagedPool,
                              (PFLT_CONTEXT*)&handle);
  if (!NT_SUCCESS(status)) return FLT_POSTOP_FINISHED_PROCESSING;
  RtlZeroMemory(handle, sizeof(*handle));
  handle->DesiredAccess = desiredAccess;
  handle->CreateDisposition = disposition;
  handle->WriteIntent = writeIntent;
  if (executeIntent) handle->RequestFlags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_EXECUTE_INTENT;
  if (writeIntent) handle->RequestFlags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_WRITE_INTENT;

  status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
  if (!NT_SUCCESS(status)) {
    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
  }
  if (!NT_SUCCESS(status)) {
    FltReleaseContext(handle);
    return FLT_POSTOP_FINISHED_PROCESSING;
  }
  FltParseFileNameInformation(name);
  if (NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT*)&instance))) {
    dosVolume = AvDosVolume(FltObjects, instance);
    if (instance->Remote) handle->RequestFlags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_REMOTE_VOLUME;
    if (instance->Removable) handle->RequestFlags |= ANTIVIRUS_REALTIME_REQUEST_FLAG_REMOVABLE_VOLUME;
  }
  if (dosVolume != NULL && name->Volume.Length > 0 && name->Name.Length >= name->Volume.Length) {
    AvAppend(handle, dosVolume->Buffer, (USHORT)(dosVolume->Length / sizeof(WCHAR)));
    AvAppend(handle, name->Name.Buffer + name->Volume.Length / sizeof(WCHAR),
             (USHORT)((name->Name.Length - name->Volume.Length) / sizeof(WCHAR)));
  } else {
    AvAppend(handle, name->Name.Buffer, (USHORT)(name->Name.Length / sizeof(WCHAR)));
  }
  if (instance != NULL) FltReleaseContext(instance);
  FltReleaseFileNameInformation(name);
  AvClassifyPath(handle);

  /* Writes are only followed for file types that can run or carry something that runs. */
  if (!executeIntent &&
      !FlagOn(handle->PathRiskFlags, ANTIVIRUS_REALTIME_PATH_RISK_EXECUTABLE_EXTENSION |
                                         ANTIVIRUS_REALTIME_PATH_RISK_SCRIPT_EXTENSION |
                                         ANTIVIRUS_REALTIME_PATH_RISK_CONTAINER_EXTENSION)) {
    FltReleaseContext(handle);
    return FLT_POSTOP_FINISHED_PROCESSING;
  }
  if (NT_SUCCESS(FltQueryInformationFile(FltObjects->Instance, FltObjects->FileObject, &standard, sizeof(standard),
                                         FileStandardInformation, NULL))) {
    handle->FileSize = (ULONG64)standard.EndOfFile.QuadPart;
  }
  FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_REPLACE_IF_EXISTS, handle,
                            NULL);
  FltReleaseContext(handle);
  return FLT_POSTOP_FINISHED_PROCESSING;
}

/* The pre-execution check: Windows is about to map this file as code. */
static FLT_PREOP_CALLBACK_STATUS FLTAPI AvPreAcquireForSection(PFLT_CALLBACK_DATA Data,
                                                               PCFLT_RELATED_OBJECTS FltObjects,
                                                               PVOID* CompletionContext) {
  PAV_HANDLE_CONTEXT handle = NULL;
  ULONG protection, operation, extraFlags = 0;
  BOOLEAN block;
  *CompletionContext = NULL;

  if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }
  protection = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
  if (protection != PAGE_EXECUTE && protection != PAGE_EXECUTE_READ && protection != PAGE_EXECUTE_READWRITE &&
      protection != PAGE_EXECUTE_WRITECOPY) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }
  if (AvIsTrustedRequestor() || !AvServiceAvailable() || FltObjects->FileObject == NULL) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }
  if (!NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&handle))) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK; /* opened before the driver loaded, or not a tracked handle */
  }
  if (FlagOn(Data->Iopb->Parameters.AcquireForSectionSynchronization.AllocationAttributes, SEC_IMAGE)) {
    operation = ANTIVIRUS_REALTIME_FILE_OPERATION_EXECUTE;
  } else {
    operation = ANTIVIRUS_REALTIME_FILE_OPERATION_SECTION_MAP;
    extraFlags = ANTIVIRUS_REALTIME_REQUEST_FLAG_SECTION_MAP_EXECUTE;
  }
  block = AvInspect(FltObjects, handle, operation, extraFlags, AV_EXECUTE_TIMEOUT_MS);
  FltReleaseContext(handle);
  if (block) {
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
  }
  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI AvPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                                   PVOID* CompletionContext) {
  PAV_HANDLE_CONTEXT handle = NULL;
  *CompletionContext = NULL;
  if (FltObjects->FileObject == NULL) return FLT_PREOP_SUCCESS_NO_CALLBACK;
  AvInvalidate(FltObjects); /* any write, including paging writes from mapped views, changes the contents */
  if (!FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) &&
      NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&handle))) {
    handle->Written = TRUE;
    FltReleaseContext(handle);
  }
  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static FLT_PREOP_CALLBACK_STATUS FLTAPI AvPreSetInformation(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                                            PVOID* CompletionContext) {
  const FILE_INFORMATION_CLASS infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
  *CompletionContext = NULL;
  if (FltObjects->FileObject != NULL &&
      (infoClass == FileEndOfFileInformation || infoClass == FileAllocationInformation ||
       infoClass == FileValidDataLengthInformation)) {
    AvInvalidate(FltObjects);
  }
  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* A handle that wrote a risky file is closing: scan what was written (the service may quarantine it). */
static FLT_PREOP_CALLBACK_STATUS FLTAPI AvPreCleanup(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                                                     PVOID* CompletionContext) {
  PAV_HANDLE_CONTEXT handle = NULL;
  UNREFERENCED_PARAMETER(Data);
  *CompletionContext = NULL;
  if (FltObjects->FileObject == NULL || AvIsTrustedRequestor() || !AvServiceAvailable()) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }
  if (!NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, (PFLT_CONTEXT*)&handle))) {
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
  }
  if (handle->WriteIntent && handle->Written) {
    (VOID) AvInspect(FltObjects, handle, ANTIVIRUS_REALTIME_FILE_OPERATION_WRITE, 0, AV_WRITE_TIMEOUT_MS);
  }
  FltReleaseContext(handle);
  return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
