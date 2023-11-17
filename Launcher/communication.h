#pragma once

#pragma warning(disable : 26812) // deprecated api

// #define __DEBUG_PRINT

#define MAX_MUT_STR 260
#define MAX_CTX_LEN 260

static wchar_t szShMemName[] = L"EnviralMap";
static wchar_t szPipeName[] = L"\\\\.\\pipe\\EnviralPipe";

typedef enum Calls {
	cNtOpenKey,
	cNtOpenKeyEx,
	cNtQueryValueKey,
	cNtCreateKey,
	cNtEnumerateKey,
	cNtEnumerateValueKey,
	cNtCreateFile,
	cNtQueryAttributesFile,
	cNtDeviceIoControlFile,
	cNtQueryVolumeInformationFile,
	cNtQuerySystemInformation,
	cNtQuerySystemInformationEx,
	cNtPowerInformation,
	cNtQueryLicenseValue,
	cNtQueryDirectoryFile,
	cNtQueryInformationProcess,
	cNtQueryDirectoryObject,
	cNtCreateMutant,
	cNtOpenMutant,
	cGetAdaptersAddresses,
	cProcess32FirstW,
	cProcess32NextW,
	cCoCreateInstance,
	cGetModuleHandleW,
	cGetModuleHandleA,
	cGetModuleHandleExW,
	cGetModuleHandleExA,
	cGetAdaptersInfo,
	cSetupDiGetDeviceRegistryPropertyW,
	cSetupDiGetDeviceRegistryPropertyA,
	cGetLastInputInfo,
	cEnumServicesStatusExA,
	cEnumServicesStatusExW,
	cInternetCheckConnectionA,
	cInternetCheckConnectionW,
	cGetWindowRect,
	cGetMonitorInfoA,
	cGetMonitorInfoW,
	cFindWindowA,
	cFindWindowW,
	cFindWindowExA,
	cFindWindowExW,
	cGetCursorPos,
	cGetSystemMetrics,
	cSystemParametersInfoA,
	cSystemParametersInfoW,
	cGetAsyncKeyState,
	cGetForegroundWindow,
	cLoadLibraryExW,
	cLoadLibraryExA,
	cLoadLibraryW,
	cLoadLibraryA,
	CALL_SEPARATOR,
	cNtOpenFile,
	cNtReadFile,
	cNtWriteFile,
	cNtDeleteFile,
	cNtQueryInformationFile,
	cNtSetInformationFile,
	cNtOpenDirectoryObject,
	cNtCreateDirectoryObject,
	cNtCreateUserProcess,
	cNtCreateProcess,
	cNtCreateProcessEx,
	cNtSuspendProcess,
	cNtTerminateProcess,
	cNtMapViewOfSection,
	cNtUnmapViewOfSection,
	cNtMakeTemporaryObject,
	cNtMakePermanentObject,
	cNtWriteVirtualMemory,
	cNtSetInformationProcess,
	cNtGetNextProcess,
	cNtReplaceKey,
	cNtRenameKey,
	cNtSaveKey,
	cNtSaveKeyEx,
	cNtSetValueKey,
	cNtDeleteKey,
	cNtDeleteValueKey,
	cNtOpenTimer,
	cNtQueryTimer,
	cNtCreateTimer,
	cNtQuerySystemTime,
	cNtOpenEvent,
	cNtNotifyChangeKey,
	cNtOpenSemaphore,
	cNtCreateSemaphore,
	cNtLockFile,
	cGetSystemTime,
	cGetLocalTime,
	cCreateProcessInternalW,
	cNtCreateThread,
	cNtCreateThreadEx,
	cURLDownloadToFileW,
	cInternetOpenA,
	cInternetConnectA,
	cInternetConnectW,
	cInternetOpenUrlA,
	cHttpOpenRequestA,
	cHttpOpenRequestW,
	cHttpSendRequestA,
	cHttpSendRequestW,
	cInternetReadFile,
	cDnsQuery_A,
	cDnsQuery_W,
	cGetAddrInfoW,
	cWSAStartup,
	cgethostbyname,
	csocket,
	cconnect,
	csend,
	csendto,
	crecv,
	crecvfrom,
	cbind,
	cWSARecv,
	cWSARecvFrom,
	cWSASend,
	cWSASendTo,
	cWSASocketW,
	cFindResourceExW,
	cFindResourceExA,
	cQueryPerformanceCounter,
	cNtDelayExecution,
	cGetTickCount,
	CALL_END
} Call;

static char DebugCallNames[(UINT)Calls::CALL_END][60] = { "NtOpenKey","NtOpenKeyEx","NtQueryValueKey","NtCreateKey","NtEnumerateKey","NtEnumerateValueKey","NtCreateFile","NtQueryAttributesFile",
"NtDeviceIoControlFile","NtQueryVolumeInformationFile","NtQuerySystemInformation","NtQuerySystemInformationEx","NtPowerInformation","NtQueryLicenseValue","NtQueryDirectoryFile",
"NtQueryInformationProcess","NtQueryDirectoryObject","NtCreateMutant","NtOpenMutant","GetAdaptersAddresses","Process32FirstW","Process32NextW","CoCreateInstance","GetModuleHandleW",
"GetModuleHandleA","GetModuleHandleExW","GetModuleHandleExA","GetAdaptersInfo","SetupDiGetDeviceRegistryPropertyW","SetupDiGetDeviceRegistryPropertyA","GetLastInputInfo",
"EnumServicesStatusExA","EnumServicesStatusExW","InternetCheckConnectionA","InternetCheckConnectionW","GetWindowRect","GetMonitorInfoA","GetMonitorInfoW","FindWindowA","FindWindowW","FindWindowExA",
"FindWindowExW","GetCursorPos","GetSystemMetrics","SystemParametersInfoA","SystemParametersInfoW","GetAsyncKeyState","GetForegroundWindow","LoadLibraryExW","LoadLibraryExA","LoadLibraryW","LoadLibraryA","CALL_SEPARATOR","NtOpenFile",
"NtReadFile","NtWriteFile","NtDeleteFile","NtQueryInformationFile","NtSetInformationFile","NtOpenDirectoryObject","NtCreateDirectoryObject","NtCreateUserProcess",
"NtCreateProcess","NtCreateProcessEx","NtSuspendProcess","NtTerminateProcess","NtMapViewOfSection","NtUnmapViewOfSection","NtMakeTemporaryObject",
"NtMakePermanentObject","NtWriteVirtualMemory","NtSetInformationProcess","NtGetNextProcess","NtReplaceKey","NtRenameKey","NtSaveKey","NtSaveKeyEx",
"NtSetValueKey","NtDeleteKey","NtDeleteValueKey","NtOpenTimer","NtQueryTimer","NtCreateTimer","NtQuerySystemTime","NtOpenEvent","NtNotifyChangeKey",
"NtOpenSemaphore","NtCreateSemaphore","NtLockFile","GetSystemTime","GetLocalTime","CreateProcessInternalW","NtCreateThread","NtCreateThreadEx",
"URLDownloadToFileW","InternetOpenA","InternetConnectA","InternetConnectW","InternetOpenUrlA","HttpOpenRequestA","HttpOpenRequestW","HttpSendRequestA",
"HttpSendRequestW","InternetReadFile","DnsQuery_A","DnsQuery_W","GetAddrInfoW","WSAStartup","gethostbyname","socket","connect","send","sendto","recv","recvfrom",
"bind","WSARecv","WSARecvFrom","WSASend","WSASendTo","WSASocketW","FindResourceExW","FindResourceExA","QueryPerformanceCounter","NtDelayExecution","GetTickCount" };

/*{ "NtOpenKey","NtOpenKeyEx","NtQueryValueKey","NtCreateKey","NtEnumerateKey","NtEnumerateValueKey","NtCreateFile","NtQueryAttributesFile","NtDeviceIoControlFile","NtQueryVolumeInformationFile","NtQuerySystemInformation","NtQuerySystemInformationEx","NtPowerInformation","NtQueryLicenseValue","NtQueryDirectoryFile","NtQueryInformationProcess","NtQueryDirectoryObject","NtCreateMutant","NtOpenMutant","GetAdaptersAddresses",
"Process32FirstW","Process32NextW","CoCreateInstance","GetModuleHandleW","GetModuleHandleA","GetModuleHandleExW","GetModuleHandleExA","GetAdaptersInfo","SetupDiGetDeviceRegistryPropertyW","SetupDiGetDeviceRegistryPropertyA","GetLastInputInfo","EnumServicesStatusExA","EnumServicesStatusExW","InternetCheckConnectionA","GetWindowRect","GetMonitorInfoA","GetMonitorInfoW","FindWindowA","FindWindowW","FindWindowExA","FindWindowExW","GetCursorPos","GetSystemMetrics","SystemParametersInfoA","SystemParametersInfoW","GetAsyncKeyState","GetForegroundWindow",
"SEPARATOR","NtOpenFile","NtReadFile","NtWriteFile","NtDeleteFile","NtQueryInformationFile","NtSetInformationFile","NtOpenDirectoryObject","NtCreateDirectoryObject",
"NtCreateUserProcess","NtCreateProcess","NtCreateProcessEx","NtSuspendProcess","NtTerminateProcess","NtMapViewOfSection","NtUnmapViewOfSection","NtMakeTemporaryObject","NtMakePermanentObject","NtWriteVirtualMemory","NtSetInformationProcess","NtGetNextProcess","NtReplaceKey","NtRenameKey","NtSaveKey","NtSaveKeyEx","NtSetValueKey","NtDeleteKey","NtDeleteValueKey","NtOpenTimer","NtQueryTimer","NtCreateTimer","NtQuerySystemTime","NtOpenEvent","NtNotifyChangeKey","NtOpenSemaphore","NtCreateSemaphore","NtLockFile","GetSystemTime","GetLocalTime",
"CreateProcessInternalW","NtCreateThread","NtCreateThreadEx","URLDownloadToFileW","InternetOpenA","InternetConnectA","InternetConnectW","InternetOpenUrlA","HttpOpenRequestA","HttpOpenRequestW",
"HttpSendRequestA","HttpSendRequestW","InternetReadFile","DnsQuery_A","DnsQuery_W","GetAddrInfoW","WSAStartup","gethostbyname","socket","connect","send","sendto","recv","recvfrom","bind","WSARecv",
"WSARecvFrom","WSASend","WSASendTo","WSASocketW","FindResourceExW","FindResourceExA","QueryPerformanceCounter","NtDelayExecution","GetTickCount" };*/

// maybe introduce a principle of counts? 1st Openkey, 2st OpenKey? we can also count it on the mutator side
// for the mutations, we would need some decision on _which_ call to mutate.
// either by means of context, but by the call count also seems important (e.g. gettickcounts?)
// problem is that call orders can vary between executions... replay?
// for now: focus on mutations by context, not call count.
enum ContextType {
	CTX_NONE,
	CTX_STR,
	CTX_NUM,
	CTX_SUB // special case for preventive experiment
};

union ContextValue {
	// all considered contexts can be represented as a string or integer
	wchar_t szCtx[MAX_CTX_LEN];
	DWORD dwCtx;
};

struct Recording {
	Call call;
	ContextType type;
	ContextValue value;
	UINT64 origin;
};

enum MutationType {
	MUT_FAIL,		// call fails -- integer error code
	MUT_SUCCEED,	// call returns success
	MUT_ALT_STR,	// alternative result -- string value
	MUT_ALT_NUM,	// alternative result -- integer value
	MUT_ALT_TUP,	// alternative result -- tuple value
	MUT_HIDE,		// hide a value from a larger structure(context ? )
	MUT_RND_NUM,	// random result -- integer value (always random for repeated calls)
	MUT_RND_TUP		// random result -- tuple value (always random for repeated calls)
};

union MutationValue {
	wchar_t szValue[MAX_MUT_STR];
	int tupValue[2];
	DWORD nValue;
};

/*
Possible memory optimization:
> Separate mutations with string-based values or contexts from numeric/None types, so that these types don't hold unnecessary bytes.
*/

struct Mutation {
	// mutation
	MutationType mutType;
	MutationValue mutValue;

	// recording
	Recording rec;

	Mutation* next;
};

// calls without context can only hold 1 mutation per execution
struct MutationNoCtx {
	MutationType mutType;
	MutationValue mutValue;
};

