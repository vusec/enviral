#pragma once
#include "ntstructs.h"
#include <winsock2.h> // GetAdaptersAddresses
#include <iphlpapi.h> // GetAdaptersAddresses, GetAdaptersInfo
#include <tlhelp32.h> // Process32First/Next
#include <setupapi.h> // SetupDiGetDeviceRegistryPropertyW
#include <wininet.h> // InternetCheckConnection
#include <Urlmon.h> // URLDownloadToFile
#include <windns.h> // DnsQuery
#include <ws2tcpip.h> // getaddrinfo
#include <wbemcli.h> // ExecQuery

// link
#pragma warning(disable : 4996) // deprecated api
#pragma comment(lib, "Iphlpapi.lib") // GetAdaptersAddresses, GetAdaptersInfo
#pragma comment(lib, "Wininet.lib") // InternetCheckConnection
#pragma comment(lib, "Setupapi.lib") // SetupDiGetDeviceRegistryPropertyW
#pragma comment(lib, "Urlmon.lib") // URLDownloadToFile
#pragma comment(lib, "Dnsapi.lib") // DnsQuery
#pragma comment(lib, "Ws2_32.lib") // getaddrinfo

#define MAX_TRACE_DEPTH 200
#define VBOX_MAC (char*)"\x08\x00\x27" // test: (char*)"\x0a\x00\x27"

#define NT_HOOK(return_type, calling_convention, name, ...) \
	return_type calling_convention Hook##name(__VA_ARGS__); \
	typedef return_type(calling_convention* Proto##name)(__VA_ARGS__); \
	Proto##name Og##name

#define API_HOOK(return_type, calling_convention, name, ...) \
	return_type calling_convention Hook##name(__VA_ARGS__); \
	return_type (calling_convention* Og##name)(__VA_ARGS__) = name

Mutation* FindMutation(Mutation* start, ContextType ctxType , ContextValue* ctxValue);
wchar_t* GetKeyNameFromHandle(HANDLE key, PULONG size);

// ~~~~~~### Environment Calls ###~~~~~~
// NtOpenKey
NT_HOOK(NTSTATUS, NTAPI, NtOpenKey, OUT PHANDLE pKeyHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);

// NtOpenKeyEx
NT_HOOK(NTSTATUS, NTAPI, NtOpenKeyEx, OUT PHANDLE KeyHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG OpenOptions);

// NtQueryValueKey
NT_HOOK(NTSTATUS, NTAPI, NtQueryValueKey, IN HANDLE KeyHandle, IN PUNICODE_STRING ValueName, IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, OUT PVOID KeyValueInformation, IN ULONG Length, OUT PULONG ResultLength);

// NtCreateKey
NT_HOOK(NTSTATUS, NTAPI, NtCreateKey, OUT PHANDLE pKeyHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN ULONG TitleIndex, IN PUNICODE_STRING Class OPTIONAL, IN ULONG CreateOptions, OUT PULONG Disposition OPTIONAL);

// NtEnumerateKey
NT_HOOK(NTSTATUS, NTAPI, NtEnumerateKey, IN HANDLE KeyHandle, IN ULONG Index, IN KEY_INFORMATION_CLASS KeyInformationClass, OUT PVOID KeyInformation, IN ULONG Length, OUT PULONG ResultLength);

// NtEnumerateValueKey
NT_HOOK(NTSTATUS, NTAPI, NtEnumerateValueKey, IN HANDLE KeyHandle, IN ULONG Index, IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, OUT PVOID KeyValueInformation, IN ULONG Length, OUT PULONG ResultLength);

// NtQueryAttributesFile
NT_HOOK(NTSTATUS, NTAPI, NtQueryAttributesFile, IN POBJECT_ATTRIBUTES ObjectAttributes,	OUT PFILE_BASIC_INFORMATION FileAttributes);

// NtCreateFile
NT_HOOK(NTSTATUS, NTAPI, NtCreateFile, OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PLARGE_INTEGER AllocationSize OPTIONAL, IN ULONG FileAttributes, IN ULONG ShareAccess, IN ULONG CreateDisposition, IN ULONG CreateOptions, IN PVOID EaBuffer OPTIONAL, IN ULONG EaLength);

// NtDeviceIoControlFile
NT_HOOK(NTSTATUS, NTAPI, NtDeviceIoControlFile, IN HANDLE FileHandle, IN HANDLE Event OPTIONAL, IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG IoControlCode, IN PVOID InputBuffer OPTIONAL, IN ULONG InputBufferLength, OUT PVOID OutputBuffer OPTIONAL, IN ULONG OutputBufferLength);

// NtQueryVolumeInformationFile
NT_HOOK(NTSTATUS, NTAPI, NtQueryVolumeInformationFile, IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock,	OUT PVOID FileSystemInformation, IN ULONG Length, IN FS_INFORMATION_CLASS FileSystemInformationClass);

// NtQuerySystemInformation
NT_HOOK(NTSTATUS, NTAPI, NtQuerySystemInformation, IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation,	IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);

// NtQuerySystemInformationEx	
NT_HOOK(NTSTATUS, NTAPI, NtQuerySystemInformationEx, SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength,	PULONG ReturnLength);

// NtPowerInformation
NT_HOOK(NTSTATUS, NTAPI, NtPowerInformation, POWER_INFORMATION_LEVEL InformationLevel, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);

// NtQueryLicenseValue
NT_HOOK(NTSTATUS, NTAPI, NtQueryLicenseValue, PUNICODE_STRING ValueName, PULONG Type, PVOID Data, ULONG DataSize, PULONG ResultDataSize);

// NtQueryDirectoryFile
NT_HOOK(NTSTATUS, NTAPI, NtQueryDirectoryFile, IN HANDLE FileHandle, IN HANDLE Event OPTIONAL, IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID FileInformation, IN ULONG Length, IN FILE_INFORMATION_CLASS FileInformationClass, IN BOOLEAN ReturnSingleEntry, IN PUNICODE_STRING FileMask OPTIONAL,	IN BOOLEAN RestartScan);

// NtQueryInformationProcess
NT_HOOK(NTSTATUS, NTAPI, NtQueryInformationProcess, IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength);

// NtQueryDirectoryObject
NT_HOOK(NTSTATUS, NTAPI, NtQueryDirectoryObject, HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength);

// NtCreateMutant
NT_HOOK(NTSTATUS, NTAPI, NtCreateMutant, OUT PHANDLE MutantHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN BOOLEAN InitialOwner);

// NtOpenMutant
NT_HOOK(NTSTATUS, NTAPI, NtOpenMutant, OUT PHANDLE MutantHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);

// GetAdaptersAddresses
API_HOOK(ULONG, WINAPI, GetAdaptersAddresses, ULONG Family,	ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer);

// Process32First (Windows interference)
NT_HOOK(BOOL, WINAPI, Process32FirstW, HANDLE hSnapshot, LPPROCESSENTRY32W lppe);

// Process32Next (Windows interference)
NT_HOOK(BOOL, WINAPI, Process32NextW, HANDLE hSnapshot, LPPROCESSENTRY32W lppe);

// CoCreateInstance
API_HOOK(HRESULT, WINAPI, CoCreateInstance, REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv);

// CoCreateInstanceEx

// GetModuleHandleW
API_HOOK(HMODULE, WINAPI, GetModuleHandleW, LPCWSTR lpModuleName);

// GetModuleHandleA
API_HOOK(HMODULE, WINAPI, GetModuleHandleA, LPCSTR lpModuleName);

// GetModuleHandleEx	
API_HOOK(BOOL, WINAPI, GetModuleHandleExW, DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule);

// GetModuleHandleExA
API_HOOK(BOOL, WINAPI, GetModuleHandleExA, DWORD dwFlags, LPCSTR lpModuleName, HMODULE* phModule);

// GetAdaptersInfo
API_HOOK(ULONG, WINAPI, GetAdaptersInfo, PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer);

// SetupDiGetDeviceRegistryPropertyW
API_HOOK(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyW, HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize);

// SetupDiGetDeviceRegistryPropertyA
API_HOOK(BOOL, WINAPI, SetupDiGetDeviceRegistryPropertyA, HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize);

// GetLastInputInfo
API_HOOK(BOOL, WINAPI, GetLastInputInfo, PLASTINPUTINFO plii);

// EnumServicesStatusExA
API_HOOK(BOOL, WINAPI, EnumServicesStatusExA, SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName);

// EnumServicesStatusExW
API_HOOK(BOOL, WINAPI, EnumServicesStatusExW, SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName);

// InternetCheckConnectionA
API_HOOK(BOOL, WINAPI, InternetCheckConnectionA, LPCSTR lpszUrl, DWORD dwFlags, DWORD dwReserved);

// InternetCheckConnectionW
API_HOOK(BOOL, WINAPI, InternetCheckConnectionW, LPCWSTR lpszUrl, DWORD dwFlags, DWORD dwReserved);

// GetWindowRect
API_HOOK(BOOL, WINAPI, GetWindowRect, HWND hWnd, LPRECT lpRect);

// GetMonitorInfoA
API_HOOK(BOOL, WINAPI, GetMonitorInfoA, HMONITOR hMonitor, LPMONITORINFO lpmi);

// GetMonitorInfoW
API_HOOK(BOOL, WINAPI, GetMonitorInfoW, HMONITOR hMonitor, LPMONITORINFO lpmi);

// FindWindowA
API_HOOK(HWND, WINAPI, FindWindowA, LPCSTR lpClassName,	LPCSTR lpWindowName);

// FindWindowW
API_HOOK(HWND, WINAPI, FindWindowW, LPCWSTR lpClassName, LPCWSTR lpWindowName);

// FindWindowExA
API_HOOK(HWND, WINAPI, FindWindowExA, HWND hWndParent, HWND hWndChildAfter,	LPCSTR lpszClass, LPCSTR lpszWindow);

// FindWindowExW
API_HOOK(HWND, WINAPI, FindWindowExW, HWND hWndParent, HWND hWndChildAfter, LPCWSTR lpszClass, LPCWSTR lpszWindow);

// GetCursorPos
API_HOOK(BOOL, WINAPI, GetCursorPos, LPPOINT lpPoint);

// GetSystemMetrics
API_HOOK(int, WINAPI, GetSystemMetrics, int nIndex);

// SystemParametersInfoA
API_HOOK(BOOL, WINAPI, SystemParametersInfoA, UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni);

// SystemParametersInfoW
API_HOOK(BOOL, WINAPI, SystemParametersInfoW, UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni);

// GetAsyncKeyState
API_HOOK(SHORT, WINAPI, GetAsyncKeyState, int vKey);

// GetForegroundWindow
API_HOOK(HWND, WINAPI, GetForegroundWindow);

// LoadLibraryExW
API_HOOK(HMODULE, WINAPI, LoadLibraryExW, LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);

// LoadLibraryExA
API_HOOK(HMODULE, WINAPI, LoadLibraryExA, LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);

// LoadLibraryW
API_HOOK(HMODULE, WINAPI, LoadLibraryW, LPCWSTR lpLibFileName);

// LoadLibraryA
API_HOOK(HMODULE, WINAPI, LoadLibraryA, LPCSTR lpLibFileName);


// ~~~~~~### Activity Calls ###~~~~~~
// ~~ FILE ~~
// NtCreateFile, NtDeviceIoControlFile, NtDeviceIoControlFile, NtQueryDirectoryFile, NtQueryAttributesFile -> (ENV)

// NtOpenFile
NT_HOOK(NTSTATUS, NTAPI, NtOpenFile, OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock, IN ULONG ShareAccess, IN ULONG OpenOptions);

// NtReadFile
NT_HOOK(NTSTATUS, NTAPI, NtReadFile, IN HANDLE FileHandle, IN HANDLE Event OPTIONAL, IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID Buffer, IN ULONG Length, IN PLARGE_INTEGER ByteOffset OPTIONAL, IN PULONG Key OPTIONAL);

// NtWriteFile
NT_HOOK(NTSTATUS, NTAPI, NtWriteFile, IN HANDLE FileHandle, IN HANDLE Event OPTIONAL, IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PVOID Buffer, IN ULONG Length, IN PLARGE_INTEGER ByteOffset OPTIONAL, IN PULONG Key OPTIONAL);

// NtDeleteFile
NT_HOOK(NTSTATUS, NTAPI, NtDeleteFile, IN POBJECT_ATTRIBUTES ObjectAttributes);

// NtQueryInformationFile
NT_HOOK(NTSTATUS, NTAPI, NtQueryInformationFile, IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock, OUT PVOID FileInformation, IN ULONG Length, IN FILE_INFORMATION_CLASS FileInformationClass);

// NtSetInformationFile
NT_HOOK(NTSTATUS, NTAPI, NtSetInformationFile, IN HANDLE FileHandle, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PVOID FileInformation, IN ULONG Length, IN FILE_INFORMATION_CLASS FileInformationClass);

// NtOpenDirectoryObject
NT_HOOK(NTSTATUS, NTAPI, NtOpenDirectoryObject, OUT PHANDLE DirectoryObjectHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);

// NtCreateDirectoryObject
NT_HOOK(NTSTATUS, NTAPI, NtCreateDirectoryObject, OUT PHANDLE DirectoryHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);


// ~~ PROCESS ~~
// NtQueryInformationProcess, NtQuerySystemInformation -> (ENV)

// NtCreateUserProcess
NT_HOOK(NTSTATUS, NTAPI, NtCreateUserProcess, OUT PHANDLE ProcessHandle, OUT PHANDLE ThreadHandle, IN ACCESS_MASK ProcessDesiredAccess, IN ACCESS_MASK ThreadDesiredAccess, IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL, IN POBJECT_ATTRIBUTES ThreadObjectAttributes, IN ULONG ProcessFlags, IN ULONG ThreadFlags, IN PVOID ProcessParameters, PPS_CREATE_INFO CreateInfo, IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

// NtCreateProcess
NT_HOOK(NTSTATUS, NTAPI, NtCreateProcess, OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ParentProcess, IN BOOLEAN InheritObjectTable, IN HANDLE SectionHandle OPTIONAL, IN HANDLE DebugPort OPTIONAL, IN HANDLE ExceptionPort OPTIONAL);

// NtCreateProcessEx
NT_HOOK(NTSTATUS, NTAPI, NtCreateProcessEx, PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel);

// NtSuspendProcess
NT_HOOK(NTSTATUS, NTAPI, NtSuspendProcess, HANDLE ProcessHandle);

// NtTerminateProcess
NT_HOOK(NTSTATUS, NTAPI, NtTerminateProcess, IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus);

// NtMapViewOfSection
NT_HOOK(NTSTATUS, NTAPI, NtMapViewOfSection, IN HANDLE SectionHandle, IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress OPTIONAL, IN ULONG ZeroBits OPTIONAL,	IN ULONG CommitSize, IN OUT PLARGE_INTEGER SectionOffset OPTIONAL, IN OUT PULONG ViewSize, IN SECTION_INHERIT InheritDisposition, IN ULONG AllocationType OPTIONAL, IN ULONG Protect);

// NtUnmapViewOfSection
NT_HOOK(NTSTATUS, NTAPI, NtUnmapViewOfSection, IN HANDLE ProcessHandle, IN PVOID BaseAddress);

// NtMakeTemporaryObject
NT_HOOK(NTSTATUS, NTAPI, NtMakeTemporaryObject, IN HANDLE ObjectHandle);

// NtMakePermanentObject
NT_HOOK(NTSTATUS, NTAPI, NtMakePermanentObject, HANDLE Handle);

// NtWriteVirtualMemory
NT_HOOK(NTSTATUS, NTAPI, NtWriteVirtualMemory, IN HANDLE ProcessHandle, IN PVOID BaseAddress, IN PVOID Buffer, IN ULONG NumberOfBytesToWrite, OUT PULONG NumberOfBytesWritten OPTIONAL);

// NtSetInformationProcess
NT_HOOK(NTSTATUS, NTAPI, NtSetInformationProcess, IN HANDLE ProcessHandle, IN PROCESS_INFORMATION_CLASS ProcessInformationClass, IN PVOID ProcessInformation, IN ULONG ProcessInformationLength);

// NtGetNextProcess
NT_HOOK(NTSTATUS, NTAPI, NtGetNextProcess, HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);


// ~~ REGISTRY ~~
// NtCreateKey -> (ENV)

// NtReplaceKey
NT_HOOK(NTSTATUS, NTAPI, NtReplaceKey, IN POBJECT_ATTRIBUTES NewHiveFileName, IN HANDLE KeyHandle, IN POBJECT_ATTRIBUTES BackupHiveFileName);

// NtRenameKey
NT_HOOK(NTSTATUS, NTAPI, NtRenameKey, HANDLE KeyHandle, PUNICODE_STRING NewName);

// NtSaveKey
NT_HOOK(NTSTATUS, NTAPI, NtSaveKey, IN HANDLE KeyHandle, IN HANDLE FileHandle);

// NtSaveKeyEx
NT_HOOK(NTSTATUS, NTAPI, NtSaveKeyEx, HANDLE KeyHandle, HANDLE FileHandle, ULONG Format);

// NtSetValueKey
NT_HOOK(NTSTATUS, NTAPI, NtSetValueKey, IN HANDLE KeyHandle, IN PUNICODE_STRING ValueName, IN ULONG TitleIndex OPTIONAL, IN ULONG Type, IN PVOID Data, IN ULONG DataSize);

// NtDeleteKey
NT_HOOK(NTSTATUS, NTAPI, NtDeleteKey, IN HANDLE KeyHandle);

// NtDeleteValueKey
NT_HOOK(NTSTATUS, NTAPI, NtDeleteValueKey, IN HANDLE KeyHandle, IN PUNICODE_STRING ValueName);

// ~~ TIME ~~
// NtOpenTimer
NT_HOOK(NTSTATUS, NTAPI, NtOpenTimer, OUT PHANDLE TimerHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);

// NtQueryTimer
NT_HOOK(NTSTATUS, NTAPI, NtQueryTimer, IN HANDLE TimerHandle, IN TIMER_INFORMATION_CLASS TimerInformationClass, OUT PVOID TimerInformation, IN ULONG TimerInformationLength, OUT PULONG ReturnLength OPTIONAL);

// NtCreateTimer
NT_HOOK(NTSTATUS, NTAPI, NtCreateTimer, OUT PHANDLE TimerHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN TIMER_TYPE TimerType);

// NtQuerySystemTime
NT_HOOK(NTSTATUS, NTAPI, NtQuerySystemTime, OUT PLARGE_INTEGER SystemTime);

// ~~ MISC ~~
// NtOpenMutant, NtCreateMutant -> (ENV)

// NtOpenEvent
NT_HOOK(NTSTATUS, NTAPI, NtOpenEvent, OUT PHANDLE EventHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);

// NtNotifyChangeKey
NT_HOOK(NTSTATUS, NTAPI, NtNotifyChangeKey, IN HANDLE KeyHandle, IN HANDLE EventHandle, IN PIO_APC_ROUTINE ApcRoutine, IN PVOID ApcRoutineContext, IN PIO_STATUS_BLOCK IoStatusBlock, IN ULONG NotifyFilter, IN BOOLEAN WatchSubtree, OUT PVOID RegChangesDataBuffer, IN ULONG RegChangesDataBufferLength, IN BOOLEAN Asynchronous);

// NtOpenSemaphore
NT_HOOK(NTSTATUS, NTAPI, NtOpenSemaphore, OUT PHANDLE SemaphoreHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes);

// NtCreateSemaphore
NT_HOOK(NTSTATUS, NTAPI, NtCreateSemaphore, OUT PHANDLE SemaphoreHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN ULONG InitialCount, IN ULONG MaximumCount);

// NtLockFile
NT_HOOK(NTSTATUS, NTAPI, NtLockFile, IN HANDLE FileHandle,  IN HANDLE LockGrantedEvent OPTIONAL, IN PIO_APC_ROUTINE ApcRoutine OPTIONAL, IN PVOID ApcContext OPTIONAL, OUT PIO_STATUS_BLOCK IoStatusBlock, IN PLARGE_INTEGER ByteOffset, IN PLARGE_INTEGER Length, IN PULONG Key, IN BOOLEAN ReturnImmediately, IN BOOLEAN ExclusiveLock);

// GetSystemTime
API_HOOK(void, WINAPI, GetSystemTime, LPSYSTEMTIME lpSystemTime);

// GetLocalTime
API_HOOK(void, WINAPI, GetLocalTime, LPSYSTEMTIME lpSystemTime);


// ~~ NETWORK & SOCKET ~~
// UrlDownloadToFileA calls UrlDownloadToFileW
API_HOOK(HRESULT, WINAPI, URLDownloadToFileW, LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB);
// InternetOpenW calls InternetOpenA
API_HOOK(HINTERNET, WINAPI, InternetOpenA, LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
API_HOOK(HINTERNET, WINAPI, InternetConnectA, HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
API_HOOK(HINTERNET, WINAPI, InternetConnectW, HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
// InternetOpenUrlW calls InternetOpenUrlA
API_HOOK(HINTERNET, WINAPI, InternetOpenUrlA, HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext);
API_HOOK(HINTERNET, WINAPI, HttpOpenRequestA, HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
API_HOOK(HINTERNET, WINAPI, HttpOpenRequestW, HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
API_HOOK(BOOL, WINAPI, HttpSendRequestA, HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
API_HOOK(BOOL, WINAPI, HttpSendRequestW, HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
API_HOOK(BOOL, WINAPI, InternetReadFile, HINTERNET hFile, LPVOID lpBuffersOut, DWORD dwFlags, LPDWORD dwContext);
API_HOOK(DNS_STATUS, WINAPI, DnsQuery_A, PCSTR pszName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved);
API_HOOK(DNS_STATUS, WINAPI, DnsQuery_W, PCWSTR pszName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved);
// getaddrinfo calls GetAddrInfoW
API_HOOK(INT, WSAAPI, GetAddrInfoW, PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints, PADDRINFOW* ppResult);
// - Socket
API_HOOK(int, WINAPI, WSAStartup, WORD wVersionRequired, LPWSADATA lpWSAData);
API_HOOK(hostent*, WINAPI, gethostbyname, const char* name);
API_HOOK(SOCKET, WSAAPI, socket, int af, int type, int protocol);
API_HOOK(int, WSAAPI, connect, SOCKET s, const sockaddr* name, int namelen);
API_HOOK(int, WSAAPI, send, SOCKET s, const char* buf, int len, int flags);
API_HOOK(int, WSAAPI, sendto, SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen);
API_HOOK(int, WINAPI, recv, SOCKET s, char* buf, int len, int flags);
API_HOOK(int, WINAPI, recvfrom, SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen);
API_HOOK(int, WINAPI, bind, SOCKET s, const sockaddr* addr, int namelen);
API_HOOK(int, WSAAPI, WSARecv, SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
API_HOOK(int, WSAAPI, WSARecvFrom, SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
API_HOOK(int, WSAAPI, WSASend, SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
API_HOOK(int, WSAAPI, WSASendTo, SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const sockaddr* lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
// WSASocketA calls WSASocketW
API_HOOK(SOCKET, WSAAPI, WSASocketW, int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags);

// FindResourceEx (FindResource is contained in Ex)
API_HOOK(HRSRC, WINAPI, FindResourceExW, HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage);
API_HOOK(HRSRC, WINAPI, FindResourceExA, HMODULE hModule, LPCSTR lpType, LPCSTR lpName, WORD wLanguage);


// ~~~~~~### Management Calls ###~~~~~~
// CreateProcessA & CreateProcessW & CreateProcessInternalA -> CreateProcessInternalW
NT_HOOK(BOOL, WINAPI, CreateProcessInternalW, IN HANDLE hUserToken, IN LPCWSTR lpApplicationName, IN LPWSTR lpCommandLine, IN LPSECURITY_ATTRIBUTES lpProcessAttributes, IN LPSECURITY_ATTRIBUTES lpThreadAttributes, IN BOOL bInheritHandles, IN DWORD dwCreationFlags, IN LPVOID lpEnvironment, IN LPCWSTR lpCurrentDirectory, IN LPSTARTUPINFOW lpStartupInfo, IN LPPROCESS_INFORMATION lpProcessInformation, OUT PHANDLE hNewToken);

// NtDelayExecution (Sleep)
NT_HOOK(NTSTATUS, NTAPI, NtDelayExecution, BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

// QueryPerformanceCounter
API_HOOK(BOOL, WINAPI, QueryPerformanceCounter, LARGE_INTEGER* lpPerformanceCount);

// GetTickCount
API_HOOK(DWORD, WINAPI, GetTickCount);


// util: NtQueryKey
typedef NTSTATUS(NTAPI* ProtoNtQueryKey)(HANDLE KeyHandle, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
ProtoNtQueryKey NtQueryKey;

// threads (NtCreateThreadEx includes Win32 CreateRemoteThread)
NT_HOOK(NTSTATUS, NTAPI, NtCreateThread, OUT PHANDLE ThreadHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN HANDLE ProcessHandle, OUT PCLIENT_ID ClientId, IN PCONTEXT ThreadContext, IN PINITIAL_TEB InitialTeb,	IN BOOLEAN CreateSuspended);
NT_HOOK(NTSTATUS, NTAPI, NtCreateThreadEx, PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);