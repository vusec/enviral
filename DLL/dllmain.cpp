// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include "detours.h"
#include <WinNT.h>
#include <Windows.h>
#include <winternl.h> // ntstatus, pio_status_block
#include <stdlib.h> // malloc
#include "communication.h"
#include "syscalls.h"
//#include <intrin.h> // ReturnAddress

// https://github.com/nybble04/Shady-Hook   (Microsoft Detours example)
// https://github.com/microsoft/Detours     (Source)
// https://resources.infosecinstitute.com/topic/api-hooking-detours/    (Include Detours in VS2019)
// https://github.com/BinaryAdventure/NotepadHook/blob/master/Notepad_Hook/Notepad_Hook.cpp     (Native API hooking stuff)

// open detours root dir in vs2019 developer command prompt and run 'nmake'
// I had to add "C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Bin\NETFX 4.0 Tools\" to PATH for sn.exe
// add "C:\Users\floris\Desktop\thesis\Detours\include" to include directories
// add "C:\Users\floris\Desktop\thesis\Detours\lib.X86" to linker libraries 

//#define TARGET_DLL "C:\\Users\\floris\\source\\repos\\EnviradllWarmachine\\Release\\EnviralDLL.dll"

// VM
#define TARGET_DLL "C:\\Users\\Lisa\\Documents\\ph1\\EnviralDLL.dll"

//#define __32BIT_SYS // vm

#pragma comment(lib, "detours.lib")
//#pragma intrinsic(_ReturnAddress)

// detours supposedly needs the injected DLL to export at least one function
/*
extern "C" __declspec(dllexport) void dummy(void) {
	return;
}
*/
HANDLE hPipe;
static DWORD dwTlsIndex;

// thread local storage would result in inconsistent views of ticks between threads
volatile ULONG TimeShift = 0; 
double dFreq = 1;

BYTE* TargetBase = NULL;
BYTE* TargetEnd = NULL;

Mutation* mutNtOpenKey = NULL;
Mutation* mutNtOpenKeyEx = NULL;
Mutation* mutNtQueryValueKey = NULL;
Mutation* mutNtCreateKey = NULL;
Mutation* mutNtEnumerateKey = NULL;
Mutation* mutNtEnumerateValueKey = NULL;
Mutation* mutNtCreateFile = NULL;
Mutation* mutNtQueryAttributesFile = NULL;
Mutation* mutNtDeviceIoControlFile = NULL;
Mutation* mutNtQueryVolumeInformationFile = NULL;
Mutation* mutNtQuerySystemInformation = NULL;
Mutation* mutNtQuerySystemInformationEx = NULL;
MutationNoCtx* mutNtPowerInformation = NULL;
Mutation* mutNtQueryLicenseValue = NULL;
Mutation* mutNtQueryDirectoryFile = NULL;
Mutation* mutNtQueryInformationProcess = NULL;
Mutation* mutNtQueryDirectoryObject = NULL;
Mutation* mutNtCreateMutant = NULL;
Mutation* mutNtOpenMutant = NULL;
MutationNoCtx* mutGetAdaptersAddresses = NULL;
MutationNoCtx* mutProcess32FirstW = NULL;
MutationNoCtx* mutProcess32NextW = NULL;
MutationNoCtx* mutCoCreateInstance = NULL;
//Mutation* mutGetModuleHandleW = NULL;
//Mutation* mutGetModuleHandleA = NULL;
//Mutation* mutGetModuleHandleExW = NULL;
//Mutation* mutGetModuleHandleExA = NULL;
MutationNoCtx* mutGetAdaptersInfo = NULL;
MutationNoCtx* mutSetupDiGetDeviceRegistryPropertyW = NULL;
MutationNoCtx* mutSetupDiGetDeviceRegistryPropertyA = NULL;
MutationNoCtx* mutGetLastInputInfo = NULL;
MutationNoCtx* mutEnumServicesStatusExA = NULL;
MutationNoCtx* mutEnumServicesStatusExW = NULL;
MutationNoCtx* mutInternetCheckConnectionA = NULL;
MutationNoCtx* mutInternetCheckConnectionW = NULL;
MutationNoCtx* mutGetWindowRect = NULL;
MutationNoCtx* mutGetMonitorInfoA = NULL;
MutationNoCtx* mutGetMonitorInfoW = NULL;
Mutation* mutFindWindowA = NULL;
Mutation* mutFindWindowW = NULL;
Mutation* mutFindWindowExA = NULL;
Mutation* mutFindWindowExW = NULL;
MutationNoCtx* mutGetCursorPos = NULL;
//Mutation* mutGetSystemMetrics = NULL;
//Mutation* mutSystemParametersInfoA = NULL;
//Mutation* mutSystemParametersInfoW = NULL;
MutationNoCtx* mutGetAsyncKeyState = NULL;
MutationNoCtx* mutGetForegroundWindow = NULL;
Mutation* mutLoadLibraryExW = NULL;
Mutation* mutLoadLibraryExA = NULL;
Mutation* mutLoadLibraryW = NULL;
Mutation* mutLoadLibraryA = NULL;

// chld
LPVOID pLoadLibraryA = NULL;

/*
We _enter_ hooks (flag) on calls that may process mutations.
The modification of the mutation may not affect the indirect activity of the call itself!
Hence, we only set the flag for possible mutations.
Even if a mutation is not applied, it may applied in the next execution.
Therefore we set the flag if a mutation _may_ be applied, s.t. the activity is equalized.
*/

BOOL SkipActivity(UINT64* Hash)
{
	BOOL* flag;
	flag = (BOOL*)TlsGetValue(dwTlsIndex);
	if (flag == NULL) {
		// TLS not created yet for this thread
		return FALSE;
	}

	if (*flag == TRUE) {
		// we are already in a hook.
		// no sub-activity will be recorded.
		// no need to calculate hash.
		return TRUE;
	}
	else {
		// we are not in a hook
		// but we may originate from a new worker thread
		// stack trace will confirm our origin
		// Quote from Microsoft Documentation: You can capture up to MAXUSHORT frames (65534).

		BOOL allforeign = TRUE;
		PVOID trace[MAX_TRACE_DEPTH];
		(*Hash) = 0; // init
		WORD cap = RtlCaptureStackBackTrace(1, MAX_TRACE_DEPTH, trace, NULL); // no hash
		for (WORD i = 0; i < cap; i++) {
			if (trace[i] >= TargetBase && trace[i] <= TargetEnd) {
				(*Hash) += (UINT32)trace[i];
				allforeign = FALSE;
			}
		}
		return allforeign; // skip unless the backtrace validates domestic

		/* // old: hash of win32 -> move to more selective domestic hash
		PVOID trace[MAX_TRACE_DEPTH];
		WORD cap = RtlCaptureStackBackTrace(1, MAX_TRACE_DEPTH, trace, Hash); // skip the current frame
		for (WORD i = 0; i < cap; i++) {
			if (trace[i] >= TargetBase && trace[i] <= TargetEnd) {
				// the trace originates from the target application
				// valid origin located
				// do not skip activity
				return FALSE;
			}
		}
		return TRUE; // skip unless the backtrace validates
		*/
	}

	return FALSE;
}

BOOL* EnterHook()
{
	BOOL* flag;
	flag = (BOOL*)TlsGetValue(dwTlsIndex);
	if (flag == NULL) {
		// make sure the TLS value exists
		flag = (BOOL*)LocalAlloc(LPTR, sizeof(BOOL));
		if (flag == NULL)
			return NULL;
		if (!TlsSetValue(dwTlsIndex, flag))
			return NULL;
	}
	*flag = TRUE;
	return flag;
}

int GetKeyNameFromHandle(HANDLE key, wchar_t* dest, PULONG size)
{
	if (key == NULL) {
		return 0;
	}

	PKEY_NAME_INFORMATION buf = (PKEY_NAME_INFORMATION)malloc(528); // KEY_NAME_INFORMATION (8) + MAX_PATH (260) * WCHAR (2) 
	if (buf == NULL) {
		return 0;
	}

	ULONG retlen;
	NTSTATUS status;

	status = NtQueryKey(key, KeyNameInformation, buf, 528, &retlen);
	if (NT_SUCCESS(status)) {
		// buf->Name is NOT null terminated
		size_t widec = buf->NameLength / sizeof(wchar_t);
		if (widec + 1 < MAX_CTX_LEN) {
			memcpy(dest, buf->Name, widec * sizeof(wchar_t));
			dest[widec] = L'\0';
		}
		else {
			widec = MAX_CTX_LEN - 1;
			memcpy(dest, buf->Name, widec * sizeof(wchar_t));
			dest[widec] = L'\0';
		}
		*size = widec;
		free(buf);
		return 1;
	}

	return 0;
}

int GetFileNameFromHandle(HANDLE file, wchar_t* dest, PULONG size)
{
	NTSTATUS status;
	IO_STATUS_BLOCK ioStatusBlock = { 0 };
	PFILE_NAME_INFORMATION buf;
	size_t nameInfoLen = sizeof(FILE_NAME_INFORMATION) + (350 * sizeof(WCHAR));

	if (file == NULL) {
		return 0;
	}

	buf = (PFILE_NAME_INFORMATION)malloc(nameInfoLen);
	if (buf == NULL) {
		return 0;
	}

	status = OgNtQueryInformationFile(file, &ioStatusBlock, buf, nameInfoLen, (FILE_INFORMATION_CLASS)9); // FileNameInformation
	if (NT_SUCCESS(status)) {
		size_t widec = buf->FileNameLength / sizeof(wchar_t);
		if (widec + 1 < MAX_CTX_LEN) {
			memcpy(dest, buf->FileName, widec * sizeof(wchar_t));
			dest[widec] = L'\0';
		}
		else {
			widec = MAX_CTX_LEN - 1;
			memcpy(dest, buf->FileName, widec * sizeof(wchar_t));
			dest[widec] = L'\0';
		}
		*size = widec;
		free(buf);
		return 1;
	}

	return 0;
}


int RecordCall(Call c, ContextType type, ContextValue* value, UINT64 hash) {
	Recording rec;
	rec.call = c;
	rec.type = type;

	if (type != CTX_NONE && value != NULL) {
		rec.value = *value;
	}

	rec.origin = hash;

	DWORD dwWritten;
	WriteFile(hPipe, (void*)&rec, sizeof(rec), &dwWritten, NULL);
	return 1;
}
/*
IMPORTANT TO NOTE:
For a specific call, it should be the case that there is only ONE mutation available,
unless the mutations rely on a specific context, then there may be multiple.
Hence, for calls that do not rely on a context, only a single mutation can be found.
i.e., we do not need to match the mutation type, as there would be only one,
and otherwise the context would have to be provided, and there would only be one mutation (type) for that specific context.

Therefore, for a mutation without context, there is no need to search.
The list should only be able to have length 0 or 1.
*/



// find a mutation in the list for a specific call, starting from a specific start point
Mutation* FindMutation(Mutation* start, ContextType ctxType, ContextValue* ctxValue)
{
	// we need to match the context to find whether there is a mutation.
	// the context is found in the call hook, and then sent here, we loop through the mutations to match.
	// should be max one full walk of the list.

	// we need to know the context type s.t. we can compare the right type (num/str)

	// TODO: if Recording CTX == "*", any context match will do.
	// are there any calls that can have both NUM & STR context? Currently not considered!
	// ^ only findresource() does this but it is not mutated.

	Mutation* loop = start;
	if (ctxType == CTX_NUM) {
		while (loop != NULL) {
			if (loop->rec.value.dwCtx == ctxValue->dwCtx) {
				// context match
				return loop;
			}
			loop = loop->next;
		}
	}
	else if (ctxType == CTX_STR) {
		/* experiment stage: preventive substring mutations */
		// the call ID are already matched through the per-call Mutation lists
		// if the recording CTX is substring, is it artificially created, and should match substring.
		while (loop != NULL) {
			if (loop->rec.type == CTX_SUB) {
				// assumes substring target ctx is lower case !
				if (wcsstr(_wcslwr(ctxValue->szCtx), loop->rec.value.szCtx) != NULL) { // is target a substring of ctx?
					// context match
					return loop;
				}
			}
			else { // CTX_STR
				if (wcsncmp(loop->rec.value.szCtx, ctxValue->szCtx, MAX_CTX_LEN) == 0) {
					// context match
					return loop;
				}
			}
			loop = loop->next;
		}
	}

	return NULL;
}


// Environment Query Hooks
NTSTATUS NTAPI HookNtOpenKey(PHANDLE pKeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (STATUS_OBJECT_NAME_NOT_FOUND)

	BOOL* flag = NULL;
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;

			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cNtOpenKey, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutNtOpenKey, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_FAIL mutation to NtOpenKey.\n");
#endif
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtOpenKey(pKeyHandle, DesiredAccess, ObjectAttributes);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtOpenKeyEx(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG OpenOptions)
{
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (STATUS_OBJECT_NAME_NOT_FOUND)

	BOOL* flag = NULL;
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;

			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cNtOpenKeyEx, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutNtOpenKeyEx, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_FAIL mutation to NtOpenKeyEx.\n");
#endif
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtOpenKeyEx(KeyHandle, DesiredAccess, ObjectAttributes, OpenOptions);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
	// MUT_TEST #2
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (value not found: STATUS_OBJECT_NAME_NOT_FOUND) or MUT_ALT_STR

	// Context ValueName:Value
	BOOL* flag = NULL;
	if (ValueName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = ValueName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN - 30) {
				widec = MAX_CTX_LEN - 30; // save some space for data
			}
			wcsncpy(ctxVal.szCtx, ValueName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';

			if (KeyValueInformationClass == KeyValuePartialInformation) { // default from Win32 API
				ret = OgNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
				if (NT_SUCCESS(ret)) {
					PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation;
					if (info != NULL) {
						// DataLength: size of Data in bytes.
						size_t widerem = MAX_CTX_LEN - 1 - widec; // this can be 0
						size_t wreq = wcslen(info->Data);
						if (wreq + 2 >= widerem) { // more chars needed than remaining
							wcscat(ctxVal.szCtx, L":");
							wcsncat(ctxVal.szCtx, info->Data, widerem - 2);
						}
						else {
							wcscat(ctxVal.szCtx, L":");
							wcscat(ctxVal.szCtx, info->Data);
						}

						RecordCall(Call::cNtQueryValueKey, CTX_STR, &ctxVal, Hash);

						Mutation* mut = FindMutation(mutNtQueryValueKey, CTX_STR, &ctxVal);
						if (mut != NULL) {
							if (mut->mutType == MUT_FAIL) {
								// return error code
								KeyValueInformation = NULL;
								ResultLength = 0;
								if (flag) (*flag) = FALSE;
								return (NTSTATUS)mut->mutValue.nValue;
							}
							else if (mut->mutType == MUT_ALT_STR) {
								size_t lenMut = wcslen(mut->mutValue.szValue);
								if (lenMut * 2 + 2 > info->DataLength) {
									// max datalen
									ULONG LastIndex = ((info->DataLength - 1) / 2);
									memcpy(info->Data, mut->mutValue.szValue, LastIndex * sizeof(wchar_t));
									info->Data[LastIndex] = L'\0';
								}
								else {
									// fits
									memcpy(info->Data, mut->mutValue.szValue, (lenMut + 1) * sizeof(wchar_t));
								}
							}
						}

					}
				}
				if (flag) (*flag) = FALSE;
				return ret;
			} // include other cases for direct NT calls
		}
	}

	ret = OgNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtCreateKey(PHANDLE pKeyHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG TitleIndex, PUNICODE_STRING Class, ULONG CreateOptions, PULONG Disposition)
{
	//SIMPLE_LOG(NTSTATUS, NtCreateKey, pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition)
	NTSTATUS ret;
	// Mutation types: MUT_ALT_NUM (disposition 1, indicating new key was created, while 2 opens an existing key)
	BOOL* flag = NULL;
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();



			ContextValue ctxVal;
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';

			RecordCall(Call::cNtCreateKey, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutNtCreateKey, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_ALT_NUM && Disposition != NULL) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_ALT_NUM mutation to NtCreateKey.\n");
#endif
					ret = OgNtCreateKey(pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
					if (NT_SUCCESS(ret)) {
						*Disposition = (ULONG)mut->mutValue.nValue;
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}

	ret = OgNtCreateKey(pKeyHandle, DesiredAccess, ObjectAttributes, TitleIndex, Class, CreateOptions, Disposition);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtEnumerateKey(HANDLE KeyHandle, ULONG Index, KEY_INFORMATION_CLASS KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength)
{
	//	SIMPLE_LOG(NTSTATUS, NtEnumerateKey, KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength)
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (STATUS_NO_MORE_ENTRIES?), MUT_ALT_STR

	BOOL* flag = NULL;
	ULONG NameSize;
	ContextValue ctxVal;
	if (GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
		if (KeyInformationClass == KeyBasicInformation) {
			UINT64 Hash;
			if (!SkipActivity(&Hash)) {
				flag = EnterHook();
				ret = OgNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
				if (NT_SUCCESS(ret)) {
					PKEY_BASIC_INFORMATION pkey = (PKEY_BASIC_INFORMATION)KeyInformation;
					if (pkey != NULL) {
						// Name is NOT null terminated...
						ULONG OgLenW = pkey->NameLength / 2;

						// Record
						wcscat(ctxVal.szCtx, L":");
						size_t curLen = NameSize + 1; // :
						size_t copylen = pkey->NameLength;
						if (curLen + (OgLenW) >= MAX_CTX_LEN) { // bounds
							copylen = (MAX_CTX_LEN - 1 - curLen) * 2;
						}
						memcpy(&ctxVal.szCtx[curLen], pkey->Name, copylen);
						ctxVal.szCtx[curLen + (copylen / 2)] = L'\0';
						RecordCall(Call::cNtEnumerateKey, CTX_STR, &ctxVal, Hash);

						// Mutations
						Mutation* mut = FindMutation(mutNtEnumerateKey, CTX_STR, &ctxVal);
						if (mut != NULL) {
							if (mut->mutType == MUT_FAIL) {
								KeyInformation = NULL;
								ResultLength = 0;
								if (flag) (*flag) = FALSE;
								return (NTSTATUS)mut->mutValue.nValue;
							}
							else if (mut->mutType == MUT_ALT_STR) {
								size_t lenMut = wcslen(mut->mutValue.szValue);
								if (lenMut <= OgLenW) {
									// fits
									memcpy(pkey->Name, mut->mutValue.szValue, lenMut * sizeof(wchar_t));
									pkey->NameLength = lenMut * 2;
								}
								else {
									// max
									memcpy(pkey->Name, mut->mutValue.szValue, pkey->NameLength);
								}
							}
						}
					}
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
		}
		// TODO: handle other classes for direct NT calls
	}

	ret = OgNtEnumerateKey(KeyHandle, Index, KeyInformationClass, KeyInformation, Length, ResultLength);
	// flag cannot be set here
	return ret;
}

NTSTATUS NTAPI HookNtEnumerateValueKey(HANDLE KeyHandle, ULONG Index, KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
	//	SIMPLE_LOG(NTSTATUS, NtEnumerateValueKey, KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength)
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (STATUS_NO_MORE_ENTRIES), MUT_ALT_STR
	BOOL* flag = NULL;
	if (KeyValueInformationClass == KeyValueFullInformation) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ret = OgNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
			if (NT_SUCCESS(ret)) {
				PKEY_VALUE_FULL_INFORMATION pvalue = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformation;
				if (pvalue != NULL) {
					if (pvalue->Type == REG_MULTI_SZ || pvalue->Type == REG_SZ || pvalue->Type == REG_EXPAND_SZ) { // string
						wchar_t* data = (wchar_t*)((BYTE*)KeyValueInformation + pvalue->DataOffset);
						ContextValue ctxVal;

						size_t widec = pvalue->NameLength / sizeof(wchar_t);
						if (widec >= MAX_CTX_LEN - 30) {
							widec = MAX_CTX_LEN - 30; // make space
						}
						memcpy(&ctxVal.szCtx, pvalue->Name, widec * sizeof(wchar_t));
						ctxVal.szCtx[widec] = L'\0';
						size_t wreq = wcslen(data);
						size_t widerem = MAX_CTX_LEN - 1 - widec;
						if (wreq + 2 >= widerem) {
							wcscat(ctxVal.szCtx, L":");
							wcsncat(ctxVal.szCtx, data, widerem - 2);
						}
						else {
							wcscat(ctxVal.szCtx, L":");
							wcscat(ctxVal.szCtx, data);
						}

						RecordCall(Call::cNtEnumerateValueKey, CTX_STR, &ctxVal, Hash);

						Mutation* mut = FindMutation(mutNtEnumerateValueKey, CTX_STR, &ctxVal);
						if (mut != NULL) {
							if (mut->mutType == MUT_FAIL) {
#ifdef __DEBUG_PRINT
								printf("Applying MUT_FAIL mutation to NtEnumerateValueKey.\n");
#endif
								KeyValueInformation = NULL;
								ResultLength = 0;
								if (flag) (*flag) = FALSE;
								return (NTSTATUS)mut->mutValue.nValue;
							}
							else if (mut->mutType == MUT_ALT_STR) {
#ifdef __DEBUG_PRINT
								printf("Applying MUT_ALT_STR mutation to NtEnumerateValueKey.\n");
#endif
								size_t lenMut = wcslen(mut->mutValue.szValue);
								size_t avail = pvalue->DataLength - pvalue->NameLength; // bytes

								if (lenMut * 2 + 2 <= avail) {
									memcpy(data, mut->mutValue.szValue, (lenMut + 1) * sizeof(wchar_t));
								}
								else {
									// limit avail bytes
									ULONG index = (avail / 2);
									memcpy(data, mut->mutValue.szValue, (index - 1) * sizeof(wchar_t));
									data[index - 1] = L'\0';
								}
							}
						}
					}
				}
			}
			if (flag) (*flag) = FALSE;
			return ret;
		}
	}
	// consider adding other cases for direct NT call completeness

	ret = OgNtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
	// flag cannot be set here
	return ret;
}

NTSTATUS NTAPI HookNtQueryAttributesFile(POBJECT_ATTRIBUTES ObjectAttributes, PFILE_BASIC_INFORMATION FileAttributes)
{
	// MUT_TEST #3
	//	SIMPLE_LOG(NTSTATUS, NtQueryAttributesFile, ObjectAttributes, FileAttributes)
	NTSTATUS ret;

	// Mutation types: MUT_FAIL (STATUS_OBJECT_NAME_NOT_FOUND)
	BOOL* flag = NULL;
	// record the call
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';

			RecordCall(Call::cNtQueryAttributesFile, CTX_STR, &ctxVal, Hash);
			Mutation* mut = FindMutation(mutNtQueryAttributesFile, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_FAIL mutation to NtQueryAttributesFile!\n");
#endif
					// return error code
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtQueryAttributesFile(ObjectAttributes, FileAttributes);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (opening existing file -> file does not exist: STATUS_OBJECT_NAME_NOT_FOUND)
	BOOL* flag = NULL;
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cNtCreateFile, CTX_STR, &ctxVal, Hash);

			// A file that is being created cannot fail by not existing. We could mutate only FILE_OPEN
			// Files can also be found by being created, since the error code will be ala ERROR_ALREADY_EXISTS, but then the file is destroyed.
			// Since we would like to prevent the VM-sensitive files from being destroyed, we should be able to mutate all CreateFile calls
			// Unfortunately, we cannot set the Last Error from this hook (gets overwritten).

			Mutation* mut = FindMutation(mutNtCreateFile, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_FAIL mutation to NtCreateFile!\n");
#endif
					// return error code
					IoStatusBlock->Status = (NTSTATUS)mut->mutValue.nValue;
					IoStatusBlock->Information = FILE_DOES_NOT_EXIST;
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}

			/* CreateDisposition:
			FILE_OPEN           -> OPEN_EXISTING | TRUNCATE_EXISTING
			FILE_CREATE         -> CREATE_NEW
			FILE_OPEN_IF        -> OPEN_ALWAYS
			FILE_OVERWRITE_IF   -> CREATE_ALWAYS*/
		}
	}

	ret = OgNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
	// 	SIMPLE_LOG(NTSTATUS, NtDeviceIoControlFile, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength)
	NTSTATUS ret;
	// Mutation types: MUT_ALT_NUM (disk size), MUT_FAIL (STATUS_INVALID_HANDLE: 0xC0000008)
	// control code IOCTL_DISK_GET_LENGTH_INFO (0x7405c)
	BOOL* flag = NULL;
	//printf("Hook NtDeviceIoControlFile: Controlcode %x\n", IoControlCode);
	// If other controlcodes are interesting, the control code should be the record context
	//if (IoControlCode == 0x7405c) { // IOCTL_DISK_GET_LENGTH_INFO
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();

			ContextValue ctxVal;
			ctxVal.dwCtx = (DWORD)IoControlCode;
			RecordCall(Call::cNtDeviceIoControlFile, CTX_NUM, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutNtDeviceIoControlFile, CTX_NUM, &ctxVal); // ctx matches the class
			if (mut != NULL) {
				// there is a mutation
				if (mut->mutType == MUT_FAIL) {
					// skip the standard call and return fail
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
				else if (mut->mutType == MUT_ALT_NUM) { // only IoControlCode 0x7405c
					ret = OgNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
					if (NT_SUCCESS(ret)) {
						if (OutputBuffer != NULL) {
							PGET_LENGTH_INFORMATION size = (PGET_LENGTH_INFORMATION)OutputBuffer;
							// pass mutation as GB, then perform LONGLONG * 1000237400
							size->Length.QuadPart = (LONGLONG)mut->mutValue.nValue * 1000237400;
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	//}

	ret = OgNtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQueryVolumeInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileSystemInformation, ULONG Length, FS_INFORMATION_CLASS FileSystemInformationClass)
{
	// 	SIMPLE_LOG(NTSTATUS, NtQueryVolumeInformationFile, FileHandle, IoStatusBlock, FileSystemInformation, Length, FileSystemInformationClass)
	NTSTATUS ret;
	// Mutation types: MUT_ALT_NUM (disk size), MUT_FAIL (STATUS_INVALID_HANDLE: 0xC0000008)
	BOOL* flag = NULL;
	// if other classes are of interest, record context should be the class
	//if (FileSystemInformationClass == FileFsDeviceInformation) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			ctxVal.dwCtx = (DWORD)FileSystemInformationClass;
			RecordCall(Call::cNtQueryVolumeInformationFile, CTX_NUM, &ctxVal, Hash);

			// no findmutation since no context to match
			Mutation* mut = FindMutation(mutNtQueryVolumeInformationFile, CTX_NUM, &ctxVal); // ctx matches the class
			if (mut != NULL) {
				// there is a mutation
				if (mut->mutType == MUT_FAIL) {
					// skip the standard call and return fail
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
				else if (mut->mutType == MUT_ALT_NUM) { // ctx only FileFsDeviceInformation
					ret = OgNtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FileSystemInformation, Length, FileSystemInformationClass);
					if (NT_SUCCESS(ret)) {
						// The value is used to multiply the total disk space
						PFILE_FS_SIZE_INFORMATION size = (PFILE_FS_SIZE_INFORMATION)FileSystemInformation;
						if (size != NULL) {
							size->TotalAllocationUnits.QuadPart *= mut->mutValue.nValue;
						}
						// Disk Size = TotalAllocationUnits * SectorsPerAllocationUnit * BytesPerSector
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	//}

	ret = OgNtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FileSystemInformation, Length, FileSystemInformationClass);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	NTSTATUS ret;
	// Mutation types: (context dependent) MUT_ALT_NUM, MUT_FAIL, MUT_ALT_STR
	BOOL* flag = NULL;
	//printf("Hook NtQuerySystemInformation: %d\n", SystemInformationClass);
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		ctxVal.dwCtx = (DWORD)SystemInformationClass;
		RecordCall(Call::cNtQuerySystemInformation, CTX_NUM, &ctxVal, Hash);

		Mutation* mut = FindMutation(mutNtQuerySystemInformation, CTX_NUM, &ctxVal); // ctx matches the class
		if (mut != NULL) {
			if (mut->mutType == MUT_FAIL) {
				// STATUS_INFO_LENGTH_MISMATCH...?
				// STATUS_INVALID_INFO_CLASS
				// STATUS_INVALID_PARAMETER
				ReturnLength = 0;
				if (flag) (*flag) = FALSE;
				return STATUS_INVALID_PARAMETER;
			}
			else if (mut->mutType == MUT_ALT_NUM) {
				if (SystemInformationClass == SystemBasicInformation) {
					ret = OgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
					if (NT_SUCCESS(ret)) {
						PSYSTEM_BASIC_INFORMATION pbi = (PSYSTEM_BASIC_INFORMATION)SystemInformation;
						if (pbi != NULL) {
							pbi->NumberOfProcessors = (CCHAR)mut->mutValue.nValue;
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
			else if (mut->mutType == MUT_HIDE) {
				if (SystemInformationClass == 11) { // SystemModuleInformation
					ret = OgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
					if (NT_SUCCESS(ret)) {
						PRTL_PROCESS_MODULES info = (PRTL_PROCESS_MODULES)SystemInformation;
						ULONG delptr = 0;
						for (ULONG i = 0; i < info->NumberOfModules; i++) {
							if (strstr((char*)info->Modules[i].FullPathName, "VBox") != NULL) {
#ifdef __DEBUG_PRINT
								printf("hook: %s\n", info->Modules[i].FullPathName);
#endif
								delptr++;
							}
						}
						ULONG newCount = info->NumberOfModules - delptr;
						// could probably allocate one struct less
						ULONG pmsize = sizeof(RTL_PROCESS_MODULE_INFORMATION) * (newCount);
						PRTL_PROCESS_MODULES nPM = (PRTL_PROCESS_MODULES)malloc(sizeof(RTL_PROCESS_MODULES) + pmsize);
						if (nPM != NULL) {
							nPM->NumberOfModules = newCount;
							ULONG j = 0;
							for (ULONG i = 0; i < info->NumberOfModules; i++) {
								if (strstr((char*)info->Modules[i].FullPathName, "VBox") == NULL) {
									memcpy(&nPM->Modules[j], &info->Modules[i], sizeof(RTL_PROCESS_MODULE_INFORMATION));
									j++;
								}
							}
							memcpy(SystemInformation, nPM, sizeof(RTL_PROCESS_MODULES) + pmsize);
							free(nPM);
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
				else if (SystemInformationClass == SystemProcessInformation) {
					ret = OgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
					if (NT_SUCCESS(ret)) {
						PSYSTEM_PROCESS_INFORMATION curr = NULL;
						PSYSTEM_PROCESS_INFORMATION next = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
						do {
							curr = next;
							next = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)curr + curr->NextEntryOffset);
							if (wcsncmp(next->ImageName.Buffer, L"VBoxTray.exe", next->ImageName.Length) == 0 ||
								wcsncmp(next->ImageName.Buffer, L"VBoxService.exe", next->ImageName.Length) == 0) {
								if (next->NextEntryOffset == 0)
									curr->NextEntryOffset = 0;
								else
									curr->NextEntryOffset += next->NextEntryOffset;
							}
						} while (curr->NextEntryOffset != 0);
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}
	ret = OgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQuerySystemInformationEx(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID InputBuffer, ULONG InputBufferLength, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
{
	// 	SIMPLE_LOG(NTSTATUS, NtQuerySystemInformationEx, SystemInformationClass, InputBuffer, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength)
	NTSTATUS ret;
	// Mutation types: (context dependent) MUT_ALT_NUM, MUT_FAIL, MUT_ALT_STR
	// BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ContextValue ctxVal;
		ctxVal.dwCtx = (DWORD)SystemInformationClass;
		RecordCall(Call::cNtQuerySystemInformationEx, CTX_NUM, &ctxVal, Hash);
	}
	ret = OgNtQuerySystemInformationEx(SystemInformationClass, InputBuffer, InputBufferLength, SystemInformation, SystemInformationLength, ReturnLength);
	return ret;
}

NTSTATUS NTAPI HookNtPowerInformation(POWER_INFORMATION_LEVEL InformationLevel, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength)
{
	//  SIMPLE_LOG(NTSTATUS, NtPowerInformation, InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength)
	NTSTATUS ret;
	// Mutation types: MUT_SUCCEED (return True)
	BOOL* flag = NULL;
	if (InformationLevel == SystemPowerCapabilities) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			RecordCall(Call::cNtPowerInformation, CTX_NONE, NULL, Hash);
			// no findmutation since no context to match
			if (mutNtPowerInformation != NULL) {
				// there is a mutation
				if (mutNtPowerInformation->mutType == MUT_SUCCEED) {
					ret = OgNtPowerInformation(InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
					if (NT_SUCCESS(ret)) {
						SYSTEM_POWER_CAPABILITIES* powerCaps = (SYSTEM_POWER_CAPABILITIES*)OutputBuffer;
						if (powerCaps != NULL) {
							powerCaps->SystemS1 = TRUE;
							powerCaps->SystemS2 = TRUE;
							powerCaps->SystemS3 = TRUE;
							powerCaps->SystemS4 = TRUE;
							powerCaps->ThermalControl = TRUE;
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}

	ret = OgNtPowerInformation(InformationLevel, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQueryLicenseValue(PUNICODE_STRING ValueName, PULONG Type, PVOID Data, ULONG DataSize, PULONG ResultDataSize)
{
	//   SIMPLE_LOG(NTSTATUS, NtQueryLicenseValue, ValueName, Type, Data, DataSize, ResultDataSize)
	NTSTATUS ret;
	// Mutation types: MUT_SUCCEED (non-zero result), MUT_FAIL (STATUS_INVALID_PARAMETER: 0xC000000D)
	BOOL* flag = NULL;
	// ctx: L"Security-SPP-GenuineLocalStatus" -> Data = 1 (genuine)
	// ctx: L"Kernel-VMDetection-Private" -> Data = 0 (no VM)

	if (ValueName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = ValueName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ValueName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cNtQueryLicenseValue, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutNtQueryLicenseValue, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_SUCCEED) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_SUCCEED mutation to NtQueryLicenseValue!\n");
#endif
					ret = OgNtQueryLicenseValue(ValueName, Type, Data, DataSize, ResultDataSize);
					if (NT_SUCCESS(ret) && Data != NULL) {
						*(DWORD*)Data = (DWORD)mut->mutValue.nValue;
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
				else if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtQueryLicenseValue(ValueName, Type, Data, DataSize, ResultDataSize);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQueryDirectoryFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry, PUNICODE_STRING FileMask, BOOLEAN RestartScan)
{
	// MUT_TEST #4
	//  SIMPLE_LOG(NTSTATUS, NtQueryDirectoryFile, FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileMask, RestartScan)
	NTSTATUS ret;

	// Mutation types: MUT_FAIL (STATUS_NO_SUCH_FILE: file not found), MUT_HIDE skip file (todo)
	// TODO: investigate repeated calls (list of files) structure

	/*
	The ZwQueryDirectoryFileroutine returns STATUS_SUCCESS or an appropriate error status.
	Note that the set of error status values that can be returned is file-system-specific.
	ZwQueryDirectoryFilealso returns the number of bytes actually written to the given FileInformation buffer in the Information member of IoStatusBlock.
	*/
	BOOL* flag = NULL;
	if (FileMask != NULL && FileInformationClass == 3) { // FileBothDirectoryInformation
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			//printf("::: FileMask: %ws\n", FileMask->Buffer);
			// record the call
			ContextValue ctxVal;
			size_t widec = FileMask->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, FileMask->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';

			RecordCall(Call::cNtQueryDirectoryFile, CTX_STR, &ctxVal, Hash);
			// STATUS_NO_SUCH_FILE for a single file request

			Mutation* mut = FindMutation(mutNtQueryDirectoryFile, CTX_STR, &ctxVal);
			if (mut != NULL) {
#ifdef __DEBUG_PRINT
				printf("Applying NtQueryDirectoryFile mutation!\n");
#endif
				if (mut->mutType == MUT_FAIL) {
					// return error code
					if (flag) (*flag) = FALSE;
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileMask, RestartScan);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength)
{
	// SIMPLE_LOG(NTSTATUS, NtQueryInformationProcess, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)
	NTSTATUS ret;
	// Mutation types: MUT_HIDE (hides all...)
	BOOL* flag = NULL;
	//if (ProcessInformationClass == ProcessBasicInformation) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();

			ContextValue ctxVal;
			ctxVal.dwCtx = (DWORD)ProcessInformationClass;
			RecordCall(Call::cNtQueryInformationProcess, CTX_NUM, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutNtQueryInformationProcess, CTX_NUM, &ctxVal); // ctx matches the class
			if (mut != NULL) {
				// there is a mutation
				if (mut->mutType == MUT_HIDE) { // ctx only ProcessBasicInformation
					ret = OgNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
					if (NT_SUCCESS(ret)) {
						PPROCESS_BASIC_INFORMATION PBI = (PPROCESS_BASIC_INFORMATION)ProcessInformation;
						if (PBI != NULL) {
							PPEB PEB = (PPEB)PBI->PebBaseAddress;
							PPEB_LDR_DATA PLDR = (PPEB_LDR_DATA)PEB->Ldr;

							PLIST_ENTRY head = &PLDR->InMemoryOrderModuleList;
							PLIST_ENTRY curr = head->Flink;
							while (curr != head) {
								LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
								if (entry) {
									// if dll name contains "Enviral" or "VBox" or "vbox"
									if (wcsstr(entry->FullDllName.Buffer, L"vbox") != NULL ||
										wcsstr(entry->FullDllName.Buffer, L"VBox") != NULL ||
										wcsstr(entry->FullDllName.Buffer, L"Enviral") != NULL) {
										// wrap around forward link
										PLIST_ENTRY prev = curr->Blink;
										prev->Flink = curr->Flink;
										// wrap around backlink
										PLIST_ENTRY next = curr->Flink;
										next->Blink = prev;
									}
								}
								curr = curr->Flink;
							}
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
				else if (mut->mutType == MUT_FAIL) {
					ReturnLength = 0;
					if (flag) (*flag) = FALSE;
					return STATUS_INVALID_PARAMETER;
				}
			}
		}
	//}

	ret = OgNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);
	if (flag) (*flag) = FALSE;
	return ret;
}

NTSTATUS NTAPI HookNtQueryDirectoryObject(HANDLE DirectoryHandle, PVOID Buffer, ULONG Length, BOOLEAN ReturnSingleEntry, BOOLEAN RestartScan, PULONG Context, PULONG ReturnLength)
{
	//  SIMPLE_LOG(NTSTATUS, NtQueryDirectoryObject, DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength)
	NTSTATUS ret;
	// Mutation types: MUT_FAIL, "empty result"?
	// BOOL* flag = NULL;
	// unclear
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtQueryDirectoryObject, CTX_NONE, NULL, Hash);
	}

	ret = OgNtQueryDirectoryObject(DirectoryHandle, Buffer, Length, ReturnSingleEntry, RestartScan, Context, ReturnLength);
	return ret;
}

NTSTATUS NTAPI HookNtCreateMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN InitialOwner)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateMutant, MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner)
	NTSTATUS ret;
	// Mutation types: MUT_SUCCEED

	// malware tries to create mutexes of installed programs to detect it being active.
	// if the mutex already exists, it will be opened, but we can forge the result to appear as new
	// the retval is 0x40000000 and getlasterror is ERROR_ALREADY_EXISTS (b7) if the create causes an open
	// createmutant should 'succeed' (as if created new)

	// win: #define MUTEX_VPCXPMODE L"MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex"
	// only useful when using Microsoft Virtual PC
	BOOL* flag = NULL;
	// Unnamed mutexes are not of relevance for evasive behavior
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ret = OgNtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
			if (NT_SUCCESS(ret)) {
				if (ret == 0x40000000) { // STATUS_OBJECT_NAME_EXISTS
					// important: we only record createmutex calls that create an already existing mutex (evasive)
					ContextValue ctxVal;
					size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
					if (widec >= MAX_CTX_LEN) {
						widec = MAX_CTX_LEN - 1;
					}
					wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
					ctxVal.szCtx[widec] = L'\0';

					RecordCall(Call::cNtCreateMutant, CTX_STR, &ctxVal, Hash);

					Mutation* mut = FindMutation(mutNtCreateMutant, CTX_STR, &ctxVal);
					if (mut != NULL) {
#ifdef __DEBUG_PRINT
						printf("Applying NtCreateMutant mutation!\n");
#endif
						if (mut->mutType == MUT_SUCCEED) {
							if (flag) (*flag) = FALSE;
							return 0; // STATUS_SUCCESS (also clears GetLastError 0xb7)
						}
					}
				}
			}
			if (flag) (*flag) = FALSE;
			return ret;
		}
	}

	ret = OgNtCreateMutant(MutantHandle, DesiredAccess, ObjectAttributes, InitialOwner);
	// flag cannot be set here
	return ret;
}

NTSTATUS NTAPI HookNtOpenMutant(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	//  SIMPLE_LOG(NTSTATUS, NtOpenMutant, MutantHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;
	// Mutation types: MUT_FAIL (STATUS_OBJECT_NAME_NOT_FOUND:0xC0000034 named mutex does not exist)

	BOOL* flag = NULL;
	// if the open
	if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';

			RecordCall(Call::cNtOpenMutant, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutNtOpenMutant, CTX_STR, &ctxVal);
			if (mut != NULL) {
#ifdef __DEBUG_PRINT
				printf("Applying NtOpenMutant mutation!\n");
#endif
				if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					// STATUS_OBJECT_NAME_NOT_FOUND also sets LastError ERROR_FILE_NOT_FOUND
					return (NTSTATUS)mut->mutValue.nValue;
				}
			}
		}
	}

	ret = OgNtOpenMutant(MutantHandle, DesiredAccess, ObjectAttributes);
	if (flag) (*flag) = FALSE;
	return ret;
}

ULONG WINAPI HookGetAdaptersAddresses(ULONG Family, ULONG Flags, PVOID Reserved, PIP_ADAPTER_ADDRESSES AdapterAddresses, PULONG SizePointer)
{
	ULONG ret;
	// Mutation types: MUT_ALT_STR
	// Stock MAC: 10 4 5a 
	BOOL* flag = NULL;
	ret = OgGetAdaptersAddresses(Family, Flags, Reserved, AdapterAddresses, SizePointer);

	if (ret == ERROR_SUCCESS) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();

			RecordCall(Call::cGetAdaptersAddresses, CTX_NONE, NULL, Hash);

			if (mutGetAdaptersAddresses != NULL) { // there is a mutation
#ifdef __DEBUG_PRINT
				printf("Applying GetAdaptersAddresses mutation!\n");
#endif
				if (mutGetAdaptersAddresses->mutType == MUT_ALT_STR) {
					IP_ADAPTER_ADDRESSES* ptr = AdapterAddresses;
					while (ptr != NULL) {
#ifdef __DEBUG_PRINT
						printf("Adapter: %ws\n", ptr->Description);
#endif
						// ptr->Description (name) can be revealing for some VMs (VMWare)
						if (ptr->PhysicalAddressLength == 0x6) {
							// if the paddr == virtualbox
							if (memcmp(VBOX_MAC, ptr->PhysicalAddress, 3) == 0) {
								for (int i = 0; i < 3; i++) {
									ptr->PhysicalAddress[i] = (BYTE)mutGetAdaptersAddresses->mutValue.szValue[i];
								}
							}
						}
						ptr = ptr->Next;
					}
				}
			}
		}
	}
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookProcess32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
	//  SIMPLE_LOG(BOOL, Process32FirstW, hSnapshot, lppe)
	BOOL ret;
	// Mutation types: MUT_HIDE (contain "vbox")
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cProcess32FirstW, CTX_NONE, NULL, Hash);
		if (mutProcess32FirstW != NULL) {
			if (mutProcess32FirstW->mutType == MUT_HIDE) {
				ret = OgProcess32FirstW(hSnapshot, lppe);
				if (ret && wcsstr(_wcslwr(lppe->szExeFile), L"vbox")) {
					if (flag) (*flag) = FALSE;
					return HookProcess32NextW(hSnapshot, lppe);
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
		}
	}

	ret = OgProcess32FirstW(hSnapshot, lppe);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookProcess32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe)
{
	//  SIMPLE_LOG(BOOL, Process32NextW, hSnapshot, lppe)
	BOOL ret;
	// Mutation types: MUT_FAIL, MUT_HIDE (contain "vbox")
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cProcess32NextW, CTX_NONE, NULL, Hash);
		if (mutProcess32NextW != NULL) {
			if (mutProcess32NextW->mutType == MUT_HIDE) {
				ret = OgProcess32NextW(hSnapshot, lppe);
				if (ret && wcsstr(_wcslwr(lppe->szExeFile), L"vbox")) {
					if (flag) (*flag) = FALSE;
					return HookProcess32NextW(hSnapshot, lppe);
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
			else if (mutProcess32NextW->mutType == MUT_FAIL) {
				// no need to memset, call not performed
				if (flag) (*flag) = FALSE;
				SetLastError(ERROR_NO_MORE_FILES);
				return FALSE;
			}
		}
	}

	ret = OgProcess32NextW(hSnapshot, lppe);
	if (flag) (*flag) = FALSE;
	return ret;
}

HRESULT WINAPI HookCoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID* ppv)
{
	HRESULT ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cCoCreateInstance, CTX_NONE, NULL, Hash);
		if (mutCoCreateInstance != NULL) {
			if (mutCoCreateInstance->mutType == MUT_FAIL) {
				if (flag) (*flag) = FALSE;
				return REGDB_E_CLASSNOTREG; //(long) 0x8000FFFFL
			}
		}
	}

	ret = OgCoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv);
	if (flag) (*flag) = FALSE;
	return ret;
}


HMODULE WINAPI HookGetModuleHandleW(LPCWSTR lpModuleName)
{
	HMODULE ret;
	// Mutation types: MUT_FAIL
	BOOL* flag = NULL;
	if (lpModuleName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpModuleName);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, lpModuleName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cGetModuleHandleW, CTX_STR, &ctxVal, Hash);

			/*
			Mutation* mut = FindMutation(mutGetModuleHandleW, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(ERROR_MOD_NOT_FOUND);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
			*/
		}
	}

	ret = OgGetModuleHandleW(lpModuleName);
	if (flag) (*flag) = FALSE;
	return ret;
}

HMODULE WINAPI HookGetModuleHandleA(LPCSTR lpModuleName)
{
	HMODULE ret;
	// Mutation types: MUT_FAIL
	BOOL* flag = NULL;
	if (lpModuleName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;

			size_t widec = strlen(lpModuleName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpModuleName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cGetModuleHandleA, CTX_STR, &ctxVal, Hash);
			/*
			Mutation* mut = FindMutation(mutGetModuleHandleA, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(ERROR_MOD_NOT_FOUND);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
			*/
		}
	}

	ret = OgGetModuleHandleA(lpModuleName);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookGetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE* phModule)
{
	BOOL ret;
	// Mutation types: MUT_FAIL
	BOOL* flag = NULL;
	if (lpModuleName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpModuleName);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, lpModuleName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cGetModuleHandleExW, CTX_STR, &ctxVal, Hash);
			
			/*
			Mutation* mut = FindMutation(mutGetModuleHandleExW, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (phModule != NULL) phModule = NULL;
					SetLastError(ERROR_MOD_NOT_FOUND);
					if (flag) (*flag) = FALSE;
					return FALSE;
				}
			}*/
		}
	}

	ret = OgGetModuleHandleExW(dwFlags, lpModuleName, phModule);
	if (flag) (*flag) = FALSE;
	return ret;
}
BOOL WINAPI HookGetModuleHandleExA(DWORD dwFlags, LPCSTR lpModuleName, HMODULE* phModule)
{
	BOOL ret;
	// Mutation types: MUT_FAIL
	BOOL* flag = NULL;
	if (lpModuleName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();

			ContextValue ctxVal;
			size_t widec = strlen(lpModuleName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpModuleName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cGetModuleHandleExA, CTX_STR, &ctxVal, Hash);
			/*
			Mutation* mut = FindMutation(mutGetModuleHandleExA, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (phModule != NULL) phModule = NULL;
					SetLastError(ERROR_MOD_NOT_FOUND);
					if (flag) (*flag) = FALSE;
					return FALSE;
				}
			}*/
		}
	}

	ret = OgGetModuleHandleExA(dwFlags, lpModuleName, phModule);
	if (flag) (*flag) = FALSE;
	return ret;
}

ULONG WINAPI HookGetAdaptersInfo(PIP_ADAPTER_INFO AdapterInfo, PULONG SizePointer)
{
	ULONG ret;
	// Mutation types: MUT_ALT_STR
	BOOL* flag = NULL;
	ret = OgGetAdaptersInfo(AdapterInfo, SizePointer);

	if (ret == ERROR_SUCCESS) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			RecordCall(Call::cGetAdaptersInfo, CTX_NONE, NULL, Hash);
			if (mutGetAdaptersInfo != NULL) {
#ifdef __DEBUG_PRINT
				printf("Applying GetAdapterInfo mutation.\n");
#endif
				if (mutGetAdaptersInfo->mutType == MUT_ALT_STR) {
					IP_ADAPTER_INFO* ptr = AdapterInfo;
					while (ptr != NULL) {
						if (ptr->AddressLength == 6) {
							// if the paddr == virtualbox
							if (memcmp(VBOX_MAC, ptr->Address, 3) == 0) {
								for (int i = 0; i < 3; i++) {
									ptr->Address[i] = (BYTE)mutGetAdaptersInfo->mutValue.szValue[i];
								}
							}
						}
						ptr = ptr->Next;
					}
				}
			}
		}
	}

	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookSetupDiGetDeviceRegistryPropertyW(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize)
{
	BOOL ret;
	// Mutation types: MUT_FAIL, MUT_ALT_STR
	// buf contains VBOX
	BOOL* flag = NULL;
	if (Property == SPDRP_HARDWAREID) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ret = OgSetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);
			if (ret) {
				if (wcsstr((wchar_t*)PropertyBuffer, L"VBOX") != NULL) { // VBOX
					RecordCall(Call::cSetupDiGetDeviceRegistryPropertyW, CTX_NONE, NULL, Hash);
					if (mutSetupDiGetDeviceRegistryPropertyW != NULL) {
#ifdef __DEBUG_PRINT
						printf("Applying SetupDiGetDeviceRegistryPropertyW mutation!\n");
#endif
						if (mutSetupDiGetDeviceRegistryPropertyW->mutType == MUT_FAIL) {
							memset(PropertyBuffer, 0, PropertyBufferSize);
							SetLastError(ERROR_INVALID_DATA);
							if (flag) (*flag) = FALSE;
							return FALSE;
						}
						else if (mutSetupDiGetDeviceRegistryPropertyW->mutType == MUT_ALT_STR) {
							size_t mutLen = wcslen(mutSetupDiGetDeviceRegistryPropertyW->mutValue.szValue);
							size_t wavail = PropertyBufferSize / sizeof(wchar_t);
							if (mutLen < wavail) {
								memcpy(PropertyBuffer, mutSetupDiGetDeviceRegistryPropertyW->mutValue.szValue, (mutLen + 1) * sizeof(wchar_t));
							}
							else {
								memcpy(PropertyBuffer, mutSetupDiGetDeviceRegistryPropertyW->mutValue.szValue, (wavail - 1) * sizeof(wchar_t));
								((wchar_t*)PropertyBuffer)[wavail - 1] = L'\0';
							}
						}
					}
				}
			}
			if (flag) (*flag) = FALSE;
			return ret;
		}
	}
	ret = OgSetupDiGetDeviceRegistryPropertyW(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);
	// flag cannot be set here
	return ret;
}


BOOL WINAPI HookSetupDiGetDeviceRegistryPropertyA(HDEVINFO DeviceInfoSet, PSP_DEVINFO_DATA DeviceInfoData, DWORD Property, PDWORD PropertyRegDataType, PBYTE PropertyBuffer, DWORD PropertyBufferSize, PDWORD RequiredSize)
{
	BOOL ret;
	// Mutation types: MUT_FAIL, MUT_ALT_STR
	// buf contains VBOX
	//printf("hook HookSetupDiGetDeviceRegistryPropertyA\n");
	BOOL* flag = NULL;
	if (Property == SPDRP_HARDWAREID) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ret = OgSetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);
			if (ret) {
				if (strstr((char*)PropertyBuffer, "VBOX") != NULL) { // VBOX
					RecordCall(Call::cSetupDiGetDeviceRegistryPropertyA, CTX_NONE, NULL, Hash);
					if (mutSetupDiGetDeviceRegistryPropertyA != NULL) {
#ifdef __DEBUG_PRINT
						printf("Applying SetupDiGetDeviceRegistryPropertyA mutation!\n");
#endif
						if (mutSetupDiGetDeviceRegistryPropertyA->mutType == MUT_FAIL) {
							memset(PropertyBuffer, 0, PropertyBufferSize);
							SetLastError(ERROR_INVALID_DATA);
							if (flag) (*flag) = FALSE;
							return FALSE;
						}
						else if (mutSetupDiGetDeviceRegistryPropertyA->mutType == MUT_ALT_STR) {
							size_t wrlen = wcstombs((char*)PropertyBuffer, mutSetupDiGetDeviceRegistryPropertyA->mutValue.szValue, PropertyBufferSize);
							if (wrlen != (size_t)-1) {
								PropertyBuffer[wrlen] = '\0';
							}
						}
					}
				}
			}
			if (flag) (*flag) = FALSE;
			return ret;
		}
	}

	ret = OgSetupDiGetDeviceRegistryPropertyA(DeviceInfoSet, DeviceInfoData, Property, PropertyRegDataType, PropertyBuffer, PropertyBufferSize, RequiredSize);
	// flag cannot be set here
	return ret;
}

BOOL WINAPI HookGetLastInputInfo(PLASTINPUTINFO plii)
{
	BOOL ret;
	// Mutation types: MUT_SUCCEED (GetTickCount())
	BOOL* flag = NULL;
	if (plii != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			RecordCall(Call::cGetLastInputInfo, CTX_NONE, NULL, Hash);
			if (mutGetLastInputInfo != NULL) {
				if (mutGetLastInputInfo->mutType == MUT_SUCCEED) {
#ifdef __DEBUG_PRINT
					printf("Applying MUT_SUCCEED mutation to GetLastInputInfo\n");
#endif
					ret = OgGetLastInputInfo(plii);
					if (ret) {
						//plii->dwTime = mutGetLastInputInfo->mutValue.nValue;
						plii->dwTime = GetTickCount();
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}

	ret = OgGetLastInputInfo(plii);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookEnumServicesStatusExA(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCSTR pszGroupName)
{
	BOOL ret;
	// Mutation types: MUT_HIDE

	BOOL* flag = NULL;
	if (InfoLevel == SC_ENUM_PROCESS_INFO && dwServiceType == SERVICE_DRIVER) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			RecordCall(Call::cEnumServicesStatusExA, CTX_NONE, NULL, Hash);

			if (mutEnumServicesStatusExA != NULL) {
				if (mutEnumServicesStatusExA->mutType == MUT_HIDE) {
					// requires mutation string source
					ret = OgEnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);
					if (ret) {
						ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)lpServices;
						if (services != NULL && lpServicesReturned != NULL) {
							for (DWORD i = 0; i < *lpServicesReturned; i++) {
								if (strstr(services[i].lpServiceName, "VBox") || strstr(services[i].lpServiceName, "vbox")) {
									size_t mutLen = strlen((char*)mutEnumServicesStatusExA->mutValue.szValue);
									memcpy(services[i].lpServiceName, (char*)mutEnumServicesStatusExA->mutValue.szValue, (mutLen + 1) * sizeof(char));
								}
							}
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}

	ret = OgEnumServicesStatusExA(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);
	return ret;
}

BOOL WINAPI HookEnumServicesStatusExW(SC_HANDLE hSCManager, SC_ENUM_TYPE InfoLevel, DWORD dwServiceType, DWORD dwServiceState, LPBYTE lpServices, DWORD cbBufSize, LPDWORD pcbBytesNeeded, LPDWORD lpServicesReturned, LPDWORD lpResumeHandle, LPCWSTR pszGroupName)
{
	BOOL ret;
	// Mutation types: MUT_HIDE
	BOOL* flag = NULL;
	if (InfoLevel == SC_ENUM_PROCESS_INFO && dwServiceType == SERVICE_DRIVER) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			RecordCall(Call::cEnumServicesStatusExW, CTX_NONE, NULL, Hash);

			if (mutEnumServicesStatusExW != NULL) {
				if (mutEnumServicesStatusExW->mutType == MUT_HIDE) {
					// requires mutation string source
					ret = OgEnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);
					if (ret) {
						ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)lpServices;
						if (services != NULL && lpServicesReturned != NULL) {
							for (DWORD i = 0; i < *lpServicesReturned; i++) {
								if (wcsstr(services[i].lpServiceName, L"VBox") || wcsstr(services[i].lpServiceName, L"vbox")) {
									size_t mutLen = wcslen(mutEnumServicesStatusExW->mutValue.szValue);
									memcpy(services[i].lpServiceName, mutEnumServicesStatusExW->mutValue.szValue, (mutLen + 1) * sizeof(wchar_t));
								}
							}
						}
					}
					if (flag) (*flag) = FALSE;
					return ret;
				}
			}
		}
	}
	ret = OgEnumServicesStatusExW(hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookInternetCheckConnectionA(LPCSTR lpszUrl, DWORD dwFlags, DWORD dwReserved)
{
	BOOL ret;
	// Mutation types: MUT_FAIL, MUT_SUCCEED

	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();

		RecordCall(Call::cInternetCheckConnectionA, CTX_NONE, NULL, Hash);
		if (mutInternetCheckConnectionA != NULL) {
			if (mutInternetCheckConnectionA->mutType == MUT_SUCCEED) {
				// perform the call regardless, to match indirect activity
				ret = OgInternetCheckConnectionA(lpszUrl, dwFlags, dwReserved);
				if (flag) (*flag) = FALSE;
				return TRUE;
			}
			else if (mutInternetCheckConnectionA->mutType == MUT_FAIL) {
				// perform the call regardless, to match indirect activity
				ret = OgInternetCheckConnectionA(lpszUrl, dwFlags, dwReserved);
				if (flag) (*flag) = FALSE;
				return FALSE;
			}
		}
	}

	ret = OgInternetCheckConnectionA(lpszUrl, dwFlags, dwReserved);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookInternetCheckConnectionW(LPCWSTR lpszUrl, DWORD dwFlags, DWORD dwReserved)
{
	BOOL ret;
	// Mutation types: MUT_FAIL, MUT_SUCCEED

	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();

		RecordCall(Call::cInternetCheckConnectionW, CTX_NONE, NULL, Hash);
		if (mutInternetCheckConnectionW != NULL) {
			if (mutInternetCheckConnectionW->mutType == MUT_SUCCEED) {
				// perform the call regardless, to match indirect activity
				ret = OgInternetCheckConnectionW(lpszUrl, dwFlags, dwReserved);
				if (flag) (*flag) = FALSE;
				return TRUE;
			}
			else if (mutInternetCheckConnectionW->mutType == MUT_FAIL) {
				// perform the call regardless, to match indirect activity
				ret = OgInternetCheckConnectionW(lpszUrl, dwFlags, dwReserved);
				if (flag) (*flag) = FALSE;
				return FALSE;
			}
		}
	}

	ret = OgInternetCheckConnectionW(lpszUrl, dwFlags, dwReserved);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookGetWindowRect(HWND hWnd, LPRECT lpRect)
{
	BOOL ret;
	// Mutation types: MUT_ALT_TUP
	// BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cGetWindowRect, CTX_NONE, NULL, Hash);
	}
	ret = OgGetWindowRect(hWnd, lpRect);
	return ret;
}

BOOL WINAPI HookGetMonitorInfoA(HMONITOR hMonitor, LPMONITORINFO lpmi)
{
	BOOL ret;
	// Mutation types: MUT_ALT_TUP
	// BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cGetMonitorInfoA, CTX_NONE, NULL, Hash);
	}
	ret = OgGetMonitorInfoA(hMonitor, lpmi);
	return ret;
}

BOOL WINAPI HookGetMonitorInfoW(HMONITOR hMonitor, LPMONITORINFO lpmi)
{
	BOOL ret;
	// Mutation types: MUT_ALT_TUP
	// BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cGetMonitorInfoW, CTX_NONE, NULL, Hash);
	}
	ret = OgGetMonitorInfoW(hMonitor, lpmi);
	return ret;
}

HWND WINAPI HookFindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName)
{
	HWND ret;
	// Mutation types: MUT_FAIL
	// maybe also include GetWindowText

	BOOL* flag = NULL;
	if (lpWindowName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = strlen(lpWindowName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpWindowName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindWindowA, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutFindWindowA, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(0);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgFindWindowA(lpClassName, lpWindowName);
	if (flag) (*flag) = FALSE;
	return ret;
}

HWND WINAPI HookFindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName)
{
	HWND ret;
	// Mutation types: MUT_FAIL

	BOOL* flag = NULL;
	if (lpWindowName != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpWindowName);
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			wcsncpy(ctxVal.szCtx, lpWindowName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindWindowW, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutFindWindowW, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(0);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgFindWindowW(lpClassName, lpWindowName);
	if (flag) (*flag) = FALSE;
	return ret;
}

HWND WINAPI HookFindWindowExA(HWND hWndParent, HWND hWndChildAfter, LPCSTR lpszClass, LPCSTR lpszWindow)
{
	HWND ret;
	// Mutation types: MUT_FAIL
	// BOOL* flag = NULL;

	BOOL* flag = NULL;
	if (lpszWindow != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = strlen(lpszWindow) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpszWindow, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindWindowExA, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutFindWindowExA, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(0);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgFindWindowExA(hWndParent, hWndChildAfter, lpszClass, lpszWindow);
	if (flag) (*flag) = FALSE;
	return ret;
}

HWND WINAPI HookFindWindowExW(HWND hWndParent, HWND hWndChildAfter, LPCWSTR lpszClass, LPCWSTR lpszWindow)
{
	HWND ret;
	// Mutation types: MUT_FAIL
	// BOOL* flag = NULL;

	BOOL* flag = NULL;
	if (lpszWindow != NULL) {
		UINT64 Hash;
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpszWindow);
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			wcsncpy(ctxVal.szCtx, lpszWindow, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindWindowExW, CTX_STR, &ctxVal, Hash);

			Mutation* mut = FindMutation(mutFindWindowExW, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					SetLastError(0);
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgFindWindowExW(hWndParent, hWndChildAfter, lpszClass, lpszWindow);
	if (flag) (*flag) = FALSE;
	return ret;
}

BOOL WINAPI HookGetCursorPos(LPPOINT lpPoint)
{
	// MUT_TEST #1
	BOOL ret;
	// Mutation types: MUT_ALT_TUP, MUT_RND_TUP
	BOOL* flag = NULL;
	//printf("GetCursorPos Return Addr: %p\n", _ReturnAddress());

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cGetCursorPos, CTX_NONE, NULL, Hash);

		if (mutGetCursorPos != NULL) { // there is a mutation
#ifdef __DEBUG_PRINT
			printf("Applying GetCursorPos mutation!\n");
#endif
			if (mutGetCursorPos->mutType == MUT_FAIL) {
				// skip the standard call and return fail
				if (flag) (*flag) = FALSE;
				return (BOOL)mutGetCursorPos->mutValue.nValue;
			}
			else if (mutGetCursorPos->mutType == MUT_ALT_TUP) {
				// there are alternative values
				ret = OgGetCursorPos(lpPoint);
				if (ret) {
					lpPoint->x = (LONG)mutGetCursorPos->mutValue.tupValue[0];
					lpPoint->y = (LONG)mutGetCursorPos->mutValue.tupValue[1];
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
			else if (mutGetCursorPos->mutType == MUT_RND_TUP) {
				// generate alternative values
				ret = OgGetCursorPos(lpPoint);
				if (ret) {
					lpPoint->x = (LONG)rand() % 1920;
					lpPoint->y = (LONG)rand() % 1080;
				}
				if (flag) (*flag) = FALSE;
				return ret;
			}
		}
	}

	ret = OgGetCursorPos(lpPoint);
	if (flag) (*flag) = FALSE;
	return ret;
}

int WINAPI HookGetSystemMetrics(int nIndex)
{
	int ret;
	// Mutation types: MUT_ALT_TUP
	BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		ctxVal.dwCtx = nIndex;
		RecordCall(Call::cGetSystemMetrics, CTX_NUM, &ctxVal, Hash);

		// mut fail: return 0
		/*Mutation* mut = FindMutation(mutGetSystemMetrics, CTX_NUM, &ctxVal);
		if (mut != NULL) {
			// there is a mutation
			if (mut->mutType == MUT_FAIL) {
				// skip the standard call and return fail
				if (flag) (*flag) = FALSE;
				return 0;
			}
		}*/
	}
	ret = OgGetSystemMetrics(nIndex);
	return ret;
}

BOOL WINAPI HookSystemParametersInfoA(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni)
{
	BOOL ret;
	// Mutation types: MUT_ALT_TUP
	BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		ctxVal.dwCtx = uiAction;
		RecordCall(Call::cSystemParametersInfoA, CTX_NUM, &ctxVal, Hash);
		/*
		Mutation* mut = FindMutation(mutSystemParametersInfoA, CTX_NUM, &ctxVal);
		if (mut != NULL) {
			// there is a mutation
			if (mut->mutType == MUT_FAIL) {
				// skip the standard call and return fail
				if (flag) (*flag) = FALSE;
				return 0;
			}
		}*/
	}
	ret = OgSystemParametersInfoA(uiAction, uiParam, pvParam, fWinIni);
	return ret;
}

BOOL WINAPI HookSystemParametersInfoW(UINT uiAction, UINT uiParam, PVOID pvParam, UINT fWinIni)
{
	BOOL ret;
	// Mutation types: MUT_ALT_TUP
	BOOL* flag = NULL;
	// (TODO)
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		ctxVal.dwCtx = uiAction;
		RecordCall(Call::cSystemParametersInfoW, CTX_NUM, &ctxVal, Hash);
		/*
		Mutation* mut = FindMutation(mutSystemParametersInfoW, CTX_NUM, &ctxVal);
		if (mut != NULL) {
			// there is a mutation
			if (mut->mutType == MUT_FAIL) {
				// skip the standard call and return fail
				if (flag) (*flag) = FALSE;
				return 0;
			}
		}*/
	}
	ret = OgSystemParametersInfoW(uiAction, uiParam, pvParam, fWinIni);
	return ret;
}

SHORT WINAPI HookGetAsyncKeyState(int vKey)
{
	SHORT ret;
	// Mutation types: MUT_SUCCEED
	BOOL* flag = NULL;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cGetAsyncKeyState, CTX_NONE, NULL, Hash);

		if (mutGetAsyncKeyState != NULL) { // there is a mutation
#ifdef __DEBUG_PRINT
			printf("Applying GetAsyncKeyState mutation!\n");
#endif
			if (mutGetAsyncKeyState->mutType == MUT_SUCCEED) {
				if (flag) (*flag) = FALSE;
				return (SHORT)0x8001;
			}
		}
	}

	ret = OgGetAsyncKeyState(vKey);
	if (flag) (*flag) = FALSE;
	return ret;
}

HWND WINAPI HookGetForegroundWindow()
{
	HWND ret;
	// Mutation types: MUT_RND_NUM (random window)

	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cGetForegroundWindow, CTX_NONE, NULL, Hash);

		if (mutGetForegroundWindow != NULL) { // there is a mutation
#ifdef __DEBUG_PRINT
			printf("Applying GetForegroundWindow mutation!\n");
#endif
			if (mutGetForegroundWindow->mutType == MUT_RND_NUM) {
				HWND window = GetTopWindow(GetDesktopWindow());
				if (window == NULL) {
					if (flag) (*flag) = FALSE;
					return NULL;
				}
				HWND nextwin = NULL;
				int cnt = rand() % 4 + 1; // 1 2 3 4
				while (cnt > 0) {
					nextwin = GetWindow(window, GW_HWNDNEXT);
					if (nextwin == NULL) {
						break;
					}
					window = nextwin;
					if (!IsWindowVisible(window))
						continue;
					cnt--;
				}
				if (flag) (*flag) = FALSE;
				return window;
			}
		}
	}

	ret = OgGetForegroundWindow();
	if (flag) (*flag) = FALSE;
	return ret;
}

HMODULE WINAPI HookLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	HMODULE ret;

	BOOL* flag = NULL;
	UINT64 Hash;
	if (lpLibFileName != NULL) {
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpLibFileName);
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			wcsncpy(ctxVal.szCtx, lpLibFileName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cLoadLibraryExW, CTX_STR, &ctxVal, Hash);

			// mut fail if string ctx is VBox -> return NULL
			Mutation* mut = FindMutation(mutFindWindowExW, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgLoadLibraryExW(lpLibFileName, hFile, dwFlags);
	if (flag) (*flag) = FALSE;
	return ret;
}

HMODULE WINAPI HookLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
{
	HMODULE ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (lpLibFileName != NULL) {
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;

			size_t widec = strlen(lpLibFileName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpLibFileName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cLoadLibraryExA, CTX_STR, &ctxVal, Hash);

			// mut fail if string ctx is VBox -> return NULL
			Mutation* mut = FindMutation(mutFindWindowExA, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgLoadLibraryExA(lpLibFileName, hFile, dwFlags);
	if (flag) (*flag) = FALSE;
	return ret;
}


HMODULE WINAPI HookLoadLibraryW(LPCWSTR lpLibFileName)
{
	HMODULE ret;

	BOOL* flag = NULL;
	UINT64 Hash;
	if (lpLibFileName != NULL) {
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;
			size_t widec = wcslen(lpLibFileName);
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			wcsncpy(ctxVal.szCtx, lpLibFileName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cLoadLibraryW, CTX_STR, &ctxVal, Hash);

			// mut fail if string ctx is VBox -> return NULL
			Mutation* mut = FindMutation(mutFindWindowExW, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgLoadLibraryW(lpLibFileName);
	if (flag) (*flag) = FALSE;
	return ret;
}

HMODULE WINAPI HookLoadLibraryA(LPCSTR lpLibFileName)
{
	HMODULE ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (lpLibFileName != NULL) {
		if (!SkipActivity(&Hash)) {
			flag = EnterHook();
			ContextValue ctxVal;

			size_t widec = strlen(lpLibFileName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpLibFileName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cLoadLibraryA, CTX_STR, &ctxVal, Hash);

			// mut fail if string ctx is VBox -> return NULL
			Mutation* mut = FindMutation(mutFindWindowExA, CTX_STR, &ctxVal);
			if (mut != NULL) {
				if (mut->mutType == MUT_FAIL) {
					if (flag) (*flag) = FALSE;
					return NULL;
				}
			}
		}
	}

	ret = OgLoadLibraryA(lpLibFileName);
	if (flag) (*flag) = FALSE;
	return ret;
}


// Activity Logs
// For the activity logs we do not set the hook flag, since their activity is constant (no mutations)
// We do check if we are already in a hook, then we do not record the activity.
NTSTATUS NTAPI HookNtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
	// SIMPLE_LOG(NTSTATUS, NtOpenFile, FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ContextValue ctxVal;
		if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
		}
		else {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtOpenFile, CTX_STR, &ctxVal, Hash);
	}

	ret = OgNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
	return ret;
}

NTSTATUS NTAPI HookNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	NTSTATUS ret;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ContextValue ctxVal;
		ULONG NameSize;
		if (!GetFileNameFromHandle(FileHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtReadFile, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	return ret;
}

NTSTATUS NTAPI HookNtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key)
{
	NTSTATUS ret;
	if (FileHandle == hPipe) { // always skip pipe writes
		return OgNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	}

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ContextValue ctxVal;
		ULONG NameSize;
		if (!GetFileNameFromHandle(FileHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtWriteFile, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
	return ret;
}

NTSTATUS NTAPI HookNtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtDeleteFile, ObjectAttributes)
	NTSTATUS ret;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ContextValue ctxVal;
		if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
		}
		else {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtDeleteFile, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtDeleteFile(ObjectAttributes);
	return ret;
}

NTSTATUS NTAPI HookNtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	// SIMPLE_LOG(NTSTATUS, NtQueryInformationFile, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)
	NTSTATUS ret;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ContextValue ctxVal;
		ULONG NameSize;
		if (!GetFileNameFromHandle(FileHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtQueryInformationFile, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	return ret;
}

NTSTATUS NTAPI HookNtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	// SIMPLE_LOG(NTSTATUS, NtSetInformationFile, FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass)
	NTSTATUS ret;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ContextValue ctxVal;
		ULONG NameSize;
		if (!GetFileNameFromHandle(FileHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtSetInformationFile, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtSetInformationFile(FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);
	return ret;
}

NTSTATUS NTAPI HookNtOpenDirectoryObject(PHANDLE DirectoryObjectHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtOpenDirectoryObject, DirectoryObjectHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ContextValue ctxVal;
		if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
		}
		else {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtOpenDirectoryObject, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtOpenDirectoryObject(DirectoryObjectHandle, DesiredAccess, ObjectAttributes);
	return ret;
}

NTSTATUS NTAPI HookNtCreateDirectoryObject(PHANDLE DirectoryHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateDirectoryObject, DirectoryHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ContextValue ctxVal;
		if (ObjectAttributes && ObjectAttributes->ObjectName != NULL) {
			size_t widec = ObjectAttributes->ObjectName->Length / sizeof(wchar_t);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, ObjectAttributes->ObjectName->Buffer, widec);
			ctxVal.szCtx[widec] = L'\0';
		}
		else {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}
		RecordCall(Call::cNtCreateDirectoryObject, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtCreateDirectoryObject(DirectoryHandle, DesiredAccess, ObjectAttributes);
	return ret;
}

NTSTATUS NTAPI HookNtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ProcessFlags, ULONG ThreadFlags, PVOID ProcessParameters, PPS_CREATE_INFO CreateInfo, PPS_ATTRIBUTE_LIST AttributeList)
{
	NTSTATUS ret;

	// unfortunately, the process flags are not passed to NtCreateUserProcess, so we cannot inject the DLL from here
	// we can still use it to track process creation activity however
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtCreateUserProcess, CTX_NONE, NULL, Hash);
	}
	ret = OgNtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList);
	return ret;
}

NTSTATUS NTAPI HookNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateProcess, ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtCreateProcess, CTX_NONE, NULL, Hash);
	}
	ret = OgNtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
	return ret;
}

NTSTATUS NTAPI HookNtCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort, ULONG JobMemberLevel)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateProcessEx, ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, JobMemberLevel)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtCreateProcessEx, CTX_NONE, NULL, Hash);
	}
	ret = OgNtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, JobMemberLevel);
	return ret;
}

NTSTATUS NTAPI HookNtSuspendProcess(HANDLE ProcessHandle)
{
	// SIMPLE_LOG(NTSTATUS, NtSuspendProcess, ProcessHandle)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtSuspendProcess, CTX_NONE, NULL, Hash);
	}
	ret = OgNtSuspendProcess(ProcessHandle);
	return ret;
}

NTSTATUS NTAPI HookNtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus)
{
	// SIMPLE_LOG(NTSTATUS, NtTerminateProcess, ProcessHandle, ExitStatus)
	NTSTATUS ret;
	// processhandle == NULL -> current process exits
	// printf("NtTerminateProcess -- Handle:%p Exit:%x\n", ProcessHandle, ExitStatus);
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtTerminateProcess, CTX_NONE, NULL, Hash);
	}
	ret = OgNtTerminateProcess(ProcessHandle, ExitStatus);
	return ret;
}

NTSTATUS NTAPI HookNtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, ULONG CommitSize, PLARGE_INTEGER SectionOffset, PULONG ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect)
{
	// SIMPLE_LOG(NTSTATUS, NtMapViewOfSection, SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtMapViewOfSection, CTX_NONE, NULL, Hash);
	}
	ret = OgNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
	return ret;
}

NTSTATUS NTAPI HookNtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress)
{
	// SIMPLE_LOG(NTSTATUS, NtUnmapViewOfSection, ProcessHandle, BaseAddress)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtUnmapViewOfSection, CTX_NONE, NULL, Hash);
	}
	ret = OgNtUnmapViewOfSection(ProcessHandle, BaseAddress);
	return ret;
}

NTSTATUS NTAPI HookNtMakeTemporaryObject(HANDLE ObjectHandle)
{
	// SIMPLE_LOG(NTSTATUS, NtMakeTemporaryObject, ObjectHandle)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtMakeTemporaryObject, CTX_NONE, NULL, Hash);
	}
	ret = OgNtMakeTemporaryObject(ObjectHandle);
	return ret;
}

NTSTATUS NTAPI HookNtMakePermanentObject(HANDLE Handle)
{
	// SIMPLE_LOG(NTSTATUS, NtMakePermanentObject, Handle)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtMakePermanentObject, CTX_NONE, NULL, Hash);
	}
	ret = OgNtMakePermanentObject(Handle);
	return ret;
}

NTSTATUS NTAPI HookNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
	// SIMPLE_LOG(NTSTATUS, NtWriteVirtualMemory, ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtWriteVirtualMemory, CTX_NONE, NULL, Hash);
	}
	ret = OgNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
	return ret;
}

NTSTATUS NTAPI HookNtSetInformationProcess(HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
	// SIMPLE_LOG(NTSTATUS, NtSetInformationProcess, ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtSetInformationProcess, CTX_NONE, NULL, Hash);
	}
	ret = OgNtSetInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength);
	return ret;
}

NTSTATUS NTAPI HookNtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle)
{
	// SIMPLE_LOG(NTSTATUS, NtGetNextProcess, ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtGetNextProcess, CTX_NONE, NULL, Hash);
	}
	ret = OgNtGetNextProcess(ProcessHandle, DesiredAccess, HandleAttributes, Flags, NewProcessHandle);
	return ret;
}

NTSTATUS NTAPI HookNtReplaceKey(POBJECT_ATTRIBUTES NewHiveFileName, HANDLE KeyHandle, POBJECT_ATTRIBUTES BackupHiveFileName)
{
	// SIMPLE_LOG(NTSTATUS, NtReplaceKey, NewHiveFileName, KeyHandle, BackupHiveFileName)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {

		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtReplaceKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtReplaceKey(NewHiveFileName, KeyHandle, BackupHiveFileName);
	return ret;
}

NTSTATUS NTAPI HookNtRenameKey(HANDLE KeyHandle, PUNICODE_STRING NewName)
{
	// SIMPLE_LOG(NTSTATUS, NtRenameKey, KeyHandle, NewName)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtRenameKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtRenameKey(KeyHandle, NewName);
	return ret;
}

NTSTATUS NTAPI HookNtSaveKey(HANDLE KeyHandle, HANDLE FileHandle)
{
	// SIMPLE_LOG(NTSTATUS, NtSaveKey, KeyHandle, FileHandle)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtSaveKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtSaveKey(KeyHandle, FileHandle);
	return ret;
}

NTSTATUS NTAPI HookNtSaveKeyEx(HANDLE KeyHandle, HANDLE FileHandle, ULONG Format)
{
	// SIMPLE_LOG(NTSTATUS, NtSaveKeyEx, KeyHandle, FileHandle, Format)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtSaveKeyEx, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtSaveKeyEx(KeyHandle, FileHandle, Format);
	return ret;
}

NTSTATUS NTAPI HookNtSetValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName, ULONG TitleIndex, ULONG Type, PVOID Data, ULONG DataSize)
{
	// SIMPLE_LOG(NTSTATUS, NtSetValueKey, KeyHandle, ValueName, TitleIndex, Type, Data, DataSize)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtSetValueKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtSetValueKey(KeyHandle, ValueName, TitleIndex, Type, Data, DataSize);
	return ret;
}

NTSTATUS NTAPI HookNtDeleteKey(HANDLE KeyHandle)
{
	// SIMPLE_LOG(NTSTATUS, NtDeleteKey, KeyHandle)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtDeleteKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtDeleteKey(KeyHandle);
	return ret;
}

NTSTATUS NTAPI HookNtDeleteValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName)
{
	// SIMPLE_LOG(NTSTATUS, NtDeleteValueKey, KeyHandle, ValueName)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtDeleteValueKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtDeleteValueKey(KeyHandle, ValueName);
	return ret;
}

NTSTATUS NTAPI HookNtOpenTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtOpenTimer, TimerHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtOpenTimer, CTX_NONE, NULL, Hash);
	}
	ret = OgNtOpenTimer(TimerHandle, DesiredAccess, ObjectAttributes);
	return ret;
}

NTSTATUS NTAPI HookNtQueryTimer(HANDLE TimerHandle, TIMER_INFORMATION_CLASS TimerInformationClass, PVOID TimerInformation, ULONG TimerInformationLength, PULONG ReturnLength)
{
	// SIMPLE_LOG(NTSTATUS, NtQueryTimer, TimerHandle, TimerInformationClass, TimerInformation, TimerInformationLength, ReturnLength)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtQueryTimer, CTX_NONE, NULL, Hash);
	}
	ret = OgNtQueryTimer(TimerHandle, TimerInformationClass, TimerInformation, TimerInformationLength, ReturnLength);
	return ret;
}

NTSTATUS NTAPI HookNtCreateTimer(PHANDLE TimerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, TIMER_TYPE TimerType)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateTimer, TimerHandle, DesiredAccess, ObjectAttributes, TimerType)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtCreateTimer, CTX_NONE, NULL, Hash);
	}
	ret = OgNtCreateTimer(TimerHandle, DesiredAccess, ObjectAttributes, TimerType);
	return ret;
}

NTSTATUS NTAPI HookNtQuerySystemTime(PLARGE_INTEGER SystemTime)
{
	// SIMPLE_LOG(NTSTATUS, NtQuerySystemTime, SystemTime)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtQuerySystemTime, CTX_NONE, NULL, Hash);
	}
	ret = OgNtQuerySystemTime(SystemTime);
	return ret;
}

NTSTATUS NTAPI HookNtOpenEvent(PHANDLE EventHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtOpenEvent, EventHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtOpenEvent, CTX_NONE, NULL, Hash);
	}
	ret = OgNtOpenEvent(EventHandle, DesiredAccess, ObjectAttributes);
	return ret;
}

NTSTATUS NTAPI HookNtNotifyChangeKey(HANDLE KeyHandle, HANDLE EventHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG NotifyFilter, BOOLEAN WatchSubtree, PVOID RegChangesDataBuffer, ULONG RegChangesDataBufferLength, BOOLEAN Asynchronous)
{
	// SIMPLE_LOG(NTSTATUS, NtNotifyChangeKey, KeyHandle, EventHandle, ApcRoutine, ApcRoutineContext, IoStatusBlock, NotifyFilter, WatchSubtree, RegChangesDataBuffer, RegChangesDataBufferLength, Asynchronous)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		ULONG NameSize;
		ContextValue ctxVal;
		if (!GetKeyNameFromHandle(KeyHandle, ctxVal.szCtx, &NameSize)) {
			wcscpy(ctxVal.szCtx, L"Unknown");
		}

		RecordCall(Call::cNtNotifyChangeKey, CTX_STR, &ctxVal, Hash);
	}
	ret = OgNtNotifyChangeKey(KeyHandle, EventHandle, ApcRoutine, ApcRoutineContext, IoStatusBlock, NotifyFilter, WatchSubtree, RegChangesDataBuffer, RegChangesDataBufferLength, Asynchronous);
	return ret;
}

NTSTATUS NTAPI HookNtOpenSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes)
{
	// SIMPLE_LOG(NTSTATUS, NtOpenSemaphore, SemaphoreHandle, DesiredAccess, ObjectAttributes)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtOpenSemaphore, CTX_NONE, NULL, Hash);
	}
	ret = OgNtOpenSemaphore(SemaphoreHandle, DesiredAccess, ObjectAttributes);
	return ret;
}

NTSTATUS NTAPI HookNtCreateSemaphore(PHANDLE SemaphoreHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, ULONG InitialCount, ULONG MaximumCount)
{
	// SIMPLE_LOG(NTSTATUS, NtCreateSemaphore, SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount, MaximumCount)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtCreateSemaphore, CTX_NONE, NULL, Hash);
	}
	ret = OgNtCreateSemaphore(SemaphoreHandle, DesiredAccess, ObjectAttributes, InitialCount, MaximumCount);
	return ret;
}

NTSTATUS NTAPI HookNtLockFile(HANDLE FileHandle, HANDLE LockGrantedEvent, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER ByteOffset, PLARGE_INTEGER Length, PULONG Key, BOOLEAN ReturnImmediately, BOOLEAN ExclusiveLock)
{
	// SIMPLE_LOG(NTSTATUS, NtLockFile, FileHandle, LockGrantedEvent, ApcRoutine, ApcContext, IoStatusBlock, ByteOffset, Length, Key, ReturnImmediately, ExclusiveLock)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtLockFile, CTX_NONE, NULL, Hash);
	}
	ret = OgNtLockFile(FileHandle, LockGrantedEvent, ApcRoutine, ApcContext, IoStatusBlock, ByteOffset, Length, Key, ReturnImmediately, ExclusiveLock);
	return ret;
}

void WINAPI HookGetSystemTime(LPSYSTEMTIME lpSystemTime)
{
	// todo: possibly mutate the time
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cGetSystemTime, CTX_NONE, NULL, Hash);
	}
	OgGetSystemTime(lpSystemTime);
	if (flag) (*flag) = FALSE;
}
void WINAPI HookGetLocalTime(LPSYSTEMTIME lpSystemTime)
{
	// todo: possibly mutate the time 
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cGetLocalTime, CTX_NONE, NULL, Hash);
	}
	OgGetLocalTime(lpSystemTime);
	if (flag) (*flag) = FALSE;
}

// network
HRESULT WINAPI HookURLDownloadToFileW(LPUNKNOWN pCaller, LPCWSTR szURL, LPCWSTR szFileName, DWORD dwReserved, LPBINDSTATUSCALLBACK lpfnCB)
{
	//simple_log_network(HRESULT, URLDownloadToFileW, pCaller, szURL, szFileName, dwReserved, lpfnCB)
	HRESULT ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;

		size_t widec = wcslen(szURL);
		if (widec >= MAX_CTX_LEN) {
			widec = MAX_CTX_LEN - 1;
		}
		wcsncpy(ctxVal.szCtx, szURL, widec);
		ctxVal.szCtx[widec] = L'\0';
		RecordCall(Call::cURLDownloadToFileW, CTX_STR, &ctxVal, Hash);
	}
	ret = OgURLDownloadToFileW(pCaller, szURL, szFileName, dwReserved, lpfnCB);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookInternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
{
	//simple_log_network(HINTERNET, InternetOpenA, lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cInternetOpenA, CTX_NONE, NULL, Hash);
	}
	ret = OgInternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookInternetConnectA(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	//simple_log_network(HINTERNET, InternetConnectA, hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();

		ContextValue ctxVal;
		size_t widec = strlen(lpszServerName) * 2;
		if (widec >= MAX_CTX_LEN) {
			widec = (MAX_CTX_LEN - 1);
		}
		mbstowcs(ctxVal.szCtx, lpszServerName, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cInternetConnectA, CTX_STR, &ctxVal, Hash);
	}
	ret = OgInternetConnectA(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookInternetConnectW(HINTERNET hInternet, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext)
{
	//simple_log_network(HINTERNET, InternetConnectW, hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;

		size_t widec = wcslen(lpszServerName);
		if (widec >= MAX_CTX_LEN) {
			widec = MAX_CTX_LEN - 1;
		}
		wcsncpy(ctxVal.szCtx, lpszServerName, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cInternetConnectW, CTX_STR, &ctxVal, Hash);
	}
	ret = OgInternetConnectW(hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookInternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext)
{
	//simple_log_network(HINTERNET, InternetOpenUrlA, hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		size_t widec = strlen(lpszUrl) * 2;
		if (widec >= MAX_CTX_LEN) {
			widec = (MAX_CTX_LEN - 1);
		}
		mbstowcs(ctxVal.szCtx, lpszUrl, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cInternetOpenUrlA, CTX_STR, &ctxVal, Hash);
	}
	ret = OgInternetOpenUrlA(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookHttpOpenRequestA(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
	//simple_log_network(HINTERNET, HttpOpenRequestA, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		size_t widec = strlen(lpszObjectName) * 2;
		if (widec >= MAX_CTX_LEN) {
			widec = (MAX_CTX_LEN - 1);
		}
		mbstowcs(ctxVal.szCtx, lpszObjectName, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cHttpOpenRequestA, CTX_STR, &ctxVal, Hash);
	}
	ret = OgHttpOpenRequestA(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
HINTERNET WINAPI HookHttpOpenRequestW(HINTERNET hConnect, LPCWSTR lpszVerb, LPCWSTR lpszObjectName, LPCWSTR lpszVersion, LPCWSTR lpszReferrer, LPCWSTR* lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)
{
	//simple_log_network(HINTERNET, HttpOpenRequestW, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext)
	HINTERNET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;

		size_t widec = wcslen(lpszObjectName);
		if (widec >= MAX_CTX_LEN) {
			widec = MAX_CTX_LEN - 1;
		}
		wcsncpy(ctxVal.szCtx, lpszObjectName, widec);
		ctxVal.szCtx[widec] = L'\0';
		RecordCall(Call::cHttpOpenRequestW, CTX_STR, &ctxVal, Hash);
	}
	ret = OgHttpOpenRequestW(hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
BOOL WINAPI HookHttpSendRequestA(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
	//simple_log_network(BOOL, HttpSendRequestA, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)
	BOOL ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cHttpSendRequestA, CTX_NONE, NULL, Hash);
	}
	ret = OgHttpSendRequestA(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
	if (flag) (*flag) = FALSE;
	return ret;
}
BOOL WINAPI HookHttpSendRequestW(HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
	//simple_log_network(BOOL, HttpSendRequestW, hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength)
	BOOL ret;
	BOOL* flag = NULL;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cHttpSendRequestW, CTX_NONE, NULL, Hash);
	}
	ret = OgHttpSendRequestW(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
	if (flag) (*flag) = FALSE;
	return ret;
}
BOOL WINAPI HookInternetReadFile(HINTERNET hFile, LPVOID lpBuffersOut, DWORD dwFlags, LPDWORD dwContext)
{
	//simple_log_network(BOOL, InternetReadFile, hFile, lpBuffersOut, dwFlags, dwContext)
	BOOL ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cInternetReadFile, CTX_NONE, NULL, Hash);
	}
	ret = OgInternetReadFile(hFile, lpBuffersOut, dwFlags, dwContext);
	if (flag) (*flag) = FALSE;
	return ret;
}
DNS_STATUS WINAPI HookDnsQuery_A(PCSTR pszName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved)
{
	//simple_log_network(DNS_STATUS, DnsQuery_A, pszName, wType, Options, pExtra, ppQueryResults, pReserved)
	DNS_STATUS ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		size_t widec = strlen(pszName) * 2;
		if (widec >= MAX_CTX_LEN) {
			widec = (MAX_CTX_LEN - 1);
		}
		mbstowcs(ctxVal.szCtx, pszName, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cDnsQuery_A, CTX_STR, &ctxVal, Hash);
	}
	ret = OgDnsQuery_A(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
	if (flag) (*flag) = FALSE;
	return ret;
}
DNS_STATUS WINAPI HookDnsQuery_W(PCWSTR pszName, WORD wType, DWORD Options, PVOID pExtra, PDNS_RECORD* ppQueryResults, PVOID* pReserved)
{
	//simple_log_network(DNS_STATUS, DnsQuery_W, pszName, wType, Options, pExtra, ppQueryResults, pReserved)
	DNS_STATUS ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;

		size_t widec = wcslen(pszName);
		if (widec >= MAX_CTX_LEN) {
			widec = MAX_CTX_LEN - 1;
		}
		wcsncpy(ctxVal.szCtx, pszName, widec);
		ctxVal.szCtx[widec] = L'\0';
		RecordCall(Call::cDnsQuery_W, CTX_STR, &ctxVal, Hash);
	}
	ret = OgDnsQuery_W(pszName, wType, Options, pExtra, ppQueryResults, pReserved);
	if (flag) (*flag) = FALSE;
	return ret;
}
INT WSAAPI HookGetAddrInfoW(PCWSTR pNodeName, PCWSTR pServiceName, const ADDRINFOW* pHints, PADDRINFOW* ppResult)
{
	//simple_log_network(INT, GetAddrInfoW, pNodeName, pServiceName, pHints, ppResult)
	INT ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		size_t widec = wcslen(pNodeName);
		if (widec >= MAX_CTX_LEN) {
			widec = MAX_CTX_LEN - 1;
		}
		wcsncpy(ctxVal.szCtx, pNodeName, widec);
		ctxVal.szCtx[widec] = L'\0';
		RecordCall(Call::cGetAddrInfoW, CTX_STR, &ctxVal, Hash);
	}
	ret = OgGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WINAPI HookWSAStartup(WORD wVersionRequired, LPWSADATA lpWSAData)
{
	//simple_log_network(int, WSAStartup, wVersionRequired, lpWSAData)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cWSAStartup, CTX_NONE, NULL, Hash);
	}
	ret = OgWSAStartup(wVersionRequired, lpWSAData);
	if (flag) (*flag) = FALSE;
	return ret;
}
hostent* WINAPI Hookgethostbyname(const char* name)
{
	//simple_log_network(hostent*, gethostbyname, name)
	hostent* ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;
		size_t widec = strlen(name) * 2;
		if (widec >= MAX_CTX_LEN) {
			widec = (MAX_CTX_LEN - 1);
		}
		mbstowcs(ctxVal.szCtx, name, widec);
		ctxVal.szCtx[widec] = L'\0';

		RecordCall(Call::cgethostbyname, CTX_STR, &ctxVal, Hash);
	}
	ret = Oggethostbyname(name);
	if (flag) (*flag) = FALSE;
	return ret;
}
SOCKET WSAAPI Hooksocket(int af, int type, int protocol)
{
	//simple_log_network(SOCKET, socket, af, type, protocol)
	SOCKET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::csocket, CTX_NONE, NULL, Hash);
	}
	ret = Ogsocket(af, type, protocol);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI Hookconnect(SOCKET s, const sockaddr* name, int namelen)
{
	//simple_log_network(int, connect, s, name, namelen)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cconnect, CTX_NONE, NULL, Hash);
	}
	ret = Ogconnect(s, name, namelen);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI Hooksend(SOCKET s, const char* buf, int len, int flags)
{
	//simple_log_network(int, send, s, buf, len, flags)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::csend, CTX_NONE, NULL, Hash);
	}
	ret = Ogsend(s, buf, len, flags);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI Hooksendto(SOCKET s, const char* buf, int len, int flags, const sockaddr* to, int tolen)
{
	//simple_log_network(int, sendto, s, buf, len, flags, to, tolen)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::csendto, CTX_NONE, NULL, Hash);
	}
	ret = Ogsendto(s, buf, len, flags, to, tolen);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WINAPI Hookrecv(SOCKET s, char* buf, int len, int flags)
{
	//simple_log_network(int, recv, s, buf, len, flags)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::crecv, CTX_NONE, NULL, Hash);
	}
	ret = Ogrecv(s, buf, len, flags);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WINAPI Hookrecvfrom(SOCKET s, char* buf, int len, int flags, sockaddr* from, int* fromlen)
{
	//simple_log_network(int, recvfrom, s, buf, len, flags, from, fromlen)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::crecvfrom, CTX_NONE, NULL, Hash);
	}
	ret = Ogrecvfrom(s, buf, len, flags, from, fromlen);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WINAPI Hookbind(SOCKET s, const sockaddr* addr, int namelen)
{
	//simple_log_network(int, bind, s, addr, namelen)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cbind, CTX_NONE, NULL, Hash);
	}
	ret = Ogbind(s, addr, namelen);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI HookWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	//simple_log_network(int, WSARecv, s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cWSARecv, CTX_NONE, NULL, Hash);
	}
	ret = OgWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI HookWSARecvFrom(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, sockaddr* lpFrom, LPINT lpFromlen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	//simple_log_network(int, WSARecvFrom, s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cWSARecvFrom, CTX_NONE, NULL, Hash);
	}
	ret = OgWSARecvFrom(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpFrom, lpFromlen, lpOverlapped, lpCompletionRoutine);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI HookWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	//simple_log_network(int, WSASend, s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cWSASend, CTX_NONE, NULL, Hash);
	}
	ret = OgWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
	if (flag) (*flag) = FALSE;
	return ret;
}
int WSAAPI HookWSASendTo(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, const sockaddr* lpTo, int iTolen, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	//simple_log_network(int, WSASendTo, s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine)
	int ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cWSASendTo, CTX_NONE, NULL, Hash);
	}
	ret = OgWSASendTo(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpTo, iTolen, lpOverlapped, lpCompletionRoutine);
	if (flag) (*flag) = FALSE;
	return ret;
}
SOCKET WSAAPI HookWSASocketW(int af, int type, int protocol, LPWSAPROTOCOL_INFOW lpProtocolInfo, GROUP g, DWORD dwFlags)
{
	//simple_log_network(SOCKET, WSASocketW, af, type, protocol, lpProtocolInfo, g, dwFlags)
	SOCKET ret;
	BOOL* flag = NULL;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		RecordCall(Call::cWSASocketW, CTX_NONE, NULL, Hash);
	}
	ret = OgWSASocketW(af, type, protocol, lpProtocolInfo, g, dwFlags);
	if (flag) (*flag) = FALSE;
	return ret;
}
HRSRC WINAPI HookFindResourceExW(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, WORD wLanguage)
{
	HRSRC ret;
	BOOL* flag = NULL;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;

		if (IS_INTRESOURCE(lpName)) {
			ctxVal.dwCtx = (DWORD)((ULONG_PTR)(lpName));
			RecordCall(Call::cFindResourceExW, CTX_NUM, &ctxVal, Hash);
		}
		else {
			size_t widec = wcslen(lpName);
			if (widec >= MAX_CTX_LEN) {
				widec = MAX_CTX_LEN - 1;
			}
			wcsncpy(ctxVal.szCtx, lpName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindResourceExW, CTX_STR, &ctxVal, Hash);
		}
	}

	ret = OgFindResourceExW(hModule, lpType, lpName, wLanguage);
	if (flag) (*flag) = FALSE;
	return ret;
}
HRSRC WINAPI HookFindResourceExA(HMODULE hModule, LPCSTR lpType, LPCSTR lpName, WORD wLanguage)
{
	HRSRC ret;
	BOOL* flag = NULL;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		flag = EnterHook();
		ContextValue ctxVal;

		if (IS_INTRESOURCE(lpName)) {
			ctxVal.dwCtx = (DWORD)((ULONG_PTR)(lpName));
			RecordCall(Call::cFindResourceExA, CTX_NUM, &ctxVal, Hash);
		}
		else {

			size_t widec = strlen(lpName) * 2;
			if (widec >= MAX_CTX_LEN) {
				widec = (MAX_CTX_LEN - 1);
			}
			mbstowcs(ctxVal.szCtx, lpName, widec);
			ctxVal.szCtx[widec] = L'\0';
			RecordCall(Call::cFindResourceExA, CTX_STR, &ctxVal, Hash);
		}
	}

	ret = OgFindResourceExA(hModule, lpType, lpName, wLanguage);
	if (flag) (*flag) = FALSE;
	return ret;
}
// Management log
BOOL WINAPI HookCreateProcessInternalW(HANDLE hUserToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, PHANDLE hNewToken)
{
	BOOL ret;
#ifdef __DEBUG_PRINT
	printf("Hook::: CreateProcessInternalW: %x\n", dwCreationFlags);
#endif
	UINT64 Hash;
	SkipActivity(&Hash);

	dwCreationFlags |= CREATE_SUSPENDED;
	ret = OgCreateProcessInternalW(hUserToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
	if (ret) {
#ifdef __DEBUG_PRINT
		printf("Created process - PID:%lu HANDLE:%p\n", lpProcessInformation->dwProcessId, lpProcessInformation->hProcess);
#endif

		ContextValue ctxVal;
		ctxVal.dwCtx = (DWORD)(lpProcessInformation->dwProcessId);
		RecordCall(Call::cCreateProcessInternalW, CTX_NUM, &ctxVal, Hash);

		size_t lendll = sizeof(TARGET_DLL); //strlen(TARGET_DLL);
		LPVOID dllname = VirtualAllocEx(lpProcessInformation->hProcess, NULL, lendll, MEM_COMMIT, PAGE_READWRITE);
		if (dllname == NULL) {
			return FALSE;
		}
		if (!WriteProcessMemory(lpProcessInformation->hProcess, dllname, TARGET_DLL, lendll, NULL)) {
			return FALSE;
		}
		HANDLE hThread = CreateRemoteThread(lpProcessInformation->hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryA, dllname, NULL, NULL);
		if (hThread == NULL) {
			return FALSE;
		}
		WaitForSingleObject(hThread, INFINITE); // INFINITE?
		ResumeThread(lpProcessInformation->hThread);
		VirtualFreeEx(lpProcessInformation->hProcess, dllname, 0, MEM_RELEASE);
	}
	return ret;
}

DWORD WINAPI HookGetTickCount()
{
	DWORD ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cGetTickCount, CTX_NONE, NULL, Hash);
	}
	// adjust for sleep skipping
	ret = OgGetTickCount() + TimeShift;
	return ret;
}

NTSTATUS NTAPI HookNtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval)
{
	NTSTATUS ret;
	// DelayInterval: Delay in 100-ns units.
	// Negative value means delay relative to current
	// :10000 = milliseconds
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		if (DelayInterval->QuadPart < 0) {
			ContextValue ctxVal;
			ctxVal.dwCtx = (DWORD)(DelayInterval->QuadPart / -10000);
			RecordCall(Call::cNtDelayExecution, CTX_NUM, &ctxVal, Hash);
		}
		else {
			RecordCall(Call::cNtDelayExecution, CTX_NONE, NULL, Hash);
		}
	}
	if (DelayInterval->QuadPart < 0) {
		// atomic addition: flip sign & convert to ms
		_InterlockedExchangeAdd(&TimeShift, (ULONG)(DelayInterval->QuadPart / -10000));
		//TimeShift += (DWORD)(DelayInterval->QuadPart / -10000); 
#ifdef __DEBUG_PRINT
		printf("New TimeShift: %lu\n", TimeShift);
#endif
		// For TickCount: Add TimeShift
		// For QueryPerformance: Add TimeShift * FREQ
	}
	DelayInterval->QuadPart = -1000; // 0.1 ms
	ret = OgNtDelayExecution(Alertable, DelayInterval);
	return ret;
}

BOOL WINAPI HookQueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
{
	BOOL ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cQueryPerformanceCounter, CTX_NONE, NULL, Hash);
	}
	// NOTE: malware can detect this behavior by executing rdtsc instruction
	ret = OgQueryPerformanceCounter(lpPerformanceCount);
	if (ret) {
		// adjust for sleep skipping
		lpPerformanceCount->QuadPart += (LONGLONG)(TimeShift * dFreq);
	}
#ifdef __DEBUG_PRINT
	printf("QueryPerformanceCounter: %lld\n", lpPerformanceCount->QuadPart);
#endif
	return ret;
}

NTSTATUS NTAPI HookNtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
	//SIMPLE_LOG(NTSTATUS, NtCreateThread, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended)
	NTSTATUS ret;
	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtCreateThread, CTX_NONE, NULL, Hash);
	}
	ret = OgNtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
	return ret;
}
NTSTATUS NTAPI HookNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList)
{
	//SIMPLE_LOG(NTSTATUS, NtCreateThreadEx, ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList)
	NTSTATUS ret;

	UINT64 Hash;
	if (!SkipActivity(&Hash)) {
		RecordCall(Call::cNtCreateThreadEx, CTX_NONE, NULL, Hash);
	}
	ret = OgNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
	/*if (NT_SUCCESS(ret)) {
		if (SkipActivity(&Hash)) {
			printf("Thread Created In Hook. Current TID: %lu\n", GetCurrentThreadId());
			CLIENT_ID* cid = (CLIENT_ID*)AttributeList->Attributes[0].Value;
			if (cid != NULL) {
				printf("CLIENT_ID P:%p U:%p TID:%lu\n", cid->UniqueProcess, cid->UniqueThread, (DWORD)cid->UniqueThread);
				//DWORD newTid = GetThreadId(cid->UniqueThread);
				//printf("Newly Created TID: %lu\n", newTid);
			}
			//printf("pValue: %p\n", AttributeList->Attributes[0].Value);
		}
	}*/
	return ret;
}

int AddMutationToCallListNoCtx(Mutation* src, MutationNoCtx** call)
{
	// call should be NULL
	if (*call != NULL) {
		fprintf(stderr, "This should not happen: NoCtx Call exists before add.\n");
		return -1;
	}

	*call = (MutationNoCtx*)malloc(sizeof(MutationNoCtx));
	if (*call == NULL) {
		fprintf(stderr, "Could not allocate memory for mutation no ctx.\n");
		return -1;
	}

	(*call)->mutType = src->mutType;
	(*call)->mutValue = src->mutValue;

	return 1;
}

int AddMutationToCallList(Mutation* src, Mutation** call)
{
	Mutation* ptr = NULL;
	if (*call == NULL) { // empty call mutation list
		*call = (Mutation*)malloc(sizeof(Mutation));
		if (*call == NULL) {
			fprintf(stderr, "Could not allocate memory for mutation.\n");
			return -1;
		}
		ptr = *call;
	}
	else { // find last and add next
		ptr = *call;
		while (ptr->next != NULL) {
			ptr = ptr->next;
		}
		// ptr is now equal to the last valid element
		ptr->next = (Mutation*)malloc(sizeof(Mutation));
		if (ptr->next == NULL) {
			fprintf(stderr, "Could not allocate memory for mutation 2.\n");
			return -1;
		}
		ptr = ptr->next;
	}

	// here ptr points to a fresh element
	ptr->mutType = src->mutType;
	ptr->mutValue = src->mutValue;
	ptr->rec = src->rec; // ctx
	ptr->next = NULL;

	return 1;
}

void StoreMutation(Mutation* gen)
{
	// we pass the address of the list because it's a NULL ptr by default
	switch (gen->rec.call) {
	case Call::cNtOpenKey: AddMutationToCallList(gen, &mutNtOpenKey); break;
	case Call::cNtOpenKeyEx: AddMutationToCallList(gen, &mutNtOpenKeyEx); break;
	case Call::cNtQueryValueKey: AddMutationToCallList(gen, &mutNtQueryValueKey); break;
	case Call::cNtCreateKey: AddMutationToCallList(gen, &mutNtCreateKey); break;
	case Call::cNtEnumerateKey: AddMutationToCallList(gen, &mutNtEnumerateKey); break;
	case Call::cNtEnumerateValueKey: AddMutationToCallList(gen, &mutNtEnumerateValueKey); break;
	case Call::cNtCreateFile: AddMutationToCallList(gen, &mutNtCreateFile); break;
	case Call::cNtQueryAttributesFile: AddMutationToCallList(gen, &mutNtQueryAttributesFile); break;
	case Call::cNtDeviceIoControlFile: AddMutationToCallList(gen, &mutNtDeviceIoControlFile); break;
	case Call::cNtQueryVolumeInformationFile: AddMutationToCallList(gen, &mutNtQueryVolumeInformationFile); break;
	case Call::cNtQuerySystemInformation: AddMutationToCallList(gen, &mutNtQuerySystemInformation); break;
	case Call::cNtQuerySystemInformationEx: AddMutationToCallList(gen, &mutNtQuerySystemInformationEx); break;
	case Call::cNtPowerInformation: AddMutationToCallListNoCtx(gen, &mutNtPowerInformation); break;
	case Call::cNtQueryLicenseValue: AddMutationToCallList(gen, &mutNtQueryLicenseValue); break;
	case Call::cNtQueryDirectoryFile: AddMutationToCallList(gen, &mutNtQueryDirectoryFile); break;
	case Call::cNtQueryInformationProcess: AddMutationToCallList(gen, &mutNtQueryInformationProcess); break;
	case Call::cNtQueryDirectoryObject: AddMutationToCallList(gen, &mutNtQueryDirectoryObject); break;
	case Call::cNtCreateMutant: AddMutationToCallList(gen, &mutNtCreateMutant); break;
	case Call::cNtOpenMutant: AddMutationToCallList(gen, &mutNtOpenMutant); break;
	case Call::cGetAdaptersAddresses: AddMutationToCallListNoCtx(gen, &mutGetAdaptersAddresses); break;
	case Call::cProcess32FirstW: AddMutationToCallListNoCtx(gen, &mutProcess32FirstW); break;
	case Call::cProcess32NextW: AddMutationToCallListNoCtx(gen, &mutProcess32NextW); break;
	case Call::cCoCreateInstance: AddMutationToCallListNoCtx(gen, &mutCoCreateInstance); break;
	//case Call::cGetModuleHandleW: AddMutationToCallList(gen, &mutGetModuleHandleW); break;
	//case Call::cGetModuleHandleA: AddMutationToCallList(gen, &mutGetModuleHandleA); break;
	//case Call::cGetModuleHandleExW: AddMutationToCallList(gen, &mutGetModuleHandleExW); break;
	//case Call::cGetModuleHandleExA: AddMutationToCallList(gen, &mutGetModuleHandleExA); break;
	case Call::cGetAdaptersInfo: AddMutationToCallListNoCtx(gen, &mutGetAdaptersInfo); break;
	case Call::cSetupDiGetDeviceRegistryPropertyW: AddMutationToCallListNoCtx(gen, &mutSetupDiGetDeviceRegistryPropertyW); break;
	case Call::cSetupDiGetDeviceRegistryPropertyA: AddMutationToCallListNoCtx(gen, &mutSetupDiGetDeviceRegistryPropertyA); break;
	case Call::cGetLastInputInfo: AddMutationToCallListNoCtx(gen, &mutGetLastInputInfo); break;
	case Call::cEnumServicesStatusExA: AddMutationToCallListNoCtx(gen, &mutEnumServicesStatusExA); break;
	case Call::cEnumServicesStatusExW: AddMutationToCallListNoCtx(gen, &mutEnumServicesStatusExW); break;
	case Call::cInternetCheckConnectionA: AddMutationToCallListNoCtx(gen, &mutInternetCheckConnectionA); break;
	case Call::cInternetCheckConnectionW: AddMutationToCallListNoCtx(gen, &mutInternetCheckConnectionW); break;
	case Call::cGetWindowRect: AddMutationToCallListNoCtx(gen, &mutGetWindowRect); break;
	case Call::cGetMonitorInfoA: AddMutationToCallListNoCtx(gen, &mutGetMonitorInfoA); break;
	case Call::cGetMonitorInfoW: AddMutationToCallListNoCtx(gen, &mutGetMonitorInfoW); break;
	case Call::cFindWindowA: AddMutationToCallList(gen, &mutFindWindowA); break;
	case Call::cFindWindowW: AddMutationToCallList(gen, &mutFindWindowW); break;
	case Call::cFindWindowExA: AddMutationToCallList(gen, &mutFindWindowExA); break;
	case Call::cFindWindowExW: AddMutationToCallList(gen, &mutFindWindowExW); break;
	case Call::cGetCursorPos: AddMutationToCallListNoCtx(gen, &mutGetCursorPos); break;
	//case Call::cGetSystemMetrics: AddMutationToCallList(gen, &mutGetSystemMetrics); break;
	//case Call::cSystemParametersInfoA: AddMutationToCallList(gen, &mutSystemParametersInfoA); break;
	//case Call::cSystemParametersInfoW: AddMutationToCallList(gen, &mutSystemParametersInfoW); break;
	case Call::cGetAsyncKeyState: AddMutationToCallListNoCtx(gen, &mutGetAsyncKeyState); break;
	case Call::cGetForegroundWindow: AddMutationToCallListNoCtx(gen, &mutGetForegroundWindow); break;
	case Call::cLoadLibraryExW: AddMutationToCallList(gen, &mutLoadLibraryExW); break;
	case Call::cLoadLibraryExA: AddMutationToCallList(gen, &mutLoadLibraryExA); break;
	case Call::cLoadLibraryW: AddMutationToCallList(gen, &mutLoadLibraryW); break;
	case Call::cLoadLibraryA: AddMutationToCallList(gen, &mutLoadLibraryA); break;

	default: fprintf(stderr, "Unknown mutation target\n"); break;
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	LPVOID lpvData;
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule); // disable notifications
#ifdef __DEBUG_PRINT
		printf("Enviral DLL Loaded\n");
#endif
		// pipe (createfile is connect)
		hPipe = CreateFile(szPipeName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		if (hPipe == INVALID_HANDLE_VALUE) {
			fprintf(stderr, "Could not create client pipe: %x\n", GetLastError());
			return -1;
		}
#ifdef __DEBUG_PRINT
		printf("[Pipe C] Client connected to pipe: %p\n", hPipe);
#endif
		WaitNamedPipe(szPipeName, 20000);
#ifdef __DEBUG_PRINT
		printf("[Pipe C] WaitNamedPipe succeeded!\n");
#endif

		DWORD dwMode = PIPE_READMODE_MESSAGE;
		BOOL set = SetNamedPipeHandleState(hPipe, &dwMode, NULL, NULL);
		if (!set) {
			fprintf(stderr, "Could not set pipe to read message mode\n");
			return -1;
		}

		// read (mut)
		DWORD dwMutationCount;
		DWORD dwRead;
		// if NumBytesToRead is < the next message, readfile returns ERROR_MORE_DATA
		BOOL rd = ReadFile(hPipe, &dwMutationCount, sizeof(dwMutationCount), &dwRead, NULL);
		if (rd) {
#ifdef __DEBUG_PRINT
			printf("[Pipe C] Mutation count: %lu\n", dwMutationCount);
#endif
			for (DWORD i = 0; i < dwMutationCount; i++) {
				Mutation mut;
				rd = ReadFile(hPipe, &mut, sizeof(Mutation), &dwRead, NULL);
				if (!rd) {
					fprintf(stderr, "[Pipe C] Could not read generated mutation.\n");
				}
#ifdef __DEBUG_PRINT // debug
				printf("[Pipe C] Received a mutation for call: %s\n", DebugCallNames[mut.rec.call]);
#endif
				// store the mutation.
				StoreMutation(&mut);
			}

		}
		else {
			DWORD err = GetLastError();
			fprintf(stderr, "Mutation Read Failed: %x\n", err);
		}

		// Get the start address of the executable module
		WCHAR FileName[MAX_PATH];
		GetModuleFileNameW(NULL, FileName, MAX_PATH);
		DWORD pid = GetCurrentProcessId();
		MODULEENTRY32 ModuleEntry = { 0 };
		HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
		if (!SnapShot) return NULL;
		ModuleEntry.dwSize = sizeof(ModuleEntry);
		if (!Module32First(SnapShot, &ModuleEntry)) return NULL;
		do {
			if (wcsstr(FileName, ModuleEntry.szModule)) {
				//printf("ModuleName: %ws\n", ModuleEntry.szModule);
				//printf("Module Base Addr: %p\n", ModuleEntry.modBaseAddr);
				//printf("Module Base Size: %lu\n", ModuleEntry.modBaseSize);
				TargetBase = ModuleEntry.modBaseAddr;
				TargetEnd = ModuleEntry.modBaseAddr + ModuleEntry.modBaseSize;
				break;
			}
		} while (Module32Next(SnapShot, &ModuleEntry));
		CloseHandle(SnapShot);
#ifdef __DEBUG_PRINT
		printf("Info: Module address (%ws) range: %p ~ %p\n", ModuleEntry.szModule, TargetBase, TargetEnd);
#endif
		// Load the Performance Counter Frequency
		LARGE_INTEGER freq;
		if (QueryPerformanceFrequency(&freq)) {
			dFreq = double(freq.QuadPart) / 1000.0;
#ifdef __DEBUG_PRINT
			printf("Performance Counter Frequency = %f\n", dFreq);
#endif
		}

		// seed random
		srand(756669);

		HMODULE nt = GetModuleHandleA("ntdll.dll");
		if (nt == NULL) return FALSE;

		HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
		if (k32 == NULL) return FALSE;

		pLoadLibraryA = GetProcAddress(k32, "LoadLibraryA");

		/* win32k.sys functions are not exposed (kernel only), so we can hook the Win32 API */
		/* The calls in user32.dll are accessible and do not need native API hook */

		/* GetTickCount cannot be hooked, since it does not contain the necessary preamble (too few bytes in the function) */
		// for some reason on 32bit it can be hooked

		// evasive
		OgNtOpenKey = (ProtoNtOpenKey)GetProcAddress(nt, "NtOpenKey");
		OgNtOpenKeyEx = (ProtoNtOpenKeyEx)GetProcAddress(nt, "NtOpenKeyEx");
		OgNtQueryValueKey = (ProtoNtQueryValueKey)GetProcAddress(nt, "NtQueryValueKey");
		OgNtCreateKey = (ProtoNtCreateKey)GetProcAddress(nt, "NtCreateKey");
		OgNtEnumerateKey = (ProtoNtEnumerateKey)GetProcAddress(nt, "NtEnumerateKey");
		OgNtEnumerateValueKey = (ProtoNtEnumerateValueKey)GetProcAddress(nt, "NtEnumerateValueKey");
		OgNtCreateFile = (ProtoNtCreateFile)GetProcAddress(nt, "NtCreateFile");
		OgNtQueryAttributesFile = (ProtoNtQueryAttributesFile)GetProcAddress(nt, "NtQueryAttributesFile");
		OgNtDeviceIoControlFile = (ProtoNtDeviceIoControlFile)GetProcAddress(nt, "NtDeviceIoControlFile");
		OgNtQueryVolumeInformationFile = (ProtoNtQueryVolumeInformationFile)GetProcAddress(nt, "NtQueryVolumeInformationFile");
		OgNtQuerySystemInformation = (ProtoNtQuerySystemInformation)GetProcAddress(nt, "NtQuerySystemInformation");
		OgNtQuerySystemInformationEx = (ProtoNtQuerySystemInformationEx)GetProcAddress(nt, "NtQuerySystemInformationEx");
		OgNtPowerInformation = (ProtoNtPowerInformation)GetProcAddress(nt, "NtPowerInformation");
		OgNtQueryLicenseValue = (ProtoNtQueryLicenseValue)GetProcAddress(nt, "NtQueryLicenseValue");
		OgNtQueryDirectoryFile = (ProtoNtQueryDirectoryFile)GetProcAddress(nt, "NtQueryDirectoryFile");
		OgNtQueryInformationProcess = (ProtoNtQueryInformationProcess)GetProcAddress(nt, "NtQueryInformationProcess");
		OgNtQueryDirectoryObject = (ProtoNtQueryDirectoryObject)GetProcAddress(nt, "NtQueryDirectoryObject");
		OgNtCreateMutant = (ProtoNtCreateMutant)GetProcAddress(nt, "NtCreateMutant");
		OgNtOpenMutant = (ProtoNtOpenMutant)GetProcAddress(nt, "NtOpenMutant");
		// activity
		OgNtOpenFile = (ProtoNtOpenFile)GetProcAddress(nt, "NtOpenFile");
		OgNtReadFile = (ProtoNtReadFile)GetProcAddress(nt, "NtReadFile");
		OgNtWriteFile = (ProtoNtWriteFile)GetProcAddress(nt, "NtWriteFile");
		OgNtDeleteFile = (ProtoNtDeleteFile)GetProcAddress(nt, "NtDeleteFile");
		OgNtQueryInformationFile = (ProtoNtQueryInformationFile)GetProcAddress(nt, "NtQueryInformationFile");
		OgNtSetInformationFile = (ProtoNtSetInformationFile)GetProcAddress(nt, "NtSetInformationFile");
		OgNtOpenDirectoryObject = (ProtoNtOpenDirectoryObject)GetProcAddress(nt, "NtOpenDirectoryObject");
		OgNtCreateDirectoryObject = (ProtoNtCreateDirectoryObject)GetProcAddress(nt, "NtCreateDirectoryObject");
		OgNtCreateUserProcess = (ProtoNtCreateUserProcess)GetProcAddress(nt, "NtCreateUserProcess");
		OgNtCreateProcess = (ProtoNtCreateProcess)GetProcAddress(nt, "NtCreateProcess");
		OgNtCreateProcessEx = (ProtoNtCreateProcessEx)GetProcAddress(nt, "NtCreateProcessEx");
		OgNtSuspendProcess = (ProtoNtSuspendProcess)GetProcAddress(nt, "NtSuspendProcess");
		OgNtTerminateProcess = (ProtoNtTerminateProcess)GetProcAddress(nt, "NtTerminateProcess");
		OgNtMapViewOfSection = (ProtoNtMapViewOfSection)GetProcAddress(nt, "NtMapViewOfSection");
		OgNtUnmapViewOfSection = (ProtoNtUnmapViewOfSection)GetProcAddress(nt, "NtUnmapViewOfSection");
		OgNtMakeTemporaryObject = (ProtoNtMakeTemporaryObject)GetProcAddress(nt, "NtMakeTemporaryObject");
		OgNtMakePermanentObject = (ProtoNtMakePermanentObject)GetProcAddress(nt, "NtMakePermanentObject");
		OgNtWriteVirtualMemory = (ProtoNtWriteVirtualMemory)GetProcAddress(nt, "NtWriteVirtualMemory");
		OgNtSetInformationProcess = (ProtoNtSetInformationProcess)GetProcAddress(nt, "NtSetInformationProcess");
		OgNtGetNextProcess = (ProtoNtGetNextProcess)GetProcAddress(nt, "NtGetNextProcess");
		OgNtReplaceKey = (ProtoNtReplaceKey)GetProcAddress(nt, "NtReplaceKey");
		OgNtRenameKey = (ProtoNtRenameKey)GetProcAddress(nt, "NtRenameKey");
		OgNtSaveKey = (ProtoNtSaveKey)GetProcAddress(nt, "NtSaveKey");
		OgNtSaveKeyEx = (ProtoNtSaveKeyEx)GetProcAddress(nt, "NtSaveKeyEx");
		OgNtSetValueKey = (ProtoNtSetValueKey)GetProcAddress(nt, "NtSetValueKey");
		OgNtDeleteKey = (ProtoNtDeleteKey)GetProcAddress(nt, "NtDeleteKey");
		OgNtDeleteValueKey = (ProtoNtDeleteValueKey)GetProcAddress(nt, "NtDeleteValueKey");
		OgNtOpenTimer = (ProtoNtOpenTimer)GetProcAddress(nt, "NtOpenTimer");
		OgNtQueryTimer = (ProtoNtQueryTimer)GetProcAddress(nt, "NtQueryTimer");
		OgNtCreateTimer = (ProtoNtCreateTimer)GetProcAddress(nt, "NtCreateTimer");
		OgNtQuerySystemTime = (ProtoNtQuerySystemTime)GetProcAddress(nt, "NtQuerySystemTime");
		OgNtOpenEvent = (ProtoNtOpenEvent)GetProcAddress(nt, "NtOpenEvent");
		OgNtNotifyChangeKey = (ProtoNtNotifyChangeKey)GetProcAddress(nt, "NtNotifyChangeKey");
		OgNtOpenSemaphore = (ProtoNtOpenSemaphore)GetProcAddress(nt, "NtOpenSemaphore");
		OgNtCreateSemaphore = (ProtoNtCreateSemaphore)GetProcAddress(nt, "NtCreateSemaphore");
		OgNtLockFile = (ProtoNtLockFile)GetProcAddress(nt, "NtLockFile");
		// edge case
		OgProcess32FirstW = (ProtoProcess32FirstW)GetProcAddress(k32, "Process32FirstW");
		OgProcess32NextW = (ProtoProcess32NextW)GetProcAddress(k32, "Process32NextW");

		// child process management
		OgCreateProcessInternalW = (ProtoCreateProcessInternalW)GetProcAddress(k32, "CreateProcessInternalW");
		// util
		NtQueryKey = (ProtoNtQueryKey)GetProcAddress(nt, "NtQueryKey");
		OgNtDelayExecution = (ProtoNtDelayExecution)GetProcAddress(nt, "NtDelayExecution");

		// thread test
		OgNtCreateThread = (ProtoNtCreateThread)GetProcAddress(nt, "NtCreateThread");
		OgNtCreateThreadEx = (ProtoNtCreateThreadEx)GetProcAddress(nt, "NtCreateThreadEx");

		//DetourSetIgnoreTooSmall(TRUE);
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());


		// evasive
		DetourAttach(&(PVOID&)OgNtOpenKey, HookNtOpenKey);
		DetourAttach(&(PVOID&)OgNtOpenKeyEx, HookNtOpenKeyEx);
		DetourAttach(&(PVOID&)OgNtQueryValueKey, HookNtQueryValueKey);
		DetourAttach(&(PVOID&)OgNtCreateKey, HookNtCreateKey);
		DetourAttach(&(PVOID&)OgNtEnumerateKey, HookNtEnumerateKey);
		DetourAttach(&(PVOID&)OgNtEnumerateValueKey, HookNtEnumerateValueKey);
		DetourAttach(&(PVOID&)OgNtCreateFile, HookNtCreateFile);
		DetourAttach(&(PVOID&)OgNtQueryAttributesFile, HookNtQueryAttributesFile);
		DetourAttach(&(PVOID&)OgNtDeviceIoControlFile, HookNtDeviceIoControlFile);
		DetourAttach(&(PVOID&)OgNtQueryVolumeInformationFile, HookNtQueryVolumeInformationFile);
		DetourAttach(&(PVOID&)OgNtQuerySystemInformation, HookNtQuerySystemInformation);
		DetourAttach(&(PVOID&)OgNtQuerySystemInformationEx, HookNtQuerySystemInformationEx);
		DetourAttach(&(PVOID&)OgNtPowerInformation, HookNtPowerInformation);
		DetourAttach(&(PVOID&)OgNtQueryLicenseValue, HookNtQueryLicenseValue);
		DetourAttach(&(PVOID&)OgNtQueryDirectoryFile, HookNtQueryDirectoryFile);
		DetourAttach(&(PVOID&)OgNtQueryInformationProcess, HookNtQueryInformationProcess);
		DetourAttach(&(PVOID&)OgNtQueryDirectoryObject, HookNtQueryDirectoryObject);
		DetourAttach(&(PVOID&)OgNtCreateMutant, HookNtCreateMutant);
		DetourAttach(&(PVOID&)OgNtOpenMutant, HookNtOpenMutant);
		DetourAttach(&(PVOID&)OgGetAdaptersAddresses, HookGetAdaptersAddresses);
		DetourAttach(&(PVOID&)OgProcess32FirstW, HookProcess32FirstW);
		DetourAttach(&(PVOID&)OgProcess32NextW, HookProcess32NextW);
		DetourAttach(&(PVOID&)OgCoCreateInstance, HookCoCreateInstance);
		DetourAttach(&(PVOID&)OgGetModuleHandleW, HookGetModuleHandleW);
		DetourAttach(&(PVOID&)OgGetModuleHandleA, HookGetModuleHandleA);
		DetourAttach(&(PVOID&)OgGetModuleHandleExW, HookGetModuleHandleExW);
		DetourAttach(&(PVOID&)OgGetModuleHandleExA, HookGetModuleHandleExA);
		DetourAttach(&(PVOID&)OgGetAdaptersInfo, HookGetAdaptersInfo);
		DetourAttach(&(PVOID&)OgSetupDiGetDeviceRegistryPropertyW, HookSetupDiGetDeviceRegistryPropertyW);
		DetourAttach(&(PVOID&)OgSetupDiGetDeviceRegistryPropertyA, HookSetupDiGetDeviceRegistryPropertyA);
		DetourAttach(&(PVOID&)OgGetLastInputInfo, HookGetLastInputInfo);
		DetourAttach(&(PVOID&)OgEnumServicesStatusExA, HookEnumServicesStatusExA);
		DetourAttach(&(PVOID&)OgEnumServicesStatusExW, HookEnumServicesStatusExW);
		DetourAttach(&(PVOID&)OgInternetCheckConnectionA, HookInternetCheckConnectionA);
		DetourAttach(&(PVOID&)OgInternetCheckConnectionW, HookInternetCheckConnectionW);
		DetourAttach(&(PVOID&)OgGetWindowRect, HookGetWindowRect);
		DetourAttach(&(PVOID&)OgGetMonitorInfoA, HookGetMonitorInfoA);
		DetourAttach(&(PVOID&)OgGetMonitorInfoW, HookGetMonitorInfoW);
		DetourAttach(&(PVOID&)OgFindWindowA, HookFindWindowA);
		DetourAttach(&(PVOID&)OgFindWindowW, HookFindWindowW);
		DetourAttach(&(PVOID&)OgFindWindowExA, HookFindWindowExA);
		DetourAttach(&(PVOID&)OgFindWindowExW, HookFindWindowExW);
		DetourAttach(&(PVOID&)OgGetCursorPos, HookGetCursorPos);
		DetourAttach(&(PVOID&)OgGetSystemMetrics, HookGetSystemMetrics);
		DetourAttach(&(PVOID&)OgSystemParametersInfoA, HookSystemParametersInfoA);
		DetourAttach(&(PVOID&)OgSystemParametersInfoW, HookSystemParametersInfoW);
		DetourAttach(&(PVOID&)OgGetAsyncKeyState, HookGetAsyncKeyState);
		DetourAttach(&(PVOID&)OgGetForegroundWindow, HookGetForegroundWindow);
		DetourAttach(&(PVOID&)OgLoadLibraryExW, HookLoadLibraryExW);
		DetourAttach(&(PVOID&)OgLoadLibraryExA, HookLoadLibraryExA);
		DetourAttach(&(PVOID&)OgLoadLibraryW, HookLoadLibraryW);
		DetourAttach(&(PVOID&)OgLoadLibraryA, HookLoadLibraryA);

		// activity
		DetourAttach(&(PVOID&)OgNtOpenFile, HookNtOpenFile);
		DetourAttach(&(PVOID&)OgNtReadFile, HookNtReadFile);
		DetourAttach(&(PVOID&)OgNtWriteFile, HookNtWriteFile);
		DetourAttach(&(PVOID&)OgNtDeleteFile, HookNtDeleteFile);
		DetourAttach(&(PVOID&)OgNtQueryInformationFile, HookNtQueryInformationFile);
		DetourAttach(&(PVOID&)OgNtSetInformationFile, HookNtSetInformationFile);
		DetourAttach(&(PVOID&)OgNtOpenDirectoryObject, HookNtOpenDirectoryObject);
		DetourAttach(&(PVOID&)OgNtCreateDirectoryObject, HookNtCreateDirectoryObject);
		DetourAttach(&(PVOID&)OgNtCreateUserProcess, HookNtCreateUserProcess);
		DetourAttach(&(PVOID&)OgNtCreateProcess, HookNtCreateProcess);
		DetourAttach(&(PVOID&)OgNtCreateProcessEx, HookNtCreateProcessEx);
		DetourAttach(&(PVOID&)OgNtSuspendProcess, HookNtSuspendProcess);
		DetourAttach(&(PVOID&)OgNtTerminateProcess, HookNtTerminateProcess);
		DetourAttach(&(PVOID&)OgNtMapViewOfSection, HookNtMapViewOfSection);
		DetourAttach(&(PVOID&)OgNtUnmapViewOfSection, HookNtUnmapViewOfSection);
		DetourAttach(&(PVOID&)OgNtMakeTemporaryObject, HookNtMakeTemporaryObject);
		DetourAttach(&(PVOID&)OgNtMakePermanentObject, HookNtMakePermanentObject);
		DetourAttach(&(PVOID&)OgNtWriteVirtualMemory, HookNtWriteVirtualMemory);
		DetourAttach(&(PVOID&)OgNtSetInformationProcess, HookNtSetInformationProcess);
		DetourAttach(&(PVOID&)OgNtGetNextProcess, HookNtGetNextProcess);
		DetourAttach(&(PVOID&)OgNtReplaceKey, HookNtReplaceKey);
		DetourAttach(&(PVOID&)OgNtRenameKey, HookNtRenameKey);
		DetourAttach(&(PVOID&)OgNtSaveKey, HookNtSaveKey);
		DetourAttach(&(PVOID&)OgNtSaveKeyEx, HookNtSaveKeyEx);
		DetourAttach(&(PVOID&)OgNtSetValueKey, HookNtSetValueKey);
		DetourAttach(&(PVOID&)OgNtDeleteKey, HookNtDeleteKey);
		DetourAttach(&(PVOID&)OgNtDeleteValueKey, HookNtDeleteValueKey);
		DetourAttach(&(PVOID&)OgNtOpenTimer, HookNtOpenTimer);
		DetourAttach(&(PVOID&)OgNtQueryTimer, HookNtQueryTimer);
		DetourAttach(&(PVOID&)OgNtCreateTimer, HookNtCreateTimer);
		DetourAttach(&(PVOID&)OgNtQuerySystemTime, HookNtQuerySystemTime);
		DetourAttach(&(PVOID&)OgNtOpenEvent, HookNtOpenEvent);
		DetourAttach(&(PVOID&)OgNtNotifyChangeKey, HookNtNotifyChangeKey);
		DetourAttach(&(PVOID&)OgNtOpenSemaphore, HookNtOpenSemaphore);
		DetourAttach(&(PVOID&)OgNtCreateSemaphore, HookNtCreateSemaphore);
		DetourAttach(&(PVOID&)OgNtLockFile, HookNtLockFile);
		DetourAttach(&(PVOID&)OgGetSystemTime, HookGetSystemTime);
		DetourAttach(&(PVOID&)OgGetLocalTime, HookGetLocalTime);
		DetourAttach(&(PVOID&)OgFindResourceExW, HookFindResourceExW);
		DetourAttach(&(PVOID&)OgFindResourceExA, HookFindResourceExA);

		// network activity
		DetourAttach(&(PVOID&)OgURLDownloadToFileW, HookURLDownloadToFileW);
		DetourAttach(&(PVOID&)OgInternetOpenA, HookInternetOpenA);
		DetourAttach(&(PVOID&)OgInternetConnectA, HookInternetConnectA);
		DetourAttach(&(PVOID&)OgInternetConnectW, HookInternetConnectW);
		DetourAttach(&(PVOID&)OgInternetOpenUrlA, HookInternetOpenUrlA);
		DetourAttach(&(PVOID&)OgHttpOpenRequestA, HookHttpOpenRequestA);
		DetourAttach(&(PVOID&)OgHttpOpenRequestW, HookHttpOpenRequestW);
		DetourAttach(&(PVOID&)OgHttpSendRequestA, HookHttpSendRequestA);
		DetourAttach(&(PVOID&)OgHttpSendRequestW, HookHttpSendRequestW);
		DetourAttach(&(PVOID&)OgInternetReadFile, HookInternetReadFile);
		DetourAttach(&(PVOID&)OgDnsQuery_A, HookDnsQuery_A);
		DetourAttach(&(PVOID&)OgDnsQuery_W, HookDnsQuery_W);
		DetourAttach(&(PVOID&)OgGetAddrInfoW, HookGetAddrInfoW);
		DetourAttach(&(PVOID&)OgWSAStartup, HookWSAStartup);
		DetourAttach(&(PVOID&)Oggethostbyname, Hookgethostbyname);
		DetourAttach(&(PVOID&)Ogsocket, Hooksocket);
		DetourAttach(&(PVOID&)Ogconnect, Hookconnect);
		DetourAttach(&(PVOID&)Ogsend, Hooksend);
		DetourAttach(&(PVOID&)Ogsendto, Hooksendto);
		DetourAttach(&(PVOID&)Ogrecv, Hookrecv);
		DetourAttach(&(PVOID&)Ogrecvfrom, Hookrecvfrom);
		DetourAttach(&(PVOID&)Ogbind, Hookbind);
		DetourAttach(&(PVOID&)OgWSARecv, HookWSARecv);
		DetourAttach(&(PVOID&)OgWSARecvFrom, HookWSARecvFrom);
		DetourAttach(&(PVOID&)OgWSASend, HookWSASend);
		DetourAttach(&(PVOID&)OgWSASendTo, HookWSASendTo);
		DetourAttach(&(PVOID&)OgWSASocketW, HookWSASocketW);

		// child process management
		DetourAttach(&(PVOID&)OgCreateProcessInternalW, HookCreateProcessInternalW);
#ifdef __32BIT_SYS
		DetourAttach(&(PVOID&)OgGetTickCount, HookGetTickCount);
#endif
		DetourAttach(&(PVOID&)OgNtDelayExecution, HookNtDelayExecution);
		DetourAttach(&(PVOID&)OgQueryPerformanceCounter, HookQueryPerformanceCounter);

		// thread test
		DetourAttach(&(PVOID&)OgNtCreateThread, HookNtCreateThread);
		DetourAttach(&(PVOID&)OgNtCreateThreadEx, HookNtCreateThreadEx);


		LONG err = DetourTransactionCommit();
		if (err != NO_ERROR) {
			fprintf(stderr, "DetourTransactionCommit FAILED\n");
			return FALSE;
		}

		// small test: NtQueryLicenseValue
		/*
		typedef VOID(NTAPI* ProtoRtlInitUnicodeString)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
		ProtoRtlInitUnicodeString OgRtlInitUnicodeString;
		OgRtlInitUnicodeString = (ProtoRtlInitUnicodeString)GetProcAddress(nt, "RtlInitUnicodeString");
		UNICODE_STRING LicenseValue;
		OgRtlInitUnicodeString(&LicenseValue, L"Kernel-VMDetection-Private");
		ULONG Result = 0, ReturnLength;
		NTSTATUS Status = HookNtQueryLicenseValue(&LicenseValue, NULL, reinterpret_cast<PVOID>(&Result), sizeof(ULONG), &ReturnLength);
		if (NT_SUCCESS(Status)) {
			printf("QueryLicenseValue Result = %lu\n", Result); // Result != 0
		}
		*/

		if ((dwTlsIndex = TlsAlloc()) == TLS_OUT_OF_INDEXES) {
			fprintf(stderr, "Fatal error: Out of TLX Indexes");
			return FALSE;
		}
#ifdef __DEBUG_PRINT
		printf("Created TLSIndex: %lu\n", dwTlsIndex);
#endif
	}
	// fall through !
	case DLL_THREAD_ATTACH:
	{
#ifdef __DEBUG_PRINT
		printf("Initialiazing TLS index for thread!\n");
#endif
		// init the TLS index for this thread.
		lpvData = (LPVOID)LocalAlloc(LPTR, sizeof(BOOL));
		if (lpvData != NULL) {
			TlsSetValue(dwTlsIndex, lpvData);
		}
		break;
	}
	case DLL_THREAD_DETACH:
	{
		// free memory for TLS index for this thread.
		lpvData = TlsGetValue(dwTlsIndex);
		if (lpvData != NULL)
			LocalFree((HLOCAL)lpvData);
		break;
	}
	case DLL_PROCESS_DETACH:
	{
		// cleanup
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		DetourDetach(&(PVOID&)OgNtOpenKey, HookNtOpenKey);
		DetourDetach(&(PVOID&)OgNtOpenKeyEx, HookNtOpenKeyEx);
		DetourDetach(&(PVOID&)OgNtQueryValueKey, HookNtQueryValueKey);
		DetourDetach(&(PVOID&)OgNtCreateKey, HookNtCreateKey);
		DetourDetach(&(PVOID&)OgNtEnumerateKey, HookNtEnumerateKey);
		DetourDetach(&(PVOID&)OgNtEnumerateValueKey, HookNtEnumerateValueKey);
		DetourDetach(&(PVOID&)OgNtCreateFile, HookNtCreateFile);
		DetourDetach(&(PVOID&)OgNtQueryAttributesFile, HookNtQueryAttributesFile);
		DetourDetach(&(PVOID&)OgNtDeviceIoControlFile, HookNtDeviceIoControlFile);
		DetourDetach(&(PVOID&)OgNtQueryVolumeInformationFile, HookNtQueryVolumeInformationFile);
		DetourDetach(&(PVOID&)OgNtQuerySystemInformation, HookNtQuerySystemInformation);
		DetourDetach(&(PVOID&)OgNtQuerySystemInformationEx, HookNtQuerySystemInformationEx);
		DetourDetach(&(PVOID&)OgNtPowerInformation, HookNtPowerInformation);
		DetourDetach(&(PVOID&)OgNtQueryLicenseValue, HookNtQueryLicenseValue);
		DetourDetach(&(PVOID&)OgNtQueryDirectoryFile, HookNtQueryDirectoryFile);
		DetourDetach(&(PVOID&)OgNtQueryInformationProcess, HookNtQueryInformationProcess);
		DetourDetach(&(PVOID&)OgNtQueryDirectoryObject, HookNtQueryDirectoryObject);
		DetourDetach(&(PVOID&)OgNtCreateMutant, HookNtCreateMutant);
		DetourDetach(&(PVOID&)OgNtOpenMutant, HookNtOpenMutant);
		DetourDetach(&(PVOID&)OgGetAdaptersAddresses, HookGetAdaptersAddresses);
		DetourDetach(&(PVOID&)OgProcess32FirstW, HookProcess32FirstW);
		DetourDetach(&(PVOID&)OgProcess32NextW, HookProcess32NextW);
		DetourDetach(&(PVOID&)OgCoCreateInstance, HookCoCreateInstance);
		DetourDetach(&(PVOID&)OgGetModuleHandleW, HookGetModuleHandleW);
		DetourDetach(&(PVOID&)OgGetModuleHandleA, HookGetModuleHandleA);
		DetourDetach(&(PVOID&)OgGetModuleHandleExW, HookGetModuleHandleExW);
		DetourDetach(&(PVOID&)OgGetModuleHandleExA, HookGetModuleHandleExA);
		//DetourDetach(&(PVOID&)OgGetTickCount, HookGetTickCount);
		DetourDetach(&(PVOID&)OgGetAdaptersInfo, HookGetAdaptersInfo);
		DetourDetach(&(PVOID&)OgSetupDiGetDeviceRegistryPropertyW, HookSetupDiGetDeviceRegistryPropertyW);
		DetourDetach(&(PVOID&)OgSetupDiGetDeviceRegistryPropertyA, HookSetupDiGetDeviceRegistryPropertyA);
		DetourDetach(&(PVOID&)OgGetLastInputInfo, HookGetLastInputInfo);
		DetourDetach(&(PVOID&)OgEnumServicesStatusExA, HookEnumServicesStatusExA);
		DetourDetach(&(PVOID&)OgEnumServicesStatusExW, HookEnumServicesStatusExW);
		DetourDetach(&(PVOID&)OgInternetCheckConnectionA, HookInternetCheckConnectionA);
		DetourDetach(&(PVOID&)OgInternetCheckConnectionW, HookInternetCheckConnectionW);
		DetourDetach(&(PVOID&)OgGetWindowRect, HookGetWindowRect);
		DetourDetach(&(PVOID&)OgGetMonitorInfoA, HookGetMonitorInfoA);
		DetourDetach(&(PVOID&)OgGetMonitorInfoW, HookGetMonitorInfoW);
		DetourDetach(&(PVOID&)OgFindWindowA, HookFindWindowA);
		DetourDetach(&(PVOID&)OgFindWindowW, HookFindWindowW);
		DetourDetach(&(PVOID&)OgFindWindowExA, HookFindWindowExA);
		DetourDetach(&(PVOID&)OgFindWindowExW, HookFindWindowExW);
		DetourDetach(&(PVOID&)OgGetCursorPos, HookGetCursorPos);
		DetourDetach(&(PVOID&)OgGetSystemMetrics, HookGetSystemMetrics);
		DetourDetach(&(PVOID&)OgSystemParametersInfoA, HookSystemParametersInfoA);
		DetourDetach(&(PVOID&)OgSystemParametersInfoW, HookSystemParametersInfoW);
		DetourDetach(&(PVOID&)OgGetAsyncKeyState, HookGetAsyncKeyState);
		DetourDetach(&(PVOID&)OgGetForegroundWindow, HookGetForegroundWindow);
		DetourDetach(&(PVOID&)OgLoadLibraryExW, HookLoadLibraryExW);
		DetourDetach(&(PVOID&)OgLoadLibraryExA, HookLoadLibraryExA);
		DetourDetach(&(PVOID&)OgLoadLibraryW, HookLoadLibraryW);
		DetourDetach(&(PVOID&)OgLoadLibraryA, HookLoadLibraryA);

		DetourDetach(&(PVOID&)OgNtOpenFile, HookNtOpenFile);
		DetourDetach(&(PVOID&)OgNtReadFile, HookNtReadFile);
		DetourDetach(&(PVOID&)OgNtWriteFile, HookNtWriteFile);
		DetourDetach(&(PVOID&)OgNtDeleteFile, HookNtDeleteFile);
		DetourDetach(&(PVOID&)OgNtQueryInformationFile, HookNtQueryInformationFile);
		DetourDetach(&(PVOID&)OgNtSetInformationFile, HookNtSetInformationFile);
		DetourDetach(&(PVOID&)OgNtOpenDirectoryObject, HookNtOpenDirectoryObject);
		DetourDetach(&(PVOID&)OgNtCreateDirectoryObject, HookNtCreateDirectoryObject);
		DetourDetach(&(PVOID&)OgNtCreateUserProcess, HookNtCreateUserProcess);
		DetourDetach(&(PVOID&)OgNtCreateProcess, HookNtCreateProcess);
		DetourDetach(&(PVOID&)OgNtCreateProcessEx, HookNtCreateProcessEx);
		DetourDetach(&(PVOID&)OgNtSuspendProcess, HookNtSuspendProcess);
		DetourDetach(&(PVOID&)OgNtTerminateProcess, HookNtTerminateProcess);
		DetourDetach(&(PVOID&)OgNtMapViewOfSection, HookNtMapViewOfSection);
		DetourDetach(&(PVOID&)OgNtUnmapViewOfSection, HookNtUnmapViewOfSection);
		DetourDetach(&(PVOID&)OgNtMakeTemporaryObject, HookNtMakeTemporaryObject);
		DetourDetach(&(PVOID&)OgNtMakePermanentObject, HookNtMakePermanentObject);
		DetourDetach(&(PVOID&)OgNtWriteVirtualMemory, HookNtWriteVirtualMemory);
		DetourDetach(&(PVOID&)OgNtSetInformationProcess, HookNtSetInformationProcess);
		DetourDetach(&(PVOID&)OgNtGetNextProcess, HookNtGetNextProcess);
		DetourDetach(&(PVOID&)OgNtReplaceKey, HookNtReplaceKey);
		DetourDetach(&(PVOID&)OgNtRenameKey, HookNtRenameKey);
		DetourDetach(&(PVOID&)OgNtSaveKey, HookNtSaveKey);
		DetourDetach(&(PVOID&)OgNtSaveKeyEx, HookNtSaveKeyEx);
		DetourDetach(&(PVOID&)OgNtSetValueKey, HookNtSetValueKey);
		DetourDetach(&(PVOID&)OgNtDeleteKey, HookNtDeleteKey);
		DetourDetach(&(PVOID&)OgNtDeleteValueKey, HookNtDeleteValueKey);
		DetourDetach(&(PVOID&)OgNtOpenTimer, HookNtOpenTimer);
		DetourDetach(&(PVOID&)OgNtQueryTimer, HookNtQueryTimer);
		DetourDetach(&(PVOID&)OgNtCreateTimer, HookNtCreateTimer);
		DetourDetach(&(PVOID&)OgNtQuerySystemTime, HookNtQuerySystemTime);
		DetourDetach(&(PVOID&)OgNtOpenEvent, HookNtOpenEvent);
		DetourDetach(&(PVOID&)OgNtNotifyChangeKey, HookNtNotifyChangeKey);
		DetourDetach(&(PVOID&)OgNtOpenSemaphore, HookNtOpenSemaphore);
		DetourDetach(&(PVOID&)OgNtCreateSemaphore, HookNtCreateSemaphore);
		DetourDetach(&(PVOID&)OgNtLockFile, HookNtLockFile);
		DetourDetach(&(PVOID&)OgGetSystemTime, HookGetSystemTime);
		DetourDetach(&(PVOID&)OgGetLocalTime, HookGetLocalTime);
		DetourDetach(&(PVOID&)OgFindResourceExW, HookFindResourceExW);
		DetourDetach(&(PVOID&)OgFindResourceExA, HookFindResourceExA);

		// network
		DetourDetach(&(PVOID&)OgURLDownloadToFileW, HookURLDownloadToFileW);
		DetourDetach(&(PVOID&)OgInternetOpenA, HookInternetOpenA);
		DetourDetach(&(PVOID&)OgInternetConnectA, HookInternetConnectA);
		DetourDetach(&(PVOID&)OgInternetConnectW, HookInternetConnectW);
		DetourDetach(&(PVOID&)OgInternetOpenUrlA, HookInternetOpenUrlA);
		DetourDetach(&(PVOID&)OgHttpOpenRequestA, HookHttpOpenRequestA);
		DetourDetach(&(PVOID&)OgHttpOpenRequestW, HookHttpOpenRequestW);
		DetourDetach(&(PVOID&)OgHttpSendRequestA, HookHttpSendRequestA);
		DetourDetach(&(PVOID&)OgHttpSendRequestW, HookHttpSendRequestW);
		DetourDetach(&(PVOID&)OgInternetReadFile, HookInternetReadFile);
		DetourDetach(&(PVOID&)OgDnsQuery_A, HookDnsQuery_A);
		DetourDetach(&(PVOID&)OgDnsQuery_W, HookDnsQuery_W);
		DetourDetach(&(PVOID&)OgGetAddrInfoW, HookGetAddrInfoW);
		DetourDetach(&(PVOID&)OgWSAStartup, HookWSAStartup);
		DetourDetach(&(PVOID&)Oggethostbyname, Hookgethostbyname);
		DetourDetach(&(PVOID&)Ogsocket, Hooksocket);
		DetourDetach(&(PVOID&)Ogconnect, Hookconnect);
		DetourDetach(&(PVOID&)Ogsend, Hooksend);
		DetourDetach(&(PVOID&)Ogsendto, Hooksendto);
		DetourDetach(&(PVOID&)Ogrecv, Hookrecv);
		DetourDetach(&(PVOID&)Ogrecvfrom, Hookrecvfrom);
		DetourDetach(&(PVOID&)Ogbind, Hookbind);
		DetourDetach(&(PVOID&)OgWSARecv, HookWSARecv);
		DetourDetach(&(PVOID&)OgWSARecvFrom, HookWSARecvFrom);
		DetourDetach(&(PVOID&)OgWSASend, HookWSASend);
		DetourDetach(&(PVOID&)OgWSASendTo, HookWSASendTo);
		DetourDetach(&(PVOID&)OgWSASocketW, HookWSASocketW);


		DetourDetach(&(PVOID&)OgCreateProcessInternalW, HookCreateProcessInternalW);
		DetourDetach(&(PVOID&)OgNtCreateThread, HookNtCreateThread);
		DetourDetach(&(PVOID&)OgNtCreateThreadEx, HookNtCreateThreadEx);
#ifdef __32BIT_SYS
		DetourDetach(&(PVOID&)OgGetTickCount, HookGetTickCount);
#endif
		DetourDetach(&(PVOID&)OgNtDelayExecution, HookNtDelayExecution);
		DetourDetach(&(PVOID&)OgQueryPerformanceCounter, HookQueryPerformanceCounter);

		DetourTransactionCommit();

		CloseHandle(hPipe);

		// Release the allocated memory for this thread.
		lpvData = TlsGetValue(dwTlsIndex);
		if (lpvData != NULL)
			LocalFree((HLOCAL)lpvData);

		// Release the TLS index.
		TlsFree(dwTlsIndex);
	}
	default: break;
	} // end switch

	return TRUE;
}

