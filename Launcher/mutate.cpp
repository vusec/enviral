#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include <conio.h>
#include "communication.h"
#include "fuzz.h"
#include "mutate.h"
#include <Shlwapi.h>

BOOL GenPreventiveMutationsAll()
{
	Recording rec;
	rec.origin = 0;
	MutationType mutType;
	MutationValue mutVal;

	/* Apply-all-observe-behavior-change phase; contexts: */

	// cNtOpenKey:	MUT_FAIL -> Ctx "VBox", "Virtual"	Ret STATUS_OBJECT_NAME_NOT_FOUND
	rec.call = Call::cNtOpenKey;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"virtual");
	mutType = MUT_FAIL;
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);

	// cNtOpenKeyEx: MUT_FAIL -> Ctx "VBox", "Virtual"	Ret STATUS_OBJECT_NAME_NOT_FOUND
	rec.call = Call::cNtOpenKeyEx;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"virtual");
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);

	// cNtQueryValueKey: MUT_ALT_STR -> Ctx "VBox", "Virtual"
	rec.call = Call::cNtQueryValueKey;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_ALT_STR;
	wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"Bolt");
	AddMutationToList(&rec, &mutType, &mutVal);
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"virtual");
	AddMutationToList(&rec, &mutType, &mutVal);
	
	// cNtCreateKey: MUT_ALT_NUM -> Ctx "VBox", "Virtual"	Num 1
	rec.call = Call::cNtCreateKey;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_ALT_NUM;
	mutVal.nValue = 1; // Disposition == new key created
	AddMutationToList(&rec, &mutType, &mutVal);
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"virtual");
	AddMutationToList(&rec, &mutType, &mutVal);
	
	// cNtEnumerateKey: MUT_ALT_STR -> Ctx "VBox", "Virtual"
	rec.call = Call::cNtEnumerateKey;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_ALT_STR;
	wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"Bolt");
	AddMutationToList(&rec, &mutType, &mutVal);
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"virtual");
	AddMutationToList(&rec, &mutType, &mutVal);

	// cNtEnumerateValueKey: MUT_ALT_STR -> Ctx "VBox", "Virtual"
	rec.call = Call::cNtEnumerateValueKey;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_ALT_STR;
	wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"Bolt");
	AddMutationToList(&rec, &mutType, &mutVal);
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"virtual");
	AddMutationToList(&rec, &mutType, &mutVal);

	// cNtCreateFile: MUT_FAIL -> Ctx "VBox"	Ret STATUS_OBJECT_NAME_NOT_FOUND
	rec.call = Call::cNtCreateFile;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);

	// cNtQueryAttributesFile: MUT_FAIL -> Ctx "VBox"	Ret STATUS_OBJECT_NAME_NOT_FOUND
	rec.call = Call::cNtQueryAttributesFile;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);

	// cNtDeviceIoControlFile: MUT_ALT_NUM -> NO Ctx	Num 512
	rec.call = Call::cNtDeviceIoControlFile;
	rec.value.dwCtx = 0x7405c; // IOCTL_DISK_GET_LENGTH_INFO
	mutType = MUT_ALT_NUM;
	mutVal.nValue = 1024; // Disk size in GB
	AddMutationToList(&rec, &mutType, &mutVal);

	// cNtQueryVolumeInformationFile: MUT_ALT_NUM -> NO Ctx	Num (multiplies current size -- match with ^)
	rec.call = Call::cNtQueryVolumeInformationFile;
	rec.value.dwCtx = 3; // FileFsDeviceInformation
	mutType = MUT_ALT_NUM;
	mutVal.nValue = 2; // Disk size multiplier
	AddMutationToList(&rec, &mutType, &mutVal);

	// cNtQuerySystemInformation: MUT_ALT_NUM -> Ctx SystemBasicInformation	Num 8 MUT_HIDE SystemModuleInformation (11) & SystemProcessInformation
	rec.call = Call::cNtQuerySystemInformation;
	rec.value.dwCtx = 0; // SystemBasicInformation
	mutType = MUT_ALT_NUM;
	mutVal.nValue = 8; // Number of logical processors 
	AddMutationToList(&rec, &mutType, &mutVal);
	rec.value.dwCtx = 11; // SystemModuleInformation
	mutType = MUT_HIDE;
	AddMutationToList(&rec, &mutType, NULL);
	rec.value.dwCtx = 5; // SystemProcessInformation
	mutType = MUT_HIDE;
	AddMutationToList(&rec, &mutType, NULL);

	// cNtPowerInformation: MUT_SUCCEED -> NO Ctx NO Val
	rec.call = Call::cNtPowerInformation;
	mutType = MUT_SUCCEED;
	AddMutationToList(&rec, &mutType, NULL);

	// cNtQueryLicenseValue: MUT_SUCCEED -> Ctx1 L"Security-SPP-GenuineLocalStatus" Num 1 Ctx2 L"Kernel-VMDetection-Private" Num 0
	rec.call = Call::cNtQueryLicenseValue;
	rec.type = CTX_STR;
	mutType = MUT_SUCCEED;
	mutVal.nValue = 1; // genuine
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"Security-SPP-GenuineLocalStatus");
	AddMutationToList(&rec, &mutType, &mutVal);
	mutVal.nValue = 0; // no VM
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"Kernel-VMDetection-Private");
	AddMutationToList(&rec, &mutType, &mutVal);

	// cNtQueryDirectoryFile: MUT_FAIL -> Ctx "VBox" Ret STATUS_NO_SUCH_FILE
	rec.call = Call::cNtQueryDirectoryFile;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	mutVal.nValue = 0xC000000F; // STATUS_NO_SUCH_FILE
	AddMutationToList(&rec, &mutType, &mutVal);

	// cNtQueryInformationProcess: MUT_HIDE -> NO Ctx NO Val
	rec.call = Call::cNtQueryInformationProcess;
	rec.value.dwCtx = 0; // ProcessBasicInformation;
	mutType = MUT_HIDE;
	AddMutationToList(&rec, &mutType, NULL);
	
	// cGetAdaptersAddresses: MUT_ALT_STR -> NO Ctx
	rec.call = Call::cGetAdaptersAddresses;
	mutType = MUT_ALT_STR;
	wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"\x10\x04\x5a"); // fake MAC
	AddMutationToList(&rec, &mutType, &mutVal);

	// cProcess32FirstW: MUT_HIDE -> NO Ctx NO Val
	rec.call = Call::cProcess32FirstW;
	mutType = MUT_HIDE;
	AddMutationToList(&rec, &mutType, NULL);

	// cProcess32NextW: MUT_HIDE -> NO Ctx NO Val
	rec.call = Call::cProcess32NextW;
	mutType = MUT_HIDE;
	AddMutationToList(&rec, &mutType, NULL);

	// cGetAdaptersInfo: MUT_ALT_STR -> NO Ctx
	rec.call = Call::cGetAdaptersInfo;
	mutType = MUT_ALT_STR;
	wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"\x10\x04\x5a"); // fake MAC
	AddMutationToList(&rec, &mutType, &mutVal);

	// cSetupDiGetDeviceRegistryPropertyW: MUT_ALT_STR -> NO Ctx
	rec.call = Call::cSetupDiGetDeviceRegistryPropertyW;
	mutType = MUT_ALT_STR;
	wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"DEVICE\\BOLT"); // fake device
	AddMutationToList(&rec, &mutType, &mutVal);

	// cSetupDiGetDeviceRegistryPropertyA: MUT_ALT_STR -> NO Ctx
	rec.call = Call::cSetupDiGetDeviceRegistryPropertyA;
	mutType = MUT_ALT_STR;
	wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"DEVICE\\BOLT"); // fake device (assumes wide)
	AddMutationToList(&rec, &mutType, &mutVal);

	// cGetLastInputInfo: MUT_SUCCEED -> NO Ctx
	rec.call = Call::cGetLastInputInfo;
	mutType = MUT_SUCCEED;
	AddMutationToList(&rec, &mutType, NULL);

	// cEnumServicesStatusExA: MUT_HIDE -> NO Ctx
	rec.call = Call::cEnumServicesStatusExA;
	mutType = MUT_HIDE;
	AddMutationToList(&rec, &mutType, NULL);

	// cEnumServicesStatusExW: MUT_HIDE -> NO Ctx
	rec.call = Call::cEnumServicesStatusExW;
	mutType = MUT_HIDE;
	AddMutationToList(&rec, &mutType, NULL);

	// cInternetCheckConnectionA: MUT_SUCCEED -> NO Ctx
	rec.call = Call::cInternetCheckConnectionA;
	mutType = MUT_SUCCEED;
	AddMutationToList(&rec, &mutType, NULL);

	// cInternetCheckConnectionW: MUT_SUCCEED -> NO Ctx
	rec.call = Call::cInternetCheckConnectionW;
	mutType = MUT_SUCCEED;
	AddMutationToList(&rec, &mutType, NULL);

	// cFindWindowA: MUT_FAIL -> Ctx "VBox"
	rec.call = Call::cFindWindowA;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	AddMutationToList(&rec, &mutType, NULL);

	// cFindWindowW: MUT_FAIL -> Ctx "VBox"
	rec.call = Call::cFindWindowW;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	AddMutationToList(&rec, &mutType, NULL);

	// cFindWindowExA: MUT_FAIL -> Ctx "VBox"
	rec.call = Call::cFindWindowExA;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	AddMutationToList(&rec, &mutType, NULL);

	// cFindWindowExW: MUT_FAIL -> Ctx "VBox"
	rec.call = Call::cFindWindowExW;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	AddMutationToList(&rec, &mutType, NULL);

	// cGetCursorPos: MUT_RND_TUP -> NO Ctx
	rec.call = Call::cGetCursorPos;
	mutType = MUT_RND_TUP;
	AddMutationToList(&rec, &mutType, NULL);

	// cGetAsyncKeyState: MUT_SUCCEED -> NO Ctx [maybe skip]?
	rec.call = Call::cGetAsyncKeyState;
	mutType = MUT_SUCCEED;
	AddMutationToList(&rec, &mutType, NULL);

	// cGetForegroundWindow: MUT_RND_NUM -> NO Ctx
	rec.call = Call::cGetForegroundWindow;
	mutType = MUT_RND_NUM;
	AddMutationToList(&rec, &mutType, NULL);

	// cLoadLibraryExW: MUT_FAIL -> Ctx "VBox", "Virtual"	Ret STATUS_OBJECT_NAME_NOT_FOUND
	rec.call = Call::cLoadLibraryExW;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"virtual");
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);

	// cLoadLibraryExW: MUT_FAIL -> Ctx "VBox", "Virtual"	Ret STATUS_OBJECT_NAME_NOT_FOUND
	rec.call = Call::cLoadLibraryExA;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"virtual");
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);

	// cLoadLibraryW: MUT_FAIL -> Ctx "VBox", "Virtual"	Ret STATUS_OBJECT_NAME_NOT_FOUND
	rec.call = Call::cLoadLibraryW;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"virtual");
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);

	// cLoadLibraryA: MUT_FAIL -> Ctx "VBox", "Virtual"	Ret STATUS_OBJECT_NAME_NOT_FOUND
	rec.call = Call::cLoadLibraryA;
	rec.type = CTX_SUB;
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"vbox");
	mutType = MUT_FAIL;
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);
	wcscpy_s(rec.value.szCtx, MAX_CTX_LEN, L"virtual");
	mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
	AddMutationToList(&rec, &mutType, &mutVal);

#ifdef __DEBUG_PRINT
	printf("All mutations generated\n");
#endif
	return NULL;
}

void MoreSensitiveMutations()
{
	// cNtCreateMutant: MUT_SUCCEED -> Ctx *.* [maybe skip]
	// cNtOpenMutant: MUT_FAIL -> Ctx *.* Ret STATUS_OBJECT_NAME_NOT_FOUND [maybe skip]
}

RecordList* GenerateResponsiveVolatileMutation(Execution* exec, RecordList* start, LONG* index) {
	exec->mutStore = GetCurrentMutation();

	RecordList* entry;
	if (start != NULL) {
		// continue where we left off since the last mutation was gainless
		entry = start;
	}
	else {
		// start at the head, this is a fresh execution
		entry = exec->recordings[*index].recHead;
	}

	/*
	case cNtOpenMutant:
		// mut
		if (MutationExists(&entry->rec)) break;
		mutType = MUT_FAIL;
		mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
		AddMutationToList(&entry->rec, &mutType, &mutVal);
		printf("Vol. Mutex Mutation: %ws\n", entry->rec.value.szCtx);
		return entry;
	*/

	MutationType mutType;
	MutationValue mutVal;

	while (TRUE) {
		while (entry != NULL) {

			if (entry->rec.call > CALL_SEPARATOR) {
				entry = entry->next;
				continue;
			}

			// all calls need to be checked for existing mutations
			if (MutationExists(&entry->rec)) {
				entry = entry->next;
				continue;
			}

			/*
			check for expansion ctx:
			cSetupDiGetDeviceRegistryPropertyW/A	-> ctx: Property
			*/

			switch (entry->rec.call) {
				case Call::cNtOpenKey:
				case Call::cNtOpenKeyEx:
				case Call::cNtCreateFile:
				case Call::cNtQueryAttributesFile:
				case Call::cNtOpenMutant:
					mutType = MUT_FAIL;
					mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return entry;

				case Call::cNtQueryValueKey:
				case Call::cNtEnumerateKey:
				case Call::cNtEnumerateValueKey:
					mutType = MUT_ALT_STR;
					wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"Blue");
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return entry;

				case Call::cNtCreateKey:
					mutType = MUT_ALT_NUM;
					mutVal.nValue = 1; // Disposition == new key created
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return entry;

				case Call::cNtQuerySystemInformation:
				case Call::cCoCreateInstance:
				//case Call::cGetModuleHandleW:
				//case Call::cGetModuleHandleA:
				//case Call::cGetModuleHandleExW:
				//case Call::cGetModuleHandleExA:
				case Call::cFindWindowA:
				case Call::cFindWindowW:
				case Call::cFindWindowExA:
				case Call::cFindWindowExW:
				//case Call::cGetSystemMetrics:
				//case Call::cSystemParametersInfoA:
				//case Call::cSystemParametersInfoW:
					// generic fail
					mutType = MUT_FAIL;
					AddMutationToList(&entry->rec, &mutType, NULL);
					return entry;

				case Call::cNtDeviceIoControlFile:
					if (entry->rec.value.dwCtx != 0x7405c) {
						mutType = MUT_FAIL;
						AddMutationToList(&entry->rec, &mutType, NULL);
						return entry;
					}
					break;

				case Call::cNtQueryVolumeInformationFile:
					if (entry->rec.value.dwCtx != 3) {
						mutType = MUT_FAIL;
						AddMutationToList(&entry->rec, &mutType, NULL);
						return entry;
					}
					break;

				case Call::cNtQueryInformationProcess:
					if (entry->rec.value.dwCtx != 0 && entry->rec.value.dwCtx != 36) { // hide & windows dep.
						mutType = MUT_FAIL;
						AddMutationToList(&entry->rec, &mutType, NULL);
						return entry;
					}
					break;

				case Call::cNtQueryLicenseValue:
					mutType = MUT_FAIL;
					mutVal.nValue = STATUS_INVALID_PARAMETER; 
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return entry;

				case Call::cNtQueryDirectoryFile:
					mutType = MUT_FAIL;
					mutVal.nValue = 0xC000000F; // STATUS_NO_SUCH_FILE;
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					return entry;

				case Call::cNtCreateMutant:
					mutType = MUT_SUCCEED;
					AddMutationToList(&entry->rec, &mutType, NULL);
					return entry;
			}

			entry = entry->next;
		}
		
		// move to next process
		(*index)++;
		if (*index > exec->RecIndex) {
			break;
		}
		entry = exec->recordings[*index].recHead;
	}

	return NULL;
}

BOOL GenerateResponsiveMutationsAll(Execution* exec) {
	/*
	For every recording, apply all 'safe' mutations if the CTX matches
	This is a forward-only principle.
	Activity gain does not interfere.
	Mutations are not backtracked.
	
	Keep executing while new mutations can be made (i.e., new recordings for mutations found)
	Measure the activity gain for info regardless
	Experiment is testing the practicality of the fuzzing engine: repeated restarts 
	*/
	exec->mutStore = GetCurrentMutation();

	// alternatively, we can compare mutCurr before and after
	BOOL NewMutation = FALSE;

	MutationType mutType;
	MutationValue mutVal;
	RecordList* entry;
	LONG i;
	for (i = 0; i <= exec->RecIndex; i++) {
		entry = exec->recordings[i].recHead;
		while (entry != NULL) {

			// skip non-evasive calls
			if (entry->rec.call > CALL_SEPARATOR) {
				entry = entry->next;
				continue;
			}

			switch (entry->rec.call) {
			case Call::cNtOpenKey:
			case Call::cNtOpenKeyEx:
			case Call::cLoadLibraryExW:
			case Call::cLoadLibraryExA:
			case Call::cLoadLibraryA:
			case Call::cLoadLibraryW:
				// MUT_FAIL -> Ctx "VBox", "Virtual"	Ret STATUS_OBJECT_NAME_NOT_FOUND
				if (StrStrIW(entry->rec.value.szCtx, L"vbox") || StrStrIW(entry->rec.value.szCtx, L"virtual")) {
					// evaluate the ctx first, because its cheaper and frequently evaluates to false 
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_FAIL;
					mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					NewMutation = TRUE;
				}
				break;
			case Call::cNtQueryValueKey:
			case Call::cNtEnumerateKey:
			case Call::cNtEnumerateValueKey:
				// MUT_ALT_STR -> Ctx "VBox", "Virtual"
				if (StrStrIW(entry->rec.value.szCtx, L"vbox") || StrStrIW(entry->rec.value.szCtx, L"virtual")) {
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_ALT_STR;
					wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"Bolt");
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					NewMutation = TRUE;
				}
				break;
			case Call::cNtCreateKey:
				// MUT_ALT_NUM -> Ctx "VBox", "Virtual"	Num 1
				if (StrStrIW(entry->rec.value.szCtx, L"vbox") || StrStrIW(entry->rec.value.szCtx, L"virtual")) {
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_ALT_NUM;
					mutVal.nValue = 1; // Disposition == new key created
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					NewMutation = TRUE;
				}
				break;
			case Call::cNtCreateFile:
			case Call::cNtQueryAttributesFile:
			case Call::cFindWindowA:
			case Call::cFindWindowW:
			case Call::cFindWindowExA:
			case Call::cFindWindowExW:
				// MUT_FAIL -> Ctx "VBox"	Ret STATUS_OBJECT_NAME_NOT_FOUND
				if (StrStrIW(entry->rec.value.szCtx, L"vbox")) {
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_FAIL;
					mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					NewMutation = TRUE;
				}
				break;
			case Call::cNtDeviceIoControlFile:
				// MUT_ALT_NUM -> Ctx	0x7405c (IOCTL_DISK_GET_LENGTH_INFO) Num 1024
				if (entry->rec.value.dwCtx == 0x7405c) { // IOCTL_DISK_GET_LENGTH_INFO
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_ALT_NUM;
					mutVal.nValue = 1024; // Disk size in GB
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					NewMutation = TRUE;
				}
				break;
			case Call::cNtQueryVolumeInformationFile:
				// MUT_ALT_NUM -> Ctx	FileFsDeviceInformation	Num (multiplies current size -- match with ^)
				if (entry->rec.value.dwCtx == 3) { // FileFsDeviceInformation
					if (!MutationExists(&entry->rec)) {
						mutType = MUT_ALT_NUM;
						mutVal.nValue = 2; // Disk size multiplier
						AddMutationToList(&entry->rec, &mutType, &mutVal);
						NewMutation = TRUE;
					}
				}
				break;
			case Call::cNtQuerySystemInformation:
				// MUT_ALT_NUM -> Ctx SystemBasicInformation	Num 8 MUT_HIDE SystemModuleInformation (11) & SystemProcessInformation
				if (entry->rec.value.dwCtx == 0) { // SystemBasicInformation
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_ALT_NUM;
					mutVal.nValue = 8; // Number of logical processors 
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					NewMutation = TRUE;
				}
				else if (entry->rec.value.dwCtx == 11 || entry->rec.value.dwCtx == 5) { // SystemModuleInformation || SystemProcessInformation
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_HIDE;
					AddMutationToList(&entry->rec, &mutType, NULL);
					NewMutation = TRUE;
				}
				break;
			case Call::cNtPowerInformation:
			case Call::cGetLastInputInfo:
			case Call::cInternetCheckConnectionA:
			case Call::cInternetCheckConnectionW:
			case Call::cGetAsyncKeyState:
				// MUT_SUCCEED -> NO Ctx NO Val
				if (!MutationExists(&entry->rec)) {
					mutType = MUT_SUCCEED;
					AddMutationToList(&entry->rec, &mutType, NULL);
					NewMutation = TRUE;
				}
				break;
			case Call::cNtQueryLicenseValue:
				// MUT_SUCCEED -> Ctx1 L"Security-SPP-GenuineLocalStatus" Num 1 Ctx2 L"Kernel-VMDetection-Private" Num 0
				if (wcscmp(entry->rec.value.szCtx, L"Security-SPP-GenuineLocalStatus") == 0) {
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_SUCCEED;
					mutVal.nValue = 1; // genuine
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					NewMutation = TRUE;
				}
				else if (wcscmp(entry->rec.value.szCtx, L"Kernel-VMDetection-Private") == 0) {
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_SUCCEED;
					mutVal.nValue = 0; // no VM
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					NewMutation = TRUE;
				}
				break;
			case Call::cNtQueryDirectoryFile:
				// MUT_FAIL -> Ctx "VBox" Ret STATUS_NO_SUCH_FILE
				if (StrStrIW(entry->rec.value.szCtx, L"vbox")) {
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_FAIL;
					mutVal.nValue = 0xC000000F; // STATUS_NO_SUCH_FILE
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					NewMutation = TRUE;
				}
				break;
			case Call::cNtQueryInformationProcess:
				if (entry->rec.value.dwCtx == 0) { // ProcessBasicInformation
					if (MutationExists(&entry->rec)) break;
					mutType = MUT_HIDE;
					AddMutationToList(&entry->rec, &mutType, NULL);
					NewMutation = TRUE;
				}
				break;
			case Call::cProcess32FirstW:
			case Call::cProcess32NextW:
			case Call::cEnumServicesStatusExA:
			case Call::cEnumServicesStatusExW:
				// MUT_HIDE -> NO Ctx NO Val
				if (!MutationExists(&entry->rec)) {
					mutType = MUT_HIDE;
					AddMutationToList(&entry->rec, &mutType, NULL);
					NewMutation = TRUE;
				}
				break;
			case Call::cGetAdaptersAddresses:
			case Call::cGetAdaptersInfo:
				// MUT_ALT_STR -> NO Ctx
				if (!MutationExists(&entry->rec)) {
					mutType = MUT_ALT_STR;
					wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"\x10\x04\x5a"); // fake MAC
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					NewMutation = TRUE;
				}
				break;
			case Call::cSetupDiGetDeviceRegistryPropertyW:
			case Call::cSetupDiGetDeviceRegistryPropertyA:
				// MUT_ALT_STR -> NO Ctx
				if (!MutationExists(&entry->rec)) {
					mutType = MUT_ALT_STR;
					wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"DEVICE\\BOLT"); // fake device
					AddMutationToList(&entry->rec, &mutType, &mutVal);
					NewMutation = TRUE;
				}
				break;

			case Call::cGetCursorPos:
				// MUT_RND_TUP -> NO Ctx
				if (!MutationExists(&entry->rec)) {
					mutType = MUT_RND_TUP;
					AddMutationToList(&entry->rec, &mutType, NULL);
					NewMutation = TRUE;
				}
				break;

			case Call::cGetForegroundWindow:
				// MUT_RND_NUM -> NO Ctx
				if (!MutationExists(&entry->rec)) {
					mutType = MUT_RND_NUM;
					AddMutationToList(&entry->rec, &mutType, NULL);
					NewMutation = TRUE;
				}
				break;
			}
			entry = entry->next;
		}
	}
	return NewMutation;
}


RecordList* GenerateResponsiveMutations(Execution* exec, RecordList* start)
{
	exec->mutStore = GetCurrentMutation(); // store the pointer pre new mutations (can be NULL)

	// todo: loop through the process indices within here. (multi/child process)
	LONG index = 0;

	/*
	Thought1: Maybe we can do some sort of initial analysis run where we apply all possible
	'safe' mutations, i.e. only fail for contexts we are confident it won't harm execution. (e.g. containing vbox)
	To see if the malware reacts at all by increasing behavior.

	Then after that stage we can focus on doing more fine-grained incremental mutations to obtain a closer to minimal set
	Perhaps do this initial mutate-all stage by default as part of the fuzzing, or maybe only as an experiment
	To see if the malware reacts to the mutations (i.e., to filter the data set for evasive malware).

	Thought2: Mutations can be dependent on each other, where activity gain is only seen when 2 or more mutations are applied in the same execution.
	Therefore the fuzzing should definitely have a phase where it tries mutations incrementally without replacement.
	i.e.: [M1] -> [M1][M2] -> [M1][M2][M3] instead of [M1] -> [M2] -> [M3]

	*/

	/*
	Mutation Strategy (Phases):
	1. Intelligent: Match call contexts to common artifacts (e.g. containing VBox). Replace with stock values.
	2. Intelligent (random): Replace the common artifacts with random results.
	3. No Context: Mutate all recorded evasive calls, regardless of their context.
	4. Intelligent (failing): Let the calls containing common artifacts fail.
	5. No Context (failing): Let all calls fail regardless of context.
	*/

	// First Iteration: let's assume all mutations are sourced from the main process...

	// mutation generation algorithm
	RecordList* entry;

	if (start != NULL) {
		// continue where we left off since the last mutation was gainless
		entry = start;
	}
	else {
		// start at the head, this is a fresh execution
		entry = exec->recordings[index].recHead;
	}

	while (entry != NULL) {

		// if not an evasive call, skip
		if (entry->rec.call > CALL_SEPARATOR) {
			entry = entry->next;
			continue;
		}

		if (MutationExists(&entry->rec)) {
			printf("The call %s already contains a gainful mutation from prev execs. Skip.\n", DebugCallNames[(UINT)entry->rec.call]);
			entry = entry->next;
			continue;
		}

		switch (entry->rec.call) {
		case Call::cNtOpenKeyEx:
		{
			if (entry->rec.type != CTX_STR) {
				fprintf(stderr, "Context mismatch on NtOpenKeyEx.\n");
				break;
			}

			// mutation: return key not found
			MutationType mutType = MUT_FAIL;
			MutationValue mutVal;
			mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
			AddMutationToList(&entry->rec, &mutType, &mutVal);
			printf("Mutation generated for NtOpenKeyEx\n");
			return entry;
			break;
		}

		case Call::cNtQueryValueKey:
		{
			// StrStrI is case insensitive
			//if (StrStrIW(entry->rec.value.szCtx, L"vbox") != NULL) { // key ctx contains vbox

			if (wcsstr(entry->rec.value.szCtx, L"SystemBiosVersion") != NULL) {
				MutationType mutType = MUT_ALT_STR;
				MutationValue mutVal;
				wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"StockHidden");
				AddMutationToList(&entry->rec, &mutType, &mutVal);
				printf("Mutation generated for NtQueryValueKey\n");
				return entry;
			}

			break;
		}

		case Call::cNtEnumerateValueKey:
		{
			// StrStrI is case insensitive
			//if (StrStrIW(entry->rec.value.szCtx, L"vbox") != NULL) { // key ctx contains vbox

			// STATUS_NO_MORE_ENTRIES 0x8000001A

			if (wcsstr(entry->rec.value.szCtx, L"SystemBiosVersion") != NULL) {

				MutationType mutType = MUT_FAIL;
				MutationValue mutVal;
				mutVal.nValue = 0x8000001A; // STATUS_NO_MORE_ENTRIES
				AddMutationToList(&entry->rec, &mutType, &mutVal);
				printf("Mutation generated for NtEnumerateValueKey.\n");

				/*
				MutationType mutType = MUT_ALT_STR;
				MutationValue mutVal;
				wcscpy_s(mutVal.szValue, MAX_MUT_STR, L"StockHiddenZzz");
				AddMutationToList(&entry->rec, &mutType, &mutVal);
				printf("Mutation generated for NtEnumerateValueKey\n");
				*/
				return entry;
			}

			break;
		}

		case Call::cNtQueryAttributesFile:
		{
			if (wcsstr(entry->rec.value.szCtx, L"basicapp.exe") != NULL) {
				MutationType mutType = MUT_FAIL;
				MutationValue mutVal;
				mutVal.nValue = 0xC0000034; // STATUS_OBJECT_NAME_NOT_FOUND
				AddMutationToList(&entry->rec, &mutType, &mutVal);
				printf("Mutation generated for NtQueryAttributesFile.\n");
				return entry;
			}
			break;
		}

		case Call::cNtQueryDirectoryFile:
		{
			if (wcsstr(entry->rec.value.szCtx, L"basicapp.exe") != NULL) {
				MutationType mutType = MUT_FAIL;
				MutationValue mutVal;
				mutVal.nValue = 0xC000000F; // STATUS_NO_SUCH_FILE
				AddMutationToList(&entry->rec, &mutType, &mutVal);
				printf("Mutation generated for NtQueryDirectoryFile\n");
				return entry;
			}
			break;
		}

		case Call::cGetCursorPos:
		{
			MutationType mutType = MUT_RND_TUP; //MUT_ALT_TUP;
			//MutationValue mutVal;
			//mutVal.tupValue[0] = rand() % 1920; // X
			//mutVal.tupValue[1] = rand() % 1080; // Y
			AddMutationToList(&entry->rec, &mutType, NULL);
			printf("Mutation generated for GetCursorPos\n");
			return entry;
		}
		}
		entry = entry->next;
	}

	return NULL;
}