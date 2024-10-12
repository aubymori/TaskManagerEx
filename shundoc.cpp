//+-------------------------------------------------------------------------
//
//  TaskMan - NT TaskManager
//  Copyright (C) Microsoft
//
//  File:       shundoc.cpp
//
//  History:    Oct-11-24   aubymori  Created
//
//--------------------------------------------------------------------------
#include "shundoc.h"

//
// Function definitions
// 
int (WINAPI *RunFileDlg)(HWND hwnd, HICON hIcon, LPCWSTR pszWorkingDir, LPCWSTR pszTitle,
	LPCWSTR pszPrompt, DWORD dwFlags) = nullptr;

BOOL (WINAPI *SHTestTokenPrivilegeW)(HANDLE hToken, LPCWSTR pszPrivilegeName) = nullptr;

DWORD_PTR (WINAPI *SHGetMachineInfo)(UINT gmi) = nullptr;

HRESULT (WINAPI *SHGetUserDisplayName)(LPWSTR pszDisplayName, PULONG uLen) = nullptr;

NTSTATUS (NTAPI *NtInitiatePowerAction)(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE MinSystemState,
	IN ULONG Flags,
	IN BOOLEAN Asynchronous
) = nullptr;

NTSTATUS (NTAPI *NtShutdownSystem)(
	IN SHUTDOWN_ACTION Action
) = nullptr;

NTSTATUS (NTAPI *NtQuerySystemInformation)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
) = nullptr;

NTSTATUS (NTAPI *NtOpenThread)(
	_Out_ PHANDLE            ThreadHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes,
	_In_  PCLIENT_ID         ClientId
) = nullptr;

NTSTATUS (NTAPI *NtClose)(
    _In_ HANDLE Handle
) = nullptr;

BOOLEAN (WINAPI *WinStationGetProcessSid)(
    HANDLE   hServer,
    DWORD    ProcessId,
    FILETIME ProcessStartTime,
    PBYTE    pProcessUserSid,
    DWORD *pdwSidSize
) = nullptr;

BOOLEAN (WINAPI *WinStationConnectW)(
    HANDLE hServer,
    ULONG LogonId,
    ULONG TargetLogonId,
    PWCHAR pPassword,
    BOOLEAN bWait
) = nullptr;

BOOLEAN (WINAPI *WinStationQueryInformationW)(
    HANDLE hServer,
    ULONG LogonId,
    WINSTATIONINFOCLASS WinStationInformationClass,
    PVOID  pWinStationInformation,
    ULONG WinStationInformationLength,
    PULONG  pReturnLength
) = nullptr;

BOOLEAN (WINAPI *WinStationShadow)(
    HANDLE hServer,
    PWSTR pTargetServerName,
    ULONG TargetLogonId,
    BYTE HotkeyVk,
    USHORT HotkeyModifiers
) = nullptr;

void (WINAPI *CachedGetUserFromSid)(PSID pSid, PWCHAR pUserName, PULONG cbUserName) = nullptr;

void (WINAPI *CurrentDateTimeString)(LPWSTR pString) = nullptr;

VOID (NTAPI *RtlTimeToElapsedTimeFields)(
    _In_  __int64 * Time,
    _Out_ PTIME_FIELDS TimeFields
) = nullptr;

NTSTATUS (NTAPI *RtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation) = nullptr;

BOOL (WINAPI *EndTask)(HWND hWnd, BOOL fShutDown, BOOL fForce) = nullptr;

//
// Function loader
//
#define MODULE_VARNAME(NAME) hMod_ ## NAME

#define LOAD_MODULE(NAME)                                        \
HMODULE MODULE_VARNAME(NAME) = LoadLibraryW(L#NAME ".dll");      \
if (!MODULE_VARNAME(NAME))                                       \
    return false;

#define LOAD_FUNCTION(MODULE, FUNCTION)                                      \
*(FARPROC *)&FUNCTION = GetProcAddress(MODULE_VARNAME(MODULE), #FUNCTION);   \
if (!FUNCTION)                                                               \
	return false;

#define LOAD_ORDINAL(MODULE, FUNCNAME, ORDINAL)                                   \
*(FARPROC *)&FUNCNAME = GetProcAddress(MODULE_VARNAME(MODULE), (LPCSTR)ORDINAL);  \
if (!FUNCNAME)                                                                    \
	return false;

bool SHUndocInit(void)
{
	LOAD_MODULE(shell32);
	LOAD_ORDINAL(shell32, RunFileDlg, 61);
	LOAD_ORDINAL(shell32, SHTestTokenPrivilegeW, 236);
	LOAD_ORDINAL(shell32, SHGetUserDisplayName, 241);

	LOAD_MODULE(shlwapi);
	LOAD_ORDINAL(shlwapi, SHGetMachineInfo, 413);

	LOAD_MODULE(ntdll);
	LOAD_FUNCTION(ntdll, NtInitiatePowerAction);
	LOAD_FUNCTION(ntdll, NtShutdownSystem);
	LOAD_FUNCTION(ntdll, NtQuerySystemInformation);
	LOAD_FUNCTION(ntdll, NtOpenThread);
	LOAD_FUNCTION(ntdll, NtClose);
	LOAD_FUNCTION(ntdll, RtlTimeToElapsedTimeFields);
	LOAD_FUNCTION(ntdll, RtlGetVersion);

	LOAD_MODULE(winsta);
	LOAD_FUNCTION(winsta, WinStationGetProcessSid);
	LOAD_FUNCTION(winsta, WinStationConnectW);
	LOAD_FUNCTION(winsta, WinStationQueryInformationW);
	LOAD_FUNCTION(winsta, WinStationShadow);

	LOAD_MODULE(utildll);
	LOAD_FUNCTION(utildll, CachedGetUserFromSid);
	LOAD_FUNCTION(utildll, CurrentDateTimeString);

	LOAD_MODULE(user32);
	LOAD_FUNCTION(user32, EndTask);

	return true;
}