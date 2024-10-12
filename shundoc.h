//+-------------------------------------------------------------------------
//
//  TaskMan - NT TaskManager
//  Copyright (C) Microsoft
//
//  File:       shundoc.h
//
//  History:    Oct-11-24   aubymori  Created
//
//--------------------------------------------------------------------------
#pragma once
#include "precomp.h"

//
// Macros
//
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

//
// Function definitions
//

// Needed for RunFileDlg
#define RFD_NOBROWSE            0x00000001
#define RFD_NODEFFILE           0x00000002
#define RFD_USEFULLPATHDIR      0x00000004
#define RFD_NOSHOWOPEN          0x00000008
#define RFD_WOW_APP             0x00000010
#define RFD_NOSEPMEMORY_BOX     0x00000020
extern int (WINAPI *RunFileDlg)(HWND hwnd, HICON hIcon, LPCWSTR pszWorkingDir, LPCWSTR pszTitle,
								LPCWSTR pszPrompt, DWORD dwFlags);

extern BOOL (WINAPI *SHTestTokenPrivilegeW)(HANDLE hToken, LPCWSTR pszPrivilegeName);

extern HRESULT (WINAPI *SHGetUserDisplayName)(LPWSTR pszDisplayName, PULONG uLen);

extern NTSTATUS (NTAPI *NtInitiatePowerAction)(
    IN POWER_ACTION SystemAction,
    IN SYSTEM_POWER_STATE MinSystemState,
    IN ULONG Flags,
    IN BOOLEAN Asynchronous
);

typedef LONG KPRIORITY;
typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
    __int64 IdleProcessTime;
    __int64 IoReadTransferCount;
    __int64 IoWriteTransferCount;
    __int64 IoOtherTransferCount;
    ULONG IoReadOperationCount;
    ULONG IoWriteOperationCount;
    ULONG IoOtherOperationCount;
    ULONG AvailablePages;
    ULONG CommittedPages;
    ULONG CommitLimit;
    ULONG PeakCommitment;
    ULONG PageFaultCount;
    ULONG CopyOnWriteCount;
    ULONG TransitionCount;
    ULONG CacheTransitionCount;
    ULONG DemandZeroCount;
    ULONG PageReadCount;
    ULONG PageReadIoCount;
    ULONG CacheReadCount;
    ULONG CacheIoCount;
    ULONG DirtyPagesWriteCount;
    ULONG DirtyWriteIoCount;
    ULONG MappedPagesWriteCount;
    ULONG MappedWriteIoCount;
    ULONG PagedPoolPages;
    ULONG NonPagedPoolPages;
    ULONG PagedPoolAllocs;
    ULONG PagedPoolFrees;
    ULONG NonPagedPoolAllocs;
    ULONG NonPagedPoolFrees;
    ULONG FreeSystemPtes;
    ULONG ResidentSystemCodePage;
    ULONG TotalSystemDriverPages;
    ULONG TotalSystemCodePages;
    ULONG NonPagedPoolLookasideHits;
    ULONG PagedPoolLookasideHits;
    ULONG AvailablePagedPoolPages;
    ULONG ResidentSystemCachePage;
    ULONG ResidentPagedPoolPage;
    ULONG ResidentSystemDriverPage;
    ULONG CcFastReadNoWait;
    ULONG CcFastReadWait;
    ULONG CcFastReadResourceMiss;
    ULONG CcFastReadNotPossible;
    ULONG CcFastMdlReadNoWait;
    ULONG CcFastMdlReadWait;
    ULONG CcFastMdlReadResourceMiss;
    ULONG CcFastMdlReadNotPossible;
    ULONG CcMapDataNoWait;
    ULONG CcMapDataWait;
    ULONG CcMapDataNoWaitMiss;
    ULONG CcMapDataWaitMiss;
    ULONG CcPinMappedDataCount;
    ULONG CcPinReadNoWait;
    ULONG CcPinReadWait;
    ULONG CcPinReadNoWaitMiss;
    ULONG CcPinReadWaitMiss;
    ULONG CcCopyReadNoWait;
    ULONG CcCopyReadWait;
    ULONG CcCopyReadNoWaitMiss;
    ULONG CcCopyReadWaitMiss;
    ULONG CcMdlReadNoWait;
    ULONG CcMdlReadWait;
    ULONG CcMdlReadNoWaitMiss;
    ULONG CcMdlReadWaitMiss;
    ULONG CcReadAheadIos;
    ULONG CcLazyWriteIos;
    ULONG CcLazyWritePages;
    ULONG CcDataFlushes;
    ULONG CcDataPages;
    ULONG ContextSwitches;
    ULONG FirstLevelTbFills;
    ULONG SecondLevelTbFills;
    ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_BASIC_INFORMATION
{
    ULONG Reserved;
    ULONG TimerResolution;
    ULONG PageSize;
    ULONG NumberOfPhysicalPages;
    ULONG LowestPhysicalPageNumber;
    ULONG HighestPhysicalPageNumber;
    ULONG AllocationGranularity;
    ULONG MinimumUserModeAddress;
    ULONG MaximumUserModeAddress;
    KAFFINITY ActiveProcessorsAffinityMask;
    // Expects a 40-byte struct but I legit cannot find one in the src
    PVOID Dummy;
    CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,             // obsolete...delete
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

extern NTSTATUS (NTAPI *NtQuerySystemInformation)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
    __int64 IdleTime;
    __int64 KernelTime;
    __int64 UserTime;
    __int64 DpcTime;          // DEVL only
    __int64 InterruptTime;    // DEVL only
    ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    __int64 SpareLi1;
    __int64 SpareLi2;
    __int64 SpareLi3;
    __int64 CreateTime;
    __int64 UserTime;
    __int64 KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    __int64 ReadOperationCount;
    __int64 WriteOperationCount;
    __int64 OtherOperationCount;
    __int64 ReadTransferCount;
    __int64 WriteTransferCount;
    __int64 OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_FILECACHE_INFORMATION
{
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG spare[1];
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

typedef struct _CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID *PCLIENT_ID;

typedef struct _TIME_FIELDS
{
    CSHORT Year;        // range [1601...]
    CSHORT Month;       // range [1..12]
    CSHORT Day;         // range [1..31]
    CSHORT Hour;        // range [0..23]
    CSHORT Minute;      // range [0..59]
    CSHORT Second;      // range [0..59]
    CSHORT Milliseconds;// range [0..999]
    CSHORT Weekday;     // range [0..6] == [Sunday..Saturday]
} TIME_FIELDS;
typedef TIME_FIELDS *PTIME_FIELDS;

extern NTSTATUS (NTAPI *NtShutdownSystem)(
    IN SHUTDOWN_ACTION Action
);

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

/* Helper Macro */
#define InitializeObjectAttributes(p,n,a,r,s) { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
  (p)->RootDirectory = (r); \
  (p)->Attributes = (a); \
  (p)->ObjectName = (n); \
  (p)->SecurityDescriptor = (s); \
  (p)->SecurityQualityOfService = NULL; \

extern NTSTATUS (NTAPI *NtOpenThread)(
    _Out_ PHANDLE            ThreadHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes,
    _In_  PCLIENT_ID         ClientId
);

extern NTSTATUS (NTAPI *NtClose)(
    _In_ HANDLE Handle
);

#define PASSWORD_LENGTH          14
#define LOGONID_CURRENT     ((ULONG)-1)

extern BOOLEAN (WINAPI *WinStationGetProcessSid)(
    HANDLE   hServer,
    DWORD    ProcessId,
    FILETIME ProcessStartTime,
    PBYTE    pProcessUserSid,
    DWORD *pdwSidSize
);

extern BOOLEAN (WINAPI *WinStationConnectW)(
    HANDLE hServer,
    ULONG LogonId,
    ULONG TargetLogonId,
    PWCHAR pPassword,
    BOOLEAN bWait
);

#define DIRECTORY_LENGTH         256
#define INITIALPROGRAM_LENGTH    256
#define CALLBACK_LENGTH          50
#define NASIFILESERVER_LENGTH    47

/*
 *  Callback options
 */
typedef enum _CALLBACKCLASS
{
    Callback_Disable,
    Callback_Roving,
    Callback_Fixed,
} CALLBACKCLASS;

/*
 *  Shadow options
 */
typedef enum _SHADOWCLASS
{
    Shadow_Disable,
    Shadow_EnableInputNotify,
    Shadow_EnableInputNoNotify,
    Shadow_EnableNoInputNotify,
    Shadow_EnableNoInputNoNotify,
} SHADOWCLASS;

#define MAX_BR_NAME              65  // maximum length of browser name (including null)
typedef WCHAR APPLICATIONNAMEW[MAX_BR_NAME];

/*
 *  User Configuration data
 */
typedef struct _USERCONFIGW
{

    /* if flag is set inherit parameter from user or client configuration */
    ULONG fInheritAutoLogon : 1;
    ULONG fInheritResetBroken : 1;
    ULONG fInheritReconnectSame : 1;
    ULONG fInheritInitialProgram : 1;
    ULONG fInheritCallback : 1;
    ULONG fInheritCallbackNumber : 1;
    ULONG fInheritShadow : 1;
    ULONG fInheritMaxSessionTime : 1;
    ULONG fInheritMaxDisconnectionTime : 1;
    ULONG fInheritMaxIdleTime : 1;
    ULONG fInheritAutoClient : 1;
    ULONG fInheritSecurity : 1;

    ULONG fPromptForPassword : 1;      // fInheritAutoLogon
    ULONG fResetBroken : 1;
    ULONG fReconnectSame : 1;
    ULONG fLogonDisabled : 1;
    ULONG fWallPaperDisabled : 1;
    ULONG fAutoClientDrives : 1;
    ULONG fAutoClientLpts : 1;
    ULONG fForceClientLptDef : 1;
    ULONG fRequireEncryption : 1;
    ULONG fDisableEncryption : 1;
    ULONG fUnused1 : 1;                 // old fDisableIniFileMapping
    ULONG fHomeDirectoryMapRoot : 1;
    ULONG fUseDefaultGina : 1;
    ULONG fCursorBlinkDisabled : 1;

    ULONG fPublishedApp : 1;
    ULONG fHideTitleBar : 1;
    ULONG fMaximize : 1;

    ULONG fDisableCpm : 1;
    ULONG fDisableCdm : 1;
    ULONG fDisableCcm : 1;
    ULONG fDisableLPT : 1;
    ULONG fDisableClip : 1;
    ULONG fDisableExe : 1;
    ULONG fDisableCam : 1;

    ULONG fDisableAutoReconnect : 1;

    /* fInheritColorDepth */
    ULONG ColorDepth : 3;

    //NA 2/19/01
    ULONG fInheritColorDepth : 1;

    //
    //Different error flags
    //
    ULONG   fErrorInvalidProfile : 1; //Set if WFProfilePath, WFHomeDir, or WFHomeDirDrive are invalid (too long).

    /* fInheritAutoLogon */
    WCHAR UserName[USERNAME_LENGTH + 1];
    WCHAR Domain[DOMAIN_LENGTH + 1];
    WCHAR Password[PASSWORD_LENGTH + 1];

    /* fInheritInitialProgram */
    WCHAR WorkDirectory[DIRECTORY_LENGTH + 1];
    WCHAR InitialProgram[INITIALPROGRAM_LENGTH + 1];

    /* fInheritCallback */
    WCHAR CallbackNumber[CALLBACK_LENGTH + 1];
    CALLBACKCLASS Callback;

    /* fInheritShadow */
    SHADOWCLASS Shadow;

    ULONG MaxConnectionTime;
    ULONG MaxDisconnectionTime;
    ULONG MaxIdleTime;

    ULONG KeyboardLayout;               // 0 = inherit

    /* fInheritSecurity */
    BYTE MinEncryptionLevel;

    WCHAR NWLogonServer[NASIFILESERVER_LENGTH + 1];

    APPLICATIONNAMEW PublishedName;

    /* WinFrame Profile Path - Overrides standard profile path */
    WCHAR WFProfilePath[DIRECTORY_LENGTH + 1];

    /* WinFrame Home Directory - Overrides standard Home Directory */
    WCHAR WFHomeDir[DIRECTORY_LENGTH + 1];

    /* WinFrame Home Directory Drive - Overrides standard Home Directory Drive*/
    WCHAR WFHomeDirDrive[4];

} USERCONFIGW, *PUSERCONFIGW;

#define WINSTATIONCOMMENT_LENGTH 60

typedef struct _WINSTATIONCONFIGW
{
    WCHAR Comment[WINSTATIONCOMMENT_LENGTH + 1];
    USERCONFIGW User;
    char OEMId[4];                // WinFrame Server OEM Id
} WINSTATIONCONFIGW, *PWINSTATIONCONFIGW;

typedef enum _WINSTATIONINFOCLASS
{
    WinStationCreateData,         // query WinStation create data
    WinStationConfiguration,      // query/set WinStation parameters
    WinStationPdParams,           // query/set PD parameters
    WinStationWd,                 // query WD config (only one can be loaded)
    WinStationPd,                 // query PD config (many can be loaded)
    WinStationPrinter,            // query/set LPT mapping to printer queues
    WinStationClient,             // query information about client
    WinStationModules,            // query information about all client modules
    WinStationInformation,        // query information about WinStation
    WinStationTrace,              // enable/disable winstation tracing
    WinStationBeep,               // beep the WinStation
    WinStationEncryptionOff,      // turn off encryption
    WinStationEncryptionPerm,     // encryption is permanent on
    WinStationNtSecurity,         // select winlogon security desktop
    WinStationUserToken,          // User token
    WinStationUnused1,            // *** AVAILABLE *** (old IniMapping)
    WinStationVideoData,          // query hres, vres, color depth
    WinStationInitialProgram,     // Identify Initial Program
    WinStationCd,                 // query CD config (only one can be loaded)
    WinStationSystemTrace,        // enable/disable system tracing
    WinStationVirtualData,        // query client virtual data
    WinStationClientData,         // send data to client
    WinStationSecureDesktopEnter, // turn encryption on, if enabled
    WinStationSecureDesktopExit,  // turn encryption off, if enabled
    WinStationLoadBalanceSessionTarget,  // Load balance info from redirected client.
    WinStationLoadIndicator,      // query load capacity information
    WinStationShadowInfo,         // query/set Shadow state & parameters
    WinStationDigProductId,       // get the outermost digital product id, the client's product id, and the current product id
    WinStationLockedState,        // winlogon sets this for notifing apps/services.
    WinStationRemoteAddress,      // Query client IP address
    WinStationIdleTime,           // Query for how much time the winstation is idle
    WinStationLastReconnectType,  // If last reconnect for this winstation was manual or auto reconnect.      
    WinStationDisallowAutoReconnect,     // Allow/Disallow AutoReconnect for this WinStation
    WinStationMprNotifyInfo,      // Mprnotify info from Winlogon for notifying 3rd party network providers
    WinStationExecSrvSystemPipe,   // Exec Srv System Pipe name
    WinStationSDRedirectedSmartCardLogon,       // Was this a Session Directory redirected SmartCard logon
    WinStationIsAdminLoggedOn      // Is the currently logged on user an administrator ?
} WINSTATIONINFOCLASS;

typedef struct _PEB_LDR_DATA
{
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef VOID(NTAPI *PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _PEB
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID Reserved4[3];
    PVOID AtlThunkSListPtr;
    PVOID Reserved5;
    ULONG Reserved6;
    PVOID Reserved7;
    ULONG Reserved8;
    ULONG AtlThunkSListPtr32;
    PVOID Reserved9[45];
    BYTE Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE Reserved11[128];
    PVOID Reserved12[1];
    ULONG SessionId;
} PEB, *PPEB;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

extern BOOLEAN (WINAPI *WinStationQueryInformationW)(
    HANDLE hServer,
    ULONG LogonId,
    WINSTATIONINFOCLASS WinStationInformationClass,
    PVOID  pWinStationInformation,
    ULONG WinStationInformationLength,
    PULONG  pReturnLength
);

extern BOOLEAN (WINAPI *WinStationShadow)(
    HANDLE hServer,
    PWSTR pTargetServerName,
    ULONG TargetLogonId,
    BYTE HotkeyVk,
    USHORT HotkeyModifiers
);

extern VOID (NTAPI *RtlTimeToElapsedTimeFields)(
    _In_  __int64 * Time,
    _Out_ PTIME_FIELDS TimeFields
);

extern NTSTATUS (NTAPI *RtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);

typedef enum _PROCESSINFOCLASS
{
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,          // Note: this is kernel mode only
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    MaxProcessInfoClass             // MaxProcessInfoClass should always be the last enum
} PROCESSINFOCLASS;

extern NTSTATUS (NTAPI *NtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

extern BOOL (WINAPI *EndTask)(HWND hWnd, BOOL fShutDown, BOOL fForce);

extern void (WINAPI *CachedGetUserFromSid)(PSID pSid, PWCHAR pUserName, PULONG cbUserName);

extern void (WINAPI *CurrentDateTimeString)(LPWSTR pString);


#define GMI_DOCKSTATE           0x0000
// Return values for SHGetMachineInfo(GMI_DOCKSTATE)
#define GMID_NOTDOCKABLE         0  // Cannot be docked
#define GMID_UNDOCKED            1  // Is undocked
#define GMID_DOCKED              2  // Is docked
extern DWORD_PTR (WINAPI *SHGetMachineInfo)(UINT gmi);

//
// Function loader
//
bool SHUndocInit(void);