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
EXTERN_C int WINAPI RunFileDlg(HWND hwnd, HICON hIcon, LPCWSTR pszWorkingDir, LPCWSTR pszTitle,
								LPCWSTR pszPrompt, DWORD dwFlags);

EXTERN_C BOOL WINAPI SHTestTokenPrivilegeW(HANDLE hToken, LPCWSTR pszPrivilegeName);

EXTERN_C HRESULT WINAPI SHGetUserDisplayName(LPWSTR pszDisplayName, PULONG uLen);

EXTERN_C NTSTATUS NTAPI NtInitiatePowerAction(
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
    SystemBasicInformation = 0x0,
    SystemProcessorInformation = 0x1,
    SystemPerformanceInformation = 0x2,
    SystemTimeOfDayInformation = 0x3,
    SystemPathInformation = 0x4,
    SystemProcessInformation = 0x5,
    SystemCallCountInformation = 0x6,
    SystemDeviceInformation = 0x7,
    SystemProcessorPerformanceInformation = 0x8,
    SystemFlagsInformation = 0x9,
    SystemCallTimeInformation = 0xA,
    SystemModuleInformation = 0xB,
    SystemLocksInformation = 0xC,
    SystemStackTraceInformation = 0xD,
    SystemPagedPoolInformation = 0xE,
    SystemNonPagedPoolInformation = 0xF,
    SystemHandleInformation = 0x10,
    SystemObjectInformation = 0x11,
    SystemPageFileInformation = 0x12,
    SystemVdmInstemulInformation = 0x13,
    SystemVdmBopInformation = 0x14,
    SystemFileCacheInformation = 0x15,
    SystemPoolTagInformation = 0x16,
    SystemInterruptInformation = 0x17,
    SystemDpcBehaviorInformation = 0x18,
    SystemFullMemoryInformation = 0x19,
    SystemLoadGdiDriverInformation = 0x1A,
    SystemUnloadGdiDriverInformation = 0x1B,
    SystemTimeAdjustmentInformation = 0x1C,
    SystemSummaryMemoryInformation = 0x1D,
    SystemMirrorMemoryInformation = 0x1E,
    SystemPerformanceTraceInformation = 0x1F,
    SystemObsolete0 = 0x20,
    SystemExceptionInformation = 0x21,
    SystemCrashDumpStateInformation = 0x22,
    SystemKernelDebuggerInformation = 0x23,
    SystemContextSwitchInformation = 0x24,
    SystemRegistryQuotaInformation = 0x25,
    SystemExtendServiceTableInformation = 0x26,
    SystemPrioritySeperation = 0x27,
    SystemVerifierAddDriverInformation = 0x28,
    SystemVerifierRemoveDriverInformation = 0x29,
    SystemProcessorIdleInformation = 0x2A,
    SystemLegacyDriverInformation = 0x2B,
    SystemCurrentTimeZoneInformation = 0x2C,
    SystemLookasideInformation = 0x2D,
    SystemTimeSlipNotification = 0x2E,
    SystemSessionCreate = 0x2F,
    SystemSessionDetach = 0x30,
    SystemSessionInformation = 0x31,
    SystemRangeStartInformation = 0x32,
    SystemVerifierInformation = 0x33,
    SystemVerifierThunkExtend = 0x34,
    SystemSessionProcessInformation = 0x35,
    SystemLoadGdiDriverInSystemSpace = 0x36,
    SystemNumaProcessorMap = 0x37,
    SystemPrefetcherInformation = 0x38,
    SystemExtendedProcessInformation = 0x39,
    SystemRecommendedSharedDataAlignment = 0x3A,
    SystemComPlusPackage = 0x3B,
    SystemNumaAvailableMemory = 0x3C,
    SystemProcessorPowerInformation = 0x3D,
    SystemEmulationBasicInformation = 0x3E,
    SystemEmulationProcessorInformation = 0x3F,
    SystemExtendedHandleInformation = 0x40,
    SystemLostDelayedWriteInformation = 0x41,
    SystemBigPoolInformation = 0x42,
    SystemSessionPoolTagInformation = 0x43,
    SystemSessionMappedViewInformation = 0x44,
    SystemHotpatchInformation = 0x45,
    SystemObjectSecurityMode = 0x46,
    SystemWatchdogTimerHandler = 0x47,
    SystemWatchdogTimerInformation = 0x48,
    SystemLogicalProcessorInformation = 0x49,
    SystemWow64SharedInformationObsolete = 0x4A,
    SystemRegisterFirmwareTableInformationHandler = 0x4B,
    SystemFirmwareTableInformation = 0x4C,
    SystemModuleInformationEx = 0x4D,
    SystemVerifierTriageInformation = 0x4E,
    SystemSuperfetchInformation = 0x4F,
    SystemMemoryListInformation = 0x50,
    SystemFileCacheInformationEx = 0x51,
    SystemThreadPriorityClientIdInformation = 0x52,
    SystemProcessorIdleCycleTimeInformation = 0x53,
    SystemVerifierCancellationInformation = 0x54,
    SystemProcessorPowerInformationEx = 0x55,
    SystemRefTraceInformation = 0x56,
    SystemSpecialPoolInformation = 0x57,
    SystemProcessIdInformation = 0x58,
    SystemErrorPortInformation = 0x59,
    SystemBootEnvironmentInformation = 0x5A,
    SystemHypervisorInformation = 0x5B,
    SystemVerifierInformationEx = 0x5C,
    SystemTimeZoneInformation = 0x5D,
    SystemImageFileExecutionOptionsInformation = 0x5E,
    SystemCoverageInformation = 0x5F,
    SystemPrefetchPatchInformation = 0x60,
    SystemVerifierFaultsInformation = 0x61,
    SystemSystemPartitionInformation = 0x62,
    SystemSystemDiskInformation = 0x63,
    SystemProcessorPerformanceDistribution = 0x64,
    SystemNumaProximityNodeInformation = 0x65,
    SystemDynamicTimeZoneInformation = 0x66,
    SystemCodeIntegrityInformation = 0x67,
    SystemProcessorMicrocodeUpdateInformation = 0x68,
    SystemProcessorBrandString = 0x69,
    SystemVirtualAddressInformation = 0x6A,
    SystemLogicalProcessorAndGroupInformation = 0x6B,
    SystemProcessorCycleTimeInformation = 0x6C,
    SystemStoreInformation = 0x6D,
    SystemRegistryAppendString = 0x6E,
    SystemAitSamplingValue = 0x6F,
    SystemVhdBootInformation = 0x70,
    SystemCpuQuotaInformation = 0x71,
    SystemNativeBasicInformation = 0x72,
    SystemErrorPortTimeouts = 0x73,
    SystemLowPriorityIoInformation = 0x74,
    SystemBootEntropyInformation = 0x75,
    SystemVerifierCountersInformation = 0x76,
    SystemPagedPoolInformationEx = 0x77,
    SystemSystemPtesInformationEx = 0x78,
    SystemNodeDistanceInformation = 0x79,
    SystemAcpiAuditInformation = 0x7A,
    SystemBasicPerformanceInformation = 0x7B,
    SystemQueryPerformanceCounterInformation = 0x7C,
    SystemSessionBigPoolInformation = 0x7D,
    SystemBootGraphicsInformation = 0x7E,
    SystemScrubPhysicalMemoryInformation = 0x7F,
    SystemBadPageInformation = 0x80,
    SystemProcessorProfileControlArea = 0x81,
    SystemCombinePhysicalMemoryInformation = 0x82,
    SystemEntropyInterruptTimingInformation = 0x83,
    SystemConsoleInformation = 0x84,
    SystemPlatformBinaryInformation = 0x85,
    SystemPolicyInformation = 0x86,
    SystemHypervisorProcessorCountInformation = 0x87,
    SystemDeviceDataInformation = 0x88,
    SystemDeviceDataEnumerationInformation = 0x89,
    SystemMemoryTopologyInformation = 0x8A,
    SystemMemoryChannelInformation = 0x8B,
    SystemBootLogoInformation = 0x8C,
    SystemProcessorPerformanceInformationEx = 0x8D,
    SystemCriticalProcessErrorLogInformation = 0x8E,
    SystemSecureBootPolicyInformation = 0x8F,
    SystemPageFileInformationEx = 0x90,
    SystemSecureBootInformation = 0x91,
    SystemEntropyInterruptTimingRawInformation = 0x92,
    SystemPortableWorkspaceEfiLauncherInformation = 0x93,
    SystemFullProcessInformation = 0x94,
    SystemKernelDebuggerInformationEx = 0x95,
    SystemBootMetadataInformation = 0x96,
    SystemSoftRebootInformation = 0x97,
    SystemElamCertificateInformation = 0x98,
    SystemOfflineDumpConfigInformation = 0x99,
    SystemProcessorFeaturesInformation = 0x9A,
    SystemRegistryReconciliationInformation = 0x9B,
    SystemEdidInformation = 0x9C,
    SystemManufacturingInformation = 0x9D,
    SystemEnergyEstimationConfigInformation = 0x9E,
    SystemHypervisorDetailInformation = 0x9F,
    SystemProcessorCycleStatsInformation = 0xA0,
    SystemVmGenerationCountInformation = 0xA1,
    SystemTrustedPlatformModuleInformation = 0xA2,
    SystemKernelDebuggerFlags = 0xA3,
    SystemCodeIntegrityPolicyInformation = 0xA4,
    SystemIsolatedUserModeInformation = 0xA5,
    SystemHardwareSecurityTestInterfaceResultsInformation = 0xA6,
    SystemSingleModuleInformation = 0xA7,
    SystemAllowedCpuSetsInformation = 0xA8,
    SystemDmaProtectionInformation = 0xA9,
    SystemInterruptCpuSetsInformation = 0xAA,
    SystemSecureBootPolicyFullInformation = 0xAB,
    SystemCodeIntegrityPolicyFullInformation = 0xAC,
    SystemAffinitizedInterruptProcessorInformation = 0xAD,
    SystemRootSiloInformation = 0xAE,
    SystemCpuSetInformation = 0xAF,
    SystemCpuSetTagInformation = 0xB0,
    SystemWin32WerStartCallout = 0xB1,
    SystemSecureKernelProfileInformation = 0xB2,
    SystemCodeIntegrityPlatformManifestInformation = 0xB3,
    SystemInterruptSteeringInformation = 0xB4,
    SystemSupportedProcessorArchitectures = 0xB5,
    MaxSystemInfoClass = 0xB6,
} SYSTEM_INFORMATION_CLASS;

typedef enum _SUPERFETCH_INFORMATION_CLASS
{
    SuperfetchRetrieveTrace = 0x1,
    SuperfetchSystemParameters = 0x2,
    SuperfetchLogEvent = 0x3,
    SuperfetchGenerateTrace = 0x4,
    SuperfetchPrefetch = 0x5,
    SuperfetchPfnQuery = 0x6,
    SuperfetchPfnSetPriority = 0x7,
    SuperfetchPrivSourceQuery = 0x8,
    SuperfetchSequenceNumberQuery = 0x9,
    SuperfetchScenarioPhase = 0xA,
    SuperfetchWorkerPriority = 0xB,
    SuperfetchScenarioQuery = 0xC,
    SuperfetchScenarioPrefetch = 0xD,
    SuperfetchRobustnessControl = 0xE,
    SuperfetchTimeControl = 0xF,
    SuperfetchMemoryListQuery = 0x10,
    SuperfetchMemoryRangesQuery = 0x11,
    SuperfetchTracingControl = 0x12,
    SuperfetchTrimWhileAgingControl = 0x13,
    SuperfetchRepurposedByPrefetchQuery = 0x14,
    SuperfetchChannelPowerRequest = 0x15,
    SuperfetchMovePages = 0x16,
    SuperfetchVirtualQuery = 0x17,
    SuperfetchCombineStatsQuery = 0x18,
    SuperfetchSetMinWsAgeRate = 0x19,
    SuperfetchDeprioritizeOldPagesInWs = 0x1A,
    SuperfetchFileExtentsQuery = 0x1B,
    SuperfetchGpuUtilizationQuery = 0x1C,
    SuperfetchInformationMax = 0x1D,
} SUPERFETCH_INFORMATION_CLASS;

typedef struct _SUPERFETCH_INFORMATION
{
    UINT Version;
    UINT Magic;
    SUPERFETCH_INFORMATION_CLASS InfoClass;
    void *Data;
    UINT Length;
} SUPERFETCH_INFORMATION;

typedef struct _PF_MEMORY_LIST_NODE
{
    unsigned __int64 Node : 8;
    unsigned __int64 Spare : 56;
    unsigned __int64 StandbyLowPageCount;
    unsigned __int64 StandbyMediumPageCount;
    unsigned __int64 StandbyHighPageCount;
    unsigned __int64 FreePageCount;
    unsigned __int64 ModifiedPageCount;
} PF_MEMORY_LIST_NODE;

typedef struct _PF_MEMORY_LIST_INFO
{
    UINT Version;
    UINT Size;
    UINT NodeCount;
    PF_MEMORY_LIST_NODE Nodes[1];
} PF_MEMORY_LIST_INFO;


EXTERN_C NTSTATUS NTAPI NtQuerySystemInformation(
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

EXTERN_C NTSTATUS NTAPI NtShutdownSystem(
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

EXTERN_C NTSTATUS NTAPI NtOpenThread(
    _Out_ PHANDLE            ThreadHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes,
    _In_  PCLIENT_ID         ClientId
);

EXTERN_C NTSTATUS NTAPI NtClose(
    _In_ HANDLE Handle
);

#define PASSWORD_LENGTH          14
#define LOGONID_CURRENT     ((ULONG)-1)

EXTERN_C BOOLEAN WINAPI WinStationGetProcessSid(
    HANDLE   hServer,
    DWORD    ProcessId,
    FILETIME ProcessStartTime,
    PBYTE    pProcessUserSid,
    DWORD *pdwSidSize
);

EXTERN_C BOOLEAN WINAPI WinStationConnectW(
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

EXTERN_C BOOLEAN WINAPI WinStationQueryInformationW(
    HANDLE hServer,
    ULONG LogonId,
    WINSTATIONINFOCLASS WinStationInformationClass,
    PVOID  pWinStationInformation,
    ULONG WinStationInformationLength,
    PULONG  pReturnLength
);

EXTERN_C BOOLEAN WINAPI WinStationShadow(
    HANDLE hServer,
    PWSTR pTargetServerName,
    ULONG TargetLogonId,
    BYTE HotkeyVk,
    USHORT HotkeyModifiers
);

EXTERN_C VOID NTAPI RtlTimeToElapsedTimeFields(
    _In_  __int64 * Time,
    _Out_ PTIME_FIELDS TimeFields
);

EXTERN_C NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

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

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
    LARGE_INTEGER BootTime;
    LARGE_INTEGER CurrentTime;
    LARGE_INTEGER TimeZoneBias;
    UINT TimeZoneId;
    UINT Reserved;
    ULONGLONG BootTimeBias;
    ULONGLONG SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;


EXTERN_C NTSTATUS NTAPI NtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

EXTERN_C void WINAPI CachedGetUserFromSid(PSID pSid, PWCHAR pUserName, PULONG cbUserName);

EXTERN_C void WINAPI CurrentDateTimeString(LPWSTR pString);

EXTERN_C ULONG NTAPI RtlNtStatusToDosError(NTSTATUS Status);

#define GMI_DOCKSTATE           0x0000
// Return values for SHGetMachineInfo(GMI_DOCKSTATE)
#define GMID_NOTDOCKABLE         0  // Cannot be docked
#define GMID_UNDOCKED            1  // Is undocked
#define GMID_DOCKED              2  // Is docked
EXTERN_C DWORD_PTR WINAPI SHGetMachineInfo(UINT gmi);

//
// Function loader
//
bool SHUndocInit(void);