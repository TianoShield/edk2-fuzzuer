#ifndef __FIRNESS_HARNESSES__
#define __FIRNESS_HARNESSES__

#include "FirnessIncludes.h"
#include "FirnessHelpers.h"

#ifndef kEmptyHashValue
#define kEmptyHashValue 0
#endif
#ifndef NULL
#define NULL ((VOID *) 0)
#endif

__attribute__((weak)) VOID AsanSetFuzzingActive(BOOLEAN Active)
{
    (VOID)Active;
}
__attribute__((weak)) VOID AsanSetRegionChecks(BOOLEAN Active)
{
    (VOID)Active;
}
__attribute__((weak)) VOID AsanRegisterUntrusted(UINT64 Base, UINT64 Size)
{
    (VOID)Base;
    (VOID)Size;
}
static inline VOID FirnessUntrusted(CONST VOID *Buffer, UINTN Size)
{
    if ((Buffer != NULL) && (AsanRegisterUntrusted != NULL)) {
        AsanRegisterUntrusted((UINT64)(UINTN)Buffer, (UINT64)Size);
    }
}
static VOID FirnessMarkFuzzStart(VOID)
{
    STATIC BOOLEAN Announced = FALSE;
    STATIC CONST CHAR8 Marker[] = "FIRNESS: fuzzing starts\n";
    UINTN Index;

    if (Announced) {
        return;
    }
    Announced = TRUE;
    for (Index = 0; Marker[Index] != 0; Index++) {
        __asm__ __volatile__ ("outb %%al, %%dx"
                              :: "a" (Marker[Index]), "d" ((UINT16)0x3F8));
    }
}
static inline VOID FirnessReportInput(CONST UINT8 *Bytes, UINTN Length)
{
    STATIC CONST CHAR8 Hex[] = "0123456789abcdef";
    CHAR8 Line[32];
    UINTN At = 0;
    UINTN Index;

    Line[At++] = 'I'; Line[At++] = 'N'; Line[At++] = '=';
    for (Index = 4; Index > 0; Index--) {
        Line[At++] = Hex[(Length >> ((Index - 1) * 4)) & 0xF];
    }
    Line[At++] = ':';
    for (Index = 0; Index < 6; Index++) {
        UINT8 Value = (Index < Length) ? Bytes[Index] : 0;
        Line[At++] = Hex[(Value >> 4) & 0xF];
        Line[At++] = Hex[Value & 0xF];
    }
    Line[At++] = '\n';

    for (Index = 0; Index < At; Index++) {
        __asm__ __volatile__ ("outb %%al, %%dx"
                              :: "a" (Line[Index]), "d" ((UINT16)0x3F8));
    }
}
static inline VOID FirnessSanitizer(BOOLEAN Active)
{
    if (Active) {
        FirnessMarkFuzzStart();
    }
    if (AsanSetFuzzingActive != NULL) {
        AsanSetFuzzingActive(Active);
    }
    if (AsanSetRegionChecks != NULL) {
        AsanSetRegionChecks(Active);
    }
    if (!Active && (AsanRegisterUntrusted != NULL)) {
        AsanRegisterUntrusted(0, 0);
    }
}

extern EFI_GUID gEdkiiDeviceIdentifierTypePciGuid;
extern EFI_GUID gEfiAuthenticatedVariableGuid;
extern EFI_GUID gEfiCallerIdGuid;
extern EFI_GUID gEfiDebugPortProtocolGuid;
extern EFI_GUID gEfiDiskInfoAhciInterfaceGuid;
extern EFI_GUID gEfiDiskInfoIdeInterfaceGuid;
extern EFI_GUID gEfiDiskInfoUfsInterfaceGuid;
extern EFI_GUID gEfiFirmwareFileSystem2Guid;
extern EFI_GUID gEfiFirmwareVolume2ProtocolGuid;
extern EFI_GUID gEfiGlobalVariableGuid;
extern EFI_GUID gEfiHobMemoryAllocBspStoreGuid;
extern EFI_GUID gEfiHobMemoryAllocModuleGuid;
extern EFI_GUID gEfiHobMemoryAllocStackGuid;
extern EFI_GUID gEfiMemoryTypeInformationGuid;
extern EFI_GUID gEfiMmCommunicateHeaderV3Guid;
extern EFI_GUID gEfiPcAnsiGuid;
extern EFI_GUID gEfiPersistentVirtualCdGuid;
extern EFI_GUID gEfiPersistentVirtualDiskGuid;
extern EFI_GUID gEfiSasDevicePathGuid;
extern EFI_GUID gEfiSmbios3TableGuid;
extern EFI_GUID gEfiSmbiosTableGuid;
extern EFI_GUID gEfiSmmVariableProtocolGuid;
extern EFI_GUID gEfiUartDevicePathGuid;
extern EFI_GUID gEfiVT100Guid;
extern EFI_GUID gEfiVT100PlusGuid;
extern EFI_GUID gEfiVTUTF8Guid;
extern EFI_GUID gEfiVirtualCdGuid;
extern EFI_GUID gEfiVirtualDiskGuid;
extern EFI_GUID gQemuRamfbGuid;
extern EFI_GUID gTcg800155PlatformIdEventHobGuid;
extern EFI_GUID gUefiOvmfPkgTokenSpaceGuid;
extern EFI_GUID gVarCheckPolicyLibMmiHandlerGuid;
extern EFI_GUID gZeroGuid;

EFI_STATUS
EFIAPI
FuzzReadSection(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzGetNextFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzReadFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzSetVolumeAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzWriteFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzGetVolumeAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzGetInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

EFI_STATUS
EFIAPI
FuzzSetInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
);

#endif // __FIRNESS_HARNESSES__
