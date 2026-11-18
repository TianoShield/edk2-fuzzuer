#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
EFI_GUID * FirnessLive_EFI_GUID__[4];
UINTN FirnessLive_EFI_GUID___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called GetSupportedTypes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSupportedTypes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ADAPTER_INFORMATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAdapterInformationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_GUID * GetSupportedTypes_Arg_1 = NULL;
    UINT8* GetSupportedTypes_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetSupportedTypes_Arg_1_OutputChoice), (VOID *)GetSupportedTypes_Arg_1_OutputChoice);
    if(*GetSupportedTypes_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetSupportedTypes_Arg_1), (VOID *)GetSupportedTypes_Arg_1);
    }
    UINTN * GetSupportedTypes_Arg_2 = (UINTN *)AllocateZeroPool(4096);
    UINT8* GetSupportedTypes_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetSupportedTypes_Arg_2_OutputChoice), (VOID *)GetSupportedTypes_Arg_2_OutputChoice);
    if(*GetSupportedTypes_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetSupportedTypes_Arg_2), (VOID *)GetSupportedTypes_Arg_2);
        *GetSupportedTypes_Arg_2 = *GetSupportedTypes_Arg_2 % ((4096 / sizeof(EFI_GUID *)) + 1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetSupportedTypes(
        ProtocolVariable,
        (EFI_GUID **)&GetSupportedTypes_Arg_1,
        GetSupportedTypes_Arg_2
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_GUID___Count < 4 && GetSupportedTypes_Arg_1 != NULL) {
        FirnessLive_EFI_GUID__[FirnessLive_EFI_GUID___Count++] = GetSupportedTypes_Arg_1;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetInformation.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetInformation(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ADAPTER_INFORMATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAdapterInformationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetInformation_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    UINT8* GetInformation_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetInformation_Arg_1_choice), (VOID *)GetInformation_Arg_1_choice);
    switch(*GetInformation_Arg_1_choice % 11) {
        case 0:
        {
        // EFI_GUID Variable Initialization
        GetInformation_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
            break;
        }
        case 1:
        {
        // EFI_GUID Variable Initialization
        GetInformation_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
            break;
        }
        case 2:
        {
        // EFI_GUID Variable Initialization
        GetInformation_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
            break;
        }
        case 3:
        {
        // EFI_GUID Variable Initialization
        GetInformation_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            GUID * CopyGuid_Arg_1 = (GUID *)AllocateZeroPool(sizeof(GUID));
            
            UINT8* CopyGuid_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*CopyGuid_Arg_1_choice), (VOID *)CopyGuid_Arg_1_choice);
            switch(*CopyGuid_Arg_1_choice % 33) {
                case 0:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gTcg800155PlatformIdEventHobGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                UINT8* CopyGuid_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
                ReadBytes(Input, sizeof(*CopyGuid_Arg_1_choice), (VOID *)CopyGuid_Arg_1_choice);
                switch(*CopyGuid_Arg_1_choice % 1) {
                    case 0:
                        ReadBytes(Input, sizeof(*CopyGuid_Arg_1), (VOID *)CopyGuid_Arg_1);
                        break;
                }
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gQemuRamfbGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbios3TableGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbiosTableGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMemoryTypeInformationGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMmCommunicateHeaderV3Guid;
            
                    break;
                }
                case 27:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 28:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gUefiOvmfPkgTokenSpaceGuid;
            
                    break;
                }
                case 29:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 30:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 31:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 32:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
            }
            FirnessUntrusted(CopyGuid_Arg_1, sizeof(GUID));
            FirnessSanitizer(TRUE);
            CopyGuid(
                GetInformation_Arg_1,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * StrToGuid_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 StrToGuid_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(StrToGuid_Arg_0_choice), (VOID *)&StrToGuid_Arg_0_choice);
            switch(StrToGuid_Arg_0_choice % 1) {
                case 0:
                    if (StrToGuid_Arg_0 != NULL) {
                        ReadBytes(Input, 31 * sizeof(*StrToGuid_Arg_0), (VOID *)StrToGuid_Arg_0);
                        StrToGuid_Arg_0[31] = 0;
                    }
                    break;
            }
            
            FirnessUntrusted(StrToGuid_Arg_0, 32 * sizeof(CHAR16));
            FirnessSanitizer(TRUE);
            StrToGuid(
                StrToGuid_Arg_0,
                GetInformation_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                GetInformation_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 7:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                (EFI_GUID **)&GetInformation_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 8:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * GetGuidFromStringName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            CHAR8 * GetGuidFromStringName_Arg_1 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0_choice), (VOID *)&GetGuidFromStringName_Arg_0_choice);
            switch(GetGuidFromStringName_Arg_0_choice % 1) {
                case 0:
                    if (GetGuidFromStringName_Arg_0 != NULL) {
                        ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_0), (VOID *)GetGuidFromStringName_Arg_0);
                        GetGuidFromStringName_Arg_0[31] = 0;
                    }
                    break;
            }
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1_choice), (VOID *)&GetGuidFromStringName_Arg_1_choice);
            switch(GetGuidFromStringName_Arg_1_choice % 1) {
                case 0:
                    if (GetGuidFromStringName_Arg_1 != NULL) {
                        ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_1), (VOID *)GetGuidFromStringName_Arg_1);
                        GetGuidFromStringName_Arg_1[31] = 0;
                    }
                    break;
            }
            
            FirnessUntrusted(GetGuidFromStringName_Arg_0, 32 * sizeof(CHAR16));
            FirnessUntrusted(GetGuidFromStringName_Arg_1, 32 * sizeof(CHAR8));
            FirnessSanitizer(TRUE);
            Status = GetGuidFromStringName(
                GetGuidFromStringName_Arg_0,
                GetGuidFromStringName_Arg_1,
                (EFI_GUID **)&GetInformation_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 9:
        {
        // Fuzzable Variable Initialization
        UINT8 GetInformation_Arg_1_choice = 0;
        ReadBytes(Input, sizeof(GetInformation_Arg_1_choice), (VOID *)&GetInformation_Arg_1_choice);
        switch(GetInformation_Arg_1_choice % 1) {
            case 0:
                if (GetInformation_Arg_1 != NULL) {
                    ReadBytes(Input, sizeof(*GetInformation_Arg_1), (VOID *)GetInformation_Arg_1);
                }
                break;
        }
    
            break;
        }
        case 10:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            GetInformation_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            GetInformation_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            GetInformation_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(GetInformation_Arg_1->Data4), (VOID *)&(GetInformation_Arg_1->Data4));
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    UINTN* GetInformation_Arg_2 = NULL;
    UINT8* GetInformation_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetInformation_Arg_2_OutputChoice), (VOID *)GetInformation_Arg_2_OutputChoice);
    if(*GetInformation_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInformation_Arg_2), (VOID *)GetInformation_Arg_2);
    }
    UINTN * GetInformation_Arg_3 = (UINTN *)AllocateZeroPool(4096);
    UINT8* GetInformation_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetInformation_Arg_3_OutputChoice), (VOID *)GetInformation_Arg_3_OutputChoice);
    if(*GetInformation_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetInformation_Arg_3), (VOID *)GetInformation_Arg_3);
        *GetInformation_Arg_3 = *GetInformation_Arg_3 % (4096 + 1);
    }
    UINT8 GetInformation_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetInformation_Arg_1_LiveChoice), (VOID *)&GetInformation_Arg_1_LiveChoice);
    if (FirnessLive_EFI_GUID___Count > 0 && (GetInformation_Arg_1_LiveChoice & 1)) {
        GetInformation_Arg_1 = FirnessLive_EFI_GUID__[GetInformation_Arg_1_LiveChoice % FirnessLive_EFI_GUID___Count];
    }
    FirnessUntrusted(GetInformation_Arg_1, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetInformation(
        ProtocolVariable,
        GetInformation_Arg_1,
        (void **)&GetInformation_Arg_2,
        GetInformation_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetInformation.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetInformation(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ADAPTER_INFORMATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAdapterInformationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * SetInformation_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN*  SetInformation_Arg_2 = (UINTN* )AllocateZeroPool(4096);
    UINTN SetInformation_Arg_3 = {0};
    
    UINT8* SetInformation_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*SetInformation_Arg_1_choice), (VOID *)SetInformation_Arg_1_choice);
    switch(*SetInformation_Arg_1_choice % 8) {
        case 0:
        {
        // EFI_GUID Variable Initialization
        SetInformation_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            GUID * CopyGuid_Arg_1 = (GUID *)AllocateZeroPool(sizeof(GUID));
            
            UINT8* CopyGuid_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*CopyGuid_Arg_1_choice), (VOID *)CopyGuid_Arg_1_choice);
            switch(*CopyGuid_Arg_1_choice % 33) {
                case 0:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gTcg800155PlatformIdEventHobGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 3:
                {
                // Constant Variable Initialization
                UINT8* CopyGuid_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
                ReadBytes(Input, sizeof(*CopyGuid_Arg_1_choice), (VOID *)CopyGuid_Arg_1_choice);
                switch(*CopyGuid_Arg_1_choice % 1) {
                    case 0:
                        ReadBytes(Input, sizeof(*CopyGuid_Arg_1), (VOID *)CopyGuid_Arg_1);
                        break;
                }
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gQemuRamfbGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbios3TableGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbiosTableGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMemoryTypeInformationGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMmCommunicateHeaderV3Guid;
            
                    break;
                }
                case 27:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 28:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gUefiOvmfPkgTokenSpaceGuid;
            
                    break;
                }
                case 29:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 30:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 31:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 32:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
            }
            FirnessUntrusted(CopyGuid_Arg_1, sizeof(GUID));
            FirnessSanitizer(TRUE);
            CopyGuid(
                SetInformation_Arg_1,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * StrToGuid_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Fuzzable Variable Initialization
            UINT8 StrToGuid_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(StrToGuid_Arg_0_choice), (VOID *)&StrToGuid_Arg_0_choice);
            switch(StrToGuid_Arg_0_choice % 1) {
                case 0:
                    if (StrToGuid_Arg_0 != NULL) {
                        ReadBytes(Input, 31 * sizeof(*StrToGuid_Arg_0), (VOID *)StrToGuid_Arg_0);
                        StrToGuid_Arg_0[31] = 0;
                    }
                    break;
            }
            
            FirnessUntrusted(StrToGuid_Arg_0, 32 * sizeof(CHAR16));
            FirnessSanitizer(TRUE);
            StrToGuid(
                StrToGuid_Arg_0,
                SetInformation_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                SetInformation_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                (EFI_GUID **)&SetInformation_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            CHAR16 * GetGuidFromStringName_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            CHAR8 * GetGuidFromStringName_Arg_1 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_0_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_0_choice), (VOID *)&GetGuidFromStringName_Arg_0_choice);
            switch(GetGuidFromStringName_Arg_0_choice % 1) {
                case 0:
                    if (GetGuidFromStringName_Arg_0 != NULL) {
                        ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_0), (VOID *)GetGuidFromStringName_Arg_0);
                        GetGuidFromStringName_Arg_0[31] = 0;
                    }
                    break;
            }
            
            // Fuzzable Variable Initialization
            UINT8 GetGuidFromStringName_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(GetGuidFromStringName_Arg_1_choice), (VOID *)&GetGuidFromStringName_Arg_1_choice);
            switch(GetGuidFromStringName_Arg_1_choice % 1) {
                case 0:
                    if (GetGuidFromStringName_Arg_1 != NULL) {
                        ReadBytes(Input, 31 * sizeof(*GetGuidFromStringName_Arg_1), (VOID *)GetGuidFromStringName_Arg_1);
                        GetGuidFromStringName_Arg_1[31] = 0;
                    }
                    break;
            }
            
            FirnessUntrusted(GetGuidFromStringName_Arg_0, 32 * sizeof(CHAR16));
            FirnessUntrusted(GetGuidFromStringName_Arg_1, 32 * sizeof(CHAR8));
            FirnessSanitizer(TRUE);
            Status = GetGuidFromStringName(
                GetGuidFromStringName_Arg_0,
                GetGuidFromStringName_Arg_1,
                (EFI_GUID **)&SetInformation_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 6:
        {
        // Fuzzable Variable Initialization
        UINT8 SetInformation_Arg_1_choice = 0;
        ReadBytes(Input, sizeof(SetInformation_Arg_1_choice), (VOID *)&SetInformation_Arg_1_choice);
        switch(SetInformation_Arg_1_choice % 1) {
            case 0:
                if (SetInformation_Arg_1 != NULL) {
                    ReadBytes(Input, sizeof(*SetInformation_Arg_1), (VOID *)SetInformation_Arg_1);
                }
                break;
        }
    
            break;
        }
        case 7:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            SetInformation_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            SetInformation_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            SetInformation_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(SetInformation_Arg_1->Data4), (VOID *)&(SetInformation_Arg_1->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 SetInformation_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetInformation_Arg_2_choice), (VOID *)&SetInformation_Arg_2_choice);
    switch(SetInformation_Arg_2_choice % 1) {
        case 0:
            if (SetInformation_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*SetInformation_Arg_2), (VOID *)SetInformation_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetInformation_Arg_3), (VOID *)&SetInformation_Arg_3);
    SetInformation_Arg_3 = SetInformation_Arg_3 % (4096 + 1);
    if (SetInformation_Arg_2 != NULL) {
        FreePool(SetInformation_Arg_2);
    }
    SetInformation_Arg_2 = (UINTN* )AllocateZeroPool(SetInformation_Arg_3 > 0 ? SetInformation_Arg_3 : 1);
    if (SetInformation_Arg_2 == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }
    
    UINT8 SetInformation_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(SetInformation_Arg_1_LiveChoice), (VOID *)&SetInformation_Arg_1_LiveChoice);
    if (FirnessLive_EFI_GUID___Count > 0 && (SetInformation_Arg_1_LiveChoice & 1)) {
        SetInformation_Arg_1 = FirnessLive_EFI_GUID__[SetInformation_Arg_1_LiveChoice % FirnessLive_EFI_GUID___Count];
    }
    FirnessUntrusted(SetInformation_Arg_1, sizeof(EFI_GUID));
    FirnessUntrusted(SetInformation_Arg_2, SetInformation_Arg_3);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetInformation(
        ProtocolVariable,
        SetInformation_Arg_1,
        (void *)SetInformation_Arg_2,
        SetInformation_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}


// Declared in a package this harness does not include, so the value is
// carried here rather than resolved through the inf.
EFI_GUID gTcg800155PlatformIdEventHobGuid = { 0xe2c3bc69, 0x615c, 0x4b5b, { 0x8e, 0x5c, 0xa0, 0x33, 0xa9, 0xc2, 0x5e, 0xd6 }};
