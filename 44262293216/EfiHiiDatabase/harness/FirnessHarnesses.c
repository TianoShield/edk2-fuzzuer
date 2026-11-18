#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
EFI_GUID * FirnessLive_EFI_GUID__[4];
UINTN FirnessLive_EFI_GUID___Count = 0;
EFI_HANDLE FirnessLive_EFI_HANDLE[4];
UINTN FirnessLive_EFI_HANDLE_Count = 0;
EFI_HII_HANDLE FirnessLive_EFI_HII_HANDLE[4];
UINTN FirnessLive_EFI_HII_HANDLE_Count = 0;
EFI_HII_PACKAGE_LIST_HEADER * FirnessLive_EFI_HII_PACKAGE_LIST_HEADER__[4];
UINTN FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count = 0;
UINT16 * FirnessLive_UINT16__[4];
UINTN FirnessLive_UINT16___Count = 0;
UINTN * FirnessLive_UINTN__[4];
UINTN FirnessLive_UINTN___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called ExportPackageLists.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExportPackageLists(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE ExportPackageLists_Arg_1 = {0};
    UINTN * ExportPackageLists_Arg_2 = (UINTN *)AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    // EFI_HII_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    UINT8 ExportPackageLists_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(ExportPackageLists_Arg_2_choice), (VOID *)&ExportPackageLists_Arg_2_choice);
    switch(ExportPackageLists_Arg_2_choice % 1) {
        case 0:
            if (ExportPackageLists_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*ExportPackageLists_Arg_2), (VOID *)ExportPackageLists_Arg_2);
                *ExportPackageLists_Arg_2 = *ExportPackageLists_Arg_2 % (sizeof(EFI_HII_PACKAGE_LIST_HEADER) + 1);
            }
            break;
    }
    
    /*
        Output Variable(s)
    */
    EFI_HII_PACKAGE_LIST_HEADER * ExportPackageLists_Arg_3 = (EFI_HII_PACKAGE_LIST_HEADER *)AllocateZeroPool(sizeof(EFI_HII_PACKAGE_LIST_HEADER));
    UINT8* ExportPackageLists_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ExportPackageLists_Arg_3_OutputChoice), (VOID *)ExportPackageLists_Arg_3_OutputChoice);
    if(*ExportPackageLists_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ExportPackageLists_Arg_3), (VOID *)ExportPackageLists_Arg_3);
    }
    UINT8 ExportPackageLists_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(ExportPackageLists_Arg_1_LiveChoice), (VOID *)&ExportPackageLists_Arg_1_LiveChoice);
    if (FirnessLive_EFI_HII_HANDLE_Count > 0 && (ExportPackageLists_Arg_1_LiveChoice & 1)) {
        ExportPackageLists_Arg_1 = FirnessLive_EFI_HII_HANDLE[ExportPackageLists_Arg_1_LiveChoice % FirnessLive_EFI_HII_HANDLE_Count];
    }
    FirnessUntrusted(ExportPackageLists_Arg_2, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->ExportPackageLists(
        ProtocolVariable,
        ExportPackageLists_Arg_1,
        ExportPackageLists_Arg_2,
        ExportPackageLists_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && ExportPackageLists_Arg_2 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = ExportPackageLists_Arg_2;
    }
    if (FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count < 4 && ExportPackageLists_Arg_3 != NULL) {
        FirnessLive_EFI_HII_PACKAGE_LIST_HEADER__[FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count++] = ExportPackageLists_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetPackageListHandle.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetPackageListHandle(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE GetPackageListHandle_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    // EFI_HII_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    /*
        Output Variable(s)
    */
    EFI_HANDLE * GetPackageListHandle_Arg_2 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* GetPackageListHandle_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetPackageListHandle_Arg_2_OutputChoice), (VOID *)GetPackageListHandle_Arg_2_OutputChoice);
    if(*GetPackageListHandle_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetPackageListHandle_Arg_2), (VOID *)GetPackageListHandle_Arg_2);
    }
    UINT8 GetPackageListHandle_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetPackageListHandle_Arg_1_LiveChoice), (VOID *)&GetPackageListHandle_Arg_1_LiveChoice);
    if (FirnessLive_EFI_HII_HANDLE_Count > 0 && (GetPackageListHandle_Arg_1_LiveChoice & 1)) {
        GetPackageListHandle_Arg_1 = FirnessLive_EFI_HII_HANDLE[GetPackageListHandle_Arg_1_LiveChoice % FirnessLive_EFI_HII_HANDLE_Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetPackageListHandle(
        ProtocolVariable,
        GetPackageListHandle_Arg_1,
        GetPackageListHandle_Arg_2
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_HANDLE_Count < 4 && GetPackageListHandle_Arg_2 != NULL && *GetPackageListHandle_Arg_2 != NULL) {
        FirnessLive_EFI_HANDLE[FirnessLive_EFI_HANDLE_Count++] = *GetPackageListHandle_Arg_2;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterPackageNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterPackageNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 RegisterPackageNotify_Arg_1 = {0};
    EFI_GUID * RegisterPackageNotify_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    EFI_HII_DATABASE_NOTIFY_TYPE RegisterPackageNotify_Arg_4 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_1), (VOID *)&RegisterPackageNotify_Arg_1);
    
    UINT8* RegisterPackageNotify_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*RegisterPackageNotify_Arg_2_choice), (VOID *)RegisterPackageNotify_Arg_2_choice);
    switch(*RegisterPackageNotify_Arg_2_choice % 7) {
        case 0:
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
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbios3TableGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbiosTableGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMemoryTypeInformationGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMmCommunicateHeaderV3Guid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gUefiOvmfPkgTokenSpaceGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 27:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 28:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gTcg800155PlatformIdEventHobGuid;
            
                    break;
                }
                case 29:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 30:
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
                case 31:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gQemuRamfbGuid;
            
                    break;
                }
                case 32:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
            }
            FirnessUntrusted(CopyGuid_Arg_1, sizeof(GUID));
            FirnessSanitizer(TRUE);
            CopyGuid(
                RegisterPackageNotify_Arg_2,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                (EFI_GUID **)&RegisterPackageNotify_Arg_2
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
                RegisterPackageNotify_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                RegisterPackageNotify_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 4:
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
                (EFI_GUID **)&RegisterPackageNotify_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Fuzzable Variable Initialization
        UINT8 RegisterPackageNotify_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_2_choice), (VOID *)&RegisterPackageNotify_Arg_2_choice);
        switch(RegisterPackageNotify_Arg_2_choice % 1) {
            case 0:
                if (RegisterPackageNotify_Arg_2 != NULL) {
                    ReadBytes(Input, sizeof(*RegisterPackageNotify_Arg_2), (VOID *)RegisterPackageNotify_Arg_2);
                }
                break;
        }
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            RegisterPackageNotify_Arg_2->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            RegisterPackageNotify_Arg_2->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            RegisterPackageNotify_Arg_2->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_2->Data4), (VOID *)&(RegisterPackageNotify_Arg_2->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_4), (VOID *)&RegisterPackageNotify_Arg_4);
    
    /*
        Output Variable(s)
    */
    EFI_HANDLE * RegisterPackageNotify_Arg_5 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
    UINT8* RegisterPackageNotify_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*RegisterPackageNotify_Arg_5_OutputChoice), (VOID *)RegisterPackageNotify_Arg_5_OutputChoice);
    if(*RegisterPackageNotify_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*RegisterPackageNotify_Arg_5), (VOID *)RegisterPackageNotify_Arg_5);
    }
    UINT8 RegisterPackageNotify_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(RegisterPackageNotify_Arg_2_LiveChoice), (VOID *)&RegisterPackageNotify_Arg_2_LiveChoice);
    if (FirnessLive_EFI_GUID___Count > 0 && (RegisterPackageNotify_Arg_2_LiveChoice & 1)) {
        RegisterPackageNotify_Arg_2 = FirnessLive_EFI_GUID__[RegisterPackageNotify_Arg_2_LiveChoice % FirnessLive_EFI_GUID___Count];
    }
    FirnessUntrusted(RegisterPackageNotify_Arg_2, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RegisterPackageNotify(
        ProtocolVariable,
        RegisterPackageNotify_Arg_1,
        RegisterPackageNotify_Arg_2,
        NULL,
        RegisterPackageNotify_Arg_4,
        RegisterPackageNotify_Arg_5
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_HANDLE_Count < 4 && RegisterPackageNotify_Arg_5 != NULL && *RegisterPackageNotify_Arg_5 != NULL) {
        FirnessLive_EFI_HANDLE[FirnessLive_EFI_HANDLE_Count++] = *RegisterPackageNotify_Arg_5;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UnregisterPackageNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnregisterPackageNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    EFI_HANDLE UnregisterPackageNotify_Arg_1_Handle = (EFI_HANDLE)ImageHandle;
    UINT8 UnregisterPackageNotify_Arg_1_Handle_LiveChoice = 0;
    ReadBytes(Input, sizeof(UnregisterPackageNotify_Arg_1_Handle_LiveChoice), (VOID *)&UnregisterPackageNotify_Arg_1_Handle_LiveChoice);
    if (FirnessLive_EFI_HANDLE_Count > 0 && (UnregisterPackageNotify_Arg_1_Handle_LiveChoice & 1)) {
        UnregisterPackageNotify_Arg_1_Handle = FirnessLive_EFI_HANDLE[UnregisterPackageNotify_Arg_1_Handle_LiveChoice % FirnessLive_EFI_HANDLE_Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->UnregisterPackageNotify(
        ProtocolVariable,
        UnregisterPackageNotify_Arg_1_Handle
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetKeyboardLayout.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetKeyboardLayout(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * SetKeyboardLayout_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    UINT8* SetKeyboardLayout_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*SetKeyboardLayout_Arg_1_choice), (VOID *)SetKeyboardLayout_Arg_1_choice);
    switch(*SetKeyboardLayout_Arg_1_choice % 8) {
        case 0:
        {
        // EFI_GUID Variable Initialization
        SetKeyboardLayout_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
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
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbios3TableGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbiosTableGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMemoryTypeInformationGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMmCommunicateHeaderV3Guid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gUefiOvmfPkgTokenSpaceGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 27:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 28:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gTcg800155PlatformIdEventHobGuid;
            
                    break;
                }
                case 29:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 30:
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
                case 31:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gQemuRamfbGuid;
            
                    break;
                }
                case 32:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
            }
            FirnessUntrusted(CopyGuid_Arg_1, sizeof(GUID));
            FirnessSanitizer(TRUE);
            CopyGuid(
                SetKeyboardLayout_Arg_1,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                (EFI_GUID **)&SetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
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
                SetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 4:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                SetKeyboardLayout_Arg_1
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
                (EFI_GUID **)&SetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 6:
        {
        // Fuzzable Variable Initialization
        UINT8 SetKeyboardLayout_Arg_1_choice = 0;
        ReadBytes(Input, sizeof(SetKeyboardLayout_Arg_1_choice), (VOID *)&SetKeyboardLayout_Arg_1_choice);
        switch(SetKeyboardLayout_Arg_1_choice % 1) {
            case 0:
                if (SetKeyboardLayout_Arg_1 != NULL) {
                    ReadBytes(Input, sizeof(*SetKeyboardLayout_Arg_1), (VOID *)SetKeyboardLayout_Arg_1);
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
            SetKeyboardLayout_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            SetKeyboardLayout_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            SetKeyboardLayout_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(SetKeyboardLayout_Arg_1->Data4), (VOID *)&(SetKeyboardLayout_Arg_1->Data4));
    
            break;
        }
    }
    UINT8 SetKeyboardLayout_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(SetKeyboardLayout_Arg_1_LiveChoice), (VOID *)&SetKeyboardLayout_Arg_1_LiveChoice);
    if (FirnessLive_EFI_GUID___Count > 0 && (SetKeyboardLayout_Arg_1_LiveChoice & 1)) {
        SetKeyboardLayout_Arg_1 = FirnessLive_EFI_GUID__[SetKeyboardLayout_Arg_1_LiveChoice % FirnessLive_EFI_GUID___Count];
    }
    FirnessUntrusted(SetKeyboardLayout_Arg_1, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetKeyboardLayout(
        ProtocolVariable,
        SetKeyboardLayout_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetKeyboardLayout.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetKeyboardLayout(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetKeyboardLayout_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT16 * GetKeyboardLayout_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
    UINT8* GetKeyboardLayout_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetKeyboardLayout_Arg_1_choice), (VOID *)GetKeyboardLayout_Arg_1_choice);
    switch(*GetKeyboardLayout_Arg_1_choice % 7) {
        case 0:
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
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbios3TableGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbiosTableGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMemoryTypeInformationGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMmCommunicateHeaderV3Guid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gUefiOvmfPkgTokenSpaceGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 27:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 28:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gTcg800155PlatformIdEventHobGuid;
            
                    break;
                }
                case 29:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 30:
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
                case 31:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gQemuRamfbGuid;
            
                    break;
                }
                case 32:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
            }
            FirnessUntrusted(CopyGuid_Arg_1, sizeof(GUID));
            FirnessSanitizer(TRUE);
            CopyGuid(
                GetKeyboardLayout_Arg_1,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                (EFI_GUID **)&GetKeyboardLayout_Arg_1
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
                GetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                GetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 4:
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
                (EFI_GUID **)&GetKeyboardLayout_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Fuzzable Variable Initialization
        UINT8 GetKeyboardLayout_Arg_1_choice = 0;
        ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_1_choice), (VOID *)&GetKeyboardLayout_Arg_1_choice);
        switch(GetKeyboardLayout_Arg_1_choice % 1) {
            case 0:
                if (GetKeyboardLayout_Arg_1 != NULL) {
                    ReadBytes(Input, sizeof(*GetKeyboardLayout_Arg_1), (VOID *)GetKeyboardLayout_Arg_1);
                }
                break;
        }
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            GetKeyboardLayout_Arg_1->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            GetKeyboardLayout_Arg_1->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            GetKeyboardLayout_Arg_1->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_1->Data4), (VOID *)&(GetKeyboardLayout_Arg_1->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 GetKeyboardLayout_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_2_choice), (VOID *)&GetKeyboardLayout_Arg_2_choice);
    switch(GetKeyboardLayout_Arg_2_choice % 1) {
        case 0:
            if (GetKeyboardLayout_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*GetKeyboardLayout_Arg_2), (VOID *)GetKeyboardLayout_Arg_2);
                *GetKeyboardLayout_Arg_2 = *GetKeyboardLayout_Arg_2 % (sizeof(EFI_HII_KEYBOARD_LAYOUT) + 1);
            }
            break;
    }
    
    /*
        Output Variable(s)
    */
    EFI_HII_KEYBOARD_LAYOUT * GetKeyboardLayout_Arg_3 = (EFI_HII_KEYBOARD_LAYOUT *)AllocateZeroPool(sizeof(EFI_HII_KEYBOARD_LAYOUT));
    UINT8* GetKeyboardLayout_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetKeyboardLayout_Arg_3_OutputChoice), (VOID *)GetKeyboardLayout_Arg_3_OutputChoice);
    if(*GetKeyboardLayout_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetKeyboardLayout_Arg_3), (VOID *)GetKeyboardLayout_Arg_3);
    }
    UINT8 GetKeyboardLayout_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetKeyboardLayout_Arg_1_LiveChoice), (VOID *)&GetKeyboardLayout_Arg_1_LiveChoice);
    if (FirnessLive_EFI_GUID___Count > 0 && (GetKeyboardLayout_Arg_1_LiveChoice & 1)) {
        GetKeyboardLayout_Arg_1 = FirnessLive_EFI_GUID__[GetKeyboardLayout_Arg_1_LiveChoice % FirnessLive_EFI_GUID___Count];
    }
    FirnessUntrusted(GetKeyboardLayout_Arg_1, sizeof(EFI_GUID));
    FirnessUntrusted(GetKeyboardLayout_Arg_2, sizeof(UINT16));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetKeyboardLayout(
        ProtocolVariable,
        GetKeyboardLayout_Arg_1,
        GetKeyboardLayout_Arg_2,
        GetKeyboardLayout_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINT16___Count < 4 && GetKeyboardLayout_Arg_2 != NULL) {
        FirnessLive_UINT16__[FirnessLive_UINT16___Count++] = GetKeyboardLayout_Arg_2;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called NewPackageList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzNewPackageList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_PACKAGE_LIST_HEADER * NewPackageList_Arg_1 = (EFI_HII_PACKAGE_LIST_HEADER *)AllocateZeroPool(sizeof(EFI_HII_PACKAGE_LIST_HEADER));
    UINTN*  NewPackageList_Arg_2 = (UINTN* )AllocateZeroPool(4096);
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(NewPackageList_Arg_1->PackageListGuid), (VOID *)&(NewPackageList_Arg_1->PackageListGuid));
    NewPackageList_Arg_1->PackageLength = sizeof(EFI_HII_PACKAGE_LIST_HEADER);
    
    UINT8* NewPackageList_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*NewPackageList_Arg_2_choice), (VOID *)NewPackageList_Arg_2_choice);
    switch(*NewPackageList_Arg_2_choice % 5) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 NewPackageList_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(NewPackageList_Arg_2_choice), (VOID *)&NewPackageList_Arg_2_choice);
        switch(NewPackageList_Arg_2_choice % 2) {
            case 0:
                if (NewPackageList_Arg_2 != NULL) {
                    ReadBytes(Input, sizeof(*NewPackageList_Arg_2), (VOID *)NewPackageList_Arg_2);
                }
                break;
            case 1:
            {
                gBS->FreePool(NewPackageList_Arg_2);
                NewPackageList_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * EfiBootManagerConnectDevicePath_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(4096);
            FirnessMakeDevicePath (EfiBootManagerConnectDevicePath_Arg_0, 4096);
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                EfiBootManagerConnectDevicePath_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                EfiBootManagerConnectDevicePath_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(EfiBootManagerConnectDevicePath_Arg_0->Length), (VOID *)&(EfiBootManagerConnectDevicePath_Arg_0->Length));
            FirnessMakeDevicePath (EfiBootManagerConnectDevicePath_Arg_0, 4096);
            
            /*
                Output Variable(s)
            */
            EFI_HANDLE * EfiBootManagerConnectDevicePath_Arg_1 = (EFI_HANDLE *)AllocateZeroPool(sizeof(EFI_HANDLE));
            UINT8* EfiBootManagerConnectDevicePath_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*EfiBootManagerConnectDevicePath_Arg_1_OutputChoice), (VOID *)EfiBootManagerConnectDevicePath_Arg_1_OutputChoice);
            if(*EfiBootManagerConnectDevicePath_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*EfiBootManagerConnectDevicePath_Arg_1), (VOID *)EfiBootManagerConnectDevicePath_Arg_1);
            }
            FirnessUntrusted(EfiBootManagerConnectDevicePath_Arg_0, 4096);
            FirnessSanitizer(TRUE);
            Status = EfiBootManagerConnectDevicePath(
                EfiBootManagerConnectDevicePath_Arg_0,
                EfiBootManagerConnectDevicePath_Arg_1
            );
            FirnessSanitizer(FALSE);
            if (FirnessLive_EFI_HANDLE_Count < 4 && EfiBootManagerConnectDevicePath_Arg_1 != NULL && *EfiBootManagerConnectDevicePath_Arg_1 != NULL) {
                FirnessLive_EFI_HANDLE[FirnessLive_EFI_HANDLE_Count++] = *EfiBootManagerConnectDevicePath_Arg_1;
            }
    
            break;
        }
        case 2:
        {
        // Fuzzable Variable Initialization
        UINT8 NewPackageList_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(NewPackageList_Arg_2_choice), (VOID *)&NewPackageList_Arg_2_choice);
        switch(NewPackageList_Arg_2_choice % 2) {
            case 0:
                if (NewPackageList_Arg_2 != NULL) {
                    ReadBytes(Input, sizeof(*NewPackageList_Arg_2), (VOID *)NewPackageList_Arg_2);
                }
                break;
            case 1:
            {
                gBS->FreePool(NewPackageList_Arg_2);
                NewPackageList_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
        case 3:
        {
        // Fuzzable Variable Initialization
        UINT8 NewPackageList_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(NewPackageList_Arg_2_choice), (VOID *)&NewPackageList_Arg_2_choice);
        switch(NewPackageList_Arg_2_choice % 2) {
            case 0:
                if (NewPackageList_Arg_2 != NULL) {
                    ReadBytes(Input, sizeof(*NewPackageList_Arg_2), (VOID *)NewPackageList_Arg_2);
                }
                break;
            case 1:
            {
                gBS->FreePool(NewPackageList_Arg_2);
                NewPackageList_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
        case 4:
        {
        // Fuzzable Variable Initialization
        UINT8 NewPackageList_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(NewPackageList_Arg_2_choice), (VOID *)&NewPackageList_Arg_2_choice);
        switch(NewPackageList_Arg_2_choice % 2) {
            case 0:
                if (NewPackageList_Arg_2 != NULL) {
                    ReadBytes(Input, sizeof(*NewPackageList_Arg_2), (VOID *)NewPackageList_Arg_2);
                }
                break;
            case 1:
            {
                gBS->FreePool(NewPackageList_Arg_2);
                NewPackageList_Arg_2 = NULL;
                break;
            }
        }
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    EFI_HII_HANDLE * NewPackageList_Arg_3 = (EFI_HII_HANDLE *)AllocateZeroPool(sizeof(EFI_HII_HANDLE));
    UINT8* NewPackageList_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*NewPackageList_Arg_3_OutputChoice), (VOID *)NewPackageList_Arg_3_OutputChoice);
    if(*NewPackageList_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*NewPackageList_Arg_3), (VOID *)NewPackageList_Arg_3);
    }
    UINT8 NewPackageList_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(NewPackageList_Arg_1_LiveChoice), (VOID *)&NewPackageList_Arg_1_LiveChoice);
    if (FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count > 0 && (NewPackageList_Arg_1_LiveChoice & 1)) {
        NewPackageList_Arg_1 = FirnessLive_EFI_HII_PACKAGE_LIST_HEADER__[NewPackageList_Arg_1_LiveChoice % FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count];
    }
    FirnessUntrusted(NewPackageList_Arg_1, sizeof(EFI_HII_PACKAGE_LIST_HEADER));
    FirnessUntrusted(NewPackageList_Arg_2, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->NewPackageList(
        ProtocolVariable,
        NewPackageList_Arg_1,
        (void *)NewPackageList_Arg_2,
        NewPackageList_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_HII_HANDLE_Count < 4 && NewPackageList_Arg_3 != NULL && *NewPackageList_Arg_3 != NULL) {
        FirnessLive_EFI_HII_HANDLE[FirnessLive_EFI_HII_HANDLE_Count++] = *NewPackageList_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RemovePackageList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRemovePackageList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE RemovePackageList_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    // EFI_HII_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    UINT8 RemovePackageList_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(RemovePackageList_Arg_1_LiveChoice), (VOID *)&RemovePackageList_Arg_1_LiveChoice);
    if (FirnessLive_EFI_HII_HANDLE_Count > 0 && (RemovePackageList_Arg_1_LiveChoice & 1)) {
        RemovePackageList_Arg_1 = FirnessLive_EFI_HII_HANDLE[RemovePackageList_Arg_1_LiveChoice % FirnessLive_EFI_HII_HANDLE_Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RemovePackageList(
        ProtocolVariable,
        RemovePackageList_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ListPackageLists.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzListPackageLists(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 ListPackageLists_Arg_1 = {0};
    EFI_GUID * ListPackageLists_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN * ListPackageLists_Arg_3 = (UINTN *)AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ListPackageLists_Arg_1), (VOID *)&ListPackageLists_Arg_1);
    ListPackageLists_Arg_1 = ListPackageLists_Arg_1 % (4096 + 1);
    
    UINT8* ListPackageLists_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ListPackageLists_Arg_2_choice), (VOID *)ListPackageLists_Arg_2_choice);
    switch(*ListPackageLists_Arg_2_choice % 7) {
        case 0:
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
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbios3TableGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbiosTableGuid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMemoryTypeInformationGuid;
            
                    break;
                }
                case 19:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMmCommunicateHeaderV3Guid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gUefiOvmfPkgTokenSpaceGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 27:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 28:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gTcg800155PlatformIdEventHobGuid;
            
                    break;
                }
                case 29:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 30:
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
                case 31:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gQemuRamfbGuid;
            
                    break;
                }
                case 32:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
            }
            FirnessUntrusted(CopyGuid_Arg_1, sizeof(GUID));
            FirnessSanitizer(TRUE);
            CopyGuid(
                ListPackageLists_Arg_2,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                (EFI_GUID **)&ListPackageLists_Arg_2
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
                ListPackageLists_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                ListPackageLists_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 4:
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
                (EFI_GUID **)&ListPackageLists_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Fuzzable Variable Initialization
        UINT8 ListPackageLists_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(ListPackageLists_Arg_2_choice), (VOID *)&ListPackageLists_Arg_2_choice);
        switch(ListPackageLists_Arg_2_choice % 1) {
            case 0:
                if (ListPackageLists_Arg_2 != NULL) {
                    ReadBytes(Input, sizeof(*ListPackageLists_Arg_2), (VOID *)ListPackageLists_Arg_2);
                }
                break;
        }
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            ListPackageLists_Arg_2->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            ListPackageLists_Arg_2->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            ListPackageLists_Arg_2->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(ListPackageLists_Arg_2->Data4), (VOID *)&(ListPackageLists_Arg_2->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 ListPackageLists_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(ListPackageLists_Arg_3_choice), (VOID *)&ListPackageLists_Arg_3_choice);
    switch(ListPackageLists_Arg_3_choice % 1) {
        case 0:
            if (ListPackageLists_Arg_3 != NULL) {
                ReadBytes(Input, sizeof(*ListPackageLists_Arg_3), (VOID *)ListPackageLists_Arg_3);
                *ListPackageLists_Arg_3 = *ListPackageLists_Arg_3 % (4096 + 1);
            }
            break;
    }
    
    /*
        Output Variable(s)
    */
    EFI_HII_HANDLE * ListPackageLists_Arg_4 = (EFI_HII_HANDLE *)AllocateZeroPool(sizeof(EFI_HII_HANDLE));
    UINT8* ListPackageLists_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ListPackageLists_Arg_4_OutputChoice), (VOID *)ListPackageLists_Arg_4_OutputChoice);
    if(*ListPackageLists_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ListPackageLists_Arg_4), (VOID *)ListPackageLists_Arg_4);
    }
    UINT8 ListPackageLists_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(ListPackageLists_Arg_2_LiveChoice), (VOID *)&ListPackageLists_Arg_2_LiveChoice);
    if (FirnessLive_EFI_GUID___Count > 0 && (ListPackageLists_Arg_2_LiveChoice & 1)) {
        ListPackageLists_Arg_2 = FirnessLive_EFI_GUID__[ListPackageLists_Arg_2_LiveChoice % FirnessLive_EFI_GUID___Count];
    }
    FirnessUntrusted(ListPackageLists_Arg_2, sizeof(EFI_GUID));
    FirnessUntrusted(ListPackageLists_Arg_3, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->ListPackageLists(
        ProtocolVariable,
        ListPackageLists_Arg_1,
        ListPackageLists_Arg_2,
        ListPackageLists_Arg_3,
        ListPackageLists_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && ListPackageLists_Arg_3 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = ListPackageLists_Arg_3;
    }
    if (FirnessLive_EFI_HII_HANDLE_Count < 4 && ListPackageLists_Arg_4 != NULL && *ListPackageLists_Arg_4 != NULL) {
        FirnessLive_EFI_HII_HANDLE[FirnessLive_EFI_HII_HANDLE_Count++] = *ListPackageLists_Arg_4;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UpdatePackageList.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUpdatePackageList(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE UpdatePackageList_Arg_1 = {0};
    EFI_HII_PACKAGE_LIST_HEADER * UpdatePackageList_Arg_2 = (EFI_HII_PACKAGE_LIST_HEADER *)AllocateZeroPool(sizeof(EFI_HII_PACKAGE_LIST_HEADER));
    
    // Fuzzable Variable Initialization
    // EFI_HII_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Generator Struct Variable Initialization
    ReadBytes(Input, sizeof(UpdatePackageList_Arg_2->PackageListGuid), (VOID *)&(UpdatePackageList_Arg_2->PackageListGuid));
    UpdatePackageList_Arg_2->PackageLength = sizeof(EFI_HII_PACKAGE_LIST_HEADER);
    
    UINT8 UpdatePackageList_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(UpdatePackageList_Arg_1_LiveChoice), (VOID *)&UpdatePackageList_Arg_1_LiveChoice);
    if (FirnessLive_EFI_HII_HANDLE_Count > 0 && (UpdatePackageList_Arg_1_LiveChoice & 1)) {
        UpdatePackageList_Arg_1 = FirnessLive_EFI_HII_HANDLE[UpdatePackageList_Arg_1_LiveChoice % FirnessLive_EFI_HII_HANDLE_Count];
    }
    UINT8 UpdatePackageList_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(UpdatePackageList_Arg_2_LiveChoice), (VOID *)&UpdatePackageList_Arg_2_LiveChoice);
    if (FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count > 0 && (UpdatePackageList_Arg_2_LiveChoice & 1)) {
        UpdatePackageList_Arg_2 = FirnessLive_EFI_HII_PACKAGE_LIST_HEADER__[UpdatePackageList_Arg_2_LiveChoice % FirnessLive_EFI_HII_PACKAGE_LIST_HEADER___Count];
    }
    FirnessUntrusted(UpdatePackageList_Arg_2, sizeof(EFI_HII_PACKAGE_LIST_HEADER));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->UpdatePackageList(
        ProtocolVariable,
        UpdatePackageList_Arg_1,
        UpdatePackageList_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FindKeyboardLayouts.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFindKeyboardLayouts(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_DATABASE_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiDatabaseProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_GUID * FindKeyboardLayouts_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINT8* FindKeyboardLayouts_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*FindKeyboardLayouts_Arg_2_OutputChoice), (VOID *)FindKeyboardLayouts_Arg_2_OutputChoice);
    if(*FindKeyboardLayouts_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*FindKeyboardLayouts_Arg_2), (VOID *)FindKeyboardLayouts_Arg_2);
    }
    VOID *FindKeyboardLayouts_Arg_1 = AllocateZeroPool(4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->FindKeyboardLayouts(
        ProtocolVariable,
        FindKeyboardLayouts_Arg_1,
        FindKeyboardLayouts_Arg_2
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_GUID___Count < 4 && FindKeyboardLayouts_Arg_2 != NULL) {
        FirnessLive_EFI_GUID__[FirnessLive_EFI_GUID___Count++] = FindKeyboardLayouts_Arg_2;
    }
    return Status;
}


// Declared in a package this harness does not include, so the value is
// carried here rather than resolved through the inf.
EFI_GUID gTcg800155PlatformIdEventHobGuid = { 0xe2c3bc69, 0x615c, 0x4b5b, { 0x8e, 0x5c, 0xa0, 0x33, 0xa9, 0xc2, 0x5e, 0xd6 }};
