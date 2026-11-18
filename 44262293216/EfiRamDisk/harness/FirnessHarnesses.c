#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
EFI_DEVICE_PATH_PROTOCOL * FirnessLive_EFI_DEVICE_PATH_PROTOCOL__[4];
UINTN FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count = 0;

/*
    This is a harness for fuzzing the Protocols service
    called Register.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegister(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_RAM_DISK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRamDiskProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 Register_Arg_0 = {0};
    UINT64 Register_Arg_1 = {0};
    EFI_GUID * Register_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Register_Arg_0), (VOID *)&Register_Arg_0);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Register_Arg_1), (VOID *)&Register_Arg_1);
    Register_Arg_1 = Register_Arg_1 % (sizeof(EFI_GUID) + 1);
    
    UINT8* Register_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Register_Arg_2_choice), (VOID *)Register_Arg_2_choice);
    switch(*Register_Arg_2_choice % 8) {
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
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbios3TableGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbiosTableGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMemoryTypeInformationGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMmCommunicateHeaderV3Guid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gUefiOvmfPkgTokenSpaceGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 13:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoUfsInterfaceGuid;
            
                    break;
                }
                case 14:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEdkiiDeviceIdentifierTypePciGuid;
            
                    break;
                }
                case 15:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiFirmwareFileSystem2Guid;
            
                    break;
                }
                case 16:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gVarCheckPolicyLibMmiHandlerGuid;
            
                    break;
                }
                case 17:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gTcg800155PlatformIdEventHobGuid;
            
                    break;
                }
                case 18:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiGlobalVariableGuid;
            
                    break;
                }
                case 19:
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
                case 20:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gQemuRamfbGuid;
            
                    break;
                }
                case 21:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gZeroGuid;
            
                    break;
                }
                case 22:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPcAnsiGuid;
            
                    break;
                }
                case 23:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100Guid;
            
                    break;
                }
                case 24:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVT100PlusGuid;
            
                    break;
                }
                case 25:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVTUTF8Guid;
            
                    break;
                }
                case 26:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiUartDevicePathGuid;
            
                    break;
                }
                case 27:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSasDevicePathGuid;
            
                    break;
                }
                case 28:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDebugPortProtocolGuid;
            
                    break;
                }
                case 29:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualDiskGuid;
            
                    break;
                }
                case 30:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiVirtualCdGuid;
            
                    break;
                }
                case 31:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualDiskGuid;
            
                    break;
                }
                case 32:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiPersistentVirtualCdGuid;
            
                    break;
                }
            }
            FirnessUntrusted(CopyGuid_Arg_1, sizeof(GUID));
            FirnessSanitizer(TRUE);
            CopyGuid(
                Register_Arg_2,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
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
                Register_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 2:
        {
        // Fuzzable Variable Initialization
        UINT8 Register_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(Register_Arg_2_choice), (VOID *)&Register_Arg_2_choice);
        switch(Register_Arg_2_choice % 1) {
            case 0:
                if (Register_Arg_2 != NULL) {
                    ReadBytes(Input, sizeof(*Register_Arg_2), (VOID *)Register_Arg_2);
                }
                break;
        }
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                Register_Arg_2
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
                (EFI_GUID **)&Register_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Fuzzable Variable Initialization
        UINT8 Register_Arg_2_choice = 0;
        ReadBytes(Input, sizeof(Register_Arg_2_choice), (VOID *)&Register_Arg_2_choice);
        switch(Register_Arg_2_choice % 1) {
            case 0:
                if (Register_Arg_2 != NULL) {
                    ReadBytes(Input, sizeof(*Register_Arg_2), (VOID *)Register_Arg_2);
                }
                break;
        }
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                (EFI_GUID **)&Register_Arg_2
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 7:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            Register_Arg_2->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            Register_Arg_2->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            Register_Arg_2->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(Register_Arg_2->Data4), (VOID *)&(Register_Arg_2->Data4));
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * Register_Arg_4 = NULL;
    FirnessMakeDevicePath (Register_Arg_4, 4096);
    UINT8* Register_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Register_Arg_4_OutputChoice), (VOID *)Register_Arg_4_OutputChoice);
    if(*Register_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Register_Arg_4), (VOID *)Register_Arg_4);
    }
    VOID *Register_Arg_3 = AllocateZeroPool(4096);
    FirnessUntrusted(Register_Arg_2, Register_Arg_1);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Register(
        Register_Arg_0,
        Register_Arg_1,
        Register_Arg_2,
        Register_Arg_3,
        (EFI_DEVICE_PATH_PROTOCOL * *)&Register_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count < 4 && Register_Arg_4 != NULL) {
        FirnessLive_EFI_DEVICE_PATH_PROTOCOL__[FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count++] = Register_Arg_4;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Unregister.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnregister(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_RAM_DISK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiRamDiskProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * Unregister_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(4096);
    FirnessMakeDevicePath (Unregister_Arg_0, 4096);
    
    UINT8* Unregister_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Unregister_Arg_0_choice), (VOID *)Unregister_Arg_0_choice);
    switch(*Unregister_Arg_0_choice % 4) {
        case 0:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_DEVICE_PATH_PROTOCOL * ChooseFile_Arg_0 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(4096);
            FirnessMakeDevicePath (ChooseFile_Arg_0, 4096);
            CHAR16 * ChooseFile_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
            
            // Generator Struct Variable Initialization
            {
                UINT8 Firness_Type;
                ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
                ChooseFile_Arg_0->Type = Firness_Type;
            }
            {
                UINT8 Firness_SubType;
                ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
                ChooseFile_Arg_0->SubType = Firness_SubType;
            }
            ReadBytes(Input, sizeof(ChooseFile_Arg_0->Length), (VOID *)&(ChooseFile_Arg_0->Length));
            FirnessMakeDevicePath (ChooseFile_Arg_0, 4096);
            
            // Fuzzable Variable Initialization
            UINT8 ChooseFile_Arg_1_choice = 0;
            ReadBytes(Input, sizeof(ChooseFile_Arg_1_choice), (VOID *)&ChooseFile_Arg_1_choice);
            switch(ChooseFile_Arg_1_choice % 1) {
                case 0:
                    if (ChooseFile_Arg_1 != NULL) {
                        ReadBytes(Input, 31 * sizeof(*ChooseFile_Arg_1), (VOID *)ChooseFile_Arg_1);
                        ChooseFile_Arg_1[31] = 0;
                    }
                    break;
            }
            
            UINT8 ChooseFile_Arg_0_LiveChoice = 0;
            ReadBytes(Input, sizeof(ChooseFile_Arg_0_LiveChoice), (VOID *)&ChooseFile_Arg_0_LiveChoice);
            if (FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count > 0 && (ChooseFile_Arg_0_LiveChoice & 1)) {
                ChooseFile_Arg_0 = FirnessLive_EFI_DEVICE_PATH_PROTOCOL__[ChooseFile_Arg_0_LiveChoice % FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count];
            }
            FirnessUntrusted(ChooseFile_Arg_0, 4096);
            FirnessUntrusted(ChooseFile_Arg_1, 32 * sizeof(CHAR16));
            FirnessSanitizer(TRUE);
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                (EFI_DEVICE_PATH_PROTOCOL **)&Unregister_Arg_0
            );
            FirnessSanitizer(FALSE);
            FirnessMakeDevicePath (Unregister_Arg_0, 4096);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        UINT8 Unregister_Arg_0_choice = 0;
        ReadBytes(Input, sizeof(Unregister_Arg_0_choice), (VOID *)&Unregister_Arg_0_choice);
        switch(Unregister_Arg_0_choice % 1) {
            case 0:
                if (Unregister_Arg_0 != NULL) {
                    ReadBytes(Input, sizeof(*Unregister_Arg_0), (VOID *)Unregister_Arg_0);
                    FirnessMakeDevicePath (Unregister_Arg_0, 4096);
                }
                break;
        }
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Input Variable(s)
            */
            EFI_GUID * GetFileDevicePathFromAnyFv_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
            EFI_SECTION_TYPE GetFileDevicePathFromAnyFv_Arg_1 = {0};
            UINTN GetFileDevicePathFromAnyFv_Arg_2 = {0};
            
            // Generator Struct Variable Initialization
            {
                UINT32 Firness_Data1;
                ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
                GetFileDevicePathFromAnyFv_Arg_0->Data1 = Firness_Data1;
            }
            {
                UINT16 Firness_Data2;
                ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
                GetFileDevicePathFromAnyFv_Arg_0->Data2 = Firness_Data2;
            }
            {
                UINT16 Firness_Data3;
                ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
                GetFileDevicePathFromAnyFv_Arg_0->Data3 = Firness_Data3;
            }
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_0->Data4), (VOID *)&(GetFileDevicePathFromAnyFv_Arg_0->Data4));
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_1), (VOID *)&GetFileDevicePathFromAnyFv_Arg_1);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(GetFileDevicePathFromAnyFv_Arg_2), (VOID *)&GetFileDevicePathFromAnyFv_Arg_2);
            
            FirnessUntrusted(GetFileDevicePathFromAnyFv_Arg_0, sizeof(EFI_GUID));
            FirnessSanitizer(TRUE);
            Status = GetFileDevicePathFromAnyFv(
                GetFileDevicePathFromAnyFv_Arg_0,
                GetFileDevicePathFromAnyFv_Arg_1,
                GetFileDevicePathFromAnyFv_Arg_2,
                (EFI_DEVICE_PATH_PROTOCOL **)&Unregister_Arg_0
            );
            FirnessSanitizer(FALSE);
            FirnessMakeDevicePath (Unregister_Arg_0, 4096);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            Unregister_Arg_0->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            Unregister_Arg_0->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(Unregister_Arg_0->Length), (VOID *)&(Unregister_Arg_0->Length));
            FirnessMakeDevicePath (Unregister_Arg_0, 4096);
    
            break;
        }
    }
    UINT8 Unregister_Arg_0_LiveChoice = 0;
    ReadBytes(Input, sizeof(Unregister_Arg_0_LiveChoice), (VOID *)&Unregister_Arg_0_LiveChoice);
    if (FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count > 0 && (Unregister_Arg_0_LiveChoice & 1)) {
        Unregister_Arg_0 = FirnessLive_EFI_DEVICE_PATH_PROTOCOL__[Unregister_Arg_0_LiveChoice % FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count];
    }
    FirnessUntrusted(Unregister_Arg_0, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Unregister(
        Unregister_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}


// Declared in a package this harness does not include, so the value is
// carried here rather than resolved through the inf.
EFI_GUID gTcg800155PlatformIdEventHobGuid = { 0xe2c3bc69, 0x615c, 0x4b5b, { 0x8e, 0x5c, 0xa0, 0x33, 0xa9, 0xc2, 0x5e, 0xd6 }};
