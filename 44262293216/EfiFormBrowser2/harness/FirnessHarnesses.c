#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
CHAR16 * FirnessLive_CHAR16__[4];
UINTN FirnessLive_CHAR16___Count = 0;
UINTN * FirnessLive_UINTN__[4];
UINTN FirnessLive_UINTN___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called SendForm.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSendForm(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FORM_BROWSER2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFormBrowser2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_HII_HANDLE * SendForm_Arg_1 = (EFI_HII_HANDLE *)AllocateZeroPool(4096);
    UINTN SendForm_Arg_2 = {0};
    EFI_GUID * SendForm_Arg_3 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    EFI_FORM_ID SendForm_Arg_4 = {0};
    EFI_SCREEN_DESCRIPTOR * SendForm_Arg_5 = (EFI_SCREEN_DESCRIPTOR *)AllocateZeroPool(sizeof(EFI_SCREEN_DESCRIPTOR));
    EFI_BROWSER_ACTION_REQUEST * SendForm_Arg_6 = (EFI_BROWSER_ACTION_REQUEST *)AllocateZeroPool(sizeof(EFI_BROWSER_ACTION_REQUEST));
    
    // Fuzzable Variable Initialization
    UINT8 SendForm_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SendForm_Arg_1_choice), (VOID *)&SendForm_Arg_1_choice);
    switch(SendForm_Arg_1_choice % 1) {
        case 0:
            if (SendForm_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*SendForm_Arg_1), (VOID *)SendForm_Arg_1);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SendForm_Arg_2), (VOID *)&SendForm_Arg_2);
    SendForm_Arg_2 = SendForm_Arg_2 % ((4096 / sizeof(EFI_HII_HANDLE)) + 1);
    
    UINT8* SendForm_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*SendForm_Arg_3_choice), (VOID *)SendForm_Arg_3_choice);
    switch(*SendForm_Arg_3_choice % 7) {
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
                CopyGuid_Arg_1 = &gEfiSmbios3TableGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbiosTableGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMemoryTypeInformationGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMmCommunicateHeaderV3Guid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gUefiOvmfPkgTokenSpaceGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
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
                SendForm_Arg_3,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                SendForm_Arg_3
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
                (EFI_GUID **)&SendForm_Arg_3
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Fuzzable Variable Initialization
        UINT8 SendForm_Arg_3_choice = 0;
        ReadBytes(Input, sizeof(SendForm_Arg_3_choice), (VOID *)&SendForm_Arg_3_choice);
        switch(SendForm_Arg_3_choice % 2) {
            case 0:
                if (SendForm_Arg_3 != NULL) {
                    ReadBytes(Input, sizeof(*SendForm_Arg_3), (VOID *)SendForm_Arg_3);
                }
                break;
            case 1:
            {
                gBS->FreePool(SendForm_Arg_3);
                SendForm_Arg_3 = NULL;
                break;
            }
        }
    
            break;
        }
        case 4:
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
                SendForm_Arg_3
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                (EFI_GUID **)&SendForm_Arg_3
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            SendForm_Arg_3->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            SendForm_Arg_3->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            SendForm_Arg_3->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(SendForm_Arg_3->Data4), (VOID *)&(SendForm_Arg_3->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SendForm_Arg_4), (VOID *)&SendForm_Arg_4);
    
    UINT8* SendForm_Arg_5_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*SendForm_Arg_5_choice), (VOID *)SendForm_Arg_5_choice);
    switch(*SendForm_Arg_5_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 SendForm_Arg_5_choice = 0;
        ReadBytes(Input, sizeof(SendForm_Arg_5_choice), (VOID *)&SendForm_Arg_5_choice);
        switch(SendForm_Arg_5_choice % 2) {
            case 0:
                if (SendForm_Arg_5 != NULL) {
                    ReadBytes(Input, sizeof(*SendForm_Arg_5), (VOID *)SendForm_Arg_5);
                }
                break;
            case 1:
            {
                gBS->FreePool(SendForm_Arg_5);
                SendForm_Arg_5 = NULL;
                break;
            }
        }
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
        {
            UINTN Firness_LeftColumn;
            ReadBytes(Input, sizeof(Firness_LeftColumn), (VOID *)&Firness_LeftColumn);
            SendForm_Arg_5->LeftColumn = Firness_LeftColumn;
        }
        {
            UINTN Firness_RightColumn;
            ReadBytes(Input, sizeof(Firness_RightColumn), (VOID *)&Firness_RightColumn);
            SendForm_Arg_5->RightColumn = Firness_RightColumn;
        }
        {
            UINTN Firness_TopRow;
            ReadBytes(Input, sizeof(Firness_TopRow), (VOID *)&Firness_TopRow);
            SendForm_Arg_5->TopRow = Firness_TopRow;
        }
        {
            UINTN Firness_BottomRow;
            ReadBytes(Input, sizeof(Firness_BottomRow), (VOID *)&Firness_BottomRow);
            SendForm_Arg_5->BottomRow = Firness_BottomRow;
        }
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 SendForm_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(SendForm_Arg_6_choice), (VOID *)&SendForm_Arg_6_choice);
    switch(SendForm_Arg_6_choice % 2) {
        case 0:
            if (SendForm_Arg_6 != NULL) {
                ReadBytes(Input, sizeof(*SendForm_Arg_6), (VOID *)SendForm_Arg_6);
            }
            break;
        case 1:
        {
            gBS->FreePool(SendForm_Arg_6);
            SendForm_Arg_6 = NULL;
            break;
        }
    }
    
    FirnessUntrusted(SendForm_Arg_1, 4096);
    FirnessUntrusted(SendForm_Arg_3, sizeof(EFI_GUID));
    FirnessUntrusted(SendForm_Arg_5, sizeof(EFI_SCREEN_DESCRIPTOR));
    FirnessUntrusted(SendForm_Arg_6, sizeof(EFI_BROWSER_ACTION_REQUEST));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SendForm(
        ProtocolVariable,
        SendForm_Arg_1,
        SendForm_Arg_2,
        SendForm_Arg_3,
        SendForm_Arg_4,
        SendForm_Arg_5,
        SendForm_Arg_6
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called BrowserCallback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBrowserCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_FORM_BROWSER2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiFormBrowser2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * BrowserCallback_Arg_1 = (UINTN *)AllocateZeroPool(4096);
    CHAR16 * BrowserCallback_Arg_2 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    BOOLEAN BrowserCallback_Arg_3 = {0};
    EFI_GUID * BrowserCallback_Arg_4 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    CHAR16 * BrowserCallback_Arg_5 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 BrowserCallback_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(BrowserCallback_Arg_1_choice), (VOID *)&BrowserCallback_Arg_1_choice);
    switch(BrowserCallback_Arg_1_choice % 1) {
        case 0:
            if (BrowserCallback_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*BrowserCallback_Arg_1), (VOID *)BrowserCallback_Arg_1);
                *BrowserCallback_Arg_1 = *BrowserCallback_Arg_1 % ((32 * sizeof(CHAR16)) + 1);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 BrowserCallback_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(BrowserCallback_Arg_2_choice), (VOID *)&BrowserCallback_Arg_2_choice);
    switch(BrowserCallback_Arg_2_choice % 1) {
        case 0:
            if (BrowserCallback_Arg_2 != NULL) {
                ReadBytes(Input, 31 * sizeof(*BrowserCallback_Arg_2), (VOID *)BrowserCallback_Arg_2);
                BrowserCallback_Arg_2[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BrowserCallback_Arg_3), (VOID *)&BrowserCallback_Arg_3);
    
    UINT8* BrowserCallback_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*BrowserCallback_Arg_4_choice), (VOID *)BrowserCallback_Arg_4_choice);
    switch(*BrowserCallback_Arg_4_choice % 7) {
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
                CopyGuid_Arg_1 = &gEfiSmbios3TableGuid;
            
                    break;
                }
                case 1:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmbiosTableGuid;
            
                    break;
                }
                case 2:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocModuleGuid;
            
                    break;
                }
                case 3:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocStackGuid;
            
                    break;
                }
                case 4:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiHobMemoryAllocBspStoreGuid;
            
                    break;
                }
                case 5:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMemoryTypeInformationGuid;
            
                    break;
                }
                case 6:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiAuthenticatedVariableGuid;
            
                    break;
                }
                case 7:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiMmCommunicateHeaderV3Guid;
            
                    break;
                }
                case 8:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiSmmVariableProtocolGuid;
            
                    break;
                }
                case 9:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiCallerIdGuid;
            
                    break;
                }
                case 10:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gUefiOvmfPkgTokenSpaceGuid;
            
                    break;
                }
                case 11:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoIdeInterfaceGuid;
            
                    break;
                }
                case 12:
                {
                // EFI_GUID Variable Initialization
                CopyGuid_Arg_1 = &gEfiDiskInfoAhciInterfaceGuid;
            
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
                BrowserCallback_Arg_4,
                CopyGuid_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = NetLibGetSystemGuid(
                BrowserCallback_Arg_4
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
                (EFI_GUID **)&BrowserCallback_Arg_4
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Fuzzable Variable Initialization
        UINT8 BrowserCallback_Arg_4_choice = 0;
        ReadBytes(Input, sizeof(BrowserCallback_Arg_4_choice), (VOID *)&BrowserCallback_Arg_4_choice);
        switch(BrowserCallback_Arg_4_choice % 2) {
            case 0:
                if (BrowserCallback_Arg_4 != NULL) {
                    ReadBytes(Input, sizeof(*BrowserCallback_Arg_4), (VOID *)BrowserCallback_Arg_4);
                }
                break;
            case 1:
            {
                gBS->FreePool(BrowserCallback_Arg_4);
                BrowserCallback_Arg_4 = NULL;
                break;
            }
        }
    
            break;
        }
        case 4:
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
                BrowserCallback_Arg_4
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 5:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            ExtractGuidedSectionGetGuidList(
                (EFI_GUID **)&BrowserCallback_Arg_4
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 6:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Data1;
            ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
            BrowserCallback_Arg_4->Data1 = Firness_Data1;
        }
        {
            UINT16 Firness_Data2;
            ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
            BrowserCallback_Arg_4->Data2 = Firness_Data2;
        }
        {
            UINT16 Firness_Data3;
            ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
            BrowserCallback_Arg_4->Data3 = Firness_Data3;
        }
        ReadBytes(Input, sizeof(BrowserCallback_Arg_4->Data4), (VOID *)&(BrowserCallback_Arg_4->Data4));
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 BrowserCallback_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(BrowserCallback_Arg_5_choice), (VOID *)&BrowserCallback_Arg_5_choice);
    switch(BrowserCallback_Arg_5_choice % 2) {
        case 0:
            if (BrowserCallback_Arg_5 != NULL) {
                ReadBytes(Input, 31 * sizeof(*BrowserCallback_Arg_5), (VOID *)BrowserCallback_Arg_5);
                BrowserCallback_Arg_5[31] = 0;
            }
            break;
        case 1:
        {
            gBS->FreePool(BrowserCallback_Arg_5);
            BrowserCallback_Arg_5 = NULL;
            break;
        }
    }
    
    FirnessUntrusted(BrowserCallback_Arg_1, 4096);
    FirnessUntrusted(BrowserCallback_Arg_2, 32 * sizeof(CHAR16));
    FirnessUntrusted(BrowserCallback_Arg_4, sizeof(EFI_GUID));
    FirnessUntrusted(BrowserCallback_Arg_5, 32 * sizeof(CHAR16));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->BrowserCallback(
        ProtocolVariable,
        BrowserCallback_Arg_1,
        BrowserCallback_Arg_2,
        BrowserCallback_Arg_3,
        BrowserCallback_Arg_4,
        BrowserCallback_Arg_5
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && BrowserCallback_Arg_1 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = BrowserCallback_Arg_1;
    }
    if (FirnessLive_CHAR16___Count < 4 && BrowserCallback_Arg_2 != NULL) {
        FirnessLive_CHAR16__[FirnessLive_CHAR16___Count++] = BrowserCallback_Arg_2;
    }
    return Status;
}


// Declared in a package this harness does not include, so the value is
// carried here rather than resolved through the inf.
EFI_GUID gTcg800155PlatformIdEventHobGuid = { 0xe2c3bc69, 0x615c, 0x4b5b, { 0x8e, 0x5c, 0xa0, 0x33, 0xa9, 0xc2, 0x5e, 0xd6 }};
