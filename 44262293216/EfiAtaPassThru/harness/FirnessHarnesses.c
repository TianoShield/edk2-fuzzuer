#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
EFI_ATA_PASS_THRU_COMMAND_PACKET * FirnessLive_EFI_ATA_PASS_THRU_COMMAND_PACKET__[4];
UINTN FirnessLive_EFI_ATA_PASS_THRU_COMMAND_PACKET___Count = 0;
EFI_DEVICE_PATH_PROTOCOL * FirnessLive_EFI_DEVICE_PATH_PROTOCOL__[4];
UINTN FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count = 0;
UINT16 * FirnessLive_UINT16__[4];
UINTN FirnessLive_UINT16___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called PassThru.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPassThru(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ATA_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAtaPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 PassThru_Arg_1 = {0};
    UINT16 PassThru_Arg_2 = {0};
    EFI_ATA_PASS_THRU_COMMAND_PACKET * PassThru_Arg_3 = (EFI_ATA_PASS_THRU_COMMAND_PACKET *)AllocateZeroPool(sizeof(EFI_ATA_PASS_THRU_COMMAND_PACKET));
    EFI_EVENT PassThru_Arg_4 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PassThru_Arg_1), (VOID *)&PassThru_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PassThru_Arg_2), (VOID *)&PassThru_Arg_2);
    
    
    UINT8* PassThru_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*PassThru_Arg_4_choice), (VOID *)PassThru_Arg_4_choice);
    switch(*PassThru_Arg_4_choice % 4) {
        case 0:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = EfiCreateEventReadyToBoot(
                (EFI_EVENT *)&PassThru_Arg_4
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            FirnessSanitizer(TRUE);
            Status = EfiCreateEventLegacyBoot(
                (EFI_EVENT *)&PassThru_Arg_4
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
            EFI_TPL EfiCreateEventReadyToBootEx_Arg_0 = {0};
            UINTN*  EfiCreateEventReadyToBootEx_Arg_2 = (UINTN* )AllocateZeroPool(4096);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiCreateEventReadyToBootEx_Arg_0), (VOID *)&EfiCreateEventReadyToBootEx_Arg_0);
            
            // Fuzzable Variable Initialization
            UINT8 EfiCreateEventReadyToBootEx_Arg_2_choice = 0;
            ReadBytes(Input, sizeof(EfiCreateEventReadyToBootEx_Arg_2_choice), (VOID *)&EfiCreateEventReadyToBootEx_Arg_2_choice);
            switch(EfiCreateEventReadyToBootEx_Arg_2_choice % 1) {
                case 0:
                    if (EfiCreateEventReadyToBootEx_Arg_2 != NULL) {
                        ReadBytes(Input, sizeof(*EfiCreateEventReadyToBootEx_Arg_2), (VOID *)EfiCreateEventReadyToBootEx_Arg_2);
                    }
                    break;
            }
            
            FirnessUntrusted(EfiCreateEventReadyToBootEx_Arg_2, 4096);
            FirnessSanitizer(TRUE);
            Status = EfiCreateEventReadyToBootEx(
                EfiCreateEventReadyToBootEx_Arg_0,
                NULL,
                (void *)EfiCreateEventReadyToBootEx_Arg_2,
                (EFI_EVENT *)&PassThru_Arg_4
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
            EFI_TPL EfiCreateEventLegacyBootEx_Arg_0 = {0};
            UINTN*  EfiCreateEventLegacyBootEx_Arg_2 = (UINTN* )AllocateZeroPool(4096);
            
            // Fuzzable Variable Initialization
            ReadBytes(Input, sizeof(EfiCreateEventLegacyBootEx_Arg_0), (VOID *)&EfiCreateEventLegacyBootEx_Arg_0);
            
            // Fuzzable Variable Initialization
            UINT8 EfiCreateEventLegacyBootEx_Arg_2_choice = 0;
            ReadBytes(Input, sizeof(EfiCreateEventLegacyBootEx_Arg_2_choice), (VOID *)&EfiCreateEventLegacyBootEx_Arg_2_choice);
            switch(EfiCreateEventLegacyBootEx_Arg_2_choice % 1) {
                case 0:
                    if (EfiCreateEventLegacyBootEx_Arg_2 != NULL) {
                        ReadBytes(Input, sizeof(*EfiCreateEventLegacyBootEx_Arg_2), (VOID *)EfiCreateEventLegacyBootEx_Arg_2);
                    }
                    break;
            }
            
            FirnessUntrusted(EfiCreateEventLegacyBootEx_Arg_2, 4096);
            FirnessSanitizer(TRUE);
            Status = EfiCreateEventLegacyBootEx(
                EfiCreateEventLegacyBootEx_Arg_0,
                NULL,
                (void *)EfiCreateEventLegacyBootEx_Arg_2,
                (EFI_EVENT *)&PassThru_Arg_4
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    UINT8 PassThru_Arg_3_LiveChoice = 0;
    ReadBytes(Input, sizeof(PassThru_Arg_3_LiveChoice), (VOID *)&PassThru_Arg_3_LiveChoice);
    if (FirnessLive_EFI_ATA_PASS_THRU_COMMAND_PACKET___Count > 0 && (PassThru_Arg_3_LiveChoice & 1)) {
        PassThru_Arg_3 = FirnessLive_EFI_ATA_PASS_THRU_COMMAND_PACKET__[PassThru_Arg_3_LiveChoice % FirnessLive_EFI_ATA_PASS_THRU_COMMAND_PACKET___Count];
    }
    FirnessUntrusted(PassThru_Arg_3, sizeof(EFI_ATA_PASS_THRU_COMMAND_PACKET));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->PassThru(
        ProtocolVariable,
        PassThru_Arg_1,
        PassThru_Arg_2,
        PassThru_Arg_3,
        PassThru_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_ATA_PASS_THRU_COMMAND_PACKET___Count < 4 && PassThru_Arg_3 != NULL) {
        FirnessLive_EFI_ATA_PASS_THRU_COMMAND_PACKET__[FirnessLive_EFI_ATA_PASS_THRU_COMMAND_PACKET___Count++] = PassThru_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ResetDevice.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzResetDevice(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ATA_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAtaPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 ResetDevice_Arg_1 = {0};
    UINT16 ResetDevice_Arg_2 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ResetDevice_Arg_1), (VOID *)&ResetDevice_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ResetDevice_Arg_2), (VOID *)&ResetDevice_Arg_2);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->ResetDevice(
        ProtocolVariable,
        ResetDevice_Arg_1,
        ResetDevice_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called BuildDevicePath.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBuildDevicePath(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ATA_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAtaPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 BuildDevicePath_Arg_1 = {0};
    UINT16 BuildDevicePath_Arg_2 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BuildDevicePath_Arg_1), (VOID *)&BuildDevicePath_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BuildDevicePath_Arg_2), (VOID *)&BuildDevicePath_Arg_2);
    
    /*
        Output Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * BuildDevicePath_Arg_3 = NULL;
    FirnessMakeDevicePath (BuildDevicePath_Arg_3, 4096);
    UINT8* BuildDevicePath_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*BuildDevicePath_Arg_3_OutputChoice), (VOID *)BuildDevicePath_Arg_3_OutputChoice);
    if(*BuildDevicePath_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*BuildDevicePath_Arg_3), (VOID *)BuildDevicePath_Arg_3);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->BuildDevicePath(
        ProtocolVariable,
        BuildDevicePath_Arg_1,
        BuildDevicePath_Arg_2,
        (EFI_DEVICE_PATH_PROTOCOL **)&BuildDevicePath_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count < 4 && BuildDevicePath_Arg_3 != NULL) {
        FirnessLive_EFI_DEVICE_PATH_PROTOCOL__[FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count++] = BuildDevicePath_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetDevice.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetDevice(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ATA_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAtaPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * GetDevice_Arg_1 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(4096);
    FirnessMakeDevicePath (GetDevice_Arg_1, 4096);
    
    UINT8* GetDevice_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetDevice_Arg_1_choice), (VOID *)GetDevice_Arg_1_choice);
    switch(*GetDevice_Arg_1_choice % 3) {
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
                (EFI_DEVICE_PATH_PROTOCOL **)&GetDevice_Arg_1
            );
            FirnessSanitizer(FALSE);
            FirnessMakeDevicePath (GetDevice_Arg_1, 4096);
    
            break;
        }
        case 1:
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
                (EFI_DEVICE_PATH_PROTOCOL **)&GetDevice_Arg_1
            );
            FirnessSanitizer(FALSE);
            FirnessMakeDevicePath (GetDevice_Arg_1, 4096);
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            GetDevice_Arg_1->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            GetDevice_Arg_1->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(GetDevice_Arg_1->Length), (VOID *)&(GetDevice_Arg_1->Length));
            FirnessMakeDevicePath (GetDevice_Arg_1, 4096);
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    UINT16 * GetDevice_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    UINT8* GetDevice_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetDevice_Arg_2_OutputChoice), (VOID *)GetDevice_Arg_2_OutputChoice);
    if(*GetDevice_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetDevice_Arg_2), (VOID *)GetDevice_Arg_2);
    }
    UINT16 * GetDevice_Arg_3 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    UINT8* GetDevice_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetDevice_Arg_3_OutputChoice), (VOID *)GetDevice_Arg_3_OutputChoice);
    if(*GetDevice_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetDevice_Arg_3), (VOID *)GetDevice_Arg_3);
    }
    UINT8 GetDevice_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetDevice_Arg_1_LiveChoice), (VOID *)&GetDevice_Arg_1_LiveChoice);
    if (FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count > 0 && (GetDevice_Arg_1_LiveChoice & 1)) {
        GetDevice_Arg_1 = FirnessLive_EFI_DEVICE_PATH_PROTOCOL__[GetDevice_Arg_1_LiveChoice % FirnessLive_EFI_DEVICE_PATH_PROTOCOL___Count];
    }
    FirnessUntrusted(GetDevice_Arg_1, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetDevice(
        ProtocolVariable,
        GetDevice_Arg_1,
        GetDevice_Arg_2,
        GetDevice_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINT16___Count < 4 && GetDevice_Arg_2 != NULL) {
        FirnessLive_UINT16__[FirnessLive_UINT16___Count++] = GetDevice_Arg_2;
    }
    if (FirnessLive_UINT16___Count < 4 && GetDevice_Arg_3 != NULL) {
        FirnessLive_UINT16__[FirnessLive_UINT16___Count++] = GetDevice_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNextPort.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextPort(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ATA_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAtaPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 * GetNextPort_Arg_1 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
    // Fuzzable Variable Initialization
    UINT8 GetNextPort_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetNextPort_Arg_1_choice), (VOID *)&GetNextPort_Arg_1_choice);
    switch(GetNextPort_Arg_1_choice % 1) {
        case 0:
            if (GetNextPort_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*GetNextPort_Arg_1), (VOID *)GetNextPort_Arg_1);
            }
            break;
    }
    
    UINT8 GetNextPort_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetNextPort_Arg_1_LiveChoice), (VOID *)&GetNextPort_Arg_1_LiveChoice);
    if (FirnessLive_UINT16___Count > 0 && (GetNextPort_Arg_1_LiveChoice & 1)) {
        GetNextPort_Arg_1 = FirnessLive_UINT16__[GetNextPort_Arg_1_LiveChoice % FirnessLive_UINT16___Count];
    }
    FirnessUntrusted(GetNextPort_Arg_1, sizeof(UINT16));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetNextPort(
        ProtocolVariable,
        GetNextPort_Arg_1
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINT16___Count < 4 && GetNextPort_Arg_1 != NULL) {
        FirnessLive_UINT16__[FirnessLive_UINT16___Count++] = GetNextPort_Arg_1;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetNextDevice.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextDevice(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ATA_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAtaPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 GetNextDevice_Arg_1 = {0};
    UINT16 * GetNextDevice_Arg_2 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetNextDevice_Arg_1), (VOID *)&GetNextDevice_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 GetNextDevice_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetNextDevice_Arg_2_choice), (VOID *)&GetNextDevice_Arg_2_choice);
    switch(GetNextDevice_Arg_2_choice % 1) {
        case 0:
            if (GetNextDevice_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*GetNextDevice_Arg_2), (VOID *)GetNextDevice_Arg_2);
            }
            break;
    }
    
    UINT8 GetNextDevice_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetNextDevice_Arg_2_LiveChoice), (VOID *)&GetNextDevice_Arg_2_LiveChoice);
    if (FirnessLive_UINT16___Count > 0 && (GetNextDevice_Arg_2_LiveChoice & 1)) {
        GetNextDevice_Arg_2 = FirnessLive_UINT16__[GetNextDevice_Arg_2_LiveChoice % FirnessLive_UINT16___Count];
    }
    FirnessUntrusted(GetNextDevice_Arg_2, sizeof(UINT16));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetNextDevice(
        ProtocolVariable,
        GetNextDevice_Arg_1,
        GetNextDevice_Arg_2
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINT16___Count < 4 && GetNextDevice_Arg_2 != NULL) {
        FirnessLive_UINT16__[FirnessLive_UINT16___Count++] = GetNextDevice_Arg_2;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ResetPort.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzResetPort(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ATA_PASS_THRU_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAtaPassThruProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 ResetPort_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(ResetPort_Arg_1), (VOID *)&ResetPort_Arg_1);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->ResetPort(
        ProtocolVariable,
        ResetPort_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

