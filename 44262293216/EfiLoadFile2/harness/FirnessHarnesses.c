#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
UINTN * FirnessLive_UINTN__[4];
UINTN FirnessLive_UINTN___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called LoadFile.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLoadFile(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_LOAD_FILE2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiLoadFile2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_DEVICE_PATH_PROTOCOL * LoadFile_Arg_1 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(4096);
    FirnessMakeDevicePath (LoadFile_Arg_1, 4096);
    BOOLEAN LoadFile_Arg_2 = {0};
    UINTN * LoadFile_Arg_3 = (UINTN *)AllocateZeroPool(4096);
    UINTN*  LoadFile_Arg_4 = (UINTN* )AllocateZeroPool(4096);
    
    UINT8* LoadFile_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*LoadFile_Arg_1_choice), (VOID *)LoadFile_Arg_1_choice);
    switch(*LoadFile_Arg_1_choice % 4) {
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
            
            FirnessUntrusted(ChooseFile_Arg_0, 4096);
            FirnessUntrusted(ChooseFile_Arg_1, 32 * sizeof(CHAR16));
            FirnessSanitizer(TRUE);
            Status = ChooseFile(
                ChooseFile_Arg_0,
                ChooseFile_Arg_1,
                NULL,
                (EFI_DEVICE_PATH_PROTOCOL **)&LoadFile_Arg_1
            );
            FirnessSanitizer(FALSE);
            FirnessMakeDevicePath (LoadFile_Arg_1, 4096);
    
            break;
        }
        case 1:
        {
        // Fuzzable Variable Initialization
        UINT8 LoadFile_Arg_1_choice = 0;
        ReadBytes(Input, sizeof(LoadFile_Arg_1_choice), (VOID *)&LoadFile_Arg_1_choice);
        switch(LoadFile_Arg_1_choice % 1) {
            case 0:
                if (LoadFile_Arg_1 != NULL) {
                    ReadBytes(Input, sizeof(*LoadFile_Arg_1), (VOID *)LoadFile_Arg_1);
                    FirnessMakeDevicePath (LoadFile_Arg_1, 4096);
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
                (EFI_DEVICE_PATH_PROTOCOL **)&LoadFile_Arg_1
            );
            FirnessSanitizer(FALSE);
            FirnessMakeDevicePath (LoadFile_Arg_1, 4096);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
        {
            UINT8 Firness_Type;
            ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
            LoadFile_Arg_1->Type = Firness_Type;
        }
        {
            UINT8 Firness_SubType;
            ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
            LoadFile_Arg_1->SubType = Firness_SubType;
        }
        ReadBytes(Input, sizeof(LoadFile_Arg_1->Length), (VOID *)&(LoadFile_Arg_1->Length));
            FirnessMakeDevicePath (LoadFile_Arg_1, 4096);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(LoadFile_Arg_2), (VOID *)&LoadFile_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 LoadFile_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(LoadFile_Arg_3_choice), (VOID *)&LoadFile_Arg_3_choice);
    switch(LoadFile_Arg_3_choice % 1) {
        case 0:
            if (LoadFile_Arg_3 != NULL) {
                ReadBytes(Input, sizeof(*LoadFile_Arg_3), (VOID *)LoadFile_Arg_3);
                *LoadFile_Arg_3 = *LoadFile_Arg_3 % (4096 + 1);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 LoadFile_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(LoadFile_Arg_4_choice), (VOID *)&LoadFile_Arg_4_choice);
    switch(LoadFile_Arg_4_choice % 2) {
        case 0:
            if (LoadFile_Arg_4 != NULL) {
                ReadBytes(Input, sizeof(*LoadFile_Arg_4), (VOID *)LoadFile_Arg_4);
            }
            break;
        case 1:
        {
            gBS->FreePool(LoadFile_Arg_4);
            LoadFile_Arg_4 = NULL;
            break;
        }
    }
    
    FirnessUntrusted(LoadFile_Arg_1, 4096);
    FirnessUntrusted(LoadFile_Arg_3, 4096);
    FirnessUntrusted(LoadFile_Arg_4, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->LoadFile(
        ProtocolVariable,
        LoadFile_Arg_1,
        LoadFile_Arg_2,
        LoadFile_Arg_3,
        (void *)LoadFile_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && LoadFile_Arg_3 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = LoadFile_Arg_3;
    }
    return Status;
}

