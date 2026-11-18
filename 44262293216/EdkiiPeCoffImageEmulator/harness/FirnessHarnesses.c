#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called IsImageSupported.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIsImageSupported(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_PECOFF_IMAGE_EMULATOR_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiPeCoffImageEmulatorProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT16 IsImageSupported_Arg_1 = {0};
    EFI_DEVICE_PATH_PROTOCOL * IsImageSupported_Arg_2 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(4096);
    FirnessMakeDevicePath (IsImageSupported_Arg_2, 4096);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(IsImageSupported_Arg_1), (VOID *)&IsImageSupported_Arg_1);
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Type;
        ReadBytes(Input, sizeof(Firness_Type), (VOID *)&Firness_Type);
        IsImageSupported_Arg_2->Type = Firness_Type;
    }
    {
        UINT8 Firness_SubType;
        ReadBytes(Input, sizeof(Firness_SubType), (VOID *)&Firness_SubType);
        IsImageSupported_Arg_2->SubType = Firness_SubType;
    }
    ReadBytes(Input, sizeof(IsImageSupported_Arg_2->Length), (VOID *)&(IsImageSupported_Arg_2->Length));
    FirnessMakeDevicePath (IsImageSupported_Arg_2, 4096);
    
    FirnessUntrusted(IsImageSupported_Arg_2, 4096);
    FirnessSanitizer(TRUE);
    ProtocolVariable->IsImageSupported(
        ProtocolVariable,
        IsImageSupported_Arg_1,
        IsImageSupported_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UnregisterImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnregisterImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_PECOFF_IMAGE_EMULATOR_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiPeCoffImageEmulatorProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PHYSICAL_ADDRESS UnregisterImage_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    // EFI_PHYSICAL_ADDRESS is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->UnregisterImage(
        ProtocolVariable,
        UnregisterImage_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RegisterImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_PECOFF_IMAGE_EMULATOR_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiPeCoffImageEmulatorProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PHYSICAL_ADDRESS RegisterImage_Arg_1 = {0};
    UINTN RegisterImage_Arg_2 = {0};
    EFI_IMAGE_ENTRY_POINT * RegisterImage_Arg_3 = (EFI_IMAGE_ENTRY_POINT *)AllocateZeroPool(sizeof(EFI_IMAGE_ENTRY_POINT));
    
    // Fuzzable Variable Initialization
    // EFI_PHYSICAL_ADDRESS is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterImage_Arg_2), (VOID *)&RegisterImage_Arg_2);
    
    // Fuzzable Variable Initialization
    UINT8 RegisterImage_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(RegisterImage_Arg_3_choice), (VOID *)&RegisterImage_Arg_3_choice);
    switch(RegisterImage_Arg_3_choice % 1) {
        case 0:
            if (RegisterImage_Arg_3 != NULL) {
                ReadBytes(Input, sizeof(*RegisterImage_Arg_3), (VOID *)RegisterImage_Arg_3);
            }
            break;
    }
    
    FirnessUntrusted(RegisterImage_Arg_3, sizeof(EFI_IMAGE_ENTRY_POINT));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RegisterImage(
        ProtocolVariable,
        RegisterImage_Arg_1,
        RegisterImage_Arg_2,
        RegisterImage_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

