#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the Protocols service
    called ConvertTextToDeviceNode.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConvertTextToDeviceNode(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathFromTextProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * ConvertTextToDeviceNode_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 ConvertTextToDeviceNode_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(ConvertTextToDeviceNode_Arg_0_choice), (VOID *)&ConvertTextToDeviceNode_Arg_0_choice);
    switch(ConvertTextToDeviceNode_Arg_0_choice % 1) {
        case 0:
            if (ConvertTextToDeviceNode_Arg_0 != NULL) {
                ReadBytes(Input, 31 * sizeof(*ConvertTextToDeviceNode_Arg_0), (VOID *)ConvertTextToDeviceNode_Arg_0);
                ConvertTextToDeviceNode_Arg_0[31] = 0;
            }
            break;
    }
    
    FirnessUntrusted(ConvertTextToDeviceNode_Arg_0, 32 * sizeof(CHAR16));
    FirnessSanitizer(TRUE);
    ProtocolVariable->ConvertTextToDeviceNode(
        ConvertTextToDeviceNode_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called ConvertTextToDevicePath.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConvertTextToDevicePath(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiDevicePathFromTextProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * ConvertTextToDevicePath_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 ConvertTextToDevicePath_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(ConvertTextToDevicePath_Arg_0_choice), (VOID *)&ConvertTextToDevicePath_Arg_0_choice);
    switch(ConvertTextToDevicePath_Arg_0_choice % 1) {
        case 0:
            if (ConvertTextToDevicePath_Arg_0 != NULL) {
                ReadBytes(Input, 31 * sizeof(*ConvertTextToDevicePath_Arg_0), (VOID *)ConvertTextToDevicePath_Arg_0);
                ConvertTextToDevicePath_Arg_0[31] = 0;
            }
            break;
    }
    
    FirnessUntrusted(ConvertTextToDevicePath_Arg_0, 32 * sizeof(CHAR16));
    FirnessSanitizer(TRUE);
    ProtocolVariable->ConvertTextToDevicePath(
        ConvertTextToDevicePath_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

