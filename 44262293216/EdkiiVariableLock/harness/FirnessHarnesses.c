#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called RequestToLock.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRequestToLock(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_LOCK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariableLockProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * RequestToLock_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    EFI_GUID * RequestToLock_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    // Fuzzable Variable Initialization
    UINT8 RequestToLock_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(RequestToLock_Arg_1_choice), (VOID *)&RequestToLock_Arg_1_choice);
    switch(RequestToLock_Arg_1_choice % 1) {
        case 0:
            if (RequestToLock_Arg_1 != NULL) {
                ReadBytes(Input, 31 * sizeof(*RequestToLock_Arg_1), (VOID *)RequestToLock_Arg_1);
                RequestToLock_Arg_1[31] = 0;
            }
            break;
    }
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        RequestToLock_Arg_2->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        RequestToLock_Arg_2->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        RequestToLock_Arg_2->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(RequestToLock_Arg_2->Data4), (VOID *)&(RequestToLock_Arg_2->Data4));
    
    FirnessUntrusted(RequestToLock_Arg_1, 32 * sizeof(CHAR16));
    FirnessUntrusted(RequestToLock_Arg_2, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RequestToLock(
        ProtocolVariable,
        RequestToLock_Arg_1,
        RequestToLock_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

