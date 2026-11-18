#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
CONST EFI_GUID * FirnessLive_CONST_EFI_GUID__[4];
UINTN FirnessLive_CONST_EFI_GUID___Count = 0;
UINTN * FirnessLive_UINTN__[4];
UINTN FirnessLive_UINTN___Count = 0;

/*
    This is a harness for fuzzing the Protocols service
    called SetSku.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetSku(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN SetSku_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetSku_Arg_0), (VOID *)&SetSku_Arg_0);
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->SetSku(
        SetSku_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Get8.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGet8(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Get8_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Get8_Arg_0), (VOID *)&Get8_Arg_0);
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->Get8(
        Get8_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Get16.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGet16(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Get16_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Get16_Arg_0), (VOID *)&Get16_Arg_0);
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->Get16(
        Get16_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Get32.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGet32(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Get32_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Get32_Arg_0), (VOID *)&Get32_Arg_0);
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->Get32(
        Get32_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Get64.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGet64(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Get64_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Get64_Arg_0), (VOID *)&Get64_Arg_0);
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->Get64(
        Get64_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetPtr.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetPtr(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN GetPtr_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetPtr_Arg_0), (VOID *)&GetPtr_Arg_0);
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetPtr(
        GetPtr_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetBool.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetBool(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN GetBool_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetBool_Arg_0), (VOID *)&GetBool_Arg_0);
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetBool(
        GetBool_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetSize.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSize(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN GetSize_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetSize_Arg_0), (VOID *)&GetSize_Arg_0);
    
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetSize(
        GetSize_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Get8Ex.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGet8Ex(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * Get8Ex_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN Get8Ex_Arg_1 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        Get8Ex_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        Get8Ex_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        Get8Ex_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(Get8Ex_Arg_0->Data4), (VOID *)&(Get8Ex_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Get8Ex_Arg_1), (VOID *)&Get8Ex_Arg_1);
    
    FirnessUntrusted(Get8Ex_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    ProtocolVariable->Get8Ex(
        Get8Ex_Arg_0,
        Get8Ex_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Get16Ex.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGet16Ex(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * Get16Ex_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN Get16Ex_Arg_1 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        Get16Ex_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        Get16Ex_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        Get16Ex_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(Get16Ex_Arg_0->Data4), (VOID *)&(Get16Ex_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Get16Ex_Arg_1), (VOID *)&Get16Ex_Arg_1);
    
    FirnessUntrusted(Get16Ex_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    ProtocolVariable->Get16Ex(
        Get16Ex_Arg_0,
        Get16Ex_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Get32Ex.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGet32Ex(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * Get32Ex_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN Get32Ex_Arg_1 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        Get32Ex_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        Get32Ex_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        Get32Ex_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(Get32Ex_Arg_0->Data4), (VOID *)&(Get32Ex_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Get32Ex_Arg_1), (VOID *)&Get32Ex_Arg_1);
    
    FirnessUntrusted(Get32Ex_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    ProtocolVariable->Get32Ex(
        Get32Ex_Arg_0,
        Get32Ex_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Get64Ex.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGet64Ex(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * Get64Ex_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN Get64Ex_Arg_1 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        Get64Ex_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        Get64Ex_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        Get64Ex_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(Get64Ex_Arg_0->Data4), (VOID *)&(Get64Ex_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Get64Ex_Arg_1), (VOID *)&Get64Ex_Arg_1);
    
    FirnessUntrusted(Get64Ex_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    ProtocolVariable->Get64Ex(
        Get64Ex_Arg_0,
        Get64Ex_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetPtrEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetPtrEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetPtrEx_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN GetPtrEx_Arg_1 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        GetPtrEx_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        GetPtrEx_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        GetPtrEx_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(GetPtrEx_Arg_0->Data4), (VOID *)&(GetPtrEx_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetPtrEx_Arg_1), (VOID *)&GetPtrEx_Arg_1);
    
    FirnessUntrusted(GetPtrEx_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetPtrEx(
        GetPtrEx_Arg_0,
        GetPtrEx_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetBoolEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetBoolEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetBoolEx_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN GetBoolEx_Arg_1 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        GetBoolEx_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        GetBoolEx_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        GetBoolEx_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(GetBoolEx_Arg_0->Data4), (VOID *)&(GetBoolEx_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetBoolEx_Arg_1), (VOID *)&GetBoolEx_Arg_1);
    
    FirnessUntrusted(GetBoolEx_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetBoolEx(
        GetBoolEx_Arg_0,
        GetBoolEx_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetSizeEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetSizeEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * GetSizeEx_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN GetSizeEx_Arg_1 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        GetSizeEx_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        GetSizeEx_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        GetSizeEx_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(GetSizeEx_Arg_0->Data4), (VOID *)&(GetSizeEx_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetSizeEx_Arg_1), (VOID *)&GetSizeEx_Arg_1);
    
    FirnessUntrusted(GetSizeEx_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    ProtocolVariable->GetSizeEx(
        GetSizeEx_Arg_0,
        GetSizeEx_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Set8.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSet8(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Set8_Arg_0 = {0};
    UINT8 Set8_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set8_Arg_0), (VOID *)&Set8_Arg_0);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set8_Arg_1), (VOID *)&Set8_Arg_1);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Set8(
        Set8_Arg_0,
        Set8_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Set16.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSet16(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Set16_Arg_0 = {0};
    UINT16 Set16_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set16_Arg_0), (VOID *)&Set16_Arg_0);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set16_Arg_1), (VOID *)&Set16_Arg_1);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Set16(
        Set16_Arg_0,
        Set16_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Set32.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSet32(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Set32_Arg_0 = {0};
    UINT32 Set32_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set32_Arg_0), (VOID *)&Set32_Arg_0);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set32_Arg_1), (VOID *)&Set32_Arg_1);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Set32(
        Set32_Arg_0,
        Set32_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Set64.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSet64(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN Set64_Arg_0 = {0};
    UINT64 Set64_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set64_Arg_0), (VOID *)&Set64_Arg_0);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set64_Arg_1), (VOID *)&Set64_Arg_1);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Set64(
        Set64_Arg_0,
        Set64_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SetPtr.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetPtr(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN SetPtr_Arg_0 = {0};
    UINTN * SetPtr_Arg_1 = (UINTN *)AllocateZeroPool(4096);
    UINTN*  SetPtr_Arg_2 = (UINTN* )AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetPtr_Arg_0), (VOID *)&SetPtr_Arg_0);
    SetPtr_Arg_0 = SetPtr_Arg_0 % (4096 + 1);
    
    // Fuzzable Variable Initialization
    UINT8 SetPtr_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(SetPtr_Arg_1_choice), (VOID *)&SetPtr_Arg_1_choice);
    switch(SetPtr_Arg_1_choice % 1) {
        case 0:
            if (SetPtr_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*SetPtr_Arg_1), (VOID *)SetPtr_Arg_1);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetPtr_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetPtr_Arg_2_choice), (VOID *)&SetPtr_Arg_2_choice);
    switch(SetPtr_Arg_2_choice % 1) {
        case 0:
            if (SetPtr_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*SetPtr_Arg_2), (VOID *)SetPtr_Arg_2);
            }
            break;
    }
    
    FirnessUntrusted(SetPtr_Arg_1, 4096);
    FirnessUntrusted(SetPtr_Arg_2, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetPtr(
        SetPtr_Arg_0,
        SetPtr_Arg_1,
        (VOID *)SetPtr_Arg_2
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && SetPtr_Arg_1 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = SetPtr_Arg_1;
    }
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SetBool.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetBool(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN SetBool_Arg_0 = {0};
    BOOLEAN SetBool_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetBool_Arg_0), (VOID *)&SetBool_Arg_0);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetBool_Arg_1), (VOID *)&SetBool_Arg_1);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetBool(
        SetBool_Arg_0,
        SetBool_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Set8Ex.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSet8Ex(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * Set8Ex_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN Set8Ex_Arg_1 = {0};
    UINT8 Set8Ex_Arg_2 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        Set8Ex_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        Set8Ex_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        Set8Ex_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(Set8Ex_Arg_0->Data4), (VOID *)&(Set8Ex_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set8Ex_Arg_1), (VOID *)&Set8Ex_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set8Ex_Arg_2), (VOID *)&Set8Ex_Arg_2);
    
    FirnessUntrusted(Set8Ex_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Set8Ex(
        Set8Ex_Arg_0,
        Set8Ex_Arg_1,
        Set8Ex_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Set16Ex.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSet16Ex(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * Set16Ex_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN Set16Ex_Arg_1 = {0};
    UINT16 Set16Ex_Arg_2 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        Set16Ex_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        Set16Ex_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        Set16Ex_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(Set16Ex_Arg_0->Data4), (VOID *)&(Set16Ex_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set16Ex_Arg_1), (VOID *)&Set16Ex_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set16Ex_Arg_2), (VOID *)&Set16Ex_Arg_2);
    
    FirnessUntrusted(Set16Ex_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Set16Ex(
        Set16Ex_Arg_0,
        Set16Ex_Arg_1,
        Set16Ex_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Set32Ex.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSet32Ex(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * Set32Ex_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN Set32Ex_Arg_1 = {0};
    UINT32 Set32Ex_Arg_2 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        Set32Ex_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        Set32Ex_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        Set32Ex_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(Set32Ex_Arg_0->Data4), (VOID *)&(Set32Ex_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set32Ex_Arg_1), (VOID *)&Set32Ex_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set32Ex_Arg_2), (VOID *)&Set32Ex_Arg_2);
    
    FirnessUntrusted(Set32Ex_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Set32Ex(
        Set32Ex_Arg_0,
        Set32Ex_Arg_1,
        Set32Ex_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Set64Ex.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSet64Ex(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * Set64Ex_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN Set64Ex_Arg_1 = {0};
    UINT64 Set64Ex_Arg_2 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        Set64Ex_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        Set64Ex_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        Set64Ex_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(Set64Ex_Arg_0->Data4), (VOID *)&(Set64Ex_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set64Ex_Arg_1), (VOID *)&Set64Ex_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Set64Ex_Arg_2), (VOID *)&Set64Ex_Arg_2);
    
    FirnessUntrusted(Set64Ex_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Set64Ex(
        Set64Ex_Arg_0,
        Set64Ex_Arg_1,
        Set64Ex_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SetPtrEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetPtrEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * SetPtrEx_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN SetPtrEx_Arg_1 = {0};
    UINTN * SetPtrEx_Arg_2 = (UINTN *)AllocateZeroPool(4096);
    UINTN*  SetPtrEx_Arg_3 = (UINTN* )AllocateZeroPool(4096);
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        SetPtrEx_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        SetPtrEx_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        SetPtrEx_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(SetPtrEx_Arg_0->Data4), (VOID *)&(SetPtrEx_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetPtrEx_Arg_1), (VOID *)&SetPtrEx_Arg_1);
    SetPtrEx_Arg_1 = SetPtrEx_Arg_1 % (4096 + 1);
    
    // Fuzzable Variable Initialization
    UINT8 SetPtrEx_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetPtrEx_Arg_2_choice), (VOID *)&SetPtrEx_Arg_2_choice);
    switch(SetPtrEx_Arg_2_choice % 1) {
        case 0:
            if (SetPtrEx_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*SetPtrEx_Arg_2), (VOID *)SetPtrEx_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetPtrEx_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetPtrEx_Arg_3_choice), (VOID *)&SetPtrEx_Arg_3_choice);
    switch(SetPtrEx_Arg_3_choice % 1) {
        case 0:
            if (SetPtrEx_Arg_3 != NULL) {
                ReadBytes(Input, sizeof(*SetPtrEx_Arg_3), (VOID *)SetPtrEx_Arg_3);
            }
            break;
    }
    
    FirnessUntrusted(SetPtrEx_Arg_0, sizeof(EFI_GUID));
    FirnessUntrusted(SetPtrEx_Arg_2, 4096);
    FirnessUntrusted(SetPtrEx_Arg_3, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetPtrEx(
        SetPtrEx_Arg_0,
        SetPtrEx_Arg_1,
        SetPtrEx_Arg_2,
        (VOID *)SetPtrEx_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && SetPtrEx_Arg_2 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = SetPtrEx_Arg_2;
    }
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SetBoolEx.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetBoolEx(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GUID * SetBoolEx_Arg_0 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    UINTN SetBoolEx_Arg_1 = {0};
    BOOLEAN SetBoolEx_Arg_2 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        SetBoolEx_Arg_0->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        SetBoolEx_Arg_0->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        SetBoolEx_Arg_0->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(SetBoolEx_Arg_0->Data4), (VOID *)&(SetBoolEx_Arg_0->Data4));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetBoolEx_Arg_1), (VOID *)&SetBoolEx_Arg_1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetBoolEx_Arg_2), (VOID *)&SetBoolEx_Arg_2);
    
    FirnessUntrusted(SetBoolEx_Arg_0, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetBoolEx(
        SetBoolEx_Arg_0,
        SetBoolEx_Arg_1,
        SetBoolEx_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called CallbackOnSet.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCallbackOnSet(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN CallbackOnSet_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CallbackOnSet_Arg_1), (VOID *)&CallbackOnSet_Arg_1);
    
    VOID *CallbackOnSet_Arg_0 = AllocateZeroPool(4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->CallbackOnSet(
        CallbackOnSet_Arg_0,
        CallbackOnSet_Arg_1,
        (PCD_PROTOCOL_CALLBACK){0}
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called CancelCallback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCancelCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN CancelCallback_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CancelCallback_Arg_1), (VOID *)&CancelCallback_Arg_1);
    
    VOID *CancelCallback_Arg_0 = AllocateZeroPool(4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->CancelCallback(
        CancelCallback_Arg_0,
        CancelCallback_Arg_1,
        (PCD_PROTOCOL_CALLBACK){0}
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetNextToken.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextToken(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * GetNextToken_Arg_1 = (UINTN *)AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    UINT8 GetNextToken_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetNextToken_Arg_1_choice), (VOID *)&GetNextToken_Arg_1_choice);
    switch(GetNextToken_Arg_1_choice % 1) {
        case 0:
            if (GetNextToken_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*GetNextToken_Arg_1), (VOID *)GetNextToken_Arg_1);
            }
            break;
    }
    
    VOID *GetNextToken_Arg_0 = AllocateZeroPool(4096);
    FirnessUntrusted(GetNextToken_Arg_1, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetNextToken(
        GetNextToken_Arg_0,
        GetNextToken_Arg_1
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && GetNextToken_Arg_1 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = GetNextToken_Arg_1;
    }
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetNextTokenSpace.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetNextTokenSpace(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    PCD_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gPcdProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CONST EFI_GUID * GetNextTokenSpace_Arg_0 = NULL;
    
    
    UINT8 GetNextTokenSpace_Arg_0_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetNextTokenSpace_Arg_0_LiveChoice), (VOID *)&GetNextTokenSpace_Arg_0_LiveChoice);
    if (FirnessLive_CONST_EFI_GUID___Count > 0 && (GetNextTokenSpace_Arg_0_LiveChoice & 1)) {
        GetNextTokenSpace_Arg_0 = FirnessLive_CONST_EFI_GUID__[GetNextTokenSpace_Arg_0_LiveChoice % FirnessLive_CONST_EFI_GUID___Count];
    }
    FirnessUntrusted(GetNextTokenSpace_Arg_0, sizeof(CONST EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetNextTokenSpace(
        (CONST EFI_GUID * *)&GetNextTokenSpace_Arg_0
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_CONST_EFI_GUID___Count < 4 && GetNextTokenSpace_Arg_0 != NULL) {
        FirnessLive_CONST_EFI_GUID__[FirnessLive_CONST_EFI_GUID___Count++] = GetNextTokenSpace_Arg_0;
    }
    return Status;
}

