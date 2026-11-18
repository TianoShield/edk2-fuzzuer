#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
VAR_CHECK_VARIABLE_PROPERTY * FirnessLive_VAR_CHECK_VARIABLE_PROPERTY__[4];
UINTN FirnessLive_VAR_CHECK_VARIABLE_PROPERTY___Count = 0;

/*
    This is a harness for fuzzing the Protocols service
    called RegisterSetVariableCheckHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterSetVariableCheckHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VAR_CHECK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVarCheckProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RegisterSetVariableCheckHandler(
        (VAR_CHECK_SET_VARIABLE_CHECK_HANDLER){0}
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called VariablePropertySet.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzVariablePropertySet(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VAR_CHECK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVarCheckProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * VariablePropertySet_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    EFI_GUID * VariablePropertySet_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    VAR_CHECK_VARIABLE_PROPERTY * VariablePropertySet_Arg_2 = (VAR_CHECK_VARIABLE_PROPERTY *)AllocateZeroPool(sizeof(VAR_CHECK_VARIABLE_PROPERTY));
    
    // Fuzzable Variable Initialization
    UINT8 VariablePropertySet_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(VariablePropertySet_Arg_0_choice), (VOID *)&VariablePropertySet_Arg_0_choice);
    switch(VariablePropertySet_Arg_0_choice % 1) {
        case 0:
            if (VariablePropertySet_Arg_0 != NULL) {
                ReadBytes(Input, 31 * sizeof(*VariablePropertySet_Arg_0), (VOID *)VariablePropertySet_Arg_0);
                VariablePropertySet_Arg_0[31] = 0;
            }
            break;
    }
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        VariablePropertySet_Arg_1->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        VariablePropertySet_Arg_1->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        VariablePropertySet_Arg_1->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(VariablePropertySet_Arg_1->Data4), (VOID *)&(VariablePropertySet_Arg_1->Data4));
    
    // Generator Struct Variable Initialization
    {
        UINT16 Firness_Revision;
        ReadBytes(Input, sizeof(Firness_Revision), (VOID *)&Firness_Revision);
        VariablePropertySet_Arg_2->Revision = Firness_Revision;
    }
    {
        UINT16 Firness_Property;
        ReadBytes(Input, sizeof(Firness_Property), (VOID *)&Firness_Property);
        VariablePropertySet_Arg_2->Property = Firness_Property;
    }
    {
        UINT32 Firness_Attributes;
        ReadBytes(Input, sizeof(Firness_Attributes), (VOID *)&Firness_Attributes);
        VariablePropertySet_Arg_2->Attributes = Firness_Attributes;
    }
    VariablePropertySet_Arg_2->MinSize = sizeof(VAR_CHECK_VARIABLE_PROPERTY);
    VariablePropertySet_Arg_2->MaxSize = sizeof(VAR_CHECK_VARIABLE_PROPERTY);
    
    UINT8 VariablePropertySet_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(VariablePropertySet_Arg_2_LiveChoice), (VOID *)&VariablePropertySet_Arg_2_LiveChoice);
    if (FirnessLive_VAR_CHECK_VARIABLE_PROPERTY___Count > 0 && (VariablePropertySet_Arg_2_LiveChoice & 1)) {
        VariablePropertySet_Arg_2 = FirnessLive_VAR_CHECK_VARIABLE_PROPERTY__[VariablePropertySet_Arg_2_LiveChoice % FirnessLive_VAR_CHECK_VARIABLE_PROPERTY___Count];
    }
    FirnessUntrusted(VariablePropertySet_Arg_0, 32 * sizeof(CHAR16));
    FirnessUntrusted(VariablePropertySet_Arg_1, sizeof(EFI_GUID));
    FirnessUntrusted(VariablePropertySet_Arg_2, sizeof(VAR_CHECK_VARIABLE_PROPERTY));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->VariablePropertySet(
        VariablePropertySet_Arg_0,
        VariablePropertySet_Arg_1,
        VariablePropertySet_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called VariablePropertyGet.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzVariablePropertyGet(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VAR_CHECK_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVarCheckProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * VariablePropertyGet_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    EFI_GUID * VariablePropertyGet_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    // Fuzzable Variable Initialization
    UINT8 VariablePropertyGet_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(VariablePropertyGet_Arg_0_choice), (VOID *)&VariablePropertyGet_Arg_0_choice);
    switch(VariablePropertyGet_Arg_0_choice % 1) {
        case 0:
            if (VariablePropertyGet_Arg_0 != NULL) {
                ReadBytes(Input, 31 * sizeof(*VariablePropertyGet_Arg_0), (VOID *)VariablePropertyGet_Arg_0);
                VariablePropertyGet_Arg_0[31] = 0;
            }
            break;
    }
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        VariablePropertyGet_Arg_1->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        VariablePropertyGet_Arg_1->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        VariablePropertyGet_Arg_1->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(VariablePropertyGet_Arg_1->Data4), (VOID *)&(VariablePropertyGet_Arg_1->Data4));
    
    /*
        Output Variable(s)
    */
    VAR_CHECK_VARIABLE_PROPERTY * VariablePropertyGet_Arg_2 = (VAR_CHECK_VARIABLE_PROPERTY *)AllocateZeroPool(sizeof(VAR_CHECK_VARIABLE_PROPERTY));
    UINT8* VariablePropertyGet_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*VariablePropertyGet_Arg_2_OutputChoice), (VOID *)VariablePropertyGet_Arg_2_OutputChoice);
    if(*VariablePropertyGet_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*VariablePropertyGet_Arg_2), (VOID *)VariablePropertyGet_Arg_2);
    }
    FirnessUntrusted(VariablePropertyGet_Arg_0, 32 * sizeof(CHAR16));
    FirnessUntrusted(VariablePropertyGet_Arg_1, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->VariablePropertyGet(
        VariablePropertyGet_Arg_0,
        VariablePropertyGet_Arg_1,
        VariablePropertyGet_Arg_2
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_VAR_CHECK_VARIABLE_PROPERTY___Count < 4 && VariablePropertyGet_Arg_2 != NULL) {
        FirnessLive_VAR_CHECK_VARIABLE_PROPERTY__[FirnessLive_VAR_CHECK_VARIABLE_PROPERTY___Count++] = VariablePropertyGet_Arg_2;
    }
    return Status;
}

