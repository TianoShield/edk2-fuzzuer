#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
UINT32 * FirnessLive_UINT32__[4];
UINTN FirnessLive_UINT32___Count = 0;
UINT8 * FirnessLive_UINT8__[4];
UINTN FirnessLive_UINT8___Count = 0;
VARIABLE_POLICY_ENTRY * FirnessLive_VARIABLE_POLICY_ENTRY__[4];
UINTN FirnessLive_VARIABLE_POLICY_ENTRY___Count = 0;

/*
    This is a harness for fuzzing the Protocols service
    called DisableVariablePolicy.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDisableVariablePolicy(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->DisableVariablePolicy(
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called RegisterVariablePolicy.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterVariablePolicy(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    VARIABLE_POLICY_ENTRY * RegisterVariablePolicy_Arg_0 = (VARIABLE_POLICY_ENTRY *)AllocateZeroPool(sizeof(VARIABLE_POLICY_ENTRY));
    
    UINT8* RegisterVariablePolicy_Arg_0_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*RegisterVariablePolicy_Arg_0_choice), (VOID *)RegisterVariablePolicy_Arg_0_choice);
    switch(*RegisterVariablePolicy_Arg_0_choice % 2) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 RegisterVariablePolicy_Arg_0_choice = 0;
        ReadBytes(Input, sizeof(RegisterVariablePolicy_Arg_0_choice), (VOID *)&RegisterVariablePolicy_Arg_0_choice);
        switch(RegisterVariablePolicy_Arg_0_choice % 1) {
            case 0:
                if (RegisterVariablePolicy_Arg_0 != NULL) {
                    ReadBytes(Input, sizeof(*RegisterVariablePolicy_Arg_0), (VOID *)RegisterVariablePolicy_Arg_0);
                }
                break;
        }
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
        {
            UINT32 Firness_Version;
            ReadBytes(Input, sizeof(Firness_Version), (VOID *)&Firness_Version);
            RegisterVariablePolicy_Arg_0->Version = Firness_Version;
        }
        RegisterVariablePolicy_Arg_0->Size = sizeof(VARIABLE_POLICY_ENTRY);
        {
            UINT16 Firness_OffsetToName;
            ReadBytes(Input, sizeof(Firness_OffsetToName), (VOID *)&Firness_OffsetToName);
            RegisterVariablePolicy_Arg_0->OffsetToName = Firness_OffsetToName;
        }
        ReadBytes(Input, sizeof(RegisterVariablePolicy_Arg_0->Namespace), (VOID *)&(RegisterVariablePolicy_Arg_0->Namespace));
        RegisterVariablePolicy_Arg_0->MinSize = sizeof(VARIABLE_POLICY_ENTRY);
        RegisterVariablePolicy_Arg_0->MaxSize = sizeof(VARIABLE_POLICY_ENTRY);
        {
            UINT32 Firness_AttributesMustHave;
            ReadBytes(Input, sizeof(Firness_AttributesMustHave), (VOID *)&Firness_AttributesMustHave);
            RegisterVariablePolicy_Arg_0->AttributesMustHave = Firness_AttributesMustHave;
        }
        {
            UINT32 Firness_AttributesCantHave;
            ReadBytes(Input, sizeof(Firness_AttributesCantHave), (VOID *)&Firness_AttributesCantHave);
            RegisterVariablePolicy_Arg_0->AttributesCantHave = Firness_AttributesCantHave;
        }
        {
            UINT8 Firness_LockPolicyType;
            ReadBytes(Input, sizeof(Firness_LockPolicyType), (VOID *)&Firness_LockPolicyType);
            RegisterVariablePolicy_Arg_0->LockPolicyType = Firness_LockPolicyType;
        }
        ReadBytes(Input, sizeof(RegisterVariablePolicy_Arg_0->Padding), (VOID *)&(RegisterVariablePolicy_Arg_0->Padding));
    
            break;
        }
    }
    UINT8 RegisterVariablePolicy_Arg_0_LiveChoice = 0;
    ReadBytes(Input, sizeof(RegisterVariablePolicy_Arg_0_LiveChoice), (VOID *)&RegisterVariablePolicy_Arg_0_LiveChoice);
    if (FirnessLive_VARIABLE_POLICY_ENTRY___Count > 0 && (RegisterVariablePolicy_Arg_0_LiveChoice & 1)) {
        RegisterVariablePolicy_Arg_0 = FirnessLive_VARIABLE_POLICY_ENTRY__[RegisterVariablePolicy_Arg_0_LiveChoice % FirnessLive_VARIABLE_POLICY_ENTRY___Count];
    }
    FirnessUntrusted(RegisterVariablePolicy_Arg_0, sizeof(VARIABLE_POLICY_ENTRY));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RegisterVariablePolicy(
        RegisterVariablePolicy_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called LockVariablePolicy.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzLockVariablePolicy(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->LockVariablePolicy(
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called IsVariablePolicyEnabled.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzIsVariablePolicyEnabled(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    BOOLEAN * IsVariablePolicyEnabled_Arg_0 = (BOOLEAN *)AllocateZeroPool(sizeof(BOOLEAN));
    UINT8* IsVariablePolicyEnabled_Arg_0_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*IsVariablePolicyEnabled_Arg_0_OutputChoice), (VOID *)IsVariablePolicyEnabled_Arg_0_OutputChoice);
    if(*IsVariablePolicyEnabled_Arg_0_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*IsVariablePolicyEnabled_Arg_0), (VOID *)IsVariablePolicyEnabled_Arg_0);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->IsVariablePolicyEnabled(
        IsVariablePolicyEnabled_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called DumpVariablePolicy.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDumpVariablePolicy(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT8 * DumpVariablePolicy_Arg_0 = (UINT8 *)AllocateZeroPool(4096);
    UINT32 * DumpVariablePolicy_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    UINT8 DumpVariablePolicy_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(DumpVariablePolicy_Arg_0_choice), (VOID *)&DumpVariablePolicy_Arg_0_choice);
    switch(DumpVariablePolicy_Arg_0_choice % 1) {
        case 0:
            if (DumpVariablePolicy_Arg_0 != NULL) {
                ReadBytes(Input, sizeof(*DumpVariablePolicy_Arg_0), (VOID *)DumpVariablePolicy_Arg_0);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 DumpVariablePolicy_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(DumpVariablePolicy_Arg_1_choice), (VOID *)&DumpVariablePolicy_Arg_1_choice);
    switch(DumpVariablePolicy_Arg_1_choice % 1) {
        case 0:
            if (DumpVariablePolicy_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*DumpVariablePolicy_Arg_1), (VOID *)DumpVariablePolicy_Arg_1);
                *DumpVariablePolicy_Arg_1 = *DumpVariablePolicy_Arg_1 % (4096 + 1);
            }
            break;
    }
    
    FirnessUntrusted(DumpVariablePolicy_Arg_0, 4096);
    FirnessUntrusted(DumpVariablePolicy_Arg_1, sizeof(UINT32));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->DumpVariablePolicy(
        DumpVariablePolicy_Arg_0,
        DumpVariablePolicy_Arg_1
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINT8___Count < 4 && DumpVariablePolicy_Arg_0 != NULL) {
        FirnessLive_UINT8__[FirnessLive_UINT8___Count++] = DumpVariablePolicy_Arg_0;
    }
    if (FirnessLive_UINT32___Count < 4 && DumpVariablePolicy_Arg_1 != NULL) {
        FirnessLive_UINT32__[FirnessLive_UINT32___Count++] = DumpVariablePolicy_Arg_1;
    }
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetVariablePolicyInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetVariablePolicyInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * GetVariablePolicyInfo_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    EFI_GUID * GetVariablePolicyInfo_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    // Fuzzable Variable Initialization
    UINT8 GetVariablePolicyInfo_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(GetVariablePolicyInfo_Arg_0_choice), (VOID *)&GetVariablePolicyInfo_Arg_0_choice);
    switch(GetVariablePolicyInfo_Arg_0_choice % 1) {
        case 0:
            if (GetVariablePolicyInfo_Arg_0 != NULL) {
                ReadBytes(Input, 31 * sizeof(*GetVariablePolicyInfo_Arg_0), (VOID *)GetVariablePolicyInfo_Arg_0);
                GetVariablePolicyInfo_Arg_0[31] = 0;
            }
            break;
    }
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        GetVariablePolicyInfo_Arg_1->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        GetVariablePolicyInfo_Arg_1->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        GetVariablePolicyInfo_Arg_1->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(GetVariablePolicyInfo_Arg_1->Data4), (VOID *)&(GetVariablePolicyInfo_Arg_1->Data4));
    
    /*
        Output Variable(s)
    */
    VARIABLE_POLICY_ENTRY * GetVariablePolicyInfo_Arg_3 = (VARIABLE_POLICY_ENTRY *)AllocateZeroPool(sizeof(VARIABLE_POLICY_ENTRY));
    UINT8* GetVariablePolicyInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetVariablePolicyInfo_Arg_3_OutputChoice), (VOID *)GetVariablePolicyInfo_Arg_3_OutputChoice);
    if(*GetVariablePolicyInfo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetVariablePolicyInfo_Arg_3), (VOID *)GetVariablePolicyInfo_Arg_3);
    }
    VOID *GetVariablePolicyInfo_Arg_2 = AllocateZeroPool(4096);
    VOID *GetVariablePolicyInfo_Arg_4 = AllocateZeroPool(4096);
    FirnessUntrusted(GetVariablePolicyInfo_Arg_0, 32 * sizeof(CHAR16));
    FirnessUntrusted(GetVariablePolicyInfo_Arg_1, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetVariablePolicyInfo(
        GetVariablePolicyInfo_Arg_0,
        GetVariablePolicyInfo_Arg_1,
        GetVariablePolicyInfo_Arg_2,
        GetVariablePolicyInfo_Arg_3,
        GetVariablePolicyInfo_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_VARIABLE_POLICY_ENTRY___Count < 4 && GetVariablePolicyInfo_Arg_3 != NULL) {
        FirnessLive_VARIABLE_POLICY_ENTRY__[FirnessLive_VARIABLE_POLICY_ENTRY___Count++] = GetVariablePolicyInfo_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetLockOnVariableStateVariablePolicyInfo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetLockOnVariableStateVariablePolicyInfo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_VARIABLE_POLICY_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiVariablePolicyProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * GetLockOnVariableStateVariablePolicyInfo_Arg_0 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    EFI_GUID * GetLockOnVariableStateVariablePolicyInfo_Arg_1 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    
    // Fuzzable Variable Initialization
    UINT8 GetLockOnVariableStateVariablePolicyInfo_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(GetLockOnVariableStateVariablePolicyInfo_Arg_0_choice), (VOID *)&GetLockOnVariableStateVariablePolicyInfo_Arg_0_choice);
    switch(GetLockOnVariableStateVariablePolicyInfo_Arg_0_choice % 1) {
        case 0:
            if (GetLockOnVariableStateVariablePolicyInfo_Arg_0 != NULL) {
                ReadBytes(Input, 31 * sizeof(*GetLockOnVariableStateVariablePolicyInfo_Arg_0), (VOID *)GetLockOnVariableStateVariablePolicyInfo_Arg_0);
                GetLockOnVariableStateVariablePolicyInfo_Arg_0[31] = 0;
            }
            break;
    }
    
    // Generator Struct Variable Initialization
    {
        UINT32 Firness_Data1;
        ReadBytes(Input, sizeof(Firness_Data1), (VOID *)&Firness_Data1);
        GetLockOnVariableStateVariablePolicyInfo_Arg_1->Data1 = Firness_Data1;
    }
    {
        UINT16 Firness_Data2;
        ReadBytes(Input, sizeof(Firness_Data2), (VOID *)&Firness_Data2);
        GetLockOnVariableStateVariablePolicyInfo_Arg_1->Data2 = Firness_Data2;
    }
    {
        UINT16 Firness_Data3;
        ReadBytes(Input, sizeof(Firness_Data3), (VOID *)&Firness_Data3);
        GetLockOnVariableStateVariablePolicyInfo_Arg_1->Data3 = Firness_Data3;
    }
    ReadBytes(Input, sizeof(GetLockOnVariableStateVariablePolicyInfo_Arg_1->Data4), (VOID *)&(GetLockOnVariableStateVariablePolicyInfo_Arg_1->Data4));
    
    /*
        Output Variable(s)
    */
    VARIABLE_LOCK_ON_VAR_STATE_POLICY * GetLockOnVariableStateVariablePolicyInfo_Arg_3 = (VARIABLE_LOCK_ON_VAR_STATE_POLICY *)AllocateZeroPool(sizeof(VARIABLE_LOCK_ON_VAR_STATE_POLICY));
    UINT8* GetLockOnVariableStateVariablePolicyInfo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetLockOnVariableStateVariablePolicyInfo_Arg_3_OutputChoice), (VOID *)GetLockOnVariableStateVariablePolicyInfo_Arg_3_OutputChoice);
    if(*GetLockOnVariableStateVariablePolicyInfo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetLockOnVariableStateVariablePolicyInfo_Arg_3), (VOID *)GetLockOnVariableStateVariablePolicyInfo_Arg_3);
    }
    VOID *GetLockOnVariableStateVariablePolicyInfo_Arg_2 = AllocateZeroPool(4096);
    VOID *GetLockOnVariableStateVariablePolicyInfo_Arg_4 = AllocateZeroPool(4096);
    FirnessUntrusted(GetLockOnVariableStateVariablePolicyInfo_Arg_0, 32 * sizeof(CHAR16));
    FirnessUntrusted(GetLockOnVariableStateVariablePolicyInfo_Arg_1, sizeof(EFI_GUID));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetLockOnVariableStateVariablePolicyInfo(
        GetLockOnVariableStateVariablePolicyInfo_Arg_0,
        GetLockOnVariableStateVariablePolicyInfo_Arg_1,
        GetLockOnVariableStateVariablePolicyInfo_Arg_2,
        GetLockOnVariableStateVariablePolicyInfo_Arg_3,
        GetLockOnVariableStateVariablePolicyInfo_Arg_4
    );
    FirnessSanitizer(FALSE);
    return Status;
}

