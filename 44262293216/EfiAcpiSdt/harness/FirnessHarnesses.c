#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
EFI_ACPI_HANDLE FirnessLive_EFI_ACPI_HANDLE[4];
UINTN FirnessLive_EFI_ACPI_HANDLE_Count = 0;
EFI_ACPI_HANDLE * FirnessLive_EFI_ACPI_HANDLE__[4];
UINTN FirnessLive_EFI_ACPI_HANDLE___Count = 0;

/*
    This is a harness for fuzzing the Protocols service
    called GetAcpiTable.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetAcpiTable(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN GetAcpiTable_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetAcpiTable_Arg_0), (VOID *)&GetAcpiTable_Arg_0);
    
    /*
        Output Variable(s)
    */
    EFI_ACPI_SDT_HEADER * GetAcpiTable_Arg_1 = NULL;
    UINT8* GetAcpiTable_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetAcpiTable_Arg_1_OutputChoice), (VOID *)GetAcpiTable_Arg_1_OutputChoice);
    if(*GetAcpiTable_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetAcpiTable_Arg_1), (VOID *)GetAcpiTable_Arg_1);
    }
    EFI_ACPI_TABLE_VERSION * GetAcpiTable_Arg_2 = (EFI_ACPI_TABLE_VERSION *)AllocateZeroPool(sizeof(EFI_ACPI_TABLE_VERSION));
    UINT8* GetAcpiTable_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetAcpiTable_Arg_2_OutputChoice), (VOID *)GetAcpiTable_Arg_2_OutputChoice);
    if(*GetAcpiTable_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetAcpiTable_Arg_2), (VOID *)GetAcpiTable_Arg_2);
    }
    UINTN * GetAcpiTable_Arg_3 = (UINTN *)AllocateZeroPool(4096);
    UINT8* GetAcpiTable_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetAcpiTable_Arg_3_OutputChoice), (VOID *)GetAcpiTable_Arg_3_OutputChoice);
    if(*GetAcpiTable_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetAcpiTable_Arg_3), (VOID *)GetAcpiTable_Arg_3);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetAcpiTable(
        GetAcpiTable_Arg_0,
        (EFI_ACPI_SDT_HEADER * *)&GetAcpiTable_Arg_1,
        GetAcpiTable_Arg_2,
        GetAcpiTable_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called RegisterNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    BOOLEAN RegisterNotify_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(RegisterNotify_Arg_0), (VOID *)&RegisterNotify_Arg_0);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RegisterNotify(
        RegisterNotify_Arg_0,
        (EFI_ACPI_NOTIFICATION_FN){0}
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Open.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOpen(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Open_Arg_0 = (UINTN* )AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    UINT8 Open_Arg_0_choice = 0;
    ReadBytes(Input, sizeof(Open_Arg_0_choice), (VOID *)&Open_Arg_0_choice);
    switch(Open_Arg_0_choice % 1) {
        case 0:
            if (Open_Arg_0 != NULL) {
                ReadBytes(Input, sizeof(*Open_Arg_0), (VOID *)Open_Arg_0);
            }
            break;
    }
    
    /*
        Output Variable(s)
    */
    EFI_ACPI_HANDLE * Open_Arg_1 = (EFI_ACPI_HANDLE *)AllocateZeroPool(sizeof(EFI_ACPI_HANDLE));
    UINT8* Open_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Open_Arg_1_OutputChoice), (VOID *)Open_Arg_1_OutputChoice);
    if(*Open_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*Open_Arg_1), (VOID *)Open_Arg_1);
    }
    FirnessUntrusted(Open_Arg_0, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Open(
        (VOID *)Open_Arg_0,
        Open_Arg_1
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_ACPI_HANDLE___Count < 4 && Open_Arg_1 != NULL) {
        FirnessLive_EFI_ACPI_HANDLE__[FirnessLive_EFI_ACPI_HANDLE___Count++] = Open_Arg_1;
    }
    if (FirnessLive_EFI_ACPI_HANDLE_Count < 4 && Open_Arg_1 != NULL && *Open_Arg_1 != NULL) {
        FirnessLive_EFI_ACPI_HANDLE[FirnessLive_EFI_ACPI_HANDLE_Count++] = *Open_Arg_1;
    }
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called OpenSdt.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzOpenSdt(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN OpenSdt_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(OpenSdt_Arg_0), (VOID *)&OpenSdt_Arg_0);
    
    /*
        Output Variable(s)
    */
    EFI_ACPI_HANDLE * OpenSdt_Arg_1 = (EFI_ACPI_HANDLE *)AllocateZeroPool(sizeof(EFI_ACPI_HANDLE));
    UINT8* OpenSdt_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*OpenSdt_Arg_1_OutputChoice), (VOID *)OpenSdt_Arg_1_OutputChoice);
    if(*OpenSdt_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*OpenSdt_Arg_1), (VOID *)OpenSdt_Arg_1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->OpenSdt(
        OpenSdt_Arg_0,
        OpenSdt_Arg_1
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_ACPI_HANDLE___Count < 4 && OpenSdt_Arg_1 != NULL) {
        FirnessLive_EFI_ACPI_HANDLE__[FirnessLive_EFI_ACPI_HANDLE___Count++] = OpenSdt_Arg_1;
    }
    if (FirnessLive_EFI_ACPI_HANDLE_Count < 4 && OpenSdt_Arg_1 != NULL && *OpenSdt_Arg_1 != NULL) {
        FirnessLive_EFI_ACPI_HANDLE[FirnessLive_EFI_ACPI_HANDLE_Count++] = *OpenSdt_Arg_1;
    }
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called Close.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzClose(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ACPI_HANDLE Close_Arg_0 = {0};
    
    // Fuzzable Variable Initialization
    // EFI_ACPI_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    UINT8 Close_Arg_0_LiveChoice = 0;
    ReadBytes(Input, sizeof(Close_Arg_0_LiveChoice), (VOID *)&Close_Arg_0_LiveChoice);
    if (FirnessLive_EFI_ACPI_HANDLE_Count > 0 && (Close_Arg_0_LiveChoice & 1)) {
        Close_Arg_0 = FirnessLive_EFI_ACPI_HANDLE[Close_Arg_0_LiveChoice % FirnessLive_EFI_ACPI_HANDLE_Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Close(
        Close_Arg_0
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetChild.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetChild(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ACPI_HANDLE GetChild_Arg_0 = {0};
    EFI_ACPI_HANDLE * GetChild_Arg_1 = (EFI_ACPI_HANDLE *)AllocateZeroPool(sizeof(EFI_ACPI_HANDLE));
    
    // Fuzzable Variable Initialization
    // EFI_ACPI_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    UINT8 GetChild_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetChild_Arg_1_choice), (VOID *)&GetChild_Arg_1_choice);
    switch(GetChild_Arg_1_choice % 1) {
        case 0:
            if (GetChild_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*GetChild_Arg_1), (VOID *)GetChild_Arg_1);
            }
            break;
    }
    
    UINT8 GetChild_Arg_0_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetChild_Arg_0_LiveChoice), (VOID *)&GetChild_Arg_0_LiveChoice);
    if (FirnessLive_EFI_ACPI_HANDLE_Count > 0 && (GetChild_Arg_0_LiveChoice & 1)) {
        GetChild_Arg_0 = FirnessLive_EFI_ACPI_HANDLE[GetChild_Arg_0_LiveChoice % FirnessLive_EFI_ACPI_HANDLE_Count];
    }
    UINT8 GetChild_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetChild_Arg_1_LiveChoice), (VOID *)&GetChild_Arg_1_LiveChoice);
    if (FirnessLive_EFI_ACPI_HANDLE___Count > 0 && (GetChild_Arg_1_LiveChoice & 1)) {
        GetChild_Arg_1 = FirnessLive_EFI_ACPI_HANDLE__[GetChild_Arg_1_LiveChoice % FirnessLive_EFI_ACPI_HANDLE___Count];
    }
    FirnessUntrusted(GetChild_Arg_1, sizeof(EFI_ACPI_HANDLE));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetChild(
        GetChild_Arg_0,
        GetChild_Arg_1
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_ACPI_HANDLE___Count < 4 && GetChild_Arg_1 != NULL) {
        FirnessLive_EFI_ACPI_HANDLE__[FirnessLive_EFI_ACPI_HANDLE___Count++] = GetChild_Arg_1;
    }
    if (FirnessLive_EFI_ACPI_HANDLE_Count < 4 && GetChild_Arg_1 != NULL && *GetChild_Arg_1 != NULL) {
        FirnessLive_EFI_ACPI_HANDLE[FirnessLive_EFI_ACPI_HANDLE_Count++] = *GetChild_Arg_1;
    }
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called GetOption.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetOption(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ACPI_HANDLE GetOption_Arg_0 = {0};
    UINTN GetOption_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    // EFI_ACPI_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(GetOption_Arg_1), (VOID *)&GetOption_Arg_1);
    
    /*
        Output Variable(s)
    */
    EFI_ACPI_DATA_TYPE * GetOption_Arg_2 = (EFI_ACPI_DATA_TYPE *)AllocateZeroPool(sizeof(EFI_ACPI_DATA_TYPE));
    UINT8* GetOption_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetOption_Arg_2_OutputChoice), (VOID *)GetOption_Arg_2_OutputChoice);
    if(*GetOption_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetOption_Arg_2), (VOID *)GetOption_Arg_2);
    }
    UINTN* GetOption_Arg_3 = NULL;
    UINT8* GetOption_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetOption_Arg_3_OutputChoice), (VOID *)GetOption_Arg_3_OutputChoice);
    if(*GetOption_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetOption_Arg_3), (VOID *)GetOption_Arg_3);
    }
    UINTN * GetOption_Arg_4 = (UINTN *)AllocateZeroPool(4096);
    UINT8* GetOption_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetOption_Arg_4_OutputChoice), (VOID *)GetOption_Arg_4_OutputChoice);
    if(*GetOption_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetOption_Arg_4), (VOID *)GetOption_Arg_4);
        *GetOption_Arg_4 = *GetOption_Arg_4 % (4096 + 1);
    }
    UINT8 GetOption_Arg_0_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetOption_Arg_0_LiveChoice), (VOID *)&GetOption_Arg_0_LiveChoice);
    if (FirnessLive_EFI_ACPI_HANDLE_Count > 0 && (GetOption_Arg_0_LiveChoice & 1)) {
        GetOption_Arg_0 = FirnessLive_EFI_ACPI_HANDLE[GetOption_Arg_0_LiveChoice % FirnessLive_EFI_ACPI_HANDLE_Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetOption(
        GetOption_Arg_0,
        GetOption_Arg_1,
        GetOption_Arg_2,
        (CONST VOID * *)&GetOption_Arg_3,
        GetOption_Arg_4
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called SetOption.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetOption(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ACPI_HANDLE SetOption_Arg_0 = {0};
    UINTN SetOption_Arg_1 = {0};
    UINTN*  SetOption_Arg_2 = (UINTN* )AllocateZeroPool(4096);
    UINTN SetOption_Arg_3 = {0};
    
    // Fuzzable Variable Initialization
    // EFI_ACPI_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetOption_Arg_1), (VOID *)&SetOption_Arg_1);
    SetOption_Arg_1 = SetOption_Arg_1 % (4096 + 1);
    
    // Fuzzable Variable Initialization
    UINT8 SetOption_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetOption_Arg_2_choice), (VOID *)&SetOption_Arg_2_choice);
    switch(SetOption_Arg_2_choice % 1) {
        case 0:
            if (SetOption_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*SetOption_Arg_2), (VOID *)SetOption_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetOption_Arg_3), (VOID *)&SetOption_Arg_3);
    SetOption_Arg_3 = SetOption_Arg_3 % (4096 + 1);
    if (SetOption_Arg_2 != NULL) {
        FreePool(SetOption_Arg_2);
    }
    SetOption_Arg_2 = (UINTN* )AllocateZeroPool(SetOption_Arg_3 > 0 ? SetOption_Arg_3 : 1);
    if (SetOption_Arg_2 == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }
    
    UINT8 SetOption_Arg_0_LiveChoice = 0;
    ReadBytes(Input, sizeof(SetOption_Arg_0_LiveChoice), (VOID *)&SetOption_Arg_0_LiveChoice);
    if (FirnessLive_EFI_ACPI_HANDLE_Count > 0 && (SetOption_Arg_0_LiveChoice & 1)) {
        SetOption_Arg_0 = FirnessLive_EFI_ACPI_HANDLE[SetOption_Arg_0_LiveChoice % FirnessLive_EFI_ACPI_HANDLE_Count];
    }
    FirnessUntrusted(SetOption_Arg_2, SetOption_Arg_3);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetOption(
        SetOption_Arg_0,
        SetOption_Arg_1,
        (VOID *)SetOption_Arg_2,
        SetOption_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the Protocols service
    called FindPath.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFindPath(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_ACPI_SDT_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiAcpiSdtProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ACPI_HANDLE FindPath_Arg_0 = {0};
    UINTN*  FindPath_Arg_1 = (UINTN* )AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    // EFI_ACPI_HANDLE is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    UINT8 FindPath_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(FindPath_Arg_1_choice), (VOID *)&FindPath_Arg_1_choice);
    switch(FindPath_Arg_1_choice % 1) {
        case 0:
            if (FindPath_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*FindPath_Arg_1), (VOID *)FindPath_Arg_1);
            }
            break;
    }
    
    /*
        Output Variable(s)
    */
    EFI_ACPI_HANDLE * FindPath_Arg_2 = (EFI_ACPI_HANDLE *)AllocateZeroPool(sizeof(EFI_ACPI_HANDLE));
    UINT8* FindPath_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*FindPath_Arg_2_OutputChoice), (VOID *)FindPath_Arg_2_OutputChoice);
    if(*FindPath_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*FindPath_Arg_2), (VOID *)FindPath_Arg_2);
    }
    UINT8 FindPath_Arg_0_LiveChoice = 0;
    ReadBytes(Input, sizeof(FindPath_Arg_0_LiveChoice), (VOID *)&FindPath_Arg_0_LiveChoice);
    if (FirnessLive_EFI_ACPI_HANDLE_Count > 0 && (FindPath_Arg_0_LiveChoice & 1)) {
        FindPath_Arg_0 = FirnessLive_EFI_ACPI_HANDLE[FindPath_Arg_0_LiveChoice % FirnessLive_EFI_ACPI_HANDLE_Count];
    }
    FirnessUntrusted(FindPath_Arg_1, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->FindPath(
        FindPath_Arg_0,
        (VOID *)FindPath_Arg_1,
        FindPath_Arg_2
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_ACPI_HANDLE___Count < 4 && FindPath_Arg_2 != NULL) {
        FirnessLive_EFI_ACPI_HANDLE__[FirnessLive_EFI_ACPI_HANDLE___Count++] = FindPath_Arg_2;
    }
    if (FirnessLive_EFI_ACPI_HANDLE_Count < 4 && FindPath_Arg_2 != NULL && *FindPath_Arg_2 != NULL) {
        FirnessLive_EFI_ACPI_HANDLE[FirnessLive_EFI_ACPI_HANDLE_Count++] = *FindPath_Arg_2;
    }
    return Status;
}

