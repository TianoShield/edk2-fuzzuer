#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
EFI_STRING FirnessLive_EFI_STRING[4];
UINTN FirnessLive_EFI_STRING_Count = 0;
EFI_STRING * FirnessLive_EFI_STRING__[4];
UINTN FirnessLive_EFI_STRING___Count = 0;
UINT8 * FirnessLive_UINT8__[4];
UINTN FirnessLive_UINT8___Count = 0;
UINTN * FirnessLive_UINTN__[4];
UINTN FirnessLive_UINTN___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called BlockToConfig.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzBlockToConfig(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING BlockToConfig_Arg_1 = {0};
    UINT8 * BlockToConfig_Arg_2 = (UINT8 *)AllocateZeroPool(4096);
    UINTN BlockToConfig_Arg_3 = {0};
    
    // Fuzzable Variable Initialization
    // EFI_STRING is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    UINT8 BlockToConfig_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(BlockToConfig_Arg_2_choice), (VOID *)&BlockToConfig_Arg_2_choice);
    switch(BlockToConfig_Arg_2_choice % 1) {
        case 0:
            if (BlockToConfig_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*BlockToConfig_Arg_2), (VOID *)BlockToConfig_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(BlockToConfig_Arg_3), (VOID *)&BlockToConfig_Arg_3);
    BlockToConfig_Arg_3 = BlockToConfig_Arg_3 % (4096 + 1);
    if (BlockToConfig_Arg_2 != NULL) {
        FreePool(BlockToConfig_Arg_2);
    }
    BlockToConfig_Arg_2 = (UINT8 *)AllocateZeroPool(BlockToConfig_Arg_3 > 0 ? BlockToConfig_Arg_3 : 1);
    if (BlockToConfig_Arg_2 == NULL) {
        return EFI_OUT_OF_RESOURCES;
    }
    
    /*
        Output Variable(s)
    */
    EFI_STRING * BlockToConfig_Arg_4 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* BlockToConfig_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*BlockToConfig_Arg_4_OutputChoice), (VOID *)BlockToConfig_Arg_4_OutputChoice);
    if(*BlockToConfig_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*BlockToConfig_Arg_4), (VOID *)BlockToConfig_Arg_4);
    }
    EFI_STRING * BlockToConfig_Arg_5 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* BlockToConfig_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*BlockToConfig_Arg_5_OutputChoice), (VOID *)BlockToConfig_Arg_5_OutputChoice);
    if(*BlockToConfig_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*BlockToConfig_Arg_5), (VOID *)BlockToConfig_Arg_5);
    }
    UINT8 BlockToConfig_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(BlockToConfig_Arg_1_LiveChoice), (VOID *)&BlockToConfig_Arg_1_LiveChoice);
    if (FirnessLive_EFI_STRING_Count > 0 && (BlockToConfig_Arg_1_LiveChoice & 1)) {
        BlockToConfig_Arg_1 = FirnessLive_EFI_STRING[BlockToConfig_Arg_1_LiveChoice % FirnessLive_EFI_STRING_Count];
    }
    FirnessUntrusted(BlockToConfig_Arg_2, BlockToConfig_Arg_3);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->BlockToConfig(
        ProtocolVariable,
        BlockToConfig_Arg_1,
        BlockToConfig_Arg_2,
        BlockToConfig_Arg_3,
        BlockToConfig_Arg_4,
        BlockToConfig_Arg_5
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_STRING___Count < 4 && BlockToConfig_Arg_4 != NULL) {
        FirnessLive_EFI_STRING__[FirnessLive_EFI_STRING___Count++] = BlockToConfig_Arg_4;
    }
    if (FirnessLive_EFI_STRING_Count < 4 && BlockToConfig_Arg_4 != NULL && *BlockToConfig_Arg_4 != NULL) {
        FirnessLive_EFI_STRING[FirnessLive_EFI_STRING_Count++] = *BlockToConfig_Arg_4;
    }
    if (FirnessLive_EFI_STRING___Count < 4 && BlockToConfig_Arg_5 != NULL) {
        FirnessLive_EFI_STRING__[FirnessLive_EFI_STRING___Count++] = BlockToConfig_Arg_5;
    }
    if (FirnessLive_EFI_STRING_Count < 4 && BlockToConfig_Arg_5 != NULL && *BlockToConfig_Arg_5 != NULL) {
        FirnessLive_EFI_STRING[FirnessLive_EFI_STRING_Count++] = *BlockToConfig_Arg_5;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ConfigToBlock.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConfigToBlock(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING ConfigToBlock_Arg_1 = {0};
    UINT8 * ConfigToBlock_Arg_2 = (UINT8 *)AllocateZeroPool(4096);
    UINTN * ConfigToBlock_Arg_3 = (UINTN *)AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    // EFI_STRING is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    UINT8 ConfigToBlock_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(ConfigToBlock_Arg_2_choice), (VOID *)&ConfigToBlock_Arg_2_choice);
    switch(ConfigToBlock_Arg_2_choice % 1) {
        case 0:
            if (ConfigToBlock_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*ConfigToBlock_Arg_2), (VOID *)ConfigToBlock_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 ConfigToBlock_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(ConfigToBlock_Arg_3_choice), (VOID *)&ConfigToBlock_Arg_3_choice);
    switch(ConfigToBlock_Arg_3_choice % 1) {
        case 0:
            if (ConfigToBlock_Arg_3 != NULL) {
                ReadBytes(Input, sizeof(*ConfigToBlock_Arg_3), (VOID *)ConfigToBlock_Arg_3);
                *ConfigToBlock_Arg_3 = *ConfigToBlock_Arg_3 % (4096 + 1);
            }
            break;
    }
    
    /*
        Output Variable(s)
    */
    EFI_STRING * ConfigToBlock_Arg_4 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* ConfigToBlock_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ConfigToBlock_Arg_4_OutputChoice), (VOID *)ConfigToBlock_Arg_4_OutputChoice);
    if(*ConfigToBlock_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ConfigToBlock_Arg_4), (VOID *)ConfigToBlock_Arg_4);
    }
    UINT8 ConfigToBlock_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(ConfigToBlock_Arg_1_LiveChoice), (VOID *)&ConfigToBlock_Arg_1_LiveChoice);
    if (FirnessLive_EFI_STRING_Count > 0 && (ConfigToBlock_Arg_1_LiveChoice & 1)) {
        ConfigToBlock_Arg_1 = FirnessLive_EFI_STRING[ConfigToBlock_Arg_1_LiveChoice % FirnessLive_EFI_STRING_Count];
    }
    FirnessUntrusted(ConfigToBlock_Arg_2, 4096);
    FirnessUntrusted(ConfigToBlock_Arg_3, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->ConfigToBlock(
        ProtocolVariable,
        ConfigToBlock_Arg_1,
        ConfigToBlock_Arg_2,
        ConfigToBlock_Arg_3,
        ConfigToBlock_Arg_4
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINT8___Count < 4 && ConfigToBlock_Arg_2 != NULL) {
        FirnessLive_UINT8__[FirnessLive_UINT8___Count++] = ConfigToBlock_Arg_2;
    }
    if (FirnessLive_UINTN___Count < 4 && ConfigToBlock_Arg_3 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = ConfigToBlock_Arg_3;
    }
    if (FirnessLive_EFI_STRING___Count < 4 && ConfigToBlock_Arg_4 != NULL) {
        FirnessLive_EFI_STRING__[FirnessLive_EFI_STRING___Count++] = ConfigToBlock_Arg_4;
    }
    if (FirnessLive_EFI_STRING_Count < 4 && ConfigToBlock_Arg_4 != NULL && *ConfigToBlock_Arg_4 != NULL) {
        FirnessLive_EFI_STRING[FirnessLive_EFI_STRING_Count++] = *ConfigToBlock_Arg_4;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called RouteConfig.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRouteConfig(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * RouteConfig_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    CHAR16 * RouteConfig_Arg_2 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 RouteConfig_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(RouteConfig_Arg_1_choice), (VOID *)&RouteConfig_Arg_1_choice);
    switch(RouteConfig_Arg_1_choice % 1) {
        case 0:
            if (RouteConfig_Arg_1 != NULL) {
                ReadBytes(Input, 31 * sizeof(*RouteConfig_Arg_1), (VOID *)RouteConfig_Arg_1);
                RouteConfig_Arg_1[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 RouteConfig_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(RouteConfig_Arg_2_choice), (VOID *)&RouteConfig_Arg_2_choice);
    switch(RouteConfig_Arg_2_choice % 1) {
        case 0:
            if (RouteConfig_Arg_2 != NULL) {
                ReadBytes(Input, 31 * sizeof(*RouteConfig_Arg_2), (VOID *)RouteConfig_Arg_2);
                RouteConfig_Arg_2[31] = 0;
            }
            break;
    }
    
    FirnessUntrusted(RouteConfig_Arg_1, 32 * sizeof(CHAR16));
    FirnessUntrusted(RouteConfig_Arg_2, 32 * sizeof(CHAR16));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RouteConfig(
        ProtocolVariable,
        RouteConfig_Arg_1,
        (CHAR16 **)&RouteConfig_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ExtractConfig.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExtractConfig(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING ExtractConfig_Arg_1 = {0};
    EFI_STRING * ExtractConfig_Arg_2 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    EFI_STRING * ExtractConfig_Arg_3 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    
    // Fuzzable Variable Initialization
    // EFI_STRING is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    UINT8 ExtractConfig_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(ExtractConfig_Arg_2_choice), (VOID *)&ExtractConfig_Arg_2_choice);
    switch(ExtractConfig_Arg_2_choice % 1) {
        case 0:
            if (ExtractConfig_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*ExtractConfig_Arg_2), (VOID *)ExtractConfig_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 ExtractConfig_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(ExtractConfig_Arg_3_choice), (VOID *)&ExtractConfig_Arg_3_choice);
    switch(ExtractConfig_Arg_3_choice % 1) {
        case 0:
            if (ExtractConfig_Arg_3 != NULL) {
                ReadBytes(Input, sizeof(*ExtractConfig_Arg_3), (VOID *)ExtractConfig_Arg_3);
            }
            break;
    }
    
    UINT8 ExtractConfig_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(ExtractConfig_Arg_1_LiveChoice), (VOID *)&ExtractConfig_Arg_1_LiveChoice);
    if (FirnessLive_EFI_STRING_Count > 0 && (ExtractConfig_Arg_1_LiveChoice & 1)) {
        ExtractConfig_Arg_1 = FirnessLive_EFI_STRING[ExtractConfig_Arg_1_LiveChoice % FirnessLive_EFI_STRING_Count];
    }
    UINT8 ExtractConfig_Arg_2_LiveChoice = 0;
    ReadBytes(Input, sizeof(ExtractConfig_Arg_2_LiveChoice), (VOID *)&ExtractConfig_Arg_2_LiveChoice);
    if (FirnessLive_EFI_STRING___Count > 0 && (ExtractConfig_Arg_2_LiveChoice & 1)) {
        ExtractConfig_Arg_2 = FirnessLive_EFI_STRING__[ExtractConfig_Arg_2_LiveChoice % FirnessLive_EFI_STRING___Count];
    }
    UINT8 ExtractConfig_Arg_3_LiveChoice = 0;
    ReadBytes(Input, sizeof(ExtractConfig_Arg_3_LiveChoice), (VOID *)&ExtractConfig_Arg_3_LiveChoice);
    if (FirnessLive_EFI_STRING___Count > 0 && (ExtractConfig_Arg_3_LiveChoice & 1)) {
        ExtractConfig_Arg_3 = FirnessLive_EFI_STRING__[ExtractConfig_Arg_3_LiveChoice % FirnessLive_EFI_STRING___Count];
    }
    FirnessUntrusted(ExtractConfig_Arg_2, sizeof(EFI_STRING));
    FirnessUntrusted(ExtractConfig_Arg_3, sizeof(EFI_STRING));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->ExtractConfig(
        ProtocolVariable,
        ExtractConfig_Arg_1,
        ExtractConfig_Arg_2,
        ExtractConfig_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called ExportConfig.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExportConfig(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_STRING * ExportConfig_Arg_1 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* ExportConfig_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ExportConfig_Arg_1_OutputChoice), (VOID *)ExportConfig_Arg_1_OutputChoice);
    if(*ExportConfig_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ExportConfig_Arg_1), (VOID *)ExportConfig_Arg_1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->ExportConfig(
        ProtocolVariable,
        ExportConfig_Arg_1
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_STRING___Count < 4 && ExportConfig_Arg_1 != NULL) {
        FirnessLive_EFI_STRING__[FirnessLive_EFI_STRING___Count++] = ExportConfig_Arg_1;
    }
    if (FirnessLive_EFI_STRING_Count < 4 && ExportConfig_Arg_1 != NULL && *ExportConfig_Arg_1 != NULL) {
        FirnessLive_EFI_STRING[FirnessLive_EFI_STRING_Count++] = *ExportConfig_Arg_1;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetAltConfig.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetAltConfig(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ROUTING_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigRoutingProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING GetAltConfig_Arg_1 = {0};
    EFI_GUID * GetAltConfig_Arg_2 = (EFI_GUID *)AllocateZeroPool(sizeof(EFI_GUID));
    EFI_STRING GetAltConfig_Arg_3 = {0};
    EFI_DEVICE_PATH_PROTOCOL * GetAltConfig_Arg_4 = (EFI_DEVICE_PATH_PROTOCOL *)AllocateZeroPool(4096);
    FirnessMakeDevicePath (GetAltConfig_Arg_4, 4096);
    UINT16 * GetAltConfig_Arg_5 = (UINT16 *)AllocateZeroPool(sizeof(UINT16));
    
    // Fuzzable Variable Initialization
    // EFI_STRING is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    UINT8 GetAltConfig_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetAltConfig_Arg_2_choice), (VOID *)&GetAltConfig_Arg_2_choice);
    switch(GetAltConfig_Arg_2_choice % 1) {
        case 0:
            if (GetAltConfig_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*GetAltConfig_Arg_2), (VOID *)GetAltConfig_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    // EFI_STRING is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    // Fuzzable Variable Initialization
    UINT8 GetAltConfig_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(GetAltConfig_Arg_4_choice), (VOID *)&GetAltConfig_Arg_4_choice);
    switch(GetAltConfig_Arg_4_choice % 1) {
        case 0:
            if (GetAltConfig_Arg_4 != NULL) {
                ReadBytes(Input, sizeof(*GetAltConfig_Arg_4), (VOID *)GetAltConfig_Arg_4);
                FirnessMakeDevicePath (GetAltConfig_Arg_4, 4096);
            }
            break;
    }
    
    UINT8* GetAltConfig_Arg_5_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetAltConfig_Arg_5_choice), (VOID *)GetAltConfig_Arg_5_choice);
    switch(*GetAltConfig_Arg_5_choice % 5) {
        case 0:
        {
    
            break;
        }
        case 1:
        {
    
            break;
        }
        case 2:
        {
    
            break;
        }
        case 3:
        {
    
            break;
        }
        case 4:
        {
        // Fuzzable Variable Initialization
        UINT8 GetAltConfig_Arg_5_choice = 0;
        ReadBytes(Input, sizeof(GetAltConfig_Arg_5_choice), (VOID *)&GetAltConfig_Arg_5_choice);
        switch(GetAltConfig_Arg_5_choice % 1) {
            case 0:
                if (GetAltConfig_Arg_5 != NULL) {
                    ReadBytes(Input, sizeof(*GetAltConfig_Arg_5), (VOID *)GetAltConfig_Arg_5);
                }
                break;
        }
    
            break;
        }
    }
    /*
        Output Variable(s)
    */
    EFI_STRING * GetAltConfig_Arg_6 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* GetAltConfig_Arg_6_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetAltConfig_Arg_6_OutputChoice), (VOID *)GetAltConfig_Arg_6_OutputChoice);
    if(*GetAltConfig_Arg_6_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetAltConfig_Arg_6), (VOID *)GetAltConfig_Arg_6);
    }
    UINT8 GetAltConfig_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetAltConfig_Arg_1_LiveChoice), (VOID *)&GetAltConfig_Arg_1_LiveChoice);
    if (FirnessLive_EFI_STRING_Count > 0 && (GetAltConfig_Arg_1_LiveChoice & 1)) {
        GetAltConfig_Arg_1 = FirnessLive_EFI_STRING[GetAltConfig_Arg_1_LiveChoice % FirnessLive_EFI_STRING_Count];
    }
    UINT8 GetAltConfig_Arg_3_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetAltConfig_Arg_3_LiveChoice), (VOID *)&GetAltConfig_Arg_3_LiveChoice);
    if (FirnessLive_EFI_STRING_Count > 0 && (GetAltConfig_Arg_3_LiveChoice & 1)) {
        GetAltConfig_Arg_3 = FirnessLive_EFI_STRING[GetAltConfig_Arg_3_LiveChoice % FirnessLive_EFI_STRING_Count];
    }
    FirnessUntrusted(GetAltConfig_Arg_2, sizeof(EFI_GUID));
    FirnessUntrusted(GetAltConfig_Arg_4, 4096);
    FirnessUntrusted(GetAltConfig_Arg_5, sizeof(UINT16));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetAltConfig(
        ProtocolVariable,
        GetAltConfig_Arg_1,
        GetAltConfig_Arg_2,
        GetAltConfig_Arg_3,
        GetAltConfig_Arg_4,
        GetAltConfig_Arg_5,
        GetAltConfig_Arg_6
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_STRING___Count < 4 && GetAltConfig_Arg_6 != NULL) {
        FirnessLive_EFI_STRING__[FirnessLive_EFI_STRING___Count++] = GetAltConfig_Arg_6;
    }
    if (FirnessLive_EFI_STRING_Count < 4 && GetAltConfig_Arg_6 != NULL && *GetAltConfig_Arg_6 != NULL) {
        FirnessLive_EFI_STRING[FirnessLive_EFI_STRING_Count++] = *GetAltConfig_Arg_6;
    }
    return Status;
}

