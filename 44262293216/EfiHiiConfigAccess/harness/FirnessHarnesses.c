#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
EFI_IFR_TYPE_VALUE * FirnessLive_EFI_IFR_TYPE_VALUE__[4];
UINTN FirnessLive_EFI_IFR_TYPE_VALUE___Count = 0;
EFI_STRING FirnessLive_EFI_STRING[4];
UINTN FirnessLive_EFI_STRING_Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called Callback.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCallback(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_HII_CONFIG_ACCESS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigAccessProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_BROWSER_ACTION Callback_Arg_1 = {0};
    EFI_QUESTION_ID Callback_Arg_2 = {0};
    UINT8 Callback_Arg_3 = {0};
    EFI_IFR_TYPE_VALUE * Callback_Arg_4 = (EFI_IFR_TYPE_VALUE *)AllocateZeroPool(sizeof(EFI_IFR_TYPE_VALUE));
    EFI_BROWSER_ACTION_REQUEST * Callback_Arg_5 = (EFI_BROWSER_ACTION_REQUEST *)AllocateZeroPool(sizeof(EFI_BROWSER_ACTION_REQUEST));
    
    UINT8* Callback_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Callback_Arg_1_choice), (VOID *)Callback_Arg_1_choice);
    switch(*Callback_Arg_1_choice % 5) {
        case 0:
        {
        // Constant Variable Initialization
        Callback_Arg_1 = EFI_BROWSER_ACTION_RETRIEVE;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        Callback_Arg_1 = EFI_BROWSER_ACTION_CHANGED;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        Callback_Arg_1 = EFI_BROWSER_ACTION_SUBMITTED;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        Callback_Arg_1 = EFI_BROWSER_ACTION_CHANGING;
    
            break;
        }
        case 4:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Callback_Arg_1), (VOID *)&Callback_Arg_1);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Callback_Arg_2), (VOID *)&Callback_Arg_2);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Callback_Arg_3), (VOID *)&Callback_Arg_3);
    
    
    // Fuzzable Variable Initialization
    UINT8 Callback_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(Callback_Arg_5_choice), (VOID *)&Callback_Arg_5_choice);
    switch(Callback_Arg_5_choice % 1) {
        case 0:
            if (Callback_Arg_5 != NULL) {
                ReadBytes(Input, sizeof(*Callback_Arg_5), (VOID *)Callback_Arg_5);
            }
            break;
    }
    
    UINT8 Callback_Arg_4_LiveChoice = 0;
    ReadBytes(Input, sizeof(Callback_Arg_4_LiveChoice), (VOID *)&Callback_Arg_4_LiveChoice);
    if (FirnessLive_EFI_IFR_TYPE_VALUE___Count > 0 && (Callback_Arg_4_LiveChoice & 1)) {
        Callback_Arg_4 = FirnessLive_EFI_IFR_TYPE_VALUE__[Callback_Arg_4_LiveChoice % FirnessLive_EFI_IFR_TYPE_VALUE___Count];
    }
    FirnessUntrusted(Callback_Arg_4, sizeof(EFI_IFR_TYPE_VALUE));
    FirnessUntrusted(Callback_Arg_5, sizeof(EFI_BROWSER_ACTION_REQUEST));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Callback(
        ProtocolVariable,
        Callback_Arg_1,
        Callback_Arg_2,
        Callback_Arg_3,
        Callback_Arg_4,
        Callback_Arg_5
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_IFR_TYPE_VALUE___Count < 4 && Callback_Arg_4 != NULL) {
        FirnessLive_EFI_IFR_TYPE_VALUE__[FirnessLive_EFI_IFR_TYPE_VALUE___Count++] = Callback_Arg_4;
    }
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
    EFI_HII_CONFIG_ACCESS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigAccessProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING ExtractConfig_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    // EFI_STRING is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    /*
        Output Variable(s)
    */
    EFI_STRING * ExtractConfig_Arg_2 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* ExtractConfig_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ExtractConfig_Arg_2_OutputChoice), (VOID *)ExtractConfig_Arg_2_OutputChoice);
    if(*ExtractConfig_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ExtractConfig_Arg_2), (VOID *)ExtractConfig_Arg_2);
    }
    EFI_STRING * ExtractConfig_Arg_3 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* ExtractConfig_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*ExtractConfig_Arg_3_OutputChoice), (VOID *)ExtractConfig_Arg_3_OutputChoice);
    if(*ExtractConfig_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*ExtractConfig_Arg_3), (VOID *)ExtractConfig_Arg_3);
    }
    UINT8 ExtractConfig_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(ExtractConfig_Arg_1_LiveChoice), (VOID *)&ExtractConfig_Arg_1_LiveChoice);
    if (FirnessLive_EFI_STRING_Count > 0 && (ExtractConfig_Arg_1_LiveChoice & 1)) {
        ExtractConfig_Arg_1 = FirnessLive_EFI_STRING[ExtractConfig_Arg_1_LiveChoice % FirnessLive_EFI_STRING_Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->ExtractConfig(
        ProtocolVariable,
        ExtractConfig_Arg_1,
        ExtractConfig_Arg_2,
        ExtractConfig_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_STRING_Count < 4 && ExtractConfig_Arg_2 != NULL && *ExtractConfig_Arg_2 != NULL) {
        FirnessLive_EFI_STRING[FirnessLive_EFI_STRING_Count++] = *ExtractConfig_Arg_2;
    }
    if (FirnessLive_EFI_STRING_Count < 4 && ExtractConfig_Arg_3 != NULL && *ExtractConfig_Arg_3 != NULL) {
        FirnessLive_EFI_STRING[FirnessLive_EFI_STRING_Count++] = *ExtractConfig_Arg_3;
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
    EFI_HII_CONFIG_ACCESS_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiHiiConfigAccessProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_STRING RouteConfig_Arg_1 = {0};
    
    // Fuzzable Variable Initialization
    // EFI_STRING is a pointer behind an opaque name: left NULL unless a live one is drawn below
    
    /*
        Output Variable(s)
    */
    EFI_STRING * RouteConfig_Arg_2 = (EFI_STRING *)AllocateZeroPool(sizeof(EFI_STRING));
    UINT8* RouteConfig_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*RouteConfig_Arg_2_OutputChoice), (VOID *)RouteConfig_Arg_2_OutputChoice);
    if(*RouteConfig_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*RouteConfig_Arg_2), (VOID *)RouteConfig_Arg_2);
    }
    UINT8 RouteConfig_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(RouteConfig_Arg_1_LiveChoice), (VOID *)&RouteConfig_Arg_1_LiveChoice);
    if (FirnessLive_EFI_STRING_Count > 0 && (RouteConfig_Arg_1_LiveChoice & 1)) {
        RouteConfig_Arg_1 = FirnessLive_EFI_STRING[RouteConfig_Arg_1_LiveChoice % FirnessLive_EFI_STRING_Count];
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RouteConfig(
        ProtocolVariable,
        RouteConfig_Arg_1,
        RouteConfig_Arg_2
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_STRING_Count < 4 && RouteConfig_Arg_2 != NULL && *RouteConfig_Arg_2 != NULL) {
        FirnessLive_EFI_STRING[FirnessLive_EFI_STRING_Count++] = *RouteConfig_Arg_2;
    }
    return Status;
}

