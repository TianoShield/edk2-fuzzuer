#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
CHAR16 * FirnessLive_CHAR16__[4];
UINTN FirnessLive_CHAR16___Count = 0;
CHAR8 * FirnessLive_CHAR8__[4];
UINTN FirnessLive_CHAR8___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called StriColl.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStriColl(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollation2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * StriColl_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    CHAR16 * StriColl_Arg_2 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 StriColl_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(StriColl_Arg_1_choice), (VOID *)&StriColl_Arg_1_choice);
    switch(StriColl_Arg_1_choice % 1) {
        case 0:
            if (StriColl_Arg_1 != NULL) {
                ReadBytes(Input, 31 * sizeof(*StriColl_Arg_1), (VOID *)StriColl_Arg_1);
                StriColl_Arg_1[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 StriColl_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(StriColl_Arg_2_choice), (VOID *)&StriColl_Arg_2_choice);
    switch(StriColl_Arg_2_choice % 1) {
        case 0:
            if (StriColl_Arg_2 != NULL) {
                ReadBytes(Input, 31 * sizeof(*StriColl_Arg_2), (VOID *)StriColl_Arg_2);
                StriColl_Arg_2[31] = 0;
            }
            break;
    }
    
    FirnessUntrusted(StriColl_Arg_1, 32 * sizeof(CHAR16));
    FirnessUntrusted(StriColl_Arg_2, 32 * sizeof(CHAR16));
    FirnessSanitizer(TRUE);
    ProtocolVariable->StriColl(
        ProtocolVariable,
        StriColl_Arg_1,
        StriColl_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called MetaiMatch.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzMetaiMatch(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollation2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * MetaiMatch_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    CHAR16 * MetaiMatch_Arg_2 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 MetaiMatch_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(MetaiMatch_Arg_1_choice), (VOID *)&MetaiMatch_Arg_1_choice);
    switch(MetaiMatch_Arg_1_choice % 1) {
        case 0:
            if (MetaiMatch_Arg_1 != NULL) {
                ReadBytes(Input, 31 * sizeof(*MetaiMatch_Arg_1), (VOID *)MetaiMatch_Arg_1);
                MetaiMatch_Arg_1[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 MetaiMatch_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(MetaiMatch_Arg_2_choice), (VOID *)&MetaiMatch_Arg_2_choice);
    switch(MetaiMatch_Arg_2_choice % 1) {
        case 0:
            if (MetaiMatch_Arg_2 != NULL) {
                ReadBytes(Input, 31 * sizeof(*MetaiMatch_Arg_2), (VOID *)MetaiMatch_Arg_2);
                MetaiMatch_Arg_2[31] = 0;
            }
            break;
    }
    
    FirnessUntrusted(MetaiMatch_Arg_1, 32 * sizeof(CHAR16));
    FirnessUntrusted(MetaiMatch_Arg_2, 32 * sizeof(CHAR16));
    FirnessSanitizer(TRUE);
    ProtocolVariable->MetaiMatch(
        ProtocolVariable,
        MetaiMatch_Arg_1,
        MetaiMatch_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StrLwr.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStrLwr(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollation2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * StrLwr_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 StrLwr_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(StrLwr_Arg_1_choice), (VOID *)&StrLwr_Arg_1_choice);
    switch(StrLwr_Arg_1_choice % 1) {
        case 0:
            if (StrLwr_Arg_1 != NULL) {
                ReadBytes(Input, 31 * sizeof(*StrLwr_Arg_1), (VOID *)StrLwr_Arg_1);
                StrLwr_Arg_1[31] = 0;
            }
            break;
    }
    
    FirnessUntrusted(StrLwr_Arg_1, 32 * sizeof(CHAR16));
    FirnessSanitizer(TRUE);
    ProtocolVariable->StrLwr(
        ProtocolVariable,
        StrLwr_Arg_1
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_CHAR16___Count < 4 && StrLwr_Arg_1 != NULL) {
        FirnessLive_CHAR16__[FirnessLive_CHAR16___Count++] = StrLwr_Arg_1;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StrUpr.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStrUpr(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollation2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * StrUpr_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    
    // Fuzzable Variable Initialization
    UINT8 StrUpr_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(StrUpr_Arg_1_choice), (VOID *)&StrUpr_Arg_1_choice);
    switch(StrUpr_Arg_1_choice % 1) {
        case 0:
            if (StrUpr_Arg_1 != NULL) {
                ReadBytes(Input, 31 * sizeof(*StrUpr_Arg_1), (VOID *)StrUpr_Arg_1);
                StrUpr_Arg_1[31] = 0;
            }
            break;
    }
    
    FirnessUntrusted(StrUpr_Arg_1, 32 * sizeof(CHAR16));
    FirnessSanitizer(TRUE);
    ProtocolVariable->StrUpr(
        ProtocolVariable,
        StrUpr_Arg_1
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_CHAR16___Count < 4 && StrUpr_Arg_1 != NULL) {
        FirnessLive_CHAR16__[FirnessLive_CHAR16___Count++] = StrUpr_Arg_1;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FatToStr.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFatToStr(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollation2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN FatToStr_Arg_1 = {0};
    CHAR8 * FatToStr_Arg_2 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(FatToStr_Arg_1), (VOID *)&FatToStr_Arg_1);
    FatToStr_Arg_1 = FatToStr_Arg_1 % ((32 * sizeof(CHAR8)) + 1);
    
    // Fuzzable Variable Initialization
    UINT8 FatToStr_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(FatToStr_Arg_2_choice), (VOID *)&FatToStr_Arg_2_choice);
    switch(FatToStr_Arg_2_choice % 1) {
        case 0:
            if (FatToStr_Arg_2 != NULL) {
                ReadBytes(Input, 31 * sizeof(*FatToStr_Arg_2), (VOID *)FatToStr_Arg_2);
                FatToStr_Arg_2[31] = 0;
            }
            break;
    }
    
    /*
        Output Variable(s)
    */
    CHAR16 * FatToStr_Arg_3 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    UINT8* FatToStr_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*FatToStr_Arg_3_OutputChoice), (VOID *)FatToStr_Arg_3_OutputChoice);
    if(*FatToStr_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*FatToStr_Arg_3), (VOID *)FatToStr_Arg_3);
    }
    FirnessUntrusted(FatToStr_Arg_2, FatToStr_Arg_1);
    FirnessSanitizer(TRUE);
    ProtocolVariable->FatToStr(
        ProtocolVariable,
        FatToStr_Arg_1,
        FatToStr_Arg_2,
        FatToStr_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_CHAR16___Count < 4 && FatToStr_Arg_3 != NULL) {
        FirnessLive_CHAR16__[FirnessLive_CHAR16___Count++] = FatToStr_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called StrToFat.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzStrToFat(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_UNICODE_COLLATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiUnicodeCollation2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * StrToFat_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    UINTN StrToFat_Arg_2 = {0};
    
    // Fuzzable Variable Initialization
    UINT8 StrToFat_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(StrToFat_Arg_1_choice), (VOID *)&StrToFat_Arg_1_choice);
    switch(StrToFat_Arg_1_choice % 1) {
        case 0:
            if (StrToFat_Arg_1 != NULL) {
                ReadBytes(Input, 31 * sizeof(*StrToFat_Arg_1), (VOID *)StrToFat_Arg_1);
                StrToFat_Arg_1[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(StrToFat_Arg_2), (VOID *)&StrToFat_Arg_2);
    StrToFat_Arg_2 = StrToFat_Arg_2 % ((32 * sizeof(CHAR8)) + 1);
    
    /*
        Output Variable(s)
    */
    CHAR8 * StrToFat_Arg_3 = (CHAR8 *)AllocateZeroPool(32 * sizeof(CHAR8));
    UINT8* StrToFat_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*StrToFat_Arg_3_OutputChoice), (VOID *)StrToFat_Arg_3_OutputChoice);
    if(*StrToFat_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*StrToFat_Arg_3), (VOID *)StrToFat_Arg_3);
    }
    FirnessUntrusted(StrToFat_Arg_1, 32 * sizeof(CHAR16));
    FirnessSanitizer(TRUE);
    ProtocolVariable->StrToFat(
        ProtocolVariable,
        StrToFat_Arg_1,
        StrToFat_Arg_2,
        StrToFat_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_CHAR8___Count < 4 && StrToFat_Arg_3 != NULL) {
        FirnessLive_CHAR8__[FirnessLive_CHAR8___Count++] = StrToFat_Arg_3;
    }
    return Status;
}

