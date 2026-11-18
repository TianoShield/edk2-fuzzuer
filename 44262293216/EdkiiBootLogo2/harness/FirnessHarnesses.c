#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
EFI_GRAPHICS_OUTPUT_BLT_PIXEL * FirnessLive_EFI_GRAPHICS_OUTPUT_BLT_PIXEL__[4];
UINTN FirnessLive_EFI_GRAPHICS_OUTPUT_BLT_PIXEL___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called SetBootLogo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetBootLogo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_BOOT_LOGO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiBootLogo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL * SetBootLogo_Arg_1 = (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)AllocateZeroPool((4096 > 1024 * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL) ? 4096 : 1024 * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL)));
    UINTN SetBootLogo_Arg_2 = {0};
    UINTN SetBootLogo_Arg_3 = {0};
    UINTN SetBootLogo_Arg_4 = {0};
    UINTN SetBootLogo_Arg_5 = {0};
    
    // Generator Struct Variable Initialization
    {
        UINT8 Firness_Blue;
        ReadBytes(Input, sizeof(Firness_Blue), (VOID *)&Firness_Blue);
        SetBootLogo_Arg_1->Blue = Firness_Blue;
    }
    {
        UINT8 Firness_Green;
        ReadBytes(Input, sizeof(Firness_Green), (VOID *)&Firness_Green);
        SetBootLogo_Arg_1->Green = Firness_Green;
    }
    {
        UINT8 Firness_Red;
        ReadBytes(Input, sizeof(Firness_Red), (VOID *)&Firness_Red);
        SetBootLogo_Arg_1->Red = Firness_Red;
    }
    {
        UINT8 Firness_Reserved;
        ReadBytes(Input, sizeof(Firness_Reserved), (VOID *)&Firness_Reserved);
        SetBootLogo_Arg_1->Reserved = Firness_Reserved;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetBootLogo_Arg_2), (VOID *)&SetBootLogo_Arg_2);
    SetBootLogo_Arg_2 = SetBootLogo_Arg_2 % (16 + 1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetBootLogo_Arg_3), (VOID *)&SetBootLogo_Arg_3);
    SetBootLogo_Arg_3 = SetBootLogo_Arg_3 % (16 + 1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetBootLogo_Arg_4), (VOID *)&SetBootLogo_Arg_4);
    SetBootLogo_Arg_4 = SetBootLogo_Arg_4 % (16 + 1);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetBootLogo_Arg_5), (VOID *)&SetBootLogo_Arg_5);
    SetBootLogo_Arg_5 = SetBootLogo_Arg_5 % (16 + 1);
    
    UINT8 SetBootLogo_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(SetBootLogo_Arg_1_LiveChoice), (VOID *)&SetBootLogo_Arg_1_LiveChoice);
    if (FirnessLive_EFI_GRAPHICS_OUTPUT_BLT_PIXEL___Count > 0 && (SetBootLogo_Arg_1_LiveChoice & 1)) {
        SetBootLogo_Arg_1 = FirnessLive_EFI_GRAPHICS_OUTPUT_BLT_PIXEL__[SetBootLogo_Arg_1_LiveChoice % FirnessLive_EFI_GRAPHICS_OUTPUT_BLT_PIXEL___Count];
    }
    FirnessUntrusted(SetBootLogo_Arg_1, (4096 > 1024 * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL) ? 4096 : 1024 * sizeof(EFI_GRAPHICS_OUTPUT_BLT_PIXEL)));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetBootLogo(
        ProtocolVariable,
        SetBootLogo_Arg_1,
        SetBootLogo_Arg_2,
        SetBootLogo_Arg_3,
        SetBootLogo_Arg_4,
        SetBootLogo_Arg_5
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetBootLogo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetBootLogo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_BOOT_LOGO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiBootLogo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Output Variable(s)
    */
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL * GetBootLogo_Arg_1 = NULL;
    UINT8* GetBootLogo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetBootLogo_Arg_1_OutputChoice), (VOID *)GetBootLogo_Arg_1_OutputChoice);
    if(*GetBootLogo_Arg_1_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetBootLogo_Arg_1), (VOID *)GetBootLogo_Arg_1);
    }
    UINTN * GetBootLogo_Arg_2 = (UINTN *)AllocateZeroPool(4096);
    UINT8* GetBootLogo_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetBootLogo_Arg_2_OutputChoice), (VOID *)GetBootLogo_Arg_2_OutputChoice);
    if(*GetBootLogo_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetBootLogo_Arg_2), (VOID *)GetBootLogo_Arg_2);
        *GetBootLogo_Arg_2 = *GetBootLogo_Arg_2 % (16 + 1);
    }
    UINTN * GetBootLogo_Arg_3 = (UINTN *)AllocateZeroPool(4096);
    UINT8* GetBootLogo_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetBootLogo_Arg_3_OutputChoice), (VOID *)GetBootLogo_Arg_3_OutputChoice);
    if(*GetBootLogo_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetBootLogo_Arg_3), (VOID *)GetBootLogo_Arg_3);
        *GetBootLogo_Arg_3 = *GetBootLogo_Arg_3 % (16 + 1);
    }
    UINTN * GetBootLogo_Arg_4 = (UINTN *)AllocateZeroPool(4096);
    UINT8* GetBootLogo_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetBootLogo_Arg_4_OutputChoice), (VOID *)GetBootLogo_Arg_4_OutputChoice);
    if(*GetBootLogo_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetBootLogo_Arg_4), (VOID *)GetBootLogo_Arg_4);
        *GetBootLogo_Arg_4 = *GetBootLogo_Arg_4 % (16 + 1);
    }
    UINTN * GetBootLogo_Arg_5 = (UINTN *)AllocateZeroPool(4096);
    UINT8* GetBootLogo_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetBootLogo_Arg_5_OutputChoice), (VOID *)GetBootLogo_Arg_5_OutputChoice);
    if(*GetBootLogo_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetBootLogo_Arg_5), (VOID *)GetBootLogo_Arg_5);
        *GetBootLogo_Arg_5 = *GetBootLogo_Arg_5 % (16 + 1);
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetBootLogo(
        ProtocolVariable,
        (EFI_GRAPHICS_OUTPUT_BLT_PIXEL **)&GetBootLogo_Arg_1,
        GetBootLogo_Arg_2,
        GetBootLogo_Arg_3,
        GetBootLogo_Arg_4,
        GetBootLogo_Arg_5
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_EFI_GRAPHICS_OUTPUT_BLT_PIXEL___Count < 4 && GetBootLogo_Arg_1 != NULL) {
        FirnessLive_EFI_GRAPHICS_OUTPUT_BLT_PIXEL__[FirnessLive_EFI_GRAPHICS_OUTPUT_BLT_PIXEL___Count++] = GetBootLogo_Arg_1;
    }
    return Status;
}

