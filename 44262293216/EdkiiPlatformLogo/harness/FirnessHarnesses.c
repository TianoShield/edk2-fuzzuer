#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
UINT32 * FirnessLive_UINT32__[4];
UINTN FirnessLive_UINT32___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called GetImage.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetImage(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EDKII_PLATFORM_LOGO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEdkiiPlatformLogoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT32 * GetImage_Arg_1 = (UINT32 *)AllocateZeroPool(sizeof(UINT32));
    
    // Fuzzable Variable Initialization
    UINT8 GetImage_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetImage_Arg_1_choice), (VOID *)&GetImage_Arg_1_choice);
    switch(GetImage_Arg_1_choice % 1) {
        case 0:
            if (GetImage_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*GetImage_Arg_1), (VOID *)GetImage_Arg_1);
            }
            break;
    }
    
    /*
        Output Variable(s)
    */
    EFI_IMAGE_INPUT * GetImage_Arg_2 = (EFI_IMAGE_INPUT *)AllocateZeroPool(sizeof(EFI_IMAGE_INPUT));
    UINT8* GetImage_Arg_2_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetImage_Arg_2_OutputChoice), (VOID *)GetImage_Arg_2_OutputChoice);
    if(*GetImage_Arg_2_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImage_Arg_2), (VOID *)GetImage_Arg_2);
    }
    EDKII_PLATFORM_LOGO_DISPLAY_ATTRIBUTE * GetImage_Arg_3 = (EDKII_PLATFORM_LOGO_DISPLAY_ATTRIBUTE *)AllocateZeroPool(sizeof(EDKII_PLATFORM_LOGO_DISPLAY_ATTRIBUTE));
    UINT8* GetImage_Arg_3_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetImage_Arg_3_OutputChoice), (VOID *)GetImage_Arg_3_OutputChoice);
    if(*GetImage_Arg_3_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImage_Arg_3), (VOID *)GetImage_Arg_3);
    }
    INTN * GetImage_Arg_4 = (INTN *)AllocateZeroPool(sizeof(INTN));
    UINT8* GetImage_Arg_4_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetImage_Arg_4_OutputChoice), (VOID *)GetImage_Arg_4_OutputChoice);
    if(*GetImage_Arg_4_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImage_Arg_4), (VOID *)GetImage_Arg_4);
    }
    INTN * GetImage_Arg_5 = (INTN *)AllocateZeroPool(sizeof(INTN));
    UINT8* GetImage_Arg_5_OutputChoice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*GetImage_Arg_5_OutputChoice), (VOID *)GetImage_Arg_5_OutputChoice);
    if(*GetImage_Arg_5_OutputChoice % 2)
    {
        ReadBytes(Input, sizeof(*GetImage_Arg_5), (VOID *)GetImage_Arg_5);
    }
    UINT8 GetImage_Arg_1_LiveChoice = 0;
    ReadBytes(Input, sizeof(GetImage_Arg_1_LiveChoice), (VOID *)&GetImage_Arg_1_LiveChoice);
    if (FirnessLive_UINT32___Count > 0 && (GetImage_Arg_1_LiveChoice & 1)) {
        GetImage_Arg_1 = FirnessLive_UINT32__[GetImage_Arg_1_LiveChoice % FirnessLive_UINT32___Count];
    }
    FirnessUntrusted(GetImage_Arg_1, sizeof(UINT32));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetImage(
        ProtocolVariable,
        GetImage_Arg_1,
        GetImage_Arg_2,
        GetImage_Arg_3,
        GetImage_Arg_4,
        GetImage_Arg_5
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINT32___Count < 4 && GetImage_Arg_1 != NULL) {
        FirnessLive_UINT32__[FirnessLive_UINT32___Count++] = GetImage_Arg_1;
    }
    return Status;
}

