#include "FirnessHarnesses.h"

//
// Objects produced by one call in a sequence, available to later ones.
// Reset every iteration, because the fuzzer restores the machine.
//
CHAR16 * FirnessLive_CHAR16__[4];
UINTN FirnessLive_CHAR16___Count = 0;
INT8 * FirnessLive_INT8__[4];
UINTN FirnessLive_INT8___Count = 0;
UINTN * FirnessLive_UINTN__[4];
UINTN FirnessLive_UINTN___Count = 0;

/*
    This is a harness for fuzzing the protocol service
    called Execute.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzExecute(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_VM_TEST_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcVmTestProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN * Execute_Arg_2 = (UINTN *)AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    UINT8 Execute_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Execute_Arg_2_choice), (VOID *)&Execute_Arg_2_choice);
    switch(Execute_Arg_2_choice % 1) {
        case 0:
            if (Execute_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*Execute_Arg_2), (VOID *)Execute_Arg_2);
                // nothing in this call names the stride of InstructionCount: bounded by the widest stride a UEFI accessor steps by, 8 bytes
                *Execute_Arg_2 = *Execute_Arg_2 % ((4096 / 8) + 1);
            }
            break;
    }
    
    VOID *Execute_Arg_1 = AllocateZeroPool(4096);
    FirnessUntrusted(Execute_Arg_2, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Execute(
        ProtocolVariable,
        Execute_Arg_1,
        Execute_Arg_2
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_UINTN___Count < 4 && Execute_Arg_2 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = Execute_Arg_2;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Assemble.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAssemble(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_VM_TEST_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcVmTestProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * Assemble_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    INT8 * Assemble_Arg_2 = (INT8 *)AllocateZeroPool(sizeof(INT8));
    UINTN * Assemble_Arg_3 = (UINTN *)AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    UINT8 Assemble_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Assemble_Arg_1_choice), (VOID *)&Assemble_Arg_1_choice);
    switch(Assemble_Arg_1_choice % 1) {
        case 0:
            if (Assemble_Arg_1 != NULL) {
                ReadBytes(Input, 31 * sizeof(*Assemble_Arg_1), (VOID *)Assemble_Arg_1);
                Assemble_Arg_1[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 Assemble_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Assemble_Arg_2_choice), (VOID *)&Assemble_Arg_2_choice);
    switch(Assemble_Arg_2_choice % 1) {
        case 0:
            if (Assemble_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*Assemble_Arg_2), (VOID *)Assemble_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 Assemble_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Assemble_Arg_3_choice), (VOID *)&Assemble_Arg_3_choice);
    switch(Assemble_Arg_3_choice % 1) {
        case 0:
            if (Assemble_Arg_3 != NULL) {
                ReadBytes(Input, sizeof(*Assemble_Arg_3), (VOID *)Assemble_Arg_3);
                *Assemble_Arg_3 = *Assemble_Arg_3 % (sizeof(INT8) + 1);
            }
            break;
    }
    
    FirnessUntrusted(Assemble_Arg_1, 32 * sizeof(CHAR16));
    FirnessUntrusted(Assemble_Arg_2, sizeof(INT8));
    FirnessUntrusted(Assemble_Arg_3, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Assemble(
        ProtocolVariable,
        Assemble_Arg_1,
        Assemble_Arg_2,
        Assemble_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_INT8___Count < 4 && Assemble_Arg_2 != NULL) {
        FirnessLive_INT8__[FirnessLive_INT8___Count++] = Assemble_Arg_2;
    }
    if (FirnessLive_UINTN___Count < 4 && Assemble_Arg_3 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = Assemble_Arg_3;
    }
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Disassemble.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzDisassemble(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_EBC_VM_TEST_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiEbcVmTestProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    CHAR16 * Disassemble_Arg_1 = (CHAR16 *)AllocateZeroPool(32 * sizeof(CHAR16));
    INT8 * Disassemble_Arg_2 = (INT8 *)AllocateZeroPool(sizeof(INT8));
    UINTN * Disassemble_Arg_3 = (UINTN *)AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    UINT8 Disassemble_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Disassemble_Arg_1_choice), (VOID *)&Disassemble_Arg_1_choice);
    switch(Disassemble_Arg_1_choice % 1) {
        case 0:
            if (Disassemble_Arg_1 != NULL) {
                ReadBytes(Input, 31 * sizeof(*Disassemble_Arg_1), (VOID *)Disassemble_Arg_1);
                Disassemble_Arg_1[31] = 0;
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 Disassemble_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Disassemble_Arg_2_choice), (VOID *)&Disassemble_Arg_2_choice);
    switch(Disassemble_Arg_2_choice % 1) {
        case 0:
            if (Disassemble_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*Disassemble_Arg_2), (VOID *)Disassemble_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 Disassemble_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Disassemble_Arg_3_choice), (VOID *)&Disassemble_Arg_3_choice);
    switch(Disassemble_Arg_3_choice % 1) {
        case 0:
            if (Disassemble_Arg_3 != NULL) {
                ReadBytes(Input, sizeof(*Disassemble_Arg_3), (VOID *)Disassemble_Arg_3);
                *Disassemble_Arg_3 = *Disassemble_Arg_3 % (4096 + 1);
            }
            break;
    }
    
    FirnessUntrusted(Disassemble_Arg_1, 32 * sizeof(CHAR16));
    FirnessUntrusted(Disassemble_Arg_2, sizeof(INT8));
    FirnessUntrusted(Disassemble_Arg_3, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Disassemble(
        ProtocolVariable,
        Disassemble_Arg_1,
        Disassemble_Arg_2,
        Disassemble_Arg_3
    );
    FirnessSanitizer(FALSE);
    if (FirnessLive_CHAR16___Count < 4 && Disassemble_Arg_1 != NULL) {
        FirnessLive_CHAR16__[FirnessLive_CHAR16___Count++] = Disassemble_Arg_1;
    }
    if (FirnessLive_INT8___Count < 4 && Disassemble_Arg_2 != NULL) {
        FirnessLive_INT8__[FirnessLive_INT8___Count++] = Disassemble_Arg_2;
    }
    if (FirnessLive_UINTN___Count < 4 && Disassemble_Arg_3 != NULL) {
        FirnessLive_UINTN__[FirnessLive_UINTN___Count++] = Disassemble_Arg_3;
    }
    return Status;
}

