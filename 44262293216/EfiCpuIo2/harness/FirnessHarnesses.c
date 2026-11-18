#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called Read.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRead(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CPU_IO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCpuIo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_CPU_IO_PROTOCOL_WIDTH Read_Arg_1 = {0};
    UINTN Read_Arg_2 = {0};
    UINTN Read_Arg_3 = {0};
    UINTN*  Read_Arg_4 = (UINTN* )AllocateZeroPool(4096);
    
    // Constant Variable Initialization
    UINT8* Read_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Read_Arg_1_choice), (VOID *)Read_Arg_1_choice);
    switch(*Read_Arg_1_choice % 14) {
        case 0:
            Read_Arg_1 = EfiCpuIoWidthFifoUint16;
            break;
        case 1:
            Read_Arg_1 = EfiCpuIoWidthFifoUint32;
            break;
        case 2:
            Read_Arg_1 = EfiCpuIoWidthFifoUint64;
            break;
        case 3:
            Read_Arg_1 = EfiCpuIoWidthFifoUint8;
            break;
        case 4:
            Read_Arg_1 = EfiCpuIoWidthFillUint16;
            break;
        case 5:
            Read_Arg_1 = EfiCpuIoWidthFillUint32;
            break;
        case 6:
            Read_Arg_1 = EfiCpuIoWidthFillUint64;
            break;
        case 7:
            Read_Arg_1 = EfiCpuIoWidthFillUint8;
            break;
        case 8:
            Read_Arg_1 = EfiCpuIoWidthMaximum;
            break;
        case 9:
            Read_Arg_1 = EfiCpuIoWidthUint16;
            break;
        case 10:
            Read_Arg_1 = EfiCpuIoWidthUint32;
            break;
        case 11:
            Read_Arg_1 = EfiCpuIoWidthUint64;
            break;
        case 12:
            Read_Arg_1 = EfiCpuIoWidthUint8;
            break;
        case 13:
            ReadBytes(Input, sizeof(Read_Arg_1), (VOID *)&Read_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Read_Arg_2), (VOID *)&Read_Arg_2);
    // Address is a bus address, not an offset into this call's buffer: left unbounded
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Read_Arg_3), (VOID *)&Read_Arg_3);
    Read_Arg_3 = Read_Arg_3 % ((4096 / (1 << (Read_Arg_1 & 0x03))) + 1);
    
    // Fuzzable Variable Initialization
    UINT8 Read_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(Read_Arg_4_choice), (VOID *)&Read_Arg_4_choice);
    switch(Read_Arg_4_choice % 1) {
        case 0:
            if (Read_Arg_4 != NULL) {
                ReadBytes(Input, sizeof(*Read_Arg_4), (VOID *)Read_Arg_4);
            }
            break;
    }
    
    EFI_CPU_IO_PROTOCOL_IO_MEM Read_Member = ProtocolVariable->Mem.Read;
    UINT8 Read_MemberChoice = 0;
    ReadBytes(Input, sizeof(Read_MemberChoice), (VOID *)&Read_MemberChoice);
    switch(Read_MemberChoice % 2) {
        case 0: Read_Member = ProtocolVariable->Mem.Read; break;
        case 1: Read_Member = ProtocolVariable->Io.Read; break;
    }
    FirnessUntrusted(Read_Arg_4, 4096);
    FirnessSanitizer(TRUE);
    Status = Read_Member(
        ProtocolVariable,
        Read_Arg_1,
        Read_Arg_2,
        Read_Arg_3,
        (void *)Read_Arg_4
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Write.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzWrite(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_CPU_IO2_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiCpuIo2ProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_CPU_IO_PROTOCOL_WIDTH Write_Arg_1 = {0};
    UINTN Write_Arg_2 = {0};
    UINTN Write_Arg_3 = {0};
    UINTN*  Write_Arg_4 = (UINTN* )AllocateZeroPool(4096);
    
    // Constant Variable Initialization
    UINT8* Write_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Write_Arg_1_choice), (VOID *)Write_Arg_1_choice);
    switch(*Write_Arg_1_choice % 14) {
        case 0:
            Write_Arg_1 = EfiCpuIoWidthFifoUint16;
            break;
        case 1:
            Write_Arg_1 = EfiCpuIoWidthFifoUint32;
            break;
        case 2:
            Write_Arg_1 = EfiCpuIoWidthFifoUint64;
            break;
        case 3:
            Write_Arg_1 = EfiCpuIoWidthFifoUint8;
            break;
        case 4:
            Write_Arg_1 = EfiCpuIoWidthFillUint16;
            break;
        case 5:
            Write_Arg_1 = EfiCpuIoWidthFillUint32;
            break;
        case 6:
            Write_Arg_1 = EfiCpuIoWidthFillUint64;
            break;
        case 7:
            Write_Arg_1 = EfiCpuIoWidthFillUint8;
            break;
        case 8:
            Write_Arg_1 = EfiCpuIoWidthMaximum;
            break;
        case 9:
            Write_Arg_1 = EfiCpuIoWidthUint16;
            break;
        case 10:
            Write_Arg_1 = EfiCpuIoWidthUint32;
            break;
        case 11:
            Write_Arg_1 = EfiCpuIoWidthUint64;
            break;
        case 12:
            Write_Arg_1 = EfiCpuIoWidthUint8;
            break;
        case 13:
            ReadBytes(Input, sizeof(Write_Arg_1), (VOID *)&Write_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Write_Arg_2), (VOID *)&Write_Arg_2);
    // Address is a bus address, not an offset into this call's buffer: left unbounded
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Write_Arg_3), (VOID *)&Write_Arg_3);
    Write_Arg_3 = Write_Arg_3 % ((4096 / (1 << (Write_Arg_1 & 0x03))) + 1);
    
    // Fuzzable Variable Initialization
    UINT8 Write_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(Write_Arg_4_choice), (VOID *)&Write_Arg_4_choice);
    switch(Write_Arg_4_choice % 1) {
        case 0:
            if (Write_Arg_4 != NULL) {
                ReadBytes(Input, sizeof(*Write_Arg_4), (VOID *)Write_Arg_4);
            }
            break;
    }
    
    EFI_CPU_IO_PROTOCOL_IO_MEM Write_Member = ProtocolVariable->Mem.Write;
    UINT8 Write_MemberChoice = 0;
    ReadBytes(Input, sizeof(Write_MemberChoice), (VOID *)&Write_MemberChoice);
    switch(Write_MemberChoice % 2) {
        case 0: Write_Member = ProtocolVariable->Mem.Write; break;
        case 1: Write_Member = ProtocolVariable->Io.Write; break;
    }
    FirnessUntrusted(Write_Arg_4, 4096);
    FirnessSanitizer(TRUE);
    Status = Write_Member(
        ProtocolVariable,
        Write_Arg_1,
        Write_Arg_2,
        Write_Arg_3,
        (void *)Write_Arg_4
    );
    FirnessSanitizer(FALSE);
    return Status;
}

