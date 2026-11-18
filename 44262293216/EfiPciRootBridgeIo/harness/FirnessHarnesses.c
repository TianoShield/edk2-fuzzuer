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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH Read_Arg_1 = {0};
    UINT64 Read_Arg_2 = {0};
    UINTN Read_Arg_3 = {0};
    UINTN*  Read_Arg_4 = (UINTN* )AllocateZeroPool(4096);
    
    // Constant Variable Initialization
    UINT8* Read_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Read_Arg_1_choice), (VOID *)Read_Arg_1_choice);
    switch(*Read_Arg_1_choice % 14) {
        case 0:
            Read_Arg_1 = EfiPciWidthFifoUint16;
            break;
        case 1:
            Read_Arg_1 = EfiPciWidthFifoUint32;
            break;
        case 2:
            Read_Arg_1 = EfiPciWidthFifoUint64;
            break;
        case 3:
            Read_Arg_1 = EfiPciWidthFifoUint8;
            break;
        case 4:
            Read_Arg_1 = EfiPciWidthFillUint16;
            break;
        case 5:
            Read_Arg_1 = EfiPciWidthFillUint32;
            break;
        case 6:
            Read_Arg_1 = EfiPciWidthFillUint64;
            break;
        case 7:
            Read_Arg_1 = EfiPciWidthFillUint8;
            break;
        case 8:
            Read_Arg_1 = EfiPciWidthMaximum;
            break;
        case 9:
            Read_Arg_1 = EfiPciWidthUint16;
            break;
        case 10:
            Read_Arg_1 = EfiPciWidthUint32;
            break;
        case 11:
            Read_Arg_1 = EfiPciWidthUint64;
            break;
        case 12:
            Read_Arg_1 = EfiPciWidthUint8;
            break;
        case 13:
            ReadBytes(Input, sizeof(Read_Arg_1), (VOID *)&Read_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(Read_Arg_2), (VOID *)&Read_Arg_2);
    // Address is a bus address, not an offset into this call's buffer: left unbounded
    
    UINT8* Read_Arg_3_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Read_Arg_3_choice), (VOID *)Read_Arg_3_choice);
    switch(*Read_Arg_3_choice % 8) {
        case 0:
        {
        // Constant Variable Initialization
        Read_Arg_3 = _PCD_VALUE_PcdUse1GPageTable;
    
            break;
        }
        case 1:
        {
        // Constant Variable Initialization
        Read_Arg_3 = 0;
    
            break;
        }
        case 2:
        {
        // Constant Variable Initialization
        Read_Arg_3 = 0;
    
            break;
        }
        case 3:
        {
        // Constant Variable Initialization
        Read_Arg_3 = 0;
    
            break;
        }
        case 4:
        {
        // Constant Variable Initialization
        Read_Arg_3 = kMatchMinLen;
    
            break;
        }
        case 5:
        {
        // Constant Variable Initialization
        Read_Arg_3 = sizeof (PCI_TYPE00) / sizeof (UINT32);
    
            break;
        }
        case 6:
        {
        // Constant Variable Initialization
        Read_Arg_3 = 0;
    
            break;
        }
        case 7:
        {
        // Fuzzable Variable Initialization
        ReadBytes(Input, sizeof(Read_Arg_3), (VOID *)&Read_Arg_3);
        Read_Arg_3 = Read_Arg_3 % ((4096 / (1 << (Read_Arg_1 & 0x03))) + 1);
    
            break;
        }
    }
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
    
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_IO_MEM Read_Member = ProtocolVariable->Mem.Read;
    UINT8 Read_MemberChoice = 0;
    ReadBytes(Input, sizeof(Read_MemberChoice), (VOID *)&Read_MemberChoice);
    switch(Read_MemberChoice % 3) {
        case 0: Read_Member = ProtocolVariable->Mem.Read; break;
        case 1: Read_Member = ProtocolVariable->Io.Read; break;
        case 2: Read_Member = ProtocolVariable->Pci.Read; break;
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
    called Configuration.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzConfiguration(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN* Configuration_Arg_1 = (UINTN*)AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    UINT8 Configuration_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Configuration_Arg_1_choice), (VOID *)&Configuration_Arg_1_choice);
    switch(Configuration_Arg_1_choice % 1) {
        case 0:
            if (Configuration_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*Configuration_Arg_1), (VOID *)Configuration_Arg_1);
            }
            break;
    }
    
    FirnessUntrusted(Configuration_Arg_1, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Configuration(
        ProtocolVariable,
        (void **)&Configuration_Arg_1
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
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH Write_Arg_1 = {0};
    UINT64 Write_Arg_2 = {0};
    UINTN Write_Arg_3 = {0};
    UINTN*  Write_Arg_4 = (UINTN* )AllocateZeroPool(4096);
    
    // Constant Variable Initialization
    UINT8* Write_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Write_Arg_1_choice), (VOID *)Write_Arg_1_choice);
    switch(*Write_Arg_1_choice % 14) {
        case 0:
            Write_Arg_1 = EfiPciWidthFifoUint16;
            break;
        case 1:
            Write_Arg_1 = EfiPciWidthFifoUint32;
            break;
        case 2:
            Write_Arg_1 = EfiPciWidthFifoUint64;
            break;
        case 3:
            Write_Arg_1 = EfiPciWidthFifoUint8;
            break;
        case 4:
            Write_Arg_1 = EfiPciWidthFillUint16;
            break;
        case 5:
            Write_Arg_1 = EfiPciWidthFillUint32;
            break;
        case 6:
            Write_Arg_1 = EfiPciWidthFillUint64;
            break;
        case 7:
            Write_Arg_1 = EfiPciWidthFillUint8;
            break;
        case 8:
            Write_Arg_1 = EfiPciWidthMaximum;
            break;
        case 9:
            Write_Arg_1 = EfiPciWidthUint16;
            break;
        case 10:
            Write_Arg_1 = EfiPciWidthUint32;
            break;
        case 11:
            Write_Arg_1 = EfiPciWidthUint64;
            break;
        case 12:
            Write_Arg_1 = EfiPciWidthUint8;
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
    
    UINT8* Write_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Write_Arg_4_choice), (VOID *)Write_Arg_4_choice);
    switch(*Write_Arg_4_choice % 5) {
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
        UINT8 Write_Arg_4_choice = 0;
        ReadBytes(Input, sizeof(Write_Arg_4_choice), (VOID *)&Write_Arg_4_choice);
        switch(Write_Arg_4_choice % 1) {
            case 0:
                if (Write_Arg_4 != NULL) {
                    ReadBytes(Input, sizeof(*Write_Arg_4), (VOID *)Write_Arg_4);
                }
                break;
        }
    
            break;
        }
    }
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_IO_MEM Write_Member = ProtocolVariable->Mem.Write;
    UINT8 Write_MemberChoice = 0;
    ReadBytes(Input, sizeof(Write_MemberChoice), (VOID *)&Write_MemberChoice);
    switch(Write_MemberChoice % 3) {
        case 0: Write_Member = ProtocolVariable->Mem.Write; break;
        case 1: Write_Member = ProtocolVariable->Io.Write; break;
        case 2: Write_Member = ProtocolVariable->Pci.Write; break;
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

/*
    This is a harness for fuzzing the protocol service
    called PollMem.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPollMem(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH PollMem_Arg_1 = {0};
    UINT64 PollMem_Arg_2 = {0};
    UINT64 PollMem_Arg_3 = {0};
    UINT64 PollMem_Arg_4 = {0};
    UINT64 PollMem_Arg_5 = {0};
    UINT64 * PollMem_Arg_6 = (UINT64 *)AllocateZeroPool((4096 > 256 * sizeof(UINT64) ? 4096 : 256 * sizeof(UINT64)));
    
    // Constant Variable Initialization
    UINT8* PollMem_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*PollMem_Arg_1_choice), (VOID *)PollMem_Arg_1_choice);
    switch(*PollMem_Arg_1_choice % 14) {
        case 0:
            PollMem_Arg_1 = EfiPciWidthFifoUint16;
            break;
        case 1:
            PollMem_Arg_1 = EfiPciWidthFifoUint32;
            break;
        case 2:
            PollMem_Arg_1 = EfiPciWidthFifoUint64;
            break;
        case 3:
            PollMem_Arg_1 = EfiPciWidthFifoUint8;
            break;
        case 4:
            PollMem_Arg_1 = EfiPciWidthFillUint16;
            break;
        case 5:
            PollMem_Arg_1 = EfiPciWidthFillUint32;
            break;
        case 6:
            PollMem_Arg_1 = EfiPciWidthFillUint64;
            break;
        case 7:
            PollMem_Arg_1 = EfiPciWidthFillUint8;
            break;
        case 8:
            PollMem_Arg_1 = EfiPciWidthMaximum;
            break;
        case 9:
            PollMem_Arg_1 = EfiPciWidthUint16;
            break;
        case 10:
            PollMem_Arg_1 = EfiPciWidthUint32;
            break;
        case 11:
            PollMem_Arg_1 = EfiPciWidthUint64;
            break;
        case 12:
            PollMem_Arg_1 = EfiPciWidthUint8;
            break;
        case 13:
            ReadBytes(Input, sizeof(PollMem_Arg_1), (VOID *)&PollMem_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_2), (VOID *)&PollMem_Arg_2);
    // Address is a bus address, not an offset into this call's buffer: left unbounded
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_3), (VOID *)&PollMem_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_4), (VOID *)&PollMem_Arg_4);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollMem_Arg_5), (VOID *)&PollMem_Arg_5);
    
    // Fuzzable Variable Initialization
    UINT8 PollMem_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(PollMem_Arg_6_choice), (VOID *)&PollMem_Arg_6_choice);
    switch(PollMem_Arg_6_choice % 1) {
        case 0:
            if (PollMem_Arg_6 != NULL) {
                ReadBytes(Input, sizeof(*PollMem_Arg_6), (VOID *)PollMem_Arg_6);
            }
            break;
    }
    
    FirnessUntrusted(PollMem_Arg_6, (4096 > 256 * sizeof(UINT64) ? 4096 : 256 * sizeof(UINT64)));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->PollMem(
        ProtocolVariable,
        PollMem_Arg_1,
        PollMem_Arg_2,
        PollMem_Arg_3,
        PollMem_Arg_4,
        PollMem_Arg_5,
        PollMem_Arg_6
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called PollIo.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzPollIo(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH PollIo_Arg_1 = {0};
    UINT64 PollIo_Arg_2 = {0};
    UINT64 PollIo_Arg_3 = {0};
    UINT64 PollIo_Arg_4 = {0};
    UINT64 PollIo_Arg_5 = {0};
    UINT64 * PollIo_Arg_6 = (UINT64 *)AllocateZeroPool((4096 > 256 * sizeof(UINT64) ? 4096 : 256 * sizeof(UINT64)));
    
    // Constant Variable Initialization
    UINT8* PollIo_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*PollIo_Arg_1_choice), (VOID *)PollIo_Arg_1_choice);
    switch(*PollIo_Arg_1_choice % 14) {
        case 0:
            PollIo_Arg_1 = EfiPciWidthFifoUint16;
            break;
        case 1:
            PollIo_Arg_1 = EfiPciWidthFifoUint32;
            break;
        case 2:
            PollIo_Arg_1 = EfiPciWidthFifoUint64;
            break;
        case 3:
            PollIo_Arg_1 = EfiPciWidthFifoUint8;
            break;
        case 4:
            PollIo_Arg_1 = EfiPciWidthFillUint16;
            break;
        case 5:
            PollIo_Arg_1 = EfiPciWidthFillUint32;
            break;
        case 6:
            PollIo_Arg_1 = EfiPciWidthFillUint64;
            break;
        case 7:
            PollIo_Arg_1 = EfiPciWidthFillUint8;
            break;
        case 8:
            PollIo_Arg_1 = EfiPciWidthMaximum;
            break;
        case 9:
            PollIo_Arg_1 = EfiPciWidthUint16;
            break;
        case 10:
            PollIo_Arg_1 = EfiPciWidthUint32;
            break;
        case 11:
            PollIo_Arg_1 = EfiPciWidthUint64;
            break;
        case 12:
            PollIo_Arg_1 = EfiPciWidthUint8;
            break;
        case 13:
            ReadBytes(Input, sizeof(PollIo_Arg_1), (VOID *)&PollIo_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_2), (VOID *)&PollIo_Arg_2);
    // Address is a bus address, not an offset into this call's buffer: left unbounded
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_3), (VOID *)&PollIo_Arg_3);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_4), (VOID *)&PollIo_Arg_4);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(PollIo_Arg_5), (VOID *)&PollIo_Arg_5);
    
    // Fuzzable Variable Initialization
    UINT8 PollIo_Arg_6_choice = 0;
    ReadBytes(Input, sizeof(PollIo_Arg_6_choice), (VOID *)&PollIo_Arg_6_choice);
    switch(PollIo_Arg_6_choice % 1) {
        case 0:
            if (PollIo_Arg_6 != NULL) {
                ReadBytes(Input, sizeof(*PollIo_Arg_6), (VOID *)PollIo_Arg_6);
            }
            break;
    }
    
    FirnessUntrusted(PollIo_Arg_6, (4096 > 256 * sizeof(UINT64) ? 4096 : 256 * sizeof(UINT64)));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->PollIo(
        ProtocolVariable,
        PollIo_Arg_1,
        PollIo_Arg_2,
        PollIo_Arg_3,
        PollIo_Arg_4,
        PollIo_Arg_5,
        PollIo_Arg_6
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called CopyMem.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzCopyMem(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_WIDTH CopyMem_Arg_1 = {0};
    UINT64 CopyMem_Arg_2 = {0};
    UINT64 CopyMem_Arg_3 = {0};
    UINTN CopyMem_Arg_4 = {0};
    
    // Constant Variable Initialization
    UINT8* CopyMem_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*CopyMem_Arg_1_choice), (VOID *)CopyMem_Arg_1_choice);
    switch(*CopyMem_Arg_1_choice % 14) {
        case 0:
            CopyMem_Arg_1 = EfiPciWidthFifoUint16;
            break;
        case 1:
            CopyMem_Arg_1 = EfiPciWidthFifoUint32;
            break;
        case 2:
            CopyMem_Arg_1 = EfiPciWidthFifoUint64;
            break;
        case 3:
            CopyMem_Arg_1 = EfiPciWidthFifoUint8;
            break;
        case 4:
            CopyMem_Arg_1 = EfiPciWidthFillUint16;
            break;
        case 5:
            CopyMem_Arg_1 = EfiPciWidthFillUint32;
            break;
        case 6:
            CopyMem_Arg_1 = EfiPciWidthFillUint64;
            break;
        case 7:
            CopyMem_Arg_1 = EfiPciWidthFillUint8;
            break;
        case 8:
            CopyMem_Arg_1 = EfiPciWidthMaximum;
            break;
        case 9:
            CopyMem_Arg_1 = EfiPciWidthUint16;
            break;
        case 10:
            CopyMem_Arg_1 = EfiPciWidthUint32;
            break;
        case 11:
            CopyMem_Arg_1 = EfiPciWidthUint64;
            break;
        case 12:
            CopyMem_Arg_1 = EfiPciWidthUint8;
            break;
        case 13:
            ReadBytes(Input, sizeof(CopyMem_Arg_1), (VOID *)&CopyMem_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CopyMem_Arg_2), (VOID *)&CopyMem_Arg_2);
    // DestAddress is a bus address, not an offset into this call's buffer: left unbounded
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CopyMem_Arg_3), (VOID *)&CopyMem_Arg_3);
    // SrcAddress is a bus address, not an offset into this call's buffer: left unbounded
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(CopyMem_Arg_4), (VOID *)&CopyMem_Arg_4);
    
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->CopyMem(
        ProtocolVariable,
        CopyMem_Arg_1,
        CopyMem_Arg_2,
        CopyMem_Arg_3,
        CopyMem_Arg_4
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Map.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzMap(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_OPERATION Map_Arg_1 = {0};
    UINTN*  Map_Arg_2 = (UINTN* )AllocateZeroPool(4096);
    UINTN * Map_Arg_3 = (UINTN *)AllocateZeroPool(4096);
    EFI_PHYSICAL_ADDRESS * Map_Arg_4 = (EFI_PHYSICAL_ADDRESS *)AllocateZeroPool(sizeof(EFI_PHYSICAL_ADDRESS));
    UINTN* Map_Arg_5 = (UINTN*)AllocateZeroPool(4096);
    
    // Constant Variable Initialization
    UINT8* Map_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Map_Arg_1_choice), (VOID *)Map_Arg_1_choice);
    switch(*Map_Arg_1_choice % 8) {
        case 0:
            Map_Arg_1 = EfiPciOperationBusMasterCommonBuffer;
            break;
        case 1:
            Map_Arg_1 = EfiPciOperationBusMasterCommonBuffer64;
            break;
        case 2:
            Map_Arg_1 = EfiPciOperationBusMasterRead;
            break;
        case 3:
            Map_Arg_1 = EfiPciOperationBusMasterRead64;
            break;
        case 4:
            Map_Arg_1 = EfiPciOperationBusMasterWrite;
            break;
        case 5:
            Map_Arg_1 = EfiPciOperationBusMasterWrite64;
            break;
        case 6:
            Map_Arg_1 = EfiPciOperationMaximum;
            break;
        case 7:
            ReadBytes(Input, sizeof(Map_Arg_1), (VOID *)&Map_Arg_1);
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 Map_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(Map_Arg_2_choice), (VOID *)&Map_Arg_2_choice);
    switch(Map_Arg_2_choice % 1) {
        case 0:
            if (Map_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*Map_Arg_2), (VOID *)Map_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 Map_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(Map_Arg_3_choice), (VOID *)&Map_Arg_3_choice);
    switch(Map_Arg_3_choice % 1) {
        case 0:
            if (Map_Arg_3 != NULL) {
                ReadBytes(Input, sizeof(*Map_Arg_3), (VOID *)Map_Arg_3);
                *Map_Arg_3 = *Map_Arg_3 % (4096 + 1);
            }
            break;
    }
    
    UINT8* Map_Arg_4_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*Map_Arg_4_choice), (VOID *)Map_Arg_4_choice);
    switch(*Map_Arg_4_choice % 4) {
        case 0:
        {
        // Fuzzable Variable Initialization
        UINT8 Map_Arg_4_choice = 0;
        ReadBytes(Input, sizeof(Map_Arg_4_choice), (VOID *)&Map_Arg_4_choice);
        switch(Map_Arg_4_choice % 1) {
            case 0:
                if (Map_Arg_4 != NULL) {
                    ReadBytes(Input, sizeof(*Map_Arg_4), (VOID *)Map_Arg_4);
                }
                break;
        }
    
            break;
        }
        case 1:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            UINT64 * GetVariableFlashFtwWorkingInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashFtwWorkingInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashFtwWorkingInfo_Arg_1), (VOID *)GetVariableFlashFtwWorkingInfo_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = GetVariableFlashFtwWorkingInfo(
                Map_Arg_4,
                GetVariableFlashFtwWorkingInfo_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 2:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            UINT64 * GetVariableFlashFtwSpareInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashFtwSpareInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashFtwSpareInfo_Arg_1), (VOID *)GetVariableFlashFtwSpareInfo_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = GetVariableFlashFtwSpareInfo(
                Map_Arg_4,
                GetVariableFlashFtwSpareInfo_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
        case 3:
        {
        // Generator Struct Variable Initialization
            /*
                Output Variable(s)
            */
            UINT64 * GetVariableFlashNvStorageInfo_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
            UINT8* GetVariableFlashNvStorageInfo_Arg_1_OutputChoice = AllocateZeroPool(sizeof(UINT8));
            ReadBytes(Input, sizeof(*GetVariableFlashNvStorageInfo_Arg_1_OutputChoice), (VOID *)GetVariableFlashNvStorageInfo_Arg_1_OutputChoice);
            if(*GetVariableFlashNvStorageInfo_Arg_1_OutputChoice % 2)
            {
                ReadBytes(Input, sizeof(*GetVariableFlashNvStorageInfo_Arg_1), (VOID *)GetVariableFlashNvStorageInfo_Arg_1);
            }
            FirnessSanitizer(TRUE);
            Status = GetVariableFlashNvStorageInfo(
                Map_Arg_4,
                GetVariableFlashNvStorageInfo_Arg_1
            );
            FirnessSanitizer(FALSE);
    
            break;
        }
    }
    // Fuzzable Variable Initialization
    UINT8 Map_Arg_5_choice = 0;
    ReadBytes(Input, sizeof(Map_Arg_5_choice), (VOID *)&Map_Arg_5_choice);
    switch(Map_Arg_5_choice % 1) {
        case 0:
            if (Map_Arg_5 != NULL) {
                ReadBytes(Input, sizeof(*Map_Arg_5), (VOID *)Map_Arg_5);
            }
            break;
    }
    
    FirnessUntrusted(Map_Arg_2, 4096);
    FirnessUntrusted(Map_Arg_3, 4096);
    FirnessUntrusted(Map_Arg_4, sizeof(EFI_PHYSICAL_ADDRESS));
    FirnessUntrusted(Map_Arg_5, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Map(
        ProtocolVariable,
        Map_Arg_1,
        (void *)Map_Arg_2,
        Map_Arg_3,
        Map_Arg_4,
        (void **)&Map_Arg_5
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Unmap.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnmap(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN*  Unmap_Arg_1 = (UINTN* )AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    UINT8 Unmap_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(Unmap_Arg_1_choice), (VOID *)&Unmap_Arg_1_choice);
    switch(Unmap_Arg_1_choice % 1) {
        case 0:
            if (Unmap_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*Unmap_Arg_1), (VOID *)Unmap_Arg_1);
            }
            break;
    }
    
    FirnessUntrusted(Unmap_Arg_1, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Unmap(
        ProtocolVariable,
        (void *)Unmap_Arg_1
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called AllocateBuffer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzAllocateBuffer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    EFI_ALLOCATE_TYPE AllocateBuffer_Arg_1 = {0};
    EFI_MEMORY_TYPE AllocateBuffer_Arg_2 = {0};
    UINTN AllocateBuffer_Arg_3 = {0};
    UINTN* AllocateBuffer_Arg_4 = (UINTN*)AllocateZeroPool(4096);
    UINT64 AllocateBuffer_Arg_5 = {0};
    
    // Constant Variable Initialization
    UINT8* AllocateBuffer_Arg_1_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*AllocateBuffer_Arg_1_choice), (VOID *)AllocateBuffer_Arg_1_choice);
    switch(*AllocateBuffer_Arg_1_choice % 5) {
        case 0:
            AllocateBuffer_Arg_1 = AllocateAddress;
            break;
        case 1:
            AllocateBuffer_Arg_1 = AllocateAnyPages;
            break;
        case 2:
            AllocateBuffer_Arg_1 = AllocateMaxAddress;
            break;
        case 3:
            AllocateBuffer_Arg_1 = MaxAllocateType;
            break;
        case 4:
            ReadBytes(Input, sizeof(AllocateBuffer_Arg_1), (VOID *)&AllocateBuffer_Arg_1);
            break;
    }
    
    // Constant Variable Initialization
    UINT8* AllocateBuffer_Arg_2_choice = AllocateZeroPool(sizeof(UINT8));
    ReadBytes(Input, sizeof(*AllocateBuffer_Arg_2_choice), (VOID *)AllocateBuffer_Arg_2_choice);
    switch(*AllocateBuffer_Arg_2_choice % 22) {
        case 0:
            AllocateBuffer_Arg_2 = EfiACPIMemoryNVS;
            break;
        case 1:
            AllocateBuffer_Arg_2 = EfiACPIReclaimMemory;
            break;
        case 2:
            AllocateBuffer_Arg_2 = EfiBootServicesCode;
            break;
        case 3:
            AllocateBuffer_Arg_2 = EfiBootServicesData;
            break;
        case 4:
            AllocateBuffer_Arg_2 = EfiConventionalMemory;
            break;
        case 5:
            AllocateBuffer_Arg_2 = EfiLoaderCode;
            break;
        case 6:
            AllocateBuffer_Arg_2 = EfiLoaderData;
            break;
        case 7:
            AllocateBuffer_Arg_2 = EfiMaxMemoryType;
            break;
        case 8:
            AllocateBuffer_Arg_2 = EfiMemoryMappedIO;
            break;
        case 9:
            AllocateBuffer_Arg_2 = EfiMemoryMappedIOPortSpace;
            break;
        case 10:
            AllocateBuffer_Arg_2 = EfiPalCode;
            break;
        case 11:
            AllocateBuffer_Arg_2 = EfiPersistentMemory;
            break;
        case 12:
            AllocateBuffer_Arg_2 = EfiReservedMemoryType;
            break;
        case 13:
            AllocateBuffer_Arg_2 = EfiRuntimeServicesCode;
            break;
        case 14:
            AllocateBuffer_Arg_2 = EfiRuntimeServicesData;
            break;
        case 15:
            AllocateBuffer_Arg_2 = EfiUnacceptedMemoryType;
            break;
        case 16:
            AllocateBuffer_Arg_2 = EfiUnusableMemory;
            break;
        case 17:
            AllocateBuffer_Arg_2 = MEMORY_TYPE_OEM_RESERVED_MAX;
            break;
        case 18:
            AllocateBuffer_Arg_2 = MEMORY_TYPE_OEM_RESERVED_MIN;
            break;
        case 19:
            AllocateBuffer_Arg_2 = MEMORY_TYPE_OS_RESERVED_MAX;
            break;
        case 20:
            AllocateBuffer_Arg_2 = MEMORY_TYPE_OS_RESERVED_MIN;
            break;
        case 21:
            ReadBytes(Input, sizeof(AllocateBuffer_Arg_2), (VOID *)&AllocateBuffer_Arg_2);
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_3), (VOID *)&AllocateBuffer_Arg_3);
    AllocateBuffer_Arg_3 = AllocateBuffer_Arg_3 % (4096 + 1);
    
    // Fuzzable Variable Initialization
    UINT8 AllocateBuffer_Arg_4_choice = 0;
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_4_choice), (VOID *)&AllocateBuffer_Arg_4_choice);
    switch(AllocateBuffer_Arg_4_choice % 1) {
        case 0:
            if (AllocateBuffer_Arg_4 != NULL) {
                ReadBytes(Input, sizeof(*AllocateBuffer_Arg_4), (VOID *)AllocateBuffer_Arg_4);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(AllocateBuffer_Arg_5), (VOID *)&AllocateBuffer_Arg_5);
    AllocateBuffer_Arg_5 = AllocateBuffer_Arg_5 % (4096 + 1);
    
    FirnessUntrusted(AllocateBuffer_Arg_4, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->AllocateBuffer(
        ProtocolVariable,
        AllocateBuffer_Arg_1,
        AllocateBuffer_Arg_2,
        AllocateBuffer_Arg_3,
        (void **)&AllocateBuffer_Arg_4,
        AllocateBuffer_Arg_5
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called FreeBuffer.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFreeBuffer(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINTN FreeBuffer_Arg_1 = {0};
    UINTN*  FreeBuffer_Arg_2 = (UINTN* )AllocateZeroPool(4096);
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(FreeBuffer_Arg_1), (VOID *)&FreeBuffer_Arg_1);
    FreeBuffer_Arg_1 = FreeBuffer_Arg_1 % (4096 + 1);
    
    // Fuzzable Variable Initialization
    UINT8 FreeBuffer_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(FreeBuffer_Arg_2_choice), (VOID *)&FreeBuffer_Arg_2_choice);
    switch(FreeBuffer_Arg_2_choice % 1) {
        case 0:
            if (FreeBuffer_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*FreeBuffer_Arg_2), (VOID *)FreeBuffer_Arg_2);
            }
            break;
    }
    
    FirnessUntrusted(FreeBuffer_Arg_2, 4096);
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->FreeBuffer(
        ProtocolVariable,
        FreeBuffer_Arg_1,
        (void *)FreeBuffer_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called Flush.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzFlush(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->Flush(
        ProtocolVariable
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called GetAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzGetAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 * GetAttributes_Arg_1 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT64 * GetAttributes_Arg_2 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    // Fuzzable Variable Initialization
    UINT8 GetAttributes_Arg_1_choice = 0;
    ReadBytes(Input, sizeof(GetAttributes_Arg_1_choice), (VOID *)&GetAttributes_Arg_1_choice);
    switch(GetAttributes_Arg_1_choice % 1) {
        case 0:
            if (GetAttributes_Arg_1 != NULL) {
                ReadBytes(Input, sizeof(*GetAttributes_Arg_1), (VOID *)GetAttributes_Arg_1);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 GetAttributes_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(GetAttributes_Arg_2_choice), (VOID *)&GetAttributes_Arg_2_choice);
    switch(GetAttributes_Arg_2_choice % 1) {
        case 0:
            if (GetAttributes_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*GetAttributes_Arg_2), (VOID *)GetAttributes_Arg_2);
            }
            break;
    }
    
    FirnessUntrusted(GetAttributes_Arg_1, sizeof(UINT64));
    FirnessUntrusted(GetAttributes_Arg_2, sizeof(UINT64));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->GetAttributes(
        ProtocolVariable,
        GetAttributes_Arg_1,
        GetAttributes_Arg_2
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called SetAttributes.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSetAttributes(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiPciRootBridgeIoProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    /*
        Input Variable(s)
    */
    UINT64 SetAttributes_Arg_1 = {0};
    UINT64 * SetAttributes_Arg_2 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    UINT64 * SetAttributes_Arg_3 = (UINT64 *)AllocateZeroPool(sizeof(UINT64));
    
    // Fuzzable Variable Initialization
    ReadBytes(Input, sizeof(SetAttributes_Arg_1), (VOID *)&SetAttributes_Arg_1);
    
    // Fuzzable Variable Initialization
    UINT8 SetAttributes_Arg_2_choice = 0;
    ReadBytes(Input, sizeof(SetAttributes_Arg_2_choice), (VOID *)&SetAttributes_Arg_2_choice);
    switch(SetAttributes_Arg_2_choice % 1) {
        case 0:
            if (SetAttributes_Arg_2 != NULL) {
                ReadBytes(Input, sizeof(*SetAttributes_Arg_2), (VOID *)SetAttributes_Arg_2);
            }
            break;
    }
    
    // Fuzzable Variable Initialization
    UINT8 SetAttributes_Arg_3_choice = 0;
    ReadBytes(Input, sizeof(SetAttributes_Arg_3_choice), (VOID *)&SetAttributes_Arg_3_choice);
    switch(SetAttributes_Arg_3_choice % 1) {
        case 0:
            if (SetAttributes_Arg_3 != NULL) {
                ReadBytes(Input, sizeof(*SetAttributes_Arg_3), (VOID *)SetAttributes_Arg_3);
                *SetAttributes_Arg_3 = *SetAttributes_Arg_3 % (sizeof(UINT64) + 1);
            }
            break;
    }
    
    FirnessUntrusted(SetAttributes_Arg_2, sizeof(UINT64));
    FirnessUntrusted(SetAttributes_Arg_3, sizeof(UINT64));
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->SetAttributes(
        ProtocolVariable,
        SetAttributes_Arg_1,
        SetAttributes_Arg_2,
        SetAttributes_Arg_3
    );
    FirnessSanitizer(FALSE);
    return Status;
}

