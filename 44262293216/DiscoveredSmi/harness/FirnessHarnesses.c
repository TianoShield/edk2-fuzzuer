#include "FirnessHarnesses.h"

STATIC CONST UINTN mFirnessShortLengths[] = {
  0, 1, 2, 3, 4, 7, 8, 12, 15, 16, 20, 24, 28, 31, 32,
  40, 48, 56, 63, 64, 96, 127, 128, 160, 255, 256, 512
};

/*
    This is a harness for fuzzing the SMI Handler
    called SmiHandlerProfileHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSmiHandlerProfileHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMM_COMMUNICATION_PROTOCOL *SmmCommunication = NULL;
    EDKII_PI_SMM_COMMUNICATION_REGION_TABLE *PiSmmCommunicationRegionTable = NULL;
    UINTN MinimalSizeNeeded = EFI_PAGE_SIZE;
    UINTN   CommSize = 0;
    UINT8    *CommBuffer = NULL;
    EFI_SMM_COMMUNICATE_HEADER   *CommHeader = NULL;
    UINT32      Index = 0;
    EFI_MEMORY_DESCRIPTOR   *Entry = NULL;
    UINTN  Size = 0;

    Status = EfiGetSystemConfigurationTable (
                &gEdkiiPiSmmCommunicationRegionTableGuid,
                (VOID **)&PiSmmCommunicationRegionTable
            );
    if (EFI_ERROR(Status) || PiSmmCommunicationRegionTable == NULL) {
        return EFI_NOT_FOUND;
    }

    Status = gBS->LocateProtocol(
                    &gEfiSmmCommunicationProtocolGuid,
                    NULL,
                    (VOID **)&SmmCommunication
                    );
    if (EFI_ERROR(Status)) {
        Print(L"Failed to handle SMM Communication Protocol");
        return Status;
    }
    Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
    Size  = 0;
    for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
        if (Entry->Type == EfiConventionalMemory) {
            Size = EFI_PAGES_TO_SIZE ((UINTN)Entry->NumberOfPages);
            if (Size >= MinimalSizeNeeded) {
                break;
            }
        }

        Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
    }

    if (Index >= PiSmmCommunicationRegionTable->NumberOfEntries) {
        return EFI_OUT_OF_RESOURCES;
    }
    CommBuffer = (UINT8 *)(UINTN)Entry->PhysicalStart;

    CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)&CommBuffer[0];
    CopyMem (&CommHeader->HeaderGuid, &gSmiHandlerProfileGuid, sizeof (gSmiHandlerProfileGuid));
    CommHeader->MessageLength = sizeof (SMI_HANDLER_PROFILE_PARAMETER_HEADER);
    UINT8  MessageLengthChoice = 0;
    UINT16 MessageLengthDelta = 0;
    ReadBytes(Input, sizeof(MessageLengthChoice), (VOID *)&MessageLengthChoice);
    ReadBytes(Input, sizeof(MessageLengthDelta), (VOID *)&MessageLengthDelta);
    UINTN MessageLengthRoom = Size - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);
    switch (MessageLengthChoice & 3) {
        case 1:
            CommHeader->MessageLength += (UINTN)MessageLengthDelta;
            break;
        case 2:
            CommHeader->MessageLength = mFirnessShortLengths[(UINTN)MessageLengthDelta % (sizeof (mFirnessShortLengths) / sizeof (mFirnessShortLengths[0]))];
            break;
        case 3:
            CommHeader->MessageLength = (UINTN)MessageLengthDelta % (sizeof (SMI_HANDLER_PROFILE_PARAMETER_HEADER) + 1);
            break;
        default:
            break;
    }
    if (CommHeader->MessageLength > MessageLengthRoom) {
        CommHeader->MessageLength = MessageLengthRoom;
    }
    SMI_HANDLER_PROFILE_PARAMETER_HEADER * HandlerData = (SMI_HANDLER_PROFILE_PARAMETER_HEADER *)&CommBuffer[OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data)];
    // Generator Struct Variable Initialization
    UINT8 HandlerDataScalarChoice = 0;
    ReadBytes(Input, sizeof(HandlerData->Command), (VOID *)&(HandlerData->Command));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->Command = 0; break;
        case 9: HandlerData->Command = 1; break;
        case 10: HandlerData->Command = (UINT32)(HandlerData->Command & 0xFF); break;
        case 11: HandlerData->Command = (UINT32)~0ULL; break;
        case 12:
        case 13:
        case 14:
        case 15:
            HandlerData->Command = (UINT32)2;  // SMI_HANDLER_PROFILE_COMMAND_GET_DATA_BY_OFFSET
            break;  // a constant the source tests this field against
        default: break;  // the raw read
    }
    ReadBytes(Input, sizeof(HandlerData->DataLength), (VOID *)&(HandlerData->DataLength));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->DataLength = 0; break;
        case 9: HandlerData->DataLength = 1; break;
        case 10: HandlerData->DataLength = (UINT32)(HandlerData->DataLength & 0xFF); break;
        case 11: HandlerData->DataLength = (UINT32)~0ULL; break;
        default: break;  // the raw read
    }
    ReadBytes(Input, sizeof(HandlerData->ReturnStatus), (VOID *)&(HandlerData->ReturnStatus));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->ReturnStatus = 0; break;
        case 9: HandlerData->ReturnStatus = 1; break;
        case 10: HandlerData->ReturnStatus = (UINT64)(HandlerData->ReturnStatus & 0xFF); break;
        case 11: HandlerData->ReturnStatus = (UINT64)~0ULL; break;
        default: break;  // the raw read
    }
    CommSize = sizeof (EFI_GUID) + sizeof (UINTN) + CommHeader->MessageLength;
    FirnessUntrusted(CommBuffer, CommSize);
    FirnessSanitizer(TRUE);
    Status   = SmmCommunication->Communicate (SmmCommunication, CommBuffer, &CommSize);
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the SMI Handler
    called SmmFaultTolerantWriteHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSmmFaultTolerantWriteHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMM_COMMUNICATION_PROTOCOL *SmmCommunication = NULL;
    EDKII_PI_SMM_COMMUNICATION_REGION_TABLE *PiSmmCommunicationRegionTable = NULL;
    UINTN MinimalSizeNeeded = EFI_PAGE_SIZE;
    UINTN   CommSize = 0;
    UINT8    *CommBuffer = NULL;
    EFI_SMM_COMMUNICATE_HEADER   *CommHeader = NULL;
    UINT32      Index = 0;
    EFI_MEMORY_DESCRIPTOR   *Entry = NULL;
    UINTN  Size = 0;

    Status = EfiGetSystemConfigurationTable (
                &gEdkiiPiSmmCommunicationRegionTableGuid,
                (VOID **)&PiSmmCommunicationRegionTable
            );
    if (EFI_ERROR(Status) || PiSmmCommunicationRegionTable == NULL) {
        return EFI_NOT_FOUND;
    }

    Status = gBS->LocateProtocol(
                    &gEfiSmmCommunicationProtocolGuid,
                    NULL,
                    (VOID **)&SmmCommunication
                    );
    if (EFI_ERROR(Status)) {
        Print(L"Failed to handle SMM Communication Protocol");
        return Status;
    }
    Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
    Size  = 0;
    for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
        if (Entry->Type == EfiConventionalMemory) {
            Size = EFI_PAGES_TO_SIZE ((UINTN)Entry->NumberOfPages);
            if (Size >= MinimalSizeNeeded) {
                break;
            }
        }

        Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
    }

    if (Index >= PiSmmCommunicationRegionTable->NumberOfEntries) {
        return EFI_OUT_OF_RESOURCES;
    }
    CommBuffer = (UINT8 *)(UINTN)Entry->PhysicalStart;

    CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)&CommBuffer[0];
    CopyMem (&CommHeader->HeaderGuid, &gEfiSmmFaultTolerantWriteProtocolGuid, sizeof (gEfiSmmFaultTolerantWriteProtocolGuid));
    CommHeader->MessageLength = sizeof (SMM_FTW_COMMUNICATE_FUNCTION_HEADER);
    UINT8  MessageLengthChoice = 0;
    UINT16 MessageLengthDelta = 0;
    ReadBytes(Input, sizeof(MessageLengthChoice), (VOID *)&MessageLengthChoice);
    ReadBytes(Input, sizeof(MessageLengthDelta), (VOID *)&MessageLengthDelta);
    UINTN MessageLengthRoom = Size - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);
    switch (MessageLengthChoice & 3) {
        case 1:
            CommHeader->MessageLength += (UINTN)MessageLengthDelta;
            break;
        case 2:
            CommHeader->MessageLength = mFirnessShortLengths[(UINTN)MessageLengthDelta % (sizeof (mFirnessShortLengths) / sizeof (mFirnessShortLengths[0]))];
            break;
        case 3:
            CommHeader->MessageLength = (UINTN)MessageLengthDelta % (sizeof (SMM_FTW_COMMUNICATE_FUNCTION_HEADER) + 1);
            break;
        default:
            break;
    }
    if (CommHeader->MessageLength > MessageLengthRoom) {
        CommHeader->MessageLength = MessageLengthRoom;
    }
    SMM_FTW_COMMUNICATE_FUNCTION_HEADER * HandlerData = (SMM_FTW_COMMUNICATE_FUNCTION_HEADER *)&CommBuffer[OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data)];
    // Generator Struct Variable Initialization
    UINT8 HandlerDataScalarChoice = 0;
    UINT8 HandlerDataConstChoice = 0;
    ReadBytes(Input, sizeof(HandlerData->Function), (VOID *)&(HandlerData->Function));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    ReadBytes(Input, sizeof(HandlerDataConstChoice), (VOID *)&HandlerDataConstChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->Function = 0; break;
        case 9: HandlerData->Function = 1; break;
        case 10: HandlerData->Function = (UINTN)(HandlerData->Function & 0xFF); break;
        case 11: HandlerData->Function = (UINTN)~0ULL; break;
        case 12:
        case 13:
        case 14:
        case 15:
            switch (HandlerDataConstChoice % 5) {
                case 0: HandlerData->Function = (UINTN)5; break;  // FTW_FUNCTION_ABORT
                case 1: HandlerData->Function = (UINTN)2; break;  // FTW_FUNCTION_ALLOCATE
                case 2: HandlerData->Function = (UINTN)6; break;  // FTW_FUNCTION_GET_LAST_WRITE
                case 3: HandlerData->Function = (UINTN)4; break;  // FTW_FUNCTION_RESTART
                case 4: HandlerData->Function = (UINTN)3; break;  // FTW_FUNCTION_WRITE
                default: break;
            }
            break;  // a constant the source tests this field against
        default: break;  // the raw read
    }
    ReadBytes(Input, sizeof(HandlerData->ReturnStatus), (VOID *)&(HandlerData->ReturnStatus));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->ReturnStatus = 0; break;
        case 9: HandlerData->ReturnStatus = 1; break;
        case 10: HandlerData->ReturnStatus = (EFI_STATUS)(HandlerData->ReturnStatus & 0xFF); break;
        case 11: HandlerData->ReturnStatus = (EFI_STATUS)~0ULL; break;
        default: break;  // the raw read
    }
    // Data is the payload region, not a one-byte field -- see PAYLOAD_FILL_BYTES
    UINTN HandlerDataPayloadAt = (UINTN)((UINT8 *)(HandlerData->Data) - (UINT8 *)HandlerData);
    UINTN HandlerDataPayloadRoom = 0;
    UINT8 HandlerDataPayloadFill[64];
    UINT8 HandlerDataPlantKind[8];
    UINT8 HandlerDataPlantSlot[8];
    UINT8 HandlerDataPlantWhich[8];
    UINTN HandlerDataPlant = 0;
    UINTN HandlerDataPlantSlots = 0;
    UINTN HandlerDataPlantAt = 0;
    VOID *HandlerDataPlantPointer = NULL;
    UINT32 HandlerDataPlantValue = 0;
    ReadBytes(Input, sizeof(HandlerDataPayloadFill), (VOID *)HandlerDataPayloadFill);
    ReadBytes(Input, sizeof(HandlerDataPlantKind), (VOID *)HandlerDataPlantKind);
    ReadBytes(Input, sizeof(HandlerDataPlantSlot), (VOID *)HandlerDataPlantSlot);
    ReadBytes(Input, sizeof(HandlerDataPlantWhich), (VOID *)HandlerDataPlantWhich);
    if (CommHeader->MessageLength > HandlerDataPayloadAt) {
        HandlerDataPayloadRoom = CommHeader->MessageLength - HandlerDataPayloadAt;
    }
    CopyMem ((UINT8 *)(HandlerData->Data), HandlerDataPayloadFill, MIN (HandlerDataPayloadRoom, sizeof (HandlerDataPayloadFill)));
    if (HandlerDataPayloadRoom > sizeof (HandlerDataPayloadFill)) {
        SetMem ((UINT8 *)(HandlerData->Data) + sizeof (HandlerDataPayloadFill), HandlerDataPayloadRoom - sizeof (HandlerDataPayloadFill), 0);
    }
    for (HandlerDataPlant = 0; HandlerDataPlant < 8; HandlerDataPlant++) {
        switch (HandlerDataPlantKind[HandlerDataPlant] & 3) {
            case 1:
                HandlerDataPlantSlots = MIN (HandlerDataPayloadRoom / sizeof (VOID *), 8);
                if (HandlerDataPlantSlots == 0) {
                    break;
                }
                HandlerDataPlantAt = ((UINTN)HandlerDataPlantSlot[HandlerDataPlant] % HandlerDataPlantSlots) * sizeof (VOID *);
                HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + HandlerDataPlantAt + sizeof (VOID *));
                CopyMem ((UINT8 *)(HandlerData->Data) + HandlerDataPlantAt, &HandlerDataPlantPointer, sizeof (HandlerDataPlantPointer));
                break;
            case 2:
                HandlerDataPlantSlots = MIN (HandlerDataPayloadRoom / sizeof (VOID *), 8);
                if (HandlerDataPlantSlots == 0) {
                    break;
                }
                HandlerDataPlantAt = ((UINTN)HandlerDataPlantSlot[HandlerDataPlant] % HandlerDataPlantSlots) * sizeof (VOID *);
                switch (HandlerDataPlantWhich[HandlerDataPlant] % 8) {
                    case 0: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 0); break;
                    case 1: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 8); break;
                    case 2: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 16); break;
                    case 3: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 24); break;
                    case 4: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 32); break;
                    case 5: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 40); break;
                    case 6: HandlerDataPlantPointer = (VOID *)CommBuffer; break;
                    default: HandlerDataPlantPointer = (VOID *)HandlerData; break;
                }
                CopyMem ((UINT8 *)(HandlerData->Data) + HandlerDataPlantAt, &HandlerDataPlantPointer, sizeof (HandlerDataPlantPointer));
                break;
            case 3:
                HandlerDataPlantSlots = MIN (HandlerDataPayloadRoom / sizeof (UINT32), 16);
                if (HandlerDataPlantSlots == 0) {
                    break;
                }
                HandlerDataPlantAt = ((UINTN)HandlerDataPlantSlot[HandlerDataPlant] % HandlerDataPlantSlots) * sizeof (UINT32);
                switch (HandlerDataPlantWhich[HandlerDataPlant] % 8) {
                    case 0: HandlerDataPlantValue = (UINT32)0; break;
                    case 1: HandlerDataPlantValue = (UINT32)1; break;
                    case 2: HandlerDataPlantValue = (UINT32)2; break;
                    case 3: HandlerDataPlantValue = (UINT32)4; break;
                    case 4: HandlerDataPlantValue = (UINT32)8; break;
                    case 5: HandlerDataPlantValue = (UINT32)16; break;
                    case 6: HandlerDataPlantValue = (UINT32)0xFF; break;
                    case 7: HandlerDataPlantValue = (UINT32)0xFFFFFFFF; break;
                    default: HandlerDataPlantValue = 0; break;
                }
                CopyMem ((UINT8 *)(HandlerData->Data) + HandlerDataPlantAt, &HandlerDataPlantValue, sizeof (HandlerDataPlantValue));
                break;
            default:
                break;  // a spent input plants nothing
        }
    }
    CommSize = sizeof (EFI_GUID) + sizeof (UINTN) + CommHeader->MessageLength;
    FirnessUntrusted(CommBuffer, CommSize);
    FirnessSanitizer(TRUE);
    Status   = SmmCommunication->Communicate (SmmCommunication, CommBuffer, &CommSize);
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the SMI Handler
    called SmmLockBoxHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSmmLockBoxHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMM_COMMUNICATION_PROTOCOL *SmmCommunication = NULL;
    EDKII_PI_SMM_COMMUNICATION_REGION_TABLE *PiSmmCommunicationRegionTable = NULL;
    UINTN MinimalSizeNeeded = EFI_PAGE_SIZE;
    UINTN   CommSize = 0;
    UINT8    *CommBuffer = NULL;
    EFI_SMM_COMMUNICATE_HEADER   *CommHeader = NULL;
    UINT32      Index = 0;
    EFI_MEMORY_DESCRIPTOR   *Entry = NULL;
    UINTN  Size = 0;

    Status = EfiGetSystemConfigurationTable (
                &gEdkiiPiSmmCommunicationRegionTableGuid,
                (VOID **)&PiSmmCommunicationRegionTable
            );
    if (EFI_ERROR(Status) || PiSmmCommunicationRegionTable == NULL) {
        return EFI_NOT_FOUND;
    }

    Status = gBS->LocateProtocol(
                    &gEfiSmmCommunicationProtocolGuid,
                    NULL,
                    (VOID **)&SmmCommunication
                    );
    if (EFI_ERROR(Status)) {
        Print(L"Failed to handle SMM Communication Protocol");
        return Status;
    }
    Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
    Size  = 0;
    for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
        if (Entry->Type == EfiConventionalMemory) {
            Size = EFI_PAGES_TO_SIZE ((UINTN)Entry->NumberOfPages);
            if (Size >= MinimalSizeNeeded) {
                break;
            }
        }

        Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
    }

    if (Index >= PiSmmCommunicationRegionTable->NumberOfEntries) {
        return EFI_OUT_OF_RESOURCES;
    }
    CommBuffer = (UINT8 *)(UINTN)Entry->PhysicalStart;

    CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)&CommBuffer[0];
    CopyMem (&CommHeader->HeaderGuid, &gEfiSmmLockBoxCommunicationGuid, sizeof (gEfiSmmLockBoxCommunicationGuid));
    CommHeader->MessageLength = sizeof (EFI_SMM_LOCK_BOX_PARAMETER_HEADER);
    UINT8  MessageLengthChoice = 0;
    UINT16 MessageLengthDelta = 0;
    ReadBytes(Input, sizeof(MessageLengthChoice), (VOID *)&MessageLengthChoice);
    ReadBytes(Input, sizeof(MessageLengthDelta), (VOID *)&MessageLengthDelta);
    UINTN MessageLengthRoom = Size - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);
    switch (MessageLengthChoice & 3) {
        case 1:
            CommHeader->MessageLength += (UINTN)MessageLengthDelta;
            break;
        case 2:
            CommHeader->MessageLength = mFirnessShortLengths[(UINTN)MessageLengthDelta % (sizeof (mFirnessShortLengths) / sizeof (mFirnessShortLengths[0]))];
            break;
        case 3:
            CommHeader->MessageLength = (UINTN)MessageLengthDelta % (sizeof (EFI_SMM_LOCK_BOX_PARAMETER_HEADER) + 1);
            break;
        default:
            break;
    }
    if (CommHeader->MessageLength > MessageLengthRoom) {
        CommHeader->MessageLength = MessageLengthRoom;
    }
    EFI_SMM_LOCK_BOX_PARAMETER_HEADER * HandlerData = (EFI_SMM_LOCK_BOX_PARAMETER_HEADER *)&CommBuffer[OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data)];
    // Generator Struct Variable Initialization
    UINT8 HandlerDataScalarChoice = 0;
    UINT8 HandlerDataConstChoice = 0;
    ReadBytes(Input, sizeof(HandlerData->Command), (VOID *)&(HandlerData->Command));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    ReadBytes(Input, sizeof(HandlerDataConstChoice), (VOID *)&HandlerDataConstChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->Command = 0; break;
        case 9: HandlerData->Command = 1; break;
        case 10: HandlerData->Command = (UINT32)(HandlerData->Command & 0xFF); break;
        case 11: HandlerData->Command = (UINT32)~0ULL; break;
        case 12:
        case 13:
        case 14:
        case 15:
            switch (HandlerDataConstChoice % 4) {
                case 0: HandlerData->Command = (UINT32)3; break;  // EFI_SMM_LOCK_BOX_COMMAND_RESTORE
                case 1: HandlerData->Command = (UINT32)5; break;  // EFI_SMM_LOCK_BOX_COMMAND_RESTORE_ALL_IN_PLACE
                case 2: HandlerData->Command = (UINT32)4; break;  // EFI_SMM_LOCK_BOX_COMMAND_SET_ATTRIBUTES
                case 3: HandlerData->Command = (UINT32)2; break;  // EFI_SMM_LOCK_BOX_COMMAND_UPDATE
                default: break;
            }
            break;  // a constant the source tests this field against
        default: break;  // the raw read
    }
    ReadBytes(Input, sizeof(HandlerData->DataLength), (VOID *)&(HandlerData->DataLength));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->DataLength = 0; break;
        case 9: HandlerData->DataLength = 1; break;
        case 10: HandlerData->DataLength = (UINT32)(HandlerData->DataLength & 0xFF); break;
        case 11: HandlerData->DataLength = (UINT32)~0ULL; break;
        default: break;  // the raw read
    }
    ReadBytes(Input, sizeof(HandlerData->ReturnStatus), (VOID *)&(HandlerData->ReturnStatus));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->ReturnStatus = 0; break;
        case 9: HandlerData->ReturnStatus = 1; break;
        case 10: HandlerData->ReturnStatus = (UINT64)(HandlerData->ReturnStatus & 0xFF); break;
        case 11: HandlerData->ReturnStatus = (UINT64)~0ULL; break;
        default: break;  // the raw read
    }
    CommSize = sizeof (EFI_GUID) + sizeof (UINTN) + CommHeader->MessageLength;
    FirnessUntrusted(CommBuffer, CommSize);
    FirnessSanitizer(TRUE);
    Status   = SmmCommunication->Communicate (SmmCommunication, CommBuffer, &CommSize);
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the SMI Handler
    called SmmVariableHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSmmVariableHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMM_COMMUNICATION_PROTOCOL *SmmCommunication = NULL;
    EDKII_PI_SMM_COMMUNICATION_REGION_TABLE *PiSmmCommunicationRegionTable = NULL;
    UINTN MinimalSizeNeeded = EFI_PAGE_SIZE;
    UINTN   CommSize = 0;
    UINT8    *CommBuffer = NULL;
    EFI_SMM_COMMUNICATE_HEADER   *CommHeader = NULL;
    UINT32      Index = 0;
    EFI_MEMORY_DESCRIPTOR   *Entry = NULL;
    UINTN  Size = 0;

    Status = EfiGetSystemConfigurationTable (
                &gEdkiiPiSmmCommunicationRegionTableGuid,
                (VOID **)&PiSmmCommunicationRegionTable
            );
    if (EFI_ERROR(Status) || PiSmmCommunicationRegionTable == NULL) {
        return EFI_NOT_FOUND;
    }

    Status = gBS->LocateProtocol(
                    &gEfiSmmCommunicationProtocolGuid,
                    NULL,
                    (VOID **)&SmmCommunication
                    );
    if (EFI_ERROR(Status)) {
        Print(L"Failed to handle SMM Communication Protocol");
        return Status;
    }
    Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
    Size  = 0;
    for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
        if (Entry->Type == EfiConventionalMemory) {
            Size = EFI_PAGES_TO_SIZE ((UINTN)Entry->NumberOfPages);
            if (Size >= MinimalSizeNeeded) {
                break;
            }
        }

        Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
    }

    if (Index >= PiSmmCommunicationRegionTable->NumberOfEntries) {
        return EFI_OUT_OF_RESOURCES;
    }
    CommBuffer = (UINT8 *)(UINTN)Entry->PhysicalStart;

    CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)&CommBuffer[0];
    CopyMem (&CommHeader->HeaderGuid, &gEfiSmmVariableProtocolGuid, sizeof (gEfiSmmVariableProtocolGuid));
    CommHeader->MessageLength = sizeof (SMM_VARIABLE_COMMUNICATE_HEADER);
    UINT8  MessageLengthChoice = 0;
    UINT16 MessageLengthDelta = 0;
    ReadBytes(Input, sizeof(MessageLengthChoice), (VOID *)&MessageLengthChoice);
    ReadBytes(Input, sizeof(MessageLengthDelta), (VOID *)&MessageLengthDelta);
    UINTN MessageLengthRoom = Size - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);
    switch (MessageLengthChoice & 3) {
        case 1:
            CommHeader->MessageLength += (UINTN)MessageLengthDelta;
            break;
        case 2:
            CommHeader->MessageLength = mFirnessShortLengths[(UINTN)MessageLengthDelta % (sizeof (mFirnessShortLengths) / sizeof (mFirnessShortLengths[0]))];
            break;
        case 3:
            CommHeader->MessageLength = (UINTN)MessageLengthDelta % (sizeof (SMM_VARIABLE_COMMUNICATE_HEADER) + 1);
            break;
        default:
            break;
    }
    if (CommHeader->MessageLength > MessageLengthRoom) {
        CommHeader->MessageLength = MessageLengthRoom;
    }
    SMM_VARIABLE_COMMUNICATE_HEADER * HandlerData = (SMM_VARIABLE_COMMUNICATE_HEADER *)&CommBuffer[OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data)];
    // Generator Struct Variable Initialization
    UINT8 HandlerDataScalarChoice = 0;
    UINT8 HandlerDataConstChoice = 0;
    ReadBytes(Input, sizeof(HandlerData->Function), (VOID *)&(HandlerData->Function));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    ReadBytes(Input, sizeof(HandlerDataConstChoice), (VOID *)&HandlerDataConstChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->Function = 0; break;
        case 9: HandlerData->Function = 1; break;
        case 10: HandlerData->Function = (UINTN)(HandlerData->Function & 0xFF); break;
        case 11: HandlerData->Function = (UINTN)~0ULL; break;
        case 12:
        case 13:
        case 14:
        case 15:
            switch (HandlerDataConstChoice % 13) {
                case 0: HandlerData->Function = (UINTN)6; break;  // SMM_VARIABLE_FUNCTION_EXIT_BOOT_SERVICE
                case 1: HandlerData->Function = (UINTN)2; break;  // SMM_VARIABLE_FUNCTION_GET_NEXT_VARIABLE_NAME
                case 2: HandlerData->Function = (UINTN)11; break;  // SMM_VARIABLE_FUNCTION_GET_PAYLOAD_SIZE
                case 3: HandlerData->Function = (UINTN)14; break;  // SMM_VARIABLE_FUNCTION_GET_RUNTIME_CACHE_INFO
                case 4: HandlerData->Function = (UINTN)7; break;  // SMM_VARIABLE_FUNCTION_GET_STATISTICS
                case 5: HandlerData->Function = (UINTN)8; break;  // SMM_VARIABLE_FUNCTION_LOCK_VARIABLE
                case 6: HandlerData->Function = (UINTN)4; break;  // SMM_VARIABLE_FUNCTION_QUERY_VARIABLE_INFO
                case 7: HandlerData->Function = (UINTN)5; break;  // SMM_VARIABLE_FUNCTION_READY_TO_BOOT
                case 8: HandlerData->Function = (UINTN)3; break;  // SMM_VARIABLE_FUNCTION_SET_VARIABLE
                case 9: HandlerData->Function = (UINTN)13; break;  // SMM_VARIABLE_FUNCTION_SYNC_RUNTIME_CACHE
                case 10: HandlerData->Function = (UINTN)10; break;
                case 11: HandlerData->Function = (UINTN)12; break;
                case 12: HandlerData->Function = (UINTN)9; break;
                default: break;
            }
            break;  // a constant the source tests this field against
        default: break;  // the raw read
    }
    ReadBytes(Input, sizeof(HandlerData->ReturnStatus), (VOID *)&(HandlerData->ReturnStatus));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->ReturnStatus = 0; break;
        case 9: HandlerData->ReturnStatus = 1; break;
        case 10: HandlerData->ReturnStatus = (EFI_STATUS)(HandlerData->ReturnStatus & 0xFF); break;
        case 11: HandlerData->ReturnStatus = (EFI_STATUS)~0ULL; break;
        default: break;  // the raw read
    }
    // Data is the payload region, not a one-byte field -- see PAYLOAD_FILL_BYTES
    UINTN HandlerDataPayloadAt = (UINTN)((UINT8 *)(HandlerData->Data) - (UINT8 *)HandlerData);
    UINTN HandlerDataPayloadRoom = 0;
    UINT8 HandlerDataPayloadFill[64];
    UINT8 HandlerDataPlantKind[8];
    UINT8 HandlerDataPlantSlot[8];
    UINT8 HandlerDataPlantWhich[8];
    UINTN HandlerDataPlant = 0;
    UINTN HandlerDataPlantSlots = 0;
    UINTN HandlerDataPlantAt = 0;
    VOID *HandlerDataPlantPointer = NULL;
    UINT32 HandlerDataPlantValue = 0;
    ReadBytes(Input, sizeof(HandlerDataPayloadFill), (VOID *)HandlerDataPayloadFill);
    ReadBytes(Input, sizeof(HandlerDataPlantKind), (VOID *)HandlerDataPlantKind);
    ReadBytes(Input, sizeof(HandlerDataPlantSlot), (VOID *)HandlerDataPlantSlot);
    ReadBytes(Input, sizeof(HandlerDataPlantWhich), (VOID *)HandlerDataPlantWhich);
    if (CommHeader->MessageLength > HandlerDataPayloadAt) {
        HandlerDataPayloadRoom = CommHeader->MessageLength - HandlerDataPayloadAt;
    }
    CopyMem ((UINT8 *)(HandlerData->Data), HandlerDataPayloadFill, MIN (HandlerDataPayloadRoom, sizeof (HandlerDataPayloadFill)));
    if (HandlerDataPayloadRoom > sizeof (HandlerDataPayloadFill)) {
        SetMem ((UINT8 *)(HandlerData->Data) + sizeof (HandlerDataPayloadFill), HandlerDataPayloadRoom - sizeof (HandlerDataPayloadFill), 0);
    }
    for (HandlerDataPlant = 0; HandlerDataPlant < 8; HandlerDataPlant++) {
        switch (HandlerDataPlantKind[HandlerDataPlant] & 3) {
            case 1:
                HandlerDataPlantSlots = MIN (HandlerDataPayloadRoom / sizeof (VOID *), 8);
                if (HandlerDataPlantSlots == 0) {
                    break;
                }
                HandlerDataPlantAt = ((UINTN)HandlerDataPlantSlot[HandlerDataPlant] % HandlerDataPlantSlots) * sizeof (VOID *);
                HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + HandlerDataPlantAt + sizeof (VOID *));
                CopyMem ((UINT8 *)(HandlerData->Data) + HandlerDataPlantAt, &HandlerDataPlantPointer, sizeof (HandlerDataPlantPointer));
                break;
            case 2:
                HandlerDataPlantSlots = MIN (HandlerDataPayloadRoom / sizeof (VOID *), 8);
                if (HandlerDataPlantSlots == 0) {
                    break;
                }
                HandlerDataPlantAt = ((UINTN)HandlerDataPlantSlot[HandlerDataPlant] % HandlerDataPlantSlots) * sizeof (VOID *);
                switch (HandlerDataPlantWhich[HandlerDataPlant] % 8) {
                    case 0: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 0); break;
                    case 1: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 8); break;
                    case 2: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 16); break;
                    case 3: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 24); break;
                    case 4: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 32); break;
                    case 5: HandlerDataPlantPointer = (VOID *)((UINT8 *)(HandlerData->Data) + 40); break;
                    case 6: HandlerDataPlantPointer = (VOID *)CommBuffer; break;
                    default: HandlerDataPlantPointer = (VOID *)HandlerData; break;
                }
                CopyMem ((UINT8 *)(HandlerData->Data) + HandlerDataPlantAt, &HandlerDataPlantPointer, sizeof (HandlerDataPlantPointer));
                break;
            case 3:
                HandlerDataPlantSlots = MIN (HandlerDataPayloadRoom / sizeof (UINT32), 16);
                if (HandlerDataPlantSlots == 0) {
                    break;
                }
                HandlerDataPlantAt = ((UINTN)HandlerDataPlantSlot[HandlerDataPlant] % HandlerDataPlantSlots) * sizeof (UINT32);
                switch (HandlerDataPlantWhich[HandlerDataPlant] % 8) {
                    case 0: HandlerDataPlantValue = (UINT32)0; break;
                    case 1: HandlerDataPlantValue = (UINT32)1; break;
                    case 2: HandlerDataPlantValue = (UINT32)2; break;
                    case 3: HandlerDataPlantValue = (UINT32)4; break;
                    case 4: HandlerDataPlantValue = (UINT32)8; break;
                    case 5: HandlerDataPlantValue = (UINT32)16; break;
                    case 6: HandlerDataPlantValue = (UINT32)0xFF; break;
                    case 7: HandlerDataPlantValue = (UINT32)0xFFFFFFFF; break;
                    default: HandlerDataPlantValue = 0; break;
                }
                CopyMem ((UINT8 *)(HandlerData->Data) + HandlerDataPlantAt, &HandlerDataPlantValue, sizeof (HandlerDataPlantValue));
                break;
            default:
                break;  // a spent input plants nothing
        }
    }
    CommSize = sizeof (EFI_GUID) + sizeof (UINTN) + CommHeader->MessageLength;
    FirnessUntrusted(CommBuffer, CommSize);
    FirnessSanitizer(TRUE);
    Status   = SmmCommunication->Communicate (SmmCommunication, CommBuffer, &CommSize);
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the SMI Handler
    called SmramProfileHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzSmramProfileHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMM_COMMUNICATION_PROTOCOL *SmmCommunication = NULL;
    EDKII_PI_SMM_COMMUNICATION_REGION_TABLE *PiSmmCommunicationRegionTable = NULL;
    UINTN MinimalSizeNeeded = EFI_PAGE_SIZE;
    UINTN   CommSize = 0;
    UINT8    *CommBuffer = NULL;
    EFI_SMM_COMMUNICATE_HEADER   *CommHeader = NULL;
    UINT32      Index = 0;
    EFI_MEMORY_DESCRIPTOR   *Entry = NULL;
    UINTN  Size = 0;

    Status = EfiGetSystemConfigurationTable (
                &gEdkiiPiSmmCommunicationRegionTableGuid,
                (VOID **)&PiSmmCommunicationRegionTable
            );
    if (EFI_ERROR(Status) || PiSmmCommunicationRegionTable == NULL) {
        return EFI_NOT_FOUND;
    }

    Status = gBS->LocateProtocol(
                    &gEfiSmmCommunicationProtocolGuid,
                    NULL,
                    (VOID **)&SmmCommunication
                    );
    if (EFI_ERROR(Status)) {
        Print(L"Failed to handle SMM Communication Protocol");
        return Status;
    }
    Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
    Size  = 0;
    for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
        if (Entry->Type == EfiConventionalMemory) {
            Size = EFI_PAGES_TO_SIZE ((UINTN)Entry->NumberOfPages);
            if (Size >= MinimalSizeNeeded) {
                break;
            }
        }

        Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
    }

    if (Index >= PiSmmCommunicationRegionTable->NumberOfEntries) {
        return EFI_OUT_OF_RESOURCES;
    }
    CommBuffer = (UINT8 *)(UINTN)Entry->PhysicalStart;

    CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)&CommBuffer[0];
    CopyMem (&CommHeader->HeaderGuid, &gEdkiiMemoryProfileGuid, sizeof (gEdkiiMemoryProfileGuid));
    CommHeader->MessageLength = sizeof (SMRAM_PROFILE_PARAMETER_RECORDING_STATE);
    UINT8  MessageLengthChoice = 0;
    UINT16 MessageLengthDelta = 0;
    ReadBytes(Input, sizeof(MessageLengthChoice), (VOID *)&MessageLengthChoice);
    ReadBytes(Input, sizeof(MessageLengthDelta), (VOID *)&MessageLengthDelta);
    UINTN MessageLengthRoom = Size - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);
    switch (MessageLengthChoice & 3) {
        case 1:
            CommHeader->MessageLength += (UINTN)MessageLengthDelta;
            break;
        case 2:
            CommHeader->MessageLength = mFirnessShortLengths[(UINTN)MessageLengthDelta % (sizeof (mFirnessShortLengths) / sizeof (mFirnessShortLengths[0]))];
            break;
        case 3:
            CommHeader->MessageLength = (UINTN)MessageLengthDelta % (sizeof (SMRAM_PROFILE_PARAMETER_RECORDING_STATE) + 1);
            break;
        default:
            break;
    }
    if (CommHeader->MessageLength > MessageLengthRoom) {
        CommHeader->MessageLength = MessageLengthRoom;
    }
    SMRAM_PROFILE_PARAMETER_RECORDING_STATE * HandlerData = (SMRAM_PROFILE_PARAMETER_RECORDING_STATE *)&CommBuffer[OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data)];
    // Generator Struct Variable Initialization
    UINT8 HandlerDataScalarChoice = 0;
    ReadBytes(Input, sizeof(HandlerData->Header), (VOID *)&(HandlerData->Header));
    ReadBytes(Input, sizeof(HandlerData->RecordingState), (VOID *)&(HandlerData->RecordingState));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->RecordingState = 0; break;
        case 9: HandlerData->RecordingState = 1; break;
        case 10: HandlerData->RecordingState = (BOOLEAN)(HandlerData->RecordingState & 0xFF); break;
        case 11: HandlerData->RecordingState = (BOOLEAN)~0ULL; break;
        default: break;  // the raw read
    }
    CommSize = sizeof (EFI_GUID) + sizeof (UINTN) + CommHeader->MessageLength;
    FirnessUntrusted(CommBuffer, CommSize);
    FirnessSanitizer(TRUE);
    Status   = SmmCommunication->Communicate (SmmCommunication, CommBuffer, &CommSize);
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the SMI Handler
    called VarCheckPolicyLibMmiHandler.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzVarCheckPolicyLibMmiHandler(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_SMM_COMMUNICATION_PROTOCOL *SmmCommunication = NULL;
    EDKII_PI_SMM_COMMUNICATION_REGION_TABLE *PiSmmCommunicationRegionTable = NULL;
    UINTN MinimalSizeNeeded = EFI_PAGE_SIZE;
    UINTN   CommSize = 0;
    UINT8    *CommBuffer = NULL;
    EFI_SMM_COMMUNICATE_HEADER   *CommHeader = NULL;
    UINT32      Index = 0;
    EFI_MEMORY_DESCRIPTOR   *Entry = NULL;
    UINTN  Size = 0;

    Status = EfiGetSystemConfigurationTable (
                &gEdkiiPiSmmCommunicationRegionTableGuid,
                (VOID **)&PiSmmCommunicationRegionTable
            );
    if (EFI_ERROR(Status) || PiSmmCommunicationRegionTable == NULL) {
        return EFI_NOT_FOUND;
    }

    Status = gBS->LocateProtocol(
                    &gEfiSmmCommunicationProtocolGuid,
                    NULL,
                    (VOID **)&SmmCommunication
                    );
    if (EFI_ERROR(Status)) {
        Print(L"Failed to handle SMM Communication Protocol");
        return Status;
    }
    Entry = (EFI_MEMORY_DESCRIPTOR *)(PiSmmCommunicationRegionTable + 1);
    Size  = 0;
    for (Index = 0; Index < PiSmmCommunicationRegionTable->NumberOfEntries; Index++) {
        if (Entry->Type == EfiConventionalMemory) {
            Size = EFI_PAGES_TO_SIZE ((UINTN)Entry->NumberOfPages);
            if (Size >= MinimalSizeNeeded) {
                break;
            }
        }

        Entry = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Entry + PiSmmCommunicationRegionTable->DescriptorSize);
    }

    if (Index >= PiSmmCommunicationRegionTable->NumberOfEntries) {
        return EFI_OUT_OF_RESOURCES;
    }
    CommBuffer = (UINT8 *)(UINTN)Entry->PhysicalStart;

    CommHeader = (EFI_SMM_COMMUNICATE_HEADER *)&CommBuffer[0];
    CopyMem (&CommHeader->HeaderGuid, &gVarCheckPolicyLibMmiHandlerGuid, sizeof (gVarCheckPolicyLibMmiHandlerGuid));
    CommHeader->MessageLength = sizeof (VAR_CHECK_POLICY_COMM_IS_ENABLED_PARAMS);
    UINT8  MessageLengthChoice = 0;
    UINT16 MessageLengthDelta = 0;
    ReadBytes(Input, sizeof(MessageLengthChoice), (VOID *)&MessageLengthChoice);
    ReadBytes(Input, sizeof(MessageLengthDelta), (VOID *)&MessageLengthDelta);
    UINTN MessageLengthRoom = Size - OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data);
    switch (MessageLengthChoice & 3) {
        case 1:
            CommHeader->MessageLength += (UINTN)MessageLengthDelta;
            break;
        case 2:
            CommHeader->MessageLength = mFirnessShortLengths[(UINTN)MessageLengthDelta % (sizeof (mFirnessShortLengths) / sizeof (mFirnessShortLengths[0]))];
            break;
        case 3:
            CommHeader->MessageLength = (UINTN)MessageLengthDelta % (sizeof (VAR_CHECK_POLICY_COMM_IS_ENABLED_PARAMS) + 1);
            break;
        default:
            break;
    }
    if (CommHeader->MessageLength > MessageLengthRoom) {
        CommHeader->MessageLength = MessageLengthRoom;
    }
    VAR_CHECK_POLICY_COMM_IS_ENABLED_PARAMS * HandlerData = (VAR_CHECK_POLICY_COMM_IS_ENABLED_PARAMS *)&CommBuffer[OFFSET_OF (EFI_SMM_COMMUNICATE_HEADER, Data)];
    // Generator Struct Variable Initialization
    UINT8 HandlerDataScalarChoice = 0;
    ReadBytes(Input, sizeof(HandlerData->State), (VOID *)&(HandlerData->State));
    ReadBytes(Input, sizeof(HandlerDataScalarChoice), (VOID *)&HandlerDataScalarChoice);
    switch (HandlerDataScalarChoice & 15) {
        case 8: HandlerData->State = 0; break;
        case 9: HandlerData->State = 1; break;
        case 10: HandlerData->State = (BOOLEAN)(HandlerData->State & 0xFF); break;
        case 11: HandlerData->State = (BOOLEAN)~0ULL; break;
        default: break;  // the raw read
    }
    CommSize = sizeof (EFI_GUID) + sizeof (UINTN) + CommHeader->MessageLength;
    FirnessUntrusted(CommBuffer, CommSize);
    FirnessSanitizer(TRUE);
    Status   = SmmCommunication->Communicate (SmmCommunication, CommBuffer, &CommSize);
    FirnessSanitizer(FALSE);
    return Status;
}

