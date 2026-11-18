#include "FirnessHarnesses.h"

/*
    This is a harness for fuzzing the protocol service
    called RegisterResetNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzRegisterResetNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_RESET_NOTIFICATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiResetNotificationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->RegisterResetNotify(
        ProtocolVariable,
        NULL
    );
    FirnessSanitizer(FALSE);
    return Status;
}

/*
    This is a harness for fuzzing the protocol service
    called UnregisterResetNotify.
*/
__attribute__((no_sanitize("address")))
EFI_STATUS
EFIAPI
FuzzUnregisterResetNotify(
    IN INPUT_BUFFER *Input,
    IN EFI_SYSTEM_TABLE *SystemTable,
    IN EFI_HANDLE *ImageHandle
) {
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_RESET_NOTIFICATION_PROTOCOL * ProtocolVariable = NULL;
    Status = SystemTable->BootServices->LocateProtocol(&gEfiResetNotificationProtocolGuid, NULL, (VOID *)&ProtocolVariable);
    if (EFI_ERROR(Status)) {
        return Status;
    }
    FirnessSanitizer(TRUE);
    Status = ProtocolVariable->UnregisterResetNotify(
        ProtocolVariable,
        NULL
    );
    FirnessSanitizer(FALSE);
    return Status;
}

