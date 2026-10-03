package com.samvaad.android.enroll

/**
 * First-bootstrap UI states (bootstrap slice only).
 *
 * Recovery codes exist ONLY inside [AwaitingCodesAck]; leaving that state
 * drops them. Nothing here carries private key material, tokens, or raw
 * server bodies — fixed safe strings are composed at the UI layer.
 */
sealed interface BootstrapProgress {
    data object Preparing : BootstrapProgress
    data object Enrolling : BootstrapProgress
    data object UploadingPrekeys : BootstrapProgress
}

sealed interface BootstrapFinal {
    /** Device adopted and usable. [codesAcknowledged]=false means the codes
     * were never confirmed (crash before ack or server sent none): the UI
     * must not present bootstrap as fully complete. */
    data class Active(val deviceLabel: String, val codesAcknowledged: Boolean) : BootstrapFinal

    /** Transient: the 25 first-bootstrap codes, shown once. */
    data class AwaitingCodesAck(val codes: List<String>) : BootstrapFinal

    /** Server returned a non-ACTIVE device: stop, no OTPK upload, no approval UI. */
    data class PendingApproval(val deviceLabel: String) : BootstrapFinal

    /**
     * The adopted pending device is gone server-side (REVOKED, expired, or
     * absent). Distinct from [ReconciliationRequired]: the lineage is dead,
     * so the UI offers a fresh enrollment instead of a retry. Never reuse
     * the dead device row.
     */
    data class Denied(val deviceLabel: String) : BootstrapFinal

    /** Server demands recovery flow (deferred slice). */
    data object RecoveryRequired : BootstrapFinal

    /** Uncertain outcome that reconcile-first could not resolve safely. */
    data class ReconciliationRequired(val reason: String) : BootstrapFinal

    data class Failed(val kind: FailKind) : BootstrapFinal
}

enum class FailKind {
    TRANSPORT_RETRYABLE,
    UNAUTHORIZED,
    REJECTED,
    IDENTITY_MISMATCH,
    MISSING_MATERIAL,
    ALREADY_RUNNING,
}
