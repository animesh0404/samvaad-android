package com.samvaad.android.enroll

import com.samvaad.android.AuthSession
import com.samvaad.android.crypto.AndroidCryptoVault
import com.samvaad.android.crypto.AndroidSignalAdapter
import com.samvaad.android.crypto.CryptoRecordKind
import com.samvaad.android.crypto.CryptoRecoveryException
import com.samvaad.android.crypto.SpikeCryptoMaterial
import com.samvaad.android.crypto.VaultException
import java.io.IOException
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import com.samvaad.android.crypto.SpikeCryptoMaterial.Identity
import com.samvaad.android.crypto.SpikeCryptoMaterial.KyberPrekey
import com.samvaad.android.crypto.SpikeCryptoMaterial.OneTimePrekey
import com.samvaad.android.crypto.SpikeCryptoMaterial.SealedHandle
import com.samvaad.android.crypto.SpikeCryptoMaterial.SignedPrekey

/**
 * Slice 10 companion-approval and recovery surface (top-level so Compose
 * and tests can reference the outcomes without a coordinator instance).
 * All outcomes derive from authoritative server truth; nothing here caches
 * device status, roles, or approval decisions.
 *
 * Owner device snapshot for the active-device approval surface and the
 * bind-existing-device picker. [ApprovalView.selfDeviceId] is this
 * installation's adopted row when present in the server list;
 * [ApprovalView.pending]/[ApprovalView.active] are the other owned rows by
 * status. Server truth, never cached.
 */
data class ApprovalView(
    val selfDeviceId: String?,
    val selfActive: Boolean,
    val pending: List<DeviceRecord>,
    val active: List<DeviceRecord>,
)

sealed interface ApprovalLoad {
    data class Ready(val view: ApprovalView) : ApprovalLoad
    data class Failed(val kind: FailKind) : ApprovalLoad
}

sealed interface ApproveOutcome {
    data class Approved(val deviceLabel: String) : ApproveOutcome
    data object StillPending : ApproveOutcome
    /** Target REVOKED or absent: converge by re-listing. */
    data object Gone : ApproveOutcome
    /** Server refused (403): this session may not approve. */
    data object Denied : ApproveOutcome
    data class Failed(val kind: FailKind) : ApproveOutcome
}

/**
 * Recovery entry choice. [Bind] reuses an existing ACTIVE row (no key
 * material generated); [NewDevice] creates a fresh identity through
 * `POST /recovery/enroll`. The code itself travels only as a call
 * argument — it is never persisted, logged, or retained.
 */
sealed interface RecoveryMode {
    data class Bind(val deviceId: String) : RecoveryMode
    data object NewDevice : RecoveryMode
}

/**
 * First-device bootstrap orchestrator. Kept out of Compose by design.
 *
 * Reconcile-first invariant: local crypto material is generated at most
 * once per device lifetime. Every uncertain outcome (transport failure,
 * timeout, 409, process death) reuses the sealed material and reconciles
 * through `GET /devices` identity matching. Nothing here regenerates an
 * identity because enrollment failed.
 *
 * Construction is explicit; no DI framework. Depends on the fakeable
 * [E2eeDeviceApi]/[DeviceMetadataStore] seams plus the real
 * [AndroidSignalAdapter]/[AndroidCryptoVault].
 */
class EnrollmentCoordinator(
    private val api: E2eeDeviceApi,
    private val metadata: DeviceMetadataStore,
    private val adapter: AndroidSignalAdapter,
    private val vault: AndroidCryptoVault,
) {
    private val running = AtomicBoolean(false)

    /** Local crypto set, either freshly generated or restored from the vault. */
    private data class LocalMaterial(
        val registrationId: Int,
        val identity: Identity,
        val signed: SignedPrekey,
        val kyber: KyberPrekey,
        val otpks: List<OneTimePrekey>,
    )

    private sealed interface MaterialLoad {
        data class Ready(val material: LocalMaterial) : MaterialLoad
        /** Keys referenced by marker/adopted record are unrecoverable. */
        data object Unrecoverable : MaterialLoad
    }

    fun hasAdoptedDevice(): Boolean = metadata.readAdopted() != null

    fun adoptedSummary(): AdoptedDevice? = metadata.readAdopted()

    /** Run first-bootstrap to completion in the calling session. Duplicate calls fail fast. */
    suspend fun runBootstrap(
        session: AuthSession,
        serverAddress: String,
        onProgress: (BootstrapProgress) -> Unit = {},
    ): BootstrapFinal {
        if (!running.compareAndSet(false, true)) {
            return BootstrapFinal.Failed(FailKind.ALREADY_RUNNING)
        }
        try {
            // Adopted device: refresh server truth, never trust the cache.
            metadata.readAdopted()?.let { adopted ->
                return refreshAdopted(session, serverAddress, adopted)
            }
            onProgress(BootstrapProgress.Preparing)
            val material = when (val load = loadOrGenerateMaterial()) {
                is MaterialLoad.Unrecoverable ->
                    return BootstrapFinal.Failed(FailKind.MISSING_MATERIAL)
                is MaterialLoad.Ready -> load.material
            }
            // Reconcile-first: adopt an existing row on identity match.
            when (val found = reconcile(session, serverAddress, identityB64(material))) {
                is ReconcileOutcome.Adopted -> return continueAfterAdopt(
                    session, serverAddress, found.device, material, onProgress
                )
                is ReconcileOutcome.NoneFound -> Unit // fall through to POST
                is ReconcileOutcome.Ambiguous ->
                    return BootstrapFinal.ReconciliationRequired("multiple-matching-devices")
                is ReconcileOutcome.Failed -> return found.final
            }
            onProgress(BootstrapProgress.Enrolling)
            val result = try {
                api.enroll(session, serverAddress, enrollRequest(material))
            } catch (e: EnrollException.Conflict) {
                return reconcileAfterConflict(session, serverAddress, material)
            } catch (e: EnrollException.RecoveryRequired) {
                return BootstrapFinal.RecoveryRequired
            } catch (e: EnrollException.Unauthorized) {
                return BootstrapFinal.Failed(FailKind.UNAUTHORIZED)
            } catch (e: EnrollException.BadRequest) {
                return BootstrapFinal.Failed(FailKind.REJECTED)
            } catch (e: EnrollException.ServerRejected) {
                return BootstrapFinal.Failed(FailKind.REJECTED)
            } catch (e: IOException) {
                return BootstrapFinal.Failed(FailKind.TRANSPORT_RETRYABLE)
            }
            // The server echoed our material: verify before trusting anything.
            if (result.device.deviceIdentityPublicKey != identityB64(material) ||
                result.device.registrationId != material.registrationId
            ) {
                return BootstrapFinal.Failed(FailKind.IDENTITY_MISMATCH)
            }
            persistAdopted(result.device, material, codesAcknowledged = false)
            pendingCodes = result.recoveryCodes?.takeIf { it.isNotEmpty() }
            return continueAfterAdopt(
                session, serverAddress, result.device, material, onProgress
            )
        } finally {
            pendingCodes = null
            running.set(false)
        }
    }

    /**
     * Confirm the transiently displayed recovery codes. Drops the codes from
     * memory (callers must release their reference) and records the ack.
     * Returns false when there is no adopted device to acknowledge for.
     */
    fun acknowledgeCodes(): Boolean {
        val adopted = metadata.readAdopted() ?: return false
        metadata.writeAdopted(adopted.copy(codesAcknowledged = true))
        return true
    }

    /**
     * Drop a dead lineage after [BootstrapFinal.Denied]: the adopted row is
     * REVOKED/absent server-side, so both the adopted record and the
     * attempt marker are cleared. The next [runBootstrap] generates fresh
     * material and POSTs a new row — the dead deviceId is never reused.
     * Clearing is legitimate here (not blind regeneration): Denied is only
     * entered from authoritative server truth.
     */
    fun clearDeniedState() {
        metadata.clearAdopted()
        metadata.clearAttempt()
    }

    /**
     * Load the owner device list for approval/recovery UI. Single-flight
     * like [runBootstrap]; safe to retry (read-only GET).
     */
    suspend fun loadApprovalView(
        session: AuthSession,
        serverAddress: String,
    ): ApprovalLoad {
        if (!running.compareAndSet(false, true)) {
            return ApprovalLoad.Failed(FailKind.ALREADY_RUNNING)
        }
        try {
            val list = try {
                api.listDevices(session, serverAddress)
            } catch (e: EnrollException.Unauthorized) {
                return ApprovalLoad.Failed(FailKind.UNAUTHORIZED)
            } catch (e: EnrollException) {
                return ApprovalLoad.Failed(FailKind.REJECTED)
            } catch (e: IOException) {
                return ApprovalLoad.Failed(FailKind.TRANSPORT_RETRYABLE)
            }
            val selfId = metadata.readAdopted()?.deviceId
            val self = selfId?.let { id -> list.devices.firstOrNull { it.deviceId == id } }
            val others = list.devices.filter { it.deviceId != selfId }
            return ApprovalLoad.Ready(
                ApprovalView(
                    selfDeviceId = self?.deviceId,
                    selfActive = self?.status == STATUS_ACTIVE,
                    pending = others.filter { it.status == STATUS_PENDING },
                    active = others.filter { it.status == STATUS_ACTIVE },
                )
            )
        } finally {
            running.set(false)
        }
    }

    /**
     * Approve one owned PENDING device from an ACTIVE-bound session.
     * Exactly one POST; the outcome always converges through a fresh
     * `GET /devices` — a 200 alone is not trusted without the row
     * reading ACTIVE.
     */
    suspend fun approvePendingDevice(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
    ): ApproveOutcome {
        if (!running.compareAndSet(false, true)) {
            return ApproveOutcome.Failed(FailKind.ALREADY_RUNNING)
        }
        try {
            try {
                api.approveDevice(session, serverAddress, deviceId)
            } catch (e: EnrollException.Unauthorized) {
                return ApproveOutcome.Failed(FailKind.UNAUTHORIZED)
            } catch (e: EnrollException.ServerRejected) {
                // 403 without the recovery reason: the server refused this
                // session (pending-bound, unbound, or foreign). Terminal.
                return ApproveOutcome.Denied
            } catch (e: EnrollException.NotFound) {
                return convergeApproveTarget(session, serverAddress, deviceId)
            } catch (e: EnrollException.Conflict) {
                // 409 here means the target is REVOKED; converge on truth.
                return convergeApproveTarget(session, serverAddress, deviceId)
            } catch (e: EnrollException.RecoveryRequired) {
                return ApproveOutcome.Failed(FailKind.REJECTED)
            } catch (e: EnrollException.BadRequest) {
                return ApproveOutcome.Failed(FailKind.REJECTED)
            } catch (e: EnrollException) {
                return ApproveOutcome.Failed(FailKind.REJECTED)
            } catch (e: IOException) {
                return ApproveOutcome.Failed(FailKind.TRANSPORT_RETRYABLE)
            }
            return convergeApproveTarget(session, serverAddress, deviceId)
        } finally {
            running.set(false)
        }
    }

    private suspend fun convergeApproveTarget(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
    ): ApproveOutcome {
        val list = try {
            api.listDevices(session, serverAddress)
        } catch (e: EnrollException.Unauthorized) {
            return ApproveOutcome.Failed(FailKind.UNAUTHORIZED)
        } catch (e: EnrollException) {
            return ApproveOutcome.Failed(FailKind.REJECTED)
        } catch (e: IOException) {
            return ApproveOutcome.Failed(FailKind.TRANSPORT_RETRYABLE)
        }
        val current = list.devices.firstOrNull { it.deviceId == deviceId }
            ?: return ApproveOutcome.Gone
        if (current.status == STATUS_ACTIVE) {
            return ApproveOutcome.Approved(deviceLabel(current))
        }
        if (current.status == STATUS_PENDING) {
            return ApproveOutcome.StillPending
        }
        return ApproveOutcome.Gone
    }

    /**
     * Recover with a single-use recovery code. Single-flight; the code is
     * a transient argument only. Transport uncertainty never blind-retries:
     * every uncertain outcome reconciles through `GET /devices` first, and
     * only proven success continues. A consumed-or-wrong code surfaces as
     * [BootstrapFinal.Failed] with [FailKind.REJECTED] so the UI can invite
     * another code from the set.
     */
    suspend fun recoverWithCode(
        session: AuthSession,
        serverAddress: String,
        recoveryCode: String,
        mode: RecoveryMode,
    ): BootstrapFinal {
        if (recoveryCode.isBlank()) {
            return BootstrapFinal.Failed(FailKind.REJECTED)
        }
        if (!running.compareAndSet(false, true)) {
            return BootstrapFinal.Failed(FailKind.ALREADY_RUNNING)
        }
        try {
            return when (mode) {
                is RecoveryMode.Bind ->
                    recoverBind(session, serverAddress, recoveryCode, mode.deviceId)
                RecoveryMode.NewDevice ->
                    recoverNewDevice(session, serverAddress, recoveryCode)
            }
        } finally {
            running.set(false)
        }
    }

    private suspend fun recoverBind(
        session: AuthSession,
        serverAddress: String,
        recoveryCode: String,
        deviceId: String,
    ): BootstrapFinal {
        val bound = try {
            api.bindDevice(session, serverAddress, deviceId, recoveryCode)
        } catch (e: EnrollException.Unauthorized) {
            return BootstrapFinal.Failed(FailKind.UNAUTHORIZED)
        } catch (e: EnrollException.Conflict) {
            // 409 is either an inactive target or SessionAlreadyBound. The
            // session started unbound and only ever attempted this target,
            // so an already-bound session proves a prior bind succeeded —
            // but only adopt when the target reads ACTIVE below.
            return convergeBoundDevice(session, serverAddress, deviceId)
        } catch (e: EnrollException.RecoveryRequired) {
            return BootstrapFinal.RecoveryRequired
        } catch (e: EnrollException) {
            // Wrong/used code (403), unknown device (404), bad shape (400).
            return BootstrapFinal.Failed(FailKind.REJECTED)
        } catch (e: IOException) {
            return BootstrapFinal.Failed(FailKind.TRANSPORT_RETRYABLE)
        }
        if (bound.status != STATUS_ACTIVE) {
            return BootstrapFinal.Failed(FailKind.REJECTED)
        }
        return convergeBoundDevice(session, serverAddress, bound.deviceId)
    }

    private suspend fun convergeBoundDevice(
        session: AuthSession,
        serverAddress: String,
        deviceId: String,
    ): BootstrapFinal {
        val list = try {
            api.listDevices(session, serverAddress)
        } catch (e: EnrollException.RecoveryRequired) {
            return BootstrapFinal.RecoveryRequired
        } catch (e: EnrollException.Unauthorized) {
            return BootstrapFinal.Failed(FailKind.UNAUTHORIZED)
        } catch (e: EnrollException) {
            return BootstrapFinal.Failed(FailKind.REJECTED)
        } catch (e: IOException) {
            return BootstrapFinal.Failed(FailKind.TRANSPORT_RETRYABLE)
        }
        val current = list.devices.firstOrNull { it.deviceId == deviceId }
            ?: return BootstrapFinal.Failed(FailKind.REJECTED)
        if (current.status != STATUS_ACTIVE) {
            return BootstrapFinal.Failed(FailKind.REJECTED)
        }
        persistAdoptedBind(current)
        return BootstrapFinal.Active(deviceLabel(current), codesAcknowledged = true)
    }

    private suspend fun recoverNewDevice(
        session: AuthSession,
        serverAddress: String,
        recoveryCode: String,
    ): BootstrapFinal {
        // Recovery ignores any stale adopted lineage: the adopted row is
        // dead by definition (zero ACTIVE account-wide), and reusing its
        // identity could collide with the revoked row. The attempt marker
        // (or fresh generation) is the legitimate lineage.
        val material = when (val load = loadRecoveryMaterial()) {
            is MaterialLoad.Unrecoverable ->
                return BootstrapFinal.Failed(FailKind.MISSING_MATERIAL)
            is MaterialLoad.Ready -> load.material
        }
        val created = try {
            api.recoverEnroll(session, serverAddress, recoveryCode, enrollRequest(material))
        } catch (e: EnrollException.Conflict) {
            return convergeRecoveryEnroll(session, serverAddress, material)
        } catch (e: EnrollException.RecoveryRequired) {
            return BootstrapFinal.RecoveryRequired
        } catch (e: EnrollException.Unauthorized) {
            return BootstrapFinal.Failed(FailKind.UNAUTHORIZED)
        } catch (e: EnrollException) {
            return BootstrapFinal.Failed(FailKind.REJECTED)
        } catch (e: IOException) {
            return BootstrapFinal.Failed(FailKind.TRANSPORT_RETRYABLE)
        }
        if (created.deviceIdentityPublicKey != identityB64(material)) {
            return BootstrapFinal.Failed(FailKind.IDENTITY_MISMATCH)
        }
        persistAdopted(created, material, codesAcknowledged = true)
        pendingCodes = null
        return asRecoveryComplete(continueAfterAdopt(session, serverAddress, created, material) {})
    }

    private suspend fun convergeRecoveryEnroll(
        session: AuthSession,
        serverAddress: String,
        material: LocalMaterial,
    ): BootstrapFinal {
        // 409 means this call created nothing. Only an ACTIVE row carrying
        // our identity proves a prior attempt succeeded (lost response);
        // anything else fails safe so the user spends another code.
        val list = try {
            api.listDevices(session, serverAddress)
        } catch (e: EnrollException.RecoveryRequired) {
            return BootstrapFinal.RecoveryRequired
        } catch (e: EnrollException.Unauthorized) {
            return BootstrapFinal.Failed(FailKind.UNAUTHORIZED)
        } catch (e: EnrollException) {
            return BootstrapFinal.Failed(FailKind.REJECTED)
        } catch (e: IOException) {
            return BootstrapFinal.Failed(FailKind.TRANSPORT_RETRYABLE)
        }
        val match = list.devices.firstOrNull {
            it.deviceIdentityPublicKey == identityB64(material) && it.status == STATUS_ACTIVE
        } ?: return BootstrapFinal.Failed(FailKind.REJECTED)
        persistAdopted(match, material, codesAcknowledged = true)
        if (match.availablePrekeys == 0L) {
            return asRecoveryComplete(continueAfterAdopt(session, serverAddress, match, material) {})
        }
        metadata.clearAttempt()
        return BootstrapFinal.Active(deviceLabel(match), codesAcknowledged = true)
    }

    private fun loadRecoveryMaterial(): MaterialLoad {
        metadata.readAttempt()?.let { attempt ->
            if (attempt.otpkIds.size != OTPK_BATCH_SIZE) return MaterialLoad.Unrecoverable
            return restoreFromHandles(
                registrationId = attempt.registrationId,
                identityHandleId = attempt.identityHandleId,
                signedHandleId = attempt.signedHandleId,
                kyberHandleId = attempt.kyberHandleId,
                otpkHandleIds = attempt.otpkHandleIds,
                otpkIds = attempt.otpkIds,
                expectedIdentityB64 = attempt.identityPublicKeyB64,
            )
        }
        return MaterialLoad.Ready(generateAndSeal())
    }

    /**
     * Recovery issues no codes, so there is nothing to acknowledge: map the
     * bootstrap continuation's `Active(acked=false)` to acked without
     * changing any other outcome.
     */
    private fun asRecoveryComplete(final: BootstrapFinal): BootstrapFinal =
        if (final is BootstrapFinal.Active) {
            final.copy(codesAcknowledged = true)
        } else {
            final
        }

    // ---- internals ----

    private sealed interface ReconcileOutcome {
        data class Adopted(val device: DeviceRecord) : ReconcileOutcome
        data object NoneFound : ReconcileOutcome
        data object Ambiguous : ReconcileOutcome
        data class Failed(val final: BootstrapFinal) : ReconcileOutcome
    }

    private suspend fun reconcile(
        session: AuthSession,
        serverAddress: String,
        identityB64: String,
    ): ReconcileOutcome {
        val list = try {
            api.listDevices(session, serverAddress)
        } catch (e: EnrollException.RecoveryRequired) {
            return ReconcileOutcome.Failed(BootstrapFinal.RecoveryRequired)
        } catch (e: EnrollException.Unauthorized) {
            return ReconcileOutcome.Failed(BootstrapFinal.Failed(FailKind.UNAUTHORIZED))
        } catch (e: EnrollException) {
            return ReconcileOutcome.Failed(BootstrapFinal.Failed(FailKind.REJECTED))
        } catch (e: IOException) {
            return ReconcileOutcome.Failed(BootstrapFinal.Failed(FailKind.TRANSPORT_RETRYABLE))
        }
        val matches = list.devices.filter { it.deviceIdentityPublicKey == identityB64 }
        return when (matches.size) {
            0 -> ReconcileOutcome.NoneFound
            1 -> ReconcileOutcome.Adopted(matches[0])
            else -> ReconcileOutcome.Ambiguous
        }
    }

    private suspend fun reconcileAfterConflict(
        session: AuthSession,
        serverAddress: String,
        material: LocalMaterial,
    ): BootstrapFinal {
        // 409 is never success: reconcile immediately, never blind-retry POST.
        return when (val found = reconcile(session, serverAddress, identityB64(material))) {
            is ReconcileOutcome.Adopted -> {
                persistAdopted(found.device, material, codesAcknowledged = false)
                continueAfterAdopt(session, serverAddress, found.device, material) {}
            }
            is ReconcileOutcome.NoneFound ->
                BootstrapFinal.ReconciliationRequired("conflict-unmatched")
            is ReconcileOutcome.Ambiguous ->
                BootstrapFinal.ReconciliationRequired("multiple-matching-devices")
            is ReconcileOutcome.Failed -> found.final
        }
    }

    private suspend fun continueAfterAdopt(
        session: AuthSession,
        serverAddress: String,
        device: DeviceRecord,
        material: LocalMaterial,
        onProgress: (BootstrapProgress) -> Unit = {},
    ): BootstrapFinal {
        persistAdopted(device, material, codesAcknowledged = false)
        if (device.status != STATUS_ACTIVE) {
            // PENDING (or anything unexpected): stop. No OTPK upload, no approval UI.
            return BootstrapFinal.PendingApproval(deviceLabel(device))
        }
        onProgress(BootstrapProgress.UploadingPrekeys)
        try {
            api.uploadOneTimePrekeys(
                session, serverAddress, device.deviceId, otpkBatch(material)
            )
        } catch (e: EnrollException.RecoveryRequired) {
            return BootstrapFinal.RecoveryRequired
        } catch (e: EnrollException.Unauthorized) {
            return BootstrapFinal.Failed(FailKind.UNAUTHORIZED)
        } catch (e: EnrollException) {
            return BootstrapFinal.Failed(FailKind.REJECTED)
        } catch (e: IOException) {
            // Provisioned on the server, upload uncertain: retain everything,
            // surface retryable failure; next run re-uploads the same batch.
            return BootstrapFinal.Failed(FailKind.TRANSPORT_RETRYABLE)
        }
        metadata.clearAttempt()
        return when (val codes = latestCodes()) {
            null -> BootstrapFinal.Active(deviceLabel(device), codesAcknowledged = false)
            else -> BootstrapFinal.AwaitingCodesAck(codes)
        }
    }

    /**
     * Recovery codes arrive only inside the enroll 201 ([pendingCodes], set
     * by the POST path and cleared after use). After adoption via
     * reconcile (commit-then-timeout), they are unrecoverable here —
     * rotation is future work — so the device goes Active-unacked rather
     * than falsely claiming code display.
     */
    private fun latestCodes(): List<String>? {
        val codes = pendingCodes
        pendingCodes = null
        return codes
    }

    private suspend fun refreshAdopted(
        session: AuthSession,
        serverAddress: String,
        adopted: AdoptedDevice,
    ): BootstrapFinal {
        val list = try {
            api.listDevices(session, serverAddress)
        } catch (e: EnrollException.RecoveryRequired) {
            return BootstrapFinal.RecoveryRequired
        } catch (e: EnrollException.Unauthorized) {
            return BootstrapFinal.Failed(FailKind.UNAUTHORIZED)
        } catch (e: EnrollException) {
            return BootstrapFinal.Failed(FailKind.REJECTED)
        } catch (e: IOException) {
            return BootstrapFinal.Failed(FailKind.TRANSPORT_RETRYABLE)
        }
        val current = list.devices.firstOrNull { it.deviceId == adopted.deviceId }
            ?: return BootstrapFinal.Denied(adoptedLabel(adopted))
        metadata.writeAdopted(
            adopted.copy(roleHint = current.deviceRole, statusHint = current.status)
        )
        if (current.status == STATUS_ACTIVE) {
            // Bind-adopted devices hold no local private material (bind
            // accepts none): server truth says ACTIVE, so report Active
            // without manufacturing handles. Downstream crypto paths keep
            // their existing fail-closed behavior.
            if (!adopted.hasLocalKeys) {
                return BootstrapFinal.Active(deviceLabel(current), adopted.codesAcknowledged)
            }
            // Keys may have vanished out-of-band while metadata survived: verify
            // before presenting Active. Messaging needs them; never pretend.
            if (!verifyIdentityAvailable(adopted)) {
                return BootstrapFinal.ReconciliationRequired("crypto-unavailable")
            }
            if (current.availablePrekeys == 0L) {
                // Crash landed between adoption and the first upload: finish
                // provisioning with the same sealed batch before going Active.
                return finishProvisioning(session, serverAddress, adopted, current)
            }
            return BootstrapFinal.Active(deviceLabel(current), adopted.codesAcknowledged)
        }
        if (current.status == STATUS_PENDING) {
            return BootstrapFinal.PendingApproval(deviceLabel(current))
        }
        // REVOKED, expired, or anything unexpected: the lineage is dead.
        // Distinct from reconciliation — the UI offers a fresh enrollment.
        return BootstrapFinal.Denied(deviceLabel(current))
    }

    /**
     * Re-upload the sealed 100-OTPK batch for an adopted-but-unprovisioned
     * device (server reports zero available prekeys). Same material, same
     * session-bound rules as the fresh path.
     */
    private suspend fun finishProvisioning(
        session: AuthSession,
        serverAddress: String,
        adopted: AdoptedDevice,
        current: DeviceRecord,
    ): BootstrapFinal {
        // Bind-adopted records carry no handles; without them there is no
        // batch to re-upload. Callers normally skip this path for such
        // records — this guard keeps it fail-closed regardless.
        val identityHandleId = adopted.identityHandleId
            ?: return BootstrapFinal.ReconciliationRequired("crypto-unavailable")
        val signedHandleId = adopted.signedHandleId
            ?: return BootstrapFinal.ReconciliationRequired("crypto-unavailable")
        val kyberHandleId = adopted.kyberHandleId
            ?: return BootstrapFinal.ReconciliationRequired("crypto-unavailable")
        val material = when (
            val load = restoreFromHandles(
                registrationId = adopted.registrationId,
                identityHandleId = identityHandleId,
                signedHandleId = signedHandleId,
                kyberHandleId = kyberHandleId,
                otpkHandleIds = adopted.otpkHandleIds,
                otpkIds = null,
                expectedIdentityB64 = adopted.identityPublicKeyB64,
            )
        ) {
            is MaterialLoad.Ready -> load.material
            is MaterialLoad.Unrecoverable ->
                return BootstrapFinal.ReconciliationRequired("crypto-unavailable")
        }
        try {
            api.uploadOneTimePrekeys(
                session, serverAddress, adopted.deviceId, otpkBatch(material)
            )
        } catch (e: EnrollException.RecoveryRequired) {
            return BootstrapFinal.RecoveryRequired
        } catch (e: EnrollException.Unauthorized) {
            return BootstrapFinal.Failed(FailKind.UNAUTHORIZED)
        } catch (e: EnrollException) {
            return BootstrapFinal.Failed(FailKind.REJECTED)
        } catch (e: IOException) {
            return BootstrapFinal.Failed(FailKind.TRANSPORT_RETRYABLE)
        }
        return BootstrapFinal.Active(deviceLabel(current), adopted.codesAcknowledged)
    }

    /** Best-effort presence check: unseal + restore the identity only. */
    private fun verifyIdentityAvailable(adopted: AdoptedDevice): Boolean = try {
        val handleId = adopted.identityHandleId ?: return false
        restoreIdentity(handleId)
        true
    } catch (_: VaultException) {
        false
    } catch (_: CryptoRecoveryException) {
        false
    } catch (_: IllegalArgumentException) {
        false
    }

    private fun loadOrGenerateMaterial(): MaterialLoad {
        metadata.readAdopted()?.let { adopted ->
            // Bind-adopted records carry no handles by design; they must
            // never reach the UUID parsers below (null would NPE).
            val identityHandleId = adopted.identityHandleId
                ?: return MaterialLoad.Unrecoverable
            val signedHandleId = adopted.signedHandleId
                ?: return MaterialLoad.Unrecoverable
            val kyberHandleId = adopted.kyberHandleId
                ?: return MaterialLoad.Unrecoverable
            return restoreFromHandles(
                registrationId = adopted.registrationId,
                identityHandleId = identityHandleId,
                signedHandleId = signedHandleId,
                kyberHandleId = kyberHandleId,
                otpkHandleIds = adopted.otpkHandleIds,
                otpkIds = null,
            )
        }
        metadata.readAttempt()?.let { attempt ->
            if (attempt.otpkIds.size != OTPK_BATCH_SIZE) return MaterialLoad.Unrecoverable
            return restoreFromHandles(
                registrationId = attempt.registrationId,
                identityHandleId = attempt.identityHandleId,
                signedHandleId = attempt.signedHandleId,
                kyberHandleId = attempt.kyberHandleId,
                otpkHandleIds = attempt.otpkHandleIds,
                otpkIds = attempt.otpkIds,
                expectedIdentityB64 = attempt.identityPublicKeyB64,
            )
        }
        return MaterialLoad.Ready(generateAndSeal())
    }

    private fun restoreFromHandles(
        registrationId: Int,
        identityHandleId: String,
        signedHandleId: String,
        kyberHandleId: String,
        otpkHandleIds: List<String>,
        otpkIds: List<Int>?,
        expectedIdentityB64: String? = null,
    ): MaterialLoad {
        return try {
            val identity = restoreIdentity(identityHandleId)
            val identityB64 = SpikeCryptoMaterial.encodeBase64(identity.publicKey)
            if (expectedIdentityB64 != null && identityB64 != expectedIdentityB64) {
                return MaterialLoad.Unrecoverable
            }
            val signed = restoreSigned(signedHandleId)
            val kyber = restoreKyber(kyberHandleId)
            val otpks = otpkHandleIds.mapIndexed { index, id ->
                restoreOtpk(id, otpkIds?.getOrNull(index))
            }
            if (otpks.size != OTPK_BATCH_SIZE) return MaterialLoad.Unrecoverable
            MaterialLoad.Ready(LocalMaterial(registrationId, identity, signed, kyber, otpks))
        } catch (_: VaultException) {
            MaterialLoad.Unrecoverable
        } catch (_: CryptoRecoveryException) {
            MaterialLoad.Unrecoverable
        } catch (_: IllegalArgumentException) {
            // Corrupt marker content (e.g. non-UUID handle IDs).
            MaterialLoad.Unrecoverable
        }
    }

    private fun restoreIdentity(handleId: String): Identity {
        val handle = SealedHandle(UUID.fromString(handleId), CryptoRecordKind.IDENTITY)
        val bytes = vault.unseal(handle, CryptoRecordKind.IDENTITY)
        return when (val r = adapter.restoreRecord(handle, bytes)) {
            is AndroidSignalAdapter.RestoredPublic.Identity -> r.value
            else -> throw CryptoRecoveryException("unexpected restore kind")
        }
    }

    private fun restoreSigned(handleId: String): SignedPrekey {
        val handle = SealedHandle(UUID.fromString(handleId), CryptoRecordKind.SIGNED_PREKEY)
        val bytes = vault.unseal(handle, CryptoRecordKind.SIGNED_PREKEY)
        return when (val r = adapter.restoreRecord(handle, bytes)) {
            is AndroidSignalAdapter.RestoredPublic.Signed -> r.value
            else -> throw CryptoRecoveryException("unexpected restore kind")
        }
    }

    private fun restoreKyber(handleId: String): KyberPrekey {
        val handle = SealedHandle(UUID.fromString(handleId), CryptoRecordKind.KYBER_PREKEY)
        val bytes = vault.unseal(handle, CryptoRecordKind.KYBER_PREKEY)
        return when (val r = adapter.restoreRecord(handle, bytes)) {
            is AndroidSignalAdapter.RestoredPublic.Kyber -> r.value
            else -> throw CryptoRecoveryException("unexpected restore kind")
        }
    }

    private fun restoreOtpk(handleId: String, expectedId: Int?): OneTimePrekey {
        val handle = SealedHandle(UUID.fromString(handleId), CryptoRecordKind.ONE_TIME_PREKEY)
        val bytes = vault.unseal(handle, CryptoRecordKind.ONE_TIME_PREKEY)
        return when (val r = adapter.restoreRecord(handle, bytes)) {
            is AndroidSignalAdapter.RestoredPublic.OneTime -> {
                if (expectedId != null && r.value.prekeyId != expectedId) {
                    throw CryptoRecoveryException("otpk id drift")
                }
                r.value
            }
            else -> throw CryptoRecoveryException("unexpected restore kind")
        }
    }

    private fun generateAndSeal(): LocalMaterial {
        val allocator = PrekeyIdAllocator()
        val registrationId = PrekeyIdAllocator.newRegistrationId()
        val identity = adapter.generateIdentity()
        val signed = adapter.generateSignedPrekey(identity, allocator.nextSignedPrekeyId())
        val kyber = adapter.generateKyberPrekey(identity, allocator.nextKyberPrekeyId())
        val otpks = allocator.nextOneTimePrekeyIds(OTPK_BATCH_SIZE).map { id ->
            adapter.generateOneTimePrekey(id)
        }
        vault.seal(identity.privateHandle, CryptoRecordKind.IDENTITY, adapter.exportRecord(identity.privateHandle))
        vault.seal(signed.privateHandle, CryptoRecordKind.SIGNED_PREKEY, adapter.exportRecord(signed.privateHandle))
        vault.seal(kyber.privateHandle, CryptoRecordKind.KYBER_PREKEY, adapter.exportRecord(kyber.privateHandle))
        otpks.forEach {
            vault.seal(it.privateHandle, CryptoRecordKind.ONE_TIME_PREKEY, adapter.exportRecord(it.privateHandle))
        }
        metadata.writeAttempt(
            EnrollmentAttempt(
                identityPublicKeyB64 = SpikeCryptoMaterial.encodeBase64(identity.publicKey),
                registrationId = registrationId,
                signedPrekeyId = signed.prekeyId,
                kyberPrekeyId = kyber.prekeyId,
                otpkIds = otpks.map { it.prekeyId },
                identityHandleId = identity.privateHandle.id.toString(),
                signedHandleId = signed.privateHandle.id.toString(),
                kyberHandleId = kyber.privateHandle.id.toString(),
                otpkHandleIds = otpks.map { it.privateHandle.id.toString() },
            )
        )
        return LocalMaterial(registrationId, identity, signed, kyber, otpks)
    }

    private fun enrollRequest(material: LocalMaterial): EnrollRequest = EnrollRequest(
        registrationId = material.registrationId,
        deviceIdentityPublicKey = SpikeCryptoMaterial.encodeBase64(material.identity.publicKey),
        signedPrekeyId = material.signed.prekeyId,
        signedPrekey = SpikeCryptoMaterial.encodeBase64(material.signed.publicKey),
        signedPrekeySignature = SpikeCryptoMaterial.encodeBase64(material.signed.signature),
        kyberPrekeyId = material.kyber.prekeyId,
        kyberPrekey = SpikeCryptoMaterial.encodeBase64(material.kyber.publicKey),
        kyberPrekeySignature = SpikeCryptoMaterial.encodeBase64(material.kyber.signature),
    )

    private fun otpkBatch(material: LocalMaterial): List<OneTimePrekeyUpload> {
        require(material.otpks.size == OTPK_BATCH_SIZE) { "OTPK batch must hold exactly 100" }
        val ids = material.otpks.map { it.prekeyId }
        require(ids.toSet().size == OTPK_BATCH_SIZE) { "OTPK IDs must be unique" }
        return material.otpks.map {
            OneTimePrekeyUpload(
                prekeyId = it.prekeyId,
                publicKey = SpikeCryptoMaterial.encodeBase64(it.publicKey),
            )
        }
    }

    private fun persistAdopted(
        device: DeviceRecord,
        material: LocalMaterial,
        codesAcknowledged: Boolean,
    ) {
        metadata.writeAdopted(
            AdoptedDevice(
                deviceId = device.deviceId,
                signalDeviceId = device.signalDeviceId,
                registrationId = material.registrationId,
                identityPublicKeyB64 = identityB64(material),
                signedPrekeyId = material.signed.prekeyId,
                kyberPrekeyId = material.kyber.prekeyId,
                otpkHighWaterMark = material.otpks.maxOf { it.prekeyId },
                roleHint = device.deviceRole,
                statusHint = device.status,
                identityHandleId = material.identity.privateHandle.id.toString(),
                signedHandleId = material.signed.privateHandle.id.toString(),
                kyberHandleId = material.kyber.privateHandle.id.toString(),
                otpkHandleIds = material.otpks.map { it.privateHandle.id.toString() },
                codesAcknowledged = codesAcknowledged,
            )
        )
    }

    private fun identityB64(material: LocalMaterial): String =
        SpikeCryptoMaterial.encodeBase64(material.identity.publicKey)

    private fun deviceLabel(device: DeviceRecord): String =
        "${device.deviceRole} · #${device.signalDeviceId}"

    private fun adoptedLabel(adopted: AdoptedDevice): String =
        "${adopted.roleHint} · #${adopted.signalDeviceId}"

    /**
     * Adopt a bind-recovered device: server truth only, no local handles
     * (bind accepts no key material — manufacturing them would be lying
     * about crypto capability). No codes are outstanding after a bind, so
     * the record starts acknowledged.
     */
    private fun persistAdoptedBind(device: DeviceRecord) {
        metadata.writeAdopted(
            AdoptedDevice(
                deviceId = device.deviceId,
                signalDeviceId = device.signalDeviceId,
                registrationId = device.registrationId,
                identityPublicKeyB64 = device.deviceIdentityPublicKey,
                signedPrekeyId = device.signedPrekeyId,
                kyberPrekeyId = device.kyberPrekeyId,
                otpkHighWaterMark = 0,
                roleHint = device.deviceRole,
                statusHint = device.status,
                identityHandleId = null,
                signedHandleId = null,
                kyberHandleId = null,
                otpkHandleIds = emptyList(),
                codesAcknowledged = true,
            )
        )
    }

    companion object {
        const val OTPK_BATCH_SIZE = 100
        const val STATUS_ACTIVE = "ACTIVE"
        const val STATUS_PENDING = "PENDING"
    }

    // Set by runBootstrap from the enroll 201 before continueAfterAdopt runs.
    // Carried as a field (not a parameter) to keep the adopt/reconcile paths
    // sharing one continuation; always cleared in the same call.
    private var pendingCodes: List<String>? = null
}
