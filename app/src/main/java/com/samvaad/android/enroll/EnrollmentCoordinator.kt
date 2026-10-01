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
            ?: return BootstrapFinal.ReconciliationRequired("adopted-device-unknown")
        metadata.writeAdopted(
            adopted.copy(roleHint = current.deviceRole, statusHint = current.status)
        )
        if (current.status != STATUS_ACTIVE) {
            return BootstrapFinal.PendingApproval(deviceLabel(current))
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
        val material = when (
            val load = restoreFromHandles(
                registrationId = adopted.registrationId,
                identityHandleId = adopted.identityHandleId,
                signedHandleId = adopted.signedHandleId,
                kyberHandleId = adopted.kyberHandleId,
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
        restoreIdentity(adopted.identityHandleId)
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
            return restoreFromHandles(
                registrationId = adopted.registrationId,
                identityHandleId = adopted.identityHandleId,
                signedHandleId = adopted.signedHandleId,
                kyberHandleId = adopted.kyberHandleId,
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

    companion object {
        const val OTPK_BATCH_SIZE = 100
        const val STATUS_ACTIVE = "ACTIVE"
    }

    // Set by runBootstrap from the enroll 201 before continueAfterAdopt runs.
    // Carried as a field (not a parameter) to keep the adopt/reconcile paths
    // sharing one continuation; always cleared in the same call.
    private var pendingCodes: List<String>? = null
}
