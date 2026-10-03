package com.samvaad.android.enroll

import android.content.Context
import java.io.File
import java.io.IOException
import org.json.JSONException
import org.json.JSONObject

/**
 * Durable non-secret enrollment metadata.
 *
 * Two records, one small JSON file under `getNoBackupFilesDir()` (device
 * identity must not clone to another device; same reasoning as the vault):
 *
 * - attempt marker: local crypto whose server outcome may be unresolved.
 *   Written BEFORE any POST so crash/timeout recovery reuses the same
 *   material instead of regenerating it.
 * - adopted device: server-assigned metadata + allocator high-water marks.
 *   A hint cache only — status/role/approval truth is re-read from
 *   `GET /api/e2ee/devices` and always wins on disagreement.
 *
 * NEVER stores: private key bytes, recovery codes, auth tokens. Callers
 * must not place them here; a unit test scans the serialized file.
 */
data class EnrollmentAttempt(
    val schemaVersion: Int = DeviceMetadataStore.SCHEMA_VERSION,
    val identityPublicKeyB64: String,
    val registrationId: Int,
    val signedPrekeyId: Int,
    val kyberPrekeyId: Int,
    val otpkIds: List<Int>,
    /** Vault handle UUIDs needed to unseal after process death. Non-secret. */
    val identityHandleId: String,
    val signedHandleId: String,
    val kyberHandleId: String,
    val otpkHandleIds: List<String>,
)

data class AdoptedDevice(
    val schemaVersion: Int = DeviceMetadataStore.SCHEMA_VERSION,
    val deviceId: String,
    val signalDeviceId: Int,
    val registrationId: Int,
    val identityPublicKeyB64: String,
    val signedPrekeyId: Int,
    val kyberPrekeyId: Int?,
    val otpkHighWaterMark: Int,
    val roleHint: String,
    val statusHint: String,
    /**
     * Vault handle UUIDs for future crypto operations. Non-secret.
     *
     * Null when this installation holds no private material for the
     * device — exactly the bind-existing-device case
     * (`POST /devices/{id}/bind` accepts no key material). Null handles
     * must never be manufactured; crypto paths fail closed without them.
     */
    val identityHandleId: String?,
    val signedHandleId: String?,
    val kyberHandleId: String?,
    val otpkHandleIds: List<String>,
    /**
     * Whether the first-bootstrap codes were displayed AND acknowledged.
     * False after crash-before-ack: the device is still adopted, but the UI
     * must not claim bootstrap is fully complete (codes are unrecoverable;
     * rotation is future work).
     */
    val codesAcknowledged: Boolean,
) {
    /** True only when every private-material handle is present locally. */
    val hasLocalKeys: Boolean
        get() = identityHandleId != null &&
            signedHandleId != null &&
            kyberHandleId != null &&
            otpkHandleIds.isNotEmpty()
}

interface DeviceMetadataStore {
    fun readAttempt(): EnrollmentAttempt?
    fun writeAttempt(attempt: EnrollmentAttempt)
    fun clearAttempt()
    fun readAdopted(): AdoptedDevice?
    fun writeAdopted(device: AdoptedDevice)
    fun clearAdopted()

    companion object {
        const val SCHEMA_VERSION = 1
    }
}

class FileDeviceMetadataStore(context: Context) : DeviceMetadataStore {
    private val file: File =
        File(File(context.noBackupFilesDir, SUBDIR), FILE_NAME).also {
            it.parentFile?.mkdirs()
        }

    override fun readAttempt(): EnrollmentAttempt? =
        readRoot()?.optJSONObject("attempt")?.let(::parseAttempt)

    override fun writeAttempt(attempt: EnrollmentAttempt) {
        val root = readRoot() ?: JSONObject()
        root.put("attempt", serializeAttempt(attempt))
        writeRoot(root)
    }

    override fun clearAttempt() {
        val root = readRoot() ?: return
        root.remove("attempt")
        writeRoot(root)
    }

    override fun readAdopted(): AdoptedDevice? =
        readRoot()?.optJSONObject("adopted")?.let(::parseAdopted)

    override fun writeAdopted(device: AdoptedDevice) {
        val root = readRoot() ?: JSONObject()
        root.put("adopted", serializeAdopted(device))
        writeRoot(root)
    }

    override fun clearAdopted() {
        val root = readRoot() ?: return
        root.remove("adopted")
        writeRoot(root)
    }

    private fun readRoot(): JSONObject? {
        return try {
            if (!file.isFile) return null
            JSONObject(file.readText(Charsets.UTF_8))
        } catch (_: IOException) {
            null
        } catch (_: JSONException) {
            null
        }
    }

    private fun writeRoot(root: JSONObject) {
        // Atomic-ish: temp + rename; readers tolerate absence, never partial JSON.
        val tmp = File(file.parent, "$FILE_NAME.tmp")
        tmp.writeText(root.toString(), Charsets.UTF_8)
        if (!tmp.renameTo(file)) {
            tmp.delete()
            throw IOException("metadata write failed")
        }
    }

    private fun serializeAttempt(a: EnrollmentAttempt): JSONObject = JSONObject()
        .put("schemaVersion", a.schemaVersion)
        .put("identityPublicKeyB64", a.identityPublicKeyB64)
        .put("registrationId", a.registrationId)
        .put("signedPrekeyId", a.signedPrekeyId)
        .put("kyberPrekeyId", a.kyberPrekeyId)
        .put("otpkIds", a.otpkIds.joinToString(","))
        .put("identityHandleId", a.identityHandleId)
        .put("signedHandleId", a.signedHandleId)
        .put("kyberHandleId", a.kyberHandleId)
        .put("otpkHandleIds", a.otpkHandleIds.joinToString(","))
        .put("createdAt", System.currentTimeMillis())

    private fun parseAttempt(json: JSONObject): EnrollmentAttempt? {
        return try {
            if (json.getInt("schemaVersion") != DeviceMetadataStore.SCHEMA_VERSION) return null
            val ids = json.getString("otpkIds")
                .split(",").filter { it.isNotEmpty() }.map { it.toInt() }
            EnrollmentAttempt(
                identityPublicKeyB64 = json.getString("identityPublicKeyB64"),
                registrationId = json.getInt("registrationId"),
                signedPrekeyId = json.getInt("signedPrekeyId"),
                kyberPrekeyId = json.getInt("kyberPrekeyId"),
                otpkIds = ids,
                identityHandleId = json.getString("identityHandleId"),
                signedHandleId = json.getString("signedHandleId"),
                kyberHandleId = json.getString("kyberHandleId"),
                otpkHandleIds = json.getString("otpkHandleIds")
                    .split(",").filter { it.isNotEmpty() },
            )
        } catch (_: JSONException) {
            null
        } catch (_: NumberFormatException) {
            null
        }
    }

    private fun serializeAdopted(d: AdoptedDevice): JSONObject = JSONObject()
        .put("schemaVersion", d.schemaVersion)
        .put("deviceId", d.deviceId)
        .put("signalDeviceId", d.signalDeviceId)
        .put("registrationId", d.registrationId)
        .put("identityPublicKeyB64", d.identityPublicKeyB64)
        .put("signedPrekeyId", d.signedPrekeyId)
        .put("kyberPrekeyId", d.kyberPrekeyId ?: JSONObject.NULL)
        .put("otpkHighWaterMark", d.otpkHighWaterMark)
        .put("roleHint", d.roleHint)
        .put("statusHint", d.statusHint)
        .put("identityHandleId", d.identityHandleId ?: JSONObject.NULL)
        .put("signedHandleId", d.signedHandleId ?: JSONObject.NULL)
        .put("kyberHandleId", d.kyberHandleId ?: JSONObject.NULL)
        .put("otpkHandleIds", d.otpkHandleIds.joinToString(","))
        .put("codesAcknowledged", d.codesAcknowledged)

    private fun parseAdopted(json: JSONObject): AdoptedDevice? {
        return try {
            if (json.getInt("schemaVersion") != DeviceMetadataStore.SCHEMA_VERSION) return null
            AdoptedDevice(
                deviceId = json.getString("deviceId"),
                signalDeviceId = json.getInt("signalDeviceId"),
                registrationId = json.getInt("registrationId"),
                identityPublicKeyB64 = json.getString("identityPublicKeyB64"),
                signedPrekeyId = json.getInt("signedPrekeyId"),
                kyberPrekeyId = if (json.isNull("kyberPrekeyId")) {
                    null
                } else {
                    json.getInt("kyberPrekeyId")
                },
                otpkHighWaterMark = json.getInt("otpkHighWaterMark"),
                roleHint = json.getString("roleHint"),
                statusHint = json.getString("statusHint"),
                // isNull covers both absent keys and explicit JSON nulls.
                identityHandleId = if (json.isNull("identityHandleId")) {
                    null
                } else {
                    json.getString("identityHandleId")
                },
                signedHandleId = if (json.isNull("signedHandleId")) {
                    null
                } else {
                    json.getString("signedHandleId")
                },
                kyberHandleId = if (json.isNull("kyberHandleId")) {
                    null
                } else {
                    json.getString("kyberHandleId")
                },
                otpkHandleIds = json.getString("otpkHandleIds")
                    .split(",").filter { it.isNotEmpty() },
                codesAcknowledged = json.optBoolean("codesAcknowledged", false),
            )
        } catch (_: JSONException) {
            null
        }
    }

    companion object {
        const val SUBDIR = "device-metadata"
        const val FILE_NAME = "enrollment.json"

        /** Test-only hook: read raw file bytes for no-secret scans. */
        fun rawFile(context: Context): File =
            File(File(context.noBackupFilesDir, SUBDIR), FILE_NAME)
    }
}
