package com.samvaad.android.session

import android.content.Context
import java.io.File
import java.io.IOException
import org.json.JSONException
import org.json.JSONObject

/**
 * How the durable session was established: with a consumed one-time
 * prekey, or via the signed-prekey fallback (empty OTPK pool).
 */
enum class EstablishedVia {
    WITH_OTPK,
    SIGNED_FALLBACK,
}

/**
 * Durable non-secret metadata for one remote Signal session, keyed by the
 * server's remote `deviceId` UUID (the application-level session key).
 *
 * The Signal address (`remoteUsername` + `remoteSignalDeviceId`) and the
 * pinned remote identity are recorded together so reuse can verify all
 * three before trusting the sealed SessionRecord blob. The remote
 * identity public key is public material, not a secret — but it is never
 * logged and never rendered.
 *
 * NEVER stores: private key bytes, session plaintext, auth tokens.
 */
data class SignalSessionEntry(
    val schemaVersion: Int = SessionMetadataStore.SCHEMA_VERSION,
    val remoteDeviceId: String,
    val remoteUsername: String,
    val remoteSignalDeviceId: Int,
    val remoteRegistrationId: Int,
    val remoteIdentityPublicKeyB64: String,
    val establishedVia: EstablishedVia,
    /** Adopted local identity's vault handle UUID (non-secret). */
    val localIdentityHandleId: String,
    val createdAt: Long,
    val updatedAt: Long,
)

interface SessionMetadataStore {
    fun read(remoteDeviceId: String): SignalSessionEntry?
    fun write(entry: SignalSessionEntry)
    fun remove(remoteDeviceId: String)
    fun listAll(): List<SignalSessionEntry>

    companion object {
        const val SCHEMA_VERSION = 1
    }
}

class FileSessionMetadataStore(context: Context) : SessionMetadataStore {
    private val file: File =
        File(File(context.noBackupFilesDir, SUBDIR), FILE_NAME).also {
            it.parentFile?.mkdirs()
        }

    override fun read(remoteDeviceId: String): SignalSessionEntry? =
        readRoot()?.optJSONObject(remoteDeviceId)?.let(::parseEntry)

    override fun write(entry: SignalSessionEntry) {
        val root = readRoot() ?: JSONObject()
        root.put(entry.remoteDeviceId, serializeEntry(entry))
        writeRoot(root)
    }

    override fun remove(remoteDeviceId: String) {
        val root = readRoot() ?: return
        root.remove(remoteDeviceId)
        writeRoot(root)
    }

    override fun listAll(): List<SignalSessionEntry> {
        val root = readRoot() ?: return emptyList()
        return root.keys().asSequence()
            .mapNotNull { runCatching { root.getJSONObject(it) }.getOrNull() }
            .mapNotNull(::parseEntry)
            .toList()
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
            throw IOException("session metadata write failed")
        }
    }

    private fun serializeEntry(e: SignalSessionEntry): JSONObject = JSONObject()
        .put("schemaVersion", e.schemaVersion)
        .put("remoteDeviceId", e.remoteDeviceId)
        .put("remoteUsername", e.remoteUsername)
        .put("remoteSignalDeviceId", e.remoteSignalDeviceId)
        .put("remoteRegistrationId", e.remoteRegistrationId)
        .put("remoteIdentityPublicKeyB64", e.remoteIdentityPublicKeyB64)
        .put("establishedVia", e.establishedVia.name)
        .put("localIdentityHandleId", e.localIdentityHandleId)
        .put("createdAt", e.createdAt)
        .put("updatedAt", e.updatedAt)

    private fun parseEntry(json: JSONObject): SignalSessionEntry? {
        return try {
            if (json.getInt("schemaVersion") != SessionMetadataStore.SCHEMA_VERSION) return null
            SignalSessionEntry(
                remoteDeviceId = json.getString("remoteDeviceId"),
                remoteUsername = json.getString("remoteUsername"),
                remoteSignalDeviceId = json.getInt("remoteSignalDeviceId"),
                remoteRegistrationId = json.getInt("remoteRegistrationId"),
                remoteIdentityPublicKeyB64 = json.getString("remoteIdentityPublicKeyB64"),
                establishedVia = EstablishedVia.valueOf(json.getString("establishedVia")),
                localIdentityHandleId = json.getString("localIdentityHandleId"),
                createdAt = json.getLong("createdAt"),
                updatedAt = json.getLong("updatedAt"),
            )
        } catch (_: JSONException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    companion object {
        const val SUBDIR = "signal-sessions"
        const val FILE_NAME = "sessions.json"

        /** Test-only hook: read raw file bytes for no-secret scans. */
        fun rawFile(context: Context): File =
            File(File(context.noBackupFilesDir, SUBDIR), FILE_NAME)
    }
}
