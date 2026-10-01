package com.samvaad.android.session

import android.content.Context
import com.samvaad.android.crypto.RecordEnvelopeCodec
import com.samvaad.android.crypto.VaultException
import com.samvaad.android.crypto.WrappingKeyProvider
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.util.UUID
import org.json.JSONException
import org.json.JSONObject

/**
 * [SessionStore] sealed under the existing Keystore wrapping key
 * (same alias as the crypto vault — one key, separate namespaces).
 *
 * Single deterministic file (`session/session.svlt` under
 * `getNoBackupFilesDir()`): a device-bound refresh token must never ride
 * cloud backup or device-to-device transfer. Envelope kind byte
 * [SESSION_KIND] and fixed handle [SESSION_HANDLE_ID] isolate this
 * namespace from crypto-vault records; AAD binds them to the ciphertext.
 *
 * Write path is temp-file + rename. Reads tolerate absence (null) and
 * fail closed on anything else. Never logs tokens.
 */
class FileSessionStore(
    context: Context,
    private val keys: WrappingKeyProvider,
) : SessionStore {

    private val file: File =
        File(File(context.noBackupFilesDir, SUBDIR), FILE_NAME).also {
            it.parentFile?.mkdirs()
        }

    override fun save(record: PersistedSession) {
        val key = try {
            keys.getOrCreate()
        } catch (e: Exception) {
            throw SessionStoreException("wrapping key unavailable", e)
        }
        val plaintext = serialize(record).toByteArray(Charsets.UTF_8)
        try {
            val envelope = RecordEnvelopeCodec.seal(key, SESSION_KIND, SESSION_HANDLE_ID, plaintext)
            java.util.Arrays.fill(plaintext, 0)
            val tmp = File(file.parent, "$FILE_NAME.tmp")
            try {
                tmp.writeBytes(envelope)
            } finally {
                java.util.Arrays.fill(envelope, 0)
            }
            if (!tmp.renameTo(file)) {
                tmp.delete()
                throw SessionStoreException("session write failed")
            }
        } catch (e: SessionStoreException) {
            throw e
        } catch (e: IOException) {
            throw SessionStoreException("session write failed", e)
        } catch (e: IllegalArgumentException) {
            throw SessionStoreException("session write failed", e)
        } finally {
            java.util.Arrays.fill(plaintext, 0)
        }
    }

    override fun load(): PersistedSession? {
        if (!file.isFile) return null
        val envelope = try {
            file.readBytes()
        } catch (e: FileNotFoundException) {
            return null
        } catch (e: IOException) {
            throw SessionStoreException("session read failed", e)
        }
        val key = try {
            keys.getExisting() ?: throw SessionStoreException(
                "wrapping key unavailable",
                keyMissing = true,
            )
        } catch (e: SessionStoreException) {
            throw e
        } catch (e: Exception) {
            throw SessionStoreException("wrapping key unavailable", e)
        }
        val plaintext = try {
            RecordEnvelopeCodec.unseal(key, SESSION_KIND, SESSION_HANDLE_ID, envelope)
        } catch (e: VaultException) {
            throw SessionStoreException("stored session failed integrity validation", e)
        }
        try {
            return parse(String(plaintext, Charsets.UTF_8))
        } finally {
            java.util.Arrays.fill(plaintext, 0)
        }
    }

    override fun clear() {
        try {
            file.delete()
            File(file.parent, "$FILE_NAME.tmp").delete()
        } catch (_: Exception) {
            // Best effort: a stale file only repeats the login outcome.
        }
    }

    private fun serialize(record: PersistedSession): String = JSONObject()
        .put("schemaVersion", SessionStore.SCHEMA_VERSION)
        .put("serverAddress", record.serverAddress)
        .put("identifier", record.identifier)
        .put("refreshToken", record.refreshToken)
        .put("sessionId", record.sessionId)
        .put("refreshExpiresAtEpochMillis", record.refreshExpiresAtEpochMillis)
        .toString()

    private fun parse(raw: String): PersistedSession {
        try {
            val json = JSONObject(raw)
            if (json.getInt("schemaVersion") != SessionStore.SCHEMA_VERSION) {
                throw SessionStoreException("unsupported session version")
            }
            val serverAddress = json.getString("serverAddress")
            if (!serverAddress.startsWith("https://")) {
                throw SessionStoreException("stored session failed validation")
            }
            // UUID format gate: a non-UUID sessionId can never authenticate.
            UUID.fromString(json.getString("sessionId"))
            return PersistedSession(
                serverAddress = serverAddress,
                identifier = json.getString("identifier"),
                refreshToken = json.getString("refreshToken"),
                sessionId = json.getString("sessionId"),
                refreshExpiresAtEpochMillis = json.getLong("refreshExpiresAtEpochMillis"),
            )
        } catch (e: SessionStoreException) {
            throw e
        } catch (e: JSONException) {
            throw SessionStoreException("stored session failed validation", e)
        } catch (e: IllegalArgumentException) {
            throw SessionStoreException("stored session failed validation", e)
        }
    }

    companion object {
        const val SUBDIR = "session"
        const val FILE_NAME = "session.svlt"

        /** Envelope namespace for the session record (crypto kinds are 0x01–0x04). */
        const val SESSION_KIND: Byte = 0x10

        /** Fixed handle: exactly one session record exists per installation. */
        val SESSION_HANDLE_ID: UUID =
            UUID.nameUUIDFromBytes("samvaad-auth-session-v1".toByteArray(Charsets.UTF_8))

        /** Test-only hook: read raw file bytes for no-plaintext scans. */
        fun rawFile(context: Context): File =
            File(File(context.noBackupFilesDir, SUBDIR), FILE_NAME)
    }
}
