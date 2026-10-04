package com.samvaad.android.session

import android.content.Context
import java.io.File
import java.io.IOException
import org.json.JSONException
import org.json.JSONObject

/**
 * Durable per-conversation history-sync frontier hints (Slice 12).
 *
 * Stores only `lastSeenFrontier` per conversation: the highest
 * Primary-advertised export frontier observed inside an authenticated
 * sync payload. The durable sync position itself is NOT stored here —
 * it derives from Room contiguity (`highestContiguous`), exactly like
 * the delivery cursor model. Semantics: synced-contiguous ==
 * lastSeenFrontier means complete-as-of-frontier; lower means pending;
 * a newly observed lower frontier than previously stored is an
 * explicit anomaly the caller must surface, never silently accept.
 *
 * Same storage pattern as [SessionMetadataStore]/[DeviceMetadataStore]:
 * one small JSON file under `getNoBackupFilesDir()` (sync frontiers
 * are device-local progress, never backup material). Unknown
 * conversation (absent key) reads as "no frontier yet" — pending, the
 * safe default after data loss.
 */
interface SyncMetadataStore {
    /** Last authenticated frontier observed, or null when never seen. */
    fun readFrontier(conversationId: String): Long?

    /**
     * Records a frontier. Callers must only pass frontiers from
     * successfully validated sync payloads, and must surface (not
     * store over) regressions they detect first.
     */
    fun writeFrontier(conversationId: String, frontier: Long)

    companion object {
        const val SCHEMA_VERSION = 1
    }
}

class FileSyncMetadataStore(context: Context) : SyncMetadataStore {
    private val file: File =
        File(File(context.noBackupFilesDir, SUBDIR), FILE_NAME).also {
            it.parentFile?.mkdirs()
        }

    override fun readFrontier(conversationId: String): Long? = try {
        readRoot()?.optLong(conversationId, Long.MIN_VALUE)
            ?.takeIf { it != Long.MIN_VALUE }
    } catch (_: Exception) {
        null
    }

    override fun writeFrontier(conversationId: String, frontier: Long) {
        try {
            val root = readRoot() ?: JSONObject()
            root.put(conversationId, frontier)
            writeRoot(root)
        } catch (e: JSONException) {
            throw IOException(e)
        }
    }

    private fun readRoot(): JSONObject? = try {
        if (!file.isFile) null else JSONObject(file.readText(Charsets.UTF_8))
    } catch (_: IOException) {
        null
    } catch (_: JSONException) {
        null
    }

    private fun writeRoot(root: JSONObject) {
        val tmp = File(file.parentFile, "$FILE_NAME.tmp")
        tmp.writeText(root.toString(), Charsets.UTF_8)
        if (!tmp.renameTo(file)) throw IOException("sync metadata persist failed")
    }

    companion object {
        const val SUBDIR = "sync-metadata"
        const val FILE_NAME = "sync-frontiers.json"
    }
}
