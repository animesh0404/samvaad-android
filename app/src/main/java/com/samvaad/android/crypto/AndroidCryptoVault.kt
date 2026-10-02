package com.samvaad.android.crypto

import android.content.Context
import com.samvaad.android.crypto.SpikeCryptoMaterial.SealedHandle
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.util.Arrays
import java.util.UUID

/**
 * Keystore-backed durable vault for libsignal private record blobs.
 *
 * Architecture: `record bytes → AES-GCM (Keystore wrapping key) →
 * versioned envelope file in [Context.getNoBackupFilesDir]`. The no-backup
 * location is the primary protection against cloning device identity via
 * cloud backup or device-to-device transfer (Keystore keys never leave the
 * device, so a restored blob without its key is undecryptable by design).
 *
 * Knows nothing about HTTP, enrollment, users, sessions, or UI: callers
 * pass opaque record bytes (produced by [AndroidSignalAdapter]) keyed by
 * ([SealedHandle], [CryptoRecordKind]). Filenames embed kind + UUID and
 * are deterministic: `<KIND>_<uuid>.svlt`.
 *
 * Fail-closed contract: missing key, GCM failure, truncation, version or
 * handle mismatch, and missing files all throw [VaultException] subtypes.
 * This class never generates crypto material and never recreates keys.
 */
class AndroidCryptoVault(
    context: Context,
    private val keys: WrappingKeyProvider,
    /**
     * Vault namespace directory under [Context.getNoBackupFilesDir].
     * Defaults to the local-identity record namespace; remote Signal
     * session blobs use `signal-sessions` with [CryptoRecordKind.SESSION].
     * Same wrapping key, separate directories, never mixed.
     */
    storeSubdir: String = STORE_SUBDIR,
) {
    init {
        // The namespace is internal API, but a `..`/separator value would
        // escape getNoBackupFilesDir() — reject it like the filename guard
        // below rejects non-UUID handle ids.
        require(storeSubdir.isNotBlank()) { "invalid vault namespace" }
        require(storeSubdir.none { it == '/' || it == '\\' }) { "invalid vault namespace" }
        require(storeSubdir != "." && storeSubdir != "..") { "invalid vault namespace" }
    }

    private val storeDir: File = File(context.noBackupFilesDir, storeSubdir).also {
        if (!it.isDirectory) it.mkdirs()
    }

    /** Encrypt [recordBytes] and durably store the envelope. */
    fun seal(handle: SealedHandle, kind: CryptoRecordKind, recordBytes: ByteArray) {
        require(handle.kind == kind) { "handle kind must match record kind" }
        val key = keys.getOrCreate()
        val envelope = RecordEnvelopeCodec.seal(key, kind, handle.id, recordBytes)
        // Best-effort plaintext hygiene: the caller's array is zeroed only
        // if the caller hands over ownership; here we zero our internal
        // envelope plaintext copies (none retained beyond this call).
        Arrays.fill(recordBytes, 0)
        try {
            fileFor(handle, kind).writeBytes(envelope)
        } catch (e: IOException) {
            throw VaultException.StorageFailure(e)
        } finally {
            Arrays.fill(envelope, 0)
        }
    }

    /**
     * Read, authenticate, and decrypt the envelope for [handle]/[kind].
     * Uses [WrappingKeyProvider.getExisting] only — a missing key fails
     * closed and never triggers key creation.
     */
    fun unseal(handle: SealedHandle, kind: CryptoRecordKind): ByteArray {
        require(handle.kind == kind) { "handle kind must match record kind" }
        val file = fileFor(handle, kind)
        val envelope = try {
            file.readBytes()
        } catch (e: FileNotFoundException) {
            throw VaultException.RecordMissing()
        } catch (e: IOException) {
            throw VaultException.StorageFailure(e)
        }
        if (envelope.isEmpty()) throw VaultException.CorruptEnvelope()
        val key = keys.getExisting() ?: throw VaultException.WrappingKeyMissing()
        return RecordEnvelopeCodec.unseal(key, kind, handle.id, envelope)
    }

    fun delete(handle: SealedHandle, kind: CryptoRecordKind) {
        require(handle.kind == kind) { "handle kind must match record kind" }
        fileFor(handle, kind).delete()
    }

    fun exists(handle: SealedHandle, kind: CryptoRecordKind): Boolean {
        require(handle.kind == kind) { "handle kind must match record kind" }
        return fileFor(handle, kind).isFile
    }

    private fun fileFor(handle: SealedHandle, kind: CryptoRecordKind): File {
        // UUID rendered canonically; kind prefix keeps the directory
        // self-describing without exposing any key material.
        val name = "${kind.name}_${handle.id}.svlt"
        // Guard against path traversal even though both parts are generated
        // internally (UUID format + enum name contain no separators).
        require(handle.id.toString().matches(UUID_PATTERN)) { "invalid handle id" }
        return File(storeDir, name)
    }

    companion object {
        const val STORE_SUBDIR = "crypto-vault"
        private val UUID_PATTERN =
            Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
    }
}
