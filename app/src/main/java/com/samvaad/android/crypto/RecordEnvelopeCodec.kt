package com.samvaad.android.crypto

import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Pure-JVM versioned AES-GCM envelope codec for libsignal record blobs.
 *
 * No Android APIs, no libsignal types, no I/O: encryption/decryption over
 * caller-supplied bytes with a caller-supplied [SecretKey]. Storage and
 * key custody live in [AndroidCryptoVault] / [WrappingKeyProvider].
 *
 * Layout (all integers big-endian):
 * ```
 * magic "SVLT" (4) | version u8 (1) | kind u8 (1) | uuid (16) |
 * ivLen u8 (1) | iv (ivLen) | ciphertext (rest)
 * ```
 * AAD binds the non-secret metadata to the ciphertext:
 * `AAD = magic | version | kind | uuid`. Swapping ciphertext between
 * records/kinds, or tampering with the header, fails GCM authentication.
 * A fresh random IV is generated for every [seal] by the platform Cipher.
 */
object RecordEnvelopeCodec {

    const val CURRENT_VERSION: Int = 1

    private val MAGIC = byteArrayOf(0x53, 0x56, 0x4C, 0x54) // "SVLT"
    private const val GCM_TAG_BITS = 128

    data class ParsedEnvelope(
        val version: Int,
        val kind: CryptoRecordKind,
        val handleId: UUID,
        val iv: ByteArray,
        val ciphertext: ByteArray,
    )

    /** Encrypt [recordBytes] into a self-describing envelope. */
    fun seal(
        key: SecretKey,
        kind: CryptoRecordKind,
        handleId: UUID,
        recordBytes: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        require(iv.isNotEmpty()) { "platform Cipher produced no GCM IV" }
        cipher.updateAAD(aad(kind, handleId))
        val ciphertext = cipher.doFinal(recordBytes)
        return buildEnvelope(kind, handleId, iv, ciphertext)
    }

    /**
     * Decrypt [envelope] for the expected [kind]/[handleId].
     *
     * @throws VaultException.UnknownVersion envelope version not understood
     * @throws VaultException.HandleMismatch kind/UUID mismatch
     * @throws VaultException.CorruptEnvelope truncation, GCM failure, bad IV
     */
    fun unseal(
        key: SecretKey,
        kind: CryptoRecordKind,
        handleId: UUID,
        envelope: ByteArray,
    ): ByteArray {
        val parsed = parse(envelope)
        if (parsed.version != CURRENT_VERSION) {
            throw VaultException.UnknownVersion(parsed.version)
        }
        if (parsed.kind != kind || parsed.handleId != handleId) {
            throw VaultException.HandleMismatch()
        }
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(GCM_TAG_BITS, parsed.iv),
            )
            cipher.updateAAD(aad(kind, handleId))
            return cipher.doFinal(parsed.ciphertext)
        } catch (e: GeneralSecurityException) {
            throw VaultException.CorruptEnvelope()
        } catch (e: IllegalArgumentException) {
            throw VaultException.CorruptEnvelope()
        }
    }

    /**
     * Structural parse only (no decryption). Exposed for tests; production
     * recovery always goes through [unseal].
     *
     * @throws VaultException.CorruptEnvelope on truncation/bad magic/IV
     * @throws VaultException.UnknownVersion handled by caller ([unseal]
     * converts post-parse; parse itself surfaces only structural failure —
     * unknown *kind codes* are corrupt, unknown *versions* pass through
     * with their version number for the caller to reject explicitly)
     */
    fun parse(envelope: ByteArray): ParsedEnvelope {
        val minSize = MAGIC.size + 1 + 1 + 16 + 1
        if (envelope.size < minSize) throw VaultException.CorruptEnvelope()
        val buf = ByteBuffer.wrap(envelope)
        val magic = ByteArray(MAGIC.size)
        buf.get(magic)
        if (!magic.contentEquals(MAGIC)) throw VaultException.CorruptEnvelope()
        val version = buf.get().toInt() and 0xFF
        val kindCode = buf.get()
        val msb = buf.long
        val lsb = buf.long
        val ivLen = buf.get().toInt() and 0xFF
        if (ivLen <= 0 || buf.remaining() < ivLen) throw VaultException.CorruptEnvelope()
        val iv = ByteArray(ivLen)
        buf.get(iv)
        val ciphertext = ByteArray(buf.remaining())
        buf.get(ciphertext)
        if (ciphertext.isEmpty()) throw VaultException.CorruptEnvelope()
        // Kind codes outside the known set are structural corruption; the
        // version gate stays the caller's explicit decision.
        val kind = CryptoRecordKind.fromCode(kindCode)
            ?: throw VaultException.CorruptEnvelope()
        return ParsedEnvelope(version, kind, UUID(msb, lsb), iv, ciphertext)
    }

    private fun buildEnvelope(
        kind: CryptoRecordKind,
        handleId: UUID,
        iv: ByteArray,
        ciphertext: ByteArray,
    ): ByteArray {
        require(iv.size in 1..255) { "IV length out of envelope range" }
        val buf = ByteBuffer.allocate(
            MAGIC.size + 1 + 1 + 16 + 1 + iv.size + ciphertext.size
        )
        buf.put(MAGIC)
        buf.put(CURRENT_VERSION.toByte())
        buf.put(kind.code)
        buf.putLong(handleId.mostSignificantBits)
        buf.putLong(handleId.leastSignificantBits)
        buf.put(iv.size.toByte())
        buf.put(iv)
        buf.put(ciphertext)
        return buf.array()
    }

    private fun aad(kind: CryptoRecordKind, handleId: UUID): ByteArray {
        val buf = ByteBuffer.allocate(MAGIC.size + 1 + 1 + 16)
        buf.put(MAGIC)
        buf.put(CURRENT_VERSION.toByte())
        buf.put(kind.code)
        buf.putLong(handleId.mostSignificantBits)
        buf.putLong(handleId.leastSignificantBits)
        return buf.array()
    }
}
