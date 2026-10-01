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
        val kindCode: Byte,
        val kind: CryptoRecordKind?,
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
    ): ByteArray = seal(key, kind.code, handleId, recordBytes)

    /**
     * Byte-oriented seal for non-crypto namespaces (e.g. the session
     * store). Same layout, AAD, and IV discipline as the record variant;
     * the kind byte only needs to be distinct from [CryptoRecordKind] codes
     * used in the same directory — session envelopes live in their own
     * directory and are never mixed with record envelopes.
     */
    fun seal(
        key: SecretKey,
        kindCode: Byte,
        handleId: UUID,
        recordBytes: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        require(iv.isNotEmpty()) { "platform Cipher produced no GCM IV" }
        cipher.updateAAD(aad(kindCode, handleId))
        val ciphertext = cipher.doFinal(recordBytes)
        return buildEnvelope(kindCode, handleId, iv, ciphertext)
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
    ): ByteArray = unseal(key, kind.code, handleId, envelope)

    /** Byte-oriented unseal; same contract as the record variant. */
    fun unseal(
        key: SecretKey,
        kindCode: Byte,
        handleId: UUID,
        envelope: ByteArray,
    ): ByteArray {
        val parsed = parse(envelope)
        if (parsed.version != CURRENT_VERSION) {
            throw VaultException.UnknownVersion(parsed.version)
        }
        if (parsed.kindCode != kindCode || parsed.handleId != handleId) {
            throw VaultException.HandleMismatch()
        }
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(GCM_TAG_BITS, parsed.iv),
            )
            cipher.updateAAD(aad(kindCode, handleId))
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
     * or empty ciphertext. Unknown versions pass through with their version
     * number for the caller to reject explicitly; kind codes outside the
     * crypto set resolve to a null [ParsedEnvelope.kind] and are rejected
     * by the kind-code comparison in [unseal].
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
        // Kind codes outside the crypto set are structurally corrupt for
        // record envelopes; byte-oriented callers (session namespace) match
        // on the raw code instead and never consult [CryptoRecordKind].
        val kind = CryptoRecordKind.fromCode(kindCode)
        return ParsedEnvelope(version, kindCode, kind, UUID(msb, lsb), iv, ciphertext)
    }

    private fun buildEnvelope(
        kindCode: Byte,
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
        buf.put(kindCode)
        buf.putLong(handleId.mostSignificantBits)
        buf.putLong(handleId.leastSignificantBits)
        buf.put(iv.size.toByte())
        buf.put(iv)
        buf.put(ciphertext)
        return buf.array()
    }

    private fun aad(kind: CryptoRecordKind, handleId: UUID): ByteArray =
        aad(kind.code, handleId)

    private fun aad(kindCode: Byte, handleId: UUID): ByteArray {
        val buf = ByteBuffer.allocate(MAGIC.size + 1 + 1 + 16)
        buf.put(MAGIC)
        buf.put(CURRENT_VERSION.toByte())
        buf.put(kindCode)
        buf.putLong(handleId.mostSignificantBits)
        buf.putLong(handleId.leastSignificantBits)
        return buf.array()
    }
}
