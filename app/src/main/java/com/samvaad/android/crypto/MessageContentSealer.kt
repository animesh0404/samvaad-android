package com.samvaad.android.crypto

import java.nio.charset.StandardCharsets
import java.util.UUID
import javax.crypto.SecretKey

/**
 * Message plaintext at rest (slice: durable message state). The ONLY new
 * abstraction in this step responsible for message content on disk.
 *
 * Reuses the existing Keystore wrapping-key infrastructure end to end:
 * same AES-256-GCM algorithm, same [RecordEnvelopeCodec] envelope layout
 * and IV discipline, same [WrappingKeyProvider] custody (no second key,
 * no new hierarchy, no new algorithm, no key derivation). Domain
 * separation from vault/session envelopes comes from a distinct kind
 * byte ([MESSAGE_CONTENT_KIND]) bound into the GCM AAD together with a
 * deterministic per-message identity — a vault record envelope can
 * never open as message content and vice versa.
 *
 * Plaintext is never written anywhere by this class: callers hand bytes
 * in and receive opaque envelope bytes back (or the reverse). Seal
 * failures fail closed via [VaultException]; no fallback, no plaintext.
 */
class MessageContentSealer(
    private val keys: WrappingKeyProvider,
) {
    /**
     * Seal [plaintext] for [messageId]. Empty plaintext is rejected —
     * the protocol has no empty messages and silently sealing them
     * would hide caller bugs.
     */
    fun seal(messageId: String, plaintext: ByteArray): ByteArray {
        require(messageId.isNotBlank()) { "messageId must be present" }
        require(plaintext.isNotEmpty()) { "plaintext must be non-empty" }
        val key: SecretKey = keys.getOrCreate()
        return RecordEnvelopeCodec.seal(key, MESSAGE_CONTENT_KIND, handleFor(messageId), plaintext)
    }

    /**
     * Open a sealed envelope for [messageId]. A wrong messageId, any
     * truncation, any bit flip, or a missing wrapping key fails closed.
     * Uses [WrappingKeyProvider.getExisting] only — opening must never
     * create key material.
     */
    fun open(messageId: String, sealed: ByteArray): ByteArray {
        require(messageId.isNotBlank()) { "messageId must be present" }
        val key: SecretKey = keys.getExisting() ?: throw VaultException.WrappingKeyMissing()
        return RecordEnvelopeCodec.unseal(key, MESSAGE_CONTENT_KIND, handleFor(messageId), sealed)
    }

    companion object {
        /**
         * Message-content AAD domain. Distinct from every
         * [CryptoRecordKind] code (0x01–0x05) and the auth-session
         * namespace (0x10); never reused for another purpose.
         */
        const val MESSAGE_CONTENT_KIND: Byte = 0x20

        /**
         * Deterministic per-message identity derived from the server
         * message ID: stable across restarts, never persisted separately,
         * non-secret (it only names the AAD, it protects nothing alone).
         */
        fun handleFor(messageId: String): UUID = UUID.nameUUIDFromBytes(
            ("samvaad-message-v1:" + messageId).toByteArray(StandardCharsets.UTF_8)
        )
    }
}
