package com.samvaad.android.crypto

import java.util.Base64
import java.util.UUID

/**
 * LOCAL-ONLY libsignal feasibility spike material.
 *
 * Samvaad-level opaque/public data only. No `org.signal.libsignal.*` types
 * may appear in this file — libsignal stays isolated behind
 * [AndroidSignalAdapter]. Private key material never appears here either:
 * generation methods return public bytes plus an opaque [SealedHandle];
 * the handle carries no bytes and reveals nothing.
 *
 * Nothing here is persisted, logged, sent over the network, or shown in UI.
 * All private objects live only in memory inside the adapter.
 */
object SpikeCryptoMaterial {

    private val encoder: Base64.Encoder = Base64.getEncoder()
    private val decoder: Base64.Decoder = Base64.getDecoder()

    /**
     * Opaque reference to private material. Carries no key bytes — only the
     * vault/store key ([id]) and the record [kind] needed for typed
     * recovery. Handles are stable: the same [id]/[kind] re-resolves after
     * process restart once the vault restores the record.
     */
    data class SealedHandle(val id: UUID, val kind: CryptoRecordKind) {
        constructor(kind: CryptoRecordKind) : this(UUID.randomUUID(), kind)
    }

    /** Public half of the identity key pair. Holds freshly serialized bytes. */
    data class Identity(val publicKey: ByteArray, val privateHandle: SealedHandle)

    /** Public half of a signed EC prekey. */
    data class SignedPrekey(
        val prekeyId: Int,
        val publicKey: ByteArray,
        val signature: ByteArray,
        val privateHandle: SealedHandle,
    )

    /** Public half of the last-resort Kyber (PQXDH) prekey. */
    data class KyberPrekey(
        val prekeyId: Int,
        val publicKey: ByteArray,
        val signature: ByteArray,
        val privateHandle: SealedHandle,
    )

    /** Public half of one EC one-time prekey. */
    data class OneTimePrekey(
        val prekeyId: Int,
        val publicKey: ByteArray,
        val privateHandle: SealedHandle,
    )

    /**
     * In-memory shape equivalent to the server's `POST /api/e2ee/devices`
     * enrollment payload. Built only to prove serialization shape; NEVER
     * sent anywhere in this spike (no HTTP client exists for it).
     */
    data class EnrollmentShape(
        val registrationId: Int,
        val deviceIdentityPublicKey: String,
        val signedPrekeyId: Int,
        val signedPrekey: String,
        val signedPrekeySignature: String,
        val kyberPrekeyId: Int,
        val kyberPrekey: String,
        val kyberPrekeySignature: String,
        val clientPlatform: String = "ANDROID",
    )

    /** Standard Base64 (matches server `E2eeMapper`: `Base64.getEncoder()`). */
    fun encodeBase64(bytes: ByteArray): String = encoder.encodeToString(bytes)

    /** Standard Base64 decode; blank input is rejected like the server. */
    fun decodeBase64(value: String): ByteArray {
        require(value.isNotBlank()) { "Base64 value must be present and non-empty" }
        return decoder.decode(value.trim())
    }

    /**
     * Canonical 33-byte identity-key gate (mirrors server ADR 0021 and the
     * JVM `IdentityFingerprints.requireCanonicalKey`): `0x05 || X25519`.
     * Pure structural check — curve validity stays with libsignal parsing.
     */
    fun requireCanonicalIdentityKey(bytes: ByteArray): ByteArray {
        require(bytes.size == 33) { "identity key must be 33 bytes" }
        require(bytes[0] == 0x05.toByte()) { "identity key must start with 0x05" }
        return bytes
    }

    fun toEnrollmentShape(
        registrationId: Int,
        identity: Identity,
        signed: SignedPrekey,
        kyber: KyberPrekey,
    ): EnrollmentShape = EnrollmentShape(
        registrationId = registrationId,
        deviceIdentityPublicKey = encodeBase64(identity.publicKey),
        signedPrekeyId = signed.prekeyId,
        signedPrekey = encodeBase64(signed.publicKey),
        signedPrekeySignature = encodeBase64(signed.signature),
        kyberPrekeyId = kyber.prekeyId,
        kyberPrekey = encodeBase64(kyber.publicKey),
        kyberPrekeySignature = encodeBase64(kyber.signature),
    )
}
