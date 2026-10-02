package com.samvaad.android.crypto

/**
 * Decoded remote prekey bundle for outbound Signal session establishment.
 *
 * Pure data with decoded public bytes — no `org.signal.libsignal.*` types
 * may appear here. The HTTP layer decodes standard-Base64 wire fields
 * into this shape; [AndroidSignalAdapter] parses and verifies it with
 * libsignal itself before any session is created.
 *
 * A null [oneTimePrekeyId]/[oneTimePrekey] pair is the server's
 * signed-prekey fallback (empty OTPK pool), not an error. Kyber fields
 * are mandatory for this slice: a pre-Kyber server row must be rejected,
 * never silently downgraded.
 */
data class RemotePrekeyBundle(
    val registrationId: Int,
    val signalDeviceId: Int,
    val identityKey: ByteArray,
    val signedPrekeyId: Int,
    val signedPrekey: ByteArray,
    val signedPrekeySignature: ByteArray,
    val oneTimePrekeyId: Int?,
    val oneTimePrekey: ByteArray?,
    val kyberPrekeyId: Int?,
    val kyberPrekey: ByteArray?,
    val kyberPrekeySignature: ByteArray?,
) {
    init {
        require(signalDeviceId >= 1) { "signal device id must be positive" }
        require(
            (oneTimePrekeyId == null) == (oneTimePrekey == null)
        ) { "one-time prekey id and bytes must agree" }
    }
}
