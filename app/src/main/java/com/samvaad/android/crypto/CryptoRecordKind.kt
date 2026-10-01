package com.samvaad.android.crypto

/**
 * Stable kind discriminator for durable crypto records.
 *
 * The spike's anonymous `SealedHandle(UUID)` cannot support recovery: the
 * vault must know which libsignal record type a blob deserializes into.
 * [code] is the on-disk stable identifier — never renumbered.
 */
enum class CryptoRecordKind(val code: Byte) {
    IDENTITY(0x01),
    SIGNED_PREKEY(0x02),
    KYBER_PREKEY(0x03),
    ONE_TIME_PREKEY(0x04),
    ;

    companion object {
        fun fromCode(code: Byte): CryptoRecordKind? =
            entries.firstOrNull { it.code == code }
    }
}
