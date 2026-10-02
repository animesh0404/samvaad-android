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
    /**
     * Durable outbound Signal SessionRecord blob (canonical
     * `SessionRecord.serialize()` bytes). Sealed under the same Keystore
     * wrapping key but in the separate `signal-sessions/` namespace —
     * never mixed with the `0x01`–`0x04` crypto-vault records nor the
     * `0x10` auth-session record.
     */
    SESSION(0x05),
    ;

    companion object {
        fun fromCode(code: Byte): CryptoRecordKind? =
            entries.firstOrNull { it.code == code }
    }
}
