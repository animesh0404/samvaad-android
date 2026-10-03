package com.samvaad.android

import com.samvaad.android.crypto.MessageContentSealer
import com.samvaad.android.crypto.RecordEnvelopeCodec
import com.samvaad.android.crypto.VaultException
import com.samvaad.android.crypto.WrappingKeyProvider
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Message-content sealer tests: AES-GCM round trip over the shared
 * wrapping key in the dedicated 0x20 AAD domain. Pure JVM (in-memory
 * AES key standing in for the Keystore key); no Android APIs, no files.
 * Test-only IDs carry no production meaning.
 */
class MessageContentSealerTest {

    private class EphemeralKeys : WrappingKeyProvider {
        private var key: SecretKey? = null
        override fun getOrCreate(): SecretKey =
            key ?: KeyGenerator.getInstance("AES").let {
                it.init(256)
                it.generateKey().also { k -> key = k }
            }

        override fun getExisting(): SecretKey? = key

        fun dropKey() {
            key = null
        }
    }

    private lateinit var keys: EphemeralKeys
    private lateinit var sealer: MessageContentSealer

    @Before
    fun setUp() {
        keys = EphemeralKeys()
        sealer = MessageContentSealer(keys)
    }

    private fun containsWindow(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (i in 0..haystack.size - needle.size) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    @Test
    fun seal_open_roundTrip() {
        val plaintext = "hello samvaad history".toByteArray(Charsets.UTF_8)
        val sealed = sealer.seal("msg-1", plaintext)
        assertArrayEquals(plaintext, sealer.open("msg-1", sealed))
    }

    @Test
    fun emptyPlaintext_rejected() {
        // The protocol has no empty messages; sealing one would hide
        // caller bugs, so the seam refuses instead of producing bytes.
        assertThrows(IllegalArgumentException::class.java) {
            sealer.seal("msg-1", ByteArray(0))
        }
    }

    @Test
    fun blankMessageId_rejected() {
        assertThrows(IllegalArgumentException::class.java) {
            sealer.seal("  ", "x".toByteArray())
        }
        assertThrows(IllegalArgumentException::class.java) {
            sealer.open("", ByteArray(10))
        }
    }

    @Test
    fun binaryPlaintext_roundTrip() {
        val plaintext = ByteArray(1024) { i -> (i * 31 + 7).toByte() }
        assertArrayEquals(plaintext, sealer.open("msg-bin", sealer.seal("msg-bin", plaintext)))
    }

    @Test
    fun largePlaintext_roundTrip() {
        val plaintext = ByteArray(64 * 1024) { i -> (i % 251).toByte() }
        assertArrayEquals(plaintext, sealer.open("msg-large", sealer.seal("msg-large", plaintext)))
    }

    @Test
    fun wrongMessageId_failsClosed() {
        val sealed = sealer.seal("msg-1", "secret".toByteArray())
        // Same key, different AAD identity: authentication rejects it.
        assertThrows(VaultException.HandleMismatch::class.java) {
            sealer.open("msg-2", sealed)
        }
    }

    @Test
    fun flippedCiphertextByte_failsClosed() {
        val sealed = sealer.seal("msg-1", "secret-and-long-enough".toByteArray())
        val tampered = sealed.copyOf().also { it[it.size - 1] = it[it.size - 1].inc().toByte() }
        assertThrows(VaultException.CorruptEnvelope::class.java) {
            sealer.open("msg-1", tampered)
        }
    }

    @Test
    fun tamperedEnvelopeHeader_failsClosed() {
        val sealed = sealer.seal("msg-1", "secret-and-long-enough".toByteArray())
        // Version byte (index 4): unknown version, explicit rejection.
        val badVersion = sealed.copyOf().also { it[4] = 0x7F }
        assertThrows(VaultException.UnknownVersion::class.java) {
            sealer.open("msg-1", badVersion)
        }
        // Kind byte (index 5): wrong AAD domain, explicit mismatch.
        val badKind = sealed.copyOf().also { it[5] = 0x01 }
        assertThrows(VaultException.HandleMismatch::class.java) {
            sealer.open("msg-1", badKind)
        }
        // Truncation: structural rejection.
        assertThrows(VaultException.CorruptEnvelope::class.java) {
            sealer.open("msg-1", sealed.copyOf(10))
        }
    }

    @Test
    fun sealedBytes_carryNoPlaintext_andDifferPerSeal() {
        val plaintext = "same plaintext every time, long enough".toByteArray(Charsets.UTF_8)
        val first = sealer.seal("msg-1", plaintext)
        val second = sealer.seal("msg-1", plaintext)
        // Fresh random IV per seal: outputs differ, both open independently.
        assertFalse(first.contentEquals(second))
        assertArrayEquals(plaintext, sealer.open("msg-1", first))
        assertArrayEquals(plaintext, sealer.open("msg-1", second))
        // No window of the sealed representation contains the plaintext.
        assertFalse(containsWindow(first, plaintext))
        assertFalse(containsWindow(second, plaintext))
    }

    @Test
    fun missingWrappingKey_openFailsClosed() {
        val sealed = sealer.seal("msg-1", "secret".toByteArray())
        keys.dropKey()
        // getExisting-only on open: never recreates, fails closed instead.
        assertThrows(VaultException.WrappingKeyMissing::class.java) {
            sealer.open("msg-1", sealed)
        }
    }

    @Test
    fun sharedKey_coexistsWithVaultDomains() {
        // Same wrapping key drives both the vault record codec and the
        // message-content domain; AAD separation keeps them isolated.
        val key = keys.getOrCreate()
        val recordEnvelope = RecordEnvelopeCodec.seal(
            key,
            com.samvaad.android.crypto.CryptoRecordKind.IDENTITY,
            java.util.UUID.randomUUID(),
            "identity-record".toByteArray(),
        )
        val messageEnvelope = sealer.seal("msg-1", "message-content".toByteArray())
        // Each opens in its own domain…
        assertArrayEquals(
            "identity-record".toByteArray(),
            RecordEnvelopeCodec.unseal(
                key,
                com.samvaad.android.crypto.CryptoRecordKind.IDENTITY,
                parseHandle(recordEnvelope),
                recordEnvelope,
            ),
        )
        assertArrayEquals("message-content".toByteArray(), sealer.open("msg-1", messageEnvelope))
        // …and neither opens in the other.
        assertThrows(VaultException.HandleMismatch::class.java) {
            sealer.open("msg-1", recordEnvelope)
        }
        assertThrows(VaultException.HandleMismatch::class.java) {
            RecordEnvelopeCodec.unseal(
                key,
                com.samvaad.android.crypto.CryptoRecordKind.IDENTITY,
                MessageContentSealer.handleFor("msg-1"),
                messageEnvelope,
            )
        }
    }

    private fun parseHandle(envelope: ByteArray): java.util.UUID =
        RecordEnvelopeCodec.parse(envelope).handleId

    @Test
    fun handleFor_isDeterministicAndScoped() {
        assertEquals(
            MessageContentSealer.handleFor("msg-1"),
            MessageContentSealer.handleFor("msg-1"),
        )
        assertFalse(
            MessageContentSealer.handleFor("msg-1") == MessageContentSealer.handleFor("msg-2")
        )
    }
}
