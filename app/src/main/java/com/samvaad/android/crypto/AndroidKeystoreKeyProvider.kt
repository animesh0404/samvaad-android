package com.samvaad.android.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * [WrappingKeyProvider] backed by the Android Keystore.
 *
 * Holds exactly one non-exportable AES-256 wrapping key under [KEY_ALIAS],
 * authorized for GCM encrypt/decrypt with no padding. No user/biometric/
 * lockscreen authentication is required (the app must work without user
 * interaction); StrongBox is not mandated (TEE fallback is acceptable).
 *
 * The Keystore holds ONLY this wrapping key — never libsignal material.
 * Key bytes are never read (`getEncoded()` is never called) and never
 * written anywhere. There is intentionally no delete/rotate API: if the key
 * is missing while data exists, callers fail closed ([getExisting] returns
 * null) instead of recreating it.
 */
class AndroidKeystoreKeyProvider(
    private val alias: String = KEY_ALIAS,
) : WrappingKeyProvider {

    companion object {
        const val KEY_ALIAS = "samvaad-crypto-vault-v1"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    }

    override fun getOrCreate(): SecretKey {
        getExisting()?.let { return it }
        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build()
        )
        return generator.generateKey()
    }

    override fun getExisting(): SecretKey? {
        val store = KeyStore.getInstance(KEYSTORE_PROVIDER)
        store.load(null)
        if (!store.containsAlias(alias)) return null
        return (store.getKey(alias, null) as? SecretKey)
    }
}
