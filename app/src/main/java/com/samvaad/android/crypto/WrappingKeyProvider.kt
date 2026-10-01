package com.samvaad.android.crypto

import javax.crypto.SecretKey

/**
 * Custody of the vault's AES wrapping key.
 *
 * Split into two operations so the vault can fail closed: sealing may
 * create the key on first use, but unsealing must NEVER create one —
 * a missing key alongside stored data is corruption/loss, not setup.
 */
interface WrappingKeyProvider {
    /** Return the existing key, generating and persisting it if absent. */
    fun getOrCreate(): SecretKey

    /** Return the existing key, or null if absent. Never generates. */
    fun getExisting(): SecretKey?
}
