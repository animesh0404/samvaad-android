package com.samvaad.android.session

import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Per-remote-device locks serializing all Signal SessionRecord mutations
 * for one peer device.
 *
 * Outbound encryption and inbound decryption both mutate the same
 * durable SessionRecord, so both directions MUST share one holder
 * instance per device scope: same device serializes, different devices
 * proceed independently. The lock covers the full mutation window
 * (load → encrypt/decrypt → export → seal) and is always released via
 * [withDeviceLock]'s finally semantics, including on failure.
 * Post-persistence network calls (submit/ACK) run outside the lock:
 * they are server-idempotent and touch no local session state.
 *
 * Lifetime is tied to the holder instance; entries are one small Mutex
 * per peer device ever contacted. Construction is explicit; no DI.
 */
class SessionDeviceLocks {
    private val mapMutex = Mutex()
    private val locks = ConcurrentHashMap<String, Mutex>()

    /** Run [block] holding this holder's mutex for [remoteDeviceId]. */
    suspend fun <T> withDeviceLock(remoteDeviceId: String, block: suspend () -> T): T {
        val deviceMutex = mapMutex.withLock {
            locks.getOrPut(remoteDeviceId) { Mutex() }
        }
        return deviceMutex.withLock { block() }
    }
}
